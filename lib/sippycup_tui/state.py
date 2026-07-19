"""Pure event decoding/reduction plus a bounded producer-consumer bridge."""

from __future__ import annotations

import json
import queue
import threading
from dataclasses import asdict, dataclass, field, replace
from typing import Iterable, Mapping

EVENT_SCHEMA = "sippycup.ui-event/v1"
PHASES = {"planning", "ready", "running", "warning", "stopping", "recovery", "complete", "failed"}


class EventError(ValueError):
    """A structured producer event does not satisfy the UI contract."""


@dataclass(frozen=True)
class Event:
    sequence: int
    source: str
    kind: str
    payload: Mapping[str, object] = field(default_factory=dict)
    schema: str = EVENT_SCHEMA


@dataclass(frozen=True)
class ViewState:
    phase: str = "planning"
    last_sequence: Mapping[str, int] = field(default_factory=dict)
    processed: int = 0
    dropped: int = 0
    late: int = 0
    schema_errors: int = 0
    warnings: tuple[str, ...] = ()
    actions: tuple[str, ...] = ("stop", "quit")
    latest: Mapping[str, object] = field(default_factory=dict)

    def as_json_record(self) -> dict[str, object]:
        record = asdict(self)
        record["schema"] = "sippycup.view-state/v1"
        return record


KIND_TO_PHASE = {
    "plan.started": "planning", "plan.ready": "ready", "run.started": "running",
    "run.warning": "warning", "stop.requested": "stopping",
    "recovery.started": "recovery", "run.completed": "complete",
    "assertions.passed": "complete", "run.failed": "failed", "assertions.failed": "failed",
}
PHASE_ACTIONS = {
    "planning": ("stop", "quit"), "ready": ("start", "stop", "quit"),
    "running": ("stop", "note", "bookmark", "quit"),
    "warning": ("stop", "note", "bookmark", "quit"),
    "stopping": ("stop", "note", "quit"), "recovery": ("stop", "note", "quit"),
    "complete": ("stop", "termshark", "note", "quit"),
    "failed": ("stop", "termshark", "note", "quit"),
}


def decode_event(raw: Mapping[str, object] | str) -> Event:
    """Decode structured JSON only; ANSI/tool text is never interpreted."""
    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise EventError("event is not JSON") from exc
    else:
        value = dict(raw)
    if not isinstance(value, dict):
        raise EventError("event must be an object")
    unknown = sorted(set(value) - {"schema", "sequence", "source", "kind", "payload"})
    if unknown:
        raise EventError("unknown event fields: " + ", ".join(unknown))
    if value.get("schema") != EVENT_SCHEMA:
        raise EventError(f"unsupported event schema: {value.get('schema')!r}")
    sequence, source, kind, payload = (
        value.get("sequence"), value.get("source"), value.get("kind"), value.get("payload", {})
    )
    if type(sequence) is not int or sequence < 0:
        raise EventError("sequence must be a non-negative integer")
    if not isinstance(source, str) or not source or len(source) > 64:
        raise EventError("source must be a non-empty string up to 64 characters")
    if not isinstance(kind, str) or not kind or len(kind) > 96:
        raise EventError("kind must be a non-empty string up to 96 characters")
    if not isinstance(payload, dict):
        raise EventError("payload must be an object")
    if len(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()) > 65536:
        raise EventError("payload exceeds 64 KiB")
    return Event(sequence, source, kind, payload)


def reduce_event(state: ViewState, event: Event) -> ViewState:
    """Pure reducer used verbatim by the interactive and JSON renderers."""
    if state.phase not in PHASES:
        raise EventError(f"invalid prior phase: {state.phase}")
    last = state.last_sequence.get(event.source)
    sequences, warnings = dict(state.last_sequence), list(state.warnings)
    if last is not None and event.sequence <= last:
        warnings.append(f"late event from {event.source}: sequence {event.sequence} after {last}")
        return replace(state, late=state.late + 1, warnings=tuple(warnings[-100:]))
    sequences[event.source] = event.sequence
    if event.kind == "ui.dropped":
        count = event.payload.get("count", 1)
        count = count if type(count) is int and count >= 1 else 1
        warnings.append(f"{count} producer event(s) dropped by backpressure")
        return replace(state, phase="warning", last_sequence=sequences,
                       processed=state.processed + 1, dropped=state.dropped + count,
                       warnings=tuple(warnings[-100:]), actions=PHASE_ACTIONS["warning"])
    if event.kind == "ui.schema-error":
        warnings.append(str(event.payload.get("message", "producer schema mismatch")))
        return replace(state, phase="warning", last_sequence=sequences,
                       processed=state.processed + 1, schema_errors=state.schema_errors + 1,
                       warnings=tuple(warnings[-100:]), actions=PHASE_ACTIONS["warning"])
    phase = KIND_TO_PHASE.get(event.kind, state.phase)
    if event.kind == "run.warning":
        warnings.append(str(event.payload.get("message", "runtime warning")))
    return replace(state, phase=phase, last_sequence=sequences,
                   processed=state.processed + 1, warnings=tuple(warnings[-100:]),
                   actions=PHASE_ACTIONS[phase],
                   latest={"source": event.source, "kind": event.kind, "payload": dict(event.payload)})


def replay(events: Iterable[Event], initial: ViewState = ViewState()) -> ViewState:
    state = initial
    for event in events:
        state = reduce_event(state, event)
    return state


class BoundedEventBuffer:
    """A finite queue with producer backpressure and explicit drop telemetry."""
    def __init__(self, capacity: int = 256):
        if type(capacity) is not int or not 1 <= capacity <= 10000:
            raise EventError("queue capacity must be an integer in 1..10000")
        self._queue: queue.Queue[Event] = queue.Queue(capacity)
        self._lock, self._dropped, self._diagnostic_sequence = threading.Lock(), 0, 0

    @property
    def capacity(self) -> int:
        return self._queue.maxsize

    def put(self, event: Event, timeout: float = 0.0) -> bool:
        try:
            self._queue.put(event, block=timeout > 0, timeout=max(0.0, timeout))
            return True
        except queue.Full:
            with self._lock:
                self._dropped += 1
            return False

    def get(self, timeout: float | None = None) -> Event:
        with self._lock:
            if self._dropped:
                count, self._dropped = self._dropped, 0
                self._diagnostic_sequence += 1
                return Event(self._diagnostic_sequence, "ui-buffer", "ui.dropped", {"count": count})
        return self._queue.get(block=True, timeout=timeout)

    def task_done(self, event: Event) -> None:
        if event.source != "ui-buffer":
            self._queue.task_done()


def visible_schema_error(message: str, sequence: int) -> Event:
    return Event(sequence, "ui-decoder", "ui.schema-error", {"message": message})
