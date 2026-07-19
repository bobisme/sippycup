"""Mission-control orchestration independent of terminal rendering."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Mapping

from .adapters import adapt_assertion, adapt_campaign
from .controls import ActionController, ActionReceipt, ControlError
from .render import DashboardModel, apply_dashboard_event, render_text
from .state import (
    BoundedEventBuffer, EVENT_SCHEMA, Event, EventError, ViewState,
    decode_event, reduce_event, visible_schema_error,
)


KEYS = {
    "?": "help", "s": "start", "p": "pause-new-calls",
    "x": "graceful-stop", "!": "emergency-stop", "k": "skip",
    "n": "note", "b": "bookmark", "t": "termshark", "q": "quit",
}


@dataclass(frozen=True)
class AppSnapshot:
    state: ViewState
    model: DashboardModel
    help_visible: bool
    stopped: bool

    def as_json_record(self) -> dict[str, object]:
        record = self.model.as_json_record(self.state)
        record.update({
            "state": self.state.as_json_record(),
            "helpVisible": self.help_visible,
            "stopped": self.stopped,
            "keyBindings": dict(KEYS),
            "guidance": {
                "trafficStart": "Traffic starts only after Start is explicitly confirmed.",
                "artifacts": "Open the frozen run directory shown in capturePath for reports and evidence.",
            },
        })
        return record


class MissionApp:
    def __init__(self, controller: ActionController | None = None, *, capacity: int = 256):
        self.controller = controller
        self.buffer = BoundedEventBuffer(capacity)
        self.state, self.model = ViewState(), DashboardModel()
        self.help_visible = False
        self.stopped = False
        self._diagnostic_sequence = 0
        self._action_sequence = 0

    def ingest(self, raw: Mapping[str, object] | str, *, assertion_sequence: int = 1) -> bool:
        try:
            record = json.loads(raw) if isinstance(raw, str) else dict(raw)
            if record.get("schema") == EVENT_SCHEMA:
                event = decode_event(record)
            elif "apiVersion" in record:
                event = adapt_campaign(record)
            elif "schema_version" in record:
                event = adapt_assertion(record, sequence=assertion_sequence)
            else:
                raise EventError("unrecognized producer event schema")
            return True if event is None else self.buffer.put(event)
        except (json.JSONDecodeError, EventError, TypeError, ValueError) as exc:
            self._diagnostic_sequence += 1
            return self.buffer.put(visible_schema_error(str(exc), self._diagnostic_sequence))

    def drain(self, *, limit: int = 10000) -> int:
        count = 0
        while count < limit:
            try:
                event = self.buffer.get(timeout=0.0)
            except Exception as exc:
                import queue
                if isinstance(exc, queue.Empty):
                    break
                raise
            self.state = reduce_event(self.state, event)
            self.model = apply_dashboard_event(self.model, event)
            self.buffer.task_done(event)
            count += 1
        return count

    def key(
        self,
        key: str,
        *,
        confirmed: bool = False,
        text: str = "",
        evidence: str | None = None,
    ) -> ActionReceipt | None:
        action = KEYS.get(key)
        if action is None:
            raise ControlError(f"unknown key: {key!r}")
        if action == "help":
            self.help_visible = not self.help_visible
            return None
        if action == "quit":
            self.close()
            return ActionReceipt("quit", self.state.phase, True, "UI stopped")
        if self.controller is None:
            raise ControlError("no campaign control API is attached")
        self._action_sequence += 1
        identity = f"ui-{self._action_sequence}"
        if action in {"note", "bookmark"}:
            return self.controller.note(
                text, self.state, idempotency_key=identity,
                bookmark=action == "bookmark", evidence=evidence,
            )
        if action == "termshark":
            capture = self.controller.run_dir / self.model.capture_path
            return self.controller.open_capture(capture, self.state)
        confirmation = None
        if action in {"start", "emergency-stop", "skip"}:
            if not confirmed:
                raise ControlError(f"{action} requires visible confirmation")
            confirmation = self.controller.request_confirmation(action).token
        return self.controller.invoke(
            action, self.state, idempotency_key=identity, confirmation=confirmation
        )

    def close(self) -> None:
        if self.stopped:
            return
        self.stopped = True
        if self.controller is not None:
            self._action_sequence += 1
            self.controller.invoke(
                "graceful-stop",
                self.state,
                idempotency_key=f"ui-close-{self._action_sequence}",
            )

    def snapshot(self) -> AppSnapshot:
        return AppSnapshot(self.state, self.model, self.help_visible, self.stopped)

    def render(self, *, width: int, height: int) -> str:
        return render_text(
            self.model, self.state, width=width, height=height,
            help_overlay=self.help_visible,
        )
