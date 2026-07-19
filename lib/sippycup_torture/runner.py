"""State-aware, fail-closed execution for the bounded torture corpus."""

from __future__ import annotations

import hashlib
import json
import math
import queue
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .corpus import Case, CorpusError, send_exact


class RunnerError(RuntimeError):
    """The runner stopped at a safety or recovery boundary."""


@dataclass(frozen=True)
class RunnerLimits:
    max_cases: int = 1
    max_packets: int = 6
    max_bytes: int = 8192
    max_rate_hz: float = 1.0
    max_concurrency: int = 1
    max_duration_s: float = 30.0
    max_failures: int = 1
    action_timeout_s: float = 5.0

    def __post_init__(self) -> None:
        integers = (self.max_cases, self.max_packets, self.max_bytes, self.max_concurrency,
                    self.max_failures)
        if any(type(value) is not int or value < 1 for value in integers):
            raise CorpusError("integer ceilings must be positive integers")
        floats = (self.max_rate_hz, self.max_duration_s, self.action_timeout_s)
        if any(not math.isfinite(value) or value <= 0 for value in floats):
            raise CorpusError("time and rate ceilings must be positive and finite")
        hard = (
            self.max_cases <= 100
            and self.max_packets <= 300
            and self.max_bytes <= 1_000_000
            and self.max_rate_hz <= 10
            and self.max_concurrency == 1
            and self.max_duration_s <= 3600
            and self.max_failures <= 20
            and self.action_timeout_s <= 60
        )
        if not hard:
            raise CorpusError("requested ceiling exceeds the runner hard safety cap")


@dataclass(frozen=True)
class ActionResult:
    ok: bool
    outcome: str
    evidence_packets: tuple[bytes, ...] = ()
    sent_packets: tuple[bytes, ...] = ()
    dialog_state: str | None = None


@dataclass(frozen=True)
class ActionContext:
    cancel: threading.Event
    deadline_monotonic: float


Action = Callable[[Case, ActionContext], ActionResult]
HealthCheck = Callable[[], bool]


@dataclass(frozen=True)
class RunnerCallbacks:
    establish: Action
    inject: Action
    classify: Action
    recovery: Action
    health: HealthCheck = lambda: True
    metrics_within_threshold: HealthCheck = lambda: True


class TortureRunner:
    """Runs one finite mutation at a time, followed by a clean canary."""

    def __init__(
        self,
        cases: Iterable[Case],
        callbacks: RunnerCallbacks,
        evidence_dir: Path,
        *,
        limits: RunnerLimits = RunnerLimits(),
        stop_event: threading.Event | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ):
        self.cases = tuple(cases)
        self.callbacks = callbacks
        self.evidence_dir = evidence_dir
        self.limits = limits
        self.stop_event = stop_event or threading.Event()
        self.monotonic = monotonic
        self.sleeper = sleeper
        if not self.cases:
            raise CorpusError("at least one explicit case is required")
        if len({case.id for case in self.cases}) != len(self.cases):
            raise CorpusError("case selection contains duplicate ids")

    def dry_run(self) -> dict[str, object]:
        selected = self.cases[: self.limits.max_cases]
        case_packets = sum(case.packet_count for case in selected)
        case_bytes = sum(len(case.wire_bytes) for case in selected)
        # Establish/recovery evidence is provider-defined, so aggregate ceilings
        # remain the immutable authority rather than making a false estimate.
        return {
            "schema": "sippycup.torture-plan/v1",
            "cases": [
                {
                    "id": case.id,
                    "sha256": case.sha256,
                    "requiredDialogState": case.dialog_state,
                    "mutationPackets": case.packet_count,
                    "mutationBytes": len(case.wire_bytes),
                }
                for case in selected
            ],
            "selectedMutationTraffic": {"packets": case_packets, "bytes": case_bytes},
            "maximumTraffic": {
                "cases": self.limits.max_cases,
                "packets": self.limits.max_packets,
                "bytes": self.limits.max_bytes,
                "rateHz": self.limits.max_rate_hz,
                "concurrency": self.limits.max_concurrency,
                "durationSeconds": self.limits.max_duration_s,
                "failures": self.limits.max_failures,
            },
        }

    def run(self) -> dict[str, object]:
        plan = self.dry_run()
        selected = self.cases[: self.limits.max_cases]
        mutation_packets = sum(case.packet_count for case in selected)
        mutation_bytes = sum(len(case.wire_bytes) for case in selected)
        if mutation_packets > self.limits.max_packets or mutation_bytes > self.limits.max_bytes:
            raise RunnerError("selected mutations exceed frozen traffic ceilings")

        self.evidence_dir.mkdir(parents=True, exist_ok=False)
        events_path = self.evidence_dir / "events.jsonl"
        start = self.monotonic()
        counters = {"cases": 0, "packets": 0, "bytes": 0, "failures": 0}
        last_case_start: float | None = None

        with events_path.open("x", encoding="utf-8") as events:
            self._event(events, "run.started", trafficClass="control", plan=plan)
            for index, case in enumerate(selected):
                reason = self._stop_reason(start, counters)
                if reason:
                    self._event(events, "run.stopped", trafficClass="control", reason=reason)
                    return self._result("stopped", reason, counters, plan)

                if last_case_start is not None:
                    delay = (1.0 / self.limits.max_rate_hz) - (self.monotonic() - last_case_start)
                    if delay > 0:
                        self.sleeper(delay)
                last_case_start = self.monotonic()

                establish = self._action("establish", case, self.callbacks.establish)
                self._record_evidence(events, index, case, "baseline-establish", establish)
                if not establish.ok or establish.dialog_state != case.dialog_state:
                    return self._halt(events, "dialog-establishment-failed", counters, plan)

                mutation = self._action("inject", case, self.callbacks.inject)
                self._verify_exact_mutation(case, mutation)
                self._record_evidence(events, index, case, "mutation", mutation)
                self._write_exact_mutation(index, case)
                counters["packets"] += case.packet_count
                counters["bytes"] += len(case.wire_bytes)
                if not mutation.ok:
                    counters["failures"] += 1

                classification = self._action("classify", case, self.callbacks.classify)
                if classification.ok and classification.outcome not in case.expected_outcomes:
                    classification = ActionResult(
                        False,
                        f"unacceptable:{classification.outcome}",
                        classification.evidence_packets,
                        classification.sent_packets,
                        classification.dialog_state,
                    )
                self._record_evidence(events, index, case, "observation", classification)
                if not classification.ok:
                    counters["failures"] += 1

                # A clean canary is mandatory even when the mutation or
                # classification failed. No subsequent mutation is allowed
                # unless recovery succeeds.
                recovery = self._action("recovery", case, self.callbacks.recovery)
                self._record_evidence(events, index, case, "baseline-recovery", recovery)
                counters["cases"] += 1
                if not recovery.ok:
                    return self._halt(events, "recovery-canary-failed", counters, plan)
                if counters["failures"] >= self.limits.max_failures:
                    return self._halt(events, "failure-ceiling-reached", counters, plan)

            self._event(events, "run.completed", trafficClass="control", counters=counters)
        return self._result("completed", None, counters, plan)

    def _action(self, name: str, case: Case, action: Action) -> ActionResult:
        cancel = threading.Event()
        deadline = self.monotonic() + self.limits.action_timeout_s
        replies: queue.Queue[object] = queue.Queue(maxsize=1)

        def invoke() -> None:
            try:
                replies.put(action(case, ActionContext(cancel, deadline)))
            except BaseException as exc:  # captured and normalized at trust boundary
                replies.put(exc)

        worker = threading.Thread(target=invoke, daemon=True, name=f"torture-{name}")
        worker.start()
        worker.join(self.limits.action_timeout_s)
        if worker.is_alive():
            cancel.set()
            raise RunnerError(f"{name} action timed out; cancellation requested")
        reply = replies.get_nowait()
        if isinstance(reply, BaseException):
            raise RunnerError(f"{name} action failed: {type(reply).__name__}") from reply
        if not isinstance(reply, ActionResult):
            raise RunnerError(f"{name} action returned an invalid result")
        return reply

    def _stop_reason(self, start: float, counters: dict[str, int]) -> str | None:
        if self.stop_event.is_set():
            return "operator-stop"
        if self.monotonic() - start >= self.limits.max_duration_s:
            return "duration-ceiling-reached"
        if counters["failures"] >= self.limits.max_failures:
            return "failure-ceiling-reached"
        try:
            if not self.callbacks.health():
                return "health-check-failed"
            if not self.callbacks.metrics_within_threshold():
                return "server-metric-threshold"
        except BaseException:
            return "safety-callback-failed"
        return None

    def _record_evidence(
        self,
        events,
        index: int,
        case: Case,
        traffic_class: str,
        result: ActionResult,
    ) -> None:
        hashes = []
        for packet_index, packet in enumerate(result.evidence_packets):
            name = f"{index:03d}-{case.id}-{traffic_class}-{packet_index:03d}.bin"
            path = self.evidence_dir / name
            path.write_bytes(packet)
            hashes.append({"file": name, "sha256": hashlib.sha256(packet).hexdigest()})
        self._event(
            events,
            "case.stage",
            trafficClass=traffic_class,
            caseId=case.id,
            ok=result.ok,
            outcome=result.outcome,
            evidence=hashes,
        )

    def _write_exact_mutation(self, index: int, case: Case) -> None:
        path = self.evidence_dir / f"{index:03d}-{case.id}-mutation-source.bin"
        path.write_bytes(case.wire_bytes)
        if hashlib.sha256(path.read_bytes()).hexdigest() != case.sha256:
            raise RunnerError("mutation evidence hash mismatch")

    @staticmethod
    def _verify_exact_mutation(case: Case, result: ActionResult) -> None:
        lengths = case.packet_lengths or (len(case.wire_bytes),)
        expected = []
        offset = 0
        for length in lengths:
            expected.append(case.wire_bytes[offset : offset + length])
            offset += length
        if result.sent_packets != tuple(expected):
            raise RunnerError("inject provider did not attest the exact case packet bytes")

    def _halt(self, events, reason, counters, plan):
        self._event(events, "run.stopped", trafficClass="control", reason=reason)
        return self._result("stopped", reason, counters, plan)

    @staticmethod
    def _event(events, kind: str, **fields: object) -> None:
        events.write(json.dumps({"event": kind, **fields}, sort_keys=True) + "\n")
        events.flush()

    @staticmethod
    def _result(state, reason, counters, plan):
        return {
            "schema": "sippycup.torture-result/v1",
            "state": state,
            "reason": reason,
            "counters": dict(counters),
            "plan": plan,
        }


def exact_injector(sender: Callable[[bytes], int]) -> Action:
    """Adapt an authorized datagram sender to the runner action contract."""

    def inject(case: Case, context: ActionContext) -> ActionResult:
        if context.cancel.is_set():
            return ActionResult(False, "cancelled")
        packets = []

        def recording_sender(packet: bytes) -> int:
            sent = sender(packet)
            if sent == len(packet):
                packets.append(packet)
            return sent

        send_exact(case, recording_sender)
        return ActionResult(
            True,
            "exact-bytes-sent",
            tuple(packets),
            tuple(packets),
        )

    return inject
