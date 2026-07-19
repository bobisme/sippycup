"""Conservative hierarchical delta debugging for protocol failures."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .corpus import CorpusError


@dataclass(frozen=True)
class Authorization:
    destination: str
    dialog_state: str
    max_packets_per_trial: int
    max_bytes_per_trial: int

    def __post_init__(self) -> None:
        if not self.destination or not self.dialog_state:
            raise CorpusError("authorization destination and dialog state are required")
        if type(self.max_packets_per_trial) is not int or not 1 <= self.max_packets_per_trial <= 3:
            raise CorpusError("trial packet authorization must be 1..3")
        if type(self.max_bytes_per_trial) is not int or not 1 <= self.max_bytes_per_trial <= 4096:
            raise CorpusError("trial byte authorization must be 1..4096")


@dataclass(frozen=True)
class Reproducer:
    wire_bytes: bytes
    dimensions: tuple[str, ...]
    authorization: Authorization


@dataclass(frozen=True)
class TrialResult:
    failed: bool
    actual_outcome: str
    capture_frames: tuple[bytes, ...] = ()


@dataclass(frozen=True)
class MinimizerLimits:
    trials: int = 5
    quorum: int = 3
    max_candidates: int = 64
    max_total_packets: int = 192
    max_total_bytes: int = 1_000_000

    def __post_init__(self) -> None:
        ints = (
            self.trials,
            self.quorum,
            self.max_candidates,
            self.max_total_packets,
            self.max_total_bytes,
        )
        if any(type(value) is not int or value < 1 for value in ints):
            raise CorpusError("minimizer limits must be positive integers")
        if self.quorum > self.trials or self.trials > 9:
            raise CorpusError("quorum must fit within at most nine trials")
        if self.max_candidates > 256 or self.max_total_packets > 768:
            raise CorpusError("minimizer request exceeds hard safety cap")


Predicate = Callable[[Reproducer], TrialResult]


class HierarchicalMinimizer:
    def __init__(
        self,
        source: Reproducer,
        predicate: Predicate,
        *,
        limits: MinimizerLimits = MinimizerLimits(),
        expected_outcome: str,
        command: Iterable[str],
    ):
        if not source.wire_bytes:
            raise CorpusError("source reproducer cannot be empty")
        if len(source.wire_bytes) > source.authorization.max_bytes_per_trial:
            raise CorpusError("source exceeds authorized per-trial bytes")
        self.source = source
        self.predicate = predicate
        self.limits = limits
        self.expected_outcome = expected_outcome
        self.command = _redact_argv(tuple(command))
        if not self.command or any(not isinstance(arg, str) or "\x00" in arg for arg in self.command):
            raise CorpusError("a safe argv-style reproduction command is required")
        self.trace: list[dict[str, object]] = []
        self.candidates = 0
        self.total_packets = 0
        self.total_bytes = 0
        self.final_trials: tuple[TrialResult, ...] = ()

    def minimize(self) -> dict[str, object]:
        baseline = self._test(self.source, "baseline")
        if baseline["failures"] < self.limits.quorum:
            raise CorpusError("source failure does not meet the configured quorum")
        current = self.source
        if baseline["classification"] == "flaky":
            return self._result(current, "flaky")

        for level in ("sections", "headers", "body-lines", "values"):
            current = self._reduce_bytes(current, level)
        current = self._reduce_dimensions(current)
        final = self._test(current, "final-confirmation")
        status = "stable" if final["classification"] == "stable" else "flaky"
        return self._result(current, status)

    def write_bundle(self, directory: Path, result: dict[str, object]) -> None:
        directory.mkdir(parents=True, exist_ok=False)
        wire = bytes.fromhex(str(result["wireHex"]))
        (directory / "reproducer.bin").write_bytes(wire)
        (directory / "manifest.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        with (directory / "reduction-trace.jsonl").open("x", encoding="utf-8") as stream:
            for record in self.trace:
                stream.write(json.dumps(record, sort_keys=True) + "\n")
        capture_dir = directory / "capture-frames"
        capture_dir.mkdir()
        for trial_index, trial in enumerate(self.final_trials):
            for frame_index, frame in enumerate(trial.capture_frames):
                (capture_dir / f"{trial_index:02d}-{frame_index:03d}.bin").write_bytes(frame)

    def _reduce_bytes(self, current: Reproducer, level: str) -> Reproducer:
        while True:
            spans = _spans(current.wire_bytes, level)
            if not spans:
                return current
            reduced = False
            # ddmin-style increasingly fine partitions. A candidate is only
            # adopted after unanimous reproduction; quorum-only candidates are
            # explicitly flaky and never become a new reduction base.
            partitions = min(2, len(spans))
            while partitions <= len(spans):
                width = math.ceil(len(spans) / partitions)
                for start in range(0, len(spans), width):
                    removal = spans[start : start + width]
                    candidate_bytes = _delete_spans(current.wire_bytes, removal)
                    if not candidate_bytes or candidate_bytes == current.wire_bytes:
                        continue
                    candidate = Reproducer(
                        candidate_bytes, current.dimensions, current.authorization
                    )
                    verdict = self._test(candidate, level)
                    if verdict["classification"] == "stable":
                        current = candidate
                        reduced = True
                        break
                if reduced or partitions == len(spans):
                    break
                partitions = min(len(spans), partitions * 2)
            if not reduced:
                return current

    def _reduce_dimensions(self, current: Reproducer) -> Reproducer:
        dimensions = list(current.dimensions)
        index = 0
        while index < len(dimensions):
            candidate_dimensions = tuple(dimensions[:index] + dimensions[index + 1 :])
            candidate = Reproducer(current.wire_bytes, candidate_dimensions, current.authorization)
            verdict = self._test(candidate, "mutation-dimensions")
            if verdict["classification"] == "stable":
                dimensions = list(candidate_dimensions)
            else:
                index += 1
        return Reproducer(current.wire_bytes, tuple(dimensions), current.authorization)

    def _test(self, candidate: Reproducer, level: str) -> dict[str, object]:
        if self.candidates >= self.limits.max_candidates:
            return {"failures": 0, "classification": "budget-exhausted"}
        if not _is_subsequence(candidate.wire_bytes, self.source.wire_bytes):
            raise CorpusError("minimization attempted to introduce or reorder bytes")
        if not set(candidate.dimensions).issubset(self.source.dimensions):
            raise CorpusError("minimization attempted to introduce a mutation dimension")
        if candidate.authorization != self.source.authorization:
            raise CorpusError("minimization attempted to change authorization")

        trial_packets = self.source.authorization.max_packets_per_trial * self.limits.trials
        trial_bytes = len(candidate.wire_bytes) * self.limits.trials
        if (
            self.total_packets + trial_packets > self.limits.max_total_packets
            or self.total_bytes + trial_bytes > self.limits.max_total_bytes
        ):
            return {"failures": 0, "classification": "budget-exhausted"}

        results = tuple(self.predicate(candidate) for _ in range(self.limits.trials))
        if any(not isinstance(result, TrialResult) for result in results):
            raise CorpusError("predicate returned an invalid trial result")
        self.candidates += 1
        self.total_packets += trial_packets
        self.total_bytes += trial_bytes
        failures = sum(result.failed for result in results)
        classification = (
            "stable"
            if failures == self.limits.trials
            else "flaky"
            if failures >= self.limits.quorum
            else "not-reproduced"
        )
        self.final_trials = results
        self.trace.append(
            {
                "index": self.candidates,
                "level": level,
                "sha256": hashlib.sha256(candidate.wire_bytes).hexdigest(),
                "bytes": len(candidate.wire_bytes),
                "dimensions": list(candidate.dimensions),
                "failures": failures,
                "trials": self.limits.trials,
                "classification": classification,
                "actualOutcomes": [result.actual_outcome for result in results],
            }
        )
        return {"failures": failures, "classification": classification}

    def _result(self, reduced: Reproducer, stability: str) -> dict[str, object]:
        return {
            "schema": "sippycup.torture-reproducer/v1",
            "sourceSha256": hashlib.sha256(self.source.wire_bytes).hexdigest(),
            "sha256": hashlib.sha256(reduced.wire_bytes).hexdigest(),
            "wireHex": reduced.wire_bytes.hex(),
            "sourceBytes": len(self.source.wire_bytes),
            "reducedBytes": len(reduced.wire_bytes),
            "dimensions": list(reduced.dimensions),
            "stability": stability,
            "quorum": {"required": self.limits.quorum, "trials": self.limits.trials},
            "expectedOutcome": self.expected_outcome,
            "actualOutcomes": [trial.actual_outcome for trial in self.final_trials],
            "command": list(self.command),
            "authorization": {
                "destination": reduced.authorization.destination,
                "dialogState": reduced.authorization.dialog_state,
                "maxPacketsPerTrial": reduced.authorization.max_packets_per_trial,
                "maxBytesPerTrial": reduced.authorization.max_bytes_per_trial,
            },
            "trafficUsed": {
                "candidateTests": self.candidates,
                "reservedPackets": self.total_packets,
                "bytes": self.total_bytes,
            },
        }


def _line_spans(data: bytes, start: int, end: int) -> list[tuple[int, int]]:
    spans = []
    cursor = start
    while cursor < end:
        line_end = data.find(b"\n", cursor, end)
        line_end = end if line_end < 0 else line_end + 1
        spans.append((cursor, line_end))
        cursor = line_end
    return spans


def _spans(data: bytes, level: str) -> list[tuple[int, int]]:
    separator = data.find(b"\r\n\r\n")
    if separator < 0:
        separator = data.find(b"\n\n")
        delimiter = 2
    else:
        delimiter = 4
    body_start = len(data) if separator < 0 else separator + delimiter
    if level == "sections":
        spans = []
        if body_start < len(data):
            spans.append((body_start, len(data)))
        return spans
    if level == "headers":
        lines = _line_spans(data, 0, body_start)
        return lines[1:]  # the request/status line is structural
    if level == "body-lines":
        return _line_spans(data, body_start, len(data))
    if level == "values":
        spans = []
        for start, end in _line_spans(data, 0, body_start):
            colon = data.find(b":", start, end)
            if colon < 0:
                continue
            cursor = colon + 1
            while cursor < end:
                while cursor < end and data[cursor : cursor + 1] in b" \t;,=":
                    cursor += 1
                token_end = cursor
                while token_end < end and data[token_end : token_end + 1] not in b" \t;,=\r\n":
                    token_end += 1
                if token_end > cursor:
                    spans.append((cursor, token_end))
                cursor = token_end + 1
        return spans
    raise CorpusError(f"unknown minimization level: {level}")


def _delete_spans(data: bytes, spans: list[tuple[int, int]]) -> bytes:
    removed = bytearray(data)
    for start, end in sorted(spans, reverse=True):
        del removed[start:end]
    return bytes(removed)


def _is_subsequence(candidate: bytes, source: bytes) -> bool:
    iterator = iter(source)
    return all(any(value == original for original in iterator) for value in candidate)


def _redact_argv(command: tuple[str, ...]) -> tuple[str, ...]:
    redacted = []
    hide_next = False
    sensitive = ("password", "passwd", "token", "secret", "authorization")
    for argument in command:
        lowered = argument.lower()
        if hide_next:
            redacted.append("<redacted>")
            hide_next = False
            continue
        if lowered.startswith("--") and any(name in lowered for name in sensitive):
            if "=" in argument:
                redacted.append(argument.split("=", 1)[0] + "=<redacted>")
            else:
                redacted.append(argument)
                hide_next = True
            continue
        redacted.append(argument)
    return tuple(redacted)
