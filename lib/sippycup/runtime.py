"""Bounded, signal-safe execution of frozen campaign plans."""

from __future__ import annotations

import json
import ipaddress
import math
import os
import queue
import re
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable, Sequence


EVENT_API_VERSION = "sippycup.dev/events/v1"
PLAN_API_VERSION = "sippycup.dev/plan/v1"
DEFAULT_GRACE_SECONDS = 2.0
DEFAULT_OUTPUT_LIMIT = 256 * 1024
OUTPUT_CHUNK_SIZE = 4096
OUTPUT_QUEUE_SIZE = 32
MAX_PLAN_BYTES = 8 * 1024 * 1024
MAX_STEP_INPUT_BYTES = 1024 * 1024
MAX_CLEANUPS = 64
SUPPORTED_TRANSPORTS = {"udp", "tcp", "tls"}
CEILING_KEYS = {
    "calls",
    "packets",
    "bytes",
    "durationSeconds",
    "concurrentCalls",
    "packetsPerSecond",
    "callsPerSecond",
}
RESERVED_EVENT_FIELDS = {
    "apiVersion",
    "sequence",
    "timeUnixNs",
    "campaign",
    "event",
    "state",
}

EXIT_SUCCESS = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_TIMEOUT = 124
EXIT_SIGINT = 130
EXIT_SIGTERM = 143


class RuntimeError(ValueError):
    """A frozen-plan or executor error suitable for command-line display."""


@dataclass(frozen=True)
class RunResult:
    exit_code: int
    state: str
    completed_steps: int


class EventWriter:
    """Append-only JSONL event writer with monotonic sequence numbers."""

    def __init__(
        self,
        path: Path,
        campaign: str,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = path
        self.campaign = campaign
        self.clock = clock
        self.sequence = 0
        path.parent.mkdir(parents=True, exist_ok=True)
        # A run owns one event stream. Refuse reuse rather than resetting the
        # sequence inside an existing append-only audit trail.
        self._file = path.open("x", encoding="utf-8", buffering=1)

    def emit(self, event: str, state: str, **fields: Any) -> None:
        collisions = sorted(RESERVED_EVENT_FIELDS & fields.keys())
        if collisions:
            raise RuntimeError(
                "event fields collide with reserved fields: " + ", ".join(collisions)
            )
        self.sequence += 1
        record = {
            "apiVersion": EVENT_API_VERSION,
            "sequence": self.sequence,
            "timeUnixNs": int(self.clock() * 1_000_000_000),
            "campaign": self.campaign,
            "event": event,
            "state": state,
            **fields,
        }
        self._file.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        self._file.flush()

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> EventWriter:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class CampaignSupervisor:
    """Execute plan steps sequentially and own every child process group."""

    def __init__(
        self,
        plan: dict[str, Any],
        runner: Sequence[str],
        events: EventWriter,
        *,
        grace_seconds: float = DEFAULT_GRACE_SECONDS,
        output_limit: int = DEFAULT_OUTPUT_LIMIT,
        monotonic: Callable[[], float] = time.monotonic,
        runner_input: Callable[[dict[str, Any]], bytes] | None = None,
        redactions: Sequence[str] = (),
        child_env: dict[str, str] | None = None,
        external_stop: Callable[[], str | None] | None = None,
    ) -> None:
        if not runner:
            raise RuntimeError("runner command must not be empty")
        if (
            isinstance(grace_seconds, bool)
            or not isinstance(grace_seconds, (int, float))
            or not math.isfinite(grace_seconds)
            or grace_seconds < 0
        ):
            raise RuntimeError("grace seconds must be a finite non-negative number")
        if isinstance(output_limit, bool) or not isinstance(output_limit, int) or output_limit < 0:
            raise RuntimeError("output limit must not be negative")
        self.plan = _validate_plan(plan)
        self.runner = list(runner)
        self.events = events
        self.grace_seconds = grace_seconds
        self.output_limit = output_limit
        self.monotonic = monotonic
        self.runner_input = runner_input or _default_runner_input
        self.redactions = tuple(value for value in redactions if value)
        self.child_env = child_env
        self.external_stop = external_stop or (lambda: None)
        self._last_call_start: float | None = None
        self._external_reason: str | None = None
        self._cancel_signal: int | None = None
        self._child: subprocess.Popen[bytes] | None = None
        self._pgid: int | None = None
        self._cleaned = False
        self._cleanups: list[tuple[str, Callable[[], None]]] = []

    def register_cleanup(self, name: str, cleanup: Callable[[], None]) -> None:
        if self._cleaned:
            raise RuntimeError("cannot register cleanup after cleanup has begun")
        if len(self._cleanups) >= MAX_CLEANUPS:
            raise RuntimeError(f"cleanup registry is limited to {MAX_CLEANUPS} entries")
        if not name:
            raise RuntimeError("cleanup name must not be empty")
        self._cleanups.append((name, cleanup))

    def request_cancel(self, signum: int) -> None:
        if self._cancel_signal is None:
            self._cancel_signal = signum

    def cleanup(self) -> None:
        """Idempotently stop the active process group, gracefully then forcibly."""
        if self._cleaned:
            return
        self._cleaned = True
        pgid = self._pgid
        if pgid is not None:
            self._terminate_group(pgid)
        child = self._child
        if child is not None:
            try:
                child.wait(timeout=max(self.grace_seconds, 0.1))
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        while self._cleanups:
            _name, rollback = self._cleanups.pop()
            try:
                rollback()
            except Exception:
                # Cleanup is best-effort and must continue through every LIFO entry.
                pass

    def _terminate_group(self, pgid: int) -> None:
        if _group_exists(pgid):
            try:
                os.killpg(pgid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = self.monotonic() + self.grace_seconds
            while _group_exists(pgid) and self.monotonic() < deadline:
                if self._child is not None:
                    self._child.poll()
                time.sleep(0.01)
            if _group_exists(pgid):
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                kill_deadline = self.monotonic() + max(self.grace_seconds, 0.1)
                while _group_exists(pgid) and self.monotonic() < kill_deadline:
                    if self._child is not None:
                        self._child.poll()
                    time.sleep(0.01)

    def run(self) -> RunResult:
        metadata = self.plan["metadata"]
        steps = self.plan["steps"]
        hard_maxima = self.plan["authorization"]["hardMaxima"]
        global_deadline = self.monotonic() + hard_maxima["durationSeconds"]
        completed = 0
        self.events.emit(
            "campaign.started",
            "running",
            manifestSha256=metadata["manifestSha256"],
            stepCount=len(steps),
        )
        try:
            for step in steps:
                external_reason = self.external_stop()
                if external_reason is not None:
                    self.events.emit(
                        "campaign.failed",
                        "failed",
                        completedSteps=completed,
                        reason=external_reason,
                    )
                    return RunResult(EXIT_FAILED, external_reason, completed)
                if self._cancel_signal is not None:
                    return self._cancelled(completed)
                if self.monotonic() >= global_deadline:
                    self.events.emit("campaign.timed_out", "timed_out", completedSteps=completed)
                    return RunResult(EXIT_TIMEOUT, "timed_out", completed)
                if step["type"] == "call":
                    interval = 1 / hard_maxima["callsPerSecond"]
                    while (
                        self._last_call_start is not None
                        and self.monotonic() - self._last_call_start < interval
                    ):
                        if self._cancel_signal is not None:
                            return self._cancelled(completed)
                        external_reason = self.external_stop()
                        if external_reason is not None:
                            self.events.emit(
                                "campaign.failed",
                                "failed",
                                completedSteps=completed,
                                reason=external_reason,
                            )
                            return RunResult(EXIT_FAILED, external_reason, completed)
                        if self.monotonic() >= global_deadline:
                            self.events.emit(
                                "campaign.timed_out",
                                "timed_out",
                                completedSteps=completed,
                            )
                            return RunResult(EXIT_TIMEOUT, "timed_out", completed)
                        time.sleep(0.01)
                    self._last_call_start = self.monotonic()
                outcome = self._run_step(step, global_deadline)
                if outcome == "success":
                    completed += 1
                    continue
                if outcome == "cancelled":
                    return self._cancelled(completed)
                if outcome == "timeout":
                    self.events.emit("campaign.timed_out", "timed_out", completedSteps=completed)
                    return RunResult(EXIT_TIMEOUT, "timed_out", completed)
                if outcome == "external":
                    reason = self._external_reason or "external_stop"
                    self.events.emit(
                        "campaign.failed",
                        "failed",
                        completedSteps=completed,
                        reason=reason,
                    )
                    return RunResult(EXIT_FAILED, reason, completed)
                self.events.emit("campaign.failed", "failed", completedSteps=completed)
                return RunResult(EXIT_FAILED, "failed", completed)
            self.events.emit("campaign.succeeded", "succeeded", completedSteps=completed)
            return RunResult(EXIT_SUCCESS, "succeeded", completed)
        finally:
            self.cleanup()

    def _run_step(self, step: dict[str, Any], global_deadline: float) -> str:
        step_number = step["index"]
        self._cleaned = False
        self.events.emit(
            "step.started",
            "running",
            step=step_number,
            case=step["case"],
            sequenceInCase=step["sequence"],
        )
        try:
            payload = self.runner_input(step)
            if not isinstance(payload, bytes):
                raise RuntimeError("runner input factory must return bytes")
            if len(payload) > MAX_STEP_INPUT_BYTES:
                raise RuntimeError(
                    f"runner input exceeds {MAX_STEP_INPUT_BYTES} byte limit"
                )
        except (RuntimeError, OSError, ValueError) as error:
            self.events.emit(
                "step.start_failed",
                "failed",
                step=step_number,
                error=f"{type(error).__name__}: {error}",
            )
            return "failed"
        try:
            child = subprocess.Popen(
                self.runner,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                env=self.child_env,
            )
        except OSError as error:
            self.events.emit(
                "step.start_failed",
                "failed",
                step=step_number,
                error=f"{type(error).__name__}: {error}",
            )
            return "failed"
        self._child = child
        self._pgid = child.pid
        assert child.stdin is not None
        input_thread = _start_writer(child.stdin, payload)

        output_queue: queue.Queue[tuple[str, bytes] | tuple[str, None]] = queue.Queue(
            maxsize=OUTPUT_QUEUE_SIZE
        )
        threads = [
            _start_reader("stdout", child.stdout, output_queue),
            _start_reader("stderr", child.stderr, output_queue),
        ]
        stream_ends = 0
        kept = 0
        dropped = 0
        retained_output = {"stdout": bytearray(), "stderr": bytearray()}
        step_deadline = min(
            global_deadline,
            self.monotonic() + step["budget"]["durationSeconds"],
        )
        outcome: str | None = None
        while stream_ends < 2 or child.poll() is None:
            if outcome is None and self._cancel_signal is not None:
                outcome = "cancelled"
                self.events.emit(
                    "campaign.stop_requested",
                    "stopping",
                    reason=signal.Signals(self._cancel_signal).name,
                    step=step_number,
                )
                self.cleanup()
            elif outcome is None and (reason := self.external_stop()) is not None:
                outcome = "external"
                self._external_reason = reason
                self.events.emit(
                    "campaign.stop_requested",
                    "stopping",
                    reason=reason,
                    step=step_number,
                )
                self.cleanup()
            elif outcome is None and self.monotonic() >= step_deadline:
                outcome = "timeout"
                self.events.emit(
                    "campaign.stop_requested",
                    "stopping",
                    reason="deadline",
                    step=step_number,
                )
                self.cleanup()
            try:
                stream, chunk = output_queue.get(timeout=0.02)
            except queue.Empty:
                continue
            if chunk is None:
                stream_ends += 1
                continue
            remaining = max(0, self.output_limit - kept)
            retained = chunk[:remaining]
            dropped += len(chunk) - len(retained)
            if retained:
                kept += len(retained)
                retained_output[stream].extend(retained)
        for thread in threads:
            thread.join()
        input_thread.join(timeout=max(self.grace_seconds, 0.1))
        return_code = child.wait()
        self._child = None
        if self._pgid is not None:
            self._terminate_group(self._pgid)
            self._pgid = None
        for stream in ("stdout", "stderr"):
            if retained_output[stream]:
                self.events.emit(
                    "step.output",
                    "running",
                    step=step_number,
                    stream=stream,
                    text=_redact_output(bytes(retained_output[stream]), self.redactions),
                )
        if dropped:
            self.events.emit(
                "step.output_truncated",
                "running",
                step=step_number,
                retainedBytes=kept,
                droppedBytes=dropped,
            )
        if outcome == "cancelled":
            self.events.emit("step.cancelled", "cancelled", step=step_number)
            return outcome
        if outcome == "timeout":
            self.events.emit("step.timed_out", "timed_out", step=step_number)
            return outcome
        if outcome == "external":
            self.events.emit(
                "step.failed",
                "failed",
                step=step_number,
                exitCode=1,
            )
            return "external"
        if return_code:
            self.events.emit(
                "step.failed",
                "failed",
                step=step_number,
                exitCode=return_code,
            )
            return "failed"
        self.events.emit("step.succeeded", "succeeded", step=step_number)
        return "success"

    def _cancelled(self, completed: int) -> RunResult:
        assert self._cancel_signal is not None
        name = signal.Signals(self._cancel_signal).name
        self.events.emit(
            "campaign.cancelled",
            "cancelled",
            completedSteps=completed,
            signal=name,
        )
        code = EXIT_SIGINT if self._cancel_signal == signal.SIGINT else EXIT_SIGTERM
        return RunResult(code, "cancelled", completed)


def _start_reader(
    stream_name: str,
    stream: BinaryIO | None,
    output_queue: queue.Queue[tuple[str, bytes] | tuple[str, None]],
) -> threading.Thread:
    assert stream is not None

    def read() -> None:
        try:
            while chunk := stream.read(OUTPUT_CHUNK_SIZE):
                output_queue.put((stream_name, chunk))
        finally:
            stream.close()
            output_queue.put((stream_name, None))

    thread = threading.Thread(target=read, name=f"campaign-{stream_name}", daemon=True)
    thread.start()
    return thread


def _start_writer(stream: BinaryIO, payload: bytes) -> threading.Thread:
    def write() -> None:
        try:
            stream.write(payload)
            stream.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    thread = threading.Thread(target=write, name="campaign-stdin", daemon=True)
    thread.start()
    return thread


def _group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _redact_output(raw: bytes, secrets: Sequence[str]) -> str:
    text = raw.decode("utf-8", errors="replace")
    for secret in secrets:
        text = text.replace(secret, "<redacted>")
    return re.sub(
        r"(?im)^(\s*(?:proxy-)?authorization\s*:)\s*.*$",
        r"\1 <redacted>",
        text,
    )


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{field} must be an object")
    return value


def _exact_keys(value: dict[str, Any], field: str, expected: set[str]) -> None:
    missing = sorted(expected - value.keys())
    extra = sorted(value.keys() - expected)
    if missing or extra:
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unsupported " + ", ".join(extra))
        raise RuntimeError(f"{field} fields are invalid: {'; '.join(details)}")


def _unique_array(
    value: Any, field: str, *, allow_empty: bool = False
) -> list[Any]:
    if not isinstance(value, list) or (not allow_empty and not value):
        qualifier = "an array" if allow_empty else "a non-empty array"
        raise RuntimeError(f"{field} must be {qualifier}")
    for index, item in enumerate(value):
        if item in value[:index]:
            raise RuntimeError(f"{field} contains a duplicate value")
    return value


def _is_uint(value: Any, *, positive: bool) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, int)
        and value >= (1 if positive else 0)
        and value <= (1 << 64) - 1
    )


def _validate_case_expectations(value: Any, step: int) -> None:
    expectations = _object(value, f"step {step} expectations")
    if not expectations:
        return
    allowed = {
        "apiVersion",
        "finalStatus",
        "allowedProvisionalStatuses",
        "requireBidirectionalRtp",
        "maxSetupSeconds",
    }
    if set(expectations) - allowed:
        raise RuntimeError(f"step {step} expectations contain unsupported fields")
    if expectations.get("apiVersion") != "sippycup.dev/case-expectations/v1":
        raise RuntimeError(f"step {step} expectations version is invalid")
    if "finalStatus" in expectations and (
        not _is_uint(expectations["finalStatus"], positive=True)
        or not 200 <= expectations["finalStatus"] <= 699
    ):
        raise RuntimeError(f"step {step} finalStatus is invalid")
    if "allowedProvisionalStatuses" in expectations:
        statuses = _unique_array(
            expectations["allowedProvisionalStatuses"],
            f"step {step} allowedProvisionalStatuses",
            allow_empty=True,
        )
        if any(not _is_uint(item, positive=True) or not 100 <= item <= 199 for item in statuses):
            raise RuntimeError(f"step {step} provisional status is invalid")
    if "requireBidirectionalRtp" in expectations and not isinstance(
        expectations["requireBidirectionalRtp"], bool
    ):
        raise RuntimeError(f"step {step} RTP expectation is invalid")
    if "maxSetupSeconds" in expectations and not _is_uint(
        expectations["maxSetupSeconds"], positive=True
    ):
        raise RuntimeError(f"step {step} setup deadline is invalid")


def _capture_filter(steps: list[dict[str, Any]], media: dict[str, Any]) -> str:
    scopes: dict[str, set[tuple[str, int]]] = {}
    for step in steps:
        destination = step["destination"]
        for address in destination["addresses"]:
            scopes.setdefault(address, set()).add(
                (destination["transport"], destination["port"])
            )
    rendered = []
    for address in sorted(
        scopes, key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value)))
    ):
        signaling = [
            f"{'udp' if transport == 'udp' else 'tcp'} port {port}"
            for transport, port in sorted(scopes[address])
        ]
        signaling.append(f"udp portrange {media['start']}-{media['end']}")
        rendered.append(f"(host {address} and ({' or '.join(signaling)}))")
    return " or ".join(rendered)


def _validate_plan(plan: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(plan, dict):
        raise RuntimeError("plan must be an object")
    try:
        encoded = json.dumps(plan, allow_nan=False, separators=(",", ":")).encode()
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"plan is not finite JSON: {error}") from error
    if len(encoded) > MAX_PLAN_BYTES:
        raise RuntimeError(f"plan exceeds {MAX_PLAN_BYTES} byte runtime limit")
    plan_keys = {
        "apiVersion", "kind", "metadata", "authorization",
        "resolvedDestinations", "captureFilter", "expectations", "evidence",
        "plannedTotals", "steps", "assumptions", "resolutionPins",
    }
    if set(plan) not in (plan_keys, plan_keys | {"matrix"}):
        missing = sorted(plan_keys - set(plan))
        extra = sorted(set(plan) - plan_keys - {"matrix"})
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if extra:
            details.append("unsupported: " + ", ".join(extra))
        raise RuntimeError("plan has invalid fields (" + "; ".join(details) + ")")
    if plan.get("apiVersion") != PLAN_API_VERSION:
        raise RuntimeError(f"plan apiVersion must be {PLAN_API_VERSION!r}")
    if plan.get("kind") != "CampaignPlan":
        raise RuntimeError("plan kind must be 'CampaignPlan'")
    metadata = _object(plan["metadata"], "metadata")
    _exact_keys(metadata, "metadata", {"name", "manifestSha256"})
    name = metadata["name"]
    if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", name):
        raise RuntimeError("plan metadata.name is invalid")
    digest = metadata["manifestSha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise RuntimeError("plan metadata.manifestSha256 must be a SHA-256 digest")

    authorization = _object(plan["authorization"], "authorization")
    _exact_keys(
        authorization,
        "authorization",
        {
            "networks", "signalingPorts", "mediaPorts", "transports",
            "credentialRefs", "hardMaxima", "stopConditions",
        },
    )
    raw_networks = _unique_array(authorization["networks"], "authorization.networks")
    networks = []
    for value in raw_networks:
        if not isinstance(value, str):
            raise RuntimeError("authorization.networks values must be strings")
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as error:
            raise RuntimeError(f"invalid authorized network {value!r}") from error
        networks.append(network)
    ports = _unique_array(
        authorization["signalingPorts"], "authorization.signalingPorts"
    )
    if any(not _is_uint(port, positive=True) or port > 65535 for port in ports):
        raise RuntimeError("authorization signaling ports must be within 1..65535")
    transports = _unique_array(
        authorization["transports"], "authorization.transports"
    )
    if not transports or any(item not in SUPPORTED_TRANSPORTS for item in transports):
        raise RuntimeError("authorization transports contain an unsupported value")
    if "matrix" in plan:
        # Reuse the compiler's complete finite-model validator. This import is
        # local because the campaign CLI imports the runtime only for execution.
        from sippycup.campaign import ManifestError, _validate_matrix

        try:
            normalized_matrix = _validate_matrix(plan["matrix"], set(transports))
        except ManifestError as error:
            raise RuntimeError(f"plan matrix is invalid: {error}") from error
        if normalized_matrix != plan["matrix"]:
            raise RuntimeError("plan matrix is not in canonical frozen form")
    credentials = _unique_array(
        authorization["credentialRefs"], "authorization.credentialRefs", allow_empty=True
    )
    if any(
        not isinstance(item, str)
        or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", item)
        for item in credentials
    ):
        raise RuntimeError("authorization credentialRefs contain an invalid value")
    media = _object(authorization["mediaPorts"], "authorization.mediaPorts")
    _exact_keys(media, "authorization.mediaPorts", {"start", "end"})
    if (
        not _is_uint(media["start"], positive=True)
        or not _is_uint(media["end"], positive=True)
        or media["start"] > media["end"]
        or media["end"] > 65535
    ):
        raise RuntimeError("authorization mediaPorts must be an ordered port range")
    maxima = _object(authorization["hardMaxima"], "authorization.hardMaxima")
    _exact_keys(maxima, "authorization.hardMaxima", CEILING_KEYS)
    if any(not _is_uint(value, positive=True) for value in maxima.values()):
        raise RuntimeError("authorization hardMaxima values must be positive integers")
    stops = _object(authorization["stopConditions"], "authorization.stopConditions")
    _exact_keys(
        stops,
        "authorization.stopConditions",
        {"consecutiveFailures", "unexpectedResponse", "packetLossPercent"},
    )
    if not _is_uint(stops["consecutiveFailures"], positive=True):
        raise RuntimeError("stopConditions.consecutiveFailures must be positive")
    if not isinstance(stops["unexpectedResponse"], bool):
        raise RuntimeError("stopConditions.unexpectedResponse must be boolean")
    loss = stops["packetLossPercent"]
    if (
        isinstance(loss, bool)
        or not isinstance(loss, (int, float))
        or not math.isfinite(loss)
        or not 0 <= loss <= 100
    ):
        raise RuntimeError("stopConditions.packetLossPercent must be finite within 0..100")

    destinations = _unique_array(
        plan["resolvedDestinations"], "resolvedDestinations"
    )
    destination_index: dict[str, set[tuple[str, str, int]]] = {}
    for index, item in enumerate(destinations):
        destination = _object(item, f"resolvedDestinations[{index}]")
        _exact_keys(
            destination,
            f"resolvedDestinations[{index}]",
            {"target", "address", "transport", "port"},
        )
        target = destination["target"]
        if not isinstance(target, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", target):
            raise RuntimeError("resolved destination target is invalid")
        try:
            address = ipaddress.ip_address(destination["address"])
        except (ValueError, TypeError) as error:
            raise RuntimeError("resolved destination address must be a literal IP") from error
        if not any(address in network for network in networks):
            raise RuntimeError("resolved destination lies outside authorization networks")
        transport = destination["transport"]
        port = destination["port"]
        if transport not in transports or port not in ports:
            raise RuntimeError("resolved destination transport or port is unauthorized")
        destination_index.setdefault(target, set()).add((str(address), transport, port))

    expectations = _object(plan["expectations"], "expectations")
    _exact_keys(
        expectations,
        "expectations",
        {"allowedSipStatuses", "requireBidirectionalRtp"},
    )
    statuses = _unique_array(
        expectations["allowedSipStatuses"], "expectations.allowedSipStatuses"
    )
    if any(not _is_uint(item, positive=True) or not 100 <= item <= 699 for item in statuses):
        raise RuntimeError("allowedSipStatuses values must be within 100..699")
    if not isinstance(expectations["requireBidirectionalRtp"], bool):
        raise RuntimeError("requireBidirectionalRtp must be boolean")

    evidence = _object(plan["evidence"], "evidence")
    _exact_keys(evidence, "evidence", {"capture", "retainPayload", "directory"})
    if not isinstance(evidence["capture"], bool) or not isinstance(evidence["retainPayload"], bool):
        raise RuntimeError("evidence capture and retainPayload must be boolean")
    directory = evidence["directory"]
    if (
        not isinstance(directory, str)
        or not directory
        or Path(directory).is_absolute()
        or ".." in Path(directory).parts
    ):
        raise RuntimeError("evidence directory must be a safe relative path")

    totals = _object(plan["plannedTotals"], "plannedTotals")
    _exact_keys(totals, "plannedTotals", {"calls", "packets", "bytes", "durationSeconds"})
    if any(not _is_uint(value, positive=False) for value in totals.values()):
        raise RuntimeError("plannedTotals values must be non-negative integers")
    if any(totals[key] > maxima[key] for key in totals):
        raise RuntimeError("plannedTotals exceed authorization hardMaxima")

    steps = _unique_array(plan["steps"], "steps")
    calculated = {"calls": 0, "packets": 0, "bytes": 0, "durationSeconds": 0}
    for expected_index, step in enumerate(steps, 1):
        step = _object(step, f"steps[{expected_index - 1}]")
        step_keys = {
            "index", "case", "sequence", "type", "target", "destination",
            "credentialRef", "budget", "expectations",
        }
        if set(step) not in (step_keys, step_keys | {"generated"}):
            raise RuntimeError(f"plan step {expected_index} has invalid fields")
        if step["index"] != expected_index:
            raise RuntimeError("plan step indexes must be contiguous starting at 1")
        if (
            not isinstance(step["case"], str)
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", step["case"])
            or not _is_uint(step["sequence"], positive=True)
            or step["type"] not in {"options", "call"}
            or step["target"] not in destination_index
        ):
            raise RuntimeError(f"plan step {expected_index} identity is invalid")
        credential = step["credentialRef"]
        if credential is not None and credential not in credentials:
            raise RuntimeError(f"plan step {expected_index} credential is unauthorized")
        step_destination = _object(
            step["destination"], f"steps[{expected_index - 1}].destination"
        )
        _exact_keys(
            step_destination,
            f"steps[{expected_index - 1}].destination",
            {"addresses", "port", "transport"},
        )
        addresses = _unique_array(
            step_destination["addresses"],
            f"steps[{expected_index - 1}].destination.addresses",
        )
        tuple_set = {
            (address, step_destination["transport"], step_destination["port"])
            for address in addresses
        }
        if tuple_set != destination_index[step["target"]]:
            raise RuntimeError(f"plan step {expected_index} destination is not frozen")
        budget = _object(step["budget"], f"steps[{expected_index - 1}].budget")
        _exact_keys(budget, f"steps[{expected_index - 1}].budget", {"calls", "packets", "bytes", "durationSeconds"})
        if (
            not _is_uint(budget["calls"], positive=False)
            or budget["calls"] not in {0, 1}
            or any(not _is_uint(budget[key], positive=True) for key in ("packets", "bytes", "durationSeconds"))
            or budget["calls"] != (1 if step["type"] == "call" else 0)
        ):
            raise RuntimeError(f"plan step {expected_index} budget is invalid")
        for key in calculated:
            calculated[key] += budget[key]
            if calculated[key] > maxima[key]:
                raise RuntimeError("step budgets exceed authorization hardMaxima")
        _validate_case_expectations(step["expectations"], expected_index)
        if "generated" in step:
            if "matrix" not in plan:
                raise RuntimeError("generated plan step requires a matrix")
            from sippycup.campaign import _validate_generated_case

            try:
                normalized_generated = _validate_generated_case(
                    step["generated"],
                    plan["matrix"],
                    f"steps[{expected_index - 1}].generated",
                )
            except ManifestError as error:
                raise RuntimeError(f"plan generated case is invalid: {error}") from error
            if normalized_generated != step["generated"]:
                raise RuntimeError("plan generated case is not canonical")
            if (
                normalized_generated["factors"]["transport"]
                != step_destination["transport"]
            ):
                raise RuntimeError(
                    "plan generated transport does not match step destination"
                )
            generated_family = normalized_generated["factors"]["addressFamily"]
            if any(
                f"ipv{ipaddress.ip_address(address).version}" != generated_family
                for address in addresses
            ):
                raise RuntimeError(
                    "plan generated addressFamily does not match step destination"
                )
    if calculated != totals:
        raise RuntimeError("plannedTotals do not equal the sum of frozen step budgets")
    assumptions = _unique_array(plan["assumptions"], "assumptions", allow_empty=True)
    if any(not isinstance(item, str) or not item for item in assumptions):
        raise RuntimeError("plan assumptions must be non-empty strings")
    expected_filter = _capture_filter(steps, media)
    if plan["captureFilter"] != expected_filter:
        raise RuntimeError("captureFilter is not the minimal filter for frozen steps")
    pins = _object(plan["resolutionPins"], "resolutionPins")
    for host, raw_addresses in pins.items():
        if (
            not isinstance(host, str)
            or not host
            or host.lower().rstrip(".") != host
        ):
            raise RuntimeError("resolutionPins contains an invalid hostname")
        addresses = _unique_array(raw_addresses, f"resolutionPins.{host}")
        for address in addresses:
            try:
                parsed = ipaddress.ip_address(address)
            except (TypeError, ValueError) as error:
                raise RuntimeError("resolutionPins values must be literal IPs") from error
            if not any(parsed in network for network in networks):
                raise RuntimeError("resolutionPins address lies outside authorization")
    return plan


def validate_plan(plan: dict[str, Any]) -> dict[str, Any]:
    return _validate_plan(plan)


def load_plan(path: Path) -> dict[str, Any]:
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise RuntimeError(f"invalid plan JSON: {error}") from error
    return _validate_plan(plan)


def _default_runner_input(step: dict[str, Any]) -> bytes:
    return json.dumps(step, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def run_plan(
    plan: dict[str, Any],
    runner: Sequence[str],
    event_path: Path,
    *,
    grace_seconds: float = DEFAULT_GRACE_SECONDS,
    output_limit: int = DEFAULT_OUTPUT_LIMIT,
    runner_input: Callable[[dict[str, Any]], bytes] | None = None,
    redactions: Sequence[str] = (),
    child_env: dict[str, str] | None = None,
    external_stop: Callable[[], str | None] | None = None,
) -> RunResult:
    campaign = _validate_plan(plan)["metadata"]["name"]
    with EventWriter(event_path, campaign) as events:
        supervisor = CampaignSupervisor(
            plan,
            runner,
            events,
            grace_seconds=grace_seconds,
            output_limit=output_limit,
            runner_input=runner_input,
            redactions=redactions,
            child_env=child_env,
            external_stop=external_stop,
        )
        previous: dict[int, Any] = {}

        def cancel(signum: int, _frame: object) -> None:
            supervisor.request_cancel(signum)

        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, cancel)
        try:
            return supervisor.run()
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
