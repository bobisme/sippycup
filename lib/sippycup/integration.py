"""Evidence-directory and tool integration for supervised campaigns."""

from __future__ import annotations

import json
import hashlib
from collections import deque
import os
import secrets as random
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from sippycup.campaign import ManifestError, verify_frozen_plan
from sippycup.runtime import RunResult, RuntimeError, run_plan, validate_plan


Preflight = Callable[[dict[str, Any]], tuple[bool, str]]
PROVIDER_TIMEOUT_SECONDS = 2.0


class _FinishExecution(Exception):
    """Internal non-error control flow used so cleanup can update the result."""


class CaptureWatchdog:
    """Continuously enforce traffic ceilings from an immediate-mode PCAP."""

    def __init__(self, capture: Path, maxima: Mapping[str, int]) -> None:
        self.capture = capture
        self.maxima = maxima
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._violation: str | None = None
        self._thread = threading.Thread(
            target=self._run, name="campaign-capture-watchdog", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)

    def violation(self) -> str | None:
        with self._lock:
            return self._violation

    def _fail(self, reason: str) -> None:
        with self._lock:
            if self._violation is None:
                self._violation = reason

    def _run(self) -> None:
        offset = 24
        endian: str | None = None
        packets = 0
        byte_count = 0
        calls = 0
        packet_times: deque[float] = deque()
        call_times: deque[float] = deque()
        while not self._stop.is_set():
            try:
                with self.capture.open("rb") as source:
                    header = source.read(24)
                    source.seek(offset)
                    record_header = source.read(16)
            except OSError:
                time.sleep(0.01)
                continue
            if endian is None and len(header) >= 24:
                if header[:4] == b"\xd4\xc3\xb2\xa1":
                    endian = "<"
                elif header[:4] == b"\xa1\xb2\xc3\xd4":
                    endian = ">"
                else:
                    self._fail("capture_format_invalid")
                    return
            if endian is not None and len(record_header) == 16:
                seconds, fraction, included, original = struct.unpack(
                    endian + "IIII", record_header
                )
                if included > 1024 * 1024:
                    self._fail("capture_record_too_large")
                    return
                try:
                    with self.capture.open("rb") as source:
                        source.seek(offset + 16)
                        packet = source.read(included)
                except OSError:
                    time.sleep(0.01)
                    continue
                if len(packet) < included:
                    time.sleep(0.01)
                    continue
                offset += 16 + included
                timestamp = seconds + fraction / 1_000_000
                packets += 1
                byte_count += original
                packet_times.append(timestamp)
                while packet_times and packet_times[0] < timestamp - 1:
                    packet_times.popleft()
                if b"INVITE " in packet:
                    calls += 1
                    call_times.append(timestamp)
                    while call_times and call_times[0] < timestamp - 1:
                        call_times.popleft()
                if packets > self.maxima["packets"]:
                    self._fail("packet_ceiling_exceeded")
                elif byte_count > self.maxima["bytes"]:
                    self._fail("byte_ceiling_exceeded")
                elif len(packet_times) > self.maxima["packetsPerSecond"]:
                    self._fail("packet_rate_ceiling_exceeded")
                elif calls > self.maxima["calls"]:
                    self._fail("call_ceiling_exceeded")
                elif len(call_times) > self.maxima["callsPerSecond"]:
                    self._fail("call_rate_ceiling_exceeded")
                if self.violation() is not None:
                    return
            else:
                time.sleep(0.01)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def create_run_directory(root: Path, campaign: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    for _ in range(8):
        path = root / f"{stamp}-{campaign}-{random.token_hex(4)}"
        try:
            path.mkdir(mode=0o700)
            return path
        except FileExistsError:
            continue
    raise RuntimeError("could not allocate a collision-safe run directory")


def resolve_secrets(
    references: Sequence[str],
    *,
    environ: Mapping[str, str] | None = None,
    env_names: Mapping[str, str] | None = None,
    fds: Mapping[str, int] | None = None,
    provider: str | None = None,
) -> dict[str, str]:
    environment = os.environ if environ is None else environ
    env_names = env_names or {}
    fds = fds or {}
    result: dict[str, str] = {}
    for reference in sorted(set(references)):
        default_name = "SIPPYCUP_SECRET_" + reference.upper().replace("-", "_")
        if reference in env_names and reference in fds:
            raise RuntimeError(
                f"credential reference {reference!r} has multiple secret sources"
            )
        if reference in env_names:
            name = env_names[reference]
            if name not in environment:
                raise RuntimeError(
                    f"environment variable {name!r} for {reference!r} is not set"
                )
            value = environment[name]
        elif reference in fds:
            chunks = []
            size = 0
            while True:
                chunk = os.read(fds[reference], min(65536, 1024 * 1024 + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > 1024 * 1024:
                    break
            try:
                value = b"".join(chunks).decode()
            except UnicodeDecodeError as error:
                raise RuntimeError(
                    f"secret FD for {reference!r} is not UTF-8"
                ) from error
        elif default_name in environment:
            value = environment[default_name]
        elif provider is None:
            raise RuntimeError(
                f"credential reference {reference!r} has no secret source"
            )
        else:
            value = _provider_secret(
                provider,
                reference,
                _sanitized_environment(
                    secret_names=[
                        *env_names.values(),
                        *(
                            "SIPPYCUP_SECRET_"
                            + item.upper().replace("-", "_")
                            for item in references
                        ),
                    ],
                    environ=environment,
                ),
            )
        value = value.rstrip("\r\n")
        if not value or len(value.encode()) > 1024 * 1024:
            raise RuntimeError(
                f"secret for credential reference {reference!r} is empty or too large"
            )
        result[reference] = value
    return result


def _provider_secret(provider: str, reference: str, environment: dict[str, str]) -> str:
    try:
        process = subprocess.Popen(
            [provider, reference],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=environment,
        )
    except OSError as error:
        raise RuntimeError(f"secret provider could not start for {reference!r}") from error
    assert process.stdout is not None
    retained = bytearray()
    overflow = threading.Event()

    def read() -> None:
        while chunk := process.stdout.read(65536):
            remaining = 1024 * 1024 + 1 - len(retained)
            if remaining > 0:
                retained.extend(chunk[:remaining])
            if len(retained) > 1024 * 1024:
                overflow.set()
        process.stdout.close()

    reader = threading.Thread(target=read, name="secret-provider-stdout", daemon=True)
    reader.start()
    deadline = time.monotonic() + PROVIDER_TIMEOUT_SECONDS
    timed_out = False
    while process.poll() is None:
        if overflow.is_set() or time.monotonic() >= deadline:
            timed_out = not overflow.is_set()
            _stop_group(process, grace=0.2)
            break
        time.sleep(0.01)
    return_code = process.wait()
    # The provider leader may exit after spawning a descendant. Its PGID remains
    # owned until all members are terminated.
    _stop_group(process, grace=0.1)
    reader.join(timeout=1)
    if reader.is_alive():
        raise RuntimeError(f"secret provider pipe did not close for {reference!r}")
    if overflow.is_set():
        raise RuntimeError(f"secret provider output exceeded 1 MiB for {reference!r}")
    if timed_out:
        raise RuntimeError(f"secret provider timed out for {reference!r}")
    if return_code:
        raise RuntimeError(
            f"secret provider failed for credential reference {reference!r}"
        )
    try:
        return retained.decode()
    except UnicodeDecodeError as error:
        raise RuntimeError(
            f"secret provider returned non-UTF-8 output for {reference!r}"
        ) from error


def _redact(command: Sequence[str], secret_values: Sequence[str]) -> list[str]:
    redacted: list[str] = []
    for argument in command:
        value = argument
        for secret in secret_values:
            value = value.replace(secret, "<redacted>")
        redacted.append(value)
    return redacted


def _sanitized_environment(
    secret_values: Sequence[str] = (),
    secret_names: Sequence[str] = (),
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    source = os.environ if environ is None else environ
    names = set(secret_names)
    values = set(secret_values)
    return {
        name: value
        for name, value in source.items()
        if name not in names
        and not name.startswith("SIPPYCUP_SECRET_")
        and value not in values
    }


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _identity(command: str) -> dict[str, Any]:
    resolved = shutil.which(command) or command
    path = Path(resolved)
    identity: dict[str, Any] = {"name": path.name, "path": str(path)}
    try:
        identity["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        identity["sha256"] = None
    return identity


def _bundled_runner() -> str:
    installed = Path("/usr/local/bin/campaign-sipp-runner")
    if installed.is_file():
        return str(installed)
    source = Path(__file__).resolve().parents[2] / "bin" / "campaign-sipp-runner"
    if source.is_file():
        return str(source)
    raise RuntimeError("bundled campaign SIP runner is unavailable")


def strip_media_payload(
    capture: Path,
    media_ports: dict[str, int],
    signaling_ports: Sequence[int],
) -> None:
    """Truncate UDP media packets after their UDP header in a classic PCAP."""
    raw = capture.read_bytes()
    if len(raw) < 24:
        raise RuntimeError("capture is too short to sanitize")
    magic = raw[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise RuntimeError("retainPayload=false requires classic PCAP capture")
    output = bytearray(raw[:24])
    offset = 24
    signal_set = set(signaling_ports)
    while offset < len(raw):
        if offset + 16 > len(raw):
            raise RuntimeError("capture record header is truncated")
        seconds, fraction, included, original = struct.unpack(
            endian + "IIII", raw[offset : offset + 16]
        )
        offset += 16
        if offset + included > len(raw):
            raise RuntimeError("capture packet is truncated")
        packet = raw[offset : offset + included]
        offset += included
        keep = _media_header_length(packet, media_ports, signal_set)
        if keep is not None:
            packet = packet[:keep]
        output.extend(
            struct.pack(endian + "IIII", seconds, fraction, len(packet), original)
        )
        output.extend(packet)
    temporary = capture.with_name(f".{capture.name}.{random.token_hex(4)}.tmp")
    try:
        temporary.write_bytes(output)
        os.replace(temporary, capture)
    finally:
        temporary.unlink(missing_ok=True)


def _media_header_length(
    packet: bytes,
    media_ports: dict[str, int],
    signaling_ports: set[int],
) -> int | None:
    if len(packet) < 14:
        return None
    network = 14
    ether_type = int.from_bytes(packet[12:14], "big")
    if ether_type == 0x8100 and len(packet) >= 18:
        ether_type = int.from_bytes(packet[16:18], "big")
        network = 18
    if ether_type == 0x0800 and len(packet) >= network + 20:
        if packet[network + 9] != 17:
            return None
        udp = network + (packet[network] & 0x0F) * 4
    elif ether_type == 0x86DD and len(packet) >= network + 40:
        if packet[network + 6] != 17:
            return None
        udp = network + 40
    else:
        return None
    if len(packet) < udp + 8:
        return None
    source = int.from_bytes(packet[udp : udp + 2], "big")
    destination = int.from_bytes(packet[udp + 2 : udp + 4], "big")
    if source in signaling_ports or destination in signaling_ports:
        return None
    start, end = media_ports["start"], media_ports["end"]
    if start <= source <= end or start <= destination <= end:
        # Preserve UDP plus the fixed RTP header (V/PT, sequence, timestamp,
        # SSRC) while dropping CSRC/extensions and encoded media bytes.
        return min(len(packet), udp + 8 + 12)
    return None


def _used_destinations(plan: dict[str, Any]) -> list[dict[str, Any]]:
    used = {step["target"] for step in plan["steps"]}
    return [
        destination
        for destination in plan["resolvedDestinations"]
        if destination["target"] in used
    ]


def sip_options_preflight(destination: dict[str, Any]) -> tuple[bool, str]:
    address = destination["address"]
    port = destination["port"]
    transport = destination["transport"]
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    call_id = random.token_hex(12)
    host = f"[{address}]" if family == socket.AF_INET6 else address
    request = (
        f"OPTIONS sip:{host}:{port} SIP/2.0\r\n"
        f"Via: SIP/2.0/{transport.upper()} 127.0.0.1;branch=z9hG4bK{random.token_hex(8)}\r\n"
        "From: <sip:sippycup@localhost>;tag=preflight\r\n"
        f"To: <sip:{host}:{port}>\r\n"
        f"Call-ID: {call_id}@localhost\r\n"
        "CSeq: 1 OPTIONS\r\n"
        "Max-Forwards: 1\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode()
    try:
        if transport == "udp":
            with socket.socket(family, socket.SOCK_DGRAM) as connection:
                connection.settimeout(2)
                connection.sendto(request, (address, port))
                response = connection.recv(4096)
        else:
            with socket.create_connection((address, port), timeout=2) as raw:
                connection = raw
                if transport == "tls":
                    context = ssl.create_default_context()
                    connection = context.wrap_socket(raw, server_hostname=address)
                connection.sendall(request)
                response = connection.recv(4096)
    except (OSError, ssl.SSLError) as error:
        return False, f"{type(error).__name__}: {error}"
    first_line = response.split(b"\r\n", 1)[0].decode(errors="replace")
    return first_line.startswith("SIP/2.0 "), first_line


def _stop_group(process: subprocess.Popen[bytes], grace: float = 2.0) -> None:
    pgid = process.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        process.poll()
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.01)
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=max(grace, 0.1))
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    kill_deadline = time.monotonic() + max(grace, 0.1)
    while time.monotonic() < kill_deadline:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.01)


def execute_campaign(
    plan: dict[str, Any],
    *,
    manifest_bytes: bytes,
    run_root: Path,
    interface: str = "any",
    runner: Sequence[str] | None = None,
    secret_values: Mapping[str, str] | None = None,
    capture_command: Sequence[str] | None = None,
    report_command: Sequence[str] | None = None,
    preflight: Preflight = sip_options_preflight,
    allow_test_runner: bool = False,
    secret_env_names: Sequence[str] = (),
) -> tuple[RunResult, Path]:
    # Authorization rebind is deliberately the first operation: no directory,
    # process, resolver, or packet exists before both checks succeed.
    validate_plan(plan)
    try:
        verify_frozen_plan(plan, manifest_bytes)
    except ManifestError as error:
        raise RuntimeError(str(error)) from error
    if runner is not None and not allow_test_runner:
        raise RuntimeError("custom runners are disabled for active campaign execution")
    if not plan["evidence"]["capture"]:
        raise RuntimeError("active execution requires evidence.capture=true for watchdogs")
    name = plan["metadata"]["name"]
    run_dir = create_run_directory(run_root, name)
    started = _utc()
    manifest_copy = run_dir / "reviewed-manifest.yaml"
    manifest_copy.write_bytes(manifest_bytes)
    manifest_copy.chmod(0o600)
    _write_json(run_dir / "plan.json", plan)
    _write_json(run_dir / "timestamps.json", {"started": started, "finished": None})
    secret_values = dict(secret_values or {})
    references = sorted(
        {
            step["credentialRef"]
            for step in plan["steps"]
            if step.get("credentialRef") is not None
        }
    )
    missing = sorted(set(references) - set(secret_values))
    if missing:
        raise RuntimeError("unresolved credential references: " + ", ".join(missing))

    capture_path = run_dir / "capture.pcap"
    capture_log = (run_dir / "capture.log").open("wb")
    capture = None
    watchdog: CaptureWatchdog | None = None
    if plan["evidence"]["capture"]:
        capture_argv = (
            [
                shutil.which("tcpdump") or "tcpdump",
                "-i",
                interface,
                "-U",
                "--immediate-mode",
                "-n",
                "-w",
                str(capture_path),
                plan["captureFilter"],
            ]
            if capture_command is None
            else [
                argument.format(
                    capture=str(capture_path),
                    filter=plan["captureFilter"],
                    interface=interface,
                )
                for argument in capture_command
            ]
        )
    else:
        capture_argv = []
    runner_argv = list(runner or [_bundled_runner()])
    report_argv = (
        [shutil.which("sippycup-report") or "sippycup-report", str(capture_path)]
        if report_command is None
        else [
            argument.format(capture=str(capture_path))
            for argument in report_command
        ]
    )
    redactions = list(secret_values.values())
    child_environment = _sanitized_environment(redactions, secret_env_names)
    _write_json(
        run_dir / "commands.json",
        {
            "capture": _redact(capture_argv, redactions),
            "runner": _redact(runner_argv, redactions),
            "report": _redact(report_argv, redactions),
        },
    )
    _write_json(
        run_dir / "versions.json",
        {
            "campaign": "sippycup.dev/campaign-run/v1",
            "python": os.sys.version.split()[0],
            "runner": _identity(runner_argv[0]),
            "capture": _identity(capture_argv[0]) if capture_argv else None,
            "report": _identity(report_argv[0]),
        },
    )
    preflight_results: list[dict[str, Any]] = []
    result = RunResult(1, "failed", 0)
    cancel_signal: int | None = None
    previous_handlers: dict[int, Any] = {}

    def request_cancel(signum: int, _frame: object) -> None:
        nonlocal cancel_signal
        if cancel_signal is None:
            cancel_signal = signum

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.signal(signum, request_cancel)
    try:
        if capture_argv:
            capture = subprocess.Popen(
                capture_argv,
                stdin=subprocess.DEVNULL,
                stdout=capture_log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                env=child_environment,
            )
            ready_deadline = time.monotonic() + 3
            while not capture_path.exists():
                if cancel_signal is not None:
                    code = 130 if cancel_signal == signal.SIGINT else 143
                    result = RunResult(code, "cancelled", 0)
                    raise _FinishExecution
                if capture.poll() is not None:
                    raise RuntimeError("capture process failed during startup")
                if time.monotonic() >= ready_deadline:
                    raise RuntimeError("capture process did not become ready")
                time.sleep(0.02)
            if capture.poll() is not None:
                raise RuntimeError("capture process died after readiness")
            watchdog = CaptureWatchdog(
                capture_path, plan["authorization"]["hardMaxima"]
            )
            watchdog.start()

        def traffic_stop_reason() -> str | None:
            if capture is not None and capture.poll() is not None:
                return "capture_process_died"
            return watchdog.violation() if watchdog is not None else None

        for destination in _used_destinations(plan):
            if cancel_signal is not None:
                code = 130 if cancel_signal == signal.SIGINT else 143
                result = RunResult(code, "cancelled", 0)
                raise _FinishExecution
            ok, detail = preflight(destination)
            preflight_results.append(
                {
                    "target": destination["target"],
                    "address": destination["address"],
                    "port": destination["port"],
                    "transport": destination["transport"],
                    "ok": ok,
                    "detail": _redact([detail], redactions)[0],
                }
            )
            if cancel_signal is not None:
                _write_json(run_dir / "preflight.json", preflight_results)
                code = 130 if cancel_signal == signal.SIGINT else 143
                result = RunResult(code, "cancelled", 0)
                raise _FinishExecution
            if (traffic_reason := traffic_stop_reason()) is not None:
                result = RunResult(1, traffic_reason, 0)
                raise _FinishExecution
            if not ok:
                _write_json(run_dir / "preflight.json", preflight_results)
                result = RunResult(1, "preflight_failed", 0)
                raise _FinishExecution
        _write_json(run_dir / "preflight.json", preflight_results)

        def runner_input(step: dict[str, Any]) -> bytes:
            credentials = {}
            reference = step.get("credentialRef")
            if reference is not None:
                credentials[reference] = secret_values[reference]
            envelope = {"step": step, "credentials": credentials}
            return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode() + b"\n"

        result = run_plan(
            plan,
            runner_argv,
            run_dir / "events.jsonl",
            output_limit=0 if secret_values else 256 * 1024,
            runner_input=runner_input,
            redactions=list(secret_values.values()),
            child_env=child_environment,
            external_stop=traffic_stop_reason,
        )
    except _FinishExecution:
        pass
    finally:
        capture_died_early = capture is not None and capture.poll() is not None
        if capture is not None:
            _stop_group(capture)
        if watchdog is not None:
            time.sleep(0.05)
            watchdog.stop()
            if (
                (traffic_reason := watchdog.violation()) is not None
                and result.state == "succeeded"
            ):
                result = RunResult(1, traffic_reason, result.completed_steps)
        if capture_died_early and result.state == "succeeded":
            result = RunResult(1, "capture_process_died", result.completed_steps)
        capture_log.close()
        if capture_path.exists() and not plan["evidence"]["retainPayload"]:
            strip_media_payload(
                capture_path,
                plan["authorization"]["mediaPorts"],
                plan["authorization"]["signalingPorts"],
            )
        if capture_path.exists():
            with (run_dir / "report.txt").open("wb") as report_stdout, (
                run_dir / "report.stderr"
            ).open("wb") as report_stderr:
                try:
                    report = subprocess.Popen(
                        report_argv,
                        stdin=subprocess.DEVNULL,
                        stdout=report_stdout,
                        stderr=report_stderr,
                        start_new_session=True,
                        env=child_environment,
                    )
                except OSError as error:
                    report_code = 127
                    report_stderr.write(
                        f"report startup failed: {type(error).__name__}: {error}\n".encode()
                    )
                else:
                    report_deadline = time.monotonic() + 30
                    report_timed_out = False
                    while report.poll() is None:
                        if cancel_signal is not None:
                            _stop_group(report, grace=0.2)
                            break
                        if time.monotonic() >= report_deadline:
                            report_timed_out = True
                            _stop_group(report, grace=0.2)
                            break
                        time.sleep(0.02)
                    report_code = report.wait()
                    if report_timed_out:
                        report_stderr.write(b"\nreport timed out\n")
            if cancel_signal is not None:
                code = 130 if cancel_signal == signal.SIGINT else 143
                result = RunResult(code, "cancelled", result.completed_steps)
            elif report_code != 0 and result.state == "succeeded":
                result = RunResult(1, "report_failed", result.completed_steps)
        else:
            (run_dir / "report.txt").write_text("capture disabled or unavailable\n")
            (run_dir / "report.stderr").write_text("")
        _write_json(
            run_dir / "result.json",
            {
                "state": result.state,
                "exitCode": result.exit_code,
                "completedSteps": result.completed_steps,
            },
        )
        _write_json(
            run_dir / "timestamps.json",
            {"started": started, "finished": _utc()},
        )
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        from sippycup.evidence import write_evidence_manifest

        write_evidence_manifest(run_dir)
    return result, run_dir
