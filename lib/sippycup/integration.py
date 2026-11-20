"""Evidence-directory and tool integration for supervised campaigns."""

from __future__ import annotations

import json
import hashlib
from collections import deque
import ipaddress
import os
import re
import secrets as random
import shutil
import signal
import socket
import struct
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from sippycup import approval as approval_rules
from sippycup import capture_scope, options, overlap_record
from sippycup.campaign import ManifestError, verify_frozen_plan
from sippycup.runtime import RunResult, RuntimeError, run_plan, validate_plan


Preflight = Callable[[dict[str, Any]], tuple[bool, str]]
PROVIDER_TIMEOUT_SECONDS = 2.0


class _FinishExecution(Exception):
    """Internal non-error control flow used so cleanup can update the result."""


class CaptureStartFailed(RuntimeError):
    """Packet capture never started, so no step ran and nothing was sent.

    ``execute`` removes the run directory (it holds only this tool's own
    copies of the plan and manifest) so a failed start is not reported as a
    failed campaign run against the target.
    """


def capture_start_failure_text(said: str) -> str:
    """Why the capture did not start, from what the capture tool wrote, and what to do.

    Two causes look alike from outside and need opposite fixes: an interface
    name that does not exist where the command runs (leave out --interface),
    and a missing capture permission (run through the launcher).
    """
    lines = [line.strip() for line in said.splitlines() if line.strip()]
    text = " ".join(lines).lower()
    last = lines[-1][:200] if lines else ""
    if last.startswith("(") and last.endswith(")"):
        last = last[1:-1]  # the capture tool's own last line is often "(No such device exists)"
    head = (
        "packet capture could not start"
        + (f" ({last})" if last else "")
        + ". Nothing was sent, and the run directory was removed. "
    )
    interface = (
        "No such interface: no network interface has the name given to --interface where the "
        "command runs (the launcher's container does not have your host's interfaces, and `lo` is "
        "right only with --practice). Leave out --interface (the default, `any`, captures on every "
        "interface) and give the same command again"
    )
    permission = (
        "Packet capture needs CAP_NET_RAW, which an unprivileged host or "
        "a rootless host-network container lacks: give the same command "
        "through the launcher, `./bin/sippycup campaign run ...`, which "
        "runs it in the image's private network namespace"
    )
    if "no such device" in text or "no such interface" in text or "siocgifhwaddr" in text:
        return head + interface
    if "permission" in text or "not permitted" in text or "cap_net_raw" in text:
        return head + permission
    return (
        head + "The capture tool did not give a reason this command knows. If you gave --interface, "
        "leave it out (a name that does not exist where the command runs stops the capture). "
        "If you did not start this through the launcher: packet capture needs CAP_NET_RAW, which an "
        "unprivileged host or a rootless host-network container lacks; give the same command "
        "through `./bin/sippycup campaign run ...`"
    )


class AuthorizationLapsed(RuntimeError):
    """The approval does not cover this run; raised before anything exists."""


class CaptureWatchdog:
    """Continuously enforce traffic ceilings from an immediate-mode PCAP.

    Every record tcpdump writes counts against the packet, byte, and rate
    ceilings, including RTP to and from authorized media networks (the
    capture filter covers them, see ``sippycup.capture_scope``). Records that
    are media by the payload-stripping rule (UDP with a port in the media
    range and no signaling port) are also counted separately as
    ``mediaPackets`` for the evidence.

    Calls are counted by cleartext ``INVITE``, so TLS calls are invisible here.
    ``ceilings.calls`` holds for them through the plan-time bound in
    ``runtime._validate_plan`` (one call per call step, summed against
    ``hardMaxima.calls``); see docs/CAMPAIGN-MANIFEST.md.
    """

    def __init__(
        self,
        capture: Path,
        maxima: Mapping[str, int],
        *,
        media_ports: Mapping[str, int] | None = None,
        signaling_ports: Sequence[int] = (),
    ) -> None:
        self.capture = capture
        self.maxima = maxima
        self.media_ports = media_ports
        self.signaling_ports = frozenset(signaling_ports)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._violation: str | None = None
        self._counts = {"packets": 0, "bytes": 0, "calls": 0, "mediaPackets": 0}
        self._thread = threading.Thread(
            target=self._run, name="campaign-capture-watchdog", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        """Stop after one final pass over every complete record already written."""
        self._stop.set()
        self._thread.join(timeout=2)

    def violation(self) -> str | None:
        with self._lock:
            return self._violation

    def counts(self) -> dict[str, int]:
        """What the watchdog has counted so far (records it read from the capture)."""
        with self._lock:
            return dict(self._counts)

    def _fail(self, reason: str) -> None:
        with self._lock:
            if self._violation is None:
                self._violation = reason

    def _run(self) -> None:
        offset = 24
        endian: str | None = None
        linktype: int | None = None
        packets = 0
        byte_count = 0
        calls = 0
        media_packets = 0
        packet_times: deque[float] = deque()
        call_times: deque[float] = deque()
        seen_call_ids: set[bytes] = set()
        final_pass = False
        while True:
            if not final_pass and self._stop.is_set():
                # Capture has stopped: read what it flushed, then exit.
                final_pass = True
            try:
                with self.capture.open("rb") as source:
                    header = source.read(24)
                    source.seek(offset)
                    record_header = source.read(16)
            except OSError:
                if final_pass:
                    return
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
                linktype = struct.unpack(endian + "I", header[20:24])[0] & 0x0FFFFFFF
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
                    if final_pass:
                        return
                    time.sleep(0.01)
                    continue
                if len(packet) < included:
                    if final_pass:
                        return
                    time.sleep(0.01)
                    continue
                offset += 16 + included
                timestamp = seconds + fraction / 1_000_000
                packets += 1
                byte_count += original
                if (
                    self.media_ports is not None
                    and linktype is not None
                    and capture_scope.media_header_length(
                        linktype, packet, self.media_ports, self.signaling_ports
                    ) is not None
                ):
                    media_packets += 1
                packet_times.append(timestamp)
                while packet_times and packet_times[0] < timestamp - 1:
                    packet_times.popleft()
                if b"INVITE " in packet:
                    # A call is a dialog, not a packet: a UDP retransmission
                    # or the single digest re-send of an INVITE keeps its
                    # Call-ID. An INVITE without a readable Call-ID counts
                    # as a new call (fail closed).
                    call_id = _invite_call_id(packet)
                    if call_id is None or call_id not in seen_call_ids:
                        if call_id is not None and len(seen_call_ids) < 65536:
                            seen_call_ids.add(call_id)
                        calls += 1
                        call_times.append(timestamp)
                    while call_times and call_times[0] < timestamp - 1:
                        call_times.popleft()
                with self._lock:
                    self._counts = {
                        "packets": packets,
                        "bytes": byte_count,
                        "calls": calls,
                        "mediaPackets": media_packets,
                    }
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
            elif final_pass:
                return
            else:
                time.sleep(0.01)


_CALL_ID = re.compile(rb"\r\n(?:call-id|i)[ \t]*:[ \t]*([^\r\n]{1,256})", re.I)


def _invite_call_id(packet: bytes) -> bytes | None:
    """Return the Call-ID of an INVITE request in ``packet``, if readable."""
    start = packet.find(b"INVITE ")
    if start < 0:
        return None
    match = _CALL_ID.search(packet, start)
    return match.group(1).strip() if match else None


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def create_run_directory(root: Path, campaign: str) -> Path:
    # A run root this call creates is private like the run directories in it.
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
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


SIPP_RUNNER = "campaign-sipp-runner"
SOFTPHONE_RUNNER = "campaign-softphone-runner"
SOFTPHONE_OUTPUT_LIMIT = 16 * 1024
# An OPTIONS step never receives a credential (see runner_input) and its output
# is redacted like every other step's, so its one-line JSON summary may be
# kept even when the campaign holds secrets.
OPTIONS_OUTPUT_LIMIT = 4 * 1024


def _bundled_runner(name: str = SIPP_RUNNER) -> str:
    installed = Path("/usr/local/bin") / name
    if installed.is_file():
        return str(installed)
    source = Path(__file__).resolve().parents[2] / "bin" / name
    if source.is_file():
        return str(source)
    raise RuntimeError(f"bundled campaign runner {name} is unavailable")


def select_runner(step: Mapping[str, Any]) -> str:
    """Name the bundled runner for a frozen step.

    The choice is a pure function of the reviewed plan: a call that names a
    dial destination or carries a credential reference needs the softphone
    runner (SIPp would expose a password in argv and always dials
    ``service``). OPTIONS and plain credential-free calls keep the SIPp runner.
    """
    if step["type"] == "call" and (
        "dial" in step or step.get("credentialRef") is not None or "tls" in step
        # DTMF and SRTP are performed only by the PJSUA softphone runner.
        or "call" in step or "media" in step
    ):
        # A reviewed TLS server name or trust anchor needs a client that
        # verifies the certificate; the bundled SIPp TLS client does not.
        return SOFTPHONE_RUNNER
    return SIPP_RUNNER


def target_tls(plan: Mapping[str, Any]) -> dict[str, dict[str, Any] | None]:
    """The frozen TLS block of each target (validation keeps it uniform)."""
    result: dict[str, dict[str, Any] | None] = {}
    for step in plan["steps"]:
        result.setdefault(step["target"], step.get("tls"))
    return result


def verified_trust_anchors(plan: Mapping[str, Any]) -> dict[str, bytes]:
    """Read every frozen CA file once and refuse any whose digest changed.

    Runs before any directory, process, or packet exists. The returned bytes
    are what the in-process preflight uses; each runner re-checks the digest
    of the bytes it loads itself.
    """
    from sippycup.tls_trust import TrustError, read_verified_ca

    anchors: dict[str, bytes] = {}
    for tls in target_tls(plan).values():
        if tls is None or tls["caFile"] is None or tls["caFile"] in anchors:
            continue
        try:
            anchors[tls["caFile"]] = read_verified_ca(tls["caFile"], tls["caSha256"])
        except TrustError as error:
            raise RuntimeError(f"{error}; refusing to execute, nothing was sent") from error
    return anchors


def _bundled_runners(names: Sequence[str]) -> dict[str, list[str]]:
    return {name: [_bundled_runner(name)] for name in names}


def _runner_ranges(names: Mapping[int, str]) -> list[dict[str, Any]]:
    """Run-length encode step-to-runner selection so metadata stays bounded."""
    ranges: list[dict[str, Any]] = []
    for index in sorted(names):
        name = names[index]
        if ranges and ranges[-1]["runner"] == name and ranges[-1]["lastStep"] == index - 1:
            ranges[-1]["lastStep"] = index
        else:
            ranges.append({"firstStep": index, "lastStep": index, "runner": name})
    return ranges


def _step_artifact_directory(run_dir: Path, step: Mapping[str, Any]) -> Path:
    return run_dir / "steps" / f"{step['index']:06d}"


def strip_media_payload(
    capture: Path,
    media_ports: dict[str, int],
    signaling_ports: Sequence[int],
) -> None:
    """Truncate UDP media records after the fixed RTP header in a classic PCAP.

    The link type comes from the PCAP header: Ethernet (``-i lo``), Linux
    cooked SLL and SLL2 (``-i any``), and raw IP are understood. Any other
    link type is refused rather than kept with media payload.
    """
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
    linktype = struct.unpack(endian + "I", raw[20:24])[0] & 0x0FFFFFFF
    if linktype not in capture_scope.SUPPORTED_LINKTYPES:
        raise RuntimeError(f"retainPayload=false cannot sanitize PCAP link type {linktype}")
    output = bytearray(raw[:24])
    offset = 24
    signal_set = frozenset(signaling_ports)
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
        # Preserve UDP plus the fixed RTP header (V/PT, sequence, timestamp,
        # SSRC) while dropping CSRC/extensions and encoded media bytes.
        keep = capture_scope.media_header_length(linktype, packet, media_ports, signal_set)
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


def _used_destinations(plan: dict[str, Any]) -> list[dict[str, Any]]:
    used = {step["target"] for step in plan["steps"]}
    return [
        destination
        for destination in plan["resolvedDestinations"]
        if destination["target"] in used
    ]


def _local_source_address(address: str, port: int) -> str | None:
    """The kernel's source address toward ADDRESS; UDP connect sends nothing.

    Campaign runners do not bind a source address, so this is the address
    every step and preflight to that destination sends from (the softphone
    runner advertises the same lookup in its Contact and SDP).
    """
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as probe:
            probe.connect((address, port))
            return str(ipaddress.ip_address(probe.getsockname()[0]))
    except (OSError, ValueError):
        return None


def local_source_addresses(plan: dict[str, Any]) -> list[str]:
    """This run's own source addresses toward its approved destinations (bn-2yib).

    Recorded in result.json so the evidence privacy lint can tell the
    assessor's own address from an unexpected party in the capture.
    """
    found: list[str] = []
    for destination in _used_destinations(plan):
        local = _local_source_address(destination["address"], destination["port"])
        if local is not None and local not in found:
            found.append(local)
    return found


_STEP_ENDED = {
    "step.succeeded", "step.failed", "step.timed_out", "step.cancelled", "step.start_failed",
}


def call_media_record(
    run_dir: Path, plan: Mapping[str, Any], softphone_steps: Sequence[int]
) -> dict[str, Any] | None:
    """The run's ``call-media.json``: each softphone call's local RTP port (bn-3oib).

    The port is the one PJSUA advertised in its SDP offer (from the step's
    softphone.json); the window is the step's start and end in events.jsonl.
    ``None`` when no softphone step started. A started step without a usable
    port makes the record incomplete, so the oracle does not rely on it for
    ports it does not list.
    """
    from sippycup_oracle.call_media import call_media_document, recorded_call

    windows: dict[int, list[int | None]] = {}
    try:
        with (run_dir / "events.jsonl").open(encoding="utf-8") as handle:
            for line in handle:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                step = event.get("step") if isinstance(event, dict) else None
                at = event.get("timeUnixNs") if isinstance(event, dict) else None
                if type(step) is not int or type(at) is not int:
                    continue
                if event.get("event") == "step.started":
                    windows[step] = [at, None]
                elif event.get("event") in _STEP_ENDED and step in windows:
                    windows[step][1] = at
    except OSError:
        return None
    wanted = set(softphone_steps)
    by_index = {step["index"]: step for step in plan["steps"]}
    started = sorted(index for index in windows if index in wanted)
    if not started:
        return None
    calls: list[dict[str, Any] | None] = []
    for index in started:
        begin, end = windows[index]
        step = by_index[index]
        try:
            summary = json.loads(
                (_step_artifact_directory(run_dir, step) / "softphone.json").read_text(
                    encoding="utf-8"
                )
            )
        except (OSError, ValueError):
            summary = {}
        destination = step["destination"]
        calls.append(
            recorded_call(
                f"step {index}",
                destination["transport"],
                _local_source_address(destination["addresses"][0], destination["port"]),
                summary.get("localRtpPort") if isinstance(summary, dict) else None,
                begin,
                end if end is not None else time.time_ns(),
            )
        )
    return call_media_document(calls, placed=len(started))


def sip_options_preflight(
    destination: dict[str, Any],
    *,
    tls_server_name: str | None = None,
    tls_ca_file: str | None = None,
    tls_ca_data: bytes | None = None,
) -> tuple[bool, str]:
    """Reachability preflight: ok when any final response arrived.

    The transaction lives in ``sippycup.options``. ``detail`` is the status
    line for a response (so ``options.status_of_detail`` recovers the class)
    and a categorized error otherwise. TLS always verifies; the keyword
    arguments let a reviewed TLS server name and trust anchor be passed down.
    A server name is also the SIP domain of the Request-URI and To; the
    connection still goes only to ``destination["address"]``.
    """
    try:
        result = options.send_options(
            destination["address"],
            destination["port"],
            destination["transport"],
            timeout=options.DEFAULT_TIMEOUT_SECONDS,
            tls_server_name=tls_server_name,
            tls_ca_file=tls_ca_file,
            tls_ca_data=tls_ca_data,
            request_host=tls_server_name,
        )
    except options.OptionsUsageError as error:
        return False, f"usage: {error}"
    return result.responded, result.detail()


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


def _nat_addresses(run_dir: Path) -> list[str]:
    """Addresses the target saw as our source, from the call steps' PJSUA logs."""
    from sippycup_softphone.driver import nat_addresses

    found: list[str] = []
    for log in sorted(run_dir.glob("steps/*/softphone.log")):
        try:
            text = log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for item in nat_addresses(text):
            if item["address"] not in found:
                found.append(item["address"])
    return found


def _make_private(run_dir: Path) -> None:
    """Run artifacts are evidence: directories 0700 and files 0600."""
    for directory, _names, files in os.walk(run_dir):
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        for name in files:
            path = os.path.join(directory, name)
            try:
                if not os.path.islink(path):
                    os.chmod(path, 0o600)
            except OSError:
                pass


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
    manifest_path: Path | None = None,
    clock: approval_rules.Clock | None = None,
) -> tuple[RunResult, Path]:
    """Run a frozen plan with capture, watchdogs, and the approval-window gate.

    ``manifest_path`` lets the gate also read a scope file beside the
    manifest; ``clock`` (UTC ``datetime``) is injectable for tests.
    """
    # Everything a run writes, including what tcpdump and the runners create,
    # is private (0700 directories, 0600 files) like call and checks runs.
    old_umask = os.umask(0o077)
    ledger: dict[str, Any] = {}
    try:
        return _execute_campaign(
            plan,
            ledger=ledger,
            manifest_bytes=manifest_bytes,
            run_root=run_root,
            interface=interface,
            runner=runner,
            secret_values=secret_values,
            capture_command=capture_command,
            report_command=report_command,
            preflight=preflight,
            allow_test_runner=allow_test_runner,
            secret_env_names=secret_env_names,
            manifest_path=manifest_path,
            clock=clock,
        )
    except CaptureStartFailed:
        # No step started, so nothing was sent: keep no run directory that
        # the owner report would list as a failed run against the target.
        run_dir = ledger.pop("run_dir", None)
        if run_dir is not None and not (Path(run_dir) / "events.jsonl").exists():
            shutil.rmtree(run_dir, ignore_errors=True)
        elif run_dir is not None:
            ledger["run_dir"] = run_dir
        raise
    finally:
        os.umask(old_umask)
        reservation = ledger.get("reservation")
        if reservation is not None:
            # The rule of every command (bn-y3er): calls of steps that never
            # started, and of softphone steps that never dialed, sent no INVITE.
            reservation.release(
                _unsent_calls(plan, ledger.get("run_dir")),
                "campaign steps that sent no INVITE (never started, or the softphone never dialed)",
            )


def _ledger_record(reservation: Any, run_dir: Path) -> dict[str, str] | None:
    from sippycup import call_ledger

    return call_ledger.run_record(reservation, run_dir)


def _planned_calls(plan: Mapping[str, Any]) -> int:
    return sum(int((step.get("budget") or {}).get("calls") or 0) for step in plan["steps"])


def _unstarted_calls(plan: Mapping[str, Any], run_dir: Path | None) -> int:
    """Calls of steps that ``events.jsonl`` does not show as started (0 when unsure)."""
    planned = _planned_calls(plan)
    if run_dir is None:
        return planned
    events = Path(run_dir) / "events.jsonl"
    if not events.exists():
        return planned
    started: set[int] = set()
    try:
        for line in events.read_text(encoding="utf-8").splitlines():
            entry = json.loads(line)
            if entry.get("event") == "step.started":
                started.add(int(entry["step"]))
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return 0
    return sum(
        int((step.get("budget") or {}).get("calls") or 0)
        for step in plan["steps"]
        if step["index"] not in started
    )


def campaign_call_ceiling(plan: Mapping[str, Any], directory: Path) -> int:
    """The call ceiling a campaign reserves against: the plan's hard maximum, or
    ``limits.calls`` of the scope file beside the manifest when that is lower."""
    ceiling = int(plan["authorization"]["hardMaxima"]["calls"])
    scope_limit = _scope_call_limit(directory)
    return ceiling if scope_limit is None else min(ceiling, scope_limit)


def campaign_calls_status(plan: Mapping[str, Any], manifest_path: Path) -> Any:
    """``Calls: N of M used, K left`` for a plan's engagement, read-only, or None
    for a plan the ledger does not count (no approval, or no call)."""
    from sippycup import call_ledger

    # The approval id the run reserves under (its window gate's).
    approval = approval_rules.plan_window(plan).approval_id
    if not approval or not _planned_calls(plan):
        return None
    directory = Path(manifest_path).parent
    return call_ledger.status(directory, approval, campaign_call_ceiling(plan, directory), context=True)


def _unsent_calls(plan: Mapping[str, Any], run_dir: Path | None) -> int:
    """Calls of steps that sent no INVITE: never started, or a started softphone
    step whose own softphone.json shows it never dialed (registration failed).

    A step run by SIPp, or a softphone step without a readable record, counts
    once it started (fail closed).
    """
    unsent = _unstarted_calls(plan, run_dir)
    if run_dir is None or not (Path(run_dir) / "events.jsonl").exists():
        return unsent
    started: set[int] = set()
    try:
        for line in (Path(run_dir) / "events.jsonl").read_text(encoding="utf-8").splitlines():
            entry = json.loads(line)
            if entry.get("event") == "step.started":
                started.add(int(entry["step"]))
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return unsent
    for step in plan["steps"]:
        calls = int((step.get("budget") or {}).get("calls") or 0)
        if not calls or step["index"] not in started:
            continue
        try:
            record = json.loads(
                (_step_artifact_directory(Path(run_dir), step) / "softphone.json").read_text(
                    encoding="utf-8"
                )
            )
        except (OSError, ValueError):
            continue
        softphone = record.get("softphone") if isinstance(record, dict) else None
        if isinstance(softphone, dict) and softphone.get("dialed") is False:
            unsent += calls
    return unsent


def _scope_call_limit(directory: Path) -> int | None:
    """``limits.calls`` of the scope file beside the manifest, when it states one."""
    path = directory / approval_rules.SCOPE_FILE
    if path.is_symlink() or not path.is_file():
        return None
    try:
        import yaml

        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - the window gate reports an unreadable scope
        return None
    limits = value.get("limits") if isinstance(value, dict) else None
    calls = limits.get("calls") if isinstance(limits, dict) else None
    return calls if type(calls) is int and calls >= 0 else None


def _execute_campaign(
    plan: dict[str, Any],
    *,
    ledger: dict[str, Any],
    manifest_bytes: bytes,
    run_root: Path,
    interface: str,
    runner: Sequence[str] | None,
    secret_values: Mapping[str, str] | None,
    capture_command: Sequence[str] | None,
    report_command: Sequence[str] | None,
    preflight: Preflight,
    allow_test_runner: bool,
    secret_env_names: Sequence[str],
    manifest_path: Path | None,
    clock: approval_rules.Clock | None,
) -> tuple[RunResult, Path]:
    # Authorization rebind is deliberately the first operation: no directory,
    # process, resolver, or packet exists before both checks succeed.
    validate_plan(plan)
    try:
        verify_frozen_plan(plan, manifest_bytes)
    except ManifestError as error:
        raise RuntimeError(str(error)) from error
    # The approval window (bn-3vxl), also before anything exists: the run must
    # be inside it with room for the preflights and the first step.
    gate = approval_rules.WindowGate(plan, manifest_path=manifest_path, clock=clock)
    preflight_seconds = options.DEFAULT_TIMEOUT_SECONDS * len(_used_destinations(plan))
    first_step = plan["steps"][0]
    refusal = gate.refusal(
        preflight_seconds + first_step["budget"]["durationSeconds"],
        "the preflight and the first step",
    )
    if refusal is not None:
        raise AuthorizationLapsed(refusal.message)
    approval_in_force = None
    if manifest_path is not None:
        # A manifest scope compile wrote must still be what it wrote, from the
        # current scope file (bn-zqe8); a hand-written one is unaffected.
        from sippycup_workbench.scope_derive import approval_record, integrity_error

        problem = integrity_error(manifest_path, manifest_bytes)
        if problem:
            raise AuthorizationLapsed(problem)
        # The approval in force for this run, kept with it (bn-2rgk).
        approval_in_force = approval_record(manifest_path, manifest_bytes)

    def step_gate(step: dict[str, Any]) -> tuple[str, str] | None:
        refusal = gate.refusal(
            step["budget"]["durationSeconds"], f"step {step['index']} ({step['case']})"
        )
        if refusal is None:
            return None
        gate.record_stop(refusal, before="step", step=step["index"])
        return approval_rules.LAPSED, refusal.message
    trust_anchors = verified_trust_anchors(plan)
    tls_by_target = target_tls(plan)
    if runner is not None and not allow_test_runner:
        raise RuntimeError("custom runners are disabled for active campaign execution")
    if not plan["evidence"]["capture"]:
        raise RuntimeError("active execution requires evidence.capture=true for watchdogs")
    name = plan["metadata"]["name"]
    calls = _planned_calls(plan)
    if manifest_path is not None and gate.window.approval_id and calls:
        # The owner's call limit holds for the engagement (bn-2sfn): reserve
        # every planned call in the ledger beside the manifest, under its
        # lock, before anything exists.
        from sippycup import call_ledger

        directory = Path(manifest_path).parent
        ceiling = campaign_call_ceiling(plan, directory)
        try:
            ledger["reservation"] = call_ledger.reserve(
                directory, approval_id=gate.window.approval_id, ceiling=ceiling, calls=calls,
                command="campaign run", source=Path(manifest_path).name,
            )
        except (call_ledger.CeilingRefused, call_ledger.LedgerError) as error:
            raise AuthorizationLapsed(str(error)) from error
    # Before the run directory exists: a run refused here leaves nothing behind.
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
    run_dir = create_run_directory(run_root, name)
    ledger["run_dir"] = run_dir
    from sippycup.call_ledger import write_run_record

    # The reservation that counts this run, before anything else is written.
    write_run_record(ledger.get("reservation"), run_dir)
    started = _utc()
    local_addresses = local_source_addresses(plan)
    manifest_copy = run_dir / "reviewed-manifest.yaml"
    manifest_copy.write_bytes(manifest_bytes)
    manifest_copy.chmod(0o600)
    _write_json(run_dir / "plan.json", plan)
    _write_json(run_dir / "timestamps.json", {"started": started, "finished": None})

    capture_path = run_dir / "capture.pcap"
    # The frozen filter, extended for an older plan with the authorized media
    # term (capture_scope.execution_filter), so the capture and its watchdog
    # see every packet of media the runner admits.
    capture_filter, capture_filter_source = capture_scope.execution_filter(plan)
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
                # Keep the capture owned by the invoking user. Debian's
                # tcpdump otherwise drops to its own account, which a rootless
                # runtime maps to a subordinate UID the host user cannot manage.
                *(("-Z", "root") if os.geteuid() == 0 else ()),
                "-w",
                str(capture_path),
                capture_filter,
            ]
            if capture_command is None
            else [
                argument.format(
                    capture=str(capture_path),
                    filter=capture_filter,
                    interface=interface,
                )
                for argument in capture_command
            ]
        )
    else:
        capture_argv = []
    if runner is not None:
        # In-process test hook only (guarded above): one runner for every step.
        step_runner_names = {step["index"]: "custom" for step in plan["steps"]}
        runner_commands = {"custom": list(runner)}
    else:
        step_runner_names = {step["index"]: select_runner(step) for step in plan["steps"]}
        runner_commands = _bundled_runners(sorted(set(step_runner_names.values())))
    first_runner = step_runner_names[plan["steps"][0]["index"]]
    runner_argv = runner_commands[first_runner]
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
    runner_identities = {
        name: _identity(command[0]) for name, command in sorted(runner_commands.items())
    }
    _write_json(
        run_dir / "commands.json",
        {
            "capture": _redact(capture_argv, redactions),
            "runner": _redact(runner_argv, redactions),
            "runners": {
                name: _redact(command, redactions)
                for name, command in sorted(runner_commands.items())
            },
            "report": _redact(report_argv, redactions),
        },
    )
    _write_json(
        run_dir / "versions.json",
        {
            "campaign": "sippycup.dev/campaign-run/v1",
            "python": os.sys.version.split()[0],
            "runner": runner_identities[first_runner],
            "runners": runner_identities,
            "stepRunners": [
                {**item, "sha256": runner_identities[item["runner"]]["sha256"]}
                for item in _runner_ranges(step_runner_names)
            ],
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

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
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
                    capture_log.flush()
                    try:
                        said = (run_dir / "capture.log").read_text(errors="replace").strip()
                    except OSError:
                        said = ""
                    raise CaptureStartFailed(capture_start_failure_text(said))
                if time.monotonic() >= ready_deadline:
                    raise RuntimeError("capture process did not become ready")
                time.sleep(0.02)
            if capture.poll() is not None:
                raise RuntimeError("capture process died after readiness")
            watchdog = CaptureWatchdog(
                capture_path,
                plan["authorization"]["hardMaxima"],
                media_ports=plan["authorization"]["mediaPorts"],
                signaling_ports=plan["authorization"]["signalingPorts"],
            )
            watchdog.start()

        def traffic_stop_reason() -> str | None:
            if capture is not None and capture.poll() is not None:
                return "capture_process_died"
            if gate.past_end():
                # Backstop for a step that is already running: admission
                # never starts a step that could end after the window, so
                # this fires only when the clock moved.
                gate.record_stop(
                    approval_rules.Refusal(
                        "expired", "the approval window ended while a step was running"
                    ),
                    before="window-end",
                )
                return approval_rules.LAPSED
            return watchdog.violation() if watchdog is not None else None

        remaining_preflights = len(_used_destinations(plan))
        for destination in _used_destinations(plan):
            if cancel_signal is not None:
                code = 130 if cancel_signal == signal.SIGINT else 143
                result = RunResult(code, "cancelled", 0)
                raise _FinishExecution
            refusal = gate.refusal(
                options.DEFAULT_TIMEOUT_SECONDS * remaining_preflights, "the preflight"
            )
            remaining_preflights -= 1
            if refusal is not None:
                gate.record_stop(refusal, before="preflight")
                _write_json(run_dir / "preflight.json", preflight_results)
                result = RunResult(1, approval_rules.LAPSED, 0)
                raise _FinishExecution
            tls = tls_by_target.get(destination["target"])
            if tls is None:
                ok, detail = preflight(destination)
            else:
                ok, detail = preflight(
                    destination,
                    tls_server_name=tls["serverName"],
                    tls_ca_data=trust_anchors.get(tls["caFile"]),
                )
            status_code, status_class = options.status_of_detail(detail)
            preflight_results.append(
                {
                    "target": destination["target"],
                    "address": destination["address"],
                    "port": destination["port"],
                    "transport": destination["transport"],
                    "ok": ok,
                    "detail": _redact([detail], redactions)[0],
                    "statusCode": status_code,
                    "statusClass": status_class,
                    # Any final response proves reachability; a server error
                    # is recorded and surfaced, not silently treated as fine.
                    "warning": (
                        "server_error_response"
                        if ok and status_class in {"5xx", "6xx"}
                        else None
                    ),
                }
            )
            if tls is not None:
                # A response over TLS implies a verified handshake: the client
                # never disables verification.
                preflight_results[-1]["tls"] = {
                    "verified": bool(ok) and "[TLS UNVERIFIED]" not in detail,
                    "serverName": tls["serverName"] or destination["address"],
                    "trust": "file" if tls["caFile"] is not None else "system",
                    "caSha256": tls["caSha256"],
                }
            if preflight_results[-1]["warning"] is not None:
                print(
                    f"campaign: preflight warning: {destination['target']} answered "
                    f"{status_code} ({status_class}); reachable, but the server "
                    "reports an error",
                    file=os.sys.stderr,
                )
            if (
                plan["authorization"]["stopConditions"].get("preflightServerError") is True
                and ok
                and status_class in {"5xx", "6xx"}
            ):
                # Strict preflight, opted into by the reviewed manifest: a
                # server-error answer fails the campaign before any further
                # preflight or step is sent.
                _write_json(run_dir / "preflight.json", preflight_results)
                result = RunResult(1, "preflight_failed", 0)
                raise _FinishExecution
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
            # Only a runner that uses a credential receives it. Selection
            # sends every credentialed call to the softphone runner, so the
            # SIPp runner sees credentials only on OPTIONS steps of a
            # credentialed target, which are sent unauthenticated anyway.
            if (
                reference is not None
                and step["type"] == "call"
                and step_runner_names[step["index"]] != SIPP_RUNNER
            ):
                credentials[reference] = secret_values[reference]
            envelope: dict[str, Any] = {"step": step, "credentials": credentials}
            if step_runner_names[step["index"]] == SOFTPHONE_RUNNER:
                # The softphone runner also needs the frozen media scope, the
                # global expectations, the payload policy, and a private
                # per-step directory for its redacted logs.
                artifacts = _step_artifact_directory(run_dir, step)
                artifacts.parent.mkdir(mode=0o700, exist_ok=True)
                artifacts.mkdir(mode=0o700)
                envelope["context"] = {
                    "authorization": {
                        "networks": plan["authorization"]["networks"],
                        "mediaPorts": plan["authorization"]["mediaPorts"],
                        # Media-only networks, only when the plan has them.
                        **(
                            {"mediaNetworks": plan["authorization"]["mediaNetworks"]}
                            if "mediaNetworks" in plan["authorization"]
                            else {}
                        ),
                        # The owner's media answer, only when the plan has it.
                        **(
                            {"mediaAllowed": plan["authorization"]["mediaAllowed"]}
                            if "mediaAllowed" in plan["authorization"]
                            else {}
                        ),
                    },
                    "expectations": plan["expectations"],
                    "evidence": {"retainPayload": plan["evidence"]["retainPayload"]},
                    # Absolute: --run-root may be relative to the CLI's cwd.
                    "artifactDirectory": str(artifacts.resolve()),
                }
            return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode() + b"\n"

        def output_limit_for(step: dict[str, Any]) -> int:
            if not secret_values:
                return 256 * 1024
            # The softphone runner prints one bounded, structured, redacted
            # result line; other runners stay silent when secrets exist.
            if step_runner_names[step["index"]] == SOFTPHONE_RUNNER:
                return SOFTPHONE_OUTPUT_LIMIT
            if step["type"] == "options":
                return OPTIONS_OUTPUT_LIMIT
            return 0

        result = run_plan(
            plan,
            runner_argv,
            run_dir / "events.jsonl",
            output_limit=0 if secret_values else 256 * 1024,
            runner_input=runner_input,
            redactions=list(secret_values.values()),
            child_env=child_environment,
            external_stop=traffic_stop_reason,
            runner_for=lambda step: runner_commands[step_runner_names[step["index"]]],
            output_limit_for=output_limit_for,
            step_gate=step_gate,
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
        # bn-3oib: the local RTP port of each softphone call, next to the
        # capture, so the oracle can tell whose media is whose.
        try:
            call_media = call_media_record(
                run_dir,
                plan,
                [index for index, name in step_runner_names.items() if name == SOFTPHONE_RUNNER],
            )
        except Exception:  # pragma: no cover - evidence only, never fails the run
            call_media = None
        if call_media is not None:
            _write_json(run_dir / "call-media.json", call_media)
        _write_json(
            run_dir / "result.json",
            {
                "state": result.state,
                "exitCode": result.exit_code,
                "completedSteps": result.completed_steps,
                # What the capture kept and what the watchdog counted from it
                # (before payload stripping), so the evidence shows that the
                # ceilings saw the media too.
                "capture": {
                    "filter": capture_filter,
                    "filterSource": capture_filter_source,
                    "watchdog": watchdog.counts() if watchdog is not None else None,
                },
                # The approval window this run was held to (bound: false for a
                # plan without one) and, when it stopped the run, why.
                "approvalWindow": gate.facts(),
                # Which scope file the manifest was compiled from, kept in
                # approved-scopes/ (bn-2rgk); None for an unbound plan.
                "approvalRecord": approval_in_force,
                # The ledger reservation that counted this run's calls.
                "callLedger": _ledger_record(ledger.get("reservation"), run_dir),
                # The run's own source addresses (route lookup, nothing sent),
                # so the privacy lint does not report them as unexpected.
                "localAddresses": local_addresses,
                # Behind NAT: the address the target saw as our source, from
                # each softphone's own log (PJSUA's address-change line).
                **({"natAddresses": translated} if (translated := _nat_addresses(run_dir)) else {}),
                # Started beside another run of this checkout (finding 6).
                **overlap_record.field(),
            },
        )
        _write_json(
            run_dir / "timestamps.json",
            {"started": started, "finished": _utc()},
        )
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        from sippycup.evidence import write_evidence_manifest

        _make_private(run_dir)
        write_evidence_manifest(run_dir)
        _make_private(run_dir)
    return result, run_dir
