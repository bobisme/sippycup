"""Execute the reviewed one-call plan: one OPTIONS, one softphone call, evidence.

``sippycup call PROFILE --dial DESTINATION`` refuses, sending nothing, unless
the target profile is ready right now and ``target.host`` is itself a literal
approved address. It then starts a target-scoped capture, waits for it to
capture, sends one OPTIONS preflight, places exactly one PJSUA call through
:mod:`sippycup_softphone`, stops capture, and runs the offline report,
triage, and oracle against expectations generated from the profile.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import shlex
import shutil
import signal
import socket
import stat as stat_module
import struct
import subprocess
import sys
import threading
import time
import wave
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, MutableMapping, Sequence

import yaml

from sippycup.integration import (
    _identity,
    _sanitized_environment,
    _stop_group,
    create_run_directory,
    sip_options_preflight,
)
from sippycup_softphone import (
    SoftphoneAccount,
    SoftphoneCall,
    SoftphoneError,
    SoftphoneResult,
    build_config,
    destination_uri,
    place_call,
)
from sippycup_softphone.driver import registrar_uri

from .profile import ProfileError, host_is_approved_literal, load_profile, rehearse

RESULT_VERSION = "sippycup.dev/call-result/v1"
PLAN_VERSION = "sippycup.dev/call-plan/v1"
DEFAULT_DURATION_SECONDS = 10
DEFAULT_ANSWER_TIMEOUT_SECONDS = 30
REGISTRATION_TIMEOUT_SECONDS = 10
CAPTURE_READY_TIMEOUT_SECONDS = 5.0
CAPTURE_TAIL_SECONDS = 0.5
OFFLINE_TIMEOUT_SECONDS = 120
MAX_SECRET_FILE_BYTES = 4096
MAX_PLAY_SECONDS = 600
SILENCE_PEAK = 104  # about -50 dBFS, the canary silence threshold
EXIT_PASS = 0
EXIT_NOT_PASS = 1
EXIT_REFUSED = 2
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_SLUG = re.compile(r"[^A-Za-z0-9._-]+")
PROJECT_ROOT = Path(__file__).resolve().parents[2]


class CallError(ValueError):
    """The guided call cannot start; nothing has been sent."""


@dataclass
class CallOptions:
    profile: Path
    destination: str
    duration: int = DEFAULT_DURATION_SECONDS
    play: Path | None = None
    codecs: tuple[str, ...] = ("PCMU",)
    username: str | None = None
    realm: str = "*"
    register: bool = True
    secret_env: str | None = None
    secret_file: Path | None = None
    run_root: Path | None = None
    engagement: Path | None = None
    media_required: bool = True
    answer_timeout: int = DEFAULT_ANSWER_TIMEOUT_SECONDS
    output_format: str = "human"
    dry_run: bool = False


class TcpdumpCapture:
    """A supervised tcpdump process that reports when it is capturing."""

    def __init__(self, argv: Sequence[str], capture: Path, log: Path, environment: dict[str, str]) -> None:
        self.argv = list(argv)
        self.capture = capture
        self.log = log
        self._log_handle = log.open("wb")
        self.process = subprocess.Popen(
            self.argv,
            stdin=subprocess.DEVNULL,
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=environment,
        )

    def wait_ready(self, timeout: float, cancel: threading.Event) -> str | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if cancel.is_set():
                return "cancelled"
            if self.process.poll() is not None:
                return "capture_failed_to_start"
            try:
                listening = b"listening on" in self.log.read_bytes()
                header = self.capture.exists() and self.capture.stat().st_size >= 24
            except OSError:
                listening = header = False
            if listening and header:
                return None
            time.sleep(0.02)
        return "capture_not_ready"

    def alive(self) -> bool:
        return self.process.poll() is None

    def stop(self) -> None:
        _stop_group(self.process)
        self._log_handle.close()


def _start_tcpdump(argv: Sequence[str], capture: Path, log: Path, environment: dict[str, str]) -> TcpdumpCapture:
    return TcpdumpCapture(argv, capture, log, environment)


def _run_offline(argv: Sequence[str], stdout: Path, stderr: Path, environment: dict[str, str]) -> int:
    with stdout.open("wb") as out, stderr.open("wb") as err:
        try:
            completed = subprocess.run(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                env=environment,
                timeout=OFFLINE_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            err.write(b"\ntimed out\n")
            return 124
        except OSError as error:
            err.write(f"could not start: {type(error).__name__}: {error}\n".encode())
            return 127
    return completed.returncode


def _local_address(host: str, port: int) -> str:
    """Return the source address the kernel would use; connect() on UDP sends nothing."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as probe:
        probe.connect((host, port))
        return str(ipaddress.ip_address(probe.getsockname()[0]))


_VERSION_PATTERNS = {
    "pjsua": re.compile(r"PJ_VERSION\s*:\s*(\S+)"),
    "tcpdump": re.compile(r"^(tcpdump version \S+)", re.M),
    "tshark": re.compile(r"^(TShark \S+ \S+?)\.?$", re.M),
}


def _version_text(argv: Sequence[str], environment: dict[str, str], pattern: re.Pattern[str]) -> str | None:
    try:
        completed = subprocess.run(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = pattern.search(completed.stdout.decode("utf-8", "replace"))
    return match.group(1)[:200] if match else None


def _tool_versions(tools: dict[str, str], environment: dict[str, str]) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": "sippycup.dev/call-versions/v1",
        "python": sys.version.split()[0],
    }
    for name, command in tools.items():
        identity = _identity(command)
        pattern = _VERSION_PATTERNS.get(name)
        identity["version"] = (
            _version_text([command, "--version"], environment, pattern) if pattern else None
        )
        value[name] = identity
    return value


def _tool(name: str, fallback: str) -> str:
    return shutil.which(name) or str(PROJECT_ROOT / "bin" / fallback)


@dataclass
class Dependencies:
    """Injectable side effects so gating and evidence logic are testable."""

    start_capture: Callable[[Sequence[str], Path, Path, dict[str, str]], Any] = _start_tcpdump
    preflight: Callable[[dict[str, Any]], tuple[bool, str]] = sip_options_preflight
    place_call: Callable[..., SoftphoneResult] = place_call
    run_offline: Callable[[Sequence[str], Path, Path, dict[str, str]], int] = _run_offline
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    local_address: Callable[[str, int], str] = _local_address
    tool_versions: Callable[[dict[str, str], dict[str, str]], dict[str, Any]] = _tool_versions
    environ: MutableMapping[str, str] = field(default_factory=lambda: os.environ)
    work_root: Path | None = None
    network_mode: str | None = None
    install_signal_handlers: bool = True
    tools: dict[str, str] = field(
        default_factory=lambda: {
            "tcpdump": shutil.which("tcpdump") or "tcpdump",
            "pjsua": shutil.which("pjsua") or "pjsua",
            "tshark": shutil.which("tshark") or "tshark",
            "report": _tool("sippycup-report", "container-report"),
            "triage": _tool("sippycup-workbench", "sippycup-workbench"),
            "assert": _tool("sippycup-assert", "sippycup-assert"),
        }
    )


def default_work_root() -> Path:
    """The repository work/ tree on the host, or its /work mount in the image."""
    override = os.environ.get("SIPPYCUP_WORK_ROOT")
    if override:
        return Path(override)
    if (PROJECT_ROOT / "work").is_dir():
        return PROJECT_ROOT / "work"
    return Path("/work")


def _utc(instant: datetime) -> str:
    return instant.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _write_json(path: Path, value: Any) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def capture_filter(addresses: Sequence[str], port: int, transport: str) -> str:
    """Capture only approved addresses: the signaling port plus UDP for RTP."""
    if not addresses:
        raise CallError("capture scope needs at least one approved address")
    hosts = " or ".join(f"host {str(ipaddress.ip_address(item))}" for item in addresses)
    protocol = "udp" if transport == "udp" else "tcp"
    return f"({hosts}) and ({protocol} port {int(port)} or udp)"


def generate_expectations(
    approved_addresses: Sequence[str],
    local_address: str | None,
    *,
    media_required: bool,
) -> dict[str, Any]:
    """Oracle expectations derived from the profile; codecs are never assumed."""
    endpoints: list[str] = []
    for address in [*approved_addresses, *([local_address] if local_address else [])]:
        rendered = str(ipaddress.ip_address(address))
        if rendered not in endpoints:
            endpoints.append(rendered)
    return {
        "schema_version": "sippycup.expectations/v1",
        "capture": {"allowed_endpoints": endpoints},
        "expectations": [
            {
                "id": "guided-baseline-call",
                "type": "call_path",
                "on_unknown": "inconclusive",
                "parameters": {
                    "require_bidirectional": media_required,
                    "require_dtmf": False,
                    "allow_symmetric_rtp": True,
                    "max_setup_ms": 5000,
                    "max_loss_fraction": 0.01,
                    "max_duplicates": 0,
                    "max_reordered": 0,
                    "max_jitter_ms": 30,
                    "timestamp_jump_tolerance_ms": 200,
                },
            }
        ],
    }


def effective_duration(requested: int, document: dict[str, Any]) -> tuple[int, int | None]:
    limits = document.get("limits") if isinstance(document.get("limits"), dict) else {}
    limit = limits.get("max_duration_seconds")
    if type(limit) is not int or limit < 1:
        return requested, None
    return min(requested, limit), limit


def planned_wall_seconds(options: CallOptions, duration: int) -> int:
    registration = REGISTRATION_TIMEOUT_SECONDS if options.username and options.register else 0
    return 10 + registration + options.answer_timeout + duration + 15


def gate(
    document: dict[str, Any],
    *,
    now: datetime,
    planned_seconds: int,
    work_root: Path | None = None,
) -> list[str]:
    """Every reason this profile cannot send a packet right now (empty when ready)."""
    rehearsal = rehearse(document, now=now, work_root=work_root)
    errors = list(rehearsal.errors)
    if not host_is_approved_literal(document):
        errors.append(
            "guided calls require target.host itself to be one of the literal approved_addresses"
        )
    valid_until = rehearsal.facts.get("authorization", {}).get("valid_until") if rehearsal.facts else None
    if not errors and valid_until:
        end = now + timedelta(seconds=planned_seconds)
        if end >= datetime.fromisoformat(valid_until):
            errors.append(
                f"authorization expires before the call's latest possible end ({planned_seconds}s from now)"
            )
    return errors


def generate_tone(path: Path, seconds: float = 3.0, rate: int = 8000) -> None:
    """Write a synthetic two-tone 16-bit mono WAV (no recorded voice)."""
    frames = bytearray()
    total = int(seconds * rate)
    for index in range(total):
        frequency = 440 if (index // (rate // 2)) % 2 == 0 else 660
        sample = int(8000 * math.sin(2 * math.pi * frequency * index / rate))
        frames += struct.pack("<h", sample)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as raw, wave.open(raw, "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(rate)
        output.writeframes(bytes(frames))


def _validate_wav(path: Path) -> dict[str, Any]:
    try:
        with wave.open(str(path), "rb") as source:
            channels = source.getnchannels()
            width = source.getsampwidth()
            rate = source.getframerate()
            frames = source.getnframes()
    except (OSError, EOFError, wave.Error) as error:
        raise CallError(f"--play must be a PCM WAV file: {error}") from error
    if width != 2 or channels not in (1, 2) or not 8000 <= rate <= 48000:
        raise CallError("--play must be 16-bit PCM WAV, mono or stereo, 8-48 kHz")
    seconds = frames / rate
    if seconds > MAX_PLAY_SECONDS:
        raise CallError(f"--play must be at most {MAX_PLAY_SECONDS} seconds")
    return {"channels": channels, "sample_rate": rate, "seconds": round(seconds, 3)}


def analyze_recording(path: Path) -> dict[str, Any]:
    """Measure the recorded WAV; only what the file shows is reported."""
    if not path.is_file():
        return {"present": False, "path": path.name}
    try:
        with wave.open(str(path), "rb") as source:
            width = source.getsampwidth()
            rate = source.getframerate()
            channels = source.getnchannels()
            data = source.readframes(source.getnframes())
    except (OSError, EOFError, wave.Error) as error:
        return {"present": True, "path": path.name, "readable": False, "error": str(error)}
    if width != 2 or not data:
        return {
            "present": True,
            "path": path.name,
            "readable": True,
            "seconds": 0.0,
            "silent": None,
            "note": "recording is empty or not 16-bit PCM; silence is unknown",
        }
    count = len(data) // 2
    samples = struct.unpack(f"<{count}h", data[: count * 2])
    peak = max(abs(value) for value in samples)
    rms = math.sqrt(sum(value * value for value in samples) / count)

    def dbfs(value: float) -> float | None:
        return round(20 * math.log10(value / 32768), 1) if value > 0 else None

    return {
        "present": True,
        "path": path.name,
        "readable": True,
        "sample_rate": rate,
        "channels": channels,
        "seconds": round(count / channels / rate, 3),
        "peak": peak,
        "peak_dbfs": dbfs(peak),
        "rms_dbfs": dbfs(rms),
        "silent": peak <= SILENCE_PEAK,
        "silence_threshold_peak": SILENCE_PEAK,
    }


def resolve_password(
    options: CallOptions,
    environ: MutableMapping[str, str],
    work_root: Path,
) -> tuple[str | None, list[str]]:
    """Return the password value and the environment names to scrub.

    The named variable is removed from ``environ`` so no later child can
    inherit it.
    """
    if options.secret_env and options.secret_file:
        raise CallError("use only one of --secret-env and --secret-file")
    if (options.secret_env or options.secret_file) and not options.username:
        raise CallError("a secret source requires --username")
    if options.secret_env:
        name = options.secret_env
        if _ENV_NAME.fullmatch(name) is None:
            raise CallError("--secret-env must name an environment variable")
        if name not in environ:
            raise CallError(f"environment variable {name} is not set")
        value = environ.pop(name)
        os.environ.pop(name, None)
        value = value.rstrip("\r\n")
        if not value:
            raise CallError(f"environment variable {name} is empty")
        return value, [name]
    if options.secret_file:
        path = Path(options.secret_file)
        if not _within(path, work_root):
            raise CallError("--secret-file must be beneath the work directory")
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as error:
            raise CallError(f"cannot open --secret-file: {error.strerror}") from error
        try:
            status = os.fstat(descriptor)
            if not stat_module.S_ISREG(status.st_mode):
                raise CallError("--secret-file must be a regular file")
            if status.st_mode & 0o077:
                raise CallError("--secret-file must be mode 0600 (no group or other access)")
            if status.st_size > MAX_SECRET_FILE_BYTES:
                raise CallError("--secret-file is too large")
            raw = os.read(descriptor, MAX_SECRET_FILE_BYTES + 1)
        finally:
            os.close(descriptor)
        try:
            value = raw.decode("utf-8").rstrip("\r\n")
        except UnicodeDecodeError as error:
            raise CallError("--secret-file must be UTF-8") from error
        if not value:
            raise CallError("--secret-file is empty")
        return value, []
    return None, []


def _display(path: Path, work_root: Path) -> str:
    """Spell a path the way the operator sees it on the host."""
    try:
        relative = path.resolve().relative_to(work_root.resolve())
    except ValueError:
        return str(path)
    return str(Path("work") / relative)


def _slug(name: str) -> str:
    return _SLUG.sub("-", name).strip("-.")[:48] or "profile"


def _network_note(mode: str, host: str) -> str:
    loopback = ipaddress.ip_address(host).is_loopback
    if loopback:
        return "The target is a loopback address inside the container's own network namespace; no NAT applies."
    if mode == "private":
        return (
            "Isolated mode: signaling and media leave the container's private network namespace "
            "through the container runtime's NAT (for example pasta or slirp4netns). The target may "
            "see a translated source address and SDP advertises the container's address, so inbound "
            "RTP can fail to return without any target defect."
        )
    if mode == "host":
        return "Host network namespace: traffic uses the host's addresses directly."
    return "Network namespace is unknown to this process."


def _softphone_parameters(
    options: CallOptions,
    document: dict[str, Any],
    duration: int,
    limit: int | None,
) -> dict[str, Any]:
    target = document.get("target", {})
    host = str(target.get("host", ""))
    port = target.get("port")
    transport = str(target.get("transport", "udp"))
    server_name = target.get("tls_server_name") if transport == "tls" else None
    try:
        uri = destination_uri(options.destination, host, port, transport, server_name)
    except SoftphoneError as error:
        uri = f"<invalid: {error}>"
    return {
        "destination_uri": uri,
        "transport": transport,
        "tls": (
            None
            if transport != "tls"
            else {
                "verify_server": True,
                "server_name": server_name,
                "verify_name": server_name or host,
                "trust": "file" if target.get("tls_ca_file") else "system",
                "ca_file": target.get("tls_ca_file"),
                "connects_to": host,
                "name_pinned_without_dns": server_name is not None,
            }
        ),
        "duration_seconds": {"requested": options.duration, "limit": limit, "effective": duration},
        "answer_timeout_seconds": options.answer_timeout,
        "codecs": list(options.codecs),
        "play": str(options.play) if options.play else "generated synthetic tone (played.wav)",
        "record": "heard.wav in the run directory",
        "account": (
            None
            if not options.username
            else {
                "username": options.username,
                "realm": options.realm,
                "register": options.register,
                "registrar": f"the approved target {host}:{port} ({transport})" if options.register else None,
                "password_source": (
                    f"environment variable {options.secret_env}"
                    if options.secret_env
                    else f"file {options.secret_file}"
                    if options.secret_file
                    else "none"
                ),
            }
        ),
        "signaling_pinned_to_target": True,
        "media_required": options.media_required,
    }


def dry_run_plan(
    options: CallOptions,
    document: dict[str, Any],
    *,
    now: datetime,
    work_root: Path | None = None,
) -> dict[str, Any]:
    from .cli import _one_call_plan

    plan = _one_call_plan(str(options.profile))
    duration, limit = effective_duration(options.duration, document)
    blocking = gate(
        document, now=now, planned_seconds=planned_wall_seconds(options, duration), work_root=work_root
    )
    for message in blocking:
        if message not in plan["blocking_errors"]:
            plan["blocking_errors"].append(message)
    target = document.get("target", {})
    approved = target.get("approved_addresses") if isinstance(target.get("approved_addresses"), list) else []
    try:
        scope = capture_filter(approved, int(target.get("port", 5060)), str(target.get("transport", "udp")))
    except (CallError, ValueError, TypeError):
        scope = None
    return {
        "schema_version": "sippycup.dev/call-dry-run/v1",
        "ready": not blocking,
        "one_call_plan": plan,
        "softphone": _softphone_parameters(options, document, duration, limit),
        "capture_filter": scope,
        "executor": "./bin/sippycup call runs these steps in one isolated container",
        "network_activity": False,
    }


def _journal_command(
    engagement: Path,
    run_dir: Path,
    work_root: Path,
    verdict: str,
    profile_name: str,
) -> list[str]:
    try:
        relative = run_dir.resolve().relative_to(engagement.resolve())
        prefix = relative.as_posix()
    except ValueError:
        prefix = None
    argv = [
        "./bin/sippycup",
        "journal",
        "add",
        _display(engagement, work_root),
        "--kind",
        "action",
        "--summary",
        f"Guided baseline call ({profile_name}): {verdict}",
    ]
    if prefix is not None:
        for name in ("result.json", "evidence-manifest.json", "capture.pcap"):
            argv.extend(["--evidence", f"{prefix}/{name}"])
    return argv


def _scalar_observed(item: dict[str, Any]) -> Any:
    """The assertion's observed value when it is a plain number or string."""
    observed = item.get("observed")
    value = observed.get("value") if isinstance(observed, dict) else None
    return value if isinstance(value, (int, float, str)) else None


def _oracle_summary(path: Path, exit_code: int | None) -> dict[str, Any] | None:
    if exit_code is None:
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"verdict": None, "exit_code": exit_code, "note": "oracle produced no JSON result"}
    streams = document.get("streams", [])
    return {
        "verdict": document.get("verdict"),
        "exit_code": exit_code,
        "summary": document.get("summary"),
        "failed": [item["id"] for item in document.get("assertions", []) if item.get("verdict") == "fail"],
        "failedDetails": [
            {"id": item["id"], "message": item.get("message"), "observed": _scalar_observed(item)}
            for item in document.get("assertions", [])
            if item.get("verdict") == "fail"
        ],
        "unknown": [item["id"] for item in document.get("assertions", []) if item.get("verdict") == "unknown"],
        "stream_directions": sorted({item.get("direction") for item in streams if item.get("direction")}),
        "dialogs": len(document.get("dialogs", [])),
    }


def _triage_summary(path: Path, exit_code: int | None) -> dict[str, Any] | None:
    if exit_code is None:
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"exit_code": exit_code, "note": "triage produced no JSON result"}
    return {
        "exit_code": exit_code,
        "packets": document.get("metadata", {}).get("packets"),
        "protocol_frames": document.get("protocol_frames"),
        "findings": [
            {"code": item.get("code"), "verdict": item.get("verdict")}
            for item in document.get("findings", [])
        ],
    }


# A far end that sends BYE this much earlier than the planned duration (seconds)
# is reported as having hung up early; smaller gaps are clock and timer slack.
EARLY_HANGUP_TOLERANCE_SECONDS = 1.5
_EARLY_STATE = re.compile(r"state changed to EARLY \((\d{3})")
_SDP_RESPONSE = re.compile(
    r"RX \d+ bytes Response msg (?:18\d|2\d\d)/INVITE[^\n]*\n(.*?)--end msg--", re.S
)
_SDP_CONNECTION = re.compile(r"^c=IN IP[46] (\S+)", re.M)


def rejection_verdict(status: int) -> tuple[str, str]:
    """Map a final SIP status of an unanswered call to (verdict, note).

    The verdict names the cause for the statuses an operator meets most, and
    otherwise the status class, so ``call-rejected-5xx`` is never mistaken for
    a timeout.
    """
    if status in (486, 600):
        return "call-busy", f"The far end answered {status}: the callee is busy."
    if status == 603:
        return "call-declined", "The far end answered 603 Decline: the callee refused the call."
    if status in (401, 407):
        return "call-auth-failed", (
            f"The far end answered {status} and the credentials were not accepted, or none were "
            "given (pass --username with --secret-env or --secret-file)."
        )
    if status == 403:
        return "call-forbidden", "The far end answered 403 Forbidden: authenticated or not, the policy refuses this call."
    if status in (404, 410, 604):
        return "call-not-found", f"The far end answered {status}: no such destination."
    if status in (480, 503):
        return "call-unavailable", f"The far end answered {status}: the service or callee is temporarily unavailable."
    if status == 429:
        return "call-rate-limited", "The far end answered 429 Too Many Requests: back off before retrying."
    if status in (488, 606):
        return "call-media-not-acceptable", (
            f"The far end answered {status}: it could not accept the offered media "
            "(codec, encryption, or direction)."
        )
    if 300 <= status < 400:
        return "call-redirected", f"The far end answered {status}; redirects are not followed."
    group = f"{status // 100}xx"
    return f"call-rejected-{group}", f"The far end rejected the call with final status {status}."


def _provisional_text(statuses: Sequence[int]) -> str:
    return ", ".join(str(item) for item in dict.fromkeys(statuses))


def remote_sdp_addresses(log_text: str) -> list[str] | None:
    """Connection addresses in the far end's SDP, from the PJSUA log, or None."""
    found: list[str] = []
    for block in _SDP_RESPONSE.finditer(log_text):
        for address in _SDP_CONNECTION.findall(block.group(1)):
            try:
                rendered = str(ipaddress.ip_address(address))
            except ValueError:
                continue
            if rendered not in found:
                found.append(rendered)
    return found or None


def _peer_unknown_but_approved(
    softphone: dict[str, Any], approved: Sequence[str], remote_media: Sequence[str] | None
) -> bool:
    """True when PJSUA had no media peer yet but the far end's SDP is wholly approved."""
    from sippycup_softphone.driver import _peer_address

    peer = softphone.get("media_peer")
    if peer and _peer_address(str(peer)) is not None:
        return False
    if not remote_media or not approved:
        return False
    allowed = {str(ipaddress.ip_address(item)) for item in approved}
    return all(item in allowed for item in remote_media)


def derive_setup(softphone: dict[str, Any] | None, log_text: str = "") -> dict[str, Any] | None:
    """Call setup facts: seconds to answer and the provisional responses seen.

    ``seconds`` runs from the INVITE's dispatch to the call's confirmation, on
    the softphone driver's clock. ``provisional`` lists the 18x statuses PJSUA
    reported (180 Ringing, 183 Session Progress). RTP that arrives before the
    answer (early media) is part of the PJSUA packet counts.
    """
    if softphone is None or not softphone.get("dialed"):
        return None
    timeline = softphone.get("timeline") or []
    at = {item.get("state"): item.get("at") for item in timeline if isinstance(item, dict)}
    start = at.get("CALLING", at.get("DIALED"))
    seconds = None
    if softphone.get("answered") and start is not None and at.get("CONFIRMED") is not None:
        seconds = round(max(0.0, at["CONFIRMED"] - start), 3)
    provisional = [int(item) for item in _EARLY_STATE.findall(log_text)]
    return {
        "seconds": seconds,
        "provisional": list(dict.fromkeys(provisional)),
        "earlyMedia": 183 in provisional,
    }


def _refine(
    state: str,
    verdict: str,
    code: int,
    notes: list[str],
    *,
    softphone: dict[str, Any] | None,
    oracle: dict[str, Any] | None,
    media_required: bool,
    recording: dict[str, Any] | None,
    requested_seconds: int | None,
    setup: dict[str, Any] | None,
) -> tuple[str, str, int, list[str]]:
    """Replace a bare ``pass`` or ``fail`` with the specific cause the evidence shows."""
    if state != "completed" or softphone is None:
        return state, verdict, code, notes
    if verdict == "fail" and oracle:
        details = oracle.get("failedDetails") or []
        for item in details:
            notes.append(f"Oracle failed {item.get('id')}: {item.get('message')}")
        if details and all(
            str(item.get("id", "")).endswith("media.timing") and "setup exceeded" in str(item.get("message"))
            for item in details
        ):
            seconds = (setup or {}).get("seconds")
            notes.append(
                "The call was answered"
                + (f" after {seconds}s" if seconds is not None else "")
                + ", later than the oracle's setup window (5s); the media itself was not judged late."
            )
            return state, "slow-setup", EXIT_NOT_PASS, notes
        if details and (setup or {}).get("earlyMedia"):
            notes.append(
                "The far end sent 183 Session Progress, so it offered early media. The oracle's "
                "timing and sequence assertions count RTP before the 200 OK as media before answer "
                "or as a timestamp discontinuity at the answer; read assert.json before treating "
                "this as a media fault."
            )
        return state, verdict, code, notes
    if verdict != "pass":
        return state, verdict, code, notes
    connected = softphone.get("connected_seconds")
    if (
        softphone.get("hangup") == "remote"
        and requested_seconds is not None
        and connected is not None
        and connected < requested_seconds - EARLY_HANGUP_TOLERANCE_SECONDS
    ):
        notes.append(
            f"The far end sent BYE after {connected:.1f}s of a planned {requested_seconds}s call "
            "(hangup by the peer, not the caller)."
        )
        return state, "peer-hung-up-early", EXIT_NOT_PASS, notes
    if media_required and recording and recording.get("silent") is True:
        notes.append(
            f"RTP flowed in both directions (PJSUA sent {softphone.get('rtp_tx_packets')}, "
            f"received {softphone.get('rtp_rx_packets')} packets) but heard.wav is digital silence "
            f"(peak {recording.get('peak')}): the far end sent packets that carry no audio."
        )
        return state, "silent-audio", EXIT_NOT_PASS, notes
    return state, verdict, code, notes


def classify(
    *,
    cancelled_signal: int | None,
    stop_reason: str | None,
    preflight_ok: bool | None,
    softphone: dict[str, Any] | None,
    oracle: dict[str, Any] | None,
    media_required: bool,
    network_mode: str,
    host: str,
    tls_media: dict[str, Any] | None = None,
    recording: dict[str, Any] | None = None,
    requested_seconds: int | None = None,
    setup: dict[str, Any] | None = None,
    approved: Sequence[str] = (),
    remote_media: Sequence[str] | None = None,
) -> tuple[str, str, int, list[str]]:
    """Return (state, verdict, exit code, notes): the core verdict, then refinements.

    The refinements (:func:`_refine`) split a bare ``fail`` or ``pass`` into
    the specific cause the evidence shows: a slow setup, a far end that hung
    up early, or audio that is digital silence.
    """
    state, verdict, code, notes = _classify_core(
        cancelled_signal=cancelled_signal, stop_reason=stop_reason, preflight_ok=preflight_ok,
        softphone=softphone, oracle=oracle, media_required=media_required,
        network_mode=network_mode, host=host, tls_media=tls_media, setup=setup,
        approved=approved, remote_media=remote_media,
    )
    return _refine(
        state, verdict, code, notes, softphone=softphone, oracle=oracle,
        media_required=media_required, recording=recording,
        requested_seconds=requested_seconds, setup=setup,
    )


def _classify_core(
    *,
    cancelled_signal: int | None,
    stop_reason: str | None,
    preflight_ok: bool | None,
    softphone: dict[str, Any] | None,
    oracle: dict[str, Any] | None,
    media_required: bool,
    network_mode: str,
    host: str,
    tls_media: dict[str, Any] | None = None,
    setup: dict[str, Any] | None = None,
    approved: Sequence[str] = (),
    remote_media: Sequence[str] | None = None,
) -> tuple[str, str, int, list[str]]:
    """Return (state, verdict, exit code, notes). Unknown stays unknown.

    ``tls_media`` is given for a TLS call: the signaling is encrypted on the
    wire, so the packet oracle cannot reconstruct the dialog. The verdict
    then rests on PJSUA's own signaling facts (including a verified TLS
    handshake) plus RTP decoded from the capture on the negotiated media
    port, and never on the oracle's ``unknown``.
    """
    notes: list[str] = []
    if cancelled_signal is not None:
        return "cancelled", "cancelled", 130 if cancelled_signal == signal.SIGINT else 143, notes
    if stop_reason is not None:
        return "failed", stop_reason, EXIT_NOT_PASS, notes
    if preflight_ok is False:
        return "failed", "preflight-failed", EXIT_NOT_PASS, notes
    if softphone is None:
        return "failed", "call-not-placed", EXIT_NOT_PASS, notes
    error = softphone.get("error")
    if error == "media_peer_outside_scope" and _peer_unknown_but_approved(
        softphone, approved, remote_media
    ):
        # PJSUA prints ``peer=-`` until the first RTP packet arrives, and the
        # softphone driver treats that placeholder as out of scope. The far
        # end's own SDP (from the PJSUA log) names only approved addresses,
        # so nothing arrived from it: a silent far end, not a scope breach.
        notes.append(
            "PJSUA never learned a media address for the far end because no RTP arrived from it, "
            "and the softphone driver hung up the call early; the far end's SDP named only "
            f"approved address(es): {', '.join(remote_media or ())}."
        )
        error = None
    if error == "media_peer_outside_scope":
        notes.append("The negotiated media peer is not an approved address; the call was hung up.")
        return "failed", "media-outside-scope", EXIT_NOT_PASS, notes
    if error in ("tls_verification_failed", "tls_verification_not_observed") or (
        tls_media is not None and softphone.get("tls_verified") is not True
    ):
        notes.append(
            "TLS server verification did not succeed, so PJSUA sent no SIP request on the connection."
            if error == "tls_verification_failed"
            else "TLS verification was not confirmed by PJSUA."
        )
        return "failed", "tls-not-verified", EXIT_NOT_PASS, notes
    if error in ("tls_name_pinning_unavailable", "tls_name_pinning_mismatch"):
        notes.append(
            "The reviewed TLS server name could not be pinned to the literal address in a private "
            "namespace, so PJSUA was not started and nothing was sent by it."
        )
        return "failed", "tls-name-pinning-failed", EXIT_NOT_PASS, notes
    if softphone.get("registered") is False:
        return "failed", "registration-failed", EXIT_NOT_PASS, notes
    if not softphone.get("answered"):
        status = softphone.get("final_status")
        provisional = (setup or {}).get("provisional") or []
        if error == "no_answer_before_timeout":
            notes.append(
                "No final response arrived before the answer timeout"
                + (f" ({_provisional_text(provisional)} was received)" if provisional else " (no provisional response was received)")
                + f"; the caller cancelled the call (final status {status})."
            )
            return "failed", "call-not-answered", EXIT_NOT_PASS, notes
        if status is not None and status >= 300:
            verdict, note = rejection_verdict(status)
            notes.append(note)
            return "failed", verdict, EXIT_NOT_PASS, notes
        if status is not None:
            notes.append(f"The call was not answered; final SIP status {status}.")
        return "failed", "call-not-answered", EXIT_NOT_PASS, notes
    if error is not None:
        return "failed", "call-error", EXIT_NOT_PASS, notes
    tx = softphone.get("rtp_tx_packets")
    rx = softphone.get("rtp_rx_packets")
    if tls_media is not None:
        return _classify_tls(softphone, tls_media, media_required, network_mode, host, notes)
    directions = set((oracle or {}).get("stream_directions") or [])
    inbound_missing = (rx == 0 and bool(tx)) or (
        oracle is not None and bool(directions) and directions == {"caller_to_callee"}
    )
    if media_required and inbound_missing:
        if network_mode == "private" and not ipaddress.ip_address(host).is_loopback:
            notes.append(
                "Signaling succeeded and RTP was sent, but no inbound RTP was observed. In isolated "
                "mode this is consistent with NAT or one-way media and is not, by itself, a target defect."
            )
            return "completed", "possible-nat-one-way-media", EXIT_NOT_PASS, notes
        notes.append("Signaling succeeded and RTP was sent, but no inbound RTP was observed.")
        return "completed", "one-way-media", EXIT_NOT_PASS, notes
    verdict = (oracle or {}).get("verdict")
    if verdict == "pass":
        return "completed", "pass", EXIT_PASS, notes
    if verdict == "fail":
        return "completed", "fail", EXIT_NOT_PASS, notes
    return "completed", "inconclusive", EXIT_NOT_PASS, notes


def _classify_tls(
    softphone: dict[str, Any],
    media: dict[str, Any],
    media_required: bool,
    network_mode: str,
    host: str,
    notes: list[str],
) -> tuple[str, str, int, list[str]]:
    notes.append(
        "Signaling was TLS-encrypted on the wire, so the packet oracle cannot reconstruct the SIP "
        "dialog; its result is recorded but does not decide the verdict. Signaling facts come from "
        f"PJSUA's own log (TLS verified for {softphone.get('tls_server_name')}); media facts come "
        "from the capture, with RTP decoded on the negotiated media port."
    )
    outbound = media.get("outbound")
    inbound = media.get("inbound")
    if outbound is None or inbound is None:
        notes.append(f"RTP in the capture could not be counted: {media.get('note', 'unknown')}.")
        return "completed", "inconclusive", EXIT_NOT_PASS, notes
    if not media_required:
        return "completed", "pass", EXIT_PASS, notes
    if outbound > 0 and inbound > 0:
        return "completed", "pass", EXIT_PASS, notes
    if outbound > 0:
        if network_mode == "private" and not ipaddress.ip_address(host).is_loopback:
            notes.append(
                "Signaling succeeded and RTP was sent, but no inbound RTP was captured. In isolated "
                "mode this is consistent with NAT or one-way media and is not, by itself, a target defect."
            )
            return "completed", "possible-nat-one-way-media", EXIT_NOT_PASS, notes
        notes.append("Signaling succeeded and RTP was sent, but no inbound RTP was captured.")
        return "completed", "one-way-media", EXIT_NOT_PASS, notes
    notes.append("No RTP to or from the negotiated media peer was captured.")
    return "completed", "fail", EXIT_NOT_PASS, notes


def tls_media_argv(tshark: str, capture: Path, peer: str | None) -> list[str] | None:
    """tshark argv that decodes RTP on the negotiated media port, or None."""
    if not peer:
        return None
    from sippycup_softphone.driver import _peer_address, _peer_port

    address = _peer_address(peer)
    port = _peer_port(peer)
    if address is None or port is None:
        return None
    field = "ipv6" if ":" in address else "ip"
    return [
        tshark, "-n", "-r", str(capture), "-d", f"udp.port=={port},rtp",
        "-Y", f"rtp && {field}.addr == {address} && udp.port == {port}",
        "-T", "fields", "-e", f"{field}.src", "-e", f"{field}.dst",
    ]


def count_tls_media(path: Path, peer: str | None, exit_code: int | None) -> dict[str, Any]:
    """Count RTP packets to and from the media peer in tshark field output."""
    from sippycup_softphone.driver import _peer_address

    address = _peer_address(peer) if peer else None
    if address is None:
        return {"outbound": None, "inbound": None, "note": "PJSUA reported no media peer"}
    if exit_code != 0:
        return {"outbound": None, "inbound": None, "note": f"tshark exited {exit_code}"}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        return {"outbound": None, "inbound": None, "note": f"no tshark output: {error.strerror}"}
    outbound = inbound = 0
    for line in lines:
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        if fields[1] == address:
            outbound += 1
        elif fields[0] == address:
            inbound += 1
    return {"peer": peer, "outbound": outbound, "inbound": inbound, "source": "capture"}


def _network_activity(
    *,
    preflight_sent: bool,
    softphone: dict[str, Any] | None,
    target: str,
    network_mode: str,
    loopback: bool = False,
) -> str:
    if not preflight_sent:
        return "none"
    parts = ["1 SIP OPTIONS preflight"]
    placed = False
    if softphone is not None and softphone.get("started"):
        if softphone.get("registration_attempted"):
            parts.append("1 REGISTER exchange (plus unregistration on exit)")
        if softphone.get("dialed"):
            placed = True
            media = " with RTP" if (softphone.get("rtp_tx_packets") or softphone.get("rtp_rx_packets")) else ""
            parts.append(f"1 INVITE dialog{media}")
    if network_mode == "private":
        where = (
            "inside the container's private network namespace (loopback, no NAT)"
            if loopback
            else "from a private network namespace through the runtime's NAT"
        )
    elif network_mode == "host":
        where = "from the host network namespace"
    else:
        where = "from an unknown network namespace"
    summary = f"{', '.join(parts)} to {target} {where}"
    return summary if placed else f"{summary}; no call placed"


def execute(options: CallOptions, deps: Dependencies | None = None) -> tuple[int, dict[str, Any]]:
    """Run the guided call. Returns (exit code, rendered result document).

    Once the run directory exists, every exit writes a result.json: an error
    that escapes the orchestrator becomes an honest ``internal-error`` result
    instead of leaving a directory with no result file.
    """
    state: dict[str, Any] = {}
    try:
        return _execute(options, deps, state)
    except Exception as error:
        if "umask" in state:
            os.umask(state["umask"])
        run_dir = state.get("run_dir")
        if run_dir is None:
            raise
        return _internal_error_result(run_dir, state, error)


def _internal_error_result(
    run_dir: Path, state: dict[str, Any], error: Exception
) -> tuple[int, dict[str, Any]]:
    detail = f"{type(error).__name__}: {error}"
    secret = state.get("password")
    if secret:
        detail = detail.replace(secret, "<redacted>")
    now = _utc(datetime.now(timezone.utc))
    timestamps = {"started": state.get("started", now), "finished": now}
    value: dict[str, Any] = {
        "apiVersion": RESULT_VERSION,
        "state": "failed",
        "verdict": "internal-error",
        "exitCode": EXIT_NOT_PASS,
        "profile": state["profile"],
        "target": state["target"],
        "destinationUri": state["uri"],
        "localAddress": state["local"],
        "networkMode": state["network_mode"],
        "durationSeconds": state["duration"],
        "captureFilter": "",
        "preflight": None,
        "softphone": None,
        "triage": None,
        "oracle": None,
        "recording": None,
        "notes": [
            f"Internal error stopped the run: {detail}",
            "The run stopped outside the normal result path; whether any packet was "
            "sent is unknown. Treat the capture, if any, as the record.",
        ],
        "timestamps": timestamps,
        "runDirectory": _display(run_dir, state["work_root"]),
        "evidenceManifest": "evidence-manifest.json",
        "journalCommand": _journal_command(
            state["engagement"], run_dir, state["work_root"], "internal-error", state["profile"]
        ),
        "networkActivity": "unknown: the run stopped on an internal error before the result was written",
    }
    _write_json(run_dir / "result.json", value)
    from sippycup.evidence import write_evidence_manifest

    try:
        value["evidencePrivacy"] = write_evidence_manifest(run_dir)["privacy"]["status"]
    except Exception as manifest_error:
        value["evidencePrivacy"] = f"manifest-error: {type(manifest_error).__name__}"
    return EXIT_NOT_PASS, value


def _execute(
    options: CallOptions, deps: Dependencies | None, state: dict[str, Any]
) -> tuple[int, dict[str, Any]]:
    deps = deps or Dependencies()
    work_root = deps.work_root or default_work_root()
    network_mode = deps.network_mode or deps.environ.get("SIPPYCUP_NETWORK_MODE", "unknown")
    document = load_profile(options.profile)
    if type(options.duration) is not int or options.duration < 1:
        raise CallError("--duration must be a positive integer")
    if type(options.answer_timeout) is not int or not 1 <= options.answer_timeout <= 120:
        raise CallError("--answer-timeout must be from 1 to 120 seconds")
    duration, limit = effective_duration(options.duration, document)
    planned = planned_wall_seconds(options, duration)
    now = deps.now()

    if options.dry_run:
        plan = dry_run_plan(options, document, now=now, work_root=work_root)
        return (EXIT_PASS if plan["ready"] else EXIT_REFUSED), plan

    blocking = gate(document, now=now, planned_seconds=planned, work_root=work_root)
    if blocking:
        return EXIT_REFUSED, {
            "apiVersion": RESULT_VERSION,
            "state": "blocked",
            "verdict": "blocked",
            "exitCode": EXIT_REFUSED,
            "blockingErrors": blocking,
            "runDirectory": None,
            "networkActivity": "none",
        }

    target = document["target"]
    host = target["host"]
    port = target["port"]
    transport = target["transport"]
    approved = list(target["approved_addresses"])
    profile_name = str(document["name"])
    server_name = target.get("tls_server_name") if transport == "tls" else None
    ca_reference = target.get("tls_ca_file") if transport == "tls" else None
    ca_data: bytes | None = None
    ca_sha256: str | None = None
    if ca_reference is not None:
        from sippycup.tls_trust import TrustError, read_ca

        # Read the reviewed trust anchor once; the preflight loads these
        # bytes from memory and PJSUA a private copy of the same bytes.
        try:
            ca_data, ca_sha256 = read_ca(ca_reference, work_root)
        except TrustError as error:
            raise CallError(str(error)) from error
    try:
        uri = destination_uri(options.destination, host, port, transport, server_name)
    except SoftphoneError as error:
        raise CallError(str(error)) from error

    password, scrub_names = resolve_password(options, deps.environ, work_root)
    secrets = [password] if password else []

    profile_path = Path(options.profile)
    run_root = Path(options.run_root) if options.run_root else profile_path.parent / "calls"
    if not _within(run_root, work_root):
        raise CallError(
            f"--run-root must be beneath the work directory ({work_root}); "
            "pass --run-root work/ENGAGEMENT/calls"
        )
    engagement = Path(options.engagement) if options.engagement else profile_path.parent
    play_info: dict[str, Any] | None = None
    if options.play is not None:
        if not _within(Path(options.play), work_root) or not Path(options.play).is_file():
            raise CallError("--play must be an existing WAV file beneath the work directory")
        play_info = _validate_wav(Path(options.play))
    try:
        local = deps.local_address(host, port)
    except OSError as error:
        raise CallError(f"no route to the approved target: {error}") from error

    # Validate every softphone option, including the password's shape, before
    # any directory, process, or packet exists.
    try:
        build_config(
            SoftphoneCall(
                destination=options.destination, host=host, port=port, transport=transport,
                play_file=Path(__file__), record_file=Path("heard.wav"),
                duration_seconds=duration, log_file=Path("softphone.log"),
                account=(SoftphoneAccount(username=options.username, realm=options.realm)
                         if options.username else None),
                codecs=tuple(options.codecs),
                tls_server_name=server_name,
                tls_ca_file=Path("trust-anchor.pem") if ca_data is not None else None,
            ),
            password=password,
        )
    except SoftphoneError as error:
        raise CallError(str(error)) from error

    child_environment = _sanitized_environment(secrets, scrub_names, environ=deps.environ)
    old_umask = os.umask(0o077)
    state["umask"] = old_umask
    run_dir = create_run_directory(run_root, _slug(profile_name))
    state.update(
        run_dir=run_dir, password=password, profile=profile_name, uri=uri, local=local,
        target={"host": host, "port": port, "transport": transport}, network_mode=network_mode,
        duration={"requested": options.duration, "limit": limit, "effective": duration},
        work_root=work_root, engagement=engagement,
    )
    capture_path = run_dir / "capture.pcap"
    play_path = Path(options.play) if options.play else run_dir / "played.wav"
    timestamps: dict[str, str | None] = {"started": _utc(deps.now())}
    state["started"] = timestamps["started"]
    cancel = threading.Event()
    cancel_signal: list[int] = []
    previous_handlers: dict[int, Any] = {}
    capture: Any = None
    preflight_sent = False
    preflight_ok: bool | None = None
    stop_reason: str | None = None
    softphone_result: dict[str, Any] | None = None
    offline_codes: dict[str, int | None] = {"report": None, "triage": None, "assert": None}
    softphone_call: SoftphoneCall | None = None
    internal_error: str | None = None
    expectations = generate_expectations(approved, local, media_required=options.media_required)
    scope = capture_filter(approved, port, transport)
    interface = str(document.get("capture", {}).get("interface", "any"))
    tools = deps.tools
    capture_argv = [
        tools["tcpdump"], "-i", interface, "-U", "--immediate-mode", "-n",
        "-Z", "root", "-w", str(capture_path), scope,
    ]
    report_argv = [tools["report"], str(capture_path)]
    triage_argv = [tools["triage"], "triage", str(capture_path), "--format", "json"]
    assert_argv = [
        tools["assert"], str(capture_path), "--expect", str(run_dir / "expectations.yaml"),
        "--format", "json",
    ]

    def handle_signal(signum: int, _frame: object) -> None:
        if not cancel_signal:
            cancel_signal.append(signum)
        cancel.set()

    def recheck(stage: str) -> bool:
        nonlocal stop_reason
        errors = gate(
            document,
            now=deps.now(),
            planned_seconds=planned if stage == "preflight" else duration + 30,
            work_root=work_root,
        )
        if errors:
            stop_reason = "authorization-lapsed"
            (run_dir / "authorization-recheck.txt").write_text(
                f"Stopped before {stage}:\n" + "\n".join(errors) + "\n", encoding="utf-8"
            )
            return False
        return True

    try:
        if deps.install_signal_handlers:
            for signum in (signal.SIGINT, signal.SIGTERM):
                previous_handlers[signum] = signal.signal(signum, handle_signal)
        # JSON rather than YAML: the evidence privacy lint reads a line that
        # starts with "authorization:" as SIP authorization material.
        _write_json(run_dir / "profile.json", document)
        (run_dir / "expectations.yaml").write_text(
            yaml.safe_dump(expectations, sort_keys=False), encoding="utf-8"
        )
        if options.play is None:
            generate_tone(play_path)
            play_info = _validate_wav(play_path)
        ca_copy: Path | None = None
        if ca_data is not None:
            from sippycup.tls_trust import write_private_copy

            ca_copy = write_private_copy(ca_data, run_dir / "trust-anchor.pem")
        account = None
        if options.username:
            account = SoftphoneAccount(
                username=options.username,
                realm=options.realm,
                registrar=(
                    registrar_uri(host, port, transport, server_name) if options.register else None
                ),
            )
        softphone_call = SoftphoneCall(
            destination=options.destination,
            host=host,
            port=port,
            transport=transport,
            play_file=play_path,
            record_file=run_dir / "heard.wav",
            duration_seconds=duration,
            log_file=run_dir / "softphone.log",
            console_file=run_dir / "softphone-console.txt",
            account=account,
            codecs=tuple(options.codecs),
            answer_timeout_seconds=options.answer_timeout,
            registration_timeout_seconds=REGISTRATION_TIMEOUT_SECONDS,
            allowed_media_addresses=tuple(approved),
            advertised_address=local,
            tls_server_name=server_name,
            tls_ca_file=ca_copy,
        )
        try:
            softphone_options = build_config(softphone_call, password=None).splitlines()
        except SoftphoneError as error:
            raise CallError(str(error)) from error
        if password is not None:
            softphone_options.append("--password=<redacted>")
        plan = {
            "schema_version": PLAN_VERSION,
            "profile": profile_name,
            "authorization": {
                "networks": [
                    str(ipaddress.ip_network(item)) for item in dict.fromkeys([*approved, local])
                ],
                "valid_until": rehearse(document, now=now).facts["authorization"]["valid_until"],
                "approval_id_present": True,
            },
            "evidence": {"capture": True, "retainPayload": True},
            "target": {"host": host, "port": port, "transport": transport},
            **(
                {
                    "tls": {
                        "verify_server": True,
                        "server_name": server_name,
                        "verify_name": server_name or host,
                        "trust": "file" if ca_data is not None else "system",
                        "ca_file": ca_reference,
                        "ca_sha256": ca_sha256,
                        "connects_to": host,
                    }
                }
                if transport == "tls"
                else {}
            ),
            "local_address": local,
            "network_mode": network_mode,
            "capture_filter": scope,
            "softphone": _softphone_parameters(options, document, duration, limit),
            "play_file": {
                "path": _display(play_path, work_root),
                "sha256": hashlib.sha256(play_path.read_bytes()).hexdigest(),
                **(play_info or {}),
            },
            "steps": [
                "start_scoped_capture",
                "single_options_preflight",
                "single_softphone_call",
                "stop_capture",
                "offline_report",
                "offline_triage",
                "offline_assert",
                "evidence_manifest",
            ],
        }
        _write_json(run_dir / "plan.json", plan)
        _write_json(
            run_dir / "commands.json",
            {
                "capture": capture_argv,
                "softphone": [tools["pjsua"], "--config-file", "<private tmpfs file, deleted>"],
                "softphone_options": softphone_options,
                "report": report_argv,
                "triage": triage_argv,
                "assert": assert_argv,
            },
        )
        _write_json(run_dir / "versions.json", deps.tool_versions(
            {name: tools[name] for name in ("pjsua", "tcpdump", "tshark")}, child_environment
        ))
        _write_json(run_dir / "timestamps.json", timestamps)

        capture = deps.start_capture(capture_argv, capture_path, run_dir / "capture.log", child_environment)
        problem = capture.wait_ready(CAPTURE_READY_TIMEOUT_SECONDS, cancel)
        if problem == "cancelled":
            raise _Finish
        if problem is not None:
            stop_reason = "capture-failed"
            raise _Finish
        timestamps["capture_ready"] = _utc(deps.now())

        # Authorization is re-checked immediately before the first packet.
        if not recheck("preflight") or cancel.is_set():
            raise _Finish
        destination = {"address": host, "port": port, "transport": transport, "target": "profile"}
        timestamps["preflight_sent"] = _utc(deps.now())
        preflight_sent = True
        if transport == "tls":
            preflight_ok, detail = deps.preflight(
                destination, tls_server_name=server_name, tls_ca_data=ca_data
            )
        else:
            preflight_ok, detail = deps.preflight(destination)
        _write_json(
            run_dir / "preflight.json",
            [{
                "target": "profile",
                "address": host,
                "port": port,
                "transport": transport,
                "ok": preflight_ok,
                "detail": detail.replace(password, "<redacted>") if password else detail,
            }],
        )
        if cancel.is_set():
            raise _Finish
        if not capture.alive():
            stop_reason = "capture-died"
            raise _Finish
        if not preflight_ok:
            raise _Finish
        if not recheck("call"):
            raise _Finish

        def abort() -> str | None:
            return None if capture.alive() else "capture_died"

        timestamps["call_started"] = _utc(deps.now())
        result = deps.place_call(
            softphone_call,
            password=password,
            cancel=cancel,
            abort=abort,
            pjsua=tools["pjsua"],
            environment=child_environment,
        )
        timestamps["call_ended"] = _utc(deps.now())
        softphone_result = result.as_dict()
        if softphone_result.get("error") == "capture_died":
            stop_reason = "capture-died"
        _write_json(run_dir / "softphone.json", softphone_result)
    except _Finish:
        pass
    except Exception as error:  # keep the evidence and report honestly
        stop_reason = "internal-error"
        internal_error = f"{type(error).__name__}: {error}"
        if password:
            internal_error = internal_error.replace(password, "<redacted>")
    finally:
        if capture is not None:
            if capture.alive() and not cancel.is_set():
                time.sleep(CAPTURE_TAIL_SECONDS)
            died = not capture.alive()
            capture.stop()
            timestamps["capture_stopped"] = _utc(deps.now())
            if died and stop_reason is None and timestamps.get("capture_ready"):
                stop_reason = "capture-died"
        if capture_path.exists() and not cancel.is_set() and preflight_sent:
            offline_codes["report"] = deps.run_offline(
                report_argv, run_dir / "report.txt", run_dir / "report.stderr", child_environment
            )
            offline_codes["triage"] = deps.run_offline(
                triage_argv, run_dir / "triage.json", run_dir / "triage.stderr", child_environment
            )
            offline_codes["assert"] = deps.run_offline(
                assert_argv, run_dir / "assert.json", run_dir / "assert.stderr", child_environment
            )
            media_argv = tls_media_argv(
                tools["tshark"], capture_path, (softphone_result or {}).get("media_peer")
            )
            if transport == "tls" and media_argv is not None:
                offline_codes["tls_media"] = deps.run_offline(
                    media_argv, run_dir / "tls-media.txt", run_dir / "tls-media.stderr",
                    child_environment,
                )
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        os.umask(old_umask)

    oracle = _oracle_summary(run_dir / "assert.json", offline_codes["assert"])
    triage = _triage_summary(run_dir / "triage.json", offline_codes["triage"])
    recording = analyze_recording(run_dir / "heard.wav") if softphone_result else None
    tls_media = (
        count_tls_media(
            run_dir / "tls-media.txt",
            (softphone_result or {}).get("media_peer"),
            offline_codes.get("tls_media"),
        )
        if transport == "tls"
        else None
    )
    log_text = ""
    if softphone_result:
        for name in ("softphone-console.txt", "softphone.log"):
            try:
                log_text += (run_dir / name).read_text(encoding="utf-8", errors="replace") + "\n"
            except OSError:
                pass
    setup = derive_setup(softphone_result, log_text)
    state, verdict, exit_code, notes = classify(
        cancelled_signal=cancel_signal[0] if cancel_signal else None,
        stop_reason=stop_reason,
        preflight_ok=preflight_ok,
        softphone=softphone_result,
        oracle=oracle,
        media_required=options.media_required,
        network_mode=network_mode,
        host=host,
        tls_media=tls_media,
        recording=recording,
        requested_seconds=duration,
        setup=setup,
        approved=approved,
        remote_media=remote_sdp_addresses(log_text),
    )
    notes.insert(0, _network_note(network_mode, host))
    if internal_error is not None:
        notes.append(f"Internal error stopped the run: {internal_error}")
    if stop_reason == "capture-failed":
        notes.append(
            "Packet capture did not start, so nothing was sent; see capture.log. Capture needs "
            "CAP_NET_RAW in a private network namespace, which `./bin/sippycup call` provides."
        )
    if limit is not None and options.duration > limit:
        notes.append(f"Requested duration {options.duration}s was clamped to the profile limit {limit}s.")
    if recording and recording.get("silent") and verdict == "pass":
        notes.append("The recording is silent even though RTP was observed; review heard.wav.")
    if cancel_signal and preflight_sent:
        notes.append("Cancelled: offline report, triage, and assertions were skipped; the capture is kept.")
    timestamps["finished"] = _utc(deps.now())
    target_text = f"{host}:{port}/{transport}"
    activity = _network_activity(
        preflight_sent=preflight_sent,
        softphone=softphone_result,
        target=target_text,
        network_mode=network_mode,
        loopback=ipaddress.ip_address(host).is_loopback,
    )
    journal = _journal_command(engagement, run_dir, work_root, verdict, profile_name)
    value = {
        "apiVersion": RESULT_VERSION,
        "state": state,
        "verdict": verdict,
        "exitCode": exit_code,
        "profile": profile_name,
        "target": {"host": host, "port": port, "transport": transport},
        "destinationUri": uri,
        **(
            {
                "tls": {
                    "verified": bool(
                        softphone_result
                        and softphone_result.get("tls_verified") is True
                        and preflight_ok
                    ),
                    "serverName": server_name or host,
                    "trust": "file" if ca_data is not None else "system",
                    "caFile": ca_reference,
                    "caSha256": ca_sha256,
                    "preflightVerified": bool(preflight_ok),
                    "softphoneVerified": (
                        None if softphone_result is None else softphone_result.get("tls_verified")
                    ),
                    "softphoneDetail": (softphone_result or {}).get("tls_detail"),
                    "connectsTo": host,
                    "media": tls_media,
                }
            }
            if transport == "tls"
            else {}
        ),
        "localAddress": local,
        "networkMode": network_mode,
        "durationSeconds": {"requested": options.duration, "limit": limit, "effective": duration},
        "captureFilter": scope,
        "preflight": None if preflight_ok is None else {"ok": preflight_ok, "detail": _read_preflight(run_dir)},
        "softphone": None if softphone_result is None else {
            key: softphone_result.get(key)
            for key in (
                "registration_attempted", "registered", "registration_status", "dialed", "answered",
                "final_status", "disconnect_status", "disconnect_reason", "connected_seconds",
                "rtp_tx_packets", "rtp_rx_packets", "codec", "media_direction", "media_peer",
                "hangup", "error", "cancelled", "tls_verified", "tls_server_name",
            )
        },
        "setup": setup,
        "triage": triage,
        "oracle": oracle,
        "recording": recording,
        "notes": notes,
        "timestamps": timestamps,
        "runDirectory": _display(run_dir, work_root),
        "evidenceManifest": "evidence-manifest.json",
        "journalCommand": journal,
        "networkActivity": activity,
    }
    _write_json(run_dir / "timestamps.json", timestamps)
    _write_json(run_dir / "result.json", value)
    from sippycup.evidence import write_evidence_manifest

    try:
        manifest = write_evidence_manifest(run_dir)
        value["evidencePrivacy"] = manifest["privacy"]["status"]
    except Exception as error:  # evidence failure must not hide the call verdict
        value["evidencePrivacy"] = f"manifest-error: {type(error).__name__}"
    return exit_code, value


def _read_preflight(run_dir: Path) -> str | None:
    try:
        return json.loads((run_dir / "preflight.json").read_text(encoding="utf-8"))[0]["detail"]
    except (OSError, ValueError, KeyError, IndexError):
        return None


class _Finish(Exception):
    """Internal control flow: stop sending and continue to evidence."""


def render_human(value: dict[str, Any]) -> str:
    lines: list[str] = []
    if value.get("schema_version") == "sippycup.dev/call-dry-run/v1":
        plan = value["one_call_plan"]
        lines.append(f"Guided call plan: {'READY' if value['ready'] else 'BLOCKED'}")
        for error in plan["blocking_errors"]:
            lines.append(f"BLOCK: {error}")
        for index, step in enumerate(plan["steps"], 1):
            marker = "NETWORK" if step["network_active"] else "OFFLINE"
            lines.append(f"{index}. [{marker}] {step['name']}")
            if "argv" in step:
                lines.append(f"   {shlex.join(step['argv'])}")
            if "instruction" in step:
                lines.append(f"   {step['instruction']}")
        softphone = value["softphone"]
        lines.append("Softphone parameters:")
        lines.append(f"  destination:     {softphone['destination_uri']}")
        lines.append(f"  transport:       {softphone['transport']}")
        tls = softphone.get("tls")
        if tls:
            trust = f"CA file {tls['ca_file']}" if tls["trust"] == "file" else "the system trust store"
            lines.append(
                f"  TLS:             verify {tls['verify_name']} against {trust}; "
                f"connects only to {tls['connects_to']}"
                + (" (name pinned in a private namespace, never resolved)" if tls["server_name"] else "")
            )
        duration = softphone["duration_seconds"]
        lines.append(
            f"  duration:        {duration['effective']}s (requested {duration['requested']}s, "
            f"profile limit {duration['limit']}s)"
        )
        lines.append(f"  answer timeout:  {softphone['answer_timeout_seconds']}s")
        lines.append(f"  codecs:          {', '.join(softphone['codecs'])}")
        lines.append(f"  play:            {softphone['play']}")
        lines.append(f"  record:          {softphone['record']}")
        account = softphone["account"]
        if account is None:
            lines.append("  account:         none (unauthenticated call)")
        else:
            lines.append(
                f"  account:         {account['username']} realm={account['realm']} "
                f"register={'yes' if account['register'] else 'no'} password={account['password_source']}"
            )
        lines.append(f"  media required:  {'yes' if softphone['media_required'] else 'no'}")
        lines.append(f"Capture filter: {value['capture_filter']}")
        lines.append(value["executor"] + " (capture, preflight, call, report, triage, assert).")
        lines.append("This command sent no packets.")
        lines.append("Network activity: none")
        return "\n".join(lines) + "\n"
    if value.get("state") == "blocked":
        lines.append("Guided call: BLOCKED")
        for error in value["blockingErrors"]:
            lines.append(f"BLOCK: {error}")
        lines.append("Nothing was started and no packets were sent.")
        lines.append("Network activity: none")
        return "\n".join(lines) + "\n"
    lines.append(f"Guided call: {value['verdict'].upper()} ({value['state']})")
    target = value["target"]
    lines.append(f"  Target:       {target['host']}:{target['port']}/{target['transport']}  {value['destinationUri']}")
    tls = value.get("tls")
    if tls:
        trust = f"CA file {tls['caFile']}" if tls["trust"] == "file" else "system trust store"
        lines.append(
            f"  TLS:          {'verified' if tls['verified'] else 'NOT VERIFIED'} for "
            f"{tls['serverName']} ({trust}); connections only to {tls['connectsTo']}"
        )
    preflight = value.get("preflight")
    lines.append(
        "  Preflight:    "
        + ("not sent" if preflight is None else f"{'ok' if preflight['ok'] else 'FAILED'}: {preflight['detail']}")
    )
    softphone = value.get("softphone")
    if softphone is None:
        lines.append("  Call:         not placed")
    else:
        if softphone["registration_attempted"]:
            lines.append(
                f"  Registration: {'registered' if softphone['registered'] else 'FAILED'}"
                f" (status {softphone['registration_status'] if softphone['registration_status'] is not None else 'unknown'})"
            )
        status = softphone["final_status"] if softphone["final_status"] is not None else "unknown"
        connected = softphone["connected_seconds"]
        lines.append(
            f"  Call:         {'answered' if softphone['answered'] else 'not answered'}, final status {status}"
            + (f", connected {connected:.1f}s" if connected is not None else "")
            + (f", hangup: {softphone['hangup']}" if softphone["hangup"] else "")
            + (f", error: {softphone['error']}" if softphone["error"] else "")
        )
        tx = softphone["rtp_tx_packets"]
        rx = softphone["rtp_rx_packets"]
        lines.append(
            "  RTP (PJSUA):  "
            + f"sent {tx if tx is not None else 'unknown'}, received {rx if rx is not None else 'unknown'}"
            + (f", codec {softphone['codec']}" if softphone["codec"] else "")
        )
    media = (tls or {}).get("media")
    if media:
        lines.append(
            "  RTP (capture): "
            + (
                f"to peer {media['outbound']}, from peer {media['inbound']} ({media.get('peer')})"
                if media.get("outbound") is not None
                else f"not counted: {media.get('note')}"
            )
        )
    recording = value.get("recording")
    if recording and recording.get("present") and recording.get("readable"):
        silent = recording.get("silent")
        lines.append(
            f"  Recording:    {recording.get('seconds')}s, peak {recording.get('peak_dbfs')} dBFS, "
            + ("silent" if silent else "not silent" if silent is False else "silence unknown")
        )
    oracle = value.get("oracle")
    if oracle is not None:
        summary = oracle.get("summary") or {}
        lines.append(
            f"  Oracle:       {oracle.get('verdict') or 'no result'}"
            + (f" (pass={summary.get('pass')} fail={summary.get('fail')} unknown={summary.get('unknown')})" if summary else "")
        )
    setup = value.get("setup")
    if setup:
        seconds = setup.get("seconds")
        lines.append(
            "  Setup:        "
            + (f"answered after {seconds}s" if seconds is not None else "not answered")
            + (f", provisional {_provisional_text(setup['provisional'])}" if setup.get("provisional") else ", no provisional response")
            + (" (early media offered)" if setup.get("earlyMedia") else "")
        )
    for note in value.get("notes", []):
        lines.append(f"NOTE: {note}")
    if value["verdict"] != "pass":
        lines.append(f"Explain: ./bin/sippycup explain call.{value['verdict']}")
    lines.append(f"Run directory: {value['runDirectory']}")
    lines.append(f"Record it: {shlex.join(value['journalCommand'])}")
    lines.append(f"Network activity: {value['networkActivity']}")
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sippycup call",
        description=(
            "Execute the reviewed one-call plan in one terminal: scoped capture, one OPTIONS "
            "preflight, one PJSUA call, and offline report, triage, and assertions."
        ),
        epilog=(
            "Refuses, sending nothing, unless the profile is approved, unexpired, and target.host "
            "is one of its literal approved addresses. Exit status: 0 pass; 1 the call ran but did "
            "not pass; 2 refused before any packet; 130/143 cancelled by SIGINT/SIGTERM."
        ),
    )
    parser.add_argument("profile", type=Path)
    parser.add_argument("--dial", required=True, metavar="DESTINATION", help="user part dialed at the profile's target")
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION_SECONDS, help="seconds; clamped to limits.max_duration_seconds")
    parser.add_argument("--answer-timeout", type=int, default=DEFAULT_ANSWER_TIMEOUT_SECONDS)
    parser.add_argument("--play", type=Path, help="16-bit PCM WAV beneath work/ (default: generated tone)")
    parser.add_argument("--codec", action="append", dest="codecs", help="codec preference, repeatable (default PCMU)")
    parser.add_argument("--username", help="account username for digest challenges")
    parser.add_argument("--realm", default="*")
    parser.add_argument("--no-register", action="store_true", help="answer challenges without sending REGISTER")
    secret = parser.add_mutually_exclusive_group()
    secret.add_argument("--secret-env", metavar="NAME", help="environment variable holding the password")
    secret.add_argument("--secret-file", type=Path, help="mode-0600 password file beneath work/")
    parser.add_argument("--run-root", type=Path, help="directory beneath work/ for the new run directory")
    parser.add_argument("--engagement", type=Path, help="journal directory for the suggested journal command")
    parser.add_argument("--no-media-required", action="store_true")
    parser.add_argument("--format", choices=("human", "json"), default="human")
    parser.add_argument("--dry-run", action="store_true", help="print the plan and softphone parameters; send nothing")
    return parser


def main(argv: Sequence[str] | None = None, deps: Dependencies | None = None) -> int:
    args = build_parser().parse_args(argv)
    options = CallOptions(
        profile=args.profile,
        destination=args.dial,
        duration=args.duration,
        play=args.play,
        codecs=tuple(args.codecs or ("PCMU",)),
        username=args.username,
        realm=args.realm,
        register=not args.no_register,
        secret_env=args.secret_env,
        secret_file=args.secret_file,
        run_root=args.run_root,
        engagement=args.engagement,
        media_required=not args.no_media_required,
        answer_timeout=args.answer_timeout,
        output_format=args.format,
        dry_run=args.dry_run,
    )
    try:
        code, value = execute(options, deps)
    except (CallError, ProfileError) as error:
        print(f"error: {error}", file=sys.stderr)
        work_root = (deps.work_root if deps and deps.work_root else default_work_root())
        if isinstance(error, ProfileError) and not _within(args.profile, work_root):
            print(
                "hint: the call runs in the image, which sees only the work/ directory; "
                "keep the profile beneath work/ (for example work/ENGAGEMENT/profile.yaml).",
                file=sys.stderr,
            )
        print("Nothing was started and no packets were sent.", file=sys.stderr)
        print("Network activity: none", file=sys.stderr if args.format == "json" else sys.stdout)
        return EXIT_REFUSED
    if args.format == "json":
        print(json.dumps(value, indent=2, sort_keys=True))
    else:
        sys.stdout.write(render_human(value))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
