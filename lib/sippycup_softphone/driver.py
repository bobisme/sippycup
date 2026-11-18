"""Drive exactly one bounded PJSUA call and report what PJSUA observed.

PJSUA accepts options only from argv or ``--config-file``. Every option,
including any password, goes into a mode-0600 file inside a private
temporary directory (``/dev/shm`` when available, so it stays in memory) that
is deleted as soon as PJSUA has read it and again in a ``finally`` block. The
password never appears in argv, the child environment, or persisted logs.

PJSUA quits when standard input reaches EOF, so the driver keeps a pipe open
and sends console commands deliberately: ``m`` to dial after the optional
registration succeeds, ``dq`` to learn the negotiated media peer, ``h`` to
hang up, and ``q`` to quit. Standard output is a pseudo-terminal so PJSUA's
C library line-buffers it and state changes arrive while the call runs.

TLS always verifies the server: ``--tls-verify-server`` with the reviewed CA
file, or the system bundle when none is given. Without a server name PJSIP
verifies the literal address against the certificate's IP SAN. With a
reviewed server name PJSIP must dial that name (it verifies, and sends as SNI,
the host it dialed), so PJSUA runs in a private user and mount namespace
whose ``/etc/hosts`` holds exactly one line, ``LITERAL NAME``, and whose
``/etc/nsswitch.conf`` says ``hosts: files``: the name can only become the
literal address, and no DNS query can be sent for it or for any other name.
"""

from __future__ import annotations

import ipaddress
import os
import pty
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

TRANSPORTS = ("udp", "tcp", "tls")
START_TIMEOUT_SECONDS = 10.0
HANGUP_TIMEOUT_SECONDS = 5.0
QUIT_TIMEOUT_SECONDS = 5.0
DURATION_BACKSTOP_SECONDS = 3.0
MAX_DURATION_SECONDS = 3600
MAX_LOG_BYTES = 32 * 1024 * 1024

_DESTINATION = re.compile(r"^[A-Za-z0-9+*][A-Za-z0-9._+*-]{0,63}$")
_TOKEN = re.compile(r"^[^\s\"'\x00-\x1f\x7f]{1,256}$")
_USERNAME = re.compile(r"^[A-Za-z0-9._+*~!$&()=,;?/%-]{1,64}$")
_URI = re.compile(r"^sips?:[A-Za-z0-9._~!$&()*+,;=:@%\[\]-]{1,255}$")
_CODEC = re.compile(r"^[A-Za-z0-9][A-Za-z0-9./-]{0,31}$")

_STATE = re.compile(r"Call (\d+) state changed to ([A-Z_]+)")
_DISCONNECTED = re.compile(r"Call (\d+) is DISCONNECTED \[reason=(\d+) \(([^)]*)\)\]")
_REGISTRATION_OK = re.compile(r"(?<!un)registration success, status=(\d{3})")
_REGISTRATION_FAILED = re.compile(r"(?<!un)registration failed, status=(\d{3})", re.I)
_REGISTRATION_ERROR = re.compile(r"SIP registration error", re.I)
_READY = re.compile(r"Ready: Success")
_DURATION_EXCEEDED = re.compile(r"Duration \(\d+ seconds\) has been exceeded")
_MEDIA = re.compile(r"#\d+ audio (\S+) @(\d+)kHz, (\w+), peer=(\S+)")
_RESPONSE = re.compile(r"Incoming Response msg (\d{3})/INVITE")
_RTP_TOTAL = re.compile(r"total (\d+)pkt")
_TLS_VERIFICATION = re.compile(
    r"TLS cert verification result of (\[[^\]]+\]|[^\s:]+):(\d+) : ([^\r\n]*)"
)
NAME_PIN_SCRIPT = (
    'mount --bind "$1" /etc/hosts && mount --bind "$2" /etc/nsswitch.conf '
    '&& shift 2 && exec "$@"'
)
NAME_PIN_TIMEOUT_SECONDS = 5.0
_AUTH_HEADER = re.compile(
    r"(?im)^([ \t]*(?:proxy-)?authorization[ \t]*:[ \t]*)[^\r\n]*"
)
_PASSWORD_OPTION = re.compile(r"(?im)(--password[ \t=]+)\S+")


class SoftphoneError(ValueError):
    """The call request cannot be safely expressed to PJSUA."""


@dataclass(frozen=True)
class SoftphoneAccount:
    """Credentials for digest challenges and optional registration.

    ``registrar`` is a SIP URI; ``None`` supplies credentials for INVITE
    challenges without sending REGISTER. The password is not part of this
    object: pass its value to :func:`place_call` so it stays in memory.
    """

    username: str
    registrar: str | None = None
    realm: str = "*"
    identity: str | None = None


@dataclass(frozen=True)
class SoftphoneCall:
    """One call: ``sip:destination@host:port`` over ``transport``."""

    destination: str
    host: str
    port: int
    transport: str
    play_file: Path
    record_file: Path
    duration_seconds: int
    log_file: Path
    console_file: Path | None = None
    account: SoftphoneAccount | None = None
    codecs: tuple[str, ...] = ("PCMU",)
    answer_timeout_seconds: float = 30.0
    registration_timeout_seconds: float = 10.0
    allowed_media_addresses: tuple[str, ...] | None = None
    # Inclusive (start, end) range the negotiated remote RTP port must lie in.
    allowed_media_ports: tuple[int, int] | None = None
    pin_signaling: bool = True
    bound_address: str | None = None
    advertised_address: str | None = None
    # TLS only. The reviewed certificate name (SNI and verification), never
    # resolved through DNS; and the PEM trust anchor PJSUA loads. ``None``
    # means the literal address is verified against the IP SAN and the
    # system bundle is the trust store. Verification cannot be disabled.
    tls_server_name: str | None = None
    tls_ca_file: Path | None = None


@dataclass
class SoftphoneResult:
    destination_uri: str
    started: bool = False
    registration_attempted: bool = False
    registered: bool | None = None
    registration_status: int | None = None
    dialed: bool = False
    answered: bool = False
    final_status: int | None = None
    disconnect_status: int | None = None
    disconnect_reason: str | None = None
    timeline: list[dict[str, Any]] = field(default_factory=list)
    connected_seconds: float | None = None
    rtp_tx_packets: int | None = None
    rtp_rx_packets: int | None = None
    codec: str | None = None
    media_direction: str | None = None
    media_peer: str | None = None
    hangup: str | None = None
    error: str | None = None
    cancelled: bool = False
    exit_code: int | None = None
    commands_sent: list[str] = field(default_factory=list)
    # TLS facts as PJSUA reported them; ``None`` for UDP and TCP.
    tls_verified: bool | None = None
    tls_server_name: str | None = None
    tls_trust: str | None = None
    tls_detail: str | None = None

    @property
    def ok(self) -> bool:
        return self.answered and self.error is None

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["schema_version"] = "sippycup.dev/softphone-result/v1"
        value["ok"] = self.ok
        value["rtp_counts_source"] = "pjsua-call-dump"
        return value


def _server_name(value: str | None, transport: str) -> str | None:
    if value is None:
        return None
    if transport != "tls":
        raise SoftphoneError("a TLS server name requires the tls transport")
    from sippycup.tls_trust import TrustError, validate_server_name

    try:
        return validate_server_name(value)
    except TrustError as error:
        raise SoftphoneError(str(error)) from error


def signaling_host(host: str, transport: str, server_name: str | None = None) -> str:
    """The host part PJSUA dials: the reviewed TLS name, else the literal."""
    address = _literal_address(host)
    name = _server_name(server_name, transport)
    if name is not None:
        return name
    return f"[{address}]" if ":" in address else address


def registrar_uri(host: str, port: int, transport: str, server_name: str | None = None) -> str:
    """The registrar URI for the approved target (the reviewed name over TLS)."""
    rendered = signaling_host(host, transport, server_name)
    suffix = "" if transport == "udp" else f";transport={transport}"
    return f"sip:{rendered}:{port}{suffix}"


def destination_uri(
    destination: str,
    host: str,
    port: int,
    transport: str,
    server_name: str | None = None,
) -> str:
    """Return the SIP URI dialed for a literal-address destination.

    With a reviewed TLS server name the URI names that host; the driver pins
    the name to the literal address, so the connection still goes only there.
    """
    if _DESTINATION.fullmatch(destination or "") is None:
        raise SoftphoneError(
            "destination must be 1-64 characters of letters, digits, and . _ + * -"
        )
    _literal_address(host)
    if type(port) is not int or not 1 <= port <= 65535:
        raise SoftphoneError("port must be an integer from 1 to 65535")
    if transport not in TRANSPORTS:
        raise SoftphoneError("transport must be udp, tcp, or tls")
    rendered = signaling_host(host, transport, server_name)
    suffix = "" if transport == "udp" else f";transport={transport}"
    return f"sip:{destination}@{rendered}:{port}{suffix}"


def tls_ca_list(call: SoftphoneCall) -> str:
    """The CA list PJSUA loads: the reviewed file or the system bundle."""
    from sippycup.tls_trust import SYSTEM_CA_BUNDLE

    return str(call.tls_ca_file) if call.tls_ca_file is not None else SYSTEM_CA_BUNDLE


def tls_trust(call: SoftphoneCall) -> str | None:
    if call.transport != "tls":
        return None
    return "file" if call.tls_ca_file is not None else "system"


def tls_expected_name(call: SoftphoneCall) -> str | None:
    """The name PJSIP verifies: the reviewed name, else the literal address."""
    if call.transport != "tls":
        return None
    return call.tls_server_name or _literal_address(call.host)


def _literal_address(host: str) -> str:
    try:
        return str(ipaddress.ip_address(host))
    except (TypeError, ValueError) as error:
        raise SoftphoneError("host must be a literal IP address") from error


def _token(value: Any, label: str) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise SoftphoneError(
            f"{label} must be 1-256 characters without whitespace, quotes, or control characters"
        )
    return value


def _validate(call: SoftphoneCall, password: str | None) -> str:
    uri = destination_uri(
        call.destination, call.host, call.port, call.transport, call.tls_server_name
    )
    if call.tls_ca_file is not None and call.transport != "tls":
        raise SoftphoneError("a TLS CA file requires the tls transport")
    if call.transport == "tls":
        _token(tls_ca_list(call), "TLS CA file")
    if type(call.duration_seconds) is not int or not 1 <= call.duration_seconds <= MAX_DURATION_SECONDS:
        raise SoftphoneError(f"duration must be an integer from 1 to {MAX_DURATION_SECONDS}")
    for label, value in (
        ("play file", call.play_file),
        ("record file", call.record_file),
        ("log file", call.log_file),
    ):
        _token(str(value), label)
    if not Path(call.play_file).is_file():
        raise SoftphoneError("play file does not exist")
    if call.console_file is not None:
        _token(str(call.console_file), "console file")
    if not call.codecs:
        raise SoftphoneError("at least one codec is required")
    for codec in call.codecs:
        if _CODEC.fullmatch(codec) is None:
            raise SoftphoneError(f"invalid codec name: {codec!r}")
    if call.answer_timeout_seconds <= 0 or call.registration_timeout_seconds <= 0:
        raise SoftphoneError("timeouts must be positive")
    for address in (call.bound_address, call.advertised_address):
        if address is not None:
            _literal_address(address)
    if call.allowed_media_addresses is not None:
        for address in call.allowed_media_addresses:
            _literal_address(address)
    if call.allowed_media_ports is not None:
        ports = call.allowed_media_ports
        if (
            not isinstance(ports, tuple)
            or len(ports) != 2
            or any(type(port) is not int or not 1 <= port <= 65535 for port in ports)
            or ports[0] > ports[1]
        ):
            raise SoftphoneError("allowed media ports must be an ordered (start, end) port range")
    if call.account is None:
        if password is not None:
            raise SoftphoneError("a password requires an account")
        return uri
    account = call.account
    if _USERNAME.fullmatch(account.username or "") is None:
        raise SoftphoneError("username contains unsupported characters")
    _token(account.realm, "realm")
    for label, value in (("registrar", account.registrar), ("identity", account.identity)):
        if value is not None and _URI.fullmatch(value) is None:
            raise SoftphoneError(f"{label} must be a SIP URI without whitespace")
    if call.tls_server_name is not None and account.registrar is not None and (
        account.registrar
        != registrar_uri(call.host, call.port, call.transport, call.tls_server_name)
    ):
        # A registrar at the literal would be verified against the IP SAN,
        # and one at any other host cannot be reached in the pinned
        # namespace: only the reviewed name is accepted.
        raise SoftphoneError("with a TLS server name the registrar must be that name")
    if password is not None:
        if not isinstance(password, str) or not password:
            raise SoftphoneError("password must be a non-empty string")
        if _TOKEN.fullmatch(password) is None:
            raise SoftphoneError(
                "password must be at most 256 characters without whitespace, quotes, "
                "or control characters (PJSUA configuration files are whitespace-delimited)"
            )
    return uri


def build_config(call: SoftphoneCall, *, password: str | None = None, log_file: Path | None = None) -> str:
    """Render the PJSUA configuration file text for ``call``.

    The result contains the password when one is supplied; write it only to
    a private mode-0600 file.
    """
    _validate(call, password)
    address = _literal_address(call.host)
    rendered = signaling_host(call.host, call.transport, call.tls_server_name)
    transport_parameter = "" if call.transport == "udp" else f";transport={call.transport}"
    lines = [
        "--null-audio",
        "--no-color",
        "--no-vad",
        "--log-level=5",
        "--app-log-level=3",
        f"--log-file={log_file or call.log_file}",
        "--max-calls=1",
        "--accept-redirect=0",
        "--local-port=0",
        f"--duration={call.duration_seconds}",
        f"--play-file={call.play_file}",
        "--auto-play",
        f"--rec-file={call.record_file}",
        "--auto-rec",
    ]
    # PJSUA raises each added codec above the previous one, so the first
    # preference is added last.
    lines.extend(f"--add-codec={codec}" for codec in reversed(call.codecs))
    if call.transport == "udp":
        lines.append("--no-tcp")
    elif call.transport == "tcp":
        lines.append("--no-udp")
    else:
        # Always verified: the certificate must chain to the CA list and name
        # the dialed host (the reviewed name, or the literal's IP SAN). There
        # is deliberately no option that removes these two lines.
        lines.extend(
            [
                "--use-tls",
                "--no-udp",
                "--no-tcp",
                "--tls-verify-server",
                f"--tls-ca-file={tls_ca_list(call)}",
            ]
        )
    if ":" in address:
        lines.append("--ipv6")
    if call.bound_address is not None:
        lines.append(f"--bound-addr={call.bound_address}")
    if call.advertised_address is not None:
        # The address in Contact and SDP; normally the kernel's source
        # address toward the target, so local evidence matches what was sent.
        lines.append(f"--ip-addr={call.advertised_address}")
    if call.pin_signaling:
        # A global outbound route keeps every request, including in-dialog
        # ACK/BYE that would otherwise follow a remote Contact, on the
        # approved address.
        lines.append(f"--outbound=sip:{rendered}:{call.port}{transport_parameter};lr")
    if call.account is not None:
        account = call.account
        identity = account.identity or f"sip:{account.username}@{rendered}"
        lines.extend(
            [
                f"--id={identity}",
                f"--username={account.username}",
                f"--realm={account.realm}",
            ]
        )
        if account.registrar is not None:
            # --rereg-delay=0 disables PJSUA's automatic retry after a failed
            # registration, so a wrong password costs one challenged attempt
            # (lockout safety); the driver quits on the first failure.
            lines.extend(
                [f"--registrar={account.registrar}", "--reg-timeout=300", "--rereg-delay=0"]
            )
        if password is not None:
            lines.append(f"--password={password}")
    return "\n".join(lines) + "\n"


def redact(text: str, secrets: Sequence[str] = ()) -> str:
    """Remove secret values and digest authorization header values."""
    for secret in sorted({value for value in secrets if value}, key=len, reverse=True):
        text = text.replace(secret, "<redacted>")
    text = _AUTH_HEADER.sub(lambda match: match.group(1) + "<redacted>", text)
    return _PASSWORD_OPTION.sub(lambda match: match.group(1) + "<redacted>", text)


def _peer_address(peer: str) -> str | None:
    if peer.startswith("["):
        candidate = peer[1:].split("]", 1)[0]
    else:
        candidate = peer.rsplit(":", 1)[0] if peer.count(":") == 1 else peer
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _peer_port(peer: str) -> int | None:
    if peer.startswith("["):
        tail = peer.split("]", 1)[1] if "]" in peer else ""
        text = tail[1:] if tail.startswith(":") else ""
    else:
        text = peer.rsplit(":", 1)[1] if peer.count(":") == 1 else ""
    return int(text) if text.isdigit() and 1 <= int(text) <= 65535 else None


def _media_outside_scope(call: SoftphoneCall, peer: str | None) -> bool:
    if peer is None:
        return False
    if (
        call.allowed_media_addresses is not None
        and _peer_address(peer) not in call.allowed_media_addresses
    ):
        return True
    if call.allowed_media_ports is not None:
        port = _peer_port(peer)
        start, end = call.allowed_media_ports
        return port is None or not start <= port <= end
    return False


def _parent_death_signal() -> None:  # pragma: no cover - runs in the child
    """Ask Linux to SIGKILL PJSUA if the process that started it dies."""
    import ctypes

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG
    except (OSError, AttributeError):
        pass


def parse_pjsua_log(text: str) -> dict[str, Any]:
    """Extract observed call facts from PJSUA log or console text.

    Every value is ``None`` unless PJSUA printed it.
    """
    facts: dict[str, Any] = {
        "final_status": None,
        "disconnect_status": None,
        "disconnect_reason": None,
        "registration_status": None,
        "registered": None,
        "rtp_rx_packets": None,
        "rtp_tx_packets": None,
        "codec": None,
        "media_direction": None,
        "media_peer": None,
        "duration_exceeded": False,
    }
    for match in _RESPONSE.finditer(text):
        status = int(match.group(1))
        if status >= 200:
            facts["final_status"] = status
    for match in _DISCONNECTED.finditer(text):
        facts["disconnect_status"] = int(match.group(2))
        facts["disconnect_reason"] = match.group(3)
    for line in text.splitlines():
        if (match := _REGISTRATION_OK.search(line)) is not None:
            facts["registration_status"] = int(match.group(1))
            facts["registered"] = True
        elif (match := _REGISTRATION_FAILED.search(line)) is not None:
            facts["registration_status"] = int(match.group(1))
            facts["registered"] = False
        elif _REGISTRATION_ERROR.search(line) and facts["registered"] is not True:
            facts["registered"] = False
    direction = None
    for line in text.splitlines():
        stripped = line.strip()
        if (match := _MEDIA.search(line)) is not None:
            facts["codec"] = match.group(1)
            facts["media_direction"] = match.group(3)
            facts["media_peer"] = match.group(4).rstrip(",")
        if stripped.startswith("RX pt="):
            direction = "rx"
        elif stripped.startswith("TX pt="):
            direction = "tx"
        elif direction is not None and (match := _RTP_TOTAL.search(stripped)):
            facts[f"rtp_{direction}_packets"] = int(match.group(1))
            direction = None
    facts["duration_exceeded"] = bool(_DURATION_EXCEEDED.search(text))
    return facts


def _private_root(explicit: Path | None) -> Path | None:
    if explicit is not None:
        return explicit
    shm = Path("/dev/shm")
    if shm.is_dir() and os.access(shm, os.W_OK | os.X_OK):
        return shm
    return None


def _write_private(path: Path, text: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(text)


def _persist(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(text)
    path.chmod(0o600)


class _Console:
    """Collect pseudo-terminal output lines on a background thread."""

    def __init__(self, descriptor: int) -> None:
        self._descriptor = descriptor
        self._lock = threading.Lock()
        self._lines: list[str] = []
        self._partial = b""
        self._size = 0
        self._thread = threading.Thread(target=self._run, name="pjsua-console", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while True:
            try:
                chunk = os.read(self._descriptor, 65536)
            except OSError:
                break
            if not chunk:
                break
            with self._lock:
                self._size += len(chunk)
                if self._size > MAX_LOG_BYTES:
                    continue
                data = self._partial + chunk
                *complete, self._partial = data.split(b"\n")
                self._lines.extend(
                    line.decode("utf-8", "replace").rstrip("\r") for line in complete
                )
        with self._lock:
            if self._partial:
                self._lines.append(self._partial.decode("utf-8", "replace").rstrip("\r"))
                self._partial = b""

    def lines_from(self, index: int) -> list[str]:
        with self._lock:
            return self._lines[index:]

    def join(self, timeout: float) -> None:
        self._thread.join(timeout)

    def text(self) -> str:
        with self._lock:
            return "\n".join(self._lines) + ("\n" if self._lines else "")


def name_pinned_argv(
    hosts: Path, nsswitch: Path, argv: Sequence[str], *, unshare: str = "unshare"
) -> list[str]:
    """Run ``argv`` in a private user+mount namespace with a pinned host map.

    Inside, ``/etc/hosts`` is ``hosts`` and ``/etc/nsswitch.conf`` is
    ``nsswitch`` (``hosts: files``), both bind-mounted from the driver's
    private directory. No other process sees them, and no resolver step is
    left that could send a DNS query. The network namespace is unchanged.
    """
    return [
        unshare, "--user", "--map-root-user", "--mount", "--",
        "/bin/sh", "-c", NAME_PIN_SCRIPT, "sh", str(hosts), str(nsswitch), *argv,
    ]


def write_name_pin(directory: Path, address: str, name: str) -> tuple[Path, Path]:
    """Write the one-line host map and the files-only switch file."""
    hosts = directory / "hosts"
    nsswitch = directory / "nsswitch.conf"
    _write_private(hosts, f"{_literal_address(address)} {name}\n")
    _write_private(nsswitch, "hosts: files\n")
    for path in (hosts, nsswitch):
        path.chmod(0o644)
    return hosts, nsswitch


def probe_name_pin(
    hosts: Path,
    nsswitch: Path,
    address: str,
    name: str,
    *,
    unshare: str,
    environment: Mapping[str, str] | None,
) -> str | None:
    """Prove the pinned namespace maps ``name`` to exactly ``address``.

    ``getent`` reads only the pinned files, so it sends nothing. Returns an
    error code, or ``None`` when the mapping is exactly one line.
    """
    try:
        completed = subprocess.run(
            name_pinned_argv(hosts, nsswitch, ["getent", "ahosts", name], unshare=unshare),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(environment) if environment is not None else None,
            timeout=NAME_PIN_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "tls_name_pinning_unavailable"
    if completed.returncode != 0:
        return "tls_name_pinning_unavailable"
    answers = {
        line.split()[0]
        for line in completed.stdout.decode("utf-8", "replace").splitlines()
        if line.strip()
    }
    if answers != {_literal_address(address)}:
        return "tls_name_pinning_mismatch"
    return None


def tls_verification(text: str, expected: str) -> tuple[bool | None, str | None]:
    """Judge PJSUA's ``TLS cert verification result`` lines for ``expected``.

    Verified only when at least one line for the expected host reads OK and
    no line reports a failure; ``None`` when PJSUA printed no result.
    """
    verified: bool | None = None
    detail: str | None = None
    for match in _TLS_VERIFICATION.finditer(text):
        host = match.group(1).strip("[]")
        message = match.group(3).strip()
        if host != expected or message != "OK":
            return False, f"{match.group(1)}:{match.group(2)}: {message}"
        verified = True if verified is None else verified
        detail = f"{match.group(1)}:{match.group(2)}: OK"
    return verified, detail


def _stop_process(process: subprocess.Popen[bytes], grace: float = 2.0) -> None:
    if process.poll() is not None:
        return
    for signum in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=grace)
            return
        except subprocess.TimeoutExpired:
            continue


def place_call(
    call: SoftphoneCall,
    *,
    password: str | None = None,
    cancel: threading.Event | None = None,
    abort: Callable[[], str | None] | None = None,
    pjsua: str = "pjsua",
    environment: Mapping[str, str] | None = None,
    private_root: Path | None = None,
    clock: Callable[[], float] = time.monotonic,
    poll_interval: float = 0.02,
    kill_with_parent: bool = False,
    unshare: str | None = None,
) -> SoftphoneResult:
    """Place exactly one call and return what PJSUA reported.

    ``cancel`` (set by a signal handler) and ``abort`` (returns a reason
    string, for example when packet capture died) both hang up an
    established call with BYE, or cancel a ringing one, before PJSUA quits.
    ``environment`` is passed to PJSUA unchanged; callers must already have
    removed secret variables from it. ``kill_with_parent`` asks Linux to
    SIGKILL PJSUA if the calling process dies first; PJSUA runs in its own
    session, so a supervisor's process-group kill would not reach it.
    """
    uri = _validate(call, password)
    result = SoftphoneResult(destination_uri=uri)
    if call.transport == "tls":
        result.tls_verified = False
        result.tls_server_name = tls_expected_name(call)
        result.tls_trust = tls_trust(call)
    secrets = [password] if password else []
    private = Path(tempfile.mkdtemp(prefix="sippycup-softphone-", dir=_private_root(private_root)))
    private.chmod(0o700)
    config_path = private / "pjsua.cfg"
    raw_log = private / "pjsua.log"
    process: subprocess.Popen[bytes] | None = None
    console: _Console | None = None
    master: int | None = None
    started = clock()

    def mark(state: str) -> None:
        result.timeline.append({"state": state, "at": round(clock() - started, 3)})

    try:
        argv = [pjsua, "--config-file", str(config_path)]
        if call.tls_server_name is not None:
            # Pin the reviewed name to the literal before PJSUA exists; refuse
            # (nothing started, nothing sent) unless the mapping is proven.
            tool = unshare or shutil.which("unshare") or "unshare"
            hosts, nsswitch = write_name_pin(private, call.host, call.tls_server_name)
            problem = probe_name_pin(
                hosts, nsswitch, call.host, call.tls_server_name,
                unshare=tool, environment=environment,
            )
            if problem is not None:
                result.error = problem
                return result
            argv = name_pinned_argv(hosts, nsswitch, argv, unshare=tool)
        _write_private(config_path, build_config(call, password=password, log_file=raw_log))
        master, slave = pty.openpty()
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=slave,
                stderr=slave,
                start_new_session=True,
                env=dict(environment) if environment is not None else None,
                close_fds=True,
                preexec_fn=_parent_death_signal if kill_with_parent else None,
            )
        except OSError as error:
            result.error = f"softphone_start_failed: {type(error).__name__}"
            return result
        finally:
            os.close(slave)
        result.started = True
        mark("STARTED")
        console = _Console(master)
        assert process.stdin is not None

        def send(command: str) -> None:
            result.commands_sent.append(command.split("\n", 1)[0] if command != uri else "<destination>")
            try:
                process.stdin.write((command + "\n").encode())
                process.stdin.flush()
            except (BrokenPipeError, OSError):
                pass

        phase = "starting"
        deadline = clock() + START_TIMEOUT_SECONDS
        read_index = 0
        ready = False
        confirmed_at: float | None = None
        disconnected = False
        quality_requested_at: float | None = None
        stopping = False
        hangup_by: str | None = None

        def quit_now() -> None:
            nonlocal phase, deadline
            if phase != "quit":
                send("q")
                phase = "quit"
                deadline = clock() + QUIT_TIMEOUT_SECONDS

        def hang_up(reason: str) -> None:
            nonlocal phase, deadline, hangup_by
            if result.dialed and not disconnected:
                if phase != "hangup":
                    send("h")
                    hangup_by = hangup_by or reason
                    phase = "hangup"
                    deadline = clock() + HANGUP_TIMEOUT_SECONDS
            else:
                quit_now()

        def consume() -> None:
            nonlocal read_index, ready, confirmed_at, disconnected, hangup_by
            for line in console.lines_from(read_index):
                read_index += 1
                if _READY.search(line):
                    ready = True
                if (match := _STATE.search(line)) is not None:
                    state = match.group(2)
                    mark(state)
                    if state == "CONFIRMED" and confirmed_at is None:
                        confirmed_at = clock()
                        result.answered = True
                if (match := _DISCONNECTED.search(line)) is not None:
                    disconnected = True
                    result.disconnect_status = int(match.group(2))
                    result.disconnect_reason = match.group(3)
                    mark("DISCONNECTED")
                if (match := _REGISTRATION_OK.search(line)) is not None:
                    result.registered = True
                    result.registration_status = int(match.group(1))
                elif (match := _REGISTRATION_FAILED.search(line)) is not None:
                    result.registered = False
                    result.registration_status = int(match.group(1))
                elif _REGISTRATION_ERROR.search(line) and result.registered is not True:
                    result.registered = False
                if (match := _MEDIA.search(line)) is not None:
                    result.media_peer = match.group(4).rstrip(",")
                    result.codec = match.group(1)
                if _DURATION_EXCEEDED.search(line):
                    hangup_by = hangup_by or "duration"

        while True:
            consume()
            now = clock()
            if process.poll() is not None:
                break
            if not stopping:
                reason = None
                if cancel is not None and cancel.is_set():
                    reason = "cancelled"
                    result.cancelled = True
                elif abort is not None:
                    reason = abort()
                if reason:
                    stopping = True
                    result.error = result.error or reason
                    hang_up(reason)
                    continue
            if not stopping and _media_outside_scope(call, result.media_peer):
                stopping = True
                result.error = "media_peer_outside_scope"
                hang_up("scope")
                continue
            if phase == "starting":
                if ready:
                    # PJSUA has parsed its configuration; remove the secret now.
                    config_path.unlink(missing_ok=True)
                    if call.account is not None and call.account.registrar is not None:
                        result.registration_attempted = True
                        phase = "registering"
                        deadline = now + call.registration_timeout_seconds
                    else:
                        phase = "dial"
                elif now >= deadline:
                    result.error = "softphone_start_timeout"
                    stopping = True
                    quit_now()
            if phase == "registering":
                if result.registered is True:
                    phase = "dial"
                elif result.registered is False:
                    result.error = "registration_failed"
                    stopping = True
                    quit_now()
                elif now >= deadline:
                    result.error = "registration_timeout"
                    stopping = True
                    quit_now()
            if phase == "dial":
                send("m")
                send(uri)
                result.dialed = True
                mark("DIALED")
                phase = "calling"
                deadline = now + call.answer_timeout_seconds
            elif phase == "calling":
                if disconnected:
                    quit_now()
                elif confirmed_at is not None:
                    phase = "confirmed"
                    deadline = confirmed_at + call.duration_seconds + DURATION_BACKSTOP_SECONDS
                elif now >= deadline:
                    result.error = "no_answer_before_timeout"
                    stopping = True
                    hang_up("answer_timeout")
            elif phase == "confirmed":
                if quality_requested_at is None and confirmed_at is not None and now >= confirmed_at + 0.5:
                    send("dq")
                    quality_requested_at = now
                if disconnected:
                    quit_now()
                elif now >= deadline:
                    hang_up("driver_duration_backstop")
            elif phase == "hangup":
                if disconnected or now >= deadline:
                    quit_now()
            elif phase == "quit" and now >= deadline:
                result.error = result.error or "softphone_quit_timeout"
                _stop_process(process)
                break
            time.sleep(poll_interval)
        process.wait(timeout=QUIT_TIMEOUT_SECONDS)
        result.exit_code = process.returncode
        console.join(timeout=1.0)
        consume()
        if result.error is None and (not result.dialed or not disconnected):
            result.error = "softphone_exited_unexpectedly"
        if confirmed_at is not None:
            ended = next(
                (item["at"] for item in reversed(result.timeline) if item["state"] == "DISCONNECTED"),
                round(clock() - started, 3),
            )
            confirmed_offset = next(
                item["at"] for item in result.timeline if item["state"] == "CONFIRMED"
            )
            result.connected_seconds = round(max(0.0, ended - confirmed_offset), 3)
        if result.answered and hangup_by is None and disconnected:
            hangup_by = "remote"
        result.hangup = hangup_by
        return result
    finally:
        if process is not None:
            _stop_process(process)
            if process.stdin is not None:
                try:
                    process.stdin.close()
                except OSError:
                    pass
        if console is not None:
            console.join(timeout=1.0)
        if master is not None:
            try:
                os.close(master)
            except OSError:
                pass
        raw_text = ""
        try:
            with raw_log.open("rb") as source:
                raw_text = source.read(MAX_LOG_BYTES).decode("utf-8", "replace")
        except OSError:
            pass
        console_text = console.text() if console is not None else ""
        facts = parse_pjsua_log(raw_text + "\n" + console_text)
        result.final_status = facts["final_status"]
        if result.disconnect_status is None:
            result.disconnect_status = facts["disconnect_status"]
            result.disconnect_reason = facts["disconnect_reason"]
        if facts["registered"] is not None and result.registration_attempted:
            result.registered = facts["registered"]
            result.registration_status = facts["registration_status"]
        result.rtp_rx_packets = facts["rtp_rx_packets"]
        result.rtp_tx_packets = facts["rtp_tx_packets"]
        result.codec = facts["codec"] or result.codec
        result.media_direction = facts["media_direction"]
        result.media_peer = facts["media_peer"] or result.media_peer
        if result.error is None and _media_outside_scope(call, result.media_peer):
            result.error = "media_peer_outside_scope"
        if result.final_status is None and result.disconnect_status is not None and not result.answered:
            result.final_status = result.disconnect_status
        if call.transport == "tls":
            verified, detail = tls_verification(
                raw_text + "\n" + console_text, tls_expected_name(call) or ""
            )
            result.tls_verified = verified is True
            result.tls_detail = detail
            if verified is False:
                # PJSIP closed the connection before sending any request on
                # it; the call or registration failed because of this.
                result.error = "tls_verification_failed"
            elif verified is None and result.error is None and (result.answered or result.registered):
                result.error = "tls_verification_not_observed"
        _persist(call.log_file, redact(raw_text, secrets))
        if call.console_file is not None:
            _persist(call.console_file, redact(console_text, secrets))
        shutil.rmtree(private, ignore_errors=True)
