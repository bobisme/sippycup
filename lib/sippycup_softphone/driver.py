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

from .evidence import (
    DEFAULT_DTMF_AFTER_SECONDS,
    DTMF_SETTLE_SECONDS,
    MAX_DTMF_AFTER_SECONDS,
    DtmfError,
    dtmf_digits,
    dtmf_log_facts,
    dtmf_schedule,
    dtmf_seconds,
    negotiated_sdp,
    parse_messages,
    registration_final_status,
    setup_timing,
    srtp_log_facts,
    validate_dtmf,
)

TRANSPORTS = ("udp", "tcp", "tls")
SRTP_MODES = ("off", "optional", "mandatory")
# PJSUA --use-srtp values: 0 disabled, 1 optional (RTP/AVP plus a=crypto),
# 2 mandatory (RTP/SAVP). Keying is SDES (--srtp-keying=0).
SRTP_USE = {"off": 0, "optional": 1, "mandatory": 2}
SDES_CLEARTEXT_WARNING = "sdes-key-exposed-on-cleartext-signaling"
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
# The audio codecs the image's PJSUA build has, as its "Cp" (codec
# priorities) console command lists them (PJSUA 2.17 in the prepared image):
#   speex/16000/1 speex/8000/1 speex/32000/1 iLBC/8000/1 GSM/8000/1
#   PCMU/8000/1 PCMA/8000/1 G722/16000/1 opus/48000/2 (L16 disabled)
# A codec request names one of these; ``--add-codec`` matches by prefix, so
# speex needs its clock rate. ``tests/test_codec_matrix.py`` (a recorded
# listing) and ``make codec-gate`` (the live binary) keep the list equal.
SUPPORTED_CODECS = (
    "PCMU", "PCMA", "G722", "GSM", "iLBC", "opus", "speex/8000", "speex/16000", "speex/32000",
)
_SUPPORTED_BY_LOWER = {name.lower(): name for name in SUPPORTED_CODECS}
# The name PJSUA prints for a negotiated codec ("PCMA", "speex", "opus"),
# lower-cased, for each supported request.
_CODEC_ENCODING = {name: name.split("/", 1)[0].lower() for name in SUPPORTED_CODECS}


def canonical_codec(name: Any) -> str:
    """The supported spelling of a requested codec name (case-insensitive)."""
    if not isinstance(name, str) or _CODEC.fullmatch(name.strip()) is None:
        raise SoftphoneError(f"invalid codec name: {name!r}")
    canonical = _SUPPORTED_BY_LOWER.get(name.strip().lower())
    if canonical is None:
        raise SoftphoneError(
            f"unsupported codec {name!r}: the image's PJSUA supports {', '.join(SUPPORTED_CODECS)}"
        )
    return canonical


def codec_encoding(name: str) -> str:
    """The lower-case encoding name (SDP rtpmap, PJSUA's report) of a supported codec."""
    return _CODEC_ENCODING[canonical_codec(name)]


def parse_codec_list(text: str) -> list[str]:
    """Codec names from PJSUA's ``Cp`` listing (``PRIO<TAB>NAME/RATE/CHANNELS``)."""
    names: list[str] = []
    for line in text.splitlines():
        match = re.match(r"^\s*(\d+)\s+([A-Za-z0-9.-]+)/(\d+)/(\d+)\s*$", line)
        if match is not None and int(match.group(1)) > 0:
            names.append(f"{match.group(2)}/{match.group(3)}")
    return names

_STATE = re.compile(r"Call (\d+) state changed to ([A-Z_]+)")
_DISCONNECTED = re.compile(r"Call (\d+) is DISCONNECTED \[reason=(\d+) \(([^)]*)\)\]")
_REGISTRATION_OK = re.compile(r"(?<!un)registration success, status=(\d{3})\b")
# A word boundary: PJSIP error codes such as status=171165 are not SIP statuses.
_REGISTRATION_FAILED = re.compile(r"(?<!un)registration failed, status=(\d{3})\b", re.I)
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
# SDES master keys in a=crypto lines: media keys, kept out of persisted logs.
_SDES_KEY = re.compile(r"(inline:)[A-Za-z0-9+/=]+")


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
    # bn-2g0: networks (CIDR) the media peer may also lie in, for example a
    # campaign's authorization networks when the media address differs from
    # the signaling address (a proxy in front of media servers).
    allowed_media_networks: tuple[str, ...] | None = None
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
    # RFC 4733 digits sent after answer (``,`` is a 1 s pause), never by
    # SIP INFO or in-band; ``None`` sends nothing.
    dtmf: str | None = None
    dtmf_after_seconds: float = DEFAULT_DTMF_AFTER_SECONDS
    # SDES-SRTP: off, optional, or mandatory.
    srtp: str = "off"
    # True offers only ``codecs`` (plus telephone-event): PJSUA's
    # ``--dis-codec=*`` disables every codec and ``--add-codec`` re-enables
    # the listed ones. False (the default) only raises their priority, and
    # PJSUA still offers every other codec it has.
    exclusive_codecs: bool = False
    # bn-3oib: the first local RTP port PJSUA tries (RTCP is the next one);
    # ``None`` keeps PJSUA's default of 4000. PJSUA moves on by two when the
    # pair is in use, so the port it really used is ``local_rtp_port``.
    rtp_port: int | None = None


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
    # DTMF, SRTP, SDP, and setup facts; ``None`` when not requested or not
    # observed. See ``place_call``.
    dtmf: dict[str, Any] | None = None
    srtp: dict[str, Any] | None = None
    sdp: dict[str, Any] | None = None
    setup: dict[str, Any] | None = None
    local_rtp_port: int | None = None
    warnings: list[str] = field(default_factory=list)
    # Requested, offered, answered, and negotiated codecs (see codec_facts).
    codecs: dict[str, Any] | None = None
    # The media-scope rules and which one admitted the media peer (see
    # media_scope_decision); ``None`` when the call had no media scope.
    media_scope: dict[str, Any] | None = None
    # bn-2jg: the first destination outside the scope that PJSUA sent to
    # (signaling) or that the far end's SDP named (media), from the message
    # log watched during the call; ``None`` when there was none.
    scope_violation: dict[str, Any] | None = None

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
        if canonical_codec(codec) != codec:
            raise SoftphoneError(f"codec {codec!r} must be spelled {canonical_codec(codec)!r}")
    if len(set(call.codecs)) != len(call.codecs):
        raise SoftphoneError("each codec may be requested once")
    if call.answer_timeout_seconds <= 0 or call.registration_timeout_seconds <= 0:
        raise SoftphoneError("timeouts must be positive")
    if call.srtp not in SRTP_MODES:
        raise SoftphoneError("srtp must be off, optional, or mandatory")
    if not isinstance(call.exclusive_codecs, bool):
        raise SoftphoneError("exclusive_codecs must be true or false")
    if call.dtmf is not None:
        try:
            validate_dtmf(call.dtmf)
        except DtmfError as error:
            raise SoftphoneError(str(error)) from error
        after = call.dtmf_after_seconds
        if (
            isinstance(after, bool)
            or not isinstance(after, (int, float))
            or not 0 <= after <= MAX_DTMF_AFTER_SECONDS
        ):
            raise SoftphoneError(
                f"DTMF delay must be from 0 to {MAX_DTMF_AFTER_SECONDS} seconds after answer"
            )
        needed = after + dtmf_seconds(call.dtmf) + DTMF_SETTLE_SECONDS
        if needed > call.duration_seconds:
            raise SoftphoneError(
                f"the call duration ({call.duration_seconds}s) is shorter than the DTMF delay "
                f"plus the digits ({needed:.2f}s)"
            )
    for address in (call.bound_address, call.advertised_address):
        if address is not None:
            _literal_address(address)
    if call.allowed_media_addresses is not None:
        for address in call.allowed_media_addresses:
            _literal_address(address)
    if call.allowed_media_networks is not None:
        for network in call.allowed_media_networks:
            try:
                ipaddress.ip_network(network)
            except ValueError as error:
                raise SoftphoneError(f"invalid media network: {network!r}") from error
    if call.rtp_port is not None and (
        type(call.rtp_port) is not int or not 1024 <= call.rtp_port <= 65534 or call.rtp_port % 2
    ):
        raise SoftphoneError("the local RTP port must be an even integer from 1024 to 65534")
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
    if call.exclusive_codecs is True:
        lines.append("--dis-codec=*")
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
    if call.srtp != "off":
        # SDES keys travel in SDP, so they are confidential only over TLS:
        # require TLS for SRTP when the signaling is TLS; otherwise SRTP is
        # still tested and the result warns that the keys were exposed.
        lines.extend(
            [
                f"--use-srtp={SRTP_USE[call.srtp]}",
                f"--srtp-secure={1 if call.transport == 'tls' else 0}",
                "--srtp-keying=0",
            ]
        )
    if call.rtp_port is not None:
        lines.append(f"--rtp-port={call.rtp_port}")
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
    text = _SDES_KEY.sub(lambda match: match.group(1) + "<redacted>", text)
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


def _observed_peer(text: str) -> str | None:
    """The media peer PJSUA printed, or None for its "-" placeholder."""
    peer = text.rstrip(",")
    return peer if _peer_address(peer) is not None else None


def _peer_port(peer: str) -> int | None:
    if peer.startswith("["):
        tail = peer.split("]", 1)[1] if "]" in peer else ""
        text = tail[1:] if tail.startswith(":") else ""
    else:
        text = peer.rsplit(":", 1)[1] if peer.count(":") == 1 else ""
    return int(text) if text.isdigit() and 1 <= int(text) <= 65535 else None


def media_scope_decision(call: SoftphoneCall, peer: str | None) -> dict[str, Any] | None:
    """Which media-scope rule admitted (or refused) the observed media peer.

    ``None`` when the call has no media scope. Otherwise the rules in force
    and, once PJSUA knows the peer, ``admittedBy``: ``approved-address`` (a
    literal approved address), ``media-network`` (inside ``network``, an
    owner-approved media network), ``any-address`` (no address rule, only a
    port rule), or ``None`` (refused); ``inScope`` is the overall answer
    (``None`` while the peer is unknown). Recorded in the result so the
    evidence shows why media was allowed to flow where it did.
    """
    if (
        call.allowed_media_addresses is None
        and call.allowed_media_networks is None
        and call.allowed_media_ports is None
    ):
        return None
    decision: dict[str, Any] = {
        "rules": {
            "approvedAddresses": (
                None if call.allowed_media_addresses is None else list(call.allowed_media_addresses)
            ),
            "mediaNetworks": (
                None if call.allowed_media_networks is None else list(call.allowed_media_networks)
            ),
            "mediaPorts": (
                None if call.allowed_media_ports is None else list(call.allowed_media_ports)
            ),
        },
        "peer": None,
        "admittedBy": None,
        "network": None,
        "portAdmitted": None,
        "inScope": None,
    }
    # PJSUA prints "peer=-" (or another placeholder) until the first RTP
    # packet arrives; an unknown peer is unknown, not out of scope.
    address = _peer_address(peer) if peer is not None else None
    if address is None:
        return decision
    decision["peer"] = peer
    parsed = ipaddress.ip_address(address)
    if call.allowed_media_addresses is None and call.allowed_media_networks is None:
        decision["admittedBy"] = "any-address"
    elif call.allowed_media_addresses is not None and any(
        ipaddress.ip_address(item) == parsed for item in call.allowed_media_addresses
    ):
        decision["admittedBy"] = "approved-address"
    else:
        for network in call.allowed_media_networks or ():
            candidate = ipaddress.ip_network(network)
            if candidate.version == parsed.version and parsed in candidate:
                decision["admittedBy"] = "media-network"
                decision["network"] = str(candidate)
                break
    address_ok = decision["admittedBy"] is not None
    if call.allowed_media_ports is not None:
        port = _peer_port(peer)
        start, end = call.allowed_media_ports
        decision["portAdmitted"] = port is not None and start <= port <= end
    decision["inScope"] = address_ok and decision["portAdmitted"] is not False
    return decision


def _media_outside_scope(call: SoftphoneCall, peer: str | None) -> bool:
    decision = media_scope_decision(call, peer)
    return decision is not None and decision["inScope"] is False


# -- bn-2jg: watch PJSUA's message log while the call runs ----------------------
#
# PJSUA's "peer=" (above) is where RTP came FROM, so a far end that sends
# from an approved address, or sends nothing, while its SDP points PJSUA's
# RTP/RTCP elsewhere, was never caught; and PJSIP follows a far end's
# Record-Route/Contact for ACK and BYE despite the global ``--outbound``
# route. The driver therefore tails the level-5 message log (written as each
# message is sent or received) and checks every destination PJSUA transmits
# SIP to and every media destination the far end's SDP names.

_LOG_MESSAGE = re.compile(r"\b(TX|RX) \d+ bytes (?:Request|Response) msg \S+")
_TX_DESTINATION = re.compile(
    r"\bTX \d+ bytes (?:Request|Response) msg \S+ \([^)]*\) to (?:UDP|TCP|TLS)6? "
    r"(\[[^\]]*\]|[^\s:\[\]]+):\d+"
)
_SDP_LINE = re.compile(r"^([a-z])=(.*)$")


def tx_destination(line: str) -> str | None:
    """The host PJSUA logged it sent a SIP message to, or ``None``."""
    match = _TX_DESTINATION.search(line)
    if match is None:
        return None
    return match.group(1).strip("[]")


def signaling_destination_allowed(call: SoftphoneCall, host: str) -> bool:
    """Only the literal target, or the reviewed TLS name pinned to it."""
    if call.tls_server_name is not None and host == call.tls_server_name:
        return True
    try:
        return ipaddress.ip_address(host) == ipaddress.ip_address(_literal_address(call.host))
    except (ValueError, SoftphoneError):
        return False


def sdp_media_destinations(lines: Sequence[str]) -> list[tuple[str, int, str]]:
    """``(address, port, "RTP"|"RTCP")`` every active stream of an SDP sends to.

    A media-level ``c=`` overrides the session-level one; ``a=rtcp`` with an
    address moves RTCP; port 0 (a rejected stream) and the unspecified hold
    address send nothing. Addresses are returned as written (a name stays a
    name, so the caller refuses it).
    """
    session: str | None = None
    streams: list[dict[str, Any]] = []
    for raw in lines:
        match = _SDP_LINE.match(raw.strip())
        if match is None:
            continue
        kind, value = match.group(1), match.group(2).strip()
        if kind == "m":
            parts = value.split()
            port_text = parts[1].split("/", 1)[0] if len(parts) > 1 else ""
            port = int(port_text) if port_text.isdigit() else -1
            streams.append({"port": port, "c": None, "rtcp": None})
        elif kind == "c":
            parts = value.split()
            address = parts[2].split("/", 1)[0] if len(parts) >= 3 else value
            if streams:
                streams[-1]["c"] = address
            else:
                session = address
        elif kind == "a" and value.startswith("rtcp:") and streams:
            parts = value[len("rtcp:"):].split()
            rtcp_port = int(parts[0]) if parts and parts[0].isdigit() else -1
            rtcp_address = parts[3] if len(parts) >= 4 else None
            streams[-1]["rtcp"] = (rtcp_address, rtcp_port)
    found: list[tuple[str, int, str]] = []
    for stream in streams:
        if stream["port"] == 0:
            continue
        address = stream["c"] if stream["c"] is not None else session
        if address is None:
            continue
        candidates = [(address, stream["port"], "RTP")]
        if stream["rtcp"] is not None and stream["rtcp"][0] is not None:
            candidates.append((stream["rtcp"][0], stream["rtcp"][1], "RTCP"))
        for item in candidates:
            try:
                if ipaddress.ip_address(item[0]).is_unspecified:
                    continue
            except ValueError:
                pass
            if item not in found:
                found.append(item)
    return found


def media_destination_refusal(call: SoftphoneCall, destination: tuple[str, int, str]) -> str | None:
    """Why a media destination is outside the call's media scope, or ``None``."""
    address, port, what = destination
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return f"{what} destination {address!r} is not a literal address"
    if call.allowed_media_addresses is not None or call.allowed_media_networks is not None:
        admitted = any(
            ipaddress.ip_address(item) == parsed for item in call.allowed_media_addresses or ()
        ) or any(
            ipaddress.ip_network(item).version == parsed.version and parsed in ipaddress.ip_network(item)
            for item in call.allowed_media_networks or ()
        )
        if not admitted:
            return f"{what} destination {address} is not an approved address or media network"
    if what == "RTP" and call.allowed_media_ports is not None:
        start, end = call.allowed_media_ports
        if not start <= port <= end:
            return f"RTP port {port} at {address} is outside the approved media ports {start}-{end}"
    return None


class _ScopeWatch:
    """Incrementally read PJSUA's message log and report the first violation."""

    def __init__(self, path: Path, call: SoftphoneCall) -> None:
        self._path = path
        self._call = call
        self._offset = 0
        self._partial = ""
        self._message: dict[str, Any] | None = None
        self._media = (
            call.allowed_media_addresses is not None
            or call.allowed_media_networks is not None
            or call.allowed_media_ports is not None
        )

    def poll(self) -> list[dict[str, Any]]:
        """Every violation in the log lines written since the last poll."""
        if self._offset >= MAX_LOG_BYTES:
            return []
        try:
            descriptor = os.open(self._path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            return []
        try:
            os.lseek(descriptor, self._offset, os.SEEK_SET)
            chunk = os.read(descriptor, min(1 << 20, MAX_LOG_BYTES - self._offset))
        finally:
            os.close(descriptor)
        if not chunk:
            return []
        self._offset += len(chunk)
        *complete, self._partial = (self._partial + chunk.decode("utf-8", "replace")).split("\n")
        found: list[dict[str, Any]] = []
        for line in complete:
            violation = self._line(line.rstrip("\r"))
            if violation is not None:
                found.append(violation)
        return found

    def _line(self, line: str) -> dict[str, Any] | None:
        start = _LOG_MESSAGE.search(line)
        if start is not None:
            self._message = {"direction": start.group(1), "header": line.strip(), "lines": []}
            if start.group(1) == "TX" and self._call.pin_signaling:
                host = tx_destination(line)
                if host is not None and not signaling_destination_allowed(self._call, host):
                    return {
                        "kind": "signaling", "what": "SIP", "address": host,
                        "detail": f"PJSUA sent SIP to {host}, which is not the approved target "
                                  f"{self._call.host}",
                    }
            return None
        if self._message is None:
            return None
        if "--end msg--" not in line:
            if len(self._message["lines"]) < 400:
                self._message["lines"].append(line)
            return None
        message, self._message = self._message, None
        if message["direction"] != "RX" or not self._media:
            return None
        for destination in sdp_media_destinations(message["lines"]):
            reason = media_destination_refusal(self._call, destination)
            if reason is not None:
                return {
                    "kind": "media", "what": destination[2], "address": destination[0],
                    "port": destination[1], "detail": f"the far end's SDP sends {reason}",
                }
        return None


def _kill_now(process: subprocess.Popen[bytes]) -> None:
    """SIGKILL PJSUA's process group: a graceful quit would hang up (BYE) along the bad route."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def codec_matches(entry: Mapping[str, Any], requested: str) -> bool:
    """Whether an SDP codec entry is the requested supported codec."""
    name = str(entry.get("name") or "").lower()
    canonical = canonical_codec(requested)
    if name != codec_encoding(canonical):
        return False
    if "/" in canonical:
        return entry.get("clockRate") == int(canonical.split("/", 1)[1])
    return True


def _same_codec(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    if left.get("name") is None or right.get("name") is None:
        return left.get("payloadType") == right.get("payloadType")
    return (
        str(left["name"]).lower() == str(right["name"]).lower()
        and left.get("clockRate") == right.get("clockRate")
    )


def codec_facts(
    requested: Sequence[str],
    exclusive: bool,
    offer: Mapping[str, Any] | None,
    answer: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """What was asked for, offered, answered, and negotiated, from the SDP.

    ``unoffered`` lists answer codecs that the offer did not contain (a far
    end that answers with a codec it was not offered). ``offerOnlyRequested``
    is true when every offered codec is one of ``requested``; it is only
    expected to hold for an exclusive offer.
    """
    offered = list((offer or {}).get("codecs") or [])
    answered = list((answer or {}).get("codecs") or [])
    unoffered = [
        item for item in answered if not any(_same_codec(item, other) for other in offered)
    ]
    first = answered[0] if answered else None
    return {
        "requested": list(requested),
        "exclusive": exclusive,
        "offered": offered,
        "answered": answered,
        "negotiated": None if first is None else first.get("name"),
        "negotiatedPayloadType": None if first is None else first.get("payloadType"),
        "negotiatedRequested": (
            None if first is None else any(codec_matches(first, name) for name in requested)
        ),
        "offerOnlyRequested": (
            None
            if offer is None
            else all(any(codec_matches(item, name) for name in requested) for item in offered)
        ),
        "unoffered": unoffered,
        "source": "pjsua-log",
    }


def _observe_media_facts(
    call: SoftphoneCall, result: SoftphoneResult, raw_text: str, combined: str
) -> None:
    """Fill registration, SDP, setup, SRTP, and DTMF facts from PJSUA's log."""
    messages = parse_messages(raw_text)
    negotiated = negotiated_sdp(messages)
    offer = negotiated["offer"]
    answer = negotiated["answer"]
    if offer is not None or answer is not None:
        result.sdp = negotiated
    if result.dialed:
        result.codecs = codec_facts(call.codecs, call.exclusive_codecs, offer, answer)
        if result.codecs["unoffered"] and result.error in (None, "softphone_exited_unexpectedly"):
            result.error = "codec_not_offered"
    result.local_rtp_port = offer["port"] if offer is not None else None
    result.setup = setup_timing(messages)
    if result.registration_attempted and result.registered is False and result.registration_status is None:
        # A rejected digest ends with a PJSIP error rather than a SIP status
        # line; the final REGISTER response in the message log is the status.
        result.registration_status = registration_final_status(messages)
    if result.dialed:
        facts = srtp_log_facts(combined)
        active = bool(result.answered and facts["active"] is True)
        result.srtp = {
            "requested": call.srtp,
            "keying": "sdes" if call.srtp != "off" else None,
            "active": active,
            "suite": facts["suite"] if active else None,
            "offerProfile": offer["profile"] if offer else None,
            "answerProfile": answer["profile"] if answer else None,
            "offerCrypto": bool(offer and offer["cryptoSuites"]),
            "answerCrypto": bool(answer and answer["cryptoSuites"]),
            "secureSignaling": call.transport == "tls",
            "source": "pjsua-log",
        }
        if call.srtp != "off" and call.transport != "tls":
            result.warnings.append(SDES_CLEARTEXT_WARNING)
        if call.srtp == "mandatory" and not active and result.error in (None, "softphone_exited_unexpectedly"):
            result.error = "srtp_not_negotiated"
    if call.dtmf is not None:
        # PJSUA prints its console lines into the log file as well: read the
        # log, and the console only for what the log lacks, never both.
        facts = dtmf_log_facts(raw_text)
        console = dtmf_log_facts(combined[len(raw_text):])
        for key in ("sent", "received"):
            facts[key] = facts[key] or console[key]
        facts["errors"] = facts["errors"] or console["errors"]
        facts["remoteUnsupported"] = facts["remoteUnsupported"] or console["remoteUnsupported"]
        requested = dtmf_digits(call.dtmf)
        negotiated_events = None if answer is None else bool(answer["telephoneEvents"])
        if facts["remoteUnsupported"] or (result.answered and negotiated_events is False):
            status = "notNegotiated"
        elif not result.answered:
            status = "notSent"
        elif facts["sent"] == requested:
            status = "sent"
        elif facts["sent"]:
            status = "incomplete"
        else:
            status = "notSent"
        result.dtmf = {
            "requested": call.dtmf,
            "requestedDigits": requested,
            "afterSeconds": call.dtmf_after_seconds,
            "method": "rfc4733",
            "status": status,
            "negotiated": negotiated_events,
            "offeredPayloadTypes": offer["telephoneEvents"] if offer else [],
            "answeredPayloadTypes": answer["telephoneEvents"] if answer else [],
            "sent": facts["sent"],
            "received": facts["received"],
            "errors": facts["errors"][:4],
            "source": "pjsua-log",
        }
        if result.answered and result.error is None and status != "sent":
            result.error = "dtmf_not_negotiated" if status == "notNegotiated" else "dtmf_not_sent"


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
            facts["media_peer"] = _observed_peer(match.group(4)) or facts["media_peer"]
        if stripped.startswith("RX pt="):
            direction = "rx"
        elif stripped.startswith("TX pt="):
            direction = "tx"
        elif direction is not None and (match := _RTP_TOTAL.search(stripped)):
            facts[f"rtp_{direction}_packets"] = int(match.group(1))
            direction = None
    facts["duration_exceeded"] = bool(_DURATION_EXCEEDED.search(text))
    return facts


_ADDRESS_CHANGE = re.compile(
    r"IP address change detected for account \d+ \((\S+):(\d+) --> (\S+):(\d+)\)"
)


def nat_addresses(text: str) -> list[dict[str, Any]]:
    """Where the far end saw this softphone, when that differs from its own address.

    PJSUA compares its own address with the ``received``/``rport`` the
    registrar puts in the Via of its response, and on a difference prints
    ``IP address change detected for account N (A:p --> B:q)`` and moves its
    Contact to B:q. B is the address the target saw: our own source after NAT
    (on an engagement, usually the public address the owner allowlisted).
    Only literal IP addresses are returned, each once.
    """
    found: list[dict[str, Any]] = []
    for match in _ADDRESS_CHANGE.finditer(text):
        local, translated = match.group(1).strip("[]"), match.group(3).strip("[]")
        try:
            local_text = str(ipaddress.ip_address(local))
            translated_text = str(ipaddress.ip_address(translated))
        except ValueError:
            continue
        if translated_text == local_text or any(item["address"] == translated_text for item in found):
            continue
        found.append({"address": translated_text, "port": int(match.group(4)),
                      "local": local_text, "localPort": int(match.group(2))})
    return found


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
    """Stop and reap PJSUA, then kill anything left in its process group.

    PJSUA runs as a session leader, so its process group holds every
    descendant (for example PJSUA under the ``unshare`` name-pinning
    wrapper). A descendant that outlives the leader could still write into
    the private directory after the driver removed it.
    """
    if process.poll() is None:
        for signum in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, signum)
            except ProcessLookupError:
                break
            try:
                process.wait(timeout=grace)
                break
            except subprocess.TimeoutExpired:
                continue
        if process.poll() is None:  # pragma: no cover - SIGKILL could not be delivered
            try:
                process.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


PRIVATE_REMOVE_ATTEMPTS = 20
PRIVATE_REMOVE_DELAY = 0.05


def remove_private_directory(private: Path, secret_files: Sequence[Path] = ()) -> bool:
    """Remove a private directory: secret files first, then retry the tree.

    Returns True when the directory is gone. A late writer can recreate a
    log file between the tree walk and ``rmdir``; retrying briefly covers it.
    """
    for path in secret_files:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
    for attempt in range(PRIVATE_REMOVE_ATTEMPTS):
        shutil.rmtree(private, ignore_errors=True)
        if not os.path.lexists(private):
            return True
        if attempt + 1 < PRIVATE_REMOVE_ATTEMPTS:
            time.sleep(PRIVATE_REMOVE_DELAY)
    return False


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
        scope_probes = 0
        scope_probed_at: float | None = None
        stopping = False
        hangup_by: str | None = None
        # Each chunk is one legacy-console command pair: ``#`` (send RFC 2833
        # DTMF) and then the digits. PJSUA refuses, rather than falling back
        # to SIP INFO or in-band tones, when the peer did not negotiate
        # telephone-event.
        dtmf_plan = dtmf_schedule(call.dtmf) if call.dtmf is not None else []
        dtmf_index = 0

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
                    result.media_peer = _observed_peer(match.group(4)) or result.media_peer
                    result.codec = match.group(1)
                if _DURATION_EXCEEDED.search(line):
                    hangup_by = hangup_by or "duration"

        watch = _ScopeWatch(raw_log, call)
        while True:
            consume()
            now = clock()
            if process.poll() is not None:
                break
            violations = watch.poll()
            signaling = next((item for item in violations if item["kind"] == "signaling"), None)
            media = next((item for item in violations if item["kind"] == "media"), None)
            if signaling is not None and result.error != "signaling_outside_scope":
                # PJSIP already sent that one message; stop it before it
                # sends anything else (a BYE or quit would follow the same
                # route). The far end's dialog then times out by itself.
                result.scope_violation = signaling
                result.error = "signaling_outside_scope"
                stopping = True
                hangup_by = hangup_by or "scope"
                _kill_now(process)
                continue
            if media is not None and result.scope_violation is None:
                result.scope_violation = media
                if not stopping:
                    stopping = True
                    result.error = "media_peer_outside_scope"
                    hang_up("scope")
                    continue
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
                # bn-2g0: PJSUA prints the media peer only in a call dump, so
                # with a media scope ask for one right away and then every
                # 0.1 s until the peer is known (at most 5), instead of waiting
                # 0.5 s while RTP flows to a possibly unapproved address.
                if (
                    (
                        call.allowed_media_addresses is not None
                        or call.allowed_media_networks is not None
                        or call.allowed_media_ports is not None
                    )
                    and result.media_peer is None
                    and quality_requested_at is None
                    and scope_probes < 5
                    and not stopping
                    and (scope_probed_at is None or now >= scope_probed_at + 0.1)
                ):
                    send("dq")
                    scope_probes += 1
                    scope_probed_at = now
                if quality_requested_at is None and confirmed_at is not None and now >= confirmed_at + 0.5:
                    send("dq")
                    quality_requested_at = now
                if (
                    dtmf_index < len(dtmf_plan)
                    and confirmed_at is not None
                    and not disconnected
                    and not stopping
                    and now >= confirmed_at + call.dtmf_after_seconds + dtmf_plan[dtmf_index][0]
                ):
                    send("#")
                    send(dtmf_plan[dtmf_index][1])
                    mark("DTMF")
                    dtmf_index += 1
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
        # Whatever PJSUA logged after the last poll (for example while it quit).
        for violation in watch.poll():
            if result.scope_violation is None or (
                violation["kind"] == "signaling" and result.scope_violation["kind"] != "signaling"
            ):
                result.scope_violation = violation
                result.error = (
                    "signaling_outside_scope" if violation["kind"] == "signaling" else "media_peer_outside_scope"
                )
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
        violation = result.scope_violation
        if (result.media_peer is None and violation is not None and violation.get("kind") == "media"
                and violation.get("what") != "RTCP" and violation.get("address") and violation.get("port")):
            # Stopped on the far end's SDP before PJSUA reported a media peer
            # (the hang-up can win that race): the peer is the one the SDP
            # named, so the report and the cockpit can still say which address.
            address = str(violation["address"])
            result.media_peer = f"[{address}]:{violation['port']}" if ":" in address else f"{address}:{violation['port']}"
        if result.error is None and _media_outside_scope(call, result.media_peer):
            result.error = "media_peer_outside_scope"
        result.media_scope = media_scope_decision(call, result.media_peer)
        if result.scope_violation is not None and result.scope_violation["kind"] == "media" and result.media_scope:
            # The far end's SDP, not the received-RTP peer, decided this.
            result.media_scope["inScope"] = False
            result.media_scope["sdpRefused"] = dict(result.scope_violation)
        if result.final_status is None and result.disconnect_status is not None and not result.answered:
            result.final_status = result.disconnect_status
        _observe_media_facts(call, result, raw_text, raw_text + "\n" + console_text)
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
        if not remove_private_directory(private, (config_path,)):
            result.warnings.append("private-directory-not-removed")
