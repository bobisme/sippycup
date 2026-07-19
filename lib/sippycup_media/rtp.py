"""Bounded RTP canary and RFC 4733 packet planning/sending."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from .canary import CODECS, DIRECTIONS, PACKETIZATION_MS, Codec

SESSION_VERSION = "sippycup.media-session/v1"
PLAN_VERSION = "sippycup.media-packet-plan/v1"
MAX_SESSION_BYTES = 256 * 1024
MAX_SDP_BYTES = 32 * 1024
MAX_REVISIONS = 8
MAX_DIGITS = 16
MAX_ECHO_TIMEOUT_MS = 5000
RTP_SEQUENCE_START = 1000
RTP_TIMESTAMP_START = 0
RTP_SSRC = 0x5A17C0DE
DTMF_DURATION_MS = 100
DTMF_END_PACKETS = 3
DTMF_GAP_MS = 40
DTMF_VOLUME = 10
DTMF_EVENTS = {
    **{str(value): value for value in range(10)},
    "*": 10,
    "#": 11,
    "A": 12,
    "B": 13,
    "C": 14,
    "D": 15,
}


class MediaSessionError(ValueError):
    """A fail-closed session or SDP error suitable for CLI output."""


class MediaNetworkError(RuntimeError):
    """A bind, send, or echo-validation error."""


@dataclass(frozen=True, slots=True)
class SdpAudio:
    address: str
    port: int
    protocol: str
    packetization_ms: int
    payloads: tuple[tuple[int, str, int], ...]


@dataclass(frozen=True, slots=True)
class Revision:
    activation_ms: int
    source_address: str
    source_port: int
    destination_address: str
    destination_port: int
    family: int
    codec_payload_type: int
    telephone_event_payload_type: int | None


@dataclass(frozen=True, slots=True)
class MediaSession:
    direction: str
    codec: Codec
    digits: str
    echo_required: bool
    echo_timeout_ms: int
    revisions: tuple[Revision, ...]
    asset_path: Path
    asset_sha256: str


@dataclass(frozen=True, slots=True)
class PlannedPacket:
    scheduled_ms: int
    revision_index: int
    kind: str
    sequence: int
    timestamp: int
    payload_type: int
    marker: bool
    ssrc: int
    source_address: str
    source_port: int
    destination_address: str
    destination_port: int
    payload: bytes
    digit: str | None = None
    event: int | None = None
    event_end: bool | None = None
    event_duration: int | None = None

    def wire_bytes(self) -> bytes:
        return struct.pack(
            "!BBHII",
            0x80,
            (0x80 if self.marker else 0) | self.payload_type,
            self.sequence,
            self.timestamp,
            self.ssrc,
        ) + self.payload


@dataclass(frozen=True, slots=True)
class PacketPlan:
    session: MediaSession
    packets: tuple[PlannedPacket, ...]


def _mapping(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise MediaSessionError(f"{field} must be an object")
    return value


def _exact_keys(
    value: dict[str, object],
    field: str,
    required: set[str],
) -> None:
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - required)
    if missing:
        raise MediaSessionError(f"{field} missing fields: {', '.join(missing)}")
    if unknown:
        raise MediaSessionError(
            f"{field} contains unsupported fields: {', '.join(unknown)}"
        )


def _integer(
    value: object, field: str, minimum: int, maximum: int
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MediaSessionError(f"{field} must be an integer")
    if value < minimum or value > maximum:
        raise MediaSessionError(
            f"{field} must be between {minimum} and {maximum}"
        )
    return value


def _literal_unicast(value: str, field: str) -> tuple[str, int]:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise MediaSessionError(f"{field} must be a literal IP address") from error
    if (
        address.is_unspecified
        or address.is_multicast
        or (isinstance(address, ipaddress.IPv4Address) and address.is_reserved)
    ):
        raise MediaSessionError(f"{field} must be a usable unicast address")
    return str(address), socket.AF_INET6 if address.version == 6 else socket.AF_INET


def _parse_connection(line: str, field: str) -> tuple[str, int]:
    match = re.fullmatch(r"c=IN (IP4|IP6) ([^ ]+)", line)
    if match is None:
        raise MediaSessionError(f"{field} has unsupported connection syntax")
    address, family = _literal_unicast(match.group(2), field)
    declared = socket.AF_INET if match.group(1) == "IP4" else socket.AF_INET6
    if family != declared:
        raise MediaSessionError(f"{field} address family disagrees with SDP")
    return address, family


def parse_sdp(raw: str, field: str) -> SdpAudio:
    try:
        encoded = raw.encode("utf-8")
    except UnicodeEncodeError as error:
        raise MediaSessionError(f"{field} is not valid UTF-8 text") from error
    if len(encoded) > MAX_SDP_BYTES:
        raise MediaSessionError(f"{field} exceeds {MAX_SDP_BYTES} bytes")
    if "\x00" in raw:
        raise MediaSessionError(f"{field} contains NUL")
    lines = [line.strip() for line in raw.replace("\r\n", "\n").split("\n")]
    lines = [line for line in lines if line]
    if len(lines) > 256 or any(len(line) > 1024 for line in lines):
        raise MediaSessionError(f"{field} exceeds SDP structural limits")
    if any(
        line.lower().startswith(
            ("a=crypto:", "a=fingerprint:", "a=setup:", "a=key-mgmt:")
        )
        for line in lines
    ):
        raise MediaSessionError(
            f"{field} contains media keying; only plain RTP/AVP is supported"
        )

    session_connection: str | None = None
    audio_sections: list[list[str]] = []
    current: list[str] | None = None
    for line in lines:
        if line.startswith("m="):
            current = [line]
            if line.startswith("m=audio "):
                audio_sections.append(current)
            continue
        if current is not None:
            current.append(line)
        elif line.startswith("c="):
            session_connection = line
    if len(audio_sections) != 1:
        raise MediaSessionError(f"{field} must contain exactly one audio section")
    section = audio_sections[0]
    media = section[0][2:].split()
    if len(media) < 4 or media[0] != "audio":
        raise MediaSessionError(f"{field} has malformed audio media line")
    if "/" in media[1]:
        raise MediaSessionError(f"{field} media port counts are unsupported")
    port = _integer_from_text(media[1], f"{field} audio port", 1024, 65535)
    protocol = media[2].upper()
    if protocol != "RTP/AVP":
        raise MediaSessionError(
            f"{field} protocol {protocol!r} is unsupported; expected RTP/AVP"
        )
    payload_ids = tuple(
        _integer_from_text(item, f"{field} payload type", 0, 127)
        for item in media[3:]
    )
    if len(set(payload_ids)) != len(payload_ids):
        raise MediaSessionError(f"{field} repeats a payload type")

    connection_lines = [line for line in section[1:] if line.startswith("c=")]
    connection = connection_lines[-1] if connection_lines else session_connection
    if connection is None:
        raise MediaSessionError(f"{field} has no connection address")
    address, _ = _parse_connection(connection, f"{field} connection")

    mappings: dict[int, tuple[str, int]] = {
        0: ("PCMU", 8000),
        8: ("PCMA", 8000),
        9: ("G722", 8000),
    }
    for line in section[1:]:
        match = re.fullmatch(
            r"a=rtpmap:(\d+) ([A-Za-z0-9_-]+)/(\d+)(?:/\d+)?",
            line,
            re.IGNORECASE,
        )
        if match is None:
            continue
        payload_type = _integer_from_text(
            match.group(1), f"{field} rtpmap payload", 0, 127
        )
        if payload_type not in payload_ids:
            raise MediaSessionError(
                f"{field} maps payload {payload_type} outside the media line"
            )
        mapping = (match.group(2).upper(), int(match.group(3)))
        if payload_type in mappings and mappings[payload_type] != mapping:
            raise MediaSessionError(
                f"{field} remaps static payload {payload_type} incorrectly"
            )
        mappings[payload_type] = mapping
    ptime_values = [
        _integer_from_text(
            line.removeprefix("a=ptime:"),
            f"{field} packetization",
            1,
            1000,
        )
        for line in section[1:]
        if line.startswith("a=ptime:")
    ]
    if ptime_values != [PACKETIZATION_MS]:
        raise MediaSessionError(
            f"{field} must declare exactly a=ptime:{PACKETIZATION_MS}"
        )
    payloads = tuple(
        (payload_type, *mappings[payload_type])
        for payload_type in payload_ids
        if payload_type in mappings
    )
    return SdpAudio(address, port, protocol, PACKETIZATION_MS, payloads)


def _integer_from_text(
    value: str, field: str, minimum: int, maximum: int
) -> int:
    if not re.fullmatch(r"\d+", value):
        raise MediaSessionError(f"{field} must be an integer")
    return _integer(int(value), field, minimum, maximum)


def _payload_for(
    audio: SdpAudio, encoding: str, clock_rate: int
) -> int | None:
    matches = [
        payload_type
        for payload_type, name, clock in audio.payloads
        if name == encoding and clock == clock_rate
    ]
    if len(matches) > 1:
        raise MediaSessionError(
            f"SDP maps {encoding}/{clock_rate} more than once"
        )
    return matches[0] if matches else None


def _parse_revision(
    value: object,
    index: int,
    codec: Codec,
    digits: str,
) -> Revision:
    item = _mapping(value, f"revisions[{index}]")
    _exact_keys(
        item,
        f"revisions[{index}]",
        {"activationMs", "localSdp", "remoteSdp"},
    )
    activation = _integer(
        item["activationMs"], f"revisions[{index}].activationMs", 0, 980
    )
    if activation % PACKETIZATION_MS:
        raise MediaSessionError(
            f"revisions[{index}].activationMs must align to "
            f"{PACKETIZATION_MS} ms packetization"
        )
    local_raw = item["localSdp"]
    remote_raw = item["remoteSdp"]
    if not isinstance(local_raw, str) or not isinstance(remote_raw, str):
        raise MediaSessionError(
            f"revisions[{index}] localSdp and remoteSdp must be strings"
        )
    local = parse_sdp(local_raw, f"revisions[{index}].localSdp")
    remote = parse_sdp(remote_raw, f"revisions[{index}].remoteSdp")
    source_address, source_family = _literal_unicast(
        local.address, f"revisions[{index}] local address"
    )
    destination_address, destination_family = _literal_unicast(
        remote.address, f"revisions[{index}] remote address"
    )
    if source_family != destination_family:
        raise MediaSessionError(
            f"revisions[{index}] local and remote address families differ"
        )
    local_codec = _payload_for(local, codec.name, codec.rtp_clock_hz)
    remote_codec = _payload_for(remote, codec.name, codec.rtp_clock_hz)
    if local_codec is None or remote_codec is None:
        raise MediaSessionError(
            f"revisions[{index}] does not negotiate {codec.name}/"
            f"{codec.rtp_clock_hz}"
        )
    if local_codec != remote_codec:
        raise MediaSessionError(
            f"revisions[{index}] codec payload mappings disagree"
        )
    local_event = _payload_for(local, "TELEPHONE-EVENT", codec.rtp_clock_hz)
    remote_event = _payload_for(remote, "TELEPHONE-EVENT", codec.rtp_clock_hz)
    event_payload: int | None = None
    if digits:
        if (
            local_event is None
            or remote_event is None
            or local_event != remote_event
            or not 96 <= local_event <= 127
        ):
            raise MediaSessionError(
                f"revisions[{index}] must negotiate one matching dynamic "
                f"telephone-event/{codec.rtp_clock_hz} payload"
            )
        event_payload = local_event
    return Revision(
        activation,
        source_address,
        local.port,
        destination_address,
        remote.port,
        source_family,
        local_codec,
        event_payload,
    )


def default_asset_root() -> Path:
    source = Path(__file__).resolve().parents[2] / "media" / "canary-v1"
    if source.is_dir():
        return source
    return Path("/usr/local/share/sippycup/media/canary-v1")


def load_session(path: Path, asset_root: Path | None = None) -> MediaSession:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise MediaSessionError(f"cannot read session: {error}") from error
    if len(raw) > MAX_SESSION_BYTES:
        raise MediaSessionError(f"session exceeds {MAX_SESSION_BYTES} bytes")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise MediaSessionError(f"invalid session JSON: {error}") from error
    document = _mapping(value, "session")
    _exact_keys(
        document,
        "session",
        {"apiVersion", "direction", "codec", "digits", "echo", "revisions"},
    )
    if document["apiVersion"] != SESSION_VERSION:
        raise MediaSessionError(f"apiVersion must equal {SESSION_VERSION}")
    direction = document["direction"]
    if direction not in DIRECTIONS:
        raise MediaSessionError(
            f"direction must be one of {', '.join(DIRECTIONS)}"
        )
    codec = next(
        (item for item in CODECS if item.name == document["codec"]), None
    )
    if codec is None:
        raise MediaSessionError("codec must be PCMU, PCMA, or G722")
    digits = document["digits"]
    if not isinstance(digits, str) or len(digits) > MAX_DIGITS:
        raise MediaSessionError(f"digits must be a string of at most {MAX_DIGITS}")
    if any(digit not in DTMF_EVENTS for digit in digits):
        raise MediaSessionError("digits may contain only 0-9, *, #, and A-D")
    echo = _mapping(document["echo"], "echo")
    _exact_keys(echo, "echo", {"required", "timeoutMs"})
    if type(echo["required"]) is not bool:
        raise MediaSessionError("echo.required must be a boolean")
    timeout = _integer(
        echo["timeoutMs"], "echo.timeoutMs", PACKETIZATION_MS, MAX_ECHO_TIMEOUT_MS
    )
    raw_revisions = document["revisions"]
    if (
        not isinstance(raw_revisions, list)
        or not raw_revisions
        or len(raw_revisions) > MAX_REVISIONS
    ):
        raise MediaSessionError(
            f"revisions must contain between 1 and {MAX_REVISIONS} entries"
        )
    revisions = tuple(
        _parse_revision(item, index, codec, digits)
        for index, item in enumerate(raw_revisions)
    )
    activations = tuple(item.activation_ms for item in revisions)
    if activations[0] != 0 or tuple(sorted(set(activations))) != activations:
        raise MediaSessionError(
            "revision activationMs values must start at zero and strictly increase"
        )

    root = asset_root or default_asset_root()
    manifest_path = root / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise MediaSessionError(f"cannot load canary manifest: {error}") from error
    assets = [
        item
        for item in manifest.get("assets", ())
        if item.get("codec") == codec.name
        and item.get("direction") == direction
    ]
    if len(assets) != 1:
        raise MediaSessionError("canary manifest has no unique matching asset")
    asset = assets[0]
    asset_path = root / str(asset.get("filename"))
    try:
        payload = asset_path.read_bytes()
    except OSError as error:
        raise MediaSessionError(f"cannot read canary asset: {error}") from error
    digest = hashlib.sha256(payload).hexdigest()
    if digest != asset.get("sha256") or len(payload) != 8000:
        raise MediaSessionError("canary asset size or SHA-256 disagrees with manifest")
    return MediaSession(
        str(direction),
        codec,
        digits,
        bool(echo["required"]),
        timeout,
        revisions,
        asset_path,
        digest,
    )


def _revision_at(revisions: Sequence[Revision], scheduled_ms: int) -> int:
    result = 0
    for index, revision in enumerate(revisions):
        if revision.activation_ms <= scheduled_ms:
            result = index
        else:
            break
    return result


def _packet(
    session: MediaSession,
    scheduled_ms: int,
    sequence: int,
    timestamp: int,
    payload: bytes,
    *,
    kind: str,
    marker: bool,
    digit: str | None = None,
    event: int | None = None,
    event_end: bool | None = None,
    event_duration: int | None = None,
) -> PlannedPacket:
    revision_index = _revision_at(session.revisions, scheduled_ms)
    revision = session.revisions[revision_index]
    payload_type = (
        revision.codec_payload_type
        if kind == "audio"
        else revision.telephone_event_payload_type
    )
    if payload_type is None:
        raise MediaSessionError(
            f"active revision {revision_index} has no telephone-event payload"
        )
    return PlannedPacket(
        scheduled_ms,
        revision_index,
        kind,
        sequence,
        timestamp,
        payload_type,
        marker,
        RTP_SSRC,
        revision.source_address,
        revision.source_port,
        revision.destination_address,
        revision.destination_port,
        payload,
        digit,
        event,
        event_end,
        event_duration,
    )


def build_packet_plan(session: MediaSession) -> PacketPlan:
    try:
        payload = session.asset_path.read_bytes()
    except OSError as error:
        raise MediaSessionError(f"cannot read canary asset: {error}") from error
    if (
        len(payload) != 8000
        or hashlib.sha256(payload).hexdigest() != session.asset_sha256
    ):
        raise MediaSessionError(
            "canary asset changed after session validation; refusing to send"
        )
    audio_packets = len(payload) // 160
    packets: list[PlannedPacket] = []
    sequence = RTP_SEQUENCE_START
    for index in range(audio_packets):
        scheduled = index * PACKETIZATION_MS
        packets.append(
            _packet(
                session,
                scheduled,
                sequence,
                RTP_TIMESTAMP_START + index * 160,
                payload[index * 160 : (index + 1) * 160],
                kind="audio",
                marker=index == 0,
            )
        )
        sequence += 1

    event_start_ms = audio_packets * PACKETIZATION_MS
    event_timestamp = RTP_TIMESTAMP_START + audio_packets * 160
    progress_packets = DTMF_DURATION_MS // PACKETIZATION_MS
    for digit in session.digits:
        event = DTMF_EVENTS[digit]
        for index in range(progress_packets + DTMF_END_PACKETS - 1):
            end = index >= progress_packets - 1
            duration = (
                progress_packets
                if end
                else index + 1
            ) * PACKETIZATION_MS * session.codec.rtp_clock_hz // 1000
            event_payload = struct.pack(
                "!BBH",
                event,
                (0x80 if end else 0) | DTMF_VOLUME,
                duration,
            )
            packets.append(
                _packet(
                    session,
                    event_start_ms + index * PACKETIZATION_MS,
                    sequence,
                    event_timestamp,
                    event_payload,
                    kind="telephone-event",
                    marker=index == 0,
                    digit=digit,
                    event=event,
                    event_end=end,
                    event_duration=duration,
                )
            )
            sequence += 1
        advance_ms = (
            DTMF_DURATION_MS
            + (DTMF_END_PACKETS - 1) * PACKETIZATION_MS
            + DTMF_GAP_MS
        )
        event_start_ms += advance_ms
        event_timestamp += advance_ms * session.codec.rtp_clock_hz // 1000
    if len(packets) > 200:
        raise MediaSessionError("compiled packet plan exceeds 200 packets")
    return PacketPlan(session, tuple(packets))


def packet_plan_document(plan: PacketPlan) -> dict[str, object]:
    return {
        "apiVersion": PLAN_VERSION,
        "direction": plan.session.direction,
        "codec": plan.session.codec.name,
        "assetSha256": plan.session.asset_sha256,
        "packetizationMs": PACKETIZATION_MS,
        "ssrc": RTP_SSRC,
        "packets": [
            {
                "scheduledMs": packet.scheduled_ms,
                "revision": packet.revision_index,
                "kind": packet.kind,
                "sequence": packet.sequence,
                "timestamp": packet.timestamp,
                "payloadType": packet.payload_type,
                "marker": packet.marker,
                "source": f"{packet.source_address}:{packet.source_port}",
                "destination": (
                    f"{packet.destination_address}:{packet.destination_port}"
                ),
                "payloadBytes": len(packet.payload),
                "payloadSha256": hashlib.sha256(packet.payload).hexdigest(),
                **(
                    {
                        "digit": packet.digit,
                        "event": packet.event,
                        "end": packet.event_end,
                        "duration": packet.event_duration,
                    }
                    if packet.kind == "telephone-event"
                    else {}
                ),
            }
            for packet in plan.packets
        ],
    }


def validate_telephone_events(
    packets: Sequence[PlannedPacket],
    expected_digits: str,
    *,
    clock_rate_hz: int = 8000,
) -> dict[str, object]:
    """Validate the exact bounded RFC 4733 event sequence emitted by Sippycup."""
    if (
        len(expected_digits) > MAX_DIGITS
        or any(digit not in DTMF_EVENTS for digit in expected_digits)
    ):
        raise MediaSessionError("expected DTMF digits are invalid")
    event_packets = [packet for packet in packets if packet.kind == "telephone-event"]
    expected_per_digit = (
        DTMF_DURATION_MS // PACKETIZATION_MS + DTMF_END_PACKETS - 1
    )
    if len(event_packets) != len(expected_digits) * expected_per_digit:
        raise MediaSessionError(
            "telephone-event packet count or redundant endings are incomplete"
        )
    for previous, current in zip(event_packets, event_packets[1:]):
        if current.sequence != previous.sequence + 1:
            raise MediaSessionError("telephone-event RTP sequence is discontinuous")

    groups: list[list[PlannedPacket]] = []
    for packet in event_packets:
        if not groups or groups[-1][0].timestamp != packet.timestamp:
            if any(group[0].timestamp == packet.timestamp for group in groups):
                raise MediaSessionError("telephone-event timestamp group reappeared")
            groups.append([packet])
        else:
            groups[-1].append(packet)
    if len(groups) != len(expected_digits):
        raise MediaSessionError("telephone-event digit grouping is malformed")

    final_duration = DTMF_DURATION_MS * clock_rate_hz // 1000
    progress = DTMF_DURATION_MS // PACKETIZATION_MS
    expected_durations = [
        min(index + 1, progress) * PACKETIZATION_MS * clock_rate_hz // 1000
        for index in range(expected_per_digit)
    ]
    expected_ends = [
        index >= progress - 1 for index in range(expected_per_digit)
    ]
    for digit, group in zip(expected_digits, groups):
        if len(group) != expected_per_digit:
            raise MediaSessionError(
                f"telephone-event digit {digit!r} lacks redundant endings"
            )
        if [packet.marker for packet in group] != [
            True,
            *([False] * (expected_per_digit - 1)),
        ]:
            raise MediaSessionError(
                f"telephone-event digit {digit!r} has invalid marker bits"
            )
        decoded: list[tuple[int, int, int]] = []
        for packet in group:
            if len(packet.payload) != 4:
                raise MediaSessionError("telephone-event payload must be four bytes")
            event, flags, duration = struct.unpack("!BBH", packet.payload)
            if flags & 0x40 or flags & 0x3F != DTMF_VOLUME:
                raise MediaSessionError("telephone-event flags or volume are invalid")
            decoded.append((event, flags, duration))
        if any(event != DTMF_EVENTS[digit] for event, _, _ in decoded):
            raise MediaSessionError(
                f"telephone-event digit {digit!r} has the wrong event code"
            )
        durations = [duration for _, _, duration in decoded]
        ends = [bool(flags & 0x80) for _, flags, _ in decoded]
        if durations != expected_durations:
            raise MediaSessionError(
                f"telephone-event digit {digit!r} duration progression is invalid"
            )
        if ends != expected_ends or any(
            duration != final_duration
            for duration, end in zip(durations, ends)
            if end
        ):
            raise MediaSessionError(
                f"telephone-event digit {digit!r} ending bits are invalid"
            )
    return {
        "status": "passed",
        "digits": expected_digits,
        "events": len(groups),
        "packets": len(event_packets),
        "redundantEndPackets": DTMF_END_PACKETS,
    }


def send_packet_plan(
    plan: PacketPlan,
    *,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    sockets: dict[tuple[int, str, int], socket.socket] = {}
    try:
        for revision in plan.session.revisions:
            key = (revision.family, revision.source_address, revision.source_port)
            if key in sockets:
                continue
            sender = socket.socket(revision.family, socket.SOCK_DGRAM)
            sender.settimeout(plan.session.echo_timeout_ms / 1000)
            try:
                sender.bind((revision.source_address, revision.source_port))
            except OSError:
                sender.close()
                raise
            sockets[key] = sender
    except OSError as error:
        for sender in sockets.values():
            sender.close()
        raise MediaNetworkError(f"cannot bind SDP source endpoint: {error}") from error

    start = monotonic()
    final_scheduled_ms = plan.packets[-1].scheduled_ms if plan.packets else 0
    global_deadline = (
        start
        + final_scheduled_ms / 1000
        + plan.session.echo_timeout_ms / 1000
        + PACKETIZATION_MS / 1000
    )
    lateness: list[float] = []
    round_trip: list[float] = []
    echoed = {"audio": 0, "telephone-event": 0}
    transitions: list[dict[str, int]] = []
    previous_revision = -1
    try:
        for packet in plan.packets:
            target = start + packet.scheduled_ms / 1000
            remaining = target - monotonic()
            if remaining > 0:
                sleep(remaining)
            sent_at = monotonic()
            if sent_at > global_deadline:
                raise MediaNetworkError("global media send deadline exceeded")
            lateness.append(max(0.0, (sent_at - target) * 1000))
            if packet.revision_index != previous_revision:
                activation = plan.session.revisions[
                    packet.revision_index
                ].activation_ms
                transitions.append(
                    {
                        "revision": packet.revision_index,
                        "activationMs": activation,
                        "firstPacketMs": packet.scheduled_ms,
                        "delayMs": packet.scheduled_ms - activation,
                    }
                )
                previous_revision = packet.revision_index
            revision = plan.session.revisions[packet.revision_index]
            sender = sockets[
                (revision.family, revision.source_address, revision.source_port)
            ]
            wire = packet.wire_bytes()
            try:
                sent_bytes = sender.sendto(
                    wire,
                    (revision.destination_address, revision.destination_port),
                )
                if sent_bytes != len(wire):
                    raise MediaNetworkError(
                        f"packet {packet.sequence} was only partially sent"
                    )
                if plan.session.echo_required:
                    echo_remaining = global_deadline - monotonic()
                    if echo_remaining <= 0:
                        raise MediaNetworkError(
                            "global media send deadline exceeded"
                        )
                    sender.settimeout(
                        min(
                            plan.session.echo_timeout_ms / 1000,
                            echo_remaining,
                        )
                    )
                    returned, peer = sender.recvfrom(65535)
            except (OSError, TimeoutError) as error:
                raise MediaNetworkError(
                    f"packet {packet.sequence} send/echo failed: {error}"
                ) from error
            if plan.session.echo_required:
                expected_peer = (
                    revision.destination_address,
                    revision.destination_port,
                )
                if peer[0:2] != expected_peer or returned != wire:
                    raise MediaNetworkError(
                        f"packet {packet.sequence} echo source or bytes differ"
                    )
                round_trip.append((monotonic() - sent_at) * 1000)
                echoed[packet.kind] += 1
    finally:
        for sender in sockets.values():
            sender.close()
    elapsed_ms = (monotonic() - start) * 1000
    return {
        "apiVersion": "sippycup.media-send-result/v1",
        "status": "passed",
        "plannedPackets": len(plan.packets),
        "sentPackets": len(plan.packets),
        "echoedAudioPackets": echoed["audio"],
        "echoedTelephoneEventPackets": echoed["telephone-event"],
        "configuredDigits": plan.session.digits,
        "elapsedMs": round(elapsed_ms, 3),
        "timing": {
            "maxSendLatenessMs": round(max(lateness, default=0), 3),
            "maxRoundTripMs": (
                round(max(round_trip), 3) if round_trip else None
            ),
            "roundTripSamples": len(round_trip),
            "oneWayLatencyClaimed": False,
        },
        "transitions": transitions,
    }
