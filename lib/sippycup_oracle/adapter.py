"""Narrow adapter for machine-readable TShark JSON output."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, TypeVar

from .records import (
    PACKET_RECORD_SCHEMA_VERSION,
    AddressFamily,
    CaptureFormat,
    CaptureRecord,
    CaptureStatus,
    CodecRecord,
    EndpointRecord,
    EvidenceRef,
    FrameRecord,
    Known,
    PayloadVisibility,
    RtcpRecord,
    RtpRecord,
    SdpMediaRecord,
    SdpRevisionRecord,
    SipRecord,
    Transport,
    Unknown,
    UnknownReason,
    Value,
)

_PCAP_MAGICS = {
    bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b23c4d"),
    bytes.fromhex("4d3cb2a1"),
}
_PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")
_ATTRIBUTE_RE = re.compile(r"^(?P<field>[^:]+)(?::(?P<value>.*))?$")


class CaptureDecodeError(ValueError):
    """The capture or TShark document cannot be decoded safely."""


def tshark_json_args(path: str | Path) -> tuple[str, ...]:
    """Return the stable machine-output invocation required by this adapter."""
    return (
        "tshark",
        "--no-duplicate-keys",
        "-r",
        str(path),
        "-T",
        "json",
    )


def probe_capture_format(path: str | Path) -> CaptureFormat:
    try:
        with Path(path).open("rb") as capture:
            magic = capture.read(4)
    except OSError as exc:
        raise CaptureDecodeError(f"cannot read capture: {exc}") from exc
    if magic in _PCAP_MAGICS:
        return CaptureFormat.PCAP
    if magic == _PCAPNG_MAGIC:
        return CaptureFormat.PCAPNG
    raise CaptureDecodeError("capture is neither pcap nor pcapng")


def _find(node: Any, key: str) -> Any | None:
    """Find an exact TShark field key without relying on rendered text."""
    if isinstance(node, dict):
        if key in node:
            return node[key]
        for child in node.values():
            found = _find(child, key)
            if found is not None:
                return found
    elif isinstance(node, list):
        for child in node:
            found = _find(child, key)
            if found is not None:
                return found
    return None


def _find_values(node: Any, key: str) -> tuple[Any, ...]:
    """Collect exact repeated field values while preserving document order."""
    found: list[Any] = []
    if isinstance(node, dict):
        for child_key, child in node.items():
            if child_key == key:
                found.extend(_all_scalars(child))
            else:
                found.extend(_find_values(child, key))
    elif isinstance(node, list):
        for child in node:
            found.extend(_find_values(child, key))
    return tuple(found)


def _scalar(value: Any) -> Any | None:
    if isinstance(value, list):
        return _scalar(value[0]) if value else None
    if isinstance(value, dict):
        # TShark sometimes emits {"field": value, "field_raw": ...}.
        for key, child in value.items():
            if not key.endswith(("_raw", "_tree")):
                scalar = _scalar(child)
                if scalar is not None:
                    return scalar
        return None
    return value


U = TypeVar("U")


def _typed(
    layers: Any,
    key: str,
    convert: Callable[[Any], U],
    *,
    missing_reason: UnknownReason = UnknownReason.MISSING_FIELD,
) -> Value[U]:
    raw = _scalar(_find(layers, key))
    if raw is None or raw == "":
        return Unknown(missing_reason, key)
    try:
        return Known(convert(raw))
    except (TypeError, ValueError, InvalidOperation, OverflowError):
        return Unknown(UnknownReason.MALFORMED_FIELD, key)


def _text(value: Any) -> str:
    return str(value)


def _integer(value: Any) -> int:
    text = str(value).strip().lower()
    return int(text, 16) if text.startswith("0x") else int(text)


def _boolean(value: Any) -> bool:
    text = str(value).strip().lower()
    if text in {"1", "true", "set", "yes"}:
        return True
    if text in {"0", "false", "not set", "no"}:
        return False
    raise ValueError("not a boolean")


def _epoch(value: Any) -> Decimal:
    text = str(value).strip()
    try:
        return Decimal(text)
    except InvalidOperation:
        pass
    match = re.fullmatch(
        r"(?P<date>\d{4}-\d{2}-\d{2})T(?P<time>\d{2}:\d{2}:\d{2})"
        r"(?:\.(?P<fraction>\d+))?Z",
        text,
    )
    if match is None:
        raise ValueError("not an epoch or UTC ISO timestamp")
    whole = datetime.fromisoformat(
        f"{match.group('date')}T{match.group('time')}+00:00"
    )
    seconds = Decimal(int(whole.replace(tzinfo=timezone.utc).timestamp()))
    fraction = match.group("fraction")
    return seconds + (Decimal(f"0.{fraction}") if fraction else Decimal(0))


def _protocols(layers: Any) -> tuple[str, ...]:
    raw = _scalar(_find(layers, "frame.protocols"))
    if not isinstance(raw, str):
        return ()
    return tuple(part for part in raw.split(":") if part)


def _status(layers: Any) -> Value[CaptureStatus]:
    captured = _typed(layers, "frame.cap_len", _integer)
    original = _typed(layers, "frame.len", _integer)
    if isinstance(captured, Known) and isinstance(original, Known):
        if captured.value < original.value:
            return Known(CaptureStatus.TRUNCATED)
        if _find(layers, "_ws.malformed") is not None or _find(layers, "malformed") is not None:
            return Known(CaptureStatus.MALFORMED)
        return Known(CaptureStatus.COMPLETE)
    return Unknown(UnknownReason.MISSING_FIELD, "frame.cap_len/frame.len")


def _missing_for(status: Value[CaptureStatus]) -> UnknownReason:
    if isinstance(status, Unknown):
        return status.reason
    if status.value is CaptureStatus.TRUNCATED:
        return UnknownReason.TRUNCATED_CAPTURE
    if status.value is CaptureStatus.MALFORMED:
        return UnknownReason.MALFORMED_FIELD
    return UnknownReason.MISSING_FIELD


def _address(layers: Any, prefix: str, status: Value[CaptureStatus]) -> tuple[Value[str], Value[AddressFamily]]:
    reason = _missing_for(status)
    ipv4 = _typed(layers, f"ip.{prefix}", _text, missing_reason=reason)
    if isinstance(ipv4, Known):
        try:
            ipaddress.IPv4Address(ipv4.value)
            return ipv4, Known(AddressFamily.IPV4)
        except ipaddress.AddressValueError:
            return (
                Unknown(UnknownReason.MALFORMED_FIELD, f"ip.{prefix}"),
                Unknown(UnknownReason.MALFORMED_FIELD, f"ip.{prefix}"),
            )
    ipv6 = _typed(layers, f"ipv6.{prefix}", _text, missing_reason=reason)
    if isinstance(ipv6, Known):
        try:
            ipaddress.IPv6Address(ipv6.value)
            return ipv6, Known(AddressFamily.IPV6)
        except ipaddress.AddressValueError:
            return (
                Unknown(UnknownReason.MALFORMED_FIELD, f"ipv6.{prefix}"),
                Unknown(UnknownReason.MALFORMED_FIELD, f"ipv6.{prefix}"),
            )
    return Unknown(reason, f"ip/ipv6.{prefix}"), Unknown(reason, "address family")


def _endpoint(layers: Any, prefix: str, status: Value[CaptureStatus]) -> EndpointRecord:
    address, family = _address(layers, prefix, status)
    reason = _missing_for(status)
    udp_port = _typed(layers, f"udp.{prefix}port", _integer, missing_reason=reason)
    if isinstance(udp_port, Known):
        return EndpointRecord(address, family, udp_port, Known(Transport.UDP))
    tcp_port = _typed(layers, f"tcp.{prefix}port", _integer, missing_reason=reason)
    if isinstance(tcp_port, Known):
        return EndpointRecord(address, family, tcp_port, Known(Transport.TCP))
    return EndpointRecord(
        address,
        family,
        Unknown(reason, f"udp/tcp.{prefix}port"),
        Unknown(reason, "transport"),
    )


def _sip(layers: Any, protocols: tuple[str, ...], status: Value[CaptureStatus]) -> SipRecord | None:
    if "sip" not in protocols and _find(layers, "sip") is None:
        return None
    reason = _missing_for(status)
    return SipRecord(
        request_method=_typed(layers, "sip.Method", _text, missing_reason=reason),
        status_code=_typed(layers, "sip.Status-Code", _integer, missing_reason=reason),
        call_id=_typed(layers, "sip.Call-ID", _text, missing_reason=reason),
        from_tag=_typed(layers, "sip.from.tag", _text, missing_reason=reason),
        to_tag=_typed(layers, "sip.to.tag", _text, missing_reason=reason),
        cseq_number=_typed(layers, "sip.CSeq.seq", _integer, missing_reason=reason),
        cseq_method=_typed(layers, "sip.CSeq.method", _text, missing_reason=reason),
        via_branch=_typed(layers, "sip.Via.branch", _text, missing_reason=reason),
        via_sent_by=_typed(
            layers, "sip.Via.sent-by.address", _text, missing_reason=reason
        ),
        rseq=_typed(layers, "sip.RSeq", _integer, missing_reason=reason),
        rack_rseq=_typed(layers, "sip.RAck.rseq", _integer, missing_reason=reason),
        rack_cseq=_typed(layers, "sip.RAck.cseq", _integer, missing_reason=reason),
        rack_method=_typed(layers, "sip.RAck.method", _text, missing_reason=reason),
        routes=tuple(
            str(item) for item in _all_scalars(_find(layers, "sip.Route")) if item
        ),
        record_routes=tuple(
            str(item)
            for item in _all_scalars(_find(layers, "sip.Record-Route"))
            if item
        ),
        has_sdp=(
            Known("sdp" in protocols or _find(layers, "sdp") is not None)
            if _find(layers, "frame.protocols") is not None
            else Unknown(UnknownReason.MISSING_FIELD, "frame.protocols")
        ),
    )


def _all_scalars(value: Any) -> tuple[Any, ...]:
    if value is None:
        return ()
    if isinstance(value, list):
        return tuple(_scalar(item) for item in value)
    return (_scalar(value),)


def _media_lines(sdp_node: Any) -> tuple[tuple[str, int, str, tuple[int, ...]], ...]:
    result: list[tuple[str, int, str, tuple[int, ...]]] = []
    for raw in _all_scalars(_find(sdp_node, "sdp.media")):
        if raw is None:
            continue
        parts = str(raw).split()
        if len(parts) < 4:
            continue
        try:
            result.append(
                (
                    parts[0],
                    _integer(parts[1]),
                    parts[2],
                    tuple(_integer(item) for item in parts[3:]),
                )
            )
        except ValueError:
            continue
    return tuple(result)


def _partition_media_attributes(
    sdp_node: Any,
    media_lines: tuple[tuple[str, int, str, tuple[int, ...]], ...],
) -> tuple[tuple[tuple[str, str], ...], ...]:
    partitioned: list[list[tuple[str, str]]] = [
        [] for _ in range(len(media_lines))
    ]
    if not partitioned:
        return ()
    current = 0
    for raw in _all_scalars(_find(sdp_node, "sdp.media_attr")):
        if raw is None:
            continue
        match = _ATTRIBUTE_RE.match(str(raw))
        if match is None:
            continue
        field = match.group("field")
        value = match.group("value") or ""
        if field in {"rtpmap", "fmtp"}:
            try:
                payload_type = _integer(value.split(None, 1)[0])
            except (ValueError, IndexError):
                payload_type = -1
            candidates = [
                index
                for index, media in enumerate(media_lines)
                if payload_type in media[3]
            ]
            if len(candidates) == 1:
                current = candidates[0]
        partitioned[current].append((field, value))
    return tuple(tuple(items) for items in partitioned)


def _section_addresses(
    sdp_node: Any, count: int, reason: UnknownReason
) -> tuple[Value[str], tuple[Value[str], ...]]:
    addresses = tuple(
        str(item)
        for item in _find_values(sdp_node, "sdp.connection_info.address")
        if item is not None
    )
    if not addresses:
        unknown = Unknown(reason, "sdp.connection_info.address")
        return unknown, tuple(unknown for _ in range(count))
    session: Value[str] = Known(addresses[0])
    if len(addresses) == 1:
        return session, tuple(Known(addresses[0]) for _ in range(count))
    media_addresses = tuple(
        Known(addresses[min(index + 1, len(addresses) - 1)])
        for index in range(count)
    )
    return session, media_addresses


def _raw_sdp(
    layers: Any, reason: UnknownReason
) -> tuple[
    Value[str],
    tuple[
        tuple[
            tuple[str, int, str, tuple[int, ...]],
            Value[str],
            tuple[tuple[str, str], ...],
        ],
        ...,
    ],
] | None:
    raw = _scalar(_find(layers, "sip.msg_body"))
    if not isinstance(raw, str):
        return None
    try:
        body = bytes.fromhex(raw.replace(":", "")).decode("utf-8", "strict")
    except (ValueError, UnicodeDecodeError):
        return None
    if "\nm=" not in body.replace("\r\n", "\n"):
        return None
    session_address: Value[str] = Unknown(
        reason, "sdp session connection address"
    )
    sections: list[
        tuple[
            tuple[str, int, str, tuple[int, ...]],
            Value[str],
            tuple[tuple[str, str], ...],
        ]
    ] = []
    current_media: tuple[str, int, str, tuple[int, ...]] | None = None
    current_address: Value[str] | None = None
    current_attributes: list[tuple[str, str]] = []

    def finish() -> None:
        nonlocal current_media, current_address, current_attributes
        if current_media is not None:
            sections.append(
                (
                    current_media,
                    current_address if current_address is not None else session_address,
                    tuple(current_attributes),
                )
            )

    for line in body.replace("\r\n", "\n").split("\n"):
        if line.startswith("m="):
            finish()
            parts = line[2:].split()
            try:
                current_media = (
                    parts[0],
                    _integer(parts[1]),
                    parts[2],
                    tuple(_integer(item) for item in parts[3:]),
                )
            except (ValueError, IndexError):
                current_media = ("", -1, "", ())
            current_address = None
            current_attributes = []
        elif line.startswith("c="):
            parts = line[2:].split()
            address: Value[str] = (
                Known(parts[2])
                if len(parts) >= 3
                else Unknown(UnknownReason.MALFORMED_FIELD, "sdp c=")
            )
            if current_media is None:
                session_address = address
            else:
                current_address = address
        elif line.startswith("a=") and current_media is not None:
            match = _ATTRIBUTE_RE.match(line[2:])
            if match is not None:
                current_attributes.append(
                    (match.group("field"), match.group("value") or "")
                )
    finish()
    if not sections:
        return None
    return session_address, tuple(sections)


def _sdp(layers: Any, protocols: tuple[str, ...], evidence: EvidenceRef, status: Value[CaptureStatus]) -> SdpRevisionRecord | None:
    if "sdp" not in protocols and _find(layers, "sdp") is None:
        return None
    reason = _missing_for(status)
    sdp_node = _find(layers, "sdp")
    if not isinstance(sdp_node, dict):
        sdp_node = layers
    raw_sdp = _raw_sdp(layers, reason)
    if raw_sdp is not None:
        session_address, raw_sections = raw_sdp
        media_lines = tuple(section[0] for section in raw_sections)
        media_addresses = tuple(section[1] for section in raw_sections)
        attributes_by_section = tuple(section[2] for section in raw_sections)
    else:
        media_lines = _media_lines(sdp_node)
        attributes_by_section = ()
        session_address = Unknown(reason, "sdp.connection_info.address")
        media_addresses = ()
    if not media_lines:
        media_types = _all_scalars(_find(sdp_node, "sdp.media.media"))
        ports = _all_scalars(_find(sdp_node, "sdp.media.port"))
        protocols_raw = _all_scalars(_find(sdp_node, "sdp.media.proto"))
        formats_raw = _all_scalars(_find(sdp_node, "sdp.media.format"))
        count = max(len(media_types), len(ports), len(protocols_raw), 1)
        fallback_lines: list[tuple[str, int, str, tuple[int, ...]]] = []
        for index in range(count):
            try:
                payloads = tuple(
                    _integer(token)
                    for token in str(formats_raw[index]).split()
                )
            except (IndexError, ValueError):
                payloads = ()
            fallback_lines.append(
                (
                    str(media_types[index]) if index < len(media_types) else "",
                    _integer(ports[index]) if index < len(ports) else -1,
                    str(protocols_raw[index]) if index < len(protocols_raw) else "",
                    payloads,
                )
            )
        media_lines = tuple(fallback_lines)
    if raw_sdp is None:
        attributes_by_section = _partition_media_attributes(sdp_node, media_lines)
        # Synthetic field fixtures may provide paired field/value arrays.
        if not any(attributes_by_section):
            fields_raw = _all_scalars(_find(sdp_node, "sdp.media_attribute.field"))
            values_raw = _all_scalars(_find(sdp_node, "sdp.media_attribute.value"))
            attributes_by_section = (
                tuple(
                    (str(field), str(values_raw[index]) if index < len(values_raw) else "")
                    for index, field in enumerate(fields_raw)
                    if field is not None
                ),
            ) + tuple(() for _ in range(max(0, len(media_lines) - 1)))
        session_address, media_addresses = _section_addresses(
            sdp_node, len(media_lines), reason
        )
    media: list[SdpMediaRecord] = []
    for index, (media_type, port, protocol, payload_tuple) in enumerate(media_lines):
        section_attributes = (
            attributes_by_section[index]
            if index < len(attributes_by_section)
            else ()
        )
        direction_raw = next(
            (
                field
                for field, _ in section_attributes
                if field in {"sendrecv", "sendonly", "recvonly", "inactive"}
            ),
            None,
        )
        direction: Value[str] = (
            Known(direction_raw)
            if direction_raw is not None
            else Unknown(reason, "sdp direction")
        )
        rtpmap: dict[int, tuple[str, int, int]] = {}
        format_parameters: dict[int, str] = {}
        packet_time: Value[int] = Unknown(reason, "sdp ptime")
        rtcp_port: Value[int] = Unknown(reason, "sdp rtcp port")
        rtcp_address: Value[str] = Unknown(reason, "sdp rtcp address")
        for field, value in section_attributes:
            if field == "rtpmap":
                try:
                    payload, description = value.split(None, 1)
                    parts = description.split("/")
                    rtpmap[_integer(payload)] = (
                        parts[0],
                        _integer(parts[1]),
                        _integer(parts[2]) if len(parts) > 2 else 1,
                    )
                except (ValueError, IndexError):
                    continue
            elif field == "fmtp":
                try:
                    payload, parameters = value.split(None, 1)
                    format_parameters[_integer(payload)] = parameters
                except ValueError:
                    continue
            elif field == "ptime":
                try:
                    packet_time = Known(_integer(value))
                except ValueError:
                    packet_time = Unknown(UnknownReason.MALFORMED_FIELD, "sdp ptime")
            elif field == "rtcp":
                parts = value.split()
                try:
                    rtcp_port = Known(_integer(parts[0]))
                except (ValueError, IndexError):
                    rtcp_port = Unknown(
                        UnknownReason.MALFORMED_FIELD, "sdp rtcp port"
                    )
                if len(parts) >= 4:
                    rtcp_address = Known(parts[3])

        static_codecs = {
            0: ("PCMU", 8000, 1),
            3: ("GSM", 8000, 1),
            8: ("PCMA", 8000, 1),
            9: ("G722", 8000, 1),
            18: ("G729", 8000, 1),
        }
        codecs: list[CodecRecord] = []
        telephone_events: list[int] = []
        for payload_type in payload_tuple:
            mapping = rtpmap.get(payload_type) or static_codecs.get(payload_type)
            if mapping is None:
                encoding: Value[str] = Unknown(reason, "sdp rtpmap encoding")
                clock: Value[int] = Unknown(reason, "sdp rtpmap clock")
                channels: Value[int] = Unknown(reason, "sdp rtpmap channels")
            else:
                encoding = Known(mapping[0])
                clock = Known(mapping[1])
                channels = Known(mapping[2])
                if mapping[0].lower() == "telephone-event":
                    telephone_events.append(payload_type)
            codecs.append(
                CodecRecord(
                    payload_type=payload_type,
                    encoding=encoding,
                    clock_rate=clock,
                    channels=channels,
                    format_parameters=(
                        Known(format_parameters[payload_type])
                        if payload_type in format_parameters
                        else Unknown(reason, "sdp fmtp")
                    ),
                )
            )
        media.append(
            SdpMediaRecord(
                media_type=Known(media_type) if media_type else Unknown(reason, "sdp.media.media"),
                address=media_addresses[index],
                port=Known(port) if port >= 0 else Unknown(reason, "sdp.media.port"),
                protocol=Known(protocol) if protocol else Unknown(reason, "sdp.media.proto"),
                payload_types=Known(payload_tuple) if payload_tuple else Unknown(reason, "sdp.media.format"),
                codecs=Known(tuple(codecs)) if payload_tuple else Unknown(reason, "sdp.media.format"),
                telephone_event_payloads=Known(tuple(telephone_events)) if payload_tuple else Unknown(reason, "sdp.media.format"),
                direction=direction,
                packet_time_ms=packet_time,
                rtcp_address=rtcp_address,
                rtcp_port=rtcp_port,
            )
        )
    return SdpRevisionRecord(
        evidence=evidence,
        connection_address=session_address,
        session_name=_typed(sdp_node, "sdp.session_name", _text, missing_reason=reason),
        media=tuple(media),
    )


def _payload_visibility(layers: Any) -> Value[PayloadVisibility]:
    protocols = _protocols(layers)
    if any(name in protocols for name in ("srtp", "srtcp", "dtls", "zrtp")):
        return Unknown(
            UnknownReason.UNSUPPORTED_ENCRYPTION,
            "encrypted media payload is not inspected",
        )
    return Known(PayloadVisibility.METADATA_ONLY)


def _rtp(layers: Any, protocols: tuple[str, ...], status: Value[CaptureStatus]) -> RtpRecord | None:
    encrypted_only = "srtp" in protocols and "rtp" not in protocols
    if "rtp" not in protocols and "srtp" not in protocols and _find(layers, "rtp") is None:
        return None
    reason = (
        UnknownReason.UNSUPPORTED_ENCRYPTION
        if encrypted_only
        else _missing_for(status)
    )
    def field(key: str, convert: Callable[[Any], U]) -> Value[U]:
        return (
            Unknown(UnknownReason.UNSUPPORTED_ENCRYPTION, key)
            if encrypted_only
            else _typed(layers, key, convert, missing_reason=reason)
        )
    return RtpRecord(
        ssrc=field("rtp.ssrc", _integer),
        sequence=field("rtp.seq", _integer),
        timestamp=field("rtp.timestamp", _integer),
        payload_type=field("rtp.p_type", _integer),
        marker=field("rtp.marker", _boolean),
        payload_visibility=_payload_visibility(layers),
    )


def _rtcp(layers: Any, protocols: tuple[str, ...], status: Value[CaptureStatus]) -> RtcpRecord | None:
    encrypted_only = "srtcp" in protocols and "rtcp" not in protocols
    if "rtcp" not in protocols and "srtcp" not in protocols and _find(layers, "rtcp") is None:
        return None
    reason = (
        UnknownReason.UNSUPPORTED_ENCRYPTION
        if encrypted_only
        else _missing_for(status)
    )
    def field(key: str) -> Value[int]:
        return (
            Unknown(UnknownReason.UNSUPPORTED_ENCRYPTION, key)
            if encrypted_only
            else _typed(layers, key, _integer, missing_reason=reason)
        )
    return RtcpRecord(
        packet_type=field("rtcp.pt"),
        sender_ssrc=field("rtcp.senderssrc"),
        payload_visibility=_payload_visibility(layers),
    )


def parse_tshark_json(document: str | bytes, capture_format: CaptureFormat) -> CaptureRecord:
    """Parse `tshark -T json` output into immutable packet records."""
    try:
        parsed = json.loads(document)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CaptureDecodeError(f"invalid TShark JSON: {exc}") from exc
    if not isinstance(parsed, list):
        raise CaptureDecodeError("TShark JSON root must be an array")

    frames: list[FrameRecord] = []
    warnings: list[str] = []
    for index, packet in enumerate(parsed):
        if not isinstance(packet, dict):
            raise CaptureDecodeError(f"packet {index} is not an object")
        source = packet.get("_source", packet)
        layers = source.get("layers") if isinstance(source, dict) else None
        if not isinstance(layers, dict):
            raise CaptureDecodeError(f"packet {index} has no layers object")
        status = _status(layers)
        reason = _missing_for(status)
        evidence = EvidenceRef(
            frame_number=_typed(layers, "frame.number", _integer, missing_reason=reason),
            timestamp_epoch=_typed(
                layers, "frame.time_epoch", _epoch, missing_reason=reason
            ),
        )
        protocols = _protocols(layers)
        if isinstance(status, Unknown):
            warnings.append(f"packet {index}: unknown capture status")
        elif status.value is not CaptureStatus.COMPLETE:
            warnings.append(f"packet {index}: {status.value.value}")
        frames.append(
            FrameRecord(
                evidence=evidence,
                captured_length=_typed(
                    layers, "frame.cap_len", _integer, missing_reason=reason
                ),
                original_length=_typed(
                    layers, "frame.len", _integer, missing_reason=reason
                ),
                status=status,
                source=_endpoint(layers, "src", status),
                destination=_endpoint(layers, "dst", status),
                protocols=protocols,
                sip=_sip(layers, protocols, status),
                sdp=_sdp(layers, protocols, evidence, status),
                rtp=_rtp(layers, protocols, status),
                rtcp=_rtcp(layers, protocols, status),
            )
        )
    return CaptureRecord(
        schema_version=PACKET_RECORD_SCHEMA_VERSION,
        capture_format=capture_format,
        frames=tuple(frames),
        warnings=tuple(warnings),
    )
