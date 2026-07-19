"""Typed, serialization-safe packet records.

The model deliberately contains protocol metadata only. It has no fields for
SIP Authorization values, packet payload bytes, or decoded audio.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, fields, is_dataclass
from decimal import Decimal
from enum import Enum
from typing import Any, Generic, TypeAlias, TypeVar

ASSERTION_SCHEMA_VERSION = "sippycup.expectations/v1"
RESULT_SCHEMA_VERSION = "sippycup.results/v1"
PACKET_RECORD_SCHEMA_VERSION = "sippycup.packet-records/v1"


class UnknownReason(str, Enum):
    MISSING_FIELD = "missing_field"
    MALFORMED_FIELD = "malformed_field"
    TRUNCATED_CAPTURE = "truncated_capture"
    UNSUPPORTED_ENCRYPTION = "unsupported_encryption"
    UNSUPPORTED_PROTOCOL = "unsupported_protocol"
    AMBIGUOUS = "ambiguous"


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class Known(Generic[T]):
    value: T


@dataclass(frozen=True, slots=True)
class Unknown:
    reason: UnknownReason
    detail: str | None = None


Value: TypeAlias = Known[T] | Unknown


class CaptureFormat(str, Enum):
    PCAP = "pcap"
    PCAPNG = "pcapng"


class CaptureStatus(str, Enum):
    COMPLETE = "complete"
    TRUNCATED = "truncated"
    MALFORMED = "malformed"


class AddressFamily(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"


class Transport(str, Enum):
    UDP = "udp"
    TCP = "tcp"


class Verdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


class PayloadVisibility(str, Enum):
    METADATA_ONLY = "metadata_only"


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    frame_number: Value[int]
    timestamp_epoch: Value[Decimal]


@dataclass(frozen=True, slots=True)
class EndpointRecord:
    address: Value[str]
    family: Value[AddressFamily]
    port: Value[int]
    transport: Value[Transport]


@dataclass(frozen=True, slots=True)
class SipRecord:
    request_method: Value[str]
    status_code: Value[int]
    call_id: Value[str]
    from_tag: Value[str]
    to_tag: Value[str]
    cseq_number: Value[int]
    cseq_method: Value[str]
    via_branch: Value[str]
    via_sent_by: Value[str]
    rseq: Value[int]
    rack_rseq: Value[int]
    rack_cseq: Value[int]
    rack_method: Value[str]
    routes: tuple[str, ...]
    record_routes: tuple[str, ...]
    has_sdp: Value[bool]


@dataclass(frozen=True, slots=True)
class CodecRecord:
    payload_type: int
    encoding: Value[str]
    clock_rate: Value[int]
    channels: Value[int]
    format_parameters: Value[str]


@dataclass(frozen=True, slots=True)
class SdpMediaRecord:
    media_type: Value[str]
    address: Value[str]
    port: Value[int]
    protocol: Value[str]
    payload_types: Value[tuple[int, ...]]
    codecs: Value[tuple[CodecRecord, ...]]
    telephone_event_payloads: Value[tuple[int, ...]]
    direction: Value[str]
    packet_time_ms: Value[int]
    rtcp_address: Value[str]
    rtcp_port: Value[int]


@dataclass(frozen=True, slots=True)
class SdpRevisionRecord:
    evidence: EvidenceRef
    connection_address: Value[str]
    session_name: Value[str]
    media: tuple[SdpMediaRecord, ...]


@dataclass(frozen=True, slots=True)
class RtpRecord:
    ssrc: Value[int]
    sequence: Value[int]
    timestamp: Value[int]
    payload_type: Value[int]
    marker: Value[bool]
    payload_visibility: Value[PayloadVisibility]


@dataclass(frozen=True, slots=True)
class RtcpRecord:
    packet_type: Value[int]
    sender_ssrc: Value[int]
    payload_visibility: Value[PayloadVisibility]


@dataclass(frozen=True, slots=True)
class FrameRecord:
    evidence: EvidenceRef
    captured_length: Value[int]
    original_length: Value[int]
    status: Value[CaptureStatus]
    source: EndpointRecord
    destination: EndpointRecord
    protocols: tuple[str, ...]
    sip: SipRecord | None
    sdp: SdpRevisionRecord | None
    rtp: RtpRecord | None
    rtcp: RtcpRecord | None


@dataclass(frozen=True, slots=True)
class CaptureRecord:
    schema_version: str
    capture_format: CaptureFormat
    frames: tuple[FrameRecord, ...]
    warnings: tuple[str, ...] = ()


def to_primitive(value: Any) -> Any:
    """Convert records to deterministic JSON primitives with typed values."""
    if isinstance(value, Known):
        return {"state": "known", "value": to_primitive(value.value)}
    if isinstance(value, Unknown):
        result: dict[str, Any] = {
            "state": "unknown",
            "reason": value.reason.value,
        }
        if value.detail is not None:
            result["detail"] = value.detail
        return result
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Decimal):
        return format(value, "f")
    if is_dataclass(value):
        return {
            field.name: to_primitive(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, (tuple, list)):
        return [to_primitive(item) for item in value]
    if isinstance(value, dict):
        return {str(key): to_primitive(item) for key, item in value.items()}
    return value


def dumps_record(value: Any, *, indent: int | None = 2) -> str:
    return json.dumps(
        to_primitive(value),
        indent=indent,
        sort_keys=True,
        separators=(",", ":") if indent is None else None,
    )
