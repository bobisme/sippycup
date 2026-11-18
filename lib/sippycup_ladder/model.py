"""Plain data model shared by the capture reader, the log reader and the builder.

The model carries protocol metadata only. It has no field for Authorization
values, nonces, crypto keys, user parts or message bodies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

SCHEMA = "sippycup.dev/ladder/v1"
AUTH_SCHEMES = ("Digest", "Basic", "Bearer")


@dataclass
class Endpoint:
    address: Optional[str]
    port: Optional[int]

    def key(self) -> tuple:
        return (self.address, self.port)


@dataclass
class SdpMedia:
    media: str
    address: Optional[str]
    port: Optional[int]
    proto: Optional[str]
    codecs: list = field(default_factory=list)  # display names, e.g. "PCMU"
    payload_types: list = field(default_factory=list)  # (pt, name) pairs
    direction: Optional[str] = None
    ptime: Optional[int] = None
    crypto_suites: list = field(default_factory=list)  # suite names only
    telephone_event: bool = False

    @property
    def srtp(self) -> bool:
        return bool(self.proto and "SAVP" in self.proto.upper()) or bool(self.crypto_suites)


@dataclass
class SdpSummary:
    media: list = field(default_factory=list)
    role: str = "offer"  # offer | answer


@dataclass
class SipMsg:
    t: float
    frame: Optional[int]
    src: Endpoint
    dst: Endpoint
    transport: Optional[str]
    kind: str  # request | response
    method: str  # request method, or the CSeq method of a response
    status: Optional[int]
    reason: Optional[str]
    call_id: str
    cseq: Optional[int]
    branch: Optional[str]
    from_tag: Optional[str] = None
    to_tag: Optional[str] = None
    auth: Optional[str] = None  # challenge | response
    auth_scheme: Optional[str] = None
    sdp: Optional[SdpSummary] = None
    other_body_bytes: int = 0
    truncated: bool = False
    source: str = "capture"  # capture | softphone-log
    retrans: int = 0  # 0 = original, n = nth repeat
    retrans_after: Optional[float] = None  # seconds after the original
    tool_retrans: bool = False


@dataclass
class TlsEvent:
    t: float
    frame: Optional[int]
    src: Endpoint
    dst: Endpoint
    kind: str  # syn | synack | handshake | ccs | alert | appdata | fin | rst
    detail: str = ""
    records: int = 1
    nbytes: int = 0
    t_last: Optional[float] = None


@dataclass
class MediaFlow:
    kind: str  # rtp | rtcp
    src: Endpoint
    dst: Endpoint
    packets: int
    t_first: float
    t_last: float
    payload_types: dict = field(default_factory=dict)  # pt -> packets
    ssrcs: int = 1
    missing: int = 0
    events: int = 0  # telephone-event events (digit values are never kept)
    setup_frame: Optional[int] = None
    heuristic: bool = False


@dataclass
class CaptureData:
    sip: list = field(default_factory=list)
    tls: list = field(default_factory=list)
    media: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    first_t: Optional[float] = None
    last_t: Optional[float] = None
    sip_frames_seen: int = 0
    truncated_frames: int = 0
    incomplete_segments: int = 0
