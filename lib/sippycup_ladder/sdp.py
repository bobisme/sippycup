"""SDP summaries built on the oracle's SDP parsing.

Only the oracle's typed `SdpRevisionRecord` is summarised. The a=crypto line
is scanned for its suite name alone; the key material after `inline:` is
never read into any variable that outlives the scan.
"""

from __future__ import annotations

import binascii
from typing import Any, Optional

from sippycup_oracle import adapter
from sippycup_oracle.records import (
    CaptureStatus,
    EvidenceRef,
    Known,
    Unknown,
    UnknownReason,
)

from .model import SdpMedia, SdpSummary

_STATIC = {0: "PCMU", 3: "GSM", 8: "PCMA", 9: "G722", 18: "G729"}


def _known(value: Any) -> Any:
    return value.value if isinstance(value, Known) else None


def summarize_revision(revision: Any, crypto_by_section: list) -> SdpSummary:
    sections = []
    for index, media in enumerate(revision.media):
        codecs_value = _known(media.codecs) or ()
        names = []
        pairs = []
        event = False
        for codec in codecs_value:
            encoding = _known(codec.encoding) or _STATIC.get(codec.payload_type)
            name = encoding or f"pt{codec.payload_type}"
            if name.lower() == "telephone-event":
                event = True
            if name not in names:
                names.append(name)
            pairs.append((codec.payload_type, name))
        if not codecs_value:
            for pt in _known(media.payload_types) or ():
                name = _STATIC.get(pt, f"pt{pt}")
                names.append(name)
                pairs.append((pt, name))
        address = _known(media.address)
        if address is None:
            address = _known(revision.connection_address)
        suites = crypto_by_section[index] if index < len(crypto_by_section) else []
        sections.append(
            SdpMedia(
                media=_known(media.media_type) or "?",
                address=address,
                port=_known(media.port),
                proto=_known(media.protocol),
                codecs=names,
                payload_types=pairs,
                direction=_known(media.direction),
                ptime=_known(media.packet_time_ms),
                crypto_suites=list(suites),
                telephone_event=event,
            )
        )
    return SdpSummary(media=sections)


def crypto_suites_by_section(body: str) -> list:
    """Suite names per m= section. Key material is not retained."""
    sections: list = []
    for line in body.replace("\r\n", "\n").split("\n"):
        if line.startswith("m="):
            sections.append([])
        elif line.startswith("a=crypto:") and sections:
            parts = line.split(None, 2)
            if len(parts) >= 2:
                suite = parts[1]
                if suite.replace("_", "").isalnum() and suite not in sections[-1]:
                    sections[-1].append(suite)
    return sections


def summary_from_body_text(body: str) -> Optional[SdpSummary]:
    """Summarise an SDP body that arrived as text (a softphone log)."""
    if "\nm=" not in "\n" + body.replace("\r\n", "\n"):
        return None
    hexbody = binascii.hexlify(body.encode("utf-8", "replace")).decode("ascii")
    layers = {"sip": {"sip.msg_body": hexbody}}
    unknown = Unknown(UnknownReason.MISSING_FIELD, "log")
    evidence = EvidenceRef(unknown, unknown)
    try:
        revision = adapter._sdp(
            layers, ("sip", "sdp"), evidence, Known(CaptureStatus.COMPLETE)
        )
    except (ValueError, TypeError, IndexError):
        return None
    if revision is None or not revision.media:
        return None
    return summarize_revision(revision, crypto_suites_by_section(body))


def summary_from_hex_body(hex_body: Optional[str], revision: Any) -> Optional[SdpSummary]:
    """Summarise a capture SDP revision; the hex body only feeds the suite scan."""
    if revision is None:
        return None
    suites: list = []
    if isinstance(hex_body, str):
        try:
            text = bytes.fromhex(hex_body.replace(":", "")).decode("utf-8", "replace")
        except ValueError:
            text = ""
        suites = crypto_suites_by_section(text)
    return summarize_revision(revision, suites)
