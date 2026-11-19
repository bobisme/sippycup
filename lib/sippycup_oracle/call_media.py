"""The run's own record of which local RTP port each call used (bn-3oib).

A run directory may hold ``call-media.json`` next to its capture. It lists,
for every call the run placed with the softphone, the local address, the
local RTP port PJSUA advertised in its SDP offer (RTCP is the next port),
and the wall-clock window in which the call's process ran. The oracle uses
it only to tell whose media is whose; it never turns an unknown result into
a pass on its own. A capture without the record is analyzed as before.

``complete`` is true when the run placed no other softphone call than the
ones listed, so media at a listed local address on an unlisted port cannot
be this run's softphone media.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterable, Mapping

CALL_MEDIA_FILE = "call-media.json"
CALL_MEDIA_VERSION = "sippycup.call-media/v1"
MAX_RECORD_BYTES = 1024 * 1024
MAX_RECORDED_CALLS = 10_000
_TRANSPORTS = {"udp", "tcp", "tls"}


class CallMediaError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RecordedCall:
    id: str
    transport: str
    local_address: str
    rtp_port: int
    started: Decimal
    ended: Decimal

    @property
    def label(self) -> str:
        return f"{self.id} ({self.transport}, local RTP port {self.rtp_port})"


@dataclass(frozen=True, slots=True)
class CallMediaRecord:
    complete: bool
    calls: tuple[RecordedCall, ...]

    @property
    def local_addresses(self) -> frozenset[str]:
        return frozenset(call.local_address for call in self.calls)


def _integer(value: Any, label: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise CallMediaError(f"{label} must be an integer from {low} to {high}")
    return value


def parse_call_media(document: Any) -> CallMediaRecord:
    """Validate a decoded ``call-media.json`` document strictly."""
    if not isinstance(document, Mapping):
        raise CallMediaError("the record must be a JSON object")
    if document.get("schema_version") != CALL_MEDIA_VERSION:
        raise CallMediaError(f"schema_version must be {CALL_MEDIA_VERSION}")
    extra = set(document) - {"schema_version", "complete", "calls"}
    if extra:
        raise CallMediaError(f"unknown fields: {', '.join(sorted(extra))}")
    complete = document.get("complete")
    if not isinstance(complete, bool):
        raise CallMediaError("complete must be true or false")
    raw_calls = document.get("calls")
    if not isinstance(raw_calls, list) or len(raw_calls) > MAX_RECORDED_CALLS:
        raise CallMediaError(f"calls must be a list of at most {MAX_RECORDED_CALLS} items")
    calls: list[RecordedCall] = []
    for index, item in enumerate(raw_calls):
        label = f"calls[{index}]"
        if not isinstance(item, Mapping):
            raise CallMediaError(f"{label} must be an object")
        keys = {"id", "transport", "local_address", "rtp_port", "rtcp_port",
                "started_unix_ns", "ended_unix_ns"}
        if set(item) != keys:
            raise CallMediaError(f"{label} must have exactly: {', '.join(sorted(keys))}")
        if not isinstance(item["id"], str) or not 0 < len(item["id"]) <= 64:
            raise CallMediaError(f"{label}.id must be a short string")
        if item["transport"] not in _TRANSPORTS:
            raise CallMediaError(f"{label}.transport must be udp, tcp, or tls")
        try:
            address = str(ipaddress.ip_address(item["local_address"]))
        except (TypeError, ValueError) as error:
            raise CallMediaError(f"{label}.local_address must be a literal IP address") from error
        rtp = _integer(item["rtp_port"], f"{label}.rtp_port", 1, 65534)
        if _integer(item["rtcp_port"], f"{label}.rtcp_port", 2, 65535) != rtp + 1:
            raise CallMediaError(f"{label}.rtcp_port must be rtp_port + 1")
        started = _integer(item["started_unix_ns"], f"{label}.started_unix_ns", 0, 2**63 - 1)
        ended = _integer(item["ended_unix_ns"], f"{label}.ended_unix_ns", 0, 2**63 - 1)
        if ended < started:
            raise CallMediaError(f"{label} ends before it starts")
        calls.append(RecordedCall(
            item["id"], item["transport"], address, rtp,
            Decimal(started) / Decimal(10**9), Decimal(ended) / Decimal(10**9),
        ))
    return CallMediaRecord(complete, tuple(calls))


def load_call_media(path: Path) -> CallMediaRecord | None:
    """Read the record at PATH; ``None`` when there is none."""
    try:
        if path.is_symlink() or not path.is_file():
            return None
        if path.stat().st_size > MAX_RECORD_BYTES:
            raise CallMediaError("the record exceeds its byte limit")
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CallMediaError(f"cannot read {path.name}: {error}") from error
    return parse_call_media(document)


def recorded_call(
    call_id: str,
    transport: str,
    local_address: str | None,
    rtp_port: Any,
    started_unix_ns: int,
    ended_unix_ns: int,
) -> dict[str, Any] | None:
    """One ``calls`` entry, or ``None`` when the port or address is unknown."""
    if type(rtp_port) is not int or not 1 <= rtp_port <= 65534 or local_address is None:
        return None
    try:
        address = str(ipaddress.ip_address(local_address))
    except ValueError:
        return None
    return {
        "id": call_id,
        "transport": transport,
        "local_address": address,
        "rtp_port": rtp_port,
        "rtcp_port": rtp_port + 1,
        "started_unix_ns": int(started_unix_ns),
        "ended_unix_ns": max(int(ended_unix_ns), int(started_unix_ns)),
    }


def call_media_document(calls: Iterable[dict[str, Any] | None], *, placed: int) -> dict[str, Any]:
    """The record for a run that placed PLACED softphone calls.

    It is complete only when every placed call has an entry.
    """
    listed = [item for item in calls if item is not None]
    document = {
        "schema_version": CALL_MEDIA_VERSION,
        "complete": len(listed) == placed,
        "calls": listed,
    }
    parse_call_media(document)
    return document
