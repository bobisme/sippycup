"""Reconstruct SIP messages from a PJSUA (softphone) log.

When signaling is TLS-encrypted on the wire, the softphone's own log is the
only place the SIP messages exist. PJSUA prints each message between a
`TX|RX N bytes ... to|from TRANSPORT addr:port:` line and `--end msg--`.

Only the start line, Call-ID, CSeq, Via sent-by, tags, authentication header
presence and the SDP body are read. Credential header values are never
copied anywhere.
"""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Optional

from .model import AUTH_SCHEMES, Endpoint, SipMsg
from .sdp import summary_from_body_text

_HEAD = re.compile(
    r"^(?P<time>\d{2}:\d{2}:\d{2}\.\d{3})\s+\S+\s+[!.]*"
    r"(?P<dir>TX|RX) (?P<size>\d+) bytes (?:Request|Response) msg .*? "
    r"(?:to|from) (?P<transport>[A-Za-z0-9]+) "
    r"(?P<addr>\[[0-9A-Fa-f:.]+\]|[0-9.]+|[^\s:]+):(?P<port>\d+):\s*$"
)
_VIA = re.compile(r"(?i)^(?:via|v)\s*:\s*SIP/2\.0/(\w+)\s+(\[[0-9A-Fa-f:.]+\]|[^\s:;,]+)(?::(\d+))?")
_TAG = re.compile(r";\s*tag=([^;>\s]+)")


def _strip_brackets(address: str) -> str:
    return address[1:-1] if address.startswith("[") and address.endswith("]") else address


def parse_log(
    text: str,
    *,
    base_date: dt.date,
    tz_shift_hours: int = 0,
) -> list:
    """Return SipMsg records in log order. Log times are UTC time of day."""
    lines = text.splitlines()
    messages: list = []
    local: Optional[Endpoint] = None
    day = base_date
    previous_seconds = None
    index = 0
    while index < len(lines):
        match = _HEAD.match(lines[index])
        index += 1
        if match is None:
            continue
        end = index
        while end < len(lines) and lines[end].strip() != "--end msg--":
            end += 1
        block = lines[index:end]
        index = end + 1
        h, m, rest = match.group("time").split(":")
        seconds = int(h) * 3600 + int(m) * 60 + float(rest)
        if previous_seconds is not None and seconds + 43200 < previous_seconds:
            day = day + dt.timedelta(days=1)
        previous_seconds = seconds
        epoch = (
            dt.datetime(day.year, day.month, day.day, tzinfo=dt.timezone.utc).timestamp()
            + seconds
            + tz_shift_hours * 3600
        )
        if not block:
            continue
        start = block[0].strip()
        headers: dict = {}
        body_lines: list = []
        in_body = False
        via_values = []
        for line in block[1:]:
            if in_body:
                body_lines.append(line)
                continue
            if line.strip() == "":
                in_body = True
                continue
            name, _, value = line.partition(":")
            key = name.strip().lower()
            headers.setdefault(key, value.strip())
            if key in ("via", "v"):
                via_values.append(line)
        kind = "response" if start.startswith("SIP/2.0") else "request"
        status = None
        reason = None
        method = None
        if kind == "response":
            parts = start.split(None, 2)
            try:
                status = int(parts[1])
            except (IndexError, ValueError):
                continue
            reason = parts[2] if len(parts) > 2 else None
        else:
            method = start.split(None, 1)[0]
        cseq_value = headers.get("cseq", "")
        cseq_parts = cseq_value.split()
        cseq = int(cseq_parts[0]) if cseq_parts and cseq_parts[0].isdigit() else None
        if kind == "response":
            method = cseq_parts[1] if len(cseq_parts) > 1 else "?"
        call_id = headers.get("call-id", headers.get("i", ""))
        peer = Endpoint(_strip_brackets(match.group("addr")), int(match.group("port")))
        transport = match.group("transport").lower()
        branch = None
        if via_values:
            via_match = _VIA.match(via_values[0].strip())
            if via_match is not None:
                branch_match = re.search(r";\s*branch=([^;,\s]+)", via_values[0])
                branch = branch_match.group(1) if branch_match else None
                if match.group("dir") == "TX" and kind == "request" and local is None:
                    local = Endpoint(
                        _strip_brackets(via_match.group(2)),
                        int(via_match.group(3)) if via_match.group(3) else None,
                    )
        auth = None
        scheme = None
        for header, mode in (
            ("authorization", "response"),
            ("proxy-authorization", "response"),
            ("www-authenticate", "challenge"),
            ("proxy-authenticate", "challenge"),
        ):
            if header in headers:
                auth = mode
                word = headers[header].split(None, 1)[0] if headers[header].split() else ""
                scheme = next(
                    (s for s in AUTH_SCHEMES if s.lower() == word.lower()),
                    "other" if word and word != "<redacted>" else None,
                )
                break
        body = "\n".join(body_lines).strip("\n")
        sdp = summary_from_body_text(body) if "m=" in body else None
        other = 0 if sdp is not None or not body.strip() else len(body.encode())
        from_tag = _TAG.search(headers.get("from", headers.get("f", "")))
        to_tag = _TAG.search(headers.get("to", headers.get("t", "")))
        mine = local if local is not None else Endpoint(None, None)
        if match.group("dir") == "TX":
            src, dst = mine, peer
        else:
            src, dst = peer, mine
        messages.append(
            SipMsg(
                t=epoch,
                frame=None,
                src=src,
                dst=dst,
                transport=transport,
                kind=kind,
                method=method or "?",
                status=status,
                reason=reason,
                call_id=call_id,
                cseq=cseq,
                branch=branch,
                from_tag=from_tag.group(1) if from_tag else None,
                to_tag=to_tag.group(1) if to_tag else None,
                auth=auth,
                auth_scheme=scheme,
                sdp=sdp,
                other_body_bytes=other,
                source="softphone-log",
            )
        )
    # The local endpoint is learned from the first outgoing request; fill it
    # into messages seen before that point.
    if local is not None:
        for message in messages:
            if message.src.address is None and message.src.port is None:
                message.src = local
            if message.dst.address is None and message.dst.port is None:
                message.dst = local
    return messages


def read_log(path: Path, *, base_date: dt.date, tz_shift_hours: int = 0) -> list:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_log(text, base_date=base_date, tz_shift_hours=tz_shift_hours)
