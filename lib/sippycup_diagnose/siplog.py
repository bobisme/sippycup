"""Read the SIP messages PJSUA printed into softphone.log.

Only protocol metadata is kept: direction, method or status, the Reason,
Warning and Retry-After headers, and the SDP connection and media lines. No
URI, Call-ID, tag, Authorization header, or body text is retained.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

_HEAD = re.compile(
    r"^(\d\d):(\d\d):(\d\d)\.(\d{3})\s+\S+\s+\.*(RX|TX) \d+ bytes (Request|Response) msg "
    r"(\S+?) \(\S+\) (?:from|to) (\S+) (\S+):\s*$"
)
_STATUS = re.compile(r"^(\d{3})/([A-Z]+)/cseq=(\d+)$")
_REQUEST = re.compile(r"^([A-Z]+)/cseq=(\d+)$")


@dataclass
class SdpLog:
    address: Optional[str] = None
    port: Optional[int] = None
    proto: Optional[str] = None
    formats: list = field(default_factory=list)
    direction: Optional[str] = None
    crypto: bool = False


@dataclass
class LogMsg:
    t: float  # seconds since midnight, on the softphone log clock
    outbound: bool  # TX when True, RX when False
    method: str
    status: Optional[int]  # None for a request
    cseq: Optional[int]
    transport: str
    reason: Optional[str] = None
    warning: Optional[str] = None
    retry_after: Optional[str] = None
    has_auth: bool = False
    phrase: Optional[str] = None
    sdp: Optional[SdpLog] = None


def _parse_sdp(lines: list) -> Optional[SdpLog]:
    sdp = SdpLog()
    seen = False
    session_address = None
    for line in lines:
        if line.startswith("c=IN ") and not seen:
            parts = line.split()
            if len(parts) >= 3:
                session_address = parts[2].split("/")[0]
        elif line.startswith("m=audio "):
            parts = line.split()
            if len(parts) >= 4 and sdp.port is None:
                seen = True
                try:
                    sdp.port = int(parts[1])
                except ValueError:
                    sdp.port = None
                sdp.proto = parts[2]
                sdp.formats = [item for item in parts[3:] if item.isdigit()]
        elif line.startswith("c=IN ") and seen and sdp.address is None:
            parts = line.split()
            if len(parts) >= 3:
                sdp.address = parts[2].split("/")[0]
        elif line.startswith("a=") and seen:
            word = line[2:].strip()
            if word in ("sendrecv", "sendonly", "recvonly", "inactive") and sdp.direction is None:
                sdp.direction = word
            elif word.startswith("crypto:"):
                sdp.crypto = True
    if sdp.address is None:
        sdp.address = session_address
    return sdp if sdp.port is not None or sdp.address else None


def parse_messages(text: str) -> list:
    """The SIP messages in a PJSUA log, in order."""
    messages: list = []
    lines = text.split("\n")
    index = 0
    while index < len(lines):
        match = _HEAD.match(lines[index])
        index += 1
        if not match:
            continue
        hour, minute, second, milli, direction, kind, descriptor, _proto, _address = match.groups()
        t = int(hour) * 3600 + int(minute) * 60 + int(second) + int(milli) / 1000.0
        status: Optional[int] = None
        if kind == "Response":
            found = _STATUS.match(descriptor)
            if not found:
                continue
            status, method, cseq = int(found.group(1)), found.group(2), int(found.group(3))
        else:
            found = _REQUEST.match(descriptor)
            if not found:
                continue
            method, cseq = found.group(1), int(found.group(2))
        message = LogMsg(
            t=t,
            outbound=direction == "TX",
            method=method,
            status=status,
            cseq=cseq,
            transport=_proto,
        )
        start_line = lines[index] if index < len(lines) else ""
        index += 1
        if status is not None:
            words = start_line.strip().split(None, 2)
            if len(words) == 3 and words[0].startswith("SIP/"):
                message.phrase = words[2]
        body: list = []
        in_body = False
        while index < len(lines) and lines[index].strip() != "--end msg--":
            line = lines[index].rstrip("\r")
            index += 1
            if not in_body:
                if line.strip() == "":
                    in_body = True
                    continue
                name, _, value = line.partition(":")
                lowered = name.strip().lower()
                if lowered == "reason":
                    message.reason = value.strip()
                elif lowered == "warning":
                    message.warning = value.strip()
                elif lowered == "retry-after":
                    message.retry_after = value.strip()
                elif lowered in ("authorization", "proxy-authorization"):
                    message.has_auth = True
            else:
                body.append(line.strip())
        if body:
            message.sdp = _parse_sdp(body)
        messages.append(message)
    return messages


def midnight_fix(messages: list) -> None:
    """Make the clock monotonic across a midnight wrap (rare, but cheap)."""
    offset = 0.0
    previous = None
    for message in messages:
        if previous is not None and message.t + offset < previous - 43200:
            offset += 86400.0
        message.t += offset
        previous = message.t
