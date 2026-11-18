"""Facts the softphone driver reads from PJSUA's level-5 log and the capture.

Nothing here sends packets. The functions parse text PJSUA already printed
(SIP messages with their SDP bodies, DTMF and SRTP lines, timestamps) and the
field output of an offline ``tshark`` run over the capture, so DTMF and SRTP
results rest on what was observed rather than on what was requested.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable, Sequence

# -- DTMF request grammar -----------------------------------------------------

DTMF_DIGITS = "0123456789*#ABCD"
MAX_DTMF_DIGITS = 32
MAX_DTMF_PAUSES = 32
MAX_DTMF_AFTER_SECONDS = 60
DEFAULT_DTMF_AFTER_SECONDS = 1
# PJSUA sends each RFC 4733 event for 200 ms and starts the next about 40 ms
# later (observed with PJSUA 2.17); a comma is a 1 s pause the driver inserts
# between console commands.
DTMF_DIGIT_SECONDS = 0.25
DTMF_PAUSE_SECONDS = 1.0
DTMF_SETTLE_SECONDS = 1.0
_DTMF = re.compile(r"^[0-9A-D*#,]{1,64}$")
# RFC 4733 section 3.2 event codes 0-15.
EVENT_DIGITS = {index: digit for index, digit in enumerate("0123456789*#ABCD")}


class DtmfError(ValueError):
    """The requested DTMF string is outside the reviewed grammar."""


def validate_dtmf(value: Any) -> str:
    """Return ``value`` when it is 1-32 digits of ``[0-9A-D*#]`` plus ``,`` pauses."""
    if not isinstance(value, str) or _DTMF.fullmatch(value) is None:
        raise DtmfError(
            "DTMF must be 1-32 digits from 0-9 A-D * # with optional ',' pauses (1 s each)"
        )
    digits = dtmf_digits(value)
    if not 1 <= len(digits) <= MAX_DTMF_DIGITS:
        raise DtmfError(f"DTMF must contain 1-{MAX_DTMF_DIGITS} digits")
    if value.count(",") > MAX_DTMF_PAUSES:
        raise DtmfError(f"DTMF may contain at most {MAX_DTMF_PAUSES} pauses")
    return value


def dtmf_digits(value: str) -> str:
    """The digits alone, without pauses."""
    return value.replace(",", "")


def dtmf_schedule(value: str) -> list[tuple[float, str]]:
    """``(offset seconds, digits)`` chunks: each chunk is one console command."""
    schedule: list[tuple[float, str]] = []
    offset = 0.0
    for index, chunk in enumerate(value.split(",")):
        if index:
            offset += DTMF_PAUSE_SECONDS
        if chunk:
            schedule.append((round(offset, 3), chunk))
            offset += len(chunk) * DTMF_DIGIT_SECONDS
    return schedule


def dtmf_seconds(value: str) -> float:
    """Seconds from the first digit to the last event's end."""
    offset = 0.0
    for index, chunk in enumerate(value.split(",")):
        if index:
            offset += DTMF_PAUSE_SECONDS
        offset += len(chunk) * DTMF_DIGIT_SECONDS
    return round(offset, 3)


# -- PJSUA message log ----------------------------------------------------------

_TIME = re.compile(r"^(\d{2}):(\d{2}):(\d{2})\.(\d{3})\s")
_MESSAGE_START = re.compile(
    r"(TX|RX) \d+ bytes (Request|Response) msg (?:(\d{3})/)?([A-Z]+)/cseq=(\d+)"
)
_END_MESSAGE = "--end msg--"
_RTPMAP = re.compile(r"^a=rtpmap:(\d+) ([A-Za-z0-9._-]+)/(\d+)", re.I)
_MEDIA_LINE = re.compile(r"^m=audio (\d+) (\S+)")
_CRYPTO = re.compile(r"^a=crypto:\d+ (\S+)")
_DTMF_SENT = re.compile(r"Sending DTMF digit id (\S)")
_DTMF_RECEIVED = re.compile(r"Incoming DTMF on call \d+: ([0-9A-D*#])")
_DTMF_ERROR = re.compile(r"Unable to send DTMF: ([^\r\n]*)")
_SRTP_STARTED = re.compile(r"SRTP started, keying=(\S+?),? crypto=(\S+)")
_SRTP_STATUS = re.compile(r"SRTP status: (Active|Not active) Crypto-suite: ?(\S*)")
_INSECURE = re.compile(r"PJSIP_ESESSIONINSECURE")


def _seconds(line: str) -> float | None:
    match = _TIME.match(line)
    if match is None:
        return None
    hours, minutes, seconds, millis = (int(item) for item in match.groups())
    return hours * 3600 + minutes * 60 + seconds + millis / 1000


def parse_messages(text: str) -> list[dict[str, Any]]:
    """Every SIP message PJSUA logged at level 5, in log order."""
    messages: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        match = _MESSAGE_START.search(line)
        if match is not None and (" bytes " in line):
            current = {
                "direction": match.group(1),
                "kind": match.group(2),
                "status": int(match.group(3)) if match.group(3) else None,
                "method": match.group(4),
                "cseq": int(match.group(5)),
                "at": _seconds(line),
                "lines": [],
            }
            messages.append(current)
            continue
        if current is not None:
            if _END_MESSAGE in line:
                current = None
            else:
                current["lines"].append(line.rstrip("\r"))
    return messages


_MEDIA_FORMATS = re.compile(r"^m=audio \d+(?:/\d+)? \S+((?: \d+)*)\s*$")
# RFC 3551 static audio payload types (name, clock rate) that an SDP may use
# without an rtpmap line.
STATIC_PAYLOAD_TYPES = {
    0: ("PCMU", 8000),
    3: ("GSM", 8000),
    4: ("G723", 8000),
    8: ("PCMA", 8000),
    9: ("G722", 8000),
    13: ("CN", 8000),
    18: ("G729", 8000),
}
# Formats that are not voice codecs: DTMF events and comfort noise.
NON_CODEC_FORMATS = frozenset({"telephone-event", "cn"})


def sdp_codecs(formats: Sequence[int], rtpmap: dict[int, tuple[str, int]]) -> list[dict[str, Any]]:
    """The voice codecs an m-line lists, in its order (no telephone-event or CN)."""
    codecs: list[dict[str, Any]] = []
    for payload_type in formats:
        name, rate = rtpmap.get(payload_type) or STATIC_PAYLOAD_TYPES.get(payload_type, (None, None))
        if name is not None and name.lower() in NON_CODEC_FORMATS:
            continue
        codecs.append({"payloadType": payload_type, "name": name, "clockRate": rate})
    return codecs


def sdp(lines: Sequence[str]) -> dict[str, Any] | None:
    """Audio facts of the SDP body in one logged message, or ``None``."""
    media = None
    events: list[int] = []
    suites: list[str] = []
    rtpmap: dict[int, tuple[str, int]] = {}
    for line in lines:
        stripped = line.strip()
        if (match := _MEDIA_LINE.match(stripped)) is not None:
            if media is not None:
                break  # only the first audio stream
            formats = _MEDIA_FORMATS.match(stripped)
            media = {
                "port": int(match.group(1)),
                "profile": match.group(2),
                "formats": [int(item) for item in formats.group(1).split()] if formats else [],
            }
            continue
        if media is None:
            continue
        if stripped.startswith("m="):
            break
        if (match := _RTPMAP.match(stripped)) is not None:
            rtpmap[int(match.group(1))] = (match.group(2), int(match.group(3)))
            if match.group(2).lower() == "telephone-event":
                events.append(int(match.group(1)))
        elif (match := _CRYPTO.match(stripped)) is not None:
            suites.append(match.group(1))
    if media is None:
        return None
    return {
        "port": media["port"],
        "profile": media["profile"],
        "telephoneEvents": events,
        "cryptoSuites": suites,
        "formats": media["formats"],
        "codecs": sdp_codecs(media["formats"], rtpmap),
    }


def negotiated_sdp(messages: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The local INVITE offer and the remote answer that the call used."""
    offer = None
    answer = None
    for message in messages:
        if message["method"] != "INVITE":
            continue
        body = sdp(message["lines"])
        if body is None:
            continue
        if message["direction"] == "TX" and message["kind"] == "Request":
            offer = body
        elif (
            message["direction"] == "RX"
            and message["kind"] == "Response"
            and message["status"] is not None
            and (200 <= message["status"] < 300 or message["status"] == 183)
        ):
            answer = body
    return {"offer": offer, "answer": answer}


def registration_final_status(messages: Sequence[dict[str, Any]]) -> int | None:
    """The last final response PJSUA received to a REGISTER, if any."""
    status = None
    for message in messages:
        if (
            message["method"] == "REGISTER"
            and message["direction"] == "RX"
            and message["status"] is not None
            and message["status"] >= 200
        ):
            status = message["status"]
    return status


def _elapsed(start: float, end: float) -> float:
    delta = end - start
    if delta < 0:  # the log crossed midnight
        delta += 86400
    return round(delta, 3)


def setup_timing(messages: Sequence[dict[str, Any]]) -> dict[str, Any] | None:
    """INVITE to first 180/183 and to the 2xx, from PJSUA's log timestamps.

    Measured from the first INVITE sent, so a digest challenge round trip is
    part of the setup time the caller experienced.
    """
    invite = None
    provisional = None
    provisional_status = None
    answer = None
    final_status = None
    for message in messages:
        if message["method"] != "INVITE" or message["at"] is None:
            continue
        if message["direction"] == "TX" and message["kind"] == "Request":
            if invite is None:
                invite = message["at"]
            continue
        if invite is None or message["direction"] != "RX" or message["status"] is None:
            continue
        status = message["status"]
        if status in (180, 183) and provisional is None and answer is None:
            provisional = message["at"]
            provisional_status = status
        elif 200 <= status < 300 and answer is None:
            answer = message["at"]
            final_status = status
    if invite is None:
        return None
    return {
        "source": "pjsua-log-timestamps",
        "inviteToProvisionalSeconds": None if provisional is None else _elapsed(invite, provisional),
        "provisionalStatus": provisional_status,
        "inviteToAnswerSeconds": None if answer is None else _elapsed(invite, answer),
        "answerStatus": final_status,
    }


def dtmf_log_facts(text: str) -> dict[str, Any]:
    """Digits PJSUA sent and received, and why it refused to send."""
    errors = [match.group(1).strip() for match in _DTMF_ERROR.finditer(text)]
    return {
        "sent": "".join(match.group(1) for match in _DTMF_SENT.finditer(text)),
        "received": "".join(match.group(1) for match in _DTMF_RECEIVED.finditer(text)),
        "errors": errors,
        "remoteUnsupported": any("2833" in item or "not support" in item for item in errors),
    }


def srtp_log_facts(text: str) -> dict[str, Any]:
    """Whether PJSUA reported SRTP active, with the crypto suite."""
    active = None
    suite = None
    keying = None
    for match in _SRTP_STARTED.finditer(text):
        active = True
        keying = match.group(1)
        suite = match.group(2)
    for match in _SRTP_STATUS.finditer(text):
        if match.group(1) == "Active":
            active = True
            suite = match.group(2) or suite
        elif active is None:
            active = False
    return {
        "active": active,
        "suite": suite,
        "keying": keying,
        "insecureSignalingRefused": bool(_INSECURE.search(text)),
    }


# -- capture: RFC 4733 events ----------------------------------------------------

def rtp_event_argv(tshark: str, capture: str, peer: str | None) -> list[str] | None:
    """tshark argv listing RTP on the negotiated media peer's port.

    The ``rtpevent`` dissector is disabled so every payload is printed as
    raw bytes and decoded here: the result does not depend on whether
    tshark saw the SDP (it cannot under TLS signaling).
    """
    from .driver import _peer_address, _peer_port

    if not peer:
        return None
    address = _peer_address(peer)
    port = _peer_port(peer)
    if address is None or port is None:
        return None
    family = "ipv6" if ":" in address else "ip"
    return [
        tshark, "-n", "-r", str(capture), "--disable-protocol", "rtpevent",
        "-d", f"udp.port=={port},rtp",
        "-Y", f"rtp && {family}.addr == {address} && udp.port == {port}",
        "-T", "fields", "-e", f"{family}.src", "-e", "rtp.p_type", "-e", "rtp.ssrc",
        "-e", "rtp.timestamp", "-e", "rtp.payload",
    ]


def parse_rtp_events(
    text: str,
    peer_address: str,
    payload_types: Iterable[int],
    *,
    encrypted: bool,
) -> dict[str, Any]:
    """Digits in each direction from tshark field rows of ``rtp_event_argv``.

    One event is one (direction, SSRC, RTP timestamp); its repeated and end
    packets are the same digit. Under SRTP the payload is encrypted, so only
    the number of events is known.
    """
    peer = str(ipaddress.ip_address(peer_address))
    types = {int(item) for item in payload_types}
    result: dict[str, Any] = {}
    for direction in ("outbound", "inbound"):
        result[direction] = {"events": 0, "digits": None if encrypted else "", "endPackets": 0}
    seen: set[tuple[str, str, str]] = set()
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) < 5 or not fields[1].isdigit() or int(fields[1]) not in types:
            continue
        try:
            source = str(ipaddress.ip_address(fields[0]))
        except ValueError:
            continue
        direction = "inbound" if source == peer else "outbound"
        payload = fields[4].replace(":", "")
        key = (direction, fields[2], fields[3])
        entry = result[direction]
        if not encrypted and len(payload) >= 8:
            try:
                flags = int(payload[2:4], 16)
            except ValueError:
                flags = 0
            if flags & 0x80:
                entry["endPackets"] += 1
        if key in seen:
            continue
        seen.add(key)
        entry["events"] += 1
        if not encrypted:
            try:
                event = int(payload[0:2], 16)
            except ValueError:
                event = -1
            entry["digits"] += EVENT_DIGITS.get(event, "?")
    return result
