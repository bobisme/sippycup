"""Source-generated, bit-exact protocol torture corpus.

The corpus deliberately contains no target discovery, authentication attempts,
reflection primitives, or network loop.  A later guarded runner may select a
case and send its finite ``wire_bytes`` exactly once.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, Iterable


class CorpusError(ValueError):
    """A corpus definition violates a safety or reproducibility invariant."""


@dataclass(frozen=True)
class Case:
    id: str
    protocol: str
    title: str
    provenance: str
    validity: str
    dialog_state: str
    risk: str
    expected_outcomes: tuple[str, ...]
    wire_bytes: bytes
    packet_count: int = 1
    packet_lengths: tuple[int, ...] = ()

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.wire_bytes).hexdigest()

    def as_manifest_record(self) -> dict[str, object]:
        return {
            "id": self.id,
            "protocol": self.protocol,
            "title": self.title,
            "provenance": self.provenance,
            "validity": self.validity,
            "requiredDialogState": self.dialog_state,
            "risk": self.risk,
            "acceptableOutcomes": list(self.expected_outcomes),
            "trafficCost": {
                "packets": self.packet_count,
                "bytes": len(self.wire_bytes),
                "packetLengths": list(self.packet_lengths or (len(self.wire_bytes),)),
            },
            "sha256": self.sha256,
            "wireHex": self.wire_bytes.hex(),
        }


def _sip(start: str, headers: Iterable[str], body: bytes = b"") -> bytes:
    head = "\r\n".join((start, *headers)).encode("ascii")
    return head + b"\r\n\r\n" + body


def _invite(extra: Iterable[str] = (), body: bytes = b"", *, cseq: str = "1 INVITE") -> bytes:
    headers = [
        "Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK-sippycup",
        "Max-Forwards: 70",
        "From: <sip:canary-a@example.invalid>;tag=sc-a",
        "To: <sip:canary-b@example.invalid>",
        "Call-ID: torture-1@example.invalid",
        f"CSeq: {cseq}",
        "Contact: <sip:canary-a@192.0.2.20:5060>",
        *extra,
        f"Content-Length: {len(body)}",
    ]
    return _sip("INVITE sip:canary-b@example.invalid SIP/2.0", headers, body)


def _rtp(sequence: int, timestamp: int, ssrc: int, payload_type: int, payload: bytes) -> bytes:
    return (
        bytes((0x80, payload_type & 0x7F))
        + sequence.to_bytes(2, "big")
        + timestamp.to_bytes(4, "big")
        + ssrc.to_bytes(4, "big")
        + payload
    )


def _rtcp(packet_type: int, declared_words_minus_one: int, body: bytes) -> bytes:
    return bytes((0x80, packet_type)) + declared_words_minus_one.to_bytes(2, "big") + body


def build_corpus() -> tuple[Case, ...]:
    """Build the immutable corpus from compact, reviewable source."""

    sdp_conflict = (
        b"v=0\r\n"
        b"o=- 1 1 IN IP4 192.0.2.20\r\n"
        b"s=sippycup\r\n"
        b"c=IN IP4 192.0.2.20\r\n"
        b"t=0 0\r\n"
        b"m=audio 40000 RTP/AVP 0\r\n"
        b"a=rtpmap:8 PCMA/8000\r\n"
        b"a=sendonly\r\n"
        b"a=recvonly\r\n"
    )
    bounded_long = "X-Sippycup-Bounded: " + ("a" * 1024)
    cases = (
        Case(
            "sip-rfc4475-conflicting-content-length",
            "sip",
            "Conflicting compact and long Content-Length",
            "RFC 4475 §3.1.2-inspired; locally generated identifiers",
            "invalid",
            "pre-dialog",
            "medium",
            ("400-response", "transaction-rejected", "connection-closed"),
            _invite(("l: 0",), b"ABCD"),
        ),
        Case(
            "sip-bounded-long-header",
            "sip",
            "Bounded long extension header",
            "RFC 4475 §3.1.1-inspired; bounded local variant",
            "valid-unusual",
            "pre-dialog",
            "low",
            ("provisional-or-final-response", "transaction-rejected"),
            _invite((bounded_long,)),
        ),
        Case(
            "sip-max-forwards-zero",
            "sip",
            "Exhausted Max-Forwards",
            "RFC 3261 §16.3; source-generated",
            "valid",
            "pre-dialog",
            "low",
            ("483-response",),
            _invite(("Max-Forwards: 0",)),
        ),
        Case(
            "sip-cseq-method-mismatch",
            "sip",
            "Request method and CSeq method disagree",
            "RFC 3261 §20.16 negative case; source-generated",
            "invalid",
            "pre-dialog",
            "medium",
            ("400-response", "transaction-rejected"),
            _invite(cseq="1 BYE"),
        ),
        Case(
            "sip-branch-cookie-missing",
            "sip",
            "Top Via branch lacks magic cookie",
            "RFC 3261 §8.1.1.7 negative case; source-generated",
            "invalid",
            "pre-dialog",
            "low",
            ("400-response", "transaction-rejected"),
            _invite(("Via: SIP/2.0/UDP 192.0.2.20:5060;branch=legacy",)),
        ),
        Case(
            "sip-in-dialog-tag-anomaly",
            "sip",
            "BYE reverses dialog tags",
            "RFC 3261 dialog matching negative case; source-generated",
            "invalid",
            "established-dialog",
            "medium",
            ("481-response", "request-ignored"),
            _sip(
                "BYE sip:canary-b@example.invalid SIP/2.0",
                (
                    "Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK-wrong-tags",
                    "From: <sip:canary-a@example.invalid>;tag=remote-tag",
                    "To: <sip:canary-b@example.invalid>;tag=local-tag",
                    "Call-ID: torture-1@example.invalid",
                    "CSeq: 2 BYE",
                    "Content-Length: 0",
                ),
            ),
        ),
        Case(
            "sdp-contradictory-direction-and-payload",
            "sdp",
            "Contradictory directions and undeclared codec mapping",
            "RFC 4566/RFC 3264 negative case; source-generated",
            "invalid",
            "offer-pending",
            "medium",
            ("488-response", "offer-rejected"),
            sdp_conflict,
        ),
        Case(
            "rtp-sequence-wrap",
            "rtp",
            "Sequence wraps while timestamp advances",
            "RFC 3550 §5.3.1 boundary case; synthetic payload",
            "valid",
            "media-active",
            "low",
            ("media-accepted",),
            _rtp(0xFFFF, 0xFFFFFF00, 0x10203040, 0, b"\xff" * 8)
            + _rtp(0, 0x000000A0, 0x10203040, 0, b"\x7f" * 8),
            2,
            (20, 20),
        ),
        Case(
            "rtp-timestamp-regression",
            "rtp",
            "Timestamp regresses without sequence restart",
            "RFC 3550 invariant negative case; synthetic payload",
            "invalid",
            "media-active",
            "low",
            ("packet-dropped", "stream-flagged"),
            _rtp(100, 32000, 0x10203040, 0, b"\xff" * 8)
            + _rtp(101, 16000, 0x10203040, 0, b"\xff" * 8),
            2,
            (20, 20),
        ),
        Case(
            "rtp-ssrc-and-payload-transition",
            "rtp",
            "Unsignaled SSRC and payload-type transition",
            "RFC 3550/RFC 3264 negative case; synthetic payload",
            "invalid",
            "media-active",
            "medium",
            ("packet-dropped", "stream-split", "stream-flagged"),
            _rtp(10, 1600, 0x10203040, 0, b"\xff" * 8)
            + _rtp(11, 1760, 0x50607080, 111, b"\x00" * 8),
            2,
            (20, 20),
        ),
        Case(
            "rfc4733-premature-end",
            "rfc4733",
            "Telephone event ends with decreasing duration",
            "RFC 4733 §2.5.1 negative case; event 5, fixed volume",
            "invalid",
            "media-active",
            "low",
            ("event-ignored", "event-flagged"),
            _rtp(20, 8000, 0x10203040, 101, bytes((5, 10, 0, 160)))
            + _rtp(21, 8000, 0x10203040, 101, bytes((5, 0x8A, 0, 80))),
            2,
            (16, 16),
        ),
        Case(
            "rfc4733-redundant-valid-end",
            "rfc4733",
            "Three identical end packets",
            "RFC 4733 §2.5.1 redundancy case; event 8",
            "valid",
            "media-active",
            "low",
            ("single-event-delivered",),
            b"".join(
                _rtp(sequence, 9000, 0x10203040, 101, bytes((8, 0x8A, 1, 0x40)))
                for sequence in (30, 31, 32)
            ),
            3,
            (16, 16, 16),
        ),
        Case(
            "rtcp-truncated-sender-report",
            "rtcp",
            "Sender Report length exceeds available bytes",
            "RFC 3550 §6.4.1 negative case; source-generated",
            "invalid",
            "media-active",
            "low",
            ("packet-dropped", "control-stream-flagged"),
            _rtcp(200, 6, b"\x10\x20\x30\x40"),
        ),
        Case(
            "rtcp-unknown-type-bounded",
            "rtcp",
            "Finite unknown RTCP packet type",
            "RFC 3550 compound validation negative case; source-generated",
            "invalid",
            "media-active",
            "low",
            ("packet-dropped", "control-stream-flagged"),
            _rtcp(255, 1, b"\x00\x00\x00\x00"),
        ),
    )
    _validate(cases)
    return cases


def _validate(cases: tuple[Case, ...]) -> None:
    ids: set[str] = set()
    allowed_protocols = {"sip", "sdp", "rtp", "rfc4733", "rtcp"}
    allowed_risks = {"low", "medium"}
    for case in cases:
        if case.id in ids:
            raise CorpusError(f"duplicate case id: {case.id}")
        ids.add(case.id)
        if case.protocol not in allowed_protocols:
            raise CorpusError(f"{case.id}: unsupported protocol")
        if case.risk not in allowed_risks:
            raise CorpusError(f"{case.id}: risk must remain bounded")
        if not case.wire_bytes or len(case.wire_bytes) > 4096:
            raise CorpusError(f"{case.id}: wire bytes must be 1..4096 bytes")
        if not 1 <= case.packet_count <= 3:
            raise CorpusError(f"{case.id}: packet cost must be 1..3")
        lengths = case.packet_lengths or (len(case.wire_bytes),)
        if len(lengths) != case.packet_count or sum(lengths) != len(case.wire_bytes):
            raise CorpusError(f"{case.id}: packet boundaries do not match wire bytes")
        if not case.expected_outcomes:
            raise CorpusError(f"{case.id}: missing acceptable outcomes")
        lowered = case.title.lower() + " " + case.provenance.lower()
        if any(term in lowered for term in ("credential guess", "reflection", "amplification")):
            raise CorpusError(f"{case.id}: prohibited behavior")


def corpus_manifest() -> dict[str, object]:
    cases = build_corpus()
    records = [case.as_manifest_record() for case in cases]
    identity = hashlib.sha256(
        "\n".join(f"{case.id}:{case.sha256}" for case in cases).encode("ascii")
    ).hexdigest()
    return {
        "schema": "sippycup.torture-corpus/v1",
        "identity": identity,
        "safety": {
            "offlineOnly": True,
            "maxCasePackets": 3,
            "maxCaseBytes": 4096,
            "credentialGuessing": False,
            "spoofedReflection": False,
            "unboundedAmplification": False,
        },
        "cases": records,
    }


def send_exact(case: Case, sender: Callable[[bytes], int]) -> int:
    """Send one case through an injected, already-authorized transport.

    The injected sender makes the exact-byte boundary testable.  Short writes
    fail closed; this function never retries or loops.
    """

    lengths = case.packet_lengths or (len(case.wire_bytes),)
    total = 0
    offset = 0
    for length in lengths:
        packet = case.wire_bytes[offset : offset + length]
        sent = sender(packet)
        if sent != length:
            raise CorpusError(f"{case.id}: short write ({sent} of {length} bytes)")
        total += sent
        offset += length
    return total
