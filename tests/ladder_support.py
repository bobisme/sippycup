"""Stdlib-only synthetic capture builder for the ladder tests.

It writes classic little-endian pcap files with Ethernet, IPv4 or IPv6, and
UDP or TCP frames. Checksums are left zero because TShark does not validate
them by default.
"""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

CRLF = "\r\n"


def _ip_header(src: str, dst: str, proto: int, payload_len: int) -> tuple[bytes, int]:
    a = ipaddress.ip_address(src)
    b = ipaddress.ip_address(dst)
    if a.version == 4:
        header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + payload_len,
            0,
            0,
            64,
            proto,
            0,
            a.packed,
            b.packed,
        )
        return header, 0x0800
    header = struct.pack(
        "!IHBB16s16s", 0x60000000, payload_len, proto, 64, a.packed, b.packed
    )
    return header, 0x86DD


class Capture:
    def __init__(self) -> None:
        self.packets: list[tuple[float, bytes]] = []
        self._seq: dict[tuple, int] = {}

    def _frame(self, ts: float, src: str, dst: str, proto: int, l4: bytes) -> None:
        ip, ethertype = _ip_header(src, dst, proto, len(l4))
        ether = bytes.fromhex("02000000000a02000000000b") + struct.pack("!H", ethertype)
        self.packets.append((ts, ether + ip + l4))

    def udp(self, ts: float, src: str, sport: int, dst: str, dport: int, payload: bytes) -> None:
        l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
        self._frame(ts, src, dst, 17, l4)

    def tcp_segment(
        self,
        ts: float,
        src: str,
        sport: int,
        dst: str,
        dport: int,
        payload: bytes = b"",
        flags: int = 0x18,
    ) -> None:
        key = (src, sport, dst, dport)
        reverse = (dst, dport, src, sport)
        seq = self._seq.setdefault(key, 1000)
        ack = self._seq.get(reverse, 5000)
        l4 = (
            struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
            + payload
        )
        consumed = len(payload) + (1 if flags & 0x03 else 0)
        self._seq[key] = seq + consumed
        self._frame(ts, src, dst, 6, l4)

    def tcp_handshake(self, ts: float, client: str, cport: int, server: str, sport: int) -> float:
        self.tcp_segment(ts, client, cport, server, sport, flags=0x02)
        self.tcp_segment(ts + 0.001, server, sport, client, cport, flags=0x12)
        self.tcp_segment(ts + 0.002, client, cport, server, sport, flags=0x10)
        return ts + 0.003

    def tcp_data(
        self,
        ts: float,
        src: str,
        sport: int,
        dst: str,
        dport: int,
        payload: bytes,
        chunk: int | None = None,
    ) -> None:
        pieces = (
            [payload]
            if not chunk
            else [payload[i : i + chunk] for i in range(0, len(payload), chunk)]
        )
        for index, piece in enumerate(pieces):
            self.tcp_segment(ts + index * 0.0005, src, sport, dst, dport, piece)

    def write(self, path: Path, *, snaplen: int = 65535) -> Path:
        out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 1))
        for ts, data in self.packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            captured = data[:snaplen]
            out += struct.pack("<IIII", sec, usec, len(captured), len(data)) + captured
        Path(path).write_bytes(bytes(out))
        return Path(path)


def sip_request(
    method: str,
    call_id: str,
    cseq: int,
    *,
    uri: str = "sip:bob@192.0.2.20",
    frm: str = "sip:alice@192.0.2.10",
    to: str = "sip:bob@192.0.2.20",
    from_tag: str = "ftag1",
    to_tag: str | None = None,
    branch: str = "z9hG4bKb1",
    via_host: str = "192.0.2.10:5060",
    transport: str = "UDP",
    extra: tuple[str, ...] = (),
    sdp: str | None = None,
) -> bytes:
    body = (sdp or "").replace("\n", CRLF)
    lines = [
        f"{method} {uri} SIP/2.0",
        f"Via: SIP/2.0/{transport} {via_host};branch={branch}",
        f"From: <{frm}>;tag={from_tag}",
        f"To: <{to}>" + (f";tag={to_tag}" if to_tag else ""),
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} {method}",
        "Contact: <sip:alice@192.0.2.10:5060>",
        "Max-Forwards: 70",
        *extra,
    ]
    if sdp:
        lines.append("Content-Type: application/sdp")
    lines.append(f"Content-Length: {len(body.encode())}")
    return (CRLF.join(lines) + CRLF + CRLF + body).encode()


def sip_response(
    status: int,
    reason: str,
    method: str,
    call_id: str,
    cseq: int,
    *,
    frm: str = "sip:alice@192.0.2.10",
    to: str = "sip:bob@192.0.2.20",
    from_tag: str = "ftag1",
    to_tag: str | None = "ttag1",
    branch: str = "z9hG4bKb1",
    via_host: str = "192.0.2.10:5060",
    transport: str = "UDP",
    extra: tuple[str, ...] = (),
    sdp: str | None = None,
) -> bytes:
    body = (sdp or "").replace("\n", CRLF)
    lines = [
        f"SIP/2.0 {status} {reason}",
        f"Via: SIP/2.0/{transport} {via_host};branch={branch}",
        f"From: <{frm}>;tag={from_tag}",
        f"To: <{to}>" + (f";tag={to_tag}" if to_tag else ""),
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} {method}",
        "Contact: <sip:bob@192.0.2.20:5060>",
        *extra,
    ]
    if sdp:
        lines.append("Content-Type: application/sdp")
    lines.append(f"Content-Length: {len(body.encode())}")
    return (CRLF.join(lines) + CRLF + CRLF + body).encode()


def sdp_body(
    address: str,
    port: int,
    *,
    profile: str = "RTP/AVP",
    codecs: tuple[tuple[int, str], ...] = ((0, "PCMU/8000"), (8, "PCMA/8000"), (101, "telephone-event/8000")),
    direction: str = "sendrecv",
    crypto: bool = False,
    family: str = "IP4",
) -> str:
    pts = " ".join(str(pt) for pt, _ in codecs)
    lines = [
        "v=0",
        f"o=- 1 1 IN {family} {address}",
        "s=-",
        f"c=IN {family} {address}",
        "t=0 0",
        f"m=audio {port} {profile} {pts}",
    ]
    for pt, name in codecs:
        lines.append(f"a=rtpmap:{pt} {name}")
    if any(name.startswith("telephone-event") for _, name in codecs):
        lines.append("a=fmtp:101 0-15")
    if crypto:
        lines.append(
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:SECRETKEYSECRETKEYSECRETKEYSECRETKEYSECR"
        )
    lines.append(f"a={direction}")
    return "\n".join(lines) + "\n"


def rtp_packet(seq: int, timestamp: int, ssrc: int = 0x11223344, pt: int = 0, payload_len: int = 160, marker: bool = False, payload: bytes | None = None) -> bytes:
    header = struct.pack(
        "!BBHII", 0x80, (0x80 if marker else 0) | pt, seq & 0xFFFF, timestamp & 0xFFFFFFFF, ssrc
    )
    return header + (payload if payload is not None else b"\xff" * payload_len)


def telephone_event(seq: int, timestamp: int, digit: int, end: bool, duration: int, ssrc: int = 0x11223344, pt: int = 101) -> bytes:
    payload = struct.pack("!BBH", digit, (0x80 if end else 0) | 10, duration)
    return rtp_packet(seq, timestamp, ssrc=ssrc, pt=pt, payload=payload)


def tls_record(kind: int, body: bytes, version: int = 0x0303) -> bytes:
    return struct.pack("!BHH", kind, version, len(body)) + body


def tls_client_hello() -> bytes:
    hello = (
        struct.pack("!H", 0x0303)
        + b"\x01" * 32
        + b"\x00"
        + struct.pack("!H", 2)
        + b"\x13\x01"
        + b"\x01\x00"
    )
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    return tls_record(22, handshake, 0x0301)


def tls_server_hello() -> bytes:
    hello = (
        struct.pack("!H", 0x0303)
        + b"\x02" * 32
        + b"\x00"
        + b"\x13\x01"
        + b"\x00"
    )
    handshake = b"\x02" + len(hello).to_bytes(3, "big") + hello
    return tls_record(22, handshake)


def tls_app_data(length: int = 120) -> bytes:
    return tls_record(23, b"\xaa" * length)


def basic_call(capture: Capture, *, call_id: str = "call-one@192.0.2.10", start: float = 1000.0, caller: str = "192.0.2.10", target: str = "192.0.2.20", dtmf: bool = False, invite_retransmit: bool = False, media_target: str | None = None, challenge_status: int = 401, challenge_reason: str = "Unauthorized") -> None:
    """One passing, authenticated call with RTP both ways and a BYE."""
    fam = "IP6" if ":" in caller else "IP4"
    sdp_a = sdp_body(caller, 4000, family=fam)
    media = media_target or target
    sdp_b = sdp_body(media, 6000, family=fam)
    inv1 = sip_request("INVITE", call_id, 1, sdp=sdp_a, uri=f"sip:bob@{target}", to=f"sip:bob@{target}", branch="z9hG4bKinv1")
    capture.udp(start, caller, 5060, target, 5060, inv1)
    if invite_retransmit:
        capture.udp(start + 0.5, caller, 5060, target, 5060, inv1)
    capture.udp(
        start + 0.02,
        target,
        5060,
        caller,
        5060,
        sip_response(
            challenge_status,
            challenge_reason,
            "INVITE",
            call_id,
            1,
            to_tag="chal1",
            branch="z9hG4bKinv1",
            extra=('WWW-Authenticate: Digest realm="r", nonce="NONCEVALUE123456", algorithm=MD5',),
        ),
    )
    capture.udp(
        start + 0.03,
        caller,
        5060,
        target,
        5060,
        sip_request("ACK", call_id, 1, to_tag="chal1", branch="z9hG4bKinv1"),
    )
    inv2 = sip_request(
        "INVITE",
        call_id,
        2,
        sdp=sdp_a,
        branch="z9hG4bKinv2",
        extra=('Authorization: Digest username="alice", realm="r", nonce="NONCEVALUE123456", uri="sip:bob", response="RESPONSEHASH00112233"',),
    )
    capture.udp(start + 0.04, caller, 5060, target, 5060, inv2)
    capture.udp(
        start + 0.06,
        target,
        5060,
        caller,
        5060,
        sip_response(100, "Trying", "INVITE", call_id, 2, to_tag=None, branch="z9hG4bKinv2"),
    )
    capture.udp(
        start + 0.5,
        target,
        5060,
        caller,
        5060,
        sip_response(180, "Ringing", "INVITE", call_id, 2, branch="z9hG4bKinv2"),
    )
    capture.udp(
        start + 1.0,
        target,
        5060,
        caller,
        5060,
        sip_response(200, "OK", "INVITE", call_id, 2, branch="z9hG4bKinv2", sdp=sdp_b),
    )
    capture.udp(
        start + 1.01,
        caller,
        5060,
        target,
        5060,
        sip_request("ACK", call_id, 2, to_tag="ttag1", branch="z9hG4bKack2"),
    )
    for i in range(10):
        t = start + 1.1 + i * 0.02
        capture.udp(t, caller, 4000, media, 6000, rtp_packet(i, i * 160))
        capture.udp(t + 0.001, media, 6000, caller, 4000, rtp_packet(i, i * 160, ssrc=0x55667788))
    if dtmf:
        base = 20 * 160
        for i in range(3):
            capture.udp(start + 1.4 + i * 0.02, caller, 4000, media, 6000, telephone_event(20 + i, base, 5, False, 160 * (i + 1)))
        for i in range(3):
            capture.udp(start + 1.46 + i * 0.001, caller, 4000, media, 6000, telephone_event(23 + i, base, 5, True, 640))
        base2 = base + 3200
        capture.udp(start + 1.6, caller, 4000, media, 6000, telephone_event(26, base2, 9, False, 160))
        capture.udp(start + 1.62, caller, 4000, media, 6000, telephone_event(27, base2, 9, True, 640))
    capture.udp(
        start + 3.0,
        caller,
        5060,
        target,
        5060,
        sip_request("BYE", call_id, 3, to_tag="ttag1", branch="z9hG4bKbye"),
    )
    capture.udp(
        start + 3.01,
        target,
        5060,
        caller,
        5060,
        sip_response(200, "OK", "BYE", call_id, 3, branch="z9hG4bKbye"),
    )
