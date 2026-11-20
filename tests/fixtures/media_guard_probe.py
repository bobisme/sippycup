#!/usr/bin/env python3
"""Exercise the compiled media guard on loopback (bn-3l8o).

    media_guard_probe.py LIBRARY            listen, run the sender, print JSON
    media_guard_probe.py --send JSON        the sender (runs with the guard preloaded)

The listener process binds UDP sockets on 127.0.0.2 ("approved") and
127.0.0.9 ("unapproved"), starts this file again as the sender with
LD_PRELOAD=LIBRARY and rules that approve 127.0.0.2 and one RTP port, and
reports which datagrams arrived. Loopback only; nothing leaves the host.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys

RTP = bytes([0x80, 0x00]) + bytes(170)
RTP_MARKER = bytes([0x80, 0x80]) + bytes(170)
RTCP_RR = bytes([0x81, 201]) + bytes(58)
RTCP_SR = bytes([0x80, 200]) + bytes(80)
STUN = bytes([0x00, 0x01]) + bytes(18)
SIP = b"OPTIONS sip:probe SIP/2.0\r\n\r\n"
KEEPALIVE = b"\r\n\r\n"
PAYLOADS = {"rtp": RTP, "rtp-marker": RTP_MARKER, "rtcp-rr": RTCP_RR, "rtcp-sr": RTCP_SR,
            "stun": STUN, "sip": SIP, "keepalive": KEEPALIVE}
# (label, listener, payload, how)
CASES = (
    ("rtp to approved address and port", "ok-rtp", "rtp", "sendto"),
    ("rtp with marker to approved address and port", "ok-rtp", "rtp-marker", "sendto"),
    ("rtcp to approved address, any port", "ok-other", "rtcp-rr", "sendto"),
    ("rtp to approved address, port outside the range", "ok-other", "rtp", "sendto"),
    ("rtp to unapproved address", "bad-rtp", "rtp", "sendto"),
    ("rtcp receiver report to unapproved address", "bad-rtp", "rtcp-rr", "sendto"),
    ("rtcp sender report to unapproved address", "bad-rtp", "rtcp-sr", "sendto"),
    ("other binary datagram to unapproved address", "bad-rtp", "stun", "sendto"),
    ("rtp to unapproved address on a connected socket", "bad-rtp", "rtp", "send"),
    ("rtp to approved address on a connected socket", "ok-rtp", "rtp", "send"),
    ("rtp to unapproved address, IPv4-mapped", "bad-rtp", "rtp", "mapped"),
    ("rtp to approved address, IPv4-mapped", "ok-rtp", "rtp", "mapped"),
    ("sip to unapproved address (signaling is not judged)", "bad-rtp", "sip", "sendto"),
    ("keep-alive to unapproved address (signaling is not judged)", "bad-rtp", "keepalive", "sendto"),
)


def sender(listeners: dict[str, list]) -> int:
    plain = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for index, (_label, listener, payload, how) in enumerate(CASES):
        where = tuple(listeners[listener])
        data = PAYLOADS[payload] + bytes([index])
        if how == "sendto":
            sent = plain.sendto(data, where)
        elif how == "send":
            connected = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            connected.connect(where)
            sent = connected.send(data)
            connected.close()
        else:
            six = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            six.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sent = six.sendto(data, ("::ffff:" + where[0], where[1]))
            six.close()
        if sent != len(data):  # a dropped datagram is still answered as sent
            return 3
    # A TCP stream whose bytes look like RTP is never judged.
    stream = socket.create_connection(tuple(listeners["tcp"]))
    stream.send(RTP)
    stream.close()
    return 0


def main() -> int:
    if sys.argv[1] == "--send":
        return sender(json.loads(sys.argv[2]))
    library = sys.argv[1]
    rules = sys.argv[2] if len(sys.argv) > 2 else None
    sockets: dict[str, socket.socket] = {}
    for name, address in (("ok-rtp", "127.0.0.2"), ("ok-other", "127.0.0.2"), ("bad-rtp", "127.0.0.9")):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((address, 0))
        sock.settimeout(0.3)
        sockets[name] = sock
    tcp = socket.socket()
    tcp.bind(("127.0.0.9", 0))
    tcp.listen(1)
    tcp.settimeout(2.0)
    listeners = {name: list(sock.getsockname()) for name, sock in sockets.items()}
    listeners["tcp"] = list(tcp.getsockname())
    port = listeners["ok-rtp"][1]
    environment = dict(os.environ, LD_PRELOAD=library)
    if rules != "none":
        environment["SIPPYCUP_MEDIA_GUARD_RULES"] = rules or f"v1;addr=127.0.0.2/32;ports={port}-{port}"
    completed = subprocess.run(
        [sys.executable, "-I", __file__, "--send", json.dumps(listeners)],
        env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
    )
    arrived: set[int] = set()
    for sock in sockets.values():
        while True:
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                break
            arrived.add(data[-1])
    peer, _ = tcp.accept()
    peer.settimeout(2.0)
    stream = peer.recv(4096)
    print(json.dumps({
        "exit": completed.returncode,
        "stderr": completed.stderr.decode("utf-8", "replace").splitlines(),
        "arrived": {label: index in arrived for index, (label, *_rest) in enumerate(CASES)},
        "tcp": stream == RTP,
        "port": port,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
