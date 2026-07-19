"""Strict, deadline-bound UDP RTP echo fixture."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import select
import socket
import struct
import sys
import time
from typing import Callable, Sequence


def _bounded_int(value: str, minimum: int, maximum: int) -> int:
    try:
        result = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if result < minimum or result > maximum:
        raise argparse.ArgumentTypeError(
            f"must be between {minimum} and {maximum}"
        )
    return result


def run_echo(
    bind_address: str,
    ports: Sequence[int],
    *,
    max_packets: int,
    deadline_ms: int,
    telephone_event_payloads: frozenset[int],
    on_ready: Callable[[], None] | None = None,
) -> dict[str, object]:
    address = ipaddress.ip_address(bind_address)
    if address.is_unspecified or address.is_multicast:
        raise ValueError("echo bind address must be a specific unicast literal")
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    listeners: list[socket.socket] = []
    packets: list[dict[str, object]] = []
    try:
        for port in ports:
            listener = socket.socket(family, socket.SOCK_DGRAM)
            listener.bind((str(address), port))
            listener.setblocking(False)
            listeners.append(listener)
        if on_ready is not None:
            on_ready()
        deadline = time.monotonic() + deadline_ms / 1000
        while len(packets) < max_packets:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            readable, _, _ = select.select(listeners, (), (), remaining)
            if not readable:
                break
            for listener in readable:
                datagram, peer = listener.recvfrom(2048)
                if len(datagram) < 12 or datagram[0] >> 6 != 2:
                    continue
                _, second, sequence, timestamp, ssrc = struct.unpack(
                    "!BBHII", datagram[:12]
                )
                payload_type = second & 0x7F
                kind = (
                    "telephone-event"
                    if payload_type in telephone_event_payloads
                    else "audio"
                )
                record: dict[str, object] = {
                    "sequence": sequence,
                    "timestamp": timestamp,
                    "ssrc": ssrc,
                    "payloadType": payload_type,
                    "marker": bool(second & 0x80),
                    "kind": kind,
                    "bytes": len(datagram),
                }
                if kind == "telephone-event" and len(datagram) == 16:
                    event, flags, duration = struct.unpack("!BBH", datagram[12:])
                    record.update(
                        {
                            "event": event,
                            "end": bool(flags & 0x80),
                            "volume": flags & 0x3F,
                            "duration": duration,
                        }
                    )
                packets.append(record)
                listener.sendto(datagram, peer)
                if len(packets) >= max_packets:
                    break
    finally:
        for listener in listeners:
            listener.close()
    return {
        "apiVersion": "sippycup.media-echo-result/v1",
        "status": "passed" if len(packets) == max_packets else "incomplete",
        "expectedPackets": max_packets,
        "receivedPackets": len(packets),
        "audioPackets": sum(item["kind"] == "audio" for item in packets),
        "telephoneEventPackets": sum(
            item["kind"] == "telephone-event" for item in packets
        ),
        "packets": packets,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sippycup-media-echo")
    parser.add_argument("--bind", required=True)
    parser.add_argument(
        "--port",
        action="append",
        required=True,
        type=lambda value: _bounded_int(value, 1024, 65535),
    )
    parser.add_argument(
        "--max-packets",
        required=True,
        type=lambda value: _bounded_int(value, 1, 200),
    )
    parser.add_argument(
        "--deadline-ms",
        required=True,
        type=lambda value: _bounded_int(value, 100, 10000),
    )
    parser.add_argument(
        "--telephone-event-pt",
        action="append",
        default=[],
        type=lambda value: _bounded_int(value, 96, 127),
    )
    parser.add_argument(
        "--ready-fd",
        type=lambda value: _bounded_int(value, 3, 65535),
        help=argparse.SUPPRESS,
    )
    arguments = parser.parse_args(argv)
    if len(arguments.port) > 8 or len(set(arguments.port)) != len(arguments.port):
        parser.error("--port must contain between one and eight unique ports")
    if (
        len(arguments.telephone_event_pt) > 8
        or len(set(arguments.telephone_event_pt))
        != len(arguments.telephone_event_pt)
    ):
        parser.error(
            "--telephone-event-pt accepts at most eight unique values"
        )
    try:
        def signal_ready() -> None:
            if arguments.ready_fd is not None:
                os.write(arguments.ready_fd, b"1")
                os.close(arguments.ready_fd)

        report = run_echo(
            arguments.bind,
            arguments.port,
            max_packets=arguments.max_packets,
            deadline_ms=arguments.deadline_ms,
            telephone_event_payloads=frozenset(arguments.telephone_event_pt),
            on_ready=signal_ready,
        )
    except (OSError, ValueError) as error:
        print(f"echo fixture error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
