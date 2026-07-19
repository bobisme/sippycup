#!/usr/bin/env python3
"""No-network capture/runner/report fixture for integration tests."""

import json
from pathlib import Path
import signal
import struct
import sys
import time


mode = sys.argv[1]

if mode == "capture-delay":
    marker = Path(sys.argv[2])
    marker.write_text(str(__import__("os").getpid()))
    while True:
        time.sleep(0.05)

if mode == "capture-die":
    capture, marker = map(Path, sys.argv[2:4])
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    marker.write_text(str(__import__("os").getpid()))
    time.sleep(0.15)
    raise SystemExit(23)

if mode == "capture-watchdog":
    capture, order, marker = map(Path, sys.argv[2:5])
    capture.write_bytes(
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    )
    marker.write_text(str(__import__("os").getpid()))
    while not order.exists() or "call" not in order.read_text():
        time.sleep(0.01)
    packet = b"\0" * 60
    with capture.open("ab", buffering=0) as output:
        for index in range(200):
            output.write(struct.pack("<IIII", 1, index, len(packet), len(packet)))
            output.write(packet)
            time.sleep(0.001)
    while True:
        time.sleep(0.05)

if mode == "capture":
    capture, order = map(Path, sys.argv[2:4])
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    order.with_suffix(".capture-env").write_bytes(Path("/proc/self/environ").read_bytes())
    order.write_text(order.read_text() + "capture-start\n" if order.exists() else "capture-start\n")

    def stop(_signum, _frame):
        order.write_text(order.read_text() + "capture-stop\n")
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    while True:
        time.sleep(0.05)

if mode == "runner":
    order = Path(sys.argv[2])
    order.with_suffix(".argv").write_bytes(Path("/proc/self/cmdline").read_bytes())
    order.with_suffix(".runner-env").write_bytes(Path("/proc/self/environ").read_bytes())
    envelope = json.loads(sys.stdin.readline())
    order.write_text(order.read_text() + "call\n")
    for value in envelope["credentials"].values():
        print(value)
        print(value, file=sys.stderr)
    raise SystemExit(0)

if mode == "runner-sleep":
    order = Path(sys.argv[2])
    marker = Path(sys.argv[3])
    json.loads(sys.stdin.readline())
    order.write_text("call\n")
    marker.write_text(str(__import__("os").getpid()))
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(0.05)

if mode == "report":
    print("fixture report: capture parsed")
    raise SystemExit(0)

if mode == "report-env":
    Path(sys.argv[2]).write_bytes(Path("/proc/self/environ").read_bytes())
    print("fixture report")
    raise SystemExit(0)

if mode == "report-delay":
    marker = Path(sys.argv[2])
    marker.write_text(str(__import__("os").getpid()))
    while True:
        time.sleep(0.05)

raise SystemExit(2)
