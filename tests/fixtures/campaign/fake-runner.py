#!/usr/bin/env python3
"""Loopback-only runner used to exercise campaign supervision."""

import json
import os
import signal
import subprocess
import sys
import time


step = json.loads(sys.stdin.readline())
mode = step["case"].rsplit("-", 1)[0]

if mode == "crash":
    print("intentional crash", file=sys.stderr)
    raise SystemExit(17)
if mode == "output":
    sys.stdout.write("x" * 200_000)
    sys.stderr.write("y" * 200_000)
    raise SystemExit(0)
if mode == "sensitive":
    print("Authorization: Digest username=alice,response=deadbeef")
    print("fixture-super-secret")
    raise SystemExit(0)
if mode == "leader-first":
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=False,
    )
    print(child.pid, flush=True)
    raise SystemExit(0)
if mode == "spawn":
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        start_new_session=False,
    )
    print(child.pid, flush=True)


def stop(_signum, _frame):
    raise SystemExit(0)


if mode in {"sleep", "spawn"}:
    signal.signal(signal.SIGTERM, stop)
    while True:
        time.sleep(0.05)

print(f"completed step {step['index']}")
