#!/usr/bin/env python3
"""Prove descendants from one successful step are gone before the next."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

json.loads(sys.stdin.readline())
state = Path(sys.argv[1])
if not state.exists():
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    state.write_text(str(child.pid))
    raise SystemExit(0)

pid = int(state.read_text())
try:
    process_state = Path(f"/proc/{pid}/stat").read_text().split()[2]
    running = process_state != "Z"
except FileNotFoundError:
    running = False
raise SystemExit(19 if running else 0)
