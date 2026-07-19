#!/usr/bin/env python3
"""Runner that never consumes stdin and ignores graceful termination."""

import signal
import time

signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(60)
