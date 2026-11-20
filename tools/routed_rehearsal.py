#!/usr/bin/env python3
"""Routed rehearsal gate: the owner-facing chain across the toolbox's real network path.

The practice target on a rootless internal network, reached from the
toolbox's own private network namespace through NAT, with every command as
FIRST-ENGAGEMENT.md gives it for a real target. Nothing leaves this host.
See lib/sippycup/routed_rehearsal.py and docs/PRACTICE-TARGET.md.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from sippycup.routed_rehearsal import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
