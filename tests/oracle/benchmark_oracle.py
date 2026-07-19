#!/usr/bin/env python3
"""Repeatable packet-oracle performance gate."""

from __future__ import annotations

import json
import sys
import time
import tracemalloc
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT))

from sippycup_oracle.media import MediaExpectations, evaluate_invariants
from tests.oracle.test_media import baseline_dialog, rtp_frame

PACKETS = 20_000
MAX_SECONDS = 8.0
MAX_PEAK_BYTES = 128 * 1024 * 1024


def main() -> int:
    frames = tuple(
        rtp_frame(
            1000 + index,
            str(Decimal("0.32") + Decimal(index) * Decimal("0.02")),
            caller_to_callee=True,
            sequence=index % 65536,
            timestamp=(index * 160) % (2**32),
        )
        for index in range(PACKETS)
    )
    tracemalloc.start()
    started = time.monotonic()
    analysis = evaluate_invariants(
        frames,
        baseline_dialog(),
        MediaExpectations(require_bidirectional=False),
    )
    elapsed = time.monotonic() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    passed = bool(analysis.streams) and elapsed < MAX_SECONDS and peak < MAX_PEAK_BYTES
    print(
        json.dumps(
            {
                "packets": PACKETS,
                "elapsed_seconds": round(elapsed, 6),
                "peak_bytes": peak,
                "limits": {
                    "elapsed_seconds": MAX_SECONDS,
                    "peak_bytes": MAX_PEAK_BYTES,
                },
                "passed": passed,
            },
            sort_keys=True,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
