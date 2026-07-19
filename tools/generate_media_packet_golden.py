#!/usr/bin/env python3
"""Regenerate the deterministic packet-level canary expectation."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_media.rtp import (  # noqa: E402
    build_packet_plan,
    load_session,
    packet_plan_document,
)


def main() -> int:
    session = load_session(
        ROOT / "tests/fixtures/media/session-transition.json",
        ROOT / "media/canary-v1",
    )
    output = ROOT / "tests/fixtures/media/packet-plan-v1.json"
    output.write_text(
        json.dumps(
            packet_plan_document(build_packet_plan(session)),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
