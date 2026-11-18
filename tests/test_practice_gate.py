"""Live practice-target gate, run by `make practice-gate`.

It needs the core toolbox image and the optional practice image, starts real
containers, and takes a few minutes, so it runs only when explicitly enabled
with SIPPYCUP_PRACTICE_GATE=1 and skips when either image is absent (unless
SIPPYCUP_PRACTICE_GATE_REQUIRE_IMAGES=1, which `make practice-gate` sets so a
missing image cannot pass the gate silently).
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import practice_gate  # noqa: E402


class PracticeGateTests(unittest.TestCase):
    def test_practice_gate(self) -> None:
        if os.environ.get("SIPPYCUP_PRACTICE_GATE") != "1":
            self.skipTest("set SIPPYCUP_PRACTICE_GATE=1 (make practice-gate) to run")
        available, reason = practice_gate.images_available()
        if not available:
            if os.environ.get("SIPPYCUP_PRACTICE_GATE_REQUIRE_IMAGES") == "1":
                self.fail(f"{reason}; run make build and make practice-build")
            self.skipTest(reason)
        summary = practice_gate.Gate().execute()
        failed = [item for item in summary["checks"] if not item["ok"]]
        self.assertTrue(summary["ok"], failed or "no checks ran")
        self.assertGreaterEqual(len(summary["checks"]), 30)


if __name__ == "__main__":
    unittest.main()
