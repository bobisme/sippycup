"""Live softphone gate, run by `make softphone-gate`.

Like the practice gate it needs the core image and the practice image, starts
real containers, and runs only when SIPPYCUP_SOFTPHONE_GATE=1; it skips when
an image is absent unless SIPPYCUP_PRACTICE_GATE_REQUIRE_IMAGES=1.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import softphone_gate  # noqa: E402


class SoftphoneGateTests(unittest.TestCase):
    def test_softphone_gate(self) -> None:
        if os.environ.get("SIPPYCUP_SOFTPHONE_GATE") != "1":
            self.skipTest("set SIPPYCUP_SOFTPHONE_GATE=1 (make softphone-gate) to run")
        available, reason = softphone_gate.practice_gate.images_available()
        if not available:
            if os.environ.get("SIPPYCUP_PRACTICE_GATE_REQUIRE_IMAGES") == "1":
                self.fail(f"{reason}; run make build and make practice-build")
            self.skipTest(reason)
        summary = softphone_gate.SoftphoneGate().execute()
        failed = [item for item in summary["checks"] if not item["ok"]]
        self.assertTrue(summary["ok"], failed or "no checks ran")
        self.assertGreaterEqual(len(summary["checks"]), 15)


if __name__ == "__main__":
    unittest.main()
