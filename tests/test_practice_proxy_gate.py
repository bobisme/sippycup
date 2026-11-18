"""Live practice proxy gate, run by `make practice-proxy-gate` (bn-2g0).

Like the practice gate it needs the core image and a practice image that
contains the Kamailio proxy, starts real containers, and runs only when
SIPPYCUP_PRACTICE_PROXY_GATE=1; it skips when an image is absent unless
SIPPYCUP_PRACTICE_GATE_REQUIRE_IMAGES=1.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import practice_proxy_gate  # noqa: E402


class PracticeProxyGateTests(unittest.TestCase):
    def test_practice_proxy_gate(self) -> None:
        if os.environ.get("SIPPYCUP_PRACTICE_PROXY_GATE") != "1":
            self.skipTest("set SIPPYCUP_PRACTICE_PROXY_GATE=1 (make practice-proxy-gate) to run")
        available, reason = practice_proxy_gate.practice_gate.images_available()
        if not available:
            if os.environ.get("SIPPYCUP_PRACTICE_GATE_REQUIRE_IMAGES") == "1":
                self.fail(f"{reason}; run make build and make practice-build")
            self.skipTest(reason)
        summary = practice_proxy_gate.ProxyGate().execute()
        failed = [item for item in summary["checks"] if not item["ok"]]
        self.assertTrue(summary["ok"], failed or "no checks ran")
        self.assertGreaterEqual(len(summary["checks"]), 35)


if __name__ == "__main__":
    unittest.main()
