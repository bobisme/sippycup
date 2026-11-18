"""Live dress rehearsal gate, run by `make dress-rehearsal-gate`.

It runs the public `./bin/sippycup practice-target rehearsal` (the whole
owner-facing chain against the practice target, about 90 s) and, with
SIPPYCUP_DRESS_REHEARSAL_GATE=proxy or =all, `rehearsal --proxy`, and needs
the core toolbox image and the practice image. It runs only when explicitly
enabled with SIPPYCUP_DRESS_REHEARSAL_GATE (1, proxy, or all) and skips when an image is absent
(unless SIPPYCUP_PRACTICE_GATE_REQUIRE_IMAGES=1, which the make target sets).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import practice_gate  # noqa: E402


class DressRehearsalGateTests(unittest.TestCase):
    """SIPPYCUP_DRESS_REHEARSAL_GATE=1 runs the direct variant, =proxy the proxy shape, =all both."""

    def test_dress_rehearsal(self) -> None:
        self._gate("direct", [])

    def test_dress_rehearsal_proxy(self) -> None:
        self._gate("proxy", ["--proxy"])

    def _gate(self, variant: str, extra: list[str]) -> None:
        wanted = os.environ.get("SIPPYCUP_DRESS_REHEARSAL_GATE")
        if wanted not in {"1" if variant == "direct" else variant, "all"}:
            self.skipTest("set SIPPYCUP_DRESS_REHEARSAL_GATE=1, =proxy, or =all "
                          "(make dress-rehearsal-gate, make dress-rehearsal-proxy-gate) to run")
        available, reason = practice_gate.images_available()
        if not available:
            if os.environ.get("SIPPYCUP_PRACTICE_GATE_REQUIRE_IMAGES") == "1":
                self.fail(f"{reason}; run make build and make practice-build")
            self.skipTest(reason)
        before = self._target_up()
        result = subprocess.run(
            [str(ROOT / "bin" / "sippycup"), "practice-target", "rehearsal", *extra], cwd=ROOT, text=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900, check=False,
        )
        print(result.stdout)
        self.assertEqual(0, result.returncode, result.stdout[-3000:])
        self.assertRegex(result.stdout, r"Dress rehearsal( \(proxy shape\))?: PASS in [0-9.]+ s")
        self.assertNotIn("[FAIL]", result.stdout)
        evidence = next(line.split()[1] for line in result.stdout.splitlines() if line.startswith("Evidence: "))
        summary = json.loads((ROOT / evidence / "rehearsal" / "summary.json").read_text(encoding="utf-8"))
        self.assertTrue(summary["ok"])
        self.assertEqual(variant, summary["shape"])
        self.assertEqual(12, len(summary["stages"]))
        report = json.loads((ROOT / evidence / "report" / "report.json").read_text(encoding="utf-8"))
        self.assertEqual([], report["integrityExceptions"])
        # The practice target accepts plain RTP, so srtp-policy reports it.
        self.assertIn("srtp-policy.plain-rtp-accepted", [item["id"] for item in report["findings"]])
        # The stop leg's own report discloses the packets sent before the stop.
        stop = json.loads((ROOT / summary["stopEngagement"] / "report" / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(["media-peer-not-approved"], [item["code"] for item in stop["integrityExceptions"]])
        self.assertEqual(["media-outside-scope"], [run.get("verdict") for run in stop["runs"]])
        # The practice target is left the way it was found.
        self.assertEqual(before, self._target_up())

    @staticmethod
    def _target_up() -> bool:
        status = subprocess.run(
            [str(ROOT / "bin" / "sippycup"), "practice-target", "status"], cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        return "Target: up" in status.stdout


if __name__ == "__main__":
    unittest.main()
