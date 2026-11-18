"""Live dress rehearsal gate, run by `make dress-rehearsal-gate`.

It runs the public `./bin/sippycup practice-target rehearsal` (the whole
owner-facing chain against the practice target, about 2 minutes) and needs
the core toolbox image and the practice image. It runs only when explicitly
enabled with SIPPYCUP_DRESS_REHEARSAL_GATE=1 and skips when an image is absent
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
    def test_dress_rehearsal(self) -> None:
        if os.environ.get("SIPPYCUP_DRESS_REHEARSAL_GATE") != "1":
            self.skipTest("set SIPPYCUP_DRESS_REHEARSAL_GATE=1 (make dress-rehearsal-gate) to run")
        available, reason = practice_gate.images_available()
        if not available:
            if os.environ.get("SIPPYCUP_PRACTICE_GATE_REQUIRE_IMAGES") == "1":
                self.fail(f"{reason}; run make build and make practice-build")
            self.skipTest(reason)
        before = self._target_up()
        result = subprocess.run(
            [str(ROOT / "bin" / "sippycup"), "practice-target", "rehearsal"], cwd=ROOT, text=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900, check=False,
        )
        print(result.stdout)
        self.assertEqual(0, result.returncode, result.stdout[-3000:])
        self.assertIn("Dress rehearsal: PASS", result.stdout)
        self.assertNotIn("[FAIL]", result.stdout)
        evidence = next(line.split()[1] for line in result.stdout.splitlines() if line.startswith("Evidence: "))
        summary = json.loads((ROOT / evidence / "rehearsal" / "summary.json").read_text(encoding="utf-8"))
        self.assertTrue(summary["ok"])
        self.assertEqual(11, len(summary["stages"]))
        report = json.loads((ROOT / evidence / "report" / "report.json").read_text(encoding="utf-8"))
        self.assertEqual([], report["integrityExceptions"])
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
