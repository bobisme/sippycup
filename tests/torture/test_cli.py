import json
from pathlib import Path
import subprocess
import sys
import unittest

from sippycup_torture import build_corpus


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "bin" / "sippycup-torture"


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(CLI), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=5,
        )

    def test_corpus_manifest_is_available_offline(self):
        result = self.run_cli("corpus")
        self.assertEqual(0, result.returncode, result.stderr)
        manifest = json.loads(result.stdout)
        self.assertTrue(manifest["safety"]["offlineOnly"])

    def test_plan_lists_exact_case_and_default_maximum(self):
        case = build_corpus()[0]
        result = self.run_cli("plan", "--case", case.id)
        self.assertEqual(0, result.returncode, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(case.sha256, plan["cases"][0]["sha256"])
        self.assertEqual(1, plan["maximumTraffic"]["cases"])
        self.assertEqual(1, plan["maximumTraffic"]["concurrency"])

    def test_unknown_case_and_unsafe_caps_fail_with_stable_exit(self):
        unknown = self.run_cli("plan", "--case", "not-a-case")
        self.assertEqual(2, unknown.returncode)
        self.assertIn("unknown case", unknown.stderr)
        unsafe = self.run_cli(
            "plan",
            "--case",
            build_corpus()[0].id,
            "--max-concurrency",
            "2",
        )
        self.assertEqual(2, unsafe.returncode)
        self.assertIn("hard safety cap", unsafe.stderr)


if __name__ == "__main__":
    unittest.main()
