import json
from pathlib import Path
import subprocess
import sys
import tempfile
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

    def test_exit_gate_and_owner_review_are_separate_offline_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gate_path = root / "gate.json"
            review_path = root / "review.json"
            gate = self.run_cli("exit-gate", "--output", str(gate_path))
            self.assertEqual(0, gate.returncode, gate.stderr)
            gate_value = json.loads(gate_path.read_text(encoding="utf-8"))
            self.assertEqual("pass", gate_value["status"])
            self.assertFalse(gate_value["networkActivity"])

            template = self.run_cli(
                "review-template",
                "--reviewer",
                "Quad",
                "--output",
                str(review_path),
            )
            self.assertEqual(0, template.returncode, template.stderr)
            pending = self.run_cli("validate-review", str(review_path))
            self.assertEqual(1, pending.returncode, pending.stderr)
            self.assertFalse(json.loads(pending.stdout)["ready"])

            review = json.loads(review_path.read_text(encoding="utf-8"))
            review.update(
                {
                    "reviewStatus": "approved",
                    "reviewId": "quad-defaults-review-1",
                    "reviewedAt": "2026-07-19T20:00:00Z",
                }
            )
            review_path.write_text(json.dumps(review), encoding="utf-8")
            approved = self.run_cli("validate-review", str(review_path))
            self.assertEqual(0, approved.returncode, approved.stderr)
            result = json.loads(approved.stdout)
            self.assertTrue(result["ready"])
            self.assertFalse(result["authorizationGranted"])

    def test_review_validation_rejects_current_code_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            review_path = Path(temporary) / "review.json"
            template = self.run_cli(
                "review-template", "--output", str(review_path)
            )
            self.assertEqual(0, template.returncode, template.stderr)
            review = json.loads(review_path.read_text(encoding="utf-8"))
            review.update(
                {
                    "reviewStatus": "approved",
                    "reviewId": "review-1",
                    "reviewedAt": "2026-07-19T20:00:00Z",
                    "technicalGateSha256": "0" * 64,
                }
            )
            review_path.write_text(json.dumps(review), encoding="utf-8")
            result = self.run_cli("validate-review", str(review_path))
            self.assertEqual(1, result.returncode)
            self.assertIn("does not match", result.stdout)


if __name__ == "__main__":
    unittest.main()
