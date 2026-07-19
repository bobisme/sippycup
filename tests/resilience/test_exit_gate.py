import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_resilience.isolation import (
    analyze_isolation,
    clean_observations,
    plan_isolation,
)
from sippycup_resilience.lifecycle import analyze_lifecycle, synthetic_snapshots
from sippycup_resilience.migration import analyze_migration, default_policy
from sippycup_resilience.overload import analyze_overload, synthetic_transactions
from sippycup_resilience.secure_media import (
    analyze_secure_media,
    clean_observation,
    default_policy as secure_policy,
)

CLI = ROOT / "bin" / "sippycup-resilience"
LAUNCHER = ROOT / "bin" / "sippycup"


class ResilienceExitGate(unittest.TestCase):
    def run_cli(self, *arguments):
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT / "lib")
        return subprocess.run(
            [str(CLI), *arguments],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )

    def test_every_demo_is_network_free_and_passes(self):
        commands = (
            ("isolation", "demo", "--calls", "64"),
            ("overload", "demo"),
            ("secure-media", "demo", "--profile", "sip-tls"),
            ("secure-media", "demo", "--profile", "srtp"),
            ("secure-media", "demo", "--profile", "dtls-srtp"),
            ("migration", "demo", "--mode", "strict"),
            ("migration", "demo", "--mode", "symmetric-rtp"),
            ("migration", "demo", "--mode", "ice"),
        )
        for command in commands:
            with self.subTest(command=command):
                result = self.run_cli(*command)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["status"], "pass")

    def test_top_level_launcher_dispatches_without_podman(self):
        result = subprocess.run(
            [str(LAUNCHER), "resilience", "isolation", "demo", "--calls", "8"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["plannedCalls"], 8)

    def test_exclusive_output_and_hard_cli_bounds(self):
        with tempfile.TemporaryDirectory() as temporary_name:
            output = Path(temporary_name) / "report.json"
            result = self.run_cli(
                "isolation", "plan", "--calls", "2", "--output", str(output)
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            result = self.run_cli(
                "isolation", "plan", "--calls", "2", "--output", str(output)
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("refusing to overwrite", result.stderr)
            plan = Path(temporary_name) / "render-plan.json"
            plan.write_text(json.dumps(plan_isolation(2)))
            pcm = Path(temporary_name) / "watermark.s16le"
            result = self.run_cli(
                "isolation",
                "render",
                str(plan),
                "call-000001",
                "--output",
                str(pcm),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            result = self.run_cli("isolation", "decode", str(pcm))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                json.loads(result.stdout)["marker"],
                plan_isolation(2)["calls"][0]["marker"],
            )
        for command in (
            ("isolation", "plan", "--calls", "4097"),
            ("lifecycle", "simulate", "--cycles", "100001"),
        ):
            result = self.run_cli(*command)
            self.assertEqual(result.returncode, 2)

    def test_seeded_scale_fixtures_are_bounded_and_make_no_scale_claim(self):
        started = time.monotonic()
        plan = plan_isolation(4096, "exit-gate")
        isolation = analyze_isolation(plan, clean_observations(plan))
        lifecycle = analyze_lifecycle(synthetic_snapshots(100_000))
        self.assertLess(time.monotonic() - started, 5.0)
        self.assertEqual((isolation["status"], lifecycle["status"]), ("pass", "pass"))
        self.assertIsNone(isolation["capacityClaim"])
        self.assertIsNone(lifecycle["scaleClaim"])

    def test_seeded_adversarial_failures_stay_separate(self):
        overload = synthetic_transactions()
        overload[0]["response"] = 503
        overload[0]["retryAfterMs"] = 1000
        overload.append(
            {
                **overload[0],
                "atMs": 1,
                "attempt": 2,
                "response": 200,
                "retryAfterMs": None,
            }
        )
        overload.sort(key=lambda item: item["atMs"])
        self.assertIn(
            "retry_before_retry_after",
            {item["code"] for item in analyze_overload(overload)["findings"]},
        )

        policy = secure_policy("srtp")
        observation = clean_observation("srtp")
        observation["replayAccepted"] = True
        self.assertEqual(
            {item["code"] for item in analyze_secure_media(policy, observation)["findings"]},
            {"replay_accepted"},
        )

        migration_policy = default_policy("symmetric-rtp")
        forged = {
            "source": {"address": "192.0.2.99", "port": 30000},
            "ssrc": migration_policy["ssrc"],
            "authenticated": False,
            "consentFresh": True,
            "afterTeardown": False,
        }
        self.assertEqual(
            {item["code"] for item in analyze_migration(migration_policy, [forged])["findings"]},
            {"packet_authentication_failed"},
        )

    def test_schema_docs_makefile_and_container_are_integrated(self):
        schema = json.loads(
            (ROOT / "schemas" / "resilience-report-v1.schema.json").read_text()
        )
        versions = json.dumps(schema, sort_keys=True)
        for version in (
            "isolation-report/v1",
            "lifecycle-report/v1",
            "overload-report/v1",
            "secure-media-report/v1",
            "migration-report/v1",
        ):
            self.assertIn(version, versions)
        self.assertIn("resilience-test:", (ROOT / "Makefile").read_text())
        self.assertIn(
            "sippycup_resilience", (ROOT / "Containerfile").read_text()
        )
        documentation = (ROOT / "docs" / "RESILIENCE-GATES.md").read_text()
        self.assertIn("network-free", documentation)
        self.assertIn("not authorization", documentation)


if __name__ == "__main__":
    unittest.main()
