from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup.campaign import _write_plan_atomic, compile_plan
from sippycup.integration import execute_campaign


FIXTURES = ROOT / "tests" / "fixtures" / "campaign"
TOOL = FIXTURES / "integration-tool.py"


def manifest_for_port(port: int) -> dict:
    manifest = yaml.safe_load((FIXTURES / "valid.yaml").read_bytes())
    manifest["authorization"]["networks"] = ["127.0.0.0/8"]
    manifest["authorization"]["signalingPorts"] = [port]
    manifest["authorization"]["credentialRefs"] = []
    manifest["targets"][0]["address"] = "127.0.0.1"
    manifest["targets"][0]["signaling"]["port"] = port
    manifest["targets"][0].pop("credentialRef")
    return manifest


class CampaignExitGateTests(unittest.TestCase):
    def test_malformed_and_over_budget_manifests_emit_zero_packets(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sentinel:
            sentinel.bind(("127.0.0.1", 0))
            sentinel.settimeout(0.1)
            port = sentinel.getsockname()[1]
            malformed = manifest_for_port(port)
            malformed["authorization"].pop("stopConditions")
            over_budget = manifest_for_port(port)
            over_budget["authorization"]["ceilings"]["packets"] = 1
            for name, manifest in (
                ("malformed", malformed),
                ("over-budget", over_budget),
            ):
                with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                    manifest_path = Path(directory) / "campaign.yaml"
                    plan_path = Path(directory) / "plan.json"
                    manifest_path.write_text(yaml.safe_dump(manifest))
                    result = subprocess.run(
                        [
                            str(ROOT / "bin" / "campaign"),
                            "plan",
                            str(manifest_path),
                            "--output",
                            str(plan_path),
                            "--error-format",
                            "json",
                        ],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 2)
                    error = json.loads(result.stderr)
                    self.assertTrue(error["message"])
                    self.assertFalse(plan_path.exists())
                    with self.assertRaises(socket.timeout):
                        sentinel.recvfrom(1)

    def test_frozen_dns_is_used_without_runtime_resolution(self):
        raw = (FIXTURES / "valid.yaml").read_bytes()
        manifest = yaml.safe_load(raw)
        answers = ["10.20.30.40"]
        resolver_calls = []

        def resolver(host):
            resolver_calls.append(host)
            return list(answers)

        plan = compile_plan(manifest, hashlib.sha256(raw).hexdigest(), resolver=resolver)
        answers[:] = ["10.20.30.99"]
        seen = []
        with tempfile.TemporaryDirectory() as directory, mock.patch(
            "socket.getaddrinfo", side_effect=AssertionError("runtime DNS lookup")
        ):
            root = Path(directory)
            order = root / "order.txt"
            result, _run_dir = execute_campaign(
                plan,
                manifest_bytes=raw,
                run_root=root / "runs",
                capture_command=[
                    sys.executable,
                    str(TOOL),
                    "capture",
                    "{capture}",
                    str(order),
                ],
                runner=[sys.executable, str(TOOL), "runner", str(order)],
                report_command=[sys.executable, str(TOOL), "report"],
                preflight=lambda destination: (
                    seen.append(destination["address"]) is None,
                    "SIP/2.0 200 OK",
                ),
                secret_values={"staging-user": "exit-gate-secret"},
                allow_test_runner=True,
            )
        self.assertEqual(result.state, "succeeded")
        self.assertEqual(resolver_calls, ["voice.test"])
        self.assertEqual(seen, ["10.20.30.40"])

    def test_ctrl_c_during_atomic_plan_commit_leaves_no_partial_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "plan.json"
            with mock.patch("os.link", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    _write_plan_atomic(output, {"safe": True})
            self.assertFalse(output.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_json_source_lock_error_is_actionable_and_side_effect_free(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = manifest_for_port(5099)
            reviewed = root / "reviewed.yaml"
            reviewed.write_text(yaml.safe_dump(manifest, sort_keys=True))
            plan = root / "plan.json"
            planned = subprocess.run(
                [
                    str(ROOT / "bin" / "campaign"),
                    "plan",
                    str(reviewed),
                    "--output",
                    str(plan),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(planned.returncode, 0, planned.stderr)
            manifest["metadata"]["name"] = "changed-after-review"
            changed = root / "changed.yaml"
            changed.write_text(yaml.safe_dump(manifest, sort_keys=True))
            run_root = root / "runs"
            result = subprocess.run(
                [
                    str(ROOT / "bin" / "campaign"),
                    "run",
                    str(plan),
                    "--manifest",
                    str(changed),
                    "--run-root",
                    str(run_root),
                    "--error-format",
                    "json",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            error = json.loads(result.stderr)
            self.assertEqual(error["code"], "invalid_plan_or_runtime")
            self.assertIn("SHA-256", error["message"])
            self.assertFalse(run_root.exists())

    def test_operator_documentation_covers_the_exit_gate(self):
        documentation = (ROOT / "docs" / "CAMPAIGN-MANIFEST.md").read_text().lower()
        for phrase in (
            "authorization",
            "side-effect-free",
            "secret",
            "sigint",
            "emergency",
            "--output",
            "--error-format",
        ):
            self.assertIn(phrase, documentation)
        completion = (ROOT / "completions" / "campaign.bash").read_text()
        self.assertIn("plan run execute", completion)
        self.assertIn("--secret-fd", completion)


if __name__ == "__main__":
    unittest.main()
