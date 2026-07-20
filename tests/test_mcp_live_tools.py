from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import yaml

from sippycup.campaign import compile_plan, load_manifest
from sippycup_mcp.capability import (
    CapabilityValidator,
    OpenSSLEd25519Verifier,
    ReplayAuditStore,
)
from sippycup_mcp.live_tools import LivePreparationTools
from sippycup_mcp.live_server import _trust_keys
from sippycup_mcp.security import MCPPolicyError
from sippycup_workbench.profile import default_profile

from tests.test_mcp_capability import CapabilityFixture, NOW

ROOT = Path(__file__).parents[1]


class LivePreparationToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.inputs = self.root / "inputs"
        self.snapshots = self.root / "snapshots"
        self.state = self.root / "state"
        for directory in (self.inputs, self.snapshots, self.state):
            directory.mkdir(mode=0o700)
        source = (
            ROOT / "tests/fixtures/campaign/valid.yaml"
        ).read_text(encoding="utf-8")
        manifest_path = self.root / "manifest.yaml"
        manifest_path.write_text(
            source.replace("voice.test", "10.20.30.40"),
            encoding="utf-8",
        )
        manifest, digest = load_manifest(manifest_path)
        plan = compile_plan(manifest, digest)
        self.plan_bytes = (
            json.dumps(plan, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )
        (self.inputs / "plan.json").write_bytes(self.plan_bytes)

        profile = default_profile(name="live-mcp-test", host="10.20.30.40")
        profile["target"]["approved_addresses"] = ["10.20.30.40"]
        profile["authorization"].update(
            {
                "status": "approved",
                "approved_by": "Test operator",
                "approval_id": "test-only-loopback-free-fixture",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2030-01-01T00:00:00Z",
            }
        )
        self.profile_bytes = yaml.safe_dump(profile, sort_keys=False).encode()
        (self.inputs / "profile.yaml").write_bytes(self.profile_bytes)

        self.fixture = CapabilityFixture(self.root)
        self.endpoints = [
            {
                "role": "signaling",
                "address": "10.20.30.40",
                "port": 5060,
                "transport": "udp",
            }
        ]
        self.ceilings = dict(plan["authorization"]["hardMaxima"])
        self.calls: list[dict[str, object]] = []

        def fake_preflight(destination: dict[str, object]) -> tuple[bool, str]:
            self.calls.append(destination)
            return True, "SIP/2.0 200 OK Authorization: should-not-return"

        self.tools = LivePreparationTools(
            self.inputs,
            self.snapshots,
            CapabilityValidator(
                OpenSSLEd25519Verifier(
                    {
                        "operator-2026": (
                            "quad-security",
                            self.fixture.public_key,
                        )
                    }
                ),
                ReplayAuditStore(self.state),
                now=lambda: NOW,
            ),
            client_id="trusted-launcher:alice",
            preflight=fake_preflight,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def issue(self, name: str, action: str, nonce: str) -> None:
        artifact = self.fixture.issue(
            payload=self.fixture.payload(
                action=action,
                targetProfileSha256=hashlib.sha256(
                    self.profile_bytes
                ).hexdigest(),
                planSha256=hashlib.sha256(self.plan_bytes).hexdigest(),
                endpoints=self.endpoints,
                ceilings=self.ceilings,
                nonce=nonce,
            )
        )
        (self.inputs / name).write_bytes(artifact)

    def test_prepare_freezes_private_immutable_artifacts_without_traffic(self) -> None:
        self.issue(
            "prepare.cap",
            "prepare_assessment",
            "11111111111111111111111111111111",
        )
        result = self.tools.prepare_assessment(
            "prepare.cap", "profile.yaml", "plan.json"
        )
        self.assertTrue(result["ok"], result["errors"])
        self.assertFalse(result["networkActivity"])
        self.assertFalse(result["data"]["networkActivity"])
        self.assertEqual(result["data"]["authorization"]["state"], "verified-not-consumed")
        self.assertEqual(self.calls, [])
        snapshot = self.snapshots / result["data"]["snapshotId"]
        self.assertEqual(snapshot.stat().st_mode & 0o777, 0o700)
        self.assertEqual((snapshot / "reviewed-plan.json").read_bytes(), self.plan_bytes)
        self.assertEqual(
            (snapshot / "target-profile.yaml").read_bytes(), self.profile_bytes
        )
        self.assertEqual((snapshot / "snapshot.json").stat().st_mode & 0o777, 0o400)
        repeated = self.tools.prepare_assessment(
            "prepare.cap", "profile.yaml", "plan.json"
        )
        self.assertEqual(
            repeated["data"]["snapshotId"], result["data"]["snapshotId"]
        )
        frozen_plan = snapshot / "reviewed-plan.json"
        frozen_plan.chmod(0o600)
        frozen_plan.write_bytes(b"tampered")
        frozen_plan.chmod(0o400)
        rejected = self.tools.prepare_assessment(
            "prepare.cap", "profile.yaml", "plan.json"
        )
        self.assertFalse(rejected["ok"])
        self.assertIn("changed", rejected["errors"][0]["message"])

    def test_preflight_consumes_grant_and_invokes_exactly_one_fixed_target(self) -> None:
        self.issue(
            "preflight.cap",
            "preflight_target",
            "22222222222222222222222222222222",
        )
        result = self.tools.preflight_target(
            "preflight.cap", "profile.yaml", "plan.json"
        )
        self.assertTrue(result["ok"], result["errors"])
        self.assertTrue(result["networkActivity"])
        self.assertEqual(result["data"]["authorization"]["state"], "consumed")
        self.assertEqual(result["data"]["trafficBudget"]["sipOptionsTransactions"], 1)
        self.assertEqual(
            self.calls,
            [
                {
                    "target": "capability-bound",
                    "address": "10.20.30.40",
                    "port": 5060,
                    "transport": "udp",
                }
            ],
        )
        self.assertNotIn("should-not-return", json.dumps(result))
        replay = self.tools.preflight_target(
            "preflight.cap", "profile.yaml", "plan.json"
        )
        self.assertFalse(replay["ok"])
        self.assertFalse(replay["networkActivity"])
        self.assertEqual(len(self.calls), 1)

    def test_invalid_binding_causes_zero_network_invocations(self) -> None:
        self.issue(
            "wrong-action.cap",
            "prepare_assessment",
            "33333333333333333333333333333333",
        )
        result = self.tools.preflight_target(
            "wrong-action.cap", "profile.yaml", "plan.json"
        )
        self.assertFalse(result["ok"])
        self.assertFalse(result["networkActivity"])
        self.assertEqual(self.calls, [])

    def test_adapter_exception_after_attempt_reports_network_activity(self) -> None:
        self.issue(
            "adapter-error.cap",
            "preflight_target",
            "55555555555555555555555555555555",
        )

        def failing_preflight(destination: dict[str, object]) -> tuple[bool, str]:
            self.calls.append(destination)
            raise RuntimeError("fixture failure with secret-token")

        self.tools.preflight_probe = failing_preflight
        result = self.tools.preflight_target(
            "adapter-error.cap", "profile.yaml", "plan.json"
        )
        self.assertFalse(result["ok"])
        self.assertTrue(result["networkActivity"])
        self.assertEqual(len(self.calls), 1)
        self.assertNotIn("secret-token", json.dumps(result))

    def test_plan_swap_and_profile_scope_drift_fail_before_network(self) -> None:
        self.issue(
            "bound.cap",
            "preflight_target",
            "44444444444444444444444444444444",
        )
        plan = json.loads(self.plan_bytes)
        plan["metadata"]["name"] = "swapped"
        (self.inputs / "plan.json").write_text(
            json.dumps(plan, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        result = self.tools.preflight_target(
            "bound.cap", "profile.yaml", "plan.json"
        )
        self.assertFalse(result["ok"])
        self.assertFalse(result["networkActivity"])
        self.assertEqual(self.calls, [])

    def test_trust_manifest_is_strict_and_confined(self) -> None:
        trust = self.root / "trust"
        trust.mkdir(mode=0o700)
        (trust / "operator.pem").write_bytes(self.fixture.public_key.read_bytes())
        manifest = {
            "apiVersion": "sippycup.dev/mcp-live-trust/v1",
            "keys": [
                {
                    "keyId": "operator-2026",
                    "issuer": "quad-security",
                    "publicKey": "operator.pem",
                }
            ],
        }
        (trust / "trust.json").write_text(json.dumps(manifest), encoding="utf-8")
        keys = _trust_keys(trust)
        self.assertEqual(keys["operator-2026"][0], "quad-security")
        manifest["keys"][0]["publicKey"] = "../private.pem"
        (trust / "trust.json").write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(MCPPolicyError):
            _trust_keys(trust)


if __name__ == "__main__":
    unittest.main()
