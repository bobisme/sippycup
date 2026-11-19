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
from sippycup_mcp.live_tools import LivePreparationTools, _require_one_call
from sippycup_mcp.live_server import _trust_keys
from sippycup_mcp.security import MCPPolicyError
from sippycup_workbench.profile import default_profile

from tests.test_mcp_capability import CapabilityFixture, NOW

ROOT = Path(__file__).parents[1]


class FakeProcessRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run_json(self, argv: list[str]) -> tuple[int, object, str]:
        self.calls.append(argv)
        return (
            0,
            {
                "apiVersion": "sippycup.dev/mcp-one-call-receipt/v1",
                "state": "succeeded",
                "exitCode": 0,
                "completedSteps": 1,
                "evidenceId": "one-call-fixture",
                "resultSha256": "a" * 64,
                "evidenceManifestSha256": "b" * 64,
            },
            "",
        )


class LivePreparationToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.inputs = self.root / "inputs"
        self.snapshots = self.root / "snapshots"
        self.state = self.root / "state"
        self.evidence = self.root / "evidence"
        for directory in (self.inputs, self.snapshots, self.state, self.evidence):
            directory.mkdir(mode=0o700)
        source = (
            ROOT / "tests/fixtures/campaign/valid.yaml"
        ).read_text(encoding="utf-8")
        manifest_path = self.root / "manifest.yaml"
        manifest_path.write_text(
            source.replace("voice.test", "10.20.30.40"),
            encoding="utf-8",
        )
        (self.inputs / "multi-manifest.yaml").write_bytes(
            manifest_path.read_bytes()
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

        one_manifest = yaml.safe_load(
            source.replace("voice.test", "10.20.30.40")
        )
        one_manifest["metadata"]["name"] = "mcp-one-call"
        one_manifest["authorization"]["credentialRefs"] = []
        one_manifest["authorization"]["ceilings"]["calls"] = 1
        one_manifest["targets"][0].pop("credentialRef")
        one_manifest["cases"] = [one_manifest["cases"][1]]
        self.one_manifest_bytes = yaml.safe_dump(
            one_manifest, sort_keys=False
        ).encode()
        one_manifest_path = self.inputs / "one-manifest.yaml"
        one_manifest_path.write_bytes(self.one_manifest_bytes)
        one_document, one_digest = load_manifest(one_manifest_path)
        one_plan = compile_plan(one_document, one_digest)
        self.one_plan_bytes = (
            json.dumps(
                one_plan, sort_keys=True, separators=(",", ":")
            ).encode()
            + b"\n"
        )
        (self.inputs / "one-plan.json").write_bytes(self.one_plan_bytes)

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
        self.process_runner = FakeProcessRunner()

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
            evidence_root=self.evidence,
            one_call_helper="/fixed/mcp-one-call",
            process_runner=self.process_runner,  # type: ignore[arg-type]
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def issue(
        self,
        name: str,
        action: str,
        nonce: str,
        *,
        plan_bytes: bytes | None = None,
        endpoints: list[dict[str, object]] | None = None,
        ceilings: dict[str, int] | None = None,
    ) -> None:
        selected_plan = plan_bytes or self.plan_bytes
        artifact = self.fixture.issue(
            payload=self.fixture.payload(
                action=action,
                targetProfileSha256=hashlib.sha256(
                    self.profile_bytes
                ).hexdigest(),
                planSha256=hashlib.sha256(selected_plan).hexdigest(),
                endpoints=endpoints or self.endpoints,
                ceilings=ceilings or self.ceilings,
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

    def test_one_call_consumes_exact_grant_and_returns_bounded_receipt(self) -> None:
        one_plan = json.loads(self.one_plan_bytes)
        media = one_plan["authorization"]["mediaPorts"]
        endpoints = [
            {
                "role": "media",
                "address": "10.20.30.40",
                "port": media["start"],
                "portEnd": media["end"],
                "transport": "udp",
            },
            {
                "role": "signaling",
                "address": "10.20.30.40",
                "port": 5060,
                "transport": "udp",
            },
        ]
        ceilings = dict(one_plan["authorization"]["hardMaxima"])
        self.issue(
            "one-call.cap",
            "execute_one_call",
            "66666666666666666666666666666666",
            plan_bytes=self.one_plan_bytes,
            endpoints=endpoints,
            ceilings=ceilings,
        )
        result = self.tools.execute_one_call(
            "one-call.cap",
            "profile.yaml",
            "one-plan.json",
            "one-manifest.yaml",
        )
        self.assertTrue(result["ok"], result["errors"])
        self.assertTrue(result["networkActivity"])
        self.assertEqual(result["data"]["authorization"]["state"], "consumed")
        self.assertEqual(result["data"]["receipt"]["completedSteps"], 1)
        self.assertEqual(len(self.process_runner.calls), 1)
        argv = self.process_runner.calls[0]
        self.assertEqual(argv[0], "/fixed/mcp-one-call")
        self.assertEqual(argv[-1], str(self.evidence))
        self.assertNotIn("signature", json.dumps(result))
        replay = self.tools.execute_one_call(
            "one-call.cap",
            "profile.yaml",
            "one-plan.json",
            "one-manifest.yaml",
        )
        self.assertFalse(replay["ok"])
        self.assertFalse(replay["networkActivity"])
        self.assertEqual(len(self.process_runner.calls), 1)

    def test_one_call_rejects_multi_step_plan_before_helper(self) -> None:
        self.issue(
            "multi.cap",
            "execute_one_call",
            "77777777777777777777777777777777",
        )
        result = self.tools.execute_one_call(
            "multi.cap",
            "profile.yaml",
            "plan.json",
            "multi-manifest.yaml",
        )
        self.assertFalse(result["ok"])
        self.assertFalse(result["networkActivity"])
        self.assertEqual(self.process_runner.calls, [])

    def test_one_call_helper_failure_is_bounded_and_reports_attempt(self) -> None:
        one_plan = json.loads(self.one_plan_bytes)
        media = one_plan["authorization"]["mediaPorts"]
        self.issue(
            "helper-failure.cap",
            "execute_one_call",
            "88888888888888888888888888888888",
            plan_bytes=self.one_plan_bytes,
            endpoints=[
                {
                    "role": "media",
                    "address": "10.20.30.40",
                    "port": media["start"],
                    "portEnd": media["end"],
                    "transport": "udp",
                },
                {
                    "role": "signaling",
                    "address": "10.20.30.40",
                    "port": 5060,
                    "transport": "udp",
                },
            ],
            ceilings=dict(one_plan["authorization"]["hardMaxima"]),
        )

        class FailedRunner:
            def run_json(self, argv: list[str]) -> tuple[int, object, str]:
                return 1, {"state": "failed"}, "secret helper detail"

        self.tools.process_runner = FailedRunner()  # type: ignore[assignment]
        result = self.tools.execute_one_call(
            "helper-failure.cap",
            "profile.yaml",
            "one-plan.json",
            "one-manifest.yaml",
        )
        self.assertFalse(result["ok"])
        self.assertTrue(result["networkActivity"])
        self.assertNotIn("secret helper detail", json.dumps(result))

    def test_one_call_local_hard_limits_and_credentials_fail_closed(self) -> None:
        plan = json.loads(self.one_plan_bytes)
        cases = []
        over_duration = json.loads(self.one_plan_bytes)
        over_duration["authorization"]["hardMaxima"]["durationSeconds"] = 61
        cases.append(over_duration)
        over_packets = json.loads(self.one_plan_bytes)
        over_packets["authorization"]["hardMaxima"]["packets"] = 2001
        cases.append(over_packets)
        credentials = json.loads(self.one_plan_bytes)
        credentials["authorization"]["credentialRefs"] = ["forbidden"]
        credentials["steps"][0]["credentialRef"] = "forbidden"
        cases.append(credentials)
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(MCPPolicyError):
                _require_one_call(candidate)
        _require_one_call(plan)

    def test_one_call_dial_destination_runs_but_an_account_is_refused(self) -> None:
        """A dial destination only changes the Request-URI user of the one
        credential-free call, so it is accepted and executed by the
        softphone runner. An account always carries a credential reference,
        so a plan with one is refused like any other credentialed plan."""
        from sippycup.integration import SOFTPHONE_RUNNER, select_runner

        manifest = yaml.safe_load(self.one_manifest_bytes)
        manifest["cases"][0]["dial"] = {"user": "1001"}
        raw = yaml.safe_dump(manifest, sort_keys=False).encode()
        dial_plan = compile_plan(manifest, hashlib.sha256(raw).hexdigest())
        self.assertEqual(dial_plan["steps"][0]["dial"], {"user": "1001"})
        _require_one_call(dial_plan)
        self.assertEqual(select_runner(dial_plan["steps"][0]), SOFTPHONE_RUNNER)

        manifest["authorization"]["credentialRefs"] = ["sip-user"]
        manifest["targets"][0]["credentialRef"] = "sip-user"
        manifest["targets"][0]["account"] = {"username": "alice", "register": True}
        raw = yaml.safe_dump(manifest, sort_keys=False).encode()
        account_plan = compile_plan(manifest, hashlib.sha256(raw).hexdigest())
        self.assertIn("account", account_plan["steps"][0])
        with self.assertRaisesRegex(MCPPolicyError, "credentials"):
            _require_one_call(account_plan)


WINDOW_UNTIL = "2030-01-01T00:00:00Z"


def scope_yaml(status: str) -> str:
    return yaml.safe_dump({"authorization": {
        "status": status, "approval_id": "CHG-MCP-1", "approved_by": "Owner",
        "valid_from": None, "valid_until": WINDOW_UNTIL,
    }})


class OneCallApprovalGateTests(unittest.TestCase):
    """bn-wcx2: an MCP one-call run passes the same approval gate as `campaign run`."""

    # The live-tools fixture, without re-running its tests.
    issue = LivePreparationToolTests.issue
    tearDown = LivePreparationToolTests.tearDown

    def setUp(self) -> None:
        LivePreparationToolTests.setUp(self)  # type: ignore[arg-type]
        manifest = yaml.safe_load(self.one_manifest_bytes)
        manifest["authorization"]["approval"] = {"id": "CHG-MCP-1", "validUntil": WINDOW_UNTIL}
        self.engagement = self.inputs / "eng"
        self.engagement.mkdir(mode=0o700)
        self.windowed_manifest = yaml.safe_dump(manifest, sort_keys=False).encode()
        (self.engagement / "campaign.yaml").write_bytes(self.windowed_manifest)
        document, digest = load_manifest(self.engagement / "campaign.yaml")
        plan = compile_plan(document, digest)
        self.windowed_plan = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        (self.engagement / "plan.json").write_bytes(self.windowed_plan)

    def issue_one_call(self, name: str, nonce: str, plan_bytes: bytes) -> None:
        plan = json.loads(plan_bytes)
        media = plan["authorization"]["mediaPorts"]
        self.issue(
            name, "execute_one_call", nonce, plan_bytes=plan_bytes,
            endpoints=[
                {"role": "media", "address": "10.20.30.40", "port": media["start"],
                 "portEnd": media["end"], "transport": "udp"},
                {"role": "signaling", "address": "10.20.30.40", "port": 5060, "transport": "udp"},
            ],
            ceilings=dict(plan["authorization"]["hardMaxima"]),
        )

    def run_windowed(self, name: str = "win.cap") -> dict:
        return self.tools.execute_one_call(name, "profile.yaml", "eng/plan.json", "eng/campaign.yaml")

    def test_a_revoked_scope_refuses_before_the_capability_or_the_helper(self) -> None:
        self.issue_one_call("win.cap", "99999999999999999999999999999991", self.windowed_plan)
        (self.engagement / "scope.yaml").write_text(scope_yaml("revoked"))
        result = self.run_windowed()
        self.assertFalse(result["ok"])
        self.assertFalse(result["networkActivity"])
        self.assertEqual(self.process_runner.calls, [])
        message = result["errors"][0]["message"]
        self.assertIn("revoked, not approved", message)
        self.assertIn("Nothing was sent", message)
        self.assertIn("the capability was not used", message)
        # Re-approved: the same capability is still unused and the call proceeds.
        (self.engagement / "scope.yaml").write_text(scope_yaml("approved"))
        result = self.run_windowed()
        self.assertTrue(result["ok"], result["errors"])
        self.assertEqual(result["warnings"], [])

    def test_the_helper_is_told_where_the_scope_file_is(self) -> None:
        self.issue_one_call("win.cap", "99999999999999999999999999999992", self.windowed_plan)
        (self.engagement / "scope.yaml").write_text(scope_yaml("approved"))
        self.assertTrue(self.run_windowed()["ok"])
        argv = self.process_runner.calls[0]
        self.assertIn(f"--scope-manifest={self.inputs.resolve() / 'eng' / 'campaign.yaml'}", argv)
        self.assertEqual(argv[-1], str(self.evidence))

    def test_a_plan_without_a_window_runs_with_the_campaign_warning(self) -> None:
        from sippycup.approval import UNBOUND_WARNING

        self.issue_one_call("plain.cap", "99999999999999999999999999999993", self.one_plan_bytes)
        result = self.tools.execute_one_call("plain.cap", "profile.yaml", "one-plan.json", "one-manifest.yaml")
        self.assertTrue(result["ok"], result["errors"])
        self.assertEqual(result["warnings"], [UNBOUND_WARNING])

    def test_a_revocation_seen_by_the_helper_reports_no_traffic(self) -> None:
        self.issue_one_call("win.cap", "99999999999999999999999999999994", self.windowed_plan)
        (self.engagement / "scope.yaml").write_text(scope_yaml("approved"))

        class LapsedRunner:
            def __init__(self) -> None:
                self.calls: list[list[str]] = []

            def run_json(self, argv: list[str]) -> tuple[int, object, str]:
                self.calls.append(argv)
                return 1, {"state": "failed", "error": "AuthorizationLapsed",
                           "detail": "the scope file says the approval is revoked, not approved"}, ""

        self.tools.process_runner = LapsedRunner()  # type: ignore[assignment]
        result = self.run_windowed()
        self.assertFalse(result["ok"])
        self.assertFalse(result["networkActivity"])
        self.assertIn("revoked, not approved", result["errors"][0]["message"])
        self.assertIn("Nothing was sent", result["errors"][0]["message"])

    def test_the_helper_itself_rereads_the_scope_file_and_sends_nothing(self) -> None:
        """The real helper entry point with the real executor: no capture, preflight, or run directory."""
        import contextlib
        import io

        from sippycup_mcp import one_call

        (self.engagement / "scope.yaml").write_text(scope_yaml("revoked"))
        frozen = self.root / "frozen"
        frozen.mkdir()
        (frozen / "reviewed-manifest.yaml").write_bytes(self.windowed_manifest)
        (frozen / "reviewed-plan.json").write_bytes(self.windowed_plan)
        runs = self.root / "one-call-runs"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = one_call.main([
                f"--scope-manifest={self.engagement / 'campaign.yaml'}",
                str(frozen / "reviewed-plan.json"), str(frozen / "reviewed-manifest.yaml"), str(runs),
            ])
        receipt = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(receipt["error"], "AuthorizationLapsed")
        self.assertIn("revoked, not approved", receipt["detail"])
        self.assertFalse(runs.exists())


if __name__ == "__main__":
    unittest.main()
