from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_webrtc.ice_turn import (  # noqa: E402
    OracleError,
    evaluate,
    validate_observation,
    validate_policy,
)


def load(name: str) -> dict:
    return json.loads((ROOT / "examples" / "webrtc" / name).read_text())


class ICETurnOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load("ice-turn-policy.json")
        self.observation = load("ice-turn-observation.clean.json")

    def test_clean_relay_flow_passes_without_capacity_claim(self) -> None:
        report = evaluate(self.policy, self.observation)
        self.assertEqual("pass", report["status"])
        self.assertFalse(report["networkActivity"])
        self.assertIsNone(report["capacityClaim"])
        self.assertEqual([], report["findings"])

    def test_policy_requires_literal_unique_servers_and_canonical_networks(self) -> None:
        hostname = deepcopy(self.policy)
        hostname["approvedServers"][0]["address"] = "stun.example.test"
        with self.assertRaisesRegex(OracleError, "literal unicast IP"):
            validate_policy(hostname)
        duplicate = deepcopy(self.policy)
        duplicate["approvedServers"].append(deepcopy(duplicate["approvedServers"][0]))
        with self.assertRaisesRegex(OracleError, "duplicates"):
            validate_policy(duplicate)
        noncanonical = deepcopy(self.policy)
        noncanonical["approvedPeerNetworks"] = ["127.0.0.1/8"]
        with self.assertRaisesRegex(OracleError, "canonical CIDR"):
            validate_policy(noncanonical)

    def test_candidate_disclosure_and_type_fail_independently(self) -> None:
        exposed = deepcopy(self.observation)
        exposed["events"][0]["data"].update(
            {"addressClass": "private", "exposed": True, "mdns": False}
        )
        exposed["events"][0]["data"]["candidateType"] = "prflx"
        codes = {item["code"] for item in evaluate(self.policy, exposed)["findings"]}
        self.assertEqual(
            {
                "ice.candidate_type_disallowed",
                "ice.candidate_address_exposed",
            },
            codes,
        )

    def test_unapproved_server_is_never_implicitly_authorized(self) -> None:
        document = deepcopy(self.observation)
        document["events"][1]["data"]["address"] = "127.0.0.9"
        codes = {item["code"] for item in evaluate(self.policy, document)["findings"]}
        self.assertIn("ice.unapproved_server_contact", codes)

    def test_nomination_consent_and_restart_fail_closed(self) -> None:
        document = deepcopy(self.observation)
        document["events"][6]["data"]["nominated"] = False
        document["events"][10]["timeMs"] = 25001
        document["events"][11]["timeMs"] = 25002
        document["events"][11]["data"]["newUfragHash"] = document["events"][11]["data"]["oldUfragHash"]
        document["events"][12]["timeMs"] = 25003
        codes = {item["code"] for item in evaluate(self.policy, document)["findings"]}
        self.assertTrue(
            {
                "ice.pair_not_nominated",
                "ice.consent_gap_exceeded",
                "ice.restart_reused_credentials",
            }.issubset(codes)
        )

    def test_turn_auth_lifetimes_transport_and_cleanup_are_independent(self) -> None:
        document = deepcopy(self.observation)
        document["events"][2]["data"].update(
            {"mechanism": "anonymous", "lifetimeSeconds": 4000}
        )
        document["events"][3]["data"].update(
            {"lifetimeSeconds": 700, "transport": "tls"}
        )
        policy = deepcopy(self.policy)
        policy["turn"]["allowedTransports"] = ["udp"]
        document["events"][12]["data"] = {"allocations": 1, "sockets": 2}
        codes = {item["code"] for item in evaluate(policy, document)["findings"]}
        self.assertTrue(
            {
                "turn.anonymous_credentials",
                "turn.credential_lifetime_exceeded",
                "turn.allocation_lifetime_exceeded",
                "turn.transport_disallowed",
                "ice.cleanup_incomplete",
            }.issubset(codes)
        )

    def test_turn_scope_permission_channel_and_amplification_fail(self) -> None:
        document = deepcopy(self.observation)
        data = document["events"][7]["data"]
        data.update(
            {
                "peerAddress": "192.0.2.10",
                "permissionPresent": False,
                "channelBound": False,
                "bytesIn": 100,
                "bytesOut": 1000,
            }
        )
        codes = {item["code"] for item in evaluate(self.policy, document)["findings"]}
        self.assertTrue(
            {
                "turn.peer_outside_scope",
                "turn.data_without_permission",
                "turn.channel_data_without_binding",
                "turn.amplification_ratio_exceeded",
            }.issubset(codes)
        )

    def test_missing_core_evidence_is_incomplete_not_pass(self) -> None:
        document = {
            "apiVersion": "sippycup.dev/ice-turn-observation/v1",
            "networkActivity": False,
            "events": [],
        }
        report = evaluate(self.policy, document)
        self.assertEqual("incomplete", report["status"])
        self.assertEqual(
            {
                "ice.selected_pair_not_observed",
                "ice.cleanup_not_observed",
                "ice.consent_not_observed",
            },
            {item["code"] for item in report["unknowns"]},
        )

    def test_failure_domain_distinguishes_peer_server_network_and_mixed(self) -> None:
        for domain in ("peer", "server", "network", "unknown"):
            with self.subTest(domain=domain):
                document = deepcopy(self.observation)
                document["events"].insert(
                    -1,
                    {
                        "timeMs": 10001,
                        "type": "failure",
                        "data": {"domain": domain, "code": "seeded.failure"},
                    },
                )
                self.assertEqual(domain, evaluate(self.policy, document)["failureDomain"])
        mixed = deepcopy(self.observation)
        mixed["events"][0:0] = [
            {"timeMs": 0, "type": "failure", "data": {"domain": "peer", "code": "a"}},
            {"timeMs": 0, "type": "failure", "data": {"domain": "network", "code": "b"}},
        ]
        self.assertEqual("mixed", evaluate(self.policy, mixed)["failureDomain"])

    def test_event_order_unknown_fields_and_boolean_integers_are_rejected(self) -> None:
        unordered = deepcopy(self.observation)
        unordered["events"][1]["timeMs"] = -1
        with self.assertRaises(OracleError):
            validate_observation(unordered)
        unknown = deepcopy(self.observation)
        unknown["events"][0]["data"]["rawCandidate"] = "forbidden"
        with self.assertRaisesRegex(OracleError, "unknown fields"):
            validate_observation(unknown)
        boolean = deepcopy(self.observation)
        boolean["events"][8]["data"]["packets"] = True
        with self.assertRaisesRegex(OracleError, "integer"):
            validate_observation(boolean)

    def test_cli_exit_codes_and_regular_file_boundary(self) -> None:
        command = [
            sys.executable,
            str(ROOT / "bin" / "webrtc-ice-turn"),
        ]
        environment = {"PYTHONPATH": str(ROOT / "lib")}
        clean = subprocess.run(
            command
            + [
                str(ROOT / "examples/webrtc/ice-turn-policy.json"),
                str(ROOT / "examples/webrtc/ice-turn-observation.clean.json"),
            ],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, clean.returncode, clean.stderr)
        self.assertEqual("pass", json.loads(clean.stdout)["status"])
        with tempfile.TemporaryDirectory() as root_name:
            link = Path(root_name) / "policy.json"
            link.symlink_to(ROOT / "examples/webrtc/ice-turn-policy.json")
            rejected = subprocess.run(
                command
                + [
                    str(link),
                    str(ROOT / "examples/webrtc/ice-turn-observation.clean.json"),
                ],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(2, rejected.returncode)
        self.assertIn("non-symlink", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
