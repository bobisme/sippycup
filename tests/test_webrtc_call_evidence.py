from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_webrtc.call_evidence import CallEvidenceError, evaluate, validate_evidence


def load(name):
    return json.loads((ROOT / "examples/webrtc" / name).read_text())


class CallEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.policy = load("call-policy.json")
        self.evidence = load("call-evidence.clean.json")

    def test_clean_cross_layer_chain_passes_privately(self):
        report = evaluate(self.policy, self.evidence)
        self.assertEqual("pass", report["status"])
        self.assertTrue(all(value is False for value in report["privacy"].values()))
        self.assertIsNone(report["capacityClaim"])

    def test_published_contract_schemas_are_strict_and_versioned(self):
        expectations = {
            "webrtc-call-policy-v1.schema.json": "sippycup.dev/webrtc-call-policy/v1",
            "webrtc-call-evidence-v1.schema.json": "sippycup.dev/webrtc-call-evidence/v1",
            "webrtc-call-report-v1.schema.json": "sippycup.dev/webrtc-call-report/v1",
        }
        for name, version in expectations.items():
            with self.subTest(name=name):
                schema = json.loads((ROOT / "schemas" / name).read_text())
                self.assertFalse(schema["additionalProperties"])
                self.assertEqual(
                    version,
                    schema["properties"]["apiVersion"]["const"],
                )

    def test_component_failure_and_uncertainty_remain_distinct(self):
        failed = deepcopy(self.evidence)
        failed["components"][0]["status"] = "fail"
        self.assertEqual("fail", evaluate(self.policy, failed)["status"])
        uncertain = deepcopy(self.evidence)
        uncertain["components"][0]["status"] = "incomplete"
        uncertain["components"][0]["uncertainty"] = ["partial-capture"]
        self.assertEqual("incomplete", evaluate(self.policy, uncertain)["status"])

    def test_layer_binding_continuity_and_missing_direction_fail_closed(self):
        document = deepcopy(self.evidence)
        document["events"][3]["data"]["associationIdHash"] = "a" * 64
        next(
            item
            for item in document["events"]
            if item["type"] == "audio"
            and item["data"]["direction"] == "outbound"
        )["data"]["continuity"] = "fail"
        document["events"] = [
            item
            for item in document["events"]
            if not (
                item["type"] in {"srtp_stream", "audio"}
                and item["data"].get("direction") == "inbound"
            )
        ]
        report = evaluate(self.policy, document)
        codes = {item["code"] for item in report["findings"]}
        self.assertIn("call.media_dtls_mismatch", codes)
        self.assertIn("call.audio_continuity_failed", codes)
        self.assertIn(
            "call.stream_direction_missing",
            {item["code"] for item in report["unknowns"]},
        )

    def test_partial_encrypted_capture_is_never_promoted_to_pass(self):
        document = deepcopy(self.evidence)
        next(
            item
            for item in document["events"]
            if item["type"] == "audio"
            and item["data"]["direction"] == "outbound"
        )["data"].update(
            {
                "measurementStatus": "not_measurable",
                "continuity": "unknown",
                "roundTripLatencyMs": None,
            }
        )
        report = evaluate(self.policy, document)
        self.assertEqual("incomplete", report["status"])
        self.assertIn(
            "call.audio_not_measurable",
            {item["code"] for item in report["unknowns"]},
        )

    def test_private_fields_literal_addresses_and_unknown_fields_are_rejected(self):
        for key, value in (
            ("icePwd", "secret"),
            ("candidateAddress", "192.0.2.1"),
            ("userAgent", "browser"),
        ):
            with self.subTest(key=key):
                document = deepcopy(self.evidence)
                document[key] = value
                with self.assertRaises(CallEvidenceError):
                    validate_evidence(document, self.policy)
        document = deepcopy(self.evidence)
        document["components"][0]["uncertainty"] = ["192.0.2.1"]
        with self.assertRaisesRegex(CallEvidenceError, "literal candidate"):
            validate_evidence(document, self.policy)

    def test_rtcp_canary_latency_and_generation_invariants(self):
        document = deepcopy(self.evidence)
        document["events"] = [
            item
            for item in document["events"]
            if not (
                item["type"] == "srtcp_stream"
                and item["data"]["direction"] == "inbound"
            )
        ]
        audio = next(
            item
            for item in document["events"]
            if item["type"] == "audio"
            and item["data"]["direction"] == "outbound"
        )
        audio["data"]["canaryAssetHash"] = None
        audio["data"]["roundTripLatencyMs"] = 3000
        report = evaluate(self.policy, document)
        self.assertIn(
            "call.srtcp_direction_missing",
            {item["code"] for item in report["unknowns"]},
        )
        self.assertIn(
            "call.canary_not_observed",
            {item["code"] for item in report["unknowns"]},
        )
        self.assertIn(
            "call.latency_ceiling_exceeded",
            {item["code"] for item in report["findings"]},
        )

    def test_recovery_and_generation_chain_are_bounded(self):
        document = deepcopy(self.evidence)
        copied = deepcopy(document["events"])
        for item in copied:
            item["timeMs"] += 10
            item["data"]["generation"] = 2
        copied.append(
            {
                "timeMs": 20,
                "type": "recovery",
                "data": {
                    "generation": 2,
                    "outcome": "failed",
                    "downtimeMs": 3000,
                },
            }
        )
        copied.sort(key=lambda item: item["timeMs"])
        document["events"].extend(copied)
        document["events"].sort(key=lambda item: item["timeMs"])
        report = evaluate(self.policy, document)
        codes = {item["code"] for item in report["findings"]}
        self.assertIn("call.generation_sequence_invalid", codes)
        self.assertIn("call.recovery_failed", codes)
        self.assertIn("call.recovery_too_slow", codes)

    def test_ice_pair_changes_require_order_and_recovery(self):
        document = deepcopy(self.evidence)
        document["events"].insert(
            2,
            {
                "timeMs": 1,
                "type": "ice_pair",
                "data": {
                    "generation": 0,
                    "pairIdHash": "c" * 64,
                    "sequence": 1,
                    "reason": "reselection",
                },
            },
        )
        report = evaluate(self.policy, document)
        self.assertEqual("incomplete", report["status"])
        self.assertIn(
            "call.recovery_missing",
            {item["code"] for item in report["unknowns"]},
        )
        document["events"][2]["data"]["sequence"] = 3
        report = evaluate(self.policy, document)
        self.assertIn(
            "call.ice_pair_sequence_invalid",
            {item["code"] for item in report["findings"]},
        )

    def test_cli_exit_codes_and_regular_file_boundary(self):
        command = [sys.executable, str(ROOT / "bin" / "webrtc-call-evidence")]
        environment = {"PYTHONPATH": str(ROOT / "lib")}
        clean = subprocess.run(
            command
            + [
                str(ROOT / "examples/webrtc/call-policy.json"),
                str(ROOT / "examples/webrtc/call-evidence.clean.json"),
            ],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, clean.returncode, clean.stderr)
        with tempfile.TemporaryDirectory() as root_name:
            link = Path(root_name) / "evidence.json"
            link.symlink_to(ROOT / "examples/webrtc/call-evidence.clean.json")
            rejected = subprocess.run(
                command
                + [
                    str(ROOT / "examples/webrtc/call-policy.json"),
                    str(link),
                ],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(2, rejected.returncode)
        self.assertIn("non-symlink", rejected.stderr)
