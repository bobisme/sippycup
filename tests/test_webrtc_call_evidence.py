from copy import deepcopy
import json
from pathlib import Path
import sys
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
        document["events"][5]["data"]["continuity"] = "fail"
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
        self.assertIn("call.srtp_dtls_mismatch", codes)
        self.assertIn("call.audio_continuity_failed", codes)
        self.assertIn(
            "call.stream_direction_missing",
            {item["code"] for item in report["unknowns"]},
        )

    def test_partial_encrypted_capture_is_never_promoted_to_pass(self):
        document = deepcopy(self.evidence)
        document["events"][5]["data"].update(
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
