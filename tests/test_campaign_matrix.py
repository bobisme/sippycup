from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup.campaign import MATRIX_FACTORS, ManifestError, compile_plan
from sippycup.runtime import RuntimeError, validate_plan


FIXTURE = ROOT / "tests" / "fixtures" / "campaign" / "valid.yaml"
SAMPLE = ROOT / "examples" / "ferivox-campaign.yaml"


def base_manifest() -> dict:
    return yaml.safe_load(FIXTURE.read_bytes())


def matrix() -> dict:
    return {
        "factors": {
            "transport": ["udp"],
            "addressFamily": ["ipv4", "ipv6"],
            "codec": ["pcmu", "opus"],
            "ptime": [20],
            "mediaProtection": ["plain", "dtls-srtp"],
            "dtmf": ["rfc4733"],
            "earlyMedia": ["disabled"],
            "holdReinvite": ["disabled"],
            "teardownInitiator": ["caller"],
            "duration": [10],
            "nat": ["none"],
            "impairment": ["none"],
        },
        "constraints": [
            {
                "id": "opus-secure",
                "if": {"codec": ["opus"]},
                "then": {"mediaProtection": ["dtls-srtp"]},
                "rationale": "exercise secure Opus",
            }
        ],
        "mandatoryCases": [
            {
                "id": "baseline",
                "values": {
                    "transport": "udp",
                    "addressFamily": "ipv4",
                    "codec": "pcmu",
                    "ptime": 20,
                    "mediaProtection": "plain",
                    "dtmf": "rfc4733",
                    "earlyMedia": "disabled",
                    "holdReinvite": "disabled",
                    "teardownInitiator": "caller",
                    "duration": 10,
                    "nat": "none",
                    "impairment": "none",
                },
            }
        ],
        "interactionStrength": 2,
        "riskWeights": [
            {
                "id": "secure-media",
                "when": {"mediaProtection": ["dtls-srtp"]},
                "weight": 5,
                "rationale": "higher security impact",
            }
        ],
    }


def compile_matrix(value: dict) -> dict:
    manifest = base_manifest()
    manifest["matrix"] = value
    return compile_plan(
        manifest,
        "a" * 64,
        resolver=lambda _host: ["10.20.30.40"],
    )


class MatrixModelTests(unittest.TestCase):
    def test_matrix_is_finite_normalized_and_runtime_validated(self):
        plan = compile_matrix(matrix())
        self.assertEqual(set(plan["matrix"]["factors"]), set(MATRIX_FACTORS))
        self.assertEqual(plan["matrix"]["interactionStrength"], 2)
        self.assertEqual(plan["matrix"]["mandatoryCases"][0]["id"], "baseline")
        self.assertIs(validate_plan(plan), plan)

        tampered = copy.deepcopy(plan)
        tampered["matrix"]["riskWeights"][0]["weight"] = 0
        with self.assertRaisesRegex(RuntimeError, "plan matrix is invalid"):
            validate_plan(tampered)

    def test_interaction_strength_defaults_to_pairwise(self):
        value = matrix()
        del value["interactionStrength"]
        plan = compile_matrix(value)
        self.assertEqual(plan["matrix"]["interactionStrength"], 2)

    def test_empty_domain_and_invalid_value_are_actionable(self):
        empty = matrix()
        empty["factors"]["codec"] = []
        with self.assertRaisesRegex(ManifestError, r"matrix\.factors\.codec.*non-empty"):
            compile_matrix(empty)

        invalid = matrix()
        invalid["factors"]["transport"] = ["sctp"]
        with self.assertRaisesRegex(
            ManifestError, r"matrix\.factors\.transport\[0\].*unsupported value 'sctp'"
        ):
            compile_matrix(invalid)

    def test_unsupported_factor_references_are_rejected(self):
        value = matrix()
        value["constraints"][0]["if"] = {"mysteryMode": ["on"]}
        with self.assertRaisesRegex(
            ManifestError, r"references unsupported factor\(s\): mysteryMode"
        ):
            compile_matrix(value)

    def test_risk_specific_strength_is_bounded_and_references_known_factors(self):
        value = matrix()
        value["riskWeights"][0].update(
            {
                "coveringFactors": ["codec", "mysteryMode"],
                "interactionStrength": 3,
            }
        )
        with self.assertRaisesRegex(
            ManifestError, r"coveringFactors references unsupported factor\(s\): mysteryMode"
        ):
            compile_matrix(value)

        value = matrix()
        value["riskWeights"][0].update(
            {
                "coveringFactors": ["codec", "ptime"],
                "interactionStrength": 2,
            }
        )
        with self.assertRaisesRegex(
            ManifestError, r"must be greater than the matrix strength \(2\)"
        ):
            compile_matrix(value)

    def test_unsatisfiable_model_reports_minimal_conflicting_ids(self):
        value = matrix()
        value["constraints"] = [
            {"id": "must-pcmu", "require": {"codec": ["pcmu"]}},
            {"id": "must-opus", "require": {"codec": ["opus"]}},
            {
                "id": "irrelevant",
                "exclude": {"addressFamily": ["ipv6"], "codec": ["pcmu"]},
            },
        ]
        with self.assertRaisesRegex(
            ManifestError,
            r"minimal conflicting constraint set: must-opus, must-pcmu",
        ):
            compile_matrix(value)

    def test_mandatory_case_must_be_complete_and_satisfy_constraints(self):
        incomplete = matrix()
        del incomplete["mandatoryCases"][0]["values"]["nat"]
        with self.assertRaisesRegex(ManifestError, r"must assign every factor.*missing nat"):
            compile_matrix(incomplete)

        conflict = matrix()
        conflict["mandatoryCases"][0]["values"]["codec"] = "opus"
        with self.assertRaisesRegex(
            ManifestError, r"mandatory case 'baseline' violates constraint\(s\): opus-secure"
        ):
            compile_matrix(conflict)

    def test_offline_ferivox_sample_compiles_without_resolution(self):
        raw = SAMPLE.read_bytes()
        manifest = yaml.safe_load(raw)

        def no_dns(_host: str) -> list[str]:
            self.fail("the offline Ferivox sample must not query DNS")

        plan = compile_plan(
            manifest,
            hashlib.sha256(raw).hexdigest(),
            resolver=no_dns,
        )
        self.assertEqual(plan["metadata"]["name"], "ferivox-model")
        self.assertEqual(len(plan["matrix"]["factors"]), 12)
        self.assertEqual(
            [item["id"] for item in plan["matrix"]["constraints"]],
            [
                "no-ipv6-endpoint-nat",
                "no-reorder-with-srtp",
                "opus-ptime",
                "reliable-early-media-needs-tcp",
                "tls-requires-dtls-srtp",
            ],
        )


if __name__ == "__main__":
    unittest.main()
