from __future__ import annotations

import copy
import hashlib
import itertools
import json
from pathlib import Path
import random
import socket
import sys
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup.campaign import ManifestError, _constraint_allows, _validate_matrix
from sippycup.covering import generate_covering_array, generate_event_sequences
from sippycup.matrix_compile import compile_matrix_campaign
from sippycup.runtime import validate_plan


SAMPLE = ROOT / "examples" / "ferivox-campaign.yaml"
GOLDEN = ROOT / "tests" / "fixtures" / "matrix" / "ferivox-golden.json"


def _sample(*, full_budget: bool = False) -> dict:
    manifest = yaml.safe_load(SAMPLE.read_bytes())
    if full_budget:
        manifest["authorization"]["ceilings"].update(
            calls=100,
            packets=1000,
            bytes=2_000_000,
            durationSeconds=600,
        )
    return manifest


def _covers(row: dict, item: tuple[tuple[str, str | int], ...]) -> bool:
    return all(row[factor] == value for factor, value in item)


def _brute_rows(model: dict) -> list[dict]:
    normalized = _validate_matrix(model, set(model["factors"]["transport"]))
    factors = tuple(normalized["factors"])
    rows = []
    for values in itertools.product(
        *(normalized["factors"][factor] for factor in factors)
    ):
        row = dict(zip(factors, values))
        if all(
            _constraint_allows(constraint, row)
            for constraint in normalized["constraints"]
        ):
            rows.append(row)
    return rows


def _random_model(seed: int) -> dict:
    rng = random.Random(seed)
    model = copy.deepcopy(_sample()["matrix"])
    model["factors"] = {
        "transport": ["udp"],
        "addressFamily": ["ipv4", "ipv6"],
        "codec": ["pcmu", "opus"],
        "ptime": [10, 20],
        "mediaProtection": ["plain", "dtls-srtp"],
        "dtmf": ["rfc4733"],
        "earlyMedia": ["disabled"],
        "holdReinvite": ["disabled"],
        "teardownInitiator": ["caller"],
        "duration": [10],
        "nat": ["none"],
        "impairment": ["none"],
    }
    model["riskWeights"] = []
    variable = {
        "addressFamily": ("ipv4", "ipv6"),
        "codec": ("pcmu", "opus"),
        "ptime": (20, 10),
        "mediaProtection": ("plain", "dtls-srtp"),
    }
    factors = tuple(variable)
    constraints = []
    for index in range(1 + seed % 4):
        left, right = rng.sample(factors, 2)
        if index % 2:
            constraints.append(
                {
                    "id": f"implication-{index}",
                    "if": {left: [variable[left][1]]},
                    "then": {right: [rng.choice(variable[right])]},
                }
            )
        else:
            constraints.append(
                {
                    "id": f"exclusion-{index}",
                    "exclude": {
                        left: [variable[left][1]],
                        right: [variable[right][1]],
                    },
                }
            )
    model["constraints"] = constraints
    return model


class MatrixExitGateTests(unittest.TestCase):
    def test_random_constrained_models_match_brute_force_pair_oracle(self):
        for model_seed in range(30):
            with self.subTest(model_seed=model_seed):
                model = _random_model(model_seed)
                brute = _brute_rows(model)
                generated = generate_covering_array(model, seed=1000 + model_seed)
                factors = tuple(_validate_matrix(model, {"udp"})["factors"])
                permitted = {
                    tuple((factor, row[factor]) for factor in subset)
                    for subset in itertools.combinations(factors, 2)
                    for row in brute
                }
                self.assertEqual(set(generated.required_tuples), permitted)
                self.assertTrue(
                    all(
                        any(_covers(row, item) for row in generated.rows)
                        for item in permitted
                    )
                )
                for excluded in generated.excluded_tuples:
                    self.assertTrue(excluded.reasons)
                    self.assertFalse(
                        any(_covers(row, excluded.values) for row in generated.rows)
                    )
                self.assertEqual(
                    generated,
                    generate_covering_array(model, seed=1000 + model_seed),
                )

    def test_ferivox_golden_is_compact_complete_and_deterministic(self):
        compilation = compile_matrix_campaign(
            _sample(full_budget=True), seed=20260718
        )
        report = compilation.report
        projection = {
            "seed": report["seed"],
            "cartesianSize": report["cartesianSize"],
            "generatedRowCount": report["generatedRowCount"],
            "sequenceSuiteSize": report["sequenceSuiteSize"],
            "candidateCaseCount": report["candidateCaseCount"],
            "executedSize": report["executedSize"],
            "factorCoverage": report["achievedCoverage"]["factorTuples"],
            "actionCoverage": report["achievedCoverage"]["orderedActionTuples"],
            "factorExclusions": len(report["exclusions"]["factorTuples"]),
            "actionExclusions": len(report["exclusions"]["orderedActionTuples"]),
            "plannedTotals": compilation.plan["plannedTotals"],
            "caseMapSha256": hashlib.sha256(
                json.dumps(
                    report["cases"], sort_keys=True, separators=(",", ":")
                ).encode()
            ).hexdigest(),
            "factorLedgerSha256": hashlib.sha256(
                json.dumps(
                    report["factorTupleLedger"],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
            "actionLedgerSha256": hashlib.sha256(
                json.dumps(
                    report["orderedActionTupleLedger"],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
        }
        self.assertEqual(projection, json.loads(GOLDEN.read_text()))
        self.assertLess(report["generatedRowCount"], report["cartesianSize"] // 1000)
        self.assertTrue(all(item["reasons"] for item in report["exclusions"]["factorTuples"]))
        repeated = compile_matrix_campaign(
            _sample(full_budget=True), seed=20260718
        )
        self.assertEqual(compilation.manifest_bytes, repeated.manifest_bytes)
        self.assertEqual(compilation.report, repeated.report)

    def test_sequence_order_recovery_and_resume_constraints_are_proven(self):
        cover = generate_event_sequences(
            ["dtmf", "failure", "hangup", "hold", "recover", "reinvite", "resume"],
            max_actions=5,
            seed=20260718,
        )
        self.assertIn(("hold", "dtmf"), cover.required_tuples)
        self.assertIn(("dtmf", "hold"), cover.required_tuples)
        self.assertIn(("failure", "recover"), cover.required_tuples)
        for sequence in cover.sequences:
            if "resume" in sequence:
                self.assertLess(sequence.index("hold"), sequence.index("resume"))
            if "recover" in sequence:
                self.assertLess(sequence.index("failure"), sequence.index("recover"))
            self.assertEqual(sequence[-1], "hangup")

    def test_unsatisfiable_model_names_minimal_conflict(self):
        model = _random_model(3)
        model["constraints"] = [
            {"id": "must-pcmu", "require": {"codec": ["pcmu"]}},
            {"id": "must-opus", "require": {"codec": ["opus"]}},
            {"id": "irrelevant", "require": {"transport": ["udp"]}},
        ]
        with self.assertRaisesRegex(
            ManifestError,
            r"minimal conflicting constraint set: must-opus, must-pcmu",
        ):
            generate_covering_array(model)

    def test_truncation_is_incomplete_exact_and_planning_sends_no_packets(self):
        sends: list[tuple] = []

        def forbidden_send(*args, **kwargs):
            sends.append((args, kwargs))
            raise AssertionError("matrix planning attempted network traffic")

        with mock.patch.object(socket.socket, "sendto", forbidden_send), mock.patch.object(
            socket.socket, "connect", forbidden_send
        ):
            compilation = compile_matrix_campaign(
                _sample(full_budget=True),
                seed=20260718,
                max_cases=2,
            )
        self.assertEqual(sends, [])
        self.assertIs(validate_plan(compilation.plan), compilation.plan)
        report = compilation.report
        self.assertTrue(report["truncated"])
        self.assertEqual(report["executionState"], "planned-not-executed")
        self.assertEqual(report["networkExecutions"], 0)
        for summary in report["achievedCoverage"].values():
            self.assertFalse(summary["complete"])
            self.assertGreater(summary["uncovered"], 0)
        for ledger_name, summary_name in (
            ("factorTupleLedger", "factorTuples"),
            ("orderedActionTupleLedger", "orderedActionTuples"),
        ):
            exact = sum(
                item["status"] == "uncovered" for item in report[ledger_name]
            )
            self.assertEqual(
                exact, report["achievedCoverage"][summary_name]["uncovered"]
            )
        self.assertIn("not exhaustive", report["coverageClaim"])
        self.assertIn("Budget truncated: yes", compilation.markdown)


if __name__ == "__main__":
    unittest.main()
