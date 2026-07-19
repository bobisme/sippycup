from __future__ import annotations

import copy
import hashlib
import itertools
from pathlib import Path
import sys
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup.campaign import _constraint_allows, _validate_matrix
from sippycup.covering import (
    generate_covering_array,
    generate_event_sequences,
)
from tests.test_campaign_matrix import matrix


SAMPLE = ROOT / "examples" / "ferivox-campaign.yaml"


def small_model() -> dict:
    value = matrix()
    value["factors"]["ptime"] = [10, 20]
    value["constraints"] = [
        {
            "id": "ipv6-secure",
            "if": {"addressFamily": ["ipv6"]},
            "then": {"mediaProtection": ["dtls-srtp"]},
        },
        {
            "id": "opus-ptime",
            "if": {"codec": ["opus"]},
            "then": {"ptime": [20]},
        },
    ]
    value["riskWeights"][0].update(
        {
            "coveringFactors": ["addressFamily", "codec", "ptime"],
            "interactionStrength": 3,
        }
    )
    return value


def brute_rows(model: dict) -> list[dict]:
    normalized = _validate_matrix(
        model, set(model["factors"]["transport"])
    )
    factors = tuple(normalized["factors"])
    return [
        dict(zip(factors, values))
        for values in itertools.product(
            *(normalized["factors"][factor] for factor in factors)
        )
        if all(
            _constraint_allows(constraint, dict(zip(factors, values)))
            for constraint in normalized["constraints"]
        )
    ]


def covers(row: dict, item: tuple[tuple[str, str | int], ...]) -> bool:
    return all(row[factor] == value for factor, value in item)


def is_subsequence(needle: tuple[str, ...], haystack: tuple[str, ...]) -> bool:
    positions = iter(haystack)
    return all(any(candidate == item for candidate in positions) for item in needle)


class CoveringArrayPropertyTests(unittest.TestCase):
    def test_brute_force_oracle_matches_every_permitted_tuple(self):
        model = small_model()
        result = generate_covering_array(model, seed=17)
        oracle = brute_rows(model)
        normalized = _validate_matrix(model, {"udp"})
        requested_subsets = set(
            itertools.combinations(tuple(normalized["factors"]), 2)
        )
        requested_subsets.add(("addressFamily", "codec", "ptime"))
        expected = {
            tuple((factor, row[factor]) for factor in factors)
            for factors in requested_subsets
            for row in oracle
        }
        self.assertEqual(set(result.required_tuples), expected)
        self.assertTrue(
            all(any(covers(row, item) for row in result.rows) for item in expected)
        )

        forbidden = {item.values for item in result.excluded_tuples}
        self.assertTrue(forbidden)
        self.assertTrue(
            all(not any(covers(row, item) for row in result.rows) for item in forbidden)
        )
        self.assertTrue(
            all(
                all(_constraint_allows(rule, row) for rule in normalized["constraints"])
                for row in result.rows
            )
        )

    def test_seed_is_stable_and_other_seeds_preserve_coverage(self):
        model = small_model()
        first = generate_covering_array(copy.deepcopy(model), seed=11)
        repeated = generate_covering_array(copy.deepcopy(model), seed=11)
        other = generate_covering_array(copy.deepcopy(model), seed=12)
        self.assertEqual(first, repeated)
        self.assertNotEqual(first.rows, other.rows)
        self.assertEqual(set(first.required_tuples), set(other.required_tuples))
        for result in (first, other):
            self.assertTrue(
                all(
                    any(covers(row, item) for row in result.rows)
                    for item in result.required_tuples
                )
            )

    def test_ferivox_cover_is_far_smaller_than_cartesian_product(self):
        manifest = yaml.safe_load(SAMPLE.read_bytes())
        model = manifest["matrix"]
        result = generate_covering_array(model, seed=20260718)
        cartesian = 1
        for domain in model["factors"].values():
            cartesian *= len(domain)
        self.assertLess(len(result.rows), cartesian // 1000)
        self.assertTrue(
            all(
                any(covers(row, item) for row in result.rows)
                for item in result.required_tuples
            )
        )


class SequenceCoverPropertyTests(unittest.TestCase):
    ACTIONS = [
        "dtmf",
        "hold",
        "resume",
        "reinvite",
        "failure",
        "recover",
        "hangup",
    ]

    def test_ordered_tuples_are_covered_and_state_constraints_hold(self):
        result = generate_event_sequences(
            self.ACTIONS,
            max_actions=5,
            interaction_strength=2,
            seed=41,
        )
        self.assertIn(("hold", "resume"), result.required_tuples)
        self.assertIn(("failure", "recover"), result.required_tuples)
        self.assertTrue(
            all(
                any(is_subsequence(item, sequence) for sequence in result.sequences)
                for item in result.required_tuples
            )
        )
        for sequence in result.sequences:
            self.assertEqual(sequence[-1], "hangup")
            held = False
            failed = False
            for action in sequence[:-1]:
                if action == "resume":
                    self.assertTrue(held)
                    held = False
                elif action == "hold":
                    self.assertFalse(held)
                    held = True
                elif action == "failure":
                    self.assertFalse(failed)
                    failed = True
                elif action == "recover":
                    self.assertTrue(failed)
                    failed = False
                else:
                    self.assertFalse(failed)

    def test_sequence_seed_is_deterministic_and_order_is_not_collapsed(self):
        first = generate_event_sequences(self.ACTIONS, seed=7)
        repeated = generate_event_sequences(self.ACTIONS, seed=7)
        other = generate_event_sequences(self.ACTIONS, seed=8)
        self.assertEqual(first, repeated)
        self.assertNotEqual(first.sequences, other.sequences)
        self.assertEqual(set(first.required_tuples), set(other.required_tuples))
        self.assertIn(("hold", "dtmf"), first.required_tuples)
        self.assertIn(("dtmf", "hold"), first.required_tuples)


if __name__ == "__main__":
    unittest.main()
