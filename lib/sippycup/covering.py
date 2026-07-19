"""Deterministic constrained covering arrays and ordered action sequences."""

from __future__ import annotations

import hashlib
import itertools
import json
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from sippycup.campaign import (
    MATRIX_FACTORS,
    ManifestError,
    _constraint_allows,
    _validate_matrix,
)


Scalar = str | int
FactorTuple = tuple[tuple[str, Scalar], ...]
ActionTuple = tuple[str, ...]
MAX_REQUIREMENTS = 250_000
MAX_SEQUENCE_CANDIDATES = 250_000
SUPPORTED_ACTIONS = {
    "dtmf",
    "hold",
    "resume",
    "reinvite",
    "failure",
    "recover",
    "hangup",
}


@dataclass(frozen=True)
class ExcludedFactorTuple:
    values: FactorTuple
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class CoveringArray:
    rows: tuple[dict[str, Scalar], ...]
    required_tuples: tuple[FactorTuple, ...]
    excluded_tuples: tuple[ExcludedFactorTuple, ...]
    seed: int
    interaction_strength: int


@dataclass(frozen=True)
class SequenceCover:
    sequences: tuple[ActionTuple, ...]
    required_tuples: tuple[ActionTuple, ...]
    excluded_tuples: tuple[ActionTuple, ...]
    seed: int
    interaction_strength: int
    max_actions: int


def _stable_key(seed: int, namespace: str, value: Any) -> str:
    encoded = json.dumps(
        [seed, namespace, value],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _tuple_key(item: FactorTuple) -> tuple[tuple[str, str], ...]:
    return tuple((factor, json.dumps(value, sort_keys=True)) for factor, value in item)


def _assignment_covers(assignment: dict[str, Scalar], item: FactorTuple) -> bool:
    return all(assignment.get(factor) == value for factor, value in item)


def _compatible(assignment: dict[str, Scalar], item: FactorTuple) -> bool:
    return all(
        factor not in assignment or assignment[factor] == value
        for factor, value in item
    )


def _complete_assignment(
    domains: dict[str, list[Scalar]],
    constraints: list[dict[str, Any]],
    fixed: dict[str, Scalar],
    *,
    seed: int,
    namespace: str,
    uncovered: set[FactorTuple] | None = None,
) -> dict[str, Scalar] | None:
    assignment = dict(fixed)
    if not all(_constraint_allows(item, assignment) for item in constraints):
        return None
    remaining = sorted(
        (factor for factor in domains if factor not in assignment),
        key=lambda factor: (len(domains[factor]), factor),
    )

    def search(index: int) -> dict[str, Scalar] | None:
        if not all(_constraint_allows(item, assignment) for item in constraints):
            return None
        if index == len(remaining):
            return dict(assignment)
        factor = remaining[index]
        candidates = list(domains[factor])

        def candidate_key(value: Scalar) -> tuple[int, str]:
            assignment[factor] = value
            score = (
                sum(1 for item in uncovered if _compatible(assignment, item))
                if uncovered
                else 0
            )
            assignment.pop(factor)
            return (
                -score,
                _stable_key(seed, f"{namespace}:{factor}", value),
            )

        candidates.sort(key=candidate_key)
        for value in candidates:
            assignment[factor] = value
            completed = search(index + 1)
            if completed is not None:
                return completed
        assignment.pop(factor, None)
        return None

    return search(0)


def _requested_subsets(matrix: dict[str, Any]) -> list[tuple[str, ...]]:
    factors = tuple(MATRIX_FACTORS)
    strength = matrix["interactionStrength"]
    subsets = set(itertools.combinations(factors, strength))
    for risk in matrix["riskWeights"]:
        if "coveringFactors" not in risk:
            continue
        subsets.update(
            itertools.combinations(
                tuple(risk["coveringFactors"]),
                risk["interactionStrength"],
            )
        )
    return sorted(subsets)


def generate_covering_array(
    matrix: dict[str, Any],
    *,
    seed: int = 0,
) -> CoveringArray:
    """Generate valid rows covering every permitted requested factor tuple."""
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise ManifestError("covering seed must be a non-negative integer")
    authorized = set(matrix.get("factors", {}).get("transport", []))
    normalized = _validate_matrix(matrix, authorized)
    domains = normalized["factors"]
    constraints = normalized["constraints"]

    required: set[FactorTuple] = set()
    excluded: list[ExcludedFactorTuple] = []
    for factors in _requested_subsets(normalized):
        value_domains = [domains[factor] for factor in factors]
        for values in itertools.product(*value_domains):
            item = tuple(zip(factors, values))
            if len(required) + len(excluded) >= MAX_REQUIREMENTS:
                raise ManifestError(
                    f"covering model exceeds {MAX_REQUIREMENTS} requested tuples"
                )
            fixed = dict(item)
            completion = _complete_assignment(
                domains,
                constraints,
                fixed,
                seed=seed,
                namespace="classify",
            )
            if completion is not None:
                required.add(item)
                continue
            direct = tuple(
                constraint["id"]
                for constraint in constraints
                if not _constraint_allows(constraint, fixed)
            )
            excluded.append(
                ExcludedFactorTuple(item, direct or ("not-extendable",))
            )

    rows: list[dict[str, Scalar]] = [
        dict(item["values"]) for item in normalized["mandatoryCases"]
    ]
    uncovered = {
        item
        for item in required
        if not any(_assignment_covers(row, item) for row in rows)
    }
    row_number = 0
    while uncovered:
        row_number += 1
        target = min(
            uncovered,
            key=lambda item: _stable_key(
                seed, f"target:{row_number}", _tuple_key(item)
            ),
        )
        completed = _complete_assignment(
            domains,
            constraints,
            dict(target),
            seed=seed,
            namespace=f"row:{row_number}",
            uncovered=uncovered,
        )
        if completed is None:  # classified as permitted above; defensive invariant
            raise ManifestError("internal error: permitted tuple cannot be completed")
        rows.append(completed)
        uncovered = {
            item for item in uncovered if not _assignment_covers(completed, item)
        }

    return CoveringArray(
        rows=tuple(rows),
        required_tuples=tuple(sorted(required, key=_tuple_key)),
        excluded_tuples=tuple(
            sorted(excluded, key=lambda item: _tuple_key(item.values))
        ),
        seed=seed,
        interaction_strength=normalized["interactionStrength"],
    )


def _valid_action_sequence(sequence: ActionTuple) -> bool:
    if not sequence or sequence[-1] != "hangup" or "hangup" in sequence[:-1]:
        return False
    held = False
    failed = False
    for action in sequence:
        if action == "hangup":
            continue
        if failed:
            if action != "recover":
                return False
            failed = False
            continue
        if action == "hold":
            if held:
                return False
            held = True
        elif action == "resume":
            if not held:
                return False
            held = False
        elif action in {"dtmf", "reinvite"}:
            pass
        elif action == "failure":
            failed = True
        elif action == "recover":
            return False
        else:
            return False
    return True


def _ordered_subsequences(sequence: ActionTuple, strength: int) -> set[ActionTuple]:
    return {
        tuple(sequence[index] for index in positions)
        for positions in itertools.combinations(range(len(sequence)), strength)
    }


def generate_event_sequences(
    actions: Sequence[str],
    *,
    max_actions: int = 5,
    interaction_strength: int = 2,
    seed: int = 0,
) -> SequenceCover:
    """Cover every permitted ordered action tuple with valid call traces."""
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise ManifestError("sequence seed must be a non-negative integer")
    if (
        isinstance(max_actions, bool)
        or not isinstance(max_actions, int)
        or not 1 <= max_actions <= 7
    ):
        raise ManifestError("max_actions must be an integer between 1 and 7")
    if (
        isinstance(interaction_strength, bool)
        or not isinstance(interaction_strength, int)
        or not 1 <= interaction_strength <= max_actions
    ):
        raise ManifestError(
            "sequence interaction_strength must be between 1 and max_actions"
        )
    ordered_actions = tuple(sorted(set(actions)))
    if len(ordered_actions) != len(actions):
        raise ManifestError("sequence actions must be unique")
    unsupported = sorted(set(ordered_actions) - SUPPORTED_ACTIONS)
    if unsupported:
        raise ManifestError("unsupported sequence actions: " + ", ".join(unsupported))
    if "hangup" not in ordered_actions:
        raise ManifestError("sequence actions must include hangup")

    nonterminal = tuple(item for item in ordered_actions if item != "hangup")
    candidates: list[ActionTuple] = []
    for length in range(1, max_actions + 1):
        prefixes: Iterable[tuple[str, ...]]
        if length == 1:
            prefixes = [()]
        else:
            prefixes = itertools.product(nonterminal, repeat=length - 1)
        for prefix in prefixes:
            sequence = tuple(prefix) + ("hangup",)
            if _valid_action_sequence(sequence):
                candidates.append(sequence)
            if len(candidates) > MAX_SEQUENCE_CANDIDATES:
                raise ManifestError(
                    f"sequence model exceeds {MAX_SEQUENCE_CANDIDATES} valid candidates"
                )
    candidates = sorted(set(candidates))
    required = set().union(
        *(
            _ordered_subsequences(item, interaction_strength)
            for item in candidates
            if len(item) >= interaction_strength
        )
    )
    all_ordered = set(
        itertools.product(ordered_actions, repeat=interaction_strength)
    )
    excluded = all_ordered - required

    uncovered = set(required)
    selected: list[ActionTuple] = []
    while uncovered:
        scored = [
            (
                len(_ordered_subsequences(item, interaction_strength) & uncovered),
                _stable_key(seed, f"sequence:{len(selected)}", item),
                item,
            )
            for item in candidates
        ]
        score, _tie, best = max(scored, key=lambda item: (item[0], item[1]))
        if score == 0:
            raise ManifestError("internal error: permitted action tuple is uncovered")
        selected.append(best)
        uncovered -= _ordered_subsequences(best, interaction_strength)

    return SequenceCover(
        sequences=tuple(selected),
        required_tuples=tuple(sorted(required)),
        excluded_tuples=tuple(sorted(excluded)),
        seed=seed,
        interaction_strength=interaction_strength,
        max_actions=max_actions,
    )
