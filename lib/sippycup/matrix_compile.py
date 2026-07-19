"""Compile covering rows into budgeted, reviewable campaign cases."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
from dataclasses import dataclass
from typing import Any, Callable

from sippycup.campaign import (
    ManifestError,
    _matrix_predicate,
    _predicate_state,
    _uint,
    _validate_matrix,
    compile_plan,
)
from sippycup.covering import (
    ActionTuple,
    FactorTuple,
    generate_covering_array,
    generate_event_sequences,
)


REPORT_VERSION = "sippycup.dev/matrix-report/v1"
DEFAULT_ACTIONS = (
    "dtmf",
    "failure",
    "hangup",
    "hold",
    "recover",
    "reinvite",
    "resume",
)


@dataclass(frozen=True)
class MatrixCompilation:
    manifest: dict[str, Any]
    manifest_bytes: bytes
    plan: dict[str, Any]
    report: dict[str, Any]
    markdown: str


def _covers(row: dict[str, str | int], item: FactorTuple) -> bool:
    return all(row[factor] == value for factor, value in item)


def _subsequence(needle: ActionTuple, haystack: ActionTuple) -> bool:
    positions = iter(haystack)
    return all(any(candidate == item for candidate in positions) for item in needle)


def _render_factor_tuple(item: FactorTuple) -> list[dict[str, Any]]:
    return [{"factor": factor, "value": value} for factor, value in item]


def _estimate(count: int, case_type: str, budget: dict[str, int]) -> dict[str, int]:
    return {
        "calls": count if case_type == "call" else 0,
        "packets": count * budget["packetsPerRun"],
        "bytes": count * budget["bytesPerRun"],
        "durationSeconds": count * budget["durationSecondsPerRun"],
    }


def _capacity(
    ceilings: dict[str, int],
    case_type: str,
    budget: dict[str, int],
    max_cases: int | None,
) -> int:
    limits = [
        ceilings["packets"] // budget["packetsPerRun"],
        ceilings["bytes"] // budget["bytesPerRun"],
        ceilings["durationSeconds"] // budget["durationSecondsPerRun"],
    ]
    if case_type == "call":
        limits.append(ceilings["calls"])
    if max_cases is not None:
        limits.append(_uint(max_cases, "max_cases"))
    return min(limits)


def _target_index(manifest: dict[str, Any]) -> dict[tuple[str, str], str]:
    result: dict[tuple[str, str], str] = {}
    for index, target in enumerate(manifest.get("targets", [])):
        try:
            family = f"ipv{ipaddress.ip_address(target["address"]).version}"
            transport = target["signaling"]["transport"]
            name = target["name"]
        except (KeyError, TypeError, ValueError) as error:
            raise ManifestError(
                "matrix compilation requires literal-IP targets with signaling metadata; "
                f"targets[{index}] is not usable"
            ) from error
        key = (family, transport)
        if key in result:
            raise ManifestError(
                f"matrix compilation has ambiguous targets for {family}/{transport}"
            )
        result[key] = name
    return result


def _history(
    raw_history: list[dict[str, Any]],
    matrix: dict[str, Any],
) -> list[dict[str, Any]]:
    result = []
    seen = set()
    for index, item in enumerate(raw_history):
        if not isinstance(item, dict):
            raise ManifestError(f"history[{index}] must be a mapping")
        unknown = sorted(set(item) - {"id", "factors", "actions", "weight"})
        if unknown:
            raise ManifestError(
                f"history[{index}] contains unsupported fields: {', '.join(unknown)}"
            )
        identifier = item.get("id")
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in seen
        ):
            raise ManifestError(f"history[{index}].id must be a unique non-empty string")
        seen.add(identifier)
        factors = _matrix_predicate(
            item.get("factors"), f"history[{index}].factors", matrix["factors"]
        )
        actions = item.get("actions", [])
        if not isinstance(actions, list) or any(not isinstance(x, str) for x in actions):
            raise ManifestError(f"history[{index}].actions must be a string list")
        result.append(
            {
                "id": identifier,
                "factors": factors,
                "actions": tuple(actions),
                "weight": _uint(item.get("weight", 1), f"history[{index}].weight"),
            }
        )
    return result


def compile_matrix_campaign(
    manifest: dict[str, Any],
    *,
    seed: int = 0,
    actions: tuple[str, ...] = DEFAULT_ACTIONS,
    max_actions: int = 5,
    sequence_strength: int = 2,
    max_cases: int | None = None,
    history: list[dict[str, Any]] | None = None,
    resolver: Callable[[str], list[str]] | None = None,
) -> MatrixCompilation:
    """Generate, prioritize, budget, and plan ordinary campaign cases."""
    if "matrix" not in manifest:
        raise ManifestError("matrix compilation requires a top-level matrix")
    source = copy.deepcopy(manifest)
    matrix = source["matrix"]
    normalized_matrix = _validate_matrix(
        matrix, set(matrix.get("factors", {}).get("transport", []))
    )
    covering = generate_covering_array(matrix, seed=seed)
    sequences = generate_event_sequences(
        actions,
        max_actions=max_actions,
        interaction_strength=sequence_strength,
        seed=seed,
    )
    call_templates = [
        item for item in source.get("cases", []) if item.get("type") == "call"
    ]
    if not call_templates:
        raise ManifestError("matrix compilation requires at least one call case template")
    template = copy.deepcopy(call_templates[0])
    if template.get("count") != 1:
        raise ManifestError("matrix call template count must be 1")
    budget = template["budget"]
    ceilings = source["authorization"]["ceilings"]
    capacity = _capacity(ceilings, "call", budget, max_cases)
    if capacity < 1:
        raise ManifestError("authorization budget cannot fit one generated call case")
    mandatory_count = len(normalized_matrix["mandatoryCases"])
    if capacity < mandatory_count:
        raise ManifestError(
            f"budget capacity {capacity} cannot retain {mandatory_count} mandatory cases"
        )

    targets = _target_index(source)
    histories = _history(history or [], normalized_matrix)
    risk_rules = normalized_matrix["riskWeights"]
    candidates = []
    for index, row in enumerate(covering.rows):
        sequence_index = index % len(sequences.sequences)
        sequence = sequences.sequences[sequence_index]
        key = (str(row["addressFamily"]), str(row["transport"]))
        if key not in targets:
            raise ManifestError(
                f"no literal target maps generated row to {key[0]}/{key[1]}"
            )
        risk_score = sum(
            rule["weight"]
            for rule in risk_rules
            if _predicate_state(rule["when"], row) is True
        )
        matched_history = [
            item
            for item in histories
            if _predicate_state(item["factors"], row) is True
            and _subsequence(item["actions"], sequence)
        ]
        candidates.append(
            {
                "rowIndex": index + 1,
                "sequenceIndex": sequence_index + 1,
                "row": row,
                "actions": sequence,
                "target": targets[key],
                "mandatory": index < mandatory_count,
                "riskScore": risk_score,
                "historyScore": sum(item["weight"] for item in matched_history),
                "history": sorted(item["id"] for item in matched_history),
            }
        )
    candidates.sort(
        key=lambda item: (
            not item["mandatory"],
            -item["historyScore"],
            -item["riskScore"],
            item["rowIndex"],
            item["sequenceIndex"],
        )
    )
    selected = candidates[:capacity]

    generated_cases = []
    case_records = []
    for ordinal, candidate in enumerate(selected, 1):
        fingerprint = hashlib.sha256(
            json.dumps(
                [candidate["row"], candidate["actions"]],
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()[:8]
        case_id = f"matrix-{ordinal:04d}-{fingerprint}"
        case = copy.deepcopy(template)
        case["id"] = case_id
        case["target"] = candidate["target"]
        case["generated"] = {
            "row": candidate["rowIndex"],
            "sequence": candidate["sequenceIndex"],
            "factors": candidate["row"],
            "actions": list(candidate["actions"]),
        }
        generated_cases.append(case)
        case_records.append(
            {
                "case": case_id,
                "executionOrder": ordinal,
                "matrixRow": candidate["rowIndex"],
                "mandatory": candidate["mandatory"],
                "target": candidate["target"],
                "factors": candidate["row"],
                "sequence": [
                    {"position": position, "action": action}
                    for position, action in enumerate(candidate["actions"], 1)
                ],
                "riskScore": candidate["riskScore"],
                "historicalScore": candidate["historyScore"],
                "historicalFailureIds": candidate["history"],
            }
        )
    source["cases"] = generated_cases
    source["metadata"]["name"] = (
        source["metadata"]["name"][:56].rstrip("-") + "-matrix"
    )
    manifest_bytes = (
        json.dumps(source, indent=2, sort_keys=True, separators=(",", ": "))
        + "\n"
    ).encode()
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    plan = compile_plan(
        source,
        digest,
        resolver=resolver or (lambda host: (_ for _ in ()).throw(
            ManifestError(f"matrix output target {host!r} is not a literal IP")
        )),
    )

    factor_ledger = []
    for item in covering.required_tuples:
        covered_by = [
            record["case"]
            for record, candidate in zip(case_records, selected)
            if _covers(candidate["row"], item)
        ]
        factor_ledger.append(
            {
                "tuple": _render_factor_tuple(item),
                "status": "covered" if covered_by else "uncovered",
                "coveredBy": covered_by,
            }
        )
    sequence_ledger = []
    for item in sequences.required_tuples:
        covered_by = [
            record["case"]
            for record, candidate in zip(case_records, selected)
            if _subsequence(item, candidate["actions"])
        ]
        sequence_ledger.append(
            {
                "tuple": list(item),
                "status": "covered" if covered_by else "uncovered",
                "coveredBy": covered_by,
            }
        )
    factor_covered = sum(item["status"] == "covered" for item in factor_ledger)
    sequence_covered = sum(item["status"] == "covered" for item in sequence_ledger)
    cartesian = 1
    for domain in matrix["factors"].values():
        cartesian *= len(domain)
    selected_estimate = _estimate(len(selected), "call", budget)
    full_estimate = _estimate(len(candidates), "call", budget)
    truncated = len(selected) < len(candidates)
    report = {
        "apiVersion": REPORT_VERSION,
        "kind": "MatrixCompilationReport",
        "seed": seed,
        "coverageClaim": (
            "Constrained t-way interaction coverage only; this is not exhaustive "
            "testing and does not prove correctness."
        ),
        "cartesianSize": cartesian,
        "generatedRowCount": len(covering.rows),
        "sequenceSuiteSize": len(sequences.sequences),
        "candidateCaseCount": len(candidates),
        "executedSize": len(selected),
        "executionState": "planned-not-executed",
        "networkExecutions": 0,
        "truncated": truncated,
        "budgets": {
            "authorized": ceilings,
            "perCase": budget,
            "capacity": capacity,
            "fullEstimate": full_estimate,
            "selectedEstimate": selected_estimate,
        },
        "achievedCoverage": {
            "factorTuples": {
                "required": len(factor_ledger),
                "covered": factor_covered,
                "uncovered": len(factor_ledger) - factor_covered,
                "complete": factor_covered == len(factor_ledger),
            },
            "orderedActionTuples": {
                "required": len(sequence_ledger),
                "covered": sequence_covered,
                "uncovered": len(sequence_ledger) - sequence_covered,
                "complete": sequence_covered == len(sequence_ledger),
            },
        },
        "cases": case_records,
        "factorTupleLedger": factor_ledger,
        "orderedActionTupleLedger": sequence_ledger,
        "exclusions": {
            "factorTuples": [
                {
                    "tuple": _render_factor_tuple(item.values),
                    "reasons": list(item.reasons),
                }
                for item in covering.excluded_tuples
            ],
            "orderedActionTuples": [
                {"tuple": list(item), "reasons": ["invalid-call-state-order"]}
                for item in sequences.excluded_tuples
            ],
        },
    }
    return MatrixCompilation(
        manifest=source,
        manifest_bytes=manifest_bytes,
        plan=plan,
        report=report,
        markdown=render_markdown(report),
    )


def render_markdown(report: dict[str, Any]) -> str:
    factor = report["achievedCoverage"]["factorTuples"]
    actions = report["achievedCoverage"]["orderedActionTuples"]
    lines = [
        "# Matrix coverage report",
        "",
        f"- Seed: `{report['seed']}`",
        f"- Cartesian size: {report['cartesianSize']}",
        f"- Generated rows: {report['generatedRowCount']}",
        f"- Executed size: {report['executedSize']} of {report['candidateCaseCount']}",
        f"- Execution state: {report['executionState']} "
        f"({report['networkExecutions']} network executions)",
        f"- Budget truncated: {'yes' if report['truncated'] else 'no'}",
        f"- Factor tuples: {factor['covered']}/{factor['required']} covered; "
        f"{factor['uncovered']} uncovered",
        f"- Ordered action tuples: {actions['covered']}/{actions['required']} covered; "
        f"{actions['uncovered']} uncovered",
        "",
        f"> {report['coverageClaim']}",
        "",
        "## Budget",
        "",
        "```json",
        json.dumps(report["budgets"], indent=2, sort_keys=True),
        "```",
        "",
        "## Uncovered tuples",
        "",
    ]
    uncovered = [
        item for item in report["factorTupleLedger"] if item["status"] == "uncovered"
    ] + [
        item
        for item in report["orderedActionTupleLedger"]
        if item["status"] == "uncovered"
    ]
    lines.extend(
        ["- None."]
        if not uncovered
        else [f"- `{json.dumps(item['tuple'], sort_keys=True)}`" for item in uncovered]
    )
    lines.extend(["", "## Exclusions", ""])
    exclusions = (
        report["exclusions"]["factorTuples"]
        + report["exclusions"]["orderedActionTuples"]
    )
    lines.extend(
        ["- None."]
        if not exclusions
        else [
            f"- `{json.dumps(item['tuple'], sort_keys=True)}` — "
            + ", ".join(item["reasons"])
            for item in exclusions
        ]
    )
    return "\n".join(lines) + "\n"
