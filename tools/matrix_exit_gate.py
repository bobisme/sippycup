#!/usr/bin/env python3
"""Publish the deterministic matrix exit-gate size and coverage comparison."""

from __future__ import annotations

import json
from pathlib import Path
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup.matrix_compile import compile_matrix_campaign


def summary(compilation):
    report = compilation.report
    return {
        "selectedCases": report["executedSize"],
        "truncated": report["truncated"],
        "factorTuples": report["achievedCoverage"]["factorTuples"],
        "orderedActionTuples": report["achievedCoverage"]["orderedActionTuples"],
        "plannedTotals": compilation.plan["plannedTotals"],
        "networkExecutions": report["networkExecutions"],
    }


def main() -> int:
    source = yaml.safe_load(
        (ROOT / "examples" / "ferivox-campaign.yaml").read_bytes()
    )
    full = yaml.safe_load(
        (ROOT / "examples" / "ferivox-campaign.yaml").read_bytes()
    )
    full["authorization"]["ceilings"].update(
        calls=100,
        packets=1000,
        bytes=2_000_000,
        durationSeconds=600,
    )
    complete = compile_matrix_campaign(full, seed=20260718)
    authorized = compile_matrix_campaign(source, seed=20260718)
    print(
        json.dumps(
            {
                "apiVersion": "sippycup.dev/matrix-gate/v1",
                "seed": 20260718,
                "cartesianSize": complete.report["cartesianSize"],
                "generatedRows": complete.report["generatedRowCount"],
                "compactionRatio": (
                    complete.report["cartesianSize"]
                    // complete.report["generatedRowCount"]
                ),
                "fullBudget": summary(complete),
                "authorizedSampleBudget": summary(authorized),
                "coverageClaim": complete.report["coverageClaim"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
