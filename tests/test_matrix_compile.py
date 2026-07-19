from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup.campaign import ManifestError, verify_frozen_plan
from sippycup.matrix_compile import compile_matrix_campaign
from sippycup.runtime import RuntimeError, validate_plan


SAMPLE = ROOT / "examples" / "ferivox-campaign.yaml"
CAMPAIGN = ROOT / "bin" / "campaign"


def sample_manifest(*, full_budget: bool = False) -> dict:
    manifest = yaml.safe_load(SAMPLE.read_bytes())
    if full_budget:
        ceilings = manifest["authorization"]["ceilings"]
        ceilings.update(
            {
                "calls": 100,
                "packets": 1000,
                "bytes": 2_000_000,
                "durationSeconds": 600,
            }
        )
    return manifest


class MatrixCompilationTests(unittest.TestCase):
    def test_full_compilation_plans_every_case_and_maps_results(self):
        compilation = compile_matrix_campaign(
            sample_manifest(full_budget=True), seed=19
        )
        report = compilation.report
        self.assertFalse(report["truncated"])
        self.assertTrue(report["achievedCoverage"]["factorTuples"]["complete"])
        self.assertTrue(report["achievedCoverage"]["orderedActionTuples"]["complete"])
        self.assertEqual(len(compilation.plan["steps"]), report["executedSize"])
        self.assertIs(validate_plan(compilation.plan), compilation.plan)
        verify_frozen_plan(compilation.plan, compilation.manifest_bytes)

        maxima = compilation.plan["authorization"]["hardMaxima"]
        for key, value in compilation.plan["plannedTotals"].items():
            self.assertLessEqual(value, maxima[key])
        records = {item["case"]: item for item in report["cases"]}
        for step in compilation.plan["steps"]:
            generated = step["generated"]
            record = records[step["case"]]
            self.assertEqual(generated["factors"], record["factors"])
            self.assertEqual(
                generated["actions"],
                [item["action"] for item in record["sequence"]],
            )
            self.assertEqual(
                [item["position"] for item in record["sequence"]],
                list(range(1, len(record["sequence"]) + 1)),
            )
            self.assertEqual(
                generated["factors"]["transport"],
                step["destination"]["transport"],
            )
        tampered = copy.deepcopy(compilation.plan)
        first = tampered["steps"][0]["generated"]["factors"]
        first["addressFamily"] = (
            "ipv6" if first["addressFamily"] == "ipv4" else "ipv4"
        )
        with self.assertRaisesRegex(
            RuntimeError, r"generated addressFamily does not match"
        ):
            validate_plan(tampered)

    def test_budget_truncation_reports_exact_uncovered_ledgers(self):
        compilation = compile_matrix_campaign(
            sample_manifest(full_budget=True),
            seed=23,
            max_cases=3,
        )
        report = compilation.report
        self.assertTrue(report["truncated"])
        self.assertEqual(report["executedSize"], 3)
        self.assertEqual(report["executionState"], "planned-not-executed")
        self.assertEqual(report["networkExecutions"], 0)
        for name, ledger_name in (
            ("factorTuples", "factorTupleLedger"),
            ("orderedActionTuples", "orderedActionTupleLedger"),
        ):
            ledger = report[ledger_name]
            uncovered = [item for item in ledger if item["status"] == "uncovered"]
            covered = [item for item in ledger if item["status"] == "covered"]
            summary = report["achievedCoverage"][name]
            self.assertEqual(summary["uncovered"], len(uncovered))
            self.assertEqual(summary["covered"], len(covered))
            self.assertFalse(summary["complete"])
            self.assertTrue(all(not item["coveredBy"] for item in uncovered))
            self.assertTrue(all(item["coveredBy"] for item in covered))
        self.assertIn("not exhaustive testing", report["coverageClaim"])
        self.assertIn("Budget truncated: yes", compilation.markdown)
        self.assertIn("uncovered", compilation.markdown.lower())
        self.assertIn("## Exclusions", compilation.markdown)

    def test_mandatory_history_and_risk_priority_are_auditable(self):
        history = [
            {
                "id": "regression-opus",
                "factors": {"codec": ["opus"]},
                "actions": [],
                "weight": 100,
            }
        ]
        compilation = compile_matrix_campaign(
            sample_manifest(full_budget=True),
            seed=31,
            max_cases=4,
            history=history,
        )
        cases = compilation.report["cases"]
        self.assertTrue(cases[0]["mandatory"])
        self.assertEqual(cases[0]["executionOrder"], 1)
        self.assertEqual(cases[1]["factors"]["codec"], "opus")
        self.assertIn("regression-opus", cases[1]["historicalFailureIds"])
        self.assertGreater(cases[1]["historicalScore"], 0)
        nonmandatory = cases[1:]
        self.assertEqual(
            [item["historicalScore"] for item in nonmandatory],
            sorted(
                (item["historicalScore"] for item in nonmandatory), reverse=True
            ),
        )

    def test_budget_cannot_drop_a_mandatory_case(self):
        manifest = sample_manifest()
        manifest["authorization"]["ceilings"]["calls"] = 1
        manifest["matrix"]["mandatoryCases"].append(
            copy.deepcopy(manifest["matrix"]["mandatoryCases"][0])
        )
        manifest["matrix"]["mandatoryCases"][1]["id"] = "second-baseline"
        with self.assertRaisesRegex(
            ManifestError, r"cannot retain 2 mandatory cases"
        ):
            compile_matrix_campaign(manifest)

    def test_cli_writes_generated_manifest_json_and_markdown_atomically(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            generated = directory / "generated.json"
            report = directory / "report.json"
            markdown = directory / "report.md"
            process = subprocess.run(
                [
                    sys.executable,
                    str(CAMPAIGN),
                    "matrix",
                    str(SAMPLE),
                    "--seed",
                    "37",
                    "--manifest-output",
                    str(generated),
                    "--report-output",
                    str(report),
                    "--markdown-output",
                    str(markdown),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            parsed = json.loads(report.read_text())
            self.assertEqual(parsed["seed"], 37)
            self.assertTrue(parsed["truncated"])
            planned = subprocess.run(
                [
                    sys.executable,
                    str(CAMPAIGN),
                    "plan",
                    str(generated),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(planned.returncode, 0, planned.stderr)
            self.assertEqual(
                len(json.loads(planned.stdout)["steps"]), parsed["executedSize"]
            )
            self.assertIn("# Matrix coverage report", markdown.read_text())

            repeated = subprocess.run(
                [
                    sys.executable,
                    str(CAMPAIGN),
                    "matrix",
                    str(SAMPLE),
                    "--manifest-output",
                    str(generated),
                    "--report-output",
                    str(directory / "other.json"),
                    "--markdown-output",
                    str(directory / "other.md"),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(repeated.returncode, 2)
            self.assertIn("refusing to overwrite", repeated.stderr)
            self.assertFalse((directory / "other.json").exists())
            self.assertFalse((directory / "other.md").exists())


if __name__ == "__main__":
    unittest.main()
