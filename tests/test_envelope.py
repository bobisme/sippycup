from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup.envelope import (  # noqa: E402
    MAXIMA_KEYS,
    U64_MAX,
    EnvelopeError,
    compile_envelope_plan,
    simulate_envelope_plan,
    validate_envelope_plan,
)

EXAMPLE = ROOT / "examples" / "capacity-envelope.yaml"
CLI = ROOT / "bin" / "sippycup-envelope"


def fixture() -> tuple[dict[str, object], str]:
    raw = EXAMPLE.read_bytes()
    return yaml.safe_load(raw), hashlib.sha256(raw).hexdigest()


class EnvelopePlanTests(unittest.TestCase):
    def compile(
        self,
        manifest: dict[str, object] | None = None,
        reductions: dict[str, int | None] | None = None,
    ) -> dict[str, object]:
        source, digest = fixture()
        return compile_envelope_plan(
            manifest if manifest is not None else source,
            digest,
            reductions=reductions,
        )

    def test_plan_is_deterministic_one_dimensional_and_worst_case_bounded(
        self,
    ) -> None:
        first = self.compile()
        second = self.compile()
        self.assertEqual(first, second)
        self.assertEqual(
            [step["level"] for step in first["steps"]],
            list(range(1, 9)),
        )
        self.assertEqual(
            [step["startAtSeconds"] for step in first["steps"]],
            list(range(0, 160, 20)),
        )
        for step in first["steps"]:
            self.assertEqual(
                set(step["intensity"]),
                {
                    "callsPerSecond",
                    "concurrentCalls",
                    "mediaPacketsPerSecond",
                },
            )
            self.assertEqual(step["intensity"]["callsPerSecond"], step["level"])
            self.assertEqual(step["intensity"]["concurrentCalls"], 5)
            self.assertEqual(step["intensity"]["mediaPacketsPerSecond"], 250)
        self.assertEqual(
            first["plannedWorstCase"],
            {
                "calls": 720,
                "mediaPackets": 40000,
                "callSeconds": 800,
                "rampDurationSeconds": 160,
                "cooldownSeconds": 30,
                "recoveryDeadlineSeconds": 120,
                "totalDurationSeconds": 310,
            },
        )
        self.assertTrue(
            first["termination"]["authorizedDimensionCeilingReached"]
        )
        self.assertEqual(
            first["termination"]["reason"], "authorization_ceiling"
        )

    def test_every_hard_maximum_is_required_positive_and_strict(self) -> None:
        for key in MAXIMA_KEYS:
            with self.subTest(key=key, condition="missing"):
                manifest, _ = fixture()
                del manifest["authorization"]["hardMaxima"][key]
                with self.assertRaisesRegex(EnvelopeError, "missing fields"):
                    self.compile(manifest)
            for invalid in (0, -1, True, 1.5, U64_MAX + 1):
                with self.subTest(key=key, invalid=invalid):
                    manifest, _ = fixture()
                    manifest["authorization"]["hardMaxima"][key] = invalid
                    with self.assertRaises(EnvelopeError):
                        self.compile(manifest)
        manifest, _ = fixture()
        manifest["authorization"]["hardMaxima"]["extra"] = 1
        with self.assertRaisesRegex(EnvelopeError, "unsupported"):
            self.compile(manifest)

    def test_reductions_can_only_lower_each_authorized_maximum(self) -> None:
        manifest, _ = fixture()
        maxima = manifest["authorization"]["hardMaxima"]
        for key in MAXIMA_KEYS:
            with self.subTest(key=key):
                reduced = max(1, maxima[key] - 1)
                try:
                    plan = self.compile(reductions={key: reduced})
                except EnvelopeError as error:
                    # A lower combined duration may honestly make the envelope
                    # infeasible, but it must never be interpreted as expansion.
                    self.assertNotIn("exceeds authorized", str(error))
                else:
                    self.assertEqual(
                        plan["authorization"]["hardMaxima"][key], reduced
                    )
                with self.assertRaisesRegex(EnvelopeError, "only lower"):
                    self.compile(reductions={key: maxima[key] + 1})

    def test_checked_arithmetic_and_ramp_expansion_fail_closed(self) -> None:
        manifest, _ = fixture()
        maxima = manifest["authorization"]["hardMaxima"]
        maxima.update(
            {
                "callsPerSecond": U64_MAX,
                "concurrentCalls": 1,
                "mediaPacketsPerSecond": 1,
                "totalCalls": U64_MAX,
                "durationSeconds": U64_MAX,
                "holdSeconds": 2,
                "cooldownSeconds": 1,
                "recoveryDeadlineSeconds": 1,
            }
        )
        manifest["workload"].update(
            {
                "callsPerSecond": U64_MAX,
                "concurrentCalls": 1,
                "mediaPacketsPerSecond": 1,
                "callDurationSeconds": 1,
            }
        )
        manifest["ramp"].update(
            {"dimension": "callsPerSecond", "start": U64_MAX, "step": 1}
        )
        with self.assertRaisesRegex(EnvelopeError, "overflow"):
            self.compile(manifest)

        manifest, _ = fixture()
        manifest["authorization"]["hardMaxima"]["callsPerSecond"] = 100_002
        manifest["authorization"]["hardMaxima"]["totalCalls"] = U64_MAX
        manifest["authorization"]["hardMaxima"]["durationSeconds"] = U64_MAX
        manifest["ramp"]["step"] = 1
        with self.assertRaisesRegex(EnvelopeError, "planner limit"):
            self.compile(manifest)

    def test_budget_exhaustion_truncates_before_unfunded_step(self) -> None:
        plan = self.compile(reductions={"totalCalls": 100})
        self.assertEqual([step["level"] for step in plan["steps"]], [1, 2])
        self.assertEqual(plan["plannedWorstCase"]["calls"], 60)
        self.assertEqual(plan["termination"]["reason"], "budget_exhausted")
        self.assertFalse(
            plan["termination"]["authorizedDimensionCeilingReached"]
        )
        with self.assertRaisesRegex(EnvelopeError, "no ramp step fits"):
            self.compile(reductions={"totalCalls": 10})

    def test_ramp_contract_rejects_ambiguous_or_multiple_dimensions(self) -> None:
        manifest, _ = fixture()
        manifest["ramp"]["otherDimension"] = "concurrentCalls"
        with self.assertRaisesRegex(EnvelopeError, "unsupported"):
            self.compile(manifest)
        manifest, _ = fixture()
        manifest["workload"]["callsPerSecond"] = 2
        with self.assertRaisesRegex(EnvelopeError, "must equal ramp.start"):
            self.compile(manifest)

    def test_each_supported_dimension_changes_alone_to_its_exact_ceiling(
        self,
    ) -> None:
        for dimension, step_size in (
            ("callsPerSecond", 3),
            ("concurrentCalls", 7),
            ("mediaPacketsPerSecond", 500),
        ):
            with self.subTest(dimension=dimension):
                manifest, _ = fixture()
                manifest["ramp"] = {
                    "dimension": dimension,
                    "start": manifest["workload"][dimension],
                    "step": step_size,
                }
                plan = self.compile(manifest)
                self.assertEqual(
                    plan["steps"][-1]["level"],
                    manifest["authorization"]["hardMaxima"][dimension],
                )
                for step in plan["steps"]:
                    changed = {
                        key
                        for key in (
                            "callsPerSecond",
                            "concurrentCalls",
                            "mediaPacketsPerSecond",
                        )
                        if step["intensity"][key] != manifest["workload"][key]
                    }
                    self.assertTrue(changed <= {dimension})

    def test_tampered_plan_cannot_expand_or_rewrite_budgets(self) -> None:
        for mutate in (
            lambda plan: plan["authorization"]["hardMaxima"].update(
                {"callsPerSecond": 9}
            ),
            lambda plan: plan["steps"][0]["budget"].update({"calls": 0}),
            lambda plan: plan["plannedWorstCase"].update({"calls": 1}),
            lambda plan: plan["steps"][0]["intensity"].update(
                {"concurrentCalls": 6}
            ),
        ):
            plan = self.compile()
            mutate(plan)
            with self.assertRaises(EnvelopeError):
                validate_envelope_plan(plan)


class RampControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        manifest, digest = fixture()
        cls.plan = compile_envelope_plan(manifest, digest)

    def test_healthy_synthetic_endpoint_reaches_ceiling_without_network(
        self,
    ) -> None:
        observed = []
        result = simulate_envelope_plan(
            self.plan, endpoint=lambda step: observed.append(step["level"])
        )
        self.assertEqual(observed, list(range(1, 9)))
        self.assertEqual(result["testedLevels"], observed)
        self.assertEqual(result["state"], "completed")
        self.assertFalse(result["networkTrafficSent"])
        starts = [
            event
            for event in result["events"]
            if event["event"] == "ramp.step_started"
        ]
        self.assertEqual(
            [event["atSeconds"] for event in starts], list(range(0, 160, 20))
        )
        self.assertEqual(result["consumedWorstCase"]["calls"], 720)

    def test_pause_precedes_a_ramp_boundary_and_resume_restarts_hold_clock(
        self,
    ) -> None:
        result = simulate_envelope_plan(
            self.plan,
            {
                "commands": [
                    {"atSeconds": 20, "command": "pause"},
                    {"atSeconds": 35, "command": "resume"},
                    {"atSeconds": 55, "command": "stop"},
                ]
            },
        )
        starts = [
            event
            for event in result["events"]
            if event["event"] == "ramp.step_started"
        ]
        self.assertEqual(
            [(event["atSeconds"], event["level"]) for event in starts],
            [(0, 1), (35, 2)],
        )
        self.assertEqual(result["state"], "stopped")
        self.assertEqual(result["startedSteps"], 2)
        self.assertEqual(
            next(
                event
                for event in result["events"]
                if event["event"] == "control.pause"
            )["atSeconds"],
            20,
        )

    def test_stop_has_precedence_over_pause_resume_and_ramp(self) -> None:
        result = simulate_envelope_plan(
            self.plan,
            {
                "commands": [
                    {"atSeconds": 20, "command": "resume"},
                    {"atSeconds": 20, "command": "pause"},
                    {"atSeconds": 20, "command": "stop"},
                ]
            },
        )
        self.assertEqual(result["testedLevels"], [1])
        self.assertEqual(
            [event["event"] for event in result["events"]],
            [
                "controller.started",
                "ramp.step_started",
                "control.stop",
            ],
        )

    def test_invalid_control_stream_fails_closed(self) -> None:
        with self.assertRaisesRegex(EnvelopeError, "ordered"):
            simulate_envelope_plan(
                self.plan,
                [
                    {"atSeconds": 2, "command": "pause"},
                    {"atSeconds": 1, "command": "resume"},
                ],
            )
        with self.assertRaisesRegex(EnvelopeError, "requires a paused"):
            simulate_envelope_plan(
                self.plan, [{"atSeconds": 1, "command": "resume"}]
            )

    def test_pause_cannot_extend_wall_clock_authorization(self) -> None:
        result = simulate_envelope_plan(
            self.plan,
            {
                "commands": [
                    {"atSeconds": 20, "command": "pause"},
                    {"atSeconds": 500, "command": "resume"},
                ]
            },
        )
        self.assertEqual(result["testedLevels"], [1])
        self.assertEqual(result["state"], "stopped")
        self.assertEqual(
            result["events"][-1]["reason"], "budget_exhausted"
        )

    def test_repeated_simulations_are_byte_deterministic(self) -> None:
        first = simulate_envelope_plan(self.plan)
        self.assertEqual(first, simulate_envelope_plan(copy.deepcopy(self.plan)))
        self.assertEqual(
            json.dumps(first, sort_keys=True, separators=(",", ":")),
            json.dumps(
                simulate_envelope_plan(self.plan),
                sort_keys=True,
                separators=(",", ":"),
            ),
        )


class EnvelopeCliContractTests(unittest.TestCase):
    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(CLI), *arguments],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )

    def test_cli_lowering_and_simulation_are_strict(self) -> None:
        planned = self.run_cli(
            "plan", str(EXAMPLE), "--max-calls-per-second", "4"
        )
        self.assertEqual(planned.returncode, 0, planned.stderr)
        plan = json.loads(planned.stdout)
        self.assertEqual(plan["authorization"]["hardMaxima"]["callsPerSecond"], 4)
        raised = self.run_cli(
            "plan", str(EXAMPLE), "--max-calls-per-second", "9"
        )
        self.assertEqual(raised.returncode, 2)
        self.assertIn("only lower", raised.stderr)

        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            controls = root / "controls.json"
            controls.write_text(
                json.dumps(
                    {
                        "commands": [
                            {"atSeconds": 20, "command": "stop"}
                        ]
                    }
                ),
                encoding="utf-8",
            )
            simulated = self.run_cli(
                "run",
                str(plan_path),
                "--manifest",
                str(EXAMPLE),
                "--controls",
                str(controls),
            )
            self.assertEqual(simulated.returncode, 0, simulated.stderr)
            result = json.loads(simulated.stdout)
            self.assertEqual(result["testedLevels"], [1])
            self.assertFalse(result["networkTrafficSent"])

            changed_manifest = root / "changed.yaml"
            changed_manifest.write_text(
                EXAMPLE.read_text(encoding="utf-8").replace(
                    "callsPerSecond: 8", "callsPerSecond: 7", 1
                ),
                encoding="utf-8",
            )
            rebound = self.run_cli(
                "run",
                str(plan_path),
                "--manifest",
                str(changed_manifest),
            )
            self.assertEqual(rebound.returncode, 2)
            self.assertIn("SHA-256 differs", rebound.stderr)

    def test_every_cli_maximum_is_a_lowering_only_option(self) -> None:
        manifest, _ = fixture()
        maxima = manifest["authorization"]["hardMaxima"]
        for key in MAXIMA_KEYS:
            option = "".join(
                f"-{character.lower()}" if character.isupper() else character
                for character in key
            )
            with self.subTest(key=key):
                reduced = maxima[key] - 1
                result = self.run_cli(
                    "plan", str(EXAMPLE), f"--max-{option}", str(reduced)
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    json.loads(result.stdout)["authorization"]["hardMaxima"][key],
                    reduced,
                )

    def test_top_level_launcher_dispatches_envelope_without_podman(self) -> None:
        result = subprocess.run(
            [
                str(ROOT / "bin" / "sippycup"),
                "envelope",
                "plan",
                str(EXAMPLE),
                "--max-calls-per-second",
                "4",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout)["authorization"]["hardMaxima"][
                "callsPerSecond"
            ],
            4,
        )

    def test_output_is_exclusive_and_schema_and_docs_are_public(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "envelope-v1.schema.json").read_text()
        )
        self.assertEqual(
            schema["properties"]["apiVersion"]["const"],
            "sippycup.dev/envelope/v1",
        )
        documentation = (ROOT / "docs" / "ENVELOPE.md").read_text()
        for phrase in (
            "only lower",
            "no network traffic",
            "pause and stop",
            "worst-case",
        ):
            self.assertIn(phrase, documentation)
        with tempfile.TemporaryDirectory() as temporary_name:
            output = Path(temporary_name) / "plan.json"
            first = self.run_cli(
                "plan", str(EXAMPLE), "--output", str(output)
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            original = output.read_bytes()
            second = self.run_cli(
                "plan", str(EXAMPLE), "--output", str(output)
            )
            self.assertEqual(second.returncode, 2)
            self.assertEqual(output.read_bytes(), original)
            self.assertEqual(list(output.parent.glob(".*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
