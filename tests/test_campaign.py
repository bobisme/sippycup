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

from sippycup.campaign import MAX_PLAN_STEPS, ManifestError, U64_MAX, compile_plan


FIXTURES = ROOT / "tests" / "fixtures" / "campaign"


def fixture(name: str = "valid.yaml"):
    raw = (FIXTURES / name).read_bytes()
    return yaml.safe_load(raw), hashlib.sha256(raw).hexdigest()


class CampaignPlanTests(unittest.TestCase):
    def compile(self, manifest=None, *, answers=None, reductions=None):
        if manifest is None:
            manifest, digest = fixture()
        else:
            digest = "0" * 64
        answers = answers or {"voice.test": ["10.20.30.40"]}
        return compile_plan(
            manifest,
            digest,
            resolver=lambda host: answers[host],
            reductions=reductions,
        )

    def test_preflight_server_error_is_optional_frozen_and_byte_stable(self):
        from sippycup.runtime import RuntimeError as PlanError, validate_plan

        manifest, _ = fixture()
        omitted = self.compile(copy.deepcopy(manifest))
        self.assertNotIn("preflightServerError", omitted["authorization"]["stopConditions"])
        strict_manifest = copy.deepcopy(manifest)
        strict_manifest["authorization"]["stopConditions"]["preflightServerError"] = True
        strict = self.compile(strict_manifest)
        self.assertIs(strict["authorization"]["stopConditions"]["preflightServerError"], True)
        validate_plan(copy.deepcopy(strict))
        validate_plan(copy.deepcopy(omitted))
        # Everything but the new field is identical, so omitting it changes nothing.
        stripped = copy.deepcopy(strict)
        del stripped["authorization"]["stopConditions"]["preflightServerError"]
        self.assertEqual(stripped, omitted)
        for bad in ("yes", 1, None):
            invalid = copy.deepcopy(manifest)
            invalid["authorization"]["stopConditions"]["preflightServerError"] = bad
            with self.assertRaises(ManifestError):
                self.compile(invalid)
            tampered = copy.deepcopy(strict)
            tampered["authorization"]["stopConditions"]["preflightServerError"] = bad
            with self.assertRaises(PlanError):
                validate_plan(tampered)

    def test_valid_plan_is_complete_and_deterministic(self):
        manifest, _ = fixture()
        first = self.compile(copy.deepcopy(manifest))
        second = self.compile(copy.deepcopy(manifest))
        self.assertEqual(first, second)
        self.assertEqual(first["plannedTotals"], {
            "calls": 1,
            "packets": 54,
            "bytes": 54096,
            "durationSeconds": 23,
        })
        self.assertEqual(len(first["steps"]), 2)
        self.assertEqual(first["resolvedDestinations"][0]["address"], "10.20.30.40")
        self.assertIn("host 10.20.30.40", first["captureFilter"])
        self.assertEqual(first["authorization"]["hardMaxima"]["packets"], 100)
        self.assertEqual(
            first["assumptions"],
            ["DNS for voice.test is frozen to 10.20.30.40 for this plan"],
        )

    def test_multiple_dns_answers_are_sorted(self):
        plan = self.compile(
            answers={"voice.test": ["10.20.30.200", "10.20.30.2", "10.20.30.2"]}
        )
        self.assertEqual(
            [item["address"] for item in plan["resolvedDestinations"]],
            ["10.20.30.2", "10.20.30.200"],
        )

    def test_dns_answer_outside_approved_network_fails(self):
        with self.assertRaisesRegex(ManifestError, "outside approved networks"):
            self.compile(answers={"voice.test": ["10.20.30.40", "10.99.0.1"]})

    def test_placeholder_fixture_fails(self):
        manifest, _ = fixture("invalid-placeholder.yaml")
        with self.assertRaisesRegex(ManifestError, "placeholder"):
            self.compile(manifest)

    def test_empty_scope_fixture_fails(self):
        manifest, _ = fixture("invalid-empty-scope.yaml")
        with self.assertRaisesRegex(ManifestError, "non-empty"):
            self.compile(manifest)

    def test_missing_ceiling_fixture_fails(self):
        manifest, _ = fixture("invalid-missing-ceiling.yaml")
        with self.assertRaisesRegex(ManifestError, "missing required fields"):
            self.compile(manifest)

    def test_unsupported_transport_fails(self):
        manifest, _ = fixture()
        manifest["authorization"]["transports"] = ["ws"]
        manifest["targets"][0]["signaling"]["transport"] = "ws"
        with self.assertRaisesRegex(ManifestError, "unsupported transports"):
            self.compile(manifest)

    def test_unknown_fields_fail(self):
        manifest, _ = fixture()
        manifest["authorization"]["password"] = "not-allowed"
        with self.assertRaisesRegex(ManifestError, "unsupported fields"):
            self.compile(manifest)

    def test_case_expectations_are_versioned_and_privacy_allowlisted(self):
        for field in ("password", "authorization", "payload", "audio", "sdp"):
            with self.subTest(field=field):
                manifest, _ = fixture()
                manifest["cases"][0]["expectations"][field] = "fixture-secret"
                with self.assertRaisesRegex(ManifestError, "unsupported fields"):
                    self.compile(manifest)

    def test_case_expectations_require_exact_version(self):
        manifest, _ = fixture()
        manifest["cases"][0]["expectations"]["apiVersion"] = "v1"
        with self.assertRaisesRegex(ManifestError, "apiVersion"):
            self.compile(manifest)
        manifest, _ = fixture()
        manifest["cases"][0]["expectations"] = {}
        with self.assertRaisesRegex(ManifestError, "apiVersion"):
            self.compile(manifest)

    def test_normative_enums_must_be_exact_lowercase(self):
        for mutate in (
            lambda manifest: manifest["authorization"].update(
                {"transports": ["UDP"]}
            ),
            lambda manifest: manifest["targets"][0]["signaling"].update(
                {"transport": "UDP"}
            ),
            lambda manifest: manifest["cases"][0].update({"type": "OPTIONS"}),
        ):
            manifest, _ = fixture()
            mutate(manifest)
            with self.assertRaises(ManifestError):
                self.compile(manifest)

    def test_normative_arrays_reject_duplicates(self):
        fields = (
            ("networks", lambda manifest: manifest["authorization"]["networks"]),
            (
                "signalingPorts",
                lambda manifest: manifest["authorization"]["signalingPorts"],
            ),
            ("transports", lambda manifest: manifest["authorization"]["transports"]),
            (
                "credentialRefs",
                lambda manifest: manifest["authorization"]["credentialRefs"],
            ),
            (
                "allowedSipStatuses",
                lambda manifest: manifest["expectations"]["allowedSipStatuses"],
            ),
        )
        for field, select in fields:
            with self.subTest(field=field):
                manifest, _ = fixture()
                values = select(manifest)
                values.append(values[0])
                with self.assertRaisesRegex(ManifestError, "duplicate"):
                    self.compile(manifest)

    def test_capture_filter_excludes_unused_authorized_scope(self):
        manifest, _ = fixture()
        manifest["authorization"]["signalingPorts"].append(5070)
        manifest["authorization"]["transports"].append("tcp")
        manifest["targets"].append(
            {
                "name": "unused",
                "address": "10.20.30.99",
                "signaling": {"transport": "tcp", "port": 5070},
            }
        )
        plan = self.compile(manifest)
        capture_filter = plan["captureFilter"]
        self.assertIn("host 10.20.30.40", capture_filter)
        self.assertIn("udp port 5060", capture_filter)
        self.assertIn("udp portrange 10000-10020", capture_filter)
        self.assertNotIn("10.20.30.99", capture_filter)
        self.assertNotIn("5070", capture_filter)

    def test_checked_multiplication_overflow_fails(self):
        manifest, _ = fixture()
        manifest["cases"] = [manifest["cases"][0]]
        manifest["cases"][0]["count"] = MAX_PLAN_STEPS
        manifest["cases"][0]["budget"]["bytesPerRun"] = (
            U64_MAX // MAX_PLAN_STEPS
        ) + 1
        manifest["authorization"]["ceilings"]["packets"] = U64_MAX
        manifest["authorization"]["ceilings"]["bytes"] = U64_MAX
        with self.assertRaisesRegex(ManifestError, "arithmetic overflow"):
            self.compile(manifest)

    def test_checked_total_addition_overflow_fails(self):
        manifest, _ = fixture()
        manifest["cases"][0]["count"] = 1
        manifest["cases"][0]["budget"]["bytesPerRun"] = U64_MAX
        manifest["cases"][1]["budget"]["bytesPerRun"] = 1
        manifest["authorization"]["ceilings"]["bytes"] = U64_MAX
        with self.assertRaisesRegex(ManifestError, "arithmetic overflow"):
            self.compile(manifest)

    def test_enormous_expansion_fails_before_rendering_steps(self):
        manifest, _ = fixture()
        manifest["cases"] = [manifest["cases"][0]]
        manifest["cases"][0]["count"] = MAX_PLAN_STEPS + 1
        manifest["authorization"]["ceilings"]["packets"] = MAX_PLAN_STEPS + 1
        manifest["authorization"]["ceilings"]["bytes"] = U64_MAX
        manifest["authorization"]["ceilings"]["durationSeconds"] = U64_MAX
        with self.assertRaisesRegex(ManifestError, "planner limit"):
            self.compile(manifest)

    def test_override_can_reduce_authorization(self):
        plan = self.compile(reductions={"calls": 1, "packets": 54})
        self.assertEqual(plan["authorization"]["hardMaxima"]["calls"], 1)
        self.assertEqual(plan["authorization"]["hardMaxima"]["packets"], 54)

    def test_override_cannot_increase_authorization(self):
        with self.assertRaisesRegex(ManifestError, "only reduce authorization"):
            self.compile(reductions={"calls": 3})

    def test_override_cannot_silently_drop_declared_work(self):
        with self.assertRaisesRegex(ManifestError, "planned packets"):
            self.compile(reductions={"packets": 53})

    def test_literal_address_does_not_call_resolver(self):
        manifest, _ = fixture()
        manifest["targets"][0]["address"] = "10.20.30.41"
        called = False

        def resolver(_host):
            nonlocal called
            called = True
            return []

        compile_plan(manifest, "0" * 64, resolver=resolver)
        self.assertFalse(called)


class CampaignRunSummaryTests(unittest.TestCase):
    def test_summary_goes_to_stderr_and_names_the_journal_command(self):
        import argparse
        import contextlib
        import io
        from types import SimpleNamespace

        from sippycup.campaign import _print_run_summary

        with tempfile.TemporaryDirectory() as directory:
            engagement = Path(directory) / "acme"
            run = engagement / "runs" / "20261118T000000Z-acme-1"
            run.mkdir(parents=True)
            result = SimpleNamespace(state="succeeded", completed_steps=3, exit_code=0)
            args = argparse.Namespace(error_format="human")
            plan = {"steps": [{}, {}, {}]}
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                _print_run_summary(args, result, run, plan)
            self.assertEqual("", stdout.getvalue())
            self.assertIn("Campaign: SUCCEEDED (3 of 3 step(s) completed; exit 0)", stderr.getvalue())
            self.assertNotIn("Record it:", stderr.getvalue())
            (engagement / "engagement.json").write_text("{}")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                _print_run_summary(args, result, run, plan)
            self.assertIn(
                f"Record it: ./bin/sippycup journal add {engagement} --kind action --summary "
                "'Campaign run: succeeded' --evidence runs/20261118T000000Z-acme-1/result.json",
                stderr.getvalue(),
            )


class CampaignCliTests(unittest.TestCase):
    def run_cli(self, *arguments):
        return subprocess.run(
            [str(ROOT / "bin" / "campaign"), *arguments],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_cli_emits_json_with_pinned_resolution(self):
        result = self.run_cli(
            "plan",
            str(FIXTURES / "valid.yaml"),
            "--resolve",
            "voice.test=10.20.30.40",
            "--max-packets",
            "54",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["authorization"]["hardMaxima"]["packets"], 54)

    def test_cli_requires_pin_for_every_hostname_when_pinning(self):
        result = self.run_cli(
            "plan",
            str(FIXTURES / "valid.yaml"),
            "--resolve",
            "other.test=10.20.30.40",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("no pinned resolution", result.stderr)

    def test_invalid_fixture_exits_before_plan(self):
        result = self.run_cli(
            "plan", str(FIXTURES / "invalid-placeholder.yaml")
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("campaign: error:", result.stderr)
        self.assertIn("placeholder", result.stderr)

    def test_json_validation_error_is_actionable(self):
        result = self.run_cli(
            "plan",
            str(FIXTURES / "invalid-placeholder.yaml"),
            "--error-format",
            "json",
        )
        self.assertEqual(result.returncode, 2)
        error = json.loads(result.stderr)
        self.assertEqual(error["apiVersion"], "sippycup.dev/error/v1")
        self.assertEqual(error["kind"], "CampaignError")
        self.assertEqual(error["code"], "invalid_manifest")
        self.assertIn("placeholder", error["message"])

    def test_atomic_plan_output_never_overwrites_or_leaves_partial_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "plan.json"
            success = self.run_cli(
                "plan",
                str(FIXTURES / "valid.yaml"),
                "--resolve",
                "voice.test=10.20.30.40",
                "--output",
                str(output),
            )
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertEqual(success.stdout, "")
            self.assertIn(f"Wrote frozen plan: {output}", success.stderr)
            self.assertIn("Next: ./bin/sippycup campaign run ", success.stderr)
            self.assertIn("Network activity: none", success.stderr)
            original = output.read_bytes()
            overwrite = self.run_cli(
                "plan",
                str(FIXTURES / "valid.yaml"),
                "--resolve",
                "voice.test=10.20.30.40",
                "--output",
                str(output),
            )
            self.assertEqual(overwrite.returncode, 2)
            self.assertEqual(output.read_bytes(), original)
            malformed = Path(directory) / "malformed.json"
            failure = self.run_cli(
                "plan",
                str(FIXTURES / "invalid-placeholder.yaml"),
                "--output",
                str(malformed),
            )
            self.assertEqual(failure.returncode, 2)
            self.assertFalse(malformed.exists())
            self.assertEqual(
                list(Path(directory).glob(".*.tmp")),
                [],
            )


if __name__ == "__main__":
    unittest.main()
