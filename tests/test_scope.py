from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup.campaign import compile_plan  # noqa: E402
from sippycup_oracle.cli import load_expectations  # noqa: E402
from sippycup_workbench import cli  # noqa: E402
from sippycup_workbench.advisor import assess  # noqa: E402
from sippycup_workbench.journal import initialize  # noqa: E402
from sippycup_workbench.profile import load_profile, rehearse  # noqa: E402
from sippycup_workbench.scope import (  # noqa: E402
    SPEC,
    ScopeError,
    create_scope,
    inspect,
)
from sippycup_workbench.scope_derive import (  # noqa: E402
    FILENAMES,
    SIDECAR_FILE,
    compile_scope,
    derivative_state,
)
from sippycup_workbench.scope_questions import QUESTIONS, render_questions  # noqa: E402

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
LAUNCHER = ROOT / "bin" / "sippycup"


def complete_scope() -> dict:
    return {
        "schema_version": "sippycup.dev/scope/v1",
        "name": "ferivox-staging",
        "authorization": {
            "status": "approved",
            "approval_id": "FERIVOX-2026-114",
            "approved_by": "Quad",
            "valid_from": "2020-01-01T09:00:00+01:00",
            "valid_until": "2099-12-31T17:00:00+01:00",
        },
        "signaling": {
            "networks": ["10.20.30.0/24"],
            "ports": [5060, 5061],
            "transports": ["udp", "tls"],
        },
        "targets": [
            {"name": "edge", "address": "10.20.30.40", "transport": "udp", "port": 5060},
            {
                "name": "edge-tls",
                "address": "10.20.30.40",
                "transport": "tls",
                "port": 5061,
                "tls_server_name": "sbc.ferivox.test",
            },
        ],
        "media": {
            "networks": ["10.20.31.0/28", "10.20.30.40"],
            "port_range": {"start": 10000, "end": 10100},
            "protection": ["rtp", "sdes-srtp"],
            "codecs": ["PCMU", "PCMA"],
            "dtmf": "rfc4733",
            "symmetric_rtp": True,
        },
        "client": {"source_addresses": ["172.16.5.9"]},
        "account": {
            "required": True,
            "username": "staging-user",
            "realm": "ferivox.test",
            "credential_ref": "staging-user",
            "credential_delivery": "secret-manager",
        },
        "destinations": [
            {"name": "echo", "target": "edge", "user": "9196", "expect": "echo"},
            {"name": "echo-tls", "target": "edge-tls", "user": "9196", "expect": "echo"},
        ],
        "limits": {
            "calls": 10,
            "concurrent_calls": 2,
            "calls_per_second": 1,
            "packets_per_second": 200,
            "packets": 20000,
            "bytes": 5000000,
            "call_duration_seconds": 60,
            "total_duration_seconds": 600,
        },
        "stop_conditions": {
            "consecutive_failures": 2,
            "unexpected_response": True,
            "packet_loss_percent": 5,
        },
        "test_scope": {
            "allowed_classes": ["options", "call"],
            "exclusions": ["flooding"],
        },
        "contact": {"name": "Quad", "channel": "phone", "can_stop_test": True},
        "evidence": {"retention_days": 30, "disclosure": "coordinated"},
    }


def mutate(document: dict, path: str, value) -> dict:
    """Set (or delete when value is the sentinel DELETE) a dotted path."""
    node = document
    parts = path.split(".")
    for part in parts[:-1]:
        node = node[int(part)] if isinstance(node, list) else node[part]
    last = parts[-1]
    key = int(last) if isinstance(node, list) else last
    if value is DELETE:
        del node[key]
    else:
        node[key] = value
    return document


DELETE = object()


class ScopeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name) / "assessment"
        self.root.mkdir(mode=0o700)

    def write_scope(self, document: dict | str) -> Path:
        path = self.root / "scope.yaml"
        text = document if isinstance(document, str) else yaml.safe_dump(document, sort_keys=False)
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)
        return path

    def codes(self, document: dict, *, severity: str | None = None) -> set[str]:
        self.write_scope(document)
        report = inspect(self.root / "scope.yaml", now=NOW)
        return {
            item.code
            for item in report.findings
            if severity is None or item.severity == severity
        }

    def run_main(self, *arguments: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(arguments))
        return code, out.getvalue(), err.getvalue()


class InitTests(ScopeTestCase):
    def test_init_creates_pending_private_file_without_invented_answers(self) -> None:
        path = create_scope(self.root, name="ferivox-staging")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        document = yaml.safe_load(path.read_text())
        self.assertEqual(document["authorization"]["status"], "pending")
        self.assertIsNone(document["authorization"]["approval_id"])
        self.assertEqual(document["targets"], [])
        self.assertEqual(document["signaling"]["networks"], [])
        self.assertIsNone(document["limits"]["calls"])
        report = inspect(path, now=NOW)
        self.assertFalse(report.ok)
        self.assertFalse(report.fatal)
        self.assertIn("scope.missing", {item.code for item in report.errors})
        self.assertIn("scope.authorization_not_approved", {item.code for item in report.errors})

    def test_init_refuses_overwrite_and_missing_directory(self) -> None:
        create_scope(self.root)
        original = (self.root / "scope.yaml").read_bytes()
        with self.assertRaises(ScopeError):
            create_scope(self.root)
        self.assertEqual((self.root / "scope.yaml").read_bytes(), original)
        with self.assertRaises(ScopeError):
            create_scope(self.root / "missing")
        with self.assertRaises(ScopeError):
            create_scope(self.root, name="Bad Name")

    def test_init_default_name_is_a_valid_slug(self) -> None:
        odd = Path(self._temporary.name) / "My Engagement 7"
        odd.mkdir()
        create_scope(odd)
        self.assertEqual(yaml.safe_load((odd / "scope.yaml").read_text())["name"], "my-engagement-7")

    def test_cli_init_and_refusal(self) -> None:
        code, out, _ = self.run_main("scope", "init", str(self.root))
        self.assertEqual(code, 0)
        self.assertIn("No addresses, approval, limits, or credentials were invented", out)
        code, _, err = self.run_main("scope", "init", str(self.root))
        self.assertEqual(code, 2)
        self.assertIn("already exists", err)


class CheckTests(ScopeTestCase):
    def test_complete_scope_is_ok(self) -> None:
        self.write_scope(complete_scope())
        report = inspect(self.root / "scope.yaml", now=NOW)
        self.assertTrue(report.ok, [item.as_dict() for item in report.findings])
        self.assertTrue(report.complete and report.consistent)

    def test_missing_answers_have_stable_code_and_field(self) -> None:
        for path, field in (
            ("authorization.approval_id", "authorization.approval_id"),
            ("authorization.valid_until", "authorization.valid_until"),
            ("limits.calls", "limits.calls"),
            ("media.codecs", "media.codecs"),
            ("media.dtmf", "media.dtmf"),
            ("signaling.ports", "signaling.ports"),
            ("stop_conditions.packet_loss_percent", "stop_conditions.packet_loss_percent"),
            ("contact.name", "contact.name"),
            ("evidence.retention_days", "evidence.retention_days"),
            ("client.source_addresses", "client.source_addresses"),
        ):
            with self.subTest(path=path):
                document = complete_scope()
                mutate(document, path, DELETE)
                self.write_scope(document)
                report = inspect(self.root / "scope.yaml", now=NOW)
                self.assertIn(("scope.missing", field), [(i.code, i.field) for i in report.errors])
                self.assertFalse(report.ok)
                self.assertFalse(report.complete)

    def test_inconsistent_answers_are_reported_with_stable_codes(self) -> None:
        cases = {
            "scope.target_outside_networks": ("targets.0.address", "10.99.99.1"),
            "scope.port_not_approved": ("targets.0.port", 5080),
            "scope.transport_not_approved": ("targets.0.transport", "tcp"),
            "scope.tls_server_name_missing": ("targets.1.tls_server_name", DELETE),
            "scope.window_expired": ("authorization.valid_until", "2026-11-19T00:00:00Z"),
            "scope.window_not_started": ("authorization.valid_from", "2026-11-25T00:00:00Z"),
            "scope.window_order": ("authorization.valid_from", "2100-01-01T00:00:00Z"),
            "scope.concurrency_exceeds_calls": ("limits.concurrent_calls", 11),
            "scope.credential_ref_missing": ("account.credential_ref", DELETE),
            "scope.ceiling_infeasible": ("limits.packets", 10),
            "scope.placeholder_value": ("targets.0.address", "198.51.100.7"),
            "scope.destination_target_unknown": ("destinations.0.target", "nope"),
            "scope.media_ports_invalid": ("media.port_range.start", 20000),
            "scope.contact_cannot_stop": ("contact.can_stop_test", False),
            "scope.class_excluded": ("test_scope.exclusions", ["call"]),
            "scope.no_baseline_class": ("test_scope.allowed_classes", ["registration"]),
            "scope.authorization_not_approved": ("authorization.status", "revoked"),
            "scope.malformed": ("targets.0.port", "5060"),
        }
        for code, (path, value) in cases.items():
            with self.subTest(code=code):
                document = mutate(complete_scope(), path, value)
                self.assertIn(code, self.codes(document, severity="error"))

    def test_ceilings_that_cannot_hold_one_call(self) -> None:
        for path, value in (
            ("limits.call_duration_seconds", 4),
            ("limits.total_duration_seconds", 20),
            ("limits.packets", 30),
            ("limits.bytes", 9000),
            ("limits.calls", 1),
            ("limits.call_duration_seconds", 700),
        ):
            with self.subTest(path=path, value=value):
                document = mutate(complete_scope(), path, value)
                self.assertIn("scope.ceiling_infeasible", self.codes(document))

    def test_documentation_ranges_and_placeholder_words_are_flagged(self) -> None:
        document = complete_scope()
        document["signaling"]["networks"] = ["203.0.113.0/24"]
        self.assertIn("scope.placeholder_value", self.codes(document))

    def test_low_packet_rate_is_only_a_warning(self) -> None:
        document = mutate(complete_scope(), "limits.packets_per_second", 50)
        self.assertEqual(self.codes(document, severity="error"), set())
        self.assertIn("scope.ceiling_low_rate", self.codes(document, severity="warning"))

    def test_unquoted_timestamps_with_timezone_are_accepted(self) -> None:
        text = yaml.safe_dump(complete_scope(), sort_keys=False)
        text = text.replace("'2020-01-01T09:00:00+01:00'", "2020-01-01T09:00:00+01:00")
        text = text.replace("'2099-12-31T17:00:00+01:00'", "2099-12-31T17:00:00Z")
        self.assertNotIn("'20", text)
        self.write_scope(text)
        raw = yaml.safe_load(text)["authorization"]
        self.assertIsInstance(raw["valid_from"], datetime)
        self.assertTrue(inspect(self.root / "scope.yaml", now=NOW).ok)

    def test_timestamp_without_timezone_is_malformed(self) -> None:
        text = yaml.safe_dump(complete_scope(), sort_keys=False).replace(
            "'2099-12-31T17:00:00+01:00'", "2099-12-31 17:00:00"
        )
        self.write_scope(text)
        report = inspect(self.root / "scope.yaml", now=NOW)
        messages = [i.message for i in report.errors if i.field == "authorization.valid_until"]
        self.assertTrue(any("timezone" in message for message in messages), messages)

    def test_secret_shaped_fields_and_values_are_rejected_without_echo(self) -> None:
        secret = "hunter2-very-secret"
        variants = {
            "password key": lambda d: d["account"].update({"password": secret}),
            "sip_password key": lambda d: d["account"].update({"sip_password": secret}),
            "token key": lambda d: d.update({"api_token": secret}),
            "private key key": lambda d: d["account"].update({"private_key": secret}),
            "inline password": lambda d: d["contact"].update({"channel": f"password={secret}"}),
            "pem": lambda d: d["contact"].update(
                {"channel": "-----BEGIN PRIVATE KEY-----\nabc"}
            ),
            "url userinfo": lambda d: d["contact"].update(
                {"channel": f"sip:user:{secret}@host"}
            ),
            "long token": lambda d: d["account"].update(
                {"credential_ref": "a" * 10, "username": "A" * 48}
            ),
        }
        for label, apply in variants.items():
            with self.subTest(label=label):
                document = complete_scope()
                apply(document)
                self.write_scope(document)
                report = inspect(self.root / "scope.yaml", now=NOW)
                codes = {item.code for item in report.errors}
                self.assertTrue(
                    codes & {"scope.secret_field", "scope.secret_value", "scope.unknown_field"}
                    and report.fatal,
                    codes,
                )
                self.assertNotIn(secret, json.dumps(report.as_dict()))
        result = compile_scope(self.root, now=NOW)
        self.assertEqual(result.exit_code, 2)
        self.assertEqual(result.generated, [])

    def test_credential_reference_names_are_not_secrets(self) -> None:
        document = complete_scope()
        self.write_scope(document)
        self.assertTrue(inspect(self.root / "scope.yaml", now=NOW).ok)

    def test_unknown_fields_and_duplicate_keys_are_rejected(self) -> None:
        document = complete_scope()
        document["surprise"] = True
        document["targets"][0]["extra"] = 1
        self.write_scope(document)
        report = inspect(self.root / "scope.yaml", now=NOW)
        self.assertTrue(report.fatal)
        self.assertEqual(
            sorted(i.field for i in report.errors if i.code == "scope.unknown_field"),
            ["surprise", "targets[0].extra"],
        )
        self.write_scope("schema_version: sippycup.dev/scope/v1\nname: a\nname: b\n")
        report = inspect(self.root / "scope.yaml", now=NOW)
        self.assertEqual([i.code for i in report.errors], ["scope.unreadable"])

    def test_wrong_schema_version_and_non_mapping(self) -> None:
        document = complete_scope()
        document["schema_version"] = "sippycup.dev/scope/v2"
        self.assertIn("scope.schema_version", self.codes(document))
        self.write_scope("- a\n- b\n")
        self.assertEqual(
            [i.code for i in inspect(self.root / "scope.yaml", now=NOW).errors],
            ["scope.not_object"],
        )

    def test_missing_scope_file_and_symlink(self) -> None:
        report = inspect(self.root / "scope.yaml", now=NOW)
        self.assertEqual([i.code for i in report.errors], ["scope.not_found"])
        target = self.root / "real.yaml"
        target.write_text(yaml.safe_dump(complete_scope()))
        (self.root / "scope.yaml").symlink_to(target)
        self.assertEqual(
            [i.code for i in inspect(self.root / "scope.yaml", now=NOW).errors],
            ["scope.not_found"],
        )

    def test_cli_check_human_json_and_exit_codes(self) -> None:
        code, out, _ = self.run_main("scope", "check", str(self.root))
        self.assertEqual(code, 2)
        self.write_scope(mutate(complete_scope(), "limits.calls", DELETE))
        code, out, _ = self.run_main("scope", "check", str(self.root), "--format", "json")
        value = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(value["apiVersion"], "sippycup.dev/scope-check/v1")
        self.assertFalse(value["ok"])
        self.assertFalse(value["networkActivity"])
        self.assertEqual(value["errors"][0]["code"], "scope.missing")
        code, out, _ = self.run_main("scope", "check", str(self.root))
        self.assertIn("ERROR scope.missing [limits.calls]", out)
        self.assertIn("Network activity: none", out)
        self.write_scope(complete_scope())
        code, out, _ = self.run_main("scope", "check", str(self.root))
        self.assertEqual(code, 0, out)
        self.assertIn("COMPLETE and CONSISTENT", out)


class QuestionTests(ScopeTestCase):
    def test_generic_sheet_covers_required_topics_and_nothing_private(self) -> None:
        code, out, _ = self.run_main("scope", "questions")
        self.assertEqual(code, 0)
        lowered = out.lower()
        for topic in (
            "approval", "who approves", "timezone", "literal ip", "cidr", "signaling port",
            "transport", "server name", "require an account", "username", "realm",
            "deliver the password", "destination", "echo", "agent", "reject", "srtp", "sdes",
            "dtls", "codec", "dtmf", "media (rtp) port range", "total calls", "concurrent calls",
            "calls per second", "packets per second", "total packets", "total bytes",
            "maximum duration", "stop", "nat", "test classes", "excluded", "live contact",
            "retain", "disclosure",
        ):
            with self.subTest(topic=topic):
                self.assertIn(topic, lowered)
        self.assertNotIn("(answered)", out)
        self.assertNotIn("(unanswered)", out)
        self.assertNotIn(self._temporary.name, out)
        self.assertEqual(out, render_questions())

    def test_sheet_marks_answers_without_echoing_values(self) -> None:
        document = complete_scope()
        mutate(document, "media.codecs", DELETE)
        mutate(document, "account.required", False)
        document["authorization"]["approval_id"] = "ZZ-APPROVAL-777"
        self.write_scope(document)
        code, out, _ = self.run_main("scope", "questions", str(self.root))
        self.assertEqual(code, 0)
        self.assertNotIn("ZZ-APPROVAL-777", out)
        self.assertNotIn("10.20.30.40", out)
        self.assertNotIn("sbc.ferivox.test", out)
        lines = out.splitlines()
        by_text = {
            question.identifier: next(
                line for line in lines if line.split(". ", 1)[-1].startswith(question.text)
            )
            for question in QUESTIONS
        }
        self.assertIn("(unanswered)", by_text["media.codecs"])
        self.assertIn("(answered)", by_text["authorization.approval"])
        self.assertIn("(not-applicable)", by_text["account.identity"])
        self.assertIn("(answered)", by_text["signaling.tls"])

    def test_pending_scope_has_everything_unanswered(self) -> None:
        create_scope(self.root)
        _, out, _ = self.run_main("scope", "questions", str(self.root))
        self.assertNotIn("(answered)", out)
        self.assertIn("(unanswered)", out)

    def test_invalid_scope_marks_nothing(self) -> None:
        document = complete_scope()
        document["account"]["password"] = "x"
        self.write_scope(document)
        _, out, _ = self.run_main("scope", "questions", str(self.root))
        self.assertIn("missing or invalid", out)
        self.assertNotIn("(answered)", out)


class CompileTests(ScopeTestCase):
    def compile(self, **kwargs):
        return compile_scope(self.root, now=NOW, **kwargs)

    def test_complete_scope_produces_three_derivatives_that_pass_real_validators(self) -> None:
        self.write_scope(complete_scope())
        result = self.compile()
        self.assertEqual(result.exit_code, 0, result.as_dict())
        self.assertEqual({item["artifact"] for item in result.generated}, set(FILENAMES))
        for name in (*FILENAMES.values(), SIDECAR_FILE):
            self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), 0o600, name)
        self.assertEqual(
            sorted(path.name for path in self.root.iterdir()),
            sorted([*FILENAMES.values(), SIDECAR_FILE, "scope.yaml"]),
        )
        profile = load_profile(self.root / "target-profile.yaml")
        rehearsal = rehearse(profile, now=NOW)
        self.assertTrue(rehearsal.ready, rehearsal.errors)
        self.assertEqual(profile["authorization"]["status"], "approved")
        self.assertEqual(profile["authorization"]["approval_id"], "FERIVOX-2026-114")
        self.assertEqual(profile["authorization"]["valid_until"], "2099-12-31T16:00:00+00:00")
        self.assertEqual(profile["target"]["host"], "10.20.30.40")
        self.assertEqual(profile["limits"]["max_calls"], 10)
        self.assertTrue(profile["features"]["srtp"])
        self.assertFalse(profile["features"]["dtls_srtp"])
        # After the window passes, rehearse (not compile) blocks the profile.
        late = rehearse(profile, now=datetime(2100, 1, 2, tzinfo=timezone.utc))
        self.assertFalse(late.ready)

        manifest_bytes = (self.root / "campaign.yaml").read_bytes()
        plan = compile_plan(yaml.safe_load(manifest_bytes), "0" * 64, resolver=self.fail_dns)
        self.assertEqual(len(plan["steps"]), 4)
        self.assertEqual(plan["authorization"]["hardMaxima"]["calls"], 10)
        self.assertEqual(plan["authorization"]["credentialRefs"], ["staging-user"])
        self.assertLessEqual(plan["plannedTotals"]["packets"], 20000)
        self.assertLessEqual(plan["plannedTotals"]["durationSeconds"], 600)
        self.assertEqual(
            {(step["case"], step["type"]) for step in plan["steps"]},
            {
                ("edge-options", "options"),
                ("edge-call", "call"),
                ("edge-tls-options", "options"),
                ("edge-tls-call", "call"),
            },
        )

        expectation, on_unknown, selector = load_expectations(self.root / "expectations.yaml")
        self.assertEqual(on_unknown, "inconclusive")
        self.assertIsNone(selector)
        self.assertEqual(expectation.expected_codecs, ("PCMU", "PCMA"))
        self.assertTrue(expectation.require_bidirectional)
        # rfc4733 is the supported method, not a demand that every call send digits.
        self.assertFalse(expectation.require_dtmf)
        self.assertIn("10.20.30.40", expectation.allowed_endpoints)
        self.assertIn("172.16.5.9", expectation.allowed_endpoints)
        self.assertIn("10.20.31.15", expectation.allowed_endpoints)
        self.assertEqual(len(expectation.allowed_endpoints), 18)

    @staticmethod
    def fail_dns(host: str):
        raise AssertionError(f"unexpected DNS lookup for {host}")

    def test_options_only_and_tls_free_scope_compiles(self) -> None:
        document = complete_scope()
        document["test_scope"]["allowed_classes"] = ["options"]
        document["destinations"] = []
        document["account"].update({"required": False})
        for key in ("username", "realm", "credential_ref", "credential_delivery"):
            del document["account"][key]
        self.write_scope(document)
        result = self.compile()
        self.assertEqual(result.exit_code, 0, result.as_dict())
        plan = compile_plan(
            yaml.safe_load((self.root / "campaign.yaml").read_bytes()), "0" * 64,
            resolver=self.fail_dns,
        )
        self.assertEqual({step["type"] for step in plan["steps"]}, {"options"})
        self.assertEqual(plan["authorization"]["credentialRefs"], [])

    def test_dtls_srtp_and_no_dtmf_flow_through(self) -> None:
        document = complete_scope()
        document["media"].update({"protection": ["dtls-srtp"], "dtmf": "none"})
        self.write_scope(document)
        self.assertEqual(self.compile().exit_code, 0)
        profile = load_profile(self.root / "target-profile.yaml")
        self.assertTrue(profile["features"]["dtls_srtp"])
        self.assertTrue(profile["features"]["srtp"])
        expectation, _, _ = load_expectations(self.root / "expectations.yaml")
        self.assertFalse(expectation.require_dtmf)

    def test_budgets_shrink_to_fit_small_ceilings(self) -> None:
        document = complete_scope()
        document["limits"].update(
            {"calls": 2, "concurrent_calls": 1, "packets": 500, "bytes": 200000,
             "total_duration_seconds": 60, "call_duration_seconds": 30}
        )
        self.write_scope(document)
        result = self.compile()
        self.assertEqual(result.exit_code, 0, result.as_dict())
        plan = compile_plan(
            yaml.safe_load((self.root / "campaign.yaml").read_bytes()), "0" * 64,
            resolver=self.fail_dns,
        )
        totals = plan["plannedTotals"]
        self.assertLessEqual(totals["packets"], 500)
        self.assertLessEqual(totals["bytes"], 200000)
        self.assertLessEqual(totals["durationSeconds"], 60)
        self.assertLessEqual(totals["calls"], 2)

    def test_pending_scope_invents_nothing(self) -> None:
        create_scope(self.root)
        result = self.compile()
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.generated, [])
        self.assertEqual(set(result.skipped), set(FILENAMES))
        for name in FILENAMES.values():
            self.assertFalse((self.root / name).exists(), name)
        self.assertEqual(derivative_state(self.root)["state"], "partial")

    def test_unanswered_expectation_inputs_skip_only_expectations(self) -> None:
        document = complete_scope()
        mutate(document, "media.codecs", DELETE)
        self.write_scope(document)
        result = self.compile()
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(set(result.skipped), {"expectations"})
        self.assertFalse((self.root / "expectations.yaml").exists())
        self.assertTrue((self.root / "campaign.yaml").exists())
        profile = load_profile(self.root / "target-profile.yaml")
        self.assertEqual(profile["authorization"]["status"], "pending")
        self.assertFalse(rehearse(profile, now=NOW).ready)
        self.assertEqual(
            result.skipped["expectations"][0].field, "media.codecs"
        )

    def test_unanswered_approval_skips_campaign_and_leaves_profile_pending(self) -> None:
        document = complete_scope()
        mutate(document, "authorization.approval_id", DELETE)
        mutate(document, "authorization.status", "pending")
        self.write_scope(document)
        result = self.compile()
        self.assertEqual(set(result.skipped), {"campaign"})
        profile = load_profile(self.root / "target-profile.yaml")
        self.assertEqual(profile["authorization"]["status"], "pending")
        self.assertEqual(profile["authorization"]["approval_id"], "")
        self.assertFalse(rehearse(profile, now=NOW).ready)
        self.assertTrue((self.root / "expectations.yaml").exists())

    def test_expired_window_leaves_profile_pending(self) -> None:
        self.write_scope(mutate(complete_scope(), "authorization.valid_until", "2026-11-19T00:00:00Z"))
        result = self.compile()
        self.assertEqual(result.profile_status, "pending")
        self.assertEqual(set(result.skipped), {"campaign"})
        self.assertFalse(rehearse(load_profile(self.root / "target-profile.yaml"), now=NOW).ready)

    def test_missing_target_blocks_every_artifact(self) -> None:
        self.write_scope(mutate(complete_scope(), "targets", []))
        result = self.compile()
        self.assertEqual(result.generated, [])
        self.assertEqual(set(result.skipped), set(FILENAMES))

    def test_oversized_media_network_skips_expectations_only(self) -> None:
        document = complete_scope()
        document["media"]["networks"] = ["10.20.0.0/20"]
        self.write_scope(document)
        result = self.compile()
        self.assertEqual(set(result.skipped), {"expectations"})
        self.assertEqual(result.skipped["expectations"][0].code, "scope.media_not_enumerable")
        self.assertEqual(result.exit_code, 1)

    def test_invalid_scope_writes_nothing(self) -> None:
        document = complete_scope()
        document["account"]["password"] = "x"
        self.write_scope(document)
        result = self.compile()
        self.assertEqual(result.exit_code, 2)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["scope.yaml"])
        self.assertEqual(self.run_main("scope", "compile", str(self.root))[0], 2)

    def test_second_target_note_and_media_cidr_note(self) -> None:
        self.write_scope(complete_scope())
        notes = " ".join(self.compile().notes)
        self.assertIn("first target", notes)
        self.assertIn("media CIDRs", notes)


class StalenessTests(ScopeTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.write_scope(complete_scope())
        self.assertEqual(compile_scope(self.root, now=NOW).exit_code, 0)

    def test_fresh_compile_is_current_and_sidecar_records_hashes(self) -> None:
        state = derivative_state(self.root)
        self.assertEqual(state["state"], "current")
        sidecar = json.loads((self.root / SIDECAR_FILE).read_text())
        import hashlib

        self.assertEqual(
            sidecar["scope"]["sha256"],
            hashlib.sha256((self.root / "scope.yaml").read_bytes()).hexdigest(),
        )
        for name, entry in sidecar["derivatives"].items():
            self.assertEqual(
                entry["sha256"],
                hashlib.sha256((self.root / FILENAMES[name]).read_bytes()).hexdigest(),
            )
            self.assertEqual(entry["scopeSha256"], sidecar["scope"]["sha256"])
        self.assertIn("generated_at", sidecar)
        # Derivatives themselves carry no hash field (their validators are strict).
        self.assertNotIn("sha256", (self.root / "campaign.yaml").read_text().lower())

    def test_editing_scope_makes_every_derivative_stale_until_recompiled(self) -> None:
        path = self.root / "scope.yaml"
        path.write_text(path.read_text().replace("calls: 10", "calls: 8"))
        state = derivative_state(self.root)
        self.assertEqual(state["state"], "stale")
        self.assertTrue(all(i["scopeChanged"] for i in state["items"].values()))
        self.assertEqual(compile_scope(self.root, now=NOW).exit_code, 0)
        self.assertEqual(derivative_state(self.root)["state"], "current")
        self.assertEqual(load_profile(self.root / "target-profile.yaml")["limits"]["max_calls"], 8)

    def test_editing_a_derivative_is_detected_and_not_clobbered(self) -> None:
        profile = self.root / "target-profile.yaml"
        profile.write_text(profile.read_text() + "# hand edit\n")
        edited = profile.read_bytes()
        state = derivative_state(self.root)
        self.assertEqual(state["state"], "stale")
        self.assertEqual(state["items"]["profile"]["state"], "edited")
        result = compile_scope(self.root, now=NOW)
        self.assertEqual(result.exit_code, 2)
        self.assertEqual([i.code for i in result.refused], ["scope.derivative_modified"])
        self.assertEqual(profile.read_bytes(), edited)
        code, out, _ = (self.run_main("scope", "compile", str(self.root)))
        self.assertEqual(code, 2)
        self.assertIn("REFUSED scope.derivative_modified", out)
        self.assertEqual(profile.read_bytes(), edited)
        forced = compile_scope(self.root, now=NOW, force=True)
        self.assertEqual(forced.exit_code, 0)
        self.assertNotIn(b"\n# hand edit\n", profile.read_bytes())
        self.assertEqual(derivative_state(self.root)["state"], "current")

    def test_unmanaged_existing_file_is_not_clobbered(self) -> None:
        for path in (self.root / SIDECAR_FILE,):
            path.unlink()
        before = (self.root / "target-profile.yaml").read_bytes()
        result = compile_scope(self.root, now=NOW)
        self.assertEqual(result.exit_code, 2)
        self.assertIn("scope.derivative_unmanaged", {i.code for i in result.refused})
        self.assertEqual((self.root / "target-profile.yaml").read_bytes(), before)
        self.assertFalse((self.root / SIDECAR_FILE).exists())

    def test_a_refusal_writes_nothing_at_all(self) -> None:
        (self.root / "campaign.yaml").write_text("edited: true\n")
        scope = self.root / "scope.yaml"
        scope.write_text(scope.read_text().replace("calls: 10", "calls: 9"))
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        self.assertEqual(compile_scope(self.root, now=NOW).exit_code, 2)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_missing_derivative_and_untrusted_sidecar(self) -> None:
        (self.root / "expectations.yaml").unlink()
        state = derivative_state(self.root)
        self.assertEqual(state["items"]["expectations"]["state"], "missing")
        self.assertEqual(state["state"], "stale")
        (self.root / SIDECAR_FILE).write_text("{not json")
        self.assertEqual(derivative_state(self.root)["state"], "invalid")

    def test_not_compiled_state(self) -> None:
        (self.root / SIDECAR_FILE).unlink()
        self.assertEqual(derivative_state(self.root)["state"], "not-compiled")


class AdvisorIntegrationTests(ScopeTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.engagement = Path(self._temporary.name) / "journaled"
        initialize(self.engagement, title="Assessment", owner="Quad")

    def ids(self, result: dict) -> list[str]:
        return [action["id"] for action in result["nextActions"]]

    def test_no_scope_recommends_init_and_questions_first(self) -> None:
        result = assess(self.engagement, now=NOW)
        self.assertEqual(self.ids(result)[:2], ["scope-init", "scope-questions"])
        self.assertFalse(result["facts"]["scope"]["present"])
        self.assertLess(self.ids(result).index("scope-init"), self.ids(result).index("create-target-profile"))
        self.assertIn("target profile is missing", result["blockers"])
        self.assertNotEqual(result["overall"], "ready-for-human-review")

    def test_incomplete_scope_recommends_check(self) -> None:
        create_scope(self.engagement)
        result = assess(self.engagement, now=NOW)
        self.assertTrue(result["facts"]["scope"]["present"])
        self.assertFalse(result["facts"]["scope"]["ok"])
        self.assertIn("scope-check", self.ids(result))
        self.assertNotIn("create-target-profile", self.ids(result))
        self.assertNotIn("scope-init", self.ids(result))
        self.assertTrue(any("scope intake is incomplete" in b for b in result["blockers"]))
        self.assertIn("scope.missing", result["facts"]["scope"]["errorCodes"])

    def test_stale_derivatives_name_scope_compile_as_next_action(self) -> None:
        scope = self.engagement / "scope.yaml"
        scope.write_text(yaml.safe_dump(complete_scope(), sort_keys=False))
        scope.chmod(0o600)
        result = assess(self.engagement, now=NOW)
        self.assertIn("scope-compile", self.ids(result))  # complete but never compiled
        self.assertEqual(compile_scope(self.engagement, now=NOW).exit_code, 0)
        result = assess(self.engagement, now=NOW)
        self.assertEqual(result["facts"]["scope"]["derivatives"]["state"], "current")
        self.assertTrue(result["facts"]["profile"]["ready"])
        self.assertFalse(any("stale" in b for b in result["blockers"]))
        # Edit the scope: stale.
        scope.write_text(scope.read_text().replace("calls: 10", "calls: 7"))
        result = assess(self.engagement, now=NOW)
        self.assertEqual(result["facts"]["scope"]["derivatives"]["state"], "stale")
        self.assertTrue(any("stale" in b for b in result["blockers"]))
        self.assertEqual(self.ids(result)[0], "scope-compile")
        self.assertEqual(result["nextActions"][0]["argv"][1:3], ["scope", "compile"])
        self.assertNotIn("review-one-call-plan", self.ids(result))
        compile_scope(self.engagement, now=NOW)
        # Edit a derivative: stale again.
        profile = self.engagement / "target-profile.yaml"
        profile.write_text(profile.read_text() + "# hand edit\n")
        result = assess(self.engagement, now=NOW)
        self.assertEqual(
            result["facts"]["scope"]["derivatives"]["items"]["profile"]["state"], "edited"
        )
        self.assertIn("scope-compile", self.ids(result))
        for action in result["nextActions"]:
            self.assertFalse(action["networkActivity"])
            joined = " ".join(action.get("argv", []))
            self.assertNotIn("execute", joined)

    def test_status_json_schema_allows_scope_facts(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "engagement-status-v1.schema.json").read_text()
        )
        self.assertIn("scope", schema["properties"]["facts"]["properties"])


class NetworkFreeTests(ScopeTestCase):
    def test_no_socket_or_dns_use_across_all_subcommands(self) -> None:
        def forbidden(*args, **kwargs):
            raise AssertionError("network access attempted")

        with (
            mock.patch.object(socket, "socket", forbidden),
            mock.patch.object(socket, "getaddrinfo", forbidden),
            mock.patch.object(socket, "gethostbyname", forbidden),
            mock.patch.object(socket, "create_connection", forbidden),
        ):
            self.assertEqual(self.run_main("scope", "init", str(self.root))[0], 0)
            self.assertEqual(self.run_main("scope", "questions", str(self.root))[0], 0)
            self.assertEqual(self.run_main("scope", "check", str(self.root))[0], 1)
            self.write_scope(complete_scope())
            self.assertEqual(self.run_main("scope", "compile", str(self.root))[0], 0)
            assess(self.root, now=NOW)


class CommandWiringTests(unittest.TestCase):
    def run_cli(self, *arguments: str):
        return subprocess.run(
            [LAUNCHER, *arguments],
            cwd=ROOT,
            env={**os.environ, "SIPPYCUP_RUNTIME": "/definitely/missing/runtime"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )

    def test_scope_help_is_network_free_and_needs_no_runtime(self) -> None:
        for arguments in (
            ("scope", "--help"),
            ("scope", "init", "--help"),
            ("scope", "questions", "--help"),
            ("scope", "check", "--help"),
            ("scope", "compile", "--help"),
        ):
            with self.subTest(arguments=arguments):
                result = self.run_cli(*arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("usage:", result.stdout)

    def test_questions_through_launcher_needs_no_runtime_or_directory(self) -> None:
        result = self.run_cli("scope", "questions")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Scope questions for the service owner", result.stdout)

    def test_registry_row(self) -> None:
        rows = [
            line.split("|")
            for line in (ROOT / "config" / "commands.tsv").read_text().splitlines()
            if line.startswith("scope|")
        ]
        self.assertEqual(len(rows), 1)
        name, mode, host, container, group, activity, _ = rows[0]
        self.assertEqual(
            (mode, host, container, group, activity),
            ("workbench", "scope", "sippycup-workbench", "Preparation", "offline"),
        )


class SchemaAndExampleTests(ScopeTestCase):
    def test_schema_properties_match_the_validator_spec(self) -> None:
        schema = json.loads((ROOT / "schemas" / "scope-v1.schema.json").read_text())
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["const"], "sippycup.dev/scope/v1")
        self.assertEqual(set(schema["properties"]), set(SPEC))
        for key, spec in SPEC.items():
            node = schema["properties"][key]
            if isinstance(spec, dict):
                self.assertFalse(node["additionalProperties"], key)
                self.assertEqual(set(node["properties"]), set(spec), key)
            elif isinstance(spec, list):
                item = node["items"]
                self.assertFalse(item["additionalProperties"], key)
                self.assertEqual(set(item["properties"]), spec[0], key)

    def test_example_is_placeholder_and_cannot_compile_into_an_approved_profile(self) -> None:
        example = ROOT / "examples" / "scope" / "scope.yaml"
        self.assertTrue(example.is_file())
        shutil_target = self.root / "scope.yaml"
        shutil_target.write_bytes(example.read_bytes())
        shutil_target.chmod(0o600)
        report = inspect(shutil_target, now=NOW)
        self.assertFalse(report.ok)
        self.assertFalse(report.fatal, [i.as_dict() for i in report.errors])
        self.assertIn("scope.placeholder_value", {i.code for i in report.errors})
        self.assertIn("scope.authorization_not_approved", {i.code for i in report.errors})
        result = compile_scope(self.root, now=NOW)
        self.assertNotEqual(result.exit_code, 0)
        self.assertNotEqual(result.profile_status, "approved")
        self.assertNotIn("campaign", {item["artifact"] for item in result.generated})
        self.assertEqual(
            yaml.safe_load(example.read_text())["authorization"]["status"], "pending"
        )

    def test_target_env_worksheet_is_retired(self) -> None:
        self.assertFalse((ROOT / "config" / "target.env.example").exists())
        for document in [ROOT / "README.md", *(ROOT / "docs").glob("*.md")]:
            self.assertNotIn("target.env.example", document.read_text(), document.name)


if __name__ == "__main__":
    unittest.main()
