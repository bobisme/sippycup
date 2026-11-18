"""Approved dial destinations and one compiled profile per target (bn-2oqn, bn-3lbc).

Host-side only: no container, capture, or socket. Capture, preflight,
softphone, and offline analyzers are the injected fakes of test_guided_call.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from sippycup import practice  # noqa: E402
from sippycup_workbench import call as guided  # noqa: E402
from sippycup_workbench import cli, matrix  # noqa: E402
from sippycup_workbench import profile as profile_module  # noqa: E402
from sippycup_workbench.advisor import assess, suggested_dial  # noqa: E402
from sippycup_workbench.profile import (  # noqa: E402
    DESTINATIONS_UNRESTRICTED,
    MAX_APPROVED_DESTINATIONS,
    ProfileError,
    approved_destinations,
    destination_refusal,
    load_profile,
    rehearse,
)
from sippycup_workbench.scope import DEST_USER_PATTERN  # noqa: E402
from sippycup_workbench.scope_derive import (  # noqa: E402
    SIDECAR_FILE,
    compile_scope,
    compiled_profiles,
    derivative_state,
    profile_filename,
    profile_key,
    read_sidecar,
)
from test_guided_call import NOW, Fakes, GuidedCallCase, profile_document  # noqa: E402
from test_scope import NOW as SCOPE_NOW  # noqa: E402
from test_scope import ScopeTestCase, complete_scope  # noqa: E402


def restricted(*destinations: str, **overrides) -> dict:
    document = profile_document(**overrides)
    document["target"]["approved_destinations"] = list(destinations)
    return document


class ProfileFieldTests(unittest.TestCase):
    def test_a_profile_without_the_field_is_unrestricted_and_rehearse_says_so(self) -> None:
        document = profile_document()
        self.assertIsNone(approved_destinations(document))
        self.assertIsNone(destination_refusal(document, "anything"))
        result = rehearse(document, now=NOW)
        self.assertTrue(result.ready, result.errors)
        self.assertIn(DESTINATIONS_UNRESTRICTED, result.warnings)
        self.assertIsNone(result.facts["approved_destinations"])

    def test_a_listed_profile_reports_its_destinations_without_a_warning(self) -> None:
        document = restricted("echo", "dtmf", "+4930*#", "1001")
        result = rehearse(document, now=NOW)
        self.assertTrue(result.ready, result.errors)
        self.assertEqual(result.facts["approved_destinations"], ["echo", "dtmf", "+4930*#", "1001"])
        self.assertNotIn(DESTINATIONS_UNRESTRICTED, result.warnings)
        self.assertIsNone(destination_refusal(document, "dtmf"))

    def test_refusal_names_the_approved_list_and_the_scope_never_a_profile_edit(self) -> None:
        message = destination_refusal(restricted("echo", "dtmf"), "ecoh")
        self.assertIsNotNone(message)
        assert message is not None
        self.assertIn("'ecoh'", message)
        self.assertIn("approved: echo, dtmf", message)
        self.assertIn("ask the owner", message)
        self.assertIn("scope.yaml", message)
        self.assertIn("scope compile", message)
        self.assertNotIn("edit the profile", message.lower())
        self.assertNotIn("target.approved_destinations", message)

    def test_matching_is_exact_and_case_sensitive(self) -> None:
        document = restricted("Echo", "1001")
        for wrong in ("echo", "ECHO", "Echo ", "100", "10011", ""):
            with self.subTest(dial=wrong):
                self.assertIsNotNone(destination_refusal(document, wrong))
        self.assertIsNone(destination_refusal(document, "Echo"))

    def test_an_empty_list_approves_no_destination(self) -> None:
        document = restricted()
        result = rehearse(document, now=NOW)
        self.assertTrue(result.ready, result.errors)
        self.assertEqual(result.facts["approved_destinations"], [])
        self.assertIn("approved: none", destination_refusal(document, "echo") or "")

    def test_malformed_lists_are_rehearse_errors_and_never_read_as_unrestricted(self) -> None:
        cases = {
            "not a list": "echo",
            "a mapping": {"echo": True},
            "an integer entry": ["echo", 1001],
            "a null entry": ["echo", None],
            "a forbidden character": ["echo", "ec ho"],
            "a uri": ["sip:echo@192.0.2.10"],
            "an empty string": [""],
            "too long": ["9" * 65],
            "a duplicate": ["echo", "echo"],
            "too many": [f"d{index}" for index in range(MAX_APPROVED_DESTINATIONS + 1)],
        }
        for name, value in cases.items():
            with self.subTest(case=name):
                document = profile_document()
                document["target"]["approved_destinations"] = value
                result = rehearse(document, now=NOW)
                self.assertFalse(result.ready)
                self.assertTrue(any("approved_destinations" in error for error in result.errors), result.errors)
                self.assertNotIn(DESTINATIONS_UNRESTRICTED, result.warnings)
                with self.assertRaises(ProfileError):
                    approved_destinations(document)
                self.assertIsNotNone(destination_refusal(document, "echo"))

    def test_the_count_limit_is_accepted_at_the_limit(self) -> None:
        document = restricted(*[f"d{index}" for index in range(MAX_APPROVED_DESTINATIONS)])
        self.assertTrue(rehearse(document, now=NOW).ready)

    def test_the_profile_uses_the_scope_character_rules(self) -> None:
        self.assertEqual(profile_module.DESTINATION_PATTERN.pattern, DEST_USER_PATTERN.pattern)

    def test_a_security_check_destination_must_be_on_the_list(self) -> None:
        section = {"approved": ["banner-disclosure"], "max_requests": 5, "destination": "echo"}
        document = restricted("echo", "dtmf", security_checks=dict(section))
        self.assertTrue(rehearse(document, now=NOW).ready, rehearse(document, now=NOW).errors)
        document = restricted("dtmf", security_checks=dict(section))
        result = rehearse(document, now=NOW)
        self.assertFalse(result.ready)
        self.assertIn("security_checks.destination 'echo' is not one of target.approved_destinations",
                      result.errors)
        # An unrestricted profile keeps working as before.
        self.assertTrue(rehearse(profile_document(security_checks=dict(section)), now=NOW).ready)

    def test_rehearse_output_shows_the_list_or_that_nothing_is_restricted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.yaml"
            for document, expected in (
                (restricted("echo", "dtmf"), "Destinations: echo, dtmf (the only values call and matrix accept"),
                (restricted(), "Destinations: none (the only values"),
                (profile_document(), "Destinations: NOT RESTRICTED by this profile"),
            ):
                document["authorization"]["valid_from"] = "2020-01-01T00:00:00Z"
                document["authorization"]["valid_until"] = "2099-01-01T00:00:00Z"
                path.write_text(yaml.safe_dump(document), encoding="utf-8")
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = cli.main(["rehearse", str(path)])
                self.assertEqual(code, 0, out.getvalue())
                self.assertIn(expected, out.getvalue())
                self.assertIn("Network activity: none", out.getvalue())
            self.assertIn("WARN:  this profile has no target.approved_destinations", out.getvalue())

    def test_the_schema_describes_the_field(self) -> None:
        schema = json.loads((ROOT / "schemas" / "target-profile-v1.schema.json").read_text())
        field = schema["properties"]["target"]["properties"]["approved_destinations"]
        self.assertEqual(field["maxItems"], MAX_APPROVED_DESTINATIONS)
        self.assertEqual(field["items"]["pattern"], profile_module.DESTINATION_PATTERN.pattern)
        self.assertNotIn("approved_destinations", schema["properties"]["target"]["required"])


class CallGateTests(GuidedCallCase):
    def test_an_unlisted_destination_is_refused_before_any_side_effect(self) -> None:
        self.write_profile(restricted("echo", "dtmf"))
        for dial in ("ecoh", "ECHO", "1001"):
            with self.subTest(dial=dial):
                fakes = Fakes()
                code, value = self.run_call(fakes, destination=dial)
                self.assertEqual(code, 2)
                self.assertEqual(value["state"], "blocked")
                self.assertEqual(value["networkActivity"], "none")
                self.assertIsNone(value["runDirectory"])
                self.assertEqual(fakes.events, [], "no capture, preflight, or call may start")
                self.assertEqual(self.run_directories(), [])
                rendered = guided.render_human(value)
                self.assertIn("Guided call: BLOCKED", rendered)
                self.assertIn(f"BLOCK: destination {dial!r} is not one of the destinations the owner approved",
                              rendered)
                self.assertIn("approved: echo, dtmf", rendered)
                self.assertIn("Nothing was started and no packets were sent.", rendered)
                self.assertTrue(rendered.rstrip().endswith("Network activity: none"))

    def test_the_refusal_comes_before_credentials_and_routing_are_touched(self) -> None:
        self.write_profile(restricted("echo"))
        fakes = Fakes()
        deps = fakes.dependencies(self.work, environ={"PATH": "/usr/bin"})

        def no_route(host, port):  # pragma: no cover - must not be reached
            raise AssertionError("the route lookup ran for a refused destination")

        deps.local_address = no_route
        # The named secret variable is not even set: resolving it would raise.
        code, value = guided.execute(
            self.options(destination="ecoh", username="alice", secret_env="NOT_SET"), deps)
        self.assertEqual((code, value["state"]), (2, "blocked"))
        self.assertEqual(fakes.events, [])

    def test_a_listed_destination_passes_and_the_result_records_the_check(self) -> None:
        self.write_profile(restricted("echo", "dtmf"))
        fakes = Fakes()
        code, value = self.run_call(fakes)
        self.assertEqual(code, 0, value.get("notes"))
        self.assertEqual(value["destination"], {
            "dialed": "echo", "approved": ["echo", "dtmf"], "restricted": True, "onApprovedList": True})
        self.assertIn("Destination:  echo is on the profile's approved destination list",
                      guided.render_human(value))
        recorded = json.loads((self.run_directories()[0] / "result.json").read_text())
        self.assertTrue(recorded["destination"]["onApprovedList"])

    def test_an_unrestricted_profile_still_calls_and_says_it_was_not_checked(self) -> None:
        fakes = Fakes()
        code, value = self.run_call(fakes, destination="ecoh")
        self.assertEqual(code, 0, value.get("notes"))
        self.assertEqual(value["destination"], {
            "dialed": "ecoh", "approved": None, "restricted": False, "onApprovedList": None})
        rendered = guided.render_human(value)
        self.assertIn("Destination:  ecoh (NOT CHECKED: this profile has no target.approved_destinations",
                      rendered)

    def test_dry_run_refuses_an_unlisted_destination_and_shows_the_list(self) -> None:
        self.write_profile(restricted("echo", "dtmf"))
        fakes = Fakes()
        code, value = self.run_call(fakes, destination="ecoh", dry_run=True)
        self.assertEqual(code, 2)
        self.assertFalse(value["ready"])
        self.assertFalse(value["network_activity"])
        self.assertEqual(fakes.events, [])
        self.assertTrue(any("destination 'ecoh' is not one of" in item
                            for item in value["one_call_plan"]["blocking_errors"]))
        rendered = guided.render_human(value)
        self.assertIn("Guided call plan: BLOCKED", rendered)
        self.assertIn("approved dial:   echo, dtmf", rendered)
        self.assertIn("This command sent no packets.", rendered)

        code, value = self.run_call(Fakes(), destination="dtmf", dry_run=True)
        self.assertEqual(code, 0)
        self.assertTrue(value["ready"])
        self.assertEqual(value["softphone"]["approved_destinations"], ["echo", "dtmf"])
        self.assertTrue(value["softphone"]["destination_restricted"])

    def test_dry_run_of_an_unrestricted_profile_says_so(self) -> None:
        code, value = self.run_call(Fakes(), destination="ecoh", dry_run=True)
        self.assertEqual(code, 0)
        self.assertIsNone(value["softphone"]["approved_destinations"])
        self.assertFalse(value["softphone"]["destination_restricted"])
        self.assertIn("approved dial:   NOT RESTRICTED", guided.render_human(value))

    def test_a_malformed_list_blocks_every_destination(self) -> None:
        document = profile_document()
        document["target"]["approved_destinations"] = "echo"
        self.write_profile(document)
        fakes = Fakes()
        code, value = self.run_call(fakes)
        self.assertEqual((code, value["state"]), (2, "blocked"))
        self.assertEqual(fakes.events, [])

    def test_the_command_line_exits_2_and_says_nothing_was_started(self) -> None:
        self.write_profile(restricted("echo", "dtmf"))
        fakes = Fakes()
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = guided.main([str(self.profile), "--dial", "ecoh"], fakes.dependencies(self.work))
        self.assertEqual(code, 2)
        self.assertIn("Nothing was started and no packets were sent.", out.getvalue())
        self.assertIn("approved: echo, dtmf", out.getvalue())
        self.assertEqual(fakes.events, [])
        self.assertEqual(self.run_directories(), [])

    def test_the_result_schema_describes_the_destination_record(self) -> None:
        schema = json.loads((ROOT / "schemas" / "call-result-v1.schema.json").read_text())
        self.assertEqual(set(schema["properties"]["destination"]["required"]),
                         {"dialed", "approved", "restricted", "onApprovedList"})


class MatrixGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.work = Path(self._directory.name) / "work"
        self.engagement = self.work / "engagement"
        self.engagement.mkdir(parents=True)
        self.udp = self.write("target-profile.yaml", restricted("echo", "dtmf", **{"limits.max_calls": 6}))
        self.tcp = self.write("target-profile-tcp.yaml", restricted(
            "echo", **{"target.transport": "tcp", "limits.max_calls": 6}))

    def write(self, name: str, document: dict) -> Path:
        path = self.engagement / name
        path.write_text(yaml.safe_dump(document), encoding="utf-8")
        return path

    def options(self, **values) -> matrix.MatrixOptions:
        defaults = {"profiles": (self.udp, self.tcp), "destination": "echo", "codecs": ("PCMU",)}
        defaults.update(values)
        return matrix.MatrixOptions(**defaults)

    def test_a_destination_on_every_list_plans(self) -> None:
        plan = matrix.build_plan(self.options(), now=NOW, work_root=self.work)
        self.assertTrue(plan["ready"], plan["blockingErrors"])
        lists = {facts["transport"]: facts["approved_destinations"] for facts in plan["profiles"].values()}
        self.assertEqual(lists, {"udp": ["echo", "dtmf"], "tcp": ["echo"]})
        self.assertNotIn("NOTE:", matrix.render_human(plan))

    def test_a_typo_blocks_the_plan_once_per_profile(self) -> None:
        plan = matrix.build_plan(self.options(destination="ecoh"), now=NOW, work_root=self.work)
        self.assertFalse(plan["ready"])
        blocked = [item for item in plan["blockingErrors"] if "destination 'ecoh' is not one of" in item]
        self.assertEqual(len(blocked), 2, plan["blockingErrors"])
        rendered = matrix.render_human(plan)
        self.assertIn("Call matrix plan: BLOCKED", rendered)
        self.assertIn("approved: echo, dtmf", rendered)
        self.assertIn("This command sent no packets.", rendered)

    def test_a_destination_approved_on_one_target_only_blocks_the_other(self) -> None:
        plan = matrix.build_plan(self.options(destination="dtmf"), now=NOW, work_root=self.work)
        self.assertFalse(plan["ready"])
        blocked = [item for item in plan["blockingErrors"] if "destination 'dtmf'" in item]
        self.assertEqual(len(blocked), 1)
        self.assertIn("target-profile-tcp.yaml", blocked[0])
        self.assertIn("approved: echo)", blocked[0])

    def test_run_refuses_with_exit_2_and_places_no_call(self) -> None:
        calls: list = []

        def execute(options, deps):  # pragma: no cover - must not be reached
            calls.append(options)
            raise AssertionError("a cell was started for a refused destination")

        deps = matrix.MatrixDependencies(
            execute=execute, call_dependencies=lambda env: env, now=lambda: NOW,
            sleep=lambda seconds: None, monotonic=lambda: 0.0, environ={"PATH": "/usr/bin"},
            work_root=self.work, install_signal_handlers=False,
        )
        code, value = matrix.run(self.options(destination="ecoh"), deps)
        self.assertEqual(code, matrix.EXIT_REFUSED)
        self.assertEqual(value["state"], "blocked")
        self.assertEqual(value["networkActivity"], "none")
        self.assertEqual(calls, [])
        self.assertFalse((self.engagement / "matrix").exists(), "no matrix directory for a refused plan")
        self.assertFalse((self.engagement / "calls").exists())

    def test_the_command_line_plan_exits_2(self) -> None:
        out = io.StringIO()
        deps = matrix.MatrixDependencies(now=lambda: NOW, work_root=self.work)
        with contextlib.redirect_stdout(out):
            code = matrix.main(["plan", str(self.udp), str(self.tcp), "--dial", "ecoh", "--codecs", "PCMU"], deps)
        self.assertEqual(code, 2)
        self.assertIn("BLOCK:", out.getvalue())

    def test_an_unrestricted_profile_plans_and_the_plan_says_so(self) -> None:
        legacy = self.write("legacy.yaml", profile_document(**{"target.transport": "tcp", "limits.max_calls": 6}))
        plan = matrix.build_plan(self.options(profiles=(self.udp, legacy)), now=NOW, work_root=self.work)
        self.assertTrue(plan["ready"], plan["blockingErrors"])
        self.assertIsNone(plan["profiles"]["work/engagement/legacy.yaml"]["approved_destinations"])
        rendered = matrix.render_human(plan)
        self.assertIn("NOTE: work/engagement/legacy.yaml has no target.approved_destinations", rendered)


def two_target_scope() -> dict:
    """UDP and TLS targets; echo on both, dtmf on both, a reject destination on UDP only."""
    document = complete_scope()
    document["destinations"] = [
        {"name": "echo", "target": "edge", "user": "echo", "expect": "echo"},
        {"name": "dtmf", "target": "edge", "user": "dtmf", "expect": "echo"},
        {"name": "closed", "target": "edge", "user": "9000", "expect": "reject"},
        {"name": "echo-tls", "target": "edge-tls", "user": "echo", "expect": "echo"},
        {"name": "agent-tls", "target": "edge-tls", "user": "+49301234", "expect": "agent"},
    ]
    return document


class CompileProfilesTests(ScopeTestCase):
    def compile(self, **kwargs):
        return compile_scope(self.root, now=SCOPE_NOW, **kwargs)

    def test_one_profile_per_target_with_predictable_names(self) -> None:
        self.write_scope(two_target_scope())
        result = self.compile()
        self.assertEqual(result.exit_code, 0, result.as_dict())
        self.assertEqual(result.expected, 4)
        self.assertEqual(
            [(item["artifact"], Path(item["path"]).name, item.get("target")) for item in result.generated],
            [("profile", "target-profile.yaml", "edge"),
             ("profile:edge-tls", "target-profile-edge-tls.yaml", "edge-tls"),
             ("campaign", "campaign.yaml", None), ("expectations", "expectations.yaml", None)],
        )
        self.assertEqual(profile_filename(None), "target-profile.yaml")
        self.assertEqual(profile_filename("edge-tls"), "target-profile-edge-tls.yaml")
        self.assertEqual(profile_key("edge-tls"), "profile:edge-tls")
        first = load_profile(self.root / "target-profile.yaml")
        second = load_profile(self.root / "target-profile-edge-tls.yaml")
        self.assertEqual((self.root / "target-profile-edge-tls.yaml").stat().st_mode & 0o777, 0o600)
        self.assertEqual(first["name"], "ferivox-staging")
        self.assertEqual(second["name"], "ferivox-staging-edge-tls")
        self.assertEqual((first["target"]["transport"], first["target"]["port"]), ("udp", 5060))
        self.assertEqual((second["target"]["transport"], second["target"]["port"]), ("tls", 5061))
        self.assertNotIn("tls_server_name", first["target"])
        self.assertEqual(second["target"]["tls_server_name"], "sbc.ferivox.test")
        # Each target's own destinations, rejecting ones included.
        self.assertEqual(first["target"]["approved_destinations"], ["echo", "dtmf", "9000"])
        self.assertEqual(second["target"]["approved_destinations"], ["echo", "+49301234"])
        # The same approval, window, addresses, limits, and media scope.
        for key in ("authorization", "limits", "media", "features", "capture"):
            self.assertEqual(first[key], second[key], key)
        self.assertEqual(first["target"]["approved_addresses"], second["target"]["approved_addresses"])
        for document in (first, second):
            rehearsal = rehearse(document, now=SCOPE_NOW)
            self.assertTrue(rehearsal.ready, rehearsal.errors)
            self.assertTrue(guided.host_is_approved_literal(document))
        notes = " ".join(result.notes)
        self.assertIn("one target profile per target: target-profile.yaml (edge, udp port 5060); "
                      "target-profile-edge-tls.yaml (edge-tls, tls port 5061)", notes)

    def test_the_tls_ca_file_goes_only_into_the_tls_profile(self) -> None:
        import subprocess

        work = self.root.parent / "work"
        engagement = work / "eng"
        engagement.mkdir(parents=True)
        key = engagement / "ca.key"
        certificate = engagement / "owner-ca.crt"
        made = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out",
             str(certificate), "-days", "2", "-subj", "/CN=fixture-ca"],
            capture_output=True, check=False)
        if made.returncode != 0:
            self.skipTest("openssl is not available")
        key.unlink()
        document = two_target_scope()
        document["targets"][1]["tls_ca_file"] = "work/eng/owner-ca.crt"
        self.root = engagement
        self.write_scope(document)
        from unittest import mock

        with mock.patch.dict("os.environ", {"SIPPYCUP_WORK_ROOT": str(work)}):
            result = self.compile()
        self.assertEqual(result.exit_code, 0, result.as_dict())
        self.assertNotIn("tls_ca_file", load_profile(engagement / "target-profile.yaml")["target"])
        self.assertEqual(load_profile(engagement / "target-profile-edge-tls.yaml")["target"]["tls_ca_file"],
                         "work/eng/owner-ca.crt")

    def test_a_single_target_scope_writes_only_the_familiar_profile(self) -> None:
        document = two_target_scope()
        del document["targets"][1]
        document["signaling"] = {"networks": ["10.20.30.0/24"], "ports": [5060], "transports": ["udp"]}
        document["destinations"] = [{"name": "echo", "user": "echo", "expect": "echo"},
                                    {"name": "dtmf", "user": "dtmf", "expect": "echo"}]
        self.write_scope(document)
        result = self.compile()
        self.assertEqual(result.exit_code, 0, result.as_dict())
        self.assertEqual(result.expected, 3)
        self.assertEqual(sorted(path.name for path in self.root.glob("target-profile*")), ["target-profile.yaml"])
        profile = load_profile(self.root / "target-profile.yaml")
        # A lone target is implied for a destination without `target:`.
        self.assertEqual(profile["target"]["approved_destinations"], ["echo", "dtmf"])
        self.assertFalse(any("one target profile per target" in note for note in result.notes))

    def test_a_target_without_destinations_gets_an_empty_list(self) -> None:
        document = two_target_scope()
        document["destinations"] = [item for item in document["destinations"] if item["target"] == "edge"]
        self.write_scope(document)
        self.assertEqual(self.compile().exit_code, 0)
        second = load_profile(self.root / "target-profile-edge-tls.yaml")
        self.assertEqual(second["target"]["approved_destinations"], [])
        self.assertIn("approved: none", destination_refusal(second, "echo") or "")

    def test_security_checks_go_only_into_the_first_profile(self) -> None:
        document = two_target_scope()
        document["test_scope"]["allowed_classes"] = ["options", "call", "security-checks"]
        document["security_checks"] = {"approved": ["banner-disclosure"], "max_requests": 10}
        self.write_scope(document)
        result = self.compile()
        self.assertEqual(result.exit_code, 0, result.as_dict())
        self.assertIn("security_checks", load_profile(self.root / "target-profile.yaml"))
        self.assertNotIn("security_checks", load_profile(self.root / "target-profile-edge-tls.yaml"))

    def test_staleness_covers_every_profile(self) -> None:
        self.write_scope(two_target_scope())
        self.assertEqual(self.compile().exit_code, 0)
        state = derivative_state(self.root)
        self.assertEqual(state["state"], "current")
        self.assertEqual(list(state["items"])[:2], ["profile", "profile:edge-tls"])
        self.assertEqual(state["items"]["profile:edge-tls"]["path"], "target-profile-edge-tls.yaml")
        self.assertEqual(state["items"]["profile:edge-tls"]["target"], "edge-tls")
        self.assertEqual(
            [(item["key"], item["target"], item["path"], item["state"], item["first"])
             for item in compiled_profiles(self.root)],
            [("profile", "edge", "target-profile.yaml", "current", True),
             ("profile:edge-tls", "edge-tls", "target-profile-edge-tls.yaml", "current", False)],
        )
        extra = self.root / "target-profile-edge-tls.yaml"
        extra.write_text(extra.read_text().replace("port: 5061", "port: 5999"))
        state = derivative_state(self.root)
        self.assertEqual(state["state"], "stale")
        self.assertEqual(state["items"]["profile:edge-tls"]["state"], "edited")
        self.assertEqual(state["items"]["profile"]["state"], "current")
        # Compile refuses to clobber the hand edit; --force regenerates it.
        result = self.compile()
        self.assertEqual(result.exit_code, 2)
        self.assertEqual([(item.code, item.field) for item in result.refused],
                         [("scope.derivative_modified", "target-profile-edge-tls.yaml")])
        self.assertIn("port: 5999", extra.read_text())
        self.assertEqual(self.compile(force=True).exit_code, 0)
        self.assertEqual(load_profile(extra)["target"]["port"], 5061)
        extra.unlink()
        self.assertEqual(derivative_state(self.root)["items"]["profile:edge-tls"]["state"], "missing")
        self.assertEqual(compiled_profiles(self.root)[1]["state"], "missing")
        scope = self.root / "scope.yaml"
        scope.write_text(scope.read_text().replace("calls: 10", "calls: 8"))
        self.assertTrue(all(item["scopeChanged"] for name, item in derivative_state(self.root)["items"].items()
                            if name != "profile:edge-tls"))

    def test_a_hand_copied_second_profile_is_refused_until_forced(self) -> None:
        self.write_scope(two_target_scope())
        hand = self.root / "target-profile-edge-tls.yaml"
        hand.write_text("name: my hand copy\n", encoding="utf-8")
        result = self.compile()
        self.assertEqual(result.exit_code, 2)
        self.assertEqual([(item.code, item.field) for item in result.refused],
                         [("scope.derivative_unmanaged", "target-profile-edge-tls.yaml")])
        self.assertEqual(hand.read_text(), "name: my hand copy\n")
        self.assertFalse((self.root / "target-profile.yaml").exists(), "a refusal writes nothing at all")
        self.assertEqual(self.compile(force=True).exit_code, 0)
        self.assertEqual(load_profile(hand)["target"]["transport"], "tls")

    def test_a_removed_target_loses_its_profile(self) -> None:
        self.write_scope(two_target_scope())
        self.assertEqual(self.compile().exit_code, 0)
        extra = self.root / "target-profile-edge-tls.yaml"
        self.assertTrue(extra.is_file())
        document = two_target_scope()
        del document["targets"][1]
        document["destinations"] = [item for item in document["destinations"] if item["target"] == "edge"]
        self.write_scope(document)
        result = self.compile()
        self.assertEqual(result.exit_code, 0, result.as_dict())
        self.assertFalse(extra.exists())
        self.assertEqual(result.removed, ["target-profile-edge-tls.yaml"])
        self.assertIn("removed target-profile-edge-tls.yaml", " ".join(result.notes))
        self.assertEqual(derivative_state(self.root)["state"], "current")
        self.assertNotIn("profile:edge-tls", json.loads((self.root / SIDECAR_FILE).read_text())["derivatives"])

    def test_an_edited_profile_of_a_removed_target_is_left_and_reported(self) -> None:
        self.write_scope(two_target_scope())
        self.assertEqual(self.compile().exit_code, 0)
        extra = self.root / "target-profile-edge-tls.yaml"
        extra.write_text(extra.read_text() + "# my note\n")
        document = two_target_scope()
        del document["targets"][1]
        document["destinations"] = [item for item in document["destinations"] if item["target"] == "edge"]
        self.write_scope(document)
        result = self.compile()
        self.assertEqual(result.exit_code, 0, result.as_dict())
        self.assertTrue(extra.exists())
        self.assertEqual(result.removed, [])
        self.assertIn("was edited by hand", " ".join(result.notes))
        self.assertIn("do not use it", " ".join(result.notes))

    def test_a_renamed_target_moves_its_profile(self) -> None:
        self.write_scope(two_target_scope())
        self.assertEqual(self.compile().exit_code, 0)
        text = yaml.safe_dump(two_target_scope(), sort_keys=False).replace("edge-tls", "secure")
        self.write_scope(text)
        result = self.compile()
        self.assertEqual(result.exit_code, 0, result.as_dict())
        self.assertEqual(sorted(path.name for path in self.root.glob("target-profile*")),
                         ["target-profile-secure.yaml", "target-profile.yaml"])

    def test_the_sidecar_accepts_only_the_predictable_path_for_a_further_profile(self) -> None:
        self.write_scope(two_target_scope())
        self.assertEqual(self.compile().exit_code, 0)
        path = self.root / SIDECAR_FILE
        good = json.loads(path.read_text())
        for mutate in (
            lambda value: value["derivatives"]["profile:edge-tls"].update(path="scope.yaml"),
            lambda value: value["derivatives"]["profile:edge-tls"].update(path="../other/target-profile-edge-tls.yaml"),
            lambda value: value["derivatives"].update({"profile:Bad Name": value["derivatives"]["profile:edge-tls"]}),
            lambda value: value["derivatives"].update({"other": value["derivatives"]["profile"]}),
        ):
            value = copy.deepcopy(good)
            mutate(value)
            path.write_text(json.dumps(value))
            sidecar, problem = read_sidecar(self.root)
            self.assertIsNone(sidecar)
            self.assertIn("cannot trust", problem or "")
            self.assertEqual(derivative_state(self.root)["state"], "invalid")
            self.assertEqual(compiled_profiles(self.root), [])
        self.assertTrue((self.root / "scope.yaml").is_file(), "an untrusted sidecar never removes a file")

    def test_a_pending_scope_writes_pending_profiles_for_every_target(self) -> None:
        document = two_target_scope()
        document["authorization"]["status"] = "pending"
        self.write_scope(document)
        result = self.compile()
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.profile_status, "pending")
        for name in ("target-profile.yaml", "target-profile-edge-tls.yaml"):
            profile = load_profile(self.root / name)
            self.assertEqual(profile["authorization"]["status"], "pending")
            self.assertFalse(rehearse(profile, now=SCOPE_NOW).ready)

    def test_invalid_destinations_never_reach_a_profile(self) -> None:
        document = two_target_scope()
        document["destinations"].append({"name": "bad", "target": "edge", "user": "has space", "expect": "echo"})
        self.write_scope(document)
        result = self.compile()
        self.assertEqual(result.exit_code, 1)
        profile = load_profile(self.root / "target-profile.yaml")
        self.assertEqual(profile["authorization"]["status"], "pending")
        self.assertEqual(profile["target"]["approved_destinations"], ["echo", "dtmf", "9000"])

    def test_the_command_line_prints_every_profile(self) -> None:
        self.write_scope(two_target_scope())
        code, out, _err = self.run_main("scope", "compile", str(self.root))
        # The fixture window is wide open, so the real clock compiles it too.
        self.assertEqual(code, 0, out)
        self.assertIn("Wrote profile: ", out)
        self.assertIn("Wrote profile:edge-tls: ", out)
        self.assertIn("target-profile-edge-tls.yaml", out)
        self.assertIn("NOTE: one target profile per target", out)


class AdvisorAndSuggestionTests(ScopeTestCase):
    def test_a_suggestion_is_on_the_profiles_target_and_on_its_list(self) -> None:
        scope = two_target_scope()
        scope["destinations"].insert(0, {"name": "tls-first", "target": "edge-tls", "user": "7777", "expect": "echo"})
        scope["destinations"].insert(1, {"name": "closed-first", "target": "edge", "user": "9001", "expect": "reject"})
        self.assertEqual(suggested_dial(scope), "echo", "the first target's first non-rejecting destination")
        self.assertEqual(suggested_dial(scope, None, "edge-tls"), "7777")
        self.assertEqual(suggested_dial(scope, restricted("dtmf")), "dtmf", "never one the profile refuses")
        self.assertIsNone(suggested_dial(scope, restricted()))
        self.assertIsNone(suggested_dial(scope, restricted("zzz"), "edge-tls"))
        self.assertIsNone(suggested_dial(None))
        malformed = profile_document()
        malformed["target"]["approved_destinations"] = "echo"
        self.assertIsNone(suggested_dial(scope, malformed))

    def test_status_reports_and_blocks_on_every_compiled_profile(self) -> None:
        from sippycup_workbench.journal import initialize

        initialize(self.root, title="Fixture", owner="Quad")
        self.write_scope(two_target_scope())
        self.assertEqual(compile_scope(self.root, now=SCOPE_NOW).exit_code, 0)
        status = assess(self.root, now=SCOPE_NOW)
        others = status["facts"]["profile"]["otherProfiles"]
        self.assertEqual([(item["target"], item["state"], item["ready"], item["transport"]) for item in others],
                         [("edge-tls", "current", True, "tls")])
        self.assertEqual(others[0]["approvedDestinations"], ["echo", "+49301234"])
        self.assertFalse(any("target-profile-edge-tls.yaml" in item for item in status["blockers"]))
        dry = next(item for item in status["nextActions"] if item["id"] == "review-guided-call-dry-run")
        self.assertEqual(dry["argv"][dry["argv"].index("--dial") + 1], "echo")

        extra = self.root / "target-profile-edge-tls.yaml"
        extra.write_text(extra.read_text().replace("status: approved", "status: revoked"))
        status = assess(self.root, now=SCOPE_NOW)
        self.assertIn("target profile target-profile-edge-tls.yaml (target edge-tls) rehearsal is blocked",
                      status["blockers"])
        self.assertTrue(any("profile:edge-tls (edited)" in item for item in status["blockers"]), status["blockers"])
        action = next(item for item in status["nextActions"] if item["id"] == "rehearse-target-profile-edge-tls")
        self.assertEqual(action["argv"][:2], ["./bin/sippycup", "rehearse"])


class PracticeProfileTests(unittest.TestCase):
    def test_every_practice_template_lists_every_practice_destination(self) -> None:
        templates = sorted((ROOT / "examples" / "practice").glob("target-profile*.template.yaml"))
        self.assertEqual(len(templates), 4)
        for path in templates:
            with self.subTest(template=path.name):
                document = yaml.safe_load(path.read_text(encoding="utf-8"))
                self.assertEqual(tuple(document["target"]["approved_destinations"]), practice.PROFILE_DESTINATIONS)

    def test_the_list_covers_the_catalog_the_aliases_and_the_drill(self) -> None:
        from sippycup import practice_drill

        listed = set(practice.PROFILE_DESTINATIONS)
        self.assertEqual(len(listed), len(practice.PROFILE_DESTINATIONS))
        self.assertLessEqual(len(listed), MAX_APPROVED_DESTINATIONS)
        self.assertLessEqual(set(practice.DESTINATIONS), listed)
        self.assertLessEqual({scenario.dial for scenario in practice_drill.SCENARIOS}, listed)
        self.assertIn(practice.MISSING_DESTINATION, listed)
        self.assertNotIn(practice.MISSING_DESTINATION, practice.DESTINATIONS)
        self.assertNotIn("ecoh", listed)
        dialplan = (ROOT / "practice-target" / "asterisk" / "extensions.conf").read_text(encoding="utf-8")
        for alias in practice.DESTINATION_ALIASES:
            self.assertIn(f"exten => {alias},", dialplan)
        self.assertNotIn(f"exten => {practice.MISSING_DESTINATION},", dialplan)

    def test_rendered_practice_profiles_rehearse_and_refuse_a_typo(self) -> None:
        from datetime import datetime, timezone

        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "examples").mkdir()
            (project / "work").mkdir()
            import shutil

            shutil.copytree(ROOT / "examples" / "practice", project / "examples" / "practice")
            shutil.copytree(ROOT / "media", project / "media")
            now = datetime.now(timezone.utc)
            practice.prepare(project, address="127.0.0.2", container="unit", image="unit", now=now)
            state = practice.state_dir(project)
            for name in practice.APPROVED_PROFILES:
                with self.subTest(profile=name):
                    document = load_profile(state / name)
                    result = rehearse(document, now=now + timedelta(minutes=1), work_root=project / "work")
                    # `up` (not `prepare`) creates the practice CA the TLS profiles name.
                    self.assertEqual([error for error in result.errors if "tls_ca_file" not in error], [])
                    self.assertEqual(tuple(result.facts["approved_destinations"]), practice.PROFILE_DESTINATIONS)
                    self.assertNotIn(DESTINATIONS_UNRESTRICTED, result.warnings)
                    self.assertIsNotNone(destination_refusal(document, "ecoh"))
                    self.assertIsNone(destination_refusal(document, "echo"))
                    self.assertIsNone(destination_refusal(document, practice.MISSING_DESTINATION))


if __name__ == "__main__":
    unittest.main()
