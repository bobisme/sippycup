"""Platform, production-safety, and application-surface answers in the scope file.

Offline only: nothing here opens a socket or starts a container.
"""

from __future__ import annotations

import copy
import json
import sys
import unittest
from datetime import timedelta
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))

from cockpit_support import NOW as COCKPIT_NOW  # noqa: E402
from cockpit_support import make_engagement, make_repo, scope_text, write_scope  # noqa: E402
from test_scope import DELETE, NOW, ROOT, ScopeTestCase, complete_scope, mutate  # noqa: E402

from sippycup_cockpit import ready  # noqa: E402
from sippycup_cockpit.model import build_model  # noqa: E402
from sippycup_cockpit.render import render_dashboard  # noqa: E402
from sippycup_workbench.advisor import assess  # noqa: E402
from sippycup_workbench.scope import create_scope, inspect  # noqa: E402
from sippycup_workbench.scope_app import (  # noqa: E402
    APP_QUESTIONS,
    APP_SPEC,
    PRODUCTION_SAFETY,
    readiness,
)
from sippycup_workbench.scope_app_derive import FILENAME, VERSION, existing_state, state_for  # noqa: E402
from sippycup_workbench.scope_derive import SIDECAR_FILE, compile_scope  # noqa: E402
from sippycup_workbench.scope_questions import QUESTIONS, render_questions  # noqa: E402

ERRORS = "error"
WARNINGS = "warning"


def platform_section() -> dict:
    """Every platform answer given, for a production system with real customers."""
    return {
        "name": "Ferivox Cloud PBX",
        "components": {
            "sip_edge": "in-scope", "media_servers": "in-scope", "admin_console": "in-scope",
            "customer_web_app": "out-of-scope", "api": "in-scope", "websocket_webrtc": "in-scope",
            "provisioning": "out-of-scope", "voicemail": "in-scope", "ivr": "out-of-scope",
            "conference": "out-of-scope", "recording": "out-of-scope",
        },
        "out_of_scope": ["billing", "the public marketing site"],
        "environment": {
            "kind": "production", "real_customers": True, "test_tenant": "sippycup-test",
            "never_touch": ["real voicemail", "call records"],
        },
        "third_parties": {
            "hosting": {"provider": "Northwind Hosting", "permission": "permitted", "reference": "ticket NW-4471"},
            "cdn_waf": {"provider": None, "permission": "out-of-path", "reference": None},
            "pstn_carrier": {"provider": None, "permission": "out-of-path", "reference": None},
            "sms": {"provider": None, "permission": "out-of-path", "reference": None},
            "email": {"provider": "Northwind Mail", "permission": "permitted", "reference": "mail of 12 Nov"},
        },
        "dialing": {
            "reach": {"echo": "on-net", "echo-tls": "on-net"},
            "never_dial": ["112", "911"],
            "never_dial_prefixes": ["00", "0900"],
            "toll": "no-cost",
        },
        "operations": {
            "allowed_hours": "weekdays 22:00 to 06:00 Europe/Amsterdam",
            "max_concurrent_calls": 2,
            "max_requests_per_second": 5,
            "blocking": "five failed logins ban the source for an hour; the duty engineer lifts it",
            "emergency_contact": {"name": "Quad", "channel": "duty phone"},
            "stop_signal": "the word HALT by phone or chat",
        },
        "addressing": [
            {"name": "sbc.ferivox.test", "addresses": ["10.20.30.40"], "shared": False, "changing": False},
            {"name": "admin.ferivox.test", "addresses": ["10.20.40.5"], "shared": False, "changing": False},
        ],
    }


def application_section() -> dict:
    return {
        "surfaces": [
            {"name": "admin-console", "kind": "browser", "status": "in-scope",
             "base_url": "https://admin.ferivox.test", "connect_address": "10.20.40.5", "connect_port": 443,
             "tls_server_name": "admin.ferivox.test", "tls_ca": "public"},
            {"name": "tenant-api", "kind": "api", "status": "in-scope",
             "base_url": "https://api.ferivox.test/v2", "connect_address": "10.20.40.6", "connect_port": 8443,
             "tls_server_name": "api.ferivox.test", "tls_ca": "public"},
            {"name": "browser-calling", "kind": "websocket", "status": "in-scope",
             "base_url": "wss://rtc.ferivox.test", "connect_address": "10.20.40.7", "connect_port": 443,
             "tls_server_name": "rtc.ferivox.test", "tls_ca": "public",
             "allowed_origins": ["https://app.ferivox.test"]},
        ],
        "identities": [
            {"id": "admin-test", "role": "admin", "tenant": "sippycup-test", "credential_ref": "admin-test"},
            {"id": "user-test", "role": "customer-user", "tenant": "sippycup-test-b", "credential_ref": "user-test"},
        ],
        "object_classes": ["voicemail", "greeting"],
        "route_inventory": {"kind": "openapi", "file": "work/ferivox/openapi.json"},
    }


def platform_scope() -> dict:
    document = complete_scope()
    document["platform"] = platform_section()
    document["application"] = application_section()
    return document


def strings(node) -> set[str]:
    if isinstance(node, dict):
        return set().union(*(strings(value) for value in node.values())) if node else set()
    if isinstance(node, list):
        return set().union(*(strings(value) for value in node)) if node else set()
    return {node} if isinstance(node, str) else set()


def keys(node) -> set[str]:
    if isinstance(node, dict):
        return set(node) | (set().union(*(keys(value) for value in node.values())) if node else set())
    if isinstance(node, list):
        return set().union(*(keys(value) for value in node)) if node else set()
    return set()


class PlatformCase(ScopeTestCase):
    def report(self, document: dict):
        self.write_scope(document)
        return inspect(self.root / "scope.yaml", now=NOW)

    def findings(self, document: dict, severity: str) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for item in self.report(document).findings:
            if item.severity == severity:
                result.setdefault(item.code, []).append(item.field)
        return result

    def record(self) -> dict:
        return yaml.safe_load((self.root / FILENAME).read_text())


class OldFileCompatibilityTests(PlatformCase):
    def test_a_scope_without_the_sections_is_unchanged(self) -> None:
        report = self.report(complete_scope())
        self.assertTrue(report.ok, [item.as_dict() for item in report.findings])
        self.assertEqual([], report.warnings)
        result = compile_scope(self.root, now=NOW)
        self.assertEqual(0, result.exit_code)
        self.assertEqual({"profile", "campaign", "expectations"}, {item["artifact"] for item in result.generated})
        self.assertIsNone(result.as_dict()["applicationSurfaces"])
        self.assertFalse((self.root / FILENAME).exists())
        self.assertFalse(any("application" in note for note in result.notes))
        self.assertFalse(readiness(report)["recorded"])

    def test_null_sections_count_as_absent(self) -> None:
        document = complete_scope()
        document["platform"] = None
        document["application"] = None
        report = self.report(document)
        self.assertTrue(report.ok)
        self.assertEqual([], report.warnings)

    def test_default_init_has_no_platform_section_and_platform_flag_adds_both(self) -> None:
        path = create_scope(self.root)
        document = yaml.safe_load(path.read_text())
        self.assertNotIn("platform", document)
        self.assertNotIn("application", document)
        self.assertIn("scope init DIR --platform", path.read_text())
        path.unlink()
        code, out, _ = self.run_main("scope", "init", str(self.root), "--platform")
        self.assertEqual(0, code, out)
        document = yaml.safe_load(path.read_text())
        self.assertEqual(set(APP_SPEC["platform"]), set(document["platform"]))
        self.assertEqual(set(APP_SPEC["application"]), set(document["application"]))
        report = inspect(path, now=NOW)
        self.assertFalse(report.fatal, [item.as_dict() for item in report.errors])
        self.assertFalse(any(item.field.startswith(("platform", "application")) for item in report.errors))

    def test_old_scope_question_sheet_keeps_part_one_and_explains_part_two(self) -> None:
        self.write_scope(complete_scope())
        code, out, _ = self.run_main("scope", "questions", str(self.root))
        self.assertEqual(0, code)
        first, second = out.split("# Part 2", 1)
        self.assertEqual(len(QUESTIONS), first.count("(answered)") + first.count("(unanswered)")
                         + first.count("(not-applicable)"))
        self.assertIn("no platform or application section yet", second)
        self.assertNotIn("(answered)", second)

    def test_old_scope_has_no_cockpit_platform_line_and_no_ready_line(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            repo = make_repo(Path(directory))
            root = make_engagement(repo)
            write_scope(root, scope_text(valid_from=COCKPIT_NOW - timedelta(hours=1),
                                         valid_until=COCKPIT_NOW + timedelta(hours=3)))
            compile_scope(root, now=COCKPIT_NOW)
            model = build_model(root, repo=repo, now=COCKPIT_NOW)
            text = "\n".join(render_dashboard(model))
            self.assertNotIn("Platform  ", text)
            self.assertNotIn("Web surfaces", text)
            self.assertNotIn("platform and web answers", text)
            from sippycup_cockpit.platform_scope import check_platform

            self.assertIsNone(check_platform(model))


class PendingScopeTests(PlatformCase):
    def test_empty_sections_are_open_never_errors(self) -> None:
        create_scope(self.root, platform=True)
        report = inspect(self.root / "scope.yaml", now=NOW)
        self.assertFalse(any(item.field.startswith(("platform", "application")) for item in report.errors))
        codes = {item.code for item in report.warnings}
        self.assertIn("scope.production_safety_open", codes)
        self.assertIn("scope.platform_open", codes)
        facts = readiness(report)
        self.assertEqual(len(APP_QUESTIONS), len(facts["open"]))
        self.assertEqual({"unanswered"}, {item["state"] for item in facts["open"]})
        self.assertEqual("unanswered", facts["environment"])
        self.assertTrue(facts["productionSafety"]["applies"], "an unanswered environment is treated as production")

    def test_pending_and_unknown_are_shown_as_open_not_as_not_applicable(self) -> None:
        document = platform_scope()
        document["platform"]["environment"]["kind"] = "pending"
        document["platform"]["third_parties"]["cdn_waf"]["permission"] = "unknown"
        document["platform"]["components"]["api"] = "unknown"
        document["application"]["route_inventory"] = {"kind": "pending", "file": None}
        document["application"]["identities"] = "pending"
        self.write_scope(document)
        _, out, _ = self.run_main("scope", "questions", str(self.root))
        part = out.split("# Part 2", 1)[1]
        flat = " ".join(part.split())
        for identifier, state in (("P1.", "unknown"), ("P3.", "pending"), ("P8.", "unknown"),
                                  ("A4.", "pending"), ("A6.", "pending"), ("P2.", "answered")):
            start = flat.index(f" {identifier} ")
            end = flat.index("Why we ask:", start)
            self.assertIn(f"({state})", flat[start:end], identifier)
        self.assertNotIn("(not-applicable)", part)
        import re

        whole = re.findall(r"\[(?:x| |\?|n/a)\] \((?:answered|unanswered|pending|unknown)\)$", part, re.M)
        self.assertEqual(len(APP_QUESTIONS), len(whole), "a state tag is never split across two lines")
        report = inspect(self.root / "scope.yaml", now=NOW)
        self.assertTrue(report.ok, [item.as_dict() for item in report.errors])

    def test_not_applicable_only_when_the_owner_ruled_the_part_out(self) -> None:
        document = platform_scope()
        for name in ("admin_console", "customer_web_app", "api", "websocket_webrtc"):
            document["platform"]["components"][name] = "out-of-scope"
        document["application"] = {"surfaces": [], "identities": [], "object_classes": [],
                                   "route_inventory": {"kind": None, "file": None}}
        states = readiness(self.report(document))["states"]
        self.assertEqual({"not-applicable"}, {states[key] for key in ("A1", "A2", "A3", "A4", "A5", "A6")})
        document["platform"]["components"]["api"] = "pending"
        states = readiness(self.report(document))["states"]
        self.assertEqual("unanswered", states["A1"])
        self.assertEqual("not-applicable", states["A3"])


class IncompleteScopeTests(PlatformCase):
    def incomplete(self) -> dict:
        document = platform_scope()
        document["platform"]["third_parties"]["hosting"] = {
            "provider": "Northwind Hosting", "permission": "pending", "reference": None}
        document["platform"]["operations"]["stop_signal"] = None
        document["application"]["surfaces"][0]["connect_address"] = "pending"
        document["application"]["surfaces"][1]["status"] = "unknown"
        return document

    def test_open_application_answers_do_not_block_the_sip_derivatives(self) -> None:
        report = self.report(self.incomplete())
        self.assertTrue(report.ok, [item.as_dict() for item in report.errors])
        result = compile_scope(self.root, now=NOW)
        self.assertEqual(0, result.exit_code, result.as_dict())
        self.assertEqual("approved", result.profile_status)
        self.assertEqual({"profile", "campaign", "expectations"}, {item["artifact"] for item in result.generated})
        self.assertEqual("application-surfaces", result.as_dict()["applicationSurfaces"]["artifact"])

    def test_open_answers_are_warnings_for_the_surface_they_gate(self) -> None:
        warnings = self.findings(self.incomplete(), WARNINGS)
        self.assertEqual(["application.surfaces[0]", "application.surfaces[2]"], warnings["scope.surface_not_ready"])
        self.assertEqual(["platform.third_parties.hosting"], warnings["scope.third_party_unresolved"])
        self.assertIn("scope.production_safety_open", warnings)
        self.assertIn("scope.platform_open", warnings)
        message = next(item.message for item in self.report(self.incomplete()).warnings
                       if item.code == "scope.production_safety_open")
        self.assertIn("P7 (pending)", message)
        self.assertIn("P17 (unanswered)", message)

    def test_record_marks_pending_undecided_and_never_approves_an_open_surface(self) -> None:
        self.write_scope(self.incomplete())
        compile_scope(self.root, now=NOW)
        record = self.record()
        self.assertEqual(VERSION, record["apiVersion"])
        self.assertEqual({"approved": [], "pending": ["admin-console", "browser-calling"],
                          "undecided": ["tenant-api"], "out-of-scope": []}, record["summary"])
        admin = record["surfaces"][0]
        self.assertEqual("pending", admin["connectAddress"])
        self.assertIn("connect address is pending", admin["open"])
        self.assertEqual("FERIVOX-2026-114", record["authorization"]["approvalId"])
        self.assertEqual("2099-12-31T17:00:00+01:00", record["authorization"]["validUntil"])
        self.assertFalse(record["webSecurityContract"]["validated"])
        self.assertIn("No live application runner exists", record["notice"])
        self.assertEqual(0o600, (self.root / FILENAME).stat().st_mode & 0o777)

    def test_production_with_real_customers_but_no_never_touch_list_or_stop_contact(self) -> None:
        document = platform_scope()
        document["platform"]["environment"]["never_touch"] = []
        document["platform"]["operations"]["emergency_contact"] = {"name": None, "channel": None}
        report = self.report(document)
        self.assertTrue(report.ok)
        message = next(item.message for item in report.warnings if item.code == "scope.production_safety_open")
        self.assertIn("the scope says production", message)
        self.assertIn("P6 (unanswered)", message)
        self.assertIn("P17 (unanswered)", message)
        self.assertEqual({"P6", "P17"} & set(PRODUCTION_SAFETY), {"P6", "P17"})

    def test_staging_has_no_production_safety_warning(self) -> None:
        document = platform_scope()
        document["platform"]["environment"]["kind"] = "staging"
        document["platform"]["operations"]["stop_signal"] = None
        warnings = self.findings(document, WARNINGS)
        self.assertNotIn("scope.production_safety_open", warnings)
        self.assertIn("scope.platform_open", warnings)

    def test_unrecorded_reach_and_shared_or_changing_addresses_warn(self) -> None:
        document = platform_scope()
        del document["platform"]["dialing"]["reach"]["echo-tls"]
        document["platform"]["addressing"][0] |= {"shared": True, "changing": True}
        document["platform"]["addressing"][1] |= {"shared": True}
        warnings = self.findings(document, WARNINGS)
        self.assertEqual(["platform.dialing.reach.echo-tls"], warnings["scope.destination_reach_open"])
        self.assertEqual(["platform.addressing[0].shared", "platform.addressing[0].shared",
                          "platform.addressing[1].shared"], warnings["scope.address_shared"])
        self.assertIn("scope.address_changing", warnings)
        document["platform"]["third_parties"]["pstn_carrier"]["permission"] = "pending"
        self.assertEqual(["platform.third_parties.pstn_carrier"],
                         self.findings(document, WARNINGS)["scope.third_party_unresolved"])


class CompleteScopeTests(PlatformCase):
    def test_complete_answers_have_no_findings_and_every_surface_is_approved(self) -> None:
        report = self.report(platform_scope())
        self.assertTrue(report.ok, [item.as_dict() for item in report.errors])
        self.assertEqual([], [item.as_dict() for item in report.warnings])
        facts = readiness(report)
        self.assertEqual([], facts["open"])
        result = compile_scope(self.root, now=NOW)
        self.assertEqual(0, result.exit_code)
        record = self.record()
        self.assertEqual(["admin-console", "tenant-api", "browser-calling"], record["summary"]["approved"])
        self.assertEqual([], record["openQuestions"])
        self.assertEqual("current", state_for(self.root, report.sha256, True))

    def test_a_ready_surface_is_not_approved_while_the_authorization_is_pending(self) -> None:
        document = platform_scope()
        document["authorization"]["status"] = "pending"
        self.write_scope(document)
        result = compile_scope(self.root, now=NOW)
        self.assertEqual(1, result.exit_code)
        record = self.record()
        self.assertEqual([], record["summary"]["approved"])
        self.assertEqual(3, len(record["summary"]["pending"]))
        self.assertIn("authorization: authorization is pending, not approved", record["surfaces"][0]["open"])

    def test_record_has_nothing_the_owner_did_not_supply(self) -> None:
        document = platform_scope()
        self.write_scope(document)
        compile_scope(self.root, now=NOW)
        record = self.record()
        forbidden = {"path", "paths", "method", "methods", "header", "headers", "body", "request", "route",
                     "routes", "url", "query", "payload", "cookie"}
        self.assertEqual(set(), {key.lower() for key in keys(record)} & forbidden)
        supplied = strings(document)
        for section in ("surfaces", "identities", "addressing", "objectClasses"):
            for value in strings(record[section]):
                if value in {"approved", "pending", "undecided", "out-of-scope"}:
                    continue
                self.assertIn(value, supplied, f"{section}: {value!r} is not in the scope file")
        # the only strings containing a slash are the owner's URLs, origins, and the inventory file
        slashed = {value for value in strings({key: record[key] for key in record
                                               if key not in {"apiVersion", "notice", "webSecurityContract", "openQuestions"}})
                   if "/" in value}
        self.assertTrue(slashed <= supplied, slashed - supplied)
        self.assertEqual("work/ferivox/openapi.json", record["routeInventory"]["file"])

    def test_record_is_tracked_stale_edited_and_never_silently_overwritten(self) -> None:
        document = platform_scope()
        self.write_scope(document)
        compile_scope(self.root, now=NOW)
        path = self.root / FILENAME
        self.assertEqual("managed", existing_state(path))
        document["platform"]["operations"]["max_requests_per_second"] = 4
        self.write_scope(document)
        report = inspect(self.root / "scope.yaml", now=NOW)
        self.assertEqual("stale", state_for(self.root, report.sha256, True))
        self.assertEqual(0, compile_scope(self.root, now=NOW).exit_code)
        self.assertEqual("current", state_for(self.root, report.sha256, True))
        path.write_text(path.read_text().replace("10.20.40.5", "10.20.40.99"))
        self.assertEqual("edited", existing_state(path))
        before = path.read_bytes()
        sidecar = (self.root / SIDECAR_FILE).read_bytes()
        refused = compile_scope(self.root, now=NOW)
        self.assertEqual(2, refused.exit_code)
        self.assertEqual(["scope.derivative_modified"], [item.code for item in refused.refused])
        self.assertEqual(before, path.read_bytes())
        self.assertEqual(sidecar, (self.root / SIDECAR_FILE).read_bytes())
        self.assertEqual(0, compile_scope(self.root, now=NOW, force=True).exit_code)
        self.assertEqual("managed", existing_state(path))
        path.write_text("notes: mine\n")
        self.assertEqual(["scope.derivative_unmanaged"],
                         [item.code for item in compile_scope(self.root, now=NOW).refused])

    def test_removing_the_sections_leaves_a_note_not_a_deleted_file(self) -> None:
        self.write_scope(platform_scope())
        compile_scope(self.root, now=NOW)
        self.write_scope(complete_scope())
        result = compile_scope(self.root, now=NOW)
        self.assertEqual(0, result.exit_code)
        self.assertTrue((self.root / FILENAME).exists())
        self.assertTrue(any("out of date" in note for note in result.notes))

    def test_confirmed_pstn_destination_is_accepted(self) -> None:
        document = platform_scope()
        document["platform"]["dialing"]["reach"]["echo-tls"] = "pstn"
        document["platform"]["dialing"]["toll"] = "accepted"
        document["platform"]["third_parties"]["pstn_carrier"] = {
            "provider": "Northwind Carrier", "permission": "permitted", "reference": "carrier mail 14 Nov"}
        report = self.report(document)
        self.assertTrue(report.ok, [item.as_dict() for item in report.errors])
        self.assertEqual(["echo-tls"], readiness(report)["pstnDestinations"])


class InconsistentScopeTests(PlatformCase):
    def test_pstn_destination_without_carrier_or_toll_answer_holds_profile_and_campaign(self) -> None:
        for carrier, toll in (("pending", "accepted"), ("permitted", "pending"), ("permitted", None),
                              (None, None), ("unknown", "refused")):
            document = platform_scope()
            document["platform"]["dialing"]["reach"]["echo-tls"] = "pstn"
            document["platform"]["dialing"]["toll"] = toll
            document["platform"]["third_parties"]["pstn_carrier"] = {
                "provider": "Northwind Carrier", "permission": carrier, "reference": "mail"}
            report = self.report(document)
            finding = next(item for item in report.errors if item.code == "scope.pstn_destination_unconfirmed")
            self.assertEqual("platform.dialing.reach.echo-tls", finding.field, (carrier, toll))
            self.assertIn("campaign", finding.blocks)
            self.assertIn("profile", finding.blocks)
            result = compile_scope(self.root, now=NOW, force=True)
            self.assertEqual(1, result.exit_code)
            self.assertEqual(set(), {"profile", "campaign"} & {item["artifact"] for item in result.generated})
            self.assertFalse((self.root / "target-profile.yaml").exists())
            self.assertFalse((self.root / "campaign.yaml").exists())
            self.assertIn("application-surfaces", result.skipped)

    def test_carrier_out_of_path_contradicts_a_pstn_destination(self) -> None:
        document = platform_scope()
        document["platform"]["dialing"]["reach"]["echo"] = "pstn"
        errors = self.findings(document, ERRORS)
        self.assertIn("scope.carrier_answer_conflict", errors)
        self.assertIn("scope.pstn_destination_unconfirmed", errors)

    def test_destination_on_the_never_dial_list_or_prefix(self) -> None:
        document = platform_scope()
        document["platform"]["dialing"]["never_dial"] = ["9196"]
        self.assertEqual(["destinations[0].user", "destinations[1].user"],
                         self.findings(document, ERRORS)["scope.destination_never_dial"])
        document = platform_scope()
        document["destinations"][1]["user"] = "0900123"
        self.assertEqual(["destinations[1].user"], self.findings(document, ERRORS)["scope.destination_never_dial"])
        self.assertNotIn("scope.destination_never_dial", self.findings(platform_scope(), ERRORS))

    def test_concurrency_ceiling_above_the_production_maximum(self) -> None:
        document = platform_scope()
        document["platform"]["operations"]["max_concurrent_calls"] = 1
        report = self.report(document)
        finding = next(item for item in report.errors if item.code == "scope.limit_exceeds_production")
        self.assertEqual("limits.concurrent_calls", finding.field)
        self.assertEqual(1, compile_scope(self.root, now=NOW).exit_code)

    def test_hostname_as_a_destination_is_rejected_everywhere(self) -> None:
        document = platform_scope()
        document["application"]["surfaces"][0]["connect_address"] = "admin.ferivox.test"
        report = self.report(document)
        finding = next(item for item in report.errors if item.field == "application.surfaces[0].connect_address")
        self.assertEqual("scope.malformed", finding.code)
        self.assertIn("no hostnames", finding.message)
        self.assertIn("write pending", finding.message)
        result = compile_scope(self.root, now=NOW)
        self.assertFalse((self.root / FILENAME).exists())
        self.assertEqual(["scope.malformed"], [item.code for item in result.skipped["application-surfaces"]])
        document = platform_scope()
        document["platform"]["addressing"][0]["addresses"] = ["sbc.ferivox.test"]
        self.assertEqual(["platform.addressing[0].addresses[0]"], self.findings(document, ERRORS)["scope.malformed"])
        document = platform_scope()
        document["platform"]["addressing"][0]["name"] = "10.20.30.40"
        self.assertEqual(["platform.addressing[0].name"], self.findings(document, ERRORS)["scope.malformed"])

    def test_contradictions_between_recorded_answers(self) -> None:
        document = platform_scope()
        document["application"]["surfaces"][0]["connect_address"] = "10.20.40.99"
        self.assertEqual(["application.surfaces[0].connect_address"],
                         self.findings(document, ERRORS)["scope.surface_address_mismatch"])
        document = platform_scope()
        for name in ("admin_console", "customer_web_app", "api", "websocket_webrtc"):
            document["platform"]["components"][name] = "out-of-scope"
        self.assertIn("scope.surface_component_conflict", self.findings(document, ERRORS))
        document = platform_scope()
        document["platform"]["dialing"]["reach"]["ecoh"] = "on-net"
        self.assertEqual(["platform.dialing.reach.ecoh"],
                         self.findings(document, ERRORS)["scope.reach_unknown_destination"])
        document = platform_scope()
        document["application"]["surfaces"][0]["tls_ca_file"] = "work/ferivox/ca.crt"
        self.assertIn("scope.tls_ca_conflict", self.findings(document, ERRORS))

    def test_malformed_values(self) -> None:
        cases = {
            "platform.components.api": "yes",
            "platform.environment.kind": "prod",
            "platform.environment.real_customers": "yes",
            "platform.third_parties.hosting.permission": "allowed",
            "platform.third_parties.hosting": "pending",
            "platform.dialing.never_dial": [112],
            "platform.dialing.reach": ["echo"],
            "platform.dialing.toll": "free",
            "platform.operations.max_concurrent_calls": 0,
            "platform.operations.max_requests_per_second": "5",
            "platform.addressing": "sbc.ferivox.test",
            "application.surfaces.0.kind": "web",
            "application.surfaces.0.base_url": "http://admin.ferivox.test",
            "application.surfaces.0.connect_port": 70000,
            "application.surfaces.0.tls_server_name": "10.20.40.5",
            "application.surfaces.2.base_url": "https://rtc.ferivox.test",
            "application.surfaces.2.allowed_origins": ["https://app.ferivox.test/login"],
            "application.surfaces.1.base_url": "https://api.ferivox.test/v2?debug=1",
            "application.identities.0.role": "Admin User",
            "application.identities.0.id": "pending",
            "application.route_inventory.kind": "swagger",
            "application.route_inventory.file": "/etc/passwd",
            "application.object_classes": "voicemail",
        }
        for path, value in cases.items():
            document = platform_scope()
            mutate(document, path, value)
            report = self.report(document)
            self.assertFalse(report.fatal, path)
            self.assertIn("scope.malformed", {item.code for item in report.errors}, path)
            self.assertTrue(all("application-surfaces" in item.blocks for item in report.errors), path)

    def test_duplicate_surface_and_identity_names(self) -> None:
        document = platform_scope()
        document["application"]["surfaces"][1]["name"] = "admin-console"
        document["application"]["identities"][1]["id"] = "admin-test"
        fields = self.findings(document, ERRORS)["scope.malformed"]
        self.assertEqual(["application.surfaces[1].name", "application.identities[1].id"], fields)

    def test_unknown_fields_are_rejected_at_every_depth(self) -> None:
        cases = {
            "platform.owner_mood": "fine",
            "platform.components.fax": "in-scope",
            "platform.environment.region": "eu",
            "platform.third_parties.dns": {"provider": "x"},
            "platform.third_parties.hosting.contact": "x",
            "platform.operations.emergency_contact.pager": "x",
            "platform.addressing.0.ttl": 60,
            "application.surfaces.0.path": "/admin/login",
            "application.surfaces.0.method": "POST",
            "application.identities.0.username": "admin",
            "application.route_inventory.routes": ["/a"],
            "application.checks": ["admin.csrf"],
        }
        for path, value in cases.items():
            document = platform_scope()
            mutate(document, path, value)
            report = self.report(document)
            self.assertTrue(report.fatal, path)
            self.assertEqual({"scope.unknown_field"}, {item.code for item in report.errors}, path)
            self.assertIsNone(report.document)
        result = compile_scope(self.root, now=NOW)
        self.assertEqual(2, result.exit_code)
        self.assertFalse((self.root / FILENAME).exists())


class SecretTests(PlatformCase):
    VALUE = "Tr0ub4dor-horse-battery-staple"

    def test_secret_fields_and_values_are_rejected_and_never_repeated(self) -> None:
        cases = {
            "application.identities.0.password": self.VALUE,
            "application.identities.0.credential_ref": f"password={self.VALUE}",
            "application.surfaces.0.base_url": f"https://admin:{self.VALUE}@admin.ferivox.test",
            "application.surfaces.0.api_key": self.VALUE,
            "platform.operations.stop_signal": "Bearer abcdefghijklmnop123456",
            "platform.third_parties.hosting.reference": "token: " + self.VALUE,
            "application.route_inventory.file": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl",
        }
        for path, value in cases.items():
            document = platform_scope()
            mutate(document, path, value)
            self.write_scope(document)
            code, out, err = self.run_main("scope", "check", str(self.root))
            self.assertEqual(1, code, path)
            self.assertRegex(out, r"scope\.secret_(field|value)", path)
            self.assertNotIn(self.VALUE, out + err, path)
            result = compile_scope(self.root, now=NOW)
            self.assertEqual(2, result.exit_code, path)
            self.assertFalse((self.root / FILENAME).exists(), path)
            self.assertNotIn(self.VALUE, json.dumps(result.as_dict()), path)

    def test_record_carries_reference_names_only(self) -> None:
        self.write_scope(platform_scope())
        compile_scope(self.root, now=NOW)
        record = self.record()
        self.assertEqual(["admin-test", "user-test"], [item["credentialRef"] for item in record["identities"]])
        self.assertEqual({"id", "role", "tenant", "credentialRef"}, set(record["identities"][0]))

    def test_question_sheet_and_cockpit_facts_never_echo_values(self) -> None:
        document = platform_scope()
        self.write_scope(document)
        _, out, _ = self.run_main("scope", "questions", str(self.root))
        facts = json.dumps(readiness(inspect(self.root / "scope.yaml", now=NOW)))
        for value in ("Ferivox Cloud PBX", "Northwind", "10.20.40.5", "admin.ferivox.test", "HALT", "NW-4471",
                      "sippycup-test"):
            self.assertNotIn(value, out)
            self.assertNotIn(value, facts)


class QuestionSheetTests(PlatformCase):
    def test_generic_sheet_has_part_two_with_a_reason_for_every_question(self) -> None:
        out = render_questions()
        part = out.split("# Part 2", 1)[1]
        self.assertEqual(len(APP_QUESTIONS), part.count("Why we ask:"))
        for question in APP_QUESTIONS:
            self.assertIn(f"\n{question.identifier}. ", part)
            self.assertTrue(question.why.strip())
        flat = " ".join(part.lower().split())
        for topic in ("out of scope", "production", "real customers", "test tenant", "never open",
                      "hosting or cloud provider", "web firewall", "phone carriers", "sms", "never dial",
                      "cost money", "hours", "calls at once", "requests per second", "automatic blocks",
                      "stop signal", "numeric ip address", "shared with other customers", "addresses change",
                      "wss://", "origins", "test accounts", "do not send passwords", "stored files",
                      "openapi", "har file", "we never guess"):
            self.assertIn(topic, flat, topic)
        self.assertNotIn("(answered)", out)
        self.assertNotIn("[ ]", part)
        self.assertEqual(24, len(APP_QUESTIONS))

    def test_part_one_numbering_is_untouched(self) -> None:
        out = render_questions()
        first = out.split("# Part 2", 1)[0]
        for number, question in enumerate(QUESTIONS, 1):
            self.assertIn(f"{number}. {question.text}", first)

    def test_an_error_on_an_answer_marks_it_unanswered(self) -> None:
        document = platform_scope()
        document["platform"]["environment"]["kind"] = "prod"
        states = readiness(self.report(document))["states"]
        self.assertEqual("unanswered", states["P3"])
        self.assertEqual("answered", states["P4"])


class SchemaAndExampleTests(PlatformCase):
    def test_schema_matches_the_validator_spec_at_every_depth(self) -> None:
        schema = json.loads((ROOT / "schemas" / "scope-v1.schema.json").read_text())

        def compare(node: dict, spec, path: str) -> None:
            if spec is None or isinstance(spec, str):
                return
            if isinstance(spec, list):
                items = next(option for option in node["oneOf"] if option.get("type") == "array")["items"]
                compare(items, spec[0], path + "[]")
                return
            self.assertFalse(node["additionalProperties"], path)
            self.assertEqual(set(spec), set(node["properties"]), path)
            for key, child in spec.items():
                compare(node["properties"][key], child, f"{path}.{key}")

        for key in ("platform", "application"):
            compare(schema["properties"][key], APP_SPEC[key], key)

    def test_example_is_pending_placeholder_and_loads_without_structural_errors(self) -> None:
        example = ROOT / "examples" / "scope" / "platform-scope.yaml"
        target = self.root / "scope.yaml"
        target.write_bytes(example.read_bytes())
        target.chmod(0o600)
        report = inspect(target, now=NOW)
        self.assertFalse(report.fatal, [item.as_dict() for item in report.errors])
        self.assertFalse(report.ok)
        codes = {item.code for item in report.errors}
        self.assertIn("scope.authorization_not_approved", codes)
        self.assertIn("scope.placeholder_value", codes)
        self.assertIn("scope.pstn_destination_unconfirmed", codes)
        self.assertEqual("pending", yaml.safe_load(example.read_text())["authorization"]["status"])
        states = set(readiness(report)["states"].values())
        self.assertTrue({"answered", "pending", "unknown", "unanswered"} <= states, states)
        result = compile_scope(self.root, now=NOW)
        self.assertNotEqual(0, result.exit_code)
        self.assertNotEqual("approved", result.profile_status)
        self.assertFalse((self.root / FILENAME).exists())

    def test_template_and_example_cover_the_same_fields(self) -> None:
        from sippycup_workbench.scope_app import TEMPLATE

        template = yaml.safe_load(TEMPLATE)
        example = yaml.safe_load((ROOT / "examples" / "scope" / "platform-scope.yaml").read_text())
        for key in ("platform", "application"):
            self.assertEqual(set(APP_SPEC[key]), set(template[key]), key)
            self.assertEqual(set(APP_SPEC[key]), set(example[key]), key)


class CockpitAndReadyTests(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = make_repo(Path(self.temp.name))
        self.root = make_engagement(self.repo)

    def build(self, platform: dict | None, application: dict | None = None, *, compile_it: bool = True) -> dict:
        text = scope_text(valid_from=COCKPIT_NOW - timedelta(hours=1), valid_until=COCKPIT_NOW + timedelta(hours=3))
        document = yaml.safe_load(text)
        if platform is not None:
            document["platform"] = platform
        if application is not None:
            document["application"] = application
        write_scope(self.root, yaml.safe_dump(document, sort_keys=False))
        if compile_it:
            compile_scope(self.root, now=COCKPIT_NOW, force=True)
        return build_model(self.root, repo=self.repo, now=COCKPIT_NOW)

    def fixture_platform(self) -> dict:
        section = platform_section()
        section["dialing"]["reach"] = {"echo": "on-net"}
        section["operations"]["max_concurrent_calls"] = 1
        section["addressing"] = [{"name": "admin.ferivox.test", "addresses": ["10.20.40.5"],
                                  "shared": False, "changing": False}]
        return section

    def check(self, model: dict) -> dict | None:
        from sippycup_cockpit.platform_scope import check_platform

        item = check_platform(model)
        return None if item is None else item.as_dict()

    def test_complete_platform_is_ok_and_ready_line_is_go(self) -> None:
        model = self.build(self.fixture_platform(), application_section())
        self.assertEqual("complete", model["scope"]["state"], model["scope"]["errors"])
        text = "\n".join(render_dashboard(model))
        self.assertIn("Platform       [ok] production; 0 of 24 platform questions open; production safety: all answered",
                      text)
        self.assertIn("Web surfaces   [ok] admin-console ready; tenant-api ready; browser-calling ready", text)
        self.assertIn("record application-surfaces.yaml: current; nothing is sent to web surfaces", text)
        self.assertEqual("go", self.check(model)["status"])
        scope_stage = next(stage for stage in model["stages"] if stage["id"] == "scope")
        self.assertTrue(scope_stage["steps"][-1]["done"])
        self.assertIn("platform and web answers recorded (0 open", scope_stage["steps"][-1]["label"])

    def test_open_production_safety_answers_show_exactly_which_and_only_warn(self) -> None:
        section = self.fixture_platform()
        section["environment"]["never_touch"] = "pending"
        section["operations"]["stop_signal"] = None
        application = application_section()
        application["surfaces"][0]["connect_address"] = "unknown"
        model = self.build(section, application)
        self.assertEqual("complete", model["scope"]["state"], "open platform answers do not make the scope incomplete")
        text = "\n".join(render_dashboard(model, question_limit=10))
        self.assertIn("production safety: 2 open (P6 (pending), P17 (unanswered))", text)
        self.assertIn("- P6 Environment and data (pending): Which data must we never open", text)
        self.assertIn("- P17 Limits on the live system (unanswered): Who do we call if something breaks", text)
        self.assertIn("- A2 Web, API, and browser-calling surfaces (unknown)", text)
        self.assertIn("admin-console pending", text)
        self.assertNotIn("real voicemail", text)
        item = self.check(model)
        self.assertEqual("warn", item["status"])
        self.assertIn("the scope says production: 2 production-safety answer(s) open", item["lines"][0])
        self.assertTrue(any(line.strip().startswith("P17 (unanswered)") for line in item["lines"]))
        self.assertIn("scope questions", item["fix"])
        scope_stage = next(stage for stage in model["stages"] if stage["id"] == "scope")
        self.assertFalse(scope_stage["steps"][-1]["done"])
        status = assess(self.root, now=COCKPIT_NOW)
        self.assertEqual(["P6", "P17"], status["facts"]["scope"]["platform"]["productionSafety"]["open"])
        self.assertTrue(any("production-safety" in line for line in status["warnings"]))
        self.assertFalse(status["facts"]["scope"]["platform"]["liveApplicationRunner"])

    def test_staging_is_go_without_production_answers(self) -> None:
        section = self.fixture_platform()
        section["environment"]["kind"] = "staging"
        section["operations"]["stop_signal"] = None
        item = self.check(self.build(section))
        self.assertEqual("go", item["status"])
        self.assertIn("staging, not production", item["lines"][0])

    def test_unconfirmed_pstn_destination_is_no_go(self) -> None:
        section = self.fixture_platform()
        section["dialing"]["reach"] = {"echo": "pstn"}
        section["third_parties"]["pstn_carrier"]["permission"] = "pending"
        model = self.build(section)
        self.assertEqual("inconsistent", model["scope"]["state"])
        item = self.check(model)
        self.assertEqual("no-go", item["status"])
        self.assertIn("reaches the public phone network", item["lines"][0])
        text = "\n".join(render_dashboard(model))
        self.assertIn("holds the SIP profile", text)

    def test_confirmed_pstn_destination_warns_about_cost(self) -> None:
        section = self.fixture_platform()
        section["dialing"] |= {"reach": {"echo": "pstn"}, "toll": "accepted"}
        section["third_parties"]["pstn_carrier"] = {"provider": "Carrier", "permission": "permitted",
                                                    "reference": "mail"}
        item = self.check(self.build(section))
        self.assertEqual("warn", item["status"])
        self.assertIn("cost money", item["lines"][-1])

    def test_ready_assess_includes_the_line_only_when_recorded(self) -> None:
        from test_ready import FakeHost

        (self.repo / "bin").mkdir(exist_ok=True)
        section = self.fixture_platform()
        section["operations"]["stop_signal"] = "pending"
        self.build(section)
        host = FakeHost(self.repo, now=COCKPIT_NOW)
        result = ready.assess(self.root, host=host, image="localhost/sippycup:test")
        item = next(entry for entry in result["checks"] if entry["id"] == "platform")
        self.assertEqual("warn", item["status"])
        self.assertEqual("Production safety answers", item["title"])
        self.assertFalse(any(entry["id"] == "platform" and entry["status"] == "no-go" for entry in result["checks"]))
        rendered = "\n".join(ready.render(result, None))
        self.assertIn("Production safety answers", rendered)
        self.assertIn("P17 (pending)", rendered)
        self.build(None)
        result = ready.assess(self.root, host=host, image="localhost/sippycup:test")
        self.assertFalse(any(entry["id"] == "platform" for entry in result["checks"]))


if __name__ == "__main__":
    unittest.main()
