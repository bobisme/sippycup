"""`scope answer` after the second first-time-operator rehearsal (findings 9-11, 15-17, 20-25, 32).

Every test drives ``scope_answer.run`` with typed lines, the same session layer
a terminal uses. Offline only: nothing here opens a socket or starts a container.
"""

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from test_scope import NOW, complete_scope  # noqa: E402
from test_scope_answer import AnswerTestCase  # noqa: E402

from sippycup_checks import catalog, scope_support  # noqa: E402
from sippycup_workbench import scope_answer  # noqa: E402
from sippycup_workbench.scope import TEST_CLASSES, ScopeError, create_scope, inspect  # noqa: E402
from sippycup_workbench.scope_questions import render_questions  # noqa: E402


def one_target_scope() -> dict:
    document = complete_scope()
    document["targets"] = document["targets"][:1]
    document["destinations"] = document["destinations"][:1]
    return document


class UnfinishedListTests(AnswerTestCase):
    """Finding 9: an interrupted list resumes inside its question and is not answered meanwhile."""

    def test_interrupt_at_another_target_keeps_the_question_open_and_resumes_inside_it(self) -> None:
        self.write_scope(one_target_scope())
        code, out = self.answer(["add", "edge-tls", "", "", "", "sbc.ferivox.test", ""], "targets",
                                interrupt=True)
        self.assertEqual(code, 130, out)
        self.assertEqual([t["name"] for t in self.document()["targets"]], ["edge", "edge-tls"])
        self.assertIn("Unfinished list: targets (question 5;", out)
        self.assertIn("5 (signaling)", out.split("Still open: ")[1].splitlines()[0])
        # the next walk opens question 5 inside the list, at target 3
        code, out = self.answer(["", "approved"])
        self.assertIn("== Question 5 of 24", out)
        self.assertIn("The last session stopped while targets were being added", out)
        self.assertIn("-- target 3 --", out)
        self.assertIn("No more targets: the list is complete as recorded.", out)
        self.assertNotIn("Unfinished list", out)
        self.assertFalse((self.root / ".scope.yaml.unfinished.json").exists())
        self.assertEqual(code, 0, out)

    def test_interrupt_inside_a_destination_and_a_test_account_too(self) -> None:
        self.write_scope(one_target_scope())
        self.answer(["add", "desk", "0201234567"], "destinations", interrupt=True)
        state = scope_answer.ScopeFile(self.scope, now=lambda: NOW).unfinished
        self.assertEqual(list(state), ["destinations"])
        _, out = self.answer(["quit"])
        self.assertIn("11 (destinations)", out.split("Still open: ")[1].splitlines()[0])
        from sippycup_workbench.scope_app import TEMPLATE

        self.scope.write_text(self.scope.read_text() + TEMPLATE)
        self.answer(["admin-test", "admin", "test-a", "admin-test"], "A4", interrupt=True)
        _, out = self.answer(["quit"])
        self.assertIn("Unfinished list: application.identities (question A4;", out)
        self.assertIn("A4", out.split("Platform answers still open: ")[1].splitlines()[0])

    def test_a_question_with_nothing_to_ask_prints_no_header(self) -> None:
        document = one_target_scope()  # transports udp, tls, but the only target is udp
        document["authorization"]["status"] = "pending"
        self.write_scope(document)
        _, out = self.answer(["approved"])
        self.assertNotIn("== Question 6", out)
        self.assertNotIn("6 (signaling)", out)
        self.assertEqual(self.document()["authorization"]["status"], "approved")
        # P11 waits for destinations: no header, the reason is listed at the end
        document = complete_scope()
        document["destinations"] = []
        document["test_scope"]["allowed_classes"] = ["options"]
        self.write_scope(document)
        from sippycup_workbench.scope_app import TEMPLATE

        self.scope.write_text(self.scope.read_text() + TEMPLATE)
        _, out = self.answer(["quit"] * 0 + [""] * 200)
        self.assertNotIn("== Question P11", out)
        self.assertIn("P11: No destinations are recorded yet (question 11); answer that first.", out)
        for block in out.split("\n== Question ")[1:]:
            with self.subTest(question=block.split(":")[0]):
                self.assertIn("  > ", block)


class SelectionTests(AnswerTestCase):
    """Finding 10 (and 24): a QUESTION argument opens exactly what it names."""

    def test_a_field_opens_that_field_only(self) -> None:
        self.write_scope(complete_scope())
        _, out = self.answer(["clear"], "contact.channel")
        self.assertIn("Cleared contact.channel", out)
        contact = self.document()["contact"]
        self.assertEqual((contact["name"], contact["channel"]), ("Quad", None))
        self.assertNotIn("[contact.name]", out)
        self.answer(["NOC phone"], "contact.channel")
        self.assertEqual(self.document()["contact"]["channel"], "NOC phone")

    def test_a_partly_answered_question_asks_only_its_open_answers(self) -> None:
        create_scope(self.root, name="platform", platform=True)
        self.answer(["Acme", "quit"], "P1")
        _, out = self.answer(["out-of-scope", "quit"], "P1")
        self.assertNotIn("[platform.name]", out)
        self.assertEqual(self.document()["platform"]["name"], "Acme")
        self.assertEqual(self.document()["platform"]["components"]["sip_edge"], "out-of-scope")

    def test_one_list_entry_or_one_field_of_it(self) -> None:
        self.write_scope(complete_scope())
        _, out = self.answer(["10.20.30.41"], "targets[1].address")
        self.assertEqual([t["address"] for t in self.document()["targets"]], ["10.20.30.40", "10.20.30.41"])
        self.assertNotIn("[targets[1].port]", out)
        _, out = self.answer(["", "", "", "5070", ""], "targets[0]")
        self.assertIn("target port is not in the approved signaling ports", out)
        self.assertIn("Target 1 is unchanged.", out)
        self.answer(["", "10.20.30.42", "", "", "", ""], "targets.1")
        self.assertEqual(self.document()["targets"][1]["address"], "10.20.30.42")
        with self.assertRaises(ScopeError) as caught:
            self.answer([], "targets[5]")
        self.assertIn("targets has 2 entries (targets[0] to targets[1]", str(caught.exception))

    def test_edit_and_remove_one_item_from_the_list_menu(self) -> None:
        self.write_scope(complete_scope())
        _, out = self.answer(["edit 2", "", "", "4444", ""], "destinations")
        self.assertEqual([d["user"] for d in self.document()["destinations"]], ["9196", "4444"])
        _, out = self.answer(["remove 2"], "destinations")
        self.assertEqual([d["name"] for d in self.document()["destinations"]], ["echo"])
        self.assertIn("Removed destination 2", out)

    def test_an_unknown_address_is_refused_with_what_can_be_opened(self) -> None:
        self.write_scope(complete_scope())
        before = self.scope.read_bytes()
        with self.assertRaises(ScopeError) as caught:
            self.answer([], "contact.chanel")
        message = str(caught.exception)
        self.assertIn("nothing was changed", message)
        self.assertIn("Did you mean: contact.channel", message)
        self.assertIn("Fields under contact: contact.name, contact.channel, contact.can_stop_test", message)
        self.assertEqual(self.scope.read_bytes(), before)

    def test_window_and_port_range_parts(self) -> None:
        self.write_scope(complete_scope())
        _, out = self.answer(["UTC", "2099-12-31 15:00"], "authorization.valid_until")
        self.assertNotIn("[authorization.valid_from]", out)
        self.assertEqual(self.document()["authorization"]["valid_until"], "2099-12-31T15:00:00Z")
        _, out = self.answer(["10200"], "media.port_range.end")
        self.assertNotIn("[media.port_range.start]", out)
        self.assertEqual(self.document()["media"]["port_range"], {"start": 10000, "end": 10200})


class ApprovalTests(AnswerTestCase):
    """Finding 11: the approval comes last with the scope on screen, and changes reopen it."""

    def test_the_approval_is_asked_last_with_a_summary_of_what_it_approves(self) -> None:
        document = complete_scope()
        document["authorization"]["status"] = "pending"
        document["contact"]["channel"] = None
        self.write_scope(document)
        _, out = self.answer(["+31 20 123", "approved"])
        self.assertLess(out.index("== Question 22 of 24"), out.index("== Question 2 of 24"))
        summary = out[out.index("== Question 2 of 24"):]
        for line in ("Targets (2): edge: 10.20.30.40 udp port 5060; edge-tls: 10.20.30.40 tls port 5061",
                     "Destinations (2): echo: dial 9196 on edge, expect echo",
                     "Media: to 10.20.31.0/28, 10.20.30.40; far-end ports 10000 to 10100",
                     "Limits: 10 calls (2 at once, 1 per second)",
                     "Window: 2020-01-01T09:00:00+01:00 to 2099-12-31T17:00:00+01:00",
                     "Security checks: none approved"):
            self.assertIn(line, summary)
        self.assertEqual(self.document()["authorization"]["status"], "approved")

    def test_approval_waits_for_what_it_approves_but_not_for_contact(self) -> None:
        document = complete_scope()
        document["authorization"]["status"] = "pending"
        document["limits"]["calls"] = None
        self.write_scope(document)
        _, out = self.answer(["approved"], "2")
        self.assertIn("17 (ceilings) is still open", out)
        self.assertEqual(self.document()["authorization"]["status"], "pending")
        # in the walk it is not asked at all until then
        _, out = self.answer([""])
        self.assertIn("2: The approval is asked once the answers it approves are recorded; still open: 17", out)
        document["limits"]["calls"] = 10
        document["contact"]["name"] = None
        self.write_scope(document)
        _, out = self.answer(["approved"], "2")
        self.assertEqual(self.document()["authorization"]["status"], "approved")
        self.assertIn("Still open: 22 (operations). They grant nothing", out)

    def test_every_change_to_what_may_be_sent_sets_it_back_to_pending(self) -> None:
        cases = [
            (["limits.calls=40"], None, "limits.calls: 10 -> 40"),
            (["media.networks=10.20.31.0/28"], None, "media.networks"),
            (["signaling.ports=5060, 5061, 5062"], None, "signaling.ports"),
            (["media.codecs=PCMU"], None, "media.codecs"),
            (["stop_conditions.consecutive_failures=9"], None, "stop_conditions.consecutive_failures"),
            (["test_scope.exclusions=none"], None, "test_scope.exclusions"),
            (None, (["add", "desk", "edge", "4444", "agent", "n"], "destinations"), "destinations"),
            (None, (["10.20.30.41"], "targets[1].address"), "targets"),
            (None, (["banner-disclosure", "1"], "24"), "security_checks"),
            (None, (["10100", "10200"], "13"), "media.port_range"),
        ]
        for settings, lines, field_name in cases:
            with self.subTest(field=field_name):
                self.write_scope(complete_scope())
                if settings:
                    _, out = self.answer([], settings=settings)
                else:
                    _, out = self.answer(*lines)
                self.assertEqual(self.document()["authorization"]["status"], "pending", out)
                self.assertIn("authorization.status is pending again", out)
                self.assertIn(field_name, out.split("authorization.status is pending again")[1])
                self.assertIn("this changes what may be sent", out)

    def test_changes_that_grant_nothing_keep_the_approval(self) -> None:
        for settings in (["contact.name=Jane Roe"], ["evidence.retention_days=60"], ["media.dtmf=sip-info"],
                         ["account.credential_delivery=in-person"], ["client.source_addresses=172.16.5.10"]):
            with self.subTest(settings=settings):
                self.write_scope(complete_scope())
                _, out = self.answer([], settings=settings)
                self.assertEqual(self.document()["authorization"]["status"], "approved", out)
                self.assertNotIn("pending again", out)

    def test_part_two_answers_that_hold_a_surface_or_a_call_reset_it_and_record_only_answers_do_not(self) -> None:
        from sippycup_workbench.scope_app import TEMPLATE

        for setting, resets in (("platform.operations.max_concurrent_calls=2", True),
                                ("platform.environment.kind=staging", True),
                                ("platform.third_parties.hosting.provider=Acme Cloud", True),
                                ("platform.name=Acme Voice", False),
                                ("platform.out_of_scope=billing", False)):
            with self.subTest(setting=setting):
                self.write_scope(complete_scope())
                self.scope.write_text(self.scope.read_text() + TEMPLATE)
                _, out = self.answer([], settings=[setting])
                self.assertEqual(self.document()["authorization"]["status"], "pending" if resets else "approved",
                                 out)

    def test_a_piped_approval_still_works_and_set_still_refuses_it(self) -> None:
        document = complete_scope()
        document["authorization"]["status"] = "pending"
        self.write_scope(document)
        _, out = self.answer(["approved"], "2")
        self.assertEqual(self.document()["authorization"]["status"], "approved")
        with self.assertRaises(ScopeError):
            self.answer([], settings=["authorization.status=approved"])


class PlatformWordsTests(AnswerTestCase):
    """Findings 15 and 32: part 2 takes the sheet's own words and says what they were recorded as."""

    def setUp(self) -> None:
        super().setUp()
        create_scope(self.root, name="platform", platform=True)

    def platform(self) -> dict:
        return self.document()["platform"]

    def test_p1_yes_no_not_sure(self) -> None:
        components = ["yes", "no", "not sure", "YES", "n", "y", "pending", "out", "in-scope", "Not sure.", "no"]
        _, out = self.answer(["Acme Voice", *components], "P1")
        self.assertEqual(self.platform()["components"], {
            "sip_edge": "in-scope", "media_servers": "out-of-scope", "admin_console": "unknown",
            "customer_web_app": "in-scope", "api": "out-of-scope", "websocket_webrtc": "in-scope",
            "provisioning": "pending", "voicemail": "out-of-scope", "ivr": "in-scope", "conference": "unknown",
            "recording": "out-of-scope"})
        self.assertIn('("yes" is recorded as in-scope)', out)
        self.assertIn('"not sure": recorded as unknown, an open answer (the owner does not know yet)', out)
        self.assertNotIn("That is a name, not an address", out)

    def test_p2_to_p6(self) -> None:
        _, out = self.answer(["nothing"], "P2")
        self.assertEqual(self.platform()["out_of_scope"], ["none"])
        self.assertIn('"nothing" is recorded as [none]', out)
        self.answer(["the live system"], "P3")
        self.assertEqual(self.platform()["environment"]["kind"], "production")
        self.answer(["not sure"], "P4")
        self.assertEqual(self.platform()["environment"]["real_customers"], "unknown")
        self.answer(["yes"], "P4")
        self.answer(["there is none"], "P5")
        self.assertEqual(self.platform()["environment"]["test_tenant"], "none")
        # P6: none on production with real customers is explained and needs the owner's written word
        _, out = self.answer(["none", "n", ""], "P6")
        self.assertIn("'none' says the system holds NO real data", out)
        self.assertIn("this scope records a production system", out)
        self.assertEqual(self.platform()["environment"]["never_touch"], [])
        self.answer(["real voicemail, call records"], "P6")
        self.assertEqual(self.platform()["environment"]["never_touch"], ["real voicemail", "call records"])

    def test_p7_to_p10_third_parties(self) -> None:
        self.answer(["Acme Cloud", "permits it", "policy page acme.example/testing"], "P7")
        hosting = self.platform()["third_parties"]["hosting"]
        self.assertEqual((hosting["permission"], hosting["reference"]),
                         ("permitted", "policy page acme.example/testing"))
        _, out = self.answer(["none"], "P8")
        self.assertEqual(self.platform()["third_parties"]["cdn_waf"],
                         {"provider": "none", "permission": "out-of-path", "reference": None})
        self.assertIn("its permission is recorded as out-of-path", out)
        self.assertNotIn("[platform.third_parties.cdn_waf.permission]", out)
        _, out = self.answer(["Carrier BV", "no", "not involved"], "P9")
        self.assertIn("'no' could mean 'not involved' or 'does not permit testing'", out)
        self.assertEqual(self.platform()["third_parties"]["pstn_carrier"]["permission"], "out-of-path")
        self.answer(["still to be asked", "", "", "nothing", ""], "P10")
        third = self.platform()["third_parties"]
        self.assertEqual(third["sms"]["provider"], "pending")
        self.assertEqual(third["email"]["provider"], "none")

    def test_p11_to_p18(self) -> None:
        document = self.document()
        document.update({key: value for key, value in complete_scope().items() if key not in ("platform",)})
        self.write_scope(document)
        _, out = self.answer(["stays inside", "goes out", "not sure"], "P11")
        self.assertIn("reaches the public phone network, but the carrier's permission is not recorded", out)
        self.assertEqual(self.platform()["dialing"]["reach"], {"echo": "on-net", "echo-tls": "unknown"})
        self.answer(["none", ""], "P12")
        self.assertEqual(self.platform()["dialing"]["never_dial"], ["none"])
        _, out = self.answer(["yes", "free"], "P13")
        self.assertIn("yes and no are ambiguous here", out)
        self.assertEqual(self.platform()["dialing"]["toll"], "no-cost")
        self.answer(["weekdays 22:00 to 06:00, Europe/Amsterdam"], "P14")
        self.answer(["2", "not sure"], "P15")
        self.assertEqual(self.platform()["operations"]["max_requests_per_second"], "unknown")
        self.answer(["fail2ban after 5 failed logins; NOC can unblock"], "P16")
        self.answer(["Jane", "+31 20 123", "STOP STOP"], "P17")
        self.answer(["sip.acme.tld", "10.20.30.40", "no", "not sure", "n"], "P18")
        self.assertEqual(self.platform()["addressing"],
                         [{"name": "sip.acme.tld", "addresses": ["10.20.30.40"], "shared": False,
                           "changing": "unknown"}])

    def test_a1_to_a6(self) -> None:
        self.answer(["Acme", "yes", "yes", "yes", "yes", "yes", "yes", "no", "no", "no", "no", "no"], "P1")
        _, out = self.answer(["admin-console", "people in a browser", "yes", "https://admin.acme.tld", "y",
                              "api", "programs", "not sure", "https://api.acme.tld", "n"], "A1")
        surfaces = self.document()["application"]["surfaces"]
        self.assertEqual([(s["kind"], s["status"]) for s in surfaces], [("browser", "in-scope"), ("api", "unknown")])
        self.assertNotIn("That is a name", out)
        _, out = self.answer(["10.20.30.41", "443", "admin.acme.tld", "our own", "work/practice/ca.crt"], "A2")
        self.assertEqual(self.document()["application"]["surfaces"][0]["tls_ca"], "private")
        _, out = self.answer(["sip.acme.tld"], "A2")  # the address prompt explains names; nothing else does
        self.answer(["admin-test", "admin", "test-a", "admin-test", "n"], "A4")
        self.answer(["none"], "A5")
        self.assertEqual(self.document()["application"]["object_classes"], ["none"])
        self.answer(["a plain list", "work/acme/routes.txt"], "A6")
        self.assertEqual(self.document()["application"]["route_inventory"],
                         {"kind": "route-list", "file": "work/acme/routes.txt"})

    def test_pty_trips_part_two(self) -> None:
        # "n" at a list prompt was recorded as a list holding the letter n; "dunno" was refused;
        # the running count of open platform answers printed after every single answer.
        _, out = self.answer(["Acme", "yes", "dunno", "no", "no", "no", "no", "no", "no", "no", "no", "no"], "P1")
        self.assertEqual(self.platform()["components"]["media_servers"], "unknown")
        self.assertEqual(out.count("WARN scope.platform_open"), 1)
        _, out = self.answer(["n", "real voicemail"], "P6")
        self.assertNotIn("only the open answers of this question", out)  # nothing of P6 was recorded yet
        self.assertIn("that is a yes or no, and this asks for a list", out)
        self.assertEqual(self.platform()["environment"]["never_touch"], ["real voicemail"])

    def test_pty_trips_surfaces(self) -> None:
        # the hostname advice printed for "nothing" and "a plain list"; each A2 answer reprinted every surface
        self.answer(["Acme", "yes", "yes", "yes", "yes", "yes", "yes", "no", "no", "no", "no", "no"], "P1")
        self.answer(["admin-console", "browser", "yes", "https://admin.acme.tld", "n"], "A1")
        _, out = self.answer(["nothing", "a plain list", "10.20.30.41", "443", "quit"], "A2")
        self.assertNotIn("That is a name", out)
        self.assertIn("Recorded application.surfaces[0].connect_port: 443", out)
        self.assertNotIn("Recorded application.surfaces (1)", out)
        self.assertLessEqual(out.count("WARN scope.surface_not_ready"), 1)
        _, out = self.answer(["admin.acme.tld", "quit"], "application.surfaces[0].connect_address")
        self.assertIn("That is a name, not an address", out)
        self.answer(["admin.acme.tld", "public"], "A2")
        self.answer(["add", "api", "programs", "yes", "https://api.acme.tld", "n"], "application.surfaces")
        _, out = self.answer(["quit"], "A2")
        self.assertNotIn("Surface admin-console", out)  # complete: no header without a prompt
        self.assertIn("Surface api (api):", out)

    def test_a_rejection_shows_only_its_own_kind_of_help(self) -> None:
        _, out = self.answer(["maybe later", ""], "P3")
        self.assertIn("Valid: production (the live system), staging", out)
        self.assertNotIn("That is a name", out)


class ReservedWordTests(AnswerTestCase):
    """Findings 16 and 21: ? and help are help at every prompt; a backslash records the word."""

    def test_help_is_never_recorded_and_a_backslash_records_it(self) -> None:
        self.new_scope()
        _, out = self.answer(["help", "?", "CHG-1", "quit"], "1")
        self.assertEqual(self.document()["authorization"]["approval_id"], "CHG-1")
        self.assertIn("Valid: any text up to 128 characters", out)
        self.assertIn("type a backslash before it", out)
        self.answer(["\\help"], "authorization.approval_id")
        self.assertEqual(self.document()["authorization"]["approval_id"], "help")

    def test_a_yes_or_no_is_not_taken_as_a_list_entry_name(self) -> None:
        # pty trip: a tired "no" at "Destination name" was recorded as a destination called no
        self.write_scope(complete_scope())
        _, out = self.answer(["add", "no", ""], "destinations")
        self.assertIn("that is a yes or no, and this asks for the destination's name", out)
        self.assertEqual([d["name"] for d in self.document()["destinations"]], ["echo", "echo-tls"])
        self.answer(["add", "\\no", "edge", "4444", "agent", "n"], "destinations")
        self.assertEqual([d["name"] for d in self.document()["destinations"]], ["echo", "echo-tls", "no"])

    def test_help_at_list_menus_confirmations_and_the_checks(self) -> None:
        self.write_scope(complete_scope())
        _, out = self.answer(["?", "help", ""], "destinations")
        self.assertIn("Type Enter, add, edit N, remove N, redo, or clear", out)
        self.assertEqual(len(self.document()["destinations"]), 2)
        _, out = self.answer(["?", ""], "24")
        self.assertIn("Valid: banner-disclosure, options-methods", out)
        self.assertNotIn("security_checks", self.document())


class SecurityChecksTests(AnswerTestCase):
    """Finding 16: ids are checked as typed, and the ceiling they need is stated first."""

    def test_a_bad_id_is_refused_before_the_ceiling(self) -> None:
        self.write_scope(complete_scope())
        _, out = self.answer(["banner-disclosur", "banner-disclosure, options-methods", "2"], "24")
        first = out.index("names an unknown check: 'banner-disclosur'")
        self.assertLess(first, out.index("[security_checks.max_requests]"))
        self.assertEqual(self.document()["security_checks"],
                         {"approved": ["banner-disclosure", "options-methods"], "max_requests": 2})

    def test_the_ceiling_needed_is_stated_and_matches_scope_check(self) -> None:
        self.write_scope(complete_scope())  # first target is udp: srtp-policy places two calls
        _, out = self.answer(["banner-disclosure, srtp-policy", "12", "13"], "24")
        self.assertIn("These checks may send up to 13 requests in this scope: banner-disclosure 1, srtp-policy 12.",
                      out)
        self.assertIn("a whole number from 13 to 200", out)
        self.assertIn("above max_requests 12", out)
        self.assertEqual(self.document()["security_checks"]["max_requests"], 13)

    def test_the_sheet_states_the_planners_numbers(self) -> None:
        spec = catalog.get("srtp-policy")
        two = catalog.declared_bound(spec, {}, "udp")
        three = catalog.declared_bound(spec, {"cleartext_endpoints": [{"transport": "udp", "port": 5060}]}, "tls")
        self.assertEqual((two, three), (12, 18))
        sheet = render_questions()
        self.assertIn("srtp-policy (active, at most 12 requests for two calls; 18 for three calls when your edge uses"
                      " TLS and you also approve a UDP or TCP signaling port)", sheet)
        self.assertIn("user-enumeration (active, at most 10 requests; 2 when no destination is approved)", sheet)
        self.assertNotIn("at most 18 requests", sheet)


class ClassTests(AnswerTestCase):
    """Finding 17: test_scope.allowed_classes is checked against the classes the tool knows."""

    def test_scope_check_refuses_an_unknown_class_and_lists_the_known_ones(self) -> None:
        document = complete_scope()
        document["test_scope"]["allowed_classes"] = ["options", "call", "flood"]
        self.write_scope(document)
        report = inspect(self.scope, now=NOW)
        found = [item for item in report.errors if item.code == "scope.unknown_class"]
        self.assertEqual(len(found), 1, [item.as_dict() for item in report.findings])
        self.assertIn("does not know: flood", found[0].message)
        for name in TEST_CLASSES:
            self.assertIn(name, found[0].message)
        self.assertFalse(report.ok)
        self.assertEqual(scope_support.CLASS_NAME, "security-checks")
        self.assertIn(scope_support.CLASS_NAME, TEST_CLASSES)

    def test_the_prompt_refuses_it_too(self) -> None:
        self.write_scope(complete_scope())
        _, out = self.answer(["options, call, flood", "options probe, call placement", ""], "21")
        self.assertIn("does not know: flood", out)
        self.assertEqual(self.document()["test_scope"]["allowed_classes"], ["options", "call"])


class PapercutTests(AnswerTestCase):
    def test_20_targets_offer_what_questions_4_and_5_already_say(self) -> None:
        self.new_scope()
        self.answer(["127.0.0.2"], "4")
        _, out = self.answer(["5060, 5061", "udp, tls", "udp-edge", "", "udp", "", "y",
                              "tls-edge", "", "", "", "sippycup-practice", "", "n"], "5")
        self.assertIn("Enter = 127.0.0.2 (the only signaling address, question 4)", out)
        self.assertIn("Enter = 5060 (the usual udp port, approved in question 5)", out)
        self.assertIn("Enter = tls (the approved transport no target uses yet, question 5)", out)
        self.assertEqual([(t["address"], t["transport"], t["port"]) for t in self.document()["targets"]],
                         [("127.0.0.2", "udp", 5060), ("127.0.0.2", "tls", 5061)])

    def test_22_upper_bounds_are_friendly(self) -> None:
        self.new_scope()
        _, out = self.answer(["0", ""], "limits.calls")
        self.assertIn("calls must be a whole number, 1 or more", out)
        self.assertNotIn("18446744073709551615", out)

    def test_23_a_reversed_port_range_is_refused_like_a_reversed_window(self) -> None:
        self.write_scope(complete_scope())
        _, out = self.answer(["", "100", "20000"], "13")
        self.assertIn("Not recorded: media port range start is above its end", out)
        self.assertNotIn("Record it anyway", out)
        self.assertEqual(self.document()["media"]["port_range"], {"start": 10000, "end": 20000})
        _, out = self.answer(["30000", "40000"], "13")
        self.assertIn("(checked together with the last port, which comes next)", out)
        self.assertEqual(self.document()["media"]["port_range"], {"start": 30000, "end": 40000})

    def test_pty_trips_a_whole_range_at_the_first_port_and_plain_protection(self) -> None:
        self.write_scope(complete_scope())
        _, out = self.answer(["20000-10000", "10000 to 20000"], "13")
        self.assertIn("media port range start is above its end", out)
        self.assertEqual(self.document()["media"]["port_range"], {"start": 10000, "end": 20000})
        self.assertNotIn("[media.port_range.end]", out)
        _, out = self.answer(["plain"], "14")
        self.assertIn('"plain" is recorded as [rtp]', out)
        self.assertEqual(self.document()["media"]["protection"], ["rtp"])

    def test_25_next_names_what_to_fix_after_a_contradiction(self) -> None:
        self.write_scope(complete_scope())
        _, out = self.answer(["10.99.0.0/24", "y"], "4")
        self.assertIn(f"To fix scope.target_outside_networks [targets[0].address]: ./bin/sippycup scope answer"
                      f" {self.root} targets[0].address", out)
        self.assertIn(f"Next: ./bin/sippycup scope answer {self.root} targets[0].address", out)


if __name__ == "__main__":
    unittest.main()
