"""`scope answer`: guided answers into scope.yaml, checked with the scope check rules.

Offline only: nothing here opens a socket or starts a container.
"""

from __future__ import annotations

import io
import os
import stat
import sys
import unittest
from pathlib import Path
from unittest import mock

import yaml

sys.path.insert(0, str(Path(__file__).parent))

from test_scope import NOW, ROOT, ScopeTestCase, complete_scope  # noqa: E402

from sippycup_workbench import cli  # noqa: E402
from sippycup_workbench import scope_answer  # noqa: E402
from sippycup_workbench.profile import load_profile  # noqa: E402
from sippycup_workbench.scope import ScopeError, create_scope, inspect  # noqa: E402
from sippycup_workbench.scope_derive import compile_scope  # noqa: E402
from sippycup_workbench.scope_edit import EditError, apply_edits  # noqa: E402

PRACTICE_EXAMPLE = ROOT / "examples" / "scope" / "practice-scope.yaml"
WINDOW = ("2026-11-20T11:00:00Z", "2026-11-20T15:00:00Z")  # contains NOW

# Every answer for the practice target, in the order `scope answer` asks them
# on a new file (the approval comes last, with the scope it approves on screen).
PRACTICE_ANSWERS = [
    "LOCAL-PRACTICE-ONLY", "practice target (you)",          # 1
    "UTC", "2026-11-20 11:00", "+4h",                         # 3: zone, start, end
    "127.0.0.2",                                              # 4
    "5060, 5061", "udp, tls",                                 # 5: ports, transports
    "practice", "127.0.0.2", "udp", "5060", "y",              # target 1, another
    "tls", "127.0.0.2", "tls", "5061", "sippycup-practice", "work/practice/ca.crt", "n",
    "127.0.0.1",                                              # 7
    "yes",                                                    # 8
    "practice", "sippycup-practice",                          # 9
    "practice-password", "other",                             # 10
    "echo", "practice", "echo", "echo", "y",                  # 11
    "dtmf", "practice", "dtmf", "echo", "y",
    "echo-tls", "tls", "echo", "echo", "n",
    "127.0.0.2",                                              # 12
    "20000", "20019",                                         # 13
    "rtp, sdes-srtp",                                         # 14
    "PCMU, PCMA", "rfc4733",                                  # 15
    "yes",                                                    # 16
    "40", "2", "1",                                           # 17
    "200", "200000", "50000000",                              # 18
    "60", "3600",                                             # 19
    "3", "yes", "20",                                         # 20
    "options, call", "none",                                  # 21
    "you", "this terminal", "yes",                            # 22
    "7", "private",                                           # 23 (24 is optional: not asked)
    "approved",                                               # 2, last
]


class Lines(io.StringIO):
    """stdin that ends with an interrupt after the given lines."""

    def __init__(self, lines: list[str], *, interrupt: bool = False) -> None:
        super().__init__("".join(line + "\n" for line in lines))
        self.interrupt = interrupt

    def readline(self, *args) -> str:  # type: ignore[override]
        line = super().readline(*args)
        if line == "" and self.interrupt:
            raise KeyboardInterrupt
        return line


class AnswerTestCase(ScopeTestCase):
    def setUp(self) -> None:
        super().setUp()
        # The practice target's CA lives in git-ignored work/practice; a fixture stands in.
        work = Path(self._temporary.name) / "work"
        (work / "practice").mkdir(parents=True)
        fixture = ROOT / "tests" / "fixtures" / "tls" / "test-ca.crt"
        (work / "practice" / "ca.crt").write_bytes(fixture.read_bytes())
        patcher = mock.patch.dict(os.environ, {"SIPPYCUP_WORK_ROOT": str(work)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.scope = self.root / "scope.yaml"

    def new_scope(self, name: str = "practice-rehearsal") -> Path:
        return create_scope(self.root, name=name)

    def answer(self, lines: list[str], *arguments: str, interrupt: bool = False,
               settings: list[str] | None = None, change_all: bool = False) -> tuple[int, str]:
        out = io.StringIO()
        code = scope_answer.run(
            str(self.root), question=arguments[0] if arguments else None, change_all=change_all,
            settings=settings, stdin=Lines(lines, interrupt=interrupt), stdout=out, now=lambda: NOW)
        return code, out.getvalue()

    def document(self) -> dict:
        return yaml.safe_load(self.scope.read_text())


class EndToEndTests(AnswerTestCase):
    def test_init_answer_everything_check_and_compile_like_the_practice_example(self) -> None:
        self.new_scope()
        code, out = self.answer(PRACTICE_ANSWERS)
        self.assertEqual(code, 0, out)
        self.assertIn("Scope: COMPLETE and CONSISTENT", out)
        self.assertIn(f"Next: ./bin/sippycup scope compile {self.root}", out)
        self.assertIn(f"Optional, not recorded: 24 (security checks: none are approved unless the owner approved some;"
                      f" to record them: ./bin/sippycup scope answer {self.root} 24)", out)
        self.assertNotIn("== Question 24", out)
        report = inspect(self.scope, now=NOW)
        self.assertTrue(report.ok, [item.as_dict() for item in report.errors])
        self.assertEqual(stat.S_IMODE(self.scope.stat().st_mode), 0o600)
        # the template's comments are still there
        text = self.scope.read_text()
        self.assertIn("# Never put a password, token, or private key here", text)
        self.assertIn("credential_ref: practice-password   # NAME of the secret, never the password", text)
        result = compile_scope(self.root, now=NOW)
        self.assertEqual(result.exit_code, 0, result.as_dict())
        answered = {name: load_profile(self.root / name)
                    for name in ("target-profile.yaml", "target-profile-tls.yaml")}

        # the same scope from the shipped example, with the same window
        other = Path(self._temporary.name) / "example"
        other.mkdir()
        example = PRACTICE_EXAMPLE.read_text().replace("2026-01-01T00:00:00Z", WINDOW[0]).replace(
            "2026-01-01T04:00:00Z", WINDOW[1])
        (other / "scope.yaml").write_text(example)
        (other / "scope.yaml").chmod(0o600)
        self.assertEqual(compile_scope(other, now=NOW).exit_code, 0)
        for name, profile in answered.items():
            with self.subTest(profile=name):
                self.assertEqual(profile, load_profile(other / name))
        for name in ("campaign.yaml", "expectations.yaml"):
            with self.subTest(derivative=name):
                self.assertEqual(yaml.safe_load((self.root / name).read_text()),
                                 yaml.safe_load((other / name).read_text()))

    def test_cli_runs_the_answer_command(self) -> None:
        self.new_scope()
        out = io.StringIO()
        with mock.patch.object(sys, "stdin", Lines(["CHG-7", "quit"])), mock.patch.object(sys, "stdout", out):
            code = cli.main(["scope", "answer", str(self.root)])
        self.assertEqual(code, 1)
        self.assertIn("Recorded authorization.approval_id: CHG-7", out.getvalue())
        self.assertIn(f"Next: ./bin/sippycup scope answer {self.root}", out.getvalue())
        self.assertTrue(out.getvalue().rstrip().endswith("Network activity: none"))


class AnswerTypeTests(AnswerTestCase):
    def test_text_int_bool_enum_list_number(self) -> None:
        self.new_scope()
        cases = [
            ("contact", ["Jane Doe", "+31 20 123", "yes"],
             {"name": "Jane Doe", "channel": "+31 20 123", "can_stop_test": True}),
            ("evidence", ["30", "coordinated"], {"retention_days": 30, "disclosure": "coordinated"}),
            ("stop", ["3", "no", "12.5"],
             {"consecutive_failures": 3, "unexpected_response": False, "packet_loss_percent": 12.5}),
        ]
        for question, lines, expected in cases:
            with self.subTest(question=question):
                self.answer(lines, question)
                section = {"contact": "contact", "evidence": "evidence", "stop": "stop_conditions"}[question]
                self.assertEqual(self.document()[section], expected)
        self.answer(["pcmu, g722", "RFC4733"], "15")
        self.assertEqual(self.document()["media"]["codecs"], ["PCMU", "G722"])
        self.assertEqual(self.document()["media"]["dtmf"], "rfc4733")
        self.answer(["options, call", "registration flood, fuzzing"], "test_scope.classes")
        self.assertEqual(self.document()["test_scope"]["exclusions"], ["registration flood", "fuzzing"])
        self.answer(["", "NONE"], "21")
        self.assertEqual(self.document()["test_scope"]["exclusions"], ["none"])

    def test_window_with_a_named_timezone_uses_that_dates_offset(self) -> None:
        self.new_scope()
        code, out = self.answer(["Europe/Amsterdam", "2026-12-01 09:00", "2026-12-01 17:00"], "3")
        auth = self.document()["authorization"]
        self.assertEqual(auth["valid_from"], "2026-12-01T09:00:00+01:00")
        self.assertEqual(auth["valid_until"], "2026-12-01T17:00:00+01:00")
        self.assertIn("= 2026-12-01 08:00 UTC", out)
        # a window that has not started is recorded, with the note scope check gives
        self.assertIn("NOTE scope.window_not_started", out)
        self.answer(["Europe/Amsterdam", "2027-07-01 09:00", "+8h"], "3")
        self.assertEqual(self.document()["authorization"]["valid_from"], "2027-07-01T09:00:00+02:00")
        self.assertEqual(self.document()["authorization"]["valid_until"], "2027-07-01T17:00:00+02:00")

    def test_window_without_a_timezone_is_asked_again(self) -> None:
        self.new_scope()
        _, out = self.answer(["", "2026-11-20 09:00", "2026-11-20T09:00:00-05:00", "2026-11-20T17:00:00-05:00"],
                             "authorization.window")
        self.assertIn("has no timezone", out)
        self.assertEqual(self.document()["authorization"]["valid_from"], "2026-11-20T09:00:00-05:00")
        _, out = self.answer(["Mars/Olympus", "UTC", "", ""], "3")
        self.assertIn("is not a timezone I know", out)

    def test_targets_and_destinations_field_by_field(self) -> None:
        self.new_scope()
        self.answer(["10.20.30.0/24"], "4")
        self.answer(["5060", "udp", "edge", "10.20.30.40", "udp", "5060", "n"], "5")
        self.assertEqual(self.document()["targets"],
                         [{"name": "edge", "address": "10.20.30.40", "transport": "udp", "port": 5060}])
        # one target: the destination's target is implied and not asked
        _, out = self.answer(["echo", "9196", "echo", "n"], "destinations")
        self.assertNotIn("On which target", out)
        self.assertEqual(self.document()["destinations"], [{"name": "echo", "user": "9196", "expect": "echo"}])
        self.assertIsInstance(self.document()["destinations"][0]["user"], str)
        # add a second, keep the first
        self.answer(["add", "desk", "0201234567", "agent", "n"], "11")
        self.assertEqual([d["name"] for d in self.document()["destinations"]], ["echo", "desk"])
        self.assertEqual(self.document()["destinations"][1]["user"], "0201234567")

    def test_platform_answers_take_pending_and_unknown(self) -> None:
        create_scope(self.root, name="platform", platform=True)
        _, out = self.answer(["pending", "unknown"], "P15")
        operations = self.document()["platform"]["operations"]
        self.assertEqual(operations["max_concurrent_calls"], "pending")
        self.assertEqual(operations["max_requests_per_second"], "unknown")
        self.assertIn("(or pending / unknown)", out)
        self.answer(["Acme Hosting", "permitted", "ticket HOST-1"], "P7")
        hosting = self.document()["platform"]["third_parties"]["hosting"]
        self.assertEqual(hosting, {"provider": "Acme Hosting", "permission": "permitted", "reference": "ticket HOST-1"})
        self.answer(["112, 911", ""], "P12")
        self.assertEqual(self.document()["platform"]["dialing"]["never_dial"], ["112", "911"])
        # the flow-style line of the template keeps its layout
        self.assertIn("cdn_waf:      {provider: null, permission: null, reference: null}", self.scope.read_text())

    def test_platform_collections_reach_surfaces_and_identities(self) -> None:
        document = complete_scope()
        self.write_scope(document)
        text = self.scope.read_text()
        from sippycup_workbench.scope_app import TEMPLATE

        self.scope.write_text(text + TEMPLATE)
        _, out = self.answer(["on-net"], "P11")
        self.assertEqual(self.document()["platform"]["dialing"]["reach"], {"echo": "on-net"})
        _, out = self.answer(["sip.acme.tld", "sip.other.tld", "10.20.30.40", "no", "pending", "n"], "P18")
        self.assertIn("That is a name, not an address", out)
        self.assertEqual(self.document()["platform"]["addressing"],
                         [{"name": "sip.acme.tld", "addresses": ["10.20.30.40"], "shared": False,
                           "changing": "pending"}])
        self.answer(["admin-console", "browser", "in-scope", "https://admin.acme.tld", "n"], "A1")
        self.answer(["10.20.30.41", "443", "admin.acme.tld", "public"], "A2")
        surface = self.document()["application"]["surfaces"][0]
        self.assertEqual((surface["connect_address"], surface["connect_port"], surface["tls_ca"]),
                         ("10.20.30.41", 443, "public"))
        _, out = self.answer(["admin-test", "admin", "test-a", "admin-test", "n"], "A4")
        self.assertEqual(self.document()["application"]["identities"],
                         [{"id": "admin-test", "role": "admin", "tenant": "test-a", "credential_ref": "admin-test"}])
        self.assertIn("NEVER type a password here", out)
        report = inspect(self.scope, now=NOW)
        self.assertIsNotNone(report.document)
        self.assertFalse([item.as_dict() for item in report.errors if item.field.startswith(("platform", "application"))])

    def test_account_not_required_skips_the_account_questions(self) -> None:
        self.new_scope()
        _, out = self.answer(["no"], "8")
        self.assertIs(self.document()["account"]["required"], False)
        _, out = self.answer(["quit"])
        self.assertNotIn("== Question 9 of", out)
        self.assertNotIn("== Question 10 of", out)


class RejectionTests(AnswerTestCase):
    def test_hostname_is_refused_with_the_reason_then_asked_again(self) -> None:
        self.new_scope()
        _, out = self.answer(["sip.acme.tld", "10.20.30.0/24"], "4")
        self.assertIn("Not recorded: must be a literal IP address", out)
        self.assertIn("That is a name, not an address", out)
        self.assertEqual(self.document()["signaling"]["networks"], ["10.20.30.0/24"])
        self.answer(["5060", "udp"], "5")
        _, out = self.answer(["5060", "udp", "edge", "sbc.acme.tld", "10.20.30.40", "udp", "5060", "n"], "5")
        self.assertIn("target address must be a literal IP address (no hostnames)", out)
        self.assertEqual(self.document()["targets"][0]["address"], "10.20.30.40")

    def test_same_rules_as_scope_check(self) -> None:
        self.new_scope()
        self.answer(["10.20.30.0/24"], "4")
        self.answer(["5060", "udp"], "5")
        _, out = self.answer(["edge", "10.99.0.1", "10.20.30.40", "udp", "5070", "5060", "n"], "5")
        self.assertIn("target address is outside the approved signaling networks", out)
        self.assertIn("target port is not in the approved signaling ports", out)
        _, out = self.answer(["abc", "40", "50", "2"], "17")
        self.assertIn("calls must be a whole number, 1 or more", out)
        self.assertNotIn("18446744073709551615", out)
        self.assertIn("concurrent calls cannot exceed total calls", out)
        self.assertEqual(self.document()["limits"]["concurrent_calls"], 2)
        _, out = self.answer(["192.0.2.7", "10.20.30.0/24"], "12")
        self.assertIn("documentation-only range is a placeholder", out)
        # checked once calls need an account, as in scope check
        self.answer(["yes"], "account.required")
        _, out = self.answer(["PRACTICE_PASSWORD"], "account.credential_ref")
        self.assertIn("credential reference name has an unsupported format", out)

    def test_a_secret_is_never_written(self) -> None:
        self.new_scope()
        _, out = self.answer(["password=hunter2hunter2", ""], "1")
        self.assertIn("That looks like a password", out)
        self.assertNotIn("hunter2", self.scope.read_text())
        self.assertNotIn("hunter2hunter2\n  Recorded", out)

    def test_the_password_itself_is_refused_as_a_credential_reference(self) -> None:
        self.new_scope()
        (self.root / "account.password").write_text("lowercasesecret\n")
        self.answer(["yes"], "8")
        _, out = self.answer(["lowercasesecret", "acme-password", "secret-manager"], "10")
        self.assertIn("that is the password from account.password", out)
        self.assertNotIn("lowercasesecret", self.scope.read_text())
        self.assertEqual(self.document()["account"]["credential_ref"], "acme-password")

    def test_a_contradiction_with_another_answer_needs_a_yes(self) -> None:
        self.write_scope(complete_scope())
        _, out = self.answer(["10.99.0.0/24", "n", ""], "4")
        self.assertIn("contradicts another recorded answer", out)
        self.assertIn("scope.target_outside_networks", out)
        self.assertEqual(self.document()["signaling"]["networks"], ["10.20.30.0/24"])


class ApprovalTests(AnswerTestCase):
    def test_approval_must_be_the_typed_word_and_says_what_it_asserts(self) -> None:
        self.new_scope()
        _, out = self.answer(["approved"], "2")
        self.assertIn("record the reference of the written approval", out)
        self.assertEqual(self.document()["authorization"]["status"], "pending")
        document = complete_scope()
        document["authorization"].update(status="pending", approval_id="CHG-1", approved_by="Jane Doe")
        self.write_scope(document)
        _, out = self.answer(["yes", "approved"], "2")
        self.assertIn("ASSERTS that the owner approved", out)
        self.assertIn("yes is not enough", out)
        self.assertIn("reference CHG-1, approved by Jane Doe", out)
        self.assertEqual(self.document()["authorization"]["status"], "approved")

    def test_changing_a_fact_of_the_approval_sets_it_back_to_pending_and_asks_again(self) -> None:
        self.write_scope(complete_scope())
        _, out = self.answer(["UTC", "2026-11-20 11:00", "2026-11-20 15:00", ""], "authorization.window")
        self.assertIn("authorization.status is pending again", out)
        self.assertIn("== Question 2 of 24", out)
        self.assertEqual(self.document()["authorization"]["status"], "pending")
        self.answer(["approved"], "2")
        self.assertEqual(self.document()["authorization"]["status"], "approved")
        # the same answer again changes nothing and keeps the approval
        self.answer(["FERIVOX-2026-114"], "authorization.approval_id")
        self.assertEqual(self.document()["authorization"]["status"], "approved")
        code, out = self.answer([], settings=["authorization.approved_by=Someone Else"])
        self.assertIn("authorization.status is pending again", out)
        self.assertEqual(self.document()["authorization"]["status"], "pending")

    def test_set_never_records_the_approval(self) -> None:
        self.new_scope()
        with self.assertRaises(ScopeError) as caught:
            self.answer([], settings=["authorization.status=approved"])
        self.assertIn("never set with --set", str(caught.exception))
        self.assertEqual(self.document()["authorization"]["status"], "pending")

    def test_skipping_never_invents_an_answer(self) -> None:
        path = self.new_scope()
        before = path.read_bytes()
        code, out = self.answer([""] * 80)
        self.assertEqual(code, 1)
        self.assertEqual(path.read_bytes(), before)
        self.assertIn("Left open: the owner has not answered.", out)
        self.assertIn("Answers recorded in this session: 0", out)


class InterruptTests(AnswerTestCase):
    def test_ctrl_c_mid_way_keeps_the_answers_given(self) -> None:
        self.new_scope()
        code, out = self.answer(["CHG-9", "Jane Doe", "UTC", "2026-11-20 11:00"], interrupt=True)
        self.assertEqual(code, 130)
        self.assertIn("Interrupted. The answers recorded so far are saved", out)
        report = inspect(self.scope, now=NOW)
        self.assertIsNotNone(report.document)
        auth = report.document["authorization"]
        self.assertEqual((auth["approval_id"], auth["approved_by"], auth["valid_from"]),
                         ("CHG-9", "Jane Doe", "2026-11-20T11:00:00Z"))
        self.assertIsNone(auth["valid_until"])
        self.assertEqual([p.name for p in self.root.iterdir()], ["scope.yaml"])

    def test_end_of_input_inside_a_target_records_no_half_target(self) -> None:
        self.new_scope()
        self.answer(["10.20.30.0/24"], "4")
        code, out = self.answer(["5060", "udp", "edge", "10.20.30.40"], "5")
        self.assertIn("Stopped at the end of the input", out)
        self.assertEqual(self.document()["targets"], [])
        self.assertEqual(self.document()["signaling"]["ports"], [5060])
        self.assertIsNotNone(inspect(self.scope, now=NOW).document)

    def test_quit_stops_and_reports(self) -> None:
        self.new_scope()
        code, out = self.answer(["CHG-1", "quit"])
        self.assertEqual(code, 1)
        self.assertIn("Stopped. The answers recorded so far are saved.", out)
        self.assertIn("Still open: 1 (authorization)", out)


class FileHandlingTests(AnswerTestCase):
    def test_permissions_become_0600_and_no_temporary_file_is_left(self) -> None:
        path = self.new_scope()
        path.chmod(0o644)
        self.answer(["CHG-2"], "1")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["scope.yaml"])

    def test_comments_and_unasked_answers_are_kept_byte_for_byte(self) -> None:
        path = self.new_scope()
        text = path.read_text().replace("limits:\n", "limits:   # the owner's e-mail of 19 Nov\n")
        text += "# operator note: ask about the second SBC\n"
        path.write_text(text)
        self.answer(["40"], "limits.calls")
        after = path.read_text()
        self.assertIn("limits:   # the owner's e-mail of 19 Nov\n", after)
        self.assertTrue(after.endswith("# operator note: ask about the second SBC\n"))
        changed = [line for line in after.splitlines() if line not in text.splitlines()]
        self.assertEqual(changed, ["  calls: 40"])

    def test_a_layout_that_cannot_be_edited_in_place_is_rewritten_with_a_backup(self) -> None:
        path = self.new_scope()
        original = path.read_bytes()
        with mock.patch("sippycup_workbench.scope_edit.set_value", side_effect=EditError("forced")):
            _, out = self.answer(["CHG-3"], "1")
        self.assertIn("its comments are NOT kept", out)
        backups = [p for p in self.root.iterdir() if p.name.startswith("scope.yaml.bak-")]
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), original)
        self.assertEqual(stat.S_IMODE(backups[0].stat().st_mode), 0o600)
        self.assertEqual(self.document()["authorization"]["approval_id"], "CHG-3")
        self.assertTrue(inspect(path, now=NOW).document is not None)

    def test_a_file_changed_on_disk_meanwhile_is_not_overwritten(self) -> None:
        path = self.new_scope()

        class Editor(Lines):
            def readline(inner, *args):  # noqa: N805
                line = super().readline(*args)
                if line == "CHG-4\n":
                    path.write_text(path.read_text().replace("approved_by: null", "approved_by: Someone"))
                return line

        out = io.StringIO()
        code = scope_answer.run(str(self.root), question="1", stdin=Editor(["CHG-4"]), stdout=out, now=lambda: NOW)
        self.assertEqual(code, 2)
        self.assertIn("changed on disk while answering", out.getvalue())
        self.assertEqual(self.document()["authorization"]["approved_by"], "Someone")
        self.assertIsNone(self.document()["authorization"]["approval_id"])

    def test_an_invalid_file_is_refused_before_any_question(self) -> None:
        self.write_scope("schema_version: sippycup.dev/scope/v1\nname: x\nlimits: [1, 2\n")
        with self.assertRaises(ScopeError) as caught:
            self.answer([])
        self.assertIn("invalid YAML at line", str(caught.exception))
        self.assertIn("nothing was changed", str(caught.exception))

    def test_a_missing_file_says_to_run_scope_init(self) -> None:
        with self.assertRaises(ScopeError) as caught:
            self.answer([])
        self.assertIn("scope init", str(caught.exception))

    def test_editor_verifies_the_result_reads_back_the_same(self) -> None:
        from sippycup_workbench.scope import _UniqueLoader

        text = "schema_version: x\nmedia:\n  port_range: {start: null}   # c\nlist: []\n"
        document = yaml.safe_load(text)
        new, result, kept = apply_edits(text, document, [
            (("media", "port_range", "end"), 9), (("list",), [{"a": "x, y"}]), (("new", "deep"), "112")],
            _UniqueLoader)
        self.assertTrue(kept)
        self.assertEqual(yaml.safe_load(new), result)
        self.assertEqual(result["new"]["deep"], "112")
        self.assertIn("port_range: {start: null, end: 9}   # c", new)


class NonInteractiveTests(AnswerTestCase):
    def test_set_records_plain_answers_and_runs_the_check(self) -> None:
        self.new_scope()
        code, out = self.answer([], settings=["limits.calls=40", "media.codecs=pcmu,pcma", "contact.name=Jane Doe"])
        self.assertEqual(code, 1)
        self.assertIn("Recorded limits.calls: 40", out)
        self.assertEqual(self.document()["media"]["codecs"], ["PCMU", "PCMA"])
        self.assertEqual(self.document()["contact"]["name"], "Jane Doe")
        self.assertIn("Scope: INCOMPLETE", out)

    def test_set_refuses_a_wrong_answer_and_writes_nothing(self) -> None:
        path = self.new_scope()
        before = path.read_bytes()
        code, out = self.answer([], settings=["limits.calls=40", "signaling.networks=sip.acme.tld"])
        self.assertEqual(code, 2)
        self.assertIn("REFUSED scope.malformed [signaling.networks[0]]", out)
        self.assertEqual(path.read_bytes(), before)
        with self.assertRaises(ScopeError):
            self.answer([], settings=["targets=10.0.0.1"])
        with self.assertRaises(ScopeError):
            self.answer([], settings=["limits.calls"])

    def test_stdin_answers_are_echoed_so_a_log_reads_like_a_session(self) -> None:
        self.new_scope()
        _, out = self.answer(["CHG-5"], "1")
        self.assertIn("  > CHG-5\n", out)
        self.assertIn("(reading answers from standard input)", out)


class SelectionTests(AnswerTestCase):
    def test_a_question_by_number_id_part_two_id_or_field(self) -> None:
        items = scope_answer.items_for({"platform": {}})
        for wanted, identifier in (("5", "signaling.ports"), ("destinations", "destinations"), ("p11", "P11"),
                                   ("limits.packets", "limits.packets"), ("targets", "signaling.ports"),
                                   ("media.port_range.end", "media.ports")):
            with self.subTest(wanted=wanted):
                self.assertEqual(scope_answer.find_item(items, wanted).identifier, identifier)
        self.assertIsNone(scope_answer.find_item(items, "99"))

    def test_changing_an_answer_shows_the_current_value_and_clear_reopens_it(self) -> None:
        self.write_scope(complete_scope())
        _, out = self.answer(["Jane Roe", "", ""], "contact")
        self.assertIn("Current: ", out)
        self.assertEqual(self.document()["contact"]["channel"], complete_scope()["contact"]["channel"])
        self.assertEqual(self.document()["contact"]["name"], "Jane Roe")
        self.answer(["clear"], "limits.calls")
        self.assertIsNone(self.document()["limits"]["calls"])
        self.assertIn("scope.missing", {item.code for item in inspect(self.scope, now=NOW).errors})


class AllQuestionsTests(AnswerTestCase):
    def test_all_walks_answered_questions_and_enter_keeps_every_answer(self) -> None:
        self.write_scope(complete_scope())
        before = self.scope.read_bytes()
        code, out = self.answer([""] * 120, change_all=True)
        self.assertEqual(self.scope.read_bytes(), before)
        self.assertIn("== Question 22 of 24", out)
        self.assertIn("Left as it is.", out)
        self.assertIn("Answers recorded in this session: 0", out)

    def test_a_complete_scope_without_all_asks_nothing(self) -> None:
        self.write_scope(complete_scope())
        _, out = self.answer([])
        self.assertIn("Every question is answered.", out)
        _, out = self.answer(["banner-disclosure", "1"], "24")
        self.assertEqual(self.document()["security_checks"], {"approved": ["banner-disclosure"], "max_requests": 1})
        self.assertIn("security-checks", self.document()["test_scope"]["allowed_classes"])


class MessageTests(AnswerTestCase):
    def test_scope_init_without_a_directory_prints_the_full_journal_command(self) -> None:
        with self.assertRaises(ScopeError) as caught:
            create_scope(self.root / "missing")
        message = str(caught.exception)
        self.assertIn(f"./bin/sippycup journal init {self.root / 'missing'} --title \"", message)
        self.assertIn("--owner \"", message)
        self.assertIn(f"./bin/sippycup scope init {self.root / 'missing'}", message)

    def test_scope_check_and_init_name_scope_answer(self) -> None:
        self.new_scope()
        code, out, _ = self.run_main("scope", "check", str(self.root))
        self.assertEqual(code, 1)
        self.assertIn(f"./bin/sippycup scope answer {self.root}", out)
        self.assertIn("or edit scope.yaml by hand", out)
        self.write_scope(complete_scope())
        _, out, _ = self.run_main("scope", "check", str(self.root))
        self.assertIn(f"Next: ./bin/sippycup scope compile {self.root}", out)


if __name__ == "__main__":
    unittest.main()
