"""Intake, recovery text and rehearsal output after the third first-time-operator rehearsal.

Findings 11 to 16 and 18 to 30 of that rehearsal, and the check-count mismatch
between `scope check` and the planner. Offline only: nothing here opens a
socket or starts a container; the routed rehearsal runs with a fake runner.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cockpit_support import (  # noqa: E402
    NOW as COCKPIT_NOW, call_result, compiled_engagement, make_engagement, make_repo, write_approved_profile,
    write_run,
)
from test_guided_call import Fakes, GuidedCallCase  # noqa: E402
from test_scope import complete_scope  # noqa: E402
from test_scope_answer import PRACTICE_ANSWERS, AnswerTestCase  # noqa: E402

from sippycup import approval, call_ledger, integration, practice  # noqa: E402
from sippycup import practice_rehearsal as rehearsal  # noqa: E402
from sippycup import routed_rehearsal as routed  # noqa: E402
from sippycup_checks import catalog, scope_support  # noqa: E402
from sippycup_cockpit import model as cockpit_model  # noqa: E402
from sippycup_cockpit import render as cockpit_render  # noqa: E402
from sippycup_cockpit.model import build_model  # noqa: E402
from sippycup_cockpit.render import render_dashboard  # noqa: E402
from sippycup_workbench import call as guided  # noqa: E402
from sippycup_workbench import cleanup, cli, scope_answer  # noqa: E402
from sippycup_workbench.call_explanations import CALL_EXPLANATIONS  # noqa: E402
from sippycup_workbench import profile as profile_module  # noqa: E402
from sippycup_workbench.scope import ScopeError, create_scope, security_check_requests  # noqa: E402
from sippycup_workbench.scope_app import TEMPLATE as PLATFORM_TEMPLATE  # noqa: E402
from sippycup_workbench.scope_derive import compile_scope, derivative_integrity  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
FIRST = (ROOT / "docs" / "FIRST-ENGAGEMENT.md").read_text(encoding="utf-8")

# The practice answers of docs/FIRST-ENGAGEMENT.md for part 2 (P1 to P18; no web part, so A1 to A6 are not asked).
PLATFORM_ANSWERS = [
    "y",                                                      # the part 2 offer
    "Practice platform", "yes", "yes", *["no"] * 9,           # P1
    "nothing",                                                # P2
    "dedicated-test", "no", "none", "none",                   # P3 to P6
    *["none"] * 5,                                            # P7 to P10
    "on-net", "on-net", "on-net",                             # P11
    "none", "", "no-cost",                                    # P12, P13
    "any time, UTC", "2", "1", "none", "you", "this terminal", "stop",   # P14 to P17
    "sippycup-practice", "127.0.0.2", "no", "no", "n",        # P18
]


class RecoveryTextTests(AnswerTestCase):
    """Finding 14: every recovery text names `scope answer ENG 2` and then compile."""

    def pending(self) -> None:
        document = complete_scope()
        document["authorization"]["status"] = "pending"
        self.write_scope(document)

    def test_next_after_a_reset_is_the_approval_and_then_compile(self) -> None:
        self.write_scope(complete_scope())
        code, out = self.answer(["43"], "limits.calls")
        self.assertEqual(self.document()["authorization"]["status"], "pending")
        self.assertEqual(code, 1, out)
        last = [line for line in out.splitlines() if line.startswith("Next: ")][-1]
        self.assertTrue(last.startswith(f"Next: ./bin/sippycup scope answer {self.root} 2 "), last)
        self.assertIn(f"then ./bin/sippycup scope compile {self.root}", last)
        message = next(line for line in out.splitlines() if "is pending again" in line)
        self.assertIn(f"./bin/sippycup scope answer {self.root} 2", message)
        self.assertIn(f"./bin/sippycup scope compile {self.root}; until both are done nothing can be sent", message)

    def test_a_long_list_change_says_what_was_added_and_removed(self) -> None:
        before = [{"name": f"destination-{index}", "target": "edge", "user": "9196"} for index in range(4)]
        after = before[1:] + [{"name": "desk", "target": "edge", "user": "0201234567"}]
        text = scope_answer._change_text("destinations", before, after)
        self.assertIn("added {name: desk", text)
        self.assertIn("removed {name: destination-0", text)
        self.assertEqual(scope_answer._change_text("limits.calls", 4, 5), "limits.calls: 4 -> 5")

    def test_the_pending_refusal_of_a_compiled_profile_gives_its_next_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = make_repo(Path(directory))
            root = compiled_engagement(repo, now=COCKPIT_NOW, account=True)
            profile = root / "target-profile.yaml"
            hint, error = profile_module.with_next_command, profile_module.PENDING_ERROR
            self.assertEqual(error, "authorization is pending, not approved")
            self.assertEqual(hint(["other"], profile), ["other"])
            scope = root / "scope.yaml"
            text = scope.read_text()
            # scope.yaml says approved: the profile is pending because of a scope error
            (approved,) = hint([error], profile)
            self.assertIn("scope check", approved)
            scope.write_text(text.replace("status: approved", "status: pending"))
            (pending,) = hint([error], profile)
            self.assertTrue(pending.startswith(error + "; nothing can be sent with this profile; "), pending)
            self.assertRegex(pending,
                             r"\./bin/sippycup scope answer \S+ 2, then run \./bin/sippycup scope compile \S+$")
            # no scope file beside the profile: the error is left as it is
            scope.unlink()
            self.assertEqual(hint([error], profile), [error])
            self.assertEqual(hint([error], None), [error])

    def test_compile_of_a_pending_scope_says_nothing_can_be_sent_and_names_the_stale_campaign(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = make_repo(Path(directory))
            root = compiled_engagement(repo, now=COCKPIT_NOW, account=True)
            first = compile_scope(root, now=COCKPIT_NOW).as_dict()
            lines = cli.compile_next_lines(first, str(root))
            self.assertEqual(len(lines), 1, lines)
            self.assertTrue(lines[0].startswith("Next: ./bin/sippycup rehearse "), lines)   # finding 30
            self.assertTrue(lines[0].endswith("target-profile.yaml"), lines)
            scope = root / "scope.yaml"
            scope.write_text(scope.read_text().replace("status: approved", "status: pending"))
            outcome = compile_scope(root, now=COCKPIT_NOW)
            self.assertEqual(outcome.exit_code, 1)
            lines = cli.compile_next_lines(outcome.as_dict(), str(root))
            self.assertTrue(lines[0].startswith(f"STALE: {root}/campaign.yaml is from an earlier scope compile"), lines)
            self.assertTrue(lines[1].startswith("NOTHING CAN BE SENT with what this wrote: the target profile is "
                                                "pending, not approved"), lines)
            self.assertTrue(lines[2].startswith(f"Next: ./bin/sippycup scope answer {root} 2 "), lines)
            self.assertIn(f"then ./bin/sippycup scope compile {root} again", lines[2])
            # the earlier campaign.yaml is still refused, and the refusal says why and what to do
            state = derivative_integrity(root / "campaign.yaml")
            self.assertEqual(state["state"], "stale")
            self.assertIn("the last scope compile did not write it again", state["error"])
            self.assertIn("scope answer work/eng 2", state["error"])
            self.assertIn("scope compile work/eng", state["error"])

    def test_the_call_limit_and_new_window_texts_name_the_approval_step(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            text = call_ledger.refusal_text(Path(directory), "A-1", 3, 3, 1, "call")
        answer = text.index(" limits.calls (that sets the approval back to pending)")
        again = text.index("record the approval again with ./bin/sippycup scope answer ")
        self.assertLess(answer, again)
        self.assertLess(again, text.index("./bin/sippycup scope compile "))
        self.assertIn("nothing was sent", text)
        self.assertRegex(approval.NEW_WINDOW, r"scope answer \S+ 2")

    def test_scope_init_platform_error_keeps_the_flag(self) -> None:
        missing = self.root / "missing" / "eng"
        with self.assertRaises(ScopeError) as caught:
            create_scope(missing, name="acme", platform=True)
        self.assertIn(f"scope init {missing} --platform", str(caught.exception))   # finding 21

    def test_the_page_names_the_approval_step_where_it_tells_the_operator_to_change_an_answer(self) -> None:
        self.assertIn("./bin/sippycup scope answer work/acme 2      # record the approval again", FIRST)
        for row in (line for line in FIRST.splitlines() if line.startswith("|") and "new written window" in line):
            with self.subTest(row=row[:60]):
                self.assertIn("scope answer work/acme 2", row)
        self.assertIn("NOTHING CAN BE SENT with what this wrote", FIRST)
        self.assertIn("BLOCK: authorization is pending, not approved; ...", FIRST)


class PlatformIntakeTests(AnswerTestCase):
    """Finding 15: the platform part can be skipped once, practised, and is in the approval summary."""

    def platform_scope(self, status: str = "pending") -> None:
        document = complete_scope()
        document["authorization"]["status"] = status
        self.write_scope(document)
        self.scope.write_text(self.scope.read_text() + PLATFORM_TEMPLATE)

    def test_enter_at_the_offer_skips_the_platform_questions_and_the_approval_still_works(self) -> None:
        self.platform_scope()
        code, out = self.answer(["", "approved"])
        self.assertIn("== Part 2: the whole platform (questions P1 to P18 and A1 to A6) ==", out)
        self.assertEqual(out.count("Walk the platform questions now?"), 1)
        self.assertNotIn("== Question P", out)
        self.assertNotIn("== Question A", out)
        self.assertEqual(self.document()["authorization"]["status"], "approved")
        self.assertEqual(code, 0, out)   # open platform answers do not hold the approval (unchanged rule)
        self.assertIn("Platform answers still open: P1, ", out)
        self.assertIsNone(self.document()["platform"]["name"])

    def test_y_walks_them_and_a_named_question_gets_no_offer(self) -> None:
        self.platform_scope()
        _, out = self.answer(["y", "Acme Voice", "quit"])
        self.assertIn("== Question P1:", out)
        self.assertEqual(self.document()["platform"]["name"], "Acme Voice")
        _, out = self.answer(["quit"], "P3")
        self.assertNotIn("Walk the platform questions now?", out)
        self.assertIn("== Question P3:", out)

    def test_the_approval_summary_says_where_each_destination_goes(self) -> None:
        self.platform_scope()
        _, out = self.answer(["", ""])
        self.assertIn("Platform dialing (questions P11 to P13): echo: NOT RECORDED; echo-tls: NOT RECORDED", out)
        self.assertIn("NOT RECORDED = ", out)
        document = self.document()
        document["platform"]["dialing"]["reach"] = {"echo": "pstn", "echo-tls": "on-net"}
        self.write_scope(document)
        _, out = self.answer([""], "2")
        self.assertIn("echo: REACHES THE PUBLIC PHONE NETWORK; echo-tls: stays on the platform", out)
        # a scope without part 2 has no such line
        self.write_scope(complete_scope())
        _, out = self.answer([""], "2")
        self.assertNotIn("Platform dialing", out)

    def test_the_documented_practice_answers_complete_a_platform_scope(self) -> None:
        create_scope(self.root, name="practice-rehearsal", platform=True)
        code, out = self.answer([*PRACTICE_ANSWERS[:-1], *PLATFORM_ANSWERS, "approved"])
        self.assertEqual(code, 0, out[-3000:])
        self.assertIn("Scope: COMPLETE and CONSISTENT", out)
        self.assertNotIn("Platform answers still open", out)
        self.assertNotIn("Not recorded:", out)
        self.assertNotIn("== Question A", out)
        summary = out.split("== Question 2 of 24")[1]
        self.assertIn("echo: stays on the platform", summary)
        self.assertIn("never dial: none; cost of public-network calls (toll): no-cost", summary)

    def test_the_page_has_the_practice_answers_for_every_platform_question(self) -> None:
        table = FIRST.split("| Part 2 offer | `y` |")[1].split("On a real engagement type the owner's")[0]
        for label in ("| P1 |", "| P2 |", "| P3 to P6 |", "| P7 to P10 |", "| P11 |", "| P12, P13 |",
                      "| P14 to P17 |", "| P18 |", "| A1 |", "| A2 |", "| A3 |", "| A4 |", "| A5, A6 |"):
            with self.subTest(label=label):
                self.assertIn(label, table)
        self.assertIn("Walk the platform questions now? [y/N] >", FIRST)


class HeldNotesTests(AnswerTestCase):
    """Findings 16 and 19: WARN lines wait for the end of the question; a half answer is named."""

    def test_a_warn_line_is_printed_once_after_the_question_not_between_its_prompts(self) -> None:
        self.write_scope(complete_scope())
        self.scope.write_text(self.scope.read_text() + PLATFORM_TEMPLATE)
        _, out = self.answer(["add", "desk", "edge", "0201234567", "echo", "", ""], "destinations")
        walk = out.split("== Where the scope stands")[0]
        warn = "WARN scope.destination_reach_open [platform.dialing.reach.desk]"
        self.assertEqual(walk.count(warn), 1, walk)
        self.assertLess(walk.index("Another destination? [y/N] >"), walk.index(warn))
        header = walk.index("scope check also notes after the answers above")
        self.assertLess(header, walk.index(warn))
        self.assertLess(walk.index(warn), walk.index("== Question 2 of 24"))
        # the summary still has it
        self.assertIn("WARN  scope.destination_reach_open [platform.dialing.reach.desk]", out.split(walk)[1])

    def test_quit_between_the_check_ids_and_the_ceiling_says_what_was_not_saved(self) -> None:
        self.write_scope(complete_scope())
        code, out = self.answer(["banner-disclosure", "quit"], "24")
        self.assertIsNone(self.document().get("security_checks", {}).get("approved")
                          if isinstance(self.document().get("security_checks"), dict) else None)
        self.assertIn("Not saved: the check ids (banner-disclosure) were not saved: the request ceiling is needed "
                      f"too. To record both: ./bin/sippycup scope answer {self.root} 24.", out)
        self.assertLess(out.index("Not saved: "), out.index("Answers recorded in this session: 0"))
        # nothing half typed: no such line
        _, out = self.answer(["quit"], "24")
        self.assertNotIn("Not saved:", out)

    def test_an_ended_window_is_named_before_the_approval_is_typed(self) -> None:
        document = complete_scope()
        document["authorization"].update(status="pending", valid_until="2020-06-01T17:00:00+01:00")
        self.write_scope(document)
        _, out = self.answer([""], "2")
        self.assertIn(f"scope answer {self.root} authorization.window", out)   # finding 26


class CheckBoundTests(AnswerTestCase):
    """The ceiling `scope check` asks for is the planner's bound for the compiled profile."""

    def planned(self, approved: list[str]) -> list[tuple[str, int]]:
        document = complete_scope()
        targets = document["targets"]
        document["test_scope"]["allowed_classes"] = [*document["test_scope"]["allowed_classes"], "security-checks"]
        document["security_checks"] = {"approved": approved, "max_requests": 200}
        section = scope_support.profile_section(document)   # what scope compile writes into the profile
        self.assertIsNotNone(section)
        return [(name, catalog.declared_bound(catalog.get(name), section, targets[0].get("transport")))
                for name in approved]

    def test_scope_check_and_the_compiled_profile_count_the_same(self) -> None:
        for approved in (["user-enumeration"], ["user-enumeration", "banner-disclosure"],
                         ["user-enumeration", "unauthenticated-invite"], ["user-enumeration", "srtp-policy"],
                         ["banner-disclosure", "srtp-policy"], ["unauthenticated-invite"]):
            with self.subTest(approved=approved):
                needs = security_check_requests(complete_scope(), approved)
                self.assertEqual([(name, bound) for name, bound, _ in needs], self.planned(approved))
        self.assertEqual(security_check_requests(complete_scope(), ["user-enumeration"]), [("user-enumeration", 2, 0)])
        self.assertEqual(security_check_requests(complete_scope(), ["user-enumeration", "unauthenticated-invite"])[0],
                         ("user-enumeration", 10, 2))

    def test_the_intake_states_two_for_user_enumeration_alone_and_accepts_that_ceiling(self) -> None:
        self.write_scope(complete_scope())
        _, out = self.answer(["user-enumeration", "2"], "24")
        self.assertIn("These checks may send up to 2 requests in this scope: user-enumeration 2.", out)
        self.assertEqual(self.document()["security_checks"], {"approved": ["user-enumeration"], "max_requests": 2})

    def test_the_sheet_text_says_when_it_is_two_and_when_ten(self) -> None:
        text = scope_support.bound_text(catalog.get("user-enumeration"))
        self.assertEqual(text, "at most 2 requests, two REGISTER queries; 10 when you also approve a check that "
                               "calls your test destination (unauthenticated-invite or srtp-policy), because it "
                               "then also sends INVITEs there")


class CaptureFailureTests(unittest.TestCase):
    """Finding 11: a wrong --interface is not a permission problem."""

    def test_no_such_device_says_leave_out_interface(self) -> None:
        text = integration.capture_start_failure_text(
            "tshark: The capture session could not be initiated on interface 'eth9'\n(No such device exists)\n")
        self.assertIn("packet capture could not start (No such device exists). Nothing was sent", text)
        self.assertIn("No such interface", text)
        self.assertIn("Leave out --interface", text)
        self.assertNotIn("CAP_NET_RAW", text)
        self.assertIn("Nothing was sent", text)

    def test_a_permission_failure_keeps_the_launcher_advice(self) -> None:
        text = integration.capture_start_failure_text(
            "dumpcap: You don't have permission to capture on that device (socket: Operation not permitted)")
        self.assertIn("CAP_NET_RAW", text)
        self.assertNotIn("No such interface", text)
        both = integration.capture_start_failure_text("")
        self.assertIn("CAP_NET_RAW", both)
        self.assertIn("--interface", both)


class RoutedRehearsalOutputTests(unittest.TestCase):
    """Findings 12 and 18: the routed rehearsal runs the documented commands and says what to expect."""

    def driver(self, runner=None):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        project = Path(self.temporary.name)
        self.out = io.StringIO()
        self.calls: list[list[str]] = []

        def record(argv, env, timeout):
            self.calls.append(list(argv))
            return runner(argv) if runner else rehearsal.Completed(argv, 0, "", "")

        driver = routed.RoutedRehearsal(project, runner=record, out=self.out)
        driver.engagement = project / "work" / "eng"
        driver.engagement.mkdir(parents=True)
        driver.shape = rehearsal.Shape("direct", routed.ROUTED_ADDRESS, (routed.ROUTED_ADDRESS,), practice.DNS_NAME,
                                       practice.DNS_NAME, "routed")
        driver.current = rehearsal.Stage(1, "t")
        return driver

    def test_both_preflights_are_bound_to_their_profile(self) -> None:
        def runner(argv):
            tls = argv[-1].endswith("routed-tls.yaml")
            port = practice.SIGNALING_PORTS["tls" if tls else "udp"]
            text = (f"Target:    {routed.ROUTED_ADDRESS}:{port}\n"
                    f"Scope: profile x approval {routed.ROUTED_APPROVAL_ID}\n"
                    + (f"TLS: verified for name '{practice.DNS_NAME}'\n" if tls else "") + "Result: PASS\n")
            return rehearsal.Completed(argv, 0, text, "")

        driver = self.driver(runner)
        driver.preflight()
        self.assertEqual(self.calls, [
            ["./bin/sippycup", "preflight", "--profile", "work/eng/target-profile.yaml"],
            ["./bin/sippycup", "preflight", "--profile", "work/eng/target-profile-routed-tls.yaml"],
        ])

    def test_an_unbound_preflight_fails_the_stage(self) -> None:
        def runner(argv):
            return rehearsal.Completed(argv, 0, (
                f"Target:    {routed.ROUTED_ADDRESS}:{practice.SIGNALING_PORTS['udp']}\nScope: profile x approval "
                f"{routed.ROUTED_APPROVAL_ID}\nScope: UNBOUND (operator-supplied target)\nResult: PASS\n"), "")

        with self.assertRaises(rehearsal.RehearsalError):
            self.driver(runner).preflight()

    def test_campaign_run_is_the_documented_command(self) -> None:
        driver = self.driver()
        documented = ["./bin/sippycup", "campaign", "run", "work/eng/plan.json", "--manifest",
                      "work/eng/campaign.yaml", "--run-root", "work/eng/runs"]
        action = {"argv": [*documented[:3], "--isolated", *documented[3:], "--interface", "any"]}
        self.assertEqual(driver.campaign_run_argv(action), documented)
        self.assertIn("campaign run work/acme/plan.json --manifest work/acme/campaign.yaml "
                      "--run-root work/acme/runs", " ".join(FIRST.replace("\\\n", " ").split()))
        with self.assertRaises(rehearsal.RehearsalError):
            driver.campaign_run_argv({"argv": [*documented, "--interface", "eth0"]})
        with self.assertRaises(rehearsal.RehearsalError):
            driver.campaign_run_argv({"argv": [*documented, "--allow-anything"]})
        # the practice rehearsal keeps the cockpit's own action
        base = rehearsal.Rehearsal(Path("."), runner=lambda *a: None, out=io.StringIO())
        self.assertEqual(base.campaign_run_argv(action), action["argv"])

    def test_the_nat_line_is_on_screen_and_the_last_lines_say_what_to_expect(self) -> None:
        driver = self.driver()
        driver.source = "192.0.2.50"
        with self.assertRaises(rehearsal.RehearsalError):
            driver.nat_line()
        run = driver.engagement / "calls" / "20261117T100000.000000Z-a"
        run.mkdir(parents=True)
        (run / "result.json").write_text(json.dumps({"natAddresses": ["203.0.113.9"]}))
        driver.nat_line()
        self.assertIn("NAT: the target saw our source as 203.0.113.9", self.out.getvalue())
        lines = driver.expectation_lines()
        self.assertEqual(len([line for line in lines if line.startswith("  ")]), 3)
        text = "\n".join(lines)
        self.assertIn('"Testing from behind NAT"', text)
        self.assertIn("\n## Testing from behind NAT\n", FIRST)
        self.assertIn("203.0.113.9", text)
        self.assertIn("192.0.2.50", text)
        self.assertIn("symmetric RTP", text)
        self.assertIn("possible-nat-one-way-media", text)
        self.assertIn("RTCP", text)


class CockpitTests(unittest.TestCase):
    """Finding 20: `go --plain` carries the calls line; stage 2 knows the documented practice call."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = make_repo(Path(self.temporary.name))

    def test_the_dashboard_has_the_calls_line(self) -> None:
        root = compiled_engagement(self.repo, now=COCKPIT_NOW)
        model = build_model(root, repo=self.repo, now=COCKPIT_NOW)
        line = cockpit_render.calls_line(model)
        self.assertIsNotNone(line)
        self.assertRegex(line, r"^Calls: 0 of \d+ used, \d+ left \(approval ")
        self.assertIn(f"Call limit     {line}", render_dashboard(model, now=COCKPIT_NOW))
        empty = {"authorization": {}, "engagement": {"path": str(root)}, "profile": {}}
        self.assertIsNone(cockpit_render.calls_line(empty))

    def test_a_passing_journalled_practice_call_made_the_documented_way_completes_stage_2(self) -> None:
        from sippycup_workbench.journal import append

        root = compiled_engagement(self.repo, now=COCKPIT_NOW)
        name = "20261117T100000.000000Z-practice-0001"
        write_run(root, "calls", name, {"result.json": call_result("pass", profile="practice", host="127.0.0.2")})

        def practice_done() -> bool:
            return build_model(root, repo=self.repo, now=COCKPIT_NOW)["readiness"]["practice"]["pass"]

        before = build_model(root, repo=self.repo, now=COCKPIT_NOW)
        (run,) = [item for item in before["runs"] if item["name"] == name]
        journal = {"evidence": [f"calls/{name}/result.json"]}
        self.assertFalse(cockpit_model._documented_practice_call(run, {"evidence": []}))        # not journalled
        self.assertTrue(cockpit_model._documented_practice_call(run, journal))
        self.assertFalse(cockpit_model._documented_practice_call({**run, "passed": False}, journal))
        self.assertFalse(cockpit_model._documented_practice_call({**run, "target": {"host": "192.0.2.20"}}, journal))
        self.assertFalse(cockpit_model._documented_practice_call({**run, "target": {"host": "sbc.example"}}, journal))
        append(root, kind="action", summary="practice call", evidence=[f"calls/{name}/result.json"])
        after = build_model(root, repo=self.repo, now=COCKPIT_NOW)
        steps = {step["label"]: step["done"] for stage in after["stages"] for step in stage.get("steps", [])}
        self.assertTrue(steps["passing practice call recorded in this engagement"], steps)
        steps = {step["label"]: step["done"] for stage in before["stages"] for step in stage.get("steps", [])}
        self.assertFalse(steps["passing practice call recorded in this engagement"])


class PapercutTests(GuidedCallCase):
    def test_22_a_dry_run_with_a_username_and_no_password_source_says_the_real_call_needs_one(self) -> None:
        _, value = self.run_call(Fakes(), dry_run=True, username="alice")
        rendered = guided.render_human(value)
        self.assertIn("NOTE: no password source was given.", rendered)
        self.assertIn("--secret-file FILE", rendered)
        _, value = self.run_call(Fakes(), dry_run=True, username="alice", secret_env="SOME_NAME")
        self.assertNotIn("NOTE: no password source", guided.render_human(value))

    def test_27_rehearse_warns_when_the_window_is_nearly_over(self) -> None:
        def shown(seconds: int) -> str:
            until = (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                cli._emit({"ready": True, "errors": [], "warnings": [],
                           "facts": {"authorization": {"valid_until": until}}}, "human")
            return out.getvalue()

        self.assertIn("WARN:  the approval window ends in ", shown(120))
        self.assertIn("may refuse although this says Ready: yes", shown(120))
        self.assertNotIn("the approval window ends in", shown(7200))

    def test_28_a_failed_registration_says_stop_and_ask_the_owner(self) -> None:
        text = CALL_EXPLANATIONS["call.registration-failed"][1]
        self.assertIn("Stop: do not try again without the owner", text)
        self.assertNotIn("Fix the credentials; use --no-register", text)

    def test_30_the_cleanup_listing_says_the_images_are_untagged_old_builds(self) -> None:
        report = cleanup.Report(apply=False, items=[cleanup.Item("images", "a80bcb71a96a", "untagged old build")])
        text = cleanup.render(report)
        self.assertIn("untagged leftovers of earlier builds", text)
        self.assertIn("is never removed", text)
        self.assertIn("--apply never removes a tagged image", FIRST)

    def test_13_the_page_and_checks_run_agree_on_the_exit_code(self) -> None:
        self.assertNotIn("Exit 1 with findings is normal.", FIRST)
        self.assertIn("Exit 0: completed,\n  and no finding is `medium` or higher", FIRST)


if __name__ == "__main__":
    unittest.main()
