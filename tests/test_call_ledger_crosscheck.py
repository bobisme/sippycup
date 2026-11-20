"""Rehearsal 2 findings 1, 2, 7, 8 and 13 (matrix line) on the call ledger (bn-y3er).

1. An emptied or shortened ledger restarted the count while the run
   directories showed the calls. The cross-check now runs on every count.
2. `summary` skipped every run under the practice approval id, so an
   engagement that rehearsed under it never saw `call-limit-exceeded`.
7. Nothing showed how many calls were left until the refusal.
8. Attempts that sent no INVITE (registration failed, preflight unanswered)
   used up the limit.
13. `matrix` said "narrow ... to 6 calls or fewer" when 1 remained.

Every test uses injected fakes: no container, capture, or socket.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

import cockpit_support as support  # noqa: E402
from test_guided_call import Fakes  # noqa: E402

from sippycup import call_ledger  # noqa: E402
from sippycup_softphone.driver import SoftphoneResult  # noqa: E402
from sippycup_workbench import call as guided  # noqa: E402
from sippycup_workbench import matrix  # noqa: E402

NOW = datetime.now(timezone.utc).replace(microsecond=0)
APPROVAL = "QUAD-APPROVAL-7Q2X"


def registration_failed(call, _cancel):
    result = SoftphoneResult(destination_uri="sip:x")
    result.started = True
    result.registration_attempted = True
    result.registered = False
    result.registration_status = 403
    result.error = "registration_failed"
    return result


def busy(call, _cancel):
    result = SoftphoneResult(destination_uri="sip:x")
    result.started = result.dialed = True
    result.final_status = 486
    result.hangup = "remote"
    return result


class Engagement(unittest.TestCase):
    approval = APPROVAL
    scope_changes: tuple[tuple[str, str], ...] = ()
    # Two targets leave the campaign uncompiled (no destination target); the
    # profiles are written all the same.
    compile_must_pass = True

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = support.make_repo(Path(temporary.name))
        self.work = self.repo / "work"
        self.root = support.make_engagement(self.repo, "eng")
        text = support.scope_text(valid_from=NOW - timedelta(hours=1), valid_until=NOW + timedelta(hours=3),
                                  approval_id=self.approval)
        for old, new in self.scope_changes:
            self.assertIn(old, text)
            text = text.replace(old, new)
        support.write_scope(self.root, text)
        from sippycup_workbench.scope_derive import compile_scope

        outcome = compile_scope(self.root, now=NOW)
        if self.compile_must_pass:
            self.assertEqual(outcome.exit_code, 0, outcome.as_dict())
        self.profile = self.root / "target-profile.yaml"
        self.ledger = self.root / call_ledger.LEDGER_FILE

    def call(self, fakes: Fakes | None = None, **options):
        fakes = fakes or Fakes()
        code, value = guided.execute(
            guided.CallOptions(profile=self.profile, destination="echo", duration=3, **options),
            fakes.dependencies(self.work, now=lambda: NOW),
        )
        return fakes, code, value

    def used(self) -> int:
        return call_ledger.check(self.root, self.approval).used


class CrossCheckTests(Engagement):
    """Finding 1: the ledger's count is never lower than the run directories show."""

    def test_an_emptied_ledger_is_refused_and_names_the_runs(self) -> None:
        for _ in range(2):
            self.assertEqual(self.call()[1], 0)
        self.ledger.write_bytes(b"")  # the tester's `rm ...; touch ...`
        fakes, code, value = self.call()
        self.assertEqual((code, value["state"], fakes.events), (2, "blocked", []))
        message = value["blockingErrors"][0]
        self.assertIn("counts 0 call(s) under approval QUAD-APPROVAL-7Q2X, but it does not account for 2 run(s)", message)
        self.assertIn("(its reservation is not in the ledger)", message)
        self.assertIn("nothing was sent", message)
        self.assertIn("restore work/eng/call-ledger.jsonl from your backup", message)
        self.assertIn("An empty, shortened or new ledger is refused the same way", message)
        self.assertNotIn("Do not create an empty ledger", message)
        self.assertEqual(len(list((self.root / "calls").iterdir())), 2, "no run directory for a refusal")

    def test_a_ledger_shortened_to_its_first_line_is_refused(self) -> None:
        for _ in range(2):
            self.call()
        first = self.ledger.read_text().splitlines()[0]
        self.ledger.write_text(first + "\n")
        # The limit alone would allow one more call (1 of 2 counted).
        fakes, code, value = self.call()
        self.assertEqual((code, fakes.events), (2, []))
        self.assertIn("does not account for 1 run(s)", value["blockingErrors"][0])

    def test_a_deleted_ledger_is_refused_too(self) -> None:
        self.call()
        self.ledger.unlink()
        fakes, code, value = self.call()
        self.assertEqual((code, fakes.events), (2, []))
        self.assertIn("is missing, so it does not account for 1 run(s)", value["blockingErrors"][0])
        self.assertFalse(self.ledger.exists())

    def test_a_run_killed_before_its_result_is_still_accounted_for(self) -> None:
        self.call()
        run = next((self.root / "calls").iterdir())
        record = json.loads((run / call_ledger.RUN_RECORD_FILE).read_text())
        self.assertEqual(record["ledger"], "../../call-ledger.jsonl")
        (run / "result.json").unlink()  # killed: the result was never written
        self.assertEqual(self.call()[1], 0)
        # The record alone is not enough when the ledger lost the reservation.
        self.ledger.write_bytes(b"")
        self.assertEqual(self.call()[1], 2)

    def test_one_matrix_reservation_accounts_for_every_cell_run(self) -> None:
        options = matrix.MatrixOptions(profiles=(self.profile,), destination="echo", codecs=("PCMU",),
                                       srtp=("off",), max_calls=4, duration=3)
        deps = matrix.MatrixDependencies(
            call_dependencies=lambda environ: Fakes().dependencies(self.work, now=lambda: NOW),
            now=lambda: NOW, sleep=lambda _s: None, work_root=self.work, install_signal_handlers=False,
        )
        code, value = matrix.run(options, deps)
        self.assertEqual((code, value["callsPlaced"]), (0, 1), value.get("blockingErrors"))
        cell = next((self.root / "calls").iterdir())
        reserve = [json.loads(line) for line in self.ledger.read_text().splitlines()][0]
        self.assertEqual(reserve["command"], "matrix run")
        self.assertEqual(json.loads((cell / call_ledger.RUN_RECORD_FILE).read_text())["reservation"], reserve["id"])
        self.assertEqual(self.used(), 1)
        self.assertEqual(self.call()[1], 0)

    def test_a_run_counted_by_another_engagement_ledger_is_accounted_for(self) -> None:
        other = self.work / "other"
        other.mkdir()
        fakes, code, value = self.call(run_root=other / "calls")
        self.assertEqual(code, 0, value)
        (other / call_ledger.LEDGER_FILE).write_bytes(b"")
        self.assertEqual(call_ledger.check(other, APPROVAL).used, 0)
        self.assertEqual(call_ledger.unaccounted_runs(other, APPROVAL, call_ledger.Usage(0)), [])


class PracticeBenchWindowTests(unittest.TestCase):
    """The practice bench's new approval window covers its earlier runs, and only those."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.bench = Path(temporary.name) / "work" / "practice"
        self.bench.mkdir(parents=True)

    def run_dir(self, stamp: str) -> Path:
        run = self.bench / "calls" / f"{stamp}-sippycup-local-practice-0000"
        run.mkdir(parents=True)
        (run / "profile.json").write_text(json.dumps({"authorization": {"approval_id": "LOCAL-PRACTICE-ONLY"}}))
        (run / "result.json").write_text(json.dumps({"verdict": "pass"}))
        return run

    def test_runs_before_the_window_are_covered_and_later_ones_are_not(self) -> None:
        self.run_dir("20200101T000000.000000Z")  # from before the ledger existed
        with self.assertRaises(call_ledger.LedgerError):
            call_ledger.check(self.bench, "LOCAL-PRACTICE-ONLY")
        call_ledger.new_approval_window(self.bench, approval_id="LOCAL-PRACTICE-ONLY", budget=5, by="up")
        self.assertEqual(call_ledger.check(self.bench, "LOCAL-PRACTICE-ONLY").used, 0)
        self.run_dir("29990101T000000.000000Z")  # after the window, but counted nowhere
        with self.assertRaisesRegex(call_ledger.LedgerError, "does not account for 1 run"):
            call_ledger.check(self.bench, "LOCAL-PRACTICE-ONLY")

    def test_an_engagement_cannot_use_a_window_record(self) -> None:
        engagement = self.bench.parent / "rehearsal"
        engagement.mkdir()
        self.assertFalse(call_ledger.is_practice_bench(engagement))
        self.assertTrue(call_ledger.is_practice_bench(self.bench))


class WhatCountsTests(Engagement):
    """Finding 8: an attempt in which no INVITE left the tool does not use a call."""

    def test_registration_failure_is_released_with_its_reason(self) -> None:
        _fakes, code, value = self.call(Fakes(softphone=registration_failed))
        self.assertNotEqual(code, 0)
        self.assertIs(value["callCounted"], False)
        self.assertEqual(self.used(), 0)
        entries = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual([entry["event"] for entry in entries], ["reserve", "release"])
        self.assertIn("no INVITE was sent: the softphone never dialed", entries[1]["reason"])

    def test_a_dialed_call_counts_whatever_happened(self) -> None:
        _fakes, code, value = self.call(Fakes(softphone=busy))
        self.assertNotEqual(code, 0)
        self.assertIs(value["callCounted"], True)
        self.assertEqual(self.used(), 1)

    def test_the_rule_in_one_function(self) -> None:
        self.assertFalse(guided.call_counts(False, None))
        self.assertTrue(guided.call_counts(True, None), "a softphone with no result counts")
        self.assertFalse(guided.call_counts(True, {"dialed": False}))
        self.assertTrue(guided.call_counts(True, {"dialed": True}))

    def test_matrix_releases_cells_whose_softphone_never_dialed(self) -> None:
        options = matrix.MatrixOptions(profiles=(self.profile,), destination="echo", codecs=("PCMU",),
                                       srtp=("off",), max_calls=4, duration=3)
        deps = matrix.MatrixDependencies(
            call_dependencies=lambda environ: Fakes(softphone=registration_failed).dependencies(
                self.work, now=lambda: NOW),
            now=lambda: NOW, sleep=lambda _s: None, work_root=self.work, install_signal_handlers=False,
        )
        matrix.run(options, deps)
        self.assertEqual(self.used(), 0)

    def test_checks_release_the_invites_of_checks_that_sent_nothing(self) -> None:
        from sippycup_checks import checks, runner
        from test_checks import profile_document, test_deps, write_profile

        def options_only(ctx):
            ctx.budget.spend("OPTIONS")
            return checks.CheckResult("banner-disclosure", "passed", "fake")

        def silent(ctx):
            return checks.CheckResult("unauthenticated-invite", "skipped", "fake: sent nothing")

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            section = {"approved": ["banner-disclosure", "unauthenticated-invite"], "max_requests": 10,
                       "destination": "echo"}
            profile = write_profile(root, profile_document("127.0.0.1", 5060, "udp", section))
            deps = test_deps(root, implementations={**checks.IMPLEMENTATIONS, "banner-disclosure": options_only,
                                                    "unauthenticated-invite": silent})
            _code, value = runner.execute(runner.RunOptions(profile=profile), deps)
            self.assertEqual(value["requestsSent"], 1)
            # Before: one request left, so the INVITE attempt was kept.
            self.assertEqual(call_ledger.check(root, "TEST-1").used, 0)


class CallsLeftTests(Engagement):
    """Finding 7: `Calls: N of M used, K left`, from the count the refusal uses."""

    def test_rehearse_dry_run_and_status_show_the_line(self) -> None:
        from sippycup_workbench.cli import rehearse_file

        self.call()
        status = call_ledger.status(self.root, APPROVAL, 2)
        self.assertEqual(status.line().split(" (")[0], "Calls: 1 of 2 used, 1 left")
        rehearsal = rehearse_file(self.profile)
        self.assertTrue(rehearsal.ready, rehearsal.errors)
        self.assertTrue(rehearsal.facts["calls"]["line"].startswith("Calls: 1 of 2 used, 1 left"))
        self.call()
        rehearsal = rehearse_file(self.profile)
        self.assertFalse(rehearsal.ready)
        self.assertTrue(any("0 remain" in error for error in rehearsal.errors), rehearsal.errors)
        code, plan = guided.execute(guided.CallOptions(profile=self.profile, destination="echo", dry_run=True),
                                    Fakes().dependencies(self.work, now=lambda: NOW))
        rendered = guided.render_human(plan)
        self.assertIn("Calls: 2 of 2 used, 0 left", rendered)
        self.assertIn("this call would place 1, but none are left, so it would be refused", rendered)
        # An untrusted ledger says so on the same line.
        self.ledger.write_bytes(b"")
        rehearsal = rehearse_file(self.profile)
        self.assertFalse(rehearsal.ready)
        self.assertTrue(rehearsal.facts["calls"]["line"].startswith("Calls: cannot be counted"))

    def test_ready_is_no_go_without_calls_or_with_an_untrusted_ledger(self) -> None:
        from sippycup_cockpit import ready

        model = {"engagement": {"display": "work/eng"}}
        document = guided.load_profile(self.profile)
        check = ready.check_calls(model, self.profile, document)
        self.assertEqual(check.status, ready.GO)
        self.assertTrue(check.lines[0].startswith("Calls: 0 of 2 used, 2 left"))
        for _ in range(2):
            self.call()
        check = ready.check_calls(model, self.profile, document)
        self.assertEqual(check.status, ready.NOGO)
        self.assertIn("none left", check.lines[0])
        self.assertIn("limits.calls", check.fix)
        self.ledger.write_bytes(b"")
        check = ready.check_calls(model, self.profile, document)
        self.assertEqual(check.status, ready.NOGO)
        self.assertIn("cannot be trusted", check.lines[0])

    def test_cockpit_live_panel_shows_limits_in_words_and_calls_left(self) -> None:
        from sippycup_cockpit import actions

        self.call()
        model = {"engagement": {"path": str(self.root)}, "authorization": {"approvalId": APPROVAL},
                 "profile": {"limits": {"max_calls": 2, "max_concurrency": 1, "max_calls_per_second": 1,
                                        "max_duration_seconds": 20}},
                 "target": {"host": "127.0.0.2", "port": 5060, "transport": "udp"},
                 "readiness": {"practice": {"running": False}}}
        lines = actions._bounded_lines(model, {"id": "call"}, self.repo, NOW)
        text = "\n".join(lines)
        self.assertNotIn("Profile limits: {", text)
        self.assertIn("Each call lasts at most 20 s", text)
        self.assertIn("Calls: 1 of 2 used, 1 left", text)

    def test_checks_plan_says_how_many_calls_it_would_place(self) -> None:
        from sippycup_checks import runner

        document = guided.load_profile(self.profile)
        document["security_checks"] = {"approved": ["unauthenticated-invite"], "max_requests": 10,
                                       "destination": "echo"}
        plan = runner.build_plan(document, now=NOW, profile_path=self.profile)
        self.assertIn("Calls: 0 of 2 used, 2 left", runner.render_plan(plan))
        self.assertIn("this checks run would place 1", runner.render_plan(plan))


class MatrixNarrowTests(Engagement):
    """Finding 13 (matrix line): narrow to the calls that remain, not to the limit."""

    scope_changes = (
        ("  transports: [udp]\n", "  transports: [udp, tcp]\n"),
        ("    port: 5060\n", "    port: 5060\n  - name: edge-tcp\n    address: 127.0.0.2\n    transport: tcp\n    port: 5060\n"),
        ("  codecs: [PCMU]\n", "  codecs: [PCMU, PCMA]\n"),
        ("  calls: 2\n", "  calls: 3\n"),
        ("    expect: echo\n", "    expect: echo\n    target: edge\n  - name: echo-tcp\n    user: echo\n"
                              "    expect: echo\n    target: edge-tcp\n"),
    )

    def test_the_shared_ceiling_message_uses_the_calls_left(self) -> None:
        profiles = sorted(self.root.glob("target-profile*.yaml"))
        self.assertEqual(len(profiles), 2, profiles)
        for _ in range(2):
            self.assertEqual(self.call()[1], 0)
        options = matrix.MatrixOptions(profiles=tuple(profiles), destination="echo", codecs=("PCMU", "PCMA"),
                                       srtp=("off",), max_calls=8, duration=3)
        plan = matrix.build_plan(options, now=NOW, work_root=self.work)
        self.assertFalse(plan["ready"])
        shared = [item for item in plan["blockingErrors"] if "share one call ceiling" in item]
        self.assertEqual(len(shared), 1, plan["blockingErrors"])
        self.assertIn("to 1 call(s) or fewer in total (2 of the 3 already counted)", shared[0])
        self.assertNotIn("to 3 calls or fewer", shared[0])
        rendered = matrix.render_human(plan)
        self.assertIn("Calls: 2 of 3 used, 1 left", rendered)
        self.assertIn("this matrix would place 4, more than the 1 left, so it would be refused", rendered)
        ledger = [item for item in plan["blockingErrors"] if item.startswith("call limit:")]
        self.assertIn("Narrow it to 1 call(s) or fewer", ledger[0])


class CampaignPlanTests(Engagement):
    """Finding 7: a campaign plan that the remaining calls cannot cover is not written."""

    def test_campaign_plan_refuses_without_calls_and_says_so(self) -> None:
        from sippycup import campaign

        manifest = self.root / "campaign.yaml"
        self.assertTrue(manifest.exists())
        output = self.root / "plan.json"
        stderr = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
            code = campaign.main(["plan", str(manifest), "--output", str(output)])
        self.assertEqual(code, 0, stderr.getvalue())
        self.assertIn("Calls: 0 of 2 used, 2 left", stderr.getvalue())
        self.assertIn("this campaign would place 1", stderr.getvalue())
        output.unlink()
        for _ in range(2):
            self.call()
        stderr = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
            code = campaign.main(["plan", str(manifest), "--output", str(output)])
        self.assertEqual(code, 2)
        self.assertFalse(output.exists())
        self.assertIn("refusing to plan: call limit", stderr.getvalue())
        self.assertIn("0 remain, and this campaign run would place 1", stderr.getvalue())
        self.assertIn("No plan was written", stderr.getvalue())


class RehearsalUnderThePracticeApprovalTests(Engagement):
    """Finding 2: an engagement that uses the practice approval id is still an engagement."""

    approval = "LOCAL-PRACTICE-ONLY"

    def summary(self):
        from sippycup_workbench.summary_model import Options, build_report

        model, _ = build_report(self.root, Options(generated_at="2026-11-19T00:00:00Z"))
        return model

    def test_an_overrun_is_reported_and_the_report_says_so_plainly(self) -> None:
        from sippycup_workbench.summary_render import render_text

        for _ in range(2):
            self.call()
        model = self.summary()
        self.assertEqual([e for e in model["integrityExceptions"] if "call-l" in e["code"]], [])
        row = model["callLimits"][0]
        self.assertEqual((row["approvalId"], row["limit"], row["counted"], row["left"], row["placedByRuns"]),
                         ("LOCAL-PRACTICE-ONLY", 2, 2, 0, 2))
        text = render_text(model, "0" * 64)
        self.assertIn("CALL LIMIT", text)
        self.assertIn("Approval LOCAL-PRACTICE-ONLY: Calls: 2 of 2 used, 0 left.", text)
        self.assertIn("Approved call limit: 2", text)
        self.assertIn("Calls counted: 2", text)
        # The tester's bypass (finding 1) placed a third call before this fix.
        self.ledger.unlink()
        (self.root / "calls").rename(self.root / "kept")
        self.assertEqual(self.call()[1], 0)
        for run in (self.root / "kept").iterdir():
            run.rename(self.root / "calls" / run.name)
        model = self.summary()
        codes = sorted(e["code"] for e in model["integrityExceptions"])
        self.assertIn("call-limit-exceeded", codes)
        self.assertIn("call-ledger-unaccounted", codes)
        paragraph = model["executiveSummary"]["paragraph"]
        self.assertIn("The owner's call limit was exceeded: 3 calls were placed under approval "
                      "LOCAL-PRACTICE-ONLY, above the approved limit of 2.", paragraph)
        self.assertNotIn("Every run fell inside", paragraph)
        self.assertIn("LIMIT EXCEEDED", render_text(model, "0" * 64))


if __name__ == "__main__":
    unittest.main()


class CampaignReleaseTests(unittest.TestCase):
    """Finding 8: a campaign releases steps that never started and softphone steps that never dialed."""

    def test_unsent_calls(self) -> None:
        from sippycup.integration import _step_artifact_directory, _unsent_calls

        plan = {"steps": [{"index": index, "budget": {"calls": calls}} for index, calls in
                          ((1, 0), (2, 1), (3, 1), (4, 1), (5, 1))]}
        with tempfile.TemporaryDirectory() as name:
            run = Path(name)
            self.assertEqual(_unsent_calls(plan, run), 4, "no events: nothing started")
            (run / "events.jsonl").write_text("".join(
                json.dumps({"event": "step.started", "step": step}) + "\n" for step in (1, 2, 3, 4)))
            for step, dialed in ((2, False), (3, True)):
                directory = _step_artifact_directory(run, plan["steps"][step - 1])
                directory.mkdir(parents=True)
                (directory / "softphone.json").write_text(json.dumps({"softphone": {"dialed": dialed}}))
            # Step 2 never dialed, step 5 never started; step 3 dialed and step 4
            # (SIPp, or no record) counts once it started.
            self.assertEqual(_unsent_calls(plan, run), 2)
