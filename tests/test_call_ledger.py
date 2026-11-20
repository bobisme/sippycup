"""The owner's call limit holds for the engagement, across commands (bn-2sfn).

Before this fix each `call`, `matrix run`, `checks run` and `campaign run`
checked only its own count: with `limits.calls: 2` a rehearsal placed 5 calls
and later 17, and the report said every run was inside the approval. Every
test here uses injected fakes: no container, capture, or socket.
"""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

import cockpit_support as support  # noqa: E402
from test_guided_call import Fakes  # noqa: E402

from sippycup import call_ledger  # noqa: E402
from sippycup.campaign import compile_plan  # noqa: E402
from sippycup.integration import AuthorizationLapsed, execute_campaign  # noqa: E402
from sippycup_workbench import call as guided  # noqa: E402
from sippycup_workbench import matrix  # noqa: E402

NOW = datetime.now(timezone.utc).replace(microsecond=0)
TOOL = ROOT / "tests" / "fixtures" / "campaign" / "integration-tool.py"
APPROVAL = "QUAD-APPROVAL-7Q2X"


def _reserve_one(directory: str, queue) -> None:  # runs in a child process
    try:
        call_ledger.reserve(directory, approval_id="CHG-9", ceiling=5, calls=1, command="call", source="p.yaml")
        queue.put("ok")
    except call_ledger.CeilingRefused:
        queue.put("refused")


class LedgerUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name) / "work"
        self.engagement = self.work / "acme"
        self.engagement.mkdir(parents=True)

    def reserve(self, calls: int = 1, ceiling: int = 2, approval: str = "CHG-9"):
        return call_ledger.reserve(self.engagement, approval_id=approval, ceiling=ceiling, calls=calls,
                                   command="call", source="target-profile.yaml")

    def test_reservations_add_up_and_the_next_one_is_refused_with_the_counts(self) -> None:
        self.reserve()
        self.reserve()
        with self.assertRaises(call_ledger.CeilingRefused) as caught:
            self.reserve()
        message = str(caught.exception)
        for text in ("approval CHG-9 allows 2 call(s) in this engagement", "2 already counted", "0 remain",
                     "would place 1", "nothing was sent", "Only the owner can raise the limit",
                     "limits.calls in work/acme/scope.yaml", "./bin/sippycup scope compile work/acme"):
            self.assertIn(text, message)
        # A larger request than what remains is refused too, without counting.
        self.assertEqual(call_ledger.check(self.engagement, "CHG-9").used, 2)
        # Another approval id has its own count.
        self.reserve(approval="CHG-10")

    def test_released_calls_do_not_count(self) -> None:
        reservation = self.reserve(calls=2)
        reservation.release(1, "nothing was sent")
        self.assertEqual(call_ledger.check(self.engagement, "CHG-9").used, 1)
        self.reserve()
        with self.assertRaises(call_ledger.CeilingRefused):
            self.reserve()

    def test_ledger_is_private_and_append_only_jsonl(self) -> None:
        self.reserve()
        path = self.engagement / call_ledger.LEDGER_FILE
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        entry = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual((entry["event"], entry["approval"], entry["calls"], entry["ceiling"]),
                         ("reserve", "CHG-9", 1, 2))

    def test_concurrent_commands_cannot_both_pass_the_check(self) -> None:
        context = multiprocessing.get_context("fork")
        queue = context.Queue()
        workers = [context.Process(target=_reserve_one, args=(str(self.engagement), queue)) for _ in range(12)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(30)
        outcomes = sorted(queue.get(timeout=5) for _ in workers)
        self.assertEqual(outcomes.count("ok"), 5, outcomes)
        self.assertEqual(outcomes.count("refused"), 7, outcomes)
        self.assertEqual(call_ledger.check(self.engagement, "CHG-9").used, 5)

    def test_missing_ledger_with_earlier_runs_refuses_and_says_how_to_recover(self) -> None:
        run = self.engagement / "calls" / "20261119T000000Z-acme-1"
        run.mkdir(parents=True)
        (run / "profile.json").write_text(json.dumps({"authorization": {"approval_id": "CHG-9"}}))
        (run / "result.json").write_text("{}")
        with self.assertRaises(call_ledger.LedgerError) as caught:
            self.reserve()
        message = str(caught.exception)
        self.assertIn("call ledger work/acme/call-ledger.jsonl is missing", message)
        self.assertIn("1 run(s) in work/acme that placed or may have placed calls under approval CHG-9", message)
        self.assertIn("calls/20261119T000000Z-acme-1 (it names no reservation in this ledger)", message)
        self.assertIn("restore work/acme/call-ledger.jsonl from your backup", message)
        self.assertIn("new approval id", message)
        # Finding 1 (bn-y3er): the refusal no longer names the bypass; it says
        # what happens if the operator tries it.
        self.assertNotIn("Do not create an empty ledger", message)
        self.assertIn("An empty, shortened or new ledger is refused the same way", message)
        self.assertFalse((self.engagement / call_ledger.LEDGER_FILE).exists())
        # A run under another approval does not block a new approval id.
        self.reserve(approval="CHG-10")

    def test_runs_whose_records_show_no_call_do_not_block_a_missing_ledger(self) -> None:
        options_only = self.engagement / "runs" / "20261119T000000Z-baseline-1"
        options_only.mkdir(parents=True)
        (options_only / "plan.json").write_text(json.dumps({
            "authorization": {"approval": {"id": "CHG-9"}},
            "steps": [{"index": 1, "budget": {"calls": 0}}, {"index": 2, "budget": {"calls": 0}}]}))
        (options_only / "result.json").write_text("{}")
        no_invite = self.engagement / "checks" / "20261119T000000Z-checks-1"
        no_invite.mkdir(parents=True)
        (no_invite / "profile.json").write_text(json.dumps({"authorization": {"approval_id": "CHG-9"}}))
        (no_invite / "plan.json").write_text(json.dumps({"inviteAttempts": 0}))
        (no_invite / "result.json").write_text(json.dumps({"requestLog": [{"request": "OPTIONS"}]}))
        nothing_sent = self.engagement / "checks" / "20261119T000001Z-checks-2"
        nothing_sent.mkdir(parents=True)
        (nothing_sent / "profile.json").write_text(json.dumps({"authorization": {"approval_id": "CHG-9"}}))
        (nothing_sent / "result.json").write_text(json.dumps({"requestLog": [], "requestsSent": 0}))
        self.assertEqual(call_ledger.earlier_runs(self.engagement, "CHG-9"), [])
        # A checks run with INVITE attempts that sent requests counts, even when
        # its log names no INVITE (on TCP the first request is logged as the
        # connection); so does a campaign that budgets a call.
        nothing_sent.rename(self.engagement / "elsewhere")
        (no_invite / "plan.json").write_text(json.dumps({"inviteAttempts": 1}))
        (no_invite / "result.json").write_text(json.dumps(
            {"requestLog": [{"request": "TCP connection and its first request"}], "requestsSent": 1}))
        (options_only / "plan.json").write_text(json.dumps({
            "authorization": {"approval": {"id": "CHG-9"}}, "steps": [{"index": 1, "budget": {"calls": 1}}]}))
        self.assertEqual(len(call_ledger.earlier_runs(self.engagement, "CHG-9")), 2)

    def test_unreadable_or_truncated_ledger_refuses(self) -> None:
        path = self.engagement / call_ledger.LEDGER_FILE
        for content, text in ((b"not json\n", "is not valid JSON"),
                              (b'{"v": "x"}\n', "is not a sippycup.dev/call-ledger/v1 entry"),
                              (b'{"v": "sippycup.dev/call-ledger/v1", "event": "reserve"', "incomplete line")):
            with self.subTest(text=text):
                path.write_bytes(content)
                with self.assertRaisesRegex(call_ledger.LedgerError, text):
                    self.reserve()

    def test_only_the_practice_bench_may_start_a_new_window(self) -> None:
        self.reserve(calls=2)
        with self.assertRaises(call_ledger.LedgerError):
            call_ledger.new_approval_window(self.engagement, approval_id="CHG-9", budget=99, by="me")
        with self.assertRaises(call_ledger.LedgerError):
            call_ledger.new_approval_window(self.engagement, approval_id="LOCAL-PRACTICE-ONLY", budget=99, by="me")
        # A hand-written window record outside work/practice is refused, not honoured.
        path = self.engagement / call_ledger.LEDGER_FILE
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"v": call_ledger.VERSION, "event": "new-approval-window",
                                     "approval": "CHG-9", "calls": 99}) + "\n")
        with self.assertRaisesRegex(call_ledger.LedgerError, "only practice-target up may record"):
            self.reserve()

    def test_practice_up_starts_a_new_window_with_the_bench_budget(self) -> None:
        bench = self.work / "practice"
        bench.mkdir()
        call_ledger.reserve(bench, approval_id="LOCAL-PRACTICE-ONLY", ceiling=1, calls=1, command="call",
                            source="target-profile.yaml")
        call_ledger.new_approval_window(bench, approval_id="LOCAL-PRACTICE-ONLY", budget=3, by="up")
        for _ in range(3):
            call_ledger.reserve(bench, approval_id="LOCAL-PRACTICE-ONLY", ceiling=1, calls=1, command="call",
                                source="target-profile.yaml")
        with self.assertRaisesRegex(call_ledger.CeilingRefused, "allows 3 call"):
            call_ledger.reserve(bench, approval_id="LOCAL-PRACTICE-ONLY", ceiling=1, calls=1, command="call",
                                source="target-profile.yaml")


class EngagementCeilingTests(unittest.TestCase):
    """The rehearsal's sequence against `limits.calls: 2`, with fakes."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = support.make_repo(Path(temporary.name))
        self.work = self.repo / "work"
        self.root = support.compiled_engagement(self.repo, now=NOW, go=False)
        self.profile = self.root / "target-profile.yaml"

    def call(self, fakes: Fakes | None = None):
        fakes = fakes or Fakes()
        options = guided.CallOptions(profile=self.profile, destination="echo", duration=3)
        code, value = guided.execute(options, fakes.dependencies(self.work, now=lambda: NOW))
        return fakes, code, value

    def campaign(self):
        manifest = self.root / "campaign.yaml"
        raw = manifest.read_bytes()
        plan = compile_plan(yaml.safe_load(raw), hashlib.sha256(raw).hexdigest())
        order = self.root / "order.txt"
        return execute_campaign(
            plan, manifest_bytes=raw, run_root=self.root / "runs",
            runner=[sys.executable, str(TOOL), "runner", str(order)],
            capture_command=[sys.executable, str(TOOL), "capture", "{capture}", str(order)],
            report_command=[sys.executable, str(TOOL), "report", "{capture}"],
            preflight=lambda _destination: (True, "SIP/2.0 200 OK"),
            allow_test_runner=True, manifest_path=manifest, clock=lambda: NOW,
        )

    def test_third_call_is_refused_before_any_packet(self) -> None:
        for _ in range(2):
            _fakes, code, _value = self.call()
            self.assertEqual(code, 0)
        fakes, code, value = self.call()
        self.assertEqual(code, 2)
        self.assertEqual(value["state"], "blocked")
        self.assertEqual(fakes.events, [])
        self.assertEqual(value["networkActivity"], "none")
        self.assertIn("2 already counted", value["blockingErrors"][0])
        self.assertNotIn("already placed", value["blockingErrors"][0])
        self.assertIn("0 remain", value["blockingErrors"][0])
        self.assertEqual(len(list((self.root / "calls").iterdir())), 2)
        rendered = guided.render_human(value)
        self.assertIn("Only the owner can raise the limit", rendered)

    def test_a_run_placed_with_run_root_elsewhere_is_counted_where_it_was_reserved(self) -> None:
        other = self.work / "other"
        fakes = Fakes()
        options = guided.CallOptions(profile=self.profile, destination="echo", duration=3,
                                     run_root=other / "calls")
        code, value = guided.execute(options, fakes.dependencies(self.work, now=lambda: NOW))
        self.assertEqual(code, 0, value)
        self.assertEqual(value["callLedger"]["ledger"], "../../../eng/call-ledger.jsonl")
        # The engagement whose ledger counted the run holds it; the directory
        # that only holds the run directory does not refuse for it.
        self.assertEqual(call_ledger.check(self.root, APPROVAL).used, 1)
        self.assertEqual(call_ledger.earlier_runs(other, APPROVAL), [])
        # Without that ledger the run counts again (fail closed).
        (self.root / call_ledger.LEDGER_FILE).unlink()
        self.assertEqual(len(call_ledger.earlier_runs(other, APPROVAL)), 1)

    def test_a_call_that_sent_nothing_does_not_count(self) -> None:
        _fakes, code, value = self.call(Fakes(capture_ready="capture failed"))
        self.assertNotEqual(code, 0)
        self.assertNotIn("preflight_sent", value["timestamps"])
        self.assertEqual(call_ledger.check(self.root, APPROVAL).used, 0)
        # Finding 8 (bn-y3er): a failed preflight sent no INVITE, so the call
        # is released, with the reason in the ledger.
        _fakes, code, value = self.call(Fakes(preflight=(False, "no_response: timeout")))
        self.assertNotEqual(code, 0)
        self.assertIs(value["callCounted"], False)
        self.assertEqual(call_ledger.check(self.root, APPROVAL).used, 0)
        last = json.loads((self.root / call_ledger.LEDGER_FILE).read_text().splitlines()[-1])
        self.assertEqual(last["event"], "release")
        self.assertIn("no INVITE was sent", last["reason"])

    def test_dry_run_is_not_ready_once_the_limit_is_used(self) -> None:
        for _ in range(2):
            self.call()
        fakes = Fakes()
        code, plan = guided.execute(
            guided.CallOptions(profile=self.profile, destination="echo", dry_run=True),
            fakes.dependencies(self.work, now=lambda: NOW),
        )
        self.assertEqual(code, 2)
        self.assertFalse(plan["ready"])

    def test_campaign_counts_with_calls_and_is_refused_when_it_would_exceed(self) -> None:
        result, _run_dir = self.campaign()  # one call step
        self.assertEqual(result.state, "succeeded")
        self.assertEqual(call_ledger.check(self.root, APPROVAL).used, 1)
        _fakes, code, _value = self.call()
        self.assertEqual(code, 0)
        runs = sorted((self.root / "runs").iterdir())
        with self.assertRaisesRegex(AuthorizationLapsed, "0 remain, and this campaign run would place 1"):
            self.campaign()
        self.assertEqual(sorted((self.root / "runs").iterdir()), runs, "no run directory for a refusal")

    def test_matrix_reserves_the_whole_grid_and_refuses_beyond_the_limit(self) -> None:
        self.call()
        options = matrix.MatrixOptions(profiles=(self.profile,), destination="echo", codecs=("PCMU",),
                                       srtp=("off",), max_calls=4, duration=3)
        plan = matrix.build_plan(options, now=NOW, work_root=self.work)
        self.assertTrue(plan["ready"], plan["blockingErrors"])  # 1 + 1 <= 2
        self.call()
        plan = matrix.build_plan(options, now=NOW, work_root=self.work)
        self.assertFalse(plan["ready"])
        self.assertTrue(any("would place 1" in item for item in plan["blockingErrors"]), plan["blockingErrors"])

    def summary(self):
        from sippycup_workbench.summary_model import Options, build_report

        model, _ = build_report(self.root, Options(generated_at="2026-11-19T00:00:00Z"))
        return model

    def test_summary_reports_calls_above_the_limit_including_earlier_overruns(self) -> None:
        for _ in range(2):
            self.call()
        model = self.summary()
        self.assertFalse([e for e in model["integrityExceptions"] if e["code"] == "call-limit-exceeded"])
        # An overrun from before the fix: a third call that no ledger counted.
        (self.root / call_ledger.LEDGER_FILE).unlink()
        (self.root / "calls").rename(self.root / "calls-kept")
        _fakes, code, _value = self.call()
        self.assertEqual(code, 0)
        for run in (self.root / "calls-kept").iterdir():
            run.rename(self.root / "calls" / run.name)
        model = self.summary()
        overrun = [e for e in model["integrityExceptions"] if e["code"] == "call-limit-exceeded"]
        self.assertEqual(len(overrun), 1, model["integrityExceptions"])
        self.assertIn(f"under {APPROVAL} in this engagement to 3, above the approved limit of 2", overrun[0]["detail"])
        self.assertNotIn("Every run fell inside", model["executiveSummary"]["paragraph"])

    def test_matrix_run_releases_cells_that_sent_nothing(self) -> None:
        fakes = Fakes()
        executed = []

        def execute(options, deps):
            executed.append(deps.ledger_reserved)
            return 0, {"verdict": "pass", "timestamps": {"preflight_sent": "x"}, "softphone": {}}

        deps = matrix.MatrixDependencies(
            execute=execute, call_dependencies=lambda environ: fakes.dependencies(self.work, now=lambda: NOW),
            now=lambda: NOW, sleep=lambda _s: None, work_root=self.work, install_signal_handlers=False,
        )
        options = matrix.MatrixOptions(profiles=(self.profile,), destination="echo", codecs=("PCMU",),
                                       srtp=("off",), max_calls=4, duration=3)
        code, value = matrix.run(options, deps)
        self.assertEqual((code, value["callsPlaced"]), (0, 1))
        self.assertEqual(executed, [True], "each cell runs under the grid's reservation")
        self.assertEqual(call_ledger.check(self.root, APPROVAL).used, 1)
        code, value = matrix.run(options, deps)
        self.assertEqual(call_ledger.check(self.root, APPROVAL).used, 2)
        code, value = matrix.run(options, deps)
        self.assertEqual(code, 2)
        self.assertEqual(value["state"], "blocked")
        self.assertEqual(len(executed), 2)


if __name__ == "__main__":
    unittest.main()
