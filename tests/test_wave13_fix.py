"""Wave 13: the fifth rehearsal's findings (bn-3btx).

Finding 1 (SAFETY): the owner report attributes every call the ledger counts
to a run, the calls of ``checks run`` included, or raises an exception.
Finding 2 (SAFETY): the report states the de-duplicated count of a sibling
directory, as the command line does. Finding 3 (SAFETY): a sibling ledger
that exists and cannot be read stops this directory. Finding 4: the fix
commands name the directory the operator is in. Findings 5 to 7 and the
papercuts follow. Nothing here sends anything.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from sippycup import call_ledger  # noqa: E402
from sippycup_workbench.summary_model import Options, build_report  # noqa: E402
from sippycup_workbench.summary_render import call_limit_lines, render_markdown  # noqa: E402

import test_checks_srtp as srtp  # noqa: E402

GENERATED = "2026-11-20T00:00:00Z"


def report(root: Path, **options) -> dict:
    return build_report(root, Options(generated_at=GENERATED, **options))[0]


def codes(model: dict) -> list[str]:
    return [item["code"] for item in model["integrityExceptions"]]


class ChecksRunCallsInTheReportTests(unittest.TestCase):
    """Finding 1: the two calls of ``srtp-policy`` are in the count, the row and the totals."""

    section = srtp.SrtpPolicyRunTests.section
    execute = srtp.SrtpPolicyRunTests.execute

    def checks_run(self) -> tuple[Path, Path, dict]:
        fake = srtp.FakeCalls({
            ("off", "udp"): {"requests": 4},
            ("mandatory", "udp"): {"requests": 5, "answer_profile": "RTP/SAVP", "answer_crypto": True,
                                   "active": True},
        })
        _code, value, run_dir = self.execute(fake, self.section(), expected=True)
        self.assertEqual(len(fake.calls), 2)
        return run_dir.parent.parent, run_dir, value

    def row(self, model: dict) -> dict:
        (row,) = model["callLimits"]
        return row

    def test_the_run_records_the_calls_it_counted(self) -> None:
        root, run_dir, value = self.checks_run()
        self.assertEqual(value["callsCounted"], 2)
        self.assertEqual(json.loads((run_dir / "result.json").read_text())["callsCounted"], 2)
        approval = self.row(report(root))["approvalId"]
        self.assertEqual(call_ledger.check(root, approval).used, 2)

    def test_counted_and_placed_agree_and_the_run_row_shows_the_calls(self) -> None:
        root, run_dir, _value = self.checks_run()
        model = report(root)
        row = self.row(model)
        self.assertEqual((row["counted"], row["placedByRuns"], row["unattributedCalls"]), (2, 2, 0))
        (run,) = model["runs"]
        self.assertEqual(run["sent"]["calls"], 2)
        self.assertEqual(model["totals"]["calls"]["total"], 2)
        self.assertEqual(model["callLimitTotals"]["placedByRuns"], 2)
        self.assertNotIn("call-ledger-unattributed", codes(model))
        text = render_markdown(model, "0" * 64)
        self.assertIn("2 calls, 9 check requests", text)
        self.assertIn("Calls placed under it by the runs in this report: 2.", text)

    def test_a_run_from_before_the_record_is_counted_from_the_ledger(self) -> None:
        # The fifth rehearsal's runs: result.json has callLedger and no callsCounted.
        root, run_dir, _value = self.checks_run()
        result = json.loads((run_dir / "result.json").read_text())
        del result["callsCounted"]
        (run_dir / "result.json").write_text(json.dumps(result))
        row = self.row(report(root))
        self.assertEqual((row["counted"], row["placedByRuns"]), (2, 2))

    def test_a_counted_call_that_no_run_names_is_an_exception(self) -> None:
        root, _run_dir, _value = self.checks_run()
        approval = self.row(report(root))["approvalId"]
        # A call counted in the ledger whose run directory is not among the report's runs.
        call_ledger.reserve(root, approval_id=approval, ceiling=3, calls=1, command="call",
                            source="target-profile.yaml")
        model = report(root)
        row = self.row(model)
        self.assertEqual((row["counted"], row["placedByRuns"], row["unattributedCalls"]), (3, 2, 1))
        (exception,) = [item for item in model["integrityExceptions"] if item["code"] == "call-ledger-unattributed"]
        self.assertIn("counts 1 call(s) under", exception["detail"])
        self.assertIn("1 reserved by call at ", exception["detail"])
        self.assertIn("--run-root", exception["detail"])
        (line, _total) = call_limit_lines(model)
        self.assertIn("1 of the counted calls are NOT among the runs in this report (1 reserved by call at ", line)

    def test_a_narrowed_report_says_so_instead_of_raising(self) -> None:
        root, _run_dir, _value = self.checks_run()
        model = report(root, run_globs=("no-such-run*",))
        row = self.row(model)
        self.assertEqual((row["counted"], row["placedByRuns"], row["unattributedCalls"]), (2, 0, 2))
        self.assertNotIn("call-ledger-unattributed", codes(model))
        self.assertIn("the report was narrowed with --runs or --since", call_limit_lines(model)[0])

    def test_calls_the_ledger_keeps_beyond_what_the_runs_recorded_are_said(self) -> None:
        root, run_dir, _value = self.checks_run()
        result = json.loads((run_dir / "result.json").read_text())
        result["callsCounted"] = 1
        (run_dir / "result.json").write_text(json.dumps(result))
        model = report(root)
        row = self.row(model)
        self.assertEqual((row["counted"], row["placedByRuns"], row["unattributedCalls"], row["countedBeyondRuns"]),
                         (2, 1, 0, 1))
        self.assertIn("1 more are counted for the runs in this report than those runs recorded as placed",
                      call_limit_lines(model)[0])


# ------------------------------------------------- findings 2, 3 and 4: two directories

import contextlib  # noqa: E402
import io  # noqa: E402
from unittest import mock  # noqa: E402

import yaml  # noqa: E402

from sippycup_cockpit import ready  # noqa: E402

from test_call_ledger_crosscheck import APPROVAL, Engagement  # noqa: E402
from test_call_ledger_crosscheck import NOW as ENGAGEMENT_NOW  # noqa: E402
from test_wave12_last import TwoDirectories  # noqa: E402


class CopiedDirectoryReportTests(Engagement):
    """Finding 2: both owner reports state the de-duplicated count after ``cp -r``."""

    scope_changes = (("  calls: 2\n", "  calls: 40\n"),)

    def copied(self) -> Path:
        """Two calls, the ledger copied to a sibling (as ``cp -r`` does), two more calls here."""
        for _ in range(2):
            self.assertEqual(self.call()[1], 0)
        other = self.work / "eng-copy"
        other.mkdir()
        (other / call_ledger.LEDGER_FILE).write_bytes(self.ledger.read_bytes())
        for _ in range(2):
            self.assertEqual(self.call()[1], 0)
        return other

    def limitation(self, model: dict) -> str:
        (item,) = [item for item in model["limitations"] if item["code"] == "same-approval-in-another-directory"]
        return item["text"]

    def test_the_directory_that_holds_every_call_says_the_copy_adds_none(self) -> None:
        self.copied()
        model = report(self.root)
        text = self.limitation(model)
        self.assertIn("work/eng-copy counts 2 call(s), all of them the same calls as 2 counted here", text)
        self.assertIn("No call is counted there that is not counted in this report", text)
        self.assertIn("Counted once, the approval has 4 call(s) in these directories, the 4 in this report", text)
        self.assertNotIn("Those calls are not in this report", text)
        self.assertNotIn("not the whole count", text)
        (row,) = model["callLimits"]
        self.assertEqual(row["sameApprovalElsewhere"]["countedOnce"], 4)
        self.assertEqual(row["sameApprovalElsewhere"]["countedOnlyElsewhere"], 0)
        line = call_limit_lines(model)[0]
        self.assertIn("The same approval is also counted in another directory on the assessor's machine "
                      "(work/eng-copy): 4 call(s) in all, each counted once; see Limitations.", line)

    def test_the_copy_says_which_calls_are_the_same_and_how_many_are_not_in_it(self) -> None:
        other = self.copied()
        # Seen from the copy: its two reservations are two of the original's four.
        (found,) = call_ledger.same_approval_elsewhere(other, APPROVAL)
        self.assertEqual((found.used, found.extra, found.same), (4, 2, 2))
        self.assertEqual(found.counts_text(),
                         "work/eng counts 4 call(s), 2 of them the same calls as 2 counted here (its ledger "
                         "repeats reservations of this one, as after a copy of the directory) and 2 others")

    def test_calls_that_are_only_in_the_other_directory_are_added_once(self) -> None:
        self.assertEqual(self.call()[1], 0)
        other = self.work / "eng-other"
        other.mkdir()
        lines = [json.dumps({"v": call_ledger.VERSION, "event": "reserve", "id": f"earlier{n}",
                             "approval": APPROVAL, "calls": 1, "ceiling": 40, "at": "2026-11-19T00:00:00Z"})
                 for n in range(3)]
        (other / call_ledger.LEDGER_FILE).write_text("\n".join(lines) + "\n")
        text = self.limitation(report(self.root))
        self.assertIn("work/eng-other counts 3 call(s). The 3 call(s) counted only there are not in this report", text)
        self.assertIn("Counted once, the approval has 4 call(s) in these directories: the 1 in this report and 3 more",
                      text)
        self.assertIn("not the whole count for the approval", text)

    def test_the_command_line_note_says_the_calls_are_the_same(self) -> None:
        self.copied()
        status = call_ledger.status(self.root, APPROVAL, 40, context=True)
        self.assertIn("work/eng-copy counts 2 call(s), all of them the same calls as 2 counted here",
                      status.notes()[-1])


@unittest.skipIf(os.geteuid() == 0, "root reads a mode-000 file")
class UnreadableSiblingLedgerTests(TwoDirectories):
    """Finding 3: a sibling ledger that exists and cannot be read stops this directory."""

    def close(self, directory: Path) -> None:
        path = directory / call_ledger.LEDGER_FILE
        path.chmod(0)
        self.addCleanup(path.chmod, 0o600)

    def test_it_is_a_hit_and_the_rule_blocks_the_copy(self) -> None:
        self.reserve(self.original, calls=4)
        (self.copy / call_ledger.LEDGER_FILE).write_bytes((self.original / call_ledger.LEDGER_FILE).read_bytes())
        self.close(self.original)
        (found,) = call_ledger.same_approval_elsewhere(self.copy, "CHG-1")
        self.assertEqual((found.directory, found.used, found.unreadable), ("work/eng", None, True))
        status = call_ledger.status(self.copy, "CHG-1", 40, context=True)
        self.assertTrue(status.elsewhere_blocks)
        self.assertIn("would be refused", status.line(1, "call"))
        text = status.rule.refusal("call")
        self.assertIn("this call is refused in work/eng-b. Nothing was sent.", text)
        self.assertIn("cannot be read by this user, in work/eng (cannot read work/eng/call-ledger.jsonl", text)
        self.assertIn("Restore read permission (chmod u+r work/eng/call-ledger.jsonl), or restore that directory "
                      "from your backup", text)
        with self.assertRaises(call_ledger.CeilingRefused):
            self.reserve(self.copy)

    def test_the_other_way_round_the_directory_that_went_on_stops_too(self) -> None:
        self.reserve(self.original, calls=4)
        self.stamp(self.original, "2026-11-20T04:00:01Z")
        (self.copy / call_ledger.LEDGER_FILE).write_text(json.dumps({
            "v": call_ledger.VERSION, "event": "reserve", "id": "later", "approval": "CHG-1", "calls": 1,
            "ceiling": 40, "at": "2026-11-20T04:00:09Z"}) + "\n")
        self.close(self.copy)
        status = call_ledger.status(self.original, "CHG-1", 40, context=True)
        self.assertTrue(status.elsewhere_blocks)
        with self.assertRaises(call_ledger.CeilingRefused) as caught:
            self.reserve(self.original)
        self.assertIn("chmod u+r work/eng-b/call-ledger.jsonl", str(caught.exception))
        # Readable again, the rule is the one of wave 12: the original goes on.
        (self.copy / call_ledger.LEDGER_FILE).chmod(0o600)
        self.reserve(self.original)

    def test_any_owner_reference_is_stopped_and_the_benches_are_not(self) -> None:
        self.reserve(self.original, approval="CHG-1", calls=1)
        self.close(self.original)
        with self.assertRaises(call_ledger.CeilingRefused):
            self.reserve(self.copy, approval="CHG-OTHER")
        self.reserve(self.copy, approval="LOCAL-PRACTICE-REHEARSAL")

    def test_a_sibling_directory_that_cannot_be_searched_stops_it_too(self) -> None:
        self.reserve(self.original, calls=1)
        self.original.chmod(0)
        self.addCleanup(self.original.chmod, 0o700)
        (found,) = call_ledger.same_approval_elsewhere(self.copy, "CHG-1")
        self.assertTrue(found.unreadable)
        with self.assertRaises(call_ledger.CeilingRefused) as caught:
            self.reserve(self.copy)
        self.assertIn("(chmod u+rx work/eng)", str(caught.exception))

    def test_rehearse_and_ready_say_no_with_the_fix(self) -> None:
        from sippycup_workbench import cli

        self.reserve(self.original, calls=4)
        self.stamp(self.original, "2026-11-20T04:00:01Z")
        (self.copy / call_ledger.LEDGER_FILE).write_text(json.dumps({
            "v": call_ledger.VERSION, "event": "reserve", "id": "later", "approval": "CHG-1", "calls": 1,
            "ceiling": 40, "at": "2026-11-20T04:00:09Z"}) + "\n")
        self.close(self.copy)
        path = self.profile(self.original)
        result = cli.rehearse_file(path)
        self.assertFalse(result.ready)
        self.assertTrue(any("cannot be read by this user, in work/eng-b" in item for item in result.errors),
                        result.errors)
        check = ready.check_calls({"engagement": {"display": "work/eng"}}, path, yaml.safe_load(path.read_text()))
        self.assertEqual(check.status, ready.NOGO)
        self.assertIn("make the call ledger in work/eng-b readable again", check.fix)
        self.assertIn("A new approval reference does not lift this", check.fix)

    def test_a_directory_without_a_ledger_beside_is_still_no_hit(self) -> None:
        (self.original / "notes.txt").write_text("x")
        self.assertEqual(call_ledger.same_approval_elsewhere(self.copy, "CHG-1"), [])
        self.reserve(self.copy)


class UnreadableInsideTheContainerTests(TwoDirectories):
    """Finding 3, the case the rehearsal could not reach: the sender cannot read it either.

    Faked: the open of the sibling ledger fails as it does for a file owned
    by another user, whoever runs the test.
    """

    def test_reserve_refuses_when_the_sibling_ledger_cannot_be_opened(self) -> None:
        self.reserve(self.original, calls=2)
        self.stamp(self.original, "2026-11-20T04:00:09Z")
        (self.copy / call_ledger.LEDGER_FILE).write_text(json.dumps({
            "v": call_ledger.VERSION, "event": "reserve", "id": "first", "approval": "CHG-1", "calls": 1,
            "ceiling": 40, "at": "2026-11-20T04:00:01Z"}) + "\n")
        # The copy holds the earlier first call, so it is where the work goes on.
        self.assertFalse(call_ledger.status(self.copy, "CHG-1", 40, context=True).elsewhere_blocks)
        sibling = str(self.original / call_ledger.LEDGER_FILE)
        real_open, real_read = os.open, Path.read_bytes

        def closed_open(path, *args, **kwargs):
            if str(path) == sibling:
                raise PermissionError(13, "Permission denied", sibling)
            return real_open(path, *args, **kwargs)

        def closed_read(path):
            if str(path) == sibling:
                raise PermissionError(13, "Permission denied", sibling)
            return real_read(path)

        before = (self.copy / call_ledger.LEDGER_FILE).read_bytes()
        with mock.patch.object(call_ledger.os, "open", closed_open), \
                mock.patch.object(Path, "read_bytes", closed_read):
            with self.assertRaises(call_ledger.CeilingRefused) as caught:
                self.reserve(self.copy)
        self.assertIn("Nothing was sent.", str(caught.exception))
        self.assertIn("cannot be read by this user, in work/eng", str(caught.exception))
        self.assertEqual((self.copy / call_ledger.LEDGER_FILE).read_bytes(), before)


class UnreadableSiblingReportTests(Engagement):
    @unittest.skipIf(os.geteuid() == 0, "root reads a mode-000 file")
    def test_the_owner_report_is_not_silent_about_it(self) -> None:
        self.assertEqual(self.call()[1], 0)
        other = self.work / "eng-copy"
        other.mkdir()
        path = other / call_ledger.LEDGER_FILE
        path.write_bytes(self.ledger.read_bytes())
        path.chmod(0)
        self.addCleanup(path.chmod, 0o600)
        model = report(self.root)
        (item,) = [item for item in model["limitations"] if item["code"] == "same-approval-in-another-directory"]
        self.assertIn("work/eng-copy has a call ledger that this user cannot read", item["text"])
        self.assertIn("the count in this report may not be the whole count for the approval", item["text"])


class ThirdDirectoryFixLineTests(TwoDirectories):
    """Finding 4: the fix commands name the directory the operator is in."""

    def three(self) -> Path:
        self.reserve(self.original, calls=4)
        self.stamp(self.original, "2026-11-20T04:00:01Z")
        (self.copy / call_ledger.LEDGER_FILE).write_text(json.dumps({
            "v": call_ledger.VERSION, "event": "reserve", "id": "later", "approval": "CHG-1", "calls": 2,
            "ceiling": 40, "at": "2026-11-20T04:00:05Z"}) + "\n")
        return self.directory("eng-c")

    def test_a_third_directory_gets_its_own_name_in_the_commands(self) -> None:
        third = self.three()
        text = call_ledger.elsewhere_rule(third, "CHG-1", 0).refusal("call")
        self.assertIn("this call is refused in work/eng-c.", text)
        self.assertIn("work/eng-b, work/eng-c send nothing more under CHG-1", text)
        self.assertIn("./bin/sippycup scope answer work/eng-c authorization.approval_id and "
                      "./bin/sippycup scope compile work/eng-c", text)
        self.assertNotIn("scope answer work/eng-b", text)
        self.assertNotIn("scope compile work/eng-b", text)

    def test_the_second_directory_gets_its_own_name_too(self) -> None:
        self.three()
        text = call_ledger.elsewhere_rule(self.copy, "CHG-1", 2).text
        self.assertIn("scope answer work/eng-b authorization.approval_id", text)
        self.assertNotIn("scope answer work/eng-c", text)

    def test_two_directories_read_as_before(self) -> None:
        self.reserve(self.original, calls=2)
        text = call_ledger.elsewhere_rule(self.copy, "CHG-1", 0).text
        self.assertIn("work/eng-b sends nothing more under CHG-1: use it again only under a new written approval "
                      "from the owner, recorded with ./bin/sippycup scope answer work/eng-b "
                      "authorization.approval_id and ./bin/sippycup scope compile work/eng-b", text)


# ------------------------------------------------- findings 5, 6 and 7

import tempfile as _tempfile  # noqa: E402
from datetime import timedelta, timezone  # noqa: E402

import cockpit_support as support  # noqa: E402
from sippycup_cockpit.model import build_model  # noqa: E402
from sippycup_cockpit.render import render_dashboard  # noqa: E402
from sippycup_workbench import media_scope  # noqa: E402


class CockpitExpiredWindowTests(unittest.TestCase):
    """Finding 5: on an ended window the cockpit gives the three steps the shell commands give."""

    def setUp(self) -> None:
        temporary = _tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = support.make_repo(Path(temporary.name))
        self.root = support.compiled_engagement(self.repo, now=support.NOW)
        from sippycup_cockpit.model import save_preferences

        save_preferences(self.root, {"skipPractice": True})

    def model(self, hours: float) -> dict:
        return build_model(self.root, repo=self.repo, now=support.NOW + timedelta(hours=hours))

    def test_next_is_the_window_then_the_approval_then_compile(self) -> None:
        model = self.model(4)  # the window ended an hour ago; nobody touched scope.yaml
        self.assertTrue(model["scope"]["windowExpired"])
        self.assertEqual(
            model["nextCommand"],
            "./bin/sippycup scope answer work/eng authorization.window   (the renewed window), then "
            "./bin/sippycup scope answer work/eng 2   (the approval again), then "
            "./bin/sippycup scope compile work/eng")
        self.assertNotIn("scope questions", model["nextCommand"])
        identifiers = [action["id"] for action in model["actions"]]
        self.assertIn("window-renew", identifiers)
        self.assertNotIn("scope-questions-open", identifiers)
        renew = next(action for action in model["actions"] if action["id"] == "window-renew")
        self.assertIsNone(renew["argv"])  # it asks questions: a terminal step, never run by the cockpit
        self.assertIn("scope answer work/eng authorization.window", renew["instruction"])

    def test_the_scope_panel_does_not_call_the_window_unanswered(self) -> None:
        text = "\n".join(render_dashboard(self.model(4)))
        self.assertIn("0 unanswered question(s), 1 error(s)", text)
        self.assertIn("the approved window has ended (question 3 is answered", text)
        self.assertIn("1. ./bin/sippycup scope answer work/eng authorization.window", text)
        self.assertIn("2. ./bin/sippycup scope answer work/eng 2", text)
        self.assertIn("3. ./bin/sippycup scope compile work/eng", text)
        self.assertNotIn("In what window may testing run", text)
        self.assertNotIn("Next: ./bin/sippycup scope questions", text)

    def test_inside_the_window_nothing_changes(self) -> None:
        model = self.model(1)
        self.assertFalse(model["scope"]["windowExpired"])
        self.assertNotIn("window-renew", [action["id"] for action in model["actions"]])
        self.assertNotIn("authorization.window", model["nextCommand"] or "")


class ReadyShortWindowTests(unittest.TestCase):
    """Finding 6: no GO beside a window that is about to end."""

    NOW = support.NOW

    def check(self, seconds: float, margin: int = 60, plan: dict | None = None):
        model = {"authorization": {"status": "approved",
                                   "validFrom": (self.NOW - timedelta(hours=1)).isoformat(),
                                   "validUntil": (self.NOW + timedelta(seconds=seconds)).isoformat(),
                                   "text": "approved"},
                 "engagement": {"display": "work/eng"}, "files": {"planFacts": plan}}
        return ready.check_window(model, self.NOW, timezone.utc, margin)

    def test_101_seconds_with_a_46_second_plan_is_no_go(self) -> None:
        item = self.check(101, plan={"plannedTotals": {"durationSeconds": 46}})
        self.assertEqual(item.status, ready.NOGO)
        text = "\n".join(item.lines)
        self.assertIn("remaining  00h 01m (101 s)", text)
        self.assertIn("only 101 s remain, less than the 346 s (5 minutes + the frozen campaign plan's 46 s)", text)
        self.assertNotIn("less than the required", text)
        self.assertIn("./bin/sippycup scope answer work/eng authorization.window", item.fix)
        self.assertIn("./bin/sippycup scope answer work/eng 2", item.fix)
        self.assertIn("./bin/sippycup scope compile work/eng", item.fix)

    def test_under_five_minutes_is_no_go_and_just_over_is_a_warning(self) -> None:
        self.assertEqual(self.check(299).status, ready.NOGO)
        item = self.check(301)
        self.assertEqual(item.status, ready.WARN)
        self.assertIn("less than the margin of 01h 00m (margin 60 min) remains", "\n".join(item.lines))
        self.assertNotIn("required", "\n".join(item.lines))

    def test_a_smaller_margin_the_operator_asked_for_is_its_own_floor(self) -> None:
        self.assertEqual(self.check(200, margin=2).status, ready.GO)
        self.assertEqual(self.check(100, margin=2).status, ready.NOGO)

    def test_more_than_the_margin_is_go_as_before(self) -> None:
        self.assertEqual(self.check(2 * 3600).status, ready.GO)


class ProxyShapeDocTests(unittest.TestCase):
    """Finding 7: FIRST-ENGAGEMENT.md quotes the line rehearse prints for its proxy answers."""

    DOC = " ".join((ROOT / "docs" / "FIRST-ENGAGEMENT.md").read_text(encoding="utf-8").split())
    # The profile scope compile writes for the doc's proxy rows (question 4: 127.0.0.3;
    # questions 12 to 16: 127.0.0.2/31, ports 20000 to 20019).
    PROFILE = {
        "target": {"host": "127.0.0.3", "port": 5060, "transport": "udp", "approved_addresses": ["127.0.0.3"]},
        "media": {"addresses": [], "networks": ["127.0.0.2/31"], "port_range": {"start": 20000, "end": 20019}},
    }

    def test_the_doc_quotes_what_the_tool_prints_for_the_documented_answers(self) -> None:
        first, second = media_scope.where_lines(self.PROFILE)[:2]
        self.assertTrue(first.startswith("Signaling only: 127.0.0.3 (the target host; the owner did not list it "
                                         "for media"), first)
        self.assertIn(f"`{first}`", self.DOC)
        self.assertIn(f"`{second}`", self.DOC)
        self.assertNotIn("`rehearse` prints `Signaling and media: 127.0.0.3", self.DOC)

    def test_media_scope_is_not_widened_to_make_the_doc_true(self) -> None:
        self.assertEqual(list(media_scope.media_addresses(self.PROFILE)), [])
        listed = json.loads(json.dumps(self.PROFILE))
        listed["media"]["addresses"] = ["127.0.0.3"]
        self.assertTrue(media_scope.where_lines(listed)[0].startswith("Signaling and media: 127.0.0.3"))


# ------------------------------------------------- papercuts 8, 9 and 15

from sippycup_workbench import call as guided  # noqa: E402
from sippycup_workbench import profile as profile_module  # noqa: E402
from sippycup_workbench import summary_render  # noqa: E402


class PapercutTests(Engagement):
    def test_the_destination_refusal_prints_the_launcher_and_the_directory(self) -> None:
        document = yaml.safe_load(self.profile.read_text(encoding="utf-8"))
        errors = guided.gate(document, now=ENGAGEMENT_NOW, planned_seconds=30, work_root=self.work,
                             destination="ecoh", profile_path=self.profile)
        (refusal,) = [item for item in errors if "ecoh" in item]
        self.assertIn("(./bin/sippycup scope answer work/eng destinations)", refusal)
        self.assertIn("(./bin/sippycup scope answer work/eng 2)", refusal)
        self.assertTrue(refusal.endswith("and run ./bin/sippycup scope compile work/eng"), refusal)
        self.assertNotIn("DIR", refusal)

    def test_the_cockpit_and_ready_profile_rows_have_no_placeholder_on_expiry(self) -> None:
        model = build_model(self.root, repo=self.repo, now=ENGAGEMENT_NOW + timedelta(hours=5))
        (error,) = [item for item in model["profile"]["errors"] if "authorization has expired" in item]
        self.assertIn("(./bin/sippycup scope answer work/eng authorization.window)", error)
        self.assertIn("run ./bin/sippycup scope compile work/eng", error)
        self.assertNotIn("DIR", error)

    def test_the_window_step_does_not_promise_the_approval_question(self) -> None:
        text = profile_module.window_too_short_step(self.profile)
        self.assertIn("authorization.window (it asks for the approval again, unless that is already open)", text)

    def test_reasons_are_joined_without_a_full_stop_before_the_semicolon(self) -> None:
        self.assertEqual(summary_render._reasons(["The peer sent back 159#.", "checked against the approval."]),
                         "The peer sent back 159#; checked against the approval.")
        self.assertEqual(summary_render._reasons(["one", None, "two"]), "one; two")
        self.assertEqual(summary_render._reasons(None), "")


# ------------------------------------------------- evidence lint: "::1" by chance in capture bytes

from sippycup.evidence import privacy_findings  # noqa: E402

from test_evidence_privacy import packet, pcap  # noqa: E402


class CaptureChanceAddressTests(unittest.TestCase):
    """A routed rehearsal failed on `::1` found in the encrypted bytes of an IPv4-only capture."""

    def flagged(self, name: str, data: bytes, media_type: str) -> str:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "result.json").write_text("{}", encoding="utf-8")
            (root / name).write_bytes(data)
            findings = privacy_findings(root, [{"path": name, "size": len(data), "mediaType": media_type}],
                                        expected_networks=["10.0.0.0/24"])
        self.assertFalse([item for item in findings if item["code"] == "capture-uninspected"], findings)
        return "; ".join(item["detail"] for item in findings if item["code"] == "unexpected-network")

    def test_chance_bytes_in_a_tls_payload_are_not_an_address(self) -> None:
        # Printable bytes on both sides of "::1", as ciphertext has now and then.
        payload = b"\x17\x03\x03\x00\x40\x8f\x12q::1Z\x9c\x01\xfe" + bytes(range(128, 160))
        capture = pcap(packet("10.0.0.1", "10.0.0.2", payload))
        self.assertEqual(self.flagged("capture.pcap", capture, "application/vnd.tcpdump.pcap"), "")

    def test_an_address_in_a_line_of_sip_text_in_a_capture_is_still_found(self) -> None:
        payload = b"v=0\r\no=- 1 1 IN IP6 2001:db8::5\r\nc=IN IP6 2001:db8::5\r\n"
        capture = pcap(packet("10.0.0.1", "10.0.0.2", payload))
        self.assertIn("2001:db8::5", self.flagged("capture.pcap", capture, "application/vnd.tcpdump.pcap"))
        loopback = pcap(packet("10.0.0.1", "10.0.0.2", b"Via: SIP/2.0/UDP [::1]:5060;branch=z9hG4bK1\r\n"))
        self.assertIn("::1", self.flagged("capture.pcap", loopback, "application/vnd.tcpdump.pcap"))

    def test_a_packet_header_address_and_an_ipv4_text_address_are_found_as_before(self) -> None:
        capture = pcap(packet("10.0.0.1", "203.0.113.9", b"\x80\x00"))
        self.assertIn("203.0.113.9", self.flagged("capture.pcap", capture, "application/vnd.tcpdump.pcap"))
        text = pcap(packet("10.0.0.1", "10.0.0.2", b"\x00c=IN IP4 198.51.100.7\x00"))
        self.assertIn("198.51.100.7", self.flagged("capture.pcap", text, "application/vnd.tcpdump.pcap"))

    def test_a_text_artifact_is_scanned_as_before(self) -> None:
        self.assertIn("::1", self.flagged("note.txt", b"q ::1 z", "text/plain"))


if __name__ == "__main__":
    unittest.main()
