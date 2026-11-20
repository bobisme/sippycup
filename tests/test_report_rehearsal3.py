"""Owner report, diagnose and cockpit reasons after the third rehearsal (wave 11).

Finding 6: the application record `scope compile` writes is recorded in the
sidecar, so a clean platform engagement has no integrity exception and an
edit is still caught. Finding 10: the tester's own stop is not a finding,
tester hints and network-path notes stay out of owner rows, an inconclusive
row has a reason, the windows are in time order, and an address only an
earlier answer named is not listed as approved. Findings 2, 10 and 13: one
call-limit line per approval reference with runs, each run judged against
the limit in force when it ran, and one total that matches the totals table.
Findings 1 and 8: both runs of an overlap are marked, in the report and in
diagnose, and more calls at once than the owner allowed is an exception.
Finding 20: the cockpit's reason is not the network-path note.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

import cockpit_support as support  # noqa: E402
from test_call_ledger_crosscheck import NOW, Engagement  # noqa: E402
from test_scope_platform import PlatformCase, platform_scope  # noqa: E402
from test_scope import NOW as SCOPE_NOW  # noqa: E402

from sippycup import run_overlap  # noqa: E402
from sippycup_cockpit import runs as cockpit_runs  # noqa: E402
from sippycup_diagnose import cli as diagnose_cli  # noqa: E402
from sippycup_workbench import summary_model  # noqa: E402
from sippycup_workbench.scope_app_derive import FILENAME as APP_FILE  # noqa: E402
from sippycup_workbench.scope_derive import (  # noqa: E402
    SIDECAR_FILE,
    compile_scope,
    derivative_integrity,
    derivative_state,
    read_sidecar,
)
from sippycup_workbench.summary_model import Options, build_report  # noqa: E402
from sippycup_workbench.summary_render import (  # noqa: E402
    _more_findings_line,
    call_limit_lines,
    render_html,
    render_markdown,
    render_text,
)

PRACTICE = ROOT / "tests" / "fixtures" / "engagement-report" / "practice"
UDP_CAMPAIGN = "20261118T025515.709822Z-local-practice-baseline-01965563"
GENERATED = "2026-11-19T00:00:00Z"
LOOPBACK_NOTE = "The target is a loopback address inside the container's own network namespace; no NAT applies."
NAT_NOTE = (
    "Isolated mode: signaling and media leave the container's private network namespace "
    "through the container runtime's NAT (for example pasta or slirp4netns). The target may "
    "see a translated source address and SDP advertises the container's address, so inbound "
    "RTP can fail to return without any target defect."
)
HINT_NOTE = (
    "127.0.0.2 is a loopback address: the practice target answers only inside its own "
    "namespace, so run the command as ./bin/sippycup --practice ... (without --practice "
    "nothing listens there); with --practice, compare the port with "
    "./bin/sippycup practice-target info."
)


def build(root: Path) -> dict:
    return build_report(root, Options(generated_at=GENERATED))[0]


def codes(model: dict) -> list[str]:
    return sorted(item["code"] for item in model["integrityExceptions"])


def renderings(model: dict) -> list[str]:
    return [render(model, "0" * 64) for render in (render_markdown, render_html, render_text)]


class ApplicationRecordTests(PlatformCase):
    """Finding 6: a file compile wrote is recorded and verified like the others."""

    def compiled(self) -> Path:
        self.write_scope(platform_scope())
        result = compile_scope(self.root, now=SCOPE_NOW)
        self.assertEqual(0, result.exit_code, result.as_dict())
        return self.root / APP_FILE

    def test_compile_records_the_application_record_by_hash(self) -> None:
        path = self.compiled()
        sidecar, problem = read_sidecar(self.root)
        self.assertIsNone(problem)
        entry = sidecar["derivatives"]["application-surfaces"]
        self.assertEqual(APP_FILE, entry["path"])
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), entry["sha256"])
        self.assertEqual("compiled-current", derivative_integrity(path)["state"])

    def test_a_clean_platform_engagement_has_no_integrity_exception(self) -> None:
        self.compiled()
        model = build(self.root)
        self.assertEqual([], model["integrityExceptions"])

    def test_an_edit_to_the_application_record_is_still_caught(self) -> None:
        path = self.compiled()
        path.write_text(path.read_text(encoding="utf-8").replace("status: approved", "status: pending", 1), encoding="utf-8")
        self.assertEqual("edited", derivative_integrity(path)["state"])
        found = [item for item in build(self.root)["integrityExceptions"] if item["code"] == "approval-record-edited"]
        self.assertEqual(1, len(found), found)
        self.assertIn(f"{APP_FILE} was edited after scope compile wrote it", found[0]["detail"])

    def test_a_second_compile_keeps_the_record_and_stays_clean(self) -> None:
        self.compiled()
        result = compile_scope(self.root, now=SCOPE_NOW)
        self.assertEqual(0, result.exit_code, result.as_dict())
        self.assertEqual("compiled-current", derivative_integrity(self.root / APP_FILE)["state"])
        self.assertEqual([], build(self.root)["integrityExceptions"])

    def test_the_sip_derivative_state_is_unchanged_by_the_record(self) -> None:
        self.compiled()
        state = derivative_state(self.root)
        self.assertEqual("current", state["state"])
        self.assertNotIn("application-surfaces", state["items"])

    def test_the_profile_campaign_and_expectations_are_as_strict_as_before(self) -> None:
        self.compiled()
        for name in ("target-profile.yaml", "campaign.yaml", "expectations.yaml"):
            path = self.root / name
            original = path.read_bytes()
            path.write_bytes(original + b"# edited\n")
            self.assertEqual("edited", derivative_integrity(path)["state"], name)
            path.write_bytes(original)
        stray = self.root / "target-profile-copy.yaml"
        stray.write_bytes((self.root / "target-profile.yaml").read_bytes())
        self.assertEqual("unrecorded", derivative_integrity(stray)["state"])
        self.assertIn("approval-record-edited", codes(build(self.root)))

    def test_a_record_from_an_older_compile_is_accepted_only_while_unedited(self) -> None:
        path = self.compiled()
        sidecar_path = self.root / SIDECAR_FILE
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        del sidecar["derivatives"]["application-surfaces"]  # what a compile before this fix wrote
        sidecar_path.write_text(json.dumps(sidecar), encoding="utf-8")
        self.assertEqual("unrecorded", derivative_integrity(path)["state"])
        self.assertEqual([], build(self.root)["integrityExceptions"])
        path.write_text(path.read_text(encoding="utf-8").replace("status: approved", "status: pending", 1), encoding="utf-8")
        self.assertEqual(["approval-record-edited"], codes(build(self.root)))


def fixture(directory: str) -> Path:
    target = Path(directory) / "engagement"
    shutil.copytree(PRACTICE, target)
    return target


class TesterStopTests(unittest.TestCase):
    """Finding 10: the operator's own stop is the tester's action, not a finding."""

    def stopped(self, root: Path, reason: str = "SIGTERM") -> None:
        run = root / "runs" / UDP_CAMPAIGN
        result = json.loads((run / "result.json").read_text(encoding="utf-8"))
        result.update({"state": "cancelled", "exitCode": 143, "completedSteps": 1})
        (run / "result.json").write_text(json.dumps(result), encoding="utf-8")
        lines = [json.loads(line) for line in (run / "events.jsonl").read_text(encoding="utf-8").splitlines() if line]
        kept = [event for event in lines if not str(event.get("event", "")).startswith("campaign.")]
        base = {"apiVersion": "sippycup.dev/events/v1", "campaign": "local-practice-baseline"}
        kept.append({**base, "event": "campaign.stop_requested", "reason": reason, "state": "stopping"})
        kept.append({**base, "event": "campaign.cancelled", "state": "cancelled", "completedSteps": 1})
        (run / "events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in kept), encoding="utf-8")

    def test_a_campaign_the_tester_stopped_is_not_a_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = fixture(directory)
            self.stopped(root)
            model = build(root)
        run = next(r for r in model["runs"] if r["id"] == UDP_CAMPAIGN)
        self.assertTrue(run["operatorStop"])
        self.assertEqual("stopped-by-tester", run["verdict"])
        self.assertEqual([], [f for f in model["findings"] if UDP_CAMPAIGN in f["runs"]])
        self.assertTrue(any("tester's own action, not a result about your system" in reason for reason in run["reasons"]))
        self.assertIn("stopped by the tester", model["executiveSummary"]["paragraph"])
        self.assertFalse(any("did not pass" in row["title"] and "stopped-by-tester" in row["title"]
                             for row in model["executiveSummary"]["rows"]))
        self.assertIn("stopped-by-tester", [item["code"] for item in model["limitations"]])
        for text in renderings(model):
            self.assertNotIn("SIGTERM", text)
            self.assertNotIn("A campaign stopped before completing every step", text)

    def test_a_campaign_that_a_ceiling_stopped_is_still_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = fixture(directory)
            self.stopped(root, reason="max_packets")
            model = build(root)
        run = next(r for r in model["runs"] if r["id"] == UDP_CAMPAIGN)
        self.assertFalse(run["operatorStop"])
        self.assertTrue([f for f in model["findings"] if UDP_CAMPAIGN in f["runs"]])


class EngagementReport(Engagement):
    def model(self) -> dict:
        return build(self.root)

    def run_dirs(self) -> list[Path]:
        return sorted(path for path in (self.root / "calls").iterdir() if path.is_dir())

    def edit_result(self, run: Path, **changes) -> None:
        path = run / "result.json"
        result = json.loads(path.read_text(encoding="utf-8"))
        result.update(changes)
        path.write_text(json.dumps(result), encoding="utf-8")

    def recompile(self, *changes: tuple[str, str]) -> None:
        text = (self.root / "scope.yaml").read_text(encoding="utf-8")
        for old, new in changes:
            self.assertIn(old, text)
            text = text.replace(old, new)
        support.write_scope(self.root, text)
        outcome = compile_scope(self.root, now=NOW, force=True)
        self.assertEqual(outcome.exit_code, 0, outcome.as_dict())

    def set_times(self, run: Path, start: int, end: int) -> None:
        """Capture open from ``start`` to ``end`` seconds after NOW; the call one second inside."""
        def at(seconds: float) -> str:
            return (NOW + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")

        stamps = {"started": at(start - 1), "capture_ready": at(start), "call_started": at(start + 1),
                  "call_ended": at(end - 1), "capture_stopped": at(end), "finished": at(end + 1)}
        (run / "timestamps.json").write_text(json.dumps(stamps), encoding="utf-8")
        self.edit_result(run, timestamps=stamps)


class OwnerRowTests(EngagementReport):
    """Finding 10: what an owner reads in a row is a statement about the run, in plain words."""

    def test_tester_hints_and_network_path_notes_stay_out_of_the_rows(self) -> None:
        self.assertEqual(self.call()[1], 0)
        self.assertEqual(self.call()[1], 0)
        first, second = self.run_dirs()
        self.edit_result(first, verdict="preflight-failed", state="failed", notes=[LOOPBACK_NOTE, HINT_NOTE])
        self.edit_result(second, notes=[NAT_NOTE])
        model = self.model()
        for run in model["runs"]:
            text = "; ".join(run["reasons"])
            for jargon in ("./bin/sippycup", "--practice", "Isolated mode", "network namespace", "pasta"):
                self.assertNotIn(jargon, text)
        hinted = next(r for r in model["runs"] if r["id"] == first.name)
        self.assertTrue(any("error on the assessor's side, not a result about your system" in r for r in hinted["reasons"]))
        nat = [item for item in model["limitations"] if item["code"] == "assessor-nat"]
        self.assertEqual(1, len(nat))
        self.assertIn("address translation", nat[0]["text"])
        for text in renderings(model):
            self.assertNotIn("./bin/sippycup --practice", text)
            self.assertNotIn("Isolated mode", text)
            self.assertNotIn("capture watchdog", text)
            self.assertNotIn("container's own network namespace", text)

    def test_an_inconclusive_row_says_why(self) -> None:
        self.assertEqual(self.call()[1], 0)
        (run,) = self.run_dirs()
        result = json.loads((run / "result.json").read_text(encoding="utf-8"))
        oracle = dict(result.get("oracle") or {})
        oracle.update({"verdict": "unknown", "summary": {"pass": 10, "fail": 0, "unknown": 3}})
        self.edit_result(run, verdict="inconclusive", notes=[LOOPBACK_NOTE], oracle=oracle)
        row = self.model()["runs"][0]
        self.assertEqual("inconclusive", row["verdict"])
        self.assertIn("The automatic packet check could not decide (10 of its checks passed, 0 failed, "
                      "3 could not be judged)", row["reasons"][0])

    def test_a_call_the_tester_stopped_is_not_counted_as_a_failure(self) -> None:
        self.assertEqual(self.call()[1], 0)
        (run,) = self.run_dirs()
        self.edit_result(run, verdict="cancelled", state="cancelled", notes=[])
        model = self.model()
        row = model["runs"][0]
        self.assertTrue(row["operatorStop"])
        self.assertIn("The tester stopped this call", row["reasons"][0])
        self.assertFalse(any("did not pass" in item["title"] for item in model["executiveSummary"]["rows"]))
        self.assertEqual([], model["findings"])

    def test_the_more_findings_note_is_a_sentence_not_a_table_row(self) -> None:
        self.assertEqual(self.call()[1], 0)
        model = self.model()
        self.assertEqual(0, model["executiveSummary"]["moreFindings"])
        self.assertFalse(any(row["source"] == "report" for row in model["executiveSummary"]["rows"]))
        self.assertIsNone(_more_findings_line({"moreFindings": 0}))
        self.assertIn("1 more finding is listed in the Findings section", _more_findings_line({"moreFindings": 1}))
        findings = [
            {"ref": f"F-{n:02d}", "severity": "info", "title": f"t{n}", "targetLabel": "x", "derived": False, "runs": []}
            for n in range(1, 7)
        ]
        summary = summary_model._executive({**model, "findings": findings})
        self.assertEqual(2, summary["moreFindings"])
        self.assertEqual(["F-01", "F-02", "F-03", "F-04"], [row["ref"] for row in summary["rows"]])

    def test_the_windows_are_listed_in_the_order_they_were_used(self) -> None:
        self.recompile(("calls: 2", "calls: 5"))
        self.assertEqual(self.call()[1], 0)
        text = (self.root / "scope.yaml").read_text(encoding="utf-8")
        until = next(line for line in text.splitlines() if line.strip().startswith("valid_until:"))
        shorter = "  valid_until: " + support.iso(NOW + timedelta(hours=1))
        self.recompile((until, shorter))  # a later window that ends before the first one
        self.assertEqual(self.call()[1], 0)
        (first, second) = self.run_dirs()
        self.set_times(first, 0, 10)
        self.set_times(second, 60, 70)
        windows = self.model()["authorization"]["windowsInForce"]
        self.assertEqual([["R1"], ["R2"]], [w["runs"] for w in windows])
        self.assertLess(windows[1]["until"], windows[0]["until"])

    def test_an_address_only_an_earlier_answer_named_is_not_listed_as_approved(self) -> None:
        self.recompile(("calls: 2", "calls: 5"), ("media:\n  networks: [127.0.0.2/32]", "media:\n  networks: [127.0.0.2/32, 127.0.0.9/32]"))
        self.assertEqual(self.call()[1], 0)
        self.recompile(("networks: [127.0.0.2/32, 127.0.0.9/32]", "networks: [127.0.0.2/32]"))
        self.assertEqual(self.call()[1], 0)
        (first, second) = self.run_dirs()
        self.set_times(first, 0, 10)
        self.set_times(second, 60, 70)
        model = self.model()
        auth = model["authorization"]
        self.assertNotIn("127.0.0.9/32", auth["approvedAddresses"])
        self.assertNotIn("127.0.0.9/32", auth["mediaOnlyNetworks"])
        self.assertEqual([{"network": "127.0.0.9/32", "mediaOnly": True, "runs": ["R1"]}], auth["earlierAddresses"])
        markdown = render_markdown(model, "0" * 64)
        approved = next(line for line in markdown.splitlines() if line.startswith("- Approved addresses:"))
        self.assertNotIn("127.0.0.9", approved)
        self.assertIn("Approved by an earlier answer only, and not part of the current approval: 127.0.0.9/32", markdown)
        self.assertEqual([], model["integrityExceptions"])

    def test_the_media_stop_sentence_is_true_with_or_without_rtcp_counts(self) -> None:
        run = {"verdict": "media-outside-scope", "details": {"media": {"toPeerPackets": 1, "stopPackets": None}}}
        text = summary_model._stop_detail(run)
        self.assertIn("after 1 RTP packet was sent to it", text)
        self.assertIn("RTCP control packets sent beside it before the stop are not counted", text)
        run["details"]["media"]["stopPackets"] = summary_model._stop_packets(
            {"mediaScope": {"sentBeforeStop": {"rtp": 1, "rtcp": 4}}})
        self.assertIn("after 1 RTP packet was sent to it (and 4 RTCP control packets)", summary_model._stop_detail(run))
        self.assertIsNone(summary_model._stop_packets({"mediaScope": {"sentBeforeStop": {"rtp": 1}}}))


class CallLimitTests(EngagementReport):
    """Findings 2, 10 and 13: a line per approval reference; the limit in force when the run ran."""

    def test_lowering_the_limit_later_does_not_turn_earlier_runs_into_overruns(self) -> None:
        for _ in range(2):
            self.assertEqual(self.call()[1], 0)
        self.recompile(("calls: 2", "calls: 1"))
        model = self.model()
        self.assertEqual([], model["integrityExceptions"])
        (row,) = model["callLimits"]
        self.assertEqual((row["limit"], row["counted"], row["placedByRuns"]), (1, 2, 2))
        self.assertFalse(row["exceeded"])
        self.assertTrue(row["aboveLoweredLimit"])
        self.assertEqual([{"limit": 2, "runs": ["R1", "R2"]}], row["limitsInForce"])
        text = "\n".join(call_limit_lines(model))
        self.assertIn("The limit changed during the engagement: 2 while R1-R2 ran, 1 now.", text)
        self.assertIn("no run exceeded the limit in force when it ran", text)
        self.assertNotIn("LIMIT EXCEEDED", text)
        self.assertNotIn("call limit was exceeded", model["executiveSummary"]["paragraph"])

    def test_a_run_over_the_limit_in_force_is_still_an_overrun(self) -> None:
        for _ in range(2):
            self.assertEqual(self.call()[1], 0)
        # The same bypass the second rehearsal used: a third call under a limit of two.
        self.ledger.unlink()
        (self.root / "calls").rename(self.root / "kept")
        self.assertEqual(self.call()[1], 0)
        for run in (self.root / "kept").iterdir():
            run.rename(self.root / "calls" / run.name)
        for index, run in enumerate(self.run_dirs()):
            self.set_times(run, index * 60, index * 60 + 10)
        model = self.model()
        over = [item for item in model["integrityExceptions"] if item["code"] == "call-limit-exceeded" and item["run"]]
        self.assertEqual(1, len(over), model["integrityExceptions"])
        self.assertIn("above the approved limit of 2 that was in force when it ran", over[0]["detail"])
        (row,) = model["callLimits"]
        self.assertTrue(row["exceeded"])
        self.assertEqual(["R3"], row["runsOverLimit"])

    def test_every_approval_reference_with_runs_keeps_its_line_and_the_totals_agree(self) -> None:
        for _ in range(2):
            self.assertEqual(self.call()[1], 0)
        self.recompile((f"approval_id: {self.approval}", "approval_id: QUAD-APPROVAL-TYPO-FIXED"))
        self.assertEqual(self.call()[1], 0)
        for index, run in enumerate(self.run_dirs()):
            self.set_times(run, index * 60, index * 60 + 10)
        model = self.model()
        rows = {row["approvalId"]: row for row in model["callLimits"]}
        self.assertEqual({self.approval, "QUAD-APPROVAL-TYPO-FIXED"}, set(rows))
        earlier, current = rows[self.approval], rows["QUAD-APPROVAL-TYPO-FIXED"]
        self.assertFalse(earlier["current"])
        self.assertTrue(current["current"])
        self.assertEqual((earlier["limit"], earlier["counted"], earlier["placedByRuns"]), (2, 2, 2))
        self.assertEqual((current["limit"], current["counted"], current["left"], current["placedByRuns"]), (2, 1, 1, 1))
        totals = model["callLimitTotals"]
        self.assertEqual(3, totals["placedByRuns"])
        self.assertEqual(model["totals"]["calls"]["total"], totals["placedByRuns"])
        text = "\n".join(call_limit_lines(model))
        self.assertIn(f"Approval {self.approval} (an earlier approval reference of this engagement", text)
        self.assertIn(f"Calls placed by the runs in this report: 3 (2 under {self.approval}, "
                      "1 under QUAD-APPROVAL-TYPO-FIXED)", text)
        self.assertEqual(1, text.count("Calls placed by the runs in this report:"))
        self.assertEqual([], model["integrityExceptions"])

    def test_an_overrun_under_an_earlier_reference_stays_in_the_report(self) -> None:
        for _ in range(2):
            self.assertEqual(self.call()[1], 0)
        self.ledger.unlink()
        (self.root / "calls").rename(self.root / "kept")
        self.assertEqual(self.call()[1], 0)
        for run in (self.root / "kept").iterdir():
            run.rename(self.root / "calls" / run.name)
        for index, run in enumerate(self.run_dirs()):
            self.set_times(run, index * 60, index * 60 + 10)
        self.recompile((f"approval_id: {self.approval}", "approval_id: QUAD-APPROVAL-TYPO-FIXED"))
        model = self.model()
        rows = {row["approvalId"]: row for row in model["callLimits"]}
        self.assertTrue(rows[self.approval]["exceeded"])
        self.assertIn("call-limit-exceeded", codes(model))
        self.assertIn(f"under approval {self.approval}", model["executiveSummary"]["paragraph"])
        self.assertIn("LIMIT EXCEEDED by R3.", "\n".join(call_limit_lines(model)))


class OverlapTests(EngagementReport):
    """Findings 1 and 8: both runs of an overlap are marked; too many calls at once is an exception."""

    def two_calls(self, second_start: int) -> tuple[Path, Path]:
        self.recompile(("calls: 2", "calls: 5"))
        for _ in range(2):
            self.assertEqual(self.call()[1], 0)
        first, second = self.run_dirs()
        self.set_times(first, 0, 14)
        self.set_times(second, second_start, second_start + 14)
        return first, second

    def test_both_runs_are_marked_and_the_concurrency_limit_is_checked(self) -> None:
        first, second = self.two_calls(4)
        model = self.model()
        for run in model["runs"]:
            self.assertTrue(run.get("overlap"), run["id"])
            self.assertIn(run_overlap.UNRELIABLE, run["reasons"])
        self.assertEqual([["R2"], ["R1"]], [run["overlapWith"] for run in model["runs"]])
        limitation = next(item for item in model["limitations"] if item["code"] == "overlapping-runs")
        self.assertIn("2 run(s) (R1-R2)", limitation["text"])
        self.assertIn(run_overlap.UNRELIABLE, limitation["text"])
        found = [item for item in model["integrityExceptions"] if item["code"] == "concurrent-calls-exceeded"]
        self.assertEqual({first.name, second.name}, {item["run"] for item in found})
        self.assertIn("2 calls were in progress at once", found[0]["detail"])
        self.assertIn("above the approved limit of 1 call at once", found[0]["detail"])
        self.assertIn("were active at the same time as another run", model["executiveSummary"]["paragraph"])
        self.assertFalse(any("completed as expected" in row["title"] for row in model["executiveSummary"]["rows"]))

    def test_an_overlap_inside_the_owners_concurrency_limit_is_unreliable_but_no_exception(self) -> None:
        self.recompile(("concurrent_calls: 1", "concurrent_calls: 2"))
        self.two_calls(4)
        model = self.model()
        self.assertTrue(all(run.get("overlap") for run in model["runs"]))
        self.assertEqual([], model["integrityExceptions"])

    def test_runs_one_after_another_are_not_marked(self) -> None:
        self.two_calls(14)  # the second capture opens the instant the first one closed
        model = self.model()
        self.assertFalse(any(run.get("overlap") for run in model["runs"]))
        self.assertEqual([], model["integrityExceptions"])
        self.assertNotIn("overlapping-runs", [item["code"] for item in model["limitations"]])

    def test_diagnose_on_the_first_run_names_the_overlap(self) -> None:
        first, second = self.two_calls(4)
        self.assertEqual([second.name], run_overlap.sibling_overlaps(first))
        self.assertEqual([first.name], run_overlap.sibling_overlaps(second))
        data = {"outcome": "The call was answered."}
        diagnose_cli._mark_overlap(data, first)
        self.assertEqual({"activeRuns": [second.name], "unreliable": True}, data["overlap"])
        self.assertTrue(data["outcome"].startswith("Another run was active; this verdict is unreliable (beside "))

    def test_diagnose_gives_the_other_run_as_the_cause_of_an_inconclusive_call(self) -> None:
        from sippycup_diagnose.call import diagnose_call
        from sippycup_diagnose.callrun import CallRun
        from sippycup_diagnose.inputs import make_redaction
        from sippycup_diagnose.ladder_bridge import Lazy

        first, _second = self.two_calls(4)
        self.edit_result(first, verdict="inconclusive", notes=[LOOPBACK_NOTE])
        red = make_redaction([first], [], False)
        diagnosis = diagnose_call(CallRun(first), red, Lazy(first, False, [], enabled=False))
        text = json.dumps(diagnosis.data)
        self.assertIn("Another run of this engagement was active at the same time", text)
        self.assertNotIn("Encrypted signaling, a truncated capture, or missing RTP counts", text)

    def test_a_run_alone_keeps_the_usual_inconclusive_text(self) -> None:
        from sippycup_diagnose.call import diagnose_call
        from sippycup_diagnose.callrun import CallRun
        from sippycup_diagnose.inputs import make_redaction
        from sippycup_diagnose.ladder_bridge import Lazy

        first, _second = self.two_calls(60)
        self.edit_result(first, verdict="inconclusive", notes=[LOOPBACK_NOTE])
        self.assertEqual([], run_overlap.sibling_overlaps(first))
        diagnosis = diagnose_call(CallRun(first), make_redaction([first], [], False), Lazy(first, False, [], enabled=False))
        self.assertIn("Encrypted signaling, a truncated capture, or missing RTP counts", json.dumps(diagnosis.data))
        data = {"outcome": "x"}
        diagnose_cli._mark_overlap(data, first)
        self.assertNotIn("overlap", data)

    def test_the_cockpit_reason_is_the_overlap_not_the_network_note(self) -> None:
        first, _second = self.two_calls(4)
        document = json.loads((first / "result.json").read_text(encoding="utf-8"))
        document.update({"verdict": "inconclusive", "notes": [LOOPBACK_NOTE]})
        summary: dict = {}
        cockpit_runs._call_summary(document, summary)
        self.assertNotIn("no NAT applies", str(summary["reason"]))
        self.assertIn("the packet check could not decide", summary["reason"])
        cockpit_runs._overlap_reason(first, document, summary)
        self.assertIn(run_overlap.UNRELIABLE, summary["reason"])


class CockpitReasonTests(unittest.TestCase):
    """Finding 20: the network-path note is never shown as why a run failed."""

    def reason(self, **changes) -> str | None:
        document = support.call_result("inconclusive")
        document.update(changes)
        summary: dict = {}
        cockpit_runs._call_summary(document, summary)
        return summary["reason"]

    def test_the_first_note_that_says_what_happened_is_the_reason(self) -> None:
        self.assertEqual("Registration was rejected with SIP status 401.", self.reason(
            verdict="registration-failed", notes=[LOOPBACK_NOTE, "Registration was rejected with SIP status 401."]))
        self.assertEqual("Registration was rejected with SIP status 401.", self.reason(
            verdict="registration-failed", notes=[NAT_NOTE, "Registration was rejected with SIP status 401."]))

    def test_a_run_with_only_the_network_note_gets_a_real_reason(self) -> None:
        for note in (LOOPBACK_NOTE, NAT_NOTE):
            reason = self.reason(notes=[note])
            self.assertNotIn("NAT", str(reason))
            self.assertNotIn("network namespace", str(reason))
            self.assertIsNotNone(reason)


if __name__ == "__main__":
    unittest.main()
