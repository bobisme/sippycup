"""The owner report says true, plain things (rehearsal 2, finding 12).

The report goes to the system owner, who does not know the tool. These tests
hold: a mixed campaign names every target it used, a campaign file shows the
approval it holds, a renewed window shows the windows each run ran under, a
run that never started is the assessor's failure and not a finding, and the
text has no tool jargon.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

import cockpit_support as support  # noqa: E402
from test_guided_call import Fakes  # noqa: E402

from sippycup_workbench import call as guided  # noqa: E402
from sippycup_workbench.scope_derive import compile_scope  # noqa: E402
from sippycup_workbench.summary_model import Options, build_report  # noqa: E402
from sippycup_workbench.summary_render import render_html, render_markdown, render_text  # noqa: E402

PRACTICE = ROOT / "tests" / "fixtures" / "engagement-report" / "practice"
UDP_CAMPAIGN = "20261118T025515.709822Z-local-practice-baseline-01965563"
GENERATED = "2026-11-18T04:00:00Z"
JARGON = ("packet oracle", "PJSUA", "approved-scopes/", "scope-in-force")


def fixture(directory: str) -> Path:
    target = Path(directory) / "engagement"
    shutil.copytree(PRACTICE, target)
    return target


def build(root: Path) -> dict:
    return build_report(root, Options(generated_at=GENERATED))[0]


def ledger_row(markdown: str, run_id: str) -> str:
    rows = [line for line in markdown.splitlines() if line.startswith("|") and run_id in line]
    assert rows, run_id
    return rows[0]


class MixedCampaignTests(unittest.TestCase):
    def test_the_ledger_row_of_a_mixed_campaign_names_every_target_it_used(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            model = build(fixture(directory))
        run = next(r for r in model["runs"] if r["id"] == UDP_CAMPAIGN)
        self.assertEqual({"udp", "tcp"}, {t["transport"] for t in run["usedTargets"]})
        for render in (render_markdown, render_html):
            text = render(model, "0" * 64)
            row = ledger_row(text, UDP_CAMPAIGN) if render is render_markdown else text
            self.assertIn("127.0.0.2:5060/udp", row)
            self.assertIn("127.0.0.2:5060/tcp", row)
        self.assertIn("127.0.0.2:5060/tcp", render_text(model, "0" * 64))
        # The row was single-target before: first resolved destination only.
        self.assertIn("127.0.0.2:5060/udp; 127.0.0.2:5060/tcp", ledger_row(render_markdown(model, "0" * 64), UDP_CAMPAIGN))


class CampaignFileApprovalTests(unittest.TestCase):
    def test_the_campaign_file_row_shows_the_approval_id_and_window_it_holds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = fixture(directory)
            path = root / "campaign.yaml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "authorization:\n",
                    "authorization:\n  approval:\n    id: HELD-ID-9\n"
                    "    validFrom: '2026-11-18T02:53:06Z'\n    validUntil: '2026-11-18T06:54:06Z'\n",
                    1,
                ),
                encoding="utf-8",
            )
            model = build(root)
            markdown = render_markdown(model, "0" * 64)
        row = next(line for line in markdown.splitlines() if line.startswith("| `campaign.yaml`"))
        self.assertIn("HELD-ID-9", row)
        self.assertIn("2026-11-18T02:53:06Z", row)
        self.assertIn("2026-11-18T06:54:06Z", row)
        self.assertNotIn("| — | — | — | — |", row)
        # The held window is shown, not trusted: it is not a window source.
        source = next(s for s in model["authorization"]["sources"] if s["ref"] == "campaign.yaml")
        self.assertIsNone(source["validFrom"])
        self.assertEqual("HELD-ID-9", source["held"]["approvalId"])


class NotStartedTests(unittest.TestCase):
    def failed_start(self, root: Path) -> str:
        run = root / "runs" / UDP_CAMPAIGN
        for name in ("events.jsonl", "preflight.json", "report.txt"):
            (run / name).unlink()
        result = json.loads((run / "result.json").read_text(encoding="utf-8"))
        result.update({"state": "failed", "exitCode": 1, "completedSteps": 0})
        (run / "result.json").write_text(json.dumps(result), encoding="utf-8")
        return UDP_CAMPAIGN

    def test_a_run_that_never_started_is_our_failure_not_a_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = fixture(directory)
            run_id = self.failed_start(root)
            model = build(root)
            markdown = render_markdown(model, "0" * 64)
        run = next(r for r in model["runs"] if r["id"] == run_id)
        self.assertTrue(run["notStarted"])
        self.assertEqual("not-started", run["verdict"])
        self.assertEqual([], [f for f in model["findings"] if f["checkId"] == "derived:campaign-stopped"])
        self.assertEqual([], [f for f in model["findings"] if run_id in f["runs"]])
        summary = model["executiveSummary"]
        self.assertIn("never started", summary["paragraph"])
        self.assertIn("nothing was sent to your system", summary["paragraph"])
        self.assertTrue(any("never started" in row["title"] for row in summary["rows"]))
        self.assertFalse(any("did not pass" in row["title"] and "not-started" in row["title"] for row in summary["rows"]))
        self.assertIn("none (the run never started; nothing was sent)", ledger_row(markdown, run_id))
        codes = [item["code"] for item in model["limitations"]]
        self.assertIn("run-not-started", codes)
        self.assertNotIn("step-not-run", codes)

    def test_a_campaign_that_started_and_failed_is_still_a_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = fixture(directory)
            run = root / "runs" / UDP_CAMPAIGN
            result = json.loads((run / "result.json").read_text(encoding="utf-8"))
            result.update({"state": "failed", "exitCode": 1, "completedSteps": 1})
            (run / "result.json").write_text(json.dumps(result), encoding="utf-8")
            model = build(root)
        found = next(r for r in model["runs"] if r["id"] == UDP_CAMPAIGN)
        self.assertFalse(found["notStarted"])
        self.assertTrue([f for f in model["findings"] if UDP_CAMPAIGN in f["runs"]])


class PlainWordsTests(unittest.TestCase):
    def test_no_tool_jargon_in_any_rendering_outside_the_technical_tables(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            model = build(fixture(directory))
        for render in (render_markdown, render_html, render_text):
            text = render(model, "0" * 64)
            for word in ("packet oracle", "PJSUA"):
                self.assertNotIn(word, text, render.__name__)
        tls = next(r for r in model["runs"] if "tls" in r["id"] and r["kind"] == "call")
        self.assertTrue(any("automatic packet check" in reason for reason in tls["reasons"]), tls["reasons"])

    def test_the_loopback_sentence_appears_once_and_not_on_every_row(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            model = build(fixture(directory))
        markdown = render_markdown(model, "0" * 64)
        self.assertLessEqual(markdown.count("loopback address inside"), 1)
        for run in model["runs"]:
            self.assertFalse(any("loopback address inside" in reason for reason in run["reasons"]))
        self.assertEqual(1, [i["code"] for i in model["limitations"]].count("loopback-target") + [i["code"] for i in model["limitations"]].count("practice-runs"))


NOW = datetime.now(timezone.utc).replace(microsecond=0)


class RenewedWindowTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = support.make_repo(Path(temporary.name))
        self.work = self.repo / "work"
        self.root = support.compiled_engagement(self.repo, now=NOW, go=False)
        self.profile = self.root / "target-profile.yaml"

    def call(self) -> None:
        options = guided.CallOptions(profile=self.profile, destination="echo", duration=3)
        code, value = guided.execute(options, Fakes().dependencies(self.work, now=lambda: NOW))
        self.assertEqual(code, 0, value)

    def renew(self) -> None:
        support.write_scope(self.root, support.scope_text(
            valid_from=NOW - timedelta(minutes=30), valid_until=NOW + timedelta(hours=9)))
        outcome = compile_scope(self.root, now=NOW, force=True)
        self.assertEqual(outcome.exit_code, 0, outcome.as_dict())

    def test_after_a_renewal_the_header_shows_the_window_each_run_ran_under(self) -> None:
        self.call()
        self.renew()
        self.call()
        model, _ = build_report(self.root, Options(generated_at="2026-11-19T00:00:00Z"))
        windows = model["authorization"]["windowsInForce"]
        self.assertEqual(2, len(windows), windows)
        self.assertEqual([["R1"], ["R2"]], sorted(w["runs"] for w in windows))
        self.assertNotEqual(windows[0]["until"], windows[1]["until"])
        paragraph = model["executiveSummary"]["paragraph"]
        for window in windows:
            self.assertIn(f"{window['from']} to {window['until']}", paragraph)
        self.assertIn("renewed", paragraph)
        self.assertEqual([], model["integrityExceptions"])
        markdown = render_markdown(model, "0" * 64)
        self.assertIn("The approval window was renewed", markdown)
        # The owner text has no archive file names; the technical table has.
        owner_part = markdown.split("Approval records the runs were checked against (technical)")[0]
        self.assertNotIn("approved-scopes/", owner_part)
        self.assertIn("approved-scopes/", markdown)
        for run in model["runs"]:
            self.assertFalse(any("approved-scopes" in reason for reason in run["reasons"]))

    def test_without_a_renewal_the_header_keeps_one_window(self) -> None:
        self.call()
        self.call()
        model, _ = build_report(self.root, Options(generated_at="2026-11-19T00:00:00Z"))
        self.assertEqual(1, len(model["authorization"]["windowsInForce"]))
        self.assertNotIn("renewed", model["executiveSummary"]["paragraph"])


if __name__ == "__main__":
    unittest.main()
