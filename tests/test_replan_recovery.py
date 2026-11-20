"""One recovery for a stale frozen plan, and `campaign plan` honouring integrity (rehearsal 2, findings 13 and 30).

A frozen plan is never overwritten. When it goes stale (a renewed window, a
rewritten campaign file, a new CA), `ready`, the `campaign plan` refusal and
the `campaign run` refusal print the same single line, and that line works
when pasted: it keeps the old plan under a dated name and freezes a new one.
`campaign plan` also refuses a campaign file that was edited or that
`scope.yaml` no longer backs, as `campaign run` does. No network.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from sippycup_cockpit import ready  # noqa: E402
from sippycup_workbench.replan import kept_name, replan_command  # noqa: E402
from test_campaign_window import CAMPAIGN, manifest_with, window  # noqa: E402

FAR = datetime(2099, 1, 1, tzinfo=timezone.utc)
FIX = re.compile(r"^mv -n (\S+) (\S+) && \./bin/sippycup campaign plan (\S+) --output (\S+)$")


class ReplanCommandTests(unittest.TestCase):
    def test_the_line_keeps_the_old_plan_under_a_dated_name_and_plans_again(self) -> None:
        now = datetime(2026, 11, 19, 23, 49, 28, tzinfo=timezone.utc)
        line = replan_command("work/acme/plan.json", "work/acme/campaign.yaml", now)
        self.assertEqual(
            "mv -n work/acme/plan.json work/acme/plan-20261119T234928Z.json && "
            "./bin/sippycup campaign plan work/acme/campaign.yaml --output work/acme/plan.json",
            line,
        )
        self.assertEqual("work/acme/plan-20261119T234928Z.json", kept_name("work/acme/plan.json", now))

    def test_the_line_is_safe_for_unusual_paths(self) -> None:
        line = replan_command("work/a b/plan.json", "work/a b/campaign.yaml")
        self.assertIn("'work/a b/plan.json'", line)
        self.assertEqual("mv", shlex.split(line)[0])


class PlanRefusalTests(unittest.TestCase):
    def run_tool(self, root: Path, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(CAMPAIGN), *arguments], text=True, capture_output=True, timeout=60, cwd=root
        )

    def make(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "campaign.yaml").write_text(yaml.safe_dump(manifest_with(window(FAR)), sort_keys=True))
        return root

    def pasted(self, text: str) -> str:
        line = next(part for part in text.split("run: ", 1)[1:2])
        return line.strip().splitlines()[0]

    def test_planning_over_an_existing_plan_prints_the_recovery_and_it_works(self) -> None:
        root = self.make()
        first = self.run_tool(root, "plan", "campaign.yaml", "--output", "plan.json")
        self.assertEqual(0, first.returncode, first.stderr)
        before = (root / "plan.json").read_bytes()
        again = self.run_tool(root, "plan", "campaign.yaml", "--output", "plan.json")
        self.assertEqual(2, again.returncode)
        self.assertEqual(before, (root / "plan.json").read_bytes())
        self.assertIn("refusing to overwrite existing frozen plan", again.stderr)
        self.assertIn("Nothing was written and nothing was sent", again.stderr)
        line = self.pasted(again.stderr)
        match = FIX.match(line)
        self.assertTrue(match, line)
        self.assertEqual(("plan.json", "campaign.yaml", "plan.json"), (match.group(1), match.group(3), match.group(4)))
        # Pasted as printed (the printed line uses ./bin/sippycup; run its two halves here).
        mv, plan = line.split(" && ")
        done = subprocess.run(shlex.split(mv), cwd=root, capture_output=True, text=True)
        self.assertEqual(0, done.returncode, done.stderr)
        kept = [p for p in root.iterdir() if p.name.startswith("plan-") and p.suffix == ".json"]
        self.assertEqual(1, len(kept))
        self.assertEqual(before, kept[0].read_bytes())
        redo = self.run_tool(root, *shlex.split(plan)[2:])
        self.assertEqual(0, redo.returncode, redo.stderr)
        self.assertTrue((root / "plan.json").is_file())

    def test_run_with_a_changed_campaign_file_says_nothing_was_sent_and_what_to_run(self) -> None:
        root = self.make()
        self.assertEqual(0, self.run_tool(root, "plan", "campaign.yaml", "--output", "plan.json").returncode)
        (root / "campaign.yaml").write_text(
            yaml.safe_dump(manifest_with(window(FAR - timedelta(days=1))), sort_keys=True)
        )
        refused = self.run_tool(
            root, "run", "plan.json", "--manifest", "campaign.yaml", "--run-root", "runs", "--interface", "lo"
        )
        self.assertEqual(2, refused.returncode)
        self.assertIn("source manifest SHA-256 does not match frozen plan", refused.stderr)
        self.assertIn("Nothing was sent", refused.stderr)
        self.assertTrue(FIX.match(self.pasted(refused.stderr)), refused.stderr)
        self.assertFalse((root / "runs").exists())


class ReadyFixLineTests(unittest.TestCase):
    NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)

    def test_the_window_mismatch_fix_is_the_one_pasteable_line(self) -> None:
        from test_campaign_window import ReadyAndCockpitTests

        case = ReadyAndCockpitTests()
        facts = case.facts(window(self.NOW + timedelta(hours=9)))
        item = ready.check_window(case.model(facts), self.NOW, timezone.utc, 60)
        self.assertEqual("warn", item.status)
        self.assertTrue(FIX.match(item.fix), item.fix)
        self.assertTrue(item.fix.endswith("work/eng/campaign.yaml --output work/eng/plan.json"), item.fix)

    def test_the_changed_ca_fix_is_the_same_line_and_the_caution_is_a_line_of_its_own(self) -> None:
        from test_ready import TlsTests

        case = TlsTests()
        case.setUp()
        self.addCleanup(case.temp.cleanup)
        (case.root / "plan.json").write_text(json.dumps({"steps": [
            {"tls": {"caFile": "work/eng/ca.crt", "caSha256": "0" * 64, "serverName": "sip.owner.test"}}]}))
        item = case.check()
        self.assertEqual("no-go", item.status)
        self.assertTrue(FIX.match(item.fix), item.fix)
        self.assertTrue(any("confirm the new CA with the owner" in line for line in item.lines), item.lines)
        self.assertNotIn("(after", item.fix)


class PlanIntegrityTests(unittest.TestCase):
    """Finding 30: `campaign plan` refuses what `campaign run` refuses."""

    def compiled(self) -> Path:
        from test_scope import NOW, complete_scope

        from sippycup_workbench.scope_derive import compile_scope

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "assessment"
        root.mkdir(mode=0o700)
        (root / "scope.yaml").write_text(yaml.safe_dump(complete_scope(), sort_keys=False))
        (root / "scope.yaml").chmod(0o600)
        outcome = compile_scope(root, now=NOW)
        self.assertEqual(0, outcome.exit_code, outcome.as_dict())
        return root

    def plan(self, root: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(CAMPAIGN), "plan", "campaign.yaml", "--output", "plan.json"],
            text=True, capture_output=True, timeout=60, cwd=root,
        )

    def test_a_compiled_current_manifest_plans(self) -> None:
        root = self.compiled()
        done = self.plan(root)
        self.assertEqual(0, done.returncode, done.stderr)

    def test_an_edited_manifest_is_refused_with_nothing_written(self) -> None:
        root = self.compiled()
        with (root / "campaign.yaml").open("a", encoding="utf-8") as handle:
            handle.write("# edited by hand\n")
        done = self.plan(root)
        self.assertEqual(2, done.returncode)
        self.assertIn("refusing to plan", done.stderr)
        self.assertIn("was edited after scope compile wrote it", done.stderr)
        self.assertIn("nothing was sent", done.stderr)
        self.assertIn("scope compile --force", done.stderr)
        self.assertFalse((root / "plan.json").exists())

    def test_a_manifest_the_scope_no_longer_backs_is_refused(self) -> None:
        root = self.compiled()
        with (root / "scope.yaml").open("a", encoding="utf-8") as handle:
            handle.write("# the scope changed after the last compile\n")
        done = self.plan(root)
        self.assertEqual(2, done.returncode)
        self.assertIn("refusing to plan", done.stderr)
        self.assertIn("changed after the last scope compile", done.stderr)
        self.assertIn("./bin/sippycup scope compile", done.stderr)
        self.assertFalse((root / "plan.json").exists())


if __name__ == "__main__":
    unittest.main()
