"""summary judges each run by the approval in force when it ran (bn-2rgk).

Before this fix summary checked every run against the current scope file and
profiles: a run to the approved address was reported as unapproved once the owner
approved another address, and a run could pass against an
approval granted after it. Every test here uses injected fakes.
"""

from __future__ import annotations

import hashlib
import json
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

NOW = datetime.now(timezone.utc).replace(microsecond=0)


class ApprovalInForceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = support.make_repo(Path(temporary.name))
        self.work = self.repo / "work"
        self.root = support.compiled_engagement(self.repo, now=NOW, go=False)
        self.profile = self.root / "target-profile.yaml"

    def call(self) -> dict:
        options = guided.CallOptions(profile=self.profile, destination="echo", duration=3)
        code, value = guided.execute(options, Fakes().dependencies(self.work, now=lambda: NOW))
        self.assertEqual(code, 0, value)
        return value

    def report(self) -> dict:
        model, _ = build_report(self.root, Options(generated_at="2026-11-19T00:00:00Z"))
        return model

    def move_target(self) -> None:
        """After the call, the owner approves another address instead of the old one."""
        support.write_scope(self.root, support.scope_text(
            valid_from=NOW - timedelta(hours=1), valid_until=NOW + timedelta(hours=3), address="127.0.0.3"))
        outcome = compile_scope(self.root, now=NOW, force=True)
        self.assertEqual(outcome.exit_code, 0, outcome.as_dict())

    def test_the_run_records_the_scope_in_force_in_a_write_once_copy(self) -> None:
        value = self.call()
        record = value["approvalRecord"]
        self.assertEqual(record["state"], "compiled-current")
        scope_sha = hashlib.sha256((self.root / "scope.yaml").read_bytes()).hexdigest()
        self.assertEqual(record["scopeSha256"], scope_sha)
        self.assertEqual(record["scopeArchive"], f"approved-scopes/scope-{scope_sha}.yaml")
        copy = self.root / record["scopeArchive"]
        self.assertEqual(copy.read_bytes(), (self.root / "scope.yaml").read_bytes())
        self.assertEqual(copy.stat().st_mode & 0o777, 0o600)
        run = self.root / "calls" / Path(value["runDirectory"]).name
        stored = json.loads((run / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(stored["approvalRecord"], record)

    def test_a_run_to_the_approved_address_stays_approved_after_the_owner_changes_it(self) -> None:
        self.call()
        self.move_target()
        model = self.report()
        self.assertEqual([e for e in model["integrityExceptions"] if e["code"] == "target-not-approved"], [])
        run = model["runs"][0]
        self.assertTrue(any("scope in force when it ran" in reason for reason in run["reasons"]), run["reasons"])

    def test_a_run_without_a_record_is_judged_against_the_current_records_and_says_so(self) -> None:
        first = self.call()
        second = self.call()
        # The second run predates the record: its result has none.
        run = self.root / "calls" / Path(second["runDirectory"]).name
        stored = json.loads((run / "result.json").read_text(encoding="utf-8"))
        del stored["approvalRecord"]
        (run / "result.json").write_text(json.dumps(stored), encoding="utf-8")
        self.move_target()
        model = self.report()
        outside = [e for e in model["integrityExceptions"] if e["code"] == "target-not-approved"]
        self.assertEqual([e["run"] for e in outside], [run.name])
        self.assertNotIn(Path(first["runDirectory"]).name, [e["run"] for e in outside])
        codes = [item["code"] for item in model["limitations"]]
        self.assertIn("approval-in-force-unrecorded", codes)

    def test_a_campaign_records_the_scope_its_manifest_was_compiled_from(self) -> None:
        from test_call_ledger import EngagementCeilingTests

        _result, run_dir = EngagementCeilingTests.campaign(self)
        stored = json.loads((Path(run_dir) / "result.json").read_text(encoding="utf-8"))
        record = stored["approvalRecord"]
        self.assertEqual((record["state"], record["source"]), ("compiled-current", "campaign.yaml"))
        self.assertTrue((self.root / record["scopeArchive"]).is_file())
        self.move_target()
        model = self.report()
        campaign = [run for run in model["runs"] if run["kind"] == "campaign"]
        self.assertEqual(len(campaign), 1)
        self.assertTrue(any("scope in force when it ran" in reason for reason in campaign[0]["reasons"]))
        self.assertEqual([e for e in model["integrityExceptions"] if e["code"] == "target-not-approved"], [])

    def test_a_tampered_copy_is_not_an_authority(self) -> None:
        value = self.call()
        copy = self.root / value["approvalRecord"]["scopeArchive"]
        copy.write_text(copy.read_text(encoding="utf-8") + "\n# edited\n", encoding="utf-8")
        self.move_target()
        model = self.report()
        self.assertTrue([e for e in model["integrityExceptions"] if e["code"] == "target-not-approved"])


if __name__ == "__main__":
    unittest.main()
