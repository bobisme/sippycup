"""Advisor additions used by the cockpit; status stays network-free and compatible."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cockpit_support import NOW, call_result, compiled_engagement, make_engagement, make_repo, write_run  # noqa: E402
from sippycup_workbench.advisor import assess  # noqa: E402


def ids(result):
    return [action["id"] for action in result["nextActions"]]


class AdvisorAdditionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = make_repo(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_new_engagement_suggests_the_practice_rehearsal(self) -> None:
        result = assess(make_engagement(self.repo), now=NOW)
        self.assertIn("rehearse-on-practice-target", ids(result))
        self.assertFalse(result["networkActivity"])
        self.assertEqual(0, result["facts"]["calls"]["count"])
        self.assertEqual(0, result["facts"]["calls"]["passed"])

    def test_ready_profile_suggests_the_guided_call_dry_run_and_campaign_plan(self) -> None:
        root = compiled_engagement(self.repo, now=NOW)
        result = assess(root, now=NOW)
        actions = {action["id"]: action for action in result["nextActions"]}
        self.assertEqual(
            ["./bin/sippycup", "call", str(root / "target-profile.yaml"), "--dial", "echo", "--dry-run"],
            actions["review-guided-call-dry-run"]["argv"],
        )
        self.assertEqual("campaign", actions["plan-baseline-campaign"]["argv"][1])
        for action in result["nextActions"]:
            self.assertFalse(action["networkActivity"], action["id"])
            argv = action.get("argv") or []
            if argv:
                self.assertEqual("./bin/sippycup", argv[0], action["id"])
        torture = actions.get("create-torture-defaults-review")
        if torture is not None:
            self.assertEqual(["./bin/sippycup", "torture", "review-template"], torture["argv"][:3])

    def test_call_runs_feed_facts_and_manifest_actions(self) -> None:
        root = compiled_engagement(self.repo, now=NOW)
        write_run(root, "calls", "20261117T100000.000000Z-stage-a", {"result.json": call_result("pass")})
        result = assess(root, now=NOW)
        self.assertEqual(1, result["facts"]["calls"]["count"])
        self.assertEqual(1, result["facts"]["calls"]["passed"])
        self.assertIn("calls-manifest-20261117T100000.000000Z-stage-a", ids(result))
        self.assertNotIn("review-guided-call-dry-run", ids(result))
        self.assertNotIn("rehearse-on-practice-target", ids(result))
        json.dumps(result)

    def test_status_json_keeps_its_existing_keys(self) -> None:
        result = assess(make_engagement(self.repo), now=NOW)
        for key in ("overall", "networkActivity", "facts", "blockers", "warnings", "nextActions"):
            self.assertIn(key, result)
        for key in ("engagement", "journal", "profile", "torture"):
            self.assertIn(key, result["facts"])


if __name__ == "__main__":
    unittest.main()
