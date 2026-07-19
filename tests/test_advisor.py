from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_torture.exit_gate import default_review, run_exit_gate
from sippycup_workbench.advisor import assess
from sippycup_workbench.journal import initialize
from sippycup_workbench.profile import default_profile, write_profile


class AdvisorTests(unittest.TestCase):
    def test_missing_engagement_recommends_only_offline_initialization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "assessment"
            result = assess(root)
        self.assertEqual("setup-required", result["overall"])
        self.assertFalse(result["networkActivity"])
        self.assertEqual(
            "initialize-engagement", result["nextActions"][0]["id"]
        )
        self.assertTrue(
            all(not action["networkActivity"] for action in result["nextActions"])
        )
        self.assertTrue(
            (ROOT / "schemas" / "engagement-status-v1.schema.json").is_file()
        )

    def test_pending_engagement_names_exact_human_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "assessment"
            initialize(root, title="Assessment", owner="Quad")
            profile = root / "target-profile.yaml"
            write_profile(
                profile,
                default_profile(
                    name="stage", host="staging.example.invalid"
                ),
                force=False,
            )
            result = assess(
                root,
                now=datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc),
            )
        self.assertEqual("blocked", result["overall"])
        self.assertTrue(result["facts"]["journal"]["valid"])
        self.assertFalse(result["facts"]["profile"]["ready"])
        self.assertEqual("pass", result["facts"]["torture"]["technicalGate"])
        identifiers = {action["id"] for action in result["nextActions"]}
        self.assertIn("complete-target-authorization", identifiers)
        self.assertIn("create-torture-defaults-review", identifiers)

    def test_approved_inputs_stop_at_human_review_and_never_execute(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "assessment"
            initialize(root, title="Assessment", owner="Quad")
            profile = default_profile(name="stage", host="192.0.2.20")
            profile["target"]["approved_addresses"] = ["192.0.2.20"]
            profile["authorization"].update(
                {
                    "status": "approved",
                    "approval_id": "quad-one-call",
                    "valid_from": "2026-07-19T10:00:00Z",
                    "valid_until": "2026-07-19T14:00:00Z",
                }
            )
            write_profile(root / "target-profile.yaml", profile, force=False)
            gate = run_exit_gate()
            review = default_review(gate, reviewer="Quad")
            review.update(
                {
                    "reviewStatus": "approved",
                    "reviewId": "quad-defaults-1",
                    "reviewedAt": "2026-07-19T11:00:00Z",
                }
            )
            (root / "torture-defaults-review.json").write_text(
                json.dumps(review), encoding="utf-8"
            )
            result = assess(
                root,
                now=datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc),
            )
        self.assertEqual("ready-for-human-review", result["overall"])
        self.assertTrue(result["facts"]["profile"]["ready"])
        self.assertTrue(result["facts"]["torture"]["defaultsReviewed"])
        self.assertFalse(result["facts"]["torture"]["liveExecutionAvailable"])
        self.assertTrue(
            all(not action["networkActivity"] for action in result["nextActions"])
        )
        rendered_commands = [
            " ".join(action.get("argv", []))
            for action in result["nextActions"]
        ]
        self.assertFalse(any("campaign execute" in command for command in rendered_commands))

    def test_runs_get_evidence_and_privacy_followups(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "assessment"
            initialize(root, title="Assessment", owner="Quad")
            run_root = root / "runs"
            missing = run_root / "missing-manifest"
            blocked = run_root / "blocked-privacy"
            missing.mkdir(parents=True)
            blocked.mkdir()
            (missing / "result.json").write_text(
                '{"state":"failed"}', encoding="utf-8"
            )
            (blocked / "result.json").write_text(
                '{"state":"succeeded"}', encoding="utf-8"
            )
            (blocked / "evidence-manifest.json").write_text(
                '{"privacy":{"status":"blocked"}}', encoding="utf-8"
            )
            result = assess(root)
        self.assertEqual(2, result["facts"]["runs"]["count"])
        self.assertEqual(1, result["facts"]["runs"]["evidenceManifestMissing"])
        self.assertEqual(1, result["facts"]["runs"]["privacyBlocked"])
        identifiers = {action["id"] for action in result["nextActions"]}
        self.assertIn("manifest-missing-manifest", identifiers)
        self.assertIn("privacy-blocked-privacy", identifiers)


if __name__ == "__main__":
    unittest.main()
