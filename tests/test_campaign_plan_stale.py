"""Wave 8 finding 9: `campaign plan` must not plan from a manifest that scope.yaml no longer backs.

No network: the plan command only reads files.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))

from test_campaign_window import CAMPAIGN, manifest_with, scope_document, window  # noqa: E402

FAR = datetime(2099, 1, 1, tzinfo=timezone.utc)
PAST = datetime(2020, 1, 1, tzinfo=timezone.utc)


class StaleManifestTests(unittest.TestCase):
    def plan(self, scope: dict | None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "campaign.yaml").write_text(yaml.safe_dump(manifest_with(window(FAR)), sort_keys=True))
        if scope is not None:
            (root / "scope.yaml").write_text(yaml.safe_dump(scope))
        process = subprocess.run(
            [sys.executable, str(CAMPAIGN), "plan", str(root / "campaign.yaml"), "--output", "plan.json"],
            text=True, capture_output=True, timeout=60, cwd=root,
        )
        return process, root

    def test_scope_with_an_ended_window_refuses_and_writes_nothing(self):
        process, root = self.plan(scope_document("approved", PAST))
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertFalse((root / "plan.json").exists())
        self.assertIn("refusing to plan", process.stderr)
        self.assertIn("scope.yaml", process.stderr)
        self.assertIn("scope compile", process.stderr)
        self.assertIn("nothing was sent", process.stderr)

    def test_scope_revoked_or_pending_refuses(self):
        for status in ("revoked", "pending"):
            with self.subTest(status):
                process, root = self.plan(scope_document(status, FAR))
                self.assertEqual(process.returncode, 2, process.stderr)
                self.assertFalse((root / "plan.json").exists())
                self.assertIn("not approved", process.stderr)

    def test_scope_that_agrees_with_the_manifest_still_plans(self):
        process, root = self.plan(scope_document("approved", FAR))
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue((root / "plan.json").is_file())

    def test_no_scope_beside_the_manifest_plans_as_before(self):
        process, root = self.plan(None)
        self.assertEqual(process.returncode, 0, process.stderr)

    def test_window_that_has_not_opened_still_plans_with_the_existing_warning(self):
        soon = datetime.now(timezone.utc) + timedelta(days=30)
        manifest = manifest_with(window(FAR, start=soon))
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "campaign.yaml").write_text(yaml.safe_dump(manifest, sort_keys=True))
        (root / "scope.yaml").write_text(yaml.safe_dump(scope_document("approved", FAR, start=soon)))
        process = subprocess.run(
            [sys.executable, str(CAMPAIGN), "plan", str(root / "campaign.yaml"), "--output", "plan.json"],
            text=True, capture_output=True, timeout=60, cwd=root,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn("has not opened yet", process.stderr)


if __name__ == "__main__":
    unittest.main()
