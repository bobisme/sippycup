"""Wave 8 polish: operator-facing wording that must stay true to what the code does.

Offline only: nothing here opens a socket or starts a container.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from test_engagement_report import engagement, run_cli  # noqa: E402


class ReportPathTests(unittest.TestCase):
    """Finding 3: the path to send to the owner must be the newest report."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = engagement(Path(self.temporary.name))

    def test_first_report_names_the_file_to_send(self) -> None:
        code, out, err = run_cli(str(self.root), "--generated-at", "2026-11-18T04:00:00Z")
        self.assertEqual(code, 0, err)
        self.assertIn(f"Send to the owner: {self.root}/report/engagement-report.html", out)
        self.assertNotIn("EARLIER", out)

    def test_later_report_says_which_directory_is_newest_and_which_is_stale(self) -> None:
        run_cli(str(self.root), "--generated-at", "2026-11-18T04:00:00Z")
        code, out, err = run_cli(str(self.root), "--generated-at", "2026-11-18T05:00:00Z")
        self.assertEqual(code, 0, err)
        newest = f"{self.root}/report-20261118T050000Z"
        self.assertIn(f"Send to the owner: {newest}/engagement-report.html", out)
        self.assertIn("EARLIER report(s), do not send", out)
        self.assertIn(f"{self.root}/report ", out + " ")
        # Nothing already written is deleted or changed.
        self.assertTrue((self.root / "report" / "report.json").is_file())


if __name__ == "__main__":
    unittest.main()
