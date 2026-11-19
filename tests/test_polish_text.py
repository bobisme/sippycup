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
from test_guided_call import Fakes, GuidedCallCase, guided  # noqa: E402


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


class DryRunTextTests(GuidedCallCase):
    """Finding 10: the dry-run text lists what `call` itself does, not a manual procedure."""

    def test_dry_run_text_describes_what_call_does(self) -> None:
        code, value = self.run_call(Fakes(), dry_run=True)
        self.assertEqual(code, 0)
        rendered = guided.render_human(value)
        self.assertIn("What call does by itself", rendered)
        self.assertIn("one SIP OPTIONS preflight to 192.0.2.10:5060", rendered)
        self.assertIn("capture on interface", rendered)
        for stale in ("speak the agreed canary phrase", "Press Ctrl-C", "./bin/sippycup capture --target",
                      "place_manual_softphone_call"):
            self.assertNotIn(stale, rendered)
        # The machine-readable plan is unchanged.
        self.assertIn("one_call_plan", value)


class CockpitTextTests(unittest.TestCase):
    """Finding 13: cockpit lines that sent the operator the wrong way."""

    def setUp(self) -> None:
        from cockpit_support import NOW, compiled_engagement, make_repo

        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = make_repo(Path(self.temporary.name))
        self.root = compiled_engagement(self.repo, now=NOW, account=True, go=False)
        self.now = NOW

    def model(self):
        from sippycup_cockpit.model import build_model

        return build_model(self.root, repo=self.repo, now=self.now)

    def test_optional_security_checks_question_is_not_an_open_owner_question(self) -> None:
        stage = next(item for item in self.model()["stages"] if item["id"] == "scope")
        step = next(item for item in stage["steps"] if item["label"].startswith("owner questions answered"))
        self.assertEqual("owner questions answered (0 open)", step["label"])
        self.assertTrue(step["done"])

    def test_live_call_command_names_the_password_source_when_pasted_into_a_shell(self) -> None:
        from sippycup_cockpit.render import render_dashboard

        text = "\n".join(render_dashboard(self.model(), now=self.now))
        self.assertIn("--secret-file work/eng/account.password", text)
        self.assertIn("the cockpit asks for the password source itself", text)


if __name__ == "__main__":
    unittest.main()
