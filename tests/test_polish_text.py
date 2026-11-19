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


class ReportGrammarTests(unittest.TestCase):
    """Finding 17: '1 run were recorded'."""

    def test_one_run_is_singular_and_several_are_plural(self) -> None:
        from test_engagement_report import PASS_CALL, model_for

        with tempfile.TemporaryDirectory() as tmp:
            root = engagement(Path(tmp))
            one = model_for(root, run_globs=("*" + PASS_CALL[-8:],))["executiveSummary"]["paragraph"]
            self.assertIn("1 run was recorded", one)
            many = model_for(root)["executiveSummary"]["paragraph"]
            self.assertRegex(many, r"\d+ runs were recorded")


class TriviaMessageTests(unittest.TestCase):
    """Finding 17: messages that named a cause but not the next step."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "eng"
        self.root.mkdir()

    def test_profile_before_compile_says_to_compile(self) -> None:
        from sippycup_workbench.profile import ProfileError, load_profile

        (self.root / "scope.yaml").write_text("name: x\n")
        with self.assertRaises(ProfileError) as raised:
            load_profile(self.root / "target-profile.yaml")
        self.assertIn("scope compile", str(raised.exception))
        self.assertIn("does not exist", str(raised.exception))

    def test_missing_profile_without_a_scope_has_no_compile_advice(self) -> None:
        from sippycup_workbench.profile import ProfileError, load_profile

        with self.assertRaises(ProfileError) as raised:
            load_profile(self.root / "target-profile.yaml")
        self.assertNotIn("scope compile", str(raised.exception))

    def test_scope_init_platform_on_an_existing_file_says_what_to_do(self) -> None:
        from sippycup_workbench.scope import ScopeError, create_scope

        create_scope(self.root)
        with self.assertRaises(ScopeError) as raised:
            create_scope(self.root, platform=True)
        message = str(raised.exception)
        self.assertIn("nothing was changed", message)
        self.assertIn("examples/scope/platform-scope.yaml", message)
        with self.assertRaises(ScopeError) as plain:
            create_scope(self.root)
        self.assertNotIn("platform", str(plain.exception))


class StopWordingTests(unittest.TestCase):
    """Finding 16: `stop` says what it proved without contradicting the lines above, and prints a runnable journal line."""

    def render(self, *, engagement=None, practice_running=True) -> str:
        import test_stop
        from sippycup_cockpit import stop

        containers = test_stop.standard_containers()
        if not practice_running:
            containers = [c for c in containers if c["Id"] != test_stop.PRACTICE]
        host = test_stop.FakeHost(containers)
        report = test_stop.run_stop(host)
        return "\n".join(stop.render(report, engagement))

    def test_silence_line_does_not_claim_no_container_while_the_practice_target_is_listed(self) -> None:
        text = self.render()
        self.assertIn("untouched ws-practice (the practice target; add --include-practice)", text)
        self.assertIn("Silence: PROVED. No Sippycup sender", text)
        self.assertNotIn("No container of this checkout is running", text)
        self.assertIn("The practice target is still up", text)
        self.assertIn("it is a server and sends nothing on its own", text)

    def test_silence_line_without_a_practice_target_has_no_practice_sentence(self) -> None:
        self.assertNotIn("practice target is still up", self.render(practice_running=False))

    def test_placeholder_journal_line_is_explained(self) -> None:
        text = self.render()
        self.assertIn("work/NAME is a placeholder", text)
        self.assertIn("--engagement DIR", text)

    def test_named_engagement_has_no_placeholder_note(self) -> None:
        text = self.render(engagement="work/acme")
        self.assertIn("journal add work/acme", text)
        self.assertNotIn("placeholder", text)

    def test_a_single_engagement_is_used_without_being_named(self) -> None:
        import test_stop
        from cockpit_support import make_engagement, make_repo
        from sippycup_cockpit import stop

        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            make_engagement(repo, "only-one")
            self.assertEqual("work/only-one", stop.default_engagement(repo))
            make_engagement(repo, "second")
            self.assertIsNone(stop.default_engagement(repo))
            del test_stop


if __name__ == "__main__":
    unittest.main()
