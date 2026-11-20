"""Cockpit action numbers and text (rehearse 2, findings 18 and 26).

Action numbers are fixed for a session, so a number read a moment ago cannot
select another action after a refresh; `yes` at the password-source prompt
takes the offered default; the target line shows each target's destinations
once; the go/no-go line says which profile changed.

What protects against a wrong number today (and still does): no action starts
on the number alone. The cockpit prints what the action is, the exact command,
and for a LIVE action asks for the typed approval token before anything is sent.
"""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cockpit_support import NOW, compiled_engagement, make_repo, write_go  # noqa: E402
from sippycup_cockpit.line import LineUI  # noqa: E402
from sippycup_cockpit.model import build_model  # noqa: E402
from sippycup_cockpit.render import _before_changed, _destinations_text, render_dashboard  # noqa: E402
from sippycup_cockpit.session import Session  # noqa: E402
from test_cockpit_confirm import FakeRunner  # noqa: E402


class NumberTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = make_repo(Path(temporary.name))
        self.runner = FakeRunner()

    def session(self, root) -> Session:
        return Session(self.repo, root, runner=self.runner, clock=lambda: NOW, environ={}, commands=None,
                       host_has_tshark=True)

    def numbers(self, session: Session) -> dict[str, int]:
        return {action["id"]: action["number"] for action in session.actions}

    def test_numbers_do_not_change_when_the_state_changes_the_list(self) -> None:
        root = compiled_engagement(self.repo, now=NOW, go=False)
        session = self.session(root)
        before = self.numbers(session)
        order_before = [action["id"] for action in session.actions]
        write_go(root, now=NOW)  # stage four is done
        session.toggle_skip_practice()  # the current stage moves, so the list is reordered
        session.refresh()
        after = self.numbers(session)
        self.assertNotEqual(order_before, [action["id"] for action in session.actions])
        for identifier, number in before.items():
            if identifier in after:
                self.assertEqual(number, after[identifier], identifier)
        self.assertEqual(len(set(after.values())), len(after), "numbers are unique")
        self.assertTrue(all(isinstance(n, int) and n >= 1 for n in after.values()))

    def test_a_number_is_never_reused_for_a_different_action(self) -> None:
        root = compiled_engagement(self.repo, now=NOW, go=True)
        session = self.session(root)
        first = self.numbers(session)
        session.model["actions"] = [a for a in session.model["actions"] if a["id"] != "call"]
        retired = first["call"]
        session._number_actions()
        write_go(root, now=NOW, verdict="NO-GO")
        session.refresh()
        self.assertNotIn(retired, [n for i, n in self.numbers(session).items() if i != "call"])
        self.assertEqual(retired, self.numbers(session).get("call", retired))

    def test_the_dashboard_prints_the_fixed_numbers(self) -> None:
        root = compiled_engagement(self.repo, now=NOW, go=False)
        session = self.session(root)
        numbers = self.numbers(session)
        text = "\n".join(render_dashboard(session.model, now=NOW))
        ready = next(a for a in session.actions if a["id"] == "ready")
        self.assertIn(f"{numbers['ready']:>2}. {ready['label']:9} {ready['title']}", text)

    def drive(self, session: Session, typed: str) -> str:
        out = io.StringIO()
        LineUI(session, io.StringIO(typed), out).loop()
        return out.getvalue()

    def test_typing_a_number_runs_nothing_for_a_number_that_is_not_offered(self) -> None:
        root = compiled_engagement(self.repo, now=NOW, go=False)
        session = self.session(root)
        gone = max(self.numbers(session).values()) + 5
        text = self.drive(session, f"{gone}\nq\n")
        self.assertIn("No such action.", text)
        self.assertEqual([], self.runner.started)

    def test_a_retired_number_says_it_is_not_offered_and_starts_nothing(self) -> None:
        root = compiled_engagement(self.repo, now=NOW, go=True)
        session = self.session(root)
        number = self.numbers(session)["call"]
        session.model["actions"] = [a for a in session.model["actions"] if a["id"] != "call"]
        text = self.drive(session, f"{number}\nq\n")
        self.assertIn(f"Action {number} (", text)
        self.assertIn("is not offered now", text)
        self.assertEqual([], self.runner.started)

    def test_yes_at_the_password_source_prompt_takes_the_offered_default(self) -> None:
        root = compiled_engagement(self.repo, now=NOW, go=True, account=True)
        password = self.repo / "work" / "eng" / "account.password"
        password.write_text("not-a-real-password\n")
        password.chmod(0o600)
        session = self.session(root)
        number = self.numbers(session)["call"]
        text = self.drive(session, f"{number}\nyes\nwrong\nq\n")
        self.assertIn("Final command:", text)
        self.assertIn("--secret-file work/eng/account.password", text)
        self.assertNotIn("answer 'file PATH' or 'env NAME'", text)
        self.assertIn("The token does not match", text, "the typed approval token is still required")
        self.assertEqual([], self.runner.started)
        text = self.drive(self.session(root), f"{number}\n\nwrong\nq\n")
        self.assertIn("Final command:", text, "Enter still takes the default")


class TextTests(unittest.TestCase):
    def test_each_targets_destinations_are_listed_once_under_its_target(self) -> None:
        target = {"name": "practice", "destinations": [
            {"user": "echo", "expect": "echo", "target": "practice"},
            {"user": "dtmf", "expect": "echo", "target": "practice"},
            {"user": "echo", "expect": "echo", "target": "tls"},
        ]}
        self.assertEqual("echo (echo), dtmf (echo); on target tls: echo (echo)", _destinations_text(target))
        self.assertEqual("none recorded", _destinations_text({"name": None, "destinations": []}))
        single = {"name": "a", "destinations": [{"user": "echo", "expect": "echo", "target": None}]}
        self.assertEqual("echo (echo)", _destinations_text(single))

    def test_the_go_line_says_which_profile_changed(self) -> None:
        self.assertEqual("was made before target-profile.yaml changed",
                         _before_changed({"changedProfiles": ["target-profile.yaml"]}))
        self.assertIn("does not cover", _before_changed({}))

    def test_a_record_for_an_older_profile_names_the_changed_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = make_repo(Path(temporary))
            root = compiled_engagement(repo, now=NOW, go=False)
            write_go(root, now=NOW, profile_sha256="0" * 64)
            model = build_model(root, repo=repo, now=NOW, advisor=False, commands=None)
        facts = model["readiness"]["goNoGo"]
        self.assertEqual(["target-profile.yaml"], facts["changedProfiles"])
        text = "\n".join(render_dashboard(model, now=NOW))
        self.assertIn("was made before target-profile.yaml changed", text)
        self.assertNotIn("was for another profile", text)


if __name__ == "__main__":
    unittest.main()
