"""Wave 8 polish: wording of `ready` that must stay true to what the code does.

Offline only: the host facts are fakes (see test_ready.py).
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from test_ready import ReadyTestCase  # noqa: E402

from cockpit_support import NOW  # noqa: E402

from sippycup_cockpit import ready  # noqa: E402


class AccountLineTests(ReadyTestCase):
    """Finding 6: the Account line must not claim a password source was checked."""

    def account_line(self, result: dict) -> str:
        return next(line for line in result["authorizes"] if line.startswith("Account"))

    def test_checked_source_is_named_as_checked(self) -> None:
        line = self.account_line(self.assess())
        self.assertIn("password from the source checked above", line)

    def test_no_source_given_says_none_was_checked(self) -> None:
        self.password.unlink()
        result = self.assess()
        self.assertEqual("GO", result["verdict"])
        line = self.account_line(result)
        self.assertNotIn("checked above", line)
        self.assertIn("no password source was given, so none was checked", line)

    def test_failed_source_does_not_claim_a_check(self) -> None:
        self.password.chmod(0o644)
        result = self.assess()
        self.assertEqual("NO-GO", result["verdict"])
        line = self.account_line(result)
        self.assertNotIn("password from the source checked above", line)
        self.assertIn("failed", line)


class PracticePasswordTests(ReadyTestCase):
    """Finding 11: the practice password is never printed, so the fix is a copy, not a typed password."""

    def test_missing_password_for_the_practice_target_says_to_copy_it(self) -> None:
        from cockpit_support import practice_state

        practice_state(self.repo, now=NOW)
        self.password.unlink()
        item = next(c for c in self.assess()["checks"] if c["id"] == "credentials")
        self.assertEqual("warn", item["status"])
        self.assertIn("cp work/practice/account.password", item["fix"])
        self.assertNotIn("read -rs", item["fix"])

    def test_other_targets_keep_the_typed_password_fix(self) -> None:
        self.password.unlink()
        item = next(c for c in self.assess()["checks"] if c["id"] == "credentials")
        self.assertNotIn("practice", item["fix"])


class EmptyScopeTests(unittest.TestCase):
    """Finding 17: no target address yet must not send the operator to a compile that is blocked."""

    def network(self, state: str) -> dict:
        from test_ready import FakeHost
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            model = {"engagement": {"display": "work/eng"}, "target": {"host": None}, "scope": {"state": state}}
            check, _ = ready.check_network(FakeHost(Path(tmp)), model, "--isolated", None)
            return check.as_dict()

    def test_incomplete_scope_points_at_scope_answer(self) -> None:
        item = self.network("incomplete")
        self.assertIn("scope answer work/eng", item["fix"])
        self.assertNotIn("sippycup scope compile", item["fix"])

    def test_inconsistent_scope_points_at_scope_check(self) -> None:
        item = self.network("inconsistent")
        self.assertIn("scope check work/eng", item["fix"])
        self.assertNotIn("sippycup scope compile", item["fix"])

    def test_complete_scope_points_at_compile(self) -> None:
        self.assertIn("scope compile work/eng", self.network("complete-not-compiled")["fix"])


class ApprovalPromptTests(ReadyTestCase):
    """Finding 12: only the cockpit asks for the last 4 characters of the approval id."""

    def test_go_line_says_where_the_prompt_appears(self) -> None:
        text = "\n".join(ready.render(self.assess(), None))
        self.assertIn("VERDICT: GO", text)
        self.assertNotIn("The first LIVE action still asks", text)
        self.assertIn("The cockpit (./bin/sippycup go) asks for the last 4 characters of the approval id", text)
        self.assertIn("call, matrix run and campaign run typed in a shell do not ask", text)


class WindowFirstTests(ReadyTestCase):
    """Finding 7: a window that is over or not open leads, and the unrelated advice is not printed."""

    def setUp(self) -> None:
        super().setUp()
        from datetime import timedelta

        from cockpit_support import make_engagement, scope_text, write_scope
        from sippycup_workbench.scope_derive import compile_scope

        self.timedelta = timedelta
        self.make_engagement, self.scope_text = make_engagement, scope_text
        self.write_scope, self.compile_scope = write_scope, compile_scope

    def pending_engagement(self, valid_from, valid_until, now, name="late"):
        root = self.make_engagement(self.repo, name)
        self.write_scope(root, self.scope_text(valid_from=valid_from, valid_until=valid_until, account=True))
        self.compile_scope(root, now=now)  # exit 1: the profile is written as pending
        return root

    def run_ready(self, root, now):
        from test_ready import FakeHost

        host = FakeHost(self.repo, now=now)
        return ready.assess(root, host=host, image="localhost/sippycup:test")

    def assert_window_leads(self, result, root, word, profile_word):
        window = next(c for c in result["checks"] if c["id"] == "window")
        self.assertEqual("no-go", window["status"])
        self.assertIn(word, "\n".join(window["lines"]))
        self.assertNotIn("record the owner's written approval", window["fix"])
        self.assertNotIn("record the owner's written approval", "\n".join(window["lines"]))
        self.assertNotIn("is pending, not approved", "\n".join(window["lines"]))
        scope = next(c for c in result["checks"] if c["id"] == "scope")
        self.assertNotIn("unanswered question", "\n".join(scope["lines"]))
        profile = next(c for c in result["checks"] if c["id"] == "profile")
        self.assertIn(profile_word, profile["lines"][0], profile["lines"])

    def test_expired_window_leads(self) -> None:
        now = NOW + self.timedelta(hours=5)
        root = self.pending_engagement(NOW - self.timedelta(hours=1), NOW + self.timedelta(hours=3), now)
        self.assert_window_leads(self.run_ready(root, now), root, "EXPIRED", "has expired")

    def test_future_window_leads(self) -> None:
        root = self.pending_engagement(NOW + self.timedelta(hours=1), NOW + self.timedelta(hours=4), NOW)
        self.assert_window_leads(self.run_ready(root, NOW), root, "not open yet", "not valid yet")


    def test_rehearse_names_the_window_before_the_pending_status(self) -> None:
        from sippycup_workbench.profile import load_profile, rehearse

        now = NOW + self.timedelta(hours=5)
        root = self.pending_engagement(NOW - self.timedelta(hours=1), NOW + self.timedelta(hours=3), now)
        errors = rehearse(load_profile(root / "target-profile.yaml"), now=now).errors
        self.assertIn("expired", errors[0])
        future = self.pending_engagement(NOW + self.timedelta(hours=1), NOW + self.timedelta(hours=4), NOW, "early")
        errors = rehearse(load_profile(future / "target-profile.yaml"), now=NOW).errors
        self.assertIn("not valid yet", errors[0])


if __name__ == "__main__":
    unittest.main()
