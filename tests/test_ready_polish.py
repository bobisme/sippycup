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


class ApprovalPromptTests(ReadyTestCase):
    """Finding 12: only the cockpit asks for the last 4 characters of the approval id."""

    def test_go_line_says_where_the_prompt_appears(self) -> None:
        text = "\n".join(ready.render(self.assess(), None))
        self.assertIn("VERDICT: GO", text)
        self.assertNotIn("The first LIVE action still asks", text)
        self.assertIn("The cockpit (./bin/sippycup go) asks for the last 4 characters of the approval id", text)
        self.assertIn("call, matrix run and campaign run typed in a shell do not ask", text)


if __name__ == "__main__":
    unittest.main()
