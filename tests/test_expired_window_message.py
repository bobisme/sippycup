"""An expired window is one true message (rehearsal 2, finding 14).

A scope that says approved, with a window that has ended, compiles to a profile
written as pending. `rehearse` and `call` used to print the expiry and then
`authorization is pending, not approved`, as if nobody had recorded the
approval; `scope compile` printed `status: pending`. Now the window is the one
cause named, and compile says `not usable: <the scope error>`. What is refused
does not change.
"""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from sippycup_workbench import cli  # noqa: E402
from sippycup_workbench.profile import default_profile, load_profile, rehearse  # noqa: E402
from sippycup_workbench.scope_derive import compile_scope  # noqa: E402

PRACTICE_EXAMPLE = ROOT / "examples" / "scope" / "practice-scope.yaml"
NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)


def approved(status: str, valid_until: datetime) -> dict:
    profile = default_profile(name="stage", host="192.0.2.20")
    profile["target"]["approved_addresses"] = ["192.0.2.20"]
    profile["authorization"].update(
        {
            "status": status,
            "approval_id": "owner-approval-1",
            "approved_by": "the owner",
            "valid_from": (NOW - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "valid_until": valid_until.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )
    return profile


class ProfileMessageTests(unittest.TestCase):
    def test_a_pending_profile_with_an_ended_window_names_only_the_window(self) -> None:
        result = rehearse(approved("pending", NOW - timedelta(hours=1)), now=NOW)
        self.assertFalse(result.ready)
        expired = [e for e in result.errors if e.startswith("authorization has expired")]
        self.assertEqual(1, len(expired), result.errors)
        self.assertFalse([e for e in result.errors if "pending" in e], result.errors)

    def test_a_pending_profile_with_a_window_that_has_not_opened_names_only_the_window(self) -> None:
        profile = approved("pending", NOW + timedelta(days=2))
        profile["authorization"]["valid_from"] = (NOW + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        result = rehearse(profile, now=NOW)
        self.assertTrue([e for e in result.errors if e.startswith("authorization is not valid yet")])
        self.assertFalse([e for e in result.errors if "pending" in e], result.errors)

    def test_other_statuses_still_say_so_next_to_an_ended_window(self) -> None:
        for status in ("revoked", "expired"):
            with self.subTest(status):
                result = rehearse(approved(status, NOW - timedelta(hours=1)), now=NOW)
                self.assertIn(f"authorization is {status}, not approved", result.errors)

    def test_a_pending_profile_with_a_current_window_still_says_pending(self) -> None:
        result = rehearse(approved("pending", NOW + timedelta(hours=3)), now=NOW)
        self.assertIn("authorization is pending, not approved", result.errors)

    def test_what_is_refused_does_not_change(self) -> None:
        for status in ("pending", "approved", "revoked"):
            with self.subTest(status):
                self.assertFalse(rehearse(approved(status, NOW - timedelta(hours=1)), now=NOW).ready)
        self.assertTrue(rehearse(approved("approved", NOW + timedelta(hours=3)), now=NOW).ready)


class CompileMessageTests(unittest.TestCase):
    def compile_expired(self) -> tuple[Path, str]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "eng"
        root.mkdir(mode=0o700)
        text = PRACTICE_EXAMPLE.read_text()  # its window is in the past
        (root / "scope.yaml").write_text(text)
        (root / "scope.yaml").chmod(0o600)
        self.addCleanup(os.chdir, os.getcwd())
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = cli.main(["scope", "compile", str(root)])
        self.assertEqual(1, code)
        return root, buffer.getvalue()

    def test_compile_says_not_usable_and_why_instead_of_pending(self) -> None:
        root, out = self.compile_expired()
        self.assertIn("Target profile: not usable: scope.window_expired [authorization.valid_until]", out)
        self.assertNotIn("Target profile authorization status: pending", out)
        self.assertEqual("pending", load_profile(root / "target-profile.yaml")["authorization"]["status"])

    def test_a_scope_that_is_really_pending_keeps_the_old_line(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "eng"
        root.mkdir(mode=0o700)
        document = yaml.safe_load(PRACTICE_EXAMPLE.read_text())
        document["authorization"]["status"] = "pending"
        (root / "scope.yaml").write_text(yaml.safe_dump(document))
        (root / "scope.yaml").chmod(0o600)
        result = compile_scope(root, now=NOW)
        self.assertIsNone(result.profile_not_usable)


if __name__ == "__main__":
    unittest.main()
