"""Wave 8 polish: scope compile never crashes, and the practice scope example works.

Offline only: nothing here opens a socket or starts a container.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))

from test_scope import DELETE, NOW, ROOT, ScopeTestCase, complete_scope, mutate  # noqa: E402

from sippycup_workbench.profile import load_profile, rehearse  # noqa: E402
from sippycup_workbench.scope import inspect  # noqa: E402
from sippycup_workbench.scope_derive import compile_scope  # noqa: E402

PRACTICE_EXAMPLE = ROOT / "examples" / "scope" / "practice-scope.yaml"

# A key that is missing (or an entry that is not a mapping) must be reported
# by `scope check` and by `scope compile` alike, never as a traceback.
BROKEN = [
    ("destinations.0.expect", DELETE),
    ("destinations.0.user", DELETE),
    ("destinations.0.name", DELETE),
    ("destinations.0", "echo"),
    ("destinations", "echo"),
    ("targets.0.name", DELETE),
    ("targets.0.address", DELETE),
    ("targets.0.transport", DELETE),
    ("targets.0.port", DELETE),
    ("targets.0", "edge"),
    ("targets", DELETE),
    ("targets", "edge"),
    ("media.networks", DELETE),
    ("media.codecs", DELETE),
    ("media.symmetric_rtp", DELETE),
    ("media", DELETE),
    ("client.source_addresses", DELETE),
    ("limits", DELETE),
    ("authorization", DELETE),
    ("account", DELETE),
    ("signaling", DELETE),
    ("test_scope", DELETE),
]


class CompileNeverCrashesTests(ScopeTestCase):
    def test_compile_reports_what_check_reports_and_never_raises(self) -> None:
        for path, value in BROKEN:
            with self.subTest(path=path, value=value):
                document = mutate(complete_scope(), path, value)
                self.write_scope(document)
                check = inspect(self.root / "scope.yaml", now=NOW)
                self.assertFalse(check.ok, "the mutation must be an error for check")
                result = compile_scope(self.root, now=NOW)
                self.assertNotEqual(result.exit_code, 0)
                reported = {item.code for item in check.errors}
                compiled = {item.code for item in result.report.errors}
                self.assertEqual(reported, compiled)

    def test_cli_compile_with_missing_expect_exits_one_with_the_check_message(self) -> None:
        self.write_scope(mutate(complete_scope(), "destinations.0.expect", DELETE))
        code, out, err = self.run_main("scope", "compile", str(self.root))
        self.assertEqual(code, 1, err)
        self.assertNotIn("Traceback", err)
        self.assertIn("scope.missing", out + err)
        self.assertIn("destinations[0].expect", out + err)


class CredentialRefFormatTests(ScopeTestCase):
    def test_error_states_the_format_and_an_example(self) -> None:
        for bad in ("PRACTICE_PASSWORD", "practice_password", "practice.password"):
            with self.subTest(bad=bad):
                self.write_scope(mutate(complete_scope(), "account.credential_ref", bad))
                report = inspect(self.root / "scope.yaml", now=NOW)
                message = next(i.message for i in report.errors if i.field == "account.credential_ref")
                self.assertIn("lowercase letters, digits and '-'", message)
                self.assertIn("practice-password", message)

    def test_template_comment_states_the_format(self) -> None:
        from sippycup_workbench.scope import default_scope

        line = next(x for x in default_scope("x").splitlines() if x.startswith("  credential_ref:"))
        self.assertIn('lowercase letters, digits and "-"', line)


class PracticeExampleTests(ScopeTestCase):
    def example_text(self, *, in_window: bool) -> str:
        text = PRACTICE_EXAMPLE.read_text()
        if in_window:
            text = text.replace("2026-01-01T00:00:00Z", "2026-11-20T11:00:00Z")
            text = text.replace("2026-01-01T04:00:00Z", "2026-11-20T15:00:00Z")
        return text

    def test_shipped_example_stops_only_on_the_window(self) -> None:
        self.write_scope(self.example_text(in_window=False))
        report = inspect(self.root / "scope.yaml", now=NOW)
        self.assertEqual({item.code for item in report.errors}, {"scope.window_expired"})

    def test_example_with_a_current_window_passes_check_and_compiles(self) -> None:
        self.write_scope(self.example_text(in_window=True))
        report = inspect(self.root / "scope.yaml", now=NOW)
        self.assertEqual([item.as_dict() for item in report.errors], [])
        result = compile_scope(self.root, now=NOW)
        self.assertEqual(result.exit_code, 0, result.as_dict())
        profile = load_profile(self.root / "target-profile.yaml")
        self.assertEqual(profile["target"]["host"], "127.0.0.2")
        self.assertEqual(profile["target"]["approved_destinations"], ["echo", "dtmf"])
        self.assertTrue(rehearse(profile, now=NOW).ready)
        self.assertTrue((self.root / "campaign.yaml").is_file())

    def test_example_credential_ref_has_the_documented_format(self) -> None:
        document = yaml.safe_load(PRACTICE_EXAMPLE.read_text())
        self.assertEqual(document["account"]["credential_ref"], "practice-password")


if __name__ == "__main__":
    unittest.main()
