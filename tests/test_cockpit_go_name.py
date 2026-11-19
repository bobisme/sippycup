"""Wave 8 finding 15: `go` with a mistyped engagement name must not look like a fresh engagement."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cockpit_support import make_engagement, make_repo  # noqa: E402

from sippycup_cockpit import cli  # noqa: E402


class GoNameTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        # cli.main changes into the repo; go back before the directory is removed,
        # or every later test in the same process starts in a deleted directory.
        self.addCleanup(os.chdir, os.getcwd())
        self.repo = make_repo(Path(self.temporary.name))
        make_engagement(self.repo, "rehearsal-1")

    def go(self, name: str) -> tuple[int, str]:
        out = io.StringIO()
        code = cli.main([f"{self.repo}/work/{name}", "--plain", "--no-runtime", "--repo", str(self.repo)],
                        stdin=io.StringIO(""), stdout=out)
        return code, out.getvalue()

    def test_typo_next_to_an_existing_engagement_is_refused_and_names_it(self) -> None:
        code, text = self.go("rehersal-1")
        self.assertEqual(code, 2)
        self.assertIn("does not exist. Nothing was created.", text)
        self.assertIn("rehearsal-1", text)
        self.assertNotIn("Stages", text)
        self.assertFalse((self.repo / "work" / "rehersal-1").exists())

    def test_a_new_name_with_no_lookalike_still_shows_the_fresh_dashboard(self) -> None:
        code, text = self.go("brand-new")
        self.assertEqual(code, 0)
        self.assertIn("The engagement directory does not exist yet.", text)

    def test_the_real_name_works(self) -> None:
        code, text = self.go("rehearsal-1")
        self.assertEqual(code, 0)
        self.assertIn("Stages", text)


if __name__ == "__main__":
    unittest.main()
