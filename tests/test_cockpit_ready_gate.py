"""The cockpit's go/no-go gate: stage 4 and every engagement LIVE action need a GO from `ready`."""

from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cockpit_support import NOW, compiled_engagement, make_repo, practice_state, write_go  # noqa: E402
from sippycup_cockpit.model import build_model, save_preferences  # noqa: E402
from sippycup_cockpit.render import render_dashboard  # noqa: E402
from sippycup_cockpit.session import Session  # noqa: E402
from test_cockpit_confirm import FakeRunner  # noqa: E402


class ReadyGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = make_repo(Path(self.temporary.name))
        self.runner = FakeRunner()

    def engagement(self, *, go: bool):
        root = compiled_engagement(self.repo, now=NOW, go=go)
        save_preferences(root, {"skipPractice": True})  # the practice stage is recommended, not required
        return root

    def model(self, root, now=NOW):
        return build_model(root, repo=self.repo, now=now, advisor=False, commands=None)

    def session(self, root, now=NOW):
        return Session(self.repo, root, runner=self.runner, clock=lambda: now, environ={}, commands=None,
                       host_has_tshark=True)

    def prepare(self, root, identifier, now=NOW):
        session = self.session(root, now)
        action = next(item for item in session.actions if item["id"] == identifier)
        return session.prepare(action)

    def test_without_a_go_stage_four_is_current_and_ready_is_the_next_command(self) -> None:
        root = self.engagement(go=False)
        model = self.model(root)
        self.assertEqual("rehearse", model["currentStage"])
        rehearse = next(stage for stage in model["stages"] if stage["id"] == "rehearse")
        self.assertEqual([True, True, False], [step["done"] for step in rehearse["steps"]])
        self.assertEqual("./bin/sippycup ready work/eng", model["nextCommand"])
        ready = next(item for item in model["actions"] if item["id"] == "ready")
        self.assertEqual(("local", "[local]"), (ready["network"], ready["label"]))
        plain = render_dashboard(model, now=NOW, all_steps=True)
        self.assertIn("Go/no-go       [  ] not run yet (./bin/sippycup ready work/eng, right before the first "
                      "live packet)", plain)
        self.assertEqual(f"Next: {model['nextCommand']}", plain[-1])

    def test_live_actions_are_refused_without_a_current_go(self) -> None:
        root = self.engagement(go=False)
        for identifier in ("call", "campaign-run") if (root / "plan.json").exists() else ("call",):
            confirmation = self.prepare(root, identifier)
            self.assertIn("no go/no-go check yet; run ./bin/sippycup ready work/eng first", confirmation.refused)
            self.assertIsNone(confirmation.token, "no token prompt is offered")
        write_go(root, now=NOW, verdict="NO-GO")
        confirmation = self.prepare(root, "call")
        self.assertIn("said NO-GO", confirmation.refused)
        self.assertEqual("rehearse", self.model(root)["currentStage"])
        self.assertIn("[!!] NO-GO", "\n".join(render_dashboard(self.model(root), now=NOW)))

    def test_a_go_for_another_profile_does_not_count(self) -> None:
        root = self.engagement(go=False)
        write_go(root, now=NOW, profile_sha256="0" * 64)
        model = self.model(root)
        self.assertEqual("rehearse", model["currentStage"])
        self.assertIn("for another version of the profile", self.prepare(root, "call").refused)

    def test_a_current_go_completes_stage_four_and_the_live_panel_shows_it(self) -> None:
        root = self.engagement(go=True)
        model = self.model(root)
        self.assertEqual("first-call", model["currentStage"])
        confirmation = self.prepare(root, "call")
        self.assertIsNone(confirmation.refused, confirmation.lines)
        self.assertEqual("7Q2X", confirmation.token)
        self.assertTrue(any(line.startswith("Go/no-go: GO at ") for line in confirmation.lines))
        later = self.prepare(root, "call", now=NOW + timedelta(hours=1, minutes=59))
        self.assertIsNone(later.refused)
        self.assertFalse(any("hours old" in line for line in later.lines))

    def test_an_old_go_is_flagged_in_the_live_panel(self) -> None:
        root = compiled_engagement(self.repo, now=NOW, go=False)
        write_go(root, now=NOW - timedelta(hours=13))
        confirmation = self.prepare(root, "call")
        self.assertIsNone(confirmation.refused, confirmation.lines)
        self.assertTrue(any("13 hours old" in line for line in confirmation.lines), confirmation.lines)

    def test_the_practice_call_is_not_gated(self) -> None:
        practice_state(self.repo, now=NOW)
        root = compiled_engagement(self.repo, now=NOW, go=False)
        confirmation = self.prepare(root, "practice-call")
        self.assertIsNone(confirmation.refused, confirmation.lines)


if __name__ == "__main__":
    unittest.main()
