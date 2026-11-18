"""Matrix-ready practice profiles (bn-3lq): rendered by `up`, separate from the one-call ones."""

from __future__ import annotations

import os
from unittest import mock

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))

import yaml  # noqa: E402

from sippycup import practice  # noqa: E402
from sippycup_workbench import summary_practice  # noqa: E402
from sippycup_workbench.matrix import MatrixOptions, build_plan  # noqa: E402
from sippycup_workbench.profile import load_profile, rehearse  # noqa: E402


def make_project(root: Path) -> Path:
    project = root / "project"
    project.mkdir()
    (project / "examples").symlink_to(ROOT / "examples")
    (project / "media").symlink_to(ROOT / "media")
    (project / "work").mkdir()
    return project


class PracticeMatrixProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.project = make_project(Path(self.temporary.name))
        self.now = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
        self.facts = practice.prepare(self.project, address="127.0.0.2", container="c", image="i", now=self.now)
        self.state = self.project / "work" / "practice"
        # The TLS profiles name work/practice/ca.crt; resolve it inside this
        # temporary project, not the checkout's git-ignored work/ tree.
        (self.state / "ca.crt").write_bytes(
            (ROOT / "tests" / "fixtures" / "tls" / "test-ca.crt").read_bytes()
        )
        patcher = mock.patch.dict(os.environ, {"SIPPYCUP_WORK_ROOT": str(self.project / "work")})
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_one_call_profiles_stay_one_call_and_matrix_ones_differ_in_four_things(self) -> None:
        for one, matrix in practice.MATRIX_PROFILES:
            with self.subTest(profile=one):
                single = yaml.safe_load((self.state / one).read_text())
                grid = yaml.safe_load((self.state / matrix).read_text())
                self.assertEqual(single["limits"]["max_calls"], 1)
                self.assertEqual(grid["limits"]["max_calls"], practice.MATRIX_MAX_CALLS)
                self.assertEqual(grid["limits"]["max_concurrency"], 1)
                self.assertTrue(grid["features"]["srtp"])
                self.assertEqual(grid["name"], single["name"] + "-matrix")
                for key in ("target", "authorization"):
                    self.assertEqual(grid[key], single[key])
                self.assertNotEqual(grid["capture"]["output"], single["capture"]["output"])
                self.assertTrue(rehearse(load_profile(self.state / matrix), now=self.now + timedelta(minutes=5)).ready)

    def test_matrix_profiles_are_archived_and_count_as_practice_approvals(self) -> None:
        archived = {path.name.split("Z-", 1)[1] for path in (self.state / "approvals").iterdir()}
        for _one, matrix in practice.MATRIX_PROFILES:
            self.assertIn(matrix, archived)
            self.assertTrue(summary_practice.is_practice_approval(yaml.safe_load((self.state / matrix).read_text())))

    def test_the_documented_grid_plans_through_direct_and_proxy_pairs(self) -> None:
        for udp, tls in (
            ("target-profile-matrix.yaml", "target-profile-matrix-tls.yaml"),
            ("target-profile-matrix-proxy.yaml", "target-profile-matrix-proxy-tls.yaml"),
        ):
            options = MatrixOptions(
                profiles=(self.state / udp, self.state / tls), destination="echo",
                codecs=("PCMU", "PCMA", "G722"), srtp=("off", "mandatory"), max_calls=12,
            )
            plan = build_plan(options, now=self.now + timedelta(minutes=5))
            self.assertEqual(plan["blockingErrors"], [])
            self.assertEqual(plan["totalCalls"], 12)

    def test_one_call_profiles_still_refuse_the_grid(self) -> None:
        options = MatrixOptions(
            profiles=(self.state / "target-profile.yaml", self.state / "target-profile-tls.yaml"),
            destination="echo", codecs=("PCMU", "PCMA"), srtp=("off",), max_calls=12,
        )
        plan = build_plan(options, now=self.now + timedelta(minutes=5))
        self.assertTrue(any("more than its limits.max_calls 1" in item for item in plan["blockingErrors"]))

    def test_info_prints_the_exact_commands_and_no_secret(self) -> None:
        human = practice.render_facts_human(self.facts)
        for label in ("direct", "proxy"):
            plan, run = self.facts["matrix"]["commands"][label]
            self.assertIn(plan, human)
            self.assertIn(run, human)
            self.assertTrue(plan.startswith("./bin/sippycup matrix plan work/practice/target-profile-matrix"))
        password = (self.state / "account.password").read_text().strip()
        self.assertNotIn(password, human)

    def test_rehearse_explains_a_multi_call_profile_without_alarm(self) -> None:
        result = rehearse(load_profile(self.state / "target-profile-matrix.yaml"), now=self.now + timedelta(minutes=5))
        (warning,) = result.warnings
        self.assertIn("matrix", warning)
        self.assertNotIn("not a one-call profile", warning)
        single = rehearse(load_profile(self.state / "target-profile.yaml"), now=self.now + timedelta(minutes=5))
        self.assertEqual(single.warnings, ())


if __name__ == "__main__":
    unittest.main()
