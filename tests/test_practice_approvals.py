"""Practice approvals survive a restart of the practice target (owner report seam).

`practice-target up` issues a new LOCAL-PRACTICE-ONLY window every time and
overwrites work/practice/target-profile.yaml. Runs placed under an earlier
window used to show `outside-approval-window` in `summary`. `up` now keeps an
immutable dated copy of every approval, and `summary` checks a run whose
recorded profile equals one of those copies against that copy. These tests
also prove the change does not widen the check for anything else.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))

import yaml  # noqa: E402

from sippycup import practice  # noqa: E402
from sippycup.campaign import operator_path  # noqa: E402
from sippycup_workbench import summary_practice  # noqa: E402
from sippycup_workbench.summary_model import Options, build_report  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "engagement-report" / "practice"
GENERATED = "2026-11-18T04:00:00Z"
UDP_CALLS = (
    "20261118T025420.201700Z-sippycup-local-practice-c956ec1d",
    "20261118T025439.548206Z-sippycup-local-practice-6fe5010f",
    "20261118T025443.708506Z-sippycup-local-practice-02c17f09",
)
TLS_CALL = "20261118T025453.149898Z-sippycup-local-practice-tls-228c57af"


def make_project(root: Path) -> Path:
    project = root / "project"
    project.mkdir()
    (project / "examples").symlink_to(ROOT / "examples")
    (project / "media").symlink_to(ROOT / "media")
    (project / "work").mkdir()
    return project


class ArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.project = make_project(Path(self.temporary.name))
        self.state = practice.state_dir(self.project)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def prepare(self, when: datetime) -> None:
        practice.prepare(self.project, address="127.0.0.2", container="c", image="i", now=when)

    def test_every_up_keeps_its_approval_and_down_keeps_the_archive(self) -> None:
        first = datetime(2026, 11, 18, 9, 0, tzinfo=timezone.utc)
        self.prepare(first)
        current = (self.state / "target-profile.yaml").read_bytes()
        self.prepare(first + timedelta(hours=1))
        archive = sorted(path.name for path in (self.state / "approvals").iterdir())
        names = ("target-profile-proxy-tls.yaml", "target-profile-proxy.yaml",
                 "target-profile-tls.yaml", "target-profile.yaml")
        self.assertEqual(archive, [
            f"{stamp}-{name}" for stamp in ("20261118T090000Z", "20261118T100000Z") for name in names
        ])
        kept = self.state / "approvals" / "20261118T090000Z-target-profile.yaml"
        self.assertEqual(kept.read_bytes(), current)
        self.assertEqual(0o600, kept.stat().st_mode & 0o777)
        practice.remove_secrets(self.project)
        self.assertEqual(8, len(list((self.state / "approvals").iterdir())))
        text = "".join(path.read_text() for path in (self.state / "approvals").iterdir())
        self.assertNotIn("password", text.lower())

    def test_archiving_the_same_approval_again_writes_nothing(self) -> None:
        started = datetime(2026, 11, 18, 9, 0, tzinfo=timezone.utc)
        self.prepare(started)
        self.assertEqual([], practice.archive_approvals(self.state, started))
        self.assertEqual(4, len(list((self.state / "approvals").iterdir())))

    def test_only_loopback_practice_profiles_are_practice_approvals(self) -> None:
        document = yaml.safe_load((FIXTURE / "target-profile.yaml").read_text())
        self.assertTrue(summary_practice.is_practice_approval(document))
        for change in (
            lambda d: d["authorization"].update(approval_id="OWNER-1"),
            lambda d: d["target"].update(host="192.0.2.10"),
            lambda d: d["target"].update(approved_addresses=["127.0.0.2", "192.0.2.10"]),
            lambda d: d["target"].update(host="127.0.0.1", approved_addresses=["127.0.0.1"]),
            lambda d: d.update(schema_version="other"),
        ):
            altered = json.loads(json.dumps(document))
            change(altered)
            self.assertFalse(summary_practice.is_practice_approval(altered), altered)


class OwnerReportAcrossRestartTests(unittest.TestCase):
    """The fixture engagement holds real practice runs from one `up`."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.work = Path(self.temporary.name) / "work"
        self.root = self.work / "eng"
        shutil.copytree(FIXTURE, self.root)
        self.archive = self.work / "practice" / "approvals"
        # A later `up` re-rendered the profiles with a new window; the
        # engagement copies now carry that window (the reported seam).
        for name in ("target-profile.yaml", "target-profile-tls.yaml"):
            path = self.root / name
            self.original = getattr(self, "original", {})
            self.original[name] = path.read_text()
            path.write_text(path.read_text().replace("2026-11-18T02:53:06Z", "2026-11-18T09:00:00Z")
                            .replace("2026-11-18T06:54:06Z", "2026-11-18T13:00:00Z"))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def report(self) -> dict:
        model, _ = build_report(self.root, Options(generated_at=GENERATED))
        return model

    def window_exceptions(self, model: dict) -> set[str]:
        return {item["run"] for item in model["integrityExceptions"] if item["code"] == "outside-approval-window"}

    def archive_original(self) -> None:
        self.archive.mkdir(parents=True)
        for name, text in self.original.items():
            (self.archive / f"20261118T025406Z-{name}").write_text(text)

    def test_without_the_archive_runs_before_the_restart_are_outside_the_window(self) -> None:
        model = self.report()
        self.assertTrue(set(UDP_CALLS) <= self.window_exceptions(model))

    def test_with_the_archive_each_run_is_checked_against_the_approval_it_used(self) -> None:
        self.archive_original()
        model = self.report()
        self.assertEqual(set(), self.window_exceptions(model) & set(UDP_CALLS + (TLS_CALL,)))
        runs = {run["id"]: run for run in model["runs"]}
        for name in UDP_CALLS:
            self.assertEqual("practice-approval/20261118T025406Z-target-profile.yaml",
                             runs[name]["practiceApproval"])
        self.assertEqual("practice-approval/20261118T025406Z-target-profile-tls.yaml",
                         runs[TLS_CALL]["practiceApproval"])
        kinds = [source["kind"] for source in model["authorization"]["sources"]]
        self.assertIn("practice-target-profile", kinds)
        self.assertEqual("practice-runs", model["limitations"][0]["code"])
        # Practice runs are listed but not counted as assessment traffic.
        owner = [run for run in model["runs"] if not run.get("practiceApproval")]
        self.assertEqual({"campaign"}, {run["kind"] for run in owner})
        self.assertEqual(len([run for run in owner if run["sent"].get("calls") is not None]),
                         model["totals"]["calls"]["runsRecorded"])

    def test_a_run_whose_recorded_profile_was_edited_is_not_matched(self) -> None:
        self.archive_original()
        path = self.root / "calls" / UDP_CALLS[0] / "profile.json"
        recorded = json.loads(path.read_text())
        recorded["authorization"]["valid_until"] = "2099-01-01T00:00:00Z"
        path.write_text(json.dumps(recorded))
        model = self.report()
        self.assertIn(UDP_CALLS[0], self.window_exceptions(model))
        self.assertNotIn("practiceApproval", {run["id"]: run for run in model["runs"]}[UDP_CALLS[0]])

    def test_a_forged_non_loopback_archive_entry_authorizes_nothing(self) -> None:
        self.archive.mkdir(parents=True)
        forged = yaml.safe_load(self.original["target-profile.yaml"])
        forged["target"]["approved_addresses"] = ["127.0.0.2", "192.0.2.10"]
        (self.archive / "forged.yaml").write_text(yaml.safe_dump(forged))
        for name in UDP_CALLS:
            path = self.root / "calls" / name / "profile.json"
            path.write_text(json.dumps(forged))
        model = self.report()
        self.assertTrue(set(UDP_CALLS) <= self.window_exceptions(model))

    def test_practice_windows_never_cover_the_engagements_own_runs(self) -> None:
        # The engagement's own profile approves 127.0.0.2 later (new window);
        # an archived practice window that covers the run time must not
        # excuse a run that did not use that practice approval.
        self.archive_original()
        for name in UDP_CALLS:
            path = self.root / "calls" / name / "profile.json"
            recorded = json.loads(path.read_text())
            recorded["name"] = "owner-engagement"
            path.write_text(json.dumps(recorded))
        model = self.report()
        self.assertTrue(set(UDP_CALLS) <= self.window_exceptions(model))


class CampaignPathTests(unittest.TestCase):
    def test_container_run_directories_are_printed_as_host_paths(self) -> None:
        self.assertEqual("work/eng/runs/R1", operator_path("/work/eng/runs/R1"))
        self.assertEqual("work/eng/runs/R1", operator_path(Path("work/eng/runs/R1")))
        self.assertEqual("/workspace/x", operator_path("/workspace/x"))
        self.assertEqual("/tmp/x", operator_path("/tmp/x"))


if __name__ == "__main__":
    unittest.main()
