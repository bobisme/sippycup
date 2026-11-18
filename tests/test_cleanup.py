"""`./bin/sippycup doctor --cleanup`: strict selection, dry run by default, safe removal."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_workbench import cleanup  # noqa: E402

LAUNCHER = ROOT / "bin" / "sippycup"


def make_directory(root: Path, name: str, files: tuple[str, ...] = ("pjsua.log",), age: float = 7200) -> Path:
    path = root / name
    path.mkdir(mode=0o700)
    for file_name in files:
        (path / file_name).write_text("x")
        os.utime(path / file_name, (time.time() - age, time.time() - age))
    os.utime(path, (time.time() - age, time.time() - age))
    return path


class FakeRuntime:
    """Stands in for subprocess.run and records every runtime invocation."""

    def __init__(self, containers=None, images=None, fail_remove: bool = False) -> None:
        self.containers = containers or []
        self.images = images or []
        self.fail_remove = fail_remove
        self.calls: list[list[str]] = []

    def __call__(self, argv, **_kwargs):
        self.calls.append(list(argv))
        verb = argv[1]
        if verb == "ps":
            return SimpleNamespace(returncode=0, stdout=json.dumps(self.containers), stderr="")
        if verb == "images":
            return SimpleNamespace(returncode=0, stdout=json.dumps(self.images), stderr="")
        if self.fail_remove:
            return SimpleNamespace(returncode=1, stdout="", stderr="image is in use")
        return SimpleNamespace(returncode=0, stdout="", stderr="")


class PrivateDirectoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.shm = Path(self.temporary.name) / "shm"
        self.shm.mkdir()
        self.proc = Path(self.temporary.name) / "proc"
        self.proc.mkdir()

    def find(self, **kwargs):
        return cleanup.find_private_directories(shm_root=self.shm, proc_root=self.proc, **kwargs)

    def test_only_exact_names_owned_by_the_user_are_candidates(self) -> None:
        keep = [
            make_directory(self.shm, "sippycup-softphone-ab12cd34"),
            make_directory(self.shm, "sippycup-campaign-softphone-_x9z0aaa", ("canary.wav",)),
        ]
        ignored = [
            "sippycup-softphone-short",
            "sippycup-softphone-AB12CD34",
            "sippycup-softphone-ab12cd34-extra",
            "sippycup-other-ab12cd34",
            "xsippycup-softphone-ab12cd34",
        ]
        for name in ignored:
            make_directory(self.shm, name)
        found = {item.ident: item for item in self.find()}
        self.assertEqual(set(found), {str(path) for path in keep})
        self.assertTrue(all(item.removable for item in found.values()))
        for name in ignored:
            self.assertTrue((self.shm / name).is_dir())

    def test_symlink_and_regular_file_with_a_matching_name_are_never_removable(self) -> None:
        target = make_directory(self.shm, "elsewhere")
        (self.shm / "sippycup-softphone-ab12cd34").symlink_to(target)
        (self.shm / "sippycup-softphone-ab12cd35").write_text("x")
        items = self.find()
        self.assertEqual(len(items), 2)
        self.assertFalse(any(item.removable for item in items))
        removed = cleanup.run_cleanup(
            apply=True, kinds=("shm",), shm_root=self.shm, proc_root=self.proc, runtime=None
        )
        self.assertFalse(any(item.removed for item in removed.items))
        self.assertTrue(target.is_dir() and (target / "pjsua.log").exists())

    def test_other_owner_live_process_and_young_directories_are_kept(self) -> None:
        theirs = make_directory(self.shm, "sippycup-softphone-aaaaaaaa")
        live = make_directory(self.shm, "sippycup-softphone-bbbbbbbb")
        young = make_directory(self.shm, "sippycup-softphone-cccccccc", age=5)
        process = self.proc / "4242"
        process.mkdir()
        (process / "cmdline").write_bytes(b"pjsua\0--config-file\0" + str(live / "pjsua.cfg").encode() + b"\0")
        by_name = {Path(item.ident).name: item for item in self.find(uid=os.getuid() + 1)}
        self.assertEqual(by_name[theirs.name].reason, "not owned by you")
        by_name = {Path(item.ident).name: item for item in self.find()}
        self.assertEqual(by_name[live.name].reason, "a live process references it")
        self.assertIn("--min-age", by_name[young.name].reason)
        self.assertTrue(by_name[theirs.name].removable)
        self.assertFalse(by_name[live.name].removable or by_name[young.name].removable)

    def test_descriptor_and_working_directory_references_count_as_live(self) -> None:
        held = make_directory(self.shm, "sippycup-campaign-softphone-dddddddd", ("canary.wav",))
        process = self.proc / "77"
        (process / "fd").mkdir(parents=True)
        (process / "cmdline").write_bytes(b"python3\0")
        os.symlink(held / "canary.wav", process / "fd" / "5")
        (item,) = self.find()
        self.assertFalse(item.removable)

    def test_dry_run_removes_nothing_and_apply_removes_only_eligible_directories(self) -> None:
        old = make_directory(self.shm, "sippycup-softphone-eeeeeeee", ("pjsua.log", "heard.wav"))
        young = make_directory(self.shm, "sippycup-softphone-ffffffff", age=1)
        bystander = make_directory(self.shm, "unrelated")
        report = cleanup.run_cleanup(
            kinds=("shm",), shm_root=self.shm, proc_root=self.proc, runtime=None
        )
        self.assertFalse(report.apply)
        self.assertTrue(old.is_dir() and young.is_dir() and bystander.is_dir())
        report = cleanup.run_cleanup(
            apply=True, kinds=("shm",), shm_root=self.shm, proc_root=self.proc, runtime=None
        )
        self.assertFalse(old.exists())
        self.assertTrue(young.is_dir() and bystander.is_dir())
        self.assertEqual([item.removed for item in report.items], [True, False])

    def test_removal_refuses_nested_directories_and_foreign_paths(self) -> None:
        nested = make_directory(self.shm, "sippycup-softphone-gggggggg")
        (nested / "inner").mkdir()
        with self.assertRaises(ValueError):
            cleanup.remove_private_directory(nested, shm_root=self.shm)
        self.assertTrue((nested / "inner").is_dir())
        elsewhere = Path(self.temporary.name) / "sippycup-softphone-hhhhhhhh"
        elsewhere.mkdir()
        with self.assertRaises(ValueError):
            cleanup.remove_private_directory(elsewhere, shm_root=self.shm)
        with self.assertRaises(ValueError):
            cleanup.remove_private_directory(self.shm / "work", shm_root=self.shm)
        with self.assertRaises(ValueError):
            cleanup.remove_private_directory(self.shm / "sippycup-softphone-x/../y", shm_root=self.shm)
        self.assertTrue(elsewhere.is_dir())

    def test_a_directory_swapped_for_a_symlink_is_not_followed(self) -> None:
        target = make_directory(self.shm, "target-evidence")
        link = self.shm / "sippycup-softphone-iiiiiiii"
        link.symlink_to(target)
        with self.assertRaises(OSError):
            cleanup.remove_private_directory(link, shm_root=self.shm)
        self.assertTrue((target / "pjsua.log").exists())

    def test_wrong_owner_is_refused_at_removal_time(self) -> None:
        path = make_directory(self.shm, "sippycup-softphone-jjjjjjjj")
        with self.assertRaises(ValueError):
            cleanup.remove_private_directory(path, shm_root=self.shm, uid=os.getuid() + 1)
        self.assertTrue(path.is_dir())


def container(ident: str, image: str, state: str, **extra):
    return {"Id": ident, "Image": image, "State": state, "Names": [f"name-{ident[:4]}"], "Labels": {}, **extra}


class RuntimeLeftoverTests(unittest.TestCase):
    def test_only_stopped_sippycup_containers_are_listed_and_removed_with_a_guarded_rm(self) -> None:
        fake = FakeRuntime(containers=[
            container("a" * 64, "localhost/sippycup:ws-x", "exited"),
            container("b" * 64, "localhost/sippycup-practice:latest", "created"),
            container("c" * 64, "localhost/sippycup:latest", "running"),
            container("d" * 64, "docker.io/library/alpine:3", "exited"),
            container("e" * 64, "example/other:1", "exited", Labels={"dev.sippycup.profile": "practice"}),
            container("f" * 64, "localhost/sippycup:latest", "exited", Id="not-hex"),
        ])
        report = cleanup.run_cleanup(
            apply=True, kinds=("containers",), runtime="/fake/podman", run=fake
        )
        removed = {item.ident for item in report.items if item.removed}
        self.assertEqual(removed, {"a" * 64, "b" * 64, "e" * 64})
        self.assertEqual(
            sorted(call for call in fake.calls if call[1] == "rm"),
            [["/fake/podman", "rm", "--", ident] for ident in ("a" * 64, "b" * 64, "e" * 64)],
        )
        self.assertFalse(any("-f" in call or "--force" in call for call in fake.calls))
        refused = [item for item in report.items if not item.removable]
        self.assertEqual([item.reason for item in refused], ["unexpected identifier"])

    def test_image_filter_limits_containers_to_one_reference(self) -> None:
        fake = FakeRuntime(containers=[
            container("a" * 64, "localhost/sippycup:ws-x", "exited"),
            container("b" * 64, "localhost/sippycup:ws-y", "exited"),
        ])
        report = cleanup.run_cleanup(
            kinds=("containers",), image="localhost/sippycup:ws-x", runtime="/fake/podman", run=fake
        )
        self.assertEqual([item.ident for item in report.items], ["a" * 64])

    def test_only_dangling_labelled_unused_old_images_are_removed(self) -> None:
        now = 2_000_000_000
        labels = {"org.opencontainers.image.title": "sippycup"}
        fake = FakeRuntime(images=[
            {"Id": "1" * 64, "Names": None, "Labels": labels, "Containers": 0, "Created": now - 7200},
            {"Id": "2" * 64, "Names": None, "Labels": labels, "Containers": 1, "Created": now - 7200},
            {"Id": "3" * 64, "Names": None, "Labels": labels, "Containers": 0, "Created": now - 10},
            {"Id": "4" * 64, "Names": None, "Labels": {"io.buildah.version": "1"}, "Containers": 0, "Created": 1},
            {"Id": "5" * 64, "Names": ["localhost/sippycup:latest"], "Labels": labels, "Containers": 0},
            {"Id": "6" * 64, "Names": None, "Labels": {"dev.sippycup.profile": "practice"}, "Containers": 0, "Created": 1},
        ])
        report = cleanup.run_cleanup(
            apply=True, kinds=("images",), runtime="/fake/podman", now=now, run=fake
        )
        removed = {item.ident for item in report.items if item.removed}
        self.assertEqual(removed, {"1" * 64, "6" * 64})
        self.assertEqual(
            sorted(call for call in fake.calls if call[1] == "rmi"),
            [["/fake/podman", "rmi", "--", "1" * 64], ["/fake/podman", "rmi", "--", "6" * 64]],
        )
        reasons = {item.ident[:1]: item.reason for item in report.items if not item.removable}
        self.assertEqual(set(reasons), {"2", "3"})

    def test_a_failed_removal_is_reported_and_marks_the_run_failed(self) -> None:
        fake = FakeRuntime(
            containers=[container("a" * 64, "localhost/sippycup:x", "exited")], fail_remove=True
        )
        report = cleanup.run_cleanup(apply=True, kinds=("containers",), runtime="/fake/podman", run=fake)
        self.assertTrue(report.failed)
        self.assertEqual(report.items[0].error, "image is in use")
        self.assertFalse(report.items[0].removed)

    def test_dry_run_never_calls_a_removal_verb(self) -> None:
        fake = FakeRuntime(containers=[container("a" * 64, "localhost/sippycup:x", "exited")])
        cleanup.run_cleanup(kinds=("containers", "images"), runtime="/fake/podman", run=fake)
        self.assertEqual({call[1] for call in fake.calls}, {"ps", "images"})


class CommandLineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.shm = Path(self.temporary.name) / "shm"
        self.shm.mkdir()
        self.work = Path(self.temporary.name) / "work"
        self.work.mkdir()
        (self.work / "evidence.txt").write_text("keep")
        runtime = Path(self.temporary.name) / "fake-runtime"
        runtime.write_text("#!/bin/sh\necho '[]'\n")
        runtime.chmod(runtime.stat().st_mode | stat.S_IXUSR)
        self.env = {**os.environ, "SIPPYCUP_RUNTIME": str(runtime)}

    def run_cli(self, *arguments: str, env=None):
        return subprocess.run(
            [str(LAUNCHER), *arguments], text=True, capture_output=True, env=env or self.env, check=False
        )

    def test_doctor_cleanup_is_a_dry_run_unless_apply_is_given(self) -> None:
        stale = make_directory(self.shm, "sippycup-softphone-kkkkkkkk")
        listed = self.run_cli("doctor", "--cleanup", "--shm-dir", str(self.shm))
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn("DRY RUN", listed.stdout)
        self.assertIn("would remove", listed.stdout)
        self.assertIn("Network activity: none", listed.stdout)
        self.assertTrue(stale.is_dir())
        applied = self.run_cli("doctor", "--cleanup", "--apply", "--shm-dir", str(self.shm), "--format", "json")
        self.assertEqual(applied.returncode, 0, applied.stderr)
        report = json.loads(applied.stdout)
        self.assertTrue(report["workUntouched"])
        self.assertEqual([item["removed"] for item in report["items"]], [True])
        self.assertFalse(stale.exists())
        self.assertEqual((self.work / "evidence.txt").read_text(), "keep")

    def test_container_options_cannot_be_combined_with_cleanup(self) -> None:
        for option in ("--isolated", "--admin", "--practice"):
            with self.subTest(option=option):
                result = self.run_cli(option, "doctor", "--cleanup")
                self.assertEqual(result.returncode, 2)
                self.assertIn("cannot be combined", result.stderr)

    def test_bad_arguments_exit_two_without_touching_anything(self) -> None:
        stale = make_directory(self.shm, "sippycup-softphone-llllllll")
        for arguments in (("--min-age", "-1"), ("--kind", "work"), ("--shm-dir", "relative")):
            with self.subTest(arguments=arguments):
                result = self.run_cli("doctor", "--cleanup", "--apply", *arguments)
                self.assertEqual(result.returncode, 2)
        self.assertTrue(stale.is_dir())


if __name__ == "__main__":
    unittest.main()
