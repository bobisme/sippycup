"""Offline tests for the optional local practice target helpers and launcher."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))

import yaml  # noqa: E402

from sippycup import practice  # noqa: E402
from sippycup.campaign import compile_plan  # noqa: E402
from sippycup_workbench.profile import load_profile, rehearse  # noqa: E402

LAUNCHER = ROOT / "bin" / "sippycup"


def make_project(root: Path) -> Path:
    project = root / "project"
    project.mkdir()
    (project / "examples").symlink_to(ROOT / "examples")
    (project / "media").symlink_to(ROOT / "media")
    (project / "work").mkdir()
    return project


class AddressTests(unittest.TestCase):
    def test_loopback_addresses_other_than_the_caller_are_accepted(self) -> None:
        for address in ("127.0.0.2", "127.0.0.9", "127.1.2.3"):
            with self.subTest(address=address):
                self.assertEqual(practice.validate_address(address), address)

    def test_routable_and_ambiguous_addresses_are_refused(self) -> None:
        for address in (
            "10.0.0.5",
            "192.168.1.20",
            "192.0.2.1",
            "8.8.8.8",
            "0.0.0.0",
            "::1",
            "127.0.0.1",
            "127.0.0.0",
            "127.255.255.255",
            "localhost",
            "sippycup-practice",
            "",
        ):
            with self.subTest(address=address):
                with self.assertRaises(practice.PracticeError):
                    practice.validate_address(address)


class PrepareTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.project = make_project(Path(self.temporary.name))
        self.now = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
        self.facts = practice.prepare(
            self.project,
            address="127.0.0.2",
            container="sippycup-practice",
            image="localhost/sippycup-practice:latest",
            now=self.now,
        )
        self.state = self.project / "work" / "practice"
        self.password = (self.state / "account.password").read_text(encoding="utf-8").strip()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_secret_files_are_private_and_password_is_never_in_facts(self) -> None:
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        self.assertRegex(self.password, r"^[A-Za-z0-9_-]{32}$")
        for name in practice.SECRET_FILES:
            with self.subTest(name=name):
                self.assertEqual(stat.S_IMODE((self.state / name).stat().st_mode), 0o600)
        for name in ("uac.cfg", "uac-tls.cfg", "uac-srtp.cfg"):
            self.assertIn(f"--password {self.password}", (self.state / name).read_text())
        rendered_facts = json.dumps(self.facts)
        connection = (self.state / "connection.json").read_text(encoding="utf-8")
        human = practice.render_facts_human(self.facts)
        for text in (rendered_facts, connection, human):
            self.assertNotIn(self.password, text)
        self.assertIn("work/practice/account.password", human)
        self.assertIn("work/practice/ca.crt", human)

    def test_every_up_generates_a_new_password(self) -> None:
        practice.prepare(
            self.project,
            address="127.0.0.2",
            container="sippycup-practice",
            image="localhost/sippycup-practice:latest",
        )
        second = (self.state / "account.password").read_text(encoding="utf-8").strip()
        self.assertNotEqual(self.password, second)

    def test_generated_profile_is_ready_only_inside_its_short_window(self) -> None:
        profile = load_profile(self.state / "target-profile.yaml")
        self.assertEqual(profile["authorization"]["approval_id"], "LOCAL-PRACTICE-ONLY")
        self.assertEqual(profile["target"]["approved_addresses"], ["127.0.0.2"])
        ready = rehearse(profile, now=self.now + timedelta(minutes=5))
        self.assertTrue(ready.ready, ready.errors)
        expired = rehearse(profile, now=self.now + practice.VALIDITY)
        self.assertFalse(expired.ready)
        self.assertIn("authorization has expired", expired.errors)

    def test_checked_in_profile_template_is_not_an_approval(self) -> None:
        template = load_profile(ROOT / "examples" / "practice" / "target-profile.template.yaml")
        self.assertFalse(rehearse(template).ready)

    def test_campaign_plans_only_the_loopback_practice_address(self) -> None:
        path = self.state / "campaign.yaml"
        manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
        plan = compile_plan(manifest, "0" * 64, resolver=lambda host: [])
        self.assertEqual(
            {item["address"] for item in plan["resolvedDestinations"]}, {"127.0.0.2"}
        )
        self.assertEqual({step["type"] for step in plan["steps"]}, {"options"})
        self.assertEqual(manifest["authorization"]["networks"], ["127.0.0.2/32"])

    def test_expectations_and_softphone_configs_are_fully_rendered(self) -> None:
        expectations = yaml.safe_load((self.state / "expectations.yaml").read_text())
        self.assertEqual(
            expectations["capture"]["allowed_endpoints"], ["127.0.0.1", "127.0.0.2"]
        )
        tls = (self.state / "uac-tls.cfg").read_text()
        self.assertIn("--registrar sip:127.0.0.2:5061;transport=tls", tls)
        self.assertIn("--tls-verify-server", tls)
        self.assertIn("--tls-ca-file /work/practice/ca.crt", tls)
        self.assertIn("--use-srtp 2", (self.state / "uac-srtp.cfg").read_text())
        for name in ("uac.cfg", "uac-tls.cfg", "uac-srtp.cfg", "campaign.yaml"):
            self.assertNotRegex((self.state / name).read_text(), r"@[A-Z_]+@")

    def test_caller_audio_is_the_decoded_canary(self) -> None:
        activity = practice.wav_activity(self.state / "phrase.wav")
        self.assertEqual(activity["seconds"], 1.0)
        self.assertGreater(activity["active_fraction"], 0.3)

    def test_remove_secrets_keeps_public_evidence(self) -> None:
        removed = practice.remove_secrets(self.project)
        self.assertIn("work/practice/account.password", removed)
        for name in practice.SECRET_FILES:
            self.assertFalse((self.state / name).exists())
        self.assertTrue((self.state / "target-profile.yaml").exists())

    def test_symlinked_state_directory_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as other_name:
            project = make_project(Path(other_name))
            (project / "work" / "practice").symlink_to(other_name)
            with self.assertRaises(practice.PracticeError):
                practice.prepare(
                    project, address="127.0.0.2", container="c", image="i"
                )


class LauncherTests(unittest.TestCase):
    def run_practice(self, *arguments: str, runtime: str = "/definitely/missing/runtime"):
        return subprocess.run(
            [LAUNCHER, "practice-target", *arguments],
            cwd=ROOT,
            env={**os.environ, "SIPPYCUP_RUNTIME": runtime},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )

    def test_help_is_network_free(self) -> None:
        for arguments in ((), ("help",), ("--help",)):
            with self.subTest(arguments=arguments):
                result = self.run_practice(*arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                for subcommand in ("build", "up", "down", "status", "info"):
                    self.assertIn(subcommand, result.stdout)
                self.assertIn("Network activity: none", result.stdout)

    def test_up_refuses_a_routable_bind_before_any_side_effect(self) -> None:
        for address in ("192.0.2.10", "10.1.2.3", "0.0.0.0", "127.0.0.1"):
            with self.subTest(address=address):
                result = self.run_practice("up", "--address", address)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("No supported container runtime", result.stderr)
                self.assertIn("practice-target:", result.stderr)

    def test_unknown_subcommand_and_arguments_fail(self) -> None:
        self.assertEqual(self.run_practice("explode").returncode, 2)
        self.assertEqual(self.run_practice("down", "now").returncode, 2)
        self.assertEqual(self.run_practice("info", "--format", "xml").returncode, 2)


if __name__ == "__main__":
    unittest.main()
