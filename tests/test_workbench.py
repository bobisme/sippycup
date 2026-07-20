from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_workbench import cli
from sippycup_workbench.doctor import diagnose
from sippycup_workbench.profile import (
    ProfileError,
    default_profile,
    load_profile,
    rehearse,
    write_profile,
)
from sippycup_workbench.triage import TriageError, analyze


class ProfileTests(unittest.TestCase):
    def test_default_is_intentionally_pending(self) -> None:
        result = rehearse(default_profile(name="stage", host="stage.example.invalid"))
        self.assertFalse(result.ready)
        self.assertIn("authorization is pending, not approved", result.errors)
        self.assertIn("at least one literal approved address is required", result.errors)
        self.assertFalse(result.as_dict()["network_activity"])

    def test_approved_bounded_profile_is_ready(self) -> None:
        profile = default_profile(name="stage", host="stage.example.test")
        profile["target"]["approved_addresses"] = ["192.0.2.20"]
        profile["authorization"].update(
            {
                "status": "approved",
                "approval_id": "quad-2026-07-20-one-call",
                "valid_from": "2026-07-20T10:00:00Z",
                "valid_until": "2026-07-20T12:00:00Z",
            }
        )
        result = rehearse(
            profile, now=datetime(2026, 7, 20, 11, 0, tzinfo=timezone.utc)
        )
        self.assertTrue(result.ready, result.errors)
        self.assertEqual(result.facts["maximum_preflight_transactions"], 1)

    def test_expired_authorization_is_blocked(self) -> None:
        profile = default_profile(name="stage", host="192.0.2.20")
        profile["target"]["approved_addresses"] = ["192.0.2.20"]
        profile["authorization"].update(
            {
                "status": "approved",
                "approval_id": "quad-one-call",
                "valid_until": "2026-07-20T10:00:00Z",
            }
        )
        result = rehearse(
            profile, now=datetime(2026, 7, 20, 11, 0, tzinfo=timezone.utc)
        )
        self.assertFalse(result.ready)
        self.assertIn("authorization has expired", result.errors)

    def test_bad_feature_dependency_is_blocked(self) -> None:
        profile = default_profile(name="stage", host="192.0.2.20")
        profile["features"]["dtls_srtp"] = True
        result = rehearse(profile)
        self.assertIn("DTLS-SRTP requires features.srtp", result.errors)

    def test_unknown_fields_and_capture_escape_are_blocked(self) -> None:
        profile = default_profile(name="stage", host="192.0.2.20")
        profile["surprise"] = True
        profile["target"]["surprise"] = True
        profile["capture"]["output"] = "../call.pcap"
        result = rehearse(profile)
        self.assertIn("unknown top-level fields: surprise", result.errors)
        self.assertIn("unknown target fields: surprise", result.errors)
        self.assertIn(
            "capture.output must be a relative work/*.pcap or work/*.pcapng path",
            result.errors,
        )

    def test_write_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "target.yaml"
            profile = default_profile(name="stage", host="stage.example.invalid")
            write_profile(path, profile, force=False)
            self.assertEqual(load_profile(path)["schema_version"], profile["schema_version"])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(ProfileError):
                write_profile(path, profile, force=False)


class DoctorTests(unittest.TestCase):
    def test_doctor_does_not_invoke_network_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            with mock.patch(
                "sippycup_workbench.doctor.subprocess.run"
            ) as run:
                with mock.patch(
                    "sippycup_workbench.doctor.shutil.which",
                    return_value=None,
                ):
                    result = diagnose(root)
        run.assert_not_called()
        self.assertFalse(result["network_activity"])
        self.assertEqual(
            "./bin/sippycup webrtc build",
            result["optional_profiles"]["webrtc"]["install"],
        )


class TriageTests(unittest.TestCase):
    def test_missing_capture_is_rejected(self) -> None:
        with self.assertRaises(TriageError):
            analyze("/definitely/missing/capture.pcap")

    def test_capture_analysis_has_no_network_activity(self) -> None:
        fixture = Path(__file__).parents[1] / "work" / "selftest.pcap"
        if not fixture.exists():
            self.skipTest("selftest capture not present")
        result = analyze(fixture)
        self.assertFalse(result["network_activity"])
        self.assertEqual(result["metadata"]["packets"], 6)
        self.assertEqual(result["protocol_frames"]["sip"], 6)
        self.assertFalse(result["privacy"]["values_disclosed"])


class CliTests(unittest.TestCase):
    def test_one_call_pending_plan_is_blocked_and_offline(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "target.yaml"
            write_profile(
                path,
                default_profile(name="stage", host="stage.example.invalid"),
                force=False,
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = cli.main(["one-call", str(path), "--format", "json"])
        self.assertEqual(status, 1)
        result = json.loads(stdout.getvalue())
        self.assertFalse(result["ready"])
        self.assertFalse(result["network_activity"])
        self.assertTrue(any(step["network_active"] for step in result["steps"]))

    def test_one_call_ready_plan_uses_only_literal_approved_scope(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "target.yaml"
            profile = default_profile(name="stage", host="192.0.2.20")
            profile["target"]["approved_addresses"] = ["192.0.2.20"]
            profile["authorization"].update(
                {
                    "status": "approved",
                    "approval_id": "quad-one-call",
                    "valid_until": "2099-01-01T00:00:00Z",
                }
            )
            write_profile(path, profile, force=False)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = cli.main(["one-call", str(path), "--format", "json"])
        self.assertEqual(status, 0)
        result = json.loads(stdout.getvalue())
        self.assertTrue(result["ready"])
        capture_argv = result["steps"][0]["argv"]
        self.assertIn("192.0.2.20", capture_argv)
        self.assertNotIn("stage.example.invalid", capture_argv)

    def test_explain_is_stable(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = cli.main(["explain", "capture.media_present", "--format", "json"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(stdout.getvalue())["code"], "capture.media_present")


class ContainerRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.resolver = Path(__file__).parents[1] / "bin" / "container-runtime"

    @staticmethod
    def _stub(root: Path, name: str) -> None:
        path = root / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def test_prefers_podman_then_nerdctl_then_docker(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            for name in ("docker", "nerdctl", "podman"):
                self._stub(root, name)
            result = subprocess.run(
                ["/bin/bash", self.resolver],
                env={"PATH": str(root)},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path(result.stdout.strip()).name, "podman")

    def test_explicit_runtime_wins(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            self._stub(root, "docker")
            self._stub(root, "my-runtime")
            result = subprocess.run(
                ["/bin/bash", self.resolver],
                env={
                    "PATH": f"{root}{os.pathsep}/usr/bin{os.pathsep}/bin",
                    "SIPPYCUP_RUNTIME": "my-runtime",
                },
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path(result.stdout.strip()).name, "my-runtime")

    def test_missing_runtime_fails_helpfully(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            result = subprocess.run(
                ["/bin/bash", self.resolver],
                env={"PATH": root_name},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No supported container runtime", result.stderr)


class LauncherRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.launcher = Path(__file__).parents[1] / "bin" / "sippycup"

    def test_doctor_runs_in_selected_container(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            runtime = root / "runtime"
            runtime.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$@\"\n",
                encoding="utf-8",
            )
            runtime.chmod(runtime.stat().st_mode | stat.S_IXUSR)
            result = subprocess.run(
                [self.launcher, "doctor", "--format", "json"],
                env={
                    **os.environ,
                    "SIPPYCUP_RUNTIME": str(runtime),
                    "SIPPYCUP_IMAGE": "example.invalid/sippycup:test",
                },
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = result.stdout.splitlines()
        self.assertIn("run", arguments)
        self.assertIn("example.invalid/sippycup:test", arguments)
        self.assertEqual(arguments[-3:], ["doctor", "--format", "json"])
        self.assertIn("sippycup-workbench", arguments)

    def test_host_doctor_bypasses_container_runtime(self) -> None:
        result = subprocess.run(
            [self.launcher, "doctor", "--host", "--format", "json"],
            env={
                **os.environ,
                "SIPPYCUP_RUNTIME": "/definitely/missing/runtime",
            },
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertIn(result.returncode, (0, 1))
        self.assertEqual(
            json.loads(result.stdout)["schema_version"],
            "sippycup.dev/doctor/v1",
        )


if __name__ == "__main__":
    unittest.main()
