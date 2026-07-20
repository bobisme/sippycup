from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_web_security.contracts import (  # noqa: E402
    WebSecurityError,
    compile_plan,
    validate_adapter,
    validate_profile,
)


def load(name: str) -> dict:
    return json.loads((ROOT / "examples/web-security" / name).read_text())


class WebSecurityContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = load("offline-profile.json")
        self.adapter = load("example-adapter.json")

    def approved_profile(self) -> dict:
        profile = deepcopy(self.profile)
        profile["executionClass"] = "approved_target"
        profile["authorization"] = {
            "required": True,
            "reference": "quad-approval-1",
            "notBefore": "2026-07-19T16:00:00Z",
            "notAfter": "2026-07-19T17:00:00Z",
            "surfaces": ["admin", "websocket"],
        }
        profile["destinations"][0]["connectAddress"] = "192.0.2.20"
        profile["destinations"][1]["connectAddress"] = "192.0.2.21"
        return profile

    def test_offline_plan_is_bounded_reviewable_and_network_free(self) -> None:
        plan = compile_plan(self.profile, self.adapter)
        self.assertFalse(plan["networkActivity"])
        self.assertFalse(plan["arbitraryRequestsAvailable"])
        self.assertEqual("not-required", plan["authorization"]["state"])
        self.assertEqual(9, len(plan["cases"]))
        self.assertLessEqual(len(plan["cases"]), plan["limits"]["maxCases"])
        viewer = next(
            item for item in plan["cases"] if item["id"] == "viewer-write-denied"
        )
        self.assertEqual("viewer-account", viewer["credentialRef"])
        encoded = json.dumps(plan)
        self.assertNotIn("SIPPYCUP_VIEWER_CREDENTIAL", encoded)
        self.assertNotIn("sourceRef", encoded)
        self.assertNotIn('"path"', encoded)
        self.assertNotIn('"method"', encoded)
        self.assertNotIn('"payload"', encoded)

    def test_literal_connect_address_is_distinct_from_tls_name(self) -> None:
        hostname = deepcopy(self.profile)
        hostname["destinations"][0]["connectAddress"] = "admin.example.test"
        with self.assertRaisesRegex(WebSecurityError, "literal IP"):
            validate_profile(hostname)
        public = deepcopy(self.profile)
        public["destinations"][0]["connectAddress"] = "192.0.2.20"
        with self.assertRaisesRegex(WebSecurityError, "loopback-only"):
            validate_profile(public)
        bad_name = deepcopy(self.profile)
        bad_name["destinations"][0]["tlsServerName"] = "https://admin.example.test/"
        with self.assertRaisesRegex(WebSecurityError, "DNS name"):
            validate_profile(bad_name)

    def test_admin_and_websocket_authorization_are_independent(self) -> None:
        profile = self.approved_profile()
        profile["authorization"]["surfaces"] = ["websocket"]
        with self.assertRaisesRegex(WebSecurityError, "independently authorized"):
            validate_profile(profile)
        profile["checks"] = [
            item for item in profile["checks"] if item.startswith("websocket.")
        ]
        plan = compile_plan(
            profile,
            self.adapter,
            now=datetime(2026, 7, 19, 16, 30, tzinfo=timezone.utc),
        )
        self.assertEqual("ready", plan["authorization"]["state"])
        self.assertEqual(["websocket"], plan["authorization"]["surfaces"])

    def test_target_window_is_short_lived_and_fails_closed(self) -> None:
        profile = self.approved_profile()
        before = compile_plan(
            profile,
            self.adapter,
            now=datetime(2026, 7, 19, 15, 59, tzinfo=timezone.utc),
        )
        expired = compile_plan(
            profile,
            self.adapter,
            now=datetime(2026, 7, 19, 17, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(
            ["authorization-window-not-started"],
            before["authorization"]["blockers"],
        )
        self.assertEqual(
            ["authorization-window-expired"],
            expired["authorization"]["blockers"],
        )
        too_long = self.approved_profile()
        too_long["authorization"]["notAfter"] = "2026-07-21T17:00:00Z"
        with self.assertRaisesRegex(WebSecurityError, "24 hours"):
            validate_profile(too_long)

    def test_credentials_are_external_unique_role_references(self) -> None:
        inline = deepcopy(self.profile)
        inline["credentialRefs"][0]["sourceRef"] = "env://bad-value"
        with self.assertRaisesRegex(WebSecurityError, "provider reference"):
            validate_profile(inline)
        duplicate = deepcopy(self.profile)
        duplicate["credentialRefs"][1]["role"] = "viewer"
        with self.assertRaisesRegex(WebSecurityError, "exactly one credential"):
            validate_profile(duplicate)

    def test_adapter_is_service_specific_without_request_primitives(self) -> None:
        arbitrary = deepcopy(self.adapter)
        arbitrary["routes"][0]["path"] = "/anything"
        with self.assertRaisesRegex(WebSecurityError, "unknown fields"):
            validate_adapter(arbitrary)
        wrong_surface = deepcopy(self.adapter)
        wrong_surface["routes"][0].update(
            {"surface": "websocket", "operation": "admin-write"}
        )
        with self.assertRaisesRegex(WebSecurityError, "incompatible"):
            validate_adapter(wrong_surface)
        mismatched = deepcopy(self.profile)
        mismatched["adapter"]["id"] = "another-service"
        with self.assertRaisesRegex(WebSecurityError, "do not match"):
            compile_plan(mismatched, self.adapter)

    def test_checks_need_routes_roles_origins_and_hard_ceilings(self) -> None:
        missing_role = deepcopy(self.profile)
        missing_role["credentialRefs"] = [
            item for item in missing_role["credentialRefs"] if item["role"] != "viewer"
        ]
        with self.assertRaisesRegex(WebSecurityError, "no applicable adapter cases"):
            compile_plan(missing_role, self.adapter)
        no_foreign_origin = deepcopy(self.profile)
        no_foreign_origin["origins"] = no_foreign_origin["origins"][:1]
        with self.assertRaisesRegex(WebSecurityError, "allowed and disallowed"):
            validate_profile(no_foreign_origin)
        boolean = deepcopy(self.profile)
        boolean["limits"]["maxConnections"] = True
        with self.assertRaisesRegex(WebSecurityError, "integer"):
            validate_profile(boolean)

    def test_cli_rejects_symlinks_and_reports_blocked_window(self) -> None:
        command = [sys.executable, str(ROOT / "bin/web-security-profile")]
        environment = {"PYTHONPATH": str(ROOT / "lib")}
        clean = subprocess.run(
            command
            + [
                str(ROOT / "examples/web-security/offline-profile.json"),
                str(ROOT / "examples/web-security/example-adapter.json"),
            ],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, clean.returncode, clean.stderr)
        self.assertFalse(json.loads(clean.stdout)["networkActivity"])
        with tempfile.TemporaryDirectory() as root_name:
            link = Path(root_name) / "profile.json"
            link.symlink_to(ROOT / "examples/web-security/offline-profile.json")
            rejected = subprocess.run(
                command
                + [
                    str(link),
                    str(ROOT / "examples/web-security/example-adapter.json"),
                ],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(2, rejected.returncode)
        self.assertIn("non-symlink", rejected.stderr)
