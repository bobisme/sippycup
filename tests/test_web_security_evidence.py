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

from sippycup_web_security.contracts import WebSecurityError, compile_plan  # noqa: E402
from sippycup_web_security.evidence import (  # noqa: E402
    evaluate,
    plan_digest,
    validate_observation,
    validate_plan,
)


def load(name: str) -> dict:
    return json.loads((ROOT / "examples/web-security" / name).read_text())


def clean_observation(plan: dict) -> dict:
    results = []
    for sequence, case in enumerate(plan["cases"], 1):
        surface = "admin" if case["check"].startswith("admin.") else "websocket"
        denied = case["expectedOutcome"] != "allowed"
        results.append(
            {
                "sequence": sequence,
                "timeMs": sequence * 100,
                "caseId": case["id"],
                "check": case["check"],
                "surface": surface,
                "observedOutcome": case["expectedOutcome"],
                "responseClass": "4xx" if denied else "2xx",
                "closeCode": 1008 if surface == "websocket" and denied else None,
                "sessionState": "closed" if denied else "authenticated",
                "counters": {
                    "connections": 0,
                    "httpRequests": 0,
                    "wsMessages": 0,
                    "authFailures": 0,
                    "bytes": 0,
                    "durationMs": 100,
                },
            }
        )
    return {
        "apiVersion": "sippycup.dev/web-security-observation/v1",
        "networkActivity": False,
        "planDigest": plan_digest(plan),
        "results": results,
        "totals": {
            "connections": 0,
            "httpRequests": 0,
            "wsMessages": 0,
            "authFailures": 0,
            "bytes": 0,
            "durationMs": len(results) * 100,
        },
        "cleanup": {"openConnections": 0, "liveSessions": 0},
    }


class WebSecurityEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = load("offline-profile.json")
        self.adapter = load("example-adapter.json")
        self.plan = compile_plan(self.profile, self.adapter)
        self.observation = clean_observation(self.plan)

    def test_clean_fixture_passes_without_retaining_sensitive_content(self) -> None:
        report = evaluate(self.plan, self.observation)
        self.assertEqual("pass", report["status"])
        self.assertFalse(report["networkActivity"])
        self.assertFalse(report["secretsRetained"])
        self.assertFalse(report["rawMessagesRetained"])
        self.assertIsNone(report["capacityClaim"])

    def test_unexpected_outcome_and_authenticated_denial_fail_independently(self) -> None:
        document = deepcopy(self.observation)
        result = document["results"][0]
        result["observedOutcome"] = "allowed"
        result["sessionState"] = "authenticated"
        codes = {item["code"] for item in evaluate(self.plan, document)["findings"]}
        self.assertIn("security.unexpected_outcome", codes)
        result["observedOutcome"] = "denied"
        codes = {item["code"] for item in evaluate(self.plan, document)["findings"]}
        self.assertIn("security.denial_left_authenticated_session", codes)

    def test_missing_error_and_unknown_evidence_never_pass(self) -> None:
        missing = deepcopy(self.observation)
        missing["results"].pop()
        missing["totals"]["durationMs"] -= 100
        self.assertEqual("incomplete", evaluate(self.plan, missing)["status"])
        unknown = deepcopy(self.observation)
        unknown["results"][0]["observedOutcome"] = "error"
        report = evaluate(self.plan, unknown)
        self.assertEqual("incomplete", report["status"])
        self.assertEqual("error", report["unknowns"][0]["reason"])

    def test_plan_digest_case_binding_and_totals_fail_closed(self) -> None:
        digest = deepcopy(self.observation)
        digest["planDigest"] = "0" * 64
        with self.assertRaisesRegex(WebSecurityError, "does not bind"):
            evaluate(self.plan, digest)
        binding = deepcopy(self.observation)
        binding["results"][0]["check"] = "admin.csrf"
        self.assertIn(
            "evidence.case_binding_mismatch",
            {item["code"] for item in evaluate(self.plan, binding)["findings"]},
        )
        totals = deepcopy(self.observation)
        totals["totals"]["bytes"] = 1
        with self.assertRaisesRegex(WebSecurityError, "does not match"):
            evaluate(self.plan, totals)

    def test_traffic_ceilings_rate_cleanup_and_blocked_window_are_enforced(self) -> None:
        document = deepcopy(self.observation)
        document["results"][0]["counters"].update(
            {
                "connections": 65,
                "httpRequests": 1001,
                "authFailures": 33,
                "bytes": 1048577,
            }
        )
        for key in ("connections", "httpRequests", "authFailures", "bytes"):
            document["totals"][key] = document["results"][0]["counters"][key]
        document["cleanup"] = {"openConnections": 1, "liveSessions": 1}
        codes = {item["code"] for item in evaluate(self.plan, document)["findings"]}
        self.assertIn("limits.ceiling_exceeded", codes)
        self.assertIn("limits.request_rate_exceeded", codes)
        self.assertIn("cleanup.incomplete", codes)

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
        blocked_plan = compile_plan(
            profile,
            self.adapter,
            now=datetime(2026, 7, 19, 15, 0, tzinfo=timezone.utc),
        )
        blocked = clean_observation(blocked_plan)
        blocked["networkActivity"] = True
        blocked["results"][0]["counters"]["connections"] = 1
        blocked["totals"]["connections"] = 1
        self.assertIn(
            "authorization.traffic_while_blocked",
            {item["code"] for item in evaluate(blocked_plan, blocked)["findings"]},
        )

    def test_unknown_fields_cannot_smuggle_tokens_headers_or_messages(self) -> None:
        for key in ("token", "headers", "rawMessage", "cookie"):
            with self.subTest(key=key):
                document = deepcopy(self.observation)
                document["results"][0][key] = "forbidden"
                with self.assertRaisesRegex(WebSecurityError, "unknown fields"):
                    validate_observation(document)

    def test_plan_rejects_hostname_connect_address(self) -> None:
        plan = deepcopy(self.plan)
        plan["destinations"][0]["connectAddress"] = "admin.example.test"
        with self.assertRaisesRegex(WebSecurityError, "literal IP"):
            validate_plan(plan)

    def test_plan_rejects_relaxed_limit(self) -> None:
        plan = deepcopy(self.plan)
        plan["limits"]["maxConnections"] = 65
        with self.assertRaisesRegex(WebSecurityError, "between 1 and 64"):
            validate_plan(plan)

    def test_network_activity_must_match_counters(self) -> None:
        observation = deepcopy(self.observation)
        observation["results"][0]["counters"]["httpRequests"] = 1
        observation["totals"]["httpRequests"] = 1
        report = evaluate(self.plan, observation)
        self.assertEqual("fail", report["status"])
        self.assertIn(
            "evidence.network_activity_mismatch",
            {item["code"] for item in report["findings"]},
        )

    def test_cli_regular_file_boundary_and_exit_contract(self) -> None:
        command = [sys.executable, str(ROOT / "bin/web-security-evidence")]
        environment = {"PYTHONPATH": str(ROOT / "lib")}
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            plan_path = root / "plan.json"
            observation_path = root / "observation.json"
            plan_path.write_text(json.dumps(self.plan))
            observation_path.write_text(json.dumps(self.observation))
            clean = subprocess.run(
                command + [str(plan_path), str(observation_path)],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, clean.returncode, clean.stderr)
            link = root / "observation-link.json"
            link.symlink_to(observation_path)
            rejected = subprocess.run(
                command + [str(plan_path), str(link)],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(2, rejected.returncode)
        self.assertIn("non-symlink", rejected.stderr)
