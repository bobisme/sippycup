from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest

from sippycup_workbench.profile import default_profile, write_profile
from sippycup_mcp.catalog import Catalog
from sippycup_mcp.security import (
    BoundedProcessRunner,
    MCPPolicyError,
    WorkRoot,
    redact,
    result,
)
from sippycup_mcp.tools import OfflineTools

ROOT = Path(__file__).parents[1]


class WorkRootTests(unittest.TestCase):
    def test_accepts_regular_relative_file_and_rejects_escape(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            (root / "ok.txt").write_text("ok", encoding="utf-8")
            confined = WorkRoot(root)
            self.assertEqual(confined.resolve("ok.txt", kind="file").name, "ok.txt")
            for path in ("../escape", "/etc/passwd", "bad\\path"):
                with self.subTest(path=path), self.assertRaises(MCPPolicyError):
                    confined.resolve(path, kind="file")

    def test_rejects_symlink_even_when_target_is_inside_root(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            (root / "real").write_text("ok", encoding="utf-8")
            (root / "link").symlink_to("real")
            with self.assertRaises(MCPPolicyError):
                WorkRoot(root).resolve("link", kind="file")


class ResultTests(unittest.TestCase):
    def test_redacts_secret_fields_and_authorization_text(self) -> None:
        value = redact(
            {
                "token": "top-secret",
                "safe": "Authorization: Digest username=x,response=y",
            }
        )
        self.assertEqual(value["token"], "<redacted>")
        self.assertEqual(value["safe"], "Authorization: <redacted>")

    def test_result_contract_is_offline_and_bounded(self) -> None:
        value = result(
            "example",
            started=time.monotonic(),
            data={"value": "x" * (2 * 1024 * 1024)},
        )
        self.assertFalse(value["ok"])
        self.assertFalse(value["networkActivity"])
        self.assertTrue(value["truncated"])
        self.assertEqual(value["errors"][0]["code"], "mcp.result_too_large")


class BoundedRunnerTests(unittest.TestCase):
    def test_timeout_kills_fixed_helper_group(self) -> None:
        runner = BoundedProcessRunner(timeout=1, output_bytes=4096)
        with self.assertRaises(MCPPolicyError):
            runner.run_json(
                ["/usr/bin/python3", "-c", "import time; time.sleep(10)"]
            )

    def test_parses_bounded_json(self) -> None:
        runner = BoundedProcessRunner(timeout=2, output_bytes=4096)
        code, value, error = runner.run_json(
            ["/usr/bin/python3", "-c", "import json; print(json.dumps({'ok': True}))"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(value, {"ok": True})
        self.assertEqual(error, "")


class CatalogTests(unittest.TestCase):
    def test_catalog_is_explicit_and_command_registry_is_network_free(self) -> None:
        catalog = Catalog(ROOT)
        index = json.loads(catalog.index())
        commands = json.loads(catalog.commands())
        self.assertFalse(index["networkActivity"])
        self.assertFalse(commands["networkActivity"])
        self.assertIn("mcp-security", index["resources"]["documents"])
        self.assertIn("webrtc-threat-model", index["resources"]["documents"])
        self.assertIn("webrtc-scenario-v1", index["resources"]["schemas"])
        self.assertIn("webrtc-result-v1", index["resources"]["schemas"])
        self.assertIn("webrtc-peer-self-test-v1", index["resources"]["schemas"])
        self.assertNotIn("sippycup://work", json.dumps(index))
        self.assertTrue(catalog.read_document("mcp-security").startswith("# MCP"))
        self.assertTrue(
            catalog.read_document("webrtc-threat-model").startswith(
                "# WebRTC assessment"
            )
        )
        with self.assertRaises(MCPPolicyError):
            catalog.read_document("../README")


class OfflineToolTests(unittest.TestCase):
    def test_target_rehearsal_returns_structured_block_without_traffic(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            write_profile(
                root / "target.yaml",
                default_profile(name="stage", host="stage.example.invalid"),
                force=False,
            )
            value = OfflineTools(root).rehearse_target("target.yaml")
        self.assertTrue(value["ok"])
        self.assertFalse(value["networkActivity"])
        self.assertFalse(value["data"]["ready"])
        self.assertEqual(value["tool"], "rehearse_target")

    def test_campaign_planner_rejects_dns_and_accepts_literal_target(self) -> None:
        source = (ROOT / "tests/fixtures/campaign/valid.yaml").read_text(
            encoding="utf-8"
        )
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            (root / "dns.yaml").write_text(source, encoding="utf-8")
            (root / "literal.yaml").write_text(
                source.replace("voice.test", "10.20.30.40"),
                encoding="utf-8",
            )
            tools = OfflineTools(root)
            rejected = tools.plan_campaign("dns.yaml")
            accepted = tools.plan_campaign("literal.yaml")
        self.assertFalse(rejected["ok"])
        self.assertIn("requires DNS", rejected["errors"][0]["message"])
        self.assertTrue(accepted["ok"], accepted["errors"])
        self.assertFalse(accepted["data"]["networkActivity"])
        self.assertEqual(
            accepted["data"]["resolvedDestinations"][0]["address"],
            "10.20.30.40",
        )

    def test_envelope_plan_is_read_only_and_offline(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            manifest = root / "envelope.yaml"
            manifest.write_bytes((ROOT / "examples/capacity-envelope.yaml").read_bytes())
            value = OfflineTools(root).plan_envelope("envelope.yaml")
        self.assertTrue(value["ok"], value["errors"])
        self.assertFalse(value["data"]["networkActivity"])
        self.assertEqual(value["data"]["kind"], "EnvelopePlan")

    def test_torture_gate_remains_technical_not_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            value = OfflineTools(root_name).run_torture_exit_gate()
        self.assertTrue(value["ok"], value["errors"])
        self.assertEqual(value["data"]["status"], "pass")
        self.assertFalse(value["data"]["ownerReview"]["authorizationGranted"])

    def test_traversal_returns_policy_error_not_exception(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            value = OfflineTools(root_name).rehearse_target("../target.yaml")
        self.assertFalse(value["ok"])
        self.assertEqual(value["errors"][0]["code"], "mcp.policy_rejected")


if __name__ == "__main__":
    unittest.main()
