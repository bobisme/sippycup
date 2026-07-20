from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_webrtc.contracts import ContractError  # noqa: E402
from sippycup_webrtc.validation_cli import validate_documents  # noqa: E402


def load(name: str) -> dict:
    return json.loads((ROOT / "examples" / "webrtc" / name).read_text())


def capabilities() -> dict:
    supported = [
        "audio",
        "wss-signaling",
        "trickle-ice",
        "ice-restart",
        "stun",
        "dtls-srtp",
        "rtcp",
    ]
    return {
        "apiVersion": "sippycup.dev/webrtc-adapter-capabilities/v1",
        "kind": "WebRTCAdapterCapabilities",
        "implementation": "pion-webrtc",
        "implementationVersion": "v4.2.13",
        "buildCommit": "0" * 40,
        "sourceDigest": "0" * 64,
        "goVersion": "go1.25.0",
        "capabilities": supported,
        "verifiedCapabilities": [
            value for value in supported if value != "stun"
        ],
        "networkActivity": False,
    }


class WebRTCValidationCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scenario = load("offline-scenario.json")
        self.result = load("offline-result.json")

    def test_scenario_and_result_bind_without_network_or_authorization(self) -> None:
        report = validate_documents(
            self.scenario,
            capability_document=capabilities(),
            result_document=self.result,
        )
        self.assertTrue(report["valid"])
        self.assertFalse(report["networkActivity"])
        self.assertFalse(report["authorizationGranted"])
        self.assertEqual("validated", report["adapter"]["capabilityBinding"])

    def test_result_cannot_swap_scenario(self) -> None:
        result = deepcopy(self.result)
        result["scenarioId"] = "different-scenario"
        with self.assertRaisesRegex(ContractError, "does not bind"):
            validate_documents(self.scenario, result_document=result)

    def test_missing_adapter_capability_fails_closed(self) -> None:
        document = capabilities()
        document["capabilities"].remove("ice-restart")
        document["verifiedCapabilities"].remove("ice-restart")
        with self.assertRaisesRegex(ContractError, "missing: ice-restart"):
            validate_documents(self.scenario, capability_document=document)

    def test_capability_report_is_strict_and_network_free(self) -> None:
        document = capabilities()
        document["networkActivity"] = True
        with self.assertRaisesRegex(ContractError, "network-free"):
            validate_documents(self.scenario, capability_document=document)
        document = capabilities()
        document["token"] = "forbidden"
        with self.assertRaisesRegex(ContractError, "unknown fields"):
            validate_documents(self.scenario, capability_document=document)

    def test_cli_rejects_symlink_and_supports_unified_entrypoint(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            scenario_path = root / "scenario.json"
            result_path = root / "result.json"
            scenario_path.write_text(json.dumps(self.scenario))
            result_path.write_text(json.dumps(self.result))
            command = [
                str(ROOT / "bin" / "sippycup"),
                "webrtc",
                "validate",
                str(scenario_path),
                "--result",
                str(result_path),
            ]
            valid = subprocess.run(
                command,
                text=True,
                capture_output=True,
                check=False,
            )
            link = root / "scenario-link.json"
            link.symlink_to(scenario_path)
            rejected = subprocess.run(
                command[:3] + [str(link)],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(0, valid.returncode, valid.stderr)
        self.assertFalse(json.loads(valid.stdout)["networkActivity"])
        self.assertEqual(2, rejected.returncode)
        self.assertIn("non-symlink", rejected.stderr)
