from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_webrtc.contracts import (  # noqa: E402
    RESULT_VERSION,
    SCENARIO_VERSION,
    ContractError,
    validate_result,
    validate_scenario,
)


def _load(name: str) -> dict:
    return json.loads((ROOT / "examples" / "webrtc" / name).read_text())


class WebRTCContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scenario = _load("offline-scenario.json")
        self.capabilities = self.scenario["adapter"]["requiredCapabilities"]
        self.result = _load("offline-result.json")

    def test_published_schemas_are_strict_and_versioned(self) -> None:
        scenario_schema = json.loads(
            (ROOT / "schemas" / "webrtc-scenario-v1.schema.json").read_text()
        )
        result_schema = json.loads(
            (ROOT / "schemas" / "webrtc-result-v1.schema.json").read_text()
        )
        self.assertFalse(scenario_schema["additionalProperties"])
        self.assertFalse(result_schema["additionalProperties"])
        self.assertEqual(
            SCENARIO_VERSION,
            scenario_schema["properties"]["apiVersion"]["const"],
        )
        self.assertEqual(
            RESULT_VERSION,
            result_schema["properties"]["apiVersion"]["const"],
        )
        signaling_schema = json.loads(
            (ROOT / "schemas" / "wss-signaling-self-test-v1.schema.json").read_text()
        )
        self.assertFalse(signaling_schema["additionalProperties"])
        self.assertEqual(
            "sippycup.dev/wss-signaling-self-test/v1",
            signaling_schema["properties"]["apiVersion"]["const"],
        )
        self.assertFalse(
            signaling_schema["properties"]["arbitraryMessagesEnabled"]["const"]
        )
        relay_schema = json.loads(
            (ROOT / "schemas" / "webrtc-relay-self-test-v1.schema.json").read_text()
        )
        self.assertFalse(relay_schema["additionalProperties"])
        self.assertEqual(
            "sippycup.dev/webrtc-relay-self-test/v1",
            relay_schema["properties"]["apiVersion"]["const"],
        )

    def test_offline_fixtures_validate_without_optional_runtime(self) -> None:
        self.assertIs(self.scenario, validate_scenario(self.scenario, self.capabilities))
        self.assertIs(self.result, validate_result(self.result))

    def test_adapter_capability_mismatch_fails_closed(self) -> None:
        with self.assertRaisesRegex(ContractError, "missing: ice-restart"):
            validate_scenario(
                self.scenario,
                set(self.capabilities) - {"ice-restart"},
            )

    def test_unknown_scenario_fields_fail_closed(self) -> None:
        document = deepcopy(self.scenario)
        document["arbitraryRequest"] = {"url": "https://127.0.0.1/"}
        with self.assertRaisesRegex(ContractError, "unknown fields"):
            validate_scenario(document, self.capabilities)

    def test_offline_and_local_lab_destinations_are_confined(self) -> None:
        offline = deepcopy(self.scenario)
        offline["destinations"][0]["address"] = "10.0.0.1"
        with self.assertRaisesRegex(ContractError, "loopback-only"):
            validate_scenario(offline, self.capabilities)

        local = deepcopy(self.scenario)
        local["executionClass"] = "local_lab"
        local["destinations"][0]["address"] = "8.8.8.8"
        with self.assertRaisesRegex(ContractError, "public address"):
            validate_scenario(local, self.capabilities)

    def test_hostnames_never_count_as_frozen_destinations(self) -> None:
        document = deepcopy(self.scenario)
        document["destinations"][0]["address"] = "voice.example.test"
        with self.assertRaisesRegex(ContractError, "literal IP"):
            validate_scenario(document, self.capabilities)

    def test_approved_target_requires_window_and_reference(self) -> None:
        document = deepcopy(self.scenario)
        document["executionClass"] = "approved_target"
        with self.assertRaisesRegex(ContractError, "required=true"):
            validate_scenario(document, self.capabilities)

    def test_inline_credentials_and_secret_values_are_rejected(self) -> None:
        inline = deepcopy(self.scenario)
        inline["credentialRefs"] = ["inline://not-a-real-value"]
        with self.assertRaisesRegex(ContractError, "forbidden inline"):
            validate_scenario(inline, self.capabilities)

        secret = deepcopy(self.result)
        secret["events"][0]["data"]["ice"] = "a=ice-pwd:do-not-store-this"
        with self.assertRaisesRegex(ContractError, "secret material"):
            validate_result(secret)

    def test_concurrency_cannot_exceed_call_ceiling(self) -> None:
        document = deepcopy(self.scenario)
        document["limits"]["maxConcurrency"] = 2
        with self.assertRaisesRegex(ContractError, "cannot exceed maxCalls"):
            validate_scenario(document, self.capabilities)

    def test_result_summary_must_match_assertions(self) -> None:
        document = deepcopy(self.result)
        document["summary"]["passed"] = 2
        with self.assertRaisesRegex(ContractError, "do not add up"):
            validate_result(document)

    def test_unknown_assertion_requires_typed_reason(self) -> None:
        document = deepcopy(self.result)
        document["status"] = "incomplete"
        document["assertions"][0]["verdict"] = "unknown"
        document["assertions"][0]["unknownReason"] = None
        document["summary"].update(
            {"passed": 0, "unknown": 1}
        )
        with self.assertRaisesRegex(ContractError, "required and unsupported"):
            validate_result(document)

    def test_pass_cannot_hide_unknown_or_failed_assertions(self) -> None:
        document = deepcopy(self.result)
        document["assertions"][0]["verdict"] = "unknown"
        document["assertions"][0]["unknownReason"] = "not_observed"
        document["summary"].update({"passed": 0, "unknown": 1})
        with self.assertRaisesRegex(ContractError, "pass status"):
            validate_result(document)

    def test_assertions_cannot_reference_missing_evidence(self) -> None:
        document = deepcopy(self.result)
        document["assertions"][0]["evidenceRefs"] = ["not-present"]
        with self.assertRaisesRegex(ContractError, "unknown evidence"):
            validate_result(document)

    def test_event_sequences_are_strictly_increasing(self) -> None:
        document = deepcopy(self.result)
        document["events"][1]["sequence"] = 0
        with self.assertRaisesRegex(ContractError, "strictly increasing"):
            validate_result(document)


if __name__ == "__main__":
    unittest.main()
