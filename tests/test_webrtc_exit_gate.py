from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_webrtc.exit_gate import ExitGateError, evaluate  # noqa: E402


PEER_IDS = [
    "loopback-candidate-confinement",
    "offer-answer-connected",
    "dtls-srtp-pcmu-audio",
    "ice-restart",
    "rtcp-reader-active",
    "graceful-cleanup",
]
SIGNALING_IDS = [
    "tls-validation",
    "origin-enforcement",
    "authentication-required",
    "session-expiry",
    "message-authorization",
    "malformed-state-transition",
    "replay-first-use",
    "replay-rejection",
    "size-limit",
    "rate-limit",
    "clean-reconnect-first",
    "clean-reconnect-second",
]


def peer(version: str, scope: str, relay: bool = False) -> dict:
    identifiers = list(PEER_IDS)
    if relay:
        identifiers[0] = "turn-relay-candidate-confinement"
    return {
        "apiVersion": version,
        "status": "pass",
        "networkActivity": True,
        "networkScope": scope,
        "checks": [{"id": identifier, "passed": True} for identifier in identifiers],
        "events": [],
        "limits": {
            "deadlineSeconds": 20,
            "packets": 50,
            "payloadBytes": 160,
            "portMin": 42000,
            "portMax": 42199,
        },
    }


def signaling(status: str = "pass") -> dict:
    return {
        "apiVersion": "sippycup.dev/wss-signaling-self-test/v1",
        "status": status,
        "networkActivity": True,
        "networkScope": "loopback",
        "checks": [
            {
                "id": identifier,
                "passed": status == "pass" or identifier != "origin-enforcement",
            }
            for identifier in SIGNALING_IDS
        ],
        "openConnections": 0,
        "arbitraryMessagesEnabled": False,
    }


class WebRTCExitGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.direct = peer(
            "sippycup.dev/webrtc-peer-self-test/v1",
            "loopback",
        )
        self.relay = peer(
            "sippycup.dev/webrtc-relay-self-test/v1",
            "loopback-turn",
            relay=True,
        )
        self.signaling = signaling()
        self.seeded = signaling("fail")
        self.recovery = signaling()
        self.digests = {
            name: str(index) * 64
            for index, name in enumerate(
                ("direct", "relay", "signaling", "seeded", "recovery"),
                1,
            )
        }

    def run_gate(self, **changes) -> dict:
        values = {
            "direct": self.direct,
            "relay": self.relay,
            "signaling": self.signaling,
            "seeded": self.seeded,
            "recovery": self.recovery,
            "digests": self.digests,
            "cancellation_observed": True,
        }
        values.update(changes)
        return evaluate(**values)

    def test_clean_gate_passes_without_authorization_or_capacity_claim(self) -> None:
        report = self.run_gate()
        self.assertEqual("pass", report["status"])
        self.assertFalse(report["authorizationGranted"])
        self.assertIsNone(report["capacityClaim"])
        self.assertTrue(report["seededFailure"]["recoveryPassed"])
        schema = json.loads(
            (ROOT / "schemas" / "webrtc-exit-gate-v1.schema.json").read_text()
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            "sippycup.dev/webrtc-exit-gate/v1",
            schema["properties"]["apiVersion"]["const"],
        )

    def test_missing_relay_failure_or_cancellation_fails_closed(self) -> None:
        relay = deepcopy(self.relay)
        relay["checks"][0]["passed"] = False
        with self.assertRaisesRegex(ExitGateError, "incomplete or failed"):
            self.run_gate(relay=relay)
        seeded = signaling()
        with self.assertRaisesRegex(ExitGateError, "was not detected"):
            self.run_gate(seeded=seeded)
        with self.assertRaisesRegex(ExitGateError, "cancellation"):
            self.run_gate(cancellation_observed=False)

    def test_ceiling_arbitrary_message_secret_and_address_tampering_fail(self) -> None:
        direct = deepcopy(self.direct)
        direct["limits"]["packets"] = 51
        with self.assertRaisesRegex(ExitGateError, "hard ceilings"):
            self.run_gate(direct=direct)
        signaling_report = deepcopy(self.signaling)
        signaling_report["arbitraryMessagesEnabled"] = True
        with self.assertRaisesRegex(ExitGateError, "arbitrary messages"):
            self.run_gate(signaling=signaling_report)
        for key, value in (("token", "secret"), ("detail", "127.0.0.1")):
            with self.subTest(key=key):
                direct = deepcopy(self.direct)
                direct["checks"][0][key] = value
                with self.assertRaises(ExitGateError):
                    self.run_gate(direct=direct)
