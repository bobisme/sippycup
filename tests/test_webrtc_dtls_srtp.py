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

from sippycup_webrtc.dtls_srtp import (  # noqa: E402
    MediaSecurityError,
    evaluate,
    validate_observation,
    validate_policy,
)


def load(name: str) -> dict:
    return json.loads((ROOT / "examples" / "webrtc" / name).read_text())


class DTLSSRTPOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load("dtls-srtp-policy.json")
        self.observation = load("dtls-srtp-observation.clean.json")

    def test_clean_trace_passes_without_keys_or_capacity_claim(self) -> None:
        report = evaluate(self.policy, self.observation)
        self.assertEqual("pass", report["status"])
        self.assertFalse(report["networkActivity"])
        self.assertFalse(report["sessionKeysObserved"])
        self.assertIsNone(report["capacityClaim"])

    def test_contract_rejects_unknown_fields_boolean_counters_and_bad_hashes(self) -> None:
        unknown = deepcopy(self.observation)
        unknown["events"][0]["data"]["certificate"] = "forbidden"
        with self.assertRaisesRegex(MediaSecurityError, "unknown fields"):
            validate_observation(unknown, self.policy)
        boolean = deepcopy(self.policy)
        boolean["limits"]["maxPackets"] = True
        with self.assertRaisesRegex(MediaSecurityError, "integer"):
            validate_policy(boolean)
        bad_hash = deepcopy(self.observation)
        bad_hash["events"][0]["data"]["certificateFingerprintHash"] = "raw-value"
        with self.assertRaisesRegex(MediaSecurityError, "SHA-256"):
            validate_observation(bad_hash, self.policy)

    def test_fingerprint_version_cipher_and_role_fail_independently(self) -> None:
        document = deepcopy(self.observation)
        document["events"][0]["data"].update(
            {
                "certificateFingerprintHash": "9" * 64,
                "verified": False,
                "version": "DTLS1.0",
                "cipher": "TLS_RSA_WITH_AES_128_CBC_SHA",
                "role": "server",
            }
        )
        document["events"][1]["data"]["role"] = "server"
        codes = {item["code"] for item in evaluate(self.policy, document)["findings"]}
        self.assertTrue(
            {
                "dtls.fingerprint_mismatch",
                "dtls.fingerprint_unverified",
                "dtls.version_disallowed",
                "dtls.cipher_disallowed",
                "dtls.role_pair_invalid",
                "dtls.peer_observation_mismatch",
            }.issubset(codes)
        )

    def test_downgrade_connection_and_media_are_separate_findings(self) -> None:
        document = deepcopy(self.observation)
        document["events"][2]["data"].update(
            {"outcome": "connected", "reachedMedia": True}
        )
        codes = {item["code"] for item in evaluate(self.policy, document)["findings"]}
        self.assertIn("dtls.downgrade_accepted", codes)
        self.assertIn("dtls.downgrade_reached_media", codes)

    def test_profile_key_separation_and_peer_profile_are_checked(self) -> None:
        document = deepcopy(self.observation)
        document["events"][3]["data"]["profile"] = "SRTP_UNKNOWN"
        document["events"][3]["data"]["rtcpKeyIdHash"] = document["events"][3]["data"][
            "rtpKeyIdHash"
        ]
        document["events"][4]["data"]["profile"] = "SRTP_AES128_CM_SHA1_80"
        codes = {item["code"] for item in evaluate(self.policy, document)["findings"]}
        self.assertTrue(
            {
                "srtp.profile_disallowed",
                "srtp.rtp_rtcp_key_reuse",
                "srtp.peer_profile_mismatch",
            }.issubset(codes)
        )

    def test_replay_auth_sequence_context_and_srtcp_fail_closed(self) -> None:
        document = deepcopy(self.observation)
        packet = document["events"][6]["data"]
        packet.update(
            {
                "sequence": 65535,
                "roc": 0,
                "accepted": True,
                "replay": True,
                "authValid": False,
                "ssrc": 9999,
            }
        )
        rtcp = document["events"][8]["data"]
        rtcp.update(
            {
                "encrypted": False,
                "authValid": False,
                "replay": True,
                "ssrc": 9998,
            }
        )
        codes = {item["code"] for item in evaluate(self.policy, document)["findings"]}
        self.assertTrue(
            {
                "srtp.packet_without_context",
                "srtp.replay_accepted",
                "srtp.invalid_auth_accepted",
                "srtcp.packet_without_context",
                "srtcp.unencrypted",
                "srtcp.replay_accepted",
                "srtcp.invalid_auth_accepted",
            }.issubset(codes)
        )

    def test_two_sided_ice_restart_rekeys_pass_and_one_sided_fails(self) -> None:
        document = deepcopy(self.observation)
        cleanup = document["events"].pop()
        document["events"].append(
            {"timeMs": 9, "type": "ice_restart", "data": {"generation": 1}}
        )
        for side, old_hash, new_hash, ssrc in (
            ("local", "3" * 64, "7" * 64, 1001),
            ("remote", "5" * 64, "8" * 64, 2002),
        ):
            document["events"].append(
                {
                    "timeMs": 10,
                    "type": "rekey",
                    "data": {
                        "side": side,
                        "reason": "ice_restart",
                        "oldEpoch": 0,
                        "newEpoch": 1,
                        "oldKeyIdHash": old_hash,
                        "newKeyIdHash": new_hash,
                    },
                }
            )
            document["events"].append(
                {
                    "timeMs": 11,
                    "type": "srtp_context",
                    "data": {
                        "side": side,
                        "profile": "SRTP_AEAD_AES_128_GCM",
                        "rtpKeyIdHash": new_hash,
                        "rtcpKeyIdHash": ("9" if side == "local" else "a") * 64,
                        "epoch": 1,
                        "ssrc": ssrc,
                    },
                }
            )
        cleanup["timeMs"] = 12
        document["events"].append(cleanup)
        document["events"].sort(key=lambda item: item["timeMs"])
        self.assertEqual("pass", evaluate(self.policy, document)["status"])
        one_sided = deepcopy(document)
        one_sided["events"] = [
            item
            for item in one_sided["events"]
            if not (
                item["type"] in {"rekey", "srtp_context"}
                and item["data"].get("side") == "remote"
                and item["timeMs"] >= 10
            )
        ]
        codes = {item["code"] for item in evaluate(self.policy, one_sided)["findings"]}
        self.assertIn("srtp.incomplete_ice_restart_rekey", codes)

    def test_rekey_reuse_epoch_and_context_binding_fail(self) -> None:
        document = deepcopy(self.observation)
        document["events"].insert(
            -1,
            {
                "timeMs": 8,
                "type": "srtp_context",
                "data": {
                    "side": "local",
                    "profile": "SRTP_AEAD_AES_128_GCM",
                    "rtpKeyIdHash": "3" * 64,
                    "rtcpKeyIdHash": "b" * 64,
                    "epoch": 2,
                    "ssrc": 1001,
                },
            },
        )
        document["events"].insert(
            -1,
            {
                "timeMs": 8,
                "type": "rekey",
                "data": {
                    "side": "remote",
                    "reason": "renegotiation",
                    "oldEpoch": 0,
                    "newEpoch": 1,
                    "oldKeyIdHash": "5" * 64,
                    "newKeyIdHash": "c" * 64,
                },
            },
        )
        document["events"].insert(
            -1,
            {
                "timeMs": 8,
                "type": "rekey",
                "data": {
                    "side": "local",
                    "reason": "renegotiation",
                    "oldEpoch": 0,
                    "newEpoch": 2,
                    "oldKeyIdHash": "3" * 64,
                    "newKeyIdHash": "3" * 64,
                },
            },
        )
        codes = {item["code"] for item in evaluate(self.policy, document)["findings"]}
        self.assertTrue(
            {
                "srtp.rekey_reused_key",
                "srtp.rekey_epoch_invalid",
                "srtp.rekey_context_mismatch",
                "srtp.context_epoch_gap",
                "srtp.key_reused_across_epochs",
            }.issubset(codes)
        )

    def test_missing_evidence_is_incomplete_and_failure_must_close(self) -> None:
        empty = {
            "apiVersion": "sippycup.dev/dtls-srtp-observation/v1",
            "networkActivity": False,
            "events": [],
        }
        report = evaluate(self.policy, empty)
        self.assertEqual("incomplete", report["status"])
        codes = {item["code"] for item in report["unknowns"]}
        self.assertIn("dtls.both_handshakes_not_observed", codes)
        self.assertIn("srtp.packet_evidence_not_observed", codes)
        document = deepcopy(self.observation)
        document["events"].insert(
            -1,
            {
                "timeMs": 8,
                "type": "failure",
                "data": {
                    "stage": "fingerprint",
                    "closure": "continued",
                    "code": "seeded.failure",
                },
            },
        )
        self.assertIn(
            "media.failure_not_closed",
            {item["code"] for item in evaluate(self.policy, document)["findings"]},
        )

    def test_limits_cleanup_and_cli_file_boundary(self) -> None:
        policy = deepcopy(self.policy)
        policy["limits"]["maxPackets"] = 1
        document = deepcopy(self.observation)
        document["events"][-1]["data"] = {"contexts": 1, "sockets": 1}
        codes = {item["code"] for item in evaluate(policy, document)["findings"]}
        self.assertIn("limits.packet_ceiling_exceeded", codes)
        self.assertIn("media.cleanup_incomplete", codes)

        command = [sys.executable, str(ROOT / "bin" / "webrtc-media-security")]
        environment = {"PYTHONPATH": str(ROOT / "lib")}
        clean = subprocess.run(
            command
            + [
                str(ROOT / "examples/webrtc/dtls-srtp-policy.json"),
                str(ROOT / "examples/webrtc/dtls-srtp-observation.clean.json"),
            ],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, clean.returncode, clean.stderr)
        with tempfile.TemporaryDirectory() as root_name:
            link = Path(root_name) / "policy.json"
            link.symlink_to(ROOT / "examples/webrtc/dtls-srtp-policy.json")
            rejected = subprocess.run(
                command
                + [
                    str(link),
                    str(ROOT / "examples/webrtc/dtls-srtp-observation.clean.json"),
                ],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(2, rejected.returncode)
        self.assertIn("non-symlink", rejected.stderr)
