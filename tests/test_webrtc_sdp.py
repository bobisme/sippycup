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

from sippycup_webrtc.sdp_oracle import (  # noqa: E402
    SDPOracleError,
    evaluate,
    generate_cases,
    minimize_failure,
    normalize_sdp,
    validate_policy,
    validate_transcript,
)


def load(name: str) -> dict:
    return json.loads((ROOT / "examples" / "webrtc" / name).read_text())


def renumber(transcript: dict) -> None:
    for sequence, revision in enumerate(transcript["revisions"], 1):
        revision["sequence"] = sequence


class SDPOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load("sdp-policy.json")
        self.transcript = load("sdp-transcript.clean.json")

    def test_clean_offer_answer_passes_without_raw_sdp_or_capacity_claim(self) -> None:
        report = evaluate(self.policy, self.transcript)
        self.assertEqual("pass", report["status"])
        self.assertFalse(report["networkActivity"])
        self.assertFalse(report["retainedRawSdp"])
        self.assertIsNone(report["capacityClaim"])
        self.assertEqual(1, report["completedNegotiations"])

    def test_raw_sdp_parser_emits_hash_only_bounded_facts(self) -> None:
        raw = (ROOT / "examples/webrtc/audio-offer.redacted.sdp").read_text()
        revision = normalize_sdp(
            raw,
            actor="local",
            revision_type="offer",
            generation=0,
            sequence=1,
        )
        encoded = json.dumps(revision)
        self.assertEqual(["audio-0"], revision["bundleMids"])
        self.assertEqual("opus", revision["media"][0]["codecs"][0]["name"])
        self.assertNotIn("offline-ufrag", encoded)
        self.assertNotIn("offline-password-placeholder", encoded)
        self.assertNotIn("00:11:22", encoded)
        with self.assertRaisesRegex(SDPOracleError, "line count"):
            normalize_sdp(
                "v=0\n" + "a=x\n" * 5000,
                actor="local",
                revision_type="offer",
                generation=0,
                sequence=1,
            )

    def test_contract_rejects_unknown_fields_duplicates_and_boolean_integers(self) -> None:
        unknown = deepcopy(self.transcript)
        unknown["revisions"][0]["rawSdp"] = "forbidden"
        with self.assertRaisesRegex(SDPOracleError, "unknown fields"):
            validate_transcript(unknown, self.policy)
        duplicate = deepcopy(self.transcript)
        duplicate["revisions"][0]["media"][0]["codecs"].append(
            deepcopy(duplicate["revisions"][0]["media"][0]["codecs"][0])
        )
        with self.assertRaisesRegex(SDPOracleError, "payload types must be unique"):
            validate_transcript(duplicate, self.policy)
        boolean = deepcopy(self.policy)
        boolean["limits"]["maxMSections"] = True
        with self.assertRaisesRegex(SDPOracleError, "integer"):
            validate_policy(boolean)

    def test_bundle_mux_trickle_fingerprint_codec_feedback_and_extmap_are_independent(self) -> None:
        document = deepcopy(self.transcript)
        section = document["revisions"][0]["media"][0]
        document["revisions"][0]["bundleMids"] = []
        section["rtcpMux"] = False
        section["iceOptions"] = []
        section["fingerprint"]["algorithm"] = "sha-1"
        section["protocol"] = "RTP/AVP"
        section["codecs"][0]["rtcpFeedback"] = []
        section["extmaps"][0]["uri"] = "urn:example:unapproved"
        codes = {item["code"] for item in evaluate(self.policy, document)["findings"]}
        self.assertTrue(
            {
                "sdp.bundle_incomplete",
                "sdp.rtcp_mux_required",
                "sdp.trickle_required",
                "sdp.fingerprint_algorithm_disallowed",
                "sdp.protocol_disallowed",
                "sdp.rtcp_feedback_missing",
                "sdp.extmap_disallowed",
            }.issubset(codes)
        )

    def test_answer_cannot_expand_direction_role_bundle_or_codecs(self) -> None:
        document = deepcopy(self.transcript)
        offer = document["revisions"][0]["media"][0]
        answer = document["revisions"][1]["media"][0]
        offer["direction"] = "sendonly"
        answer["direction"] = "sendonly"
        answer["setup"] = "passive"
        self.policy["dtls"]["allowedSetupPairs"] = [
            {"offer": "actpass", "answer": "active"}
        ]
        answer["codecs"][0]["payloadType"] = 112
        document["revisions"][1]["bundleMids"].append("ghost")
        codes = {item["code"] for item in evaluate(self.policy, document)["findings"]}
        self.assertTrue(
            {
                "sdp.bundle_unknown_mid",
                "sdp.answer_bundle_expanded",
                "sdp.direction_incompatible",
                "sdp.dtls_role_invalid",
                "sdp.answer_codec_not_offered",
            }.issubset(codes)
        )

    def test_glare_requires_rollback_but_clean_rollback_retry_passes(self) -> None:
        glare = deepcopy(self.transcript)
        competing = deepcopy(glare["revisions"][0])
        competing["actor"] = "remote"
        glare["revisions"].insert(1, competing)
        renumber(glare)
        codes = {item["code"] for item in evaluate(self.policy, glare)["findings"]}
        self.assertIn("sdp.glare", codes)

        rolled_back = deepcopy(self.transcript)
        rollback = {
            "sequence": 2,
            "type": "rollback",
            "actor": "local",
            "generation": 0,
            "sdpHash": None,
            "bundleMids": [],
            "media": [],
        }
        retry = deepcopy(rolled_back["revisions"][0])
        rolled_back["revisions"] = [
            rolled_back["revisions"][0],
            rollback,
            retry,
            rolled_back["revisions"][1],
        ]
        renumber(rolled_back)
        self.assertEqual("pass", evaluate(self.policy, rolled_back)["status"])

    def test_renegotiation_and_ice_restart_credentials_are_atomic(self) -> None:
        restarted = deepcopy(self.transcript)
        offer = deepcopy(restarted["revisions"][0])
        answer = deepcopy(restarted["revisions"][1])
        offer["generation"] = answer["generation"] = 1
        for revision, ufrag, password in (
            (offer, "a" * 64, "b" * 64),
            (answer, "c" * 64, "d" * 64),
        ):
            revision["media"][0]["iceUfragHash"] = ufrag
            revision["media"][0]["icePwdHash"] = password
        restarted["revisions"].extend([offer, answer])
        renumber(restarted)
        self.assertEqual("pass", evaluate(self.policy, restarted)["status"])

        reused = deepcopy(restarted)
        reused["revisions"][3]["media"][0]["iceUfragHash"] = "6" * 64
        reused["revisions"][3]["media"][0]["icePwdHash"] = "7" * 64
        codes = {item["code"] for item in evaluate(self.policy, reused)["findings"]}
        self.assertIn("sdp.restart_reused_credentials", codes)

        partial = deepcopy(restarted)
        partial["revisions"][3]["media"][0]["iceUfragHash"] = "6" * 64
        codes = {item["code"] for item in evaluate(self.policy, partial)["findings"]}
        self.assertIn("sdp.partial_ice_restart", codes)

    def test_pending_and_empty_transcripts_are_incomplete(self) -> None:
        pending = deepcopy(self.transcript)
        pending["revisions"] = pending["revisions"][:1]
        self.assertEqual("incomplete", evaluate(self.policy, pending)["status"])
        empty = deepcopy(self.transcript)
        empty["revisions"] = []
        report = evaluate(self.policy, empty)
        self.assertEqual("incomplete", report["status"])
        self.assertEqual("sdp.no_revisions", report["unknowns"][0]["code"])

    def test_generator_is_deterministic_bounded_and_pairwise(self) -> None:
        first = generate_cases(self.policy, self.transcript)
        second = generate_cases(self.policy, self.transcript)
        self.assertEqual(first, second)
        self.assertLessEqual(len(first["cases"]), self.policy["limits"]["maxGeneratedCases"])
        self.assertTrue(any(len(item["mutations"]) == 2 for item in first["cases"]))
        self.assertTrue(
            all(
                evaluate(self.policy, item["transcript"])["status"] == "fail"
                for item in first["cases"]
                if len(item["mutations"]) == 1
            )
        )

    def test_minimizer_preserves_requested_failure(self) -> None:
        document = deepcopy(self.transcript)
        document["revisions"][0]["media"][0]["rtcpMux"] = False
        minimized = minimize_failure(self.policy, document, "sdp.rtcp_mux_required")
        codes = {item["code"] for item in minimized["report"]["findings"]}
        self.assertIn("sdp.rtcp_mux_required", codes)
        self.assertLessEqual(
            len(minimized["transcript"]["revisions"]),
            len(document["revisions"]),
        )
        with self.assertRaisesRegex(SDPOracleError, "finding is not present"):
            minimize_failure(self.policy, self.transcript, "sdp.rtcp_mux_required")

    def test_cli_routes_and_input_file_boundary(self) -> None:
        command = [sys.executable, str(ROOT / "bin" / "webrtc-sdp")]
        environment = {"PYTHONPATH": str(ROOT / "lib")}
        clean = subprocess.run(
            command
            + [
                "evaluate",
                str(ROOT / "examples/webrtc/sdp-policy.json"),
                str(ROOT / "examples/webrtc/sdp-transcript.clean.json"),
            ],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, clean.returncode, clean.stderr)
        self.assertEqual("pass", json.loads(clean.stdout)["status"])
        generated = subprocess.run(
            command
            + [
                "generate",
                str(ROOT / "examples/webrtc/sdp-policy.json"),
                str(ROOT / "examples/webrtc/sdp-transcript.clean.json"),
            ],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, generated.returncode, generated.stderr)
        normalized = subprocess.run(
            command
            + [
                "normalize",
                str(ROOT / "examples/webrtc/audio-offer.redacted.sdp"),
                "--actor",
                "local",
                "--type",
                "offer",
            ],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, normalized.returncode, normalized.stderr)
        self.assertNotIn("offline-password-placeholder", normalized.stdout)
        with tempfile.TemporaryDirectory() as root_name:
            link = Path(root_name) / "transcript.json"
            link.symlink_to(ROOT / "examples/webrtc/sdp-transcript.clean.json")
            rejected = subprocess.run(
                command
                + [
                    "evaluate",
                    str(ROOT / "examples/webrtc/sdp-policy.json"),
                    str(link),
                ],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(2, rejected.returncode)
        self.assertIn("non-symlink", rejected.stderr)
