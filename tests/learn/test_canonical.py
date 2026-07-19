import json
from dataclasses import replace
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "oracle"))
from test_dialogs import scenario_frames

from sippycup_learn import CanonicalizationError, canonicalize_dialog
from sippycup_oracle.dialogs import Reconstruction, reconstruct_dialogs
from sippycup_oracle.records import Known


class CanonicalTests(unittest.TestCase):
    def canonical(self, scenario, *, call_id="secret-call@example.invalid"):
        frames = scenario_frames(scenario, call_id=call_id)
        return canonicalize_dialog(
            reconstruct_dialogs(frames), frames, local_networks=("192.0.2.0/24",)
        )

    def test_supported_dialog_shapes_are_stable(self):
        expected = {
            "baseline": "local", "digest_challenge": "local", "cancel": "none",
            "remote_bye": "remote", "renegotiation": "local",
        }
        for scenario, teardown in expected.items():
            with self.subTest(scenario):
                first, second = self.canonical(scenario), self.canonical(scenario)
                self.assertEqual(first, second)
                self.assertEqual(teardown, first["dialog"]["teardownInitiator"])
                self.assertTrue(first["provenance"]["sourceFrames"])

    def test_sensitive_fields_become_typed_placeholders(self):
        model = self.canonical("baseline")
        transaction = model["transactions"][0]
        for field, kind in (("cseq", "cseq"), ("branch", "branch")):
            self.assertEqual(kind, transaction[field]["type"])
        self.assertEqual("address", transaction["flow"]["sourceAddress"]["type"])
        self.assertEqual("port", transaction["flow"]["sourcePort"]["type"])
        self.assertEqual("length", transaction["requestLength"]["type"])
        self.assertEqual("contact", model["dialog"]["localContact"]["type"])
        self.assertIsInstance(transaction["timingWindowMs"]["earliest"], int)
        self.assertEqual("media-port", model["sdpRevisions"][0]["media"][0]["port"]["type"])

    def test_raw_identifiers_authorization_and_identities_never_serialize(self):
        raw = "private-call-id@example.invalid"
        encoded = json.dumps(self.canonical("digest_challenge", call_id=raw), sort_keys=True)
        for secret in (raw, "192.0.2.10", "198.51.100.20", '"a"', '"b"',
                       "Authorization", "Proxy-Authorization"):
            self.assertNotIn(secret, encoded)

    def test_incomplete_and_multiple_dialogs_fail_with_diagnostics(self):
        incomplete_frames = scenario_frames("baseline")[:-2]
        with self.assertRaises(CanonicalizationError) as caught:
            canonicalize_dialog(
                reconstruct_dialogs(incomplete_frames), incomplete_frames,
                local_networks=("192.0.2.0/24",),
            )
        self.assertEqual("incomplete", caught.exception.code)

        left = scenario_frames("baseline", call_id="one", start=1)
        right = scenario_frames("baseline", call_id="two", start=20)
        with self.assertRaises(CanonicalizationError) as caught:
            canonicalize_dialog(
                reconstruct_dialogs(left + right), left + right,
                local_networks=("192.0.2.0/24",),
            )
        self.assertEqual("ambiguous-fork", caught.exception.code)
        self.assertTrue(caught.exception.frames)

    def test_ambiguous_and_encrypted_dialogs_fail_closed(self):
        frames = scenario_frames("baseline")
        reconstructed = reconstruct_dialogs(frames)
        ambiguous = Reconstruction(
            (replace(reconstructed.transactions[0], ambiguity=Known(True)),
             *reconstructed.transactions[1:]),
            reconstructed.dialogs, reconstructed.orphan_frames,
        )
        with self.assertRaises(CanonicalizationError) as caught:
            canonicalize_dialog(ambiguous, frames, local_networks=("192.0.2.0/24",))
        self.assertEqual("ambiguous", caught.exception.code)
        encrypted = (replace(frames[0], protocols=("ip", "udp", "srtp")), *frames[1:])
        with self.assertRaises(CanonicalizationError) as caught:
            canonicalize_dialog(
                reconstruct_dialogs(frames), encrypted, local_networks=("192.0.2.0/24",)
            )
        self.assertEqual("encrypted", caught.exception.code)

    def test_invalid_or_empty_local_scope_fails(self):
        frames = scenario_frames("baseline")
        reconstruction = reconstruct_dialogs(frames)
        for scope in ((), ("not-a-network",)):
            with self.subTest(scope), self.assertRaises(CanonicalizationError) as caught:
                canonicalize_dialog(reconstruction, frames, local_networks=scope)
            self.assertEqual("scope", caught.exception.code)


if __name__ == "__main__":
    unittest.main()
