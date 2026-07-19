import hashlib
import json
from dataclasses import replace
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "oracle"))
from test_dialogs import scenario_frames

from sippycup_learn import (
    CanonicalizationError, canonicalize_dialog, generate_pack,
    scan_pack_privacy, validate_pack,
)
from sippycup_oracle.dialogs import reconstruct_dialogs
from sippycup_oracle.records import Known


class LearnExitGate(unittest.TestCase):
    def pipeline(self, root, scenario, **frame_kwargs):
        frames = scenario_frames(scenario, **frame_kwargs)
        model = canonicalize_dialog(
            reconstruct_dialogs(frames), frames, local_networks=("192.0.2.0/24",)
        )
        pack = root / "pack"
        generate_pack(model, pack)
        validation = validate_pack(pack, root / "validation", image_identity="gate-image")
        return frames, model, pack, validation

    def test_golden_supported_fixtures_replay_with_empty_packet_diff(self):
        identities = {}
        for scenario in ("baseline", "digest_challenge", "cancel", "remote_bye", "renegotiation"):
            with self.subTest(scenario), tempfile.TemporaryDirectory() as tmp:
                frames, model, pack, validation = self.pipeline(Path(tmp), scenario)
                self.assertEqual("pass", validation["verdict"])
                self.assertEqual([], validation["semanticDiff"])
                self.assertEqual(
                    model["provenance"]["sourceFrames"],
                    json.loads((pack / "provenance.json").read_text())["sourceFrames"],
                )
                identities[scenario] = hashlib.sha256(
                    b"".join(
                        path.relative_to(pack).as_posix().encode() + b"\0" + path.read_bytes()
                        for path in sorted(pack.rglob("*")) if path.is_file()
                    )
                ).hexdigest()
        self.assertEqual(5, len(set(identities.values())))

    def test_secret_scan_finds_no_captured_credentials_identities_or_addresses(self):
        call_id = "private-call-id@customer.example"
        with tempfile.TemporaryDirectory() as tmp:
            _, _, pack, _ = self.pipeline(
                Path(tmp), "digest_challenge", call_id=call_id,
                caller_address="192.0.2.10", callee_address="198.51.100.20",
            )
            findings = scan_pack_privacy(
                pack,
                forbidden_values=(
                    call_id.encode(), b"192.0.2.10", b"198.51.100.20",
                    b"Digest username=\"alice\", response=\"secret\"",
                    b"sip:alice@customer.example",
                ),
            )
        self.assertEqual([], findings)

    def test_hostile_inputs_emit_no_runnable_pack(self):
        scenarios = []
        truncated = scenario_frames("baseline")[:-2]
        scenarios.append(("truncated", truncated))
        left = scenario_frames("baseline", call_id="a", start=1)
        right = scenario_frames("baseline", call_id="b", start=20)
        scenarios.append(("multiple", left + right))
        complete = scenario_frames("baseline")
        reconstruction = reconstruct_dialogs(complete)
        ambiguous = replace(
            reconstruction,
            transactions=(
                replace(reconstruction.transactions[0], ambiguity=Known(True)),
                *reconstruction.transactions[1:],
            ),
        )
        for name, frames in scenarios:
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                destination = Path(tmp) / "pack"
                with self.assertRaises(CanonicalizationError):
                    model = canonicalize_dialog(
                        reconstruct_dialogs(frames), frames,
                        local_networks=("192.0.2.0/24",),
                    )
                    generate_pack(model, destination)
                self.assertFalse(destination.exists())
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "pack"
            with self.assertRaises(CanonicalizationError):
                model = canonicalize_dialog(
                    ambiguous, complete, local_networks=("192.0.2.0/24",)
                )
                generate_pack(model, destination)
            self.assertFalse(destination.exists())

    def test_every_generated_wait_is_bounded_and_review_is_clear(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, pack, _ = self.pipeline(Path(tmp), "renegotiation")
            root = ET.parse(pack / "scenario.xml").getroot()
            self.assertTrue(all(item.get("timeout") for item in root.findall("recv")))
            self.assertTrue(all(
                item.get("milliseconds", "").isdigit()
                and 1 <= int(item.get("milliseconds")) <= 5000
                for item in root.findall("pause")
            ))
            readme = (pack / "README.md").read_text()
            normalized = " ".join(readme.split())
            for phrase in (
                "REVIEW REQUIRED", "explicitly authorized target",
                "one call", "concurrency one", "field disposition",
            ):
                self.assertIn(phrase, normalized)

    def test_provenance_hashes_trace_every_generated_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, pack, _ = self.pipeline(Path(tmp), "baseline")
            provenance = json.loads((pack / "provenance.json").read_text())
            for name, digest in provenance["generatedFiles"].items():
                self.assertEqual(digest, hashlib.sha256((pack / name).read_bytes()).hexdigest())
            self.assertNotIn("provenance.json", provenance["generatedFiles"])


if __name__ == "__main__":
    unittest.main()
