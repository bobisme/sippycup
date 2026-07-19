import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "oracle"))
from test_dialogs import scenario_frames

from sippycup_learn import (
    CanonicalizationError, canonicalize_dialog, generate_pack,
)
from sippycup_oracle.dialogs import reconstruct_dialogs
from sippycup_oracle.cli import load_expectations


def model(scenario):
    frames = scenario_frames(scenario, call_id="captured-secret@example.invalid")
    return canonicalize_dialog(
        reconstruct_dialogs(frames), frames, local_networks=("192.0.2.0/24",)
    )


class GenerateTests(unittest.TestCase):
    def generate(self, scenario="baseline", **kwargs):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        destination = Path(temporary.name) / "pack"
        provenance = generate_pack(model(scenario), destination, **kwargs)
        return destination, provenance

    def test_pack_contains_reviewable_complete_artifacts(self):
        pack, provenance = self.generate()
        expected = {
            "scenario.xml", "injection-schema.csv", "injection-template.csv",
            "expectations.yaml", "manifest.yaml", "provenance.json",
            "field-disposition.json", "README.md", "media-assets.json",
            "media", "canonical-model.json",
        }
        self.assertEqual(expected, {path.name for path in pack.iterdir()})
        self.assertTrue(provenance["sourceFrames"])
        for name, digest in provenance["generatedFiles"].items():
            self.assertEqual(digest, hashlib.sha256((pack / name).read_bytes()).hexdigest())
        self.assertEqual(6, len(list((pack / "media").glob("*.pcm*")))
                         + len(list((pack / "media").glob("*.g722"))))

    def test_xml_is_syntactic_finite_and_dynamic(self):
        pack, _ = self.generate("renegotiation")
        root = ET.parse(pack / "scenario.xml").getroot()
        self.assertTrue(root.findall(".//send"))
        self.assertTrue(root.findall(".//recv"))
        self.assertTrue(all(item.get("timeout") for item in root.findall(".//recv")))
        sends = "\n".join(item.text or "" for item in root.findall(".//send"))
        for dynamic in ("[call_id]", "[branch]", "[cseq]", "Content-Length: [len]",
                        "[local_ip]", "[remote_ip]", "[media_ip]", "[media_port]"):
            self.assertIn(dynamic, sends)
        for captured in ("192.0.2.10", "198.51.100.20", "captured-secret"):
            self.assertNotIn(captured, sends)
        expectations = yaml.safe_load((pack / "expectations.yaml").read_text())
        self.assertEqual(["127.0.0.1"], expectations["capture"]["allowed_endpoints"])
        self.assertEqual("call_path", expectations["expectations"][0]["type"])
        loaded, on_unknown, selector = load_expectations(pack / "expectations.yaml")
        self.assertEqual(("PCMU", "PCMA"), loaded.expected_codecs)
        self.assertEqual("inconclusive", on_unknown)
        self.assertIsNone(selector)

    def test_manifest_is_unreviewed_and_cannot_name_captured_peer(self):
        pack, _ = self.generate()
        manifest = yaml.safe_load((pack / "manifest.yaml").read_text())
        self.assertFalse(manifest["review"]["reviewed"])
        self.assertFalse(manifest["review"]["sourcePeerApproved"])
        self.assertEqual("REPLACE_WITH_REVIEWED_TARGET.invalid", manifest["target"]["host"])
        self.assertEqual({"calls": 1, "concurrency": 1, "durationSeconds": 30},
                         manifest["limits"])

    def test_digest_generation_requires_understood_challenge_and_named_references(self):
        pack, _ = self.generate(
            "digest_challenge",
            auth_username_ref="ferivox.test-user",
            auth_secret_ref="ferivox.test-password",
        )
        root = ET.parse(pack / "scenario.xml").getroot()
        sends = "\n".join(item.text or "" for item in root.findall(".//send"))
        self.assertIn("[authentication username=[field0] password=[field1]]", sends)
        ack_sends = [
            item.text or "" for item in root.findall(".//send")
            if (item.text or "").startswith("ACK ")
        ]
        self.assertTrue(ack_sends)
        self.assertTrue(all("[authentication" not in text for text in ack_sends))
        template = (pack / "injection-template.csv").read_text()
        self.assertIn("${secret:ferivox.test-user}", template)
        self.assertNotIn("password=", template)
        self.assertTrue(any(item.get("auth") == "true" for item in root.findall(".//recv")))

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(CanonicalizationError):
                generate_pack(
                    model("baseline"), Path(tmp) / "pack",
                    auth_username_ref="user", auth_secret_ref="password",
                )
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(CanonicalizationError):
                generate_pack(
                    model("digest_challenge"), Path(tmp) / "pack",
                    auth_username_ref="user",
                )

    def test_field_disposition_is_explicit_and_private(self):
        pack, _ = self.generate()
        report = json.loads((pack / "field-disposition.json").read_text())
        self.assertTrue(report["kept"])
        self.assertTrue(report["parameterized"])
        self.assertTrue(report["removed"])
        self.assertIn("Authorization and Proxy-Authorization values", report["removed"])
        all_text = "\n".join(
            path.read_text(errors="replace") for path in pack.iterdir() if path.is_file()
        )
        self.assertNotIn("captured-secret@example.invalid", all_text)

    def test_output_is_deterministic_and_existing_destination_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            left, right = Path(tmp) / "left", Path(tmp) / "right"
            generate_pack(model("baseline"), left)
            generate_pack(model("baseline"), right)
            left_files = {
                path.relative_to(left).as_posix(): path.read_bytes()
                for path in left.rglob("*") if path.is_file()
            }
            right_files = {
                path.relative_to(right).as_posix(): path.read_bytes()
                for path in right.rglob("*") if path.is_file()
            }
            self.assertEqual(left_files, right_files)
            with self.assertRaisesRegex(CanonicalizationError, "must not exist"):
                generate_pack(model("baseline"), left)


if __name__ == "__main__":
    unittest.main()
