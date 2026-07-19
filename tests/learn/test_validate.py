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

from sippycup_learn import canonicalize_dialog, generate_pack, validate_pack
from sippycup_oracle.dialogs import reconstruct_dialogs


def make_pack(root, scenario):
    frames = scenario_frames(scenario)
    model = canonicalize_dialog(
        reconstruct_dialogs(frames), frames, local_networks=("192.0.2.0/24",)
    )
    pack = root / f"pack-{scenario}"
    generate_pack(model, pack)
    return pack


class ValidateTests(unittest.TestCase):
    def test_every_supported_pack_passes_isolated_reference_and_records_versions(self):
        for scenario in ("baseline", "digest_challenge", "cancel", "remote_bye", "renegotiation"):
            with self.subTest(scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                pack = make_pack(root, scenario)
                before = (pack / "manifest.yaml").read_bytes()
                result = validate_pack(
                    pack, root / "validation",
                    image_identity="sha256:test-image",
                    tool_versions={"sipp": "3.7.7", "tshark": "4.x"},
                )
                self.assertEqual("pass", result["verdict"], result["semanticDiff"])
                self.assertEqual(0, result["networkIsolation"]["externalTraffic"])
                self.assertEqual("AF_UNIX", result["networkIsolation"]["family"])
                self.assertEqual("sha256:test-image", result["versions"]["image"])
                self.assertEqual(before, (pack / "manifest.yaml").read_bytes())
                self.assertFalse(result["authorizationChanged"])
                capture = (root / "validation" / "validation-capture.jsonl").read_text()
                self.assertTrue(capture)

    def mutate_xml(self, pack, mutation):
        path = pack / "scenario.xml"
        root = ET.parse(path).getroot()
        mutation(root)
        ET.indent(root, space="  ")
        path.write_bytes(ET.tostring(root, encoding="utf-8", xml_declaration=True))

    def validate_mutation(self, mutation):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        pack = make_pack(root, "baseline")
        mutation(pack)
        return validate_pack(pack, root / "validation", image_identity="test")

    def test_missing_transaction_fails_with_focused_diff(self):
        def mutation(pack):
            def remove_bye(root):
                for node in list(root):
                    if node.tag == "send" and (node.text or "").startswith("BYE "):
                        root.remove(node)
                        break
            self.mutate_xml(pack, remove_bye)
        result = self.validate_mutation(mutation)
        self.assertEqual("fail", result["verdict"])
        self.assertIn("transactions.count", {item["path"] for item in result["semanticDiff"]})

    def test_response_class_change_fails(self):
        def mutation(pack):
            def change(root):
                response = next(item for item in root.findall("recv") if item.get("response") == "200")
                response.set("response", "486")
            self.mutate_xml(pack, change)
        result = self.validate_mutation(mutation)
        self.assertTrue(any(item["path"].endswith("responseClasses")
                            for item in result["semanticDiff"]))

    def test_wrong_sdp_fails(self):
        def mutation(pack):
            def change(root):
                send = next(item for item in root.findall("send") if "a=rtpmap:0 PCMU" in (item.text or ""))
                send.text = send.text.replace("PCMU/8000", "OPUS/48000")
            self.mutate_xml(pack, change)
        result = self.validate_mutation(mutation)
        self.assertTrue(any(item["path"].endswith("sdpCodecs")
                            for item in result["semanticDiff"]))

    def test_teardown_drift_fails(self):
        def mutation(pack):
            def change(root):
                send = next(item for item in root.findall("send") if (item.text or "").startswith("BYE "))
                send.text = send.text.replace("BYE ", "OPTIONS ", 1).replace("CSeq: [cseq] BYE", "CSeq: [cseq] OPTIONS")
            self.mutate_xml(pack, change)
        result = self.validate_mutation(mutation)
        paths = {item["path"] for item in result["semanticDiff"]}
        self.assertIn("dialog.teardownInitiator", paths)

    def test_timing_tolerance_is_explicit_and_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pack = make_pack(root, "baseline")
            result = validate_pack(
                pack, root / "validation", image_identity="test", timing_tolerance_ms=250
            )
            self.assertEqual(250, result["timingToleranceMs"])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pack = make_pack(root, "baseline")
            with self.assertRaisesRegex(ValueError, "0..5000"):
                validate_pack(
                    pack, root / "validation", image_identity="test",
                    timing_tolerance_ms=5001,
                )

    def test_concrete_or_reviewed_target_is_refused_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pack = make_pack(root, "baseline")
            manifest_path = pack / "manifest.yaml"
            manifest = yaml.safe_load(manifest_path.read_text())
            manifest["target"]["host"] = "192.0.2.10"
            manifest_path.write_text(yaml.safe_dump(manifest))
            with self.assertRaisesRegex(ValueError, "concrete target"):
                validate_pack(pack, root / "validation", image_identity="test")


if __name__ == "__main__":
    unittest.main()
