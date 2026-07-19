from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup.evidence import (
    EvidenceError,
    MANIFEST_VERSION,
    OVERRIDE_VERSION,
    build_evidence_manifest,
    lint_evidence,
    write_evidence_manifest,
)


CLI = ROOT / "bin" / "sippycup-evidence"


def packet(source: str, destination: str, payload: bytes = b"") -> bytes:
    import ipaddress

    source_bytes = ipaddress.ip_address(source).packed
    destination_bytes = ipaddress.ip_address(destination).packed
    ethernet = b"\x00" * 12 + b"\x08\x00"
    total = 20 + 8 + len(payload)
    ip = (
        b"\x45\x00"
        + total.to_bytes(2, "big")
        + b"\x00\x00\x00\x00\x40\x11\x00\x00"
        + source_bytes
        + destination_bytes
    )
    udp = b"\x13\xc4\x13\xc4" + (8 + len(payload)).to_bytes(2, "big") + b"\x00\x00"
    return ethernet + ip + udp + payload


def pcap(*packets: bytes) -> bytes:
    output = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, raw in enumerate(packets, 1):
        output.extend(struct.pack("<IIII", index, 0, len(raw), len(raw)))
        output.extend(raw)
    return bytes(output)


def make_run(root: Path, *, sensitive: bool = False, complete: bool = True) -> None:
    plan = {
        "authorization": {"networks": ["10.0.0.0/24"]},
        "evidence": {"retainPayload": False},
    }
    (root / "plan.json").write_text(json.dumps(plan))
    (root / "reviewed-manifest.yaml").write_text("apiVersion: test\n")
    (root / "commands.json").write_text('{"runner":["safe"]}\n')
    (root / "events.jsonl").write_text('{"event":"campaign.started"}\n')
    (root / "versions.json").write_text('{"python":"test"}\n')
    (root / "preflight.json").write_text("[]\n")
    (root / "report.txt").write_text("offline assertion summary\n")
    (root / "report.stderr").write_text("")
    (root / "timestamps.json").write_text('{"started":"x","finished":"y"}\n')
    if complete:
        (root / "result.json").write_text('{"state":"succeeded"}\n')
    payload = b""
    destination = "10.0.0.2"
    if sensitive:
        destination = "203.0.113.9"
        payload = (
            b"INVITE sip:+15551234567@voice.test SIP/2.0\r\n"
            b"Call-ID: fixture-call@example.test\r\n"
            b"Authorization: Digest username=\"fixture-user\", response=\"fixture-secret\"\r\n\r\n"
        )
    (root / "capture.pcap").write_bytes(
        pcap(packet("10.0.0.1", destination, payload))
    )
    if sensitive:
        (root / "decoded.wav").write_bytes(
            b"RIFF" + b"\x00" * 4 + b"WAVEfmt " + b"\x00" * 64
        )
        (root / "notes.jsonl").write_text(
            '{"text":"call +15557654321 sounded wrong"}\n'
        )


class EvidenceManifestTests(unittest.TestCase):
    def test_manifest_is_deterministic_and_never_modifies_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_run(root)
            before = {
                path.name: (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
                for path in root.iterdir()
            }
            first = build_evidence_manifest(
                root, created_at="2026-01-01T00:00:00Z"
            )
            second = build_evidence_manifest(
                root, created_at="2026-02-01T00:00:00Z"
            )
            self.assertEqual(first["apiVersion"], MANIFEST_VERSION)
            self.assertEqual(first["contentIdentity"], second["contentIdentity"])
            self.assertEqual(first["artifacts"], second["artifacts"])
            self.assertNotEqual(first["creation"], second["creation"])
            self.assertFalse(first["creation"]["contentIdentityIncludesCreation"])
            after = {
                path.name: (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
                for path in root.iterdir()
            }
            self.assertEqual(before, after)

            written = write_evidence_manifest(
                root, created_at="2026-03-01T00:00:00Z"
            )
            self.assertEqual(written["contentIdentity"], first["contentIdentity"])
            self.assertEqual(
                0o600,
                (root / "evidence-manifest.json").stat().st_mode & 0o777,
            )
            self.assertNotIn(
                "evidence-manifest.json",
                [item["path"] for item in written["artifacts"]],
            )

    def test_inventory_has_types_provenance_sizes_hashes_and_sensitivity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_run(root)
            (root / "notes.jsonl").write_text('{"text":"jitter begins"}\n')
            (root / "assertions.json").write_text('{"verdict":"pass"}\n')
            (root / "stats.json").write_text('{"packets":1}\n')
            manifest = build_evidence_manifest(root)
            artifacts = {item["path"]: item for item in manifest["artifacts"]}
            self.assertEqual(
                {
                    "path",
                    "mediaType",
                    "size",
                    "sha256",
                    "provenance",
                    "sensitivity",
                },
                set(artifacts["capture.pcap"]),
            )
            self.assertEqual(
                "application/vnd.tcpdump.pcap",
                artifacts["capture.pcap"]["mediaType"],
            )
            self.assertEqual(
                "network-capture", artifacts["capture.pcap"]["provenance"]
            )
            self.assertEqual("confidential", artifacts["capture.pcap"]["sensitivity"])
            self.assertEqual("reviewed-authorization", artifacts["plan.json"]["provenance"])
            self.assertEqual("operator-note", artifacts["notes.jsonl"]["provenance"])
            self.assertEqual("confidential", artifacts["notes.jsonl"]["sensitivity"])
            self.assertEqual("offline-analysis", artifacts["assertions.json"]["provenance"])
            self.assertEqual("offline-analysis", artifacts["stats.json"]["provenance"])
            self.assertEqual("succeeded", manifest["runState"])
            self.assertEqual([], manifest["missingExpected"])

    def test_incomplete_run_remains_inspectable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_run(root, complete=False)
            (root / "events.jsonl").unlink()
            manifest = build_evidence_manifest(root)
            self.assertEqual("incomplete", manifest["runState"])
            self.assertIn("result.json", manifest["missingExpected"])
            self.assertIn("events.jsonl", manifest["missingExpected"])
            self.assertTrue(manifest["artifacts"])
            self.assertRegex(manifest["contentIdentity"], r"^sha256:[0-9a-f]{64}$")


class PrivacyLintTests(unittest.TestCase):
    def test_all_high_risk_fixture_classes_are_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_run(root, sensitive=True)
            result = lint_evidence(root, max_capture_bytes=64)
            self.assertFalse(result["passed"])
            codes = {item["code"] for item in result["findings"]}
            self.assertTrue(
                {
                    "authorization-material",
                    "subscriber-identifier",
                    "unexpected-network",
                    "decoded-audio",
                    "oversized-capture",
                }.issubset(codes)
            )
            capture_before = hashlib.sha256((root / "capture.pcap").read_bytes()).hexdigest()
            lint_evidence(root, max_capture_bytes=64)
            self.assertEqual(
                capture_before,
                hashlib.sha256((root / "capture.pcap").read_bytes()).hexdigest(),
            )

    def test_high_risk_requires_external_mode_0600_identity_bound_override(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "run"
            root.mkdir()
            make_run(root, sensitive=True)
            blocked = lint_evidence(root, max_capture_bytes=64)
            codes = sorted({item["code"] for item in blocked["findings"]})
            override = base / "local-override.json"
            override.write_text(
                json.dumps(
                    {
                        "apiVersion": OVERRIDE_VERSION,
                        "localOnly": True,
                        "contentIdentity": blocked["contentIdentity"],
                        "allowFindings": codes,
                        "justification": "approved local security fixture",
                    }
                )
            )
            override.chmod(0o600)
            allowed = lint_evidence(
                root, override=override, max_capture_bytes=64
            )
            self.assertTrue(allowed["passed"])
            self.assertTrue(all(item["overridden"] for item in allowed["findings"]))
            self.assertNotIn(
                override.name,
                [item["path"] for item in build_evidence_manifest(root)["artifacts"]],
            )

            override.chmod(0o644)
            with self.assertRaisesRegex(EvidenceError, "mode 0600"):
                lint_evidence(root, override=override, max_capture_bytes=64)
            override.chmod(0o600)
            wrong_identity = json.loads(override.read_text())
            wrong_identity["contentIdentity"] = "sha256:" + "0" * 64
            override.write_text(json.dumps(wrong_identity))
            with self.assertRaisesRegex(EvidenceError, "identity does not match"):
                lint_evidence(root, override=override, max_capture_bytes=64)
            wrong_identity["contentIdentity"] = blocked["contentIdentity"]
            wrong_identity["allowFindings"].append("not-a-real-finding")
            override.write_text(json.dumps(wrong_identity))
            with self.assertRaisesRegex(EvidenceError, "not present"):
                lint_evidence(root, override=override, max_capture_bytes=64)
            wrong_identity["allowFindings"].remove("not-a-real-finding")
            override.write_text(json.dumps(wrong_identity))
            inside = root / "override.json"
            inside.write_bytes(override.read_bytes())
            inside.chmod(0o600)
            with self.assertRaisesRegex(EvidenceError, "outside"):
                lint_evidence(root, override=inside, max_capture_bytes=64)

    def test_cli_exit_contract_distinguishes_blocked_and_clean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_run(root)
            clean = subprocess.run(
                [sys.executable, str(CLI), "lint", str(root)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(clean.returncode, 0, clean.stderr)
            self.assertTrue(json.loads(clean.stdout)["passed"])
            (root / "report.txt").write_text(
                "Call-ID: fixture@example.test\nAuthorization: Digest fixture\n"
            )
            blocked = subprocess.run(
                [sys.executable, str(CLI), "lint", str(root)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(blocked.returncode, 1)
            self.assertFalse(json.loads(blocked.stdout)["passed"])


if __name__ == "__main__":
    unittest.main()
