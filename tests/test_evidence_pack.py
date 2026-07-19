from __future__ import annotations

import copy
import io
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
import subprocess
import sys
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup.evidence import write_evidence_manifest
from sippycup.evidence_pack import (
    CI_VERSION,
    PACK_VERSION,
    EvidencePackError,
    create_evidence_pack,
    export_ci,
    render_verification_json,
    render_verification_junit,
    render_verification_markdown,
    sign_evidence_pack,
    verify_evidence_pack,
)


CLI = ROOT / "bin" / "sippycup-pack"
IMAGE = "sha256:" + "a" * 64


def make_run(root: Path) -> None:
    (root / "plan.json").write_text(
        json.dumps(
            {
                "authorization": {"networks": ["192.0.2.0/24"]},
                "evidence": {"retainPayload": True},
            }
        )
    )
    (root / "result.json").write_text('{"state":"succeeded"}\n')
    (root / "report.txt").write_text("assertions passed\n")
    (root / "capture.pcap").write_bytes(b"sensitive-capture-fixture")
    write_evidence_manifest(root, created_at="2026-07-18T00:00:00Z")


def archive_entries(path: Path) -> list[tuple[str, bytes]]:
    with tarfile.open(path, "r") as archive:
        return [
            (item.name, archive.extractfile(item).read())
            for item in archive.getmembers()
            if item.isfile()
        ]


def write_archive(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with tarfile.open(path, "w") as archive:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))


class PortablePackTests(unittest.TestCase):
    def build(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        run = base / "run"
        run.mkdir()
        make_run(run)
        pack = base / "evidence.tar"
        return base, run, pack

    def test_plain_pack_is_deterministic_portable_and_records_supply_chain(self):
        base, run, first = self.build()
        second = base / "second.tar"
        created = create_evidence_pack(run, first, image_digest=IMAGE)
        create_evidence_pack(run, second, image_digest=IMAGE)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        shutil.rmtree(run)
        result = verify_evidence_pack(first)
        self.assertEqual("pass", result["verdict"], result)
        self.assertEqual("valid", result["content"]["status"])
        self.assertEqual(IMAGE, result["supplyChain"]["imageDigest"])
        self.assertEqual(
            "SPDX-2.3", result["supplyChain"]["sbom"]["spdxVersion"]
        )
        self.assertEqual(PACK_VERSION, created["apiVersion"])

    def test_modified_missing_duplicate_traversal_and_undeclared_are_rejected(self):
        base, run, valid = self.build()
        create_evidence_pack(run, valid, image_digest=IMAGE)
        entries = archive_entries(valid)
        capture_index = next(
            index for index, item in enumerate(entries) if item[0] == "capture.pcap"
        )
        cases = {}
        modified = copy.deepcopy(entries)
        original_capture = entries[capture_index][1]
        modified[capture_index] = (
            "capture.pcap",
            original_capture[:-1] + bytes([original_capture[-1] ^ 1]),
        )
        cases["hash differs"] = modified
        cases["missing declared"] = [
            item for item in entries if item[0] != "capture.pcap"
        ]
        cases["duplicate archive"] = entries + [entries[capture_index]]
        cases["unsafe artifact path"] = entries + [("../escape", b"bad")]
        cases["undeclared archive"] = entries + [("extra.txt", b"extra")]
        relabeled = copy.deepcopy(entries)
        manifest_index = next(
            index for index, item in enumerate(relabeled)
            if item[0] == "pack-manifest.json"
        )
        manifest = json.loads(relabeled[manifest_index][1])
        next(
            item for item in manifest["artifacts"]
            if item["path"] == "capture.pcap"
        )["sensitivity"] = "public"
        relabeled[manifest_index] = (
            "pack-manifest.json",
            (json.dumps(manifest, sort_keys=True) + "\n").encode(),
        )
        cases["inventory differs"] = relabeled
        for expected, content in cases.items():
            with self.subTest(expected):
                hostile = base / (expected.replace(" ", "-") + ".tar")
                write_archive(hostile, content)
                result = verify_evidence_pack(hostile)
                self.assertEqual("content-failure", result["verdict"])
                self.assertTrue(
                    any(expected in error for error in result["content"]["errors"]),
                    result,
                )
        self.assertFalse((base / "escape").exists())

    def test_signature_failure_is_distinct_and_keys_are_external(self):
        base, run, pack = self.build()
        create_evidence_pack(run, pack, image_digest=IMAGE)
        signature, public = base / "pack.minisig", base / "public.key"
        signature.write_text("invalid-signature")
        public.write_text("untrusted comment: fixture")

        def reject(_command):
            return SimpleNamespace(returncode=1, stdout="", stderr="bad signature")

        result = verify_evidence_pack(
            pack,
            signature=signature,
            public_key=public,
            runner=reject,
        )
        self.assertEqual("signature-failure", result["verdict"])
        self.assertEqual("valid", result["content"]["status"])
        self.assertEqual("invalid", result["signature"]["status"])

        secret = base / "secret.key"
        secret.write_text("fixture-key-material")
        before = secret.read_bytes()

        def sign(command):
            destination = Path(command[command.index("-x") + 1])
            destination.write_text("fixture-signature")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        output = sign_evidence_pack(pack, secret, runner=sign)
        self.assertTrue(output.is_file())
        self.assertEqual(before, secret.read_bytes())
        self.assertFalse(any(path.name.endswith(".key") and path != secret and path != public
                             for path in base.iterdir()))

    def test_recipient_encryption_cleans_plaintext_on_success_and_failure(self):
        base, run, _pack = self.build()
        plaintext_paths = []

        def encrypt(command):
            output = Path(command[command.index("-o") + 1])
            plaintext = Path(command[-1])
            plaintext_paths.append(plaintext)
            output.write_bytes(b"age-encrypted-fixture")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        encrypted = base / "portable.age"
        result = create_evidence_pack(
            run,
            encrypted,
            image_digest=IMAGE,
            recipients=("age1fixture",),
            runner=encrypt,
        )
        self.assertTrue(result["encrypted"])
        self.assertEqual(b"age-encrypted-fixture", encrypted.read_bytes())
        self.assertTrue(all(not path.exists() for path in plaintext_paths))
        self.assertFalse(any(path.name.startswith(f".{encrypted.name}.")
                             for path in base.iterdir()))

        failed_plaintext = []

        def fail(command):
            failed_plaintext.append(Path(command[-1]))
            return SimpleNamespace(returncode=1, stdout="", stderr="recipient rejected")

        with self.assertRaisesRegex(EvidencePackError, "encryption failed"):
            create_evidence_pack(
                run,
                base / "failed.age",
                image_digest=IMAGE,
                recipients=("age1fixture",),
                runner=fail,
            )
        self.assertTrue(all(not path.exists() for path in failed_plaintext))
        self.assertFalse((base / "failed.age").exists())

    def test_ci_export_is_reports_only_unless_artifact_is_explicit(self):
        base, run, pack = self.build()
        create_evidence_pack(run, pack, image_digest=IMAGE)
        reports = base / "ci-reports"
        with self.assertRaisesRegex(EvidencePackError, "privacy findings block"):
            export_ci(pack, reports)
        exported = export_ci(pack, reports, allow_privacy_findings=True)
        self.assertEqual(CI_VERSION, exported["apiVersion"])
        self.assertEqual([], exported["includedArtifacts"])
        self.assertFalse((reports / "artifacts").exists())
        combined = b"".join(
            path.read_bytes() for path in reports.iterdir() if path.is_file()
        )
        self.assertNotIn(b"sensitive-capture-fixture", combined)

        selected = base / "ci-selected"
        manifest = export_ci(
            pack,
            selected,
            include_artifacts=("capture.pcap",),
            allow_privacy_findings=True,
        )
        self.assertEqual(
            "restricted", manifest["includedArtifacts"][0]["sensitivity"]
        )
        self.assertTrue(
            manifest["includedArtifacts"][0]["explicitlySelected"]
        )
        self.assertEqual(
            b"sensitive-capture-fixture",
            (selected / "artifacts" / "capture.pcap").read_bytes(),
        )

    def test_json_markdown_junit_and_cli_use_same_verification(self):
        base, run, pack = self.build()
        create_evidence_pack(run, pack, image_digest=IMAGE)
        result = verify_evidence_pack(pack)
        self.assertEqual(result, json.loads(render_verification_json(result)))
        markdown = render_verification_markdown(result)
        junit = ET.fromstring(render_verification_junit(result))
        self.assertIn(result["verdict"], markdown)
        self.assertEqual("0", junit.attrib["failures"])
        for output_format in ("json", "markdown", "junit"):
            completed = subprocess.run(
                [
                    sys.executable,
                    str(CLI),
                    "verify",
                    str(pack),
                    "--format",
                    output_format,
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertTrue(completed.stdout)


if __name__ == "__main__":
    unittest.main()
