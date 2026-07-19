from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests" / "oracle"))

from test_dialogs import scenario_frames

from sippycup.evidence import write_evidence_manifest
from sippycup.evidence_pack import (
    EvidencePackError,
    create_evidence_pack,
    export_ci,
    verify_evidence_pack,
)
from sippycup_learn import canonicalize_dialog, compare_behavior_packs
from sippycup_oracle.dialogs import reconstruct_dialogs

from tests.learn.test_golden_diff import (
    oracle_result,
    rewrite_nondeterminism,
    shift_evidence,
    write_pack,
)
from tests.test_evidence_pack import IMAGE, archive_entries


SAMPLE = ROOT / "examples" / "evidence-pack" / "sanitized-evidence.tar"


def clean_model():
    frames = scenario_frames("baseline")
    return canonicalize_dialog(
        reconstruct_dialogs(frames),
        frames,
        local_networks=("192.0.2.0/24",),
    )


def write_canonical_archive(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o600
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))


class EvidencePackExitGate(unittest.TestCase):
    def test_published_sanitized_pack_is_reproducible_portable_and_ci_clean(self):
        completed = verify_evidence_pack(SAMPLE)
        self.assertEqual("pass", completed["verdict"], completed)
        with tempfile.TemporaryDirectory() as temporary:
            isolated = Path(temporary)
            moved = isolated / "received-on-another-machine.tar"
            shutil.copyfile(SAMPLE, moved)
            previous = Path.cwd()
            os.chdir(isolated)
            try:
                result = verify_evidence_pack(moved)
                export = export_ci(moved, isolated / "ci")
            finally:
                os.chdir(previous)
            self.assertEqual("pass", result["verdict"])
            self.assertEqual("pass", export["privacyStatus"])
            self.assertEqual([], export["includedArtifacts"])
            self.assertFalse((isolated / "ci" / "artifacts").exists())
            combined = b"".join(
                path.read_bytes()
                for path in (isolated / "ci").iterdir()
                if path.is_file()
            )
            for forbidden in (
                b"Authorization:",
                b"Call-ID:",
                b"sensitive-capture-fixture",
                b"RIFF",
            ):
                self.assertNotIn(forbidden, combined)

        check = __import__("subprocess").run(
            [
                sys.executable,
                str(ROOT / "tools" / "generate_sanitized_evidence_pack.py"),
                "--check",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, check.returncode, check.stderr)

    def test_every_member_payload_and_path_tamper_is_detected(self):
        entries = archive_entries(SAMPLE)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, (name, payload) in enumerate(entries):
                with self.subTest(member=name, mutation="payload"):
                    changed = list(entries)
                    mutated = (
                        payload[:-1] + bytes([payload[-1] ^ 1])
                        if payload
                        else b"x"
                    )
                    changed[index] = (name, mutated)
                    hostile = root / f"payload-{index}.tar"
                    write_canonical_archive(hostile, changed)
                    self.assertEqual(
                        "content-failure",
                        verify_evidence_pack(hostile)["verdict"],
                    )
                with self.subTest(member=name, mutation="path"):
                    renamed = list(entries)
                    renamed[index] = (f"renamed-{index}", payload)
                    hostile = root / f"path-{index}.tar"
                    write_canonical_archive(hostile, renamed)
                    self.assertEqual(
                        "content-failure",
                        verify_evidence_pack(hostile)["verdict"],
                    )

    def test_exact_archive_byte_tamper_is_caught_by_optional_signature(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            signed_bytes = SAMPLE.read_bytes()
            expected = hashlib.sha256(signed_bytes).hexdigest()
            tampered = root / "padding-tampered.tar"
            changed = bytearray(signed_bytes)
            changed[-1] ^= 1
            tampered.write_bytes(changed)
            signature, public = root / "pack.minisig", root / "minisign.pub"
            signature.write_text("fixture")
            public.write_text("fixture")

            def exact_byte_signature(command):
                message = Path(command[command.index("-m") + 1])
                valid = hashlib.sha256(message.read_bytes()).hexdigest() == expected
                return SimpleNamespace(
                    returncode=0 if valid else 1,
                    stdout="",
                    stderr="" if valid else "exact bytes changed",
                )

            result = verify_evidence_pack(
                tampered,
                signature=signature,
                public_key=public,
                runner=exact_byte_signature,
            )
            self.assertEqual("signature-failure", result["verdict"])
            self.assertEqual("invalid", result["signature"]["status"])

    def test_secret_bearing_pack_blocks_default_export_and_never_leaks_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = root / "run"
            run.mkdir()
            (run / "plan.json").write_text(
                '{"authorization":{"networks":[]},"evidence":{"retainPayload":true}}'
            )
            secret = (
                "Authorization: Digest username=\"fixture\", response=\"secret\"\n"
                "Call-ID: private-call@example.invalid\n"
            )
            (run / "report.txt").write_text(secret)
            (run / "decoded.wav").write_bytes(
                b"RIFF" + b"\0" * 4 + b"WAVEfmt " + b"\0" * 32
            )
            write_evidence_manifest(run, created_at="2026-07-18T00:00:00Z")
            pack = root / "secret-bearing.tar"
            create_evidence_pack(run, pack, image_digest=IMAGE)
            with self.assertRaisesRegex(EvidencePackError, "privacy findings block"):
                export_ci(pack, root / "default-ci")
            reports = root / "acknowledged-ci"
            exported = export_ci(
                pack, reports, allow_privacy_findings=True
            )
            self.assertTrue(exported["privacyFindingsAcknowledged"])
            self.assertEqual([], exported["includedArtifacts"])
            combined = b"".join(
                path.read_bytes()
                for path in reports.iterdir()
                if path.is_file()
            )
            self.assertNotIn(b"response=\"secret\"", combined)
            self.assertNotIn(b"private-call@example.invalid", combined)
            self.assertNotIn(b"RIFF", combined)

    def test_incomplete_pack_remains_verifiable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = root / "interrupted"
            run.mkdir()
            (run / "plan.json").write_text(
                '{"authorization":{"networks":[]},"evidence":{"retainPayload":false}}'
            )
            manifest = write_evidence_manifest(
                run, created_at="2026-07-18T00:00:00Z"
            )
            self.assertEqual("incomplete", manifest["runState"])
            self.assertTrue(manifest["missingExpected"])
            pack = root / "interrupted.tar"
            create_evidence_pack(run, pack, image_digest=IMAGE)
            shutil.rmtree(run)
            self.assertEqual("pass", verify_evidence_pack(pack)["verdict"])

    def test_canonical_diff_equivalence_and_regression_corpus(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline_model = clean_model()
            baseline_oracle = oracle_result()
            equivalent_model = copy.deepcopy(baseline_model)
            equivalent_oracle = copy.deepcopy(baseline_oracle)
            rewrite_nondeterminism(equivalent_model)
            for transaction in equivalent_model["transactions"]:
                for field in ("earliest", "latest"):
                    if transaction["timingWindowMs"][field] is not None:
                        transaction["timingWindowMs"][field] += 10_000
            equivalent_oracle["dialogs"][0]["call_id"] = "new-id@example.invalid"
            shift_evidence(equivalent_oracle)
            baseline = write_pack(
                root, "baseline", baseline_model, baseline_oracle
            )
            equivalent = write_pack(
                root, "equivalent", equivalent_model, equivalent_oracle
            )
            self.assertEqual(
                "equal",
                compare_behavior_packs(baseline, equivalent)["verdict"],
            )

            regression_model = copy.deepcopy(baseline_model)
            regression_oracle = copy.deepcopy(baseline_oracle)
            regression_model["sdpRevisions"][0]["media"][0]["codecs"][0][
                "encoding"
            ] = "OPUS"
            regression_oracle["streams"].pop()
            regression_oracle["assertions"][0]["verdict"] = "fail"
            regression = write_pack(
                root, "regression", regression_model, regression_oracle
            )
            result = compare_behavior_packs(baseline, regression)
            self.assertEqual("different", result["verdict"])
            categories = {item["category"] for item in result["changes"]}
            self.assertTrue({"codec", "media", "assertion"} <= categories)


if __name__ == "__main__":
    unittest.main()
