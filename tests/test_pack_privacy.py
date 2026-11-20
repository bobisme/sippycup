"""`pack create` and `pack verify` report what `evidence lint` reports (rehearsal 2, finding 19).

An operator who ran `pack create` saw nothing about the capture's SIP
authorization material and sent the tar to the owner, because the doc said to.
Both commands now print the privacy findings first, on standard error, from the
same lint, and say what to send instead. Nothing here blocks `pack create`:
the pack is local evidence, and only `export-ci` is the gate (documented).
"""

from __future__ import annotations

import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from sippycup.evidence import lint_evidence, write_evidence_manifest  # noqa: E402
from sippycup.evidence_pack import (  # noqa: E402
    create_evidence_pack,
    privacy_notice,
    render_verification_markdown,
    verify_evidence_pack,
)

CLI = ROOT / "bin" / "sippycup-pack"
IMAGE = "sha256:" + "a" * 64
EMPTY_PCAP = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
CAPTURE_WITH_AUTH = b'INVITE sip:echo@192.0.2.5 SIP/2.0\r\nAuthorization: Digest username="practice", response="00112233445566778899aabbccddeeff"\r\n'


def make_run(root: Path, capture: bytes) -> None:
    (root / "plan.json").write_text(json.dumps({"authorization": {"networks": ["192.0.2.0/24"]}}))
    (root / "result.json").write_text('{"state":"succeeded"}\n')
    (root / "report.txt").write_text("assertions passed\n")
    (root / "capture.pcap").write_bytes(capture)
    write_evidence_manifest(root, created_at="2026-07-18T00:00:00Z")


class PackPrivacyTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.run_dir = self.base / "run"
        self.run_dir.mkdir()

    def cli(self, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(CLI), *arguments], text=True, capture_output=True, timeout=60)

    def test_create_reports_the_same_findings_as_evidence_lint(self) -> None:
        make_run(self.run_dir, CAPTURE_WITH_AUTH)
        lint = lint_evidence(self.run_dir)
        self.assertFalse(lint["passed"])
        done = self.cli("create", str(self.run_dir), str(self.base / "p.tar"), "--image-digest", IMAGE)
        self.assertEqual(0, done.returncode, done.stderr)
        result = json.loads(done.stdout)
        expected = sorted((f["code"], f["path"]) for f in lint["findings"])
        self.assertEqual(expected, sorted((f["code"], f["path"]) for f in result["privacy"]["findings"]))
        self.assertEqual("blocked", result["privacy"]["status"])
        self.assertIn("WARNING:", done.stderr.splitlines()[0])
        self.assertIn("authorization-material in capture.pcap", done.stderr)
        self.assertIn("Do not send this pack to anyone as it stands", done.stderr)
        self.assertIn("--recipient AGE_PUBLIC_KEY", done.stderr)
        self.assertIn("pack export-ci", done.stderr)
        self.assertNotIn("response=", done.stderr + done.stdout)

    def test_create_does_not_block_and_says_nothing_for_a_clean_run(self) -> None:
        make_run(self.run_dir, EMPTY_PCAP)
        done = self.cli("create", str(self.run_dir), str(self.base / "p.tar"), "--image-digest", IMAGE)
        self.assertEqual(0, done.returncode, done.stderr)
        self.assertEqual("", done.stderr)
        self.assertEqual("pass", json.loads(done.stdout)["privacy"]["status"])

    def test_verify_reports_the_findings_the_pack_carries_in_every_format(self) -> None:
        make_run(self.run_dir, CAPTURE_WITH_AUTH)
        pack = self.base / "p.tar"
        create_evidence_pack(self.run_dir, pack, image_digest=IMAGE)
        result = verify_evidence_pack(pack)
        self.assertEqual("pass", result["verdict"])
        self.assertEqual("blocked", result["privacy"]["status"])
        self.assertIn("authorization-material", {f["code"] for f in result["privacy"]["findings"]})
        markdown = render_verification_markdown(result)
        self.assertIn("Privacy:", markdown.splitlines()[2])
        self.assertIn("Do not send this pack as it stands", markdown)
        done = self.cli("verify", str(pack), "--format", "markdown")
        self.assertEqual(0, done.returncode, "verify still exits 0: the pack is intact")
        self.assertIn("WARNING:", done.stderr)
        self.assertIn("Privacy finding: `authorization-material`", done.stdout)
        as_json = self.cli("verify", str(pack))
        self.assertEqual("blocked", json.loads(as_json.stdout)["privacy"]["status"])
        self.assertIn("WARNING:", as_json.stderr)

    def test_verify_of_a_clean_pack_says_no_findings(self) -> None:
        make_run(self.run_dir, EMPTY_PCAP)
        pack = self.base / "p.tar"
        create_evidence_pack(self.run_dir, pack, image_digest=IMAGE)
        done = self.cli("verify", str(pack), "--format", "markdown")
        self.assertEqual("", done.stderr)
        self.assertIn("Privacy: no findings recorded", done.stdout)

    def test_the_notice_names_what_to_send_instead(self) -> None:
        lines = privacy_notice([{"code": "authorization-material", "severity": "high", "path": "capture.pcap", "detail": "d"}])
        text = "\n".join(lines)
        for word in ("owner report", "export-ci", "--allow-privacy-findings", "--recipient"):
            self.assertIn(word, text)
        self.assertEqual([], privacy_notice([]))


if __name__ == "__main__":
    unittest.main()
