from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_workbench.journal import (
    JournalError,
    append,
    initialize,
    render,
    verify,
    write_rendered,
)


class JournalTests(unittest.TestCase):
    def test_initialize_is_private_and_refuses_existing_directory(self) -> None:
        with tempfile.TemporaryDirectory() as parent_name:
            root = Path(parent_name) / "assessment"
            initialize(
                root,
                title="Ferivox staging assessment",
                owner="Quad",
                created_at="2026-07-19T12:00:00Z",
            )
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((root / "engagement.json").stat().st_mode), 0o600
            )
            self.assertEqual(
                stat.S_IMODE((root / "journal.jsonl").stat().st_mode), 0o600
            )
            with self.assertRaises(JournalError):
                initialize(root, title="replacement", owner="Quad")

    def test_append_builds_a_verifiable_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as parent_name:
            root = Path(parent_name) / "assessment"
            initialize(root, title="Assessment", owner="Quad")
            first = append(
                root,
                kind="hypothesis",
                summary="RTP source tuple may not be pinned",
                detail="Test only after the live scope is approved.",
                tags=["rtp", "security"],
                recorded_at="2026-07-19T12:00:00Z",
            )
            second = append(
                root,
                kind="action",
                summary="Compiled the offline campaign plan",
                evidence=["runs/baseline/plan.json"],
                recorded_at="2026-07-19T12:01:00Z",
            )
            result = verify(root)
            self.assertEqual(len(result.entries), 2)
            self.assertEqual(second["previousSha256"], first["entrySha256"])
            self.assertEqual(result.final_sha256, second["entrySha256"])
            self.assertEqual(
                result.missing_evidence, ("runs/baseline/plan.json",)
            )

    def test_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as parent_name:
            root = Path(parent_name) / "assessment"
            initialize(root, title="Assessment", owner="Quad")
            append(root, kind="note", summary="Original")
            path = root / "journal.jsonl"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["summary"] = "Changed"
            path.write_text(json.dumps(value) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(JournalError, "digest does not match"):
                verify(root)

    def test_unsafe_evidence_reference_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as parent_name:
            root = Path(parent_name) / "assessment"
            initialize(root, title="Assessment", owner="Quad")
            for unsafe in ("../secret", "/etc/passwd", "runs\\capture.pcap"):
                with self.subTest(reference=unsafe), self.assertRaises(JournalError):
                    append(
                        root,
                        kind="observation",
                        summary="Unsafe evidence",
                        evidence=[unsafe],
                    )

    def test_internal_render_includes_private_content(self) -> None:
        with tempfile.TemporaryDirectory() as parent_name:
            root = Path(parent_name) / "assessment"
            initialize(root, title="Ferivox assessment", owner="Quad")
            append(
                root,
                kind="finding",
                summary="PRIVATE CANARY finding",
                evidence=["runs/one/report.txt"],
            )
            output = render(root, audience="internal")
            self.assertIn("PRIVATE CANARY finding", output)
            self.assertIn("runs/one/report.txt", output)
            self.assertIn("Privacy lint", output)

    def test_public_render_never_copies_journal_content_or_evidence_paths(self) -> None:
        with tempfile.TemporaryDirectory() as parent_name:
            root = Path(parent_name) / "assessment"
            initialize(root, title="PRIVATE TARGET", owner="PRIVATE OWNER")
            append(
                root,
                kind="finding",
                summary="PRIVATE CANARY finding",
                detail="PRIVATE DETAIL",
                evidence=["runs/private/capture.pcap"],
            )
            output = render(root, audience="public")
            for private in (
                "PRIVATE TARGET",
                "PRIVATE OWNER",
                "PRIVATE CANARY",
                "PRIVATE DETAIL",
                "runs/private/capture.pcap",
            ):
                self.assertNotIn(private, output)
            self.assertIn("intentionally contains no journal text", output)
            self.assertIn("explicit disclosure approval", output)

    def test_render_refuses_to_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as parent_name:
            output = Path(parent_name) / "report.md"
            write_rendered(output, "first\n")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            with self.assertRaises(JournalError):
                write_rendered(output, "second\n")
            self.assertEqual(output.read_text(encoding="utf-8"), "first\n")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_journal_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as parent_name:
            root = Path(parent_name) / "assessment"
            initialize(root, title="Assessment", owner="Quad")
            target = Path(parent_name) / "outside"
            target.write_text("", encoding="utf-8")
            (root / "journal.jsonl").unlink()
            (root / "journal.jsonl").symlink_to(target)
            with self.assertRaises(JournalError):
                verify(root)


if __name__ == "__main__":
    unittest.main()
