"""Append-only assessment journal and privacy-safe report scaffolding."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, TextIO


ENGAGEMENT_VERSION = "sippycup.dev/engagement/v1"
ENTRY_VERSION = "sippycup.dev/journal-entry/v1"
JOURNAL_NAME = "journal.jsonl"
ENGAGEMENT_NAME = "engagement.json"
MAX_JOURNAL_BYTES = 32 * 1024 * 1024
MAX_ENTRY_BYTES = 1024 * 1024
MAX_ENTRIES = 100_000
MAX_SUMMARY_CHARS = 500
MAX_DETAIL_CHARS = 64 * 1024
MAX_REFERENCES = 128
MAX_TAGS = 32
KINDS = (
    "authorization",
    "hypothesis",
    "action",
    "observation",
    "finding",
    "decision",
    "follow-up",
    "note",
)
_TAG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ENTRY_KEYS = {
    "apiVersion",
    "sequence",
    "recordedAt",
    "kind",
    "summary",
    "detail",
    "evidence",
    "tags",
    "previousSha256",
    "entrySha256",
}


class JournalError(ValueError):
    """Invalid or unsafe journal operation."""


@dataclass(frozen=True)
class Verification:
    entries: tuple[dict[str, Any], ...]
    final_sha256: str | None
    missing_evidence: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "apiVersion": "sippycup.dev/journal-verification/v1",
            "valid": True,
            "entryCount": len(self.entries),
            "finalSha256": self.final_sha256,
            "missingEvidence": list(self.missing_evidence),
            "networkActivity": False,
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _entry_digest(entry: dict[str, Any]) -> str:
    material = {key: value for key, value in entry.items() if key != "entrySha256"}
    return hashlib.sha256(_canonical(material)).hexdigest()


def _validate_text(name: str, value: Any, *, maximum: int, empty: bool = False) -> str:
    if not isinstance(value, str):
        raise JournalError(f"{name} must be text")
    if not empty and not value.strip():
        raise JournalError(f"{name} must not be empty")
    if "\x00" in value:
        raise JournalError(f"{name} must not contain NUL")
    if len(value) > maximum:
        raise JournalError(f"{name} exceeds {maximum} characters")
    return value


def _safe_reference(value: str) -> str:
    _validate_text("evidence reference", value, maximum=1024)
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or "\\" in value
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise JournalError(
            "evidence references must be normalized relative paths without dot segments"
        )
    return value


def _validate_metadata(value: Any) -> dict[str, Any]:
    expected = {
        "apiVersion",
        "kind",
        "title",
        "owner",
        "createdAt",
        "confidentiality",
        "journal",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise JournalError("engagement metadata has invalid fields")
    if value["apiVersion"] != ENGAGEMENT_VERSION:
        raise JournalError("unsupported engagement metadata version")
    if value["kind"] != "AssessmentEngagement":
        raise JournalError("invalid engagement metadata kind")
    _validate_text("title", value["title"], maximum=200)
    _validate_text("owner", value["owner"], maximum=200)
    _validate_text("createdAt", value["createdAt"], maximum=64)
    if value["confidentiality"] != "private":
        raise JournalError("engagement confidentiality must be private")
    if value["journal"] != JOURNAL_NAME:
        raise JournalError("engagement journal path is invalid")
    return value


def _load_metadata(root: Path) -> dict[str, Any]:
    try:
        resolved = root.resolve(strict=True)
    except OSError as error:
        raise JournalError(f"engagement directory is unavailable: {error}") from error
    if not resolved.is_dir():
        raise JournalError("engagement path must be a directory")
    try:
        raw = (resolved / ENGAGEMENT_NAME).read_text(encoding="utf-8")
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise JournalError(f"cannot read engagement metadata: {error}") from error
    return _validate_metadata(value)


def initialize(
    root: str | Path,
    *,
    title: str,
    owner: str,
    created_at: str | None = None,
) -> dict[str, Any]:
    title = _validate_text("title", title, maximum=200).strip()
    owner = _validate_text("owner", owner, maximum=200).strip()
    path = Path(root)
    try:
        path.mkdir(mode=0o700, parents=False, exist_ok=False)
    except OSError as error:
        raise JournalError(f"cannot create engagement directory: {error}") from error
    metadata = {
        "apiVersion": ENGAGEMENT_VERSION,
        "kind": "AssessmentEngagement",
        "title": title,
        "owner": owner,
        "createdAt": created_at or _utc_now(),
        "confidentiality": "private",
        "journal": JOURNAL_NAME,
    }
    try:
        descriptor = os.open(
            path / ENGAGEMENT_NAME,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(metadata, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        journal_descriptor = os.open(
            path / JOURNAL_NAME,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.close(journal_descriptor)
    except OSError as error:
        raise JournalError(f"cannot initialize engagement files: {error}") from error
    return metadata


def _validate_entry(
    value: Any, *, expected_sequence: int, previous_sha256: str | None
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _ENTRY_KEYS:
        raise JournalError(f"journal entry {expected_sequence} has invalid fields")
    if value["apiVersion"] != ENTRY_VERSION:
        raise JournalError(f"journal entry {expected_sequence} has an unsupported version")
    if value["sequence"] != expected_sequence:
        raise JournalError(f"journal sequence must be {expected_sequence}")
    _validate_text("recordedAt", value["recordedAt"], maximum=64)
    if value["kind"] not in KINDS:
        raise JournalError(f"journal entry {expected_sequence} has an invalid kind")
    _validate_text("summary", value["summary"], maximum=MAX_SUMMARY_CHARS)
    _validate_text(
        "detail", value["detail"], maximum=MAX_DETAIL_CHARS, empty=True
    )
    if (
        not isinstance(value["evidence"], list)
        or len(value["evidence"]) > MAX_REFERENCES
        or value["evidence"] != sorted(set(value["evidence"]))
    ):
        raise JournalError(
            f"journal entry {expected_sequence} evidence must be sorted and unique"
        )
    for reference in value["evidence"]:
        if not isinstance(reference, str):
            raise JournalError("evidence references must be text")
        _safe_reference(reference)
    if (
        not isinstance(value["tags"], list)
        or len(value["tags"]) > MAX_TAGS
        or value["tags"] != sorted(set(value["tags"]))
        or any(not isinstance(tag, str) or _TAG.fullmatch(tag) is None for tag in value["tags"])
    ):
        raise JournalError(
            f"journal entry {expected_sequence} tags must be sorted safe identifiers"
        )
    if value["previousSha256"] != previous_sha256:
        raise JournalError(f"journal entry {expected_sequence} breaks the hash chain")
    digest = value["entrySha256"]
    if not isinstance(digest, str) or _HEX_DIGEST.fullmatch(digest) is None:
        raise JournalError(f"journal entry {expected_sequence} has an invalid digest")
    if digest != _entry_digest(value):
        raise JournalError(f"journal entry {expected_sequence} digest does not match")
    return value


def _verify_stream(source: TextIO) -> Verification:
    entries: list[dict[str, Any]] = []
    previous: str | None = None
    total = 0
    for line_number, line in enumerate(source, 1):
        encoded_size = len(line.encode("utf-8"))
        total += encoded_size
        if total > MAX_JOURNAL_BYTES:
            raise JournalError("journal exceeds the 32 MiB verification limit")
        if encoded_size > MAX_ENTRY_BYTES:
            raise JournalError(f"journal line {line_number} exceeds the 1 MiB limit")
        if not line.endswith("\n"):
            raise JournalError(f"journal line {line_number} is incomplete")
        if not line.strip():
            raise JournalError(f"journal line {line_number} is empty")
        if len(entries) >= MAX_ENTRIES:
            raise JournalError("journal exceeds the 100,000 entry limit")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise JournalError(f"journal line {line_number} is invalid JSON: {error}") from error
        entry = _validate_entry(
            value,
            expected_sequence=len(entries) + 1,
            previous_sha256=previous,
        )
        entries.append(entry)
        previous = entry["entrySha256"]
    return Verification(tuple(entries), previous)


def verify(root: str | Path) -> Verification:
    path = Path(root)
    _load_metadata(path)
    journal = path / JOURNAL_NAME
    try:
        descriptor = os.open(
            journal, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        )
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise JournalError("journal must be a regular file")
        with os.fdopen(descriptor, "r", encoding="utf-8") as source:
            fcntl.flock(source.fileno(), fcntl.LOCK_SH)
            verification = _verify_stream(source)
            resolved_root = path.resolve(strict=True)
            references = {
                reference
                for entry in verification.entries
                for reference in entry["evidence"]
            }
            missing = []
            for reference in sorted(references):
                candidate = resolved_root / reference
                try:
                    resolved = candidate.resolve(strict=True)
                    resolved.relative_to(resolved_root)
                    available = resolved.is_file() and not candidate.is_symlink()
                except (OSError, ValueError):
                    available = False
                if not available:
                    missing.append(reference)
            return Verification(
                verification.entries,
                verification.final_sha256,
                tuple(missing),
            )
    except OSError as error:
        raise JournalError(f"cannot verify journal: {error}") from error


def append(
    root: str | Path,
    *,
    kind: str,
    summary: str,
    detail: str = "",
    evidence: Iterable[str] = (),
    tags: Iterable[str] = (),
    recorded_at: str | None = None,
) -> dict[str, Any]:
    path = Path(root)
    _load_metadata(path)
    if kind not in KINDS:
        raise JournalError(f"kind must be one of: {', '.join(KINDS)}")
    summary = _validate_text("summary", summary.strip(), maximum=MAX_SUMMARY_CHARS)
    detail = _validate_text(
        "detail", detail.rstrip(), maximum=MAX_DETAIL_CHARS, empty=True
    )
    references = sorted({_safe_reference(item) for item in evidence})
    if len(references) > MAX_REFERENCES:
        raise JournalError(f"at most {MAX_REFERENCES} evidence references are allowed")
    normalized_tags = sorted(set(tags))
    if (
        len(normalized_tags) > MAX_TAGS
        or any(_TAG.fullmatch(tag) is None for tag in normalized_tags)
    ):
        raise JournalError(
            f"at most {MAX_TAGS} lowercase identifier tags are allowed"
        )
    journal = path / JOURNAL_NAME
    try:
        descriptor = os.open(
            journal,
            os.O_RDWR | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
        )
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise JournalError("journal must be a regular file")
        with os.fdopen(descriptor, "r+", encoding="utf-8") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            stream.seek(0)
            verification = _verify_stream(stream)
            entry: dict[str, Any] = {
                "apiVersion": ENTRY_VERSION,
                "sequence": len(verification.entries) + 1,
                "recordedAt": recorded_at or _utc_now(),
                "kind": kind,
                "summary": summary,
                "detail": detail,
                "evidence": references,
                "tags": normalized_tags,
                "previousSha256": verification.final_sha256,
            }
            entry["entrySha256"] = _entry_digest(entry)
            encoded = _canonical(entry) + b"\n"
            if len(encoded) > MAX_ENTRY_BYTES:
                raise JournalError("encoded journal entry exceeds the 1 MiB limit")
            if stream.tell() + len(encoded) > MAX_JOURNAL_BYTES:
                raise JournalError("journal would exceed the 32 MiB limit")
            os.write(stream.fileno(), encoded)
            os.fsync(stream.fileno())
            return entry
    except OSError as error:
        raise JournalError(f"cannot append journal entry: {error}") from error


_SECTION_TITLES = {
    "authorization": "Scope and authorization",
    "hypothesis": "Hypotheses",
    "action": "Activity log",
    "observation": "Observations",
    "finding": "Findings",
    "decision": "Decisions",
    "follow-up": "Follow-ups",
    "note": "Notes",
}


def _internal_markdown(
    metadata: dict[str, Any], verification: Verification
) -> str:
    lines = [
        f"# {metadata['title']} — internal assessment draft",
        "",
        "> Confidential working document. Privacy lint and human review are required before sharing.",
        "",
        "## Record integrity",
        "",
        f"- Owner: {metadata['owner']}",
        f"- Engagement created: {metadata['createdAt']}",
        f"- Verified journal entries: {len(verification.entries)}",
        f"- Final journal SHA-256: `{verification.final_sha256 or 'empty'}`",
        f"- Missing or unsafe evidence references: {len(verification.missing_evidence)}",
        "",
        "## Executive summary",
        "",
        "_Write after findings are validated and severity is agreed._",
        "",
    ]
    if verification.missing_evidence:
        lines.extend(
            [
                "### Evidence references requiring attention",
                "",
                *[
                    f"- `{reference}`"
                    for reference in verification.missing_evidence
                ],
                "",
            ]
        )
    for kind in KINDS:
        entries = [entry for entry in verification.entries if entry["kind"] == kind]
        lines.extend([f"## {_SECTION_TITLES[kind]}", ""])
        if not entries:
            lines.extend(["_No entries recorded._", ""])
            continue
        for entry in entries:
            lines.append(
                f"### {entry['sequence']}. {entry['summary']}"
            )
            lines.extend(["", f"- Recorded: {entry['recordedAt']}"])
            if entry["tags"]:
                lines.append("- Tags: " + ", ".join(f"`{tag}`" for tag in entry["tags"]))
            if entry["evidence"]:
                lines.append(
                    "- Evidence: "
                    + ", ".join(f"`{reference}`" for reference in entry["evidence"])
                )
            if entry["detail"]:
                lines.extend(["", entry["detail"]])
            lines.append("")
    lines.extend(
        [
            "## Report completion checklist",
            "",
            "- [ ] Validate each candidate finding independently.",
            "- [ ] Separate observed facts from inference and unknowns.",
            "- [ ] Include exact affected scope and reproduction ceilings.",
            "- [ ] Link every technical claim to retained evidence.",
            "- [ ] Remove credentials, tokens, subscriber identifiers, private addresses, and decoded audio.",
            "- [ ] Run evidence privacy lint and obtain Quad's disclosure approval.",
            "- [ ] Record remediation status and retest results.",
            "",
        ]
    )
    return "\n".join(lines)


def _public_markdown(verification: Verification) -> str:
    del verification
    return "\n".join(
        [
            "# Security assessment publication outline",
            "",
            "> This outline intentionally contains no journal text, target identifiers, evidence paths, or technical findings.",
            "",
            "## Private source record",
            "",
            "- Verify the private journal before drafting.",
            "- Select only validated facts that received explicit disclosure approval.",
            "- Do not copy private source material into this scaffold automatically.",
            "",
            "## Suggested article structure",
            "",
            "1. Engagement context and written authorization",
            "2. System architecture at an approved level of abstraction",
            "3. Safety constraints and traffic ceilings",
            "4. Test methodology",
            "5. Validated findings approved for disclosure",
            "6. Defensive changes and retest results",
            "7. General lessons for voice-platform engineering",
            "",
            "## Publication gate",
            "",
            "- [ ] Quad approved the exact disclosure text.",
            "- [ ] Every finding was validated and remediation status confirmed.",
            "- [ ] Names, addresses, credentials, tokens, subscriber data, Call-IDs, and audio were removed.",
            "- [ ] Screenshots and packet excerpts received separate privacy review.",
            "- [ ] Claims distinguish observed evidence, inference, and unknowns.",
            "- [ ] The publication does not provide unsafe operational details for an unpatched system.",
            "",
        ]
    )


def render(root: str | Path, *, audience: str) -> str:
    path = Path(root)
    metadata = _load_metadata(path)
    verification = verify(path)
    if audience == "internal":
        return _internal_markdown(metadata, verification)
    if audience == "public":
        return _public_markdown(verification)
    raise JournalError("audience must be internal or public")


def write_rendered(path: str | Path, content: str) -> None:
    output = Path(path)
    if output.exists():
        raise JournalError(f"refusing to overwrite existing output: {output}")
    if not output.parent.is_dir():
        raise JournalError(f"output parent does not exist: {output.parent}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
        output.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)
