"""``./bin/sippycup summary DIR``: write the owner-facing engagement report.

Exit status:
  0  report written; no integrity exceptions (or --allow-exceptions)
  1  report written; integrity exceptions are listed at its top
  2  usage or input error (nothing written), or the --journal append failed
     after the report was written
  3  privacy lint failed on the model or a rendering; nothing written
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from .journal import JournalError, append as append_journal
from .summary_model import Options, build_report, iso, parse_time
from .summary_privacy import lint_model, lint_text
from .summary_render import render_html, render_markdown, render_text

FILES = {
    "md": "engagement-report.md",
    "html": "engagement-report.html",
    "text": "engagement-report.txt",
    "json": "report.json",
}
MAX_FORBID_BYTES = 4096


class UsageError(ValueError):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="./bin/sippycup summary",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Assemble an owner-facing engagement report from an engagement\n"
            "directory and its run directories: what was approved, what ran,\n"
            "what happened, what was found, and what to fix. It reads recorded\n"
            "artifacts only and fails closed on any privacy lint hit."
        ),
        epilog=(
            "Exit status: 0 written; 1 written with integrity exceptions\n"
            "(0 with --allow-exceptions); 2 usage or input error; 3 privacy\n"
            "lint failed and nothing was written. See docs/ENGAGEMENT-REPORT.md.\n"
            "Network activity: none"
        ),
    )
    parser.add_argument("directory", metavar="DIR", help="engagement directory (journal, scope, profiles, runs)")
    parser.add_argument("--output", metavar="PATH", help="output directory (default DIR/report; a new DIR/report-STAMP when that exists)")
    parser.add_argument(
        "--format",
        action="append",
        choices=("md", "html", "json", "text"),
        help="rendering to write; repeatable (default md and html). report.json, the model, is always written",
    )
    parser.add_argument("--audience", choices=("owner", "internal"), default="owner")
    parser.add_argument("--runs", nargs="+", action="extend", default=[], metavar="GLOB", help="only runs whose name or relative path matches")
    parser.add_argument("--since", metavar="TIME", help="only runs that started at or after this RFC 3339 time")
    parser.add_argument("--title", metavar="TEXT", help="report title (default: the engagement title)")
    parser.add_argument("--generated-at", metavar="TIME", help="fixed generation time (RFC 3339) for reproducible output")
    parser.add_argument("--run-root", action="append", default=[], metavar="DIR", help="extra directory of run directories; repeatable")
    parser.add_argument("--matrix-root", action="append", default=[], metavar="DIR", help="extra directory of matrix run directories (each holds matrix.json); repeatable. DIR/matrix and matrix/ beside each profile are read without it")
    parser.add_argument("--profile", action="append", default=[], metavar="PATH", help="extra target profile to treat as an authorization record")
    parser.add_argument("--manifest", action="append", default=[], metavar="PATH", help="extra campaign manifest to treat as an authorization record")
    parser.add_argument("--include-journal-notes", action="store_true", help="include journal entry detail text (sanitized)")
    parser.add_argument(
        "--forbid-file",
        action="append",
        default=[],
        metavar="PATH",
        help="file holding a value (such as the account password) that must not appear anywhere in the report; compared only, never stored",
    )
    parser.add_argument("--force", action="store_true", help="replace the report files in an existing output directory")
    parser.add_argument("--allow-exceptions", action="store_true", help="exit 0 even when integrity exceptions are present")
    parser.add_argument("--journal", action="store_true", help="append a journal action entry recording the report.json hash")
    return parser


def _cli_version() -> str | None:
    override = os.environ.get("SIPPYCUP_CLI_VERSION")
    if override and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", override):
        return override
    launcher = Path(__file__).resolve().parents[2] / "bin" / "sippycup"
    try:
        text = launcher.read_text(encoding="utf-8")[:4096]
    except OSError:
        return None
    match = re.search(r'readonly cli_version="([0-9]+\.[0-9]+\.[0-9]+)"', text)
    return match.group(1) if match else None


def _time(value: str | None, name: str) -> datetime | None:
    if value is None:
        return None
    parsed = parse_time(value)
    if parsed is None:
        raise UsageError(f"{name} must be an RFC 3339 time with a timezone")
    return parsed


def _forbidden(paths: Sequence[str]) -> tuple[str, ...]:
    values = []
    for name in paths:
        path = Path(name)
        try:
            info = path.lstat()
        except OSError as error:
            raise UsageError(f"cannot read --forbid-file {name}: {error.strerror}") from error
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FORBID_BYTES:
            raise UsageError(f"--forbid-file {name} must be a regular file of at most {MAX_FORBID_BYTES} bytes")
        value = path.read_text(encoding="utf-8", errors="replace").strip()
        if len(value) < 4:
            raise UsageError(f"--forbid-file {name} holds fewer than 4 characters")
        values.append(value)
    return tuple(values)


def _stamp(value: str) -> str:
    return re.sub(r"[^0-9TZ]", "", value)


def _output_directory(root: Path, requested: str | None, generated: str, force: bool) -> tuple[Path, bool]:
    """Return (directory, existing). Never silently replaces a report."""
    if requested is not None:
        target = Path(requested)
        if not target.parent.is_dir():
            raise UsageError(f"output parent does not exist: {target.parent}")
        if target.is_symlink():
            raise UsageError("output must not be a symlink")
        if target.exists():
            if not target.is_dir():
                raise UsageError(f"output is not a directory: {target}")
            if any(target.iterdir()) and not force:
                raise UsageError(f"output directory is not empty: {target} (use --force to replace its report files)")
            return target, True
        return target, False
    default = root / "report"
    if default.is_symlink():
        raise UsageError("DIR/report must not be a symlink")
    if not default.exists() or (default.is_dir() and not any(default.iterdir())):
        return default, default.exists()
    if force:
        if not default.is_dir():
            raise UsageError(f"{default} is not a directory")
        return default, True
    base = root / f"report-{_stamp(generated)}"
    candidate = base
    counter = 2
    while candidate.exists() or candidate.is_symlink():
        candidate = Path(f"{base}-{counter}")
        counter += 1
    return candidate, False


def _write_file(path: Path, content: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _write_all(directory: Path, existing: bool, outputs: dict[str, str]) -> None:
    if existing:
        for name, content in outputs.items():
            _write_file(directory / name, content)
        return
    staging = Path(tempfile.mkdtemp(prefix=f".{directory.name}.", dir=directory.parent))
    try:
        os.chmod(staging, 0o700)
        for name, content in outputs.items():
            _write_file(staging / name, content)
        os.rename(staging, directory)
    except OSError:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _display(path: Path, given: str, root: Path) -> str:
    try:
        return str(Path(given) / path.resolve().relative_to(root))
    except ValueError:
        return str(path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        root_path = Path(args.directory)
        if root_path.is_symlink() or not root_path.is_dir():
            raise UsageError(f"engagement directory does not exist: {args.directory}")
        root = root_path.resolve()
        generated = _time(args.generated_at, "--generated-at") or datetime.now(timezone.utc)
        generated_text = iso(generated)
        options = Options(
            audience=args.audience,
            include_journal_notes=args.include_journal_notes,
            run_globs=tuple(args.runs),
            since=_time(args.since, "--since"),
            title=args.title,
            generated_at=generated_text,
            run_roots=tuple(Path(p) for p in args.run_root),
            matrix_roots=tuple(Path(p) for p in args.matrix_root),
            profiles=tuple(Path(p) for p in args.profile),
            manifests=tuple(Path(p) for p in args.manifest),
            forbidden=_forbidden(args.forbid_file),
            cli_version=_cli_version(),
        )
        for extra in list(options.run_roots) + list(options.matrix_roots) + list(options.profiles) + list(options.manifests):
            if not extra.exists():
                raise UsageError(f"path does not exist: {extra}")
        formats = sorted(set(args.format or ["md", "html"]))
        model, ctx = build_report(root, options)
        report_json = json.dumps(model, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        report_sha = hashlib.sha256(report_json.encode("utf-8")).hexdigest()
        outputs = {FILES["json"]: report_json}
        if "md" in formats:
            outputs[FILES["md"]] = render_markdown(model, report_sha)
        if "html" in formats:
            outputs[FILES["html"]] = render_html(model, report_sha)
        if "text" in formats:
            outputs[FILES["text"]] = render_text(model, report_sha)
        hits = lint_model(model, addresses=ctx.addresses, forbidden=ctx.forbidden, allow_call_ids=ctx.allow_call_ids)
        for name, content in sorted(outputs.items()):
            if name == FILES["json"]:
                continue
            hits.extend(lint_text(name, content, addresses=ctx.addresses, forbidden=ctx.forbidden, allow_call_ids=ctx.allow_call_ids))
        if hits:
            unique = sorted({(hit.path, hit.code) for hit in hits})
            print(
                f"privacy lint failed: {len(unique)} field(s) would disclose protected material; nothing was written",
                file=sys.stderr,
            )
            for path, code in unique[:50]:
                print(f"  {path}: {code}", file=sys.stderr)
            if len(unique) > 50:
                print(f"  ... {len(unique) - 50} more", file=sys.stderr)
            print("Network activity: none", file=sys.stderr)
            return 3
        directory, existing = _output_directory(root, args.output, generated_text, args.force)
        _write_all(directory, existing, outputs)
    except UsageError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"error: cannot write the report: {error}", file=sys.stderr)
        return 2
    shown = _display(directory, args.directory, root)
    counts = model["runCounts"]
    derived = sum(1 for f in model["findings"] if f["derived"])
    print(f"Engagement report: {shown}")
    print("  Files: " + ", ".join(sorted(outputs)) + " (mode 0600)")
    print(f"  report.json SHA-256: {report_sha}")
    print(
        f"  Runs: {len(model['runs'])} ({counts['call']} calls, {counts['campaign']} campaigns, "
        f"{counts['check']} check runs); findings: {len(model['findings']) - derived}; derived observations: {derived}"
    )
    exceptions = model["integrityExceptions"]
    print(f"  Integrity exceptions: {len(exceptions)}")
    for item in exceptions[:20]:
        print(f"    [{item['code']}] {item['run'] or '-'}: {item['detail']}")
    status = 1 if exceptions and not args.allow_exceptions else 0
    if args.journal:
        evidence = []
        for name in sorted(outputs):
            try:
                evidence.append((directory / name).resolve().relative_to(root).as_posix())
            except ValueError:
                pass
        try:
            entry = append_journal(
                root,
                kind="action",
                summary=f"Rendered the {args.audience} engagement report; report.json sha256 {report_sha}",
                evidence=evidence,
                tags=["engagement-report"],
            )
        except JournalError as error:
            print(f"error: report written, but the journal entry failed: {error}", file=sys.stderr)
            print("Network activity: none")
            return 2
        print(f"  Journal entry {entry['sequence']}: {entry['entrySha256']}")
    print("Network activity: none")
    return status


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
