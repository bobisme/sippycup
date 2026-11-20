"""`sippycup diagnose`: one page that says what happened to a run and what to do next.

Offline: reads the files a run directory holds and sends nothing.

Exit codes: 0 diagnosis written, 2 bad arguments or path, 4 the directory is not
a run Sippycup knows, 5 internal error or privacy lint refusal.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional, Sequence

from sippycup_workbench.summary_privacy import lint_text

from . import render
from .core import Diagnosis, work_relative
from .inputs import InputError, NotARun, detect_kind, make_redaction
from .ladder_bridge import Lazy, excerpt, pick_section

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_A_RUN = 4
EXIT_INTERNAL = 5

_FORBIDDEN = (
    ("crypto-key", re.compile(r"(?i)\ba=crypto\b|\binline:[A-Za-z0-9+/=]{8,}")),
    ("digest-parameter", re.compile(r"(?i)\b(?:nonce|cnonce|opaque|response)\s*=\s*\"?[A-Za-z0-9+/=_-]{4,}")),
    ("credential-header", re.compile(r"(?im)^\s*(?:proxy-)?(?:authorization|www-authenticate|proxy-authenticate)\s*:")),
)


class PrivacyLintError(RuntimeError):
    def __init__(self, hits: list) -> None:
        super().__init__("privacy lint failed")
        self.hits = hits


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sippycup diagnose",
        description=(
            "One page for a run that did not pass: what happened, how sure we are, whose side it is "
            "probably on, and what to do next. Offline: reads a run directory (guided call, matrix, "
            "campaign, or checks run), sends nothing."
        ),
        epilog=(
            "Exit codes: 0 written, 2 bad arguments or path, 4 not a run directory, "
            "5 internal error or privacy lint refusal."
        ),
    )
    parser.add_argument("run", metavar="RUN_DIR", nargs="?", help="a call, matrix, campaign, or checks run directory")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--brief", action="store_true", help="five lines for a status bar or the cockpit")
    parser.add_argument(
        "--compare", nargs=2, metavar=("RUN_A", "RUN_B"),
        help="compare two runs of the same call (for example a passing and a failing one)",
    )
    parser.add_argument("--output", metavar="FILE", help="write here instead of standard output (mode 0600)")
    parser.add_argument("--width", type=int, metavar="N", help="text width (default: 100; 60-300)")
    parser.add_argument("--no-ladder", action="store_true", help="skip the ladder excerpt (no capture is read)")
    parser.add_argument(
        "--approve", action="append", default=[], metavar="NET",
        help="address or CIDR whose addresses may be shown (repeatable); a run directory adds its own approved networks",
    )
    parser.add_argument(
        "--show-addresses", action="store_true",
        help="operator copy: show every address unredacted (do not attach to an owner report)",
    )
    return parser


def _fail(code: int, message: str) -> int:
    print(f"sippycup diagnose: {message}", file=sys.stderr)
    return code


def _write_output(path: Path, text: str) -> None:
    if path.is_symlink():
        raise OSError("refusing to write through a symbolic link")
    directory = path.parent if str(path.parent) else Path(".")
    descriptor, temporary = tempfile.mkstemp(dir=str(directory), prefix=".diagnose-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def attach_ladder(d: Diagnosis, ladder: Lazy, run_dir: Path, prefer: str, width: int) -> None:
    if not ladder.enabled:
        return
    document = ladder.document()
    if document is None:
        d.data["ladder"] = {"reason": d.red.text(ladder.reason or "no ladder", 200), "text": None}
        return
    section = pick_section(document, prefer)
    if section is None:
        d.data["ladder"] = {"reason": "the ladder found no section to draw", "text": None}
        return
    shown = excerpt(document, section, min(width, 110))
    shown["full"] = f"./bin/sippycup ladder {work_relative(run_dir)} --call-id-index {section.get('index')}"
    shown["reason"] = None
    d.data["ladder"] = shown
    for note in document.get("notes") or []:
        text = str(note)
        if "softphone log" in text and "capture was used" in text:
            continue
        d.gap("ladder: " + text)
    for warning in document.get("warnings") or []:
        d.gap("ladder warning: " + str(warning))


STAGE_SECTION = {
    "registration": "registration",
    "preflight": "options",
    "TLS": "options",
}


def diagnose(path: Path, arguments: argparse.Namespace, width: int):
    """Return (diagnosis dict, redaction) for one run directory."""
    kind = detect_kind(path)
    from . import callrun  # noqa: F401  (imported for side-effect-free error surfacing)

    if kind == "call":
        from .call import diagnose_call
        from .callrun import CallRun

        red = make_redaction([path], arguments.approve, arguments.show_addresses)
        run = CallRun(path)
        ladder = Lazy(path, arguments.show_addresses, arguments.approve, enabled=not arguments.no_ladder)
        d = diagnose_call(run, red, ladder)
        stage = d.data["stage"]
        attach_ladder(d, ladder, path, STAGE_SECTION.get(stage, "call"), width)
    elif kind == "matrix":
        from .matrix import diagnose_matrix

        d, red = diagnose_matrix(path, arguments)
    elif kind == "campaign":
        from .campaign import diagnose_campaign

        d, red = diagnose_campaign(path, arguments)
    else:
        from .checks import diagnose_checks

        d, red = diagnose_checks(path, arguments)
    d.finalize()
    _mark_overlap(d.data, path)
    d.data["runRef"] = work_relative(path.resolve())
    d.data["redaction"] = {
        "addresses": "operator copy: addresses shown, not for an owner report" if arguments.show_addresses
        else "approved addresses shown, others replaced by labels",
        "never": "credentials, nonces, crypto keys, user parts, Call-IDs, message bodies",
    }
    return d, red


def _mark_overlap(data: dict, path: Path) -> None:
    """A run that was active beside another run of its engagement (findings 6 and 8).

    The run started second carries the record (result ``overlap``). The run
    started first, or one of two started in the same instant, has none, so
    the times the sibling run directories recorded are compared too. Either
    way its capture, ladder, and oracle may hold the other run's packets, and
    the diagnosis says first that its verdict is unreliable.
    """
    from sippycup import run_overlap

    try:
        result = json.loads((path / "result.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        result = None
    overlap = result.get("overlap") if isinstance(result, dict) else None
    recorded = isinstance(overlap, dict)
    runs = []
    if recorded:
        runs = [str(item.get("name")) for item in overlap.get("activeRuns") or [] if isinstance(item, dict)]
    siblings = run_overlap.sibling_overlaps(path)
    if not recorded and not siblings:
        return
    runs += [name for name in siblings if name not in runs]
    beside = f" (beside {', '.join(runs[:4])}{', and more' if len(runs) > 4 else ''})" if runs else ""
    data["overlap"] = {"activeRuns": runs, "unreliable": True}
    data["outcome"] = (f"Another run was active; this verdict is unreliable{beside}: its capture and "
                       f"ladder may hold the other run's packets. Repeat it alone. " + str(data.get("outcome") or ""))


def lint_output(text: str, red, show: bool) -> list:
    hits = []
    for hit in lint_text("diagnose", text, addresses=red.book, allow_call_ids=False):
        if show and hit.code == "unapproved-address":
            continue
        hits.append((hit.path, hit.code))
    for number, line in enumerate(text.split("\n"), 1):
        for code, pattern in _FORBIDDEN:
            if pattern.search(line):
                hits.append((f"diagnose:line {number}", code))
    return hits


def run(arguments: argparse.Namespace) -> str:
    width = arguments.width
    if width is None:
        width = shutil.get_terminal_size((100, 24)).columns if sys.stdout.isatty() else 100
        width = max(60, min(width, 140))
    if not 60 <= width <= 300:
        raise InputError("--width must be between 60 and 300")
    if arguments.compare:
        from .compare import compare_runs

        if arguments.run:
            raise InputError("--compare takes the two runs itself; do not also name RUN_DIR")
        data, red = compare_runs(Path(arguments.compare[0]), Path(arguments.compare[1]), arguments)
        text = render.render_json(data) if arguments.format == "json" else render.render_compare_text(data, width)
    else:
        if not arguments.run:
            raise InputError("name a run directory (or use --compare RUN_A RUN_B)")
        d, red = diagnose(Path(arguments.run), arguments, width)
        run_ref = d.data["runRef"]
        if arguments.brief:
            if arguments.format == "json":
                import json

                text = json.dumps(render.brief_json(d.data, run_ref), indent=2, sort_keys=True) + "\n"
            else:
                text = render.render_brief_text(d.data, run_ref)
        elif arguments.format == "json":
            text = render.render_json(d.data)
        else:
            text = render.render_text(d.data, width)
    hits = lint_output(text, red, arguments.show_addresses)
    if hits:
        raise PrivacyLintError(hits)
    return text


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        text = run(arguments)
    except InputError as exc:
        return _fail(EXIT_USAGE, str(exc))
    except NotARun as exc:
        return _fail(EXIT_NOT_A_RUN, str(exc))
    except PrivacyLintError as exc:
        codes = sorted({code for _, code in exc.hits})
        where = ", ".join(sorted({path for path, _ in exc.hits})[:5])
        return _fail(EXIT_INTERNAL, f"privacy lint blocked the output ({', '.join(codes)} at {where}); nothing was written")
    except OSError as exc:
        return _fail(EXIT_USAGE, f"cannot read input: {exc}")
    if arguments.output:
        try:
            _write_output(Path(arguments.output), text)
        except OSError as exc:
            return _fail(EXIT_USAGE, f"cannot write {arguments.output}: {exc}")
        print(f"sippycup diagnose: wrote {arguments.format} diagnosis to {arguments.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
