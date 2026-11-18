"""`sippycup ladder`: redacted SIP and media ladder diagram, offline only.

Exit codes follow the capture oracle (`sippycup assert`):
0 drawn, 2 unusable arguments or input path, 3 unreadable capture,
4 nothing to draw (no SIP, TLS or media), 5 internal error or privacy lint.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional, Sequence

from sippycup_workbench.summary_privacy import AddressBook, lint_text

from .build import Redactor, build_document
from .capture import LadderCaptureError, read_media, read_signaling
from .inputs import InputError, Inputs, resolve
from .model import CaptureData
from .render_html import render_html
from .render_text import render_text
from .softphone_log import read_log

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_BAD_CAPTURE = 3
EXIT_NOTHING = 4
EXIT_INTERNAL = 5

# Content that must never reach any rendering, whatever the address policy.
import re  # noqa: E402

_FORBIDDEN_PATTERNS = (
    ("crypto-key", re.compile(r"(?i)\ba=crypto\b|\binline:[A-Za-z0-9+/=]{8,}")),
    ("digest-parameter", re.compile(r"(?i)\b(?:nonce|cnonce|opaque|response)\s*=\s*\"?[A-Za-z0-9+/=_-]{4,}")),
    ("credential-header", re.compile(r"(?im)^\s*(?:proxy-)?(?:authorization|www-authenticate|proxy-authenticate)\s*:")),
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sippycup ladder",
        description=(
            "Draw a redacted SIP and media ladder (sequence) diagram from a run "
            "directory or a capture. Offline: reads files, sends nothing."
        ),
        epilog=(
            "Exit codes: 0 drawn, 2 bad arguments or input path, 3 unreadable capture, "
            "4 nothing to draw (no SIP, TLS, or media found), 5 internal error or privacy lint failure."
        ),
    )
    parser.add_argument("source", metavar="RUN_DIR|CAPTURE", help="run directory, or a .pcap/.pcapng capture")
    parser.add_argument("--format", choices=("text", "html", "json"), default="text")
    parser.add_argument("--output", metavar="FILE", help="write here instead of standard output (mode 0600)")
    parser.add_argument(
        "--call-id-index",
        type=int,
        metavar="N",
        help="draw only section N (1-based, in the order shown); default draws all",
    )
    parser.add_argument("--width", type=int, metavar="N", help="text width (default: terminal width, 100 when piped; 60-300)")
    parser.add_argument(
        "--approve",
        action="append",
        default=[],
        metavar="NET",
        help="address or CIDR whose addresses may be shown (repeatable); run directories add their own approved networks",
    )
    parser.add_argument(
        "--show-addresses",
        action="store_true",
        help="operator copy: show every address unredacted (marked on the output; do not attach to an owner report)",
    )
    return parser


def _fail(code: int, message: str) -> int:
    print(f"sippycup ladder: {message}", file=sys.stderr)
    return code


def _write_output(path: Path, text: str) -> None:
    if path.is_symlink():
        raise OSError("refusing to write through a symbolic link")
    directory = path.parent if str(path.parent) else Path(".")
    descriptor, temporary = tempfile.mkstemp(dir=str(directory), prefix=".ladder-", suffix=".tmp")
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


def _align_log(messages_epoch_first: float, capture: Optional[CaptureData]) -> int:
    """Whole-hour shift that places the log inside the capture window, else 0."""
    if capture is None or capture.first_t is None or capture.last_t is None:
        return 0
    low, high = capture.first_t - 5, capture.last_t + 5
    if low <= messages_epoch_first <= high:
        return 0
    guess = round((capture.first_t - messages_epoch_first) / 3600)
    if guess and abs(guess) <= 26 and low <= messages_epoch_first + guess * 3600 <= high:
        return guess
    return 0


def run(arguments: argparse.Namespace) -> tuple:
    """Return (exit code, text or None)."""
    width = arguments.width
    if width is None:
        width = shutil.get_terminal_size((100, 24)).columns if sys.stdout.isatty() else 100
    if not 60 <= width <= 300:
        raise InputError("--width must be between 60 and 300")
    if arguments.call_id_index is not None and arguments.call_id_index < 1:
        raise InputError("--call-id-index must be 1 or greater")
    inputs: Inputs = resolve(arguments.source)

    book = AddressBook()
    approved = list(inputs.approved)
    for network in arguments.approve:
        if not book.add_network(network):
            raise InputError(f"--approve {network!r} is not an address or CIDR")
        approved.append(network)
    for network in inputs.approved:
        book.add_network(network)
    book.assessor.update(a for a in inputs.assessor if not book.approved(a))
    redactor = Redactor(book, arguments.show_addresses)

    notes: list = []
    capture: Optional[CaptureData] = None
    if inputs.capture is not None:
        capture = read_signaling(inputs.capture)
    log_messages: list = []
    if inputs.log is not None:
        try:
            base = inputs.run_date
            if capture is not None and capture.first_t is not None:
                base = dt.datetime.fromtimestamp(capture.first_t, dt.timezone.utc).date()
            if base is None:
                base = dt.datetime.fromtimestamp(inputs.log.stat().st_mtime, dt.timezone.utc).date()
            log_messages = read_log(inputs.log, base_date=base)
            if log_messages:
                shift = _align_log(log_messages[0].t, capture)
                if shift:
                    log_messages = read_log(inputs.log, base_date=base, tz_shift_hours=shift)
                    notes.append(f"softphone log clock was {shift:+d} h from the capture clock; shifted to align")
        except OSError as exc:
            notes.append(f"softphone log could not be read ({type(exc).__name__}); ignored")
    capture_has_sip = bool(capture and capture.sip)
    if log_messages and capture_has_sip and capture and not any(e.kind == "appdata" for e in capture.tls):
        notes.append("softphone log present but the capture has plain SIP; the capture was used")
        log_messages = []

    flows: list = []
    if inputs.capture is not None:
        ports = set()
        for message in list(capture.sip if capture else []) + log_messages:
            if message.sdp:
                for media in message.sdp.media:
                    if media.port:
                        ports.add(media.port)
                        ports.add(media.port + 1)
        heuristic = not ports
        flows = read_media(inputs.capture, decode_ports=ports, heuristic=heuristic)
    if capture is None and log_messages:
        notes.append("no capture: media and transport rows are not available")

    source = {
        "capture": inputs.capture.name if inputs.capture else None,
        "softphoneLog": inputs.log.name if inputs.log and log_messages else None,
        "run": inputs.run_dir.resolve().name if inputs.run_dir else None,
    }
    if not (capture and (capture.sip or capture.tls)) and not log_messages and not flows:
        raise LookupError(
            "nothing to draw: no SIP signaling, TLS connections, or RTP found in "
            + (inputs.capture.name if inputs.capture else str(arguments.source))
        )
    try:
        document = build_document(
            capture=capture,
            log_messages=log_messages,
            flows=flows,
            redactor=redactor,
            source=source,
            approved_networks=approved,
            call_index=arguments.call_id_index,
            notes=notes,
        )
    except IndexError as exc:
        raise InputError(str(exc)) from exc
    if not document["sections"]:
        raise LookupError("nothing to draw: the capture has no SIP, TLS, or RTP evidence")
    if arguments.format == "json":
        text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    elif arguments.format == "html":
        text = render_html(document, render_text(document, 110))
    else:
        text = render_text(document, width)
    hits = lint_output(text, book, arguments.show_addresses)
    if hits:
        raise PrivacyLintError(hits)
    return EXIT_OK, text


class PrivacyLintError(RuntimeError):
    def __init__(self, hits: list) -> None:
        super().__init__("privacy lint failed")
        self.hits = hits


def lint_output(text: str, book: AddressBook, show_addresses: bool) -> list:
    """Fail-closed check of a finished rendering. Reports codes and lines, never values."""
    hits = []
    for hit in lint_text("ladder", text, addresses=book, allow_call_ids=False):
        if show_addresses and hit.code == "unapproved-address":
            continue
        hits.append((hit.path, hit.code))
    for number, line in enumerate(text.split("\n"), 1):
        for code, pattern in _FORBIDDEN_PATTERNS:
            if pattern.search(line):
                hits.append((f"ladder:line {number}", code))
    return hits


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        code, text = run(arguments)
    except InputError as exc:
        return _fail(EXIT_USAGE, str(exc))
    except LadderCaptureError as exc:
        return _fail(exc.code, str(exc))
    except LookupError as exc:
        return _fail(EXIT_NOTHING, str(exc))
    except PrivacyLintError as exc:
        codes = sorted({code for _, code in exc.hits})
        where = ", ".join(sorted({path for path, _ in exc.hits})[:5])
        return _fail(
            EXIT_INTERNAL,
            f"privacy lint blocked the output ({', '.join(codes)} at {where}); nothing was written",
        )
    except OSError as exc:
        return _fail(EXIT_BAD_CAPTURE, f"cannot read input: {exc}")
    if arguments.output:
        try:
            _write_output(Path(arguments.output), text)
        except OSError as exc:
            return _fail(EXIT_USAGE, f"cannot write {arguments.output}: {exc}")
        print(f"sippycup ladder: wrote {arguments.format} ladder to {arguments.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
