"""``./bin/sippycup go [DIR]``: the operator cockpit entry point."""

from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import sys
from pathlib import Path
from typing import TextIO

from .help_text import NO_ENGAGEMENT
from .model import to_json
from .probes import commands as registry_commands
from .probes import find_engagements, probe_image, record_build
from .render import render_dashboard
from .runner import SubprocessRunner, run_streaming
from .session import Session

DESCRIPTION = """\
Show where an engagement stands and walk through the next step.

The dashboard is built only from files on disk (scope, profile, journal,
runs, and work/practice records) plus a local image inspect; it sends no
traffic. Every action it offers is a separate ./bin/sippycup command shown
in full before it runs. Network-free actions run on Enter; [LIVE] actions
need the last 4 characters of the approval id typed, and the command's own
gates still apply.

With DIR omitted, the only engagement under work/ is used, candidates are
listed, or you are offered to create one. Without a terminal the dashboard
is printed as text (--plain) and ends with the single most important next
command.
"""
NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")


def _repo_default() -> Path:
    return Path(__file__).resolve().parents[2]


def _interactive(stdin: TextIO, stdout: TextIO) -> bool:
    try:
        return stdin.isatty() and stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _ask(stdin: TextIO, stdout: TextIO, prompt: str) -> str | None:
    stdout.write(prompt)
    stdout.flush()
    line = stdin.readline()
    return None if line == "" else line.strip()


def _create_engagement(repo: Path, stdin: TextIO, stdout: TextIO, runner) -> Path | None:
    stdout.write(NO_ENGAGEMENT + "\n")
    name = _ask(stdin, stdout, "New engagement name (a-z, 0-9, -; empty cancels): ")
    if not name:
        return None
    if not NAME.fullmatch(name):
        stdout.write("Names are lowercase letters, digits, and '-'.\n")
        return None
    title = _ask(stdin, stdout, f"Title [{name} security assessment]: ") or f"{name} security assessment"
    owner = _ask(stdin, stdout, "Service owner (who approves the scope): ")
    if not owner:
        stdout.write("An owner is required. Nothing was created.\n")
        return None
    directory = f"work/{name}"
    for argv in (
        ["./bin/sippycup", "journal", "init", directory, "--title", title, "--owner", owner],
        ["./bin/sippycup", "scope", "init", directory],
    ):
        stdout.write(f"$ {shlex.join(argv)}\n")
        code = run_streaming(runner, argv, lambda line: stdout.write(f"  | {line}\n"))
        if code != 0:
            stdout.write(f"Exit code {code}; stopping. (journal init may refuse an existing directory: "
                         "pick a new name.)\n")
            return repo / directory if (repo / directory / "engagement.json").is_file() else None
    return repo / directory


def resolve_engagement(args, repo: Path, stdin: TextIO, stdout: TextIO, runner, interactive: bool) -> Path | None:
    if args.engagement:
        path = Path(args.engagement)
        return path if path.is_absolute() else (Path.cwd() / path)
    candidates = find_engagements(repo)
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        stdout.write("Several engagements exist under work/:\n")
        for index, item in enumerate(candidates, 1):
            stdout.write(f"  {index}. work/{item.name}\n")
        if not interactive:
            stdout.write("Choose one: ./bin/sippycup go work/NAME\n")
            return None
        answer = _ask(stdin, stdout, "Number: ")
        if answer and answer.isdigit() and 1 <= int(answer) <= len(candidates):
            return candidates[int(answer) - 1]
        return None
    if not interactive:
        stdout.write(NO_ENGAGEMENT + "\n")
        stdout.write("Next: ./bin/sippycup journal init work/NAME --title TITLE --owner OWNER\n")
        stdout.write("Then: ./bin/sippycup scope init work/NAME\n")
        return None
    return _create_engagement(repo, stdin, stdout, runner)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="./bin/sippycup go", description=DESCRIPTION, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("engagement", nargs="?", metavar="DIR", help="engagement directory, e.g. work/NAME")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plain", action="store_true", help="print the dashboard as text and exit")
    mode.add_argument("--line", action="store_true", help="interactive line-mode prompts (no full screen)")
    mode.add_argument("--format", choices=("text", "json"), help="print the dashboard model and exit")
    parser.add_argument("--no-runtime", action="store_true",
                        help="do not ask the container runtime about the image (shown as unknown)")
    parser.add_argument("--image", default=os.environ.get("SIPPYCUP_IMAGE", "localhost/sippycup:latest"),
                        help="toolbox image to check (default: $SIPPYCUP_IMAGE or localhost/sippycup:latest)")
    parser.add_argument("--repo", type=Path, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--record-build", metavar="IMAGE", help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None, *, stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    args = build_parser().parse_args(argv)
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    repo = (args.repo or _repo_default()).resolve()
    if args.record_build:
        # Called by `make build`: remember which input fingerprint this image holds.
        try:
            path = record_build(repo, args.record_build)
        except (OSError, RuntimeError) as exc:
            sys.stderr.write(f"could not record the image build: {exc}\n")
            return 1
        stdout.write(f"Recorded image build: {path.relative_to(repo)}\n")
        return 0
    runner = SubprocessRunner(repo)
    batch = args.plain or args.format is not None
    interactive = not batch and (args.line or _interactive(stdin, stdout))
    engagement = resolve_engagement(args, repo, stdin, stdout, runner, interactive)
    if engagement is None:
        return 2
    engagement = engagement.resolve()
    os.chdir(repo)
    probe = None if args.no_runtime else (lambda: probe_image(repo, args.image))
    session = Session(repo, engagement, runner=runner, image_probe=probe, commands=registry_commands(repo))
    if args.format == "json":
        stdout.write(to_json(session.model) + "\n")
        return 0
    if batch or not interactive:
        for line in render_dashboard(session.model, now=session.clock(), all_steps=True):
            stdout.write(line + "\n")
        return 0
    use_curses = (
        not args.line
        and _interactive(stdin, stdout)
        and os.environ.get("TERM", "dumb") not in {"", "dumb", "unknown"}
    )
    if use_curses:
        size = shutil.get_terminal_size((0, 0))
        from .tui import MIN_COLS, MIN_LINES

        use_curses = size.columns >= MIN_COLS and size.lines >= MIN_LINES
    if use_curses:
        try:
            import curses  # noqa: F401
        except ImportError:
            use_curses = False
    if use_curses:
        from .tui import run_curses

        try:
            return run_curses(session)
        except KeyboardInterrupt:
            return 130
    from .line import LineUI

    try:
        return LineUI(session, stdin, stdout).loop()
    except KeyboardInterrupt:
        stdout.write("\n")
        return 130
