"""Line-mode cockpit: plain prompts on any terminal, pipe, or TERM=dumb.

It never changes terminal modes, so there is nothing to restore on exit.
"""

from __future__ import annotations

import re
from typing import TextIO

from .actions import command_line
from .help_text import JOURNAL_NOTE_PRIVACY, LIVE_CONFIRMATION, SECRET_GUIDANCE, STAGES, keys_help, stage_help
from .render import render_confirmation, render_dashboard, render_run
from .runner import run_streaming
from .session import JOURNAL_KINDS, Session

PAGER_LINES = 400


class LineUI:
    def __init__(self, session: Session, stdin: TextIO, stdout: TextIO):
        self.session = session
        self.stdin = stdin
        self.stdout = stdout

    def say(self, text: str = "") -> None:
        self.stdout.write(text + "\n")
        self.stdout.flush()

    def ask(self, prompt: str) -> str | None:
        self.stdout.write(prompt)
        self.stdout.flush()
        line = self.stdin.readline()
        if line == "":
            return None
        return line.rstrip("\r\n")

    def show_dashboard(self) -> None:
        for line in render_dashboard(self.session.model, now=self.session.clock()):
            self.say(line)

    def loop(self) -> int:
        self.show_dashboard()
        while True:
            answer = self.ask("\ngo> [N action, rN run, sN stage, ? help, q quit, Enter refresh] ")
            if answer is None:
                self.say("")
                return 0
            answer = answer.strip()
            if answer in {"q", "quit", "exit"}:
                return 0
            if answer == "":
                self.session.refresh(probe_image=True)
                self.show_dashboard()
                continue
            if answer == "?":
                self.say(keys_help(line_mode=True))
                continue
            if answer == "skip":
                skipped = self.session.toggle_skip_practice()
                self.say("Practice stage " + ("skipped (preference saved in .cockpit.json)." if skipped
                                              else "is recommended again."))
                self.show_dashboard()
                continue
            match = re.fullmatch(r"([rs]?)\s*(\d+)", answer)
            if not match:
                self.say(f"Unknown input {answer!r}. Type ? for help.")
                continue
            prefix, number = match.group(1), int(match.group(2))
            if prefix == "s":
                if 1 <= number <= len(STAGES):
                    self.say(stage_help(STAGES[number - 1].identifier))
                else:
                    self.say(f"There are {len(STAGES)} stages.")
                continue
            if prefix == "r":
                if 1 <= number <= len(self.session.runs):
                    self.browse_run(self.session.runs[number - 1])
                else:
                    self.say("No such run.")
                continue
            chosen = self.session.action_numbered(number)
            if chosen is not None:
                self.perform(chosen)
                continue
            retired = self.session.retired_title(number)
            if retired:
                self.say(f"Action {number} ({retired}) is not offered now. Press Enter to see the current "
                         "list; numbers do not change during a session.")
            else:
                self.say("No such action.")

    # -- actions -------------------------------------------------------------
    def perform(self, action) -> None:
        self.say("")
        self.say("=" * 70)
        confirmation = self.session.prepare(action)
        for line in render_confirmation(confirmation):
            self.say(line)
        if confirmation.refused:
            self.say("Nothing was started.")
            return
        if confirmation.secret_needed:
            self.say(SECRET_GUIDANCE.format(path=confirmation.secret_default))
            choice = self.ask(f"Password source: 'file PATH' or 'env NAME' [file {confirmation.secret_default}]: ")
            if choice is None:
                return
            choice = choice.strip()
            if not choice or choice.lower() in {"y", "yes"}:
                choice = f"file {confirmation.secret_default}"  # Enter, or yes: take the offered default
            problem = self.session.apply_secret(confirmation, choice)
            if problem:
                self.say(f"[!!] {problem}. Nothing was started.")
                return
            self.say(f"Final command: {command_line(confirmation.argv)}")
        if confirmation.live:
            self.say(LIVE_CONFIRMATION.format(approval_hint=confirmation.approval_hint))
            typed = self.ask("Approval token: ")
            if typed is None or not typed.strip():
                self.say("Cancelled. Nothing was started.")
                return
            if not self.session.token_ok(confirmation, typed):
                self.say("[!!] The token does not match. Nothing was started.")
                return
        elif confirmation.needs_yes:
            typed = self.ask("Start it? [y/N] ")
            if (typed or "").strip().lower() not in {"y", "yes"}:
                self.say("Cancelled. Nothing was started.")
                return
        else:
            typed = self.ask("Press Enter to run it, or n to cancel: ")
            if typed is None or typed.strip().lower() in {"n", "no"}:
                self.say("Cancelled. Nothing was started.")
                return
        self.execute(confirmation.argv, env=confirmation.env)

    def execute(self, argv, *, env=None, stdin_data=None) -> None:
        before = self.session.run_paths()
        self.say(f"$ {command_line(argv)}")

        def interrupted():
            self.say("[Ctrl-C forwarded to the command; it stops and keeps its evidence]")

        code = run_streaming(self.session.runner, argv, lambda line: self.say(f"  | {line}"), env=env,
                             stdin_data=stdin_data, on_interrupt=interrupted)
        outcome = self.session.finish(before, code, argv)
        self.say(f"Exit code: {outcome.exit_code}")
        for run in outcome.new_runs:
            self.say(f"New run: {run['relative']} ({run['kind']}, verdict {run.get('verdict')})")
        self.say("")
        self.show_dashboard()

    # -- runs ----------------------------------------------------------------
    def browse_run(self, run) -> None:
        while True:
            value = self.session.run_detail(run)
            self.say("")
            for line in render_run(value):
                self.say(line)
            items = self.session.run_actions(run)
            self.say("Quick actions (all network-free):")
            for item in items:
                command = f"  -> {item['command']}" if item.get("command") else ""
                self.say(f"  {item['key']}  {item['title']}{command}")
            answer = self.ask("run> [letter, Enter back] ")
            if answer is None or not answer.strip():
                self.show_dashboard()
                return
            chosen = next((item for item in items if item["key"] == answer.strip()), None)
            if chosen is None:
                self.say("No such quick action.")
                continue
            if chosen["kind"] == "pager":
                lines = self.session.report_text(run)
                for line in lines[:PAGER_LINES]:
                    self.say(line)
                if len(lines) > PAGER_LINES:
                    self.say(f"[..] {len(lines) - PAGER_LINES} more lines in {run['relative']}/report.txt")
                continue
            if chosen["kind"] == "journal":
                self.say(JOURNAL_NOTE_PRIVACY)
                kind = self.ask(f"Kind ({', '.join(JOURNAL_KINDS)}) [observation]: ")
                if kind is None:
                    return
                kind = kind.strip() or "observation"
                if kind not in JOURNAL_KINDS:
                    self.say("[!!] Unknown kind. Nothing was recorded.")
                    continue
                note = self.ask("Note (one line, non-secret): ")
                if note is None or not note.strip():
                    self.say("Cancelled. Nothing was recorded.")
                    continue
                argv = self.session.journal_argv(run, kind)
                self.execute(argv, stdin_data=note.strip() + "\n")
                return
            typed = self.ask(f"Run {chosen['command']} ? [Enter runs, n cancels] ")
            if typed is None or typed.strip().lower() in {"n", "no"}:
                continue
            self.execute(chosen["argv"])
            return
