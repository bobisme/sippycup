"""Full-screen curses cockpit (standard library only).

The screen shows the same model as plain and line modes. Every exit path,
including exceptions and SIGTERM, goes through ``curses.wrapper``'s
``endwin()`` so the terminal is restored. While a command runs, its output
streams into a scrollable pane and Ctrl-C is forwarded to it.
"""

from __future__ import annotations

import curses
import os
import signal
from typing import Any

from .actions import command_line
from .help_text import JOURNAL_NOTE_PRIVACY, LIVE_CONFIRMATION, SECRET_GUIDANCE, STAGES, keys_help, stage_help
from .render import (
    STAGE_MARKER, _image_line, _journal_line, _practice_line, _scope_lines, _target_line,
    live_authorization, render_confirmation, render_run, run_line, step_marker,
)
from .session import JOURNAL_KINDS, Session

MIN_COLS = 60
MIN_LINES = 20
MAX_OUTPUT_LINES = 5000
MARK_COLORS = {"[ok]": 1, "[!!]": 2, "[LIVE]": 3, "[>>]": 4, "[??]": 3}


class TerminalTooSmall(Exception):
    pass


def usable(lines: int, cols: int) -> bool:
    return lines >= MIN_LINES and cols >= MIN_COLS


class CursesUI:
    def __init__(self, session: Session, screen, *, color: bool):
        self.session = session
        self.screen = screen
        self.color = color
        self.focus = "actions"
        self.selected = {"actions": 0, "runs": 0}
        self.message = ""
        self.help_visible = False

    # -- drawing -------------------------------------------------------------
    def put(self, y: int, x: int, text: str, attr: int = 0) -> None:
        lines, cols = self.screen.getmaxyx()
        if y < 0 or y >= lines or x >= cols:
            return
        width = cols - x - (1 if y == lines - 1 else 0)
        if width <= 0:
            return
        if len(text) > width:
            text = text[: max(0, width - 1)] + "~"
        try:
            self.screen.addstr(y, x, text, attr)
        except curses.error:
            return
        if self.color:
            for token, pair in MARK_COLORS.items():
                start = text.find(token)
                while start != -1:
                    try:
                        self.screen.addstr(y, x + start, token, curses.color_pair(pair) | curses.A_BOLD | attr)
                    except curses.error:
                        pass
                    start = text.find(token, start + 1)

    def draw_dashboard(self) -> None:
        screen = self.screen
        screen.erase()
        lines, cols = screen.getmaxyx()
        model = self.session.model
        now = self.session.clock()
        auth = live_authorization(model["authorization"], now)
        self.put(0, 0, f" Sippycup cockpit  {model['engagement']['display']}".ljust(cols), curses.A_REVERSE)
        self.put(0, max(0, cols - 22), "? help  q quit ", curses.A_REVERSE)
        self.put(1, 0, f"Auth    {auth.get('marker', '[??]')} {auth.get('text')}  id: {auth.get('approvalId') or 'none'}")
        self.put(2, 0, f"Scope   {_scope_lines(model['scope'], limit=0)[0]}")
        self.put(3, 0, f"Target  {_target_line(model['target'])}")
        self.put(4, 0, f"Image   {_image_line(model['readiness']['image'])}")
        self.put(5, 0, f"Prac.   {_practice_line(model['readiness']['practice'], now)}")
        self.put(6, 0, f"Journal {_journal_line(model['journal'])}")
        self.put(7, 0, "-" * (cols - 1))
        left = 28
        y = 8
        self.put(y, 0, "Stages", curses.A_BOLD)
        for stage in model["stages"]:
            y += 1
            attr = curses.A_BOLD if stage["state"] == "current" else 0
            self.put(y, 0, f"{STAGE_MARKER[stage['state']]} {stage['number']} {stage['title']}", attr)
        current = next((stage for stage in model["stages"] if stage["state"] == "current"), None)
        if current:
            y += 1
            for step in current["steps"]:
                y += 1
                if y >= lines - 2:
                    break
                self.put(y, 0, f" {step_marker(step['done'])} {step['label']}"[:left - 1])
        tabs = f"{'[Actions]' if self.focus == 'actions' else ' Actions '} {'[Runs]' if self.focus == 'runs' else ' Runs '}  (Tab)"
        self.put(8, left, tabs, curses.A_BOLD)
        items = self.items()
        top = 9
        bottom = lines - 4
        visible = max(1, bottom - top)
        index = self.selected[self.focus]
        start = max(0, min(index - visible + 1, len(items) - visible)) if index >= visible else 0
        for offset, item in enumerate(items[start:start + visible]):
            row = start + offset
            text = self.item_text(row, item)
            attr = curses.A_REVERSE if row == index else 0
            self.put(top + offset, left, text.ljust(cols - left - 1), attr)
        if not items:
            self.put(top, left, "none")
        chosen = items[index] if items and index < len(items) else None
        footer = ""
        if chosen is not None and self.focus == "actions":
            footer = chosen.get("command") or chosen.get("instruction") or chosen.get("unavailableReason") or ""
        elif chosen is not None:
            footer = chosen.get("reason") or ""
        self.put(lines - 3, 0, "-" * (cols - 1))
        self.put(lines - 2, 0, f"> {footer}")
        self.put(lines - 1, 0, self.message or f"Next: {model['nextCommand'] or 'see manual steps'}")
        screen.refresh()

    def items(self) -> list[dict[str, Any]]:
        return self.session.actions if self.focus == "actions" else self.session.runs

    def item_text(self, row: int, item: dict[str, Any]) -> str:
        if self.focus == "actions":
            flag = "" if item["available"] else " [!!]"
            return f"{row + 1:>2} {item['label']:9} {item['title']}{flag}"
        return run_line(row + 1, item)

    def panel(self, title: str, lines: list[str], *, footer: str = "Esc/q close  Up/Down/PgUp/PgDn scroll") -> None:
        """Scrollable full-screen text panel; returns on Esc, q, or Enter."""
        offset = 0
        while True:
            self.screen.erase()
            rows, cols = self.screen.getmaxyx()
            wrapped = _wrap(lines, cols - 2)
            self.put(0, 0, f" {title}".ljust(cols), curses.A_REVERSE)
            height = rows - 2
            offset = max(0, min(offset, max(0, len(wrapped) - height)))
            for row, text in enumerate(wrapped[offset:offset + height]):
                self.put(1 + row, 1, text)
            self.put(rows - 1, 0, footer[: cols - 1], curses.A_REVERSE)
            self.screen.refresh()
            key = self.screen.getch()
            if key in (27, ord("q"), 10, 13, curses.KEY_ENTER):
                return
            if key == curses.KEY_RESIZE:
                curses.update_lines_cols()
            elif key in (curses.KEY_DOWN, ord("j")):
                offset += 1
            elif key in (curses.KEY_UP, ord("k")):
                offset -= 1
            elif key == curses.KEY_NPAGE:
                offset += height
            elif key == curses.KEY_PPAGE:
                offset -= height

    def prompt(self, lines: list[str], question: str) -> str | None:
        """Show ``lines`` and read one typed line; Esc cancels (returns None)."""
        typed = ""
        _cursor(1)
        try:
            while True:
                self.screen.erase()
                rows, cols = self.screen.getmaxyx()
                wrapped = _wrap(lines, cols - 2)
                height = rows - 3
                shown = wrapped[-height:] if len(wrapped) > height else wrapped
                for row, text in enumerate(shown):
                    self.put(row, 1, text)
                self.put(rows - 2, 0, question[: cols - 1], curses.A_BOLD)
                self.put(rows - 1, 0, "> " + typed[-(cols - 4):])
                self.screen.refresh()
                try:
                    key = self.screen.get_wch()
                except curses.error:
                    # The dashboard loop sets a one-second input timeout for
                    # its countdown; here no key yet just means keep waiting.
                    continue
                if key == "\x1b":
                    return None
                if key in ("\n", "\r") or key == curses.KEY_ENTER:
                    return typed
                if key in (curses.KEY_BACKSPACE, "\x7f", "\b"):
                    typed = typed[:-1]
                elif key == curses.KEY_RESIZE:
                    curses.update_lines_cols()
                elif isinstance(key, str) and key.isprintable() and len(typed) < 200:
                    typed += key
        finally:
            _cursor(0)

    # -- flows ---------------------------------------------------------------
    def perform(self, action: dict[str, Any]) -> None:
        confirmation = self.session.prepare(action)
        lines = render_confirmation(confirmation)
        if confirmation.refused:
            self.panel("Refused - nothing was started", lines + ["", "Nothing was started."])
            return
        if confirmation.secret_needed:
            guidance = SECRET_GUIDANCE.format(path=confirmation.secret_default).splitlines()
            choice = self.prompt(lines + [""] + guidance,
                                 f"Password source: file PATH | env NAME (Enter: file {confirmation.secret_default})")
            if choice is None:
                self.message = "Cancelled. Nothing was started."
                return
            problem = self.session.apply_secret(confirmation, choice.strip() or f"file {confirmation.secret_default}")
            if problem:
                self.panel("Refused - nothing was started", lines + ["", f"[!!] {problem}"])
                return
            lines = render_confirmation(confirmation) + ["Final command:", f"  {command_line(confirmation.argv)}"]
        if confirmation.live:
            typed = self.prompt(lines + ["", LIVE_CONFIRMATION.format(approval_hint=confirmation.approval_hint)],
                                "[LIVE] Type the approval token (Esc cancels):")
            if typed is None or not typed.strip():
                self.message = "Cancelled. Nothing was started."
                return
            if not self.session.token_ok(confirmation, typed):
                self.panel("Refused - nothing was started", lines + ["", "[!!] The token does not match."])
                return
        elif confirmation.needs_yes:
            typed = self.prompt(lines, "Start it? type y and Enter (Esc cancels)")
            if (typed or "").strip().lower() not in {"y", "yes"}:
                self.message = "Cancelled. Nothing was started."
                return
        else:
            typed = self.prompt(lines, "Enter runs it; Esc cancels")
            if typed is None:
                self.message = "Cancelled. Nothing was started."
                return
        self.execute(confirmation.argv, env=confirmation.env)

    def execute(self, argv: list[str], *, env=None, stdin_data: str | None = None) -> None:
        before = self.session.run_paths()
        output = [f"$ {command_line(argv)}", ""]
        process = self.session.start(argv, env=env, stdin_data=stdin_data)
        state = {"term": False}

        def forward(_signum, _frame):
            process.interrupt()
            output.append("[Ctrl-C forwarded to the command; it stops and keeps its evidence]")

        def forward_term(_signum, _frame):
            state["term"] = True
            process.terminate()

        previous = signal.signal(signal.SIGINT, forward)
        previous_term = signal.signal(signal.SIGTERM, forward_term)
        follow, start = True, 0
        self.screen.nodelay(True)
        try:
            code = None
            while True:
                for line in process.read_lines(0.05):
                    output.append(line)
                if len(output) > MAX_OUTPUT_LINES:
                    del output[: len(output) - MAX_OUTPUT_LINES]
                if code is None:
                    code = process.poll()
                    if code is not None:
                        outcome = self.session.finish(before, code, argv)
                        output.append("")
                        output.append(f"Exit code: {code}")
                        for run in outcome.new_runs:
                            output.append(f"New run: {run['relative']} ({run['kind']}, verdict {run.get('verdict')})")
                        output.append("Press q or Enter to return to the dashboard.")
                        if state["term"]:
                            raise SystemExit(143)
                start, maximum = self._draw_output(output, None if follow else start, running=code is None)
                key = self.screen.getch()
                if key == -1:
                    continue
                step = {curses.KEY_UP: -1, ord("k"): -1, curses.KEY_DOWN: 1, ord("j"): 1,
                        curses.KEY_PPAGE: -10, curses.KEY_NPAGE: 10}.get(key)
                if key == curses.KEY_RESIZE:
                    curses.update_lines_cols()
                elif step is not None:
                    start = max(0, start + step)
                    follow = start >= maximum
                elif code is not None and key in (ord("q"), 10, 13, 27, curses.KEY_ENTER):
                    return
        finally:
            self.screen.nodelay(False)
            signal.signal(signal.SIGINT, previous)
            signal.signal(signal.SIGTERM, previous_term)

    def _draw_output(self, output: list[str], offset: int | None, *, running: bool) -> tuple[int, int]:
        self.screen.erase()
        rows, cols = self.screen.getmaxyx()
        wrapped = _wrap(output, cols - 2)
        height = rows - 2
        maximum = max(0, len(wrapped) - height)
        start = maximum if offset is None else max(0, min(offset, maximum))
        status = "RUNNING - Ctrl-C forwards an interrupt" if running else "FINISHED"
        self.put(0, 0, f" Command output  [{status}]".ljust(cols), curses.A_REVERSE)
        for row, text in enumerate(wrapped[start:start + height]):
            self.put(1 + row, 1, text)
        self.put(rows - 1, 0, "Up/Down/PgUp/PgDn scroll" + ("" if running else "  q/Enter return"), curses.A_REVERSE)
        self.screen.refresh()
        return start, maximum

    def browse_run(self, run: dict[str, Any]) -> None:
        while True:
            lines = render_run(self.session.run_detail(run))
            items = self.session.run_actions(run)
            lines += ["", "Quick actions (all network-free; press the letter):"]
            for item in items:
                lines.append(f"  {item['key']}  {item['title']}")
                if item.get("command"):
                    lines.append(f"       {item['command']}")
            key = self._panel_key(f"Run {run['relative']}", lines, [item["key"] for item in items])
            if key is None:
                return
            chosen = next(item for item in items if item["key"] == key)
            if chosen["kind"] == "pager":
                self.panel(f"{run['relative']}/report.txt", self.session.report_text(run))
            elif chosen["kind"] == "journal":
                kind = self.prompt([JOURNAL_NOTE_PRIVACY], f"Kind ({', '.join(JOURNAL_KINDS)}), Enter: observation")
                if kind is None:
                    continue
                kind = kind.strip() or "observation"
                if kind not in JOURNAL_KINDS:
                    self.message = "Unknown journal kind; nothing was recorded."
                    continue
                note = self.prompt([JOURNAL_NOTE_PRIVACY], "Note (one line, non-secret; Esc cancels)")
                if note and note.strip():
                    self.execute(self.session.journal_argv(run, kind), stdin_data=note.strip() + "\n")
                    return
            else:
                typed = self.prompt([chosen["command"]], "Enter runs it; Esc cancels")
                if typed is not None:
                    self.execute(chosen["argv"])
                    return

    def _panel_key(self, title: str, lines: list[str], keys: list[str]) -> str | None:
        offset = 0
        while True:
            self.screen.erase()
            rows, cols = self.screen.getmaxyx()
            wrapped = _wrap(lines, cols - 2)
            height = rows - 2
            offset = max(0, min(offset, max(0, len(wrapped) - height)))
            self.put(0, 0, f" {title}".ljust(cols), curses.A_REVERSE)
            for row, text in enumerate(wrapped[offset:offset + height]):
                self.put(1 + row, 1, text)
            self.put(rows - 1, 0, "letter: quick action  Up/Down scroll  Esc/q back", curses.A_REVERSE)
            self.screen.refresh()
            key = self.screen.getch()
            if key in (27, ord("q")):
                return None
            if key == curses.KEY_RESIZE:
                curses.update_lines_cols()
            elif key in (curses.KEY_DOWN, ord("j")) and "j" not in keys:
                offset += 1
            elif key in (curses.KEY_UP, ord("k")) and "k" not in keys:
                offset -= 1
            elif key == curses.KEY_NPAGE:
                offset += height
            elif key == curses.KEY_PPAGE:
                offset -= height
            elif 0 <= key < 256 and chr(key) in keys:
                return chr(key)

    # -- main loop -------------------------------------------------------------
    def loop(self) -> int:
        self.screen.timeout(1000)
        while True:
            rows, cols = self.screen.getmaxyx()
            if not usable(rows, cols):
                self.screen.erase()
                self.put(0, 0, f"Terminal too small ({cols}x{rows}); need {MIN_COLS}x{MIN_LINES}. Enlarge, or q quits.")
                self.screen.refresh()
            else:
                self.draw_dashboard()
            key = self.screen.getch()
            if key == -1:
                continue  # one-second tick: the countdown redraws
            self.message = ""
            if key == ord("q"):
                return 0
            if key == curses.KEY_RESIZE:
                curses.update_lines_cols()
                continue
            if not usable(rows, cols):
                continue
            items = self.items()
            if key == ord("?"):
                self.panel("Help", keys_help().splitlines())
            elif key == 9:
                self.focus = "runs" if self.focus == "actions" else "actions"
            elif key in (curses.KEY_DOWN, ord("j")):
                self.selected[self.focus] = min(len(items) - 1, self.selected[self.focus] + 1) if items else 0
            elif key in (curses.KEY_UP, ord("k")):
                self.selected[self.focus] = max(0, self.selected[self.focus] - 1)
            elif key == ord("r"):
                self.session.refresh(probe_image=True)
                self.message = "Refreshed from disk."
            elif key == ord("S"):
                skipped = self.session.toggle_skip_practice()
                self.message = "Practice stage skipped." if skipped else "Practice stage recommended again."
            elif ord("1") <= key <= ord(str(len(STAGES))):
                self.panel("Stage", stage_help(STAGES[key - ord("1")].identifier).splitlines())
            elif key in (10, 13, curses.KEY_ENTER) and items:
                index = min(self.selected[self.focus], len(items) - 1)
                if self.focus == "actions":
                    self.perform(items[index])
                else:
                    self.browse_run(items[index])
                self.session.refresh()
            for name in ("actions", "runs"):
                count = len(self.session.actions if name == "actions" else self.session.runs)
                self.selected[name] = max(0, min(self.selected[name], count - 1))


def _cursor(visibility: int) -> None:
    try:
        curses.curs_set(visibility)
    except curses.error:
        pass


def _wrap(lines: list[str], width: int) -> list[str]:
    width = max(10, width)
    out: list[str] = []
    for line in lines:
        for part in str(line).split("\n"):
            while len(part) > width:
                out.append(part[:width])
                part = "    " + part[width:]
            out.append(part)
    return out


def run_curses(session: Session) -> int:
    """Run the curses UI; the terminal is restored on every exit path."""

    def terminate(_signum, _frame):
        raise SystemExit(143)

    previous = signal.signal(signal.SIGTERM, terminate)
    color = "NO_COLOR" not in os.environ

    def main(screen) -> int:
        _cursor(0)
        nonlocal color
        if color and curses.has_colors():
            curses.start_color()
            try:
                curses.use_default_colors()
                background = -1
            except curses.error:
                background = curses.COLOR_BLACK
            curses.init_pair(1, curses.COLOR_GREEN, background)
            curses.init_pair(2, curses.COLOR_RED, background)
            curses.init_pair(3, curses.COLOR_YELLOW, background)
            curses.init_pair(4, curses.COLOR_CYAN, background)
        else:
            color = False
        screen.keypad(True)
        return CursesUI(session, screen, color=color).loop()

    try:
        return curses.wrapper(main)
    finally:
        signal.signal(signal.SIGTERM, previous)
