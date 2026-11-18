"""End-to-end cockpit tests under a pseudo-terminal (stdlib pty).

A fake ./bin/sippycup in a temporary repository records every argv, so the
tests prove exactly what the cockpit would start, and that nothing starts
after a refused confirmation.
"""

from __future__ import annotations

import fcntl
import os
import re
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cockpit_support import ROOT, compiled_engagement, install_fake_launcher, launcher_log, make_repo  # noqa: E402

COCKPIT = ROOT / "bin" / "sippycup-go"


class Terminal:
    def __init__(self, argv, *, cwd, env, rows=24, cols=80):
        self.master, self.slave = os.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.before = termios.tcgetattr(self.slave)
        self.process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=self.slave, stdout=self.slave,
                                        stderr=self.slave, close_fds=True)
        self.output = ""
        self.cursor = 0

    def read(self, timeout=0.2) -> None:
        end = time.monotonic() + timeout
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                return
            ready, _, _ = select.select([self.master], [], [], remaining)
            if not ready:
                return
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                return
            if not chunk:
                return
            self.output += chunk.decode("utf-8", errors="replace")

    def expect(self, pattern: str, timeout: float = 20.0) -> str:
        """Wait for ``pattern`` after the previous match; return the text up to and including it."""
        end = time.monotonic() + timeout
        start = self.cursor
        while True:
            match = re.search(pattern, self.output[start:])
            if match:
                self.cursor = start + match.end()
                return self.output[start:self.cursor]
            if time.monotonic() >= end:
                break
            exited = self.process.poll() is not None
            self.read(0.1)
            if exited and not re.search(pattern, self.output[start:]):
                break
        raise AssertionError(f"did not see {pattern!r}; output tail:\n{self.output[-3000:]}")

    def send(self, text: str) -> None:
        os.write(self.master, text.encode("utf-8"))

    def wait(self, timeout: float = 20.0) -> int:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            self.read(0.1)
            code = self.process.poll()
            if code is not None:
                self.read(0.2)
                return code
        self.process.kill()
        raise AssertionError(f"cockpit did not exit; output tail:\n{self.output[-3000:]}")

    def restored(self) -> bool:
        return termios.tcgetattr(self.slave) == self.before

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()
        os.close(self.master)
        os.close(self.slave)


def action_number(text: str, title: str) -> int:
    match = re.search(rf"^\s*(\d+)\. \[[A-Za-z]+\]\s+{re.escape(title)}", text, re.MULTILINE)
    if not match:
        raise AssertionError(f"no action {title!r} in:\n{text[-3000:]}")
    return int(match.group(1))


class CockpitTerminalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = make_repo(Path(self.temporary.name))
        install_fake_launcher(self.repo)
        compiled_engagement(self.repo, now=datetime.now(timezone.utc))
        self.env = {key: value for key, value in os.environ.items() if key not in {"NO_COLOR"}}
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def start(self, *arguments, term="dumb", rows=24, cols=80):
        env = dict(self.env, TERM=term)
        terminal = Terminal([sys.executable, str(COCKPIT), "--repo", str(self.repo), "work/eng", "--no-runtime",
                             *arguments], cwd=self.repo, env=env, rows=rows, cols=cols)
        self.addCleanup(terminal.close)
        return terminal

    def test_line_mode_navigates_confirms_and_spawns_exact_argv(self) -> None:
        terminal = self.start("--line")
        dashboard = terminal.expect(r"go> ")
        self.assertIn("Sippycup cockpit: engagement work/eng", dashboard)
        terminal.send("?\n")
        terminal.expect(r"Markers \(colour is only a supplement\)")
        terminal.send("s5\n")
        terminal.expect(r"Stage 5: First call")
        rehearse = action_number(dashboard, "Rehearse the target profile")
        call = action_number(dashboard, "Place the guided baseline call")

        terminal.send(f"{rehearse}\n")
        terminal.expect(r"Press Enter to run it")
        terminal.send("\n")
        terminal.expect(r"Exit code: 0")
        terminal.expect(r"go> ")

        terminal.send(f"{call}\n")
        panel = terminal.expect(r"Approval token: ")
        self.assertIn("[LIVE] Place the guided baseline call", panel)
        self.assertIn("Literal address: 127.0.0.2", panel)
        terminal.send("0000\n")
        terminal.expect(r"The token does not match\. Nothing was started\.")
        live_calls = [entry for entry in launcher_log(self.repo) if "--dry-run" not in entry["argv"]
                      and entry["argv"][:1] == ["call"]]
        self.assertEqual([], live_calls)

        terminal.send(f"{call}\n")
        terminal.expect(r"Approval token: ")
        terminal.send("7Q2X\n")
        terminal.expect(r"New run: calls/20261117T120000\.000000Z-fixture-0001 \(call, verdict pass\)")
        terminal.expect(r"go> ")

        terminal.send("r1\n")
        detail = terminal.expect(r"run> ")
        self.assertIn("Verdict: pass", detail)
        self.assertIn("Quick actions (all network-free):", detail)
        terminal.send("\n")
        terminal.expect(r"go> ")
        terminal.send("q\n")
        self.assertEqual(0, terminal.wait())
        self.assertTrue(terminal.restored())
        self.assertNotIn("Traceback", terminal.output)

        argvs = [entry["argv"] for entry in launcher_log(self.repo)]
        self.assertIn(["rehearse", "work/eng/target-profile.yaml"], argvs)
        live = [argv for argv in argvs if argv[:1] == ["call"] and "--dry-run" not in argv]
        self.assertEqual([["call", "work/eng/target-profile.yaml", "--dial", "echo"]], live)
        previews = [argv for argv in argvs if argv[:1] == ["call"] and "--dry-run" in argv]
        self.assertEqual(2, len(previews))
        self.assertTrue(all(argv[-2:] == ["--format", "json"] for argv in previews))

    def test_plain_mode_without_a_terminal_ends_with_the_next_command(self) -> None:
        result = subprocess.run([sys.executable, str(COCKPIT), "--repo", str(self.repo), "work/eng", "--no-runtime"],
                                cwd=self.repo, env=self.env, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=30, check=False)
        self.assertEqual(0, result.returncode, result.stderr)
        last = result.stdout.strip().splitlines()[-1]
        self.assertTrue(last.startswith("Next: ./bin/sippycup "), last)
        self.assertIn("Stages", result.stdout)
        self.assertEqual([], launcher_log(self.repo))

    def test_dumb_terminal_falls_back_to_line_mode(self) -> None:
        terminal = self.start(term="dumb")
        terminal.expect(r"go> ")
        terminal.send("q\n")
        self.assertEqual(0, terminal.wait())
        self.assertTrue(terminal.restored())

    def _curses_available(self) -> bool:
        import curses

        probe = os.openpty()
        try:
            curses.setupterm("xterm-256color", probe[1])
            return True
        except curses.error:
            return False
        finally:
            os.close(probe[0])
            os.close(probe[1])

    def test_curses_smoke_at_80x24(self) -> None:
        if not self._curses_available():
            self.skipTest("terminfo for xterm-256color is not available")
        terminal = self.start(term="xterm-256color")
        terminal.expect(r"Sippycup cockpit")
        terminal.expect(r"Stages")
        terminal.send("?")
        terminal.expect(r"Keys:")
        terminal.send("q")
        time.sleep(0.3)
        terminal.send("q")
        self.assertEqual(0, terminal.wait())
        self.assertNotIn("Traceback", terminal.output)
        self.assertTrue(terminal.restored(), "terminal modes were not restored")

    def test_curses_confirmation_prompt_waits_longer_than_the_refresh_timeout(self) -> None:
        # The dashboard refreshes every second; a confirmation prompt left
        # open longer than that used to crash with "_curses.error: no input".
        if not self._curses_available():
            self.skipTest("terminfo for xterm-256color is not available")
        terminal = self.start(term="xterm-256color")
        terminal.expect(r"Stages")
        terminal.send("\r")
        terminal.expect(r"Esc cancels")
        time.sleep(2.5)
        terminal.read(0.2)
        self.assertIsNone(terminal.process.poll(), terminal.output[-2000:])
        terminal.send("\x1b")
        time.sleep(0.5)
        terminal.send("q")
        self.assertEqual(0, terminal.wait())
        self.assertNotIn("Traceback", terminal.output)
        self.assertTrue(terminal.restored(), "terminal modes were not restored")

    def test_curses_restores_the_terminal_on_sigterm(self) -> None:
        if not self._curses_available():
            self.skipTest("terminfo for xterm-256color is not available")
        terminal = self.start(term="xterm-256color")
        terminal.expect(r"Stages")
        terminal.process.send_signal(signal.SIGTERM)
        self.assertEqual(143, terminal.wait())
        self.assertNotIn("Traceback", terminal.output)
        self.assertTrue(terminal.restored(), "terminal modes were not restored after SIGTERM")

    def test_tiny_terminal_uses_line_mode(self) -> None:
        terminal = self.start(term="xterm-256color", rows=12, cols=50)
        terminal.expect(r"go> ")
        terminal.send("q\n")
        self.assertEqual(0, terminal.wait())
        self.assertTrue(terminal.restored())


class WrapTests(unittest.TestCase):
    def test_wrap_breaks_between_words_and_cuts_only_long_tokens(self) -> None:
        sys.path.insert(0, str(ROOT / "lib"))
        from sippycup_cockpit.tui import _wrap

        lines = _wrap(["generate the target profile, campaign manifest, and oracle expectations"], 30)
        self.assertEqual(["generate the target profile,", "    campaign manifest, and", "    oracle expectations"], lines)
        self.assertEqual(["x" * 20, "    " + "x" * 5], _wrap(["x" * 25], 20))


if __name__ == "__main__":
    unittest.main()
