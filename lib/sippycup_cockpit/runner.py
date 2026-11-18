"""Spawn ``./bin/sippycup`` subprocesses for the cockpit, and only those.

The child runs in its own session, so a terminal Ctrl-C reaches the cockpit,
which forwards SIGINT to the child's process group. The launched commands
handle cancellation themselves (the guided call hangs up and keeps the
evidence). Output is read line by line with a bounded buffer.
"""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
from pathlib import Path
from typing import Callable, Iterable, Mapping

from .actions import spawnable

MAX_PROBE_BYTES = 256 * 1024
MAX_LINE = 4000


class RunnerError(RuntimeError):
    """The cockpit refused to start a process."""


class RunningProcess:
    def __init__(self, popen: subprocess.Popen):
        self.popen = popen
        self._selector = selectors.DefaultSelector()
        self._buffer = b""
        self._open = popen.stdout is not None
        if self._open:
            os.set_blocking(popen.stdout.fileno(), False)
            self._selector.register(popen.stdout, selectors.EVENT_READ)
        self.interrupted = 0

    @property
    def pid(self) -> int:
        return self.popen.pid

    def interrupt(self) -> None:
        """Forward SIGINT to the child's process group (repeatable)."""
        self.interrupted += 1
        try:
            os.killpg(self.popen.pid, signal.SIGINT)
        except (ProcessLookupError, PermissionError):
            pass

    def terminate(self) -> None:
        try:
            os.killpg(self.popen.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass

    def read_lines(self, timeout: float = 0.1) -> list[str]:
        """Return complete output lines available within ``timeout``."""
        lines: list[str] = []
        if not self._open:
            return lines
        for _key, _events in self._selector.select(timeout):
            try:
                chunk = os.read(self.popen.stdout.fileno(), 65536)
            except BlockingIOError:
                continue
            except OSError:
                chunk = b""
            if not chunk:
                self._selector.unregister(self.popen.stdout)
                # EOF: release the pipe and the epoll descriptor now rather
                # than leaving them to the garbage collector (ResourceWarning).
                self.popen.stdout.close()
                self._selector.close()
                self._open = False
                break
            self._buffer += chunk
        while b"\n" in self._buffer:
            raw, self._buffer = self._buffer.split(b"\n", 1)
            lines.append(raw.decode("utf-8", errors="replace").rstrip("\r")[:MAX_LINE])
        if len(self._buffer) > MAX_LINE:
            lines.append(self._buffer.decode("utf-8", errors="replace")[:MAX_LINE])
            self._buffer = b""
        if not self._open and self._buffer:
            lines.append(self._buffer.decode("utf-8", errors="replace")[:MAX_LINE])
            self._buffer = b""
        return lines

    @property
    def finished(self) -> bool:
        return not self._open and self.popen.poll() is not None

    def wait(self) -> int:
        return self.popen.wait()

    def poll(self) -> int | None:
        if self._open:
            return None
        return self.popen.poll()


class SubprocessRunner:
    """Run launcher commands from the repository root."""

    def __init__(self, repo: str | Path, environ: Mapping[str, str] | None = None):
        self.repo = Path(repo)
        self.environ = dict(os.environ if environ is None else environ)

    def _environment(self, extra: Mapping[str, str] | None) -> dict[str, str]:
        environment = dict(self.environ)
        environment["PYTHONUNBUFFERED"] = "1"
        environment.update(extra or {})
        return environment

    def probe(self, argv: list[str], timeout: float = 120) -> tuple[int, str]:
        """Run a network-free preview command and capture bounded stdout."""
        if not spawnable(argv):
            raise RunnerError("only ./bin/sippycup commands can be started")
        try:
            result = subprocess.run(
                argv, cwd=self.repo, env=self._environment(None), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 127, f"could not run the preview: {exc}"
        output = result.stdout[:MAX_PROBE_BYTES].decode("utf-8", errors="replace")
        if result.returncode != 0 and not output.strip():
            output = result.stderr[:MAX_PROBE_BYTES].decode("utf-8", errors="replace")
        return result.returncode, output

    def start(self, argv: list[str], *, env: Mapping[str, str] | None = None,
              stdin_data: str | None = None) -> RunningProcess:
        if not spawnable(argv):
            raise RunnerError("only ./bin/sippycup commands can be started")
        popen = subprocess.Popen(
            argv, cwd=self.repo, env=self._environment(env),
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
        )
        if stdin_data is not None and popen.stdin is not None:
            try:
                popen.stdin.write(stdin_data.encode("utf-8"))
            except BrokenPipeError:
                pass
            finally:
                popen.stdin.close()
        return RunningProcess(popen)


def run_streaming(
    runner,
    argv: list[str],
    on_line: Callable[[str], None],
    *,
    env: Mapping[str, str] | None = None,
    stdin_data: str | None = None,
    on_interrupt: Callable[[], None] | None = None,
) -> int:
    """Run to completion, streaming lines; Ctrl-C is forwarded to the child."""
    process = runner.start(argv, env=env, stdin_data=stdin_data)
    terminated = []

    def forward(_signum, _frame):
        process.interrupt()
        if on_interrupt:
            on_interrupt()

    def forward_term(_signum, _frame):
        terminated.append(True)
        process.terminate()

    previous = signal.signal(signal.SIGINT, forward)
    previous_term = signal.signal(signal.SIGTERM, forward_term)
    try:
        while True:
            for line in process.read_lines(0.1):
                on_line(line)
            code = process.poll()
            if code is not None:
                for line in process.read_lines(0):
                    on_line(line)
                break
    finally:
        signal.signal(signal.SIGINT, previous)
        signal.signal(signal.SIGTERM, previous_term)
    if terminated:
        raise SystemExit(143)
    return code


def iter_commands(path: Path) -> Iterable[str]:
    """Names in config/commands.tsv (the public registry)."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    names = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        name = line.split("|", 1)[0].strip()
        if name:
            names.append(name)
    return names
