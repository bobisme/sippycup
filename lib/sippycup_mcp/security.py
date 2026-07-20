"""Containment, redaction, and bounded-result primitives for MCP."""

from __future__ import annotations

import json
import os
import re
import signal
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

from . import RESULT_API_VERSION

MAX_RESULT_BYTES = 1024 * 1024
MAX_PATH_CHARS = 512
MAX_SUBPROCESS_BYTES = 1024 * 1024
MAX_SUBPROCESS_SECONDS = 130
MAX_CONCURRENT_CALLS = 2

_SECRET_KEY = re.compile(
    r"(?i)^(?:password|passwd|secret|token|access_token|refresh_token|"
    r"private_key|authorization_header|proxy_authorization|credential_value)$"
)
_SECRET_TEXT = (
    re.compile(r"(?i)(authorization:\s*)([^\r\n]+)"),
    re.compile(r"(?i)(proxy-authorization:\s*)([^\r\n]+)"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
)


class MCPPolicyError(ValueError):
    """An MCP request violates the local safety contract."""


class WorkRoot:
    """Resolve caller paths beneath one fixed root without symlink traversal."""

    def __init__(self, root: str | Path):
        supplied = Path(root)
        if supplied.is_symlink() or not supplied.is_dir():
            raise MCPPolicyError("MCP work root must be a real directory")
        self.path = supplied.resolve(strict=True)

    def resolve(
        self,
        relative: str,
        *,
        kind: str,
        max_bytes: int | None = None,
    ) -> Path:
        if (
            not isinstance(relative, str)
            or not relative
            or len(relative) > MAX_PATH_CHARS
            or "\x00" in relative
            or "\\" in relative
        ):
            raise MCPPolicyError("path must be a short non-empty POSIX relative path")
        requested = Path(relative)
        if requested.is_absolute() or any(part == ".." for part in requested.parts):
            raise MCPPolicyError("path must remain beneath the MCP work root")
        candidate = self.path / requested
        current = self.path
        for part in requested.parts:
            if part in {"", "."}:
                continue
            current = current / part
            if current.is_symlink():
                raise MCPPolicyError("symlinked MCP paths are not allowed")
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise MCPPolicyError("requested path does not exist") from exc
        if resolved != self.path and self.path not in resolved.parents:
            raise MCPPolicyError("path escaped the MCP work root")
        if kind == "file" and not resolved.is_file():
            raise MCPPolicyError("requested path must be a regular file")
        if kind == "directory" and not resolved.is_dir():
            raise MCPPolicyError("requested path must be a directory")
        if max_bytes is not None and kind == "file" and resolved.stat().st_size > max_bytes:
            raise MCPPolicyError(f"requested file exceeds the {max_bytes}-byte limit")
        return resolved


def redact(value: Any) -> Any:
    """Redact known secret-bearing fields and common authorization text."""
    if isinstance(value, dict):
        return {
            str(key): "<redacted>" if _SECRET_KEY.fullmatch(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        result = value
        for pattern in _SECRET_TEXT:
            result = pattern.sub(r"\1<redacted>", result)
        return result
    return value


def _bounded(document: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) <= MAX_RESULT_BYTES:
        return document
    return {
        "apiVersion": RESULT_API_VERSION,
        "tool": document.get("tool", "unknown"),
        "ok": False,
        "networkActivity": False,
        "sensitivity": "internal",
        "durationMs": document.get("durationMs", 0),
        "data": None,
        "warnings": [],
        "errors": [
            {
                "code": "mcp.result_too_large",
                "message": f"result exceeded the {MAX_RESULT_BYTES}-byte limit",
            }
        ],
        "artifacts": [],
        "truncated": True,
    }


def result(
    tool: str,
    *,
    started: float,
    data: Any = None,
    error: Exception | None = None,
    warnings: list[str] | None = None,
    sensitivity: str = "internal",
) -> dict[str, Any]:
    errors = []
    if error is not None:
        errors.append(
            {
                "code": (
                    "mcp.policy_rejected"
                    if isinstance(error, MCPPolicyError)
                    else "mcp.tool_failed"
                ),
                "message": str(error) or type(error).__name__,
                "type": type(error).__name__,
            }
        )
    document = {
        "apiVersion": RESULT_API_VERSION,
        "tool": tool,
        "ok": error is None,
        "networkActivity": False,
        "sensitivity": sensitivity,
        "durationMs": max(0, round((time.monotonic() - started) * 1000)),
        "data": redact(data),
        "warnings": redact(warnings or []),
        "errors": redact(errors),
        "artifacts": [],
        "truncated": False,
    }
    return _bounded(document)


class CallGate:
    """Bound concurrent MCP work and return stable busy errors."""

    def __init__(self, maximum: int = MAX_CONCURRENT_CALLS):
        self._semaphore = threading.BoundedSemaphore(maximum)

    def invoke(self, name: str, function: Callable[[], Any]) -> dict[str, Any]:
        started = time.monotonic()
        if not self._semaphore.acquire(timeout=0.25):
            return result(
                name,
                started=started,
                error=MCPPolicyError("MCP concurrency limit is busy; retry later"),
            )
        try:
            try:
                return result(name, started=started, data=function())
            except Exception as exc:  # converted to a stable MCP result
                return result(name, started=started, error=exc)
        finally:
            self._semaphore.release()


class BoundedProcessRunner:
    """Run only caller-constructed fixed argv with hard time and file limits."""

    def __init__(
        self,
        *,
        timeout: int = MAX_SUBPROCESS_SECONDS,
        output_bytes: int = MAX_SUBPROCESS_BYTES,
    ):
        self.timeout = timeout
        self.output_bytes = output_bytes

    def run_json(self, argv: list[str]) -> tuple[int, Any, str]:
        if (
            not argv
            or any(not isinstance(item, str) or "\x00" in item for item in argv)
        ):
            raise MCPPolicyError("invalid fixed command arguments")
        environment = {
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/opt/voip-tools/bin:/usr/local/bin:/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
        }
        prlimit = shutil.which("prlimit", path=environment["PATH"])
        if prlimit is None:
            raise MCPPolicyError("prlimit is required for bounded helper output")
        limited_argv = [
            prlimit,
            f"--fsize={self.output_bytes}:{self.output_bytes}",
            "--",
            *argv,
        ]
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                process = subprocess.Popen(
                    limited_argv,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    env=environment,
                    start_new_session=True,
                    close_fds=True,
                )
            except OSError as exc:
                raise MCPPolicyError(f"cannot start fixed helper: {argv[0]}") from exc
            try:
                process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired as exc:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                raise MCPPolicyError(
                    f"fixed helper exceeded the {self.timeout}-second limit"
                ) from exc
            stdout.seek(0)
            stderr.seek(0)
            raw_stdout = stdout.read(self.output_bytes + 1)
            raw_stderr = stderr.read(self.output_bytes + 1)
        if len(raw_stdout) > self.output_bytes or len(raw_stderr) > self.output_bytes:
            raise MCPPolicyError("fixed helper exceeded the output limit")
        stderr_text = raw_stderr.decode("utf-8", errors="replace").strip()
        try:
            parsed = json.loads(raw_stdout)
        except json.JSONDecodeError as exc:
            raise MCPPolicyError(
                f"fixed helper returned invalid JSON: {redact(stderr_text) or 'no detail'}"
            ) from exc
        return process.returncode, parsed, stderr_text
