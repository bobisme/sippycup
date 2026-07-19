"""Guarded action dispatch; rendering code has no access to this module."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol

from .state import ViewState


class ControlError(RuntimeError):
    pass


class CampaignControlAPI(Protocol):
    def start(self) -> None: ...
    def pause_new_calls(self) -> None: ...
    def graceful_stop(self) -> None: ...
    def emergency_stop(self) -> None: ...
    def skip_current(self) -> None: ...


@dataclass(frozen=True)
class ActionReceipt:
    action: str
    state: str
    applied: bool
    detail: str


@dataclass(frozen=True)
class Confirmation:
    action: str
    token: str


DANGEROUS = {"start", "emergency-stop", "skip"}


class ActionController:
    """Idempotent adapter from key actions to the campaign control API."""

    def __init__(
        self,
        api: CampaignControlAPI,
        run_dir: Path,
        *,
        launcher: Callable[[list[str]], int] | None = None,
        now: Callable[[], datetime] | None = None,
    ):
        self.api, self.run_dir = api, run_dir.resolve()
        self.launcher = launcher or self._launch
        self.now = now or (lambda: datetime.now(timezone.utc))
        self._confirmations: dict[str, str] = {}
        self._receipts: dict[str, ActionReceipt] = {}
        self._note_ids: set[str] = set()

    def request_confirmation(self, action: str) -> Confirmation:
        if action not in DANGEROUS:
            raise ControlError(f"{action} does not use dangerous-action confirmation")
        token = secrets.token_urlsafe(18)
        self._confirmations[action] = token
        return Confirmation(action, token)

    def invoke(
        self,
        action: str,
        state: ViewState,
        *,
        idempotency_key: str,
        confirmation: str | None = None,
    ) -> ActionReceipt:
        if not idempotency_key or len(idempotency_key) > 128:
            raise ControlError("an idempotency key up to 128 characters is required")
        if idempotency_key in self._receipts:
            return self._receipts[idempotency_key]
        if action in DANGEROUS:
            expected = self._confirmations.pop(action, None)
            if not expected or not secrets.compare_digest(confirmation or "", expected):
                raise ControlError(f"{action} requires a fresh explicit confirmation")

        methods = {
            "start": self.api.start,
            "pause-new-calls": self.api.pause_new_calls,
            "graceful-stop": self.api.graceful_stop,
            "emergency-stop": self.api.emergency_stop,
            "skip": self.api.skip_current,
        }
        method = methods.get(action)
        if method is None:
            raise ControlError(f"unsupported campaign action: {action}")
        method()
        receipt = ActionReceipt(action, state.phase, True, "campaign API acknowledged")
        self._receipts[idempotency_key] = receipt
        return receipt

    def note(
        self,
        text: str,
        state: ViewState,
        *,
        idempotency_key: str,
        bookmark: bool = False,
        evidence: str | None = None,
    ) -> ActionReceipt:
        if idempotency_key in self._note_ids:
            return ActionReceipt("bookmark" if bookmark else "note", state.phase, False, "duplicate")
        if not isinstance(text, str) or not text.strip() or len(text.encode("utf-8")) > 4096:
            raise ControlError("note must contain 1..4096 UTF-8 bytes")
        if any(ord(character) < 32 and character not in "\t\n" for character in text):
            raise ControlError("note contains unsupported control characters")
        self.run_dir.mkdir(parents=True, exist_ok=True)
        record = {
            "schema": "sippycup.note/v1",
            "id": idempotency_key,
            "kind": "bookmark" if bookmark else "note",
            "timeUtc": self.now().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "phase": state.phase,
            "text": text.strip(),
            "evidence": evidence,
        }
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        descriptor = os.open(self.run_dir / "notes.jsonl", flags, 0o600)
        try:
            os.write(descriptor, (json.dumps(record, sort_keys=True) + "\n").encode())
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._note_ids.add(idempotency_key)
        return ActionReceipt(record["kind"], state.phase, True, "notes.jsonl")

    def open_capture(self, capture: Path, state: ViewState) -> ActionReceipt:
        resolved = capture.resolve(strict=True)
        try:
            resolved.relative_to(self.run_dir)
        except ValueError as exc:
            raise ControlError("capture must be inside the frozen run directory") from exc
        if resolved.suffix.lower() not in {".pcap", ".pcapng"} or not resolved.is_file():
            raise ControlError("current capture must be a PCAP or PCAPNG file")
        prior_phase = state.phase
        code = self.launcher(["termshark", "-r", str(resolved)])
        if code:
            raise ControlError(f"Termshark exited with status {code}")
        return ActionReceipt("termshark", prior_phase, True, "returned to same run state")

    @staticmethod
    def _launch(argv: list[str]) -> int:
        # Separate session isolates Termshark's terminal/process group without
        # transferring ownership of campaign or capture children.
        return subprocess.run(argv, start_new_session=True, check=False).returncode


def remaining_budget(authorized: int, consumed: int) -> int:
    if type(authorized) is not int or authorized < 0:
        raise ControlError("authorized budget must be a non-negative integer")
    if type(consumed) is not int or consumed < 0:
        raise ControlError("consumed budget must be a non-negative integer")
    return max(0, min(authorized, authorized - consumed))
