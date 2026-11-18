"""Interaction state shared by the line-mode and curses front ends.

A ``Session`` owns the current model, rebuilds it from disk, prepares
confirmations, and runs confirmed actions through an injectable runner and
clock, so both front ends behave identically and can be tested without a
terminal.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from .actions import LAUNCHER, Confirmation, apply_secret, command_line, prepare_confirmation, token_matches
from .model import build_model
from .runs import MAX_TEXT_BYTES, Unreadable, detail, read_text

Clock = Callable[[], datetime]
JOURNAL_KINDS = ("observation", "action", "finding", "decision", "follow-up", "note", "hypothesis")


@dataclass
class Outcome:
    exit_code: int
    new_runs: list[dict[str, Any]]
    command: str


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Session:
    def __init__(
        self,
        repo: str | Path,
        engagement: str | Path,
        *,
        runner,
        clock: Clock = utc_now,
        environ: Mapping[str, str] | None = None,
        image_probe: Callable[[], dict[str, Any]] | None = None,
        commands: set[str] | None = None,
        host_has_tshark: bool | None = None,
    ):
        self.repo = Path(repo)
        self.engagement = Path(engagement)
        self.runner = runner
        self.clock = clock
        self.environ = dict(os.environ if environ is None else environ)
        self.image_probe = image_probe
        self.commands = commands
        self._image: dict[str, Any] | None = None
        self.host_has_tshark = shutil.which("tshark") is not None if host_has_tshark is None else host_has_tshark
        self.model: dict[str, Any] = {}
        self.refresh(probe_image=True)

    # -- model -------------------------------------------------------------
    def refresh(self, *, probe_image: bool = False) -> dict[str, Any]:
        if probe_image and self.image_probe is not None:
            self._image = self.image_probe()
        self.model = build_model(self.engagement, repo=self.repo, now=self.clock(), image=self._image,
                                 commands=self.commands)
        return self.model

    def toggle_skip_practice(self) -> bool:
        """Flip the 'skip the practice stage' UI preference; returns the new value."""
        from .model import save_preferences

        value = not self.model.get("preferences", {}).get("skipPractice", False)
        if self.engagement.is_dir():
            save_preferences(self.engagement, {"skipPractice": value})
        self.refresh()
        return value

    @property
    def actions(self) -> list[dict[str, Any]]:
        return self.model["actions"]

    @property
    def runs(self) -> list[dict[str, Any]]:
        return self.model["runs"]

    def eng(self) -> str:
        return self.model["engagement"]["display"]

    # -- confirmation --------------------------------------------------------
    def prepare(self, action: dict[str, Any]) -> Confirmation:
        return prepare_confirmation(action, self.model, repo=self.repo, probe=self.runner.probe, now=self.clock())

    def apply_secret(self, confirmation: Confirmation, choice: str) -> str | None:
        return apply_secret(confirmation, choice, repo=self.repo, environ=self.environ, model=self.model)

    @staticmethod
    def token_ok(confirmation: Confirmation, typed: str) -> bool:
        return token_matches(confirmation, typed)

    # -- execution -----------------------------------------------------------
    def start(self, argv: list[str], *, env: Mapping[str, str] | None = None, stdin_data: str | None = None):
        return self.runner.start(argv, env=env, stdin_data=stdin_data)

    def run_paths(self) -> set[str]:
        return {run["path"] for run in self.runs}

    def finish(self, before: set[str], exit_code: int, argv: list[str]) -> Outcome:
        self.refresh()
        new = [run for run in self.runs if run["path"] not in before]
        return Outcome(exit_code, new, command_line(argv))

    # -- runs ----------------------------------------------------------------
    def run_detail(self, run: dict[str, Any]) -> dict[str, Any]:
        return detail(run)

    def report_text(self, run: dict[str, Any]) -> list[str]:
        path = Path(run["path"]) / "report.txt"
        try:
            text, truncated = read_text(path, limit=MAX_TEXT_BYTES)
        except Unreadable as exc:
            return [f"[??] {exc}"]
        lines = text.splitlines()
        if truncated:
            lines.append(f"[..] report.txt truncated at {MAX_TEXT_BYTES // 1024} KiB for display")
        return lines

    def run_actions(self, run: dict[str, Any]) -> list[dict[str, Any]]:
        """Quick actions for one run; every one is network-free."""
        eng = self.eng()
        relative = f"{eng}/{run['relative']}"
        prefix = [LAUNCHER] if self.host_has_tshark else [LAUNCHER, "--isolated"]
        items: list[dict[str, Any]] = []
        if run.get("hasReport"):
            items.append({"key": "v", "title": "View report.txt", "kind": "pager"})
        if run.get("hasCapture"):
            items.append({"key": "t", "title": "Triage the capture", "kind": "command",
                          "argv": [*prefix, "triage", f"{relative}/capture.pcap"]})
            if run.get("hasExpectations"):
                items.append({"key": "a", "title": "Assert the call-path expectations", "kind": "command",
                              "argv": [*prefix, "assert", "--expect", f"{relative}/expectations.yaml",
                                       f"{relative}/capture.pcap"]})
        items.append({"key": "m", "title": "Rebuild the evidence manifest", "kind": "command",
                      "argv": [LAUNCHER, "evidence", "manifest", relative, "--write"]})
        if run.get("evidenceManifest"):
            items.append({"key": "l", "title": "Privacy-lint the evidence", "kind": "command",
                          "argv": [LAUNCHER, "evidence", "lint", relative]})
            image = self.model["readiness"]["image"]
            if image.get("id"):
                items.append({"key": "p", "title": "Create an evidence pack", "kind": "command",
                              "argv": [LAUNCHER, "pack", "create", relative, f"{eng}/packs/{run['name']}.tar",
                                       "--image-digest", f"sha256:{image['id']}"]})
        if self.model["journal"]["valid"]:
            items.append({"key": "j", "title": "Add a journal entry about this run", "kind": "journal"})
        for item in items:
            if item.get("argv"):
                item["command"] = command_line(item["argv"])
        return items

    def journal_argv(self, run: dict[str, Any], kind: str) -> list[str]:
        if kind not in JOURNAL_KINDS:
            raise ValueError(f"kind must be one of {', '.join(JOURNAL_KINDS)}")
        argv = [LAUNCHER, "journal", "add", self.eng(), "--kind", kind, "--summary-file", "-"]
        root = Path(run["path"])
        for name in ("result.json", "findings.json", "evidence-manifest.json"):
            if (root / name).is_file():
                argv.extend(["--evidence", f"{run['relative']}/{name}"])
        return argv
