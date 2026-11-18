"""Shared vocabulary, redaction context, and the diagnosis builder."""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from sippycup_workbench.summary_privacy import AddressBook, Sanitizer

from . import SCHEMA

STAGES = (
    "preflight", "TLS", "registration", "INVITE", "answer", "media",
    "teardown", "oracle", "capture", "safety stop", "internal", "none",
)

OUR = "our side"
THEIR = "their side"
NETWORK = "network or NAT in between"
UNKNOWN = "cannot tell from this evidence"
NONE = "none (nothing failed)"
SIDES = (OUR, THEIR, NETWORK, UNKNOWN, NONE)

HIGH, MEDIUM, LOW = "high", "medium", "low"

_SAFE_ARG = re.compile(r"^[A-Za-z0-9_./+:=@,%-]+$")


def work_relative(path: Path) -> str:
    """The path as the operator types it: from the last `work` directory down."""
    parts = path.parts
    for index in range(len(parts) - 1, -1, -1):
        if parts[index] == "work":
            return "/".join(parts[index:])
    return str(path)


def container_to_host_path(value: str) -> str:
    """Recorded container paths (/work/...) become the host spelling (work/...)."""
    return value[1:] if value.startswith("/work/") else value


def quote(argument: str) -> Optional[str]:
    """Shell-safe rendering, or None when the value has characters we refuse to echo."""
    if _SAFE_ARG.match(argument):
        return argument
    if any(ord(char) < 32 or char in "\n\r\x00" for char in argument):
        return None
    return shlex.quote(argument)


def command(*words: str, practice: bool = False) -> Optional[str]:
    """Build one ./bin/sippycup line; None when any word is not safe to print."""
    rendered = []
    for word in words:
        safe = quote(str(word))
        if safe is None:
            return None
        rendered.append(safe)
    head = ["./bin/sippycup"] + (["--practice"] if practice else [])
    return " ".join(head + rendered)


@dataclass
class Redaction:
    """Address book and sanitizer shared by every string that reaches the page."""

    book: AddressBook
    show_addresses: bool = False
    sanitizer: Sanitizer = field(init=False)
    relabeled: int = 0

    def __post_init__(self) -> None:
        self.sanitizer = Sanitizer(addresses=self.book)

    def note_run_names(self, *names: str) -> None:
        self.sanitizer.run_names.update(name for name in names if name)

    def text(self, value: Any, limit: int = 220) -> str:
        if value is None:
            return ""
        text = str(value)
        if self.show_addresses:
            # Operator copy: keep addresses, still strip credentials and tokens.
            book = AddressBook()
            book.add_network("0.0.0.0/0")
            book.add_network("::/0")
            clean = Sanitizer(addresses=book, run_names=set(self.sanitizer.run_names))
            return clean.text(text, "diagnose", limit=limit) or ""
        return self.sanitizer.text(text, "diagnose", limit=limit) or ""

    def addr(self, address: Optional[str]) -> str:
        if address is None:
            return "unknown"
        if self.show_addresses:
            return address
        return self.book.label(address)

    def hostport(self, address: Optional[str], port: Optional[int]) -> str:
        host = self.addr(address)
        try:
            if ipaddress.ip_address(host).version == 6:
                host = f"[{host}]"
        except ValueError:
            pass
        return f"{host}:{port}" if port is not None else host


def is_private(address: Optional[str]) -> bool:
    if not address:
        return False
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return parsed.is_private and not parsed.is_loopback


def is_loopback(address: Optional[str]) -> bool:
    try:
        return bool(address) and ipaddress.ip_address(str(address)).is_loopback
    except ValueError:
        return False


class Diagnosis:
    """Accumulates the one-page answer. Everything stored is already redacted."""

    def __init__(self, kind: str, redaction: Redaction) -> None:
        self.kind = kind
        self.red = redaction
        self.data: dict = {
            "schema": SCHEMA,
            "kind": kind,
            "run": None,
            "verdict": None,
            "state": None,
            "outcome": "",
            "stage": "none",
            "stageDetail": "",
            "evidence": [],
            "timing": [],
            "attribution": {
                "side": UNKNOWN,
                "confidence": LOW,
                "reasoning": [],
                "distinguish": [],
            },
            "nextSteps": [],
            "stopAndAsk": None,
            "gaps": [],
            "ladder": None,
            "children": [],
            "networkActivity": False,
        }

    # -- setters ---------------------------------------------------------
    def set(self, **values: Any) -> "Diagnosis":
        self.data.update(values)
        return self

    def outcome(self, text: str) -> None:
        self.data["outcome"] = self.red.text(text, 400)

    def stage(self, name: str, detail: str = "") -> None:
        assert name in STAGES, name
        self.data["stage"] = name
        self.data["stageDetail"] = self.red.text(detail, 300)

    def evidence(self, label: str, text: str, limit: int = 240) -> None:
        self.data["evidence"].append({"label": label, "text": self.red.text(text, limit)})

    def timing(self, label: str, seconds: Optional[float], note: str = "") -> None:
        if seconds is None:
            return
        self.data["timing"].append(
            {"stage": label, "seconds": round(float(seconds), 3), "note": self.red.text(note, 120) if note else ""}
        )

    def attribute(
        self,
        side: str,
        confidence: str,
        reasoning: list,
        distinguish: Optional[list] = None,
    ) -> None:
        assert side in SIDES, side
        self.data["attribution"] = {
            "side": side,
            "confidence": confidence,
            "reasoning": [self.red.text(item, 360) for item in reasoning],
            "distinguish": [self.red.text(item, 360) for item in (distinguish or [])],
        }

    def gap(self, text: str) -> None:
        self.data["gaps"].append(self.red.text(text, 260))

    def step(self, why: str, line: Optional[str] = None, kind: str = "command") -> None:
        """Add a next step. `line` must be a finished ./bin/sippycup command (or None)."""
        if kind == "command" and line is None:
            return
        entry = {"kind": kind, "why": self.red.text(why, 300)}
        if line is not None:
            entry["command"] = line
        if entry not in self.data["nextSteps"]:
            self.data["nextSteps"].append(entry)

    _EVIDENCE_ORDER = {
        "registration": ("registration", "REGISTER authentication", "REGISTER requests", "failing step", "softphone step", "Reason", "Warning", "Retry-After", "INVITE"),
        "preflight": ("preflight", "OPTIONS", "failing step", "TLS trust", "PJSUA TLS"),
        "TLS": ("preflight", "PJSUA TLS", "TLS alert", "TLS trust"),
        "INVITE": ("INVITE", "INVITE authentication", "failing step", "softphone step", "Reason", "Warning", "Retry-After", "SDP offer", "SDP answer", "SRTP", "codecs"),
        "answer": ("INVITE", "SDP answer", "codecs", "Reason", "Warning", "Retry-After"),
        "media": ("RTP per direction", "RTP", "recording", "softphone step", "SDP answer", "SDP offer", "media scope"),
        "teardown": ("Reason", "Warning", "INVITE", "RTP"),
        "oracle": ("oracle assertion", "RTP", "not judged", "oracle"),
        "safety stop": ("media scope", "SDP answer", "SDP offer", "RTP"),
    }

    def finalize(self) -> None:
        """Put the evidence that decides the stage first; keep the rest in recorded order."""
        order = self._EVIDENCE_ORDER.get(self.data["stage"], ())

        def rank(item: dict) -> int:
            for position, prefix in enumerate(order):
                if item["label"].startswith(prefix):
                    return position
            return len(order) + (1 if item["label"] in ("registration", "oracle") else 0)

        self.data["evidence"].sort(key=rank)

    def stop_and_ask(self, reason: str) -> None:
        self.data["stopAndAsk"] = self.red.text(reason, 400)
        self.data["nextSteps"].insert(0, {"kind": "stop-and-ask", "why": self.red.text(reason, 400)})
