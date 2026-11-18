"""Reuse the ladder model for the diagnosis; no capture parsing lives here.

``load`` runs the ladder's own pipeline (`sippycup_ladder.cli.run`) on a run
directory and returns its redacted JSON document. ``rtp_flows`` asks the
ladder's capture reader for the exact RTP endpoints of the same capture, so a
diagnosis can say whether RTP went to the address the answer SDP named.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional

from sippycup_ladder.capture import LadderCaptureError, read_media
from sippycup_ladder.cli import PrivacyLintError, run as ladder_run
from sippycup_ladder.inputs import InputError, resolve
from sippycup_ladder.render_text import render_section, render_text

DEFAULT_WIDTH = 100
MAX_EXCERPT_EVENTS = 22


def load(run_dir: Path, show_addresses: bool, approve: list, width: int = DEFAULT_WIDTH) -> tuple:
    """Return (document or None, reason when None)."""
    arguments = argparse.Namespace(
        source=str(run_dir),
        format="json",
        output=None,
        call_id_index=None,
        width=width,
        approve=list(approve),
        show_addresses=show_addresses,
    )
    try:
        _code, text = ladder_run(arguments)
        return json.loads(text), None
    except InputError as error:
        return None, f"no ladder: {error}"
    except LookupError as error:
        return None, str(error)
    except LadderCaptureError as error:
        return None, f"the capture could not be read ({error})"
    except PrivacyLintError:
        return None, "the ladder was withheld by its privacy lint"
    except (OSError, ValueError) as error:
        return None, f"the ladder could not be built ({type(error).__name__})"


def pick_section(document: dict, prefer: str) -> Optional[dict]:
    """The ladder section that matters: a call, a registration, or the preflight."""
    sections = document.get("sections") or []
    order = {"call": ("call", "registration", "options"), "registration": ("registration", "call", "options"),
             "options": ("options", "registration", "call")}[prefer]
    for kind in order:
        found = [item for item in sections if item.get("kind") == kind]
        if found:
            return found[-1] if kind == "call" else found[0] if kind == "options" else found[-1]
    return sections[-1] if sections else None


def _failure_index(events: list) -> int:
    """Index of the event the page should centre on."""
    chosen = None
    for index, event in enumerate(events):
        if event.get("type") != "sip":
            continue
        status = event.get("status")
        if event.get("kind") == "response" and status is not None and status >= 300:
            if "auth-challenge" in event.get("tags", ()) and index + 1 < len(events):
                continue
            chosen = index
            break
    if chosen is not None:
        return chosen
    for index in range(len(events) - 1, -1, -1):
        if events[index].get("type") == "sip" and events[index].get("method") == "BYE":
            return index
    return len(events) - 1


def excerpt(document: dict, section: dict, width: int = DEFAULT_WIDTH) -> dict:
    """A compact rendering of one section, centred on the failure."""
    events = list(section.get("events") or [])
    omitted = 0
    if len(events) > MAX_EXCERPT_EVENTS:
        centre = _failure_index(events)
        keep = {0}
        keep.update(index for index, event in enumerate(events) if event.get("type") == "media")
        keep.update(range(max(0, centre - 7), min(len(events), centre + 6)))
        keep.update(index for index, event in enumerate(events) if event.get("method") == "BYE")
        kept = [events[index] for index in sorted(keep)]
        omitted = len(events) - len(kept)
        events = kept
    # Keep SDP summaries only for the last offer and the last answer; drop the
    # Digest notes (the tags already say AUTH CHALLENGE / AUTH RESPONSE).
    last_offer = last_answer = -1
    for index, event in enumerate(events):
        for item in event.get("details", ()):
            if item.startswith("offer:"):
                last_offer = index
            elif item.startswith("answer:"):
                last_answer = index
    trimmed = []
    for index, event in enumerate(events):
        copy = dict(event)
        details = []
        for item in event.get("details", ()):
            if item.startswith(("authentication challenge", "authentication response")):
                continue
            if item.startswith("offer:") and index != last_offer:
                continue
            if item.startswith("answer:") and index != last_answer:
                continue
            details.append(item)
        copy["details"] = details
        trimmed.append(copy)
    slim = dict(section)
    slim["events"] = trimmed
    lines = render_section(slim, width)
    if omitted:
        lines.append(f"({omitted} SIP rows between the call setup and the failure are omitted from this excerpt)")
    return {
        "section": section.get("index"),
        "title": section.get("title"),
        "outcome": section.get("outcome"),
        "omittedRows": omitted,
        "text": "\n".join(lines),
    }


def rtp_flows(run_dir: Path, ports: set) -> list:
    """RTP flows (ladder MediaFlow objects) from the run's capture, or []."""
    try:
        inputs = resolve(str(run_dir))
    except InputError:
        return []
    if inputs.capture is None:
        return []
    try:
        return [flow for flow in read_media(inputs.capture, decode_ports=ports, heuristic=not ports) if flow.kind == "rtp"]
    except (LadderCaptureError, OSError, ValueError):
        return []


class Lazy:
    """The ladder document and RTP flows for one run directory, built on first use."""

    def __init__(self, run_dir: Path, show_addresses: bool, approve: list, enabled: bool = True) -> None:
        self.run_dir = run_dir
        self.show = show_addresses
        self.approve = list(approve)
        self.enabled = enabled
        self._document: Optional[dict] = None
        self._tried = False
        self.reason: Optional[str] = None
        self._flows: dict = {}

    def document(self) -> Optional[dict]:
        if not self._tried:
            self._tried = True
            if not self.enabled:
                self.reason = "the ladder was not requested"
            else:
                self._document, self.reason = load(self.run_dir, self.show, self.approve)
        return self._document

    def peek(self) -> Optional[dict]:
        return self._document

    def flows(self, ports: set) -> list:
        if not self.enabled:
            return []
        key = frozenset(ports)
        if key not in self._flows:
            self._flows[key] = rtp_flows(self.run_dir, set(ports))
        return self._flows[key]


__all__ = ["load", "pick_section", "excerpt", "rtp_flows", "render_text", "Lazy"]
