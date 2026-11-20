"""Which runs of one engagement were active at the same time (rehearsal 3, findings 1 and 8).

The overlap guard refuses a second sender while one is active, and a run the
operator allowed beside another one records that in its own result
(``overlap``). Neither tells the *first* run that a second one joined it, and
two commands started in the same instant can both pass the guard. This module
finds the overlap afterwards, from the times every run directory records
(``timestamps.json``), for ``diagnose`` and the owner report.

A run's window is the time its packet capture was open (``capture_ready`` to
``capture_stopped``), or ``started`` to ``finished`` where a run records no
capture times. Two runs overlap when their windows share more than an instant.
Runs are compared only within one engagement directory (the direct children of
``ENG/calls``, ``ENG/runs`` and ``ENG/checks``). Reads local files only.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

RUN_ROOTS = ("calls", "runs", "checks")
MAX_SIBLINGS = 5000
MAX_STAMPS_BYTES = 64 * 1024
UNRELIABLE = "another run was active; this verdict is unreliable"


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def window(stamps: Mapping[str, Any] | None) -> tuple[datetime, datetime] | None:
    """The time a run could send or capture, from its recorded timestamps, or None."""
    if not isinstance(stamps, Mapping):
        return None
    start = _time(stamps.get("capture_ready")) or _time(stamps.get("started"))
    end = _time(stamps.get("capture_stopped")) or _time(stamps.get("finished"))
    if start is None or end is None or end < start:
        return None
    return start, end


def call_window(stamps: Mapping[str, Any] | None) -> tuple[datetime, datetime] | None:
    """The time a guided call was in progress (``call_started`` to ``call_ended``), else the run window."""
    if isinstance(stamps, Mapping):
        start, end = _time(stamps.get("call_started")), _time(stamps.get("call_ended"))
        if start is not None and end is not None and end >= start:
            return start, end
    return window(stamps)


def overlaps(first: tuple[datetime, datetime] | None, second: tuple[datetime, datetime] | None) -> bool:
    """True when both windows are known and share more than an instant."""
    if first is None or second is None:
        return False
    return first[0] < second[1] and second[0] < first[1]


def read_stamps(run_dir: Path) -> dict[str, Any] | None:
    """``timestamps.json`` of a run directory (else the result's ``timestamps``), or None."""
    for name, key in (("timestamps.json", None), ("result.json", "timestamps")):
        path = run_dir / name
        try:
            if path.is_symlink() or not path.is_file():
                continue
            if key is None and path.stat().st_size > MAX_STAMPS_BYTES:
                continue
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if key is not None:
            value = value.get(key) if isinstance(value, dict) else None
        if isinstance(value, dict):
            return value
    return None


def engagement_of(run_dir: Path) -> Path | None:
    """The engagement directory of ``ENG/calls/RUN`` (or ``runs``, ``checks``), else None."""
    run_dir = Path(run_dir)
    return run_dir.parent.parent if run_dir.parent.name in RUN_ROOTS else None


def sibling_overlaps(run_dir: str | Path) -> list[str]:
    """Names of the other runs of the same engagement whose windows overlap this run's.

    Empty when the run records no times, is not inside an engagement's run
    root, or ran alone. Never raises.
    """
    run_dir = Path(run_dir)
    try:
        engagement = engagement_of(run_dir)
        own = window(read_stamps(run_dir))
        if engagement is None or own is None:
            return []
        found: list[str] = []
        seen = 0
        for root in RUN_ROOTS:
            directory = engagement / root
            if directory.is_symlink() or not directory.is_dir():
                continue
            for sibling in sorted(directory.iterdir()):
                seen += 1
                if seen > MAX_SIBLINGS:
                    return sorted(found)
                if sibling.name == run_dir.name and sibling.parent.name == run_dir.parent.name:
                    continue
                if sibling.is_symlink() or not sibling.is_dir():
                    continue
                if overlaps(own, window(read_stamps(sibling))):
                    found.append(sibling.name)
        return sorted(found)
    except OSError:
        return []
