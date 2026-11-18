"""Column spacing and label fitting shared by the text and HTML renderers.

A label is never cut mid-word and a tag is never cut at all. When labels do not
fit the spacing, the reason phrase is shortened by whole words first; the
column gaps are sized from what the arrows need before any shortening.
"""

from __future__ import annotations

import re
from typing import Optional

REASON_CAPS = (None, 28, 20, 14, 8, 0)  # progressively shorter reason phrases
_METHOD_SUFFIX = re.compile(r"^(.*?)( \([A-Z]+\))?$")


def split_label(event: dict) -> tuple:
    """Return (head, reason, suffix); only SIP responses carry a reason."""
    label = event.get("label", "")
    status = event.get("status")
    if event.get("type") != "sip" or status is None or not label.startswith(str(status)):
        return label, "", ""
    rest = label[len(str(status)) :].strip()
    match = _METHOD_SUFFIX.match(rest)
    reason = (match.group(1) if match else rest) or ""
    suffix = (match.group(2) or "") if match else ""
    return str(status), reason, suffix


def shorten_reason(reason: str, cap: Optional[int]) -> str:
    if cap is None or len(reason) <= cap:
        return reason
    if cap <= 0:
        return ""
    words = reason.split()
    kept: list = []
    for word in words:
        trial = " ".join(kept + [word])
        if len(trial) + 3 > cap:
            break
        kept.append(word)
    return (" ".join(kept) + "...") if kept else ""


def fit_label(event: dict, cap: Optional[int]) -> str:
    head, reason, suffix = split_label(event)
    if not reason and not suffix:
        return event.get("label", "")
    short = shorten_reason(reason, cap)
    return (head + (" " + short if short else "") + suffix).strip()


def solve_gaps(count: int, needs: list, mins: list, avail: float) -> Optional[list]:
    """Gaps between adjacent columns.

    needs: (lo, hi, span_needed) per arrow, columns lo < hi. mins: minimum gap
    per adjacent pair. Returns None when the minimum layout exceeds avail.
    Spare room is shared equally.
    """
    gaps = list(mins)
    for _ in range(3):
        for lo, hi, need in sorted(needs, key=lambda n: n[1] - n[0]):
            have = sum(gaps[lo:hi])
            if have < need:
                add = (need - have) / (hi - lo)
                for i in range(lo, hi):
                    gaps[i] += add
    total = sum(gaps)
    if total > avail:
        return None
    extra = (avail - total) / len(gaps)
    return [g + extra for g in gaps]


def pick_caps(count: int, events: list, avail: float, need_of, mins: list) -> tuple:
    """Choose the least aggressive reason cap whose layout fits avail.

    need_of(event, label) -> span needed. Returns (cap, gaps); gaps may be
    scaled to fit when even the shortest labels do not, in which case cap is the
    shortest and the renderer must fall back to moving tags below the arrow.
    """
    for cap in REASON_CAPS:
        needs = []
        for event in events:
            if event["from"] == event["to"]:
                continue
            lo, hi = sorted((event["from"], event["to"]))
            needs.append((lo, hi, need_of(event, fit_label(event, cap))))
        gaps = solve_gaps(count, needs, mins, avail)
        if gaps is not None:
            return cap, gaps
    each = avail / (count - 1)
    return REASON_CAPS[-1], [each] * (count - 1)


def label_slot(xs: list, lo_i: int, hi_i: int, width_needed: float, pad: float) -> tuple:
    """Return (left, right) bounds for a label of width_needed on an arrow that
    runs from column lo_i to hi_i. Prefer a single gap that fits so the label
    does not sit on a lifeline in between; else the whole span."""
    best = None
    for i in range(lo_i, hi_i):
        left, right = xs[i], xs[i + 1]
        if right - left - 2 * pad >= width_needed:
            if best is None or (right - left) > (best[1] - best[0]):
                best = (left, right)
            if hi_i - lo_i == 1:
                break
    return best if best is not None else (xs[lo_i], xs[hi_i])


def trim_words(label: str, room: int) -> str:
    """Cut a label at a word boundary and mark the cut; never mid-word."""
    if len(label) <= room:
        return label
    kept: list = []
    for word in label.split():
        trial = " ".join(kept + [word])
        if len(trial) + 3 > room:
            break
        kept.append(word)
    return (" ".join(kept) + "...") if kept else label[: max(room, 1)]
