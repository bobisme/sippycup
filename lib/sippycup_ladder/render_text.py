"""Terminal rendering of the ladder document (ASCII only)."""

from __future__ import annotations

import textwrap
from typing import Any

MARGIN = 14


def _fmt_t(value: float) -> str:
    return f"+{value:.3f}s"


def _fmt_gap(value: Any) -> str:
    return "" if value is None else f"(+{value:.3f}s)"


def _clip(text: str, room: int) -> str:
    if room <= 0:
        return ""
    if len(text) <= room:
        return text
    if room <= 3:
        return text[:room]
    return text[: room - 3] + "..."


def _positions(count: int, gutter: int, width: int) -> list:
    body = width - gutter
    if count == 1:
        return [gutter + body // 2]
    margin = min(MARGIN, max(4, body // (count * 3)))
    span = body - 2 * margin
    return [gutter + margin + (span * i) // (count - 1) for i in range(count)]


def _put(canvas: list, x: int, text: str) -> None:
    for offset, char in enumerate(text):
        position = x + offset
        if 0 <= position < len(canvas):
            canvas[position] = char


def _bars(canvas: list, xs: list) -> None:
    for x in xs:
        if 0 <= x < len(canvas):
            canvas[x] = "|"


def _arrow_line(canvas: list, xs: list, event: dict, label: str) -> None:
    a, b = xs[event["from"]], xs[event["to"]]
    if event["type"] == "media":
        fill = "="
    elif "retransmission" in event.get("tags", ()):
        fill = "~"
    else:
        fill = "-"
    if a == b:
        _put(canvas, a + 2, label)
        return
    lo, hi = (a, b) if a < b else (b, a)
    for x in range(lo + 1, hi):
        canvas[x] = fill
    if a < b:
        canvas[hi - 1] = ">"
    else:
        canvas[lo + 1] = "<"
    room = hi - lo - 6
    text = " " + _clip(label, room) + " "
    start = lo + 1 + ((hi - lo - 1) - len(text)) // 2
    _put(canvas, max(lo + 3, start), text)


def render_section(section: dict, width: int) -> list:
    columns = section["columns"]
    events = section["events"]
    time_w = max([8] + [len(_fmt_t(e["t"])) for e in events])
    gap_w = max([9] + [len(_fmt_gap(e.get("gap"))) for e in events])
    gutter = 1 + time_w + 2 + gap_w + 2
    xs = _positions(len(columns), gutter, width)
    lines = []
    title = f"[{section['index']}] {section['title']}"
    if section.get("callIdHash"):
        title += f"  [call-id hash {section['callIdHash']}]"
    title += f"  [source: {section['source']}]"
    lines.append("=" * min(width, max(len(title) + 6, 20)))
    lines.append(title)
    lines.append(f"start {section['startUtc']}   span {section['durationSeconds']:.3f}s")
    if section.get("outcome"):
        lines.append(f"outcome: {section['outcome']}")
    lines.append("")
    spacing = min((xs[i + 1] - xs[i] for i in range(len(xs) - 1)), default=width)
    header_labels = _header(columns, xs, width, spacing)
    for header in header_labels:
        lines.append(header)
    time_head = " " + "time".ljust(time_w) + "  " + "gap".ljust(gap_w)
    row = [" "] * width
    _put(row, 0, time_head)
    _bars(row, xs)
    lines.append("".join(row).rstrip())
    for event in events:
        canvas = [" "] * width
        _put(canvas, 1, _fmt_t(event["t"]).rjust(time_w))
        if event.get("gap") is not None:
            _put(canvas, 1 + time_w + 2, _fmt_gap(event["gap"]))
        _bars(canvas, xs)
        label = event["label"]
        tag_text = _tag_text(event)
        _arrow_line(canvas, xs, event, label + tag_text)
        lines.append("".join(canvas).rstrip())
        lo = min(xs[event["from"]], xs[event["to"]])
        hi = max(xs[event["from"]], xs[event["to"]])
        for detail in event.get("details", []):
            start = lo + 2
            room = max(24, (hi - start - 2) if hi > lo else width - start - 1)
            wrapped = textwrap.wrap(detail, room, subsequent_indent="  ") or [""]
            for piece in wrapped:
                detail_canvas = [" "] * width
                _bars(detail_canvas, xs)
                _put(detail_canvas, start, piece)
                lines.append("".join(detail_canvas).rstrip())
    return lines


def _tag_text(event: dict) -> str:
    short = []
    for tag in event.get("tags", ()):
        short.append({"auth-challenge": "AUTH CHALLENGE", "auth-response": "AUTH RESPONSE", "retransmission": f"RETRANS #{event.get('retrans', '')}", "truncated": "TRUNCATED", "encrypted": "ENCRYPTED"}.get(tag, tag))
    return (" [" + ",".join(short) + "]") if short else ""


def _header(columns: list, xs: list, width: int, spacing: int) -> list:
    out = []
    for key in ("label", "roles"):
        canvas = [" "] * width
        for column, x in zip(columns, xs):
            text = column["label"] if key == "label" else "(" + "/".join(column["roles"]) + ")"
            text = _clip(text, max(8, spacing - 1) if len(columns) > 1 else width - 4)
            start = max(0, min(width - len(text), x - len(text) // 2))
            _put(canvas, start, text)
        out.append("".join(canvas).rstrip())
    return out


def render_text(document: dict, width: int = 100) -> str:
    out = []
    out.append("Sippycup ladder (offline analysis; no network activity)")
    source = document["source"]
    bits = [f"{k}={v}" for k, v in source.items() if v]
    out.append("source: " + ", ".join(bits))
    redaction = document["redaction"]
    banner = (
        "ADDRESSES ARE NOT REDACTED: operator copy, do not attach to an owner report"
        if redaction["addresses"].startswith("shown")
        else "redaction: " + redaction["addresses"]
        + (f" ({redaction['addressesRelabeled']} relabeled)" if redaction["addressesRelabeled"] else "")
    )
    out.append(banner)
    out.append("never shown: credentials, nonces, crypto keys, user parts, Call-IDs (hash only), message bodies (SDP summary only), DTMF digit values")
    for note in document["notes"]:
        out.extend(textwrap.wrap("note: " + note, width - 2, subsequent_indent="      "))
    for warning in document["warnings"]:
        out.extend(textwrap.wrap("WARNING: " + warning, width - 2, subsequent_indent="         "))
    out.append("")
    for section in document["sections"]:
        out.extend(render_section(section, width))
        out.append("")
    out.append("legend: ---> SIP message   ~~~> retransmission   ===> RTP/RTCP aggregate   [AUTH CHALLENGE]/[AUTH RESPONSE] Digest exchange (values never shown)")
    return "\n".join(out) + "\n"
