"""Self-contained HTML rendering: inline SVG and CSS, no external assets."""

from __future__ import annotations

import html
import textwrap
from typing import Any

from .layout import fit_label, label_slot, pick_caps

CHAR_W = 7.2  # monospace 12px
LINE_H = 15
GUTTER = 150
MARGIN = 20

_STYLE = """
:root{--bg:#ffffff;--fg:#1b2330;--muted:#5d6878;--line:#c9d0da;--panel:#f4f6f9;--req:#1f5fbf;--ok:#17803d;--err:#c62828;--warn:#a15c00;--info:#5d6878;--retrans:#c2570c;--auth:#7b3fa8;--media:#0b7a75;--transport:#59647a;--note:#fff7e0;--noteb:#e2b93b}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#10151d;--fg:#e3e8ef;--muted:#9aa6b8;--line:#3a4557;--panel:#182030;--req:#6ea8ff;--ok:#5ad08a;--err:#ff7b72;--warn:#e3a53b;--info:#9aa6b8;--retrans:#ff9a52;--auth:#c79bf2;--media:#4fd1c5;--transport:#9aa6b8;--note:#2a2410;--noteb:#8a6d12}}
:root[data-theme="dark"]{--bg:#10151d;--fg:#e3e8ef;--muted:#9aa6b8;--line:#3a4557;--panel:#182030;--req:#6ea8ff;--ok:#5ad08a;--err:#ff7b72;--warn:#e3a53b;--info:#9aa6b8;--retrans:#ff9a52;--auth:#c79bf2;--media:#4fd1c5;--transport:#9aa6b8;--note:#2a2410;--noteb:#8a6d12}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:20px 16px 40px}
h1{font-size:1.4rem;margin:0 0 4px}
h2{font-size:1.1rem;margin:0}
.sub{color:var(--muted);margin:0 0 14px}
.banner{border:1px solid var(--line);background:var(--panel);border-radius:8px;padding:10px 14px;margin:12px 0}
.banner.warn{background:var(--note);border-color:var(--noteb)}
.banner ul{margin:6px 0 0;padding-left:20px}
section.call{border:1px solid var(--line);border-radius:10px;margin:22px 0;padding:14px 14px 10px;break-inside:avoid}
.meta{color:var(--muted);font-size:.92rem;margin:4px 0 6px}
.meta b{color:var(--fg)}
.outcome{margin:2px 0 8px}
.scroll{overflow-x:auto}
svg{display:block;min-width:720px;width:100%;height:auto}
svg text{font-family:ui-monospace,"SFMono-Regular",Menlo,Consolas,monospace;font-size:12px;fill:var(--fg)}
svg .muted{fill:var(--muted)}
svg .lbl{paint-order:stroke;stroke:var(--bg);stroke-width:4px;stroke-linejoin:round}
svg .life{stroke:var(--line);stroke-width:1.2;stroke-dasharray:3 4}
svg .head{fill:var(--panel);stroke:var(--line)}
svg .rowline{stroke:var(--line);stroke-width:.5;opacity:.5}
svg .a{fill:none;stroke-width:1.8}
svg .req{stroke:var(--req)} svg .ok{stroke:var(--ok)} svg .err{stroke:var(--err)} svg .info{stroke:var(--info)} svg .redir{stroke:var(--warn)}
svg .resp{stroke-dasharray:7 3}
svg .retrans{stroke:var(--retrans);stroke-dasharray:2 3}
svg .media{stroke:var(--media);stroke-width:4;stroke-linecap:butt}
svg .transport{stroke:var(--transport)}
svg .mk-req{fill:var(--req)} svg .mk-ok{fill:var(--ok)} svg .mk-err{fill:var(--err)} svg .mk-info{fill:var(--info)} svg .mk-redir{fill:var(--warn)} svg .mk-retrans{fill:var(--retrans)} svg .mk-media{fill:var(--media)} svg .mk-transport{fill:var(--transport)}
svg .pill{fill:none;stroke-width:1.2;rx:8}
svg .pill-auth{stroke:var(--auth)} svg .pill-retrans{stroke:var(--retrans)} svg .pill-bad{stroke:var(--err)} svg .pill-enc{stroke:var(--transport)}
svg .t-auth{fill:var(--auth)} svg .t-retrans{fill:var(--retrans)} svg .t-bad{fill:var(--err)} svg .t-enc{fill:var(--transport)}
svg .lbl-err{fill:var(--err)} svg .lbl-ok{fill:var(--ok)} svg .lbl-media{fill:var(--media)}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;color:var(--muted);font-size:.88rem;margin:10px 0 0}
.legend i{display:inline-block;width:26px;border-top:2px solid;vertical-align:middle;margin-right:6px}
details{margin-top:10px}
summary{cursor:pointer;color:var(--muted)}
pre{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px;font-size:12px;line-height:1.35}
footer{color:var(--muted);font-size:.88rem;margin-top:24px}
@media print{
 :root{--bg:#fff;--fg:#000;--muted:#444;--line:#999;--panel:#fff}
 body{font-size:11pt} main{max-width:none;padding:0}
 details{display:none} svg{min-width:0} .scroll{overflow:visible}
 section.call{page-break-inside:avoid}
}
"""


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _clip(text: str, chars: int) -> str:
    if chars <= 4:
        return text[: max(chars, 0)]
    return text if len(text) <= chars else text[: chars - 3] + "..."


def _arrow_class(event: dict) -> tuple:
    if event["type"] == "media":
        return "media", "mk-media", "lbl-media"
    if event["type"] == "transport":
        return "transport", "mk-transport", ""
    if event.get("retrans"):
        return "retrans", "mk-retrans", ""
    status = event.get("status")
    resp = " resp" if event.get("kind") == "response" else ""
    if status is None:
        return "req", "mk-req", ""
    if status < 200:
        return "info" + resp, "mk-info", ""
    if status < 300:
        return "ok" + resp, "mk-ok", "lbl-ok"
    if status < 400:
        return "redir" + resp, "mk-redir", ""
    return "err" + resp, "mk-err", "lbl-err"


_TAGS = {
    "auth-challenge": ("AUTH CHALLENGE", "auth"),
    "auth-response": ("AUTH RESPONSE", "auth"),
    "retransmission": ("RETRANSMISSION", "retrans"),
    "truncated": ("TRUNCATED", "bad"),
    "encrypted": ("ENCRYPTED", "enc"),
}


def _section_svg(section: dict) -> str:
    columns = section["columns"]
    count = len(columns)
    inner = 90
    base = max(1000, 250 * count + GUTTER + 2 * MARGIN)
    events_all = section["events"]

    def pills_of(event: dict) -> list:
        return [_TAGS[t] for t in event.get("tags", ()) if t in _TAGS]

    def need(event: dict, label: str) -> float:
        return (len(label) + sum(len(text) + 3 for text, _ in pills_of(event))) * CHAR_W + 40

    width, cap, gaps = base, None, None
    if count > 1:
        for width in dict.fromkeys((base, max(base, 1300), max(base, 1600))):
            span = width - GUTTER - 2 * MARGIN
            cap, gaps = pick_caps(count, events_all, span - 2 * inner, need, [210] * (count - 1))
            if cap is None:  # every label fits in full: widen rather than shorten
                break
    span = width - GUTTER - 2 * MARGIN
    if count == 1:
        xs = [GUTTER + MARGIN + span // 2]
    else:
        xs = [GUTTER + MARGIN + inner]
        for gap in gaps:
            xs.append(xs[-1] + gap)
        xs = [int(x) for x in xs]
    head_h = 52
    rows = []
    y = head_h + 14
    markers = set()
    for event in section["events"]:
        a, b = xs[event["from"]], xs[event["to"]]
        lo, hi = min(a, b), max(a, b)
        klass, marker, label_class = _arrow_class(event)
        markers.add(marker)
        pills = pills_of(event)
        pill_chars = sum(len(text) + 3 for text, _ in pills)
        label = fit_label(event, cap)
        y_label = y + 11
        y_line = y + 20
        parts = []
        t_text = f"+{event['t']:.3f}s"
        parts.append(f'<text x="{MARGIN}" y="{y_line + 4}">{_esc(t_text)}</text>')
        if event.get("gap") is not None:
            parts.append(f'<text x="{MARGIN + 74}" y="{y_line + 4}" class="muted">(+{event["gap"]:.3f}s)</text>')
        if hi > lo:
            direction_right = a < b
            x1, x2 = (lo + 3, hi - 3) if direction_right else (hi - 3, lo + 3)
            # Leave room for the arrow head.
            if direction_right:
                x2 -= 2
            else:
                x2 += 2
            parts.append(
                f'<line class="a {klass}" x1="{x1}" y1="{y_line}" x2="{x2}" y2="{y_line}" marker-end="url(#{marker})"/>'
            )
            ci, cj = xs.index(lo), xs.index(hi)
            left, right = label_slot(xs, ci, cj, (len(label) + pill_chars) * CHAR_W + 8, 4)
            mid = (left + right) / 2
        else:
            mid = a + 80
        text_width = (len(label) + pill_chars) * CHAR_W
        start = mid - text_width / 2
        parts.append(
            f'<text x="{start:.1f}" y="{y_label}" class="lbl {label_class}"><title>{_esc(event["label"])}</title>{_esc(label)}</text>'
        )
        px = start + len(label) * CHAR_W + 8
        for text, kind in pills:
            w = len(text) * CHAR_W + 10
            parts.append(
                f'<rect class="pill pill-{kind}" x="{px:.1f}" y="{y_label - 11}" width="{w:.1f}" height="15" rx="7"/>'
                f'<text x="{px + 5:.1f}" y="{y_label}" class="t-{kind}" style="font-size:10px">{_esc(text)}</text>'
            )
            px += w + 5
        y_next = y + 34
        detail_x = lo + 10
        detail_chars = max(30, int((max(hi - lo, 320) - 16) / (CHAR_W - 0.6)))
        for detail in event.get("details", []):
            for piece in textwrap.wrap(detail, detail_chars, subsequent_indent="  ") or [""]:
                parts.append(f'<text x="{detail_x}" y="{y_next}" class="muted" style="font-size:11px">{_esc(piece)}</text>')
                y_next += LINE_H - 1
        rows.append("".join(parts))
        parts_y = y_next + 6
        rows.append(f'<line class="rowline" x1="{MARGIN}" y1="{parts_y - 4}" x2="{width - MARGIN}" y2="{parts_y - 4}"/>')
        y = parts_y
    total_h = y + 8
    out = [
        f'<svg viewBox="0 0 {width} {total_h}" role="img" aria-label="{_esc(section["title"])} {section["index"]} sequence diagram">',
        f"<title>{_esc(section['title'])} {section['index']} ladder</title>",
        "<defs>",
    ]
    for name in sorted(markers):
        out.append(
            f'<marker id="{name}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto"><path class="{name}" d="M0 0L10 5L0 10z"/></marker>'
        )
    out.append("</defs>")
    out.append(f'<text x="{MARGIN}" y="22" class="muted">time</text><text x="{MARGIN + 74}" y="22" class="muted">gap</text>')
    for column, x in zip(columns, xs):
        label = _clip(column["label"], 28)
        role = "/".join(column["roles"])
        out.append(f'<line class="life" x1="{x}" y1="{head_h}" x2="{x}" y2="{total_h}"/>')
        out.append(f'<rect class="head" x="{x - 100}" y="8" width="200" height="40" rx="6"/>')
        out.append(f'<text x="{x}" y="25" text-anchor="middle">{_esc(label)}</text>')
        out.append(f'<text x="{x}" y="41" text-anchor="middle" class="muted" style="font-size:11px">{_esc(role)}</text>')
    out.extend(rows)
    out.append("</svg>")
    return "".join(out)


def render_html(document: dict, text_version: str) -> str:
    sections_html = []
    for section in document["sections"]:
        meta = [
            f"<b>start</b> {_esc(section['startUtc'])}",
            f"<b>span</b> {section['durationSeconds']:.3f}s",
            f"<b>source</b> {_esc(section['source'])}",
        ]
        if section.get("callIdHash"):
            meta.append(f"<b>call-id hash</b> {_esc(section['callIdHash'])}")
        counts = section["counts"]
        meta.append(
            f"{counts['sipMessages']} SIP message(s), {counts['retransmissions']} retransmission(s), {counts['mediaFlows']} media flow(s)"
        )
        outcome = f'<p class="outcome"><b>Outcome:</b> {_esc(section["outcome"])}</p>' if section.get("outcome") else ""
        sections_html.append(
            f'<section class="call" id="section-{section["index"]}">'
            f"<h2>[{section['index']}] {_esc(section['title'])}</h2>"
            f'<p class="meta">{" &middot; ".join(meta)}</p>{outcome}'
            f'<div class="scroll">{_section_svg(section)}</div></section>'
        )
    redaction = document["redaction"]
    unredacted = redaction["addresses"].startswith("shown")
    banner_class = "banner warn" if unredacted or document["warnings"] else "banner"
    items = [
        "Addresses: " + _esc(redaction["addresses"])
        + (f" ({redaction['addressesRelabeled']} relabeled)" if redaction["addressesRelabeled"] else ""),
        "Never shown: credentials, nonces, crypto keys, user parts, message bodies beyond the SDP summary, DTMF digit values. Call-IDs appear only as a short hash.",
    ]
    if unredacted:
        items.insert(0, "<b>Operator copy: addresses are not redacted. Do not attach this file to an owner report.</b>")
    for note in document["notes"]:
        items.append("Note: " + _esc(note))
    for warning in document["warnings"]:
        items.append("<b>Warning:</b> " + _esc(warning))
    source = ", ".join(f"{_esc(k)}: {_esc(v)}" for k, v in document["source"].items() if v)
    legend = (
        '<div class="legend">'
        '<span><i style="color:var(--req)"></i>request</span>'
        '<span><i style="color:var(--ok);border-top-style:dashed"></i>2xx response</span>'
        '<span><i style="color:var(--err);border-top-style:dashed"></i>4xx-6xx response</span>'
        '<span><i style="color:var(--info);border-top-style:dashed"></i>1xx response</span>'
        '<span><i style="color:var(--retrans);border-top-style:dotted"></i>retransmission</span>'
        '<span><i style="color:var(--media);border-top-width:4px"></i>RTP/RTCP aggregate</span>'
        '<span><i style="color:var(--transport)"></i>TCP/TLS</span>'
        "</div>"
    )
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="color-scheme" content="light dark">'
        "<title>Sippycup ladder</title>"
        f"<style>{_STYLE}</style></head><body><main>"
        "<h1>SIP and media ladder</h1>"
        f'<p class="sub">Offline analysis of recorded evidence; no traffic was sent. Evidence: {source}</p>'
        f'<div class="{banner_class}"><ul>' + "".join(f"<li>{item}</li>" for item in items) + "</ul></div>"
        + "".join(sections_html)
        + legend
        + "<details><summary>Plain-text version (copy and paste)</summary><pre>"
        + _esc(text_version)
        + "</pre></details>"
        "<footer>Generated by sippycup ladder. Aggregate media rows replace one line per packet.</footer>"
        "</main></body></html>\n"
    )
