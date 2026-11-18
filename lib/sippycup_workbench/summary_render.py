"""Markdown, HTML, and plain-text renderings of the engagement report model.

Rendering is pure: the same model and report hash give byte-identical
output. Every value is escaped for its target syntax; the HTML is a single
self-contained file (inline CSS and static SVG, no scripts, no external
assets) that reads the same with scripts disabled and prints cleanly.
"""

from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from typing import Any, Iterable

SEVERITY_LABEL = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO", "none": "NONE"}
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|~&])")


# --------------------------------------------------------------------------
# Shared formatting


def _value(value: Any, empty: str = "—") -> str:
    if value is None or value == "" or value == []:
        return empty
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:g}"
    return str(value)


def _target(target: dict[str, Any] | None) -> str:
    if not target:
        return "—"
    text = target.get("address") or "unrecorded"
    if target.get("port") is not None:
        text += f":{target['port']}"
    if target.get("transport"):
        text += f"/{target['transport']}"
    if target.get("serverName"):
        text += f" ({target['serverName']})"
    return text


def _sent(sent: dict[str, Any]) -> str:
    parts = []
    labels = (
        ("optionsRequests", "OPTIONS request", "OPTIONS requests"),
        ("registerAttempts", "REGISTER transaction", "REGISTER transactions"),
        ("calls", "call", "calls"),
        ("rtpPacketsSent", "RTP packet sent", "RTP packets sent"),
        ("checkRequests", "check request", "check requests"),
        ("capturePackets", "packet captured", "packets captured"),
        ("captureBytes", "capture byte", "capture bytes"),
    )
    for key, one, many in labels:
        value = sent.get(key)
        if value is None:
            continue
        if key in {"calls", "optionsRequests", "registerAttempts", "rtpPacketsSent"} and value == 0:
            continue
        prefix = "at least " if key == "optionsRequests" and sent.get("optionsLowerBound") else ""
        parts.append(f"{prefix}{value} {one if value == 1 else many}")
    return ", ".join(parts) or "—"


def _yes(value: Any) -> str:
    return _value(value)


def _call_answer(call: dict[str, Any]) -> str:
    if not call:
        return "—"
    if call.get("answered"):
        text = f"answered ({_value(call.get('finalStatus'))})"
        if call.get("connectedSeconds") is not None:
            text += f", {call['connectedSeconds']:g} s"
        return text
    if call.get("dialed") is False:
        return "not placed"
    status = call.get("finalStatus")
    reason = call.get("disconnectReason")
    text = "not answered"
    if status is not None:
        text += f" ({status}{' ' + reason if reason else ''})"
    if call.get("error"):
        text += f", {call['error']}"
    return text


def _registration(registration: dict[str, Any]) -> str:
    if not registration or not registration.get("attempted"):
        return "not attempted"
    if registration.get("registered"):
        return f"registered ({_value(registration.get('statusCode'))})"
    return f"rejected ({_value(registration.get('statusCode'), 'no status')})"


def _preflight(preflight: dict[str, Any] | None) -> str:
    if not preflight:
        return "not sent"
    code = preflight.get("statusCode")
    reason = preflight.get("reason")
    status = f"{code} {reason}" if code and reason else _value(code, "no response")
    return ("ok: " if preflight.get("ok") else "failed: ") + status


def _tls(tls: dict[str, Any] | None) -> str:
    if not tls:
        return "not used"
    state = "verified" if tls.get("verified") else "NOT verified"
    name = tls.get("serverName")
    trust = tls.get("trust")
    return f"{state}{' as ' + name if name else ''}{' (' + trust + ' trust)' if trust else ''}"


def _oracle(oracle: dict[str, Any]) -> str:
    if not oracle or oracle.get("verdict") is None:
        return "—"
    text = f"{oracle['verdict']} ({_value(oracle.get('pass'), '0')}/{_value(oracle.get('fail'), '0')}/{_value(oracle.get('unknown'), '0')})"
    if not oracle.get("decidesVerdict"):
        text += ", advisory"
    return text


def _media(media: dict[str, Any]) -> str:
    if not media:
        return "—"
    return f"{_value(media.get('toPeerPackets'))} / {_value(media.get('fromPeerPackets'))}"


def _seconds(value: Any) -> str:
    return "—" if value is None else f"{value:g}"


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Markdown


def md(value: Any) -> str:
    text = _value(value)
    return _MD_SPECIAL.sub(r"\\\1", text)


def code(value: Any) -> str:
    # GFM splits table cells on "|" even inside code spans, so escape it.
    text = _value(value).replace("`", "'").replace("|", "\\|")
    return f"`{text}`"


def _md_table(headers: list[str], rows: Iterable[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    count = 0
    for row in rows:
        assert len(row) == len(headers)
        lines.append("| " + " | ".join(cell if cell else "—" for cell in row) + " |")
        count += 1
    if count == 0:
        lines.append("| " + " | ".join(["—"] * len(headers)) + " |")
    return lines + [""]


def render_markdown(model: dict[str, Any], report_sha256: str) -> str:
    e = model["engagement"]
    out: list[str] = [f"# {md(e['title'])}", ""]
    out.append(
        f"Engagement report for the platform owner. Generated {md(e['generatedAt'])}; "
        f"audience: {md(model['audience'])}; Sippycup {md(model['toolbox']['cliVersion'])}. "
        "No network activity was needed to produce it."
    )
    out.append("")
    exceptions = model["integrityExceptions"]
    if exceptions:
        out += [f"> **Integrity exceptions: {len(exceptions)}.** The report re-checked every run against the approved targets, ports, transports, window, and ceilings. Review these before relying on any result.", ""]
        out += _md_table(
            ["Code", "Run", "Detail"],
            ([code(x["code"]), code(x["run"]) if x["run"] else "—", md(x["detail"])] for x in exceptions),
        )
    # Executive summary
    summary = model["executiveSummary"]
    out += ["## Executive summary", "", md(summary["paragraph"]), ""]
    out += _md_table(
        ["Ref", "Severity", "What we found", "Where", "Source"],
        (
            [md(r["ref"]), f"**{SEVERITY_LABEL.get(r['severity'], r['severity'].upper())}**", md(r["title"]), md(r["where"]), md(r["source"])]
            for r in summary["rows"]
        ),
    )
    # Authorization
    auth = model["authorization"]
    out += ["## Authorization", ""]
    if auth["window"]:
        out.append(f"- Approval window: {md(auth['window']['from'])} to {md(auth['window']['until'])}")
    out.append("- Approved addresses: " + (", ".join(code(a) for a in auth["approvedAddresses"]) or "none recorded"))
    out.append("")
    out += _md_table(
        ["Record", "Kind", "Approval", "Approved by", "Status", "Valid from", "Valid until", "Addresses", "Ports", "Transports", "Server names"],
        (
            [
                code(s["ref"]),
                md(s["kind"]),
                md(s["approvalId"]),
                md(s["approvedBy"]),
                md(s["status"]),
                md(s["validFrom"]),
                md(s["validUntil"]),
                md(", ".join(s["networks"] + s["mediaNetworks"])),
                md(", ".join(str(p) for p in s["ports"])),
                md(", ".join(s["transports"])),
                md(", ".join(s["serverNames"])),
            ]
            for s in auth["sources"]
        ),
    )
    if model["ceilings"]:
        out += ["Approved limits recorded in those records:", ""]
        out += _md_table(
            ["Record", "Limit", "Value"],
            ([code(c["source"]), md(c["limit"]), md(c["value"])] for c in model["ceilings"]),
        )
    # Activity ledger
    out += ["## Activity ledger", ""]
    out += _md_table(
        ["Lane", "Run", "Kind", "Start", "End", "Target", "Sent", "Verdict", "Reason"],
        (
            [
                md(r.get("label")),
                code(r["id"]),
                md(r["kind"]),
                md(r["started"]),
                md(r["finished"]),
                md(_target(r.get("target"))),
                md(_sent(r["sent"])),
                md(r.get("verdict") or r["readable"]),
                md("; ".join(x for x in (r.get("reasons") or []) if x) or ("; ".join(p for p in r["problems"] if p) if r["problems"] else "—")),
            ]
            for r in model["runs"]
        ),
    )
    out += ["Engagement totals (recorded numbers):", ""]
    out += _md_table(
        ["Metric", "Total", "Runs recorded", "Runs without a record"],
        ([md(_METRICS[k]), md(_total(v)), md(v["runsRecorded"]), md(v["runsUnrecorded"])] for k, v in model["totals"].items()),
    )
    out += ["Media per run (RTP packets to and from the peer):", ""]
    out += _md_table(
        ["Run", "To peer", "From peer", "Count source"],
        ([code(m["run"]), md(m["to"]), md(m["from"]), md(m["source"])] for m in media_rows(model)),
    )
    # Results
    out += ["## Results", "", "### Guided calls", ""]
    calls = [r for r in model["runs"] if r["kind"] == "call" and r["readable"] != "unreadable"]
    out += _md_table(
        ["Run", "Destination", "Preflight", "Registration", "Answer", "Setup s", "RTP to/from peer", "Codec", "TLS", "Oracle p/f/u", "Failing assertions"],
        (
            [
                code(r["id"]),
                md(r["details"].get("destination")),
                md(_preflight(r["details"].get("preflight"))),
                md(_registration(r["details"].get("registration") or {})),
                md(_call_answer(r["details"].get("call") or {})),
                md(_seconds((r["details"].get("call") or {}).get("setupSeconds"))),
                md(_media(r["details"].get("media") or {})),
                md((r["details"].get("media") or {}).get("codec")),
                md(_tls(r["details"].get("tls"))),
                md(_oracle(r["details"].get("oracle") or {})),
                md(", ".join((r["details"].get("oracle") or {}).get("failed") or [])),
            ]
            for r in calls
        ),
    )
    out += ["### Campaigns", ""]
    campaigns = [r for r in model["runs"] if r["kind"] == "campaign"]
    if not campaigns:
        out += ["No campaign runs.", ""]
    for run in campaigns:
        d = run["details"]
        out.append(
            f"**{code(run['id'])}** ({md(run.get('campaign'))}): {md(run.get('state') or run['readable'])}, "
            f"{md(d.get('completedSteps'))} of {md(d.get('plannedSteps'))} steps completed"
            + (f"; stop reason {code(d['stopReason'])}" if d.get("stopReason") else "")
            + "."
        )
        out.append("")
        out += _md_table(
            ["Step", "Case", "Type", "Target", "Destination", "Outcome", "Status", "Expected", "RTP to/from", "Setup s", "TLS", "Reasons"],
            (
                [
                    md(c["step"]),
                    code(c["case"]),
                    md(c["type"]),
                    md(_target(c.get("target"))),
                    md(c.get("destination")),
                    md(c["outcome"]),
                    md(c.get("statusCode")),
                    md(c.get("expectedStatus")),
                    md(f"{_value(c.get('rtpToPeer'))} / {_value(c.get('rtpFromPeer'))}" if c["type"] == "call" else None),
                    md(_seconds(c.get("setupSeconds"))),
                    md(None if c.get("tlsVerified") is None else ("verified" if c["tlsVerified"] else "NOT verified")),
                    md(", ".join(c.get("reasons") or [])),
                ]
                for c in d.get("cases", [])
            ),
        )
        if d.get("preflight"):
            out += _md_table(
                ["Preflight target", "Result", "Status", "Warning", "TLS"],
                (
                    [
                        md(_target(p.get("target"))),
                        md("ok" if p.get("ok") else "failed"),
                        md(f"{p['statusCode']} {p['reason']}" if p.get("statusCode") and p.get("reason") else p.get("statusCode")),
                        md(p.get("warning")),
                        md(None if p.get("tlsVerified") is None else ("verified" if p["tlsVerified"] else "NOT verified")),
                    ]
                    for p in d["preflight"]
                ),
            )
    out += ["### Security checks", ""]
    checks = [r for r in model["runs"] if r["kind"] == "check" and r["readable"] != "unreadable"]
    if not checks:
        out += ["No security-check runs.", ""]
    for run in checks:
        out += [f"**{code(run['id'])}** against {md(_target(run.get('target')))}:", ""]
        out += _md_table(
            ["Check", "Status", "Requests sent", "Summary"],
            ([code(c["id"]), md(c["status"]), md(c["requestsSent"]), md(c["summary"])] for c in run["details"].get("checks", [])),
        )
    # Findings
    out += ["## Findings", ""]
    if not model["findings"]:
        out += ["No findings were reported and no observations were derived.", ""]
    for f in model["findings"]:
        label = SEVERITY_LABEL[f["severity"]]
        out += [f"### {md(f['ref'])} {md(f['title'])}", ""]
        out.append(f"- Severity: **{label}**" + (f"; confidence {md(f['confidence'])}" if f.get("confidence") else ""))
        out.append("- Source: " + ("derived by this report from run results (not a security-check finding)" if f["derived"] else f"security check {code(f['checkId'])}"))
        out.append(f"- Target: {md(f.get('targetLabel'))}")
        out.append(f"- First seen: {md(f.get('firstSeen'))}; last seen: {md(f.get('lastSeen'))}; occurrences: {md(f['occurrences'])}")
        out.append("- Evidenced by: " + ", ".join(code(r) for r in f["runs"]))
        out.append("")
        if f.get("summary"):
            out += [md(f["summary"]), ""]
        if f.get("evidence"):
            out.append("Evidence:")
            out.append("")
            for item in f["evidence"]:
                out.append(f"- {md(item.get('kind'))}: {md(item.get('detail'))}" + (f" ({code(item['artifact'])})" if item.get("artifact") else ""))
            out.append("")
        if f.get("remediation"):
            out += [f"Remediation: {md(f['remediation'])}", ""]
        if f.get("references"):
            out += ["References: " + "; ".join(md(r) for r in f["references"] if r), ""]
    # Evidence index
    out += ["## Evidence index", ""]
    out += [f"Toolbox: {md(_toolbox(model['toolbox']))}.", ""]
    journal = model["journal"]
    if journal["present"]:
        out.append(
            f"Journal: {'verified' if journal['valid'] else 'FAILED verification'}, "
            f"{md(journal['entryCount'])} entries, head {code(journal['headSha256'] or 'empty')}, "
            f"{md(journal['missingEvidence'])} missing evidence references"
            + (f" ({md(journal['error'])})" if journal.get("error") else "")
            + "."
        )
        out.append("")
        if journal["entries"]:
            headers = ["Seq", "Kind", "Recorded", "Title"] + (["Notes"] if journal.get("notesIncluded") else [])
            out += _md_table(
                headers,
                (
                    [md(j["sequence"]), md(j["kind"]), md(j["recordedAt"]), md(j["title"])]
                    + ([md(j.get("notes"))] if journal.get("notesIncluded") else [])
                    for j in journal["entries"]
                ),
            )
    else:
        out += ["No assessment journal was found.", ""]
    if model["packs"]:
        out += _md_table(
            ["Evidence pack", "Encrypted", "Size", "SHA-256", "Content identity"],
            ([code(p["name"]), md(p["encrypted"]), md(p["size"]), code(p["sha256"]), code(p["contentIdentity"])] for p in model["packs"]),
        )
    for run in model["runs"]:
        ev = run["evidence"]
        out.append(
            f"**{code(run['id'])}** ({code(run['ref'])}): {md(ev['artifactCount'])} artifacts, {md(ev['totalBytes'])} bytes, "
            f"hashes from {md(ev['source'])}, privacy {md(ev['privacyStatus'] or 'not linted')}"
            + (f" ({md(', '.join(ev['privacyFindingCodes']))})" if ev["privacyFindingCodes"] else "")
            + (f"; changed since manifest: {md(', '.join(ev['changedSinceManifest']))}" if ev["changedSinceManifest"] else "")
            + "."
        )
        out.append("")
        out += _md_table(
            ["Artifact", "Size", "SHA-256", "Sensitivity"],
            ([code(a["path"]), md(a["size"]), code(a["sha256"]), md(a["sensitivity"])] for a in ev["artifacts"]),
        )
    # Limitations and recommendations
    out += ["## Limitations", ""]
    for item in model["limitations"]:
        out.append(f"- {md(item['text'])}")
    out.append("")
    out += ["## Recommendations", ""]
    if model["recommendations"]:
        out += _md_table(
            ["Finding", "Severity", "Recommendation", "Origin"],
            (
                [md(r["finding"]), f"**{SEVERITY_LABEL[r['severity']]}**", md(r["text"]), md("reviewed observation table" if r["derived"] else "security check")]
                for r in model["recommendations"]
            ),
        )
    else:
        out += ["No remediation is recommended from the recorded results.", ""]
    # Integrity footer
    out += ["## Integrity", ""]
    out.append(f"- SHA-256 of `report.json`: {code(report_sha256)}")
    out.append(f"- Journal head: {code(model['integrity']['journalHeadSha256'] or 'none')}")
    out.append("")
    out += _md_table(
        ["Run", "Content identity", "Source"],
        ([code(i["run"]), code(i["contentIdentity"]), md(i["source"])] for i in model["integrity"]["runContentIdentities"]),
    )
    return "\n".join(out).rstrip("\n") + "\n"


_METRICS = {
    "optionsRequests": "SIP OPTIONS requests",
    "registerAttempts": "REGISTER transactions",
    "calls": "Calls placed",
    "rtpPacketsSent": "RTP packets sent",
    "capturePackets": "Captured packets (both directions)",
    "captureBytes": "Captured bytes",
    "checkRequests": "Security-check requests",
}


def _toolbox(toolbox: dict[str, Any]) -> str:
    parts = [f"Sippycup {toolbox.get('cliVersion') or 'unknown'}"]
    for name, versions in sorted((toolbox.get("tools") or {}).items()):
        parts.append(f"{name} {' / '.join(versions)}")
    if toolbox.get("python"):
        parts.append("Python " + " / ".join(toolbox["python"]))
    images = toolbox.get("imageIds") or []
    parts.append("image " + ", ".join(images) if images else "no image id recorded by the runs")
    return "; ".join(parts)


def _total(value: dict[str, Any]) -> str:
    if value.get("total") is None:
        return "—"
    return ("at least " if value.get("lowerBound") else "") + str(value["total"])


def media_rows(model: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for run in model["runs"]:
        if run["kind"] == "call":
            media = run["details"].get("media") or {}
            if media.get("toPeerPackets") is not None or media.get("fromPeerPackets") is not None:
                rows.append({"run": run["id"], "label": run.get("label", ""), "to": media.get("toPeerPackets"), "from": media.get("fromPeerPackets"), "source": media.get("countSource")})
        elif run["kind"] == "campaign":
            for case in run["details"].get("cases", []):
                if case["type"] == "call" and (case.get("rtpToPeer") is not None or case.get("rtpFromPeer") is not None):
                    rows.append({"run": f"{run['id']} step {case['step']}", "label": f"{run.get('label', '')} step {case['step']}", "to": case.get("rtpToPeer"), "from": case.get("rtpFromPeer"), "source": "PJSUA call statistics"})
    return rows


# --------------------------------------------------------------------------
# SVG (static, generated here, paired with text tables)


def _x(value: datetime, start: datetime, end: datetime, left: float, width: float) -> float:
    span = (end - start).total_seconds() or 1.0
    return left + width * max(0.0, min(1.0, (value - start).total_seconds() / span))


def timeline_svg(model: dict[str, Any]) -> str:
    runs = [r for r in model["runs"] if _parse(r.get("started"))]
    window = model["authorization"]["window"]
    w_start = _parse(window["from"]) if window else None
    w_end = _parse(window["until"]) if window else None
    if not runs and not window:
        return ""
    starts = [_parse(r["started"]) for r in runs]
    ends = [_parse(r.get("finished")) or _parse(r["started"]) for r in runs]
    a_start = min(starts) if starts else w_start
    a_end = max(ends) if ends else w_end
    o_start = min(x for x in (w_start, a_start) if x)
    o_end = max(x for x in (w_end, a_end) if x)
    width, left, right = 760.0, 150.0, 20.0
    plot = width - left - right
    lanes = runs[:40]
    height = 96 + 18 * max(1, len(lanes)) + 50
    parts = [
        f'<svg class="timeline" viewBox="0 0 {int(width)} {int(height)}" width="100%" role="img" aria-labelledby="tl-title tl-desc" xmlns="http://www.w3.org/2000/svg">',
        '<title id="tl-title">Runs across the approval window</title>',
        f'<desc id="tl-desc">{len(runs)} runs; the table beside this figure lists the same start and end times.</desc>',
        f'<text x="0" y="16" class="svg-label">Approval window</text>',
    ]
    # Overview band: window and the activity bracket.
    if w_start and w_end:
        x1, x2 = _x(w_start, o_start, o_end, left, plot), _x(w_end, o_start, o_end, left, plot)
        parts.append(f'<rect x="{x1:.1f}" y="8" width="{max(2.0, x2 - x1):.1f}" height="14" class="svg-window"/>')
        parts.append(f'<text x="{x1:.1f}" y="38" class="svg-tick">{html.escape(window["from"])}</text>')
        parts.append(f'<text x="{x2:.1f}" y="38" class="svg-tick" text-anchor="end">{html.escape(window["until"])}</text>')
    if a_start and a_end:
        x1, x2 = _x(a_start, o_start, o_end, left, plot), _x(a_end, o_start, o_end, left, plot)
        parts.append(f'<rect x="{x1:.1f}" y="6" width="{max(3.0, x2 - x1):.1f}" height="18" class="svg-activity"/>')
    # Zoomed band: per-run lanes over the activity span.
    if lanes:
        z_start, z_end = a_start, a_end
        span = (z_end - z_start).total_seconds() or 1.0
        top = 62
        parts.append(f'<text x="0" y="{top - 8}" class="svg-label">Activity span ({span:g} s)</text>')
        for index, run in enumerate(lanes):
            y = top + 18 * index
            s = _parse(run["started"])
            e = _parse(run.get("finished")) or s
            x1 = left + plot * (s - z_start).total_seconds() / span
            x2 = left + plot * (e - z_start).total_seconds() / span
            status = _status_class(run)
            outside = any(x["run"] == run["id"] for x in model["integrityExceptions"])
            label = f"{run.get('label', '')} {run['kind']}"
            parts.append(f'<text x="{left - 6:.0f}" y="{y + 11}" class="svg-run" text-anchor="end">{html.escape(label)}</text>')
            parts.append(
                f'<rect x="{x1:.1f}" y="{y + 2}" width="{max(3.0, x2 - x1):.1f}" height="12" class="svg-bar {status}{" svg-exception" if outside else ""}">'
                f'<title>{html.escape(run["id"])}: {html.escape(run.get("verdict") or run["readable"])}</title></rect>'
            )
        axis = top + 18 * len(lanes) + 6
        parts.append(f'<line x1="{left}" y1="{axis}" x2="{left + plot}" y2="{axis}" class="svg-axis"/>')
        parts.append(f'<text x="{left}" y="{axis + 16}" class="svg-tick">{html.escape(_hms(z_start))}</text>')
        parts.append(f'<text x="{left + plot}" y="{axis + 16}" class="svg-tick" text-anchor="end">{html.escape(_hms(z_end))}</text>')
        legend = axis + 34
        for offset, css, text in ((0, "st-ok", "completed as expected"), (190, "st-bad", "did not pass"), (330, "st-unknown", "unreadable")):
            parts.append(f'<rect x="{left + offset}" y="{legend - 9}" width="10" height="10" class="svg-bar {css}"/>')
            parts.append(f'<text x="{left + offset + 14}" y="{legend}" class="svg-tick">{text}</text>')
        parts.append(f'<rect x="{left + 450}" y="{legend - 9}" width="10" height="10" class="svg-bar st-unknown svg-exception"/>')
        parts.append(f'<text x="{left + 464}" y="{legend}" class="svg-tick">integrity exception</text>')
    parts.append("</svg>")
    return "".join(parts)


def _hms(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%SZ") if value else ""


def _status_class(run: dict[str, Any]) -> str:
    verdict = run.get("verdict")
    if run["readable"] == "unreadable":
        return "st-unknown"
    if verdict in {"pass", "succeeded", "no-findings"}:
        return "st-ok"
    if verdict in {"findings"}:
        return "st-warn"
    return "st-bad"


def media_svg(model: dict[str, Any]) -> str:
    rows = media_rows(model)
    if not rows:
        return ""
    peak = max([r["to"] or 0 for r in rows] + [r["from"] or 0 for r in rows] + [1])
    width, left, right = 760.0, 110.0, 120.0
    plot = width - left - right
    height = 20 + 34 * len(rows[:40])
    parts = [
        f'<svg class="media" viewBox="0 0 {int(width)} {int(height)}" width="100%" role="img" aria-labelledby="md-title md-desc" xmlns="http://www.w3.org/2000/svg">',
        '<title id="md-title">RTP packets to and from the peer per call</title>',
        '<desc id="md-desc">Two bars per call: packets sent to the peer and packets received from it. The adjacent table has the same numbers.</desc>',
    ]
    for index, row in enumerate(rows[:40]):
        y = 10 + 34 * index
        parts.append(f'<text x="{left - 8:.0f}" y="{y + 12}" class="svg-run" text-anchor="end">{html.escape(row["label"])}</text>')
        for offset, key, css, label in ((0, "to", "svg-to", "to peer"), (14, "from", "svg-from", "from peer")):
            value = row[key]
            length = 0.0 if not value else plot * value / peak
            parts.append(f'<rect x="{left}" y="{y + offset}" width="{max(0.0, length):.1f}" height="11" class="{css}"/>')
            parts.append(f'<text x="{left + length + 6:.1f}" y="{y + offset + 10}" class="svg-tick">{label}: {html.escape(_value(value, "unrecorded"))}</text>')
    parts.append("</svg>")
    return "".join(parts)


# --------------------------------------------------------------------------
# HTML

_CSS = """
:root{--bg:#ffffff;--fg:#1d2330;--muted:#5a6270;--line:#d9dde3;--panel:#f5f7f9;--accent:#1f5fa8;
--high:#9b1c1c;--high-bg:#fde8e8;--medium:#8a4b00;--medium-bg:#fdf0dc;--low:#5c5200;--low-bg:#f7f3cf;
--info:#2b4b70;--info-bg:#e3ecf7;--none:#3d4651;--none-bg:#eceff2;--ok:#1d6b3a;--bad:#a12727;--warn:#8a5a00;--unk:#6b7280;
--window:#dbe7f5;--activity:#1f5fa8;--to:#1f5fa8;--from:#2f8a57}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e4e7eb;--muted:#a3abb7;--line:#353b45;--panel:#1c2027;--accent:#7fb0ea;
--high:#ffb4b4;--high-bg:#4a1d1d;--medium:#ffcf94;--medium-bg:#43300f;--low:#ece08a;--low-bg:#3b3712;--info:#b7d0f0;--info-bg:#1f2e42;
--none:#cfd5dc;--none-bg:#2a2f37;--ok:#7fd49b;--bad:#ff9d9d;--warn:#f2c46d;--unk:#9aa3ae;--window:#23354b;--activity:#7fb0ea;--to:#7fb0ea;--from:#7fd49b}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
main{max-width:1040px;margin:0 auto;padding:28px 16px 64px}
h1{font-size:1.75rem;line-height:1.25;margin:0 0 6px}
h2{font-size:1.25rem;margin:40px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:1.05rem;margin:28px 0 8px}
p,li{max-width:72ch}
.meta{color:var(--muted);margin:0 0 20px}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.86em;overflow-wrap:anywhere}
.table-wrap{overflow-x:auto;margin:0 0 18px;border:1px solid var(--line);border-radius:6px}
table{border-collapse:collapse;width:100%;font-size:.9rem}
caption{caption-side:top;text-align:left;font-weight:600;padding:8px 10px;color:var(--fg);background:var(--panel);border-bottom:1px solid var(--line)}
th,td{padding:6px 10px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line);overflow-wrap:break-word;word-break:normal}
th{font-weight:600;color:var(--muted);background:var(--bg)}
tbody tr:last-child td,tbody tr:last-child th{border-bottom:0}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.sev{display:inline-block;min-width:4.6em;text-align:center;font-weight:700;font-size:.75rem;letter-spacing:.04em;padding:1px 6px;border-radius:3px;border:1px solid currentColor}
.sev-high{color:var(--high);background:var(--high-bg)}.sev-medium{color:var(--medium);background:var(--medium-bg)}
.sev-low{color:var(--low);background:var(--low-bg)}.sev-info{color:var(--info);background:var(--info-bg)}.sev-none{color:var(--none);background:var(--none-bg)}
.alert{border:2px solid var(--bad);border-radius:6px;padding:12px 14px;margin:0 0 20px}
.alert h2{margin-top:0;border:0;color:var(--bad)}
.summary{font-size:1.02rem}
.finding{border:1px solid var(--line);border-radius:6px;padding:12px 14px;margin:0 0 14px;break-inside:avoid}
.finding h3{margin:0 0 6px}
.finding dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;margin:8px 0}
.finding dt{color:var(--muted)}.finding dd{margin:0;overflow-wrap:anywhere}
.derived{font-size:.8rem;color:var(--muted);font-weight:600}
.figure{display:grid;grid-template-columns:minmax(0,3fr) minmax(0,2fr);gap:16px;align-items:start}
.figure svg{display:block;width:100%;height:auto;border:1px solid var(--line);border-radius:6px;background:var(--panel)}
.svg-label{font:600 12px system-ui,sans-serif;fill:var(--fg)}
.svg-tick,.svg-run{font:11px ui-monospace,Menlo,Consolas,monospace;fill:var(--muted)}
.svg-window{fill:var(--window)}.svg-activity{fill:var(--activity)}.svg-axis{stroke:var(--line)}
.svg-bar.st-ok{fill:var(--ok)}.svg-bar.st-bad{fill:var(--bad)}.svg-bar.st-warn{fill:var(--warn)}.svg-bar.st-unknown{fill:var(--unk)}
.svg-exception{stroke:var(--bad);stroke-width:2;stroke-dasharray:3 2}
.svg-to{fill:var(--to)}.svg-from{fill:var(--from)}
details{margin:0 0 12px}summary{cursor:pointer;font-weight:600;padding:4px 0}
footer{margin-top:40px;color:var(--muted);font-size:.85rem}
@media (max-width:720px){body{font-size:14px}.figure{grid-template-columns:1fr}h1{font-size:1.4rem}th,td{padding:5px 7px}}
@page{size:auto;margin:16mm 14mm}
@media print{:root{--bg:#fff;--fg:#000;--muted:#333;--line:#999;--panel:#fff}
body{font-size:10.5pt}main{max-width:none;padding:0}h2{break-before:auto;break-after:avoid}h3{break-after:avoid}
.table-wrap{overflow:visible;border:0}table{font-size:9pt}tr,.finding,.figure,svg{break-inside:avoid}
thead{display:table-header-group}details>summary{list-style:none}a{color:inherit;text-decoration:none}
section.evidence{break-before:page}}
""".strip()


def h(value: Any, empty: str = "—") -> str:
    return html.escape(_value(value, empty), quote=True)


def _sev(severity: str) -> str:
    label = SEVERITY_LABEL.get(severity, severity.upper())
    return f'<span class="sev sev-{h(severity)}">{h(label)}</span>'


def _html_table(caption: str, headers: list[str], rows: Iterable[list[str]], numeric: Iterable[int] = (), row_header: bool = True) -> str:
    numeric = set(numeric)
    body = []
    for row in rows:
        cells = []
        for index, cell in enumerate(row):
            if index == 0 and row_header:
                cells.append(f'<th scope="row">{cell}</th>')
            else:
                css = ' class="num"' if index in numeric else ""
                cells.append(f"<td{css}>{cell}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    if not body:
        body.append(f'<tr><td colspan="{len(headers)}">None.</td></tr>')
    head = "".join(f'<th scope="col">{h(x)}</th>' for x in headers)
    return (
        f'<div class="table-wrap"><table><caption>{h(caption)}</caption>'
        f"<thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table></div>"
    )


def _c(value: Any) -> str:
    return f"<code>{h(value)}</code>"


def render_html(model: dict[str, Any], report_sha256: str) -> str:
    e = model["engagement"]
    out: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta name="color-scheme" content="light dark">',
        '<meta name="referrer" content="no-referrer">',
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">",
        f"<title>{h(e['title'])} — engagement report</title>",
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        "<main>",
        "<header>",
        f"<h1>{h(e['title'])}</h1>",
        f'<p class="meta">Engagement report for the platform owner · generated {h(e["generatedAt"])} · audience {h(model["audience"])} · Sippycup {h(model["toolbox"]["cliVersion"])} · produced without network activity</p>',
        "</header>",
    ]
    exceptions = model["integrityExceptions"]
    if exceptions:
        out.append('<section class="alert" aria-labelledby="exceptions">')
        out.append(f'<h2 id="exceptions">Integrity exceptions: {len(exceptions)}</h2>')
        out.append("<p>The report independently re-checked every run against the approved targets, ports, transports, window, and ceilings. Review these before relying on any result.</p>")
        out.append(_html_table("Integrity exceptions", ["Code", "Run", "Detail"], ([_c(x["code"]), _c(x["run"]) if x["run"] else "—", h(x["detail"])] for x in exceptions)))
        out.append("</section>")
    summary = model["executiveSummary"]
    out.append('<section aria-labelledby="summary">')
    out.append('<h2 id="summary">Executive summary</h2>')
    out.append(f'<p class="summary">{h(summary["paragraph"])}</p>')
    out.append(
        _html_table(
            "What we found",
            ["Ref", "Severity", "What we found", "Where", "Source"],
            ([h(r["ref"]), _sev(r["severity"]), h(r["title"]), h(r["where"]), h(r["source"])] for r in summary["rows"]),
        )
    )
    out.append("</section>")
    # Authorization
    auth = model["authorization"]
    out.append('<section aria-labelledby="authorization">')
    out.append('<h2 id="authorization">Authorization</h2>')
    out.append("<ul>")
    if auth["window"]:
        out.append(f"<li>Approval window: {h(auth['window']['from'])} to {h(auth['window']['until'])}</li>")
    out.append("<li>Approved addresses: " + (", ".join(_c(a) for a in auth["approvedAddresses"]) or "none recorded") + "</li>")
    out.append("</ul>")
    out.append(
        _html_table(
            "Reviewed authorization records",
            ["Record", "Kind", "Approval", "Approved by", "Status", "Valid from", "Valid until", "Addresses", "Ports", "Transports", "Server names"],
            (
                [
                    _c(s["ref"]), h(s["kind"]), h(s["approvalId"]), h(s["approvedBy"]), h(s["status"]),
                    h(s["validFrom"]), h(s["validUntil"]), h(", ".join(s["networks"] + s["mediaNetworks"])),
                    h(", ".join(str(p) for p in s["ports"])), h(", ".join(s["transports"])), h(", ".join(s["serverNames"])),
                ]
                for s in auth["sources"]
            ),
        )
    )
    if model["ceilings"]:
        out.append(_html_table("Approved limits", ["Record", "Limit", "Value"], ([_c(c["source"]), h(c["limit"]), h(c["value"])] for c in model["ceilings"]), numeric=[2]))
    out.append("</section>")
    # Activity
    out.append('<section aria-labelledby="activity">')
    out.append('<h2 id="activity">Activity ledger</h2>')
    timeline = timeline_svg(model)
    if timeline:
        out.append('<div class="figure">')
        out.append(timeline)
        out.append(
            _html_table(
                "Run times (text equivalent)",
                ["Lane", "Start", "End", "Verdict"],
                ([h(f"{r.get('label', '')} {r['kind']}"), h(r["started"]), h(r["finished"]), h(r.get("verdict") or r["readable"])] for r in model["runs"]),
            )
        )
        out.append("</div>")
    out.append(
        _html_table(
            "Every run",
            ["Lane", "Run", "Kind", "Start", "End", "Target", "Sent", "Verdict", "Reason"],
            (
                [
                    h(r.get("label")), _c(r["id"]), h(r["kind"]), h(r["started"]), h(r["finished"]), h(_target(r.get("target"))), h(_sent(r["sent"])),
                    h(r.get("verdict") or r["readable"]),
                    h("; ".join(x for x in (r.get("reasons") or []) if x) or ("; ".join(p for p in r["problems"] if p) if r["problems"] else None)),
                ]
                for r in model["runs"]
            ),
        )
    )
    out.append(
        _html_table(
            "Engagement totals (recorded numbers)",
            ["Metric", "Total", "Runs recorded", "Runs without a record"],
            ([h(_METRICS[k]), h(_total(v)), h(v["runsRecorded"]), h(v["runsUnrecorded"])] for k, v in model["totals"].items()),
            numeric=[1, 2, 3],
        )
    )
    media = media_svg(model)
    if media:
        out.append('<div class="figure">')
        out.append(media)
        out.append(
            _html_table(
                "RTP packets per call (text equivalent)",
                ["Lane", "Run", "To peer", "From peer", "Count source"],
                ([h(m["label"]), _c(m["run"]), h(m["to"]), h(m["from"]), h(m["source"])] for m in media_rows(model)),
                numeric=[2, 3],
            )
        )
        out.append("</div>")
    out.append("</section>")
    # Results
    out.append('<section aria-labelledby="results">')
    out.append('<h2 id="results">Results</h2>')
    calls = [r for r in model["runs"] if r["kind"] == "call" and r["readable"] != "unreadable"]
    out.append('<h3>Guided calls</h3>')
    out.append(
        _html_table(
            "Guided call results",
            ["Run", "Destination", "Preflight", "Registration", "Answer", "Setup s", "RTP to / from peer", "Codec", "TLS", "Oracle p/f/u", "Failing assertions"],
            (
                [
                    _c(r["id"]), h(r["details"].get("destination")), h(_preflight(r["details"].get("preflight"))),
                    h(_registration(r["details"].get("registration") or {})), h(_call_answer(r["details"].get("call") or {})),
                    h(_seconds((r["details"].get("call") or {}).get("setupSeconds"))), h(_media(r["details"].get("media") or {})),
                    h((r["details"].get("media") or {}).get("codec")), h(_tls(r["details"].get("tls"))),
                    h(_oracle(r["details"].get("oracle") or {})), h(", ".join((r["details"].get("oracle") or {}).get("failed") or [])),
                ]
                for r in calls
            ),
        )
    )
    out.append('<h3>Campaigns</h3>')
    campaigns = [r for r in model["runs"] if r["kind"] == "campaign"]
    if not campaigns:
        out.append("<p>No campaign runs.</p>")
    for run in campaigns:
        d = run["details"]
        out.append(
            f"<p>{_c(run['id'])} ({h(run.get('campaign'))}): {h(run.get('state') or run['readable'])}, "
            f"{h(d.get('completedSteps'))} of {h(d.get('plannedSteps'))} steps completed"
            + (f"; stop reason {_c(d['stopReason'])}" if d.get("stopReason") else "")
            + ".</p>"
        )
        out.append(
            _html_table(
                f"Cases in {run['id']}",
                ["Step", "Case", "Type", "Target", "Destination", "Outcome", "Status", "Expected", "RTP to / from", "Setup s", "TLS", "Reasons"],
                (
                    [
                        h(c["step"]), _c(c["case"]), h(c["type"]), h(_target(c.get("target"))), h(c.get("destination")), h(c["outcome"]),
                        h(c.get("statusCode")), h(c.get("expectedStatus")),
                        h(f"{_value(c.get('rtpToPeer'))} / {_value(c.get('rtpFromPeer'))}" if c["type"] == "call" else None),
                        h(_seconds(c.get("setupSeconds"))),
                        h(None if c.get("tlsVerified") is None else ("verified" if c["tlsVerified"] else "NOT verified")),
                        h(", ".join(c.get("reasons") or [])),
                    ]
                    for c in d.get("cases", [])
                ),
            )
        )
        if d.get("preflight"):
            out.append(
                _html_table(
                    f"Campaign preflight for {run['id']}",
                    ["Target", "Result", "Status", "Warning", "TLS"],
                    (
                        [
                            h(_target(p.get("target"))), h("ok" if p.get("ok") else "failed"),
                            h(f"{p['statusCode']} {p['reason']}" if p.get("statusCode") and p.get("reason") else p.get("statusCode")),
                            h(p.get("warning")), h(None if p.get("tlsVerified") is None else ("verified" if p["tlsVerified"] else "NOT verified")),
                        ]
                        for p in d["preflight"]
                    ),
                )
            )
    out.append('<h3>Security checks</h3>')
    checks = [r for r in model["runs"] if r["kind"] == "check" and r["readable"] != "unreadable"]
    if not checks:
        out.append("<p>No security-check runs.</p>")
    for run in checks:
        out.append(
            _html_table(
                f"Checks in {run['id']} against {_target(run.get('target'))}",
                ["Check", "Status", "Requests sent", "Summary"],
                ([_c(c["id"]), h(c["status"]), h(c["requestsSent"]), h(c["summary"])] for c in run["details"].get("checks", [])),
                numeric=[2],
            )
        )
    out.append("</section>")
    # Findings
    out.append('<section aria-labelledby="findings">')
    out.append('<h2 id="findings">Findings</h2>')
    if not model["findings"]:
        out.append("<p>No findings were reported and no observations were derived.</p>")
    for f in model["findings"]:
        out.append(f'<article class="finding" aria-labelledby="{h(f["ref"])}">')
        out.append(f'<h3 id="{h(f["ref"])}">{h(f["ref"])} {_sev(f["severity"])} {h(f["title"])}</h3>')
        if f["derived"]:
            out.append('<p class="derived">Derived by this report from run results; not a security-check finding.</p>')
        out.append("<dl>")
        out.append(f"<dt>Severity</dt><dd>{h(SEVERITY_LABEL[f['severity']])}" + (f"; confidence {h(f['confidence'])}" if f.get("confidence") else "") + "</dd>")
        out.append(f"<dt>Source</dt><dd>{'reviewed observation table' if f['derived'] else 'security check ' + _c(f['checkId'])}</dd>")
        out.append(f"<dt>Target</dt><dd>{h(f.get('targetLabel'))}</dd>")
        out.append(f"<dt>Seen</dt><dd>{h(f.get('firstSeen'))} to {h(f.get('lastSeen'))} ({h(f['occurrences'])} occurrence{'s' if f['occurrences'] != 1 else ''})</dd>")
        out.append("<dt>Evidenced by</dt><dd>" + ", ".join(_c(r) for r in f["runs"]) + "</dd>")
        out.append("</dl>")
        if f.get("summary"):
            out.append(f"<p>{h(f['summary'])}</p>")
        if f.get("evidence"):
            out.append("<ul>" + "".join(f"<li>{h(i.get('kind'))}: {h(i.get('detail'))}" + (f" ({_c(i['artifact'])})" if i.get("artifact") else "") + "</li>" for i in f["evidence"]) + "</ul>")
        if f.get("remediation"):
            out.append(f"<p><strong>Remediation:</strong> {h(f['remediation'])}</p>")
        if f.get("references"):
            out.append("<p><strong>References:</strong> " + "; ".join(h(r) for r in f["references"] if r) + "</p>")
        out.append("</article>")
    out.append("</section>")
    # Recommendations and limitations
    out.append('<section aria-labelledby="recommendations">')
    out.append('<h2 id="recommendations">Recommendations</h2>')
    if model["recommendations"]:
        out.append(
            _html_table(
                "Recommendations",
                ["Finding", "Severity", "Recommendation", "Origin"],
                ([h(r["finding"]), _sev(r["severity"]), h(r["text"]), h("reviewed observation table" if r["derived"] else "security check")] for r in model["recommendations"]),
            )
        )
    else:
        out.append("<p>No remediation is recommended from the recorded results.</p>")
    out.append("</section>")
    out.append('<section aria-labelledby="limitations">')
    out.append('<h2 id="limitations">Limitations</h2>')
    out.append("<ul>" + "".join(f"<li>{h(i['text'])}</li>" for i in model["limitations"]) + "</ul>")
    out.append("</section>")
    # Evidence
    out.append('<section class="evidence" aria-labelledby="evidence">')
    out.append('<h2 id="evidence">Evidence index</h2>')
    out.append(f"<p>Toolbox: {h(_toolbox(model['toolbox']))}.</p>")
    journal = model["journal"]
    if journal["present"]:
        out.append(
            f"<p>Journal: {'verified' if journal['valid'] else '<strong>FAILED verification</strong>'}, {h(journal['entryCount'])} entries, "
            f"head {_c(journal['headSha256'] or 'empty')}, {h(journal['missingEvidence'])} missing evidence references"
            + (f" ({h(journal['error'])})" if journal.get("error") else "") + ".</p>"
        )
        if journal["entries"]:
            headers = ["Seq", "Kind", "Recorded", "Title"] + (["Notes"] if journal.get("notesIncluded") else [])
            out.append(
                _html_table(
                    "Journal entries",
                    headers,
                    ([h(j["sequence"]), h(j["kind"]), h(j["recordedAt"]), h(j["title"])] + ([h(j.get("notes"))] if journal.get("notesIncluded") else []) for j in journal["entries"]),
                )
            )
    else:
        out.append("<p>No assessment journal was found.</p>")
    if model["packs"]:
        out.append(_html_table("Evidence packs", ["Pack", "Encrypted", "Size", "SHA-256", "Content identity"], ([_c(p["name"]), h(p["encrypted"]), h(p["size"]), _c(p["sha256"]), _c(p["contentIdentity"])] for p in model["packs"]), numeric=[2]))
    for run in model["runs"]:
        ev = run["evidence"]
        out.append("<details open>")
        out.append(
            f"<summary>{_c(run['id'])}: {h(ev['artifactCount'])} artifacts, {h(ev['totalBytes'])} bytes, privacy {h(ev['privacyStatus'] or 'not linted')}</summary>"
        )
        out.append(
            f"<p>Location {_c(run['ref'])}; hashes from {h(ev['source'])}"
            + (f"; privacy findings {h(', '.join(ev['privacyFindingCodes']))}" if ev["privacyFindingCodes"] else "")
            + (f"; changed since manifest: {h(', '.join(ev['changedSinceManifest']))}" if ev["changedSinceManifest"] else "")
            + ".</p>"
        )
        out.append(
            _html_table(
                f"Artifacts of {run['id']}",
                ["Artifact", "Size", "SHA-256", "Sensitivity"],
                ([_c(a["path"]), h(a["size"]), _c(a["sha256"]), h(a["sensitivity"])] for a in ev["artifacts"]),
                numeric=[1],
            )
        )
        out.append("</details>")
    out.append("</section>")
    # Integrity footer
    out.append('<footer aria-labelledby="integrity">')
    out.append('<h2 id="integrity">Integrity</h2>')
    out.append(f"<p>SHA-256 of <code>report.json</code>: {_c(report_sha256)}<br>Journal head: {_c(model['integrity']['journalHeadSha256'] or 'none')}</p>")
    out.append(
        _html_table(
            "Run content identities",
            ["Run", "Content identity", "Source"],
            ([_c(i["run"]), _c(i["contentIdentity"]), h(i["source"])] for i in model["integrity"]["runContentIdentities"]),
        )
    )
    out.append("</footer>")
    out += ["</main>", "</body>", "</html>"]
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# Plain text


def render_text(model: dict[str, Any], report_sha256: str) -> str:
    e = model["engagement"]
    out = [_value(e["title"]), "=" * min(78, max(8, len(_value(e["title"])))), ""]
    out.append(f"Generated {e['generatedAt']} for audience {model['audience']}; network activity: none.")
    out.append("")
    if model["integrityExceptions"]:
        out.append(f"INTEGRITY EXCEPTIONS: {len(model['integrityExceptions'])}")
        for x in model["integrityExceptions"]:
            out.append(f"  - [{x['code']}] {x['run'] or '-'}: {x['detail']}")
        out.append("")
    out += ["EXECUTIVE SUMMARY", "", model["executiveSummary"]["paragraph"], ""]
    for row in model["executiveSummary"]["rows"]:
        out.append(f"  {row['ref']:<5} {SEVERITY_LABEL.get(row['severity'], row['severity']):<7} {row['title']} ({row['source']})")
    out += ["", "APPROVAL", ""]
    for s in model["authorization"]["sources"]:
        out.append(f"  {s['ref']} [{s['kind']}] approval {_value(s['approvalId'])}, {_value(s['validFrom'])} to {_value(s['validUntil'])}, addresses {', '.join(s['networks']) or '-'}")
    out += ["", "ACTIVITY", ""]
    for r in model["runs"]:
        out.append(f"  {r['id']}  {r['kind']:<8} {_value(r['started'])}  {_target(r.get('target'))}  {r.get('verdict') or r['readable']}")
        out.append(f"      sent: {_sent(r['sent'])}")
    out += ["", "FINDINGS", ""]
    if not model["findings"]:
        out.append("  none")
    for f in model["findings"]:
        out.append(f"  {f['ref']} {SEVERITY_LABEL[f['severity']]:<7} {f['title']}{' (derived)' if f['derived'] else ''}")
        if f.get("remediation"):
            out.append(f"      remediation: {f['remediation']}")
    out += ["", "LIMITATIONS", ""]
    for item in model["limitations"]:
        out.append(f"  - {item['text']}")
    out += ["", "INTEGRITY", "", f"  report.json sha256 {report_sha256}", f"  journal head {model['integrity']['journalHeadSha256'] or 'none'}"]
    for i in model["integrity"]["runContentIdentities"]:
        out.append(f"  {i['run']} {i['contentIdentity'] or '-'}")
    return "\n".join(out) + "\n"
