"""Text, brief, and JSON renderings of a diagnosis. ASCII only."""

from __future__ import annotations

import json
import textwrap
from typing import Any

BRIEF_LINE_MAX = 150


def _wrap(prefix: str, text: str, width: int, indent: str = "") -> list:
    return textwrap.wrap(
        text, width=width, initial_indent=prefix, subsequent_indent=indent or " " * len(prefix),
        break_long_words=False, break_on_hyphens=False,
    ) or [prefix.rstrip()]


def _clip(text: str, limit: int = BRIEF_LINE_MAX) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def emphasise(text: str) -> str:
    """Mark a stop-and-ask sentence without repeating 'stop and ask the owner'."""
    text = " ".join(str(text).split())
    if text.startswith("Stop"):
        return "STOP" + text[4:]
    if text.startswith("Ask the owner"):
        return "STOP. " + text
    return "STOP: " + text


def first_sentence(text: str) -> str:
    text = " ".join(str(text).split())
    for stop in (". ", "; "):
        if stop in text:
            return text.split(stop)[0].rstrip(".") + "."
    return text


def top_evidence(data: dict) -> str:
    """The first evidence line: finalize() already put the stage's decisive line first."""
    evidence = data.get("evidence") or []
    if evidence:
        return f"{evidence[0]['label']}: {evidence[0]['text']}"
    return "no recorded evidence beyond the verdict"


def brief_lines(data: dict, run_ref: str) -> list:
    side = data["attribution"]
    first = None
    for step in data.get("nextSteps") or []:
        if step["kind"] == "stop-and-ask":
            first = emphasise(first_sentence(step["why"]))
            break
    if first is None:
        for step in data.get("nextSteps") or []:
            if step["kind"] == "command" and step.get("command"):
                first = step["command"]
                break
    if first is None:
        first = "nothing to do; the run passed" if data.get("verdict") == "pass" else "no further command suggested"
    verdict = data.get("verdict") or data.get("state") or "run"
    return [
        _clip(f"{data['kind']} {verdict}: {first_sentence(data['outcome'])}"),
        _clip(f"stopped at: {data['stage']} | side: {side['side']} ({side['confidence']} confidence)"),
        _clip("evidence: " + top_evidence(data)),
        _clip("next: " + first),
        _clip(f"full page: ./bin/sippycup diagnose {run_ref}"),
    ]


def render_brief_text(data: dict, run_ref: str) -> str:
    return "\n".join(brief_lines(data, run_ref)) + "\n"


def render_text(data: dict, width: int = 100) -> str:
    out: list = []
    out.append("Sippycup diagnosis (offline analysis; no network activity)")
    head = f"run: {data['kind']} {data.get('runRef') or data.get('run')}"
    out.append(head)
    meta = []
    if data.get("verdict"):
        meta.append(f"verdict: {data['verdict']}")
    if data.get("state"):
        meta.append(f"state: {data['state']}")
    if data.get("target"):
        meta.append(f"target: {data['target']}")
    if meta:
        out.append("  ".join(meta))
    redaction = data.get("redaction") or {}
    if redaction.get("addresses"):
        out.append("redaction: " + redaction["addresses"])
    out.append("")
    out.append("WHAT HAPPENED")
    out.extend(_wrap("  ", data["outcome"], width - 2))
    out.extend(_wrap("  stopped at: ", f"{data['stage']}" + (f" - {data['stageDetail']}" if data.get("stageDetail") else ""), width - 2, "      "))
    out.append("")
    side = data["attribution"]
    out.append("WHOSE SIDE, AND HOW SURE")
    out.append(f"  {side['side']} (confidence: {side['confidence']})")
    for line in side["reasoning"]:
        out.extend(_wrap("  - ", line, width - 2, "    "))
    if side["distinguish"]:
        out.append("  What would tell the alternatives apart:")
        for line in side["distinguish"]:
            out.extend(_wrap("  - ", line, width - 2, "    "))
    out.append("")
    if data["evidence"]:
        out.append("DECISIVE EVIDENCE")
        for item in data["evidence"]:
            out.extend(_wrap(f"  {item['label']}: ", item["text"], width - 2, "      "))
        out.append("")
    if data["timing"]:
        out.append("TIMING")
        for item in data["timing"]:
            note = f"  ({item['note']})" if item.get("note") else ""
            out.append(f"  {item['seconds']:>9.3f} s  {item['stage']}{note}")
        out.append("")
    if data.get("children"):
        out.append("PARTS (each diagnosed on its own)")
        for child in data["children"]:
            out.extend(_wrap("  - ", child["line"], width - 2, "    "))
        out.append("")
    ladder = data.get("ladder")
    if ladder and ladder.get("text"):
        out.append(f"LADDER EXCERPT (section {ladder.get('section')}: {ladder.get('title')}; full: {ladder.get('full')})")
        out.extend(ladder["text"].rstrip("\n").split("\n"))
        out.append("")
    elif ladder and ladder.get("reason"):
        out.extend(_wrap("LADDER: ", ladder["reason"], width))
        out.append("")
    out.append("NEXT STEPS")
    steps = data["nextSteps"]
    if not steps:
        out.append("  none suggested")
    number = 0
    for step in steps:
        if step["kind"] == "stop-and-ask":
            out.extend(_wrap("  >> ", emphasise(step["why"]), width - 2, "     "))
            continue
        number += 1
        out.extend(_wrap(f"  {number}. ", step["why"], width - 2, "     "))
        if step.get("command"):
            out.append("       $ " + step["command"])
    out.append("")
    if data["gaps"]:
        out.append("WHAT THIS EVIDENCE CANNOT SHOW")
        for gap in data["gaps"]:
            out.extend(_wrap("  - ", gap, width - 2, "    "))
        out.append("")
    out.append("Redaction: credentials, nonces, crypto keys, user parts and Call-IDs are never shown; unapproved addresses are labelled.")
    return "\n".join(out) + "\n"


def render_json(data: dict) -> str:
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def brief_json(data: dict, run_ref: str) -> dict:
    lines = brief_lines(data, run_ref)
    side = data["attribution"]
    return {
        "schema": "sippycup.dev/diagnosis-brief/v1",
        "kind": data["kind"],
        "run": data.get("run"),
        "verdict": data.get("verdict"),
        "stage": data["stage"],
        "side": side["side"],
        "confidence": side["confidence"],
        "stopAndAsk": bool(data.get("stopAndAsk")),
        "lines": lines,
        "networkActivity": False,
    }


def render_compare_text(data: dict, width: int = 100) -> str:
    out = ["Sippycup diagnosis compare (offline analysis; no network activity)"]
    out.append(f"A: {data['a']['run']}  verdict {data['a'].get('verdict')}")
    out.append(f"B: {data['b']['run']}  verdict {data['b'].get('verdict')}")
    out.append("")
    out.append(f"  {data['summary']}")
    out.append("")
    out.append("DIFFERENCES")
    if not data["differences"]:
        out.append("  none in the recorded settings, statuses, timings, or media peer")
    for item in data["differences"]:
        out.extend(_wrap(f"  {item['field']}: ", f"A = {item['a']}; B = {item['b']}", width - 2, "      "))
    out.append("")
    out.append("SAME IN BOTH")
    out.extend(_wrap("  ", ", ".join(data["same"]) or "nothing recorded in common", width - 2))
    out.append("")
    if data.get("likely"):
        out.append("WHAT THE DIFFERENCES SUGGEST")
        for line in data["likely"]:
            out.extend(_wrap("  - ", line, width - 2, "    "))
        out.append("")
    for gap in data.get("gaps", []):
        out.extend(_wrap("limit: ", gap, width))
    return "\n".join(out) + "\n"


def stable(value: Any) -> Any:
    return value
