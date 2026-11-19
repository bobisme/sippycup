"""Platform, production-safety, and web-surface readiness for the cockpit and ``ready``.

Everything here reads the checked scope file and local files only. Values
from the scope file are never shown: only question numbers, question texts,
surface names, and states.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

SIP_BLOCKERS = {
    "scope.pstn_destination_unconfirmed":
        "a destination reaches the public phone network without the carrier's permission and a toll answer",
    "scope.carrier_answer_conflict":
        "the carrier is recorded as out of the path, but a destination reaches the public phone network",
    "scope.destination_never_dial": "a destination is on the owner's never-dial list",
    "scope.limit_exceeds_production": "limits.concurrent_calls is above the owner's production maximum",
}


def platform_facts(report: Any, root: Path) -> dict[str, Any] | None:
    """Facts for the cockpit model, or None when the scope has no document."""
    from sippycup_workbench.scope_app import readiness
    from sippycup_workbench.scope_app_derive import FILENAME, state_for

    facts = readiness(report)
    if facts is None:
        return None
    facts["record"] = {"file": FILENAME, "state": state_for(root, report.sha256, facts["recorded"])}
    facts["sipBlockers"] = sorted({item.code for item in report.errors if item.code in SIP_BLOCKERS})
    return facts


def open_count(scope: dict[str, Any]) -> int | None:
    """Open platform and application questions, or None when none are recorded."""
    facts = scope.get("platform")
    if not facts or not facts.get("recorded"):
        return None
    return len(facts["open"])


def platform_lines(scope: dict[str, Any], *, limit: int) -> list[str]:
    """Dashboard lines; empty when the scope records no platform section."""
    facts = scope.get("platform")
    if not facts or not facts.get("recorded"):
        return []
    opened = facts["open"]
    safety = facts["productionSafety"]
    environment = facts["environment"]
    label = environment if environment in {"production", "staging", "dedicated-test"} else (
        f"environment {environment} (treated as production)")
    parts = [label, f"{len(opened)} of {facts['questions']} platform questions open"]
    if safety["applies"]:
        parts.append("production safety: " + (f"{len(safety['open'])} open ({', '.join(safety['open'])})"
                                              if safety["open"] else "all answered"))
    marker = "[!!]" if facts.get("sipBlockers") else "[??]" if opened else "[ok]"
    lines = [f"Platform       {marker} " + "; ".join(parts)]
    for code in facts.get("sipBlockers") or []:
        lines.append(f"       - holds the SIP profile: {SIP_BLOCKERS[code]} ({code})")
    for question in opened[:limit]:
        lines.append(f"       - {question['id']} {question['section']} ({question['state']}): {question['text']}")
    if len(opened) > limit:
        lines.append(f"       ... and {len(opened) - limit} more (scope questions)")
    surfaces = facts["surfaces"]
    if surfaces:
        text = "; ".join(f"{item['name']} {item['state']}" for item in surfaces)
        ready = all(item["state"] in {"ready", "out-of-scope"} for item in surfaces)
        lines.append(f"Web surfaces   {'[ok]' if ready else '[??]'} {text}")
    else:
        lines.append("Web surfaces   [  ] none recorded")
    record = facts["record"]
    lines.append(f"               record {record['file']}: {record['state']}; nothing is sent to web surfaces "
                 "(no live application runner exists)")
    return lines


def check_platform(model: dict[str, Any]) -> Any:
    """The ``ready`` line for production-safety answers, or None when not recorded.

    WARN, not NO-GO, for open answers: they are the owner's to give and the
    SIP/RTP profile stands on its own approval. NO-GO only for the scope
    errors in SIP_BLOCKERS, where a call itself could leave the platform,
    reach a forbidden number, or exceed the production maximum.
    """
    from .ready import GO, LAUNCHER, NOGO, WARN, Check

    scope = model["scope"]
    facts = scope.get("platform")
    if not facts or not facts.get("recorded"):
        return None
    eng = model["engagement"]["display"]
    title = "Production safety answers"
    fix = (f"{LAUNCHER} scope questions {eng}   (ask the owner, record the answers with {LAUNCHER} scope answer "
           f"{eng} or in {eng}/scope.yaml by hand, then {LAUNCHER} scope compile {eng})")
    blockers = facts.get("sipBlockers") or []
    if blockers:
        return Check("platform", title, NOGO, [SIP_BLOCKERS[code] for code in blockers],
                     f"{LAUNCHER} scope check {eng}   (record the owner's answer or remove the destination, then compile)")
    safety = facts["productionSafety"]
    pstn = facts.get("pstnDestinations") or []
    if not safety["applies"]:
        lines = [f"the scope says {facts['environment']}, not production; "
                 f"{len(facts['open'])} platform question(s) open"]
        if pstn:
            lines.append(f"{len(pstn)} destination(s) reach the public phone network: calls to them can cost "
                         "money and ring real phones")
        return Check("platform", title, WARN if pstn else GO, lines, fix if pstn else None)
    questions = safety.get("questions") or []
    if questions:
        lines = [f"{safety['reason']}: {len(questions)} production-safety answer(s) open"]
        lines += [f"  {item['id']} ({item['state']}): {item['text']}" for item in questions]
        lines.append("the SIP/RTP approval is not affected; get these answers before testing a live system")
        return Check("platform", title, WARN, lines, fix)
    lines = [f"{safety['reason']}: every production-safety answer is recorded"]
    if pstn:
        lines.append(f"{len(pstn)} destination(s) reach the public phone network (carrier permitted, toll "
                     "answered): calls to them can cost money and ring real phones")
        return Check("platform", title, WARN, lines, None)
    return Check("platform", title, GO, lines)
