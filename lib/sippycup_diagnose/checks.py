"""Diagnose a security-checks run directory."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from .core import (
    HIGH, LOW, MEDIUM, NONE, OUR, THEIR, UNKNOWN, Diagnosis, command, work_relative,
)
from .files import read_dict, read_jsonl
from .inputs import make_redaction, sibling_profiles
from .ladder_bridge import Lazy

SEVERITY = ("critical", "high", "medium", "low", "info")


def _rank(finding: dict) -> int:
    try:
        return SEVERITY.index(str(finding.get("severity")))
    except ValueError:
        return len(SEVERITY)


def diagnose_checks(path: Path, arguments) -> tuple:
    red = make_redaction([path], arguments.approve, arguments.show_addresses)
    d = Diagnosis("checks", red)
    result = read_dict(path / "result.json")
    findings_doc = result.get("findings") if isinstance(result.get("findings"), dict) else read_dict(path / "findings.json")
    detail = read_dict(path / "checks-detail.json")
    plan = read_dict(path / "plan.json")
    profile = read_dict(path / "profile.json")
    transcript = read_jsonl(path / "transcript.jsonl")
    checks = [c for c in findings_doc.get("checks", []) if isinstance(c, dict)]
    findings = sorted((f for f in findings_doc.get("findings", []) if isinstance(f, dict)), key=_rank)
    statuses = Counter(str(c.get("status")) for c in checks)
    stops = [(c.get("id"), c.get("stop")) for c in detail.get("checks", []) if isinstance(c, dict) and c.get("stop")]
    state = result.get("state")
    exit_code = result.get("exitCode")
    problem = result.get("problem")
    target = profile.get("target") if isinstance(profile.get("target"), dict) else {}
    host, port, transport = target.get("host"), target.get("port"), target.get("transport") or "udp"
    practice = isinstance(profile.get("authorization"), dict) and profile["authorization"].get("approval_id") == "LOCAL-PRACTICE-ONLY"
    d.set(
        run=path.name, verdict=f"exit {exit_code}", state=state, profile=red.text(result.get("profile")),
        target=f"{transport}://{red.hostport(host, port)}" if host else None,
    )
    errors = [c for c in checks if c.get("status") == "error"]
    by_status = ", ".join(f"{n} {s}" for s, n in sorted(statuses.items()))
    d.evidence("checks", f"{len(checks)} checks: {by_status}; {result.get('requestsSent')} request(s) sent")
    if findings:
        counts = Counter(str(f.get("severity")) for f in findings)
        d.evidence("findings", ", ".join(f"{counts[s]} {s}" for s in SEVERITY if counts[s]) + f" (fail-on {result.get('failOn')})")
        for finding in findings[:4]:
            d.evidence("finding", f"[{finding.get('severity')}] {finding.get('id')}: {finding.get('title')}", 300)
    for check in errors[:4]:
        d.evidence("check error", f"{check.get('id')}: {check.get('summary')}", 300)
    for ident, stop in stops[:3]:
        d.evidence("stop", f"{ident}: {stop}", 300)
    if problem:
        d.evidence("problem", str(problem), 300)
    d.timing("whole run", _span(result.get("timestamps") or {}))
    slow = sorted(
        (item for item in transcript if isinstance(item.get("elapsedMs"), (int, float))),
        key=lambda item: -item["elapsedMs"],
    )[:1]
    if slow and slow[0]["elapsedMs"] >= 50:
        d.timing("slowest reply", slow[0]["elapsedMs"] / 1000.0, f"{slow[0].get('check')} {slow[0].get('request')}")
    not_approved = statuses.get("not-approved", 0)
    skipped = statuses.get("skipped", 0)

    ladder = Lazy(path, arguments.show_addresses, arguments.approve, enabled=not arguments.no_ladder)
    run_ref = work_relative(path.resolve())
    profile_word = _profile_word(path, result, host, port, transport)

    if state == "cancelled":
        d.outcome(f"The checks run was interrupted after {result.get('requestsSent')} request(s); the checks that had not run were not sent.")
        d.stage("none", "interrupted by the operator")
        d.attribute(OUR, HIGH, ["The run ended because the operator (or a wrapper) sent SIGINT or SIGTERM."])
    elif problem or state == "failed":
        text = str(problem or "")
        lapsed = "authorization" in text.lower() or "window" in text.lower() or "expired" in text.lower()
        capture = "capture" in text.lower()
        d.outcome(f"The checks run stopped with a run problem: {text or 'see the run directory'}.")
        d.stage("safety stop" if lapsed else "capture" if capture else "internal", text or "run problem")
        d.attribute(OUR, MEDIUM, ["The run stopped on a toolbox-side condition (an authorization window, a bound, or capture), not on something the target did."])
        if lapsed:
            d.stop_and_ask("Stop: only the owner can renew the authorization window; do not edit valid_until yourself.")
            d.step("Check the profile after the owner renews it (no traffic).", command("rehearse", profile_word))
    elif errors:
        refused = any("refused" in str(c.get("summary")) for c in errors)
        silent = any(("no usable answer" in str(c.get("summary")) or "timeout" in str(c.get("summary")).lower()) and "refused" not in str(c.get("summary")) for c in errors)
        d.outcome(f"{len(errors)} of {len(checks)} checks could not conclude: the target did not give a usable answer, so no finding about it is possible.")
        d.stage("preflight", "the first requests got no usable answer")
        if refused:
            d.attribute(THEIR, MEDIUM, ["The connection was refused: the host is reachable and nothing accepts it on that port and transport, or the profile's port or transport is wrong."], ["Confirm the signaling port and transport with the owner."])
        elif silent:
            d.attribute(UNKNOWN, LOW, ["Nothing answered; the service being down, a firewall, and a wrong address or transport are all possible."], ["Preflight the same target to see whether it answers OPTIONS at all."])
        else:
            d.attribute(UNKNOWN, LOW, ["The check summaries do not name one cause."])
        if host:
            d.step("Repeat only the OPTIONS preflight to the profile's target.", command("preflight", str(host), str(port), str(transport), practice=practice))
        d.stop_and_ask("If a repeat fails the same way, ask the owner to confirm the signaling address, port, and transport before running the checks again.")
    elif findings and exit_code == 1:
        top = findings[0]
        d.outcome(f"The checks completed and reported {len(findings)} finding(s); the most severe is {top.get('severity')}: {top.get('title')}.")
        d.stage("none", "every approved check ran to the end")
        d.attribute(
            THEIR, HIGH,
            ["Findings describe the target's own configuration and behavior; each is a candidate to confirm, not a conclusion."],
            ["Confirm a finding as the assessment workflow describes before reporting it (a second observation, preferably by another method)."],
        )
    elif findings:
        d.outcome(f"The checks completed with {len(findings)} finding(s), none at or above the fail-on level ({result.get('failOn')}).")
        d.stage("none", "every approved check ran to the end")
        d.attribute(THEIR, HIGH, ["Findings describe the target's own configuration and behavior; each is a candidate to confirm."])
    else:
        d.outcome("The checks completed with no findings.")
        d.stage("none", "every approved check ran to the end")
        d.attribute(NONE, HIGH, ["Every approved check ran and none produced a finding."])
    for finding in findings[:3]:
        check_id = finding.get("checkId")
        if check_id:
            d.step(f"Read what check {check_id} does, what it sends, and how to confirm its finding.", command("checks", "explain", str(check_id)))
    d.step("Draw the run's capture as a ladder.", command("ladder", run_ref))
    if not_approved:
        d.gap(f"{not_approved} check(s) were not run because they are not listed in security_checks.approved; only the owner's scope can add them")
    if skipped:
        d.gap(f"{skipped} check(s) were skipped (planned but not runnable, or not selected)")
    if findings:
        d.gap("a finding is a candidate; confirm it before it goes into the owner report")
    from .cli import attach_ladder

    attach_ladder(d, ladder, path, "options", 100)
    return d, red


def _profile_word(path: Path, result: dict, host, port, transport) -> str:
    name = result.get("profile")
    matches = [
        item for item in sibling_profiles(path)
        if item["name"] == name and item["host"] == host and item["port"] == port and item["transport"] == transport
    ]
    return work_relative(matches[0]["path"]) if len(matches) == 1 else "PROFILE.yaml"


def _span(stamps: dict):
    from datetime import datetime

    try:
        a = datetime.fromisoformat(str(stamps.get("started")).replace("Z", "+00:00"))
        b = datetime.fromisoformat(str(stamps.get("finished")).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (b - a).total_seconds()
