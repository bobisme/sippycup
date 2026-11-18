"""Diagnose a campaign run directory: events.jsonl, the steps, and the run's capture."""

from __future__ import annotations

import json
from pathlib import Path

from .call import MediaFacts, media_reasoning
from .callrun import CallRun
from .core import (
    HIGH, LOW, MEDIUM, NONE, OUR, THEIR, UNKNOWN, Diagnosis, Redaction, command,
    is_loopback, work_relative,
)
from .files import read_dict, read_json, read_jsonl
from .inputs import make_redaction
from .ladder_bridge import Lazy

REJECTION_TEXT = {
    "call-busy": ("486 busy: the destination refused to ring", THEIR, HIGH, False),
    "call-declined": ("603 decline: the destination refused the call", THEIR, HIGH, True),
    "call-auth-failed": ("the INVITE was challenged and not accepted", UNKNOWN, LOW, True),
    "call-forbidden": ("403 Forbidden: policy refuses this identity or destination", THEIR, MEDIUM, True),
    "call-not-found": ("no such destination", UNKNOWN, LOW, True),
    "call-unavailable": ("the service or callee is unavailable", THEIR, MEDIUM, False),
    "call-rate-limited": ("429: a rate limit is throttling us", THEIR, HIGH, True),
    "call-media-not-acceptable": ("the far end rejected the offered media", UNKNOWN, LOW, False),
    "call-redirected": ("the far end redirected the call; redirects are not followed", THEIR, MEDIUM, True),
}


def _step_outputs(events: list) -> dict:
    """step number -> parsed step result (the JSON a runner printed), when it printed one."""
    out: dict = {}
    for event in events:
        if event.get("event") != "step.output" or event.get("stream") != "stdout":
            continue
        try:
            value = json.loads(str(event.get("text", "")).strip().split("\n")[0])
        except ValueError:
            continue
        if isinstance(value, dict):
            out[event.get("step")] = value
    return out


def _step_cases(events: list) -> dict:
    return {e["step"]: e.get("case") for e in events if e.get("event") == "step.started" and "step" in e}


def _targets(plan: dict) -> dict:
    steps = plan.get("steps") if isinstance(plan.get("steps"), list) else []
    return {s.get("index"): s for s in steps if isinstance(s, dict)}


def diagnose_campaign(path: Path, arguments) -> tuple:
    red = make_redaction([path], arguments.approve, arguments.show_addresses)
    d = Diagnosis("campaign", red)
    result = read_dict(path / "result.json")
    plan = read_dict(path / "plan.json")
    events = read_jsonl(path / "events.jsonl")
    outputs = _step_outputs(events)
    cases = _step_cases(events)
    steps = _targets(plan)
    state = result.get("state") or next((e.get("state") for e in reversed(events) if str(e.get("event", "")).startswith("campaign.")), None)
    completed = result.get("completedSteps")
    total = next((e.get("stepCount") for e in events if e.get("event") == "campaign.started"), None) or len(steps) or None
    name = ((plan.get("metadata") or {}).get("name")) or next((e.get("campaign") for e in events if e.get("campaign")), None)
    d.set(run=path.name, verdict=state, state=state, profile=red.text(name))
    terminal = next((e for e in reversed(events) if str(e.get("event", "")).startswith("campaign.") and e.get("event") != "campaign.stop_requested"), {})
    stop = next((e for e in events if e.get("event") == "campaign.stop_requested"), None)
    failing = next((e for e in events if e.get("event") in ("step.failed", "step.timed_out", "step.start_failed", "step.cancelled")), None)
    ladder = Lazy(path, arguments.show_addresses, arguments.approve, enabled=not arguments.no_ladder)
    practice = _all_loopback(plan)

    d.evidence("campaign", f"state {state}; {completed if completed is not None else '?'} of {total if total is not None else '?'} steps completed; exit code {result.get('exitCode')}")
    if not events:
        d.gap("events.jsonl is missing or empty; the step outcomes below come only from the other files")

    if state == "succeeded" and not failing:
        d.outcome(f"The campaign succeeded: all {completed} steps completed.")
        d.stage("none", "every step completed")
        d.attribute(NONE, HIGH, ["Every step met its expectations and no stop condition fired."])
        d.step("Draw the campaign's capture as a ladder.", command("ladder", work_relative(path.resolve())))
        return d, red

    if state == "authorization_lapsed" or terminal.get("reason") == "authorization_lapsed":
        # bn-3vxl: our own approval-window stop, never a platform failure.
        window = result.get("approvalWindow") if isinstance(result.get("approvalWindow"), dict) else {}
        halt = window.get("stop") if isinstance(window.get("stop"), dict) else {}
        detail = halt.get("detail") or terminal.get("detail") or "the approval no longer covered the next step"
        before = halt.get("step") or terminal.get("notStartedStep")
        where = f"before step {before}" if before else "before the first step"
        remaining = (total or 0) - (completed or 0)
        d.stage("safety stop", "the owner's approval no longer covered the next step")
        d.outcome(
            f"Sippycup stopped this campaign itself {where}: {detail}. "
            f"{completed if completed is not None else '?'} of {total if total is not None else '?'} step(s) completed"
            + (f"; {remaining} were not sent." if remaining > 0 else ".")
        )
        if window.get("validUntil"):
            d.evidence("approval window", f"valid until {window.get('validUntil')}"
                       + (f", from {window.get('validFrom')}" if window.get("validFrom") else "")
                       + (f"; stopped at {halt.get('at')}" if halt.get("at") else ""))
        d.attribute(OUR, HIGH, [
            "This is a safety stop on our side, not a platform failure: the campaign re-checks the "
            "approval window before every step and starts no step that could end after it.",
            "The steps that completed before the stop are valid results; nothing about the platform "
            "follows from the stop itself.",
        ])
        if remaining > 0:
            d.gap(f"{remaining} step(s) were never sent")
        d.stop_and_ask(
            "Stop: only the owner can renew the approval. Ask the owner for a new written window, "
            "record it in scope.yaml, run scope compile, then campaign plan again. Do not edit "
            "the window in the manifest or the plan yourself."
        )
        d.step("Draw what the capture recorded before the stop.", command("ladder", work_relative(path.resolve())))
        return d, red

    if terminal.get("event") == "campaign.cancelled":
        d.outcome(f"The campaign was interrupted ({terminal.get('signal')}) after {completed} completed step(s).")
        d.stage("none", "interrupted by the operator")
        d.attribute(OUR, HIGH, ["The run ended because the operator (or a wrapper) sent a signal; nothing about the platform can be concluded."])
        d.gap("steps after the interrupt were never sent")
        d.step("Draw what the capture recorded before the interrupt.", command("ladder", work_relative(path.resolve())))
        return d, red
    if terminal.get("event") == "campaign.timed_out":
        d.outcome(f"The campaign timed out after {completed} completed step(s).")
        d.stage("answer", "a step did not finish in its time budget")
        d.attribute(UNKNOWN, LOW, ["A step ran past its duration budget; the runner stopped it. Whether the far end or the path was slow is not recorded."])
        d.step("Draw the capture to see where the last step stalled.", command("ladder", work_relative(path.resolve())))
        return d, red

    if failing is None:
        # failed, but no failing step event: the campaign failed around preflight or setup
        _preflight_failure(d, path, plan, practice)
        d.step("Draw the capture, if any.", command("ladder", work_relative(path.resolve())))
        _attach(d, ladder, path, "options", arguments)
        return d, red

    number = failing.get("step")
    case = cases.get(number) or (steps.get(number) or {}).get("case")
    kind = (steps.get(number) or {}).get("type")
    output = outputs.get(number) or {}
    d.evidence("failing step", f"step {number} of {total}, case {case}, type {kind or 'unknown'}: {failing.get('event')}" + (f" (exit {failing.get('exitCode')})" if failing.get("exitCode") is not None else ""))
    if stop is not None:
        d.evidence("stop condition", f"stop requested: {stop.get('reason')}")
    if failing.get("event") == "step.start_failed":
        d.outcome(f"Step {number} could not start: {failing.get('error')}.")
        d.stage("internal", "the runner did not start")
        d.attribute(OUR, MEDIUM, ["The step runner did not start, so nothing reached the platform."])
        d.step("Check the toolbox image and runtime.", "./bin/sippycup doctor")
    elif "registrationStatus" in output or output.get("runner") == "campaign-softphone-runner":
        _softphone_step(d, path, red, output, number, case, total, completed, steps.get(number) or {}, ladder)
    elif "status_code" in output or kind == "options":
        _options_step(d, output, number, case, total, completed, practice, steps.get(number) or {})
    else:
        d.stage("INVITE" if kind == "call" else "preflight", "the step failed and recorded no structured result")
        d.outcome(f"Step {number} ({case}) failed (exit code {failing.get('exitCode')}); its runner recorded no structured result to read.")
        d.attribute(UNKNOWN, LOW, ["Without the runner's result or a softphone log, the campaign files do not say how the step failed."], ["The ladder of the run's capture shows what went on the wire."])
        d.gap("this step has no structured result (a SIPp step prints a different report); read the capture's ladder")
    d.step("Draw the campaign capture as a ladder.", command("ladder", work_relative(path.resolve())))
    d.step("Save the ladder as a self-contained HTML file for the owner report.", command("ladder", work_relative(path.resolve()), "--format", "html", "--output", f"{work_relative(path.resolve()).split('/', 1)[0]}/ladder-{''.join(c for c in path.name if c.isalnum())[-12:]}.html"))
    if (completed or 0) + 1 < (total or 0):
        d.gap(f"{(total or 0) - (completed or 0) - 1} later step(s) were not run because the campaign stops at the first failure")
    _attach(d, ladder, path, "registration" if d.data["stage"] == "registration" else ("options" if d.data["stage"] in ("preflight", "TLS") else "call"), arguments)
    return d, red


def _attach(d: Diagnosis, ladder: Lazy, path: Path, prefer: str, arguments) -> None:
    from .cli import attach_ladder

    attach_ladder(d, ladder, path, prefer, 100)


def _all_loopback(plan: dict) -> bool:
    destinations = plan.get("resolvedDestinations")
    addresses = []
    if isinstance(destinations, list):
        for item in destinations:
            if isinstance(item, dict):
                addresses += item.get("addresses") or [item.get("address")]
    if not addresses:
        for step in (plan.get("steps") or []):
            if isinstance(step, dict):
                addresses += (step.get("destination") or {}).get("addresses") or []
    addresses = [a for a in addresses if a]
    return bool(addresses) and all(is_loopback(a) for a in addresses)


def _preflight_failure(d: Diagnosis, path: Path, plan: dict, practice: bool) -> None:
    entries = read_json(path / "preflight.json")
    bad = [e for e in entries if isinstance(e, dict) and e.get("ok") is False] if isinstance(entries, list) else []
    d.stage("preflight", "the campaign's own OPTIONS preflight failed")
    if bad:
        first = bad[0]
        d.evidence("preflight", f"{first.get('transport')} {d.red.hostport(first.get('address'), first.get('port'))}: {first.get('detail')}")
        d.outcome(f"The campaign's OPTIONS preflight to {first.get('transport')} {d.red.hostport(first.get('address'), first.get('port'))} failed, so no step was sent.")
        d.step(
            "Repeat only the preflight for that target.",
            command("preflight", str(first.get("address")), str(first.get("port")), str(first.get("transport")), practice=practice),
        )
    else:
        d.outcome("The campaign failed before any step was recorded.")
    d.attribute(
        UNKNOWN, LOW,
        ["A failed preflight means the target did not answer OPTIONS in the way the campaign requires; the far end, a firewall, or the address and transport are all possible."],
        ["Preflight the same target over another approved transport if the manifest lists one.", "Ask the owner whether our source address is allowed."],
    )
    d.stop_and_ask("If a repeat fails the same way, ask the owner to confirm the signaling address, port, transport, and that our source is allowed.")


def _options_step(d: Diagnosis, output: dict, number, case, total, completed, practice: bool, step: dict) -> None:
    status = output.get("status_code")
    expectation = output.get("expectation")
    category = output.get("error_category")
    target = (step.get("destination") or {})
    address = (target.get("addresses") or [None])[0]
    where = f"{target.get('transport')} {d.red.hostport(address, target.get('port'))}" if address else "the target"
    d.stage("preflight", "an OPTIONS step failed its expectation")
    if status is not None:
        d.evidence("OPTIONS", f"{output.get('status_line')} (expected {expectation})")
        d.outcome(f"Step {number} ({case}): OPTIONS to {where} was answered {status}, not the expected {expectation}.")
        d.attribute(THEIR, MEDIUM, [f"The far end answered {status}: it is reachable and chose that response."], ["Ask the owner whether OPTIONS from our source address should return this status."])
    else:
        d.evidence("OPTIONS", f"outcome {output.get('outcome')}" + (f", error {category}" if category else "") + (f" after {output.get('elapsed_seconds')} s" if output.get("elapsed_seconds") is not None else ""))
        d.outcome(f"Step {number} ({case}): OPTIONS to {where} got no usable reply ({output.get('outcome') or 'no result recorded'}).")
        d.attribute(
            UNKNOWN, LOW,
            ["Nothing answered in the way the case expects; the far end, a firewall, or the address and transport are all possible."],
            ["Preflight the same address over another approved transport if the manifest lists one."],
        )
        if address:
            d.step(
                "Repeat only that OPTIONS exchange.",
                command("preflight", str(address), str(target.get("port")), str(target.get("transport")), practice=practice),
            )
        d.stop_and_ask("If a repeat fails the same way, ask the owner to confirm the address, port, transport, and that our source is allowed.")


def _softphone_step(d, path: Path, red: Redaction, output: dict, number, case, total, completed, step: dict, ladder: Lazy) -> None:
    from sippycup_workbench.call import rejection_verdict

    reasons = output.get("reasons") or []
    d.evidence("softphone step", f"outcome {output.get('outcome')}; reasons: {', '.join(str(r) for r in reasons) or 'none recorded'}")
    auth = output.get("authentication") or {}
    for method in ("REGISTER", "INVITE"):
        if auth.get(method):
            d.evidence(f"{method} authentication", f"{auth[method].get('attempts')} attempt(s), {auth[method].get('rejected')} rejected")
    reg_status = output.get("registrationStatus")
    status = output.get("finalStatus")
    error = output.get("error")
    step_dir = path / "steps" / f"{int(number):06d}" if isinstance(number, int) else path / "steps"
    run = CallRun(step_dir)
    for label, text in run.far_end_headers():
        d.evidence(label, text)
    d.timing("INVITE to answer", output.get("setupSeconds"))
    account = step.get("account")
    if error == "registration_failed":
        d.stage("registration", "REGISTER did not succeed, so the step quit before dialing")
        rejected = ((auth.get("REGISTER") or {}).get("rejected") or 0) >= 1
        d.outcome(f"Step {number} ({case}): registration was rejected"
                  + (f" ({reg_status})" if reg_status is not None else " (no final status was recorded)") + ", so no call was placed.")
        if reg_status in (401, 407) and rejected:
            d.attribute(
                OUR, MEDIUM,
                ["The registrar challenged, the step answered with the account's credentials, and it rejected them: the password, username, or realm was not accepted.",
                 "An account that exists but is disabled or locked on their side looks the same."],
                ["Ask the owner to confirm the account, realm, and that it may register from our source address; do not try other passwords."],
            )
            d.stop_and_ask("Stop and ask the owner to confirm the account before any retry; repeated wrong passwords can lock it.")
        elif reg_status == 403:
            d.attribute(THEIR, MEDIUM, ["403 is a policy decision (an ACL or a barred account)."])
            d.stop_and_ask("Stop and ask the owner: a 403 will not change on retry.")
        else:
            d.attribute(UNKNOWN, LOW, [f"Registration status {reg_status if reg_status is not None else 'not recorded'}: no clear credential or policy signal."])
            d.stop_and_ask("Ask the owner to confirm the account before retrying.")
        if account is None:
            d.gap("the plan records no account for this step, so a missing credential cannot be ruled out")
        d.step("Read the reference text.", "./bin/sippycup explain call.registration-failed")
    elif status is not None and status >= 300 and not output.get("answered"):
        verdict, _note = rejection_verdict(int(status))
        text, side, confidence, ask = REJECTION_TEXT.get(verdict, (f"final status {status}", THEIR if int(status) >= 500 else UNKNOWN, LOW, False))
        d.stage("INVITE", f"the INVITE was answered {status} and no call was established")
        d.outcome(f"Step {number} ({case}): the call was rejected with {status}: {text}.")
        d.attribute(side, confidence, [f"Final status {status} after {(auth.get('INVITE') or {}).get('attempts', 0)} INVITE authentication attempt(s)."], ["Diagnose the same call with ./bin/sippycup call for the full SDP and headers if the profile allows it."])
        if ask:
            d.stop_and_ask("Stop and ask the owner before retrying: " + text + ".")
        d.step("Read the reference text for this status.", command("explain", f"call.{verdict}"))
    elif "not_answered" in reasons and not output.get("answered"):
        d.stage("answer", "no final answer arrived in the step's time budget")
        d.outcome(f"Step {number} ({case}): the call was not answered within the step's time budget.")
        d.attribute(UNKNOWN, LOW, ["Neither a final response nor a clear rejection was recorded; ringing that never ends and a lost response look the same here."], ["Draw the ladder to see whether a 180 arrived."])
        d.step("Read the reference text.", "./bin/sippycup explain call.call-not-answered")
    elif "bidirectional_rtp_not_observed" in reasons and output.get("answered"):
        rtp = output.get("rtp") or {}
        d.stage("media", "the call was answered but RTP did not flow both ways")
        d.outcome(f"Step {number} ({case}): answered, but RTP was {rtp.get('txPackets')} packets out and {rtp.get('rxPackets')} in.")
        d.evidence("RTP", f"PJSUA counters: {rtp.get('txPackets')} out, {rtp.get('rxPackets')} in")
        run.result = {"captureFilter": read_dict(path / "plan.json").get("captureFilter"), "target": {"host": (step.get("destination") or {}).get("addresses", [None])[0]}, "softphone": {"rtp_tx_packets": rtp.get("txPackets"), "rtp_rx_packets": rtp.get("rxPackets")}}
        run.has_capture = (path / "capture.pcap").is_file()
        facts = _root_media_facts(run, path, ladder)
        side, confidence, reasoning, distinguish = media_reasoning(d, run, facts, one_way=True)
        d.attribute(side, confidence, reasoning, distinguish)
        d.step("Read the reference text.", "./bin/sippycup explain call.one-way-media")
    else:
        d.stage("oracle", "the step failed its expectations")
        d.outcome(f"Step {number} ({case}) failed: {', '.join(str(r) for r in reasons) or output.get('outcome') or 'no reason recorded'}.")
        d.attribute(UNKNOWN, LOW, ["The step's reasons do not single out one side."])
    if not run.has_log:
        d.gap("this step has no softphone.log, so no SIP headers can be quoted")


def _root_media_facts(run: CallRun, path: Path, ladder: Lazy) -> MediaFacts:
    return MediaFacts(run, ladder)
