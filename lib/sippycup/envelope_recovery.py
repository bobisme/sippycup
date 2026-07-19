"""Bounded backoff, recovery proof, and tested-envelope reporting."""
from __future__ import annotations
from typing import Any, Sequence
from .envelope import EnvelopeError, validate_envelope_plan

VERSION = "sippycup.dev/envelope-report/v1"

def prove_recovery(plan: Any, analysis: dict[str, Any], *, expectations: dict[str, Any],
                   baseline: dict[str, Any], canaries: Sequence[dict[str, Any]],
                   trigger_at_seconds: int, teardown_seconds: int,
                   canary_interval_seconds: int, level_artifacts: dict[int, dict[str, str]],
                   stop_reason: str | None = None) -> dict[str, Any]:
    frozen = validate_envelope_plan(plan)
    maxima = frozen["authorization"]["hardMaxima"]
    if not expectations or baseline.get("expectations") != expectations:
        raise EnvelopeError("baseline canary must use the reviewed expectations")
    if teardown_seconds < 0 or canary_interval_seconds <= 0:
        raise EnvelopeError("teardown/interval bounds are invalid")
    tested = [d["level"] for d in analysis.get("decisions", [])]
    if any(level not in level_artifacts or set(level_artifacts[level]) != {"capture", "assertions"}
           for level in tested):
        raise EnvelopeError("every tested ramp level requires capture and assertions")
    global_deadline = maxima["durationSeconds"]
    teardown_end = min(trigger_at_seconds + teardown_seconds, global_deadline)
    cooldown_end = min(teardown_end + maxima["cooldownSeconds"], global_deadline)
    recovery_deadline = min(cooldown_end + maxima["recoveryDeadlineSeconds"], global_deadline)
    events = [{"event": "admission.stopped", "atSeconds": trigger_at_seconds,
               "reason": stop_reason or analysis.get("outcome")},
              {"event": "teardown.completed", "atSeconds": teardown_end},
              {"event": "cooldown.completed", "atSeconds": cooldown_end}]
    recovered_at = None
    attempts = []
    now = cooldown_end
    for item in canaries:
        if now > recovery_deadline:
            break
        if item.get("expectations") != expectations:
            raise EnvelopeError("recovery canary expectations differ from baseline")
        passed = item.get("passed")
        if not isinstance(passed, bool):
            raise EnvelopeError("recovery canary result must be boolean")
        attempts.append({"atSeconds": now, "passed": passed})
        if passed:
            recovered_at = now
            break
        now += canary_interval_seconds
    load_failed = analysis.get("outcome") in {"degraded", "hard_stop"}
    if recovered_at is not None:
        outcome = "recovered_after_load_failure" if load_failed else "recovered_after_stop"
    else:
        outcome = "failed_to_recover" if load_failed else "recovery_unproven"
    return {"apiVersion": VERSION, "outcome": outcome, "stopReason": stop_reason,
            "testedLevels": tested, "testedKneeInterval": analysis.get("testedKneeInterval"),
            "authorizationCensored": analysis.get("outcome") == "censored",
            "capacityClaim": None, "trigger": analysis.get("trigger"),
            "policy": analysis.get("policy"), "hysteresis": analysis.get("decisions"),
            "baselineCanary": baseline, "recoveryAttempts": attempts,
            "recoveredAtSeconds": recovered_at,
            "recoveryTimeSeconds": None if recovered_at is None else recovered_at - trigger_at_seconds,
            "deadlines": {"global": global_deadline, "teardownEnd": teardown_end,
                          "cooldownEnd": cooldown_end, "recoveryEnd": recovery_deadline},
            "levelArtifacts": {str(k): v for k, v in sorted(level_artifacts.items())},
            "events": events}
