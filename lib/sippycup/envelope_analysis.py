"""Typed observation fusion and conservative envelope degradation decisions."""

from __future__ import annotations

import json
import math
import subprocess
from statistics import median
from typing import Any, Callable, Sequence

from .envelope import EnvelopeError, validate_envelope_plan

ANALYSIS_VERSION = "sippycup.dev/envelope-analysis/v1"
MAX_ADAPTER_OUTPUT = 64 * 1024


def known(value: float, source: str) -> dict[str, Any]:
    return {"state": "known", "value": value, "source": source}


def unknown(state: str, source: str, detail: str) -> dict[str, Any]:
    if state not in {"missing", "stale"}:
        raise EnvelopeError("unknown observation state must be missing or stale")
    return {"state": state, "source": source, "detail": detail}


def run_health_adapter(
    command: Sequence[str],
    *,
    deadline_ms: int,
    sampled_at_ms: int,
    runner: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    """Run a bounded read-only JSON adapter and return a typed observation."""
    if not command or deadline_ms <= 0 or deadline_ms > 60_000:
        raise EnvelopeError("health adapter requires a command and 1..60000 ms deadline")
    try:
        result = runner(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=deadline_ms / 1000,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return unknown("missing", "health", "adapter deadline exceeded")
    if result.returncode != 0:
        return unknown("missing", "health", f"adapter exited {result.returncode}")
    output = result.stdout
    if isinstance(output, bytes):
        output = output.decode("utf-8", "replace")
    if len(output.encode("utf-8")) > MAX_ADAPTER_OUTPUT:
        return unknown("missing", "health", "adapter output exceeded limit")
    try:
        document = json.loads(output)
        value = float(document["value"])
        observed_at = int(document["observedAtMs"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return unknown("missing", "health", "adapter JSON is malformed")
    if not math.isfinite(value) or observed_at < 0:
        return unknown("missing", "health", "adapter value/time is invalid")
    return {
        "state": "known",
        "value": value,
        "source": "health",
        "observedAtMs": observed_at,
        "sampledAtMs": sampled_at_ms,
    }


def fuse_observation(
    *,
    level: int,
    at_ms: int,
    sipp: dict[str, Any] | None,
    oracle: dict[str, Any] | None,
    rtp: dict[str, Any] | None,
    socket_errors: int | None,
    health: dict[str, Any] | None,
    stale_after_ms: int,
) -> dict[str, Any]:
    """Normalize SIPp, oracle, RTP, socket, and health facts without optimism."""
    if level <= 0 or at_ms < 0 or stale_after_ms <= 0:
        raise EnvelopeError("observation level/time/staleness bounds are invalid")
    metrics: dict[str, dict[str, Any]] = {}

    def number(source: dict[str, Any] | None, key: str, name: str) -> None:
        value = None if source is None else source.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            metrics[name] = unknown("missing", name.split(".")[0], f"{key} unavailable")
        elif not math.isfinite(float(value)):
            metrics[name] = unknown("missing", name.split(".")[0], f"{key} non-finite")
        else:
            metrics[name] = known(float(value), name.split(".")[0])

    number(sipp, "successRatePercent", "call.successRatePercent")
    number(sipp, "setupP95Ms", "call.setupP95Ms")
    number(sipp, "timeoutRatePercent", "call.timeoutRatePercent")
    number(sipp, "server5xxRatePercent", "call.server5xxRatePercent")
    number(rtp, "lossPercent", "media.lossPercent")
    number(rtp, "jitterMs", "media.jitterMs")
    if (
        isinstance(socket_errors, bool)
        or not isinstance(socket_errors, int)
        or socket_errors < 0
    ):
        metrics["socket.errors"] = unknown("missing", "socket", "error count unavailable")
    else:
        metrics["socket.errors"] = known(float(socket_errors), "socket")
    assertions = None if oracle is None else oracle.get("assertions")
    if (
        not isinstance(assertions, list)
        or any(
            not isinstance(item, dict)
            or item.get("verdict") not in {"pass", "fail", "unknown"}
            for item in assertions
        )
    ):
        metrics["oracle.failedAssertions"] = unknown(
            "missing", "oracle", "assertions unavailable"
        )
    else:
        failed = sum(
            item.get("verdict") == "fail"
            for item in assertions
        )
        metrics["oracle.failedAssertions"] = known(float(failed), "oracle")
    if health is None:
        metrics["health.value"] = unknown("missing", "health", "adapter not configured")
    elif health.get("state") != "known":
        metrics["health.value"] = dict(health)
    else:
        observed_at = health.get("observedAtMs", at_ms)
        if (
            isinstance(observed_at, bool)
            or not isinstance(observed_at, int)
            or observed_at > at_ms
            or at_ms - observed_at > stale_after_ms
        ):
            metrics["health.value"] = unknown("stale", "health", "adapter sample is stale")
        else:
            value = health.get("value")
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
            ):
                metrics["health.value"] = unknown(
                    "missing", "health", "adapter value is invalid"
                )
            else:
                metrics["health.value"] = known(float(value), "health")
    return {"level": level, "atMs": at_ms, "metrics": metrics}


def _normalize_policy(policy: Any) -> dict[str, Any]:
    if not isinstance(policy, dict) or set(policy) != {
        "staleAfterMs", "baselineSamples", "metrics"
    }:
        raise EnvelopeError("policy must contain staleAfterMs, baselineSamples, and metrics")
    stale = policy["staleAfterMs"]
    baseline = policy["baselineSamples"]
    if any(isinstance(v, bool) or not isinstance(v, int) or v <= 0 for v in (stale, baseline)):
        raise EnvelopeError("policy time/sample bounds must be positive integers")
    if not isinstance(policy["metrics"], dict) or not policy["metrics"]:
        raise EnvelopeError("policy.metrics must be a non-empty object")
    normalized = {}
    for name, raw in policy["metrics"].items():
        if not isinstance(raw, dict) or set(raw) != {
            "direction", "soft", "hard", "consecutive", "changeDelta", "required"
        }:
            raise EnvelopeError(f"policy metric {name} has invalid fields")
        if raw["direction"] not in {"max", "min"} or not isinstance(raw["required"], bool):
            raise EnvelopeError(f"policy metric {name} direction/required is invalid")
        consecutive = raw["consecutive"]
        if isinstance(consecutive, bool) or not isinstance(consecutive, int) or consecutive < 2:
            raise EnvelopeError(f"policy metric {name} consecutive must be >= 2")
        values = [raw[key] for key in ("soft", "hard", "changeDelta")]
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in values):
            raise EnvelopeError(f"policy metric {name} thresholds must be finite")
        if raw["changeDelta"] < 0:
            raise EnvelopeError(f"policy metric {name} changeDelta must be non-negative")
        if (
            raw["direction"] == "max" and raw["hard"] < raw["soft"]
        ) or (
            raw["direction"] == "min" and raw["hard"] > raw["soft"]
        ):
            raise EnvelopeError(f"policy metric {name} hard threshold is weaker than soft")
        normalized[name] = dict(raw)
    return {"staleAfterMs": stale, "baselineSamples": baseline, "metrics": normalized}


def analyze_degradation(
    plan: Any,
    observations: Sequence[dict[str, Any]],
    policy: Any,
) -> dict[str, Any]:
    """Return the first evidence-backed tested knee interval, or a censored run."""
    frozen = validate_envelope_plan(plan)
    configured = _normalize_policy(policy)
    tested_levels = [step["level"] for step in frozen["steps"]]
    if not observations:
        raise EnvelopeError("at least one observation is required")
    streaks = {name: 0 for name in configured["metrics"]}
    history = {name: [] for name in configured["metrics"]}
    healthy_levels: list[int] = []
    decisions = []
    trigger = None
    previous_at = -1
    previous_level_index = -1
    for index, sample in enumerate(observations):
        if sample.get("level") not in tested_levels or not isinstance(sample.get("metrics"), dict):
            raise EnvelopeError("observation level/metrics are not in the frozen plan")
        at_ms = sample.get("atMs")
        level_index = tested_levels.index(sample["level"])
        if (
            isinstance(at_ms, bool)
            or not isinstance(at_ms, int)
            or at_ms < previous_at
            or level_index < previous_level_index
        ):
            raise EnvelopeError("observations must follow monotonic plan level/time order")
        previous_at = at_ms
        previous_level_index = level_index
        citations = []
        unknown_required = []
        hard = []
        repeated = []
        for name, rule in configured["metrics"].items():
            fact = sample["metrics"].get(name)
            if not isinstance(fact, dict) or fact.get("state") != "known":
                if rule["required"]:
                    unknown_required.append(name)
                citations.append({"metric": name, "fact": fact or unknown("missing", name, "not supplied")})
                streaks[name] = 0
                continue
            value = fact.get("value")
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise EnvelopeError(f"known metric {name} must be finite")
            adverse = value > rule["soft"] if rule["direction"] == "max" else value < rule["soft"]
            hard_adverse = value > rule["hard"] if rule["direction"] == "max" else value < rule["hard"]
            baseline_values = history[name][: configured["baselineSamples"]]
            changed = False
            baseline_value = None
            if len(baseline_values) == configured["baselineSamples"]:
                baseline_value = median(baseline_values)
                delta = value - baseline_value if rule["direction"] == "max" else baseline_value - value
                changed = delta >= rule["changeDelta"] > 0
            streaks[name] = streaks[name] + 1 if (adverse or changed) else 0
            history[name].append(float(value))
            citation = {"metric": name, "fact": fact, "rule": rule, "baseline": baseline_value, "streak": streaks[name]}
            citations.append(citation)
            if hard_adverse:
                hard.append(name)
            elif streaks[name] >= rule["consecutive"]:
                repeated.append(name)
        if hard:
            classification, action, reasons = "hard_stop", "stop", hard
        elif unknown_required:
            classification, action, reasons = "unknown", "stop", unknown_required
        elif repeated:
            classification, action, reasons = "degraded", "backoff", repeated
        else:
            suspect = [
                name for name, streak in streaks.items() if streak > 0
            ]
            classification = "suspect" if suspect else "healthy"
            action, reasons = "continue", suspect
            if not suspect:
                healthy_levels.append(sample["level"])
        decision = {
            "sampleIndex": index,
            "level": sample["level"],
            "classification": classification,
            "action": action,
            "reasons": reasons,
            "citations": citations,
        }
        decisions.append(decision)
        if action != "continue":
            trigger = decision
            break
    if trigger is None:
        interval = {
            "lowerTestedHealthy": max(healthy_levels) if healthy_levels else None,
            "upperTestedDegraded": None,
            "censoredByTestedCeiling": True,
        }
        outcome = "censored"
    else:
        prior = [level for level in healthy_levels if level < trigger["level"]]
        interval = {
            "lowerTestedHealthy": max(prior) if prior else None,
            "upperTestedDegraded": trigger["level"],
            "censoredByTestedCeiling": False,
        }
        outcome = trigger["classification"]
    return {
        "apiVersion": ANALYSIS_VERSION,
        "outcome": outcome,
        "testedKneeInterval": interval,
        "capacityClaim": None,
        "policy": configured,
        "decisions": decisions,
        "trigger": trigger,
    }


__all__ = ("analyze_degradation", "fuse_observation", "run_health_adapter")
