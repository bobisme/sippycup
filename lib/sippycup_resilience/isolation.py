"""Cross-call identity planning and contamination detection."""

from __future__ import annotations

import hashlib
import math
from typing import Any, Sequence

from .common import (
    ResilienceError,
    bounded_int,
    exact_keys,
    nonempty_string,
    require_mapping,
    verdict,
)

PLAN_VERSION = "sippycup.dev/isolation-plan/v1"
REPORT_VERSION = "sippycup.dev/isolation-report/v1"
MAX_CALLS = 4096
MAX_OBSERVATIONS = 262_144
WATERMARK_BITS = 32
SYMBOL_MS = 20
ZERO_HZ = 697
ONE_HZ = 1209
WATERMARK_LEVEL = 7000


def plan_isolation(call_count: int, seed: str = "sippycup-isolation-v1") -> dict[str, Any]:
    count = bounded_int(call_count, "callCount", 2, MAX_CALLS)
    seed = nonempty_string(seed, "seed", 128)
    calls: list[dict[str, Any]] = []
    used_ssrc: set[int] = set()
    used_markers: set[str] = set()
    for index in range(count):
        identity = f"call-{index + 1:06d}"
        material = hashlib.sha256(f"{seed}:{identity}".encode()).digest()
        ssrc = int.from_bytes(material[:4], "big") or 1
        while ssrc in used_ssrc:
            ssrc = (ssrc + 1) & 0xFFFFFFFF or 1
        used_ssrc.add(ssrc)
        marker_value = int.from_bytes(material[4:8], "big")
        marker = f"{marker_value:032b}"
        while marker in used_markers:
            marker_value = (marker_value + 1) & 0xFFFFFFFF
            marker = f"{marker_value:032b}"
        used_markers.add(marker)
        calls.append(
            {
                "callId": identity,
                "ssrc": ssrc,
                "marker": marker,
                "dtmf": f"{int.from_bytes(material[12:14], 'big') % 10000:04d}",
                "sourcePort": 20_000 + index * 2,
                "destinationPort": 20_001 + index * 2,
            }
        )
    return {
        "apiVersion": PLAN_VERSION,
        "seed": seed,
        "callCount": count,
        "calls": calls,
        "networkExecutions": 0,
        "claim": "Identity coverage only; this plan does not prove isolation.",
    }


def _validate_plan(value: Any) -> dict[str, Any]:
    plan = require_mapping(value, "isolation plan")
    exact_keys(
        plan,
        ("apiVersion", "seed", "callCount", "calls", "networkExecutions", "claim"),
        name="isolation plan",
    )
    if plan["apiVersion"] != PLAN_VERSION or plan["networkExecutions"] != 0:
        raise ResilienceError("unsupported or network-bearing isolation plan")
    count = bounded_int(plan["callCount"], "callCount", 2, MAX_CALLS)
    if not isinstance(plan["calls"], list) or len(plan["calls"]) != count:
        raise ResilienceError("isolation plan calls must match callCount")
    identities: set[str] = set()
    markers: set[str] = set()
    ssrcs: set[int] = set()
    for index, raw in enumerate(plan["calls"]):
        call = require_mapping(raw, f"calls[{index}]")
        exact_keys(
            call,
            ("callId", "ssrc", "marker", "dtmf", "sourcePort", "destinationPort"),
            name=f"calls[{index}]",
        )
        call_id = nonempty_string(call["callId"], f"calls[{index}].callId")
        marker = nonempty_string(call["marker"], f"calls[{index}].marker", 64)
        if len(marker) != WATERMARK_BITS or set(marker) - {"0", "1"}:
            raise ResilienceError(
                f"calls[{index}].marker must be a {WATERMARK_BITS}-bit watermark"
            )
        ssrc = bounded_int(call["ssrc"], f"calls[{index}].ssrc", 1, 0xFFFFFFFF)
        bounded_int(call["sourcePort"], "sourcePort", 1024, 65535)
        bounded_int(call["destinationPort"], "destinationPort", 1024, 65535)
        if call_id in identities or marker in markers or ssrc in ssrcs:
            raise ResilienceError("call IDs, markers, and SSRCs must be unique")
        identities.add(call_id)
        markers.add(marker)
        ssrcs.add(ssrc)
    return plan


def analyze_isolation(plan_value: Any, observations_value: Any) -> dict[str, Any]:
    plan = _validate_plan(plan_value)
    if not isinstance(observations_value, list):
        raise ResilienceError("observations must be an array")
    if len(observations_value) > MAX_OBSERVATIONS:
        raise ResilienceError(f"observations exceed {MAX_OBSERVATIONS}")
    calls = {item["callId"]: item for item in plan["calls"]}
    marker_owner = {item["marker"]: item["callId"] for item in plan["calls"]}
    ssrc_owner = {item["ssrc"]: item["callId"] for item in plan["calls"]}
    findings: list[dict[str, Any]] = []
    observed_calls: set[str] = set()
    for index, raw in enumerate(observations_value):
        item = require_mapping(raw, f"observations[{index}]")
        exact_keys(
            item,
            ("callId", "marker", "ssrc", "sourcePort", "afterTeardown"),
            name=f"observations[{index}]",
        )
        call_id = nonempty_string(item["callId"], "callId")
        if call_id not in calls:
            raise ResilienceError(f"observation {index} names an unknown call")
        marker = nonempty_string(item["marker"], "marker", 64)
        ssrc = bounded_int(item["ssrc"], "ssrc", 1, 0xFFFFFFFF)
        source_port = bounded_int(item["sourcePort"], "sourcePort", 1024, 65535)
        if type(item["afterTeardown"]) is not bool:
            raise ResilienceError("afterTeardown must be a boolean")
        expected = calls[call_id]
        observed_calls.add(call_id)
        if marker_owner.get(marker) != call_id:
            findings.append(
                {
                    "severity": "fail",
                    "code": "cross_call_marker",
                    "callId": call_id,
                    "owner": marker_owner.get(marker),
                    "observation": index,
                }
            )
        if ssrc_owner.get(ssrc) != call_id or ssrc != expected["ssrc"]:
            findings.append(
                {
                    "severity": "fail",
                    "code": "ssrc_misassociation",
                    "callId": call_id,
                    "owner": ssrc_owner.get(ssrc),
                    "observation": index,
                }
            )
        if source_port != expected["sourcePort"]:
            findings.append(
                {
                    "severity": "fail",
                    "code": "source_tuple_mismatch",
                    "callId": call_id,
                    "observation": index,
                }
            )
        if item["afterTeardown"]:
            findings.append(
                {
                    "severity": "fail",
                    "code": "media_after_teardown",
                    "callId": call_id,
                    "observation": index,
                }
            )
    missing = sorted(calls.keys() - observed_calls)
    for call_id in missing:
        findings.append(
            {"severity": "fail", "code": "call_unobserved", "callId": call_id}
        )
    return {
        "apiVersion": REPORT_VERSION,
        "status": verdict(findings),
        "plannedCalls": len(calls),
        "observedCalls": len(observed_calls),
        "observations": len(observations_value),
        "findings": findings,
        "capacityClaim": None,
    }


def clean_observations(plan: dict[str, Any]) -> list[dict[str, Any]]:
    validated = _validate_plan(plan)
    return [
        {
            "callId": item["callId"],
            "marker": item["marker"],
            "ssrc": item["ssrc"],
            "sourcePort": item["sourcePort"],
            "afterTeardown": False,
        }
        for item in validated["calls"]
    ]


def render_watermark(marker: str, sample_rate_hz: int = 8000) -> tuple[int, ...]:
    """Render a codec-tolerant two-frequency identity watermark as PCM16."""
    if (
        not isinstance(marker, str)
        or len(marker) != WATERMARK_BITS
        or set(marker) - {"0", "1"}
    ):
        raise ResilienceError(f"marker must contain exactly {WATERMARK_BITS} bits")
    rate = bounded_int(sample_rate_hz, "sampleRateHz", 8000, 48000)
    symbol_samples = rate * SYMBOL_MS // 1000
    samples: list[int] = []
    for bit in marker:
        frequency = ONE_HZ if bit == "1" else ZERO_HZ
        for offset in range(symbol_samples):
            fade = min(1.0, (offset + 1) / 8, (symbol_samples - offset) / 8)
            value = int(
                WATERMARK_LEVEL
                * fade
                * math.sin(2.0 * math.pi * frequency * offset / rate)
            )
            samples.append(value)
    return tuple(samples)


def _tone_power(samples: Sequence[int], frequency: int, rate: int) -> float:
    sine = 0.0
    cosine = 0.0
    for index, value in enumerate(samples):
        angle = 2.0 * math.pi * frequency * index / rate
        sine += value * math.sin(angle)
        cosine += value * math.cos(angle)
    return sine * sine + cosine * cosine


def decode_watermark(samples: Sequence[int], sample_rate_hz: int = 8000) -> str:
    """Decode a watermark; ambiguous mixed symbols are returned as '?'."""
    rate = bounded_int(sample_rate_hz, "sampleRateHz", 8000, 48000)
    symbol_samples = rate * SYMBOL_MS // 1000
    expected = WATERMARK_BITS * symbol_samples
    if len(samples) != expected:
        raise ResilienceError(f"watermark PCM must contain exactly {expected} samples")
    decoded: list[str] = []
    for index in range(WATERMARK_BITS):
        segment = samples[index * symbol_samples : (index + 1) * symbol_samples]
        zero = _tone_power(segment, ZERO_HZ, rate)
        one = _tone_power(segment, ONE_HZ, rate)
        if one > zero * 2.0:
            decoded.append("1")
        elif zero > one * 2.0:
            decoded.append("0")
        else:
            decoded.append("?")
    return "".join(decoded)
