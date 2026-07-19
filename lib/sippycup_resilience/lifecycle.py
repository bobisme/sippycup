"""Lifecycle soak and bounded resource-leak analysis."""

from __future__ import annotations

from typing import Any

from .common import (
    ResilienceError,
    bounded_int,
    exact_keys,
    finite_number,
    require_mapping,
    verdict,
)

REPORT_VERSION = "sippycup.dev/lifecycle-report/v1"
SCENARIOS = (
    "answered_bye",
    "cancel_487",
    "reinvite",
    "lost_bye_expiry",
    "reconnect",
    "graceful_drain_restart",
)
RESOURCE_KEYS = ("sessions", "sockets", "tasks", "memoryBytes")
MAX_CYCLES = 100_000


def synthetic_snapshots(cycles: int, leak: str | None = None) -> list[dict[str, Any]]:
    count = bounded_int(cycles, "cycles", 1, MAX_CYCLES)
    if leak is not None and leak not in RESOURCE_KEYS:
        raise ResilienceError(f"leak must be one of {', '.join(RESOURCE_KEYS)}")
    snapshots: list[dict[str, Any]] = [
        {
            "cycle": 0,
            "phase": "baseline",
            "scenario": "answered_bye",
            "sessions": 0,
            "sockets": 2,
            "tasks": 4,
            "memoryBytes": 16_777_216,
        }
    ]
    for cycle in range(1, count + 1):
        values = {
            "sessions": 0,
            "sockets": 2,
            "tasks": 4,
            "memoryBytes": 16_777_216,
        }
        if leak is not None:
            values[leak] += cycle * (4096 if leak == "memoryBytes" else 1)
        snapshots.append(
            {
                "cycle": cycle,
                "phase": "settled",
                "scenario": SCENARIOS[(cycle - 1) % len(SCENARIOS)],
                **values,
            }
        )
    return snapshots


def analyze_lifecycle(
    snapshots_value: Any,
    *,
    memory_tolerance_bytes: int = 1_048_576,
) -> dict[str, Any]:
    if not isinstance(snapshots_value, list) or not 2 <= len(snapshots_value) <= MAX_CYCLES + 1:
        raise ResilienceError("snapshots must contain baseline plus 1..100000 settled cycles")
    tolerance = bounded_int(
        memory_tolerance_bytes, "memoryToleranceBytes", 0, 1_073_741_824
    )
    snapshots: list[dict[str, Any]] = []
    previous_cycle = -1
    scenarios: set[str] = set()
    for index, raw in enumerate(snapshots_value):
        item = require_mapping(raw, f"snapshots[{index}]")
        exact_keys(
            item,
            ("cycle", "phase", "scenario", *RESOURCE_KEYS),
            name=f"snapshots[{index}]",
        )
        cycle = bounded_int(item["cycle"], "cycle", 0, MAX_CYCLES)
        if cycle <= previous_cycle:
            raise ResilienceError("snapshot cycles must be strictly increasing")
        previous_cycle = cycle
        if item["phase"] not in {"baseline", "settled"}:
            raise ResilienceError("phase must be baseline or settled")
        if item["scenario"] not in SCENARIOS:
            raise ResilienceError("snapshot scenario is unsupported")
        for key in RESOURCE_KEYS:
            bounded_int(item[key], key, 0, 1 << 50)
        scenarios.add(item["scenario"])
        snapshots.append(item)
    if snapshots[0]["cycle"] != 0 or snapshots[0]["phase"] != "baseline":
        raise ResilienceError("first snapshot must be cycle-zero baseline")
    if any(item["phase"] != "settled" for item in snapshots[1:]):
        raise ResilienceError("post-baseline snapshots must be settled")
    baseline = snapshots[0]
    findings: list[dict[str, Any]] = []
    maxima = {key: max(item[key] for item in snapshots[1:]) for key in RESOURCE_KEYS}
    for key in ("sessions", "sockets", "tasks"):
        leaked = [item for item in snapshots[1:] if item[key] > baseline[key]]
        if leaked:
            findings.append(
                {
                    "severity": "fail",
                    "code": f"{key}_not_recovered",
                    "firstCycle": leaked[0]["cycle"],
                    "maximum": maxima[key],
                    "baseline": baseline[key],
                }
            )
    memory_limit = baseline["memoryBytes"] + tolerance
    memory_leak = [item for item in snapshots[1:] if item["memoryBytes"] > memory_limit]
    if memory_leak:
        findings.append(
            {
                "severity": "fail",
                "code": "memory_not_recovered",
                "firstCycle": memory_leak[0]["cycle"],
                "maximum": maxima["memoryBytes"],
                "baseline": baseline["memoryBytes"],
                "toleranceBytes": tolerance,
            }
        )
    first_memory = finite_number(
        snapshots[1]["memoryBytes"], "first memory", 0, 1 << 50
    )
    last_memory = finite_number(
        snapshots[-1]["memoryBytes"], "last memory", 0, 1 << 50
    )
    slope = (last_memory - first_memory) / max(1, len(snapshots) - 2)
    return {
        "apiVersion": REPORT_VERSION,
        "status": verdict(findings),
        "cycles": len(snapshots) - 1,
        "scenariosObserved": sorted(scenarios),
        "baseline": {key: baseline[key] for key in RESOURCE_KEYS},
        "maxSettled": maxima,
        "memorySlopeBytesPerCycle": round(slope, 3),
        "findings": findings,
        "scaleClaim": None,
    }
