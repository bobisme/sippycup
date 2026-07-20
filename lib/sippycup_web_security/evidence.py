"""Offline oracle for normalized admin and WebSocket probe evidence."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import sys
from typing import Any, Mapping

from .contracts import (
    ALL_CHECKS,
    LIMIT_BOUNDS,
    MAX_INPUT_BYTES,
    OUTCOMES,
    PLAN_VERSION,
    WebSecurityError,
    _HOSTNAME,
    _array,
    _boolean,
    _enum,
    _exact,
    _identifier,
    _integer,
    _object,
    _read,
)

OBSERVATION_VERSION = "sippycup.dev/web-security-observation/v1"
REPORT_VERSION = "sippycup.dev/web-security-report/v1"
_DIGEST = __import__("re").compile(r"^[0-9a-f]{64}$")
_OBSERVED_OUTCOMES = OUTCOMES | {"unknown", "error"}
_COUNTERS = {
    "connections",
    "httpRequests",
    "wsMessages",
    "authFailures",
    "bytes",
    "durationMs",
}


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise WebSecurityError(f"{path} must be a SHA-256 digest")
    return value


def plan_digest(plan: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        plan,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def validate_plan(document: Any) -> dict[str, Any]:
    plan = dict(_object(document, "$"))
    _exact(
        plan,
        "$",
        {
            "apiVersion",
            "networkActivity",
            "executionClass",
            "adapter",
            "authorization",
            "destinations",
            "cases",
            "limits",
            "arbitraryRequestsAvailable",
        },
    )
    if plan["apiVersion"] != PLAN_VERSION:
        raise WebSecurityError("$.apiVersion is unsupported")
    if plan["networkActivity"] is not False:
        raise WebSecurityError("$.networkActivity must be false")
    execution_class = _enum(
        plan["executionClass"],
        "$.executionClass",
        {"offline_fixture", "local_lab", "approved_target"},
    )
    adapter = _object(plan["adapter"], "$.adapter")
    _exact(adapter, "$.adapter", {"id", "version"})
    _identifier(adapter["id"], "$.adapter.id")
    if not isinstance(adapter["version"], str) or len(adapter["version"]) > 32:
        raise WebSecurityError("$.adapter.version is invalid")
    authorization = _object(plan["authorization"], "$.authorization")
    _exact(
        authorization,
        "$.authorization",
        {"state", "reference", "surfaces", "blockers"},
    )
    state = _enum(
        authorization["state"],
        "$.authorization.state",
        {"not-required", "ready", "blocked"},
    )
    if authorization["reference"] is not None:
        _identifier(authorization["reference"], "$.authorization.reference")
    surfaces = _array(authorization["surfaces"], "$.authorization.surfaces")
    if len(surfaces) != len(set(surfaces)):
        raise WebSecurityError("$.authorization.surfaces must be unique")
    for index, surface in enumerate(surfaces):
        _enum(surface, f"$.authorization.surfaces[{index}]", {"admin", "websocket"})
    blockers = _array(authorization["blockers"], "$.authorization.blockers")
    for index, blocker in enumerate(blockers):
        _enum(
            blocker,
            f"$.authorization.blockers[{index}]",
            {"authorization-window-not-started", "authorization-window-expired"},
        )
    if state == "blocked" and not blockers:
        raise WebSecurityError("blocked authorization requires a blocker")
    if state != "blocked" and blockers:
        raise WebSecurityError("authorization blockers require blocked state")
    if execution_class == "approved_target":
        if state not in {"ready", "blocked"}:
            raise WebSecurityError("approved_target authorization cannot be not-required")
        if authorization["reference"] is None or not surfaces:
            raise WebSecurityError(
                "approved_target requires an authorization reference and surfaces"
            )
    elif (
        state != "not-required"
        or authorization["reference"] is not None
        or surfaces
    ):
        raise WebSecurityError(
            "offline_fixture/local_lab authorization must be not-required and empty"
        )

    destinations = _array(plan["destinations"], "$.destinations")
    if not destinations or len(destinations) > 8:
        raise WebSecurityError("$.destinations must contain 1 to 8 entries")
    for index, item in enumerate(destinations):
        path = f"$.destinations[{index}]"
        destination = _object(item, path)
        _exact(
            destination,
            path,
            {"id", "surface", "scheme", "connectAddress", "port", "tlsServerName"},
        )
        _identifier(destination["id"], f"{path}.id")
        surface = _enum(
            destination["surface"], f"{path}.surface", {"admin", "websocket"}
        )
        expected_scheme = "https" if surface == "admin" else "wss"
        if destination["scheme"] != expected_scheme:
            raise WebSecurityError(f"{path}.scheme must be {expected_scheme}")
        try:
            address = ipaddress.ip_address(destination["connectAddress"])
        except (TypeError, ValueError) as exc:
            raise WebSecurityError(
                f"{path}.connectAddress must be a literal IP"
            ) from exc
        if address.is_multicast or address.is_unspecified:
            raise WebSecurityError(f"{path}.connectAddress must be unicast")
        if execution_class == "offline_fixture" and not address.is_loopback:
            raise WebSecurityError("offline_fixture destinations are loopback-only")
        if execution_class == "local_lab" and not (
            address.is_loopback or address.is_private or address.is_link_local
        ):
            raise WebSecurityError("local_lab destinations cannot use public addresses")
        _integer(destination["port"], f"{path}.port", 1, 65535)
        if not isinstance(destination["tlsServerName"], str) or not _HOSTNAME.fullmatch(
            destination["tlsServerName"]
        ):
            raise WebSecurityError(f"{path}.tlsServerName must be a DNS name")

    cases = _array(plan["cases"], "$.cases")
    case_ids: set[str] = set()
    for index, item in enumerate(cases):
        path = f"$.cases[{index}]"
        case = _object(item, path)
        _exact(
            case,
            path,
            {
                "id",
                "check",
                "routeId",
                "credentialRole",
                "credentialRef",
                "originClass",
                "expectedOutcome",
            },
        )
        case_id = _identifier(case["id"], f"{path}.id")
        if case_id in case_ids:
            raise WebSecurityError(f"{path}.id is duplicated")
        case_ids.add(case_id)
        _enum(case["check"], f"{path}.check", ALL_CHECKS)
        _identifier(case["routeId"], f"{path}.routeId")
        for key in ("credentialRole", "credentialRef"):
            if case[key] is not None:
                _identifier(case[key], f"{path}.{key}")
        if case["originClass"] is not None:
            _enum(
                case["originClass"],
                f"{path}.originClass",
                {"allowed", "disallowed"},
            )
        _enum(case["expectedOutcome"], f"{path}.expectedOutcome", OUTCOMES)

    limits = _object(plan["limits"], "$.limits")
    _exact(
        limits,
        "$.limits",
        {
            "maxCases",
            "maxConnections",
            "maxHttpRequests",
            "maxWsMessages",
            "maxAuthFailures",
            "maxBytes",
            "maxDurationSeconds",
            "maxRequestsPerSecond",
        },
    )
    for key, (minimum, maximum) in LIMIT_BOUNDS.items():
        _integer(limits[key], f"$.limits.{key}", minimum, maximum)
    if len(cases) > limits["maxCases"]:
        raise WebSecurityError("$.cases exceeds $.limits.maxCases")
    selected_surfaces = {
        "admin" if case["check"].startswith("admin.") else "websocket"
        for case in cases
    }
    if execution_class == "approved_target" and not selected_surfaces <= set(surfaces):
        raise WebSecurityError("$.cases exceed authorized surfaces")
    if plan["arbitraryRequestsAvailable"] is not False:
        raise WebSecurityError("$.arbitraryRequestsAvailable must be false")
    return plan


def validate_observation(document: Any) -> dict[str, Any]:
    observation = dict(_object(document, "$"))
    _exact(
        observation,
        "$",
        {"apiVersion", "networkActivity", "planDigest", "results", "totals", "cleanup"},
    )
    if observation["apiVersion"] != OBSERVATION_VERSION:
        raise WebSecurityError("$.apiVersion is unsupported")
    _boolean(observation["networkActivity"], "$.networkActivity")
    _digest(observation["planDigest"], "$.planDigest")
    results = _array(observation["results"], "$.results")
    if len(results) > 256:
        raise WebSecurityError("$.results exceeds 256 entries")
    case_ids: set[str] = set()
    last_sequence = 0
    last_time = -1
    for index, item in enumerate(results):
        path = f"$.results[{index}]"
        result = _object(item, path)
        _exact(
            result,
            path,
            {
                "sequence",
                "timeMs",
                "caseId",
                "check",
                "surface",
                "observedOutcome",
                "responseClass",
                "closeCode",
                "sessionState",
                "counters",
            },
        )
        sequence = _integer(result["sequence"], f"{path}.sequence", 1, 256)
        if sequence != last_sequence + 1:
            raise WebSecurityError("$.results sequence must start at 1 and be contiguous")
        last_sequence = sequence
        time_ms = _integer(result["timeMs"], f"{path}.timeMs", 0, 900000)
        if time_ms < last_time:
            raise WebSecurityError("$.results timeMs must be nondecreasing")
        last_time = time_ms
        case_id = _identifier(result["caseId"], f"{path}.caseId")
        if case_id in case_ids:
            raise WebSecurityError(f"{path}.caseId is duplicated")
        case_ids.add(case_id)
        _enum(result["check"], f"{path}.check", ALL_CHECKS)
        _enum(result["surface"], f"{path}.surface", {"admin", "websocket"})
        _enum(
            result["observedOutcome"],
            f"{path}.observedOutcome",
            _OBSERVED_OUTCOMES,
        )
        _enum(
            result["responseClass"],
            f"{path}.responseClass",
            {"none", "2xx", "3xx", "4xx", "5xx", "network-error"},
        )
        if result["closeCode"] is not None:
            _integer(result["closeCode"], f"{path}.closeCode", 1000, 4999)
        _enum(
            result["sessionState"],
            f"{path}.sessionState",
            {"none", "pre-auth", "authenticated", "expired", "closed", "unknown"},
        )
        counters = _object(result["counters"], f"{path}.counters")
        _exact(counters, f"{path}.counters", _COUNTERS)
        for key in _COUNTERS:
            _integer(counters[key], f"{path}.counters.{key}", 0, 16777216)
    totals = _object(observation["totals"], "$.totals")
    _exact(totals, "$.totals", _COUNTERS)
    for key in _COUNTERS:
        _integer(totals[key], f"$.totals.{key}", 0, 16777216)
    cleanup = _object(observation["cleanup"], "$.cleanup")
    _exact(cleanup, "$.cleanup", {"openConnections", "liveSessions"})
    _integer(cleanup["openConnections"], "$.cleanup.openConnections", 0, 100000)
    _integer(cleanup["liveSessions"], "$.cleanup.liveSessions", 0, 100000)
    return observation


def evaluate(plan_document: Any, observation_document: Any) -> dict[str, Any]:
    plan = validate_plan(plan_document)
    observation = validate_observation(observation_document)
    findings: list[dict[str, Any]] = []
    unknowns: list[dict[str, Any]] = []

    def fail(code: str, case_id: str | None, detail: str) -> None:
        findings.append({"code": code, "caseId": case_id, "detail": detail})

    if observation["planDigest"] != plan_digest(plan):
        raise WebSecurityError("$.planDigest does not bind the supplied plan")
    planned = {item["id"]: item for item in plan["cases"]}
    observed = {item["caseId"]: item for item in observation["results"]}
    for case_id in sorted(set(observed) - set(planned)):
        fail("evidence.unplanned_case", case_id, "case is absent from plan")
    for case_id, case in planned.items():
        result = observed.get(case_id)
        if result is None:
            unknowns.append({"code": "evidence.case_missing", "caseId": case_id})
            continue
        expected_surface = (
            "admin" if case["check"].startswith("admin.") else "websocket"
        )
        if result["check"] != case["check"] or result["surface"] != expected_surface:
            fail("evidence.case_binding_mismatch", case_id, "check or surface")
        outcome = result["observedOutcome"]
        if outcome in {"unknown", "error"}:
            unknowns.append(
                {"code": "evidence.case_unknown", "caseId": case_id, "reason": outcome}
            )
        elif outcome != case["expectedOutcome"]:
            fail(
                "security.unexpected_outcome",
                case_id,
                f"expected={case['expectedOutcome']} observed={outcome}",
            )
        if outcome in {"denied", "rejected", "expired", "closed"} and result[
            "sessionState"
        ] == "authenticated":
            fail(
                "security.denial_left_authenticated_session",
                case_id,
                outcome,
            )
    summed = {
        key: sum(item["counters"][key] for item in observation["results"])
        for key in _COUNTERS
    }
    for key in _COUNTERS:
        if observation["totals"][key] != summed[key]:
            raise WebSecurityError(f"$.totals.{key} does not match case counters")
    limits = plan["limits"]
    comparisons = {
        "connections": ("maxConnections", summed["connections"]),
        "httpRequests": ("maxHttpRequests", summed["httpRequests"]),
        "wsMessages": ("maxWsMessages", summed["wsMessages"]),
        "authFailures": ("maxAuthFailures", summed["authFailures"]),
        "bytes": ("maxBytes", summed["bytes"]),
        "durationMs": ("maxDurationSeconds", summed["durationMs"] / 1000),
    }
    for name, (limit_name, value) in comparisons.items():
        if value > limits[limit_name]:
            fail("limits.ceiling_exceeded", None, f"{name}:{value}>{limits[limit_name]}")
    duration_seconds = max(1.0, summed["durationMs"] / 1000)
    request_rate = (summed["httpRequests"] + summed["wsMessages"]) / duration_seconds
    if request_rate > limits["maxRequestsPerSecond"]:
        fail(
            "limits.request_rate_exceeded",
            None,
            f"{request_rate:.3f}>{limits['maxRequestsPerSecond']}",
        )
    if plan["authorization"]["state"] == "blocked" and any(
        summed[key] > 0
        for key in ("connections", "httpRequests", "wsMessages", "bytes")
    ):
        fail("authorization.traffic_while_blocked", None, "nonzero traffic counters")
    observed_traffic = any(
        summed[key] > 0
        for key in ("connections", "httpRequests", "wsMessages", "bytes")
    )
    if observed_traffic != observation["networkActivity"]:
        fail(
            "evidence.network_activity_mismatch",
            None,
            "networkActivity does not match normalized traffic counters",
        )
    if observation["cleanup"]["openConnections"] or observation["cleanup"]["liveSessions"]:
        fail(
            "cleanup.incomplete",
            None,
            f"connections={observation['cleanup']['openConnections']} "
            f"sessions={observation['cleanup']['liveSessions']}",
        )
    status = "fail" if findings else ("incomplete" if unknowns else "pass")
    return {
        "apiVersion": REPORT_VERSION,
        "status": status,
        "networkActivity": False,
        "observedNetworkActivity": observation["networkActivity"],
        "planDigest": observation["planDigest"],
        "casesPlanned": len(planned),
        "casesObserved": len(observed),
        "findings": findings,
        "unknowns": unknowns,
        "totals": dict(observation["totals"]),
        "secretsRetained": False,
        "rawMessagesRetained": False,
        "capacityClaim": None,
    }


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="web-security-evidence",
        description="Evaluate normalized admin/WebSocket security evidence offline.",
    )
    parser.add_argument("plan")
    parser.add_argument("observation")
    parsed = parser.parse_args(arguments)
    try:
        report = evaluate(_read(parsed.plan), _read(parsed.observation))
    except WebSecurityError as exc:
        print(f"Web security evidence rejected: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return {"pass": 0, "fail": 1, "incomplete": 3}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
