"""Strict contracts for bounded admin and WebSocket security profiles."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping
from urllib.parse import urlsplit

PROFILE_VERSION = "sippycup.dev/web-security-profile/v1"
ADAPTER_VERSION = "sippycup.dev/web-security-adapter/v1"
PLAN_VERSION = "sippycup.dev/web-security-plan/v1"
MAX_INPUT_BYTES = 2 * 1024 * 1024
_ID = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_ENV_REF = re.compile(r"^env://[A-Z][A-Z0-9_]{0,63}$")
_FD_REF = re.compile(r"^fd://(?:[3-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
_EXEC_REF = re.compile(r"^exec://[a-z][a-z0-9.-]{0,63}$")

ADMIN_CHECKS = {
    "admin.auth-required",
    "admin.role-boundary",
    "admin.csrf",
    "admin.session-expiry",
    "admin.object-scope",
    "admin.rate-limit",
}
WEBSOCKET_CHECKS = {
    "websocket.origin",
    "websocket.auth-required",
    "websocket.session-expiry",
    "websocket.replay",
    "websocket.message-authorization",
    "websocket.size-limit",
    "websocket.rate-limit",
    "websocket.state-machine",
    "websocket.reconnect",
}
ALL_CHECKS = ADMIN_CHECKS | WEBSOCKET_CHECKS
OPERATIONS = {
    "login",
    "session-check",
    "admin-read",
    "admin-write",
    "ws-connect",
    "ws-message",
    "ws-close",
}
OUTCOMES = {
    "allowed",
    "denied",
    "rate-limited",
    "expired",
    "closed",
    "rejected",
}
LIMIT_BOUNDS = {
    "maxCases": (1, 256),
    "maxConnections": (1, 64),
    "maxHttpRequests": (0, 1000),
    "maxWsMessages": (0, 10000),
    "maxAuthFailures": (0, 32),
    "maxBytes": (1, 16777216),
    "maxDurationSeconds": (1, 900),
    "maxRequestsPerSecond": (1, 100),
}


class WebSecurityError(ValueError):
    """A profile, adapter, or plan violates the safety contract."""


def _object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise WebSecurityError(f"{path} must be an object")
    return value


def _array(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise WebSecurityError(f"{path} must be an array")
    return value


def _exact(
    value: Mapping[str, Any],
    path: str,
    required: set[str],
) -> None:
    missing = required - set(value)
    extra = set(value) - required
    if missing:
        raise WebSecurityError(f"{path} is missing: {', '.join(sorted(missing))}")
    if extra:
        raise WebSecurityError(f"{path} has unknown fields: {', '.join(sorted(extra))}")


def _integer(value: Any, path: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise WebSecurityError(f"{path} must be an integer")
    if not minimum <= value <= maximum:
        raise WebSecurityError(f"{path} must be between {minimum} and {maximum}")
    return value


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise WebSecurityError(f"{path} must be boolean")
    return value


def _enum(value: Any, path: str, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise WebSecurityError(f"{path} must be one of: {', '.join(sorted(allowed))}")
    return value


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise WebSecurityError(f"{path} must be a bounded lowercase identifier")
    return value


def _optional_identifier(value: Any, path: str) -> str | None:
    return None if value is None else _identifier(value, path)


def _timestamp(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise WebSecurityError(f"{path} must be a UTC RFC3339 timestamp")
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise WebSecurityError(f"{path} must be a UTC RFC3339 timestamp") from exc
    if result.tzinfo != timezone.utc:
        raise WebSecurityError(f"{path} must be UTC")
    return result


def _origin(value: Any, path: str) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise WebSecurityError(f"{path} must be a bounded HTTPS origin")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise WebSecurityError(f"{path} has an invalid port") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise WebSecurityError(
            f"{path} must be an HTTPS origin without credentials or path"
        )
    return value


def _validate_authorization(profile: Mapping[str, Any], execution_class: str) -> None:
    authorization = _object(profile["authorization"], "$.authorization")
    _exact(
        authorization,
        "$.authorization",
        {"required", "reference", "notBefore", "notAfter", "surfaces"},
    )
    required = _boolean(authorization["required"], "$.authorization.required")
    surfaces = _array(authorization["surfaces"], "$.authorization.surfaces")
    if len(surfaces) != len(set(surfaces)):
        raise WebSecurityError("$.authorization.surfaces must be unique")
    for index, surface in enumerate(surfaces):
        _enum(surface, f"$.authorization.surfaces[{index}]", {"admin", "websocket"})
    if execution_class == "approved_target":
        if not required:
            raise WebSecurityError("approved_target requires authorization.required=true")
        _identifier(authorization["reference"], "$.authorization.reference")
        start = _timestamp(authorization["notBefore"], "$.authorization.notBefore")
        end = _timestamp(authorization["notAfter"], "$.authorization.notAfter")
        if end <= start:
            raise WebSecurityError("$.authorization.notAfter must follow notBefore")
        if (end - start).total_seconds() > 86400:
            raise WebSecurityError("authorization window cannot exceed 24 hours")
        if not surfaces:
            raise WebSecurityError("approved_target requires explicit authorized surfaces")
    elif required or surfaces or any(
        authorization[key] is not None
        for key in ("reference", "notBefore", "notAfter")
    ):
        raise WebSecurityError(
            "offline_fixture/local_lab cannot carry target authorization"
        )


def _validate_destinations(
    profile: Mapping[str, Any],
    execution_class: str,
) -> set[str]:
    destinations = _array(profile["destinations"], "$.destinations")
    if not destinations or len(destinations) > 8:
        raise WebSecurityError("$.destinations must contain 1 to 8 entries")
    identifiers: set[str] = set()
    surfaces: set[str] = set()
    for index, item in enumerate(destinations):
        path = f"$.destinations[{index}]"
        destination = _object(item, path)
        _exact(
            destination,
            path,
            {"id", "surface", "scheme", "connectAddress", "port", "tlsServerName"},
        )
        identifier = _identifier(destination["id"], f"{path}.id")
        if identifier in identifiers:
            raise WebSecurityError(f"{path}.id is duplicated")
        identifiers.add(identifier)
        surface = _enum(
            destination["surface"], f"{path}.surface", {"admin", "websocket"}
        )
        surfaces.add(surface)
        expected_scheme = "https" if surface == "admin" else "wss"
        if destination["scheme"] != expected_scheme:
            raise WebSecurityError(f"{path}.scheme must be {expected_scheme}")
        try:
            address = ipaddress.ip_address(destination["connectAddress"])
        except (TypeError, ValueError) as exc:
            raise WebSecurityError(f"{path}.connectAddress must be a literal IP") from exc
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
    return surfaces


def _validate_credentials(profile: Mapping[str, Any]) -> set[str]:
    credentials = _array(profile["credentialRefs"], "$.credentialRefs")
    if len(credentials) > 16:
        raise WebSecurityError("$.credentialRefs exceeds 16 entries")
    identifiers: set[str] = set()
    roles: set[str] = set()
    for index, item in enumerate(credentials):
        path = f"$.credentialRefs[{index}]"
        credential = _object(item, path)
        _exact(credential, path, {"id", "provider", "sourceRef", "role"})
        identifier = _identifier(credential["id"], f"{path}.id")
        if identifier in identifiers:
            raise WebSecurityError(f"{path}.id is duplicated")
        identifiers.add(identifier)
        provider = _enum(
            credential["provider"], f"{path}.provider", {"env", "fd", "exec"}
        )
        pattern = {"env": _ENV_REF, "fd": _FD_REF, "exec": _EXEC_REF}[provider]
        if not isinstance(credential["sourceRef"], str) or not pattern.fullmatch(
            credential["sourceRef"]
        ):
            raise WebSecurityError(
                f"{path}.sourceRef must be a bounded {provider} provider reference"
            )
        role = _identifier(credential["role"], f"{path}.role")
        if role in roles:
            raise WebSecurityError(f"{path}.role must map to exactly one credential")
        roles.add(role)
    return roles


def _validate_origins(profile: Mapping[str, Any]) -> set[str]:
    origins = _array(profile["origins"], "$.origins")
    if len(origins) > 16:
        raise WebSecurityError("$.origins exceeds 16 entries")
    identifiers: set[str] = set()
    classes: set[str] = set()
    for index, item in enumerate(origins):
        path = f"$.origins[{index}]"
        origin = _object(item, path)
        _exact(origin, path, {"id", "value", "classification"})
        identifier = _identifier(origin["id"], f"{path}.id")
        if identifier in identifiers:
            raise WebSecurityError(f"{path}.id is duplicated")
        identifiers.add(identifier)
        _origin(origin["value"], f"{path}.value")
        classes.add(
            _enum(
                origin["classification"],
                f"{path}.classification",
                {"allowed", "disallowed"},
            )
        )
    return classes


def validate_profile(document: Any) -> dict[str, Any]:
    profile = dict(_object(document, "$"))
    _exact(
        profile,
        "$",
        {
            "apiVersion",
            "executionClass",
            "adapter",
            "authorization",
            "destinations",
            "credentialRefs",
            "origins",
            "checks",
            "limits",
        },
    )
    if profile["apiVersion"] != PROFILE_VERSION:
        raise WebSecurityError("$.apiVersion is unsupported")
    execution_class = _enum(
        profile["executionClass"],
        "$.executionClass",
        {"offline_fixture", "local_lab", "approved_target"},
    )
    adapter = _object(profile["adapter"], "$.adapter")
    _exact(adapter, "$.adapter", {"id", "version"})
    _identifier(adapter["id"], "$.adapter.id")
    if not isinstance(adapter["version"], str) or not _VERSION.fullmatch(
        adapter["version"]
    ):
        raise WebSecurityError("$.adapter.version must be semantic version X.Y.Z")
    _validate_authorization(profile, execution_class)
    destination_surfaces = _validate_destinations(profile, execution_class)
    _validate_credentials(profile)
    origin_classes = _validate_origins(profile)

    checks = _array(profile["checks"], "$.checks")
    if not checks or len(checks) != len(set(checks)):
        raise WebSecurityError("$.checks must be non-empty and unique")
    for index, check in enumerate(checks):
        _enum(check, f"$.checks[{index}]", ALL_CHECKS)
    selected_surfaces = {
        "admin" if check.startswith("admin.") else "websocket" for check in checks
    }
    if not selected_surfaces <= destination_surfaces:
        raise WebSecurityError("every selected check requires a matching destination")
    if execution_class == "approved_target" and not selected_surfaces <= set(
        profile["authorization"]["surfaces"]
    ):
        raise WebSecurityError(
            "selected checks exceed independently authorized surfaces"
        )
    if "websocket.origin" in checks and not {
        "allowed",
        "disallowed",
    } <= origin_classes:
        raise WebSecurityError(
            "websocket.origin requires allowed and disallowed origin fixtures"
        )

    limits = _object(profile["limits"], "$.limits")
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
    return profile


def validate_adapter(document: Any) -> dict[str, Any]:
    adapter = dict(_object(document, "$"))
    _exact(adapter, "$", {"apiVersion", "id", "version", "checks", "routes", "cases"})
    if adapter["apiVersion"] != ADAPTER_VERSION:
        raise WebSecurityError("$.apiVersion is unsupported")
    _identifier(adapter["id"], "$.id")
    if not isinstance(adapter["version"], str) or not _VERSION.fullmatch(
        adapter["version"]
    ):
        raise WebSecurityError("$.version must be semantic version X.Y.Z")
    checks = _array(adapter["checks"], "$.checks")
    if not checks or len(checks) != len(set(checks)):
        raise WebSecurityError("$.checks must be non-empty and unique")
    for index, check in enumerate(checks):
        _enum(check, f"$.checks[{index}]", ALL_CHECKS)
    routes = _array(adapter["routes"], "$.routes")
    if not routes or len(routes) > 64:
        raise WebSecurityError("$.routes must contain 1 to 64 entries")
    route_surfaces: dict[str, str] = {}
    for index, item in enumerate(routes):
        path = f"$.routes[{index}]"
        route = _object(item, path)
        _exact(route, path, {"id", "surface", "operation"})
        route_id = _identifier(route["id"], f"{path}.id")
        if route_id in route_surfaces:
            raise WebSecurityError(f"{path}.id is duplicated")
        surface = _enum(route["surface"], f"{path}.surface", {"admin", "websocket"})
        route_surfaces[route_id] = surface
        operation = _enum(route["operation"], f"{path}.operation", OPERATIONS)
        if surface == "admin" and operation.startswith("ws-"):
            raise WebSecurityError(f"{path}.operation is incompatible with admin")
        if surface == "websocket" and not operation.startswith("ws-"):
            raise WebSecurityError(f"{path}.operation is incompatible with websocket")
    cases = _array(adapter["cases"], "$.cases")
    if not cases or len(cases) > 256:
        raise WebSecurityError("$.cases must contain 1 to 256 entries")
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
                "originClass",
                "expectedOutcome",
            },
        )
        case_id = _identifier(case["id"], f"{path}.id")
        if case_id in case_ids:
            raise WebSecurityError(f"{path}.id is duplicated")
        case_ids.add(case_id)
        check = _enum(case["check"], f"{path}.check", set(checks))
        route_id = _identifier(case["routeId"], f"{path}.routeId")
        if route_id not in route_surfaces:
            raise WebSecurityError(f"{path}.routeId is unknown")
        surface = "admin" if check.startswith("admin.") else "websocket"
        if route_surfaces[route_id] != surface:
            raise WebSecurityError(f"{path} check and route surfaces differ")
        _optional_identifier(case["credentialRole"], f"{path}.credentialRole")
        if case["originClass"] is not None:
            _enum(
                case["originClass"],
                f"{path}.originClass",
                {"allowed", "disallowed"},
            )
        if check == "websocket.origin" and case["originClass"] is None:
            raise WebSecurityError(f"{path}.originClass is required for origin checks")
        _enum(case["expectedOutcome"], f"{path}.expectedOutcome", OUTCOMES)
    return adapter


def compile_plan(
    profile_document: Any,
    adapter_document: Any,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    profile = validate_profile(profile_document)
    adapter = validate_adapter(adapter_document)
    if (
        profile["adapter"]["id"] != adapter["id"]
        or profile["adapter"]["version"] != adapter["version"]
    ):
        raise WebSecurityError("profile and adapter identity/version do not match")
    selected_checks = set(profile["checks"])
    if not selected_checks <= set(adapter["checks"]):
        missing = sorted(selected_checks - set(adapter["checks"]))
        raise WebSecurityError(f"adapter does not support: {', '.join(missing)}")
    role_refs = {item["role"]: item["id"] for item in profile["credentialRefs"]}
    origin_classes = {item["classification"] for item in profile["origins"]}
    cases = []
    covered: set[str] = set()
    for case in adapter["cases"]:
        if case["check"] not in selected_checks:
            continue
        if (
            case["credentialRole"] is not None
            and case["credentialRole"] not in role_refs
        ):
            continue
        if (
            case["originClass"] is not None
            and case["originClass"] not in origin_classes
        ):
            continue
        compiled_case = dict(case)
        compiled_case["credentialRef"] = (
            role_refs.get(case["credentialRole"])
            if case["credentialRole"] is not None
            else None
        )
        cases.append(compiled_case)
        covered.add(case["check"])
    if covered != selected_checks:
        missing = sorted(selected_checks - covered)
        raise WebSecurityError(f"no applicable adapter cases for: {', '.join(missing)}")
    if len(cases) > profile["limits"]["maxCases"]:
        raise WebSecurityError("applicable adapter cases exceed profile maxCases")

    authorization_state = "not-required"
    blockers: list[str] = []
    if profile["executionClass"] == "approved_target":
        authorization_state = "ready"
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise WebSecurityError("now must be timezone-aware")
        current = current.astimezone(timezone.utc)
        start = _timestamp(
            profile["authorization"]["notBefore"],
            "$.authorization.notBefore",
        )
        end = _timestamp(
            profile["authorization"]["notAfter"],
            "$.authorization.notAfter",
        )
        if current < start:
            authorization_state = "blocked"
            blockers.append("authorization-window-not-started")
        elif current >= end:
            authorization_state = "blocked"
            blockers.append("authorization-window-expired")
    return {
        "apiVersion": PLAN_VERSION,
        "networkActivity": False,
        "executionClass": profile["executionClass"],
        "adapter": dict(profile["adapter"]),
        "authorization": {
            "state": authorization_state,
            "reference": profile["authorization"]["reference"],
            "surfaces": list(profile["authorization"]["surfaces"]),
            "blockers": blockers,
        },
        "destinations": [dict(item) for item in profile["destinations"]],
        "cases": cases,
        "limits": dict(profile["limits"]),
        "arbitraryRequestsAvailable": False,
    }


def _read(path: str) -> Any:
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise WebSecurityError(f"input must be a regular non-symlink file: {path}")
    if candidate.stat().st_size > MAX_INPUT_BYTES:
        raise WebSecurityError(f"input exceeds {MAX_INPUT_BYTES} bytes: {path}")
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WebSecurityError(f"cannot read JSON input {path}: {exc}") from exc


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="web-security-profile",
        description="Compile a bounded admin/WebSocket security plan offline.",
    )
    parser.add_argument("profile")
    parser.add_argument("adapter")
    parser.add_argument(
        "--now",
        help="UTC RFC3339 evaluation time (for deterministic review)",
    )
    parsed = parser.parse_args(arguments)
    try:
        now = _timestamp(parsed.now, "--now") if parsed.now else None
        plan = compile_plan(_read(parsed.profile), _read(parsed.adapter), now=now)
    except WebSecurityError as exc:
        print(f"Web security profile rejected: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0 if plan["authorization"]["state"] != "blocked" else 3


if __name__ == "__main__":
    raise SystemExit(main())
