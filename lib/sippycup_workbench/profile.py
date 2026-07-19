"""Target profiles and network-free readiness compilation."""

from __future__ import annotations

import ipaddress
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from . import PROFILE_VERSION

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,63}$")
_SAFE_HOST = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")
_TRANSPORTS = {"udp", "tcp", "tls"}
_TOP_LEVEL_FIELDS = {
    "schema_version",
    "name",
    "target",
    "authorization",
    "limits",
    "capture",
    "features",
}
_SECTION_FIELDS = {
    "target": {"host", "port", "transport", "approved_addresses"},
    "authorization": {
        "status",
        "approved_by",
        "approval_id",
        "valid_from",
        "valid_until",
    },
    "limits": {
        "max_calls",
        "max_concurrency",
        "max_calls_per_second",
        "max_duration_seconds",
    },
    "capture": {"interface", "output"},
    "features": {"ice", "turn", "srtp", "dtls_srtp", "webrtc"},
}


class ProfileError(ValueError):
    """A target profile cannot be safely interpreted."""


@dataclass(frozen=True)
class Rehearsal:
    ready: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    facts: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "sippycup.dev/rehearsal/v1",
            "ready": self.ready,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "facts": self.facts,
            "network_activity": False,
        }


def default_profile(
    *,
    name: str,
    host: str,
    port: int = 5060,
    transport: str = "udp",
    approved_by: str = "Quad",
) -> dict[str, Any]:
    return {
        "schema_version": PROFILE_VERSION,
        "name": name,
        "target": {
            "host": host,
            "port": port,
            "transport": transport,
            "approved_addresses": [],
        },
        "authorization": {
            "status": "pending",
            "approved_by": approved_by,
            "approval_id": "",
            "valid_from": None,
            "valid_until": None,
        },
        "limits": {
            "max_calls": 1,
            "max_concurrency": 1,
            "max_calls_per_second": 1,
            "max_duration_seconds": 120,
        },
        "capture": {
            "interface": "any",
            "output": "work/call.pcap",
        },
        "features": {
            "ice": False,
            "turn": False,
            "srtp": False,
            "dtls_srtp": False,
            "webrtc": False,
        },
    }


def write_profile(path: str | Path, profile: dict[str, Any], *, force: bool) -> None:
    destination = Path(path)
    if destination.exists() and not force:
        raise ProfileError(f"profile already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    rendered = yaml.safe_dump(
        profile, sort_keys=False, default_flow_style=False
    )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
        if force:
            os.replace(temporary, destination)
        else:
            try:
                os.link(temporary, destination)
            except FileExistsError as exc:
                raise ProfileError(f"profile already exists: {destination}") from exc
        destination.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def load_profile(path: str | Path) -> dict[str, Any]:
    try:
        document = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ProfileError(f"cannot read profile: {exc}") from exc
    if not isinstance(document, dict):
        raise ProfileError("profile must be a YAML object")
    return document


def _mapping(document: dict[str, Any], key: str) -> dict[str, Any]:
    value = document.get(key)
    if not isinstance(value, dict):
        raise ProfileError(f"{key} must be an object")
    return value


def _parse_time(value: Any, field: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ProfileError(f"{field} must be an RFC 3339 timestamp or null")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProfileError(f"{field} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ProfileError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def rehearse(document: dict[str, Any], *, now: datetime | None = None) -> Rehearsal:
    errors: list[str] = []
    warnings: list[str] = []
    facts: dict[str, Any] = {}
    if document.get("schema_version") != PROFILE_VERSION:
        errors.append("unsupported or missing schema_version")
    unknown_top = set(document) - _TOP_LEVEL_FIELDS
    if unknown_top:
        errors.append(f"unknown top-level fields: {', '.join(sorted(unknown_top))}")

    name = document.get("name")
    if not isinstance(name, str) or _SAFE_NAME.fullmatch(name) is None:
        errors.append("name must be 1-64 safe display characters")

    try:
        target = _mapping(document, "target")
        authorization = _mapping(document, "authorization")
        limits = _mapping(document, "limits")
        capture = _mapping(document, "capture")
        features = _mapping(document, "features")
    except ProfileError as exc:
        return Rehearsal(False, (str(exc),), (), {"network_activity": False})
    sections = {
        "target": target,
        "authorization": authorization,
        "limits": limits,
        "capture": capture,
        "features": features,
    }
    for section_name, section in sections.items():
        unknown = set(section) - _SECTION_FIELDS[section_name]
        if unknown:
            errors.append(
                f"unknown {section_name} fields: {', '.join(sorted(unknown))}"
            )

    host = target.get("host")
    if not isinstance(host, str) or _SAFE_HOST.fullmatch(host) is None or host.startswith("-"):
        errors.append("target.host is invalid")
    port = target.get("port")
    if type(port) is not int or not 1 <= port <= 65535:
        errors.append("target.port must be an integer from 1 to 65535")
    transport = target.get("transport")
    if transport not in _TRANSPORTS:
        errors.append("target.transport must be udp, tcp, or tls")

    approved_addresses = target.get("approved_addresses")
    if not isinstance(approved_addresses, list):
        errors.append("target.approved_addresses must be a list")
        approved_addresses = []
    else:
        for address in approved_addresses:
            try:
                ipaddress.ip_address(address)
            except (TypeError, ValueError):
                errors.append("approved_addresses must contain only literal IP addresses")
                break
        if len(set(approved_addresses)) != len(approved_addresses):
            errors.append("approved_addresses must be unique")

    status = authorization.get("status")
    if status not in {"pending", "approved", "revoked", "expired"}:
        errors.append("authorization.status is invalid")
    approval_id = authorization.get("approval_id")
    if not isinstance(approval_id, str):
        errors.append("authorization.approval_id must be a string")
        approval_id = ""
    if status == "approved" and not approval_id:
        errors.append("approved profiles require authorization.approval_id")
    approved_by = authorization.get("approved_by")
    if not isinstance(approved_by, str) or not approved_by.strip():
        errors.append("authorization.approved_by must be a non-empty string")
    if status != "approved":
        errors.append(f"authorization is {status or 'missing'}, not approved")
    if not approved_addresses:
        errors.append("at least one literal approved address is required")

    try:
        valid_from = _parse_time(authorization.get("valid_from"), "authorization.valid_from")
        valid_until = _parse_time(authorization.get("valid_until"), "authorization.valid_until")
    except ProfileError as exc:
        errors.append(str(exc))
        valid_from = valid_until = None
    instant = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if valid_from and instant < valid_from:
        errors.append("authorization is not valid yet")
    if valid_until and instant >= valid_until:
        errors.append("authorization has expired")
    if status == "approved" and valid_until is None:
        errors.append("approved profiles require authorization.valid_until")
    if valid_from and valid_until and valid_from >= valid_until:
        errors.append("authorization.valid_from must precede valid_until")

    integer_limits = {
        "max_calls": 1,
        "max_concurrency": 1,
        "max_calls_per_second": 1,
        "max_duration_seconds": 1,
    }
    for field, minimum in integer_limits.items():
        value = limits.get(field)
        if type(value) is not int or value < minimum:
            errors.append(f"limits.{field} must be an integer >= {minimum}")
    if (
        type(limits.get("max_concurrency")) is int
        and type(limits.get("max_calls")) is int
        and limits["max_concurrency"] > limits["max_calls"]
    ):
        errors.append("max_concurrency cannot exceed max_calls")
    if limits.get("max_calls") != 1 or limits.get("max_concurrency") != 1:
        warnings.append("this is not a one-call profile")

    interface = capture.get("interface")
    if (
        not isinstance(interface, str)
        or not interface
        or interface.startswith("-")
        or re.fullmatch(r"[A-Za-z0-9_.:-]+", interface) is None
    ):
        errors.append("capture.interface is invalid")
    output = capture.get("output")
    if not isinstance(output, str) or not output:
        errors.append("capture.output is required")
    elif (
        not output.startswith("work/")
        or Path(output).is_absolute()
        or ".." in Path(output).parts
        or Path(output).suffix.lower() not in {".pcap", ".pcapng"}
    ):
        errors.append("capture.output must be a relative work/*.pcap or work/*.pcapng path")

    known_features = _SECTION_FIELDS["features"]
    unknown_features = set(features) - known_features
    if unknown_features:
        errors.append(f"unknown features: {', '.join(sorted(unknown_features))}")
    for field in known_features & set(features):
        if type(features[field]) is not bool:
            errors.append(f"features.{field} must be boolean")
    if features.get("turn") and not features.get("ice"):
        warnings.append("TURN is enabled without ICE; confirm this is intentional")
    if features.get("dtls_srtp") and not features.get("srtp"):
        errors.append("DTLS-SRTP requires features.srtp")

    facts.update(
        {
            "profile_name": name,
            "target": {
                "host": host,
                "port": port,
                "transport": transport,
                "approved_addresses": approved_addresses,
            },
            "authorization": {
                "status": status,
                "approved_by": authorization.get("approved_by"),
                "approval_id_present": bool(approval_id),
                "valid_from": valid_from.isoformat() if valid_from else None,
                "valid_until": valid_until.isoformat() if valid_until else None,
            },
            "limits": limits,
            "capture": capture,
            "features": features,
            "maximum_preflight_transactions": 1,
            "network_activity": False,
        }
    )
    return Rehearsal(not errors, tuple(errors), tuple(warnings), facts)
