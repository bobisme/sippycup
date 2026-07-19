#!/usr/bin/env python3
"""Fail-closed compiler for sippycup campaign manifests."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

try:
    import yaml
except ImportError:  # pragma: no cover - exercised by installation smoke tests
    yaml = None


API_VERSION = "sippycup.dev/v1"
KIND = "Campaign"
U64_MAX = (1 << 64) - 1
MAX_PLAN_STEPS = 100_000
SUPPORTED_TRANSPORTS = {"udp", "tcp", "tls"}
CASE_EXPECTATIONS_VERSION = "sippycup.dev/case-expectations/v1"
MATRIX_FACTORS = (
    "transport",
    "addressFamily",
    "codec",
    "ptime",
    "mediaProtection",
    "dtmf",
    "earlyMedia",
    "holdReinvite",
    "teardownInitiator",
    "duration",
    "nat",
    "impairment",
)
MATRIX_ENUMS = {
    "transport": {"udp", "tcp", "tls"},
    "addressFamily": {"ipv4", "ipv6"},
    "codec": {"pcmu", "pcma", "g722", "opus"},
    "mediaProtection": {"plain", "sdes-srtp", "dtls-srtp"},
    "dtmf": {"rfc4733", "sip-info", "inband", "none"},
    "earlyMedia": {"disabled", "183-sdp", "reliable"},
    "holdReinvite": {"disabled", "sendonly", "inactive"},
    "teardownInitiator": {"caller", "callee", "timeout"},
    "nat": {"none", "endpoint-nat", "symmetric-nat"},
    "impairment": {"none", "loss", "jitter", "latency", "reorder", "duplicate"},
}
MATRIX_NUMERIC_DOMAINS = {
    "ptime": ({10, 20, 30, 40, 60}, "one of 10, 20, 30, 40, or 60"),
    "duration": (range(1, 3601), "an integer between 1 and 3600 seconds"),
}
MAX_MATRIX_DOMAIN = 32
MAX_SAT_STATES = 1_000_000
MATRIX_ACTIONS = {"dtmf", "hold", "resume", "reinvite", "failure", "recover", "hangup"}
CEILING_KEYS = (
    "calls",
    "packets",
    "bytes",
    "durationSeconds",
    "concurrentCalls",
    "packetsPerSecond",
    "callsPerSecond",
)
PLACEHOLDER_WORDS = re.compile(
    r"(^|[._-])(change[-_]?me|example|placeholder|todo|tbd)([._-]|$)", re.I
)
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


class ManifestError(ValueError):
    """An authorization or schema error suitable for command-line display."""


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(f"{field} must be a mapping")
    return value


def _list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list) or not value:
        raise ManifestError(f"{field} must be a non-empty list")
    return value


def _unique_list(value: Any, field: str) -> list[Any]:
    result = _list(value, field)
    for index, item in enumerate(result):
        if item in result[:index]:
            raise ManifestError(f"{field} contains duplicate value {item!r}")
    return result


def _keys(value: dict[str, Any], field: str, allowed: set[str]) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ManifestError(f"{field} contains unsupported fields: {', '.join(unknown)}")


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(f"{field} must be a non-empty string")
    return value.strip()


def _uint(value: Any, field: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int):
        raise ManifestError(f"{field} must be an integer")
    if value < minimum or value > U64_MAX:
        raise ManifestError(f"{field} must be between {minimum} and {U64_MAX}")
    return value


def _checked_add(left: int, right: int, field: str) -> int:
    if left > U64_MAX - right:
        raise ManifestError(f"arithmetic overflow while calculating {field}")
    return left + right


def _checked_mul(left: int, right: int, field: str) -> int:
    if left and right > U64_MAX // left:
        raise ManifestError(f"arithmetic overflow while calculating {field}")
    return left * right


def _is_placeholder(value: str) -> bool:
    lowered = value.lower().rstrip(".")
    if lowered.endswith(".invalid") or lowered in {
        "example.com",
        "example.net",
        "example.org",
        "localhost",
    }:
        return True
    if PLACEHOLDER_WORDS.search(lowered):
        return True
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    return any(address in network for network in DOCUMENTATION_NETWORKS)


def _name(value: Any, field: str) -> str:
    result = _string(value, field)
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", result):
        raise ManifestError(f"{field} must match [a-z][a-z0-9-]{{0,62}}")
    return result


def load_manifest(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if yaml is None:
        raise ManifestError(
            "PyYAML is required; install python3-yaml or PyYAML before using campaign"
        )
    try:
        value = yaml.safe_load(raw)
    except yaml.YAMLError as error:
        raise ManifestError(f"invalid YAML: {error}") from error
    return _mapping(value, "manifest"), digest


def _parse_overrides(values: list[str]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for item in values:
        if "=" not in item:
            raise ManifestError(f"resolution override must be HOST=IP, got {item!r}")
        host, raw_address = item.split("=", 1)
        host = host.lower().rstrip(".")
        _string(host, "resolution host")
        try:
            address = str(ipaddress.ip_address(raw_address))
        except ValueError as error:
            raise ManifestError(f"invalid resolution address {raw_address!r}") from error
        result.setdefault(host, []).append(address)
    return result


def _parse_assignments(values: list[str], option: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in values:
        if "=" not in item:
            raise ManifestError(f"{option} must be REF=VALUE, got {item!r}")
        reference, value = item.split("=", 1)
        reference = _name(reference, f"{option} reference")
        if reference in result:
            raise ManifestError(f"{option} repeats credential reference {reference!r}")
        result[reference] = _string(value, f"{option} value")
    return result


def system_resolver(host: str) -> list[str]:
    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM)
    except socket.gaierror as error:
        raise ManifestError(f"DNS resolution failed for {host!r}: {error}") from error
    return sorted({answer[4][0] for answer in answers}, key=_address_sort_key)


def _address_sort_key(value: str) -> tuple[int, int]:
    address = ipaddress.ip_address(value)
    return address.version, int(address)


def _validate_ceilings(value: Any) -> dict[str, int]:
    ceilings = _mapping(value, "authorization.ceilings")
    _keys(ceilings, "authorization.ceilings", set(CEILING_KEYS))
    missing = [key for key in CEILING_KEYS if key not in ceilings]
    if missing:
        raise ManifestError(
            "authorization.ceilings is missing required fields: " + ", ".join(missing)
        )
    return {key: _uint(ceilings[key], f"authorization.ceilings.{key}") for key in CEILING_KEYS}


def _apply_reductions(
    ceilings: dict[str, int], reductions: dict[str, int | None]
) -> dict[str, int]:
    result = dict(ceilings)
    for key, value in reductions.items():
        if value is None:
            continue
        reduced = _uint(value, f"--max-{key}")
        if reduced > ceilings[key]:
            raise ManifestError(
                f"override for {key} ({reduced}) exceeds authorized maximum "
                f"({ceilings[key]}); overrides may only reduce authorization"
            )
        result[key] = reduced
    return result


def _case_expectations(value: Any, field: str) -> dict[str, Any]:
    expectations = _mapping(value, field)
    _keys(
        expectations,
        field,
        {
            "apiVersion",
            "finalStatus",
            "allowedProvisionalStatuses",
            "requireBidirectionalRtp",
            "maxSetupSeconds",
        },
    )
    if expectations.get("apiVersion") != CASE_EXPECTATIONS_VERSION:
        raise ManifestError(
            f"{field}.apiVersion must be {CASE_EXPECTATIONS_VERSION!r}"
        )
    result: dict[str, Any] = {"apiVersion": CASE_EXPECTATIONS_VERSION}
    if "finalStatus" in expectations:
        status = _uint(expectations["finalStatus"], f"{field}.finalStatus")
        if status < 200 or status > 699:
            raise ManifestError(f"{field}.finalStatus must be between 200 and 699")
        result["finalStatus"] = status
    if "allowedProvisionalStatuses" in expectations:
        provisional = [
            _uint(item, f"{field}.allowedProvisionalStatuses[{index}]")
            for index, item in enumerate(
                _unique_list(
                    expectations["allowedProvisionalStatuses"],
                    f"{field}.allowedProvisionalStatuses",
                )
            )
        ]
        if any(status < 100 or status > 199 for status in provisional):
            raise ManifestError(
                f"{field}.allowedProvisionalStatuses values must be between 100 and 199"
            )
        result["allowedProvisionalStatuses"] = sorted(provisional)
    if "requireBidirectionalRtp" in expectations:
        bidirectional = expectations["requireBidirectionalRtp"]
        if not isinstance(bidirectional, bool):
            raise ManifestError(f"{field}.requireBidirectionalRtp must be a boolean")
        result["requireBidirectionalRtp"] = bidirectional
    if "maxSetupSeconds" in expectations:
        result["maxSetupSeconds"] = _uint(
            expectations["maxSetupSeconds"], f"{field}.maxSetupSeconds"
        )
    return result


def _matrix_value(value: Any, factor: str, field: str) -> str | int:
    if factor in MATRIX_ENUMS:
        result = _string(value, field)
        if result not in MATRIX_ENUMS[factor]:
            choices = ", ".join(sorted(MATRIX_ENUMS[factor]))
            raise ManifestError(f"{field} has unsupported value {result!r}; choose from {choices}")
        return result
    allowed, description = MATRIX_NUMERIC_DOMAINS[factor]
    if isinstance(value, bool) or not isinstance(value, int) or value not in allowed:
        raise ManifestError(f"{field} must be {description}")
    return value


def _matrix_predicate(
    value: Any,
    field: str,
    domains: dict[str, list[str | int]],
) -> dict[str, list[str | int]]:
    predicate = _mapping(value, field)
    if not predicate:
        raise ManifestError(f"{field} must reference at least one factor")
    unknown = sorted(set(predicate) - set(domains))
    if unknown:
        raise ManifestError(
            f"{field} references unsupported factor(s): {', '.join(unknown)}"
        )
    normalized: dict[str, list[str | int]] = {}
    for factor in sorted(predicate):
        raw = predicate[factor]
        values = raw if isinstance(raw, list) else [raw]
        if not values:
            raise ManifestError(f"{field}.{factor} must select at least one value")
        selected: list[str | int] = []
        for index, item in enumerate(values):
            parsed = _matrix_value(item, factor, f"{field}.{factor}[{index}]")
            if parsed in selected:
                raise ManifestError(
                    f"{field}.{factor} contains duplicate value {parsed!r}"
                )
            if parsed not in domains[factor]:
                raise ManifestError(
                    f"{field}.{factor} selects {parsed!r}, outside its declared domain"
                )
            selected.append(parsed)
        normalized[factor] = sorted(selected, key=lambda item: (str(type(item)), item))
    return normalized


def _predicate_state(
    predicate: dict[str, list[str | int]],
    assignment: dict[str, str | int],
) -> bool | None:
    unknown = False
    for factor, allowed in predicate.items():
        if factor not in assignment:
            unknown = True
        elif assignment[factor] not in allowed:
            return False
    return None if unknown else True


def _constraint_allows(
    constraint: dict[str, Any],
    assignment: dict[str, str | int],
) -> bool:
    if "require" in constraint:
        return _predicate_state(constraint["require"], assignment) is not False
    if "exclude" in constraint:
        return _predicate_state(constraint["exclude"], assignment) is not True
    antecedent = _predicate_state(constraint["if"], assignment)
    consequent = _predicate_state(constraint["then"], assignment)
    return not (antecedent is True and consequent is False)


def _matrix_satisfiable(
    domains: dict[str, list[str | int]],
    constraints: list[dict[str, Any]],
) -> bool:
    ordered = sorted(domains, key=lambda factor: (len(domains[factor]), factor))
    assignment: dict[str, str | int] = {}
    states = 0

    def search(index: int) -> bool:
        nonlocal states
        states += 1
        if states > MAX_SAT_STATES:
            raise ManifestError(
                f"matrix satisfiability search exceeds {MAX_SAT_STATES} states; "
                "reduce domains or add pruning constraints"
            )
        if not all(_constraint_allows(item, assignment) for item in constraints):
            return False
        if index == len(ordered):
            return True
        factor = ordered[index]
        for item in domains[factor]:
            assignment[factor] = item
            if search(index + 1):
                return True
        assignment.pop(factor, None)
        return False

    return search(0)


def _minimal_unsat_core(
    domains: dict[str, list[str | int]],
    constraints: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    core = list(constraints)
    index = 0
    while index < len(core):
        candidate = core[:index] + core[index + 1 :]
        if not _matrix_satisfiable(domains, candidate):
            core = candidate
        else:
            index += 1
    return core


def _validate_matrix(
    value: Any,
    authorized_transports: set[str],
) -> dict[str, Any]:
    matrix = _mapping(value, "matrix")
    _keys(
        matrix,
        "matrix",
        {
            "factors",
            "constraints",
            "mandatoryCases",
            "interactionStrength",
            "riskWeights",
        },
    )
    raw_factors = _mapping(matrix.get("factors"), "matrix.factors")
    missing = sorted(set(MATRIX_FACTORS) - set(raw_factors))
    unsupported = sorted(set(raw_factors) - set(MATRIX_FACTORS))
    if missing:
        raise ManifestError("matrix.factors is missing required factors: " + ", ".join(missing))
    if unsupported:
        raise ManifestError(
            "matrix.factors contains unsupported factors: " + ", ".join(unsupported)
        )
    domains: dict[str, list[str | int]] = {}
    for factor in MATRIX_FACTORS:
        raw_domain = _unique_list(raw_factors[factor], f"matrix.factors.{factor}")
        if len(raw_domain) > MAX_MATRIX_DOMAIN:
            raise ManifestError(
                f"matrix.factors.{factor} exceeds the {MAX_MATRIX_DOMAIN}-value domain limit"
            )
        domains[factor] = sorted(
            (
                _matrix_value(item, factor, f"matrix.factors.{factor}[{index}]")
                for index, item in enumerate(raw_domain)
            ),
            key=lambda item: (str(type(item)), item),
        )
    unauthorized = sorted(set(domains["transport"]) - authorized_transports)
    if unauthorized:
        raise ManifestError(
            "matrix.factors.transport contains unauthorized transports: "
            + ", ".join(unauthorized)
        )

    raw_constraints = matrix.get("constraints", [])
    if not isinstance(raw_constraints, list):
        raise ManifestError("matrix.constraints must be a list")
    constraints: list[dict[str, Any]] = []
    constraint_ids: set[str] = set()
    for index, raw in enumerate(raw_constraints):
        field = f"matrix.constraints[{index}]"
        item = _mapping(raw, field)
        _keys(item, field, {"id", "require", "exclude", "if", "then", "rationale"})
        identifier = _name(item.get("id"), f"{field}.id")
        if identifier in constraint_ids:
            raise ManifestError(f"duplicate matrix constraint id {identifier!r}")
        constraint_ids.add(identifier)
        forms = (
            "require" in item,
            "exclude" in item,
            "if" in item or "then" in item,
        )
        if sum(forms) != 1 or (forms[2] and not ("if" in item and "then" in item)):
            raise ManifestError(
                f"{field} must contain exactly one logical form: require, exclude, "
                "or both if and then"
            )
        normalized: dict[str, Any] = {"id": identifier}
        for key in ("require", "exclude", "if", "then"):
            if key in item:
                normalized[key] = _matrix_predicate(item[key], f"{field}.{key}", domains)
        if "rationale" in item:
            normalized["rationale"] = _string(item["rationale"], f"{field}.rationale")
        constraints.append(normalized)
    constraints.sort(key=lambda item: item["id"])

    if not _matrix_satisfiable(domains, constraints):
        core = _minimal_unsat_core(domains, constraints)
        raise ManifestError(
            "matrix constraints are unsatisfiable; minimal conflicting constraint "
            "set: " + ", ".join(item["id"] for item in core)
        )

    raw_mandatory = matrix.get("mandatoryCases", [])
    if not isinstance(raw_mandatory, list):
        raise ManifestError("matrix.mandatoryCases must be a list")
    mandatory: list[dict[str, Any]] = []
    mandatory_ids: set[str] = set()
    for index, raw in enumerate(raw_mandatory):
        field = f"matrix.mandatoryCases[{index}]"
        item = _mapping(raw, field)
        _keys(item, field, {"id", "values", "rationale"})
        identifier = _name(item.get("id"), f"{field}.id")
        if identifier in mandatory_ids:
            raise ManifestError(f"duplicate mandatory case id {identifier!r}")
        mandatory_ids.add(identifier)
        raw_values = _mapping(item.get("values"), f"{field}.values")
        missing_values = sorted(set(domains) - set(raw_values))
        extra_values = sorted(set(raw_values) - set(domains))
        if missing_values or extra_values:
            details = []
            if missing_values:
                details.append("missing " + ", ".join(missing_values))
            if extra_values:
                details.append("unsupported " + ", ".join(extra_values))
            raise ManifestError(f"{field}.values must assign every factor ({'; '.join(details)})")
        assignment = {
            factor: _matrix_predicate(
                {factor: raw_values[factor]},
                f"{field}.values",
                domains,
            )[factor][0]
            for factor in MATRIX_FACTORS
        }
        violated = [
            constraint["id"]
            for constraint in constraints
            if not _constraint_allows(constraint, assignment)
        ]
        if violated:
            raise ManifestError(
                f"mandatory case {identifier!r} violates constraint(s): "
                + ", ".join(violated)
            )
        normalized_case: dict[str, Any] = {"id": identifier, "values": assignment}
        if "rationale" in item:
            normalized_case["rationale"] = _string(
                item["rationale"], f"{field}.rationale"
            )
        mandatory.append(normalized_case)
    mandatory.sort(key=lambda item: item["id"])

    strength = _uint(
        matrix.get("interactionStrength", 2), "matrix.interactionStrength"
    )
    if strength > len(MATRIX_FACTORS):
        raise ManifestError(
            f"matrix.interactionStrength must be between 1 and {len(MATRIX_FACTORS)}"
        )

    raw_risks = matrix.get("riskWeights", [])
    if not isinstance(raw_risks, list):
        raise ManifestError("matrix.riskWeights must be a list")
    risks: list[dict[str, Any]] = []
    risk_ids: set[str] = set()
    for index, raw in enumerate(raw_risks):
        field = f"matrix.riskWeights[{index}]"
        item = _mapping(raw, field)
        _keys(
            item,
            field,
            {
                "id",
                "when",
                "weight",
                "rationale",
                "coveringFactors",
                "interactionStrength",
            },
        )
        identifier = _name(item.get("id"), f"{field}.id")
        if identifier in risk_ids:
            raise ManifestError(f"duplicate risk weight id {identifier!r}")
        risk_ids.add(identifier)
        risk = {
            "id": identifier,
            "when": _matrix_predicate(item.get("when"), f"{field}.when", domains),
            "weight": _uint(item.get("weight"), f"{field}.weight"),
            "rationale": _string(item.get("rationale"), f"{field}.rationale"),
        }
        has_factors = "coveringFactors" in item
        has_strength = "interactionStrength" in item
        if has_factors != has_strength:
            raise ManifestError(
                f"{field} must provide coveringFactors and interactionStrength together"
            )
        if has_factors:
            selected = [
                _string(value, f"{field}.coveringFactors[{index}]")
                for index, value in enumerate(
                    _unique_list(item["coveringFactors"], f"{field}.coveringFactors")
                )
            ]
            unknown = sorted(set(selected) - set(domains))
            if unknown:
                raise ManifestError(
                    f"{field}.coveringFactors references unsupported factor(s): "
                    + ", ".join(unknown)
                )
            selected = sorted(selected)
            risk_strength = _uint(
                item["interactionStrength"], f"{field}.interactionStrength"
            )
            if risk_strength <= strength or risk_strength > len(selected):
                raise ManifestError(
                    f"{field}.interactionStrength must be greater than the matrix "
                    f"strength ({strength}) and no greater than its "
                    f"{len(selected)} coveringFactors"
                )
            risk["coveringFactors"] = selected
            risk["interactionStrength"] = risk_strength
        risks.append(risk)
    risks.sort(key=lambda item: item["id"])
    return {
        "factors": domains,
        "constraints": constraints,
        "mandatoryCases": mandatory,
        "interactionStrength": strength,
        "riskWeights": risks,
    }


def _validate_generated_case(
    value: Any,
    matrix: dict[str, Any],
    field: str,
) -> dict[str, Any]:
    generated = _mapping(value, field)
    _keys(generated, field, {"row", "sequence", "factors", "actions"})
    row = _uint(generated.get("row"), f"{field}.row")
    sequence = _uint(generated.get("sequence"), f"{field}.sequence")
    raw_factors = _mapping(generated.get("factors"), f"{field}.factors")
    if set(raw_factors) != set(matrix["factors"]):
        raise ManifestError(f"{field}.factors must assign every matrix factor exactly")
    factors = {
        factor: _matrix_predicate(
            {factor: raw_factors[factor]},
            f"{field}.factors",
            matrix["factors"],
        )[factor][0]
        for factor in MATRIX_FACTORS
    }
    violated = [
        constraint["id"]
        for constraint in matrix["constraints"]
        if not _constraint_allows(constraint, factors)
    ]
    if violated:
        raise ManifestError(f"{field}.factors violates: " + ", ".join(violated))
    actions = [
        _string(item, f"{field}.actions[{index}]")
        for index, item in enumerate(_list(generated.get("actions"), f"{field}.actions"))
    ]
    if any(item not in MATRIX_ACTIONS for item in actions):
        raise ManifestError(f"{field}.actions contains an unsupported action")
    if actions[-1] != "hangup" or "hangup" in actions[:-1]:
        raise ManifestError(f"{field}.actions must end with one terminal hangup")
    held = failed = False
    for action in actions[:-1]:
        if failed:
            if action != "recover":
                raise ManifestError(f"{field}.actions requires recovery after failure")
            failed = False
        elif action == "hold":
            if held:
                raise ManifestError(f"{field}.actions cannot hold an already held call")
            held = True
        elif action == "resume":
            if not held:
                raise ManifestError(f"{field}.actions resume requires a prior hold")
            held = False
        elif action == "failure":
            failed = True
        elif action == "recover":
            raise ManifestError(f"{field}.actions recover requires a prior failure")
    return {
        "row": row,
        "sequence": sequence,
        "factors": factors,
        "actions": actions,
    }


def compile_plan(
    manifest: dict[str, Any],
    digest: str,
    *,
    resolver: Callable[[str], list[str]] = system_resolver,
    reductions: dict[str, int | None] | None = None,
) -> dict[str, Any]:
    """Validate and resolve a manifest, returning a deterministic frozen plan."""
    _keys(manifest, "manifest", {"apiVersion", "kind", "metadata", "authorization", "targets", "cases", "expectations", "evidence", "matrix"})
    if manifest.get("apiVersion") != API_VERSION:
        raise ManifestError(f"apiVersion must be {API_VERSION!r}")
    if manifest.get("kind") != KIND:
        raise ManifestError(f"kind must be {KIND!r}")

    metadata = _mapping(manifest.get("metadata"), "metadata")
    _keys(metadata, "metadata", {"name"})
    campaign_name = _name(metadata.get("name"), "metadata.name")

    authorization = _mapping(manifest.get("authorization"), "authorization")
    _keys(
        authorization,
        "authorization",
        {
            "networks",
            "signalingPorts",
            "mediaPorts",
            "transports",
            "credentialRefs",
            "ceilings",
            "stopConditions",
        },
    )
    raw_networks = _unique_list(
        authorization.get("networks"), "authorization.networks"
    )
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for index, value in enumerate(raw_networks):
        text = _string(value, f"authorization.networks[{index}]")
        try:
            network = ipaddress.ip_network(text, strict=True)
        except ValueError as error:
            raise ManifestError(f"invalid approved network {text!r}: {error}") from error
        if any(
            network.version == documentation.version
            and network.subnet_of(documentation)
            for documentation in DOCUMENTATION_NETWORKS
        ):
            raise ManifestError(f"documentation-only network {text!r} is a placeholder")
        networks.append(network)
    networks.sort(key=lambda item: (item.version, int(item.network_address), item.prefixlen))

    signaling_ports = {
        _uint(value, f"authorization.signalingPorts[{index}]")
        for index, value in enumerate(
            _unique_list(
                authorization.get("signalingPorts"),
                "authorization.signalingPorts",
            )
        )
    }
    if any(port > 65535 for port in signaling_ports):
        raise ManifestError("signaling ports must be between 1 and 65535")

    media = _mapping(authorization.get("mediaPorts"), "authorization.mediaPorts")
    _keys(media, "authorization.mediaPorts", {"start", "end"})
    media_start = _uint(media.get("start"), "authorization.mediaPorts.start")
    media_end = _uint(media.get("end"), "authorization.mediaPorts.end")
    if media_start > media_end or media_end > 65535:
        raise ManifestError("authorization.mediaPorts must be an ordered range within 1..65535")

    transports = {
        _string(value, f"authorization.transports[{index}]")
        for index, value in enumerate(
            _unique_list(
                authorization.get("transports"), "authorization.transports"
            )
        )
    }
    unsupported = sorted(transports - SUPPORTED_TRANSPORTS)
    if unsupported:
        raise ManifestError("unsupported transports: " + ", ".join(unsupported))
    matrix = (
        _validate_matrix(manifest["matrix"], transports)
        if "matrix" in manifest
        else None
    )

    credential_refs = {
        _name(value, f"authorization.credentialRefs[{index}]")
        for index, value in enumerate(
            _unique_list(authorization.get("credentialRefs", []), "authorization.credentialRefs")
            if authorization.get("credentialRefs", [])
            else []
        )
    }
    ceilings = _validate_ceilings(authorization.get("ceilings"))
    ceilings = _apply_reductions(ceilings, reductions or {})

    stops = _mapping(authorization.get("stopConditions"), "authorization.stopConditions")
    _keys(
        stops,
        "authorization.stopConditions",
        {"consecutiveFailures", "unexpectedResponse", "packetLossPercent"},
    )
    stop_conditions = {
        "consecutiveFailures": _uint(
            stops.get("consecutiveFailures"), "stopConditions.consecutiveFailures"
        ),
        "unexpectedResponse": stops.get("unexpectedResponse"),
        "packetLossPercent": stops.get("packetLossPercent"),
    }
    if not isinstance(stop_conditions["unexpectedResponse"], bool):
        raise ManifestError("stopConditions.unexpectedResponse must be a boolean")
    loss = stop_conditions["packetLossPercent"]
    if isinstance(loss, bool) or not isinstance(loss, (int, float)) or not 0 <= loss <= 100:
        raise ManifestError("stopConditions.packetLossPercent must be between 0 and 100")

    targets: dict[str, dict[str, Any]] = {}
    destinations: list[dict[str, Any]] = []
    assumptions: list[str] = []
    resolution_pins: dict[str, list[str]] = {}
    for index, raw_target in enumerate(_list(manifest.get("targets"), "targets")):
        target = _mapping(raw_target, f"targets[{index}]")
        _keys(target, f"targets[{index}]", {"name", "address", "signaling", "credentialRef"})
        target_name = _name(target.get("name"), f"targets[{index}].name")
        if target_name in targets:
            raise ManifestError(f"duplicate target name {target_name!r}")
        host = _string(target.get("address"), f"targets[{index}].address").lower().rstrip(".")
        if _is_placeholder(host):
            raise ManifestError(f"target address {host!r} is a placeholder")
        try:
            literal = ipaddress.ip_address(host)
            answers = [str(literal)]
        except ValueError:
            answers = sorted(set(resolver(host)), key=_address_sort_key)
            resolution_pins[host] = answers
            assumptions.append(
                f"DNS for {host} is frozen to {', '.join(answers)} for this plan"
            )
        if not answers:
            raise ManifestError(f"target {host!r} resolved to no addresses")
        for answer in answers:
            address = ipaddress.ip_address(answer)
            if not any(address in network for network in networks):
                raise ManifestError(
                    f"target {host!r} resolved to {answer}, outside approved networks"
                )

        signaling = _mapping(target.get("signaling"), f"targets[{index}].signaling")
        _keys(signaling, f"targets[{index}].signaling", {"transport", "port"})
        transport = _string(
            signaling.get("transport"), f"targets[{index}].signaling.transport"
        )
        port = _uint(signaling.get("port"), f"targets[{index}].signaling.port")
        if transport not in transports:
            raise ManifestError(
                f"target {target_name!r} transport {transport!r} is not authorized"
            )
        if port not in signaling_ports:
            raise ManifestError(
                f"target {target_name!r} signaling port {port} is not authorized"
            )
        credential = target.get("credentialRef")
        if credential is not None:
            credential = _name(credential, f"targets[{index}].credentialRef")
            if credential not in credential_refs:
                raise ManifestError(
                    f"target {target_name!r} uses unauthorized credential reference {credential!r}"
                )
        targets[target_name] = {
            "host": host,
            "addresses": answers,
            "transport": transport,
            "port": port,
            "credentialRef": credential,
        }
        for address in answers:
            destinations.append(
                {
                    "target": target_name,
                    "address": address,
                    "transport": transport,
                    "port": port,
                }
            )

    global_expectations = _mapping(manifest.get("expectations"), "expectations")
    _keys(
        global_expectations,
        "expectations",
        {"allowedSipStatuses", "requireBidirectionalRtp"},
    )
    statuses = [
        _uint(value, f"expectations.allowedSipStatuses[{index}]")
        for index, value in enumerate(
            _unique_list(
                global_expectations.get("allowedSipStatuses"),
                "expectations.allowedSipStatuses",
            )
        )
    ]
    if any(value < 100 or value > 699 for value in statuses):
        raise ManifestError("allowed SIP statuses must be between 100 and 699")
    bidirectional = global_expectations.get("requireBidirectionalRtp")
    if not isinstance(bidirectional, bool):
        raise ManifestError("expectations.requireBidirectionalRtp must be a boolean")

    steps: list[dict[str, Any]] = []
    planned_step_count = 0
    totals = {"calls": 0, "packets": 0, "bytes": 0, "durationSeconds": 0}
    seen_cases: set[str] = set()
    for index, raw_case in enumerate(_list(manifest.get("cases"), "cases")):
        case = _mapping(raw_case, f"cases[{index}]")
        _keys(case, f"cases[{index}]", {"id", "type", "target", "count", "budget", "expectations", "generated"})
        case_id = _name(case.get("id"), f"cases[{index}].id")
        if case_id in seen_cases:
            raise ManifestError(f"duplicate case id {case_id!r}")
        seen_cases.add(case_id)
        case_type = _string(case.get("type"), f"cases[{index}].type")
        if case_type not in {"options", "call"}:
            raise ManifestError(f"unsupported case type {case_type!r}")
        target_name = _name(case.get("target"), f"cases[{index}].target")
        if target_name not in targets:
            raise ManifestError(f"case {case_id!r} references unknown target {target_name!r}")
        count = _uint(case.get("count"), f"cases[{index}].count")
        planned_step_count = _checked_add(
            planned_step_count, count, "generated step count"
        )
        if planned_step_count > ceilings["packets"]:
            raise ManifestError(
                "generated step count exceeds packet ceiling; refusing oversized plan"
            )
        if planned_step_count > MAX_PLAN_STEPS:
            raise ManifestError(
                f"generated step count exceeds planner limit ({MAX_PLAN_STEPS})"
            )
        budget = _mapping(case.get("budget"), f"cases[{index}].budget")
        _keys(
            budget,
            f"cases[{index}].budget",
            {"packetsPerRun", "bytesPerRun", "durationSecondsPerRun"},
        )
        per_run = {
            "packets": _uint(budget.get("packetsPerRun"), f"cases[{index}].budget.packetsPerRun"),
            "bytes": _uint(budget.get("bytesPerRun"), f"cases[{index}].budget.bytesPerRun"),
            "durationSeconds": _uint(
                budget.get("durationSecondsPerRun"),
                f"cases[{index}].budget.durationSecondsPerRun",
            ),
        }
        calls_per_run = 1 if case_type == "call" else 0
        contributions = {
            "calls": _checked_mul(count, calls_per_run, f"{case_id}.calls"),
            **{
                key: _checked_mul(count, value, f"{case_id}.{key}")
                for key, value in per_run.items()
            },
        }
        for key, value in contributions.items():
            totals[key] = _checked_add(totals[key], value, f"total {key}")
        case_expectations = (
            _case_expectations(
                case["expectations"],
                f"cases[{index}].expectations",
            )
            if "expectations" in case
            else {}
        )
        generated = None
        if "generated" in case:
            if matrix is None:
                raise ManifestError(
                    f"cases[{index}].generated requires a top-level matrix"
                )
            generated = _validate_generated_case(
                case["generated"], matrix, f"cases[{index}].generated"
            )
            if generated["factors"]["transport"] != targets[target_name]["transport"]:
                raise ManifestError(
                    f"cases[{index}].generated transport does not match its target"
                )
            generated_family = generated["factors"]["addressFamily"]
            if any(
                f"ipv{ipaddress.ip_address(address).version}" != generated_family
                for address in targets[target_name]["addresses"]
            ):
                raise ManifestError(
                    f"cases[{index}].generated addressFamily does not match its target"
                )
        for sequence in range(1, count + 1):
            step = {
                    "index": len(steps) + 1,
                    "case": case_id,
                    "sequence": sequence,
                    "type": case_type,
                    "target": target_name,
                    "destination": {
                        "addresses": targets[target_name]["addresses"],
                        "port": targets[target_name]["port"],
                        "transport": targets[target_name]["transport"],
                    },
                    "credentialRef": targets[target_name]["credentialRef"],
                    "budget": {
                        "calls": calls_per_run,
                        **per_run,
                    },
                    "expectations": case_expectations,
                }
            if generated is not None:
                step["generated"] = generated
            steps.append(step)

    for key, value in totals.items():
        if value > ceilings[key]:
            raise ManifestError(
                f"planned {key} ({value}) exceeds hard maximum ({ceilings[key]})"
            )
    evidence = _mapping(manifest.get("evidence"), "evidence")
    _keys(evidence, "evidence", {"capture", "retainPayload", "directory"})
    if not isinstance(evidence.get("capture"), bool):
        raise ManifestError("evidence.capture must be a boolean")
    if not isinstance(evidence.get("retainPayload"), bool):
        raise ManifestError("evidence.retainPayload must be a boolean")
    directory = _string(evidence.get("directory"), "evidence.directory")
    if Path(directory).is_absolute() or ".." in Path(directory).parts:
        raise ManifestError("evidence.directory must be a safe relative path")

    used_target_names = {step["target"] for step in steps}
    port_terms = sorted(signaling_ports)
    used_destinations = [
        item for item in destinations if item["target"] in used_target_names
    ]
    capture_scopes: list[str] = []
    for address in sorted(
        {item["address"] for item in used_destinations}, key=_address_sort_key
    ):
        signaling_terms = sorted(
            {
                (item["transport"], item["port"])
                for item in used_destinations
                if item["address"] == address
            }
        )
        port_filters = [
            f"{'udp' if transport == 'udp' else 'tcp'} port {port}"
            for transport, port in signaling_terms
        ]
        port_filters.append(f"udp portrange {media_start}-{media_end}")
        capture_scopes.append(
            f"(host {address} and ({' or '.join(port_filters)}))"
        )
    capture_filter = " or ".join(capture_scopes)

    plan = {
        "apiVersion": "sippycup.dev/plan/v1",
        "kind": "CampaignPlan",
        "metadata": {
            "name": campaign_name,
            "manifestSha256": digest,
        },
        "authorization": {
            "networks": [str(item) for item in networks],
            "signalingPorts": port_terms,
            "mediaPorts": {"start": media_start, "end": media_end},
            "transports": sorted(transports),
            "credentialRefs": sorted(credential_refs),
            "hardMaxima": ceilings,
            "stopConditions": stop_conditions,
        },
        "resolvedDestinations": sorted(
            destinations,
            key=lambda item: (
                item["target"],
                _address_sort_key(item["address"]),
                item["transport"],
                item["port"],
            ),
        ),
        "captureFilter": capture_filter,
        "expectations": {
            "allowedSipStatuses": sorted(statuses),
            "requireBidirectionalRtp": bidirectional,
        },
        "evidence": {
            "capture": evidence["capture"],
            "retainPayload": evidence["retainPayload"],
            "directory": directory,
        },
        "plannedTotals": totals,
        "steps": steps,
        "assumptions": sorted(assumptions),
        "resolutionPins": {
            host: resolution_pins[host] for host in sorted(resolution_pins)
        },
    }
    if matrix is not None:
        plan["matrix"] = matrix
    return plan


def verify_frozen_plan(plan: dict[str, Any], manifest_bytes: bytes) -> None:
    """Recompile source authorization with frozen DNS and compare every byte."""
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    try:
        manifest = yaml.safe_load(manifest_bytes)
    except (AttributeError, yaml.YAMLError) as error:
        raise ManifestError(f"invalid source manifest YAML: {error}") from error
    manifest = _mapping(manifest, "manifest")
    if plan.get("metadata", {}).get("manifestSha256") != digest:
        raise ManifestError("source manifest SHA-256 does not match frozen plan")
    pins = plan.get("resolutionPins")
    if not isinstance(pins, dict):
        raise ManifestError("frozen plan has no resolution pin map")

    def resolver(host: str) -> list[str]:
        answers = pins.get(host)
        if not isinstance(answers, list) or not answers:
            raise ManifestError(f"frozen plan has no DNS pin for {host!r}")
        return answers

    try:
        maxima = plan["authorization"]["hardMaxima"]
    except (KeyError, TypeError) as error:
        raise ManifestError("frozen plan lacks hard maxima") from error
    expected = compile_plan(
        manifest,
        digest,
        resolver=resolver,
        reductions={key: maxima.get(key) for key in CEILING_KEYS},
    )
    if json.dumps(expected, sort_keys=True, separators=(",", ":")) != json.dumps(
        plan, sort_keys=True, separators=(",", ":")
    ):
        raise ManifestError(
            "frozen plan differs from recompilation of the reviewed manifest"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="campaign")
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser(
        "plan", help="validate, resolve, and print a side-effect-free frozen plan"
    )
    plan.add_argument("manifest", type=Path)
    plan.add_argument(
        "--resolve",
        action="append",
        default=[],
        metavar="HOST=IP",
        help="pin a DNS answer; repeat for multiple answers",
    )
    plan.add_argument(
        "--error-format", choices=("human", "json"), default="human"
    )
    plan.add_argument(
        "--output",
        type=Path,
        help="atomically create the frozen JSON plan instead of writing stdout",
    )
    for option, key in (
        ("calls", "calls"),
        ("packets", "packets"),
        ("bytes", "bytes"),
        ("duration-seconds", "durationSeconds"),
        ("concurrent-calls", "concurrentCalls"),
        ("packets-per-second", "packetsPerSecond"),
        ("calls-per-second", "callsPerSecond"),
    ):
        plan.add_argument(f"--max-{option}", type=int, dest=f"max_{key}")
    matrix = commands.add_parser(
        "matrix", help="generate budgeted cases and honest coverage reports"
    )
    matrix.add_argument("manifest", type=Path)
    matrix.add_argument("--manifest-output", type=Path, required=True)
    matrix.add_argument("--report-output", type=Path, required=True)
    matrix.add_argument("--markdown-output", type=Path, required=True)
    matrix.add_argument("--seed", type=int, default=0)
    matrix.add_argument("--max-cases", type=int)
    matrix.add_argument("--history", type=Path)
    matrix.add_argument(
        "--actions",
        default="dtmf,failure,hangup,hold,recover,reinvite,resume",
    )
    matrix.add_argument("--max-actions", type=int, default=5)
    matrix.add_argument("--sequence-strength", type=int, default=2)
    matrix.add_argument("--error-format", choices=("human", "json"), default="human")
    run = commands.add_parser(
        "run", help="execute a reviewed plan with capture and traffic watchdogs"
    )
    run.add_argument("plan", type=Path)
    run.add_argument("--manifest", type=Path, required=True)
    run.add_argument("--run-root", type=Path, default=Path("work/runs"))
    run.add_argument("--interface", default="any")
    run.add_argument("--secret-env", action="append", default=[], metavar="REF=NAME")
    run.add_argument("--secret-fd", action="append", default=[], metavar="REF=FD")
    run.add_argument("--secret-provider")
    run.add_argument("--error-format", choices=("human", "json"), default="human")
    execute = commands.add_parser(
        "execute", help="run a frozen plan with capture, preflight, evidence, and SIP tools"
    )
    execute.add_argument("plan", type=Path)
    execute.add_argument("--manifest", type=Path, required=True)
    execute.add_argument("--run-root", type=Path, default=Path("work/runs"))
    execute.add_argument("--interface", default="any")
    execute.add_argument("--secret-env", action="append", default=[], metavar="REF=NAME")
    execute.add_argument("--secret-fd", action="append", default=[], metavar="REF=FD")
    execute.add_argument("--secret-provider")
    execute.add_argument(
        "--error-format", choices=("human", "json"), default="human"
    )
    return parser


def _emit_error(args: argparse.Namespace, code: str, message: str, **fields: Any) -> None:
    if getattr(args, "error_format", "human") == "json":
        print(
            json.dumps(
                {
                    "apiVersion": "sippycup.dev/error/v1",
                    "kind": "CampaignError",
                    "code": code,
                    "message": message,
                    **fields,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
    else:
        print(f"campaign: error: {message}", file=sys.stderr)


def _write_plan_atomic(path: Path, plan: dict[str, Any]) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(plan, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise ManifestError(
                f"refusing to overwrite existing frozen plan {path}"
            ) from error
    finally:
        temporary.unlink(missing_ok=True)


def _write_bytes_atomic(path: Path, content: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise ManifestError(f"refusing to overwrite existing output {path}") from error
    finally:
        temporary.unlink(missing_ok=True)


def _write_outputs_atomic(outputs: tuple[tuple[Path, bytes], ...]) -> None:
    staged: list[tuple[Path, Path]] = []
    linked: list[Path] = []
    try:
        for path, content in outputs:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
            )
            temporary = Path(temporary_name)
            staged.append((path, temporary))
            with os.fdopen(descriptor, "wb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
        for path, temporary in staged:
            try:
                os.link(temporary, path)
            except FileExistsError as error:
                raise ManifestError(
                    f"refusing to overwrite existing output {path}"
                ) from error
            linked.append(path)
    except BaseException:
        for path in linked:
            path.unlink(missing_ok=True)
        raise
    finally:
        for _path, temporary in staged:
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "matrix":
        from sippycup.matrix_compile import compile_matrix_campaign

        try:
            manifest, _digest = load_manifest(args.manifest)
            history = (
                json.loads(args.history.read_text(encoding="utf-8"))
                if args.history is not None
                else []
            )
            if not isinstance(history, list):
                raise ManifestError("history file must contain a JSON list")
            actions = tuple(item.strip() for item in args.actions.split(",") if item.strip())
            compilation = compile_matrix_campaign(
                manifest,
                seed=args.seed,
                actions=actions,
                max_actions=args.max_actions,
                sequence_strength=args.sequence_strength,
                max_cases=args.max_cases,
                history=history,
            )
            outputs = (
                (args.manifest_output, compilation.manifest_bytes),
                (
                    args.report_output,
                    (
                        json.dumps(compilation.report, indent=2, sort_keys=True)
                        + "\n"
                    ).encode(),
                ),
                (args.markdown_output, compilation.markdown.encode()),
            )
            if len({path.resolve() for path, _content in outputs}) != len(outputs):
                raise ManifestError("matrix output paths must be distinct")
            _write_outputs_atomic(outputs)
        except (ManifestError, OSError, json.JSONDecodeError) as error:
            _emit_error(args, "matrix_generation_failed", str(error))
            return 2
        print(args.report_output)
        return 0
    if args.command == "run":
        from sippycup.integration import execute_campaign, resolve_secrets
        from sippycup.runtime import RuntimeError as CampaignRuntimeError
        from sippycup.runtime import load_plan

        try:
            plan = load_plan(args.plan)
            manifest_bytes = args.manifest.read_bytes()
            verify_frozen_plan(plan, manifest_bytes)
            env_names = _parse_assignments(args.secret_env, "--secret-env")
            raw_fds = _parse_assignments(args.secret_fd, "--secret-fd")
            try:
                fds = {reference: int(value) for reference, value in raw_fds.items()}
            except ValueError as error:
                raise ManifestError("--secret-fd values must be integers") from error
            references = sorted(
                {
                    step["credentialRef"]
                    for step in plan["steps"]
                    if step.get("credentialRef") is not None
                }
            )
            secrets = resolve_secrets(
                references,
                env_names=env_names,
                fds=fds,
                provider=args.secret_provider,
            )
            result, run_directory = execute_campaign(
                plan,
                manifest_bytes=manifest_bytes,
                run_root=args.run_root,
                interface=args.interface,
                secret_values=secrets,
                secret_env_names=list(env_names.values()),
            )
        except (ManifestError, CampaignRuntimeError, OSError) as error:
            _emit_error(args, "invalid_plan_or_runtime", str(error))
            return 2
        print(run_directory)
        if result.exit_code:
            _emit_error(
                args,
                result.state,
                f"campaign ended in state {result.state!r}",
                exitCode=result.exit_code,
                completedSteps=result.completed_steps,
                runDirectory=str(run_directory),
            )
        return result.exit_code
    if args.command == "execute":
        from sippycup.integration import execute_campaign, resolve_secrets
        from sippycup.runtime import RuntimeError as CampaignRuntimeError
        from sippycup.runtime import load_plan

        try:
            plan = load_plan(args.plan)
            manifest_bytes = args.manifest.read_bytes()
            verify_frozen_plan(plan, manifest_bytes)
            env_names = _parse_assignments(args.secret_env, "--secret-env")
            raw_fds = _parse_assignments(args.secret_fd, "--secret-fd")
            try:
                fds = {reference: int(value) for reference, value in raw_fds.items()}
            except ValueError as error:
                raise ManifestError("--secret-fd values must be integers") from error
            references = sorted(
                {
                    step["credentialRef"]
                    for step in plan["steps"]
                    if step.get("credentialRef") is not None
                }
            )
            secrets = resolve_secrets(
                references,
                env_names=env_names,
                fds=fds,
                provider=args.secret_provider,
            )
            result, run_directory = execute_campaign(
                plan,
                manifest_bytes=manifest_bytes,
                run_root=args.run_root,
                interface=args.interface,
                secret_values=secrets,
                secret_env_names=list(env_names.values()),
            )
        except (ManifestError, CampaignRuntimeError, OSError) as error:
            _emit_error(args, "invalid_plan_or_runtime", str(error))
            return 2
        print(run_directory)
        if result.exit_code:
            _emit_error(
                args,
                result.state,
                f"campaign ended in state {result.state!r}",
                exitCode=result.exit_code,
                completedSteps=result.completed_steps,
                runDirectory=str(run_directory),
            )
        return result.exit_code
    try:
        manifest, digest = load_manifest(args.manifest)
        pinned = _parse_overrides(args.resolve)

        def resolver(host: str) -> list[str]:
            if pinned:
                if host not in pinned:
                    raise ManifestError(
                        f"no pinned resolution supplied for hostname {host!r}"
                    )
                return pinned[host]
            return system_resolver(host)

        reductions = {
            key.removeprefix("max_"): value
            for key, value in vars(args).items()
            if key.startswith("max_")
        }
        plan = compile_plan(
            manifest,
            digest,
            resolver=resolver,
            reductions=reductions,
        )
    except (ManifestError, OSError) as error:
        _emit_error(args, "invalid_manifest", str(error))
        return 2
    if args.output is not None:
        try:
            _write_plan_atomic(args.output, plan)
        except (ManifestError, OSError) as error:
            _emit_error(args, "plan_write_failed", str(error))
            return 2
    else:
        json.dump(plan, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    return 0
