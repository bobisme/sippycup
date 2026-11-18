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

from . import approval as approval_rules
from . import capture_scope

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
# The SIP user part a call dials and the account username: letters, digits,
# and + * . _ - only, never an @, URI parameter, header, or whitespace. The
# grammar equals the softphone driver's destination grammar.
SIP_USER_PATTERN = re.compile(r"[A-Za-z0-9+*][A-Za-z0-9._+*-]{0,63}")
SIP_REALM_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}")


class ManifestError(ValueError):
    """An authorization or schema error suitable for command-line display."""


def system_trust_reader(reference: str) -> str:
    """SHA-256 of a reviewed ``work/...`` CA file; never opens a socket."""
    from sippycup.tls_trust import TrustError, read_ca

    try:
        return read_ca(reference)[1]
    except TrustError as error:
        raise ManifestError(str(error)) from error


def _tls(signaling: dict[str, Any], transport: str, field: str,
         trust_reader: Callable[[str], str]) -> dict[str, Any] | None:
    """The reviewed TLS server name and trust anchor of one target, if any."""
    from sippycup.tls_trust import TrustError, validate_ca_reference, validate_server_name

    if "tlsServerName" not in signaling and "tlsCaFile" not in signaling:
        return None
    if transport != "tls":
        raise ManifestError(
            f"{field}.tlsServerName and {field}.tlsCaFile are only valid with transport tls"
        )
    tls: dict[str, Any] = {"serverName": None, "caFile": None, "caSha256": None}
    try:
        if "tlsServerName" in signaling:
            tls["serverName"] = validate_server_name(signaling["tlsServerName"])
        if "tlsCaFile" in signaling:
            tls["caFile"] = validate_ca_reference(signaling["tlsCaFile"])
    except TrustError as error:
        raise ManifestError(f"{field}: {error}") from error
    if tls["caFile"] is not None:
        # The trust anchor is security-relevant input: its digest is frozen so
        # execution refuses a CA file that changed after review.
        tls["caSha256"] = trust_reader(tls["caFile"])
    return tls


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


def _sip_user(value: Any, field: str) -> str:
    if isinstance(value, bool) or isinstance(value, int):
        raise ManifestError(
            f"{field} must be a quoted string (YAML reads an unquoted number as an integer)"
        )
    if not isinstance(value, str) or SIP_USER_PATTERN.fullmatch(value) is None:
        raise ManifestError(
            f"{field} must be 1-64 characters of letters, digits, and + * . _ - "
            "starting with a letter, digit, + or * (no @, URI parameters, or whitespace)"
        )
    if PLACEHOLDER_WORDS.search(value.lower()):
        raise ManifestError(f"{field} {value!r} is a placeholder")
    return value


def _dial(value: Any, field: str) -> dict[str, str]:
    dial = _mapping(value, field)
    _keys(dial, field, {"user"})
    if "user" not in dial:
        raise ManifestError(f"{field}.user is required")
    return {"user": _sip_user(dial["user"], f"{field}.user")}


SRTP_MODES = ("off", "optional", "mandatory")
MAX_DTMF_AFTER_SECONDS = 60
MAX_CALL_SECONDS = 3600


def _call_options(value: Any, field: str) -> dict[str, Any]:
    """A call case's reviewed in-call actions: RFC 4733 digits after answer,
    how long the call stays connected (to hear the response), and the only
    codecs the call offers."""
    from sippycup_softphone.evidence import DtmfError, validate_dtmf

    call = _mapping(value, field)
    _keys(call, field, {"dtmf", "dtmfAfterSeconds", "durationSeconds", "codecs"})
    if "dtmf" not in call and "codecs" not in call:
        raise ManifestError(f"{field} needs dtmf or codecs")
    result: dict[str, Any] = {}
    if "dtmf" in call:
        digits = call["dtmf"]
        if isinstance(digits, (bool, int)):
            raise ManifestError(
                f"{field}.dtmf must be a quoted string (YAML reads unquoted digits as a number)"
            )
        try:
            result["dtmf"] = validate_dtmf(digits)
        except DtmfError as error:
            raise ManifestError(f"{field}.dtmf: {error}") from error
    elif "dtmfAfterSeconds" in call:
        raise ManifestError(f"{field}.dtmfAfterSeconds requires dtmf")
    if "codecs" in call:
        result["codecs"] = _codecs(call["codecs"], f"{field}.codecs")
    if "dtmfAfterSeconds" in call:
        after = _uint(call["dtmfAfterSeconds"], f"{field}.dtmfAfterSeconds", allow_zero=True)
        if after > MAX_DTMF_AFTER_SECONDS:
            raise ManifestError(
                f"{field}.dtmfAfterSeconds must be at most {MAX_DTMF_AFTER_SECONDS}"
            )
        result["dtmfAfterSeconds"] = after
    if "durationSeconds" in call:
        seconds = _uint(call["durationSeconds"], f"{field}.durationSeconds")
        if seconds > MAX_CALL_SECONDS:
            raise ManifestError(f"{field}.durationSeconds must be at most {MAX_CALL_SECONDS}")
        result["durationSeconds"] = seconds
    return result


def _codecs(value: Any, field: str) -> list[str]:
    """1-9 distinct codecs the image's PJSUA supports, in preference order."""
    from sippycup_softphone.driver import SUPPORTED_CODECS, SoftphoneError, canonical_codec

    if not isinstance(value, list) or not 1 <= len(value) <= len(SUPPORTED_CODECS):
        raise ManifestError(
            f"{field} must be a list of 1-{len(SUPPORTED_CODECS)} codec names: "
            + ", ".join(SUPPORTED_CODECS)
        )
    names: list[str] = []
    for item in value:
        try:
            name = canonical_codec(item)
        except SoftphoneError as error:
            raise ManifestError(f"{field}: {error}") from error
        if name in names:
            raise ManifestError(f"{field} lists {name} twice")
        names.append(name)
    return names


def _media(value: Any, field: str) -> dict[str, str]:
    """A target's media security for softphone calls (SDES-SRTP mode)."""
    media = _mapping(value, field)
    _keys(media, field, {"srtp"})
    if media.get("srtp") not in SRTP_MODES:
        raise ManifestError(f"{field}.srtp must be one of off, optional, mandatory")
    return {"srtp": media["srtp"]}


def _account(value: Any, field: str) -> dict[str, Any]:
    account = _mapping(value, field)
    _keys(account, field, {"username", "realm", "register"})
    if "username" not in account:
        raise ManifestError(f"{field}.username is required")
    result: dict[str, Any] = {"username": _sip_user(account["username"], f"{field}.username")}
    if "realm" in account:
        realm = account["realm"]
        if not isinstance(realm, str) or SIP_REALM_PATTERN.fullmatch(realm) is None:
            raise ManifestError(
                f"{field}.realm must be 1-253 characters of letters, digits, and . _ - "
                "(omit it to answer a challenge for any realm)"
            )
        result["realm"] = realm
    register = account.get("register", False)
    if not isinstance(register, bool):
        raise ManifestError(f"{field}.register must be a boolean")
    result["register"] = register
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


def _media_networks(value: Any) -> list[str]:
    """Validate the optional media-only ``authorization.mediaNetworks``.

    The same breadth rule as a target profile's ``media.networks`` (at most 16
    networks and 1024 addresses together, no unspecified, multicast, reserved,
    or broadcast addresses), no documentation range, and canonical sorted
    output. These networks admit media only: a target must still resolve
    inside ``authorization.networks``.
    """
    from sippycup_workbench.media_scope import validate_networks

    items = _unique_list(value, "authorization.mediaNetworks")
    errors: list[str] = []
    canonical = validate_networks(items, errors)
    if canonical is None:
        raise ManifestError(
            "; ".join(item.replace("media.networks", "authorization.mediaNetworks") for item in errors)
        )
    parsed = [ipaddress.ip_network(item) for item in canonical]
    for network in parsed:
        if any(
            network.version == documentation.version and network.subnet_of(documentation)
            for documentation in DOCUMENTATION_NETWORKS
        ):
            raise ManifestError(f"documentation-only network {str(network)!r} is a placeholder")
    parsed.sort(key=lambda item: (item.version, int(item.network_address), item.prefixlen))
    return [str(item) for item in parsed]


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
    trust_reader: Callable[[str], str] = system_trust_reader,
) -> dict[str, Any]:
    """Validate and resolve a manifest, returning a deterministic frozen plan.

    ``trust_reader`` maps a reviewed ``work/...`` CA file to its SHA-256; it
    is called only for a target that declares ``signaling.tlsCaFile``.
    """
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
            "mediaNetworks",
            "approval",
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
    # bn-3vxl: no "any" network and a documented total (see sippycup.approval).
    try:
        approval_rules.check_network_breadth(networks)
        # Optional, frozen only when the manifest states it, so manifests
        # without an approval window keep their plan bytes.
        approval = (
            approval_rules.manifest_approval(authorization["approval"])
            if "approval" in authorization
            else None
        )
    except approval_rules.ApprovalError as error:
        raise ManifestError(str(error)) from error
    media_networks = (
        _media_networks(authorization["mediaNetworks"])
        if "mediaNetworks" in authorization
        else None
    )

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
        {
            "consecutiveFailures", "unexpectedResponse", "packetLossPercent",
            "preflightServerError",
        },
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
    if "preflightServerError" in stops:
        # Optional and frozen only when the manifest states it, so plans (and
        # their digests) for manifests that omit it stay byte-identical.
        if not isinstance(stops["preflightServerError"], bool):
            raise ManifestError("stopConditions.preflightServerError must be a boolean")
        stop_conditions["preflightServerError"] = stops["preflightServerError"]

    targets: dict[str, dict[str, Any]] = {}
    destinations: list[dict[str, Any]] = []
    assumptions: list[str] = []
    resolution_pins: dict[str, list[str]] = {}
    for index, raw_target in enumerate(_list(manifest.get("targets"), "targets")):
        target = _mapping(raw_target, f"targets[{index}]")
        _keys(
            target,
            f"targets[{index}]",
            {"name", "address", "signaling", "credentialRef", "account", "media"},
        )
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
                media_only = media_networks is not None and any(
                    address in ipaddress.ip_network(item) for item in media_networks
                )
                raise ManifestError(
                    f"target {host!r} resolved to {answer}, outside approved networks"
                    + (
                        " (it is inside authorization.mediaNetworks, which admits media "
                        "only, never a signaling destination)"
                        if media_only
                        else ""
                    )
                )

        signaling = _mapping(target.get("signaling"), f"targets[{index}].signaling")
        _keys(
            signaling,
            f"targets[{index}].signaling",
            {"transport", "port", "tlsServerName", "tlsCaFile"},
        )
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
        account = None
        if "account" in target:
            account = _account(target["account"], f"targets[{index}].account")
            if credential is None:
                raise ManifestError(
                    f"targets[{index}].account requires the target's credentialRef "
                    "(the password is supplied at run time, never in the manifest)"
                )
        media = _media(target["media"], f"targets[{index}].media") if "media" in target else None
        tls = _tls(signaling, transport, f"targets[{index}].signaling", trust_reader)
        if tls is not None:
            trust = (
                f"CA file {tls['caFile']} (sha256 {tls['caSha256']})"
                if tls["caFile"] is not None
                else "the system trust store"
            )
            name = (
                f"server name {tls['serverName']}"
                if tls["serverName"] is not None
                else "the IP address SAN"
            )
            assumptions.append(
                f"TLS to {target_name} verifies {name} against {trust}; connections "
                f"go only to {', '.join(answers)} and the name is never resolved"
            )
        targets[target_name] = {
            "host": host,
            "addresses": answers,
            "transport": transport,
            "port": port,
            "credentialRef": credential,
            "account": account,
            "tls": tls,
            "media": media,
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
        _keys(
            case,
            f"cases[{index}]",
            {"id", "type", "target", "count", "budget", "expectations", "generated", "dial", "call"},
        )
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
        dial = None
        if "dial" in case:
            if case_type != "call":
                raise ManifestError(f"cases[{index}].dial is only valid for a call case")
            dial = _dial(case["dial"], f"cases[{index}].dial")
        call_options = None
        if "call" in case:
            if case_type != "call":
                raise ManifestError(f"cases[{index}].call is only valid for a call case")
            call_options = _call_options(case["call"], f"cases[{index}].call")
            if "durationSeconds" in call_options and "generated" in case:
                raise ManifestError(
                    f"cases[{index}].call.durationSeconds conflicts with the generated "
                    "duration factor"
                )
            if "codecs" in call_options and "generated" in case:
                raise ManifestError(
                    f"cases[{index}].call.codecs conflicts with the generated codec factor"
                )
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
            # Optional call facts are added only when declared so a manifest
            # without them compiles to exactly the same plan bytes as before.
            if dial is not None:
                step["dial"] = dict(dial)
            if case_type == "call" and targets[target_name]["account"] is not None:
                step["account"] = dict(targets[target_name]["account"])
            if targets[target_name]["tls"] is not None:
                step["tls"] = dict(targets[target_name]["tls"])
            if call_options is not None:
                step["call"] = dict(call_options)
            if case_type == "call" and targets[target_name]["media"] is not None:
                step["media"] = dict(targets[target_name]["media"])
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
    del used_destinations  # the capture scope is derived from the steps below
    # One rule for planner, runtime validator, and execution (capture_scope):
    # a manifest without mediaNetworks keeps the original filter byte for
    # byte; with it, the plan freezes the authorized media term too.
    capture_filter = capture_scope.frozen_filter(
        steps,
        {"start": media_start, "end": media_end},
        [str(item) for item in networks],
        media_networks,
    )
    if approval is not None:
        assumptions.append(
            "traffic is sent only inside the owner's approval window ("
            + (f"from {approval['validFrom']} " if "validFrom" in approval else "")
            + f"until {approval['validUntil']}); campaign run checks it before any packet and "
            "before every step, and starts no step that could end after it"
        )
    if media_networks is not None:
        assumptions.append(
            "media (never signaling) may also flow to and from authorization.mediaNetworks "
            f"{', '.join(media_networks)} on UDP ports {media_start}-{media_end}; the capture "
            "and its watchdog include UDP in that port range with every authorized network"
        )

    plan = {
        "apiVersion": "sippycup.dev/plan/v1",
        "kind": "CampaignPlan",
        "metadata": {
            "name": campaign_name,
            "manifestSha256": digest,
        },
        "authorization": {
            "networks": [str(item) for item in networks],
            **({"mediaNetworks": media_networks} if media_networks is not None else {}),
            **({"approval": approval} if approval is not None else {}),
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

    # Like DNS, a trust anchor's digest is frozen at plan time; recompilation
    # uses the frozen digest, and execution separately refuses a CA file whose
    # bytes no longer match it.
    frozen_digests: dict[str, str] = {}
    for step in plan.get("steps") or []:
        tls = step.get("tls") if isinstance(step, dict) else None
        if isinstance(tls, dict) and isinstance(tls.get("caFile"), str):
            if frozen_digests.setdefault(tls["caFile"], tls.get("caSha256")) != tls.get("caSha256"):
                raise ManifestError(f"frozen plan has conflicting digests for {tls['caFile']}")

    def trust_reader(reference: str) -> str:
        frozen = frozen_digests.get(reference)
        if not isinstance(frozen, str):
            raise ManifestError(f"frozen plan has no trust-anchor digest for {reference!r}")
        return frozen

    try:
        maxima = plan["authorization"]["hardMaxima"]
    except (KeyError, TypeError) as error:
        raise ManifestError("frozen plan lacks hard maxima") from error
    expected = compile_plan(
        manifest,
        digest,
        resolver=resolver,
        reductions={key: maxima.get(key) for key in CEILING_KEYS},
        trust_reader=trust_reader,
    )
    if json.dumps(expected, sort_keys=True, separators=(",", ":")) != json.dumps(
        plan, sort_keys=True, separators=(",", ":")
    ):
        raise ManifestError(
            "frozen plan differs from recompilation of the reviewed manifest"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sippycup campaign")
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
    run.add_argument("plan", type=Path, help="the frozen plan from campaign plan --output")
    run.add_argument("--manifest", type=Path, required=True,
                        help="the exact manifest the plan was frozen from")
    run.add_argument("--run-root", type=Path, default=Path("work/runs"),
                        help="directory for the new run directory (default work/runs; use work/ENGAGEMENT/runs)")
    run.add_argument("--interface", default="any",
                        help="capture interface (default any; lo with --practice)")
    run.add_argument("--secret-env", action="append", default=[], metavar="REF=NAME",
                        help="read credential REF from environment variable NAME (repeatable)")
    run.add_argument("--secret-fd", action="append", default=[], metavar="REF=FD")
    run.add_argument("--secret-provider")
    run.add_argument("--error-format", choices=("human", "json"), default="human")
    execute = commands.add_parser(
        "execute", help="run a frozen plan with capture, preflight, evidence, and SIP tools"
    )
    execute.add_argument("plan", type=Path, help="the frozen plan from campaign plan --output")
    execute.add_argument("--manifest", type=Path, required=True,
                        help="the exact manifest the plan was frozen from")
    execute.add_argument("--run-root", type=Path, default=Path("work/runs"),
                        help="directory for the new run directory (default work/runs; use work/ENGAGEMENT/runs)")
    execute.add_argument("--interface", default="any",
                        help="capture interface (default any; lo with --practice)")
    execute.add_argument("--secret-env", action="append", default=[], metavar="REF=NAME",
                        help="read credential REF from environment variable NAME (repeatable)")
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



def operator_path(path: Path | str) -> str:
    """Spell a run directory the way the operator sees it on the host.

    Inside the image the repository's work/ tree is mounted at /work, so a
    containerized run (``--isolated``, ``--practice``) would otherwise print
    ``/work/ENGAGEMENT/runs/RUN``, a path that does not exist on the host.
    """
    text = str(path)
    if text == "/work" or text.startswith("/work/"):
        return "work" + text[len("/work"):]
    return text

def _print_run_summary(args: argparse.Namespace, result: Any, run_directory: Path, plan: dict[str, Any]) -> None:
    """Tell the operator, on stderr, what happened and what to do next.

    Standard output stays exactly the run directory, which scripts read.
    """
    if getattr(args, "error_format", "human") == "json":
        return
    shown = operator_path(run_directory)
    engagement = operator_path(Path(run_directory).parent.parent)
    relative = f"{Path(run_directory).parent.name}/{Path(run_directory).name}"
    lines = [
        f"Campaign: {str(result.state).upper()} ({result.completed_steps} of "
        f"{len(plan.get('steps', []))} step(s) completed; exit {result.exit_code})",
        f"Run directory: {shown} (result.json, events.jsonl, capture.pcap, report.txt)",
    ]
    if result.state == approval_rules.LAPSED:
        detail = ""
        try:
            stop = json.loads((Path(run_directory) / "result.json").read_text(encoding="utf-8"))[
                "approvalWindow"
            ]["stop"]
            detail = str(stop["detail"])
        except (OSError, ValueError, KeyError, TypeError):
            pass
        lines.append(
            "Safety stop on our side, not a platform failure: the approval no longer covers "
            f"the next step, so Sippycup stopped before sending it"
            + (f" ({detail})" if detail else "")
            + ". Steps already completed are in the run directory; "
            f"{len(plan.get('steps', [])) - result.completed_steps} step(s) were not sent."
        )
    if (Path(run_directory).parent.parent / "engagement.json").is_file():
        lines.append(
            f"Record it: ./bin/sippycup journal add {engagement} --kind action "
            f"--summary 'Campaign run: {result.state}' --evidence {relative}/result.json "
            f"--evidence {relative}/evidence-manifest.json"
        )
    print("\n".join(lines), file=sys.stderr)


def _warn(args: argparse.Namespace, code: str, message: str) -> None:
    """A warning on standard error; never changes the exit status."""
    if getattr(args, "error_format", "human") == "json":
        print(
            json.dumps(
                {
                    "apiVersion": "sippycup.dev/warning/v1",
                    "kind": "CampaignWarning",
                    "code": code,
                    "message": message,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
    else:
        print(f"campaign: {message}", file=sys.stderr)


def plan_window_check(
    plan: dict[str, Any], now: Any = None
) -> tuple[str | None, list[tuple[str, str]]]:
    """``(refusal, warnings)`` for a freshly compiled plan against the clock.

    Refuses a plan whose approval window has already ended. Planning before
    the window opens is allowed. Warns when the plan has no window, when the
    window is not open yet, and when the planned duration cannot fit in what
    remains.
    """
    window = approval_rules.plan_window(plan)
    if not window.bound:
        return None, [("window_unbound", approval_rules.UNBOUND_WARNING)]
    instant = now or approval_rules.utc_now()
    refusal = approval_rules.window_refusal(window, instant)
    if refusal is not None and refusal.kind == "expired":
        return (
            f"{refusal.message}. No plan was written and nothing was sent.",
            [],
        )
    warnings: list[tuple[str, str]] = []
    planned = plan.get("plannedTotals", {}).get("durationSeconds", 0)
    assert window.valid_until is not None
    if refusal is not None:
        warnings.append(
            ("window_not_open", f"WARNING: {refusal.message}. campaign run refuses until then.")
        )
    else:
        remaining = int((window.valid_until - instant).total_seconds())
        if planned >= remaining:
            warnings.append(
                (
                    "window_too_short",
                    f"WARNING: the planned duration ({planned} s) cannot fit in what remains of "
                    f"the approval window ({remaining} s, valid until "
                    f"{approval_rules.stamp(window.valid_until)}). campaign run will stop before "
                    "the first step that could end after the window; ask the owner to extend "
                    "the window or plan fewer steps.",
                )
            )
    return None, warnings


def _run_command(args: argparse.Namespace) -> int:
    from sippycup.integration import AuthorizationLapsed, execute_campaign, resolve_secrets
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
        # The approval window is checked before any secret is read; the
        # executor checks it again before it creates anything.
        gate = approval_rules.WindowGate(plan, manifest_path=args.manifest)
        refusal = gate.refusal()
        if refusal is not None:
            raise AuthorizationLapsed(refusal.message)
        if not gate.window.bound:
            _warn(args, "window_unbound", approval_rules.UNBOUND_WARNING)
        else:
            planned = plan["plannedTotals"]["durationSeconds"]
            fits = approval_rules.window_refusal(gate.window, gate.clock(), planned, "the whole plan")
            if fits is not None:
                _warn(
                    args,
                    "window_too_short",
                    f"WARNING: {fits.message}. The campaign will stop before the first step "
                    "that could end after the window.",
                )
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
            manifest_path=args.manifest,
        )
    except AuthorizationLapsed as error:
        _emit_error(
            args,
            approval_rules.LAPSED,
            f"refusing to run: {error}. Nothing was sent and no run directory was created.",
        )
        return 2
    except (ManifestError, CampaignRuntimeError, OSError) as error:
        _emit_error(args, "invalid_plan_or_runtime", str(error))
        return 2
    print(operator_path(run_directory))
    _print_run_summary(args, result, run_directory, plan)
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
    if args.command in {"run", "execute"}:
        return _run_command(args)
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
    refused, warnings = plan_window_check(plan)
    if refused is not None:
        _emit_error(args, approval_rules.LAPSED, f"refusing to plan: {refused}")
        return 2
    for code, message in warnings:
        _warn(args, code, message)
    if args.output is not None:
        try:
            _write_plan_atomic(args.output, plan)
        except (ManifestError, OSError) as error:
            _emit_error(args, "plan_write_failed", str(error))
            return 2
        credentials = plan.get("authorization", {}).get("credentialRefs") or []
        secret_hint = "".join(f" --secret-env {ref}=VARIABLE" for ref in credentials)
        print(
            f"Wrote frozen plan: {operator_path(args.output)} "
            f"({len(plan.get('steps', []))} step(s); review it before running)\n"
            f"Next: ./bin/sippycup campaign run {operator_path(args.output)} "
            f"--manifest {operator_path(args.manifest)} --run-root {operator_path(args.manifest.parent / 'runs')} "
            f"--interface any{secret_hint}\n"
            "(VARIABLE: an environment variable that holds the password; against the practice target "
            "add --practice before campaign and use --interface lo)\n"
            "Network activity: none",
            file=sys.stderr,
        )
    else:
        json.dump(plan, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    return 0
