"""Fail-closed semantic checks for the versioned WebRTC contracts.

The published JSON Schemas describe the wire format. These checks cover
cross-field security properties which are awkward or misleading to encode in
schema alone. They deliberately use only the Python standard library so an
operator can validate a fixture before installing an optional WebRTC peer.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
import ipaddress
import re
from typing import Any

SCENARIO_VERSION = "sippycup.dev/webrtc-scenario/v1"
RESULT_VERSION = "sippycup.dev/webrtc-result/v1"

CAPABILITIES = frozenset(
    {
        "audio",
        "trickle-ice",
        "ice-restart",
        "stun",
        "turn-udp",
        "turn-tcp",
        "turn-tls",
        "dtls-srtp",
        "rtcp",
        "wss-signaling",
    }
)
EXECUTION_CLASSES = frozenset({"offline_fixture", "local_lab", "approved_target"})
DESTINATION_ROLES = frozenset({"signaling", "stun", "turn", "media"})
TRANSPORTS = frozenset({"udp", "tcp", "tls", "wss"})
NEGATIVE_TESTS = frozenset(
    {
        "auth",
        "origin",
        "signaling-state",
        "ice",
        "turn",
        "dtls",
        "srtp",
        "consent",
    }
)
VERDICTS = frozenset({"pass", "fail", "unknown", "not_applicable"})
UNKNOWN_REASONS = frozenset(
    {
        "missing_evidence",
        "encrypted",
        "unsupported",
        "malformed",
        "redacted",
        "not_observed",
        "adapter_failure",
    }
)
_CREDENTIAL_REF = re.compile(r"^[a-z][a-z0-9+.-]*://[A-Za-z0-9._/-]{1,240}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SECRET_KEYS = frozenset(
    {
        "bearer",
        "cookie",
        "icepassword",
        "icepwd",
        "keymaterial",
        "password",
        "privatekey",
        "secret",
        "token",
        "turnpassword",
    }
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]+"),
    re.compile(r"(?im)^a=ice-pwd:"),
    re.compile(r"(?im)^authorization:"),
    re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
)


class ContractError(ValueError):
    """A WebRTC contract violated a fail-closed semantic rule."""


def _object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{path} must be an object")
    return value


def _array(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise ContractError(f"{path} must be an array")
    return value


def _string(value: Any, path: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ContractError(f"{path} must be a non-empty string")
    return value


def _integer(value: Any, path: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError(f"{path} must be an integer")
    if not minimum <= value <= maximum:
        raise ContractError(f"{path} must be between {minimum} and {maximum}")
    return value


def _exact_keys(
    value: Mapping[str, Any],
    path: str,
    required: Iterable[str],
    optional: Iterable[str] = (),
) -> None:
    required_set = set(required)
    allowed = required_set | set(optional)
    missing = required_set - set(value)
    extra = set(value) - allowed
    if missing:
        raise ContractError(f"{path} is missing: {', '.join(sorted(missing))}")
    if extra:
        raise ContractError(f"{path} has unknown fields: {', '.join(sorted(extra))}")


def _timestamp(value: Any, path: str) -> datetime:
    text = _string(value, path)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError(f"{path} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ContractError(f"{path} must include a timezone")
    return parsed


def _scan_for_secrets(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = re.sub(r"[^a-z]", "", str(key).lower())
            if normalized in _SECRET_KEYS:
                raise ContractError(f"{path}.{key} is a forbidden secret-bearing field")
            _scan_for_secrets(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan_for_secrets(item, f"{path}[{index}]")
    elif isinstance(value, str):
        for pattern in _SECRET_VALUE_PATTERNS:
            if pattern.search(value):
                raise ContractError(f"{path} appears to contain secret material")


def _validate_authorization(
    value: Any, execution_class: str
) -> None:
    authorization = _object(value, "$.authorization")
    _exact_keys(
        authorization,
        "$.authorization",
        (
            "required",
            "approvalRef",
            "validFrom",
            "validUntil",
            "negativeTests",
        ),
    )
    required = authorization["required"]
    if not isinstance(required, bool):
        raise ContractError("$.authorization.required must be boolean")
    approval_ref = authorization["approvalRef"]
    valid_from = authorization["validFrom"]
    valid_until = authorization["validUntil"]
    tests = _array(authorization["negativeTests"], "$.authorization.negativeTests")
    if len(tests) != len(set(tests)):
        raise ContractError("$.authorization.negativeTests must be unique")
    unknown_tests = set(tests) - NEGATIVE_TESTS
    if unknown_tests:
        raise ContractError(
            "$.authorization.negativeTests contains unsupported values: "
            + ", ".join(sorted(unknown_tests))
        )
    if execution_class == "approved_target":
        if required is not True:
            raise ContractError("approved_target requires authorization.required=true")
        _string(approval_ref, "$.authorization.approvalRef")
        start = _timestamp(valid_from, "$.authorization.validFrom")
        end = _timestamp(valid_until, "$.authorization.validUntil")
        if end <= start:
            raise ContractError("$.authorization.validUntil must follow validFrom")
    elif required or any(item is not None for item in (approval_ref, valid_from, valid_until)):
        raise ContractError(
            f"{execution_class} must not carry a target authorization reference or window"
        )
    if tests and execution_class == "offline_fixture":
        # Fixtures describe negative cases, but do not grant permission to execute them.
        return


def _validate_destinations(value: Any, execution_class: str) -> None:
    destinations = _array(value, "$.destinations")
    if execution_class == "approved_target" and not destinations:
        raise ContractError("approved_target requires at least one literal destination")
    seen: set[tuple[str, str, int, str]] = set()
    for index, item in enumerate(destinations):
        path = f"$.destinations[{index}]"
        destination = _object(item, path)
        _exact_keys(destination, path, ("role", "address", "port", "transport"))
        role = _string(destination["role"], f"{path}.role")
        if role not in DESTINATION_ROLES:
            raise ContractError(f"{path}.role is unsupported")
        address_text = _string(destination["address"], f"{path}.address")
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError as exc:
            raise ContractError(f"{path}.address must be a literal IP address") from exc
        port = _integer(destination["port"], f"{path}.port", 1, 65535)
        transport = _string(destination["transport"], f"{path}.transport")
        if transport not in TRANSPORTS:
            raise ContractError(f"{path}.transport is unsupported")
        if role == "signaling" and transport != "wss":
            raise ContractError(f"{path}: signaling requires wss transport")
        if role == "media" and transport != "udp":
            raise ContractError(f"{path}: media requires udp transport")
        if execution_class == "offline_fixture" and not address.is_loopback:
            raise ContractError(f"{path}: offline fixtures are loopback-only")
        if execution_class == "local_lab" and not (
            address.is_loopback or address.is_private or address.is_link_local
        ):
            raise ContractError(f"{path}: local_lab cannot name a public address")
        key = (role, address.compressed, port, transport)
        if key in seen:
            raise ContractError(f"{path} duplicates an earlier destination")
        seen.add(key)


def _validate_credentials(value: Any) -> None:
    references = _array(value, "$.credentialRefs")
    if len(references) != len(set(references)):
        raise ContractError("$.credentialRefs must be unique")
    for index, item in enumerate(references):
        reference = _string(item, f"$.credentialRefs[{index}]")
        if not _CREDENTIAL_REF.fullmatch(reference):
            raise ContractError(
                f"$.credentialRefs[{index}] must be an external provider reference"
            )
        if reference.lower().startswith(("inline://", "data://")):
            raise ContractError(
                f"$.credentialRefs[{index}] uses a forbidden inline provider"
            )


def _validate_limits(value: Any) -> None:
    limits = _object(value, "$.limits")
    fields = {
        "maxCalls": (1, 4096),
        "maxConcurrency": (1, 4096),
        "maxDurationSeconds": (1, 3600),
        "maxSignalingMessages": (1, 100000),
        "maxPackets": (1, 10000000),
        "maxBytes": (1, 1073741824),
        "maxEvidenceBytes": (1024, 1073741824),
    }
    _exact_keys(limits, "$.limits", fields)
    parsed = {
        key: _integer(limits[key], f"$.limits.{key}", *bounds)
        for key, bounds in fields.items()
    }
    if parsed["maxConcurrency"] > parsed["maxCalls"]:
        raise ContractError("$.limits.maxConcurrency cannot exceed maxCalls")


def validate_scenario(
    document: Any, adapter_capabilities: Iterable[str] = ()
) -> Mapping[str, Any]:
    """Validate a scenario and the selected adapter's advertised capabilities."""

    scenario = _object(document, "$")
    _exact_keys(
        scenario,
        "$",
        (
            "apiVersion",
            "kind",
            "metadata",
            "executionClass",
            "adapter",
            "authorization",
            "destinations",
            "credentialRefs",
            "limits",
            "negotiation",
            "evidence",
        ),
    )
    if scenario["apiVersion"] != SCENARIO_VERSION:
        raise ContractError("$.apiVersion is unsupported")
    if scenario["kind"] != "WebRTCScenario":
        raise ContractError("$.kind must be WebRTCScenario")

    metadata = _object(scenario["metadata"], "$.metadata")
    _exact_keys(metadata, "$.metadata", ("name", "scenarioId"))
    _string(metadata["name"], "$.metadata.name")
    _string(metadata["scenarioId"], "$.metadata.scenarioId")

    execution_class = _string(scenario["executionClass"], "$.executionClass")
    if execution_class not in EXECUTION_CLASSES:
        raise ContractError("$.executionClass is unsupported")

    adapter = _object(scenario["adapter"], "$.adapter")
    _exact_keys(
        adapter,
        "$.adapter",
        ("name", "capabilityVersion", "requiredCapabilities"),
    )
    _string(adapter["name"], "$.adapter.name")
    _string(adapter["capabilityVersion"], "$.adapter.capabilityVersion")
    required_capabilities = _array(
        adapter["requiredCapabilities"], "$.adapter.requiredCapabilities"
    )
    if len(required_capabilities) != len(set(required_capabilities)):
        raise ContractError("$.adapter.requiredCapabilities must be unique")
    unsupported = set(required_capabilities) - CAPABILITIES
    if unsupported:
        raise ContractError(
            "$.adapter.requiredCapabilities contains unsupported values: "
            + ", ".join(sorted(unsupported))
        )
    missing = set(required_capabilities) - set(adapter_capabilities)
    if missing:
        raise ContractError(
            "adapter capability mismatch; missing: " + ", ".join(sorted(missing))
        )

    _validate_authorization(scenario["authorization"], execution_class)
    _validate_destinations(scenario["destinations"], execution_class)
    _validate_credentials(scenario["credentialRefs"])
    _validate_limits(scenario["limits"])

    negotiation = _object(scenario["negotiation"], "$.negotiation")
    _exact_keys(
        negotiation,
        "$.negotiation",
        (
            "audioOnly",
            "trickleIce",
            "iceRestart",
            "requireRtcpMux",
            "requireBundle",
        ),
    )
    for key, item in negotiation.items():
        if not isinstance(item, bool):
            raise ContractError(f"$.negotiation.{key} must be boolean")
    if negotiation["audioOnly"] is not True:
        raise ContractError("v1 supports audio-only scenarios")
    if negotiation["trickleIce"] and "trickle-ice" not in required_capabilities:
        raise ContractError("trickleIce requires the trickle-ice adapter capability")
    if negotiation["iceRestart"] and "ice-restart" not in required_capabilities:
        raise ContractError("iceRestart requires the ice-restart adapter capability")

    evidence = _object(scenario["evidence"], "$.evidence")
    _exact_keys(
        evidence,
        "$.evidence",
        ("sensitivity", "retainRawAudio", "retainFullSdp"),
    )
    if evidence["sensitivity"] not in ("internal", "restricted"):
        raise ContractError("$.evidence.sensitivity is unsupported")
    if evidence["retainRawAudio"] is not False:
        raise ContractError("$.evidence.retainRawAudio must be false in v1")
    if not isinstance(evidence["retainFullSdp"], bool):
        raise ContractError("$.evidence.retainFullSdp must be boolean")
    if execution_class == "approved_target" and evidence["retainFullSdp"]:
        raise ContractError("approved_target cannot retain full SDP in v1")

    _scan_for_secrets(scenario)
    return scenario


def validate_result(document: Any) -> Mapping[str, Any]:
    """Validate result semantics and reject secret-bearing output."""

    result = _object(document, "$")
    _exact_keys(
        result,
        "$",
        (
            "apiVersion",
            "kind",
            "scenarioId",
            "status",
            "networkActivity",
            "summary",
            "events",
            "assertions",
            "evidence",
            "redactions",
        ),
    )
    if result["apiVersion"] != RESULT_VERSION:
        raise ContractError("$.apiVersion is unsupported")
    if result["kind"] != "WebRTCResult":
        raise ContractError("$.kind must be WebRTCResult")
    _string(result["scenarioId"], "$.scenarioId")
    status = _string(result["status"], "$.status")
    if status not in ("pass", "fail", "incomplete"):
        raise ContractError("$.status is unsupported")
    if not isinstance(result["networkActivity"], bool):
        raise ContractError("$.networkActivity must be boolean")

    summary = _object(result["summary"], "$.summary")
    _exact_keys(
        summary,
        "$.summary",
        ("assertions", "passed", "failed", "unknown", "notApplicable"),
    )
    counts = {
        key: _integer(value, f"$.summary.{key}", 0, 100000)
        for key, value in summary.items()
    }
    if counts["assertions"] != sum(
        counts[key] for key in ("passed", "failed", "unknown", "notApplicable")
    ):
        raise ContractError("$.summary assertion counts do not add up")

    events = _array(result["events"], "$.events")
    if len(events) > 100000:
        raise ContractError("$.events exceeds 100000 entries")
    last_sequence = -1
    for index, item in enumerate(events):
        path = f"$.events[{index}]"
        event = _object(item, path)
        _exact_keys(
            event,
            path,
            ("sequence", "source", "kind", "sensitivity", "data"),
        )
        sequence = _integer(event["sequence"], f"{path}.sequence", 0, 1000000000)
        if sequence <= last_sequence:
            raise ContractError("$.events sequences must be strictly increasing")
        last_sequence = sequence
        _string(event["source"], f"{path}.source")
        _string(event["kind"], f"{path}.kind")
        if event["sensitivity"] not in ("public", "internal", "restricted"):
            raise ContractError(f"{path}.sensitivity is unsupported")
        _object(event["data"], f"{path}.data")

    assertions = _array(result["assertions"], "$.assertions")
    if len(assertions) != counts["assertions"]:
        raise ContractError("$.summary.assertions does not match $.assertions")
    observed_counts = {key: 0 for key in VERDICTS}
    for index, item in enumerate(assertions):
        path = f"$.assertions[{index}]"
        assertion = _object(item, path)
        _exact_keys(
            assertion,
            path,
            ("id", "verdict", "unknownReason", "evidenceRefs"),
        )
        _string(assertion["id"], f"{path}.id")
        verdict = _string(assertion["verdict"], f"{path}.verdict")
        if verdict not in VERDICTS:
            raise ContractError(f"{path}.verdict is unsupported")
        observed_counts[verdict] += 1
        unknown_reason = assertion["unknownReason"]
        if verdict == "unknown":
            if unknown_reason not in UNKNOWN_REASONS:
                raise ContractError(f"{path}.unknownReason is required and unsupported")
        elif unknown_reason is not None:
            raise ContractError(
                f"{path}.unknownReason must be null unless verdict is unknown"
            )
        refs = _array(assertion["evidenceRefs"], f"{path}.evidenceRefs")
        if len(refs) != len(set(refs)):
            raise ContractError(f"{path}.evidenceRefs must be unique")
        for ref_index, ref in enumerate(refs):
            _string(ref, f"{path}.evidenceRefs[{ref_index}]")

    expected_counts = {
        "pass": counts["passed"],
        "fail": counts["failed"],
        "unknown": counts["unknown"],
        "not_applicable": counts["notApplicable"],
    }
    if observed_counts != expected_counts:
        raise ContractError("$.summary verdict counts do not match $.assertions")
    if status == "pass" and (counts["failed"] or counts["unknown"]):
        raise ContractError("pass status cannot contain fail or unknown assertions")
    if status == "fail" and not counts["failed"]:
        raise ContractError("fail status requires at least one failed assertion")
    if status == "incomplete" and not counts["unknown"]:
        raise ContractError("incomplete status requires at least one unknown assertion")

    evidence = _array(result["evidence"], "$.evidence")
    evidence_ids: set[str] = set()
    for index, item in enumerate(evidence):
        path = f"$.evidence[{index}]"
        artifact = _object(item, path)
        _exact_keys(
            artifact,
            path,
            ("artifactId", "sha256", "mediaType", "sensitivity"),
        )
        artifact_id = _string(artifact["artifactId"], f"{path}.artifactId")
        if artifact_id in evidence_ids:
            raise ContractError(f"{path}.artifactId must be unique")
        evidence_ids.add(artifact_id)
        if not _SHA256.fullmatch(_string(artifact["sha256"], f"{path}.sha256")):
            raise ContractError(f"{path}.sha256 must be lowercase hexadecimal")
        _string(artifact["mediaType"], f"{path}.mediaType")
        if artifact["sensitivity"] not in ("public", "internal", "restricted"):
            raise ContractError(f"{path}.sensitivity is unsupported")
    referenced = {
        ref
        for assertion in assertions
        for ref in assertion["evidenceRefs"]
    }
    missing_evidence = referenced - evidence_ids
    if missing_evidence:
        raise ContractError(
            "assertions reference unknown evidence: "
            + ", ".join(sorted(missing_evidence))
        )

    redactions = _object(result["redactions"], "$.redactions")
    _exact_keys(redactions, "$.redactions", ("count", "classes"))
    _integer(redactions["count"], "$.redactions.count", 0, 1000000)
    classes = _array(redactions["classes"], "$.redactions.classes")
    if len(classes) != len(set(classes)):
        raise ContractError("$.redactions.classes must be unique")
    for index, item in enumerate(classes):
        _string(item, f"$.redactions.classes[{index}]")

    _scan_for_secrets(result)
    return result
