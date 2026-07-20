"""Cross-layer, privacy-preserving WebRTC call evidence correlation."""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping

POLICY_VERSION = "sippycup.dev/webrtc-call-policy/v1"
EVIDENCE_VERSION = "sippycup.dev/webrtc-call-evidence/v1"
REPORT_VERSION = "sippycup.dev/webrtc-call-report/v1"
MAX_INPUT_BYTES = 4 * 1024 * 1024
_HASH = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


class CallEvidenceError(ValueError):
    pass


def _object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CallEvidenceError(f"{path} must be an object")
    return value


def _array(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise CallEvidenceError(f"{path} must be an array")
    return value


def _exact(value: Mapping[str, Any], path: str, required: set[str]) -> None:
    missing = required - set(value)
    extra = set(value) - required
    if missing:
        raise CallEvidenceError(f"{path} is missing: {', '.join(sorted(missing))}")
    if extra:
        raise CallEvidenceError(f"{path} has unknown fields: {', '.join(sorted(extra))}")


def _integer(value: Any, path: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CallEvidenceError(f"{path} must be an integer")
    if not minimum <= value <= maximum:
        raise CallEvidenceError(f"{path} must be between {minimum} and {maximum}")
    return value


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise CallEvidenceError(f"{path} must be boolean")
    return value


def _enum(value: Any, path: str, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise CallEvidenceError(f"{path} must be one of: {', '.join(sorted(allowed))}")
    return value


def _token(value: Any, path: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise CallEvidenceError(f"{path} must be a bounded token")
    return value


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise CallEvidenceError(f"{path} must be a SHA-256 digest")
    return value


def validate_policy(document: Any) -> dict[str, Any]:
    policy = dict(_object(document, "$"))
    _exact(policy, "$", {"apiVersion", "media", "recovery", "privacy", "limits"})
    if policy["apiVersion"] != POLICY_VERSION:
        raise CallEvidenceError("$.apiVersion is unsupported")
    media = _object(policy["media"], "$.media")
    _exact(
        media,
        "$.media",
        {
            "requiredDirections",
            "requireRtcpEvidence",
            "requireCanaryEvidence",
            "maxRoundTripLatencyMs",
        },
    )
    directions = _array(media["requiredDirections"], "$.media.requiredDirections")
    if not directions or len(directions) != len(set(directions)):
        raise CallEvidenceError("$.media.requiredDirections must be non-empty and unique")
    for index, item in enumerate(directions):
        _enum(item, f"$.media.requiredDirections[{index}]", {"outbound", "inbound"})
    _boolean(media["requireRtcpEvidence"], "$.media.requireRtcpEvidence")
    _boolean(media["requireCanaryEvidence"], "$.media.requireCanaryEvidence")
    _integer(
        media["maxRoundTripLatencyMs"],
        "$.media.maxRoundTripLatencyMs",
        1,
        300000,
    )
    recovery = _object(policy["recovery"], "$.recovery")
    _exact(recovery, "$.recovery", {"maxDowntimeMs", "requireRecoveryEvidence"})
    _integer(recovery["maxDowntimeMs"], "$.recovery.maxDowntimeMs", 0, 300000)
    _boolean(recovery["requireRecoveryEvidence"], "$.recovery.requireRecoveryEvidence")
    privacy = _object(policy["privacy"], "$.privacy")
    _exact(
        privacy,
        "$.privacy",
        {
            "requireCandidateAddressRedaction",
            "requireCredentialRedaction",
            "requireBrowserMetadataRedaction",
            "retainRawAudio",
        },
    )
    for key in privacy:
        _boolean(privacy[key], f"$.privacy.{key}")
    if privacy["retainRawAudio"]:
        raise CallEvidenceError("$.privacy.retainRawAudio must be false in v1")
    limits = _object(policy["limits"], "$.limits")
    _exact(limits, "$.limits", {"maxEvents", "maxGenerations", "maxSsrcs"})
    _integer(limits["maxEvents"], "$.limits.maxEvents", 1, 100000)
    _integer(limits["maxGenerations"], "$.limits.maxGenerations", 1, 1024)
    _integer(limits["maxSsrcs"], "$.limits.maxSsrcs", 1, 4096)
    return policy


_EVENT_FIELDS = {
    "revision": {"generation", "revisionHash"},
    "ice_pair": {"generation", "pairIdHash", "sequence", "reason"},
    "dtls_association": {"generation", "associationIdHash"},
    "srtp_stream": {"generation", "associationIdHash", "ssrc", "direction"},
    "srtcp_stream": {"generation", "associationIdHash", "ssrc", "direction"},
    "audio": {
        "generation",
        "direction",
        "measurementStatus",
        "continuity",
        "roundTripLatencyMs",
        "canaryAssetHash",
    },
    "recovery": {"generation", "outcome", "downtimeMs"},
}


def validate_evidence(document: Any, policy_document: Any) -> dict[str, Any]:
    policy = validate_policy(policy_document)
    evidence = dict(_object(document, "$"))
    _exact(evidence, "$", {"apiVersion", "networkActivity", "callIdHash", "components", "events"})
    if evidence["apiVersion"] != EVIDENCE_VERSION:
        raise CallEvidenceError("$.apiVersion is unsupported")
    _boolean(evidence["networkActivity"], "$.networkActivity")
    _digest(evidence["callIdHash"], "$.callIdHash")
    components = _array(evidence["components"], "$.components")
    if not components or len(components) > 64:
        raise CallEvidenceError("$.components must contain 1 to 64 entries")
    identities = []
    for index, item in enumerate(components):
        path = f"$.components[{index}]"
        component = _object(item, path)
        _exact(component, path, {"kind", "status", "reportHash", "uncertainty"})
        identities.append(
            _enum(
                component["kind"],
                f"{path}.kind",
                {"sdp", "ice-turn", "dtls-srtp", "audio-outbound", "audio-inbound"},
            )
        )
        _enum(component["status"], f"{path}.status", {"pass", "fail", "incomplete"})
        _digest(component["reportHash"], f"{path}.reportHash")
        uncertainty = _array(component["uncertainty"], f"{path}.uncertainty")
        if len(uncertainty) > 32:
            raise CallEvidenceError(f"{path}.uncertainty exceeds 32 entries")
        for uncertainty_index, value in enumerate(uncertainty):
            _token(value, f"{path}.uncertainty[{uncertainty_index}]")
    if len(identities) != len(set(identities)):
        raise CallEvidenceError("$.components kinds must be unique")
    events = _array(evidence["events"], "$.events")
    if len(events) > policy["limits"]["maxEvents"]:
        raise CallEvidenceError("$.events exceeds the policy limit")
    last_time = -1
    for index, item in enumerate(events):
        path = f"$.events[{index}]"
        event = _object(item, path)
        _exact(event, path, {"timeMs", "type", "data"})
        time_ms = _integer(event["timeMs"], f"{path}.timeMs", 0, 3600000)
        if time_ms < last_time:
            raise CallEvidenceError("$.events timeMs values must be nondecreasing")
        last_time = time_ms
        kind = _enum(event["type"], f"{path}.type", set(_EVENT_FIELDS))
        data = _object(event["data"], f"{path}.data")
        _exact(data, f"{path}.data", _EVENT_FIELDS[kind])
        _integer(data["generation"], f"{path}.data.generation", 0, 65535)
        if kind == "revision":
            _digest(data["revisionHash"], f"{path}.data.revisionHash")
        elif kind == "ice_pair":
            _digest(data["pairIdHash"], f"{path}.data.pairIdHash")
            _integer(data["sequence"], f"{path}.data.sequence", 0, 65535)
            _enum(
                data["reason"],
                f"{path}.data.reason",
                {"initial", "reselection", "ice_restart"},
            )
        elif kind == "dtls_association":
            _digest(data["associationIdHash"], f"{path}.data.associationIdHash")
        elif kind in {"srtp_stream", "srtcp_stream"}:
            _digest(data["associationIdHash"], f"{path}.data.associationIdHash")
            _integer(data["ssrc"], f"{path}.data.ssrc", 0, 4294967295)
            _enum(data["direction"], f"{path}.data.direction", {"outbound", "inbound"})
        elif kind == "audio":
            _enum(data["direction"], f"{path}.data.direction", {"outbound", "inbound"})
            _enum(
                data["measurementStatus"],
                f"{path}.data.measurementStatus",
                {"measured", "not_measurable"},
            )
            _enum(data["continuity"], f"{path}.data.continuity", {"pass", "fail", "unknown"})
            canary_hash = data["canaryAssetHash"]
            if canary_hash is not None:
                _digest(canary_hash, f"{path}.data.canaryAssetHash")
            latency = data["roundTripLatencyMs"]
            if latency is not None and (
                isinstance(latency, bool)
                or not isinstance(latency, (int, float))
                or not 0 <= latency <= 300000
            ):
                raise CallEvidenceError(f"{path}.data.roundTripLatencyMs is invalid")
        elif kind == "recovery":
            _enum(data["outcome"], f"{path}.data.outcome", {"recovered", "failed", "unknown"})
            _integer(data["downtimeMs"], f"{path}.data.downtimeMs", 0, 300000)
    _privacy_scan(evidence, policy)
    return evidence


def _privacy_scan(value: Any, policy: Mapping[str, Any], path: str = "$") -> None:
    privacy = policy["privacy"]
    forbidden_keys = set()
    if privacy["requireCredentialRedaction"]:
        forbidden_keys |= {"iceUfrag", "icePwd", "token", "authorization", "cookie"}
    if privacy["requireCandidateAddressRedaction"]:
        forbidden_keys |= {"candidateAddress", "ipAddress", "address"}
    if privacy["requireBrowserMetadataRedaction"]:
        forbidden_keys |= {"userAgent", "deviceId", "browserVersion", "deviceLabel"}
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key in forbidden_keys:
                raise CallEvidenceError(f"{path}.{key} contains forbidden private evidence")
            _privacy_scan(item, policy, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _privacy_scan(item, policy, f"{path}[{index}]")
    elif isinstance(value, str):
        lowered = value.lower()
        if privacy["requireCandidateAddressRedaction"]:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                pass
            else:
                raise CallEvidenceError(f"{path} contains a literal candidate address")
            if any(
                marker in lowered
                for marker in ("candidate:", "typ host", "typ srflx", "typ relay")
            ):
                raise CallEvidenceError(f"{path} contains a raw candidate")
        if privacy["requireCredentialRedaction"] and any(
            marker in lowered
            for marker in (
                "ice-pwd",
                "ice-ufrag",
                "authorization",
                "bearer",
                "cookie",
            )
        ):
            raise CallEvidenceError(f"{path} contains credential material")
        if privacy["requireBrowserMetadataRedaction"] and any(
            marker in lowered
            for marker in ("mozilla/", "chrome/", "firefox/", "deviceid")
        ):
            raise CallEvidenceError(f"{path} contains browser or device metadata")


def evaluate(policy_document: Any, evidence_document: Any) -> dict[str, Any]:
    policy = validate_policy(policy_document)
    evidence = validate_evidence(evidence_document, policy)
    findings: list[dict[str, Any]] = []
    unknowns: list[dict[str, Any]] = []

    def fail(code: str, generation: int, detail: str) -> None:
        findings.append({"code": code, "generation": generation, "detail": detail})

    components = {item["kind"]: item for item in evidence["components"]}
    required_components = {"sdp", "ice-turn", "dtls-srtp"}
    required_components.update(
        f"audio-{direction}" for direction in policy["media"]["requiredDirections"]
    )
    for required in sorted(required_components):
        if required not in components:
            unknowns.append({"code": "call.component_missing", "component": required})
    for component in evidence["components"]:
        if component["status"] == "fail":
            fail("call.component_failed", -1, component["kind"])
        elif component["status"] == "incomplete" or component["uncertainty"]:
            unknowns.append(
                {"code": "call.component_uncertain", "component": component["kind"]}
            )

    by_generation: dict[int, dict[str, list[Mapping[str, Any]]]] = {}
    for event in evidence["events"]:
        generation = event["data"]["generation"]
        by_generation.setdefault(generation, {}).setdefault(event["type"], []).append(
            event["data"]
        )
    for generation, layers in sorted(by_generation.items()):
        for layer in ("revision", "ice_pair", "dtls_association", "srtp_stream"):
            if layer not in layers:
                unknowns.append(
                    {
                        "code": "call.layer_missing",
                        "generation": generation,
                        "layer": layer,
                    }
                )
        for singleton in ("revision", "dtls_association"):
            if len(layers.get(singleton, [])) > 1:
                fail("call.layer_ambiguous", generation, singleton)
        ice_pairs = layers.get("ice_pair", [])
        ice_sequences = [item["sequence"] for item in ice_pairs]
        if ice_sequences != list(range(len(ice_pairs))):
            fail("call.ice_pair_sequence_invalid", generation, repr(ice_sequences))
        if ice_pairs:
            expected_reason = "initial" if generation == 0 else "ice_restart"
            if ice_pairs[0]["reason"] != expected_reason:
                fail(
                    "call.ice_generation_reason_invalid",
                    generation,
                    ice_pairs[0]["reason"],
                )
            if any(item["reason"] == "initial" for item in ice_pairs[1:]):
                fail("call.ice_reselection_reason_invalid", generation, "initial")
        associations = {
            item["associationIdHash"]
            for item in layers.get("dtls_association", [])
        }
        for stream in layers.get("srtp_stream", []) + layers.get("srtcp_stream", []):
            if stream["associationIdHash"] not in associations:
                fail(
                    "call.media_dtls_mismatch",
                    generation,
                    f"{stream['direction']}:{stream['ssrc']}",
                )
        audio_directions = {
            item["direction"] for item in layers.get("audio", [])
        }
        stream_directions = {
            item["direction"] for item in layers.get("srtp_stream", [])
        }
        rtcp_directions = {
            item["direction"] for item in layers.get("srtcp_stream", [])
        }
        stream_ssrcs = {
            (item["direction"], item["ssrc"])
            for item in layers.get("srtp_stream", [])
        }
        for rtcp in layers.get("srtcp_stream", []):
            if (rtcp["direction"], rtcp["ssrc"]) not in stream_ssrcs:
                fail(
                    "call.srtcp_without_rtp_stream",
                    generation,
                    f"{rtcp['direction']}:{rtcp['ssrc']}",
                )
        for direction in policy["media"]["requiredDirections"]:
            if direction not in stream_directions:
                unknowns.append(
                    {
                        "code": "call.stream_direction_missing",
                        "generation": generation,
                        "direction": direction,
                    }
                )
            if direction not in audio_directions:
                unknowns.append(
                    {
                        "code": "call.audio_direction_missing",
                        "generation": generation,
                        "direction": direction,
                    }
                )
            if (
                policy["media"]["requireRtcpEvidence"]
                and direction not in rtcp_directions
            ):
                unknowns.append(
                    {
                        "code": "call.srtcp_direction_missing",
                        "generation": generation,
                        "direction": direction,
                    }
                )
        for audio in layers.get("audio", []):
            if audio["continuity"] == "fail":
                fail("call.audio_continuity_failed", generation, audio["direction"])
            if (
                audio["measurementStatus"] == "not_measurable"
                or audio["continuity"] == "unknown"
            ):
                unknowns.append(
                    {
                        "code": "call.audio_not_measurable",
                        "generation": generation,
                        "direction": audio["direction"],
                    }
                )
            if (
                policy["media"]["requireCanaryEvidence"]
                and audio["canaryAssetHash"] is None
            ):
                unknowns.append(
                    {
                        "code": "call.canary_not_observed",
                        "generation": generation,
                        "direction": audio["direction"],
                    }
                )
            latency = audio["roundTripLatencyMs"]
            if audio["measurementStatus"] == "measured" and latency is None:
                unknowns.append(
                    {
                        "code": "call.latency_not_observed",
                        "generation": generation,
                        "direction": audio["direction"],
                    }
                )
            elif (
                latency is not None
                and latency > policy["media"]["maxRoundTripLatencyMs"]
            ):
                fail(
                    "call.latency_ceiling_exceeded",
                    generation,
                    f"{audio['direction']}:{latency}",
                )
        recoveries = layers.get("recovery", [])
        needs_recovery = generation > 0 or len(ice_pairs) > 1
        if (
            policy["recovery"]["requireRecoveryEvidence"]
            and needs_recovery
            and not recoveries
        ):
            unknowns.append({"code": "call.recovery_missing", "generation": generation})
        for recovery in recoveries:
            if recovery["outcome"] == "failed":
                fail("call.recovery_failed", generation, str(recovery["downtimeMs"]))
            elif recovery["outcome"] == "unknown":
                unknowns.append({"code": "call.recovery_unknown", "generation": generation})
            if recovery["downtimeMs"] > policy["recovery"]["maxDowntimeMs"]:
                fail("call.recovery_too_slow", generation, str(recovery["downtimeMs"]))

    generations = set(by_generation)
    if generations and generations != set(range(max(generations) + 1)):
        fail("call.generation_sequence_invalid", -1, repr(sorted(generations)))
    ssrcs = {
        item["ssrc"]
        for layers in by_generation.values()
        for item in layers.get("srtp_stream", [])
    }
    if len(generations) > policy["limits"]["maxGenerations"]:
        fail("limits.generation_ceiling_exceeded", -1, str(len(generations)))
    if len(ssrcs) > policy["limits"]["maxSsrcs"]:
        fail("limits.ssrc_ceiling_exceeded", -1, str(len(ssrcs)))
    if not generations:
        unknowns.append({"code": "call.no_timeline"})
    status = "fail" if findings else ("incomplete" if unknowns else "pass")
    return {
        "apiVersion": REPORT_VERSION,
        "status": status,
        "networkActivity": False,
        "observedNetworkActivity": evidence["networkActivity"],
        "callIdHash": evidence["callIdHash"],
        "generations": len(generations),
        "ssrcs": len(ssrcs),
        "findings": findings,
        "unknowns": unknowns,
        "privacy": {
            "candidateAddressesRetained": False,
            "credentialsRetained": False,
            "browserMetadataRetained": False,
            "rawAudioRetained": False,
        },
        "capacityClaim": None,
    }


def _read(path: str) -> Any:
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise CallEvidenceError(f"input must be a regular non-symlink file: {path}")
    if candidate.stat().st_size > MAX_INPUT_BYTES:
        raise CallEvidenceError(f"input exceeds {MAX_INPUT_BYTES} bytes: {path}")
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CallEvidenceError(f"cannot read JSON input {path}: {exc}") from exc


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="webrtc-call-evidence",
        description="Correlate normalized WebRTC call evidence offline.",
    )
    parser.add_argument("policy")
    parser.add_argument("evidence")
    parsed = parser.parse_args(arguments)
    try:
        report = evaluate(_read(parsed.policy), _read(parsed.evidence))
    except CallEvidenceError as exc:
        print(f"WebRTC call evidence rejected: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return {"pass": 0, "fail": 1, "incomplete": 3}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
