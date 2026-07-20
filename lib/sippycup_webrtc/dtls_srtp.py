"""Offline DTLS-SRTP identity and media-security evidence oracle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping

POLICY_VERSION = "sippycup.dev/dtls-srtp-policy/v1"
OBSERVATION_VERSION = "sippycup.dev/dtls-srtp-observation/v1"
REPORT_VERSION = "sippycup.dev/dtls-srtp-report/v1"
MAX_INPUT_BYTES = 4 * 1024 * 1024
_HASH = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_.:+/-]{1,128}$")


class MediaSecurityError(ValueError):
    """Strict DTLS-SRTP evidence validation failed."""


def _object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise MediaSecurityError(f"{path} must be an object")
    return value


def _array(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise MediaSecurityError(f"{path} must be an array")
    return value


def _exact(
    value: Mapping[str, Any],
    path: str,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    missing = required - set(value)
    extra = set(value) - required - optional
    if missing:
        raise MediaSecurityError(f"{path} is missing: {', '.join(sorted(missing))}")
    if extra:
        raise MediaSecurityError(
            f"{path} has unknown fields: {', '.join(sorted(extra))}"
        )


def _integer(value: Any, path: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MediaSecurityError(f"{path} must be an integer")
    if not minimum <= value <= maximum:
        raise MediaSecurityError(f"{path} must be between {minimum} and {maximum}")
    return value


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise MediaSecurityError(f"{path} must be boolean")
    return value


def _enum(value: Any, path: str, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise MediaSecurityError(f"{path} must be one of: {', '.join(sorted(allowed))}")
    return value


def _token(value: Any, path: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise MediaSecurityError(f"{path} must be a bounded token")
    return value


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise MediaSecurityError(f"{path} must be a SHA-256 digest")
    return value


def _unique_tokens(value: Any, path: str, maximum: int) -> list[str]:
    items = _array(value, path)
    if not items or len(items) > maximum:
        raise MediaSecurityError(f"{path} must contain 1 to {maximum} entries")
    result = [_token(item, f"{path}[{index}]") for index, item in enumerate(items)]
    if len(result) != len(set(result)):
        raise MediaSecurityError(f"{path} must contain unique values")
    return result


def validate_policy(document: Any) -> dict[str, Any]:
    policy = dict(_object(document, "$"))
    _exact(policy, "$", {"apiVersion", "dtls", "srtp", "limits"})
    if policy["apiVersion"] != POLICY_VERSION:
        raise MediaSecurityError("$.apiVersion is unsupported")
    dtls = _object(policy["dtls"], "$.dtls")
    _exact(
        dtls,
        "$.dtls",
        {
            "allowedVersions",
            "allowedCiphers",
            "allowedRolePairs",
            "requireVerifiedFingerprint",
            "requireDowngradeProbe",
        },
    )
    versions = _unique_tokens(dtls["allowedVersions"], "$.dtls.allowedVersions", 4)
    if not set(versions) <= {"DTLS1.2", "DTLS1.3"}:
        raise MediaSecurityError("$.dtls.allowedVersions contains an unsupported value")
    _unique_tokens(dtls["allowedCiphers"], "$.dtls.allowedCiphers", 32)
    pairs = _array(dtls["allowedRolePairs"], "$.dtls.allowedRolePairs")
    if not pairs or len(pairs) > 4:
        raise MediaSecurityError("$.dtls.allowedRolePairs must contain 1 to 4 pairs")
    normalized_pairs = []
    for index, item in enumerate(pairs):
        path = f"$.dtls.allowedRolePairs[{index}]"
        pair = _object(item, path)
        _exact(pair, path, {"local", "remote"})
        normalized_pairs.append(
            (
                _enum(pair["local"], f"{path}.local", {"client", "server"}),
                _enum(pair["remote"], f"{path}.remote", {"client", "server"}),
            )
        )
    if len(normalized_pairs) != len(set(normalized_pairs)):
        raise MediaSecurityError("$.dtls.allowedRolePairs must be unique")
    for key in ("requireVerifiedFingerprint", "requireDowngradeProbe"):
        _boolean(dtls[key], f"$.dtls.{key}")

    srtp = _object(policy["srtp"], "$.srtp")
    _exact(
        srtp,
        "$.srtp",
        {
            "allowedProfiles",
            "requireDistinctRtpRtcpKeys",
            "requireRtcpProtection",
            "requireRekeyOnIceRestart",
            "maxSequenceGap",
        },
    )
    _unique_tokens(srtp["allowedProfiles"], "$.srtp.allowedProfiles", 16)
    for key in (
        "requireDistinctRtpRtcpKeys",
        "requireRtcpProtection",
        "requireRekeyOnIceRestart",
    ):
        _boolean(srtp[key], f"$.srtp.{key}")
    _integer(srtp["maxSequenceGap"], "$.srtp.maxSequenceGap", 1, 65536)

    limits = _object(policy["limits"], "$.limits")
    _exact(
        limits,
        "$.limits",
        {"maxEvents", "maxPackets", "maxSsrcs", "maxEpochs", "maxDurationMs"},
    )
    _integer(limits["maxEvents"], "$.limits.maxEvents", 1, 100000)
    _integer(limits["maxPackets"], "$.limits.maxPackets", 1, 10000000)
    _integer(limits["maxSsrcs"], "$.limits.maxSsrcs", 1, 4096)
    _integer(limits["maxEpochs"], "$.limits.maxEpochs", 1, 1024)
    _integer(limits["maxDurationMs"], "$.limits.maxDurationMs", 1, 3600000)
    return policy


_EVENT_FIELDS = {
    "dtls_handshake": {
        "side",
        "role",
        "version",
        "cipher",
        "sdpFingerprintHash",
        "certificateFingerprintHash",
        "verified",
    },
    "downgrade_probe": {"offeredVersion", "outcome", "reachedMedia"},
    "srtp_context": {
        "side",
        "profile",
        "rtpKeyIdHash",
        "rtcpKeyIdHash",
        "epoch",
        "ssrc",
    },
    "rtp_packet": {
        "direction",
        "ssrc",
        "sequence",
        "roc",
        "accepted",
        "replay",
        "authValid",
    },
    "rtcp_packet": {
        "direction",
        "ssrc",
        "index",
        "encrypted",
        "authValid",
        "accepted",
        "replay",
    },
    "rekey": {
        "side",
        "reason",
        "oldEpoch",
        "newEpoch",
        "oldKeyIdHash",
        "newKeyIdHash",
    },
    "ice_restart": {"generation"},
    "failure": {"stage", "closure", "code"},
    "cleanup": {"contexts", "sockets"},
}


def _validate_event_data(kind: str, data: Mapping[str, Any], path: str) -> None:
    if kind == "dtls_handshake":
        _enum(data["side"], f"{path}.side", {"local", "remote"})
        _enum(data["role"], f"{path}.role", {"client", "server"})
        _enum(data["version"], f"{path}.version", {"DTLS1.0", "DTLS1.2", "DTLS1.3"})
        _token(data["cipher"], f"{path}.cipher")
        _digest(data["sdpFingerprintHash"], f"{path}.sdpFingerprintHash")
        _digest(
            data["certificateFingerprintHash"],
            f"{path}.certificateFingerprintHash",
        )
        _boolean(data["verified"], f"{path}.verified")
    elif kind == "downgrade_probe":
        _enum(
            data["offeredVersion"],
            f"{path}.offeredVersion",
            {"DTLS1.0", "DTLS1.2", "DTLS1.3"},
        )
        _enum(data["outcome"], f"{path}.outcome", {"rejected", "connected", "timeout"})
        _boolean(data["reachedMedia"], f"{path}.reachedMedia")
    elif kind == "srtp_context":
        _enum(data["side"], f"{path}.side", {"local", "remote"})
        _token(data["profile"], f"{path}.profile")
        _digest(data["rtpKeyIdHash"], f"{path}.rtpKeyIdHash")
        _digest(data["rtcpKeyIdHash"], f"{path}.rtcpKeyIdHash")
        _integer(data["epoch"], f"{path}.epoch", 0, 65535)
        _integer(data["ssrc"], f"{path}.ssrc", 0, 4294967295)
    elif kind == "rtp_packet":
        _enum(data["direction"], f"{path}.direction", {"outbound", "inbound"})
        _integer(data["ssrc"], f"{path}.ssrc", 0, 4294967295)
        _integer(data["sequence"], f"{path}.sequence", 0, 65535)
        _integer(data["roc"], f"{path}.roc", 0, 4294967295)
        for key in ("accepted", "replay", "authValid"):
            _boolean(data[key], f"{path}.{key}")
    elif kind == "rtcp_packet":
        _enum(data["direction"], f"{path}.direction", {"outbound", "inbound"})
        _integer(data["ssrc"], f"{path}.ssrc", 0, 4294967295)
        _integer(data["index"], f"{path}.index", 0, 2147483647)
        for key in ("encrypted", "authValid", "accepted", "replay"):
            _boolean(data[key], f"{path}.{key}")
    elif kind == "rekey":
        _enum(data["side"], f"{path}.side", {"local", "remote"})
        _enum(data["reason"], f"{path}.reason", {"ice_restart", "renegotiation"})
        _integer(data["oldEpoch"], f"{path}.oldEpoch", 0, 65535)
        _integer(data["newEpoch"], f"{path}.newEpoch", 0, 65535)
        _digest(data["oldKeyIdHash"], f"{path}.oldKeyIdHash")
        _digest(data["newKeyIdHash"], f"{path}.newKeyIdHash")
    elif kind == "ice_restart":
        _integer(data["generation"], f"{path}.generation", 1, 65535)
    elif kind == "failure":
        _enum(
            data["stage"],
            f"{path}.stage",
            {"fingerprint", "handshake", "srtp", "rtcp", "rekey"},
        )
        _enum(
            data["closure"],
            f"{path}.closure",
            {"closed", "media-blocked", "continued"},
        )
        _token(data["code"], f"{path}.code")
    elif kind == "cleanup":
        _integer(data["contexts"], f"{path}.contexts", 0, 100000)
        _integer(data["sockets"], f"{path}.sockets", 0, 100000)


def validate_observation(document: Any, policy_document: Any) -> dict[str, Any]:
    policy = validate_policy(policy_document)
    observation = dict(_object(document, "$"))
    _exact(observation, "$", {"apiVersion", "networkActivity", "events"})
    if observation["apiVersion"] != OBSERVATION_VERSION:
        raise MediaSecurityError("$.apiVersion is unsupported")
    _boolean(observation["networkActivity"], "$.networkActivity")
    events = _array(observation["events"], "$.events")
    if len(events) > policy["limits"]["maxEvents"]:
        raise MediaSecurityError("$.events exceeds the policy limit")
    last_time = -1
    for index, item in enumerate(events):
        path = f"$.events[{index}]"
        event = _object(item, path)
        _exact(event, path, {"timeMs", "type", "data"})
        time_ms = _integer(event["timeMs"], f"{path}.timeMs", 0, 3600000)
        if time_ms < last_time:
            raise MediaSecurityError("$.events timeMs values must be nondecreasing")
        last_time = time_ms
        kind = _enum(event["type"], f"{path}.type", set(_EVENT_FIELDS))
        data = _object(event["data"], f"{path}.data")
        _exact(data, f"{path}.data", _EVENT_FIELDS[kind])
        _validate_event_data(kind, data, f"{path}.data")
    return observation


def evaluate(policy_document: Any, observation_document: Any) -> dict[str, Any]:
    policy = validate_policy(policy_document)
    observation = validate_observation(observation_document, policy)
    findings: list[dict[str, Any]] = []
    unknowns: list[dict[str, Any]] = []

    def fail(code: str, event: int, detail: str) -> None:
        findings.append(
            {"severity": "fail", "code": code, "event": event, "detail": detail}
        )

    handshakes: dict[str, Mapping[str, Any]] = {}
    contexts: dict[str, list[Mapping[str, Any]]] = {"local": [], "remote": []}
    downgrade_seen = False
    cleanup_seen = False
    ice_rekeys: set[str] = set()
    ice_restart_seen = False
    last_rtp: dict[tuple[str, int], int] = {}
    last_rtcp: dict[tuple[str, int], int] = {}
    ssrcs: set[int] = set()
    epochs: set[int] = set()
    packet_count = 0
    rtp_seen = False
    rtcp_seen = False
    last_context_epoch: dict[str, int] = {}
    context_key_epochs: dict[str, dict[str, int]] = {"local": {}, "remote": {}}

    for index, event in enumerate(observation["events"]):
        kind = event["type"]
        data = event["data"]
        if kind == "dtls_handshake":
            side = data["side"]
            if side in handshakes:
                fail("dtls.duplicate_handshake", index, side)
            handshakes[side] = data
            if data["version"] not in policy["dtls"]["allowedVersions"]:
                fail("dtls.version_disallowed", index, data["version"])
            if data["cipher"] not in policy["dtls"]["allowedCiphers"]:
                fail("dtls.cipher_disallowed", index, data["cipher"])
            if (
                data["sdpFingerprintHash"]
                != data["certificateFingerprintHash"]
            ):
                fail("dtls.fingerprint_mismatch", index, side)
            if policy["dtls"]["requireVerifiedFingerprint"] and not data["verified"]:
                fail("dtls.fingerprint_unverified", index, side)
        elif kind == "downgrade_probe":
            downgrade_seen = True
            if data["offeredVersion"] not in policy["dtls"]["allowedVersions"]:
                if data["outcome"] == "connected":
                    fail("dtls.downgrade_accepted", index, data["offeredVersion"])
                if data["reachedMedia"]:
                    fail("dtls.downgrade_reached_media", index, data["offeredVersion"])
        elif kind == "srtp_context":
            side = data["side"]
            contexts[side].append(data)
            ssrcs.add(data["ssrc"])
            epochs.add(data["epoch"])
            previous_epoch = last_context_epoch.get(side)
            if previous_epoch is not None:
                if data["epoch"] < previous_epoch:
                    fail("srtp.context_epoch_regression", index, side)
                elif data["epoch"] > previous_epoch + 1:
                    fail("srtp.context_epoch_gap", index, side)
            last_context_epoch[side] = max(previous_epoch or 0, data["epoch"])
            for key_name in ("rtpKeyIdHash", "rtcpKeyIdHash"):
                identifier = data[key_name]
                prior_key_epoch = context_key_epochs[side].get(identifier)
                if prior_key_epoch is not None and prior_key_epoch != data["epoch"]:
                    fail("srtp.key_reused_across_epochs", index, f"{side}:{key_name}")
                context_key_epochs[side][identifier] = data["epoch"]
            if data["profile"] not in policy["srtp"]["allowedProfiles"]:
                fail("srtp.profile_disallowed", index, data["profile"])
            if (
                policy["srtp"]["requireDistinctRtpRtcpKeys"]
                and data["rtpKeyIdHash"] == data["rtcpKeyIdHash"]
            ):
                fail("srtp.rtp_rtcp_key_reuse", index, side)
        elif kind == "rtp_packet":
            rtp_seen = True
            packet_count += 1
            expected_side = "local" if data["direction"] == "outbound" else "remote"
            if data["ssrc"] not in {item["ssrc"] for item in contexts[expected_side]}:
                fail("srtp.packet_without_context", index, repr((data["direction"], data["ssrc"])))
            ssrcs.add(data["ssrc"])
            key = (data["direction"], data["ssrc"])
            extended = (data["roc"] << 16) | data["sequence"]
            previous = last_rtp.get(key)
            if data["replay"] and data["accepted"]:
                fail("srtp.replay_accepted", index, repr(key))
            if not data["authValid"] and data["accepted"]:
                fail("srtp.invalid_auth_accepted", index, repr(key))
            if data["accepted"] and previous is not None:
                if extended <= previous:
                    fail("srtp.sequence_regression", index, repr(key))
                elif extended - previous > policy["srtp"]["maxSequenceGap"]:
                    fail(
                        "srtp.sequence_gap_exceeded",
                        index,
                        str(extended - previous),
                    )
            if data["accepted"]:
                last_rtp[key] = max(previous or 0, extended)
        elif kind == "rtcp_packet":
            rtcp_seen = True
            packet_count += 1
            expected_side = "local" if data["direction"] == "outbound" else "remote"
            if data["ssrc"] not in {item["ssrc"] for item in contexts[expected_side]}:
                fail("srtcp.packet_without_context", index, repr((data["direction"], data["ssrc"])))
            ssrcs.add(data["ssrc"])
            key = (data["direction"], data["ssrc"])
            previous = last_rtcp.get(key)
            if policy["srtp"]["requireRtcpProtection"] and not data["encrypted"]:
                fail("srtcp.unencrypted", index, repr(key))
            if data["replay"] and data["accepted"]:
                fail("srtcp.replay_accepted", index, repr(key))
            if not data["authValid"] and data["accepted"]:
                fail("srtcp.invalid_auth_accepted", index, repr(key))
            if data["accepted"] and previous is not None and data["index"] <= previous:
                fail("srtcp.index_regression", index, repr(key))
            if data["accepted"]:
                last_rtcp[key] = max(previous or 0, data["index"])
        elif kind == "rekey":
            side = data["side"]
            if data["oldKeyIdHash"] == data["newKeyIdHash"]:
                fail("srtp.rekey_reused_key", index, side)
            if data["newEpoch"] != data["oldEpoch"] + 1:
                fail("srtp.rekey_epoch_invalid", index, side)
            epochs.update({data["oldEpoch"], data["newEpoch"]})
            if data["reason"] == "ice_restart":
                ice_rekeys.add(side)
        elif kind == "ice_restart":
            ice_restart_seen = True
        elif kind == "failure":
            if data["closure"] == "continued":
                fail("media.failure_not_closed", index, f"{data['stage']}:{data['code']}")
        elif kind == "cleanup":
            cleanup_seen = True
            if data["contexts"] or data["sockets"]:
                fail(
                    "media.cleanup_incomplete",
                    index,
                    f"contexts={data['contexts']} sockets={data['sockets']}",
                )

    if set(handshakes) != {"local", "remote"}:
        unknowns.append({"code": "dtls.both_handshakes_not_observed"})
    else:
        roles = (handshakes["local"]["role"], handshakes["remote"]["role"])
        allowed_pairs = {
            (item["local"], item["remote"])
            for item in policy["dtls"]["allowedRolePairs"]
        }
        if roles not in allowed_pairs:
            fail("dtls.role_pair_invalid", -1, f"{roles[0]}/{roles[1]}")
        if (
            handshakes["local"]["version"] != handshakes["remote"]["version"]
            or handshakes["local"]["cipher"] != handshakes["remote"]["cipher"]
        ):
            fail("dtls.peer_observation_mismatch", -1, "version or cipher")
    if policy["dtls"]["requireDowngradeProbe"] and not downgrade_seen:
        unknowns.append({"code": "dtls.downgrade_probe_not_observed"})
    for side, values in contexts.items():
        if not values:
            unknowns.append({"code": "srtp.context_not_observed", "side": side})
        profiles = {item["profile"] for item in values}
        if len(profiles) > 1:
            fail("srtp.profile_changed_without_negotiation", -1, side)
    if contexts["local"] and contexts["remote"]:
        if contexts["local"][-1]["profile"] != contexts["remote"][-1]["profile"]:
            fail("srtp.peer_profile_mismatch", -1, "local/remote")
    for event in observation["events"]:
        if event["type"] != "rekey":
            continue
        data = event["data"]
        old_matches = any(
            item["epoch"] == data["oldEpoch"]
            and item["rtpKeyIdHash"] == data["oldKeyIdHash"]
            for item in contexts[data["side"]]
        )
        new_matches = any(
            item["epoch"] == data["newEpoch"]
            and item["rtpKeyIdHash"] == data["newKeyIdHash"]
            for item in contexts[data["side"]]
        )
        if not old_matches or not new_matches:
            fail("srtp.rekey_context_mismatch", -1, data["side"])
    if policy["srtp"]["requireRekeyOnIceRestart"] and ice_restart_seen:
        if ice_rekeys != {"local", "remote"}:
            fail("srtp.incomplete_ice_restart_rekey", -1, ",".join(sorted(ice_rekeys)))
    if not rtp_seen:
        unknowns.append({"code": "srtp.packet_evidence_not_observed"})
    if policy["srtp"]["requireRtcpProtection"] and not rtcp_seen:
        unknowns.append({"code": "srtcp.packet_evidence_not_observed"})
    if not cleanup_seen:
        unknowns.append({"code": "media.cleanup_not_observed"})

    limits = policy["limits"]
    duration = observation["events"][-1]["timeMs"] if observation["events"] else 0
    if packet_count > limits["maxPackets"]:
        fail("limits.packet_ceiling_exceeded", -1, str(packet_count))
    if len(ssrcs) > limits["maxSsrcs"]:
        fail("limits.ssrc_ceiling_exceeded", -1, str(len(ssrcs)))
    if len(epochs) > limits["maxEpochs"]:
        fail("limits.epoch_ceiling_exceeded", -1, str(len(epochs)))
    if duration > limits["maxDurationMs"]:
        fail("limits.duration_ceiling_exceeded", -1, str(duration))
    status = "fail" if findings else ("incomplete" if unknowns else "pass")
    return {
        "apiVersion": REPORT_VERSION,
        "status": status,
        "networkActivity": False,
        "observedNetworkActivity": observation["networkActivity"],
        "events": len(observation["events"]),
        "packets": packet_count,
        "ssrcs": len(ssrcs),
        "epochs": len(epochs),
        "durationMs": duration,
        "findings": findings,
        "unknowns": unknowns,
        "sessionKeysObserved": False,
        "capacityClaim": None,
    }


def _read(path: str) -> Any:
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise MediaSecurityError(f"input must be a regular non-symlink file: {path}")
    if candidate.stat().st_size > MAX_INPUT_BYTES:
        raise MediaSecurityError(f"input exceeds {MAX_INPUT_BYTES} bytes: {path}")
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MediaSecurityError(f"cannot read JSON input {path}: {exc}") from exc


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="webrtc-media-security",
        description="Evaluate normalized DTLS-SRTP security evidence offline.",
    )
    parser.add_argument("policy")
    parser.add_argument("observation")
    parsed = parser.parse_args(arguments)
    try:
        report = evaluate(_read(parsed.policy), _read(parsed.observation))
    except MediaSecurityError as exc:
        print(f"DTLS-SRTP input rejected: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return {"pass": 0, "fail": 1, "incomplete": 3}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
