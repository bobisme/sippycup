"""Offline ICE, STUN, and TURN security-policy oracle."""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping

POLICY_VERSION = "sippycup.dev/ice-turn-policy/v1"
OBSERVATION_VERSION = "sippycup.dev/ice-turn-observation/v1"
REPORT_VERSION = "sippycup.dev/ice-turn-report/v1"
MAX_INPUT_BYTES = 4 * 1024 * 1024
_HASH = re.compile(r"^[0-9a-f]{64}$")


class OracleError(ValueError):
    """An input violates the strict oracle contract."""


def _object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise OracleError(f"{path} must be an object")
    return value


def _array(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise OracleError(f"{path} must be an array")
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
        raise OracleError(f"{path} is missing: {', '.join(sorted(missing))}")
    if extra:
        raise OracleError(f"{path} has unknown fields: {', '.join(sorted(extra))}")


def _integer(value: Any, path: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise OracleError(f"{path} must be an integer")
    if not minimum <= value <= maximum:
        raise OracleError(f"{path} must be between {minimum} and {maximum}")
    return value


def _number(value: Any, path: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise OracleError(f"{path} must be a number")
    result = float(value)
    if not minimum <= result <= maximum:
        raise OracleError(f"{path} must be between {minimum} and {maximum}")
    return result


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise OracleError(f"{path} must be boolean")
    return value


def _enum(value: Any, path: str, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise OracleError(f"{path} must be one of: {', '.join(sorted(allowed))}")
    return value


def validate_policy(document: Any) -> dict[str, Any]:
    policy = dict(_object(document, "$"))
    _exact(
        policy,
        "$",
        {
            "apiVersion",
            "candidatePolicy",
            "approvedServers",
            "approvedPeerNetworks",
            "ice",
            "turn",
            "limits",
        },
    )
    if policy["apiVersion"] != POLICY_VERSION:
        raise OracleError("$.apiVersion is unsupported")

    candidates = _object(policy["candidatePolicy"], "$.candidatePolicy")
    _exact(
        candidates,
        "$.candidatePolicy",
        {"allowedTypes", "allowAddressExposure", "requireMdnsForPrivateHost"},
    )
    types = _array(candidates["allowedTypes"], "$.candidatePolicy.allowedTypes")
    if not types or len(types) != len(set(types)):
        raise OracleError("$.candidatePolicy.allowedTypes must be non-empty and unique")
    for index, item in enumerate(types):
        _enum(
            item,
            f"$.candidatePolicy.allowedTypes[{index}]",
            {"host", "srflx", "prflx", "relay"},
        )
    _boolean(candidates["allowAddressExposure"], "$.candidatePolicy.allowAddressExposure")
    _boolean(
        candidates["requireMdnsForPrivateHost"],
        "$.candidatePolicy.requireMdnsForPrivateHost",
    )

    servers = _array(policy["approvedServers"], "$.approvedServers")
    if len(servers) > 32:
        raise OracleError("$.approvedServers exceeds 32 entries")
    server_keys: set[tuple[str, str, int, str]] = set()
    for index, item in enumerate(servers):
        path = f"$.approvedServers[{index}]"
        server = _object(item, path)
        _exact(server, path, {"role", "address", "port", "transport"})
        role = _enum(server["role"], f"{path}.role", {"stun", "turn"})
        try:
            address = ipaddress.ip_address(server["address"])
        except (TypeError, ValueError) as exc:
            raise OracleError(f"{path}.address must be a literal unicast IP") from exc
        if address.is_multicast or address.is_unspecified:
            raise OracleError(f"{path}.address must be a literal unicast IP")
        port = _integer(server["port"], f"{path}.port", 1, 65535)
        transport = _enum(
            server["transport"], f"{path}.transport", {"udp", "tcp", "tls"}
        )
        key = (role, address.compressed, port, transport)
        if key in server_keys:
            raise OracleError(f"{path} duplicates an approved server")
        server_keys.add(key)

    networks = _array(policy["approvedPeerNetworks"], "$.approvedPeerNetworks")
    if not networks or len(networks) > 64:
        raise OracleError("$.approvedPeerNetworks must contain 1 to 64 CIDRs")
    normalized_networks = []
    for index, item in enumerate(networks):
        try:
            network = ipaddress.ip_network(item, strict=True)
        except (TypeError, ValueError) as exc:
            raise OracleError(
                f"$.approvedPeerNetworks[{index}] must be a canonical CIDR"
            ) from exc
        normalized_networks.append(network)
    if len({item.with_prefixlen for item in normalized_networks}) != len(
        normalized_networks
    ):
        raise OracleError("$.approvedPeerNetworks must be unique")

    ice = _object(policy["ice"], "$.ice")
    _exact(
        ice,
        "$.ice",
        {
            "requireNomination",
            "requireConsentFreshness",
            "maxConsentGapMs",
            "requireRestartCredentialChange",
        },
    )
    _boolean(ice["requireNomination"], "$.ice.requireNomination")
    _boolean(ice["requireConsentFreshness"], "$.ice.requireConsentFreshness")
    _integer(ice["maxConsentGapMs"], "$.ice.maxConsentGapMs", 100, 60000)
    _boolean(
        ice["requireRestartCredentialChange"],
        "$.ice.requireRestartCredentialChange",
    )

    turn = _object(policy["turn"], "$.turn")
    _exact(
        turn,
        "$.turn",
        {
            "requireLongTermCredentials",
            "maxCredentialLifetimeSeconds",
            "maxAllocationLifetimeSeconds",
            "allowedTransports",
            "maxAmplificationRatio",
            "requirePermissionBeforeData",
            "requireChannelBindingForChannelData",
        },
    )
    _boolean(
        turn["requireLongTermCredentials"], "$.turn.requireLongTermCredentials"
    )
    _integer(
        turn["maxCredentialLifetimeSeconds"],
        "$.turn.maxCredentialLifetimeSeconds",
        1,
        86400,
    )
    _integer(
        turn["maxAllocationLifetimeSeconds"],
        "$.turn.maxAllocationLifetimeSeconds",
        1,
        3600,
    )
    transports = _array(turn["allowedTransports"], "$.turn.allowedTransports")
    if not transports or len(transports) != len(set(transports)):
        raise OracleError("$.turn.allowedTransports must be non-empty and unique")
    for index, item in enumerate(transports):
        _enum(item, f"$.turn.allowedTransports[{index}]", {"udp", "tcp", "tls"})
    _number(
        turn["maxAmplificationRatio"], "$.turn.maxAmplificationRatio", 1.0, 100.0
    )
    _boolean(
        turn["requirePermissionBeforeData"], "$.turn.requirePermissionBeforeData"
    )
    _boolean(
        turn["requireChannelBindingForChannelData"],
        "$.turn.requireChannelBindingForChannelData",
    )

    limits = _object(policy["limits"], "$.limits")
    _exact(limits, "$.limits", {"maxEvents", "maxPackets", "maxBytes", "maxDurationMs"})
    _integer(limits["maxEvents"], "$.limits.maxEvents", 1, 100000)
    _integer(limits["maxPackets"], "$.limits.maxPackets", 1, 10000000)
    _integer(limits["maxBytes"], "$.limits.maxBytes", 1, 1073741824)
    _integer(limits["maxDurationMs"], "$.limits.maxDurationMs", 1, 3600000)
    return policy


_EVENT_FIELDS = {
    "candidate": {"candidateType", "addressClass", "exposed", "mdns"},
    "server_contact": {"role", "address", "port", "transport"},
    "pair_selected": {"nominated", "localType", "remoteType"},
    "consent": {"success"},
    "ice_restart": {"oldUfragHash", "newUfragHash"},
    "turn_credential": {"mechanism", "lifetimeSeconds"},
    "turn_allocation": {"lifetimeSeconds", "transport"},
    "turn_permission": {"peerAddress"},
    "turn_channel_bind": {"peerAddress"},
    "turn_data": {
        "peerAddress",
        "mode",
        "bytesIn",
        "bytesOut",
        "permissionPresent",
        "channelBound",
    },
    "traffic": {"packets", "bytes"},
    "cleanup": {"allocations", "sockets"},
    "failure": {"domain", "code"},
}


def validate_observation(document: Any, max_events: int = 100000) -> dict[str, Any]:
    observation = dict(_object(document, "$"))
    _exact(observation, "$", {"apiVersion", "networkActivity", "events"})
    if observation["apiVersion"] != OBSERVATION_VERSION:
        raise OracleError("$.apiVersion is unsupported")
    _boolean(observation["networkActivity"], "$.networkActivity")
    events = _array(observation["events"], "$.events")
    if len(events) > max_events:
        raise OracleError(f"$.events exceeds the policy limit of {max_events}")
    last_time = -1
    for index, item in enumerate(events):
        path = f"$.events[{index}]"
        event = _object(item, path)
        _exact(event, path, {"timeMs", "type", "data"})
        time_ms = _integer(event["timeMs"], f"{path}.timeMs", 0, 3600000)
        if time_ms < last_time:
            raise OracleError("$.events timeMs values must be nondecreasing")
        last_time = time_ms
        event_type = _enum(event["type"], f"{path}.type", set(_EVENT_FIELDS))
        data = _object(event["data"], f"{path}.data")
        _exact(data, f"{path}.data", _EVENT_FIELDS[event_type])
        _validate_event_data(event_type, data, f"{path}.data")
    return observation


def _validate_event_data(kind: str, data: Mapping[str, Any], path: str) -> None:
    if kind == "candidate":
        _enum(data["candidateType"], f"{path}.candidateType", {"host", "srflx", "prflx", "relay"})
        _enum(data["addressClass"], f"{path}.addressClass", {"private", "public", "mdns", "redacted"})
        _boolean(data["exposed"], f"{path}.exposed")
        _boolean(data["mdns"], f"{path}.mdns")
    elif kind == "server_contact":
        _enum(data["role"], f"{path}.role", {"stun", "turn"})
        try:
            ipaddress.ip_address(data["address"])
        except (TypeError, ValueError) as exc:
            raise OracleError(f"{path}.address must be a literal IP") from exc
        _integer(data["port"], f"{path}.port", 1, 65535)
        _enum(data["transport"], f"{path}.transport", {"udp", "tcp", "tls"})
    elif kind == "pair_selected":
        _boolean(data["nominated"], f"{path}.nominated")
        _enum(data["localType"], f"{path}.localType", {"host", "srflx", "prflx", "relay"})
        _enum(data["remoteType"], f"{path}.remoteType", {"host", "srflx", "prflx", "relay"})
    elif kind == "consent":
        _boolean(data["success"], f"{path}.success")
    elif kind == "ice_restart":
        for key in ("oldUfragHash", "newUfragHash"):
            if not isinstance(data[key], str) or not _HASH.fullmatch(data[key]):
                raise OracleError(f"{path}.{key} must be a SHA-256 digest")
    elif kind == "turn_credential":
        _enum(data["mechanism"], f"{path}.mechanism", {"long-term", "rest", "anonymous"})
        _integer(data["lifetimeSeconds"], f"{path}.lifetimeSeconds", 0, 604800)
    elif kind == "turn_allocation":
        _integer(data["lifetimeSeconds"], f"{path}.lifetimeSeconds", 1, 3600)
        _enum(data["transport"], f"{path}.transport", {"udp", "tcp", "tls"})
    elif kind in {"turn_permission", "turn_channel_bind"}:
        try:
            ipaddress.ip_address(data["peerAddress"])
        except (TypeError, ValueError) as exc:
            raise OracleError(f"{path}.peerAddress must be a literal IP") from exc
    elif kind == "turn_data":
        try:
            ipaddress.ip_address(data["peerAddress"])
        except (TypeError, ValueError) as exc:
            raise OracleError(f"{path}.peerAddress must be a literal IP") from exc
        _enum(data["mode"], f"{path}.mode", {"indication", "channel"})
        _integer(data["bytesIn"], f"{path}.bytesIn", 0, 1073741824)
        _integer(data["bytesOut"], f"{path}.bytesOut", 0, 1073741824)
        _boolean(data["permissionPresent"], f"{path}.permissionPresent")
        _boolean(data["channelBound"], f"{path}.channelBound")
    elif kind == "traffic":
        _integer(data["packets"], f"{path}.packets", 0, 10000000)
        _integer(data["bytes"], f"{path}.bytes", 0, 1073741824)
    elif kind == "cleanup":
        _integer(data["allocations"], f"{path}.allocations", 0, 100000)
        _integer(data["sockets"], f"{path}.sockets", 0, 100000)
    elif kind == "failure":
        _enum(data["domain"], f"{path}.domain", {"peer", "server", "network", "unknown"})
        if not isinstance(data["code"], str) or not 1 <= len(data["code"]) <= 128:
            raise OracleError(f"{path}.code must be a bounded string")


def evaluate(policy_document: Any, observation_document: Any) -> dict[str, Any]:
    policy = validate_policy(policy_document)
    observation = validate_observation(
        observation_document, policy["limits"]["maxEvents"]
    )
    findings: list[dict[str, Any]] = []
    unknowns: list[dict[str, Any]] = []

    def fail(code: str, event: int, detail: str) -> None:
        findings.append({"severity": "fail", "code": code, "event": event, "detail": detail})

    allowed_types = set(policy["candidatePolicy"]["allowedTypes"])
    approved_servers = {
        (
            item["role"],
            ipaddress.ip_address(item["address"]).compressed,
            item["port"],
            item["transport"],
        )
        for item in policy["approvedServers"]
    }
    peer_networks = [
        ipaddress.ip_network(item) for item in policy["approvedPeerNetworks"]
    ]
    consent_times: list[int] = []
    pair_seen = False
    cleanup_seen = False
    turn_seen = False
    total_packets = 0
    total_bytes = 0
    failure_domains: set[str] = set()

    for index, event in enumerate(observation["events"]):
        kind = event["type"]
        data = event["data"]
        if kind == "candidate":
            if data["candidateType"] not in allowed_types:
                fail("ice.candidate_type_disallowed", index, data["candidateType"])
            if data["exposed"] and not policy["candidatePolicy"]["allowAddressExposure"]:
                fail("ice.candidate_address_exposed", index, data["addressClass"])
            if (
                data["candidateType"] == "host"
                and data["addressClass"] == "private"
                and policy["candidatePolicy"]["requireMdnsForPrivateHost"]
                and not data["mdns"]
            ):
                fail("ice.private_host_without_mdns", index, "private host candidate")
        elif kind == "server_contact":
            key = (
                data["role"],
                ipaddress.ip_address(data["address"]).compressed,
                data["port"],
                data["transport"],
            )
            if key not in approved_servers:
                fail("ice.unapproved_server_contact", index, repr(key))
        elif kind == "pair_selected":
            pair_seen = True
            if policy["ice"]["requireNomination"] and not data["nominated"]:
                fail("ice.pair_not_nominated", index, "selected pair was not nominated")
        elif kind == "consent":
            if data["success"]:
                consent_times.append(event["timeMs"])
            else:
                fail("ice.consent_failed", index, "consent check failed")
        elif kind == "ice_restart":
            if (
                policy["ice"]["requireRestartCredentialChange"]
                and data["oldUfragHash"] == data["newUfragHash"]
            ):
                fail("ice.restart_reused_credentials", index, "ufrag hash did not change")
        elif kind == "turn_credential":
            turn_seen = True
            if policy["turn"]["requireLongTermCredentials"] and data["mechanism"] == "anonymous":
                fail("turn.anonymous_credentials", index, "anonymous TURN access")
            if data["lifetimeSeconds"] > policy["turn"]["maxCredentialLifetimeSeconds"]:
                fail("turn.credential_lifetime_exceeded", index, str(data["lifetimeSeconds"]))
        elif kind == "turn_allocation":
            turn_seen = True
            if data["transport"] not in policy["turn"]["allowedTransports"]:
                fail("turn.transport_disallowed", index, data["transport"])
            if data["lifetimeSeconds"] > policy["turn"]["maxAllocationLifetimeSeconds"]:
                fail("turn.allocation_lifetime_exceeded", index, str(data["lifetimeSeconds"]))
        elif kind in {"turn_permission", "turn_channel_bind", "turn_data"}:
            turn_seen = True
            address = ipaddress.ip_address(data["peerAddress"])
            if not any(address in network for network in peer_networks):
                fail("turn.peer_outside_scope", index, address.compressed)
            if kind == "turn_data":
                if policy["turn"]["requirePermissionBeforeData"] and not data["permissionPresent"]:
                    fail("turn.data_without_permission", index, data["mode"])
                if (
                    data["mode"] == "channel"
                    and policy["turn"]["requireChannelBindingForChannelData"]
                    and not data["channelBound"]
                ):
                    fail("turn.channel_data_without_binding", index, "channel")
                if data["bytesIn"] == 0:
                    if data["bytesOut"] > 0:
                        fail("turn.unbounded_amplification", index, "zero input bytes")
                elif data["bytesOut"] / data["bytesIn"] > policy["turn"]["maxAmplificationRatio"]:
                    fail(
                        "turn.amplification_ratio_exceeded",
                        index,
                        f"{data['bytesOut'] / data['bytesIn']:.3f}",
                    )
        elif kind == "traffic":
            total_packets += data["packets"]
            total_bytes += data["bytes"]
        elif kind == "cleanup":
            cleanup_seen = True
            if data["allocations"] or data["sockets"]:
                fail(
                    "ice.cleanup_incomplete",
                    index,
                    f"allocations={data['allocations']} sockets={data['sockets']}",
                )
        elif kind == "failure":
            failure_domains.add(data["domain"])

    if not pair_seen:
        unknowns.append({"code": "ice.selected_pair_not_observed"})
    if not cleanup_seen:
        unknowns.append({"code": "ice.cleanup_not_observed"})
    if policy["ice"]["requireConsentFreshness"]:
        if not consent_times:
            unknowns.append({"code": "ice.consent_not_observed"})
        for left, right in zip(consent_times, consent_times[1:]):
            if right - left > policy["ice"]["maxConsentGapMs"]:
                fail("ice.consent_gap_exceeded", -1, str(right - left))
    if turn_seen and not any(
        event["type"] == "turn_allocation" for event in observation["events"]
    ):
        unknowns.append({"code": "turn.allocation_not_observed"})

    limits = policy["limits"]
    duration = observation["events"][-1]["timeMs"] if observation["events"] else 0
    if total_packets > limits["maxPackets"]:
        fail("limits.packet_ceiling_exceeded", -1, str(total_packets))
    if total_bytes > limits["maxBytes"]:
        fail("limits.byte_ceiling_exceeded", -1, str(total_bytes))
    if duration > limits["maxDurationMs"]:
        fail("limits.duration_ceiling_exceeded", -1, str(duration))

    status = "fail" if findings else ("incomplete" if unknowns else "pass")
    failure_domain = (
        next(iter(failure_domains))
        if len(failure_domains) == 1
        else ("mixed" if failure_domains else None)
    )
    return {
        "apiVersion": REPORT_VERSION,
        "status": status,
        "networkActivity": False,
        "observedNetworkActivity": observation["networkActivity"],
        "events": len(observation["events"]),
        "totals": {
            "packets": total_packets,
            "bytes": total_bytes,
            "durationMs": duration,
        },
        "failureDomain": failure_domain,
        "findings": findings,
        "unknowns": unknowns,
        "capacityClaim": None,
    }


def _read(path: str) -> Any:
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise OracleError(f"input must be a regular non-symlink file: {path}")
    if candidate.stat().st_size > MAX_INPUT_BYTES:
        raise OracleError(f"input exceeds {MAX_INPUT_BYTES} bytes: {path}")
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OracleError(f"cannot read JSON input {path}: {exc}") from exc


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sippycup-webrtc-ice-turn",
        description="Evaluate normalized ICE/STUN/TURN evidence offline.",
    )
    parser.add_argument("policy")
    parser.add_argument("observation")
    parsed = parser.parse_args(arguments)
    try:
        report = evaluate(_read(parsed.policy), _read(parsed.observation))
    except OracleError as exc:
        print(f"ICE/TURN input rejected: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return {"pass": 0, "fail": 1, "incomplete": 3}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
