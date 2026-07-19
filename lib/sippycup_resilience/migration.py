"""RTP tuple migration, consent, collision, and spoof-resistance oracle."""

from __future__ import annotations

import ipaddress
from typing import Any

from .common import (
    ResilienceError,
    boolean,
    bounded_int,
    exact_keys,
    nonempty_string,
    require_mapping,
    verdict,
)

REPORT_VERSION = "sippycup.dev/migration-report/v1"
MODES = ("strict", "symmetric-rtp", "ice")
MAX_PACKETS = 1_000_000


def _tuple(value: Any, name: str) -> tuple[str, int]:
    item = require_mapping(value, name)
    exact_keys(item, ("address", "port"), name=name)
    address = nonempty_string(item["address"], f"{name}.address", 64)
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as error:
        raise ResilienceError(f"{name}.address must be an IP literal") from error
    if parsed.is_multicast or parsed.is_unspecified:
        raise ResilienceError(f"{name}.address must be specific unicast")
    return str(parsed), bounded_int(item["port"], f"{name}.port", 1024, 65535)


def analyze_migration(policy_value: Any, packets_value: Any) -> dict[str, Any]:
    policy = require_mapping(policy_value, "migration policy")
    exact_keys(
        policy,
        (
            "mode",
            "initialTuple",
            "ssrc",
            "allowAuthenticatedRebinding",
            "requireAuthentication",
        ),
        name="migration policy",
    )
    if policy["mode"] not in MODES:
        raise ResilienceError(f"mode must be one of {', '.join(MODES)}")
    initial = _tuple(policy["initialTuple"], "initialTuple")
    expected_ssrc = bounded_int(policy["ssrc"], "ssrc", 1, 0xFFFFFFFF)
    allow_rebinding = boolean(
        policy["allowAuthenticatedRebinding"], "allowAuthenticatedRebinding"
    )
    require_authentication = boolean(
        policy["requireAuthentication"], "requireAuthentication"
    )
    if not isinstance(packets_value, list) or not packets_value:
        raise ResilienceError("packets must be a non-empty array")
    if len(packets_value) > MAX_PACKETS:
        raise ResilienceError(f"packets exceed {MAX_PACKETS}")
    active = initial
    findings: list[dict[str, Any]] = []
    accepted = 0
    migrations: list[dict[str, Any]] = []
    for index, raw in enumerate(packets_value):
        packet = require_mapping(raw, f"packets[{index}]")
        exact_keys(
            packet,
            ("source", "ssrc", "authenticated", "consentFresh", "afterTeardown"),
            name=f"packets[{index}]",
        )
        source = _tuple(packet["source"], f"packets[{index}].source")
        ssrc = bounded_int(packet["ssrc"], "ssrc", 1, 0xFFFFFFFF)
        authenticated = boolean(packet["authenticated"], "authenticated")
        consent = boolean(packet["consentFresh"], "consentFresh")
        after_teardown = boolean(packet["afterTeardown"], "afterTeardown")
        if after_teardown:
            findings.append(
                {"severity": "fail", "code": "packet_after_teardown", "packet": index}
            )
            continue
        if require_authentication and not authenticated:
            findings.append(
                {
                    "severity": "fail",
                    "code": "packet_authentication_failed",
                    "packet": index,
                }
            )
            continue
        if ssrc != expected_ssrc:
            findings.append(
                {"severity": "fail", "code": "ssrc_collision", "packet": index}
            )
            continue
        if source == active:
            if policy["mode"] == "ice" and not consent:
                findings.append(
                    {"severity": "fail", "code": "ice_consent_expired", "packet": index}
                )
                continue
            accepted += 1
            continue
        can_move = (
            policy["mode"] != "strict"
            and allow_rebinding
            and authenticated
            and (policy["mode"] != "ice" or consent)
        )
        if not can_move:
            findings.append(
                {
                    "severity": "fail",
                    "code": "unauthorized_tuple",
                    "packet": index,
                    "source": {"address": source[0], "port": source[1]},
                }
            )
            continue
        migrations.append(
            {
                "packet": index,
                "from": {"address": active[0], "port": active[1]},
                "to": {"address": source[0], "port": source[1]},
            }
        )
        active = source
        accepted += 1
    return {
        "apiVersion": REPORT_VERSION,
        "status": verdict(findings),
        "acceptedPackets": accepted,
        "rejectedPackets": len(packets_value) - accepted,
        "migrations": migrations,
        "activeTuple": {"address": active[0], "port": active[1]},
        "findings": findings,
        "redirectClaim": None,
    }


def default_policy(mode: str = "strict") -> dict[str, Any]:
    if mode not in MODES:
        raise ResilienceError(f"mode must be one of {', '.join(MODES)}")
    return {
        "mode": mode,
        "initialTuple": {"address": "192.0.2.10", "port": 20_000},
        "ssrc": 0x51CC0A11,
        "allowAuthenticatedRebinding": mode != "strict",
        "requireAuthentication": True,
    }
