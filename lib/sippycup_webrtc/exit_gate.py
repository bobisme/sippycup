"""Aggregate the confined browser-realistic WebRTC local exit gate."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any

MAX_INPUT_BYTES = 2 * 1024 * 1024
EXIT_GATE_VERSION = "sippycup.dev/webrtc-exit-gate/v1"
_FORBIDDEN_KEYS = {
    "authorization",
    "cookie",
    "credential",
    "icepwd",
    "password",
    "privatekey",
    "secret",
    "token",
}
_FORBIDDEN_TEXT = (
    re.compile(r"(?i)\bbearer\s+"),
    re.compile(r"(?i)a=ice-pwd:"),
    re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
)


class ExitGateError(ValueError):
    """An exit-gate component is missing, malformed, or unsafe."""


def _read(path_text: str) -> tuple[dict[str, Any], str]:
    path = Path(path_text)
    if path.is_symlink() or not path.is_file():
        raise ExitGateError(f"input must be a regular non-symlink file: {path_text}")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ExitGateError(f"input exceeds {MAX_INPUT_BYTES} bytes: {path_text}")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ExitGateError(f"cannot parse JSON input {path_text}: {exc}") from exc
    if not isinstance(value, dict):
        raise ExitGateError(f"input must contain an object: {path_text}")
    return value, hashlib.sha256(raw).hexdigest()


def _scan(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = re.sub(r"[^a-z]", "", str(key).lower())
            if normalized in _FORBIDDEN_KEYS:
                raise ExitGateError(f"{path}.{key} is secret-bearing")
            _scan(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan(item, f"{path}[{index}]")
    elif isinstance(value, str):
        if any(pattern.search(value) for pattern in _FORBIDDEN_TEXT):
            raise ExitGateError(f"{path} contains secret material")
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return
        raise ExitGateError(f"{path} contains a literal address")


def _check_component(
    document: dict[str, Any],
    *,
    version: str,
    scope: str,
    expected_ids: set[str],
) -> None:
    if document.get("apiVersion") != version:
        raise ExitGateError(f"{version} component has wrong apiVersion")
    if document.get("status") != "pass":
        raise ExitGateError(f"{version} component did not pass")
    if document.get("networkActivity") is not True:
        raise ExitGateError(f"{version} must report local network activity")
    if document.get("networkScope") != scope:
        raise ExitGateError(f"{version} has unexpected network scope")
    checks = document.get("checks")
    if not isinstance(checks, list):
        raise ExitGateError(f"{version} checks must be an array")
    observed_ids = {
        item.get("id")
        for item in checks
        if isinstance(item, dict) and item.get("passed") is True
    }
    if observed_ids != expected_ids or len(checks) != len(expected_ids):
        raise ExitGateError(f"{version} checks are incomplete or failed")
    _scan(document)


def evaluate(
    direct: dict[str, Any],
    relay: dict[str, Any],
    signaling: dict[str, Any],
    seeded: dict[str, Any],
    recovery: dict[str, Any],
    *,
    digests: dict[str, str],
    cancellation_observed: bool,
) -> dict[str, Any]:
    peer_checks = {
        "loopback-candidate-confinement",
        "offer-answer-connected",
        "dtls-srtp-pcmu-audio",
        "ice-restart",
        "rtcp-reader-active",
        "graceful-cleanup",
    }
    relay_checks = set(peer_checks)
    relay_checks.remove("loopback-candidate-confinement")
    relay_checks.add("turn-relay-candidate-confinement")
    signaling_checks = {
        "tls-validation",
        "origin-enforcement",
        "authentication-required",
        "session-expiry",
        "message-authorization",
        "malformed-state-transition",
        "replay-first-use",
        "replay-rejection",
        "size-limit",
        "rate-limit",
        "clean-reconnect-first",
        "clean-reconnect-second",
    }
    _check_component(
        direct,
        version="sippycup.dev/webrtc-peer-self-test/v1",
        scope="loopback",
        expected_ids=peer_checks,
    )
    _check_component(
        relay,
        version="sippycup.dev/webrtc-relay-self-test/v1",
        scope="loopback-turn",
        expected_ids=relay_checks,
    )
    _check_component(
        signaling,
        version="sippycup.dev/wss-signaling-self-test/v1",
        scope="loopback",
        expected_ids=signaling_checks,
    )
    _check_component(
        recovery,
        version="sippycup.dev/wss-signaling-self-test/v1",
        scope="loopback",
        expected_ids=signaling_checks,
    )
    if seeded.get("apiVersion") != "sippycup.dev/wss-signaling-self-test/v1":
        raise ExitGateError("seeded failure report has wrong apiVersion")
    if seeded.get("status") != "fail":
        raise ExitGateError("seeded failure was not detected")
    seeded_checks = seeded.get("checks")
    origin = next(
        (
            item
            for item in seeded_checks
            if isinstance(item, dict) and item.get("id") == "origin-enforcement"
        ),
        None,
    ) if isinstance(seeded_checks, list) else None
    if not isinstance(origin, dict) or origin.get("passed") is not False:
        raise ExitGateError("seeded Origin failure was not classified")
    _scan(seeded)
    if not cancellation_observed:
        raise ExitGateError("cancellation did not stop the disposable runner")

    for name, document in (("direct", direct), ("relay", relay)):
        limits = document.get("limits")
        if not isinstance(limits, dict):
            raise ExitGateError(f"{name} limits are absent")
        if (
            limits.get("packets") != 50
            or limits.get("payloadBytes") != 160
            or not isinstance(limits.get("deadlineSeconds"), int)
            or not 1 <= limits["deadlineSeconds"] <= 30
            or not isinstance(limits.get("portMin"), int)
            or not isinstance(limits.get("portMax"), int)
            or limits["portMax"] - limits["portMin"] + 1 > 1000
        ):
            raise ExitGateError(f"{name} hard ceilings are invalid")
    if signaling.get("arbitraryMessagesEnabled") is not False:
        raise ExitGateError("signaling exposed arbitrary messages")
    if signaling.get("openConnections") != 0 or recovery.get("openConnections") != 0:
        raise ExitGateError("signaling cleanup is incomplete")

    return {
        "apiVersion": EXIT_GATE_VERSION,
        "status": "pass",
        "networkActivity": True,
        "networkScope": "disposable-loopback-no-egress",
        "components": [
            {
                "id": name,
                "sha256": digests[name],
                "status": document["status"],
                "checks": len(document["checks"]),
            }
            for name, document in (
                ("direct", direct),
                ("relay", relay),
                ("signaling", signaling),
            )
        ],
        "seededFailure": {
            "id": "origin-accept",
            "detected": True,
            "recoveryPassed": True,
            "sha256": digests["seeded"],
        },
        "cancellationObserved": True,
        "limits": {
            "callsPerMediaComponent": 1,
            "rtpPacketsPerCall": 50,
            "payloadBytesPerPacket": 160,
            "maxComponentDeadlineSeconds": 30,
            "maxPeerPortSpan": 1000,
            "maxSignalingConnections": 12,
            "maxSignalingMessages": 24,
        },
        "secretsRetained": False,
        "literalAddressesRetained": False,
        "rawMessagesRetained": False,
        "authorizationGranted": False,
        "capacityClaim": None,
        "residualGaps": [
            "real browser engine interoperability",
            "TURN over TCP and TLS",
            "service-specific target signaling adapter",
            "approval-bound target one-call execution",
        ],
    }


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="webrtc-exit-gate",
        description="Aggregate confined WebRTC local exit-gate evidence.",
    )
    for name in ("direct", "relay", "signaling", "seeded", "recovery"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument(
        "--cancellation-observed",
        action="store_true",
        help="runner cancellation was independently observed",
    )
    parsed = parser.parse_args(arguments)
    documents: dict[str, dict[str, Any]] = {}
    digests: dict[str, str] = {}
    try:
        for name in ("direct", "relay", "signaling", "seeded", "recovery"):
            documents[name], digests[name] = _read(getattr(parsed, name))
        report = evaluate(
            documents["direct"],
            documents["relay"],
            documents["signaling"],
            documents["seeded"],
            documents["recovery"],
            digests=digests,
            cancellation_observed=parsed.cancellation_observed,
        )
    except (ExitGateError, OSError) as exc:
        print(f"WebRTC exit gate rejected: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
