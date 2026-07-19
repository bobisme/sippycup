"""Deterministic, network-free technical exit gate for torture tooling."""

from __future__ import annotations

import hashlib
import json
import socket
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from .corpus import build_corpus, corpus_manifest
from .minimize import (
    Authorization,
    HierarchicalMinimizer,
    MinimizerLimits,
    Reproducer,
    TrialResult,
)
from .runner import (
    ActionResult,
    RunnerCallbacks,
    RunnerLimits,
    TortureRunner,
    exact_injector,
)


REPORT_VERSION = "sippycup.dev/torture-exit-gate/v1"
REVIEW_VERSION = "sippycup.dev/torture-defaults-review/v1"


def _canonical(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def report_sha256(report: dict[str, object]) -> str:
    return hashlib.sha256(_canonical(report)).hexdigest()


def _packets() -> tuple[bytes, ...]:
    packets = []
    for case in build_corpus():
        lengths = case.packet_lengths or (len(case.wire_bytes),)
        offset = 0
        for length in lengths:
            packets.append(case.wire_bytes[offset : offset + length])
            offset += length
    return tuple(packets)


def _exact_transmission_check() -> dict[str, object]:
    cases = build_corpus()
    expected = _packets()
    client, endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        callbacks = RunnerCallbacks(
            establish=lambda case, context: ActionResult(
                True,
                "dialog-ready",
                (b"clean-establish",),
                dialog_state=case.dialog_state,
            ),
            inject=exact_injector(client.send),
            classify=lambda case, context: ActionResult(
                True, case.expected_outcomes[0], (b"reference-response",)
            ),
            recovery=lambda case, context: ActionResult(
                True, "clean-call-passed", (b"clean-recovery",)
            ),
        )
        limits = RunnerLimits(
            max_cases=len(cases),
            max_packets=len(expected),
            max_bytes=sum(map(len, expected)),
            max_rate_hz=10,
            max_duration_s=60,
        )
        with tempfile.TemporaryDirectory() as temporary:
            result = TortureRunner(
                cases,
                callbacks,
                Path(temporary) / "evidence",
                limits=limits,
                sleeper=lambda delay: None,
            ).run()
        endpoint.settimeout(0.25)
        received = tuple(endpoint.recv(4096) for _ in expected)
    finally:
        client.close()
        endpoint.close()
    passed = result["state"] == "completed" and received == expected
    return {
        "id": "bit-exact-isolated-endpoint",
        "passed": passed,
        "cases": len(cases),
        "packets": len(expected),
        "bytes": sum(map(len, expected)),
    }


def _recovery_check() -> dict[str, object]:
    cases = build_corpus()[:2]
    injections: list[str] = []

    def inject(case, context):
        injections.append(case.id)
        lengths = case.packet_lengths or (len(case.wire_bytes),)
        packets = []
        offset = 0
        for length in lengths:
            packets.append(case.wire_bytes[offset : offset + length])
            offset += length
        return ActionResult(
            True,
            "fragile-endpoint-reset",
            tuple(packets),
            tuple(packets),
        )

    callbacks = RunnerCallbacks(
        establish=lambda case, context: ActionResult(
            True, "ready", dialog_state=case.dialog_state
        ),
        inject=inject,
        classify=lambda case, context: ActionResult(
            True, case.expected_outcomes[0]
        ),
        recovery=lambda case, context: ActionResult(False, "clean-canary-failed"),
    )
    with tempfile.TemporaryDirectory() as temporary:
        result = TortureRunner(
            cases,
            callbacks,
            Path(temporary) / "evidence",
            limits=RunnerLimits(max_cases=2),
        ).run()
    return {
        "id": "recovery-failure-stops-admission",
        "passed": result["reason"] == "recovery-canary-failed"
        and len(injections) == 1,
        "mutationsBeforeStop": len(injections),
        "reason": result["reason"],
    }


def _health_check() -> dict[str, object]:
    case = build_corpus()[0]
    injections: list[str] = []
    callbacks = RunnerCallbacks(
        establish=lambda selected, context: ActionResult(
            True, "ready", dialog_state=selected.dialog_state
        ),
        inject=lambda selected, context: injections.append(selected.id),
        classify=lambda selected, context: ActionResult(
            True, selected.expected_outcomes[0]
        ),
        recovery=lambda selected, context: ActionResult(True, "recovered"),
        health=lambda: False,
    )
    with tempfile.TemporaryDirectory() as temporary:
        result = TortureRunner(
            (case,), callbacks, Path(temporary) / "evidence"
        ).run()
    return {
        "id": "health-failure-sends-no-mutation",
        "passed": result["reason"] == "health-check-failed" and not injections,
        "mutations": len(injections),
        "reason": result["reason"],
    }


def _minimization_check() -> dict[str, object]:
    source_bytes = (
        b"INVITE sip:test@example.invalid SIP/2.0\r\n"
        b"X-Noise: remove-me\r\n"
        b"X-Trigger: SEEDED-RESET\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    authorization = Authorization(
        "192.0.2.10:5060/udp", "pre-dialog", 1, len(source_bytes)
    )
    source = Reproducer(
        source_bytes, ("noise", "seeded-trigger"), authorization
    )

    def endpoint(candidate):
        failed = b"SEEDED-RESET" in candidate.wire_bytes
        return TrialResult(
            failed,
            "reset" if failed else "accepted",
            (b"offline-frame",),
        )

    minimizer = HierarchicalMinimizer(
        source,
        endpoint,
        limits=MinimizerLimits(max_candidates=32),
        expected_outcome="accepted-or-rejected-without-reset",
        command=("sippycup-torture", "replay", "--authorization", "secret"),
    )
    result = minimizer.minimize()
    reduced = bytes.fromhex(str(result["wireHex"]))
    replayed = endpoint(Reproducer(reduced, (), authorization)).failed
    return {
        "id": "seeded-failure-minimizes-and-replays",
        "passed": result["stability"] == "stable"
        and len(reduced) < len(source_bytes)
        and b"SEEDED-RESET" in reduced
        and replayed
        and result["command"][-1] == "<redacted>",
        "sourceBytes": len(source_bytes),
        "reducedBytes": len(reduced),
        "stability": result["stability"],
        "reservedPackets": result["trafficUsed"]["reservedPackets"],
    }


def _prohibited_behavior_check() -> dict[str, object]:
    manifest = corpus_manifest()
    no_auth = all(
        b"authorization:" not in case.wire_bytes.lower()
        and b"proxy-authorization:" not in case.wire_bytes.lower()
        for case in build_corpus()
    )
    passed = (
        manifest["safety"]["credentialGuessing"] is False
        and manifest["safety"]["spoofedReflection"] is False
        and manifest["safety"]["unboundedAmplification"] is False
        and manifest["safety"]["maxCasePackets"] <= 3
        and no_auth
    )
    return {
        "id": "no-credential-reflection-or-load-behavior",
        "passed": passed,
        "credentialGuessing": False,
        "spoofedReflection": False,
        "unboundedAmplification": False,
        "authorizationHeaders": False,
        "maximumPacketsPerCase": manifest["safety"]["maxCasePackets"],
    }


def run_exit_gate() -> dict[str, object]:
    checks = []
    for identifier, function in (
        ("bit-exact-isolated-endpoint", _exact_transmission_check),
        ("recovery-failure-stops-admission", _recovery_check),
        ("health-failure-sends-no-mutation", _health_check),
        ("seeded-failure-minimizes-and-replays", _minimization_check),
        (
            "no-credential-reflection-or-load-behavior",
            _prohibited_behavior_check,
        ),
    ):
        try:
            checks.append(function())
        except Exception as exc:
            checks.append(
                {
                    "id": identifier,
                    "passed": False,
                    "error": type(exc).__name__,
                }
            )
    defaults = RunnerLimits()
    report: dict[str, object] = {
        "apiVersion": REPORT_VERSION,
        "kind": "TortureTechnicalExitGate",
        "status": "pass" if all(check["passed"] for check in checks) else "fail",
        "networkActivity": False,
        "corpusIdentity": corpus_manifest()["identity"],
        "checks": checks,
        "defaultLimits": {
            "cases": defaults.max_cases,
            "packets": defaults.max_packets,
            "bytes": defaults.max_bytes,
            "rateHz": defaults.max_rate_hz,
            "concurrency": defaults.max_concurrency,
            "durationSeconds": defaults.max_duration_s,
            "failures": defaults.max_failures,
            "actionTimeoutSeconds": defaults.action_timeout_s,
        },
        "ownerReview": {
            "required": True,
            "status": "pending",
            "authorizationGranted": False,
            "statement": (
                "Technical safety passed offline; the service owner must review "
                "the default limits separately. This report authorizes no traffic."
            ),
        },
    }
    return report


def default_review(
    report: dict[str, object], *, reviewer: str
) -> dict[str, object]:
    if (
        not isinstance(reviewer, str)
        or not reviewer.strip()
        or len(reviewer) > 200
        or "\x00" in reviewer
    ):
        raise ValueError("reviewer must be 1-200 safe text characters")
    return {
        "apiVersion": REVIEW_VERSION,
        "reviewStatus": "pending",
        "reviewedBy": reviewer,
        "reviewId": "",
        "reviewedAt": None,
        "corpusIdentity": report["corpusIdentity"],
        "technicalGateSha256": report_sha256(report),
        "acceptedDefaultLimits": report["defaultLimits"],
        "comments": (
            "Review of bounded defaults only. This does not authorize target traffic."
        ),
    }


def validate_review(
    value: Any, report: dict[str, object]
) -> dict[str, object]:
    errors: list[str] = []
    expected_fields = {
        "apiVersion",
        "reviewStatus",
        "reviewedBy",
        "reviewId",
        "reviewedAt",
        "corpusIdentity",
        "technicalGateSha256",
        "acceptedDefaultLimits",
        "comments",
    }
    if not isinstance(value, dict):
        raise ValueError("torture defaults review must be a JSON object")
    unknown = set(value) - expected_fields
    missing = expected_fields - set(value)
    if unknown:
        errors.append("unknown fields: " + ", ".join(sorted(unknown)))
    if missing:
        errors.append("missing fields: " + ", ".join(sorted(missing)))
    if value.get("apiVersion") != REVIEW_VERSION:
        errors.append("unsupported or missing apiVersion")
    if value.get("reviewStatus") != "approved":
        errors.append("reviewStatus is not approved")
    for field in ("reviewedBy", "reviewId"):
        item = value.get(field)
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{field} must be non-empty")
        elif len(item) > 200 or "\x00" in item:
            errors.append(f"{field} is invalid")
    reviewed_at = value.get("reviewedAt")
    if not isinstance(reviewed_at, str) or not reviewed_at:
        errors.append("reviewedAt must be an RFC 3339 timestamp")
    else:
        try:
            parsed = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
        except ValueError:
            errors.append("reviewedAt must include a timezone")
    comments = value.get("comments")
    if not isinstance(comments, str) or len(comments) > 2000 or "\x00" in comments:
        errors.append("comments must be at most 2000 safe text characters")
    if value.get("corpusIdentity") != report["corpusIdentity"]:
        errors.append("corpusIdentity does not match the current corpus")
    if value.get("technicalGateSha256") != report_sha256(report):
        errors.append("technicalGateSha256 does not match the current gate")
    if value.get("acceptedDefaultLimits") != report["defaultLimits"]:
        errors.append("acceptedDefaultLimits do not match the current defaults")
    if report.get("status") != "pass":
        errors.append("current technical exit gate does not pass")
    return {
        "apiVersion": "sippycup.dev/torture-defaults-review-result/v1",
        "ready": not errors,
        "errors": errors,
        "reviewedBy": value.get("reviewedBy"),
        "reviewId": value.get("reviewId"),
        "technicalGateSha256": report_sha256(report),
        "networkActivity": False,
        "authorizationGranted": False,
        "statement": (
            "This validates owner review of tool defaults only; a target profile "
            "and live authorization window are still required."
        ),
    }
