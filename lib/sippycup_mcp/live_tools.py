"""Capability-backed preparation and single-transaction preflight tools.

These tools are intentionally not registered on the offline MCP server.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import threading
import time
from typing import Any, Callable

import yaml

from sippycup.integration import sip_options_preflight
from sippycup.runtime import validate_plan
from sippycup_workbench.profile import rehearse

from .capability import (
    CEILING_KEYS,
    CapabilityValidator,
    Endpoint,
    ExpectedBinding,
    PinnedInput,
    PinnedInputRoot,
)
from .security import MCPPolicyError, redact

LIVE_RESULT_API_VERSION = "sippycup.dev/mcp-live-result/v1"
SNAPSHOT_API_VERSION = "sippycup.dev/mcp-live-snapshot/v1"
MAX_LIVE_INPUT_BYTES = 2 * 1024 * 1024
MAX_PREFLIGHT_DESTINATIONS = 1

Preflight = Callable[[dict[str, Any]], tuple[bool, str]]


class PreflightAttemptError(RuntimeError):
    """The fixed network adapter failed after an attempt began."""


def _strict_json(content: bytes, field: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        document: dict[str, Any] = {}
        for key, value in pairs:
            if key in document:
                raise MCPPolicyError(f"{field} contains duplicate fields")
            document[key] = value
        return document

    try:
        value = json.loads(content, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MCPPolicyError(f"{field} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise MCPPolicyError(f"{field} must be a JSON object")
    return value


def _load_profile(content: bytes) -> dict[str, Any]:
    try:
        profile = yaml.safe_load(content)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise MCPPolicyError("target profile is invalid YAML") from exc
    if not isinstance(profile, dict):
        raise MCPPolicyError("target profile must be a YAML object")
    rehearsal = rehearse(profile)
    if not rehearsal.ready:
        raise MCPPolicyError(
            "target profile is not ready: " + "; ".join(rehearsal.errors)
        )
    return rehearsal.as_dict()


def _load_plan(content: bytes) -> dict[str, Any]:
    try:
        return validate_plan(_strict_json(content, "reviewed plan"))
    except RuntimeError as exc:
        raise MCPPolicyError(f"reviewed plan is invalid: {exc}") from exc


def _plan_bindings(
    plan: dict[str, Any], profile_facts: dict[str, Any]
) -> tuple[tuple[Endpoint, ...], dict[str, int]]:
    destinations = plan["resolvedDestinations"]
    used_targets = {step["target"] for step in plan["steps"]}
    used = [
        destination
        for destination in destinations
        if destination["target"] in used_targets
    ]
    if len(used) != MAX_PREFLIGHT_DESTINATIONS:
        raise MCPPolicyError(
            "live MCP preflight currently requires exactly one used destination"
        )
    target = profile_facts["facts"]["target"]
    approved = set(target["approved_addresses"])
    endpoints = tuple(
        sorted(
            (
                Endpoint(
                    "signaling",
                    destination["address"],
                    destination["port"],
                    destination["transport"],
                )
                for destination in used
            ),
            key=lambda endpoint: (
                endpoint.role,
                endpoint.address,
                endpoint.port,
                endpoint.transport,
            ),
        )
    )
    for endpoint in endpoints:
        if endpoint.address not in approved:
            raise MCPPolicyError(
                "reviewed plan destination is outside the target profile"
            )
        if endpoint.port != target["port"] or endpoint.transport != target["transport"]:
            raise MCPPolicyError(
                "reviewed plan signaling tuple does not match the target profile"
            )
    maxima = plan["authorization"]["hardMaxima"]
    ceilings = {key: maxima[key] for key in CEILING_KEYS}
    return endpoints, ceilings


def _binding(
    *,
    client_id: str,
    action: str,
    profile: PinnedInput,
    plan: PinnedInput,
    endpoints: tuple[Endpoint, ...],
    ceilings: dict[str, int],
) -> ExpectedBinding:
    return ExpectedBinding(
        client_id=client_id,
        action=action,
        target_profile_sha256=profile.sha256,
        plan_sha256=plan.sha256,
        endpoints=endpoints,
        requested_ceilings=ceilings,
    )


def _result(
    tool: str,
    *,
    started: float,
    network_activity: bool,
    data: Any = None,
    error: Exception | None = None,
) -> dict[str, Any]:
    return {
        "apiVersion": LIVE_RESULT_API_VERSION,
        "tool": tool,
        "ok": error is None,
        "networkActivity": network_activity,
        "durationMs": max(0, round((time.monotonic() - started) * 1000)),
        "sensitivity": "internal",
        "data": redact(data) if error is None else None,
        "warnings": [],
        "errors": (
            []
            if error is None
            else [
                {
                    "code": (
                        "mcp.live_policy_rejected"
                        if isinstance(error, MCPPolicyError)
                        else "mcp.live_tool_failed"
                    ),
                    "message": str(error) or type(error).__name__,
                }
            ]
        ),
    }


class LivePreparationTools:
    """Prepare immutable inputs and perform one capability-bound preflight."""

    def __init__(
        self,
        input_root: str | Path,
        snapshot_root: str | Path,
        validator: CapabilityValidator,
        *,
        client_id: str,
        preflight: Preflight = sip_options_preflight,
    ):
        self.inputs = PinnedInputRoot(input_root)
        self.snapshots = self._private_root(snapshot_root)
        if not client_id or len(client_id) > 128:
            raise MCPPolicyError("trusted live MCP client ID is invalid")
        self.client_id = client_id
        self.validator = validator
        self.preflight_probe = preflight
        self._gate = threading.BoundedSemaphore(1)

    @staticmethod
    def _private_root(path: str | Path) -> Path:
        supplied = Path(path)
        if supplied.is_symlink() or not supplied.is_dir():
            raise MCPPolicyError("live MCP snapshot root must be a real directory")
        status = supplied.stat()
        if status.st_uid != os.geteuid() or status.st_mode & 0o077:
            raise MCPPolicyError("live MCP snapshot root must be owner-private")
        return supplied.resolve(strict=True)

    def prepare_assessment(
        self,
        capability: str,
        target_profile: str,
        reviewed_plan: str,
    ) -> dict[str, Any]:
        return self._invoke(
            "prepare_assessment",
            False,
            lambda: self._prepare(capability, target_profile, reviewed_plan),
        )

    def _invoke(
        self,
        tool: str,
        network_on_success: bool,
        function: Callable[[], dict[str, Any]],
    ) -> dict[str, Any]:
        started = time.monotonic()
        if not self._gate.acquire(timeout=0.25):
            return _result(
                tool,
                started=started,
                network_activity=False,
                error=MCPPolicyError("live MCP tool concurrency limit is busy"),
            )
        try:
            try:
                return _result(
                    tool,
                    started=started,
                    network_activity=network_on_success,
                    data=function(),
                )
            except Exception as exc:
                return _result(
                    tool,
                    started=started,
                    network_activity=isinstance(exc, PreflightAttemptError),
                    error=exc,
                )
        finally:
            self._gate.release()

    def _prepare(
        self,
        capability_path: str,
        profile_path: str,
        plan_path: str,
    ) -> dict[str, Any]:
        capability, profile, plan = self._read_inputs(
            capability_path, profile_path, plan_path
        )
        plan_value = _load_plan(plan.content)
        profile_status = _load_profile(profile.content)
        endpoints, ceilings = _plan_bindings(plan_value, profile_status)
        grant = self.validator.validate(
            capability.content,
            _binding(
                client_id=self.client_id,
                action="prepare_assessment",
                profile=profile,
                plan=plan,
                endpoints=endpoints,
                ceilings=ceilings,
            ),
            consume=False,
        )
        snapshot_id = hashlib.sha256(
            (
                SNAPSHOT_API_VERSION
                + profile.sha256
                + plan.sha256
                + capability.sha256
            ).encode()
        ).hexdigest()
        snapshot = self._freeze_snapshot(
            snapshot_id,
            profile=profile,
            plan=plan,
            grant=grant.public(),
            endpoints=endpoints,
            ceilings=ceilings,
        )
        return {
            "snapshotId": snapshot_id,
            "snapshotSha256": snapshot["snapshotSha256"],
            "authorization": {
                "state": "verified-not-consumed",
                "issuer": grant.issuer,
                "keyId": grant.key_id,
                "clientId": grant.client_id,
                "action": grant.action,
                "expiresAt": grant.expires_at,
                "auditRef": grant.artifact_sha256,
            },
            "targetProfileSha256": profile.sha256,
            "reviewedPlanSha256": plan.sha256,
            "literalTargets": [endpoint.public() for endpoint in endpoints],
            "trafficCeilings": ceilings,
            "networkActivity": False,
        }

    def preflight_target(
        self,
        capability: str,
        target_profile: str,
        reviewed_plan: str,
    ) -> dict[str, Any]:
        return self._invoke(
            "preflight_target",
            True,
            lambda: self._preflight(capability, target_profile, reviewed_plan),
        )

    def _preflight(
        self,
        capability_path: str,
        profile_path: str,
        plan_path: str,
    ) -> dict[str, Any]:
        capability, profile, plan = self._read_inputs(
            capability_path, profile_path, plan_path
        )
        plan_value = _load_plan(plan.content)
        profile_status = _load_profile(profile.content)
        endpoints, ceilings = _plan_bindings(plan_value, profile_status)
        grant = self.validator.validate(
            capability.content,
            _binding(
                client_id=self.client_id,
                action="preflight_target",
                profile=profile,
                plan=plan,
                endpoints=endpoints,
                ceilings=ceilings,
            ),
            consume=True,
        )
        if int(time.time()) >= grant.expires_at:
            raise MCPPolicyError("capability expired immediately before preflight")
        endpoint = endpoints[0]
        destination = {
            "target": "capability-bound",
            "address": endpoint.address,
            "port": endpoint.port,
            "transport": endpoint.transport,
        }
        try:
            ok, detail = self.preflight_probe(destination)
        except Exception as exc:
            raise PreflightAttemptError(
                "fixed SIP OPTIONS adapter failed after network activity began"
            ) from exc
        return {
            "authorization": {
                "state": "consumed",
                "issuer": grant.issuer,
                "keyId": grant.key_id,
                "clientId": grant.client_id,
                "action": grant.action,
                "expiresAt": grant.expires_at,
                "auditRef": grant.artifact_sha256,
            },
            "targetProfileSha256": profile.sha256,
            "reviewedPlanSha256": plan.sha256,
            "literalTarget": endpoint.public(),
            "trafficBudget": {
                "sipOptionsTransactions": 1,
                "concurrentTransactions": 1,
                "timeoutSeconds": 2,
            },
            "outcome": "reachable" if ok else "unreachable",
            "responseSummary": str(redact(detail))[:512],
            "networkActivity": True,
        }

    def _read_inputs(
        self, capability: str, profile: str, plan: str
    ) -> tuple[PinnedInput, PinnedInput, PinnedInput]:
        return (
            self.inputs.read(capability, maximum=64 * 1024),
            self.inputs.read(profile, maximum=MAX_LIVE_INPUT_BYTES),
            self.inputs.read(plan, maximum=MAX_LIVE_INPUT_BYTES),
        )

    def _freeze_snapshot(
        self,
        snapshot_id: str,
        *,
        profile: PinnedInput,
        plan: PinnedInput,
        grant: dict[str, Any],
        endpoints: tuple[Endpoint, ...],
        ceilings: dict[str, int],
    ) -> dict[str, Any]:
        destination = self.snapshots / snapshot_id
        manifest = {
            "apiVersion": SNAPSHOT_API_VERSION,
            "snapshotId": snapshot_id,
            "targetProfileSha256": profile.sha256,
            "reviewedPlanSha256": plan.sha256,
            "capabilityArtifactSha256": grant["artifactSha256"],
            "literalTargets": [endpoint.public() for endpoint in endpoints],
            "trafficCeilings": ceilings,
        }
        manifest["snapshotSha256"] = hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if destination.exists():
            if destination.is_symlink() or not destination.is_dir():
                raise MCPPolicyError("immutable snapshot path is unsafe")
            existing = _strict_json(
                (destination / "snapshot.json").read_bytes(), "snapshot manifest"
            )
            if existing != manifest:
                raise MCPPolicyError("immutable snapshot ID collision")
            expected_files = {
                "target-profile.yaml": profile.sha256,
                "reviewed-plan.json": plan.sha256,
                "snapshot.json": hashlib.sha256(
                    json.dumps(
                        manifest, sort_keys=True, separators=(",", ":")
                    ).encode()
                    + b"\n"
                ).hexdigest(),
            }
            for name, expected_hash in expected_files.items():
                path = destination / name
                if (
                    path.is_symlink()
                    or not path.is_file()
                    or path.stat().st_nlink != 1
                    or path.stat().st_mode & 0o777 != 0o400
                    or hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash
                ):
                    raise MCPPolicyError("immutable snapshot content is unsafe or changed")
            return existing
        temporary = Path(
            tempfile.mkdtemp(prefix=f".{snapshot_id}.", dir=self.snapshots)
        )
        os.chmod(temporary, 0o700)
        try:
            for name, content in (
                ("target-profile.yaml", profile.content),
                ("reviewed-plan.json", plan.content),
                (
                    "snapshot.json",
                    json.dumps(
                        manifest, sort_keys=True, separators=(",", ":")
                    ).encode()
                    + b"\n",
                ),
            ):
                path = temporary / name
                with path.open("xb") as output:
                    output.write(content)
                    output.flush()
                    os.fsync(output.fileno())
                path.chmod(0o400)
            os.rename(temporary, destination)
            directory = os.open(self.snapshots, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        return manifest
