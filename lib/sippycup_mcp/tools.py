"""Typed, offline-only MCP tool implementations."""

from __future__ import annotations

import hashlib
import os
import socket
from pathlib import Path
from typing import Any

import yaml

from sippycup.campaign import ManifestError, compile_plan, load_manifest
from sippycup.envelope import compile_envelope_plan
from sippycup_torture.exit_gate import run_exit_gate
from sippycup_workbench.advisor import assess
from sippycup_workbench.doctor import _effective_capabilities
from sippycup_workbench.profile import load_profile, rehearse

from .security import (
    BoundedProcessRunner,
    CallGate,
    MCPPolicyError,
    WorkRoot,
)

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_CAPTURE_BYTES = 512 * 1024 * 1024
MAX_PACK_BYTES = 512 * 1024 * 1024
MAX_MCP_PLAN_STEPS = 1000


def _offline_resolver(host: str) -> list[str]:
    raise ManifestError(
        f"hostname {host!r} requires DNS; MCP offline planning accepts literal addresses only"
    )


class OfflineTools:
    def __init__(
        self,
        work_root: str | Path,
        *,
        helper: str = "sippycup-workbench",
        evidence_helper: str = "sippycup-evidence",
        pack_helper: str = "sippycup-pack",
    ):
        self.work = WorkRoot(work_root)
        self.helper = helper
        self.evidence_helper = evidence_helper
        self.pack_helper = pack_helper
        self.calls = CallGate()
        self.runner = BoundedProcessRunner()

    def _invoke(self, name: str, function):
        return self.calls.invoke(name, function)

    def sandbox_status(self) -> dict[str, Any]:
        def inspect() -> dict[str, Any]:
            caps = _effective_capabilities()
            interfaces = sorted(
                path.name for path in Path("/sys/class/net").glob("*")
            )
            raw_socket_available = False
            try:
                probe = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            except OSError:
                pass
            else:
                raw_socket_available = True
                probe.close()
            root_read_only = _mount_is_read_only(Path("/"))
            work_read_only = _mount_is_read_only(self.work.path)
            non_loopback = [name for name in interfaces if name != "lo"]
            required = os.environ.get("SIPPYCUP_MCP_REQUIRE_SANDBOX") == "1"
            return {
                "effectiveCapabilities": sorted(caps),
                "capNetAdmin": 12 in caps,
                "capNetRaw": 13 in caps,
                "rawSocketAvailable": raw_socket_available,
                "interfaces": interfaces,
                "nonLoopbackInterfaces": non_loopback,
                "workRoot": str(self.work.path),
                "workMountReadOnly": work_read_only,
                "rootFilesystemReadOnly": root_read_only,
                "sandboxRequired": required,
                "sandboxEnforced": (
                    not raw_socket_available
                    and not (12 in caps or 13 in caps)
                    and (not required or (not non_loopback and work_read_only and root_read_only))
                ),
                "policy": "offline-read-only",
            }

        return self._invoke("sandbox_status", inspect)

    def doctor(self) -> dict[str, Any]:
        def inspect() -> Any:
            returncode, value, stderr = self.runner.run_json(
                [
                    self.helper,
                    "doctor",
                    "--workdir",
                    str(self.work.path),
                    "--format",
                    "json",
                ]
            )
            if returncode not in (0, 1):
                raise MCPPolicyError(stderr or "doctor failed")
            return value

        return self._invoke("doctor", inspect)

    def rehearse_target(self, profile: str) -> dict[str, Any]:
        return self._invoke(
            "rehearse_target",
            lambda: rehearse(
                load_profile(
                    self.work.resolve(
                        profile,
                        kind="file",
                        max_bytes=MAX_MANIFEST_BYTES,
                    )
                )
            ).as_dict(),
        )

    def engagement_status(
        self,
        engagement: str,
        profile: str = "",
        torture_review: str = "",
    ) -> dict[str, Any]:
        def inspect() -> dict[str, Any]:
            root = self.work.resolve(engagement, kind="directory")
            selected_profile = (
                self.work.resolve(
                    profile,
                    kind="file",
                    max_bytes=MAX_MANIFEST_BYTES,
                )
                if profile
                else None
            )
            selected_review = (
                self.work.resolve(
                    torture_review,
                    kind="file",
                    max_bytes=MAX_MANIFEST_BYTES,
                )
                if torture_review
                else None
            )
            return assess(
                root,
                profile_path=selected_profile,
                torture_review_path=selected_review,
            )

        return self._invoke("engagement_status", inspect)

    def triage_capture(self, capture: str) -> dict[str, Any]:
        def inspect() -> Any:
            path = self.work.resolve(
                capture,
                kind="file",
                max_bytes=MAX_CAPTURE_BYTES,
            )
            returncode, value, stderr = self.runner.run_json(
                [self.helper, "triage", str(path), "--format", "json"]
            )
            if returncode not in (0, 1):
                raise MCPPolicyError(stderr or "capture triage failed")
            return value

        return self._invoke("triage_capture", inspect)

    def plan_campaign(self, manifest: str) -> dict[str, Any]:
        def compile_offline() -> dict[str, Any]:
            path = self.work.resolve(
                manifest,
                kind="file",
                max_bytes=MAX_MANIFEST_BYTES,
            )
            document, digest = load_manifest(path)
            cases = document.get("cases") if isinstance(document, dict) else None
            if not isinstance(cases, list):
                raise MCPPolicyError("campaign cases must be a list")
            counts = [
                item.get("count")
                for item in cases
                if isinstance(item, dict)
            ]
            if (
                len(counts) != len(cases)
                or any(type(count) is not int or count < 1 for count in counts)
                or sum(counts) > MAX_MCP_PLAN_STEPS
            ):
                raise MCPPolicyError(
                    f"MCP campaign planning is limited to {MAX_MCP_PLAN_STEPS} steps"
                )
            plan = compile_plan(document, digest, resolver=_offline_resolver)
            plan["networkActivity"] = False
            return plan

        return self._invoke("plan_campaign", compile_offline)

    def plan_envelope(self, manifest: str) -> dict[str, Any]:
        def compile_offline() -> dict[str, Any]:
            path = self.work.resolve(
                manifest,
                kind="file",
                max_bytes=MAX_MANIFEST_BYTES,
            )
            raw = path.read_bytes()
            document = yaml.safe_load(raw)
            if not isinstance(document, dict):
                raise MCPPolicyError("envelope manifest must be an object")
            try:
                maxima = document["authorization"]["hardMaxima"]
                ramp = document["ramp"]
                count = (
                    (maxima[ramp["dimension"]] - ramp["start"]) // ramp["step"]
                ) + 1
            except (KeyError, TypeError, ZeroDivisionError) as exc:
                raise MCPPolicyError("envelope ramp cannot be bounded safely") from exc
            if count > MAX_MCP_PLAN_STEPS:
                raise MCPPolicyError(
                    f"MCP envelope planning is limited to {MAX_MCP_PLAN_STEPS} steps"
                )
            plan = compile_envelope_plan(
                document,
                hashlib.sha256(raw).hexdigest(),
            )
            plan["networkActivity"] = False
            return plan

        return self._invoke("plan_envelope", compile_offline)

    def lint_evidence(self, directory: str) -> dict[str, Any]:
        def inspect() -> Any:
            root = self.work.resolve(directory, kind="directory")
            returncode, value, stderr = self.runner.run_json(
                [self.evidence_helper, "lint", str(root)]
            )
            if returncode not in (0, 1):
                raise MCPPolicyError(stderr or "evidence lint failed")
            return {**value, "networkActivity": False}

        return self._invoke("lint_evidence", inspect)

    def verify_evidence_pack(self, pack: str) -> dict[str, Any]:
        def inspect() -> Any:
            path = self.work.resolve(
                pack,
                kind="file",
                max_bytes=MAX_PACK_BYTES,
            )
            returncode, value, stderr = self.runner.run_json(
                [self.pack_helper, "verify", str(path), "--format", "json"]
            )
            if returncode not in (0, 1, 3):
                raise MCPPolicyError(stderr or "evidence-pack verification failed")
            return {**value, "networkActivity": False}

        return self._invoke("verify_evidence_pack", inspect)

    def run_torture_exit_gate(self) -> dict[str, Any]:
        return self._invoke("run_torture_exit_gate", run_exit_gate)


def self_test(work_root: str | Path) -> dict[str, Any]:
    tools = OfflineTools(work_root)
    sandbox = tools.sandbox_status()
    torture = tools.run_torture_exit_gate()
    passed = (
        sandbox["ok"]
        and sandbox["data"]["sandboxEnforced"]
        and torture["ok"]
        and torture["data"]["status"] == "pass"
    )
    return {
        "apiVersion": "sippycup.dev/mcp-self-test/v1",
        "status": "pass" if passed else "fail",
        "networkActivity": False,
        "sandbox": sandbox,
        "torture": torture,
    }


def _mount_is_read_only(path: Path) -> bool:
    """Inspect the nearest Linux mount entry without attempting a write."""
    try:
        target = path.resolve(strict=True)
        best_length = -1
        best_options: set[str] = set()
        for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
            before, _separator, after = line.partition(" - ")
            fields = before.split()
            if len(fields) < 6 or not after:
                continue
            mount_point = Path(
                fields[4]
                .replace("\\040", " ")
                .replace("\\011", "\t")
                .replace("\\134", "\\")
            )
            try:
                target.relative_to(mount_point)
            except ValueError:
                continue
            length = len(mount_point.parts)
            if length > best_length:
                best_length = length
                best_options = set(fields[5].split(","))
        return "ro" in best_options
    except OSError:
        return False
