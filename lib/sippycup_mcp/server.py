"""Official-SDK adapter for Sippycup's local offline MCP surface."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import SERVER_VERSION
from .catalog import Catalog
from .tools import OfflineTools, self_test


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _work_root() -> Path:
    configured = os.environ.get("SIPPYCUP_MCP_WORK_ROOT")
    if configured:
        return Path(configured)
    return Path("/work") if Path("/work").is_dir() else _project_root() / "work"


def _share_root() -> Path:
    configured = os.environ.get("SIPPYCUP_MCP_SHARE_ROOT")
    if configured:
        return Path(configured)
    installed = Path("/usr/local/share/sippycup")
    if (installed / "config" / "commands.tsv").is_file():
        return installed
    return _project_root()


def _helper(name: str) -> str:
    installed = shutil.which(name)
    if installed is not None:
        return installed
    local = _project_root() / "bin" / name
    return str(local)


def build_server():
    try:
        from mcp.server.fastmcp import FastMCP
        from mcp.types import ToolAnnotations
    except ImportError as exc:
        raise RuntimeError(
            "Sippycup MCP requires mcp==1.27.2; use the prepared container "
            "through './bin/sippycup mcp'"
        ) from exc

    catalog = Catalog(_share_root())
    tools = OfflineTools(
        _work_root(),
        helper=_helper("sippycup-workbench"),
        evidence_helper=_helper("sippycup-evidence"),
        pack_helper=_helper("sippycup-pack"),
    )
    server = FastMCP(
        "Sippycup",
        instructions=(
            "Discover and run Sippycup's explicitly allowlisted offline assessment "
            "workflows. This server cannot authorize or initiate target traffic."
        ),
        log_level="WARNING",
    )
    read_only = ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )

    @server.resource(
        "sippycup://catalog",
        name="catalog",
        description="Allowlisted Sippycup MCP resource index.",
        mime_type="application/json",
    )
    def resource_catalog() -> str:
        return catalog.index()

    @server.resource(
        "sippycup://commands",
        name="commands",
        description="Stable command registry with execution and activity classes.",
        mime_type="application/json",
    )
    def resource_commands() -> str:
        return catalog.commands()

    @server.resource(
        "sippycup://security",
        name="security",
        description="MCP trust boundaries, guarantees, and exclusions.",
        mime_type="text/markdown",
    )
    def resource_security() -> str:
        return catalog.read_document("mcp-security")

    @server.resource(
        "sippycup://docs/{name}",
        name="documentation",
        description="One allowlisted Sippycup public document; enumerate names in the catalog.",
        mime_type="text/markdown",
    )
    def resource_document(name: str) -> str:
        return catalog.read_document(name)

    @server.resource(
        "sippycup://schemas/{name}",
        name="schema",
        description="One allowlisted Sippycup schema; enumerate names in the catalog.",
        mime_type="text/plain",
    )
    def resource_schema(name: str) -> str:
        return catalog.read_schema(name)

    def register(name: str, description: str, function):
        server.tool(
            name=name,
            description=description,
            annotations=read_only,
            structured_output=True,
        )(function)

    register(
        "sandbox_status",
        "Inspect MCP container capabilities and interfaces without sending traffic.",
        tools.sandbox_status,
    )
    register(
        "doctor",
        "Inventory installed Sippycup tools and offline runtime readiness.",
        tools.doctor,
    )
    register(
        "rehearse_target",
        "Validate a relative target-profile path without DNS or target traffic.",
        tools.rehearse_target,
    )
    register(
        "engagement_status",
        "Return redacted readiness and safe next actions for a relative engagement directory.",
        tools.engagement_status,
    )
    register(
        "triage_capture",
        "Summarize an existing relative PCAP without returning payload values.",
        tools.triage_capture,
    )
    register(
        "plan_campaign",
        "Compile a campaign with literal targets only; never execute it.",
        tools.plan_campaign,
    )
    register(
        "plan_envelope",
        "Compile a bounded capacity envelope without executing load.",
        tools.plan_envelope,
    )
    register(
        "lint_evidence",
        "Privacy-lint an existing relative evidence directory without modifying it.",
        tools.lint_evidence,
    )
    register(
        "verify_evidence_pack",
        "Verify an existing relative evidence pack without extracting it.",
        tools.verify_evidence_pack,
    )
    register(
        "run_torture_exit_gate",
        "Run the deterministic offline technical torture gate; this authorizes no traffic.",
        tools.run_torture_exit_gate,
    )
    return server


def _exit_gate_fixtures(root: Path) -> None:
    from sippycup_workbench.profile import default_profile, write_profile

    write_profile(
        root / "target.yaml",
        default_profile(name="mcp-gate", host="127.0.0.1"),
        force=False,
    )
    (root / "engagement").mkdir()
    (root / "evidence").mkdir()
    campaign = {
        "apiVersion": "sippycup.dev/v1",
        "kind": "Campaign",
        "metadata": {"name": "mcp-gate"},
        "authorization": {
            "networks": ["127.0.0.0/8"],
            "signalingPorts": [5060],
            "mediaPorts": {"start": 10000, "end": 10020},
            "transports": ["udp"],
            "credentialRefs": [],
            "ceilings": {
                "calls": 1,
                "packets": 6,
                "bytes": 8192,
                "durationSeconds": 30,
                "concurrentCalls": 1,
                "packetsPerSecond": 6,
                "callsPerSecond": 1,
            },
            "stopConditions": {
                "consecutiveFailures": 1,
                "unexpectedResponse": True,
                "packetLossPercent": 5,
            },
        },
        "targets": [
            {
                "name": "loopback",
                "address": "127.0.0.1",
                "signaling": {"transport": "udp", "port": 5060},
            }
        ],
        "cases": [
            {
                "id": "options",
                "type": "options",
                "target": "loopback",
                "count": 1,
                "budget": {
                    "packetsPerRun": 4,
                    "bytesPerRun": 4096,
                    "durationSecondsPerRun": 3,
                },
            }
        ],
        "expectations": {
            "allowedSipStatuses": [200],
            "requireBidirectionalRtp": False,
        },
        "evidence": {
            "capture": True,
            "retainPayload": False,
            "directory": "evidence/mcp-gate",
        },
    }
    envelope = {
        "apiVersion": "sippycup.dev/envelope/v1",
        "kind": "Envelope",
        "metadata": {"name": "mcp-gate"},
        "authorization": {
            "hardMaxima": {
                "callsPerSecond": 2,
                "concurrentCalls": 2,
                "mediaPacketsPerSecond": 100,
                "totalCalls": 10,
                "durationSeconds": 60,
                "holdSeconds": 2,
                "cooldownSeconds": 2,
                "recoveryDeadlineSeconds": 10,
            }
        },
        "workload": {
            "callsPerSecond": 1,
            "concurrentCalls": 1,
            "mediaPacketsPerSecond": 50,
            "callDurationSeconds": 5,
        },
        "ramp": {"dimension": "callsPerSecond", "start": 1, "step": 1},
    }
    import yaml

    (root / "campaign.yaml").write_text(yaml.safe_dump(campaign), encoding="utf-8")
    (root / "envelope.yaml").write_text(yaml.safe_dump(envelope), encoding="utf-8")
    sip = (
        b"OPTIONS sip:service@127.0.0.1 SIP/2.0\r\n"
        b"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-mcp\r\n"
        b"From: <sip:a@127.0.0.1>;tag=a\r\n"
        b"To: <sip:service@127.0.0.1>\r\n"
        b"Call-ID: mcp-fixture\r\n"
        b"CSeq: 1 OPTIONS\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    udp = struct.pack("!HHHH", 5060, 5060, 8 + len(sip), 0) + sip
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        1,
        0,
        64,
        17,
        0,
        bytes((127, 0, 0, 1)),
        bytes((127, 0, 0, 1)),
    )
    packet = ethernet + ipv4 + udp
    pcap = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for second in (1, 2):
        pcap += struct.pack("<IIII", second, 0, len(packet), len(packet)) + packet
    (root / "capture.pcap").write_bytes(pcap)
    pack_fixture = _share_root() / "fixtures" / "sanitized-evidence.tar"
    if not pack_fixture.is_file():
        pack_fixture = (
            _share_root()
            / "examples"
            / "evidence-pack"
            / "sanitized-evidence.tar"
        )
    shutil.copyfile(pack_fixture, root / "evidence.tar")


async def _interoperability_gate() -> dict[str, Any]:
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError as exc:
        raise RuntimeError("mcp==1.27.2 is required for the exit gate") from exc

    checks: list[dict[str, Any]] = []
    outer_sandbox = OfflineTools(_work_root()).sandbox_status()
    with tempfile.TemporaryDirectory(prefix="sippycup-mcp-gate-") as root_name:
        fixture_root = Path(root_name)
        _exit_gate_fixtures(fixture_root)
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "sippycup_mcp.server"],
            env={
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
                "SIPPYCUP_MCP_WORK_ROOT": str(fixture_root),
                "SIPPYCUP_MCP_SHARE_ROOT": str(_share_root()),
                "SIPPYCUP_MCP_REQUIRE_SANDBOX": "0",
            },
        )
        async with stdio_client(parameters) as streams:
            async with ClientSession(*streams) as session:
                initialized = await session.initialize()
                checks.append(
                    {
                        "id": "initialize",
                        "passed": initialized.serverInfo.name == "Sippycup",
                    }
                )
                resources = await session.list_resources()
                resource_uris = {str(item.uri) for item in resources.resources}
                checks.append(
                    {
                        "id": "static-resources",
                        "passed": {
                            "sippycup://catalog",
                            "sippycup://commands",
                            "sippycup://security",
                        }.issubset(resource_uris),
                    }
                )
                catalog = await session.read_resource("sippycup://catalog")
                checks.append(
                    {
                        "id": "read-resource",
                        "passed": bool(catalog.contents),
                    }
                )
                listed = await session.list_tools()
                names = {item.name for item in listed.tools}
                expected = {
                    "sandbox_status",
                    "doctor",
                    "rehearse_target",
                    "engagement_status",
                    "triage_capture",
                    "plan_campaign",
                    "plan_envelope",
                    "lint_evidence",
                    "verify_evidence_pack",
                    "run_torture_exit_gate",
                }
                checks.append(
                    {
                        "id": "explicit-tool-allowlist",
                        "passed": names == expected,
                    }
                )
                calls = {
                    "sandbox_status": {},
                    "doctor": {},
                    "rehearse_target": {"profile": "target.yaml"},
                    "engagement_status": {"engagement": "engagement"},
                    "triage_capture": {"capture": "capture.pcap"},
                    "plan_campaign": {"manifest": "campaign.yaml"},
                    "plan_envelope": {"manifest": "envelope.yaml"},
                    "lint_evidence": {"directory": "evidence"},
                    "verify_evidence_pack": {"pack": "evidence.tar"},
                    "run_torture_exit_gate": {},
                }
                results = {}
                for name, arguments in calls.items():
                    response = await session.call_tool(name, arguments)
                    results[name] = response.structuredContent or {}
                checks.append(
                    {
                        "id": "all-offline-tools",
                        "passed": all(
                            value.get("ok") is True for value in results.values()
                        )
                        and results["run_torture_exit_gate"]
                        .get("data", {})
                        .get("status")
                        == "pass",
                    }
                )
                sandbox_data = results["sandbox_status"].get("data", {})
                checks.append(
                    {
                        "id": "offline-container-containment",
                        "passed": outer_sandbox.get("ok") is True
                        and outer_sandbox.get("data", {}).get("sandboxEnforced")
                        is True
                        and not sandbox_data.get("capNetRaw")
                        and not sandbox_data.get("capNetAdmin")
                        and not sandbox_data.get("rawSocketAvailable")
                        and not sandbox_data.get("nonLoopbackInterfaces"),
                    }
                )
                schema_resource = await session.read_resource(
                    "sippycup://schemas/mcp-result-v1"
                )
                schema_text = schema_resource.contents[0].text
                from jsonschema import validate

                schema = json.loads(schema_text)
                schema_valid = True
                try:
                    for value in results.values():
                        validate(instance=value, schema=schema)
                except Exception:
                    schema_valid = False
                checks.append(
                    {
                        "id": "structured-result-schema",
                        "passed": schema_valid,
                    }
                )
                rejected = await session.call_tool(
                    "rehearse_target",
                    {"profile": "../escape.yaml"},
                )
                rejected_result = rejected.structuredContent or {}
                checks.append(
                    {
                        "id": "path-traversal-rejected",
                        "passed": rejected_result.get("ok") is False
                        and rejected_result.get("errors", [{}])[0].get("code")
                        == "mcp.policy_rejected",
                    }
                )
    return {
        "apiVersion": "sippycup.dev/mcp-exit-gate/v1",
        "status": "pass" if all(item["passed"] for item in checks) else "fail",
        "networkActivity": False,
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sippycup-mcp",
        description="Local, stdio-only, offline Sippycup MCP server.",
    )
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--exit-gate", action="store_true")
    args = parser.parse_args(argv)
    if args.version:
        print(f"sippycup-mcp {SERVER_VERSION}")
        return 0
    if args.self_test:
        report = self_test(_work_root())
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["status"] == "pass" else 1
    if args.exit_gate:
        report = asyncio.run(_interoperability_gate())
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["status"] == "pass" else 1
    try:
        server = build_server()
    except RuntimeError as exc:
        print(f"sippycup-mcp: {exc}", file=sys.stderr)
        return 2
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
