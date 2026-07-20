"""Separate SDK adapter for capability-backed live MCP tools."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from .capability import (
    CapabilityValidator,
    OpenSSLEd25519Verifier,
    ReplayAuditStore,
)
from .live_tools import LivePreparationTools
from .security import MCPPolicyError

TRUST_API_VERSION = "sippycup.dev/mcp-live-trust/v1"


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise MCPPolicyError(f"{name} is required for the live MCP server")
    return value


def _trust_keys(root_name: str | Path) -> dict[str, tuple[str, Path]]:
    supplied = Path(root_name)
    if supplied.is_symlink() or not supplied.is_dir():
        raise MCPPolicyError("live MCP trust root must be a real directory")
    if supplied.stat().st_mode & 0o022:
        raise MCPPolicyError("live MCP trust root must not be writable by others")
    root = supplied.resolve(strict=True)
    manifest = root / "trust.json"
    if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 64 * 1024:
        raise MCPPolicyError("live MCP trust manifest is unavailable or unsafe")
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        document: dict[str, Any] = {}
        for key, item in pairs:
            if key in document:
                raise MCPPolicyError("live MCP trust manifest contains duplicate fields")
            document[key] = item
        return document

    try:
        value = json.loads(
            manifest.read_bytes(), object_pairs_hook=reject_duplicates
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MCPPolicyError("live MCP trust manifest is invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != {"apiVersion", "keys"}:
        raise MCPPolicyError("live MCP trust manifest has missing or unknown fields")
    if value["apiVersion"] != TRUST_API_VERSION:
        raise MCPPolicyError("live MCP trust manifest version is unsupported")
    raw_keys = value["keys"]
    if not isinstance(raw_keys, list) or not raw_keys or len(raw_keys) > 32:
        raise MCPPolicyError("live MCP trust manifest must contain 1..32 keys")
    keys: dict[str, tuple[str, Path]] = {}
    for item in raw_keys:
        if not isinstance(item, dict) or set(item) != {
            "keyId",
            "issuer",
            "publicKey",
        }:
            raise MCPPolicyError("live MCP trust key has missing or unknown fields")
        key_id = item["keyId"]
        issuer = item["issuer"]
        relative = item["publicKey"]
        if (
            not isinstance(key_id, str)
            or not key_id
            or key_id in keys
            or not isinstance(issuer, str)
            or not issuer
            or len(key_id) > 128
            or len(issuer) > 128
            or not isinstance(relative, str)
            or not relative
            or len(relative) > 512
        ):
            raise MCPPolicyError("live MCP trust key fields are invalid or duplicated")
        requested = Path(relative)
        if requested.is_absolute() or any(part in {"", ".", ".."} for part in requested.parts):
            raise MCPPolicyError("live MCP public key path must remain beneath trust root")
        candidate = root / requested
        if candidate.is_symlink() or not candidate.is_file():
            raise MCPPolicyError("live MCP public key is unavailable or unsafe")
        resolved = candidate.resolve(strict=True)
        if root not in resolved.parents:
            raise MCPPolicyError("live MCP public key escaped the trust root")
        keys[key_id] = (issuer, resolved)
    return keys


def build_live_tools() -> LivePreparationTools:
    state_root = Path(_required_environment("SIPPYCUP_MCP_LIVE_STATE_ROOT"))
    snapshot_root = state_root / "snapshots"
    audit_root = state_root / "audit"
    return LivePreparationTools(
        _required_environment("SIPPYCUP_MCP_LIVE_INPUT_ROOT"),
        snapshot_root,
        CapabilityValidator(
            OpenSSLEd25519Verifier(
                _trust_keys(_required_environment("SIPPYCUP_MCP_LIVE_TRUST_ROOT"))
            ),
            ReplayAuditStore(audit_root),
        ),
        client_id=_required_environment("SIPPYCUP_MCP_LIVE_CLIENT_ID"),
    )


def build_server():
    try:
        from mcp.server.fastmcp import FastMCP
        from mcp.types import ToolAnnotations
    except ImportError as exc:
        raise RuntimeError(
            "Sippycup live MCP requires mcp==1.27.2; use the prepared container"
        ) from exc

    tools = build_live_tools()
    server = FastMCP(
        "Sippycup Live",
        instructions=(
            "Prepare immutable reviewed artifacts and perform only one "
            "capability-bound SIP OPTIONS preflight. This server cannot mint grants."
        ),
        log_level="WARNING",
    )
    prepare_annotations = ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
    preflight_annotations = ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True,
    )
    server.tool(
        name="prepare_assessment",
        description=(
            "Verify a prepare grant and freeze exact profile/plan bytes without traffic."
        ),
        annotations=prepare_annotations,
        structured_output=True,
    )(tools.prepare_assessment)
    server.tool(
        name="preflight_target",
        description=(
            "Consume a matching grant and send exactly one SIP OPTIONS transaction "
            "to the single literal reviewed destination."
        ),
        annotations=preflight_annotations,
        structured_output=True,
    )(tools.preflight_target)
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sippycup-mcp-live",
        description="Run Sippycup's separate capability-backed MCP server.",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate trust, state, inputs, and client identity without traffic",
    )
    arguments = parser.parse_args(argv)
    if arguments.check_config:
        build_live_tools()
        print(
            json.dumps(
                {
                    "apiVersion": "sippycup.dev/mcp-live-config-check/v1",
                    "ok": True,
                    "networkActivity": False,
                },
                sort_keys=True,
            )
        )
        return 0
    build_server().run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
