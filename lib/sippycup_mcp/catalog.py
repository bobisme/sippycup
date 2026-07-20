"""Explicitly allowlisted MCP resources."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import MCP_API_VERSION
from .security import MCPPolicyError

MAX_RESOURCE_BYTES = 2 * 1024 * 1024

DOCUMENTS = {
    "getting-started": "README.md",
    "cli": "docs/CLI.md",
    "workbench": "docs/WORKBENCH.md",
    "assessment-workflow": "docs/ASSESSMENT-WORKFLOW.md",
    "campaign-manifest": "docs/CAMPAIGN-MANIFEST.md",
    "evidence-privacy": "docs/EVIDENCE-PRIVACY.md",
    "mcp": "docs/MCP.md",
    "mcp-security": "docs/MCP-SECURITY.md",
    "webrtc-contracts": "docs/WEBRTC-CONTRACTS.md",
    "webrtc-ice-turn": "docs/WEBRTC-ICE-TURN.md",
    "webrtc-peer": "docs/WEBRTC-PEER.md",
    "webrtc-threat-model": "docs/WEBRTC-THREAT-MODEL.md",
}
SCHEMAS = {
    "commands-v1": "schemas/commands-v1.schema.json",
    "target-profile-v1": "schemas/target-profile-v1.schema.json",
    "engagement-status-v1": "schemas/engagement-status-v1.schema.json",
    "campaign-v1": "schemas/campaign-v1.schema.yaml",
    "envelope-v1": "schemas/envelope-v1.schema.json",
    "evidence-manifest-v1": "schemas/evidence-manifest-v1.schema.json",
    "evidence-pack-v1": "schemas/evidence-pack-v1.schema.json",
    "torture-exit-gate-v1": "schemas/torture-exit-gate-v1.schema.json",
    "mcp-result-v1": "schemas/mcp-result-v1.schema.json",
    "webrtc-scenario-v1": "schemas/webrtc-scenario-v1.schema.json",
    "webrtc-result-v1": "schemas/webrtc-result-v1.schema.json",
    "webrtc-adapter-capabilities-v1": "schemas/webrtc-adapter-capabilities-v1.schema.json",
    "webrtc-peer-self-test-v1": "schemas/webrtc-peer-self-test-v1.schema.json",
}


class Catalog:
    def __init__(self, share_root: str | Path):
        supplied = Path(share_root)
        if supplied.is_symlink() or not supplied.is_dir():
            raise MCPPolicyError("MCP share root must be a real directory")
        self.root = supplied.resolve(strict=True)

    def _read(self, mapping: dict[str, str], name: str) -> str:
        relative = mapping.get(name)
        if relative is None:
            raise MCPPolicyError("resource name is not allowlisted")
        candidate = self.root / relative
        if candidate.is_symlink() or not candidate.is_file():
            raise MCPPolicyError("allowlisted resource is unavailable")
        resolved = candidate.resolve(strict=True)
        if self.root not in resolved.parents:
            raise MCPPolicyError("allowlisted resource escaped the share root")
        if resolved.stat().st_size > MAX_RESOURCE_BYTES:
            raise MCPPolicyError("allowlisted resource exceeds the size limit")
        return resolved.read_text(encoding="utf-8")

    def read_document(self, name: str) -> str:
        return self._read(DOCUMENTS, name)

    def read_schema(self, name: str) -> str:
        return self._read(SCHEMAS, name)

    def commands(self) -> str:
        path = self.root / "config" / "commands.tsv"
        if path.is_symlink() or not path.is_file():
            raise MCPPolicyError("command registry is unavailable")
        commands = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            fields = line.split("|")
            if len(fields) != 7:
                raise MCPPolicyError("command registry is malformed")
            name, mode, _host, _container, group, activity, summary = fields
            commands.append(
                {
                    "name": name,
                    "group": group,
                    "activity": activity,
                    "execution": mode,
                    "summary": summary,
                }
            )
        return json.dumps(
            {
                "apiVersion": "sippycup.dev/commands/v1",
                "commands": commands,
                "networkActivity": False,
            },
            indent=2,
            sort_keys=True,
        )

    def index(self) -> str:
        return json.dumps(
            {
                "apiVersion": MCP_API_VERSION,
                "networkActivity": False,
                "resources": {
                    "static": [
                        "sippycup://catalog",
                        "sippycup://commands",
                        "sippycup://security",
                    ],
                    "documents": sorted(DOCUMENTS),
                    "schemas": sorted(SCHEMAS),
                },
                "excluded": [
                    "arbitrary repository files",
                    "assessment journals",
                    "credentials and secret providers",
                    "raw packet captures",
                    "run directories and payloads",
                ],
            },
            indent=2,
            sort_keys=True,
        )
