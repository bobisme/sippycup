"""Network-free CLI for WebRTC scenario, adapter, and result validation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from .contracts import CAPABILITIES, ContractError, validate_result, validate_scenario

MAX_INPUT_BYTES = 2 * 1024 * 1024
CAPABILITY_VERSION = "sippycup.dev/webrtc-adapter-capabilities/v1"
VALIDATION_VERSION = "sippycup.dev/webrtc-validation/v1"


def _read(path_text: str) -> Any:
    path = Path(path_text)
    if path.is_symlink() or not path.is_file():
        raise ContractError(f"input must be a regular non-symlink file: {path_text}")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ContractError(f"input exceeds {MAX_INPUT_BYTES} bytes: {path_text}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read JSON input {path_text}: {exc}") from exc


def _adapter_capabilities(document: Any) -> tuple[str, list[str]]:
    if not isinstance(document, dict):
        raise ContractError("adapter capability document must be an object")
    required = {
        "apiVersion",
        "kind",
        "implementation",
        "implementationVersion",
        "buildCommit",
        "sourceDigest",
        "goVersion",
        "capabilities",
        "verifiedCapabilities",
        "networkActivity",
    }
    missing = required - set(document)
    extra = set(document) - required
    if missing:
        raise ContractError(
            "adapter capability document is missing: " + ", ".join(sorted(missing))
        )
    if extra:
        raise ContractError(
            "adapter capability document has unknown fields: "
            + ", ".join(sorted(extra))
        )
    if document["apiVersion"] != CAPABILITY_VERSION:
        raise ContractError("adapter capability apiVersion is unsupported")
    if document["kind"] != "WebRTCAdapterCapabilities":
        raise ContractError("adapter capability kind is unsupported")
    if document["networkActivity"] is not False:
        raise ContractError("adapter capability discovery must be network-free")
    implementation = document["implementation"]
    if not isinstance(implementation, str) or not implementation:
        raise ContractError("adapter implementation must be a non-empty string")
    capabilities = document["capabilities"]
    verified = document["verifiedCapabilities"]
    for name, values in (
        ("capabilities", capabilities),
        ("verifiedCapabilities", verified),
    ):
        if not isinstance(values, list) or len(values) != len(set(values)):
            raise ContractError(f"adapter {name} must be a unique array")
        if any(
            not isinstance(value, str) or value not in CAPABILITIES
            for value in values
        ):
            raise ContractError(f"adapter {name} contains unsupported values")
    if not set(verified) <= set(capabilities):
        raise ContractError("verifiedCapabilities must be a subset of capabilities")
    return implementation, capabilities


def validate_documents(
    scenario_document: Any,
    *,
    capability_document: Any | None = None,
    result_document: Any | None = None,
) -> dict[str, Any]:
    if not isinstance(scenario_document, dict):
        raise ContractError("scenario must be an object")
    adapter_name = "scenario-declared"
    if capability_document is None:
        adapter = scenario_document.get("adapter")
        capabilities = (
            adapter.get("requiredCapabilities", [])
            if isinstance(adapter, dict)
            else []
        )
        capability_binding = "not-supplied"
    else:
        adapter_name, capabilities = _adapter_capabilities(capability_document)
        capability_binding = "validated"
    scenario = validate_scenario(scenario_document, capabilities)
    result_summary = None
    if result_document is not None:
        result = validate_result(result_document)
        if result["scenarioId"] != scenario["metadata"]["scenarioId"]:
            raise ContractError("result scenarioId does not bind the supplied scenario")
        result_summary = {
            "scenarioId": result["scenarioId"],
            "status": result["status"],
            "networkActivity": result["networkActivity"],
        }
    return {
        "apiVersion": VALIDATION_VERSION,
        "valid": True,
        "networkActivity": False,
        "scenario": {
            "scenarioId": scenario["metadata"]["scenarioId"],
            "executionClass": scenario["executionClass"],
        },
        "adapter": {
            "name": adapter_name,
            "capabilityBinding": capability_binding,
            "capabilities": sorted(capabilities),
        },
        "result": result_summary,
        "authorizationGranted": False,
    }


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sippycup webrtc validate",
        description="Validate WebRTC scenario and result contracts without traffic.",
    )
    parser.add_argument("scenario")
    parser.add_argument("--capabilities", help="adapter capability JSON")
    parser.add_argument("--result", help="normalized result JSON")
    parsed = parser.parse_args(arguments)
    try:
        report = validate_documents(
            _read(parsed.scenario),
            capability_document=(
                _read(parsed.capabilities) if parsed.capabilities else None
            ),
            result_document=_read(parsed.result) if parsed.result else None,
        )
    except ContractError as exc:
        print(f"WebRTC validation rejected: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
