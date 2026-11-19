"""Fixed helper for one reviewed, credential-free campaign call."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from sippycup.integration import AuthorizationLapsed, execute_campaign
from sippycup.runtime import load_plan


def execute(
    plan_path: Path,
    manifest_path: Path,
    run_root: Path,
    scope_manifest: Path | None = None,
) -> dict[str, Any]:
    """Run the frozen one-call plan.

    ``manifest_path`` is the frozen copy whose bytes bind the plan.
    ``scope_manifest`` is the reviewed manifest where the operator keeps it:
    the approval gate reads ``scope.yaml`` beside it before the run and before
    the step, as ``campaign run`` does (bn-wcx2).
    """
    plan = load_plan(plan_path)
    manifest = manifest_path.read_bytes()
    result, run_directory = execute_campaign(
        plan,
        manifest_bytes=manifest,
        run_root=run_root,
        manifest_path=scope_manifest,
    )
    result_path = run_directory / "result.json"
    evidence_path = run_directory / "evidence-manifest.json"
    return {
        "apiVersion": "sippycup.dev/mcp-one-call-receipt/v1",
        "state": result.state,
        "exitCode": result.exit_code,
        "completedSteps": result.completed_steps,
        "evidenceId": run_directory.name,
        "resultSha256": hashlib.sha256(result_path.read_bytes()).hexdigest(),
        "evidenceManifestSha256": hashlib.sha256(
            evidence_path.read_bytes()
        ).hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sippycup-mcp-one-call",
        description="Execute one prevalidated credential-free campaign call.",
    )
    parser.add_argument("plan", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("run_root", type=Path)
    parser.add_argument(
        "--scope-manifest",
        type=Path,
        help="the reviewed manifest in the input root; scope.yaml beside it is re-read",
    )
    arguments = parser.parse_args(argv)
    try:
        receipt = execute(
            arguments.plan, arguments.manifest, arguments.run_root, arguments.scope_manifest
        )
    except Exception as exc:
        failure = {
            "apiVersion": "sippycup.dev/mcp-one-call-receipt/v1",
            "state": "failed",
            "error": type(exc).__name__,
        }
        if isinstance(exc, AuthorizationLapsed):
            # Approval facts only (window, scope file state); raised before
            # anything was created or sent.
            failure["detail"] = str(exc)[:512]
        print(json.dumps(failure, sort_keys=True))
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
