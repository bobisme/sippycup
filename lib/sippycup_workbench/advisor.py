"""Network-free engagement readiness and next-action advisor."""

from __future__ import annotations

import itertools
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from sippycup_torture.exit_gate import run_exit_gate, validate_review

from .journal import JournalError, verify
from .profile import ProfileError, load_profile, rehearse


ADVISOR_VERSION = "sippycup.dev/engagement-status/v1"
MAX_RUNS = 1000
MAX_JSON_BYTES = 8 * 1024 * 1024
_SAFE_RUN_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _read_json(path: Path) -> Any:
    def no_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON field: {key}")
            value[key] = item
        return value

    try:
        if path.stat().st_size > MAX_JSON_BYTES:
            raise ValueError(f"{path.name} exceeds the 8 MiB inspection limit")
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=no_duplicates,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot inspect {path}: {exc}") from exc


def _action(
    identifier: str,
    title: str,
    reason: str,
    *,
    argv: list[str] | None = None,
    instruction: str | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "id": identifier,
        "title": title,
        "reason": reason,
        "networkActivity": False,
    }
    if argv is not None:
        value["argv"] = argv
    if instruction is not None:
        value["instruction"] = instruction
    return value


def _run_facts(root: Path) -> tuple[dict[str, Any], list[str], list[dict[str, Any]]]:
    run_root = root / "runs"
    facts = {
        "directory": str(run_root),
        "count": 0,
        "succeeded": 0,
        "incomplete": 0,
        "evidenceManifestMissing": 0,
        "privacyPass": 0,
        "privacyBlocked": 0,
    }
    warnings: list[str] = []
    actions: list[dict[str, Any]] = []
    if not run_root.exists():
        return facts, warnings, actions
    if not run_root.is_dir() or run_root.is_symlink():
        warnings.append("runs path is not a safe directory")
        return facts, warnings, actions
    children = list(itertools.islice(run_root.iterdir(), MAX_RUNS + 1))
    if len(children) > MAX_RUNS:
        warnings.append(f"runs directory exceeds the {MAX_RUNS}-entry inspection limit")
        children = children[:MAX_RUNS]
    children.sort(key=lambda item: item.name)
    for run in children:
        if not run.is_dir() or run.is_symlink():
            warnings.append("ignored a non-directory or symlinked run entry")
            continue
        if _SAFE_RUN_NAME.fullmatch(run.name) is None:
            warnings.append("ignored a run directory with an unsafe name")
            continue
        facts["count"] += 1
        result_path = run / "result.json"
        state = "incomplete"
        if result_path.is_file() and not result_path.is_symlink():
            try:
                result = _read_json(result_path)
                if isinstance(result, dict) and isinstance(result.get("state"), str):
                    state = result["state"]
            except ValueError as exc:
                warnings.append(str(exc))
        if state == "succeeded":
            facts["succeeded"] += 1
        else:
            facts["incomplete"] += 1
        manifest_path = run / "evidence-manifest.json"
        if not manifest_path.is_file() or manifest_path.is_symlink():
            facts["evidenceManifestMissing"] += 1
            actions.append(
                _action(
                    f"manifest-{run.name}",
                    f"Inventory evidence for run {run.name}",
                    "The run has no evidence manifest.",
                    argv=[
                        "./bin/sippycup-evidence",
                        "manifest",
                        str(run),
                        "--write",
                    ],
                )
            )
            continue
        try:
            manifest = _read_json(manifest_path)
            privacy = manifest.get("privacy", {}) if isinstance(manifest, dict) else {}
            status = privacy.get("status") if isinstance(privacy, dict) else None
            if status == "pass":
                facts["privacyPass"] += 1
            elif status == "blocked":
                facts["privacyBlocked"] += 1
                actions.append(
                    _action(
                        f"privacy-{run.name}",
                        f"Review privacy findings for run {run.name}",
                        "The evidence manifest reports blocked privacy findings.",
                        argv=[
                            "./bin/sippycup-evidence",
                            "lint",
                            str(run),
                        ],
                    )
                )
            else:
                warnings.append(f"run {run.name} has an invalid privacy status")
        except ValueError as exc:
            warnings.append(str(exc))
    return facts, warnings, actions


def assess(
    engagement: str | Path,
    *,
    profile_path: str | Path | None = None,
    torture_review_path: str | Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    root = Path(engagement)
    blockers: list[str] = []
    warnings: list[str] = []
    actions: list[dict[str, Any]] = []
    facts: dict[str, Any] = {
        "engagement": {"path": str(root), "exists": root.is_dir()},
        "journal": {"valid": False, "entries": 0, "missingEvidence": []},
        "profile": {"path": None, "present": False, "ready": False},
        "torture": {
            "technicalGate": "not-run",
            "defaultsReviewPresent": False,
            "defaultsReviewed": False,
            "liveExecutionAvailable": False,
        },
    }
    if not root.exists():
        blockers.append("engagement journal has not been initialized")
        actions.append(
            _action(
                "initialize-engagement",
                "Initialize the private engagement record",
                "Every assessment needs a private human record before execution.",
                argv=[
                    "./bin/sippycup",
                    "journal",
                    "init",
                    str(root),
                ],
            )
        )
        return {
            "apiVersion": ADVISOR_VERSION,
            "overall": "setup-required",
            "networkActivity": False,
            "facts": facts,
            "blockers": blockers,
            "warnings": warnings,
            "nextActions": actions,
        }
    try:
        journal = verify(root)
        facts["journal"] = {
            "valid": True,
            "entries": len(journal.entries),
            "finalSha256": journal.final_sha256,
            "missingEvidence": list(journal.missing_evidence),
            "kinds": {
                kind: sum(1 for entry in journal.entries if entry["kind"] == kind)
                for kind in (
                    "authorization",
                    "hypothesis",
                    "action",
                    "observation",
                    "finding",
                    "decision",
                    "follow-up",
                    "note",
                )
            },
        }
        if journal.missing_evidence:
            warnings.append("journal has missing or unsafe evidence references")
            actions.append(
                _action(
                    "repair-evidence-links",
                    "Resolve journal evidence references",
                    "Every report claim should link to retained regular files.",
                    argv=[
                        "./bin/sippycup",
                        "journal",
                        "verify",
                        str(root),
                    ],
                )
            )
    except JournalError as exc:
        blockers.append(f"journal verification failed: {exc}")

    selected_profile = (
        Path(profile_path)
        if profile_path is not None
        else root / "target-profile.yaml"
    )
    facts["profile"]["path"] = str(selected_profile)
    if not selected_profile.is_file() or selected_profile.is_symlink():
        blockers.append("target profile is missing")
        actions.append(
            _action(
                "create-target-profile",
                "Create a pending target profile",
                "The profile starts blocked and contains no invented approval or address.",
                argv=[
                    "./bin/sippycup",
                    "init",
                    str(selected_profile),
                ],
            )
        )
    else:
        facts["profile"]["present"] = True
        try:
            rehearsal = rehearse(load_profile(selected_profile), now=now)
            facts["profile"].update(
                {
                    "ready": rehearsal.ready,
                    "errors": list(rehearsal.errors),
                    "warnings": list(rehearsal.warnings),
                    "authorization": rehearsal.facts.get("authorization"),
                    "target": rehearsal.facts.get("target"),
                }
            )
            warnings.extend(rehearsal.warnings)
            if not rehearsal.ready:
                blockers.append("target profile rehearsal is blocked")
                actions.append(
                    _action(
                        "complete-target-authorization",
                        "Obtain and record Quad's exact live scope",
                        "; ".join(rehearsal.errors),
                        instruction=(
                            "Update the ignored target profile only from Quad's "
                            "written approval, then rehearse it again."
                        ),
                    )
                )
                actions.append(
                    _action(
                        "rehearse-target-profile",
                        "Rehearse the target profile",
                        "Rehearsal parses scope and expiration without network traffic.",
                        argv=[
                            "./bin/sippycup",
                            "rehearse",
                            str(selected_profile),
                        ],
                    )
                )
            else:
                actions.append(
                    _action(
                        "review-one-call-plan",
                        "Review the compiled one-call sequence",
                        "The profile is ready; this command still sends no packets.",
                        argv=[
                            "./bin/sippycup",
                            "one-call",
                            str(selected_profile),
                        ],
                    )
                )
        except ProfileError as exc:
            blockers.append(f"target profile cannot be read: {exc}")

    gate = run_exit_gate()
    facts["torture"]["technicalGate"] = gate["status"]
    if gate["status"] != "pass":
        blockers.append("torture technical exit gate failed")
    selected_review = (
        Path(torture_review_path)
        if torture_review_path is not None
        else root / "torture-defaults-review.json"
    )
    facts["torture"]["defaultsReviewPath"] = str(selected_review)
    if not selected_review.is_file() or selected_review.is_symlink():
        actions.append(
            _action(
                "create-torture-defaults-review",
                "Generate Quad's torture-defaults review packet",
                "Technical safety passed, but the service owner has not reviewed the defaults.",
                argv=[
                    "./bin/sippycup-torture",
                    "review-template",
                    "--reviewer",
                    "Quad",
                    "--output",
                    str(selected_review),
                ],
            )
        )
    else:
        facts["torture"]["defaultsReviewPresent"] = True
        try:
            review = validate_review(_read_json(selected_review), gate)
            facts["torture"]["defaultsReviewed"] = review["ready"]
            facts["torture"]["reviewErrors"] = review["errors"]
            if not review["ready"]:
                actions.append(
                    _action(
                        "complete-torture-defaults-review",
                        "Have Quad complete the defaults review",
                        "; ".join(review["errors"]),
                        argv=[
                            "./bin/sippycup-torture",
                            "validate-review",
                            str(selected_review),
                        ],
                    )
                )
        except ValueError as exc:
            warnings.append(f"cannot validate torture review: {exc}")

    run_facts, run_warnings, run_actions = _run_facts(root)
    facts["runs"] = run_facts
    warnings.extend(run_warnings)
    actions.extend(run_actions)
    if run_facts["count"] == 0 and facts["profile"]["ready"]:
        actions.append(
            _action(
                "prepare-baseline-record",
                "Prepare the first baseline run directory",
                "Start with one reviewed call before adversarial cases.",
                instruction=(
                    "Do not execute traffic automatically. Review the one-call "
                    "plan with Quad during the approved window."
                ),
            )
        )
    if run_facts["count"] > 0:
        actions.append(
            _action(
                "refresh-internal-report",
                "Render a new internal assessment draft",
                "Synthesize the verified journal after evidence review.",
                argv=[
                    "./bin/sippycup",
                    "journal",
                    "render",
                    str(root),
                    "--audience",
                    "internal",
                    "--output",
                    str(root / "internal-report-NEXT.md"),
                ],
            )
        )

    overall = (
        "blocked"
        if blockers
        else "ready-for-human-review"
    )
    return {
        "apiVersion": ADVISOR_VERSION,
        "overall": overall,
        "networkActivity": False,
        "facts": facts,
        "blockers": blockers,
        "warnings": sorted(set(warnings)),
        "nextActions": actions,
    }
