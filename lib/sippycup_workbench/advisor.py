"""Network-free engagement readiness and next-action advisor."""

from __future__ import annotations

import itertools
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from sippycup_torture.exit_gate import run_exit_gate, validate_review

from .journal import JournalError, _load_metadata, verify
from .profile import ProfileError, load_profile, rehearse
from .scope import SCOPE_FILE, inspect as inspect_scope
from .scope_derive import derivative_state


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
                        "./bin/sippycup",
                        "evidence",
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
                            "./bin/sippycup",
                        "evidence",
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


def _call_facts(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]], bool]:
    """Inspect guided-call run directories (``calls/`` and ``practice-calls/``).

    Returns the facts for ``calls/``, evidence actions for any guided-call
    run without a manifest, and whether a passing practice call exists.
    """
    facts = {"directory": str(root / "calls"), "count": 0, "passed": 0, "evidenceManifestMissing": 0}
    actions: list[dict[str, Any]] = []
    practice_passed = False
    newest: tuple[Path, Any] | None = None
    for name in ("calls", "practice-calls"):
        directory = root / name
        if not directory.is_dir() or directory.is_symlink():
            continue
        children = sorted(itertools.islice(directory.iterdir(), MAX_RUNS))
        for run in children:
            if not run.is_dir() or run.is_symlink() or _SAFE_RUN_NAME.fullmatch(run.name) is None:
                continue
            verdict = None
            result_path = run / "result.json"
            if result_path.is_file() and not result_path.is_symlink():
                try:
                    result = _read_json(result_path)
                    if isinstance(result, dict):
                        verdict = result.get("verdict")
                except ValueError:
                    verdict = None
            if name == "practice-calls":
                practice_passed = practice_passed or verdict == "pass"
                continue
            facts["count"] += 1
            facts["passed"] += 1 if verdict == "pass" else 0
            newest = (run, verdict)
            manifest = run / "evidence-manifest.json"
            if not manifest.is_file() or manifest.is_symlink():
                facts["evidenceManifestMissing"] += 1
                actions.append(
                    _action(
                        f"calls-manifest-{run.name}",
                        f"Inventory evidence for guided call {run.name}",
                        "The guided-call run has no evidence manifest (it was interrupted or is unfinished).",
                        argv=["./bin/sippycup", "evidence", "manifest", str(run), "--write"],
                    )
                )
    if newest is not None and isinstance(newest[1], str) and newest[1] != "pass":
        actions.append(
            _action(
                f"calls-diagnose-{newest[0].name}",
                f"Explain why the newest guided call did not pass ({newest[1]})",
                "One page: where it stopped, the decisive evidence, whose side it is on, and the next step. Reads files only.",
                argv=["./bin/sippycup", "diagnose", str(newest[0])],
            )
        )
    return facts, actions, practice_passed


def _first_dial(root: Path, now: datetime | None) -> str | None:
    """The first destination user in the scope whose expected behaviour is not reject."""
    scope_file = root / SCOPE_FILE
    if not scope_file.is_file() or scope_file.is_symlink():
        return None
    document = inspect_scope(scope_file, now=now).document or {}
    for item in document.get("destinations") or []:
        if isinstance(item, dict) and item.get("expect") != "reject" and isinstance(item.get("user"), (str, int)):
            user = str(item["user"])
            if re.fullmatch(r"[A-Za-z0-9+*._-]{1,64}", user):
                return user
    return None


def _scope_facts(
    root: Path, now: datetime | None
) -> tuple[dict[str, Any], list[str], list[str], list[dict[str, Any]]]:
    """Inspect the scope intake file and its derivatives; all local and offline."""
    scope_file = root / SCOPE_FILE
    facts: dict[str, Any] = {"path": str(scope_file), "present": False}
    blockers: list[str] = []
    warnings: list[str] = []
    actions: list[dict[str, Any]] = []
    if not scope_file.is_file() or scope_file.is_symlink():
        actions.append(
            _action(
                "scope-init",
                "Create the private scope intake file",
                "One scope file replaces hand-copying the owner's answers into the "
                "profile, campaign manifest, and oracle expectations.",
                argv=["./bin/sippycup", "scope", "init", str(root)],
            )
        )
        actions.append(
            _action(
                "scope-questions",
                "Render the question sheet for the service owner",
                "The sheet lists every answer needed before any live step.",
                argv=["./bin/sippycup", "scope", "questions"],
            )
        )
        return facts, blockers, warnings, actions
    report = inspect_scope(scope_file, now=now)
    derivatives = derivative_state(root, scope_file)
    facts.update(
        {
            "present": True,
            "sha256": report.sha256,
            "ok": report.ok,
            "complete": report.complete,
            "consistent": report.consistent,
            "errorCount": len(report.errors),
            "errorCodes": sorted({item.code for item in report.errors}),
            "derivatives": derivatives,
        }
    )
    if not report.ok:
        blockers.append(
            f"scope intake is incomplete or inconsistent ({len(report.errors)} errors)"
        )
        actions.append(
            _action(
                "scope-check",
                "Check the scope intake file",
                "Lists exactly which answers are missing, malformed, or inconsistent.",
                argv=["./bin/sippycup", "scope", "check", str(root)],
            )
        )
        actions.append(
            _action(
                "scope-questions-open",
                "Send the unanswered questions to the service owner",
                "Marks each question answered or unanswered without showing values.",
                argv=["./bin/sippycup", "scope", "questions", str(root)],
            )
        )
    state = derivatives["state"]
    if state in {"stale", "invalid"}:
        stale = sorted(
            f"{name} ({item['state']})"
            for name, item in derivatives["items"].items()
            if item["state"] != "current"
        )
        blockers.append(
            "scope derivatives are stale: " + (", ".join(stale) or derivatives.get("problem", state))
        )
        actions.append(
            _action(
                "scope-compile",
                "Regenerate the derived profile, manifest, and expectations",
                "The scope file changed since compile, or a derivative was edited or removed.",
                argv=["./bin/sippycup", "scope", "compile", str(root)],
            )
        )
    elif state == "not-compiled" and report.ok:
        actions.append(
            _action(
                "scope-compile",
                "Generate the profile, manifest, and expectations from the scope file",
                "The scope is complete and consistent but nothing was generated from it.",
                argv=["./bin/sippycup", "scope", "compile", str(root)],
            )
        )
    elif state == "partial":
        warnings.append("some scope derivatives were skipped for unanswered questions")
    return facts, blockers, warnings, actions


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
    # Name the engagement's recorded owner in the advice, not a fixed name.
    try:
        owner = str(_load_metadata(root)["owner"]).strip() or "the service owner"
    except (JournalError, KeyError):
        owner = "the service owner"
    owner_s = f"{owner}'" if owner.endswith("s") else f"{owner}'s"
    scope_facts, scope_blockers, scope_warnings, scope_actions = _scope_facts(root, now)
    facts["scope"] = scope_facts
    blockers.extend(scope_blockers)
    warnings.extend(scope_warnings)
    actions.extend(scope_actions)
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
        if not scope_facts["present"]:
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
                        f"Obtain and record {owner_s} exact live scope",
                        "; ".join(rehearsal.errors),
                        instruction=(
                            f"Update the ignored target profile only from {owner_s} "
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
                f"Generate {owner_s} torture-defaults review packet",
                "Technical safety passed, but the service owner has not reviewed the defaults.",
                argv=[
                    "./bin/sippycup",
                    "torture",
                    "review-template",
                    "--reviewer",
                    owner,
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
                        f"Have {owner} complete the defaults review",
                        "; ".join(review["errors"]),
                        argv=[
                            "./bin/sippycup",
                            "torture",
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
    call_facts, call_actions, practice_passed = _call_facts(root)
    facts["calls"] = call_facts
    actions.extend(call_actions)
    if call_facts["count"] == 0 and run_facts["count"] == 0 and not practice_passed:
        actions.append(
            _action(
                "rehearse-on-practice-target",
                "Rehearse the whole sequence on the local practice target first",
                "A passing practice call proves the image, capture, registration, media, "
                "and evidence path before any packet reaches the owner's system.",
                instruction=(
                    f"Run ./bin/sippycup go {root} and follow stage 2, or see "
                    "docs/PRACTICE-TARGET.md (practice-target up, then a --practice call)."
                ),
            )
        )
    if facts["profile"]["ready"] and call_facts["count"] == 0:
        dial = _first_dial(root, now)
        if dial is not None:
            actions.append(
                _action(
                    "review-guided-call-dry-run",
                    "Review the guided baseline call plan",
                    "The dry run prints the plan, softphone parameters, and capture filter; "
                    "it sends no packets.",
                    argv=[
                        "./bin/sippycup",
                        "call",
                        str(selected_profile),
                        "--dial",
                        dial,
                        "--dry-run",
                    ],
                )
            )
        else:
            actions.append(
                _action(
                    "review-guided-call-dry-run",
                    "Record a destination for the guided baseline call",
                    "The guided call needs a destination; none is recorded in the scope.",
                    instruction=(
                        "Add the owner's destinations[] (user, expect) to scope.yaml and compile, "
                        "then run ./bin/sippycup call PROFILE --dial USER --dry-run."
                    ),
                )
            )
    campaign_manifest = root / "campaign.yaml"
    campaign_plan = root / "plan.json"
    if (
        facts["profile"]["ready"]
        and campaign_manifest.is_file()
        and not campaign_manifest.is_symlink()
        and not campaign_plan.exists()
    ):
        actions.append(
            _action(
                "plan-baseline-campaign",
                "Freeze the baseline campaign plan for review",
                "Planning compiles the manifest into an immutable plan without traffic.",
                argv=[
                    "./bin/sippycup",
                    "campaign",
                    "plan",
                    str(campaign_manifest),
                    "--output",
                    str(campaign_plan),
                ],
            )
        )
    if run_facts["privacyPass"] > 0:
        actions.append(
            _action(
                "package-evidence",
                "Package privacy-reviewed runs as evidence packs",
                "At least one run's evidence manifest reports privacy pass.",
                instruction=(
                    "After the disclosure decision, run ./bin/sippycup pack create RUN_DIR "
                    "OUTPUT.tar --image-digest sha256:IMAGE_ID (see docs/EVIDENCE-PACKS.md)."
                ),
            )
        )
    if run_facts["count"] == 0 and call_facts["count"] == 0 and facts["profile"]["ready"]:
        actions.append(
            _action(
                "prepare-baseline-record",
                "Prepare the first baseline run directory",
                "Start with one reviewed call before adversarial cases.",
                instruction=(
                    "Do not execute traffic automatically. Review the one-call "
                    f"plan with {owner} during the approved window."
                ),
            )
        )
    if run_facts["count"] > 0 or call_facts["count"] > 0:
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

    # Owner-facing engagement report: offered once any campaign or guided-call
    # run directory exists (docs/ENGAGEMENT-REPORT.md).
    calls_root = root / "calls"
    has_call_runs = (
        calls_root.is_dir()
        and not calls_root.is_symlink()
        and any(child.is_dir() for child in itertools.islice(calls_root.iterdir(), MAX_RUNS))
    )
    if run_facts["count"] > 0 or has_call_runs:
        actions.append(
            _action(
                "render-owner-report",
                "Render the owner report",
                "Assemble what was approved, run, observed, and found for the platform owner; fails closed on privacy lint.",
                argv=["./bin/sippycup", "summary", str(root)],
            )
        )

    if scope_facts.get("derivatives", {}).get("state") in {"stale", "invalid"}:
        # Do not steer the operator toward stale derived files.
        actions = [
            action
            for action in actions
            if action["id"] not in {
                "review-one-call-plan",
                "prepare-baseline-record",
                "review-guided-call-dry-run",
                "plan-baseline-campaign",
            }
        ]

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
