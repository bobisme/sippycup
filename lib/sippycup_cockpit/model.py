"""The cockpit dashboard model: a pure function of files on disk.

``build_model`` reads the engagement directory, the repository's work
directory, and probe results handed to it (image facts, the command
registry). It never contacts the network, never calls the container runtime,
and never writes. Stage completion is derived from files on disk only, so it
cannot drift from what actually exists.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import COCKPIT_VERSION
from .actions import build_actions
from .help_text import STAGES
from .runs import Unreadable, discover, read_json

WARN_SECONDS = 60 * 60
PRACTICE_DIR = "practice"
PRACTICE_RUN_ROOT = "practice-calls"
ADVISOR_STAGE = {
    "initialize-engagement": "prepare",
    "scope-init": "scope",
    "scope-questions": "scope",
    "scope-check": "scope",
    "scope-questions-open": "scope",
    "scope-compile": "scope",
    "create-target-profile": "rehearse",
    "complete-target-authorization": "rehearse",
    "rehearse-target-profile": "rehearse",
    "review-one-call-plan": "rehearse",
    "create-torture-defaults-review": "rehearse",
    "complete-torture-defaults-review": "rehearse",
    "rehearse-on-practice-target": "practice",
    "review-guided-call-dry-run": "first-call",
    "prepare-baseline-record": "first-call",
    "plan-baseline-campaign": "campaign",
    "repair-evidence-links": "evidence",
    "package-evidence": "evidence",
    "refresh-internal-report": "report",
}


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if value else None


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else None
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


def format_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    if days:
        return f"{days}d {hours:02d}h {minutes:02d}m"
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def authorization_window(
    status: str | None,
    valid_from: Any,
    valid_until: Any,
    now: datetime,
) -> dict[str, Any]:
    """Classify an approval window against ``now`` with a countdown.

    States: missing, pending, revoked, invalid, not-yet-valid, valid,
    expiring (under 60 minutes left), expired.
    """
    start = _parse_time(valid_from)
    end = _parse_time(valid_until)
    value: dict[str, Any] = {
        "status": status,
        "validFrom": _iso(start),
        "validUntil": _iso(end),
        "secondsRemaining": None,
        "secondsUntilOpen": None,
    }
    if status is None:
        value.update(state="missing", marker="[!!]", text="no authorization recorded")
        return value
    if status != "approved":
        value.update(state=status if status in {"pending", "revoked"} else "invalid", marker="[!!]",
                     text=f"authorization is {status}, not approved")
        return value
    if end is None:
        value.update(state="invalid", marker="[!!]", text="approved without valid_until")
        return value
    if start is not None and now < start:
        value["secondsUntilOpen"] = (start - now).total_seconds()
        value.update(state="not-yet-valid", marker="[!!]",
                     text=f"not yet valid: opens in {format_duration(value['secondsUntilOpen'])}"
                          f" ({value['validFrom']})")
        return value
    remaining = (end - now).total_seconds()
    value["secondsRemaining"] = max(0.0, remaining)
    if remaining <= 0:
        value.update(state="expired", marker="[!!]", text=f"EXPIRED at {value['validUntil']}")
    elif remaining < WARN_SECONDS:
        value.update(state="expiring", marker="[!!]",
                     text=f"expires in {format_duration(remaining)} (under 60 minutes) at {value['validUntil']}")
    else:
        value.update(state="valid", marker="[ok]",
                     text=f"valid, expires in {format_duration(remaining)} at {value['validUntil']}")
    return value


def _display(path: Path, repo: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except (OSError, ValueError):
        return str(path)


def _load_yaml(path: Path) -> Any:
    from sippycup_workbench.profile import ProfileError, load_profile

    try:
        return load_profile(path)
    except ProfileError as exc:
        raise Unreadable(str(exc)) from exc


def _profile_facts(path: Path, repo: Path, now: datetime) -> dict[str, Any]:
    from sippycup_workbench.profile import host_is_approved_literal, rehearse

    facts: dict[str, Any] = {
        "path": _display(path, repo),
        "present": path.is_file() and not path.is_symlink(),
        "ready": False,
        "errors": [],
        "approvalId": None,
        "document": None,
    }
    if not facts["present"]:
        return facts
    try:
        document = _load_yaml(path)
    except Unreadable as exc:
        facts["errors"] = [str(exc)]
        return facts
    rehearsal = rehearse(document, now=now, work_root=repo / "work")
    authorization = document.get("authorization") if isinstance(document.get("authorization"), dict) else {}
    approval = authorization.get("approval_id")
    facts.update(
        ready=rehearsal.ready and host_is_approved_literal(document),
        errors=list(rehearsal.errors),
        warnings=list(rehearsal.warnings),
        approvalId=approval if isinstance(approval, str) and approval else None,
        approvedBy=authorization.get("approved_by"),
        name=document.get("name"),
        literalHost=host_is_approved_literal(document),
        authorization=authorization_window(
            authorization.get("status") if isinstance(authorization.get("status"), str) else None,
            authorization.get("valid_from"),
            authorization.get("valid_until"),
            now,
        ),
        limits=document.get("limits") if isinstance(document.get("limits"), dict) else {},
        target=document.get("target") if isinstance(document.get("target"), dict) else {},
    )
    if not facts["literalHost"] and "target.host must be one of the literal approved_addresses" not in facts["errors"]:
        facts["errors"].append("target.host must itself be one of the literal approved_addresses")
    return facts


def _scope_facts(root: Path, repo: Path, now: datetime) -> dict[str, Any]:
    from sippycup_workbench.scope import SCOPE_FILE, inspect
    from sippycup_workbench.scope_derive import derivative_state
    from sippycup_workbench.scope_questions import QUESTIONS, question_state

    path = root / SCOPE_FILE
    facts: dict[str, Any] = {
        "path": _display(path, repo),
        "present": path.is_file() and not path.is_symlink(),
        "state": "missing",
        "unanswered": [],
        "errors": [],
        "derivatives": "not-compiled",
        "staleItems": [],
        "document": None,
    }
    if not facts["present"]:
        return facts
    report = inspect(path, now=now)
    facts["errors"] = [f"{item.code} [{item.field or '-'}]" for item in report.errors][:40]
    if report.document is None:
        facts["state"] = "invalid"
        return facts
    facts["document"] = report.document
    for number, question in enumerate(QUESTIONS, 1):
        if question_state(report, question) == "unanswered":
            facts["unanswered"].append({"number": number, "id": question.identifier,
                                        "section": question.section, "text": question.text})
    try:
        derivatives = derivative_state(root, path)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        derivatives = {"state": "invalid", "problem": str(exc), "items": {}}
    facts["derivatives"] = derivatives.get("state", "invalid")
    facts["staleItems"] = sorted(
        f"{name} ({item.get('state')})"
        for name, item in (derivatives.get("items") or {}).items()
        if item.get("state") != "current"
    )
    if not report.complete:
        facts["state"] = "incomplete"
    elif not report.ok:
        facts["state"] = "inconsistent"
    elif facts["derivatives"] in {"stale", "invalid"}:
        facts["state"] = "stale"
    elif facts["derivatives"] == "not-compiled":
        facts["state"] = "complete-not-compiled"
    else:
        facts["state"] = "complete"
    return facts


def _target_summary(profile: dict[str, Any], scope: dict[str, Any]) -> dict[str, Any]:
    target = profile.get("target") or {}
    document = scope.get("document") or {}
    account = document.get("account") if isinstance(document.get("account"), dict) else {}
    destinations = []
    for item in document.get("destinations") or []:
        if isinstance(item, dict) and isinstance(item.get("user"), (str, int)):
            destinations.append({
                "name": str(item.get("name") or item.get("user")),
                "user": str(item["user"]),
                "expect": str(item.get("expect") or "unknown"),
                "target": item.get("target"),
            })
    if not target and isinstance(document.get("targets"), list) and document["targets"]:
        first = document["targets"][0] if isinstance(document["targets"][0], dict) else {}
        target = {"host": first.get("address"), "port": first.get("port"), "transport": first.get("transport"),
                  "tls_server_name": first.get("tls_server_name")}
    required = account.get("required") if isinstance(account.get("required"), bool) else None
    return {
        "host": target.get("host"),
        "port": target.get("port"),
        "transport": target.get("transport"),
        "tlsServerName": target.get("tls_server_name"),
        "approvedAddresses": list(target.get("approved_addresses") or []),
        "literal": bool(profile.get("literalHost")) if profile.get("present") else None,
        "source": profile["path"] if profile.get("present") else (scope.get("path") if target else None),
        "account": {
            "required": required,
            "username": account.get("username") if isinstance(account.get("username"), str) else None,
            "credentialRef": account.get("credential_ref") if isinstance(account.get("credential_ref"), str) else None,
            "present": bool(required and account.get("username")),
        },
        "destinations": destinations,
        "dial": next((item["user"] for item in destinations if item["expect"] != "reject"), None),
    }


def _practice_facts(repo: Path, now: datetime) -> dict[str, Any]:
    from sippycup_workbench.doctor import _practice_target

    work = repo / "work"
    record = _practice_target(work)
    state = work / PRACTICE_DIR
    facts: dict[str, Any] = {
        "installed": record["installed"],
        "image": record["image"],
        "up": record["up"],
        "source": "work/practice records (no runtime call; live check: practice-target status)",
        "address": None,
        "profile": "work/practice/target-profile.yaml",
        "profilePresent": (state / "target-profile.yaml").is_file(),
        "passwordFile": "work/practice/account.password",
        "passwordPresent": (state / "account.password").is_file(),
        "authorization": None,
        "approvalId": None,
    }
    if record["up"]:
        try:
            connection = read_json(state / "connection.json")
            facts["address"] = connection.get("address")
            facts["authorization"] = authorization_window(
                "approved", connection.get("started_utc"), connection.get("profile_valid_until_utc"), now
            )
            facts["approvalId"] = str(connection.get("authorization", "")).split(":", 1)[0] or None
        except (Unreadable, AttributeError) as exc:
            facts["error"] = str(exc)
    return facts


def _journal_facts(root: Path) -> dict[str, Any]:
    from sippycup_workbench.journal import JournalError, verify

    facts: dict[str, Any] = {"valid": False, "entries": 0, "last": None, "error": None, "evidence": []}
    if not (root / "engagement.json").is_file():
        facts["error"] = "no engagement.json (journal not initialized)"
        return facts
    try:
        result = verify(root)
    except JournalError as exc:
        facts["error"] = str(exc)
        return facts
    facts["valid"] = True
    facts["entries"] = len(result.entries)
    facts["missingEvidence"] = list(result.missing_evidence)[:20]
    references: set[str] = set()
    for entry in result.entries:
        for reference in entry.get("evidence") or []:
            references.add(str(reference))
    facts["evidence"] = sorted(references)
    if result.entries:
        last = result.entries[-1]
        facts["last"] = {
            "sequence": last.get("sequence"),
            "recordedAt": last.get("recordedAt"),
            "kind": last.get("kind"),
            "summary": str(last.get("summary", ""))[:160],
        }
    return facts


def _engagement_facts(root: Path, repo: Path) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "name": root.name,
        "path": str(root),
        "display": _display(root, repo),
        "exists": root.is_dir(),
        "initialized": (root / "engagement.json").is_file(),
        "title": None,
        "owner": None,
        "insideWork": _display(root, repo).startswith("work/"),
    }
    if facts["initialized"]:
        try:
            metadata = read_json(root / "engagement.json")
            facts["title"] = metadata.get("title")
            facts["owner"] = metadata.get("owner")
        except (Unreadable, AttributeError) as exc:
            facts["error"] = str(exc)
    return facts


def _step(label: str, done: bool | None) -> dict[str, Any]:
    return {"label": label, "done": done}


def derive_stages(model: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the guided stages with completion derived from the model."""
    engagement = model["engagement"]
    image = model["readiness"]["image"]
    practice = model["readiness"]["practice"]
    scope = model["scope"]
    profile = model["profile"]
    runs = model["runs"]
    journal = model["journal"]
    files = model["files"]
    image_ok = None if image.get("present") is None else bool(image.get("present") and not image.get("stale"))
    practice_pass = any(run["kind"] == "practice-call" and run["passed"] for run in runs)
    live_runs = [run for run in runs if run["kind"] not in {"practice-call"}]
    call_pass = any(run["kind"] == "call" and run["passed"] for run in runs)
    call_any = any(run["kind"] == "call" for run in runs)
    campaign_pass = any(run["kind"] == "campaign" and run["passed"] for run in runs)
    scope_ok = scope["state"] == "complete" or (not scope["present"] and profile["present"] and profile["ready"])
    manifests = bool(live_runs) and all(run["evidenceManifest"] for run in live_runs)
    journal_linked = bool(live_runs) and all(
        any(reference.startswith(run["relative"] + "/") for reference in journal.get("evidence", []))
        for run in live_runs
    )
    steps = {
        "prepare": [
            _step("engagement record (journal init)", engagement["initialized"]),
            _step("toolbox image present", image.get("present")),
            _step("image built after the last code change", None if image.get("stale") is None else not image["stale"]),
        ],
        "practice": [
            _step("practice image built", bool(practice["installed"] or practice["up"])),
            _step("practice target up (from work/practice records)", practice["up"]),
            _step("passing practice call recorded in this engagement", practice_pass),
        ],
        "scope": [
            _step("scope.yaml created (scope init)", scope["present"]),
            _step(f"owner questions answered ({len(scope['unanswered'])} open)" if scope["present"]
                  else "owner questions answered (no scope file yet)",
                  scope["present"] and not scope["unanswered"] and scope["state"] != "invalid"),
            _step("scope check clean", scope["state"] in {"complete", "complete-not-compiled", "stale"}),
            _step("derivatives compiled and current (scope compile)", scope["derivatives"] in {"current", "partial"}),
        ],
        "rehearse": [
            _step("target profile present", profile["present"]),
            _step("rehearse ready (approved, in window, literal address)", profile["ready"]),
        ],
        "first-call": [
            _step("guided call run recorded", call_any),
            _step("guided call verdict PASS", call_pass),
        ],
        "campaign": [
            _step("campaign manifest present", files["campaign"]),
            _step("frozen plan present (campaign plan)", files["plan"]),
            _step("campaign run succeeded", campaign_pass),
        ],
        "evidence": [
            _step("every run has an evidence manifest", manifests),
            _step("journal links every run", journal_linked),
            _step("evidence pack created (optional)", files["packs"]),
        ],
        "report": [
            _step("internal report draft rendered", files["internalReport"]),
        ],
    }
    done = {
        "prepare": bool(engagement["initialized"]) and image_ok is not False,
        "practice": practice_pass,
        "scope": scope_ok,
        "rehearse": bool(profile["ready"]),
        "first-call": call_pass,
        "campaign": campaign_pass,
        "evidence": manifests and journal_linked,
        "report": files["internalReport"],
    }
    # Practice stays the current stage until it passes, a live run exists, or
    # the operator chose to skip it (a UI preference, not a completion record).
    started_after_practice = bool(live_runs) or bool((model.get("preferences") or {}).get("skipPractice"))
    stages: list[dict[str, Any]] = []
    current_found = False
    for text in STAGES:
        identifier = text.identifier
        if done[identifier]:
            state = "done"
        elif identifier == "practice" and started_after_practice:
            state = "recommended"
        elif not current_found:
            state = "current"
            current_found = True
        else:
            state = "todo"
        stages.append({
            "id": identifier,
            "number": text.number,
            "title": text.title,
            "state": state,
            "steps": steps[identifier],
        })
    if not current_found:
        for stage in stages:
            if stage["state"] == "recommended":
                stage["state"] = "current"
                break
    return stages


def _files(root: Path, repo: Path) -> dict[str, Any]:
    def exists(name: str) -> bool:
        path = root / name
        return path.is_file() and not path.is_symlink()

    packs = root / "packs"
    has_packs = False
    if packs.is_dir() and not packs.is_symlink():
        try:
            has_packs = any(item.is_file() for item in packs.iterdir())
        except OSError:
            has_packs = False
    internal = False
    try:
        internal = any(item.name.startswith("internal-report") and item.suffix == ".md" for item in root.iterdir())
    except OSError:
        pass
    return {
        "profile": exists("target-profile.yaml"),
        "campaign": exists("campaign.yaml"),
        "plan": exists("plan.json"),
        "expectations": exists("expectations.yaml"),
        "packs": has_packs,
        "internalReport": internal,
        "planFacts": _plan_facts(root / "plan.json") if exists("plan.json") else None,
    }


def _plan_facts(path: Path) -> dict[str, Any] | None:
    try:
        plan = read_json(path)
    except Unreadable as exc:
        return {"error": str(exc)}
    if not isinstance(plan, dict):
        return {"error": "plan.json is not an object"}
    authorization = plan.get("authorization") if isinstance(plan.get("authorization"), dict) else {}
    return {
        "name": (plan.get("metadata") or {}).get("name") if isinstance(plan.get("metadata"), dict) else None,
        "steps": len(plan.get("steps") or []) if isinstance(plan.get("steps"), list) else None,
        "plannedTotals": plan.get("plannedTotals"),
        "hardMaxima": authorization.get("hardMaxima"),
        "credentialRefs": authorization.get("credentialRefs") or [],
        "destinations": [
            f"{item.get('address')}:{item.get('port')}/{item.get('transport')}"
            for item in plan.get("resolvedDestinations") or []
            if isinstance(item, dict)
        ],
    }


PREFERENCES_FILE = ".cockpit.json"


def load_preferences(root: Path) -> dict[str, Any]:
    """UI preferences only (for example skipping the practice stage)."""
    try:
        value = read_json(root / PREFERENCES_FILE, limit=16 * 1024)
    except Unreadable:
        return {}
    if not isinstance(value, dict):
        return {}
    return {"skipPractice": value.get("skipPractice") is True}


def save_preferences(root: Path, preferences: dict[str, Any]) -> None:
    path = root / PREFERENCES_FILE
    temporary = root / (PREFERENCES_FILE + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump({"skipPractice": bool(preferences.get("skipPractice"))}, output, sort_keys=True)
        output.write("\n")
    os.replace(temporary, path)


def build_model(
    engagement: str | Path | None,
    *,
    repo: str | Path,
    now: datetime | None = None,
    image: dict[str, Any] | None = None,
    commands: set[str] | frozenset[str] | None = None,
    advisor: bool = True,
) -> dict[str, Any]:
    """Build the JSON-serializable dashboard model."""
    repo_path = Path(repo)
    instant = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    root = Path(engagement) if engagement is not None else repo_path / "work" / "ENGAGEMENT"
    if not root.is_absolute():
        root = repo_path / root
    engagement_facts = _engagement_facts(root, repo_path)
    profile_path = root / "target-profile.yaml"
    profile = _profile_facts(profile_path, repo_path, instant)
    scope = _scope_facts(root, repo_path, instant) if engagement_facts["exists"] else {
        "path": _display(root / "scope.yaml", repo_path), "present": False, "state": "missing",
        "unanswered": [], "errors": [], "derivatives": "not-compiled", "staleItems": [], "document": None,
    }
    authorization = profile.get("authorization") or authorization_window(None, None, None, instant)
    authorization = dict(authorization)
    authorization["approvalId"] = profile.get("approvalId")
    authorization["source"] = profile["path"] if profile["present"] else None
    if not profile["present"] and scope.get("document"):
        section = scope["document"].get("authorization") or {}
        if isinstance(section, dict):
            authorization = authorization_window(section.get("status"), section.get("valid_from"),
                                                 section.get("valid_until"), instant)
            authorization["approvalId"] = section.get("approval_id") if isinstance(section.get("approval_id"), str) else None
            authorization["source"] = f"{scope['path']} (not compiled into a profile yet)"
    model: dict[str, Any] = {
        "apiVersion": COCKPIT_VERSION,
        "networkActivity": False,
        "generatedAt": _iso(instant),
        "repo": str(repo_path),
        "engagement": engagement_facts,
        "scope": {key: value for key, value in scope.items() if key != "document"},
        "profile": {key: value for key, value in profile.items() if key not in {"document", "target", "authorization"}},
        "authorization": authorization,
        "target": _target_summary(profile, scope),
        "readiness": {
            "image": image or {"checked": False, "present": None, "stale": None,
                               "detail": "image not checked (no runtime query was made)"},
            "practice": _practice_facts(repo_path, instant),
            "doctor": {"command": "./bin/sippycup doctor", "note": "inspects the image; network-free"},
        },
        "journal": _journal_facts(root) if engagement_facts["exists"] else {
            "valid": False, "entries": 0, "last": None, "error": "engagement directory does not exist",
            "evidence": []},
        "runs": discover(root) if engagement_facts["exists"] else [],
        "files": _files(root, repo_path) if engagement_facts["exists"] else {
            "profile": False, "campaign": False, "plan": False, "expectations": False, "packs": False,
            "internalReport": False, "planFacts": None},
        "commands": sorted(commands) if commands is not None else None,
        "preferences": load_preferences(root),
    }
    advice: dict[str, Any] = {"overall": None, "blockers": [], "warnings": [], "nextActions": []}
    if advisor:
        from sippycup_workbench.advisor import assess

        try:
            advice = assess(root, now=instant)
        except Exception as exc:  # the cockpit must still render
            advice = {"overall": "unavailable", "blockers": [f"advisor failed: {exc}"], "warnings": [],
                      "nextActions": []}
    model["advisor"] = {key: advice.get(key) for key in ("overall", "blockers", "warnings")}
    model["stages"] = derive_stages(model)
    model["currentStage"] = next((stage["id"] for stage in model["stages"] if stage["state"] == "current"), None)
    model["actions"] = build_actions(model, advice.get("nextActions") or [], commands, ADVISOR_STAGE)
    runnable = [action for action in model["actions"] if action["available"] and action.get("argv")]
    primary = next((action for action in runnable if action["progress"]), runnable[0] if runnable else None)
    if model["currentStage"] is None:
        primary = None  # every stage is complete; nothing is the single next step
    model["complete"] = model["currentStage"] is None
    model["nextCommand"] = primary["command"] if primary else None
    model["nextActionId"] = primary["id"] if primary else None
    return model


def to_json(model: dict[str, Any]) -> str:
    return json.dumps(model, indent=2, sort_keys=True, default=str)
