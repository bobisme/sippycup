"""The cockpit's action table and confirmation logic.

Add a command to the cockpit with one ``ActionSpec`` row in ``TABLE``. A row
names its stage, how it touches the network, the argv it would run (built
from the dashboard model), an optional network-free preview argv (the
command's own ``--dry-run`` or plan output), and whether it needs the account
password. ``requires`` names a row in ``config/commands.tsv``; the action is
hidden while that command does not exist, so rows for commands that other
work adds later are harmless today.

The cockpit never bypasses or reimplements a gate. Every action is a
``./bin/sippycup ...`` subprocess, so every refusal of the real command still
applies. The checks here only stop an action earlier, with a clearer reason.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

LAUNCHER = "./bin/sippycup"
NETWORK_LABEL = {"none": "[offline]", "local": "[local]", "live": "[LIVE]"}
COCKPIT_SECRET_ENV = "SIPPYCUP_COCKPIT_SECRET"
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_DIAL = re.compile(r"^[A-Za-z0-9+*._-]{1,64}$")
PREVIEW_LIMIT = 64 * 1024

Build = Callable[[dict[str, Any]], "list[str] | str | None"]


@dataclass(frozen=True)
class ActionSpec:
    """One cockpit action. ``build`` returns argv, an unavailable reason, or None (hidden)."""

    identifier: str
    stage: str
    title: str
    why: str
    network: str
    build: Build
    requires: str | None = None
    preview: Build | None = None
    secret: str | None = None
    approval: str = "engagement"
    instruction: Callable[[dict[str, Any]], str | None] | None = None
    progress: bool = True  # False for pure checks that never advance a stage


def _eng(model: dict[str, Any]) -> str:
    return model["engagement"]["display"]


def _profile(model: dict[str, Any]) -> str:
    return f"{_eng(model)}/target-profile.yaml"


def _account_args(model: dict[str, Any]) -> list[str]:
    account = model["target"]["account"]
    if account.get("required") and account.get("username"):
        return ["--username", account["username"]]
    return []


def practice_route(model: dict[str, Any]) -> bool:
    """True when the engagement's own target is the running practice target.

    Such a target exists only inside the practice namespace, so the command
    must join it with ``--practice`` (which itself fails closed unless the
    loopback-only practice container is up).
    """
    practice = model["readiness"]["practice"]
    host = model["target"].get("host")
    # The practice proxy is a second address in the same namespace (bn-2g0).
    addresses = practice.get("addresses") or ([practice["address"]] if practice.get("address") else [])
    return bool(practice.get("up") and host and host in addresses)


def _route(model: dict[str, Any]) -> list[str]:
    return [LAUNCHER, "--practice"] if practice_route(model) else [LAUNCHER]


def _practice_call(model: dict[str, Any], *, dry_run: bool, json_output: bool = False) -> list[str] | str | None:
    practice = model["readiness"]["practice"]
    if not model["engagement"]["initialized"]:
        return None
    if not practice["up"]:
        return "the practice target is not up (start it with practice-target up)"
    if not practice["profilePresent"]:
        return "work/practice/target-profile.yaml is missing; run practice-target up again"
    argv = [
        LAUNCHER, "--practice", "call", practice["profile"], "--dial", "echo",
        "--username", "practice", "--secret-file", practice["passwordFile"],
        "--run-root", f"{_eng(model)}/practice-calls", "--engagement", _eng(model),
    ]
    if dry_run:
        argv.append("--dry-run")
        if json_output:
            argv.extend(["--format", "json"])
    return argv


def _guided_call(model: dict[str, Any], *, dry_run: bool, json_output: bool = False) -> list[str] | str | None:
    if not model["profile"]["present"]:
        return None
    dial = model["target"].get("dial")
    if not dial:
        return ("no approved destination to dial on this target: add it to destinations[] (user, expect, target) "
                "in scope.yaml from the owner's written answer, then run scope compile")
    if not _DIAL.fullmatch(str(dial)):
        return f"destination user {dial!r} has characters the cockpit will not pass on"
    if model["scope"]["state"] == "stale":
        return "scope derivatives are stale; run scope compile first"
    argv = [*_route(model), "call", _profile(model), "--dial", str(dial), *_account_args(model)]
    if dry_run:
        argv.append("--dry-run")
        if json_output:
            argv.extend(["--format", "json"])
    return argv


def _campaign_run(model: dict[str, Any]) -> list[str] | str | None:
    files = model["files"]
    if not files["campaign"]:
        return None
    if not files["plan"]:
        return "no frozen plan yet: run campaign plan first"
    eng = _eng(model)
    practice = practice_route(model)
    return [
        LAUNCHER, "--practice" if practice else "--isolated", "campaign", "run", f"{eng}/plan.json",
        "--manifest", f"{eng}/campaign.yaml", "--run-root", f"{eng}/runs", "--interface", "lo" if practice else "any",
    ]


def _checks_run(model: dict[str, Any], *, dry_run: bool) -> list[str] | str | None:
    if not model["profile"]["present"]:
        return None
    if not model["profile"].get("securityChecks"):
        return "the profile approves no checks: add security_checks to scope.yaml (with the owner's approval) and compile"
    # Same route as the guided call: the practice address is reachable only
    # through --practice. The password (needed by nonce-replay) is added from
    # the confirmation prompt, like the call's.
    argv = [*_route(model), "checks", "run", _profile(model)]
    if dry_run:
        argv.append("--dry-run")
    return argv


def _summary(model: dict[str, Any]) -> list[str] | None:
    if not model["engagement"]["initialized"]:
        return None
    return [LAUNCHER, "summary", _eng(model), "--journal"]


def _next_report(model: dict[str, Any]) -> list[str] | None:
    if not model["journal"]["valid"] or model["journal"]["entries"] == 0:
        return None
    root = Path(model["engagement"]["path"])
    number = 1
    while (root / f"internal-report-{number:02d}.md").exists() and number < 99:
        number += 1
    eng = _eng(model)
    return [LAUNCHER, "journal", "render", eng, "--audience", "internal", "--output",
            f"{eng}/internal-report-{number:02d}.md"]


def _image_instruction(model: dict[str, Any]) -> str | None:
    image = model["readiness"]["image"]
    if image.get("present") is False:
        return f"Build the toolbox image: make build IMAGE={image.get('image', 'localhost/sippycup:latest')}"
    if image.get("stale"):
        return (f"Rebuild the toolbox image; it predates the last code change: "
                f"make build IMAGE={image.get('image', 'localhost/sippycup:latest')}")
    return None


TABLE: tuple[ActionSpec, ...] = (
    ActionSpec(
        "journal-init", "prepare", "Create the private engagement record",
        "Every assessment needs the private hash-chained journal before anything else.",
        "none",
        lambda m: [LAUNCHER, "journal", "init", _eng(m)] if not m["engagement"]["initialized"] else None,
    ),
    ActionSpec(
        "build-image", "prepare", "Build the toolbox image",
        "Live commands run inside the image; it must exist and match the reviewed code.",
        "local",
        lambda m: "run it from a shell; the cockpit only starts ./bin/sippycup commands"
        if _image_instruction(m) else None,
        instruction=_image_instruction,
    ),
    ActionSpec(
        "doctor", "prepare", "Inspect the toolbox image (doctor)",
        "Checks tools and capture capability inside the image without network activity.",
        "none", lambda m: [LAUNCHER, "doctor"], progress=False,
    ),
    ActionSpec(
        "practice-build", "practice", "Build the practice target image",
        "A one-off local build of the pinned Asterisk practice server.",
        "local",
        lambda m: [LAUNCHER, "practice-target", "build"]
        if not (m["readiness"]["practice"]["installed"] or m["readiness"]["practice"]["up"]) else None,
        requires="practice-target",
    ),
    ActionSpec(
        "practice-up", "practice", "Start the practice target",
        "Starts the loopback-only Asterisk with a fresh account, CA, and four-hour practice profile.",
        "local",
        lambda m: [LAUNCHER, "practice-target", "up"]
        if not m["readiness"]["practice"]["up"]
        or (m["readiness"]["practice"].get("authorization") or {}).get("state") == "expired"
        else None,
        requires="practice-target",
    ),
    ActionSpec(
        "practice-status", "practice", "Check the practice target live (practice-target status)",
        "Asks the container runtime whether the target really runs; the dashboard reads only files.",
        "none", lambda m: [LAUNCHER, "practice-target", "status"], requires="practice-target", progress=False,
    ),
    ActionSpec(
        "practice-call-dry-run", "practice", "Review the practice call plan (dry run)",
        "Prints the exact plan and softphone parameters; sends nothing.",
        "none", lambda m: _practice_call(m, dry_run=True), requires="call",
    ),
    ActionSpec(
        "practice-call", "practice", "Place the guided practice call to echo",
        "Rehearses the real live sequence against 127.0.0.2 inside the practice namespace only.",
        "live", lambda m: _practice_call(m, dry_run=False), requires="call",
        preview=lambda m: _practice_call(m, dry_run=True, json_output=True), secret="practice", approval="practice",
    ),
    ActionSpec(
        "scope-edit", "scope", "Fill scope.yaml from the owner's written answers",
        "Only the owner's written reply may go into the scope file; then run scope check.",
        "none", lambda m: "edit the file in your editor, then run scope check"
        if m["scope"]["state"] in {"incomplete", "inconsistent", "invalid"} else None,
        instruction=lambda m: f"Edit {m['scope']['path']} (mode 0600); never put a password in it.",
    ),
    ActionSpec(
        "scope-check", "scope", "Check the scope intake file",
        "Lists exactly which answers are missing, malformed, or inconsistent.",
        "none", lambda m: [LAUNCHER, "scope", "check", _eng(m)] if m["scope"]["present"] else None,
        requires="scope", progress=False,
    ),
    ActionSpec(
        "ready", "rehearse", "Go/no-go check before the first live packet (ready)",
        "Checks window, clock, image, capture, disk, credentials, TLS, and network position; sends nothing to "
        "the target (one loopback-only capture in a local container).",
        "local",
        lambda m: [LAUNCHER, "ready", _eng(m)] if m["profile"]["present"] and m["profile"]["ready"] else None,
        requires="ready",
    ),
    ActionSpec(
        "rehearse", "rehearse", "Rehearse the target profile",
        "Parses scope and expiration without network traffic.",
        "none", lambda m: [LAUNCHER, "rehearse", _profile(m)] if m["profile"]["present"] else None,
    ),
    ActionSpec(
        "one-call-plan", "rehearse", "Review the compiled one-call plan",
        "Shows the capture, preflight, and analysis commands; sends no packets.",
        "none", lambda m: [LAUNCHER, "one-call", _profile(m)] if m["profile"]["present"] else None,
    ),
    ActionSpec(
        "call-dry-run", "first-call", "Review the guided call (dry run)",
        "Prints the plan, softphone parameters, and capture filter; sends nothing.",
        "none", lambda m: _guided_call(m, dry_run=True), requires="call",
    ),
    ActionSpec(
        "call", "first-call", "Place the guided baseline call",
        "One OPTIONS preflight and one call with scoped capture and offline evidence.",
        "live", lambda m: _guided_call(m, dry_run=False), requires="call",
        preview=lambda m: _guided_call(m, dry_run=True, json_output=True), secret="call",
    ),
    ActionSpec(
        "campaign-plan", "campaign", "Freeze the reviewed campaign plan",
        "Compiles the manifest into an immutable plan without traffic.",
        "none",
        lambda m: [LAUNCHER, "campaign", "plan", f"{_eng(m)}/campaign.yaml", "--output", f"{_eng(m)}/plan.json"]
        if m["files"]["campaign"] and not m["files"]["plan"] else None,
        requires="campaign",
    ),
    ActionSpec(
        "campaign-run", "campaign", "Run the frozen campaign plan",
        "Executes exactly the reviewed plan under the ceiling and stop-condition supervisor.",
        "live", _campaign_run, requires="campaign", secret="campaign",
    ),
    ActionSpec(
        "checks-plan", "checks", "Plan the security posture checks",
        "Shows which checks would run and what each sends; sends nothing.",
        "none", lambda m: [LAUNCHER, "checks", "plan", _profile(m)] if m["profile"]["present"] else None,
        requires="checks",
    ),
    ActionSpec(
        "checks-run", "checks", "Run the security posture checks",
        "Sends the bounded checks to the approved target and writes findings.json.",
        "live", lambda m: _checks_run(m, dry_run=False), requires="checks",
        preview=lambda m: _checks_run(m, dry_run=True), secret="call",
    ),
    ActionSpec(
        "render-internal-report", "report", "Render a new internal report draft (optional)",
        "Synthesizes the verified journal; confidential, never overwrites an earlier draft.",
        "none", _next_report, progress=False,
    ),
    ActionSpec(
        "summary", "report", "Write the owner report (summary)",
        "Re-checks every run against the approval, writes the owner report, and records its hash in the journal; "
        "network-free. Add --forbid-file with the password file to prove the password is absent.",
        "none", _summary, requires="summary",
    ),
)
TABLE_BY_ID = {spec.identifier: spec for spec in TABLE}
# Advisor actions the table already offers in a cockpit-specific form.
ADVISOR_COVERED = {
    "refresh-internal-report",  # the table renders the next free numbered draft
    "review-guided-call-dry-run",  # call-dry-run adds the account username
    "rehearse-on-practice-target",  # stage 2 is the practice rehearsal itself
    # A hand-made pending profile from `init` blocks the first `scope compile`
    # (scope.derivative_unmanaged, needs --force); stage 3 compiles the profile.
    "create-target-profile",
}


def command_line(argv: list[str]) -> str:
    return shlex.join(argv)


def _action_dict(
    identifier: str,
    stage: str,
    title: str,
    reason: str,
    *,
    network: str,
    argv: list[str] | None,
    unavailable: str | None,
    source: str,
    spec: ActionSpec | None = None,
    instruction: str | None = None,
) -> dict[str, Any]:
    runnable = bool(argv) and argv[0] == LAUNCHER
    value: dict[str, Any] = {
        "id": identifier,
        "stage": stage,
        "title": title,
        "reason": reason,
        "network": network,
        "label": NETWORK_LABEL[network],
        "networkActivity": network == "live",
        "argv": argv,
        "command": command_line(argv) if argv else None,
        "available": unavailable is None and runnable,
        "unavailableReason": unavailable if unavailable is not None else (
            None if runnable or not argv else "only ./bin/sippycup commands can be started from the cockpit"),
        "instruction": instruction,
        "source": source,
        "secret": spec.secret if spec else None,
        "approval": spec.approval if spec else None,
        "hasPreview": bool(spec and spec.preview),
        "progress": spec.progress if spec else True,
    }
    if argv is None and unavailable is None and instruction:
        value["available"] = False
        value["unavailableReason"] = "manual step"
    return value


def _runs_actions(model: dict[str, Any]) -> list[dict[str, Any]]:
    actions = []
    linked = model["journal"].get("evidence", [])
    for run in model["runs"]:
        if not run["readable"]:
            continue
        if not run["evidenceManifest"]:
            actions.append(_action_dict(
                f"manifest-{run['name']}", "evidence", f"Inventory evidence for run {run['relative']}",
                "The run has no evidence manifest.", network="none",
                argv=[LAUNCHER, "evidence", "manifest", f"{_eng(model)}/{run['relative']}", "--write"],
                unavailable=None, source="cockpit"))
        if run["kind"] == "practice-call":
            continue
        if model["journal"]["valid"] and not any(ref.startswith(run["relative"] + "/") for ref in linked):
            journal = run.get("journalCommand")
            if not journal and run["kind"] in {"campaign", "checks"}:
                root = Path(model["engagement"]["path"]) / run["relative"]
                journal = [LAUNCHER, "journal", "add", _eng(model), "--kind", "action", "--summary",
                           f"{'Campaign' if run['kind'] == 'campaign' else 'Security checks'} run "
                           f"{run['name']}: {run.get('verdict')}"]
                for name in ("result.json", "findings.json", "events.jsonl", "evidence-manifest.json"):
                    if (root / name).is_file():
                        journal.extend(["--evidence", f"{run['relative']}/{name}"])
            if journal:
                actions.append(_action_dict(
                    f"journal-{run['name']}", "evidence", f"Record run {run['relative']} in the journal",
                    "The command the run printed; links result, manifest, and capture.", network="none",
                    argv=journal, unavailable=None, source="cockpit"))
    return actions


def _profile_actions(model: dict[str, Any]) -> list[dict[str, Any]]:
    """Network-free actions for each further target's compiled profile.

    The table's actions use the first target's profile (target-profile.yaml).
    A scope with more targets compiles one profile per target; for each the
    cockpit offers its rehearse and its dry run, with that target's own
    approved destination. The live call on such a profile is the printed dry
    run command without --dry-run, run from a shell: the cockpit's typed
    confirmation is wired to the first profile only.
    """
    actions: list[dict[str, Any]] = []
    eng = _eng(model)
    for item in model.get("profiles") or []:
        if item.get("first") or not item.get("present"):
            continue
        name = item.get("target") or "other"
        path = item["path"] if str(item["path"]).startswith(eng) else f"{eng}/{Path(str(item['path'])).name}"
        label = f"target {name} ({item.get('transport')} port {item.get('port')})"
        actions.append(_action_dict(
            f"rehearse-{name}", "rehearse", f"Rehearse the profile of {label}",
            "Parses that target's scope and expiration without network traffic.", network="none",
            argv=[LAUNCHER, "rehearse", path], unavailable=None, source="cockpit"))
        dial = item.get("dial")
        unavailable = None
        argv: list[str] | None = None
        if model["scope"]["state"] == "stale":
            unavailable = "scope derivatives are stale; run scope compile first"
        elif not dial:
            unavailable = (f"no approved destination to dial on target {name}: add it to destinations[] "
                           "(user, expect, target) in scope.yaml, then run scope compile")
        elif not _DIAL.fullmatch(str(dial)):
            unavailable = f"destination user {dial!r} has characters the cockpit will not pass on"
        else:
            argv = [*_route(model), "call", path, "--dial", str(dial), *_account_args(model), "--dry-run"]
        actions.append(_action_dict(
            f"call-dry-run-{name}", "first-call", f"Review the guided call on {label} (dry run)",
            "Prints the plan for that target's profile; sends nothing. To place the call, run the same "
            "command from a shell without --dry-run (add the password source).",
            network="none", argv=argv, unavailable=unavailable, source="cockpit"))
    for action in actions:
        action["progress"] = False  # never the single "next" step; the first profile leads
    return actions


def build_actions(
    model: dict[str, Any],
    advisor_actions: list[dict[str, Any]],
    commands: set[str] | frozenset[str] | None,
    advisor_stage: Mapping[str, str],
) -> list[dict[str, Any]]:
    """Merge the table and the advisor's network-free actions, current stage first."""
    order = [stage["id"] for stage in model["stages"]]
    current = model.get("currentStage") or next(
        (stage["id"] for stage in model["stages"] if stage["state"] == "current"), order[0])
    collected: list[dict[str, Any]] = []
    for spec in TABLE:
        if spec.requires and commands is not None and spec.requires not in commands:
            continue
        built = spec.build(model)
        if built is None:
            continue
        argv = built if isinstance(built, list) else None
        unavailable = built if isinstance(built, str) else None
        if unavailable and spec.instruction:
            unavailable = "manual step"
        collected.append(_action_dict(
            spec.identifier, spec.stage, spec.title, spec.why, network=spec.network, argv=argv,
            unavailable=unavailable, source="cockpit", spec=spec,
            instruction=spec.instruction(model) if spec.instruction else None))
    collected.extend(_profile_actions(model))
    collected.extend(_runs_actions(model))
    root = model["engagement"]["path"]
    display = model["engagement"]["display"]
    for item in advisor_actions:
        identifier = str(item.get("id"))
        if identifier in ADVISOR_COVERED:
            continue
        stage = advisor_stage.get(identifier) or (
            "evidence" if identifier.startswith(("manifest-", "privacy-", "calls-manifest-")) else
            "rehearse" if identifier.startswith("rehearse-target-profile-") else current)
        argv = item.get("argv") if isinstance(item.get("argv"), list) else None
        if argv is not None:
            argv = [display + value[len(root):] if value.startswith(root) else value for value in argv]
        collected.append(_action_dict(
            identifier, stage, str(item.get("title", identifier)), str(item.get("reason", "")),
            network="live" if item.get("networkActivity") else "none", argv=argv, unavailable=None,
            source="advisor", instruction=item.get("instruction")))
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for action in collected:
        key = action["command"] or f"id:{action['id']}"
        if key in seen:
            continue
        if not action["available"] and action["stage"] not in {current, "practice"}:
            continue  # a later stage's blocked action is noise; the stage list shows why
        seen.add(key)
        unique.append(action)
    rank = {stage: index for index, stage in enumerate(order)}
    unique.sort(key=lambda action: (
        0 if action["stage"] == current else 1,
        0 if action["available"] else 1,
        rank.get(action["stage"], 99),
        0 if action["progress"] else 1,
    ))
    return unique


# ---------------------------------------------------------------------------
# Confirmation


@dataclass
class Confirmation:
    action: dict[str, Any]
    argv: list[str]
    lines: list[str] = field(default_factory=list)
    refused: str | None = None
    token: str | None = None
    approval_hint: str | None = None
    secret_needed: str | None = None
    secret_default: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    preview_text: str | None = None
    manual: bool = False

    @property
    def live(self) -> bool:
        return self.action["network"] == "live"

    @property
    def needs_yes(self) -> bool:
        return self.action["network"] == "local"


def _approval_facts(model: dict[str, Any], action: dict[str, Any], repo: Path, now) -> tuple[str | None, bool, list[str], str]:
    if action.get("approval") == "practice":
        from .model import _profile_facts

        facts = _profile_facts(repo / "work" / "practice" / "target-profile.yaml", repo, now)
        return facts.get("approvalId"), facts["ready"], facts["errors"], facts["path"]
    profile = model["profile"]
    return profile.get("approvalId"), bool(profile.get("ready")), list(profile.get("errors") or []), profile["path"]


def _parse_preview(action: dict[str, Any], stdout: str) -> tuple[list[str], str | None]:
    """Turn a dry-run/plan output into confirmation lines and a refusal reason."""
    lines: list[str] = []
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        text = stdout.strip()
        return ([f"  {line}" for line in text.splitlines()[:40]] or ["  (no plan output)"]), None
    if isinstance(value, dict) and value.get("schema_version") == "sippycup.dev/call-dry-run/v1":
        plan = value.get("one_call_plan") or {}
        softphone = value.get("softphone") or {}
        account = softphone.get("account") if isinstance(softphone.get("account"), dict) else None
        duration = softphone.get("duration_seconds") if isinstance(softphone.get("duration_seconds"), dict) else {}
        lines.append(f"  Destination: {softphone.get('destination_uri')} over {softphone.get('transport')}")
        lines.append("  Sends at most:")
        lines.append("    - 1 SIP OPTIONS preflight (over UDP at most 2 datagrams)")
        if account and account.get("register"):
            lines.append(f"    - 1 REGISTER exchange as {account.get('username')} (plus unregistration on exit)")
        lines.append(f"    - 1 INVITE dialog with RTP, hung up {duration.get('effective')} s after answer "
                     f"(profile limit {duration.get('limit')} s), CANCEL after "
                     f"{softphone.get('answer_timeout_seconds')} s unanswered")
        if softphone.get("tls"):
            lines.append(f"  TLS: {json.dumps(softphone['tls'], sort_keys=True)}")
        lines.append(f"  Capture filter: {value.get('capture_filter')}")
        blocking = list(plan.get("blocking_errors") or [])
        if not value.get("ready"):
            return lines, "the dry run is BLOCKED: " + "; ".join(blocking or ["not ready"])
        return lines, None
    return [f"  {line}" for line in json.dumps(value, indent=1, sort_keys=True).splitlines()[:40]], None


def _bounded_lines(model: dict[str, Any], action: dict[str, Any], repo: Path, now) -> list[str]:
    lines: list[str] = []
    if action["id"] == "campaign-run":
        plan = model["files"].get("planFacts") or {}
        if plan.get("error"):
            lines.append(f"  plan.json unreadable: {plan['error']}")
        else:
            lines.append(f"  Plan {plan.get('name')}: {plan.get('steps')} step(s)")
            lines.append(f"  Destinations (literal): {', '.join(plan.get('destinations') or []) or 'none'}")
            if plan.get("mediaNetworks"):
                lines.append(f"  Media only (never signaling; captured): {', '.join(plan['mediaNetworks'])}")
            approval = plan.get("approval") or {}
            if plan.get("windowBound"):
                lines.append(
                    "  Approval window: "
                    + (f"from {approval.get('validFrom')} " if approval.get("validFrom") else "")
                    + f"until {approval.get('validUntil')} (checked before every step)"
                )
            else:
                lines.append(
                    "  WARNING: this plan is NOT bound to an approval window; run scope compile "
                    "and campaign plan again to bind it"
                )
            lines.append(f"  Planned totals: {json.dumps(plan.get('plannedTotals'), sort_keys=True)}")
            lines.append(f"  Hard maxima: {json.dumps(plan.get('hardMaxima'), sort_keys=True)}")
        return lines
    if action.get("approval") == "practice":
        practice = model["readiness"]["practice"]
        lines.append(f"  Literal address: {practice.get('address') or '127.0.0.2'} (practice namespace, loopback only)")
        return lines
    target = model["target"]
    lines.append(f"  Literal address: {target.get('host')} port {target.get('port')}/{target.get('transport')}")
    if practice_route(model):
        lines.append("  Route: --practice (the target is the local practice address; loopback namespace only)")
    limits = (model["profile"].get("limits") or {})
    if limits:
        lines.append(f"  Profile limits: {json.dumps(limits, sort_keys=True)}")
    return lines


GO_STALE_SECONDS = 12 * 3600


def _go_no_go_lines(model: dict[str, Any], lines: list[str], now) -> str | None:
    """The cockpit's gate before a LIVE action: a GO from `ready` for the current profile."""
    facts = (model.get("readiness") or {}).get("goNoGo") or {}
    command = f"{LAUNCHER} ready {_eng(model)}"
    if not facts.get("present"):
        return f"no go/no-go check yet; run {command} first (it sends nothing to the target)"
    if not facts.get("current"):
        return f"the last go/no-go check was for another version of the profile; run {command} again"
    if facts.get("verdict") != "GO":
        return f"the last go/no-go check said {facts.get('verdict')} ({facts.get('path')}); fix it and run {command}"
    age = facts.get("ageSeconds")
    lines.append(f"Go/no-go: GO at {facts.get('generatedAt')} ({facts.get('path')}); "
                 f"source address {facts.get('sourceAddress') or '-'}")
    if isinstance(age, (int, float)) and age > GO_STALE_SECONDS:
        lines.append(f"  [!!] that check is {int(age // 3600)} hours old; consider running {command} again")
    return None


def prepare_confirmation(
    action: dict[str, Any],
    model: dict[str, Any],
    *,
    repo: str | Path,
    probe: Callable[[list[str]], tuple[int, str]],
    now=None,
) -> Confirmation:
    """Build the confirmation panel for one action; never runs a live command.

    ``probe`` runs a network-free preview argv and returns (exit code, stdout).
    """
    from datetime import datetime, timezone

    repo_path = Path(repo)
    instant = now or datetime.now(timezone.utc)
    argv = list(action.get("argv") or [])
    confirmation = Confirmation(action=action, argv=argv)
    lines = confirmation.lines
    lines.append(f"{action['label']} {action['title']}")
    lines.append(f"Why: {action['reason']}")
    if not action["available"]:
        if action.get("instruction") and not argv:
            lines.append(f"Manual step: {action['instruction']}")
            confirmation.manual = True
            confirmation.refused = "this is a manual step; there is nothing for the cockpit to run"
            return confirmation
        confirmation.refused = action.get("unavailableReason") or "this action is not available"
        if action.get("instruction"):
            lines.append(f"How: {action['instruction']}")
        return confirmation
    lines.append("Command (copy it to run it yourself):")
    lines.append(f"  {command_line(argv)}")
    if action["network"] == "none":
        lines.append("Network: none. This command sends no traffic.")
        return confirmation
    if action["network"] == "local":
        lines.append("Network: no target traffic. It builds or starts a local container.")
        return confirmation
    approval_id, ready, errors, source = _approval_facts(model, action, repo_path, instant)
    lines.append("Network: LIVE. This sends traffic.")
    lines.extend(_bounded_lines(model, action, repo_path, instant))
    lines.append(f"Approval: {approval_id or 'none'} (from {source})")
    if not approval_id:
        confirmation.refused = "no approval id is recorded, so the gate would refuse; nothing was started"
        return confirmation
    if not ready:
        confirmation.refused = "the profile is not ready, so the gate would refuse: " + "; ".join(errors or ["blocked"])
        return confirmation
    if action.get("approval") != "practice":
        refusal = _go_no_go_lines(model, lines, instant)
        if refusal:
            confirmation.refused = refusal
            return confirmation
    spec = TABLE_BY_ID.get(action["id"])
    if spec and spec.preview:
        preview_argv = spec.preview(model)
        if isinstance(preview_argv, list):
            lines.append(f"Plan from: {command_line(preview_argv)}")
            code, stdout = probe(preview_argv)
            confirmation.preview_text = stdout[:PREVIEW_LIMIT]
            parsed, refusal = _parse_preview(action, stdout[:PREVIEW_LIMIT])
            lines.extend(parsed)
            if refusal:
                confirmation.refused = refusal
                return confirmation
            if code != 0:
                confirmation.refused = f"the network-free plan exited {code}; nothing was started"
                return confirmation
    confirmation.token = approval_id[-4:]
    confirmation.approval_hint = "*" * max(0, len(approval_id) - 4) + "????"
    if action.get("secret") == "practice":
        problem = None
        from .runs import secret_file_problem

        problem = secret_file_problem(repo_path / model["readiness"]["practice"]["passwordFile"], repo_path / "work")
        if problem:
            confirmation.refused = f"practice password file: {problem}"
            return confirmation
        lines.append("Password: --secret-file work/practice/account.password (mode 0600, never shown)")
    elif action.get("secret") == "call" and model["target"]["account"].get("required"):
        confirmation.secret_needed = "call"
        confirmation.secret_default = f"{_eng(model)}/account.password"
    elif action.get("secret") == "campaign" and (model["files"].get("planFacts") or {}).get("credentialRefs"):
        confirmation.secret_needed = "campaign"
        confirmation.secret_default = f"{_eng(model)}/account.password"
    return confirmation


def apply_secret(
    confirmation: Confirmation,
    choice: str,
    *,
    repo: str | Path,
    environ: Mapping[str, str],
    model: dict[str, Any],
) -> str | None:
    """Apply ``file PATH`` or ``env NAME``. Returns an error message, or None.

    A password itself is never accepted: only a mode-0600 file beneath work/
    or the name of an environment variable that is already set.
    """
    from .runs import secret_file_problem

    repo_path = Path(repo)
    parts = choice.strip().split(None, 1)
    if len(parts) != 2 or parts[0] not in {"file", "env"}:
        return "answer 'file PATH' or 'env NAME'"
    kind, value = parts[0], parts[1].strip()
    if kind == "file":
        path = Path(value)
        absolute = path if path.is_absolute() else repo_path / path
        problem = secret_file_problem(absolute, repo_path / "work")
        if problem:
            return problem
        display = value
        if confirmation.secret_needed == "call":
            confirmation.argv = [*confirmation.argv, "--secret-file", display]
        else:
            reference = (model["files"].get("planFacts") or {}).get("credentialRefs")[0]
            try:
                secret = absolute.read_text(encoding="utf-8").rstrip("\n")
            except (OSError, UnicodeDecodeError) as exc:
                return f"cannot read {display}: {exc}"
            confirmation.env = {COCKPIT_SECRET_ENV: secret}
            confirmation.argv = [*confirmation.argv, "--secret-env", f"{reference}={COCKPIT_SECRET_ENV}"]
        confirmation.lines.append(f"Password: from file {display} (mode 0600, never shown)")
        return None
    if not _ENV_NAME.fullmatch(value):
        return "environment variable names are letters, digits, and _ only"
    if not environ.get(value):
        return f"{value} is not set in this environment; export it first (never type the password here)"
    if confirmation.secret_needed == "call":
        confirmation.argv = [*confirmation.argv, "--secret-env", value]
    else:
        reference = (model["files"].get("planFacts") or {}).get("credentialRefs")[0]
        confirmation.argv = [*confirmation.argv, "--secret-env", f"{reference}={value}"]
    confirmation.lines.append(f"Password: from environment variable {value} (forwarded by name only)")
    return None


def token_matches(confirmation: Confirmation, typed: str) -> bool:
    """True only for the exact last 4 characters of the approval id."""
    return confirmation.token is not None and typed.strip() == confirmation.token


def spawnable(argv: list[str]) -> bool:
    return bool(argv) and argv[0] == LAUNCHER and all(isinstance(item, str) and "\x00" not in item for item in argv)
