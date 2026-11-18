"""Text rendering of the cockpit model, shared by plain, line, and curses modes.

Status is always carried by text markers (``[ok]``, ``[!!]``, ``[LIVE]``...);
colour, where a terminal shows it, is only a supplement. This follows the
explicit-label convention of mission control (docs/MISSION-CONTROL.md).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .help_text import STAGE_BY_ID
from .model import authorization_window
from .runs import human_size

STAGE_MARKER = {"done": "[ok]", "current": "[>>]", "todo": "[  ]", "recommended": "[--]", "not-applicable": "[--]"}


def step_marker(done: bool | None) -> str:
    return "[ok]" if done is True else "[??]" if done is None else "[  ]"


def live_authorization(auth: dict[str, Any], now: datetime | None) -> dict[str, Any]:
    """Recompute the countdown for ``now`` without rebuilding the model."""
    if now is None or not auth.get("status"):
        return auth
    value = authorization_window(auth.get("status"), auth.get("validFrom"), auth.get("validUntil"), now)
    value["approvalId"] = auth.get("approvalId")
    value["source"] = auth.get("source")
    return value


def _image_line(image: dict[str, Any]) -> str:
    if not image.get("checked"):
        return f"[??] {image.get('detail', 'not checked')}"
    if image.get("present") is False:
        return f"[!!] {image.get('image')} is not built ({image.get('detail', '')})".rstrip(" ()")
    if image.get("stale"):
        if not image.get("inputsChanged"):
            return (f"[!!] {image.get('image')} built {image.get('created')} was built from different sources "
                    "than this checkout; rebuild")
        return (f"[!!] {image.get('image')} built {image.get('created')} is OLDER than the last code change "
                f"({image.get('inputsChanged')}); rebuild")
    marker = "[ok]" if image.get("present") else "[??]"
    extra = "; working tree has uncommitted image inputs" if image.get("dirty") else ""
    return f"{marker} {image.get('image')} built {image.get('created')}{extra}"


def _practice_line(practice: dict[str, Any], now: datetime | None) -> str:
    if not practice.get("up"):
        if not practice.get("installed"):
            return "[  ] practice target down; image not recorded as built (work/practice/image.json)"
        return "[  ] practice target down (per work/practice records)"
    auth = practice.get("authorization") or {}
    if auth and now is not None:
        auth = live_authorization(auth, now)
    profile = f"; practice profile {auth.get('text')}" if auth else ""
    marker = "[!!]" if auth.get("state") == "expired" else "[ok]"
    return f"{marker} practice target up at {practice.get('address')}{profile}"


def _scope_lines(scope: dict[str, Any], *, limit: int) -> list[str]:
    state = scope["state"]
    if state == "missing":
        return ["[  ] no scope.yaml yet"]
    if state == "invalid":
        return [f"[!!] scope.yaml is structurally invalid: {', '.join(scope['errors'][:3])}"]
    if state in {"incomplete", "inconsistent"}:
        lines = [f"[!!] {state}: {len(scope['unanswered'])} unanswered question(s), {len(scope['errors'])} error(s)"]
        for question in scope["unanswered"][:limit]:
            lines.append(f"       - Q{question['number']} {question['section']}: {question['text']}")
        if len(scope["unanswered"]) > limit:
            lines.append(f"       ... and {len(scope['unanswered']) - limit} more (scope questions)")
        if not scope["unanswered"]:
            for error in scope["errors"][:limit]:
                lines.append(f"       - {error}")
        return lines
    if state == "stale":
        return [f"[!!] complete, but derivatives are stale: {', '.join(scope['staleItems']) or 'recompile'}"]
    if state == "complete-not-compiled":
        return ["[  ] complete and consistent; not compiled yet"]
    return [f"[ok] complete and consistent; derivatives {scope['derivatives']}"]


def _target_line(target: dict[str, Any]) -> str:
    if not target.get("host"):
        return "[  ] no target yet"
    account = target["account"]
    if account.get("required") is None:
        account_text = "account unknown"
    elif account.get("required"):
        account_text = f"account yes ({account.get('username') or 'username missing'})"
    else:
        account_text = "account no"
    destinations = ", ".join(
        f"{item['user']} ({item['expect']})" for item in target.get("destinations", [])
    ) or "none recorded"
    tls = f", TLS name {target['tlsServerName']}" if target.get("tlsServerName") else ""
    if target.get("literal") is None:
        literal = "from scope.yaml; not compiled into a profile yet"
    else:
        literal = "literal approved address" if target.get("literal") else "NOT a literal approved address"
    return (f"{target.get('host')} port {target.get('port')}/{target.get('transport')} ({literal}){tls}; "
            f"{account_text}; destinations: {destinations}")


def _journal_line(journal: dict[str, Any]) -> str:
    if not journal.get("valid"):
        return f"[!!] {journal.get('error') or 'invalid'}"
    last = journal.get("last")
    if not last:
        return "[ok] valid, no entries yet"
    return (f"[ok] valid, {journal['entries']} entries; last #{last['sequence']} {last['recordedAt']} "
            f"{last['kind']}: {last['summary']}")


def run_line(index: int, run: dict[str, Any]) -> str:
    marker = "[ok]" if run["passed"] else "[??]" if not run["readable"] else "[!!]"
    if run.get("verdict") == "incomplete":
        marker = "[??]"
    if run.get("safetyStop"):
        marker = "[stop]"
    reason = f" - {run['reason']}" if run.get("reason") else ""
    return (f"{index:>2}. {marker} {run.get('time') or '-':20} {run['kind']:13} {str(run.get('verdict')):12} "
            f"{run['relative']}{reason}")


def action_line(index: int, action: dict[str, Any]) -> list[str]:
    if action["available"]:
        status = ""
    elif action.get("unavailableReason") == "manual step":
        status = "  [..] manual step"
    else:
        status = f"  [!!] {action.get('unavailableReason')}"
    lines = [f"{index:>2}. {action['label']:9} {action['title']} (stage {STAGE_BY_ID[action['stage']].number})"
             f"{status}" if action["stage"] in STAGE_BY_ID else f"{index:>2}. {action['label']:9} {action['title']}{status}"]
    if action.get("command"):
        lines.append(f"      {action['command']}")
    elif action.get("instruction"):
        lines.append(f"      {action['instruction']}")
    return lines


def render_dashboard(model: dict[str, Any], *, now: datetime | None = None, question_limit: int = 5,
                     action_limit: int | None = None, all_steps: bool = False) -> list[str]:
    engagement = model["engagement"]
    title = f" ({engagement['title']}, owner {engagement['owner']})" if engagement.get("title") else ""
    lines = [
        f"Sippycup cockpit: engagement {engagement['display']}{title}",
        f"As of {model['generatedAt']}. The cockpit itself sends no traffic.",
        "",
    ]
    if not engagement["exists"]:
        lines.append("[!!] The engagement directory does not exist yet.")
    auth = live_authorization(model["authorization"], now)
    approval = auth.get("approvalId") or "none"
    lines.append(f"Authorization  {auth.get('marker', '[??]')} {auth.get('text')}; approval id: {approval}")
    if auth.get("source"):
        lines.append(f"               from {auth['source']}")
    scope_lines = _scope_lines(model["scope"], limit=question_limit)
    lines.append(f"Scope          {scope_lines[0]}")
    lines.extend(scope_lines[1:])
    lines.append(f"Target         {_target_line(model['target'])}")
    lines.append(f"Image          {_image_line(model['readiness']['image'])}")
    lines.append(f"Practice       {_practice_line(model['readiness']['practice'], now)}")
    lines.append(f"Journal        {_journal_line(model['journal'])}")
    for blocker in (model.get("advisor") or {}).get("blockers") or []:
        lines.append(f"Blocker        [!!] {blocker}")
    lines.append("")
    lines.append("Stages")
    for stage in model["stages"]:
        suffix = "   <- you are here" if stage["state"] == "current" else (
            "   (recommended before the first live call)" if stage["state"] == "recommended" else
            "   (not applicable: the profile approves no checks)" if stage["state"] == "not-applicable" else "")
        lines.append(f"  {STAGE_MARKER[stage['state']]} {stage['number']} {stage['title']}{suffix}")
        if all_steps or stage["state"] in {"current"}:
            for step in stage["steps"]:
                lines.append(f"         {step_marker(step['done'])} {step['label']}")
    lines.append("")
    runs = model["runs"]
    lines.append(f"Runs ({len(runs)})")
    if not runs:
        lines.append("   none yet")
    for index, run in enumerate(runs, 1):
        lines.append("  " + run_line(index, run))
    lines.append("")
    actions = model["actions"]
    shown = actions if action_limit is None else actions[:action_limit]
    lines.append("Next actions ([offline] runs on Enter, [local] asks y/N, [LIVE] needs the typed approval token)")
    if not shown:
        lines.append("   none")
    for index, action in enumerate(shown, 1):
        lines.extend("  " + line for line in action_line(index, action))
    if action_limit is not None and len(actions) > action_limit:
        lines.append(f"   ... {len(actions) - action_limit} more")
    lines.append("")
    if model.get("complete"):
        lines.append("Next: every stage is complete; record remediation and retests as journal follow-ups.")
    else:
        lines.append(f"Next: {model['nextCommand'] or 'no runnable action; see the manual steps above'}")
    return lines


def render_run(run: dict[str, Any]) -> list[str]:
    lines = [
        f"Run {run['relative']}",
        f"Kind: {run['kind']}   Time: {run.get('time')}   State: {run.get('state')}   Verdict: {run.get('verdict')}",
    ]
    if not run["readable"]:
        lines.append(f"[??] unreadable: {run.get('reason')}")
    for name, value in run.get("facts") or []:
        lines.append(f"  {name}: {value}")
    privacy = run.get("privacy")
    lines.append(f"  Evidence manifest: {'present' if run.get('evidenceManifest') else 'missing'}"
                 f"{f', privacy {privacy}' if privacy else ''}")
    if run.get("notes"):
        lines.append("Notes:")
        lines.extend(f"  - {note}" for note in run["notes"])
    if "files" in run:
        lines.append("Files:")
        for item in run["files"]:
            suffix = "/" if item["type"] == "dir" else ""
            lines.append(f"  {human_size(item['size']):>10}  {item['name']}{suffix}")
    return lines


def render_confirmation(confirmation) -> list[str]:
    lines = list(confirmation.lines)
    if confirmation.manual:
        lines.append("[..] Do this yourself; refresh the dashboard afterwards.")
    elif confirmation.refused:
        lines.append(f"[!!] REFUSED: {confirmation.refused}")
    return lines
