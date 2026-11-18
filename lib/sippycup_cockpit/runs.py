"""Discover and summarize run directories below an engagement, safely.

Every read is bounded. A run whose files are missing, oversized, or malformed
is still listed, marked unreadable with the reason, and never crashes the
cockpit. Nothing here interprets packets; verdicts come from the files the
producing command wrote.
"""

from __future__ import annotations

import itertools
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 1024 * 1024
# Call verdicts where Sippycup stopped the run itself to stay inside the scope.
SAFETY_STOPS = frozenset({"media-outside-scope"})
MAX_CONTAINERS = 64
MAX_RUNS_PER_CONTAINER = 500
MAX_FILES_LISTED = 200
MAX_EVENT_LINES = 20000
MAX_EVENT_BYTES = 4 * 1024 * 1024
MAX_TEXT_BYTES = 256 * 1024
FINDINGS_VERSION = "sippycup.dev/findings/v1"
CALL_VERSION = "sippycup.dev/call-result/v1"
CHECKS_RESULT_VERSION = "sippycup.dev/checks-result/v1"
PRACTICE_CONTAINER = "practice-calls"
PRACTICE_PROFILE_PREFIX = "sippycup-local-practice"
RUN_MARKERS = ("result.json", "findings.json", "events.jsonl", "evidence-manifest.json")
_TIMESTAMP = re.compile(r"^(\d{8}T\d{6})(\.\d+)?Z")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class Unreadable(ValueError):
    """A run file cannot be read within the cockpit's bounds."""


def _regular(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode)


def _directory(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except OSError:
        return False
    return stat.S_ISDIR(mode)


def read_json(path: Path, *, limit: int = MAX_JSON_BYTES) -> Any:
    """Read one JSON document of at most ``limit`` bytes, refusing symlinks."""
    if not _regular(path):
        raise Unreadable(f"{path.name} is missing or not a regular file")
    try:
        with path.open("rb") as source:
            data = source.read(limit + 1)
    except OSError as exc:
        raise Unreadable(f"cannot read {path.name}: {exc.strerror or exc}") from exc
    if len(data) > limit:
        raise Unreadable(f"{path.name} exceeds the {limit // 1024} KiB display limit")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Unreadable(f"{path.name} is not valid JSON: {exc}") from exc


def read_text(path: Path, *, limit: int = MAX_TEXT_BYTES) -> tuple[str, bool]:
    """Return (text, truncated) for at most ``limit`` bytes of a text file."""
    if not _regular(path):
        raise Unreadable(f"{path.name} is missing or not a regular file")
    try:
        with path.open("rb") as source:
            data = source.read(limit + 1)
    except OSError as exc:
        raise Unreadable(f"cannot read {path.name}: {exc.strerror or exc}") from exc
    truncated = len(data) > limit
    return data[:limit].decode("utf-8", errors="replace"), truncated


def _run_time(run: Path, document: Any) -> str | None:
    match = _TIMESTAMP.match(run.name)
    if match:
        try:
            value = datetime.strptime(match.group(1), "%Y%m%dT%H%M%S").replace(tzinfo=timezone.utc)
            return value.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass
    if isinstance(document, dict):
        stamps = document.get("timestamps")
        if isinstance(stamps, dict) and isinstance(stamps.get("started"), str):
            return stamps["started"][:19] + "Z"
    try:
        return datetime.fromtimestamp(run.lstat().st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        return None


def _is_run(path: Path) -> bool:
    return any(_regular(path / name) for name in RUN_MARKERS)


def discover(engagement: Path) -> list[dict[str, Any]]:
    """List run summaries below ``engagement``, oldest first.

    A run is a directory that holds result.json, findings.json, events.jsonl,
    or evidence-manifest.json, either directly below the engagement or one
    level deeper (``calls/``, ``runs/``, ``practice-calls/``, ``checks/`` and
    any directory another command adds).
    """
    if not _directory(engagement):
        return []
    found: list[tuple[Path, str]] = []
    try:
        containers = sorted(itertools.islice(engagement.iterdir(), MAX_CONTAINERS * 4))
    except OSError:
        return []
    counted = 0
    for container in containers:
        if container.name.startswith(".") or not _directory(container):
            continue
        counted += 1
        if counted > MAX_CONTAINERS:
            break
        if _is_run(container):
            found.append((container, ""))
            continue
        try:
            children = sorted(itertools.islice(container.iterdir(), MAX_RUNS_PER_CONTAINER))
        except OSError:
            continue
        for child in children:
            if child.name.startswith(".") or not _directory(child):
                continue
            if _is_run(child):
                found.append((child, container.name))
    summaries = [summarize(run, container=group, engagement=engagement) for run, group in found]
    summaries.sort(key=lambda item: (item.get("time") or "", item["name"]))
    return summaries


def _count_events(path: Path) -> tuple[int, dict[str, Any] | None, str | None]:
    """Count events and return the last decodable one, within bounds."""
    if not _regular(path):
        return 0, None, None
    count = 0
    last: dict[str, Any] | None = None
    problem = None
    try:
        with path.open("rb") as source:
            consumed = 0
            for raw in source:
                consumed += len(raw)
                if consumed > MAX_EVENT_BYTES or count >= MAX_EVENT_LINES:
                    problem = "events.jsonl exceeds the display limit; counted a prefix"
                    break
                count += 1
                try:
                    value = json.loads(raw)
                    if isinstance(value, dict):
                        last = value
                except (UnicodeDecodeError, json.JSONDecodeError):
                    problem = "events.jsonl has an undecodable line"
    except OSError as exc:
        problem = f"cannot read events.jsonl: {exc.strerror or exc}"
    return count, last, problem


def _campaign_media_scopes(path: Path, limit: int = 16) -> list[tuple[Any, dict[str, Any]]]:
    """``(step, mediaScope)`` from the softphone runner's step results, bounded."""
    found: list[tuple[Any, dict[str, Any]]] = []
    if not _regular(path):
        return found
    try:
        with path.open("rb") as source:
            consumed = 0
            for count, raw in enumerate(source):
                consumed += len(raw)
                if consumed > MAX_EVENT_BYTES or count >= MAX_EVENT_LINES or len(found) >= limit:
                    break
                try:
                    event = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if not isinstance(event, dict) or event.get("event") != "step.output" \
                        or not isinstance(event.get("text"), str):
                    continue
                for line in event["text"].splitlines()[:4]:
                    try:
                        value = json.loads(line)
                    except (ValueError, RecursionError):
                        continue
                    if isinstance(value, dict) and isinstance(value.get("mediaScope"), dict) \
                            and value["mediaScope"].get("peer"):
                        found.append((event.get("step"), value["mediaScope"]))
                        break
    except OSError:
        return found
    return found


def _files(run: Path) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    try:
        entries = sorted(itertools.islice(run.iterdir(), MAX_FILES_LISTED))
    except OSError:
        return files
    for entry in entries:
        try:
            info = entry.lstat()
        except OSError:
            continue
        kind = "dir" if stat.S_ISDIR(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "other"
        files.append({"name": entry.name, "size": info.st_size if kind == "file" else None, "type": kind})
    return files


def _manifest_privacy(run: Path) -> str | None:
    path = run / "evidence-manifest.json"
    if not _regular(path):
        return None
    try:
        document = read_json(path)
    except Unreadable:
        return "unreadable"
    privacy = document.get("privacy") if isinstance(document, dict) else None
    status = privacy.get("status") if isinstance(privacy, dict) else None
    return status if isinstance(status, str) else "unknown"


def _call_summary(document: dict[str, Any], summary: dict[str, Any]) -> None:
    verdict = document.get("verdict")
    summary["verdict"] = verdict if isinstance(verdict, str) else None
    summary["state"] = document.get("state") if isinstance(document.get("state"), str) else None
    summary["passed"] = verdict == "pass"
    target = document.get("target") if isinstance(document.get("target"), dict) else {}
    summary["target"] = target
    preflight = document.get("preflight") if isinstance(document.get("preflight"), dict) else None
    softphone = document.get("softphone") if isinstance(document.get("softphone"), dict) else None
    oracle = document.get("oracle") if isinstance(document.get("oracle"), dict) else None
    tls = document.get("tls") if isinstance(document.get("tls"), dict) else None
    facts: list[tuple[str, str]] = []
    if preflight is None:
        facts.append(("Preflight", "not run"))
    else:
        facts.append(("Preflight", f"{'ok' if preflight.get('ok') else 'FAILED'} {preflight.get('detail') or ''}".strip()))
    if softphone:
        if softphone.get("registration_attempted"):
            facts.append(
                ("Registration", f"{'registered' if softphone.get('registered') else 'not registered'}"
                 f" (status {softphone.get('registration_status')})")
            )
        else:
            facts.append(("Registration", "not attempted"))
        facts.append(
            ("Call", f"{'answered' if softphone.get('answered') else 'not answered'}, final status "
             f"{softphone.get('final_status')}, connected {softphone.get('connected_seconds')} s")
        )
        facts.append(
            ("RTP", f"sent {softphone.get('rtp_tx_packets')}, received {softphone.get('rtp_rx_packets')}"
             f" (PJSUA counters), codec {softphone.get('codec')}")
        )
    if tls is not None:
        facts.append(("TLS", f"{'verified' if tls.get('verified') else 'NOT verified'} as {tls.get('serverName')}"
                      f" ({tls.get('trust')}), connects only to {tls.get('connectsTo')}"))
    if oracle is not None:
        counts = oracle.get("summary") if isinstance(oracle.get("summary"), dict) else {}
        facts.append(
            ("Oracle", f"{oracle.get('verdict')} (pass {counts.get('pass', '?')}, fail {counts.get('fail', '?')},"
             f" unknown {counts.get('unknown', '?')})")
        )
    media_scope = document.get("mediaScope") if isinstance(document.get("mediaScope"), dict) else None
    if media_scope is not None and media_scope.get("peer"):
        rule = media_scope.get("admittedBy")
        facts.append((
            "Media scope",
            f"peer {media_scope.get('peer')} "
            + ("admitted by a literal approved address" if rule == "approved-address"
               else f"admitted by the approved media network {media_scope.get('network')} (media only)"
               if rule == "media-network"
               else "admitted (no address rule)" if rule == "any-address"
               else "NOT approved")
            + ("; port outside the approved media port range" if media_scope.get("portAdmitted") is False else ""),
        ))
    if isinstance(document.get("networkActivity"), str):
        facts.append(("Network activity", document["networkActivity"]))
    summary["facts"] = facts
    notes = document.get("notes")
    summary["notes"] = [str(item) for item in notes][:20] if isinstance(notes, list) else []
    reason = summary["notes"][0] if summary["notes"] and verdict != "pass" else None
    if reason is None and softphone and softphone.get("error"):
        reason = str(softphone["error"])
    if reason is None and oracle is not None:
        reason = f"oracle {oracle.get('verdict')}"
    if verdict in SAFETY_STOPS:
        # Sippycup stopped the call to stay inside the scope; the target did
        # nothing wrong. Say so first, with what reached the unapproved peer.
        summary["safetyStop"] = True
        peer = (softphone or {}).get("media_peer") or "an unapproved address"
        sent = (softphone or {}).get("rtp_tx_packets")
        packets = f" after {sent} RTP packet{'s' if sent != 1 else ''}" if isinstance(sent, int) else ""
        reason = (f"safety stop, not a target failure: the media peer {peer} is not an approved address "
                  f"or inside an approved media network, so the call was hung up{packets}; add the owner's "
                  "media addresses or media network to the scope and compile again")
        facts.insert(0, ("Safety stop", reason))
    summary["reason"] = reason
    journal = document.get("journalCommand")
    if (
        isinstance(journal, list)
        and len(journal) > 3
        and all(isinstance(item, str) for item in journal)
        and journal[:3] == ["./bin/sippycup", "journal", "add"]
    ):
        summary["journalCommand"] = journal


def _campaign_summary(run: Path, document: dict[str, Any], summary: dict[str, Any]) -> None:
    state = document.get("state") if isinstance(document.get("state"), str) else None
    summary["state"] = state
    summary["verdict"] = state
    summary["passed"] = state == "succeeded"
    count, last, problem = _count_events(run / "events.jsonl")
    facts = [
        ("State", str(state)),
        ("Completed steps", str(document.get("completedSteps"))),
        ("Exit code", str(document.get("exitCode"))),
        ("Events", str(count)),
    ]
    try:
        preflight = read_json(run / "preflight.json")
        facts.append(("Preflight", json.dumps(preflight, sort_keys=True)[:160]))
    except Unreadable:
        pass
    capture = document.get("capture") if isinstance(document.get("capture"), dict) else {}
    watchdog = capture.get("watchdog") if isinstance(capture.get("watchdog"), dict) else {}
    if isinstance(watchdog.get("packets"), int):
        facts.append((
            "Capture",
            f"watchdog counted {watchdog['packets']} packets, {watchdog.get('mediaPackets')} of them media"
            + (" (filter extended with the plan's authorized media networks)"
               if capture.get("filterSource") == "plan+authorized-media" else ""),
        ))
    for step, scope in _campaign_media_scopes(run / "events.jsonl"):
        rule = scope.get("admittedBy")
        source = {"destination": "the step's destination address", "networks": "authorization.networks",
                  "mediaNetworks": "authorization.mediaNetworks (media only)"}.get(str(scope.get("authorization")))
        facts.append((
            f"Media step {step}",
            f"peer {scope.get('peer')} "
            + (f"admitted by {source}" if rule and source else "admitted" if rule else "NOT approved (media-scope stop)")
            + ("; port outside the approved media port range" if scope.get("portAdmitted") is False else ""),
        ))
    summary["facts"] = facts
    notes = []
    for key in ("error", "reason", "stopReason", "message"):
        if isinstance(document.get(key), str):
            notes.append(f"{key}: {document[key]}")
    if problem:
        notes.append(problem)
    summary["notes"] = notes
    summary["reason"] = (
        notes[0] if notes else
        (f"last event {last.get('event')}" if isinstance(last, dict) and last.get("event") else None)
    )


def _findings_summary(document: dict[str, Any], summary: dict[str, Any], run: Path | None = None) -> None:
    checks = document.get("checks") if isinstance(document.get("checks"), list) else []
    findings = document.get("findings") if isinstance(document.get("findings"), list) else []
    severities: dict[str, int] = {}
    titles: list[str] = []
    for item in findings[:500]:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity", "unknown"))
        severities[severity] = severities.get(severity, 0) + 1
        titles.append(f"[{severity}] {item.get('title', '(untitled)')}")
    summary["verdict"] = f"{len(findings)} finding(s)" if findings else "no findings"
    summary["state"] = document.get("state") if isinstance(document.get("state"), str) else "completed"
    # `checks run` records its own state and exit code in result.json
    # (sippycup.dev/checks-result/v1); findings.json alone cannot say whether
    # the run was stopped by an error or an interruption.
    result: Any = None
    if run is not None and _regular(run / "result.json"):
        try:
            result = read_json(run / "result.json")
        except Unreadable:
            result = None
    if isinstance(result, dict) and result.get("apiVersion") == CHECKS_RESULT_VERSION:
        if isinstance(result.get("state"), str):
            summary["state"] = result["state"]
        summary["exitCode"] = result.get("exitCode")
    errors = [item for item in checks if isinstance(item, dict) and item.get("status") == "error"]
    # Completed: every approved check ran to an outcome. Findings are the
    # product of a completed run, not a failure of it.
    summary["completed"] = summary["state"] == "completed" and not errors
    summary["passed"] = not findings
    counts = ", ".join(f"{key} {value}" for key, value in sorted(severities.items())) or "none"
    summary["facts"] = [("State", str(summary["state"])), ("Checks", str(len(checks))),
                        ("Findings", str(len(findings))), ("By severity", counts)]
    if errors:
        summary["facts"].append(("Check errors", ", ".join(str(item.get("id")) for item in errors)))
    summary["notes"] = titles[:20]
    summary["reason"] = titles[0] if titles else f"{len(checks)} check(s), no findings"


def summarize(run: Path, *, container: str = "", engagement: Path | None = None) -> dict[str, Any]:
    """Summarize one run directory. Never raises for bad content."""
    relative = run.name if not container else f"{container}/{run.name}"
    summary: dict[str, Any] = {
        "name": run.name,
        "path": str(run),
        "relative": relative,
        "container": container,
        "kind": "unknown",
        "time": None,
        "state": None,
        "verdict": None,
        "passed": False,
        "readable": True,
        "reason": None,
        "facts": [],
        "notes": [],
        "evidenceManifest": _regular(run / "evidence-manifest.json"),
        "privacy": _manifest_privacy(run),
        "hasReport": _regular(run / "report.txt"),
        "hasCapture": _regular(run / "capture.pcap"),
        "hasExpectations": _regular(run / "expectations.yaml"),
    }
    if _SAFE_NAME.fullmatch(run.name) is None:
        summary.update(readable=False, kind="unreadable", reason="unsafe run directory name")
        return summary
    document: Any = None
    try:
        if _regular(run / "findings.json"):
            document = read_json(run / "findings.json")
            if not isinstance(document, dict) or document.get("apiVersion") != FINDINGS_VERSION:
                raise Unreadable("findings.json does not declare sippycup.dev/findings/v1")
            summary["kind"] = "checks"
            _findings_summary(document, summary, run)
        elif _regular(run / "result.json"):
            document = read_json(run / "result.json")
            if not isinstance(document, dict):
                raise Unreadable("result.json is not a JSON object")
            if document.get("apiVersion") == CALL_VERSION:
                practice = container == PRACTICE_CONTAINER or str(document.get("profile", "")).startswith(
                    PRACTICE_PROFILE_PREFIX
                )
                summary["kind"] = "practice-call" if practice else "call"
                _call_summary(document, summary)
            elif "state" in document:
                summary["kind"] = "campaign"
                _campaign_summary(run, document, summary)
            else:
                raise Unreadable("result.json has no recognised apiVersion or state")
        else:
            summary["kind"] = "campaign" if _regular(run / "events.jsonl") else "unknown"
            summary["state"] = "incomplete"
            summary["verdict"] = "incomplete"
            summary["reason"] = "no result.json yet (interrupted, running, or still being written)"
    except Unreadable as exc:
        summary.update(readable=False, kind=summary["kind"] if summary["kind"] != "unknown" else "unreadable",
                       verdict="unreadable", reason=str(exc))
    summary["time"] = _run_time(run, document)
    return summary


def detail(run: dict[str, Any]) -> dict[str, Any]:
    """Add the file listing to a summary (only when a run is opened)."""
    value = dict(run)
    value["files"] = _files(Path(run["path"]))
    return value


def human_size(size: int | None) -> str:
    if size is None:
        return "-"
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024  # type: ignore[assignment]
    return str(size)


def secret_file_problem(path: Path, work_root: Path) -> str | None:
    """Why ``path`` is not an acceptable password file, or None when it is."""
    try:
        resolved = path.resolve()
        resolved.relative_to(work_root.resolve())
    except (OSError, ValueError):
        return f"{path} is not beneath {work_root}"
    try:
        info = os.lstat(path)
    except OSError:
        return f"{path} does not exist"
    if not stat.S_ISREG(info.st_mode):
        return f"{path} is not a regular file (symlinks are refused)"
    if info.st_mode & 0o077:
        return f"{path} is readable by group or others (mode {stat.S_IMODE(info.st_mode):04o}); run chmod 600 {path}"
    if info.st_size == 0:
        return f"{path} is empty"
    return None
