"""Rehearsal drill: run the guided call against practice destinations that fail.

``./bin/sippycup practice-target drill [NAME|all]`` places one guided call
(``./bin/sippycup --practice call``) per scenario against the local practice
target and prints what the server did, the verdict Sippycup reported, the
verdict that is correct, and the ``explain`` text for that verdict.

Safety: the drill has no address, profile, or host option. It reads the
generated practice connection facts, requires the profile and the facts to name
the same IPv4 loopback address, and reaches the target only through
``--practice``, which itself fails closed unless the named container is the
running, labelled, network-less practice target. A scenario that needs a
variant profile (a closed port) writes it from the generated practice profile
and changes nothing but the port.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from . import practice

PROFILE_NAME = "target-profile.yaml"
PASSWORD_NAME = "account.password"
# Fixed cost of one guided call beyond the call itself: container start,
# capture start, preflight, registration, PJSUA start and exit, offline
# analysis.
OVERHEAD_SECONDS = 5
CLOSED_PORT = 5099


@dataclass(frozen=True)
class Scenario:
    name: str
    server: str
    dial: str
    expected: str
    expected_exit: int = 1
    duration: int = 4
    answer_timeout: int = 8
    username: str = practice.ACCOUNT
    password: str = "account"  # "account" or "wrong"
    port: int | None = None
    media_required: bool = True
    wire: str = ""  # what the capture must show; asserted by tools/practice_faults.py
    extra: tuple[str, ...] = field(default_factory=tuple)

    run_seconds: int = 0  # expected seconds the call itself takes, beyond the fixed overhead

    @property
    def estimate(self) -> int:
        """Expected seconds this scenario takes."""
        return OVERHEAD_SECONDS + self.run_seconds


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        "echo", "answers and echoes your audio (the healthy control)", "echo", "pass", 0,
        run_seconds=4, wire="200 OK, RTP in both directions",
    ),
    Scenario(
        "noanswer", "rings (180) and never answers", "noanswer", "call-not-answered",
        answer_timeout=6, run_seconds=6, wire="180 Ringing, no final response, CANCEL from the caller",
    ),
    Scenario(
        "late", "rings 12 s, then answers and echoes (patient caller)", "late", "slow-setup",
        duration=3, answer_timeout=20, run_seconds=15, wire="180, then 200 OK about 12 s after the INVITE",
    ),
    Scenario(
        "late-impatient", "rings 12 s, then answers (caller gives up after 6 s)", "late",
        "call-not-answered", answer_timeout=6, run_seconds=6,
        wire="180, CANCEL from the caller at about 6 s",
    ),
    Scenario(
        "silent", "answers and sends no RTP at all", "silent", "one-way-media",
        run_seconds=1, wire="200 OK, RTP only from the caller, none from the server",
    ),
    Scenario(
        "silence", "answers and sends RTP that is digital silence", "silence", "silent-audio",
        run_seconds=4, wire="200 OK, RTP in both directions",
    ),
    Scenario(
        "drop", "answers, echoes 3 s, then sends BYE", "drop", "peer-hung-up-early",
        duration=10, run_seconds=3, wire="200 OK, BYE from the server about 3 s later",
    ),
    Scenario(
        "unavailable", "rejects with 503 Service Unavailable", "unavailable", "call-unavailable",
        wire="final 503",
    ),
    Scenario("forbidden", "rejects with 403 Forbidden", "forbidden", "call-forbidden", wire="final 403"),
    Scenario(
        "ratelimit", "rejects with 429 Too Many Requests", "ratelimit", "call-rate-limited",
        wire="final 429",
    ),
    Scenario("busy", "rejects with 486 Busy Here", "busy", "call-busy", wire="final 486"),
    Scenario("decline", "rejects with 603 Decline", "decline", "call-declined", wire="final 603"),
    Scenario(
        "notfound", "no such destination: 404 Not Found", "nobody-home", "call-not-found",
        wire="final 404",
    ),
    Scenario(
        "earlymedia",
        "183 with 3 s of early media, then answers and echoes (Asterisk re-bases the RTP "
        "timestamp at the answer, which the oracle reports)",
        "earlymedia", "fail", run_seconds=7,
        wire="183 Session Progress with SDP before the 200 OK",
    ),
    Scenario(
        "srtp-required", "account that demands SRTP; the guided call offers plain RTP", "echo",
        "call-media-not-acceptable", username="practice-srtp", wire="final 488",
    ),
    Scenario(
        "badpassword", "rejects a REGISTER that carries the wrong password", "echo",
        "registration-failed", password="wrong", wire="401 challenge, then 401 again",
    ),
    Scenario(
        "closedport", f"nothing listens on UDP {CLOSED_PORT}, so the preflight gets no reply",
        "echo", "preflight-failed", port=CLOSED_PORT, run_seconds=1, wire="OPTIONS, no response",
    ),
)
BY_NAME = {item.name: item for item in SCENARIOS}


class DrillError(RuntimeError):
    """The drill cannot start; nothing was sent."""


def estimate_seconds(scenarios: list[Scenario]) -> int:
    return sum(item.estimate for item in scenarios)


def select(name: str) -> list[Scenario]:
    if name == "all":
        return list(SCENARIOS)
    if name not in BY_NAME:
        raise DrillError(f"unknown scenario {name!r}; choose one of: all, {', '.join(BY_NAME)}")
    return [BY_NAME[name]]


def explanation(verdict: str | None) -> dict[str, str] | None:
    """The ``./bin/sippycup explain call.VERDICT`` text, or None."""
    if verdict is None:
        return None
    from sippycup_workbench.cli import EXPLANATIONS

    entry = EXPLANATIONS.get(f"call.{verdict}")
    if entry is None:
        return None
    return {"command": f"./bin/sippycup explain call.{verdict}", "title": entry[0], "text": entry[1]}


def verify_namespace(project: Path) -> dict[str, Any]:
    """Read the practice facts and refuse anything that is not the loopback target."""
    try:
        facts = practice.load_facts(project)
    except (practice.PracticeError, OSError) as error:
        raise DrillError(f"the practice target is not set up: {error}") from error
    address = str(facts.get("address", ""))
    try:
        practice.validate_address(address)
        parsed = ipaddress.ip_address(address)
    except (practice.PracticeError, ValueError) as error:
        raise DrillError(f"practice address is not an IPv4 loopback literal: {address!r}") from error
    if not parsed.is_loopback or parsed.version != 4:
        raise DrillError(f"practice address is not an IPv4 loopback literal: {address!r}")
    profile = practice.state_dir(project) / PROFILE_NAME
    try:
        document = yaml.safe_load(profile.read_text(encoding="utf-8"))
        target = document["target"]
        approved = document["target"]["approved_addresses"]
    except (OSError, KeyError, TypeError, yaml.YAMLError) as error:
        raise DrillError(f"cannot read {profile.name}: {error}") from error
    if target.get("host") != address or approved != [address]:
        raise DrillError("the practice profile does not name only the practice address")
    if document.get("authorization", {}).get("approval_id") != practice.APPROVAL_ID:
        raise DrillError("the practice profile is not the generated LOCAL-PRACTICE-ONLY profile")
    return facts


def target_is_up(project: Path, env: dict[str, str]) -> bool:
    result = subprocess.run(
        [str(project / "bin" / "sippycup"), "practice-target", "status"],
        cwd=project, env=env, text=True, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=60,
    )
    return "Target: up" in result.stdout


def prepare_inputs(project: Path, scenario: Scenario, drill_dir: Path) -> tuple[str, str]:
    """Return the (profile, secret file) work-relative paths for one scenario."""
    state = practice.state_dir(project)
    profile = f"work/practice/{PROFILE_NAME}"
    secret = f"work/practice/{PASSWORD_NAME}"
    if scenario.port is not None:
        document = yaml.safe_load((state / PROFILE_NAME).read_text(encoding="utf-8"))
        document["target"]["port"] = scenario.port
        document["name"] = f"sippycup-local-practice-{scenario.name}"
        path = drill_dir / f"profile-{scenario.name}.yaml"
        practice.write_private(path, yaml.safe_dump(document, sort_keys=False))
        profile = f"work/practice/drills/{drill_dir.name}/{path.name}"
    if scenario.password == "wrong":
        path = drill_dir / "wrong.password"
        practice.write_private(path, "this-is-not-the-practice-password-0123456789\n")
        secret = f"work/practice/drills/{drill_dir.name}/{path.name}"
    return profile, secret


def call_argv(scenario: Scenario, profile: str, secret: str, run_root: str) -> list[str]:
    argv = [
        "--practice", "call", profile,
        "--dial", scenario.dial,
        "--username", scenario.username,
        "--secret-file", secret,
        "--duration", str(scenario.duration),
        "--answer-timeout", str(scenario.answer_timeout),
        "--run-root", run_root,
        "--engagement", run_root,
        "--format", "json",
        *scenario.extra,
    ]
    if not scenario.media_required:
        argv.append("--no-media-required")
    return argv


def run_scenario(
    project: Path, env: dict[str, str], scenario: Scenario, drill_dir: Path
) -> dict[str, Any]:
    profile, secret = prepare_inputs(project, scenario, drill_dir)
    run_root = f"work/practice/drills/{drill_dir.name}/calls"
    started = time.monotonic()
    completed = subprocess.run(
        [str(project / "bin" / "sippycup"), *call_argv(scenario, profile, secret, run_root)],
        cwd=project, env=env, text=True, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        timeout=scenario.estimate + 90,
    )
    elapsed = round(time.monotonic() - started, 1)
    result: dict[str, Any] | None = None
    try:
        result = json.loads(completed.stdout)
    except ValueError:
        result = None
    verdict = result.get("verdict") if isinstance(result, dict) else None
    softphone = (result or {}).get("softphone") or {}
    ok = verdict == scenario.expected and completed.returncode == scenario.expected_exit
    return {
        "scenario": scenario.name,
        "server": scenario.server,
        "dial": f"sip:{scenario.dial}@" + "<practice address>",
        "account": scenario.username,
        "expected": scenario.expected,
        "expectedExit": scenario.expected_exit,
        "verdict": verdict,
        "exit": completed.returncode,
        "status": "PASS" if ok else "MISMATCH",
        "finalStatus": softphone.get("final_status"),
        "hangup": softphone.get("hangup"),
        "connectedSeconds": softphone.get("connected_seconds"),
        "rtp": {"sent": softphone.get("rtp_tx_packets"), "received": softphone.get("rtp_rx_packets")},
        "runDirectory": (result or {}).get("runDirectory"),
        "elapsedSeconds": elapsed,
        "notes": [item for item in (result or {}).get("notes", [])][1:],
        "explain": explanation(verdict),
        "stderr": completed.stderr.strip()[-400:] if result is None else None,
    }


def render_human(entry: dict[str, Any]) -> str:
    lines = [
        f"== {entry['scenario']}: {entry['server']}",
        f"   dialed:       {entry['dial']} as account {entry['account']}",
        f"   verdict:      {entry['verdict']} (exit {entry['exit']})"
        f"   expected: {entry['expected']} (exit {entry['expectedExit']})   {entry['status']}",
    ]
    facts = []
    if entry["finalStatus"] is not None:
        facts.append(f"final status {entry['finalStatus']}")
    if entry["hangup"]:
        facts.append(f"hangup by {entry['hangup']}")
    if entry["connectedSeconds"] is not None:
        facts.append(f"connected {entry['connectedSeconds']}s")
    if entry["rtp"]["sent"] is not None or entry["rtp"]["received"] is not None:
        facts.append(f"RTP sent {entry['rtp']['sent']} received {entry['rtp']['received']}")
    if facts:
        lines.append("   observed:     " + ", ".join(facts))
    for note in entry["notes"]:
        lines.append(f"   note:         {note}")
    lines.append(f"   run:          {entry['runDirectory']}")
    explain = entry["explain"]
    if explain is not None:
        lines.append(f"   explain:      {explain['command']}")
        lines.append(f"                 {explain['title']}. {explain['text']}")
    if entry["stderr"]:
        lines.append(f"   stderr:       {entry['stderr']}")
    return "\n".join(lines)


def render_table(entries: list[dict[str, Any]]) -> str:
    header = f"{'scenario':<16} {'verdict':<28} {'expected':<28} result"
    rows = [header, "-" * len(header)]
    for entry in entries:
        rows.append(
            f"{entry['scenario']:<16} {str(entry['verdict']):<28} "
            f"{entry['expected']:<28} {entry['status']}"
        )
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sippycup practice-target drill",
        description=(
            "Place the guided call against practice destinations that misbehave on purpose and "
            "compare each verdict with the correct one. Only the local practice target is reachable."
        ),
    )
    parser.add_argument("scenario", nargs="?", default="all", help="a scenario name or 'all'")
    parser.add_argument("--format", choices=("human", "json"), default="human")
    parser.add_argument("--list", action="store_true", help="list scenarios and estimates; send nothing")
    parser.add_argument("--project-dir", required=True, help=argparse.SUPPRESS)
    arguments = parser.parse_args(argv)
    project = Path(arguments.project_dir).resolve()
    try:
        chosen = select(arguments.scenario)
        if arguments.list:
            for item in SCENARIOS:
                print(f"{item.name:<16} ~{item.estimate:>3}s  expect {item.expected:<28} {item.server}")
            print("Network activity: none")
            return 0
        env = dict(os.environ)
        verify_namespace(project)
        if not target_is_up(project, env):
            raise DrillError("the practice target is not up; run ./bin/sippycup practice-target up")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        drill_dir = practice.state_dir(project) / "drills" / f"{stamp}-{os.getpid()}"
        drill_dir.mkdir(mode=0o700, parents=True)
        estimate = estimate_seconds(chosen)
        if arguments.format == "human":
            print(
                f"Drill: {len(chosen)} scenario(s), estimated {estimate} s "
                f"(about {estimate / 60:.1f} min). Practice target only: loopback inside the "
                "practice namespace.",
                flush=True,
            )
        entries: list[dict[str, Any]] = []
        for scenario in chosen:
            entry = run_scenario(project, env, scenario, drill_dir)
            entries.append(entry)
            if arguments.format == "human":
                print(render_human(entry), flush=True)
    except DrillError as error:
        print(f"practice-target drill: {error}", file=sys.stderr)
        print("Nothing was sent.", file=sys.stderr)
        return 2
    except subprocess.TimeoutExpired as error:
        print(f"practice-target drill: a scenario timed out: {error.cmd[-1:]}", file=sys.stderr)
        return 1
    mismatches = [item["scenario"] for item in entries if item["status"] != "PASS"]
    summary = {
        "schema_version": "sippycup.dev/practice-drill/v1",
        "ok": not mismatches,
        "estimateSeconds": estimate,
        "elapsedSeconds": round(sum(item["elapsedSeconds"] for item in entries), 1),
        "mismatches": mismatches,
        "scenarios": entries,
        "evidence": f"work/practice/drills/{drill_dir.name}",
        "network_activity": "loopback inside the practice namespace only",
    }
    if arguments.format == "json":
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print()
        print(render_table(entries))
        print(
            f"Drill: {'PASS' if summary['ok'] else 'MISMATCH ' + ', '.join(mismatches)} "
            f"in {summary['elapsedSeconds']} s; evidence {summary['evidence']}"
        )
        print("Network activity: loopback inside the practice namespace only")
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
