"""Fixture engagements and a fake launcher for the cockpit tests."""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_workbench.journal import initialize  # noqa: E402
from sippycup_workbench.profile import default_profile, write_profile  # noqa: E402

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_repo(base: Path, *, commands: tuple[str, ...] | None = None) -> Path:
    """A minimal repository: config/commands.tsv and an empty work/."""
    repo = base / "repo"
    (repo / "config").mkdir(parents=True)
    (repo / "work").mkdir()
    registry = (ROOT / "config" / "commands.tsv").read_text(encoding="utf-8")
    if commands is not None:
        rows = [line for line in registry.splitlines() if line.startswith("#") or line.split("|", 1)[0] in commands]
        registry = "\n".join(rows) + "\n"
    (repo / "config" / "commands.tsv").write_text(registry, encoding="utf-8")
    return repo


def make_engagement(repo: Path, name: str = "eng") -> Path:
    root = repo / "work" / name
    initialize(root, title="Fixture assessment", owner="Quad")
    return root


def write_approved_profile(
    root: Path,
    *,
    valid_from: datetime,
    valid_until: datetime,
    host: str = "192.0.2.20",
    approval_id: str = "QUAD-APPROVAL-7Q2X",
    status: str = "approved",
) -> Path:
    profile = default_profile(name="stage", host=host)
    profile["target"]["approved_addresses"] = [host]
    profile["authorization"].update(
        {"status": status, "approval_id": approval_id, "valid_from": iso(valid_from), "valid_until": iso(valid_until)}
    )
    path = root / "target-profile.yaml"
    write_profile(path, profile, force=True)
    return path


def scope_text(*, valid_from: datetime, valid_until: datetime, address: str = "127.0.0.2",
               account: bool = False, approval_id: str = "QUAD-APPROVAL-7Q2X", checks: bool = False) -> str:
    account_block = (
        "account:\n  required: true\n  username: practice\n  realm: sippycup-practice\n"
        "  credential_ref: practice-password\n  credential_delivery: other\n"
        if account else
        "account:\n  required: false\n  username: null\n  realm: null\n  credential_ref: null\n"
        "  credential_delivery: null\n"
    )
    classes = "[options, call, security-checks]" if checks else "[options, call]"
    checks_block = (
        "security_checks:\n  approved: [banner-disclosure, options-methods]\n  max_requests: 10\n" if checks else ""
    )
    return f"""schema_version: sippycup.dev/scope/v1
name: fixture
authorization:
  status: approved
  approval_id: {approval_id}
  approved_by: Quad
  valid_from: {iso(valid_from)}
  valid_until: {iso(valid_until)}
signaling:
  networks: [{address}/32]
  ports: [5060]
  transports: [udp]
targets:
  - name: edge
    address: {address}
    transport: udp
    port: 5060
media:
  networks: [{address}/32]
  port_range: {{start: 20000, end: 20019}}
  protection: [rtp]
  codecs: [PCMU]
  dtmf: none
  symmetric_rtp: true
client:
  source_addresses: [127.0.0.1]
{account_block}destinations:
  - name: echo
    user: echo
    expect: echo
limits:
  calls: 2
  concurrent_calls: 1
  calls_per_second: 1
  packets_per_second: 400
  packets: 5000
  bytes: 2000000
  call_duration_seconds: 20
  total_duration_seconds: 300
stop_conditions:
  consecutive_failures: 1
  unexpected_response: true
  packet_loss_percent: 5
test_scope:
  allowed_classes: {classes}
  exclusions: [none]
contact:
  name: Fixture operator
  channel: terminal
  can_stop_test: true
evidence:
  retention_days: 30
  disclosure: private
{checks_block}"""


def write_scope(root: Path, text: str) -> Path:
    path = root / "scope.yaml"
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    return path


def write_go(root: Path, *, now: datetime, verdict: str = "GO", profile_sha256: str | None = None) -> Path:
    """Record a `ready` result for the engagement's current profile (as `./bin/sippycup ready` does)."""
    from sippycup_cockpit.ready import READY_VERSION, file_sha256, record

    result = {
        "apiVersion": READY_VERSION, "generatedAt": iso(now), "verdict": verdict,
        "engagement": f"work/{root.name}", "sourceAddress": "127.0.0.1",
        "profileSha256": profile_sha256 or file_sha256(root / "target-profile.yaml"),
        "blocking": 0 if verdict == "GO" else 1, "warnings": 0, "checks": [],
    }
    path = record(result, root)
    assert path is not None
    return path


def compiled_engagement(repo: Path, *, now: datetime, account: bool = False, name: str = "eng",
                        checks: bool = False, go: bool = True) -> Path:
    """A compiled engagement; ``go`` also records a GO from `ready` for its profile."""
    from sippycup_workbench.scope_derive import compile_scope

    root = make_engagement(repo, name)
    write_scope(root, scope_text(valid_from=now - timedelta(hours=1), valid_until=now + timedelta(hours=3),
                                 account=account, checks=checks))
    outcome = compile_scope(root, now=now)
    if outcome.exit_code != 0:
        raise AssertionError(outcome.as_dict())
    if go:
        write_go(root, now=now)
    return root


def call_result(verdict: str = "pass", *, profile: str = "stage", host: str = "192.0.2.20") -> dict:
    return {
        "apiVersion": "sippycup.dev/call-result/v1",
        "state": "completed" if verdict == "pass" else "failed",
        "verdict": verdict,
        "exitCode": 0 if verdict == "pass" else 1,
        "profile": profile,
        "target": {"host": host, "port": 5060, "transport": "udp"},
        "preflight": {"ok": True, "detail": "SIP/2.0 200 OK"},
        "softphone": {"registration_attempted": True, "registered": True, "registration_status": 200,
                      "answered": True, "final_status": 200, "connected_seconds": 10.0,
                      "rtp_tx_packets": 500, "rtp_rx_packets": 500 if verdict == "pass" else 0, "codec": "PCMU",
                      "error": None},
        "oracle": {"verdict": "pass" if verdict == "pass" else "fail", "summary": {"pass": 10, "fail": 0, "unknown": 2}},
        "notes": [] if verdict == "pass" else ["No inbound RTP was observed."],
        "timestamps": {"started": "2026-11-17T11:00:00Z", "finished": "2026-11-17T11:00:20Z"},
        "networkActivity": "1 SIP OPTIONS preflight, 1 INVITE dialog",
        "journalCommand": ["./bin/sippycup", "journal", "add", "work/eng", "--kind", "action", "--summary",
                           f"Guided baseline call (stage): {verdict}"],
    }


def write_run(root: Path, container: str, name: str, files: dict[str, object]) -> Path:
    run = root / container / name
    run.mkdir(parents=True)
    for filename, content in files.items():
        data = content if isinstance(content, (str, bytes)) else json.dumps(content)
        mode = "wb" if isinstance(data, bytes) else "w"
        with (run / filename).open(mode) as output:
            output.write(data)
    return run


FAKE_LAUNCHER = r'''#!/usr/bin/env python3
"""Fake ./bin/sippycup: records argv and imitates a few commands."""
import json, os, sys
from pathlib import Path
repo = Path(__file__).resolve().parents[1]
argv = sys.argv[1:]
with open(repo / "launcher.log", "a", encoding="utf-8") as log:
    log.write(json.dumps({"argv": argv, "stdin": None if sys.stdin is None or sys.stdin.isatty() else sys.stdin.read(),
                          "secretEnv": "SIPPYCUP_COCKPIT_SECRET" in os.environ}) + "\n")
words = [item for item in argv if not item.startswith("--practice")]
if words[:1] == ["call"] and "--dry-run" in words:
    if "--format" in words:
        print(json.dumps({"schema_version": "sippycup.dev/call-dry-run/v1", "ready": True,
                          "one_call_plan": {"blocking_errors": [], "steps": []},
                          "softphone": {"destination_uri": "sip:echo@127.0.0.2:5060", "transport": "udp",
                                        "duration_seconds": {"effective": 10, "limit": 20},
                                        "answer_timeout_seconds": 30, "account": None},
                          "capture_filter": "(host 127.0.0.2) and (udp port 5060 or udp)"}))
    else:
        print("Guided call plan: READY")
    sys.exit(0)
if words[:1] == ["call"]:
    profile = Path(words[1])
    run = repo / profile.parent / "calls" / "20261117T120000.000000Z-fixture-0001"
    run.mkdir(parents=True, exist_ok=True)
    (run / "result.json").write_text(json.dumps({"apiVersion": "sippycup.dev/call-result/v1", "state": "completed",
        "verdict": "pass", "target": {"host": "127.0.0.2", "port": 5060, "transport": "udp"},
        "preflight": {"ok": True, "detail": "SIP/2.0 200 OK"}, "softphone": None, "oracle": None, "notes": []}))
    print("Guided call: PASS (completed)")
    print(f"Run directory: {run.relative_to(repo)}")
    sys.exit(0)
print("fake launcher: " + " ".join(argv))
print("Network activity: none")
'''


def install_fake_launcher(repo: Path) -> Path:
    bin_dir = repo / "bin"
    bin_dir.mkdir(exist_ok=True)
    launcher = bin_dir / "sippycup"
    launcher.write_text(FAKE_LAUNCHER, encoding="utf-8")
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR)
    return launcher


def launcher_log(repo: Path) -> list[dict]:
    path = repo / "launcher.log"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def practice_state(repo: Path, *, now: datetime, up: bool = True) -> Path:
    """work/practice records as practice-target up writes them (no container)."""
    state = repo / "work" / "practice"
    state.mkdir(parents=True, exist_ok=True)
    (state / "image.json").write_text(json.dumps({"image": "localhost/sippycup-practice:latest"}), encoding="utf-8")
    if up:
        (state / "connection.json").write_text(json.dumps({
            "address": "127.0.0.2", "started_utc": iso(now - timedelta(minutes=5)),
            "profile_valid_until_utc": iso(now + timedelta(hours=4)),
            "authorization": "LOCAL-PRACTICE-ONLY: practice only"}), encoding="utf-8")
        profile = default_profile(name="sippycup-local-practice", host="127.0.0.2")
        profile["target"]["approved_addresses"] = ["127.0.0.2"]
        profile["authorization"].update({"status": "approved", "approval_id": "LOCAL-PRACTICE-ONLY",
                                         "valid_from": iso(now - timedelta(minutes=5)),
                                         "valid_until": iso(now + timedelta(hours=4))})
        profile["capture"] = {"interface": "lo", "output": "work/practice/call.pcap"}
        write_profile(state / "target-profile.yaml", profile, force=True)
        password = state / "account.password"
        password.write_text("not-a-real-password", encoding="utf-8")
        password.chmod(0o600)
    return state


def copy_tree(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination)


def env_without(*names: str) -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key not in names}
