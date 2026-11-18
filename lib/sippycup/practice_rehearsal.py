"""Dress rehearsal: walk the whole owner-facing chain against the practice target.

``./bin/sippycup practice-target rehearsal`` runs, in the order the operator
will use them on the real engagement, the real public commands:

  journal init, scope init      a fresh engagement directory
  --practice call (cockpit 2)   the cockpit's practice call to echo
  scope check, scope compile    from a scope answers file for the practice target
  rehearse                      the compiled profile, no traffic
  --practice preflight          UDP, then TLS verified against the practice CA
  --practice call               the cockpit's guided call, then one with DTMF
  campaign plan, campaign run   the compiled manifest, UDP and TLS cases
  checks plan, checks run       the scope's approved posture checks
  journal add, evidence ...     what the cockpit offers for the evidence stage
  summary                       the owner report, with --forbid-file

After every stage it asks the cockpit (``go --format json`` and ``go
--plain``) where the engagement stands and requires both to agree with each
other and with the stage just finished. Each stage prints PASS or FAIL and the
exact commands it ran, so the operator learns the real sequence. The first
failure stops the chain (later stages depend on it); the exit status is 0 only
when every stage passed, 1 on a failure, and 2 when it could not start.

Safety: it has no address, profile, or host option. The scope answers name
only the practice address from the generated connection facts, which must be
an IPv4 loopback literal, and every live command goes through ``--practice``,
which fails closed unless the named container is the running, labelled,
network-less practice target. The password is read only from the generated
mode-0600 file and is passed to commands as ``--secret-file`` or, for the
campaign (like the cockpit does), in one child's environment; it is never
printed. When the rehearsal had to start the target it takes it down again,
so the target is left as it was found. All evidence stays in the engagement
directory.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from . import practice
from .campaign import operator_path
from .practice_drill import DrillError, verify_namespace

LAUNCHER = "./bin/sippycup"
SCHEMA = "sippycup.dev/practice-rehearsal/v1"
APPROVAL_ID = "LOCAL-PRACTICE-REHEARSAL"
SCOPE_NAME = "dress-rehearsal"
CREDENTIAL_REF = "practice-password"
SECRET_ENV = "SIPPYCUP_COCKPIT_SECRET"  # the variable the cockpit itself uses for a campaign
PASSWORD_FILE = "work/practice/account.password"
DTMF_DIGITS = "159#"
UDP_CHECKS = (
    "banner-disclosure", "options-methods", "unauthenticated-register", "digest-quality",
    "unauthenticated-invite", "user-enumeration", "nonce-replay",
)
MIN_WINDOW = timedelta(minutes=20)
COCKPIT_COMPLETE = "Next: every stage is complete"


class RehearsalError(RuntimeError):
    """A stage assertion failed."""


class CannotStart(RuntimeError):
    """The rehearsal cannot start; nothing was sent."""


def scope_answers(facts: dict[str, Any], *, now: datetime, name: str, ca_file: str) -> str:
    """The owner's answers for the practice target, as scope.yaml text.

    Every value comes from the generated connection facts; the window starts a
    minute ago and ends when the practice approval itself ends.
    """
    address = practice.validate_address(str(facts["address"]))
    until = datetime.fromisoformat(str(facts["profile_valid_until_utc"]).replace("Z", "+00:00"))
    start = (now - timedelta(minutes=1)).astimezone(timezone.utc).replace(microsecond=0)
    if until - now < MIN_WINDOW:
        raise CannotStart(
            f"the practice approval ends at {facts['profile_valid_until_utc']}, too soon for a rehearsal; "
            "restart the target (practice-target down, then up)"
        )
    stamp = lambda value: value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
    checks = ", ".join(UDP_CHECKS)
    return f"""# Owner answers for the LOCAL PRACTICE TARGET, written by
# `./bin/sippycup practice-target rehearsal`. Every value comes from the
# generated practice connection facts (work/practice/connection.json); the
# address exists only inside the loopback-only practice namespace. On a real
# engagement this file is filled from the service owner's written answers.
schema_version: sippycup.dev/scope/v1
name: {name}
authorization:
  status: approved
  approval_id: {APPROVAL_ID}
  approved_by: sippycup practice-target rehearsal (local loopback practice only)
  valid_from: {stamp(start)}
  valid_until: {stamp(until)}
signaling:
  networks: [{address}]
  ports: [{practice.SIGNALING_PORTS['udp']}, {practice.SIGNALING_PORTS['tls']}]
  transports: [udp, tls]
targets:
  - name: practice-udp
    address: {address}
    transport: udp
    port: {practice.SIGNALING_PORTS['udp']}
  - name: practice-tls
    address: {address}
    transport: tls
    port: {practice.SIGNALING_PORTS['tls']}
    tls_server_name: {practice.DNS_NAME}
    tls_ca_file: {ca_file}
media:
  networks: [{address}]
  port_range: {{start: {practice.RTP_PORTS['start']}, end: {practice.RTP_PORTS['end']}}}
  protection: [rtp, sdes-srtp]
  codecs: [PCMU, PCMA]
  dtmf: rfc4733
  symmetric_rtp: true
client:
  source_addresses: [{practice.CALLER_ADDRESS}]
account:
  required: true
  username: {practice.ACCOUNT}
  realm: {practice.DNS_NAME}
  credential_ref: {CREDENTIAL_REF}
  credential_delivery: other
destinations:
  - name: echo
    target: practice-udp
    user: echo
    expect: echo
  - name: echo-tls
    target: practice-tls
    user: echo
    expect: echo
  - name: dtmf
    target: practice-udp
    user: dtmf
    expect: agent
limits:
  calls: 8
  concurrent_calls: 1
  calls_per_second: 1
  packets_per_second: 200
  packets: 20000
  bytes: 4000000
  call_duration_seconds: 20
  total_duration_seconds: 600
stop_conditions:
  consecutive_failures: 1
  unexpected_response: true
  packet_loss_percent: 5
test_scope:
  allowed_classes: [options, call, security-checks]
  exclusions: [none]
contact:
  name: practice operator
  channel: local terminal
  can_stop_test: true
evidence:
  retention_days: 30
  disclosure: private
security_checks:
  approved: [{checks}]
  max_requests: 40
"""


def cockpit_view(model: dict[str, Any], plain: str) -> dict[str, Any]:
    """What the JSON model and the plain dashboard each say, for comparison."""
    lines = [line for line in plain.splitlines() if line.strip()]
    last = lines[-1] if lines else ""
    here = [line for line in lines if line.rstrip().endswith("<- you are here")]
    plain_stage = None
    if here:
        words = here[0].split()
        # "  [>>] 5 First call   <- you are here"
        title = " ".join(words[2:-4])
        plain_stage = next((s["id"] for s in model.get("stages", []) if s.get("title") == title), title)
    return {
        "jsonStage": model.get("currentStage"),
        "plainStage": plain_stage,
        "jsonNext": model.get("nextCommand"),
        "plainNext": last,
        "complete": bool(model.get("complete")),
        "done": [s["id"] for s in model.get("stages", []) if s.get("state") == "done"],
    }


def agreement_problems(view: dict[str, Any], expected: str | None) -> list[str]:
    """Why ``go --plain`` and ``go --format json`` disagree, or miss ``expected``."""
    problems = []
    if view["jsonStage"] != view["plainStage"]:
        problems.append(f"go --format json says stage {view['jsonStage']!r}, go --plain says {view['plainStage']!r}")
    if expected is None:
        if not view["complete"] or not view["plainNext"].startswith(COCKPIT_COMPLETE):
            problems.append(f"expected every stage complete, cockpit is at {view['jsonStage']!r}")
    else:
        if view["jsonStage"] != expected:
            problems.append(f"expected the cockpit at stage {expected!r}, it says {view['jsonStage']!r}")
        if view["plainNext"] != f"Next: {view['jsonNext']}":
            problems.append(f"plain next line {view['plainNext']!r} differs from JSON nextCommand {view['jsonNext']!r}")
    return problems


def find_action(model: dict[str, Any], identifier: str) -> dict[str, Any]:
    action = next((item for item in model.get("actions", []) if item.get("id") == identifier), None)
    if action is None or not action.get("available") or not action.get("argv"):
        reason = (action or {}).get("unavailableReason") or "not offered"
        raise RehearsalError(f"the cockpit does not offer {identifier!r}: {reason}")
    argv = list(action["argv"])
    if argv[0] != LAUNCHER:
        raise RehearsalError(f"cockpit action {identifier!r} is not a ./bin/sippycup command")
    return action


def files_containing(root: Path, secret: bytes) -> list[str]:
    """Relative paths of regular files under ``root`` that contain ``secret``."""
    hits = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            if secret in path.read_bytes():
                hits.append(path.relative_to(root).as_posix())
        except OSError:
            continue
    return hits


def _failure_summary(stdout: str) -> str | None:
    """A short reason from a call or checks result printed with --format json."""
    try:
        document = json.loads(stdout)
    except ValueError:
        return None
    if not isinstance(document, dict):
        return None
    parts = []
    for key in ("verdict", "state"):
        if isinstance(document.get(key), str):
            parts.append(f"{key} {document[key]}")
    oracle = document.get("oracle")
    if isinstance(oracle, dict):
        for item in oracle.get("failedDetails") or []:
            if isinstance(item, dict):
                parts.append(f"{item.get('id')}: {item.get('message')}")
    if isinstance(document.get("runDirectory"), str):
        parts.append(f"run {operator_path(document['runDirectory'])}")
    return "; ".join(parts) or None


@dataclass
class Stage:
    number: int
    title: str
    status: str = "SKIP"
    seconds: float = 0.0
    commands: list[str] = field(default_factory=list)
    facts: list[str] = field(default_factory=list)
    problem: str | None = None
    cockpit: dict[str, Any] | None = None


@dataclass
class Completed:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[list[str], dict[str, str] | None, float], Completed]


class Rehearsal:
    def __init__(self, project: Path, *, runner: Runner | None = None, out=None, now=None) -> None:
        self.project = project
        self.runner = runner or self._run
        self.out = out or sys.stdout
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.stages: list[Stage] = []
        self.started_target = False
        self.engagement: Path | None = None
        self.log: Path | None = None
        self.secret: bytes | None = None
        self.current: Stage | None = None
        self.counter = 0
        self.facts: dict[str, Any] = {}

    # -- plumbing -------------------------------------------------------
    def _run(self, argv: list[str], env: dict[str, str] | None, timeout: float) -> Completed:
        environment = dict(os.environ)
        environment.update(env or {})
        result = subprocess.run(
            [str(self.project / "bin" / "sippycup"), *argv[1:]], cwd=self.project, env=environment,
            text=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False,
        )
        return Completed(argv, result.returncode, result.stdout, result.stderr)

    def say(self, text: str = "") -> None:
        print(text, file=self.out, flush=True)

    @property
    def eng(self) -> str:
        assert self.engagement is not None
        return self.engagement.relative_to(self.project).as_posix()

    def command(self, argv: list[str], *, env: dict[str, str] | None = None, timeout: float = 300,
                quiet: bool = False, expect: tuple[int, ...] | None = (0,)) -> Completed:
        """Run one public command, print it, and keep its output as evidence."""
        line = shlex.join(argv)
        if env:
            line = " ".join(f"{name}=<from {PASSWORD_FILE}>" for name in env) + " " + line
        if not quiet and self.current is not None:
            self.current.commands.append(line)
            self.say(f"    $ {line}")
        result = self.runner(argv, env, timeout)
        self.counter += 1
        if self.log is not None:
            with self.log.open("a", encoding="utf-8") as output:
                output.write(f"### {self.counter:03d} $ {line}\n### exit {result.returncode}\n")
                output.write(result.stdout)
                if result.stderr:
                    output.write("### stderr\n" + result.stderr)
                output.write("\n")
        if expect is not None and result.returncode not in expect:
            tail = _failure_summary(result.stdout) or (result.stderr.strip() or result.stdout.strip())[-600:]
            raise RehearsalError(f"exit {result.returncode} from {line}: {tail}")
        return result

    def cockpit(self, expected: str | None) -> dict[str, Any]:
        """Ask the cockpit where things stand; both renderings must agree."""
        model_text = self.command([LAUNCHER, "go", self.eng, "--format", "json"], quiet=True, expect=None)
        plain = self.command([LAUNCHER, "go", self.eng, "--plain"], quiet=True, expect=None)
        try:
            model = json.loads(model_text.stdout)
        except ValueError as error:
            raise RehearsalError(f"go --format json printed no model: {model_text.stderr.strip()[-300:]}") from error
        view = cockpit_view(model, plain.stdout)
        problems = agreement_problems(view, expected)
        if self.current is not None:
            self.current.cockpit = view
            self.current.commands.append(f"{LAUNCHER} go {self.eng} --plain    # and --format json")
            shown = "every stage complete" if view["complete"] else f"stage {view['jsonStage']}"
            verdict = "as expected, agrees with --format json" if not problems else "UNEXPECTED"
            self.say(f"    $ {LAUNCHER} go {self.eng} --plain    # cockpit: {shown}; {verdict}")
        if problems:
            raise RehearsalError("cockpit: " + "; ".join(problems))
        return model

    def fact(self, text: str) -> None:
        assert self.current is not None
        self.current.facts.append(text)
        self.say(f"      {text}")

    def require(self, condition: bool, problem: str) -> None:
        if not condition:
            raise RehearsalError(problem)

    def stage(self, title: str, body: Callable[[], None]) -> bool:
        stage = Stage(len(self.stages) + 1, title)
        self.stages.append(stage)
        if any(item.status == "FAIL" for item in self.stages[:-1]):
            stage.status = "SKIP"
            self.say(f"[SKIP] {stage.number:>2}. {title} (an earlier stage failed)")
            return False
        self.current = stage
        self.say(f"[....] {stage.number:>2}. {title}")
        started = time.monotonic()
        try:
            body()
            stage.status = "PASS"
        except RehearsalError as error:
            stage.status = "FAIL"
            stage.problem = str(error)
        except subprocess.TimeoutExpired as error:
            stage.status = "FAIL"
            stage.problem = f"timed out: {shlex.join([str(item) for item in error.cmd])}"
        stage.seconds = round(time.monotonic() - started, 1)
        self.say(f"[{stage.status}] {stage.number:>2}. {title} ({stage.seconds} s)")
        if stage.problem:
            self.say(f"      FAIL: {stage.problem}")
        self.current = None
        return stage.status == "PASS"

    def password(self) -> str:
        return (self.project / PASSWORD_FILE).read_text(encoding="utf-8").strip()

    def run_result(self, completed: Completed) -> dict[str, Any]:
        try:
            value = json.loads(completed.stdout)
        except ValueError as error:
            raise RehearsalError(f"no JSON result from {shlex.join(completed.argv)}") from error
        if not isinstance(value, dict):
            raise RehearsalError(f"unexpected output from {shlex.join(completed.argv)}")
        return value

    def journal_call(self, result: dict[str, Any]) -> None:
        argv = result.get("journalCommand")
        self.require(isinstance(argv, list) and argv[:3] == [LAUNCHER, "journal", "add"],
                     "the call printed no journal command")
        self.command(list(argv))

    # -- stages ---------------------------------------------------------
    def target_up(self) -> None:
        status = self.command([LAUNCHER, "practice-target", "status"], expect=None)
        if "Practice profile: installed" not in status.stdout:
            raise CannotStart("the practice image is not installed; run ./bin/sippycup practice-target build")
        if "Target: up" not in status.stdout:
            self.command([LAUNCHER, "practice-target", "up"], timeout=120)
            self.started_target = True
            self.fact("started the practice target; it is taken down again at the end")
        else:
            self.fact("the practice target was already up; it is left up")
        try:
            facts = verify_namespace(self.project)
        except DrillError as error:
            raise RehearsalError(str(error)) from error
        until = datetime.fromisoformat(str(facts["profile_valid_until_utc"]).replace("Z", "+00:00"))
        if until - self.now() < MIN_WINDOW:
            raise CannotStart(
                f"the practice approval ends at {facts['profile_valid_until_utc']}, too soon for a rehearsal; "
                "restart the target (practice-target down, then up)"
            )
        self.facts = facts
        self.secret = self.password().encode("utf-8")
        # A target started before approvals were archived has no record of its
        # approval yet; record the current one (idempotent) so the owner report
        # can check practice runs against it.
        practice.archive_approvals(
            practice.state_dir(self.project),
            datetime.fromisoformat(str(facts["started_utc"]).replace("Z", "+00:00")),
        )
        self.fact(f"practice target {facts['address']} (UDP/TCP {practice.SIGNALING_PORTS['udp']}, "
                  f"TLS {practice.SIGNALING_PORTS['tls']}), approval until {facts['profile_valid_until_utc']}")

    def create_engagement(self) -> None:
        stamp = self.now().strftime("%Y%m%dt%H%M%Sz")
        parent = practice.state_dir(self.project) / "rehearsals"
        parent.mkdir(mode=0o700, exist_ok=True)
        self.engagement = parent / f"dress-{stamp}-{os.getpid()}"
        self.log = None
        self.command([LAUNCHER, "journal", "init", self.eng, "--title", "Dress rehearsal (local practice target)",
                      "--owner", "Practice target"])
        (self.engagement / "rehearsal").mkdir(mode=0o700)
        self.log = self.engagement / "rehearsal" / "commands.log"
        self.command([LAUNCHER, "scope", "init", self.eng, "--name", SCOPE_NAME])
        self.require((self.engagement / "scope.yaml").is_file(), "scope init wrote no scope.yaml")
        self.cockpit("practice")

    def practice_call(self) -> None:
        model = self.cockpit("practice")
        action = find_action(model, "practice-call")
        result = self.run_result(self.command([*action["argv"], "--format", "json"], timeout=180))
        self.require(result.get("verdict") == "pass", f"practice call verdict {result.get('verdict')!r}")
        self.fact(f"verdict pass; run {result.get('runDirectory')}")
        self.journal_call(result)
        self.cockpit("scope")

    def scope(self) -> None:
        assert self.engagement is not None
        ca = self.engagement / "practice-ca.crt"
        # On a real engagement this is the owner's private CA certificate.
        ca.write_bytes((practice.state_dir(self.project) / "ca.crt").read_bytes())
        ca.chmod(0o600)
        answers = scope_answers(self.facts, now=self.now(), name=SCOPE_NAME, ca_file=f"{self.eng}/practice-ca.crt")
        practice.write_private(self.engagement / "scope.yaml", answers)
        self.say(f"    (answers written to {self.eng}/scope.yaml from the practice connection facts; "
                 "on a real engagement you fill it from the owner's written reply)")
        self.command([LAUNCHER, "scope", "check", self.eng])
        compiled = self.command([LAUNCHER, "scope", "compile", self.eng])
        for name in ("target-profile.yaml", "campaign.yaml", "expectations.yaml"):
            self.require((self.engagement / name).is_file(), f"scope compile did not write {name}")
        self.require("authorization status: approved" in compiled.stdout, "the compiled profile is not approved")
        self.fact("compiled target-profile.yaml (approved), campaign.yaml, expectations.yaml")
        self.cockpit("first-call")

    def rehearse(self) -> None:
        result = self.command([LAUNCHER, "rehearse", f"{self.eng}/target-profile.yaml"])
        self.require("Ready: yes" in result.stdout, "rehearse did not report Ready: yes")
        self.command([LAUNCHER, "checks", "plan", f"{self.eng}/target-profile.yaml"])

    def preflight(self) -> None:
        address = self.facts["address"]
        udp = self.command([LAUNCHER, "--practice", "preflight", address, str(practice.SIGNALING_PORTS["udp"]), "udp"])
        self.require("Result: PASS" in udp.stdout, "UDP preflight did not PASS")
        tls = self.command([
            LAUNCHER, "--practice", "preflight", address, str(practice.SIGNALING_PORTS["tls"]), "tls",
            "--tls-ca", f"{self.eng}/practice-ca.crt", "--tls-server-name", practice.DNS_NAME,
        ])
        self.require("Result: PASS" in tls.stdout and f"TLS: verified for name '{practice.DNS_NAME}'" in tls.stdout,
                     "TLS preflight did not PASS with a verified server name")
        self.fact(f"UDP 200 OK; TLS 200 OK verified as {practice.DNS_NAME} against the engagement's CA copy")

    def calls(self) -> None:
        model = self.cockpit("first-call")
        action = find_action(model, "call")
        # The cockpit adds the password source the operator chooses.
        argv = [*action["argv"], "--secret-file", PASSWORD_FILE, "--format", "json"]
        result = self.run_result(self.command(argv, timeout=180))
        self.require(result.get("verdict") == "pass", f"guided call verdict {result.get('verdict')!r}")
        self.fact(f"guided call to echo: pass; run {result.get('runDirectory')}")
        self.journal_call(result)
        route = argv[:argv.index("call")]
        dtmf = self.run_result(self.command([
            *route, "call", f"{self.eng}/target-profile.yaml", "--dial", "dtmf", "--dtmf", DTMF_DIGITS,
            "--duration", "8", "--username", practice.ACCOUNT, "--secret-file", PASSWORD_FILE, "--format", "json",
        ], timeout=180))
        facts = dtmf.get("dtmf") if isinstance(dtmf.get("dtmf"), dict) else {}
        wire = facts.get("wire") if isinstance(facts.get("wire"), dict) else {}
        outbound = (wire.get("outbound") or {}).get("digits")
        inbound = (wire.get("inbound") or {}).get("digits")
        self.require(dtmf.get("verdict") == "pass", f"DTMF call verdict {dtmf.get('verdict')!r}")
        self.require(outbound == DTMF_DIGITS and inbound == DTMF_DIGITS,
                     f"the digits and their echo were not both seen on the wire: {json.dumps(wire)[:200]}")
        self.fact(f"DTMF call: pass; {outbound} sent and {inbound} echoed, both decoded from the capture")
        self.journal_call(dtmf)
        self.cockpit("campaign")

    def campaign(self) -> None:
        assert self.engagement is not None
        model = self.cockpit("campaign")
        self.command(list(find_action(model, "campaign-plan")["argv"]))
        model = self.cockpit("campaign")
        action = find_action(model, "campaign-run")
        reference = (model["files"].get("planFacts") or {}).get("credentialRefs") or []
        self.require(reference == [CREDENTIAL_REF], f"plan credential references {reference!r}")
        before = set((self.engagement / "runs").glob("*")) if (self.engagement / "runs").exists() else set()
        completed = self.command([*action["argv"], "--secret-env", f"{CREDENTIAL_REF}={SECRET_ENV}"],
                                 env={SECRET_ENV: self.password()}, timeout=300)
        printed = completed.stdout.strip().splitlines()[-1] if completed.stdout.strip() else ""
        self.require(printed.startswith(f"{self.eng}/runs/"),
                     f"campaign run printed {printed!r}, not the host path of its run directory")
        runs = sorted(set((self.engagement / "runs").glob("*")) - before)
        self.require(len(runs) == 1, f"expected one new campaign run directory, found {len(runs)}")
        result = json.loads((runs[0] / "result.json").read_text(encoding="utf-8"))
        self.require(result.get("state") == "succeeded" and result.get("completedSteps") == 4,
                     f"campaign result {result}")
        self.fact(f"campaign succeeded: 4 steps (UDP and TLS OPTIONS, UDP and TLS calls); run {printed}")
        self.cockpit("checks")

    def checks(self) -> None:
        model = self.cockpit("checks")
        self.command(list(find_action(model, "checks-plan")["argv"]))
        action = find_action(model, "checks-run")
        result = self.run_result(self.command(
            [*action["argv"], "--secret-file", PASSWORD_FILE, "--format", "json"], timeout=300, expect=(0, 1)))
        statuses = {row["id"]: row["status"] for row in (result.get("findings") or {}).get("checks", [])}
        self.require(result.get("state") == "completed", f"checks state {result.get('state')!r}")
        self.require(all(statuses.get(item) in {"passed", "finding"} for item in UDP_CHECKS),
                     f"an approved check did not run to an outcome: {statuses}")
        found = sorted(item["id"] for item in (result.get("findings") or {}).get("findings", []))
        self.fact(f"{result.get('requestsSent')} requests; findings: {', '.join(found) or 'none'}")
        self.cockpit("evidence")

    def evidence(self) -> None:
        for _ in range(12):
            model = self._model()
            pending = [item for item in model.get("actions", [])
                       if item.get("available") and str(item.get("id", "")).startswith(("journal-", "manifest-"))]
            if model.get("currentStage") != "evidence" or not pending:
                break
            self.command(list(pending[0]["argv"]))
        self.cockpit("report")
        self.fact("every run has an evidence manifest and a journal entry")

    def _model(self) -> dict[str, Any]:
        completed = self.command([LAUNCHER, "go", self.eng, "--format", "json"], quiet=True, expect=None)
        try:
            return json.loads(completed.stdout)
        except ValueError as error:
            raise RehearsalError("go --format json printed no model") from error

    def summary(self) -> None:
        assert self.engagement is not None and self.secret is not None
        model = self.cockpit("report")
        action = find_action(model, "summary")
        self.command([*action["argv"], "--forbid-file", PASSWORD_FILE])
        report = json.loads((self.engagement / "report" / "report.json").read_text(encoding="utf-8"))
        self.require(report.get("integrityExceptions") == [],
                     f"integrity exceptions: {report.get('integrityExceptions')}")
        kinds = report.get("runCounts") or {}
        self.require(kinds.get("call") == 3 and kinds.get("campaign") == 1 and kinds.get("check") == 1,
                     f"report run counts {kinds}")
        practice_runs = [run["id"] for run in report.get("runs", []) if run.get("practiceApproval")]
        self.require(len(practice_runs) == 1, f"expected the practice call labelled as practice, got {practice_runs}")
        leaked = files_containing(self.engagement, self.secret)
        self.require(not leaked, f"the practice password appears in {leaked}")
        self.fact(f"report/engagement-report.html: {sum(kinds.values())} runs, "
                  f"{sum((report.get('findingCounts') or {}).values())} findings, 0 integrity exceptions; "
                  "the password appears in no file of the engagement")
        self.cockpit(None)

    # -- driver -----------------------------------------------------------
    def teardown(self) -> None:
        if self.started_target:
            self.current = Stage(0, "teardown")
            self.command([LAUNCHER, "practice-target", "down"], expect=None)
            self.current = None
            self.say("Practice target taken down again (it was down when the rehearsal started).")

    def execute(self) -> int:
        started = time.monotonic()
        self.say("Dress rehearsal: the owner-facing chain against the local practice target "
                 "(loopback inside the practice namespace only).")
        bodies = (
            self.target_up, self.create_engagement, self.practice_call, self.scope, self.rehearse,
            self.preflight, self.calls, self.campaign, self.checks, self.evidence, self.summary,
        )
        try:
            for title, body in zip(STAGE_TITLES, bodies, strict=True):
                self.stage(title, body)
        except CannotStart as error:
            self.say(f"practice-target rehearsal: {error}")
            self.say("Nothing was sent to the practice target by the chain.")
            self.teardown()
            return 2
        self.teardown()
        elapsed = round(time.monotonic() - started, 1)
        ok = bool(self.stages) and all(stage.status == "PASS" for stage in self.stages)
        summary = {
            "schema_version": SCHEMA,
            "ok": ok,
            "elapsedSeconds": elapsed,
            "engagement": self.eng if self.engagement else None,
            "stages": [stage.__dict__ for stage in self.stages],
            "practiceTargetStartedHere": self.started_target,
            "network_activity": "loopback inside the practice namespace only",
        }
        if self.engagement is not None and (self.engagement / "rehearsal").is_dir():
            practice.write_private(self.engagement / "rehearsal" / "summary.json",
                                   json.dumps(summary, indent=2, default=str) + "\n")
        self.say("")
        for stage in self.stages:
            self.say(f"  {stage.status:<4} {stage.number:>2}. {stage.title} ({stage.seconds} s)")
        verdict = "PASS" if ok else "FAIL"
        self.say(f"Dress rehearsal: {verdict} in {elapsed} s "
                 f"({sum(1 for s in self.stages if s.status == 'PASS')}/{len(self.stages)} stages)")
        if self.engagement is not None:
            self.say(f"Evidence: {self.eng} (commands.log and summary.json in rehearsal/; "
                     f"owner report in report/)")
            self.say(f"Cockpit:  {LAUNCHER} go {self.eng}")
        self.say("Network activity: loopback inside the practice namespace only")
        return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sippycup practice-target rehearsal",
        description=(
            "Walk the whole owner-facing chain (scope, rehearse, preflight, call, campaign, checks, "
            "evidence, owner report) against the local practice target with the real public commands, "
            "and check the cockpit agrees at every stage. Only the practice target is reachable."
        ),
    )
    parser.add_argument("--list", action="store_true", help="print the stages; send nothing")
    parser.add_argument("--project-dir", required=True, help=argparse.SUPPRESS)
    arguments = parser.parse_args(argv)
    project = Path(arguments.project_dir).resolve()
    if arguments.list:
        for number, title in enumerate(STAGE_TITLES, 1):
            print(f"{number:>2}. {title}")
        print("Network activity: none")
        return 0
    return Rehearsal(project).execute()


STAGE_TITLES = (
    "practice target up and verified",
    "new engagement: journal init, scope init",
    "practice call from the cockpit (stage 2)",
    "scope answers: scope check, scope compile",
    "rehearse the compiled profile (no traffic)",
    "preflight: UDP and verified TLS",
    "guided call (pass) and a DTMF call",
    "campaign plan and run",
    "security checks plan and run",
    "evidence: manifests and journal entries",
    "owner report: summary --forbid-file",
)


if __name__ == "__main__":
    raise SystemExit(main())
