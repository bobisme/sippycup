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
  safety stop                   a throwaway engagement (DIR-stop) whose answers
                                omit the media address: the guided call must
                                end media-outside-scope and be presented as a
                                safety stop by the cockpit and owner report

``--proxy`` writes the answers in the proxy shape: signaling to the practice
proxy (407 challenges, realm and certificate name sippycup-proxy), media from
the practice address, so signaling and media addresses differ like on most
real platforms. The approved checks include srtp-policy.

``--media-cidr`` (implies ``--proxy``) answers media as a RANGE, the way
owners approve a media-server pool: the /31 around the practice address
(127.0.0.2/31, which covers 127.0.0.2 and 127.0.0.3; no range wider than one
address can hold 127.0.0.2 without 127.0.0.3). The compiled profile then
lists only the proxy as a literal approved address and the range as a
media-only network; every call must record that the media peer was admitted
by that network, a guided call whose host is the media address must be
refused before any packet (a media network never admits signaling), and the
stop leg answers the adjacent range 127.0.0.4/31, just outside the media
address, so the call must stop media-outside-scope.

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
# srtp-policy places two 1-second calls on a UDP first target (plain RTP, then
# a mandatory SDES offer); its findings must reach the owner report.
CHECKS = (*UDP_CHECKS, "srtp-policy")
MIN_WINDOW = timedelta(minutes=20)
COCKPIT_COMPLETE = "Next: every stage is complete"
# The stop leg: RTP packets the softphone may send to the unapproved media
# address before the media-scope stop hangs up (the proxy gate's bound).
STOP_MAX_PACKETS = 10


class RehearsalError(RuntimeError):
    """A stage assertion failed."""


class CannotStart(RuntimeError):
    """The rehearsal cannot start; nothing was sent."""


@dataclass(frozen=True)
class Shape:
    """What the owner's answers describe: where signaling and media live.

    ``direct`` is Asterisk itself (signaling and media on one address, 401
    challenges). ``proxy`` is the practice proxy, the shape of most real
    platforms: signaling to the proxy (407 challenges, Record-Route, its own
    realm and certificate name), media from a different address.
    """

    kind: str
    signaling: str
    media: tuple[str, ...]
    server_name: str
    realm: str
    prefix: str
    # What the owner wrote under media.networks when it is not the literal
    # media addresses (the --media-cidr ranges); None means ``media``.
    media_answer: tuple[str, ...] | None = None

    @property
    def answered_media(self) -> tuple[str, ...]:
        return self.media_answer if self.media_answer is not None else self.media


def shape_for(facts: dict[str, Any], *, proxy: bool, media_approved: bool = True,
              media_cidr: bool = False) -> Shape:
    """The answer shape from the generated connection facts, loopback only.

    ``media_approved=False`` is the deliberate mistake of the stop leg: the
    owner answers that media comes from the signaling address, so only the
    signaling address is approved and the real media address is not. With
    ``media_cidr`` media is answered as a range: the /31 holding the media
    address, or for the stop leg the adjacent /31 just outside it.
    """
    address = practice.validate_address(str(facts["address"]))
    if not proxy:
        if not media_approved:
            raise ValueError("the direct shape has one address; only the proxy shape can omit media")
        return Shape("direct", address, (address,), practice.DNS_NAME, practice.DNS_NAME, "practice")
    details = facts.get("proxy")
    if not isinstance(details, dict) or not details.get("address"):
        raise CannotStart("the practice facts describe no proxy; rebuild the practice image "
                          "(practice-target build) and restart the target")
    signaling = practice.validate_address(str(details["address"]))
    if signaling == address:
        raise CannotStart("the practice proxy shares the practice address; restart the target")
    if details.get("dns_name") != practice.PROXY_DNS_NAME:
        raise CannotStart(f"unexpected proxy server name {details.get('dns_name')!r}")
    media = (address,) if media_approved else (signaling,)
    answer = None
    if media_cidr:
        answer = (media_range(address, inside=media_approved),)
        media = (address,)
    return Shape("proxy", signaling, media, practice.PROXY_DNS_NAME, practice.PROXY_REALM, "proxy",
                 media_answer=answer)


def media_range(address: str, *, inside: bool = True) -> str:
    """The /31 holding ``address`` (inside) or the next /31 above it (just outside).

    Both stay in 127.0.0.0/8 and never hold 127.0.0.1, the caller's address.
    """
    import ipaddress

    network = ipaddress.ip_network(f"{address}/31", strict=False)
    if not inside:
        network = ipaddress.ip_network(f"{network.broadcast_address + 1}/31")
    loopback = ipaddress.ip_network("127.0.0.0/8")
    if not network.subnet_of(loopback) or ipaddress.ip_address(practice.CALLER_ADDRESS) in network:
        raise CannotStart(f"cannot form a practice media range from {address}: {network} leaves the "
                          "loopback practice addresses or holds the caller's address")
    return str(network)


def checks_section(checks: tuple[str, ...] = CHECKS) -> dict[str, Any]:
    """``security_checks`` for a UDP first target with an account and a destination.

    ``max_requests`` is exactly the sum of the declared bounds, the same sum
    ``scope check`` compares it with, so nothing beyond what the approved
    checks may send is approved.
    """
    from sippycup_checks import catalog

    section = {"account": practice.ACCOUNT, "destination": "echo", "cleartext_endpoints": []}
    total = sum(catalog.declared_bound(catalog.get(item), section, "udp") for item in checks)
    return {"approved": list(checks), "max_requests": total}


def scope_answers(facts: dict[str, Any], *, now: datetime, name: str, ca_file: str,
                  shape: Shape | None = None, checks: tuple[str, ...] = CHECKS) -> str:
    """The owner's answers for the practice target, as scope.yaml text.

    Every value comes from the generated connection facts; the window starts a
    minute ago and ends when the practice approval itself ends.
    """
    shape = shape or shape_for(facts, proxy=False)
    practice.validate_address(str(facts["address"]))
    until = datetime.fromisoformat(str(facts["profile_valid_until_utc"]).replace("Z", "+00:00"))
    start = (now - timedelta(minutes=1)).astimezone(timezone.utc).replace(microsecond=0)
    if until - now < MIN_WINDOW:
        raise CannotStart(
            f"the practice approval ends at {facts['profile_valid_until_utc']}, too soon for a rehearsal; "
            "restart the target (practice-target down, then up)"
        )
    stamp = lambda value: value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
    if checks:
        section = checks_section(checks)
        classes = "[options, call, security-checks]"
        checks_text = (f"security_checks:\n  approved: [{', '.join(section['approved'])}]\n"
                       f"  max_requests: {section['max_requests']}\n")
    else:
        classes, checks_text = "[options, call]", ""
    address = shape.signaling
    if shape.kind == "proxy":
        where = ("# Proxy shape: signaling goes to the practice proxy, which challenges with\n"
                 "# 407 in its own realm and Record-Routes; the media address differs from the\n"
                 "# signaling address, exactly as an owner of such a platform answers.\n")
        if shape.media == (shape.signaling,):
            where += ("# DELIBERATE MISTAKE (the stop leg): media is answered as the signaling\n"
                      "# address, so the real media address is not approved.\n")
        if shape.media_answer is not None:
            where += ("# Media is answered as a RANGE (a media-server pool), as most owners do;\n"
                      "# it becomes the profile's media-only media.networks.\n")
            if not any(_contains(item, shape.media[0]) for item in shape.media_answer):
                where += ("# DELIBERATE MISTAKE (the stop leg): the range is the one just outside\n"
                          "# the real media address, so that address is not approved.\n")
    else:
        where = ""
    return f"""# Owner answers for the LOCAL PRACTICE TARGET, written by
# `./bin/sippycup practice-target rehearsal`. Every value comes from the
# generated practice connection facts (work/practice/connection.json); the
# address exists only inside the loopback-only practice namespace. On a real
# engagement this file is filled from the service owner's written answers.
{where}schema_version: sippycup.dev/scope/v1
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
  - name: {shape.prefix}-udp
    address: {address}
    transport: udp
    port: {practice.SIGNALING_PORTS['udp']}
  - name: {shape.prefix}-tls
    address: {address}
    transport: tls
    port: {practice.SIGNALING_PORTS['tls']}
    tls_server_name: {shape.server_name}
    tls_ca_file: {ca_file}
media:
  networks: [{', '.join(shape.answered_media)}]
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
  realm: {shape.realm}
  credential_ref: {CREDENTIAL_REF}
  credential_delivery: other
destinations:
  - name: echo
    target: {shape.prefix}-udp
    user: echo
    expect: echo
  - name: echo-tls
    target: {shape.prefix}-tls
    user: echo
    expect: echo
  - name: dtmf
    target: {shape.prefix}-udp
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
  allowed_classes: {classes}
  exclusions: [none]
contact:
  name: practice operator
  channel: local terminal
  can_stop_test: true
evidence:
  retention_days: 30
  disclosure: private
{checks_text}"""


def _contains(network: str, address: str) -> bool:
    import ipaddress

    return ipaddress.ip_address(address) in ipaddress.ip_network(network, strict=False)


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
    def __init__(self, project: Path, *, runner: Runner | None = None, out=None, now=None,
                 proxy: bool = False, media_cidr: bool = False) -> None:
        self.project = project
        self.media_cidr = media_cidr
        self.proxy = proxy or media_cidr
        self.shape: Shape | None = None
        self.check_findings: list[str] = []
        self.stop_engagement: Path | None = None
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
        self.shape = shape_for(facts, proxy=self.proxy, media_cidr=self.media_cidr)
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
        if self.shape.kind == "proxy":
            self.fact(f"proxy shape: signaling to the proxy {self.shape.signaling} ({self.shape.server_name}, "
                      f"407 in realm {self.shape.realm}), media from {', '.join(self.shape.media)}")
        if self.shape.media_answer is not None:
            import ipaddress

            covered = [str(item) for net in self.shape.media_answer for item in ipaddress.ip_network(net)]
            self.fact(f"media answered as the range {', '.join(self.shape.media_answer)}, which covers "
                      f"{', '.join(covered)}; signaling stays bound to the literal proxy address")

    def create_engagement(self) -> None:
        stamp = self.now().strftime("%Y%m%dt%H%M%Sz")
        parent = practice.state_dir(self.project) / "rehearsals"
        parent.mkdir(mode=0o700, exist_ok=True)
        kind = "dress-proxy-cidr" if self.media_cidr else "dress-proxy" if self.proxy else "dress"
        self.engagement = parent / f"{kind}-{stamp}-{os.getpid()}"
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
        self.write_answers(self.shape)
        self.compile_scope()
        # Stage 4 waits for the go/no-go check (`ready`) of this profile.
        self.cockpit("rehearse")

    def write_answers(self, shape: Shape | None, *, checks: tuple[str, ...] = CHECKS) -> None:
        assert self.engagement is not None
        ca = self.engagement / "practice-ca.crt"
        # On a real engagement this is the owner's private CA certificate.
        ca.write_bytes((practice.state_dir(self.project) / "ca.crt").read_bytes())
        ca.chmod(0o600)
        answers = scope_answers(self.facts, now=self.now(), name=SCOPE_NAME, ca_file=f"{self.eng}/practice-ca.crt",
                                shape=shape, checks=checks)
        practice.write_private(self.engagement / "scope.yaml", answers)
        assert shape is not None
        media = ", ".join(shape.answered_media)
        self.say(f"    (answers written to {self.eng}/scope.yaml from the practice connection facts: signaling "
                 f"{shape.signaling}, media {media}; on a real engagement you fill it from the owner's written reply)")

    def compile_scope(self, shape: Shape | None = None) -> None:
        assert self.engagement is not None
        self.command([LAUNCHER, "scope", "check", self.eng])
        compiled = self.command([LAUNCHER, "scope", "compile", self.eng])
        for name in ("target-profile.yaml", "campaign.yaml", "expectations.yaml"):
            self.require((self.engagement / name).is_file(), f"scope compile did not write {name}")
        self.require("authorization status: approved" in compiled.stdout, "the compiled profile is not approved")
        self.fact("compiled target-profile.yaml (approved), campaign.yaml, expectations.yaml")
        shape = shape or self.shape
        if shape is not None and shape.media_answer is not None:
            self.require_media_networks(shape, compiled.stdout)

    def require_media_networks(self, shape: Shape, compiled: str) -> None:
        """The range became a media-only rule; only the proxy is a literal approved address."""
        import yaml

        assert self.engagement is not None
        profile = yaml.safe_load((self.engagement / "target-profile.yaml").read_text(encoding="utf-8"))
        approved = (profile.get("target") or {}).get("approved_addresses")
        networks = (profile.get("media") or {}).get("networks")
        self.require(approved == [shape.signaling],
                     f"the profile's literal approved addresses are {approved}, expected only {shape.signaling}")
        self.require(networks == list(shape.media_answer or ()),
                     f"the profile's media.networks are {networks}, expected {list(shape.media_answer or ())}")
        self.require("media.networks" in compiled and "media only" in compiled,
                     "scope compile did not say where the media range went")
        self.fact(f"profile: approved_addresses {approved} (signaling and media), media.networks {networks} "
                  "(media only)")

    def rehearse(self) -> None:
        result = self.command([LAUNCHER, "rehearse", f"{self.eng}/target-profile.yaml"])
        self.require("Ready: yes" in result.stdout, "rehearse did not report Ready: yes")
        if self.shape is not None and self.shape.media_answer is not None:
            shown = [line for line in result.stdout.splitlines() if line.startswith("Media only: ")]
            self.require(len(shown) == 1 and all(item in shown[0] for item in self.shape.media_answer),
                         f"rehearse does not show the media network for review: {result.stdout.strip()[-400:]}")
            self.fact(f"rehearse shows it for review: {shown[0]}")
        self.command([LAUNCHER, "checks", "plan", f"{self.eng}/target-profile.yaml"])
        self.go_no_go(self.cockpit("rehearse"))
        self.cockpit("first-call")

    def go_no_go(self, model: dict[str, Any] | None = None) -> None:
        """The cockpit's go/no-go action, with the password source the calls will use."""
        argv = list(find_action(model, "ready")["argv"]) if model is not None else [LAUNCHER, "ready", self.eng]
        result = self.command([*argv, "--secret-file", PASSWORD_FILE])
        self.require("VERDICT: GO" in result.stdout, f"ready did not say GO: {result.stdout.strip()[-600:]}")
        marks = [line.split("]", 1)[0] + "]" for line in result.stdout.splitlines() if line.startswith("[")]
        self.fact(f"ready: GO ({len(marks)} lines: {marks.count('[GO]')} GO, {marks.count('[WARN]')} WARN, "
                  f"{marks.count('[INFO]')} INFO); recorded under {self.eng}/readiness/")

    def preflight(self) -> None:
        assert self.shape is not None
        address, name = self.shape.signaling, self.shape.server_name
        udp = self.command([LAUNCHER, "--practice", "preflight", address, str(practice.SIGNALING_PORTS["udp"]), "udp"])
        self.require("Result: PASS" in udp.stdout, "UDP preflight did not PASS")
        tls = self.command([
            LAUNCHER, "--practice", "preflight", address, str(practice.SIGNALING_PORTS["tls"]), "tls",
            "--tls-ca", f"{self.eng}/practice-ca.crt", "--tls-server-name", name,
        ])
        self.require("Result: PASS" in tls.stdout and f"TLS: verified for name '{name}'" in tls.stdout,
                     "TLS preflight did not PASS with a verified server name")
        self.fact(f"UDP 200 OK from {address}; TLS 200 OK verified as {name} against the engagement's CA copy")

    def calls(self) -> None:
        model = self.cockpit("first-call")
        action = find_action(model, "call")
        # The cockpit adds the password source the operator chooses.
        argv = [*action["argv"], "--secret-file", PASSWORD_FILE, "--format", "json"]
        result = self.run_result(self.command(argv, timeout=180))
        self.require(result.get("verdict") == "pass", f"guided call verdict {result.get('verdict')!r}")
        self.fact(f"guided call to echo: pass; {self.shape_seen(result)}; run {result.get('runDirectory')}")
        self.journal_call(result)
        route = argv[:argv.index("call")]
        if self.shape is not None and self.shape.media_answer is not None:
            self.signaling_not_widened(route)
        dtmf = self.run_result(self.command([
            *route, "call", f"{self.eng}/target-profile.yaml", "--dial", "dtmf", "--dtmf", DTMF_DIGITS,
            "--duration", "8", "--username", practice.ACCOUNT, "--secret-file", PASSWORD_FILE, "--format", "json",
        ], timeout=180))
        facts = dtmf.get("dtmf") if isinstance(dtmf.get("dtmf"), dict) else {}
        wire = facts.get("wire") if isinstance(facts.get("wire"), dict) else {}
        outbound = (wire.get("outbound") or {}).get("digits")
        inbound = (wire.get("inbound") or {}).get("digits")
        self.require(dtmf.get("verdict") == "pass", f"DTMF call verdict {dtmf.get('verdict')!r}")
        self.shape_seen(dtmf)
        self.require(outbound == DTMF_DIGITS and inbound == DTMF_DIGITS,
                     f"the digits and their echo were not both seen on the wire: {json.dumps(wire)[:200]}")
        self.fact(f"DTMF call: pass; {outbound} sent and {inbound} echoed, both decoded from the capture")
        self.journal_call(dtmf)
        self.cockpit("campaign")

    def shape_seen(self, result: dict[str, Any]) -> str:
        """Signaling went to the answered signaling address, media to an answered media address."""
        assert self.shape is not None
        host = (result.get("target") or {}).get("host")
        peer = str((result.get("softphone") or {}).get("media_peer") or "")
        self.require(host == self.shape.signaling, f"the call signalled to {host!r}, not {self.shape.signaling}")
        self.require(peer.rsplit(":", 1)[0] in self.shape.media,
                     f"the media peer {peer!r} is not the answered media address {', '.join(self.shape.media)}")
        if self.shape.media_answer is None:
            return f"signaling {host}, media peer {peer}"
        record = result.get("mediaScope") if isinstance(result.get("mediaScope"), dict) else {}
        self.require(record.get("admittedBy") == "media-network" and record.get("network") in self.shape.media_answer
                     and record.get("inScope") is True,
                     f"the result does not record the media range as the rule that admitted the peer: {record}")
        return f"signaling {host}, media peer {peer} admitted by media network {record['network']}"

    def signaling_not_widened(self, route: list[str]) -> None:
        """A media network never admits signaling: a call whose host is the media address is refused.

        The profile copy differs from the compiled one only in target.host
        (the media address, inside the approved media range); the guided call
        must refuse it before any packet (exit 2, no run directory).
        """
        import yaml

        assert self.engagement is not None and self.shape is not None
        document = yaml.safe_load((self.engagement / "target-profile.yaml").read_text(encoding="utf-8"))
        media_address = self.shape.media[0]
        document["target"]["host"] = media_address
        path = self.engagement / "rehearsal" / "media-address-as-signaling.yaml"
        practice.write_private(path, yaml.safe_dump(document, sort_keys=False))
        relative = path.relative_to(self.project).as_posix()
        refused = self.run_result(self.command([
            *route, "call", relative, "--dial", "echo", "--username", practice.ACCOUNT,
            "--secret-file", PASSWORD_FILE, "--format", "json",
        ], timeout=120, expect=(2,)))
        errors = " ".join(str(item) for item in refused.get("blockingErrors") or [])
        self.require(refused.get("state") == "blocked" and refused.get("runDirectory") is None
                     and refused.get("networkActivity") == "none"
                     and "literal approved_addresses" in errors,
                     f"a call signalling to the media address {media_address} was not refused: {refused}")
        self.fact(f"signaling to the media address {media_address} (inside the media range) refused before any "
                  f"packet: {errors}")

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
        self.campaign_media(runs[0], result)
        self.cockpit("checks")

    def campaign_media(self, run: Path, result: dict[str, Any]) -> None:
        """The campaign capture holds the calls' RTP both ways, and the watchdog counted it.

        Read from the run's own files: the capture (with the same media rule
        the watchdog and payload stripping use), result.json's watchdog
        counts, and each call step's recorded media peer and the
        authorization that admitted it.
        """
        from .capture_scope import media_flows

        assert self.shape is not None
        plan = json.loads((run / "plan.json").read_text(encoding="utf-8"))
        authorization = plan["authorization"]
        records, flows = media_flows((run / "capture.pcap").read_bytes(), authorization["mediaPorts"],
                                     authorization["signalingPorts"])
        media = set(self.shape.media)
        to_media = sum(count for (source, destination), count in flows.items()
                       if destination in media and source not in media)
        from_media = sum(count for (source, destination), count in flows.items()
                         if source in media and destination not in media)
        watchdog = (result.get("capture") or {}).get("watchdog") or {}
        counted = sum(flows.values())
        self.require(to_media > 50 and from_media > 50,
                     f"the campaign capture holds {to_media} RTP packets to and {from_media} from the media "
                     f"address {', '.join(sorted(media))} (expected more than 50 each way)")
        self.require(watchdog.get("packets") == records and watchdog.get("mediaPackets") == counted,
                     f"the capture watchdog counted {watchdog} but the capture holds {records} packets, "
                     f"{counted} of them media")
        scopes = []
        for line in (run / "events.jsonl").read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            if event.get("event") != "step.output" or event.get("stream") != "stdout":
                continue
            try:
                value = json.loads(event.get("text") or "")
            except ValueError:
                continue
            if isinstance(value, dict) and value.get("runner") == "campaign-softphone-runner":
                scopes.append(value.get("mediaScope") or {})
        expected = "mediaNetworks" if self.shape.kind == "proxy" else "destination"
        self.require(len(scopes) == 2 and all(
            str(item.get("peer") or "").rsplit(":", 1)[0] in media and item.get("inScope") is True
            and item.get("authorization") == expected for item in scopes),
            f"the campaign call steps do not record media peers admitted by {expected}: {scopes}")
        if self.shape.kind == "proxy":
            self.require(authorization.get("mediaNetworks") and not any(
                address in authorization["networks"] for address in (f"{item}/32" for item in media)),
                f"the plan does not keep the media address media-only: {authorization}")
        self.fact(f"campaign capture: {to_media} RTP packets to and {from_media} from the media address "
                  f"{', '.join(sorted(media))}; the watchdog counted all {records} packets ({counted} media); "
                  "each call's media peer admitted by "
                  + ("authorization.mediaNetworks (media only)" if expected == "mediaNetworks"
                     else "the step's own destination address"))

    def checks(self) -> None:
        model = self.cockpit("checks")
        self.command(list(find_action(model, "checks-plan")["argv"]))
        action = find_action(model, "checks-run")
        result = self.run_result(self.command(
            [*action["argv"], "--secret-file", PASSWORD_FILE, "--format", "json"], timeout=300, expect=(0, 1)))
        statuses = {row["id"]: row["status"] for row in (result.get("findings") or {}).get("checks", [])}
        self.require(result.get("state") == "completed", f"checks state {result.get('state')!r}")
        self.require(all(statuses.get(item) in {"passed", "finding"} for item in CHECKS),
                     f"an approved check did not run to an outcome: {statuses}")
        found = sorted(item["id"] for item in (result.get("findings") or {}).get("findings", []))
        self.check_findings = found
        if self.proxy:
            rows = {row["id"]: row for row in (result.get("findings") or {}).get("checks", [])}
            text = json.dumps(rows.get("unauthenticated-invite") or {})
            self.require("407" in text, f"unauthenticated-invite did not see the proxy's 407: {text[:300]}")
        bound = checks_section()["max_requests"]
        sent = result.get("requestsSent")
        self.require(isinstance(sent, int) and sent <= bound, f"checks sent {sent!r} requests, bound {bound}")
        self.fact(f"{sent} requests (bound {bound}); findings: {', '.join(found) or 'none'}")
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
        reported = sorted(item["id"] for item in report.get("findings", []) if item.get("checkId"))
        self.require(sorted(self.check_findings) == reported,
                     f"the owner report's check findings {reported} differ from the checks run's {self.check_findings}")
        srtp = [item for item in reported if item.startswith("srtp-policy.")]
        self.require(srtp == [item for item in self.check_findings if item.startswith("srtp-policy.")],
                     "the srtp-policy findings are not in the owner report")
        self.fact(f"srtp-policy findings in the owner report: {', '.join(srtp) or 'none (the check passed)'}")
        leaked = files_containing(self.engagement, self.secret)
        self.require(not leaked, f"the practice password appears in {leaked}")
        self.fact(f"report/engagement-report.html: {sum(kinds.values())} runs, "
                  f"{sum((report.get('findingCounts') or {}).values())} findings, 0 integrity exceptions; "
                  "the password appears in no file of the engagement")
        self.cockpit(None)

    def safety_stop(self) -> None:
        """The stop leg: the owner forgot the media address; the call must stop itself.

        It runs in a throwaway sibling engagement (``DIR-stop``) so the main
        engagement's owner report stays clean, through the same public
        commands: scope answers that approve only the proxy (media answered as
        the signaling address), scope check and compile, rehearse, the
        cockpit's guided call, its journal entry and manifest, and the owner
        report of that engagement.
        """
        assert self.engagement is not None and self.secret is not None
        main = self.engagement
        stop_shape = shape_for(self.facts, proxy=True, media_approved=False, media_cidr=self.media_cidr)
        self.engagement = main.parent / f"{main.name}-stop"
        try:
            self.command([LAUNCHER, "journal", "init", self.eng, "--title",
                          "Dress rehearsal stop leg (media address not approved)", "--owner", "Practice target"])
            self.command([LAUNCHER, "scope", "init", self.eng, "--name", SCOPE_NAME])
            self.write_answers(stop_shape, checks=())
            self.compile_scope(stop_shape)
            self.rehearse_only()
            model = self.cockpit("practice")
            action = find_action(model, "call")
            argv = [*action["argv"], "--secret-file", PASSWORD_FILE, "--format", "json"]
            result = self.run_result(self.command(argv, timeout=180, expect=(1,)))
            softphone = result.get("softphone") if isinstance(result.get("softphone"), dict) else {}
            peer = str(softphone.get("media_peer") or "")
            media = self.facts["address"]
            self.require(result.get("verdict") == "media-outside-scope",
                         f"expected verdict media-outside-scope, got {result.get('verdict')!r}")
            self.require(peer.split(":")[0] == media, f"the stopped media peer is {peer!r}, not {media}")
            if stop_shape.media_answer is not None:
                record = result.get("mediaScope") if isinstance(result.get("mediaScope"), dict) else {}
                self.require(record.get("admittedBy") is None and record.get("inScope") is False,
                             f"the stopped call's media scope record does not show the refusal: {record}")
                self.fact(f"media peer {media} is just outside the approved range "
                          f"{', '.join(stop_shape.media_answer)}: refused, recorded admittedBy null")
            self.journal_call(result)
            model = self.cockpit("first-call")
            self.require_stop_presented(model)
            for _ in range(4):
                model = self._model()
                pending = [item for item in model.get("actions", [])
                           if item.get("available") and str(item.get("id", "")).startswith("manifest-")]
                if not pending:
                    break
                self.command(list(pending[0]["argv"]))
            model = self._model()
            # summary exits 1 when the report has integrity exceptions; here
            # exactly one is required (the packets sent before the stop).
            self.command([*find_action(model, "summary")["argv"], "--forbid-file", PASSWORD_FILE], expect=(1,))
            report = json.loads((self.engagement / "report" / "report.json").read_text(encoding="utf-8"))
            sent = self.stop_report(report)
            leaked = files_containing(self.engagement, self.secret)
            self.require(not leaked, f"the practice password appears in {leaked}")
            self.fact(f"verdict media-outside-scope (exit 1): media peer {peer} not approved; "
                      f"{sent} RTP packets sent there (at most {STOP_MAX_PACKETS})")
            self.cockpit("first-call")
            self.fact("cockpit: [stop] safety stop, not a target failure; owner report: one informational "
                      "safety-stop observation and the packets disclosed as the one integrity exception")
            self.fact(f"evidence: {self.eng} (the main engagement's report is untouched)")
        finally:
            self.stop_engagement = self.engagement
            self.engagement = main

    def rehearse_only(self) -> None:
        result = self.command([LAUNCHER, "rehearse", f"{self.eng}/target-profile.yaml"])
        self.require("Ready: yes" in result.stdout, "rehearse did not report Ready: yes")
        self.go_no_go()

    def require_stop_presented(self, model: dict[str, Any]) -> None:
        """The cockpit must call the stopped call a safety stop, not a target failure."""
        runs = [run for run in model.get("runs", []) if run.get("kind") == "call"]
        self.require(len(runs) == 1, f"the cockpit lists {len(runs)} guided calls, expected 1")
        run = runs[0]
        self.require(run.get("verdict") == "media-outside-scope" and run.get("safetyStop") is True,
                     f"the cockpit does not mark the call as a safety stop: {json.dumps(run)[:300]}")
        self.require(str(run.get("reason") or "").startswith("safety stop, not a target failure"),
                     f"the cockpit's reason for the stop is {run.get('reason')!r}")

    def stop_report(self, report: dict[str, Any]) -> int:
        """Check how the owner report presents the stop; return the RTP packets sent.

        The few RTP packets sent before the stop did reach an address the
        scope does not approve, so the report must disclose them as an
        integrity exception (exactly that one); the stop itself is an
        informational observation, never a target finding, and the oracle
        failures it causes are not reported as a target observation.
        """
        calls = [run for run in report.get("runs", []) if run.get("kind") == "call"]
        self.require(len(calls) == 1, f"the stop report lists {len(calls)} calls, expected 1")
        run = calls[0]
        media = ((run.get("details") or {}).get("media") or {})
        sent = media.get("toPeerPackets")
        self.require(isinstance(sent, int) and sent <= STOP_MAX_PACKETS,
                     f"{sent!r} RTP packets were sent to the unapproved media address (at most {STOP_MAX_PACKETS})")
        self.require(media.get("peerApproved") is False, f"the report does not mark the media peer unapproved: {media}")
        exceptions = report.get("integrityExceptions") or []
        self.require([item.get("code") for item in exceptions] == ["media-peer-not-approved"],
                     f"expected exactly the media-peer-not-approved integrity exception, got {exceptions}")
        self.require(f"after {sent} RTP packet" in str(exceptions[0].get("detail")),
                     f"the integrity exception does not say how many packets reached the peer: {exceptions[0]}")
        findings = {item["id"]: item for item in report.get("findings", [])}
        stop = findings.get("obs-media-outside-scope") or {}
        self.require(stop.get("severity") == "info" and "safety stop" in str(stop.get("title", "")).lower(),
                     f"the report does not present the stop as an informational safety stop: {stop}")
        self.require(set(findings) == {"obs-media-outside-scope"},
                     f"the stop produced other observations or findings: {sorted(findings)}")
        rows = " ".join(str(row.get("title")) for row in (report.get("executiveSummary") or {}).get("rows", []))
        self.require("safety stop" in rows and "did not pass" not in rows,
                     f"the executive summary does not call the run a safety stop: {rows}")
        return sent

    # -- driver -----------------------------------------------------------
    def teardown(self) -> None:
        if self.started_target:
            self.current = Stage(0, "teardown")
            self.command([LAUNCHER, "practice-target", "down"], expect=None)
            self.current = None
            self.say("Practice target taken down again (it was down when the rehearsal started).")

    def execute(self) -> int:
        started = time.monotonic()
        shape = ("the proxy shape (signaling to the practice proxy, media from the practice address)"
                 if self.proxy else "the practice target directly")
        if self.media_cidr:
            shape += " with media answered as a range"
        self.say(f"Dress rehearsal: the owner-facing chain against {shape} "
                 "(loopback inside the practice namespace only).")
        bodies = (
            self.target_up, self.create_engagement, self.practice_call, self.scope, self.rehearse,
            self.preflight, self.calls, self.campaign, self.checks, self.evidence, self.summary,
            self.safety_stop,
        )
        try:
            for title, body in zip(stage_titles(self.proxy, self.media_cidr), bodies, strict=True):
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
            "shape": "proxy" if self.proxy else "direct",
            "mediaAnswer": "range" if self.media_cidr else "addresses",
            "stopEngagement": (self.stop_engagement.relative_to(self.project).as_posix()
                               if self.stop_engagement else None),
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
        label = ("Dress rehearsal (proxy shape, media range)" if self.media_cidr
                 else "Dress rehearsal (proxy shape)" if self.proxy else "Dress rehearsal")
        self.say(f"{label}: {verdict} in {elapsed} s "
                 f"({sum(1 for s in self.stages if s.status == 'PASS')}/{len(self.stages)} stages)")
        if self.engagement is not None:
            self.say(f"Evidence: {self.eng} (commands.log and summary.json in rehearsal/; "
                     f"owner report in report/)")
            self.say(f"Cockpit:  {LAUNCHER} go {self.eng}")
        if self.stop_engagement is not None and self.stop_engagement.is_dir():
            self.say(f"Stop leg: {self.stop_engagement.relative_to(self.project).as_posix()} "
                     "(throwaway engagement; its own owner report shows the safety stop)")
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
    parser.add_argument(
        "--proxy", action="store_true",
        help="describe the proxy shape in the scope answers: signaling to the practice proxy (407 challenges, "
             "Record-Route, realm and certificate name sippycup-proxy), media from the practice address",
    )
    parser.add_argument(
        "--media-cidr", action="store_true",
        help="the proxy shape with media answered as a range (127.0.0.2/31, a media-only network in the "
             "profile); the stop leg answers the adjacent range just outside the media address",
    )
    parser.add_argument("--project-dir", required=True, help=argparse.SUPPRESS)
    arguments = parser.parse_args(argv)
    project = Path(arguments.project_dir).resolve()
    proxy = arguments.proxy or arguments.media_cidr
    if arguments.list:
        for number, title in enumerate(stage_titles(proxy, arguments.media_cidr), 1):
            print(f"{number:>2}. {title}")
        print("Network activity: none")
        return 0
    return Rehearsal(project, proxy=proxy, media_cidr=arguments.media_cidr).execute()


STAGE_TITLES = (
    "practice target up and verified",
    "new engagement: journal init, scope init",
    "practice call from the cockpit (stage 2)",
    "scope answers: scope check, scope compile",
    "rehearse the compiled profile and the go/no-go check (no traffic)",
    "preflight: UDP and verified TLS",
    "guided call (pass) and a DTMF call",
    "campaign plan and run",
    "security checks plan and run",
    "evidence: manifests and journal entries",
    "owner report: summary --forbid-file",
    "safety stop: media address not approved (throwaway engagement)",
)


def stage_titles(proxy: bool, media_cidr: bool = False) -> tuple[str, ...]:
    if not proxy and not media_cidr:
        return STAGE_TITLES
    titles = list(STAGE_TITLES)
    titles[3] = "scope answers (proxy shape): scope check, scope compile"
    titles[5] = "preflight to the proxy: UDP and verified TLS"
    if media_cidr:
        titles[3] = "scope answers (proxy shape, media as a range): scope check, scope compile"
        titles[6] = "guided call (media admitted by the range), DTMF call, signaling to the media address refused"
        titles[11] = "safety stop: media address just outside the approved range (throwaway engagement)"
    return tuple(titles)


if __name__ == "__main__":
    raise SystemExit(main())
