"""Routed rehearsal: the owner-facing chain across the toolbox's real network path.

Every dress rehearsal joins the practice target's network namespace
(``--practice``), so signaling, media and capture are loopback. On the
engagement the toolbox sends from its own private (pasta) network namespace,
captures on a real interface, and reaches the target through NAT. This
rehearsal exercises exactly that path while nothing leaves this host:

  target      the practice image on a rootless ``--internal`` network (no
              route to any host), with its SIP and RTP ports published on
              host loopback (127.0.0.1) only, and Asterisk advertising
              ROUTED_ADDRESS in Contact and SDP;
  toolbox     every command exactly as FIRST-ENGAGEMENT.md gives it for a
              real target (no ``--practice``). The launcher sees
              SIPPYCUP_ROUTED_PRACTICE, checks that container (running,
              labelled, internal network only) and gives every networked
              container the normal private network plus one pasta mapping:
              ROUTED_ADDRESS -> host loopback. Nothing runs on the host
              network, so the link-local address never reaches a real
              interface;
  scope       ROUTED_ADDRESS (169.254.77.2) is written into scope.yaml the way
              an owner's address is; the approval id is ROUTED-REHEARSAL, not
              a practice approval, so the owner report treats the runs like
              a real engagement's.

The path between the two is a real NAT: the toolbox's SDP and Via carry its
own address (pasta copies the host's), the target sees the rootless port
forwarder's address and a rewritten source port, and media returns only
because the target sends symmetric RTP. The stages are those of the dress
rehearsal (``practice_rehearsal``), minus the practice call (a real
engagement has no practice profile), plus checks of the wire, the evidence
lint, the owner report's wording, the overlap guard and an emergency stop
during a call. The stop leg answers media at another address than the
signaling address, so the call must stop media-outside-scope at the
signaling address (finding 3).

Run it with ``make routed-rehearsal`` or ``python3 tools/routed_rehearsal.py``.
"""

from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from . import practice
from .practice_rehearsal import (
    CHECKS,
    CREDENTIAL_REF,
    DTMF_DIGITS,
    LAUNCHER,
    SCOPE_NAME,
    CannotStart,
    Rehearsal,
    RehearsalError,
    Shape,
    checks_section,
)

ROUTED_ADDRESS = "169.254.77.2"
# The stop leg's media answer: an address the target never uses. Loopback
# inside the toolbox's own namespace, so even a send there stays in the
# container; a second link-local address is refused (sippycup.link_local).
STOP_MEDIA_ADDRESS = "127.0.0.9"
ROUTED_APPROVAL_ID = "ROUTED-REHEARSAL"
STATE_NAME = "routed-practice"
PROFILE_LABEL = "routed-practice"
ENV_NAME = "SIPPYCUP_ROUTED_PRACTICE"
WINDOW = timedelta(hours=2)
NETWORK_TEXT = ("loopback on this host only: the toolbox's private (pasta) namespace, mapped to host "
                "loopback, and a target on an internal network")
# Host-loopback ports the target publishes (protocol, port).
PUBLISHED = (
    ("udp", 5060), ("tcp", 5060), ("tcp", 5061), ("tcp", 5071),
    *(("udp", port) for port in range(practice.RTP_PORTS["start"], practice.RTP_PORTS["end"] + 1)),
)


def container_name() -> str:
    base = os.environ.get("SIPPYCUP_PRACTICE_CONTAINER") or "sippycup-practice"
    return f"{base}-routed"


def port_problems(ports=PUBLISHED, host: str = "127.0.0.1") -> list[str]:
    """Host-loopback ports the target needs that something else holds."""
    busy = []
    for protocol, port in ports:
        kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
        with socket.socket(socket.AF_INET, kind) as probe:
            try:
                probe.bind((host, port))
            except OSError as error:
                if error.errno == errno.EADDRINUSE:
                    busy.append(f"{host}:{port}/{protocol}")
                else:
                    busy.append(f"{host}:{port}/{protocol} ({error})")
    return busy


def routed_scope(*, now: datetime, name: str, ca_file: str, source: str, media: tuple[str, ...],
                 checks: tuple[str, ...] = CHECKS) -> str:
    """The owner's answers for the routed target, as scope.yaml text."""
    start = (now - timedelta(minutes=1)).astimezone(timezone.utc).replace(microsecond=0)
    until = start + WINDOW
    stamp = lambda value: value.strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
    if checks:
        section = checks_section(checks)
        classes = "[options, call, security-checks]"
        checks_text = (f"security_checks:\n  approved: [{', '.join(section['approved'])}]\n"
                       f"  max_requests: {section['max_requests']}\n")
    else:
        classes, checks_text = "[options, call]", ""
    mistake = ""
    if media != (ROUTED_ADDRESS,):
        mistake = ("# DELIBERATE MISTAKE (the stop leg): media is answered at another address than\n"
                   "# the signaling address, which is where the target really sends media.\n")
    return f"""# Owner answers for the ROUTED practice target, written by
# `make routed-rehearsal`. {ROUTED_ADDRESS} is the link-local address the
# rehearsal maps to host loopback, where the practice target publishes its
# ports; it is written here exactly as an owner's address would be.
{mistake}schema_version: sippycup.dev/scope/v1
name: {name}
authorization:
  status: approved
  approval_id: {ROUTED_APPROVAL_ID}
  approved_by: sippycup routed rehearsal (this host only)
  valid_from: {stamp(start)}
  valid_until: {stamp(until)}
signaling:
  networks: [{ROUTED_ADDRESS}]
  ports: [{practice.SIGNALING_PORTS['udp']}, {practice.SIGNALING_PORTS['tls']}]
  transports: [udp, tls]
targets:
  - name: routed-udp
    address: {ROUTED_ADDRESS}
    transport: udp
    port: {practice.SIGNALING_PORTS['udp']}
  - name: routed-tls
    address: {ROUTED_ADDRESS}
    transport: tls
    port: {practice.SIGNALING_PORTS['tls']}
    tls_server_name: {practice.DNS_NAME}
    tls_ca_file: {ca_file}
media:
  networks: [{', '.join(media)}]
  port_range: {{start: {practice.RTP_PORTS['start']}, end: {practice.RTP_PORTS['end']}}}
  protection: [rtp, sdes-srtp]
  codecs: [PCMU, PCMA]
  dtmf: rfc4733
  symmetric_rtp: true
client:
  source_addresses: [{source}]
account:
  required: true
  username: {practice.ACCOUNT}
  realm: {practice.DNS_NAME}
  credential_ref: {CREDENTIAL_REF}
  credential_delivery: other
destinations:
  - name: echo
    target: routed-udp
    user: echo
    expect: echo
  - name: echo-tls
    target: routed-tls
    user: echo
    expect: echo
  - name: dtmf
    target: routed-udp
    user: dtmf
    expect: agent
limits:
  # 2 guided calls, the TLS call, 4 matrix cells, 2 campaign calls, the
  # checks run's 5 INVITE attempts, the overlap and stop stage's call (15),
  # with room for 3.
  calls: 18
  concurrent_calls: 2
  calls_per_second: 1
  packets_per_second: 200
  packets: 20000
  bytes: 4000000
  call_duration_seconds: 40
  total_duration_seconds: 600
stop_conditions:
  consecutive_failures: 1
  unexpected_response: true
  packet_loss_percent: 5
test_scope:
  allowed_classes: {classes}
  exclusions: [none]
contact:
  name: rehearsal operator
  channel: local terminal
  can_stop_test: true
evidence:
  retention_days: 30
  disclosure: private
{checks_text}"""


class RoutedRehearsal(Rehearsal):
    def __init__(self, project: Path, **kwargs: Any) -> None:
        super().__init__(project, **kwargs)
        self.container = container_name()
        self.network = f"{self.container}-net"
        self.password_file = f"work/{STATE_NAME}/account.password"
        self.route = ()
        self.network_text = NETWORK_TEXT
        self.expected_calls = 2
        self.expected_practice_runs = 0
        self.program = "routed rehearsal"
        self.label = "Routed rehearsal"
        self.ca_name = "routed-ca.crt"
        self.approval_id = ROUTED_APPROVAL_ID
        self.created_network = False
        self.source = ""
        self.call_runs: list[str] = []

    # -- plumbing -------------------------------------------------------
    def state_root(self) -> Path:
        return self.project / "work" / STATE_NAME

    def runtime(self) -> str:
        completed = subprocess.run([str(self.project / "bin" / "container-runtime")], text=True,
                                   capture_output=True, check=False)
        runtime = completed.stdout.strip()
        if completed.returncode != 0 or not runtime:
            raise CannotStart("no container runtime (podman or docker) was found")
        return runtime

    def podman(self, *argv: str, check: bool = True, timeout: float = 120) -> subprocess.CompletedProcess:
        completed = subprocess.run([self.runtime(), *argv], text=True, capture_output=True,
                                   timeout=timeout, check=False)
        if check and completed.returncode != 0:
            raise RehearsalError(f"{shlex.join(argv[:3])} failed: {completed.stderr.strip()[-300:]}")
        return completed

    def plan(self) -> list[tuple[str, Callable[[], None]]]:
        return [
            ("routed target up: internal network, ports on host loopback only", self.target_up),
            ("new engagement: journal init, scope init", self.create_engagement),
            ("scope answers for the routed address: scope check, scope compile", self.scope),
            ("rehearse the compiled profile and the go/no-go check (no traffic)", self.rehearse),
            ("preflight without --practice: UDP and verified TLS", self.preflight),
            ("guided call (pass) and a DTMF call, across NAT", self.calls),
            ("TLS and SRTP call, then a 2x2 call matrix", self.tls_and_matrix),
            ("campaign plan and run (the documented command, no --isolated)", self.campaign),
            ("security checks plan and run", self.checks),
            ("wire: every packet to or from the approved address, our own NAT'd address recorded",
             self.wire),
            ("overlap refused, then an emergency stop during a call", self.overlap_and_stop),
            ("evidence: manifests and journal entries", self.evidence),
            ("owner report: summary --forbid-file, no loopback wording", self.summary),
            ("safety stop: media answered elsewhere, SDP names the signaling address", self.safety_stop),
        ]

    def announce(self) -> None:
        self.say("Routed rehearsal: the owner-facing chain across the toolbox's own network path "
                 f"(private namespace, NAT, real capture interface) to {ROUTED_ADDRESS}, "
                 "the routed practice target; nothing leaves this host.")

    # -- stages ---------------------------------------------------------
    def target_up(self) -> None:
        image = os.environ.get("SIPPYCUP_PRACTICE_IMAGE") or "localhost/sippycup-practice:latest"
        if self.podman("image", "inspect", image, check=False).returncode != 0:
            raise CannotStart(f"the practice image {image} is not installed; run ./bin/sippycup practice-target build")
        if self.podman("container", "inspect", self.container, check=False).returncode == 0:
            raise CannotStart(f"container {self.container} already exists (an earlier routed rehearsal?); "
                              f"remove it with: podman rm -f {self.container}")
        busy = port_problems()
        if busy:
            raise CannotStart("these host-loopback ports are in use, so the routed target cannot publish "
                              f"there: {', '.join(busy[:6])}")
        state = self.state_root()
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(state, 0o700)
        import secrets as _secrets

        practice.write_private(state / "account.password", _secrets.token_urlsafe(24) + "\n")
        for name in ("ca.crt", "server.crt", "proxy.crt"):
            (state / name).unlink(missing_ok=True)
        if self.podman("network", "exists", self.network, check=False).returncode != 0:
            self.podman("network", "create", "--internal", "--label", f"dev.sippycup.profile={PROFILE_LABEL}",
                        self.network)
            self.created_network = True
        internal = self.podman("network", "inspect", "--format", "{{.Internal}}", self.network).stdout.strip()
        self.require(internal == "true", f"network {self.network} is not internal")
        publish = [f"--publish=127.0.0.1:{port}:{port}/{protocol}" for protocol, port in PUBLISHED]
        self.podman(
            "run", "--detach", "--name", self.container,
            "--label", f"dev.sippycup.profile={PROFILE_LABEL}",
            "--label", f"dev.sippycup.routed-address={ROUTED_ADDRESS}",
            f"--network={self.network}", "--hostname=sippycup-practice",
            "--cap-drop=ALL", "--security-opt=no-new-privileges=true", "--read-only",
            "--tmpfs=/run:rw,nosuid,nodev,size=32m", "--pids-limit=256", "--memory=512m",
            f"--env=SIPPYCUP_PRACTICE_ROUTED_ADDRESS={ROUTED_ADDRESS}",
            *publish, f"--volume={state}:/practice:z", image,
        )
        self.started_target = True
        for _ in range(60):
            booted = self.podman("exec", self.container, "asterisk", "-C", "/run/sippycup-practice/etc/asterisk.conf",
                                 "-rx", "core waitfullybooted", check=False)
            if booted.returncode == 0 and (state / "ca.crt").is_file():
                break
            running = self.podman("container", "inspect", "--format", "{{.State.Running}}", self.container,
                                  check=False).stdout.strip()
            if running != "true":
                logs = self.podman("logs", self.container, check=False)
                raise RehearsalError(f"the routed target stopped: {(logs.stdout + logs.stderr).strip()[-400:]}")
            time.sleep(0.5)
        else:
            raise RehearsalError("the routed target did not become ready in 30 s")
        routes = self.podman("exec", self.container, "cat", "/proc/net/route").stdout.splitlines()[1:]
        self.require(not any(line.split()[1] == "00000000" for line in routes if len(line.split()) > 1),
                     "the routed target has a default route")
        os.environ[ENV_NAME] = self.container
        self.facts = {"address": ROUTED_ADDRESS}
        self.shape = Shape("direct", ROUTED_ADDRESS, (ROUTED_ADDRESS,), practice.DNS_NAME, practice.DNS_NAME,
                           "routed")
        self.secret = self.password().encode("utf-8")
        self.fact(f"target {self.container} on internal network {self.network} (no default route); "
                  f"SIP 5060 udp/tcp, TLS 5061/5071, RTP {practice.RTP_PORTS['start']}-{practice.RTP_PORTS['end']} "
                  "published on 127.0.0.1 only")
        self.fact(f"toolbox containers map {ROUTED_ADDRESS} to host loopback ({ENV_NAME}={self.container})")

    def create_engagement(self) -> None:
        stamp = self.now().strftime("%Y%m%dt%H%M%Sz")
        parent = self.state_root() / "rehearsals"
        parent.mkdir(mode=0o700, exist_ok=True)
        self.engagement = parent / f"routed-{stamp}-{os.getpid()}"
        self.log = None
        self.command([LAUNCHER, "journal", "init", self.eng, "--title", "Routed rehearsal (this host only)",
                      "--owner", "Routed practice target"])
        (self.engagement / "rehearsal").mkdir(mode=0o700)
        self.log = self.engagement / "rehearsal" / "commands.log"
        self.command([LAUNCHER, "scope", "init", self.eng, "--name", SCOPE_NAME])
        self.require((self.engagement / "scope.yaml").is_file(), "scope init wrote no scope.yaml")
        # A real engagement has no practice call of its own (the operator
        # practised elsewhere): the cockpit recommends the practice stage
        # until the operator skips it, which is what this records (the same
        # preference the cockpit's skip toggle writes).
        self.cockpit("practice")
        from sippycup_cockpit.model import save_preferences

        save_preferences(self.engagement, {"skipPractice": True})
        self.fact("cockpit: practice stage recommended, then skipped as an operator would (no practice call "
                  "in a real engagement)")
        self.cockpit("scope")

    def own_source(self) -> str:
        """The toolbox's source address as a private container sees it (route lookup only)."""
        probe = self.command([LAUNCHER, "--isolated", "doctor", "--ready-probe", "--route-to", ROUTED_ADDRESS,
                              "--route-port", str(practice.SIGNALING_PORTS["udp"])], quiet=True)
        try:
            facts = json.loads(probe.stdout.strip().splitlines()[-1])
            source = str((facts.get("route") or {}).get("source") or "")
            ipaddress.ip_address(source)
        except (ValueError, IndexError, AttributeError) as error:
            raise RehearsalError(f"the private container's route lookup gave no source: {probe.stdout[-300:]}") from error
        return source

    def write_answers(self, shape: Shape | None, *, checks: tuple[str, ...] = CHECKS) -> None:
        assert self.engagement is not None and shape is not None
        ca = self.engagement / "routed-ca.crt"
        ca.write_bytes((self.state_root() / "ca.crt").read_bytes())
        ca.chmod(0o600)
        if not self.source:
            self.source = self.own_source()
        answers = routed_scope(now=self.now(), name=SCOPE_NAME, ca_file=f"{self.eng}/routed-ca.crt",
                               source=self.source, media=shape.answered_media, checks=checks)
        practice.write_private(self.engagement / "scope.yaml", answers)
        self.say(f"    (answers written to {self.eng}/scope.yaml: signaling {shape.signaling}, media "
                 f"{', '.join(shape.answered_media)}, our source {self.source} as a private container sees it)")

    def scope(self) -> None:
        self.write_answers(self.shape)
        self.compile_scope()
        self.cockpit("rehearse")

    def preflight(self) -> None:
        super().preflight()
        self.require(not any("--practice" in line for line in self.current.commands),
                     "a routed command used --practice")

    def calls(self) -> None:
        super().calls()
        for line in self.current.commands:
            self.require("--practice" not in line, f"a routed command used --practice: {line}")

    def call_json(self, argv: list[str], *, expect: tuple[int, ...] = (0,), timeout: float = 180) -> dict[str, Any]:
        return self.run_result(self.command([*argv, "--secret-file", self.password_file, "--format", "json"],
                                            timeout=timeout, expect=expect))

    def tls_and_matrix(self) -> None:
        result = self.call_json([LAUNCHER, "call", f"{self.eng}/target-profile-routed-tls.yaml", "--dial", "echo",
                                 "--srtp", "mandatory", "--duration", "6", "--username", practice.ACCOUNT])
        self.require(result.get("verdict") == "pass", f"TLS+SRTP call verdict {result.get('verdict')!r}")
        srtp = result.get("srtp") if isinstance(result.get("srtp"), dict) else {}
        self.require(srtp.get("active") is True or "active" in json.dumps(srtp),
                     f"SRTP was not active on the TLS call: {json.dumps(srtp)[:200]}")
        self.shape_seen(result)
        self.fact(f"TLS+SRTP call: pass, SRTP active; run {result.get('runDirectory')}")
        self.journal_call(result)
        matrix = self.command([
            LAUNCHER, "matrix", "run", f"{self.eng}/target-profile.yaml", f"{self.eng}/target-profile-routed-tls.yaml",
            "--dial", "echo", "--codecs", "PCMU", "--srtp", "off,mandatory", "--max-calls", "4",
            "--duration", "3", "--username", practice.ACCOUNT, "--secret-file", self.password_file,
        ], timeout=600)
        self.require("Call matrix: COMPLETED - 4 of 4 call(s) placed, 4 passed" in matrix.stdout,
                     f"the matrix did not pass every cell: {matrix.stdout.strip()[-500:]}")
        for line in matrix.stdout.splitlines():
            if line.startswith("Record it: "):
                self.command(shlex.split(line.removeprefix("Record it: ")))
        self.fact("matrix: 4 of 4 cells passed (udp and tls, SRTP off and mandatory)")
        self.expected_calls += 5

    def wire(self) -> None:
        """Every captured packet has the approved address on one side; our NAT'd source is recorded."""
        from .capture_scope import ip_addresses  # noqa: F401  (import check)

        assert self.engagement is not None
        runs = sorted((self.engagement / "calls").glob("*/capture.pcap")) + sorted(
            (self.engagement / "runs").glob("*/capture.pcap"))
        self.require(bool(runs), "no captures to inspect")
        problems, translated = [], set()
        for capture in runs:
            for source, destination in pcap_pairs(capture.read_bytes()):
                if ROUTED_ADDRESS not in (source, destination):
                    problems.append(f"{capture.parent.name}: {source} -> {destination}")
            result = json.loads((capture.parent / "result.json").read_text(encoding="utf-8"))
            for item in result.get("natAddresses") or []:
                translated.add(str(item))
        self.require(not problems, "packets not to or from the approved address: " + "; ".join(problems[:5]))
        self.fact(f"{len(runs)} captures: every packet to or from {ROUTED_ADDRESS} only; the capture interface "
                  "is the private namespace's own interface, not loopback")
        self.require(bool(translated), "no run recorded the address the target saw (natAddresses)")
        self.fact(f"the target saw our source as {', '.join(sorted(translated))} (recorded as natAddresses; "
                  f"our own address is {self.source})")
        for capture in runs:
            lint = self.command([LAUNCHER, "evidence", "lint", capture.parent.relative_to(self.project).as_posix()],
                                quiet=True, expect=(0, 1))
            try:
                findings = json.loads(lint.stdout).get("findings") or []
            except ValueError as error:
                raise RehearsalError(f"evidence lint printed no JSON for {capture.parent.name}") from error
            unexpected = [item["detail"] for item in findings if item.get("code") == "unexpected-network"]
            self.require(not unexpected,
                         f"evidence lint flags our own or the target's address in {capture.parent.name}: {unexpected}")
        self.fact("evidence lint: no unexpected-network finding (own address, NAT'd address and target only)")

    def overlap_and_stop(self) -> None:
        """A second sender against the same target is refused while a call runs; stop ends the call."""
        assert self.engagement is not None
        environment = dict(os.environ)
        argv = [str(self.project / "bin" / "sippycup"), "call", f"{self.eng}/target-profile.yaml", "--dial", "echo",
                "--duration", "30", "--username", practice.ACCOUNT, "--secret-file", self.password_file,
                "--format", "json"]
        self.current.commands.append(shlex.join([LAUNCHER, *argv[1:]]) + "    # in the background")
        self.say(f"    $ {shlex.join([LAUNCHER, *argv[1:]])} &")
        before = set((self.engagement / "calls").glob("*"))
        long_call = subprocess.Popen(argv, cwd=self.project, env=environment, text=True,
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 60
            run = None
            while time.monotonic() < deadline and long_call.poll() is None:
                fresh = sorted(set((self.engagement / "calls").glob("*")) - before)
                if fresh and (fresh[0] / "softphone.log").exists() and "CONFIRMED" in (
                        fresh[0] / "softphone.log").read_text(encoding="utf-8", errors="replace"):
                    run = fresh[0]
                    break
                time.sleep(0.5)
            self.require(run is not None, "the long call did not connect within 60 s")
            second = self.command([LAUNCHER, "call", f"{self.eng}/target-profile.yaml", "--dial", "echo",
                                   "--username", practice.ACCOUNT, "--secret-file", self.password_file],
                                  expect=(2,), timeout=60)
            text = second.stdout + second.stderr
            self.require("another sending command" in text and "Nothing was sent" in text,
                         f"a second call during the first was not refused as an overlap: {text.strip()[-400:]}")
            self.fact("a second call while the first was connected: refused, nothing sent, the other run named")
            stop = self.command([LAUNCHER, "stop", "--engagement", self.eng], timeout=120, expect=(0,))
            self.require("Silence: PROVED" in stop.stdout, f"stop did not prove silence: {stop.stdout.strip()[-400:]}")
            out, _err = long_call.communicate(timeout=60)
        finally:
            if long_call.poll() is None:
                long_call.kill()
                long_call.communicate()
        result = json.loads(out) if out.strip().startswith("{") else {}
        self.require(result.get("state") == "cancelled", f"the stopped call's state is {result.get('state')!r}")
        self.fact(f"stop during the call: Silence: PROVED; the call ended cancelled; run {result.get('runDirectory')}")
        for line in stop.stdout.splitlines():
            if line.startswith("Record it: "):
                self.command(shlex.split(line.removeprefix("Record it: ")))
        self.journal_call(result)
        diagnose = self.command([LAUNCHER, "diagnose", str(result.get("runDirectory"))], expect=(0, 1))
        self.require("loopback" not in diagnose.stdout.lower(),
                     f"diagnose describes the routed run as loopback: {diagnose.stdout.strip()[-300:]}")
        self.expected_calls += 1

    def summary(self) -> None:
        super().summary()
        assert self.engagement is not None
        text = (self.engagement / "report" / "engagement-report.md").read_text(encoding="utf-8")
        # How the report describes the network and the runs. (The target's own
        # Server header, "Sippycup practice target (Asterisk)", is a true finding.)
        for phrase in ("loopback address inside", "practice namespace", "against the local practice target",
                       "practice target run"):
            self.require(phrase not in text, f"the owner report says {phrase!r} about the routed runs")
        self.fact("the owner report does not describe the network as loopback or practice")

    def stop_shape(self) -> Shape:
        return Shape("direct", ROUTED_ADDRESS, (ROUTED_ADDRESS,), practice.DNS_NAME, practice.DNS_NAME, "routed",
                     media_answer=(STOP_MEDIA_ADDRESS,))

    def require_media_networks(self, shape: Shape, compiled: str) -> None:
        """The stop leg's answer is a literal address: media goes only there, not to the signaling address."""
        import yaml

        assert self.engagement is not None
        profile = yaml.safe_load((self.engagement / "target-profile.yaml").read_text(encoding="utf-8"))
        approved = (profile.get("target") or {}).get("approved_addresses")
        media = profile.get("media") or {}
        self.require(approved == [shape.signaling, *(shape.media_answer or ())],
                     f"the profile's literal approved addresses are {approved}")
        self.require(media.get("addresses") == list(shape.media_answer or ()),
                     f"the profile's media.addresses are {media.get('addresses')}, expected only the media answer "
                     f"{list(shape.media_answer or ())} (not the signaling address)")
        self.fact(f"profile: approved_addresses {approved}; media.addresses {media.get('addresses')} (the owner's "
                  f"media answer; {shape.signaling} is approved for signaling only)")

    def safety_stop(self) -> None:
        super().safety_stop()

    def teardown(self) -> None:
        os.environ.pop(ENV_NAME, None)
        if self.started_target:
            self.podman("rm", "--force", "--time", "5", self.container, check=False)
        if self.created_network:
            self.podman("network", "rm", self.network, check=False)
        (self.state_root() / "account.password").unlink(missing_ok=True)
        if self.started_target:
            self.say(f"Routed target {self.container} and network {self.network} removed; password deleted.")


def pcap_pairs(data: bytes) -> set[tuple[str, str]]:
    """(source, destination) of every IPv4 packet in a classic PCAP."""
    import struct

    pairs: set[tuple[str, str]] = set()
    if len(data) < 24:
        return pairs
    magic = data[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    offset = 24
    while offset + 16 <= len(data):
        included = struct.unpack(endian + "I", data[offset + 8:offset + 12])[0]
        packet = data[offset + 16:offset + 16 + included]
        offset += 16 + included
        if linktype == 113:  # Linux cooked SLL
            start, proto = 16, packet[14:16]
        elif linktype == 276:  # SLL2
            start, proto = 20, packet[0:2]
        elif linktype == 1:  # Ethernet
            start, proto = 14, packet[12:14]
        elif linktype in (101, 228):
            start, proto = 0, b"\x08\x00"
        else:
            continue
        if proto != b"\x08\x00" or len(packet) < start + 20:
            continue
        header = packet[start:start + 20]
        pairs.add((str(ipaddress.ip_address(header[12:16])), str(ipaddress.ip_address(header[16:20]))))
    return pairs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="routed-rehearsal",
        description="Walk the owner-facing chain across the toolbox's own network path (private namespace, NAT, "
                    "real capture interface) to a practice target on this host, with the commands a real "
                    "target gets (no --practice). Nothing leaves this host.",
    )
    parser.add_argument("--list", action="store_true", help="print the stages; send nothing")
    parser.add_argument("--project-dir", default=str(Path(__file__).resolve().parents[2]))
    arguments = parser.parse_args(argv)
    project = Path(arguments.project_dir).resolve()
    rehearsal = RoutedRehearsal(project)
    if arguments.list:
        for number, (title, _body) in enumerate(rehearsal.plan(), 1):
            print(f"{number:>2}. {title}")
        print("Network activity: none")
        return 0
    if os.environ.get(ENV_NAME):
        print(f"routed rehearsal: {ENV_NAME} is already set; unset it first", file=sys.stderr)
        return 2
    return rehearsal.execute()


if __name__ == "__main__":
    raise SystemExit(main())
