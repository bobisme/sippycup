#!/usr/bin/env python3
"""Live gate for the practice proxy (bn-2g0): every path through Kamailio.

Opt-in (``make practice-proxy-gate``); needs the core image and a practice
image with the proxy. It reuses the practice gate's helpers and lifecycle
(starts the target only when it is not up, removes only what it started) and
runs, through the unified launcher and only inside the practice namespace:

- the proxy facts and profiles (signaling on the proxy, media on Asterisk);
- the launcher preflight over UDP, TCP, and TLS (verified as sippycup-proxy;
  a wrong name fails verification);
- raw probes: 407 on INVITE and 401 on REGISTER in the proxy's realm, 404 for
  an in-dialog request without the proxy's Route, and the trust decision
  between the proxy and Asterisk (only the per-start token from the proxy
  address skips Asterisk's challenge; a client-supplied token is stripped);
- guided calls with registration, without it, with DTMF, with a server BYE,
  and over TLS with name pinning and mandatory SRTP; the route set is
  followed (the caller sends nothing to the media address but RTP);
- the media-scope stop when only the proxy is approved, within a bounded
  number of RTP packets;
- a campaign with the softphone runner (one call ceiling: the 407 re-send is
  not a second call), whose capture holds the RTP to and from the media-only
  network both ways and whose watchdog counted every packet, the same for an
  older manifest without ``mediaNetworks``, a planner refusal of a target on
  a media-only network, and the SIPp runner's handling of a 407;
- ``checks run`` against the proxy over UDP and TLS.

Evidence is kept in ``work/practice/proxy-gate-<UTC>-<PID>/``.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tools"))

import yaml  # noqa: E402

import practice_gate  # noqa: E402
from practice_gate import LAUNCHER, GateFailure  # noqa: E402

from sippycup import practice  # noqa: E402

CALL_SECONDS = "3"
# bn-3l8o: the media-scope stop lets no RTP and no RTCP packet leave for the
# unapproved media address. (Before the media guard PJSUA got 1 RTP and 4 RTCP
# packets out: two RTCP before the ACK, two more as it hung up.)
SCOPE_STOP_MAX_PACKETS = 0
# The calls the whole gate may place under the practice approval from its own
# directory: the signaling-only call, the legacy campaign and the INVITE
# attempts of both checks runs share one count (bn-2sfn), about 8 in all.
GATE_CALL_BUDGET = 12

SIPP_MANIFEST = """\
apiVersion: sippycup.dev/v1
kind: Campaign
metadata:
  name: proxy-gate-sipp
authorization:
  networks: ['@PROXY@/32', '@ADDRESS@/32']
  signalingPorts: [5060]
  mediaPorts: {start: 20000, end: 20019}
  transports: [udp]
  credentialRefs: []
  ceilings: {calls: 1, packets: 200, bytes: 200000, durationSeconds: 30,
             concurrentCalls: 1, packetsPerSecond: 100, callsPerSecond: 1}
  stopConditions: {consecutiveFailures: 1, unexpectedResponse: true, packetLossPercent: 5}
targets:
  - name: proxy-udp
    address: '@PROXY@'
    signaling: {transport: udp, port: 5060}
cases:
  - id: call-sipp
    type: call
    target: proxy-udp
    count: 1
    budget: {packetsPerRun: 100, bytesPerRun: 100000, durationSecondsPerRun: 10}
expectations:
  allowedSipStatuses: [100, 407]
  requireBidirectionalRtp: false
evidence:
  capture: true
  retainPayload: false
  directory: evidence/proxy-gate-sipp
"""


class ProxyGate(practice_gate.Gate):
    proxy: str = practice.DEFAULT_PROXY_ADDRESS

    def ensure_target(self) -> None:
        super().ensure_target()
        assert self.gate_dir is not None
        renamed = self.gate_dir.with_name("proxy-" + self.gate_dir.name)
        self.gate_dir.rename(renamed)
        self.gate_dir = renamed
        facts = practice.load_facts(self.project)
        proxy = facts.get("proxy") or {}
        self.record(
            "connection facts name the proxy, its media address, and both approved addresses",
            proxy.get("address") not in (None, self.address)
            and proxy.get("media_address") == self.address
            and proxy.get("approved_addresses") == [proxy.get("address"), self.address]
            and (proxy.get("account") or {}).get("realm") == practice.PROXY_REALM,
            proxy or "no proxy facts (rebuild the practice image and run up again)",
        )
        self.proxy = proxy["address"]

    def guided(self, profile: str, label: str, *arguments: str) -> tuple[int, dict[str, Any]]:
        result = self.run(
            "--practice", "call", profile, *arguments,
            "--run-root", self.work_path(f"calls-{label}"), "--format", "json",
            timeout=240,
        )
        self.host_path(f"call-{label}.json").write_text(result.stdout, encoding="utf-8")
        self.host_path(f"call-{label}.stderr").write_text(result.stderr, encoding="utf-8")
        try:
            value = json.loads(result.stdout or "{}")
        except ValueError:
            value = {}
        return result.returncode, value

    def call_capture(self, value: dict[str, Any]) -> str:
        return "/" + str(Path(str(value.get("runDirectory") or "missing")) / "capture.pcap")

    def sip_rows(self, capture: str) -> list[tuple[str, str, str, str]]:
        """(source, destination, method, status) for every cleartext SIP message."""
        result = self.run(
            "--practice", "--", "tshark", "-n", "-r", capture, "-Y", "sip",
            "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "sip.Method", "-e", "sip.Status-Code",
        )
        if result.returncode != 0:
            raise GateFailure(f"tshark failed: {result.stderr.strip()[:300]}")
        rows = []
        for line in result.stdout.splitlines():
            fields = (line.split("\t") + ["", "", "", ""])[:4]
            rows.append((fields[0], fields[1], fields[2], fields[3]))
        return rows

    # -- checks ----------------------------------------------------------
    def check_profiles(self) -> None:
        for name in ("target-profile-proxy.yaml", "target-profile-proxy-tls.yaml"):
            result = self.run("rehearse", f"work/practice/{name}", "--format", "json")
            value = json.loads(result.stdout or "{}") if result.returncode == 0 else {}
            self.record(f"rehearse {name}: ready", value.get("ready") is True,
                        result.stderr.strip()[:200] or None)
            document = yaml.safe_load((practice.state_dir(self.project) / name).read_text(encoding="utf-8"))
            target = document["target"]
            self.record(
                f"{name}: signaling at the proxy, both proxy and media address approved",
                target["host"] == self.proxy and target["approved_addresses"] == [self.proxy, self.address],
                target,
            )

    def check_preflight(self) -> None:
        for port, transport, extra, expected in (
            ("5060", "udp", (), 0),
            ("5060", "tcp", (), 0),
            ("5061", "tls", ("--tls-ca", "/work/practice/ca.crt", "--tls-server-name",
                             practice.PROXY_DNS_NAME), 0),
            ("5061", "tls", ("--tls-ca", "/work/practice/ca.crt", "--tls-server-name",
                             practice.DNS_NAME), 5),
        ):
            result = self.run("--practice", "preflight", self.proxy, port, transport, *extra)
            label = f"preflight {transport} to the proxy" + (
                f" verified as {extra[3]}" if extra else ""
            )
            ok = result.returncode == expected and (
                expected != 0 or "SIP/2.0 200 OK" in result.stdout
            )
            self.record(f"{label}: exit {expected}", ok,
                        {"exit": result.returncode, "tail": result.stdout.strip()[-160:]})

    def check_probes(self) -> None:
        script = self.host_path("practice_proxy_probe.py")
        script.write_text((ROOT / "tools" / "practice_proxy_probe.py").read_text(encoding="utf-8"),
                          encoding="utf-8")
        runtime = subprocess.run([str(ROOT / "bin" / "container-runtime")], text=True,
                                 stdout=subprocess.PIPE, check=True).stdout.strip()
        container = self.env.get("SIPPYCUP_PRACTICE_CONTAINER", "sippycup-practice")
        # The trunk token is read from the target's tmpfs only to prove what
        # it grants; it is kept in a private file and removed right after.
        rendered = subprocess.run(
            [runtime, "exec", container, "grep", "-h", "^match_header = X-Sippycup-Trunk: ",
             "/run/sippycup-practice/etc/pjsip.conf"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        ).stdout.strip()
        token = rendered.rsplit(" ", 1)[-1] if rendered else ""
        self.record("the trunk token was generated at start (48 hex digits)",
                    len(token) == 48 and all(c in "0123456789abcdef" for c in token))
        token_file = self.host_path("trunk-token")
        practice.write_private(token_file, token + "\n")
        try:
            result = self.run(
                "--practice", "--", "python3", self.container_path("practice_proxy_probe.py"),
                self.proxy, self.address, "/work/practice/account.password",
                self.container_path("trunk-token"), timeout=90,
            )
        finally:
            token_file.unlink(missing_ok=True)
        self.host_path("probes.json").write_text(result.stdout, encoding="utf-8")
        try:
            probes = json.loads(result.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise GateFailure(f"probe failed: {result.stderr.strip()[-300:]}") from None
        self.record("probe output carries neither the password nor the token",
                    self.password() not in result.stdout and token not in result.stdout)
        expectations = (
            ("proxy_invite_unauthenticated",
             "INVITE to the proxy is challenged with 407 in realm sippycup-proxy (qop auth)",
             lambda v: v.get("status") == 407 and v.get("challengeRealm") == practice.PROXY_REALM
             and v.get("challengeQop") == "auth"),
            ("proxy_register_unauthenticated",
             "REGISTER to the proxy is challenged with 401 in realm sippycup-proxy",
             lambda v: v.get("status") == 401 and v.get("challengeRealm") == practice.PROXY_REALM),
            ("proxy_bye_without_route",
             "an in-dialog BYE without the proxy's Route is refused with 404",
             lambda v: v.get("status") == 404),
            ("proxy_invite_client_token",
             "a client-supplied trunk token is stripped: after 407 the call reaches busy (486)",
             lambda v: v.get("status") == 407 and v.get("authenticatedStatus") == 486),
            ("asterisk_forged_token_from_caller",
             "direct path unchanged: a forged token from the caller gets Asterisk's 401",
             lambda v: v.get("status") == 401 and v.get("challengeRealm") == practice.DNS_NAME),
            ("asterisk_no_token_from_proxy_address",
             "the proxy address alone grants nothing: no token from 127.0.0.3 gets 401",
             lambda v: v.get("status") == 401),
            ("asterisk_forged_token_from_proxy_address",
             "a forged token from the proxy address gets 401",
             lambda v: v.get("status") == 401),
            ("asterisk_real_token_from_caller",
             "the real token from any other source is refused by the endpoint ACL (401)",
             lambda v: v.get("status") == 401),
            ("asterisk_real_token_from_proxy_address",
             "control: the real token from the proxy address skips the challenge (486 from busy)",
             lambda v: v.get("status") == 486),
        )
        for key, label, predicate in expectations:
            value = probes.get(key) or {}
            self.record(label, predicate(value), value)

    def check_call(self) -> None:
        status, value = self.guided(
            "work/practice/target-profile-proxy.yaml", "register",
            "--dial", "echo", "--duration", CALL_SECONDS,
            "--username", "practice", "--secret-file", "work/practice/account.password",
        )
        oracle = value.get("oracle") or {}
        self.record(
            "guided call through the proxy with registration: pass, oracle pass on one dialog",
            status == 0 and value.get("verdict") == "pass" and oracle.get("verdict") == "pass"
            and oracle.get("dialogs") == 1,
            {"exit": status, "verdict": value.get("verdict"), "oracle": oracle.get("summary"),
             "dialogs": oracle.get("dialogs")},
        )
        rows = self.sip_rows(self.call_capture(value))
        caller = practice.CALLER_ADDRESS
        sent = [row for row in rows if row[0] == caller and row[2]]
        invites = [row for row in sent if row[2] == "INVITE"]
        statuses = [row[3] for row in rows if row[1] == caller and row[3]]
        self.record(
            "the caller answered a 407 (two INVITEs to the proxy, 401 for REGISTER, 407 for INVITE)",
            len(invites) == 2 and "407" in statuses and "401" in statuses,
            {"invites": len(invites), "statuses": statuses},
        )
        self.record(
            "the route set is followed: every caller request (ACK, BYE, in-dialog) goes to the proxy",
            bool(sent) and all(row[1] == self.proxy for row in sent)
            and {"ACK", "BYE"} <= {row[2] for row in sent},
            sorted({(row[1], row[2]) for row in sent}),
        )
        media = self.tshark_count(
            self.call_capture(value),
            f"ip.src == {caller} && ip.dst == {self.address} && udp.dstport >= 20000 && udp.dstport <= 20019",
        )
        back = self.tshark_count(
            self.call_capture(value),
            f"ip.src == {self.address} && ip.dst == {caller} && udp.srcport >= 20000 && udp.srcport <= 20019",
        )
        self.record("media flows between the caller and the media address, not the proxy",
                    media > 50 and back > 50, {"to_media": media, "from_media": back})

    def check_no_register(self) -> None:
        status, value = self.guided(
            "work/practice/target-profile-proxy.yaml", "noregister",
            "--dial", "echo", "--duration", CALL_SECONDS, "--no-register",
            "--username", "practice", "--secret-file", "work/practice/account.password",
        )
        rows = self.sip_rows(self.call_capture(value))
        self.record(
            "--no-register through the proxy: pass, no REGISTER on the wire",
            status == 0 and value.get("verdict") == "pass"
            and not any(row[2] == "REGISTER" for row in rows),
            {"exit": status, "verdict": value.get("verdict")},
        )

    def check_dtmf(self) -> None:
        status, value = self.guided(
            "work/practice/target-profile-proxy.yaml", "dtmf",
            "--dial", "dtmf", "--dtmf", "159#", "--duration", "8",
            "--username", "practice", "--secret-file", "work/practice/account.password",
        )
        dtmf = value.get("dtmf") or {}
        self.record(
            "DTMF through the proxy: pass, 159# sent and echoed",
            status == 0 and value.get("verdict") == "pass"
            and dtmf.get("status") == "sent" and dtmf.get("sent") == "159#"
            and dtmf.get("echoed") == "159#",
            {"exit": status, "verdict": value.get("verdict"), "dtmf": dtmf},
        )

    def check_server_bye(self) -> None:
        status, value = self.guided(
            "work/practice/target-profile-proxy.yaml", "drop",
            "--dial", "drop", "--duration", "8",
            "--username", "practice", "--secret-file", "work/practice/account.password",
        )
        rows = self.sip_rows(self.call_capture(value))
        byes = [row for row in rows if row[2] == "BYE"]
        self.record(
            "server hang-up through the proxy: peer-hung-up-early, BYE arrives from the proxy",
            status == 1 and value.get("verdict") == "peer-hung-up-early"
            and byes and all(row[0] == self.proxy for row in byes),
            {"exit": status, "verdict": value.get("verdict"), "byes": byes},
        )

    def check_tls(self) -> None:
        status, value = self.guided(
            "work/practice/target-profile-proxy-tls.yaml", "tls",
            "--dial", "echo", "--duration", CALL_SECONDS, "--srtp", "mandatory",
            "--username", "practice", "--secret-file", "work/practice/account.password",
        )
        softphone = value.get("softphone") or {}
        srtp = value.get("srtp") or {}
        self.record(
            "TLS to the proxy pinned to sippycup-proxy with mandatory SRTP: pass, verified, SAVP",
            status == 0 and value.get("verdict") == "pass"
            and softphone.get("tls_verified") is True
            and softphone.get("tls_server_name") == practice.PROXY_DNS_NAME
            and srtp.get("active") is True and srtp.get("answerProfile") == "RTP/SAVP",
            {"exit": status, "verdict": value.get("verdict"), "tls": softphone.get("tls_verified"),
             "srtp": srtp},
        )

    def check_media_scope(self) -> None:
        source = practice.state_dir(self.project) / "target-profile-proxy.yaml"
        document = yaml.safe_load(source.read_text(encoding="utf-8"))
        document["name"] = "proxy-gate-signaling-only"
        document["target"]["approved_addresses"] = [self.proxy]
        document["limits"]["max_calls"] = GATE_CALL_BUDGET
        practice.write_private(self.host_path("signaling-only.yaml"),
                               yaml.safe_dump(document, sort_keys=False))
        status, value = self.guided(
            self.work_path("signaling-only.yaml"), "scope",
            "--dial", "echo", "--duration", CALL_SECONDS,
            "--username", "practice", "--secret-file", "work/practice/account.password",
        )
        self.record_stop(
            "only the proxy approved: media-outside-scope stops the call; the media guard dropped the RTP and "
            "RTCP addressed to the unapproved media address (this capture's filter does not cover that address)",
            status, value,
        )
        # The owner's media answer lists no address at all, on the direct
        # target: signaling and (unlisted) media are the same address, so the
        # call's own capture covers it and shows what really left.
        source = practice.state_dir(self.project) / "target-profile.yaml"
        document = yaml.safe_load(source.read_text(encoding="utf-8"))
        document["name"] = "proxy-gate-direct-no-media"
        document["media"] = {"addresses": [], "port_range": {"start": 20000, "end": 20019}}
        document["limits"]["max_calls"] = GATE_CALL_BUDGET
        practice.write_private(self.host_path("direct-no-media.yaml"),
                               yaml.safe_dump(document, sort_keys=False))
        status, value = self.guided(
            self.work_path("direct-no-media.yaml"), "scope-direct",
            "--dial", "echo", "--duration", CALL_SECONDS,
            "--username", "practice", "--secret-file", "work/practice/account.password",
        )
        self.record_stop(
            "signaling address not listed for media (direct): media-outside-scope, and the call's capture, "
            f"which covers that address, holds at most {SCOPE_STOP_MAX_PACKETS} RTP or RTCP packets to it",
            status, value, captured=True,
        )

    def record_stop(self, name: str, status: int, value: dict[str, Any], *, captured: bool = False) -> None:
        """One media-scope stop: verdict, the guard's own record, and the capture."""
        sent = self.tshark_count(
            self.call_capture(value),
            f"ip.src == {practice.CALLER_ADDRESS} && ip.dst == {self.address} "
            "&& udp.dstport >= 20000 && udp.dstport <= 20020",
        )
        covered = self.tshark_count(
            self.call_capture(value), f"ip.dst == {self.address} && udp.dstport == 5060",
        )
        peer = str((value.get("softphone") or {}).get("media_peer") or "")
        guard = value.get("mediaGuard") or {}
        blocked = guard.get("blocked") or {}
        self.record(
            name,
            status == 1 and value.get("verdict") == "media-outside-scope"
            and peer.startswith(self.address + ":") and sent <= SCOPE_STOP_MAX_PACKETS
            and guard.get("active") is True and guard.get("listTruncated") is False
            # The stop was exercised: PJSUA did address media there, RTCP included.
            and int(blocked.get("rtcp") or 0) >= 2
            and int(blocked.get("rtp") or 0) + int(blocked.get("rtcp") or 0) <= 10
            and (covered > 0 if captured else True),
            {"exit": status, "verdict": value.get("verdict"), "media_peer": peer,
             "media_packets_to_peer_in_capture": sent, "capture_covers_peer": covered > 0,
             "guard": guard},
        )

    def campaign(self, manifest: str, label: str) -> tuple[int, dict[str, Any], list[dict[str, Any]], Path | None]:
        plan = self.work_path(f"plan-{label}.json")
        planned = self.run("campaign", "plan", manifest, "--output", plan)
        self.record(f"campaign plan ({label})", planned.returncode == 0,
                    planned.stderr.strip()[:300] or None)
        environment = dict(self.env, SIPPYCUP_GATE_PRACTICE_SECRET=self.password())
        executed = subprocess.run(
            [str(LAUNCHER), "--practice", "campaign", "run", plan, "--manifest", manifest,
             "--run-root", self.work_path(f"runs-{label}"), "--interface", "lo",
             "--secret-env", "practice-password=SIPPYCUP_GATE_PRACTICE_SECRET"],
            cwd=self.project, env=environment, text=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240, check=False,
        )
        runs = sorted(self.host_path(f"runs-{label}").glob("*/result.json"))
        run_dir = runs[-1].parent if runs else None
        result = json.loads(runs[-1].read_text(encoding="utf-8")) if runs else {}
        events = []
        if run_dir and (run_dir / "events.jsonl").exists():
            events = [json.loads(line) for line in
                      (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        return executed.returncode, result, events, run_dir

    def check_campaign(self) -> None:
        code, result, events, run_dir = self.campaign("work/practice/campaign-proxy.yaml", "proxy")
        call = self.softphone_line(events)
        self.record(
            "campaign through the proxy (OPTIONS UDP/TCP, softphone call with 407) succeeds "
            "under a one-call ceiling",
            code == 0 and result.get("state") == "succeeded" and call.get("outcome") == "passed"
            and (call.get("authentication") or {}).get("INVITE", {}).get("attempts") == 1,
            {"exit": code, "state": result.get("state"), "outcome": call.get("outcome"),
             "reasons": call.get("reasons"), "authentication": call.get("authentication")},
        )
        self.record(
            "the practice password appears nowhere in the proxy campaign evidence",
            run_dir is not None and not any(
                self.password().encode() in path.read_bytes()
                for path in run_dir.rglob("*") if path.is_file()
            ),
        )
        plan = json.loads((run_dir / "plan.json").read_text(encoding="utf-8")) if run_dir else {}
        authorization = plan.get("authorization") or {}
        self.record(
            "the plan keeps the media address media only (mediaNetworks) and freezes its capture term",
            authorization.get("networks") == [f"{self.proxy}/32"]
            and authorization.get("mediaNetworks") == [f"{self.address}/32"]
            and f"(udp portrange 20000-20019 and (host {self.address}))" in str(plan.get("captureFilter")),
            {"networks": authorization.get("networks"), "mediaNetworks": authorization.get("mediaNetworks"),
             "captureFilter": plan.get("captureFilter")},
        )
        self.campaign_media(run_dir, result, call, "plan", "mediaNetworks", "proxy campaign")
        capture = "/" + str(run_dir.relative_to(self.project) / "capture.pcap") if run_dir else ""
        asserted = self.run("--practice", "--", "sippycup-assert", capture, "--expect",
                            "/work/practice/expectations-proxy.yaml", "--format", "json", timeout=120)
        try:
            oracle = json.loads(asserted.stdout or "{}")
        except ValueError:
            oracle = {}
        self.record(
            "the oracle passes on the proxy campaign's own capture (media now inside it)",
            oracle.get("verdict") == "pass",
            {"exit": asserted.returncode, "verdict": oracle.get("verdict"), "summary": oracle.get("summary"),
             "stderr": asserted.stderr.strip()[-200:]},
        )
        self.check_media_network_never_signaling()
        self.check_legacy_campaign()

    def softphone_line(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        lines = []
        for event in events:
            if event.get("event") == "step.output" and event.get("stream") == "stdout":
                with contextlib.suppress(ValueError):
                    lines.append(json.loads(event.get("text", "")))
        calls = [line for line in lines if line.get("runner") == "campaign-softphone-runner"]
        return calls[0] if calls else {}

    def campaign_media(self, run_dir: Path | None, result: dict[str, Any], call: dict[str, Any],
                       source: str, admitted: str, label: str) -> None:
        """The campaign capture holds the RTP both ways and the watchdog counted every packet."""
        capture = "/" + str(run_dir.relative_to(self.project) / "capture.pcap") if run_dir else ""
        caller = practice.CALLER_ADDRESS
        rtp = "udp.port in {20000..20019} && !(udp.port == 5060)"
        to_media = self.tshark_count(capture, f"ip.src == {caller} && ip.dst == {self.address} && {rtp}")
        from_media = self.tshark_count(capture, f"ip.src == {self.address} && ip.dst == {caller} && {rtp}")
        media = self.tshark_count(capture, rtp)
        frames = self.tshark_count(capture, "frame")
        recorded = result.get("capture") or {}
        watchdog = recorded.get("watchdog") or {}
        self.record(
            f"{label}: the capture holds the call's RTP both ways between the caller and the media address",
            to_media > 50 and from_media > 50,
            {"to_media": to_media, "from_media": from_media},
        )
        self.record(
            f"{label}: the watchdog counted every captured packet, media included "
            f"(capture filter from {source})",
            recorded.get("filterSource") == source and watchdog.get("packets") == frames
            and watchdog.get("mediaPackets") == media and media >= to_media + from_media,
            {"filterSource": recorded.get("filterSource"), "watchdog": watchdog,
             "tshark_frames": frames, "tshark_media": media},
        )
        scope = call.get("mediaScope") or {}
        self.record(
            f"{label}: the call step records the media peer and the authorization that admitted it",
            str(scope.get("peer") or "").startswith(self.address + ":") and scope.get("inScope") is True
            and scope.get("admittedBy") == "media-network" and scope.get("authorization") == admitted,
            scope,
        )

    def check_media_network_never_signaling(self) -> None:
        """A target inside a media-only network is refused by the planner."""
        source = practice.state_dir(self.project) / "campaign-proxy.yaml"
        document = yaml.safe_load(source.read_text(encoding="utf-8"))
        document["metadata"]["name"] = "proxy-gate-media-as-signaling"
        document["targets"][0]["address"] = self.address
        practice.write_private(self.host_path("campaign-media-as-signaling.yaml"),
                               yaml.safe_dump(document, sort_keys=False))
        planned = self.run("campaign", "plan", self.work_path("campaign-media-as-signaling.yaml"))
        self.record(
            "a media-only network never admits signaling: a target on the media address is refused at plan time",
            planned.returncode != 0 and "mediaNetworks" in planned.stderr and not planned.stdout.strip(),
            {"exit": planned.returncode, "stderr": planned.stderr.strip()[-240:]},
        )

    def check_legacy_campaign(self) -> None:
        """An older manifest (media address merged into networks) is captured the same way."""
        source = practice.state_dir(self.project) / "campaign-proxy.yaml"
        document = yaml.safe_load(source.read_text(encoding="utf-8"))
        document["metadata"]["name"] = "proxy-gate-legacy-networks"
        authorization = document["authorization"]
        authorization["networks"] = [*authorization["networks"], *authorization.pop("mediaNetworks")]
        # See GATE_CALL_BUDGET: this directory's calls share one count.
        authorization["ceilings"]["calls"] = GATE_CALL_BUDGET
        practice.write_private(self.host_path("campaign-legacy.yaml"), yaml.safe_dump(document, sort_keys=False))
        code, result, events, run_dir = self.campaign(self.work_path("campaign-legacy.yaml"), "legacy")
        plan = json.loads((run_dir / "plan.json").read_text(encoding="utf-8")) if run_dir else {}
        self.record(
            "legacy campaign (no mediaNetworks) succeeds; its frozen filter is the original one",
            code == 0 and result.get("state") == "succeeded"
            and "mediaNetworks" not in (plan.get("authorization") or {})
            and f"host {self.address}" not in str(plan.get("captureFilter")),
            {"exit": code, "state": result.get("state"), "captureFilter": plan.get("captureFilter")},
        )
        self.campaign_media(run_dir, result, self.softphone_line(events), "plan+authorized-media",
                            "networks", "legacy campaign")

    def check_sipp(self) -> None:
        manifest = SIPP_MANIFEST.replace("@PROXY@", self.proxy).replace("@ADDRESS@", self.address)
        practice.write_private(self.host_path("campaign-sipp.yaml"), manifest)
        code, result, events, run_dir = self.campaign(self.work_path("campaign-sipp.yaml"), "sipp")
        capture = "/" + str(run_dir.relative_to(self.project) / "capture.pcap") if run_dir else ""
        rows = self.sip_rows(capture) if capture else []
        self.record(
            "SIPp runner (no credentials) through the proxy: the step fails on 407 and SIPp ACKs it",
            code != 0 and result.get("state") == "failed"
            and ("127.0.0.3", "127.0.0.1", "", "407") in {(r[0], r[1], r[2], r[3]) for r in rows}
            and any(row[2] == "ACK" and row[1] == self.proxy for row in rows),
            {"exit": code, "state": result.get("state"), "rows": rows},
        )

    def checks_profile(self, source: str, name: str, section: dict[str, Any]) -> str:
        document = yaml.safe_load((practice.state_dir(self.project) / source).read_text(encoding="utf-8"))
        document["limits"]["max_calls"] = GATE_CALL_BUDGET  # see GATE_CALL_BUDGET
        document["security_checks"] = section
        practice.write_private(self.host_path(name), yaml.safe_dump(document, sort_keys=False))
        return self.work_path(name)

    def run_checks(self, profile: str, label: str, *extra: str) -> dict[str, Any]:
        result = self.run("--practice", "checks", "run", profile, "--run-root",
                          self.work_path(f"checks-{label}"), "--format", "json", *extra, timeout=300)
        self.host_path(f"checks-{label}.json").write_text(result.stdout, encoding="utf-8")
        try:
            value = json.loads(result.stdout or "{}")
        except ValueError:
            value = {}
        value["_exit"] = result.returncode
        return value

    def check_security_checks(self) -> None:
        profile = self.checks_profile("target-profile-proxy.yaml", "checks-udp.yaml", {
            "approved": ["banner-disclosure", "options-methods", "unauthenticated-register",
                         "digest-quality", "unauthenticated-invite", "user-enumeration",
                         "nonce-replay"],
            "max_requests": 40, "account": practice.ACCOUNT, "destination": "echo",
        })
        value = self.run_checks(profile, "udp", "--secret-file", "work/practice/account.password")
        rows = {row["id"]: row for row in (value.get("findings") or {}).get("checks", [])}
        invite = rows.get("unauthenticated-invite", {})
        self.record(
            "checks run against the proxy completes; unauthenticated INVITE challenged with 407 "
            "and ACKed; unauthenticated REGISTER challenged",
            value.get("state") == "completed" and invite.get("status") == "passed"
            and "407" in invite.get("summary", "") and "ACKed" in invite.get("summary", "")
            and rows.get("unauthenticated-register", {}).get("status") == "passed",
            {"exit": value.get("_exit"), "state": value.get("state"),
             "statuses": {key: row.get("status") for key, row in rows.items()}},
        )
        profile = self.checks_profile("target-profile-proxy-tls.yaml", "checks-tls.yaml", {
            "approved": ["tls-certificate", "tls-protocols", "cleartext-signaling"],
            "max_requests": 20,
            "cleartext_endpoints": [{"transport": "udp", "port": 5060}, {"transport": "tcp", "port": 5060}],
        })
        value = self.run_checks(profile, "tls")
        rows = {row["id"]: row for row in (value.get("findings") or {}).get("checks", [])}
        self.record(
            "TLS checks against the proxy: certificate verified for sippycup-proxy",
            value.get("state") == "completed"
            and f"verified for {practice.PROXY_DNS_NAME}" in rows.get("tls-certificate", {}).get("summary", "")
            and rows.get("cleartext-signaling", {}).get("status") == "finding",
            {"exit": value.get("_exit"), "statuses": {key: row.get("status") for key, row in rows.items()}},
        )

    def execute(self) -> dict[str, Any]:
        ok = False
        try:
            self.ensure_target()
            self.check_profiles()
            self.check_preflight()
            self.check_probes()
            self.check_call()
            self.check_no_register()
            self.check_dtmf()
            self.check_server_bye()
            self.check_tls()
            self.check_media_scope()
            self.check_campaign()
            self.check_sipp()
            self.check_security_checks()
            ok = True
        except GateFailure:
            ok = False
        finally:
            summary = {
                "schema_version": "sippycup.dev/practice-proxy-gate/v1",
                "ok": ok and all(item["ok"] for item in self.checks) and bool(self.checks),
                "checks": self.checks,
                "evidence": str(self.gate_dir.relative_to(self.project)) if self.gate_dir else None,
                "network_activity": "loopback inside the practice namespace only",
                "finished": datetime.now(timezone.utc).isoformat(),
            }
            if self.gate_dir:
                (self.gate_dir / "summary.json").write_text(
                    json.dumps(summary, indent=2) + "\n", encoding="utf-8"
                )
            self.teardown()
        return summary


def main() -> int:
    available, reason = practice_gate.images_available()
    if not available:
        print(f"practice proxy gate cannot run: {reason}", file=sys.stderr)
        return 2
    summary = ProxyGate().execute()
    passed = sum(1 for item in summary["checks"] if item["ok"])
    print(f"practice proxy gate: {'PASS' if summary['ok'] else 'FAIL'} "
          f"({passed}/{len(summary['checks'])} checks); evidence {summary['evidence']}")
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
