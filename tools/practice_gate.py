#!/usr/bin/env python3
"""Live regression gate against the optional local practice target.

Every check runs rootless and without sudo through the unified launcher:
toolbox containers join the practice target's loopback-only network namespace
with ``--practice``. The gate starts the target when it is not already up and
removes only what it started. Evidence is kept under
``work/practice/gate-<UTC>/``; nothing in it is sent anywhere.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup import practice  # noqa: E402

LAUNCHER = ROOT / "bin" / "sippycup"
CALL_SECONDS = 5


class GateFailure(AssertionError):
    """A practice-gate check failed."""


class _OnlyFaults(Exception):
    """Control flow: SIPPYCUP_PRACTICE_GATE_ONLY=faults runs just the fault drill checks."""


@dataclass
class Gate:
    project: Path = ROOT
    env: dict[str, str] = field(default_factory=lambda: dict(os.environ))
    checks: list[dict[str, Any]] = field(default_factory=list)
    started_target: bool = False
    gate_dir: Path | None = None
    address: str = practice.DEFAULT_ADDRESS

    # -- helpers ---------------------------------------------------------
    def run(
        self,
        *arguments: str,
        timeout: float = 120,
        stdin: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(LAUNCHER), *arguments],
            cwd=self.project,
            env=self.env,
            input=stdin if stdin is not None else "",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )

    def record(self, name: str, ok: bool, detail: Any = None) -> None:
        self.checks.append({"check": name, "ok": bool(ok), "detail": detail})
        print(f"{'PASS' if ok else 'FAIL'} {name}" + (f": {detail}" if detail else ""))
        if not ok:
            raise GateFailure(f"{name}: {detail}")

    def host_path(self, name: str) -> Path:
        assert self.gate_dir is not None
        return self.gate_dir / name

    def container_path(self, name: str) -> str:
        assert self.gate_dir is not None
        return f"/work/practice/{self.gate_dir.name}/{name}"

    def work_path(self, name: str) -> str:
        assert self.gate_dir is not None
        return f"work/practice/{self.gate_dir.name}/{name}"

    def tshark_count(self, capture: str, display_filter: str) -> int:
        result = self.run(
            "--practice", "--", "tshark", "-r", capture, "-Y", display_filter,
            "-T", "fields", "-e", "frame.number",
        )
        if result.returncode != 0:
            raise GateFailure(f"tshark failed: {result.stderr.strip()[:300]}")
        return len([line for line in result.stdout.splitlines() if line.strip()])

    # -- lifecycle -------------------------------------------------------
    def ensure_target(self) -> None:
        status = subprocess.run(
            [str(LAUNCHER), "practice-target", "status"],
            cwd=self.project, env=self.env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if "Practice profile: installed" not in status.stdout:
            raise GateFailure("practice image is not installed; run practice-target build")
        if "Target: up" not in status.stdout:
            up = subprocess.run(
                [str(LAUNCHER), "practice-target", "up"],
                cwd=self.project, env=self.env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.record("practice-target up", up.returncode == 0, up.stderr.strip()[-300:] or None)
            self.started_target = True
        facts = practice.load_facts(self.project)
        self.address = facts["address"]
        self.record("connection facts omit the password", not self.password_leaked(facts))
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.gate_dir = practice.state_dir(self.project) / f"gate-{stamp}-{os.getpid()}"
        self.gate_dir.mkdir(mode=0o700)

    def password_leaked(self, facts: dict[str, Any]) -> bool:
        password = self.password()
        return password in json.dumps(facts)

    def password(self) -> str:
        path = practice.state_dir(self.project) / "account.password"
        return path.read_text(encoding="utf-8").strip()

    def teardown(self) -> None:
        if self.started_target:
            subprocess.run(
                [str(LAUNCHER), "practice-target", "down"],
                cwd=self.project, env=self.env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )

    # -- capture and softphone --------------------------------------------
    def start_capture(
        self, name: str, *, everything: bool = False, seconds: int = 60
    ) -> tuple[subprocess.Popen[str], str]:
        """Capture on lo; ``everything`` drops the host filter (for no-DNS proof)."""
        capture = self.container_path(name)
        # The child inherits its own copy of the log descriptor; close ours.
        with open(self.host_path(f"{name}.tcpdump.log"), "w", encoding="utf-8") as log:
            process = subprocess.Popen(
                [
                    str(LAUNCHER), "--practice", "--", "timeout", str(seconds),
                    "tcpdump", "-Z", "root", "-i", "lo", "-U", "-s", "0",
                    "-w", capture, *([] if everything else ["host", self.address]),
                ],
                cwd=self.project, env=self.env, text=True,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log,
            )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.host_path(name).exists() and self.host_path(name).stat().st_size > 0:
                time.sleep(0.3)
                return process, capture
            if process.poll() is not None:
                break
            time.sleep(0.1)
        process.kill()
        process.wait()
        raise GateFailure(f"tcpdump did not start in the practice namespace ({name})")

    def stop_capture(self, process: subprocess.Popen[str]) -> None:
        time.sleep(0.5)
        process.send_signal(2)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    def softphone(
        self,
        name: str,
        *,
        variant: str = "udp",
        destination: str | None = None,
        password: str | None = None,
        authenticated: bool = True,
        ca_file: str | None = None,
        done: tuple[str, ...] = ("is DISCONNECTED",),
        duration: int = CALL_SECONDS,
        settle: float | None = None,
    ) -> tuple[int, str]:
        """Run one PJSUA session; type `q` once the expected log line appears."""
        log = self.host_path(f"{name}.log")
        config = practice.render_uac(
            self.project,
            address=self.address,
            password=password if password is not None else self.password(),
            variant=variant,
            rec_file=self.container_path(f"{name}.wav"),
            log_file=self.container_path(f"{name}.log"),
            duration=duration,
            ca_file=ca_file,
        )
        if not authenticated:
            kept = []
            for line in config.splitlines():
                option = line.split(" ", 1)[0]
                if option in {"--registrar", "--realm", "--username", "--password", "--reg-timeout"}:
                    continue
                if option == "--id":
                    line = f"--id sip:anonymous@{practice.CALLER_ADDRESS}"
                kept.append(line)
            config = "\n".join(kept) + "\n"
        practice.write_private(self.host_path(f"{name}.cfg"), config)
        arguments = ["--practice", "--", "pjsua", "--config-file", self.container_path(f"{name}.cfg")]
        if destination:
            arguments.append(destination)
        process = subprocess.Popen(
            [str(LAUNCHER), *arguments],
            cwd=self.project, env=self.env, text=True,
            stdin=subprocess.PIPE,
            stdout=open(self.host_path(f"{name}.stdout"), "w", encoding="utf-8"),
            stderr=subprocess.STDOUT,
        )
        # PJSUA buffers its log, so a marker may only appear late; the fixed
        # settle time (call duration plus slack, or a few seconds for a
        # rejected attempt) is the normal path and the marker an early exit.
        deadline = time.monotonic() + (settle if settle is not None else duration + 3)
        while time.monotonic() < deadline and process.poll() is None:
            text = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
            if any(marker in text for marker in done):
                time.sleep(0.5)
                break
            time.sleep(0.2)
        try:
            # The console command reaches PJSUA only through forwarded stdin.
            assert process.stdin is not None
            process.stdin.write("q\n")
            process.stdin.flush()
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        try:
            status = process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            status = -9
        text = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
        self.host_path(f"{name}.cfg").unlink(missing_ok=True)
        return status, text

    # -- checks -------------------------------------------------------------
    def check_profile(self) -> None:
        result = self.run("rehearse", "work/practice/target-profile.yaml", "--format", "json")
        ready = result.returncode == 0 and json.loads(result.stdout or "{}").get("ready") is True
        self.record("rehearse generated practice profile", ready, result.stderr.strip()[:200] or None)

    def check_sipsak_absent(self) -> None:
        # The OPTIONS client is in-tree; nothing may fall back to sipsak.
        result = self.run("--practice", "--", "bash", "-c", "command -v sipsak", timeout=60)
        self.record(
            "sipsak is absent from the toolbox image",
            result.returncode != 0 and not result.stdout.strip(),
            f"exit {result.returncode}",
        )

    def preflight(self, port: str, transport: str, *options: str) -> subprocess.CompletedProcess[str]:
        result = self.run(
            "--practice", "preflight", self.address, port, transport, *options, timeout=60
        )
        name = "-".join(["preflight", transport, port, *options])
        name = "".join(c if c.isalnum() or c in "-." else "_" for c in name)
        self.host_path(f"{name[:120]}.txt").write_text(
            result.stdout + result.stderr, encoding="utf-8"
        )
        return result

    def check_preflight(self) -> None:
        ca = "/work/practice/ca.crt"
        for port, transport in (("5060", "udp"), ("5060", "tcp")):
            result = self.preflight(port, transport)
            self.record(
                f"launcher preflight {transport}",
                result.returncode == 0
                and "SIP/2.0 200 OK [class 2xx]" in result.stdout
                and "Result: PASS (exit 0)" in result.stdout,
                f"exit {result.returncode}",
            )
        result = self.preflight(
            "5061", "tls", "--tls-ca", ca, "--tls-server-name", practice.DNS_NAME
        )
        self.record(
            "launcher preflight tls verified against the practice CA as sippycup-practice",
            result.returncode == 0
            and f"TLS: verified for name '{practice.DNS_NAME}'" in result.stdout
            and "SIP/2.0 200 OK" in result.stdout
            and "Result: PASS (exit 0)" in result.stdout,
            f"exit {result.returncode}",
        )
        result = self.preflight("5061", "tls", "--tls-ca", ca)
        self.record(
            "launcher preflight tls verified against the practice CA by IP SAN",
            result.returncode == 0 and "TLS: verified for name" in result.stdout,
            f"exit {result.returncode}",
        )
        result = self.preflight("5061", "tls")
        self.record(
            "launcher preflight tls without the practice CA fails verification (exit 5)",
            result.returncode == 5
            and "TLS: FAILED (tls_verification)" in result.stdout
            and "Result: TLS FAILURE" in result.stdout
            and "SIP/2.0 200" not in result.stdout,
            f"exit {result.returncode}",
        )
        result = self.preflight(
            "5061", "tls", "--tls-ca", ca, "--tls-server-name", "wrong-name.invalid"
        )
        self.record(
            "launcher preflight tls with a wrong server name fails (exit 5)",
            result.returncode == 5 and "TLS: FAILED (tls_verification)" in result.stdout,
            f"exit {result.returncode}",
        )
        result = self.preflight("5061", "tls", "--tls-unverified")
        self.record(
            "launcher preflight --tls-unverified is reported UNVERIFIED",
            result.returncode == 0
            and "TLS: UNVERIFIED" in result.stdout
            and "Result: PASS, TLS UNVERIFIED" in result.stdout
            and "Result: PASS (exit" not in result.stdout,
            f"exit {result.returncode}",
        )
        for port, transport, code, label in (
            ("5099", "udp", 3, "times out (exit 3)"),
            ("5099", "tcp", 4, "is refused (exit 4)"),
        ):
            result = self.preflight(port, transport)
            self.record(
                f"launcher preflight {transport} against a closed port {label}",
                result.returncode == code,
                f"exit {result.returncode}",
            )

    def check_no_name_workaround(self) -> None:
        # sipsak resolved its own hostname before sending, which once needed
        # hosts entries on both routes. They are gone: the fixed toolbox
        # hostname must not resolve in the practice namespace, so every later
        # preflight, campaign, and PJSUA check proves nothing depends on it.
        # getent reads /etc/hosts and sends nothing.
        result = self.run("--practice", "--", "getent", "hosts", "sippycup", timeout=60)
        self.record(
            "practice route has no hosts entry for the toolbox hostname",
            result.returncode != 0 and not result.stdout.strip(),
            f"exit {result.returncode}",
        )

    def check_campaign(self) -> None:
        plan = self.work_path("plan.json")
        planned = self.run(
            "campaign", "plan", "work/practice/campaign.yaml", "--output", plan
        )
        self.record("campaign plan of the practice manifest", planned.returncode == 0,
                    planned.stderr.strip()[:300] or None)
        executed = self.run(
            "--practice", "campaign", "execute", plan,
            "--manifest", "work/practice/campaign.yaml",
            "--run-root", self.work_path("runs"),
            "--interface", "lo",
            timeout=180,
        )
        runs = sorted(self.host_path("runs").glob("*/result.json"))
        result = json.loads(runs[-1].read_text(encoding="utf-8")) if runs else {}
        preflight_path = runs[-1].parent / "preflight.json" if runs else None
        preflight = (
            json.loads(preflight_path.read_text(encoding="utf-8"))
            if preflight_path and preflight_path.exists() else []
        )
        self.record(
            "campaign execute: sip_options_preflight answered on udp and tcp",
            executed.returncode == 0
            and len(preflight) == 2
            and all(
                item.get("ok") and item.get("detail") == "SIP/2.0 200 OK"
                and item.get("statusClass") == "2xx" and item.get("warning") is None
                for item in preflight
            ),
            {"exit": executed.returncode, "preflight": [item.get("detail") for item in preflight],
             "stderr": executed.stderr.strip()[-300:] or None},
        )
        self.record(
            "campaign execute succeeded with both OPTIONS steps",
            result.get("state") == "succeeded" and result.get("completedSteps") == 2,
            result,
        )
        # The options steps run the in-tree client, which prints one JSON
        # summary per step; sipsak would print nothing of the kind.
        events = runs[-1].parent / "events.jsonl" if runs else None
        summaries = []
        if events is not None and events.exists():
            for line in events.read_text(encoding="utf-8").splitlines():
                event = json.loads(line)
                if event.get("event") == "step.output" and event.get("stream") == "stdout":
                    for text in str(event.get("text", "")).splitlines():
                        with contextlib.suppress(ValueError):
                            summaries.append(json.loads(text))
        self.record(
            "campaign options steps used the in-tree client and met finalStatus 200",
            len(summaries) == 2
            and all(item.get("met") is True and item.get("status_code") == 200
                    and item.get("expectation") == 200 for item in summaries),
            [(item.get("transport"), item.get("status_code"), item.get("requests_sent"))
             for item in summaries],
        )

    def check_unauthenticated_invite(self) -> None:
        capture_process, capture = self.start_capture("unauthenticated.pcap")
        status, log = self.softphone(
            "unauthenticated", destination=f"sip:echo@{self.address}",
            authenticated=False, settle=4,
        )
        self.stop_capture(capture_process)
        self.record("unauthenticated softphone exits after q", status == 0, f"exit {status}")
        self.record(
            "unauthenticated INVITE is rejected with 401",
            "DISCONNECTED [reason=401" in log,
            next((line.strip() for line in log.splitlines() if "is DISCONNECTED" in line), None),
        )
        challenged = self.tshark_count(
            capture, 'sip.Status-Code == 401 && sip.CSeq.method == "INVITE" && sip.WWW-Authenticate'
        )
        self.record("401 carries a Digest WWW-Authenticate challenge", challenged >= 1, challenged)

    def check_authenticated_call(self) -> None:
        capture_process, capture = self.start_capture("call.pcap")
        status, log = self.softphone("call", destination=f"sip:echo@{self.address}")
        self.stop_capture(capture_process)
        self.record("authenticated softphone exits after q", status == 0, f"exit {status}")
        self.record(
            "registration with Digest authentication succeeds",
            "registration success, status=200" in log,
        )
        self.record("authenticated echo call is confirmed", "state changed to CONFIRMED" in log)
        self.record("echo call ends normally", "DISCONNECTED [reason=200" in log)
        authorized = self.tshark_count(capture, 'sip.Method == "INVITE" && sip.Authorization')
        self.record("INVITE was retried with Authorization after the challenge", authorized == 1, authorized)
        activity = practice.wav_activity(self.host_path("call.wav"))
        self.record(
            "recorded echo is non-silent",
            activity["seconds"] >= CALL_SECONDS - 1 and activity["active_fraction"] > 0.2
            and activity["peak"] > 2000,
            activity,
        )
        report = self.run("report", self.work_path("call.pcap"), timeout=120)
        self.host_path("report.txt").write_text(report.stdout, encoding="utf-8")
        self.record("report on the call capture", report.returncode == 0 and "SIP" in report.stdout,
                    f"exit {report.returncode}")
        triage = self.run("--practice", "triage", self.work_path("call.pcap"), "--format", "json")
        triaged = json.loads(triage.stdout or "{}") if triage.returncode == 0 else {}
        verdicts = {item["code"]: item["verdict"] for item in triaged.get("findings", [])}
        self.host_path("triage.json").write_text(triage.stdout, encoding="utf-8")
        self.record(
            "triage sees SIP and RTP",
            triage.returncode == 0
            and verdicts.get("capture.sip_present") == "pass"
            and verdicts.get("capture.media_present") == "pass",
            verdicts,
        )
        asserted = self.run(
            "--practice", "assert", "--expect", "work/practice/expectations.yaml",
            self.work_path("call.pcap"), "--format", "json",
        )
        self.host_path("assert.json").write_text(asserted.stdout, encoding="utf-8")
        result = json.loads(asserted.stdout or "{}")
        assertions = {item["id"]: item["verdict"] for item in result.get("assertions", [])}
        self.record(
            "assert overall PASS",
            asserted.returncode == 0 and result.get("verdict") == "pass",
            {"exit": asserted.returncode, "verdict": result.get("verdict")},
        )
        self.record(
            "assert observed bidirectional media",
            any(key.endswith("media.directionality") and value == "pass"
                for key, value in assertions.items()),
            {key: value for key, value in assertions.items() if "direction" in key},
        )

    def check_wrong_password(self) -> None:
        capture_process, capture = self.start_capture("wrong-password.pcap")
        status, log = self.softphone(
            "wrong-password",
            password="wrong-" + os.urandom(8).hex(),
            done=("registration error", "registration failed", "status=403"),
            settle=4,
        )
        self.stop_capture(capture_process)
        self.record("wrong-password softphone exits after q", status == 0, f"exit {status}")
        self.record(
            "wrong password is rejected",
            "registration success" not in log
            and ("PJSIP_EFAILEDCREDENTIAL" in log or "status=403" in log),
            next((line.split("pjsua_acc.c", 1)[-1].strip() for line in log.splitlines()
                  if "registration error" in line or "registration failed" in line), None),
        )
        attempts = self.tshark_count(capture, 'sip.Method == "REGISTER" && sip.Authorization')
        self.record("exactly one credentialed REGISTER attempt", attempts == 1, attempts)

    def check_rejections(self) -> None:
        for destination, code in (("busy", "486"), ("decline", "603")):
            status, log = self.softphone(
                f"reject-{destination}",
                destination=f"sip:{destination}@{self.address}",
                settle=4,
            )
            self.record(
                f"{destination} destination rejects with {code}",
                status == 0 and f"DISCONNECTED [reason={code}" in log,
                next((line.strip() for line in log.splitlines() if "is DISCONNECTED" in line), None),
            )

    def check_tls(self) -> None:
        status, log = self.softphone(
            "tls-tone",
            variant="tls",
            destination=f"sip:tone@{self.address}:5061;transport=tls",
            ca_file="/work/practice/ca.crt",
        )
        self.record("TLS softphone exits after q", status == 0, f"exit {status}")
        self.record(
            "TLS server certificate verified against the generated CA",
            f"TLS cert verification result of {self.address}:5061 : OK" in log,
        )
        self.record(
            "TLS-signaled INVITE and call confirmed",
            "Request msg INVITE" in log and "to TLS" in log
            and "state changed to CONFIRMED" in log and "DISCONNECTED [reason=200" in log,
        )
        activity = practice.wav_activity(self.host_path("tls-tone.wav"))
        self.record("tone prompt received over the TLS call is non-silent",
                    activity["active_fraction"] > 0.2 and activity["peak"] > 2000, activity)
        status, log = self.softphone(
            "tls-untrusted",
            variant="tls",
            destination=f"sip:tone@{self.address}:5061;transport=tls",
            ca_file="/etc/ssl/certs/ca-certificates.crt",
            settle=4,
        )
        self.record(
            "TLS against an untrusted CA is refused",
            "registration success" not in log and "state changed to CONFIRMED" not in log,
            next((line.strip() for line in log.splitlines() if "verification result" in line), None),
        )

    # -- reviewed TLS server name on the pinned literal address -------------
    def capture_facts(self, capture: str, name: str) -> dict[str, int]:
        """Counts that prove literal-only, DNS-free traffic and the SNI."""
        literal = "{127.0.0.1, %s}" % self.address
        return {
            "frames": self.tshark_count(capture, "frame"),
            "dns": self.tshark_count(capture, "dns || udp.port == 53 || tcp.port == 53"),
            "non_literal": self.tshark_count(
                capture, f"!(ip.src in {literal} && ip.dst in {literal})"
            ),
            "client_hello": self.tshark_count(capture, "tls.handshake.type == 1"),
            "sni_reviewed": self.tshark_count(
                capture, f'tls.handshake.extensions_server_name == "{name}"'
            ),
            "sni_other": self.tshark_count(
                capture,
                f'tls.handshake.type == 1 && !(tls.handshake.extensions_server_name == "{name}")',
            ),
            # TLS 1.2 (what Asterisk negotiates here): application data from
            # the client toward 5061 means a SIP request was sent.
            "client_application_data": self.tshark_count(
                capture, "tls.record.content_type == 23 && tcp.dstport == 5061"
            ),
            "tls_version_1_3": self.tshark_count(
                capture, "tls.handshake.extensions.supported_version == 0x0304 && tls.handshake.type == 2"
            ),
        }

    def tls_profile_variant(self, name: str, **changes: Any) -> str:
        """A copy of the generated TLS profile with ``changes`` applied."""
        import yaml

        source = practice.state_dir(self.project) / "target-profile-tls.yaml"
        document = yaml.safe_load(source.read_text(encoding="utf-8"))
        for key, value in changes.items():
            if value is None:
                document["target"].pop(key, None)
            else:
                document["target"][key] = value
        practice.write_private(self.host_path(name), yaml.safe_dump(document, sort_keys=False))
        return self.work_path(name)

    def guided_tls_call(self, profile: str, label: str) -> tuple[int, dict[str, Any]]:
        result = self.run(
            "--practice", "call", profile, "--dial", "echo",
            "--username", "practice", "--secret-file", "work/practice/account.password",
            "--duration", str(CALL_SECONDS), "--run-root", self.work_path(f"calls-{label}"),
            "--format", "json",
            timeout=180,
        )
        self.host_path(f"call-{label}.json").write_text(result.stdout, encoding="utf-8")
        self.host_path(f"call-{label}.stderr").write_text(result.stderr, encoding="utf-8")
        try:
            value = json.loads(result.stdout or "{}")
        except ValueError:
            value = {}
        return result.returncode, value

    def probe(self, label: str, name: str, ca: str) -> dict[str, Any]:
        script = self.host_path("practice_tls_probe.py")
        if not script.exists():
            script.write_text(
                (ROOT / "tools" / "practice_tls_probe.py").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
        capture_process, capture = self.start_capture(f"probe-{label}.pcap", everything=True)
        result = self.run(
            "--practice", "--", "python3", self.container_path("practice_tls_probe.py"),
            self.address, name, ca, self.container_path(f"probe-{label}"),
            timeout=90,
        )
        self.stop_capture(capture_process)
        self.host_path(f"probe-{label}.json").write_text(result.stdout, encoding="utf-8")
        try:
            value = json.loads(result.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            value = {"stderr": result.stderr.strip()[-300:]}
        value["capture"] = self.capture_facts(capture, name)
        return value

    def check_tls_name(self) -> None:
        name = practice.DNS_NAME
        profile = "work/practice/target-profile-tls.yaml"
        for command in ("rehearse", "one-call"):
            result = self.run(command, profile, "--format", "json")
            value = json.loads(result.stdout or "{}") if result.stdout.strip().startswith("{") else {}
            tls = value.get("tls") or value.get("facts", {}).get("tls") or {}
            self.record(
                f"{command} is ready for the TLS profile with server name {name} on {self.address}",
                result.returncode == 0 and value.get("ready") is True
                and tls.get("server_name") == name and tls.get("connects_to") == self.address
                and tls.get("trust") == "file",
                result.stderr.strip()[:200] or tls,
            )
        # Outside the softphone's private namespace the name does not
        # resolve at all, so the pinned host map is the only way it maps.
        result = self.run("--practice", "--", "getent", "hosts", name, timeout=60)
        self.record(
            f"{name} does not resolve on the practice route outside the pinned namespace",
            result.returncode != 0 and not result.stdout.strip(),
            f"exit {result.returncode}",
        )

        capture_process, capture = self.start_capture("tls-name.pcap", everything=True, seconds=90)
        status, value = self.guided_tls_call(profile, "tls")
        self.stop_capture(capture_process)
        tls = value.get("tls") or {}
        self.record(
            "guided TLS call with registration passes, verified for the reviewed name",
            status == 0 and value.get("verdict") == "pass"
            and tls.get("verified") is True and tls.get("serverName") == name
            and tls.get("softphoneVerified") is True and tls.get("preflightVerified") is True
            and tls.get("trust") == "file"
            and (value.get("softphone") or {}).get("registered") is True,
            {"exit": status, "verdict": value.get("verdict"), "tls": {
                key: tls.get(key) for key in ("verified", "serverName", "trust", "softphoneDetail")
            }},
        )
        media = tls.get("media") or {}
        self.record(
            "guided TLS call judged from PJSUA facts plus RTP decoded from the capture",
            (media.get("outbound") or 0) > 0 and (media.get("inbound") or 0) > 0
            and any("TLS-encrypted" in note for note in value.get("notes", [])),
            media,
        )
        facts = self.capture_facts(capture, name)
        self.host_path("tls-name.facts.json").write_text(json.dumps(facts, indent=2), encoding="utf-8")
        self.record(
            "capture: no DNS, only the literal addresses, every ClientHello carries SNI "
            f"{name} (TLS 1.2)",
            facts["frames"] > 0 and facts["dns"] == 0 and facts["non_literal"] == 0
            and facts["client_hello"] >= 2 and facts["sni_reviewed"] == facts["client_hello"]
            and facts["sni_other"] == 0 and facts["client_application_data"] > 0
            and facts["tls_version_1_3"] == 0,
            facts,
        )

        for label, profile_changes, wanted in (
            ("wrong-name", {"tls_server_name": "wrong-practice-name"}, "wrong server name"),
            ("system-ca", {"tls_ca_file": None}, "system trust store (no practice CA)"),
        ):
            variant = self.tls_profile_variant(f"profile-{label}.yaml", **profile_changes)
            capture_process, capture = self.start_capture(f"{label}.pcap", everything=True, seconds=90)
            status, value = self.guided_tls_call(variant, label)
            self.stop_capture(capture_process)
            facts = self.capture_facts(capture, profile_changes.get("tls_server_name") or name)
            self.record(
                f"guided TLS call with a {wanted} fails before any SIP request (exit non-zero)",
                status != 0 and (value.get("tls") or {}).get("verified") is False
                and (value.get("softphone") is None or value.get("softphone", {}).get("dialed") is not True)
                and facts["client_application_data"] == 0 and facts["dns"] == 0
                and facts["non_literal"] == 0 and facts["client_hello"] >= 1,
                {"exit": status, "verdict": value.get("verdict"), "state": value.get("state"),
                 "capture": facts},
            )
            # The preflight stops a guided call first; drive the softphone
            # itself into the same failure to prove PJSUA refuses on its own.
            result = self.probe(
                label,
                profile_changes.get("tls_server_name") or name,
                "system" if label == "system-ca" else "/work/practice/ca.crt",
            )
            facts = result.get("capture", {})
            self.record(
                f"PJSUA itself refuses a {wanted} before sending SIP",
                result.get("error") == "tls_verification_failed"
                and result.get("tls_verified") is False and result.get("answered") is False
                and result.get("final_status") is None
                and facts.get("client_application_data") == 0 and facts.get("dns") == 0
                and facts.get("non_literal") == 0 and facts.get("sni_other") == 0
                and facts.get("client_hello", 0) >= 1,
                {"error": result.get("error"), "detail": result.get("tls_detail"), "capture": facts},
            )
        # Positive control for the probe: the same unauthenticated attempt
        # with the reviewed name and CA reaches Asterisk (401 challenge).
        result = self.probe("control", name, "/work/practice/ca.crt")
        self.record(
            "probe control: reviewed name and CA verify and the INVITE is answered with 401",
            result.get("tls_verified") is True and result.get("final_status") == 401
            and result.get("capture", {}).get("client_application_data", 0) > 0,
            {"detail": result.get("tls_detail"), "final": result.get("final_status")},
        )

    def check_tls_campaign(self) -> None:
        manifest = "work/practice/campaign-tls.yaml"
        plan = self.work_path("plan-tls.json")
        planned = self.run("campaign", "plan", manifest, "--output", plan)
        self.record("campaign plan of the TLS practice manifest freezes name and CA digest",
                    planned.returncode == 0, planned.stderr.strip()[:300] or None)
        frozen = json.loads(self.host_path("plan-tls.json").read_text(encoding="utf-8"))
        ca_digest = __import__("hashlib").sha256(
            (practice.state_dir(self.project) / "ca.crt").read_bytes()
        ).hexdigest()
        self.record(
            "every TLS plan step carries the reviewed name and the CA SHA-256",
            frozen["steps"] and all(
                step.get("tls") == {"serverName": practice.DNS_NAME,
                                    "caFile": "work/practice/ca.crt", "caSha256": ca_digest}
                for step in frozen["steps"]
            ),
            [step.get("tls") for step in frozen["steps"]],
        )
        environment = dict(self.env, SIPPYCUP_GATE_PRACTICE_SECRET=self.password())
        executed = subprocess.run(
            [str(LAUNCHER), "--practice", "campaign", "run", plan, "--manifest", manifest,
             "--run-root", self.work_path("runs-tls"), "--interface", "lo",
             "--secret-env", "practice-password=SIPPYCUP_GATE_PRACTICE_SECRET"],
            cwd=self.project, env=environment, text=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240, check=False,
        )
        runs = sorted(self.host_path("runs-tls").glob("*/result.json"))
        run_dir = runs[-1].parent if runs else None
        result = json.loads(runs[-1].read_text(encoding="utf-8")) if runs else {}
        preflight = (
            json.loads((run_dir / "preflight.json").read_text(encoding="utf-8"))
            if run_dir and (run_dir / "preflight.json").exists() else []
        )
        steps = []
        if run_dir and (run_dir / "events.jsonl").exists():
            for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines():
                event = json.loads(line)
                if event.get("event") == "step.output" and event.get("stream") == "stdout":
                    with contextlib.suppress(ValueError):
                        steps.append(json.loads(event.get("text", "")))
        call = next((item for item in steps if item.get("case") == "call-echo-tls"), {})
        self.record(
            "TLS campaign run (options + authenticated softphone call) succeeds, all verified",
            executed.returncode == 0 and result.get("state") == "succeeded"
            and result.get("completedSteps") == 2
            and len(preflight) == 1 and preflight[0].get("tls", {}).get("verified") is True
            and preflight[0]["tls"].get("serverName") == practice.DNS_NAME
            and call.get("outcome") == "passed" and call.get("registered") is True
            and call.get("tls", {}).get("verified") is True
            and call.get("tls", {}).get("serverName") == practice.DNS_NAME
            and call.get("tls", {}).get("trust") == "file",
            {"exit": executed.returncode, "state": result.get("state"),
             "preflight": [item.get("tls") for item in preflight], "call": call.get("tls"),
             "stderr": executed.stderr.strip()[-300:] or None},
        )
        self.record(
            "the practice password appears nowhere in the TLS campaign evidence",
            run_dir is not None and not any(
                self.password() in path.read_text(encoding="utf-8", errors="replace")
                for path in run_dir.rglob("*") if path.is_file() and path.suffix != ".pcap"
            ),
        )

        # A CA changed after planning: the copy below is referenced by a
        # manifest variant, planned, then modified. Execution must refuse
        # before any packet, preflight, or run directory.
        import yaml

        copy = self.host_path("ca-reviewed.crt")
        copy.write_bytes((practice.state_dir(self.project) / "ca.crt").read_bytes())
        document = yaml.safe_load(
            (practice.state_dir(self.project) / "campaign-tls.yaml").read_text(encoding="utf-8")
        )
        document["targets"][0]["signaling"]["tlsCaFile"] = self.work_path("ca-reviewed.crt")
        document["evidence"]["directory"] = "evidence/local-practice-tls-tamper"
        practice.write_private(self.host_path("campaign-tamper.yaml"), yaml.safe_dump(document))
        planned = self.run(
            "campaign", "plan", self.work_path("campaign-tamper.yaml"),
            "--output", self.work_path("plan-tamper.json"),
        )
        self.record("campaign plan of the CA-copy manifest", planned.returncode == 0,
                    planned.stderr.strip()[:300] or None)
        with copy.open("a", encoding="ascii") as handle:
            handle.write("\n")
        capture_process, capture = self.start_capture("tamper.pcap", everything=True)
        executed = subprocess.run(
            [str(LAUNCHER), "--practice", "campaign", "run", self.work_path("plan-tamper.json"),
             "--manifest", self.work_path("campaign-tamper.yaml"),
             "--run-root", self.work_path("runs-tamper"), "--interface", "lo",
             "--secret-env", "practice-password=SIPPYCUP_GATE_PRACTICE_SECRET"],
            cwd=self.project, env=environment, text=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False,
        )
        self.stop_capture(capture_process)
        frames = self.tshark_count(capture, f"ip.addr == {self.address} || tcp.port == 5061")
        self.record(
            "a CA modified after planning is refused with nothing sent",
            executed.returncode != 0
            and "changed since it was reviewed" in executed.stderr
            and not any(self.host_path("runs-tamper").glob("*/result.json"))
            and frames == 0,
            {"exit": executed.returncode, "frames": frames,
             "stderr": executed.stderr.strip()[-300:]},
        )

    def check_srtp(self) -> None:
        capture_process, capture = self.start_capture("srtp.pcap")
        status, log = self.softphone("srtp", variant="srtp", destination=f"sip:echo@{self.address}")
        self.stop_capture(capture_process)
        self.record("SRTP softphone exits after q", status == 0, f"exit {status}")
        self.record(
            "SDES-SRTP is active on the echo call",
            "SRTP started, keying=SDES" in log and "state changed to CONFIRMED" in log,
        )
        offers = self.tshark_count(capture, 'sdp.media.proto == "RTP/SAVP" && sdp.media_attr contains "crypto"')
        self.record("both SDP offer and answer use RTP/SAVP with a=crypto", offers >= 2, offers)
        activity = practice.wav_activity(self.host_path("srtp.wav"))
        self.record("SRTP echo is non-silent",
                    activity["active_fraction"] > 0.2 and activity["peak"] > 2000, activity)

    # -- fault destinations (bn-20l): the drill, wire behavior, and verdicts --
    def check_faults(self) -> None:
        import practice_faults

        practice_faults.check_faults(self)

    def execute(self) -> dict[str, Any]:
        try:
            self.ensure_target()
            if os.environ.get("SIPPYCUP_PRACTICE_GATE_ONLY") == "faults":
                self.check_faults()
                raise _OnlyFaults
            self.check_profile()
            self.check_sipsak_absent()
            self.check_preflight()
            self.check_no_name_workaround()
            self.check_campaign()
            self.check_unauthenticated_invite()
            self.check_authenticated_call()
            self.check_wrong_password()
            self.check_rejections()
            self.check_tls()
            self.check_tls_name()
            self.check_tls_campaign()
            self.check_srtp()
            self.check_faults()
            ok = True
        except _OnlyFaults:
            ok = True
        except GateFailure:
            ok = False
        finally:
            summary = {
                "schema_version": "sippycup.dev/practice-gate/v1",
                "ok": all(item["ok"] for item in self.checks) and bool(self.checks),
                "checks": self.checks,
                "evidence": str(self.gate_dir.relative_to(self.project)) if self.gate_dir else None,
                "network_activity": "loopback inside the practice namespace only",
            }
            if self.gate_dir:
                (self.gate_dir / "summary.json").write_text(
                    json.dumps(summary, indent=2) + "\n", encoding="utf-8"
                )
            self.teardown()
        summary["ok"] = summary["ok"] and ok
        return summary


def images_available(env: dict[str, str] | None = None) -> tuple[bool, str]:
    environment = env or os.environ
    try:
        runtime = subprocess.run(
            [str(ROOT / "bin" / "container-runtime")], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return False, "no container runtime"
    for image in (
        environment.get("SIPPYCUP_IMAGE", "localhost/sippycup:latest"),
        environment.get("SIPPYCUP_PRACTICE_IMAGE", "localhost/sippycup-practice:latest"),
    ):
        found = subprocess.run(
            [runtime, "image", "inspect", image],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        if found.returncode != 0:
            return False, f"image not installed: {image}"
    return True, ""


def main() -> int:
    available, reason = images_available()
    if not available:
        print(f"practice gate cannot run: {reason}", file=sys.stderr)
        return 2
    summary = Gate().execute()
    passed = sum(1 for item in summary["checks"] if item["ok"])
    print(f"practice gate: {'PASS' if summary['ok'] else 'FAIL'} "
          f"({passed}/{len(summary['checks'])} checks); evidence {summary['evidence']}")
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
