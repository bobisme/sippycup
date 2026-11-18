#!/usr/bin/env python3
"""Live regression gate against the optional local practice target.

Every check runs rootless and without sudo through the unified launcher:
toolbox containers join the practice target's loopback-only network namespace
with ``--practice``. The gate starts the target when it is not already up and
removes only what it started. Evidence is kept under
``work/practice/gate-<UTC>/``; nothing in it is sent anywhere.
"""

from __future__ import annotations

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
    def start_capture(self, name: str) -> tuple[subprocess.Popen[str], str]:
        capture = self.container_path(name)
        process = subprocess.Popen(
            [
                str(LAUNCHER), "--practice", "--", "timeout", "60",
                "tcpdump", "-Z", "root", "-i", "lo", "-U", "-s", "0",
                "-w", capture, "host", self.address,
            ],
            cwd=self.project, env=self.env, text=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=open(self.host_path(f"{name}.tcpdump.log"), "w", encoding="utf-8"),
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

    def check_preflight(self) -> None:
        for port, transport in (("5060", "udp"), ("5060", "tcp"), ("5061", "tls")):
            result = self.run("--practice", "preflight", self.address, port, transport, timeout=60)
            self.record(
                f"launcher preflight {transport}",
                result.returncode == 0 and "SIP/2.0 200 OK" in result.stdout,
                f"exit {result.returncode}",
            )
        for port, transport in (("5099", "udp"), ("5099", "tcp")):
            result = self.run("--practice", "preflight", self.address, port, transport, timeout=60)
            self.record(
                f"launcher preflight {transport} against a closed port fails",
                result.returncode != 0,
                f"exit {result.returncode}",
            )

    def check_host_network_name_resolution(self) -> None:
        # The practice route never uses the host network, so check the
        # host-network fix directly: the fixed toolbox hostname must resolve
        # there (sipsak needs it). getent reads /etc/hosts and sends nothing.
        result = self.run("--", "getent", "hosts", "sippycup", timeout=60)
        self.record(
            "host-network toolbox resolves its fixed hostname",
            result.returncode == 0 and "sippycup" in result.stdout,
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
            and all(item.get("ok") and item.get("detail") == "SIP/2.0 200 OK" for item in preflight),
            {"exit": executed.returncode, "preflight": [item.get("detail") for item in preflight],
             "stderr": executed.stderr.strip()[-300:] or None},
        )
        self.record(
            "campaign execute succeeded with both OPTIONS steps",
            result.get("state") == "succeeded" and result.get("completedSteps") == 2,
            result,
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

    def execute(self) -> dict[str, Any]:
        try:
            self.ensure_target()
            self.check_profile()
            self.check_preflight()
            self.check_host_network_name_resolution()
            self.check_campaign()
            self.check_unauthenticated_invite()
            self.check_authenticated_call()
            self.check_wrong_password()
            self.check_rejections()
            self.check_tls()
            self.check_srtp()
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
