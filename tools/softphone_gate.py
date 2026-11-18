#!/usr/bin/env python3
"""Live softphone gate: DTMF, SRTP, registration status, and media scope.

It reuses the practice gate's helpers (launcher, capture, tshark, target
lifecycle) by import and runs only against the loopback practice target, plus
one PJSUA auto-answer peer inside a single isolated container for the SRTP
negative case. Evidence is kept under ``work/practice/softphone-gate-<UTC>/``.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tools"))

import practice_gate  # noqa: E402
from practice_gate import LAUNCHER, GateFailure  # noqa: E402

from sippycup import practice  # noqa: E402

DTMF_DIGITS = "159#*0AD"
DTMF_REQUEST = "159#,*0AD"
CAMPAIGN_DTMF = "2468"
SRTP_PEER_PORT = 5062
SDES_WARNING = "sdes-key-exposed-on-cleartext-signaling"

# One isolated container: a PJSUA auto-answer peer with SRTP disabled on
# 127.0.0.2:5062, and the real guided call with --srtp mandatory against it.
SRTP_NEGATIVE_SCRIPT = r"""#!/usr/bin/env bash
set -euo pipefail
root="$1"
mkfifo -m 0600 "${root}/peer.stdin"
sleep 120 >"${root}/peer.stdin" &
holder=$!
pjsua --null-audio --no-color --no-vad --bound-addr=127.0.0.2 --ip-addr=127.0.0.2 \
    --local-port=@PORT@ --no-tcp --auto-answer=200 --auto-loop --max-calls=1 \
    --add-codec=PCMU --use-srtp=0 --rtp-port=20000 --log-file="${root}/peer.log" \
    --log-level=4 --app-log-level=0 <"${root}/peer.stdin" >"${root}/peer.out" 2>&1 &
peer=$!
trap 'kill "${peer}" "${holder}" 2>/dev/null || true' EXIT
for _ in $(seq 100); do
    ss -Hlun "src 127.0.0.2:@PORT@" 2>/dev/null | grep -q . && break
    sleep 0.05
done
from="$(date -u -d '-5 minutes' +%Y-%m-%dT%H:%M:%SZ)"
until="$(date -u -d '+30 minutes' +%Y-%m-%dT%H:%M:%SZ)"
cat >"${root}/profile.yaml" <<YAML
schema_version: sippycup.dev/target-profile/v1
name: softphone-gate-plain-peer
target: {host: 127.0.0.2, port: @PORT@, transport: udp, approved_addresses: [127.0.0.2]}
authorization:
  status: approved
  approved_by: softphone-gate
  approval_id: SOFTPHONE-GATE-LOOPBACK
  valid_from: "${from}"
  valid_until: "${until}"
limits: {max_calls: 1, max_concurrency: 1, max_calls_per_second: 1, max_duration_seconds: 10}
capture: {interface: any, output: work/softphone-gate.pcap}
features: {ice: false, turn: false, srtp: false, dtls_srtp: false, webrtc: false}
YAML
chmod 0600 "${root}/profile.yaml"
set +e
sippycup-call "${root}/profile.yaml" --dial echo --duration 4 --srtp mandatory \
    --run-root "${root}/calls" --format json >"${root}/call.json" 2>"${root}/call.stderr"
echo "exit=$?" >"${root}/call.exit"
"""


class SoftphoneGate(practice_gate.Gate):
    """The practice gate's helpers plus softphone-specific checks."""

    def ensure_target(self) -> None:
        super().ensure_target()
        assert self.gate_dir is not None
        # Keep softphone evidence apart from practice-gate runs.
        renamed = self.gate_dir.with_name("softphone-" + self.gate_dir.name)
        self.gate_dir.rename(renamed)
        self.gate_dir = renamed

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

    def run_dir(self, value: dict[str, Any]) -> Path:
        return self.project / str(value.get("runDirectory"))

    def capture_digits(self, capture: str, peer: str) -> dict[str, str]:
        """Digits per direction, decoded by tshark's own rtpevent dissector."""
        result = self.run(
            "--practice", "--", "tshark", "-n", "-r", capture, "-Y", "rtpevent",
            "-T", "fields", "-e", "ip.src", "-e", "rtp.ssrc", "-e", "rtp.timestamp",
            "-e", "rtpevent.event_id",
        )
        if result.returncode != 0:
            raise GateFailure(f"tshark failed: {result.stderr.strip()[:300]}")
        digits = {"outbound": "", "inbound": ""}
        seen: set[tuple[str, str, str]] = set()
        names = "0123456789*#ABCD"
        for line in result.stdout.splitlines():
            fields = line.split("\t")
            if len(fields) < 4 or not fields[3].isdigit():
                continue
            key = (fields[0], fields[1], fields[2])
            if key in seen:
                continue
            seen.add(key)
            direction = "inbound" if fields[0] == peer else "outbound"
            event = int(fields[3])
            digits[direction] += names[event] if event < len(names) else "?"
        return digits

    # -- checks ----------------------------------------------------------
    def check_dtmf_guided(self) -> None:
        status, value = self.guided(
            "work/practice/target-profile.yaml", "dtmf",
            "--dial", "dtmf", "--username", "practice",
            "--secret-file", "work/practice/account.password",
            "--duration", "14", "--dtmf", DTMF_REQUEST, "--dtmf-after", "1",
        )
        dtmf = value.get("dtmf") or {}
        self.record(
            f"guided DTMF call to the dtmf destination passes; digits {DTMF_DIGITS} verified "
            "on the wire",
            status == 0 and value.get("verdict") == "pass"
            and dtmf.get("method") == "rfc4733" and dtmf.get("status") == "sent"
            and dtmf.get("verified") is True and dtmf.get("sentSource") == "capture"
            and dtmf.get("sent") == DTMF_DIGITS and dtmf.get("negotiated") is True,
            {"exit": status, "verdict": value.get("verdict"),
             "dtmf": {key: dtmf.get(key) for key in ("status", "sent", "echoed", "verified")}},
        )
        self.record(
            "the practice target echoed the same digits back as RFC 4733 events",
            dtmf.get("echoed") == DTMF_DIGITS and dtmf.get("pjsuaReceived") == DTMF_DIGITS,
            {"echoed": dtmf.get("echoed"), "pjsua_received": dtmf.get("pjsuaReceived")},
        )
        capture = "/" + str(Path(str(value.get("runDirectory"))) / "capture.pcap")
        digits = self.capture_digits(capture, self.address)
        self.record(
            "independent tshark rtpevent decode: sent == echoed == requested",
            digits == {"outbound": DTMF_DIGITS, "inbound": DTMF_DIGITS},
            digits,
        )
        oracle = value.get("oracle") or {}
        assert_path = self.run_dir(value) / "assert.json"
        assertions = {}
        with contextlib.suppress(OSError, ValueError):
            document = json.loads(assert_path.read_text(encoding="utf-8"))
            assertions = {item["id"]: item["verdict"] for item in document.get("assertions", [])}
        self.record(
            "oracle require_dtmf: media.dtmf passes and timing checks ignore event packets",
            oracle.get("verdict") == "pass"
            and any(key.endswith("media.dtmf") and verdict == "pass" for key, verdict in assertions.items()),
            {key: verdict for key, verdict in assertions.items() if "dtmf" in key or "jitter" in key},
        )

    def check_wrong_password_status(self) -> None:
        wrong = self.host_path("wrong.password")
        practice.write_private(wrong, "wrong-" + os.urandom(8).hex() + "\n")
        capture_process, capture = self.start_capture("wrong-password.pcap")
        status, value = self.guided(
            "work/practice/target-profile.yaml", "wrong-password",
            "--dial", "echo", "--username", "practice",
            "--secret-file", self.work_path("wrong.password"), "--duration", "5",
        )
        self.stop_capture(capture_process)
        softphone = value.get("softphone") or {}
        self.record(
            "guided call with a wrong password reports registration status 401",
            status == 1 and value.get("verdict") == "registration-failed"
            and softphone.get("registered") is False and softphone.get("registration_status") == 401
            and any("401" in note for note in value.get("notes", [])),
            {"exit": status, "verdict": value.get("verdict"),
             "status": softphone.get("registration_status")},
        )
        attempts = self.tshark_count(capture, 'sip.Method == "REGISTER" && sip.Authorization')
        rejected = self.tshark_count(capture, 'sip.Status-Code == 401 && sip.CSeq.method == "REGISTER"')
        self.record(
            "capture: exactly one credentialed REGISTER, and REGISTER answered 401",
            attempts == 1 and rejected >= 1, {"credentialed": attempts, "401": rejected},
        )

    def check_srtp_tls(self) -> None:
        status, value = self.guided(
            "work/practice/target-profile-tls.yaml", "srtp-tls",
            "--dial", "echo", "--username", "practice",
            "--secret-file", "work/practice/account.password",
            "--duration", "5", "--srtp", "mandatory",
        )
        srtp = value.get("srtp") or {}
        media = (value.get("tls") or {}).get("media") or {}
        self.record(
            "guided call with --srtp mandatory over TLS passes with RTP/SAVP negotiated",
            status == 0 and value.get("verdict") == "pass"
            and srtp.get("mode") == "mandatory" and srtp.get("active") is True
            and srtp.get("answerProfile") == "RTP/SAVP" and bool(srtp.get("suite"))
            and srtp.get("secureSignaling") is True and srtp.get("warning") is None
            and value.get("warnings") == []
            and (media.get("outbound") or 0) > 0 and (media.get("inbound") or 0) > 0,
            {"exit": status, "verdict": value.get("verdict"), "srtp": {
                key: srtp.get(key) for key in ("active", "suite", "answerProfile", "warning")
            }, "media": media},
        )
        log = (self.run_dir(value) / "softphone.log").read_text(encoding="utf-8", errors="replace") \
            if value.get("runDirectory") else ""
        self.record(
            "persisted softphone log keeps SDES keys redacted",
            "inline:<redacted>" in log and "a=crypto" in log
            and not any("inline:" in line and "inline:<redacted>" not in line for line in log.splitlines()),
        )

    def check_srtp_udp_warning(self) -> None:
        status, value = self.guided(
            "work/practice/target-profile.yaml", "srtp-udp",
            "--dial", "echo", "--username", "practice",
            "--secret-file", "work/practice/account.password",
            "--duration", "5", "--srtp", "mandatory",
        )
        srtp = value.get("srtp") or {}
        self.record(
            f"--srtp mandatory over UDP still runs SRTP and warns {SDES_WARNING}",
            status == 0 and value.get("verdict") == "pass" and srtp.get("active") is True
            and srtp.get("warning") == SDES_WARNING and value.get("warnings") == [SDES_WARNING]
            and ((srtp.get("media") or {}).get("inbound") or 0) > 0,
            {"exit": status, "verdict": value.get("verdict"), "warnings": value.get("warnings"),
             "media": srtp.get("media")},
        )

    def check_srtp_negative(self) -> None:
        root = self.host_path("srtp-negative")
        root.mkdir(mode=0o700)
        script = root / "run.sh"
        script.write_text(SRTP_NEGATIVE_SCRIPT.replace("@PORT@", str(SRTP_PEER_PORT)), encoding="utf-8")
        result = self.run(
            "--isolated", "--", "bash", self.container_path("srtp-negative/run.sh"),
            self.container_path("srtp-negative"), timeout=180,
        )
        try:
            value = json.loads((root / "call.json").read_text(encoding="utf-8") or "{}")
        except (OSError, ValueError):
            value = {}
        exit_text = (root / "call.exit").read_text(encoding="utf-8").strip() if (root / "call.exit").exists() else None
        softphone = value.get("softphone") or {}
        self.record(
            "--srtp mandatory against a plain-RTP PJSUA peer fails with srtp-not-negotiated",
            exit_text == "exit=1" and value.get("verdict") == "srtp-not-negotiated"
            and softphone.get("answered") is False and softphone.get("final_status") == 488
            and (value.get("srtp") or {}).get("active") is False,
            {"exit": exit_text, "verdict": value.get("verdict"), "final": softphone.get("final_status"),
             "stderr": result.stderr.strip()[-300:] or None},
        )

    def dtmf_manifest(self) -> str:
        import yaml

        document = yaml.safe_load(
            (practice.state_dir(self.project) / "campaign.yaml").read_text(encoding="utf-8")
        )
        authorization = document["authorization"]
        authorization["credentialRefs"] = ["practice-password"]
        authorization["signalingPorts"] = [5060]
        authorization["transports"] = ["udp"]
        authorization["ceilings"].update(
            calls=1, packets=2500, bytes=800000, durationSeconds=60,
            concurrentCalls=1, packetsPerSecond=400, callsPerSecond=1,
        )
        document["targets"] = [{
            "name": "practice-udp",
            "address": self.address,
            "signaling": {"transport": "udp", "port": 5060},
            "credentialRef": "practice-password",
            "account": {"username": "practice", "register": True},
            "media": {"srtp": "off"},
        }]
        document["cases"] = [{
            "id": "call-dtmf",
            "type": "call",
            "target": "practice-udp",
            "count": 1,
            "dial": {"user": "dtmf"},
            "call": {"dtmf": CAMPAIGN_DTMF, "dtmfAfterSeconds": 1, "durationSeconds": 10},
            "budget": {"packetsPerRun": 2400, "bytesPerRun": 800000, "durationSecondsPerRun": 16},
            "expectations": {
                "apiVersion": "sippycup.dev/case-expectations/v1",
                "finalStatus": 200,
                "requireBidirectionalRtp": True,
                "maxSetupSeconds": 5,
            },
        }]
        document["metadata"]["name"] = "softphone-gate-dtmf"
        document["evidence"]["directory"] = "evidence/softphone-gate-dtmf"
        # A headers-only capture (retainPayload false) keeps the RTP header
        # but not the RFC 4733 event code; the digits need the payload.
        document["evidence"]["retainPayload"] = True
        practice.write_private(self.host_path("campaign-dtmf.yaml"), yaml.safe_dump(document, sort_keys=False))
        return self.work_path("campaign-dtmf.yaml")

    def check_dtmf_campaign(self) -> None:
        manifest = self.dtmf_manifest()
        plan_path = self.work_path("plan-dtmf.json")
        planned = self.run("campaign", "plan", manifest, "--output", plan_path)
        self.record("campaign plan freezes the DTMF call case and target media", planned.returncode == 0,
                    planned.stderr.strip()[:300] or None)
        plan = json.loads(self.host_path("plan-dtmf.json").read_text(encoding="utf-8"))
        (step,) = plan["steps"]
        self.record(
            "frozen step carries call.dtmf and media.srtp",
            step.get("call") == {"dtmf": CAMPAIGN_DTMF, "dtmfAfterSeconds": 1, "durationSeconds": 10}
            and step.get("media") == {"srtp": "off"},
            {"call": step.get("call"), "media": step.get("media")},
        )
        environment = dict(self.env, SIPPYCUP_GATE_PRACTICE_SECRET=self.password())
        executed = subprocess.run(
            [str(LAUNCHER), "--practice", "campaign", "run", plan_path, "--manifest", manifest,
             "--run-root", self.work_path("runs-dtmf"), "--interface", "lo",
             "--secret-env", "practice-password=SIPPYCUP_GATE_PRACTICE_SECRET"],
            cwd=self.project, env=environment, text=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240, check=False,
        )
        runs = sorted(self.host_path("runs-dtmf").glob("*/result.json"))
        run_dir = runs[-1].parent if runs else None
        result = json.loads(runs[-1].read_text(encoding="utf-8")) if runs else {}
        lines = []
        if run_dir and (run_dir / "events.jsonl").exists():
            for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines():
                event = json.loads(line)
                if event.get("event") == "step.output" and event.get("stream") == "stdout":
                    with contextlib.suppress(ValueError):
                        lines.append(json.loads(event.get("text", "")))
        call = lines[0] if lines else {}
        dtmf = call.get("dtmf") or {}
        self.record(
            "--practice campaign run with a DTMF call case passes; runner reports rfc4733 sent "
            "and echoed",
            executed.returncode == 0 and result.get("state") == "succeeded"
            and call.get("outcome") == "passed" and dtmf.get("method") == "rfc4733"
            and dtmf.get("status") == "sent" and dtmf.get("sent") == CAMPAIGN_DTMF
            and dtmf.get("received") == CAMPAIGN_DTMF
            and (call.get("setup") or {}).get("inviteToAnswerSeconds") is not None,
            {"exit": executed.returncode, "state": result.get("state"), "outcome": call.get("outcome"),
             "reasons": call.get("reasons"), "dtmf": dtmf, "setup": call.get("setup"),
             "stderr": executed.stderr.strip()[-300:] or None},
        )
        captures = sorted(run_dir.rglob("*.pcap")) if run_dir else []
        capture = "/" + str(captures[0].relative_to(self.project)) if captures else ""
        digits = self.capture_digits(capture, self.address) if capture else {}
        self.record(
            "campaign capture: RFC 4733 digits sent == echoed == requested",
            digits == {"outbound": CAMPAIGN_DTMF, "inbound": CAMPAIGN_DTMF},
            {"capture": capture, "digits": digits},
        )
        # authorization.mediaPorts is the target's media range: the capture
        # filter admits RTP whose target-side port lies in it, so both
        # directions are captured whatever local port PJSUA chose.
        media = plan["authorization"]["mediaPorts"]
        local_port = call.get("localRtpPort")
        to_peer = self.tshark_count(
            capture, f"ip.dst == {self.address} && udp.dstport >= {media['start']} "
            f"&& udp.dstport <= {media['end']} && udp.srcport == {local_port}"
        ) if capture and local_port else 0
        from_peer = self.tshark_count(
            capture, f"ip.src == {self.address} && udp.srcport >= {media['start']} "
            f"&& udp.srcport <= {media['end']} && udp.dstport == {local_port}"
        ) if capture and local_port else 0
        self.record(
            "both RTP directions are captured on the target's authorized media ports; the "
            f"softphone's local RTP port is reported ({local_port})",
            isinstance(local_port, int) and to_peer > 100 and from_peer > 100,
            {"mediaPorts": media, "localRtpPort": local_port, "to_peer": to_peer, "from_peer": from_peer},
        )
        self.record(
            "the practice password appears nowhere in the DTMF campaign evidence",
            run_dir is not None and not any(
                self.password() in path.read_text(encoding="utf-8", errors="replace")
                for path in run_dir.rglob("*") if path.is_file() and path.suffix != ".pcap"
            ),
        )

    def execute(self) -> dict[str, Any]:
        ok = False
        try:
            self.ensure_target()
            self.check_dtmf_guided()
            self.check_wrong_password_status()
            self.check_srtp_tls()
            self.check_srtp_udp_warning()
            self.check_srtp_negative()
            self.check_dtmf_campaign()
            ok = True
        except GateFailure:
            ok = False
        finally:
            summary = {
                "schema_version": "sippycup.dev/softphone-gate/v1",
                "ok": ok and all(item["ok"] for item in self.checks) and bool(self.checks),
                "checks": self.checks,
                "evidence": str(self.gate_dir.relative_to(self.project)) if self.gate_dir else None,
                "network_activity": "loopback inside the practice namespace and one isolated container only",
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
        print(f"softphone gate cannot run: {reason}", file=sys.stderr)
        return 2
    summary = SoftphoneGate().execute()
    passed = sum(1 for item in summary["checks"] if item["ok"])
    print(f"softphone gate: {'PASS' if summary['ok'] else 'FAIL'} "
          f"({passed}/{len(summary['checks'])} checks); evidence {summary['evidence']}")
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
