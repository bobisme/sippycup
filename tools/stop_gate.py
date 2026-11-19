#!/usr/bin/env python3
"""Live gate for ``./bin/sippycup stop`` against the local practice target.

Opt-in (``make stop-gate``); needs the core and practice images. Loopback
only, inside the practice namespace. It builds a throwaway practice
engagement with long calls (scope answers, scope compile, ``ready`` GO), then
starts each long-running sender through the public launcher and stops it
mid-flight with ``./bin/sippycup stop``:

1. a guided call (60 s, answered by echo),
2. a call matrix (two cells; stopped in the first),
3. a campaign whose call steps run on the softphone runner,
4. a security checks run (stopped while its checks are running).

For each it asserts: ``stop`` found exactly that container by its checkout
label, it ended after SIGTERM (clean, not forced), silence was proved, the
command's run directory records ``cancelled`` (never half-written), and,
for the calls, the capture shows our BYE and no RTP from us after it.

It starts the practice target only when it is not up, and takes it down only
if it started it. Every artifact stays under work/practice/stop-gate-*/.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tools"))

import yaml  # noqa: E402

from practice_gate import images_available  # noqa: E402
from sippycup import practice  # noqa: E402
from sippycup.practice_rehearsal import (  # noqa: E402
    CREDENTIAL_REF, LAUNCHER, PASSWORD_FILE, CannotStart, Rehearsal, RehearsalError, Stage,
)

CALL_SECONDS = 60
SECRET_ENV = "SIPPYCUP_STOP_GATE_SECRET"


class GateFailure(AssertionError):
    pass


class StopGate:
    def __init__(self) -> None:
        self.rehearsal = Rehearsal(ROOT)
        self.checks: list[dict[str, Any]] = []
        self.samples: dict[str, Any] = {}

    # -- helpers ---------------------------------------------------------
    def record(self, name: str, ok: bool, detail: Any = None) -> None:
        self.checks.append({"check": name, "ok": bool(ok), "detail": detail})
        print(f"{'PASS' if ok else 'FAIL'} {name}" + (f": {detail}" if detail is not None and not ok else ""),
              flush=True)
        if not ok:
            raise GateFailure(f"{name}: {detail}")

    @property
    def eng(self) -> str:
        return self.rehearsal.eng

    @property
    def root(self) -> Path:
        assert self.rehearsal.engagement is not None
        return self.rehearsal.engagement

    def run(self, *arguments: str, env: dict[str, str] | None = None, timeout: float = 300) -> subprocess.CompletedProcess:
        return subprocess.run([str(ROOT / "bin" / "sippycup"), *arguments], cwd=ROOT,
                              env={**os.environ, **(env or {})}, text=True, stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=timeout, check=False)

    def background(self, label: str, *arguments: str, env: dict[str, str] | None = None) -> tuple[subprocess.Popen, Path]:
        log = self.root / "stop-gate" / f"{label}.out"
        output = log.open("w", encoding="utf-8")
        process = subprocess.Popen([str(ROOT / "bin" / "sippycup"), *arguments], cwd=ROOT,
                                   env={**os.environ, **(env or {})}, text=True, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT)
        output.close()
        return process, log

    def stop_now(self, label: str) -> dict[str, Any]:
        result = self.run("stop", "--grace", "60", "--engagement", self.eng, "--format", "json", timeout=200)
        (self.root / "stop-gate" / f"{label}-stop.json").write_text(result.stdout, encoding="utf-8")
        text = self.run("stop", "--dry-run")  # after the stop: must list nothing of this checkout
        try:
            report = json.loads(result.stdout)
        except ValueError as error:
            raise GateFailure(f"stop printed no JSON: {result.stderr[-300:]}") from error
        report["exit"] = result.returncode
        report["afterwards"] = text.stdout
        return report

    def wait_for(self, predicate, seconds: float, what: str) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.5)
        raise GateFailure(f"timed out waiting for {what}")

    def assert_stop(self, label: str, report: dict[str, Any], command: str) -> None:
        targets = [item for item in report.get("targets", []) if item["kind"] == "container"]
        self.record(f"{label}: stop found exactly one container of this checkout running '{command}'",
                    len(targets) == 1 and targets[0]["detail"].startswith(f"{command}:")
                    and targets[0]["matchedBy"] == "label",
                    [(item["name"], item["detail"]) for item in targets])
        self.record(f"{label}: it ended after SIGTERM within the grace period (clean, not forced)",
                    targets[0]["outcome"] == "clean", targets[0])
        self.record(f"{label}: silence proved and stop exited 0",
                    report.get("exit") == 0 and report["silence"].get("proved") is True, report.get("silence"))
        self.record(f"{label}: the practice target was left alone",
                    report.get("practice") is None and any("practice" in item for item in report.get("untouched", [])),
                    report.get("untouched"))
        self.record(f"{label}: stop --dry-run afterwards lists no sender of this checkout",
                    "No Sippycup sender from this checkout is running." in report["afterwards"],
                    report["afterwards"][-300:])

    def tshark(self, capture: str, display: str, fields: list[str]) -> list[list[str]]:
        argv = ["--practice", "--", "tshark", "-n", "-r", capture, "-Y", display, "-T", "fields"]
        for name in fields:
            argv += ["-e", name]
        result = self.run(*argv, timeout=120)
        if result.returncode != 0:
            raise GateFailure(f"tshark failed: {result.stderr.strip()[-300:]}")
        return [line.split("\t") for line in result.stdout.splitlines() if line.strip()]

    def assert_bye_and_silence(self, label: str, capture_host: Path) -> None:
        capture = "/work/" + capture_host.relative_to(ROOT / "work").as_posix()
        target = self.rehearsal.facts["address"]
        byes = self.tshark(capture, f'sip.Method == "BYE" && ip.dst == {target}', ["frame.time_epoch"])
        oks = self.tshark(capture, f'sip.Status-Code == 200 && sip.CSeq.method == "BYE" && ip.src == {target}',
                          ["frame.time_epoch"])
        rtp = self.tshark(capture, f"udp && ip.dst == {target} && rtp.version == 2", ["frame.time_epoch"])
        if not rtp:
            rtp = self.tshark(capture, f"udp && ip.dst == {target} && !sip", ["frame.time_epoch"])
        bye_time = float(byes[0][0]) if byes else None
        late = [row for row in rtp if bye_time is not None and float(row[0]) > bye_time + 0.5]
        self.samples[label] = {"bye": len(byes), "byeOk": len(oks), "rtpToTarget": len(rtp),
                               "rtpAfterBye": len(late),
                               "lastRtpBeforeBye": (round(bye_time - float(rtp[-1][0]), 3)
                                                    if rtp and bye_time and not late else None)}
        self.record(f"{label}: the capture shows our BYE to {target} and its 200 OK", bool(byes) and bool(oks),
                    self.samples[label])
        self.record(f"{label}: RTP flowed before the stop and none was sent after the BYE",
                    len(rtp) > 50 and not late, self.samples[label])

    def newest(self, directory: Path, marker: str) -> Path | None:
        found = sorted(directory.glob(f"*/{marker}"))
        return found[-1].parent if found else None

    # -- setup -----------------------------------------------------------
    def setup(self) -> None:
        reh = self.rehearsal
        reh.current = Stage(0, "stop-gate setup")
        reh.target_up()
        self.record("practice target up", True)
        reh.create_engagement()
        reh.write_answers(reh.shape)
        scope_path = self.root / "scope.yaml"
        document = yaml.safe_load(scope_path.read_text(encoding="utf-8"))
        document["limits"].update(call_duration_seconds=CALL_SECONDS + 30, total_duration_seconds=1800,
                                  packets=200000, bytes=40000000, calls=12)
        practice.write_private(scope_path, yaml.safe_dump(document, sort_keys=False))
        reh.compile_scope()
        (self.root / "stop-gate").mkdir(mode=0o700)
        ready = self.run("ready", self.eng, "--secret-file", PASSWORD_FILE, "--format", "json", timeout=180)
        value = json.loads(ready.stdout or "{}")
        self.record("ready says GO for the practice engagement", ready.returncode == 0 and value.get("verdict") == "GO",
                    [(item["id"], item["status"], item["lines"][:1]) for item in value.get("checks", [])])
        before = self.run("stop", "--dry-run", "--format", "json")
        self.record("before any sender: stop --dry-run finds nothing of this checkout running",
                    before.returncode == 0 and json.loads(before.stdout)["targets"] == [], before.stdout[-400:])

    # -- scenarios ---------------------------------------------------------
    def scenario_call(self) -> None:
        runs = self.root / "stop-calls"
        process, log = self.background(
            "call", "--practice", "call", f"{self.eng}/target-profile.yaml", "--dial", "echo",
            "--duration", str(CALL_SECONDS), "--username", practice.ACCOUNT, "--secret-file", PASSWORD_FILE,
            "--run-root", f"{self.eng}/stop-calls", "--format", "json")
        self.wait_for(lambda: self.newest(runs, "capture.pcap") is not None, 60, "the call's capture")
        time.sleep(15)  # well inside the answered 60 s call
        self.record("call: still running 15 s into the call", process.poll() is None, log.read_text()[-400:])
        report = self.stop_now("call")
        code = process.wait(timeout=120)
        self.assert_stop("call", report, "call")
        run = self.newest(runs, "result.json")
        result = json.loads((run / "result.json").read_text(encoding="utf-8")) if run else {}
        self.record("call: exit 143 and result.json records state cancelled",
                    code == 143 and result.get("state") == "cancelled",
                    {"exit": code, "state": result.get("state"), "verdict": result.get("verdict")})
        self.record("call: the run is complete on disk (capture, softphone record, evidence manifest written)",
                    all((run / name).is_file() for name in ("capture.pcap", "softphone.json",
                                                            "evidence-manifest.json", "timestamps.json")),
                    sorted(item.name for item in run.iterdir()))
        self.assert_bye_and_silence("call", run / "capture.pcap")
        self.samples["call"]["runDirectory"] = run.relative_to(ROOT).as_posix()

    def scenario_matrix(self) -> None:
        process, log = self.background(
            "matrix", "--practice", "matrix", "run", f"{self.eng}/target-profile.yaml", "--dial", "echo",
            "--codecs", "PCMU,PCMA", "--duration", str(CALL_SECONDS), "--username", practice.ACCOUNT,
            "--secret-file", PASSWORD_FILE, "--run-root", f"{self.eng}/stop-matrix-calls",
            "--matrix-root", f"{self.eng}/stop-matrix", "--format", "json")
        calls = self.root / "stop-matrix-calls"
        self.wait_for(lambda: self.newest(calls, "capture.pcap") is not None, 60, "the first matrix cell")
        time.sleep(15)
        self.record("matrix: still running inside the first cell", process.poll() is None, log.read_text()[-400:])
        report = self.stop_now("matrix")
        code = process.wait(timeout=120)
        self.assert_stop("matrix", report, "matrix")
        record = sorted((self.root / "stop-matrix").glob("*/matrix.json"))
        value = json.loads(record[-1].read_text(encoding="utf-8")) if record else {}
        cells = value.get("cells") or []
        self.record("matrix: exit 143, matrix.json state cancelled, first cell cancelled, the rest not-run",
                    code == 143 and value.get("state") == "cancelled" and len(cells) == 2
                    and cells[1].get("status") == "not-run" and cells[0].get("verdict") == "cancelled",
                    {"exit": code, "state": value.get("state"),
                     "cells": [(cell.get("codec"), cell.get("status"), cell.get("verdict")) for cell in cells]})
        run = self.newest(calls, "result.json")
        self.assert_bye_and_silence("matrix", run / "capture.pcap")

    def scenario_campaign(self) -> None:
        # The compiled manifest's calls last the runner's default 5 s; make the
        # UDP call long enough to be stopped mid-call (a reviewed manifest
        # field). A compiled manifest is never edited (senders refuse it,
        # bn-zqe8): the gate writes its own hand-written copy beside its logs.
        manifest = yaml.safe_load((self.root / "campaign.yaml").read_text(encoding="utf-8"))
        manifest_path = self.root / "stop-gate" / "campaign-long-call.yaml"
        manifest_work = f"{self.eng}/stop-gate/campaign-long-call.yaml"
        case = next(item for item in manifest["cases"] if item["id"] == "practice-udp-call")
        case["call"] = {"codecs": ["PCMU"], "durationSeconds": CALL_SECONDS}
        case["budget"].update(durationSecondsPerRun=CALL_SECONDS + 20, packetsPerRun=8000, bytesPerRun=2000000)
        practice.write_private(manifest_path, yaml.safe_dump(manifest, sort_keys=False))
        planned = self.run("campaign", "plan", manifest_work, "--output", f"{self.eng}/plan.json")
        self.record("campaign plan frozen", planned.returncode == 0, planned.stderr[-300:])
        plan = json.loads((self.root / "plan.json").read_text(encoding="utf-8"))
        kinds = ["call" if step.get("dial") else "options" for step in plan.get("steps", [])]
        runs = self.root / "runs"
        process, log = self.background(
            "campaign", "--practice", "campaign", "run", f"{self.eng}/plan.json", "--manifest",
            manifest_work, "--run-root", f"{self.eng}/runs", "--interface", "lo",
            "--secret-env", f"{CREDENTIAL_REF}={SECRET_ENV}", env={SECRET_ENV: self.rehearsal.password()})

        def in_call() -> bool:
            run = self.newest(runs, "events.jsonl")
            if run is None:
                return False
            for line in (run / "events.jsonl").read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                step = plan["steps"][int(event.get("step") or 0) - 1] if event.get("step") else {}
                if event.get("event") == "step.started" and step.get("dial"):
                    return True
            return False
        self.wait_for(in_call, 120, "the campaign's first softphone call step")
        time.sleep(12)  # inside the 60 s UDP call
        self.record("campaign: still running inside a softphone call step", process.poll() is None,
                    log.read_text()[-400:])
        report = self.stop_now("campaign")
        code = process.wait(timeout=120)
        self.assert_stop("campaign", report, "campaign")
        run = self.newest(runs, "result.json")
        result = json.loads((run / "result.json").read_text(encoding="utf-8")) if run else {}
        events = (run / "events.jsonl").read_text(encoding="utf-8") if run else ""
        self.record("campaign: exit 143, result.json state cancelled, the cancellation is an event",
                    code == 143 and result.get("state") == "cancelled" and "campaign.cancelled" in events,
                    {"exit": code, "state": result.get("state"), "completedSteps": result.get("completedSteps"),
                     "steps": kinds})
        captures = sorted(run.rglob("*.pcap*")) if run else []
        self.samples["campaign"] = {"runDirectory": run.relative_to(ROOT).as_posix() if run else None,
                                    "captures": [item.relative_to(run).as_posix() for item in captures]}
        self.record("campaign: the run directory holds its capture", (run / "capture.pcap").is_file(),
                    self.samples["campaign"])
        self.assert_bye_and_silence("campaign", run / "capture.pcap")

    def scenario_checks(self) -> None:
        runs = self.root / "stop-checks"
        process, log = self.background(
            "checks", "--practice", "checks", "run", f"{self.eng}/target-profile.yaml", "--secret-file",
            PASSWORD_FILE, "--run-root", f"{self.eng}/stop-checks", "--only", "srtp-policy", "--only",
            "banner-disclosure", "--format", "json")
        self.wait_for(lambda: any(runs.glob("*")) if runs.is_dir() else False, 60, "the checks run directory")
        time.sleep(4)
        self.record("checks: still running", process.poll() is None, log.read_text()[-400:])
        report = self.stop_now("checks")
        code = process.wait(timeout=120)
        self.assert_stop("checks", report, "checks")
        run = sorted(runs.glob("*"))[-1]
        result = json.loads((run / "result.json").read_text(encoding="utf-8")) if (run / "result.json").is_file() else {}
        # The checks runner documents an interruption as exit 3 (run error), not 128+15.
        self.record("checks: exit 3 (interruption) and result.json records state cancelled; findings.json written",
                    code == 3 and result.get("exitCode") == 3 and result.get("state") == "cancelled" and (run / "findings.json").is_file(),
                    {"exit": code, "state": result.get("state"), "files": sorted(item.name for item in run.iterdir())})

    def teardown(self) -> None:
        self.rehearsal.teardown()

    def execute(self) -> int:
        failure = None
        try:
            self.setup()
            for scenario in (self.scenario_call, self.scenario_matrix, self.scenario_campaign, self.scenario_checks):
                scenario()
        except (GateFailure, RehearsalError, CannotStart, subprocess.TimeoutExpired, OSError, ValueError,
                KeyError) as error:
            failure = str(error)
        finally:
            leftover = self.run("stop", "--format", "json", "--grace", "20")  # never leave a sender behind
            self.teardown()
        summary = {"ok": failure is None, "failure": failure, "checks": self.checks, "samples": self.samples,
                   "engagement": self.eng if self.rehearsal.engagement else None,
                   "finalStopExit": leftover.returncode,
                   "finishedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        if self.rehearsal.engagement is not None and (self.root / "stop-gate").is_dir():
            practice.write_private(self.root / "stop-gate" / "summary.json", json.dumps(summary, indent=2) + "\n")
        print(json.dumps({"samples": self.samples}, indent=2))
        passed = sum(1 for item in self.checks if item["ok"])
        print(f"Stop gate: {'PASS' if failure is None else 'FAIL'} ({passed}/{len(self.checks)} checks)"
              + (f"; {failure}" if failure else ""))
        print("Network activity: loopback inside the practice namespace only")
        return 0 if failure is None else 1


def main() -> int:
    ok, reason = images_available()
    if not ok:
        print(f"stop gate: {reason}", file=sys.stderr)
        return 2
    return StopGate().execute()


if __name__ == "__main__":
    raise SystemExit(main())
