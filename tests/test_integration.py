from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup.campaign import compile_plan
from sippycup.integration import (
    CaptureWatchdog,
    execute_campaign,
    resolve_secrets,
    strip_media_payload,
)
from sippycup.runtime import RuntimeError


FIXTURES = ROOT / "tests" / "fixtures" / "campaign"
TOOL = FIXTURES / "integration-tool.py"
PROVIDER = FIXTURES / "secret-provider.py"


def one_call_plan(*, credential: bool = False, max_packets: int = 100):
    manifest = yaml.safe_load((FIXTURES / "valid.yaml").read_bytes())
    manifest["targets"][0]["address"] = "127.0.0.1"
    manifest["authorization"]["networks"] = ["127.0.0.0/8"]
    manifest["cases"] = [copy.deepcopy(manifest["cases"][1])]
    manifest["authorization"]["ceilings"]["packets"] = max_packets
    manifest["authorization"]["ceilings"]["packetsPerSecond"] = min(20, max_packets)
    manifest["cases"][0]["budget"]["packetsPerRun"] = min(
        manifest["cases"][0]["budget"]["packetsPerRun"], max_packets
    )
    manifest["authorization"]["ceilings"]["bytes"] = 100_000
    manifest["authorization"]["ceilings"]["durationSeconds"] = 30
    if not credential:
        manifest["targets"][0].pop("credentialRef")
        manifest["authorization"]["credentialRefs"] = []
    raw = yaml.safe_dump(manifest, sort_keys=True).encode()
    return compile_plan(manifest, hashlib.sha256(raw).hexdigest()), raw


class IntegrationTests(unittest.TestCase):
    def execute(self, planned, *, preflight, secrets=None):
        plan, manifest_bytes = planned
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        order = root / "order.txt"
        capture = [
            sys.executable,
            str(TOOL),
            "capture",
            "{capture}",
            str(order),
        ]
        runner = [sys.executable, str(TOOL), "runner", str(order)]
        report = [sys.executable, str(TOOL), "report", "{capture}"]
        result, run_dir = execute_campaign(
            plan,
            manifest_bytes=manifest_bytes,
            run_root=root / "runs",
            runner=runner,
            capture_command=capture,
            report_command=report,
            preflight=preflight,
            secret_values=secrets,
            allow_test_runner=True,
        )
        return result, run_dir, order

    def test_one_call_run_has_complete_evidence_and_order(self):
        seen_capture = []

        def preflight(_destination):
            seen_capture.append(True)
            return True, "SIP/2.0 200 OK"

        result, run_dir, order = self.execute(
            one_call_plan(), preflight=preflight
        )
        self.assertEqual(result.state, "succeeded")
        self.assertEqual(
            order.read_text().splitlines(),
            ["capture-start", "call", "capture-stop"],
        )
        self.assertTrue(seen_capture)
        required = {
            "capture.log",
            "capture.pcap",
            "commands.json",
            "events.jsonl",
            "plan.json",
            "preflight.json",
            "report.stderr",
            "report.txt",
            "reviewed-manifest.yaml",
            "result.json",
            "timestamps.json",
            "versions.json",
        }
        self.assertTrue(required.issubset({path.name for path in run_dir.iterdir()}))
        self.assertIn("capture parsed", (run_dir / "report.txt").read_text())
        self.assertEqual(run_dir.stat().st_uid, os.getuid())
        self.assertEqual(run_dir.stat().st_mode & 0o777, 0o700)

    def test_failed_preflight_sends_no_call_and_still_tears_down_capture(self):
        result, run_dir, order = self.execute(
            one_call_plan(),
            preflight=lambda _destination: (False, "timeout"),
        )
        self.assertEqual(result.state, "preflight_failed")
        self.assertEqual(
            order.read_text().splitlines(),
            ["capture-start", "capture-stop"],
        )
        self.assertFalse((run_dir / "events.jsonl").exists())
        self.assertEqual(json.loads((run_dir / "result.json").read_text())["completedSteps"], 0)

    def test_fixture_secret_never_appears_in_artifacts_or_argv(self):
        secret = "correct horse fixture battery staple"
        result, run_dir, _order = self.execute(
            one_call_plan(credential=True),
            preflight=lambda _destination: (True, "SIP/2.0 401 Unauthorized"),
            secrets={"staging-user": secret},
        )
        self.assertEqual(result.state, "succeeded")
        for path in run_dir.iterdir():
            if path.is_file():
                self.assertNotIn(secret.encode(), path.read_bytes(), path.name)
        commands = json.loads((run_dir / "commands.json").read_text())
        self.assertNotIn(secret, json.dumps(commands))
        self.assertNotIn(secret.encode(), _order.with_suffix(".argv").read_bytes())
        events = (run_dir / "events.jsonl").read_text()
        self.assertIn("step.output_truncated", events)

    def test_signal_during_preflight_stops_capture_without_starting_call(self):
        def interrupted_preflight(_destination):
            timer = threading.Timer(0.02, os.kill, args=(os.getpid(), signal.SIGTERM))
            timer.start()
            time.sleep(0.08)
            timer.join()
            return True, "SIP/2.0 200 OK"

        result, _run_dir, order = self.execute(
            one_call_plan(),
            preflight=interrupted_preflight,
        )
        self.assertEqual((result.state, result.exit_code), ("cancelled", 143))
        self.assertEqual(
            order.read_text().splitlines(),
            ["capture-start", "capture-stop"],
        )

    def test_ctrl_c_during_capture_startup_leaves_no_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "capture.pid"
            monitor = threading.Thread(
                target=_interrupt_when_ready,
                args=(marker, signal.SIGINT),
            )
            monitor.start()
            plan, manifest_bytes = one_call_plan()
            result, _run_dir = execute_campaign(
                plan,
                manifest_bytes=manifest_bytes,
                run_root=root / "runs",
                capture_command=[
                    sys.executable,
                    str(TOOL),
                    "capture-delay",
                    str(marker),
                ],
                report_command=[sys.executable, str(TOOL), "report"],
                preflight=lambda _destination: (True, "SIP/2.0 200 OK"),
                allow_test_runner=True,
            )
            monitor.join()
            self.assertEqual((result.state, result.exit_code), ("cancelled", 130))
            self.assertFalse(_process_is_running(int(marker.read_text())))

    def test_ctrl_c_during_report_is_bounded_and_preserves_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            order = root / "order.txt"
            marker = root / "report.pid"
            before_qdisc = _qdisc()
            monitor = threading.Thread(
                target=_interrupt_when_ready,
                args=(marker, signal.SIGINT),
            )
            monitor.start()
            plan, manifest_bytes = one_call_plan()
            result, run_dir = execute_campaign(
                plan,
                manifest_bytes=manifest_bytes,
                run_root=root / "runs",
                capture_command=[
                    sys.executable,
                    str(TOOL),
                    "capture",
                    "{capture}",
                    str(order),
                ],
                runner=[sys.executable, str(TOOL), "runner", str(order)],
                report_command=[
                    sys.executable,
                    str(TOOL),
                    "report-delay",
                    str(marker),
                ],
                preflight=lambda _destination: (True, "SIP/2.0 200 OK"),
                allow_test_runner=True,
            )
            monitor.join()
            self.assertEqual((result.state, result.exit_code), ("cancelled", 130))
            self.assertFalse(_process_is_running(int(marker.read_text())))
            self.assertEqual(order.read_text().splitlines()[-1], "capture-stop")
            self.assertEqual(_qdisc(), before_qdisc)
            self.assertEqual(
                json.loads((run_dir / "result.json").read_text())["state"],
                "cancelled",
            )

    def test_reviewed_manifest_rebind_precedes_every_side_effect(self):
        reviewed_plan, reviewed_bytes = one_call_plan()
        attacker_manifest = yaml.safe_load(reviewed_bytes)
        attacker_manifest["metadata"]["name"] = "self-authorized"
        attacker_bytes = yaml.safe_dump(attacker_manifest, sort_keys=True).encode()
        attacker_plan = compile_plan(
            attacker_manifest, hashlib.sha256(attacker_bytes).hexdigest()
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "must-not-exist"
            called = False

            def preflight(_destination):
                nonlocal called
                called = True
                return True, "unexpected"

            with self.assertRaisesRegex(RuntimeError, "SHA-256"):
                execute_campaign(
                    attacker_plan,
                    manifest_bytes=reviewed_bytes,
                    run_root=root,
                    preflight=preflight,
                )
            self.assertFalse(called)
            self.assertFalse(root.exists())
        self.assertNotEqual(attacker_plan, reviewed_plan)

    def test_active_execution_rejects_custom_runner_before_side_effects(self):
        plan, manifest_bytes = one_call_plan()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "must-not-exist"
            with self.assertRaisesRegex(RuntimeError, "custom runners"):
                execute_campaign(
                    plan,
                    manifest_bytes=manifest_bytes,
                    run_root=root,
                    runner=["/bin/true"],
                )
            self.assertFalse(root.exists())

    def test_live_watchdog_stops_buggy_runner_at_packet_ceiling(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            order = root / "order.txt"
            capture_pid = root / "capture.pid"
            runner_pid = root / "runner.pid"
            plan, manifest_bytes = one_call_plan(max_packets=5)
            result, run_dir = execute_campaign(
                plan,
                manifest_bytes=manifest_bytes,
                run_root=root / "runs",
                capture_command=[
                    sys.executable,
                    str(TOOL),
                    "capture-watchdog",
                    "{capture}",
                    str(order),
                    str(capture_pid),
                ],
                runner=[
                    sys.executable,
                    str(TOOL),
                    "runner-sleep",
                    str(order),
                    str(runner_pid),
                ],
                report_command=[sys.executable, str(TOOL), "report"],
                preflight=lambda _destination: (True, "SIP/2.0 200 OK"),
                allow_test_runner=True,
            )
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn(
                result.state,
                {"failed", "packet_ceiling_exceeded", "packet_rate_ceiling_exceeded"},
            )
            self.assertFalse(_process_is_running(int(runner_pid.read_text())))
            self.assertFalse(_process_is_running(int(capture_pid.read_text())))
            self.assertIn(
                "ceiling_exceeded",
                (run_dir / "result.json").read_text(),
            )

    def test_watchdog_enforces_every_traffic_dimension(self):
        cases = (
            ("packet_ceiling_exceeded", {"packets": 1}, [b"x", b"x"]),
            ("byte_ceiling_exceeded", {"bytes": 10}, [b"x" * 20]),
            (
                "packet_rate_ceiling_exceeded",
                {"packetsPerSecond": 1},
                [b"x", b"x"],
            ),
            (
                "call_ceiling_exceeded",
                {"calls": 1},
                [b"INVITE x", b"INVITE x"],
            ),
            (
                "call_rate_ceiling_exceeded",
                {"callsPerSecond": 1},
                [b"INVITE x", b"INVITE x"],
            ),
        )
        defaults = {
            "calls": 100,
            "packets": 100,
            "bytes": 100_000,
            "packetsPerSecond": 100,
            "callsPerSecond": 100,
        }
        for expected, override, packets in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                capture = Path(directory) / "watchdog.pcap"
                records = b"".join(
                    _pcap_record_at(packet, index)
                    for index, packet in enumerate(packets)
                )
                capture.write_bytes(
                    b"\xd4\xc3\xb2\xa1"
                    + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
                    + records
                )
                maxima = {**defaults, **override}
                watchdog = CaptureWatchdog(capture, maxima)
                watchdog.start()
                deadline = time.monotonic() + 1
                while watchdog.violation() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                watchdog.stop()
                self.assertEqual(watchdog.violation(), expected)

    def test_capture_death_during_step_fails_and_stops_runner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            order = root / "order.txt"
            capture_pid = root / "capture.pid"
            runner_pid = root / "runner.pid"
            plan, manifest_bytes = one_call_plan()
            result, _run_dir = execute_campaign(
                plan,
                manifest_bytes=manifest_bytes,
                run_root=root / "runs",
                capture_command=[
                    sys.executable,
                    str(TOOL),
                    "capture-die",
                    "{capture}",
                    str(capture_pid),
                ],
                runner=[
                    sys.executable,
                    str(TOOL),
                    "runner-sleep",
                    str(order),
                    str(runner_pid),
                ],
                report_command=[sys.executable, str(TOOL), "report"],
                preflight=lambda _destination: (True, "SIP/2.0 200 OK"),
                allow_test_runner=True,
            )
            self.assertEqual(result.state, "capture_process_died")
            self.assertFalse(_process_is_running(int(runner_pid.read_text())))

    def test_secret_source_environment_is_scrubbed_from_every_tool(self):
        secret = "environment-canary-secret"
        plan, manifest_bytes = one_call_plan(credential=True)
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ,
            {
                "NAMED_SECRET_SOURCE": secret,
                "SIPPYCUP_SECRET_OTHER": "other-canary",
            },
        ):
            root = Path(directory)
            order = root / "order.txt"
            report_environment = root / "report.env"
            result, _run_dir = execute_campaign(
                plan,
                manifest_bytes=manifest_bytes,
                run_root=root / "runs",
                capture_command=[
                    sys.executable,
                    str(TOOL),
                    "capture",
                    "{capture}",
                    str(order),
                ],
                runner=[sys.executable, str(TOOL), "runner", str(order)],
                report_command=[
                    sys.executable,
                    str(TOOL),
                    "report-env",
                    str(report_environment),
                ],
                preflight=lambda _destination: (True, "SIP/2.0 401 Unauthorized"),
                secret_values={"staging-user": secret},
                secret_env_names=["NAMED_SECRET_SOURCE"],
                allow_test_runner=True,
            )
            self.assertEqual(result.state, "succeeded")
            for environment_file in (
                order.with_suffix(".capture-env"),
                order.with_suffix(".runner-env"),
                report_environment,
            ):
                environment = environment_file.read_bytes()
                self.assertNotIn(secret.encode(), environment)
                self.assertNotIn(b"other-canary", environment)

    def test_retain_payload_false_removes_media_canary_but_keeps_sip(self):
        media_canary = b"AUDIO-CANARY-MUST-NOT-PERSIST"
        sip_marker = b"INVITE sip:loopback SIP/2.0"
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture.pcap"
            rtp_header = b"\x80\x00\x00\x01" + b"\0" * 8
            media = _udp_packet(10000, 10002, rtp_header + media_canary)
            signaling = _udp_packet(5060, 5099, sip_marker)
            capture.write_bytes(
                b"\xd4\xc3\xb2\xa1"
                + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
                + _pcap_record(media)
                + _pcap_record(signaling)
            )
            strip_media_payload(
                capture,
                {"start": 10000, "end": 10020},
                [5060, 5099],
            )
            sanitized = capture.read_bytes()
            self.assertNotIn(media_canary, sanitized)
            self.assertIn(sip_marker, sanitized)
            self.assertIn((10000).to_bytes(2, "big"), sanitized)

    def test_secret_sources_support_environment_fd_and_provider(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        os.write(write_fd, b"fd-value\n")
        os.close(write_fd)
        values = resolve_secrets(
            ["env-ref", "fd-ref"],
            environ={"NAMED_SECRET": "env-value"},
            env_names={"env-ref": "NAMED_SECRET"},
            fds={"fd-ref": read_fd},
        )
        self.assertEqual(values, {"env-ref": "env-value", "fd-ref": "fd-value"})
        provider_values = resolve_secrets(
            ["provider-ref"],
            environ={},
            provider=str(PROVIDER),
        )
        self.assertEqual(
            provider_values,
            {"provider-ref": "provider-value-for-provider-ref"},
        )

    def test_provider_is_bounded_scrubbed_and_kills_descendants(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment_marker = root / "provider.env"
            safe_provider = root / "safe-provider"
            safe_provider.write_text(
                "#!/usr/bin/env python3\n"
                "from pathlib import Path\n"
                f"Path({str(environment_marker)!r}).write_bytes(Path('/proc/self/environ').read_bytes())\n"
                "print('provider-safe-value')\n"
            )
            safe_provider.chmod(0o755)
            values = resolve_secrets(
                ["provider-ref"],
                environ={
                    "PATH": os.environ["PATH"],
                    "NAMED_SECRET_SOURCE": "provider-env-canary",
                    "SIPPYCUP_SECRET_OTHER": "other-provider-canary",
                },
                env_names={"unrelated-ref": "NAMED_SECRET_SOURCE"},
                provider=str(safe_provider),
            )
            self.assertEqual(values["provider-ref"], "provider-safe-value")
            provider_environment = environment_marker.read_bytes()
            self.assertNotIn(b"provider-env-canary", provider_environment)
            self.assertNotIn(b"other-provider-canary", provider_environment)

            overflow_provider = root / "overflow-provider"
            overflow_provider.write_text(
                "#!/usr/bin/env python3\n"
                "import sys,time\n"
                "sys.stdout.buffer.write(b'x' * (1024 * 1024 + 2)); sys.stdout.flush()\n"
                "time.sleep(60)\n"
            )
            overflow_provider.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "exceeded"):
                resolve_secrets(
                    ["overflow"],
                    environ={"PATH": os.environ["PATH"]},
                    provider=str(overflow_provider),
                )

            child_marker = root / "provider-child.pid"
            timeout_provider = root / "timeout-provider"
            timeout_provider.write_text(
                "#!/usr/bin/env python3\n"
                "import signal,subprocess,sys,time\n"
                "from pathlib import Path\n"
                "child=subprocess.Popen([sys.executable,'-c',"
                "'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)'])\n"
                f"Path({str(child_marker)!r}).write_text(str(child.pid))\n"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                "time.sleep(60)\n"
            )
            timeout_provider.chmod(0o755)
            started = time.monotonic()
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                resolve_secrets(
                    ["timeout"],
                    environ={"PATH": os.environ["PATH"]},
                    provider=str(timeout_provider),
                )
            self.assertLess(time.monotonic() - started, 4)
            self.assertFalse(_process_is_running(int(child_marker.read_text())))


def _interrupt_when_ready(marker: Path, signum: int) -> None:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if marker.exists():
            os.kill(os.getpid(), signum)
            return
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {marker}")


def _process_is_running(pid: int) -> bool:
    try:
        state = Path(f"/proc/{pid}/stat").read_text().split()[2]
    except FileNotFoundError:
        return False
    return state != "Z"


def _qdisc() -> str | None:
    tc = shutil.which("tc")
    if tc is None:
        return None
    return subprocess.run(
        [tc, "qdisc", "show", "dev", "lo"],
        text=True,
        capture_output=True,
        check=False,
    ).stdout


def _udp_packet(source_port: int, destination_port: int, payload: bytes) -> bytes:
    ethernet = b"\0" * 12 + b"\x08\x00"
    total_length = 20 + 8 + len(payload)
    ipv4 = (
        b"\x45\x00"
        + total_length.to_bytes(2, "big")
        + b"\0\0\0\0\x40\x11\0\0"
        + b"\x7f\0\0\1\x7f\0\0\1"
    )
    udp = (
        source_port.to_bytes(2, "big")
        + destination_port.to_bytes(2, "big")
        + (8 + len(payload)).to_bytes(2, "big")
        + b"\0\0"
    )
    return ethernet + ipv4 + udp + payload


def _pcap_record(packet: bytes) -> bytes:
    return struct.pack("<IIII", 1, 0, len(packet), len(packet)) + packet


def _pcap_record_at(packet: bytes, microseconds: int) -> bytes:
    return (
        struct.pack("<IIII", 1, microseconds, len(packet), len(packet)) + packet
    )


if __name__ == "__main__":
    unittest.main()
