"""Host-side tests for the guided baseline call and its softphone driver.

No container, capture, or socket is used: capture, preflight, softphone, and
offline analyzers are injected fakes, and the PJSUA console is a fixture
script.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import signal
import stat
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_softphone import (  # noqa: E402
    SoftphoneAccount,
    SoftphoneCall,
    SoftphoneError,
    SoftphoneResult,
    build_config,
    destination_uri,
    parse_pjsua_log,
    place_call,
    redact,
)
from sippycup_workbench import call as guided  # noqa: E402

FAKE_PJSUA = ROOT / "tests" / "fixtures" / "fake_pjsua.py"
NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
SECRET = "Canary-Secret-7f3e9b!value"


def profile_document(**overrides):
    document = {
        "schema_version": "sippycup.dev/target-profile/v1",
        "name": "voice staging",
        "target": {
            "host": "192.0.2.10",
            "port": 5060,
            "transport": "udp",
            "approved_addresses": ["192.0.2.10", "192.0.2.11"],
        },
        "authorization": {
            "status": "approved",
            "approved_by": "service owner",
            "approval_id": "CHG-1",
            "valid_from": (NOW - timedelta(hours=1)).isoformat(),
            "valid_until": (NOW + timedelta(hours=1)).isoformat(),
        },
        "limits": {
            "max_calls": 1,
            "max_concurrency": 1,
            "max_calls_per_second": 1,
            "max_duration_seconds": 30,
        },
        "capture": {"interface": "any", "output": "work/call.pcap"},
        "features": {"ice": False, "turn": False, "srtp": False, "dtls_srtp": False, "webrtc": False},
    }
    for path, value in overrides.items():
        section, _, key = path.partition(".")
        if key:
            document[section][key] = value
        else:
            document[section] = value
    return document


def write_tone(path: Path, seconds: float = 0.5) -> None:
    guided.generate_tone(path, seconds=seconds)


class Fakes:
    """Recording fakes for every side effect of a guided call."""

    def __init__(self, *, capture_ready=None, capture_alive=True, preflight=(True, "SIP/2.0 200 OK"),
                 softphone=None, oracle="pass", directions=("caller_to_callee", "callee_to_caller")):
        self.events: list[str] = []
        self.environments: dict[str, dict[str, str]] = {}
        self.capture_argv: list[str] | None = None
        self.softphone_call: SoftphoneCall | None = None
        self.softphone_password: str | None = None
        self.capture_ready = capture_ready
        self.capture_alive = capture_alive
        self.preflight_result = preflight
        self.softphone_behavior = softphone
        self.oracle = oracle
        self.directions = directions
        self.on_capture_ready = None

    def start_capture(self, argv, capture, log, environment):
        self.events.append("capture")
        self.capture_argv = list(argv)
        self.environments["capture"] = dict(environment)
        capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
        log.write_text("listening on any\n")
        fakes = self

        class Handle:
            def wait_ready(self, timeout, cancel):
                if fakes.on_capture_ready:
                    fakes.on_capture_ready()
                return fakes.capture_ready

            def alive(self):
                return fakes.capture_alive

            def stop(self):
                fakes.events.append("capture-stop")

        return Handle()

    def preflight(self, destination):
        self.events.append("preflight")
        self.preflight_destination = destination
        return self.preflight_result

    def place_call(self, call, *, password=None, cancel=None, abort=None, pjsua=None, environment=None):
        self.events.append("softphone")
        self.softphone_call = call
        self.softphone_password = password
        self.environments["softphone"] = dict(environment or {})
        write_tone(call.record_file)
        call.log_file.write_text("fake log\n")
        if self.softphone_behavior is not None:
            return self.softphone_behavior(call, cancel)
        result = SoftphoneResult(destination_uri="sip:x")
        result.started = result.dialed = result.answered = True
        result.final_status = 200
        result.disconnect_status = 200
        result.rtp_tx_packets = 200
        result.rtp_rx_packets = 199
        result.codec = "PCMU"
        result.connected_seconds = 4.0
        result.hangup = "duration"
        return result

    def run_offline(self, argv, stdout, stderr, environment):
        name = "assert" if "--expect" in argv else "triage" if "triage" in argv else "report"
        self.events.append(name)
        self.environments[name] = dict(environment)
        if name == "assert":
            stdout.write_text(json.dumps({
                "verdict": self.oracle,
                "summary": {"pass": 5, "fail": 0 if self.oracle != "fail" else 1, "unknown": 1},
                "assertions": [],
                "dialogs": [{}],
                "streams": [{"direction": item} for item in self.directions],
            }))
        elif name == "triage":
            stdout.write_text(json.dumps({"metadata": {"packets": 10}, "protocol_frames": {}, "findings": []}))
        else:
            stdout.write_text("report\n")
        stderr.write_text("")
        return {"pass": 0, "fail": 1, "unknown": 4}[self.oracle] if name == "assert" else 0

    def dependencies(self, work_root: Path, environ=None, now=None, network_mode="private", signals=False):
        return guided.Dependencies(
            start_capture=self.start_capture,
            preflight=self.preflight,
            place_call=self.place_call,
            run_offline=self.run_offline,
            now=now or (lambda: NOW),
            local_address=lambda host, port: "10.0.2.100",
            tool_versions=lambda tools, environment: {"schema": "fake"},
            environ=environ if environ is not None else {"PATH": "/usr/bin"},
            work_root=work_root,
            network_mode=network_mode,
            install_signal_handlers=signals,
            tools={
                "tcpdump": "/usr/bin/tcpdump",
                "pjsua": "/usr/local/bin/pjsua",
                "tshark": "/usr/bin/tshark",
                "report": "/usr/local/bin/sippycup-report",
                "triage": "/usr/local/bin/sippycup-workbench",
                "assert": "/usr/local/bin/sippycup-assert",
            },
        )


class GuidedCallCase(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.work = Path(self._directory.name) / "work"
        self.engagement = self.work / "engagement"
        self.engagement.mkdir(parents=True)
        self.profile = self.engagement / "profile.yaml"
        self.write_profile(profile_document())

    def tearDown(self):
        self._directory.cleanup()

    def write_profile(self, document):
        self.profile.write_text(yaml.safe_dump(document), encoding="utf-8")

    def options(self, **values):
        defaults = {"profile": self.profile, "destination": "echo", "duration": 5}
        defaults.update(values)
        return guided.CallOptions(**defaults)

    def run_call(self, fakes, **values):
        deps_values = {key: values.pop(key) for key in ("environ", "now", "network_mode", "signals") if key in values}
        deps = fakes.dependencies(self.work, **deps_values)
        return guided.execute(self.options(**values), deps)

    def run_directories(self):
        root = self.engagement / "calls"
        return sorted(root.iterdir()) if root.exists() else []


class GatingTests(GuidedCallCase):
    def test_unready_profiles_send_zero_packets(self):
        cases = {
            "pending": {"authorization.status": "pending"},
            "revoked": {"authorization.status": "revoked"},
            "expired": {"authorization.valid_until": (NOW - timedelta(minutes=1)).isoformat()},
            "not-yet-valid": {"authorization.valid_from": (NOW + timedelta(minutes=5)).isoformat()},
            "hostname-only": {"target.host": "staging.example.invalid"},
            "host-not-approved": {"target.host": "192.0.2.99"},
            "expires-during-call": {"authorization.valid_until": (NOW + timedelta(seconds=20)).isoformat()},
        }
        for name, overrides in cases.items():
            with self.subTest(case=name):
                self.write_profile(profile_document(**overrides))
                fakes = Fakes()
                code, value = self.run_call(fakes)
                self.assertEqual(code, 2)
                self.assertEqual(value["state"], "blocked")
                self.assertTrue(value["blockingErrors"])
                self.assertEqual(value["networkActivity"], "none")
                self.assertEqual(fakes.events, [], "no capture, preflight, or call may start")
                self.assertEqual(self.run_directories(), [])
                rendered = guided.render_human(value)
                self.assertIn("BLOCKED", rendered)
                self.assertTrue(rendered.rstrip().endswith("Network activity: none"))

    def test_expiry_is_rechecked_immediately_before_the_first_packet(self):
        clock = {"now": NOW}
        fakes = Fakes()

        def lapse():
            clock["now"] = NOW + timedelta(hours=2)

        fakes.on_capture_ready = lapse
        code, value = self.run_call(fakes, now=lambda: clock["now"])
        self.assertEqual(code, 1)
        self.assertEqual(value["verdict"], "authorization-lapsed")
        self.assertNotIn("preflight", fakes.events)
        self.assertNotIn("softphone", fakes.events)
        self.assertIn("capture-stop", fakes.events)
        self.assertEqual(value["networkActivity"], "none")
        (run_dir,) = self.run_directories()
        self.assertIn("expired", (run_dir / "authorization-recheck.txt").read_text())
        self.assertEqual(json.loads((run_dir / "result.json").read_text())["verdict"], "authorization-lapsed")

    def test_capture_failure_stops_before_preflight(self):
        fakes = Fakes(capture_ready="capture_failed_to_start")
        code, value = self.run_call(fakes)
        self.assertEqual(code, 1)
        self.assertEqual(value["verdict"], "capture-failed")
        self.assertEqual(fakes.events, ["capture", "capture-stop"])
        self.assertEqual(value["networkActivity"], "none")

    def test_preflight_failure_places_no_call(self):
        fakes = Fakes(preflight=(False, "TimeoutError: timed out"))
        code, value = self.run_call(fakes)
        self.assertEqual(code, 1)
        self.assertEqual(value["verdict"], "preflight-failed")
        self.assertNotIn("softphone", fakes.events)
        self.assertEqual(fakes.events.count("preflight"), 1)
        self.assertIn("no call placed", value["networkActivity"])

    def test_capture_death_during_preflight_is_a_hard_failure(self):
        fakes = Fakes()
        original = fakes.preflight

        def preflight(destination):
            fakes.capture_alive = False
            return original(destination)

        fakes.preflight = preflight
        code, value = self.run_call(fakes)
        self.assertEqual(code, 1)
        self.assertEqual(value["verdict"], "capture-died")
        self.assertNotIn("softphone", fakes.events)

    def test_dry_run_prints_plan_and_sends_nothing(self):
        fakes = Fakes()
        code, value = self.run_call(fakes, dry_run=True, username="alice", secret_env="SOME_NAME")
        self.assertEqual(code, 0)
        self.assertEqual(fakes.events, [])
        self.assertEqual(self.run_directories(), [])
        self.assertFalse(value["network_activity"])
        self.assertEqual(value["softphone"]["destination_uri"], "sip:echo@192.0.2.10:5060")
        self.assertEqual(
            value["capture_filter"], "(host 192.0.2.10 or host 192.0.2.11) and (udp port 5060 or udp)"
        )
        rendered = guided.render_human(value)
        self.assertIn("Softphone parameters:", rendered)
        self.assertIn("single_options_preflight", rendered)
        self.assertIn("password=environment variable SOME_NAME", rendered)
        self.assertTrue(rendered.rstrip().endswith("Network activity: none"))

        self.write_profile(profile_document(**{"authorization.status": "pending"}))
        code, value = self.run_call(Fakes(), dry_run=True)
        self.assertEqual(code, 2)
        self.assertFalse(value["ready"])

    def test_run_root_must_stay_beneath_work(self):
        fakes = Fakes()
        outside = Path(self._directory.name) / "elsewhere"
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
            code = guided.main(
                [str(self.profile), "--dial", "echo", "--run-root", str(outside)],
                fakes.dependencies(self.work),
            )
        self.assertEqual(code, 2)
        self.assertIn("--run-root must be beneath", stderr.getvalue())
        self.assertEqual(fakes.events, [])
        self.assertFalse(outside.exists())


class ExecutionTests(GuidedCallCase):
    def test_successful_run_writes_complete_private_run_directory(self):
        fakes = Fakes()
        code, value = self.run_call(fakes)
        self.assertEqual(code, 0, value)
        self.assertEqual(value["verdict"], "pass")
        self.assertEqual(
            fakes.events,
            ["capture", "preflight", "softphone", "capture-stop", "report", "triage", "assert"],
        )
        (run_dir,) = self.run_directories()
        self.assertRegex(run_dir.name, r"^\d{8}T\d{6}\.\d{6}Z-voice-staging-[0-9a-f]{8}$")
        self.assertEqual(stat.S_IMODE(run_dir.stat().st_mode), 0o700)
        expected = {
            "profile.json", "plan.json", "commands.json", "versions.json", "timestamps.json",
            "capture.pcap", "capture.log", "preflight.json", "softphone.json", "softphone.log",
            "played.wav", "heard.wav", "expectations.yaml", "report.txt", "report.stderr",
            "triage.json", "triage.stderr", "assert.json", "assert.stderr", "result.json",
            "evidence-manifest.json",
        }
        present = {path.name for path in run_dir.iterdir()}
        self.assertLessEqual(expected, present)
        for path in run_dir.iterdir():
            with self.subTest(artifact=path.name):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0)
        result = json.loads((run_dir / "result.json").read_text())
        schema = json.loads((ROOT / "schemas" / "call-result-v1.schema.json").read_text())
        self.assertEqual(result["apiVersion"], schema["properties"]["apiVersion"]["const"])
        for key in schema["required"]:
            self.assertIn(key, result)
        self.assertIn(result["verdict"], schema["properties"]["verdict"]["enum"])
        self.assertIn(result["state"], schema["properties"]["state"]["enum"])
        self.assertEqual(result["runDirectory"], f"work/engagement/calls/{run_dir.name}")
        self.assertEqual(
            result["journalCommand"][:4], ["./bin/sippycup", "journal", "add", "work/engagement"]
        )
        self.assertIn(f"calls/{run_dir.name}/result.json", result["journalCommand"])
        self.assertTrue(result["networkActivity"].startswith("1 SIP OPTIONS preflight, 1 INVITE dialog"))
        rendered = guided.render_human(value)
        self.assertIn("Guided call: PASS", rendered)
        self.assertIn("Run directory: work/engagement/calls/", rendered)
        self.assertIn("Record it: ./bin/sippycup journal add work/engagement", rendered)
        self.assertTrue(rendered.rstrip().splitlines()[-1].startswith("Network activity: 1 SIP OPTIONS"))
        manifest = json.loads((run_dir / "evidence-manifest.json").read_text())
        self.assertEqual(manifest["runState"], "completed")

    def test_every_run_gets_a_new_directory(self):
        self.run_call(Fakes())
        self.run_call(Fakes())
        directories = self.run_directories()
        self.assertEqual(len(directories), 2)
        self.assertNotEqual(directories[0], directories[1])

    def test_capture_filter_and_expectations_come_from_the_profile(self):
        fakes = Fakes()
        self.run_call(fakes)
        self.assertEqual(
            fakes.capture_argv[-1], "(host 192.0.2.10 or host 192.0.2.11) and (udp port 5060 or udp)"
        )
        self.assertIn("-Z", fakes.capture_argv)
        (run_dir,) = self.run_directories()
        expectations = yaml.safe_load((run_dir / "expectations.yaml").read_text())
        self.assertEqual(
            expectations["capture"]["allowed_endpoints"], ["192.0.2.10", "192.0.2.11", "10.0.2.100"]
        )
        parameters = expectations["expectations"][0]["parameters"]
        self.assertTrue(parameters["require_bidirectional"])
        self.assertNotIn("expected_codecs", parameters)
        from sippycup_oracle.cli import load_expectations

        loaded, on_unknown, _ = load_expectations(run_dir / "expectations.yaml")
        self.assertEqual(loaded.allowed_endpoints, ("192.0.2.10", "192.0.2.11", "10.0.2.100"))
        self.assertEqual(on_unknown, "inconclusive")

        relaxed = guided.generate_expectations(["192.0.2.10"], "192.0.2.10", media_required=False)
        self.assertEqual(relaxed["capture"]["allowed_endpoints"], ["192.0.2.10"])
        self.assertFalse(relaxed["expectations"][0]["parameters"]["require_bidirectional"])
        self.assertEqual(
            guided.capture_filter(["2001:db8::5"], 5061, "tls"),
            "(host 2001:db8::5) and (tcp port 5061 or udp)",
        )

    def test_duration_is_clamped_to_the_profile_limit(self):
        fakes = Fakes()
        code, value = self.run_call(fakes, duration=600)
        self.assertEqual(code, 0)
        self.assertEqual(fakes.softphone_call.duration_seconds, 30)
        self.assertEqual(value["durationSeconds"], {"requested": 600, "limit": 30, "effective": 30})
        self.assertTrue(any("clamped" in note for note in value["notes"]))
        fakes = Fakes()
        self.run_call(fakes, duration=3)
        self.assertEqual(fakes.softphone_call.duration_seconds, 3)

    def test_one_way_media_is_classified_honestly(self):
        def no_inbound(call, cancel):
            result = SoftphoneResult(destination_uri="sip:x")
            result.started = result.dialed = result.answered = True
            result.final_status = 200
            result.rtp_tx_packets = 200
            result.rtp_rx_packets = 0
            return result

        fakes = Fakes(softphone=no_inbound, oracle="fail", directions=("caller_to_callee",))
        code, value = self.run_call(fakes)
        self.assertEqual(code, 1)
        self.assertEqual(value["verdict"], "possible-nat-one-way-media")
        self.assertTrue(any("not, by itself, a target defect" in note for note in value["notes"]))
        self.assertTrue(any("through the container runtime's NAT" in note for note in value["notes"]))

        self.write_profile(profile_document(**{
            "target.host": "127.0.0.2", "target.approved_addresses": ["127.0.0.2"],
        }))
        fakes = Fakes(softphone=no_inbound, oracle="fail", directions=("caller_to_callee",))
        code, value = self.run_call(fakes)
        self.assertEqual(value["verdict"], "one-way-media")

    def test_media_not_required_and_unknowns_stay_unknown(self):
        fakes = Fakes(oracle="unknown")
        code, value = self.run_call(fakes)
        self.assertEqual((code, value["verdict"]), (1, "inconclusive"))
        fakes = Fakes()
        code, value = self.run_call(fakes, media_required=False)
        (latest,) = [path for path in self.run_directories() if path.name == Path(value["runDirectory"]).name]
        expectations = yaml.safe_load((latest / "expectations.yaml").read_text())
        self.assertFalse(expectations["expectations"][0]["parameters"]["require_bidirectional"])

    def test_unanswered_and_rejected_calls_fail_without_media_claims(self):
        def rejected(call, cancel):
            result = SoftphoneResult(destination_uri="sip:x")
            result.started = result.dialed = True
            result.final_status = 486
            result.error = None
            return result

        code, value = self.run_call(Fakes(softphone=rejected))
        self.assertEqual((code, value["verdict"]), (1, "call-not-answered"))
        self.assertIsNone(value["softphone"]["rtp_rx_packets"])
        self.assertTrue(any("486" in note for note in value["notes"]))


class SecretTests(GuidedCallCase):
    def assert_no_secret_in_tree(self, root: Path, secret: str):
        for path in root.rglob("*"):
            if path.is_file():
                with self.subTest(artifact=str(path.relative_to(root))):
                    self.assertNotIn(secret.encode(), path.read_bytes())

    def test_secret_env_reaches_only_the_softphone_in_memory(self):
        environ = {"PATH": "/usr/bin", "SIPPYCUP_CALL_SECRET": SECRET, "SIPPYCUP_SECRET_OTHER": "other-canary"}
        fakes = Fakes()
        code, value = self.run_call(
            fakes, environ=environ, username="alice", secret_env="SIPPYCUP_CALL_SECRET"
        )
        self.assertEqual(code, 0, value)
        self.assertEqual(fakes.softphone_password, SECRET)
        self.assertNotIn("SIPPYCUP_CALL_SECRET", environ, "the source variable is removed")
        for name, environment in fakes.environments.items():
            with self.subTest(child=name):
                self.assertNotIn("SIPPYCUP_CALL_SECRET", environment)
                self.assertNotIn(SECRET, environment.values())
                self.assertNotIn("other-canary", environment.values())
        self.assertNotIn(SECRET, json.dumps(value))
        self.assertNotIn(SECRET, " ".join(fakes.capture_argv))
        self.assert_no_secret_in_tree(self.work, SECRET)
        (run_dir,) = self.run_directories()
        # The plan records the source by name, never by value.
        self.assertIn("environment variable SIPPYCUP_CALL_SECRET", (run_dir / "plan.json").read_text())
        commands = json.loads((run_dir / "commands.json").read_text())
        self.assertIn("--password=<redacted>", commands["softphone_options"])
        self.assertEqual(fakes.softphone_call.account.registrar, "sip:192.0.2.10:5060")

    def test_secret_file_must_be_private_and_beneath_work(self):
        secret_file = self.engagement / "password"
        secret_file.write_text(SECRET + "\n")
        secret_file.chmod(0o644)
        fakes = Fakes()
        with self.assertRaisesRegex(guided.CallError, "mode 0600"):
            self.run_call(fakes, username="alice", secret_file=secret_file)
        self.assertEqual(fakes.events, [])
        outside = Path(self._directory.name) / "password"
        outside.write_text(SECRET)
        outside.chmod(0o600)
        with self.assertRaisesRegex(guided.CallError, "beneath the work directory"):
            self.run_call(fakes, username="alice", secret_file=outside)
        with self.assertRaisesRegex(guided.CallError, "requires --username"):
            self.run_call(fakes, secret_env="ANY")
        self.assertEqual(fakes.events, [])
        secret_file.chmod(0o600)
        code, value = self.run_call(fakes, username="alice", secret_file=secret_file, register=False)
        self.assertEqual(code, 0)
        self.assertEqual(fakes.softphone_password, SECRET)
        self.assertIsNone(fakes.softphone_call.account.registrar)
        secret_file.unlink()
        self.assert_no_secret_in_tree(self.work, SECRET)

    def test_unsafe_password_is_refused_before_any_side_effect(self):
        environ = {"PASS": "has space"}
        fakes = Fakes()
        with self.assertRaisesRegex(guided.CallError, "whitespace"):
            self.run_call(fakes, environ=environ, username="alice", secret_env="PASS")
        self.assertEqual(fakes.events, [])
        self.assertEqual(self.run_directories(), [])

    def test_real_driver_keeps_secret_out_of_argv_environment_and_artifacts(self):
        witness = Path(self._directory.name) / "witness.json"
        private = Path(self._directory.name) / "private"
        private.mkdir()
        environ = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "SIPPYCUP_CALL_SECRET": SECRET,
            "FAKE_PJSUA_WITNESS": str(witness),
        }
        fakes = Fakes()

        def real_place_call(call, **kwargs):
            fakes.events.append("softphone")
            kwargs["pjsua"] = str(FAKE_PJSUA)
            return place_call(call, private_root=private, **kwargs)

        fakes.place_call = real_place_call
        self.write_profile(profile_document(**{"limits.max_duration_seconds": 1}))
        code, value = self.run_call(
            fakes, environ=environ, username="alice", secret_env="SIPPYCUP_CALL_SECRET", duration=1
        )
        self.assertEqual(value["softphone"]["registered"], True, value)
        self.assertTrue(value["softphone"]["answered"], value)
        record = json.loads(witness.read_text())
        self.assertNotIn(SECRET, " ".join(record["argv"]))
        self.assertNotIn(SECRET, record["environ"].values())
        self.assertNotIn("SIPPYCUP_CALL_SECRET", record["environ"])
        self.assertIn(f"--password={SECRET}", record["config"])
        self.assertEqual(record["config_mode"], "0o600")
        self.assertEqual(record["config_dir_mode"], "0o700")
        self.assertEqual(list(private.iterdir()), [], "private config directory is deleted")
        (run_dir,) = self.run_directories()
        log = (run_dir / "softphone.log").read_text()
        self.assertIn("Authorization: <redacted>", log)
        self.assertIn("Proxy-Authorization: <redacted>", log)
        self.assertNotIn("deadbeef", log)
        witness.unlink()
        self.assert_no_secret_in_tree(self.work, SECRET)


class SignalTests(GuidedCallCase):
    def test_interrupt_and_terminate_cancel_with_evidence(self):
        for signum, expected in ((signal.SIGINT, 130), (signal.SIGTERM, 143)):
            with self.subTest(signal=signum):
                def interrupted(call, cancel):
                    os.kill(os.getpid(), signum)
                    deadline = time.monotonic() + 2
                    while not cancel.is_set() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    result = SoftphoneResult(destination_uri="sip:x")
                    result.started = result.dialed = result.answered = True
                    result.cancelled = cancel.is_set()
                    result.error = "cancelled"
                    result.hangup = "cancelled"
                    return result

                previous = signal.getsignal(signum)
                fakes = Fakes(softphone=interrupted)
                code, value = self.run_call(fakes, signals=True)
                self.assertEqual(signal.getsignal(signum), previous, "handlers are restored")
                self.assertEqual(code, expected)
                self.assertEqual(value["state"], "cancelled")
                self.assertIn("capture-stop", fakes.events)
                self.assertNotIn("assert", fakes.events)
                run_dir = self.engagement / "calls" / Path(value["runDirectory"]).name
                result = json.loads((run_dir / "result.json").read_text())
                self.assertEqual((result["state"], result["exitCode"]), ("cancelled", expected))
                self.assertTrue((run_dir / "capture.pcap").exists())
                self.assertTrue((run_dir / "evidence-manifest.json").exists())


class SoftphoneDriverTests(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name)
        self.play = self.root / "play.wav"
        write_tone(self.play)

    def tearDown(self):
        self._directory.cleanup()

    def call(self, **values):
        defaults = {
            "destination": "echo",
            "host": "192.0.2.10",
            "port": 5060,
            "transport": "udp",
            "play_file": self.play,
            "record_file": self.root / "heard.wav",
            "duration_seconds": 2,
            "log_file": self.root / "softphone.log",
            "console_file": self.root / "console.txt",
            "allowed_media_addresses": ("192.0.2.10",),
        }
        defaults.update(values)
        return SoftphoneCall(**defaults)

    def run_fake(self, call, mode="answer", password=None, **kwargs):
        witness = self.root / f"witness-{mode}.json"
        private = self.root / f"private-{mode}"
        private.mkdir(exist_ok=True)
        environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                       "FAKE_PJSUA_WITNESS": str(witness), "FAKE_PJSUA_MODE": mode}
        result = place_call(
            call, password=password, pjsua=str(FAKE_PJSUA), environment=environment,
            private_root=private, **kwargs,
        )
        self.assertEqual(list(private.iterdir()), [])
        return result, json.loads(witness.read_text())

    def test_uri_and_config_generation(self):
        self.assertEqual(destination_uri("1001", "192.0.2.10", 5060, "udp"), "sip:1001@192.0.2.10:5060")
        self.assertEqual(
            destination_uri("echo", "2001:db8::1", 5061, "tls"), "sip:echo@[2001:db8::1]:5061;transport=tls"
        )
        for bad in ({"destination": "a@b"}, {"host": "pbx.example.test"}, {"transport": "sctp"}):
            with self.subTest(bad=bad):
                arguments = {"destination": "echo", "host": "192.0.2.10", "port": 5060, "transport": "udp"}
                arguments.update(bad)
                with self.assertRaises(SoftphoneError):
                    destination_uri(**arguments)
        account = SoftphoneAccount(username="alice", registrar="sip:192.0.2.10:5060")
        config = build_config(self.call(account=account, codecs=("PCMU", "PCMA")), password="pw#1$x")
        lines = config.splitlines()
        self.assertIn("--id=sip:alice@192.0.2.10", lines)
        self.assertIn("--username=alice", lines)
        self.assertIn("--realm=*", lines)
        self.assertIn("--registrar=sip:192.0.2.10:5060", lines)
        self.assertIn("--password=pw#1$x", lines)
        self.assertIn("--outbound=sip:192.0.2.10:5060;lr", lines)
        self.assertIn("--accept-redirect=0", lines)
        self.assertIn("--max-calls=1", lines)
        self.assertIn("--duration=2", lines)
        self.assertIn("--no-tcp", lines)
        self.assertLess(lines.index("--add-codec=PCMA"), lines.index("--add-codec=PCMU"),
                        "first preference is added last so it ends highest")
        unregistered = build_config(self.call(account=SoftphoneAccount(username="alice")), password="pw")
        self.assertNotIn("--registrar", unregistered)
        self.assertIn("--username=alice", unregistered)
        anonymous = build_config(self.call())
        self.assertNotIn("--username", anonymous)
        self.assertNotIn("--password", anonymous)
        tls = build_config(self.call(transport="tls", port=5061)).splitlines()
        self.assertIn("--use-tls", tls)
        self.assertIn("--no-udp", tls)
        self.assertIn("--outbound=sip:192.0.2.10:5061;transport=tls;lr", tls)
        for password in ("has space", "quote\"d", "line\nbreak", ""):
            with self.subTest(password=password), self.assertRaises(SoftphoneError):
                build_config(self.call(account=account), password=password)
        with self.assertRaises(SoftphoneError):
            build_config(self.call(), password="orphan")

    def test_redaction_and_log_parsing(self):
        text = (
            "Authorization: Digest username=\"a\", response=\"0123\"\n"
            "proxy-authorization:Digest response=\"4567\"\n"
            "--password hunter2x\n"
            "the value hunter2x leaked\n"
        )
        redacted = redact(text, ["hunter2x"])
        self.assertNotIn("0123", redacted)
        self.assertNotIn("4567", redacted)
        self.assertNotIn("hunter2x", redacted)
        self.assertIn("Authorization: <redacted>", redacted)
        facts = parse_pjsua_log(
            "Incoming Response msg 401/INVITE/cseq=1\n"
            "Incoming Response msg 200/INVITE/cseq=2\n"
            "    #0 audio PCMU @8kHz, sendrecv, peer=192.0.2.10:4000\n"
            "       RX pt=0, last update\n          total 12pkt 1KB\n"
            "       TX pt=0, ptime=20\n          total 13pkt 1KB\n"
            "Call 0 is DISCONNECTED [reason=200 (OK)]\n"
            "acc: registration success, status=200 (OK), will re-register\n"
            "acc: unregistration success\n"
        )
        self.assertEqual(facts["final_status"], 200)
        self.assertEqual((facts["rtp_rx_packets"], facts["rtp_tx_packets"]), (12, 13))
        self.assertEqual(facts["codec"], "PCMU")
        self.assertTrue(facts["registered"])
        self.assertIsNone(parse_pjsua_log("nothing here")["rtp_rx_packets"], "unknown stays unknown")

    def test_answered_call_reports_observed_facts(self):
        result, record = self.run_fake(self.call(duration_seconds=1))
        self.assertTrue(result.ok, result)
        self.assertEqual(result.final_status, 200)
        self.assertEqual((result.rtp_tx_packets, result.rtp_rx_packets), (43, 42))
        self.assertEqual(result.hangup, "duration")
        self.assertEqual([item["state"] for item in result.timeline][-1], "DISCONNECTED")
        self.assertEqual(record["commands"][:2], ["m", "sip:echo@192.0.2.10:5060"])
        self.assertEqual(record["commands"][-1], "q")
        self.assertEqual(record["argv"][1:], ["--config-file", record["argv"][2]])

    def test_cancel_sends_bye_for_established_call(self):
        cancel = threading.Event()
        threading.Timer(0.8, cancel.set).start()
        result, record = self.run_fake(self.call(duration_seconds=20), cancel=cancel)
        self.assertTrue(result.cancelled)
        self.assertEqual(result.error, "cancelled")
        self.assertEqual(record.get("hangups"), ["BYE"])
        self.assertLess(result.connected_seconds, 5)

    def test_abort_hangs_up_when_capture_dies(self):
        started = time.monotonic()
        result, record = self.run_fake(
            self.call(duration_seconds=20),
            abort=lambda: "capture_died" if time.monotonic() - started > 0.8 else None,
        )
        self.assertEqual(result.error, "capture_died")
        self.assertEqual(record.get("hangups"), ["BYE"])

    def test_registration_failure_never_dials(self):
        account = SoftphoneAccount(username="alice", registrar="sip:192.0.2.10:5060")
        result, record = self.run_fake(self.call(account=account), mode="regfail", password="pw")
        self.assertFalse(result.registered)
        self.assertEqual(result.registration_status, 403)
        self.assertFalse(result.dialed)
        self.assertNotIn("m", record["commands"])
        self.assertEqual(result.error, "registration_failed")

    def test_unanswered_call_is_cancelled_after_answer_timeout(self):
        result, record = self.run_fake(self.call(answer_timeout_seconds=0.5), mode="noanswer")
        self.assertFalse(result.answered)
        self.assertEqual(result.error, "no_answer_before_timeout")
        self.assertEqual(record.get("hangups"), ["CANCEL"])
        self.assertIsNone(result.rtp_rx_packets)

    def test_media_peer_outside_scope_hangs_up(self):
        result, record = self.run_fake(self.call(duration_seconds=20), mode="outside")
        self.assertEqual(result.error, "media_peer_outside_scope")
        self.assertEqual(record.get("hangups"), ["BYE"])


if __name__ == "__main__":
    unittest.main()
