"""Host tests for dial/account manifest fields and the softphone campaign runner.

No container, capture, or SIP socket is used. PJSUA is the fixture console
``tests/fixtures/fake_pjsua.py``; capture and report are fixture tools.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup import integration  # noqa: E402
from sippycup.campaign import ManifestError, compile_plan, main as campaign_main, verify_frozen_plan  # noqa: E402
from sippycup.integration import (  # noqa: E402
    SIPP_RUNNER,
    SOFTPHONE_RUNNER,
    CaptureWatchdog,
    execute_campaign,
    select_runner,
)
from sippycup.matrix_compile import compile_matrix_campaign  # noqa: E402
from sippycup.runtime import RuntimeError as PlanError, validate_plan  # noqa: E402
from sippycup_softphone import SoftphoneCall, build_config  # noqa: E402
from sippycup_softphone import campaign_runner  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "campaign"
FAKE_PJSUA = ROOT / "tests" / "fixtures" / "fake_pjsua.py"
SHIM = FIXTURES / "softphone-runner-shim.py"
TOOL = FIXTURES / "integration-tool.py"
SECRET = "Fixture-Secret-41c9e2!campaign"
PEER = "10.20.30.40"


def base_manifest() -> dict:
    return {
        "apiVersion": "sippycup.dev/v1",
        "kind": "Campaign",
        "metadata": {"name": "softphone-call"},
        "authorization": {
            "networks": ["10.20.30.0/24"],
            "signalingPorts": [5060],
            "mediaPorts": {"start": 4000, "end": 4100},
            "transports": ["udp"],
            "credentialRefs": ["sip-user"],
            "ceilings": {
                "calls": 4,
                "packets": 4000,
                "bytes": 1000000,
                "durationSeconds": 120,
                "concurrentCalls": 1,
                "packetsPerSecond": 400,
                "callsPerSecond": 1,
            },
            "stopConditions": {
                "consecutiveFailures": 1,
                "unexpectedResponse": True,
                "packetLossPercent": 5,
            },
        },
        "targets": [
            {
                "name": "pbx",
                "address": PEER,
                "signaling": {"transport": "udp", "port": 5060},
                "credentialRef": "sip-user",
                "account": {"username": "alice", "realm": "pbx.lab", "register": True},
            }
        ],
        "cases": [
            {
                "id": "probe",
                "type": "options",
                "target": "pbx",
                "count": 1,
                "budget": {"packetsPerRun": 4, "bytesPerRun": 4096, "durationSecondsPerRun": 3},
            },
            {
                "id": "dial-echo",
                "type": "call",
                "target": "pbx",
                "count": 1,
                "dial": {"user": "1001"},
                "budget": {"packetsPerRun": 1000, "bytesPerRun": 200000, "durationSecondsPerRun": 12},
                "expectations": {
                    "apiVersion": "sippycup.dev/case-expectations/v1",
                    "finalStatus": 200,
                    "requireBidirectionalRtp": True,
                },
            },
        ],
        "expectations": {"allowedSipStatuses": [100, 180, 200], "requireBidirectionalRtp": True},
        "evidence": {"capture": True, "retainPayload": False, "directory": "evidence/softphone"},
    }


def compiled(manifest: dict) -> tuple[dict, bytes]:
    raw = yaml.safe_dump(manifest, sort_keys=True).encode()
    return compile_plan(yaml.safe_load(raw), hashlib.sha256(raw).hexdigest()), raw


def canonical(plan: dict) -> str:
    return hashlib.sha256((json.dumps(plan, indent=2, sort_keys=True) + "\n").encode()).hexdigest()


class ManifestFieldTests(unittest.TestCase):
    def test_dial_and_account_are_frozen_into_call_steps_only(self):
        plan, _raw = compiled(base_manifest())
        options, call = plan["steps"]
        self.assertNotIn("dial", options)
        self.assertNotIn("account", options)
        self.assertEqual(call["dial"], {"user": "1001"})
        self.assertEqual(call["account"], {"username": "alice", "realm": "pbx.lab", "register": True})
        self.assertEqual(call["credentialRef"], "sip-user")
        validate_plan(plan)

    def test_account_defaults_to_no_registration_and_any_realm(self):
        manifest = base_manifest()
        manifest["targets"][0]["account"] = {"username": "+15550100"}
        plan, _raw = compiled(manifest)
        self.assertEqual(plan["steps"][1]["account"], {"username": "+15550100", "register": False})

    def test_invalid_dial_and_account_fields_are_rejected(self):
        cases = {
            "dial with @": (("cases", 1, "dial"), {"user": "1001@evil.test"}),
            "dial with parameter": (("cases", 1, "dial"), {"user": "1001;transport=tcp"}),
            "dial with space": (("cases", 1, "dial"), {"user": "10 01"}),
            "dial too long": (("cases", 1, "dial"), {"user": "1" * 65}),
            "dial unquoted number": (("cases", 1, "dial"), {"user": 1001}),
            "dial empty": (("cases", 1, "dial"), {"user": ""}),
            "dial leading dot": (("cases", 1, "dial"), {"user": ".1001"}),
            "dial placeholder": (("cases", 1, "dial"), {"user": "change-me"}),
            "dial unknown field": (("cases", 1, "dial"), {"user": "1001", "host": "x"}),
            "dial missing user": (("cases", 1, "dial"), {}),
            "dial scalar": (("cases", 1, "dial"), "1001"),
            "dial on options": (("cases", 0, "dial"), {"user": "1001"}),
            "account unknown field": (("targets", 0, "account"), {"username": "alice", "password": "x"}),
            "account bad username": (("targets", 0, "account"), {"username": "alice@pbx"}),
            "account bad realm": (("targets", 0, "account"), {"username": "alice", "realm": "a b"}),
            "account star realm": (("targets", 0, "account"), {"username": "alice", "realm": "*"}),
            "account register string": (("targets", 0, "account"), {"username": "alice", "register": "yes"}),
            "account missing username": (("targets", 0, "account"), {"register": True}),
        }
        for name, (path, value) in cases.items():
            with self.subTest(name=name):
                manifest = base_manifest()
                manifest[path[0]][path[1]][path[2]] = value
                with self.assertRaises(ManifestError):
                    compiled(manifest)

    def test_account_requires_the_targets_credential_reference(self):
        manifest = base_manifest()
        del manifest["targets"][0]["credentialRef"]
        with self.assertRaisesRegex(ManifestError, "credentialRef"):
            compiled(manifest)

    def test_old_manifests_compile_to_byte_identical_plans(self):
        """Golden digests were recorded from the planner before dial/account
        existed (commit 0fee722); a manifest without the new fields must keep
        exactly the same plan bytes."""

        def resolver(_host):
            return ["10.20.30.40"]

        golden = {
            "tests/fixtures/campaign/valid.yaml": "96697cc43102048429079ff62baf328ec762ee7c43a51d276275b4ffbb9df054",
            "examples/ferivox-campaign.yaml": "e5d0865f5e07fa1d5f15dd40f2f28030aca2e290f3aa70db0545e0b3e4849dd5",
        }
        for name, digest in golden.items():
            with self.subTest(name=name):
                raw = (ROOT / name).read_bytes()
                plan = compile_plan(yaml.safe_load(raw), hashlib.sha256(raw).hexdigest(), resolver=resolver)
                self.assertEqual(canonical(plan), digest)
        raw = (ROOT / "examples/ferivox-campaign.yaml").read_bytes()
        matrix = compile_matrix_campaign(
            yaml.safe_load(raw),
            seed=20260718,
            actions=("dtmf", "failure", "hangup", "hold", "recover", "reinvite", "resume"),
            max_actions=5,
            sequence_strength=2,
            max_cases=None,
            history=[],
        )
        self.assertEqual(
            hashlib.sha256(matrix.manifest_bytes).hexdigest(),
            "65e01126802fc3e1c4999d5ee5eac438d1bb3030620e2096027a184553cb9bb2",
        )
        plan = compile_plan(
            yaml.safe_load(matrix.manifest_bytes),
            hashlib.sha256(matrix.manifest_bytes).hexdigest(),
            resolver=resolver,
        )
        self.assertEqual(
            canonical(plan), "9b689081a99278ce801a6ba828e1d2c415b45d33e9793ea8d51a18aa48ccba95"
        )

    def test_matrix_generated_cases_inherit_the_template_dial(self):
        raw = (ROOT / "examples/ferivox-campaign.yaml").read_bytes()
        source = yaml.safe_load(raw)
        template = next(item for item in source["cases"] if item["type"] == "call")
        template["dial"] = {"user": "9196"}
        matrix = compile_matrix_campaign(
            source, seed=1, actions=("hangup",), max_actions=1, sequence_strength=1,
            max_cases=2, history=[],
        )
        plan = compile_plan(
            yaml.safe_load(matrix.manifest_bytes), hashlib.sha256(matrix.manifest_bytes).hexdigest()
        )
        calls = [step for step in plan["steps"] if step["type"] == "call"]
        self.assertTrue(calls)
        self.assertTrue(all(step["dial"] == {"user": "9196"} and "generated" in step for step in calls))


class FrozenPlanTamperTests(unittest.TestCase):
    def setUp(self):
        self.plan, self.raw = compiled(base_manifest())

    def tampered(self, change):
        plan = copy.deepcopy(self.plan)
        change(plan)
        return plan

    def test_runtime_validator_rejects_malformed_dial_and_account(self):
        changes = {
            "dial uri injection": lambda p: p["steps"][1]["dial"].update(user="1001@10.9.9.9"),
            "dial extra key": lambda p: p["steps"][1]["dial"].update(host="10.9.9.9"),
            "dial on options": lambda p: p["steps"][0].update(dial={"user": "1001"}),
            "account on options": lambda p: p["steps"][0].update(account=dict(p["steps"][1]["account"])),
            "account extra key": lambda p: p["steps"][1]["account"].update(registrar="sip:10.9.9.9"),
            "account bad username": lambda p: p["steps"][1]["account"].update(username="a b"),
            "account register type": lambda p: p["steps"][1]["account"].update(register="true"),
            "account without credential": lambda p: p["steps"][1].update(credentialRef=None),
            "unknown step field": lambda p: p["steps"][1].update(runner="/bin/sh"),
        }
        for name, change in changes.items():
            with self.subTest(name=name), self.assertRaises(PlanError):
                validate_plan(self.tampered(change))

    def test_account_must_match_across_a_targets_call_steps(self):
        manifest = base_manifest()
        second = copy.deepcopy(manifest["cases"][1])
        second["id"] = "dial-again"
        manifest["cases"].append(second)
        plan, _raw = compiled(manifest)
        validate_plan(plan)
        plan["steps"][2]["account"] = {"username": "mallory", "register": True}
        with self.assertRaisesRegex(PlanError, "differs"):
            validate_plan(plan)

    def test_manifest_lock_rejects_a_coherent_edit_of_dial_or_account(self):
        for name, change in {
            "dial": lambda p: p["steps"][1]["dial"].update(user="9999"),
            "register": lambda p: p["steps"][1]["account"].update(register=False),
            "realm": lambda p: p["steps"][1]["account"].update(realm="other.lab"),
            "dropped dial": lambda p: p["steps"][1].pop("dial"),
        }.items():
            with self.subTest(name=name):
                plan = self.tampered(change)
                validate_plan(plan)  # still well formed ...
                with self.assertRaisesRegex(ManifestError, "differs from recompilation"):
                    verify_frozen_plan(plan, self.raw)  # ... but not what was reviewed


class SelectionTests(unittest.TestCase):
    def test_selection_is_a_function_of_the_frozen_step(self):
        plan, _raw = compiled(base_manifest())
        self.assertEqual(select_runner(plan["steps"][0]), SIPP_RUNNER)
        self.assertEqual(select_runner(plan["steps"][1]), SOFTPHONE_RUNNER)
        plain = base_manifest()
        plain["authorization"]["credentialRefs"] = []
        del plain["targets"][0]["credentialRef"]
        del plain["targets"][0]["account"]
        del plain["cases"][1]["dial"]
        plan, _raw = compiled(plain)
        self.assertEqual([select_runner(step) for step in plan["steps"]], [SIPP_RUNNER, SIPP_RUNNER])
        # A credentialed call without a dial destination still needs the
        # softphone (SIPp would put the password in argv).
        credential_only = base_manifest()
        del credential_only["cases"][1]["dial"]
        plan, _raw = compiled(credential_only)
        self.assertEqual(select_runner(plan["steps"][1]), SOFTPHONE_RUNNER)

    def test_cli_offers_no_runner_option(self):
        for command in ("run", "execute"):
            with self.subTest(command=command), mock.patch("sys.stderr"), self.assertRaises(SystemExit) as raised:
                campaign_main([command, "plan.json", "--manifest", "m.yaml", "--runner", "/bin/sh"])
            self.assertEqual(raised.exception.code, 2)

    def test_execute_campaign_dispatches_each_step_and_records_runner_hashes(self):
        manifest = base_manifest()
        manifest["authorization"]["credentialRefs"] = []
        del manifest["targets"][0]["credentialRef"]
        del manifest["targets"][0]["account"]
        plan, raw = compiled(manifest)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            order = root / "order.txt"
            seen = root / "seen.jsonl"
            fake = {
                SIPP_RUNNER: [sys.executable, str(TOOL), "runner", str(order)],
                SOFTPHONE_RUNNER: [sys.executable, "-c", _ENVELOPE_RECORDER, str(seen)],
            }
            with mock.patch.object(
                integration, "_bundled_runners", lambda names: {name: fake[name] for name in names}
            ):
                result, run_dir = execute_campaign(
                    plan,
                    manifest_bytes=raw,
                    run_root=root / "runs",
                    capture_command=[sys.executable, str(TOOL), "capture", "{capture}", str(order)],
                    report_command=[sys.executable, str(TOOL), "report", "{capture}"],
                    preflight=lambda _destination: (True, "SIP/2.0 200 OK"),
                )
            self.assertEqual(result.state, "succeeded", (run_dir / "events.jsonl").read_text())
            envelopes = [json.loads(line) for line in seen.read_text().splitlines()]
            self.assertEqual(len(envelopes), 1)
            envelope = envelopes[0]
            self.assertEqual(envelope["step"]["dial"], {"user": "1001"})
            self.assertEqual(envelope["credentials"], {})
            self.assertEqual(
                envelope["context"]["authorization"]["mediaPorts"], {"start": 4000, "end": 4100}
            )
            self.assertEqual(envelope["context"]["evidence"], {"retainPayload": False})
            artifacts = Path(envelope["context"]["artifactDirectory"])
            self.assertEqual(artifacts.parent.parent, run_dir)
            versions = json.loads((run_dir / "versions.json").read_text())
            self.assertEqual(
                [(item["firstStep"], item["lastStep"], item["runner"]) for item in versions["stepRunners"]],
                [(1, 1, SIPP_RUNNER), (2, 2, SOFTPHONE_RUNNER)],
            )
            self.assertEqual(set(versions["runners"]), {SIPP_RUNNER, SOFTPHONE_RUNNER})
            for item in versions["stepRunners"]:
                self.assertEqual(item["sha256"], versions["runners"][item["runner"]]["sha256"])
            commands = json.loads((run_dir / "commands.json").read_text())
            self.assertEqual(commands["runners"][SOFTPHONE_RUNNER][:2], fake[SOFTPHONE_RUNNER][:2])

    def test_bundled_runners_exist_in_the_source_tree(self):
        for name in (SIPP_RUNNER, SOFTPHONE_RUNNER):
            path = Path(integration._bundled_runner(name))
            self.assertTrue(path.is_file())
            self.assertTrue(os.access(path, os.X_OK))


_ENVELOPE_RECORDER = (
    "import sys\n"
    "line = sys.stdin.readline()\n"
    "open(sys.argv[1], 'a').write(line)\n"
)


class WatchdogDialogTests(unittest.TestCase):
    def run_watchdog(self, packets, calls=1):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture.pcap"
            records = b"".join(
                struct.pack("<IIII", 1, index * 300000, len(packet), len(packet)) + packet
                for index, packet in enumerate(packets)
            )
            capture.write_bytes(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1) + records)
            watchdog = CaptureWatchdog(
                capture,
                {"calls": calls, "packets": 100, "bytes": 100000, "packetsPerSecond": 100, "callsPerSecond": 1},
            )
            watchdog.start()
            time.sleep(0.3)
            watchdog.stop()
            return watchdog.violation()

    def test_digest_resend_with_same_call_id_is_one_call(self):
        first = b"INVITE sip:1001@10.20.30.40 SIP/2.0\r\nCall-ID: abc@host\r\nCSeq: 1 INVITE\r\n\r\n"
        resend = b"INVITE sip:1001@10.20.30.40 SIP/2.0\r\ni: abc@host\r\nCSeq: 2 INVITE\r\n\r\n"
        self.assertIsNone(self.run_watchdog([first, resend]))
        other = b"INVITE sip:1001@10.20.30.40 SIP/2.0\r\nCall-ID: def@host\r\n\r\n"
        self.assertEqual(self.run_watchdog([first, other]), "call_ceiling_exceeded")


def step_envelope(
    *,
    mode_manifest=None,
    password: str | None = SECRET,
    retain: bool = False,
    artifacts: Path,
    budget: int = 12,
    generated: dict | None = None,
    expectations: dict | None = None,
    register: bool = False,
    account: bool = True,
) -> bytes:
    step = {
        "index": 2,
        "case": "dial-echo",
        "sequence": 1,
        "type": "call",
        "target": "pbx",
        "destination": {"addresses": ["192.0.2.10"], "port": 5060, "transport": "udp"},
        "credentialRef": "sip-user" if password is not None else None,
        "budget": {"calls": 1, "packets": 1000, "bytes": 200000, "durationSeconds": budget},
        "expectations": expectations
        if expectations is not None
        else {
            "apiVersion": "sippycup.dev/case-expectations/v1",
            "finalStatus": 200,
            "requireBidirectionalRtp": True,
        },
        "dial": {"user": "1001"},
    }
    if account and password is not None:
        step["account"] = {"username": "alice", "realm": "pbx.lab", "register": register}
    if generated is not None:
        step["generated"] = generated
    envelope = {
        "step": step,
        "credentials": {"sip-user": password} if password is not None else {},
        "context": {
            "authorization": {"networks": ["192.0.2.0/24"], "mediaPorts": {"start": 4000, "end": 4100}},
            "expectations": {"allowedSipStatuses": [100, 180, 200], "requireBidirectionalRtp": True},
            "evidence": {"retainPayload": retain},
            "artifactDirectory": str(artifacts),
        },
    }
    return json.dumps(envelope).encode() + b"\n"


def generated_case(**factors) -> dict:
    values = {
        "transport": "udp",
        "addressFamily": "ipv4",
        "codec": "pcmu",
        "ptime": 20,
        "mediaProtection": "plain",
        "dtmf": "none",
        "earlyMedia": "disabled",
        "holdReinvite": "disabled",
        "teardownInitiator": "caller",
        "duration": 1,
        "nat": "none",
        "impairment": "none",
    }
    values.update(factors)
    return {"row": 1, "sequence": 1, "factors": values, "actions": ["hold", "resume", "hangup"]}


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name)
        self.artifacts = self.root / "steps" / "000002"
        self.artifacts.mkdir(parents=True, mode=0o700)
        # Keep fixture calls short; the clamp test sets its own durations.
        patcher = mock.patch.object(campaign_runner, "DEFAULT_CALL_SECONDS", 1)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self._directory.cleanup()

    def run_runner(self, mode="answer", **kwargs):
        witness = self.root / f"witness-{mode}.json"
        lines: list[str] = []
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "FAKE_PJSUA_WITNESS": str(witness),
            "FAKE_PJSUA_MODE": mode,
            "LEAKY_VARIABLE": f"prefix-{SECRET}",
            "SIPPYCUP_SECRET_SIP_USER": "source-variable",
            **kwargs.pop("extra_environment", {}),
        }
        code = campaign_runner.run(
            step_envelope(artifacts=self.artifacts, **kwargs),
            pjsua=str(FAKE_PJSUA),
            environ=environment,
            emit=lines.append,
        )
        self.assertEqual(len(lines), 1, lines)
        self.assertLessEqual(len(lines[0].encode()), campaign_runner.MAX_LINE_BYTES)
        summary = json.loads(lines[0])
        record = json.loads(witness.read_text()) if witness.exists() else None
        return code, summary, record

    def test_answered_call_passes_and_secret_reaches_only_the_private_config(self):
        code, summary, record = self.run_runner()
        self.assertEqual(code, 0, summary)
        self.assertEqual(summary["outcome"], "passed")
        self.assertEqual(summary["finalStatus"], 200)
        self.assertEqual(summary["rtp"], {"txPackets": 43, "rxPackets": 42})
        self.assertEqual(summary["codec"], "PCMU")
        self.assertEqual(summary["dial"], {"user": "1001", "default": False})
        self.assertEqual(record["commands"][:2], ["m", "sip:1001@192.0.2.10:5060"])
        # The password reached PJSUA only through its private 0600 config.
        self.assertIn(f"--password={SECRET}", record["config"])
        self.assertEqual(record["config_mode"], "0o600")
        self.assertIn("--username=alice", record["config"])
        self.assertIn("--realm=pbx.lab", record["config"])
        self.assertNotIn("--registrar", record["config"])
        self.assertIn("--accept-redirect=0", record["config"])
        self.assertIn("--outbound=sip:192.0.2.10:5060;lr", record["config"])
        self.assertNotIn(SECRET, json.dumps(record["argv"]))
        self.assertNotIn(SECRET, json.dumps(record["environ"]))
        self.assertNotIn("SIPPYCUP_SECRET_SIP_USER", record["environ"])
        self.assertNotIn("LEAKY_VARIABLE", record["environ"])
        for path in self.root.rglob("*"):
            if path.is_file() and not path.name.startswith("witness-"):
                self.assertNotIn(SECRET.encode(), path.read_bytes(), path)
        self.assertNotIn(SECRET, json.dumps(summary))
        detail = json.loads((self.artifacts / "softphone.json").read_text())
        self.assertEqual(detail["outcome"], "passed")
        self.assertFalse(any(Path("/dev/shm").glob("sippycup-campaign-softphone-*")))

    def test_registration_is_attempted_only_when_the_plan_says_so(self):
        code, summary, record = self.run_runner(register=True)
        self.assertEqual(code, 0, summary)
        self.assertIn("--registrar=sip:192.0.2.10:5060", record["config"])
        self.assertIn("--rereg-delay=0", record["config"])
        self.assertTrue(summary["registered"])

    def test_failure_outcomes_exit_nonzero(self):
        cases = {
            "rejected": ({"mode": "reject"}, {"not_answered", "unexpected_final_status"}),
            "unanswered": ({"mode": "noanswer", "budget": 6}, {"not_answered"}),
            "one-way media": ({"mode": "oneway"}, {"bidirectional_rtp_not_observed"}),
            "registration failure": ({"mode": "regfail", "register": True}, {"registration_failed"}),
            "media port outside scope": ({"mode": "badport"}, {"media_peer_outside_scope"}),
            "wrong final status": (
                {"expectations": {"apiVersion": "sippycup.dev/case-expectations/v1", "finalStatus": 486}},
                {"unexpectedly_answered", "unexpected_final_status"},
            ),
        }
        for name, (arguments, expected) in cases.items():
            with self.subTest(name=name):
                code, summary, record = self.run_runner(**arguments)
                self.assertEqual(code, 1, summary)
                self.assertEqual(summary["outcome"], "failed")
                self.assertTrue(expected <= set(summary["reasons"]), summary["reasons"])
                if arguments.get("mode") == "regfail":
                    self.assertNotIn("m", record["commands"], "a failed registration never dials")

    def test_expected_rejection_passes_without_media(self):
        code, summary, _record = self.run_runner(
            mode="reject",
            expectations={"apiVersion": "sippycup.dev/case-expectations/v1", "finalStatus": 486},
        )
        self.assertEqual(code, 0, summary)
        self.assertEqual(summary["finalStatus"], 486)

    def test_wrong_password_is_one_rejected_attempt_and_retries_are_flagged(self):
        code, summary, _record = self.run_runner(mode="authfail")
        self.assertEqual(code, 1)
        self.assertEqual(summary["authentication"]["INVITE"], {"attempts": 1, "rejected": 1})
        self.assertEqual(summary["finalStatus"], 407)
        self.assertNotIn("repeated_rejected_authentication", summary["reasons"])
        code, summary, _record = self.run_runner(mode="authretry")
        self.assertEqual(code, 1)
        self.assertEqual(summary["authentication"]["INVITE"], {"attempts": 2, "rejected": 2})
        self.assertIn("repeated_rejected_authentication", summary["reasons"])

    def test_authentication_counter_ignores_retransmissions_and_unregister(self):
        log = "\n".join(
            [
                "TX 400 bytes Request msg REGISTER/cseq=1 (tdta1) to UDP 10.0.0.1:5060:",
                "REGISTER sip:10.0.0.1 SIP/2.0",
                "--end msg--",
                "RX 300 bytes Response msg 401/REGISTER/cseq=1 (rdata1) from UDP 10.0.0.1:5060:",
                "TX 500 bytes Request msg REGISTER/cseq=2 (tdta2) to UDP 10.0.0.1:5060:",
                "Authorization: <redacted>",
                "--end msg--",
                "TX 500 bytes Request msg REGISTER/cseq=2 (tdta2) to UDP 10.0.0.1:5060:",
                "Authorization: <redacted>",
                "--end msg--",
                "RX 300 bytes Response msg 200/REGISTER/cseq=2 (rdata2) from UDP 10.0.0.1:5060:",
                "TX 500 bytes Request msg REGISTER/cseq=3 (tdta3) to UDP 10.0.0.1:5060:",
                "Authorization: <redacted>",
                "--end msg--",
                "RX 300 bytes Response msg 200/REGISTER/cseq=3 (rdata3) from UDP 10.0.0.1:5060:",
            ]
        )
        self.assertEqual(
            campaign_runner.authentication_attempts(log)["REGISTER"], {"attempts": 2, "rejected": 0}
        )

    def test_invalid_envelopes_exit_two_before_pjsua_starts(self):
        for name, arguments in {
            "credential without account": {"account": False},
            "budget below minimum": {"budget": 4},
        }.items():
            with self.subTest(name=name):
                code, summary, record = self.run_runner(**arguments)
                self.assertEqual(code, 2, summary)
                self.assertEqual(summary["outcome"], "invalid")
                self.assertIsNone(record)
        lines = []
        self.assertEqual(campaign_runner.run(b"not json\n", emit=lines.append), 2)
        envelope = json.loads(step_envelope(artifacts=self.artifacts))
        envelope["step"]["type"] = "options"
        self.assertEqual(campaign_runner.run(json.dumps(envelope).encode(), emit=lines.append), 2)
        envelope = json.loads(step_envelope(artifacts=self.artifacts))
        envelope["credentials"] = {"other-ref": SECRET}
        self.assertEqual(campaign_runner.run(json.dumps(envelope).encode(), emit=lines.append), 2)
        self.assertFalse(any(SECRET in line for line in lines))

    def test_retain_payload_controls_where_received_audio_is_recorded(self):
        _code, summary, record = self.run_runner(retain=False)
        rec = next(line for line in record["config"].splitlines() if line.startswith("--rec-file="))
        self.assertTrue(rec.startswith("--rec-file=/"))
        self.assertNotIn(str(self.root), rec, "unretained audio is recorded only privately")
        self.assertFalse(summary["payloadRetained"])
        self.assertFalse((self.artifacts / "heard.wav").exists())
        _code, summary, record = self.run_runner(retain=True)
        rec = next(line for line in record["config"].splitlines() if line.startswith("--rec-file="))
        self.assertEqual(rec, f"--rec-file={self.artifacts / 'heard.wav'}")
        self.assertTrue(summary["payloadRetained"])

    def test_duration_is_clamped_to_the_step_budget(self):
        self.assertEqual(
            campaign_runner.call_duration(
                {"budget": {"durationSeconds": 20}, "generated": generated_case(duration=60)}
            ),
            {"requested": 60, "effective": 16, "budget": 20, "clamped": True},
        )
        with mock.patch.object(campaign_runner, "DEFAULT_CALL_SECONDS", 5):
            self.assertEqual(
                campaign_runner.call_duration(
                    {"budget": {"durationSeconds": 20}, "account": {"register": True}}
                ),
                {"requested": 5, "effective": 5, "budget": 20, "clamped": False},
            )
            self.assertEqual(
                campaign_runner.call_duration({"budget": {"durationSeconds": 6}})["effective"], 2
            )
            self.assertEqual(
                campaign_runner.call_duration(
                    {"budget": {"durationSeconds": 6}, "account": {"register": True}}
                )["effective"],
                1,
            )
        code, summary, record = self.run_runner(budget=8, generated=generated_case(duration=60))
        self.assertIn("--duration=4", record["config"].splitlines())
        self.assertEqual(summary["durationSeconds"]["effective"], 4)
        self.assertIn("duration", summary["factors"]["notExercised"])
        self.assertEqual(code, 0, summary)

    def test_hard_budget_hangs_up_before_the_supervisor_deadline(self):
        started = time.monotonic()
        code, summary, record = self.run_runner(mode="noanswer", budget=5)
        elapsed = time.monotonic() - started
        self.assertEqual(code, 1)
        self.assertLess(elapsed, 5)
        self.assertEqual(record.get("hangups"), ["CANCEL"])

    def test_matrix_factors_report_only_what_was_performed(self):
        code, summary, _record = self.run_runner(
            generated=generated_case(codec="pcma", dtmf="rfc4733", ptime=30)
        )
        self.assertEqual(code, 0)
        factors = summary["factors"]
        self.assertIn("negotiated PCMU", factors["notExercised"]["codec"])
        self.assertIn("dtmf", factors["notExercised"])
        self.assertIn("ptime", factors["notExercised"])
        self.assertIn("nat", factors["notExercised"])
        self.assertIn("earlyMedia", factors["notExercised"])
        self.assertEqual(factors["exercised"]["teardownInitiator"], "caller")
        self.assertEqual(factors["exercised"]["duration"], 1)
        self.assertEqual(
            factors["actions"]["notExercised"],
            [{"position": 1, "action": "hold"}, {"position": 2, "action": "resume"}],
        )
        self.assertEqual(factors["actions"]["exercised"], [{"position": 3, "action": "hangup"}])
        _code, summary, record = self.run_runner(
            generated=generated_case(codec="pcma"), extra_environment={"FAKE_PJSUA_CODEC": "PCMA"}
        )
        self.assertEqual(summary["factors"]["exercised"]["codec"], "pcma")
        self.assertIn("--add-codec=PCMA", record["config"].splitlines())
        self.assertFalse(set(summary["factors"]["exercised"]) & set(summary["factors"]["notExercised"]))


class EndToEndSecretTests(unittest.TestCase):
    """The real supervisor, integration lifecycle, and runner with fake PJSUA."""

    def test_secret_is_absent_from_argv_environments_events_and_artifacts(self):
        plan, raw = compiled(base_manifest())
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ,
            {
                "NAMED_SECRET_SOURCE": SECRET,
                "FAKE_PJSUA_PEER": PEER,
                "FAKE_PJSUA_MODE": "answer",
            },
        ):
            root = Path(directory)
            order = root / "order.txt"
            witness = root / "pjsua-witness.json"
            shim_witness = root / "runner-witness.jsonl"
            os.environ["FAKE_PJSUA_WITNESS"] = str(witness)
            runners = {
                SIPP_RUNNER: [sys.executable, str(TOOL), "runner", str(order)],
                SOFTPHONE_RUNNER: [sys.executable, str(SHIM), str(FAKE_PJSUA), str(shim_witness)],
            }
            with mock.patch.object(
                integration, "_bundled_runners", lambda names: {name: runners[name] for name in names}
            ):
                result, run_dir = execute_campaign(
                    plan,
                    manifest_bytes=raw,
                    run_root=root / "runs",
                    capture_command=[sys.executable, str(TOOL), "capture", "{capture}", str(order)],
                    report_command=[sys.executable, str(TOOL), "report", "{capture}"],
                    preflight=lambda _destination: (True, "SIP/2.0 200 OK"),
                    secret_values={"sip-user": SECRET},
                    secret_env_names=["NAMED_SECRET_SOURCE"],
                )
            events = (run_dir / "events.jsonl").read_text()
            self.assertEqual(result.state, "succeeded", events)
            # The runner's structured line is in the event stream despite the
            # secret (other runners stay silent when secrets exist).
            outputs = [
                json.loads(json.loads(line)["text"])
                for line in events.splitlines()
                if json.loads(line)["event"] == "step.output" and json.loads(line)["step"] == 2
            ]
            self.assertEqual(len(outputs), 1)
            self.assertEqual(outputs[0]["outcome"], "passed")
            # The OPTIONS step ran on the SIPp/sipsak fixture, which prints
            # every credential it is given: it was given none.
            step_one = [
                json.loads(line)
                for line in events.splitlines()
                if json.loads(line).get("step") == 1
            ]
            self.assertFalse(
                [item for item in step_one if item["event"].startswith("step.output")], step_one
            )
            self.assertEqual(step_one[-1]["event"], "step.succeeded")
            self.assertEqual(outputs[0]["apiVersion"], "sippycup.dev/softphone-step-result/v1")
            shim = json.loads(shim_witness.read_text().splitlines()[0])
            pjsua = json.loads(witness.read_text())
            self.assertIn(f"--password={SECRET}", pjsua["config"])
            for label, value in {
                "runner argv": shim["argv"],
                "runner environment": shim["environ"],
                "pjsua argv": pjsua["argv"],
                "pjsua environment": pjsua["environ"],
                "events": events,
            }.items():
                self.assertNotIn(SECRET, json.dumps(value), label)
            self.assertNotIn("NAMED_SECRET_SOURCE", shim["environ"])
            self.assertNotIn(SECRET.encode(), order.with_suffix(".runner-env").read_bytes())
            files = [path for path in run_dir.rglob("*") if path.is_file()]
            self.assertIn(run_dir / "steps" / "000002" / "softphone.log", files)
            self.assertIn(run_dir / "steps" / "000002" / "softphone.json", files)
            for path in files:
                self.assertNotIn(SECRET.encode(), path.read_bytes(), path)
            self.assertFalse((run_dir / "steps" / "000002" / "heard.wav").exists())


class DriverExtensionTests(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name)
        self.play = self.root / "play.wav"
        campaign_runner.write_tone(self.play)

    def tearDown(self):
        self._directory.cleanup()

    def call(self, **values):
        arguments = {
            "destination": "echo",
            "host": "192.0.2.10",
            "port": 5060,
            "transport": "udp",
            "play_file": self.play,
            "record_file": self.root / "heard.wav",
            "duration_seconds": 30,
            "log_file": self.root / "softphone.log",
        }
        arguments.update(values)
        return SoftphoneCall(**arguments)

    def test_media_port_range_is_validated(self):
        for ports in ((10, 5), (0, 10), (1, 70000), [1, 2]):
            with self.subTest(ports=ports), self.assertRaises(Exception):
                build_config(self.call(allowed_media_ports=ports))
        build_config(self.call(allowed_media_ports=(4000, 4000)))

    def test_pjsua_dies_with_its_parent(self):
        witness = self.root / "witness.json"
        script = (
            "import sys; from pathlib import Path\n"
            f"sys.path.insert(0, {str(ROOT / 'lib')!r})\n"
            "from sippycup_softphone import SoftphoneCall, place_call\n"
            f"call = SoftphoneCall(destination='echo', host='192.0.2.10', port=5060, transport='udp',"
            f" play_file=Path({str(self.play)!r}), record_file=Path({str(self.root / 'h.wav')!r}),"
            f" duration_seconds=60, log_file=Path({str(self.root / 'l.log')!r}))\n"
            f"place_call(call, pjsua={str(FAKE_PJSUA)!r}, kill_with_parent=True,"
            f" environment={{'PATH': '/usr/bin:/bin', 'FAKE_PJSUA_WITNESS': {str(witness)!r}}})\n"
        )
        parent = subprocess.Popen([sys.executable, "-c", script])
        try:
            deadline = time.monotonic() + 10
            pid = None
            while time.monotonic() < deadline:
                if witness.exists():
                    try:
                        record = json.loads(witness.read_text())
                    except json.JSONDecodeError:
                        record = {}
                    if "m" in record.get("commands", []):
                        pid = record["pid"]
                        break
                time.sleep(0.05)
            self.assertIsNotNone(pid, "fake PJSUA never dialed")
            parent.send_signal(signal.SIGKILL)
            parent.wait()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and _alive(pid):
                time.sleep(0.05)
            self.assertFalse(_alive(pid), "PJSUA outlived its killed parent")
        finally:
            if parent.poll() is None:
                parent.kill()
                parent.wait()


def _alive(pid: int) -> bool:
    try:
        state = Path(f"/proc/{pid}/stat").read_text().split()[2]
    except FileNotFoundError:
        return False
    return state != "Z"


if __name__ == "__main__":
    unittest.main()
