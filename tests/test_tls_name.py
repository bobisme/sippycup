"""Host tests for a reviewed TLS server name and CA on a pinned literal address.

No container, socket, or capture is used. PJSUA is the fixture console
``tests/fixtures/fake_pjsua.py`` and the namespace helper is the fixture
``tests/fixtures/fake_unshare.py``. The live proof (SNI, no DNS, refusals
before SIP) is the practice gate.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import ssl
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from sippycup import integration, options, practice, runtime, tls_trust  # noqa: E402
from sippycup.campaign import ManifestError, compile_plan, verify_frozen_plan  # noqa: E402
from sippycup.tls_trust import TrustError  # noqa: E402
from sippycup_softphone import SoftphoneAccount, SoftphoneCall, build_config, place_call  # noqa: E402
from sippycup_softphone import campaign_runner, driver  # noqa: E402
from sippycup_workbench import call as guided  # noqa: E402
from sippycup_workbench import cli  # noqa: E402
from sippycup_workbench.profile import rehearse  # noqa: E402
from sippycup_workbench.scope import inspect  # noqa: E402
from sippycup_workbench.scope_derive import compile_scope  # noqa: E402
from sippycup_workbench.scope_questions import render_questions  # noqa: E402

import test_softphone_runner as runner_tests  # noqa: E402

CA_PEM = (ROOT / "tests" / "fixtures" / "tls" / "test-ca.crt").read_bytes()
CA_SHA256 = hashlib.sha256(CA_PEM).hexdigest()
FAKE_PJSUA = ROOT / "tests" / "fixtures" / "fake_pjsua.py"
FAKE_UNSHARE = ROOT / "tests" / "fixtures" / "fake_unshare.py"
NAME = "sbc.voice-lab.test"
NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)


class WorkTree(unittest.TestCase):
    """A temporary work/ tree with the fixture CA at work/eng/owner-ca.crt."""

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.base = Path(self._directory.name)
        self.work = self.base / "work"
        (self.work / "eng").mkdir(parents=True)
        self.ca = self.work / "eng" / "owner-ca.crt"
        self.ca.write_bytes(CA_PEM)
        patcher = mock.patch.dict(os.environ, {"SIPPYCUP_WORK_ROOT": str(self.work)})
        patcher.start()
        self.addCleanup(patcher.stop)


class ServerNameAndTrustTests(WorkTree):
    def test_server_name_grammar(self) -> None:
        for good in ("sippycup-practice", NAME, "a.b-c.d1", "corp.local", "x" * 63):
            with self.subTest(good=good):
                self.assertEqual(tls_trust.validate_server_name(good), good)
        bad = [
            None, "", 7, "*.voice-lab.test", "Sbc.voice-lab.test", "192.0.2.10", "[2001:db8::1]",
            "2001:db8::1", "sbc.voice-lab.test.", "-sbc.test", "sbc-.test", "sbc_1.test",
            "a..b", "host.123", "x" * 64, ".".join(["a" * 50] * 6), "localhost", "pbx.localhost",
            "sbc.example.invalid", "example.com", "sip.example.org", "changeme.voice.test",
            "todo", "placeholder.lab", "sbc example.test",
        ]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(TrustError):
                tls_trust.validate_server_name(value)

    def test_ca_reference_must_stay_beneath_work(self) -> None:
        self.assertEqual(tls_trust.read_ca("work/eng/owner-ca.crt"), (CA_PEM, CA_SHA256))
        for reference in ("/etc/ssl/ca.crt", "eng/ca.crt", "work/../ca.crt", "work/./x.crt",
                          "work/eng/a b.crt", "work/", "work/eng/missing.crt"):
            with self.subTest(reference=reference), self.assertRaises(TrustError):
                tls_trust.read_ca(reference)
        outside = self.base / "outside.crt"
        outside.write_bytes(CA_PEM)
        (self.work / "eng" / "link.crt").symlink_to(outside)
        with self.assertRaisesRegex(TrustError, "outside the work directory"):
            tls_trust.read_ca("work/eng/link.crt")
        (self.work / "eng" / "dir.crt").mkdir()
        with self.assertRaises(TrustError):
            tls_trust.read_ca("work/eng/dir.crt")

    def test_ca_content_must_be_a_bounded_pem_certificate_without_a_key(self) -> None:
        cases = {
            "junk.crt": b"not a certificate\n",
            "key.crt": CA_PEM + b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            "broken.crt": b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
            "binary.crt": b"\xff\xfe" + CA_PEM,
            "huge.crt": CA_PEM + b"#" * (tls_trust.MAX_CA_BYTES + 1),
        }
        for name, data in cases.items():
            (self.work / "eng" / name).write_bytes(data)
            with self.subTest(name=name), self.assertRaises(TrustError):
                tls_trust.read_ca(f"work/eng/{name}")

    def test_verified_read_refuses_a_changed_file_and_private_copy_is_0600(self) -> None:
        self.assertEqual(tls_trust.read_verified_ca("work/eng/owner-ca.crt", CA_SHA256), CA_PEM)
        self.ca.write_bytes(CA_PEM + b"\n")
        with self.assertRaisesRegex(TrustError, "changed since it was reviewed"):
            tls_trust.read_verified_ca("work/eng/owner-ca.crt", CA_SHA256)
        with self.assertRaises(TrustError):
            tls_trust.read_verified_ca("work/eng/owner-ca.crt", "ABC")
        copy_path = tls_trust.write_private_copy(CA_PEM, self.base / "copy.pem")
        self.assertEqual(stat.S_IMODE(copy_path.stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            tls_trust.write_private_copy(CA_PEM, copy_path)


class OptionsTests(unittest.TestCase):
    def test_in_memory_trust_anchor_and_no_way_to_combine_it_with_insecure(self) -> None:
        context = options._tls_context(ca_file=None, insecure=False, ca_data=CA_PEM)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        with self.assertRaises(ValueError):
            options.send_options("192.0.2.10", 5061, "tls", insecure=True, tls_ca_data=CA_PEM)
        with self.assertRaises(ValueError):
            options.send_options("192.0.2.10", 5060, "udp", tls_ca_data=CA_PEM)


def profile_document(**target) -> dict:
    document = {
        "schema_version": "sippycup.dev/target-profile/v1",
        "name": "voice tls",
        "target": {
            "host": "192.0.2.10",
            "port": 5061,
            "transport": "tls",
            "approved_addresses": ["192.0.2.10"],
            **target,
        },
        "authorization": {
            "status": "approved",
            "approved_by": "service owner",
            "approval_id": "CHG-7",
            "valid_from": (NOW - timedelta(hours=1)).isoformat(),
            "valid_until": (NOW + timedelta(hours=1)).isoformat(),
        },
        "limits": {"max_calls": 1, "max_concurrency": 1, "max_calls_per_second": 1,
                   "max_duration_seconds": 30},
        "capture": {"interface": "any", "output": "work/eng/call.pcap"},
        "features": {"ice": False, "turn": False, "srtp": False, "dtls_srtp": False,
                     "webrtc": False},
    }
    return document


class ProfileTests(WorkTree):
    def test_reviewed_name_and_ca_make_a_ready_profile_with_honest_facts(self) -> None:
        result = rehearse(
            profile_document(tls_server_name=NAME, tls_ca_file="work/eng/owner-ca.crt"), now=NOW
        )
        self.assertTrue(result.ready, result.errors)
        tls = result.facts["tls"]
        self.assertEqual(tls["server_name"], NAME)
        self.assertEqual(tls["verify_name"], NAME)
        self.assertEqual((tls["trust"], tls["ca_sha256"]), ("file", CA_SHA256))
        self.assertEqual(tls["connects_to"], "192.0.2.10")
        self.assertEqual(tls["verification"], "required")
        line = cli.tls_summary(tls)
        self.assertIn(NAME, line)
        self.assertIn("never resolved", line)
        self.assertIn("only to the literal address 192.0.2.10", line)

    def test_without_a_name_the_ip_san_and_system_store_are_used(self) -> None:
        result = rehearse(profile_document(), now=NOW)
        self.assertTrue(result.ready, result.errors)
        tls = result.facts["tls"]
        self.assertEqual((tls["server_name"], tls["verify_name"], tls["trust"]),
                         (None, "192.0.2.10", "system"))
        self.assertIn("IP SAN", cli.tls_summary(tls))

    def test_invalid_tls_fields_block_the_profile(self) -> None:
        cases = [
            {"tls_server_name": "192.0.2.10"},
            {"tls_server_name": "*.voice-lab.test"},
            {"tls_server_name": "sbc.example.invalid"},
            {"tls_ca_file": "/etc/ssl/certs/ca-certificates.crt"},
            {"tls_ca_file": "work/eng/missing.crt"},
            {"tls_verify": False},
            {"tls_insecure": True},
        ]
        for target in cases:
            with self.subTest(target=target):
                self.assertFalse(rehearse(profile_document(**target), now=NOW).ready)
        udp = profile_document(tls_server_name=NAME)
        udp["target"].update(transport="udp", port=5060)
        result = rehearse(udp, now=NOW)
        self.assertFalse(result.ready)
        self.assertTrue(any("require transport tls" in error for error in result.errors))

    def test_one_call_plan_carries_the_name_and_ca_into_the_preflight(self) -> None:
        path = self.work / "eng" / "profile.yaml"
        path.write_text(yaml.safe_dump(profile_document(
            tls_server_name=NAME, tls_ca_file="work/eng/owner-ca.crt"
        )), encoding="utf-8")
        with mock.patch.object(cli, "rehearse", partial(rehearse, now=NOW)):
            plan = cli._one_call_plan(str(path))
        self.assertTrue(plan["ready"], plan["blocking_errors"])
        preflight = next(step for step in plan["steps"] if step["name"] == "single_options_preflight")
        self.assertEqual(
            preflight["argv"][-4:],
            ["--tls-server-name", NAME, "--tls-ca-file", "work/eng/owner-ca.crt"],
        )
        self.assertEqual(plan["tls"]["connects_to"], "192.0.2.10")


def tls_manifest(**signaling) -> dict:
    manifest = runner_tests.base_manifest()
    manifest["authorization"]["signalingPorts"] = [5061]
    manifest["authorization"]["transports"] = ["tls"]
    manifest["targets"][0]["signaling"] = {"transport": "tls", "port": 5061, **signaling}
    return manifest


def compile_tls(manifest: dict, digest: str = "0" * 64) -> dict:
    return compile_plan(manifest, digest, resolver=lambda host: [])


class ManifestTests(WorkTree):
    def test_name_and_ca_digest_are_frozen_into_every_step(self) -> None:
        plan = compile_tls(tls_manifest(tlsServerName=NAME, tlsCaFile="work/eng/owner-ca.crt"))
        expected = {"serverName": NAME, "caFile": "work/eng/owner-ca.crt", "caSha256": CA_SHA256}
        self.assertTrue(plan["steps"])
        for step in plan["steps"]:
            self.assertEqual(step["tls"], expected)
        self.assertTrue(any("never resolved" in item for item in plan["assumptions"]))
        runtime.validate_plan(plan)

    def test_name_alone_uses_the_system_store(self) -> None:
        plan = compile_tls(tls_manifest(tlsServerName=NAME))
        for step in plan["steps"]:
            self.assertEqual(step["tls"], {"serverName": NAME, "caFile": None, "caSha256": None})
        plain = compile_tls(tls_manifest())
        self.assertTrue(all("tls" not in step for step in plain["steps"]))

    def test_invalid_or_unknown_tls_fields_are_rejected(self) -> None:
        cases = [
            {"tlsServerName": "192.0.2.10"},
            {"tlsServerName": "*.lab.test"},
            {"tlsServerName": "changeme.lab.test"},
            {"tlsCaFile": "/etc/ssl/certs/ca-certificates.crt"},
            {"tlsCaFile": "work/eng/missing.crt"},
            {"tlsVerify": False},
            {"tlsInsecure": True},
            {"tlsCaSha256": CA_SHA256},
        ]
        for signaling in cases:
            with self.subTest(signaling=signaling), self.assertRaises(ManifestError):
                compile_tls(tls_manifest(**signaling))
        manifest = runner_tests.base_manifest()
        manifest["targets"][0]["signaling"]["tlsServerName"] = NAME
        with self.assertRaisesRegex(ManifestError, "tls"):
            compile_tls(manifest)

    def test_manifest_lock_uses_the_frozen_digest_and_rejects_edits(self) -> None:
        manifest = tls_manifest(tlsServerName=NAME, tlsCaFile="work/eng/owner-ca.crt")
        raw = yaml.safe_dump(manifest).encode()
        plan = compile_tls(manifest, hashlib.sha256(raw).hexdigest())
        # The lock recompiles from the frozen digest, so it holds even after
        # the file changed; execution (below) is what refuses that.
        self.ca.write_bytes(CA_PEM + b"\n")
        verify_frozen_plan(plan, raw)
        edited = copy.deepcopy(plan)
        for step in edited["steps"]:
            step["tls"]["serverName"] = "other.voice-lab.test"
        with self.assertRaises(Exception):
            verify_frozen_plan(edited, raw)

    def test_runtime_revalidates_tls_facts_independently(self) -> None:
        plan = compile_tls(tls_manifest(tlsServerName=NAME, tlsCaFile="work/eng/owner-ca.crt"))
        changes = [
            lambda step: step["tls"].update(serverName="10.0.0.1"),
            lambda step: step["tls"].update(caSha256=None),
            lambda step: step["tls"].update(caFile="../ca.crt"),
            lambda step: step["tls"].update(verify=False),
            lambda step: step.update(tls={}),
            lambda step: step["destination"].update(transport="udp"),
        ]
        for change in changes:
            edited = copy.deepcopy(plan)
            change(edited["steps"][0])
            with self.subTest(change=change), self.assertRaises(runtime.RuntimeError):
                runtime.validate_plan(edited)
        if len(plan["steps"]) > 1:
            edited = copy.deepcopy(plan)
            edited["steps"][-1]["tls"]["serverName"] = "other.voice-lab.test"
            with self.assertRaises(runtime.RuntimeError):
                runtime.validate_plan(edited)

    def test_execution_refuses_a_changed_ca_before_anything_is_created(self) -> None:
        plan = compile_tls(tls_manifest(tlsServerName=NAME, tlsCaFile="work/eng/owner-ca.crt"))
        self.assertEqual(integration.verified_trust_anchors(plan),
                         {"work/eng/owner-ca.crt": CA_PEM})
        self.assertEqual(integration.target_tls(plan)["pbx"]["serverName"], NAME)
        self.ca.write_bytes(CA_PEM + b"\n")
        with self.assertRaisesRegex(runtime.RuntimeError, "changed since it was reviewed.*nothing was sent"):
            integration.verified_trust_anchors(plan)
        manifest = tls_manifest(tlsServerName=NAME, tlsCaFile="work/eng/owner-ca.crt")
        self.ca.write_bytes(CA_PEM)
        raw = yaml.safe_dump(manifest).encode()
        plan = compile_tls(manifest, hashlib.sha256(raw).hexdigest())
        self.ca.write_bytes(CA_PEM + b"\n")
        run_root = self.base / "runs"
        with self.assertRaises(runtime.RuntimeError) as caught:
            integration.execute_campaign(plan, manifest_bytes=raw, run_root=run_root)
        self.assertIn("changed since it was reviewed", str(caught.exception))
        self.assertFalse(run_root.exists() and any(run_root.iterdir()))

    def test_tls_call_steps_go_to_the_softphone_runner_and_sipp_refuses_them(self) -> None:
        plan = compile_tls(tls_manifest(tlsServerName=NAME))
        for step in plan["steps"]:
            runner = integration.select_runner(step)
            if step["type"] == "call":
                self.assertEqual(runner, integration.SOFTPHONE_RUNNER)


class DriverTests(WorkTree):
    def setUp(self) -> None:
        super().setUp()
        self.play = self.base / "play.wav"
        guided.generate_tone(self.play, seconds=0.5)

    def call(self, **values) -> SoftphoneCall:
        defaults = {
            "destination": "echo",
            "host": "192.0.2.10",
            "port": 5061,
            "transport": "tls",
            "play_file": self.play,
            "record_file": self.base / "heard.wav",
            "duration_seconds": 1,
            "log_file": self.base / "softphone.log",
            "allowed_media_addresses": ("192.0.2.10",),
            "tls_server_name": NAME,
            "tls_ca_file": self.ca,
        }
        defaults.update(values)
        return SoftphoneCall(**defaults)

    def run_fake(self, call, *, tls="ok", unshare_mode="ok", password=None):
        witness = self.base / "pjsua-witness.json"
        unshare_witness = self.base / "unshare-witness.jsonl"
        for path in (witness, unshare_witness):
            path.unlink(missing_ok=True)
        private = self.base / "private"
        private.mkdir(exist_ok=True)
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "FAKE_PJSUA_WITNESS": str(witness),
            "FAKE_PJSUA_TLS": tls,
            "FAKE_PJSUA_PEER": "192.0.2.10",
            "FAKE_UNSHARE_WITNESS": str(unshare_witness),
            "FAKE_UNSHARE_MODE": unshare_mode,
        }
        result = place_call(
            call, password=password, pjsua=str(FAKE_PJSUA), environment=environment,
            private_root=private, unshare=str(FAKE_UNSHARE),
        )
        self.assertEqual(list(private.iterdir()), [], "private directory was not removed")
        record = json.loads(witness.read_text()) if witness.exists() else None
        runs = [json.loads(line) for line in unshare_witness.read_text().splitlines()] \
            if unshare_witness.exists() else []
        return result, record, runs

    def test_config_always_verifies_and_uses_the_name_only_as_a_name(self) -> None:
        account = SoftphoneAccount(
            username="alice", registrar=driver.registrar_uri("192.0.2.10", 5061, "tls", NAME)
        )
        lines = build_config(self.call(account=account), password="pw").splitlines()
        self.assertIn("--tls-verify-server", lines)
        self.assertIn(f"--tls-ca-file={self.ca}", lines)
        self.assertIn(f"--outbound=sip:{NAME}:5061;transport=tls;lr", lines)
        self.assertIn(f"--registrar=sip:{NAME}:5061;transport=tls", lines)
        self.assertIn(f"--id=sip:alice@{NAME}", lines)
        self.assertFalse(any("192.0.2.10" in line for line in lines if not line.startswith("--bound")))
        system = build_config(self.call(tls_server_name=None, tls_ca_file=None)).splitlines()
        self.assertIn("--tls-verify-server", system)
        self.assertIn(f"--tls-ca-file={tls_trust.SYSTEM_CA_BUNDLE}", system)
        self.assertIn("--outbound=sip:192.0.2.10:5061;transport=tls;lr", system)
        self.assertEqual(
            driver.destination_uri("echo", "192.0.2.10", 5061, "tls", NAME),
            f"sip:echo@{NAME}:5061;transport=tls",
        )

    def test_invalid_tls_inputs_are_refused_before_pjsua(self) -> None:
        for values in (
            {"tls_server_name": "10.0.0.1"},
            {"tls_server_name": "*.lab.test"},
            {"transport": "udp", "port": 5060},
            {"transport": "udp", "port": 5060, "tls_server_name": None},
        ):
            with self.subTest(values=values), self.assertRaises(driver.SoftphoneError):
                build_config(self.call(**values))
        wrong = SoftphoneAccount(username="alice", registrar="sip:192.0.2.10:5061;transport=tls")
        with self.assertRaises(driver.SoftphoneError):
            build_config(self.call(account=wrong), password="pw")

    def test_verified_call_runs_pjsua_in_the_pinned_namespace(self) -> None:
        result, record, runs = self.run_fake(self.call())
        self.assertTrue(result.answered, result)
        self.assertIsNone(result.error)
        self.assertTrue(result.tls_verified)
        self.assertEqual((result.tls_server_name, result.tls_trust), (NAME, "file"))
        self.assertEqual(result.tls_detail, f"{NAME}:5061: OK")
        self.assertEqual(len(runs), 2, runs)
        probe, call = runs
        self.assertEqual(probe["command"], ["getent", "ahosts", NAME])
        self.assertEqual(probe["hosts"], f"192.0.2.10 {NAME}\n")
        self.assertEqual(probe["nsswitch"], "hosts: files\n")
        self.assertIn("mount --bind", probe["script"])
        self.assertEqual(call["command"][0], str(FAKE_PJSUA))
        self.assertIn("FAKE_PINNED_HOSTS", record["environ"])

    def test_verification_failures_are_reported_and_never_pass(self) -> None:
        for tls, message in (("mismatch", "identity does not match"), ("untrusted", "untrusted")):
            with self.subTest(tls=tls):
                result, _record, _runs = self.run_fake(self.call(), tls=tls)
                self.assertFalse(result.answered)
                self.assertFalse(result.tls_verified)
                self.assertEqual(result.error, "tls_verification_failed")
                self.assertIn(message, result.tls_detail)
                self.assertFalse(result.ok)
        result, _record, _runs = self.run_fake(self.call(), tls="none")
        self.assertFalse(result.tls_verified)
        self.assertEqual(result.error, "tls_verification_not_observed")
        self.assertFalse(result.ok)

    def test_pinning_must_be_proven_before_pjsua_starts(self) -> None:
        for mode, error in (("fail", "tls_name_pinning_unavailable"),
                            ("extra", "tls_name_pinning_mismatch")):
            with self.subTest(mode=mode):
                result, record, runs = self.run_fake(self.call(), unshare_mode=mode)
                self.assertEqual(result.error, error)
                self.assertIsNone(record, "PJSUA must not start")
                self.assertFalse(result.dialed)
                self.assertEqual(len(runs), 1)
        missing = self.call()
        result = place_call(missing, pjsua=str(FAKE_PJSUA), environment={"PATH": "/usr/bin:/bin"},
                            private_root=self.base, unshare=str(self.base / "no-unshare"))
        self.assertEqual(result.error, "tls_name_pinning_unavailable")

    def test_without_a_name_no_namespace_is_used_and_the_ip_is_verified(self) -> None:
        result, record, runs = self.run_fake(self.call(tls_server_name=None))
        self.assertEqual(runs, [])
        self.assertTrue(result.tls_verified)
        self.assertEqual(result.tls_server_name, "192.0.2.10")
        self.assertNotIn("FAKE_PINNED_HOSTS", record["environ"])

    def test_verification_line_parser(self) -> None:
        line = "TLS cert verification result of {} : {}\n"
        self.assertEqual(driver.tls_verification("", NAME), (None, None))
        self.assertEqual(driver.tls_verification(line.format(f"{NAME}:5061", "OK"), NAME)[0], True)
        self.assertEqual(driver.tls_verification(line.format("other.lab.test:5061", "OK"), NAME)[0],
                         False)
        mixed = line.format(f"{NAME}:5061", "OK") + line.format(f"{NAME}:5061", "The certificate is untrusted")
        self.assertEqual(driver.tls_verification(mixed, NAME)[0], False)
        self.assertEqual(driver.tls_verification(line.format("[2001:db8::1]:5061", "OK"),
                                                 "2001:db8::1")[0], True)


class RunnerTests(WorkTree):
    def envelope(self, tls: dict | None, transport: str = "tls") -> bytes:
        artifacts = self.base / "steps" / "000002"
        artifacts.mkdir(parents=True, exist_ok=True, mode=0o700)
        envelope = json.loads(runner_tests.step_envelope(artifacts=artifacts, budget=8))
        envelope["step"]["destination"].update(port=5061, transport=transport)
        if tls is not None:
            envelope["step"]["tls"] = tls
        return json.dumps(envelope).encode() + b"\n"

    def run_runner(self, raw: bytes, tls: str = "ok"):
        lines: list[str] = []
        environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "FAKE_PJSUA_TLS": tls,
                       "FAKE_PJSUA_PEER": "192.0.2.10"}
        seen: dict = {}

        def fake_place_call(call, **kwargs):
            seen["call"] = call
            seen["ca"] = Path(call.tls_ca_file).read_bytes() if call.tls_ca_file else None
            return place_call(call, unshare=str(FAKE_UNSHARE), **kwargs)

        with mock.patch.object(campaign_runner, "DEFAULT_CALL_SECONDS", 1), \
                mock.patch.object(campaign_runner, "place_call", fake_place_call):
            code = campaign_runner.run(raw, pjsua=str(FAKE_PJSUA), environ=environment,
                                       emit=lines.append)
        return code, json.loads(lines[0]), seen

    def test_runner_verifies_with_a_private_copy_of_the_reviewed_ca(self) -> None:
        tls = {"serverName": NAME, "caFile": "work/eng/owner-ca.crt", "caSha256": CA_SHA256}
        code, summary, seen = self.run_runner(self.envelope(tls))
        self.assertEqual(code, 0, summary)
        self.assertEqual(summary["tls"]["verified"], True)
        self.assertEqual(summary["tls"]["serverName"], NAME)
        self.assertEqual(summary["tls"]["trust"], "file")
        self.assertEqual(seen["call"].tls_server_name, NAME)
        self.assertEqual(seen["ca"], CA_PEM)
        self.assertNotEqual(Path(seen["call"].tls_ca_file), self.ca)
        code, summary, _ = self.run_runner(self.envelope(tls), tls="mismatch")
        self.assertNotEqual(code, 0)
        self.assertIn("tls_not_verified", summary.get("reasons", []))

    def test_runner_without_tls_facts_verifies_the_ip_against_the_system_store(self) -> None:
        code, summary, seen = self.run_runner(self.envelope(None))
        self.assertEqual(code, 0, summary)
        self.assertEqual(summary["tls"], {"verified": True, "serverName": "192.0.2.10",
                                          "trust": "system", "caSha256": None,
                                          "detail": "192.0.2.10:5061: OK"})
        self.assertIsNone(seen["call"].tls_ca_file)

    def test_runner_refuses_a_changed_ca_and_malformed_tls_facts(self) -> None:
        tls = {"serverName": NAME, "caFile": "work/eng/owner-ca.crt", "caSha256": "1" * 64}
        code, summary, seen = self.run_runner(self.envelope(tls))
        self.assertNotEqual(code, 0)
        self.assertNotIn("call", seen)
        for bad in (
            {"serverName": NAME},
            {"serverName": "10.0.0.1", "caFile": None, "caSha256": None},
            {"serverName": NAME, "caFile": "work/eng/owner-ca.crt", "caSha256": None},
            {"serverName": NAME, "caFile": None, "caSha256": None, "verify": False},
        ):
            with self.subTest(bad=bad):
                code, summary, seen = self.run_runner(self.envelope(bad))
                self.assertEqual(code, campaign_runner.EXIT_INVALID, summary)
                self.assertNotIn("call", seen)
        code, summary, seen = self.run_runner(
            self.envelope({"serverName": NAME, "caFile": None, "caSha256": None}, transport="udp")
        )
        self.assertEqual(code, campaign_runner.EXIT_INVALID)


class GuidedCallTlsTests(unittest.TestCase):
    def softphone(self, **values) -> dict:
        base = {"started": True, "dialed": True, "answered": True, "final_status": 200,
                "registered": True, "tls_verified": True, "tls_server_name": NAME,
                "rtp_tx_packets": 250, "rtp_rx_packets": 250, "media_peer": "192.0.2.10:20000",
                "error": None}
        base.update(values)
        return base

    def classify(self, softphone, media):
        return guided.classify(
            cancelled_signal=None, stop_reason=None,
            preflight_ok=True, softphone=softphone, oracle={"verdict": "unknown"},
            media_required=True, network_mode="private", host="192.0.2.10",
            tls_media=media,
        )

    def test_tls_verdict_uses_pjsua_facts_and_captured_rtp_not_the_oracle(self) -> None:
        media = {"outbound": 250, "inbound": 249}
        state, verdict, code, notes = self.classify(self.softphone(), media)
        self.assertEqual((state, verdict, code), ("completed", "pass", 0))
        self.assertTrue(any("TLS-encrypted" in note for note in notes))
        _s, verdict, code, _n = self.classify(self.softphone(tls_verified=False), media)
        self.assertEqual((verdict, code), ("tls-not-verified", 1))
        _s, verdict, _c, _n = self.classify(
            self.softphone(error="tls_verification_failed", answered=False), media)
        self.assertEqual(verdict, "tls-not-verified")
        _s, verdict, _c, _n = self.classify(self.softphone(), {"outbound": None, "inbound": None})
        self.assertEqual(verdict, "inconclusive")
        _s, verdict, _c, _n = self.classify(self.softphone(), {"outbound": 0, "inbound": 0})
        self.assertEqual(verdict, "fail")
        _s, verdict, _c, _n = self.classify(
            self.softphone(error="tls_name_pinning_unavailable", answered=False), media)
        self.assertEqual(verdict, "tls-name-pinning-failed")

    def test_media_counter_and_tshark_argv(self) -> None:
        argv = guided.tls_media_argv("tshark", Path("/work/c.pcap"), "192.0.2.10:20000")
        self.assertIn("udp.port==20000,rtp", argv)
        self.assertIsNone(guided.tls_media_argv("tshark", Path("c"), None))
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "fields.txt"
            path.write_text("10.0.0.5\t192.0.2.10\n192.0.2.10\t10.0.0.5\n10.0.0.5\t192.0.2.10\nbad\n")
            self.assertEqual(guided.count_tls_media(path, "192.0.2.10:20000", 0),
                             {"peer": "192.0.2.10:20000", "outbound": 2, "inbound": 1,
                              "source": "capture"})
            self.assertIsNone(guided.count_tls_media(path, "192.0.2.10:20000", 2)["outbound"])


class ScopeTests(WorkTree):
    def scope(self, **target) -> dict:
        import test_scope

        document = test_scope.complete_scope()
        document["targets"] = [
            {"name": "edge-tls", "address": "10.20.30.40", "transport": "tls", "port": 5061,
             "tls_server_name": NAME, **target},
        ]
        document["destinations"] = [
            {"name": "echo-tls", "target": "edge-tls", "user": "9196", "expect": "echo"}
        ]
        return document

    def write(self, document: dict) -> Path:
        root = self.base / "assessment"
        root.mkdir(mode=0o700, exist_ok=True)
        path = root / "scope.yaml"
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        path.chmod(0o600)
        return root

    def test_compile_carries_the_name_and_ca_into_profile_and_campaign(self) -> None:
        root = self.write(self.scope(tls_ca_file="work/eng/owner-ca.crt"))
        import test_scope

        result = compile_scope(root, now=test_scope.NOW)
        self.assertEqual(result.exit_code, 0, result.as_dict())
        profile = yaml.safe_load((root / "target-profile.yaml").read_text())
        self.assertEqual(profile["target"]["tls_server_name"], NAME)
        self.assertEqual(profile["target"]["tls_ca_file"], "work/eng/owner-ca.crt")
        manifest = yaml.safe_load((root / "campaign.yaml").read_text())
        self.assertEqual(manifest["targets"][0]["signaling"],
                         {"transport": "tls", "port": 5061, "tlsServerName": NAME,
                          "tlsCaFile": "work/eng/owner-ca.crt"})
        plan = compile_plan(manifest, "0" * 64, resolver=lambda host: [])
        self.assertTrue(all(step["tls"]["caSha256"] == CA_SHA256 for step in plan["steps"]))

    def test_check_rejects_bad_ca_and_placeholder_names(self) -> None:
        import test_scope

        cases = {
            "scope.tls_ca_unreadable": {"tls_ca_file": "work/eng/missing.crt"},
            "scope.placeholder_value": {"tls_server_name": "sbc.example.invalid"},
            "scope.malformed": {"tls_server_name": "10.20.30.40"},
        }
        for code, target in cases.items():
            with self.subTest(code=code):
                root = self.write(self.scope(**target))
                report = inspect(root / "scope.yaml", now=test_scope.NOW)
                self.assertIn(code, {item.code for item in report.errors})
        document = self.scope()
        document["targets"][0].update(transport="udp", port=5060, tls_server_name=None,
                                      tls_ca_file="work/eng/owner-ca.crt")
        root = self.write(document)
        report = inspect(root / "scope.yaml", now=test_scope.NOW)
        self.assertIn("scope.tls_ca_without_tls", {item.code for item in report.errors})

    def test_questions_ask_for_the_certificate_name_and_issuing_ca(self) -> None:
        text = render_questions(None).lower()
        for phrase in ("name is on the certificate", "public ca or a private one",
                       "send us the ca certificate", "never a private key"):
            self.assertIn(phrase, text)


class PracticeTemplateTests(unittest.TestCase):
    def test_tls_profile_and_campaign_render_with_the_practice_ca(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            project = Path(name)
            (project / "examples").symlink_to(ROOT / "examples")
            (project / "media").symlink_to(ROOT / "media")
            (project / "work").mkdir()
            practice.prepare(project, address="127.0.0.2", container="c", image="i")
            state = practice.state_dir(project)
            profile = yaml.safe_load((state / "target-profile-tls.yaml").read_text())
            self.assertEqual(profile["target"]["tls_server_name"], practice.DNS_NAME)
            self.assertEqual(profile["target"]["tls_ca_file"], "work/practice/ca.crt")
            self.assertEqual(profile["target"]["host"], "127.0.0.2")
            manifest = yaml.safe_load((state / "campaign-tls.yaml").read_text())
            signaling = manifest["targets"][0]["signaling"]
            self.assertEqual(signaling["tlsServerName"], practice.DNS_NAME)
            self.assertEqual(signaling["tlsCaFile"], "work/practice/ca.crt")
            self.assertEqual({case["type"] for case in manifest["cases"]}, {"options", "call"})
            plan = compile_plan(manifest, "0" * 64, resolver=lambda host: [],
                                trust_reader=lambda reference: CA_SHA256)
            self.assertEqual({item["address"] for item in plan["resolvedDestinations"]},
                             {"127.0.0.2"})
            udp = yaml.safe_load((state / "target-profile.yaml").read_text())
            self.assertEqual(udp["target"]["transport"], "udp")
            self.assertNotIn("tls_server_name", udp["target"])
            for name_ in ("target-profile-tls.yaml", "campaign-tls.yaml"):
                self.assertNotRegex((state / name_).read_text(), r"@[A-Z_]+@")
                self.assertEqual(stat.S_IMODE((state / name_).stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
