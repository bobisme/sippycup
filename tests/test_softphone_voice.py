"""Host tests for softphone DTMF, SRTP, registration status, and setup timing.

PJSUA is the fixture console ``tests/fixtures/fake_pjsua.py``; capture and
offline tools are injected fakes. No container, capture, or socket is used.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from sippycup.campaign import ManifestError  # noqa: E402
from sippycup.integration import SIPP_RUNNER, SOFTPHONE_RUNNER, select_runner  # noqa: E402
from sippycup.runtime import RuntimeError as PlanError, validate_plan  # noqa: E402
from sippycup_softphone import SoftphoneCall, SoftphoneError, SoftphoneResult, build_config, place_call, redact  # noqa: E402
from sippycup_softphone import campaign_runner  # noqa: E402
from sippycup_softphone import evidence  # noqa: E402
from sippycup_workbench import call as guided  # noqa: E402

from test_guided_call import FAKE_PJSUA, Fakes, profile_document, write_tone  # noqa: E402
from test_softphone_runner import base_manifest, compiled, generated_case, step_envelope  # noqa: E402

LOG = """\
10:00:00.000    pjsua_core.c  .TX 500 bytes Request msg REGISTER/cseq=1 (tdta1) to UDP 192.0.2.10:5060:
REGISTER sip:192.0.2.10 SIP/2.0
--end msg--
10:00:00.010    pjsua_core.c  .RX 400 bytes Response msg 401/REGISTER/cseq=1 (rdata1) from UDP 192.0.2.10:5060:
SIP/2.0 401 Unauthorized
--end msg--
10:00:00.020    pjsua_core.c  .TX 520 bytes Request msg REGISTER/cseq=2 (tdta2) to UDP 192.0.2.10:5060:
REGISTER sip:192.0.2.10 SIP/2.0
Authorization: Digest username="alice"
--end msg--
10:00:00.030    pjsua_core.c  .RX 400 bytes Response msg 403/REGISTER/cseq=2 (rdata2) from UDP 192.0.2.10:5060:
SIP/2.0 403 Forbidden
--end msg--
23:59:59.900    pjsua_core.c  .TX 900 bytes Request msg INVITE/cseq=7 (tdta3) to UDP 192.0.2.10:5060:
INVITE sip:echo@192.0.2.10 SIP/2.0
v=0
m=audio 4002 RTP/SAVP 0 120 121
a=rtpmap:120 telephone-event/16000
a=rtpmap:121 telephone-event/8000
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNk
m=video 5000 RTP/AVP 96
a=rtpmap:96 telephone-event/8000
--end msg--
00:00:00.150    pjsua_core.c  .RX 300 bytes Response msg 180/INVITE/cseq=7 (rdata3) from UDP 192.0.2.10:5060:
SIP/2.0 180 Ringing
--end msg--
00:00:01.400    pjsua_core.c  .RX 900 bytes Response msg 200/INVITE/cseq=7 (rdata4) from UDP 192.0.2.10:5060:
SIP/2.0 200 OK
m=audio 20000 RTP/SAVP 0 101
a=rtpmap:101 telephone-event/8000
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz
--end msg--
00:00:01.401 srtp0x1  .SRTP started, keying=SDES, crypto=AES_CM_128_HMAC_SHA1_80
00:00:02.500     strm0x1  Sending DTMF digit id 1
00:00:02.740     strm0x1  Sending DTMF digit id #
00:00:03.000 pjsua_app.c  .Incoming DTMF on call 0: 1, using RFC2833 method
"""


class GrammarTests(unittest.TestCase):
    def test_dtmf_grammar_is_bounded(self):
        for value in ("1", "0123456789*#ABCD", "1,2,,3", "*" * 32, ",1", "1" * 16 + "," * 32 + "1" * 16):
            with self.subTest(value=value):
                self.assertEqual(evidence.validate_dtmf(value), value)
        for value in ("", ",", ",,", "1" * 33, "a", "E", "1 2", "1;2", "12\n", 12, None, "R",
                      "1" + "," * 33, "١"):
            with self.subTest(value=value), self.assertRaises(evidence.DtmfError):
                evidence.validate_dtmf(value)

    def test_schedule_and_duration(self):
        self.assertEqual(evidence.dtmf_schedule("12,3"), [(0.0, "12"), (1.5, "3")])
        self.assertEqual(evidence.dtmf_schedule("1,,2"), [(0.0, "1"), (2.25, "2")])
        self.assertEqual(evidence.dtmf_seconds("12,3"), 1.75)
        self.assertEqual(evidence.dtmf_digits("1,2#,"), "12#")


class LogParsingTests(unittest.TestCase):
    def test_messages_sdp_setup_and_registration_status(self):
        messages = evidence.parse_messages(LOG)
        self.assertEqual(
            [(item["direction"], item["method"], item["status"]) for item in messages],
            [("TX", "REGISTER", None), ("RX", "REGISTER", 401), ("TX", "REGISTER", None),
             ("RX", "REGISTER", 403), ("TX", "INVITE", None), ("RX", "INVITE", 180),
             ("RX", "INVITE", 200)],
        )
        self.assertEqual(evidence.registration_final_status(messages), 403)
        sdp = evidence.negotiated_sdp(messages)
        self.assertEqual(sdp["offer"], {"port": 4002, "profile": "RTP/SAVP",
                                        "telephoneEvents": [120, 121],
                                        "cryptoSuites": ["AES_CM_128_HMAC_SHA1_80"],
                                        "formats": [0, 120, 121],
                                        "codecs": [{"payloadType": 0, "name": "PCMU",
                                                    "clockRate": 8000}]})
        self.assertEqual(sdp["answer"]["telephoneEvents"], [101])
        setup = evidence.setup_timing(messages)
        # The log crossed midnight between the INVITE and its responses.
        self.assertEqual(setup["inviteToProvisionalSeconds"], 0.25)
        self.assertEqual(setup["inviteToAnswerSeconds"], 1.5)
        self.assertEqual((setup["provisionalStatus"], setup["answerStatus"]), (180, 200))
        self.assertIsNone(evidence.setup_timing([]))

    def test_dtmf_and_srtp_log_facts(self):
        facts = evidence.dtmf_log_facts(LOG)
        self.assertEqual((facts["sent"], facts["received"]), ("1#", "1"))
        self.assertFalse(facts["remoteUnsupported"])
        refused = evidence.dtmf_log_facts(
            "Unable to send DTMF: Remote does not support RFC 2833 (PJMEDIA_RTP_EREMNORFC2833)\n"
        )
        self.assertTrue(refused["remoteUnsupported"])
        self.assertEqual(evidence.srtp_log_facts(LOG)["suite"], "AES_CM_128_HMAC_SHA1_80")
        self.assertTrue(evidence.srtp_log_facts(LOG)["active"])
        self.assertFalse(evidence.srtp_log_facts("SRTP status: Not active Crypto-suite: \n")["active"])
        self.assertIsNone(evidence.srtp_log_facts("nothing\n")["active"])

    def test_sdes_keys_are_redacted(self):
        text = redact(LOG)
        self.assertNotIn("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNk", text)
        self.assertIn("inline:<redacted>", text)

    def test_registration_status_ignores_pjsip_error_codes(self):
        from sippycup_softphone import parse_pjsua_log

        facts = parse_pjsua_log("SIP registration failed, status=171165 (PJSIP_TLS_ECERTVERIF)\n")
        self.assertIsNone(facts["registration_status"])
        self.assertFalse(facts["registered"])


class RtpEventTests(unittest.TestCase):
    ROWS = "\n".join([
        "10.0.0.1\t101\t0x1\t160\t01:0a:00:a0",
        "10.0.0.1\t101\t0x1\t160\t01:8a:03:20",
        "10.0.0.1\t101\t0x1\t160\t01:8a:03:20",
        "10.0.0.1\t0\t0x1\t320\tffffffff",
        "10.0.0.1\t101\t0x1\t800\t0b0a00a0",
        "192.0.2.10\t121\t0x2\t999\t0b8a0320",
        "192.0.2.10\t121\t0x2\t1999\t0c0a0320",
        "garbage",
    ])

    def test_digits_per_direction_from_raw_payloads(self):
        result = evidence.parse_rtp_events(self.ROWS, "192.0.2.10", [101, 121], encrypted=False)
        self.assertEqual(result["outbound"], {"events": 2, "digits": "1#", "endPackets": 2})
        self.assertEqual(result["inbound"]["digits"], "#A")

    def test_encrypted_payload_counts_events_only(self):
        result = evidence.parse_rtp_events(self.ROWS, "192.0.2.10", [101, 121], encrypted=True)
        self.assertEqual(result["outbound"]["events"], 2)
        self.assertIsNone(result["outbound"]["digits"])

    def test_tshark_argv_decodes_raw_payload_on_the_media_port(self):
        argv = evidence.rtp_event_argv("tshark", "/run/capture.pcap", "192.0.2.10:20000")
        self.assertIn("--disable-protocol", argv)
        self.assertIn("udp.port==20000,rtp", argv)
        self.assertIn("rtp.payload", argv)
        self.assertIsNone(evidence.rtp_event_argv("tshark", "c", None))


class DriverTests(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name)
        self.play = self.root / "play.wav"
        write_tone(self.play)

    def tearDown(self):
        self._directory.cleanup()

    def call(self, **values):
        defaults = {
            "destination": "echo", "host": "192.0.2.10", "port": 5060, "transport": "udp",
            "play_file": self.play, "record_file": self.root / "heard.wav", "duration_seconds": 4,
            "log_file": self.root / "softphone.log", "console_file": self.root / "console.txt",
            "allowed_media_addresses": ("192.0.2.10",),
        }
        defaults.update(values)
        return SoftphoneCall(**defaults)

    def run_fake(self, call, mode="answer", password=None, **environment):
        witness = self.root / f"witness-{mode}.json"
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "FAKE_PJSUA_WITNESS": str(witness),
               "FAKE_PJSUA_MODE": mode, **environment}
        private = self.root / f"private-{mode}"
        private.mkdir(mode=0o700, exist_ok=True)
        result = place_call(call, password=password, pjsua=str(FAKE_PJSUA), environment=env,
                            private_root=private)
        # Fails on a leaked private directory (it would hold the password config).
        self.assertEqual(list(private.iterdir()), [], "private directory leaked")
        self.assertNotIn("private-directory-not-removed", result.warnings)
        return result, json.loads(witness.read_text())

    def test_srtp_config_lines(self):
        self.assertNotIn("--use-srtp", build_config(self.call()))
        udp = build_config(self.call(srtp="mandatory")).splitlines()
        self.assertIn("--use-srtp=2", udp)
        self.assertIn("--srtp-secure=0", udp)
        self.assertIn("--srtp-keying=0", udp)
        tls = build_config(self.call(srtp="optional", transport="tls", port=5061)).splitlines()
        self.assertIn("--use-srtp=1", tls)
        self.assertIn("--srtp-secure=1", tls)

    def test_refusals_before_anything_starts(self):
        for values in ({"srtp": "dtls"}, {"srtp": True}, {"dtmf": "12x"}, {"dtmf": ""},
                       {"dtmf": "1", "dtmf_after_seconds": -1}, {"dtmf": "1", "dtmf_after_seconds": 61},
                       {"dtmf": "1", "dtmf_after_seconds": True},
                       {"dtmf": "1" * 20, "duration_seconds": 4}):
            with self.subTest(values=values), self.assertRaises(SoftphoneError):
                build_config(self.call(**values))

    def test_dtmf_is_sent_with_the_rfc2833_console_command_and_pauses(self):
        result, record = self.run_fake(self.call(dtmf="12,3", dtmf_after_seconds=0),
                                       FAKE_PJSUA_ECHO_DTMF="1")
        self.assertTrue(result.ok, result)
        commands = record["commands"]
        self.assertEqual(commands[commands.index("#") + 1], "12")
        self.assertEqual(commands[len(commands) - 1 - commands[::-1].index("#") + 1], "3")
        self.assertEqual(commands.count("#"), 2)
        self.assertEqual(result.dtmf["status"], "sent")
        self.assertEqual(result.dtmf["sent"], "123")
        self.assertEqual(result.dtmf["received"], "123")
        self.assertEqual(result.dtmf["answeredPayloadTypes"], [101])
        self.assertTrue(result.dtmf["negotiated"])
        self.assertEqual(result.local_rtp_port, 4000)
        self.assertEqual(result.setup["answerStatus"], 200)
        self.assertEqual(result.setup["provisionalStatus"], 180)
        pause = [item["at"] for item in result.timeline if item["state"] == "DTMF"]
        self.assertGreaterEqual(pause[1] - pause[0], 1.4)

    def test_peer_without_telephone_event_is_not_negotiated_and_never_falls_back(self):
        result, record = self.run_fake(self.call(dtmf="5"), FAKE_PJSUA_DTMF="none")
        self.assertEqual(result.error, "dtmf_not_negotiated")
        self.assertEqual(result.dtmf["status"], "notNegotiated")
        self.assertFalse(result.dtmf["negotiated"])
        self.assertEqual(result.dtmf["sent"], "")
        # The SIP INFO console command (*) is never used.
        self.assertNotIn("*", record["commands"])

    def test_wrong_password_reports_the_final_register_status(self):
        result, _record = self.run_fake(
            self.call(account=campaign_runner.SoftphoneAccount(username="alice", registrar="sip:192.0.2.10")),
            mode="regfail401", password="wrong-password",
        )
        self.assertFalse(result.registered)
        self.assertEqual(result.registration_status, 401)
        self.assertEqual(result.error, "registration_failed")

    def test_mandatory_srtp_against_a_plain_peer_is_not_negotiated(self):
        result, record = self.run_fake(self.call(srtp="mandatory"), FAKE_PJSUA_SRTP_PEER="plain")
        self.assertEqual(result.error, "srtp_not_negotiated")
        self.assertEqual(result.final_status, 488)
        self.assertFalse(result.srtp["active"])
        self.assertEqual(result.srtp["offerProfile"], "RTP/SAVP")
        self.assertIn("sdes-key-exposed-on-cleartext-signaling", result.warnings)
        self.assertIn("--use-srtp=2", record["config"].splitlines())

    def test_optional_srtp_reports_what_was_negotiated(self):
        result, _ = self.run_fake(self.call(srtp="optional"))
        self.assertTrue(result.ok)
        self.assertTrue(result.srtp["active"])
        self.assertEqual(result.srtp["suite"], "AES_CM_128_HMAC_SHA1_80")
        self.assertEqual(result.srtp["answerProfile"], "RTP/AVP")
        plain, _ = self.run_fake(self.call(srtp="optional"), FAKE_PJSUA_SRTP_PEER="plain")
        self.assertTrue(plain.ok)
        self.assertFalse(plain.srtp["active"])
        log = (self.root / "softphone.log").read_text()
        self.assertNotIn("WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz", log)

    def test_silent_far_end_is_unknown_not_out_of_scope_and_runs_its_duration(self):
        call = self.call(duration_seconds=2, allowed_media_ports=(4000, 4100))
        result, _ = self.run_fake(call, mode="silent")
        self.assertIsNone(result.error, result)
        self.assertEqual(result.hangup, "duration")
        self.assertIsNone(result.media_peer)
        self.assertEqual(result.rtp_rx_packets, 0)
        self.assertGreaterEqual(result.connected_seconds or 0, 1.5)
        # A real out-of-scope peer is still hung up.
        outside, _ = self.run_fake(self.call(duration_seconds=2), mode="outside")
        self.assertEqual(outside.error, "media_peer_outside_scope")

    def test_exclusive_codecs_disable_everything_else(self):
        lines = build_config(self.call(codecs=("PCMA", "PCMU"), exclusive_codecs=True)).splitlines()
        disable = lines.index("--dis-codec=*")
        self.assertLess(disable, lines.index("--add-codec=PCMU"))
        self.assertEqual([line for line in lines if "codec" in line],
                         ["--dis-codec=*", "--add-codec=PCMU", "--add-codec=PCMA"])
        self.assertNotIn("--dis-codec=*", build_config(self.call()))
        with self.assertRaises(SoftphoneError):
            build_config(self.call(exclusive_codecs="yes"))

    def test_every_exit_path_removes_the_private_directory(self):
        account = campaign_runner.SoftphoneAccount(username="alice", registrar="sip:192.0.2.10")
        digest = campaign_runner.SoftphoneAccount(username="alice")
        for mode, values in (("regfail401", {"account": account}), ("authfail", {"account": digest}),
                             ("outside", {"account": digest}),
                             ("silent", {"account": digest, "duration_seconds": 1})):
            with self.subTest(mode=mode):
                self.run_fake(self.call(**values), mode=mode, password="Pw-123")
        private = self.root / "private-missing"
        private.mkdir(mode=0o700)
        result = place_call(self.call(), pjsua=str(self.root / "no-pjsua"),
                            environment={"PATH": "/usr/bin:/bin"}, private_root=private)
        self.assertTrue(result.error.startswith("softphone_start_failed"))
        self.assertEqual(list(private.iterdir()), [])

    def test_removal_retries_while_a_late_writer_recreates_its_log(self):
        from sippycup_softphone import driver

        private = self.root / "late"
        private.mkdir(mode=0o700)
        secret = private / "pjsua.cfg"
        secret.write_text("--password=x\n")
        calls = {"count": 0}
        real_rmtree = driver.shutil.rmtree

        def racing_rmtree(path, ignore_errors=False):
            real_rmtree(path, ignore_errors=ignore_errors)
            calls["count"] += 1
            if calls["count"] < 3:
                # A writer that still holds the directory recreates its log.
                Path(path).mkdir(exist_ok=True)
                (Path(path) / "pjsua.log").write_text("late\n")

        with mock.patch.object(driver.shutil, "rmtree", racing_rmtree), \
                mock.patch.object(driver, "PRIVATE_REMOVE_DELAY", 0):
            self.assertTrue(driver.remove_private_directory(private, (secret,)))
        self.assertFalse(private.exists())
        self.assertEqual(calls["count"], 3)

    def test_stop_process_kills_descendants_left_in_the_process_group(self):
        import subprocess
        import time as _time

        from sippycup_softphone import driver

        marker = self.root / "child.pid"
        process = subprocess.Popen(
            ["/bin/sh", "-c", f"sleep 30 & echo $! > {marker}; exit 0"], start_new_session=True,
        )
        process.wait(timeout=5)
        deadline = _time.monotonic() + 5
        while not marker.exists() or not marker.read_text().strip():
            self.assertLess(_time.monotonic(), deadline)
            _time.sleep(0.02)
        child = int(marker.read_text())
        driver._stop_process(process)
        deadline = _time.monotonic() + 5
        while _time.monotonic() < deadline:
            try:
                state = Path(f"/proc/{child}/stat").read_text().split()[2]
            except (FileNotFoundError, ProcessLookupError):
                break
            if state == "Z":
                break
            _time.sleep(0.02)
        else:
            self.fail("descendant survived _stop_process")

    def test_off_reports_plain_media_and_no_warning(self):
        result, _ = self.run_fake(self.call())
        self.assertEqual(result.srtp["requested"], "off")
        self.assertFalse(result.srtp["active"])
        self.assertEqual(result.warnings, [])
        self.assertIsNone(result.dtmf)


class GuidedCallTests(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.work = Path(self._directory.name) / "work"
        (self.work / "engagement").mkdir(parents=True)
        self.profile = self.work / "engagement" / "profile.yaml"
        self.profile.write_text(yaml.safe_dump(profile_document()))

    def tearDown(self):
        self._directory.cleanup()

    def execute(self, fakes, **values):
        options = guided.CallOptions(profile=self.profile, destination="echo", duration=5, **values)
        return guided.execute(options, fakes.dependencies(self.work))

    def test_srtp_default_comes_from_the_profile(self):
        options = guided.CallOptions(profile=self.profile, destination="echo")
        self.assertEqual(guided.srtp_mode(options, profile_document()), "off")
        srtp_udp = profile_document(**{"features": {"srtp": True}})
        self.assertEqual(guided.srtp_mode(options, srtp_udp), "off")
        srtp_tls = copy.deepcopy(srtp_udp)
        srtp_tls["target"]["transport"] = "tls"
        self.assertEqual(guided.srtp_mode(options, srtp_tls), "optional")
        self.assertEqual(guided.srtp_mode(guided.CallOptions(profile=self.profile, destination="e",
                                                             srtp="mandatory"), profile_document()),
                         "mandatory")

    def test_invalid_dtmf_or_srtp_is_refused_with_nothing_sent(self):
        for values in ({"dtmf": "12Z"}, {"srtp": "maybe"}, {"dtmf": "1", "dtmf_after": 99},
                       {"dtmf": "1" * 30}):
            fakes = Fakes()
            with self.subTest(values=values), self.assertRaises(guided.CallError):
                self.execute(fakes, **values)
            self.assertEqual(fakes.events, [])

    def test_dry_run_and_config_carry_dtmf_and_srtp(self):
        fakes = Fakes()
        code, plan = self.execute(fakes, dtmf="1#", srtp="mandatory", dry_run=True)
        self.assertEqual(code, 0)
        self.assertEqual(plan["softphone"]["dtmf"]["digits"], "1#")
        self.assertIsNone(plan["softphone"]["dtmf"]["fallback"])
        self.assertEqual(plan["softphone"]["srtp"]["warning"], "sdes-key-exposed-on-cleartext-signaling")
        rendered = guided.render_human(plan)
        self.assertIn("DTMF:            1# as RFC 4733 events", rendered)
        self.assertIn("WARNING sdes-key-exposed-on-cleartext-signaling", rendered)
        self.assertEqual(fakes.events, [])

    def test_dtmf_wire_report_compares_the_capture_with_the_request(self):
        root = Path(self._directory.name)
        rows = root / "events.txt"
        rows.write_text(RtpEventTests.ROWS.replace("10.0.0.1", "10.0.2.100"))
        softphone = {
            "media_peer": "192.0.2.10:20000",
            "dtmf": {"status": "sent", "sent": "1#", "offeredPayloadTypes": [121],
                     "answeredPayloadTypes": [101], "negotiated": True},
            "srtp": {"active": False},
        }
        report = guided.dtmf_wire_report("1,#", softphone, rows, 0)
        self.assertTrue(report["verified"])
        self.assertEqual((report["sent"], report["echoed"], report["sentSource"]), ("1#", "#A", "capture"))
        report = guided.dtmf_wire_report("12", softphone, rows, 0)
        self.assertFalse(report["verified"])
        self.assertEqual(report["status"], "mismatch")
        encrypted = guided.dtmf_wire_report("1#", {**softphone, "srtp": {"active": True}}, rows, 0)
        self.assertIsNone(encrypted["verified"])
        self.assertEqual(encrypted["wire"]["outbound"]["events"], 2)
        self.assertIsNone(guided.dtmf_wire_report(None, softphone, rows, 0))
        self.assertIn("note", guided.dtmf_wire_report("1", softphone, rows, None)["wire"])

    def classify(self, softphone, **values):
        base = {"started": True, "dialed": True, "answered": True, "final_status": 200,
                "rtp_tx_packets": 10, "rtp_rx_packets": 10, "error": None, "registered": None}
        base.update(softphone)
        return guided.classify(cancelled_signal=None, stop_reason=None, preflight_ok=True,
                               softphone=base, oracle={"verdict": "pass", "stream_directions": []},
                               media_required=True, network_mode="private", host="127.0.0.2", **values)

    def test_distinct_verdicts(self):
        self.assertEqual(self.classify({"answered": False, "final_status": 488,
                                        "error": "srtp_not_negotiated"})[1], "srtp-not-negotiated")
        self.assertEqual(self.classify({"error": "dtmf_not_negotiated"})[1], "dtmf-not-negotiated")
        self.assertEqual(self.classify({"error": "dtmf_not_sent", "dtmf": {"sent": "1",
                                        "requestedDigits": "12"}})[1], "dtmf-mismatch")
        state, verdict, code, notes = self.classify({"registered": False, "registration_status": 401})
        self.assertEqual((verdict, code), ("registration-failed", 1))
        self.assertIn("Registration was rejected with SIP status 401.", notes)
        mismatch = {"requestedDigits": "12", "verified": False, "wire": {"outbound": {"digits": "1"}}}
        self.assertEqual(self.classify({}, dtmf=mismatch)[1], "dtmf-mismatch")
        verified = {"requestedDigits": "12", "verified": True, "echoed": "12", "wire": {}}
        self.assertEqual(self.classify({}, dtmf=verified)[1], "pass")
        unknown = {"requestedDigits": "12", "verified": None, "wire": {"note": "tshark exited 2"}}
        self.assertEqual(self.classify({}, dtmf=unknown)[1], "inconclusive")
        hidden = {"requestedDigits": "12", "verified": None, "pjsuaSent": "12",
                  "wire": {"encrypted": True, "outbound": {"events": 2}}}
        srtp_media = {"outbound": 10, "inbound": 10}
        self.assertEqual(self.classify({"srtp": {"active": True}}, dtmf=hidden,
                                       srtp_media=srtp_media)[1], "pass")
        self.assertEqual(self.classify({"srtp": {"active": True}}, srtp_media={"outbound": 10, "inbound": 0})[1],
                         "one-way-media")
        slow = self.classify({"tls_verified": True, "setup": {"inviteToAnswerSeconds": 9.0}},
                             tls_media={"outbound": 5, "inbound": 5})
        self.assertEqual(slow[1], "fail")

    def test_guided_call_with_dtmf_records_expectations_and_wire_analysis(self):
        fakes = Fakes()

        def answered(call, cancel):
            self.assertEqual(call.dtmf, "1#")
            self.assertEqual(call.srtp, "off")
            result = SoftphoneResult(destination_uri="sip:x")
            result.started = result.dialed = result.answered = True
            result.final_status = result.disconnect_status = 200
            result.rtp_tx_packets = result.rtp_rx_packets = 100
            result.media_peer = "192.0.2.10:20000"
            result.srtp = {"requested": "off", "active": False}
            result.dtmf = {"status": "sent", "sent": "1#", "received": "1#",
                           "offeredPayloadTypes": [121], "answeredPayloadTypes": [101],
                           "negotiated": True, "requestedDigits": "1#"}
            result.setup = {"inviteToAnswerSeconds": 0.2, "answerStatus": 200}
            return result

        fakes.softphone_behavior = answered
        original = fakes.run_offline

        def run_offline(argv, stdout, stderr, environment):
            if "rtp.payload" in argv:
                fakes.events.append("dtmf-events")
                stdout.write_text("10.0.2.100\t101\t0x1\t160\t01:8a:03:20\n"
                                  "10.0.2.100\t101\t0x1\t800\t0b8a0320\n"
                                  "192.0.2.10\t121\t0x2\t9\t018a0320\n192.0.2.10\t121\t0x2\t99\t0b8a0320\n")
                stderr.write_text("")
                return 0
            return original(argv, stdout, stderr, environment)

        fakes.run_offline = run_offline
        code, value = self.execute(fakes, dtmf="1#")
        self.assertEqual(code, 0, value)
        self.assertIn("dtmf-events", fakes.events)
        self.assertEqual(value["dtmf"]["sent"], "1#")
        self.assertEqual(value["dtmf"]["echoed"], "1#")
        self.assertTrue(value["dtmf"]["verified"])
        self.assertEqual(value["setup"]["inviteToAnswerSeconds"], 0.2)
        run_dir = self.work / value["runDirectory"].removeprefix("work/")
        expectations = yaml.safe_load((run_dir / "expectations.yaml").read_text())
        self.assertTrue(expectations["expectations"][0]["parameters"]["require_dtmf"])
        schema = json.loads((ROOT / "schemas" / "call-result-v1.schema.json").read_text())
        self.assertIn(value["verdict"], schema["properties"]["verdict"]["enum"])
        for verdict in ("srtp-not-negotiated", "dtmf-not-negotiated", "dtmf-mismatch"):
            self.assertIn(verdict, schema["properties"]["verdict"]["enum"])
        rendered = guided.render_human(value)
        self.assertIn("DTMF:         requested 1# (rfc4733), status sent; on the wire sent '1#'", rendered)
        self.assertIn("Setup:        INVITE to 180/183 not seen, to 200 0.200s", rendered)

    def test_registration_status_is_rendered(self):
        value = {"verdict": "registration-failed", "state": "failed",
                 "target": {"host": "h", "port": 1, "transport": "udp"}, "destinationUri": "sip:x",
                 "preflight": None, "runDirectory": "work/x", "journalCommand": ["x"],
                 "networkActivity": "n",
                 "softphone": {"registration_attempted": True, "registered": False,
                               "registration_status": 401, "final_status": None,
                               "connected_seconds": None, "answered": False, "hangup": None,
                               "error": "registration_failed", "rtp_tx_packets": None,
                               "rtp_rx_packets": None, "codec": None}}
        self.assertIn("Registration: FAILED (status 401)", guided.render_human(value))


def dtmf_manifest(**case_call):
    manifest = base_manifest()
    manifest["cases"][1]["call"] = case_call or {"dtmf": "1#"}
    manifest["targets"][0]["media"] = {"srtp": "optional"}
    return manifest


class CampaignFieldTests(unittest.TestCase):
    def test_call_and_media_are_frozen_into_call_steps_only(self):
        plan, _raw = compiled(dtmf_manifest(dtmf="12,3", dtmfAfterSeconds=0, durationSeconds=8))
        options, call = plan["steps"]
        self.assertNotIn("call", options)
        self.assertNotIn("media", options)
        self.assertEqual(call["call"], {"dtmf": "12,3", "dtmfAfterSeconds": 0, "durationSeconds": 8})
        self.assertEqual(call["media"], {"srtp": "optional"})
        validate_plan(plan)
        self.assertEqual(select_runner(call), SOFTPHONE_RUNNER)
        bare = {key: value for key, value in call.items() if key not in ("dial", "account")}
        bare["credentialRef"] = None
        self.assertEqual(select_runner(bare), SOFTPHONE_RUNNER)
        plain = {key: value for key, value in bare.items() if key not in ("call", "media")}
        self.assertEqual(select_runner(plain), SIPP_RUNNER)
        self.assertEqual(select_runner({**plain, "media": {"srtp": "off"}}), SOFTPHONE_RUNNER)

    def test_manifest_without_new_fields_is_unchanged(self):
        plan, _ = compiled(base_manifest())
        self.assertFalse(any("call" in step or "media" in step for step in plan["steps"]))

    def test_invalid_call_and_media_are_rejected(self):
        cases = {
            "unquoted digits": (("cases", 1, "call"), {"dtmf": 1234}),
            "bad digit": (("cases", 1, "call"), {"dtmf": "12x"}),
            "too many digits": (("cases", 1, "call"), {"dtmf": "1" * 33}),
            "missing dtmf": (("cases", 1, "call"), {"dtmfAfterSeconds": 1}),
            "unknown key": (("cases", 1, "call"), {"dtmf": "1", "method": "info"}),
            "after too late": (("cases", 1, "call"), {"dtmf": "1", "dtmfAfterSeconds": 61}),
            "after negative": (("cases", 1, "call"), {"dtmf": "1", "dtmfAfterSeconds": -1}),
            "duration zero": (("cases", 1, "call"), {"dtmf": "1", "durationSeconds": 0}),
            "call on options": (("cases", 0, "call"), {"dtmf": "1"}),
            "media scalar": (("targets", 0, "media"), "srtp"),
            "media dtls": (("targets", 0, "media"), {"srtp": "dtls"}),
            "media unknown key": (("targets", 0, "media"), {"srtp": "off", "keying": "dtls"}),
        }
        for name, (path, value) in cases.items():
            with self.subTest(name=name):
                manifest = dtmf_manifest()
                manifest[path[0]][path[1]][path[2]] = value
                with self.assertRaises(ManifestError):
                    compiled(manifest)

    def test_runtime_rejects_tampered_call_and_media(self):
        plan, _raw = compiled(dtmf_manifest())
        changes = {
            "dtmf injection": lambda p: p["steps"][1]["call"].update(dtmf="1;info"),
            "dtmf too long": lambda p: p["steps"][1]["call"].update(dtmf="1" * 33),
            "unknown call key": lambda p: p["steps"][1]["call"].update(method="sip-info"),
            "call on options": lambda p: p["steps"][0].update(call={"dtmf": "1"}),
            "media on options": lambda p: p["steps"][0].update(media={"srtp": "off"}),
            "media enum": lambda p: p["steps"][1]["media"].update(srtp="dtls"),
            "duration with generated": lambda p: (
                p["steps"][1]["call"].update(durationSeconds=5),
                p["steps"][1].update(generated=generated_case()),
            ),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                tampered = copy.deepcopy(plan)
                change(tampered)
                with self.assertRaises(PlanError):
                    validate_plan(tampered)

    def test_media_must_be_uniform_across_a_targets_call_steps(self):
        manifest = dtmf_manifest()
        manifest["cases"][1]["count"] = 2
        plan, _ = compiled(manifest)
        validate_plan(plan)
        plan["steps"][2]["media"] = {"srtp": "off"}
        with self.assertRaises(PlanError):
            validate_plan(plan)
        del plan["steps"][2]["media"]
        with self.assertRaises(PlanError):
            validate_plan(plan)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name)
        self.artifacts = self.root / "steps" / "000002"
        self.artifacts.mkdir(parents=True, mode=0o700)

    def tearDown(self):
        self._directory.cleanup()

    def envelope(self, call=None, media=None, **kwargs):
        envelope = json.loads(step_envelope(artifacts=self.artifacts, **kwargs))
        if call is not None:
            envelope["step"]["call"] = call
        if media is not None:
            envelope["step"]["media"] = media
        return json.dumps(envelope).encode() + b"\n"

    def run_runner(self, raw, mode="answer", **environment):
        lines: list[str] = []
        witness = self.root / "witness.json"
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "FAKE_PJSUA_WITNESS": str(witness),
               "FAKE_PJSUA_MODE": mode, **environment}
        private = self.root / "private"
        private.mkdir(mode=0o700, exist_ok=True)
        code = campaign_runner.run(raw, pjsua=str(FAKE_PJSUA), environ=env, emit=lines.append,
                                   private_root=private)
        self.assertEqual(list(private.iterdir()), [], "private directory leaked")
        self.assertEqual(len(lines), 1)
        self.assertLessEqual(len(lines[0].encode()), campaign_runner.MAX_LINE_BYTES)
        return code, json.loads(lines[0]), (json.loads(witness.read_text()) if witness.exists() else None)

    def test_dtmf_call_reports_sent_received_setup_and_srtp(self):
        raw = self.envelope(call={"dtmf": "1#", "dtmfAfterSeconds": 0, "durationSeconds": 3},
                            media={"srtp": "optional"})
        code, summary, record = self.run_runner(raw, FAKE_PJSUA_ECHO_DTMF="1")
        self.assertEqual(code, 0, summary)
        self.assertEqual(summary["dtmf"]["status"], "sent")
        self.assertEqual(summary["dtmf"]["sent"], "1#")
        self.assertEqual(summary["dtmf"]["received"], "1#")
        self.assertEqual(summary["dtmf"]["method"], "rfc4733")
        self.assertEqual(summary["durationSeconds"]["effective"], 3)
        self.assertTrue(summary["srtp"]["active"])
        self.assertEqual(summary["warnings"], ["sdes-key-exposed-on-cleartext-signaling"])
        self.assertEqual(summary["setup"]["answerStatus"], 200)
        self.assertEqual(summary["localRtpPort"], 4000)
        self.assertIn("--use-srtp=1", record["config"].splitlines())

    def test_dtmf_not_negotiated_and_srtp_not_negotiated_fail(self):
        code, summary, _ = self.run_runner(self.envelope(call={"dtmf": "5"}), FAKE_PJSUA_DTMF="none")
        self.assertEqual(code, 1)
        self.assertIn("dtmf_not_negotiated", summary["reasons"])
        code, summary, _ = self.run_runner(self.envelope(media={"srtp": "mandatory"}),
                                           FAKE_PJSUA_SRTP_PEER="plain")
        self.assertEqual(code, 1)
        self.assertIn("srtp_not_negotiated", summary["reasons"])
        self.assertEqual(summary["finalStatus"], 488)

    def test_wrong_password_status_is_in_the_result_line(self):
        code, summary, _ = self.run_runner(self.envelope(register=True), mode="regfail401")
        self.assertEqual(code, 1)
        self.assertEqual(summary["registrationStatus"], 401)
        self.assertIn("registration_failed", summary["reasons"])

    def test_dtmf_lengthens_the_call_within_the_budget_or_is_refused(self):
        step = {"budget": {"durationSeconds": 12}, "call": {"dtmf": "1" * 12, "dtmfAfterSeconds": 2}}
        duration = campaign_runner.call_duration(step)
        self.assertEqual(duration["dtmfNeeds"], 6)
        self.assertEqual(duration["effective"], 6)
        self.assertTrue(duration["lengthenedForDtmf"])
        raw = self.envelope(call={"dtmf": "1" * 32, "dtmfAfterSeconds": 9}, budget=12)
        code, summary, _ = self.run_runner(raw)
        self.assertEqual(code, 2)
        self.assertIn("DTMF", summary["error"])

    def test_invalid_call_or_media_envelopes_exit_two(self):
        for call, media in (({"dtmf": "12x"}, None), ({"dtmf": "1", "x": 1}, None),
                            ({"dtmf": "1", "dtmfAfterSeconds": 61}, None), (None, {"srtp": "dtls"}),
                            (None, {"srtp": "off", "extra": 1})):
            with self.subTest(call=call, media=media):
                code, summary, record = self.run_runner(self.envelope(call=call, media=media))
                self.assertEqual(code, 2)
                self.assertIsNone(record)

    def test_matrix_dtmf_and_media_protection_factors_are_honest(self):
        with mock.patch.object(campaign_runner, "DEFAULT_CALL_SECONDS", 1):
            generated = generated_case(dtmf="rfc4733", mediaProtection="sdes-srtp", duration=3)
            generated["actions"] = ["dtmf", "dtmf", "hangup"]
            code, summary, _ = self.run_runner(
                self.envelope(call={"dtmf": "7", "dtmfAfterSeconds": 0}, media={"srtp": "mandatory"},
                              generated=generated)
            )
            self.assertEqual(code, 0, summary)
            factors = summary["factors"]
            self.assertEqual(factors["exercised"]["dtmf"], "rfc4733")
            self.assertEqual(factors["exercised"]["mediaProtection"], "sdes-srtp")
            self.assertEqual(factors["actions"]["exercised"][0], {"position": 1, "action": "dtmf"})
            self.assertIn({"position": 2, "action": "dtmf"}, factors["actions"]["notExercised"])
            code, summary, _ = self.run_runner(
                self.envelope(generated=generated_case(dtmf="rfc4733", mediaProtection="sdes-srtp"))
            )
            factors = summary["factors"]
            self.assertIn("cases[].call.dtmf", factors["notExercised"]["dtmf"])
            self.assertIn("media.srtp is off", factors["notExercised"]["mediaProtection"])
            code, summary, _ = self.run_runner(
                self.envelope(generated=generated_case(dtmf="sip-info", mediaProtection="dtls-srtp"))
            )
            self.assertIn("never SIP INFO", summary["factors"]["notExercised"]["dtmf"])
            self.assertIn("never DTLS", summary["factors"]["notExercised"]["mediaProtection"])


if __name__ == "__main__":
    unittest.main()
