"""Tests for `sippycup diagnose` on small synthetic run directories."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from ladder_support import Capture, basic_call  # noqa: E402

from sippycup_diagnose import cli as diagnose_cli  # noqa: E402
from sippycup_diagnose.call import HANDLERS  # noqa: E402
from sippycup_workbench.call_explanations import CALL_EXPLANATIONS  # noqa: E402

BIN = ROOT / "bin" / "sippycup-diagnose"
SIPPYCUP = ROOT / "bin" / "sippycup"
FORBIDDEN = (
    "NONCEVALUE", "RESPONSEHASH", "SECRETKEY", "inline:", "a=crypto", "hunter2-secret-pw",
    "alice-private-user", "call-one@", "Authorization:", "WWW-Authenticate", "192.0.2.99",
    "sip:alice-private-user", "4155550123",
)

APPROVED = ["198.51.100.10", "198.51.100.11"]


def run_cli(*args: str, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(BIN), *args], text=True, capture_output=True, timeout=180, check=check,
    )


def sip_block(t: str, outbound: bool, first: str, headers: tuple = (), sdp: tuple = ()) -> str:
    """One PJSUA log message. `first` is e.g. 'INVITE' or '503 Service Unavailable'."""
    is_response = first[0].isdigit()
    status = first.split()[0] if is_response else ""
    method = "INVITE" if "INVITE" in first or is_response else first.split()[0]
    descriptor = f"Response msg {status}/{headers_method(headers)}/cseq=101" if is_response else f"Request msg {first.split()[0]}/cseq=101"
    direction = "TX" if outbound else "RX"
    arrow = "to" if outbound else "from"
    start = f"SIP/2.0 {first}" if is_response else f"{first} sip:alice-private-user@198.51.100.10:5060 SIP/2.0"
    lines = [
        f"{t}           pjsua_core.c  .{direction} 500 bytes {descriptor} (rdata0x1) {arrow} UDP 198.51.100.10:5060:",
        start,
        "Via: SIP/2.0/UDP 198.51.100.99:5060;branch=z9hG4bKaaa",
        "Call-ID: call-one@198.51.100.99",
        "From: <sip:alice-private-user@198.51.100.10>;tag=aa",
        f"CSeq: 101 {method_of(headers, first)}",
    ]
    lines += [h for h in headers if not h.startswith("@")]
    if sdp:
        lines += ["Content-Type: application/sdp", "Content-Length: 200", ""] + list(sdp)
    else:
        lines += ["Content-Length: 0", ""]
    lines += ["", "--end msg--"]
    return "\n".join(lines)


def headers_method(headers: tuple) -> str:
    for header in headers:
        if header.startswith("@method="):
            return header.split("=", 1)[1]
    return "INVITE"


def method_of(headers: tuple, first: str) -> str:
    return headers_method(headers) if first[0].isdigit() else first.split()[0]


def sdp_lines(address: str, port: int, formats: str = "0 8 120", extra: tuple = ()) -> tuple:
    return (
        "v=0", f"o=- 1 1 IN IP4 {address}", "s=pjmedia", f"c=IN IP4 {address}", "t=0 0",
        f"m=audio {port} RTP/AVP {formats}", "a=rtpmap:0 PCMU/8000", "a=sendrecv", *extra,
    )


class Fixture:
    """A synthetic guided-call run directory under <tmp>/work/eng/calls/."""

    def __init__(self, root: Path, name: str = "20260101T000000.000000Z-profile-abcd1234") -> None:
        self.root = root
        self.eng = root / "work" / "eng"
        self.eng.mkdir(parents=True, exist_ok=True)
        self.dir = self.eng / "calls" / name
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.eng / "target-profile.yaml").write_text(
            "schema_version: sippycup.dev/target-profile/v1\nname: eng-profile\n"
            "target:\n  host: '198.51.100.10'\n  port: 5060\n  transport: udp\n  approved_addresses:\n    - '198.51.100.10'\n    - '198.51.100.11'\n"
            "authorization:\n  status: approved\n  valid_until: '2999-01-01T00:00:00Z'\n",
            encoding="utf-8",
        )

    def write(self, name: str, value) -> None:
        text = value if isinstance(value, str) else json.dumps(value)
        (self.dir / name).write_text(text, encoding="utf-8")

    def call(
        self,
        verdict: str,
        *,
        state: str = "failed",
        softphone: dict | None = None,
        notes: list | None = None,
        plan_phone: dict | None = None,
        result: dict | None = None,
        log: list | None = None,
        profile_features: dict | None = None,
        practice: bool = False,
        preflight: dict | None = None,
        transport: str = "udp",
    ) -> "Fixture":
        phone = {"registration_attempted": True, "registered": True, "registration_status": 200, "dialed": True,
                 "answered": False, "final_status": None, "rtp_tx_packets": None, "rtp_rx_packets": None,
                 "error": None, "setup": {}, "hangup": None, "connected_seconds": None}
        phone.update(softphone or {})
        value = {
            "apiVersion": "sippycup.dev/call-result/v1", "state": state, "verdict": verdict, "exitCode": 1,
            "profile": "eng-profile", "target": {"host": "198.51.100.10", "port": 5060, "transport": transport},
            "destinationUri": "sip:echo@198.51.100.10:5060", "localAddress": "203.0.113.77", "networkMode": "private",
            "notes": notes or [], "softphone": phone,
            "preflight": preflight if preflight is not None else {"ok": True, "detail": "SIP/2.0 200 OK"},
            "setup": phone.get("setup") or {}, "mediaScope": {"rules": {"approvedAddresses": APPROVED}},
            "codec": {}, "oracle": {}, "srtp": {"mode": "off"}, "warnings": [],
            "timestamps": {}, "runDirectory": f"work/eng/calls/{self.dir.name}",
        }
        value.update(result or {})
        self.write("result.json", value)
        pp = {
            "destination_uri": "sip:echo@198.51.100.10:5060", "transport": transport, "answer_timeout_seconds": 20,
            "duration_seconds": {"requested": 5, "limit": 60, "effective": 5}, "codecs": ["PCMU"], "codec_offer": "preferred",
            "approved_codecs": None, "media_required": True, "dtmf": None, "srtp": {"mode": "off", "requested_by": "profile features.srtp"},
            "account": {"username": "bob-user", "realm": "*", "register": True, "password_source": "file /work/eng/secret.txt"},
        }
        pp.update(plan_phone or {})
        self.write("plan.json", {
            "schema_version": "sippycup.dev/call-plan/v1", "profile": "eng-profile",
            "profile_path": "work/eng/target-profile.yaml", "softphone": pp,
            "target": {"host": "198.51.100.10", "port": 5060, "transport": transport},
            "authorization": {"networks": APPROVED + ["203.0.113.77/32"]}, "local_address": "203.0.113.77",
        })
        authorization = {"approval_id": "LOCAL-PRACTICE-ONLY"} if practice else {"approval_id": "REAL-1"}
        self.write("profile.json", {"authorization": authorization, "features": profile_features or {}, "target": {"host": "198.51.100.10", "approved_addresses": APPROVED}})
        self.write("timestamps.json", {"started": "2026-01-01T00:00:00Z", "call_started": "2026-01-01T00:00:01Z", "finished": "2026-01-01T00:00:09Z"})
        self.write("preflight.json", [{"ok": True, "detail": "SIP/2.0 200 OK"}])
        if log is not None:
            self.write("softphone.log", "\n".join(log) + "\n")
        return self

    def diagnose(self, *extra: str) -> dict:
        process = run_cli(str(self.dir), "--format", "json", "--no-ladder", *extra)
        assert process.returncode == 0, process.stderr
        return json.loads(process.stdout)

    def commands(self, data: dict) -> list:
        return [step["command"] for step in data["nextSteps"] if step.get("command")]


def reject_log(status: str, *headers: str) -> list:
    return [
        sip_block("12:00:00.100", True, "INVITE", sdp=sdp_lines("203.0.113.77", 4000)),
        sip_block("12:00:00.150", False, status, headers=headers),
    ]


class DiagnoseCallTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.fx = Fixture(self.root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # -- coverage -------------------------------------------------------
    def test_every_call_verdict_has_a_handler(self) -> None:
        verdicts = {key.split(".", 1)[1] for key in CALL_EXPLANATIONS}
        self.assertEqual(verdicts - set(HANDLERS), set())

    def test_every_verdict_produces_a_complete_page(self) -> None:
        for verdict in sorted(HANDLERS):
            with self.subTest(verdict=verdict):
                fx = Fixture(self.root, f"20260101T000000.000000Z-v-{verdict}")
                fx.call(verdict, softphone={"final_status": 503, "answered": verdict in ("pass", "silent-audio", "fail")},
                        result={"oracle": {"summary": {"pass": 1, "fail": 0, "unknown": 0}}})
                data = fx.diagnose()
                self.assertTrue(data["outcome"])
                self.assertIn(data["stage"], ("preflight", "TLS", "registration", "INVITE", "answer", "media", "teardown", "oracle", "capture", "safety stop", "internal", "none"))
                self.assertIn(data["attribution"]["side"], (
                    "our side", "their side", "network or NAT in between",
                    "cannot tell from this evidence", "none (nothing failed)"))
                self.assertTrue(data["attribution"]["reasoning"])
                self.assertTrue(data["nextSteps"] or verdict == "pass")

    # -- stages, attribution, next steps --------------------------------
    def test_503_is_their_side_with_retry_after_and_ask_after_second_failure(self) -> None:
        self.fx.call("call-unavailable", softphone={"final_status": 503}, log=reject_log("503 Service Unavailable", "Reason: Q.850;cause=34", "Retry-After: 120"))
        data = self.fx.diagnose()
        self.assertEqual(data["stage"], "INVITE")
        self.assertEqual(data["attribution"]["side"], "their side")
        labels = " | ".join(f"{e['label']}: {e['text']}" for e in data["evidence"])
        self.assertIn("503 Service Unavailable", labels)
        self.assertIn("Reason (on 503 Service Unavailable to INVITE): Q.850;cause=34", labels)
        self.assertIn("Retry-After", labels)
        self.assertTrue(data["stopAndAsk"])

    def test_429_403_and_603_say_stop_and_ask_and_do_not_suggest_a_retry_call(self) -> None:
        for verdict, status in (("call-rate-limited", 429), ("call-forbidden", 403), ("call-declined", 603)):
            with self.subTest(verdict=verdict):
                fx = Fixture(self.root, f"20260101T000000.000000Z-ask-{status}")
                fx.call(verdict, softphone={"final_status": status})
                data = fx.diagnose()
                self.assertTrue(data["stopAndAsk"], verdict)
                self.assertEqual(data["nextSteps"][0]["kind"], "stop-and-ask")
                self.assertFalse([c for c in fx.commands(data) if " call " in c], verdict)

    def test_wrong_password_after_auth_is_our_side_credentials_and_stops(self) -> None:
        log = [
            sip_block("12:00:00.100", True, "REGISTER", headers=("@method=REGISTER",)),
            sip_block("12:00:00.110", False, "401 Unauthorized", headers=("@method=REGISTER",)),
            sip_block("12:00:00.120", True, "REGISTER", headers=("@method=REGISTER", 'Authorization: Digest username="alice-private-user", nonce="NONCEVALUE", response="RESPONSEHASH0011"')),
            sip_block("12:00:00.130", False, "401 Unauthorized", headers=("@method=REGISTER",)),
        ]
        self.fx.call("registration-failed", softphone={"registered": False, "registration_status": 401, "dialed": False}, log=log)
        data = self.fx.diagnose()
        self.assertEqual(data["stage"], "registration")
        self.assertEqual(data["attribution"]["side"], "our side")
        self.assertTrue(data["stopAndAsk"])
        text = json.dumps(data)
        self.assertIn("2 sent, 1 with an Authorization header", text)
        self.assertNotIn("NONCEVALUE", text)
        self.assertFalse([c for c in self.fx.commands(data) if " call " in c])

    def test_407_without_credentials_is_our_side_and_the_command_names_placeholders(self) -> None:
        self.fx.call("call-auth-failed", softphone={"final_status": 407}, plan_phone={"account": None})
        data = self.fx.diagnose()
        self.assertEqual(data["attribution"]["side"], "our side")
        commands = self.fx.commands(data)
        self.assertTrue(any("--username USERNAME --secret-env SIP_PASSWORD" in c for c in commands), commands)

    def test_not_answered_with_ringing_suggests_a_longer_timeout_within_the_limit(self) -> None:
        self.fx.call("call-not-answered", softphone={"final_status": 487, "error": "no_answer_before_timeout", "setup": {"provisionalStatus": 180}},
                     result={"setup": {"provisional": [180]}}, plan_phone={"answer_timeout_seconds": 20})
        data = self.fx.diagnose()
        self.assertEqual(data["stage"], "answer")
        self.assertEqual(data["attribution"]["side"], "their side")
        self.assertTrue(any("--answer-timeout 40" in c for c in self.fx.commands(data)))
        fx2 = Fixture(self.root, "20260101T000000.000000Z-max")
        fx2.call("call-not-answered", softphone={"final_status": 487, "error": "no_answer_before_timeout"},
                 result={"setup": {"provisional": [180]}}, plan_phone={"answer_timeout_seconds": 120})
        self.assertFalse([c for c in fx2.commands(fx2.diagnose()) if "--answer-timeout" in c])

    def test_not_answered_without_ringing_does_not_blame_the_far_end(self) -> None:
        self.fx.call("call-not-answered", softphone={"final_status": 487, "error": "no_answer_before_timeout"})
        data = self.fx.diagnose()
        self.assertEqual(data["attribution"]["side"], "cannot tell from this evidence")

    def test_488_with_exclusive_codec_offers_only_approved_alternatives(self) -> None:
        self.fx.call("call-media-not-acceptable", softphone={"final_status": 488},
                     plan_phone={"codec_offer": "only", "codecs": ["G722"], "approved_codecs": ["G722", "PCMA"]})
        data = self.fx.diagnose()
        commands = self.fx.commands(data)
        self.assertTrue(any("--codec PCMA" in c for c in commands), commands)
        self.assertFalse(any("--codec PCMU" in c for c in commands), commands)
        self.assertFalse(any("--srtp" in c for c in commands), "profile does not approve SRTP")
        fx2 = Fixture(self.root, "20260101T000000.000000Z-488b")
        fx2.call("call-media-not-acceptable", softphone={"final_status": 488}, profile_features={"srtp": True})
        self.assertTrue(any("--srtp mandatory" in c for c in fx2.commands(fx2.diagnose())))

    def test_srtp_mandatory_failure_is_their_side_and_never_offers_plain_without_saying_so(self) -> None:
        self.fx.call("srtp-not-negotiated", state="completed", softphone={"final_status": 488, "answered": False},
                     plan_phone={"srtp": {"mode": "mandatory", "requested_by": "--srtp"}},
                     result={"srtp": {"mode": "mandatory", "offerProfile": "RTP/SAVP", "answerProfile": None}})
        data = self.fx.diagnose()
        self.assertEqual(data["attribution"]["side"], "their side")
        self.assertTrue(any("--srtp" in c for c in self.fx.commands(data)))

    def test_one_way_media_on_loopback_without_capture_is_low_confidence_their_side(self) -> None:
        self.fx.call("one-way-media", state="completed", softphone={"answered": True, "final_status": 200, "rtp_tx_packets": 200, "rtp_rx_packets": 0},
                     result={"target": {"host": "127.0.0.1", "port": 5060, "transport": "udp"}},
                     log=[sip_block("12:00:00.100", True, "INVITE", sdp=sdp_lines("127.0.0.1", 4000)),
                          sip_block("12:00:00.150", False, "200 OK", sdp=sdp_lines("127.0.0.1", 20000))])
        data = self.fx.diagnose()
        self.assertEqual(data["stage"], "media")
        self.assertEqual(data["attribution"]["side"], "their side")
        self.assertEqual(data["attribution"]["confidence"], "low")
        self.assertTrue(any("no capture" in gap for gap in data["gaps"]))

    def test_one_way_media_with_private_sdp_answer_behind_nat_points_at_their_sdp(self) -> None:
        self.fx.call("possible-nat-one-way-media", state="completed", softphone={"answered": True, "final_status": 200, "rtp_tx_packets": 100, "rtp_rx_packets": 0},
                     result={"target": {"host": "93.184.216.34", "port": 5060, "transport": "udp"}},
                     log=[sip_block("12:00:00.100", True, "INVITE", sdp=sdp_lines("10.0.0.5", 4000)),
                          sip_block("12:00:00.150", False, "200 OK", sdp=sdp_lines("192.168.1.9", 30000))])
        data = self.fx.diagnose()
        self.assertEqual(data["attribution"]["side"], "their side")
        self.assertIn("private address", " ".join(data["attribution"]["reasoning"]))

    def test_media_outside_scope_is_a_stop_and_ask_with_an_operator_copy_step(self) -> None:
        self.fx.call("media-outside-scope", softphone={"answered": True, "final_status": 200, "error": "media_peer_outside_scope", "media_peer": "203.0.113.200:20000"},
                     result={"mediaScope": {"peer": "203.0.113.200:20000", "inScope": False, "admittedBy": None, "rules": {"approvedAddresses": APPROVED, "mediaNetworks": None}}})
        data = self.fx.diagnose()
        self.assertEqual(data["stage"], "safety stop")
        self.assertTrue(data["stopAndAsk"])
        commands = self.fx.commands(data)
        self.assertTrue(any(c.endswith("--show-addresses") for c in commands))
        self.assertTrue(any("scope questions" in c for c in commands))
        self.assertIn("unapproved-address-1:20000", json.dumps(data))
        self.assertNotIn("203.0.113.200", json.dumps(data))
        shown = self.fx.diagnose("--show-addresses")
        self.assertIn("203.0.113.200:20000", json.dumps(shown))

    def test_authorization_lapsed_says_only_the_owner_can_renew(self) -> None:
        self.fx.call("authorization-lapsed")
        data = self.fx.diagnose()
        self.assertEqual(data["stage"], "safety stop")
        self.assertTrue(data["stopAndAsk"])
        self.assertTrue(any(c.startswith("./bin/sippycup rehearse ") for c in self.fx.commands(data)))

    def test_tls_failures_never_suggest_unverified_and_stop(self) -> None:
        for detail, expect in (
            ("tls_failure: tls_verification: unable to get local issuer certificate [TLS UNVERIFIED]", "does not chain"),
            ("tls_failure: tls_verification: Hostname mismatch, certificate is not valid for 'pbx.example.net'. [TLS UNVERIFIED]", "not valid for the reviewed name"),
        ):
            with self.subTest(detail=detail[-40:]):
                fx = Fixture(self.root, "20260101T000000.000000Z-tls" + str(abs(hash(detail)) % 1000))
                fx.call("preflight-failed", softphone=None, transport="tls", preflight={"ok": False, "detail": detail},
                        result={"softphone": None, "tls": {"serverName": "pbx.example.net", "trust": "file", "caFile": "work/eng/ca.crt"}})
                data = fx.diagnose()
                self.assertEqual(data["stage"], "TLS")
                self.assertIn(expect, data["outcome"])
                self.assertTrue(data["stopAndAsk"])
                text = json.dumps(data)
                self.assertNotIn("--tls-unverified\"", text.replace("Never fall back to --tls-unverified", ""))
                self.assertTrue(any("preflight 198.51.100.10 5060 tls --tls-ca work/eng/ca.crt --tls-server-name pbx.example.net" in c for c in fx.commands(data)))

    def test_preflight_timeout_is_cannot_tell_and_offers_other_approved_transport_only_when_one_exists(self) -> None:
        self.fx.call("preflight-failed", softphone=None, preflight={"ok": False, "detail": "no_response: timeout: no final response within 2s"}, result={"softphone": None})
        data = self.fx.diagnose()
        self.assertEqual(data["attribution"]["side"], "cannot tell from this evidence")
        self.assertTrue(data["stopAndAsk"], "no other approved transport: ask the owner")
        (self.fx.eng / "target-profile-tcp.yaml").write_text(
            "schema_version: sippycup.dev/target-profile/v1\nname: eng-tcp\ntarget:\n  host: '198.51.100.10'\n  port: 5060\n  transport: tcp\n"
            "authorization:\n  status: approved\n  valid_until: '2999-01-01T00:00:00Z'\n", encoding="utf-8")
        data = self.fx.diagnose()
        self.assertTrue(any("preflight 198.51.100.10 5060 tcp" in c for c in self.fx.commands(data)))
        (self.fx.eng / "target-profile-tcp.yaml").write_text(
            "schema_version: sippycup.dev/target-profile/v1\nname: eng-tcp\ntarget:\n  host: '198.51.100.10'\n  port: 5060\n  transport: tcp\n"
            "authorization:\n  status: pending\n", encoding="utf-8")
        self.assertFalse(any("preflight 198.51.100.10 5060 tcp" in c for c in self.fx.commands(self.fx.diagnose())), "an unapproved profile is never suggested")

    def test_practice_runs_get_the_practice_flag_and_real_runs_do_not(self) -> None:
        self.fx.call("call-busy", softphone={"final_status": 486}, practice=True)
        self.assertTrue(any(c.startswith("./bin/sippycup --practice call ") for c in self.fx.commands(self.fx.diagnose())))
        fx2 = Fixture(self.root, "20260101T000000.000000Z-real")
        fx2.call("call-busy", softphone={"final_status": 486})
        self.assertTrue(all("--practice" not in c for c in fx2.commands(fx2.diagnose())))

    def test_commands_rebuild_the_recorded_flags_and_use_the_host_secret_path(self) -> None:
        self.fx.call("call-busy", softphone={"final_status": 486}, plan_phone={"srtp": {"mode": "optional", "requested_by": "--srtp"}, "dtmf": {"digits": "123", "after_seconds": 2}})
        command = [c for c in self.fx.commands(self.fx.diagnose()) if " call " in c][0]
        for part in ("work/eng/target-profile.yaml", "--dial echo", "--duration 5", "--answer-timeout 20", "--srtp optional",
                     "--username bob-user", "--secret-file work/eng/secret.txt", "--dtmf 123 --dtmf-after 2"):
            self.assertIn(part, command)

    def test_phone_number_like_dial_is_never_printed(self) -> None:
        self.fx.call("call-busy", softphone={"final_status": 486}, plan_phone={"destination_uri": "sip:4155550123@198.51.100.10:5060"})
        process = run_cli(str(self.fx.dir), "--no-ladder")
        self.assertNotIn("4155550123", process.stdout)
        self.assertIn("--dial DESTINATION", process.stdout)

    def test_no_result_json_is_reported_as_incomplete(self) -> None:
        shutil.rmtree(self.fx.dir)
        self.fx.dir.mkdir()
        self.fx.write("plan.json", {"schema_version": "sippycup.dev/call-plan/v1"})
        self.fx.write("timestamps.json", {"started": "2026-01-01T00:00:00Z", "capture_ready": "2026-01-01T00:00:01Z"})
        data = self.fx.diagnose()
        self.assertEqual(data["state"], "incomplete")
        self.assertTrue(any("result.json is missing" in gap for gap in data["gaps"]))

    def test_cancelled_names_the_interrupt_not_a_platform_fault(self) -> None:
        self.fx.call("cancelled", state="cancelled", softphone={"answered": True, "cancelled": True, "connected_seconds": 7.5})
        data = self.fx.diagnose()
        self.assertEqual(data["attribution"]["side"], "our side")
        self.assertIn("interrupted", data["outcome"])

    def test_passing_run_has_no_fault_and_lists_what_was_not_judged(self) -> None:
        self.fx.call("pass", state="completed", softphone={"answered": True, "final_status": 200, "rtp_tx_packets": 200, "rtp_rx_packets": 200, "codec": "PCMU", "setup": {"inviteToAnswerSeconds": 0.01}},
                     result={"oracle": {"summary": {"pass": 10, "fail": 0, "unknown": 2}, "unknown": ["dialog[0].media.codecs", "dialog[0].media.dtmf"]}})
        data = self.fx.diagnose()
        self.assertEqual(data["attribution"]["side"], "none (nothing failed)")
        self.assertTrue(any("did not judge" in e["text"] for e in data["evidence"]))

    def test_oracle_failure_quotes_numbers(self) -> None:
        assertion = {"assertions": [
            {"id": "dialog[0].media.sequence", "message": "loss exceeded limits", "verdict": "fail", "observed": {"state": "known", "value": [
                {"received": 90, "expected": 100, "lost": {"state": "known", "value": 10}, "duplicates": {"state": "known", "value": 0},
                 "reordered": {"state": "known", "value": 0}, "timestamp_jumps": {"state": "known", "value": 0}}]}},
        ]}
        self.fx.call("fail", state="completed", softphone={"answered": True, "final_status": 200},
                     result={"oracle": {"failed": ["dialog[0].media.sequence"], "failedDetails": [{"id": "dialog[0].media.sequence", "message": "loss exceeded limits"}]}})
        self.fx.write("assert.json", assertion)
        data = self.fx.diagnose()
        self.assertEqual(data["stage"], "oracle")
        self.assertTrue(any("90/100 received, lost 10" in e["text"] for e in data["evidence"]))

    def test_far_end_reason_and_warning_are_quoted_but_ours_are_not(self) -> None:
        log = [
            sip_block("12:00:00.100", True, "INVITE", sdp=sdp_lines("203.0.113.77", 4000)),
            sip_block("12:00:00.150", False, "200 OK", sdp=sdp_lines("198.51.100.11", 20000)),
            sip_block("12:00:03.000", False, "BYE", headers=("Reason: SIP;cause=200;text=\"session timer\"",)),
            sip_block("12:00:03.010", True, "BYE", headers=('Warning: 399 pjsua "Call duration exceeded"',)),
        ]
        self.fx.call("peer-hung-up-early", state="completed", softphone={"answered": True, "final_status": 200, "hangup": "remote", "connected_seconds": 3.0, "rtp_tx_packets": 150, "rtp_rx_packets": 150}, log=log)
        data = self.fx.diagnose()
        text = json.dumps(data)
        self.assertIn("session timer", text)
        self.assertNotIn("Call duration exceeded", text)
        self.assertEqual(data["stage"], "teardown")

    # -- forms ----------------------------------------------------------
    def test_brief_form_is_five_short_lines_and_json_brief_matches(self) -> None:
        self.fx.call("call-rate-limited", softphone={"final_status": 429})
        process = run_cli(str(self.fx.dir), "--brief", "--no-ladder")
        self.assertEqual(process.returncode, 0, process.stderr)
        lines = process.stdout.strip().split("\n")
        self.assertEqual(len(lines), 5)
        self.assertTrue(all(len(line) <= 150 for line in lines))
        self.assertIn("STOP", lines[3])
        self.assertTrue(lines[4].startswith("full page: ./bin/sippycup diagnose work/eng/calls/"))
        brief = json.loads(run_cli(str(self.fx.dir), "--brief", "--format", "json", "--no-ladder").stdout)
        self.assertEqual(brief["lines"], lines)
        self.assertTrue(brief["stopAndAsk"])
        self.assertEqual(brief["stage"], "INVITE")

    def test_json_form_has_the_documented_keys(self) -> None:
        self.fx.call("call-busy", softphone={"final_status": 486})
        data = self.fx.diagnose()
        for key in ("schema", "kind", "run", "verdict", "outcome", "stage", "evidence", "timing", "attribution", "nextSteps", "stopAndAsk", "gaps", "ladder", "networkActivity"):
            self.assertIn(key, data)
        self.assertEqual(data["schema"], "sippycup.dev/diagnosis/v1")
        self.assertFalse(data["networkActivity"])
        self.assertEqual(set(data["attribution"]), {"side", "confidence", "reasoning", "distinguish"})

    def test_every_suggested_command_is_a_registered_sippycup_command(self) -> None:
        registry = {line.split("|")[0] for line in (ROOT / "config" / "commands.tsv").read_text().splitlines() if line and not line.startswith("#")}
        for verdict in sorted(HANDLERS):
            fx = Fixture(self.root, f"20260101T000000.000000Z-reg-{verdict}")
            fx.call(verdict, softphone={"final_status": 500, "answered": verdict in ("pass", "silent-audio", "fail")})
            for command in fx.commands(fx.diagnose()):
                words = command.split()
                self.assertEqual(words[0], "./bin/sippycup", command)
                index = 2 if words[1] == "--practice" else 1
                self.assertIn(words[index], registry, command)

    def test_output_file_is_mode_0600_and_no_symlink_write(self) -> None:
        self.fx.call("call-busy", softphone={"final_status": 486})
        target = self.root / "page.txt"
        process = run_cli(str(self.fx.dir), "--no-ladder", "--output", str(target))
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        link = self.root / "link.txt"
        os.symlink(target, link)
        process = run_cli(str(self.fx.dir), "--no-ladder", "--output", str(link))
        self.assertEqual(process.returncode, 2)

    # -- privacy --------------------------------------------------------
    def test_privacy_forbidden_strings_never_reach_any_form(self) -> None:
        hostile_notes = [
            "Authorization: Digest username=\"alice-private-user\", nonce=\"NONCEVALUE\", response=\"RESPONSEHASH00112233\"",
            "password=hunter2-secret-pw seen at 192.0.2.99 for sip:alice-private-user@192.0.2.99 Call-ID: call-one@192.0.2.99",
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:SECRETKEYSECRETKEYSECRETKEY1234",
        ]
        log = reject_log(
            "503 Service Unavailable",
            "Reason: Q.850;cause=34;text=\"password=hunter2-secret-pw 192.0.2.99\"",
            "Warning: 399 edge \"Authorization: Digest nonce=NONCEVALUEABCDEF response=RESPONSEHASH0011\"",
        )
        self.fx.call(
            "call-unavailable", softphone={"final_status": 503}, notes=hostile_notes, log=log,
            preflight={"ok": True, "detail": "SIP/2.0 200 OK from 192.0.2.99 user alice-private-user"},
        )
        for arguments in ((), ("--brief",), ("--format", "json"), ("--brief", "--format", "json")):
            process = run_cli(str(self.fx.dir), "--no-ladder", *arguments)
            self.assertEqual(process.returncode, 0, (arguments, process.stderr))
            for forbidden in FORBIDDEN:
                self.assertNotIn(forbidden, process.stdout, (arguments, forbidden))

    def test_show_addresses_shows_addresses_but_still_never_secrets(self) -> None:
        log = reject_log("503 Service Unavailable", "Reason: Q.850;cause=34;text=\"password=hunter2-secret-pw from 192.0.2.99\"")
        self.fx.call("call-unavailable", softphone={"final_status": 503}, log=log)
        process = run_cli(str(self.fx.dir), "--no-ladder", "--show-addresses")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn("192.0.2.99", process.stdout)
        self.assertNotIn("hunter2-secret-pw", process.stdout)
        self.assertIn("operator copy", process.stdout)

    def test_lint_refusal_fails_closed_with_exit_5(self) -> None:
        # A finished rendering that contains key material is refused, not written.
        book_run = diagnose_cli.lint_output
        from sippycup_diagnose.core import Redaction
        from sippycup_workbench.summary_privacy import AddressBook

        red = Redaction(AddressBook())
        hits = book_run("a=crypto:1 AES inline:SECRETKEYSECRETKEY", red, False)
        self.assertTrue(hits)

    # -- arguments ------------------------------------------------------
    def test_bad_paths_and_unknown_directories(self) -> None:
        self.assertEqual(run_cli(str(self.root / "missing")).returncode, 2)
        empty = self.root / "empty"
        empty.mkdir()
        process = run_cli(str(empty))
        self.assertEqual(process.returncode, 4)
        self.assertIn("not a call, matrix, campaign, or checks run", process.stderr)
        self.fx.call("call-busy", softphone={"final_status": 486})
        process = run_cli(str(self.fx.dir.parent))
        self.assertEqual(process.returncode, 4)
        self.assertIn("holds several runs", process.stderr)
        self.assertEqual(run_cli().returncode, 2)
        self.assertEqual(run_cli(str(self.fx.dir), "--approve", "not-an-address").returncode, 2)

    def test_runs_through_the_public_entry_point_offline(self) -> None:
        self.fx.call("call-busy", softphone={"final_status": 486})
        env = dict(os.environ, SIPPYCUP_RUNTIME="/definitely/missing/runtime")
        process = subprocess.run([str(SIPPYCUP), "diagnose", str(self.fx.dir), "--brief", "--no-ladder"], text=True, capture_output=True, env=env, timeout=60)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(len(process.stdout.strip().split("\n")), 5)


@unittest.skipUnless(shutil.which("tshark"), "tshark is required")
class DiagnoseCaptureTests(unittest.TestCase):
    """The ladder model and RTP reader feed the diagnosis."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.fx = Fixture(self.root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _one_way_capture(self, answer_port: int = 6000) -> None:
        capture = Capture()
        basic_call(capture, caller="198.51.100.11", target="198.51.100.10")
        # keep only caller -> callee RTP: drop packets sourced from the media port
        capture.packets = [(t, d) for t, d in capture.packets if d[34:36] != (6000).to_bytes(2, "big")]
        capture.write(self.fx.dir / "capture.pcap")

    def test_one_way_media_uses_the_capture_and_reports_per_direction_counts(self) -> None:
        self._one_way_capture()
        self.fx.call(
            "one-way-media", state="completed",
            softphone={"answered": True, "final_status": 200, "rtp_tx_packets": 10, "rtp_rx_packets": 0},
            log=[sip_block("12:00:00.100", True, "INVITE", sdp=sdp_lines("198.51.100.11", 4000)),
                 sip_block("12:00:00.150", False, "200 OK", sdp=sdp_lines("198.51.100.10", 6000))],
            result={"localAddress": "198.51.100.11", "networkMode": "host"},
        )
        process = run_cli(str(self.fx.dir), "--format", "json")
        self.assertEqual(process.returncode, 0, process.stderr)
        data = json.loads(process.stdout)
        text = json.dumps(data)
        self.assertIn("did go to the address the answer SDP named", text)
        self.assertIn("Nothing arrived at our RTP port 4000", text)
        self.assertIsNotNone(data["ladder"]["text"])
        self.assertIn("INVITE", data["ladder"]["text"])
        for forbidden in ("NONCEVALUE", "RESPONSEHASH", "alice", "call-one@"):
            self.assertNotIn(forbidden, process.stdout)

    def test_truncated_or_unreadable_capture_is_named_not_hidden(self) -> None:
        (self.fx.dir / "capture.pcap").write_bytes(b"not a pcap at all")
        self.fx.call("call-busy", softphone={"final_status": 486})
        process = run_cli(str(self.fx.dir), "--format", "json")
        self.assertEqual(process.returncode, 0, process.stderr)
        data = json.loads(process.stdout)
        self.assertIsNone(data["ladder"]["text"])
        self.assertTrue(data["ladder"]["reason"])


class DiagnoseOtherKindsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.fx = Fixture(self.root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _cell(self, index: int, codec: str, verdict: str, status: int | None, name: str) -> dict:
        cell_fx = Fixture(self.root, name)
        if verdict == "pass":
            cell_fx.call("pass", state="completed", softphone={"answered": True, "final_status": 200, "rtp_tx_packets": 5, "rtp_rx_packets": 5})
        else:
            cell_fx.call(verdict, softphone={"final_status": status}, plan_phone={"codec_offer": "only", "codecs": [codec]})
        return {"index": index, "codec": codec, "srtp": "off", "transport": "udp", "status": "run", "verdict": verdict,
                "finalStatus": status, "runDirectory": f"work/eng/calls/{name}", "setupSeconds": 0.01}

    def test_matrix_finds_the_setting_every_failure_shares_and_rules_out_the_rest(self) -> None:
        matrix_dir = self.fx.eng / "matrix" / "20260101T000000.000000Z-matrix-echo-aaaa1111"
        matrix_dir.mkdir(parents=True)
        cells = [
            self._cell(1, "PCMU", "pass", 200, "20260101T000001.000000Z-c1"),
            self._cell(2, "PCMA", "pass", 200, "20260101T000002.000000Z-c2"),
            self._cell(3, "G722", "call-media-not-acceptable", 488, "20260101T000003.000000Z-c3"),
        ]
        (matrix_dir / "matrix.json").write_text(json.dumps({
            "apiVersion": "sippycup.dev/call-matrix/v1", "state": "completed", "cells": cells, "callsPlaced": 3, "totalCalls": 3,
            "blockingErrors": [], "timestamps": {"started": "2026-01-01T00:00:00Z", "finished": "2026-01-01T00:00:30Z"}}), encoding="utf-8")
        process = run_cli(str(matrix_dir), "--format", "json", "--no-ladder")
        self.assertEqual(process.returncode, 0, process.stderr)
        data = json.loads(process.stdout)
        self.assertEqual(data["kind"], "matrix")
        self.assertTrue(any("codec G722: 0 of 1 passed" in e["text"] for e in data["evidence"]))
        self.assertEqual(data["attribution"]["side"], "their side")
        self.assertEqual(len(data["children"]), 1)
        self.assertTrue(data["children"][0]["runRef"].startswith("work/eng/calls/"))

    def test_matrix_stopped_on_429_says_stop_and_ask(self) -> None:
        matrix_dir = self.fx.eng / "matrix" / "20260101T000000.000000Z-matrix-echo-bbbb2222"
        matrix_dir.mkdir(parents=True)
        cell = self._cell(1, "PCMU", "call-rate-limited", 429, "20260101T000001.000000Z-r1")
        (matrix_dir / "matrix.json").write_text(json.dumps({
            "state": "stopped", "stopReason": "call-rate-limited: 429", "callsPlaced": 1, "totalCalls": 2, "blockingErrors": [],
            "cells": [cell, {"index": 2, "codec": "PCMA", "srtp": "off", "transport": "udp", "status": "not-run", "reason": "call-rate-limited"}]}), encoding="utf-8")
        data = json.loads(run_cli(str(matrix_dir), "--format", "json", "--no-ladder").stdout)
        self.assertTrue(data["stopAndAsk"])
        self.assertTrue(any("not run" in child["line"] for child in data["children"]))

    def _campaign(self, output: dict, state: str = "failed") -> Path:
        run = self.fx.eng / "runs" / "20260101T000000.000000Z-camp-cccc3333"
        (run / "steps" / "000001").mkdir(parents=True)
        (run / "result.json").write_text(json.dumps({"state": state, "exitCode": 1, "completedSteps": 0}), encoding="utf-8")
        (run / "plan.json").write_text(json.dumps({
            "apiVersion": "sippycup.dev/plan/v1", "metadata": {"name": "camp"},
            "steps": [{"index": 1, "case": "call-1", "type": "call", "account": {"username": "bob-user", "register": True},
                       "destination": {"addresses": ["198.51.100.10"], "port": 5060, "transport": "udp"}}],
            "authorization": {"networks": ["198.51.100.10/32"]}}), encoding="utf-8")
        events = [
            {"event": "campaign.started", "sequence": 1, "state": "running", "stepCount": 1, "campaign": "camp"},
            {"event": "step.started", "sequence": 2, "state": "running", "step": 1, "case": "call-1", "campaign": "camp"},
            {"event": "step.output", "sequence": 3, "state": "running", "step": 1, "stream": "stdout", "text": json.dumps(output) + "\n", "campaign": "camp"},
            {"event": "step.failed", "sequence": 4, "state": "failed", "step": 1, "exitCode": 1, "campaign": "camp"},
            {"event": "campaign.failed", "sequence": 5, "state": "failed", "completedSteps": 0, "campaign": "camp"},
        ]
        (run / "events.jsonl").write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
        return run

    def test_campaign_registration_failure_is_our_side_and_asks(self) -> None:
        run = self._campaign({"outcome": "failed", "error": "registration_failed", "registrationStatus": 401, "reasons": ["registration_failed"],
                              "authentication": {"REGISTER": {"attempts": 1, "rejected": 1}, "INVITE": {"attempts": 0, "rejected": 0}}})
        data = json.loads(run_cli(str(run), "--format", "json", "--no-ladder").stdout)
        self.assertEqual(data["kind"], "campaign")
        self.assertEqual(data["stage"], "registration")
        self.assertEqual(data["attribution"]["side"], "our side")
        self.assertTrue(data["stopAndAsk"])

    def test_campaign_403_is_their_side_and_asks(self) -> None:
        run = self._campaign({"outcome": "failed", "finalStatus": 403, "answered": False, "registrationStatus": 200, "reasons": ["not_answered"],
                              "authentication": {"REGISTER": {"attempts": 2, "rejected": 0}, "INVITE": {"attempts": 1, "rejected": 1}}})
        data = json.loads(run_cli(str(run), "--format", "json", "--no-ladder").stdout)
        self.assertEqual(data["stage"], "INVITE")
        self.assertEqual(data["attribution"]["side"], "their side")
        self.assertTrue(data["stopAndAsk"])

    def test_checks_run_with_findings_and_with_errors(self) -> None:
        run = self.fx.eng / "checks" / "20260101T000000.000000Z-checks-dddd4444"
        run.mkdir(parents=True)
        findings = {"checks": [{"id": "nonce-replay", "status": "finding", "summary": "replay accepted", "requestsSent": 3},
                               {"id": "tls-certificate", "status": "not-approved", "summary": "not listed", "requestsSent": 0}],
                    "findings": [{"id": "nonce-replay.accepted", "checkId": "nonce-replay", "severity": "medium", "title": "Replayed digest credentials are accepted"}]}
        (run / "result.json").write_text(json.dumps({"apiVersion": "sippycup.dev/checks-result/v1", "state": "completed", "exitCode": 1, "failOn": "medium",
                                                     "profile": "eng-profile", "requestsSent": 3, "findings": findings, "timestamps": {}}), encoding="utf-8")
        (run / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
        (run / "checks-detail.json").write_text(json.dumps({"checks": []}), encoding="utf-8")
        data = json.loads(run_cli(str(run), "--format", "json", "--no-ladder").stdout)
        self.assertEqual(data["kind"], "checks")
        self.assertEqual(data["attribution"]["side"], "their side")
        self.assertIn("./bin/sippycup checks explain nonce-replay", [s.get("command") for s in data["nextSteps"]])
        self.assertTrue(any("not run because they are not listed" in gap for gap in data["gaps"]))
        # errors only: nothing concluded
        findings = {"checks": [{"id": "banner-disclosure", "status": "error", "summary": "OPTIONS got no usable answer (connection_refused); nothing concluded", "requestsSent": 1}], "findings": []}
        (run / "result.json").write_text(json.dumps({"apiVersion": "sippycup.dev/checks-result/v1", "state": "completed", "exitCode": 3, "failOn": "medium", "findings": findings}), encoding="utf-8")
        data = json.loads(run_cli(str(run), "--format", "json", "--no-ladder").stdout)
        self.assertEqual(data["stage"], "preflight")
        self.assertTrue(data["stopAndAsk"])

    def test_compare_names_what_differs_and_flags_identical_settings(self) -> None:
        a = Fixture(self.root, "20260101T000010.000000Z-a")
        a.call("pass", state="completed", softphone={"answered": True, "final_status": 200, "rtp_tx_packets": 5, "rtp_rx_packets": 5})
        b = Fixture(self.root, "20260101T000020.000000Z-b")
        b.call("call-unavailable", softphone={"final_status": 503}, log=reject_log("503 Service Unavailable", "Retry-After: 30"))
        data = json.loads(run_cli("--compare", str(a.dir), str(b.dir), "--format", "json").stdout)
        fields = {item["field"] for item in data["differences"]}
        self.assertIn("verdict", fields)
        self.assertIn("final INVITE status", fields)
        self.assertNotIn("codec offer", fields)
        self.assertTrue(any("identical" in line for line in data["likely"]))
        text = run_cli("--compare", str(a.dir), str(b.dir)).stdout
        self.assertIn("DIFFERENCES", text)
        c = Fixture(self.root, "20260101T000030.000000Z-c")
        c.call("call-unavailable", softphone={"final_status": 503}, plan_phone={"codec_offer": "only", "codecs": ["PCMA"]})
        data = json.loads(run_cli("--compare", str(a.dir), str(c.dir), "--format", "json").stdout)
        self.assertTrue(any("Only one setting differs (codec offer)" in line for line in data["likely"]))
        self.assertEqual(run_cli("--compare", str(a.dir), str(self.root / "nope")).returncode, 2)


if __name__ == "__main__":
    unittest.main()
