from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from ladder_support import (  # noqa: E402
    Capture,
    basic_call,
    sdp_body,
    sip_request,
    sip_response,
    tls_app_data,
    tls_client_hello,
    tls_server_hello,
)

LADDER = ROOT / "bin" / "sippycup-ladder"
FORBIDDEN = (
    "NONCEVALUE",
    "RESPONSEHASH",
    "SECRETKEY",
    "inline:",
    "a=crypto",
    "alice",
    "bob",
    "call-one@",
    "Authorization",
    "WWW-Authenticate",
)


def flat(text: str) -> str:
    return " ".join(text.replace("|", " ").split())


def ladder(*args: str):
    return subprocess.run(
        [sys.executable, str(LADDER), *args],
        text=True,
        capture_output=True,
        timeout=120,
    )


@unittest.skipUnless(shutil.which("tshark"), "tshark is required")
class LadderTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def capture(self, build, name="c.pcap", **kw) -> Path:
        cap = Capture()
        build(cap)
        return cap.write(self.dir / name, **kw)

    def test_call_text_marks_everything_and_leaks_nothing(self):
        path = self.capture(lambda c: basic_call(c, dtmf=True, invite_retransmit=True, start=1_700_000_000.0))
        for fmt in ("text", "html", "json"):
            with self.subTest(fmt=fmt):
                result = ladder(str(path), "--approve", "192.0.2.0/24", "--format", fmt)
                self.assertEqual(result.returncode, 0, result.stderr)
                for word in FORBIDDEN:
                    self.assertNotIn(word, result.stdout, word)
        text = flat(ladder(str(path), "--approve", "192.0.2.0/24").stdout)
        for expected in (
            "INVITE",
            "401 Unauthorized",
            "AUTH CHALLENGE",
            "AUTH RESPONSE",
            "RETRANS #1",
            "offer: audio 192.0.2.10:4000 RTP/AVP",
            "answer: audio 192.0.2.20:6000",
            "telephone-event: 2 event(s); digit values are not shown",
            "RTP 18 pkts",
            "payload types: PCMU(0) x10, telephone-event(101) x8",
            "ended by BYE from caller",
            "(caller)",
            "(target)",
        ):
            self.assertIn(expected, text)
        # Aggregated: no per-packet lines.
        self.assertLess(len(text), 6000)

    def test_addresses_redacted_unless_approved_or_shown(self):
        path = self.capture(lambda c: basic_call(c))
        plain = ladder(str(path)).stdout
        self.assertNotIn("192.0.2.10", plain)
        self.assertIn("unapproved-address-1", plain)
        shown = ladder(str(path), "--show-addresses").stdout
        self.assertIn("192.0.2.10", shown)
        self.assertIn("NOT REDACTED", shown)

    def test_srtp_keys_never_printed(self):
        def build(c):
            sdp = sdp_body("192.0.2.10", 4000, profile="RTP/SAVP", crypto=True)
            c.udp(5.0, "192.0.2.10", 5060, "192.0.2.20", 5060, sip_request("INVITE", "s1", 1, sdp=sdp))
        path = self.capture(build)
        result = ladder(str(path), "--approve", "192.0.2.0/24")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SDES-SRTP offered: AES_CM_128_HMAC_SHA1_80 (keys not shown)", flat(result.stdout))
        self.assertNotIn("SECRETKEY", result.stdout)

    def test_ipv6_and_tcp_reassembly(self):
        def build(c):
            a, b = "2001:db8::10", "2001:db8::20"
            t = c.tcp_handshake(10.0, a, 40000, b, 5060)
            req = sip_request("OPTIONS", "o1", 1, transport="TCP", branch="z9hG4bKo1")
            rsp = sip_response(200, "OK", "OPTIONS", "o1", 1, transport="TCP", branch="z9hG4bKo1")
            c.tcp_data(t, a, 40000, b, 5060, req, chunk=90)
            c.tcp_data(t + 0.2, b, 5060, a, 40000, rsp, chunk=70)
        path = self.capture(build)
        result = ladder(str(path), "--approve", "2001:db8::/32")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[2001:db8::10]:40000", result.stdout)
        self.assertIn("200 OK (OPTIONS)", result.stdout)

    def test_multiple_calls_and_index(self):
        def build(c):
            basic_call(c, call_id="first@x", start=100.0)
            basic_call(c, call_id="second@x", start=200.0, caller="192.0.2.11")
        path = self.capture(build)
        both = ladder(str(path), "--approve", "192.0.2.0/24", "--format", "json")
        doc = json.loads(both.stdout)
        self.assertEqual(len(doc["sections"]), 2)
        one = json.loads(ladder(str(path), "--approve", "192.0.2.0/24", "--format", "json", "--call-id-index", "2").stdout)
        self.assertEqual(len(one["sections"]), 1)
        self.assertEqual(one["sections"][0]["index"], 2)
        bad = ladder(str(path), "--call-id-index", "9")
        self.assertEqual(bad.returncode, 2)

    def test_no_sip_and_bad_inputs(self):
        def build(c):
            c.udp(1.0, "192.0.2.1", 1000, "192.0.2.2", 2000, b"hello")
        path = self.capture(build)
        result = ladder(str(path))
        self.assertEqual(result.returncode, 4)
        self.assertIn("nothing to draw", result.stderr)
        junk = self.dir / "junk.pcap"
        junk.write_bytes(b"not a capture at all")
        self.assertEqual(ladder(str(junk)).returncode, 3)
        self.assertEqual(ladder(str(self.dir / "missing.pcap")).returncode, 2)

    def test_truncated_capture_warns(self):
        path = self.capture(lambda c: basic_call(c), snaplen=150)
        result = ladder(str(path), "--approve", "192.0.2.0/24")
        self.assertIn(result.returncode, (0, 4), result.stderr)
        if result.returncode == 0:
            self.assertIn("WARNING", result.stdout)

    def test_tls_capture_says_so_and_log_supplies_sip(self):
        def build(c):
            a, b = "192.0.2.10", "192.0.2.20"
            t = c.tcp_handshake(1_700_000_000.0, a, 40000, b, 5061)
            c.tcp_data(t, a, 40000, b, 5061, tls_client_hello())
            c.tcp_data(t + 0.01, b, 5061, a, 40000, tls_server_hello())
            c.tcp_data(t + 0.05, a, 40000, b, 5061, tls_app_data())
            c.tcp_data(t + 0.06, b, 5061, a, 40000, tls_app_data(80))
        run = self.dir / "run"
        run.mkdir()
        cap = Capture()
        build(cap)
        cap.write(run / "capture.pcap")
        result = ladder(str(run), "--approve", "192.0.2.0/24")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("TLS-encrypted", result.stdout)
        self.assertIn("TLS ClientHello", result.stdout)
        log = (
            "22:13:20.100  pjsua_core.c  .TX 300 bytes Request msg OPTIONS/cseq=1 (tdta0x1) to TLS 192.0.2.20:5061:\n"
            "OPTIONS sip:bob@192.0.2.20 SIP/2.0\n"
            "Via: SIP/2.0/TLS 192.0.2.10:40000;branch=z9hG4bKx\n"
            "From: <sip:alice@192.0.2.10>;tag=a\nTo: <sip:bob@192.0.2.20>\n"
            "Call-ID: logcall@x\nCSeq: 1 OPTIONS\nAuthorization: <redacted>\nContent-Length:  0\n\n\n--end msg--\n"
            "22:13:20.150  pjsua_core.c  .RX 200 bytes Response msg 200/OPTIONS/cseq=1 (rdata0x2) from TLS 192.0.2.20:5061:\n"
            "SIP/2.0 200 OK\nVia: SIP/2.0/TLS 192.0.2.10:40000;branch=z9hG4bKx\n"
            "Call-ID: logcall@x\nCSeq: 1 OPTIONS\nContent-Length:  0\n\n\n--end msg--\n"
        )
        (run / "softphone.log").write_text(log)
        result = ladder(str(run), "--approve", "192.0.2.0/24")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("source: softphone-log", result.stdout)
        self.assertIn("200 OK (OPTIONS)", result.stdout)
        for word in ("logcall", "alice", "bob", "redacted>"):
            self.assertNotIn(word, result.stdout)

    def test_lint_blocks_forbidden_content(self):
        from sippycup_ladder.cli import lint_output
        from sippycup_workbench.summary_privacy import AddressBook

        book = AddressBook()
        self.assertTrue(lint_output('nonce="abcdef123456"', book, True))
        self.assertTrue(lint_output("a=crypto:1 AES inline:AAAAAAAAAAAAAAAA", book, True))
        self.assertTrue(lint_output("Authorization: Digest x", book, True))
        self.assertFalse(lint_output("INVITE 401 Unauthorized", book, False))

    def test_output_file_mode_and_cli_registry(self):
        path = self.capture(lambda c: basic_call(c))
        out = self.dir / "o.html"
        result = ladder(str(path), "--format", "html", "--output", str(out))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)
        self.assertIn("<svg", out.read_text())
        self.assertNotIn("http://", out.read_text().replace("http://www.w3.org", ""))
        help_run = subprocess.run([str(ROOT / "bin" / "sippycup"), "ladder", "--help"], text=True, capture_output=True, cwd=ROOT)
        self.assertEqual(help_run.returncode, 0, help_run.stderr)


if __name__ == "__main__":
    unittest.main()
