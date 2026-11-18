"""In-tree SIP OPTIONS transaction and its CLI, against loopback sockets only."""

from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup import options  # noqa: E402
from sippycup import options_cli  # noqa: E402
from sippycup.integration import sip_options_preflight  # noqa: E402


def reply_for(request: bytes, status: str = "200 OK", **overrides: str) -> bytes:
    """Build a response that echoes the transaction headers of ``request``."""
    text = request.decode()
    head = text.split("\r\n\r\n", 1)[0].split("\r\n")
    headers = {}
    for line in head[1:]:
        name, _, value = line.partition(":")
        headers.setdefault(name.strip().lower(), value.strip())
    via = overrides.get("via", headers["via"])
    lines = [
        f"SIP/2.0 {status}",
        f"Via: {via}",
        f"From: {headers['from']}",
        f"To: {headers['to']};tag=srv",
        f"Call-ID: {overrides.get('call_id', headers['call-id'])}",
        f"CSeq: {overrides.get('cseq', headers['cseq'])}",
        "Content-Length: 0",
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


class UdpServer:
    def __init__(self, handler, family=socket.AF_INET, host="127.0.0.1"):
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.bind((host, 0))
        self.sock.settimeout(5)
        self.port = self.sock.getsockname()[1]
        self.requests: list[bytes] = []
        self.handler = handler
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                data, source = self.sock.recvfrom(65535)
            except OSError:
                return
            self.requests.append(data)
            for reply in self.handler(data, len(self.requests)) or ():
                self.sock.sendto(reply, source)

    def close(self):
        self.sock.close()
        self.thread.join(2)


class TcpServer:
    def __init__(self, handler, *, tls_context: ssl.SSLContext | None = None):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(5)
        self.port = self.listener.getsockname()[1]
        self.handler = handler
        self.tls_context = tls_context
        self.requests: list[bytes] = []
        self.errors: list[str] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            connection, _ = self.listener.accept()
        except OSError:
            return
        try:
            connection.settimeout(5)
            if self.tls_context is not None:
                connection = self.tls_context.wrap_socket(connection, server_side=True)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = connection.recv(4096)
                if not chunk:
                    return
                data += chunk
            self.requests.append(data)
            self.handler(data, connection)
        except (OSError, ssl.SSLError) as error:
            self.errors.append(f"{type(error).__name__}: {error}")
        finally:
            with contextlib.suppress(OSError):
                connection.close()

    def close(self):
        self.listener.close()
        self.thread.join(3)


def run_cli(*argv: str) -> tuple[int, str]:
    output = io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
        try:
            code = options_cli.main(list(argv))
        except SystemExit as exit_:
            code = int(exit_.code)
    return code, output.getvalue()


def free_port(kind=socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class UdpTransactionTests(unittest.TestCase):
    def serve(self, handler, **kwargs) -> UdpServer:
        server = UdpServer(handler, **kwargs)
        self.addCleanup(server.close)
        return server

    def test_200_is_met_with_exit_zero_and_structured_result(self):
        server = self.serve(lambda request, _n: [reply_for(request)])
        result = options.send_options("127.0.0.1", server.port, "udp")
        self.assertEqual(result.outcome, options.RESPONSE)
        self.assertEqual(
            (result.status_code, result.reason, result.status_class),
            (200, "OK", "2xx"),
        )
        self.assertEqual((result.requests_sent, result.retransmissions), (1, 0))
        self.assertIsNone(result.tls_verified)
        self.assertIsNone(result.error_category)
        self.assertGreater(result.elapsed_seconds, 0)
        code, text = run_cli("127.0.0.1", str(server.port), "udp")
        self.assertEqual(code, 0, text)
        self.assertIn("SIP/2.0 200 OK", text)
        self.assertIn("Result: PASS", text)

    def test_request_carries_real_port_rport_and_matching_identifiers(self):
        server = self.serve(lambda request, _n: [reply_for(request)])
        options.send_options("127.0.0.1", server.port, "udp")
        text = server.requests[0].decode()
        self.assertTrue(text.startswith(f"OPTIONS sip:127.0.0.1:{server.port} SIP/2.0\r\n"))
        via = re.search(r"^Via: SIP/2.0/UDP 127\.0\.0\.1:(\d+);rport;branch=(z9hG4bK\w+)\r$",
                        text, re.M)
        self.assertIsNotNone(via, text)
        self.assertNotEqual(via.group(1), "5060")
        self.assertIn("CSeq: 1 OPTIONS\r\n", text)

    def test_404_and_500_are_responses_that_miss_the_default_expectation(self):
        for status, klass in (("404 Not Found", "4xx"), ("500 Server Internal Error", "5xx")):
            with self.subTest(status=status):
                server = self.serve(lambda request, _n, s=status: [reply_for(request, s)])
                code, text = run_cli("127.0.0.1", str(server.port), "udp")
                self.assertEqual(code, 1, text)
                self.assertIn(f"[class {klass}]", text)
                code, _ = run_cli("127.0.0.1", str(server.port), "udp",
                                  "--expect-status", status.split()[0])
                self.assertEqual(code, 0)
                code, _ = run_cli("127.0.0.1", str(server.port), "udp", "--expect-class", "any")
                self.assertEqual(code, 0)
                code, _ = run_cli("127.0.0.1", str(server.port), "udp", "--expect-class", klass)
                self.assertEqual(code, 0)

    def test_campaign_wrapper_keeps_reachability_contract_and_exposes_class(self):
        server = self.serve(lambda request, _n: [reply_for(request, "503 Service Unavailable")])
        ok, detail = sip_options_preflight(
            {"address": "127.0.0.1", "port": server.port, "transport": "udp"}
        )
        self.assertTrue(ok)
        self.assertEqual(detail, "SIP/2.0 503 Service Unavailable")
        self.assertEqual(options.status_of_detail(detail), (503, "5xx"))
        self.assertEqual(options.status_of_detail("no_response: timeout"), (None, None))

    def test_silence_retransmits_once_then_times_out_with_exit_3(self):
        server = self.serve(lambda _request, _n: [])
        result = options.send_options("127.0.0.1", server.port, "udp", timeout=0.6)
        self.assertEqual(result.outcome, options.NO_RESPONSE)
        self.assertEqual(result.error_category, "timeout")
        self.assertEqual((result.requests_sent, result.retransmissions), (2, 1))
        time.sleep(0.1)
        self.assertEqual(len(server.requests), 2)
        self.assertLess(result.elapsed_seconds, 1.0)
        code, text = run_cli("127.0.0.1", str(server.port), "udp", "--timeout", "0.4")
        self.assertEqual(code, 3, text)
        self.assertIn("NO RESPONSE", text)

    def test_max_requests_one_never_retransmits(self):
        server = self.serve(lambda _request, _n: [])
        result = options.send_options(
            "127.0.0.1", server.port, "udp", timeout=0.6, max_requests=1
        )
        self.assertEqual((result.requests_sent, result.retransmissions), (1, 0))

    def test_retransmission_answered_on_second_datagram(self):
        server = self.serve(lambda request, n: [reply_for(request)] if n == 2 else [])
        result = options.send_options("127.0.0.1", server.port, "udp", timeout=2)
        self.assertEqual(result.status_code, 200)
        self.assertEqual((result.requests_sent, result.retransmissions), (2, 1))
        self.assertEqual(server.requests[0], server.requests[1])

    def test_stray_and_non_matching_datagrams_are_ignored(self):
        def handler(request, _n):
            return [
                b"garbage that is not SIP",
                b"SIP/2.0 2000 OK\r\n\r\n",
                b"SIP/2.0 200 OK\r\n\r\n",
                reply_for(request, call_id="someone-else@example.invalid"),
                reply_for(request, cseq="2 OPTIONS"),
                reply_for(request, via="SIP/2.0/UDP 127.0.0.1:9;branch=z9hG4bKother"),
                reply_for(request, "404 Not Found"),
            ]

        server = self.serve(handler)
        result = options.send_options("127.0.0.1", server.port, "udp")
        self.assertEqual(result.status_code, 404)
        self.assertEqual(result.ignored_datagrams, 6)
        self.assertEqual(result.requests_sent, 1)

    def test_provisional_then_final_over_udp_stops_retransmission(self):
        def handler(request, _n):
            time.sleep(0.05)
            return [reply_for(request, "100 Trying")]

        server = self.serve(handler)
        result = options.send_options("127.0.0.1", server.port, "udp", timeout=0.8)
        self.assertEqual(result.outcome, options.NO_RESPONSE)
        self.assertEqual(result.provisional, [100])
        self.assertEqual(result.requests_sent, 1)

    def test_closed_udp_port_is_no_response_with_icmp_note(self):
        port = free_port(socket.SOCK_DGRAM)
        result = options.send_options("127.0.0.1", port, "udp", timeout=0.6)
        self.assertEqual(result.outcome, options.NO_RESPONSE)
        self.assertIn("icmp_port_unreachable", result.notes)
        code, _ = run_cli("127.0.0.1", str(port), "udp", "--timeout", "0.4")
        self.assertEqual(code, 3)

    def test_ipv6_loopback_brackets_request_uri_and_via(self):
        if not socket.has_ipv6:
            self.skipTest("no IPv6 support")
        try:
            server = UdpServer(lambda request, _n: [reply_for(request)],
                               family=socket.AF_INET6, host="::1")
        except OSError as error:
            self.skipTest(f"::1 unavailable: {error}")
        self.addCleanup(server.close)
        result = options.send_options("::1", server.port, "udp")
        self.assertEqual(result.status_code, 200, result.detail())
        text = server.requests[0].decode()
        self.assertTrue(text.startswith(f"OPTIONS sip:[::1]:{server.port} SIP/2.0\r\n"), text)
        self.assertRegex(text, r"(?m)^Via: SIP/2\.0/UDP \[::1\]:\d+;rport;branch=")
        self.assertIn(f"To: <sip:[::1]:{server.port}>", text)
        code, output = run_cli("[::1]", str(server.port), "udp")
        self.assertEqual(code, 0, output)
        self.assertIn(f"[::1]:{server.port}", output)


class StreamTransactionTests(unittest.TestCase):
    def serve(self, handler, **kwargs) -> TcpServer:
        server = TcpServer(handler, **kwargs)
        self.addCleanup(server.close)
        return server

    def test_refused_tcp_exits_4(self):
        port = free_port()
        result = options.send_options("127.0.0.1", port, "tcp")
        self.assertEqual(result.outcome, options.UNREACHABLE)
        self.assertEqual(result.error_category, "connection_refused")
        self.assertEqual(result.requests_sent, 0)
        code, text = run_cli("127.0.0.1", str(port), "tcp")
        self.assertEqual(code, 4, text)
        self.assertIn("UNREACHABLE", text)

    def test_response_split_across_segments(self):
        def handler(request, connection):
            reply = reply_for(request)
            for piece in (reply[:5], reply[5:40], reply[40:-3], reply[-3:]):
                connection.sendall(piece)
                time.sleep(0.05)

        server = self.serve(handler)
        result = options.send_options("127.0.0.1", server.port, "tcp")
        self.assertEqual(result.status_code, 200, result.detail())
        self.assertIn(b"Via: SIP/2.0/TCP 127.0.0.1:", server.requests[0])

    def test_provisional_with_body_then_final_on_one_stream(self):
        def handler(request, connection):
            provisional = reply_for(request, "100 Trying").replace(
                b"Content-Length: 0", b"Content-Length: 4"
            ) + b"abcd"
            connection.sendall(provisional + reply_for(request, "200 OK"))

        server = self.serve(handler)
        result = options.send_options("127.0.0.1", server.port, "tcp")
        self.assertEqual((result.provisional, result.status_code), ([100], 200))

    def test_malformed_and_closed_stream_replies_are_no_response(self):
        cases = {
            "malformed_response": lambda _r, c: c.sendall(b"HTTP/1.1 200 OK\r\n\r\n"),
            "connection_closed": lambda _r, c: None,
            "mismatched_response": lambda r, c: c.sendall(reply_for(r, call_id="x@y")),
        }
        for category, handler in cases.items():
            with self.subTest(category=category):
                server = self.serve(handler)
                result = options.send_options("127.0.0.1", server.port, "tcp")
                self.assertEqual(result.outcome, options.NO_RESPONSE)
                self.assertEqual(result.error_category, category)
                self.assertEqual(options_cli.exit_code_for(result, False), 3)

    def test_silent_tcp_peer_times_out(self):
        server = self.serve(lambda _r, _c: time.sleep(1.0))
        code, text = run_cli("127.0.0.1", str(server.port), "tcp", "--timeout", "0.3")
        self.assertEqual(code, 3, text)


OPENSSL = shutil.which("openssl")


@unittest.skipUnless(OPENSSL, "openssl CLI is not available")
class TlsTransactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        cls.ca = root / "ca.crt"
        cls.cert = root / "server.crt"
        cls.key = root / "server.key"
        extensions = root / "server.ext"
        extensions.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid,issuer\n"
            "subjectAltName=DNS:sippycup-test,IP:127.0.0.1\n",
            encoding="utf-8",
        )
        ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"]
        commands = [
            [OPENSSL, "req", "-x509", *ec, "-keyout", str(root / "ca.key"),
             "-out", str(cls.ca), "-days", "1", "-subj", "/CN=sippycup test CA",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
            [OPENSSL, "req", *ec, "-keyout", str(cls.key), "-out", str(root / "server.csr"),
             "-subj", "/CN=sippycup-test"],
            [OPENSSL, "x509", "-req", "-in", str(root / "server.csr"), "-CA", str(cls.ca),
             "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-out", str(cls.cert),
             "-days", "1", "-extfile", str(extensions)],
        ]
        for command in commands:
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
            if completed.returncode != 0:
                cls.directory.cleanup()
                raise unittest.SkipTest(f"openssl failed: {completed.stderr.strip()[:200]}")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def serve(self) -> TcpServer:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        server = TcpServer(
            lambda request, connection: connection.sendall(reply_for(request)),
            tls_context=context,
        )
        self.addCleanup(server.close)
        return server

    def test_verified_against_test_ca_by_literal_address(self):
        server = self.serve()
        result = options.send_options(
            "127.0.0.1", server.port, "tls", tls_ca_file=str(self.ca)
        )
        self.assertEqual(result.status_code, 200, result.detail())
        self.assertTrue(result.tls_verified)
        self.assertEqual(result.tls_server_name, "127.0.0.1")
        self.assertIn(b"Via: SIP/2.0/TLS 127.0.0.1:", server.requests[0])

    def test_verified_against_server_name(self):
        server = self.serve()
        code, text = run_cli("127.0.0.1", str(server.port), "tls",
                             "--tls-ca-file", str(self.ca),
                             "--tls-server-name", "sippycup-test")
        self.assertEqual(code, 0, text)
        self.assertIn("TLS: verified for name 'sippycup-test'", text)
        self.assertIn("Result: PASS (exit 0)", text)

    def test_name_mismatch_fails_with_exit_5(self):
        server = self.serve()
        code, text = run_cli("127.0.0.1", str(server.port), "tls",
                             "--tls-ca-file", str(self.ca),
                             "--tls-server-name", "wrong.example.invalid",
                             "--format", "json")
        self.assertEqual(code, 5, text)
        document = json.loads(text)
        self.assertEqual(document["outcome"], "tls_failure")
        self.assertEqual(document["error_category"], "tls_verification")
        self.assertFalse(document["tls_verified"])
        self.assertEqual(document["requests_sent"], 0)

    def test_untrusted_certificate_fails_with_exit_5(self):
        server = self.serve()
        result = options.send_options("127.0.0.1", server.port, "tls")
        self.assertEqual(result.outcome, options.TLS_FAILURE)
        self.assertEqual(result.error_category, "tls_verification")
        self.assertEqual(options_cli.exit_code_for(result, False), 5)
        server = self.serve()
        ok, detail = sip_options_preflight(
            {"address": "127.0.0.1", "port": server.port, "transport": "tls"}
        )
        self.assertFalse(ok)
        self.assertIn("tls_verification", detail)

    def test_insecure_is_reported_unverified_never_plain_pass(self):
        server = self.serve()
        code, text = run_cli("127.0.0.1", str(server.port), "tls", "--insecure")
        self.assertEqual(code, 0, text)
        self.assertIn("TLS: UNVERIFIED", text)
        self.assertIn("Result: PASS, TLS UNVERIFIED", text)
        self.assertNotIn("Result: PASS (exit", text)
        server = self.serve()
        code, text = run_cli("127.0.0.1", str(server.port), "tls", "--insecure",
                             "--format", "json")
        document = json.loads(text)
        self.assertEqual(document["verdict"], "pass_tls_unverified")
        self.assertFalse(document["tls_verified"])
        server = self.serve()
        result = options.send_options("127.0.0.1", server.port, "tls", insecure=True)
        self.assertIn("[TLS UNVERIFIED]", result.detail())


class UsageTests(unittest.TestCase):
    def test_usage_errors_exit_2_without_traffic(self):
        for argv in (
            ("127.0.0.1", "0", "udp"),
            ("127.0.0.1", "5060", "sctp"),
            ("127.0.0.1", "5060", "udp", "--insecure"),
            ("127.0.0.1", "5060", "tls", "--insecure", "--tls-ca-file", "/x"),
            ("127.0.0.1", "5060", "udp", "--timeout", "0"),
            ("127.0.0.1", "5060", "udp", "--timeout", "31"),
            ("127.0.0.1", "5060", "udp", "--expect-status", "180"),
            ("127.0.0.1", "5060", "udp", "--expect-status", "200", "--expect-class", "2xx"),
            ("-bad", "5060", "udp"),
            ("127.0.0.1", "5060", "tls", "--tls-ca-file", "/definitely/missing.pem"),
        ):
            with self.subTest(argv=argv):
                code, _ = run_cli(*argv)
                self.assertEqual(code, 2)
        with self.assertRaises(options.OptionsUsageError):
            options.send_options("not-an-ip", 5060, "udp")

    def test_installed_entry_point_help_and_exit_code(self):
        executable = ROOT / "bin" / "container-options"
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        helped = subprocess.run([executable, "--help"], capture_output=True, text=True,
                                env=environment, check=False, timeout=20)
        self.assertEqual(helped.returncode, 0)
        self.assertIn("5  TLS handshake or certificate verification failed", helped.stdout)
        refused = subprocess.run([executable, "127.0.0.1", str(free_port()), "tcp"],
                                 capture_output=True, text=True, env=environment,
                                 check=False, timeout=20)
        self.assertEqual(refused.returncode, 4, refused.stdout)


class CampaignOptionsStepTests(unittest.TestCase):
    """The bundled runner judges an options step by its frozen expectations."""

    def run_step(self, server_status: str, expectations, packets: int = 10):
        server = UdpServer(lambda request, _n: [reply_for(request, server_status)])
        self.addCleanup(server.close)
        step = {
            "type": "options",
            "destination": {"addresses": ["127.0.0.1"], "port": server.port, "transport": "udp"},
            "budget": {"calls": 0, "packets": packets, "bytes": 10000, "durationSeconds": 2},
            "expectations": expectations,
        }
        completed = subprocess.run(
            [sys.executable, ROOT / "bin" / "campaign-sipp-runner"],
            input=json.dumps({"step": step, "credentials": {}}) + "\n",
            capture_output=True, text=True, check=False, timeout=20,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        return completed.returncode, json.loads(completed.stdout), server

    def test_final_status_expectation_decides(self):
        expectations = {"apiVersion": "sippycup.dev/case-expectations/v1", "finalStatus": 404}
        code, summary, _ = self.run_step("404 Not Found", expectations)
        self.assertEqual((code, summary["met"], summary["expectation"]), (0, True, 404))
        code, summary, _ = self.run_step("200 OK", expectations)
        self.assertEqual((code, summary["met"]), (1, False))

    def test_without_expectations_a_2xx_is_required(self):
        code, summary, _ = self.run_step("200 OK", None)
        self.assertEqual((code, summary["expectation"]), (0, "2xx"))
        code, summary, _ = self.run_step("404 Not Found", None)
        self.assertEqual((code, summary["status_code"]), (1, 404))
        code, _, _ = self.run_step("500 Server Internal Error", None)
        self.assertEqual(code, 1)

    def test_small_packet_budget_disables_retransmission(self):
        server = UdpServer(lambda _request, _n: [])
        self.addCleanup(server.close)
        for packets, sent in ((3, 1), (4, 2)):
            step = {
                "type": "options",
                "destination": {"addresses": ["127.0.0.1"], "port": server.port,
                                "transport": "udp"},
                "budget": {"calls": 0, "packets": packets, "bytes": 1000, "durationSeconds": 1},
                "expectations": None,
            }
            completed = subprocess.run(
                [sys.executable, ROOT / "bin" / "campaign-sipp-runner"],
                input=json.dumps({"step": step, "credentials": {}}) + "\n",
                capture_output=True, text=True, check=False, timeout=20,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(json.loads(completed.stdout)["requests_sent"], sent)


class LauncherPreflightArgumentTests(unittest.TestCase):
    """bin/container-preflight validation and dry runs send nothing."""

    def preflight(self, *argv: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [ROOT / "bin" / "container-preflight", *argv],
            capture_output=True, text=True, check=False, timeout=20,
            env={"PATH": "/usr/bin:/bin"},
        )

    def test_usage_errors_exit_2(self):
        for argv in (
            ("192.0.2.1", "5061", "tls", "--tls-ignore-cert-failure"),
            ("192.0.2.1", "5060", "udp", "--tls-unverified"),
            ("192.0.2.1", "5061", "tls", "--tls-ca", "/etc/ssl/ca.pem"),
            ("192.0.2.1", "5061", "tls", "--tls-ca", "/work/../etc/ca.pem"),
            ("192.0.2.1", "5061", "tls", "--tls-ca", "/work/ca.pem", "--tls-unverified"),
            ("192.0.2.1", "5061", "tls", "--tls-server-name", "-bad"),
            ("192.0.2.1", "5060", "udp", "--expect-status", "180"),
            ("192.0.2.1", "5060", "udp", "--expect-class", "7xx"),
            ("192.0.2.1", "5060", "udp", "--expect-status", "200", "--expect-class", "2xx"),
            ("192.0.2.1", "5060", "udp", "--bogus"),
        ):
            with self.subTest(argv=argv):
                result = self.preflight(*argv, "--dry-run")
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertNotIn("Network activity", result.stdout)

    def test_dry_run_reports_tls_verification_plan(self):
        verified = self.preflight(
            "127.0.0.2", "5061", "tls", "--tls-ca", "/work/practice/ca.crt",
            "--tls-server-name", "sippycup-practice", "--dry-run",
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertIn("verify as sippycup-practice with extra CA /work/practice/ca.crt",
                      verified.stdout)
        self.assertIn("Network activity: none", verified.stdout)
        unverified = self.preflight("127.0.0.2", "5061", "tls", "--tls-unverified", "--dry-run")
        self.assertEqual(unverified.returncode, 0)
        self.assertIn("TLS:       UNVERIFIED", unverified.stdout)
        udp = self.preflight("127.0.0.2", "--dry-run")
        self.assertIn("(at most two datagrams)", udp.stdout)
        helped = self.preflight("--help")
        self.assertEqual(helped.returncode, 0)
        self.assertIn("--tls-unverified", helped.stdout)


if __name__ == "__main__":
    unittest.main()
