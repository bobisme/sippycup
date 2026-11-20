"""Host tests for ./bin/sippycup checks against loopback stub servers.

Every check is proven in both directions: the finding fires on a weak stub
and does not fire on a hardened one, and the transport-layer request counter
holds. Stubs listen on 127.0.0.1 ephemeral ports only. TLS certificates are
generated with the openssl CLI at test time; TLS tests skip cleanly without it.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_checks import catalog, checks, runner, sip  # noqa: E402
from sippycup_checks.budget import Budget, BudgetExceeded  # noqa: E402
from sippycup_checks.checks import Context  # noqa: E402
from sippycup_checks.sip import Endpoint  # noqa: E402
from sippycup_workbench.profile import rehearse  # noqa: E402

PASSWORD = "stub-password-canary-7731"
ACCOUNT = "alice"
NOW = datetime.now(timezone.utc)


# -- a small configurable SIP stub ------------------------------------------------

def _parse_request(data: bytes) -> tuple[str, str, dict[str, list[str]], bytes] | None:
    head, separator, body = data.partition(b"\r\n\r\n")
    if not separator:
        return None
    lines = head.decode("utf-8", "replace").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[2] != "SIP/2.0":
        return None
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    return parts[0], parts[1], headers, body


class Behaviour:
    """What the stub does. ``weak`` turns every posture problem on."""

    def __init__(self, weak: bool, **overrides: Any) -> None:
        self.weak = weak
        self.server = "Asterisk PBX 18.2.1" if weak else None
        self.allow = ("INVITE, ACK, CANCEL, BYE, OPTIONS, REFER, MESSAGE, SUBSCRIBE" if weak
                      else "INVITE, ACK, CANCEL, BYE, OPTIONS")
        self.register_unauthenticated = "accept" if weak else "challenge"
        self.algorithms = ("MD5",) if weak else ("SHA-256", "MD5")
        self.qop = None if weak else "auth"
        self.realm = "pbx.internal" if weak else "voice.test"
        self.short_nonce = weak
        self.unknown_user = 404 if weak else None  # None: identical challenge
        self.invite = "ring" if weak else "challenge"
        self.allow_replay = weak
        for key, value in overrides.items():
            setattr(self, key, value)


class SipStub:
    def __init__(self, transport: str, behaviour: Behaviour, *, tls: ssl.SSLContext | None = None,
                 port: int = 0) -> None:
        self.transport = transport
        self.behaviour = behaviour
        self.tls = tls
        self.requests: list[str] = []
        self.handshakes = 0
        self.nonces: dict[str, set[str]] = {}
        self.pending_invites: dict[str, tuple[dict[str, list[str]], str]] = {}
        self._stop = threading.Event()
        family_type = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
        self.sock = socket.socket(socket.AF_INET, family_type)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.port = self.sock.getsockname()[1]
        if transport != "udp":
            self.sock.listen(16)
        self.sock.settimeout(0.1)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self._stop.set()
        self.thread.join(timeout=2)
        self.sock.close()

    def __enter__(self) -> "SipStub":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- serving -------------------------------------------------------------
    def _serve(self) -> None:
        while not self._stop.is_set():
            if self.transport == "udp":
                try:
                    data, address = self.sock.recvfrom(65535)
                except (socket.timeout, OSError):
                    continue
                for reply in self.handle(data):
                    self.sock.sendto(reply, address)
                continue
            try:
                connection, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._stream, args=(connection,), daemon=True).start()

    def _stream(self, connection: socket.socket) -> None:
        connection.settimeout(5)
        try:
            if self.tls is not None:
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", DeprecationWarning)
                        connection = self.tls.wrap_socket(connection, server_side=True)
                    self.handshakes += 1
                except (ssl.SSLError, OSError):
                    self.handshakes += 1
                    return
            buffer = b""
            while not self._stop.is_set():
                try:
                    chunk = connection.recv(65535)
                except (socket.timeout, ssl.SSLError, OSError):
                    return
                if not chunk:
                    return
                buffer += chunk
                while b"\r\n\r\n" in buffer:
                    head, _, rest = buffer.partition(b"\r\n\r\n")
                    length = 0
                    for line in head.split(b"\r\n"):
                        if line.lower().startswith(b"content-length:"):
                            length = int(line.split(b":", 1)[1])
                    if len(rest) < length:
                        break
                    message, buffer = head + b"\r\n\r\n" + rest[:length], rest[length:]
                    for reply in self.handle(message):
                        connection.sendall(reply)
        finally:
            connection.close()

    # -- SIP -----------------------------------------------------------------
    def respond(self, headers: dict[str, list[str]], code: int, reason: str, *, tag: str | None = "stubtag",
                extra: list[str] = (), cseq: str | None = None) -> bytes:
        lines = [f"SIP/2.0 {code} {reason}"]
        lines.extend(f"Via: {value}" for value in headers.get("via", []))
        lines.append(f"From: {headers['from'][0]}")
        to = headers["to"][0]
        if tag and ";tag=" not in to:
            to += f";tag={tag}"
        lines.append(f"To: {to}")
        lines.append(f"Call-ID: {headers['call-id'][0]}")
        lines.append(f"CSeq: {cseq or headers['cseq'][0]}")
        if self.behaviour.server:
            lines.append(f"Server: {self.behaviour.server}")
        lines.extend(extra)
        lines.append("Content-Length: 0")
        return ("\r\n".join(lines) + "\r\n\r\n").encode()

    def challenge(self, headers: dict[str, list[str]], *, stale: bool = False) -> bytes:
        behaviour = self.behaviour
        nonce = "abc123" if behaviour.short_nonce else os.urandom(24).hex()
        self.nonces.setdefault(nonce, set())
        extra = []
        for algorithm in behaviour.algorithms:
            parts = [f'realm="{behaviour.realm}"', f'nonce="{nonce}"', f"algorithm={algorithm}"]
            if behaviour.qop:
                parts.append(f'qop="{behaviour.qop}"')
            if stale:
                parts.append("stale=true")
            extra.append("WWW-Authenticate: Digest " + ", ".join(parts))
        return self.respond(headers, 401, "Unauthorized", extra=extra)

    def handle(self, data: bytes) -> list[bytes]:
        parsed = _parse_request(data)
        if parsed is None:
            return []
        method, uri, headers, _body = parsed
        self.requests.append(method)
        behaviour = self.behaviour
        user = headers["from"][0].split("sip:", 1)[-1].split("@", 1)[0]
        if method == "OPTIONS":
            return [self.respond(headers, 200, "OK", extra=[f"Allow: {behaviour.allow}", "Supported: replaces"])]
        if method == "REGISTER":
            auth = headers.get("authorization")
            if auth:
                return [self._authenticate(headers, auth[0])]
            if behaviour.unknown_user and user != ACCOUNT:
                return [self.respond(headers, behaviour.unknown_user, "Not Found")]
            if behaviour.register_unauthenticated == "accept":
                return [self.respond(headers, 200, "OK")]
            return [self.challenge(headers)]
        if method == "INVITE":
            if behaviour.unknown_user and user not in (ACCOUNT, "anonymous") and behaviour.invite == "challenge":
                return [self.respond(headers, behaviour.unknown_user, "Not Found")]
            if behaviour.invite == "ring":
                self.pending_invites[headers["call-id"][0]] = (headers, "ring")
                return [self.respond(headers, 100, "Trying", tag=None),
                        self.respond(headers, 180, "Ringing")]
            if behaviour.invite == "answer":
                return [self.respond(headers, 100, "Trying", tag=None),
                        self.respond(headers, 200, "OK", extra=[f"Contact: <sip:stub@127.0.0.1:{self.port}>"])]
            return [self.challenge(headers)]
        if method == "CANCEL":
            pending = self.pending_invites.pop(headers["call-id"][0], None)
            replies = [self.respond(headers, 200, "OK")]
            if pending is not None:
                replies.append(self.respond(pending[0], 487, "Request Terminated"))
            return replies
        if method == "BYE":
            return [self.respond(headers, 200, "OK")]
        return []  # ACK

    def _authenticate(self, headers: dict[str, list[str]], value: str) -> bytes:
        params = sip.parse_challenge(value) or {}
        nonce = params.get("nonce", "")
        if nonce not in self.nonces:
            return self.challenge(headers, stale=True)
        algorithm = params.get("algorithm", "MD5")
        expected = sip.digest_response(
            algorithm=algorithm, username=params.get("username", ""), realm=params.get("realm", ""),
            password=PASSWORD, method="REGISTER", uri=params.get("uri", ""), nonce=nonce,
            qop=params.get("qop"), nc=params.get("nc", ""), cnonce=params.get("cnonce", ""),
        )
        if params.get("response") != expected:
            return self.respond(headers, 403, "Forbidden")
        key = params.get("nc", "") + "/" + params.get("cnonce", "")
        if key in self.nonces[nonce] and not self.behaviour.allow_replay:
            return self.challenge(headers, stale=True)
        self.nonces[nonce].add(key)
        return self.respond(headers, 200, "OK")


# -- helpers -----------------------------------------------------------------------

class ChecksTestCase(unittest.TestCase):
    def context(self, endpoint: Endpoint, section: dict[str, Any] | None = None, *,
                limit: int = 20, password: str | None = None) -> Context:
        budget = Budget(total_limit=100, interval=0.0)
        section = {"approved": [], "max_requests": 100, "account": ACCOUNT, "destination": "echo", **(section or {})}
        return Context(endpoint=endpoint, section=section, budget=budget, password=password,
                       timeout=1.0, invite_timeout=1.5, openssl=shutil.which("openssl"),
                       now=lambda: datetime.now(timezone.utc))

    def run_check(self, check_id: str, ctx: Context) -> checks.CheckResult:
        spec = catalog.get(check_id)
        ctx.budget.begin(check_id, catalog.declared_bound(spec, ctx.section))
        result = checks.IMPLEMENTATIONS[check_id](ctx)
        result.requests_sent = ctx.budget.end()
        self.assertLessEqual(result.requests_sent, catalog.declared_bound(spec, ctx.section))
        return result

    @staticmethod
    def ids(result: checks.CheckResult) -> set[str]:
        return {item["id"] for item in result.findings}


def endpoint_for(stub: SipStub, *, server_name: str | None = None, ca: bytes | None = None) -> Endpoint:
    return Endpoint("127.0.0.1", stub.port, stub.transport, domain=server_name or "127.0.0.1",
                    server_name=server_name, ca_data=ca)


# -- catalog and profile validation ------------------------------------------------

class CatalogTests(unittest.TestCase):
    def test_catalog_is_complete_and_consistent(self) -> None:
        ids = catalog.ids()
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(catalog.ids(runnable_only=True)), set(checks.IMPLEMENTATIONS))
        for spec in catalog.CHECKS:
            self.assertIn(spec.impact, catalog.IMPACTS)
            self.assertTrue(set(spec.needs) <= set(catalog.NEEDS), spec.id)
            if spec.state == "runnable":
                self.assertGreater(spec.max_requests, 0, spec.id)
                self.assertTrue(spec.findings, spec.id)
            for item in spec.findings:
                self.assertTrue(item.id.startswith(spec.id + "."), item.id)
                self.assertIn(item.severity, catalog.SEVERITIES)
                self.assertTrue(item.remediation)
            if spec.impact == "passive":
                self.assertEqual(spec.invites, 0)
        self.assertEqual(catalog.get("srtp-policy").state, "runnable")

    def test_list_and_explain_are_network_free(self) -> None:
        listed = subprocess.run([ROOT / "bin" / "sippycup", "checks", "list", "--format", "json"],
                                cwd=ROOT, env={**os.environ, "SIPPYCUP_RUNTIME": "/definitely/missing"},
                                text=True, capture_output=True, timeout=20, check=False)
        self.assertEqual(listed.returncode, 0, listed.stderr)
        document = json.loads(listed.stdout)
        self.assertFalse(document["networkActivity"])
        self.assertEqual([item["id"] for item in document["checks"]], list(catalog.ids()))
        explained = subprocess.run([ROOT / "bin" / "sippycup", "checks", "explain", "nonce-replay"],
                                   cwd=ROOT, env={**os.environ, "SIPPYCUP_RUNTIME": "/definitely/missing"},
                                   text=True, capture_output=True, timeout=20, check=False)
        self.assertEqual(explained.returncode, 0, explained.stderr)
        self.assertIn("Request bound: 3", explained.stdout)
        self.assertTrue(explained.stdout.rstrip().endswith("Network activity: none"))
        unknown = subprocess.run([ROOT / "bin" / "sippycup", "checks", "explain", "port-scan"],
                                 cwd=ROOT, env={**os.environ, "SIPPYCUP_RUNTIME": "/definitely/missing"},
                                 text=True, capture_output=True, timeout=20, check=False)
        self.assertEqual(unknown.returncode, 2)

    def test_section_validation_rejects_unknown_planned_and_placeholder_ids(self) -> None:
        self.assertEqual(catalog.validate_section(None), [])
        good = {"approved": ["banner-disclosure"], "max_requests": 5}
        self.assertEqual(catalog.validate_section(good), [])
        cases = {
            "unknown check": {"approved": ["port-scan"], "max_requests": 5},
            "placeholder": {"approved": ["<check-id>"], "max_requests": 5},
            "duplicates": {"approved": ["banner-disclosure", "banner-disclosure"], "max_requests": 5},
            "max_requests": {"approved": ["banner-disclosure"], "max_requests": 0},
            "unknown security_checks fields": {"approved": [], "max_requests": 5, "brute": True},
            "account is a placeholder": {"approved": [], "max_requests": 5, "account": "changeme"},
        }
        for needle, section in cases.items():
            with self.subTest(needle=needle):
                errors = catalog.validate_section(section)
                self.assertTrue(any(needle in error for error in errors), errors)
        errors = catalog.validate_section(
            {"approved": [], "max_requests": 5, "cleartext_endpoints": [{"transport": "udp", "port": 5060}]},
            {"transport": "udp"},
        )
        self.assertTrue(any("only to a tls target" in error for error in errors))

    def test_rehearse_validates_the_section(self) -> None:
        document = profile_document("127.0.0.1", 5060, "udp", {"approved": ["nmap-scan"], "max_requests": 3})
        result = rehearse(document)
        self.assertFalse(result.ready)
        self.assertTrue(any("unknown check" in error for error in result.errors))
        document["security_checks"]["approved"] = ["banner-disclosure"]
        self.assertTrue(rehearse(document).ready, rehearse(document).errors)


def profile_document(host: str, port: int, transport: str, section: dict[str, Any] | None,
                     **target: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": "sippycup.dev/target-profile/v1",
        "name": "checks-test",
        "target": {"host": host, "port": port, "transport": transport, "approved_addresses": [host], **target},
        "authorization": {
            "status": "approved", "approved_by": "test owner", "approval_id": "TEST-1",
            "valid_from": (NOW - timedelta(hours=1)).isoformat(),
            "valid_until": (NOW + timedelta(hours=4)).isoformat(),
        },
        "limits": {"max_calls": 3, "max_concurrency": 1, "max_calls_per_second": 1, "max_duration_seconds": 60},
        "capture": {"interface": "lo", "output": "work/checks.pcap"},
        "features": {"ice": False, "turn": False, "srtp": False, "dtls_srtp": False, "webrtc": False},
    }
    if section is not None:
        document["security_checks"] = section
    return document


class PlanTests(unittest.TestCase):
    def test_default_deny(self) -> None:
        plan = runner.build_plan(profile_document("127.0.0.1", 5060, "udp", None), now=NOW)
        self.assertFalse(plan["ready"])
        self.assertIn("no security checks are approved", plan["blockingErrors"][0] + " ".join(plan["blockingErrors"]))
        self.assertTrue(all(entry["status"] in ("not-approved", "skipped") for entry in plan["checks"]))
        plan = runner.build_plan(profile_document("127.0.0.1", 5060, "udp", {"approved": [], "max_requests": 5}), now=NOW)
        self.assertFalse(plan["ready"])

    def test_budget_rate_and_only_gates(self) -> None:
        section = {"approved": ["banner-disclosure", "user-enumeration"], "max_requests": 5,
                   "account": ACCOUNT, "destination": "echo"}
        plan = runner.build_plan(profile_document("127.0.0.1", 5060, "udp", section), now=NOW)
        self.assertFalse(plan["ready"])
        self.assertTrue(any("above security_checks.max_requests 5" in error for error in plan["blockingErrors"]))
        section["max_requests"] = 40
        document = profile_document("127.0.0.1", 5060, "udp", section)
        document["limits"]["max_calls"] = 1
        plan = runner.build_plan(document, now=NOW)
        self.assertTrue(any("above limits.max_calls 1" in error for error in plan["blockingErrors"]))
        document["limits"]["max_calls"] = 2
        plan = runner.build_plan(document, now=NOW)
        self.assertTrue(plan["ready"], plan["blockingErrors"])
        self.assertEqual(plan["totalMaxRequests"], 11)
        plan = runner.build_plan(document, now=NOW, only=("nonce-replay",))
        self.assertTrue(any("does not approve" in error for error in plan["blockingErrors"]))
        plan = runner.build_plan(document, now=NOW, only=("banner-disclosure",))
        self.assertTrue(plan["ready"])
        self.assertEqual(plan["totalMaxRequests"], 1)
        statuses = {entry["id"]: entry["status"] for entry in plan["checks"]}
        self.assertEqual(statuses["user-enumeration"], "skipped")
        self.assertEqual(statuses["tls-certificate"], "not-approved")

    def test_prerequisites_skip_with_reasons(self) -> None:
        section = {"approved": ["banner-disclosure", "tls-certificate", "nonce-replay", "unauthenticated-invite"],
                   "max_requests": 40}
        plan = runner.build_plan(profile_document("127.0.0.1", 5060, "udp", section), now=NOW,
                                 password_available=False)
        reasons = {entry["id"]: entry["reason"] for entry in plan["checks"]}
        self.assertIn("needs a tls target", reasons["tls-certificate"])
        self.assertIn("security_checks.account", reasons["nonce-replay"])
        self.assertIn("security_checks.destination", reasons["unauthenticated-invite"])

    def test_host_must_be_an_approved_literal_and_unexpired(self) -> None:
        document = profile_document("127.0.0.1", 5060, "udp", {"approved": ["banner-disclosure"], "max_requests": 2})
        document["target"]["approved_addresses"] = ["127.0.0.9"]
        self.assertFalse(runner.build_plan(document, now=NOW)["ready"])
        document = profile_document("127.0.0.1", 5060, "udp", {"approved": ["banner-disclosure"], "max_requests": 2})
        self.assertFalse(runner.build_plan(document, now=NOW + timedelta(hours=5))["ready"])


# -- request counter ---------------------------------------------------------------

class BudgetTests(ChecksTestCase):
    def test_counter_refuses_before_sending(self) -> None:
        with SipStub("udp", Behaviour(weak=False)) as stub:
            ctx = self.context(endpoint_for(stub))
            ctx.budget.begin("banner-disclosure", 1)
            with ctx.channel() as channel:
                sip.transact(channel, sip.options_request(channel.endpoint), timeout=1)
                with self.assertRaises(BudgetExceeded):
                    sip.transact(channel, sip.options_request(channel.endpoint), timeout=1)
            self.assertEqual(ctx.budget.end(), 1)
            time.sleep(0.2)
            self.assertEqual(stub.requests, ["OPTIONS"])

    def test_total_limit_and_pacing(self) -> None:
        clock = [0.0]
        sleeps: list[float] = []
        budget = Budget(total_limit=2, interval=1.0, monotonic=lambda: clock[0],
                        sleep=lambda seconds: (sleeps.append(seconds), clock.__setitem__(0, clock[0] + seconds)))
        budget.begin("x", 5)
        budget.spend("a")
        budget.spend("ack", paced=False)
        with self.assertRaises(BudgetExceeded):
            budget.spend("b")
        self.assertEqual(sleeps, [])
        budget = Budget(total_limit=5, interval=1.0, monotonic=lambda: clock[0],
                        sleep=lambda seconds: (sleeps.append(seconds), clock.__setitem__(0, clock[0] + seconds)))
        budget.begin("x", 5)
        budget.spend("a")
        budget.spend("b")
        self.assertEqual(sleeps, [1.0])
        with self.assertRaises(BudgetExceeded):
            Budget(total_limit=5).spend("no check")

    def test_a_check_exceeding_its_bound_is_an_internal_error(self) -> None:
        def greedy(ctx: Context) -> checks.CheckResult:
            for _ in range(3):
                with ctx.channel() as channel:
                    sip.transact(channel, sip.options_request(channel.endpoint), timeout=1)
            return checks.CheckResult("banner-disclosure", "passed", "should never get here")

        with SipStub("udp", Behaviour(weak=False)) as stub, tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            section = {"approved": ["banner-disclosure", "options-methods"], "max_requests": 10}
            profile = write_profile(root, profile_document("127.0.0.1", stub.port, "udp", section))
            deps = test_deps(root, implementations={**checks.IMPLEMENTATIONS, "banner-disclosure": greedy})
            code, value = runner.execute(runner.RunOptions(profile=profile), deps)
            time.sleep(0.2)
            self.assertEqual(code, runner.EXIT_RUN_ERROR)
            rows = {item["id"]: item for item in value["findings"]["checks"]}
            self.assertEqual(rows["banner-disclosure"]["status"], "error")
            self.assertIn("declared at most 1", rows["banner-disclosure"]["summary"])
            self.assertEqual(rows["banner-disclosure"]["requestsSent"], 1)
            self.assertEqual(rows["options-methods"]["status"], "skipped")
            self.assertEqual(stub.requests, ["OPTIONS"])
            self.assertEqual(value["requestsSent"], 1)


# -- passive checks ------------------------------------------------------------------

class PassiveTests(ChecksTestCase):
    def test_banner_and_methods_both_directions(self) -> None:
        for transport in ("udp", "tcp"):
            with self.subTest(transport=transport):
                with SipStub(transport, Behaviour(weak=True)) as weak:
                    ctx = self.context(endpoint_for(weak))
                    banner = self.run_check("banner-disclosure", ctx)
                    methods = self.run_check("options-methods", ctx)
                self.assertEqual(self.ids(banner), {"banner-disclosure.version"})
                self.assertIn("18.2.1", json.dumps(banner.findings))
                self.assertEqual(self.ids(methods), {"options-methods.extra-methods"})
                self.assertIn("NOT tested", methods.findings[0]["summary"])
                self.assertEqual((banner.requests_sent, methods.requests_sent), (1, 1))
                with SipStub(transport, Behaviour(weak=False)) as hardened:
                    ctx = self.context(endpoint_for(hardened))
                    banner = self.run_check("banner-disclosure", ctx)
                    methods = self.run_check("options-methods", ctx)
                self.assertEqual((banner.status, methods.status), ("passed", "passed"))
        with SipStub("udp", Behaviour(weak=True, server="Example SBC")) as product:
            result = self.run_check("banner-disclosure", self.context(endpoint_for(product)))
        self.assertEqual(self.ids(result), {"banner-disclosure.product"})
        self.assertEqual(result.findings[0]["severity"], "info")

    def test_no_answer_is_an_error_not_a_pass(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
            silent.bind(("127.0.0.1", 0))
            endpoint = Endpoint("127.0.0.1", silent.getsockname()[1], "udp", domain="127.0.0.1")
            result = self.run_check("banner-disclosure", self.context(endpoint))
        self.assertEqual(result.status, "error")
        self.assertEqual(result.requests_sent, 1)

    def test_cleartext_signaling_probes_only_approved_endpoints(self) -> None:
        tls_side = Endpoint("127.0.0.1", 5061, "tls", domain="voice.test", server_name="voice.test")
        with SipStub("udp", Behaviour(weak=False)) as approved, SipStub("udp", Behaviour(weak=False)) as other:
            section = {"cleartext_endpoints": [{"transport": "udp", "port": approved.port}]}
            result = self.run_check("cleartext-signaling", self.context(tls_side, section))
            time.sleep(0.2)
            self.assertEqual(self.ids(result), {"cleartext-signaling.answered"})
            self.assertEqual(result.requests_sent, 1)
            self.assertEqual(approved.requests, ["OPTIONS"])
            self.assertEqual(other.requests, [])
        free = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        free.bind(("127.0.0.1", 0))
        closed_port = free.getsockname()[1]
        free.close()
        section = {"cleartext_endpoints": [{"transport": "tcp", "port": closed_port}]}
        result = self.run_check("cleartext-signaling", self.context(tls_side, section))
        self.assertEqual(result.status, "passed")
        self.assertEqual(result.requests_sent, 1)


# -- TLS -------------------------------------------------------------------------------

OPENSSL = shutil.which("openssl")


def _openssl(*arguments: str, cwd: Path) -> None:
    subprocess.run([OPENSSL, *arguments], cwd=cwd, check=True, capture_output=True, timeout=60)


def make_certificates(root: Path) -> dict[str, Path]:
    """A CA-signed EC P-256 leaf for voice.test, and a weak self-signed one."""
    _openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
             "-keyout", "ca.key", "-out", "ca.crt", "-days", "30", "-subj", "/CN=Checks Test CA",
             "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign",
             cwd=root)
    _openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
             "-keyout", "good.key", "-out", "good.csr", "-subj", "/CN=voice.test", cwd=root)
    (root / "good.ext").write_text("subjectAltName=DNS:voice.test\nbasicConstraints=CA:FALSE\n", encoding="utf-8")
    _openssl("x509", "-req", "-in", "good.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
             "-out", "good.crt", "-days", "365", "-sha256", "-extfile", "good.ext", cwd=root)
    _openssl("req", "-x509", "-newkey", "rsa:1024", "-nodes", "-sha1", "-keyout", "weak.key",
             "-out", "weak.crt", "-days", "5", "-subj", "/CN=other.test", "-addext",
             "subjectAltName=DNS:other.test", cwd=root)
    return {name: root / name for name in ("ca.crt", "good.crt", "good.key", "weak.crt", "weak.key")}


def server_context(cert: Path, key: Path, *, weak: bool) -> ssl.SSLContext:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if weak:
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.maximum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers("ALL:aNULL:eNULL:@SECLEVEL=0")
        else:
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
    return context


@unittest.skipIf(OPENSSL is None, "openssl CLI not available")
class TlsTests(ChecksTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.certs = make_certificates(Path(cls.temp.name))
        cls.ca = cls.certs["ca.crt"].read_bytes()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def stub(self, weak: bool) -> SipStub:
        name = "weak" if weak else "good"
        return SipStub("tls", Behaviour(weak=weak),
                       tls=server_context(self.certs[f"{name}.crt"], self.certs[f"{name}.key"], weak=weak))

    def test_certificate_both_directions(self) -> None:
        with self.stub(weak=False) as hardened:
            result = self.run_check("tls-certificate", self.context(endpoint_for(hardened, server_name="voice.test", ca=self.ca)))
        self.assertEqual(result.status, "passed", result.findings)
        self.assertEqual(result.requests_sent, 1)
        self.assertTrue(result.detail["verified"])
        with self.stub(weak=True) as weak:
            result = self.run_check("tls-certificate", self.context(endpoint_for(weak, server_name="voice.test", ca=self.ca)))
        self.assertEqual(result.requests_sent, 2)
        found = self.ids(result)
        for expected in ("tls-certificate.name-mismatch", "tls-certificate.weak-key",
                         "tls-certificate.weak-signature", "tls-certificate.self-signed",
                         "tls-certificate.expiring"):
            self.assertIn(expected, found)
        expiring = next(item for item in result.findings if item["id"] == "tls-certificate.expiring")
        self.assertEqual(expiring["severity"], "medium")

    def test_untrusted_chain_with_matching_name(self) -> None:
        with self.stub(weak=False) as hardened:
            result = self.run_check("tls-certificate", self.context(endpoint_for(hardened, server_name="voice.test", ca=None)))
        self.assertIn("tls-certificate.untrusted", self.ids(result))
        self.assertNotIn("tls-certificate.name-mismatch", self.ids(result))

    def test_protocols_both_directions(self) -> None:
        with self.stub(weak=False) as hardened:
            result = self.run_check("tls-protocols", self.context(endpoint_for(hardened, server_name="voice.test", ca=self.ca)))
            sent = result.requests_sent
            time.sleep(0.3)
            self.assertEqual(hardened.handshakes, sent)
        untestable_ids = {item["label"] for item in result.detail["probes"] if item["outcome"] == "untestable"}
        # A probe this library cannot offer is a finding, never a clean pass.
        self.assertEqual(self.ids(result), {"tls-protocols.untestable-probes"} if untestable_ids else set(),
                         result.findings)
        self.assertEqual(result.status, "finding" if untestable_ids else "passed")
        self.assertEqual(set(result.detail["notTestable"]), untestable_ids)
        probes = {item["label"]: item["outcome"] for item in result.detail["probes"]}
        self.assertEqual([item["protocol"] for item in result.detail["acceptedVersions"]], ["TLS 1.2", "TLS 1.3"])
        self.assertTrue(all(item["cipher"] for item in result.detail["acceptedVersions"]))
        self.assertIn("TLS 1.2 (", result.summary)
        self.assertEqual(probes["TLS 1.2"], "accepted")
        self.assertEqual(probes["TLS 1.3"], "accepted")
        untestable = sum(1 for outcome in probes.values() if outcome == "untestable")
        self.assertEqual(sent, 9 - untestable)
        with self.stub(weak=True) as weak:
            result = self.run_check("tls-protocols", self.context(endpoint_for(weak, server_name="voice.test")))
        probes = {item["label"]: item for item in result.detail["probes"]}
        found = self.ids(result)
        if probes["TLS 1.0"]["outcome"] == "untestable":
            self.skipTest("local TLS library cannot offer TLS 1.0")
        self.assertIn("tls-protocols.deprecated-version", found)
        self.assertIn("tls-protocols.no-tls13", found)
        if probes["NULL ciphers"]["outcome"] == "accepted" or probes["anonymous ciphers"]["outcome"] == "accepted":
            self.assertIn("tls-protocols.broken-cipher", found)

    def test_banner_over_verified_tls(self) -> None:
        with self.stub(weak=True) as weak:
            ctx = self.context(endpoint_for(weak, server_name="other.test"))
            result = self.run_check("banner-disclosure", ctx)
            time.sleep(0.2)
            self.assertEqual(weak.requests, [])
        # The weak certificate does not verify, so no SIP was sent; the
        # connection attempt itself is counted.
        self.assertEqual(result.status, "error")
        self.assertEqual(result.requests_sent, 1)
        with self.stub(weak=False) as hardened:
            ctx = self.context(endpoint_for(hardened, server_name="voice.test", ca=self.ca))
            result = self.run_check("banner-disclosure", ctx)
        self.assertEqual(result.status, "passed")
        self.assertEqual(result.requests_sent, 1)


# -- active checks ---------------------------------------------------------------------

class ActiveTests(ChecksTestCase):
    def test_unauthenticated_register_both_directions(self) -> None:
        with SipStub("udp", Behaviour(weak=True)) as weak:
            result = self.run_check("unauthenticated-register", self.context(endpoint_for(weak)))
            time.sleep(0.1)
            self.assertEqual(weak.requests, ["REGISTER"])
        self.assertEqual(self.ids(result), {"unauthenticated-register.accepted"})
        self.assertEqual(result.stop, "unauthenticated REGISTER accepted")
        with SipStub("tcp", Behaviour(weak=False)) as hardened:
            ctx = self.context(endpoint_for(hardened))
            result = self.run_check("unauthenticated-register", ctx)
        self.assertEqual(result.status, "passed")
        self.assertIn("register_challenge", ctx.shared)

    def test_register_query_has_no_contact(self) -> None:
        endpoint = Endpoint("127.0.0.1", 5060, "udp", domain="127.0.0.1")
        channel = sip.Channel(endpoint, Budget(total_limit=1))
        channel.local = ("127.0.0.1", 40000)
        rendered = sip.register_query(ACCOUNT, endpoint).render(channel).decode()
        self.assertNotIn("\r\nContact:", rendered)
        self.assertNotIn("Expires", rendered)
        self.assertIn(f"To: <sip:{ACCOUNT}@127.0.0.1>", rendered)

    def test_digest_quality_both_directions(self) -> None:
        with SipStub("udp", Behaviour(weak=True, register_unauthenticated="challenge")) as weak:
            ctx = self.context(endpoint_for(weak))
            result = self.run_check("digest-quality", ctx)
        self.assertEqual(result.requests_sent, 1)
        self.assertEqual(self.ids(result), {"digest-quality.md5-only", "digest-quality.no-qop",
                                            "digest-quality.weak-nonce", "digest-quality.internal-realm"})
        self.assertNotIn("abc123\"", json.dumps(result.findings))
        with SipStub("udp", Behaviour(weak=False)) as hardened:
            ctx = self.context(endpoint_for(hardened))
            self.run_check("unauthenticated-register", ctx)
            result = self.run_check("digest-quality", ctx)
            time.sleep(0.1)
            self.assertEqual(hardened.requests, ["REGISTER"])  # the challenge was reused
        self.assertEqual(result.status, "passed", result.findings)
        self.assertEqual(result.requests_sent, 0)

    def test_unauthenticated_invite_is_always_ended_correctly(self) -> None:
        with SipStub("udp", Behaviour(weak=False)) as hardened:
            result = self.run_check("unauthenticated-invite", self.context(endpoint_for(hardened)))
            time.sleep(0.2)
            self.assertEqual(hardened.requests, ["INVITE", "ACK"])
        self.assertEqual(result.status, "passed")
        self.assertEqual(result.requests_sent, 2)
        for transport in ("udp", "tcp"):
            with self.subTest(transport=transport), SipStub(transport, Behaviour(weak=True)) as ringing:
                result = self.run_check("unauthenticated-invite", self.context(endpoint_for(ringing)))
                time.sleep(0.2)
                self.assertEqual(ringing.requests, ["INVITE", "CANCEL", "ACK"])
                self.assertEqual(self.ids(result), {"unauthenticated-invite.progressed"})
                self.assertEqual(result.stop, "unauthenticated INVITE progressed")
                self.assertEqual(result.requests_sent, 3)
                self.assertEqual(ringing.pending_invites, {})
        with SipStub("udp", Behaviour(weak=True, invite="answer")) as answering:
            result = self.run_check("unauthenticated-invite", self.context(endpoint_for(answering)))
            time.sleep(0.2)
            self.assertEqual(answering.requests, ["INVITE", "ACK", "BYE"])
        self.assertEqual(self.ids(result), {"unauthenticated-invite.progressed"})
        self.assertIn("answered", result.findings[0]["summary"])
        self.assertEqual(result.detail["steps"], ["INVITE", "ACK 2xx", "BYE -> 200"])

    def test_invite_offers_an_inactive_stream(self) -> None:
        sdp = sip.inactive_sdp("127.0.0.1", 40002).decode()
        self.assertIn("a=inactive", sdp)
        self.assertIn("m=audio 40002 RTP/AVP 0", sdp)

    def test_user_enumeration_both_directions(self) -> None:
        weak = Behaviour(weak=True, register_unauthenticated="challenge", invite="challenge")
        with SipStub("udp", weak) as stub:
            result = self.run_check("user-enumeration", self.context(endpoint_for(stub)))
            time.sleep(0.2)
            self.assertEqual(stub.requests, ["REGISTER", "REGISTER", "INVITE", "ACK", "INVITE", "ACK"])
        self.assertEqual(self.ids(result), {"user-enumeration.differential"})
        self.assertEqual(result.findings[0]["confidence"], "medium")
        self.assertIn("not a scan", result.findings[0]["summary"])
        self.assertIn("timing", result.summary)
        with SipStub("udp", Behaviour(weak=False)) as hardened:
            result = self.run_check("user-enumeration", self.context(endpoint_for(hardened)))
        self.assertEqual(result.status, "passed")
        self.assertEqual(result.requests_sent, 6)
        with SipStub("udp", Behaviour(weak=False)) as hardened:
            result = self.run_check("user-enumeration", self.context(endpoint_for(hardened), {"destination": None}))
        self.assertEqual(result.requests_sent, 2)

    def test_nonce_replay_both_directions(self) -> None:
        for weak, expected in ((True, {"nonce-replay.accepted"}), (False, set())):
            behaviour = Behaviour(weak=weak, register_unauthenticated="challenge", qop="auth",
                                  short_nonce=False, algorithms=("SHA-256",) if weak else ("SHA-256", "MD5"))
            with self.subTest(weak=weak), SipStub("tcp", behaviour) as stub:
                result = self.run_check("nonce-replay", self.context(endpoint_for(stub), password=PASSWORD))
                time.sleep(0.1)
                self.assertEqual(stub.requests, ["REGISTER", "REGISTER", "REGISTER"])
                self.assertEqual(self.ids(result), expected, result.summary)
                self.assertEqual(result.requests_sent, 3)
                self.assertNotIn(PASSWORD, json.dumps([result.summary, result.findings, result.detail]))
        with SipStub("udp", Behaviour(weak=False)) as stub:
            result = self.run_check("nonce-replay", self.context(endpoint_for(stub), password="wrong-password"))
            time.sleep(0.1)
            self.assertEqual(stub.requests, ["REGISTER", "REGISTER"])  # never retried
        self.assertEqual(result.status, "error")
        self.assertIn("not accepted", result.summary)
        result = self.run_check("nonce-replay", self.context(Endpoint("127.0.0.1", 9, "udp", domain="x"), password=None))
        self.assertEqual((result.status, result.requests_sent), ("skipped", 0))


class DigestVectorTests(unittest.TestCase):
    def test_rfc_vectors(self) -> None:
        # RFC 2617 section 3.5 and RFC 7616 section 3.9.1.
        self.assertEqual(sip.digest_response(
            algorithm="MD5", username="Mufasa", realm="testrealm@host.com", password="Circle Of Life",
            method="GET", uri="/dir/index.html", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
            qop="auth", nc="00000001", cnonce="0a4f113b"), "6629fae49393a05397450978507c4ef1")
        vector = dict(username="Mufasa", realm="http-auth@example.org", password="Circle of Life",
                      method="GET", uri="/dir/index.html",
                      nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", qop="auth", nc="00000001",
                      cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ")
        self.assertEqual(sip.digest_response(algorithm="MD5", **vector), "8ca523f5e9506fed4657c9700eebdbec")
        self.assertEqual(sip.digest_response(algorithm="SHA-256", **vector),
                         "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1")

    def test_challenge_parsing_and_choice(self) -> None:
        parsed = sip.parse_challenge('Digest realm="a, b", nonce="n1", algorithm=MD5, qop="auth,auth-int", stale=FALSE')
        self.assertEqual(parsed["realm"], "a, b")
        self.assertEqual(parsed["qop"], "auth,auth-int")
        self.assertIsNone(sip.parse_challenge('Basic realm="x"'))
        chosen = sip.strongest([{"algorithm": "MD5"}, {"algorithm": "SHA-256"}])
        self.assertEqual(chosen["algorithm"], "SHA-256")
        self.assertTrue(sip.is_internal_realm("10.1.2.3"))
        self.assertTrue(sip.is_internal_realm("pbx01.corp"))
        self.assertFalse(sip.is_internal_realm("voice.example.org"))


# -- end to end --------------------------------------------------------------------------

def write_profile(root: Path, document: dict[str, Any]) -> Path:
    path = root / "profile.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    path.chmod(0o600)
    return path


def test_deps(root: Path, **changes: Any) -> runner.Dependencies:
    values: dict[str, Any] = dict(
        work_root=root, capture=False, interval=0.0, timeout=1.0, invite_timeout=1.5,
        install_signal_handlers=False, environ={}, network_mode="host",
    )
    values.update(changes)
    return runner.Dependencies(**values)


def check_findings_schema(test: unittest.TestCase, document: dict[str, Any]) -> None:
    schema = json.loads((ROOT / "schemas" / "findings-v1.schema.json").read_text(encoding="utf-8"))
    test.assertEqual(set(document), set(schema["required"]))
    test.assertEqual(document["apiVersion"], "sippycup.dev/findings/v1")
    test.assertEqual(set(document["target"]), set(schema["properties"]["target"]["required"]))
    check_props = schema["properties"]["checks"]["items"]
    statuses = check_props["properties"]["status"]["enum"]
    for item in document["checks"]:
        test.assertEqual(set(item), set(check_props["required"]))
        test.assertIn(item["status"], statuses)
        test.assertIsInstance(item["requestsSent"], int)
    finding_props = schema["properties"]["findings"]["items"]
    ranks = [catalog.SEVERITY_RANK[item["severity"]] for item in document["findings"]]
    test.assertEqual(ranks, sorted(ranks, reverse=True))
    for item in document["findings"]:
        test.assertEqual(set(item), set(finding_props["required"]))
        test.assertIn(item["severity"], finding_props["properties"]["severity"]["enum"])
        test.assertIn(item["confidence"], finding_props["properties"]["confidence"]["enum"])
        for evidence in item["evidence"]:
            test.assertTrue({"kind", "detail"} <= set(evidence) <= {"kind", "detail", "artifact"})
            test.assertLessEqual(len(evidence["detail"]), 200)


class ExecuteTests(unittest.TestCase):
    def run_profile(self, stub: SipStub, section: dict[str, Any], *, password: bool, fail_on: str = "medium",
                    continue_after: bool = False, engagement: bool = False) -> tuple[int, dict[str, Any], Path]:
        # Each run is its own engagement under its own parent: two directories
        # under one parent that count calls under one approval are refused
        # (wave 12, finding 1).
        root = Path(self.enterContext(tempfile.TemporaryDirectory())) / "work"
        root.mkdir()
        if engagement:
            (root / "engagement.json").write_text("{}", encoding="utf-8")
        profile = write_profile(root, profile_document("127.0.0.1", stub.port, stub.transport, section))
        secret = root / "account.password"
        secret.write_text(PASSWORD + "\n", encoding="utf-8")
        secret.chmod(0o600)
        options = runner.RunOptions(profile=profile, secret_file=secret if password else None,
                                    fail_on=fail_on, continue_after_finding=continue_after)
        code, value = runner.execute(options, test_deps(root))
        run_dir = root / Path(value["runDirectory"]).relative_to("work") if value.get("runDirectory") else None
        return code, value, run_dir

    ALL_ACTIVE = ["banner-disclosure", "options-methods", "unauthenticated-register", "digest-quality",
                  "unauthenticated-invite", "user-enumeration", "nonce-replay"]

    def section(self) -> dict[str, Any]:
        return {"approved": list(self.ALL_ACTIVE), "max_requests": 40, "account": ACCOUNT, "destination": "echo"}

    def test_hardened_run_exit_zero_and_artifacts(self) -> None:
        behaviour = Behaviour(weak=False)
        with SipStub("udp", behaviour) as stub:
            code, value, run_dir = self.run_profile(stub, self.section(), password=True)
            time.sleep(0.2)
            received = len(stub.requests)
        self.assertEqual(code, runner.EXIT_OK, json.dumps(value["findings"]["checks"], indent=1))
        document = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
        check_findings_schema(self, document)
        self.assertEqual(document["findings"], [])
        self.assertEqual(sum(item["requestsSent"] for item in document["checks"]), received)
        self.assertEqual(value["requestsSent"], received)
        for path in run_dir.rglob("*"):
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(mode & 0o077, 0, path)
            self.assertNotIn(PASSWORD, path.read_text(encoding="utf-8", errors="replace"), path)
        human = runner.render_result(value)
        self.assertTrue(human.rstrip().endswith(f"Network activity: {received} requests to 127.0.0.1"))
        self.assertNotIn("Record it:", human)

    def test_run_in_an_engagement_prints_the_journal_command(self) -> None:
        with SipStub("udp", Behaviour(weak=False)) as stub:
            _code, value, run_dir = self.run_profile(stub, self.section(), password=True, engagement=True)
        human = runner.render_result(value)
        relative = f"checks/{run_dir.name}"
        self.assertIn(f"--evidence {relative}/findings.json --evidence {relative}/result.json", human)
        self.assertIn("Record it: ./bin/sippycup journal add ", human)
        self.assertNotIn(PASSWORD, human)

    def test_weak_run_stops_after_progression_and_exit_one(self) -> None:
        with SipStub("udp", Behaviour(weak=True, register_unauthenticated="challenge")) as stub:
            code, value, run_dir = self.run_profile(stub, self.section(), password=True)
        self.assertEqual(code, runner.EXIT_FINDINGS)
        document = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
        check_findings_schema(self, document)
        rows = {item["id"]: item for item in document["checks"]}
        self.assertEqual(rows["unauthenticated-invite"]["status"], "finding")
        self.assertEqual(rows["user-enumeration"]["status"], "skipped")
        self.assertIn("stopped after unauthenticated-invite", rows["user-enumeration"]["summary"])
        self.assertEqual(rows["nonce-replay"]["requestsSent"], 0)
        self.assertEqual(document["findings"][0]["severity"], "high")
        with SipStub("udp", Behaviour(weak=True, register_unauthenticated="challenge")) as stub:
            code, value, run_dir = self.run_profile(stub, self.section(), password=True, continue_after=True)
        rows = {item["id"]: item for item in value["findings"]["checks"]}
        self.assertNotEqual(rows["nonce-replay"]["status"], "skipped")
        self.assertEqual(code, runner.EXIT_FINDINGS)
        with SipStub("udp", Behaviour(weak=True, register_unauthenticated="challenge")) as stub:
            section = {"approved": ["banner-disclosure"], "max_requests": 2}
            code, _value, _ = self.run_profile(stub, section, password=False, fail_on="medium")
            self.assertEqual(code, runner.EXIT_OK)  # a low finding is below --fail-on medium
            code, _value, _ = self.run_profile(stub, section, password=False, fail_on="low")
            self.assertEqual(code, runner.EXIT_FINDINGS)

    def test_refusal_sends_nothing(self) -> None:
        with SipStub("udp", Behaviour(weak=True)) as stub:
            code, value, run_dir = self.run_profile(stub, {"approved": [], "max_requests": 5}, password=False)
            time.sleep(0.2)
            self.assertEqual(stub.requests, [])
        self.assertEqual(code, runner.EXIT_REFUSED)
        self.assertIsNone(run_dir)
        self.assertEqual(value["networkActivity"], "none")
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        document = profile_document("127.0.0.1", 5060, "udp", None)
        code, value = runner.execute(runner.RunOptions(profile=write_profile(root, document)), test_deps(root))
        self.assertEqual(code, runner.EXIT_REFUSED)

    def test_capture_failure_is_a_run_error_with_nothing_sent(self) -> None:
        class Dead:
            def wait_ready(self, *_a: Any) -> str:
                return "capture_failed_to_start"

            def alive(self) -> bool:
                return False

            def stop(self) -> None:
                pass

        with SipStub("udp", Behaviour(weak=True)) as stub:
            root = Path(self.enterContext(tempfile.TemporaryDirectory()))
            profile = write_profile(root, profile_document("127.0.0.1", stub.port, "udp",
                                                           {"approved": ["banner-disclosure"], "max_requests": 2}))
            code, value = runner.execute(runner.RunOptions(profile=profile),
                                         test_deps(root, capture=True, start_capture=lambda *a: Dead()))
            time.sleep(0.2)
            self.assertEqual(stub.requests, [])
        self.assertEqual(code, runner.EXIT_RUN_ERROR)
        self.assertEqual(value["requestsSent"], 0)

    def test_cli_plan_and_dry_run_are_network_free(self) -> None:
        with SipStub("udp", Behaviour(weak=True)) as stub, tempfile.TemporaryDirectory(dir=ROOT / "work") as root_name:
            root = Path(root_name)
            profile = write_profile(root, profile_document("127.0.0.1", stub.port, "udp",
                                                           {"approved": ["banner-disclosure"], "max_requests": 2}))
            for arguments in (["checks", "plan", str(profile)], ["checks", "run", str(profile), "--dry-run"]):
                result = subprocess.run([ROOT / "bin" / "sippycup", *arguments], cwd=ROOT,
                                        env={**os.environ, "SIPPYCUP_RUNTIME": "/definitely/missing"},
                                        text=True, capture_output=True, timeout=30, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("RUN   banner-disclosure", result.stdout)
                self.assertTrue(result.stdout.rstrip().endswith("Network activity: none"))
            time.sleep(0.2)
            self.assertEqual(stub.requests, [])


class LauncherTests(unittest.TestCase):
    def test_run_is_container_private_with_name_only_secret(self) -> None:
        canary = "checks-launcher-canary-55"
        with tempfile.TemporaryDirectory() as root_name:
            runtime = Path(root_name) / "runtime"
            runtime.write_text("#!/bin/sh\nif [ \"$1\" = ps ]; then echo '[]'; exit 0; fi\nprintf '%s\\n' \"$@\"\n", encoding="utf-8")
            runtime.chmod(0o755)
            result = subprocess.run(
                [ROOT / "bin" / "sippycup", "checks", "run", "work/engagement/profile.yaml",
                 "--secret-env", "CHECKS_SECRET", "--run-root", "./work/engagement/checks"],
                cwd=ROOT, env={**os.environ, "SIPPYCUP_RUNTIME": str(runtime), "CHECKS_SECRET": canary},
                text=True, capture_output=True, timeout=20, check=False)
            rejected = subprocess.run(
                [ROOT / "bin" / "sippycup", "--admin", "checks", "run", "work/p.yaml"],
                cwd=ROOT, env={**os.environ, "SIPPYCUP_RUNTIME": str(runtime)},
                text=True, capture_output=True, timeout=20, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = result.stdout.splitlines()
        self.assertNotIn(canary, result.stdout)
        self.assertNotIn("--network=host", arguments)
        self.assertIn("--cap-add=NET_RAW", arguments)
        self.assertIn("--env=SIPPYCUP_NETWORK_MODE=private", arguments)
        self.assertIn("--env=CHECKS_SECRET", arguments)
        self.assertEqual(arguments[arguments.index("sippycup-checks") + 1:],
                         ["run", "/work/engagement/profile.yaml", "--secret-env", "CHECKS_SECRET",
                          "--run-root", "/work/engagement/checks"])
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("rejects --admin", rejected.stderr)


def _scope_fixture() -> dict[str, Any]:
    import importlib.util

    spec = importlib.util.spec_from_file_location("_scope_tests", ROOT / "tests" / "test_scope.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module.complete_scope()


class ScopeTests(unittest.TestCase):
    def write(self, root: Path, document: dict[str, Any]) -> Path:
        path = root / "scope.yaml"
        path.write_text(yaml.safe_dump(document), encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_scope_validation_and_compile(self) -> None:
        from sippycup_workbench.scope import inspect
        from sippycup_workbench.scope_derive import compile_scope

        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            document = _scope_fixture()
            path = self.write(root, document)
            self.assertTrue(inspect(path).ok)
            self.assertNotIn("security_checks", yaml.safe_load(_compiled(root, compile_scope)))
            document["security_checks"] = {"approved": ["banner-disclosure", "port-scan"], "max_requests": 5}
            self.write(root, document)
            messages = [item.message for item in inspect(path).errors]
            self.assertTrue(any("unknown check" in message for message in messages), messages)
            document["security_checks"]["approved"] = ["banner-disclosure", "unauthenticated-invite",
                                                       "nonce-replay", "tls-certificate"]
            self.write(root, document)
            messages = [item.message for item in inspect(path).errors]
            self.assertTrue(any("security-checks" in message for message in messages), messages)
            self.assertTrue(any("needs the first target to use tls" in message for message in messages))
            self.assertTrue(any("above max_requests 5" in message for message in messages))
            document["test_scope"]["allowed_classes"].append("security-checks")
            document["security_checks"] = {"approved": ["banner-disclosure", "unauthenticated-invite",
                                                        "nonce-replay"], "max_requests": 8}
            self.write(root, document)
            report = inspect(path)
            self.assertTrue(report.ok, [item.message for item in report.errors])
            profile = yaml.safe_load(_compiled(root, compile_scope))
            self.assertEqual(profile["security_checks"], {
                "approved": ["banner-disclosure", "unauthenticated-invite", "nonce-replay"],
                "max_requests": 8, "account": "staging-user", "destination": "9196",
            })
            self.assertTrue(rehearse(profile).ready, rehearse(profile).errors)
            document["limits"]["calls"] = 1
            document["security_checks"]["approved"].append("user-enumeration")
            document["security_checks"]["max_requests"] = 40
            self.write(root, document)
            messages = [item.message for item in inspect(path).errors]
            self.assertTrue(any("above limits.calls 1" in message for message in messages), messages)

    def test_cleartext_endpoints_come_from_the_approved_signaling_envelope(self) -> None:
        from sippycup_workbench.scope import inspect
        from sippycup_workbench.scope_derive import compile_scope

        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            document = _scope_fixture()
            document["targets"].reverse()  # the TLS target first
            document["test_scope"]["allowed_classes"].append("security-checks")
            document["security_checks"] = {"approved": ["tls-certificate", "cleartext-signaling"], "max_requests": 6}
            path = self.write(root, document)
            report = inspect(path)
            self.assertTrue(report.ok, [item.message for item in report.errors])
            profile = yaml.safe_load(_compiled(root, compile_scope))
            self.assertEqual(profile["security_checks"]["cleartext_endpoints"],
                             [{"transport": "udp", "port": 5060}, {"transport": "udp", "port": 5061}])

    def test_question_sheet_explains_every_runnable_check_with_its_count(self) -> None:
        from sippycup_workbench.scope_questions import render_questions

        sheet = render_questions()
        for spec in catalog.CHECKS:
            if spec.state == "runnable":
                self.assertIn(f"- {spec.id} ({spec.impact}, ", sheet)
        self.assertIn("at most 4 requests", sheet)


def _compiled(root: Path, compile_scope: Any) -> str:
    result = compile_scope(root, force=True)
    path = root / "target-profile.yaml"
    assert path.exists(), result.as_dict()
    return path.read_text(encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
