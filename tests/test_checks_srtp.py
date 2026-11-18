"""Host tests for the srtp-policy check and the TLS protocol report.

The softphone driver is replaced by a fake that writes the PJSUA-style
message log a real call would and returns a scripted ``SoftphoneResult``, so
every outcome branch is proven without a SIP server: what was offered, what
was answered, the request accounting (reserve, settle, refund), the gates
(authorization re-check, media scope, credentials never retried), and that
the password reaches the driver only as an argument and never any artifact.
"""

from __future__ import annotations

import json
import shutil
import ssl
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from sippycup_checks import catalog, checks, runner, srtpcheck, tlsprobe  # noqa: E402
from sippycup_checks.budget import Budget, BudgetExceeded, Stopped  # noqa: E402
from sippycup_checks.checks import Context  # noqa: E402
from sippycup_checks.sip import Endpoint  # noqa: E402
from sippycup_softphone.driver import SoftphoneResult  # noqa: E402

import test_checks as base  # noqa: E402

PASSWORD = base.PASSWORD
ACCOUNT = base.ACCOUNT
SCRIPT_DEFAULT = {"status": 200, "answered": True, "active": False, "answer_profile": "RTP/AVP",
                  "answer_crypto": False}


def message(direction: str, kind: str, method: str, cseq: int, status: int | None = None, body: str = "") -> str:
    head = f"{status}/" if status else ""
    return (f"12:00:00.000 pjsua_core.c .{direction} 600 bytes {kind} msg {head}{method}/cseq={cseq} (tdta1)\n"
            f"{body}--end msg--\n")


def sdp_body(profile: str, crypto: bool) -> str:
    lines = ["v=0", "m=audio 4000 " + profile + " 0"]
    if crypto:
        lines.append("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:SECRETKEYSECRETKEYSECRETKEYSECRETKEY1234")
    return "\n".join(lines) + "\n"


def request_log(requests: int) -> str:
    return "".join(message("TX", "Request", "INVITE" if index % 2 == 0 else "ACK", index + 1) for index in range(requests))


class FakeCalls:
    """Stands in for ``place_call``; ``script`` maps (srtp, transport) to the outcome."""

    def __init__(self, script: dict[tuple[str, str], dict[str, Any]] | None = None, *,
                 default: dict[str, Any] | None = None) -> None:
        self.script = script or {}
        self.default = default or SCRIPT_DEFAULT
        self.calls: list[dict[str, Any]] = []

    def __call__(self, call: Any, *, password: str | None = None, cancel: Any = None, pjsua: str = "pjsua",
                 environment: Any = None, **_rest: Any) -> SoftphoneResult:
        plan = {**self.default, **self.script.get((call.srtp, call.transport), {})}
        self.calls.append({"call": call, "password": password, "cancel": cancel, "environment": environment})
        offer_profile = "RTP/SAVP" if call.srtp == "mandatory" else "RTP/AVP"
        offer = {"port": 4002, "profile": offer_profile, "telephoneEvents": [],
                 "cryptoSuites": ["AES_CM_128_HMAC_SHA1_80"] if call.srtp != "off" else []}
        answered = plan["answered"]
        answer = None
        if answered:
            answer = {"port": 4000, "profile": plan["answer_profile"], "telephoneEvents": [],
                      "cryptoSuites": ["AES_CM_128_HMAC_SHA1_80"] if plan["answer_crypto"] else []}
        started = plan.get("started", True)
        result = SoftphoneResult(
            destination_uri="sip:echo@127.0.0.1", started=started, dialed=started, answered=answered,
            final_status=plan["status"], sdp={"offer": offer, "answer": answer},
            srtp={"requested": call.srtp, "active": bool(plan["active"]), "suite": "AES_CM_128_HMAC_SHA1_80"
                  if plan["active"] else None, "secureSignaling": call.transport == "tls"},
            error=plan.get("error"), connected_seconds=1.0 if answered else None,
            hangup="duration" if answered else None,
        )
        requests = plan.get("requests")
        if requests is None:
            requests = 5 if answered else 4
        if started:
            call.log_file.write_text(request_log(requests), encoding="utf-8")
        return result


def endpoint(transport: str = "tls", port: int = 5061, **extra: Any) -> Endpoint:
    values: dict[str, Any] = dict(domain="127.0.0.1")
    if transport == "tls":
        values.update(domain="voice.test", server_name="voice.test", ca_data=b"-----BEGIN CERTIFICATE-----\nx\n")
    values.update(extra)
    return Endpoint("127.0.0.1", port, transport, **values)


CLEARTEXT = [{"transport": "udp", "port": 5060}, {"transport": "tcp", "port": 5060}]


class SrtpPolicyTests(unittest.TestCase):
    def context(self, fake: FakeCalls, *, transport: str = "tls", cleartext: bool = True,
                limit: int = 100, recheck: Any = None, expected: bool = False, **extra: Any) -> Context:
        section: dict[str, Any] = {"approved": ["srtp-policy"], "max_requests": limit, "account": ACCOUNT,
                                   "destination": "echo"}
        if cleartext:
            section["cleartext_endpoints"] = list(CLEARTEXT)
        self.temp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        context = Context(
            endpoint=endpoint(transport, 5061 if transport == "tls" else 5060), section=section,
            budget=Budget(total_limit=limit, interval=0.0), password=PASSWORD, timeout=1.0,
            approved_addresses=("127.0.0.1",), place_call=fake, run_dir=self.temp, srtp_expected=expected,
            call_environment={"PATH": "/usr/bin"}, local_address="127.0.0.1", **extra,
        )
        if recheck is not None:
            context.recheck = recheck
        return context

    def run_check(self, ctx: Context) -> checks.CheckResult:
        spec = catalog.get("srtp-policy")
        bound = catalog.declared_bound(spec, ctx.section, ctx.endpoint.transport)
        ctx.budget.begin("srtp-policy", bound)
        try:
            result = checks.IMPLEMENTATIONS["srtp-policy"](ctx)
        finally:
            sent = ctx.budget.end()
        result.requests_sent = sent
        self.assertLessEqual(sent, bound)
        return result

    @staticmethod
    def ids(result: checks.CheckResult) -> set[str]:
        return {item["id"] for item in result.findings}

    # -- outcome branches ------------------------------------------------------------

    def test_hardened_edge_requires_srtp_and_refuses_cleartext_keys(self) -> None:
        fake = FakeCalls({
            ("off", "tls"): {"status": 488, "answered": False},
            ("mandatory", "tls"): {"answer_profile": "RTP/SAVP", "answer_crypto": True, "active": True},
            ("optional", "udp"): {"status": 488, "answered": False},
        })
        result = self.run_check(self.context(fake))
        self.assertEqual(result.status, "passed", result.summary)
        self.assertEqual(result.findings, [])
        self.assertEqual([item["call"].srtp for item in fake.calls], ["off", "mandatory", "optional"])
        self.assertEqual([item["call"].transport for item in fake.calls], ["tls", "tls", "udp"])
        rows = {row["probe"]: row for row in result.detail["calls"]}
        self.assertEqual(rows["plain-rtp"]["outcome"], "refused")
        self.assertEqual(rows["plain-rtp"]["status"], 488)
        self.assertEqual(rows["sdes-mandatory"]["answerProfile"], "RTP/SAVP")
        self.assertTrue(rows["sdes-mandatory"]["srtpActive"])
        self.assertIn("RTP/SAVP with a=crypto", rows["sdes-mandatory"]["offered"])
        self.assertEqual(rows["sdes-over-cleartext"]["signaling"], "UDP 5060")

    def test_permissive_edge_accepts_plain_rtp_and_cleartext_keys(self) -> None:
        fake = FakeCalls({
            ("mandatory", "tls"): {"answer_profile": "RTP/SAVP", "answer_crypto": True, "active": True},
            ("optional", "udp"): {"answer_crypto": True, "active": True},
        })
        result = self.run_check(self.context(fake))
        self.assertEqual(result.status, "finding")
        self.assertEqual(self.ids(result), {"srtp-policy.plain-rtp-accepted", "srtp-policy.keys-over-cleartext"})
        plain = next(item for item in result.findings if item["id"] == "srtp-policy.plain-rtp-accepted")
        self.assertEqual(plain["severity"], "low")
        offered = [item["detail"] for item in plain["evidence"] if item["kind"] == "offered"]
        answered = [item["detail"] for item in plain["evidence"] if item["kind"] == "answered"]
        self.assertIn("RTP/AVP without a=crypto", offered[0])
        self.assertIn("TLS 5061", offered[0])
        self.assertIn("status 200", answered[0])
        keys = next(item for item in result.findings if item["id"] == "srtp-policy.keys-over-cleartext")
        self.assertIn("UDP 5060", " ".join(item["detail"] for item in keys["evidence"]))
        self.assertIn("SRTP active", " ".join(item["detail"] for item in keys["evidence"]))
        self.assertNotIn("SECRETKEY", json.dumps(result.findings) + json.dumps(result.detail))

    def test_plain_rtp_severity_follows_the_profile_expectation(self) -> None:
        for expected, severity in ((True, "medium"), (False, "low")):
            fake = FakeCalls({("mandatory", "tls"): {"status": 488, "answered": False}})
            result = self.run_check(self.context(fake, expected=expected, cleartext=False))
            plain = next(item for item in result.findings if item["id"] == "srtp-policy.plain-rtp-accepted")
            self.assertEqual(plain["severity"], severity)

    def test_mandatory_offer_answered_with_plain_rtp_is_a_downgrade(self) -> None:
        fake = FakeCalls({
            ("off", "tls"): {"status": 488, "answered": False},
            ("mandatory", "tls"): {"answer_profile": "RTP/AVP", "answer_crypto": False, "active": False,
                                   "error": "srtp_not_negotiated"},
            ("optional", "udp"): {"status": 488, "answered": False},
        })
        result = self.run_check(self.context(fake))
        self.assertEqual(self.ids(result), {"srtp-policy.downgrade"})
        item = result.findings[0]
        text = " ".join(evidence["detail"] for evidence in item["evidence"])
        self.assertIn("RTP/SAVP with a=crypto", text)
        self.assertIn("RTP/AVP without a=crypto", text)
        self.assertIn("SRTP not active", text)

    def test_sdes_refused_is_informational(self) -> None:
        fake = FakeCalls(default={"status": 488, "answered": False, "active": False,
                                  "answer_profile": None, "answer_crypto": False})
        result = self.run_check(self.context(fake))
        self.assertEqual(self.ids(result), {"srtp-policy.sdes-not-accepted"})
        self.assertEqual(result.findings[0]["severity"], "info")
        self.assertEqual(result.status, "finding")

    def test_cleartext_target_that_accepts_sdes_exposes_keys(self) -> None:
        fake = FakeCalls({
            ("off", "udp"): {"status": 488, "answered": False},
            ("mandatory", "udp"): {"answer_profile": "RTP/SAVP", "answer_crypto": True, "active": True},
        })
        result = self.run_check(self.context(fake, transport="udp", cleartext=False))
        self.assertEqual(self.ids(result), {"srtp-policy.keys-over-cleartext"})
        self.assertEqual(len(fake.calls), 2)
        self.assertEqual(result.requests_sent, 4 + 5)

    def test_sdes_answered_without_crypto_over_cleartext_is_not_a_key_finding(self) -> None:
        fake = FakeCalls({
            ("off", "tls"): {"status": 488, "answered": False},
            ("mandatory", "tls"): {"answer_profile": "RTP/SAVP", "answer_crypto": True, "active": True},
            ("optional", "udp"): {"answer_crypto": False, "active": False},
        })
        result = self.run_check(self.context(fake))
        self.assertEqual(self.ids(result), set())
        self.assertIn("no SRTP", result.summary)

    def test_without_an_approved_cleartext_endpoint_that_probe_is_not_run_and_said_so(self) -> None:
        fake = FakeCalls({
            ("off", "tls"): {"status": 488, "answered": False},
            ("mandatory", "tls"): {"answer_profile": "RTP/SAVP", "answer_crypto": True, "active": True},
        })
        result = self.run_check(self.context(fake, cleartext=False))
        self.assertEqual(result.status, "passed")
        self.assertEqual(len(fake.calls), 2)
        self.assertIn("SDES over cleartext not tested", result.summary)

    # -- credentials, gates, and failures -----------------------------------------------

    def test_rejected_credentials_end_the_check_and_nothing_is_retried(self) -> None:
        fake = FakeCalls(default={"status": 401, "answered": False, "active": False,
                                  "answer_profile": None, "answer_crypto": False})
        result = self.run_check(self.context(fake))
        self.assertEqual(result.status, "error")
        self.assertEqual(len(fake.calls), 1)
        self.assertIn("not accepted", result.summary)
        self.assertEqual(result.detail["notRun"], ["sdes-mandatory", "sdes-over-cleartext"])

    def test_authorization_is_rechecked_before_every_call(self) -> None:
        reasons = [None, "the window closed"]
        seen: list[int] = []

        def recheck() -> str | None:
            seen.append(1)
            return reasons.pop(0) if reasons else "the window closed"

        fake = FakeCalls({("off", "tls"): {"status": 488, "answered": False}})
        result = self.run_check(self.context(fake, recheck=recheck))
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(result.status, "error")
        self.assertEqual(result.stop, "authorization lapsed: the window closed")
        self.assertEqual(len(seen), 2)

    def test_media_outside_scope_stops_the_run(self) -> None:
        fake = FakeCalls({("off", "tls"): {"error": "media_peer_outside_scope", "active": False}})
        result = self.run_check(self.context(fake))
        self.assertEqual(result.status, "error")
        self.assertEqual(result.stop, "call stopped: media_peer_outside_scope")
        self.assertEqual(len(fake.calls), 1)

    def test_tls_verification_failure_is_an_error_not_a_finding(self) -> None:
        fake = FakeCalls({("off", "tls"): {"status": None, "answered": False, "error": "tls_verification_failed"}})
        result = self.run_check(self.context(fake))
        self.assertEqual(result.status, "error")
        self.assertEqual(result.findings, [])
        self.assertIn("tls_verification_failed", result.summary)

    def test_softphone_not_starting_places_no_call_and_charges_nothing(self) -> None:
        fake = FakeCalls(default={"started": False, "status": None, "answered": False, "active": False,
                                  "answer_profile": None, "answer_crypto": False})
        ctx = self.context(fake)
        result = self.run_check(ctx)
        self.assertEqual(result.status, "error")
        self.assertEqual(result.requests_sent, 0)
        self.assertEqual(len(fake.calls), 1)

    def test_unanswered_call_is_inconclusive_never_a_clean_pass(self) -> None:
        fake = FakeCalls({
            ("off", "tls"): {"status": 488, "answered": False},
            ("mandatory", "tls"): {"status": None, "answered": False, "error": "no_answer_before_timeout"},
            ("optional", "udp"): {"status": 488, "answered": False},
        })
        result = self.run_check(self.context(fake))
        self.assertEqual(result.status, "error")
        self.assertIn("INCONCLUSIVE: sdes-mandatory", result.summary)

    def test_invalid_softphone_request_is_reported_before_any_call(self) -> None:
        fake = FakeCalls()
        ctx = self.context(fake)
        ctx.section["destination"] = "bad destination"
        result = self.run_check(ctx)
        self.assertEqual(result.status, "error")
        self.assertEqual(fake.calls, [])
        self.assertEqual(result.requests_sent, 0)

    # -- what reaches the softphone ---------------------------------------------------

    def test_calls_are_one_second_scoped_and_carry_the_gates(self) -> None:
        fake = FakeCalls({("mandatory", "tls"): {"status": 488, "answered": False}})
        ctx = self.context(fake)
        ctx.approved_addresses = ("127.0.0.1", "127.0.0.9")
        self.run_check(ctx)
        tls_call, _, clear = (item["call"] for item in fake.calls)
        for call in (tls_call, clear):
            self.assertEqual(call.duration_seconds, 1)
            self.assertEqual(call.destination, "echo")
            self.assertEqual(call.host, "127.0.0.1")
            self.assertEqual(call.allowed_media_addresses, ("127.0.0.1", "127.0.0.9"))
            self.assertEqual(call.account.username, ACCOUNT)
            self.assertIsNone(call.account.registrar)
            self.assertEqual(call.advertised_address, "127.0.0.1")
        self.assertEqual((tls_call.port, tls_call.tls_server_name), (5061, "voice.test"))
        self.assertIsNotNone(tls_call.tls_ca_file)
        self.assertEqual((clear.port, clear.transport), (5060, "udp"))
        self.assertIsNone(clear.tls_server_name)
        self.assertIsNone(clear.tls_ca_file)
        for item in fake.calls:
            self.assertEqual(item["password"], PASSWORD)
            self.assertNotIn(PASSWORD, json.dumps(item["environment"]))

    def test_the_password_appears_in_no_artifact(self) -> None:
        fake = FakeCalls({("off", "tls"): {"status": 488, "answered": False}})
        ctx = self.context(fake)
        result = self.run_check(ctx)
        artifacts = list(ctx.run_dir.rglob("*"))
        self.assertTrue(any(path.name == "plain-rtp.json" for path in artifacts))
        for path in artifacts:
            if path.is_file():
                self.assertNotIn(PASSWORD.encode(), path.read_bytes(), path)
        self.assertNotIn(PASSWORD, json.dumps(result.detail) + json.dumps(result.findings) + result.summary)

    # -- request accounting ---------------------------------------------------------------

    def test_calls_are_charged_at_the_worst_case_then_settled_to_the_log(self) -> None:
        fake = FakeCalls({
            ("off", "tls"): {"status": 488, "answered": False, "requests": 3},
            ("mandatory", "tls"): {"requests": 4, "answer_profile": "RTP/SAVP", "answer_crypto": True, "active": True},
            ("optional", "udp"): {"status": 488, "answered": False, "requests": 4},
        })
        ctx = self.context(fake)
        result = self.run_check(ctx)
        self.assertEqual(result.requests_sent, 3 + 4 + 4)
        self.assertEqual([row["requests"] for row in result.detail["calls"]], [3, 4, 4])
        reserved = [item["reserved"] for item in ctx.budget.log if "reserved" in item and "settled" not in item]
        self.assertEqual(reserved, [6, 6, 6])
        self.assertEqual(ctx.budget.total, result.requests_sent)

    def test_a_call_that_sends_more_than_reserved_is_an_error(self) -> None:
        fake = FakeCalls({("off", "udp"): {"requests": 9}})
        ctx = self.context(fake, transport="udp", cleartext=False)
        ctx.budget.begin("srtp-policy", catalog.declared_bound(catalog.get("srtp-policy"), ctx.section, "udp"))
        with self.assertRaises(BudgetExceeded):
            checks.IMPLEMENTATIONS["srtp-policy"](ctx)
        self.assertEqual(ctx.budget.end(), 9)  # the excess is counted, not hidden

    def test_the_worst_case_must_fit_before_a_call_is_placed(self) -> None:
        fake = FakeCalls()
        ctx = self.context(fake, limit=5)  # one call can cost 6
        ctx.budget.begin("srtp-policy", 5)
        with self.assertRaises(BudgetExceeded):
            checks.IMPLEMENTATIONS["srtp-policy"](ctx)
        self.assertEqual(fake.calls, [])
        self.assertEqual(ctx.budget.total, 0)

    def test_cancellation_stops_before_a_call(self) -> None:
        fake = FakeCalls()
        ctx = self.context(fake)
        ctx.budget.should_stop = lambda: "cancelled by signal"
        ctx.budget.begin("srtp-policy", 18)
        with self.assertRaises(Stopped):
            checks.IMPLEMENTATIONS["srtp-policy"](ctx)
        self.assertEqual(fake.calls, [])

    def test_declared_bounds_follow_the_transport_and_endpoints(self) -> None:
        spec = catalog.get("srtp-policy")
        with_clear = {"cleartext_endpoints": CLEARTEXT}
        self.assertEqual(catalog.declared_bound(spec, with_clear, "tls"), 6 + 6 + 6)
        self.assertEqual(catalog.declared_bound(spec, {"cleartext_endpoints": [CLEARTEXT[1]]}, "tls"), 18)
        self.assertEqual(catalog.declared_bound(spec, {}, "tls"), 12)
        self.assertEqual(catalog.declared_bound(spec, with_clear, "udp"), 12)
        self.assertEqual(catalog.declared_bound(spec, {}, "tcp"), 12)
        self.assertEqual(catalog.invites_declared(spec, with_clear, "tls"), 3)
        self.assertEqual(catalog.invites_declared(spec, with_clear, "udp"), 2)

    def test_count_requests_counts_every_transmission(self) -> None:
        log = request_log(5) + message("RX", "Response", "INVITE", 1, 200)
        self.assertEqual(srtpcheck.count_requests(log, "udp"), 5)
        self.assertEqual(srtpcheck.count_requests(log, "tls"), 5)
        # a stream that connected counts one request even if no SIP followed
        self.assertEqual(srtpcheck.count_requests("", "tls"), 1)
        self.assertEqual(srtpcheck.count_requests("", "udp"), 0)


class SrtpPolicyRunTests(unittest.TestCase):
    """The same check through the runner: plan, gates, artifacts, schema."""

    def section(self, **extra: Any) -> dict[str, Any]:
        return {"approved": ["srtp-policy"], "max_requests": 40, "account": ACCOUNT, "destination": "echo", **extra}

    def execute(self, fake: FakeCalls, section: dict[str, Any], *, password: bool = True, expected: bool = False,
                max_calls: int = 3) -> tuple[int, dict[str, Any], Path]:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        document = base.profile_document("127.0.0.1", 5060, "udp", section)
        document["features"]["srtp"] = expected
        document["limits"]["max_calls"] = max_calls
        profile = base.write_profile(root, document)
        secret = root / "account.password"
        secret.write_text(PASSWORD + "\n", encoding="utf-8")
        secret.chmod(0o600)
        options = runner.RunOptions(profile=profile, secret_file=secret if password else None)
        code, value = runner.execute(options, base.test_deps(root, place_call=fake, environ={"HOME": "/x"}))
        run_dir = root / Path(value["runDirectory"]).relative_to("work") if value.get("runDirectory") else root
        return code, value, run_dir

    def test_run_reports_findings_and_counts_what_the_calls_sent(self) -> None:
        fake = FakeCalls({
            ("off", "udp"): {"requests": 4},
            ("mandatory", "udp"): {"requests": 5, "answer_profile": "RTP/SAVP", "answer_crypto": True,
                                   "active": True},
        })
        code, value, run_dir = self.execute(fake, self.section(), expected=True)
        document = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
        base.check_findings_schema(self, document)
        row = next(item for item in document["checks"] if item["id"] == "srtp-policy")
        self.assertEqual(row["status"], "finding")
        self.assertEqual(row["requestsSent"], 9)
        self.assertEqual(value["requestsSent"], 9)
        self.assertEqual({item["id"] for item in document["findings"]},
                         {"srtp-policy.plain-rtp-accepted", "srtp-policy.keys-over-cleartext"})
        self.assertEqual(code, runner.EXIT_FINDINGS)  # plain RTP is medium when features.srtp is true
        self.assertEqual(len(fake.calls), 2)
        for path in run_dir.rglob("*"):
            if path.is_file():
                self.assertNotIn(PASSWORD.encode(), path.read_bytes(), path)
        detail = json.loads((run_dir / "checks-detail.json").read_text(encoding="utf-8"))
        calls = next(item for item in detail["checks"] if item["id"] == "srtp-policy")["detail"]["calls"]
        self.assertEqual([row["probe"] for row in calls], ["plain-rtp", "sdes-mandatory"])
        self.assertEqual([item["request"] for item in value["requestLog"]][:3],
                         ["softphone call (plain-rtp)", "softphone call (plain-rtp)", "softphone call (sdes-mandatory)"])

    def test_plan_is_default_deny_and_bounded(self) -> None:
        now = datetime.now(timezone.utc)
        document = base.profile_document("127.0.0.1", 5060, "udp", self.section())
        plan = runner.build_plan(document, now=now, password_available=True)
        entry = next(item for item in plan["checks"] if item["id"] == "srtp-policy")
        self.assertEqual((entry["status"], entry["maxRequests"]), ("will-run", 12))
        self.assertEqual(plan["inviteAttempts"], 2)
        blocked = runner.build_plan(base.profile_document("127.0.0.1", 5060, "udp", self.section(max_requests=11)),
                                    now=now, password_available=True)
        self.assertFalse(blocked["ready"])
        self.assertIn("above security_checks.max_requests 11", " ".join(blocked["blockingErrors"]))
        document["limits"]["max_calls"] = 1
        self.assertIn("above limits.max_calls 1", " ".join(runner.build_plan(document, now=now, password_available=True)["blockingErrors"]))
        missing = runner.build_plan(base.profile_document("127.0.0.1", 5060, "udp", self.section()), now=now,
                                    password_available=False)
        self.assertEqual(next(item for item in missing["checks"] if item["id"] == "srtp-policy")["status"], "skipped")
        unapproved = self.section()
        unapproved["approved"] = ["banner-disclosure"]
        other = runner.build_plan(base.profile_document("127.0.0.1", 5060, "udp", unapproved), now=now,
                                  password_available=True)
        self.assertEqual(next(item for item in other["checks"] if item["id"] == "srtp-policy")["status"], "not-approved")

    def test_an_unapproved_check_places_no_call(self) -> None:
        fake = FakeCalls()
        section = self.section()
        section["approved"] = ["banner-disclosure"]
        code, value, _ = self.execute(fake, section)
        self.assertEqual(fake.calls, [])
        self.assertNotIn("srtp-policy", [item["id"] for item in value["findings"]["checks"] if item["requestsSent"]])

    def test_explain_lists_the_probes_and_findings(self) -> None:
        text = catalog.render_explain("srtp-policy")
        for needle in ("plain RTP/AVP", "mandatory", "a=crypto", "Request bound: 18", "srtp-policy.downgrade",
                       "srtp-policy.keys-over-cleartext"):
            self.assertIn(needle, text)
        self.assertNotIn("PLANNED", text)


@unittest.skipIf(base.OPENSSL is None, "openssl CLI not available")
class TlsProtocolReportTests(base.ChecksTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.certs = base.make_certificates(Path(cls.temp.name))
        cls.ca = cls.certs["ca.crt"].read_bytes()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def server(self, minimum: ssl.TLSVersion, maximum: ssl.TLSVersion) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = minimum
        context.maximum_version = maximum
        context.load_cert_chain(self.certs["good.crt"], self.certs["good.key"])
        return context

    def test_every_accepted_version_is_listed_with_its_cipher(self) -> None:
        with base.SipStub("tls", base.Behaviour(weak=False),
                          tls=self.server(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)) as stub:
            ctx = self.context(base.endpoint_for(stub, server_name="voice.test", ca=self.ca))
            certificate = self.run_check("tls-certificate", ctx)
            result = self.run_check("tls-protocols", ctx)
        versions = {item["protocol"]: item for item in result.detail["acceptedVersions"]}
        self.assertEqual(set(versions), {"TLS 1.2", "TLS 1.3"})
        self.assertEqual(versions["TLS 1.3"]["negotiated"], "TLSv1.3")
        self.assertTrue(versions["TLS 1.2"]["cipher"])
        self.assertNotIn("tls-protocols.deprecated-version", self.ids(result))
        self.assertNotIn("tls-protocols.no-tls13", self.ids(result))
        self.assertEqual(result.detail["certificate"]["source"], "tls-certificate check in this run")
        self.assertEqual(result.detail["certificate"]["notAfter"], certificate.detail["certificate"]["notAfter"])

    def test_tls12_only_edge_is_reported_without_tls13(self) -> None:
        with base.SipStub("tls", base.Behaviour(weak=False),
                          tls=self.server(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)) as stub:
            result = self.run_check("tls-protocols", self.context(base.endpoint_for(stub, server_name="voice.test")))
        self.assertEqual([item["protocol"] for item in result.detail["acceptedVersions"]], ["TLS 1.2"])
        self.assertIn("tls-protocols.no-tls13", self.ids(result))
        self.assertIn("rejected: TLS 1.0, TLS 1.1, TLS 1.3", result.summary)

    def test_deprecated_versions_are_flagged_when_accepted(self) -> None:
        if not isinstance(tlsprobe.probe_context(tlsprobe.V.TLSv1, tlsprobe.V.TLSv1, "DEFAULT:@SECLEVEL=0"), ssl.SSLContext):
            self.skipTest("local TLS library cannot offer TLS 1.0")
        with base.SipStub("tls", base.Behaviour(weak=True),
                          tls=base.server_context(self.certs["weak.crt"], self.certs["weak.key"], weak=True)) as stub:
            result = self.run_check("tls-protocols", self.context(base.endpoint_for(stub, server_name="voice.test")))
        accepted = {item["protocol"] for item in result.detail["acceptedVersions"]}
        self.assertIn("TLS 1.0", accepted)
        flagged = next(item for item in result.findings if item["id"] == "tls-protocols.deprecated-version")
        self.assertEqual(flagged["severity"], "medium")
        self.assertTrue(any("cipher" in item["detail"] for item in flagged["evidence"]))

    def test_a_probe_the_toolbox_cannot_offer_is_not_testable_never_not_accepted(self) -> None:
        real = tlsprobe.probe_context

        def probe_context(minimum: Any, maximum: Any, ciphers: str | None) -> Any:
            if minimum == tlsprobe.V.TLSv1 and maximum == tlsprobe.V.TLSv1 or ciphers and ciphers.startswith("3DES"):
                return "the local TLS library cannot offer it (fake)"
            return real(minimum, maximum, ciphers)

        tlsprobe.probe_context = probe_context
        self.addCleanup(setattr, tlsprobe, "probe_context", real)
        with base.SipStub("tls", base.Behaviour(weak=False),
                          tls=self.server(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)) as stub:
            result = self.run_check("tls-protocols", self.context(base.endpoint_for(stub, server_name="voice.test")))
        outcomes = {item["label"]: item["outcome"] for item in result.detail["probes"]}
        self.assertEqual(outcomes["TLS 1.0"], "untestable")
        self.assertEqual(outcomes["3DES ciphers"], "untestable")
        self.assertIn("tls-protocols.untestable-probes", self.ids(result))
        self.assertEqual(result.status, "finding")
        self.assertIn("NOT TESTABLE from this toolbox", result.summary)
        self.assertNotIn("rejected: TLS 1.0", result.summary)
        self.assertIn("TLS 1.0", result.detail["notTestable"])
        evidence = " ".join(item["detail"] for finding in result.findings for item in finding["evidence"])
        self.assertIn("not testable from this toolbox", evidence)
        # nothing was sent for them: 9 probes minus every untestable one
        untestable = sum(1 for value in outcomes.values() if value == "untestable")
        self.assertEqual(result.requests_sent, 9 - untestable)


if __name__ == "__main__":
    unittest.main()
