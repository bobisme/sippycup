"""Implementations of the runnable checks in :mod:`sippycup_checks.catalog`.

Each function receives a :class:`Context` (with the hard request budget
already opened for that check) and returns a :class:`CheckResult`. Evidence
quotes only non-secret protocol facts: status lines, header names, Server
values, cipher names, truncated nonces. No credential or full nonce is ever
recorded.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from . import catalog
from . import sip
from . import tlsprobe
from .budget import Budget
from .sip import Channel, ChannelError, Endpoint, Response

RISKY_METHODS = ("REFER", "MESSAGE", "SUBSCRIBE", "PUBLISH", "UPDATE")
_VERSION = re.compile(r"(?<![A-Za-z0-9])v?\d+(?:\.\d+)+(?:[-.][A-Za-z0-9]+)*")
MAX_QUOTE = 160

# Stop reasons that --continue-after-finding may override (a finding, not a fault).
FINDING_STOPS = {"unauthenticated INVITE progressed", "unauthenticated REGISTER accepted"}


@dataclass
class Context:
    endpoint: Endpoint
    section: dict[str, Any]
    budget: Budget
    password: str | None = None
    timeout: float = 4.0
    invite_timeout: float = 8.0
    openssl: str | None = None
    now: Callable[[], datetime] = datetime.now
    monotonic: Callable[[], float] = tlsprobe.monotonic
    shared: dict[str, Any] = field(default_factory=dict)
    transcript: list[dict[str, Any]] = field(default_factory=list)

    def channel(self, endpoint: Endpoint | None = None) -> Channel:
        return Channel(endpoint or self.endpoint, self.budget, timeout=self.timeout, monotonic=self.monotonic)

    def note(self, check: str, event: str, **values: Any) -> None:
        self.transcript.append({"check": check, "event": event, **values})


@dataclass
class CheckResult:
    id: str
    status: str
    summary: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)
    stop: str | None = None
    requests_sent: int = 0


def quote(value: str | None) -> str:
    text = (value or "").replace("\r", " ").replace("\n", " ")
    return text if len(text) <= MAX_QUOTE else text[:MAX_QUOTE] + "..."


def finding(
    finding_id: str,
    summary: str,
    evidence: list[dict[str, Any]],
    *,
    confidence: str = "high",
    severity: str | None = None,
) -> dict[str, Any]:
    spec = catalog.finding_spec(finding_id)
    return {
        "id": finding_id,
        "checkId": finding_id.split(".", 1)[0],
        "title": spec.title,
        "severity": severity or spec.severity,
        "confidence": confidence,
        "summary": summary,
        "evidence": evidence,
        "remediation": spec.remediation,
        "references": list(spec.references),
    }


def ev(kind: str, detail: str, artifact: str | None = None) -> dict[str, Any]:
    item: dict[str, Any] = {"kind": kind, "detail": quote(detail)}
    if artifact:
        item["artifact"] = artifact
    return item


def _response_note(ctx: Context, check: str, response: Response | None, label: str) -> None:
    if response is None:
        ctx.note(check, "no-response", request=label)
        return
    ctx.note(check, "response", request=label, status=response.status_line,
             headers=response.header_names(), elapsedMs=response.elapsed_ms)


def _error(check: str, summary: str, *, stop: str | None = None) -> CheckResult:
    return CheckResult(check, "error", summary, stop=stop)


def _options_once(ctx: Context, check: str, endpoint: Endpoint | None = None) -> tuple[Response | None, str | None]:
    """One OPTIONS, no retransmission. Returns (final response, problem)."""
    try:
        with ctx.channel(endpoint) as channel:
            exchange = sip.transact(channel, sip.options_request(channel.endpoint), timeout=ctx.timeout)
    except ChannelError as error:
        return None, error.category
    _response_note(ctx, check, exchange.final, "OPTIONS")
    if exchange.final is None:
        return None, "no final response before the deadline"
    return exchange.final, None


# -- passive ----------------------------------------------------------------------

def banner_disclosure(ctx: Context) -> CheckResult:
    check = "banner-disclosure"
    response, problem = _options_once(ctx, check)
    if response is None:
        return _error(check, f"OPTIONS got no usable answer ({problem}); nothing concluded")
    banners = [(name, value) for name in ("server", "user-agent") for value in response.all(name) if value.strip()]
    evidence = [ev("status-line", response.status_line)]
    evidence.extend(ev("header", f"{'Server' if name == 'server' else 'User-Agent'}: {value}") for name, value in banners)
    detail = {"status": response.code, "banners": [quote(value) for _, value in banners]}
    if not banners:
        return CheckResult(check, "passed", f"OPTIONS answered {response.code}; no Server or User-Agent header", detail=detail)
    versioned = [value for _, value in banners if _VERSION.search(value)]
    if versioned:
        result = finding("banner-disclosure.version",
                         f"The edge announces a product and version: {quote(versioned[0])}.", evidence)
        return CheckResult(check, "finding", f"version disclosed: {quote(versioned[0])}", [result], detail)
    result = finding("banner-disclosure.product",
                     f"The edge announces a product name without a version: {quote(banners[0][1])}.", evidence)
    return CheckResult(check, "finding", f"product named without a version: {quote(banners[0][1])}", [result], detail)


def options_methods(ctx: Context) -> CheckResult:
    check = "options-methods"
    response, problem = _options_once(ctx, check)
    if response is None:
        return _error(check, f"OPTIONS got no usable answer ({problem}); nothing concluded")

    def tokens(name: str) -> list[str]:
        items: list[str] = []
        for value in response.all(name):
            items.extend(part.strip() for part in value.split(",") if part.strip())
        return items

    allow = [item.upper() for item in tokens("allow")]
    supported = tokens("supported")
    detail = {"status": response.code, "allow": allow, "supported": supported}
    if not allow:
        return CheckResult(check, "passed",
                           f"OPTIONS answered {response.code} without an Allow header; nothing advertised",
                           detail=detail)
    extra = [item for item in RISKY_METHODS if item in allow]
    summary = f"Allow: {', '.join(allow)}" + (f"; Supported: {', '.join(supported)}" if supported else "")
    if not extra:
        return CheckResult(check, "passed", quote(summary), detail=detail)
    evidence = [ev("status-line", response.status_line), ev("header", "Allow: " + ", ".join(allow))]
    if supported:
        evidence.append(ev("header", "Supported: " + ", ".join(supported)))
    result = finding(
        "options-methods.extra-methods",
        f"The edge advertises {', '.join(extra)} out of dialog. This is an inventory only; whether "
        "they work without authentication was NOT tested.",
        evidence,
    )
    return CheckResult(check, "finding", f"advertises {', '.join(extra)} (inventory only, not tested)",
                       [result], detail)


def tls_certificate(ctx: Context) -> CheckResult:
    check = "tls-certificate"
    endpoint = ctx.endpoint
    if not ctx.openssl:
        return CheckResult(check, "skipped", "the openssl CLI is not available to parse the certificate; nothing sent")
    literal = endpoint.address
    name = endpoint.server_name or literal
    is_ip = endpoint.server_name is None
    verified, der = tlsprobe.handshake(endpoint, tlsprobe.verified_context(endpoint), label="verified",
                                       budget=ctx.budget, timeout=ctx.timeout)
    ctx.note(check, "handshake", probe=verified.as_dict())
    if verified.outcome in ("unreachable", "timeout"):
        return _error(check, f"TLS port did not complete a handshake ({verified.outcome}); nothing concluded")
    if verified.outcome == "rejected":
        return _error(check, f"verified handshake failed before certificate checks: {verified.detail}")
    findings: list[dict[str, Any]] = []
    verification_failed = verified.outcome == "verify_failed"
    if verification_failed:
        second, der = tlsprobe.handshake(endpoint, tlsprobe.unverified_context(), label="read certificate",
                                         budget=ctx.budget, timeout=ctx.timeout)
        ctx.note(check, "handshake", probe=second.as_dict())
        if der is None:
            return _error(check, f"certificate verification failed ({verified.detail}) and the certificate could not be read")
    assert der is not None
    try:
        facts = tlsprobe.parse_certificate(der, ctx.openssl)
    except (ValueError, OSError) as error:
        return _error(check, f"certificate could not be parsed: {error}")
    now = ctx.now()
    days = tlsprobe.days_left(facts, now)
    covers = tlsprobe.san_covers(facts, name, is_ip=is_ip)
    detail = {"verified": not verification_failed, "verifyName": name, "certificate": facts,
              "daysLeft": None if days is None else round(days, 2), "tlsVersion": verified.version}
    base = [
        ev("certificate", f"subject {facts.get('subject')}; issuer {facts.get('issuer')}"),
        ev("certificate", f"valid until {facts.get('notAfter')}"),
    ]
    hostname_failure = verification_failed and "hostname" in (verified.detail or "").lower()
    if verification_failed and not hostname_failure:
        findings.append(finding("tls-certificate.untrusted",
                                f"The chain does not verify for {name}: {verified.detail}.",
                                base + [ev("verification", verified.detail or "failed")]))
    if not covers or hostname_failure:
        findings.append(finding("tls-certificate.name-mismatch",
                                f"The certificate's subjectAltName does not cover {name}.",
                                base + [ev("subjectAltName", ", ".join(facts.get("subjectAltName") or []) or "none")]))
    if not facts.get("subjectAltName"):
        findings.append(finding("tls-certificate.no-san", "The certificate has no subjectAltName extension.", base))
    if (days is not None and days <= 0) or tlsprobe.not_yet_valid(facts, now):
        findings.append(finding("tls-certificate.expired",
                                f"The certificate is outside its validity period (notBefore {facts.get('notBefore')}, notAfter {facts.get('notAfter')}).",
                                base))
    elif days is not None and days <= 30:
        findings.append(finding("tls-certificate.expiring",
                                f"The certificate expires in {days:.1f} days ({facts.get('notAfter')}).",
                                base, severity="medium" if days <= 14 else "low"))
    if tlsprobe.weak_key(facts):
        findings.append(finding("tls-certificate.weak-key",
                                f"The certificate key is {facts.get('keyAlgorithm')} {facts.get('keyBits')} bits.",
                                [ev("key", f"{facts.get('keyAlgorithm')} {facts.get('keyBits')} bits")]))
    if tlsprobe.weak_signature(facts):
        findings.append(finding("tls-certificate.weak-signature",
                                f"The certificate is signed with {facts.get('signatureAlgorithm')}.",
                                [ev("signature", str(facts.get("signatureAlgorithm")))]))
    if tlsprobe.self_signed(facts):
        findings.append(finding("tls-certificate.self-signed", "The leaf certificate is self-signed.", base))
    key = f"{facts.get('keyAlgorithm')} {facts.get('keyBits')} bits"
    summary = (
        f"{'verified' if not verification_failed else 'NOT verified'} for {name}; "
        f"{'expires in %.1f days' % days if days is not None else 'expiry unknown'}; {key}; "
        f"{facts.get('signatureAlgorithm')}"
    )
    return CheckResult(check, "finding" if findings else "passed", summary, findings, detail)


def tls_protocols(ctx: Context) -> CheckResult:
    check = "tls-protocols"
    results: list[tlsprobe.ProbeResult] = []
    for label, minimum, maximum, ciphers in tlsprobe.PROTOCOL_PROBES:
        context = tlsprobe.probe_context(minimum, maximum, ciphers)
        if isinstance(context, str):
            results.append(tlsprobe.ProbeResult(label, "untestable", detail=context))
            continue
        result, _ = tlsprobe.handshake(ctx.endpoint, context, label=label, budget=ctx.budget, timeout=ctx.timeout)
        results.append(result)
    for label, ciphers, _klass in tlsprobe.CIPHER_PROBES:
        context = tlsprobe.probe_context(tlsprobe.V.TLSv1, tlsprobe.V.TLSv1_2, ciphers)
        if isinstance(context, str):
            results.append(tlsprobe.ProbeResult(f"{label} ciphers", "untestable", detail=context))
            continue
        result, _ = tlsprobe.handshake(ctx.endpoint, context, label=f"{label} ciphers",
                                       budget=ctx.budget, timeout=ctx.timeout)
        results.append(result)
    for item in results:
        ctx.note(check, "probe", probe=item.as_dict())
    by_label = {item.label: item for item in results}
    unreachable = [item.label for item in results if item.outcome == "unreachable"]
    if unreachable and len(unreachable) == len([item for item in results if item.outcome != "untestable"]):
        return CheckResult(check, "error", "the TLS port refused every probe connection; nothing concluded",
                           detail={"probes": [item.as_dict() for item in results]})
    findings: list[dict[str, Any]] = []
    deprecated = [label for label in ("TLS 1.0", "TLS 1.1") if by_label[label].outcome == "accepted"]
    if deprecated:
        findings.append(finding("tls-protocols.deprecated-version",
                                f"The edge completed handshakes with {', '.join(deprecated)}.",
                                [ev("handshake", f"{label} accepted, cipher {by_label[label].cipher}") for label in deprecated]))
    for klass, finding_id in (("broken", "tls-protocols.broken-cipher"), ("weak", "tls-protocols.weak-cipher")):
        accepted = [
            by_label[f"{label} ciphers"] for label, _c, k in tlsprobe.CIPHER_PROBES
            if k == klass and by_label[f"{label} ciphers"].outcome == "accepted"
        ]
        if accepted:
            findings.append(finding(finding_id,
                                    "The edge accepted " + ", ".join(f"{item.cipher} ({item.version})" for item in accepted) + ".",
                                    [ev("handshake", f"{item.label}: {item.cipher} with {item.version}") for item in accepted]))
    if by_label["TLS 1.3"].outcome == "rejected":
        findings.append(finding("tls-protocols.no-tls13", "The edge rejected a TLS 1.3-only handshake.",
                                [ev("handshake", f"TLS 1.3 rejected: {by_label['TLS 1.3'].detail}")]))
    accepted = [item.label for item in results if item.outcome == "accepted"]
    untestable = [item.label for item in results if item.outcome == "untestable"]
    inconclusive = [item.label for item in results if item.outcome in ("timeout", "unreachable", "verify_failed")]
    summary = f"accepted: {', '.join(accepted) or 'none'}"
    if untestable:
        summary += f"; not offered locally (not sent): {', '.join(untestable)}"
    if inconclusive:
        summary += f"; inconclusive: {', '.join(inconclusive)}"
    return CheckResult(check, "finding" if findings else "passed", summary, findings,
                       {"probes": [item.as_dict() for item in results]})


def cleartext_signaling(ctx: Context) -> CheckResult:
    check = "cleartext-signaling"
    answered: list[str] = []
    outcomes: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for item in catalog.cleartext_endpoints(ctx.section):
        endpoint = Endpoint(ctx.endpoint.address, item["port"], item["transport"], domain=ctx.endpoint.address)
        label = f"{item['transport'].upper()} {item['port']}"
        response, problem = _options_once(ctx, check, endpoint)
        if response is not None:
            answered.append(label)
            evidence.append(ev("status-line", f"{label}: {response.status_line}"))
            outcomes.append({"endpoint": label, "status": response.code})
        else:
            outcomes.append({"endpoint": label, "status": None, "problem": problem})
    detail = {"endpoints": outcomes}
    if answered:
        result = finding("cleartext-signaling.answered",
                         f"{ctx.endpoint.address} also answers SIP in cleartext on {', '.join(answered)}.", evidence)
        return CheckResult(check, "finding", f"cleartext SIP answered on {', '.join(answered)}", [result], detail)
    return CheckResult(check, "passed",
                       "no approved cleartext endpoint answered: " + "; ".join(
                           f"{entry['endpoint']} {entry.get('problem')}" for entry in outcomes),
                       detail=detail)


# -- active -----------------------------------------------------------------------

def _unexpected_server_error(code: int) -> bool:
    return code >= 500 and code != 501


def _register_query(ctx: Context, check: str, user: str) -> tuple[Response | None, str | None]:
    try:
        with ctx.channel() as channel:
            exchange = sip.transact(channel, sip.register_query(user, ctx.endpoint), timeout=ctx.timeout)
    except ChannelError as error:
        return None, error.category
    _response_note(ctx, check, exchange.final, "REGISTER query")
    if exchange.final is None:
        return None, "no final response before the deadline"
    return exchange.final, None


def unauthenticated_register(ctx: Context) -> CheckResult:
    check = "unauthenticated-register"
    account = ctx.section["account"]
    response, problem = _register_query(ctx, check, account)
    if response is None:
        return _error(check, f"REGISTER query got no usable answer ({problem}); nothing concluded")
    detail = {"status": response.code, "headers": response.header_names()}
    if 200 <= response.code < 300:
        result = finding(
            "unauthenticated-register.accepted",
            f"A REGISTER binding query for {account} without credentials was answered {response.code}. "
            "The query had no Contact, so no binding changed.",
            [ev("status-line", response.status_line),
             ev("header", f"Contact bindings returned: {len(response.all('contact'))}")],
        )
        return CheckResult(check, "finding", f"accepted without credentials ({response.status_line})",
                           [result], detail, stop="unauthenticated REGISTER accepted")
    if response.code in (401, 407):
        ctx.shared["register_challenge"] = response
        return CheckResult(check, "passed", f"challenged: {response.status_line}", detail=detail)
    if _unexpected_server_error(response.code):
        return CheckResult(check, "error", f"unexpected server error {response.status_line}; stopping",
                           detail=detail, stop=f"server error {response.code}")
    return CheckResult(check, "passed", f"not accepted: {response.status_line} (no challenge)", detail=detail)


def _nonce_assessment(nonce: str) -> tuple[bool, str]:
    distinct = len(set(nonce))
    weak = len(nonce) < 16 or distinct < 8
    return weak, f"nonce length {len(nonce)}, {distinct} distinct characters, starts {sip.truncate(nonce)}"


def digest_quality(ctx: Context) -> CheckResult:
    check = "digest-quality"
    response = ctx.shared.get("register_challenge")
    reused = response is not None
    if response is None:
        response, problem = _register_query(ctx, check, ctx.section["account"])
        if response is None:
            return _error(check, f"REGISTER query got no usable answer ({problem}); nothing concluded")
    if response.code not in (401, 407):
        if _unexpected_server_error(response.code):
            return CheckResult(check, "error", f"unexpected server error {response.status_line}; stopping",
                               stop=f"server error {response.code}")
        return CheckResult(check, "skipped", f"no challenge to review ({response.status_line})")
    items = sip.challenges(response)
    if not items:
        return CheckResult(check, "skipped", f"{response.status_line} carried no Digest challenge")
    algorithms = sorted({sip.algorithm_of(item) for item in items})
    qops = sorted({part.strip() for item in items for part in item.get("qop", "").split(",") if part.strip()})
    realms = sorted({item.get("realm", "") for item in items})
    chosen = sip.strongest(items) or items[0]
    nonce = chosen.get("nonce", "")
    weak_nonce, nonce_text = _nonce_assessment(nonce)
    base = [ev("status-line", response.status_line),
            ev("challenge", f"algorithms {', '.join(algorithms)}; qop {', '.join(qops) or 'absent'}; realm {', '.join(realms)}")]
    findings: list[dict[str, Any]] = []
    if all(sip._base_algorithm(name) == "MD5" for name in algorithms):
        findings.append(finding("digest-quality.md5-only", "Every Digest challenge offers only MD5.", base))
    if not qops:
        findings.append(finding("digest-quality.no-qop", "The Digest challenge has no qop parameter.", base))
    if weak_nonce:
        findings.append(finding("digest-quality.weak-nonce", f"The nonce looks short or low-variety: {nonce_text}.",
                                base + [ev("nonce", nonce_text)], confidence="low"))
    internal = [realm for realm in realms if sip.is_internal_realm(realm)]
    if internal:
        findings.append(finding("digest-quality.internal-realm",
                                f"The realm names an internal host or address: {', '.join(internal)}.", base))
    if any(item.get("stale", "").lower() == "true" for item in items):
        findings.append(finding("digest-quality.stale-initial", "The first challenge is marked stale=true.", base))
    detail = {"reusedChallenge": reused, "algorithms": algorithms, "qop": qops, "realms": realms,
              "nonce": {"length": len(nonce), "distinct": len(set(nonce)), "prefix": sip.truncate(nonce)},
              "opaque": "opaque" in chosen}
    summary = (f"{'reused the earlier challenge' if reused else 'one REGISTER query'}: algorithms "
               f"{', '.join(algorithms)}; qop {', '.join(qops) or 'absent'}; {nonce_text}")
    return CheckResult(check, "finding" if findings else "passed", summary, findings, detail)


def _invite(ctx: Context, check: str, from_user: str, label: str) -> tuple[sip.InviteOutcome | None, str | None]:
    try:
        with ctx.channel() as channel:
            outcome = sip.invite(channel, from_user=from_user, from_display=None,
                                 destination=ctx.section["destination"],
                                 invite_timeout=ctx.invite_timeout, cleanup_timeout=ctx.timeout)
    except ChannelError as error:
        return None, error.category
    ctx.note(check, "invite", request=label, provisional=outcome.provisional,
             status=outcome.final.status_line if outcome.final else None,
             headers=outcome.final.header_names() if outcome.final else None,
             steps=outcome.steps, cleanupOk=outcome.cleanup_ok)
    return outcome, None


def _invite_evidence(outcome: sip.InviteOutcome) -> list[dict[str, Any]]:
    items = [ev("provisional", ", ".join(str(code) for code in outcome.provisional) or "none")]
    if outcome.final is not None:
        items.append(ev("status-line", outcome.final.status_line))
    items.append(ev("cleanup", " -> ".join(outcome.steps)))
    return items


def unauthenticated_invite(ctx: Context) -> CheckResult:
    check = "unauthenticated-invite"
    outcome, problem = _invite(ctx, check, "anonymous", "anonymous INVITE")
    if outcome is None:
        return _error(check, f"INVITE could not be sent or answered ({problem}); nothing concluded")
    detail = {"provisional": outcome.provisional, "final": outcome.final_code, "steps": outcome.steps,
              "cleanupOk": outcome.cleanup_ok}
    if not outcome.cleanup_ok:
        return CheckResult(check, "error", f"cleanup not confirmed: {outcome.cleanup_detail}; stopping",
                           [finding("unauthenticated-invite.progressed",
                                    "An unauthenticated INVITE progressed and its cleanup was not confirmed.",
                                    _invite_evidence(outcome))] if outcome.progressed else [],
                           detail, stop="INVITE cleanup not confirmed")
    if outcome.progressed:
        what = "answered" if outcome.answered else "rang"
        result = finding(
            "unauthenticated-invite.progressed",
            f"An INVITE without credentials to {ctx.section['destination']} {what} "
            f"({', '.join(str(code) for code in outcome.provisional)}{'; final ' + str(outcome.final_code) if outcome.final_code else ''}). "
            "It was ended at once; no media was sent.",
            _invite_evidence(outcome),
        )
        return CheckResult(check, "finding", f"{what} without credentials; ended with {' -> '.join(outcome.steps)}",
                           [result], detail, stop="unauthenticated INVITE progressed")
    if outcome.final is None:
        return _error(check, "no final response to the INVITE before the deadline; nothing concluded")
    if _unexpected_server_error(outcome.final.code):
        return CheckResult(check, "error", f"unexpected server error {outcome.final.status_line}; stopping",
                           detail=detail, stop=f"server error {outcome.final.code}")
    ctx.shared["invite_challenge"] = outcome.final
    kind = "challenged" if outcome.final.code in (401, 407) else "rejected"
    return CheckResult(check, "passed", f"{kind}: {outcome.final.status_line}; ACKed", detail=detail)


def random_user() -> str:
    """One syntactically valid user name that cannot plausibly exist."""
    return "sc" + secrets.token_hex(6)


def _signature(response: Response | None) -> dict[str, Any]:
    if response is None:
        return {"status": None}
    realms = sorted({item.get("realm", "") for item in sip.challenges(response)}) if response.code in (401, 407) else []
    return {"status": response.code, "headers": response.header_names(), "realms": realms}


def _differences(first: dict[str, Any], second: dict[str, Any]) -> list[str]:
    found = []
    if first.get("status") != second.get("status"):
        found.append(f"status {first.get('status')} vs {second.get('status')}")
    if first.get("headers") != second.get("headers"):
        only_first = sorted(set(first.get("headers") or []) - set(second.get("headers") or []))
        only_second = sorted(set(second.get("headers") or []) - set(first.get("headers") or []))
        found.append(f"header names only for the account: {', '.join(only_first) or 'none'}; "
                     f"only for the random user: {', '.join(only_second) or 'none'}")
    if first.get("realms") != second.get("realms"):
        found.append(f"realm {first.get('realms') or 'absent'} vs {second.get('realms') or 'absent'}")
    return found


def user_enumeration(ctx: Context) -> CheckResult:
    check = "user-enumeration"
    account = ctx.section["account"]
    other = random_user()
    comparisons: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    timings: list[str] = []
    stop: str | None = None
    first, problem_first = _register_query(ctx, check, account)
    second, problem_second = _register_query(ctx, check, other)
    if first is None or second is None:
        return _error(check, f"REGISTER comparison incomplete ({problem_first or problem_second}); nothing concluded")
    a, b = _signature(first), _signature(second)
    diffs = _differences(a, b)
    comparisons.append({"method": "REGISTER", "account": a, "random": b, "differences": diffs,
                        "elapsedMs": [first.elapsed_ms, second.elapsed_ms]})
    timings.append(f"REGISTER {first.elapsed_ms:.1f} ms vs {second.elapsed_ms:.1f} ms")
    for item in diffs:
        evidence.append(ev("differential", f"REGISTER: {item}"))
    if ctx.section.get("destination"):
        one, p1 = _invite(ctx, check, account, "INVITE from the account")
        if one is not None and (one.progressed or not one.cleanup_ok):
            stop = "unauthenticated INVITE progressed" if one.cleanup_ok else "INVITE cleanup not confirmed"
            findings.append(finding("user-enumeration.invite-progressed",
                                    "An unauthenticated INVITE claiming the reviewed account progressed; it was ended at once.",
                                    _invite_evidence(one)))
            return CheckResult(check, "finding" if one.cleanup_ok else "error",
                               "INVITE progressed without credentials; comparison stopped", findings,
                               {"comparisons": comparisons, "randomUser": other}, stop=stop)
        two, p2 = (None, None)
        if one is not None:
            two, p2 = _invite(ctx, check, other, "INVITE from the random user")
        if two is not None and (two.progressed or not two.cleanup_ok):
            stop = "unauthenticated INVITE progressed" if two.cleanup_ok else "INVITE cleanup not confirmed"
            findings.append(finding("user-enumeration.invite-progressed",
                                    "An unauthenticated INVITE from a random identity progressed; it was ended at once.",
                                    _invite_evidence(two)))
            return CheckResult(check, "finding" if two.cleanup_ok else "error",
                               "INVITE progressed without credentials; comparison stopped", findings,
                               {"comparisons": comparisons, "randomUser": other}, stop=stop)
        if one is None or two is None or one.final is None or two.final is None:
            return _error(check, f"INVITE comparison incomplete ({p1 or p2 or 'no final response'}); nothing concluded")
        a, b = _signature(one.final), _signature(two.final)
        diffs = _differences(a, b)
        comparisons.append({"method": "INVITE", "account": a, "random": b, "differences": diffs,
                            "elapsedMs": [one.final.elapsed_ms, two.final.elapsed_ms]})
        timings.append(f"INVITE {one.final.elapsed_ms:.1f} ms vs {two.final.elapsed_ms:.1f} ms")
        for item in diffs:
            evidence.append(ev("differential", f"INVITE: {item}"))
    detail = {"comparisons": comparisons, "randomUser": other,
              "timing": "measured values only; no claim is made from timing"}
    methods = "/".join(item["method"] for item in comparisons)
    timing_text = "timing (account vs random, not a claim): " + "; ".join(timings)
    if evidence:
        findings.append(finding(
            "user-enumeration.differential",
            f"A single differential ({methods}) between the reviewed account and one random name shows "
            "different answers. This is one comparison, not a scan.",
            evidence, confidence="medium"))
        return CheckResult(check, "finding", f"answers differ ({methods}); {timing_text}", findings, detail)
    return CheckResult(check, "passed", f"identical answers for the account and one random name ({methods}); {timing_text}",
                       detail=detail)


def nonce_replay(ctx: Context) -> CheckResult:
    check = "nonce-replay"
    account = ctx.section["account"]
    if not ctx.password:
        return CheckResult(check, "skipped", "no password source given (--secret-env or --secret-file); nothing sent")
    endpoint = ctx.endpoint
    call_id = sip.token(12) + "@sippycup-checks"
    from_tag = sip.token(6)
    try:
        with ctx.channel() as channel:
            query = sip.register_query(account, endpoint, call_id=call_id, from_tag=from_tag, cseq=1)
            first = sip.transact(channel, query, timeout=ctx.timeout)
            _response_note(ctx, check, first.final, "REGISTER query")
            if first.final is None:
                return _error(check, "REGISTER query got no final response; nothing concluded")
            if first.final.code not in (401, 407):
                if 200 <= first.final.code < 300:
                    return CheckResult(check, "skipped", "the target did not challenge (see unauthenticated-register); no credentials sent")
                return _error(check, f"expected a challenge, got {first.final.status_line}; no credentials sent")
            chosen = sip.strongest(sip.challenges(first.final))
            if chosen is None:
                return CheckResult(check, "skipped", "no supported Digest algorithm was offered; no credentials sent")
            header = sip.authorization(chosen, username=account, password=ctx.password,
                                       method="REGISTER", uri=query.uri)
            signed = sip.register_query(account, endpoint, call_id=call_id, from_tag=from_tag, cseq=2,
                                        authorization=header)
            second = sip.transact(channel, signed, timeout=ctx.timeout, what="REGISTER (authenticated)")
            _response_note(ctx, check, second.final, "REGISTER query (authenticated)")
            if second.final is None or not 200 <= second.final.code < 300:
                status = second.final.status_line if second.final else "no response"
                return _error(check, f"the reviewed credentials were not accepted ({status}); replay not attempted, nothing retried")
            replay = sip.register_query(account, endpoint, call_id=call_id, from_tag=from_tag, cseq=3,
                                        authorization=header)
            third = sip.transact(channel, replay, timeout=ctx.timeout, what="REGISTER (replayed Authorization)")
            _response_note(ctx, check, third.final, "REGISTER query (replayed Authorization)")
    except ChannelError as error:
        return _error(check, f"connection problem ({error.category}); nothing concluded")
    nonce = chosen.get("nonce", "")
    evidence = [
        ev("challenge", f"algorithm {sip.algorithm_of(chosen)}, qop {chosen.get('qop', 'absent')}, nonce {sip.truncate(nonce)}"),
        ev("status-line", f"authenticated: {second.final.status_line}"),
    ]
    detail = {"algorithm": sip.algorithm_of(chosen), "nc": "00000001", "noncePrefix": sip.truncate(nonce),
              "authenticated": second.final.code,
              "replay": third.final.code if third.final else None}
    if third.final is None:
        return _error(check, "the replay got no final response; nothing concluded")
    evidence.append(ev("status-line", f"replayed (same nonce, nc=00000001): {third.final.status_line}"))
    if 200 <= third.final.code < 300:
        result = finding("nonce-replay.accepted",
                         "The same Authorization header (same nonce and nonce count) was accepted a second time.",
                         evidence)
        return CheckResult(check, "finding", f"replay accepted ({third.final.status_line})", [result], detail)
    stale = any(item.get("stale", "").lower() == "true" for item in sip.challenges(third.final)) \
        if third.final.code in (401, 407) else False
    return CheckResult(check, "passed",
                       f"replay rejected: {third.final.status_line}{' (stale=true)' if stale else ''}", detail=detail)


IMPLEMENTATIONS: dict[str, Callable[[Context], CheckResult]] = {
    "banner-disclosure": banner_disclosure,
    "options-methods": options_methods,
    "tls-certificate": tls_certificate,
    "tls-protocols": tls_protocols,
    "cleartext-signaling": cleartext_signaling,
    "unauthenticated-register": unauthenticated_register,
    "digest-quality": digest_quality,
    "unauthenticated-invite": unauthenticated_invite,
    "user-enumeration": user_enumeration,
    "nonce-replay": nonce_replay,
}
