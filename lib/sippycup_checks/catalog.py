"""The reviewed catalog of security posture checks, and profile validation.

Everything in this module is offline data and validation: it never opens a
socket. Each check declares an exact upper bound on what it may send; the
transport layer (:mod:`sippycup_checks.budget`) aborts a check that tries to
send more, so the bound is enforced, not advisory.

A *request* is one SIP request message (OPTIONS, REGISTER, INVITE, and the
ACK, CANCEL, or BYE that correctly ends an INVITE transaction or dialog) or
one TCP connection made only for a TLS handshake probe. Over TCP or TLS the
connection attempt is counted as the first request it carries, so a refused
or unverified connection that never carried SIP still counts.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("info", "low", "medium", "high")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
IMPACTS = ("passive", "active")
STATES = ("runnable", "planned")
NEEDS = ("tls", "account", "password", "destination", "cleartext_endpoints", "srtp")
MAX_REQUESTS_CEILING = 200
MAX_CLEARTEXT_ENDPOINTS = 8
CATALOG_VERSION = "sippycup.dev/checks-catalog/v1"

_ACCOUNT = re.compile(r"^[A-Za-z0-9._+-]{1,64}$")
_DESTINATION = re.compile(r"^[A-Za-z0-9._+*#-]{1,64}$")
_PLACEHOLDERS = {
    "changeme", "change-me", "change_me", "todo", "tbd", "placeholder", "example",
    "xxx", "check-id", "id", "user", "username", "account", "destination",
}


@dataclass(frozen=True)
class FindingSpec:
    id: str
    title: str
    severity: str
    remediation: str
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class CheckSpec:
    id: str
    title: str
    impact: str
    sends: str
    max_requests: int
    transports: tuple[str, ...]
    needs: tuple[str, ...]
    rationale: str
    owner_text: str
    findings: tuple[FindingSpec, ...]
    references: tuple[str, ...] = ()
    state: str = "runnable"
    per_endpoint: bool = False
    invites: int = 0
    notes: tuple[str, ...] = field(default_factory=tuple)

    def finding(self, finding_id: str) -> FindingSpec:
        for item in self.findings:
            if item.id == finding_id:
                return item
        raise KeyError(finding_id)


_SERVER_REFS = ("RFC 3261 section 20.35 (Server)", "RFC 3261 section 20.41 (User-Agent)", "CWE-200")
_DIGEST_REFS = ("RFC 3261 section 22", "RFC 7616", "RFC 8760")

CHECKS: tuple[CheckSpec, ...] = (
    CheckSpec(
        id="banner-disclosure",
        title="Server and User-Agent banner disclosure",
        impact="passive",
        sends="1 SIP OPTIONS request to the target address over the profile's transport; no retransmission",
        max_requests=1,
        transports=("udp", "tcp", "tls"),
        needs=(),
        rationale=(
            "A Server or User-Agent header naming the product and its exact version lets anyone "
            "who can reach the edge match it against published vulnerabilities without any further "
            "probing. RFC 3261 recommends making the header configurable for this reason."
        ),
        owner_text=(
            "We send one ordinary SIP OPTIONS request (the same 'are you there' message phones "
            "send) and read which product name and version your edge announces."
        ),
        findings=(
            FindingSpec(
                "banner-disclosure.version",
                "Edge announces its product and version",
                "low",
                "Remove the version from the Server/User-Agent header (or remove the header): in "
                "Asterisk set user_agent in pjsip.conf [global]; in Kamailio set server_header / "
                "user_agent_header; in FreeSWITCH set user-agent-string.",
                _SERVER_REFS + ("CWE-497",),
            ),
            FindingSpec(
                "banner-disclosure.product",
                "Edge announces its product name",
                "info",
                "Consider a neutral Server/User-Agent value that does not name the product.",
                _SERVER_REFS,
            ),
        ),
        references=_SERVER_REFS,
    ),
    CheckSpec(
        id="options-methods",
        title="Advertised SIP methods and extensions",
        impact="passive",
        sends="1 SIP OPTIONS request to the target address over the profile's transport; no retransmission",
        max_requests=1,
        transports=("udp", "tcp", "tls"),
        needs=(),
        rationale=(
            "The Allow and Supported headers advertise which methods and extensions the edge "
            "accepts. Methods beyond basic calling (REFER, MESSAGE, SUBSCRIBE, PUBLISH, UPDATE) "
            "widen the attack surface (call transfer abuse, messaging spam, presence leaks). This "
            "check is an inventory only: it does NOT test whether those methods work without "
            "authentication, so it never claims they do."
        ),
        owner_text=(
            "From the same kind of OPTIONS request we list which SIP features (transfer, "
            "messaging, presence) your edge says it supports. We do not try any of them."
        ),
        findings=(
            FindingSpec(
                "options-methods.extra-methods",
                "Edge advertises methods beyond basic calling",
                "info",
                "Disable the methods the service does not need at the edge (for example REFER, "
                "MESSAGE, SUBSCRIBE, PUBLISH) and make sure every advertised method requires "
                "authentication. Verify exposure with a separately approved test.",
                ("RFC 3261 section 20.5 (Allow)", "RFC 3261 section 20.37 (Supported)",
                 "RFC 3515 (REFER)", "RFC 3428 (MESSAGE)", "RFC 6665 (SUBSCRIBE)"),
            ),
        ),
        references=("RFC 3261 section 11", "RFC 3261 section 20.5"),
    ),
    CheckSpec(
        id="tls-certificate",
        title="TLS certificate for the reviewed server name",
        impact="passive",
        sends=(
            "1 TLS handshake verifying the reviewed server name against the reviewed trust anchor; "
            "only if that fails, 1 more unverified handshake to read the certificate. No SIP is sent"
        ),
        max_requests=2,
        transports=("tls",),
        needs=("tls",),
        rationale=(
            "Clients that cannot verify the edge's certificate either fail or, worse, are "
            "configured to skip verification, which makes signaling interceptable. Expiry, weak "
            "keys, SHA-1/MD5 signatures, self-signed leaves, and names missing from the "
            "subjectAltName are the usual causes."
        ),
        owner_text=(
            "We open one encrypted connection to your TLS port, check the certificate against the "
            "server name and CA you gave us, then close it without sending any SIP."
        ),
        findings=(
            FindingSpec("tls-certificate.untrusted", "Certificate does not verify for the reviewed name",
                        "high",
                        "Serve a certificate chain issued by the CA your clients trust, including "
                        "any intermediates, for the server name clients use.",
                        ("RFC 5922 section 7", "RFC 6125", "CWE-295")),
            FindingSpec("tls-certificate.name-mismatch", "Certificate does not name the reviewed server",
                        "high",
                        "Add the SIP server name to the certificate's subjectAltName (dNSName).",
                        ("RFC 5922 section 7.1", "RFC 6125 section 6", "CWE-297")),
            FindingSpec("tls-certificate.expired", "Certificate is expired or not yet valid", "high",
                        "Renew the certificate and automate renewal.", ("RFC 5280 section 4.1.2.5", "CWE-298")),
            FindingSpec("tls-certificate.expiring", "Certificate expires soon", "medium",
                        "Renew the certificate before it expires (alert at 30 days) and automate renewal.",
                        ("RFC 5280 section 4.1.2.5",)),
            FindingSpec("tls-certificate.weak-key", "Certificate key is too small", "medium",
                        "Use RSA 2048 bits or more, or ECDSA P-256 or stronger.",
                        ("RFC 9325 section 4.1", "CWE-326")),
            FindingSpec("tls-certificate.weak-signature", "Certificate uses a weak signature algorithm",
                        "medium", "Reissue the certificate with a SHA-256 or stronger signature.",
                        ("RFC 9155", "CWE-327")),
            FindingSpec("tls-certificate.self-signed", "Certificate is self-signed", "medium",
                        "Use a certificate issued by a CA the clients trust instead of a self-signed one.",
                        ("RFC 5922 section 7", "CWE-295")),
            FindingSpec("tls-certificate.no-san", "Certificate has no subjectAltName", "low",
                        "Put every server name in the subjectAltName; clients must not rely on the CN.",
                        ("RFC 6125 section 6.4.4", "RFC 5922 section 7.1")),
        ),
        references=("RFC 5922", "RFC 6125", "RFC 5280"),
    ),
    CheckSpec(
        id="tls-protocols",
        title="Deprecated TLS versions and weak cipher suites",
        impact="passive",
        sends=(
            "up to 9 TLS handshakes, each closed right after the handshake: TLS 1.0, 1.1, 1.2, and "
            "1.3 offered one at a time, then NULL, EXPORT, RC4, 3DES, and anonymous cipher suites "
            "offered one family at a time. A probe the local TLS library cannot offer is not sent. "
            "No SIP is sent"
        ),
        max_requests=9,
        transports=("tls",),
        needs=("tls",),
        rationale=(
            "TLS 1.0 and 1.1 are deprecated (RFC 8996) and NULL, EXPORT, RC4, 3DES, and anonymous "
            "suites give no or weak protection. An edge that still accepts them lets a downgrade or "
            "a passive attacker read or alter signaling, including digest exchanges."
        ),
        owner_text=(
            "We open up to nine short encrypted connections to your TLS port, each offering only "
            "one old protocol version or one weak encryption family, and note which ones your edge "
            "accepts. Each connection is closed right after the handshake; no SIP is sent."
        ),
        findings=(
            FindingSpec("tls-protocols.deprecated-version", "Edge accepts deprecated TLS versions",
                        "medium", "Disable TLS 1.0 and 1.1; allow only TLS 1.2 and 1.3.",
                        ("RFC 8996", "RFC 9325 section 3.1.1", "CWE-327")),
            FindingSpec("tls-protocols.broken-cipher", "Edge accepts NULL, EXPORT, or anonymous cipher suites",
                        "high", "Remove NULL, EXPORT, and anonymous (aNULL) suites from the cipher list.",
                        ("RFC 9325 section 4.1", "CWE-327")),
            FindingSpec("tls-protocols.weak-cipher", "Edge accepts RC4 or 3DES cipher suites", "medium",
                        "Remove RC4 and 3DES suites; prefer AEAD suites (AES-GCM, ChaCha20-Poly1305).",
                        ("RFC 7465", "RFC 9325 section 4.1", "CWE-327")),
            FindingSpec("tls-protocols.no-tls13", "Edge does not offer TLS 1.3", "info",
                        "Enable TLS 1.3 alongside TLS 1.2 where the SIP stack supports it.",
                        ("RFC 8446", "RFC 9325 section 3.1.1")),
        ),
        references=("RFC 8996", "RFC 9325", "RFC 7465"),
    ),
    CheckSpec(
        id="cleartext-signaling",
        title="Cleartext SIP alongside TLS",
        impact="passive",
        sends=(
            "1 SIP OPTIONS request to the same literal address per approved cleartext endpoint "
            "(security_checks.cleartext_endpoints, at most 8); no other port is ever probed"
        ),
        max_requests=MAX_CLEARTEXT_ENDPOINTS,
        transports=("udp", "tcp"),
        needs=("tls", "cleartext_endpoints"),
        per_endpoint=True,
        rationale=(
            "When the edge is meant to be reached over TLS but the same address also answers SIP "
            "in cleartext, clients or attackers can fall back to unencrypted signaling and the "
            "TLS protection is optional rather than enforced."
        ),
        owner_text=(
            "Your edge uses TLS. On each cleartext port you list as approved (for example UDP or "
            "TCP 5060) we send one OPTIONS request to see whether the same address also answers "
            "unencrypted SIP. We never touch a port you did not list."
        ),
        findings=(
            FindingSpec("cleartext-signaling.answered", "Same address answers cleartext SIP", "medium",
                        "If TLS is the policy, stop listening for SIP on UDP/TCP at this address or "
                        "reject cleartext requests; otherwise document why both are needed.",
                        ("RFC 3261 section 26.2", "RFC 5630", "CWE-319")),
        ),
        references=("RFC 3261 section 26.2", "RFC 5630"),
    ),
    CheckSpec(
        id="unauthenticated-register",
        title="REGISTER accepted without credentials",
        impact="active",
        sends=(
            "1 REGISTER without credentials and WITHOUT a Contact header for the reviewed account "
            "(a binding query, RFC 3261 section 10.2.3, which changes nothing even if accepted)"
        ),
        max_requests=1,
        transports=("udp", "tcp", "tls"),
        needs=("account",),
        rationale=(
            "If the registrar answers 200 OK to an unauthenticated REGISTER for an account, anyone "
            "can read and, with a Contact, replace that account's bindings and receive its calls. "
            "The query form has no Contact, so even a vulnerable registrar changes nothing."
        ),
        owner_text=(
            "We send one registration request for the account you gave us, without a password "
            "and without asking to be registered (a read-only 'which phones are registered?' "
            "query). We expect your edge to ask for a password."
        ),
        findings=(
            FindingSpec("unauthenticated-register.accepted",
                        "Registrar answers an unauthenticated REGISTER with 200 OK", "high",
                        "Require digest authentication for every REGISTER, including binding queries.",
                        ("RFC 3261 section 10.2.3", "RFC 3261 section 22", "CWE-306")),
        ),
        references=("RFC 3261 section 10.2.3", "RFC 3261 section 22"),
    ),
    CheckSpec(
        id="digest-quality",
        title="Digest challenge quality",
        impact="active",
        sends=(
            "reuses the challenge from unauthenticated-register when it ran; otherwise 1 REGISTER "
            "binding query without credentials and without a Contact. No credentials are sent"
        ),
        max_requests=1,
        transports=("udp", "tcp", "tls"),
        needs=("account",),
        rationale=(
            "The challenge decides how strong the password exchange is: MD5-only digest is weak "
            "against offline guessing of captured exchanges (RFC 8760 adds SHA-256), a missing "
            "qop removes client nonce and counter protection, short or low-variety nonces ease "
            "replay, and a realm naming an internal host leaks topology."
        ),
        owner_text=(
            "From the password challenge your edge already sent (or one more read-only "
            "registration query) we review how strong the challenge is. We never send a password "
            "in this check."
        ),
        findings=(
            FindingSpec("digest-quality.md5-only", "Digest offers only MD5", "low",
                        "Offer SHA-256 (and SHA-512-256) digest challenges alongside or instead of MD5 "
                        "where clients support it; enforce TLS for signaling.",
                        ("RFC 8760", "RFC 7616 section 3.7", "CWE-328")),
            FindingSpec("digest-quality.no-qop", "Digest challenge has no qop", "medium",
                        "Send qop=\"auth\" in every challenge so clients use a client nonce and a "
                        "nonce counter.", ("RFC 7616 section 3.3", "RFC 3261 section 22.4")),
            FindingSpec("digest-quality.weak-nonce", "Digest nonce looks short or low-variety", "medium",
                        "Generate nonces of at least 128 bits from a cryptographic random source plus "
                        "a timestamp, and bound their lifetime.", ("RFC 7616 section 3.3", "CWE-330")),
            FindingSpec("digest-quality.internal-realm", "Digest realm names an internal host", "low",
                        "Use the public SIP domain as the realm, not an internal host name or address.",
                        ("RFC 3261 section 22.1", "CWE-200")),
            FindingSpec("digest-quality.stale-initial", "Initial challenge is marked stale", "info",
                        "Send stale=true only when a request reused an expired nonce.",
                        ("RFC 7616 section 3.3",)),
        ),
        references=_DIGEST_REFS,
    ),
    CheckSpec(
        id="unauthenticated-invite",
        title="INVITE progresses without credentials",
        impact="active",
        sends=(
            "1 INVITE without credentials from an anonymous identity to the reviewed destination, "
            "offering an inactive audio stream on a local port that sends nothing; then exactly "
            "what correctly ends it: an ACK for a rejection, or a CANCEL (and ACK) if it rings, or "
            "an ACK and BYE if it is answered. At most 4 requests; no media is ever sent"
        ),
        max_requests=4,
        transports=("udp", "tcp", "tls"),
        needs=("destination",),
        invites=1,
        rationale=(
            "An edge that rings or answers an unauthenticated INVITE can be used for toll fraud "
            "and spam calls by anyone who can reach it. The expected answer is a 401/407 "
            "challenge or a 403."
        ),
        owner_text=(
            "We place one call attempt to the destination you approved without any password. We "
            "expect your edge to ask for a password. If it rings or answers instead, we hang up "
            "at once (no audio is ever sent) and stop the remaining active checks."
        ),
        findings=(
            FindingSpec("unauthenticated-invite.progressed",
                        "Unauthenticated INVITE rang or was answered", "high",
                        "Require digest authentication (or an explicit trusted-peer ACL) before any "
                        "INVITE is routed; reject anonymous calls at the edge.",
                        ("RFC 3261 section 22", "CWE-306")),
        ),
        references=("RFC 3261 section 22", "RFC 3261 section 9.1", "RFC 3261 section 13.2.2.4", "RFC 3261 section 15"),
    ),
    CheckSpec(
        id="user-enumeration",
        title="Account existence differential",
        impact="active",
        sends=(
            "1 REGISTER binding query (no Contact, no credentials) for the reviewed account and 1 "
            "for ONE random non-existent user; when a destination is approved, also 1 INVITE "
            "without credentials from each of the two identities to the reviewed destination, each "
            "ended correctly (ACK, or CANCEL/ACK/BYE). At most 10 requests. A single differential, "
            "not a scan"
        ),
        max_requests=10,
        transports=("udp", "tcp", "tls"),
        needs=("account",),
        invites=2,
        rationale=(
            "If the edge answers an existing account differently from a non-existent one "
            "(status code, header set, or realm), an attacker can confirm valid account names "
            "before guessing passwords. This check compares the reviewed account with exactly one "
            "random name per method; it is not an enumeration scan. Timing is reported only as "
            "measured values and never claimed as a finding."
        ),
        owner_text=(
            "We compare your edge's answer for the approved account with its answer for one "
            "made-up name that cannot exist, once with a read-only registration query and, if a "
            "destination is approved, once with an unauthenticated call attempt. Two names, no "
            "list, no guessing."
        ),
        findings=(
            FindingSpec("user-enumeration.differential",
                        "Edge answers existing and non-existent accounts differently", "medium",
                        "Answer unknown users exactly like known ones (same status, headers, and "
                        "challenge realm), for example Asterisk's default behaviour of challenging "
                        "every request.", ("RFC 3261 section 26.1", "CWE-204")),
            FindingSpec("user-enumeration.invite-progressed",
                        "Unauthenticated INVITE rang or was answered during the comparison", "high",
                        "Require digest authentication before any INVITE is routed.",
                        ("RFC 3261 section 22", "CWE-306")),
        ),
        references=("CWE-204", "CWE-203"),
    ),
    CheckSpec(
        id="nonce-replay",
        title="Digest replay accepted",
        impact="active",
        sends=(
            "1 REGISTER binding query without credentials (to obtain a challenge), 1 correctly "
            "authenticated REGISTER binding query with the reviewed password, then the SAME "
            "Authorization header (same nonce, same nonce count) once more. None has a Contact, "
            "so no binding changes. At most 3 requests; the correct password is used, so there is "
            "no lockout risk"
        ),
        max_requests=3,
        transports=("udp", "tcp", "tls"),
        needs=("account", "password"),
        rationale=(
            "A server that accepts the exact same digest response twice (same nonce and nonce "
            "count) lets anyone who captured one request replay it while the nonce is valid. "
            "RFC 7616 servers track the nonce count to prevent this."
        ),
        owner_text=(
            "Using the account password you delivered (kept only in memory), we make one correct "
            "read-only registration query and then send the very same signed request once more, "
            "to see whether your edge accepts a replayed request. Nothing is registered."
        ),
        findings=(
            FindingSpec("nonce-replay.accepted", "Replayed digest credentials are accepted", "medium",
                        "Track the nonce count per nonce and reject a repeated or lower count; keep "
                        "nonce lifetimes short; use TLS so digest exchanges cannot be captured.",
                        ("RFC 7616 section 3.3", "RFC 7616 section 5.5", "CWE-294")),
        ),
        references=("RFC 7616 section 5.5", "CWE-294"),
    ),
    CheckSpec(
        id="srtp-policy",
        title="SRTP required for media (planned)",
        impact="active",
        sends="nothing in this version: it needs a real authenticated call and is planned",
        max_requests=0,
        transports=("udp", "tcp", "tls"),
        needs=("account", "password", "destination", "srtp"),
        state="planned",
        rationale=(
            "When the profile says SRTP is required, an edge that also accepts plain RTP lets media "
            "be intercepted. Testing it needs a real call offering only RTP/AVP, which this version "
            "does not place."
        ),
        owner_text="Planned; not run in this version and cannot be approved yet.",
        findings=(),
        references=("RFC 3711", "RFC 4568", "RFC 5763"),
    ),
)

_BY_ID = {item.id: item for item in CHECKS}
RUN_ORDER = tuple(item.id for item in CHECKS)


class CatalogError(ValueError):
    """An id or a profile security_checks section is not acceptable."""


def get(check_id: str) -> CheckSpec:
    try:
        return _BY_ID[check_id]
    except KeyError as error:
        raise CatalogError(f"unknown check id: {check_id}") from error


def ids(*, runnable_only: bool = False) -> tuple[str, ...]:
    return tuple(item.id for item in CHECKS if not runnable_only or item.state == "runnable")


def finding_spec(finding_id: str) -> FindingSpec:
    check_id = finding_id.split(".", 1)[0]
    return get(check_id).finding(finding_id)


def as_dict(spec: CheckSpec) -> dict[str, Any]:
    return {
        "id": spec.id,
        "title": spec.title,
        "state": spec.state,
        "impact": spec.impact,
        "sends": spec.sends,
        "maxRequests": spec.max_requests,
        "maxRequestsPer": "approved cleartext endpoint" if spec.per_endpoint else "run",
        "transports": list(spec.transports),
        "needs": list(spec.needs),
        "invites": spec.invites,
        "rationale": spec.rationale,
        "ownerText": spec.owner_text,
        "findings": [
            {
                "id": item.id,
                "title": item.title,
                "severity": item.severity,
                "remediation": item.remediation,
                "references": list(item.references),
            }
            for item in spec.findings
        ],
        "references": list(spec.references),
    }


def catalog_document() -> dict[str, Any]:
    return {
        "apiVersion": CATALOG_VERSION,
        "checks": [as_dict(item) for item in CHECKS],
        "requestUnit": (
            "one SIP request message (including the ACK, CANCEL, or BYE that ends an INVITE) or "
            "one TCP connection made only for a TLS handshake probe; over TCP/TLS the connection "
            "attempt counts as its first request, so a refused connection still counts"
        ),
        "networkActivity": False,
    }


def render_list(output_format: str = "human") -> str:
    if output_format == "json":
        return json.dumps(catalog_document(), indent=2) + "\n"
    lines = [f"{'ID':<26} {'IMPACT':<8} {'MAX':>4}  {'NEEDS':<28} TITLE"]
    for spec in CHECKS:
        bound = f"{spec.max_requests}" + ("*" if spec.per_endpoint else "")
        needs = ",".join(spec.needs) or "-"
        title = spec.title + (" [planned, not runnable]" if spec.state == "planned" else "")
        lines.append(f"{spec.id:<26} {spec.impact:<8} {bound:>4}  {needs:<28} {title}")
    lines.append("")
    lines.append("MAX is the enforced upper bound of requests per check (* = 1 per approved cleartext endpoint, at most 8).")
    lines.append("Nothing runs unless the target profile approves it under security_checks.approved.")
    lines.append("Network activity: none")
    return "\n".join(lines) + "\n"


def render_explain(check_id: str, output_format: str = "human") -> str:
    spec = get(check_id)
    if output_format == "json":
        return json.dumps({**as_dict(spec), "networkActivity": False}, indent=2) + "\n"
    lines = [
        f"{spec.id}: {spec.title}" + (" (PLANNED: not runnable in this version)" if spec.state == "planned" else ""),
        f"  Impact:        {spec.impact} ({'only OPTIONS or TLS handshakes' if spec.impact == 'passive' else 'REGISTER/INVITE; nothing more intrusive'})",
        f"  Sends:         {spec.sends}",
        f"  Request bound: {spec.max_requests}" + (" per approved cleartext endpoint (at most 8 endpoints)" if spec.per_endpoint else " (enforced; exceeding it aborts the check)"),
        f"  Transports:    {', '.join(spec.transports)}",
        f"  Needs:         {', '.join(spec.needs) or 'nothing beyond an approved profile'}",
        "",
        "Why it matters:",
        f"  {spec.rationale}",
        "",
        "For the service owner:",
        f"  {spec.owner_text}",
        "",
    ]
    if spec.findings:
        lines.append("Findings it can raise:")
        for item in spec.findings:
            lines.append(f"  [{item.severity}] {item.id}: {item.title}")
            lines.append(f"      Remediation: {item.remediation}")
            if item.references:
                lines.append(f"      References: {'; '.join(item.references)}")
        lines.append("")
    if spec.references:
        lines.append(f"References: {'; '.join(spec.references)}")
    lines.append("Network activity: none")
    return "\n".join(lines) + "\n"


# -- profile section ---------------------------------------------------------

SECTION_FIELDS = {"approved", "max_requests", "account", "destination", "cleartext_endpoints"}


def _placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return (
        lowered in _PLACEHOLDERS
        or "<" in value
        or ">" in value
        or (value.startswith("@") and value.endswith("@"))
    )


def validate_section(section: Any, target: dict[str, Any] | None = None) -> list[str]:
    """Every problem with a profile's optional ``security_checks`` section.

    ``None`` (absent) is valid and approves nothing. Unknown or planned check
    ids, placeholders, duplicates, and out-of-range numbers are refused.
    """
    if section is None:
        return []
    if not isinstance(section, dict):
        return ["security_checks must be an object"]
    errors: list[str] = []
    unknown = set(section) - SECTION_FIELDS
    if unknown:
        errors.append(f"unknown security_checks fields: {', '.join(sorted(map(str, unknown)))}")
    approved = section.get("approved")
    if not isinstance(approved, list) or not all(isinstance(item, str) for item in approved):
        errors.append("security_checks.approved must be a list of check ids")
        approved = []
    if len(set(approved)) != len(approved):
        errors.append("security_checks.approved contains duplicates")
    for item in approved:
        if _placeholder(item):
            errors.append(f"security_checks.approved contains a placeholder: {item!r}")
        elif item not in _BY_ID:
            errors.append(f"security_checks.approved names an unknown check: {item!r}")
        elif _BY_ID[item].state != "runnable":
            errors.append(f"security_checks.approved names {item}, which is planned and cannot be approved")
    maximum = section.get("max_requests")
    if type(maximum) is not int or not 1 <= maximum <= MAX_REQUESTS_CEILING:
        errors.append(f"security_checks.max_requests must be an integer from 1 to {MAX_REQUESTS_CEILING}")
    account = section.get("account")
    if account is not None:
        if not isinstance(account, str) or _ACCOUNT.fullmatch(account) is None:
            errors.append("security_checks.account must be a SIP user name (letters, digits, . _ + -; no @)")
        elif _placeholder(account):
            errors.append(f"security_checks.account is a placeholder: {account!r}")
    destination = section.get("destination")
    if destination is not None:
        if not isinstance(destination, str) or _DESTINATION.fullmatch(destination) is None:
            errors.append("security_checks.destination must be a SIP user part to dial")
        elif _placeholder(destination):
            errors.append(f"security_checks.destination is a placeholder: {destination!r}")
    endpoints = section.get("cleartext_endpoints")
    if endpoints is not None:
        if not isinstance(endpoints, list) or len(endpoints) > MAX_CLEARTEXT_ENDPOINTS:
            errors.append(
                f"security_checks.cleartext_endpoints must be a list of at most {MAX_CLEARTEXT_ENDPOINTS} entries"
            )
        else:
            seen: set[tuple[str, int]] = set()
            for index, item in enumerate(endpoints):
                where = f"security_checks.cleartext_endpoints[{index}]"
                if not isinstance(item, dict) or set(item) != {"transport", "port"}:
                    errors.append(f"{where} must be {{transport, port}}")
                    continue
                if item["transport"] not in ("udp", "tcp"):
                    errors.append(f"{where}.transport must be udp or tcp")
                    continue
                if type(item["port"]) is not int or not 1 <= item["port"] <= 65535:
                    errors.append(f"{where}.port must be an integer from 1 to 65535")
                    continue
                key = (item["transport"], item["port"])
                if key in seen:
                    errors.append(f"{where} duplicates another endpoint")
                seen.add(key)
            if target is not None and target.get("transport") != "tls" and endpoints:
                errors.append("security_checks.cleartext_endpoints apply only to a tls target")
    return errors


def cleartext_endpoints(section: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(section, dict):
        return []
    value = section.get("cleartext_endpoints")
    return list(value) if isinstance(value, list) else []


def declared_bound(spec: CheckSpec, section: dict[str, Any] | None) -> int:
    """The enforced request bound of ``spec`` for this profile section."""
    if spec.per_endpoint:
        return len(cleartext_endpoints(section))
    if spec.id == "user-enumeration" and not (isinstance(section, dict) and section.get("destination")):
        return 2  # the REGISTER pair only
    return spec.max_requests


def invites_declared(spec: CheckSpec, section: dict[str, Any] | None) -> int:
    if spec.id == "user-enumeration" and not (isinstance(section, dict) and section.get("destination")):
        return 0
    return spec.invites
