"""Scope intake support for security checks: validation, compile, questions.

The scope file may carry an optional owner-approved section::

    security_checks:
      approved: [banner-disclosure, unauthenticated-invite]
      max_requests: 20

Absent means nothing is approved (default deny). ``scope compile`` carries the
list into the target profile together with what the checks need from the rest
of the scope (account name, one destination, approved cleartext endpoints).
Offline only.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from . import catalog

CLASS_NAME = "security-checks"


def _wanted(document: dict[str, Any]) -> tuple[list[str], Any] | None:
    section = document.get("security_checks")
    if section is None:
        return None
    approved = section.get("approved") if isinstance(section, dict) else None
    return (approved if isinstance(approved, list) else []), section


def cleartext_endpoints(document: dict[str, Any], first_target: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Approved cleartext (transport, port) pairs on the first target's address."""
    if not first_target or first_target.get("transport") != "tls":
        return []
    signaling = document.get("signaling") or {}
    ports = [p for p in signaling.get("ports") or [] if type(p) is int]
    transports = [t for t in signaling.get("transports") or [] if t in ("udp", "tcp")]
    return [{"transport": t, "port": p} for t in transports for p in ports]


def validate_scope(
    document: dict[str, Any],
    *,
    targets: list[dict[str, Any]],
    destinations: list[dict[str, Any]],
    classes: list[str] | None,
    limits: dict[str, int],
) -> list[tuple[str, str, str, str, str]]:
    """(code, kind, field, message, severity) for the security_checks section."""
    wanted = _wanted(document)
    if wanted is None:
        return []
    approved, section = wanted
    out: list[tuple[str, str, str, str, str]] = []

    def add(code: str, kind: str, field: str, message: str, severity: str = "error") -> None:
        out.append((code, kind, field, message, severity))

    if not isinstance(section, dict):
        add("scope.malformed", "malformed", "security_checks", "security_checks must be a mapping")
        return out
    shaped = {key: value for key, value in section.items() if key in ("approved", "max_requests")}
    for problem in catalog.validate_section(shaped):
        kind = "inconsistent" if "placeholder" in problem else "malformed"
        add("scope.placeholder_value" if "placeholder" in problem else "scope.malformed", kind,
            "security_checks", problem)
    if out:
        return out
    if not approved:
        return out
    if classes is not None and CLASS_NAME not in classes:
        add("scope.security_checks_class", "inconsistent", "test_scope.allowed_classes",
            f"security checks are approved but test_scope.allowed_classes does not include {CLASS_NAME}")
    first = targets[0] if targets else None
    account = document.get("account") or {}
    section_like: dict[str, Any] = {
        "account": account.get("username") if account.get("required") else None,
        "destination": _destination(first, destinations),
        "cleartext_endpoints": cleartext_endpoints(document, first),
    }
    total = 0
    invites = 0
    for check_id in approved:
        spec = catalog.get(check_id)
        if "tls" in spec.needs and (first is None or first.get("transport") != "tls"):
            add("scope.security_check_inapplicable", "inconsistent", "security_checks.approved",
                f"{check_id} needs the first target to use tls")
        if "account" in spec.needs and not section_like["account"]:
            add("scope.security_check_inapplicable", "inconsistent", "security_checks.approved",
                f"{check_id} needs account.required true and account.username")
        if "destination" in spec.needs and not section_like["destination"]:
            add("scope.security_check_inapplicable", "inconsistent", "security_checks.approved",
                f"{check_id} needs a destination on the first target")
        if spec.per_endpoint:
            count = len(section_like["cleartext_endpoints"])
            if count == 0:
                add("scope.security_check_inapplicable", "inconsistent", "security_checks.approved",
                    f"{check_id} needs udp or tcp among signaling.transports for the TLS address")
            elif count > catalog.MAX_CLEARTEXT_ENDPOINTS:
                add("scope.security_check_inapplicable", "inconsistent", "security_checks.approved",
                    f"{check_id} would probe {count} cleartext endpoints; at most "
                    f"{catalog.MAX_CLEARTEXT_ENDPOINTS} are allowed")
        first_transport = first.get("transport") if first else None
        total += catalog.declared_bound(spec, section_like, first_transport)
        invites += catalog.invites_declared(spec, section_like, first_transport)
    maximum = section.get("max_requests")
    if type(maximum) is int and total > maximum:
        add("scope.security_checks_budget", "inconsistent", "security_checks.max_requests",
            f"the approved checks may send up to {total} requests, above max_requests {maximum}")
    if "packets" in limits and total > limits["packets"]:
        add("scope.security_checks_budget", "inconsistent", "limits.packets",
            f"the approved checks may send up to {total} requests, above limits.packets {limits['packets']}")
    if invites and "calls" in limits and invites > limits["calls"]:
        add("scope.security_checks_budget", "inconsistent", "limits.calls",
            f"the approved checks place up to {invites} INVITE attempts, above limits.calls {limits['calls']}")
    return out


def _destination(first: dict[str, Any] | None, destinations: list[dict[str, Any]]) -> str | None:
    if first is None:
        return None
    for item in destinations:
        if item.get("target") == first.get("name"):
            return item.get("user")
    return None


def profile_section(document: dict[str, Any]) -> dict[str, Any] | None:
    """The profile's ``security_checks`` for a validated scope, or None."""
    wanted = _wanted(document)
    if wanted is None or not wanted[0]:
        return None
    approved, section = wanted
    targets = document.get("targets") or []
    first = None
    if targets:
        item = targets[0]
        first = {**item, "address": str(ipaddress.ip_address(str(item["address"]).strip()))}
    destinations = []
    for item in document.get("destinations") or []:
        target = item.get("target") or (targets[0]["name"] if len(targets) == 1 else None)
        destinations.append({"target": target, "user": item.get("user")})
    needs = {need for check_id in approved for need in catalog.get(check_id).needs}
    result: dict[str, Any] = {"approved": list(approved), "max_requests": section["max_requests"]}
    account = document.get("account") or {}
    if "account" in needs and account.get("required") and account.get("username"):
        result["account"] = account["username"]
    destination = _destination(first, destinations)
    if "destination" in needs and destination:
        result["destination"] = destination
    # srtp-policy uses an approved cleartext endpoint when there is one, but does not require it.
    if "cleartext_endpoints" in needs or "srtp-policy" in approved:
        endpoints = cleartext_endpoints(document, first)
        if endpoints:
            result["cleartext_endpoints"] = endpoints
    return result


def question_text() -> str:
    """The owner question, explaining every runnable check with its exact count."""
    lines = [
        "Optional: which security posture checks do you approve? Each is a handful of ordinary, "
        "protocol-conformant requests with an enforced upper bound; none guesses passwords, scans "
        "accounts or ports, floods, or exploits anything. List the ids you approve under "
        "security_checks.approved, the total request ceiling under security_checks.max_requests, "
        f"and add '{CLASS_NAME}' to the allowed test classes. Nothing is run that you do not list:",
    ]
    for spec in catalog.CHECKS:
        if spec.state != "runnable":
            continue
        bound = (f"at most 1 request per approved cleartext port, {catalog.MAX_CLEARTEXT_ENDPOINTS} at most"
                 if spec.per_endpoint else f"at most {spec.max_requests} request{'s' if spec.max_requests != 1 else ''}")
        lines.append(f"   - {spec.id} ({spec.impact}, {bound}): {spec.owner_text}")
    return "\n".join(lines)
