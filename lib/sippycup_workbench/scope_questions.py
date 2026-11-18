"""Render the owner question sheet and mark answers without echoing them."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .scope import Report, lookup, present


@dataclass(frozen=True)
class Question:
    identifier: str
    section: str
    text: str
    fields: tuple[str, ...]
    applies: Callable[[dict[str, Any]], bool] = lambda document: True
    answered: Callable[[dict[str, Any]], bool] | None = None
    details: Callable[[], list[str]] | None = None


def _uses_tls(document: dict[str, Any]) -> bool:
    transports = lookup(document, "signaling.transports")
    targets = document.get("targets")
    if isinstance(transports, list) and "tls" in transports:
        return True
    if isinstance(targets, list):
        return any(isinstance(item, dict) and item.get("transport") == "tls" for item in targets)
    return False


def _needs_account(document: dict[str, Any]) -> bool:
    return lookup(document, "account.required") is not False


def _tls_name_answered(document: dict[str, Any]) -> bool:
    targets = document.get("targets")
    if not isinstance(targets, list):
        return False
    tls = [item for item in targets if isinstance(item, dict) and item.get("transport") == "tls"]
    return bool(tls) and all(present(item.get("tls_server_name")) for item in tls)


def _status_answered(document: dict[str, Any]) -> bool:
    return lookup(document, "authorization.status") == "approved"


def _targets_answered(document: dict[str, Any]) -> bool:
    targets = document.get("targets")
    return isinstance(targets, list) and bool(targets) and all(
        isinstance(item, dict)
        and all(present(item.get(key)) for key in ("name", "address", "transport", "port"))
        for item in targets
    )


def _destinations_answered(document: dict[str, Any]) -> bool:
    destinations = document.get("destinations")
    return isinstance(destinations, list) and bool(destinations) and all(
        isinstance(item, dict) and all(present(item.get(key)) for key in ("name", "user", "expect"))
        for item in destinations
    )


def _security_checks_text() -> list[str]:
    from sippycup_checks.scope_support import question_text

    return question_text().splitlines()


QUESTIONS: tuple[Question, ...] = (
    Question("authorization.approval", "Authorization",
             "What is the identifier of your written approval for this test (ticket, email id, contract number), and who approves it?",
             ("authorization.approval_id", "authorization.approved_by")),
    Question("authorization.status", "Authorization",
             "Is the scope approved in writing today? (We record it as pending until you confirm.)",
             ("authorization.status",), answered=_status_answered),
    Question("authorization.window", "Authorization",
             "In what window may testing run? Give the start and end with a timezone (for example 2026-12-01 09:00 to 2026-12-01 17:00, Europe/Amsterdam).",
             ("authorization.valid_from", "authorization.valid_until")),
    Question("signaling.addresses", "Signaling",
             "Which literal IP address(es) or CIDR(s) may we send SIP signaling to? (Hostnames are not enough: we pin literal addresses.)",
             ("signaling.networks", "targets")),
    Question("signaling.ports", "Signaling",
             "Which signaling port(s) and which transport(s) (UDP, TCP, TLS) may we use against each address?",
             ("signaling.ports", "signaling.transports"), answered=_targets_answered),
    Question("signaling.tls", "Signaling",
             "For TLS: what server name is on the certificate for each TLS address, and which CA "
             "issued it: a public CA or a private one? If private, send us the CA certificate "
             "(never a private key). We verify that name and CA while still connecting only to the "
             "literal address; the name is never looked up in DNS.",
             ("targets",), applies=_uses_tls, answered=_tls_name_answered),
    Question("client.source", "Signaling",
             "Which source address(es) will our tests come from as you see them, so you can allow them?",
             ("client.source_addresses",)),
    Question("account.required", "Account",
             "Do calls require an account (SIP registration or digest authentication)?",
             ("account.required",)),
    Question("account.identity", "Account",
             "If yes: what are the account username and realm (SIP domain)?",
             ("account.username", "account.realm"), applies=_needs_account),
    Question("account.delivery", "Account",
             "If yes: how will you deliver the password? (Secret manager, encrypted message, in person, phone call.) Do NOT send the password in your written answer; we record only a reference name for it.",
             ("account.credential_ref", "account.credential_delivery"), applies=_needs_account),
    Question("destinations", "Destinations",
             "Which destination(s) should we dial (extension, echo service, voice agent) and what should each do: echo the audio, answer as an agent, or reject the call?",
             ("destinations",), answered=_destinations_answered),
    Question("media.addresses", "Media",
             "Which IP addresses will your media servers send RTP from and receive it on? Give each media-server "
             "address, or each media-server pool as a range in CIDR form (for example 198.51.100.0/27), even when it "
             "is the signaling address.",
             ("media.networks",), details=lambda: [
                 "   We send media only to these addresses and ranges, never signaling: SIP goes only to the",
                 "   signaling addresses above. A call stops by itself if your side offers media anywhere else.",
                 "   Each range may hold at most 1024 addresses (IPv4 /22 or narrower), 1024 in total; a wider",
                 "   range is refused, so please name the actual media-server pool(s).",
             ]),
    Question("media.ports", "Media",
             "Which media (RTP) port range do your media servers use (the far-end UDP ports we will send "
             "media to), as a first and last port (for example 10000 to 20000)?",
             ("media.port_range.start", "media.port_range.end"), details=lambda: [
                 "   A call stops by itself if your side offers a media port outside this range.",
             ]),
    Question("media.protection", "Media",
             "Is media plain RTP or SRTP, and if SRTP which keying: SDES or DTLS-SRTP?",
             ("media.protection",)),
    Question("media.codecs", "Media",
             "Which codec(s) and which DTMF method (RFC 4733, SIP INFO, in-band, none) should we expect?",
             ("media.codecs", "media.dtmf")),
    Question("media.nat", "Media",
             "Does the service send media to the source address it observes, for clients behind NAT (symmetric RTP)?",
             ("media.symmetric_rtp",)),
    Question("limits.volume", "Ceilings",
             "What are the ceilings for total calls, concurrent calls, and calls per second?",
             ("limits.calls", "limits.concurrent_calls", "limits.calls_per_second")),
    Question("limits.packets", "Ceilings",
             "What are the ceilings for packets per second, total packets, and total bytes?",
             ("limits.packets_per_second", "limits.packets", "limits.bytes")),
    Question("limits.duration", "Ceilings",
             "What is the maximum duration of a single call, and of the whole test?",
             ("limits.call_duration_seconds", "limits.total_duration_seconds")),
    Question("stop", "Stop conditions",
             "When must we stop? (Number of consecutive failures, any unexpected response, packet-loss percentage.)",
             ("stop_conditions.consecutive_failures", "stop_conditions.unexpected_response", "stop_conditions.packet_loss_percent")),
    Question("test_scope.classes", "Test scope",
             "Which test classes are allowed (for example OPTIONS probe, call placement), and which are explicitly excluded (write 'none' if nothing is excluded)?",
             ("test_scope.allowed_classes", "test_scope.exclusions")),
    Question("contact", "Operations",
             "Who is the live contact that can stop the test or inspect server metrics, and how do we reach them?",
             ("contact.name", "contact.channel", "contact.can_stop_test")),
    Question("evidence", "Evidence",
             "How long may we retain captures and logs, and what are your disclosure expectations for findings (private, coordinated, public after remediation)?",
             ("evidence.retention_days", "evidence.disclosure")),
    Question("security_checks", "Security checks", _security_checks_text()[0],
             ("security_checks.approved", "security_checks.max_requests"),
             details=lambda: _security_checks_text()[1:]),
)


def _field_has_error(report: Report, path: str) -> bool:
    for finding in report.errors:
        value = finding.field
        if value == path or value.startswith(path + ".") or value.startswith(path + "["):
            return True
    return False


def question_state(report: Report | None, question: Question) -> str:
    """Return answered, unanswered, or not-applicable for one question."""
    if report is None or report.document is None:
        return "unanswered"
    document = report.document
    if not question.applies(document):
        return "not-applicable"
    if question.answered is not None:
        complete = question.answered(document)
    else:
        complete = all(present(lookup(document, path)) for path in question.fields)
    if not complete:
        return "unanswered"
    if any(_field_has_error(report, path) for path in question.fields):
        return "unanswered"
    return "answered"


def render_questions(report: Report | None = None) -> str:
    """Render the question sheet. Values from the scope file are never echoed."""
    lines = [
        "# Scope questions for the service owner",
        "",
        "We need the following answers in writing before any test traffic is sent.",
        "Please do not send passwords, tokens, or private keys in your reply; tell us",
        "how you will deliver the account password instead.",
        "",
    ]
    marked = report is not None and report.document is not None
    if report is not None and not marked:
        lines.extend(
            [
                "NOTE: the scope file is missing or invalid, so no question is marked.",
                "Run `./bin/sippycup scope check` for details.",
                "",
            ]
        )
    section = ""
    for number, question in enumerate(QUESTIONS, 1):
        if question.section != section:
            section = question.section
            lines.extend([f"## {section}", ""])
        tag = ""
        if marked:
            state = question_state(report, question)
            tag = f" [{'x' if state == 'answered' else ' ' if state == 'unanswered' else 'n/a'}] ({state})"
        lines.append(f"{number}. {question.text}{tag}")
        if question.details is not None:
            lines.extend(question.details())
        lines.append("")
    from .scope_app import render_part

    part_two = render_part(report if marked else None)
    if marked:
        lines.append("Legend: [x] answered, [ ] unanswered, [n/a] not applicable. Values are not shown.")
    lines.extend(part_two)
    return "\n".join(lines).rstrip() + "\n"
