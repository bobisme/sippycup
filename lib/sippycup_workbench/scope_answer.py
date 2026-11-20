"""``scope answer``: put the owner's written answers into scope.yaml, guided.

The operator types each answer once; this module checks it with exactly the
rules ``scope check`` uses (``scope.document_findings`` on the document with
that answer in it), explains a rejected answer and asks again, and writes the
accepted answer at once. It edits only scope.yaml, atomically and mode 0600,
and keeps the operator's comments and everything it did not ask about (see
``scope_edit``). It never writes a password, never invents an answer, and never
marks the authorization approved by itself.

Questions are the numbered questions of ``scope questions`` (part 1, 1 to 24)
and, when the file has the platform sections, P1 to P18 and A1 to A6. The
approval (question 2) is asked last, with the scope it approves on screen, and
any later change to what may be sent sets it back to pending.
"""

from __future__ import annotations

import copy
import difflib
import ipaddress
import json
import os
import re
import shlex
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, TextIO

from .scope import (
    AUTH_STATUSES,
    CODECS,
    CREDENTIAL_DELIVERIES,
    DISCLOSURES,
    DTMF_METHODS,
    EXPECT_BEHAVIORS,
    HOSTNAME_PATTERN,
    PROTECTIONS,
    TEST_CLASSES,
    TRANSPORTS,
    Finding,
    Report,
    ScopeError,
    _UniqueLoader,
    document_findings,
    inspect,
    present,
)
from .scope_edit import EditError, apply_edits, get_in, render_inline, set_in
from .scope_questions import QUESTIONS, question_state

LAUNCHER = "./bin/sippycup"
OPEN_WORDS = ("pending", "unknown")
# Notes that only count what is still open; shown once per session.
PROGRESS_NOTES = ("scope.platform_open", "scope.production_safety_open", "scope.surface_not_ready")
# Findings that record a fact about time or approval, not a wrong answer: the
# answer is recorded and the finding is shown as a note (scope check keeps
# reporting it until it is resolved).
NOTE_CODES = {"scope.window_not_started", "scope.window_expired", "scope.authorization_not_approved"}
OPTIONAL_QUESTIONS = {"security_checks"}
STATUS_PATH = ("authorization", "status")

# ------------------------------------------------------------ the approval rule
#
# Typing `approved` asserts that the owner approved THIS scope in writing. Any
# later change to what the approval names (reference, approver, window) or to
# what the tools may send sets the status back to pending, so the approval is
# asked again and never carried over to facts the owner did not see.
#
# What may be sent is everything `scope compile` turns into a permission or a
# bound: the target profile (approved addresses, destinations, codecs, media
# networks and ports, SRTP features, call limits, the security checks), the
# campaign manifest (networks, ports, transports, credential reference and
# account, ceilings, stop conditions, the cases the classes generate), and the
# platform answers that hold the profile and the campaign (never-dial, reach,
# carrier permission, toll, the production concurrency maximum), and every
# answer that decides whether application-surfaces.yaml records a surface as
# `approved` (the surfaces themselves, the third parties, and the
# production-safety answers under platform.environment and platform.operations).
# Not in the list, because they grant nothing: the scope name, contact,
# evidence handling, how the password is delivered, our own source addresses
# (an expectation for the oracle), the DTMF method and symmetric RTP
# (expectations), and the record-only answers (platform name, components,
# out_of_scope, addressing, test identities, stored file kinds, route inventory).
APPROVAL_FACTS = ("authorization.approval_id", "authorization.approved_by", "authorization.valid_from",
                  "authorization.valid_until")
GRANTS = (
    "signaling", "targets", "destinations", "media.networks", "media.port_range", "media.protection",
    "media.codecs", "limits", "stop_conditions", "test_scope", "account.required", "account.username",
    "account.realm", "account.credential_ref", "security_checks", "platform.dialing",
    "platform.third_parties", "platform.environment", "platform.operations", "application.surfaces",
)


def _canon(value: Any) -> Any:
    """A value in a form that compares equal however YAML or the prompt spelled it."""
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat() if value.tzinfo else value.isoformat()
    if isinstance(value, str):
        moment = _as_datetime(value)
        return moment.astimezone(timezone.utc).isoformat() if moment is not None else value
    if isinstance(value, list):
        return [_canon(item) for item in value]
    if isinstance(value, dict):
        return {key: _canon(item) for key, item in value.items() if item is not None}
    return value


def _value_at(document: dict[str, Any], dotted: str) -> Any:
    value = _canon(get_in(document, tuple(dotted.split("."))))
    return None if value in ([], {}, "") else value


def reapproval(document: dict[str, Any], edits: list[tuple[tuple[str, ...], Any]]) -> tuple[list, list[tuple]]:
    """Add the status reset when an edit changes what a recorded approval approved.

    Returns ``(edits, changes)``; ``changes`` lists ``(field, before, after)``.
    """
    if get_in(document, STATUS_PATH) != "approved" or any(path == STATUS_PATH for path, _ in edits):
        return edits, []
    after = copy.deepcopy(document)
    for path, value in edits:
        set_in(after, path, copy.deepcopy(value))
    changes: list[tuple] = []
    for name in APPROVAL_FACTS + GRANTS:
        if _value_at(document, name) != _value_at(after, name):
            _leaves(name, get_in(document, tuple(name.split("."))), get_in(after, tuple(name.split("."))), changes)
    return (edits + [(STATUS_PATH, "pending")], changes) if changes else (edits, [])


def _leaves(name: str, before: Any, after: Any, out: list[tuple]) -> None:
    """The changed answers under ``name``, by their own field path (limits.calls, not limits)."""
    if isinstance(before, dict) and isinstance(after, dict):
        for key in dict.fromkeys([*before, *after]):
            if _canon(before.get(key)) != _canon(after.get(key)):
                _leaves(f"{name}.{key}", before.get(key), after.get(key), out)
        return
    out.append((name, before, after))


def _short(value: Any) -> str:
    text = show(value)
    return text if len(text) <= 60 else text[:57] + "..."


def _change_text(name: str, before: Any, after: Any) -> str:
    """One changed answer; for a list, what was added and removed (two long lists cut short look the same)."""
    if isinstance(before, list) and isinstance(after, list) and (len(show(before)) > 60 or len(show(after)) > 60):
        old, new = [_canon(item) for item in before], [_canon(item) for item in after]
        parts = [f"{word} {_short(item)}" for word, items in (("added", [item for item in after if _canon(item) not in old]),
                                                             ("removed", [item for item in before if _canon(item) not in new]))
                 for item in items[:2]]
        more = sum(1 for item in after if _canon(item) not in old) + sum(1 for item in before if _canon(item) not in new) - len(parts)
        if parts:
            return f"{name}: " + ", ".join(parts) + (f", and {more} more" if more > 0 else "")
        return f"{name}: the same {len(after)} entries in another order"
    return f"{name}: {_short(before)} -> {_short(after)}"


def reapprove_message(changes: list[tuple], engagement: str) -> str:
    facts = [item for item in changes if item[0] in APPROVAL_FACTS]
    what = ("the approval's reference, approver, or window" if facts
            else "what may be sent")
    detail = "; ".join(_change_text(name, before, after) for name, before, after in changes[:4])
    if len(changes) > 4:
        detail += f"; and {len(changes) - 4} more"
    return (f"authorization.status is pending again: the approval you recorded asserted that the owner approved"
            f" the scope as it was, and this changes {what} ({detail}). If the owner's written approval covers"
            f" the new answer, record the approval again: {LAUNCHER} scope answer {shlex.quote(engagement)} 2"
            f"   (then {LAUNCHER} scope compile {shlex.quote(engagement)}; until both are done nothing can be sent)")


class Quit(Exception):
    """The operator typed quit: stop asking, keep what was recorded."""


class ChangedOnDisk(ScopeError):
    """scope.yaml changed on disk while answering."""


class Refused(ValueError):
    """A typed word the prompt understands but must not record (the message says why)."""


# ------------------------------------------------------------------ fields


@dataclass(frozen=True)
class Field:
    """One answer: where it is stored, how it is typed, what is valid."""

    path: tuple[str, ...]
    label: str
    hint: str
    kind: str = "text"  # text, int, number, bool, enum, words, list, enumlist, ints, addresses, address, dials
    choices: tuple[str, ...] = ()
    open_words: bool = False  # platform answers: pending / unknown are answers too
    # The owner's own words (from the sheet) and what they are stored as.
    words: tuple[tuple[str, Any], ...] = ()
    # Words that are understood but cannot be recorded, with the reason.
    refuse: tuple[tuple[str, str], ...] = ()

    @property
    def dotted(self) -> str:
        return ".".join(self.path)


def _f(path: str, label: str, hint: str, kind: str = "text", choices: tuple[str, ...] = (),
       open_words: bool = False, words: dict[str, Any] | None = None,
       refuse: dict[str, str] | None = None) -> Field:
    return Field(tuple(path.split(".")), label, hint, kind, choices, open_words,
                 tuple((words or {}).items()), tuple((refuse or {}).items()))


def _many(value: Any, *phrases: str) -> dict[str, Any]:
    return {phrase: value for phrase in phrases}


def _not_a_name(noun: str) -> dict[str, str]:
    """A yes or no typed where a list entry's name is asked is almost always a slip."""
    reason = (f"that is a yes or no, and this asks for the {noun}'s name. Press Enter if there is no (more)"
              f" {noun}; to name it that word, type a backslash before it (\\no)")
    return _many(reason, "y", "yes", "n", "no")


YES = ("yes", "y", "yes please", "in", "in scope", "in-scope", "test it", "include", "included")
NO = ("no", "n", "out", "out of scope", "out-of-scope", "not in scope", "leave it out", "exclude", "excluded")
IN_OUT = {**_many("in-scope", *YES), **_many("out-of-scope", *NO)}
# Answers that mean the owner does not know yet, or that the question is still with the owner.
OPEN_PHRASES = {**_many("unknown", "not sure", "unsure", "don't know", "do not know", "dont know", "dunno", "not known",
                        "no idea"),
                **_many("pending", "still to be asked", "to be asked", "not asked yet", "waiting", "asked")}
# "Write none / nothing if nothing is": for a list answer these are the explicit empty answer [none].
NONE_PHRASES = ("none", "nothing", "no", "n/a", "there are none", "there is none", "nothing is", "none at all")
YES_NO_HINT = "yes or no"
ADDRESS_KINDS = ("addresses", "address")
RESERVED_HINT = ("? or help = this help; Enter = leave it open (nothing is invented); clear = remove the recorded"
                 " answer; quit = stop (every accepted answer is already saved). To record one of these words as"
                 " an answer, type a backslash before it, e.g. \\help")

ADDRESS_HINT = ("literal IP addresses or CIDR ranges, separated by commas, e.g. 203.0.113.10, 203.0.113.0/28. "
                "No hostnames: ask the owner for the numeric address behind a name")
PERMISSION_REFUSE = {
    "no": "'no' could mean 'not involved' or 'does not permit testing'. If the company is not involved in what we"
          " test, type out-of-path. If it does not permit testing, type pending and tell the owner: nothing that"
          " goes through it is tested until it permits",
    **_many("there is no answer for a refusal: a refused permission means what goes through that company cannot"
            " be tested. Type pending (the question stays open) and tell the owner; if the company is not"
            " involved at all, type out-of-path",
            "refused", "forbidden", "not permitted", "does not permit", "doesn't permit", "denied"),
}
FIELDS: dict[str, Field] = {item.dotted: item for item in (
    _f("authorization.approval_id", "Reference of the owner's written approval",
       "any text up to 128 characters: a ticket number, contract number, or e-mail id (e.g. CHG-2026-1142)"),
    _f("authorization.approved_by", "Who approved it (name and role)",
       "any text up to 128 characters, e.g. Jane Doe, head of voice platform"),
    _f("signaling.networks", "Signaling addresses or ranges", ADDRESS_HINT, "addresses"),
    _f("signaling.ports", "Signaling ports", "whole numbers 1-65535, separated by commas, e.g. 5060, 5061", "ints"),
    _f("signaling.transports", "Signaling transports", "one or more of: udp, tcp, tls (e.g. udp, tls)",
       "enumlist", TRANSPORTS),
    _f("client.source_addresses", "Our source address(es) as the owner sees them",
       "literal IP addresses separated by commas; add your local capture-side address too when NAT makes it "
       "differ. `./bin/sippycup ready DIR` prints the address it sees (the practice target sees 127.0.0.1)",
       "addresses"),
    _f("account.required", "Do calls need an account (registration or digest authentication)?",
       YES_NO_HINT, "bool"),
    _f("account.username", "Account username", "letters, digits and . _ + @ - (e.g. practice)"),
    _f("account.realm", "Account realm (SIP domain)", "letters, digits and . _ - (e.g. sip.acme.tld)"),
    _f("account.credential_ref", "Credential reference NAME (never the password)",
       "a NAME you choose for the password, NOT the password itself: lowercase letters, digits and '-', "
       "starting with a letter, at most 63 characters (e.g. acme-password). It is the name you later pass to "
       "campaign run --secret-env NAME=VARIABLE; the password goes only in a private file "
       "(docs/FIRST-ENGAGEMENT.md, section 2)"),
    _f("account.credential_delivery", "How the owner delivers the password",
       "one of: " + ", ".join(CREDENTIAL_DELIVERIES), "enum", CREDENTIAL_DELIVERIES,
       words={**_many("secret-manager", "secret manager", "a secret manager", "vault"),
              **_many("encrypted-message", "encrypted message", "an encrypted message", "encrypted e-mail",
                      "encrypted email"),
              **_many("in-person", "in person"), **_many("phone-call", "phone call", "a phone call", "phone",
                                                         "by phone")}),
    _f("media.networks", "Media addresses or ranges", ADDRESS_HINT + "; each range at most 1024 addresses (/22)",
       "addresses"),
    _f("media.port_range.start", "First media (RTP) port", "a whole number 1-65535, e.g. 10000", "int"),
    _f("media.port_range.end", "Last media (RTP) port", "a whole number 1-65535, not below the first, e.g. 20000",
       "int"),
    _f("media.protection", "Media protection", "one or more of: rtp (plain), sdes-srtp, dtls-srtp", "enumlist",
       PROTECTIONS, words={**_many("rtp", "plain", "plain rtp"), **_many("sdes-srtp", "sdes", "srtp sdes"),
                           **_many("dtls-srtp", "dtls", "dtls srtp")}),
    _f("media.codecs", "Codecs", "one or more of: PCMU, PCMA, G722, OPUS", "enumlist", CODECS,
       words={**_many("PCMU", "g.711u", "g711u", "ulaw", "u-law"), **_many("PCMA", "g.711a", "g711a", "alaw",
                                                                         "a-law"),
              **_many("G722", "g.722")}),
    _f("media.dtmf", "DTMF method", "one of: rfc4733, sip-info, inband, none", "enum", DTMF_METHODS,
       words={**_many("rfc4733", "rfc 4733", "rfc-4733"), **_many("sip-info", "sip info", "info"),
              **_many("inband", "in-band", "in band")}),
    _f("media.symmetric_rtp", "Symmetric RTP (media sent to the observed source address)?", YES_NO_HINT, "bool"),
    _f("limits.calls", "Total calls", "a whole number, e.g. 40", "int"),
    _f("limits.concurrent_calls", "Concurrent calls", "a whole number, not above total calls, e.g. 2", "int"),
    _f("limits.calls_per_second", "Calls per second", "a whole number, e.g. 1", "int"),
    _f("limits.packets_per_second", "Packets per second", "a whole number; 100 or more for a normal call, e.g. 200",
       "int"),
    _f("limits.packets", "Total packets", "a whole number, e.g. 200000", "int"),
    _f("limits.bytes", "Total bytes", "a whole number, e.g. 50000000 (50 MB)", "int"),
    _f("limits.call_duration_seconds", "Longest single call, in seconds", "a whole number, e.g. 60", "int"),
    _f("limits.total_duration_seconds", "Whole test duration, in seconds", "a whole number, e.g. 3600", "int"),
    _f("stop_conditions.consecutive_failures", "Stop after this many consecutive failures", "a whole number, e.g. 3",
       "int"),
    _f("stop_conditions.unexpected_response", "Stop on any unexpected response?", YES_NO_HINT, "bool"),
    _f("stop_conditions.packet_loss_percent", "Stop above this packet loss, in percent",
       "a number from 0 to 100, e.g. 20", "number"),
    _f("test_scope.allowed_classes", "Allowed test classes",
       "one or more of: " + ", ".join(f"{name} ({what})" for name, what in TEST_CLASSES.items())
       + "; security-checks only with question 24", "enumlist", tuple(TEST_CLASSES),
       words={**_many("options", "options probe", "an options probe", "option"),
              **_many("call", "calls", "call placement", "placing calls")}),
    _f("test_scope.exclusions", "Explicit exclusions",
       "words separated by commas, e.g. registration flood; type none if nothing is excluded", "words"),
    _f("contact.name", "Live contact (name)", "any text, e.g. Jane Doe (NOC)"),
    _f("contact.channel", "How to reach the live contact", "any text, e.g. +31 20 123 4567 or #voice-test on Slack"),
    _f("contact.can_stop_test", "Can that contact stop the test?", "yes or no (a contact who can stop it is required)",
       "bool"),
    _f("evidence.retention_days", "Keep captures and logs for (days)", "a whole number from 1 to 3650, e.g. 30",
       "int"),
    _f("evidence.disclosure", "Disclosure of findings", "one of: " + ", ".join(DISCLOSURES), "enum", DISCLOSURES,
       words=_many("public-after-remediation", "public after remediation")),
    _f("security_checks.approved", "Approved check ids",
       "ids from `./bin/sippycup checks list`, separated by commas", "list"),
    _f("security_checks.max_requests", "Request ceiling for the checks", "a whole number", "int"),
    # part 2: platform and application (every answer may be pending or unknown)
    _f("platform.name", "Product or platform name", "any text", open_words=True),
    _f("platform.out_of_scope", "Explicitly out of scope",
       "plain words separated by commas, e.g. billing, the public marketing site; nothing (or none) if nothing is",
       "words", open_words=True),
    _f("platform.environment.kind", "Environment",
       "production (the live system), staging (a staging copy), or dedicated-test (set up only for this test)",
       "enum", ("production", "staging", "dedicated-test"), True,
       words={**_many("production", "prod", "live", "live production", "live production system", "the live system",
                      "production system", "live system"),
              **_many("staging", "stage", "a staging copy", "staging copy", "copy"),
              **_many("dedicated-test", "dedicated test", "test", "test instance", "dedicated",
                      "an instance set up only for this test", "instance set up only for this test",
                      "only for this test", "set up only for this test")}),
    _f("platform.environment.real_customers", "Real customers use it during the test?", "yes, no, or not sure",
       "bool", open_words=True),
    _f("platform.environment.test_tenant", "Test tenant label",
       "the tenant's name only (never a password); none if there is none", open_words=True,
       words=_many("none", "nothing", "no", "there is none", "no tenant", "no test tenant")),
    _f("platform.environment.never_touch", "Data we must never open or change",
       "plain words separated by commas, e.g. real voicemail, call records; none only if the system holds no real"
       " data", "words", open_words=True),
    _f("platform.dialing.never_dial", "Numbers we must never dial",
       "numbers separated by commas, e.g. 112, 911; none only if the platform cannot reach any of them", "dials",
       open_words=True),
    _f("platform.dialing.never_dial_prefixes", "Prefixes we must never dial (optional)",
       "prefixes separated by commas, e.g. 00, 0900; Enter if the owner gave none", "dials", open_words=True),
    _f("platform.dialing.toll", "Cost of calls that reach the public network",
       "no-cost (such calls cost nothing), accepted (they cost money and the owner accepts it), or refused (the"
       " owner does not accept the cost)", "enum", ("no-cost", "accepted", "refused"), True,
       words={**_many("no-cost", "no cost", "free", "costs nothing", "it costs nothing", "does not cost money",
                      "no money"),
              **_many("accepted", "accept", "we accept", "we accept the cost", "accept the cost", "cost accepted"),
              **_many("refused", "refuse", "not accepted", "do not accept", "don't accept", "we do not accept")},
       refuse=_many("yes and no are ambiguous here (does it cost money? do you accept the cost?). Type no-cost,"
                    " accepted, or refused", "yes", "no", "y", "n")),
    _f("platform.operations.allowed_hours", "Allowed test hours", "plain words with a timezone, e.g. weekdays "
       "22:00 to 06:00, Europe/Amsterdam", open_words=True),
    _f("platform.operations.max_concurrent_calls", "Most calls at once on the live system", "a whole number", "int",
       open_words=True),
    _f("platform.operations.max_requests_per_second", "Most web or API requests per second", "a whole number",
       "int", open_words=True),
    _f("platform.operations.blocking", "Alarms or automatic blocks we may trigger, and who can undo a block",
       "plain words", open_words=True),
    _f("platform.operations.emergency_contact.name", "Emergency contact (name)", "any text", open_words=True),
    _f("platform.operations.emergency_contact.channel", "Emergency contact (phone answered during the test)",
       "any text", open_words=True),
    _f("platform.operations.stop_signal", "The owner's stop signal", "the word or message that means stop now",
       open_words=True),
    _f("application.object_classes", "Kinds of stored files",
       "words separated by commas, e.g. voicemail, recording; none if it stores no files", "words",
       open_words=True),
    _f("application.route_inventory.kind", "List of pages and API calls",
       "openapi (an OpenAPI file), har (a browser recording), route-list (a plain list), or none", "enum",
       ("openapi", "har", "route-list", "none"), True,
       words={**_many("openapi", "openapi file", "an openapi file", "swagger"),
              **_many("har", "har file", "a har file", "browser recording", "a browser recording"),
              **_many("route-list", "route list", "plain list", "a plain list", "list"),
              **_many("none", "no", "nothing", "no list")}),
    _f("application.route_inventory.file", "Where that file is (optional)",
       "a path under work/, e.g. work/acme/openapi.json (recorded, never read); Enter if none", open_words=True),
)}
COMPONENT_CHOICES = ("in-scope", "out-of-scope")
for _name in ("sip_edge", "media_servers", "admin_console", "customer_web_app", "api", "websocket_webrtc",
              "provisioning", "voicemail", "ivr", "conference", "recording"):
    FIELDS[f"platform.components.{_name}"] = _f(
        f"platform.components.{_name}", f"Part: {_name.replace('_', ' ')}  (test it?)",
        "yes (test it), no (leave it out), or not sure; in-scope and out-of-scope work too", "enum",
        COMPONENT_CHOICES, True, words=IN_OUT)
for _name, _label in (("hosting", "hosting provider"), ("cdn_waf", "CDN or web firewall"),
                      ("pstn_carrier", "phone carrier or gateway"), ("sms", "SMS provider"),
                      ("email", "e-mail provider")):
    FIELDS[f"platform.third_parties.{_name}.provider"] = _f(
        f"platform.third_parties.{_name}.provider", f"{_label.capitalize()}: which company",
        "the company's name; none if there is no such company (it is then recorded as not involved: out-of-path)",
        open_words=True, words=_many("none", *NONE_PHRASES, "no such company", "there is no such company"))
    FIELDS[f"platform.third_parties.{_name}.permission"] = _f(
        f"platform.third_parties.{_name}.permission", f"{_label.capitalize()}: permission",
        "out-of-path (not involved in what we test), permitted (it permits the test), or pending (still to be"
        " asked)", "enum", ("out-of-path", "permitted"), True,
        words={**_many("out-of-path", "out of path", "not involved", "not in the path", "uninvolved",
                       "not involved in what we test"),
               **_many("permitted", "permits", "permits it", "allowed", "allows", "allows it", "yes")},
        refuse=PERMISSION_REFUSE)
    FIELDS[f"platform.third_parties.{_name}.reference"] = _f(
        f"platform.third_parties.{_name}.reference", f"{_label.capitalize()}: where the permission is written",
        "a policy page, ticket, or e-mail id; required when permitted", open_words=True)

# What --set may change: plain answers only. The approval itself is never set
# this way: it must be typed at the prompt that says what typing it asserts.
SETTABLE = {name for name in FIELDS}

TARGET_FIELDS = (
    _f("name", "Target name", "a short lowercase name, e.g. edge or tls (letters, digits, -)",
       refuse=_not_a_name("target")),
    _f("address", "Target address", "ONE literal IP address the owner wrote down, e.g. 203.0.113.10 (no hostname)",
       "address"),
    _f("transport", "Transport", "udp, tcp, or tls", "enum", TRANSPORTS),
    _f("port", "Signaling port", "a whole number, e.g. 5060 (5061 for TLS)", "int"),
)
TLS_FIELDS = (
    _f("tls_server_name", "Name on the TLS certificate",
       "the DNS name the owner gave, e.g. sip.acme.tld (never looked up: packets go to the literal address)"),
    _f("tls_ca_file", "Private CA certificate file (optional)",
       "Enter when the certificate is from a public CA; else the owner's CA certificate saved under work/, "
       "e.g. work/acme/owner-ca.crt"),
)
DESTINATION_FIELDS = (
    _f("name", "Destination name", "a short lowercase name for it, e.g. echo or front-desk",
       refuse=_not_a_name("destination")),
    _f("target", "On which target", "one of the target names"),
    _f("user", "Exactly what to dial", "letters, digits and . _ + * # -, e.g. 9196 or echo"),
    _f("expect", "What it should do", "echo (echoes the audio), agent (answers as an agent), or reject", "enum",
       EXPECT_BEHAVIORS,
       words={**_many("echo", "echoes", "echo the audio", "echoes audio", "echoes the audio"),
              **_many("agent", "answers as an agent", "answer as an agent", "voice agent"),
              **_many("reject", "rejects", "reject the call", "rejects the call")}),
)
ADDRESSING_FIELDS = (
    _f("name", "Public name", "the DNS name, e.g. sip.acme.tld (an identity only, never looked up)", open_words=True),
    _f("addresses", "Addresses behind it", "literal IP addresses separated by commas", "addresses", open_words=True),
    _f("shared", "Shared with other customers of the provider?", "yes, no, or not sure", "bool", open_words=True),
    _f("changing", "Behind a load balancer or delivery network whose addresses change?", "yes, no, or not sure",
       "bool", open_words=True),
)
SURFACE_FIELDS = (
    _f("name", "Surface name", "a short lowercase name, e.g. admin-console", refuse=_not_a_name("surface")),
    _f("kind", "Used by", "browser (people in a browser), api (programs), or websocket (browser calling)", "enum",
       ("browser", "api", "websocket"),
       words={**_many("browser", "people", "people in a browser", "by people", "web"),
              **_many("api", "programs", "program", "by programs"),
              **_many("websocket", "web socket", "wss")}),
    _f("status", "In scope?", "yes, no, or not sure (in-scope / out-of-scope work too)", "enum",
       ("in-scope", "out-of-scope"), True, words=IN_OUT),
    _f("base_url", "Web address", "https://... (wss://... for a websocket); an identity, never looked up",
       open_words=True),
)
SURFACE_CONNECT_FIELDS = (
    _f("connect_address", "Connect to address", "one literal IP address (no hostname)", "address", open_words=True),
    _f("connect_port", "Connect to port", "a whole number, e.g. 443", "int", open_words=True),
    _f("tls_server_name", "Name on the TLS certificate", "a DNS name, e.g. admin.acme.tld", open_words=True),
    _f("tls_ca", "Certificate issued by", "public (a public authority) or private (the owner's own)", "enum",
       ("public", "private"), True,
       words={**_many("public", "public ca", "a public authority", "public authority",
                      "public certificate authority"),
              **_many("private", "own", "our own", "your own", "their own", "private ca", "self-signed",
                      "self signed", "by our own", "by your own")}),
)
SURFACE_CA_FIELD = _f("tls_ca_file", "Private CA certificate file",
                      "the owner's CA certificate saved under work/, e.g. work/acme/owner-ca.crt", open_words=True)
SURFACE_SOCKET_FIELDS = (
    _f("base_url", "WebSocket address", "wss://...", open_words=True),
    _f("allowed_origins", "Allowed origins", "https://... web sites separated by commas; none if none", "list",
       open_words=True),
)
IDENTITY_FIELDS = (
    _f("id", "Account label", "a short lowercase name, e.g. admin-test", refuse=_not_a_name("test account")),
    _f("role", "Role", "e.g. admin, reseller, customer-admin, user", open_words=True),
    _f("tenant", "Tenant or company", "the test tenant's label", open_words=True),
    _f("credential_ref", "Credential reference NAME (never the password)",
       "a NAME for its password, e.g. admin-test; the password itself is never written here", open_words=True),
)
REACH_FIELD_WORDS = {
    **_many("on-net", "on net", "stays", "stays inside", "stays on the platform", "inside", "internal",
            "on the platform", "inside the platform", "stays inside your platform"),
    **_many("pstn", "public", "public network", "public phone network", "goes out", "out", "leaves", "external",
            "goes out to the public phone network"),
}


def reach_field(name: str) -> Field:
    return _f(f"platform.dialing.reach.{name}", f"Destination {name}: where does the call go?",
              "on-net (stays inside the platform) or pstn (goes out to the public phone network)", "enum",
              ("on-net", "pstn"), True, words=REACH_FIELD_WORDS)


# ---------------------------------------------------------------- parsing


def _phrase(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower().replace("’", "'")).rstrip(".!")


def _split(raw: str, *, commas_only: bool = False) -> list[str]:
    parts = raw.split(",") if commas_only else re.split(r"[,\s]+", raw)
    return [part.strip() for part in parts if part.strip()]


def _number(text: str) -> Any:
    if re.fullmatch(r"[+-]?\d+", text):
        return int(text)
    if re.fullmatch(r"[+-]?\d+\.\d+", text):
        return float(text)
    return text


def interpret(spec: Field, raw: str, literal: bool = False) -> tuple[Any, str | None]:
    """Turn typed text into the YAML value and say what a mapped word became.

    Never refuses a value of the wrong shape: it is passed on as typed, so the
    refusal is the same one ``scope check`` gives. Raises ``Refused`` only for
    a word the prompt understands but cannot record (an ambiguous yes or no).
    """
    text = raw.strip()
    if literal and spec.kind == "text":
        return text, None  # typed after a backslash: exactly these characters
    phrase = _phrase(text)
    if spec.kind in ("list", "words", "dials") and phrase in ("y", "yes", "n") and not literal:
        empty = "none (or nothing)" if spec.kind in ("words", "dials") or spec.open_words else "Enter"
        raise Refused(f"that is a yes or no, and this asks for a list. Type the items separated by commas, or"
                      f" {empty} if there are none; to record the word itself, type a backslash before it")
    refusals = dict(spec.refuse)
    if phrase in refusals:
        raise Refused(refusals[phrase])
    if spec.open_words and phrase in OPEN_WORDS:
        return phrase, None
    if spec.open_words and phrase in OPEN_PHRASES:
        value = OPEN_PHRASES[phrase]
        meaning = "the owner does not know yet" if value == "unknown" else "still with the owner"
        return value, f"\"{text}\": recorded as {value}, an open answer ({meaning})"
    words = dict(spec.words)
    if phrase in words:
        value = copy.deepcopy(words[phrase])
        if spec.kind == "enumlist" and not isinstance(value, list):
            value = [value]  # one of the sheet's words for a list answer: a list of one
        return value, (None if show(value).lower() == phrase else f"\"{text}\" is recorded as {show(value)}")
    kind = spec.kind
    if kind == "int":
        return (int(text) if re.fullmatch(r"\d+", text) else text), None
    if kind == "number":
        return _number(text), None
    if kind == "bool":
        if phrase in ("y", "yes", "true"):
            return True, None
        if phrase in ("n", "no", "false"):
            return False, None
        return text, None
    if kind == "enum":
        return (phrase if phrase in spec.choices else text), None
    if kind == "enumlist":
        items = [item for item in (_split(text, commas_only=True) if "," in text else _split(text))
                 if _phrase(item) not in ("and", "&")]
        result = []
        for item in items:
            key = _phrase(item)
            if key in words:
                result.append(words[key])
            elif spec.choices == CODECS:
                result.append(item.upper())
            else:
                result.append(key if key in spec.choices else item)
        mapped = [show(value) for value in result] != [_phrase(item) if spec.choices != CODECS else item.upper()
                                                       for item in items]
        return result, (f"\"{text}\" is recorded as {render_inline(result)}" if mapped and result else None)
    if kind == "ints":
        return [int(item) if re.fullmatch(r"\d+", item) else item for item in _split(text)], None
    if kind in ("list", "addresses"):
        if spec.open_words and phrase in NONE_PHRASES:
            return ["none"], None if phrase == "none" else f"\"{text}\" is recorded as [none]"
        return _split(text), None
    if kind in ("words", "dials"):
        if phrase in NONE_PHRASES:
            return ["none"], (None if phrase == "none" else f"\"{text}\" is recorded as [none] (nothing)")
        return _split(text, commas_only=True), None
    return text, None


def parse(spec: Field, raw: str) -> Any:
    """The YAML value of a typed answer (see ``interpret``)."""
    try:
        return interpret(spec, raw)[0]
    except Refused:
        return raw.strip()


def parse_zone(text: str) -> timezone | Any:
    """A timezone: UTC, Z, an offset (+01:00), or an IANA name (Europe/Amsterdam)."""
    value = text.strip()
    if value.upper() in ("UTC", "Z", "GMT"):
        return timezone.utc
    match = re.fullmatch(r"(?:UTC)?([+-])(\d{1,2}):?(\d{2})?", value, re.I)
    if match:
        hours, minutes = int(match.group(2)), int(match.group(3) or 0)
        if hours <= 14 and minutes < 60:
            sign = 1 if match.group(1) == "+" else -1
            return timezone(sign * timedelta(hours=hours, minutes=minutes))
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    try:
        return ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError, OSError) as exc:
        raise ValueError(
            f"'{value}' is not a timezone I know; type a name such as Europe/Amsterdam or America/New_York, "
            "UTC, or an offset such as +01:00"
        ) from exc


def rfc3339(moment: datetime) -> str:
    text = moment.replace(microsecond=0).isoformat()
    return text[:-6] + "Z" if text.endswith("+00:00") else text


def parse_time(raw: str, zone: Any, *, now: datetime, start: datetime | None = None) -> Any:
    """A window end as RFC 3339 text; anything unrecognized is passed on as typed."""
    text = raw.strip()
    if text.lower() == "now":
        return rfc3339(now.astimezone(timezone.utc).replace(second=0))
    relative = re.fullmatch(r"\+\s*(\d+)\s*(h|m|d)", text.lower())
    if relative and start is not None:
        unit = {"h": "hours", "m": "minutes", "d": "days"}[relative.group(2)]
        return rfc3339(start + timedelta(**{unit: int(relative.group(1))}))
    candidate = text.replace("Z", "+00:00").replace("z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return text
    if parsed.tzinfo is None:
        if zone is None:
            return text
        parsed = parsed.replace(tzinfo=zone)
        # back to a fixed offset for that date (daylight saving time included)
        parsed = parsed.astimezone(timezone(parsed.utcoffset()))
    return rfc3339(parsed)


def show(value: Any) -> str:
    """The current value of an answer, in the file's own spelling."""
    if not present(value):
        return "not answered"
    if isinstance(value, str) and value in OPEN_WORDS:
        return f"{value} (open)"
    if isinstance(value, datetime):
        return rfc3339(value)
    if isinstance(value, str):
        return value
    return render_inline(value)


def _under(finding: Finding, paths: list[str]) -> bool:
    name = finding.field
    return any(name == path or name.startswith(path + ".") or name.startswith(path + "[") for path in paths)


def _key(finding: Finding) -> tuple[str, str, str]:
    return finding.code, finding.field, finding.message


@dataclass
class Outcome:
    rejected: list[Finding] = field(default_factory=list)
    conflicts: list[Finding] = field(default_factory=list)
    notes: list[Finding] = field(default_factory=list)


# ---------------------------------------------------------------- the file


class ScopeFile:
    """scope.yaml as text plus its parsed document; every write is atomic, 0600.

    Beside it, ``.scope.yaml.unfinished.json`` (mode 0600) names the lists
    (targets, destinations, ...) whose entry was interrupted: those questions
    stay open, and the next ``scope answer`` continues inside them. It exists
    only while such a list is unfinished.
    """

    def __init__(self, path: Path, *, now: Callable[[], datetime]) -> None:
        self.path = path
        self.now = now
        self.backup: Path | None = None
        report = inspect(path, now=now())
        if not report.present:
            raise ScopeError(f"no scope file at {path} (nothing was changed); create it with "
                             f"{LAUNCHER} scope init {shlex.quote(str(path.parent))}")
        if report.document is None:
            problems = "; ".join(
                f"{item.code} [{item.field or '-'}]: {item.message}" for item in report.errors)
            raise ScopeError(
                f"scope.yaml cannot be answered into while it is invalid (nothing was changed): {problems}. "
                f"Fix that line by hand, then run {LAUNCHER} scope check {shlex.quote(str(path.parent))}")
        self.raw = path.read_bytes()
        self.text = self.raw.decode("utf-8")
        self.document: dict[str, Any] = report.document
        self.report: Report = report
        self.baseline = document_findings(self.document, now=now())
        self.unfinished_path = path.with_name(f".{path.name}.unfinished.json")
        self.unfinished: dict[str, str] = read_unfinished(self.unfinished_path)

    def refresh(self) -> None:
        self.report = inspect(self.path, now=self.now())
        if self.report.document is not None:
            self.document = self.report.document
        self.baseline = document_findings(self.document, now=self.now())

    def candidate(self, edits: list[tuple[tuple[str, ...], Any]]) -> dict[str, Any]:
        document = copy.deepcopy(self.document)
        for path, value in edits:
            set_in(document, path, copy.deepcopy(value))
        return document

    def judge(self, edits: list[tuple[tuple[str, ...], Any]], focus: list[str]) -> Outcome:
        """Classify what the edits would add to the findings of scope check."""
        before = {_key(item) for item in self.baseline}
        outcome = Outcome()
        for finding in document_findings(self.candidate(edits), now=self.now()):
            if _key(finding) in before:
                continue
            if finding.severity != "error":
                outcome.notes.append(finding)
            elif finding.kind == "secret" or finding.code in ("scope.unknown_field", "scope.schema_version"):
                outcome.rejected.append(finding)
            elif finding.kind == "missing":
                continue
            elif finding.code in NOTE_CODES:
                outcome.notes.append(finding)
            elif _under(finding, focus):
                outcome.rejected.append(finding)
            else:
                outcome.conflicts.append(finding)
        return outcome

    def write(self, edits: list[tuple[tuple[str, ...], Any]], out: TextIO) -> list[tuple]:
        """Write the edits (with the approval rule applied); return what reset the approval."""
        edits, changes = reapproval(self.document, edits)
        current = self.path.read_bytes() if self.path.is_file() and not self.path.is_symlink() else None
        if current != self.raw:
            raise ChangedOnDisk(
                f"{self.path} changed on disk while answering (another editor?). Nothing more was written; "
                f"the answers recorded before are in the file. Run {LAUNCHER} scope answer "
                f"{shlex.quote(str(self.path.parent))} again to continue from the file as it is now")
        text, document, kept = apply_edits(self.text, self.document, edits, _UniqueLoader)
        if not kept:
            self._keep_backup(out)
        data = text.encode("utf-8")
        _atomic_write(self.path, data)
        self.raw = data
        self.text = text
        self.refresh()
        return changes

    def mark(self, collection: str, note: str | None) -> None:
        """Record (note) or clear (None) that a list's entry is unfinished."""
        if note is None:
            if self.unfinished.pop(collection, None) is None:
                return
        else:
            if self.unfinished.get(collection) == note:
                return
            self.unfinished[collection] = note
        if not self.unfinished:
            try:
                self.unfinished_path.unlink()
            except FileNotFoundError:
                pass
            return
        payload = {"schema": "sippycup.dev/scope-answer-unfinished/v1", "scope": self.path.name,
                   "lists": self.unfinished}
        _atomic_write(self.unfinished_path, (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode())

    def _keep_backup(self, out: TextIO) -> None:
        if self.backup is not None:
            return
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = self.path.with_name(f"{self.path.name}.bak-{stamp}")
        descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(self.raw)
            handle.flush()
            os.fsync(handle.fileno())
        self.backup = backup
        out.write(
            f"NOTE: this answer could not be written into the file's own layout, so scope.yaml is rewritten "
            f"as a whole and its comments are NOT kept. The previous file is kept as {backup} (mode 0600).\n")


def read_unfinished(path: Path) -> dict[str, str]:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    lists = value.get("lists") if isinstance(value, dict) else None
    if not isinstance(lists, dict):
        return {}
    return {str(key): str(note) for key, note in lists.items() if key in COLLECTIONS}


def _atomic_write(path: Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.answer-{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    try:
        directory = os.open(path.parent, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


# ---------------------------------------------------------------- questions


@dataclass(frozen=True)
class Item:
    """A question as the operator walks it: sheet number, text, handler."""

    number: str
    identifier: str
    section: str
    text: str
    details: tuple[str, ...]
    part: int
    sheet: Any


# The list questions: list path -> (question identifier, noun).
COLLECTIONS = {
    "targets": ("signaling.ports", "target"),
    "destinations": ("destinations", "destination"),
    "platform.addressing": ("P18", "public name"),
    "application.surfaces": ("A1", "surface"),
    "application.identities": ("A4", "test account"),
}
COLLECTION_OF = {identifier: path for path, (identifier, _) in COLLECTIONS.items()}


def items_for(document: dict[str, Any] | None) -> list[Item]:
    result = [
        Item(str(index), q.identifier, q.section, q.text,
             tuple(q.details()) if q.details else (), 1, q)
        for index, q in enumerate(QUESTIONS, 1)
    ]
    from .scope_app import APP_QUESTIONS, has_sections

    if has_sections(document):
        result += [Item(q.identifier, q.identifier, q.section, q.text, (f"   Why we ask: {q.why}",), 2, q)
                   for q in APP_QUESTIONS]
    return result


def item_state(report: Report, item: Item, unfinished: dict[str, str] | None = None) -> str:
    if item.part == 1:
        state = question_state(report, item.sheet)
    else:
        from .scope_app import app_question_state

        state = app_question_state(report.document or {}, item.sheet, report)
    if state == "answered" and unfinished and COLLECTION_OF.get(item.identifier) in unfinished:
        return "unanswered"
    return state


def walk_order(items: list[Item]) -> list[Item]:
    """Sheet order, except that the approval comes last, when what it approves is on screen."""
    return [item for item in items if item.identifier != "authorization.status"] + [
        item for item in items if item.identifier == "authorization.status"]


def find_item(items: list[Item], wanted: str) -> Item | None:
    """The question that asks ``wanted`` (a number, an id, or a field)."""
    token = wanted.strip()
    special = {"tls_server_name": "signaling.tls"}
    if token in special:
        token = special[token]
    for item in items:
        if token == item.number or token.upper() == item.number or token == item.identifier:
            return item
    root = re.sub(r"\[\d+\]|\.\d+(?=\.|$)", "", token)
    for path, (identifier, _) in COLLECTIONS.items():
        if root == path or root.startswith(path + "."):
            if path == "targets" and root.endswith((".tls_server_name", ".tls_ca_file")):
                identifier = "signaling.tls"
            return next((item for item in items if item.identifier == identifier), None)
    # a field path: the question that asks it
    for item in items:
        fields = getattr(item.sheet, "fields", ())
        if any(root == name or root.startswith(name + ".") for name in fields):
            return item
    return None


@dataclass
class Selection:
    """What one QUESTION argument names, exactly (finding: never more than that)."""

    item: Item
    kind: str  # question, collection, entry, fields, approval, window, range, checks, reach
    fields: tuple[str, ...] = ()
    collection: str = ""
    index: int | None = None
    key: str | None = None
    name: str = ""
    label: str = ""


_INDEXED = re.compile(r"^(?P<list>[a-z_.]+?)(?:\[(?P<i>\d+)\]|\.(?P<j>\d+))(?:\.(?P<key>[a-z_]+))?$")


def _entry_keys(collection: str) -> tuple[str, ...]:
    specs = {"targets": TARGET_FIELDS + TLS_FIELDS, "destinations": DESTINATION_FIELDS,
             "platform.addressing": ADDRESSING_FIELDS,
             "application.surfaces": SURFACE_FIELDS + SURFACE_CONNECT_FIELDS + (SURFACE_CA_FIELD,)
             + SURFACE_SOCKET_FIELDS[1:],
             "application.identities": IDENTITY_FIELDS}[collection]
    return tuple(dict.fromkeys(spec.path[-1] for spec in specs))


def resolve(items: list[Item], token: str, document: dict[str, Any]) -> list[Selection]:
    """Every Selection the QUESTION argument names, or [] when it names nothing this can open."""
    wanted = token.strip()
    by_id = {item.identifier: item for item in items}
    if wanted == "tls_server_name":
        wanted = "signaling.tls"
    for item in items:
        if wanted == item.number or wanted.upper() == item.number or wanted == item.identifier:
            kind = "approval" if item.identifier == "authorization.status" else "question"
            return [Selection(item, kind, label=f"question {item.number}")]
    if wanted in COLLECTIONS:
        identifier = COLLECTIONS[wanted][0]
        return [Selection(by_id[identifier], "collection", collection=wanted, label=wanted)] if identifier in by_id else []
    match = _INDEXED.match(wanted)
    if match and match.group("list") in COLLECTIONS:
        collection = match.group("list")
        identifier = COLLECTIONS[collection][0]
        if identifier not in by_id:
            return []
        index = int(match.group("i") if match.group("i") is not None else match.group("j"))
        key = match.group("key")
        rows = get_in(document, tuple(collection.split(".")))
        count = len(rows) if isinstance(rows, list) else 0
        if index >= count:
            raise ScopeError(
                f"{collection} has {count} entr{'y' if count == 1 else 'ies'}"
                + (f" ({collection}[0] to {collection}[{count - 1}], numbered from 0 as scope check prints them)"
                   if count else "")
                + f", so there is no {collection}[{index}] (nothing was changed). To add one: "
                f"scope answer DIR {collection} (then type add)")
        if key is not None and key not in _entry_keys(collection):
            raise ScopeError(f"a {COLLECTIONS[collection][1]} has no field '{key}' (nothing was changed); its fields"
                             f" are: {', '.join(_entry_keys(collection))}")
        item = by_id[identifier]
        if collection == "targets" and key in ("tls_server_name", "tls_ca_file") and "signaling.tls" in by_id:
            item = by_id["signaling.tls"]
        return [Selection(item, "entry", collection=collection, index=index, key=key, label=wanted)]
    if wanted == "authorization.status":
        return [Selection(by_id["authorization.status"], "approval", label=wanted)]
    if wanted in ("authorization.valid_from", "authorization.valid_until"):
        return [Selection(by_id["authorization.window"], "window", fields=(wanted.split(".")[-1],), label=wanted)]
    if wanted in ("media.port_range", "media.port_range.start", "media.port_range.end"):
        keys = ("start", "end") if wanted == "media.port_range" else (wanted.split(".")[-1],)
        return [Selection(by_id["media.ports"], "range", fields=keys, label=wanted)]
    if wanted in ("security_checks", "security_checks.approved", "security_checks.max_requests"):
        part = wanted.split(".")[-1] if "." in wanted else ""
        return [Selection(by_id["security_checks"], "checks", key=part or None, label=wanted)]
    if wanted.startswith("platform.dialing.reach.") and "P11" in by_id:
        return [Selection(by_id["P11"], "reach", name=wanted.rsplit(".", 1)[-1], label=wanted)]
    if wanted in ("platform.dialing.reach",) and "P11" in by_id:
        return [Selection(by_id["P11"], "question", label="question P11")]
    names = [name for name in FIELDS if name == wanted] or [name for name in FIELDS if name.startswith(wanted + ".")]
    if not names:
        return []
    if any(name.startswith(("platform.", "application.")) for name in names) and not any(
            item.part == 2 for item in items):
        return []
    groups: dict[str, list[str]] = {}
    for name in names:
        item = find_item(items, name)
        if item is not None:
            groups.setdefault(item.identifier, []).append(name)
    return [Selection(by_id[identifier], "fields", fields=tuple(fields), label=wanted)
            for identifier, fields in groups.items()]


def unknown_selection(token: str, items: list[Item]) -> ScopeError:
    part_two = any(item.part == 2 for item in items)
    head = token.strip().split(".")[0].split("[")[0]
    nearby = [name for name in FIELDS if name.split(".")[0] == head and (part_two or not name.startswith(
        ("platform.", "application.")))]
    candidates = list(FIELDS) + list(COLLECTIONS) + [item.identifier for item in items]
    close = difflib.get_close_matches(token.strip(), candidates, n=4, cutoff=0.6)
    lines = [f"nothing to open for '{token}' (nothing was changed). QUESTION can be: a question number"
             f" (1 to {len(QUESTIONS)}{', P1 to P18, A1 to A6' if part_two else ''}); a question id such as"
             " authorization.window or destinations; one field such as limits.calls or contact.channel; a list"
             " such as targets or destinations; or one entry of a list or one of its fields, numbered from 0 as"
             " scope check prints them, such as targets[0] or targets[0].address"]
    if close:
        lines.append("Did you mean: " + ", ".join(close))
    if nearby:
        lines.append(f"Fields under {head}: " + ", ".join(nearby[:16]) + (" ..." if len(nearby) > 16 else ""))
    return ScopeError(". ".join(lines))


# ---------------------------------------------------------------- session


HELP = (
    "At every prompt: Enter = the owner has not answered this yet (it stays open; nothing is invented),\n"
    "  ? or help = how to write a valid answer, clear = remove a recorded answer (the question is open again),\n"
    "  quit = stop here. Every accepted answer is saved at once, so quit, Ctrl-C, or Ctrl-D keeps them.\n"
    "  To record one of these words as an answer, type a backslash before it (\\help)."
)


class Session:
    def __init__(self, scope: ScopeFile, engagement: str, stdin: TextIO, stdout: TextIO, *,
                 interactive: bool, now: Callable[[], datetime]) -> None:
        self.scope = scope
        self.engagement = engagement
        self.stdin = stdin
        self.out = stdout
        self.interactive = interactive
        self.now = now
        self.recorded = 0
        self.noted: set[tuple[str, ...]] = set()
        self.asked_count = 0
        self.reapprove = False
        self.escaped = False
        # Output of the current question, held until its first prompt: a
        # question with nothing to ask prints no header at all.
        self.held: list[str] | None = None
        self.held_header = 0
        self.waiting: list[tuple[Item, list[str]]] = []
        # WARN lines an answer adds, held until the question ends: printed
        # between two prompts they read as a reaction to what was just typed.
        self.notes: list[Finding] = []
        # What is typed but not saved yet (half of an answer that is stored
        # whole); said when the session stops there.
        self.partial: str | None = None
        # The platform part of a walk: None until the operator was asked.
        self.walk_platform: bool | None = None

    # -- input and output

    def flush_notes(self) -> None:
        """Print the held WARN lines that still hold, each once per session."""
        notes, self.notes = self.notes, []
        current = {_key(item) for item in self.scope.baseline}
        notes = [item for item in notes if _key(item) in current]
        if not notes:
            return
        self.say("  scope check also notes after the answers above (not an error in what you typed; it is in the"
                 " summary too):")
        for finding in notes:
            self.say(f"    WARN {finding.code} [{finding.field}]: {finding.message}")

    def say(self, text: str = "") -> None:
        if self.held is not None:
            self.held.append(text)
            return
        self.out.write(text + "\n")
        self.out.flush()

    def _release(self) -> None:
        if self.held is not None:
            lines, self.held = self.held, None
            for line in lines:
                self.out.write(line + "\n")
            self.out.flush()

    def begin(self, item: Item, position: str, note: str = "") -> None:
        part = "" if item.part == 1 else " (part 2: the whole platform)"
        self.held = ["", f"== Question {item.number}{position}: {item.section}{part} ==", item.text, *item.details]
        if note:
            self.held.append(note)
        self.held_header = len(self.held)

    def end(self) -> list[str] | None:
        """Close the current question: None when it asked something, else what it would have said."""
        if self.held is None:
            return None
        lines = [line for line in self.held[self.held_header:] if line.strip()]
        self.held = None
        return lines

    def read(self, prompt: str = "  > ", *, help: str | None = None) -> str:
        """One typed line; quit raises Quit, end of input raises EOFError; ? and help print help."""
        self._release()
        while True:
            if self.interactive and self.stdin is sys.stdin and self.out is sys.stdout:
                try:
                    import readline  # noqa: F401  (line editing for input())
                except ImportError:
                    pass
                line = input(prompt) + "\n"  # raises EOFError on Ctrl-D
            else:
                self.out.write(prompt)
                self.out.flush()
                line = self.stdin.readline()
            if line == "":
                if not self.interactive:
                    self.say("(end of input)")
                raise EOFError
            answer = line.rstrip("\r\n")
            if not self.interactive:
                self.out.write(answer + "\n")
            typed = answer.strip()
            self.escaped = typed.startswith("\\")
            if self.escaped:
                return typed[1:].strip()
            lowered = typed.lower()
            if lowered in ("quit", "q", "exit"):
                raise Quit
            if lowered in ("?", "help"):
                if help:
                    self.say(f"    {help}")
                self.say(f"    ({RESERVED_HINT})")
                continue
            return typed

    def word(self, typed: str, *words: str) -> bool:
        """True when the operator typed one of these command words (not escaped with a backslash)."""
        return not self.escaped and typed.lower() in words

    def confirm(self, question: str) -> bool:
        while True:
            answer = self.read(f"  {question} [y/N] > ", help="Type y (yes) or n (no); Enter means no.").lower()
            if answer in ("", "n", "no"):
                return False
            if answer in ("y", "yes"):
                return True
            self.say("  Type y or n.")

    # -- one answer

    def explain(self, finding: Finding, typed: str | None, spec: Field | None = None) -> list[str]:
        lines = [f"  Not recorded: {finding.message} [{finding.field or '-'}]."]
        if finding.kind == "secret":
            lines.append("  That looks like a password, token, or key. scope.yaml holds only reference NAMES;"
                         " the secret itself never goes in it. Nothing was written.")
            return lines
        address_field = spec is not None and spec.kind in ADDRESS_KINDS
        if address_field and typed and any(
                HOSTNAME_PATTERN.fullmatch(word) and re.search(r"[A-Za-z]", word) and not _is_literal(word)
                and ("." in word.strip(".") or word.lower() == "localhost")
                for word in _split(typed)):
            lines.append("  That is a name, not an address. Sippycup sends only to the literal IP addresses the owner"
                         " wrote down, because a name can point somewhere else tomorrow. Ask the owner for the"
                         " numeric address(es) behind it; until then press Enter to leave the question open.")
        elif finding.code == "scope.media_ports_invalid":
            lines.append("  The first port must not be above the last (like the start and end of the window)."
                         f" Type a last port at or above the first, or change the first port: {LAUNCHER} scope"
                         f" answer {shlex.quote(self.engagement)} media.port_range")
        elif spec is not None and spec.kind in ("enum", "enumlist", "bool"):
            lines.append(f"    Valid: {spec.hint}{' (or pending / unknown)' if spec.open_words else ''}")
        return lines

    def changed_approval(self, changes: list[tuple]) -> None:
        if changes:
            self.reapprove = True
            self.say(f"  {reapprove_message(changes, self.engagement)}")

    def write(self, edits: list[tuple[tuple[str, ...], Any]]) -> None:
        self.changed_approval(self.scope.write(edits, self.out))

    def accept(self, edits: list[tuple[tuple[str, ...], Any]], focus: list[str], typed: str | None,
               spec: Field | None = None, meaning: str | None = None) -> bool | None:
        """Check edits with scope check's rules; write them when accepted.

        Returns True (written), False (rejected: ask again), None (the
        operator declined a conflicting answer: ask again).
        """
        edits, changes = reapproval(self.scope.document, edits)
        outcome = self.scope.judge(edits, focus)
        if outcome.rejected:
            for finding in outcome.rejected:
                for line in self.explain(finding, typed, spec):
                    self.say(line)
            self.say("  Please type it again (or press Enter to leave it open).")
            return False
        if outcome.conflicts:
            self.say("  This answer contradicts another recorded answer; scope check would report:")
            for finding in outcome.conflicts:
                self.say(f"    ERROR {finding.code} [{finding.field}]: {finding.message}")
            if not self.confirm("Record it anyway (then change the other answer)?"):
                self.say("  Not recorded.")
                return None
        before = {path: copy.deepcopy(get_in(self.scope.document, path)) for path, _ in edits}
        self.scope.write(edits, self.out)
        self.recorded += 1
        for path, value in edits:
            if path == STATUS_PATH and changes:
                continue
            old = before.get(path)
            if (isinstance(value, list) and isinstance(old, list) and len(old) == len(value)
                    and all(isinstance(entry, dict) for entry in value + old)):
                # one entry of a list changed: say which answers, not the whole list again
                changed = [(index, key, entry.get(key)) for index, (entry, was) in enumerate(zip(value, old))
                           for key in dict.fromkeys([*was, *entry]) if _canon(entry.get(key)) != _canon(was.get(key))]
                if changed and len(changed) <= 3:
                    for index, key, new in changed:
                        self.say(f"  Recorded {'.'.join(path)}[{index}].{key}: {show(new)}")
                    continue
            if isinstance(value, list) and value and all(isinstance(entry, dict) for entry in value):
                self.say(f"  Recorded {'.'.join(path)} ({len(value)}):")
                for entry in value:
                    self.say(f"    - {render_inline(entry)}")
            else:
                self.say(f"  Recorded {'.'.join(path)}: {show(value)}")
        if meaning:
            self.say(f"    ({meaning})")
        for finding in outcome.notes:
            if changes and finding.code == "scope.authorization_not_approved":
                continue
            # A running count of open answers changes its text with every answer: once per
            # session by code; every other note once by its text (the summary repeats them).
            seen = (finding.code, finding.field) if finding.code in PROGRESS_NOTES else _key(finding)
            if seen in self.noted:
                continue
            self.noted.add(seen)
            if finding.severity == "error":
                self.say(f"  NOTE {finding.code} [{finding.field}]: {finding.message}")
            else:
                self.notes.append(finding)  # shown when the question ends (flush_notes)
        self.changed_approval(changes)
        return True

    def ask(self, spec: Field, *, path: tuple[str, ...] | None = None, focus: str | None = None,
            current: Any = None, has_current: bool = False, build: Callable[[Any], list] | None = None,
            only_open: bool = False) -> Any:
        """Ask one field until a valid answer or Enter. Returns the recorded value or None."""
        where = path or spec.path
        dotted = focus or ".".join(where)
        value_now = current if has_current else get_in(self.scope.document, where)
        if only_open and present(value_now) and value_now not in OPEN_WORDS and not self._has_error(dotted):
            return value_now
        open_note = " (or pending / unknown)" if spec.open_words else ""
        valid = f"Valid: {spec.hint}{open_note}"
        self.asked_count += 1
        self.say(f"  {spec.label}  [{dotted}]")
        self.say(f"    {valid}")
        self.say(f"    Current: {show(value_now)}")
        hook = FIELD_HOOKS.get(spec.dotted) if build is None else None
        while True:
            typed = self.read(help=valid)
            if typed == "":
                self.say("    Left as it is." if present(value_now) else "    Left open: the owner has not answered.")
                return value_now if present(value_now) else None
            if self.word(typed, "clear"):
                value = [] if isinstance(value_now, list) else None
                edits = build(value) if build else [(where, value)]
                self.write(edits)
                self.say(f"  Cleared {dotted}: the question is open again.")
                return None
            try:
                value, meaning = interpret(spec, typed, self.escaped)
            except Refused as exc:
                self.say(f"  Not recorded: {exc}.")
                self.say(f"    {valid}")
                continue
            edits = build(value) if build else [(where, value)]
            if hook is not None:
                extra = hook(self, spec, typed, value)
                if extra is None:
                    continue
                edits += extra
            result = self.accept(edits, [dotted], typed, spec, meaning)
            if result:
                return value

    def _has_error(self, dotted: str) -> bool:
        return any(item.severity == "error" and item.kind != "missing" and item.code not in NOTE_CODES
                   and _under(item, [dotted])
                   for item in self.scope.baseline)

    def run_item(self, item: Item, *, only_open: bool) -> None:
        handler = HANDLERS.get(item.identifier)
        if handler is not None:
            handler(self, item, only_open)
            return
        for name in getattr(item.sheet, "fields", ()):
            spec = FIELDS.get(name)
            if spec is not None:
                self.ask(spec, only_open=only_open)


def _is_literal(text: str) -> bool:
    try:
        ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False
    return True


# ------------------------------------------------------------- field hooks
#
# A hook runs after a typed answer is understood and before it is checked. It
# returns more edits to record with it, or None to ask again (it said why).


def _password_file_match(session: Session, typed: str) -> bool:
    candidate = Path(session.engagement) / "account.password"
    try:
        if candidate.is_file() and not candidate.is_symlink() and candidate.stat().st_size <= 4096:
            secret = candidate.read_bytes().strip()
            return bool(secret) and secret == typed.strip().encode("utf-8")
    except OSError:
        return False
    return False


def _credential_hook(session: Session, spec: Field, typed: str, value: Any) -> list | None:
    if _password_file_match(session, typed):
        session.say("  Not recorded: that is the password from account.password. Type a NAME for it instead,"
                    " e.g. acme-password. Nothing was written.")
        return None
    return []


def _never_touch_hook(session: Session, spec: Field, typed: str, value: Any) -> list | None:
    if value != ["none"]:
        return []
    environment = get_in(session.scope.document, ("platform", "environment")) or {}
    kind, customers = environment.get("kind"), environment.get("real_customers")
    live = kind == "production" or customers is True
    if not live and kind in ("staging", "dedicated-test"):
        return []
    why = ("this scope records a production system" if kind == "production" else
           "this scope records that real customers use it" if customers is True else
           "the environment is not recorded yet, so it is treated as production")
    session.say(f"  'none' says the system holds NO real data, so no data is off-limits to the tests. The sheet asks"
                f" for none only in that case, and {why}. On a system with real data the tests stop before they"
                " would touch anything on this list, so an empty list protects nothing.")
    if session.confirm("Did the owner confirm in writing that the system holds no real data?"):
        return []
    session.say("  Not recorded. Ask the owner which data must be left alone (for example real voicemail, call"
                " recordings, call records, customer accounts), or press Enter to leave it open.")
    return None


def _provider_hook(session: Session, spec: Field, typed: str, value: Any) -> list | None:
    if value != "none":
        return []
    name = spec.path[2]
    session.say("    There is no such company, so it is not involved in what we test: its permission is recorded"
                " as out-of-path with it.")
    return [(("platform", "third_parties", name, "permission"), "out-of-path")]


FIELD_HOOKS: dict[str, Callable[[Session, Field, str, Any], list | None]] = {
    "account.credential_ref": _credential_hook,
    "platform.environment.never_touch": _never_touch_hook,
}
for _name in ("hosting", "cdn_waf", "pstn_carrier", "sms", "email"):
    FIELD_HOOKS[f"platform.third_parties.{_name}.provider"] = _provider_hook


# ---------------------------------------------------------------- handlers


def _simple(*names: str) -> Callable[[Session, Item, bool], None]:
    def handler(session: Session, item: Item, only_open: bool) -> None:
        for name in names:
            session.ask(FIELDS[name], only_open=only_open)

    return handler


def _ask_field(session: Session, name: str, only_open: bool = False) -> Any:
    return session.ask(FIELDS[name], only_open=only_open)


def _window(session: Session, item: Item, only_open: bool, wanted: tuple[str, ...] | None = None) -> None:
    document = session.scope.document
    auth = document.get("authorization") if isinstance(document.get("authorization"), dict) else {}
    keys = [key for key in ("valid_from", "valid_until")
            if (wanted is None or key in wanted)
            and (not only_open or not present(auth.get(key)) or session._has_error(f"authorization.{key}"))]
    if not keys:
        return
    session.say("  The window is asked in parts: the timezone the owner used, then "
                + ("the start and the end." if len(keys) == 2 else f"the {'start' if keys == ['valid_from'] else 'end'}."))
    session.say("    Timezone  [not stored; used to turn the owner's times into RFC 3339 with an offset]")
    zone_help = ("Valid: a name such as Europe/Amsterdam, UTC, or an offset such as +01:00;"
                 " Enter when the times below carry their own offset")
    session.say(f"    {zone_help}")
    zone = None
    while True:
        typed = session.read(help=zone_help)
        if typed == "":
            break
        try:
            zone = parse_zone(typed)
            break
        except ValueError as exc:
            session.say(f"  {exc}")
    focus = ["authorization.valid_from", "authorization.valid_until"]
    held: list[tuple[tuple[str, ...], Any]] = []
    start: datetime | None = None
    current_start = auth.get("valid_from")
    for key, label, example in (
            ("valid_from", "Start of the window", "2026-12-01 09:00 (in the timezone above), or with an offset"
                                                   " 2026-12-01T09:00:00+01:00; practice: now"),
            ("valid_until", "End of the window", "2026-12-01 17:00, or relative to the start: +8h; practice: +4h")):
        if key not in keys:
            continue
        if key == "valid_until" and start is None and current_start is not None:
            start = _as_datetime(get_in(session.scope.document, ("authorization", "valid_from")))
        spec = Field(("authorization", key), label, example, "time")

        def convert(typed: str, _key: str = key) -> Any:
            return parse_time(typed, zone, now=session.now(), start=start if _key == "valid_until" else None)

        session.say(f"  {label}  [authorization.{key}]")
        session.say(f"    Valid: {example}")
        session.say(f"    Current: {show(auth.get(key))}")
        while True:
            typed = session.read(help=f"Valid: {example}")
            if typed == "":
                session.say("    Left as it is." if present(auth.get(key)) else
                            "    Left open: the owner has not answered.")
                break
            if session.word(typed, "clear"):
                session.write([(spec.path, None)])
                session.say(f"  Cleared authorization.{key}.")
                break
            value = convert(typed)
            if zone is None and _naive(typed):
                session.say("  Not recorded: this time has no timezone, and none was given above. Type it with"
                            " its offset as the owner meant it, e.g. 2026-12-01T09:00:00+01:00 (or ...Z for UTC).")
                continue
            moment = _as_datetime(value)
            if moment is not None:
                session.say(f"    = {moment.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC")
            edits = held + [(spec.path, value)]
            if key == "valid_from" and "valid_until" in keys:
                # The old end may precede the new start; the order is checked
                # with the new end, so hold a start that only fails that rule.
                outcome = session.scope.judge(edits, focus)
                if outcome.rejected and all(f.code == "scope.window_order" for f in outcome.rejected):
                    held = edits
                    start = moment
                    session.partial = "the start of the window was not saved: the end is needed too"
                    session.say("    (checked together with the end, which comes next)")
                    break
            result = session.accept(edits, focus, typed)
            if result:
                held = []
                if key == "valid_from":
                    start = moment
                break
        auth = {**(session.scope.document.get("authorization") or {}),
                **{path[-1]: value for path, value in held}}
    if held:
        session.say("  The start was not recorded: the end that goes with it was not given.")


def _range(session: Session, item: Item, only_open: bool, wanted: tuple[str, ...] | None = None) -> None:
    """Question 13: the first and last media port, refused when reversed (like the window)."""
    current = get_in(session.scope.document, ("media", "port_range"))
    current = current if isinstance(current, dict) else {}
    keys = [key for key in ("start", "end") if (wanted is None or key in wanted) and (
        not only_open or not present(current.get(key)) or session._has_error("media.port_range"))]
    focus = ["media.port_range"]
    held: list[tuple[tuple[str, ...], Any]] = []
    for key in keys:
        spec = FIELDS[f"media.port_range.{key}"]
        valid = f"Valid: {spec.hint}"
        session.say(f"  {spec.label}  [media.port_range.{key}]")
        session.say(f"    {valid}")
        session.say(f"    Current: {show(get_in(session.scope.document, spec.path))}")
        while True:
            typed = session.read(help=valid)
            if typed == "":
                now_value = get_in(session.scope.document, spec.path)
                session.say("    Left as it is." if present(now_value) else "    Left open: the owner has not answered.")
                break
            if session.word(typed, "clear"):
                session.write([(spec.path, None)])
                session.say(f"  Cleared media.port_range.{key}: the question is open again.")
                break
            both = re.fullmatch(r"(\d+)\s*(?:-|to|until|through)\s*(\d+)", typed.strip(), re.IGNORECASE)
            if key == "start" and both and not session.escaped:
                # the whole range at the first prompt, as the sheet asks for it ("10000 to 20000")
                first, last = int(both.group(1)), int(both.group(2))
                session.say(f"    = first port {first}, last port {last} (both are recorded together)")
                if session.accept([(spec.path, first), (FIELDS["media.port_range.end"].path, last)], focus, typed,
                                  spec):
                    return
                continue
            value = parse(spec, typed)
            edits = held + [(spec.path, value)]
            if key == "start" and "end" in keys:
                outcome = session.scope.judge(edits, focus)
                if outcome.rejected and all(f.code == "scope.media_ports_invalid" for f in outcome.rejected):
                    held = edits
                    session.partial = "the first media port was not saved: the last port is needed too"
                    session.say("    (checked together with the last port, which comes next)")
                    break
            if session.accept(edits, focus, typed, spec):
                held = []
                break
    if held:
        session.say("  The first port was not recorded: the last port that goes with it was not given.")


def _naive(typed: str) -> bool:
    try:
        parsed = datetime.fromisoformat(typed.strip())
    except ValueError:
        return False
    return parsed.tzinfo is None


def _as_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else None
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else None
    return None


# ------------------------------------------------------------- the approval


def _grants(item: Item) -> bool:
    names = getattr(item.sheet, "fields", ())
    return any(name in APPROVAL_FACTS or any(name == grant or name.startswith(grant + ".") or grant.startswith(
        name + ".") for grant in GRANTS) for name in names)


def approval_blockers(report: Report, unfinished: dict[str, str]) -> tuple[list[Item], list[Item]]:
    """(open part-1 questions the approval approves, open part-1 questions that grant nothing)."""
    pending = [item for item in open_items(report, unfinished)
               if item.part == 1 and item.identifier not in OPTIONAL_QUESTIONS
               and item.identifier != "authorization.status"]
    return [item for item in pending if _grants(item)], [item for item in pending if not _grants(item)]


def _numbers(items: list[Item]) -> str:
    return ", ".join(f"{item.number} ({item.section.lower()})" for item in items)


def _yes_no(value: Any) -> str:
    return {True: "yes", False: "no"}.get(value, show(value)) if isinstance(value, bool) else show(value)


def approval_summary(document: dict[str, Any]) -> list[str]:
    """What typing approved asserts, compactly, from the file as it is."""
    def at(dotted: str) -> Any:
        return get_in(document, tuple(dotted.split(".")))

    def listing(value: Any) -> str:
        if not present(value):
            return "not answered"
        return ", ".join(str(item) for item in value) if isinstance(value, list) else show(value)

    auth = at("authorization") or {}
    lines = [f"Approval: reference {show(auth.get('approval_id'))}, approved by {show(auth.get('approved_by'))}"]
    start, end = _as_datetime(auth.get("valid_from")), _as_datetime(auth.get("valid_until"))
    window = f"Window: {show(auth.get('valid_from'))} to {show(auth.get('valid_until'))}"
    if start and end:
        window += (f" (UTC {start.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M')} to"
                   f" {end.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M')})")
    lines.append(window)
    lines.append(f"Signaling: to {listing(at('signaling.networks'))}; ports {listing(at('signaling.ports'))};"
                 f" transports {listing(at('signaling.transports'))}")
    targets = [row for row in at("targets") or [] if isinstance(row, dict)]
    lines.append(f"Targets ({len(targets)}): " + ("; ".join(_describe_target(row) for row in targets)
                                                 if targets else "none recorded"))
    destinations = [row for row in at("destinations") or [] if isinstance(row, dict)]
    lines.append(f"Destinations ({len(destinations)}): " + ("; ".join(_describe_destination(row)
                                                                      for row in destinations)
                                                           if destinations else "none recorded"))
    if at("account.required") is True:
        lines.append(f"Account: {show(at('account.username'))}, realm {show(at('account.realm'))}, password"
                     f" reference {show(at('account.credential_ref'))}")
    elif at("account.required") is False:
        lines.append("Account: none (calls need no account)")
    else:
        lines.append("Account: not answered")
    port_range = at("media.port_range") or {}
    lines.append(f"Media: to {listing(at('media.networks'))}; far-end ports {show(port_range.get('start'))} to"
                 f" {show(port_range.get('end'))}; {listing(at('media.protection'))}; codecs"
                 f" {listing(at('media.codecs'))}")
    limits = at("limits") or {}
    lines.append(f"Limits: {show(limits.get('calls'))} calls ({show(limits.get('concurrent_calls'))} at once,"
                 f" {show(limits.get('calls_per_second'))} per second); {show(limits.get('packets_per_second'))}"
                 f" packets/s, {show(limits.get('packets'))} packets, {show(limits.get('bytes'))} bytes;"
                 f" {show(limits.get('call_duration_seconds'))} s per call,"
                 f" {show(limits.get('total_duration_seconds'))} s in all")
    stops = at("stop_conditions") or {}
    lines.append(f"Stop: after {show(stops.get('consecutive_failures'))} failures in a row; on any unexpected"
                 f" response: {_yes_no(stops.get('unexpected_response'))}; above"
                 f" {show(stops.get('packet_loss_percent'))}% packet loss")
    lines.append(f"Test classes: {listing(at('test_scope.allowed_classes'))}; excluded:"
                 f" {listing(at('test_scope.exclusions'))}")
    checks = at("security_checks")
    if isinstance(checks, dict) and checks.get("approved"):
        lines.append(f"Security checks: {listing(checks.get('approved'))}, at most"
                     f" {show(checks.get('max_requests'))} requests")
    else:
        lines.append("Security checks: none approved")
    # The platform answers that matter for sending a call: where each
    # destination goes (scope check warns about each one that is not recorded).
    if isinstance(at("platform"), dict):
        dialing = at("platform.dialing") if isinstance(at("platform.dialing"), dict) else {}
        reach = dialing.get("reach") if isinstance(dialing.get("reach"), dict) else {}
        names = [str(row.get("name")) for row in destinations if isinstance(row.get("name"), str)]
        names += [str(name) for name in reach if name not in names]
        where = {"on-net": "stays on the platform", "pstn": "REACHES THE PUBLIC PHONE NETWORK"}
        unrecorded = [name for name in names if reach.get(name) not in where]
        reach_text = "; ".join(
            f"{name}: {where.get(reach.get(name)) or 'NOT RECORDED' + (f' ({reach[name]})' if present(reach.get(name)) else '')}"
            for name in names) or "no destinations recorded"
        lines.append(f"Platform dialing (questions P11 to P13): {reach_text}")
        lines.append(f"  never dial: {listing(dialing.get('never_dial'))}; cost of public-network calls (toll):"
                     f" {show(dialing.get('toll'))}")
        if unrecorded:
            lines.append(f"  NOT RECORDED = the owner has not said whether {', '.join(unrecorded)}"
                         f" stay{'s' if len(unrecorded) == 1 else ''} on the platform or"
                         f" reach{'es' if len(unrecorded) == 1 else ''} the public phone network. scope check warns"
                         " about it and the approval covers dialing it all the same: ask the owner first")
    carrier = at("platform.third_parties.pstn_carrier")
    calls = at("platform.operations.max_concurrent_calls")
    if isinstance(carrier, dict) and present(carrier.get("provider")) or present(calls):
        who = carrier.get("provider") if isinstance(carrier, dict) else None
        lines.append(f"Platform: phone carrier {show(who)}"
                     f" ({show(carrier.get('permission') if isinstance(carrier, dict) else None)});"
                     f" at most {show(calls)} calls at once on the live system")
    surfaces = [row for row in (at("application.surfaces") or []) if isinstance(row, dict)]
    if surfaces:
        lines.append(f"Surfaces ({len(surfaces)}): " + "; ".join(
            f"{show(row.get('name'))}: {show(row.get('status'))}, {show(row.get('connect_address'))}"
            f" port {show(row.get('connect_port'))}" for row in surfaces))
    return lines


def _approval(session: Session, item: Item, only_open: bool) -> None:
    auth = session.scope.document.get("authorization") or {}
    status = auth.get("status")
    if only_open and status == "approved":
        return
    blockers, later = approval_blockers(session.scope.report, session.scope.unfinished)
    if only_open and blockers:
        # Not asked while the scope it approves is incomplete: any of these
        # answers would set it back to pending at once.
        session.say(f"  The approval is asked once the answers it approves are recorded; still open: "
                    f"{_numbers(blockers)}.")
        return
    session.say("  Approval status  [authorization.status]")
    session.say(f"    Current: {status if present(status) else 'not answered'}")
    session.say("    Typing approved records authorization.status: approved and ASSERTS that the owner approved")
    session.say("    in writing exactly this scope, as recorded now:")
    for line in approval_summary(session.scope.document):
        session.say(f"      {line}")
    session.say("    Type the word approved ONLY if you hold the owner's written approval of all of the above.")
    session.say("    Any later change to what may be sent sets it back to pending, and it is asked again.")
    window_end = _as_datetime(auth.get("valid_until"))
    if window_end is not None and session.now() >= window_end:
        session.say("    NOTE: the window above has ended, so nothing can be sent with this approval whatever is"
                    " typed here. A new window sets the approval back to pending: record the owner's new window"
                    f" first ({LAUNCHER} scope answer {shlex.quote(session.engagement)} authorization.window),"
                    " then the approval.")
    session.say("    Other answers: pending (not approved yet), revoked (the owner withdrew it),"
                " Enter = leave it as it is.")
    valid = "Valid: approved, pending, or revoked (the word itself; yes is not enough)"
    while True:
        typed = session.read(help=valid)
        if typed == "":
            session.say("    Left as it is." if present(status) else "    Left open.")
            return
        word = typed.lower()
        if word not in AUTH_STATUSES or session.escaped:
            session.say("  Not recorded: type approved, pending, or revoked (the word itself; yes is not enough).")
            continue
        if word == "approved":
            missing = [label for key, label in (("approval_id", "the reference of the written approval"),
                                                ("approved_by", "who approved it"),
                                                ("valid_from", "the start of the window"),
                                                ("valid_until", "the end of the window"))
                       if not present(auth.get(key))]
            if missing:
                session.say("  Not recorded: record " + ", ".join(missing) + " first (questions 1 and 3), so the"
                            " approval you assert names who, which document, and when.")
                return
            if blockers:
                session.say(f"  Not recorded: the approval approves what the file says may be sent, and"
                            f" {_numbers(blockers)} {'is' if len(blockers) == 1 else 'are'} still open. Recording"
                            " it now would assert approval of answers nobody has seen, and the next of those"
                            " answers would set it back to pending anyway. Answer them first: "
                            f"{LAUNCHER} scope answer {shlex.quote(session.engagement)}  (the approval is asked"
                            " last).")
                return
        if session.accept([(STATUS_PATH, word)], ["authorization.status"], typed):
            session.reapprove = False
            if word == "approved" and later:
                session.say(f"  Still open: {_numbers(later)}. They grant nothing, but scope check is not clean"
                            " until they are answered, and until then scope compile writes the profile as pending:"
                            " nothing can be sent.")
            return


# ------------------------------------------------------------- collections


def _collection(session: Session, *, path: tuple[str, ...], noun: str, fields: Callable[[dict], tuple[Field, ...]],
                only_open: bool, answered: bool, describe: Callable[[dict], str],
                announce: Callable[[Session, Field], None] | None = None,
                defaults: Callable[[dict, list[dict], Field], tuple[Any, str] | None] | None = None,
                prune: Callable[[dict], dict] | None = None) -> None:
    """Ask a list of mappings (targets, destinations, ...) entry by entry, field by field.

    ``fields(entry)`` may depend on what is typed so far (a TLS target has
    more fields). An entry is written only when it is complete. While a list
    is being added to, the unfinished marker is set: an interruption leaves the
    question open, and the next session continues inside it.
    """
    dotted = ".".join(path)
    current = get_in(session.scope.document, path)
    entries = [dict(item) for item in current if isinstance(item, dict)] if isinstance(current, list) else []
    resume = dotted in session.scope.unfinished
    if resume and not entries:
        session.scope.mark(dotted, None)
        resume = False
    if entries:
        session.say(f"  Recorded {noun}s:")
        for index, entry in enumerate(entries):
            session.say(f"    {index + 1}. {describe(entry)}")
    if resume:
        session.say(f"  The last session stopped while {noun}s were being added, so this question is still open."
                    f" Continue with {noun} {len(entries) + 1}; press Enter at its first field when there are no"
                    f" more {noun}s.")
    elif only_open and answered:
        return
    elif entries:
        session.say(f"  Enter = keep them; add = add another {noun}; edit N = change {noun} N; remove N = remove"
                    f" {noun} N; redo = enter all {noun}s again; clear = remove them (the question is open again)")
        menu_help = "Type Enter, add, edit N, remove N, redo, or clear (N is the number shown above)."
        while True:
            choice = session.read(help=menu_help)
            words = choice.lower().split()
            if choice == "":
                session.say("    Left as it is.")
                return
            if session.word(choice, "clear"):
                session.write([(path, [])])
                session.scope.mark(dotted, None)
                session.say(f"  Cleared {dotted}: the question is open again.")
                return
            if len(words) == 2 and words[0] in ("edit", "remove") and words[1].isdigit() and (
                    1 <= int(words[1]) <= len(entries)):
                index = int(words[1]) - 1
                if words[0] == "edit":
                    _edit_entry(session, path=path, noun=noun, fields=fields, index=index, prune=prune)
                else:
                    remaining = entries[:index] + entries[index + 1:]
                    if session.accept([(path, remaining)], [dotted], None):
                        session.say(f"  Removed {noun} {index + 1} ({describe(entries[index])}).")
                return
            if words and words[0] in ("edit", "remove"):
                session.say(f"  Type {words[0]} and a number from 1 to {len(entries)}, e.g. {words[0]} 1.")
                continue
            if choice.lower() in ("add", "redo"):
                break
            session.say(f"  {menu_help}")
        if choice.lower() == "redo":
            entries = []
            session.say(f"  The recorded {noun}s are replaced when the first new one is complete.")
    replacing = bool(current) and not entries
    while True:
        index = len(entries)
        if entries or replacing:
            session.scope.mark(dotted, f"adding {noun} {index + 1}")
        session.say(f"  -- {noun} {index + 1} --")
        entry: dict[str, Any] = {}
        position = 0
        while position < len(fields(entry)):
            spec = fields(entry)[position]
            first = position == 0
            position += 1
            key = spec.path[-1]
            focus = f"{dotted}[{index}].{key}"
            optional = spec.label.endswith("(optional)")
            if announce is not None:
                announce(session, spec)
            offered = defaults(entry, entries, spec) if defaults is not None else None
            valid = f"Valid: {spec.hint}{' (or pending / unknown)' if spec.open_words else ''}"
            session.say(f"  {spec.label}  [{focus}]")
            session.say(f"    {valid}")
            if offered is not None:
                session.say(f"    Enter = {show(offered[0])} ({offered[1]})")
            while True:
                typed = session.read(help=valid)
                if typed == "" and offered is not None:
                    value, meaning = offered[0], None
                elif typed == "":
                    break
                else:
                    try:
                        value, meaning = interpret(spec, typed, session.escaped)
                    except Refused as exc:
                        session.say(f"  Not recorded: {exc}.")
                        continue
                trial = {**entry, key: value}
                outcome = session.scope.judge([(path, entries + [trial])], [focus])
                if outcome.rejected:
                    for finding in outcome.rejected:
                        for line in session.explain(finding, typed, spec):
                            session.say(line)
                    session.say("  Please type it again (or press Enter if the owner has not answered).")
                    continue
                entry[key] = value
                session.partial = (f"{noun} {index + 1} was not saved ({', '.join(entry)} typed): a {noun} is"
                                   " saved when all its fields are answered")
                if meaning:
                    session.say(f"    ({meaning})")
                break
            if key not in entry and not optional:
                session.partial = None
                if first and (entries or replacing):
                    session.scope.mark(dotted, None)
                    session.say(f"    No more {noun}s: the list is complete as recorded.")
                    return
                session.say(f"    The owner has not answered this, so this {noun} is not recorded (nothing is"
                            " invented). The question stays open"
                            + (": the next scope answer continues here." if entries or replacing else "."))
                return
        candidate = entries + [entry]
        result = session.accept([(path, candidate)], [dotted], None)
        if not result:
            session.say(f"  This {noun} was not recorded. Enter it again, or press Enter at its first field to stop.")
            continue
        entries = candidate
        replacing = False
        session.partial = None
        session.scope.mark(dotted, f"asking whether there is another {noun}")
        if not session.confirm(f"Another {noun}?"):
            session.scope.mark(dotted, None)
            return


def _collection_spec(collection: str, session: Session) -> tuple[Callable[[dict], tuple[Field, ...]], str,
                                                                 Callable[[dict], dict] | None]:
    """(fields, noun, prune) of one list, for editing one entry."""
    noun = COLLECTIONS[collection][1]
    if collection == "targets":
        return _target_fields, noun, _prune_target
    if collection == "destinations":
        return _destination_fields(session), noun, None
    if collection == "platform.addressing":
        return (lambda entry: ADDRESSING_FIELDS), noun, None
    if collection == "application.surfaces":
        def surface(entry: dict) -> tuple[Field, ...]:
            extra = (SURFACE_CA_FIELD,) if entry.get("tls_ca") == "private" else ()
            sockets = SURFACE_SOCKET_FIELDS[1:] if entry.get("kind") == "websocket" else ()
            return SURFACE_FIELDS + SURFACE_CONNECT_FIELDS + extra + sockets
        return surface, noun, None
    return (lambda entry: IDENTITY_FIELDS), noun, None


def _edit_entry(session: Session, *, path: tuple[str, ...], noun: str, fields: Callable[[dict], tuple[Field, ...]],
                index: int, prune: Callable[[dict], dict] | None = None, only: str | None = None) -> None:
    """Change one entry of a list, field by field (Enter keeps each); only ``only`` when given."""
    dotted = ".".join(path)
    rows = [dict(row) for row in get_in(session.scope.document, path) or [] if isinstance(row, dict)]
    entry = dict(rows[index])
    session.say(f"  Changing {noun} {index + 1} [{dotted}[{index}]]: Enter keeps each answer as it is.")
    position = 0
    changed = False
    while position < len(fields(entry)):
        spec = fields(entry)[position]
        position += 1
        key = spec.path[-1]
        if only is not None and key != only:
            continue
        focus = f"{dotted}[{index}].{key}"
        optional = spec.label.endswith("(optional)")
        valid = f"Valid: {spec.hint}{' (or pending / unknown)' if spec.open_words else ''}"
        session.say(f"  {spec.label}  [{focus}]")
        session.say(f"    {valid}")
        session.say(f"    Current: {show(entry.get(key))}")
        while True:
            typed = session.read(help=valid)
            if typed == "":
                break
            if session.word(typed, "clear"):
                if not optional and key != "target":
                    session.say(f"  A {noun} needs this answer; to remove the whole {noun}, use remove"
                                f" {index + 1} at {dotted}.")
                    continue
                entry.pop(key, None)
                changed = True
                break
            try:
                value, meaning = interpret(spec, typed)
            except Refused as exc:
                session.say(f"  Not recorded: {exc}.")
                continue
            trial = {**entry, key: value}
            outcome = session.scope.judge([(path, rows[:index] + [trial] + rows[index + 1:])], [focus])
            if outcome.rejected:
                for finding in outcome.rejected:
                    for line in session.explain(finding, typed, spec):
                        session.say(line)
                session.say("  Please type it again (or press Enter to keep it).")
                continue
            entry[key] = value
            changed = True
            if meaning:
                session.say(f"    ({meaning})")
            break
    if prune is not None:
        entry = prune(entry)
    if not changed or entry == rows[index]:
        session.say(f"    {noun.capitalize()} {index + 1} is unchanged.")
        return
    session.accept([(path, rows[:index] + [entry] + rows[index + 1:])], [f"{dotted}[{index}]"], None)


def _describe_target(entry: dict) -> str:
    text = f"{entry.get('name')}: {entry.get('address')} {entry.get('transport')} port {entry.get('port')}"
    if entry.get("tls_server_name"):
        text += f", certificate name {entry['tls_server_name']}"
    if entry.get("tls_ca_file"):
        text += f", CA {entry['tls_ca_file']}"
    return text


def _target_fields(entry: dict) -> tuple[Field, ...]:
    return TARGET_FIELDS + (TLS_FIELDS if entry.get("transport") == "tls" else ())


def _prune_target(entry: dict) -> dict:
    if entry.get("transport") != "tls":
        return {key: value for key, value in entry.items() if key not in ("tls_server_name", "tls_ca_file")}
    return entry


def _target_defaults(session: Session) -> Callable[[dict, list[dict], Field], tuple[Any, str] | None]:
    """Offer what questions 4 and 5 already say, so it is confirmed with Enter instead of typed again."""
    def offer(entry: dict, entries: list[dict], spec: Field) -> tuple[Any, str] | None:
        signaling = get_in(session.scope.document, ("signaling",)) or {}
        key = spec.path[-1]
        if key == "address":
            if entries and entries[-1].get("address"):
                return entries[-1]["address"], f"the address of {entries[-1].get('name')}"
            networks = [text for text in signaling.get("networks") or [] if isinstance(text, str)]
            if len(networks) == 1:
                try:
                    network = ipaddress.ip_network(networks[0].strip(), strict=False)
                except ValueError:
                    return None
                if network.num_addresses == 1:
                    return str(network.network_address), "the only signaling address, question 4"
        if key == "transport":
            transports = [item for item in signaling.get("transports") or [] if item in TRANSPORTS]
            unused = [item for item in transports if item not in {row.get("transport") for row in entries}]
            if len(transports) == 1:
                return transports[0], "the only approved transport, question 5"
            if entries and len(unused) == 1:
                return unused[0], "the approved transport no target uses yet, question 5"
        if key == "port":
            ports = [item for item in signaling.get("ports") or [] if type(item) is int]
            if len(ports) == 1:
                return ports[0], "the only approved port, question 5"
            usual = {"tls": 5061, "udp": 5060, "tcp": 5060}.get(str(entry.get("transport")))
            if usual in ports:
                return usual, f"the usual {entry.get('transport')} port, approved in question 5"
        return None

    return offer


def _announce_tls(session: Session, spec: Field) -> None:
    if spec.path[-1] == "tls_server_name":
        session.say(f"  This target uses TLS (question 6): {QUESTIONS[5].text}")


def _targets_answered_now(session: Session) -> bool:
    from .scope_questions import _targets_answered

    return _targets_answered(session.scope.document) and not session._has_error("targets")


def _ports(session: Session, item: Item, only_open: bool) -> None:
    for name in ("signaling.ports", "signaling.transports"):
        session.ask(FIELDS[name], only_open=only_open)
    session.say("  Targets: each address, transport, and port we test against, one at a time"
                " (each gets its own target profile).")
    _targets(session, only_open)


def _targets(session: Session, only_open: bool) -> None:
    _collection(session, path=("targets",), noun="target", fields=_target_fields, only_open=only_open,
                answered=_targets_answered_now(session), describe=_describe_target, announce=_announce_tls,
                defaults=_target_defaults(session), prune=_prune_target)


def _tls(session: Session, item: Item, only_open: bool) -> None:
    targets = get_in(session.scope.document, ("targets",))
    if not isinstance(targets, list):
        return
    for index, entry in enumerate(list(targets)):
        if isinstance(entry, dict) and entry.get("transport") == "tls":
            session.say(f"  Target {entry.get('name')} ({entry.get('address')} port {entry.get('port')}):")
            for spec in TLS_FIELDS:
                key = spec.path[-1]
                current = (get_in(session.scope.document, ("targets",)) or [{}])[index].get(key)
                if only_open and (present(current) or key == "tls_ca_file") and not session._has_error(
                        f"targets[{index}].{key}"):
                    continue

                def build(value: Any, _key: str = key, _index: int = index) -> list:
                    updated = [dict(row) for row in get_in(session.scope.document, ("targets",))]
                    if value is None:
                        updated[_index].pop(_key, None)
                    else:
                        updated[_index][_key] = value
                    return [(("targets",), updated)]

                session.ask(spec, path=("targets", str(index), key), focus=f"targets[{index}].{key}",
                            current=current, has_current=True, build=build)


def _delivery(session: Session, item: Item, only_open: bool) -> None:
    session.say("  NEVER type the password here. The credential reference is only a name for it; the password"
                " stays in a private file or your secret manager.")
    session.ask(FIELDS["account.credential_ref"], only_open=only_open)
    session.ask(FIELDS["account.credential_delivery"], only_open=only_open)


def _describe_destination(entry: dict) -> str:
    target = f" on {entry['target']}" if entry.get("target") else ""
    return f"{entry.get('name')}: dial {entry.get('user')}{target}, expect {entry.get('expect')}"


def _destination_fields(session: Session) -> Callable[[dict], tuple[Field, ...]]:
    targets = [row.get("name") for row in (get_in(session.scope.document, ("targets",)) or [])
               if isinstance(row, dict)]

    def fields(entry: dict) -> tuple[Field, ...]:
        if len(targets) > 1:
            return tuple(Field(spec.path, spec.label, f"one of: {', '.join(map(str, targets))}" if
                               spec.path[-1] == "target" else spec.hint, spec.kind, spec.choices, spec.open_words,
                               spec.words, spec.refuse)
                         for spec in DESTINATION_FIELDS)
        return tuple(spec for spec in DESTINATION_FIELDS if spec.path[-1] != "target")

    return fields


def _destinations(session: Session, item: Item, only_open: bool) -> None:
    from .scope_questions import _destinations_answered

    targets = [row.get("name") for row in (get_in(session.scope.document, ("targets",)) or [])
               if isinstance(row, dict)]
    if len(targets) > 1:
        session.say(f"  Targets in this scope: {', '.join(str(name) for name in targets)}")
    answered = _destinations_answered(session.scope.document) and not session._has_error("destinations")
    _collection(session, path=("destinations",), noun="destination", fields=_destination_fields(session),
                only_open=only_open, answered=answered, describe=_describe_destination)


def _security_checks(session: Session, item: Item, only_open: bool, part: str | None = None) -> None:
    """Question 24: the ids (checked as typed), then the ceiling they need, stated before it is asked."""
    from sippycup_checks import catalog

    from .scope import security_check_requests

    session.say("  Optional. Press Enter when the owner approved no posture checks: nothing is run that is not"
                " listed here.")
    current = session.scope.document.get("security_checks")
    current = current if isinstance(current, dict) else {}
    ids_spec, ceiling_spec = FIELDS["security_checks.approved"], FIELDS["security_checks.max_requests"]
    runnable = catalog.ids(runnable_only=True)
    ids_help = "Valid: " + ", ".join(runnable) + " (`./bin/sippycup checks explain ID` says what each sends)"
    approved = current.get("approved") if isinstance(current.get("approved"), list) else []

    def edits_for(ids: list[str], ceiling: Any) -> list:
        edits: list = [(("security_checks",), {"approved": ids, "max_requests": ceiling})]
        classes = get_in(session.scope.document, ("test_scope", "allowed_classes"))
        if ids and isinstance(classes, list) and "security-checks" not in classes:
            edits.append((("test_scope", "allowed_classes"), [*classes, "security-checks"]))
        return edits

    if part != "max_requests":
        while True:
            session.say(f"  {ids_spec.label}  [security_checks.approved]")
            session.say(f"    {ids_help}")
            session.say(f"    Current: {show(current.get('approved'))}")
            typed = session.read(help=ids_help)
            if typed == "":
                session.say("    Left as it is." if current else "    Left open: no checks are approved.")
                return
            if session.word(typed, "clear"):
                classes = get_in(session.scope.document, ("test_scope", "allowed_classes"))
                edits: list = [(("security_checks",), None)]
                if isinstance(classes, list) and "security-checks" in classes:
                    edits.append((("test_scope", "allowed_classes"), [c for c in classes if c != "security-checks"]))
                session.write(edits)
                session.say("  Cleared security_checks: no checks are approved.")
                return
            approved = parse(ids_spec, typed)
            # The ids alone, with scope check's rules and the largest ceiling allowed.
            outcome = session.scope.judge(edits_for(approved, catalog.MAX_REQUESTS_CEILING),
                                          ["security_checks", "limits"])
            bad = [finding for finding in outcome.rejected if finding.field != "security_checks.max_requests"]
            if bad:
                for finding in bad:
                    for line in session.explain(finding, typed, ids_spec):
                        session.say(line)
                session.say("  Type the approved ids again (or press Enter to leave the question open).")
                continue
            break
    elif not approved:
        session.say("  No checks are approved yet, so there is no ceiling to set: "
                    f"{LAUNCHER} scope answer {shlex.quote(session.engagement)} 24")
        return
    else:
        session.say(f"  Approved checks: {', '.join(map(str, approved))}")
    candidate = session.scope.candidate(edits_for(approved, catalog.MAX_REQUESTS_CEILING))
    needs = security_check_requests(candidate, approved)
    total = sum(item[1] for item in needs)
    if part != "max_requests":
        session.partial = (f"the check ids ({', '.join(map(str, approved))}) were not saved: the request ceiling is"
                           f" needed too. To record both: {LAUNCHER} scope answer {shlex.quote(session.engagement)} 24")
    session.say(f"  These checks may send up to {total} request{'s' if total != 1 else ''} in this scope: "
                + ", ".join(f"{check_id} {count}" for check_id, count, _ in needs)
                + ". The owner's ceiling must be at least that.")
    valid = (f"Valid: the owner's written ceiling, a whole number from {max(total, 1)} to"
             f" {catalog.MAX_REQUESTS_CEILING}")
    while True:
        session.say(f"  {ceiling_spec.label}  [security_checks.max_requests]")
        session.say(f"    {valid}")
        session.say(f"    Current: {show(current.get('max_requests'))}")
        ceiling_text = session.read(help=valid)
        if ceiling_text == "":
            session.say("    The owner has not given the ceiling, so the checks are not recorded (nothing is"
                        " invented).")
            return
        edits = edits_for(approved, parse(ceiling_spec, ceiling_text))
        if len(edits) > 1:
            session.say("  (security-checks is added to test_scope.allowed_classes with them: the owner's approval"
                        " of the checks is what allows that class.)")
        if session.accept(edits, ["security_checks", "test_scope.allowed_classes", "limits"], ceiling_text,
                          ceiling_spec):
            return


def _components(session: Session, item: Item, only_open: bool) -> None:
    session.ask(FIELDS["platform.name"], only_open=only_open)
    for name in ("sip_edge", "media_servers", "admin_console", "customer_web_app", "api", "websocket_webrtc",
                 "provisioning", "voicemail", "ivr", "conference", "recording"):
        session.ask(FIELDS[f"platform.components.{name}"], only_open=only_open)


def _third(*names: str) -> Callable[[Session, Item, bool], None]:
    def handler(session: Session, item: Item, only_open: bool) -> None:
        for name in names:
            provider = _ask_field(session, f"platform.third_parties.{name}.provider", only_open)
            if provider == "none":
                session.say(f"    ({name.replace('_', ' ')}: no such company, so its permission is out-of-path"
                            " and no reference is needed.)")
                continue
            for key in ("permission", "reference"):
                if key == "reference" and get_in(session.scope.document,
                                                 ("platform", "third_parties", name, "permission")) == "out-of-path":
                    continue
                _ask_field(session, f"platform.third_parties.{name}.{key}", only_open)

    return handler


def _reach(session: Session, item: Item, only_open: bool, only: str | None = None) -> None:
    names = [row.get("name") for row in (get_in(session.scope.document, ("destinations",)) or [])
             if isinstance(row, dict) and isinstance(row.get("name"), str)]
    if not names:
        session.say("  No destinations are recorded yet (question 11); answer that first.")
        return
    if only is not None and only not in names:
        session.say(f"  No destination is named {only}; the destinations are: {', '.join(names)}.")
        return
    for name in names:
        if only is None or name == only:
            session.ask(reach_field(name), only_open=only_open)


def _list_rows(session: Session, path: tuple[str, ...]) -> list[dict]:
    rows = get_in(session.scope.document, path)
    return [dict(row) for row in rows] if isinstance(rows, list) else []


def _addressing(session: Session, item: Item, only_open: bool) -> None:
    from .scope_app import ANSWERED, _addressing_states, worst

    answered = worst(_addressing_states(session.scope.document)) == ANSWERED
    _collection(session, path=("platform", "addressing"), noun="public name", fields=lambda e: ADDRESSING_FIELDS,
                only_open=only_open, answered=answered,
                describe=lambda e: f"{e.get('name')}: {show(e.get('addresses'))}, shared {show(e.get('shared'))},"
                                   f" changing {show(e.get('changing'))}")


def _surfaces(session: Session, item: Item, only_open: bool) -> None:
    from .scope_app import ANSWERED, _surface_states, worst

    answered = worst(_surface_states("name", "kind", "status", "base_url")(session.scope.document)) == ANSWERED
    _collection(session, path=("application", "surfaces"), noun="surface", fields=lambda e: SURFACE_FIELDS,
                only_open=only_open, answered=answered,
                describe=lambda e: f"{e.get('name')}: {e.get('kind')}, {show(e.get('status'))},"
                                   f" {show(e.get('base_url'))}")


def _row_fields(session: Session, path: tuple[str, ...], index: int, specs: tuple[Field, ...],
                only_open: bool, header: str | None = None) -> None:
    """Ask these fields of one list entry; the header prints only above a field that is asked."""
    for spec in specs:
        key = spec.path[-1]
        rows = _list_rows(session, path)
        current = rows[index].get(key)
        focus = f"{'.'.join(path)}[{index}].{key}"
        if only_open and present(current) and current not in OPEN_WORDS and not session._has_error(focus):
            continue
        if header is not None:
            session.say(header)
            header = None

        def build(value: Any, _key: str = key) -> list:
            updated = _list_rows(session, path)
            if value is None:
                updated[index].pop(_key, None)
            else:
                updated[index][_key] = value
            return [(path, updated)]

        session.ask(spec, path=(*path, str(index), key), focus=focus, current=current, has_current=True,
                    build=build)


def _surface_connect(session: Session, item: Item, only_open: bool) -> None:
    rows = _list_rows(session, ("application", "surfaces"))
    if not rows:
        session.say("  No surfaces are recorded yet (question A1); answer that first.")
    for index, row in enumerate(rows):
        if row.get("status") == "out-of-scope":
            continue
        header = f"  Surface {row.get('name')} ({row.get('kind')}):"
        before = session.asked_count
        _row_fields(session, ("application", "surfaces"), index, SURFACE_CONNECT_FIELDS, only_open, header)
        if _list_rows(session, ("application", "surfaces"))[index].get("tls_ca") == "private":
            _row_fields(session, ("application", "surfaces"), index, (SURFACE_CA_FIELD,), only_open,
                        header if session.asked_count == before else None)


def _websocket(session: Session, item: Item, only_open: bool) -> None:
    rows = _list_rows(session, ("application", "surfaces"))
    sockets = [i for i, row in enumerate(rows) if row.get("kind") == "websocket" and row.get("status") != "out-of-scope"]
    if not sockets:
        session.say("  No websocket surface is recorded (question A1: kind websocket); answer that first.")
    for index in sockets:
        _row_fields(session, ("application", "surfaces"), index, SURFACE_SOCKET_FIELDS, only_open,
                    f"  Surface {rows[index].get('name')}:")


def _identities(session: Session, item: Item, only_open: bool) -> None:
    from .scope_app import ANSWERED, _identity_states, worst

    answered = worst(_identity_states(session.scope.document)) == ANSWERED
    session.say("  NEVER type a password here: each account gets a reference NAME only.")
    _collection(session, path=("application", "identities"), noun="test account", fields=lambda e: IDENTITY_FIELDS,
                only_open=only_open, answered=answered,
                describe=lambda e: f"{e.get('id')}: role {show(e.get('role'))}, tenant {show(e.get('tenant'))},"
                                   f" credential reference {show(e.get('credential_ref'))}")


HANDLERS: dict[str, Callable[[Session, Item, bool], None]] = {
    "authorization.approval": _simple("authorization.approval_id", "authorization.approved_by"),
    "authorization.status": _approval,
    "authorization.window": _window,
    "signaling.addresses": _simple("signaling.networks"),
    "signaling.ports": _ports,
    "signaling.tls": _tls,
    "account.delivery": _delivery,
    "destinations": _destinations,
    "media.ports": _range,
    "security_checks": _security_checks,
    "P1": _components,
    "P7": _third("hosting"),
    "P8": _third("cdn_waf"),
    "P9": _third("pstn_carrier"),
    "P10": _third("sms", "email"),
    "P11": _reach,
    "P12": _simple("platform.dialing.never_dial", "platform.dialing.never_dial_prefixes"),
    "P17": _simple("platform.operations.emergency_contact.name", "platform.operations.emergency_contact.channel",
                   "platform.operations.stop_signal"),
    "P18": _addressing,
    "A1": _surfaces,
    "A2": _surface_connect,
    "A3": _websocket,
    "A4": _identities,
    "A6": _simple("application.route_inventory.kind", "application.route_inventory.file"),
}


def _recorded(document: dict, dotted: str) -> bool:
    """True when some answer under this field is recorded (open words count: they were typed)."""
    value = get_in(document, tuple(dotted.split(".")))
    if isinstance(value, dict):
        return any(_recorded(value, key) for key in value)
    return present(value) or (isinstance(value, list) and bool(value))


def run_selection(session: Session, selection: Selection, *, only_open: bool) -> None:
    """Ask exactly what the selection names."""
    item = selection.item
    if selection.kind == "question":
        session.run_item(item, only_open=only_open)
    elif selection.kind == "collection":
        if selection.collection == "targets":
            _targets(session, False)
        else:
            HANDLERS[item.identifier](session, item, False)
    elif selection.kind == "entry":
        fields, noun, prune = _collection_spec(selection.collection, session)
        _edit_entry(session, path=tuple(selection.collection.split(".")), noun=noun, fields=fields,
                    index=selection.index or 0, prune=prune, only=selection.key)
    elif selection.kind == "fields":
        for name in selection.fields:
            _ask_field(session, name)
    elif selection.kind == "approval":
        _approval(session, item, False)
    elif selection.kind == "window":
        _window(session, item, False, selection.fields)
    elif selection.kind == "range":
        _range(session, item, False, selection.fields)
    elif selection.kind == "checks":
        _security_checks(session, item, False, selection.key)
    elif selection.kind == "reach":
        _reach(session, item, False, selection.name)


# ---------------------------------------------------------------- entry points


def answered_view(report: Report) -> Report:
    """The report without findings about time (a window not open yet is answered)."""
    return Report(report.path, report.present, report.sha256,
                  [item for item in report.findings if item.code not in NOTE_CODES], report.document, report.fatal)


def open_items(report: Report, unfinished: dict[str, str] | None = None) -> list[Item]:
    view = answered_view(report)
    return [item for item in items_for(report.document)
            if item_state(view, item, unfinished) not in ("answered", "not-applicable")]


def fix_command(items: list[Item], finding: Finding, engagement: str, document: dict[str, Any]) -> str | None:
    """The exact `scope answer` command that opens the field a finding names, or its question."""
    eng = shlex.quote(engagement)
    target = finding.field
    try:
        if target and resolve(items, target, document):
            return f"{LAUNCHER} scope answer {eng} {target}"
    except ScopeError:
        pass
    item = find_item(items, target) if target else None
    return f"{LAUNCHER} scope answer {eng} {item.number}" if item is not None else None


def summarize(path: Path, engagement: str, out: TextIO, now: datetime,
              unfinished: dict[str, str] | None = None) -> Report:
    """Run the same check as scope check; print what is open and the next command.

    The findings are printed as scope check prints them, except that the
    ``scope.missing`` lines are counted, not listed: the open questions are
    listed by number instead. A list whose entry was interrupted is open too.
    """
    report = inspect(path, now=now)
    value = report.as_dict()
    out.write("\n== Where the scope stands (the same check as scope check) ==\n")
    out.write(f"Scope file: {path}\n")
    if value["ok"]:
        out.write("Scope: COMPLETE and CONSISTENT\n")
    else:
        state = "INCOMPLETE" if not value["complete"] else "INCONSISTENT"
        out.write(f"Scope: {state} ({len(value['errors'])} errors, {len(value['warnings'])} warnings)\n")
    missing = [item for item in value["errors"] if item["code"] == "scope.missing"]
    for item in value["errors"]:
        if item["code"] != "scope.missing":
            out.write(f"ERROR {item['code']} [{item['field'] or '-'}]: {item['message']}\n")
    for item in value["warnings"]:
        out.write(f"WARN  {item['code']} [{item['field'] or '-'}]: {item['message']}\n")
    if missing:
        out.write(f"Unanswered fields: {len(missing)} (scope check lists each as scope.missing)\n")
    eng = shlex.quote(engagement)
    if report.document is None:
        out.write(f"Next: fix the file by hand (see the ERROR above), then {LAUNCHER} scope check {eng}\n")
        return report
    unfinished = unfinished or {}
    for collection, note in sorted(unfinished.items()):
        identifier = COLLECTIONS[collection][0]
        number = next((item.number for item in items_for(report.document) if item.identifier == identifier), "?")
        out.write(f"Unfinished list: {collection} (question {number}; the last session stopped while {note})."
                  f" scope check does not know this; {LAUNCHER} scope answer {eng} continues there\n")
    pending = open_items(report, unfinished)
    required = [item for item in pending if item.identifier not in OPTIONAL_QUESTIONS and item.part == 1]
    optional = [item for item in pending if item.identifier in OPTIONAL_QUESTIONS]
    platform = [item for item in pending if item.part == 2]
    if required:
        out.write("Still open: " + ", ".join(f"{item.number} ({item.section.lower()})" for item in required) + "\n")
    if optional:
        for item in optional:
            out.write(f"Optional, not recorded: {item.number} (security checks: none are approved unless the owner "
                      f"approved some; to record them: {LAUNCHER} scope answer {eng} {item.number})\n")
    if platform:
        out.write("Platform answers still open: " + ", ".join(item.number for item in platform)
                  + " (they do not hold the SIP tests unless scope check says ERROR)\n")
    items = items_for(report.document)
    fixes: list[str] = []
    wrong = [finding for finding in report.errors if finding.kind != "missing" and finding.code not in NOTE_CODES]
    # Questions that are open only because an answer is wrong: fixing it is the next step, not another walk.
    complete_view = Report(report.path, report.present, report.sha256,
                           [finding for finding in report.findings if finding not in wrong], report.document,
                           report.fatal)
    broken = {item.identifier for item in required
              if item_state(answered_view(complete_view), item, unfinished) in ("answered", "not-applicable")}
    for finding in wrong:
        command = fix_command(items, finding, engagement, report.document)
        if command and command not in fixes:
            fixes.append(command)
            out.write(f"To fix {finding.code} [{finding.field}]: {command}   (or change the answer it contradicts)\n")
    # Open only because of a wrong answer: the fix is the next step, not another walk.
    walk_needed = [item for item in required
                   if item.identifier != "authorization.status" and item.identifier not in broken]
    only_approval = bool(required) and all(item.identifier == "authorization.status" for item in required)
    if only_approval and not fixes and not unfinished:
        # Everything the approval approves is recorded: the one step left is the approval itself,
        # not another walk (with platform sections a walk passes every open platform question first).
        out.write(f"Next: {LAUNCHER} scope answer {eng} 2   (record the approval: only with the owner's written"
                  f" approval of the summary it shows), then {LAUNCHER} scope compile {eng}\n")
    elif required and (walk_needed or not fixes):
        out.write(f"Next: {LAUNCHER} scope answer {eng}   (when the owner has answered the open questions)\n")
    elif fixes:
        out.write(f"Next: {fixes[0]}\n")
    elif not report.ok:
        out.write(f"Next: {LAUNCHER} scope check {eng}   (fix what it reports; change one answer with "
                  f"{LAUNCHER} scope answer {eng} NUMBER)\n")
    else:
        out.write(f"Next: {LAUNCHER} scope compile {eng}\n")
    return report


def _offer_platform(session: Session, selections: list[Selection]) -> bool:
    """Once per walk, before the first open platform question: walk them now, or skip them for this session.

    Skipping records nothing and loosens nothing: the questions stay open, scope
    check keeps its WARN (or ERROR) lines for them, and the approval rule is as
    it was (an open platform answer never held question 2; see approval_blockers).
    """
    view = answered_view(session.scope.report)
    pending = [selection.item for selection in selections if selection.item.part == 2 and item_state(
        view, selection.item, session.scope.unfinished) not in ("answered", "not-applicable")]
    eng = shlex.quote(session.engagement)
    session.say("")
    session.say("== Part 2: the whole platform (questions P1 to P18 and A1 to A6) ==")
    session.say(f"  {len(pending)} of these questions {'is' if len(pending) == 1 else 'are'} still open: "
                + ", ".join(item.number for item in pending))
    session.say("  They record the owner's answers about the product around the SIP service. An open one is a WARN"
                " line in scope check; it does not hold the approval (question 2) or the SIP tests unless scope"
                " check says ERROR. Where each destination's calls go (P11 to P13) is shown in the approval summary.")
    session.say("  y = ask each open one now.  Enter or n = the owner has not answered these yet: skip them for"
                " this session and go straight on (they stay open; nothing is invented).")
    if session.confirm("Walk the platform questions now?"):
        return True
    session.say(f"  Skipped for this session; the platform questions stay open. One of them later: {LAUNCHER} scope"
                f" answer {eng} {pending[0].number if pending else 'P1'}   (any of the numbers above); all of them:"
                f" {LAUNCHER} scope answer {eng} and type y here.")
    return False


def run(engagement: str, *, scope: str | None = None, question: str | None = None, change_all: bool = False,
        settings: list[str] | None = None, stdin: TextIO | None = None, stdout: TextIO | None = None,
        now: Callable[[], datetime] | None = None) -> int:
    stdin = stdin or sys.stdin
    out = stdout or sys.stdout
    clock = now or (lambda: datetime.now(timezone.utc))
    path = Path(scope) if scope is not None else Path(engagement) / "scope.yaml"
    try:
        interactive = stdin.isatty() and out.isatty()
    except (AttributeError, ValueError):
        interactive = False
    scope_file = ScopeFile(path, now=clock)
    if settings:
        return _set(scope_file, engagement, settings, out, clock)
    session = Session(scope_file, engagement, stdin, out, interactive=interactive, now=clock)
    items = items_for(scope_file.document)
    if question is not None:
        selections = resolve(items, question, scope_file.document)
        if not selections:
            raise unknown_selection(question, items)
    else:
        selections = [Selection(item, "question") for item in walk_order(items)]
    session.say(f"Scope answers: {path}")
    session.say("Type the owner's written answers. Each answer is checked with the same rules as scope check and"
                " saved at once (mode 0600). Comments and everything not asked about stay as they are.")
    session.say(HELP)
    if not interactive:
        session.say("(reading answers from standard input)")
    code = 0
    asked_approval = False
    try:
        asked = 0
        for selection in selections:
            item = selection.item
            state = item_state(answered_view(scope_file.report), item, scope_file.unfinished)
            if question is None:
                if state == "not-applicable" or item.identifier in OPTIONAL_QUESTIONS:
                    continue  # question 24 is offered in the summary with its own command
                if not change_all and state == "answered":
                    continue
                if item.part == 2 and not change_all:
                    if session.walk_platform is None:
                        session.walk_platform = _offer_platform(session, selections)
                    if not session.walk_platform:
                        continue
            position = f" of {len(QUESTIONS)}" if item.part == 1 else ""
            if state == "not-applicable":
                session.say(f"\nQuestion {item.number} is not asked: an earlier answer rules it out (for example"
                            " question 8 says calls need no account). Change that answer first.")
                continue
            # Asking only what is open (a walk, or a question that is partly answered).
            only_open = question is None and not change_all
            note = ""
            if question is not None and selection.kind == "question" and state != "answered":
                only_open = True
            if only_open and question is not None and selection.kind == "question" and any(
                    _recorded(session.scope.document, name) for name in getattr(item.sheet, "fields", ())):
                note = ("  (only the open answers of this question are asked; to change a recorded one, name its"
                        " field, e.g. scope answer DIR " + (getattr(item.sheet, "fields", ("",))[0]) + ")")
            elif selection.kind not in ("question",):
                note = f"  (only {selection.label} is asked; the other answers stay as they are)"
            session.begin(item, position, note)
            if selection.kind == "question":
                session.run_item(item, only_open=only_open)
            else:
                run_selection(session, selection, only_open=only_open)
            asked_approval = asked_approval or item.identifier == "authorization.status"
            session.partial = None
            unsaid = session.end()
            session.flush_notes()
            if unsaid is None:
                asked += 1
            elif question is not None:
                session.say(f"\nQuestion {item.number}: nothing to ask now. " + " ".join(
                    line.strip() for line in unsaid) if unsaid else
                    f"\nQuestion {item.number}: nothing to ask now: every answer it needs is recorded.")
            elif unsaid or state != "answered":
                session.waiting.append((item, unsaid))
        if session.reapprove and get_in(scope_file.document, STATUS_PATH) != "approved":
            status_item = next(item for item in items if item.identifier == "authorization.status")
            session.begin(status_item, f" of {len(QUESTIONS)}")
            _approval(session, status_item, True)
            unsaid = session.end()
            if unsaid is None:
                asked += 1
            else:
                session.say("")
                session.say("The approval is pending again. " + " ".join(line.strip() for line in unsaid)
                            + f" Then: {LAUNCHER} scope answer {shlex.quote(engagement)} 2")
        if session.waiting:
            session.say("")
            session.say("Not asked now (nothing to ask until another answer is recorded):")
            for item, lines in session.waiting:
                reason = " ".join(line.strip() for line in lines) or "it is open because of a finding below."
                session.say(f"  {item.number}: {reason}")
        if asked == 0 and not session.waiting and question is None:
            session.say("Every question is answered. To change one: "
                        f"{LAUNCHER} scope answer {shlex.quote(engagement)} NUMBER (or --all).")
    except Quit:
        session.held = None
        session.say("Stopped. The answers recorded so far are saved.")
    except EOFError:
        session.held = None
        session.say("Stopped at the end of the input. The answers recorded so far are saved.")
    except KeyboardInterrupt:
        session.held = None
        out.write("\nInterrupted. The answers recorded so far are saved; the answer being typed was not.\n")
        code = 130
    except ChangedOnDisk as exc:
        session.held = None
        out.write(f"error: {exc}\n")
        code = 2
    except EditError as exc:
        session.held = None
        out.write(f"error: {exc}; nothing more was written\n")
        code = 2
    session.held = None
    if session.partial:
        session.say(f"Not saved: {session.partial}.")
    session.say(f"Answers recorded in this session: {session.recorded}")
    report = summarize(path, engagement, out, clock(), scope_file.unfinished)
    out.write("Network activity: none\n")
    if code:
        return code
    return 0 if report.ok and not scope_file.unfinished else 1


def _set(scope_file: ScopeFile, engagement: str, settings: list[str], out: TextIO,
         clock: Callable[[], datetime]) -> int:
    edits: list[tuple[tuple[str, ...], Any]] = []
    focus: list[str] = []
    for setting in settings:
        name, sep, raw = setting.partition("=")
        name = name.strip()
        if not sep or not name:
            raise ScopeError(f"--set needs FIELD=VALUE, e.g. --set limits.calls=40 (got '{setting}')")
        if name == "authorization.status":
            raise ScopeError(
                "the approval is never set with --set (nothing was changed): record it at the prompt that says what"
                f" typing it asserts: {LAUNCHER} scope answer {shlex.quote(engagement)} authorization.status")
        spec = FIELDS.get(name)
        if spec is None or name not in SETTABLE:
            raise ScopeError(
                f"--set cannot change '{name}' (nothing was changed). It takes plain answers such as limits.calls,"
                " media.codecs, or contact.name; targets, destinations, the window, and the approval are asked"
                f" field by field: {LAUNCHER} scope answer {shlex.quote(engagement)} QUESTION")
        if not raw.strip():
            raise ScopeError(f"--set {name}= has no value (nothing was changed); leave an unanswered question out")
        try:
            value = interpret(spec, raw)[0]
        except Refused as exc:
            raise ScopeError(f"--set {name}: {exc} (nothing was changed)") from exc
        edits.append((spec.path, value))
        focus.append(name)
    edits, changes = reapproval(scope_file.document, edits)
    outcome = scope_file.judge(edits, focus)
    if outcome.rejected or outcome.conflicts:
        for finding in outcome.rejected:
            out.write(f"REFUSED {finding.code} [{finding.field}]: {finding.message}\n")
        for finding in outcome.conflicts:
            out.write(f"REFUSED {finding.code} [{finding.field}]: {finding.message} (it contradicts another answer;"
                      " change both in one command, or answer interactively)\n")
        out.write("Nothing was written.\nNetwork activity: none\n")
        return 2
    scope_file.write(edits, out)
    for path, value in edits:
        if path == STATUS_PATH and changes:
            continue
        out.write(f"Recorded {'.'.join(path)}: {show(value)}\n")
    if changes:
        out.write(f"{reapprove_message(changes, engagement)}\n")
    for finding in outcome.notes:
        if changes and finding.code == "scope.authorization_not_approved":
            continue
        label = "NOTE" if finding.severity == "error" else "WARN"
        out.write(f"{label} {finding.code} [{finding.field}]: {finding.message}\n")
    report = summarize(scope_file.path, engagement, out, clock(), scope_file.unfinished)
    out.write("Network activity: none\n")
    return 0 if report.ok else 1
