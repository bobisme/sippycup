"""``scope answer``: put the owner's written answers into scope.yaml, guided.

The operator types each answer once; this module checks it with exactly the
rules ``scope check`` uses (``scope.document_findings`` on the document with
that answer in it), explains a rejected answer and asks again, and writes the
accepted answer at once. It edits only scope.yaml, atomically and mode 0600,
and keeps the operator's comments and everything it did not ask about (see
``scope_edit``). It never writes a password, never invents an answer, and never
marks the authorization approved by itself.

Questions are the numbered questions of ``scope questions`` (part 1, 1 to 24)
and, when the file has the platform sections, P1 to P18 and A1 to A6.
"""

from __future__ import annotations

import copy
import ipaddress
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
    TRANSPORTS,
    Finding,
    Report,
    ScopeError,
    _UniqueLoader,
    document_findings,
    inspect,
    present,
)
from .scope_edit import EditError, apply_edits, get_in, render_inline
from .scope_questions import QUESTIONS, question_state

LAUNCHER = "./bin/sippycup"
OPEN_WORDS = ("pending", "unknown")
# Findings that record a fact about time or approval, not a wrong answer: the
# answer is recorded and the finding is shown as a note (scope check keeps
# reporting it until it is resolved).
NOTE_CODES = {"scope.window_not_started", "scope.window_expired", "scope.authorization_not_approved"}
OPTIONAL_QUESTIONS = {"security_checks"}
# The facts a recorded approval names. Changing one while the status is
# approved sets the status back to pending: the operator asserted the owner's
# written approval of the OLD facts, so it is asked again (never carried over).
APPROVAL_FACTS = {("authorization", key) for key in ("approval_id", "approved_by", "valid_from", "valid_until")}
STATUS_PATH = ("authorization", "status")
REAPPROVE = ("authorization.status is pending again: the approval you recorded named the previous reference,"
             " approver, or window. If the owner's written approval covers the new answer, record it again"
             " (question 2).")


def with_reapproval(document: dict[str, Any], edits: list[tuple[tuple[str, ...], Any]]) -> tuple[list, bool]:
    """Add the status reset when an edit changes a fact of a recorded approval."""
    if get_in(document, STATUS_PATH) != "approved" or any(path == STATUS_PATH for path, _ in edits):
        return edits, False
    changed = any(path in APPROVAL_FACTS and value != get_in(document, path) for path, value in edits)
    return (edits + [(STATUS_PATH, "pending")], True) if changed else (edits, False)


class Quit(Exception):
    """The operator typed quit: stop asking, keep what was recorded."""


class ChangedOnDisk(ScopeError):
    """scope.yaml changed on disk while answering."""


# ------------------------------------------------------------------ fields


@dataclass(frozen=True)
class Field:
    """One answer: where it is stored, how it is typed, what is valid."""

    path: tuple[str, ...]
    label: str
    hint: str
    kind: str = "text"  # text, int, number, bool, enum, words, list, enumlist, ints, addresses, dials
    choices: tuple[str, ...] = ()
    open_words: bool = False  # platform answers: pending / unknown are answers too

    @property
    def dotted(self) -> str:
        return ".".join(self.path)


def _f(path: str, label: str, hint: str, kind: str = "text", choices: tuple[str, ...] = (),
       open_words: bool = False) -> Field:
    return Field(tuple(path.split(".")), label, hint, kind, choices, open_words)


ADDRESS_HINT = ("literal IP addresses or CIDR ranges, separated by commas, e.g. 203.0.113.10, 203.0.113.0/28. "
                "No hostnames: ask the owner for the numeric address behind a name")
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
       "list"),
    _f("account.required", "Do calls need an account (registration or digest authentication)?",
       "yes or no", "bool"),
    _f("account.username", "Account username", "letters, digits and . _ + @ - (e.g. practice)"),
    _f("account.realm", "Account realm (SIP domain)", "letters, digits and . _ - (e.g. sip.acme.tld)"),
    _f("account.credential_ref", "Credential reference NAME (never the password)",
       "a NAME you choose for the password, NOT the password itself: lowercase letters, digits and '-', "
       "starting with a letter, at most 63 characters (e.g. acme-password). It is the name you later pass to "
       "campaign run --secret-env NAME=VARIABLE; the password goes only in a private file "
       "(docs/FIRST-ENGAGEMENT.md, section 2)"),
    _f("account.credential_delivery", "How the owner delivers the password",
       "one of: " + ", ".join(CREDENTIAL_DELIVERIES), "enum", CREDENTIAL_DELIVERIES),
    _f("media.networks", "Media addresses or ranges", ADDRESS_HINT + "; each range at most 1024 addresses (/22)",
       "addresses"),
    _f("media.port_range.start", "First media (RTP) port", "a whole number 1-65535, e.g. 10000", "int"),
    _f("media.port_range.end", "Last media (RTP) port", "a whole number 1-65535, not below the first, e.g. 20000",
       "int"),
    _f("media.protection", "Media protection", "one or more of: rtp, sdes-srtp, dtls-srtp", "enumlist",
       PROTECTIONS),
    _f("media.codecs", "Codecs", "one or more of: PCMU, PCMA, G722, OPUS", "enumlist", CODECS),
    _f("media.dtmf", "DTMF method", "one of: rfc4733, sip-info, inband, none", "enum", DTMF_METHODS),
    _f("media.symmetric_rtp", "Symmetric RTP (media sent to the observed source address)?", "yes or no", "bool"),
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
    _f("stop_conditions.unexpected_response", "Stop on any unexpected response?", "yes or no", "bool"),
    _f("stop_conditions.packet_loss_percent", "Stop above this packet loss, in percent",
       "a number from 0 to 100, e.g. 20", "number"),
    _f("test_scope.allowed_classes", "Allowed test classes",
       "names separated by commas, e.g. options, call (add security-checks only with question 24)", "list"),
    _f("test_scope.exclusions", "Explicit exclusions",
       "words separated by commas, e.g. registration flood; type none if nothing is excluded", "words"),
    _f("contact.name", "Live contact (name)", "any text, e.g. Jane Doe (NOC)"),
    _f("contact.channel", "How to reach the live contact", "any text, e.g. +31 20 123 4567 or #voice-test on Slack"),
    _f("contact.can_stop_test", "Can that contact stop the test?", "yes or no (a contact who can stop it is required)",
       "bool"),
    _f("evidence.retention_days", "Keep captures and logs for (days)", "a whole number from 1 to 3650, e.g. 30",
       "int"),
    _f("evidence.disclosure", "Disclosure of findings", "one of: " + ", ".join(DISCLOSURES), "enum", DISCLOSURES),
    _f("security_checks.approved", "Approved check ids",
       "ids from `./bin/sippycup checks list`, separated by commas", "list"),
    _f("security_checks.max_requests", "Request ceiling for the checks", "a whole number; scope check says what the "
       "approved checks need", "int"),
    # part 2: platform and application (every answer may be pending or unknown)
    _f("platform.name", "Product or platform name", "any text", open_words=True),
    _f("platform.out_of_scope", "Explicitly out of scope",
       "plain words separated by commas, e.g. billing, the public marketing site; type none if nothing is",
       "words", open_words=True),
    _f("platform.environment.kind", "Environment", "one of: production, staging, dedicated-test", "enum",
       ("production", "staging", "dedicated-test"), True),
    _f("platform.environment.real_customers", "Real customers use it during the test?", "yes or no", "bool",
       open_words=True),
    _f("platform.environment.test_tenant", "Test tenant label", "the tenant's name only; type none if there is none",
       open_words=True),
    _f("platform.environment.never_touch", "Data we must never open or change",
       "plain words separated by commas, e.g. real voicemail, call records; none only if no real data", "words",
       open_words=True),
    _f("platform.dialing.never_dial", "Numbers we must never dial",
       "numbers separated by commas, e.g. 112, 911; type none if there are none", "dials", open_words=True),
    _f("platform.dialing.never_dial_prefixes", "Prefixes we must never dial (optional)",
       "prefixes separated by commas, e.g. 00, 0900; Enter if the owner gave none", "dials", open_words=True),
    _f("platform.dialing.toll", "Cost of calls that reach the public network",
       "one of: no-cost, accepted, refused", "enum", ("no-cost", "accepted", "refused"), True),
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
    _f("application.object_classes", "Kinds of stored files", "words separated by commas, e.g. voicemail, recording",
       "words", open_words=True),
    _f("application.route_inventory.kind", "List of pages and API calls", "one of: openapi, har, route-list, none",
       "enum", ("openapi", "har", "route-list", "none"), True),
    _f("application.route_inventory.file", "Where that file is (optional)",
       "a path under work/, e.g. work/acme/openapi.json (recorded, never read); Enter if none", open_words=True),
)}
COMPONENT_CHOICES = ("in-scope", "out-of-scope")
for _name in ("sip_edge", "media_servers", "admin_console", "customer_web_app", "api", "websocket_webrtc",
              "provisioning", "voicemail", "ivr", "conference", "recording"):
    FIELDS[f"platform.components.{_name}"] = _f(
        f"platform.components.{_name}", f"Part: {_name.replace('_', ' ')}",
        "in-scope or out-of-scope", "enum", COMPONENT_CHOICES, True)
for _name, _label in (("hosting", "hosting provider"), ("cdn_waf", "CDN or web firewall"),
                      ("pstn_carrier", "phone carrier or gateway"), ("sms", "SMS provider"),
                      ("email", "e-mail provider")):
    FIELDS[f"platform.third_parties.{_name}.provider"] = _f(
        f"platform.third_parties.{_name}.provider", f"{_label.capitalize()}: which company", "the company name",
        open_words=True)
    FIELDS[f"platform.third_parties.{_name}.permission"] = _f(
        f"platform.third_parties.{_name}.permission", f"{_label.capitalize()}: permission",
        "out-of-path (confirmed not involved in what we test) or permitted (it allows the test)", "enum",
        ("out-of-path", "permitted"), True)
    FIELDS[f"platform.third_parties.{_name}.reference"] = _f(
        f"platform.third_parties.{_name}.reference", f"{_label.capitalize()}: where the permission is written",
        "a policy page, ticket, or e-mail id; required when permitted", open_words=True)

# What --set may change: plain answers only. The approval itself is never set
# this way: it must be typed at the prompt that says what typing it asserts.
SETTABLE = {name for name in FIELDS}

TARGET_FIELDS = (
    _f("name", "Target name", "a short lowercase name, e.g. edge or tls (letters, digits, -)"),
    _f("address", "Target address", "ONE literal IP address the owner wrote down, e.g. 203.0.113.10 (no hostname)"),
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
    _f("name", "Destination name", "a short lowercase name for it, e.g. echo or front-desk"),
    _f("target", "On which target", "one of the target names"),
    _f("user", "Exactly what to dial", "letters, digits and . _ + * # -, e.g. 9196 or echo"),
    _f("expect", "What it should do", "echo (echoes audio), agent (answers as an agent), or reject", "enum",
       EXPECT_BEHAVIORS),
)
ADDRESSING_FIELDS = (
    _f("name", "Public name", "the DNS name, e.g. sip.acme.tld (an identity only, never looked up)", open_words=True),
    _f("addresses", "Addresses behind it", "literal IP addresses separated by commas", "list", open_words=True),
    _f("shared", "Shared with other customers of the provider?", "yes or no", "bool", open_words=True),
    _f("changing", "Behind a load balancer or delivery network whose addresses change?", "yes or no", "bool",
       open_words=True),
)
SURFACE_FIELDS = (
    _f("name", "Surface name", "a short lowercase name, e.g. admin-console"),
    _f("kind", "Kind", "browser, api, or websocket", "enum", ("browser", "api", "websocket")),
    _f("status", "In scope?", "in-scope or out-of-scope", "enum", ("in-scope", "out-of-scope"), True),
    _f("base_url", "Web address", "https://... (wss://... for a websocket); an identity, never looked up",
       open_words=True),
)
SURFACE_CONNECT_FIELDS = (
    _f("connect_address", "Connect to address", "one literal IP address (no hostname)", open_words=True),
    _f("connect_port", "Connect to port", "a whole number, e.g. 443", "int", open_words=True),
    _f("tls_server_name", "Name on the TLS certificate", "a DNS name, e.g. admin.acme.tld", open_words=True),
    _f("tls_ca", "Certificate issued by", "public or private", "enum", ("public", "private"), True),
)
IDENTITY_FIELDS = (
    _f("id", "Account label", "a short lowercase name, e.g. admin-test"),
    _f("role", "Role", "e.g. admin, reseller, customer-admin, user", open_words=True),
    _f("tenant", "Tenant or company", "the test tenant's label", open_words=True),
    _f("credential_ref", "Credential reference NAME (never the password)",
       "a NAME for its password, e.g. admin-test; the password itself is never written here", open_words=True),
)


# ---------------------------------------------------------------- parsing


def _split(raw: str, *, commas_only: bool = False) -> list[str]:
    parts = raw.split(",") if commas_only else re.split(r"[,\s]+", raw)
    return [part.strip() for part in parts if part.strip()]


def _number(text: str) -> Any:
    if re.fullmatch(r"[+-]?\d+", text):
        return int(text)
    if re.fullmatch(r"[+-]?\d+\.\d+", text):
        return float(text)
    return text


def parse(spec: Field, raw: str) -> Any:
    """Turn typed text into the YAML value. Never refuses: the checker does.

    A value that does not have the expected shape is passed on as typed, so
    the refusal is the same one ``scope check`` gives.
    """
    text = raw.strip()
    if spec.open_words and text.lower() in OPEN_WORDS:
        return text.lower()
    kind = spec.kind
    if kind == "int":
        return int(text) if re.fullmatch(r"\d+", text) else text
    if kind == "number":
        return _number(text)
    if kind == "bool":
        lowered = text.lower()
        if lowered in ("y", "yes", "true"):
            return True
        if lowered in ("n", "no", "false"):
            return False
        return text
    if kind == "enum":
        return text.lower() if text.lower() in spec.choices else text
    if kind == "enumlist":
        items = _split(text)
        if spec.choices == CODECS:
            return [item.upper() for item in items]
        return [item.lower() if item.lower() in spec.choices else item for item in items]
    if kind == "ints":
        return [int(item) if re.fullmatch(r"\d+", item) else item for item in _split(text)]
    if kind in ("list", "addresses"):
        return _split(text)
    if kind in ("words", "dials"):
        items = _split(text, commas_only=True)
        if [item.lower() for item in items] == ["none"]:
            return ["none"]
        return items
    return text


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
    """scope.yaml as text plus its parsed document; every write is atomic, 0600."""

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

    def refresh(self) -> None:
        self.report = inspect(self.path, now=self.now())
        if self.report.document is not None:
            self.document = self.report.document
        self.baseline = document_findings(self.document, now=self.now())

    def candidate(self, edits: list[tuple[tuple[str, ...], Any]]) -> dict[str, Any]:
        from .scope_edit import set_in

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

    def write(self, edits: list[tuple[tuple[str, ...], Any]], out: TextIO) -> None:
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


def item_state(report: Report, item: Item) -> str:
    if item.part == 1:
        return question_state(report, item.sheet)
    from .scope_app import app_question_state

    return app_question_state(report.document or {}, item.sheet, report)


def walk_order(items: list[Item]) -> list[Item]:
    """Sheet order, except that the approval itself comes after the window."""
    ordered = [item for item in items if item.identifier != "authorization.status"]
    status = [item for item in items if item.identifier == "authorization.status"]
    if status:
        position = next((i for i, item in enumerate(ordered) if item.identifier == "authorization.window"), 0)
        ordered[position + 1:position + 1] = status
    return ordered


def find_item(items: list[Item], wanted: str) -> Item | None:
    token = wanted.strip()
    special = {"targets": "signaling.ports", "tls_server_name": "signaling.tls"}
    if token in special:
        token = special[token]
    for item in items:
        if token == item.number or token.upper() == item.number or token == item.identifier:
            return item
    # a field path: the question that asks it
    for item in items:
        fields = getattr(item.sheet, "fields", ())
        if any(token == name or token.startswith(name + ".") for name in fields):
            return item
    return None


# ---------------------------------------------------------------- session


HELP = (
    "At every prompt: Enter = the owner has not answered this yet (it stays open; nothing is invented),\n"
    "  ? = how to write a valid answer, clear = remove a recorded answer (the question is open again),\n"
    "  quit = stop here. Every accepted answer is saved at once, so quit, Ctrl-C, or Ctrl-D keeps them."
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
        self.reapprove = False

    # -- input and output

    def say(self, text: str = "") -> None:
        self.out.write(text + "\n")
        self.out.flush()

    def read(self, prompt: str = "  > ") -> str:
        """One typed line; quit raises Quit, end of input raises EOFError."""
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
        if answer.strip().lower() in ("quit", "q", "exit"):
            raise Quit
        return answer.strip()

    def confirm(self, question: str) -> bool:
        while True:
            answer = self.read(f"  {question} [y/N] > ").lower()
            if answer in ("", "n", "no"):
                return False
            if answer in ("y", "yes"):
                return True
            self.say("  Type y or n.")

    # -- one answer

    def explain(self, finding: Finding, typed: str | None) -> list[str]:
        lines = [f"  Not recorded: {finding.message} [{finding.field or '-'}]."]
        if finding.kind == "secret":
            lines.append("  That looks like a password, token, or key. scope.yaml holds only reference NAMES;"
                         " the secret itself never goes in it. Nothing was written.")
        elif typed and any(HOSTNAME_PATTERN.fullmatch(word) and re.search(r"[A-Za-z]", word)
                           and not _is_literal(word) for word in _split(typed)) and (
                "literal" in finding.message or "IP" in finding.message):
            lines.append("  That is a name, not an address. Sippycup sends only to the literal IP addresses the owner"
                         " wrote down, because a name can point somewhere else tomorrow. Ask the owner for the"
                         " numeric address(es) behind it; until then press Enter to leave the question open.")
        return lines

    def accept(self, edits: list[tuple[tuple[str, ...], Any]], focus: list[str], typed: str | None) -> bool | None:
        """Check edits with scope check's rules; write them when accepted.

        Returns True (written), False (rejected: ask again), None (the
        operator declined a conflicting answer: ask again).
        """
        edits, reset = with_reapproval(self.scope.document, edits)
        outcome = self.scope.judge(edits, focus)
        if outcome.rejected:
            for finding in outcome.rejected:
                for line in self.explain(finding, typed):
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
        self.scope.write(edits, self.out)
        self.recorded += 1
        for path, value in edits:
            if isinstance(value, list) and value and all(isinstance(entry, dict) for entry in value):
                self.say(f"  Recorded {'.'.join(path)} ({len(value)}):")
                for entry in value:
                    self.say(f"    - {render_inline(entry)}")
            else:
                self.say(f"  Recorded {'.'.join(path)}: {show(value)}")
        for finding in outcome.notes:
            label = "NOTE" if finding.severity == "error" else "WARN"
            self.say(f"  {label} {finding.code} [{finding.field}]: {finding.message}")
        if reset:
            self.reapprove = True
            self.say(f"  {REAPPROVE}")
        return True

    def clear(self, edits: list[tuple[tuple[str, ...], Any]]) -> None:
        edits, reset = with_reapproval(self.scope.document, edits)
        self.scope.write(edits, self.out)
        if reset:
            self.reapprove = True
            self.say(f"  {REAPPROVE}")

    def ask(self, spec: Field, *, path: tuple[str, ...] | None = None, focus: str | None = None,
            current: Any = None, has_current: bool = False, build: Callable[[Any], list] | None = None,
            only_open: bool = False, transform: Callable[[str], Any] | None = None) -> Any:
        """Ask one field until a valid answer or Enter. Returns the recorded value or None."""
        where = path or spec.path
        dotted = focus or ".".join(where)
        value_now = current if has_current else get_in(self.scope.document, where)
        if only_open and present(value_now) and value_now not in OPEN_WORDS and not self._has_error(dotted):
            return value_now
        open_note = " (or pending / unknown)" if spec.open_words else ""
        self.say(f"  {spec.label}  [{dotted}]")
        self.say(f"    Valid: {spec.hint}{open_note}")
        self.say(f"    Current: {show(value_now)}")
        while True:
            typed = self.read()
            if typed == "":
                self.say("    Left as it is." if present(value_now) else "    Left open: the owner has not answered.")
                return value_now if present(value_now) else None
            if typed == "?":
                self.say(f"    Valid: {spec.hint}{open_note}")
                continue
            if typed.lower() == "clear":
                value = [] if isinstance(value_now, list) else None
                edits = build(value) if build else [(where, value)]
                self.clear(edits)
                self.say(f"  Cleared {dotted}: the question is open again.")
                return None
            value = transform(typed) if transform else parse(spec, typed)
            edits = build(value) if build else [(where, value)]
            result = self.accept(edits, [dotted], typed)
            if result:
                return value

    def _has_error(self, dotted: str) -> bool:
        return any(item.severity == "error" and item.kind != "missing" and item.code not in NOTE_CODES
                   and _under(item, [dotted])
                   for item in self.scope.baseline)

    # -- questions

    def header(self, item: Item, position: str) -> None:
        part = "" if item.part == 1 else " (part 2: the whole platform)"
        self.say("")
        self.say(f"== Question {item.number}{position}: {item.section}{part} ==")
        self.say(item.text)
        for line in item.details:
            self.say(line)

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


# ---------------------------------------------------------------- handlers


def _simple(*names: str) -> Callable[[Session, Item, bool], None]:
    def handler(session: Session, item: Item, only_open: bool) -> None:
        for name in names:
            session.ask(FIELDS[name], only_open=only_open)

    return handler


def _window(session: Session, item: Item, only_open: bool) -> None:
    document = session.scope.document
    auth = document.get("authorization") if isinstance(document.get("authorization"), dict) else {}
    keys = [key for key in ("valid_from", "valid_until")
            if not only_open or not present(auth.get(key)) or session._has_error(f"authorization.{key}")]
    if not keys:
        return
    session.say("  The window is asked in three parts: the timezone the owner used, then the start and the end.")
    session.say("    Timezone  [not stored; used to turn the owner's times into RFC 3339 with an offset]")
    session.say("    Valid: a name such as Europe/Amsterdam, UTC, or an offset such as +01:00;"
                " Enter when both times below carry their own offset")
    zone = None
    while True:
        typed = session.read()
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
            typed = session.read()
            if typed == "":
                session.say("    Left as it is." if present(auth.get(key)) else
                            "    Left open: the owner has not answered.")
                break
            if typed == "?":
                session.say(f"    Valid: {example}")
                continue
            if typed.lower() == "clear":
                session.clear([(spec.path, None)])
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


def _approval(session: Session, item: Item, only_open: bool) -> None:
    auth = session.scope.document.get("authorization") or {}
    status = auth.get("status")
    if only_open and status == "approved":
        return
    window = f"{show(auth.get('valid_from'))} to {show(auth.get('valid_until'))}"
    session.say("  Approval status  [authorization.status]")
    session.say(f"    Current: {status if present(status) else 'not answered'}")
    session.say(f"    Recorded so far: reference {show(auth.get('approval_id'))}, approved by "
                f"{show(auth.get('approved_by'))}, window {window}")
    session.say("    Type the word approved ONLY if you hold the owner's written approval of this scope.")
    session.say("    Typing it records authorization.status: approved and ASSERTS that the owner approved this")
    session.say("    scope in writing, with the reference, approver, and window shown above.")
    session.say("    Other answers: pending (not approved yet), revoked (the owner withdrew it),"
                " Enter = leave it as it is.")
    while True:
        typed = session.read()
        if typed == "":
            session.say("    Left as it is." if present(status) else "    Left open.")
            return
        word = typed.lower()
        if word == "?":
            session.say("    Valid: approved, pending, or revoked")
            continue
        if word not in AUTH_STATUSES:
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
        if session.accept([(("authorization", "status"), word)], ["authorization.status"], typed):
            return


def _collection(session: Session, *, path: tuple[str, ...], noun: str, fields: Callable[[dict], tuple[Field, ...]],
                only_open: bool, answered: bool, describe: Callable[[dict], str],
                announce: Callable[[Session, Field], None] | None = None) -> None:
    """Ask a list of mappings (targets, destinations, ...) entry by entry, field by field.

    ``fields(entry)`` may depend on what is typed so far (a TLS target has
    more fields). An entry is written only when it is complete, so an
    interruption leaves the list as it was before that entry.
    """
    current = get_in(session.scope.document, path)
    entries = [dict(item) for item in current if isinstance(item, dict)] if isinstance(current, list) else []
    dotted = ".".join(path)
    if entries:
        session.say(f"  Recorded {noun}s:")
        for index, entry in enumerate(entries):
            session.say(f"    {index + 1}. {describe(entry)}")
    if only_open and answered:
        return
    if entries:
        session.say(f"  Enter = keep them; add = add another {noun}; redo = enter all {noun}s again;"
                    " clear = remove them (the question is open again)")
        while True:
            choice = session.read().lower()
            if choice == "":
                session.say("    Left as it is.")
                return
            if choice == "clear":
                session.scope.write([(path, [])], session.out)
                session.say(f"  Cleared {dotted}: the question is open again.")
                return
            if choice in ("add", "redo"):
                break
            session.say("  Type add, redo, clear, or press Enter.")
        if choice == "redo":
            entries = []
            session.say(f"  The recorded {noun}s are replaced when the first new one is complete.")
    while True:
        index = len(entries)
        session.say(f"  -- {noun} {index + 1} --")
        entry: dict[str, Any] = {}
        position = 0
        abandoned = False
        while position < len(fields(entry)):
            spec = fields(entry)[position]
            position += 1
            key = spec.path[-1]
            focus = f"{dotted}[{index}].{key}"
            optional = spec.label.endswith("(optional)")
            if announce is not None:
                announce(session, spec)
            session.say(f"  {spec.label}  [{focus}]")
            session.say(f"    Valid: {spec.hint}{' (or pending / unknown)' if spec.open_words else ''}")
            while True:
                typed = session.read()
                if typed == "?":
                    session.say(f"    Valid: {spec.hint}")
                    continue
                if typed == "":
                    break
                value = parse(spec, typed)
                trial = {**entry, key: value}
                outcome = session.scope.judge([(path, entries + [trial])], [focus])
                if outcome.rejected:
                    for finding in outcome.rejected:
                        for line in session.explain(finding, typed):
                            session.say(line)
                    session.say("  Please type it again (or press Enter if the owner has not answered).")
                    continue
                entry[key] = value
                break
            if typed == "" and not optional:
                abandoned = True
                session.say(f"    The owner has not answered this, so this {noun} is not recorded (nothing is"
                            " invented). The question stays open.")
                break
        if abandoned:
            return
        candidate = entries + [entry]
        result = session.accept([(path, candidate)], [dotted], None)
        if not result:
            session.say(f"  This {noun} was not recorded. Enter it again, or press Enter at its first field to stop.")
            continue
        entries = candidate
        if not session.confirm(f"Another {noun}?"):
            return


def _describe_target(entry: dict) -> str:
    text = f"{entry.get('name')}: {entry.get('address')} {entry.get('transport')} port {entry.get('port')}"
    if entry.get("tls_server_name"):
        text += f", certificate name {entry['tls_server_name']}"
    if entry.get("tls_ca_file"):
        text += f", CA {entry['tls_ca_file']}"
    return text


def _target_fields(entry: dict) -> tuple[Field, ...]:
    return TARGET_FIELDS + (TLS_FIELDS if entry.get("transport") == "tls" else ())


def _announce_tls(session: Session, spec: Field) -> None:
    if spec.path[-1] == "tls_server_name":
        session.say(f"  This target uses TLS (question 6): {QUESTIONS[5].text}")


def _ports(session: Session, item: Item, only_open: bool) -> None:
    for name in ("signaling.ports", "signaling.transports"):
        session.ask(FIELDS[name], only_open=only_open)
    from .scope_questions import _targets_answered

    session.say("  Targets: each address, transport, and port we test against, one at a time"
                " (each gets its own target profile).")
    answered = _targets_answered(session.scope.document) and not session._has_error("targets")
    _collection(session, path=("targets",), noun="target", fields=_target_fields, only_open=only_open,
                answered=answered, describe=_describe_target, announce=_announce_tls)


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


def _password_file_match(session: Session, typed: str) -> bool:
    candidate = Path(session.engagement) / "account.password"
    try:
        if candidate.is_file() and not candidate.is_symlink() and candidate.stat().st_size <= 4096:
            secret = candidate.read_bytes().strip()
            return bool(secret) and secret == typed.strip().encode("utf-8")
    except OSError:
        return False
    return False


def _delivery(session: Session, item: Item, only_open: bool) -> None:
    spec = FIELDS["account.credential_ref"]
    session.say("  NEVER type the password here. The credential reference is only a name for it; the password"
                " stays in a private file or your secret manager.")

    def transform(typed: str) -> Any:
        if _password_file_match(session, typed):
            raise _PasswordTyped
        return typed

    while True:
        try:
            session.ask(spec, only_open=only_open, transform=transform)
            break
        except _PasswordTyped:
            session.say("  Not recorded: that is the password from account.password. Type a NAME for it instead,"
                        " e.g. acme-password. Nothing was written.")
    session.ask(FIELDS["account.credential_delivery"], only_open=only_open)


class _PasswordTyped(Exception):
    pass


def _describe_destination(entry: dict) -> str:
    target = f" on {entry['target']}" if entry.get("target") else ""
    return f"{entry.get('name')}: dial {entry.get('user')}{target}, expect {entry.get('expect')}"


def _destinations(session: Session, item: Item, only_open: bool) -> None:
    from .scope_questions import _destinations_answered

    targets = [row.get("name") for row in (get_in(session.scope.document, ("targets",)) or [])
               if isinstance(row, dict)]
    if len(targets) > 1:
        session.say(f"  Targets in this scope: {', '.join(str(name) for name in targets)}")

    def fields(entry: dict) -> tuple[Field, ...]:
        if len(targets) > 1:
            return tuple(Field(spec.path, spec.label, f"one of: {', '.join(map(str, targets))}" if
                               spec.path[-1] == "target" else spec.hint, spec.kind, spec.choices)
                         for spec in DESTINATION_FIELDS)
        return tuple(spec for spec in DESTINATION_FIELDS if spec.path[-1] != "target")

    answered = _destinations_answered(session.scope.document) and not session._has_error("destinations")
    _collection(session, path=("destinations",), noun="destination", fields=fields, only_open=only_open,
                answered=answered, describe=_describe_destination)


def _security_checks(session: Session, item: Item, only_open: bool) -> None:
    """Question 24: the ids and their ceiling are checked together, as one section."""
    session.say("  Optional. Press Enter when the owner approved no posture checks: nothing is run that is not"
                " listed here.")
    current = session.scope.document.get("security_checks")
    current = current if isinstance(current, dict) else {}
    ids_spec, ceiling_spec = FIELDS["security_checks.approved"], FIELDS["security_checks.max_requests"]
    while True:
        session.say(f"  {ids_spec.label}  [security_checks.approved]")
        session.say(f"    Valid: {ids_spec.hint}")
        session.say(f"    Current: {show(current.get('approved'))}")
        typed = session.read()
        if typed == "":
            session.say("    Left as it is." if current else "    Left open: no checks are approved.")
            return
        if typed.lower() == "clear":
            classes = get_in(session.scope.document, ("test_scope", "allowed_classes"))
            edits: list = [(("security_checks",), None)]
            if isinstance(classes, list) and "security-checks" in classes:
                edits.append((("test_scope", "allowed_classes"), [c for c in classes if c != "security-checks"]))
            session.scope.write(edits, session.out)
            session.say("  Cleared security_checks: no checks are approved.")
            return
        approved = parse(ids_spec, typed)
        session.say(f"  {ceiling_spec.label}  [security_checks.max_requests]")
        session.say(f"    Valid: {ceiling_spec.hint}")
        session.say(f"    Current: {show(current.get('max_requests'))}")
        ceiling_text = session.read()
        if ceiling_text == "":
            session.say("    The owner has not given the ceiling, so the checks are not recorded (nothing is"
                        " invented).")
            return
        edits = [(("security_checks",), {"approved": approved, "max_requests": parse(ceiling_spec, ceiling_text)})]
        classes = get_in(session.scope.document, ("test_scope", "allowed_classes"))
        if approved and isinstance(classes, list) and "security-checks" not in classes:
            edits.append((("test_scope", "allowed_classes"), [*classes, "security-checks"]))
            session.say("  (security-checks is added to test_scope.allowed_classes with them: the owner's approval"
                        " of the checks is what allows that class.)")
        if session.accept(edits, ["security_checks", "test_scope.allowed_classes", "limits"], typed):
            return
        session.say("  Type the approved ids again, then the ceiling.")


def _components(session: Session, item: Item, only_open: bool) -> None:
    session.ask(FIELDS["platform.name"], only_open=only_open)
    for name in ("sip_edge", "media_servers", "admin_console", "customer_web_app", "api", "websocket_webrtc",
                 "provisioning", "voicemail", "ivr", "conference", "recording"):
        session.ask(FIELDS[f"platform.components.{name}"], only_open=only_open)


def _third(*names: str) -> Callable[[Session, Item, bool], None]:
    def handler(session: Session, item: Item, only_open: bool) -> None:
        for name in names:
            for key in ("provider", "permission", "reference"):
                session.ask(FIELDS[f"platform.third_parties.{name}.{key}"], only_open=only_open)

    return handler


def _reach(session: Session, item: Item, only_open: bool) -> None:
    names = [row.get("name") for row in (get_in(session.scope.document, ("destinations",)) or [])
             if isinstance(row, dict) and isinstance(row.get("name"), str)]
    if not names:
        session.say("  No destinations are recorded yet (question 11); answer that first.")
        return
    for name in names:
        spec = Field(("platform", "dialing", "reach", name), f"Destination {name}: where does the call go?",
                     "on-net (stays inside the platform) or pstn (reaches the public phone network)", "enum",
                     ("on-net", "pstn"), True)
        session.ask(spec, only_open=only_open)


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
                only_open: bool) -> None:
    for spec in specs:
        key = spec.path[-1]
        rows = _list_rows(session, path)
        current = rows[index].get(key)
        focus = f"{'.'.join(path)}[{index}].{key}"
        if only_open and present(current) and current not in OPEN_WORDS and not session._has_error(focus):
            continue

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
        session.say(f"  Surface {row.get('name')} ({row.get('kind')}):")
        specs = SURFACE_CONNECT_FIELDS
        _row_fields(session, ("application", "surfaces"), index, specs, only_open)
        if _list_rows(session, ("application", "surfaces"))[index].get("tls_ca") == "private":
            _row_fields(session, ("application", "surfaces"), index, (
                _f("tls_ca_file", "Private CA certificate file", "the owner's CA certificate saved under work/,"
                   " e.g. work/acme/owner-ca.crt", open_words=True),), only_open)


def _websocket(session: Session, item: Item, only_open: bool) -> None:
    rows = _list_rows(session, ("application", "surfaces"))
    sockets = [i for i, row in enumerate(rows) if row.get("kind") == "websocket" and row.get("status") != "out-of-scope"]
    if not sockets:
        session.say("  No websocket surface is recorded (question A1: kind websocket); answer that first.")
    for index in sockets:
        session.say(f"  Surface {rows[index].get('name')}:")
        _row_fields(session, ("application", "surfaces"), index, (
            _f("base_url", "WebSocket address", "wss://...", open_words=True),
            _f("allowed_origins", "Allowed origins", "https://... web sites separated by commas", "list",
               open_words=True)), only_open)


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


# ---------------------------------------------------------------- entry points


@dataclass
class Result:
    exit_code: int
    report: Report | None


def answered_view(report: Report) -> Report:
    """The report without findings about time (a window not open yet is answered)."""
    return Report(report.path, report.present, report.sha256,
                  [item for item in report.findings if item.code not in NOTE_CODES], report.document, report.fatal)


def open_items(report: Report) -> list[Item]:
    view = answered_view(report)
    return [item for item in items_for(report.document)
            if item_state(view, item) not in ("answered", "not-applicable")]


def summarize(path: Path, engagement: str, out: TextIO, now: datetime) -> Report:
    """Run the same check as scope check; print what is open and the next command.

    The findings are printed as scope check prints them, except that the
    ``scope.missing`` lines are counted, not listed: the open questions are
    listed by number instead.
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
    pending = open_items(report)
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
    if required:
        out.write(f"Next: {LAUNCHER} scope answer {eng}   (when the owner has answered the open questions)\n")
    elif not report.ok:
        out.write(f"Next: {LAUNCHER} scope check {eng}   (fix what it reports; change one answer with "
                  f"{LAUNCHER} scope answer {eng} NUMBER)\n")
    else:
        out.write(f"Next: {LAUNCHER} scope compile {eng}\n")
    return report


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
        chosen = find_item(items, question)
        if chosen is None:
            raise ScopeError(f"no question '{question}': give its number from scope questions (1 to {len(QUESTIONS)}"
                             f"{', P1 to P18, A1 to A6' if any(i.part == 2 for i in items) else ''}),"
                             " its id (e.g. destinations), or a field (e.g. limits.calls)")
        selected = [chosen]
    else:
        selected = walk_order(items)
    session.say(f"Scope answers: {path}")
    session.say("Type the owner's written answers. Each answer is checked with the same rules as scope check and"
                " saved at once (mode 0600). Comments and everything not asked about stay as they are.")
    session.say(HELP)
    if not interactive:
        session.say("(reading answers from standard input)")
    code = 0
    try:
        asked = 0
        for item in selected:
            state = item_state(answered_view(scope_file.report), item)
            if state == "not-applicable" and question is None:
                continue
            if question is None and not change_all and state == "answered":
                continue
            if question is None and not change_all and item.identifier in OPTIONAL_QUESTIONS:
                continue  # offered in the summary with its own command
            asked += 1
            only_open = question is None and not change_all
            position = f" of {len(QUESTIONS)}" if item.part == 1 else ""
            session.header(item, position)
            if state == "not-applicable":
                session.say("  Not applicable: an earlier answer rules it out.")
                continue
            session.run_item(item, only_open=only_open)
        if session.reapprove and get_in(scope_file.document, STATUS_PATH) != "approved":
            status_item = next(item for item in items if item.identifier == "authorization.status")
            session.header(status_item, f" of {len(QUESTIONS)}")
            _approval(session, status_item, False)
        if asked == 0:
            session.say("Every question is answered. To change one: "
                        f"{LAUNCHER} scope answer {shlex.quote(engagement)} NUMBER (or --all).")
    except Quit:
        session.say("Stopped. The answers recorded so far are saved.")
    except EOFError:
        session.say("Stopped at the end of the input. The answers recorded so far are saved.")
    except KeyboardInterrupt:
        out.write("\nInterrupted. The answers recorded so far are saved; the answer being typed was not.\n")
        code = 130
    except ChangedOnDisk as exc:
        out.write(f"error: {exc}\n")
        code = 2
    except EditError as exc:
        out.write(f"error: {exc}; nothing more was written\n")
        code = 2
    session.say(f"Answers recorded in this session: {session.recorded}")
    report = summarize(path, engagement, out, clock())
    out.write("Network activity: none\n")
    if code:
        return code
    return 0 if report.ok else 1


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
        edits.append((spec.path, parse(spec, raw)))
        focus.append(name)
    edits, reset = with_reapproval(scope_file.document, edits)
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
        out.write(f"Recorded {'.'.join(path)}: {show(value)}\n")
    if reset:
        out.write(f"{REAPPROVE} Run {LAUNCHER} scope answer {shlex.quote(engagement)} 2\n")
    for finding in outcome.notes:
        label = "NOTE" if finding.severity == "error" else "WARN"
        out.write(f"{label} {finding.code} [{finding.field}]: {finding.message}\n")
    report = summarize(scope_file.path, engagement, out, clock())
    out.write("Network activity: none\n")
    return 0 if report.ok else 1
