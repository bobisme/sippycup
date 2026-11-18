"""One private scope intake file: loading, strict validation, and checking.

The scope file is the single place where the service owner's written answers
are recorded. Everything here is offline and host-side. Validation never
resolves names and never opens a socket.

A finding carries a stable ``code``, a ``kind`` (missing, malformed,
inconsistent, secret, unknown, invalid), the offending ``field`` path, and the
derived artifacts it ``blocks`` (profile, campaign, expectations).
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from sippycup.campaign import DOCUMENTATION_NETWORKS, _is_placeholder
from sippycup.tls_trust import TrustError, read_ca, validate_ca_reference, validate_server_name

from .profile import ProfileError, _parse_time

SCOPE_VERSION = "sippycup.dev/scope/v1"
CHECK_VERSION = "sippycup.dev/scope-check/v1"
SCOPE_FILE = "scope.yaml"
MAX_SCOPE_BYTES = 1024 * 1024
U64_MAX = 18446744073709551615

PROFILE = "profile"
CAMPAIGN = "campaign"
EXPECTATIONS = "expectations"
ARTIFACTS = (PROFILE, CAMPAIGN, EXPECTATIONS)

NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
TARGET_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,40}$")
HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
USER_PATTERN = re.compile(r"^[A-Za-z0-9._+@-]{1,128}$")
DEST_USER_PATTERN = re.compile(r"^[A-Za-z0-9._+*#-]{1,64}$")

TRANSPORTS = ("udp", "tcp", "tls")
PROTECTIONS = ("rtp", "sdes-srtp", "dtls-srtp")
CODECS = ("PCMU", "PCMA", "G722", "OPUS")
DTMF_METHODS = ("rfc4733", "sip-info", "inband", "none")
AUTH_STATUSES = ("pending", "approved", "revoked")
EXPECT_BEHAVIORS = ("echo", "agent", "reject")
CREDENTIAL_DELIVERIES = (
    "secret-manager",
    "encrypted-message",
    "in-person",
    "phone-call",
    "other",
)
DISCLOSURES = ("private", "coordinated", "public-after-remediation")
PROFILE_LIMITS = (
    "calls",
    "concurrent_calls",
    "calls_per_second",
    "call_duration_seconds",
)
LIMIT_FIELDS = (
    "calls",
    "concurrent_calls",
    "calls_per_second",
    "packets_per_second",
    "packets",
    "bytes",
    "call_duration_seconds",
    "total_duration_seconds",
)

# Baseline budget model. These are conservative per-run upper bounds, not
# predictions. A call that cannot fit at least the minimum is infeasible.
OPTIONS_PACKETS = 4
OPTIONS_BYTES = 4096
OPTIONS_SECONDS = 3
CALL_SECONDS_TARGET = 20
CALL_RTP_PPS = 100
CALL_SIGNALING_PACKETS = 40
CALL_BYTES_PER_PACKET = 256
CALL_SIGNALING_BYTES = 16384
MIN_CALL_SECONDS = 5
MIN_CALL_PACKETS = 24
MIN_CALL_BYTES = 8192
LOW_RATE_PPS = 100
MAX_ENDPOINTS = 1024
BROAD_V4_PREFIX = 16
BROAD_V6_PREFIX = 48

# The allowed field set at every level of the scope document.
SPEC: dict[str, Any] = {
    "schema_version": None,
    "name": None,
    "authorization": {
        "status": None,
        "approval_id": None,
        "approved_by": None,
        "valid_from": None,
        "valid_until": None,
    },
    "signaling": {"networks": None, "ports": None, "transports": None},
    "targets": [
        {"name", "address", "transport", "port", "tls_server_name", "tls_ca_file"}
    ],
    "media": {
        "networks": None,
        "port_range": {"start", "end"},
        "protection": None,
        "codecs": None,
        "dtmf": None,
        "symmetric_rtp": None,
    },
    "client": {"source_addresses": None},
    "account": {
        "required": None,
        "username": None,
        "realm": None,
        "credential_ref": None,
        "credential_delivery": None,
    },
    "destinations": [{"name", "target", "user", "expect"}],
    "limits": {name: None for name in LIMIT_FIELDS},
    "stop_conditions": {
        "consecutive_failures": None,
        "unexpected_response": None,
        "packet_loss_percent": None,
    },
    "test_scope": {"allowed_classes": None, "exclusions": None},
    "contact": {"name": None, "channel": None, "can_stop_test": None},
    "evidence": {"retention_days": None, "disclosure": None},
    # Optional owner-approved posture checks (see docs/SECURITY-CHECKS.md).
    "security_checks": {"approved": None, "max_requests": None},
}

_SECRET_WORDS = {
    "password",
    "passwd",
    "pass",
    "passphrase",
    "secret",
    "token",
    "psk",
    "bearer",
}
_SECRET_COMPOUNDS = ("private_key", "privatekey", "api_key", "apikey")
_SECRET_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)"),
    re.compile(
        r"(password|passwd|passphrase|secret|token|api[_-]?key)\s*[:=]\s*\S",
        re.I,
    ),
    re.compile(r"\b[a-z][a-z0-9+.-]*:(//)?[^/\s:@]+:[^/\s@]+@", re.I),
    re.compile(r"^(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.I),
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}"),
    re.compile(r"^[A-Za-z0-9+/=_-]{40,}$"),
)


class ScopeError(ValueError):
    """The scope file cannot be created or safely read."""


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    kind: str
    field: str
    message: str
    blocks: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "kind": self.kind,
            "field": self.field,
            "message": self.message,
            "blocks": list(self.blocks),
        }


@dataclass
class Report:
    path: str
    present: bool
    sha256: str | None
    findings: list[Finding] = field(default_factory=list)
    document: dict[str, Any] | None = None
    fatal: bool = False

    @property
    def errors(self) -> list[Finding]:
        return [item for item in self.findings if item.severity == "error"]

    @property
    def warnings(self) -> list[Finding]:
        return [item for item in self.findings if item.severity == "warning"]

    @property
    def complete(self) -> bool:
        return self.present and not any(
            item.kind in {"missing", "secret", "unknown", "invalid"}
            for item in self.errors
        )

    @property
    def consistent(self) -> bool:
        return self.present and not any(
            item.kind in {"malformed", "inconsistent", "expired", "secret", "unknown", "invalid"}
            for item in self.errors
        )

    @property
    def ok(self) -> bool:
        return self.present and not self.errors

    def blocked(self, artifact: str) -> list[Finding]:
        return [item for item in self.findings if artifact in item.blocks]

    def as_dict(self) -> dict[str, Any]:
        return {
            "apiVersion": CHECK_VERSION,
            "scope": {"path": self.path, "present": self.present, "sha256": self.sha256},
            "ok": self.ok,
            "complete": self.complete,
            "consistent": self.consistent,
            "errors": [item.as_dict() for item in self.errors],
            "warnings": [item.as_dict() for item in self.warnings],
            "networkActivity": False,
        }


def slugify(value: str, fallback: str = "engagement") -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:63].strip("-")
    if not slug or not slug[0].isalpha():
        return fallback
    return slug


def default_scope(name: str) -> str:
    """Render the pending scope template. It contains no invented answers."""
    return f"""\
# Sippycup scope intake (sippycup.dev/scope/v1). PRIVATE: keep this file mode
# 0600 and out of version control. Fill it only from the service owner's
# written answers; `./bin/sippycup scope questions` renders the question sheet.
# Never put a password, token, or private key here: credential_ref is only an
# opaque NAME of a secret kept in your approved external secret source.
# Run `./bin/sippycup scope check` after every edit.
schema_version: {SCOPE_VERSION}
name: {name}
authorization:
  status: pending        # pending | approved | revoked
  approval_id: null
  approved_by: null
  valid_from: null       # RFC 3339 with a timezone, e.g. 2026-12-01T09:00:00+01:00
  valid_until: null
signaling:
  networks: []           # literal IPs or CIDRs the owner approved for signaling
  ports: []
  transports: []         # udp | tcp | tls
targets: []              # name, address (literal IP), transport, port, tls_server_name, tls_ca_file
media:
  networks: []           # literal IPs or CIDRs the owner approved for media
  port_range: {{start: null, end: null}}
  protection: []         # rtp | sdes-srtp | dtls-srtp
  codecs: []             # PCMU | PCMA | G722 | OPUS
  dtmf: null             # rfc4733 | sip-info | inband | none
  symmetric_rtp: null    # true when the service sends media to the observed source
client:
  source_addresses: []   # address(es) the service sees us come from, plus our local capture-side address if NAT makes it differ
account:
  required: null         # true | false
  username: null
  realm: null
  credential_ref: null   # NAME of the secret, never the password
  credential_delivery: null   # secret-manager | encrypted-message | in-person | phone-call | other
destinations: []         # name, target, user, expect (echo | agent | reject)
limits:
  calls: null
  concurrent_calls: null
  calls_per_second: null
  packets_per_second: null
  packets: null
  bytes: null
  call_duration_seconds: null
  total_duration_seconds: null
stop_conditions:
  consecutive_failures: null
  unexpected_response: null
  packet_loss_percent: null
test_scope:
  allowed_classes: []   # e.g. options, call
  exclusions: []        # explicit exclusions; write [none] if there are none
contact:
  name: null
  channel: null
  can_stop_test: null
evidence:
  retention_days: null
  disclosure: null       # private | coordinated | public-after-remediation
"""


def create_scope(engagement: str | Path, *, name: str | None = None) -> Path:
    root = Path(engagement)
    destination = root / SCOPE_FILE
    if root.is_symlink():
        raise ScopeError(f"engagement directory is a symlink: {root}")
    chosen = name if name is not None else slugify(root.resolve().name)
    if NAME_PATTERN.fullmatch(chosen) is None:
        raise ScopeError("--name must match [a-z][a-z0-9-]{0,62}")
    if not root.is_dir():
        raise ScopeError(
            f"engagement directory does not exist: {root}; create it first with "
            f"`./bin/sippycup journal init {root}` (or create the directory yourself; either order works)"
        )
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
    except FileExistsError as exc:
        raise ScopeError(f"scope file already exists: {destination}") from exc
    except OSError as exc:
        raise ScopeError(f"cannot create scope file: {exc}") from exc
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(default_scope(chosen))
        output.flush()
        os.fsync(output.fileno())
    destination.chmod(0o600)
    return destination


class _UniqueLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys."""


def _construct_mapping(loader: _UniqueLoader, node: yaml.MappingNode, deep: bool = False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark
            )
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


_UniqueLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def scope_path_for(engagement: str | Path, scope: str | Path | None = None) -> Path:
    return Path(scope) if scope is not None else Path(engagement) / SCOPE_FILE


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _secret_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if set(normalized.split("_")) & _SECRET_WORDS:
        return True
    return any(item in normalized for item in _SECRET_COMPOUNDS)


def _secret_scan(node: Any, path: str, out: list[Finding]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}" if path else str(key)
            if isinstance(key, str) and _secret_key(key):
                out.append(
                    Finding(
                        "scope.secret_field",
                        "error",
                        "secret",
                        child,
                        "field name looks like it carries a password, token, or key; "
                        "store only a credential reference name",
                    )
                )
                continue
            _secret_scan(value, child, out)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _secret_scan(value, f"{path}[{index}]", out)
    elif isinstance(node, str):
        if any(pattern.search(node) for pattern in _SECRET_VALUE_PATTERNS):
            out.append(
                Finding(
                    "scope.secret_value",
                    "error",
                    "secret",
                    path,
                    "value looks like a password, token, or key material; "
                    "the scope file holds credential reference names only",
                )
            )


def _unknown_scan(document: dict[str, Any], out: list[Finding]) -> None:
    def add(path: str) -> None:
        out.append(
            Finding(
                "scope.unknown_field",
                "error",
                "unknown",
                path,
                "unknown field; the scope schema does not allow it",
            )
        )

    for key, value in document.items():
        if key not in SPEC:
            add(str(key))
            continue
        spec = SPEC[key]
        if spec is None or value is None:
            continue
        if isinstance(spec, list):
            if isinstance(value, list):
                for index, item in enumerate(value):
                    if isinstance(item, dict):
                        for sub in item:
                            if sub not in spec[0]:
                                add(f"{key}[{index}].{sub}")
            continue
        if not isinstance(value, dict):
            continue
        for sub, subvalue in value.items():
            if sub not in spec:
                add(f"{key}.{sub}")
                continue
            nested = spec[sub]
            if isinstance(nested, set) and isinstance(subvalue, dict):
                for leaf in subvalue:
                    if leaf not in nested:
                        add(f"{key}.{sub}.{leaf}")


def inspect(
    path: str | Path,
    *,
    now: datetime | None = None,
) -> Report:
    """Read, structurally validate, and check a scope file."""
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        report = Report(str(target), False, None, fatal=True)
        report.findings.append(
            Finding(
                "scope.not_found",
                "error",
                "missing",
                "",
                "scope file does not exist or is not a regular file",
            )
        )
        return report
    try:
        if target.stat().st_size > MAX_SCOPE_BYTES:
            raise ScopeError("scope file exceeds the 1 MiB limit")
        raw = target.read_bytes()
    except (OSError, ScopeError) as exc:
        report = Report(str(target), True, None, fatal=True)
        report.findings.append(
            Finding("scope.unreadable", "error", "invalid", "", f"cannot read scope file: {exc}")
        )
        return report
    digest = hashlib.sha256(raw).hexdigest()
    report = Report(str(target), True, digest)
    try:
        document = yaml.load(raw.decode("utf-8"), Loader=_UniqueLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        first = str(exc).splitlines()[0] if str(exc) else "invalid YAML"
        report.fatal = True
        report.findings.append(
            Finding("scope.unreadable", "error", "invalid", "", f"invalid YAML: {first}")
        )
        return report
    if not isinstance(document, dict):
        report.fatal = True
        report.findings.append(
            Finding("scope.not_object", "error", "invalid", "", "scope file must be a YAML mapping")
        )
        return report
    fatal: list[Finding] = []
    if document.get("schema_version") != SCOPE_VERSION:
        fatal.append(
            Finding(
                "scope.schema_version",
                "error",
                "invalid",
                "schema_version",
                f"schema_version must be {SCOPE_VERSION}",
            )
        )
    _secret_scan(document, "", fatal)
    _unknown_scan(document, fatal)
    if fatal:
        report.fatal = True
        report.findings.extend(fatal)
        return report
    report.document = document
    report.findings.extend(validate(document, now=now))
    return report


def present(value: Any) -> bool:
    return value is not None and value != "" and value != [] and value != {}


def lookup(document: dict[str, Any], dotted: str) -> Any:
    node: Any = document
    for part in dotted.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def canonical_network(text: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(text, strict=True)


def _is_documentation(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    return any(
        network.version == documentation.version and network.subnet_of(documentation)
        for documentation in DOCUMENTATION_NETWORKS
    )


class _Validator:
    def __init__(self, document: dict[str, Any], now: datetime | None) -> None:
        self.doc = document
        self.now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        self.findings: list[Finding] = []

    def add(
        self,
        code: str,
        kind: str,
        field_name: str,
        message: str,
        blocks: tuple[str, ...] = (),
        severity: str = "error",
    ) -> None:
        self.findings.append(Finding(code, severity, kind, field_name, message, blocks))

    def section(self, key: str) -> dict[str, Any]:
        value = self.doc.get(key)
        if value is None:
            return {}
        if not isinstance(value, dict):
            self.add("scope.malformed", "malformed", key, f"{key} must be a mapping", ARTIFACTS)
            return {}
        return value

    def missing(self, path: str, what: str, blocks: tuple[str, ...]) -> None:
        self.add("scope.missing", "missing", path, f"{what} is unanswered", blocks)

    def string(
        self,
        container: dict[str, Any],
        key: str,
        path: str,
        what: str,
        blocks: tuple[str, ...],
        *,
        pattern: re.Pattern[str] | None = None,
        enum: tuple[str, ...] | None = None,
        maximum: int = 200,
    ) -> str | None:
        value = container.get(key)
        if not present(value):
            self.missing(path, what, blocks)
            return None
        if not isinstance(value, str) or not value.strip() or len(value) > maximum:
            self.add("scope.malformed", "malformed", path, f"{what} must be a non-empty string", blocks)
            return None
        if enum is not None and value not in enum:
            self.add(
                "scope.malformed",
                "malformed",
                path,
                f"{what} must be one of: {', '.join(enum)}",
                blocks,
            )
            return None
        if pattern is not None and pattern.fullmatch(value) is None:
            self.add("scope.malformed", "malformed", path, f"{what} has an unsupported format", blocks)
            return None
        return value

    def integer(
        self,
        container: dict[str, Any],
        key: str,
        path: str,
        what: str,
        blocks: tuple[str, ...],
        *,
        minimum: int = 1,
        maximum: int = U64_MAX,
    ) -> int | None:
        value = container.get(key)
        if value is None:
            self.missing(path, what, blocks)
            return None
        if type(value) is not int or not minimum <= value <= maximum:
            self.add(
                "scope.malformed",
                "malformed",
                path,
                f"{what} must be an integer from {minimum} to {maximum}",
                blocks,
            )
            return None
        return value

    def boolean(
        self, container: dict[str, Any], key: str, path: str, what: str, blocks: tuple[str, ...]
    ) -> bool | None:
        value = container.get(key)
        if value is None:
            self.missing(path, what, blocks)
            return None
        if type(value) is not bool:
            self.add("scope.malformed", "malformed", path, f"{what} must be true or false", blocks)
            return None
        return value

    def string_list(
        self,
        container: dict[str, Any],
        key: str,
        path: str,
        what: str,
        blocks: tuple[str, ...],
        *,
        enum: tuple[str, ...] | None = None,
        normalize: Any = None,
    ) -> list[str] | None:
        value = container.get(key)
        if not present(value):
            self.missing(path, what, blocks)
            return None
        if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
            self.add("scope.malformed", "malformed", path, f"{what} must be a list of strings", blocks)
            return None
        items = [normalize(item) if normalize else item for item in value]
        if len(set(items)) != len(items):
            self.add("scope.malformed", "malformed", path, f"{what} contains duplicates", blocks)
            return None
        if enum is not None and any(item not in enum for item in items):
            self.add(
                "scope.malformed",
                "malformed",
                path,
                f"{what} entries must be among: {', '.join(enum)}",
                blocks,
            )
            return None
        return items

    def networks(
        self,
        container: dict[str, Any],
        key: str,
        path: str,
        what: str,
        blocks: tuple[str, ...],
    ) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None:
        value = container.get(key)
        if not present(value):
            self.missing(path, what, blocks)
            return None
        if not isinstance(value, list):
            self.add("scope.malformed", "malformed", path, f"{what} must be a list", blocks)
            return None
        result: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        ok = True
        for index, item in enumerate(value):
            where = f"{path}[{index}]"
            try:
                if not isinstance(item, str):
                    raise ValueError
                network = canonical_network(item.strip())
            except ValueError:
                self.add(
                    "scope.malformed",
                    "malformed",
                    where,
                    "must be a literal IP address or a CIDR with no host bits set",
                    blocks,
                )
                ok = False
                continue
            if _is_documentation(network):
                self.add(
                    "scope.placeholder_value",
                    "inconsistent",
                    where,
                    "documentation-only range is a placeholder; the campaign planner rejects it",
                    blocks,
                )
                ok = False
            if network.prefixlen < (
                BROAD_V4_PREFIX if network.version == 4 else BROAD_V6_PREFIX
            ):
                self.add(
                    "scope.network_too_broad",
                    "inconsistent",
                    where,
                    "network is unusually broad; confirm the owner really approved it",
                    (),
                    "warning",
                )
            result.append(network)
        if len({str(item) for item in result}) != len(result):
            self.add("scope.malformed", "malformed", path, f"{what} contains duplicates", blocks)
            ok = False
        return result if ok else None


def validate(document: dict[str, Any], *, now: datetime | None = None) -> list[Finding]:
    v = _Validator(document, now)
    all_three = ARTIFACTS

    # name
    v.string(document, "name", "name", "engagement name", (PROFILE, CAMPAIGN), pattern=NAME_PATTERN)

    # authorization
    auth = v.section("authorization")
    status = v.string(auth, "status", "authorization.status", "approval status", (PROFILE, CAMPAIGN), enum=AUTH_STATUSES)
    if status is not None and status != "approved":
        v.add(
            "scope.authorization_not_approved",
            "inconsistent",
            "authorization.status",
            f"authorization is {status}, not approved",
            (CAMPAIGN,),
        )
    v.string(auth, "approval_id", "authorization.approval_id", "approval identifier", (CAMPAIGN,), maximum=128)
    v.string(auth, "approved_by", "authorization.approved_by", "name of who approves", (CAMPAIGN,), maximum=128)
    window: dict[str, datetime | None] = {}
    for key in ("valid_from", "valid_until"):
        path = f"authorization.{key}"
        raw = auth.get(key)
        if raw is None:
            v.missing(path, f"{key.replace('_', ' ')}", (CAMPAIGN,))
            window[key] = None
            continue
        try:
            window[key] = _parse_time(raw, path)
        except ProfileError as exc:
            v.add("scope.malformed", "malformed", path, str(exc), (CAMPAIGN,))
            window[key] = None
    start, end = window.get("valid_from"), window.get("valid_until")
    if start and end and start >= end:
        v.add("scope.window_order", "inconsistent", "authorization.valid_from",
              "valid_from must precede valid_until", (CAMPAIGN,))
    else:
        if start and v.now < start:
            v.add("scope.window_not_started", "expired", "authorization.valid_from",
                  "validity window has not started yet", (CAMPAIGN,))
        if end and v.now >= end:
            v.add("scope.window_expired", "expired", "authorization.valid_until",
                  "validity window has expired", (CAMPAIGN,))

    # signaling envelope
    signaling = v.section("signaling")
    sig_networks = v.networks(signaling, "networks", "signaling.networks", "signaling addresses", (CAMPAIGN,))
    sig_ports: list[int] | None = None
    raw_ports = signaling.get("ports")
    if not present(raw_ports):
        v.missing("signaling.ports", "signaling ports", (CAMPAIGN,))
    elif (
        not isinstance(raw_ports, list)
        or not all(type(p) is int and 1 <= p <= 65535 for p in raw_ports)
        or len(set(raw_ports)) != len(raw_ports)
    ):
        v.add("scope.malformed", "malformed", "signaling.ports",
              "signaling ports must be unique integers from 1 to 65535", (CAMPAIGN,))
    else:
        sig_ports = list(raw_ports)
    sig_transports = v.string_list(
        signaling, "transports", "signaling.transports", "signaling transports",
        (CAMPAIGN,), enum=TRANSPORTS, normalize=lambda item: item,
    )

    # targets
    targets: list[dict[str, Any]] = []
    raw_targets = document.get("targets")
    target_blocks = all_three
    if not present(raw_targets):
        v.missing("targets", "signaling target(s) to test", target_blocks)
    elif not isinstance(raw_targets, list):
        v.add("scope.malformed", "malformed", "targets", "targets must be a list", target_blocks)
    else:
        names: set[str] = set()
        for index, item in enumerate(raw_targets):
            where = f"targets[{index}]"
            if not isinstance(item, dict):
                v.add("scope.malformed", "malformed", where, "target must be a mapping", target_blocks)
                continue
            before = len(v.findings)
            name = v.string(item, "name", f"{where}.name", "target name", target_blocks, pattern=TARGET_NAME_PATTERN)
            if name in names:
                v.add("scope.malformed", "malformed", f"{where}.name", "duplicate target name", target_blocks)
                name = None
            elif name:
                names.add(name)
            address_text = v.string(item, "address", f"{where}.address", "target address", target_blocks, maximum=64)
            address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
            if address_text is not None:
                try:
                    address = ipaddress.ip_address(address_text.strip())
                except ValueError:
                    v.add("scope.malformed", "malformed", f"{where}.address",
                          "target address must be a literal IP address (no hostnames)", target_blocks)
            transport = v.string(item, "transport", f"{where}.transport", "target transport", target_blocks, enum=TRANSPORTS)
            port = v.integer(item, "port", f"{where}.port", "target signaling port", target_blocks, minimum=1, maximum=65535)
            tls_name = item.get("tls_server_name")
            tls_blocks = (PROFILE, CAMPAIGN)
            if tls_name is not None:
                if (
                    not isinstance(tls_name, str)
                    or HOSTNAME_PATTERN.fullmatch(tls_name) is None
                    or _is_ip(tls_name)
                ):
                    v.add("scope.malformed", "malformed", f"{where}.tls_server_name",
                          "TLS server name must be a DNS name, not an IP address", tls_blocks)
                    tls_name = None
                else:
                    try:
                        validate_server_name(tls_name)
                    except TrustError as exc:
                        placeholder = "placeholder" in str(exc)
                        v.add(
                            "scope.placeholder_value" if placeholder else "scope.malformed",
                            "inconsistent" if placeholder else "malformed",
                            f"{where}.tls_server_name", str(exc), tls_blocks,
                        )
                        tls_name = None
            if transport == "tls" and item.get("tls_server_name") is None:
                v.add("scope.tls_server_name_missing", "inconsistent", f"{where}.tls_server_name",
                      "TLS target requires the server name to validate", (CAMPAIGN,))
            tls_ca = item.get("tls_ca_file")
            if tls_ca is not None:
                if transport is not None and transport != "tls":
                    v.add("scope.tls_ca_without_tls", "inconsistent", f"{where}.tls_ca_file",
                          "a TLS CA file is only valid for a tls target", tls_blocks)
                    tls_ca = None
                else:
                    try:
                        read_ca(validate_ca_reference(tls_ca))
                    except TrustError as exc:
                        v.add("scope.tls_ca_unreadable", "malformed", f"{where}.tls_ca_file",
                              f"{exc} (spell it work/ENGAGEMENT/FILE.crt; omit it for a public CA)",
                              tls_blocks)
                        tls_ca = None
            if address is not None and _is_placeholder(str(address)):
                v.add("scope.placeholder_value", "inconsistent", f"{where}.address",
                      "documentation or placeholder address; the campaign planner rejects it", target_blocks)
            if address is not None and sig_networks and not any(
                address.version == net.version and address in net for net in sig_networks
            ):
                v.add("scope.target_outside_networks", "inconsistent", f"{where}.address",
                      "target address is outside the approved signaling networks", target_blocks)
            if port is not None and sig_ports is not None and port not in sig_ports:
                v.add("scope.port_not_approved", "inconsistent", f"{where}.port",
                      "target port is not in the approved signaling ports", target_blocks)
            if transport is not None and sig_transports is not None and transport not in sig_transports:
                v.add("scope.transport_not_approved", "inconsistent", f"{where}.transport",
                      "target transport is not in the approved signaling transports", target_blocks)
            if not any(f.severity == "error" for f in v.findings[before:]):
                targets.append(
                    {
                        "name": name,
                        "address": str(address),
                        "transport": transport,
                        "port": port,
                        "tls_server_name": tls_name,
                        "tls_ca_file": tls_ca,
                    }
                )
        addresses = [t["address"] for t in targets]
        if len(set(addresses)) != len(addresses):
            # Same address on distinct ports is legitimate; only identical tuples collide.
            tuples = [(t["address"], t["transport"], t["port"]) for t in targets]
            if len(set(tuples)) != len(tuples):
                v.add("scope.malformed", "malformed", "targets",
                      "two targets share the same address, transport, and port", target_blocks)

    # media
    media = v.section("media")
    media_networks = v.networks(media, "networks", "media.networks", "media addresses", (CAMPAIGN, EXPECTATIONS))
    port_range = media.get("port_range")
    media_range: tuple[int, int] | None = None
    if not isinstance(port_range, dict) and port_range is not None:
        v.add("scope.malformed", "malformed", "media.port_range", "media.port_range must be a mapping", (CAMPAIGN,))
    else:
        port_range = port_range or {}
        low = v.integer(port_range, "start", "media.port_range.start", "media port range start", (CAMPAIGN,), maximum=65535)
        high = v.integer(port_range, "end", "media.port_range.end", "media port range end", (CAMPAIGN,), maximum=65535)
        if low is not None and high is not None:
            if low > high:
                v.add("scope.media_ports_invalid", "inconsistent", "media.port_range",
                      "media port range start is above its end", (CAMPAIGN,))
            else:
                media_range = (low, high)
    protection = v.string_list(media, "protection", "media.protection", "expected media protection", (PROFILE,), enum=PROTECTIONS)
    codecs = v.string_list(media, "codecs", "media.codecs", "expected codecs", (EXPECTATIONS,),
                           enum=CODECS, normalize=lambda item: item.strip().upper())
    dtmf = v.string(media, "dtmf", "media.dtmf", "DTMF method", (EXPECTATIONS,), enum=DTMF_METHODS)
    symmetric = v.boolean(media, "symmetric_rtp", "media.symmetric_rtp",
                          "whether media is sent to the observed source address", (EXPECTATIONS,))

    client = v.section("client")
    client_sources = v.string_list(client, "source_addresses", "client.source_addresses",
                                   "source address(es) of our test traffic", (EXPECTATIONS,))
    if client_sources is not None:
        for index, item in enumerate(client_sources):
            try:
                ipaddress.ip_address(item)
            except ValueError:
                v.add("scope.malformed", "malformed", f"client.source_addresses[{index}]",
                      "must be a literal IP address", (EXPECTATIONS,))

    # account
    account = v.section("account")
    required = v.boolean(account, "required", "account.required", "whether calls require an account", (CAMPAIGN,))
    if required:
        v.string(account, "username", "account.username", "account username", (CAMPAIGN,), pattern=USER_PATTERN)
        v.string(account, "realm", "account.realm", "account realm", (CAMPAIGN,),
                 pattern=re.compile(r"^[A-Za-z0-9._-]{1,253}$"))
        ref = account.get("credential_ref")
        if not present(ref):
            v.add("scope.credential_ref_missing", "missing", "account.credential_ref",
                  "account required but no credential reference name is recorded", (CAMPAIGN,))
        else:
            v.string(account, "credential_ref", "account.credential_ref", "credential reference name",
                     (CAMPAIGN,), pattern=NAME_PATTERN)
        v.string(account, "credential_delivery", "account.credential_delivery",
                 "how the password will be delivered", (CAMPAIGN,), enum=CREDENTIAL_DELIVERIES)

    # test scope (needed before destinations)
    test_scope = v.section("test_scope")
    classes = v.string_list(test_scope, "allowed_classes", "test_scope.allowed_classes",
                            "allowed test classes", (CAMPAIGN,), normalize=lambda item: item.strip().lower())
    if classes is not None and any(NAME_PATTERN.fullmatch(item) is None for item in classes):
        v.add("scope.malformed", "malformed", "test_scope.allowed_classes",
              "test classes must be short lowercase names such as options or call", (CAMPAIGN,))
        classes = None
    exclusions = v.string_list(test_scope, "exclusions", "test_scope.exclusions", "explicit exclusions", ())
    if classes is not None and exclusions is not None:
        clash = sorted(set(classes) & {item.strip().lower() for item in exclusions})
        if clash:
            v.add("scope.class_excluded", "inconsistent", "test_scope.exclusions",
                  f"class is both allowed and excluded: {', '.join(clash)}", (CAMPAIGN,))
    if classes is not None and not ({"options", "call"} & set(classes)):
        v.add("scope.no_baseline_class", "inconsistent", "test_scope.allowed_classes",
              "neither options nor call is allowed, so no baseline case can be generated", (CAMPAIGN,))

    # destinations
    call_allowed = classes is not None and "call" in classes
    destinations = document.get("destinations")
    dest_blocks = (CAMPAIGN,)
    valid_dest: list[dict[str, Any]] = []
    if not present(destinations):
        if classes is None or call_allowed:
            v.missing("destinations", "destination(s) to dial", dest_blocks)
    elif not isinstance(destinations, list):
        v.add("scope.malformed", "malformed", "destinations", "destinations must be a list", dest_blocks)
    else:
        target_names = [t["name"] for t in targets]
        seen: set[str] = set()
        for index, item in enumerate(destinations):
            where = f"destinations[{index}]"
            if not isinstance(item, dict):
                v.add("scope.malformed", "malformed", where, "destination must be a mapping", dest_blocks)
                continue
            before = len(v.findings)
            dname = v.string(item, "name", f"{where}.name", "destination name", dest_blocks, pattern=NAME_PATTERN)
            if dname in seen:
                v.add("scope.malformed", "malformed", f"{where}.name", "duplicate destination name", dest_blocks)
            elif dname:
                seen.add(dname)
            v.string(item, "user", f"{where}.user", "destination to dial", dest_blocks, pattern=DEST_USER_PATTERN)
            expect = v.string(item, "expect", f"{where}.expect", "expected destination behavior", dest_blocks, enum=EXPECT_BEHAVIORS)
            tname = item.get("target")
            if tname is None:
                if len(raw_targets or []) == 1 and target_names:
                    tname = target_names[0]
                elif present(raw_targets):
                    v.missing(f"{where}.target", "which target this destination is on", dest_blocks)
            if tname is not None and target_names is not None and tname not in target_names and present(raw_targets):
                v.add("scope.destination_target_unknown", "inconsistent", f"{where}.target",
                      "destination refers to a target that is not defined or not valid", dest_blocks)
                tname = None
            if len(v.findings) == before and tname is not None and expect is not None:
                valid_dest.append({"name": dname, "target": tname, "user": item["user"], "expect": expect})

    # limits
    limits_raw = v.section("limits")
    limits: dict[str, int] = {}
    for name in LIMIT_FIELDS:
        value = v.integer(
            limits_raw,
            name,
            f"limits.{name}",
            name.replace("_", " "),
            (PROFILE, CAMPAIGN) if name in PROFILE_LIMITS else (CAMPAIGN,),
        )
        if value is not None:
            limits[name] = value
    if "concurrent_calls" in limits and "calls" in limits and limits["concurrent_calls"] > limits["calls"]:
        v.add("scope.concurrency_exceeds_calls", "inconsistent", "limits.concurrent_calls",
              "concurrent calls cannot exceed total calls", (PROFILE, CAMPAIGN))
    if "call_duration_seconds" in limits and "total_duration_seconds" in limits and (
        limits["call_duration_seconds"] > limits["total_duration_seconds"]
    ):
        v.add("scope.ceiling_infeasible", "inconsistent", "limits.call_duration_seconds",
              "per-call duration exceeds the total duration ceiling", (CAMPAIGN,))
    if "packets_per_second" in limits and limits["packets_per_second"] < LOW_RATE_PPS:
        v.add("scope.ceiling_low_rate", "inconsistent", "limits.packets_per_second",
              f"below {LOW_RATE_PPS} packets per second a bidirectional 20 ms call will be throttled",
              (), "warning")

    # stop conditions
    stops = v.section("stop_conditions")
    v.integer(stops, "consecutive_failures", "stop_conditions.consecutive_failures", "consecutive failure stop", (CAMPAIGN,))
    v.boolean(stops, "unexpected_response", "stop_conditions.unexpected_response", "unexpected response stop", (CAMPAIGN,))
    loss = stops.get("packet_loss_percent")
    if loss is None:
        v.missing("stop_conditions.packet_loss_percent", "packet loss stop", (CAMPAIGN,))
    elif type(loss) not in (int, float) or not 0 <= loss <= 100:
        v.add("scope.malformed", "malformed", "stop_conditions.packet_loss_percent",
              "packet loss stop must be a number from 0 to 100", (CAMPAIGN,))

    # contact and evidence
    contact = v.section("contact")
    v.string(contact, "name", "contact.name", "live contact", (), maximum=100)
    v.string(contact, "channel", "contact.channel", "how to reach the live contact", (), maximum=200)
    can_stop = v.boolean(contact, "can_stop_test", "contact.can_stop_test", "whether the contact can stop the test", ())
    if can_stop is False:
        v.add("scope.contact_cannot_stop", "inconsistent", "contact.can_stop_test",
              "a live contact who can stop the test is required", ())
    evidence = v.section("evidence")
    v.integer(evidence, "retention_days", "evidence.retention_days", "evidence retention", (), maximum=3650)
    v.string(evidence, "disclosure", "evidence.disclosure", "disclosure expectation", (), enum=DISCLOSURES)

    # ceilings that cannot hold even one call
    if len(limits) == len(LIMIT_FIELDS) and targets and classes is not None:
        problem = baseline_budget(
            limits, classes, targets, valid_dest, pps=limits["packets_per_second"]
        )
        if isinstance(problem, list):
            for field_name, message in problem:
                v.add("scope.ceiling_infeasible", "inconsistent", field_name, message, (CAMPAIGN,))

    # media CIDRs become the profile's media-only networks: the profile's
    # breadth rule (media_scope) is checked here so the owner can be asked
    # before compile, and a wide but acceptable range is flagged for review
    if media_networks is not None:
        from .media_scope import MAX_MEDIA_ADDRESSES, validate_networks

        ranges = [n for n in media_networks if n.prefixlen != n.max_prefixlen]
        problems: list[str] = []
        if ranges:
            validate_networks([str(n) for n in ranges], problems, indexed=False)
        for problem in problems:
            v.add("scope.media_network_too_broad", "inconsistent", "media.networks",
                  f"{problem} (the target profile is not generated until this is fixed; "
                  "the campaign manifest is not affected)", (PROFILE,))
        for network in ranges if not problems else []:
            if network.num_addresses > 256:
                v.add("scope.media_network_wide", "inconsistent", "media.networks",
                      f"media network {network} admits {network.num_addresses} addresses as media peers "
                      f"(at most {MAX_MEDIA_ADDRESSES} are accepted); confirm with the owner that every "
                      "address in it is one of their media servers", (), "warning")

    # a media network that the oracle cannot enumerate is a documented skip
    if media_networks is not None and sum(n.num_addresses for n in media_networks) > MAX_ENDPOINTS:
        v.add("scope.media_not_enumerable", "inconsistent", "media.networks",
              f"media networks span more than {MAX_ENDPOINTS} addresses; the oracle allowlist "
              "takes literal addresses only, so expectations are not generated",
              (EXPECTATIONS,), "warning")

    # optional owner-approved security posture checks (absent = none approved)
    from sippycup_checks.scope_support import validate_scope

    for code, kind, field_name, message, severity in validate_scope(
        document, targets=targets, destinations=valid_dest, classes=classes, limits=limits
    ):
        v.add(code, kind, field_name, message, (PROFILE,), severity)
    return v.findings


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def normalized_targets(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Targets with canonical addresses. Call only on a validated document."""
    result = []
    for item in document.get("targets") or []:
        result.append(
            {
                "name": item["name"],
                "address": str(ipaddress.ip_address(item["address"].strip())),
                "transport": item["transport"],
                "port": item["port"],
                "tls_server_name": item.get("tls_server_name"),
                "tls_ca_file": item.get("tls_ca_file"),
            }
        )
    return result


def normalized_destinations(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Destinations with their target resolved (a lone target is implied)."""
    targets = document.get("targets") or []
    result = []
    for item in document.get("destinations") or []:
        target = item.get("target")
        if target is None and len(targets) == 1:
            target = targets[0]["name"]
        result.append(
            {"name": item["name"], "target": target, "user": item["user"], "expect": item["expect"]}
        )
    return result


def baseline_budget(
    limits: dict[str, int],
    classes: list[str],
    targets: list[dict[str, Any]],
    destinations: list[dict[str, Any]],
    *,
    pps: int,
) -> dict[str, Any] | list[tuple[str, str]]:
    """Compute conservative per-run budgets, or list why none can fit.

    Returns a mapping with ``options`` and ``call`` per-run budgets (``None``
    when that class is not generated) and the ``call_targets``, or a list of
    ``(field, message)`` problems when the ceilings cannot hold one baseline.
    """
    problems: list[tuple[str, str]] = []
    names_with_destination = {item["target"] for item in destinations}
    options = "options" in classes
    n = len(targets)
    call_targets = (
        [t["name"] for t in targets if t["name"] in names_with_destination]
        if "call" in classes
        else []
    )
    m = len(call_targets)
    opt_seconds = OPTIONS_SECONDS if options else 0
    opt_packets = OPTIONS_PACKETS if options else 0
    opt_bytes = OPTIONS_BYTES if options else 0
    if m and limits["calls"] < m:
        problems.append(
            ("limits.calls", f"calls ceiling {limits['calls']} cannot hold one call per target ({m})")
        )
    if options and limits["total_duration_seconds"] < n * opt_seconds:
        problems.append(("limits.total_duration_seconds", "total duration cannot hold the OPTIONS probes"))
    if options and limits["packets"] < n * opt_packets:
        problems.append(("limits.packets", "packet ceiling cannot hold the OPTIONS probes"))
    if options and limits["bytes"] < n * opt_bytes:
        problems.append(("limits.bytes", "byte ceiling cannot hold the OPTIONS probes"))
    call_budget = None
    if m and not problems:
        avail_seconds = limits["total_duration_seconds"] - n * opt_seconds
        avail_packets = limits["packets"] - n * opt_packets
        avail_bytes = limits["bytes"] - n * opt_bytes
        seconds = min(limits["call_duration_seconds"], CALL_SECONDS_TARGET, avail_seconds // m)
        if seconds < MIN_CALL_SECONDS:
            problems.append(
                (
                    "limits.total_duration_seconds"
                    if avail_seconds // m < limits["call_duration_seconds"]
                    else "limits.call_duration_seconds",
                    f"duration ceilings cannot hold a call of at least {MIN_CALL_SECONDS} seconds",
                )
            )
        else:
            rate = min(CALL_RTP_PPS, pps)
            packets = min(rate * seconds + CALL_SIGNALING_PACKETS, avail_packets // m)
            if packets < MIN_CALL_PACKETS:
                problems.append(("limits.packets", f"packet ceiling cannot hold a call of at least {MIN_CALL_PACKETS} packets"))
            else:
                size = min(packets * CALL_BYTES_PER_PACKET + CALL_SIGNALING_BYTES, avail_bytes // m)
                if size < MIN_CALL_BYTES:
                    problems.append(("limits.bytes", f"byte ceiling cannot hold a call of at least {MIN_CALL_BYTES} bytes"))
                else:
                    call_budget = {"packets": packets, "bytes": size, "seconds": seconds}
    if problems:
        return problems
    return {
        "options": (
            {"packets": OPTIONS_PACKETS, "bytes": OPTIONS_BYTES, "seconds": OPTIONS_SECONDS}
            if options
            else None
        ),
        "call": call_budget,
        "call_targets": call_targets,
    }
