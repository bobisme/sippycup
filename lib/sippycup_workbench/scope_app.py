"""Platform, production-safety, and application-surface answers in the scope file.

Two optional top-level sections of ``scope.yaml``:

``platform``
    What the owner's whole product is, which parts are in scope, whether it is
    production with real customers, which other companies are involved, where
    dialed calls end up, the production limits, and which literal addresses
    stand behind each public name.

``application``
    The web, API, and WebSocket surfaces, the test identities, the stored
    object classes, and the owner's route inventory.

Everything here is offline. Nothing in this module resolves a name, opens a
socket, or sends a request, and no Sippycup command sends HTTP or WebSocket
traffic to the surfaces recorded here: no live application runner exists.

Answer states. Any answer may be the word ``pending`` (asked, waiting for the
owner) or ``unknown`` (the owner does not know yet). Both are OPEN, exactly
like a missing answer. Nothing is ever inferred from an open answer, and an
open answer is shown as open, never as not-applicable.

Severity rule (see docs/SCOPE-INTAKE.md, "Platform and application answers"):

* A WRONG answer (unknown field, secret, malformed value, a hostname where a
  literal address belongs, two answers that contradict each other) is an
  error like anywhere else in the file: correct it, or write ``pending``.
* An OPEN answer is never an error. It is a warning when it gates a surface
  that is in scope or a production-safety answer; that surface stays
  ``pending`` in the application-surfaces artifact. The SIP/RTP derivatives
  are not affected.
* Three contradictions touch SIP traffic itself and are errors that hold the
  profile and the campaign: a destination that reaches the public phone
  network without the carrier's permission and a toll answer, a destination
  on the never-dial list, and a concurrency ceiling above the production
  maximum.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

from sippycup.campaign import _is_placeholder
from sippycup.tls_trust import TrustError, validate_ca_reference

APPLICATION = "application-surfaces"
PROFILE = "profile"
CAMPAIGN = "campaign"

OPEN = ("pending", "unknown")
ANSWERED = "answered"
UNANSWERED = "unanswered"
PENDING = "pending"
UNKNOWN = "unknown"
NOT_APPLICABLE = "not-applicable"

COMPONENTS = (
    "sip_edge",
    "media_servers",
    "admin_console",
    "customer_web_app",
    "api",
    "websocket_webrtc",
    "provisioning",
    "voicemail",
    "ivr",
    "conference",
    "recording",
)
COMPONENT_LABELS = {
    "sip_edge": "SIP edge",
    "media_servers": "media servers",
    "admin_console": "admin console",
    "customer_web_app": "customer web app",
    "api": "API",
    "websocket_webrtc": "browser calling (WebSocket/WebRTC)",
    "provisioning": "phone provisioning",
    "voicemail": "voicemail",
    "ivr": "IVR menus",
    "conference": "conferencing",
    "recording": "call recording",
}
WEB_COMPONENTS = ("admin_console", "customer_web_app", "api", "websocket_webrtc")
COMPONENT_STATES = ("in-scope", "out-of-scope", *OPEN)
ENVIRONMENTS = ("production", "staging", "dedicated-test", *OPEN)
THIRD_PARTIES = ("hosting", "cdn_waf", "pstn_carrier", "sms", "email")
THIRD_PARTY_LABELS = {
    "hosting": "hosting or cloud provider",
    "cdn_waf": "CDN or web firewall",
    "pstn_carrier": "phone carrier or PSTN gateway",
    "sms": "SMS provider",
    "email": "email provider",
}
PERMISSIONS = ("out-of-path", "permitted", *OPEN)
REACHES = ("on-net", "pstn", *OPEN)
TOLLS = ("no-cost", "accepted", "refused", *OPEN)
SURFACE_KINDS = ("browser", "api", "websocket")
SURFACE_STATES = ("in-scope", "out-of-scope", *OPEN)
TLS_CAS = ("public", "private", *OPEN)
INVENTORY_KINDS = ("openapi", "har", "route-list", "none", *OPEN)
INVENTORY_PROVIDED = ("openapi", "har", "route-list")

_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_ROLE = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$")
_DIAL = re.compile(r"^[A-Za-z0-9._+*#-]{1,64}$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
_WORK_REFERENCE = re.compile(r"^work/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")

_FREE = "free-keys"

# The allowed field set at every level of the two sections.
APP_SPEC: dict[str, Any] = {
    "platform": {
        "name": None,
        "components": {name: None for name in COMPONENTS},
        "out_of_scope": None,
        "environment": {
            "kind": None,
            "real_customers": None,
            "test_tenant": None,
            "never_touch": None,
        },
        "third_parties": {
            name: {"provider": None, "permission": None, "reference": None}
            for name in THIRD_PARTIES
        },
        "dialing": {
            "reach": _FREE,
            "never_dial": None,
            "never_dial_prefixes": None,
            "toll": None,
        },
        "operations": {
            "allowed_hours": None,
            "max_concurrent_calls": None,
            "max_requests_per_second": None,
            "blocking": None,
            "emergency_contact": {"name": None, "channel": None},
            "stop_signal": None,
        },
        "addressing": [{"name": None, "addresses": None, "shared": None, "changing": None}],
    },
    "application": {
        "surfaces": [
            {
                "name": None,
                "kind": None,
                "status": None,
                "base_url": None,
                "connect_address": None,
                "connect_port": None,
                "tls_server_name": None,
                "tls_ca": None,
                "tls_ca_file": None,
                "allowed_origins": None,
            }
        ],
        "identities": [{"id": None, "role": None, "tenant": None, "credential_ref": None}],
        "object_classes": None,
        "route_inventory": {"kind": None, "file": None},
    },
}
SECTIONS = tuple(APP_SPEC)


def has_sections(document: dict[str, Any] | None) -> bool:
    """True when the scope file records a platform or application section."""
    return isinstance(document, dict) and any(
        isinstance(document.get(key), dict) for key in SECTIONS
    )


def state_of(value: Any) -> str:
    """answered, pending, unknown, or unanswered for one recorded answer."""
    if value is None or value == "" or value == [] or value == {}:
        return UNANSWERED
    if isinstance(value, str) and value in OPEN:
        return value
    return ANSWERED


def worst(states: list[str]) -> str:
    """The state of a question made of several answers."""
    for candidate in (UNANSWERED, UNKNOWN, PENDING):
        if candidate in states:
            return candidate
    return ANSWERED if states else UNANSWERED


def _section(document: dict[str, Any], *path: str) -> dict[str, Any]:
    node: Any = document
    for part in path:
        node = node.get(part) if isinstance(node, dict) else None
    return node if isinstance(node, dict) else {}


def _items(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _is_none_list(value: Any) -> bool:
    return isinstance(value, list) and [str(item).strip().lower() for item in value] == ["none"]


# ---------------------------------------------------------------- unknown fields


def unknown_scan(document: dict[str, Any], add: Callable[[str], None]) -> None:
    """Report every field the two sections do not allow, at any depth."""

    def walk(value: Any, spec: Any, path: str) -> None:
        if spec is None or spec == _FREE or value is None:
            return
        if isinstance(spec, list):
            if isinstance(value, list):
                for index, item in enumerate(value):
                    walk(item, spec[0], f"{path}[{index}]")
            return
        if not isinstance(value, dict):
            return
        for key, child in value.items():
            where = f"{path}.{key}"
            if key not in spec:
                add(where)
                continue
            walk(child, spec[key], where)

    for key in SECTIONS:
        walk(document.get(key), APP_SPEC[key], key)


# -------------------------------------------------------------------- validation


class _Check:
    """Typed readers that add findings through the scope validator."""

    def __init__(self, validator: Any) -> None:
        self.v = validator

    def error(self, code: str, kind: str, path: str, message: str,
              blocks: tuple[str, ...] = (APPLICATION,)) -> None:
        self.v.add(code, kind, path, message, blocks)

    def warn(self, code: str, kind: str, path: str, message: str) -> None:
        self.v.add(code, kind, path, message, (APPLICATION,), "warning")

    def malformed(self, path: str, message: str) -> None:
        self.error("scope.malformed", "malformed", path, message)

    def mapping(self, container: dict[str, Any], key: str, path: str) -> dict[str, Any]:
        value = container.get(key)
        if value is None:
            return {}
        if not isinstance(value, dict):
            self.malformed(path, f"{path} must be a mapping")
            return {}
        return value

    def text(self, container: dict[str, Any], key: str, path: str, what: str, *,
             maximum: int = 200, pattern: re.Pattern[str] | None = None,
             hint: str = "") -> str | None:
        value = container.get(key)
        if state_of(value) != ANSWERED:
            return None
        if not isinstance(value, str) or not value.strip() or len(value) > maximum:
            self.malformed(path, f"{what} must be text of at most {maximum} characters "
                                 "(or pending / unknown)")
            return None
        if pattern is not None and pattern.fullmatch(value) is None:
            self.malformed(path, f"{what} has an unsupported format{hint}")
            return None
        return value

    def choice(self, container: dict[str, Any], key: str, path: str, what: str,
               allowed: tuple[str, ...]) -> str | None:
        value = container.get(key)
        if value is None:
            return None
        if not isinstance(value, str) or value not in allowed:
            self.malformed(path, f"{what} must be one of: {', '.join(allowed)}")
            return None
        return value

    def flag(self, container: dict[str, Any], key: str, path: str, what: str) -> bool | None:
        value = container.get(key)
        if state_of(value) != ANSWERED:
            return None
        if type(value) is not bool:
            self.malformed(path, f"{what} must be true, false, pending, or unknown")
            return None
        return value

    def number(self, container: dict[str, Any], key: str, path: str, what: str,
               maximum: int = 1_000_000) -> int | None:
        value = container.get(key)
        if state_of(value) != ANSWERED:
            return None
        if type(value) is not int or not 1 <= value <= maximum:
            self.malformed(path, f"{what} must be a whole number from 1 to {maximum}, "
                                 "pending, or unknown")
            return None
        return value

    def words(self, container: dict[str, Any], key: str, path: str, what: str, *,
              pattern: re.Pattern[str] | None = None, hint: str = "") -> list[str] | None:
        """A list of short texts; ``[none]`` is an explicit empty answer."""
        value = container.get(key)
        if state_of(value) != ANSWERED:
            return None
        if (
            not isinstance(value, list)
            or len(value) > 64
            or not all(isinstance(item, str) and item.strip() and len(item) <= 200 for item in value)
        ):
            self.malformed(path, f"{what} must be a list of at most 64 texts in quotes "
                                 "(write [none] for none, or pending / unknown)")
            return None
        if len(set(value)) != len(value):
            self.malformed(path, f"{what} contains duplicates")
            return None
        if _is_none_list(value):
            return []
        if pattern is not None and any(pattern.fullmatch(item) is None for item in value):
            self.malformed(path, f"{what} has an entry in an unsupported format{hint}")
            return None
        return list(value)


def _literal(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip())) if isinstance(value, str) else None
    except ValueError:
        return None


def _dns_name(value: Any) -> bool:
    return isinstance(value, str) and _HOSTNAME.fullmatch(value) is not None and _literal(value) is None


def _url_problem(value: str, schemes: tuple[str, ...], *, origin: bool = False) -> str | None:
    if len(value) > 512:
        return "is longer than 512 characters"
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return "is not a valid URL"
    if parsed.scheme not in schemes:
        return f"must start with {' or '.join(item + '://' for item in schemes)}"
    if not parsed.hostname:
        return "has no host name"
    if parsed.username is not None or parsed.password is not None:
        return "must not carry a user name or password"
    if parsed.query or parsed.fragment:
        return "must not carry a query or fragment"
    if port is not None and not 1 <= port <= 65535:
        return "has an invalid port"
    if origin and parsed.path not in {"", "/"}:
        return "must be an origin (scheme and host only, no path)"
    return None


def _url_host(value: Any) -> str | None:
    try:
        return urlsplit(value).hostname if isinstance(value, str) else None
    except ValueError:
        return None


def validate_sections(validator: Any, document: dict[str, Any], *, limits: dict[str, int]) -> None:
    """Validate the optional platform and application sections.

    ``validator`` is the scope validator (it collects the findings). A scope
    file without either section gets no finding from here.
    """
    if not any(key in document and document[key] is not None for key in SECTIONS):
        return
    check = _Check(validator)
    for key in SECTIONS:
        if document.get(key) is not None and not isinstance(document[key], dict):
            check.malformed(key, f"{key} must be a mapping")
    platform = _section(document, "platform")
    application = _section(document, "application")

    # what is in scope
    check.text(platform, "name", "platform.name", "product or platform name", maximum=100)
    components = check.mapping(platform, "components", "platform.components")
    for name in COMPONENTS:
        check.choice(components, name, f"platform.components.{name}",
                     f"{COMPONENT_LABELS[name]} scope", COMPONENT_STATES)
    check.words(platform, "out_of_scope", "platform.out_of_scope", "out-of-scope list")

    # environment
    environment = check.mapping(platform, "environment", "platform.environment")
    check.choice(environment, "kind", "platform.environment.kind", "environment", ENVIRONMENTS)
    check.flag(environment, "real_customers", "platform.environment.real_customers",
               "whether real customers use it")
    check.text(environment, "test_tenant", "platform.environment.test_tenant",
               "test tenant label", maximum=64, pattern=_LABEL,
               hint=" (a short label; write none if there is no test tenant)")
    check.words(environment, "never_touch", "platform.environment.never_touch", "never-touch list")

    # third parties
    third = check.mapping(platform, "third_parties", "platform.third_parties")
    permissions: dict[str, str | None] = {}
    for name in THIRD_PARTIES:
        where = f"platform.third_parties.{name}"
        entry = check.mapping(third, name, where)
        check.text(entry, "provider", f"{where}.provider", f"{THIRD_PARTY_LABELS[name]} name", maximum=100)
        permissions[name] = check.choice(entry, "permission", f"{where}.permission",
                                         f"{THIRD_PARTY_LABELS[name]} permission", PERMISSIONS)
        check.text(entry, "reference", f"{where}.reference", "where the permission is written")

    # dialing
    dialing = check.mapping(platform, "dialing", "platform.dialing")
    destinations = {
        item.get("name"): item.get("user")
        for item in _items(document.get("destinations"))
        if isinstance(item.get("name"), str)
    }
    reach_raw = dialing.get("reach")
    reach: dict[str, str] = {}
    if reach_raw is not None and not isinstance(reach_raw, dict):
        check.malformed("platform.dialing.reach",
                        "reach must map each destination name to on-net, pstn, pending, or unknown")
    elif isinstance(reach_raw, dict):
        for name, value in reach_raw.items():
            where = f"platform.dialing.reach.{name}"
            if not isinstance(value, str) or value not in REACHES:
                check.malformed(where, f"reach must be one of: {', '.join(REACHES)}")
                continue
            if name not in destinations:
                check.error("scope.reach_unknown_destination", "inconsistent", where,
                            "reach names a destination that is not in destinations[]; "
                            "use the destination's name exactly as written there")
                continue
            reach[name] = value
    quoted = " (write each number in quotes, for example \"112\")"
    never = check.words(dialing, "never_dial", "platform.dialing.never_dial",
                        "never-dial list", pattern=_DIAL, hint=quoted)
    prefixes = check.words(dialing, "never_dial_prefixes", "platform.dialing.never_dial_prefixes",
                           "never-dial prefix list", pattern=_DIAL, hint=quoted)
    toll = check.choice(dialing, "toll", "platform.dialing.toll", "toll cost answer", TOLLS)
    for index, item in enumerate(_items(document.get("destinations"))):
        user, name = item.get("user"), item.get("name")
        if not isinstance(user, str):
            continue
        hit = user in (never or []) or any(user.startswith(prefix) for prefix in prefixes or [])
        if hit:
            check.error("scope.destination_never_dial", "inconsistent", f"destinations[{index}].user",
                        "this destination is on the owner's never-dial list "
                        "(platform.dialing); remove the destination or correct the list",
                        (PROFILE, CAMPAIGN, APPLICATION))
        if reach.get(name) == "pstn":
            problems = []
            if permissions.get("pstn_carrier") != "permitted":
                problems.append("the carrier's permission is not recorded as permitted "
                                "(platform.third_parties.pstn_carrier.permission)")
            if toll not in {"no-cost", "accepted"}:
                problems.append("the toll cost answer is not no-cost or accepted (platform.dialing.toll)")
            if problems:
                check.error("scope.pstn_destination_unconfirmed", "inconsistent",
                            f"platform.dialing.reach.{name}",
                            f"destination {name} reaches the public phone network, but "
                            + " and ".join(problems)
                            + "; no call may leave the platform until the owner answers both, "
                            "or remove the destination",
                            (PROFILE, CAMPAIGN, APPLICATION))
    if "pstn" in reach.values() and permissions.get("pstn_carrier") == "out-of-path":
        check.error("scope.carrier_answer_conflict", "inconsistent",
                    "platform.third_parties.pstn_carrier.permission",
                    "the carrier is recorded as out of the path, but a destination reaches the "
                    "public phone network; one of the two answers is wrong",
                    (PROFILE, CAMPAIGN, APPLICATION))

    # operations
    operations = check.mapping(platform, "operations", "platform.operations")
    check.text(operations, "allowed_hours", "platform.operations.allowed_hours", "allowed hours")
    max_calls = check.number(operations, "max_concurrent_calls",
                             "platform.operations.max_concurrent_calls", "maximum concurrent calls")
    check.number(operations, "max_requests_per_second",
                 "platform.operations.max_requests_per_second", "maximum requests per second")
    check.text(operations, "blocking", "platform.operations.blocking",
               "monitoring and automatic blocking", maximum=400)
    emergency = check.mapping(operations, "emergency_contact", "platform.operations.emergency_contact")
    check.text(emergency, "name", "platform.operations.emergency_contact.name", "emergency contact", maximum=100)
    check.text(emergency, "channel", "platform.operations.emergency_contact.channel",
               "how to reach the emergency contact")
    check.text(operations, "stop_signal", "platform.operations.stop_signal", "stop signal")
    if max_calls is not None and limits.get("concurrent_calls", 0) > max_calls:
        check.error("scope.limit_exceeds_production", "inconsistent", "limits.concurrent_calls",
                    f"limits.concurrent_calls is above the production maximum the owner gave "
                    f"(platform.operations.max_concurrent_calls: {max_calls}); lower the ceiling "
                    "or ask the owner which number is right",
                    (PROFILE, CAMPAIGN, APPLICATION))

    # names versus addresses
    by_name: dict[str, dict[str, Any]] = {}
    addressing = platform.get("addressing")
    if state_of(addressing) == ANSWERED and not isinstance(addressing, list):
        check.malformed("platform.addressing", "addressing must be a list (or pending / unknown)")
    for index, item in enumerate(addressing if isinstance(addressing, list) else []):
        where = f"platform.addressing[{index}]"
        if not isinstance(item, dict):
            check.malformed(where, "each addressing entry must be a mapping")
            continue
        name = item.get("name")
        if not _dns_name(name):
            check.malformed(f"{where}.name", "name must be a public DNS name (an identity; it is never looked up)")
            name = None
        elif name.lower() in by_name:
            check.malformed(f"{where}.name", "duplicate name")
            name = None
        addresses: list[str] = []
        raw = item.get("addresses")
        if state_of(raw) == ANSWERED:
            if not isinstance(raw, list):
                check.malformed(f"{where}.addresses", "addresses must be a list of literal IP addresses "
                                                       "(or pending / unknown)")
            else:
                for position, text in enumerate(raw):
                    literal = _literal(text)
                    if literal is None:
                        check.malformed(f"{where}.addresses[{position}]",
                                        "must be a literal IP address; a name is not an address "
                                        "(write pending until the owner gives the address)")
                    else:
                        addresses.append(literal)
        shared = check.flag(item, "shared", f"{where}.shared", "whether the address is shared with other customers")
        changing = check.flag(item, "changing", f"{where}.changing", "whether the addresses change")
        if name:
            by_name[name.lower()] = {"addresses": addresses, "shared": shared, "changing": changing,
                                     "path": where, "name": name}
    for index, item in enumerate(_items(document.get("targets"))):
        literal = _literal(item.get("address"))
        for entry in by_name.values():
            if literal is None or literal not in entry["addresses"]:
                continue
            if entry["shared"] is True:
                check.warn("scope.address_shared", "inconsistent", f"{entry['path']}.shared",
                           f"{entry['name']} ({literal}, SIP target targets[{index}]) is shared with other "
                           "customers: the owner's permission alone does not cover them; get the "
                           "provider's written permission or a dedicated address")
            if entry["changing"] is True:
                check.warn("scope.address_changing", "inconsistent", f"{entry['path']}.changing",
                           f"the addresses behind {entry['name']} change (SIP target targets[{index}]): "
                           "ask the owner to confirm the literal address again right before each session")

    # application surfaces
    surfaces = application.get("surfaces")
    if state_of(surfaces) == ANSWERED and not isinstance(surfaces, list):
        check.malformed("application.surfaces", "surfaces must be a list (or pending / unknown)")
    seen: set[str] = set()
    in_scope_surface = False
    for index, item in enumerate(surfaces if isinstance(surfaces, list) else []):
        where = f"application.surfaces[{index}]"
        if not isinstance(item, dict):
            check.malformed(where, "each surface must be a mapping")
            continue
        name = check.text(item, "name", f"{where}.name", "surface name", pattern=_NAME,
                          hint=" (lowercase letters, digits, and -)")
        if name is None and state_of(item.get("name")) != ANSWERED:
            check.malformed(f"{where}.name", "every surface needs a short name, for example admin-console")
        elif name in seen:
            check.malformed(f"{where}.name", "duplicate surface name")
        elif name:
            seen.add(name)
        kind = check.choice(item, "kind", f"{where}.kind", "surface kind", SURFACE_KINDS)
        status = check.choice(item, "status", f"{where}.status", "surface status", SURFACE_STATES)
        in_scope_surface = in_scope_surface or status == "in-scope"
        url = item.get("base_url")
        host = None
        if state_of(url) == ANSWERED:
            schemes = ("wss",) if kind == "websocket" else ("https",) if kind else ("https", "wss")
            problem = "must be text" if not isinstance(url, str) else _url_problem(url, schemes)
            if problem:
                check.malformed(f"{where}.base_url", f"base URL {problem}")
            else:
                host = _url_host(url)
                if host and _is_placeholder(host):
                    check.error("scope.placeholder_value", "inconsistent", f"{where}.base_url",
                                "placeholder or documentation host name")
        address = item.get("connect_address")
        literal = None
        if state_of(address) == ANSWERED:
            literal = _literal(address)
            if literal is None:
                check.malformed(f"{where}.connect_address",
                                "connect address must be a literal IP address (no hostnames: a name is an "
                                "identity, never a destination); write pending until the owner gives it")
            elif _is_placeholder(literal):
                check.error("scope.placeholder_value", "inconsistent", f"{where}.connect_address",
                            "documentation or placeholder address")
        check.number(item, "connect_port", f"{where}.connect_port", "connect port", maximum=65535)
        tls_name = item.get("tls_server_name")
        if state_of(tls_name) == ANSWERED:
            if not _dns_name(tls_name):
                check.malformed(f"{where}.tls_server_name", "TLS server name must be a DNS name, not an IP address")
            elif _is_placeholder(tls_name):
                check.error("scope.placeholder_value", "inconsistent", f"{where}.tls_server_name",
                            "placeholder TLS server name")
        tls_ca = check.choice(item, "tls_ca", f"{where}.tls_ca", "TLS CA answer", TLS_CAS)
        if item.get("tls_ca_file") is not None:
            try:
                validate_ca_reference(item["tls_ca_file"])
            except TrustError as exc:
                check.malformed(f"{where}.tls_ca_file", str(exc))
            if tls_ca is not None and tls_ca != "private":
                check.error("scope.tls_ca_conflict", "inconsistent", f"{where}.tls_ca_file",
                            "a CA file is recorded but tls_ca is not private")
        origins = item.get("allowed_origins")
        if state_of(origins) == ANSWERED and not _is_none_list(origins):
            if not isinstance(origins, list) or len(origins) > 16:
                check.malformed(f"{where}.allowed_origins", "allowed origins must be a list of at most 16 "
                                                             "https:// origins (or pending / unknown)")
            else:
                for position, origin in enumerate(origins):
                    problem = ("must be text" if not isinstance(origin, str)
                               else _url_problem(origin, ("https",), origin=True))
                    if problem:
                        check.malformed(f"{where}.allowed_origins[{position}]", f"origin {problem}")
        entry = by_name.get(host.lower()) if host else None
        if entry and literal and entry["addresses"] and literal not in entry["addresses"]:
            check.error("scope.surface_address_mismatch", "inconsistent", f"{where}.connect_address",
                        f"the connect address is not one of the addresses recorded for {entry['name']} "
                        f"({entry['path']}.addresses); one of the two answers is wrong")
        if entry and status == "in-scope":
            if entry["shared"] is True:
                check.warn("scope.address_shared", "inconsistent", f"{entry['path']}.shared",
                           f"{entry['name']} (surface {name or index}) is shared with other customers: the "
                           "owner's permission alone does not cover them")
            if entry["changing"] is True:
                check.warn("scope.address_changing", "inconsistent", f"{entry['path']}.changing",
                           f"the addresses behind {entry['name']} change (surface {name or index}): a literal "
                           "address recorded today may belong to someone else tomorrow")
    web_states = [components.get(name) for name in WEB_COMPONENTS]
    if in_scope_surface and all(item == "out-of-scope" for item in web_states):
        check.error("scope.surface_component_conflict", "inconsistent", "application.surfaces",
                    "a surface is in scope, but platform.components records the admin console, the "
                    "customer web app, the API, and browser calling all as out of scope")

    # identities, object classes, route inventory
    identities = application.get("identities")
    if state_of(identities) == ANSWERED and not isinstance(identities, list):
        check.malformed("application.identities", "identities must be a list (or pending / unknown)")
    ids: set[str] = set()
    for index, item in enumerate(identities if isinstance(identities, list) else []):
        where = f"application.identities[{index}]"
        if not isinstance(item, dict):
            check.malformed(where, "each identity must be a mapping")
            continue
        identifier = check.text(item, "id", f"{where}.id", "identity id", pattern=_NAME,
                                hint=" (lowercase letters, digits, and -)")
        if identifier is None and state_of(item.get("id")) != ANSWERED:
            check.malformed(f"{where}.id", "every identity needs a short id, for example admin-test")
        elif identifier is None:
            pass
        elif identifier in ids:
            check.malformed(f"{where}.id", "duplicate identity id")
        else:
            ids.add(identifier)
        check.text(item, "role", f"{where}.role", "role", pattern=_ROLE,
                   hint=" (a short lowercase name such as admin or customer-user)")
        check.text(item, "tenant", f"{where}.tenant", "tenant label", pattern=_LABEL, hint=" (a short label)")
        check.text(item, "credential_ref", f"{where}.credential_ref", "credential reference name",
                   pattern=_NAME, hint=" (the NAME of the secret in your secret source, never its value)")
    check.words(application, "object_classes", "application.object_classes", "stored object classes",
                pattern=_LABEL, hint=" (short names such as voicemail or recording)")
    inventory = check.mapping(application, "route_inventory", "application.route_inventory")
    check.choice(inventory, "kind", "application.route_inventory.kind", "route inventory kind", INVENTORY_KINDS)
    if inventory.get("file") is not None and (
        not isinstance(inventory["file"], str) or _WORK_REFERENCE.fullmatch(inventory["file"]) is None
        or ".." in inventory["file"].split("/")
    ):
        check.malformed("application.route_inventory.file",
                        "the inventory file must be a relative path beneath work/ (it is recorded, never read)")

    # open answers: warnings only, and only for what they gate
    if any(item.severity == "error" and APPLICATION in item.blocks for item in validator.findings):
        return
    facts = readiness_of(document)
    safety = facts["productionSafety"]
    if safety["applies"] and safety["open"]:
        check.warn("scope.production_safety_open", "missing", "platform",
                   f"{safety['reason']}: {len(safety['open'])} production-safety answer(s) are open: "
                   + ", ".join(safety["open"]) + " (`scope questions DIR` shows them)")
    for name, entry in facts["thirdParties"].items():
        if entry["gates"] and entry["state"] != ANSWERED:
            check.warn("scope.third_party_unresolved", "missing", f"platform.third_parties.{name}",
                       f"{THIRD_PARTY_LABELS[name]}: {entry['why']}; it gates {', '.join(entry['gates'])}. "
                       "The owner cannot give this permission alone: record it as out-of-path or "
                       "permitted (with where that is written) once confirmed")
    for name in facts["reachOpen"]:
        check.warn("scope.destination_reach_open", "missing", f"platform.dialing.reach.{name}",
                   f"it is not recorded whether destination {name} stays on the platform or reaches the "
                   "public phone network; ask the owner before dialing it")
    for surface in facts["surfaces"]:
        if surface["state"] == "pending":
            check.warn("scope.surface_not_ready", "missing", surface["field"],
                       f"surface {surface['name']} is in scope but not ready: " + "; ".join(surface["open"]))
    if facts["open"]:
        check.warn("scope.platform_open", "missing", "platform",
                   f"{len(facts['open'])} of {facts['questions']} platform and application question(s) are "
                   f"open ({', '.join(item['id'] for item in facts['open'])}); "
                   "`scope questions DIR` shows them. Open answers here do not hold the SIP/RTP derivatives")


# --------------------------------------------------------------------- questions


@dataclass(frozen=True)
class AppQuestion:
    identifier: str
    section: str
    text: str
    why: str
    fields: tuple[str, ...]
    states: Callable[[dict[str, Any]], list[str]]
    applies: Callable[[dict[str, Any]], bool] = lambda document: True


def _at(document: dict[str, Any], dotted: str) -> Any:
    node: Any = document
    for part in dotted.split("."):
        node = node.get(part) if isinstance(node, dict) else None
    return node


def _simple(*paths: str) -> Callable[[dict[str, Any]], list[str]]:
    return lambda document: [state_of(_at(document, path)) for path in paths]


def _scope_states(document: dict[str, Any]) -> list[str]:
    components = _section(document, "platform", "components")
    return [state_of(_at(document, "platform.name"))] + [state_of(components.get(name)) for name in COMPONENTS]


def third_party_state(document: dict[str, Any], name: str) -> tuple[str, str]:
    """State of one third-party answer and, when open, why in plain words."""
    entry = _section(document, "platform", "third_parties", name)
    permission = state_of(entry.get("permission"))
    if permission != ANSWERED:
        return permission, f"permission is {permission}"
    if entry.get("permission") == "permitted":
        for key, what in (("provider", "the provider's name"), ("reference", "where the permission is written")):
            state = state_of(entry.get(key))
            if state != ANSWERED:
                return state, f"permitted, but {what} is {state}"
    return ANSWERED, ""


def _third(*names: str) -> Callable[[dict[str, Any]], list[str]]:
    return lambda document: [third_party_state(document, name)[0] for name in names]


def _destination_names(document: dict[str, Any]) -> list[str]:
    return [item["name"] for item in _items(document.get("destinations")) if isinstance(item.get("name"), str)]


def _reach_states(document: dict[str, Any]) -> list[str]:
    reach = _section(document, "platform", "dialing", "reach")
    names = _destination_names(document)
    return [state_of(reach.get(name)) for name in names] if names else [UNANSWERED]


def _addressing_states(document: dict[str, Any]) -> list[str]:
    value = _at(document, "platform.addressing")
    if not isinstance(value, list):
        return [state_of(value)]
    states = [UNANSWERED] if not value else []
    for item in _items(value):
        states += [state_of(item.get(key)) for key in ("name", "addresses", "shared", "changing")]
    return states


def _surfaces(document: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(_at(document, "application.surfaces"))


def _surface_states(*keys: str, live_only: bool = False) -> Callable[[dict[str, Any]], list[str]]:
    def states(document: dict[str, Any]) -> list[str]:
        value = _at(document, "application.surfaces")
        if not isinstance(value, list):
            return [state_of(value)]
        chosen = [item for item in _items(value) if not (live_only and item.get("status") == "out-of-scope")]
        if not value:
            return [UNANSWERED]
        result: list[str] = []
        for item in chosen:
            required = keys if item.get("status") != "out-of-scope" else tuple(
                key for key in keys if key in {"name", "kind", "status"})
            result += [state_of(item.get(key)) for key in required]
        return result or [ANSWERED]

    return states


def _websocket_states(document: dict[str, Any]) -> list[str]:
    value = _at(document, "application.surfaces")
    if not isinstance(value, list):
        return [state_of(value)]
    sockets = [item for item in _items(value) if item.get("kind") == "websocket"
               and item.get("status") != "out-of-scope"]
    if not sockets:
        return [UNANSWERED]
    result: list[str] = []
    for item in sockets:
        result += [state_of(item.get("base_url")), state_of(item.get("allowed_origins"))]
    return result


def _identity_states(document: dict[str, Any]) -> list[str]:
    value = _at(document, "application.identities")
    if not isinstance(value, list):
        return [state_of(value)]
    states = [UNANSWERED] if not value else []
    for item in _items(value):
        states += [state_of(item.get(key)) for key in ("id", "role", "tenant", "credential_ref")]
    return states


def _web_applies(document: dict[str, Any]) -> bool:
    components = _section(document, "platform", "components")
    return not all(components.get(name) == "out-of-scope" for name in WEB_COMPONENTS)


def _websocket_applies(document: dict[str, Any]) -> bool:
    return _at(document, "platform.components.websocket_webrtc") != "out-of-scope"


_PARTS = "What is in scope"
_ENV = "Environment and data"
_THIRD = "Other companies involved"
_DIALING = "Where our test calls go"
_OPS = "Limits on the live system"
_NAMES = "Names and addresses"
_WEB = "Web, API, and browser-calling surfaces"

APP_QUESTIONS: tuple[AppQuestion, ...] = (
    AppQuestion(
        "P1", _PARTS,
        "What is the product or platform called, and which of its parts do you want tested? For each part "
        "please say yes, no, or not sure: the SIP edge (where phones and trunks connect), the media servers "
        "(the audio), the admin console, the customer web app or portal, the API, calling from a browser "
        "(WebSocket/WebRTC), phone provisioning, voicemail, IVR menus, conferencing, call recording.",
        "we test only the parts you say yes to. A part you leave open is treated as not approved.",
        ("platform.name", "platform.components"), _scope_states),
    AppQuestion(
        "P2", _PARTS,
        "What is explicitly OUT of scope? (For example billing, the public marketing site, a partner's "
        "network, other customers' systems.) Write \"nothing\" if nothing is.",
        "a written list of what we must leave alone prevents an honest mistake.",
        ("platform.out_of_scope",), _simple("platform.out_of_scope")),
    AppQuestion(
        "P3", _ENV,
        "Is the system we will test your live production system, a staging copy, or an instance set up "
        "only for this test?",
        "on a live system we work with lower limits and stricter stop rules.",
        ("platform.environment.kind",), _simple("platform.environment.kind")),
    AppQuestion(
        "P4", _ENV,
        "Will real customers be using it while we test?",
        "if they are, a mistake of ours could reach them, so we need the answers below before we start.",
        ("platform.environment.real_customers",), _simple("platform.environment.real_customers")),
    AppQuestion(
        "P5", _ENV,
        "Is there a test tenant, test company, or test account set up only for us? What is it called? "
        "(The name only. Never send a password in your answer.)",
        "everything we create or change should land in a test account, never in a real customer's.",
        ("platform.environment.test_tenant",), _simple("platform.environment.test_tenant")),
    AppQuestion(
        "P6", _ENV,
        "Which data must we never open, play, download, change, or delete? (For example real voicemail, "
        "call recordings, call records, customer accounts.) Write \"none\" only if the system holds no real data.",
        "we treat this list as a hard limit and stop if a test would touch it.",
        ("platform.environment.never_touch",), _simple("platform.environment.never_touch")),
    AppQuestion(
        "P7", _THIRD,
        "Who hosts the platform (which hosting or cloud provider)? Does that provider allow security "
        "testing, and must it be told in advance? Where is that written (a policy page, a ticket, an email)?",
        "you can approve a test of your own systems, but not of another company's. We need each "
        "company's answer as one of: not involved in what we test, permits it, or still to be asked.",
        ("platform.third_parties.hosting",), _third("hosting")),
    AppQuestion(
        "P8", _THIRD,
        "Is there a content delivery network or a web firewall, run by another company, in front of the "
        "web site, the admin console, or the API? If so: which one, and does it permit testing through it?",
        "our requests would pass through that company's systems first, and it may block us or object.",
        ("platform.third_parties.cdn_waf",), _third("cdn_waf")),
    AppQuestion(
        "P9", _THIRD,
        "Which phone carriers or gateways connect the platform to the public phone network? Could any of "
        "our test calls leave your platform through them? If so: do they permit test calls?",
        "a call that leaves your platform uses the carrier's network, can cost money, and can ring a "
        "real phone.",
        ("platform.third_parties.pstn_carrier",), _third("pstn_carrier")),
    AppQuestion(
        "P10", _THIRD,
        "Does the platform send text messages (SMS) or email through an outside provider, and could our "
        "tests cause it to send any (for example a voicemail notification or a password reset)?",
        "messages sent by a test go through another company and may reach real people.",
        ("platform.third_parties.sms", "platform.third_parties.email"), _third("sms", "email")),
    AppQuestion(
        "P11", _DIALING,
        "For each destination we may dial (the destinations question in part 1): does the call stay "
        "inside your platform (a test extension, an echo service), or does it go out to the public "
        "phone network?",
        "we dial a number that reaches the public phone network only after you and the carrier have "
        "said yes in writing.",
        ("platform.dialing.reach",), _reach_states),
    AppQuestion(
        "P12", _DIALING,
        "Which numbers must we never dial? Please list emergency numbers, premium-rate and international "
        "prefixes, and any real customer's number that the platform could reach. Write \"none\" only if "
        "the platform cannot reach any of them.",
        "the list is checked against every destination before a call is planned.",
        ("platform.dialing.never_dial",), _simple("platform.dialing.never_dial")),
    AppQuestion(
        "P13", _DIALING,
        "If a test call does reach the public phone network: does it cost money, and do you accept that "
        "cost for this test?",
        "we do not spend your money, or anyone else's, without a written yes.",
        ("platform.dialing.toll",), _simple("platform.dialing.toll")),
    AppQuestion(
        "P14", _OPS,
        "During which hours may we test? Please give days, times, and the timezone.",
        "on a live system we test when a problem would hurt least and your people can be reached.",
        ("platform.operations.allowed_hours",), _simple("platform.operations.allowed_hours")),
    AppQuestion(
        "P15", _OPS,
        "What is the most we may do at the same time: how many calls at once, and how many web or API "
        "requests per second?",
        "we set our tools to stay under your numbers; we never pick them ourselves.",
        ("platform.operations.max_concurrent_calls", "platform.operations.max_requests_per_second"),
        _simple("platform.operations.max_concurrent_calls", "platform.operations.max_requests_per_second")),
    AppQuestion(
        "P16", _OPS,
        "Which alarms or automatic blocks could our tests set off (monitoring alerts, fraud detection, "
        "rate limits, automatic address bans after failed logins)? What happens then, and who can undo a block?",
        "so your team is not alarmed by our test, and we know why we are suddenly blocked.",
        ("platform.operations.blocking",), _simple("platform.operations.blocking")),
    AppQuestion(
        "P17", _OPS,
        "Who do we call if something breaks (a name and a phone number that is answered during the test "
        "hours)? And what is your stop signal: the word or message from you that means \"stop now\"?",
        "when you send the stop signal we stop at once and ask questions afterwards.",
        ("platform.operations.emergency_contact", "platform.operations.stop_signal"),
        _simple("platform.operations.emergency_contact.name", "platform.operations.emergency_contact.channel",
                "platform.operations.stop_signal")),
    AppQuestion(
        "P18", _NAMES,
        "For each public name of the platform (for example the names phones register to, the admin "
        "console, the API): which numeric IP address or addresses are behind it? Is any of those "
        "addresses shared with other customers of your provider? Is it behind a load balancer or "
        "delivery network whose addresses change?",
        "a name is not a destination. We never look names up; we send only to the numeric addresses you "
        "give us in writing, because a name can point somewhere else tomorrow. An address shared with "
        "other companies cannot be tested on your permission alone.",
        ("platform.addressing",), _addressing_states),
    AppQuestion(
        "A1", _WEB,
        "For the admin console, the customer web app, and the API: what is the web address (URL) of "
        "each? Is each one used by people in a browser, or by programs?",
        "the web address tells us which site we are talking about. It is an identity only; we do not "
        "send anything to it on the strength of the name.",
        ("application.surfaces",), _surface_states("name", "kind", "status", "base_url"), _web_applies),
    AppQuestion(
        "A2", _WEB,
        "For each of those: which numeric IP address and port should we connect to, which name is on its "
        "TLS certificate, and was the certificate issued by a public authority or by your own? (If your "
        "own: send us the CA certificate, never a private key.)",
        "we connect only to the numeric address you give and check that the certificate is really yours.",
        ("application.surfaces",),
        _surface_states("connect_address", "connect_port", "tls_server_name", "tls_ca", live_only=True),
        _web_applies),
    AppQuestion(
        "A3", _WEB,
        "If calls can be made from a browser: what is the WebSocket address (it starts with wss://), and "
        "which web sites (origins) are allowed to use it?",
        "a browser-calling service should refuse connections from web sites that are not yours; we can "
        "only check that if we know which ones are.",
        ("application.surfaces",), _websocket_states, _websocket_applies),
    AppQuestion(
        "A4", _WEB,
        "Which test accounts will you give us? For each: what it is called, its role (for example "
        "administrator, reseller, customer administrator, ordinary user), and which tenant or company it "
        "belongs to. Please do NOT send passwords in your answer; tell us how you will deliver them, and "
        "we record only a reference name.",
        "we check that each role can do only what it should, and that one customer cannot see another's "
        "data. That needs at least two roles, and ideally two test tenants.",
        ("application.identities",), _identity_states, _web_applies),
    AppQuestion(
        "A5", _WEB,
        "Which kinds of stored files does the platform keep? (For example voicemail messages, call "
        "recordings, greetings, faxes, exported reports.)",
        "stored files are where private data lives; we need to know the kinds, never their contents.",
        ("application.object_classes",), _simple("application.object_classes"), _web_applies),
    AppQuestion(
        "A6", _WEB,
        "Can you give us a list of the pages and API calls the platform has: an OpenAPI file, a browser "
        "recording (HAR file) of a normal session, or a plain list?",
        "we test only what you list. We do not crawl your site or guess addresses.",
        ("application.route_inventory.kind",), _simple("application.route_inventory.kind"), _web_applies),
)
PRODUCTION_SAFETY = ("P4", "P6", "P7", "P11", "P12", "P14", "P15", "P16", "P17")


def _has_error(report: Any, path: str) -> bool:
    if report is None:
        return False
    for finding in report.errors:
        value = finding.field
        if value == path or value.startswith(path + ".") or value.startswith(path + "["):
            return True
    return False


def app_question_state(document: dict[str, Any], question: AppQuestion, report: Any = None) -> str:
    """answered, unanswered, pending, unknown, or not-applicable for one question.

    not-applicable is returned only when the owner's own answer rules the
    question out (those parts are recorded as out of scope), never by a guess.
    """
    if not question.applies(document):
        return NOT_APPLICABLE
    state = worst(question.states(document))
    if state == ANSWERED and any(_has_error(report, path) for path in question.fields):
        return UNANSWERED
    return state


def _short(question: AppQuestion) -> str:
    first = question.text.split("? ")[0].split(". ")[0]
    return first if first.endswith("?") else first + "?"


def readiness_of(document: dict[str, Any], report: Any = None) -> dict[str, Any]:
    """Platform, production-safety, and surface readiness. Values are not included."""
    recorded = has_sections(document)
    states = {q.identifier: app_question_state(document, q, report) for q in APP_QUESTIONS}
    open_items = [
        {"id": q.identifier, "section": q.section, "state": states[q.identifier], "text": _short(q)}
        for q in APP_QUESTIONS
        if states[q.identifier] not in {ANSWERED, NOT_APPLICABLE}
    ]
    kind = _at(document, "platform.environment.kind")
    kind_state = state_of(kind)
    production = kind == "production" or kind_state != ANSWERED
    reason = ("the scope says production" if kind == "production"
              else f"the environment answer is {kind_state}, so it is treated as production")
    safety_items = [item for item in open_items if item["id"] in PRODUCTION_SAFETY] if production else []
    safety_open = [f"{item['id']} ({item['state']})" for item in safety_items]

    components = _section(document, "platform", "components")
    surfaces = _surfaces(document)
    web_live = [item for item in surfaces if item.get("status") == "in-scope"]
    reach = _section(document, "platform", "dialing", "reach")
    reach_open = [name for name in _destination_names(document) if reach.get(name) not in {"on-net", "pstn"}]
    gates: dict[str, list[str]] = {name: [] for name in THIRD_PARTIES}
    in_scope = [COMPONENT_LABELS[name] for name in COMPONENTS if components.get(name) == "in-scope"]
    if in_scope or web_live or document.get("targets"):
        gates["hosting"] = ["everything hosted there"]
    if web_live:
        names = ", ".join(str(item.get("name")) for item in web_live)
        gates["cdn_waf"] = [f"the web surfaces ({names})"]
        gates["sms"] = gates["email"] = [f"the web surfaces ({names})"]
    if reach_open or "pstn" in reach.values():
        gates["pstn_carrier"] = ["calls that may leave the platform"]
    third = {}
    for name in THIRD_PARTIES:
        state, why = third_party_state(document, name)
        third[name] = {"state": state, "why": why, "gates": gates[name] if recorded else []}

    surface_facts = []
    for index, item in enumerate(surfaces):
        status = item.get("status")
        opened: list[str] = []
        if status == "in-scope":
            for key, what in (("base_url", "web address"), ("connect_address", "connect address"),
                              ("connect_port", "connect port"), ("tls_server_name", "TLS certificate name"),
                              ("tls_ca", "certificate authority")):
                state = state_of(item.get(key))
                if state != ANSWERED:
                    opened.append(f"{what} is {state}")
            if item.get("kind") == "websocket" and state_of(item.get("allowed_origins")) != ANSWERED:
                opened.append(f"allowed origins are {state_of(item.get('allowed_origins'))}")
            for name in ("hosting", "cdn_waf"):
                if third[name]["state"] != ANSWERED:
                    opened.append(f"{THIRD_PARTY_LABELS[name]}: {third[name]['why']}")
            if production and safety_open:
                opened.append(f"{len(safety_open)} production-safety answer(s) are open")
            state_name = "pending" if opened else "ready"
        elif status == "out-of-scope":
            state_name = "out-of-scope"
        else:
            state_name = "undecided"
            opened.append(f"whether it is in scope is {state_of(status)}")
        surface_facts.append({"name": str(item.get("name") or f"surface-{index + 1}"),
                              "kind": item.get("kind"), "state": state_name, "open": opened,
                              "field": f"application.surfaces[{index}]"})
    return {
        "recorded": recorded,
        "environment": kind if kind_state == ANSWERED else kind_state,
        "questions": len(APP_QUESTIONS),
        "states": states,
        "open": open_items,
        "productionSafety": {"applies": bool(recorded and production), "reason": reason,
                             "open": safety_open if recorded else [],
                             "questions": safety_items if recorded else []},
        "thirdParties": third,
        "reachOpen": reach_open if recorded else [],
        "pstnDestinations": sorted(name for name, value in reach.items() if value == "pstn"),
        "surfaces": surface_facts,
    }


def readiness(report: Any) -> dict[str, Any] | None:
    """Cockpit facts for a checked scope, or None when it has no document."""
    document = getattr(report, "document", None)
    if document is None:
        return None
    return readiness_of(document, report)


def status_summary(report: Any) -> tuple[dict[str, Any] | None, list[str]]:
    """Facts and warnings for ``status``: states and question numbers only."""
    facts = readiness(report)
    if facts is None or not facts["recorded"]:
        return None, []
    safety = facts["productionSafety"]
    summary = {
        "recorded": True,
        "environment": facts["environment"],
        "openQuestions": [item["id"] for item in facts["open"]],
        "productionSafety": {"applies": safety["applies"], "open": [item["id"] for item in safety["questions"]]},
        "surfaces": [{"name": item["name"], "state": item["state"]} for item in facts["surfaces"]],
        "liveApplicationRunner": False,
    }
    warnings = []
    if safety["applies"] and safety["open"]:
        warnings.append(f"{len(safety['open'])} production-safety answer(s) are open in the scope "
                        f"({', '.join(summary['productionSafety']['open'])}); see scope questions")
    elif facts["open"]:
        warnings.append(f"{len(facts['open'])} platform and application question(s) are open in the scope")
    return summary, warnings


_TAGS = {ANSWERED: "[x]", UNANSWERED: "[ ]", PENDING: "[?]", UNKNOWN: "[?]", NOT_APPLICABLE: "[n/a]"}


def _wrap(prefix: str, text: str, width: int = 100) -> list[str]:
    lines: list[str] = []
    current = prefix
    indent = " " * len(prefix)
    for word in text.split():
        if len(current) + len(word) + 1 > width and current.strip():
            lines.append(current.rstrip())
            current = indent
        current += word + " "
    lines.append(current.rstrip())
    return lines


def render_part(report: Any = None) -> list[str]:
    """Part 2 of the question sheet. Values from the scope file are never echoed."""
    document = getattr(report, "document", None) if report is not None else None
    lines = [
        "",
        "# Part 2: the whole platform (answer this when the test covers a product people use)",
        "",
        "Part 1 above is about one SIP service. This part is about everything around it: the",
        "web site, the admin console, the API, your customers, and the other companies the",
        "platform depends on. Plain answers are fine. If you do not know an answer yet, say so:",
        "we write it down as open and we never guess. An open answer in this part does not",
        "hold up the SIP and audio tests of part 1, unless it is about where calls can end up.",
        "Writing these answers down does not start any web or API test.",
        "",
    ]
    if document is not None and not has_sections(document):
        lines += [
            "NOTE: this scope file has no platform or application section yet, so nothing in",
            "this part is recorded. Copy the two sections from examples/scope/platform-scope.yaml",
            "into scope.yaml (or start a new file with `./bin/sippycup scope init DIR --platform`).",
            "",
        ]
    section = ""
    for question in APP_QUESTIONS:
        if question.section != section:
            section = question.section
            lines += [f"## {section}", ""]
        tag = ""
        if document is not None:
            state = app_question_state(document, question, report)
            tag = f" {_TAGS[state]} ({state})"
        lines += _wrap(f"{question.identifier}. ", question.text + tag)
        lines += _wrap("   Why we ask: ", question.why)
        lines.append("")
    if document is not None:
        lines.append("Part 2 legend: [?] pending means asked and waiting for the answer; [?] unknown means the")
        lines.append("owner does not know yet. Both are open, like [ ]. Nothing is assumed from an open answer.")
    return lines


TEMPLATE = """\
# ---------------------------------------------------------------------------
# Platform and application answers (question sheet part 2; optional sections).
# Every answer may be the word pending (asked, waiting) or unknown (the owner
# does not know yet). Never guess: an open answer stays open. No Sippycup
# command sends web or API requests to anything recorded here.
platform:
  name: null               # the product or platform name
  components:              # each: in-scope | out-of-scope | pending | unknown
    sip_edge: null
    media_servers: null
    admin_console: null
    customer_web_app: null
    api: null
    websocket_webrtc: null
    provisioning: null
    voicemail: null
    ivr: null
    conference: null
    recording: null
  out_of_scope: []         # plain words, in quotes; write [none] if nothing is out of scope
  environment:
    kind: null             # production | staging | dedicated-test | pending | unknown
    real_customers: null   # true | false | pending | unknown
    test_tenant: null      # the test tenant's label; write none if there is none
    never_touch: []        # data we must never open or change, e.g. ["real voicemail", "call records"]
  third_parties:           # permission: out-of-path | permitted | pending | unknown
    hosting:      {provider: null, permission: null, reference: null}
    cdn_waf:      {provider: null, permission: null, reference: null}
    pstn_carrier: {provider: null, permission: null, reference: null}
    sms:          {provider: null, permission: null, reference: null}
    email:        {provider: null, permission: null, reference: null}
                           # reference: where the permission is written (policy page, ticket, email id)
  dialing:
    reach: {}              # destination name -> on-net | pstn | pending | unknown, e.g. {echo: on-net}
    never_dial: []         # exact numbers, IN QUOTES: ["112", "911"]; [none] if none
    never_dial_prefixes: []   # optional prefixes, in quotes: ["00", "+", "0900"]
    toll: null             # no-cost | accepted | refused | pending | unknown
  operations:
    allowed_hours: null    # plain words with a timezone
    max_concurrent_calls: null      # a number | pending | unknown
    max_requests_per_second: null   # a number | pending | unknown (web and API)
    blocking: null         # alarms and automatic blocks we may trigger, and who can undo a block
    emergency_contact: {name: null, channel: null}
    stop_signal: null      # the owner's word or message that means stop now
  addressing: []           # per public name: {name: sip.acme.tld, addresses: ["192.0.2.1"], shared: false, changing: false}
application:
  surfaces: []             # per surface:
  #  - name: admin-console          # short lowercase name
  #    kind: browser                # browser | api | websocket
  #    status: pending              # in-scope | out-of-scope | pending | unknown
  #    base_url: pending            # https://... (wss://... for websocket); an identity, never looked up
  #    connect_address: pending     # literal IP only
  #    connect_port: pending
  #    tls_server_name: pending     # the DNS name on the certificate
  #    tls_ca: pending              # public | private | pending | unknown (private: add tls_ca_file: work/...)
  #    allowed_origins: pending     # websocket: ["https://app.acme.tld"]
  identities: []           # per test account: {id: admin-test, role: admin, tenant: test-a, credential_ref: admin-test}
                           # credential_ref is the NAME of the secret, never its value
  object_classes: []       # kinds of stored files, e.g. [voicemail, recording, greeting]
  route_inventory: {kind: null, file: null}   # kind: openapi | har | route-list | none | pending | unknown
"""
