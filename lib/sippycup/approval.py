"""The owner's approval window for campaigns, and the signaling breadth rule.

A campaign manifest may carry the written approval's window::

    authorization:
      approval:
        id: CHG-1234                       # optional
        validFrom: "2026-11-20T08:00:00Z"  # optional
        validUntil: "2026-11-20T12:00:00Z" # required when approval is present

``campaign plan`` freezes it into ``plan.authorization.approval`` (only when
the manifest states it, so older manifests keep their plan bytes), and
``campaign run`` checks it before any packet and again before every step
(``WindowGate``). A scope file beside the manifest is read too: when the
owner's approval is revoked or changed there, the campaign stops.

Nothing here opens a socket. The clock is injectable for tests.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

# Campaign state and stop reason when the approval window (or the approval
# itself) no longer covers the next step. The guided call's verdict for the
# same stop is spelled ``authorization-lapsed``; campaign states use "_".
LAPSED = "authorization_lapsed"

APPROVAL_KEYS = {"id", "validFrom", "validUntil"}
MAX_APPROVAL_ID = 128
SCOPE_FILE = "scope.yaml"
MAX_SCOPE_BYTES = 1024 * 1024

# Signaling breadth rule for ``authorization.networks``: together at most one
# IPv4 /8 (16,777,216 addresses) and one IPv6 /64 (a single subnet), and no
# network that contains the unspecified ("any") address.
MAX_IPV4_ADDRESSES = 1 << 24
MAX_IPV6_ADDRESSES = 1 << 64

_TIME = re.compile(
    r"\d{4}-\d\d-\d\d[Tt]\d\d:\d\d:\d\d(\.\d{1,6})?([Zz]|[+-]\d\d:\d\d)"
)
_CANONICAL = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")

Clock = Callable[[], datetime]


class ApprovalError(ValueError):
    """A malformed approval block or an over-broad network list."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def stamp(value: datetime) -> str:
    """The one canonical spelling: UTC, whole seconds, ``Z``."""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _instant(value: Any, field: str) -> datetime:
    if isinstance(value, datetime):
        # YAML reads an unquoted RFC 3339 timestamp as a datetime.
        if value.tzinfo is None:
            raise ApprovalError(f"{field} must include a timezone (for example ...Z or ...+01:00)")
        return value.astimezone(timezone.utc)
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        raise ApprovalError(
            f"{field} must be an RFC 3339 timestamp with a timezone, "
            "for example 2026-11-20T12:00:00Z"
        )
    try:
        parsed = datetime.fromisoformat(value.upper().replace("Z", "+00:00"))
    except ValueError as error:
        raise ApprovalError(f"{field} is not a valid date and time") from error
    return parsed.astimezone(timezone.utc)


def _floor(value: datetime) -> datetime:
    return value.replace(microsecond=0)


def _ceil(value: datetime) -> datetime:
    return _floor(value) + timedelta(seconds=1) if value.microsecond else value


def canonical_window(valid_from: Any, valid_until: Any, field: str) -> tuple[str | None, str]:
    """Canonical ``(validFrom, validUntil)``; fractions round to the narrower window."""
    if valid_until is None:
        raise ApprovalError(f"{field}.validUntil is required")
    until = _floor(_instant(valid_until, f"{field}.validUntil"))
    start = None if valid_from is None else _ceil(_instant(valid_from, f"{field}.validFrom"))
    if start is not None and start >= until:
        raise ApprovalError(f"{field}.validFrom must be earlier than validUntil")
    return (None if start is None else stamp(start)), stamp(until)


def manifest_approval(value: Any) -> dict[str, str]:
    """Validate a manifest's ``authorization.approval`` and return the frozen form."""
    field = "authorization.approval"
    if not isinstance(value, dict):
        raise ApprovalError(f"{field} must be a mapping")
    unknown = sorted(str(key) for key in set(value) - APPROVAL_KEYS)
    if unknown:
        raise ApprovalError(f"{field} contains unsupported fields: {', '.join(unknown)}")
    start, until = canonical_window(value.get("validFrom"), value.get("validUntil"), field)
    if "validFrom" in value and start is None:
        raise ApprovalError(f"{field}.validFrom must be a timestamp (omit it for no start)")
    result: dict[str, str] = {}
    if "id" in value:
        identifier = value["id"]
        if (
            not isinstance(identifier, str)
            or not 1 <= len(identifier) <= MAX_APPROVAL_ID
            or not identifier.isprintable()
            or identifier != identifier.strip()
        ):
            raise ApprovalError(
                f"{field}.id must be a quoted string of 1-{MAX_APPROVAL_ID} printable characters "
                "without leading or trailing spaces"
            )
        result["id"] = identifier
    if start is not None:
        result["validFrom"] = start
    result["validUntil"] = until
    return result


def frozen_approval(value: Any) -> dict[str, str]:
    """Independently check a frozen plan's ``authorization.approval``."""
    field = "authorization.approval"
    if not isinstance(value, dict) or not set(value) <= APPROVAL_KEYS or "validUntil" not in value:
        raise ApprovalError(f"{field} must hold validUntil and only id, validFrom, validUntil")
    for key in ("validFrom", "validUntil"):
        if key in value and (
            not isinstance(value[key], str) or _CANONICAL.fullmatch(value[key]) is None
        ):
            raise ApprovalError(f"{field}.{key} is not in frozen form (YYYY-MM-DDTHH:MM:SSZ)")
    if manifest_approval(dict(value)) != value:
        raise ApprovalError(f"{field} is not in canonical frozen form")
    return value


def check_network_breadth(networks: Sequence[Any]) -> None:
    """Refuse "any" networks and totals beyond the documented breadth rule."""
    totals = {4: 0, 6: 0}
    for network in networks:
        if network.network_address.is_unspecified:
            raise ApprovalError(
                f"approved network {str(network)!r} contains the unspecified (any) address; "
                "name the service's own addresses or ranges"
            )
        totals[network.version] += network.num_addresses
    if totals[4] > MAX_IPV4_ADDRESSES:
        raise ApprovalError(
            f"authorization.networks holds {totals[4]} IPv4 addresses, more than the "
            f"{MAX_IPV4_ADDRESSES} allowed (one /8 in total); name the service's own ranges"
        )
    if totals[6] > MAX_IPV6_ADDRESSES:
        raise ApprovalError(
            "authorization.networks holds more IPv6 addresses than one /64 in total; "
            "name the service's own ranges"
        )


def parse_networks(values: Sequence[str]) -> list[Any]:
    return [ipaddress.ip_network(item, strict=True) for item in values]


@dataclass(frozen=True)
class Refusal:
    """Why nothing more may be sent, in words an operator can act on."""

    kind: str  # not-open | expired | too-short | not-approved | scope-changed | scope-unreadable
    message: str


@dataclass(frozen=True)
class Window:
    approval_id: str | None
    valid_from: datetime | None
    valid_until: datetime | None
    source: str | None  # "plan", "scope-file", or None when unbound

    @property
    def bound(self) -> bool:
        return self.valid_until is not None

    def facts(self) -> dict[str, Any]:
        return {
            "bound": self.bound,
            "source": self.source,
            "approvalId": self.approval_id,
            "validFrom": None if self.valid_from is None else stamp(self.valid_from),
            "validUntil": None if self.valid_until is None else stamp(self.valid_until),
        }


def plan_window(plan: Mapping[str, Any]) -> Window:
    """The window a frozen plan carries (unbound when it has none)."""
    authorization = plan.get("authorization") if isinstance(plan, Mapping) else None
    approval = authorization.get("approval") if isinstance(authorization, Mapping) else None
    if not isinstance(approval, Mapping):
        return Window(None, None, None, None)
    try:
        start, until = canonical_window(
            approval.get("validFrom"), approval.get("validUntil"), "authorization.approval"
        )
    except ApprovalError:
        return Window(None, None, None, None)
    identifier = approval.get("id") if isinstance(approval.get("id"), str) else None
    return Window(
        identifier,
        None if start is None else _instant(start, "validFrom"),
        _instant(until, "validUntil"),
        "plan",
    )


def _span(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 120:
        return f"{seconds} s"
    if seconds < 7200:
        return f"{seconds // 60} min"
    return f"{seconds // 3600} h {seconds % 3600 // 60} min"


NEW_WINDOW = (
    "ask the owner for a new written window, record it in scope.yaml, run scope compile, "
    "then campaign plan again"
)


def window_refusal(window: Window, now: datetime, seconds: float = 0, what: str = "") -> Refusal | None:
    """The pure clock rule shared by ``campaign plan`` and ``campaign run``."""
    if not window.bound:
        return None
    assert window.valid_until is not None
    if window.valid_from is not None and now < window.valid_from:
        return Refusal(
            "not-open",
            f"the approval window has not opened yet (valid from {stamp(window.valid_from)}, "
            f"in {_span((window.valid_from - now).total_seconds())}); wait for it to open",
        )
    remaining = (window.valid_until - now).total_seconds()
    if remaining <= 0:
        return Refusal(
            "expired",
            f"the approval window has ended (valid until {stamp(window.valid_until)}); {NEW_WINDOW}",
        )
    if seconds and remaining <= seconds:
        return Refusal(
            "too-short",
            f"{what or 'the next step'} may take up to {_span(seconds)}, but only "
            f"{_span(remaining)} of the approval window remain (valid until "
            f"{stamp(window.valid_until)}); {NEW_WINDOW}",
        )
    return None


def _read_scope(path: Path) -> tuple[Window | None, Refusal | None]:
    """The approval a scope file states now. Fails closed on anything unclear."""
    try:
        import yaml

        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SCOPE_BYTES:
            raise ValueError("it is not a regular file of a sensible size")
        document = yaml.safe_load(path.read_bytes())
        if not isinstance(document, dict) or not isinstance(document.get("authorization"), dict):
            raise ValueError("it has no authorization section")
    except Exception as error:  # noqa: BLE001 - any unreadable scope refuses traffic
        return None, Refusal(
            "scope-unreadable",
            f"the scope file beside the manifest ({path.name}) cannot be read ({error}); "
            "fix it, then run scope check",
        )
    authorization = document["authorization"]
    status = authorization.get("status")
    if status != "approved":
        return None, Refusal(
            "not-approved",
            f"the scope file beside the manifest ({path.name}) says the authorization is "
            f"{status if isinstance(status, str) and status else 'missing'}, not approved; "
            "do not test until the owner approves in writing; then record it in scope.yaml, "
            "run scope compile, and campaign plan again",
        )
    try:
        start, until = canonical_window(
            authorization.get("valid_from"), authorization.get("valid_until"), "scope authorization"
        )
    except ApprovalError as error:
        return None, Refusal(
            "scope-unreadable",
            f"the scope file beside the manifest ({path.name}) has no usable approval window "
            f"({error}); fix it, then run scope check",
        )
    identifier = authorization.get("approval_id")
    return (
        Window(
            identifier.strip() if isinstance(identifier, str) and identifier.strip() else None,
            None if start is None else _instant(start, "valid_from"),
            _instant(until, "valid_until"),
            "scope-file",
        ),
        None,
    )


class WindowGate:
    """Decide, from the clock and the files, whether more traffic may be sent.

    ``refusal(seconds)`` is asked before the run, before every preflight, and
    before every step, with the longest time that piece of work may take. It
    re-reads the scope file beside the manifest each time, so a revoked or
    changed approval takes effect at the next step.
    """

    def __init__(
        self,
        plan: Mapping[str, Any],
        *,
        manifest_path: Path | None = None,
        clock: Clock | None = None,
    ) -> None:
        self.plan_window = plan_window(plan)
        self.clock = clock or utc_now
        self.scope_path = None if manifest_path is None else Path(manifest_path).parent / SCOPE_FILE
        self.window = self.plan_window
        self.stop: dict[str, Any] | None = None
        self._effective()

    def _scope_present(self) -> bool:
        return self.scope_path is not None and (
            self.scope_path.exists() or self.scope_path.is_symlink()
        )

    def _effective(self) -> Refusal | None:
        """Set ``self.window``; return a refusal when the scope file forbids traffic."""
        if not self._scope_present():
            self.window = self.plan_window
            return None
        assert self.scope_path is not None
        scope, refusal = _read_scope(self.scope_path)
        if refusal is not None:
            return refusal
        assert scope is not None
        if not self.plan_window.bound:
            # An older or hand-written plan inside an engagement directory:
            # the scope file's window binds it.
            self.window = scope
            return None
        self.window = self.plan_window
        mine, theirs = self.plan_window, scope
        if (mine.valid_from, mine.valid_until) != (theirs.valid_from, theirs.valid_until) or (
            mine.approval_id != theirs.approval_id
        ):
            return Refusal(
                "scope-changed",
                f"the approval in the scope file beside the manifest ({self.scope_path.name}) "
                "differs from the one frozen in this plan; run scope compile, then campaign "
                "plan again and review the new plan",
            )
        return None

    def refusal(self, seconds: float = 0, what: str = "") -> Refusal | None:
        refusal = self._effective()
        if refusal is not None:
            return refusal
        return window_refusal(self.window, self.clock(), seconds, what)

    def past_end(self) -> bool:
        """Clock-only backstop for a step that is already running."""
        until = self.window.valid_until
        return until is not None and self.clock() >= until

    def record_stop(self, refusal: Refusal, *, before: str, step: int | None = None) -> None:
        if self.stop is None:
            self.stop = {
                "reason": LAPSED,
                "kind": refusal.kind,
                "detail": refusal.message,
                "before": before,
                "step": step,
                "at": stamp(self.clock()),
            }

    def facts(self) -> dict[str, Any]:
        facts = self.window.facts()
        if self.stop is not None:
            facts["stop"] = dict(self.stop)
        return facts


UNBOUND_WARNING = (
    "WARNING: this campaign plan is not bound to an approval window. Nothing stops it after "
    "the owner's approval ends or is revoked: check the written window yourself before and "
    "during the run. To bind it, add authorization.approval (validUntil) to the manifest, or "
    "generate the manifest with scope compile, and plan again."
)
