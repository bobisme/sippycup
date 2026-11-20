"""Scope binding for the optionally-bound senders: ``preflight`` and ``media send``.

``call``, ``matrix``, ``checks`` and ``campaign`` always run from a profile or
a manifest. ``preflight`` and ``media send`` take their destination from the
operator (a host argument, or the remote SDP of a session file), so they can
be bound to a target profile with ``--profile``:

* the profile must pass ``rehearse`` (approved, inside its window, literal
  approved addresses) and the window must cover the planned send;
* a ``preflight`` goes only to the profile's literal ``target.host``, port and
  transport (and its reviewed TLS name and CA);
* a ``media send`` goes only to approved addresses or owner-approved media
  networks, within ``media.port_range`` when the profile has one.

This module adds no validation rule of its own. It composes ``rehearse`` and
``host_is_approved_literal`` from ``profile.py`` and ``profile_scope`` from
``media_scope.py``, and renders the one ``Scope:`` line and ``scope`` object
that both commands print. Nothing here opens a socket or resolves a name.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

REQUIRE_ENV = "SIPPYCUP_REQUIRE_PROFILE"
PREFLIGHT_RESULT_SCHEMA = "sippycup.dev/preflight-result/v1"
# nc 8 s + openssl s_client 12 s + sippycup-options 15 s, as bin/container-preflight bounds them.
PREFLIGHT_PLANNED_SECONDS = 40

UNBOUND_LOOPBACK = "loopback only"


class BindingError(ValueError):
    """The command may not send. ``reasons`` are plain sentences; ``advice`` says what to do."""

    def __init__(self, summary: str, reasons: Sequence[str] = (), advice: str = "") -> None:
        super().__init__(summary)
        self.summary = summary
        self.reasons = tuple(reasons)
        self.advice = advice

    def render(self, command: str) -> str:
        lines = [f"{command} refused: {self.summary}"]
        lines.extend(f"  - {reason}" for reason in self.reasons)
        lines.append("Nothing was sent: no socket was opened and no name was resolved.")
        if self.advice:
            lines.append(f"What to do: {self.advice}")
        return "\n".join(lines)


def require_profile(flag: bool = False, environ: Mapping[str, str] | None = None) -> bool:
    """True when unbound runs are refused (``--require-profile`` or the environment).

    Any value other than empty or ``0`` turns it on, so a typo fails closed.
    """
    value = (os.environ if environ is None else environ).get(REQUIRE_ENV, "")
    return bool(flag) or value.strip() not in {"", "0"}


def _clean(value: Any) -> str:
    """One printable line: operator-written profile text never breaks the Scope line."""
    return "".join(ch if ch.isprintable() else "?" for ch in str(value))[:128]


def _stamp(value: str | None) -> str | None:
    if not value:
        return None
    return datetime.fromisoformat(value).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def display_path(path: str | Path) -> str:
    """Spell an in-image ``/work/...`` path the way the operator typed it (``work/...``)."""
    text = str(path)
    return "work/" + text[len("/work/"):] if text.startswith("/work/") else text


@dataclass(frozen=True)
class Binding:
    """An approved profile whose window covers the planned send."""

    path: str
    document: dict[str, Any]
    name: str
    approval_id: str
    valid_from: str | None
    valid_until: str | None

    def scope_object(self, **extra: Any) -> dict[str, Any]:
        return {
            "binding": "profile",
            "profile": self.name,
            "profileFile": self.path,
            "approvalId": self.approval_id,
            "validFrom": self.valid_from,
            "validUntil": self.valid_until,
            **extra,
        }


def unbound_scope(*, target: str | None = None, reason: str | None = None) -> dict[str, Any]:
    scope: dict[str, Any] = {"binding": "unbound"}
    if target is not None:
        scope["operatorSuppliedTarget"] = target
    if reason is not None:
        scope["reason"] = reason
    return scope


def scope_line(scope: Mapping[str, Any]) -> str:
    """The one ``Scope:`` line every optionally-bound command prints."""
    if scope.get("binding") == "profile":
        window = (
            f"window {scope.get('validFrom')} to {scope.get('validUntil')}"
            if scope.get("validFrom")
            else f"window until {scope.get('validUntil')}"
        )
        return (
            f"Scope: profile {_clean(scope.get('profile'))} "
            f"(approval {_clean(scope.get('approvalId'))}, {window})"
        )
    if scope.get("operatorSuppliedTarget") is not None:
        return f"Scope: UNBOUND (operator-supplied target {_clean(scope['operatorSuppliedTarget'])})"
    return f"Scope: UNBOUND ({_clean(scope.get('reason') or 'no approval checked')})"


def _resolve_profile_path(path: str | Path) -> Path:
    candidate = Path(path)
    # `--profile=work/...` is not rewritten by the launcher; inside the image
    # the same file is /work/...
    if not candidate.exists() and not candidate.is_absolute() and candidate.parts[:1] == ("work",):
        mounted = Path("/", *candidate.parts)
        if mounted.exists():
            return mounted
    return candidate


def load_binding(
    path: str | Path,
    *,
    planned_seconds: float,
    now: datetime | None = None,
    work_root: Path | None = None,
    literal_host: bool = False,
    what: str = "send",
) -> Binding:
    """Load a profile and require that it may send for ``planned_seconds`` from now.

    ``literal_host`` additionally requires ``target.host`` to be one of the
    literal approved addresses (signaling senders), as the guided call does.
    """
    from .profile import ProfileError, host_is_approved_literal, load_profile, rehearse

    shown = display_path(path)
    try:
        document = load_profile(_resolve_profile_path(path))
    except ProfileError as exc:
        raise BindingError(
            f"the profile {shown} cannot be used",
            [str(exc)],
            "give the path of the compiled target profile (for example work/ENGAGEMENT/profile.yaml).",
        ) from exc
    instant = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    rehearsal = rehearse(document, now=instant, work_root=work_root)
    reasons = list(rehearsal.errors)
    from .scope_derive import integrity_error

    # A profile scope compile wrote must still be what it wrote (bn-zqe8).
    refusal = integrity_error(_resolve_profile_path(path))
    if refusal:
        reasons.insert(0, refusal)
    from .profile import with_next_command

    reasons = with_next_command(reasons, _resolve_profile_path(path))
    if literal_host and not host_is_approved_literal(document):
        reasons.append("target.host must itself be one of the literal approved_addresses")
    authorization = rehearsal.facts.get("authorization", {}) if rehearsal.facts else {}
    valid_until = authorization.get("valid_until")
    seconds = max(1, math.ceil(planned_seconds))
    if not reasons and valid_until:
        if instant + timedelta(seconds=seconds) >= datetime.fromisoformat(valid_until):
            reasons.append(
                f"authorization expires before the latest possible end of this {what} "
                f"({seconds}s from now; valid_until {_stamp(valid_until)})"
            )
    if reasons:
        from .profile import _engagement_beside

        # The real directory where it is known (rehearsal 4, finding 6).
        where = _engagement_beside(_resolve_profile_path(path)) or "DIR"
        raise BindingError(
            f"the profile {shown} does not allow sending now",
            reasons,
            f"run `./bin/sippycup rehearse {shown}` and fix what it reports; "
            "for an approval or window problem ask the owner for a new written approval, "
            f"record it in scope.yaml (the approval itself: `./bin/sippycup scope answer {where} 2`) and run "
            f"`./bin/sippycup scope compile {where}`.",
        )
    return Binding(
        path=shown,
        document=document,
        name=str(document.get("name")),
        approval_id=str(document["authorization"]["approval_id"]),
        valid_from=_stamp(authorization.get("valid_from")),
        valid_until=_stamp(valid_until),
    )


def is_loopback(address: str) -> bool:
    """127.0.0.0/8 or ::1 exactly (a mapped or embedded form is not loopback here)."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    if parsed.version == 4:
        return parsed in ipaddress.ip_network("127.0.0.0/8")
    return parsed == ipaddress.ip_address("::1")


def _endpoint(address: str, port: int) -> str:
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def media_scope(
    destinations: Sequence[tuple[str, int]],
    *,
    profile: str | Path | None,
    planned_seconds: float,
    require: bool = False,
    now: datetime | None = None,
    work_root: Path | None = None,
) -> dict[str, Any]:
    """The scope decision for a media send, or :class:`BindingError` when it may not send.

    With a profile every destination must be an approved address or lie in an
    owner-approved media network, and within ``media.port_range`` when the
    profile has one. Without a profile only loopback destinations are
    allowed (fixture work), and not at all when ``require`` is set.
    """
    unique = list(dict.fromkeys(destinations))
    if profile is None:
        if require:
            raise BindingError(
                "a profile is required (--require-profile or "
                f"{REQUIRE_ENV}) and none was given",
                advice="add --profile PROFILE (the approved target profile of this engagement).",
            )
        outside = [_endpoint(a, p) for a, p in unique if not is_loopback(a)]
        if outside:
            raise BindingError(
                "the session's remote SDP names a destination that is not loopback, "
                "and no profile was given",
                [f"destination {item} is not a loopback address" for item in outside],
                "add --profile PROFILE so the destination is checked against the owner's "
                "approval (approved addresses, media networks, media ports and window). "
                "Without a profile, media send works only on loopback, for fixture tests.",
            )
        return unbound_scope(reason=UNBOUND_LOOPBACK)

    from .media_scope import describe, profile_scope

    binding = load_binding(
        profile, planned_seconds=planned_seconds, now=now, work_root=work_root, what="media send"
    )
    scope = profile_scope(binding.document)
    reasons: list[str] = []
    admitted: list[dict[str, Any]] = []
    for address, port in unique:
        rule = scope.rule(address)
        if rule is None:
            reasons.append(
                f"destination {_endpoint(address, port)} is not an approved address"
                + (f" and is in no approved media network ({describe(scope.networks)})" if scope.networks else "")
            )
            continue
        if scope.ports is not None and not scope.ports[0] <= port <= scope.ports[1]:
            reasons.append(
                f"destination {_endpoint(address, port)}: port {port} is outside the approved "
                f"media ports {scope.ports[0]}-{scope.ports[1]}"
            )
            continue
        admitted.append(
            {"destination": _endpoint(address, port), "rule": rule[0], "network": rule[1]}
        )
    if reasons:
        raise BindingError(
            f"the session's remote SDP is outside the scope of profile {_clean(binding.name)} "
            f"({binding.path})",
            reasons,
            "do not send. Check that the session file holds the SDP of the approved call. "
            "If the far end really uses this address or port, ask the owner to approve it in "
            "writing (media networks or media ports), record it in scope.yaml, record the approval "
            "again (`./bin/sippycup scope answer DIR 2`) and run `./bin/sippycup scope compile DIR`.",
        )
    return binding.scope_object(destinations=admitted)


def preflight_scope(
    profile: str | Path,
    *,
    host: str | None = None,
    port: int | None = None,
    transport: str | None = None,
    tls_server_name: str | None = None,
    tls_ca: str | None = None,
    tls_unverified: bool = False,
    now: datetime | None = None,
    work_root: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """``(target, scope)`` for a profile-bound preflight, or :class:`BindingError`.

    The target comes from the profile. Anything the operator also typed must
    match it exactly; a mismatch is refused, never silently replaced.
    """
    binding = load_binding(
        profile,
        planned_seconds=PREFLIGHT_PLANNED_SECONDS,
        now=now,
        work_root=work_root,
        literal_host=True,
        what="preflight",
    )
    target = binding.document["target"]
    reasons: list[str] = []
    if host is not None and host != target["host"]:
        reasons.append(f"host {_clean(host)} is not the profile's target.host {target['host']}")
    if port is not None and port != target["port"]:
        reasons.append(f"port {port} is not the profile's target.port {target['port']}")
    if transport is not None and transport != target["transport"]:
        reasons.append(
            f"transport {_clean(transport)} is not the profile's target.transport {target['transport']}"
        )
    name = target.get("tls_server_name")
    ca_reference = target.get("tls_ca_file")
    ca_mounted = None if ca_reference is None else "/" + ca_reference
    if target["transport"] == "tls":
        if tls_unverified:
            reasons.append(
                "--tls-unverified cannot be used with a profile: the profile's TLS target is always verified"
            )
        if tls_server_name is not None and tls_server_name != name:
            reasons.append(
                f"--tls-server-name {_clean(tls_server_name)} is not the profile's "
                f"target.tls_server_name ({name or 'none'})"
            )
        if tls_ca is not None and tls_ca != ca_mounted:
            reasons.append(
                f"--tls-ca {display_path(_clean(tls_ca))} is not the profile's "
                f"target.tls_ca_file ({ca_reference or 'none'})"
            )
    elif tls_unverified or tls_server_name is not None or tls_ca is not None:
        reasons.append(
            f"TLS options were given but the profile's target.transport is {target['transport']}"
        )
    if reasons:
        raise BindingError(
            f"what was asked does not match profile {_clean(binding.name)} ({binding.path})",
            reasons,
            f"run `./bin/sippycup preflight --profile {binding.path}` with no host, port or "
            "transport: they come from the profile. To test another address, the owner must "
            "approve it and the profile must be compiled again.",
        )
    resolved = {
        "host": target["host"],
        "port": target["port"],
        "transport": target["transport"],
        "tlsServerName": name if target["transport"] == "tls" else None,
        "tlsCa": ca_mounted if target["transport"] == "tls" else None,
    }
    return resolved, binding.scope_object()


# --- helper for bin/container-preflight (a bash script) -----------------------


def _helper_resolve(arguments: argparse.Namespace) -> int:
    try:
        target, scope = preflight_scope(
            arguments.profile,
            host=arguments.host,
            port=arguments.port,
            transport=arguments.transport,
            tls_server_name=arguments.tls_server_name,
            tls_ca=arguments.tls_ca,
            tls_unverified=arguments.tls_unverified,
        )
    except BindingError as error:
        print(error.render("preflight"), file=sys.stderr)
        return 2
    # One `key=value` per line; every value is a validated profile field or
    # text made printable, so the shell reads them with `read -r`.
    print(f"host={target['host']}")
    print(f"port={target['port']}")
    print(f"transport={target['transport']}")
    print(f"tls_server_name={target['tlsServerName'] or ''}")
    print(f"tls_ca={target['tlsCa'] or ''}")
    print(f"scope_line={scope_line(scope)}")
    print(f"scope_json={json.dumps(scope, sort_keys=True, separators=(',', ':'))}")
    return 0


def _helper_report(arguments: argparse.Namespace) -> int:
    try:
        scope = json.loads(arguments.scope_json) if arguments.scope_json else unbound_scope(target=arguments.host)
        options = json.loads(arguments.options_json) if arguments.options_json else None
    except ValueError:
        print("preflight: internal error building the JSON result", file=sys.stderr)
        return 5
    document = {
        "schema": PREFLIGHT_RESULT_SCHEMA,
        "target": {"host": arguments.host, "port": arguments.port, "transport": arguments.transport},
        "scope": scope,
        "dryRun": arguments.dry_run,
        "networkActivity": not arguments.dry_run,
        "exitStatus": arguments.exit_status,
        "options": options,
    }
    print(json.dumps(document, sort_keys=True, separators=(",", ":")))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m sippycup_workbench.binding")
    commands = parser.add_subparsers(dest="command", required=True)
    resolve = commands.add_parser("preflight-resolve")
    resolve.add_argument("--profile", required=True)
    resolve.add_argument("--host")
    resolve.add_argument("--port", type=int)
    resolve.add_argument("--transport")
    resolve.add_argument("--tls-server-name")
    resolve.add_argument("--tls-ca")
    resolve.add_argument("--tls-unverified", action="store_true")
    report = commands.add_parser("preflight-report")
    report.add_argument("--host", required=True)
    report.add_argument("--port", type=int, required=True)
    report.add_argument("--transport", required=True)
    report.add_argument("--scope-json", default="")
    report.add_argument("--options-json", default="")
    report.add_argument("--exit-status", type=int, required=True)
    report.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args(argv)
    if arguments.command == "preflight-resolve":
        return _helper_resolve(arguments)
    return _helper_report(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
