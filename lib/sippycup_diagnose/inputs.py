"""Run-directory detection and the approved-address book shared by every kind."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from sippycup_workbench.summary_privacy import AddressBook

from .core import Redaction
from .files import read_dict, read_json, read_text, read_yaml_dict, regular

CALL_RESULT = "sippycup.dev/call-result/v1"
MATRIX = "sippycup.dev/call-matrix/v1"
CHECKS_RESULT = "sippycup.dev/checks-result/v1"
FINDINGS = "sippycup.dev/findings/v1"
CAMPAIGN_PLAN = "sippycup.dev/plan/v1"


class InputError(ValueError):
    """The path cannot be used (exit 2)."""


class NotARun(LookupError):
    """The directory is not a run Sippycup knows how to diagnose (exit 4)."""


def detect_kind(path: Path) -> str:
    """One of call, matrix, campaign, checks. Raises NotARun with a hint."""
    if not path.exists():
        raise InputError(f"no such file or directory: {path}")
    if not path.is_dir():
        raise InputError("expected a run directory (a call, matrix, campaign, or checks run)")
    if regular(path / "matrix.json"):
        return "matrix"
    result = read_dict(path / "result.json")
    api = str(result.get("apiVersion", ""))
    if api == CALL_RESULT:
        return "call"
    if api == CHECKS_RESULT or (regular(path / "findings.json") and regular(path / "checks-detail.json")):
        return "checks"
    plan = read_dict(path / "plan.json")
    if regular(path / "events.jsonl") or str(plan.get("apiVersion", "")) == CAMPAIGN_PLAN:
        return "campaign"
    if str(plan.get("schema_version", "")) == "sippycup.dev/call-plan/v1" or regular(path / "softphone.json"):
        return "call"
    children = sorted(
        item.name for item in path.iterdir()
        if item.is_dir() and not item.is_symlink() and (regular(item / "result.json") or regular(item / "matrix.json"))
    )
    if children:
        newest = ", ".join(children[-3:])
        raise NotARun(
            f"{path} holds several runs and is not itself a run; name one, for example the newest: {newest}"
        )
    raise NotARun(
        f"{path} is not a call, matrix, campaign, or checks run directory "
        "(no result.json, matrix.json, events.jsonl, or findings.json found)"
    )


@dataclass
class Approved:
    networks: list = field(default_factory=list)
    assessor: set = field(default_factory=set)


def _add_networks(out: list, values) -> None:
    if not isinstance(values, (list, tuple)):
        return
    for item in values:
        try:
            ipaddress.ip_network(str(item).strip(), strict=False)
        except ValueError:
            continue
        text = str(item).strip()
        if text not in out:
            out.append(text)


def gather_approved(directories: Iterable[Path]) -> Approved:
    """Approved networks and the assessor address from the files runs record."""
    out = Approved()
    for directory in directories:
        plan = read_dict(directory / "plan.json")
        authorization = plan.get("authorization")
        if isinstance(authorization, dict):
            _add_networks(out.networks, authorization.get("networks"))
            _add_networks(out.networks, authorization.get("media_networks"))
        profile = read_dict(directory / "profile.json")
        target = profile.get("target")
        if isinstance(target, dict):
            _add_networks(out.networks, target.get("approved_addresses"))
            _add_networks(out.networks, [target.get("host")] if target.get("host") else [])
        media = profile.get("media")
        if isinstance(media, dict):
            _add_networks(out.networks, media.get("networks"))
        result = read_dict(directory / "result.json")
        scope = result.get("mediaScope")
        if isinstance(scope, dict) and isinstance(scope.get("rules"), dict):
            _add_networks(out.networks, scope["rules"].get("approvedAddresses"))
            _add_networks(out.networks, scope["rules"].get("mediaNetworks"))
        target = result.get("target")
        if isinstance(target, dict) and target.get("host"):
            _add_networks(out.networks, [target["host"]])
        local = result.get("localAddress") or plan.get("local_address")
        if isinstance(local, str):
            try:
                out.assessor.add(str(ipaddress.ip_address(local)))
            except ValueError:
                pass
    return out


def make_redaction(directories: Iterable[Path], approve: Iterable[str], show: bool) -> Redaction:
    directories = list(directories)
    approved = gather_approved(directories)
    book = AddressBook()
    for network in approve:
        if not book.add_network(network):
            raise InputError(f"--approve {network!r} is not an address or CIDR")
    for network in approved.networks:
        book.add_network(network)
    book.assessor.update(address for address in approved.assessor if not book.approved(address))
    redaction = Redaction(book, show)
    redaction.note_run_names(*(directory.resolve().name for directory in directories))
    return redaction


def date_dirs(path: Path, limit: int = 400) -> list:
    """Child directories (no links), oldest name first."""
    try:
        entries = sorted(item for item in path.iterdir() if item.is_dir() and not item.is_symlink())
    except OSError:
        return []
    return entries[:limit]


def sibling_profiles(run_dir: Path, name: Optional[str] = None) -> list:
    """Target profiles near a run (same engagement), as plain dicts."""
    seen: dict = {}
    roots = []
    current = run_dir.resolve().parent
    for _ in range(6):
        roots.append(current)
        if current.name == "work" or current.parent == current:
            break
        current = current.parent
    for root in roots:
        try:
            files = sorted(root.glob("*.yaml"))[:60]
        except OSError:
            continue
        for path in files:
            if path in seen or not regular(path):
                continue
            try:
                if path.stat().st_size > 64 * 1024:
                    continue
            except OSError:
                continue
            document = read_yaml_dict(path)
            if str(document.get("schema_version", "")) != "sippycup.dev/target-profile/v1":
                continue
            target = document.get("target") if isinstance(document.get("target"), dict) else {}
            authorization = document.get("authorization") if isinstance(document.get("authorization"), dict) else {}
            seen[path] = {
                "path": path,
                "name": str(document.get("name", "")),
                "host": str(target.get("host", "")),
                "port": target.get("port"),
                "transport": str(target.get("transport", "udp")),
                "tlsServerName": target.get("tls_server_name"),
                "tlsCaFile": target.get("tls_ca_file"),
                "approved": str(authorization.get("status", "")) == "approved",
                "validUntil": str(authorization.get("valid_until", "")),
                "calls": ((document.get("limits") or {}).get("max_calls") if isinstance(document.get("limits"), dict) else None),
                "srtp": bool((document.get("features") or {}).get("srtp")) if isinstance(document.get("features"), dict) else False,
            }
    now = datetime.now(timezone.utc)
    out = []
    for item in seen.values():
        try:
            until = datetime.fromisoformat(item["validUntil"].replace("Z", "+00:00"))
            if until.tzinfo is None:
                until = until.replace(tzinfo=timezone.utc)
            item["expired"] = until < now
        except ValueError:
            item["expired"] = False
        out.append(item)
    return out


__all__ = [
    "InputError", "NotARun", "detect_kind", "gather_approved", "make_redaction",
    "sibling_profiles", "read_json", "read_text", "date_dirs", "Approved",
]
