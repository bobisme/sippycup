"""Resolve a run directory or capture file into the inputs the ladder reads."""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

CAPTURE_SUFFIXES = {".pcap", ".pcapng"}
MAX_JSON_BYTES = 8 * 1024 * 1024


class InputError(ValueError):
    """The path cannot be used (exit 2)."""


@dataclass
class Inputs:
    capture: Optional[Path] = None
    log: Optional[Path] = None
    run_dir: Optional[Path] = None
    approved: list = field(default_factory=list)
    assessor: set = field(default_factory=set)
    run_date: Optional[dt.date] = None


def _read_json(path: Path) -> dict:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _networks(values) -> list:
    out = []
    if not isinstance(values, (list, tuple)):
        return out
    for item in values:
        try:
            ipaddress.ip_network(str(item).strip(), strict=False)
        except ValueError:
            continue
        out.append(str(item).strip())
    return out


def _shallow_find(root: Path, names: tuple, suffixes: set) -> list:
    """Files directly in root, else one level down (campaign artifacts/)."""
    for depth_dirs in ([root], sorted(p for p in root.iterdir() if p.is_dir() and not p.is_symlink())):
        found = []
        for directory in depth_dirs if isinstance(depth_dirs, list) else [depth_dirs]:
            try:
                entries = sorted(directory.iterdir())
            except OSError:
                continue
            for entry in entries:
                if entry.is_symlink() or not entry.is_file():
                    continue
                if entry.name in names or (suffixes and entry.suffix in suffixes):
                    found.append(entry)
        if found:
            return found
    return []


def resolve(path_text: str) -> Inputs:
    path = Path(path_text)
    if not path.exists():
        raise InputError(f"no such file or directory: {path}")
    inputs = Inputs()
    if path.is_file():
        if path.suffix.lower() in CAPTURE_SUFFIXES:
            inputs.capture = path
            return inputs
        if path.suffix.lower() == ".log":
            inputs.log = path
            return inputs
        raise InputError("expected a run directory, a .pcap/.pcapng capture, or a softphone .log file")
    if not path.is_dir():
        raise InputError(f"not a regular file or directory: {path}")
    inputs.run_dir = path
    captures = _shallow_find(path, ("capture.pcap", "capture.pcapng"), set())
    if not captures:
        captures = _shallow_find(path, (), CAPTURE_SUFFIXES)
    if len(captures) > 1:
        preferred = [c for c in captures if c.name in ("capture.pcap", "capture.pcapng")]
        if len(preferred) == 1:
            captures = preferred
        else:
            names = ", ".join(c.name for c in captures[:6])
            raise InputError(f"{path} holds several captures ({names}); pass one capture file directly")
    inputs.capture = captures[0] if captures else None
    logs = _shallow_find(path, ("softphone.log",), set())
    inputs.log = logs[0] if logs else None
    if inputs.capture is None and inputs.log is None:
        raise InputError(f"{path} has no capture (.pcap/.pcapng) and no softphone.log")
    approved: list = []
    for source in (inputs.capture or inputs.log).parent, path:
        plan = _read_json(source / "plan.json")
        authorization = plan.get("authorization")
        if isinstance(authorization, dict):
            approved += _networks(authorization.get("networks"))
            approved += _networks(authorization.get("media_networks"))
        profile = _read_json(source / "profile.json")
        target = profile.get("target")
        if isinstance(target, dict):
            approved += _networks(target.get("approved_addresses"))
        # Owner-approved media networks: shown, not redacted (the ladder
        # draws addresses; it never decides where signaling may go).
        media = profile.get("media")
        if isinstance(media, dict):
            approved += _networks(media.get("networks"))
        result = _read_json(source / "result.json")
        local = result.get("localAddress") or plan.get("local_address")
        if isinstance(local, str):
            try:
                inputs.assessor.add(str(ipaddress.ip_address(local)))
            except ValueError:
                pass
        stamps = _read_json(source / "timestamps.json")
        for key in ("call_started", "started"):
            value = stamps.get(key)
            if isinstance(value, str) and inputs.run_date is None:
                try:
                    inputs.run_date = dt.datetime.fromisoformat(value.replace("Z", "+00:00")).date()
                except ValueError:
                    pass
    seen = set()
    inputs.approved = [n for n in approved if not (n in seen or seen.add(n))]
    return inputs
