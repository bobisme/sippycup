"""Bounded, symlink-refusing readers for the files a run directory holds."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_LINES = 20000


def regular(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink()
    except OSError:
        return False


def read_json(path: Path) -> Optional[Any]:
    """Parsed JSON, or None when missing, oversized, a link, or malformed."""
    try:
        if not regular(path) or path.stat().st_size > MAX_JSON_BYTES:
            return None
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def read_dict(path: Path) -> dict:
    value = read_json(path)
    return value if isinstance(value, dict) else {}


def read_text(path: Path) -> Optional[str]:
    try:
        if not regular(path) or path.stat().st_size > MAX_TEXT_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def read_jsonl(path: Path) -> list:
    """Parsed lines of a JSON-lines file; malformed lines are skipped."""
    text = read_text(path)
    out: list = []
    if text is None:
        return out
    for number, line in enumerate(text.split("\n")):
        if number >= MAX_LINES:
            break
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            out.append(value)
    return out


def read_yaml_dict(path: Path) -> dict:
    text = read_text(path)
    if text is None:
        return {}
    try:
        import yaml

        value = yaml.safe_load(text)
    except Exception:  # a profile we cannot parse is simply not used
        return {}
    return value if isinstance(value, dict) else {}


def unwrap(value: Any) -> Any:
    """Strip the oracle's {"state": "known", "value": X} wrappers."""
    if isinstance(value, dict):
        if set(value) >= {"state", "value"} and len(value) == 2:
            return unwrap(value["value"]) if value.get("state") == "known" else None
        return {key: unwrap(item) for key, item in value.items()}
    if isinstance(value, list):
        return [unwrap(item) for item in value]
    return value
