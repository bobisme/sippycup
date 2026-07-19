"""Shared strict-validation helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

MAX_DOCUMENT_BYTES = 4 * 1024 * 1024


class ResilienceError(ValueError):
    """An unsafe, ambiguous, or malformed resilience input."""


def require_mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ResilienceError(f"{name} must be an object")
    if not all(isinstance(key, str) for key in value):
        raise ResilienceError(f"{name} keys must be strings")
    return value


def exact_keys(
    value: dict[str, Any],
    required: Iterable[str],
    optional: Iterable[str] = (),
    *,
    name: str,
) -> None:
    required_set, optional_set = set(required), set(optional)
    missing = sorted(required_set - value.keys())
    unknown = sorted(value.keys() - required_set - optional_set)
    if missing:
        raise ResilienceError(f"{name} is missing {', '.join(missing)}")
    if unknown:
        raise ResilienceError(f"{name} has unsupported fields: {', '.join(unknown)}")


def bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ResilienceError(f"{name} must be an integer in {minimum}..{maximum}")
    return value


def finite_number(value: Any, name: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ResilienceError(f"{name} must be a finite number")
    result = float(value)
    if result != result or result in (float("inf"), float("-inf")):
        raise ResilienceError(f"{name} must be a finite number")
    if not minimum <= result <= maximum:
        raise ResilienceError(f"{name} must be in {minimum}..{maximum}")
    return result


def nonempty_string(value: Any, name: str, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ResilienceError(f"{name} must be a non-empty string of at most {maximum} characters")
    return value


def boolean(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise ResilienceError(f"{name} must be a boolean")
    return value


def load_json(path: Path) -> Any:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ResilienceError(f"cannot inspect {path}: {error}") from error
    if size > MAX_DOCUMENT_BYTES:
        raise ResilienceError(f"{path} exceeds {MAX_DOCUMENT_BYTES} bytes")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ResilienceError(f"cannot read JSON from {path}: {error}") from error


def digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def verdict(findings: list[dict[str, Any]]) -> str:
    return "fail" if any(item["severity"] == "fail" for item in findings) else "pass"
