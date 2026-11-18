"""Recognize runs placed against the local practice target, for ``summary``.

``./bin/sippycup practice-target up`` issues a new LOCAL-PRACTICE-ONLY approval
window on every start and overwrites ``work/practice/target-profile.yaml``.
It also keeps an immutable dated copy of every approval it issued in
``work/practice/approvals/``. A guided call or a checks run writes the profile
it actually used to its run directory as ``profile.json``.

A run counts as a practice run only when that recorded profile is equal,
field for field, to one archived practice approval. The archive, not the run's
own copy, is the authority: an archived record must be a target profile with
approval id LOCAL-PRACTICE-ONLY whose target and every approved address are
IPv4 loopback addresses other than 127.0.0.1 (the only addresses `up` can
issue). Such a run can only have reached the loopback-only practice
namespace. The report then checks it against the approval window and address
that authorized it, instead of against the engagement's own records, and
labels it as practice. Everything else is checked exactly as before.
"""

from __future__ import annotations

import ipaddress
import itertools
import json
from pathlib import Path
from typing import Any, Callable

APPROVAL_ID = "LOCAL-PRACTICE-ONLY"
ARCHIVE = Path("practice") / "approvals"
MAX_ARCHIVED = 2000
PROFILE_SCHEMA = "sippycup.dev/target-profile/v1"


def work_root(engagement: Path) -> Path | None:
    """The ``work`` directory that holds ``engagement`` (``/work`` in the image)."""
    for candidate in (engagement, *engagement.parents):
        if candidate.name == "work":
            return candidate
    return None


def _practice_address(value: Any) -> bool:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return address.version == 4 and address.is_loopback and str(address) != "127.0.0.1"


def is_practice_approval(document: Any) -> bool:
    """True for a profile that only `practice-target up` could have issued."""
    if not isinstance(document, dict) or document.get("schema_version") != PROFILE_SCHEMA:
        return False
    authorization = document.get("authorization")
    target = document.get("target")
    if not isinstance(authorization, dict) or not isinstance(target, dict):
        return False
    if authorization.get("approval_id") != APPROVAL_ID:
        return False
    approved = target.get("approved_addresses")
    if not isinstance(approved, list) or not approved:
        return False
    return _practice_address(target.get("host")) and all(_practice_address(item) for item in approved)


def canonical(document: Any) -> str:
    """Canonical JSON of a profile, as a run's profile.json records it."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), default=str)


def load_archive(engagement: Path, read_yaml: Callable[[Path], Any]) -> dict[str, tuple[str, dict[str, Any]]]:
    """Map canonical profile JSON to (reference, document) for every archived practice approval."""
    work = work_root(engagement)
    if work is None:
        return {}
    directory = work / ARCHIVE
    if directory.is_symlink() or not directory.is_dir():
        return {}
    archive: dict[str, tuple[str, dict[str, Any]]] = {}
    try:
        paths = sorted(itertools.islice(directory.iterdir(), MAX_ARCHIVED))
    except OSError:
        return {}
    for path in paths:
        if path.suffix != ".yaml" or path.is_symlink() or not path.is_file():
            continue
        try:
            document = read_yaml(path)
        except Exception:  # noqa: BLE001 - an unreadable record is simply not an authority
            continue
        if is_practice_approval(document):
            archive.setdefault(canonical(document), (f"practice-approval/{path.name}", document))
    return archive


def match(recorded: Any, archive: dict[str, tuple[str, dict[str, Any]]]) -> tuple[str, dict[str, Any]] | None:
    """The archived approval a run's recorded profile equals, or None."""
    if not is_practice_approval(recorded):
        return None
    return archive.get(canonical(recorded))
