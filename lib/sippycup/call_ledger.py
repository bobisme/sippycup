"""The engagement's call ledger: the owner's call limit holds across commands (bn-2sfn).

Every command that places calls under an approval (``call``, ``matrix run``,
``checks run`` for its INVITE attempts, ``campaign run`` and the MCP live
one-call tool) reserves its calls here *before its first packet*, under an
exclusive lock, and refuses when the calls already placed under that approval
id in this engagement directory plus the calls it is about to place would
exceed the approved ceiling. Calls that were reserved but never attempted (the
command stopped before sending anything) are released again; a call that was
attempted counts, whatever happened to it.

The ledger is ``call-ledger.jsonl`` in the engagement directory (the directory
that holds the target profile or the campaign manifest), one JSON object per
line, append only, mode 0600:

- ``reserve``: ``id``, ``approval``, ``calls``, ``ceiling``, ``command``,
  ``source`` (file name of the profile or manifest), ``at``;
- ``release``: ``id`` of a reservation, ``calls`` given back, ``reason``;
- ``new-approval-window``: written only by ``practice-target up`` in
  ``work/practice`` for the practice approval, which issues a new approval
  window (and a bench budget of ``calls``) on every start.

Fail closed: an unreadable or malformed ledger refuses, and so does a missing
ledger while run directories of the engagement show calls under the same
approval id. Nothing here sends anything.

Limits that remain (see docs/SAFETY-AUDIT.md, finding 6): the ledger counts per
engagement directory, so a copied engagement directory, a profile copied into
another directory, or another checkout keeps its own count; and it is an aid
against honest mistakes, not a seal against someone who edits it.
"""

from __future__ import annotations

import fcntl
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

LEDGER_FILE = "call-ledger.jsonl"
LOCK_FILE = ".call-ledger.lock"
VERSION = "sippycup.dev/call-ledger/v1"
MAX_LEDGER_BYTES = 16 * 1024 * 1024
PRACTICE_APPROVAL_ID = "LOCAL-PRACTICE-ONLY"
# Run roots the cross-check reads when the ledger is missing.
RUN_ROOTS = ("calls", "matrix", "runs", "checks")
MAX_RUNS_SCANNED = 5000


class LedgerError(ValueError):
    """The ledger cannot be trusted; nothing may be sent until it is fixed."""


class CeilingRefused(ValueError):
    """The calls about to be placed would exceed the approved ceiling."""


def operator_path(path: str | Path) -> str:
    """``work/...`` as the operator types it, also inside the image (``/work/...``)."""
    text = str(path)
    if text.startswith("/work/") or text == "/work":
        return "work" + text[len("/work"):]
    parts = Path(text).parts
    if "work" in parts:
        index = len(parts) - 1 - parts[::-1].index("work")
        return str(Path(*parts[index:]))
    return text


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _is_practice_bench(directory: Path) -> bool:
    resolved = directory.resolve()
    return resolved.name == "practice" and resolved.parent.name == "work"


@dataclass
class Usage:
    """What the ledger says about one approval id."""

    used: int
    # A budget stated by the issuer of the approval window (the practice
    # bench only); None means the profile's or manifest's own ceiling holds.
    budget: int | None = None


def _check_ledger_file(path: Path) -> None:
    status = path.lstat()
    if path.is_symlink() or not path.is_file():
        raise LedgerError(f"{operator_path(path)} is not a regular file")
    if status.st_size > MAX_LEDGER_BYTES:
        raise LedgerError(f"{operator_path(path)} is larger than {MAX_LEDGER_BYTES} bytes")


def read_entries(directory: str | Path) -> list[dict[str, Any]] | None:
    """Every ledger entry, or None when the ledger does not exist. Raises LedgerError."""
    path = Path(directory) / LEDGER_FILE
    if not path.exists() and not path.is_symlink():
        return None
    try:
        _check_ledger_file(path)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            data = handle.read(MAX_LEDGER_BYTES + 1)
    except OSError as exc:
        raise LedgerError(f"cannot read {operator_path(path)}: {exc.strerror or exc}") from exc
    if data and not data.endswith(b"\n"):
        raise LedgerError(f"{operator_path(path)} ends in an incomplete line (a write was interrupted)")
    entries = []
    for number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
        try:
            entry = json.loads(line)
        except ValueError as exc:
            raise LedgerError(f"{operator_path(path)} line {number} is not valid JSON") from exc
        if not isinstance(entry, dict) or entry.get("v") != VERSION:
            raise LedgerError(f"{operator_path(path)} line {number} is not a {VERSION} entry")
        entry["_line"] = number
        entries.append(entry)
    return entries


def usage(entries: Iterable[dict[str, Any]], approval_id: str, directory: Path) -> Usage:
    """Calls placed or reserved under ``approval_id``, checked entry by entry."""
    path = operator_path(Path(directory) / LEDGER_FILE)
    reserved: dict[str, int] = {}
    used = 0
    budget: int | None = None
    for entry in entries:
        if entry.get("approval") != approval_id:
            continue
        event = entry.get("event")
        calls = entry.get("calls")
        if isinstance(calls, bool) or not isinstance(calls, int) or calls < 0:
            raise LedgerError(f"{path} line {entry['_line']} has no valid call count")
        if event == "reserve":
            identifier = entry.get("id")
            if not isinstance(identifier, str) or identifier in reserved:
                raise LedgerError(f"{path} line {entry['_line']} has a missing or repeated reservation id")
            reserved[identifier] = calls
            used += calls
        elif event == "release":
            identifier = entry.get("id")
            if identifier not in reserved or calls > reserved[identifier]:
                raise LedgerError(
                    f"{path} line {entry['_line']} releases calls that were not reserved"
                )
            reserved[identifier] -= calls
            used -= calls
        elif event == "new-approval-window":
            # Only `practice-target up` issues a new approval window, and only
            # for the practice approval in work/practice.
            if approval_id != PRACTICE_APPROVAL_ID or not _is_practice_bench(Path(directory)):
                raise LedgerError(
                    f"{path} line {entry['_line']} starts a new approval window, which only "
                    "practice-target up may record, for its own practice approval"
                )
            reserved.clear()
            used = 0
            budget = calls
        else:
            raise LedgerError(f"{path} line {entry['_line']} has an unknown event {event!r}")
    return Usage(used, budget)


def _run_approval(run: Path) -> str | None:
    """The approval id a run directory recorded, or "" when it cannot be read."""
    for name, keys in (
        ("profile.json", ("authorization", "approval_id")),
        ("plan.json", ("authorization", "approval", "id")),
        ("result.json", ("approvalWindow", "approvalId")),
    ):
        path = run / name
        if path.is_symlink() or not path.is_file():
            continue
        try:
            value: Any = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return ""
        for key in keys:
            value = value.get(key) if isinstance(value, dict) else None
        if isinstance(value, str):
            return value
    return ""


def run_record(reservation: "Reservation | None", run_dir: str | Path) -> dict[str, str] | None:
    """What a run records about the ledger reservation that counted it.

    The ledger path is relative to the run directory, so it resolves the same
    on the host and inside the image (``work/`` is ``/work``).
    """
    if reservation is None:
        return None
    return {
        "ledger": os.path.relpath(Path(reservation.directory) / LEDGER_FILE, Path(run_dir)),
        "reservation": reservation.identifier,
    }


def _placed_no_calls(run: Path) -> bool:
    """True only when the run's own record shows it could not have placed a call:
    a campaign whose plan budgets no call, or a checks run whose request log
    has no INVITE. Anything unreadable may have placed calls (False)."""
    def load(name: str) -> Any:
        path = run / name
        if path.is_symlink() or not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    if (run / "profile.json").exists():
        result = load("result.json")
        log = result.get("requestLog") if isinstance(result, dict) else None
        if not isinstance(log, list) or (result or {}).get("verdict") is not None:
            return False  # a guided call, or a checks run without a readable log
        return not any(
            isinstance(entry, dict) and str(entry.get("request", "")).upper().startswith("INVITE")
            for entry in log
        )
    plan = load("plan.json")
    steps = plan.get("steps") if isinstance(plan, dict) else None
    if not isinstance(steps, list) or not steps:
        return False
    try:
        return all(int((step.get("budget") or {}).get("calls")) == 0 for step in steps)
    except (TypeError, ValueError, AttributeError):
        return False


def _counted_elsewhere(run: Path, directory: Path) -> bool:
    """True when the run's result names a reservation in another engagement's ledger
    that exists and holds it (a run placed with ``--run-root`` in this directory)."""
    path = run / "result.json"
    if path.is_symlink() or not path.is_file():
        return False
    try:
        record = json.loads(path.read_text(encoding="utf-8")).get("callLedger")
    except (OSError, ValueError, AttributeError):
        return False
    if not isinstance(record, dict) or not isinstance(record.get("ledger"), str):
        return False
    ledger = (run / record["ledger"]).resolve()
    if ledger.name != LEDGER_FILE or ledger.parent == Path(directory).resolve():
        return False
    try:
        entries = read_entries(ledger.parent)
    except LedgerError:
        return False
    return any(
        entry.get("event") == "reserve" and entry.get("id") == record.get("reservation")
        for entry in entries or ()
    )


def earlier_runs(directory: str | Path, approval_id: str) -> list[str]:
    """Run directories in the engagement's default run roots recorded under ``approval_id``.

    A run whose approval cannot be read counts (fail closed). A run that
    another engagement's existing ledger counted (``--run-root`` here) does not.
    """
    found: list[str] = []
    seen = 0
    for name in RUN_ROOTS:
        root = Path(directory) / name
        if root.is_symlink() or not root.is_dir():
            continue
        try:
            children = sorted(root.iterdir())
        except OSError:
            continue
        for child in children:
            seen += 1
            if seen > MAX_RUNS_SCANNED:
                return found
            if child.is_symlink() or not child.is_dir():
                continue
            recorded = _run_approval(child)
            if _counted_elsewhere(child, Path(directory)) or _placed_no_calls(child):
                continue
            if recorded in ("", approval_id) and (
                recorded == approval_id or any((child / item).exists() for item in ("result.json", "capture.pcap"))
            ):
                found.append(f"{name}/{child.name}")
    return found


@dataclass
class Reservation:
    directory: Path
    approval_id: str
    identifier: str
    calls: int
    released: int = 0

    def release(self, calls: int, reason: str) -> None:
        """Give back ``calls`` that were reserved but never attempted."""
        calls = max(0, min(int(calls), self.calls - self.released))
        if not calls:
            return
        with _locked(self.directory):
            _append(self.directory, {
                "event": "release", "id": self.identifier, "approval": self.approval_id,
                "calls": calls, "reason": reason[:300], "at": _now(),
            })
        self.released += calls


class _locked:
    def __init__(self, directory: Path) -> None:
        self.path = Path(directory) / LOCK_FILE

    def __enter__(self) -> None:
        try:
            self.descriptor = os.open(
                self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
            )
        except OSError as exc:
            raise LedgerError(
                f"cannot lock {operator_path(self.path)}: {exc.strerror or exc}"
            ) from exc
        fcntl.flock(self.descriptor, fcntl.LOCK_EX)

    def __exit__(self, *_exc: object) -> None:
        fcntl.flock(self.descriptor, fcntl.LOCK_UN)
        os.close(self.descriptor)


def _append(directory: Path, entry: dict[str, Any]) -> None:
    path = Path(directory) / LEDGER_FILE
    line = (json.dumps({"v": VERSION, **entry}, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if path.exists() or path.is_symlink():
        _check_ledger_file(path)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        os.write(descriptor, line)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _recover_text(directory: Path, approval_id: str) -> str:
    engagement = operator_path(directory)
    text = (
        f"restore {engagement}/{LEDGER_FILE} from your backup of the engagement directory, or ask "
        f"the owner for a new written approval with a new approval id, record it in "
        f"{engagement}/scope.yaml, and run ./bin/sippycup scope compile {engagement}. Do not "
        "create an empty ledger: the owner's limit counts every call already placed"
    )
    if approval_id == PRACTICE_APPROVAL_ID and _is_practice_bench(directory):
        text += (
            "; on the practice target, ./bin/sippycup practice-target down, then up, issues a "
            "new practice approval"
        )
    return text


def check(directory: str | Path, approval_id: str) -> Usage:
    """Read-only: the usage under ``approval_id``, or LedgerError (for plans and dry runs)."""
    directory = Path(directory)
    entries = read_entries(directory)
    if entries is None:
        runs = earlier_runs(directory, approval_id)
        if runs:
            raise LedgerError(
                f"the call ledger {operator_path(directory / LEDGER_FILE)} is missing, but "
                f"{len(runs)} earlier run(s) under approval {approval_id} are in "
                f"{operator_path(directory)} (for example {runs[0]}), so the calls already "
                f"placed cannot be counted; nothing was sent. To recover, "
                + _recover_text(directory, approval_id)
            )
        return Usage(0)
    return usage(entries, approval_id, directory)


def effective_ceiling(found: Usage, ceiling: int) -> int:
    return found.budget if found.budget is not None else ceiling


def refusal_text(
    directory: Path, approval_id: str, ceiling: int, used: int, calls: int, command: str
) -> str:
    engagement = operator_path(directory)
    remaining = max(0, ceiling - used)
    return (
        f"call limit: approval {approval_id} allows {ceiling} call(s) in this engagement "
        f"(limits.calls in {engagement}/scope.yaml); {used} already placed (recorded in "
        f"{engagement}/{LEDGER_FILE}), {remaining} remain, and this {command} would place "
        f"{calls}; nothing was sent. Only the owner can raise the limit: ask them, record the new "
        f"limits.calls in {engagement}/scope.yaml, and run ./bin/sippycup scope compile {engagement}"
    )


def reserve(
    directory: str | Path,
    *,
    approval_id: str,
    ceiling: int,
    calls: int,
    command: str,
    source: str,
) -> Reservation:
    """Reserve ``calls`` under ``approval_id`` or raise CeilingRefused / LedgerError.

    The check and the reservation happen under one exclusive lock, so two
    commands started at once cannot both pass.
    """
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise LedgerError(f"the engagement directory {operator_path(directory)} is missing or a symlink")
    if not isinstance(approval_id, str) or not approval_id:
        raise LedgerError("a call needs an approval id to be counted against")
    with _locked(directory):
        found = check(directory, approval_id)
        limit = effective_ceiling(found, ceiling)
        if found.used + calls > limit:
            raise CeilingRefused(refusal_text(directory, approval_id, limit, found.used, calls, command))
        identifier = uuid.uuid4().hex
        _append(directory, {
            "event": "reserve", "id": identifier, "approval": approval_id, "calls": calls,
            "ceiling": limit, "usedBefore": found.used, "command": command, "source": source,
            "at": _now(),
        })
    return Reservation(directory, approval_id, identifier, calls)


def new_approval_window(directory: str | Path, *, approval_id: str, budget: int, by: str) -> None:
    """Record that ``by`` issued a new approval window (practice bench only)."""
    directory = Path(directory)
    if approval_id != PRACTICE_APPROVAL_ID or not _is_practice_bench(directory):
        raise LedgerError("only the practice target may start a new approval window in its ledger")
    with _locked(directory):
        _append(directory, {
            "event": "new-approval-window", "approval": approval_id, "calls": int(budget),
            "by": by, "at": _now(),
        })
