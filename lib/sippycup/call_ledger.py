"""The engagement's call ledger: the owner's call limit holds across commands (bn-2sfn).

Every command that places calls under an approval (``call``, ``matrix run``,
``checks run`` for its INVITE attempts, ``campaign run`` and the MCP live
one-call tool) reserves its calls here *before its first packet*, under an
exclusive lock, and refuses when the calls already counted under that approval
id in this engagement directory plus the calls it is about to place would
exceed the approved ceiling.

What consumes a call (one rule for every command): the owner's limit is on
calls, so a reserved call is released again, with the reason in the ledger,
when no INVITE for it can have left the tool: the command stopped before its
first packet, the OPTIONS preflight failed, registration failed, a campaign
step never started, or a security check sent no request at all. From the first
INVITE on, the call counts, whatever happened to it. Where a command cannot
tell (a campaign step run by SIPp, a security check that sent some requests,
an internal error), the call counts.

The ledger is ``call-ledger.jsonl`` in the engagement directory (the directory
that holds the target profile or the campaign manifest), one JSON object per
line, append only, mode 0600:

- ``reserve``: ``id``, ``approval``, ``calls``, ``ceiling``, ``command``,
  ``source`` (file name of the profile or manifest), ``at``;
- ``release``: ``id`` of a reservation, ``calls`` given back, ``reason``;
- ``new-approval-window``: written only by ``practice-target up`` in
  ``work/practice`` for the practice approval, which issues a new approval
  window (and a bench budget of ``calls``) on every start.

Each run directory records the reservation that counted it, as soon as the
directory exists (``call-ledger.json``) and again in ``result.json``
(``callLedger``): the ledger path relative to the run and the reservation id.

The cross-check (every reservation and every read-only count, whether or not
the ledger file exists): the ledger must account for every run directory of
the engagement that placed, or may have placed, calls under the approval. The
runs read are the direct children of ``ENG/calls``, ``matrix``, ``runs`` and
``checks`` (at most 5000). A run is under the approval when its profile.json,
plan.json or result.json names it, and also when none of them can be read
(fail closed); a campaign whose readable plan names no approval is unbound and
not counted here. A run may have placed calls unless its own record shows it
could not: a campaign plan that budgets no call, a checks plan with no INVITE
attempt, or a checks run that sent no request. A run is accounted for when

1. it names a reservation of this approval that is in this ledger (a matrix or
   campaign reservation covers every run that names it), or
2. it names a reservation in another engagement's ledger that exists and holds
   it (a run placed with ``--run-root`` here from another engagement), or
3. on the practice bench only, it started before the latest
   ``new-approval-window`` (the bench's runs from earlier windows, including
   runs from before the ledger existed).

Any other run is unaccounted for and the command refuses, naming the runs:
an empty, truncated, replaced or missing ledger cannot start a new count while
the run directories show calls. A run from before the ledger existed names no
reservation, so outside the practice bench it is unaccounted for too; the
recovery is the same (restore the ledger, or a new approval id from the owner).
Runs placed with ``--run-root`` outside these four directories are not read:
the ledger counted them when they were placed, and the cross-check only
catches a ledger that holds fewer calls than the disk shows.

Fail closed: an unreadable or malformed ledger refuses too. Nothing here sends
anything.

One count per approval reference, never silently (wave 11, findings 2 and 4):
a new written approval from the owner legitimately brings a new reference and
a new limit, so calls stay counted under the reference they were placed under,
whatever the scope names later. What is shown beside the count
(:func:`status` with ``context=True``: ``rehearse``, ``ready``, dry runs and
plans) is every other reference this directory's ledger holds calls under
(:func:`reference_counts`), and every sibling directory beside this one whose
ledger counts calls under the same reference (:func:`same_approval_elsewhere`).
Ledger files are never merged.

One rule for an owner's reference that a sibling directory counts calls under
too (wave 12, finding 1; :func:`elsewhere_rule`): the directory whose ledger
has the earlier first call is where the work goes on, and its reservations
add the calls of the others (those its own ledger does not also hold, so a
ledger copied with its directory counts once); every other directory's
reservation is refused before anything is sent. ``ready``, ``rehearse``, the
dry runs and the plans read the same rule and print the same text. The
benches' own references (:data:`BENCH_APPROVAL_IDS`) are exempt.

Limits that remain (see docs/SAFETY-AUDIT.md, findings 4 and 6): the ledger
counts per engagement directory, so an engagement directory or a profile
copied under another parent, or another checkout, keeps its own count (a
sibling directory under the same parent is seen and refused, see above;
another parent or checkout is not seen); and it stops honest mistakes, not an operator who
deliberately rewrites the ledger, the run directories, or the profiles.
"""

from __future__ import annotations

import fcntl
import json
import os
import stat
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
# Run roots the cross-check reads (every reservation and every count).
RUN_ROOTS = ("calls", "matrix", "runs", "checks")
MAX_RUNS_SCANNED = 5000
# Written into each run directory as soon as it exists: the reservation that
# counted the run, so a run that never finished is still accounted for.
RUN_RECORD_FILE = "call-ledger.json"
# How many unaccounted runs a refusal names.
SHOWN_RUNS = 5
# Approval references the tool's own benches write (the practice target, the
# dress rehearsal, the routed rehearsal). Each bench reuses its reference in
# many directories by design and can reach only its own local target, so a
# sibling directory under the same reference is named but is not a NO-GO.
# tests/test_wave11_guard.py holds these equal to the benches' constants.
BENCH_APPROVAL_IDS = frozenset({PRACTICE_APPROVAL_ID, "LOCAL-PRACTICE-REHEARSAL", "ROUTED-REHEARSAL"})
# Sibling directories read by same_approval_elsewhere, and how many a line names.
MAX_SIBLINGS_SCANNED = 2000
SHOWN_DIRECTORIES = 3


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
    resolved = Path(directory).resolve()
    return resolved.name == "practice" and resolved.parent.name == "work"


def is_practice_bench(directory: str | Path) -> bool:
    """True for ``work/practice``, the practice bench (not an engagement)."""
    return _is_practice_bench(Path(directory))


@dataclass
class Usage:
    """What the ledger says about one approval id."""

    used: int
    # A budget stated by the issuer of the approval window (the practice
    # bench only); None means the profile's or manifest's own ceiling holds.
    budget: int | None = None
    # Every reservation id of this approval in the ledger (all windows).
    reservations: frozenset[str] = frozenset()
    # When the latest new approval window started (practice bench only).
    window_at: str | None = None


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
    every: set[str] = set()
    used = 0
    budget: int | None = None
    window_at: str | None = None
    for entry in entries:
        if entry.get("approval") != approval_id:
            continue
        event = entry.get("event")
        calls = entry.get("calls")
        if isinstance(calls, bool) or not isinstance(calls, int) or calls < 0:
            raise LedgerError(f"{path} line {entry['_line']} has no valid call count")
        if event == "reserve":
            identifier = entry.get("id")
            if not isinstance(identifier, str) or identifier in every:
                raise LedgerError(f"{path} line {entry['_line']} has a missing or repeated reservation id")
            reserved[identifier] = calls
            every.add(identifier)
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
            window_at = entry.get("at") if isinstance(entry.get("at"), str) else None
        else:
            raise LedgerError(f"{path} line {entry['_line']} has an unknown event {event!r}")
    return Usage(used, budget, frozenset(every), window_at)


_UNBOUND = None  # a readable record that names no approval (an unbound campaign)


def _load(run: Path, name: str) -> Any:
    """A run file's JSON; None when absent; ``_UNREADABLE`` when it cannot be read."""
    path = run / name
    if path.is_symlink() or not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _UNREADABLE


class _Unreadable:
    pass


_UNREADABLE = _Unreadable()


def _run_approval(run: Path) -> str | None:
    """The approval id a run directory recorded.

    "" when it cannot be read (fail closed: it may be under any approval);
    None when a readable campaign plan names no approval (an unbound plan,
    which the ledger never counts).
    """
    for name, keys in (
        ("profile.json", ("authorization", "approval_id")),
        ("plan.json", ("authorization", "approval", "id")),
        ("result.json", ("approvalWindow", "approvalId")),
    ):
        value: Any = _load(run, name)
        if value is None:
            continue
        if value is _UNREADABLE:
            return ""
        if (
            name == "plan.json"
            and not (run / "profile.json").exists()
            and isinstance(value, dict)
            and isinstance(value.get("authorization"), dict)
            and value["authorization"].get("approval") is None
            and isinstance(value.get("steps"), list)
        ):
            return _UNBOUND
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


def write_run_record(reservation: "Reservation | None", run_dir: str | Path) -> None:
    """Record the reservation in a run directory as soon as it exists (``call-ledger.json``).

    A run that is killed before it writes ``result.json`` is then still
    accounted for by the cross-check. Nothing is written without a reservation.
    """
    record = run_record(reservation, run_dir)
    if record is None:
        return
    path = Path(run_dir) / RUN_RECORD_FILE
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump({"v": VERSION, **record}, output, sort_keys=True)
        output.write("\n")


def _run_reference(run: Path) -> dict[str, Any] | None:
    """The reservation a run names (``call-ledger.json``, else ``result.json``), or None."""
    early = _load(run, RUN_RECORD_FILE)
    if isinstance(early, dict) and isinstance(early.get("ledger"), str):
        return early
    result = _load(run, "result.json")
    record = result.get("callLedger") if isinstance(result, dict) else None
    if isinstance(record, dict) and isinstance(record.get("ledger"), str):
        return record
    return None


def _placed_no_calls(run: Path) -> bool:
    """True only when the run's own record shows it could not have placed a call:
    a campaign whose plan budgets no call, a checks run whose plan has no INVITE
    attempt, or a checks run that sent no request at all. Anything unreadable
    may have placed calls (False).

    A checks run's request log does not show every INVITE by name (on TCP and
    TLS the first request of a connection is logged as the connection), so a
    log without "INVITE" in it is not proof of no call.
    """
    if (run / "profile.json").exists():
        plan = _load(run, "plan.json")
        if isinstance(plan, dict) and "inviteAttempts" in plan:
            attempts = plan.get("inviteAttempts")
            if type(attempts) is int and attempts == 0:
                return True
        result = _load(run, "result.json")
        if not isinstance(result, dict) or result.get("verdict") is not None:
            return False  # a guided call, or a checks run without a readable result
        log = result.get("requestLog")
        return isinstance(log, list) and not log and result.get("requestsSent") == 0
    plan = _load(run, "plan.json")
    steps = plan.get("steps") if isinstance(plan, dict) else None
    if not isinstance(steps, list) or not steps:
        return False
    try:
        return all(int((step.get("budget") or {}).get("calls")) == 0 for step in steps)
    except (TypeError, ValueError, AttributeError):
        return False


def _reference_ledger(run: Path, record: dict[str, Any]) -> Path | None:
    try:
        ledger = (run / record["ledger"]).resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    return ledger if ledger.name == LEDGER_FILE else None


def _counted_elsewhere(run: Path, directory: Path) -> bool:
    """True when the run names a reservation in another engagement's ledger
    that exists and holds it (a run placed with ``--run-root`` in this directory)."""
    record = _run_reference(run)
    if record is None:
        return False
    ledger = _reference_ledger(run, record)
    if ledger is None or ledger.parent == Path(directory).resolve():
        return False
    try:
        entries = read_entries(ledger.parent)
    except LedgerError:
        return False
    return any(
        entry.get("event") == "reserve" and entry.get("id") == record.get("reservation")
        for entry in entries or ()
    )


def _run_started(name: str) -> datetime | None:
    """The start time in a run directory's name (``YYYYmmddTHHMMSS[.ffffff]Z-...``)."""
    stamp = name.split("-", 1)[0]
    for pattern in ("%Y%m%dT%H%M%S.%fZ", "%Y%m%dT%H%M%SZ"):
        try:
            return datetime.strptime(stamp, pattern).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _parse_at(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def _candidate_runs(directory: Path, approval_id: str) -> list[tuple[str, Path]]:
    """Run directories in the default run roots that placed, or may have placed,
    calls under ``approval_id`` (see the module docstring)."""
    found: list[tuple[str, Path]] = []
    seen = 0
    for name in RUN_ROOTS:
        root = directory / name
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
            if recorded is _UNBOUND or recorded not in ("", approval_id):
                continue
            if recorded == "" and not any(
                (child / item).exists() for item in ("result.json", "capture.pcap", RUN_RECORD_FILE)
            ):
                continue
            if _placed_no_calls(child):
                continue
            found.append((f"{name}/{child.name}", child))
    return found


@dataclass
class Unaccounted:
    """A run the ledger does not account for, and why."""

    run: str
    why: str


def unaccounted_runs(directory: str | Path, approval_id: str, found: Usage) -> list[Unaccounted]:
    """The runs on disk that the ledger's reservations do not account for."""
    directory = Path(directory)
    here = (directory / LEDGER_FILE).resolve()
    bench = approval_id == PRACTICE_APPROVAL_ID and _is_practice_bench(directory)
    window = _parse_at(found.window_at) if bench else None
    missing: list[Unaccounted] = []
    for label, run in _candidate_runs(directory, approval_id):
        record = _run_reference(run)
        if record is not None:
            ledger = _reference_ledger(run, record)
            if ledger == here:
                if record.get("reservation") in found.reservations:
                    continue
                if window is not None and (_run_started(run.name) or window) < window:
                    continue
                missing.append(Unaccounted(label, "its reservation is not in the ledger"))
                continue
            if _counted_elsewhere(run, directory):
                continue
        if window is not None:
            started = _run_started(run.name)
            if started is not None and started < window:
                continue
        missing.append(Unaccounted(
            label,
            "it names no reservation in this ledger" if record is None
            else "it names a reservation in a ledger that does not hold it",
        ))
    return missing


def earlier_runs(directory: str | Path, approval_id: str) -> list[str]:
    """Run directories that a missing ledger would leave uncounted (kept for callers)."""
    return [item.run for item in unaccounted_runs(directory, approval_id, Usage(0))]


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
        f"restore {engagement}/{LEDGER_FILE} from your backup of the engagement directory. If it "
        f"cannot be restored, tell the owner how many calls the run directories show and ask for a "
        f"new written approval with a new approval id (changing the id without one only hides the "
        f"calls already placed); record it in "
        f"{engagement}/scope.yaml, and run ./bin/sippycup scope compile {engagement}. An empty, "
        "shortened or new ledger is refused the same way: every command reads these run "
        "directories again before it sends anything"
    )
    if approval_id == PRACTICE_APPROVAL_ID and _is_practice_bench(directory):
        text += (
            "; on the practice target, ./bin/sippycup practice-target down, then up, issues a "
            "new practice approval"
        )
    return text


def _runs_text(missing: list[Unaccounted]) -> str:
    shown = ", ".join(f"{item.run} ({item.why})" for item in missing[:SHOWN_RUNS])
    more = len(missing) - SHOWN_RUNS
    return shown + (f", and {more} more" if more > 0 else "")


def check(directory: str | Path, approval_id: str) -> Usage:
    """Read-only: the usage under ``approval_id``, or LedgerError.

    The same count every reservation makes (it calls this under the lock), so
    plans, dry runs, ``rehearse``, ``ready`` and the cockpit show the number
    the refusal uses. The run-directory cross-check runs whether or not the
    ledger file exists.
    """
    directory = Path(directory)
    entries = read_entries(directory)
    found = Usage(0) if entries is None else usage(entries, approval_id, directory)
    missing = unaccounted_runs(directory, approval_id, found)
    if not missing:
        return found
    ledger = operator_path(directory / LEDGER_FILE)
    if entries is None:
        opening = f"the call ledger {ledger} is missing, so it does not account for"
        cause = "The ledger was deleted or moved"
    else:
        opening = (
            f"the call ledger {ledger} counts {found.used} call(s) under approval {approval_id}, "
            "but it does not account for"
        )
        cause = "The ledger was emptied, shortened or replaced since those runs"
    raise LedgerError(
        f"{opening} {len(missing)} run(s) in {operator_path(directory)} that placed or may have "
        f"placed calls under approval {approval_id}: {_runs_text(missing)}. {cause}, so the calls "
        f"already placed cannot be counted; nothing was sent. To recover, "
        + _recover_text(directory, approval_id)
    )


def effective_ceiling(found: Usage, ceiling: int) -> int:
    return found.budget if found.budget is not None else ceiling


def refusal_text(
    directory: Path, approval_id: str, ceiling: int, used: int, calls: int, command: str,
    elsewhere: int = 0,
) -> str:
    engagement = operator_path(directory)
    remaining = max(0, ceiling - used - elsewhere)
    beside = (
        f", {elsewhere} more counted under the same approval in another directory beside it"
        if elsewhere else ""
    )
    narrow = (
        f" Narrow it to {remaining} call(s) or fewer, or ask the owner for more."
        if calls > 1 and remaining > 0
        else ""
    )
    return (
        f"call limit: approval {approval_id} allows {ceiling} call(s) in this engagement "
        f"(limits.calls in {engagement}/scope.yaml); {used} already counted in "
        f"{engagement}/{LEDGER_FILE} (calls placed, and calls reserved by a command that may still "
        f"be running){beside}, {remaining} remain, and this {command} would place {calls}; nothing was "
        f"sent.{narrow} Only the owner can raise the limit: ask them, record the new number with "
        f"./bin/sippycup scope answer {engagement} limits.calls (that sets the approval back to pending), "
        f"record the approval again with ./bin/sippycup scope answer {engagement} 2, and then run "
        f"./bin/sippycup scope compile {engagement}"
    )


@dataclass
class ReferenceCount:
    """What one engagement directory's ledger holds under one approval reference."""

    approval_id: str
    # Calls counted (reserved minus released); None when they cannot be counted.
    used: int | None
    # The limit in force at this reference's latest reservation (None: no reservation).
    ceiling: int | None = None
    first_at: str | None = None
    last_at: str | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"approvalId": self.approval_id, "used": self.used, "ceiling": self.ceiling,
                "firstAt": self.first_at, "lastAt": self.last_at, "error": self.error}


def reference_counts(directory: str | Path) -> list[ReferenceCount]:
    """Every approval reference the ledger in ``directory`` has entries for, in order of first use.

    Read-only and never raises: no ledger, or one that cannot be read at all,
    gives ``[]`` (:func:`status` reports that error for the reference in
    force). A reference whose own entries are inconsistent has ``used`` None
    and ``error`` set. Calls stay under the reference they were reserved
    under, whatever the scope names now. The run directories are not read
    here; :func:`check` cross-checks them for one reference.
    """
    directory = Path(directory)
    try:
        entries = read_entries(directory)
    except (LedgerError, OSError):
        return []
    found: dict[str, ReferenceCount] = {}
    for entry in entries or ():
        approval = entry.get("approval")
        if not isinstance(approval, str) or not approval:
            continue
        item = found.setdefault(approval, ReferenceCount(approval, 0))
        at = entry.get("at") if isinstance(entry.get("at"), str) else None
        item.first_at = item.first_at or at
        item.last_at = at or item.last_at
        if entry.get("event") == "reserve" and type(entry.get("ceiling")) is int:
            item.ceiling = entry["ceiling"]
    for approval, item in found.items():
        try:
            item.used = usage(entries or (), approval, directory).used
        except LedgerError as error:
            item.used, item.error = None, str(error)
    return list(found.values())


def reservation_counts(directory: str | Path) -> dict[str, dict[str, Any]]:
    """Every reservation in the ledger of ``directory``: id -> approval, command, time, and
    the calls it still counts (reserved minus released).

    Read-only and never raises: no ledger, or one that cannot be read, gives
    ``{}``. For the owner report, which attributes every counted call to a run
    through the reservation the run names (wave 13, finding 1).
    """
    try:
        entries = read_entries(Path(directory))
    except (LedgerError, OSError):
        return {}
    found: dict[str, dict[str, Any]] = {}
    for entry in entries or ():
        identifier, calls = entry.get("id"), entry.get("calls")
        if not isinstance(identifier, str) or type(calls) is not int or calls < 0:
            continue
        if entry.get("event") == "reserve" and identifier not in found:
            found[identifier] = {
                "approval": entry.get("approval"), "calls": calls,
                "command": entry.get("command") if isinstance(entry.get("command"), str) else None,
                "at": entry.get("at") if isinstance(entry.get("at"), str) else None,
            }
        elif entry.get("event") == "release" and identifier in found:
            found[identifier]["calls"] = max(0, found[identifier]["calls"] - calls)
    return found


def run_reservation(run_dir: str | Path) -> tuple[Path | None, str | None]:
    """(the ledger file a run directory names, resolved; its reservation id), or (None, None).

    Read-only and never raises.
    """
    try:
        record = _run_reference(Path(run_dir))
        if record is None:
            return None, None
        identifier = record.get("reservation")
        return _reference_ledger(Path(run_dir), record), identifier if isinstance(identifier, str) else None
    except (OSError, RuntimeError, ValueError):
        return None, None


@dataclass
class ElsewhereCount:
    """A sibling directory whose ledger counts calls under the same approval reference."""

    directory: str
    used: int | None
    error: str | None = None
    # When that ledger's first reservation under the reference was made.
    first_at: str | None = None
    # The calls there that this directory's own ledger does not also hold (a
    # ledger copied with its directory repeats the same reservations).
    extra: int | None = None
    # The ledger there exists, or may exist, and this user cannot open it
    # (wave 13, finding 3): whether it counts calls under the reference cannot
    # be shown, so it stops this directory like a damaged ledger that names it.
    unreadable: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {"directory": self.directory, "used": self.used, "error": self.error,
                "firstAt": self.first_at, "extra": self.extra}

    @property
    def same(self) -> int:
        """The calls there that are the same calls as this directory counts (copied reservations)."""
        if self.used is None or self.extra is None:
            return 0
        return max(0, self.used - self.extra)

    def counts_text(self, name: str | None = None) -> str:
        """``DIR counts N call(s)``, saying which of them this directory counts too
        (wave 13, findings 2 and 16), so that nobody adds the same calls twice."""
        name = name or self.directory
        if self.unreadable:
            return (f"{name} has a call ledger that this user cannot read, so whether it counts calls under "
                    "the approval is not known")
        if self.used is None:
            return f"{name} has a call ledger that names it and cannot be read"
        text = f"{name} counts {self.used} call(s)"
        if not self.same:
            return text
        if self.same == self.used:
            return (f"{text}, all of them the same calls as {self.same} counted here (its ledger repeats "
                    "reservations of this one, as after a copy of the directory), counted once")
        return (f"{text}, {self.same} of them the same calls as {self.same} counted here (its ledger repeats "
                f"reservations of this one, as after a copy of the directory) and {self.extra} others")


def _first_reserve(entries: Iterable[dict[str, Any]], approval_id: str) -> tuple[str | None, set[str]]:
    """When the first reservation under ``approval_id`` was made, and every reservation id."""
    first: str | None = None
    identifiers: set[str] = set()
    for entry in entries:
        if entry.get("approval") != approval_id or entry.get("event") != "reserve":
            continue
        if first is None and isinstance(entry.get("at"), str):
            first = entry["at"]
        if isinstance(entry.get("id"), str):
            identifiers.add(entry["id"])
    return first, identifiers


def own_first_reserve(directory: str | Path, approval_id: str) -> tuple[str | None, set[str]]:
    """:func:`_first_reserve` for this directory's ledger; never raises."""
    try:
        return _first_reserve(read_entries(Path(directory)) or (), approval_id)
    except (LedgerError, OSError):
        return None, set()


def same_approval_elsewhere(directory: str | Path, approval_id: str) -> list[ElsewhereCount]:
    """Sibling directories (same parent) whose call ledger counts calls under ``approval_id``.

    Wave 11, finding 4: an engagement's scope files copied into a new
    directory start a ledger of their own, so the owner's one limit would be
    spent twice. Read-only, never raises, merges nothing. The practice bench
    (``work/practice``) is neither asked about nor read: every practice
    profile is generated from it and shares its approval by design. A sibling
    ledger that is damaged counts as a hit only when its bytes name the
    reference. A sibling ledger that exists and that this user cannot open is
    a hit with ``unreadable`` set (wave 13, finding 3): it used to be skipped
    without a word, so the commands that run on the host showed GO in a
    directory the sending commands refuse, and a ledger the container cannot
    read either would have let the refused directory send. The same holds for
    a sibling directory that cannot be searched for a ledger, and for a parent
    directory that cannot be listed.
    """
    if not isinstance(approval_id, str) or not approval_id:
        return []
    try:
        here = Path(directory).resolve()
        if _is_practice_bench(here):
            return []
        try:
            children = sorted(here.parent.iterdir())[:MAX_SIBLINGS_SCANNED]
        except PermissionError as error:
            return [ElsewhereCount(
                operator_path(here.parent), None,
                f"cannot list {operator_path(here.parent)}: {error.strerror or error}", unreadable=True)]
    except (OSError, RuntimeError):
        return []
    found: list[ElsewhereCount] = []
    _own_first, own_ids = own_first_reserve(here, approval_id)
    for child in children:
        ledger = child / LEDGER_FILE
        try:
            if child.is_symlink() or not child.is_dir() or child == here or _is_practice_bench(child):
                continue
        except OSError:
            continue
        shown = operator_path(child)
        try:
            # lstat, not is_file(): is_file() answers False when the directory
            # cannot be searched, which would hide a ledger that is there.
            mode = os.lstat(ledger).st_mode
        except PermissionError as error:
            found.append(ElsewhereCount(
                shown, None, f"cannot look for {operator_path(ledger)}: {error.strerror or error}",
                unreadable=True))
            continue
        except OSError:
            continue
        if not stat.S_ISREG(mode):
            continue
        try:
            entries = read_entries(child) or []
            used = usage(entries, approval_id, child).used
            first_at, _ids = _first_reserve(entries, approval_id)
            # Reservations this directory's ledger also holds were copied
            # with the directory: the same calls, counted once.
            extra = usage([entry for entry in entries if entry.get("id") not in own_ids],
                          approval_id, child).used if own_ids else used
        except (LedgerError, OSError) as error:
            try:
                named = approval_id.encode() in ledger.read_bytes()[:MAX_LEDGER_BYTES]
            except OSError:
                # It exists and cannot be opened: it may count calls under the
                # reference, and nothing here can show that it does not.
                found.append(ElsewhereCount(shown, None, str(error), unreadable=True))
                continue
            if named:
                found.append(ElsewhereCount(shown, None, str(error)))
            continue
        if used > 0:
            found.append(ElsewhereCount(shown, used, first_at=first_at, extra=max(0, min(extra, used))))
    return found


@dataclass
class ElsewhereRule:
    """One owner's approval counted in more than one directory: the one rule (wave 12, finding 1).

    The directory whose ledger has the earlier first call under the reference
    (the first by name when the times are equal) is where the work goes on;
    its count adds the calls of the others. Every other directory sends
    nothing more under the reference. Each side computes the same ``keeper``
    and prints the same :attr:`text`. A sibling ledger that names the
    reference and cannot be read stops every directory that sees it.
    """

    approval_id: str
    engagement: str
    keeper: str | None
    blocks: bool
    # Calls counted in the other directories that this one adds (the keeper only).
    extra: int
    text: str
    # The part of the text that is the same from every directory involved.
    advice: str = ""

    def refusal(self, command: str) -> str:
        return (f"call limit: this {command} is refused in {self.engagement}. Nothing was sent. "
                f"{self.text[0].upper()}{self.text[1:]}")


def elsewhere_rule(
    directory: str | Path, approval_id: str, used: int | None,
    elsewhere: Iterable[ElsewhereCount] | None = None,
) -> ElsewhereRule | None:
    """The rule for ``directory``; None when no sibling directory counts calls
    under ``approval_id``, or the reference is one of the tool's own benches
    (exempt: every bench directory shares its reference by design).

    Read-only; never raises.
    """
    if not isinstance(approval_id, str) or not approval_id or approval_id in BENCH_APPROVAL_IDS:
        return None
    others = list(same_approval_elsewhere(directory, approval_id) if elsewhere is None else elsewhere)
    if not others:
        return None
    try:
        engagement = operator_path(Path(directory).resolve())
    except (OSError, RuntimeError):
        engagement = operator_path(directory)
    unreadable = [item for item in others if item.used is None]
    closed = [item for item in unreadable if item.unreadable]
    if closed:
        # Wave 13, finding 3: a ledger this user cannot open. The fix line
        # names the file and both ways back.
        names = ", ".join(item.directory for item in closed[:SHOWN_DIRECTORIES])
        first = closed[0].directory
        chmod = (f"chmod u+r {first}/{LEDGER_FILE}" if (closed[0].error or "").startswith("cannot read")
                 else f"chmod u+rx {first}")
        return ElsewhereRule(approval_id, engagement, None, True, 0, (
            f"a call ledger beside {engagement} cannot be read by this user, in {names} "
            f"({closed[0].error}). The owner's limit is one limit for the approval, whatever the directory, "
            f"and it cannot be shown that no call is counted there under {approval_id}. Restore read "
            f"permission ({chmod}), or restore that directory "
            f"from your backup; a directory that is not an engagement does not belong beside {engagement}. "
            f"Until then {engagement} sends nothing under {approval_id}"
        ))
    if unreadable:
        names = ", ".join(item.directory for item in unreadable[:SHOWN_DIRECTORIES])
        return ElsewhereRule(approval_id, engagement, None, True, 0, (
            f"approval {approval_id} is named by a call ledger that cannot be read in {names}, beside "
            f"{engagement}. The owner's limit is one limit for the approval, and the calls there cannot be "
            f"counted. Restore that ledger from your backup; until then no directory beside it sends "
            f"anything under {approval_id}"
        ))
    own_first, _ids = own_first_reserve(directory, approval_id)
    holders = [(item.first_at or "9999", item.directory, item.used) for item in others]
    if used:
        holders.append((own_first or "9999", engagement, used))
    holders.sort()
    keeper = holders[0][1]
    tie = len(holders) > 1 and holders[0][0] == holders[1][0]
    stopped = [name for _at, name, _used in holders[1:]]
    if not used and engagement not in stopped:
        stopped.append(engagement)
    listed = ", ".join(
        f"{name} ({count} call(s), first at {at if at != '9999' else 'an unrecorded time'})"
        for at, name, count in holders[:SHOWN_DIRECTORIES + 1]
    )
    more = len(holders) - (SHOWN_DIRECTORIES + 1)
    listed += f", and {more} more" if more > 0 else ""
    if len(holders) == 1:
        why = "the directory that holds its calls"
    elif tie:
        why = ("the first by name, as the first calls have the same time; its count adds the calls of the "
               "other directory that its own ledger does not hold")
    else:
        why = "its ledger has the earlier first call, and its count adds the calls of the other directory"
    one = len(stopped) == 1
    stop_names = ", ".join(stopped[:SHOWN_DIRECTORIES]) + (" and others" if len(stopped) > SHOWN_DIRECTORIES else "")
    # The fix commands name the directory the operator is in when it is one
    # of the stopped ones (wave 13, finding 4: in a third directory they named
    # the second, and typed literally changed the wrong engagement's reference).
    first_stopped = engagement if engagement in stopped or not stopped else stopped[0]
    each = f" (for {first_stopped}; the same in each of the others)" if len(stopped) > 1 else ""
    listing = f"approval {approval_id} has calls counted in {listed}"
    advice = (
        f"The owner's limit is one limit for the approval, whatever the directory. Go on in {keeper} ({why}): "
        f"./bin/sippycup ready {keeper}. "
        f"{stop_names} send{'s' if one else ''} nothing more under {approval_id}: "
        f"use {'it' if one else 'them'} again only under a new written approval from the owner, "
        f"recorded{each} with ./bin/sippycup scope answer {first_stopped} authorization.approval_id and "
        f"./bin/sippycup scope compile {first_stopped}"
    )
    text = f"{listing}. {advice}"
    if keeper != engagement:
        return ElsewhereRule(approval_id, engagement, keeper, True, 0, text, advice)
    return ElsewhereRule(approval_id, engagement, keeper, False, sum(item.extra or 0 for item in others),
                         text, advice)


def stopped_elsewhere(directory: str | Path, approval_id: str, command: str) -> str | None:
    """Read-only: the refusal for a command that reserves no call, in a directory the rule stops.

    The rule says a stopped directory "sends nothing more under" the approval,
    so a ``checks run`` that places no call (and therefore reserves nothing)
    is refused there too (wave 13). None when the rule does not stop this
    directory. The own count is read the way :func:`status` reads it: a
    ledger that cannot be counted is no count. Never raises.
    """
    directory = Path(directory)
    try:
        used: int | None = check(directory, approval_id).used
    except (LedgerError, OSError):
        used = None
    rule = elsewhere_rule(directory, approval_id, used)
    return rule.refusal(command) if rule is not None and rule.blocks else None


@dataclass
class CallsStatus:
    """The ``Calls: N of M used, K left`` line, read-only, from :func:`check`."""

    approval_id: str
    ledger: str
    limit: int | None = None
    used: int | None = None
    error: str | None = None
    # Filled by status(context=True) only (wave 11, findings 2 and 4): the
    # other references this directory holds calls under, and the sibling
    # directories that count calls under this reference.
    other_references: tuple[ReferenceCount, ...] = ()
    elsewhere: tuple[ElsewhereCount, ...] = ()
    # The one rule for an owner's approval counted in a sibling directory too
    # (wave 12, finding 1); None for the benches' references and when no
    # sibling counts calls. Filled by status(context=True).
    rule: "ElsewhereRule | None" = None

    @property
    def elsewhere_blocks(self) -> bool:
        """True when this directory may send nothing more under the approval: a sibling
        directory spends the same (non-bench) approval's limit and is where the count
        goes on, or a sibling ledger cannot be read (:class:`ElsewhereRule`)."""
        if self.rule is not None:
            return self.rule.blocks
        # No rule was computed (a status built by hand): the strict reading.
        return bool(self.elsewhere) and self.approval_id not in BENCH_APPROVAL_IDS

    @property
    def elsewhere_used(self) -> int:
        """Calls of sibling directories that count against the limit here (only in the
        directory where the count goes on)."""
        return self.rule.extra if self.rule is not None and not self.rule.blocks else 0

    def notes(self) -> list[str]:
        """Sentences that must stand beside the count; empty when there is nothing to add."""
        notes: list[str] = []
        engagement = self.ledger.rsplit("/", 1)[0] if "/" in self.ledger else "this directory"
        others = [item for item in self.other_references if item.used or item.error]
        if others:
            parts = [
                f"{item.used} call(s) were placed here under reference {item.approval_id}" if item.used is not None
                else f"calls under reference {item.approval_id} cannot be counted"
                for item in others
            ]
            total = sum(item.used or 0 for item in others) + (self.used or 0)
            notes.append(
                f"Also in {engagement}: {'; '.join(parts)} ({total} in all, with the {self.used or 0} under "
                f"{self.approval_id}). Each reference keeps its own count; a new reference brings a new limit "
                "only when the owner gave a new written approval, not when a reference was corrected or retyped"
            )
        if self.elsewhere:
            shown = ", ".join(
                item.counts_text() if item.used is not None or item.unreadable
                else f"{item.directory} has a ledger that names it and cannot be read"
                for item in self.elsewhere[:SHOWN_DIRECTORIES]
            )
            more = len(self.elsewhere) - SHOWN_DIRECTORIES
            shown += f", and {more} more director{'y' if more == 1 else 'ies'}" if more > 0 else ""
            if self.approval_id in BENCH_APPROVAL_IDS:
                tail = ("That is expected for this practice reference, which every practice directory shares; "
                        "an owner's approval reference used in two directories is refused by ready, by "
                        "rehearse and by every command that places a call")
            elif self.rule is not None:
                # The same sentences from every directory involved (finding 4).
                tail = self.rule.advice or (self.rule.text[0].upper() + self.rule.text[1:])
            else:
                tail = ("The owner's limit is one limit for the approval: the calls there are NOT in the count "
                        f"above. Keep working in that directory, or use {engagement} only with a new written "
                        "approval (a new reference) from the owner")
            notes.append(f"Same approval reference {self.approval_id} in another directory: {shown}. {tail}")
        return notes

    @property
    def left(self) -> int | None:
        if self.limit is None or self.used is None:
            return None
        return max(0, self.limit - self.used - self.elsewhere_used)

    @property
    def trusted(self) -> bool:
        return self.error is None and self.left is not None

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"approvalId": self.approval_id, "ledger": self.ledger, "limit": self.limit,
                                 "used": self.used, "left": self.left, "error": self.error}
        if self.other_references:
            value["otherReferences"] = [item.as_dict() for item in self.other_references]
        if self.elsewhere:
            value["sameApprovalElsewhere"] = [item.as_dict() for item in self.elsewhere]
            if self.rule is not None:
                value["sameApprovalRule"] = {"goOnIn": self.rule.keeper, "refusedHere": self.rule.blocks,
                                             "countedElsewhere": self.rule.extra}
        return value

    def line(self, placing: int | None = None, command: str = "command", notes: bool = True) -> str:
        """One line for the operator; ``placing`` adds what a command would place.

        The notes (other references here, the same reference elsewhere) are
        part of the line, so no caller can show the count without them;
        ``notes=False`` is for a caller that prints :meth:`notes` itself.
        """
        if self.error is not None:
            text = (f"Calls: cannot be counted, so no call can be placed under approval "
                    f"{self.approval_id}: {self.error}")
        elif self.left is None:
            text = f"Calls: no call limit is recorded for approval {self.approval_id}"
        else:
            beside = self.elsewhere_used
            used = (f"{self.used + beside} of {self.limit} used ({self.used} here and {beside} in another "
                    "directory under the same approval)" if beside else f"{self.used} of {self.limit} used")
            text = (f"Calls: {used}, {self.left} left "
                    f"(approval {self.approval_id}, counted in {self.ledger})")
            if placing is not None:
                text += f"; this {command} would place {placing}"
                if self.elsewhere_blocks:
                    text += (", but it would be refused: this directory sends nothing more under "
                             "this approval")
                elif placing > self.left:
                    text += (f", more than the {self.left} left, so it would be refused"
                             if self.left else ", but none are left, so it would be refused")
        extra = self.notes() if notes else []
        return ". ".join([text, *extra]) + ("." if extra else "")


def status(directory: str | Path, approval_id: str, ceiling: int | None, *, context: bool = False) -> CallsStatus:
    """Calls used and left under ``approval_id`` in ``directory``; never raises, sends nothing.

    ``context=True`` also fills what must be said beside the count: the other
    references this directory holds calls under and the sibling directories
    that count calls under this one. The owner report builds its own lines
    per reference from :func:`reference_counts` and leaves it off.
    """
    directory = Path(directory)
    shown = operator_path(directory / LEDGER_FILE)
    others: tuple[ReferenceCount, ...] = ()
    elsewhere: tuple[ElsewhereCount, ...] = ()
    if context:
        others = tuple(item for item in reference_counts(directory)
                       if item.approval_id != approval_id and (item.used or item.error))
        elsewhere = tuple(same_approval_elsewhere(directory, approval_id))
    try:
        found = check(directory, approval_id)
    except LedgerError as error:
        return CallsStatus(approval_id, shown, error=str(error), other_references=others, elsewhere=elsewhere,
                           rule=elsewhere_rule(directory, approval_id, None, elsewhere) if context else None)
    except OSError as error:
        return CallsStatus(approval_id, shown, error=f"cannot read {shown}: {error.strerror or error}",
                           other_references=others, elsewhere=elsewhere,
                           rule=elsewhere_rule(directory, approval_id, None, elsewhere) if context else None)
    limit = found.budget if found.budget is not None else ceiling
    return CallsStatus(approval_id, shown, limit=limit if isinstance(limit, int) else None, used=found.used,
                       other_references=others, elsewhere=elsewhere,
                       rule=elsewhere_rule(directory, approval_id, found.used, elsewhere) if context else None)


def reserve(
    directory: str | Path,
    *,
    approval_id: str,
    ceiling: int,
    calls: int,
    command: str,
    source: str,
    concurrent_limit: int | None = None,
) -> Reservation:
    """Reserve ``calls`` under ``approval_id`` or raise CeilingRefused / LedgerError.

    The check and the reservation happen under one exclusive lock, so two
    commands started at once cannot both pass.

    ``concurrent_limit`` is the owner's limit on calls at once that the
    caller's profile or plan carries. A command that the launcher let start
    beside another run (SIPPYCUP_ALLOW_OVERLAP) is refused here, before
    anything is reserved or sent, when the two would exceed it (wave 13;
    ``overlap_record.concurrency_refusal``). Every caller that sends passes it.
    """
    if concurrent_limit is not None:
        from sippycup.overlap_record import concurrency_refusal

        beside = concurrency_refusal(concurrent_limit, command)
        if beside is not None:
            raise CeilingRefused(beside)
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise LedgerError(f"the engagement directory {operator_path(directory)} is missing or a symlink")
    if not isinstance(approval_id, str) or not approval_id:
        raise LedgerError("a call needs an approval id to be counted against")
    with _locked(directory):
        found = check(directory, approval_id)
        limit = effective_ceiling(found, ceiling)
        # One owner's approval counted in a sibling directory too (wave 12,
        # finding 1): only one of the directories goes on, and it adds the
        # calls of the others. The benches' own references are exempt.
        rule = elsewhere_rule(directory, approval_id, found.used)
        if rule is not None and rule.blocks:
            raise CeilingRefused(rule.refusal(command))
        beside = rule.extra if rule is not None else 0
        if found.used + beside + calls > limit:
            raise CeilingRefused(
                refusal_text(directory, approval_id, limit, found.used, calls, command, elsewhere=beside)
            )
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
