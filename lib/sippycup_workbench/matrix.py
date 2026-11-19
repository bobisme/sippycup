"""Plan or run a transport x codec x SRTP grid of guided calls.

``sippycup matrix plan PROFILE... --dial D --codecs ...`` prints the cells
and the call count and sends nothing. ``sippycup matrix run`` places the
cells strictly one after another, each through :func:`call.execute`, the
guided call's own code path: its profile gate and authorization re-checks,
scoped capture, one OPTIONS preflight, one PJSUA call, media-scope stop, and
offline evidence. Every call writes its normal run directory; the matrix adds
one ``matrix.json`` (``schemas/call-matrix-v1.schema.json``).

Each profile approves exactly one transport (its ``target``), so a grid over
several transports takes one approved profile per transport (for example the
practice target's UDP and TLS profiles). A profile's ``media.codecs`` limits
the codecs, its ``features.srtp`` permits SRTP, and its ``limits`` bound the
number and rate of calls placed through it.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import signal
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, MutableMapping, Sequence

from sippycup.integration import create_run_directory
from sippycup_softphone.driver import (
    SDES_CLEARTEXT_WARNING,
    SRTP_MODES,
    SUPPORTED_CODECS,
    TRANSPORTS,
    SoftphoneError,
    canonical_codec,
)

from . import call as guided
from .profile import ProfileError, approved_codecs, load_profile

MATRIX_VERSION = "sippycup.dev/call-matrix/v1"
DEFAULT_MAX_CALLS = 6
HARD_MAX_CALLS = 48
DEFAULT_DURATION_SECONDS = 5
# Pause between the end of one call and the start of the next, on top of the
# profile's call-rate limit.
GAP_SECONDS = 1.0
EXIT_PASS = 0
EXIT_NOT_PASS = 1
EXIT_REFUSED = 2
EXIT_STOPPED = 3
# Verdicts after which the matrix places no further call: continuing would
# repeat a rejected credential, ignore a rate limit or overload, or send
# without authorization or evidence.
STOP_VERDICTS = {
    "registration-failed": "registration was refused; another call would repeat the credentials",
    "call-auth-failed": "the far end refused the credentials; another call would repeat them",
    "call-rate-limited": "the far end answered 429 Too Many Requests",
    "authorization-lapsed": "the profile's authorization lapsed",
    "blocked": "the profile gate refused the call",
    "capture-failed": "packet capture did not start",
    "capture-died": "packet capture stopped",
    "media-outside-scope": "the far end negotiated media outside the approved addresses and media networks",
    "signaling-outside-scope": "the far end routed in-dialog SIP to an address that is not the approved target",
    "internal-error": "an internal error stopped a call",
    "cancelled": "the operator cancelled the run",
}


class MatrixError(ValueError):
    """The matrix cannot be planned; nothing was sent."""


@dataclasses.dataclass
class MatrixOptions:
    profiles: tuple[Path, ...]
    destination: str
    codecs: tuple[str, ...] = ()
    transports: tuple[str, ...] = ()
    srtp: tuple[str, ...] = ("off",)
    max_calls: int = DEFAULT_MAX_CALLS
    duration: int = DEFAULT_DURATION_SECONDS
    answer_timeout: int = guided.DEFAULT_ANSWER_TIMEOUT_SECONDS
    username: str | None = None
    realm: str = "*"
    register: bool = True
    secret_env: str | None = None
    secret_file: Path | None = None
    run_root: Path | None = None
    matrix_root: Path | None = None
    engagement: Path | None = None
    media_required: bool = True
    output_format: str = "human"


def _split(values: Sequence[str] | None) -> tuple[str, ...]:
    return tuple(item.strip() for value in values or () for item in value.split(",") if item.strip())


def _unique(values: Sequence[str], label: str) -> tuple[str, ...]:
    if len(set(values)) != len(values):
        raise MatrixError(f"--{label} names a value twice")
    return tuple(values)


def _cell_options(options: MatrixOptions, profile: Path, codec: str, srtp: str) -> guided.CallOptions:
    return guided.CallOptions(
        profile=profile,
        destination=options.destination,
        duration=options.duration,
        codecs=(codec,),
        exclusive_codecs=True,
        username=options.username,
        realm=options.realm,
        register=options.register,
        secret_env=options.secret_env,
        secret_file=options.secret_file,
        run_root=options.run_root,
        engagement=options.engagement,
        media_required=options.media_required,
        answer_timeout=options.answer_timeout,
        srtp=srtp,
    )


def build_plan(
    options: MatrixOptions, *, now: datetime, work_root: Path | None = None
) -> dict[str, Any]:
    """Every cell, the call count, and every reason the matrix may not run.

    Raises :class:`MatrixError` for a request that is malformed or outside
    what the profiles approve; returns ``blockingErrors`` for a profile that
    is not ready right now (the same gate as ``call``).
    """
    if not options.profiles:
        raise MatrixError("name at least one target profile")
    if type(options.max_calls) is not int or not 1 <= options.max_calls <= HARD_MAX_CALLS:
        raise MatrixError(f"--max-calls must be from 1 to {HARD_MAX_CALLS}")
    if type(options.duration) is not int or options.duration < 1:
        raise MatrixError("--duration must be a positive integer")
    if type(options.answer_timeout) is not int or not 1 <= options.answer_timeout <= 120:
        raise MatrixError("--answer-timeout must be from 1 to 120 seconds")
    by_transport: dict[str, dict[str, Any]] = {}

    def shown(path: Path) -> str:
        return guided._display(Path(path), work_root) if work_root is not None else str(path)

    for path in options.profiles:
        try:
            document = load_profile(path)
        except ProfileError as error:
            raise MatrixError(f"{path}: {error}") from error
        target = document.get("target") if isinstance(document.get("target"), dict) else {}
        transport = target.get("transport")
        if transport not in TRANSPORTS:
            raise MatrixError(f"{path}: target.transport must be udp, tcp, or tls")
        if transport in by_transport:
            raise MatrixError(
                f"{path} and {by_transport[transport]['path']} both approve {transport}; "
                "give one profile per transport"
            )
        try:
            approved = approved_codecs(document)
        except ProfileError as error:
            raise MatrixError(f"{path}: {error}") from error
        by_transport[transport] = {"path": path, "document": document, "approved": approved}

    transports = _unique(options.transports or tuple(by_transport), "transports")
    for transport in transports:
        if transport not in TRANSPORTS:
            raise MatrixError(f"--transports: {transport!r} is not udp, tcp, or tls")
        if transport not in by_transport:
            raise MatrixError(
                f"--transports: no given profile approves {transport} "
                f"(approved: {', '.join(by_transport)})"
            )
    requested_codecs = options.codecs
    if not requested_codecs:
        lists = {entry["approved"] for entry in by_transport.values()}
        if len(lists) != 1 or None in lists:
            raise MatrixError(
                "--codecs is required unless every profile approves the same media.codecs"
            )
        requested_codecs = next(iter(lists))
    try:
        codecs = _unique(tuple(canonical_codec(item) for item in requested_codecs), "codecs")
    except SoftphoneError as error:
        raise MatrixError(f"--codecs: {error}") from error
    srtp_modes = _unique(options.srtp or ("off",), "srtp")
    for mode in srtp_modes:
        if mode not in SRTP_MODES:
            raise MatrixError(f"--srtp: {mode!r} is not off, optional, or mandatory")

    cells: list[dict[str, Any]] = []
    per_profile: dict[str, int] = {}
    wall_seconds = 0.0
    for transport in transports:
        entry = by_transport[transport]
        document = entry["document"]
        features = document.get("features") if isinstance(document.get("features"), dict) else {}
        for codec in codecs:
            if entry["approved"] is not None and codec not in entry["approved"]:
                raise MatrixError(
                    f"codec {codec} is not approved by {entry['path']} "
                    f"(media.codecs: {', '.join(entry['approved'])})"
                )
            for mode in srtp_modes:
                if mode != "off" and features.get("srtp") is not True:
                    raise MatrixError(
                        f"SRTP {mode} is not approved by {entry['path']} (features.srtp is not true)"
                    )
                cell_options = _cell_options(options, entry["path"], codec, mode)
                duration, _limit = guided.effective_duration(options.duration, document)
                wall_seconds += guided.planned_wall_seconds(cell_options, duration) + GAP_SECONDS
                per_profile[shown(entry["path"])] = per_profile.get(shown(entry["path"]), 0) + 1
                cells.append(
                    {
                        "index": len(cells) + 1,
                        "transport": transport,
                        "codec": codec,
                        "srtp": mode,
                        "profile": shown(entry["path"]),
                        "warning": (
                            SDES_CLEARTEXT_WARNING if mode != "off" and transport != "tls" else None
                        ),
                        "status": "planned",
                    }
                )
    if not cells:
        raise MatrixError("the matrix has no cells")
    blocking: list[str] = []
    if len(cells) > options.max_calls:
        blocking.append(
            f"the matrix needs {len(cells)} calls, more than --max-calls {options.max_calls}; "
            "narrow --transports, --codecs, or --srtp, or raise --max-calls"
        )
    limits_view: dict[str, Any] = {}
    spacing = GAP_SECONDS
    for transport in transports:
        entry = by_transport[transport]
        document = entry["document"]
        path = shown(entry["path"])
        limits = document.get("limits") if isinstance(document.get("limits"), dict) else {}
        max_calls = limits.get("max_calls")
        rate = limits.get("max_calls_per_second")
        if type(max_calls) is int and per_profile[path] > max_calls:
            blocking.append(
                f"{path}: the matrix places {per_profile[path]} calls through this profile, "
                f"more than its limits.max_calls {max_calls}"
            )
        if type(rate) is int and rate >= 1:
            spacing = max(spacing, 1.0 / rate)
        for message in guided.gate(
            document, now=now, planned_seconds=int(wall_seconds) + 1, work_root=work_root,
            destination=options.destination, profile_path=entry["path"],
        ):
            blocking.append(f"{path}: {message}")
        limits_view[path] = {
            "transport": transport,
            "calls": per_profile[path],
            "max_calls": max_calls,
            "max_calls_per_second": rate,
            "approved_codecs": None if entry["approved"] is None else list(entry["approved"]),
            # None: this profile does not restrict the destination.
            "approved_destinations": guided._destination_record(
                document, options.destination, key="snake"
            )["approved_destinations"],
            "srtp_approved": (document.get("features") or {}).get("srtp") is True,
        }
    shared = _shared_ceilings(transports, by_transport, per_profile, shown)
    for group in _ledger_groups(transports, by_transport, per_profile, shown):
        for message in guided.ledger_blocking_in(
            group["directory"], group["approval"], group["ceiling"], group["calls"], "matrix run"
        ):
            if message not in blocking:
                blocking.append(message)
    for item in shared:
        if item["calls"] > item["max_calls"]:
            counted = ", ".join(f"{calls} through {path}" for path, calls in item["profiles"].items())
            blocking.append(
                f"the matrix places {item['calls']} calls under approval {item['approval_id']}, "
                f"more than its limits.max_calls {item['max_calls']} ({counted}); the profiles of one "
                "approval (one scope) share one call ceiling, it is not a ceiling per profile; "
                f"narrow --transports, --codecs, or --srtp to {item['max_calls']} calls or fewer in "
                "total, or ask the owner to approve more calls (limits.calls in scope.yaml) and run "
                "scope compile"
            )
    value: dict[str, Any] = {
        "apiVersion": MATRIX_VERSION,
        "state": "planned",
        "ready": not blocking,
        "destination": options.destination,
        "transports": list(transports),
        "codecs": list(codecs),
        "srtp": list(srtp_modes),
        "totalCalls": len(cells),
        "maxCalls": options.max_calls,
        "profiles": limits_view,
        "spacingSeconds": spacing,
        "plannedWallSeconds": int(wall_seconds),
        "callSeconds": options.duration,
        "cells": cells,
        "blockingErrors": blocking,
        "networkActivity": "none",
    }
    if shared:
        value["sharedCeilings"] = shared
    return value


def _shared_ceilings(
    transports: Sequence[str],
    by_transport: dict[str, dict[str, Any]],
    per_profile: dict[str, int],
    shown: Callable[[Path], str],
) -> list[dict[str, Any]]:
    """The call ceiling of every approval that two or more of the given profiles share (bn-28vz).

    ``scope compile`` writes one profile per target, each with the same
    ``authorization.approval_id`` and the scope's ``limits.calls`` as
    ``limits.max_calls``. That number is the owner's total, so the calls placed
    through all of those profiles are counted together against the smallest
    ``max_calls`` among them. A profile without an approval id, or the only
    profile of its approval, is counted alone, as before.
    """
    groups: dict[str, list[str]] = {}
    for transport in transports:
        document = by_transport[transport]["document"]
        approval = (document.get("authorization") or {}).get("approval_id")
        if isinstance(approval, str) and approval.strip():
            groups.setdefault(approval, []).append(transport)
    shared: list[dict[str, Any]] = []
    for approval, members in groups.items():
        if len(members) < 2:
            continue
        ceilings = [
            limits["max_calls"]
            for limits in (by_transport[item]["document"].get("limits") or {} for item in members)
            if isinstance(limits, dict) and type(limits.get("max_calls")) is int
        ]
        if not ceilings:
            continue
        counted = {shown(by_transport[item]["path"]): per_profile[shown(by_transport[item]["path"])] for item in members}
        shared.append(
            {
                "approval_id": approval,
                "max_calls": min(ceilings),
                "calls": sum(counted.values()),
                "profiles": counted,
            }
        )
    return shared


def _ledger_groups(
    transports: Sequence[str],
    by_transport: dict[str, dict[str, Any]],
    per_profile: dict[str, int],
    shown: Callable[[Path], str],
) -> list[dict[str, Any]]:
    """The calls this grid places per engagement call ledger (bn-2sfn).

    One group per (engagement directory, approval id); its ceiling is the
    smallest ``limits.max_calls`` among the group's profiles.
    """
    groups: dict[tuple[Path, str], dict[str, Any]] = {}
    for transport in transports:
        entry = by_transport[transport]
        approval, ceiling = guided.ledger_terms(entry["document"])
        if not approval:
            continue
        directory = Path(entry["path"]).parent
        key = (directory.resolve(), approval)
        group = groups.setdefault(key, {
            "directory": directory, "approval": approval, "ceiling": ceiling, "calls": 0,
            "sources": [],
        })
        group["ceiling"] = min(group["ceiling"], ceiling)
        group["calls"] += per_profile[shown(entry["path"])]
        group["sources"].append(Path(entry["path"]).name)
    return list(groups.values())


def _reserve_grid(
    plan: dict[str, Any], profile_paths: dict[str, Path]
) -> tuple[dict[tuple[Path, str], Any], dict[str, tuple[Path, str] | None], str | None]:
    """Reserve every cell of the grid in its engagement's call ledger (bn-2sfn)."""
    from sippycup import call_ledger

    groups: dict[tuple[Path, str], dict[str, Any]] = {}
    group_of: dict[str, tuple[Path, str] | None] = {}
    for transport, path in profile_paths.items():
        approval, ceiling = guided.ledger_terms(load_profile(path))
        if not approval:
            group_of[transport] = None
            continue
        key = (path.parent.resolve(), approval)
        group_of[transport] = key
        group = groups.setdefault(key, {"directory": path.parent, "ceiling": ceiling, "calls": 0, "sources": []})
        group["ceiling"] = min(group["ceiling"], ceiling)
        group["sources"].append(path.name)
    for cell in plan["cells"]:
        key = group_of.get(cell["transport"])
        if key is not None:
            groups[key]["calls"] += 1
    reservations: dict[tuple[Path, str], Any] = {}
    for key, group in groups.items():
        try:
            reservations[key] = call_ledger.reserve(
                group["directory"], approval_id=key[1], ceiling=group["ceiling"],
                calls=group["calls"], command="matrix run", source=", ".join(group["sources"]),
            )
        except (call_ledger.CeilingRefused, call_ledger.LedgerError) as error:
            for reservation in reservations.values():
                reservation.release(reservation.calls, "the matrix was refused before its first cell")
            return {}, group_of, str(error)
    return reservations, group_of, None


def _profile_transports(paths: Sequence[Path]) -> list[dict[str, str]]:
    return [{"transport": str(load_profile(path)["target"]["transport"])} for path in paths]


def _setup_seconds(value: dict[str, Any]) -> float | None:
    setup = value.get("setup") or {}
    seconds = setup.get("inviteToAnswerSeconds")
    return seconds if seconds is not None else setup.get("seconds")


def _cell_result(value: dict[str, Any], code: int) -> dict[str, Any]:
    softphone = value.get("softphone") or {}
    codec = value.get("codec") or {}
    wire = codec.get("wire") or {}
    srtp = value.get("srtp") or {}
    return {
        "status": "run",
        "verdict": value.get("verdict"),
        "state": value.get("state"),
        "exitCode": code,
        "finalStatus": softphone.get("final_status"),
        "setupSeconds": _setup_seconds(value),
        "offered": codec.get("offered"),
        "negotiated": codec.get("negotiated"),
        "negotiatedPayloadType": codec.get("negotiatedPayloadType"),
        "codecVerifiedOnWire": wire.get("verified"),
        "srtpActive": srtp.get("active"),
        "mediaAdmittedBy": (value.get("mediaScope") or {}).get("admittedBy"),
        "mediaNetwork": (value.get("mediaScope") or {}).get("network"),
        "runDirectory": value.get("runDirectory"),
    }


def _stop_reason(value: dict[str, Any]) -> str | None:
    verdict = value.get("verdict")
    if verdict in STOP_VERDICTS:
        return f"{verdict}: {STOP_VERDICTS[verdict]}"
    if verdict == "call-unavailable" and (value.get("softphone") or {}).get("final_status") == 503:
        return "call-unavailable: the far end answered 503 (overload or a failed downstream)"
    return None


@dataclasses.dataclass
class MatrixDependencies:
    execute: Callable[..., tuple[int, dict[str, Any]]] = guided.execute
    call_dependencies: Callable[[MutableMapping[str, str]], Any] = (
        lambda environ: guided.Dependencies(environ=environ)
    )
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    sleep: Callable[[float], None] = time.sleep
    monotonic: Callable[[], float] = time.monotonic
    environ: MutableMapping[str, str] = dataclasses.field(default_factory=lambda: os.environ)
    work_root: Path | None = None
    install_signal_handlers: bool = True
    # One line per cell as it starts and ends, so a long grid shows progress.
    progress: Callable[[str], None] | None = None


def run(options: MatrixOptions, deps: MatrixDependencies | None = None) -> tuple[int, dict[str, Any]]:
    """Run every cell in order; stop at the first stop condition."""
    deps = deps or MatrixDependencies()
    work_root = deps.work_root or guided.default_work_root()
    plan = build_plan(options, now=deps.now(), work_root=work_root)
    if not plan["ready"]:
        plan["state"] = "blocked"
        return EXIT_REFUSED, plan
    if options.username and options.register and not (options.secret_env or options.secret_file):
        raise MatrixError(
            "--username needs the account password: add --secret-env NAME or "
            "--secret-file work/PATH (or --no-register for an account that is not registered)"
        )
    # Resolve the secret once: the variable leaves this process's
    # environment, and each call receives it only in its private mapping.
    secret: tuple[str, str] | None = None
    if options.secret_env:
        if options.secret_env not in deps.environ:
            raise MatrixError(f"environment variable {options.secret_env} is not set")
        secret = (options.secret_env, deps.environ.pop(options.secret_env))
        os.environ.pop(options.secret_env, None)
    base_environ = dict(deps.environ)
    profile_paths = {
        facts["transport"]: Path(path)
        for path, facts in zip(options.profiles, _profile_transports(options.profiles))
    }
    first_profile = Path(options.profiles[0])
    matrix_root = Path(options.matrix_root) if options.matrix_root else first_profile.parent / "matrix"
    if not guided._within(matrix_root, work_root):
        raise MatrixError(f"the matrix directory must be beneath the work directory ({work_root})")
    # The owner's call limit holds for the engagement (bn-2sfn): reserve the
    # whole grid in each engagement's call ledger before the first cell.
    reservations, group_of, refusal = _reserve_grid(plan, profile_paths)
    if refusal is not None:
        plan["state"] = "blocked"
        plan["ready"] = False
        plan["blockingErrors"].append(refusal)
        return EXIT_REFUSED, plan
    sent: dict[int, bool] = {}
    old_umask = os.umask(0o077)
    try:
        matrix_dir = create_run_directory(matrix_root, guided._slug(f"matrix-{options.destination}"))
    finally:
        os.umask(old_umask)
    cancelled: list[int] = []
    previous: dict[int, Any] = {}

    def handle(signum: int, _frame: object) -> None:
        if not cancelled:
            cancelled.append(signum)

    if deps.install_signal_handlers:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[signum] = signal.signal(signum, handle)
    started = guided._utc(deps.now())
    stop: str | None = None
    last_start: float | None = None
    try:
        for cell in plan["cells"]:
            if stop is None and cancelled:
                stop = STOP_VERDICTS["cancelled"]
            if stop is not None:
                cell.update(status="not-run", reason=stop)
                continue
            if last_start is not None:
                wait = last_start + plan["spacingSeconds"] - deps.monotonic()
                if wait > 0:
                    deps.sleep(wait)
                if cancelled:
                    stop = STOP_VERDICTS["cancelled"]
                    cell.update(status="not-run", reason=stop)
                    continue
            last_start = deps.monotonic()
            environ = dict(base_environ)
            if secret is not None:
                environ[secret[0]] = secret[1]
            call_options = _cell_options(
                options, profile_paths[cell["transport"]], cell["codec"], cell["srtp"]
            )
            label = f"cell {cell['index']}/{len(plan['cells'])} {cell['transport']}/{cell['codec']}/srtp {cell['srtp']}"
            if deps.progress is not None:
                deps.progress(f"Matrix: {label}: calling ...")
            call_deps = deps.call_dependencies(environ)
            try:
                call_deps.ledger_reserved = True
                call_deps.ledger_reservation = reservations.get(group_of.get(cell["transport"]))
            except AttributeError:
                pass
            try:
                code, value = deps.execute(call_options, call_deps)
            except (guided.CallError, ProfileError) as error:
                cell.update(status="refused", verdict="refused", exitCode=EXIT_REFUSED, reason=str(error))
                stop = f"refused: {error}"
                if deps.progress is not None:
                    deps.progress(f"Matrix: {label}: refused: {error}")
                continue
            cell.update(_cell_result(value, code))
            sent[cell["index"]] = bool(
                (value.get("timestamps") or {}).get("preflight_sent")
                or value.get("verdict") == "internal-error"
            )
            if deps.progress is not None:
                deps.progress(f"Matrix: {label}: {cell.get('verdict')}")
            if code in (130, 143):
                cancelled.append(code)
            stop = _stop_reason(value)
            if stop is None and deps.monotonic() - last_start < GAP_SECONDS:
                # Never faster than the gap, even when a call ends at once.
                deps.sleep(GAP_SECONDS)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        # Cells that sent nothing (not run, refused, blocked) do not count.
        for key, reservation in reservations.items():
            unsent = sum(
                1 for cell in plan["cells"]
                if group_of[cell["transport"]] == key and not sent.get(cell["index"], False)
            )
            reservation.release(unsent, "matrix cells that sent nothing")
    run_cells = [cell for cell in plan["cells"] if cell["status"] == "run"]
    if cancelled:
        code = 130 if cancelled[0] in (signal.SIGINT, 130) else 143
        state = "cancelled"
    elif stop is not None and not run_cells:
        code, state = EXIT_REFUSED, "blocked"
    elif stop is not None:
        code, state = EXIT_STOPPED, "stopped"
    elif all(cell.get("verdict") == "pass" for cell in run_cells):
        code, state = EXIT_PASS, "completed"
    else:
        code, state = EXIT_NOT_PASS, "completed"
    plan.update(
        state=state,
        exitCode=code,
        stopReason=stop,
        callsPlaced=len(run_cells),
        passed=sum(1 for cell in run_cells if cell.get("verdict") == "pass"),
        matrixDirectory=guided._display(matrix_dir, work_root),
        timestamps={"started": started, "finished": guided._utc(deps.now())},
        networkActivity=(
            f"{len(run_cells)} guided call(s), each with 1 SIP OPTIONS preflight, one after another"
            if run_cells
            else "none"
        ),
    )
    guided._write_json(matrix_dir / "matrix.json", plan)
    return code, plan


def _cell_text(cell: dict[str, Any]) -> str:
    if cell["status"] == "planned":
        return "planned"
    if cell["status"] != "run":
        return cell["status"]
    seconds = cell.get("setupSeconds")
    return f"{cell.get('verdict')}" + (f" {seconds:.3f}s" if isinstance(seconds, (int, float)) else "")


def render_grid(value: dict[str, Any]) -> list[str]:
    """Rows are transport x SRTP; columns are codecs; each cell a verdict and setup time."""
    codecs = value["codecs"]
    rows: list[list[str]] = [["transport", "srtp", *codecs]]
    by_key = {(cell["transport"], cell["srtp"], cell["codec"]): cell for cell in value["cells"]}
    for transport in value["transports"]:
        for mode in value["srtp"]:
            rows.append(
                [transport, mode, *(_cell_text(by_key[(transport, mode, codec)]) for codec in codecs)]
            )
    widths = [max(len(row[index]) for row in rows) for index in range(len(rows[0]))]
    return ["  " + "  ".join(item.ljust(widths[index]) for index, item in enumerate(row)).rstrip() for row in rows]


def render_human(value: dict[str, Any]) -> str:
    lines: list[str] = []
    state = value["state"]
    executed = "callsPlaced" in value
    if not executed:
        lines.append(
            f"Call matrix plan: {'READY' if value['ready'] else 'BLOCKED'} - {value['totalCalls']} "
            f"call(s) to {value['destination']} (--max-calls {value['maxCalls']})"
        )
        for error in value["blockingErrors"]:
            lines.append(f"BLOCK: {error}")
    else:
        lines.append(
            f"Call matrix: {state.upper()} - {value['callsPlaced']} of {value['totalCalls']} call(s) "
            f"placed, {value['passed']} passed"
        )
    for path, facts in value["profiles"].items():
        lines.append(
            f"  {facts['transport']}: {path} ({facts['calls']} call(s); limits.max_calls "
            f"{facts['max_calls']}, approved codecs "
            f"{', '.join(facts['approved_codecs']) if facts['approved_codecs'] else 'any'}, "
            f"SRTP {'approved' if facts['srtp_approved'] else 'not approved'})"
        )
        if "approved_destinations" in facts and facts["approved_destinations"] is None:
            lines.append(
                f"    NOTE: {path} has no target.approved_destinations, so it does not restrict "
                f"which destination is dialed; check {value['destination']} against the owner's "
                "written approval yourself"
            )
    for item in value.get("sharedCeilings") or ():
        lines.append(
            f"  Shared ceiling: approval {item['approval_id']} allows {item['max_calls']} call(s) in "
            f"total across {', '.join(item['profiles'])}; this grid places {item['calls']}."
        )
    lines.append(
        f"  Each cell is one guided call ({value['callSeconds']}s, offering only its codec), "
        f"strictly in order, at least {value['spacingSeconds']:.1f}s apart."
    )
    lines.extend(render_grid(value))
    warned = [cell for cell in value["cells"] if cell.get("warning")]
    if warned:
        lines.append(
            f"WARNING: cells {', '.join(str(cell['index']) for cell in warned)} (SRTP over "
            f"{'/'.join(sorted({cell['transport'] for cell in warned}))}): "
            f"{warned[0]['warning']}: SDES keys travel in cleartext SDP."
        )
    if executed:
        for cell in value["cells"]:
            if cell["status"] == "run" and cell.get("runDirectory"):
                lines.append(
                    f"  {cell['index']}. {cell['transport']}/{cell['codec']}/{cell['srtp']}: "
                    f"{cell['verdict']} -> {cell['runDirectory']}"
                )
            elif cell["status"] == "refused":
                lines.append(f"  {cell['index']}. refused: {cell.get('reason')}")
        if value.get("stopReason"):
            lines.append(f"STOPPED: {value['stopReason']}; the remaining cells were not run.")
        lines.append(f"Matrix record: {value['matrixDirectory']}/matrix.json")
    else:
        lines.append("This command sent no packets.")
    lines.append(f"Network activity: {value['networkActivity']}")
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sippycup matrix",
        description=(
            "Plan or run a transport x codec x SRTP grid of guided calls, one after another, "
            "each through the same gates and evidence as `call`."
        ),
        epilog=(
            "plan sends nothing and needs no container. run places each cell as one guided call. "
            "Exit status: 0 every cell passed; 1 the grid ran and some cell did not pass; "
            "2 refused before any packet; 3 stopped early on a stop condition (auth failure, "
            "429, 503, authorization lapse, capture failure); 130/143 cancelled. "
            f"Codecs: {', '.join(SUPPORTED_CODECS)}."
        ),
    )
    actions = parser.add_subparsers(dest="action", required=True)
    for name in ("plan", "run"):
        sub = actions.add_parser(name, help="print the grid and send nothing" if name == "plan" else "place the grid's calls")
        sub.add_argument("profiles", nargs="+", type=Path, metavar="PROFILE", help="one approved profile per transport")
        sub.add_argument("--dial", required=True, metavar="DESTINATION")
        sub.add_argument("--transports", action="append", metavar="T[,T]", help="udp, tcp, tls (default: every profile's)")
        sub.add_argument(
            "--codecs", action="append", metavar="C[,C]",
            help="one cell per codec, each offered alone (default: the profiles' common media.codecs)",
        )
        sub.add_argument("--srtp", action="append", metavar="M[,M]", help="off, optional, mandatory (default off)")
        sub.add_argument("--max-calls", type=int, default=DEFAULT_MAX_CALLS, help=f"refuse a grid with more calls (default {DEFAULT_MAX_CALLS}, at most {HARD_MAX_CALLS})")
        sub.add_argument("--duration", type=int, default=DEFAULT_DURATION_SECONDS)
        sub.add_argument("--answer-timeout", type=int, default=guided.DEFAULT_ANSWER_TIMEOUT_SECONDS)
        sub.add_argument("--username")
        sub.add_argument("--realm", default="*")
        sub.add_argument("--no-register", action="store_true")
        secret = sub.add_mutually_exclusive_group()
        secret.add_argument("--secret-env", metavar="NAME")
        secret.add_argument("--secret-file", type=Path)
        sub.add_argument("--run-root", type=Path, help="directory beneath work/ for the calls' run directories")
        sub.add_argument("--matrix-root", type=Path, help="directory beneath work/ for the matrix record")
        sub.add_argument("--engagement", type=Path)
        sub.add_argument("--no-media-required", action="store_true")
        sub.add_argument("--format", choices=("human", "json"), default="human")
        sub.add_argument("--dry-run", action="store_true", help="same as plan")
    return parser


def main(argv: Sequence[str] | None = None, deps: MatrixDependencies | None = None) -> int:
    args = build_parser().parse_args(argv)
    options = MatrixOptions(
        profiles=tuple(args.profiles),
        destination=args.dial,
        codecs=_split(args.codecs),
        transports=_split(args.transports),
        srtp=_split(args.srtp) or ("off",),
        max_calls=args.max_calls,
        duration=args.duration,
        answer_timeout=args.answer_timeout,
        username=args.username,
        realm=args.realm,
        register=not args.no_register,
        secret_env=args.secret_env,
        secret_file=args.secret_file,
        run_root=args.run_root,
        matrix_root=args.matrix_root,
        engagement=args.engagement,
        media_required=not args.no_media_required,
        output_format=args.format,
    )
    try:
        if args.action == "plan" or args.dry_run:
            dependencies = deps or MatrixDependencies()
            value = build_plan(
                options, now=dependencies.now(), work_root=dependencies.work_root or guided.default_work_root()
            )
            code = EXIT_PASS if value["ready"] else EXIT_REFUSED
        else:
            if deps is None:
                deps = MatrixDependencies(progress=lambda line: print(line, file=sys.stderr, flush=True))
            code, value = run(options, deps)
    except (MatrixError, guided.CallError, ProfileError) as error:
        print(f"error: {error}", file=sys.stderr)
        print("Nothing was started and no packets were sent.", file=sys.stderr)
        print("Network activity: none", file=sys.stderr if args.format == "json" else sys.stdout)
        return EXIT_REFUSED
    if args.format == "json":
        print(json.dumps(value, indent=2, sort_keys=True))
    else:
        sys.stdout.write(render_human(value))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
