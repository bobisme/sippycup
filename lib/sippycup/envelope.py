"""Immutable authorization budgets and deterministic one-dimensional ramps."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Callable, Sequence

try:
    import yaml
except ImportError:  # pragma: no cover - installation failure path
    yaml = None


MANIFEST_VERSION = "sippycup.dev/envelope/v1"
PLAN_VERSION = "sippycup.dev/envelope-plan/v1"
SIMULATION_VERSION = "sippycup.dev/envelope-simulation/v1"
U64_MAX = (1 << 64) - 1
MAX_PLAN_STEPS = 100_000
MAX_DOCUMENT_BYTES = 1024 * 1024
DIMENSIONS = (
    "callsPerSecond",
    "concurrentCalls",
    "mediaPacketsPerSecond",
)
MAXIMA_KEYS = (
    *DIMENSIONS,
    "totalCalls",
    "durationSeconds",
    "holdSeconds",
    "cooldownSeconds",
    "recoveryDeadlineSeconds",
)
WORKLOAD_KEYS = (*DIMENSIONS, "callDurationSeconds")


class EnvelopeError(ValueError):
    """A fail-closed manifest, plan, or controller error."""


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EnvelopeError(f"{field} must be an object")
    return value


def _exact_keys(
    value: dict[str, Any],
    field: str,
    required: set[str],
) -> None:
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - required)
    if missing:
        raise EnvelopeError(f"{field} missing fields: {', '.join(missing)}")
    if unknown:
        raise EnvelopeError(
            f"{field} contains unsupported fields: {', '.join(unknown)}"
        )


def _uint(
    value: Any,
    field: str,
    *,
    allow_zero: bool = False,
) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int):
        raise EnvelopeError(f"{field} must be an integer")
    if value < minimum or value > U64_MAX:
        raise EnvelopeError(f"{field} must be between {minimum} and {U64_MAX}")
    return value


def _checked_add(left: int, right: int, field: str) -> int:
    if left > U64_MAX - right:
        raise EnvelopeError(f"arithmetic overflow while calculating {field}")
    return left + right


def _checked_mul(left: int, right: int, field: str) -> int:
    if left and right > U64_MAX // left:
        raise EnvelopeError(f"arithmetic overflow while calculating {field}")
    return left * right


def _ceil_div(numerator: int, denominator: int) -> int:
    return numerator // denominator + bool(numerator % denominator)


def _name(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 63
        or value[0] not in "abcdefghijklmnopqrstuvwxyz"
        or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789-"
            for character in value
        )
    ):
        raise EnvelopeError(f"{field} must match [a-z][a-z0-9-]{{0,62}}")
    return value


def _sha256(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise EnvelopeError(f"{field} must be 64 lowercase hex digits")
    return value


def _read_document(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise EnvelopeError(f"cannot read {label}: {error}") from error
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise EnvelopeError(f"{label} exceeds {MAX_DOCUMENT_BYTES} bytes")
    return _parse_document(raw, label), raw


def _parse_document(raw: bytes, label: str) -> dict[str, Any]:
    if yaml is None:
        raise EnvelopeError("PyYAML is required for envelope manifests")
    try:
        value = yaml.safe_load(raw)
    except yaml.YAMLError as error:
        raise EnvelopeError(f"invalid {label}: {error}") from error
    return _object(value, label)


def _normalize_maxima(value: Any, field: str) -> dict[str, int]:
    maxima = _object(value, field)
    _exact_keys(maxima, field, set(MAXIMA_KEYS))
    return {
        key: _uint(maxima[key], f"{field}.{key}") for key in MAXIMA_KEYS
    }


def _apply_reductions(
    maxima: dict[str, int],
    reductions: dict[str, int | None] | None,
) -> dict[str, int]:
    result = dict(maxima)
    for key, value in (reductions or {}).items():
        if key not in MAXIMA_KEYS:
            raise EnvelopeError(f"unsupported maximum override {key!r}")
        if value is None:
            continue
        reduced = _uint(value, f"--max-{key}")
        if reduced > maxima[key]:
            raise EnvelopeError(
                f"override for {key} ({reduced}) exceeds authorized maximum "
                f"({maxima[key]}); overrides may only lower authorization"
            )
        result[key] = reduced
    return result


def _normalize_workload(value: Any) -> dict[str, int]:
    workload = _object(value, "workload")
    _exact_keys(workload, "workload", set(WORKLOAD_KEYS))
    return {
        key: _uint(workload[key], f"workload.{key}") for key in WORKLOAD_KEYS
    }


def _normalize_ramp(value: Any) -> dict[str, Any]:
    ramp = _object(value, "ramp")
    _exact_keys(ramp, "ramp", {"dimension", "start", "step"})
    dimension = ramp["dimension"]
    if dimension not in DIMENSIONS:
        raise EnvelopeError(
            "ramp.dimension must be callsPerSecond, concurrentCalls, "
            "or mediaPacketsPerSecond"
        )
    return {
        "dimension": dimension,
        "start": _uint(ramp["start"], "ramp.start"),
        "step": _uint(ramp["step"], "ramp.step"),
    }


def _validate_constraints(
    maxima: dict[str, int],
    workload: dict[str, int],
    ramp: dict[str, Any],
) -> None:
    for dimension in DIMENSIONS:
        if workload[dimension] > maxima[dimension]:
            raise EnvelopeError(
                f"workload.{dimension} exceeds authorization hard maximum"
            )
    if workload["callDurationSeconds"] > maxima["durationSeconds"]:
        raise EnvelopeError(
            "workload.callDurationSeconds exceeds duration hard maximum"
        )
    if workload[ramp["dimension"]] != ramp["start"]:
        raise EnvelopeError(
            "workload value for ramp.dimension must equal ramp.start"
        )
    if ramp["start"] > maxima[ramp["dimension"]]:
        raise EnvelopeError("ramp.start exceeds its authorization hard maximum")


def _normalize_manifest(
    manifest: Any,
    reductions: dict[str, int | None] | None = None,
) -> dict[str, Any]:
    document = _object(manifest, "manifest")
    _exact_keys(
        document,
        "manifest",
        {
            "apiVersion",
            "kind",
            "metadata",
            "authorization",
            "workload",
            "ramp",
        },
    )
    if document["apiVersion"] != MANIFEST_VERSION:
        raise EnvelopeError(f"apiVersion must be {MANIFEST_VERSION!r}")
    if document["kind"] != "Envelope":
        raise EnvelopeError("kind must be 'Envelope'")
    metadata = _object(document["metadata"], "metadata")
    _exact_keys(metadata, "metadata", {"name"})
    name = _name(metadata["name"], "metadata.name")
    authorization = _object(document["authorization"], "authorization")
    _exact_keys(authorization, "authorization", {"hardMaxima"})
    source_maxima = _normalize_maxima(
        authorization["hardMaxima"], "authorization.hardMaxima"
    )
    maxima = _apply_reductions(source_maxima, reductions)
    workload = _normalize_workload(document["workload"])
    ramp = _normalize_ramp(document["ramp"])
    _validate_constraints(maxima, workload, ramp)
    return {
        "name": name,
        "sourceMaxima": source_maxima,
        "maxima": maxima,
        "workload": workload,
        "ramp": ramp,
    }


def _levels(start: int, step: int, maximum: int) -> list[int]:
    count = _ceil_div(maximum - start, step) + 1
    if count > MAX_PLAN_STEPS:
        raise EnvelopeError(
            f"ramp expansion exceeds planner limit ({MAX_PLAN_STEPS})"
        )
    levels = [start + index * step for index in range(count)]
    levels[-1] = min(levels[-1], maximum)
    if levels[-1] != maximum:
        levels.append(maximum)
    return levels


def _step_budget(
    intensity: dict[str, int],
    hold_seconds: int,
    call_duration_seconds: int,
) -> dict[str, int]:
    calls_at_rate = _checked_mul(
        intensity["callsPerSecond"], hold_seconds, "step calls at CPS"
    )
    rotations = _ceil_div(hold_seconds, call_duration_seconds)
    calls_at_concurrency = _checked_mul(
        intensity["concurrentCalls"], rotations, "step calls at concurrency"
    )
    calls = max(calls_at_rate, calls_at_concurrency)
    media_packets = _checked_mul(
        intensity["mediaPacketsPerSecond"],
        hold_seconds,
        "step media packets",
    )
    call_seconds = _checked_mul(
        intensity["concurrentCalls"], hold_seconds, "step call-seconds"
    )
    return {
        "calls": calls,
        "mediaPackets": media_packets,
        "callSeconds": call_seconds,
        "durationSeconds": hold_seconds,
    }


def _compile_normalized(
    normalized: dict[str, Any],
    manifest_sha256: str,
) -> dict[str, Any]:
    maxima = normalized["maxima"]
    workload = normalized["workload"]
    ramp = normalized["ramp"]
    reserved_tail = _checked_add(
        maxima["cooldownSeconds"],
        maxima["recoveryDeadlineSeconds"],
        "cooldown and recovery duration",
    )
    if reserved_tail >= maxima["durationSeconds"]:
        raise EnvelopeError(
            "duration hard maximum must leave time for at least one ramp hold "
            "before cooldown and recovery"
        )
    totals = {
        "calls": 0,
        "mediaPackets": 0,
        "callSeconds": 0,
        "rampDurationSeconds": 0,
    }
    steps: list[dict[str, Any]] = []
    reason = "authorization_ceiling"
    for level in _levels(
        ramp["start"],
        ramp["step"],
        maxima[ramp["dimension"]],
    ):
        intensity = {
            key: (level if key == ramp["dimension"] else workload[key])
            for key in DIMENSIONS
        }
        budget = _step_budget(
            intensity,
            maxima["holdSeconds"],
            workload["callDurationSeconds"],
        )
        next_calls = _checked_add(totals["calls"], budget["calls"], "total calls")
        next_duration = _checked_add(
            totals["rampDurationSeconds"],
            budget["durationSeconds"],
            "ramp duration",
        )
        total_duration = _checked_add(
            next_duration, reserved_tail, "worst-case duration"
        )
        if (
            next_calls > maxima["totalCalls"]
            or total_duration > maxima["durationSeconds"]
        ):
            reason = "budget_exhausted"
            break
        next_media = _checked_add(
            totals["mediaPackets"],
            budget["mediaPackets"],
            "total media packets",
        )
        next_call_seconds = _checked_add(
            totals["callSeconds"],
            budget["callSeconds"],
            "total call-seconds",
        )
        steps.append(
            {
                "index": len(steps) + 1,
                "level": level,
                "startAtSeconds": totals["rampDurationSeconds"],
                "holdSeconds": maxima["holdSeconds"],
                "intensity": intensity,
                "budget": budget,
            }
        )
        totals = {
            "calls": next_calls,
            "mediaPackets": next_media,
            "callSeconds": next_call_seconds,
            "rampDurationSeconds": next_duration,
        }
    if not steps:
        raise EnvelopeError(
            "no ramp step fits the remaining total-call and duration budgets"
        )
    reached = steps[-1]["level"] == maxima[ramp["dimension"]]
    if not reached:
        reason = "budget_exhausted"
    total_duration = _checked_add(
        totals["rampDurationSeconds"], reserved_tail, "worst-case duration"
    )
    return {
        "apiVersion": PLAN_VERSION,
        "kind": "EnvelopePlan",
        "metadata": {
            "name": normalized["name"],
            "manifestSha256": manifest_sha256,
        },
        "authorization": {
            "sourceMaxima": normalized["sourceMaxima"],
            "hardMaxima": maxima,
        },
        "workload": workload,
        "ramp": ramp,
        "plannedWorstCase": {
            **totals,
            "cooldownSeconds": maxima["cooldownSeconds"],
            "recoveryDeadlineSeconds": maxima["recoveryDeadlineSeconds"],
            "totalDurationSeconds": total_duration,
        },
        "termination": {
            "reason": reason,
            "authorizedDimensionCeilingReached": reached,
        },
        "steps": steps,
    }


def compile_envelope_plan(
    manifest: Any,
    manifest_sha256: str,
    *,
    reductions: dict[str, int | None] | None = None,
) -> dict[str, Any]:
    _sha256(manifest_sha256, "manifest SHA-256")
    normalized = _normalize_manifest(manifest, reductions)
    return _compile_normalized(normalized, manifest_sha256)


def validate_envelope_plan(value: Any) -> dict[str, Any]:
    plan = _object(value, "plan")
    _exact_keys(
        plan,
        "plan",
        {
            "apiVersion",
            "kind",
            "metadata",
            "authorization",
            "workload",
            "ramp",
            "plannedWorstCase",
            "termination",
            "steps",
        },
    )
    if plan["apiVersion"] != PLAN_VERSION or plan["kind"] != "EnvelopePlan":
        raise EnvelopeError("unsupported envelope plan contract")
    metadata = _object(plan["metadata"], "plan.metadata")
    _exact_keys(metadata, "plan.metadata", {"name", "manifestSha256"})
    authorization = _object(plan["authorization"], "plan.authorization")
    _exact_keys(
        authorization,
        "plan.authorization",
        {"sourceMaxima", "hardMaxima"},
    )
    normalized = {
        "name": _name(metadata["name"], "plan.metadata.name"),
        "sourceMaxima": _normalize_maxima(
            authorization["sourceMaxima"],
            "plan.authorization.sourceMaxima",
        ),
        "maxima": _normalize_maxima(
            authorization["hardMaxima"],
            "plan.authorization.hardMaxima",
        ),
        "workload": _normalize_workload(plan["workload"]),
        "ramp": _normalize_ramp(plan["ramp"]),
    }
    _sha256(metadata["manifestSha256"], "plan.metadata.manifestSha256")
    if any(
        normalized["maxima"][key] > normalized["sourceMaxima"][key]
        for key in MAXIMA_KEYS
    ):
        raise EnvelopeError("plan hard maxima expand source authorization")
    _validate_constraints(
        normalized["maxima"], normalized["workload"], normalized["ramp"]
    )
    expected = _compile_normalized(normalized, metadata["manifestSha256"])
    if expected != plan:
        raise EnvelopeError(
            "envelope plan differs from deterministic budget recompilation"
        )
    return plan


def verify_envelope_plan(
    plan: Any,
    manifest_bytes: bytes,
) -> dict[str, Any]:
    """Rebind a frozen plan to the exact reviewed source authorization."""
    validated = validate_envelope_plan(plan)
    if len(manifest_bytes) > MAX_DOCUMENT_BYTES:
        raise EnvelopeError(
            f"envelope manifest exceeds {MAX_DOCUMENT_BYTES} bytes"
        )
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    if digest != validated["metadata"]["manifestSha256"]:
        raise EnvelopeError("envelope manifest SHA-256 differs from frozen plan")
    manifest = _parse_document(manifest_bytes, "envelope manifest")
    expected = compile_envelope_plan(
        manifest,
        digest,
        reductions=dict(validated["authorization"]["hardMaxima"]),
    )
    if expected != validated:
        raise EnvelopeError(
            "frozen envelope plan differs from reviewed manifest recompilation"
        )
    return validated


def _normalize_commands(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    commands = value.get("commands") if isinstance(value, dict) else value
    if not isinstance(commands, list):
        raise EnvelopeError("controls must be a list or an object with commands")
    result = []
    previous = -1
    for index, raw in enumerate(commands):
        item = _object(raw, f"controls[{index}]")
        _exact_keys(item, f"controls[{index}]", {"atSeconds", "command"})
        at_seconds = _uint(
            item["atSeconds"], f"controls[{index}].atSeconds", allow_zero=True
        )
        command = item["command"]
        if command not in {"pause", "resume", "stop"}:
            raise EnvelopeError(
                f"controls[{index}].command must be pause, resume, or stop"
            )
        if at_seconds < previous:
            raise EnvelopeError("controls must be ordered by atSeconds")
        previous = at_seconds
        result.append({"atSeconds": at_seconds, "command": command})
    return result


def simulate_envelope_plan(
    plan: Any,
    controls: Any = None,
    *,
    endpoint: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Run the ramp state machine without opening sockets or starting children."""
    validated = validate_envelope_plan(plan)
    commands = _normalize_commands(controls)
    grouped: dict[int, list[str]] = {}
    for item in commands:
        grouped.setdefault(item["atSeconds"], []).append(item["command"])
    command_times = sorted(grouped)
    command_index = 0
    next_step = 0
    next_start: int | None = 0
    state = "running"
    events: list[dict[str, Any]] = []
    consumed = {
        "calls": 0,
        "mediaPackets": 0,
        "callSeconds": 0,
        "rampDurationSeconds": 0,
    }
    maxima = validated["authorization"]["hardMaxima"]

    def emit(at_seconds: int, event: str, **fields: Any) -> None:
        events.append(
            {
                "sequence": len(events) + 1,
                "atSeconds": at_seconds,
                "event": event,
                "state": state,
                **fields,
            }
        )

    emit(0, "controller.started")
    while state not in {"stopped", "completed"}:
        control_time = (
            command_times[command_index]
            if command_index < len(command_times)
            else None
        )
        candidates = [
            value for value in (control_time, next_start) if value is not None
        ]
        if not candidates:
            break
        now = min(candidates)
        if control_time == now:
            command_group = grouped[now]
            command_index += 1
            # Safety controls win over resume and over a ramp event at the
            # same timestamp. Stop has the strongest precedence.
            if "stop" in command_group:
                state = "stopped"
                emit(now, "control.stop", reason="operator_stop")
                break
            if "pause" in command_group:
                state = "paused"
                next_start = None
                emit(now, "control.pause")
                continue
            if "resume" in command_group:
                if state != "paused":
                    raise EnvelopeError("resume requires a paused controller")
                state = "running"
                next_start = now
                emit(now, "control.resume")
                continue
        if next_start == now and state == "running":
            if next_step >= len(validated["steps"]):
                state = "completed"
                emit(
                    now,
                    "controller.completed",
                    reason=validated["termination"]["reason"],
                )
                break
            step = validated["steps"][next_step]
            prospective_calls = _checked_add(
                consumed["calls"], step["budget"]["calls"], "consumed calls"
            )
            prospective_duration = _checked_add(
                consumed["rampDurationSeconds"],
                step["holdSeconds"],
                "consumed ramp duration",
            )
            wall_clock_after_hold = _checked_add(
                now, step["holdSeconds"], "wall-clock hold deadline"
            )
            wall_clock_with_recovery = _checked_add(
                wall_clock_after_hold,
                maxima["cooldownSeconds"] + maxima["recoveryDeadlineSeconds"],
                "wall-clock recovery deadline",
            )
            if (
                prospective_calls > maxima["totalCalls"]
                or _checked_add(
                    prospective_duration,
                    maxima["cooldownSeconds"]
                    + maxima["recoveryDeadlineSeconds"],
                    "remaining duration",
                )
                > maxima["durationSeconds"]
                or wall_clock_with_recovery > maxima["durationSeconds"]
            ):
                state = "stopped"
                emit(now, "controller.stopped", reason="budget_exhausted")
                break
            for key in consumed:
                consumed[key] = _checked_add(
                    consumed[key],
                    step["budget"][
                        "durationSeconds"
                        if key == "rampDurationSeconds"
                        else key
                    ],
                    f"consumed {key}",
                )
            if endpoint is not None:
                endpoint(step)
            emit(
                now,
                "ramp.step_started",
                step=step["index"],
                level=step["level"],
                intensity=step["intensity"],
                budget=step["budget"],
            )
            next_step += 1
            next_start = now + step["holdSeconds"]
    return {
        "apiVersion": SIMULATION_VERSION,
        "kind": "EnvelopeSimulation",
        "state": state,
        "networkTrafficSent": False,
        "startedSteps": next_step,
        "testedLevels": [
            event["level"]
            for event in events
            if event["event"] == "ramp.step_started"
        ],
        "consumedWorstCase": consumed,
        "events": events,
    }


def _write_json_exclusive(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(document, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise EnvelopeError(f"refusing to overwrite existing output {path}") from error
    finally:
        temporary.unlink(missing_ok=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sippycup envelope")
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser(
        "plan", help="compile an immutable, side-effect-free ramp plan"
    )
    plan.add_argument("manifest", type=Path)
    plan.add_argument("--output", type=Path)
    for key in MAXIMA_KEYS:
        option = []
        for character in key:
            option.append(f"-{character.lower()}" if character.isupper() else character)
        plan.add_argument(
            f"--max-{''.join(option)}",
            type=int,
            dest=f"max_{key}",
        )
    run = commands.add_parser(
        "run", help="deterministically simulate a frozen ramp plan"
    )
    run.add_argument("plan", type=Path)
    run.add_argument("--manifest", type=Path, required=True)
    run.add_argument("--controls", type=Path)
    run.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            manifest, raw = _read_document(args.manifest, "envelope manifest")
            reductions = {
                key: getattr(args, f"max_{key}") for key in MAXIMA_KEYS
            }
            result = compile_envelope_plan(
                manifest,
                hashlib.sha256(raw).hexdigest(),
                reductions=reductions,
            )
        else:
            plan, _raw = _read_document(args.plan, "envelope plan")
            _manifest, manifest_bytes = _read_document(
                args.manifest, "envelope manifest"
            )
            verify_envelope_plan(plan, manifest_bytes)
            controls = (
                _read_document(args.controls, "controls")[0]
                if args.controls is not None
                else None
            )
            result = simulate_envelope_plan(plan, controls)
        if args.output is not None:
            _write_json_exclusive(args.output, result)
            print(args.output)
        else:
            print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (EnvelopeError, OSError) as error:
        print(f"sippycup envelope: error: {error}", file=os.sys.stderr)
        return 2


__all__ = (
    "EnvelopeError",
    "MANIFEST_VERSION",
    "PLAN_VERSION",
    "SIMULATION_VERSION",
    "compile_envelope_plan",
    "simulate_envelope_plan",
    "validate_envelope_plan",
    "verify_envelope_plan",
)
