"""Command-line interface for bounded resilience plans and observations."""

from __future__ import annotations

import argparse
import json
import os
import struct
from pathlib import Path
from typing import Any, Sequence

from .common import ResilienceError, bounded_int, load_json
from .isolation import (
    WATERMARK_BITS,
    SYMBOL_MS,
    analyze_isolation,
    clean_observations,
    decode_watermark,
    plan_isolation,
    render_watermark,
)
from .lifecycle import analyze_lifecycle, synthetic_snapshots
from .migration import analyze_migration, default_policy as migration_policy
from .overload import analyze_overload, synthetic_transactions
from .secure_media import (
    analyze_secure_media,
    clean_observation,
    default_policy as secure_policy,
)


def _write(value: Any, output: str | None) -> None:
    encoded = json.dumps(value, sort_keys=True, indent=2) + "\n"
    if output is None:
        print(encoded, end="")
        return
    path = Path(output)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(encoded)
    except FileExistsError as error:
        raise ResilienceError(f"refusing to overwrite {path}") from error
    except OSError as error:
        raise ResilienceError(f"cannot write {path}: {error}") from error


def _write_bytes(payload: bytes, output: str) -> None:
    path = Path(output)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
    except FileExistsError as error:
        raise ResilienceError(f"refusing to overwrite {path}") from error
    except OSError as error:
        raise ResilienceError(f"cannot write {path}: {error}") from error


def _output(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", help="write a new mode-0600 JSON file")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sippycup-resilience")
    areas = parser.add_subparsers(dest="area", required=True)

    isolation = areas.add_parser("isolation", help="cross-call contamination")
    isolation_actions = isolation.add_subparsers(dest="action", required=True)
    isolation_plan = isolation_actions.add_parser("plan")
    isolation_plan.add_argument("--calls", type=int, default=64)
    isolation_plan.add_argument("--seed", default="sippycup-isolation-v1")
    _output(isolation_plan)
    isolation_analyze = isolation_actions.add_parser("analyze")
    isolation_analyze.add_argument("plan")
    isolation_analyze.add_argument("observations")
    _output(isolation_analyze)
    isolation_demo = isolation_actions.add_parser("demo")
    isolation_demo.add_argument("--calls", type=int, default=64)
    _output(isolation_demo)
    isolation_render = isolation_actions.add_parser("render")
    isolation_render.add_argument("plan")
    isolation_render.add_argument("call_id")
    isolation_render.add_argument("--sample-rate", type=int, default=8000)
    isolation_render.add_argument("--output", required=True)
    isolation_decode = isolation_actions.add_parser("decode")
    isolation_decode.add_argument("pcm")
    isolation_decode.add_argument("--sample-rate", type=int, default=8000)
    _output(isolation_decode)

    lifecycle = areas.add_parser("lifecycle", help="settled resource leaks")
    lifecycle_actions = lifecycle.add_subparsers(dest="action", required=True)
    lifecycle_simulate = lifecycle_actions.add_parser("simulate")
    lifecycle_simulate.add_argument("--cycles", type=int, default=1000)
    lifecycle_simulate.add_argument(
        "--leak", choices=("sessions", "sockets", "tasks", "memoryBytes")
    )
    _output(lifecycle_simulate)
    lifecycle_analyze = lifecycle_actions.add_parser("analyze")
    lifecycle_analyze.add_argument("snapshots")
    lifecycle_analyze.add_argument(
        "--memory-tolerance-bytes", type=int, default=1_048_576
    )
    _output(lifecycle_analyze)

    overload = areas.add_parser("overload", help="retry and fairness behavior")
    overload_actions = overload.add_subparsers(dest="action", required=True)
    overload_demo = overload_actions.add_parser("demo")
    overload_demo.add_argument("--clients", type=int, default=2)
    overload_demo.add_argument("--requests-per-client", type=int, default=4)
    overload_demo.add_argument("--accepted-per-client", type=int, default=2)
    _output(overload_demo)
    overload_analyze = overload_actions.add_parser("analyze")
    overload_analyze.add_argument("transactions")
    overload_analyze.add_argument("--max-attempts", type=int, default=2)
    overload_analyze.add_argument(
        "--fairness-tolerance-percent", type=int, default=20
    )
    _output(overload_analyze)

    secure = areas.add_parser("secure-media", help="TLS/SRTP policy")
    secure_actions = secure.add_subparsers(dest="action", required=True)
    secure_demo = secure_actions.add_parser("demo")
    secure_demo.add_argument(
        "--profile", choices=("sip-tls", "srtp", "dtls-srtp"), default="srtp"
    )
    _output(secure_demo)
    secure_check = secure_actions.add_parser("check")
    secure_check.add_argument("policy")
    secure_check.add_argument("observation")
    _output(secure_check)

    migration = areas.add_parser("migration", help="RTP tuple ownership")
    migration_actions = migration.add_subparsers(dest="action", required=True)
    migration_demo = migration_actions.add_parser("demo")
    migration_demo.add_argument(
        "--mode", choices=("strict", "symmetric-rtp", "ice"), default="strict"
    )
    _output(migration_demo)
    migration_check = migration_actions.add_parser("check")
    migration_check.add_argument("policy")
    migration_check.add_argument("packets")
    _output(migration_check)
    return parser


def run(arguments: argparse.Namespace) -> tuple[Any, int]:
    if arguments.area == "isolation":
        if arguments.action == "plan":
            plan = plan_isolation(arguments.calls, arguments.seed)
            return plan, 0
        if arguments.action == "demo":
            plan = plan_isolation(arguments.calls)
            report = analyze_isolation(plan, clean_observations(plan))
            return report, 0
        if arguments.action == "render":
            plan = load_json(Path(arguments.plan))
            clean_observations(plan)
            matches = [
                item for item in plan["calls"] if item["callId"] == arguments.call_id
            ]
            if len(matches) != 1:
                raise ResilienceError("call_id is not present exactly once in plan")
            samples = render_watermark(matches[0]["marker"], arguments.sample_rate)
            payload = b"".join(struct.pack("<h", item) for item in samples)
            _write_bytes(payload, arguments.output)
            return {
                "apiVersion": "sippycup.dev/watermark-render/v1",
                "callId": arguments.call_id,
                "sampleRateHz": arguments.sample_rate,
                "samples": len(samples),
                "bytes": len(payload),
                "output": str(Path(arguments.output)),
            }, 0
        if arguments.action == "decode":
            path = Path(arguments.pcm)
            rate = bounded_int(arguments.sample_rate, "sampleRateHz", 8000, 48000)
            expected_samples = WATERMARK_BITS * rate * SYMBOL_MS // 1000
            expected_bytes = expected_samples * 2
            try:
                payload = path.read_bytes()
            except OSError as error:
                raise ResilienceError(f"cannot read {path}: {error}") from error
            if len(payload) != expected_bytes:
                raise ResilienceError(
                    f"watermark PCM must contain exactly {expected_bytes} bytes"
                )
            samples = tuple(item[0] for item in struct.iter_unpack("<h", payload))
            marker = decode_watermark(samples, rate)
            return {
                "apiVersion": "sippycup.dev/watermark-decode/v1",
                "marker": marker,
                "ambiguousSymbols": marker.count("?"),
                "sampleRateHz": rate,
            }, 0 if "?" not in marker else 1
        report = analyze_isolation(
            load_json(Path(arguments.plan)),
            load_json(Path(arguments.observations)),
        )
        return report, 0 if report["status"] == "pass" else 1
    if arguments.area == "lifecycle":
        if arguments.action == "simulate":
            return synthetic_snapshots(arguments.cycles, arguments.leak), 0
        report = analyze_lifecycle(
            load_json(Path(arguments.snapshots)),
            memory_tolerance_bytes=arguments.memory_tolerance_bytes,
        )
        return report, 0 if report["status"] == "pass" else 1
    if arguments.area == "overload":
        if arguments.action == "demo":
            transactions = synthetic_transactions(
                arguments.clients,
                arguments.requests_per_client,
                arguments.accepted_per_client,
            )
            return analyze_overload(transactions), 0
        report = analyze_overload(
            load_json(Path(arguments.transactions)),
            max_attempts=arguments.max_attempts,
            fairness_tolerance_percent=arguments.fairness_tolerance_percent,
        )
        return report, 0 if report["status"] == "pass" else 1
    if arguments.area == "secure-media":
        if arguments.action == "demo":
            policy = secure_policy(arguments.profile)
            return analyze_secure_media(policy, clean_observation(arguments.profile)), 0
        report = analyze_secure_media(
            load_json(Path(arguments.policy)),
            load_json(Path(arguments.observation)),
        )
        return report, 0 if report["status"] == "pass" else 1
    if arguments.area == "migration":
        if arguments.action == "demo":
            policy = migration_policy(arguments.mode)
            packet = {
                "source": policy["initialTuple"],
                "ssrc": policy["ssrc"],
                "authenticated": True,
                "consentFresh": True,
                "afterTeardown": False,
            }
            return analyze_migration(policy, [packet]), 0
        report = analyze_migration(
            load_json(Path(arguments.policy)),
            load_json(Path(arguments.packets)),
        )
        return report, 0 if report["status"] == "pass" else 1
    raise ResilienceError("unsupported command")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        report, status = run(arguments)
        output = (
            None
            if arguments.area == "isolation" and arguments.action == "render"
            else arguments.output
        )
        _write(report, output)
        return status
    except ResilienceError as error:
        parser.exit(2, f"sippycup-resilience: error: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
