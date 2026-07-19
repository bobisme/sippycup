"""CLI for read-only chaos capability and topology planning."""

from __future__ import annotations

import argparse
import json
import signal
import sys
from pathlib import Path
from typing import Sequence

from .profiles import ProfileError, compile_profile, load_profile
from .lifecycle import (
    ChaosLifecycle,
    LifecycleError,
    load_json_document,
)
from .topology import (
    CapabilitySnapshot,
    Direction,
    TopologyError,
    TopologyKind,
    TopologyRequest,
    collect_network_snapshot,
    detect_capabilities,
    plan_topology,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sippycup chaos")
    commands = parser.add_subparsers(dest="command", required=True)
    probe = commands.add_parser(
        "capabilities", help="print a read-only capability snapshot"
    )
    probe.add_argument("--output", type=Path)
    plan = commands.add_parser(
        "topology-plan", help="render a no-change disposable topology plan"
    )
    plan.add_argument("--target", action="append", required=True, dest="targets")
    plan.add_argument(
        "--direction",
        choices=[item.value for item in Direction],
        default=Direction.BIDIRECTIONAL.value,
    )
    plan.add_argument(
        "--topology",
        choices=[item.value for item in TopologyKind],
        default=TopologyKind.DISPOSABLE_ROUTER.value,
    )
    plan.add_argument("--namespace-prefix", default="sippycup-chaos")
    plan.add_argument("--dangerous-confirmation")
    plan.add_argument("--host-interface")
    plan.add_argument("--require-mtu", action="store_true")
    plan.add_argument(
        "--capabilities",
        type=Path,
        help="reviewed capability JSON from `sippycup chaos capabilities`",
    )
    plan.add_argument("--output", type=Path)
    profile = commands.add_parser(
        "profile-plan",
        help="compile a reviewed impairment profile against a frozen topology plan",
    )
    profile.add_argument("topology_plan", type=Path)
    profile.add_argument("profile", type=Path)
    profile.add_argument("--output", type=Path)
    run = commands.add_parser(
        "run",
        help="apply a reviewed chaos plan, own one traffic child, and prove cleanup",
    )
    run.add_argument("topology_plan", type=Path)
    run.add_argument("impairment_plan", type=Path)
    run.add_argument(
        "--observation",
        action="append",
        default=[],
        metavar="DIRECTION=BEFORE,AFTER",
        help="paired classic PCAPs captured before/after an impairment point",
    )
    run.add_argument("--report", type=Path, required=True)
    run.add_argument("traffic_command", nargs=argparse.REMAINDER)
    return parser


def _write(document: dict, path: Path | None) -> None:
    rendered = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if path is None:
        sys.stdout.write(rendered)
        return
    try:
        with path.open("x", encoding="utf-8") as destination:
            destination.write(rendered)
    except OSError as error:
        raise TopologyError(f"cannot exclusively create output: {error}") from error


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "capabilities":
            _write(detect_capabilities().to_dict(), args.output)
            return 0
        if args.command == "profile-plan":
            try:
                if args.topology_plan.stat().st_size > 4 * 1024 * 1024:
                    raise ProfileError("topology plan exceeds 4 MiB")
                topology = json.loads(
                    args.topology_plan.read_text(encoding="utf-8")
                )
            except (OSError, json.JSONDecodeError) as error:
                raise ProfileError(f"cannot read topology plan: {error}") from error
            profile, source_sha256 = load_profile(args.profile)
            _write(
                compile_profile(
                    topology, profile, source_sha256=source_sha256
                ),
                args.output,
            )
            return 0
        if args.command == "run":
            observations = {}
            for value in args.observation:
                try:
                    direction, paths = value.split("=", 1)
                    before, after = paths.split(",", 1)
                except ValueError as error:
                    raise LifecycleError(
                        "--observation must be DIRECTION=BEFORE,AFTER"
                    ) from error
                if (
                    direction not in {"egress", "ingress"}
                    or direction in observations
                    or not before
                    or not after
                ):
                    raise LifecycleError(
                        "observation direction must be unique egress or ingress"
                    )
                observations[direction] = (Path(before), Path(after))
            traffic_command = list(args.traffic_command)
            if traffic_command and traffic_command[0] == "--":
                traffic_command.pop(0)
            topology = load_json_document(args.topology_plan, "topology plan")
            impairment = load_json_document(
                args.impairment_plan, "impairment plan"
            )
            lifecycle = ChaosLifecycle(topology, impairment)
            previous = {}

            def cancel(signum: int, _frame: object) -> None:
                lifecycle.cancel(signum)

            for signum in (signal.SIGINT, signal.SIGTERM):
                previous[signum] = signal.signal(signum, cancel)
            try:
                report = lifecycle.run(
                    traffic_command, observations=observations
                )
            finally:
                for signum, handler in previous.items():
                    signal.signal(signum, handler)
            _write(report, args.report)
            return int(report["exitCode"])
        if args.capabilities is None:
            capabilities = detect_capabilities()
        else:
            try:
                if args.capabilities.stat().st_size > 1024 * 1024:
                    raise TopologyError("capability snapshot exceeds 1 MiB")
                capabilities = CapabilitySnapshot.from_dict(
                    json.loads(args.capabilities.read_text(encoding="utf-8"))
                )
            except (OSError, json.JSONDecodeError) as error:
                raise TopologyError(f"cannot read capability snapshot: {error}") from error
        prefix = args.namespace_prefix
        namespace_names = (
            (
                f"{prefix}-test",
                f"{prefix}-impair",
                f"{prefix}-uplink",
            )
            if TopologyKind(args.topology) is TopologyKind.DISPOSABLE_ROUTER
            else ()
        )
        snapshot = collect_network_snapshot(namespace_names)
        document = plan_topology(
            TopologyRequest(
                targets=tuple(args.targets),
                direction=Direction(args.direction),
                topology=TopologyKind(args.topology),
                namespace_prefix=prefix,
                dangerous_confirmation=args.dangerous_confirmation,
                require_mtu=args.require_mtu,
                host_interface=args.host_interface,
            ),
            capabilities,
            snapshot,
        )
        _write(document, args.output)
        return 0
    except (TopologyError, ProfileError, LifecycleError) as error:
        print(f"sippycup chaos: error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
