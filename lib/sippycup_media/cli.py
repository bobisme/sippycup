"""Command-line interface for bounded canary RTP sending."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .analysis import MediaAnalysisError, analyze_payload, load_payload
from .rtp import (
    MediaNetworkError,
    MediaSessionError,
    build_packet_plan,
    load_session,
    packet_plan_document,
    send_packet_plan,
)


def _send_destinations(plan: object) -> list[tuple[str, int]]:
    """Every (address, port) the plan would send to, in revision order."""
    return [
        (revision.destination_address, revision.destination_port)
        for revision in plan.session.revisions  # type: ignore[attr-defined]
    ]


def _planned_seconds(plan: object) -> float:
    """The latest possible end of the send (rtp.send_packet_plan's global deadline)."""
    packets = plan.packets  # type: ignore[attr-defined]
    final_ms = packets[-1].scheduled_ms if packets else 0
    return (final_ms + plan.session.echo_timeout_ms + 20) / 1000  # type: ignore[attr-defined]


def _human(value: dict[str, object], dry_run: bool) -> str:
    if dry_run:
        packets = value["packets"]
        return (
            f"media plan: {value['codec']} {value['direction']}; "
            f"{len(packets)} packets; no traffic sent"
        )
    timing = value["timing"]
    return (
        f"media send passed: {value['sentPackets']} sent, "
        f"{value['echoedAudioPackets']} audio echoes, "
        f"{value['echoedTelephoneEventPackets']} RFC4733 echoes; "
        f"max RTT {timing['maxRoundTripMs']} ms"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sippycup media")
    subcommands = parser.add_subparsers(dest="command", required=True)
    send = subcommands.add_parser("send", help="send negotiated canary RTP")
    send.add_argument("session", type=Path)
    send.add_argument("--dry-run", action="store_true")
    send.add_argument(
        "--profile",
        type=Path,
        help=(
            "approved target profile: the remote SDP destination must be an approved "
            "address or media network, within the media ports and the approval window. "
            "Required for any destination that is not loopback"
        ),
    )
    send.add_argument(
        "--require-profile",
        action="store_true",
        help="refuse to run without --profile (also SIPPYCUP_REQUIRE_PROFILE=1)",
    )
    send.add_argument("--format", choices=("human", "json"), default="human")
    analyze = subcommands.add_parser(
        "analyze", help="measure deterministic canary media"
    )
    analyze.add_argument("payload", type=Path)
    analyze.add_argument("--codec", required=True)
    analyze.add_argument(
        "--direction",
        required=True,
        choices=("caller_to_callee", "callee_to_caller"),
    )
    analyze.add_argument("--encrypted", action="store_true")
    analyze.add_argument("--send-start-ms", type=float)
    analyze.add_argument("--recording-start-ms", type=float)
    analyze.add_argument("--format", choices=("human", "json"), default="human")
    arguments = parser.parse_args(argv)
    if arguments.command == "analyze":
        try:
            result = analyze_payload(
                load_payload(arguments.payload),
                arguments.codec,
                arguments.direction,
                encrypted=arguments.encrypted,
                send_start_ms=arguments.send_start_ms,
                recording_start_ms=arguments.recording_start_ms,
            )
        except MediaAnalysisError as error:
            print(f"media analysis error: {error}", file=sys.stderr)
            return 2
        if arguments.format == "json":
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        elif result["measurementStatus"] == "not_measurable":
            print(
                f"media not measurable: {result['reason']} "
                f"({result['codec']})"
            )
        else:
            metrics = result["metrics"]
            round_trip = metrics["roundTripLatencyMs"]
            round_trip_text = (
                f"{round_trip['value']}±"
                f"{result['uncertainty']['roundTripMs']} ms"
                if round_trip["state"] == "known"
                else "not synchronized"
            )
            print(
                "media measured: "
                f"markers={sum(item['present'] for item in result['markers'])}/"
                f"{len(result['markers'])}; "
                f"dropouts={len(metrics['dropouts']['value'])}; "
                f"round-trip={round_trip_text}"
            )
        return 4 if result["measurementStatus"] == "not_measurable" else 0
    # The scope code is first-party but lives in the workbench package.
    from sippycup_workbench import binding

    try:
        session = load_session(arguments.session)
        plan = build_packet_plan(session)
        # Scope decision: after the network-free plan, before any socket.
        scope = binding.media_scope(
            _send_destinations(plan),
            profile=arguments.profile,
            planned_seconds=_planned_seconds(plan),
            require=binding.require_profile(arguments.require_profile),
        )
        result = (
            packet_plan_document(plan)
            if arguments.dry_run
            else send_packet_plan(plan)
        )
    except binding.BindingError as error:
        print(error.render("media send"), file=sys.stderr)
        return 2
    except MediaSessionError as error:
        print(f"media session error: {error}", file=sys.stderr)
        return 2
    except MediaNetworkError as error:
        print(f"media network error: {error}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("media send interrupted", file=sys.stderr)
        return 130
    if arguments.format == "json":
        print(json.dumps({**result, "scope": scope}, sort_keys=True, separators=(",", ":")))
    else:
        print(binding.scope_line(scope))
        print(_human(result, arguments.dry_run))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
