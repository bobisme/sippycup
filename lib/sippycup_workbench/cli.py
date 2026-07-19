"""Operator-facing Sippycup workbench CLI."""

from __future__ import annotations

import argparse
import ipaddress
import json
import shlex
import sys
from pathlib import Path
from typing import Any, Sequence

from .advisor import assess
from .doctor import diagnose
from .journal import (
    JournalError,
    KINDS as JOURNAL_KINDS,
    MAX_DETAIL_CHARS,
    MAX_SUMMARY_CHARS,
    append as append_journal,
    initialize as initialize_journal,
    render as render_journal,
    verify as verify_journal,
    write_rendered,
)
from .profile import ProfileError, default_profile, load_profile, rehearse, write_profile
from .triage import TriageError, analyze

EXPLANATIONS = {
    "capture.nonempty": (
        "Capture contains packets",
        "A zero-packet capture cannot establish signaling or media behavior. Check capture placement, interface, scope, and permissions.",
    ),
    "capture.sip_present": (
        "SIP was decoded",
        "TShark recognized at least one SIP frame. An unknown result may mean encrypted signaling, a nonstandard port, a truncated capture, or no SIP traffic.",
    ),
    "capture.media_present": (
        "RTP or RTCP was decoded",
        "Media was recognized in the capture. An unknown result is not proof of missing media: SRTP, dynamic ports, truncation, or dissector classification may prevent recognition.",
    ),
    "privacy.authorization_present": (
        "Authorization material is present",
        "The capture appears to contain SIP Authorization or Proxy-Authorization fields. Keep the original restricted and use the evidence privacy workflow before sharing.",
    ),
    "doctor.capture_capability": (
        "Live-capture capability is absent",
        "CAP_NET_RAW is not effective in this process. Use the project launcher, add only the documented capability, or capture on the host. Do not default to --privileged.",
    ),
    "doctor.tools_missing": (
        "Essential tools are missing",
        "The current environment is not the complete Sippycup image. Rebuild the image or run through bin/sippycup.",
    ),
}


def _emit(value: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(value, indent=2, sort_keys=True))
        return
    if "ready" in value:
        print(f"Ready: {'yes' if value['ready'] else 'no'}")
        for error in value.get("errors", []):
            print(f"ERROR: {error}")
        for warning in value.get("warnings", []):
            print(f"WARN:  {warning}")
        target = value.get("facts", {}).get("target")
        if target:
            print(f"Target: {target['host']}:{target['port']} ({target['transport']})")
        print("Network activity: none")
        return
    if value.get("schema_version") == "sippycup.dev/doctor/v1":
        print(f"Doctor: {'ready' if value['ok'] else 'needs attention'}")
        for problem in value["problems"]:
            print(f"{problem['code']}: {problem['message']}")
        missing_optional = [
            name
            for name in ("zeek", "visqol", "heplify")
            if not value["tools"][name]["available"]
        ]
        if missing_optional:
            print(f"Optional profiles not installed: {', '.join(missing_optional)}")
        print("Network activity: none")
        return
    if value.get("schema_version") == "sippycup.dev/triage/v1":
        metadata = value["metadata"]
        print(
            f"Capture: {metadata['packets']} packets, {metadata['bytes']} bytes, "
            f"{metadata['duration_seconds']:.6f}s"
        )
        for finding in value["findings"]:
            print(f"{finding['verdict'].upper():7} {finding['code']}: {finding['message']}")
        print("Network activity: none")
        return
    print(json.dumps(value, indent=2, sort_keys=True))


def _one_call_plan(profile_path: str) -> dict[str, Any]:
    document = load_profile(profile_path)
    rehearsal = rehearse(document)
    target = document.get("target", {})
    capture = document.get("capture", {})
    host = str(target.get("host", "TARGET"))
    port = str(target.get("port", 5060))
    transport = str(target.get("transport", "udp"))
    interface = str(capture.get("interface", "any"))
    output = str(capture.get("output", "work/call.pcap"))
    approved_addresses = target.get("approved_addresses", [])
    scope_arguments: list[str] = []
    if isinstance(approved_addresses, list):
        for address in approved_addresses:
            scope_arguments.extend(["--target", str(address)])
    if not scope_arguments:
        scope_arguments = ["--target", host]
    blocking_errors = list(rehearsal.errors)
    try:
        host_is_approved_literal = (
            str(ipaddress.ip_address(host)) == host and host in approved_addresses
        )
    except ValueError:
        host_is_approved_literal = False
    if not host_is_approved_literal:
        blocking_errors.append(
            "one-call v1 requires target.host itself to be one of the literal approved_addresses"
        )
    commands = [
        ["./bin/capture", *scope_arguments, "--interface", interface, "--output", output, "--dry-run"],
        ["./bin/preflight", host, port, transport],
        ["./bin/report", output],
        ["./bin/sippycup", "triage", output],
    ]
    return {
        "schema_version": "sippycup.dev/one-call-plan/v1",
        "ready": rehearsal.ready and host_is_approved_literal,
        "blocking_errors": blocking_errors,
        "network_activity": False,
        "steps": [
            {"name": "review_capture", "network_active": False, "argv": commands[0]},
            {"name": "start_scoped_capture", "network_active": True, "argv": commands[0][:-1]},
            {"name": "single_options_preflight", "network_active": True, "argv": commands[1]},
            {
                "name": "place_manual_softphone_call",
                "network_active": True,
                "instruction": "Place exactly one approved call, speak the agreed canary phrase, test both directions, then hang up.",
            },
            {"name": "stop_capture", "network_active": False, "instruction": "Press Ctrl-C in the capture terminal."},
            {"name": "offline_report", "network_active": False, "argv": commands[2]},
            {"name": "offline_triage", "network_active": False, "argv": commands[3]},
        ],
    }


def _render_plan(value: dict[str, Any]) -> None:
    print(f"One-call plan: {'READY' if value['ready'] else 'BLOCKED'}")
    for error in value["blocking_errors"]:
        print(f"BLOCK: {error}")
    for index, step in enumerate(value["steps"], 1):
        marker = "NETWORK" if step["network_active"] else "OFFLINE"
        print(f"{index}. [{marker}] {step['name']}")
        if "argv" in step:
            print(f"   {shlex.join(step['argv'])}")
        if "instruction" in step:
            print(f"   {step['instruction']}")
    print("This command sent no packets.")


def _render_status(value: dict[str, Any]) -> None:
    print(f"Engagement status: {value['overall'].upper()}")
    facts = value["facts"]
    journal = facts["journal"]
    profile = facts["profile"]
    torture = facts["torture"]
    print(
        "Checks: "
        f"journal={'ready' if journal['valid'] else 'blocked'}, "
        f"profile={'ready' if profile['ready'] else 'blocked'}, "
        f"torture-technical={torture['technicalGate']}, "
        f"torture-defaults={'reviewed' if torture['defaultsReviewed'] else 'pending'}"
    )
    for blocker in value["blockers"]:
        print(f"BLOCK: {blocker}")
    for warning in value["warnings"]:
        print(f"WARN:  {warning}")
    print("Next safe actions:")
    if not value["nextActions"]:
        print("  No offline action is currently recommended.")
    for index, action in enumerate(value["nextActions"], 1):
        print(f"{index}. {action['title']}")
        print(f"   {action['reason']}")
        if "argv" in action:
            print(f"   {shlex.join(action['argv'])}")
        if "instruction" in action:
            print(f"   {action['instruction']}")
    print("Network activity: none")


def _read_text_argument(
    inline: str | None,
    source_name: str | None,
    *,
    label: str,
    maximum: int,
) -> str:
    if inline is not None:
        return inline
    if source_name is None:
        return ""
    try:
        if source_name == "-":
            value = sys.stdin.read(maximum + 1)
        else:
            with Path(source_name).open("r", encoding="utf-8") as source:
                value = source.read(maximum + 1)
    except OSError as exc:
        raise JournalError(f"cannot read {label}: {exc}") from exc
    if len(value) > maximum:
        raise JournalError(f"{label} exceeds {maximum} characters")
    return value.rstrip("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sippycup", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="run zero-network environment checks")
    doctor.add_argument("--workdir", default="/work" if Path("/work").is_dir() else "work")
    doctor.add_argument("--format", choices=("human", "json"), default="human")

    init = sub.add_parser("init", help="create a safe pending target profile")
    init.add_argument("output")
    init.add_argument("--name", default="ferivox-staging")
    init.add_argument("--host", default="staging.example.invalid")
    init.add_argument("--port", type=int, default=5060)
    init.add_argument("--transport", choices=("udp", "tcp", "tls"), default="udp")
    init.add_argument("--approved-by", default="Quad")
    init.add_argument("--force", action="store_true")

    rehearsal = sub.add_parser("rehearse", help="compile readiness without network traffic")
    rehearsal.add_argument("profile")
    rehearsal.add_argument("--format", choices=("human", "json"), default="human")

    one_call = sub.add_parser("one-call", help="compile a guided one-call workflow")
    one_call.add_argument("profile")
    one_call.add_argument("--format", choices=("human", "json"), default="human")

    triage = sub.add_parser("triage", help="run bounded read-only capture triage")
    triage.add_argument("capture")
    triage.add_argument("--format", choices=("human", "json"), default="human")

    explain = sub.add_parser("explain", help="explain a finding code")
    explain.add_argument("code", choices=sorted(EXPLANATIONS))
    explain.add_argument("--format", choices=("human", "json"), default="human")

    journal = sub.add_parser(
        "journal", help="maintain a hash-chained assessment journal"
    )
    journal_commands = journal.add_subparsers(
        dest="journal_command", required=True
    )
    journal_init = journal_commands.add_parser(
        "init", help="create a private engagement journal"
    )
    journal_init.add_argument("directory")
    journal_init.add_argument("--title", default="Ferivox security assessment")
    journal_init.add_argument("--owner", default="Quad")

    journal_add = journal_commands.add_parser(
        "add", help="append a human assessment record"
    )
    journal_add.add_argument("directory")
    journal_add.add_argument("--kind", choices=JOURNAL_KINDS, required=True)
    summary = journal_add.add_mutually_exclusive_group(required=True)
    summary.add_argument("--summary")
    summary.add_argument(
        "--summary-file",
        help="read the summary from a UTF-8 file, or - for standard input",
    )
    detail = journal_add.add_mutually_exclusive_group()
    detail.add_argument("--detail")
    detail.add_argument(
        "--detail-file",
        help="read detail from a UTF-8 file, or - for standard input",
    )
    journal_add.add_argument("--evidence", action="append", default=[])
    journal_add.add_argument("--tag", action="append", default=[])
    journal_add.add_argument("--format", choices=("human", "json"), default="human")

    journal_verify = journal_commands.add_parser(
        "verify", help="verify journal structure and hash chain"
    )
    journal_verify.add_argument("directory")
    journal_verify.add_argument("--format", choices=("human", "json"), default="human")

    journal_render = journal_commands.add_parser(
        "render", help="render an internal draft or safe publication outline"
    )
    journal_render.add_argument("directory")
    journal_render.add_argument("--audience", choices=("internal", "public"), required=True)
    journal_render.add_argument("--output", required=True)

    status = sub.add_parser(
        "status", help="show offline engagement readiness and next safe actions"
    )
    status.add_argument("engagement")
    status.add_argument("--profile")
    status.add_argument("--torture-review")
    status.add_argument("--format", choices=("human", "json"), default="human")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "doctor":
            value = diagnose(args.workdir)
            _emit(value, args.format)
            return 0 if value["ok"] else 1
        if args.command == "init":
            profile = default_profile(
                name=args.name,
                host=args.host,
                port=args.port,
                transport=args.transport,
                approved_by=args.approved_by,
            )
            write_profile(args.output, profile, force=args.force)
            print(f"Created pending profile: {args.output}")
            print("No approval, credentials, or resolved addresses were invented.")
            return 0
        if args.command == "rehearse":
            value = rehearse(load_profile(args.profile)).as_dict()
            _emit(value, args.format)
            return 0 if value["ready"] else 1
        if args.command == "one-call":
            value = _one_call_plan(args.profile)
            if args.format == "json":
                _emit(value, "json")
            else:
                _render_plan(value)
            return 0 if value["ready"] else 1
        if args.command == "triage":
            value = analyze(args.capture)
            _emit(value, args.format)
            return 1 if any(item["verdict"] == "fail" for item in value["findings"]) else 0
        if args.command == "explain":
            title, detail = EXPLANATIONS[args.code]
            value = {"code": args.code, "title": title, "explanation": detail}
            if args.format == "json":
                _emit(value, "json")
            else:
                print(f"{args.code}: {title}\n{detail}")
            return 0
        if args.command == "journal":
            if args.journal_command == "init":
                value = initialize_journal(
                    args.directory,
                    title=args.title,
                    owner=args.owner,
                )
                print(f"Created private engagement journal: {args.directory}")
                print(f"Owner: {value['owner']}")
                print("Network activity: none")
                return 0
            if args.journal_command == "add":
                summary = _read_text_argument(
                    args.summary,
                    args.summary_file,
                    label="summary",
                    maximum=MAX_SUMMARY_CHARS,
                )
                detail = _read_text_argument(
                    args.detail,
                    args.detail_file,
                    label="detail",
                    maximum=MAX_DETAIL_CHARS,
                )
                value = append_journal(
                    args.directory,
                    kind=args.kind,
                    summary=summary,
                    detail=detail,
                    evidence=args.evidence,
                    tags=args.tag,
                )
                if args.format == "json":
                    _emit(
                        {
                            "apiVersion": "sippycup.dev/journal-append/v1",
                            "sequence": value["sequence"],
                            "entrySha256": value["entrySha256"],
                            "networkActivity": False,
                        },
                        "json",
                    )
                else:
                    print(
                        f"Appended journal entry {value['sequence']}: "
                        f"{value['entrySha256']}"
                    )
                    print("Network activity: none")
                return 0
            if args.journal_command == "verify":
                value = verify_journal(args.directory).as_dict()
                if args.format == "json":
                    _emit(value, "json")
                else:
                    print(
                        f"Journal: valid ({value['entryCount']} entries, "
                        f"final SHA-256: {value['finalSha256'] or 'empty'})"
                    )
                    if value["missingEvidence"]:
                        print(
                            "Missing or unsafe evidence references: "
                            + ", ".join(value["missingEvidence"])
                        )
                    print("Network activity: none")
                return 0
            if args.journal_command == "render":
                content = render_journal(
                    args.directory, audience=args.audience
                )
                write_rendered(args.output, content)
                print(f"Wrote {args.audience} draft: {args.output}")
                print("Network activity: none")
                return 0
        if args.command == "status":
            value = assess(
                args.engagement,
                profile_path=args.profile,
                torture_review_path=args.torture_review,
            )
            if args.format == "json":
                _emit(value, "json")
            else:
                _render_status(value)
            return 0 if value["overall"] == "ready-for-human-review" else 1
    except (JournalError, ProfileError, TriageError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2
