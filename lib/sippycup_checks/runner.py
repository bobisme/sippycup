"""``./bin/sippycup checks``: list, explain, plan, and run the reviewed checks.

Default deny: a check sends something only when the target profile passes
``rehearse`` right now, names ``target.host`` among its literal approved
addresses, AND lists the check under ``security_checks.approved``, and the
sum of the declared request bounds fits ``security_checks.max_requests``.
``list``, ``explain``, ``plan``, and ``run --dry-run`` are network-free.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, MutableMapping, Sequence

from sippycup_workbench.profile import ProfileError, host_is_approved_literal, load_profile, rehearse

from . import FINDINGS_VERSION, catalog
from .budget import Budget, BudgetExceeded, Stopped
from .checks import FINDING_STOPS, CheckResult, Context, IMPLEMENTATIONS
from .sip import Endpoint
from . import tlsprobe

RESULT_VERSION = "sippycup.dev/checks-result/v1"
PLAN_VERSION = "sippycup.dev/checks-plan/v1"
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_REFUSED = 2
EXIT_RUN_ERROR = 3
DEFAULT_INTERVAL = 1.0
TRANSACTION_TIMEOUT = 4.0
INVITE_TIMEOUT = 8.0
CAPTURE_READY_TIMEOUT = 5.0
CAPTURE_TAIL_SECONDS = 0.5


class ChecksError(ValueError):
    """The run cannot start; nothing has been sent."""


# -- planning (network-free) ---------------------------------------------------------

def _section(document: dict[str, Any]) -> dict[str, Any] | None:
    value = document.get("security_checks")
    return value if isinstance(value, dict) else None


def interval_for(document: dict[str, Any]) -> float:
    limits = document.get("limits") if isinstance(document.get("limits"), dict) else {}
    rate = limits.get("max_calls_per_second")
    if type(rate) is int and rate >= 1:
        return max(DEFAULT_INTERVAL, 1.0 / rate)
    return DEFAULT_INTERVAL


def _missing_needs(spec: catalog.CheckSpec, document: dict[str, Any], section: dict[str, Any],
                   password_available: bool | None) -> str | None:
    target = document.get("target") if isinstance(document.get("target"), dict) else {}
    features = document.get("features") if isinstance(document.get("features"), dict) else {}
    transport = target.get("transport")
    for need in spec.needs:
        if need == "tls" and transport != "tls":
            return "needs a tls target; this profile's transport is " + str(transport)
        if need == "account" and not section.get("account"):
            return "needs security_checks.account (the reviewed account name)"
        if need == "destination" and not section.get("destination"):
            return "needs security_checks.destination (the reviewed destination)"
        if need == "cleartext_endpoints" and not catalog.cleartext_endpoints(section):
            return "needs security_checks.cleartext_endpoints (approved cleartext ports)"
        if need == "srtp" and not features.get("srtp"):
            return "applies only when features.srtp is true"
        if need == "password" and password_available is False:
            return "needs the account password via --secret-env or --secret-file"
    if transport not in spec.transports and not spec.per_endpoint:
        return f"does not run over {transport}"
    return None


def build_plan(
    document: dict[str, Any],
    *,
    now: datetime,
    only: Sequence[str] = (),
    password_available: bool | None = None,
    work_root: Path | None = None,
) -> dict[str, Any]:
    rehearsal = rehearse(document, now=now, work_root=work_root)
    blocking = list(rehearsal.errors)
    if not host_is_approved_literal(document):
        blocking.append("checks require target.host itself to be one of the literal approved_addresses")
    section = _section(document)
    approved: list[str] = []
    if section is None:
        blocking.append("no security checks are approved: the profile has no security_checks section")
        section = {}
    else:
        approved = [item for item in section.get("approved") or [] if isinstance(item, str)]
        if not approved:
            blocking.append("no security checks are approved: security_checks.approved is empty")
    for item in only:
        if item not in catalog.ids():
            blocking.append(f"--only names an unknown check: {item}")
        elif item not in approved:
            blocking.append(f"--only names {item}, which this profile does not approve")
    entries: list[dict[str, Any]] = []
    total = 0
    invites = 0
    interval = interval_for(document)
    seconds = 10.0
    for spec in catalog.CHECKS:
        entry: dict[str, Any] = {
            "id": spec.id, "title": spec.title, "impact": spec.impact, "sends": spec.sends,
            "maxRequests": 0, "status": "will-run", "reason": None,
        }
        if spec.state == "planned":
            entry.update(status="skipped", reason="planned; not runnable in this version")
        elif spec.id not in approved:
            entry.update(status="not-approved", reason="not listed in security_checks.approved")
        elif only and spec.id not in only:
            entry.update(status="skipped", reason="not selected with --only")
        else:
            missing = _missing_needs(spec, document, section, password_available)
            if missing:
                entry.update(status="skipped", reason=missing)
        if entry["status"] == "will-run":
            bound = catalog.declared_bound(spec, section)
            entry["maxRequests"] = bound
            total += bound
            invites += catalog.invites_declared(spec, section)
            per_request = TRANSACTION_TIMEOUT + interval
            seconds += bound * per_request + (INVITE_TIMEOUT if spec.invites else 0) * max(1, spec.invites)
            if spec.per_endpoint:
                entry["endpoints"] = [f"{item['transport']}/{item['port']}" for item in catalog.cleartext_endpoints(section)]
        entries.append(entry)
    runnable = [entry for entry in entries if entry["status"] == "will-run"]
    if approved and not runnable and not blocking:
        blocking.append("no approved check can run against this profile (see the skipped reasons)")
    maximum = section.get("max_requests") if isinstance(section, dict) else None
    if type(maximum) is int and total > maximum:
        blocking.append(
            f"the declared request bounds add up to {total}, above security_checks.max_requests {maximum}"
        )
    limits = document.get("limits") if isinstance(document.get("limits"), dict) else {}
    max_calls = limits.get("max_calls")
    if invites and type(max_calls) is int and invites > max_calls:
        blocking.append(
            f"the selected checks place up to {invites} INVITE attempts, above limits.max_calls {max_calls}"
        )
    valid_until = (rehearsal.facts.get("authorization") or {}).get("valid_until") if rehearsal.facts else None
    if not blocking and valid_until and now + timedelta(seconds=seconds) >= datetime.fromisoformat(valid_until):
        blocking.append(f"authorization expires before the run's latest possible end ({int(seconds)}s from now)")
    target = document.get("target") if isinstance(document.get("target"), dict) else {}
    return {
        "apiVersion": PLAN_VERSION,
        "ready": not blocking,
        "blockingErrors": blocking,
        "profile": document.get("name"),
        "target": {
            "address": target.get("host"),
            "port": target.get("port"),
            "transport": target.get("transport"),
            "serverName": target.get("tls_server_name") if target.get("transport") == "tls" else None,
        },
        "checks": entries,
        "totalMaxRequests": total,
        "maxRequests": maximum,
        "inviteAttempts": invites,
        "pacingSeconds": interval,
        "plannedSeconds": int(seconds),
        "validUntil": valid_until,
        "networkActivity": False,
    }


def render_plan(plan: dict[str, Any]) -> str:
    target = plan["target"]
    lines = [f"Security checks plan: {'READY' if plan['ready'] else 'BLOCKED'}"]
    for error in plan["blockingErrors"]:
        lines.append(f"BLOCK: {error}")
    name = f" (TLS name {target['serverName']})" if target.get("serverName") else ""
    lines.append(f"Target: {target['address']}:{target['port']}/{target['transport']}{name}")
    for entry in plan["checks"]:
        if entry["status"] == "will-run":
            lines.append(f"  RUN   {entry['id']:<26} <= {entry['maxRequests']} requests [{entry['impact']}]")
            lines.append(f"        sends: {entry['sends']}")
            if entry.get("endpoints"):
                lines.append(f"        endpoints: {', '.join(entry['endpoints'])}")
        else:
            label = "DENY " if entry["status"] == "not-approved" else "SKIP "
            lines.append(f"  {label} {entry['id']:<26} {entry['reason']}")
    lines.append(
        f"Total: at most {plan['totalMaxRequests']} requests (security_checks.max_requests "
        f"{plan['maxRequests']}), {plan['inviteAttempts']} INVITE attempts, new requests paced "
        f">= {plan['pacingSeconds']:g}s apart, never retried."
    )
    lines.append("This command sent no packets.")
    lines.append("Network activity: none")
    return "\n".join(lines) + "\n"


# -- execution ----------------------------------------------------------------------

@dataclass
class Dependencies:
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    environ: MutableMapping[str, str] = field(default_factory=lambda: os.environ)
    work_root: Path | None = None
    network_mode: str | None = None
    start_capture: Callable[..., Any] | None = None  # None: tcpdump via the guided-call helper
    capture: bool = True
    interval: float | None = None
    timeout: float = TRANSACTION_TIMEOUT
    invite_timeout: float = INVITE_TIMEOUT
    sleep: Callable[[float], None] = time.sleep
    monotonic: Callable[[], float] = time.monotonic
    openssl: str | None = field(default_factory=tlsprobe.openssl_path)
    install_signal_handlers: bool = True
    tcpdump: str = "tcpdump"
    implementations: dict[str, Callable[[Context], CheckResult]] | None = None


@dataclass
class RunOptions:
    profile: Path
    only: tuple[str, ...] = ()
    secret_env: str | None = None
    secret_file: Path | None = None
    run_root: Path | None = None
    dry_run: bool = False
    fail_on: str = "medium"
    continue_after_finding: bool = False


def _work_root(deps: Dependencies) -> Path:
    from sippycup_workbench.call import default_work_root

    return deps.work_root or default_work_root()


def _needs_password(plan: dict[str, Any]) -> bool:
    return any(
        entry["status"] == "will-run" and "password" in catalog.get(entry["id"]).needs
        for entry in plan["checks"]
    )


def capture_filter(addresses: Sequence[str]) -> str:
    hosts = " or ".join(f"host {ipaddress.ip_address(item)}" for item in addresses)
    return f"({hosts}) and (tcp or udp)"


def _utc(instant: datetime) -> str:
    return instant.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _write_json(path: Path, value: Any) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")


def severity_at_least(severity: str, threshold: str) -> bool:
    return catalog.SEVERITY_RANK[severity] >= catalog.SEVERITY_RANK[threshold]


def _redact(value: Any, secrets: Sequence[str]) -> Any:
    text = json.dumps(value)
    for secret in secrets:
        if secret:
            text = text.replace(json.dumps(secret)[1:-1], "<redacted>")
    return json.loads(text)


def execute(options: RunOptions, deps: Dependencies | None = None) -> tuple[int, dict[str, Any]]:
    deps = deps or Dependencies()
    work_root = _work_root(deps)
    document = load_profile(options.profile)
    if options.fail_on not in catalog.SEVERITIES:
        raise ChecksError("--fail-on must be info, low, medium, or high")
    password_source = bool(options.secret_env or options.secret_file)
    now = deps.now()
    plan = build_plan(document, now=now, only=options.only, password_available=password_source,
                      work_root=work_root)
    if options.dry_run:
        return (EXIT_OK if plan["ready"] else EXIT_REFUSED), plan
    if not plan["ready"]:
        return EXIT_REFUSED, {
            "apiVersion": RESULT_VERSION, "state": "blocked", "exitCode": EXIT_REFUSED,
            "blockingErrors": plan["blockingErrors"], "runDirectory": None, "requestsSent": 0,
            "networkActivity": "none",
        }

    from sippycup.integration import create_run_directory
    from sippycup_workbench.call import CallError, _display, _slug, _within, resolve_password

    target = document["target"]
    host, port, transport = target["host"], target["port"], target["transport"]
    approved_addresses = list(target["approved_addresses"])
    section = dict(document["security_checks"])
    server_name = target.get("tls_server_name") if transport == "tls" else None
    ca_data: bytes | None = None
    if transport == "tls" and target.get("tls_ca_file"):
        from sippycup.tls_trust import TrustError, read_ca

        try:
            ca_data, _digest = read_ca(target["tls_ca_file"], work_root)
        except TrustError as error:
            raise ChecksError(str(error)) from error
    password: str | None = None
    if password_source:
        shim = SimpleNamespace(secret_env=options.secret_env, secret_file=options.secret_file,
                               username=section.get("account") or "")
        try:
            password, _names = resolve_password(shim, deps.environ, work_root)
        except CallError as error:
            raise ChecksError(str(error)) from error
    secrets_list = [password] if password else []

    profile_path = Path(options.profile)
    run_root = Path(options.run_root) if options.run_root else profile_path.parent / "checks"
    if not _within(run_root, work_root):
        raise ChecksError(f"--run-root must be beneath the work directory ({work_root})")
    network_mode = deps.network_mode or deps.environ.get("SIPPYCUP_NETWORK_MODE", "unknown")
    old_umask = os.umask(0o077)
    run_dir = create_run_directory(run_root, _slug(str(document.get("name", "profile"))))
    timestamps: dict[str, str] = {"started": _utc(deps.now())}
    cancel = threading.Event()
    cancel_signal: list[int] = []
    previous: dict[int, Any] = {}
    capture: Any = None
    run_problem: str | None = None
    results: list[CheckResult] = []
    endpoint = Endpoint(host, port, transport, domain=server_name or host, server_name=server_name, ca_data=ca_data)

    def lapsed() -> str | None:
        if cancel.is_set():
            return "cancelled by signal"
        errors = rehearse(document, now=deps.now(), work_root=work_root).errors
        return f"authorization lapsed: {errors[0]}" if errors else None

    budget = Budget(
        total_limit=int(section["max_requests"]),
        interval=deps.interval if deps.interval is not None else plan["pacingSeconds"],
        monotonic=deps.monotonic,
        sleep=deps.sleep,
        should_stop=lambda: "cancelled by signal" if cancel.is_set() else None,
    )
    context = Context(endpoint=endpoint, section=section, budget=budget, password=password,
                      timeout=deps.timeout, invite_timeout=deps.invite_timeout, openssl=deps.openssl,
                      now=deps.now, monotonic=deps.monotonic)
    implementations = deps.implementations or IMPLEMENTATIONS
    scope = capture_filter(approved_addresses)
    interface = str((document.get("capture") or {}).get("interface", "any"))
    capture_path = run_dir / "capture.pcap"
    capture_argv = [deps.tcpdump, "-i", interface, "-U", "--immediate-mode", "-n", "-Z", "root",
                    "-w", str(capture_path), scope]

    def handle(signum: int, _frame: object) -> None:
        if not cancel_signal:
            cancel_signal.append(signum)
        cancel.set()

    try:
        if deps.install_signal_handlers:
            for signum in (signal.SIGINT, signal.SIGTERM):
                previous[signum] = signal.signal(signum, handle)
        _write_json(run_dir / "profile.json", document)
        local_networks: list[str] = []
        try:
            from sippycup_workbench.call import _local_address

            local = _local_address(host, port)  # UDP connect() sends nothing
            if local not in approved_addresses:
                local_networks.append(str(ipaddress.ip_network(local)))
        except OSError:
            pass
        _write_json(run_dir / "plan.json", {
            **plan,
            "authorization": {
                "networks": [str(ipaddress.ip_network(item)) for item in approved_addresses] + local_networks,
                "valid_until": plan.get("validUntil"),
            },
            "evidence": {"capture": deps.capture, "retainPayload": True},
            "captureFilter": scope if deps.capture else None,
            "networkMode": network_mode,
        })
        _write_json(run_dir / "timestamps.json", timestamps)
        if deps.capture:
            from sippycup.integration import _sanitized_environment
            from sippycup_workbench.call import _start_tcpdump

            starter = deps.start_capture or _start_tcpdump
            child_env = _sanitized_environment(secrets_list, [options.secret_env] if options.secret_env else [],
                                               environ=deps.environ)
            capture = starter(capture_argv, capture_path, run_dir / "capture.log", child_env)
            problem = capture.wait_ready(CAPTURE_READY_TIMEOUT, cancel)
            if problem is not None:
                run_problem = "capture-failed" if problem != "cancelled" else "cancelled"
            else:
                timestamps["capture_ready"] = _utc(deps.now())
        stop: str | None = run_problem and f"not run: {run_problem}"
        for entry in plan["checks"]:
            spec = catalog.get(entry["id"])
            if entry["status"] != "will-run":
                results.append(CheckResult(spec.id, entry["status"], entry["reason"]))
                continue
            if stop is None:
                stop = lapsed()
            if stop is None and capture is not None and not capture.alive():
                stop = "capture stopped"
            if stop is not None:
                results.append(CheckResult(spec.id, "skipped", f"not run: {stop}"))
                continue
            budget.begin(spec.id, entry["maxRequests"])
            try:
                result = implementations[spec.id](context)
            except BudgetExceeded as error:
                result = CheckResult(spec.id, "error", f"internal error: {error}", stop="request bound exceeded")
            except Stopped as error:
                result = CheckResult(spec.id, "error", f"stopped before sending: {error}", stop=str(error))
            except Exception as error:  # report honestly and stop everything
                text = f"{type(error).__name__}: {error}"
                for secret in secrets_list:
                    text = text.replace(secret, "<redacted>")
                result = CheckResult(spec.id, "error", f"internal error: {text}", stop="internal error")
            result.requests_sent = budget.end()
            results.append(result)
            if result.stop is not None:
                if result.stop in FINDING_STOPS and options.continue_after_finding:
                    continue
                stop = f"stopped after {spec.id}: {result.stop}"
    finally:
        if capture is not None:
            if capture.alive() and not cancel.is_set():
                time.sleep(CAPTURE_TAIL_SECONDS)
            capture.stop()
            timestamps["capture_stopped"] = _utc(deps.now())
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        os.umask(old_umask)

    timestamps["finished"] = _utc(deps.now())
    findings = [item for result in results for item in result.findings]
    findings.sort(key=lambda item: (-catalog.SEVERITY_RANK[item["severity"]], item["id"]))
    total = sum(result.requests_sent for result in results)
    findings_document = {
        "apiVersion": FINDINGS_VERSION,
        "target": {"address": host, "port": port, "transport": transport, "serverName": server_name},
        "generatedAt": timestamps["finished"],
        "checks": [
            {"id": result.id, "status": result.status, "requestsSent": result.requests_sent,
             "summary": result.summary}
            for result in results
        ],
        "findings": findings,
    }
    findings_document = _redact(findings_document, secrets_list)
    _write_json(run_dir / "findings.json", findings_document)
    _write_json(run_dir / "checks-detail.json", _redact(
        {"apiVersion": "sippycup.dev/checks-detail/v1",
         "checks": [{"id": result.id, "detail": result.detail, "stop": result.stop} for result in results]},
        secrets_list))
    transcript = _redact(context.transcript, secrets_list)
    descriptor = os.open(run_dir / "transcript.jsonl", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        for item in transcript:
            output.write(json.dumps(item, sort_keys=True) + "\n")
    errors = [result for result in results if result.status == "error"]
    at_threshold = [item for item in findings if severity_at_least(item["severity"], options.fail_on)]
    if cancel_signal or run_problem or errors:
        exit_code = EXIT_RUN_ERROR
    elif at_threshold:
        exit_code = EXIT_FINDINGS
    else:
        exit_code = EXIT_OK
    state = "cancelled" if cancel_signal else "failed" if run_problem else "completed"
    activity = (
        f"{total} requests to {host}" + (f" ({transport}" + (f", TLS name {server_name}" if server_name else "") + ")")
        + (" from a private network namespace" if network_mode == "private" else "")
        if total else "none"
    )
    value = {
        "apiVersion": RESULT_VERSION,
        "state": state,
        "exitCode": exit_code,
        "failOn": options.fail_on,
        "profile": document.get("name"),
        "runDirectory": _display(run_dir, work_root),
        "requestsSent": total,
        "requestLog": budget.log,
        "problem": run_problem,
        "findings": findings_document,
        "timestamps": timestamps,
        "networkMode": network_mode,
        "networkActivity": activity,
    }
    value = _redact(value, secrets_list)
    _write_json(run_dir / "timestamps.json", timestamps)
    _write_json(run_dir / "result.json", value)
    from sippycup.evidence import write_evidence_manifest

    try:
        manifest = write_evidence_manifest(run_dir)
        value["evidencePrivacy"] = manifest["privacy"]["status"]
    except Exception as error:  # evidence failure must not hide the verdict
        value["evidencePrivacy"] = f"manifest-error: {type(error).__name__}"
    return exit_code, value


def render_result(value: dict[str, Any]) -> str:
    if value.get("state") == "blocked":
        lines = ["Security checks: BLOCKED"]
        lines.extend(f"BLOCK: {error}" for error in value["blockingErrors"])
        lines.append("Nothing was started and no packets were sent.")
        lines.append("Network activity: none")
        return "\n".join(lines) + "\n"
    document = value["findings"]
    target = document["target"]
    lines = [
        f"Security checks: {value['state'].upper()} (exit {value['exitCode']}, fail-on {value['failOn']})",
        f"Target: {target['address']}:{target['port']}/{target['transport']}"
        + (f" (TLS name {target['serverName']})" if target.get("serverName") else ""),
        "",
        f"{'CHECK':<26} {'STATUS':<13} {'REQ':>3}  SUMMARY",
    ]
    for item in document["checks"]:
        summary = item["summary"] or ""
        if len(summary) > 100:
            summary = summary[:97] + "..."
        lines.append(f"{item['id']:<26} {item['status']:<13} {item['requestsSent']:>3}  {summary}")
    lines.append("")
    if document["findings"]:
        lines.append("Findings (most severe first):")
        for item in document["findings"]:
            lines.append(f"  [{item['severity'].upper()}] {item['id']}: {item['title']} (confidence {item['confidence']})")
            lines.append(f"      {item['summary']}")
            lines.append(f"      Fix: {item['remediation']}")
    else:
        lines.append("Findings: none")
    if value.get("problem"):
        lines.append(f"PROBLEM: {value['problem']}")
    lines.append(f"Run directory: {value['runDirectory']}")
    lines.append(f"Network activity: {value['requestsSent']} requests to {target['address']}"
                 if value["requestsSent"] else "Network activity: none")
    return "\n".join(lines) + "\n"


# -- CLI ------------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sippycup checks",
        description=(
            "A reviewed catalog of low-volume SIP edge security posture checks. Nothing is sent "
            "unless the target profile approves the check under security_checks.approved."
        ),
        epilog=(
            "list, explain, plan, and run --dry-run are network-free. run exit status: 0 no "
            "findings at or above --fail-on; 1 findings at or above it; 2 refused before any "
            "packet; 3 run error (a check errored, capture failed, or cancelled)."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)
    listing = sub.add_parser("list", help="list the catalog (network-free)")
    listing.add_argument("--format", choices=("human", "json"), default="human")
    explain = sub.add_parser("explain", help="explain one check (network-free)")
    explain.add_argument("id")
    explain.add_argument("--format", choices=("human", "json"), default="human")
    planning = sub.add_parser("plan", help="show exactly what a run would send (network-free)")
    planning.add_argument("profile", type=Path)
    planning.add_argument("--only", action="append", default=[], metavar="ID")
    planning.add_argument("--format", choices=("human", "json"), default="human")
    run = sub.add_parser("run", help="run the approved checks with scoped capture")
    run.add_argument("profile", type=Path)
    run.add_argument("--only", action="append", default=[], metavar="ID", help="run only this approved check (repeatable)")
    secret = run.add_mutually_exclusive_group()
    secret.add_argument("--secret-env", metavar="NAME", help="environment variable holding the account password")
    secret.add_argument("--secret-file", type=Path, help="mode-0600 password file beneath work/")
    run.add_argument("--run-root", type=Path, help="directory beneath work/ for the run directory")
    run.add_argument("--fail-on", choices=catalog.SEVERITIES, default="medium")
    run.add_argument("--continue-after-finding", action="store_true",
                     help="keep running active checks after an unauthenticated INVITE/REGISTER finding")
    run.add_argument("--dry-run", action="store_true", help="print the plan; send nothing")
    run.add_argument("--format", choices=("human", "json"), default="human")
    return parser


def main(argv: Sequence[str] | None = None, deps: Dependencies | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list":
        sys.stdout.write(catalog.render_list(args.format))
        return 0
    if args.command == "explain":
        try:
            sys.stdout.write(catalog.render_explain(args.id, args.format))
        except catalog.CatalogError as error:
            print(f"error: {error}; run ./bin/sippycup checks list", file=sys.stderr)
            return 2
        return 0
    if args.command == "plan":
        try:
            document = load_profile(args.profile)
        except ProfileError as error:
            print(f"error: {error}", file=sys.stderr)
            print("Network activity: none", file=sys.stderr if args.format == "json" else sys.stdout)
            return EXIT_REFUSED
        plan = build_plan(document, now=datetime.now(timezone.utc), only=tuple(args.only),
                          work_root=(deps.work_root if deps else None) or _work_root(Dependencies()))
        if args.format == "json":
            print(json.dumps(plan, indent=2, sort_keys=True))
        else:
            sys.stdout.write(render_plan(plan))
        return EXIT_OK if plan["ready"] else EXIT_REFUSED
    options = RunOptions(
        profile=args.profile, only=tuple(args.only), secret_env=args.secret_env,
        secret_file=args.secret_file, run_root=args.run_root, dry_run=args.dry_run,
        fail_on=args.fail_on, continue_after_finding=args.continue_after_finding,
    )
    try:
        code, value = execute(options, deps)
    except (ChecksError, ProfileError) as error:
        print(f"error: {error}", file=sys.stderr)
        print("Nothing was started and no packets were sent.", file=sys.stderr)
        print("Network activity: none", file=sys.stderr if args.format == "json" else sys.stdout)
        return EXIT_REFUSED
    if args.format == "json":
        print(json.dumps(value, indent=2, sort_keys=True))
    elif value.get("apiVersion") == PLAN_VERSION:
        sys.stdout.write(render_plan(value))
    else:
        sys.stdout.write(render_result(value))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
