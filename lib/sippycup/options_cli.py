"""Command-line front end for one bounded SIP OPTIONS transaction."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import sys
from typing import Sequence

from sippycup import options

EXIT_MET = 0
EXIT_NOT_MET = 1
EXIT_USAGE = 2
EXIT_NO_RESPONSE = 3
EXIT_UNREACHABLE = 4
EXIT_TLS = 5

RESULT_SCHEMA = "sippycup.dev/options-result/v1"
_HOST = re.compile(r"^[A-Za-z0-9._:\[\]%-]+$")

EPILOG = """\
Exit codes:
  0  a final response met the expectation (default: any 2xx)
  1  a final response arrived but did not meet the expectation
  2  usage error; nothing was sent
  3  no valid final response before the deadline (UDP silence, an ICMP
     port-unreachable, a TCP connect that never completed, a closed or
     malformed stream reply)
  4  connection refused, host or network unreachable, or name resolution failed
  5  TLS handshake or certificate verification failed

TLS verifies by default against --tls-server-name, or else against HOST as
given. --insecure disables verification and is always reported as
UNVERIFIED. The connection goes only to HOST (resolved once when it is a
name); --tls-server-name never changes where packets go.

UDP sends at most two datagrams (one retransmission after 0.5 s or half the
timeout) and stops retransmitting once any matching response arrives.
"""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # argparse exits 2 already
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="sippycup-options",
        description=(
            "Send one bounded SIP OPTIONS transaction to HOST and report the "
            "transport outcome, status, and TLS verification."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("host", metavar="HOST", help="IP literal ([v6] allowed) or name")
    parser.add_argument("port", metavar="PORT", type=_port)
    parser.add_argument("transport", metavar="TRANSPORT", choices=options.TRANSPORTS)
    parser.add_argument(
        "--timeout",
        type=float,
        default=options.DEFAULT_TIMEOUT_SECONDS,
        metavar="S",
        help=f"overall deadline in seconds (default {options.DEFAULT_TIMEOUT_SECONDS:g}, max "
        f"{options.MAX_TIMEOUT_SECONDS:g})",
    )
    expectation = parser.add_mutually_exclusive_group()
    expectation.add_argument("--expect-status", type=_status, metavar="N")
    expectation.add_argument(
        "--expect-class", choices=(*options.STATUS_CLASSES, "any"),
        help="required status class; 'any' accepts every final response",
    )
    parser.add_argument("--tls-server-name", metavar="NAME", help="SNI and name to verify")
    parser.add_argument("--tls-ca-file", metavar="PATH", help="additional trust anchor (PEM)")
    parser.add_argument(
        "--insecure", action="store_true",
        help="do not verify the TLS certificate (reported as UNVERIFIED)",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def _port(value: str) -> int:
    if not value.isdigit() or not 1 <= int(value) <= 65535:
        raise argparse.ArgumentTypeError("PORT must be an integer from 1 to 65535")
    return int(value)


def _status(value: str) -> int:
    if not value.isdigit() or not 200 <= int(value) <= 699:
        raise argparse.ArgumentTypeError("--expect-status must be a final status 200-699")
    return int(value)


def _literal_or_none(host: str) -> str | None:
    bare = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ipaddress.ip_address(bare.split("%", 1)[0])
    except ValueError:
        return None
    return bare


def exit_code_for(result: options.OptionsResult, met: bool) -> int:
    if result.outcome == options.RESPONSE:
        return EXIT_MET if met else EXIT_NOT_MET
    if result.outcome == options.TLS_FAILURE:
        return EXIT_TLS
    if result.outcome == options.NO_RESPONSE:
        return EXIT_NO_RESPONSE
    return EXIT_UNREACHABLE


def verdict_for(result: options.OptionsResult, met: bool) -> str:
    if result.outcome == options.RESPONSE:
        if not met:
            return "fail"
        if result.transport == "tls" and not result.tls_verified:
            return "pass_tls_unverified"
        return "pass"
    return result.outcome


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    if not _HOST.match(arguments.host) or arguments.host.startswith("-"):
        parser.error(f"invalid HOST: {arguments.host!r}")
    if arguments.transport != "tls" and (
        arguments.tls_server_name or arguments.tls_ca_file or arguments.insecure
    ):
        parser.error("--tls-server-name, --tls-ca-file, and --insecure need TRANSPORT tls")
    if arguments.insecure and arguments.tls_ca_file:
        parser.error("--insecure and --tls-ca-file are mutually exclusive")
    if not 0 < arguments.timeout <= options.MAX_TIMEOUT_SECONDS:
        parser.error(f"--timeout must be in (0, {options.MAX_TIMEOUT_SECONDS:g}]")

    literal = _literal_or_none(arguments.host)
    request_host = None
    resolved_from = None
    if literal is None:
        # A name is resolved once here; the transaction itself only ever
        # sees the literal address it connects to.
        kind = socket.SOCK_DGRAM if arguments.transport == "udp" else socket.SOCK_STREAM
        try:
            literal = socket.getaddrinfo(arguments.host, arguments.port, type=kind)[0][4][0]
        except (OSError, IndexError) as error:
            return _report_resolution_failure(arguments, error)
        request_host = arguments.host
        resolved_from = arguments.host
    server_name = arguments.tls_server_name
    if arguments.transport == "tls" and server_name is None and resolved_from is not None:
        server_name = resolved_from
    try:
        result = options.send_options(
            literal,
            arguments.port,
            arguments.transport,
            timeout=arguments.timeout,
            tls_server_name=server_name,
            tls_ca_file=arguments.tls_ca_file,
            insecure=arguments.insecure,
            request_host=request_host,
        )
    except options.OptionsUsageError as error:
        parser.error(str(error))
        raise AssertionError("unreachable")  # pragma: no cover
    met = options.meets_expectation(
        result,
        expect_status=arguments.expect_status,
        expect_class=arguments.expect_class,
    )
    code = exit_code_for(result, met)
    expectation = (
        str(arguments.expect_status)
        if arguments.expect_status is not None
        else (arguments.expect_class or "2xx")
    )
    if arguments.format == "json":
        document = {
            "schema": RESULT_SCHEMA,
            **result.to_dict(),
            "resolved_from": resolved_from,
            "expectation": expectation,
            "met": met,
            "verdict": verdict_for(result, met),
            "exit_code": code,
        }
        print(json.dumps(document, indent=2, sort_keys=True))
    else:
        _print_text(result, arguments, expectation, met, code, resolved_from)
    return code


def _report_resolution_failure(arguments: argparse.Namespace, error: Exception) -> int:
    message = f"{type(error).__name__}: {error}"
    if arguments.format == "json":
        print(json.dumps({
            "schema": RESULT_SCHEMA,
            "address": None,
            "port": arguments.port,
            "transport": arguments.transport,
            "resolved_from": arguments.host,
            "outcome": options.UNREACHABLE,
            "error_category": "resolution_failed",
            "error": message,
            "requests_sent": 0,
            "met": False,
            "verdict": options.UNREACHABLE,
            "exit_code": EXIT_UNREACHABLE,
        }, indent=2, sort_keys=True))
    else:
        print(f"Resolution of {arguments.host!r} failed: {message}")
        print("Result: UNREACHABLE (nothing was sent)")
    return EXIT_UNREACHABLE


def _print_text(result, arguments, expectation, met, code, resolved_from) -> None:
    host = options.uri_host(result.address)
    target = f"{host}:{result.port}"
    if resolved_from:
        target += f" (resolved from {resolved_from})"
    print(f"SIP OPTIONS over {result.transport} to {target}")
    if result.transport == "tls":
        if result.outcome == options.TLS_FAILURE:
            print(f"TLS: FAILED ({result.error_category}) for name "
                  f"{result.tls_server_name!r}: {result.error}")
        elif result.tls_verified:
            print(f"TLS: verified for name {result.tls_server_name!r} ({result.tls_version})")
        elif arguments.insecure:
            print(f"TLS: UNVERIFIED (--insecure; certificate not checked, {result.tls_version})")
    if result.outcome == options.RESPONSE:
        print(f"Response: {result.status_line} [class {result.status_class}]")
        if result.provisional:
            print(f"Provisional: {', '.join(str(item) for item in result.provisional)}")
    elif result.outcome != options.TLS_FAILURE:
        print(f"Response: none ({result.error_category}: {result.error})")
    for note in result.notes:
        print(f"Note: {note}")
    print(
        f"Requests sent: {result.requests_sent} (retransmissions {result.retransmissions}); "
        f"ignored datagrams: {result.ignored_datagrams}; "
        f"elapsed: {result.elapsed_seconds:.3f} s"
    )
    print(f"Expectation: {expectation} -> {'met' if met else 'not met'}")
    labels = {
        "pass": "PASS",
        "pass_tls_unverified": "PASS, TLS UNVERIFIED",
        "fail": "FAIL (response did not meet the expectation)",
        options.NO_RESPONSE: "NO RESPONSE",
        options.UNREACHABLE: "UNREACHABLE",
        options.TLS_FAILURE: "TLS FAILURE",
        options.LOCAL_ERROR: "LOCAL ERROR",
    }
    print(f"Result: {labels[verdict_for(result, met)]} (exit {code})")
