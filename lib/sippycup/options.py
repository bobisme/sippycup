"""One bounded SIP OPTIONS client transaction (RFC 3261 section 11).

This is the only OPTIONS sender in Sippycup. The launcher preflight
(``sippycup-preflight`` through ``sippycup-options``), the campaign preflight
(``integration.sip_options_preflight``), the guided call, the live MCP
preflight, and the campaign ``options`` step all use it.

Traffic contract, per call of :func:`send_options`:

- exactly one transaction to exactly the literal address and port given; no
  name resolution happens here;
- UDP: at most ``max_requests`` datagrams (default 2: the request and one
  retransmission after ``T1`` or half the timeout, whichever is shorter),
  never more, and no retransmission once any response to this transaction
  arrived;
- TCP/TLS: one connection and one request;
- everything ends at one overall deadline (``timeout`` seconds).

TLS verifies the peer by default: against ``tls_server_name`` when given,
otherwise against the literal address. ``insecure=True`` disables
verification and the result then always reports ``tls_verified=False``.
"""

from __future__ import annotations

import errno
import ipaddress
import re
import secrets
import socket
import ssl
import time
from dataclasses import asdict, dataclass, field
from typing import Any

DEFAULT_TIMEOUT_SECONDS = 2.0
MAX_TIMEOUT_SECONDS = 30.0
T1_SECONDS = 0.5
MAX_UDP_REQUESTS = 2
MAX_RESPONSE_BYTES = 64 * 1024
TRANSPORTS = ("udp", "tcp", "tls")
STATUS_CLASSES = ("2xx", "3xx", "4xx", "5xx", "6xx")

# Outcomes. Exactly one applies to every result.
RESPONSE = "response"  # a final SIP response to this transaction arrived
NO_RESPONSE = "no_response"  # deadline passed, peer closed, or reply invalid
UNREACHABLE = "unreachable"  # connection refused, host or network unreachable
TLS_FAILURE = "tls_failure"  # handshake or certificate verification failed
LOCAL_ERROR = "local_error"  # the request could not be built or sent locally

_STATUS_LINE = re.compile(r"SIP/2\.0 ([1-6][0-9]{2}) ([\x20-\x7e\x80-\xff]*)")
_DETAIL_STATUS = re.compile(r"^SIP/2\.0 ([1-6][0-9]{2})(?: |$)")
_BRANCH = re.compile(r";\s*branch\s*=\s*([^;,\s]+)", re.IGNORECASE)
_COMPACT = {"v": "via", "i": "call-id", "l": "content-length"}


class OptionsUsageError(ValueError):
    """The caller passed an argument this transaction cannot honor."""


@dataclass
class OptionsResult:
    """Structured outcome of one OPTIONS transaction."""

    address: str
    port: int
    transport: str
    outcome: str
    status_code: int | None = None
    reason: str | None = None
    status_class: str | None = None
    status_line: str | None = None
    provisional: list[int] = field(default_factory=list)
    tls_verified: bool | None = None
    tls_server_name: str | None = None
    tls_version: str | None = None
    elapsed_seconds: float = 0.0
    requests_sent: int = 0
    retransmissions: int = 0
    ignored_datagrams: int = 0
    error_category: str | None = None
    error: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def responded(self) -> bool:
        return self.outcome == RESPONSE

    def detail(self) -> str:
        """One line for logs and evidence; never claims an unverified TLS ok."""
        if self.outcome == RESPONSE:
            text = self.status_line or f"SIP/2.0 {self.status_code}"
        else:
            text = f"{self.outcome}: {self.error_category}"
            if self.error:
                text += f": {self.error}"
        if self.transport == "tls" and self.tls_verified is False:
            text += " [TLS UNVERIFIED]"
        return text

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["elapsed_seconds"] = round(self.elapsed_seconds, 6)
        return value


def status_class(code: int | None) -> str | None:
    if code is None or not 100 <= code <= 699:
        return None
    return f"{code // 100}xx"


def status_of_detail(detail: str) -> tuple[int | None, str | None]:
    """Recover the status code and class from a ``(ok, detail)`` preflight."""
    match = _DETAIL_STATUS.match(detail or "")
    if match is None:
        return None, None
    code = int(match.group(1))
    return code, status_class(code)


def meets_expectation(
    result: OptionsResult,
    *,
    expect_status: int | None = None,
    expect_class: str | None = None,
) -> bool:
    """Exact status, a class (``2xx``..``6xx`` or ``any``), or 2xx by default."""
    if result.outcome != RESPONSE or result.status_code is None:
        return False
    if expect_status is not None:
        return result.status_code == expect_status
    wanted = expect_class or "2xx"
    if wanted == "any":
        return True
    return result.status_class == wanted


def _literal(address: str) -> tuple[str, int]:
    """Validate an IP literal; return it without brackets or zone, and family."""
    text = address.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    base = text.split("%", 1)[0]
    try:
        parsed = ipaddress.ip_address(base)
    except ValueError as error:
        raise OptionsUsageError(f"not an IP address literal: {address!r}") from error
    family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
    return text, family


def uri_host(host: str) -> str:
    """Host part for a SIP URI or Via sent-by: IPv6 literals in brackets."""
    bare = host.split("%", 1)[0]
    try:
        if ipaddress.ip_address(bare).version == 6:
            return f"[{bare}]"
    except ValueError:
        pass
    return host


def build_request(
    *,
    target_host: str,
    port: int,
    transport: str,
    local: tuple[Any, ...],
    branch: str,
    call_id: str,
    from_tag: str,
) -> bytes:
    # A compliant server answers a UDP request at the Via sent-by port
    # (default 5060), not the datagram's source port, unless the client
    # names its real port and asks for RFC 3581 symmetric routing. Without
    # both, the reply never reaches this ephemeral socket.
    sent_by = uri_host(str(local[0]))
    request_host = uri_host(target_host)
    return (
        f"OPTIONS sip:{request_host}:{port} SIP/2.0\r\n"
        f"Via: SIP/2.0/{transport.upper()} {sent_by}:{local[1]}"
        f";rport;branch={branch}\r\n"
        "Max-Forwards: 1\r\n"
        f"From: <sip:sippycup@localhost>;tag={from_tag}\r\n"
        f"To: <sip:{request_host}:{port}>\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 1 OPTIONS\r\n"
        "Accept: application/sdp\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode()


@dataclass
class _Parsed:
    code: int
    reason: str
    status_line: str
    headers: dict[str, list[str]]
    content_length: int


def parse_response_head(head: bytes) -> _Parsed | None:
    """Parse a response start line and headers strictly; None if invalid."""
    try:
        text = head.decode("utf-8")
    except UnicodeDecodeError:
        text = head.decode("latin-1")
    lines = text.split("\r\n")
    match = _STATUS_LINE.fullmatch(lines[0])
    if match is None:
        return None
    headers: dict[str, list[str]] = {}
    last: str | None = None
    for line in lines[1:]:
        if not line:
            continue
        if line[0] in " \t":
            if last is None:
                return None
            headers[last][-1] += " " + line.strip()
            continue
        name, separator, value = line.partition(":")
        if not separator or not name.strip() or name != name.rstrip():
            return None
        key = name.strip().lower()
        key = _COMPACT.get(key, key)
        headers.setdefault(key, []).append(value.strip())
        last = key
    length_values = headers.get("content-length", ["0"])
    try:
        content_length = int(length_values[0])
    except ValueError:
        return None
    if content_length < 0:
        return None
    return _Parsed(
        int(match.group(1)), match.group(2), lines[0], headers, content_length
    )


def _matches(parsed: _Parsed, call_id: str, branch: str) -> bool:
    call_ids = parsed.headers.get("call-id", [])
    cseqs = parsed.headers.get("cseq", [])
    vias = parsed.headers.get("via", [])
    if len(call_ids) != 1 or call_ids[0] != call_id:
        return False
    if len(cseqs) != 1 or cseqs[0].split() != ["1", "OPTIONS"]:
        return False
    if not vias:
        return False
    top_via = vias[0].split(",", 1)[0]
    found = _BRANCH.search(top_via)
    return found is not None and found.group(1) == branch


def _split_message(buffer: bytes) -> tuple[bytes, bytes] | None:
    end = buffer.find(b"\r\n\r\n")
    if end < 0:
        return None
    return buffer[:end], buffer[end + 4 :]


def _classify_os_error(error: OSError) -> tuple[str, str]:
    if isinstance(error, (socket.timeout, TimeoutError)):
        return NO_RESPONSE, "timeout"
    if isinstance(error, ConnectionRefusedError) or error.errno == errno.ECONNREFUSED:
        return UNREACHABLE, "connection_refused"
    if error.errno in {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EADDRNOTAVAIL}:
        return UNREACHABLE, "unreachable"
    if isinstance(error, (ConnectionResetError, BrokenPipeError)):
        return NO_RESPONSE, "connection_reset"
    return LOCAL_ERROR, "socket_error"


def _tls_context(
    *, ca_file: str | None, insecure: bool, ca_data: bytes | None = None
) -> ssl.SSLContext:
    if insecure:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    context = ssl.create_default_context()
    if ca_file is not None:
        try:
            context.load_verify_locations(cafile=ca_file)
        except (OSError, ssl.SSLError) as error:
            raise OptionsUsageError(f"cannot load TLS CA file {ca_file!r}: {error}") from error
    if ca_data is not None:
        # Already digest-checked bytes: loading them from memory closes the
        # window between checking a reviewed CA file and reading it again.
        try:
            context.load_verify_locations(cadata=ca_data.decode("ascii"))
        except (UnicodeDecodeError, ssl.SSLError) as error:
            raise OptionsUsageError(f"cannot load TLS CA data: {error}") from error
    return context


def send_options(
    address: str,
    port: int,
    transport: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_requests: int = MAX_UDP_REQUESTS,
    tls_server_name: str | None = None,
    tls_ca_file: str | None = None,
    insecure: bool = False,
    request_host: str | None = None,
    tls_ca_data: bytes | None = None,
) -> OptionsResult:
    """Send one OPTIONS transaction to a literal address; never raises on I/O.

    ``request_host`` replaces the address in the Request-URI and To (for a
    name the caller resolved itself); the connection still goes only to
    ``address``. Usage problems raise :class:`OptionsUsageError` before any
    socket exists.
    """
    if transport not in TRANSPORTS:
        raise OptionsUsageError("transport must be udp, tcp, or tls")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise OptionsUsageError("port must be an integer between 1 and 65535")
    if not 0 < float(timeout) <= MAX_TIMEOUT_SECONDS:
        raise OptionsUsageError(
            f"timeout must be greater than 0 and at most {MAX_TIMEOUT_SECONDS:g} seconds"
        )
    if max_requests not in (1, 2):
        raise OptionsUsageError("max_requests must be 1 or 2")
    if transport != "tls" and (tls_server_name or tls_ca_file or insecure or tls_ca_data):
        raise OptionsUsageError("TLS options require the tls transport")
    if insecure and (tls_ca_file or tls_ca_data):
        raise OptionsUsageError("--insecure and a TLS CA file are mutually exclusive")
    if tls_ca_file and tls_ca_data:
        raise OptionsUsageError("give a TLS CA file or CA data, not both")
    literal, family = _literal(address)
    context = (
        _tls_context(ca_file=tls_ca_file, insecure=insecure, ca_data=tls_ca_data)
        if transport == "tls"
        else None
    )

    result = OptionsResult(address=literal, port=port, transport=transport, outcome=NO_RESPONSE)
    if transport == "tls":
        result.tls_server_name = tls_server_name or literal.split("%", 1)[0]
        result.tls_verified = False
    branch = "z9hG4bK" + secrets.token_hex(10)
    call_id = secrets.token_hex(12) + "@sippycup"
    from_tag = secrets.token_hex(6)
    started = time.monotonic()
    deadline = started + float(timeout)

    def remaining() -> float:
        return deadline - time.monotonic()

    def request_for(sock: socket.socket) -> bytes:
        return build_request(
            target_host=request_host or literal,
            port=port,
            transport=transport,
            local=sock.getsockname(),
            branch=branch,
            call_id=call_id,
            from_tag=from_tag,
        )

    def accept(parsed: _Parsed) -> bool:
        """Record a matching response; True once it is final."""
        if parsed.code < 200:
            result.provisional.append(parsed.code)
            return False
        result.outcome = RESPONSE
        result.status_code = parsed.code
        result.reason = parsed.reason
        result.status_class = status_class(parsed.code)
        result.status_line = parsed.status_line
        result.error_category = None
        result.error = None
        return True

    try:
        if transport == "udp":
            _udp(result, literal, family, port, remaining, request_for, accept,
                 call_id, branch, max_requests, timeout)
        else:
            _stream(result, literal, family, port, transport, context, remaining,
                    request_for, accept, call_id, branch)
    finally:
        result.elapsed_seconds = time.monotonic() - started
    if result.outcome == NO_RESPONSE and result.error_category is None:
        result.error_category = "timeout"
        result.error = (
            f"no final response within {float(timeout):g}s"
            + (f" (provisional {result.provisional})" if result.provisional else "")
        )
    return result


def _udp(result, literal, family, port, remaining, request_for, accept,
         call_id, branch, max_requests, timeout) -> None:
    retransmit_after = min(T1_SECONDS, float(timeout) / 2)
    try:
        sock = socket.socket(family, socket.SOCK_DGRAM)
    except OSError as error:
        result.outcome, result.error_category = LOCAL_ERROR, "socket_error"
        result.error = f"{type(error).__name__}: {error}"
        return
    with sock:
        try:
            # Connecting pins the reply source to the destination and reveals
            # the real local address and port for the Via header.
            sock.connect((literal, port))
            request = request_for(sock)
            sock.send(request)
        except OSError as error:
            result.outcome, result.error_category = _classify_os_error(error)
            result.error = f"{type(error).__name__}: {error}"
            return
        result.requests_sent = 1
        sent_at = time.monotonic()
        heard_any = False
        while True:
            left = remaining()
            if left <= 0:
                return
            wait = left
            if result.requests_sent < max_requests and not heard_any:
                wait = min(left, max(0.0, sent_at + retransmit_after - time.monotonic()))
            if wait <= 0:
                try:
                    sock.send(request)
                except OSError as error:
                    if not _udp_refusal(result, error):
                        result.outcome, result.error_category = _classify_os_error(error)
                        result.error = f"{type(error).__name__}: {error}"
                        return
                result.requests_sent += 1
                result.retransmissions += 1
                continue
            sock.settimeout(wait)
            try:
                datagram = sock.recv(MAX_RESPONSE_BYTES)
            except (socket.timeout, TimeoutError):
                continue
            except OSError as error:
                if _udp_refusal(result, error):
                    continue
                result.outcome, result.error_category = _classify_os_error(error)
                result.error = f"{type(error).__name__}: {error}"
                return
            split = _split_message(datagram)
            parsed = parse_response_head(split[0]) if split else None
            if parsed is None or not _matches(parsed, call_id, branch):
                result.ignored_datagrams += 1
                continue
            heard_any = True
            if accept(parsed):
                return


def _udp_refusal(result: OptionsResult, error: OSError) -> bool:
    """ICMP port unreachable on a connected UDP socket is advisory only.

    It may be filtered, rate limited, or forged, so it never decides the
    outcome: the transaction keeps waiting and ends as no response.
    """
    if isinstance(error, ConnectionRefusedError) or error.errno == errno.ECONNREFUSED:
        note = "icmp_port_unreachable"
        if note not in result.notes:
            result.notes.append(note)
        return True
    return False


def _stream(result, literal, family, port, transport, context, remaining,
            request_for, accept, call_id, branch) -> None:
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
    except OSError as error:
        result.outcome, result.error_category = LOCAL_ERROR, "socket_error"
        result.error = f"{type(error).__name__}: {error}"
        return
    connection: socket.socket = sock
    try:
        try:
            sock.settimeout(max(remaining(), 0.001))
            sock.connect((literal, port))
        except OSError as error:
            result.outcome, result.error_category = _classify_os_error(error)
            if result.error_category == "timeout":
                result.error = "TCP connection not established before the deadline"
            else:
                result.error = f"{type(error).__name__}: {error}"
            return
        request = request_for(sock)
        if transport == "tls":
            assert context is not None
            try:
                connection = context.wrap_socket(
                    sock,
                    server_hostname=result.tls_server_name,
                    do_handshake_on_connect=False,
                )
                connection.settimeout(max(remaining(), 0.001))
                connection.do_handshake()
            except ssl.SSLCertVerificationError as error:
                result.outcome, result.error_category = TLS_FAILURE, "tls_verification"
                result.error = error.verify_message or str(error)
                return
            except (ssl.SSLError, OSError) as error:
                if isinstance(error, (socket.timeout, TimeoutError)):
                    result.outcome, result.error_category = TLS_FAILURE, "tls_handshake_timeout"
                else:
                    result.outcome, result.error_category = TLS_FAILURE, "tls_handshake"
                result.error = f"{type(error).__name__}: {error}"
                return
            result.tls_verified = context.verify_mode == ssl.CERT_REQUIRED
            result.tls_version = connection.version()
        try:
            connection.settimeout(max(remaining(), 0.001))
            connection.sendall(request)
        except OSError as error:
            result.outcome, result.error_category = _classify_os_error(error)
            result.error = f"{type(error).__name__}: {error}"
            return
        result.requests_sent = 1
        buffer = b""
        while True:
            # Consume complete messages; a stream response may arrive split
            # across segments, and provisional responses may precede it.
            while (split := _split_message(buffer)) is not None:
                head, rest = split
                parsed = parse_response_head(head)
                if parsed is None:
                    result.outcome, result.error_category = NO_RESPONSE, "malformed_response"
                    result.error = "reply is not a valid SIP response: " + repr(head[:80])
                    return
                if len(rest) < parsed.content_length:
                    break
                buffer = rest[parsed.content_length :]
                if not _matches(parsed, call_id, branch):
                    result.outcome, result.error_category = NO_RESPONSE, "mismatched_response"
                    result.error = "response does not match this transaction"
                    return
                if accept(parsed):
                    return
            if len(buffer) > MAX_RESPONSE_BYTES:
                result.outcome, result.error_category = NO_RESPONSE, "oversized_response"
                result.error = f"response exceeds {MAX_RESPONSE_BYTES} bytes"
                return
            left = remaining()
            if left <= 0:
                return
            connection.settimeout(left)
            try:
                chunk = connection.recv(MAX_RESPONSE_BYTES)
            except (socket.timeout, TimeoutError):
                return
            except (ssl.SSLError, OSError) as error:
                result.outcome, result.error_category = NO_RESPONSE, "connection_reset"
                result.error = f"{type(error).__name__}: {error}"
                return
            if not chunk:
                result.outcome, result.error_category = NO_RESPONSE, "connection_closed"
                result.error = "peer closed the connection before a final response"
                return
            buffer += chunk
    finally:
        connection.close()
        if connection is not sock:
            sock.close()
