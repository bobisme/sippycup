"""Minimal SIP client transactions for the posture checks (RFC 3261).

This reuses the in-tree OPTIONS client's strict pieces (literal address
validation, response parsing, TLS context) and adds what the checks need:
REGISTER binding queries, an INVITE that is always ended correctly (ACK for a
rejection, CANCEL and ACK if it rings, ACK and BYE if answered), and Digest
computation. Every request goes through :class:`~sippycup_checks.budget.Budget`
before it is sent, connects only to the literal approved address, and is
never retransmitted.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import secrets
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from sippycup.options import (
    _classify_os_error,
    _literal,
    _split_message,
    _tls_context,
    parse_response_head,
    uri_host,
)

from .budget import Budget

MAX_MESSAGE_BYTES = 64 * 1024
USER_AGENT = "sippycup-checks"
_BRANCH = re.compile(r";\s*branch\s*=\s*([^;,\s]+)", re.IGNORECASE)
_TAG = re.compile(r";\s*tag\s*=\s*([^;,\s>]+)", re.IGNORECASE)
_URI_IN_BRACKETS = re.compile(r"<(sips?:[^<>\s]+)>")
_SAFE_URI = re.compile(r"^sips?:[A-Za-z0-9._~%!$&'()*+,;=:@\[\]/?-]+$")


class ChannelError(RuntimeError):
    """The connection could not be used; ``category`` says why."""

    def __init__(self, category: str, detail: str) -> None:
        super().__init__(f"{category}: {detail}")
        self.category = category
        self.detail = detail


@dataclass(frozen=True)
class Endpoint:
    address: str
    port: int
    transport: str
    domain: str
    server_name: str | None = None
    ca_data: bytes | None = None


@dataclass
class Response:
    code: int
    reason: str
    status_line: str
    headers: dict[str, list[str]]
    body: bytes
    elapsed_ms: float

    def first(self, name: str) -> str | None:
        values = self.headers.get(name.lower())
        return values[0] if values else None

    def all(self, name: str) -> list[str]:
        return list(self.headers.get(name.lower(), []))

    def header_names(self) -> list[str]:
        return sorted(self.headers)

    def to_tag(self) -> str | None:
        value = self.first("to") or ""
        match = _TAG.search(value)
        return match.group(1) if match else None


def _matches(response: Response, call_id: str, cseq: int, method: str, branch: str) -> bool:
    call_ids = response.all("call-id")
    cseqs = response.all("cseq")
    vias = response.all("via")
    if len(call_ids) != 1 or call_ids[0] != call_id:
        return False
    if len(cseqs) != 1 or cseqs[0].split() != [str(cseq), method]:
        return False
    if not vias:
        return False
    found = _BRANCH.search(vias[0].split(",", 1)[0])
    return found is not None and found.group(1) == branch


def _content_length(head: bytes) -> int | None:
    for line in head.split(b"\r\n")[1:]:
        name, separator, value = line.partition(b":")
        if separator and name.strip().lower() in (b"content-length", b"l"):
            try:
                length = int(value.strip())
            except ValueError:
                return None
            return length if length >= 0 else None
    return 0


class Channel:
    """One connection (or connected UDP socket) to the literal target address."""

    def __init__(
        self,
        endpoint: Endpoint,
        budget: Budget,
        *,
        timeout: float = 4.0,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.endpoint = endpoint
        self.budget = budget
        self.timeout = timeout
        self.monotonic = monotonic
        self.sock: socket.socket | None = None
        self.local: tuple[str, int] = ("0.0.0.0", 0)
        self.tls_version: str | None = None
        self.tls_verified: bool | None = None
        self._buffer = b""
        self.ignored = 0
        self.sent_at: float | None = None
        # A TCP/TLS connection attempt is counted (and paced) as the first
        # request: a refused or unverified connection still put packets on
        # the wire, and the request it then carries is not counted again.
        self._prepaid = False

    # -- lifecycle ---------------------------------------------------------
    def open(self) -> None:
        literal, family = _literal(self.endpoint.address)
        transport = self.endpoint.transport
        kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
        if transport != "udp":
            self.budget.spend(f"{transport.upper()} connection and its first request")
            self._prepaid = True
        try:
            sock = socket.socket(family, kind)
        except OSError as error:
            raise ChannelError("local_error", f"{type(error).__name__}: {error}") from error
        try:
            sock.settimeout(self.timeout)
            sock.connect((literal, self.endpoint.port))
        except OSError as error:
            sock.close()
            outcome, category = _classify_os_error(error)
            raise ChannelError(category if outcome != "local_error" else "local_error",
                               f"{type(error).__name__}: {error}") from error
        if transport == "tls":
            context = _tls_context(ca_file=None, insecure=False, ca_data=self.endpoint.ca_data)
            name = self.endpoint.server_name or literal.split("%", 1)[0]
            wrapped = context.wrap_socket(sock, server_hostname=name, do_handshake_on_connect=False)
            try:
                wrapped.settimeout(self.timeout)
                wrapped.do_handshake()
            except ssl.SSLCertVerificationError as error:
                wrapped.close()
                raise ChannelError("tls_verification", error.verify_message or str(error)) from error
            except (ssl.SSLError, OSError) as error:
                wrapped.close()
                raise ChannelError("tls_handshake", f"{type(error).__name__}: {error}") from error
            self.tls_verified = True
            self.tls_version = wrapped.version()
            sock = wrapped
        self.sock = sock
        host, port = sock.getsockname()[:2]
        self.local = (str(host), int(port))

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def __enter__(self) -> "Channel":
        self.open()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- I/O ---------------------------------------------------------------
    def send(self, data: bytes, what: str, *, paced: bool = True) -> None:
        assert self.sock is not None
        if self._prepaid:
            self._prepaid = False
        else:
            self.budget.spend(what, paced=paced)
        try:
            if self.endpoint.transport == "udp":
                self.sock.send(data)
            else:
                self.sock.sendall(data)
        except OSError as error:
            raise ChannelError("send_failed", f"{type(error).__name__}: {error}") from error
        self.sent_at = self.monotonic()

    def receive(self, deadline: float) -> Response | None:
        """The next SIP response before ``deadline``; peer requests are ignored."""
        assert self.sock is not None
        while True:
            if self.endpoint.transport != "udp":
                message = self._next_stream_message()
                if message is not None:
                    if message is _IGNORED:
                        continue
                    return message
            left = deadline - self.monotonic()
            if left <= 0:
                return None
            self.sock.settimeout(left)
            try:
                chunk = self.sock.recv(MAX_MESSAGE_BYTES)
            except (socket.timeout, TimeoutError):
                return None
            except ConnectionRefusedError:
                # ICMP port unreachable on UDP is advisory only.
                continue
            except (ssl.SSLError, OSError) as error:
                raise ChannelError("connection_reset", f"{type(error).__name__}: {error}") from error
            if self.endpoint.transport == "udp":
                parsed = self._parse_datagram(chunk)
                if parsed is not None:
                    return parsed
                self.ignored += 1
                continue
            if not chunk:
                raise ChannelError("connection_closed", "peer closed the connection")
            self._buffer += chunk
            if len(self._buffer) > MAX_MESSAGE_BYTES * 4:
                raise ChannelError("oversized_response", "peer sent too much data")

    def _response(self, head: bytes, body: bytes) -> Response | None:
        parsed = parse_response_head(head)
        if parsed is None:
            return None
        elapsed = (self.monotonic() - self.sent_at) * 1000 if self.sent_at is not None else 0.0
        return Response(parsed.code, parsed.reason, parsed.status_line, parsed.headers,
                        body[: parsed.content_length], round(elapsed, 3))

    def _parse_datagram(self, data: bytes) -> Response | None:
        split = _split_message(data)
        if split is None or not split[0].startswith(b"SIP/2.0 "):
            return None
        return self._response(split[0], split[1])

    def _next_stream_message(self) -> Any:
        while self._buffer.startswith(b"\r\n"):
            self._buffer = self._buffer[2:]  # keep-alive CRLF
        split = _split_message(self._buffer)
        if split is None:
            return None
        head, rest = split
        length = _content_length(head)
        if length is None:
            raise ChannelError("malformed_response", "invalid Content-Length from peer")
        if len(rest) < length:
            return None
        self._buffer = rest[length:]
        if not head.startswith(b"SIP/2.0 "):
            self.ignored += 1
            return _IGNORED
        parsed = self._response(head, rest[:length])
        if parsed is None:
            raise ChannelError("malformed_response", "reply is not a valid SIP response")
        return parsed


_IGNORED = object()


# -- requests ----------------------------------------------------------------

def token(nbytes: int = 8) -> str:
    return secrets.token_hex(nbytes)


def new_branch() -> str:
    return "z9hG4bK" + token(10)


@dataclass
class Request:
    method: str
    uri: str
    from_uri: str
    from_tag: str
    to_uri: str
    call_id: str
    cseq: int
    branch: str = field(default_factory=new_branch)
    to_tag: str | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    content_type: str | None = None
    cseq_method: str | None = None

    def render(self, channel: Channel) -> bytes:
        host, port = channel.local
        transport = channel.endpoint.transport.upper()
        to = f"<{self.to_uri}>" + (f";tag={self.to_tag}" if self.to_tag else "")
        lines = [
            f"{self.method} {self.uri} SIP/2.0",
            f"Via: SIP/2.0/{transport} {uri_host(host)}:{port};rport;branch={self.branch}",
            "Max-Forwards: 70",
            f"From: {self.from_uri};tag={self.from_tag}",
            f"To: {to}",
            f"Call-ID: {self.call_id}",
            f"CSeq: {self.cseq} {self.cseq_method or self.method}",
            f"User-Agent: {USER_AGENT}",
        ]
        for name, value in self.headers:
            lines.append(f"{name}: {value}")
        if self.content_type:
            lines.append(f"Content-Type: {self.content_type}")
        lines.append(f"Content-Length: {len(self.body)}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode() + self.body


def sip_uri(user: str | None, endpoint: Endpoint) -> str:
    host = uri_host(endpoint.domain)
    scheme = "sip"
    port = f":{endpoint.port}"
    transport = "" if endpoint.transport == "udp" else f";transport={endpoint.transport}"
    return f"{scheme}:{user + '@' if user else ''}{host}{port}{transport}"


def aor(user: str, endpoint: Endpoint) -> str:
    return f"sip:{user}@{uri_host(endpoint.domain)}"


def contact(channel: Channel) -> str:
    host, port = channel.local
    transport = channel.endpoint.transport
    suffix = "" if transport == "udp" else f";transport={transport}"
    return f"<sip:sippycup@{uri_host(host)}:{port}{suffix}>"


@dataclass
class Exchange:
    """What one request transaction produced."""

    method: str
    provisional: list[int] = field(default_factory=list)
    final: Response | None = None
    timed_out: bool = False


def transact(channel: Channel, request: Request, *, timeout: float, paced: bool = True,
             what: str | None = None) -> Exchange:
    """Send one non-INVITE request once and wait for its final response."""
    method = request.cseq_method or request.method
    channel.send(request.render(channel), what or request.method, paced=paced)
    exchange = Exchange(method)
    deadline = channel.monotonic() + timeout
    while True:
        response = channel.receive(deadline)
        if response is None:
            exchange.timed_out = True
            return exchange
        if not _matches(response, request.call_id, request.cseq, method, request.branch):
            channel.ignored += 1
            continue
        if response.code < 200:
            exchange.provisional.append(response.code)
            continue
        exchange.final = response
        return exchange


def register_query(
    user: str,
    endpoint: Endpoint,
    *,
    call_id: str | None = None,
    from_tag: str | None = None,
    cseq: int = 1,
    authorization: tuple[str, str] | None = None,
) -> Request:
    """A REGISTER without Contact: a binding query that changes nothing."""
    identity = aor(user, endpoint)
    headers: list[tuple[str, str]] = []
    if authorization is not None:
        headers.append(authorization)
    return Request(
        method="REGISTER",
        uri=sip_uri(None, endpoint),
        from_uri=f"<{identity}>",
        from_tag=from_tag or token(6),
        to_uri=identity,
        call_id=call_id or token(12) + "@sippycup-checks",
        cseq=cseq,
        headers=headers,
    )


def options_request(endpoint: Endpoint) -> Request:
    return Request(
        method="OPTIONS",
        uri=sip_uri(None, endpoint),
        from_uri="<sip:sippycup@localhost>",
        from_tag=token(6),
        to_uri=sip_uri(None, endpoint),
        call_id=token(12) + "@sippycup-checks",
        cseq=1,
        headers=[("Accept", "application/sdp")],
    )


# -- INVITE, always ended correctly ---------------------------------------------

@dataclass
class InviteOutcome:
    provisional: list[int] = field(default_factory=list)
    final: Response | None = None
    progressed: bool = False
    answered: bool = False
    steps: list[str] = field(default_factory=list)
    cleanup_ok: bool = True
    cleanup_detail: str | None = None
    timed_out: bool = False

    @property
    def final_code(self) -> int | None:
        return self.final.code if self.final is not None else None


def inactive_sdp(host: str, port: int) -> bytes:
    family = "IP6" if ":" in host else "IP4"
    session = token(4)
    return (
        "v=0\r\n"
        f"o=sippycup {int(session, 16)} 1 IN {family} {host}\r\n"
        "s=sippycup posture check\r\n"
        f"c=IN {family} {host}\r\n"
        "t=0 0\r\n"
        f"m=audio {port} RTP/AVP 0\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=inactive\r\n"
    ).encode()


def _remote_target(response: Response, fallback: str) -> str:
    value = response.first("contact") or ""
    match = _URI_IN_BRACKETS.search(value)
    uri = match.group(1) if match else value.split(";", 1)[0].strip()
    return uri if _SAFE_URI.fullmatch(uri or "") else fallback


def _route_set(response: Response) -> list[str]:
    routes: list[str] = []
    for value in response.all("record-route"):
        routes.extend(part.strip() for part in value.split(",") if part.strip())
    return [item for item in reversed(routes) if "\r" not in item and "\n" not in item]


def invite(
    channel: Channel,
    *,
    from_user: str,
    from_display: str | None,
    destination: str,
    invite_timeout: float,
    cleanup_timeout: float,
) -> InviteOutcome:
    """One INVITE without credentials, ended correctly whatever happens.

    A rejection is ACKed; a provisional response is CANCELled (and the 487
    ACKed); a 2xx is ACKed and immediately ended with BYE. The SDP offers an
    inactive stream on a local UDP port this process owns and never sends on.
    """
    endpoint = channel.endpoint
    media = socket.socket(socket.AF_INET6 if ":" in channel.local[0] else socket.AF_INET, socket.SOCK_DGRAM)
    try:
        media.bind((channel.local[0], 0))
        media_port = media.getsockname()[1]
        target = sip_uri(destination, endpoint)
        identity = f"sip:{from_user}@{uri_host(endpoint.domain)}"
        if from_user == "anonymous":
            identity = "sip:anonymous@anonymous.invalid"
        request = Request(
            method="INVITE",
            uri=target,
            from_uri=(f'"{from_display}" ' if from_display else "") + f"<{identity}>",
            from_tag=token(6),
            to_uri=target.split(";", 1)[0],
            call_id=token(12) + "@sippycup-checks",
            cseq=1,
            headers=[("Contact", contact(channel)), ("Allow", "INVITE, ACK, CANCEL, BYE")],
            body=inactive_sdp(channel.local[0], media_port),
            content_type="application/sdp",
        )
        return _run_invite(channel, request, invite_timeout, cleanup_timeout)
    finally:
        media.close()


def _ack_non_2xx(channel: Channel, request: Request, response: Response, outcome: InviteOutcome) -> None:
    ack = Request(
        method="ACK", uri=request.uri, from_uri=request.from_uri, from_tag=request.from_tag,
        to_uri=request.to_uri, to_tag=response.to_tag(), call_id=request.call_id,
        cseq=request.cseq, branch=request.branch,
    )
    channel.send(ack.render(channel), "ACK", paced=False)
    outcome.steps.append(f"ACK {response.code}")


def _end_answered(channel: Channel, request: Request, response: Response, outcome: InviteOutcome,
                  cleanup_timeout: float) -> None:
    remote = _remote_target(response, request.uri)
    routes = [("Route", item) for item in _route_set(response)]
    tag = response.to_tag()
    ack = Request(
        method="ACK", uri=remote, from_uri=request.from_uri, from_tag=request.from_tag,
        to_uri=request.to_uri, to_tag=tag, call_id=request.call_id, cseq=request.cseq,
        headers=list(routes),
    )
    channel.send(ack.render(channel), "ACK 2xx", paced=False)
    outcome.steps.append("ACK 2xx")
    bye = Request(
        method="BYE", uri=remote, from_uri=request.from_uri, from_tag=request.from_tag,
        to_uri=request.to_uri, to_tag=tag, call_id=request.call_id, cseq=request.cseq + 1,
        headers=list(routes),
    )
    result = transact(channel, bye, timeout=cleanup_timeout, paced=False, what="BYE")
    outcome.steps.append(f"BYE -> {result.final.code if result.final else 'no response'}")
    if result.final is None or not 200 <= result.final.code < 300:
        outcome.cleanup_ok = False
        outcome.cleanup_detail = (
            "BYE was not confirmed with 2xx" if result.final is not None else "BYE got no response"
        )


def _run_invite(channel: Channel, request: Request, invite_timeout: float,
                cleanup_timeout: float) -> InviteOutcome:
    outcome = InviteOutcome()
    channel.send(request.render(channel), "INVITE", paced=True)
    outcome.steps.append("INVITE")
    deadline = channel.monotonic() + invite_timeout
    cancelled = False
    cancel_branch = request.branch

    def send_cancel() -> None:
        nonlocal cancelled, deadline
        cancel = Request(
            method="CANCEL", uri=request.uri, from_uri=request.from_uri, from_tag=request.from_tag,
            to_uri=request.to_uri, call_id=request.call_id, cseq=request.cseq, branch=cancel_branch,
        )
        channel.send(cancel.render(channel), "CANCEL", paced=False)
        outcome.steps.append("CANCEL")
        cancelled = True
        deadline = channel.monotonic() + cleanup_timeout

    while True:
        response = channel.receive(deadline)
        if response is None:
            if outcome.final is None and outcome.provisional and not cancelled:
                # Only a provisional so far: a CANCEL is allowed and required.
                send_cancel()
                continue
            if cancelled and outcome.final is None:
                outcome.cleanup_ok = False
                outcome.cleanup_detail = "no final response to the INVITE after CANCEL"
            outcome.timed_out = outcome.final is None
            return outcome
        if _matches(response, request.call_id, request.cseq, "CANCEL", cancel_branch):
            outcome.steps.append(f"CANCEL -> {response.code}")
            continue
        if not _matches(response, request.call_id, request.cseq, "INVITE", request.branch):
            channel.ignored += 1
            continue
        if response.code < 200:
            outcome.provisional.append(response.code)
            if response.code > 100:
                outcome.progressed = True
                if not cancelled:
                    send_cancel()
            continue
        outcome.final = response
        if response.code < 300:
            outcome.progressed = True
            outcome.answered = True
            _end_answered(channel, request, response, outcome, cleanup_timeout)
        else:
            _ack_non_2xx(channel, request, response, outcome)
        return outcome


# -- Digest (RFC 7616 / RFC 2617 / RFC 8760) -------------------------------------

_ALGORITHMS: dict[str, str] = {"MD5": "md5", "SHA-256": "sha256", "SHA-512-256": "sha512_256"}
STRENGTH = ("SHA-512-256", "SHA-256", "MD5")


def parse_challenge(value: str) -> dict[str, str] | None:
    """Parse one ``Digest k=v, ...`` challenge; None for another scheme."""
    text = value.strip()
    scheme, _, rest = text.partition(" ")
    if scheme.lower() != "digest":
        return None
    params: dict[str, str] = {}
    index = 0
    while index < len(rest):
        while index < len(rest) and rest[index] in " ,\t":
            index += 1
        match = re.match(r"([A-Za-z0-9_-]+)\s*=\s*", rest[index:])
        if match is None:
            break
        key = match.group(1).lower()
        index += match.end()
        if index < len(rest) and rest[index] == '"':
            index += 1
            chars = []
            while index < len(rest) and rest[index] != '"':
                if rest[index] == "\\" and index + 1 < len(rest):
                    index += 1
                chars.append(rest[index])
                index += 1
            index += 1
            params[key] = "".join(chars)
        else:
            end = rest.find(",", index)
            end = len(rest) if end < 0 else end
            params[key] = rest[index:end].strip()
            index = end
    return params


def challenges(response: Response) -> list[dict[str, str]]:
    header = "www-authenticate" if response.code == 401 else "proxy-authenticate"
    result = []
    for value in response.all(header):
        parsed = parse_challenge(value)
        if parsed is not None:
            parsed["_header"] = header
            result.append(parsed)
    return result


def algorithm_of(challenge: dict[str, str]) -> str:
    return (challenge.get("algorithm") or "MD5").upper()


def strongest(items: list[dict[str, str]]) -> dict[str, str] | None:
    supported = [item for item in items if _base_algorithm(algorithm_of(item)) in _ALGORITHMS
                 and _hash_available(_base_algorithm(algorithm_of(item)))]
    for name in STRENGTH:
        for item in supported:
            if _base_algorithm(algorithm_of(item)) == name:
                return item
    return None


def _base_algorithm(name: str) -> str:
    return name[:-5] if name.endswith("-SESS") else name


def _hash_available(name: str) -> bool:
    try:
        hashlib.new(_ALGORITHMS[name])
    except (KeyError, ValueError):
        return False
    return True


def _h(algorithm: str, text: str) -> str:
    return hashlib.new(_ALGORITHMS[algorithm], text.encode("utf-8")).hexdigest()


def digest_response(
    *, algorithm: str, username: str, realm: str, password: str, method: str, uri: str,
    nonce: str, qop: str | None, nc: str, cnonce: str,
) -> str:
    base = _base_algorithm(algorithm)
    ha1 = _h(base, f"{username}:{realm}:{password}")
    if algorithm.endswith("-SESS"):
        ha1 = _h(base, f"{ha1}:{nonce}:{cnonce}")
    ha2 = _h(base, f"{method}:{uri}")
    if qop:
        return _h(base, f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    return _h(base, f"{ha1}:{nonce}:{ha2}")


def authorization(
    challenge: dict[str, str], *, username: str, password: str, method: str, uri: str,
) -> tuple[str, str]:
    """(header name, value) answering ``challenge``; the password stays in memory."""
    algorithm = algorithm_of(challenge)
    realm = challenge.get("realm", "")
    nonce = challenge.get("nonce", "")
    offered = [item.strip().lower() for item in challenge.get("qop", "").split(",") if item.strip()]
    qop = "auth" if "auth" in offered else None
    nc = "00000001"
    cnonce = token(8)
    response = digest_response(
        algorithm=algorithm, username=username, realm=realm, password=password, method=method,
        uri=uri, nonce=nonce, qop=qop, nc=nc, cnonce=cnonce,
    )
    parts = [
        f'username="{username}"', f'realm="{realm}"', f'nonce="{nonce}"', f'uri="{uri}"',
        f'response="{response}"', f"algorithm={algorithm}",
    ]
    if "opaque" in challenge:
        parts.append(f'opaque="{challenge["opaque"]}"')
    if qop:
        parts.extend([f"qop={qop}", f"nc={nc}", f'cnonce="{cnonce}"'])
    name = "Proxy-Authorization" if challenge.get("_header") == "proxy-authenticate" else "Authorization"
    return name, "Digest " + ", ".join(parts)


def truncate(value: str, keep: int = 8) -> str:
    """At most ``keep`` leading characters and never the whole value."""
    keep = min(keep, len(value) // 2)
    return value[:keep] + "..."


def is_internal_realm(realm: str) -> bool:
    text = realm.strip().lower()
    host = text.split(":", 1)[0].strip("[]")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return text.endswith((".local", ".lan", ".internal", ".intranet", ".corp", ".localdomain",
                              ".home.arpa", ".private")) or text == "localhost"
    return address.is_private or address.is_loopback or address.is_link_local
