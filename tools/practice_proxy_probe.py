#!/usr/bin/env python3
"""Raw SIP probes for the practice proxy gate (bn-2g0).

Runs inside the toolbox container in the practice target's loopback-only
namespace (``./bin/sippycup --practice -- python3 ...``). Every request goes
over UDP to a loopback literal: the proxy or the practice Asterisk. It proves
the proxy's shape (407 on INVITE, 401 on REGISTER, 404 for an in-dialog
request without its Route) and the trust decision between the proxy and
Asterisk (only the per-start trunk token, and only from the proxy address,
skips Asterisk's Digest challenge; a client-supplied token is stripped).

Usage: practice_proxy_probe.py PROXY ADDRESS PASSWORD_FILE TOKEN_FILE

Prints one JSON object. Neither the password nor the token is printed.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import socket
import sys
import time

CALLER = "127.0.0.1"
ACCOUNT = "practice"
TIMEOUT = 3.0


def _header(message: str, name: str) -> str | None:
    match = re.search(rf"^{name}:\s*(.*)$", message, re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip() if match else None


def _status(message: str) -> int | None:
    match = re.match(r"SIP/2\.0 (\d{3})", message)
    return int(match.group(1)) if match else None


class Probe:
    def __init__(self, source: str, destination: str) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((source, 0))
        self.socket.settimeout(0.2)
        self.source = source
        self.port = self.socket.getsockname()[1]
        self.destination = destination
        self.call_id = secrets.token_hex(12) + "@" + source
        self.tag = secrets.token_hex(6)
        self.cseq = 1

    def close(self) -> None:
        self.socket.close()

    def request(
        self,
        method: str,
        uri: str,
        *,
        to_user: str,
        to_tag: str | None = None,
        extra: tuple[str, ...] = (),
        cseq: int | None = None,
    ) -> tuple[str | None, str]:
        """Send one request; return the final response (or None) and the branch."""
        branch = "z9hG4bK" + secrets.token_hex(8)
        to = f"<sip:{to_user}@{self.destination}>" + (f";tag={to_tag}" if to_tag else "")
        lines = [
            f"{method} {uri} SIP/2.0",
            f"Via: SIP/2.0/UDP {self.source}:{self.port};rport;branch={branch}",
            "Max-Forwards: 70",
            f"From: <sip:{ACCOUNT}@{self.destination}>;tag={self.tag}",
            f"To: {to}",
            f"Call-ID: {self.call_id}",
            f"CSeq: {cseq if cseq is not None else self.cseq} {method}",
            f"Contact: <sip:{ACCOUNT}@{self.source}:{self.port}>",
            "User-Agent: sippycup practice proxy gate probe",
            *extra,
            "Content-Length: 0",
            "",
            "",
        ]
        self.socket.sendto("\r\n".join(lines).encode(), (self.destination, 5060))
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            try:
                data, _ = self.socket.recvfrom(65535)
            except TimeoutError:
                continue
            text = data.decode("utf-8", errors="replace")
            status = _status(text)
            if status is None or _header(text, "Call-ID") != self.call_id:
                continue
            if status >= 200:
                return text, branch
        return None, branch

    def ack(self, uri: str, response: str, branch: str, cseq: int) -> None:
        """ACK a non-2xx final response (same branch, hop by hop)."""
        lines = [
            f"ACK {uri} SIP/2.0",
            f"Via: SIP/2.0/UDP {self.source}:{self.port};rport;branch={branch}",
            "Max-Forwards: 70",
            f"From: <sip:{ACCOUNT}@{self.destination}>;tag={self.tag}",
            f"To: {_header(response, 'To')}",
            f"Call-ID: {self.call_id}",
            f"CSeq: {cseq} ACK",
            "Content-Length: 0",
            "",
            "",
        ]
        self.socket.sendto("\r\n".join(lines).encode(), (self.destination, 5060))


def _challenge(response: str, header: str) -> dict[str, str]:
    value = _header(response, header) or ""
    return dict(re.findall(r'(\w+)="?([^",]*)"?', value))


def invite(
    source: str,
    destination: str,
    user: str,
    *,
    extra: tuple[str, ...] = (),
    password: str | None = None,
) -> dict[str, object]:
    """One INVITE transaction (answering a 407 once when a password is given)."""
    probe = Probe(source, destination)
    uri = f"sip:{user}@{destination}"
    try:
        response, branch = probe.request("INVITE", uri, to_user=user, extra=extra)
        result: dict[str, object] = {"status": _status(response) if response else None}
        if response is not None and (_status(response) or 0) >= 300:
            probe.ack(uri, response, branch, probe.cseq)
        if response is not None and _status(response) == 407:
            challenge = _challenge(response, "Proxy-Authenticate")
            result["challengeRealm"] = challenge.get("realm")
            result["challengeQop"] = challenge.get("qop")
            if password is not None:
                probe.cseq += 1
                nonce = challenge.get("nonce", "")
                realm = challenge.get("realm", "")
                cnonce = secrets.token_hex(8)
                ha1 = hashlib.md5(f"{ACCOUNT}:{realm}:{password}".encode()).hexdigest()
                ha2 = hashlib.md5(f"INVITE:{uri}".encode()).hexdigest()
                digest = hashlib.md5(
                    f"{ha1}:{nonce}:00000001:{cnonce}:auth:{ha2}".encode()
                ).hexdigest()
                authorization = (
                    f'Proxy-Authorization: Digest username="{ACCOUNT}", realm="{realm}", '
                    f'nonce="{nonce}", uri="{uri}", response="{digest}", algorithm=MD5, '
                    f'qop=auth, nc=00000001, cnonce="{cnonce}"'
                )
                response, branch = probe.request(
                    "INVITE", uri, to_user=user, extra=(*extra, authorization)
                )
                result["authenticatedStatus"] = _status(response) if response else None
                if response is not None and (_status(response) or 0) >= 300:
                    probe.ack(uri, response, branch, probe.cseq)
        elif response is not None and _status(response) == 401:
            result["challengeRealm"] = _challenge(response, "WWW-Authenticate").get("realm")
        return result
    finally:
        probe.close()


def register(source: str, destination: str) -> dict[str, object]:
    probe = Probe(source, destination)
    try:
        response, _ = probe.request("REGISTER", f"sip:{destination}", to_user=ACCOUNT)
        return {
            "status": _status(response) if response else None,
            "challengeRealm": _challenge(response, "WWW-Authenticate").get("realm")
            if response
            else None,
        }
    finally:
        probe.close()


def stray_bye(source: str, destination: str) -> dict[str, object]:
    """An in-dialog request (To tag set) that carries no Route header."""
    probe = Probe(source, destination)
    try:
        response, _ = probe.request(
            "BYE", f"sip:echo@{destination}", to_user="echo", to_tag=secrets.token_hex(6)
        )
        return {"status": _status(response) if response else None}
    finally:
        probe.close()


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print(__doc__, file=sys.stderr)
        return 2
    proxy, address, password_file, token_file = argv[1:]
    with open(password_file, encoding="utf-8") as handle:
        password = handle.read().strip()
    with open(token_file, encoding="utf-8") as handle:
        token = handle.read().strip()
    forged = "X-Sippycup-Trunk: " + secrets.token_hex(24)
    real = "X-Sippycup-Trunk: " + token
    results = {
        "proxy_invite_unauthenticated": invite(CALLER, proxy, "echo"),
        "proxy_register_unauthenticated": register(CALLER, proxy),
        "proxy_bye_without_route": stray_bye(CALLER, proxy),
        # A client-supplied token is stripped: after the 407 the INVITE is
        # forwarded with the proxy's own token and reaches the destination.
        "proxy_invite_client_token": invite(
            CALLER, proxy, "busy", extra=(forged,), password=password
        ),
        "asterisk_forged_token_from_caller": invite(CALLER, address, "busy", extra=(forged,)),
        "asterisk_no_token_from_proxy_address": invite(proxy, address, "busy"),
        "asterisk_forged_token_from_proxy_address": invite(proxy, address, "busy", extra=(forged,)),
        "asterisk_real_token_from_caller": invite(CALLER, address, "busy", extra=(real,)),
        "asterisk_real_token_from_proxy_address": invite(proxy, address, "busy", extra=(real,)),
    }
    del password, token, real
    print(json.dumps(results, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
