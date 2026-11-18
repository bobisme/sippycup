"""Bounded TLS handshake probes and offline certificate parsing.

Each probe is one TCP connection to the literal address carrying one TLS
handshake with the reviewed server name as SNI; it is closed right after the
handshake and never carries SIP. A probe the local TLS library cannot offer
(checked first against memory buffers, which sends nothing) is reported as
``untestable`` and not sent. Certificates are parsed offline with
``openssl x509``.
"""

from __future__ import annotations

import re
import shutil
import socket
import ssl
import subprocess
import time
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sippycup.options import _classify_os_error, _literal, _tls_context

from .budget import Budget
from .sip import Endpoint

V = ssl.TLSVersion

# (label, minimum, maximum, cipher string or None)
PROTOCOL_PROBES: tuple[tuple[str, Any, Any, str | None], ...] = (
    ("TLS 1.0", V.TLSv1, V.TLSv1, "DEFAULT:@SECLEVEL=0"),
    ("TLS 1.1", V.TLSv1_1, V.TLSv1_1, "DEFAULT:@SECLEVEL=0"),
    ("TLS 1.2", V.TLSv1_2, V.TLSv1_2, None),
    ("TLS 1.3", V.TLSv1_3, V.TLSv1_3, None),
)
# (label, cipher string, class): offered with TLS 1.0-1.2 only, since TLS 1.3
# suites cannot be restricted and are never weak.
CIPHER_PROBES: tuple[tuple[str, str, str], ...] = (
    ("NULL", "eNULL:@SECLEVEL=0", "broken"),
    ("EXPORT", "EXP:@SECLEVEL=0", "broken"),
    ("RC4", "RC4:@SECLEVEL=0", "weak"),
    ("3DES", "3DES:@SECLEVEL=0", "weak"),
    ("anonymous", "aNULL:!eNULL:@SECLEVEL=0", "broken"),
)


@dataclass
class ProbeResult:
    label: str
    outcome: str  # accepted | rejected | untestable | unreachable | timeout
    version: str | None = None
    cipher: str | None = None
    detail: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {key: value for key, value in self.__dict__.items() if value is not None}


def probe_context(minimum: Any, maximum: Any, ciphers: str | None) -> ssl.SSLContext | str:
    """A client context offering only what the probe tests, or why it cannot."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = minimum
            context.maximum_version = maximum
        except (ValueError, ssl.SSLError) as error:
            return f"local TLS library cannot restrict versions: {error}"
        if ciphers is not None:
            try:
                context.set_ciphers(ciphers)
            except ssl.SSLError:
                return "the local TLS library has no such cipher suite to offer"
    # Build a ClientHello into memory: proves it can be offered, sends nothing.
    probe = context.wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO(), server_hostname="probe.invalid")
    try:
        probe.do_handshake()
    except ssl.SSLWantReadError:
        return context
    except ssl.SSLError as error:
        return f"the local TLS library cannot offer it ({error.reason or error})"
    return context


def handshake(
    endpoint: Endpoint,
    context: ssl.SSLContext,
    *,
    label: str,
    budget: Budget,
    timeout: float,
) -> tuple[ProbeResult, bytes | None]:
    """One counted connection carrying one handshake; returns (result, leaf DER)."""
    literal, family = _literal(endpoint.address)
    server_name = endpoint.server_name or literal.split("%", 1)[0]
    budget.spend(f"TLS handshake ({label})")
    sock = socket.socket(family, socket.SOCK_STREAM)
    connection: ssl.SSLSocket | None = None
    try:
        sock.settimeout(timeout)
        try:
            sock.connect((literal, endpoint.port))
        except OSError as error:
            outcome, category = _classify_os_error(error)
            return ProbeResult(label, "timeout" if category == "timeout" else "unreachable",
                               detail=f"{category}: {error}"), None
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                connection = context.wrap_socket(sock, server_hostname=server_name,
                                                 do_handshake_on_connect=False)
                connection.settimeout(timeout)
                connection.do_handshake()
        except ssl.SSLCertVerificationError as error:
            return ProbeResult(label, "verify_failed",
                               detail=f"{error.verify_message or error} (code {error.verify_code})"), None
        except (socket.timeout, TimeoutError):
            return ProbeResult(label, "timeout", detail="no handshake answer before the deadline"), None
        except (ssl.SSLError, OSError) as error:
            reason = getattr(error, "reason", None) or type(error).__name__
            return ProbeResult(label, "rejected", detail=str(reason)), None
        cipher = connection.cipher()
        der = connection.getpeercert(binary_form=True)
        return ProbeResult(label, "accepted", version=connection.version(),
                           cipher=cipher[0] if cipher else None), der
    finally:
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass
        sock.close()


def verified_context(endpoint: Endpoint) -> ssl.SSLContext:
    return _tls_context(ca_file=None, insecure=False, ca_data=endpoint.ca_data)


def unverified_context() -> ssl.SSLContext:
    """Only to READ a certificate that failed verification; carries no SIP.

    Security level 0 so a weak (small-key or SHA-1) certificate can still be
    read and reported instead of failing the handshake locally.
    """
    context = _tls_context(ca_file=None, insecure=True)
    try:
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return context


# -- certificate parsing ---------------------------------------------------------

_SIGNATURE = re.compile(r"Signature Algorithm:\s*(\S+)")
_KEY_ALGORITHM = re.compile(r"Public Key Algorithm:\s*(\S+)")
_KEY_BITS = re.compile(r"Public-Key:\s*\((\d+) bit\)")
_KEYID = re.compile(r"(?:keyid:)?([0-9A-F]{2}(?::[0-9A-F]{2})+)")


def openssl_path() -> str | None:
    return shutil.which("openssl")


def parse_certificate(der: bytes, openssl: str) -> dict[str, Any]:
    """Facts from a DER certificate via ``openssl x509`` (offline)."""
    def run(*arguments: str) -> str:
        completed = subprocess.run(
            [openssl, "x509", "-inform", "DER", "-noout", *arguments],
            input=der, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False,
        )
        if completed.returncode != 0:
            raise ValueError(completed.stderr.decode("utf-8", "replace").strip()[:200] or "openssl x509 failed")
        return completed.stdout.decode("utf-8", "replace")

    text = run("-text")
    names = run("-nameopt", "RFC2253", "-subject", "-issuer", "-startdate", "-enddate")
    fields: dict[str, str] = {}
    for line in names.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            fields[key.strip()] = value.strip()
    signature = _SIGNATURE.search(text)
    key_algorithm = _KEY_ALGORITHM.search(text)
    key_bits = _KEY_BITS.search(text)
    lines = text.splitlines()

    def after(marker: str) -> str | None:
        for index, line in enumerate(lines):
            if marker in line and index + 1 < len(lines):
                return lines[index + 1].strip()
        return None

    san_text = after("X509v3 Subject Alternative Name")
    san: list[str] = []
    if san_text:
        san = [item.strip() for item in san_text.split(",") if item.strip()]
    ski = after("X509v3 Subject Key Identifier")
    aki_text = after("X509v3 Authority Key Identifier")
    aki_match = _KEYID.search(aki_text or "")
    not_after = fields.get("notAfter")
    not_before = fields.get("notBefore")
    return {
        "subject": fields.get("subject"),
        "issuer": fields.get("issuer"),
        "notBefore": _iso(not_before),
        "notAfter": _iso(not_after),
        "signatureAlgorithm": signature.group(1) if signature else None,
        "keyAlgorithm": key_algorithm.group(1) if key_algorithm else None,
        "keyBits": int(key_bits.group(1)) if key_bits else None,
        "subjectAltName": san,
        "subjectKeyId": ski,
        "authorityKeyId": aki_match.group(1) if aki_match else None,
    }


def _iso(value: str | None) -> str | None:
    if not value:
        return None
    try:
        seconds = ssl.cert_time_to_seconds(value)
    except ValueError:
        return None
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat().replace("+00:00", "Z")


def self_signed(facts: dict[str, Any]) -> bool:
    if not facts.get("subject") or facts.get("subject") != facts.get("issuer"):
        return False
    aki = facts.get("authorityKeyId")
    return aki is None or aki == facts.get("subjectKeyId")


def san_covers(facts: dict[str, Any], name: str, *, is_ip: bool) -> bool:
    for item in facts.get("subjectAltName") or []:
        kind, _, value = item.partition(":")
        kind = kind.strip().lower()
        value = value.strip().lower()
        if is_ip and kind == "ip address" and value == name.lower():
            return True
        if not is_ip and kind == "dns":
            if value == name.lower():
                return True
            if value.startswith("*.") and "." in name:
                if name.lower().split(".", 1)[1] == value[2:] and name.split(".", 1)[0]:
                    return True
    return False


def weak_key(facts: dict[str, Any]) -> bool:
    algorithm = (facts.get("keyAlgorithm") or "").lower()
    bits = facts.get("keyBits")
    if "dsa" in algorithm and "ecdsa" not in algorithm:
        return True
    if bits is None:
        return False
    if "rsa" in algorithm:
        return bits < 2048
    if "ec" in algorithm:
        return bits < 256
    return False


def weak_signature(facts: dict[str, Any]) -> bool:
    algorithm = (facts.get("signatureAlgorithm") or "").lower()
    return "md5" in algorithm or "sha1" in algorithm or algorithm.endswith("-with-sha1")


def days_left(facts: dict[str, Any], now: datetime) -> float | None:
    value = facts.get("notAfter")
    if not value:
        return None
    end = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return (end - now).total_seconds() / 86400


def not_yet_valid(facts: dict[str, Any], now: datetime) -> bool:
    value = facts.get("notBefore")
    if not value:
        return False
    return datetime.fromisoformat(value.replace("Z", "+00:00")) > now


def monotonic() -> float:
    return time.monotonic()
