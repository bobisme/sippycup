"""Reviewed TLS server names and trust anchors for a pinned literal address.

A target is always reached at a literal, approved IP address. Over TLS the
certificate usually names a DNS host instead, so a profile or a campaign
target may carry a reviewed *server name* and, optionally, a reviewed *trust
anchor* (a PEM CA file beneath the work directory). The name is used only for
SNI, certificate verification, and the SIP domain in the request URI; it is
never resolved through DNS. Without a CA file the system trust store is used.
Nothing here can turn verification off.

Everything in this module is offline: it validates strings and reads local
files, and never opens a socket or resolves a name.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import ssl
import stat
from pathlib import Path

SYSTEM_CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
MAX_SERVER_NAME = 253
MAX_CA_REFERENCE = 255
MAX_CA_BYTES = 1024 * 1024
WORK_PREFIX = "work/"

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_CA_REFERENCE = re.compile(r"work/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_PLACEHOLDER_LABELS = {"changeme", "change-me", "change_me", "example", "placeholder", "todo", "tbd"}
_RESERVED_SUFFIXES = (".invalid", ".example", ".localhost")
_RESERVED_NAMES = {"localhost", "invalid", "example"}


class TrustError(ValueError):
    """A server name or trust anchor cannot be used safely."""


def validate_server_name(value: object) -> str:
    """Return ``value`` when it is a reviewable DNS host name; raise otherwise.

    The grammar is LDH (letters, digits, hyphen) labels of 1-63 characters,
    lowercase, at most 253 characters, with no trailing dot. An IP literal,
    a wildcard, an all-numeric final label, and reserved or placeholder names
    (``localhost``, ``*.invalid``, ``example.com``, ``changeme``, ...) are
    refused so a template value can never pass review by accident.
    """
    if not isinstance(value, str) or not value:
        raise TrustError("TLS server name must be a non-empty string")
    if len(value) > MAX_SERVER_NAME:
        raise TrustError(f"TLS server name must be at most {MAX_SERVER_NAME} characters")
    if "*" in value:
        raise TrustError("TLS server name must not be a wildcard")
    if value != value.lower():
        raise TrustError("TLS server name must be lowercase")
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        pass
    else:
        raise TrustError(
            "TLS server name must be a DNS name, not an IP address (an IP literal is "
            "verified against the certificate's IP SAN without a server name)"
        )
    labels = value.split(".")
    if any(_LABEL.fullmatch(label) is None for label in labels):
        raise TrustError(
            "TLS server name must be dot-separated labels of 1-63 lowercase letters, "
            "digits, and inner hyphens, with no trailing dot"
        )
    if labels[-1].isdigit():
        raise TrustError("TLS server name must not end in an all-numeric label")
    if (
        value in _RESERVED_NAMES
        or value.endswith(_RESERVED_SUFFIXES)
        or value in {"example.com", "example.net", "example.org"}
        or value.endswith((".example.com", ".example.net", ".example.org"))
        or any(label in _PLACEHOLDER_LABELS for label in labels)
    ):
        raise TrustError(f"TLS server name {value!r} is a reserved or placeholder name")
    return value


def validate_ca_reference(value: object) -> str:
    """Return a ``work/...`` CA file reference when its spelling is safe."""
    if not isinstance(value, str) or not value:
        raise TrustError("TLS CA file must be a non-empty string")
    if len(value) > MAX_CA_REFERENCE:
        raise TrustError(f"TLS CA file must be at most {MAX_CA_REFERENCE} characters")
    if _CA_REFERENCE.fullmatch(value) is None or any(
        part in {".", ".."} for part in value.split("/")
    ):
        raise TrustError(
            "TLS CA file must be a relative path beneath the work directory, spelled "
            "work/... (letters, digits, . _ - and /; no .. or absolute paths)"
        )
    return value


def validate_sha256(value: object) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise TrustError("TLS CA digest must be a lowercase SHA-256 hex digest")
    return value


def default_work_root() -> Path:
    """The repository work/ tree on the host, or its /work mount in the image."""
    override = os.environ.get("SIPPYCUP_WORK_ROOT")
    if override:
        return Path(override)
    repository = Path(__file__).resolve().parents[2] / "work"
    if repository.is_dir():
        return repository
    return Path("/work")


def resolve_ca_path(reference: str, work_root: Path | None = None) -> Path:
    """Map ``work/REL`` to the work directory this process sees."""
    reference = validate_ca_reference(reference)
    root = Path(work_root) if work_root is not None else default_work_root()
    path = root / reference[len(WORK_PREFIX):]
    try:
        resolved = path.resolve(strict=True)
        root_resolved = root.resolve(strict=True)
    except OSError as error:
        raise TrustError(f"TLS CA file {reference} cannot be read: {error.strerror or error}") from error
    try:
        resolved.relative_to(root_resolved)
    except ValueError as error:
        raise TrustError(f"TLS CA file {reference} resolves outside the work directory") from error
    return resolved


def read_ca(reference: str, work_root: Path | None = None) -> tuple[bytes, str]:
    """Read, bound, and parse a PEM trust anchor; return (bytes, sha256)."""
    path = resolve_ca_path(reference, work_root)
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise TrustError(f"TLS CA file {reference} cannot be opened: {error.strerror}") from error
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise TrustError(f"TLS CA file {reference} is not a regular file")
        if status.st_size > MAX_CA_BYTES:
            raise TrustError(f"TLS CA file {reference} exceeds {MAX_CA_BYTES} bytes")
        chunks = []
        size = 0
        while chunk := os.read(descriptor, 65536):
            size += len(chunk)
            if size > MAX_CA_BYTES:
                raise TrustError(f"TLS CA file {reference} exceeds {MAX_CA_BYTES} bytes")
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    check_pem(data, reference)
    return data, hashlib.sha256(data).hexdigest()


def check_pem(data: bytes, label: str = "TLS CA file") -> None:
    """Refuse bytes that do not load as at least one PEM CA certificate."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise TrustError(f"{label} is not ASCII PEM") from error
    if "-----BEGIN CERTIFICATE-----" not in text:
        raise TrustError(f"{label} contains no PEM certificate")
    if "PRIVATE KEY-----" in text:
        raise TrustError(f"{label} contains a private key; supply only the CA certificate")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        context.load_verify_locations(cadata=text)
    except ssl.SSLError as error:
        raise TrustError(f"{label} does not load as a CA certificate: {error}") from error


def read_verified_ca(reference: str, expected_sha256: str, work_root: Path | None = None) -> bytes:
    """Return the CA bytes only when they still match the reviewed digest."""
    expected = validate_sha256(expected_sha256)
    data, actual = read_ca(reference, work_root)
    if actual != expected:
        raise TrustError(
            f"TLS CA file {reference} changed since it was reviewed: SHA-256 {actual} "
            f"differs from the frozen {expected}"
        )
    return data


def write_private_copy(data: bytes, path: Path) -> Path:
    """Write verified CA bytes to a new mode-0600 file (never through a link)."""
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
    return path
