"""Verify externally issued live-MCP capability grants.

This module intentionally contains no signing or private-key functionality.
Possession of a valid grant is bearer authority unless ``client_id`` comes from
an authenticated launcher or transport rather than an MCP tool argument.
"""

from __future__ import annotations

import base64
from contextlib import closing
import hashlib
import ipaddress
import json
import os
import sqlite3
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from .security import MCPPolicyError

CAPABILITY_API_VERSION = "sippycup.dev/mcp-live-capability/v1"
CAPABILITY_AUDIENCE = "sippycup-mcp-live"
MAX_CAPABILITY_BYTES = 64 * 1024
MAX_PAYLOAD_BYTES = 32 * 1024
MAX_GRANT_LIFETIME_SECONDS = 15 * 60
MAX_CLOCK_SKEW_SECONDS = 30

ACTIONS = frozenset(
    {
        "prepare_assessment",
        "preflight_target",
        "execute_one_call",
        "run_supervised_campaign",
    }
)
TRANSPORTS = frozenset({"udp", "tcp", "tls", "ws", "wss"})
CEILING_KEYS = (
    "calls",
    "packets",
    "bytes",
    "durationSeconds",
    "concurrentCalls",
    "packetsPerSecond",
    "callsPerSecond",
)
_ENVELOPE_KEYS = frozenset({"apiVersion", "alg", "keyId", "payload", "signature"})
_PAYLOAD_KEYS = frozenset(
    {
        "apiVersion",
        "issuer",
        "audience",
        "clientId",
        "action",
        "targetProfileSha256",
        "planSha256",
        "endpoints",
        "ceilings",
        "issuedAt",
        "notBefore",
        "expiresAt",
        "nonce",
    }
)
_ENDPOINT_REQUIRED_KEYS = frozenset({"role", "address", "port", "transport"})
_ENDPOINT_ALLOWED_KEYS = _ENDPOINT_REQUIRED_KEYS | {"tlsServerName"}


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _strict_json(content: bytes, field: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise MCPPolicyError(f"capability {field} contains duplicate fields")
            value[key] = item
        return value

    try:
        return json.loads(content, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MCPPolicyError(f"capability {field} is invalid JSON") from exc


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _short_string(value: Any, field: str, *, maximum: int = 128) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise MCPPolicyError(f"capability {field} must be a short printable string")
    return value


def _decode_base64url(value: Any, field: str, *, maximum: int) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise MCPPolicyError(f"capability {field} must be unpadded base64url")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise MCPPolicyError(f"capability {field} is invalid base64url") from exc
    if len(decoded) > maximum or (
        base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value
    ):
        raise MCPPolicyError(f"capability {field} is not canonical base64url")
    return decoded


def _exact_object(value: Any, keys: frozenset[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise MCPPolicyError(f"capability {field} has missing or unknown fields")
    return value


def _positive_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise MCPPolicyError(f"capability {field} must be a positive integer")
    if value > 2**63 - 1:
        raise MCPPolicyError(f"capability {field} exceeds the supported range")
    return value


def _timestamp(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise MCPPolicyError(f"capability {field} must be an epoch-second integer")
    return value


@dataclass(frozen=True, order=True)
class Endpoint:
    role: str
    address: str
    port: int
    transport: str
    tls_server_name: str | None = None

    @classmethod
    def parse(cls, value: Any) -> "Endpoint":
        if not isinstance(value, dict):
            raise MCPPolicyError("capability endpoint must be an object")
        keys = set(value)
        if not _ENDPOINT_REQUIRED_KEYS <= keys or not keys <= _ENDPOINT_ALLOWED_KEYS:
            raise MCPPolicyError("capability endpoint has missing or unknown fields")
        role = _short_string(value["role"], "endpoint role", maximum=64)
        address_value = _short_string(value["address"], "endpoint address", maximum=64)
        try:
            address = ipaddress.ip_address(address_value)
        except ValueError as exc:
            raise MCPPolicyError(
                "capability endpoints must use literal IP addresses; DNS is forbidden"
            ) from exc
        if address_value != str(address):
            raise MCPPolicyError("capability endpoint address must be canonical")
        port = _positive_integer(value["port"], "endpoint port")
        if port > 65535:
            raise MCPPolicyError("capability endpoint port exceeds 65535")
        transport = _short_string(
            value["transport"], "endpoint transport", maximum=8
        ).lower()
        if transport not in TRANSPORTS or value["transport"] != transport:
            raise MCPPolicyError("capability endpoint transport is not allowlisted")
        tls_name = value.get("tlsServerName")
        if tls_name is not None:
            tls_name = _short_string(tls_name, "TLS server name", maximum=253)
        if transport not in {"tls", "wss"} and tls_name is not None:
            raise MCPPolicyError("TLS server name is only valid for TLS/WSS endpoints")
        return cls(role, str(address), port, transport, tls_name)

    def public(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "role": self.role,
            "address": self.address,
            "port": self.port,
            "transport": self.transport,
        }
        if self.tls_server_name is not None:
            value["tlsServerName"] = self.tls_server_name
        return value


@dataclass(frozen=True)
class Grant:
    issuer: str
    key_id: str
    client_id: str
    action: str
    target_profile_sha256: str
    plan_sha256: str
    endpoints: tuple[Endpoint, ...]
    ceilings: Mapping[str, int]
    issued_at: int
    not_before: int
    expires_at: int
    nonce: str
    artifact_sha256: str

    def public(self) -> dict[str, Any]:
        return {
            "valid": True,
            "issuer": self.issuer,
            "keyId": self.key_id,
            "clientId": self.client_id,
            "action": self.action,
            "targetProfileSha256": self.target_profile_sha256,
            "planSha256": self.plan_sha256,
            "endpoints": [endpoint.public() for endpoint in self.endpoints],
            "ceilings": dict(self.ceilings),
            "issuedAt": self.issued_at,
            "notBefore": self.not_before,
            "expiresAt": self.expires_at,
            "nonce": self.nonce,
            "artifactSha256": self.artifact_sha256,
        }


@dataclass(frozen=True)
class ExpectedBinding:
    """Trusted request context to compare with a signed grant."""

    client_id: str
    action: str
    target_profile_sha256: str
    plan_sha256: str
    endpoints: Sequence[Endpoint]
    requested_ceilings: Mapping[str, int]


@dataclass(frozen=True)
class PinnedInput:
    """Immutable bytes read through a no-symlink descriptor walk."""

    content: bytes
    sha256: str
    size: int


class PinnedInputRoot:
    """Open capability-bound inputs without returning a racy pathname."""

    def __init__(self, root: str | Path):
        supplied = Path(root)
        if supplied.is_symlink() or not supplied.is_dir():
            raise MCPPolicyError("pinned input root must be a real directory")
        self.path = supplied.resolve(strict=True)

    def read(self, relative: str, *, maximum: int = 2 * 1024 * 1024) -> PinnedInput:
        if (
            not isinstance(relative, str)
            or not relative
            or len(relative) > 512
            or relative.startswith("/")
            or "\\" in relative
        ):
            raise MCPPolicyError("pinned input path must be a short POSIX relative path")
        parts = Path(relative).parts
        if any(part in {"", ".", ".."} for part in parts):
            raise MCPPolicyError("pinned input path must remain beneath its root")
        descriptors: list[int] = []
        try:
            current = os.open(
                self.path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            descriptors.append(current)
            for part in parts[:-1]:
                current = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=current,
                )
                descriptors.append(current)
            descriptor = os.open(
                parts[-1],
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current,
            )
            descriptors.append(descriptor)
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise MCPPolicyError(
                    "pinned input must be a single-link regular file"
                )
            if before.st_size > maximum:
                raise MCPPolicyError("pinned input exceeds the size limit")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(descriptor, min(128 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            after = os.fstat(descriptor)
            if len(content) > maximum:
                raise MCPPolicyError("pinned input exceeds the size limit")
            stable_fields = (
                "st_dev",
                "st_ino",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
                raise MCPPolicyError("pinned input changed while it was being read")
            return PinnedInput(content, sha256_bytes(content), len(content))
        except OSError as exc:
            raise MCPPolicyError("pinned input is unavailable or unsafe") from exc
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)


class SignatureVerifier(Protocol):
    def verify(self, key_id: str, payload: bytes, signature: bytes) -> str: ...


class OpenSSLEd25519Verifier:
    """Verify Ed25519 signatures against an operator-owned public-key map."""

    def __init__(
        self,
        public_keys: Mapping[str, tuple[str, str | Path]],
        *,
        openssl: str = "/usr/bin/openssl",
    ):
        if not public_keys:
            raise MCPPolicyError("capability trust store is empty")
        self._keys: dict[str, tuple[str, bytes]] = {}
        for key_id, (supplied_issuer, supplied_path) in public_keys.items():
            key = _short_string(key_id, "key ID", maximum=128)
            issuer = _short_string(supplied_issuer, "trusted issuer", maximum=128)
            path = Path(supplied_path)
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024:
                raise MCPPolicyError("capability public key is unavailable or unsafe")
            content = path.read_bytes()
            if not content.startswith(b"-----BEGIN PUBLIC KEY-----"):
                raise MCPPolicyError("capability public key is not a PEM public key")
            self._keys[key] = (issuer, content)
        executable = Path(openssl)
        if not executable.is_file():
            raise MCPPolicyError("OpenSSL is required for capability verification")
        self._openssl = str(executable.resolve(strict=True))

    def verify(self, key_id: str, payload: bytes, signature: bytes) -> str:
        trusted_key = self._keys.get(key_id)
        if trusted_key is None:
            raise MCPPolicyError("capability key ID is not trusted")
        issuer, public_key_bytes = trusted_key
        with tempfile.TemporaryDirectory(prefix="sippycup-capability-") as directory:
            root = Path(directory)
            payload_path = root / "payload"
            signature_path = root / "signature"
            public_key_path = root / "public.pem"
            payload_path.write_bytes(payload)
            signature_path.write_bytes(signature)
            public_key_path.write_bytes(public_key_bytes)
            try:
                completed = subprocess.run(
                    [
                        self._openssl,
                        "pkeyutl",
                        "-verify",
                        "-pubin",
                        "-inkey",
                        str(public_key_path),
                        "-rawin",
                        "-in",
                        str(payload_path),
                        "-sigfile",
                        str(signature_path),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise MCPPolicyError("capability signature verification failed closed") from exc
        if completed.returncode != 0:
            raise MCPPolicyError("capability signature is invalid")
        return issuer


class ReplayAuditStore:
    """Crash-safe audit log and atomic one-time nonce claim."""

    def __init__(self, state_directory: str | Path):
        supplied = Path(state_directory)
        if supplied.is_symlink() or not supplied.is_dir():
            raise MCPPolicyError("capability state directory must be a real directory")
        root_stat = supplied.stat()
        if root_stat.st_uid != os.geteuid() or root_stat.st_mode & 0o022:
            raise MCPPolicyError(
                "capability state directory must be owner-controlled and not writable by others"
            )
        self.path = supplied.resolve(strict=True) / "capability-audit.sqlite3"
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        if self.path.exists() or self.path.is_symlink():
            state = self.path.lstat()
            if (
                self.path.is_symlink()
                or not stat.S_ISREG(state.st_mode)
                or state.st_uid != os.geteuid()
                or state.st_mode & 0o077
            ):
                raise MCPPolicyError("capability audit database is unsafe")
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _initialize(self) -> None:
        try:
            with closing(self._connect()) as connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS consumed (
                        issuer TEXT NOT NULL,
                        nonce TEXT NOT NULL,
                        consumed_at INTEGER NOT NULL,
                        artifact_sha256 TEXT NOT NULL,
                        PRIMARY KEY (issuer, nonce)
                    );
                    CREATE TABLE IF NOT EXISTS decisions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        decided_at INTEGER NOT NULL,
                        decision TEXT NOT NULL,
                        code TEXT NOT NULL,
                        issuer TEXT,
                        key_id TEXT,
                        nonce TEXT,
                        client_id TEXT,
                        action TEXT,
                        artifact_sha256 TEXT NOT NULL
                    );
                    """
                )
            os.chmod(self.path, 0o600)
        except (OSError, sqlite3.Error, MCPPolicyError) as exc:
            raise MCPPolicyError("capability audit store is unavailable") from exc

    def reject(
        self,
        *,
        artifact_sha256: str,
        code: str,
        issuer: str | None = None,
        key_id: str | None = None,
        nonce: str | None = None,
        client_id: str | None = None,
        action: str | None = None,
    ) -> None:
        self._decision(
            "reject",
            code,
            artifact_sha256,
            issuer,
            key_id,
            nonce,
            client_id,
            action,
        )

    def allow(self, grant: Grant, *, consume: bool) -> None:
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                if consume:
                    connection.execute(
                        """
                        INSERT INTO consumed
                            (issuer, nonce, consumed_at, artifact_sha256)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            grant.issuer,
                            grant.nonce,
                            int(time.time()),
                            grant.artifact_sha256,
                        ),
                    )
                connection.execute(
                    """
                    INSERT INTO decisions
                        (decided_at, decision, code, issuer, key_id, nonce,
                         client_id, action, artifact_sha256)
                    VALUES (?, 'allow', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        int(time.time()),
                        "consumed" if consume else "inspected",
                        grant.issuer,
                        grant.key_id,
                        grant.nonce,
                        grant.client_id,
                        grant.action,
                        grant.artifact_sha256,
                    ),
                )
                connection.commit()
        except sqlite3.IntegrityError as exc:
            self.reject(
                artifact_sha256=grant.artifact_sha256,
                code="replay",
                issuer=grant.issuer,
                key_id=grant.key_id,
                nonce=grant.nonce,
                client_id=grant.client_id,
                action=grant.action,
            )
            raise MCPPolicyError("capability nonce has already been consumed") from exc
        except (OSError, sqlite3.Error, MCPPolicyError) as exc:
            raise MCPPolicyError("capability audit failed closed") from exc

    def _decision(
        self,
        decision: str,
        code: str,
        artifact_sha256: str,
        issuer: str | None,
        key_id: str | None,
        nonce: str | None,
        client_id: str | None,
        action: str | None,
    ) -> None:
        try:
            with closing(self._connect()) as connection:
                connection.execute(
                    """
                    INSERT INTO decisions
                        (decided_at, decision, code, issuer, key_id, nonce,
                         client_id, action, artifact_sha256)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        int(time.time()),
                        decision,
                        code,
                        issuer,
                        key_id,
                        nonce,
                        client_id,
                        action,
                        artifact_sha256,
                    ),
                )
        except (OSError, sqlite3.Error, MCPPolicyError) as exc:
            raise MCPPolicyError("capability audit failed closed") from exc


class CapabilityValidator:
    def __init__(
        self,
        verifier: SignatureVerifier,
        audit_store: ReplayAuditStore,
        *,
        now: Callable[[], int] | None = None,
    ):
        self.verifier = verifier
        self.audit = audit_store
        self._now = now or (lambda: int(time.time()))

    def validate(
        self,
        artifact: bytes,
        expected: ExpectedBinding,
        *,
        consume: bool = True,
    ) -> Grant:
        artifact_hash = sha256_bytes(
            artifact if isinstance(artifact, bytes) else b"<invalid capability type>"
        )
        context: dict[str, str | None] = {
            "issuer": None,
            "key_id": None,
            "nonce": None,
            "client_id": None,
            "action": None,
        }
        try:
            grant = self._validate(artifact, artifact_hash, expected)
            context.update(
                issuer=grant.issuer,
                key_id=grant.key_id,
                nonce=grant.nonce,
                client_id=grant.client_id,
                action=grant.action,
            )
            self.audit.allow(grant, consume=consume)
            return grant
        except MCPPolicyError as exc:
            if str(exc) not in {
                "capability nonce has already been consumed",
                "capability audit failed closed",
            }:
                self.audit.reject(
                    artifact_sha256=artifact_hash,
                    code=_error_code(exc),
                    **context,
                )
            raise

    def _validate(
        self,
        artifact: bytes,
        artifact_hash: str,
        expected: ExpectedBinding,
    ) -> Grant:
        if not isinstance(artifact, bytes) or len(artifact) > MAX_CAPABILITY_BYTES:
            raise MCPPolicyError("capability artifact is missing or too large")
        envelope = _strict_json(artifact, "envelope")
        envelope = _exact_object(envelope, _ENVELOPE_KEYS, "envelope")
        if envelope["apiVersion"] != CAPABILITY_API_VERSION:
            raise MCPPolicyError("capability API version is not supported")
        if envelope["alg"] != "Ed25519":
            raise MCPPolicyError("capability signature algorithm is not supported")
        key_id = _short_string(envelope["keyId"], "key ID")
        payload_bytes = _decode_base64url(
            envelope["payload"], "payload", maximum=MAX_PAYLOAD_BYTES
        )
        signature = _decode_base64url(
            envelope["signature"], "signature", maximum=128
        )
        if len(signature) != 64:
            raise MCPPolicyError("capability Ed25519 signature must be 64 bytes")
        trusted_issuer = self.verifier.verify(key_id, payload_bytes, signature)
        payload = _strict_json(payload_bytes, "signed payload")
        if (
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            != payload_bytes
        ):
            raise MCPPolicyError("capability signed payload is not canonical JSON")
        payload = _exact_object(payload, _PAYLOAD_KEYS, "signed payload")
        if payload["apiVersion"] != CAPABILITY_API_VERSION:
            raise MCPPolicyError("capability payload API version is not supported")
        issuer = _short_string(payload["issuer"], "issuer")
        if issuer != trusted_issuer:
            raise MCPPolicyError("capability issuer does not own the trusted key ID")
        if payload["audience"] != CAPABILITY_AUDIENCE:
            raise MCPPolicyError("capability audience does not match")
        client_id = _short_string(payload["clientId"], "client ID")
        action = _short_string(payload["action"], "action")
        if action not in ACTIONS:
            raise MCPPolicyError("capability action is not allowlisted")
        profile_hash = payload["targetProfileSha256"]
        plan_hash = payload["planSha256"]
        if not _is_sha256(profile_hash) or not _is_sha256(plan_hash):
            raise MCPPolicyError("capability artifact digests must be lowercase SHA-256")
        endpoints_value = payload["endpoints"]
        if not isinstance(endpoints_value, list) or not endpoints_value:
            raise MCPPolicyError("capability endpoints must be a non-empty array")
        endpoints = tuple(Endpoint.parse(value) for value in endpoints_value)
        sorted_endpoints = tuple(
            sorted(
                endpoints,
                key=lambda endpoint: (
                    endpoint.role,
                    endpoint.address,
                    endpoint.port,
                    endpoint.transport,
                    endpoint.tls_server_name or "",
                ),
            )
        )
        if sorted_endpoints != endpoints or len(set(endpoints)) != len(endpoints):
            raise MCPPolicyError("capability endpoints must be sorted and unique")
        ceilings_value = _exact_object(
            payload["ceilings"], frozenset(CEILING_KEYS), "ceilings"
        )
        ceilings = {
            key: _positive_integer(ceilings_value[key], f"ceiling {key}")
            for key in CEILING_KEYS
        }
        issued_at = _timestamp(payload["issuedAt"], "issuedAt")
        not_before = _timestamp(payload["notBefore"], "notBefore")
        expires_at = _timestamp(payload["expiresAt"], "expiresAt")
        if not issued_at <= not_before < expires_at:
            raise MCPPolicyError("capability time window is inconsistent")
        if expires_at - issued_at > MAX_GRANT_LIFETIME_SECONDS:
            raise MCPPolicyError("capability lifetime exceeds 15 minutes")
        now = int(self._now())
        if now + MAX_CLOCK_SKEW_SECONDS < not_before:
            raise MCPPolicyError("capability is not yet valid")
        if now >= expires_at:
            raise MCPPolicyError("capability has expired")
        nonce = _short_string(payload["nonce"], "nonce", maximum=128)
        try:
            nonce_bytes = bytes.fromhex(nonce)
        except ValueError as exc:
            raise MCPPolicyError("capability nonce must be lowercase hexadecimal") from exc
        if len(nonce_bytes) < 16 or nonce != nonce.lower():
            raise MCPPolicyError("capability nonce must contain at least 128 random bits")
        grant = Grant(
            issuer,
            key_id,
            client_id,
            action,
            profile_hash,
            plan_hash,
            endpoints,
            ceilings,
            issued_at,
            not_before,
            expires_at,
            nonce,
            artifact_hash,
        )
        _match_binding(grant, expected)
        return grant


def _match_binding(grant: Grant, expected: ExpectedBinding) -> None:
    if grant.client_id != expected.client_id:
        raise MCPPolicyError("capability client identity does not match")
    if grant.action != expected.action:
        raise MCPPolicyError("capability action does not match")
    if grant.target_profile_sha256 != expected.target_profile_sha256:
        raise MCPPolicyError("capability target-profile digest does not match")
    if grant.plan_sha256 != expected.plan_sha256:
        raise MCPPolicyError("capability reviewed-plan digest does not match")
    if grant.endpoints != tuple(expected.endpoints):
        raise MCPPolicyError("capability literal endpoints do not match")
    if set(expected.requested_ceilings) != set(CEILING_KEYS):
        raise MCPPolicyError("requested traffic ceilings are incomplete")
    for key in CEILING_KEYS:
        requested = _positive_integer(
            expected.requested_ceilings[key], f"requested ceiling {key}"
        )
        if requested > grant.ceilings[key]:
            raise MCPPolicyError(f"requested traffic ceiling {key} exceeds the grant")


def _error_code(error: Exception) -> str:
    text = str(error)
    if "signature" in text or "key ID" in text:
        return "signature"
    if "expired" in text or "not yet" in text or "lifetime" in text:
        return "time"
    if "digest" in text:
        return "digest"
    if "endpoint" in text or "DNS" in text:
        return "endpoint"
    if "ceiling" in text:
        return "ceiling"
    if "action" in text:
        return "action"
    if "client" in text or "audience" in text:
        return "identity"
    return "malformed"
