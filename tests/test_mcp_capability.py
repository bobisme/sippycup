from __future__ import annotations

import base64
import concurrent.futures
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

from sippycup_mcp.capability import (
    CAPABILITY_API_VERSION,
    CapabilityValidator,
    Endpoint,
    ExpectedBinding,
    OpenSSLEd25519Verifier,
    PinnedInputRoot,
    ReplayAuditStore,
)
from sippycup_mcp.security import MCPPolicyError


NOW = 2_000_000_000
CEILINGS = {
    "calls": 1,
    "packets": 100,
    "bytes": 100_000,
    "durationSeconds": 30,
    "concurrentCalls": 1,
    "packetsPerSecond": 20,
    "callsPerSecond": 1,
}
ENDPOINTS = (
    Endpoint("media", "192.0.2.10", 10000, "udp"),
    Endpoint("signaling", "192.0.2.10", 5061, "tls", "voice.example.test"),
)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


class CapabilityFixture:
    def __init__(self, root: Path):
        self.root = root
        self.private_key = root / "private.pem"
        self.public_key = root / "public.pem"
        subprocess.run(
            [
                "/usr/bin/openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(self.private_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "/usr/bin/openssl",
                "pkey",
                "-in",
                str(self.private_key),
                "-pubout",
                "-out",
                str(self.public_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def payload(self, **changes: object) -> dict[str, object]:
        value: dict[str, object] = {
            "apiVersion": CAPABILITY_API_VERSION,
            "issuer": "quad-security",
            "audience": "sippycup-mcp-live",
            "clientId": "trusted-launcher:alice",
            "action": "execute_one_call",
            "targetProfileSha256": hashlib.sha256(b"profile").hexdigest(),
            "planSha256": hashlib.sha256(b"plan").hexdigest(),
            "endpoints": [
                {
                    "role": endpoint.role,
                    "address": endpoint.address,
                    "port": endpoint.port,
                    "transport": endpoint.transport,
                    **(
                        {"tlsServerName": endpoint.tls_server_name}
                        if endpoint.tls_server_name
                        else {}
                    ),
                }
                for endpoint in ENDPOINTS
            ],
            "ceilings": dict(CEILINGS),
            "issuedAt": NOW - 10,
            "notBefore": NOW - 5,
            "expiresAt": NOW + 300,
            "nonce": "0123456789abcdef0123456789abcdef",
        }
        value.update(changes)
        return value

    def issue(
        self,
        *,
        payload: dict[str, object] | None = None,
        payload_bytes: bytes | None = None,
        key_id: str = "operator-2026",
    ) -> bytes:
        encoded = payload_bytes if payload_bytes is not None else canonical(
            payload or self.payload()
        )
        payload_path = self.root / "payload"
        signature_path = self.root / "signature"
        payload_path.write_bytes(encoded)
        subprocess.run(
            [
                "/usr/bin/openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(self.private_key),
                "-rawin",
                "-in",
                str(payload_path),
                "-out",
                str(signature_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return canonical(
            {
                "apiVersion": CAPABILITY_API_VERSION,
                "alg": "Ed25519",
                "keyId": key_id,
                "payload": b64(encoded),
                "signature": b64(signature_path.read_bytes()),
            }
        )

    def binding(self, **changes: object) -> ExpectedBinding:
        values: dict[str, object] = {
            "client_id": "trusted-launcher:alice",
            "action": "execute_one_call",
            "target_profile_sha256": hashlib.sha256(b"profile").hexdigest(),
            "plan_sha256": hashlib.sha256(b"plan").hexdigest(),
            "endpoints": ENDPOINTS,
            "requested_ceilings": dict(CEILINGS),
        }
        values.update(changes)
        return ExpectedBinding(**values)  # type: ignore[arg-type]


class CapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = CapabilityFixture(self.root)
        self.store = ReplayAuditStore(self.root)
        self.validator = CapabilityValidator(
            OpenSSLEd25519Verifier(
                {"operator-2026": ("quad-security", self.fixture.public_key)}
            ),
            self.store,
            now=lambda: NOW,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_known_good_grant_is_consumed_once_and_audited(self) -> None:
        artifact = self.fixture.issue()
        grant = self.validator.validate(artifact, self.fixture.binding())
        self.assertEqual(grant.action, "execute_one_call")
        self.assertNotIn("signature", json.dumps(grant.public()))
        with self.assertRaisesRegex(MCPPolicyError, "already been consumed"):
            self.validator.validate(artifact, self.fixture.binding())
        restarted = CapabilityValidator(
            OpenSSLEd25519Verifier(
                {"operator-2026": ("quad-security", self.fixture.public_key)}
            ),
            ReplayAuditStore(self.root),
            now=lambda: NOW,
        )
        with self.assertRaisesRegex(MCPPolicyError, "already been consumed"):
            restarted.validate(artifact, self.fixture.binding())
        with closing(sqlite3.connect(self.store.path)) as connection:
            decisions = connection.execute(
                "SELECT decision, code FROM decisions ORDER BY id"
            ).fetchall()
        self.assertEqual(decisions, [("allow", "consumed"), ("reject", "replay"), ("reject", "replay")])

    def test_inspection_does_not_consume_grant(self) -> None:
        artifact = self.fixture.issue()
        self.validator.validate(artifact, self.fixture.binding(), consume=False)
        self.validator.validate(artifact, self.fixture.binding(), consume=True)

    def test_tamper_unknown_key_and_noncanonical_payload_fail(self) -> None:
        artifact = bytearray(self.fixture.issue())
        artifact[-3] ^= 1
        for candidate in (
            bytes(artifact),
            self.fixture.issue(key_id="untrusted"),
            self.fixture.issue(
                payload_bytes=json.dumps(self.fixture.payload(), indent=2).encode()
            ),
        ):
            with self.subTest(candidate=candidate[:30]), self.assertRaises(MCPPolicyError):
                self.validator.validate(candidate, self.fixture.binding(), consume=False)

    def test_duplicate_envelope_fields_fail(self) -> None:
        artifact = self.fixture.issue()
        duplicate = artifact[:-1] + b',"alg":"Ed25519"}'
        with self.assertRaisesRegex(MCPPolicyError, "duplicate"):
            self.validator.validate(duplicate, self.fixture.binding(), consume=False)

    def test_time_identity_action_and_digest_confusion_fail_closed(self) -> None:
        cases = (
            ({"expiresAt": NOW}, self.fixture.binding()),
            ({"notBefore": NOW + 60}, self.fixture.binding()),
            ({"expiresAt": NOW + 901}, self.fixture.binding()),
            ({"issuer": "impersonated-issuer"}, self.fixture.binding()),
            ({}, self.fixture.binding(client_id="self-asserted-client")),
            ({}, self.fixture.binding(action="preflight_target")),
            ({}, self.fixture.binding(plan_sha256="0" * 64)),
            ({}, self.fixture.binding(target_profile_sha256="0" * 64)),
        )
        for payload_changes, binding in cases:
            with self.subTest(payload_changes=payload_changes, binding=binding):
                artifact = self.fixture.issue(
                    payload=self.fixture.payload(**payload_changes)
                )
                with self.assertRaises(MCPPolicyError):
                    self.validator.validate(artifact, binding, consume=False)

    def test_dns_drift_duplicate_endpoint_and_endpoint_changes_fail(self) -> None:
        dns = self.fixture.payload()
        dns["endpoints"] = [
            {
                "role": "signaling",
                "address": "voice.example.test",
                "port": 5060,
                "transport": "udp",
            }
        ]
        duplicate = self.fixture.payload()
        duplicate["endpoints"] = [duplicate["endpoints"][0], duplicate["endpoints"][0]]  # type: ignore[index]
        for artifact, binding in (
            (self.fixture.issue(payload=dns), self.fixture.binding()),
            (self.fixture.issue(payload=duplicate), self.fixture.binding()),
            (
                self.fixture.issue(),
                self.fixture.binding(
                    endpoints=(
                        Endpoint("media", "192.0.2.10", 10002, "udp"),
                        ENDPOINTS[1],
                    )
                ),
            ),
        ):
            with self.assertRaises(MCPPolicyError):
                self.validator.validate(artifact, binding, consume=False)

    def test_media_port_range_is_exact_and_cannot_be_broadened(self) -> None:
        range_endpoint = Endpoint(
            "media", "192.0.2.10", 10000, "udp", None, 10020
        )
        payload = self.fixture.payload(
            endpoints=[
                {
                    "role": "media",
                    "address": "192.0.2.10",
                    "port": 10000,
                    "portEnd": 10020,
                    "transport": "udp",
                }
            ]
        )
        artifact = self.fixture.issue(payload=payload)
        binding = self.fixture.binding(endpoints=(range_endpoint,))
        self.validator.validate(artifact, binding, consume=False)
        broadened = self.fixture.binding(
            endpoints=(
                Endpoint("media", "192.0.2.10", 10000, "udp", None, 10021),
            )
        )
        with self.assertRaises(MCPPolicyError):
            self.validator.validate(artifact, broadened, consume=False)

    def test_ceiling_escalation_boolean_and_incomplete_budget_fail(self) -> None:
        escalated = dict(CEILINGS)
        escalated["packets"] += 1
        boolean = dict(CEILINGS)
        boolean["calls"] = True
        incomplete = dict(CEILINGS)
        incomplete.pop("bytes")
        for requested in (escalated, boolean, incomplete):
            with self.subTest(requested=requested), self.assertRaises(MCPPolicyError):
                self.validator.validate(
                    self.fixture.issue(),
                    self.fixture.binding(requested_ceilings=requested),
                    consume=False,
                )

    def test_concurrent_replay_allows_exactly_one_claim(self) -> None:
        artifact = self.fixture.issue()

        def claim() -> bool:
            validator = CapabilityValidator(
                OpenSSLEd25519Verifier(
                    {"operator-2026": ("quad-security", self.fixture.public_key)}
                ),
                ReplayAuditStore(self.root),
                now=lambda: NOW,
            )
            try:
                validator.validate(artifact, self.fixture.binding())
                return True
            except MCPPolicyError:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(lambda _: claim(), range(4)))
        self.assertEqual(outcomes.count(True), 1)

    def test_pinned_input_freezes_bytes_and_rejects_links(self) -> None:
        inputs = self.root / "inputs"
        inputs.mkdir()
        plan = inputs / "plan.json"
        plan.write_bytes(b"reviewed")
        pinned = PinnedInputRoot(inputs).read("plan.json")
        replacement = inputs / "replacement.json"
        replacement.write_bytes(b"swapped")
        replacement.replace(plan)
        self.assertEqual(pinned.content, b"reviewed")
        self.assertEqual(pinned.sha256, hashlib.sha256(b"reviewed").hexdigest())
        (inputs / "link").symlink_to("plan.json")
        with self.assertRaises(MCPPolicyError):
            PinnedInputRoot(inputs).read("link")

    def test_corrupt_audit_store_denies_validation(self) -> None:
        artifact = self.fixture.issue()
        self.store.path.write_bytes(b"not a sqlite database")
        with self.assertRaisesRegex(MCPPolicyError, "audit failed closed"):
            self.validator.validate(artifact, self.fixture.binding())

    def test_production_capability_module_has_no_signing_api(self) -> None:
        source = (
            Path(__file__).parents[1] / "lib/sippycup_mcp/capability.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("private_key", source)
        self.assertNotIn('"-sign"', source)
        self.assertNotIn("def sign", source)


if __name__ == "__main__":
    unittest.main()
