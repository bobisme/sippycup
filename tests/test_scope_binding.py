"""Scope binding of the optionally-bound senders (bn-328, bn-3df).

``media send`` and ``preflight`` take their destination from the operator.
These tests pin that a profile binds them, that a refusal happens before any
socket, and that an unbound run says so. Loopback only; no container.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_media import cli as media_cli  # noqa: E402
from sippycup_media.rtp import build_packet_plan, load_session, packet_plan_document  # noqa: E402
from sippycup_workbench import binding  # noqa: E402

SDP_MARKER = "scope-binding-sdp-marker"


def profile(
    *,
    host: str = "127.0.0.2",
    approved: list[str] | None = None,
    port: int = 5060,
    transport: str = "udp",
    status: str = "approved",
    valid_from: timedelta = timedelta(hours=-1),
    valid_until: timedelta = timedelta(hours=1),
    media: dict | None = None,
    target_extra: dict | None = None,
) -> dict:
    # Offsets from the moment the profile is written, so a slow suite cannot age it.
    current = datetime.now(timezone.utc)
    document = {
        "schema_version": "sippycup.dev/target-profile/v1",
        "name": "binding-test",
        "target": {
            "host": host,
            "port": port,
            "transport": transport,
            "approved_addresses": approved if approved is not None else [host],
            **(target_extra or {}),
        },
        "authorization": {
            "status": status,
            "approved_by": "owner",
            "approval_id": "CHG-4711",
            "valid_from": (current + valid_from).isoformat(),
            "valid_until": (current + valid_until).isoformat(),
        },
        "limits": {"max_calls": 1, "max_concurrency": 1, "max_calls_per_second": 1, "max_duration_seconds": 30},
        "capture": {"interface": "any", "output": "work/call.pcap"},
        "features": {"ice": False, "turn": False, "srtp": False, "dtls_srtp": False, "webrtc": False},
    }
    if media is not None:
        document["media"] = media
    return document


def sdp(address: str, port: int) -> str:
    return (
        "v=0\r\n"
        f"o=test 1 1 IN IP4 {address}\r\n"
        f"s={SDP_MARKER}\r\n"
        f"c=IN IP4 {address}\r\n"
        "t=0 0\r\n"
        f"m=audio {port} RTP/AVP 0 101\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=rtpmap:101 telephone-event/8000\r\n"
        "a=fmtp:101 0-15\r\n"
        "a=ptime:20\r\n"
    )


def session(destination: str, port: int, *, source_port: int = 20000, echo: bool = False) -> dict:
    return {
        "apiVersion": "sippycup.media-session/v1",
        "direction": "caller_to_callee",
        "codec": "PCMU",
        "digits": "1",
        "echo": {"required": echo, "timeoutMs": 500},
        "revisions": [
            {"activationMs": 0, "localSdp": sdp("127.0.0.1", source_port), "remoteSdp": sdp(destination, port)}
        ],
    }


class Workspace(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def write_profile(self, document: dict, name: str = "profile.yaml") -> Path:
        path = self.root / name
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        return path

    def write_session(self, document: dict) -> Path:
        path = self.root / "session.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path


class MediaSendScopeTests(Workspace):
    """media send: refused before any socket unless the destination is in scope."""

    def run_cli(self, *argv: str, environ: dict[str, str] | None = None) -> tuple[int, str, str, mock.Mock]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            mock.patch("sippycup_media.rtp.socket.socket") as constructor,
            mock.patch.dict(os.environ, environ or {}, clear=False),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            if environ is None:
                os.environ.pop(binding.REQUIRE_ENV, None)
            code = media_cli.main(["send", *argv])
        return code, stdout.getvalue(), stderr.getvalue(), constructor

    def refused(self, *argv: str, **keywords) -> str:
        """A refusal: exit 2, no socket, nothing on stdout, no new file, no SDP in the message."""
        before = sorted(item.name for item in self.root.iterdir())
        code, stdout, stderr, constructor = self.run_cli(*argv, **keywords)
        self.assertEqual(code, 2, stderr)
        constructor.assert_not_called()
        self.assertEqual(stdout, "")
        self.assertEqual(sorted(item.name for item in self.root.iterdir()), before)
        self.assertIn("media send refused", stderr)
        self.assertIn("Nothing was sent", stderr)
        self.assertIn("What to do:", stderr)
        self.assertNotIn(SDP_MARKER, stderr)
        self.assertNotIn("m=audio", stderr)
        return stderr

    def test_non_loopback_without_a_profile_is_refused_live_and_dry(self):
        path = self.write_session(session("8.8.8.8", 5353))
        for extra in ((), ("--dry-run",), ("--dry-run", "--format", "json")):
            with self.subTest(extra=extra):
                message = self.refused(str(path), *extra)
                self.assertIn("destination 8.8.8.8:5353 is not a loopback address", message)
                self.assertIn("--profile", message)

    def test_out_of_scope_address_is_refused(self):
        path = self.write_session(session("8.8.8.8", 5353))
        approved = self.write_profile(profile(host="192.0.2.10"))
        for extra in ((), ("--dry-run",)):
            with self.subTest(extra=extra):
                message = self.refused(str(path), "--profile", str(approved), *extra)
                self.assertIn("destination 8.8.8.8:5353 is not an approved address", message)
                self.assertIn("binding-test", message)

    def test_loopback_destination_is_still_checked_when_a_profile_is_given(self):
        path = self.write_session(session("127.0.0.1", 21000))
        approved = self.write_profile(profile(host="192.0.2.10"))
        message = self.refused(str(path), "--profile", str(approved))
        self.assertIn("destination 127.0.0.1:21000 is not an approved address", message)

    def test_address_outside_the_media_network_names_the_network(self):
        path = self.write_session(session("198.51.100.40", 12000))
        approved = self.write_profile(
            profile(host="192.0.2.10", media={"networks": ["198.51.100.0/27"]})
        )
        message = self.refused(str(path), "--profile", str(approved))
        self.assertIn("in no approved media network (198.51.100.0/27 (32 addresses))", message)

    def test_out_of_range_port_is_refused(self):
        path = self.write_session(session("198.51.100.7", 30000))
        approved = self.write_profile(
            profile(
                host="192.0.2.10",
                media={"networks": ["198.51.100.0/27"], "port_range": {"start": 10000, "end": 20000}},
            )
        )
        message = self.refused(str(path), "--profile", str(approved))
        self.assertIn("port 30000 is outside the approved media ports 10000-20000", message)

    def test_expired_not_yet_valid_and_unapproved_profiles_are_refused(self):
        path = self.write_session(session("192.0.2.10", 12000))
        cases = {
            "authorization has expired": profile(
                host="192.0.2.10",
                valid_from=timedelta(hours=-3),
                valid_until=timedelta(hours=-1),
            ),
            "authorization is not valid yet": profile(
                host="192.0.2.10",
                valid_from=timedelta(hours=1),
                valid_until=timedelta(hours=3),
            ),
            "authorization is pending, not approved": profile(host="192.0.2.10", status="pending"),
            "authorization is revoked, not approved": profile(host="192.0.2.10", status="revoked"),
        }
        for expected, document in cases.items():
            with self.subTest(expected=expected):
                approved = self.write_profile(document)
                for extra in ((), ("--dry-run",)):
                    message = self.refused(str(path), "--profile", str(approved), *extra)
                    self.assertIn(expected, message)
                    self.assertIn("rehearse", message)

    def test_window_must_cover_the_planned_send(self):
        path = self.write_session(session("192.0.2.10", 12000))
        approved = self.write_profile(
            profile(host="192.0.2.10", valid_until=timedelta(seconds=1))
        )
        message = self.refused(str(path), "--profile", str(approved))
        self.assertTrue(
            "expires before the latest possible end of this media send" in message
            or "authorization has expired" in message,
            message,
        )

    def test_unreadable_profile_is_refused(self):
        path = self.write_session(session("192.0.2.10", 12000))
        message = self.refused(str(path), "--profile", str(self.root / "missing.yaml"))
        self.assertIn("cannot be used", message)

    def test_in_scope_dry_run_keeps_the_packet_plan_and_shows_the_profile(self):
        path = self.write_session(session("198.51.100.7", 12000))
        approved = self.write_profile(
            profile(
                host="192.0.2.10",
                media={"networks": ["198.51.100.0/27"], "port_range": {"start": 10000, "end": 20000}},
            )
        )
        expected = packet_plan_document(build_packet_plan(load_session(path)))
        code, stdout, stderr, constructor = self.run_cli(
            str(path), "--profile", str(approved), "--dry-run", "--format", "json"
        )
        self.assertEqual(code, 0, stderr)
        constructor.assert_not_called()
        document = json.loads(stdout)
        scope = document.pop("scope")
        self.assertEqual(document, expected)
        self.assertEqual(scope["binding"], "profile")
        self.assertEqual(scope["profile"], "binding-test")
        self.assertEqual(scope["approvalId"], "CHG-4711")
        self.assertTrue(scope["validFrom"].endswith("Z") and scope["validUntil"].endswith("Z"))
        self.assertEqual(
            scope["destinations"],
            [{"destination": "198.51.100.7:12000", "rule": "media-network", "network": "198.51.100.0/27"}],
        )
        code, stdout, stderr, _ = self.run_cli(str(path), "--profile", str(approved), "--dry-run")
        self.assertEqual(code, 0, stderr)
        first, second = stdout.splitlines()
        self.assertRegex(
            first,
            r"^Scope: profile binding-test \(approval CHG-4711, window \S+Z to \S+Z\)$",
        )
        self.assertIn("no traffic sent", second)
        self.assertNotIn(SDP_MARKER, stdout + stderr)

    def test_loopback_without_a_profile_is_allowed_and_labelled_unbound(self):
        path = self.write_session(session("127.0.0.1", 21000))
        code, stdout, stderr, constructor = self.run_cli(str(path), "--dry-run")
        self.assertEqual(code, 0, stderr)
        constructor.assert_not_called()
        self.assertEqual(stdout.splitlines()[0], "Scope: UNBOUND (loopback only)")
        code, stdout, _, _ = self.run_cli(str(path), "--dry-run", "--format", "json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["scope"], {"binding": "unbound", "reason": "loopback only"})

    def test_require_profile_refuses_an_unbound_run(self):
        path = self.write_session(session("127.0.0.1", 21000))
        self.assertIn("a profile is required", self.refused(str(path), "--dry-run", "--require-profile"))
        self.assertIn(
            "a profile is required",
            self.refused(str(path), "--dry-run", environ={binding.REQUIRE_ENV: "1"}),
        )
        self.assertIn("a profile is required", self.refused(str(path), environ={binding.REQUIRE_ENV: "yes"}))
        code, _, stderr, _ = self.run_cli(str(path), "--dry-run", environ={binding.REQUIRE_ENV: "0"})
        self.assertEqual(code, 0, stderr)
        approved = self.write_profile(profile(host="127.0.0.1"))
        code, stdout, stderr, _ = self.run_cli(
            str(path), "--dry-run", "--require-profile", "--profile", str(approved)
        )
        self.assertEqual(code, 0, stderr)
        self.assertTrue(stdout.startswith("Scope: profile binding-test"))

    def test_mapped_and_ipv6_destinations_are_not_loopback_exceptions(self):
        self.assertTrue(binding.is_loopback("127.0.0.1"))
        self.assertTrue(binding.is_loopback("127.5.5.5"))
        self.assertTrue(binding.is_loopback("::1"))
        for address in ("::ffff:127.0.0.1", "8.8.8.8", "10.0.0.1", "0.0.0.0", "::", "example.invalid"):
            self.assertFalse(binding.is_loopback(address), address)


class MediaSendLiveLoopbackTests(Workspace):
    """A real send on loopback: bound and in scope, unbound, and refused with a listener watching."""

    def listener(self) -> tuple[socket.socket, int]:
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(0.2)
        self.addCleanup(receiver.close)
        return receiver, receiver.getsockname()[1]

    def free_port(self) -> int:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        return port

    def received(self, receiver: socket.socket) -> int:
        count = 0
        while True:
            try:
                receiver.recvfrom(2048)
            except (TimeoutError, socket.timeout):
                return count
            count += 1

    def send(self, *argv: str) -> subprocess.CompletedProcess[str]:
        environment = {key: value for key, value in os.environ.items() if key != binding.REQUIRE_ENV}
        return subprocess.run(
            [str(ROOT / "bin" / "sippycup"), "media", "send", *argv],
            capture_output=True, text=True, check=False, timeout=30, env=environment,
        )

    def test_bound_send_in_scope_delivers_the_planned_packets(self):
        receiver, port = self.listener()
        path = self.write_session(session("127.0.0.1", port, source_port=self.free_port()))
        planned = len(packet_plan_document(build_packet_plan(load_session(path)))["packets"])
        approved = self.write_profile(
            profile(host="127.0.0.1", media={"port_range": {"start": port, "end": port}})
        )
        completed = self.send(str(path), "--profile", str(approved), "--format", "json")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        document = json.loads(completed.stdout)
        self.assertEqual(document["sentPackets"], planned)
        self.assertEqual(document["scope"]["binding"], "profile")
        self.assertEqual(document["scope"]["approvalId"], "CHG-4711")
        self.assertEqual(self.received(receiver), planned)

    def test_bound_send_out_of_scope_delivers_nothing(self):
        receiver, port = self.listener()
        path = self.write_session(session("127.0.0.1", port, source_port=self.free_port()))
        approved = self.write_profile(
            profile(host="127.0.0.1", media={"port_range": {"start": port + 1, "end": port + 1}})
        )
        completed = self.send(str(path), "--profile", str(approved), "--format", "json")
        self.assertEqual(completed.returncode, 2, completed.stdout)
        self.assertEqual(completed.stdout, "")
        self.assertIn("is outside the approved media ports", completed.stderr)
        self.assertEqual(self.received(receiver), 0)

    def test_unbound_loopback_send_is_labelled(self):
        receiver, port = self.listener()
        path = self.write_session(session("127.0.0.1", port, source_port=self.free_port()))
        completed = self.send(str(path))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.splitlines()[0], "Scope: UNBOUND (loopback only)")
        self.assertGreater(self.received(receiver), 0)


class PreflightScopeTests(Workspace):
    """bin/container-preflight: --profile binds it; a refusal comes before any plan or packet."""

    def preflight(self, *argv: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [ROOT / "bin" / "container-preflight", *argv],
            capture_output=True, text=True, check=False, timeout=30,
            env={"PATH": "/usr/bin:/bin", "SIPPYCUP_WORK_ROOT": str(self.root), **(env or {})},
        )

    def refused(self, *argv: str, env: dict[str, str] | None = None) -> str:
        result = self.preflight(*argv, env=env)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn("preflight refused", result.stderr)
        self.assertIn("Nothing was sent", result.stderr)
        self.assertIn("What to do:", result.stderr)
        return result.stderr

    def test_bound_dry_run_takes_the_target_from_the_profile(self):
        approved = self.write_profile(profile(host="192.0.2.10", port=5080, transport="tcp"))
        for argv in ((), ("192.0.2.10",), ("192.0.2.10", "5080"), ("192.0.2.10", "5080", "tcp")):
            with self.subTest(argv=argv):
                result = self.preflight(*argv, "--profile", str(approved), "--dry-run")
                self.assertEqual(result.returncode, 0, result.stderr)
                lines = result.stdout.splitlines()
                self.assertIn("Target:    192.0.2.10:5080", lines)
                self.assertIn("Transport: tcp", lines)
                self.assertTrue(
                    any(
                        line.startswith("Scope: profile binding-test (approval CHG-4711, window ")
                        for line in lines
                    ),
                    result.stdout,
                )
                self.assertIn("Network activity: none", lines)

    def test_mismatches_are_refused_before_any_plan(self):
        approved = self.write_profile(profile(host="192.0.2.10", port=5080, transport="tcp"))
        cases = {
            ("192.0.2.99",): "host 192.0.2.99 is not the profile's target.host 192.0.2.10",
            ("192.0.2.10", "5060"): "port 5060 is not the profile's target.port 5080",
            ("192.0.2.10", "5080", "udp"): "transport udp is not the profile's target.transport tcp",
            ("192.0.2.10", "5080", "tcp", "--tls-unverified"): "TLS options were given",
        }
        for argv, expected in cases.items():
            for extra in ((), ("--dry-run",), ("--format", "json")):
                with self.subTest(argv=argv, extra=extra):
                    self.assertIn(expected, self.refused(*argv, "--profile", str(approved), *extra))

    def test_approval_problems_are_refused(self):
        cases = {
            "authorization has expired": profile(
                host="192.0.2.10", valid_from=timedelta(hours=-3), valid_until=timedelta(hours=-1)
            ),
            "authorization is not valid yet": profile(
                host="192.0.2.10", valid_from=timedelta(hours=1), valid_until=timedelta(hours=3)
            ),
            "authorization is pending, not approved": profile(host="192.0.2.10", status="pending"),
            "expires before the latest possible end of this preflight": profile(
                host="192.0.2.10", valid_until=timedelta(seconds=20)
            ),
            "target.host must itself be one of the literal approved_addresses": profile(
                host="sip.example.invalid", approved=["192.0.2.10"]
            ),
        }
        for expected, document in cases.items():
            with self.subTest(expected=expected):
                approved = self.write_profile(document)
                self.assertIn(expected, self.refused("--profile", str(approved)))
        self.assertIn("cannot be used", self.refused("--profile", str(self.root / "missing.yaml")))

    def test_tls_name_and_ca_come_from_the_profile(self):
        pem = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
             "-nodes", "-subj", "/CN=binding-test-ca", "-days", "1", "-keyout", "/dev/null"],
            capture_output=True, text=True, check=False, timeout=20,
        )
        if pem.returncode != 0:
            self.skipTest("openssl cannot create a test CA")
        (self.root / "ca.crt").write_text(pem.stdout, encoding="utf-8")
        approved = self.write_profile(
            profile(
                host="192.0.2.10", port=5061, transport="tls",
                target_extra={"tls_server_name": "sip.owner-voice.net", "tls_ca_file": "work/ca.crt"},
            )
        )
        result = self.preflight("--profile", str(approved), "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("TLS:       verify as sip.owner-voice.net with extra CA work/ca.crt", result.stdout)
        same = self.preflight(
            "--profile", str(approved), "--tls-server-name", "sip.owner-voice.net",
            "--tls-ca", "/work/ca.crt", "--dry-run",
        )
        self.assertEqual(same.returncode, 0, same.stderr)
        cases = {
            ("--tls-server-name", "other.example"): "is not the profile's target.tls_server_name",
            ("--tls-ca", "/work/other.crt"): "is not the profile's target.tls_ca_file (work/ca.crt)",
            ("--tls-unverified",): "--tls-unverified cannot be used with a profile",
        }
        for argv, expected in cases.items():
            with self.subTest(argv=argv):
                self.assertIn(expected, self.refused("--profile", str(approved), *argv, "--dry-run"))

    def test_unbound_run_says_so(self):
        result = self.preflight("192.0.2.10", "5060", "udp", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Scope: UNBOUND (operator-supplied target 192.0.2.10)", result.stdout.splitlines())

    def test_require_profile_refuses_an_unbound_run(self):
        self.assertIn("a profile is required", self.refused("192.0.2.10", "--dry-run", "--require-profile"))
        self.assertIn(
            "a profile is required",
            self.refused("192.0.2.10", "--dry-run", env={"SIPPYCUP_REQUIRE_PROFILE": "1"}),
        )
        self.assertIn("a profile is required", self.refused("192.0.2.10", env={"SIPPYCUP_REQUIRE_PROFILE": "true"}))
        allowed = self.preflight("192.0.2.10", "--dry-run", env={"SIPPYCUP_REQUIRE_PROFILE": "0"})
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        approved = self.write_profile(profile(host="192.0.2.10"))
        bound = self.preflight(
            "--profile", str(approved), "--dry-run", env={"SIPPYCUP_REQUIRE_PROFILE": "1"}
        )
        self.assertEqual(bound.returncode, 0, bound.stderr)

    def test_json_output_carries_the_scope_object(self):
        approved = self.write_profile(profile(host="192.0.2.10"))
        bound = self.preflight("--profile", str(approved), "--dry-run", "--format", "json")
        self.assertEqual(bound.returncode, 0, bound.stderr)
        document = json.loads(bound.stdout)
        self.assertEqual(document["schema"], "sippycup.dev/preflight-result/v1")
        self.assertEqual(document["target"], {"host": "192.0.2.10", "port": 5060, "transport": "udp"})
        self.assertEqual(document["scope"]["binding"], "profile")
        self.assertEqual(document["scope"]["profile"], "binding-test")
        self.assertEqual(document["scope"]["approvalId"], "CHG-4711")
        self.assertIs(document["dryRun"], True)
        self.assertIs(document["networkActivity"], False)
        self.assertIn("Scope: profile binding-test", bound.stderr)
        unbound = self.preflight("192.0.2.10", "--dry-run", "--format", "json")
        self.assertEqual(
            json.loads(unbound.stdout)["scope"],
            {"binding": "unbound", "operatorSuppliedTarget": "192.0.2.10"},
        )

    def test_usage_errors(self):
        approved = self.write_profile(profile(host="192.0.2.10"))
        for argv in (
            ("--profile",),
            ("--profile=",),
            ("192.0.2.10", "--format", "yaml"),
            (),
            ("192.0.2.10", "5060", "udp", "extra", "--profile", str(approved)),
        ):
            with self.subTest(argv=argv):
                result = self.preflight(*argv, "--dry-run")
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertNotIn("Network activity", result.stdout)


class BindingModelTests(unittest.TestCase):
    def test_scope_line_never_carries_control_characters(self):
        scope = {
            "binding": "profile", "profile": "name", "approvalId": "CHG\n1\x1b[31m",
            "validFrom": None, "validUntil": "2026-11-18T13:00:00Z",
        }
        line = binding.scope_line(scope)
        self.assertEqual(line, "Scope: profile name (approval CHG?1?[31m, window until 2026-11-18T13:00:00Z)")

    def test_the_binding_reuses_rehearse(self):
        document = copy.deepcopy(profile(host="192.0.2.10"))
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "profile.yaml"
            path.write_text(yaml.safe_dump(document), encoding="utf-8")
            with mock.patch("sippycup_workbench.profile.rehearse", wraps=__import__(
                "sippycup_workbench.profile", fromlist=["rehearse"]
            ).rehearse) as rehearse:
                bound = binding.load_binding(path, planned_seconds=5)
        rehearse.assert_called_once()
        self.assertEqual(bound.approval_id, "CHG-4711")


class ScopeClassDocumentationTests(unittest.TestCase):
    """Every registry command that can touch a network has a documented scope class."""

    def table_commands(self, path: Path, heading: str) -> set[str]:
        text = path.read_text(encoding="utf-8")
        section = text.split(heading, 1)[1].split("\n## ", 1)[0].split("\n### ", 1)[0]
        names: set[str] = set()
        for line in section.splitlines():
            if not line.startswith("| `"):
                continue
            first = line.split("|")[1]
            names.update(part.split()[0] for part in first.split("`")[1::2])
        return names

    def test_cli_and_safety_audit_tables_cover_the_registry(self):
        networked = set()
        for line in (ROOT / "config" / "commands.tsv").read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#"):
                fields = line.split("|")
                if fields[5] != "offline":
                    networked.add(fields[0])
        self.assertIn("preflight", networked)
        for path, heading in (
            (ROOT / "docs" / "CLI.md", "## Scope binding"),
            (ROOT / "docs" / "SAFETY-AUDIT.md", "### 7: `media send` is bound to a profile"),
        ):
            with self.subTest(path=path.name):
                documented = self.table_commands(path, heading)
                self.assertEqual(networked - documented, set(), "commands without a scope class")
                self.assertIn("--", documented, "the escape hatch is classified too")


class LauncherScopeTests(unittest.TestCase):
    """bin/sippycup: the escape hatch and shell say UNBOUND; the requirement reaches the image."""

    def launch(self, *argv: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as name:
            runtime = Path(name) / "runtime"
            runtime.write_text("#!/bin/sh\nif [ \"$1\" = ps ]; then echo '[]'; exit 0; fi\nprintf '%s\\n' \"$@\"\n", encoding="utf-8")
            runtime.chmod(runtime.stat().st_mode | stat.S_IXUSR)
            environment = {key: value for key, value in os.environ.items() if key != "SIPPYCUP_REQUIRE_PROFILE"}
            environment.update({"SIPPYCUP_RUNTIME": str(runtime), "SIPPYCUP_IMAGE": "example.invalid/sippycup:test"})
            environment.update(env or {})
            return subprocess.run(
                [ROOT / "bin" / "sippycup", *argv],
                cwd=ROOT, env=environment, capture_output=True, text=True, check=False, timeout=20,
            )

    def test_escape_hatch_and_shell_print_an_unbound_notice_on_stderr(self):
        for argv in (("--", "tshark", "--version"), ("shell",), ()):
            with self.subTest(argv=argv):
                result = self.launch(*argv)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stderr.startswith("Scope: UNBOUND ("), result.stderr)
                self.assertNotIn("Scope:", result.stdout)

    def test_first_party_commands_do_not_print_the_notice(self):
        for argv in (("preflight", "192.0.2.10", "--dry-run"), ("selftest",), ("shell", "--help")):
            with self.subTest(argv=argv):
                result = self.launch(*argv)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("UNBOUND", result.stderr)

    def test_require_profile_environment_is_forwarded_into_the_image(self):
        on = self.launch("preflight", "192.0.2.10", env={"SIPPYCUP_REQUIRE_PROFILE": "1"})
        self.assertIn("--env=SIPPYCUP_REQUIRE_PROFILE=1", on.stdout.splitlines())
        for value in ("", "0"):
            off = self.launch("preflight", "192.0.2.10", env={"SIPPYCUP_REQUIRE_PROFILE": value})
            self.assertNotIn("SIPPYCUP_REQUIRE_PROFILE", off.stdout)

    def test_profile_path_is_spelled_for_the_image(self):
        result = self.launch("preflight", "--profile", "work/engagement/profile.yaml", "--dry-run")
        self.assertIn("/work/engagement/profile.yaml", result.stdout.splitlines())


if __name__ == "__main__":
    unittest.main()
