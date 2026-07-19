from __future__ import annotations

import json
import os
import select
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_media.rtp import (  # noqa: E402
    DTMF_END_PACKETS,
    DTMF_VOLUME,
    MediaSessionError,
    PACKETIZATION_MS,
    RTP_SEQUENCE_START,
    RTP_SSRC,
    build_packet_plan,
    load_session,
    packet_plan_document,
    send_packet_plan,
)

ASSETS = ROOT / "media" / "canary-v1"
FIXTURES = ROOT / "tests" / "fixtures" / "media"


def sdp(
    port: int,
    *,
    codec: str = "PCMU",
    codec_payload: int = 0,
    event_payload: int = 101,
    protocol: str = "RTP/AVP",
) -> str:
    return (
        "v=0\r\n"
        "o=test 1 1 IN IP4 127.0.0.1\r\n"
        "s=media-test\r\n"
        "c=IN IP4 127.0.0.1\r\n"
        "t=0 0\r\n"
        f"m=audio {port} {protocol} {codec_payload} {event_payload}\r\n"
        f"a=rtpmap:{codec_payload} {codec}/8000\r\n"
        f"a=rtpmap:{event_payload} telephone-event/8000\r\n"
        f"a=fmtp:{event_payload} 0-15\r\n"
        "a=ptime:20\r\n"
    )


def session_document(
    source_port: int,
    destination_port: int,
    *,
    codec: str = "PCMU",
    codec_payload: int = 0,
    event_payload: int = 101,
    digits: str = "12#",
    protocol: str = "RTP/AVP",
) -> dict[str, object]:
    return {
        "apiVersion": "sippycup.media-session/v1",
        "direction": "caller_to_callee",
        "codec": codec,
        "digits": digits,
        "echo": {"required": True, "timeoutMs": 500},
        "revisions": [
            {
                "activationMs": 0,
                "localSdp": sdp(
                    source_port,
                    codec=codec,
                    codec_payload=codec_payload,
                    event_payload=event_payload,
                    protocol=protocol,
                ),
                "remoteSdp": sdp(
                    destination_port,
                    codec=codec,
                    codec_payload=codec_payload,
                    event_payload=event_payload,
                    protocol=protocol,
                ),
            }
        ],
    }


def write_session(document: dict[str, object], directory: Path) -> Path:
    path = directory / "session.json"
    path.write_text(
        json.dumps(document, sort_keys=True), encoding="utf-8"
    )
    return path


def free_udp_ports(count: int) -> list[int]:
    sockets = []
    try:
        for _ in range(count):
            item = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            item.bind(("127.0.0.1", 0))
            sockets.append(item)
        return [item.getsockname()[1] for item in sockets]
    finally:
        for item in sockets:
            item.close()


class MediaPacketPlanTests(unittest.TestCase):
    def test_packet_plan_exactly_matches_checked_in_expectation(self) -> None:
        session = load_session(
            FIXTURES / "session-transition.json", ASSETS
        )
        observed = packet_plan_document(build_packet_plan(session))
        expected = json.loads(
            (FIXTURES / "packet-plan-v1.json").read_text(encoding="utf-8")
        )
        self.assertEqual(observed, expected)

    def test_reinvite_transition_uses_current_sdp_with_zero_delay(self) -> None:
        plan = build_packet_plan(
            load_session(FIXTURES / "session-transition.json", ASSETS)
        )
        before, after = plan.packets[24:26]
        self.assertEqual(before.scheduled_ms, 480)
        self.assertEqual(before.revision_index, 0)
        self.assertEqual(
            (before.source_port, before.destination_port, before.payload_type),
            (20000, 21000, 0),
        )
        self.assertEqual(after.scheduled_ms, 500)
        self.assertEqual(after.revision_index, 1)
        self.assertEqual(
            (after.source_port, after.destination_port, after.payload_type),
            (20002, 21002, 96),
        )
        first_event = plan.packets[50]
        self.assertEqual(first_event.payload_type, 110)
        self.assertLessEqual(
            after.scheduled_ms - session_activation(plan, 1),
            PACKETIZATION_MS,
        )

    def test_rtp_and_rfc4733_wire_contract(self) -> None:
        plan = build_packet_plan(
            load_session(FIXTURES / "session-transition.json", ASSETS)
        )
        self.assertEqual(
            [item.sequence for item in plan.packets],
            list(
                range(
                    RTP_SEQUENCE_START,
                    RTP_SEQUENCE_START + len(plan.packets),
                )
            ),
        )
        for packet in plan.packets:
            version, second, sequence, timestamp, ssrc = struct.unpack(
                "!BBHII", packet.wire_bytes()[:12]
            )
            self.assertEqual(version, 0x80)
            self.assertEqual(sequence, packet.sequence)
            self.assertEqual(timestamp, packet.timestamp)
            self.assertEqual(ssrc, RTP_SSRC)
            self.assertEqual(second & 0x7F, packet.payload_type)
            self.assertEqual(bool(second & 0x80), packet.marker)

        event_packets = plan.packets[50:]
        self.assertEqual(len(event_packets), 3 * 7)
        groups = [event_packets[index : index + 7] for index in range(0, 21, 7)]
        for digit, event, group in zip("12#", (1, 2, 11), groups):
            self.assertEqual({packet.digit for packet in group}, {digit})
            self.assertEqual({packet.event for packet in group}, {event})
            self.assertEqual(
                [packet.marker for packet in group],
                [True, False, False, False, False, False, False],
            )
            self.assertEqual(
                [packet.event_duration for packet in group],
                [160, 320, 480, 640, 800, 800, 800],
            )
            self.assertEqual(
                [packet.event_end for packet in group],
                [False, False, False, False, True, True, True],
            )
            self.assertEqual(
                len([packet for packet in group if packet.event_end]),
                DTMF_END_PACKETS,
            )
            self.assertEqual(len({packet.timestamp for packet in group}), 1)
            for packet in group:
                decoded_event, flags, duration = struct.unpack(
                    "!BBH", packet.payload
                )
                self.assertEqual(decoded_event, event)
                self.assertEqual(flags & 0x3F, DTMF_VOLUME)
                self.assertEqual(bool(flags & 0x80), packet.event_end)
                self.assertEqual(duration, packet.event_duration)

    def test_all_three_codecs_compile_with_negotiated_payloads(self) -> None:
        cases = (
            ("PCMU", 0),
            ("PCMA", 8),
            ("G722", 9),
        )
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            for codec, payload_type in cases:
                with self.subTest(codec=codec):
                    document = session_document(
                        22000,
                        22002,
                        codec=codec,
                        codec_payload=payload_type,
                    )
                    session = load_session(
                        write_session(document, temporary), ASSETS
                    )
                    plan = build_packet_plan(session)
                    self.assertEqual(plan.packets[0].payload_type, payload_type)
                    self.assertEqual(len(plan.packets[0].payload), 160)

    def test_unaligned_or_mismatched_revision_is_rejected(self) -> None:
        document = json.loads(
            (FIXTURES / "session-transition.json").read_text(encoding="utf-8")
        )
        document["revisions"][1]["activationMs"] = 501
        with tempfile.TemporaryDirectory() as temporary_name:
            with self.assertRaisesRegex(MediaSessionError, "align"):
                load_session(
                    write_session(document, Path(temporary_name)), ASSETS
                )
        document["revisions"][1]["activationMs"] = 500
        document["revisions"][1]["remoteSdp"] = document["revisions"][1][
            "remoteSdp"
        ].replace("a=rtpmap:96 PCMU/8000", "a=rtpmap:96 PCMA/8000")
        with tempfile.TemporaryDirectory() as temporary_name:
            with self.assertRaisesRegex(MediaSessionError, "negotiate PCMU"):
                load_session(
                    write_session(document, Path(temporary_name)), ASSETS
                )

    def test_unsupported_codec_and_keying_fail_before_socket_creation(self) -> None:
        documents = [
            session_document(22000, 22002, codec="OPUS", codec_payload=111),
            session_document(
                22000, 22002, protocol="RTP/SAVP"
            ),
        ]
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            with mock.patch("sippycup_media.rtp.socket.socket") as constructor:
                for document in documents:
                    with self.assertRaises(MediaSessionError):
                        load_session(write_session(document, temporary), ASSETS)
                constructor.assert_not_called()

    def test_digits_require_matching_dynamic_telephone_event(self) -> None:
        document = session_document(22000, 22002)
        document["revisions"][0]["remoteSdp"] = document["revisions"][0][
            "remoteSdp"
        ].replace("101", "102")
        with tempfile.TemporaryDirectory() as temporary_name:
            with self.assertRaisesRegex(MediaSessionError, "telephone-event"):
                load_session(
                    write_session(document, Path(temporary_name)), ASSETS
                )

    def test_schema_boundary_rejects_unknown_fields_and_bool_integers(self) -> None:
        document = session_document(22000, 22002)
        document["unexpected"] = True
        with tempfile.TemporaryDirectory() as temporary_name:
            with self.assertRaisesRegex(MediaSessionError, "unsupported"):
                load_session(
                    write_session(document, Path(temporary_name)), ASSETS
                )
        document.pop("unexpected")
        document["echo"]["timeoutMs"] = True
        with tempfile.TemporaryDirectory() as temporary_name:
            with self.assertRaisesRegex(MediaSessionError, "integer"):
                load_session(
                    write_session(document, Path(temporary_name)), ASSETS
                )


def session_activation(plan, revision: int) -> int:
    return plan.session.revisions[revision].activation_ms


class MediaEchoIntegrationTests(unittest.TestCase):
    def test_isolated_echo_returns_audio_and_configured_digits(self) -> None:
        source_one, destination_one, source_two, destination_two = free_udp_ports(4)
        document = session_document(source_one, destination_one)
        document["revisions"].append(
            {
                "activationMs": 500,
                "localSdp": sdp(
                    source_two, codec_payload=96, event_payload=110
                ),
                "remoteSdp": sdp(
                    destination_two, codec_payload=96, event_payload=110
                ),
            }
        )
        with tempfile.TemporaryDirectory() as temporary_name:
            path = write_session(document, Path(temporary_name))
            plan = build_packet_plan(load_session(path, ASSETS))
            command = [
                sys.executable,
                str(ROOT / "bin" / "sippycup-media-echo"),
                "--bind",
                "127.0.0.1",
                "--port",
                str(destination_one),
                "--port",
                str(destination_two),
                "--max-packets",
                str(len(plan.packets)),
                "--deadline-ms",
                "4000",
                "--telephone-event-pt",
                "101",
                "--telephone-event-pt",
                "110",
            ]
            ready_read, ready_write = os.pipe()
            command.extend(["--ready-fd", str(ready_write)])
            echo = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                pass_fds=(ready_write,),
            )
            os.close(ready_write)
            try:
                readable, _, _ = select.select([ready_read], (), (), 5)
                self.assertEqual(readable, [ready_read], "echo fixture did not become ready")
                self.assertEqual(os.read(ready_read, 1), b"1")
                report = send_packet_plan(plan)
                stdout, stderr = echo.communicate(timeout=5)
            finally:
                os.close(ready_read)
                if echo.poll() is None:
                    echo.kill()
                    echo.communicate()
            self.assertEqual(echo.returncode, 0, stderr)
            echo_report = json.loads(stdout)
        self.assertEqual(report["sentPackets"], 71)
        self.assertEqual(report["echoedAudioPackets"], 50)
        self.assertEqual(report["echoedTelephoneEventPackets"], 21)
        self.assertLessEqual(
            report["timing"]["maxRoundTripMs"], PACKETIZATION_MS
        )
        self.assertLessEqual(
            report["timing"]["maxSendLatenessMs"], PACKETIZATION_MS
        )
        self.assertFalse(report["timing"]["oneWayLatencyClaimed"])
        self.assertEqual(
            report["transitions"],
            [
                {
                    "revision": 0,
                    "activationMs": 0,
                    "firstPacketMs": 0,
                    "delayMs": 0,
                },
                {
                    "revision": 1,
                    "activationMs": 500,
                    "firstPacketMs": 500,
                    "delayMs": 0,
                },
            ],
        )
        self.assertEqual(echo_report["audioPackets"], 50)
        self.assertEqual(echo_report["telephoneEventPackets"], 21)
        starts = [
            packet["event"]
            for packet in echo_report["packets"]
            if packet["kind"] == "telephone-event" and packet["marker"]
        ]
        self.assertEqual(starts, [1, 2, 11])

    def test_cli_dry_run_dispatch_sends_no_packets(self) -> None:
        completed = subprocess.run(
            [
                str(ROOT / "bin" / "sippycup"),
                "media",
                "send",
                str(FIXTURES / "session-transition.json"),
                "--dry-run",
                "--format",
                "json",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        document = json.loads(completed.stdout)
        self.assertEqual(document["apiVersion"], "sippycup.media-packet-plan/v1")
        self.assertEqual(len(document["packets"]), 71)

    def test_asset_mutation_after_validation_fails_before_socket(self) -> None:
        source, destination = free_udp_ports(2)
        document = session_document(source, destination)
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            asset_root = temporary / "assets"
            asset_root.mkdir()
            for item in ASSETS.iterdir():
                if item.is_file():
                    (asset_root / item.name).write_bytes(item.read_bytes())
            session = load_session(
                write_session(document, temporary), asset_root
            )
            asset = asset_root / session.asset_path.name
            asset.write_bytes(b"\x00" + asset.read_bytes()[1:])
            with mock.patch(
                "sippycup_media.rtp.socket.socket"
            ) as constructor:
                with self.assertRaisesRegex(MediaSessionError, "changed"):
                    build_packet_plan(session)
                constructor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
