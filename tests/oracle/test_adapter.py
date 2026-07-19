from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_oracle import (  # noqa: E402
    CaptureDecodeError,
    CaptureFormat,
    CaptureStatus,
    Known,
    Unknown,
    UnknownReason,
    dumps_record,
    parse_tshark_json,
    probe_capture_format,
)

FIXTURES = Path(__file__).parent / "fixtures"


def parse_fixture(name: str, capture_format: CaptureFormat):
    return parse_tshark_json(
        (FIXTURES / name).read_text(encoding="utf-8"), capture_format
    )


class CaptureProbeTests(unittest.TestCase):
    def _probe_hex(self, fixture: str) -> CaptureFormat:
        data = bytes.fromhex((FIXTURES / fixture).read_text(encoding="ascii"))
        with tempfile.NamedTemporaryFile() as capture:
            capture.write(data)
            capture.flush()
            return probe_capture_format(capture.name)

    def test_pcap_magic(self) -> None:
        self.assertEqual(
            self._probe_hex("ipv4-sip-no-rtp.pcap.hex"), CaptureFormat.PCAP
        )

    def test_pcapng_magic(self) -> None:
        self.assertEqual(
            self._probe_hex("ipv6-rtp-no-sip.pcapng.hex"), CaptureFormat.PCAPNG
        )

    def test_unknown_capture_format_is_rejected(self) -> None:
        with tempfile.NamedTemporaryFile() as capture:
            capture.write(b"nope")
            capture.flush()
            with self.assertRaises(CaptureDecodeError):
                probe_capture_format(capture.name)


class AdapterTests(unittest.TestCase):
    def test_ipv4_sip_and_sdp_without_rtp(self) -> None:
        capture = parse_fixture(
            "ipv4-sip-no-rtp.pcap.tshark.json", CaptureFormat.PCAP
        )
        frame = capture.frames[0]
        self.assertEqual(frame.status, Known(CaptureStatus.COMPLETE))
        self.assertIsNotNone(frame.sip)
        self.assertIsNotNone(frame.sdp)
        self.assertIsNone(frame.rtp)
        self.assertEqual(frame.source.address, Known("192.0.2.20"))
        self.assertEqual(frame.sdp.media[0].payload_types, Known((0, 101)))
        self.assertEqual(
            frame.sdp.media[0].codecs.value[0].encoding, Known("PCMU")
        )
        self.assertEqual(
            frame.sdp.media[0].telephone_event_payloads, Known((101,))
        )
        self.assertEqual(frame.sdp.media[0].packet_time_ms, Known(20))
        self.assertEqual(frame.sdp.media[0].rtcp_port, Known(4001))

    def test_ipv6_rtp_without_sip(self) -> None:
        capture = parse_fixture(
            "ipv6-rtp-no-sip.pcapng.tshark.json", CaptureFormat.PCAPNG
        )
        frame = capture.frames[0]
        self.assertIsNone(frame.sip)
        self.assertIsNotNone(frame.rtp)
        self.assertEqual(frame.rtp.ssrc, Known(0x01020304))
        self.assertEqual(frame.evidence.timestamp_epoch.value.as_tuple().exponent, -9)

    def test_capture_with_neither_sip_nor_rtp(self) -> None:
        capture = parse_fixture(
            "no-sip-no-rtp.pcap.tshark.json", CaptureFormat.PCAP
        )
        self.assertIsNone(capture.frames[0].sip)
        self.assertIsNone(capture.frames[0].rtp)

    def test_truncation_and_bad_field_are_typed(self) -> None:
        capture = parse_fixture("truncated.pcap.tshark.json", CaptureFormat.PCAP)
        frame = capture.frames[0]
        self.assertEqual(frame.status, Known(CaptureStatus.TRUNCATED))
        self.assertEqual(
            frame.rtp.sequence,
            Unknown(UnknownReason.MALFORMED_FIELD, "rtp.seq"),
        )
        self.assertEqual(
            frame.rtp.timestamp.reason, UnknownReason.TRUNCATED_CAPTURE
        )
        self.assertIn("truncated", capture.warnings[0])

    def test_malformed_dissection_does_not_invent_defaults(self) -> None:
        capture = parse_fixture(
            "malformed.pcapng.tshark.json", CaptureFormat.PCAPNG
        )
        frame = capture.frames[0]
        self.assertEqual(frame.status, Known(CaptureStatus.MALFORMED))
        self.assertIsInstance(frame.evidence.frame_number, Unknown)
        self.assertIsInstance(frame.source.port, Unknown)
        self.assertIsNotNone(frame.sip)
        self.assertIsInstance(frame.sip.call_id, Unknown)

    def test_encrypted_media_is_explicitly_unknown(self) -> None:
        capture = parse_fixture(
            "encrypted-media.pcapng.tshark.json", CaptureFormat.PCAPNG
        )
        visibility = capture.frames[0].rtp.payload_visibility
        self.assertEqual(visibility.reason, UnknownReason.UNSUPPORTED_ENCRYPTION)
        self.assertIsNotNone(capture.frames[0].rtcp)
        self.assertEqual(
            capture.frames[0].rtp.ssrc.reason,
            UnknownReason.UNSUPPORTED_ENCRYPTION,
        )
        self.assertEqual(
            capture.frames[0].rtcp.packet_type.reason,
            UnknownReason.UNSUPPORTED_ENCRYPTION,
        )

    def test_missing_structural_fields_never_become_false_or_empty_defaults(self) -> None:
        capture = parse_fixture(
            "missing-structural-fields.pcap.tshark.json", CaptureFormat.PCAP
        )
        frame = capture.frames[0]
        self.assertIsInstance(frame.status, Unknown)
        self.assertIsInstance(frame.sip.has_sdp, Unknown)
        media = frame.sdp.media[0]
        self.assertIsInstance(media.payload_types, Unknown)
        self.assertIsInstance(media.codecs, Unknown)
        self.assertIsInstance(media.telephone_event_payloads, Unknown)

    def test_sensitive_and_payload_fields_never_serialize(self) -> None:
        sip_json = dumps_record(
            parse_fixture(
                "ipv4-sip-no-rtp.pcap.tshark.json", CaptureFormat.PCAP
            )
        )
        rtp_json = dumps_record(
            parse_fixture(
                "ipv6-rtp-no-sip.pcapng.tshark.json", CaptureFormat.PCAPNG
            )
        )
        combined = (sip_json + rtp_json).lower()
        self.assertNotIn("authorization", combined)
        self.assertNotIn("must-never-serialize", combined)
        self.assertNotIn("payload-bytes", combined)
        self.assertNotIn('"payload"', combined)

    def test_json_contract_uses_typed_known_and_unknown_values(self) -> None:
        capture = parse_fixture(
            "ipv4-sip-no-rtp.pcap.tshark.json", CaptureFormat.PCAP
        )
        serialized = json.loads(dumps_record(capture))
        self.assertEqual(
            serialized["schema_version"], "sippycup.packet-records/v1"
        )
        self.assertEqual(
            serialized["frames"][0]["evidence"]["frame_number"],
            {"state": "known", "value": 1},
        )
        self.assertEqual(
            serialized["frames"][0]["sip"]["status_code"]["state"], "unknown"
        )

    def test_terminal_text_and_non_array_json_are_rejected(self) -> None:
        with self.assertRaises(CaptureDecodeError):
            parse_tshark_json("Frame 1: pretty terminal output", CaptureFormat.PCAP)
        with self.assertRaises(CaptureDecodeError):
            parse_tshark_json('{"layers": {}}', CaptureFormat.PCAP)


if __name__ == "__main__":
    unittest.main()
