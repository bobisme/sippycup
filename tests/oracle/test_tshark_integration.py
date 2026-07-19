from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_oracle import (  # noqa: E402
    CaptureFormat,
    Known,
    parse_tshark_json,
    probe_capture_format,
    tshark_json_args,
    reconstruct_dialogs,
)
from sippycup_oracle.records import (  # noqa: E402
    AddressFamily,
    CaptureStatus,
    Unknown,
)


def _hexdump(payload: bytes) -> str:
    lines = []
    for offset in range(0, len(payload), 16):
        chunk = payload[offset : offset + 16]
        lines.append(f"{offset:06x}  " + " ".join(f"{byte:02x}" for byte in chunk))
    return "\n".join(lines) + "\n"


def _sip_payload(
    address: str, address_type: str, sdp_body: str | None = None
) -> bytes:
    audio_address = "2001:db8::11" if address_type == "IP6" else "192.0.2.11"
    video_address = "2001:db8::12" if address_type == "IP6" else "192.0.2.12"
    body_text = sdp_body or (
        "v=0\r\n"
        f"o=caller 1 1 IN {address_type} {address}\r\n"
        "s=real tshark fixture\r\n"
        f"c=IN {address_type} {address}\r\n"
        "t=0 0\r\n"
        "m=audio 4000 RTP/AVP 0 101\r\n"
        f"c=IN {address_type} {audio_address}\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=rtpmap:101 telephone-event/8000\r\n"
        "a=fmtp:101 0-16\r\n"
        "a=ptime:20\r\n"
        "a=sendrecv\r\n"
        f"a=rtcp:4001 IN {address_type} {address}\r\n"
        "m=video 6000 RTP/AVP 96\r\n"
        f"c=IN {address_type} {video_address}\r\n"
        "a=rtpmap:96 VP8/90000\r\n"
        "a=recvonly\r\n"
        f"a=rtcp:6001 IN {address_type} {address}\r\n"
    )
    body = body_text.encode("ascii")
    headers = (
        "INVITE sip:callee@example.invalid SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP [{address}]:5060;branch=z9hG4bK-real\r\n"
        "From: <sip:caller@example.invalid>;tag=caller-real\r\n"
        "To: <sip:callee@example.invalid>\r\n"
        "Call-ID: real-tshark@example.invalid\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Type: application/sdp\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("ascii")
    return headers + body


@unittest.skipUnless(
    shutil.which("text2pcap") and shutil.which("editcap") and shutil.which("tshark"),
    "Wireshark command-line tools are required",
)
class RealTsharkIntegrationTests(unittest.TestCase):
    def _capture(
        self,
        capture_format: CaptureFormat,
        ipv6: bool,
        sdp_body: str | None = None,
        transport: str = "udp",
    ):
        temporary = tempfile.TemporaryDirectory()
        directory = Path(temporary.name)
        intermediate = directory / "generated.pcapng"
        output = directory / (
            "semantic.pcap" if capture_format is CaptureFormat.PCAP else "semantic.pcapng"
        )
        source = "2001:db8::10" if ipv6 else "192.0.2.10"
        destination = "2001:db8::20" if ipv6 else "198.51.100.20"
        address_flag = "-6" if ipv6 else "-4"
        subprocess.run(
            [
                "text2pcap",
                "-q",
                "-T" if transport == "tcp" else "-u",
                "5060,5060",
                address_flag,
                f"{source},{destination}",
                "-",
                str(intermediate),
            ],
            input=_hexdump(
                _sip_payload(
                    source, "IP6" if ipv6 else "IP4", sdp_body=sdp_body
                )
            ),
            text=True,
            check=True,
            capture_output=True,
        )
        if capture_format is CaptureFormat.PCAP:
            subprocess.run(
                ["editcap", "-F", "pcap", str(intermediate), str(output)],
                check=True,
                capture_output=True,
                text=True,
            )
        else:
            output = intermediate
        tshark = subprocess.run(
            tshark_json_args(output),
            check=True,
            capture_output=True,
            text=True,
        )
        return temporary, output, parse_tshark_json(tshark.stdout, capture_format)

    def test_generated_tcp_signaling_round_trip(self) -> None:
        temporary, _, capture = self._capture(
            CaptureFormat.PCAP, False, transport="tcp"
        )
        try:
            frame = capture.frames[0]
            self.assertIsNotNone(frame.sip)
            self.assertEqual(frame.source.transport.value.value, "tcp")
            self.assertEqual(frame.sip.request_method, Known("INVITE"))
        finally:
            temporary.cleanup()

    def test_generated_ipv4_pcap_round_trip_and_repeated_sdp_sections(self) -> None:
        temporary, path, capture = self._capture(CaptureFormat.PCAP, False)
        try:
            self.assertEqual(probe_capture_format(path), CaptureFormat.PCAP)
            frame = capture.frames[0]
            self.assertIsNotNone(frame.sip)
            self.assertEqual(len(frame.sdp.media), 2)
            audio, video = frame.sdp.media
            self.assertEqual(audio.payload_types, Known((0, 101)))
            self.assertEqual(video.payload_types, Known((96,)))
            self.assertEqual(audio.address, Known("192.0.2.11"))
            self.assertEqual(video.address, Known("192.0.2.12"))
            self.assertEqual(audio.direction, Known("sendrecv"))
            self.assertEqual(video.direction, Known("recvonly"))
            self.assertEqual(audio.packet_time_ms, Known(20))
            self.assertEqual(audio.rtcp_port, Known(4001))
            self.assertEqual(video.rtcp_port, Known(6001))
            self.assertEqual(
                audio.telephone_event_payloads, Known((101,))
            )
            self.assertEqual(video.codecs.value[0].encoding, Known("VP8"))
        finally:
            temporary.cleanup()

    def test_generated_ipv6_pcapng_round_trip(self) -> None:
        temporary, path, capture = self._capture(CaptureFormat.PCAPNG, True)
        try:
            self.assertEqual(probe_capture_format(path), CaptureFormat.PCAPNG)
            frame = capture.frames[0]
            self.assertEqual(frame.source.family, Known(AddressFamily.IPV6))
            self.assertEqual(frame.source.address, Known("2001:db8::10"))
            self.assertIsNotNone(frame.sdp)
            self.assertEqual(len(frame.sdp.media), 2)
        finally:
            temporary.cleanup()

    def test_repeated_same_codec_sections_keep_leading_attributes_and_media_c(self) -> None:
        body = (
            "v=0\r\n"
            "o=caller 1 1 IN IP4 192.0.2.10\r\n"
            "s=edge association\r\n"
            "t=0 0\r\n"
            "m=audio 4000 RTP/AVP 0\r\n"
            "c=IN IP4 192.0.2.11\r\n"
            "a=sendonly\r\n"
            "a=ptime:10\r\n"
            "a=rtcp:4001 IN IP4 192.0.2.11\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "m=audio 5000 RTP/AVP 0\r\n"
            "c=IN IP4 192.0.2.12\r\n"
            "a=recvonly\r\n"
            "a=ptime:30\r\n"
            "a=rtcp:5001 IN IP4 192.0.2.12\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
        )
        temporary, _, capture = self._capture(
            CaptureFormat.PCAPNG, False, body
        )
        try:
            sdp = capture.frames[0].sdp
            self.assertIsInstance(sdp.connection_address, Unknown)
            self.assertEqual(len(sdp.media), 2)
            first, second = sdp.media
            self.assertEqual(first.address, Known("192.0.2.11"))
            self.assertEqual(second.address, Known("192.0.2.12"))
            self.assertEqual(first.direction, Known("sendonly"))
            self.assertEqual(second.direction, Known("recvonly"))
            self.assertEqual(first.packet_time_ms, Known(10))
            self.assertEqual(second.packet_time_ms, Known(30))
            self.assertEqual(first.rtcp_port, Known(4001))
            self.assertEqual(second.rtcp_port, Known(5001))
            self.assertEqual(first.codecs.value[0].encoding, Known("PCMU"))
            self.assertEqual(second.codecs.value[0].encoding, Known("PCMU"))
        finally:
            temporary.cleanup()

    def test_physical_snaplen_truncation_cannot_complete_dialog(self) -> None:
        temporary, path, _ = self._capture(CaptureFormat.PCAP, False)
        try:
            truncated = Path(temporary.name) / "truncated.pcap"
            subprocess.run(
                ["editcap", "-s", "350", str(path), str(truncated)],
                check=True,
                capture_output=True,
                text=True,
            )
            tshark = subprocess.run(
                tshark_json_args(truncated),
                check=True,
                capture_output=True,
                text=True,
            )
            capture = parse_tshark_json(tshark.stdout, CaptureFormat.PCAP)
            self.assertEqual(
                capture.frames[0].status, Known(CaptureStatus.TRUNCATED)
            )
            reconstruction = reconstruct_dialogs(capture.frames)
            self.assertTrue(reconstruction.dialogs)
            self.assertTrue(
                all(
                    not (
                        isinstance(dialog.complete, Known)
                        and dialog.complete.value is True
                    )
                    for dialog in reconstruction.dialogs
                )
            )
        finally:
            temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
