"""bn-2jg: the softphone driver watches what PJSUA sends and what the far end asks for.

A loopback experiment (docs/SAFETY-AUDIT.md) showed that a far end can steer
PJSUA off the approved scope: a Record-Route or Contact in its 200 OK sends the
ACK and BYE to another address despite the ``--outbound`` route, and an SDP
connection address (or ``a=rtcp``) sends RTP/RTCP to another address while
the received-RTP "peer" the driver used to check stays unknown or approved.

PJSUA is the fixture console ``tests/fixtures/fake_pjsua.py``. No container,
capture, or socket is used.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from sippycup_softphone import SoftphoneCall, place_call  # noqa: E402
from sippycup_softphone import driver  # noqa: E402
from sippycup_workbench import call as guided  # noqa: E402

from test_guided_call import FAKE_PJSUA, write_tone  # noqa: E402


class SdpDestinationTests(unittest.TestCase):
    def test_media_level_connection_overrides_session_level(self):
        lines = [
            "SIP/2.0 200 OK", "Contact: <sip:far@192.0.2.10>", "",
            "v=0", "c=IN IP4 192.0.2.10", "m=audio 4000 RTP/AVP 0", "c=IN IP4 198.51.100.88",
            "a=rtpmap:0 PCMU/8000",
        ]
        self.assertEqual(
            driver.sdp_media_destinations(lines),
            [("198.51.100.88", 4000, "RTP")],
        )

    def test_rtcp_attribute_address_and_rejected_streams(self):
        lines = [
            "v=0", "c=IN IP4 192.0.2.10/127", "m=audio 4000 RTP/AVP 0",
            "a=rtcp:4001 IN IP4 198.51.100.99", "m=video 0 RTP/AVP 96",
        ]
        self.assertEqual(
            driver.sdp_media_destinations(lines),
            [("192.0.2.10", 4000, "RTP"), ("198.51.100.99", 4001, "RTCP")],
        )

    def test_hold_address_is_not_a_destination(self):
        self.assertEqual(driver.sdp_media_destinations(["c=IN IP4 0.0.0.0", "m=audio 4000 RTP/AVP 0"]), [])

    def test_admission_follows_addresses_networks_and_ports(self):
        call = SoftphoneCall(
            destination="echo", host="192.0.2.10", port=5060, transport="udp",
            play_file=Path("p.wav"), record_file=Path("r.wav"), duration_seconds=2,
            log_file=Path("l.log"), allowed_media_addresses=("192.0.2.10",),
            allowed_media_networks=("203.0.113.0/28",), allowed_media_ports=(4000, 4100),
        )
        self.assertIsNone(driver.media_destination_refusal(call, ("192.0.2.10", 4000, "RTP")))
        self.assertIsNone(driver.media_destination_refusal(call, ("203.0.113.5", 4002, "RTP")))
        self.assertIsNotNone(driver.media_destination_refusal(call, ("203.0.113.99", 4002, "RTP")))
        self.assertIsNotNone(driver.media_destination_refusal(call, ("192.0.2.10", 9, "RTP")))
        # A name would be resolved by PJSUA: never admitted.
        self.assertIsNotNone(driver.media_destination_refusal(call, ("media.example.test", 4000, "RTP")))


class TransmitDestinationTests(unittest.TestCase):
    def test_tx_lines(self):
        self.assertEqual(
            driver.tx_destination(
                "20:15:53.568  pjsua_core.c  .....TX 363 bytes Request msg ACK/cseq=4739 (tdta0x7f) to UDP 127.0.0.66:5060:"
            ),
            "127.0.0.66",
        )
        self.assertEqual(
            driver.tx_destination("..TX 500 bytes Response msg 200/INVITE/cseq=7 (tdta1) to TLS [2001:db8::5]:5061:"),
            "2001:db8::5",
        )
        self.assertIsNone(driver.tx_destination("RX 900 bytes Response msg 200/INVITE/cseq=1 (rdata0x3) from UDP 192.0.2.10:5060:"))

    def test_only_the_literal_target_or_reviewed_name_is_a_signaling_destination(self):
        call = SoftphoneCall(
            destination="echo", host="192.0.2.10", port=5061, transport="tls",
            play_file=Path("p.wav"), record_file=Path("r.wav"), duration_seconds=2,
            log_file=Path("l.log"), tls_server_name="voice.example.test",
        )
        self.assertTrue(driver.signaling_destination_allowed(call, "192.0.2.10"))
        self.assertTrue(driver.signaling_destination_allowed(call, "voice.example.test"))
        self.assertFalse(driver.signaling_destination_allowed(call, "198.51.100.66"))
        self.assertFalse(driver.signaling_destination_allowed(call, "other.example.test"))


class DriverScopeWatchTests(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name)
        self.play = self.root / "play.wav"
        write_tone(self.play)

    def tearDown(self):
        self._directory.cleanup()

    def call(self, **values):
        defaults = {
            "destination": "echo", "host": "192.0.2.10", "port": 5060, "transport": "udp",
            "play_file": self.play, "record_file": self.root / "heard.wav", "duration_seconds": 4,
            "log_file": self.root / "softphone.log", "console_file": self.root / "console.txt",
            "allowed_media_addresses": ("192.0.2.10",),
        }
        defaults.update(values)
        return SoftphoneCall(**defaults)

    def run_fake(self, call, mode):
        witness = self.root / f"witness-{mode}.json"
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "FAKE_PJSUA_WITNESS": str(witness),
               "FAKE_PJSUA_MODE": mode}
        private = self.root / f"private-{mode}"
        private.mkdir(mode=0o700, exist_ok=True)
        result = place_call(call, pjsua=str(FAKE_PJSUA), environment=env, private_root=private)
        self.assertEqual(list(private.iterdir()), [], "private directory leaked")
        return result, json.loads(witness.read_text())

    def test_far_end_route_set_off_scope_stops_pjsua_without_a_bye(self):
        result, record = self.run_fake(self.call(), "steer")
        self.assertEqual(result.error, "signaling_outside_scope")
        self.assertEqual(result.scope_violation["kind"], "signaling")
        self.assertEqual(result.scope_violation["address"], "198.51.100.66")
        # PJSUA was stopped before it could hang up (a BYE would follow the same route).
        self.assertNotIn("hangups", record)
        self.assertNotIn("h", record["commands"])
        self.assertLess(result.connected_seconds or 0, 2.0)

    def test_sdp_connection_address_off_scope_hangs_up_although_rtp_comes_from_an_approved_peer(self):
        result, record = self.run_fake(self.call(duration_seconds=20), "sdpsteer")
        self.assertEqual(result.error, "media_peer_outside_scope")
        self.assertEqual(result.scope_violation["kind"], "media")
        self.assertEqual(result.scope_violation["address"], "198.51.100.88")
        self.assertEqual(record.get("hangups"), ["BYE"])
        self.assertFalse(result.media_scope["inScope"])
        # The report names a media peer even when the hang-up came before
        # PJSUA printed one: then it is the address the SDP named.
        self.assertTrue(result.media_peer)
        self.assertIn(result.media_peer.rsplit(":", 1)[0], {"198.51.100.88", "192.0.2.10", "127.0.0.1"})

    def test_rtcp_attribute_off_scope_hangs_up(self):
        result, record = self.run_fake(self.call(duration_seconds=20), "rtcpsteer")
        self.assertEqual(result.error, "media_peer_outside_scope")
        self.assertEqual(result.scope_violation["address"], "198.51.100.99")
        self.assertEqual(result.scope_violation["what"], "RTCP")
        self.assertEqual(record.get("hangups"), ["BYE"])

    def test_in_scope_call_is_untouched(self):
        result, record = self.run_fake(self.call(duration_seconds=1), "answer")
        self.assertIsNone(result.error, result)
        self.assertIsNone(result.scope_violation)
        self.assertEqual(result.hangup, "duration")


class GuidedVerdictTests(unittest.TestCase):
    def classify(self, softphone, **values):
        return guided.classify(
            cancelled_signal=None, stop_reason=None, preflight_ok=True, softphone=softphone,
            oracle=None, media_required=True, network_mode="private", host="192.0.2.10",
            approved=["192.0.2.10"], **values,
        )

    def test_signaling_violation_is_a_safety_stop_verdict(self):
        from sippycup_cockpit.runs import SAFETY_STOPS as COCKPIT_STOPS
        from sippycup_workbench.call_explanations import CALL_EXPLANATIONS
        from sippycup_workbench.matrix import STOP_VERDICTS
        from sippycup_workbench.summary_model import SAFETY_STOPS as REPORT_STOPS

        state, verdict, code, notes = self.classify(
            {"error": "signaling_outside_scope", "answered": True,
             "scope_violation": {"kind": "signaling", "address": "198.51.100.66"}},
        )
        self.assertEqual((state, verdict, code), ("failed", "signaling-outside-scope", guided.EXIT_NOT_PASS))
        self.assertIn("198.51.100.66", " ".join(notes))
        self.assertIn("call.signaling-outside-scope", CALL_EXPLANATIONS)
        self.assertIn("signaling-outside-scope", STOP_VERDICTS)
        self.assertIn("signaling-outside-scope", COCKPIT_STOPS)
        self.assertIn("signaling-outside-scope", REPORT_STOPS)

    def test_sdp_refusal_is_not_cleared_by_the_unknown_peer_rule(self):
        softphone = {"error": "media_peer_outside_scope", "answered": True, "media_peer": None,
                     "scope_violation": {"kind": "media", "address": "198.51.100.99", "what": "RTCP"}}
        _state, verdict, _code, _notes = self.classify(softphone, remote_media=["192.0.2.10"])
        self.assertEqual(verdict, "media-outside-scope")


if __name__ == "__main__":
    unittest.main()
