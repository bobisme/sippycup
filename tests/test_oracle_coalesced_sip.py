"""Several SIP messages in one TCP segment must all reach the oracle."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from ladder_support import Capture, sip_request, sip_response  # noqa: E402

from sippycup_oracle.adapter import (  # noqa: E402
    _per_sip_message,
    parse_tshark_json,
    probe_capture_format,
    tshark_json_args,
)
from sippycup_oracle.dialogs import reconstruct_dialogs  # noqa: E402


class PerMessageLayersTests(unittest.TestCase):
    def test_single_message_frames_are_untouched(self) -> None:
        layers = {"frame": {}, "sip": {"sip.Call-ID": "a"}}
        self.assertEqual(_per_sip_message(layers), (layers,))
        self.assertEqual(_per_sip_message({"frame": {}}), ({"frame": {}},))

    def test_a_list_of_messages_becomes_one_view_each_in_order(self) -> None:
        layers = {"frame": {"frame.number": "7"}, "sip": [{"n": 1}, {"n": 2}]}
        views = _per_sip_message(layers)
        self.assertEqual([view["sip"] for view in views], [{"n": 1}, {"n": 2}])
        self.assertTrue(all(view["frame"] == layers["frame"] for view in views))


@unittest.skipUnless(shutil.which("tshark"), "tshark is required")
class CoalescedResponsesTests(unittest.TestCase):
    def test_ringing_and_answer_in_one_segment_are_both_decoded(self) -> None:
        caller, target = "192.0.2.10", "192.0.2.20"
        capture = Capture()
        start = capture.tcp_handshake(10.0, caller, 40000, target, 5060)
        invite = sip_request("INVITE", "coalesced-1", 1, transport="TCP", branch="z9hG4bKc1")
        ringing = sip_response(180, "Ringing", "INVITE", "coalesced-1", 1, transport="TCP",
                               branch="z9hG4bKc1")
        answer = sip_response(200, "OK", "INVITE", "coalesced-1", 1, transport="TCP",
                              branch="z9hG4bKc1")
        capture.tcp_data(start, caller, 40000, target, 5060, invite)
        capture.tcp_data(start + 0.2, target, 5060, caller, 40000, ringing + answer)
        with tempfile.TemporaryDirectory() as directory:
            path = capture.write(Path(directory) / "coalesced.pcap")
            completed = subprocess.run(tshark_json_args(path), capture_output=True, check=True)
            record = parse_tshark_json(completed.stdout, probe_capture_format(path))
        statuses = [
            frame.sip.status_code.value
            for frame in record.frames
            if frame.sip is not None and getattr(frame.sip.status_code, "value", None) is not None
        ]
        self.assertEqual(statuses, [180, 200])
        coalesced = [frame for frame in record.frames if frame.sip is not None][1:]
        self.assertEqual(
            coalesced[0].evidence.frame_number, coalesced[1].evidence.frame_number
        )
        events = [
            item.event for dialog in reconstruct_dialogs(record.frames).dialogs
            for item in dialog.transitions
        ]
        self.assertTrue(any("200" in event or "answer" in event or "2xx" in event for event in events),
                        events)


if __name__ == "__main__":
    unittest.main()
