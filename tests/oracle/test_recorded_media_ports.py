"""bn-3oib: the run's recorded local RTP port attributes media whose dialog is not visible.

A capture that holds a cleartext (UDP) call and a TLS call shows only the
cleartext dialog. Without a record the TLS call's RTP is unattributed and
the run is inconclusive (exit 4) even when both calls were healthy; when the
TLS call overlapped the cleartext one its RTP was even judged against the
cleartext dialog (a false failure). ``call-media.json`` records each call's
local RTP port and window, so the oracle can tell whose media is whose and
still refuses to guess where the record does not decide.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_oracle.call_media import (  # noqa: E402
    CALL_MEDIA_VERSION,
    CallMediaError,
    call_media_document,
    load_call_media,
    parse_call_media,
    recorded_call,
)
from sippycup_oracle.cli import build_result_document  # noqa: E402
from sippycup_oracle.media import MediaExpectations  # noqa: E402
from sippycup_oracle.records import CaptureFormat, CaptureRecord  # noqa: E402
from tests.oracle.test_dialogs import scenario_frames  # noqa: E402
from tests.oracle.test_media import good_media, rtp_frame  # noqa: E402

CALLER = "192.0.2.10"
NS = 10**9


def media_at(first_number: int, base: str, *, caller_port: int, caller_ssrc: int,
             callee_ssrc: int, callee_port: int = 5000) -> tuple:
    """Bidirectional RTP of one call from CALLER:CALLER_PORT, 20 ms apart."""
    from decimal import Decimal

    start = Decimal(base)
    frames = []
    for index in range(3):
        at = start + Decimal("0.02") * index
        frames.append(rtp_frame(
            first_number + index, str(at), caller_to_callee=True,
            sequence=1 + index, timestamp=160 * index, ssrc=caller_ssrc,
            source_port=caller_port, destination_port=callee_port,
        ))
        frames.append(rtp_frame(
            first_number + 10 + index, str(at + Decimal("0.01")), caller_to_callee=False,
            sequence=10 + index, timestamp=160 * index, ssrc=callee_ssrc,
            source_port=callee_port, destination_port=caller_port,
        ))
    return tuple(frames)


def record(*calls, complete: bool = True):
    return parse_call_media({
        "schema_version": CALL_MEDIA_VERSION,
        "complete": complete,
        "calls": list(calls),
    })


def call(name: str, transport: str, port: int, start: float, end: float) -> dict:
    return recorded_call(name, transport, CALLER, port, int(start * NS), int(end * NS))


# The UDP call of scenario "baseline" runs from 0.1 s to 0.6 s on port 4000.
UDP_CALL = call("step 1", "udp", 4000, 0.0, 0.9)


def analyze(frames, call_media=None) -> dict:
    capture = CaptureRecord("sippycup.packet-records/v1", CaptureFormat.PCAP, frames)
    return build_result_document(capture, MediaExpectations(), call_media=call_media)


def by_id(document: dict) -> dict:
    return {item["id"]: item for item in document["assertions"]}


def failed(document: dict) -> list:
    return sorted(key for key, item in by_id(document).items() if item["verdict"] == "fail")


def stream_frames(document: dict) -> list:
    return sorted(
        item["frame_number"]["value"]
        for stream in document["streams"] for item in stream["evidence"]
    )


GOOD_RTP = sorted(
    frame.evidence.frame_number.value for frame in good_media() if frame.rtp is not None
)


class SequentialMixedTransportTests(unittest.TestCase):
    """Campaign steps: a UDP call, then a TLS call (the normal mixed case)."""

    TLS = media_at(900, "2.00", caller_port=4002, caller_ssrc=7001, callee_ssrc=7002)
    FRAMES = scenario_frames("baseline") + good_media() + TLS

    def test_without_a_record_it_stays_inconclusive(self) -> None:
        document = analyze(self.FRAMES)
        self.assertEqual(document["verdict"], "unknown")
        attribution = by_id(document)["capture.media.attribution"]
        self.assertEqual(attribution["verdict"], "unknown")
        self.assertIn("no call-media.json", attribution["message"])

    def test_the_recorded_port_attributes_the_tls_media_and_the_run_passes(self) -> None:
        tls = call("step 2", "tls", 4002, 1.9, 3.0)
        document = analyze(self.FRAMES, record(UDP_CALL, tls))
        self.assertEqual(failed(document), [])
        attribution = by_id(document)["capture.media.attribution"]
        self.assertEqual(attribution["verdict"], "pass")
        self.assertIn("step 2 (tls, local RTP port 4002)", attribution["message"])
        self.assertIn("not judged", attribution["message"])
        self.assertEqual(
            attribution["observed"]["value"],
            [{"call": "step 2", "transport": "tls", "local_rtp_port": 4002, "packets": 6}],
        )
        # Only the UDP dialog's own media was judged against it.
        self.assertEqual(stream_frames(document), GOOD_RTP)
        self.assertNotEqual(document["verdict"], "fail")
        self.assertEqual(
            {item["verdict"] for key, item in by_id(document).items()
             if item["applicability"] == "applicable"} - {"pass"},
            set(),
        )

    def test_a_reused_port_in_a_later_window_is_still_attributed(self) -> None:
        # Ports wrap in long campaigns: the same port 50 steps later is told
        # apart by its window.
        tls = media_at(900, "2.00", caller_port=4000, caller_ssrc=7001, callee_ssrc=7002)
        document = analyze(
            scenario_frames("baseline") + good_media() + tls,
            record(UDP_CALL, call("step 51", "tls", 4000, 1.9, 3.0)),
        )
        self.assertEqual(failed(document), [])
        self.assertEqual(by_id(document)["capture.media.attribution"]["verdict"], "pass")
        self.assertEqual(stream_frames(document), GOOD_RTP)

    def test_a_record_that_misses_the_tls_call_refuses_to_guess(self) -> None:
        document = analyze(self.FRAMES, record(UDP_CALL))
        attribution = by_id(document)["capture.media.attribution"]
        self.assertEqual(attribution["verdict"], "unknown")
        self.assertIn("does not attribute them", attribution["message"])
        self.assertEqual(document["verdict"], "unknown")


class OverlappingCallTests(unittest.TestCase):
    """A TLS call whose RTP starts while the UDP call is up (hand-run concurrency)."""

    TLS = media_at(900, "0.40", caller_port=4002, caller_ssrc=7001, callee_ssrc=7002)
    FRAMES = scenario_frames("baseline") + good_media() + TLS

    def test_without_a_record_the_tls_media_is_judged_against_the_udp_dialog(self) -> None:
        # The pre-record behaviour, kept for old captures: nothing in the
        # capture says the port-4002 stream is another call.
        self.assertIn("dialog[0].media.transitions", failed(analyze(self.FRAMES)))

    def test_the_recorded_port_keeps_the_tls_media_off_the_udp_dialog(self) -> None:
        document = analyze(
            self.FRAMES, record(UDP_CALL, call("step 2", "tls", 4002, 0.35, 1.0))
        )
        self.assertEqual(failed(document), [])
        self.assertEqual(by_id(document)["capture.media.attribution"]["verdict"], "pass")
        self.assertEqual(stream_frames(document), GOOD_RTP)

    def test_a_complete_record_without_that_port_makes_it_unknown_not_failed(self) -> None:
        # A `call` run's record lists only its own call; a concurrent call
        # from another terminal is on a port the record does not know.
        document = analyze(self.FRAMES, record(UDP_CALL))
        self.assertEqual(failed(document), [])
        self.assertEqual(by_id(document)["capture.media.attribution"]["verdict"], "unknown")
        self.assertEqual(document["verdict"], "unknown")
        self.assertEqual(stream_frames(document), GOOD_RTP)

    def test_an_incomplete_record_keeps_the_old_behaviour_for_unrecorded_ports(self) -> None:
        document = analyze(self.FRAMES, record(UDP_CALL, complete=False))
        self.assertIn("dialog[0].media.transitions", failed(document))

    def test_one_port_recorded_for_two_overlapping_calls_is_unknown(self) -> None:
        tls = media_at(900, "0.40", caller_port=4000, caller_ssrc=7001, callee_ssrc=7002)
        document = analyze(
            scenario_frames("baseline") + good_media() + tls,
            record(UDP_CALL, call("step 2", "tls", 4000, 0.35, 1.0)),
        )
        self.assertEqual(failed(document), [])
        self.assertEqual(by_id(document)["capture.media.attribution"]["verdict"], "unknown")
        self.assertEqual(document["verdict"], "unknown")


class RealFaultsStillFailTests(unittest.TestCase):
    def test_media_after_bye_on_the_recorded_port_still_fails_timing(self) -> None:
        late = rtp_frame(130, "1.40", caller_to_callee=True, sequence=4, timestamp=480)
        document = analyze(
            scenario_frames("baseline") + good_media() + (late,), record(UDP_CALL)
        )
        self.assertIn("dialog[0].media.timing", failed(document))
        self.assertNotIn("capture.media.attribution", by_id(document))

    def test_a_single_recorded_call_adds_no_attribution_result(self) -> None:
        document = analyze(scenario_frames("baseline") + good_media(), record(UDP_CALL))
        self.assertEqual(document["verdict"], "pass")
        self.assertNotIn("capture.media.attribution", by_id(document))


class RecordFileTests(unittest.TestCase):
    def test_document_is_complete_only_when_every_call_is_listed(self) -> None:
        self.assertTrue(call_media_document([UDP_CALL], placed=1)["complete"])
        self.assertFalse(call_media_document([UDP_CALL, None], placed=2)["complete"])
        self.assertIsNone(recorded_call("step 3", "tls", CALLER, None, 0, 1))

    def test_malformed_records_are_refused(self) -> None:
        good = {"schema_version": CALL_MEDIA_VERSION, "complete": True, "calls": [UDP_CALL]}
        bad = [
            {**good, "schema_version": "sippycup.call-media/v2"},
            {**good, "extra": 1},
            {**good, "complete": "yes"},
            {**good, "calls": [{**UDP_CALL, "rtcp_port": 4003}]},
            {**good, "calls": [{**UDP_CALL, "local_address": "host.example"}]},
            {**good, "calls": [{**UDP_CALL, "ended_unix_ns": -1}]},
            {**good, "calls": [{**UDP_CALL, "rtp_port": True}]},
        ]
        for document in bad:
            with self.subTest(document=document), self.assertRaises(CallMediaError):
                parse_call_media(document)

    def test_load_reads_the_file_and_tolerates_its_absence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "call-media.json"
            self.assertIsNone(load_call_media(path))
            path.write_text(json.dumps(call_media_document([UDP_CALL], placed=1)))
            loaded = load_call_media(path)
            self.assertEqual(loaded.calls[0].rtp_port, 4000)
            path.write_text("{")
            with self.assertRaises(CallMediaError):
                load_call_media(path)


if __name__ == "__main__":
    unittest.main()
