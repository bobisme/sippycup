"""bn-2sfa: RTP of a TLS call must not be judged as part of a cleartext dialog.

In a campaign capture that holds cleartext (UDP) calls and TLS calls, only the
cleartext dialogs and their SDP are visible. Every PJSUA call binds the same
local RTP port (PJSUA's default, 4000), so the RTP of a later TLS call uses the
same local address and port as an earlier cleartext call. Before the fix the
oracle treated a dialog's SDP as active for ever after its answer and handed a
lone dialog every RTP frame in the capture, so the TLS call's RTP was judged
against the cleartext dialog: media.timing failed (media after teardown) and
media.transitions failed (SSRC change without renegotiation) for a call that
was fine.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_oracle.cli import build_result_document  # noqa: E402
from sippycup_oracle.dialogs import reconstruct_dialogs  # noqa: E402
from sippycup_oracle.media import (  # noqa: E402
    MediaExpectations,
    partition_media_frames,
)
from sippycup_oracle.records import (  # noqa: E402
    CaptureFormat,
    CaptureRecord,
)
from tests.oracle.test_dialogs import scenario_frames  # noqa: E402
from tests.oracle.test_media import good_media, rtcp_frame, rtp_frame  # noqa: E402


def media_at(first_number: int, base: str, *, callee_port: int = 5000,
             caller_ssrc: int = 100, callee_ssrc: int = 200) -> tuple:
    """Bidirectional RTP of one call, 20 ms apart, starting at BASE seconds."""
    from decimal import Decimal

    start = Decimal(base)
    frames = []
    for index in range(3):
        at = start + Decimal("0.02") * index
        frames.append(rtp_frame(
            first_number + index, str(at), caller_to_callee=True,
            sequence=1 + index, timestamp=160 * index, ssrc=caller_ssrc,
            destination_port=callee_port,
        ))
        frames.append(rtp_frame(
            first_number + 10 + index, str(at + Decimal("0.01")), caller_to_callee=False,
            sequence=10 + index, timestamp=160 * index, ssrc=callee_ssrc,
            source_port=callee_port,
        ))
    return tuple(frames)


# The TLS call: its SIP is encrypted (no SIP records), its RTP leaves the same
# local port 4000 and uses fresh SSRCs, two seconds after the cleartext call.
TLS_CALL_MEDIA = media_at(900, "2.00", caller_ssrc=7001, callee_ssrc=7002)


def by_id(document: dict) -> dict:
    return {item["id"]: item for item in document["assertions"]}


class MixedTransportAttributionTests(unittest.TestCase):
    def test_tls_call_media_is_not_judged_against_the_only_cleartext_dialog(self) -> None:
        capture = CaptureRecord(
            "sippycup.packet-records/v1",
            CaptureFormat.PCAP,
            scenario_frames("baseline") + good_media() + TLS_CALL_MEDIA,
        )
        document = build_result_document(capture, MediaExpectations())
        results = by_id(document)
        failed = sorted(key for key, item in results.items() if item["verdict"] == "fail")
        self.assertEqual(failed, [])
        self.assertEqual(results["dialog[0].media.timing"]["verdict"], "pass")
        self.assertEqual(results["dialog[0].media.transitions"]["verdict"], "pass")
        attribution = results["capture.media.attribution"]
        self.assertEqual(attribution["verdict"], "unknown")
        self.assertEqual(attribution["applicability"], "applicable")
        self.assertIn("could not be attributed", attribution["message"])
        self.assertEqual(
            sorted(item["frame_number"]["value"] for item in attribution["evidence"]),
            sorted(frame.evidence.frame_number.value for frame in TLS_CALL_MEDIA),
        )
        # Inconclusive, not failed: the TLS call's media was not judged.
        self.assertEqual(document["verdict"], "unknown")
        self.assertEqual(
            {stream["dialog_id"] for stream in document["streams"]}, {"dialog[0]"}
        )
        self.assertEqual(
            sum(len(stream["evidence"]) for stream in document["streams"]),
            sum(1 for frame in good_media() if frame.rtp is not None),
        )

    def test_tls_call_between_two_cleartext_calls_is_not_given_to_the_earlier_one(self) -> None:
        second = scenario_frames("baseline", call_id="second@example.invalid", start=31)
        second_media = media_at(950, "3.32", caller_ssrc=300, callee_ssrc=400)
        frames = scenario_frames("baseline") + good_media() + TLS_CALL_MEDIA
        dialogs = reconstruct_dialogs(frames + second).dialogs
        self.assertEqual(len(dialogs), 2)
        assigned, ambiguous = partition_media_frames(
            frames + second + second_media, dialogs
        )
        first_index = next(
            index for index, dialog in enumerate(dialogs)
            if dialog.key.call_id == "baseline@example.invalid"
        )
        tls_numbers = {frame.evidence.frame_number.value for frame in TLS_CALL_MEDIA}
        for index in range(len(dialogs)):
            self.assertFalse(
                tls_numbers & {frame.evidence.frame_number.value for frame in assigned[index]}
            )
            self.assertFalse(
                tls_numbers & {item.frame_number.value for item in ambiguous[index]}
            )
        self.assertEqual(
            {frame.evidence.frame_number.value for frame in assigned[first_index]},
            {frame.evidence.frame_number.value for frame in good_media()},
        )

    def test_media_continuing_past_bye_still_fails_timing(self) -> None:
        # The same stream (same five-tuple and SSRC) running on after the BYE
        # still belongs to its dialog, so a real late-media fault is reported.
        late = rtp_frame(130, "1.40", caller_to_callee=True, sequence=4, timestamp=480)
        capture = CaptureRecord(
            "sippycup.packet-records/v1",
            CaptureFormat.PCAP,
            scenario_frames("baseline") + good_media() + (late,),
        )
        results = by_id(build_result_document(capture, MediaExpectations()))
        self.assertEqual(results["dialog[0].media.timing"]["verdict"], "fail")
        self.assertNotIn("capture.media.attribution", results)

    def test_rtcp_sent_just_after_teardown_stays_with_its_call(self) -> None:
        capture = CaptureRecord(
            "sippycup.packet-records/v1",
            CaptureFormat.PCAP,
            scenario_frames("baseline") + good_media() + (rtcp_frame(140, "0.95"),),
        )
        document = build_result_document(capture, MediaExpectations())
        self.assertEqual(document["verdict"], "pass")
        self.assertNotIn("capture.media.attribution", by_id(document))

    def test_selected_call_gets_only_its_own_media(self) -> None:
        second = scenario_frames("baseline", call_id="second@example.invalid", start=31)
        second_media = media_at(950, "3.32", caller_ssrc=300, callee_ssrc=400)
        capture = CaptureRecord(
            "sippycup.packet-records/v1",
            CaptureFormat.PCAP,
            scenario_frames("baseline") + good_media() + second + second_media,
        )
        document = build_result_document(
            capture, MediaExpectations(), dialog_selector="second@example.invalid"
        )
        self.assertEqual(document["verdict"], "pass")
        self.assertNotIn("capture.media.attribution", by_id(document))
        self.assertEqual(
            sorted(
                item["frame_number"]["value"]
                for stream in document["streams"] for item in stream["evidence"]
            ),
            sorted(frame.evidence.frame_number.value for frame in second_media),
        )

    def test_single_call_capture_has_no_attribution_result(self) -> None:
        capture = CaptureRecord(
            "sippycup.packet-records/v1",
            CaptureFormat.PCAP,
            scenario_frames("baseline") + good_media(),
        )
        document = build_result_document(capture, MediaExpectations())
        self.assertNotIn("capture.media.attribution", by_id(document))


if __name__ == "__main__":
    unittest.main()
