from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_oracle.dialogs import reconstruct_dialogs  # noqa: E402
from sippycup_oracle.media import (  # noqa: E402
    Applicability,
    CorrelationKind,
    MediaDirection,
    MediaExpectations,
    evaluate_invariants,
    partition_media_frames,
)
from sippycup_oracle.records import (  # noqa: E402
    CaptureStatus,
    EvidenceRef,
    FrameRecord,
    Known,
    PayloadVisibility,
    RtcpRecord,
    RtpRecord,
    Unknown,
    UnknownReason,
    Verdict,
)
from tests.oracle.test_dialogs import endpoint, scenario_frames  # noqa: E402


def rtp_frame(
    number: int,
    arrival: str,
    *,
    caller_to_callee: bool,
    sequence: int | None,
    timestamp: int | None,
    payload_type: int | None = 0,
    ssrc: int | None = None,
    source_port: int | None = None,
    destination_port: int | None = None,
    source_address: str | None = None,
    destination_address: str | None = None,
    encrypted: bool = False,
) -> FrameRecord:
    caller = "192.0.2.10"
    callee = "198.51.100.20"
    if caller_to_callee:
        source_address = source_address or caller
        destination_address = destination_address or callee
        source_port = source_port or 4000
        destination_port = destination_port or 5000
        ssrc = ssrc if ssrc is not None else 100
    else:
        source_address = source_address or callee
        destination_address = destination_address or caller
        source_port = source_port or 5000
        destination_port = destination_port or 4000
        ssrc = ssrc if ssrc is not None else 200
    reason = UnknownReason.UNSUPPORTED_ENCRYPTION

    def value(item, field):
        return (
            Unknown(reason, field)
            if encrypted or item is None
            else Known(item)
        )

    return FrameRecord(
        evidence=EvidenceRef(Known(number), Known(Decimal(arrival))),
        captured_length=Known(172),
        original_length=Known(172),
        status=Known(CaptureStatus.COMPLETE),
        source=endpoint(source_address, source_port),
        destination=endpoint(destination_address, destination_port),
        protocols=("ip", "udp", "srtp" if encrypted else "rtp"),
        sip=None,
        sdp=None,
        rtp=RtpRecord(
            ssrc=value(ssrc, "rtp.ssrc"),
            sequence=value(sequence, "rtp.seq"),
            timestamp=value(timestamp, "rtp.timestamp"),
            payload_type=value(payload_type, "rtp.p_type"),
            marker=value(False, "rtp.marker"),
            payload_visibility=(
                Unknown(reason, "encrypted media")
                if encrypted
                else Known(PayloadVisibility.METADATA_ONLY)
            ),
        ),
        rtcp=None,
    )


def rtcp_frame(number: int, arrival: str) -> FrameRecord:
    return FrameRecord(
        evidence=EvidenceRef(Known(number), Known(Decimal(arrival))),
        captured_length=Known(96),
        original_length=Known(96),
        status=Known(CaptureStatus.COMPLETE),
        source=endpoint("192.0.2.10", 4001),
        destination=endpoint("198.51.100.20", 5001),
        protocols=("ip", "udp", "rtcp"),
        sip=None,
        sdp=None,
        rtp=None,
        rtcp=RtcpRecord(
            packet_type=Known(200),
            sender_ssrc=Known(100),
            payload_visibility=Known(PayloadVisibility.METADATA_ONLY),
        ),
    )


def baseline_dialog():
    return reconstruct_dialogs(scenario_frames("baseline")).dialogs[0]


def good_media() -> tuple[FrameRecord, ...]:
    return (
        rtp_frame(100, "0.32", caller_to_callee=True, sequence=1, timestamp=0),
        rtp_frame(101, "0.34", caller_to_callee=True, sequence=2, timestamp=160),
        rtp_frame(
            102,
            "0.36",
            caller_to_callee=True,
            sequence=3,
            timestamp=320,
            payload_type=101,
        ),
        rtp_frame(110, "0.33", caller_to_callee=False, sequence=10, timestamp=0),
        rtp_frame(111, "0.35", caller_to_callee=False, sequence=11, timestamp=160),
        rtcp_frame(120, "0.37"),
    )


def assertions(analysis):
    return {item.assertion_id: item for item in analysis.assertions}


class MediaInvariantTests(unittest.TestCase):
    def test_good_bidirectional_media_codecs_dtmf_metrics_and_rtcp(self) -> None:
        analysis = evaluate_invariants(
            good_media(),
            baseline_dialog(),
            MediaExpectations(
                expected_codecs=("PCMU",),
                require_dtmf=True,
                max_jitter_ms=Decimal("5"),
            ),
        )
        result = assertions(analysis)
        for key in (
            "media.directionality",
            "media.endpoints",
            "media.payloads",
            "media.codecs",
            "media.dtmf",
            "media.timing",
            "media.sequence",
            "media.jitter",
            "media.transitions",
        ):
            self.assertEqual(result[key].verdict, Verdict.PASS, key)
            self.assertTrue(result[key].evidence, key)
        self.assertEqual(len(analysis.streams), 2)
        self.assertEqual(len(analysis.rtcp), 1)
        self.assertIsInstance(analysis.rtcp[0].matched_stream, Known)
        self.assertEqual(analysis.streams[0].metrics.lost, Known(0))

    def test_one_way_media_fails_directionality(self) -> None:
        media = tuple(
            frame for frame in good_media() if frame.rtp and frame.source.address == Known("192.0.2.10")
        )
        result = assertions(evaluate_invariants(media, baseline_dialog()))
        self.assertEqual(result["media.directionality"].verdict, Verdict.FAIL)
        self.assertIn("callee_to_caller", result["media.directionality"].message)

    def test_third_party_address_fails_endpoint_assertion(self) -> None:
        media = good_media() + (
            rtp_frame(
                130,
                "0.40",
                caller_to_callee=True,
                sequence=4,
                timestamp=480,
                source_address="203.0.113.66",
            ),
        )
        result = assertions(evaluate_invariants(media, baseline_dialog()))
        self.assertEqual(result["media.endpoints"].verdict, Verdict.FAIL)
        self.assertEqual(
            result["media.endpoints"].evidence[0].frame_number, Known(130)
        )

    def test_payload_mismatch_loss_duplicate_reorder_and_jump_fail(self) -> None:
        media = (
            rtp_frame(200, "0.32", caller_to_callee=True, sequence=1, timestamp=0),
            rtp_frame(201, "0.34", caller_to_callee=True, sequence=3, timestamp=160),
            rtp_frame(202, "0.36", caller_to_callee=True, sequence=3, timestamp=160),
            rtp_frame(
                203,
                "0.38",
                caller_to_callee=True,
                sequence=2,
                timestamp=100000,
                payload_type=99,
            ),
            rtp_frame(210, "0.33", caller_to_callee=False, sequence=1, timestamp=0),
            rtp_frame(211, "0.35", caller_to_callee=False, sequence=2, timestamp=160),
        )
        result = assertions(evaluate_invariants(media, baseline_dialog()))
        self.assertEqual(result["media.payloads"].verdict, Verdict.FAIL)
        self.assertEqual(result["media.sequence"].verdict, Verdict.FAIL)
        self.assertEqual(result["media.transitions"].verdict, Verdict.FAIL)

    def test_media_before_answer_and_after_bye_request_fails_timing(self) -> None:
        media = good_media() + (
            rtp_frame(300, "0.25", caller_to_callee=True, sequence=20, timestamp=0),
            rtp_frame(301, "0.51", caller_to_callee=True, sequence=21, timestamp=160),
        )
        result = assertions(evaluate_invariants(media, baseline_dialog()))
        self.assertEqual(result["media.timing"].verdict, Verdict.FAIL)
        frames = {item.frame_number.value for item in result["media.timing"].evidence}
        self.assertEqual(frames, {300, 301})

    def test_renegotiated_payload_change_is_not_an_unexpected_transition(self) -> None:
        dialog = reconstruct_dialogs(scenario_frames("renegotiation")).dialogs[0]
        media = (
            rtp_frame(400, "0.25", caller_to_callee=True, sequence=1, timestamp=0),
            rtp_frame(
                401,
                "0.55",
                caller_to_callee=True,
                sequence=2,
                timestamp=2400,
                payload_type=8,
                ssrc=300,
            ),
            rtp_frame(
                402,
                "0.85",
                caller_to_callee=True,
                sequence=3,
                timestamp=4800,
                payload_type=0,
                ssrc=400,
            ),
        )
        result = assertions(
            evaluate_invariants(
                media, dialog, MediaExpectations(require_bidirectional=False)
            )
        )
        self.assertEqual(result["media.payloads"].verdict, Verdict.PASS)
        self.assertEqual(result["media.transitions"].verdict, Verdict.PASS)

    def test_unnegotiated_ssrc_change_fails_transition_assertion(self) -> None:
        media = (
            rtp_frame(450, "0.32", caller_to_callee=True, sequence=1, timestamp=0),
            rtp_frame(
                451,
                "0.34",
                caller_to_callee=True,
                sequence=2,
                timestamp=160,
                ssrc=999,
            ),
        )
        result = assertions(
            evaluate_invariants(
                media,
                baseline_dialog(),
                MediaExpectations(require_bidirectional=False),
            )
        )
        self.assertEqual(result["media.transitions"].verdict, Verdict.FAIL)
        self.assertEqual(
            result["media.transitions"].evidence[0].frame_number, Known(451)
        )

    def test_rtp_sequence_wrap_does_not_look_like_loss_or_reordering(self) -> None:
        media = (
            rtp_frame(
                470,
                "0.32",
                caller_to_callee=True,
                sequence=65535,
                timestamp=0,
            ),
            rtp_frame(
                471,
                "0.34",
                caller_to_callee=True,
                sequence=0,
                timestamp=160,
            ),
        )
        analysis = evaluate_invariants(
            media,
            baseline_dialog(),
            MediaExpectations(require_bidirectional=False),
        )
        metrics = analysis.streams[0].metrics
        self.assertEqual(metrics.expected, Known(2))
        self.assertEqual(metrics.lost, Known(0))
        self.assertEqual(metrics.reordered, Known(0))

    def test_isolated_timestamp_jump_fails_sequence_continuity(self) -> None:
        media = (
            rtp_frame(480, "0.32", caller_to_callee=True, sequence=1, timestamp=0),
            rtp_frame(
                481,
                "0.34",
                caller_to_callee=True,
                sequence=2,
                timestamp=100000,
            ),
            rtp_frame(482, "0.32", caller_to_callee=False, sequence=1, timestamp=0),
            rtp_frame(483, "0.34", caller_to_callee=False, sequence=2, timestamp=160),
        )
        analysis = evaluate_invariants(media, baseline_dialog())
        jumping = next(
            stream
            for stream in analysis.streams
            if stream.direction is MediaDirection.CALLER_TO_CALLEE
        )
        self.assertEqual(jumping.metrics.lost, Known(0))
        self.assertEqual(jumping.metrics.duplicates, Known(0))
        self.assertEqual(jumping.metrics.reordered, Known(0))
        self.assertEqual(jumping.metrics.timestamp_jumps, Known(1))
        self.assertEqual(
            assertions(analysis)["media.sequence"].verdict, Verdict.FAIL
        )

    def test_symmetric_rtp_is_explicit_and_configurable(self) -> None:
        media = (
            rtp_frame(
                500,
                "0.32",
                caller_to_callee=True,
                sequence=1,
                timestamp=0,
                source_port=45000,
                destination_port=55000,
            ),
            rtp_frame(
                501,
                "0.33",
                caller_to_callee=False,
                sequence=1,
                timestamp=0,
                source_port=55000,
                destination_port=45000,
            ),
        )
        allowed = evaluate_invariants(media, baseline_dialog())
        self.assertTrue(
            all(
                stream.correlation is CorrelationKind.SYMMETRIC
                for stream in allowed.streams
            )
        )
        self.assertEqual(
            assertions(allowed)["media.endpoints"].verdict, Verdict.PASS
        )
        denied = evaluate_invariants(
            media,
            baseline_dialog(),
            MediaExpectations(allow_symmetric_rtp=False),
        )
        self.assertEqual(
            assertions(denied)["media.endpoints"].verdict, Verdict.FAIL
        )

    def test_encrypted_media_gets_transport_only_analysis(self) -> None:
        media = (
            rtp_frame(
                600,
                "0.32",
                caller_to_callee=True,
                sequence=None,
                timestamp=None,
                encrypted=True,
            ),
            rtp_frame(
                601,
                "0.33",
                caller_to_callee=False,
                sequence=None,
                timestamp=None,
                encrypted=True,
            ),
        )
        result = assertions(evaluate_invariants(media, baseline_dialog()))
        self.assertEqual(result["media.directionality"].verdict, Verdict.PASS)
        self.assertEqual(result["media.endpoints"].verdict, Verdict.PASS)
        self.assertEqual(result["media.payloads"].verdict, Verdict.UNKNOWN)
        self.assertEqual(result["media.sequence"].verdict, Verdict.UNKNOWN)
        self.assertEqual(result["media.transitions"].verdict, Verdict.UNKNOWN)
        self.assertEqual(
            result["media.payloads"].observed.reason,
            UnknownReason.UNSUPPORTED_ENCRYPTION,
        )

    def test_frozen_allowlist_does_not_self_authorize_negotiated_relay(self) -> None:
        dialog = baseline_dialog()
        answer = dialog.sdp_revisions[1]
        answer_media = answer.revision.media[0]
        relay_answer = replace(
            answer,
            revision=replace(
                answer.revision,
                connection_address=Known("203.0.113.50"),
                media=(
                    replace(
                        answer_media,
                        address=Known("203.0.113.50"),
                    ),
                ),
            ),
        )
        relay_dialog = replace(
            dialog,
            sdp_revisions=(dialog.sdp_revisions[0], relay_answer),
        )
        strict = MediaExpectations(
            allowed_endpoints=("192.0.2.10", "198.51.100.20")
        )
        result = assertions(
            evaluate_invariants(good_media(), relay_dialog, strict)
        )
        self.assertEqual(result["media.endpoints"].verdict, Verdict.FAIL)
        self.assertIn("unapproved", result["media.endpoints"].message)

        relay_media = (
            rtp_frame(
                900,
                "0.32",
                caller_to_callee=True,
                sequence=1,
                timestamp=0,
                destination_address="203.0.113.50",
            ),
            rtp_frame(
                901,
                "0.33",
                caller_to_callee=False,
                sequence=1,
                timestamp=0,
                source_address="203.0.113.50",
            ),
        )
        approved = replace(
            strict,
            allowed_endpoints=(
                "192.0.2.10",
                "198.51.100.20",
                "203.0.113.50",
            ),
        )
        self.assertEqual(
            assertions(
                evaluate_invariants(relay_media, relay_dialog, approved)
            )["media.endpoints"].verdict,
            Verdict.PASS,
        )

    def test_frozen_allowlist_applies_to_sip_frames(self) -> None:
        signaling = list(scenario_frames("baseline"))
        signaling[3] = replace(
            signaling[3],
            source=endpoint("203.0.113.60", 5060),
        )
        frames = tuple(signaling) + good_media()
        result = assertions(
            evaluate_invariants(
                frames,
                baseline_dialog(),
                MediaExpectations(
                    allowed_endpoints=("192.0.2.10", "198.51.100.20")
                ),
            )
        )
        self.assertEqual(result["media.endpoints"].verdict, Verdict.FAIL)

    def test_sdp_direction_and_port_zero_are_enforced(self) -> None:
        dialog = baseline_dialog()
        offer, answer = dialog.sdp_revisions
        offer_media = replace(
            offer.revision.media[0], direction=Known("sendonly")
        )
        answer_media = replace(
            answer.revision.media[0], direction=Known("recvonly")
        )
        directional = replace(
            dialog,
            sdp_revisions=(
                replace(offer, revision=replace(offer.revision, media=(offer_media,))),
                replace(answer, revision=replace(answer.revision, media=(answer_media,))),
            ),
        )
        result = assertions(evaluate_invariants(good_media(), directional))
        self.assertEqual(result["media.sdp_direction"].verdict, Verdict.FAIL)
        prohibited = {
            evidence.frame_number.value
            for evidence in result["media.sdp_direction"].evidence
        }
        self.assertTrue({110, 111} <= prohibited)

        disabled_answer = replace(answer_media, port=Known(0))
        disabled = replace(
            directional,
            sdp_revisions=(
                directional.sdp_revisions[0],
                replace(
                    directional.sdp_revisions[1],
                    revision=replace(
                        directional.sdp_revisions[1].revision,
                        media=(disabled_answer,),
                    ),
                ),
            ),
        )
        disabled_result = assertions(
            evaluate_invariants(good_media(), disabled)
        )
        self.assertEqual(
            disabled_result["media.sdp_direction"].verdict, Verdict.FAIL
        )

    def test_rejected_reinvite_sdp_does_not_activate_payload_or_codec(self) -> None:
        dialog = reconstruct_dialogs(scenario_frames("failed_reinvite")).dialogs[0]
        packet = rtp_frame(
            920,
            "0.55",
            caller_to_callee=True,
            sequence=1,
            timestamp=0,
            payload_type=8,
        )
        result = assertions(
            evaluate_invariants(
                (packet,),
                dialog,
                MediaExpectations(
                    require_bidirectional=False,
                    expected_codecs=("PCMA",),
                ),
            )
        )
        self.assertEqual(result["media.payloads"].verdict, Verdict.FAIL)
        self.assertEqual(result["media.codecs"].verdict, Verdict.FAIL)

    def test_fork_media_is_not_reused_across_dialog_legs(self) -> None:
        dialogs = reconstruct_dialogs(scenario_frames("fork")).dialogs
        packet = rtp_frame(
            930,
            "0.35",
            caller_to_callee=True,
            sequence=1,
            timestamp=0,
        )
        assigned, ambiguity = partition_media_frames((packet,), dialogs)
        self.assertEqual(sum(len(items) for items in assigned), 0)
        self.assertTrue(all(items for items in ambiguity))
        for dialog, frames, evidence in zip(dialogs, assigned, ambiguity):
            result = assertions(
                evaluate_invariants(
                    frames,
                    dialog,
                    MediaExpectations(require_bidirectional=False),
                    assignment_ambiguity=evidence,
                )
            )
            self.assertEqual(
                result["media.assignment"].verdict, Verdict.UNKNOWN
            )

    def test_assertions_always_report_evidence_and_applicability(self) -> None:
        analysis = evaluate_invariants(
            (),
            baseline_dialog(),
            MediaExpectations(require_bidirectional=False),
        )
        for result in analysis.assertions:
            self.assertTrue(result.evidence, result.assertion_id)
            self.assertIsInstance(result.applicability, Applicability)
        result = assertions(analysis)
        self.assertEqual(
            result["media.directionality"].applicability,
            Applicability.NOT_APPLICABLE,
        )
        self.assertEqual(
            result["media.codecs"].applicability,
            Applicability.NOT_APPLICABLE,
        )


if __name__ == "__main__":
    unittest.main()
