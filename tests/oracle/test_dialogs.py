from __future__ import annotations

import json
import sys
import unittest
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_oracle.dialogs import (  # noqa: E402
    DialogState,
    SdpRole,
    TransactionState,
    reconstruct_dialogs,
)
from sippycup_oracle.records import (  # noqa: E402
    AddressFamily,
    CaptureStatus,
    CodecRecord,
    EndpointRecord,
    EvidenceRef,
    FrameRecord,
    Known,
    SdpMediaRecord,
    SdpRevisionRecord,
    SipRecord,
    Transport,
    Unknown,
    UnknownReason,
)

FIXTURES = Path(__file__).parent / "fixtures"
SCENARIOS = json.loads(
    (FIXTURES / "dialog-scenarios.json").read_text(encoding="utf-8")
)


def endpoint(address: str, port: int = 5060) -> EndpointRecord:
    return EndpointRecord(
        Known(address),
        Known(AddressFamily.IPV4),
        Known(port),
        Known(Transport.UDP),
    )


def sdp(evidence: EvidenceRef, role: str) -> SdpRevisionRecord:
    is_offer = role.startswith("offer")
    address = "192.0.2.10" if is_offer else "198.51.100.20"
    port = 4000 if is_offer else 5000
    primary_payload = 8 if role.endswith("2") else 0
    primary_codec = "PCMA" if primary_payload == 8 else "PCMU"
    return SdpRevisionRecord(
        evidence=evidence,
        connection_address=Known(address),
        session_name=Known(f"{role} fixture"),
        media=(
            SdpMediaRecord(
                media_type=Known("audio"),
                address=Known(address),
                port=Known(port),
                protocol=Known("RTP/AVP"),
                payload_types=Known((primary_payload, 101)),
                codecs=Known((
                    CodecRecord(
                        primary_payload,
                        Known(primary_codec),
                        Known(8000),
                        Known(1),
                        Unknown(UnknownReason.MISSING_FIELD, "sdp fmtp"),
                    ),
                    CodecRecord(
                        101,
                        Known("telephone-event"),
                        Known(8000),
                        Known(1),
                        Known("0-16"),
                    ),
                )),
                telephone_event_payloads=Known((101,)),
                direction=Known("sendrecv"),
                packet_time_ms=Known(20),
                rtcp_address=Known(address),
                rtcp_port=Known(port + 1),
            ),
        ),
    )


def scenario_frames(
    name: str,
    *,
    call_id: str | None = None,
    caller_address: str = "192.0.2.10",
    callee_address: str = "198.51.100.20",
    start: int = 1,
) -> tuple[FrameRecord, ...]:
    frames: list[FrameRecord] = []
    call_id = call_id or f"{name}@example.invalid"
    for offset, event in enumerate(SCENARIOS[name]):
        number = start + offset
        evidence = EvidenceRef(Known(number), Known(Decimal(number) / 10))
        reverse = bool(event.get("reverse"))
        is_request = event["kind"] == "req"
        request_source_is_callee = reverse
        source_is_callee = (
            request_source_is_callee if is_request else not request_source_is_callee
        )
        source = endpoint(callee_address if source_is_callee else caller_address)
        destination = endpoint(caller_address if source_is_callee else callee_address)
        request_method = (
            Known(event["method"])
            if is_request
            else Unknown(UnknownReason.MISSING_FIELD, "sip.Method")
        )
        status = (
            Known(event["status"])
            if not is_request
            else Unknown(UnknownReason.MISSING_FIELD, "sip.Status-Code")
        )
        sip = SipRecord(
            request_method=request_method,
            status_code=status,
            call_id=Known(call_id),
            from_tag=(
                Known(event["from"])
                if event.get("from")
                else Unknown(UnknownReason.MISSING_FIELD, "sip.from.tag")
            ),
            to_tag=(
                Known(event["to"])
                if event.get("to")
                else Unknown(UnknownReason.MISSING_FIELD, "sip.to.tag")
            ),
            cseq_number=Known(event["cseq"]),
            cseq_method=Known(event["method"]),
            via_branch=Known(event["branch"]),
            via_sent_by=Known(caller_address),
            rseq=(
                Known(event["rseq"])
                if event.get("rseq") is not None
                else Unknown(UnknownReason.MISSING_FIELD, "sip.RSeq")
            ),
            rack_rseq=(
                Known(event["rack_rseq"])
                if event.get("rack_rseq") is not None
                else Unknown(UnknownReason.MISSING_FIELD, "sip.RAck.rseq")
            ),
            rack_cseq=(
                Known(event["rack_cseq"])
                if event.get("rack_cseq") is not None
                else Unknown(UnknownReason.MISSING_FIELD, "sip.RAck.cseq")
            ),
            rack_method=(
                Known(event["rack_method"])
                if event.get("rack_method") is not None
                else Unknown(UnknownReason.MISSING_FIELD, "sip.RAck.method")
            ),
            routes=("<sip:edge.example.invalid;lr>",) if event["method"] == "BYE" else (),
            record_routes=(
                ("<sip:edge.example.invalid;lr>",)
                if event.get("status") == 200 and event["method"] == "INVITE"
                else ()
            ),
            has_sdp=Known("sdp" in event),
        )
        frames.append(
            FrameRecord(
                evidence=evidence,
                captured_length=Known(300),
                original_length=Known(300),
                status=Known(CaptureStatus.COMPLETE),
                source=source,
                destination=destination,
                protocols=("ip", "udp", "sip")
                + (("sdp",) if "sdp" in event else ()),
                sip=sip,
                sdp=sdp(evidence, event["sdp"]) if "sdp" in event else None,
                rtp=None,
                rtcp=None,
            )
        )
    return tuple(frames)


class DialogReconstructionTests(unittest.TestCase):
    def test_baseline_is_complete_and_every_transition_has_evidence(self) -> None:
        result = reconstruct_dialogs(scenario_frames("baseline"))
        self.assertEqual(len(result.dialogs), 1)
        dialog = result.dialogs[0]
        self.assertEqual(dialog.state, DialogState.TERMINATED)
        self.assertEqual(dialog.complete, Known(True))
        self.assertTrue(dialog.transitions)
        self.assertTrue(
            all(isinstance(item.evidence.frame_number, Known) for item in dialog.transitions)
        )
        self.assertEqual(dialog.route_set, ("<sip:edge.example.invalid;lr>",))
        ack = next(
            item for item in result.transactions if item.key.cseq_method == "ACK"
        )
        self.assertEqual(ack.state, TransactionState.COMPLETED)

    def test_digest_challenge_and_authenticated_retry_share_dialog(self) -> None:
        dialog = reconstruct_dialogs(scenario_frames("digest_challenge")).dialogs[0]
        events = [item.event for item in dialog.transitions]
        self.assertIn("challenge_401", events)
        self.assertGreaterEqual(events.count("invite"), 2)
        self.assertEqual(dialog.complete, Known(True))
        self.assertEqual(len(reconstruct_dialogs(scenario_frames("digest_challenge")).dialogs), 1)

    def test_challenge_ack_does_not_acknowledge_later_success(self) -> None:
        frames = scenario_frames("digest_challenge")
        without_success_ack = frames[:5] + frames[6:]
        dialog = reconstruct_dialogs(without_success_ack).dialogs[0]
        self.assertIsInstance(dialog.complete, Unknown)

    def test_retransmissions_do_not_create_transactions(self) -> None:
        result = reconstruct_dialogs(scenario_frames("retransmission"))
        invite = next(
            item
            for item in result.transactions
            if item.key.cseq_method == "INVITE"
        )
        self.assertEqual(len(invite.retransmissions), 2)
        self.assertEqual(invite.state, TransactionState.COMPLETED)
        self.assertEqual(result.dialogs[0].state, DialogState.REJECTED)
        self.assertEqual(result.dialogs[0].complete, Known(True))

    def test_cancel_flow_is_complete(self) -> None:
        dialog = reconstruct_dialogs(scenario_frames("cancel")).dialogs[0]
        events = [item.event for item in dialog.transitions]
        self.assertIn("cancel", events)
        self.assertIn("invite_487", events)
        self.assertEqual(dialog.complete, Known(True))

    def test_remote_bye_is_distinguished(self) -> None:
        dialog = reconstruct_dialogs(scenario_frames("remote_bye")).dialogs[0]
        self.assertIn("remote_bye", [item.event for item in dialog.transitions])
        self.assertEqual(dialog.complete, Known(True))

    def test_early_media_has_evidenced_answer_revision(self) -> None:
        dialog = reconstruct_dialogs(scenario_frames("early_media")).dialogs[0]
        early = next(
            item for item in dialog.transitions if item.event == "provisional_183"
        )
        self.assertEqual(early.current, DialogState.EARLY.value)
        answer = next(
            item for item in dialog.sdp_revisions if item.status_code == 183
        )
        self.assertEqual(answer.role, SdpRole.ANSWER)
        self.assertEqual(
            answer.revision.media[0].telephone_event_payloads, Known((101,))
        )

    def test_forks_remain_separate_dialog_legs(self) -> None:
        result = reconstruct_dialogs(scenario_frames("fork"))
        self.assertEqual(len(result.dialogs), 2)
        tags = {
            dialog.key.callee_tag.value
            for dialog in result.dialogs
            if isinstance(dialog.key.callee_tag, Known)
        }
        self.assertEqual(tags, {"b1", "b2"})
        states = {dialog.state for dialog in result.dialogs}
        self.assertEqual(states, {DialogState.TERMINATED, DialogState.REJECTED})

    def test_reinvite_and_update_preserve_all_sdp_revisions(self) -> None:
        dialog = reconstruct_dialogs(scenario_frames("renegotiation")).dialogs[0]
        events = [item.event for item in dialog.transitions]
        self.assertIn("reinvite", events)
        self.assertIn("update", events)
        self.assertEqual(len(dialog.sdp_revisions), 6)
        self.assertEqual(
            [item.role for item in dialog.sdp_revisions].count(SdpRole.OFFER), 3
        )
        media = dialog.sdp_revisions[-1].revision.media[0]
        self.assertEqual(media.packet_time_ms, Known(20))
        self.assertEqual(media.rtcp_port, Known(5001))
        self.assertEqual(
            media.codecs.value[1].encoding, Known("telephone-event")
        )

    def test_offerless_invite_uses_200_offer_and_ack_answer(self) -> None:
        dialog = reconstruct_dialogs(scenario_frames("offerless_200")).dialogs[0]
        self.assertEqual(
            [item.role for item in dialog.sdp_revisions],
            [SdpRole.OFFER, SdpRole.ANSWER],
        )
        self.assertEqual(dialog.complete, Known(True))

    def test_reliable_provisional_offer_is_answered_by_prack(self) -> None:
        result = reconstruct_dialogs(scenario_frames("reliable_provisional"))
        dialog = result.dialogs[0]
        self.assertEqual(
            [item.role for item in dialog.sdp_revisions],
            [SdpRole.OFFER, SdpRole.ANSWER],
        )
        prack = next(
            item for item in result.transactions if item.key.cseq_method == "PRACK"
        )
        self.assertEqual(prack.request.sip.rack_rseq, Known(1))

    def test_failed_reinvite_restores_confirmed_state(self) -> None:
        dialog = reconstruct_dialogs(scenario_frames("failed_reinvite")).dialogs[0]
        self.assertEqual(dialog.state, DialogState.CONFIRMED)
        self.assertIn(
            "reinvite_failed_488", [item.event for item in dialog.transitions]
        )

    def test_every_successful_reinvite_requires_its_exact_ack(self) -> None:
        frames = scenario_frames("renegotiation")
        # Remove only the ACK for successful re-INVITE CSeq 2.
        without_reinvite_ack = frames[:5] + frames[6:]
        dialog = reconstruct_dialogs(without_reinvite_ack).dialogs[0]
        self.assertIsInstance(dialog.complete, Unknown)

    def test_ack_for_failed_reinvite_cannot_replace_initial_success_ack(self) -> None:
        frames = list(scenario_frames("renegotiation"))
        # Turn the in-dialog re-INVITE final into a failure, retain its CSeq 2
        # ACK, and remove only the ACK for the successful initial CSeq 1.
        frames[4] = replace(
            frames[4],
            sip=replace(frames[4].sip, status_code=Known(488)),
        )
        del frames[2]
        dialog = reconstruct_dialogs(frames).dialogs[0]
        self.assertIsInstance(dialog.complete, Unknown)

    def test_changed_rseq_or_sdp_is_not_discarded_as_retransmission(self) -> None:
        result = reconstruct_dialogs(
            scenario_frames("changed_reliable_provisional")
        )
        invite = next(
            item for item in result.transactions if item.key.cseq_method == "INVITE"
        )
        self.assertEqual(len(invite.responses), 2)
        self.assertEqual(len(invite.retransmissions), 0)
        self.assertEqual(len(result.dialogs[0].sdp_revisions), 3)

    def test_bad_relevant_frame_prevents_known_complete(self) -> None:
        frames = list(scenario_frames("baseline"))
        frames[1] = replace(
            frames[1], status=Known(CaptureStatus.TRUNCATED)
        )
        dialog = reconstruct_dialogs(frames).dialogs[0]
        self.assertIsInstance(dialog.complete, Unknown)

        malformed_sip = replace(
            frames[0].sip,
            via_branch=Unknown(UnknownReason.MALFORMED_FIELD, "sip.Via.branch"),
        )
        malformed = replace(
            frames[0],
            evidence=EvidenceRef(Known(99), Known(Decimal("9.9"))),
            status=Known(CaptureStatus.MALFORMED),
            sip=malformed_sip,
        )
        dialog = reconstruct_dialogs(tuple(scenario_frames("baseline")) + (malformed,)).dialogs[0]
        self.assertIsInstance(dialog.complete, Unknown)

    def test_route_set_reverses_record_route_without_unioning_route_headers(self) -> None:
        frames = list(scenario_frames("baseline"))
        response = frames[2]
        frames[2] = replace(
            response,
            sip=replace(
                response.sip,
                record_routes=("<sip:first;lr>", "<sip:second;lr>"),
                routes=("<sip:observed;lr>",),
            ),
        )
        dialog = reconstruct_dialogs(frames).dialogs[0]
        self.assertEqual(
            dialog.route_set, ("<sip:second;lr>", "<sip:first;lr>")
        )
        self.assertEqual(dialog.observed_routes, ("<sip:observed;lr>", "<sip:edge.example.invalid;lr>"))

    def test_incomplete_capture_is_localized_unknown_not_complete(self) -> None:
        frames = scenario_frames("baseline")[:3]
        dialog = reconstruct_dialogs(frames).dialogs[0]
        self.assertIsInstance(dialog.complete, Unknown)
        self.assertEqual(dialog.complete.reason, UnknownReason.MISSING_FIELD)
        self.assertEqual(dialog.unknowns[0].field, "dialog.complete")
        self.assertIsInstance(dialog.unknowns[0].evidence.frame_number, Known)

    def test_response_only_capture_is_orphan_not_a_dialog(self) -> None:
        response = scenario_frames("baseline")[1]
        result = reconstruct_dialogs((response,))
        self.assertEqual(result.dialogs, ())
        self.assertEqual(
            result.transactions[0].state, TransactionState.ORPHAN_RESPONSE
        )
        self.assertEqual(len(result.orphan_frames), 1)

    def test_colliding_identifiers_on_different_flows_never_merge(self) -> None:
        first = scenario_frames(
            "baseline",
            call_id="collision@example.invalid",
            caller_address="192.0.2.10",
            start=1,
        )
        second = scenario_frames(
            "baseline",
            call_id="collision@example.invalid",
            caller_address="192.0.2.99",
            start=100,
        )
        result = reconstruct_dialogs(first + second)
        self.assertEqual(len(result.dialogs), 2)
        self.assertTrue(all(dialog.complete == Known(True) for dialog in result.dialogs))
        flows = {dialog.key.initial_flow.initiator_address for dialog in result.dialogs}
        self.assertEqual(flows, {"192.0.2.10", "192.0.2.99"})


if __name__ == "__main__":
    unittest.main()
