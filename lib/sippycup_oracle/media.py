"""RTP/RTCP correlation, RFC 3550 metrics, and call-path assertions."""

from __future__ import annotations

from dataclasses import dataclass, replace
from decimal import Decimal
from enum import Enum
from typing import Iterable

from .dialogs import DialogRecord, NegotiatedSdpRevision, SdpRole
from .records import (
    EvidenceRef,
    FrameRecord,
    Known,
    PayloadVisibility,
    RtcpRecord,
    SdpMediaRecord,
    Unknown,
    UnknownReason,
    Value,
    Verdict,
)


class Applicability(str, Enum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class MediaDirection(str, Enum):
    CALLER_TO_CALLEE = "caller_to_callee"
    CALLEE_TO_CALLER = "callee_to_caller"
    UNKNOWN = "unknown"


class CorrelationKind(str, Enum):
    EXACT = "exact"
    SYMMETRIC = "symmetric_rtp"
    UNMATCHED = "unmatched"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class MediaFlowKey:
    source_address: str
    source_port: int
    destination_address: str
    destination_port: int
    transport: str
    ssrc: int | None


@dataclass(frozen=True, slots=True)
class SequenceMetrics:
    received: int
    unique: Value[int]
    expected: Value[int]
    lost: Value[int]
    duplicates: Value[int]
    reordered: Value[int]
    jitter_ms: Value[Decimal]
    timestamp_jumps: Value[int]


@dataclass(frozen=True, slots=True)
class RtpStream:
    key: MediaFlowKey
    direction: MediaDirection
    correlation: CorrelationKind
    frames: tuple[FrameRecord, ...]
    payload_types: tuple[int, ...]
    encrypted: bool
    metrics: SequenceMetrics


@dataclass(frozen=True, slots=True)
class RtcpObservation:
    frame: FrameRecord
    matched_stream: Value[MediaFlowKey]


@dataclass(frozen=True, slots=True)
class AssertionResult:
    id: str
    verdict: Verdict
    applicability: Applicability
    message: str
    evidence: tuple[EvidenceRef, ...]
    observed: Value[object]

    @property
    def assertion_id(self) -> str:
        return self.id


@dataclass(frozen=True, slots=True)
class MediaExpectations:
    require_bidirectional: bool = True
    allowed_endpoints: tuple[str, ...] = ()
    expected_codecs: tuple[str, ...] = ()
    require_dtmf: bool = False
    allow_symmetric_rtp: bool = True
    max_setup_ms: Decimal = Decimal("5000")
    max_loss_fraction: Decimal = Decimal("0")
    max_duplicates: int = 0
    max_reordered: int = 0
    max_jitter_ms: Decimal = Decimal("30")
    timestamp_jump_tolerance_ms: Decimal = Decimal("200")


@dataclass(frozen=True, slots=True)
class MediaAnalysis:
    dialog: DialogRecord
    streams: tuple[RtpStream, ...]
    rtcp: tuple[RtcpObservation, ...]
    assertions: tuple[AssertionResult, ...]


def _media_endpoint(
    media: SdpMediaRecord | None,
) -> tuple[str, int] | None:
    if media is None:
        return None
    address = _known(media.address)
    port = _known(media.port)
    if address is None or port is None:
        return None
    return str(address), int(port)


def _known(value: Value[object]) -> object | None:
    return value.value if isinstance(value, Known) else None


def _evidence_time(evidence: EvidenceRef) -> Decimal | None:
    value = _known(evidence.timestamp_epoch)
    return Decimal(value) if value is not None else None


def _endpoint(frame: FrameRecord, source: bool) -> tuple[str, int, str] | None:
    endpoint = frame.source if source else frame.destination
    address = _known(endpoint.address)
    port = _known(endpoint.port)
    transport = _known(endpoint.transport)
    if None in (address, port, transport):
        return None
    return (
        str(address),
        int(port),
        str(getattr(transport, "value", transport)),
    )


def _direction(frame: FrameRecord, dialog: DialogRecord) -> MediaDirection:
    source = _endpoint(frame, True)
    destination = _endpoint(frame, False)
    caller = _known(dialog.caller.address)
    callee = _known(dialog.callee.address)
    if source is None or destination is None:
        return MediaDirection.UNKNOWN
    if source[0] == caller or destination[0] == callee:
        return MediaDirection.CALLER_TO_CALLEE
    if source[0] == callee or destination[0] == caller:
        return MediaDirection.CALLEE_TO_CALLER
    return MediaDirection.UNKNOWN


def _audio(revision: NegotiatedSdpRevision | None) -> SdpMediaRecord | None:
    if revision is None:
        return None
    for media in revision.revision.media:
        if _known(media.media_type) == "audio":
            return media
    return None


def _active_pair(
    dialog: DialogRecord, at: Decimal | None
) -> tuple[NegotiatedSdpRevision | None, NegotiatedSdpRevision | None]:
    pending_offer: NegotiatedSdpRevision | None = None
    active_offer: NegotiatedSdpRevision | None = None
    active_answer: NegotiatedSdpRevision | None = None
    for revision in dialog.sdp_revisions:
        revision_time = _evidence_time(revision.revision.evidence)
        if at is not None and revision_time is not None and revision_time > at:
            break
        if revision.role is SdpRole.OFFER:
            if (
                revision.status_code is None
                or 100 <= revision.status_code < 300
            ):
                pending_offer = revision
            else:
                pending_offer = None
        elif revision.role is SdpRole.ANSWER:
            if (
                revision.status_code is None
                or 100 <= revision.status_code < 300
            ) and pending_offer is not None:
                active_offer = pending_offer
                active_answer = revision
            elif revision.status_code is not None and revision.status_code >= 300:
                pending_offer = None
    return active_offer, active_answer


def _successful_pairs(
    dialog: DialogRecord,
) -> tuple[
    tuple[NegotiatedSdpRevision, NegotiatedSdpRevision], ...
]:
    pairs: list[
        tuple[NegotiatedSdpRevision, NegotiatedSdpRevision]
    ] = []
    pending: NegotiatedSdpRevision | None = None
    for revision in dialog.sdp_revisions:
        if revision.role is SdpRole.OFFER:
            if (
                revision.status_code is None
                or 100 <= revision.status_code < 300
            ):
                pending = revision
            else:
                pending = None
        elif revision.role is SdpRole.ANSWER:
            if (
                (
                    revision.status_code is None
                    or 100 <= revision.status_code < 300
                )
                and pending is not None
            ):
                pair = (pending, revision)
                if pair not in pairs:
                    pairs.append(pair)
            elif revision.status_code is not None and revision.status_code >= 300:
                pending = None
    return tuple(pairs)


def _direction_permission(
    media: SdpMediaRecord | None, *, sending: bool
) -> Value[bool]:
    if media is None:
        return Unknown(UnknownReason.MISSING_FIELD, "negotiated media section")
    port = _known(media.port)
    direction = _known(media.direction)
    if port is None or direction is None:
        return Unknown(
            UnknownReason.MISSING_FIELD, "SDP direction or media port"
        )
    if int(port) == 0 or str(direction) == "inactive":
        return Known(False)
    if sending:
        return Known(str(direction) in {"sendrecv", "sendonly"})
    return Known(str(direction) in {"sendrecv", "recvonly"})


def _direction_allowed(
    dialog: DialogRecord,
    frame: FrameRecord,
    direction: MediaDirection,
) -> Value[bool]:
    offer, answer = _active_pair(dialog, _evidence_time(frame.evidence))
    offer_media = _audio(offer)
    answer_media = _audio(answer)
    if direction is MediaDirection.CALLER_TO_CALLEE:
        permissions = (
            _direction_permission(offer_media, sending=True),
            _direction_permission(answer_media, sending=False),
        )
    elif direction is MediaDirection.CALLEE_TO_CALLER:
        permissions = (
            _direction_permission(answer_media, sending=True),
            _direction_permission(offer_media, sending=False),
        )
    else:
        return Unknown(UnknownReason.AMBIGUOUS, "media direction")
    if any(isinstance(item, Known) and item.value is False for item in permissions):
        return Known(False)
    if all(isinstance(item, Known) and item.value is True for item in permissions):
        return Known(True)
    return Unknown(UnknownReason.MISSING_FIELD, "SDP direction applicability")


def _expected_receiver(
    dialog: DialogRecord, frame: FrameRecord, direction: MediaDirection
) -> SdpMediaRecord | None:
    offer, answer = _active_pair(dialog, _evidence_time(frame.evidence))
    if direction is MediaDirection.CALLER_TO_CALLEE:
        return _audio(answer)
    if direction is MediaDirection.CALLEE_TO_CALLER:
        return _audio(offer)
    return None


def _expected_sender(
    dialog: DialogRecord, frame: FrameRecord, direction: MediaDirection
) -> SdpMediaRecord | None:
    offer, answer = _active_pair(dialog, _evidence_time(frame.evidence))
    if direction is MediaDirection.CALLER_TO_CALLEE:
        return _audio(offer)
    if direction is MediaDirection.CALLEE_TO_CALLER:
        return _audio(answer)
    return None


def partition_media_frames(
    frames: Iterable[FrameRecord],
    dialogs: tuple[DialogRecord, ...],
) -> tuple[
    tuple[tuple[FrameRecord, ...], ...],
    tuple[tuple[EvidenceRef, ...], ...],
]:
    """Assign each media frame to at most one fork leg.

    Equal best matches are withheld from every leg and surfaced as ambiguity
    evidence, preventing one packet from satisfying multiple dialogs.
    """
    assigned: list[list[FrameRecord]] = [[] for _ in dialogs]
    ambiguous: list[list[EvidenceRef]] = [[] for _ in dialogs]
    media_frames = [
        frame for frame in frames if frame.rtp is not None or frame.rtcp is not None
    ]
    if len(dialogs) == 1:
        return (
            (tuple(media_frames),),
            ((),),
        )
    for frame in media_frames:
        scored: list[tuple[int, int]] = []
        for index, dialog in enumerate(dialogs):
            direction = _direction(frame, dialog)
            if direction is MediaDirection.UNKNOWN:
                scored.append((index, 0))
                continue
            source = _endpoint(frame, True)
            destination = _endpoint(frame, False)
            receiver = _media_endpoint(
                _expected_receiver(dialog, frame, direction)
            )
            sender = _media_endpoint(
                _expected_sender(dialog, frame, direction)
            )
            score = 1
            if destination is not None and receiver == destination[:2]:
                score += 8
            if source is not None and sender == source[:2]:
                score += 4
            scored.append((index, score))
        best = max((score for _, score in scored), default=0)
        candidates = [index for index, score in scored if score == best and score > 0]
        if len(candidates) == 1:
            assigned[candidates[0]].append(frame)
        elif candidates:
            for index in candidates:
                ambiguous[index].append(frame.evidence)
    return (
        tuple(tuple(items) for items in assigned),
        tuple(tuple(items) for items in ambiguous),
    )


def _correlation(
    frame: FrameRecord,
    dialog: DialogRecord,
    direction: MediaDirection,
    allow_symmetric: bool,
) -> CorrelationKind:
    observed = _endpoint(frame, False)
    expected = _expected_receiver(dialog, frame, direction)
    if observed is None or expected is None:
        return CorrelationKind.UNKNOWN
    address = _known(expected.address)
    port = _known(expected.port)
    if address is None or port is None:
        return CorrelationKind.UNKNOWN
    if observed[:2] == (str(address), int(port)):
        return CorrelationKind.EXACT
    signaling_addresses = {
        _known(dialog.caller.address),
        _known(dialog.callee.address),
    }
    if allow_symmetric and observed[0] in signaling_addresses:
        return CorrelationKind.SYMMETRIC
    return CorrelationKind.UNMATCHED


def _clock_rate(frame: FrameRecord, dialog: DialogRecord) -> int | None:
    if frame.rtp is None:
        return None
    payload_type = _known(frame.rtp.payload_type)
    receiver = _expected_receiver(
        dialog, frame, _direction(frame, dialog)
    )
    if payload_type is None or receiver is None or not isinstance(receiver.codecs, Known):
        return None
    for codec in receiver.codecs.value:
        if codec.payload_type == payload_type:
            rate = _known(codec.clock_rate)
            return int(rate) if rate is not None else None
    return None


def _sequence_metrics(
    frames: tuple[FrameRecord, ...],
    dialog: DialogRecord,
    timestamp_jump_tolerance_ms: Decimal,
) -> SequenceMetrics:
    encrypted = any(
        frame.rtp is not None
        and isinstance(frame.rtp.payload_visibility, Unknown)
        and frame.rtp.payload_visibility.reason
        is UnknownReason.UNSUPPORTED_ENCRYPTION
        for frame in frames
    )
    sequences: list[int] = []
    for frame in frames:
        if frame.rtp is not None:
            sequence = _known(frame.rtp.sequence)
            if sequence is not None:
                sequences.append(int(sequence))
    if encrypted or len(sequences) != len(frames):
        unknown = Unknown(
            UnknownReason.UNSUPPORTED_ENCRYPTION
            if encrypted
            else UnknownReason.MISSING_FIELD,
            "RTP sequence metrics unavailable",
        )
        return SequenceMetrics(
            received=len(frames),
            unique=unknown,
            expected=unknown,
            lost=unknown,
            duplicates=unknown,
            reordered=unknown,
            jitter_ms=unknown,
            timestamp_jumps=unknown,
        )

    extended: list[int] = []
    cycles = 0
    previous = sequences[0]
    for sequence in sequences:
        if previous - sequence > 32768:
            cycles += 65536
        extended.append(cycles + sequence)
        previous = sequence
    seen: set[int] = set()
    duplicates = 0
    reordered = 0
    highest = -1
    for sequence in extended:
        if sequence in seen:
            duplicates += 1
        elif sequence < highest:
            reordered += 1
        seen.add(sequence)
        highest = max(highest, sequence)
    expected = max(extended) - min(extended) + 1
    lost = max(expected - len(seen), 0)

    jitter: Decimal | None = None
    previous_transit: Decimal | None = None
    jumps = 0
    previous_rtp_timestamp: int | None = None
    previous_arrival: Decimal | None = None
    for frame in frames:
        assert frame.rtp is not None
        arrival = _evidence_time(frame.evidence)
        rtp_timestamp = _known(frame.rtp.timestamp)
        rate = _clock_rate(frame, dialog)
        if arrival is None or rtp_timestamp is None or rate is None:
            jitter = None
            break
        transit = arrival * rate - int(rtp_timestamp)
        if previous_transit is not None:
            delta = abs(transit - previous_transit)
            jitter = (
                delta
                if jitter is None
                else jitter + (delta - jitter) / Decimal(16)
            )
        if previous_rtp_timestamp is not None and previous_arrival is not None:
            timestamp_delta = (
                int(rtp_timestamp) - previous_rtp_timestamp
            ) % (2**32)
            expected_delta = (arrival - previous_arrival) * rate
            tolerance = (
                Decimal(rate) * timestamp_jump_tolerance_ms / Decimal(1000)
            )
            if abs(Decimal(timestamp_delta) - expected_delta) > tolerance:
                jumps += 1
        previous_transit = transit
        previous_rtp_timestamp = int(rtp_timestamp)
        previous_arrival = arrival
    jitter_ms: Value[Decimal] = (
        Known((jitter or Decimal(0)) * Decimal(1000) / _clock_rate(frames[0], dialog))
        if jitter is not None and _clock_rate(frames[0], dialog)
        else Unknown(UnknownReason.MISSING_FIELD, "RTP clock rate or timestamp")
    )
    return SequenceMetrics(
        received=len(frames),
        unique=Known(len(seen)),
        expected=Known(expected),
        lost=Known(lost),
        duplicates=Known(duplicates),
        reordered=Known(reordered),
        jitter_ms=jitter_ms,
        timestamp_jumps=Known(jumps),
    )


def _stream_key(frame: FrameRecord) -> MediaFlowKey | None:
    source = _endpoint(frame, True)
    destination = _endpoint(frame, False)
    if source is None or destination is None or source[2] != destination[2]:
        return None
    ssrc = _known(frame.rtp.ssrc) if frame.rtp is not None else None
    return MediaFlowKey(
        source[0], source[1], destination[0], destination[1], source[2],
        int(ssrc) if ssrc is not None else None,
    )


def correlate_streams(
    frames: Iterable[FrameRecord],
    dialog: DialogRecord,
    *,
    allow_symmetric_rtp: bool = True,
    timestamp_jump_tolerance_ms: Decimal = Decimal("200"),
) -> tuple[tuple[RtpStream, ...], tuple[RtcpObservation, ...]]:
    grouped: dict[MediaFlowKey, list[FrameRecord]] = {}
    rtcp_frames: list[FrameRecord] = []
    for frame in frames:
        if frame.rtp is not None:
            key = _stream_key(frame)
            if key is not None:
                grouped.setdefault(key, []).append(frame)
        if frame.rtcp is not None:
            rtcp_frames.append(frame)
    streams: list[RtpStream] = []
    for key, packet_list in grouped.items():
        packets = tuple(
            sorted(
                packet_list,
                key=lambda frame: _evidence_time(frame.evidence) or Decimal(0),
            )
        )
        direction = _direction(packets[0], dialog)
        correlations = {
            _correlation(packet, dialog, direction, allow_symmetric_rtp)
            for packet in packets
        }
        if CorrelationKind.UNMATCHED in correlations:
            correlation = CorrelationKind.UNMATCHED
        elif CorrelationKind.SYMMETRIC in correlations:
            correlation = CorrelationKind.SYMMETRIC
        elif correlations == {CorrelationKind.EXACT}:
            correlation = CorrelationKind.EXACT
        else:
            correlation = CorrelationKind.UNKNOWN
        payload_types = tuple(
            sorted(
                {
                    int(value)
                    for packet in packets
                    if packet.rtp is not None
                    and (value := _known(packet.rtp.payload_type)) is not None
                }
            )
        )
        encrypted = any(
            packet.rtp is not None
            and isinstance(packet.rtp.payload_visibility, Unknown)
            for packet in packets
        )
        streams.append(
            RtpStream(
                key,
                direction,
                correlation,
                packets,
                payload_types,
                encrypted,
                _sequence_metrics(
                    packets, dialog, timestamp_jump_tolerance_ms
                ),
            )
        )
    streams.sort(
        key=lambda stream: (
            stream.key.source_address,
            stream.key.source_port,
            stream.key.destination_address,
            stream.key.destination_port,
            stream.key.ssrc or -1,
        )
    )
    flow_pairs = {
        (
            stream.key.source_address,
            stream.key.source_port,
            stream.key.destination_address,
            stream.key.destination_port,
        )
        for stream in streams
    }
    streams = [
        (
            replace(stream, correlation=CorrelationKind.UNMATCHED)
            if stream.correlation is CorrelationKind.SYMMETRIC
            and (
                stream.key.destination_address,
                stream.key.destination_port,
                stream.key.source_address,
                stream.key.source_port,
            )
            not in flow_pairs
            else stream
        )
        for stream in streams
    ]
    rtcp: list[RtcpObservation] = []
    for frame in rtcp_frames:
        source = _endpoint(frame, True)
        destination = _endpoint(frame, False)
        sender_ssrc = (
            _known(frame.rtcp.sender_ssrc) if frame.rtcp is not None else None
        )
        matches = [
            stream
            for stream in streams
            if source is not None
            and destination is not None
            and stream.key.source_address == source[0]
            and stream.key.destination_address == destination[0]
            and (
                sender_ssrc is None
                or stream.key.ssrc is None
                or stream.key.ssrc == sender_ssrc
            )
        ]
        matched: Value[MediaFlowKey] = (
            Known(matches[0].key)
            if len(matches) == 1
            else Unknown(
                UnknownReason.AMBIGUOUS if matches else UnknownReason.MISSING_FIELD,
                "RTCP stream correlation",
            )
        )
        rtcp.append(RtcpObservation(frame, matched))
    return tuple(streams), tuple(rtcp)


def _fallback_evidence(dialog: DialogRecord) -> tuple[EvidenceRef, ...]:
    if dialog.transitions:
        return (dialog.transitions[0].evidence,)
    if dialog.sdp_revisions:
        return (dialog.sdp_revisions[0].revision.evidence,)
    raise ValueError("dialog has no evidence")


def _result(
    assertion_id: str,
    verdict: Verdict,
    applicability: Applicability,
    message: str,
    evidence: Iterable[EvidenceRef],
    observed: Value[object],
    fallback: tuple[EvidenceRef, ...],
) -> AssertionResult:
    evidence_tuple = tuple(evidence) or fallback
    return AssertionResult(
        assertion_id, verdict, applicability, message, evidence_tuple, observed
    )


def evaluate_invariants(
    frames: Iterable[FrameRecord],
    dialog: DialogRecord,
    expectations: MediaExpectations = MediaExpectations(),
    assignment_ambiguity: tuple[EvidenceRef, ...] = (),
) -> MediaAnalysis:
    frame_tuple = tuple(frames)
    streams, rtcp = correlate_streams(
        frame_tuple,
        dialog,
        allow_symmetric_rtp=expectations.allow_symmetric_rtp,
        timestamp_jump_tolerance_ms=expectations.timestamp_jump_tolerance_ms,
    )
    fallback = _fallback_evidence(dialog)
    results: list[AssertionResult] = []
    media_evidence = tuple(
        stream.frames[0].evidence for stream in streams if stream.frames
    )
    results.append(
        _result(
            "media.assignment",
            Verdict.UNKNOWN if assignment_ambiguity else Verdict.PASS,
            Applicability.APPLICABLE,
            (
                "media frames match multiple dialog or fork legs"
                if assignment_ambiguity
                else "media frames are uniquely assigned to this dialog leg"
            ),
            assignment_ambiguity or media_evidence,
            (
                Unknown(
                    UnknownReason.AMBIGUOUS,
                    "media-to-dialog assignment",
                )
                if assignment_ambiguity
                else Known(True)
            ),
            fallback,
        )
    )

    directions = {stream.direction for stream in streams}
    required = {
        MediaDirection.CALLER_TO_CALLEE,
        MediaDirection.CALLEE_TO_CALLER,
    }
    if expectations.require_bidirectional:
        missing = required - directions
        results.append(
            _result(
                "media.directionality",
                (
                    Verdict.UNKNOWN
                    if missing and assignment_ambiguity
                    else Verdict.FAIL if missing else Verdict.PASS
                ),
                Applicability.APPLICABLE,
                (
                    "directionality is ambiguous across dialog or fork legs"
                    if missing and assignment_ambiguity
                    else "missing " + ", ".join(sorted(item.value for item in missing))
                    if missing
                    else "bidirectional media observed"
                ),
                media_evidence,
                Known(tuple(sorted(item.value for item in directions))),
                fallback,
            )
        )
    else:
        results.append(
            _result(
                "media.directionality",
                Verdict.UNKNOWN,
                Applicability.NOT_APPLICABLE,
                "bidirectional media was not required",
                (),
                Known(tuple(sorted(item.value for item in directions))),
                fallback,
            )
        )

    direction_failures: list[FrameRecord] = []
    direction_unknown: list[FrameRecord] = []
    for stream in streams:
        for packet in stream.frames:
            allowed = _direction_allowed(dialog, packet, stream.direction)
            if isinstance(allowed, Known) and allowed.value is False:
                direction_failures.append(packet)
            elif isinstance(allowed, Unknown):
                direction_unknown.append(packet)
    results.append(
        _result(
            "media.sdp_direction",
            (
                Verdict.FAIL
                if direction_failures
                else Verdict.UNKNOWN
                if direction_unknown or not streams
                else Verdict.PASS
            ),
            Applicability.APPLICABLE,
            (
                "media violates negotiated SDP direction or disabled port"
                if direction_failures
                else "SDP direction applicability is incomplete"
                if direction_unknown or not streams
                else "media follows negotiated SDP direction and port state"
            ),
            (
                frame.evidence
                for frame in direction_failures + direction_unknown
            ),
            (
                Known(True)
                if streams and not direction_failures and not direction_unknown
                else Unknown(
                    UnknownReason.MISSING_FIELD,
                    "SDP direction evaluation",
                )
            ),
            fallback,
        )
    )

    frozen_allowlist = bool(expectations.allowed_endpoints)
    if frozen_allowlist:
        allowed_addresses = set(expectations.allowed_endpoints)
    else:
        allowed_addresses = {
            str(value)
            for value in (
                _known(dialog.caller.address),
                _known(dialog.callee.address),
            )
            if value is not None
        }
        for offer, answer in _successful_pairs(dialog):
            for revision in (offer, answer):
                for media in revision.revision.media:
                    address = _known(media.address)
                    if address is not None:
                        allowed_addresses.add(str(address))
    unapproved_evidence: list[EvidenceRef] = []
    if frozen_allowlist:
        for endpoint in (dialog.caller, dialog.callee):
            address = _known(endpoint.address)
            if address is not None and str(address) not in allowed_addresses:
                unapproved_evidence.extend(fallback)
        for frame in frame_tuple:
            if frame.sip is None or _known(frame.sip.call_id) != dialog.key.call_id:
                continue
            for endpoint in (frame.source, frame.destination):
                address = _known(endpoint.address)
                if address is not None and str(address) not in allowed_addresses:
                    unapproved_evidence.append(frame.evidence)
        for revision in dialog.sdp_revisions:
            for media in revision.revision.media:
                address = _known(media.address)
                if address is not None and str(address) not in allowed_addresses:
                    unapproved_evidence.append(revision.revision.evidence)
    unexpected_frames = [
        packet
        for stream in streams
        for packet in stream.frames
        if (
            _endpoint(packet, True) is not None
            and _endpoint(packet, True)[0] not in allowed_addresses
        )
        or (
            _endpoint(packet, False) is not None
            and _endpoint(packet, False)[0] not in allowed_addresses
        )
    ]
    unmatched = [
        stream
        for stream in streams
        if stream.correlation is CorrelationKind.UNMATCHED
    ]
    endpoint_failures = unexpected_frames + [
        stream.frames[0] for stream in unmatched
    ]
    unresolved_endpoints = [
        stream
        for stream in streams
        if stream.correlation is CorrelationKind.UNKNOWN
    ]
    results.append(
        _result(
            "media.endpoints",
            (
            Verdict.FAIL
                if endpoint_failures or unapproved_evidence
                else Verdict.UNKNOWN
                if not streams or unresolved_endpoints
                else Verdict.PASS
            ),
            Applicability.APPLICABLE,
            (
                "unapproved signaling, negotiated SDP, or media endpoint observed"
                if unapproved_evidence
                else "unexpected or unexplained media endpoint observed"
                if endpoint_failures
                else "media endpoint correlation is incomplete"
                if not streams or unresolved_endpoints
                else "media endpoints match negotiation or symmetric RTP"
            ),
            tuple(unapproved_evidence)
            + tuple(frame.evidence for frame in endpoint_failures),
            Known(tuple(sorted(allowed_addresses))),
            fallback,
        )
    )

    payload_failures: list[FrameRecord] = []
    payload_unknown: list[FrameRecord] = []
    encrypted_frames: list[FrameRecord] = []
    for stream in streams:
        for packet in stream.frames:
            if stream.encrypted:
                encrypted_frames.append(packet)
                continue
            receiver = _expected_receiver(dialog, packet, stream.direction)
            payload_type = (
                _known(packet.rtp.payload_type) if packet.rtp is not None else None
            )
            allowed = _known(receiver.payload_types) if receiver is not None else None
            if payload_type is None or allowed is None:
                payload_unknown.append(packet)
            elif payload_type not in allowed:
                payload_failures.append(packet)
    if payload_failures:
        payload_verdict = Verdict.FAIL
        payload_message = "observed payload type was not negotiated"
        payload_evidence = (frame.evidence for frame in payload_failures)
    elif encrypted_frames:
        payload_verdict = Verdict.UNKNOWN
        payload_message = "encrypted media received transport-only analysis"
        payload_evidence = (frame.evidence for frame in encrypted_frames)
    elif payload_unknown:
        payload_verdict = Verdict.UNKNOWN
        payload_message = "payload negotiation or observation is incomplete"
        payload_evidence = (frame.evidence for frame in payload_unknown)
    elif not streams:
        payload_verdict = Verdict.UNKNOWN
        payload_message = "no media was available for payload evaluation"
        payload_evidence = ()
    else:
        payload_verdict = Verdict.PASS
        payload_message = "observed payload types were negotiated"
        payload_evidence = media_evidence
    results.append(
        _result(
            "media.payloads",
            payload_verdict,
            Applicability.APPLICABLE,
            payload_message,
            payload_evidence,
            (
                Unknown(UnknownReason.UNSUPPORTED_ENCRYPTION, "payload metadata")
                if encrypted_frames and not payload_failures
                else Known(tuple(stream.payload_types for stream in streams))
            ),
            fallback,
        )
    )

    negotiated_codecs: set[str] = set()
    telephone_payloads: set[int] = set()
    codec_mapping_known = False
    telephone_mapping_known = False
    successful_revisions = tuple(
        revision
        for pair in _successful_pairs(dialog)
        for revision in pair
    )
    for revision in successful_revisions:
        for media in revision.revision.media:
            if isinstance(media.codecs, Known):
                codec_mapping_known = True
                for codec in media.codecs.value:
                    encoding = _known(codec.encoding)
                    if encoding is not None:
                        negotiated_codecs.add(str(encoding).lower())
            if isinstance(media.telephone_event_payloads, Known):
                telephone_mapping_known = True
                telephone_payloads.update(media.telephone_event_payloads.value)
    missing_codecs = {
        codec.lower() for codec in expectations.expected_codecs
    } - negotiated_codecs
    results.append(
        _result(
            "media.codecs",
            (
                Verdict.UNKNOWN
                if not expectations.expected_codecs
                else Verdict.UNKNOWN
                if not codec_mapping_known
                else Verdict.FAIL if missing_codecs else Verdict.PASS
            ),
            (
                Applicability.NOT_APPLICABLE
                if not expectations.expected_codecs
                else Applicability.APPLICABLE
            ),
            (
                "missing negotiated codecs: " + ", ".join(sorted(missing_codecs))
                if missing_codecs and codec_mapping_known
                else "no codec expectation was configured"
                if not expectations.expected_codecs
                else "codec negotiation is incomplete"
                if not codec_mapping_known
                else "expected codecs are negotiated"
            ),
            (revision.revision.evidence for revision in successful_revisions),
            Known(tuple(sorted(negotiated_codecs))),
            fallback,
        )
    )
    if expectations.require_dtmf:
        observed_payloads = {
            payload_type
            for stream in streams
            for payload_type in stream.payload_types
        }
        dtmf_seen = bool(telephone_payloads & observed_payloads)
        dtmf_encrypted = any(stream.encrypted for stream in streams)
        results.append(
            _result(
                "media.dtmf",
                (
                    Verdict.PASS
                    if dtmf_seen
                    else Verdict.UNKNOWN
                    if dtmf_encrypted or not telephone_mapping_known
                    else Verdict.FAIL
                ),
                Applicability.APPLICABLE,
                (
                    "telephone-event RTP observed"
                    if dtmf_seen
                    else "DTMF payload is hidden by encryption"
                    if dtmf_encrypted
                    else "telephone-event negotiation is incomplete"
                    if not telephone_mapping_known
                    else "no negotiated telephone-event RTP observed"
                ),
                media_evidence,
                (
                    Unknown(UnknownReason.UNSUPPORTED_ENCRYPTION, "DTMF payload")
                    if dtmf_encrypted and not dtmf_seen
                    else Known(dtmf_seen)
                ),
                fallback,
            )
        )
    else:
        results.append(
            _result(
                "media.dtmf",
                Verdict.UNKNOWN,
                Applicability.NOT_APPLICABLE,
                "DTMF observation was not required",
                (),
                Known(False),
                fallback,
            )
        )

    answer_times = [
        _evidence_time(revision.revision.evidence)
        for revision in dialog.sdp_revisions
        if revision.role is SdpRole.ANSWER
    ]
    answer_times = [item for item in answer_times if item is not None]
    invite_times = [
        _evidence_time(item.evidence)
        for item in dialog.transitions
        if item.event == "invite"
    ]
    invite_times = [item for item in invite_times if item is not None]
    teardown_times = [
        _evidence_time(item.evidence)
        for item in dialog.transitions
        if item.event.startswith("bye_")
        or item.event in {"local_bye", "remote_bye"}
    ]
    teardown_times = [item for item in teardown_times if item is not None]
    first_answer = min(answer_times) if answer_times else None
    first_invite = min(invite_times) if invite_times else None
    teardown = min(teardown_times) if teardown_times else None
    before_answer = [
        packet
        for stream in streams
        for packet in stream.frames
        if first_answer is not None
        and _evidence_time(packet.evidence) is not None
        and _evidence_time(packet.evidence) < first_answer
    ]
    after_teardown = [
        packet
        for stream in streams
        for packet in stream.frames
        if teardown is not None
        and _evidence_time(packet.evidence) is not None
        and _evidence_time(packet.evidence) > teardown
    ]
    setup_ms = (
        (first_answer - first_invite) * Decimal(1000)
        if first_answer is not None and first_invite is not None
        else None
    )
    timing_failures = before_answer + after_teardown
    setup_slow = setup_ms is not None and setup_ms > expectations.max_setup_ms
    timing_unknown = first_answer is None or first_invite is None
    results.append(
        _result(
            "media.timing",
            (
                Verdict.FAIL
                if timing_failures or setup_slow
                else Verdict.UNKNOWN if timing_unknown else Verdict.PASS
            ),
            Applicability.APPLICABLE,
            (
                "media occurred before answer or after teardown"
                if timing_failures
                else "setup exceeded timing window"
                if setup_slow
                else "answer timing is incomplete"
                if timing_unknown
                else "media and setup timing are within bounds"
            ),
            (frame.evidence for frame in timing_failures),
            (
                Known(setup_ms)
                if setup_ms is not None
                else Unknown(UnknownReason.MISSING_FIELD, "invite/answer time")
            ),
            fallback,
        )
    )

    known_metrics = [
        stream.metrics
        for stream in streams
        if isinstance(stream.metrics.lost, Known)
    ]
    sequence_failures = [
        stream
        for stream in streams
        if isinstance(stream.metrics.lost, Known)
        and (
            (
                Decimal(stream.metrics.lost.value)
                / Decimal(max(stream.metrics.expected.value, 1))
            )
            > expectations.max_loss_fraction
            or stream.metrics.duplicates.value > expectations.max_duplicates
            or stream.metrics.reordered.value > expectations.max_reordered
            or stream.metrics.timestamp_jumps.value > 0
        )
    ]
    results.append(
        _result(
            "media.sequence",
            (
                Verdict.FAIL
                if sequence_failures
                else Verdict.UNKNOWN if len(known_metrics) != len(streams) or not streams
                else Verdict.PASS
            ),
            Applicability.APPLICABLE,
            (
                "loss, duplication, reordering, or timestamp jump exceeded limits"
                if sequence_failures
                else "sequence metrics unavailable for encrypted/incomplete media"
                if len(known_metrics) != len(streams) or not streams
                else "sequence and timestamp continuity are within limits"
            ),
            (stream.frames[0].evidence for stream in sequence_failures),
            (
                Known(tuple(stream.metrics for stream in streams))
                if len(known_metrics) == len(streams) and streams
                else Unknown(
                    UnknownReason.UNSUPPORTED_ENCRYPTION
                    if any(stream.encrypted for stream in streams)
                    else UnknownReason.MISSING_FIELD,
                    "sequence metrics",
                )
            ),
            fallback,
        )
    )

    jitter_failures = [
        stream
        for stream in streams
        if isinstance(stream.metrics.jitter_ms, Known)
        and stream.metrics.jitter_ms.value > expectations.max_jitter_ms
    ]
    known_jitter = [
        stream for stream in streams if isinstance(stream.metrics.jitter_ms, Known)
    ]
    results.append(
        _result(
            "media.jitter",
            (
                Verdict.FAIL
                if jitter_failures
                else Verdict.UNKNOWN if len(known_jitter) != len(streams) or not streams
                else Verdict.PASS
            ),
            Applicability.APPLICABLE,
            (
                "interarrival jitter exceeded limit"
                if jitter_failures
                else "jitter unavailable for encrypted/incomplete media"
                if len(known_jitter) != len(streams) or not streams
                else "RFC 3550 interarrival jitter is within limit"
            ),
            (stream.frames[0].evidence for stream in jitter_failures),
            (
                Known(tuple(stream.metrics.jitter_ms for stream in streams))
                if len(known_jitter) == len(streams) and streams
                else Unknown(UnknownReason.MISSING_FIELD, "jitter metrics")
            ),
            fallback,
        )
    )

    unexpected_ssrc: list[FrameRecord] = []
    packets_by_direction: dict[MediaDirection, list[FrameRecord]] = {}
    for stream in streams:
        packets_by_direction.setdefault(stream.direction, []).extend(stream.frames)
    for direction, packets in packets_by_direction.items():
        packets.sort(key=lambda frame: _evidence_time(frame.evidence) or Decimal(0))
        previous_ssrc: int | None = None
        previous_revision: object | None = None
        for packet in packets:
            current_ssrc = (
                _known(packet.rtp.ssrc) if packet.rtp is not None else None
            )
            offer, answer = _active_pair(
                dialog, _evidence_time(packet.evidence)
            )
            active = answer if direction is MediaDirection.CALLER_TO_CALLEE else offer
            revision_token = (
                _known(active.revision.evidence.frame_number)
                if active is not None
                else None
            )
            if (
                current_ssrc is not None
                and previous_ssrc is not None
                and int(current_ssrc) != previous_ssrc
                and revision_token == previous_revision
            ):
                unexpected_ssrc.append(packet)
            if current_ssrc is not None:
                previous_ssrc = int(current_ssrc)
                previous_revision = revision_token
    transition_failures = payload_failures + unexpected_ssrc
    encrypted_transitions = any(stream.encrypted for stream in streams)
    results.append(
        _result(
            "media.transitions",
            (
                Verdict.FAIL
                if transition_failures
                else Verdict.UNKNOWN
                if not streams or payload_unknown or encrypted_transitions
                else Verdict.PASS
            ),
            Applicability.APPLICABLE,
            (
                "unexplained media transition observed"
                if transition_failures
                else "media transition correlation is incomplete"
                if not streams or payload_unknown or encrypted_transitions
                else "media transitions align with active SDP revisions"
            ),
            (frame.evidence for frame in transition_failures),
            (
                Unknown(
                    UnknownReason.UNSUPPORTED_ENCRYPTION,
                    "encrypted SSRC/payload transitions",
                )
                if encrypted_transitions and not transition_failures
                else Known(len(successful_revisions))
            ),
            fallback,
        )
    )

    return MediaAnalysis(dialog, streams, rtcp, tuple(results))
