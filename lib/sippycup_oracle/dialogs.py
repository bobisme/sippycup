"""Deterministic SIP transaction and dialog reconstruction."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from .records import (
    EndpointRecord,
    EvidenceRef,
    FrameRecord,
    Known,
    SdpRevisionRecord,
    Unknown,
    UnknownReason,
    Value,
)


class TransactionState(str, Enum):
    REQUEST_SEEN = "request_seen"
    PROCEEDING = "proceeding"
    COMPLETED = "completed"
    INCOMPLETE = "incomplete"
    ORPHAN_RESPONSE = "orphan_response"


class DialogState(str, Enum):
    NEW = "new"
    TRYING = "trying"
    EARLY = "early"
    CHALLENGED = "challenged"
    CONFIRMED = "confirmed"
    RENEGOTIATING = "renegotiating"
    CANCELLING = "cancelling"
    TERMINATING = "terminating"
    TERMINATED = "terminated"
    REJECTED = "rejected"
    INCOMPLETE = "incomplete"


class SdpRole(str, Enum):
    OFFER = "offer"
    ANSWER = "answer"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class FlowKey:
    initiator_address: str
    initiator_port: int
    responder_address: str
    responder_port: int
    transport: str


@dataclass(frozen=True, slots=True)
class TransactionKey:
    call_id: str
    cseq_number: int
    cseq_method: str
    via_branch: str
    flow: FlowKey


@dataclass(frozen=True, slots=True)
class StateTransition:
    previous: str
    current: str
    event: str
    evidence: EvidenceRef


@dataclass(frozen=True, slots=True)
class TransactionRecord:
    key: TransactionKey
    request: FrameRecord | None
    responses: tuple[FrameRecord, ...]
    retransmissions: tuple[EvidenceRef, ...]
    state: TransactionState
    transitions: tuple[StateTransition, ...]
    ambiguity: Value[bool]


@dataclass(frozen=True, slots=True)
class NegotiatedSdpRevision:
    role: SdpRole
    method: str
    status_code: int | None
    revision: SdpRevisionRecord


@dataclass(frozen=True, slots=True)
class LocalizedUnknown:
    field: str
    reason: UnknownReason
    evidence: EvidenceRef


@dataclass(frozen=True, slots=True)
class DialogKey:
    call_id: str
    caller_tag: Value[str]
    callee_tag: Value[str]
    initial_flow: FlowKey


@dataclass(frozen=True, slots=True)
class DialogRecord:
    key: DialogKey
    caller: EndpointRecord
    callee: EndpointRecord
    transaction_keys: tuple[TransactionKey, ...]
    state: DialogState
    complete: Value[bool]
    transitions: tuple[StateTransition, ...]
    sdp_revisions: tuple[NegotiatedSdpRevision, ...]
    route_set: tuple[str, ...]
    observed_routes: tuple[str, ...]
    unknowns: tuple[LocalizedUnknown, ...]


@dataclass(frozen=True, slots=True)
class Reconstruction:
    transactions: tuple[TransactionRecord, ...]
    dialogs: tuple[DialogRecord, ...]
    orphan_frames: tuple[EvidenceRef, ...]


@dataclass(slots=True)
class _TransactionBuilder:
    key: TransactionKey
    request: FrameRecord | None
    responses: list[FrameRecord]
    retransmissions: list[EvidenceRef]
    ambiguous: bool = False


def _known(value: Value[object]) -> object | None:
    return value.value if isinstance(value, Known) else None


def _frame_number(frame: FrameRecord) -> int:
    number = _known(frame.evidence.frame_number)
    return int(number) if number is not None else 2**63 - 1


def _endpoint_tuple(endpoint: EndpointRecord) -> tuple[str, int, str] | None:
    address = _known(endpoint.address)
    port = _known(endpoint.port)
    transport = _known(endpoint.transport)
    if address is None or port is None or transport is None:
        return None
    transport_value = getattr(transport, "value", str(transport))
    return str(address), int(port), str(transport_value)


def _flow(frame: FrameRecord) -> FlowKey | None:
    source = _endpoint_tuple(frame.source)
    destination = _endpoint_tuple(frame.destination)
    if source is None or destination is None or source[2] != destination[2]:
        return None
    return FlowKey(source[0], source[1], destination[0], destination[1], source[2])


def _reverse_flow(frame: FrameRecord) -> FlowKey | None:
    flow = _flow(frame)
    if flow is None:
        return None
    return FlowKey(
        flow.responder_address,
        flow.responder_port,
        flow.initiator_address,
        flow.initiator_port,
        flow.transport,
    )


def _sip_value(frame: FrameRecord, field: str) -> object | None:
    if frame.sip is None:
        return None
    return _known(getattr(frame.sip, field))


def _base_key(frame: FrameRecord) -> tuple[str, int, str, str] | None:
    call_id = _sip_value(frame, "call_id")
    cseq = _sip_value(frame, "cseq_number")
    method = _sip_value(frame, "cseq_method")
    branch = _sip_value(frame, "via_branch")
    if None in (call_id, cseq, method, branch):
        return None
    return str(call_id), int(cseq), str(method).upper(), str(branch)


def _request_method(frame: FrameRecord) -> str | None:
    method = _sip_value(frame, "request_method")
    return str(method).upper() if method is not None else None


def _status_code(frame: FrameRecord) -> int | None:
    status = _sip_value(frame, "status_code")
    return int(status) if status is not None else None


def _transaction_record(builder: _TransactionBuilder) -> TransactionRecord:
    transitions: list[StateTransition] = []
    if builder.request is None:
        state = TransactionState.ORPHAN_RESPONSE
    else:
        state = TransactionState.REQUEST_SEEN
        transitions.append(
            StateTransition(
                previous="new",
                current=state.value,
                event="request",
                evidence=builder.request.evidence,
            )
        )
        for response in builder.responses:
            status = _status_code(response)
            if status is None:
                continue
            next_state = (
                TransactionState.PROCEEDING
                if status < 200
                else TransactionState.COMPLETED
            )
            transitions.append(
                StateTransition(
                    previous=state.value,
                    current=next_state.value,
                    event=f"response_{status}",
                    evidence=response.evidence,
                )
            )
            state = next_state
        if builder.key.cseq_method == "ACK":
            state = TransactionState.COMPLETED
        elif not any(
            (_status_code(response) or 0) >= 200 for response in builder.responses
        ):
            state = TransactionState.INCOMPLETE
    ambiguity: Value[bool] = (
        Unknown(UnknownReason.AMBIGUOUS, "multiple transactions matched a response")
        if builder.ambiguous
        else Known(False)
    )
    return TransactionRecord(
        key=builder.key,
        request=builder.request,
        responses=tuple(builder.responses),
        retransmissions=tuple(builder.retransmissions),
        state=state,
        transitions=tuple(transitions),
        ambiguity=ambiguity,
    )


def reconstruct_transactions(
    frames: Iterable[FrameRecord],
) -> tuple[tuple[TransactionRecord, ...], tuple[EvidenceRef, ...]]:
    builders: list[_TransactionBuilder] = []
    orphan_frames: list[EvidenceRef] = []
    for frame in sorted(frames, key=_frame_number):
        if frame.sip is None:
            continue
        base = _base_key(frame)
        flow = _flow(frame)
        method = _request_method(frame)
        if base is None or flow is None:
            orphan_frames.append(frame.evidence)
            continue
        if method is not None:
            matching = [
                builder
                for builder in builders
                if builder.key.call_id == base[0]
                and builder.key.cseq_number == base[1]
                and builder.key.cseq_method == base[2]
                and builder.key.via_branch == base[3]
                and builder.key.flow == flow
                and builder.request is not None
            ]
            if matching:
                matching[0].retransmissions.append(frame.evidence)
                continue
            builders.append(
                _TransactionBuilder(
                    key=TransactionKey(*base, flow),
                    request=frame,
                    responses=[],
                    retransmissions=[],
                )
            )
            continue

        reverse = _reverse_flow(frame)
        matching = [
            builder
            for builder in builders
            if builder.key.call_id == base[0]
            and builder.key.cseq_number == base[1]
            and builder.key.cseq_method == base[2]
            and builder.key.via_branch == base[3]
            and builder.key.flow == reverse
        ]
        if not matching:
            orphan_frames.append(frame.evidence)
            # Keep the response visible without pretending its request direction.
            builders.append(
                _TransactionBuilder(
                    key=TransactionKey(*base, flow),
                    request=None,
                    responses=[frame],
                    retransmissions=[],
                )
            )
        elif len(matching) == 1:
            status = _status_code(frame)
            if any(
                (
                    _status_code(item),
                    _tag(item, "from_tag"),
                    _tag(item, "to_tag"),
                    _sip_value(item, "rseq"),
                    item.sdp,
                )
                == (
                    status,
                    _tag(frame, "from_tag"),
                    _tag(frame, "to_tag"),
                    _sip_value(frame, "rseq"),
                    frame.sdp,
                )
                for item in matching[0].responses
            ):
                matching[0].retransmissions.append(frame.evidence)
            else:
                matching[0].responses.append(frame)
        else:
            for builder in matching:
                builder.ambiguous = True
            orphan_frames.append(frame.evidence)

    return (
        tuple(_transaction_record(builder) for builder in builders),
        tuple(orphan_frames),
    )


def _tag(frame: FrameRecord, which: str) -> str | None:
    value = _sip_value(frame, which)
    return str(value) if value is not None else None


def _frame_belongs(
    frame: FrameRecord,
    call_id: str,
    caller_tag: str | None,
    callee_tag: str | None,
) -> bool:
    if _sip_value(frame, "call_id") != call_id:
        return False
    from_tag = _tag(frame, "from_tag")
    to_tag = _tag(frame, "to_tag")
    if _status_code(frame) in {401, 407} and from_tag == caller_tag:
        return True
    if caller_tag is not None and callee_tag is not None:
        if (from_tag, to_tag) in {
            (caller_tag, callee_tag),
            (callee_tag, caller_tag),
        }:
            return True
    # Untagged initial requests, challenges, and CANCEL belong to the root.
    return from_tag == caller_tag and to_tag is None


def _dialog_from_root(
    roots: list[TransactionRecord],
    transactions: tuple[TransactionRecord, ...],
    callee_tag: str | None,
    source_frames: tuple[FrameRecord, ...],
) -> DialogRecord:
    initial = roots[0]
    assert initial.request is not None
    call_id = initial.key.call_id
    caller_tag = _tag(initial.request, "from_tag")
    included: list[TransactionRecord] = []
    frames: list[tuple[FrameRecord, TransactionRecord, bool]] = []
    for transaction in transactions:
        transaction_frames = (
            ([transaction.request] if transaction.request is not None else [])
            + list(transaction.responses)
        )
        selected = [
            frame
            for frame in transaction_frames
            if _frame_belongs(frame, call_id, caller_tag, callee_tag)
        ]
        if selected:
            included.append(transaction)
            for frame in selected:
                frames.append((frame, transaction, frame is transaction.request))
    frames.sort(key=lambda item: _frame_number(item[0]))

    transitions: list[StateTransition] = []
    sdp_revisions: list[NegotiatedSdpRevision] = []
    unknowns: list[LocalizedUnknown] = []
    record_routes: list[str] = []
    observed_routes: list[str] = []
    state = DialogState.NEW
    successful_invites: set[int] = set()
    failed_initial_invites: set[int] = set()
    acknowledged_invites: set[int] = set()
    bye_success = False
    cancel_success = False
    invite_487 = False

    def transition(next_state: DialogState, event: str, evidence: EvidenceRef) -> None:
        nonlocal state
        transitions.append(
            StateTransition(state.value, next_state.value, event, evidence)
        )
        state = next_state

    for frame, transaction, is_request in frames:
        method = (
            _request_method(frame)
            if is_request
            else str(_sip_value(frame, "cseq_method") or "").upper()
        )
        status = None if is_request else _status_code(frame)
        if frame.sip is not None:
            if (
                not record_routes
                and not is_request
                and method == "INVITE"
                and status is not None
                and 100 < status < 300
            ):
                record_routes.extend(frame.sip.record_routes)
            for route in frame.sip.routes:
                if route not in observed_routes:
                    observed_routes.append(route)
        if frame.sdp is not None:
            request_has_sdp = (
                transaction.request is not None
                and transaction.request.sdp is not None
            )
            if is_request and method in {"INVITE", "UPDATE"}:
                role = SdpRole.OFFER
            elif (
                not is_request
                and method in {"INVITE", "UPDATE"}
                and request_has_sdp
            ):
                role = SdpRole.ANSWER
            elif (
                not is_request
                and method in {"INVITE", "UPDATE"}
                and not request_has_sdp
            ):
                role = SdpRole.OFFER
            elif is_request and method in {"ACK", "PRACK"}:
                role = SdpRole.ANSWER
            else:
                role = SdpRole.UNKNOWN
            sdp_revisions.append(
                NegotiatedSdpRevision(role, method, status, frame.sdp)
            )

        if is_request:
            if method == "INVITE":
                if state in {DialogState.CONFIRMED, DialogState.EARLY}:
                    transition(DialogState.RENEGOTIATING, "reinvite", frame.evidence)
                elif state in {
                    DialogState.NEW,
                    DialogState.CHALLENGED,
                    DialogState.INCOMPLETE,
                }:
                    transition(DialogState.TRYING, "invite", frame.evidence)
            elif method == "UPDATE":
                transition(DialogState.RENEGOTIATING, "update", frame.evidence)
            elif method == "ACK":
                cseq = _sip_value(frame, "cseq_number")
                if cseq is not None:
                    acknowledged_invites.add(int(cseq))
                transition(state, "ack", frame.evidence)
            elif method == "CANCEL":
                transition(DialogState.CANCELLING, "cancel", frame.evidence)
            elif method == "BYE":
                frame_flow = _flow(frame)
                remote = frame_flow is not None and (
                    frame_flow.initiator_address,
                    frame_flow.initiator_port,
                    frame_flow.transport,
                    frame_flow.responder_address,
                    frame_flow.responder_port,
                ) == (
                    initial.key.flow.responder_address,
                    initial.key.flow.responder_port,
                    initial.key.flow.transport,
                    initial.key.flow.initiator_address,
                    initial.key.flow.initiator_port,
                )
                transition(
                    DialogState.TERMINATING,
                    "remote_bye" if remote else "local_bye",
                    frame.evidence,
                )
            continue

        if status is None:
            unknowns.append(
                LocalizedUnknown(
                    "sip.status_code", UnknownReason.MISSING_FIELD, frame.evidence
                )
            )
            continue
        if method == "INVITE":
            cseq_value = _sip_value(frame, "cseq_number")
            cseq = int(cseq_value) if cseq_value is not None else None
            in_dialog = (
                transaction.request is not None
                and _tag(transaction.request, "to_tag") is not None
            )
            if status in {401, 407}:
                if not in_dialog:
                    transition(DialogState.CHALLENGED, f"challenge_{status}", frame.evidence)
                else:
                    transition(DialogState.CONFIRMED, f"reinvite_failed_{status}", frame.evidence)
            elif 100 < status < 200:
                transition(DialogState.EARLY, f"provisional_{status}", frame.evidence)
            elif 200 <= status < 300:
                if cseq is not None:
                    successful_invites.add(cseq)
                transition(DialogState.CONFIRMED, f"answer_{status}", frame.evidence)
            elif status == 487:
                invite_487 = True
                if cseq is not None and not in_dialog:
                    failed_initial_invites.add(cseq)
                transition(DialogState.TERMINATED, "invite_487", frame.evidence)
            elif status >= 300:
                if cseq is not None and not in_dialog:
                    failed_initial_invites.add(cseq)
                transition(
                    DialogState.CONFIRMED if in_dialog else DialogState.REJECTED,
                    f"reinvite_failed_{status}" if in_dialog else f"invite_failed_{status}",
                    frame.evidence,
                )
        elif method in {"INVITE", "UPDATE"} and 200 <= status < 300:
            transition(DialogState.CONFIRMED, f"negotiated_{status}", frame.evidence)
        elif method == "UPDATE" and status >= 200:
            transition(DialogState.CONFIRMED, f"update_final_{status}", frame.evidence)
        elif method == "CANCEL" and 200 <= status < 300:
            cancel_success = True
            transition(state, f"cancel_{status}", frame.evidence)
        elif method == "BYE" and 200 <= status < 300:
            bye_success = True
            transition(DialogState.TERMINATED, f"bye_{status}", frame.evidence)

    if not transitions:
        state = DialogState.INCOMPLETE
    setup_acknowledged = bool(successful_invites) and successful_invites.issubset(
        acknowledged_invites
    )
    failure_acknowledged = bool(
        failed_initial_invites & acknowledged_invites
    )
    successful_complete = setup_acknowledged and bye_success
    canceled_complete = cancel_success and invite_487 and failure_acknowledged
    rejected_complete = failure_acknowledged
    initial_flow = initial.key.flow
    reverse_initial_flow = FlowKey(
        initial_flow.responder_address,
        initial_flow.responder_port,
        initial_flow.initiator_address,
        initial_flow.initiator_port,
        initial_flow.transport,
    )
    structurally_uncertain = any(
        (
            not isinstance(frame.status, Known)
            or frame.status.value.value != "complete"
            or _base_key(frame) is None
        )
        for frame in source_frames
        if frame.sip is not None
        and (
            _sip_value(frame, "call_id") == call_id
            or _flow(frame) in {initial_flow, reverse_initial_flow}
        )
    ) or any(
        isinstance(item.ambiguity, Unknown) for item in included
    )
    if (successful_complete or canceled_complete or rejected_complete) and not structurally_uncertain:
        complete: Value[bool] = Known(True)
    else:
        complete = Unknown(
            UnknownReason.MISSING_FIELD,
            "dialog lacks a conclusive setup/ACK/teardown sequence",
        )
        evidence = initial.request.evidence
        unknowns.append(
            LocalizedUnknown("dialog.complete", UnknownReason.MISSING_FIELD, evidence)
        )
        if state is DialogState.NEW:
            state = DialogState.INCOMPLETE

    return DialogRecord(
        key=DialogKey(
            call_id=call_id,
            caller_tag=(
                Known(caller_tag)
                if caller_tag is not None
                else Unknown(UnknownReason.MISSING_FIELD, "sip.from.tag")
            ),
            callee_tag=(
                Known(callee_tag)
                if callee_tag is not None
                else Unknown(UnknownReason.MISSING_FIELD, "sip.to.tag")
            ),
            initial_flow=initial.key.flow,
        ),
        caller=initial.request.source,
        callee=initial.request.destination,
        transaction_keys=tuple(item.key for item in included),
        state=state,
        complete=complete,
        transitions=tuple(transitions),
        sdp_revisions=tuple(sdp_revisions),
        route_set=tuple(reversed(record_routes)),
        observed_routes=tuple(observed_routes),
        unknowns=tuple(unknowns),
    )


def reconstruct_dialogs(
    frames: Iterable[FrameRecord],
) -> Reconstruction:
    frame_tuple = tuple(frames)
    transactions, orphan_frames = reconstruct_transactions(frame_tuple)
    roots_by_call: dict[tuple[str, str | None, FlowKey], list[TransactionRecord]] = {}
    for transaction in transactions:
        request = transaction.request
        if request is None or _request_method(request) != "INVITE":
            continue
        # An initial INVITE has no To-tag. Tagged INVITEs are renegotiations.
        if _tag(request, "to_tag") is not None:
            continue
        root_key = (
            transaction.key.call_id,
            _tag(request, "from_tag"),
            transaction.key.flow,
        )
        roots_by_call.setdefault(root_key, []).append(transaction)

    dialogs: list[DialogRecord] = []
    for roots in roots_by_call.values():
        callee_tags: set[str] = set()
        for root in roots:
            for response in root.responses:
                tag = _tag(response, "to_tag")
                if tag is not None and _status_code(response) not in {401, 407}:
                    callee_tags.add(tag)
        if callee_tags:
            for tag in sorted(callee_tags):
                dialogs.append(_dialog_from_root(roots, transactions, tag, frame_tuple))
        else:
            dialogs.append(_dialog_from_root(roots, transactions, None, frame_tuple))

    dialogs.sort(
        key=lambda dialog: (
            dialog.key.call_id,
            dialog.key.initial_flow.initiator_address,
            dialog.key.initial_flow.initiator_port,
            str(_known(dialog.key.callee_tag) or ""),
        )
    )
    return Reconstruction(transactions, tuple(dialogs), orphan_frames)
