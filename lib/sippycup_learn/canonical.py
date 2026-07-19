"""Canonicalize one complete, unambiguous SIP dialog into typed placeholders."""

from __future__ import annotations

import ipaddress
from decimal import Decimal
from typing import Iterable

from sippycup_oracle.dialogs import DialogRecord, DialogState, Reconstruction, TransactionRecord
from sippycup_oracle.records import FrameRecord, Known, Unknown


class CanonicalizationError(ValueError):
    def __init__(self, code: str, message: str, frames: Iterable[int] = ()):
        super().__init__(message)
        self.code, self.frames = code, tuple(frames)


def _known(value):
    return value.value if isinstance(value, Known) else None


def _frame_number(frame: FrameRecord) -> int | None:
    value = _known(frame.evidence.frame_number)
    return int(value) if value is not None else None


def _time(frame: FrameRecord) -> Decimal | None:
    value = _known(frame.evidence.timestamp_epoch)
    return Decimal(value) if value is not None else None


class _Placeholders:
    def __init__(self):
        self.values: dict[str, dict[object, str]] = {}

    def get(self, kind: str, raw: object) -> dict[str, str]:
        mapping = self.values.setdefault(kind, {})
        if raw not in mapping:
            mapping[raw] = f"{kind}-{len(mapping) + 1}"
        return {"type": kind, "name": mapping[raw]}


def canonicalize_dialog(
    reconstruction: Reconstruction,
    frames: Iterable[FrameRecord],
    *,
    local_networks: Iterable[str],
) -> dict[str, object]:
    frames = tuple(frames)
    networks = _networks(local_networks)
    dialog = _select_dialog(reconstruction)
    _validate_dialog(dialog, reconstruction, frames)
    initial = dialog.key.initial_flow
    caller_local = _is_local(initial.initiator_address, networks)
    callee_local = _is_local(initial.responder_address, networks)
    if caller_local == callee_local:
        raise CanonicalizationError(
            "scope", "exactly one initial dialog endpoint must be in local scope"
        )
    placeholders = _Placeholders()
    first_time = min((time for frame in frames if (time := _time(frame)) is not None), default=Decimal(0))

    transaction_by_key = {transaction.key: transaction for transaction in reconstruction.transactions}
    transactions = []
    used_frames: set[int] = set()
    teardown = "none"
    for index, key in enumerate(dialog.transaction_keys, 1):
        transaction = transaction_by_key.get(key)
        if transaction is None or transaction.request is None:
            raise CanonicalizationError("incomplete", "dialog references an incomplete transaction")
        request = transaction.request
        number = _frame_number(request)
        evidence = [value for value in (number,) if value is not None]
        response_records = []
        for response in transaction.responses:
            response_number = _frame_number(response)
            if response_number is not None:
                evidence.append(response_number)
            status = _known(response.sip.status_code) if response.sip else None
            response_records.append({
                "status": int(status) if status is not None else None,
                "optional": bool(status is not None and int(status) < 200),
                "frame": response_number,
                "length": placeholders.get(
                    "length", _known(response.original_length)
                ) if _known(response.original_length) is not None else None,
            })
        used_frames.update(evidence)
        local_to_remote = _is_local(key.flow.initiator_address, networks)
        direction = "local-to-remote" if local_to_remote else "remote-to-local"
        if key.cseq_method == "BYE":
            teardown = "local" if local_to_remote else "remote"
        times = [time for frame in (request, *transaction.responses) if (time := _time(frame)) is not None]
        transactions.append({
            "id": f"transaction-{index}",
            "method": key.cseq_method,
            "direction": direction,
            "cseq": placeholders.get("cseq", key.cseq_number),
            "branch": placeholders.get("branch", key.via_branch),
            "flow": {
                "sourceAddress": placeholders.get("address", key.flow.initiator_address),
                "sourcePort": placeholders.get("port", key.flow.initiator_port),
                "destinationAddress": placeholders.get("address", key.flow.responder_address),
                "destinationPort": placeholders.get("port", key.flow.responder_port),
                "transport": key.flow.transport,
            },
            "timingWindowMs": {
                "earliest": _offset(min(times), first_time) if times else None,
                "latest": _offset(max(times), first_time) if times else None,
            },
            "requestFrame": number,
            "requestHasSdp": request.sdp is not None,
            "requestLength": placeholders.get(
                "length", _known(request.original_length)
            ) if _known(request.original_length) is not None else None,
            "responses": response_records,
            "retransmissionFrames": [
                _known(item.frame_number) for item in transaction.retransmissions
                if _known(item.frame_number) is not None
            ],
        })

    sdp = []
    media_endpoints: set[tuple[str, int]] = set()
    for index, negotiated in enumerate(dialog.sdp_revisions, 1):
        media_records = []
        for media in negotiated.revision.media:
            address, port = _known(media.address), _known(media.port)
            if address is not None and port is not None:
                media_endpoints.add((str(address), int(port)))
            codecs = _known(media.codecs)
            media_records.append({
                "mediaType": _known(media.media_type),
                "address": placeholders.get("media-address", address) if address is not None else None,
                "port": placeholders.get("media-port", port) if port is not None else None,
                "protocol": _known(media.protocol),
                "payloadTypes": list(_known(media.payload_types) or ()),
                "codecs": [
                    {
                        "payloadType": codec.payload_type,
                        "encoding": _known(codec.encoding),
                        "clockRate": _known(codec.clock_rate),
                    }
                    for codec in (codecs or ())
                ],
                "direction": _known(media.direction),
                "packetTimeMs": _known(media.packet_time_ms),
            })
        evidence_frame = _known(negotiated.revision.evidence.frame_number)
        if evidence_frame is not None:
            used_frames.add(int(evidence_frame))
        sdp.append({
            "id": f"sdp-{index}",
            "role": negotiated.role.value,
            "method": negotiated.method,
            "status": negotiated.status_code,
            "frame": evidence_frame,
            "media": media_records,
        })

    media_packets = []
    for frame in frames:
        if frame.rtp is None or not _matches_media(frame, media_endpoints):
            continue
        number = _frame_number(frame)
        if number is not None:
            used_frames.add(number)
        ssrc = _known(frame.rtp.ssrc)
        media_packets.append({
            "frame": number,
            "ssrc": placeholders.get("ssrc", ssrc) if ssrc is not None else None,
            "sequence": placeholders.get("rtp-sequence", _known(frame.rtp.sequence))
            if _known(frame.rtp.sequence) is not None else None,
            "timestamp": placeholders.get("rtp-timestamp", _known(frame.rtp.timestamp))
            if _known(frame.rtp.timestamp) is not None else None,
            "payloadType": _known(frame.rtp.payload_type),
            "offsetMs": _offset(_time(frame), first_time) if _time(frame) is not None else None,
        })

    return {
        "schema": "sippycup.learned-dialog/v1",
        "roles": {"local": "test-agent", "remote": "target"},
        "dialog": {
            "callId": placeholders.get("call-id", dialog.key.call_id),
            "localTag": placeholders.get("tag", _known(dialog.key.caller_tag)),
            "remoteTag": placeholders.get("tag", _known(dialog.key.callee_tag)),
            "localContact": placeholders.get(
                "contact",
                (
                    initial.initiator_address if caller_local else initial.responder_address,
                    initial.initiator_port if caller_local else initial.responder_port,
                ),
            ),
            "remoteContact": placeholders.get(
                "contact",
                (
                    initial.responder_address if caller_local else initial.initiator_address,
                    initial.responder_port if caller_local else initial.initiator_port,
                ),
            ),
            "state": dialog.state.value,
            "teardownInitiator": teardown,
        },
        "transactions": transactions,
        "sdpRevisions": sdp,
        "mediaPackets": media_packets,
        "provenance": {
            "sourceFrames": sorted(used_frames),
            "sourceFrameCount": len(frames),
        },
    }


def _select_dialog(reconstruction: Reconstruction) -> DialogRecord:
    if not reconstruction.dialogs:
        raise CanonicalizationError("incomplete", "no dialog can be selected")
    if len(reconstruction.dialogs) != 1:
        frames = [
            int(value) for dialog in reconstruction.dialogs
            for transition in dialog.transitions
            if (value := _known(transition.evidence.frame_number)) is not None
        ]
        raise CanonicalizationError("ambiguous-fork", "capture contains multiple dialog legs", frames)
    return reconstruction.dialogs[0]


def _validate_dialog(dialog: DialogRecord, reconstruction: Reconstruction, frames):
    complete = _known(dialog.complete)
    if complete is not True or dialog.state not in {DialogState.TERMINATED, DialogState.REJECTED}:
        raise CanonicalizationError("incomplete", "dialog is incomplete or still active")
    if isinstance(dialog.key.caller_tag, Unknown) or isinstance(dialog.key.callee_tag, Unknown):
        raise CanonicalizationError("ambiguous", "dialog tags are not known")
    if dialog.unknowns:
        raise CanonicalizationError("ambiguous", "dialog contains unresolved fields")
    if any(isinstance(tx.ambiguity, Unknown) or _known(tx.ambiguity) is True
           for tx in reconstruction.transactions if tx.key in dialog.transaction_keys):
        raise CanonicalizationError("ambiguous", "a dialog transaction is ambiguous")
    if any(any(name in {"tls", "srtp", "dtls"} for name in frame.protocols) for frame in frames):
        raise CanonicalizationError("encrypted", "encrypted dialogs cannot be learned safely")


def _networks(values: Iterable[str]):
    try:
        networks = tuple(ipaddress.ip_network(value, strict=False) for value in values)
    except ValueError as exc:
        raise CanonicalizationError("scope", "local network scope is invalid") from exc
    if not networks:
        raise CanonicalizationError("scope", "at least one local network is required")
    return networks


def _is_local(address: str, networks) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise CanonicalizationError("scope", "dialog endpoint is not a literal address") from exc
    matches = [network for network in networks if parsed.version == network.version and parsed in network]
    if not matches:
        return False
    return True


def _matches_media(frame: FrameRecord, endpoints: set[tuple[str, int]]) -> bool:
    source = (_known(frame.source.address), _known(frame.source.port))
    destination = (_known(frame.destination.address), _known(frame.destination.port))
    return source in endpoints or destination in endpoints


def _offset(value: Decimal, first: Decimal) -> int:
    return int((value - first) * 1000)
