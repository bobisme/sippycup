"""Read SIP, TLS and RTP evidence from a capture with TShark.

Two bounded TShark runs share the oracle's runner and limits:

1. a JSON run filtered to signaling (SIP, TLS, TCP connection events), whose
   frames go through the oracle's packet adapter, and
2. a field run for RTP and RTCP, which would be far too large as JSON.

Message bodies are never kept. Header values other than the ones named in
`model.SipMsg` are never read.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Optional

from sippycup_oracle.adapter import (
    CaptureDecodeError,
    _find,
    _find_values,
    _scalar,
    parse_tshark_json,
    probe_capture_format,
    tshark_json_args,
)
from sippycup_oracle.cli import (
    MAX_CAPTURE_BYTES,
    TsharkExecutionError,
    _run_tshark_bounded,
)
from sippycup_oracle.records import Known

from .model import (
    AUTH_SCHEMES,
    CaptureData,
    Endpoint,
    MediaFlow,
    SipMsg,
    TlsEvent,
)
from .sdp import summary_from_hex_body

SIP_PORTS = "5060, 5061, 5062, 5063, 5080"

_JSON_FILTER = (
    "sip || tls"
    f" || (tcp.flags.syn==1 && tcp.port in {{{SIP_PORTS}}})"
    f" || (tcp.flags.fin==1 && tcp.port in {{{SIP_PORTS}}})"
    f" || (tcp.flags.reset==1 && tcp.port in {{{SIP_PORTS}}})"
    " || frame.cap_len < frame.len"
    f" || (tcp.len>0 && !tcp.reassembled_in && !sip && !tls && tcp.port in {{{SIP_PORTS}}})"
)

_MEDIA_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "udp.srcport",
    "ip.dst",
    "ipv6.dst",
    "udp.dstport",
    "rtp.ssrc",
    "rtp.p_type",
    "rtp.extseq",
    "rtp.timestamp",
    "rtpevent.end_of_event",
    "rtp.setup-frame",
    "rtcp.pt",
)

_HANDSHAKE = {
    "0": "HelloRequest",
    "1": "ClientHello",
    "2": "ServerHello",
    "4": "NewSessionTicket",
    "8": "EncryptedExtensions",
    "11": "Certificate",
    "12": "ServerKeyExchange",
    "13": "CertificateRequest",
    "14": "ServerHelloDone",
    "15": "CertificateVerify",
    "16": "ClientKeyExchange",
    "20": "Finished",
}


class LadderCaptureError(ValueError):
    """The capture cannot be read (bad file, TShark failure)."""

    def __init__(self, message: str, code: int = 3) -> None:
        super().__init__(message)
        self.code = code


def _int(value: Any) -> Optional[int]:
    try:
        text = str(value).strip().lower()
        return int(text, 16) if text.startswith("0x") else int(text)
    except (TypeError, ValueError):
        return None


def _scalars(node: Any, key: str) -> list:
    return [str(item) for item in _find_values(node, key) if item is not None]


def _endpoint(known_addr: Any, known_port: Any) -> Endpoint:
    address = known_addr.value if isinstance(known_addr, Known) else None
    port = known_port.value if isinstance(known_port, Known) else None
    return Endpoint(address, port)


def _transport(record: Any) -> Optional[str]:
    value = record.source.transport
    return value.value.value if isinstance(value, Known) else None


def _auth_scheme(layer: Any, key: str) -> Optional[str]:
    raw = _scalar(_find(layer, key))
    if not isinstance(raw, str):
        return None
    word = raw.strip().split(None, 1)[0] if raw.strip() else ""
    for scheme in AUTH_SCHEMES:
        if word.lower() == scheme.lower():
            return scheme
    return "other"


def _sip_messages(
    packet: dict, layers: dict, fmt: Any, data: CaptureData
) -> list:
    sip_layer = layers.get("sip")
    if sip_layer is None:
        return []
    variants = sip_layer if isinstance(sip_layer, list) else [sip_layer]
    messages = []
    for variant in variants:
        if not isinstance(variant, dict):
            continue
        shadow = dict(layers)
        shadow["sip"] = variant
        record = parse_tshark_json(
            json.dumps([{"_source": {"layers": shadow}}]), fmt
        ).frames[0]
        sip = record.sip
        if sip is None:
            continue
        data.sip_frames_seen += 1
        request_line = _scalar(variant.get("sip.Request-Line"))
        status_line = _scalar(variant.get("sip.Status-Line"))
        method = sip.request_method.value if isinstance(sip.request_method, Known) else None
        status = sip.status_code.value if isinstance(sip.status_code, Known) else None
        reason = None
        if isinstance(status_line, str):
            parts = status_line.split(None, 2)
            if len(parts) >= 3:
                reason = parts[2]
        if method is None and isinstance(request_line, str):
            method = request_line.split(None, 1)[0]
        kind = "response" if status is not None else "request"
        cseq_method = sip.cseq_method.value if isinstance(sip.cseq_method, Known) else None
        if kind == "response":
            method = cseq_method or "?"
        if method is None:
            continue
        auth = None
        scheme = None
        if _find(variant, "sip.Authorization") is not None:
            auth, scheme = "response", _auth_scheme(variant, "sip.Authorization")
        elif _find(variant, "sip.Proxy-Authorization") is not None:
            auth, scheme = "response", _auth_scheme(variant, "sip.Proxy-Authorization")
        elif _find(variant, "sip.WWW-Authenticate") is not None:
            auth, scheme = "challenge", _auth_scheme(variant, "sip.WWW-Authenticate")
        elif _find(variant, "sip.Proxy-Authenticate") is not None:
            auth, scheme = "challenge", _auth_scheme(variant, "sip.Proxy-Authenticate")
        body = _scalar(_find(variant, "sip.msg_body"))
        sdp = summary_from_hex_body(body, record.sdp)
        other_body = 0
        if sdp is None and isinstance(body, str) and body:
            other_body = len(body.replace(":", "")) // 2
        timestamp = record.evidence.timestamp_epoch
        frame_number = record.evidence.frame_number
        resend = _scalar(variant.get("sip.resend")) if "sip.resend" in variant else None
        messages.append(
            SipMsg(
                t=float(timestamp.value) if isinstance(timestamp, Known) else 0.0,
                frame=frame_number.value if isinstance(frame_number, Known) else None,
                src=_endpoint(record.source.address, record.source.port),
                dst=_endpoint(record.destination.address, record.destination.port),
                transport=_transport(record),
                kind=kind,
                method=method,
                status=status,
                reason=reason,
                call_id=sip.call_id.value if isinstance(sip.call_id, Known) else "",
                cseq=sip.cseq_number.value if isinstance(sip.cseq_number, Known) else None,
                branch=sip.via_branch.value if isinstance(sip.via_branch, Known) else None,
                from_tag=sip.from_tag.value if isinstance(sip.from_tag, Known) else None,
                to_tag=sip.to_tag.value if isinstance(sip.to_tag, Known) else None,
                auth=auth,
                auth_scheme=scheme,
                sdp=sdp,
                other_body_bytes=other_body,
                truncated=_truncated(record),
                tool_retrans=str(resend) == "1",
            )
        )
    return messages


def _truncated(record: Any) -> bool:
    status = record.status
    return isinstance(status, Known) and status.value.value == "truncated"


def _tls_events(layers: dict, record: Any) -> list:
    timestamp = record.evidence.timestamp_epoch
    t = float(timestamp.value) if isinstance(timestamp, Known) else 0.0
    frame = record.evidence.frame_number.value if isinstance(record.evidence.frame_number, Known) else None
    src = _endpoint(record.source.address, record.source.port)
    dst = _endpoint(record.destination.address, record.destination.port)
    events: list = []
    tls = layers.get("tls")
    if tls is not None:
        content_types = _scalars(tls, "tls.record.content_type")
        handshakes = [
            _HANDSHAKE.get(item, f"handshake-{item}")
            for item in _scalars(tls, "tls.handshake.type")
        ]
        versions = _scalars(tls, "tls.record.version")
        lengths = [n for n in (_int(v) for v in _scalars(tls, "tls.record.length")) if n]
        version = versions[0] if versions else ""
        names = {"0x0300": "SSL3", "0x0301": "TLS1.0", "0x0302": "TLS1.1", "0x0303": "TLS1.2", "0x0304": "TLS1.3"}
        version_name = names.get(version.lower(), "")
        if "22" in content_types or "20" in content_types or "21" in content_types:
            detail = list(handshakes)
            if "20" in content_types:
                detail.append("ChangeCipherSpec")
            if "22" in content_types and not handshakes:
                detail.append("encrypted handshake")
            if "21" in content_types:
                detail.append("Alert")
            kind = "alert" if "21" in content_types and not handshakes else "handshake"
            text = ", ".join(detail)
            if version_name and "ClientHello" in handshakes:
                text += f" ({version_name} record)"
            events.append(TlsEvent(t, frame, src, dst, kind, text))
        if "23" in content_types:
            events.append(
                TlsEvent(
                    t,
                    frame,
                    src,
                    dst,
                    "appdata",
                    records=content_types.count("23"),
                    nbytes=sum(lengths) if lengths else 0,
                )
            )
    elif layers.get("tcp") is not None:
        flags = _int(_scalar(layers["tcp"].get("tcp.flags")) if isinstance(layers["tcp"], dict) else None)
        if flags is not None:
            if flags & 0x02:
                events.append(TlsEvent(t, frame, src, dst, "synack" if flags & 0x10 else "syn"))
            elif flags & 0x04:
                events.append(TlsEvent(t, frame, src, dst, "rst"))
            elif flags & 0x01:
                events.append(TlsEvent(t, frame, src, dst, "fin"))
    return events


def read_signaling(path: Path) -> CaptureData:
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise LadderCaptureError(f"cannot read capture: {exc}") from exc
    if size > MAX_CAPTURE_BYTES:
        raise LadderCaptureError("capture exceeds the 512 MiB byte limit")
    try:
        fmt = probe_capture_format(path)
    except CaptureDecodeError as exc:
        raise LadderCaptureError(str(exc)) from exc
    command = list(tshark_json_args(path)) + ["-2", "-Y", _JSON_FILTER]
    try:
        status, stdout, stderr = _run_tshark_bounded(command)
    except TsharkExecutionError as exc:
        raise LadderCaptureError(f"TShark failed: {exc}", code=5) from exc
    if status != 0:
        raise LadderCaptureError(
            "TShark could not read the capture: " + stderr.strip().splitlines()[-1][:200]
            if stderr.strip()
            else "TShark could not read the capture"
        )
    try:
        packets = json.loads(stdout) if stdout.strip() else []
    except json.JSONDecodeError as exc:
        raise LadderCaptureError(f"TShark produced invalid JSON: {exc}", code=5) from exc
    data = CaptureData()
    for packet in packets:
        source = packet.get("_source", packet) if isinstance(packet, dict) else None
        layers = source.get("layers") if isinstance(source, dict) else None
        if not isinstance(layers, dict):
            continue
        try:
            record = parse_tshark_json(json.dumps([{"_source": {"layers": layers}}]), fmt).frames[0]
        except (CaptureDecodeError, IndexError):
            continue
        timestamp = record.evidence.timestamp_epoch
        if isinstance(timestamp, Known):
            t = float(timestamp.value)
            data.first_t = t if data.first_t is None else min(data.first_t, t)
            data.last_t = t if data.last_t is None else max(data.last_t, t)
        if _truncated(record):
            data.truncated_frames += 1
        if layers.get("sip") is not None:
            data.sip.extend(_sip_messages(packet, layers, fmt, data))
        elif layers.get("tls") is not None or layers.get("tcp") is not None:
            events = _tls_events(layers, record)
            data.tls.extend(events)
            if not events and layers.get("tcp") is not None and layers.get("tls") is None:
                if isinstance(layers.get("tcp"), dict) and _scalar(layers["tcp"].get("tcp.len")) not in (None, "0"):
                    data.incomplete_segments += 1
    data.sip.sort(key=lambda m: (m.t, m.frame or 0))
    data.tls.sort(key=lambda e: (e.t, e.frame or 0))
    if data.truncated_frames:
        data.warnings.append(
            f"{data.truncated_frames} frame(s) were cut short by the capture snap length; "
            "messages in them may be missing or incomplete"
        )
    if data.incomplete_segments:
        data.warnings.append(
            f"{data.incomplete_segments} TCP segment(s) on SIP ports never completed a SIP message "
            "(capture ended or lost segments); that signaling is missing from the ladder"
        )
    return data


def read_media(
    path: Path,
    *,
    decode_ports: Iterable[int] = (),
    heuristic: bool = False,
) -> list:
    command = ["tshark", "-r", str(path), "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"]
    for port in sorted({int(p) for p in decode_ports if p}):
        command += ["-d", f"udp.port=={port},rtp"]
    if heuristic:
        command += ["-o", "rtp.heuristic_rtp:TRUE", "-o", "rtcp.heuristic_rtcp:TRUE"]
    command += ["-2", "-Y", "rtp || rtcp"]
    for field_name in _MEDIA_FIELDS:
        command += ["-e", field_name]
    try:
        status, stdout, stderr = _run_tshark_bounded(command)
    except TsharkExecutionError as exc:
        raise LadderCaptureError(f"TShark failed: {exc}", code=5) from exc
    if status != 0:
        raise LadderCaptureError("TShark could not read the capture for media")
    flows: dict = {}
    seen_events: dict = {}
    for line in stdout.splitlines():
        cells = line.split("\t")
        if len(cells) < len(_MEDIA_FIELDS):
            cells += [""] * (len(_MEDIA_FIELDS) - len(cells))
        (_frame, epoch, ip4s, ip6s, sport, ip4d, ip6d, dport, ssrc, ptype, extseq, rtpts, event_end, setup, rtcp_pt) = cells[: len(_MEDIA_FIELDS)]
        try:
            t = float(epoch)
        except ValueError:
            continue
        src = Endpoint(ip4s or ip6s or None, _int(sport))
        dst = Endpoint(ip4d or ip6d or None, _int(dport))
        kind = "rtp" if ssrc or ptype else "rtcp"
        if kind == "rtcp" and not rtcp_pt:
            continue
        key = (kind, src.key(), dst.key())
        flow = flows.get(key)
        if flow is None:
            flow = flows[key] = {
                "packets": 0,
                "first": t,
                "last": t,
                "pts": {},
                "ssrc": {},
                "setup": _int(setup),
            }
        flow["packets"] += 1
        flow["first"] = min(flow["first"], t)
        flow["last"] = max(flow["last"], t)
        if kind == "rtp":
            pt = _int(ptype)
            if pt is not None:
                flow["pts"][pt] = flow["pts"].get(pt, 0) + 1
            seq = _int(extseq)
            stats = flow["ssrc"].setdefault(ssrc, [None, None, 0])
            if seq is not None:
                stats[0] = seq if stats[0] is None else min(stats[0], seq)
                stats[1] = seq if stats[1] is None else max(stats[1], seq)
            stats[2] += 1
            if event_end != "":
                seen_events.setdefault(key, set()).add((ssrc, rtpts))
    result = []
    for key, flow in flows.items():
        kind, src_key, dst_key = key
        missing = 0
        for low, high, count in flow["ssrc"].values():
            if low is not None and high is not None:
                missing += max(0, (high - low + 1) - count)
        result.append(
            MediaFlow(
                kind=kind,
                src=Endpoint(*src_key),
                dst=Endpoint(*dst_key),
                packets=flow["packets"],
                t_first=flow["first"],
                t_last=flow["last"],
                payload_types=dict(sorted(flow["pts"].items())),
                ssrcs=max(1, len(flow["ssrc"])),
                missing=missing,
                events=len(seen_events.get(key, ())),
                setup_frame=flow["setup"],
                heuristic=heuristic,
            )
        )
    result.sort(key=lambda f: (f.t_first, f.src.key(), f.dst.key()))
    return result
