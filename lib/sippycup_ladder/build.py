"""Assemble the ladder document (the one structure every renderer draws).

The document is built from already-redacted strings: addresses go through the
address book, free text goes through the owner-report sanitizer, Call-IDs are
reduced to a short hash, and message bodies exist only as SDP summaries.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
from typing import Any, Optional

from sippycup_workbench.summary_privacy import AddressBook, Sanitizer, short_hash

from .model import SCHEMA, CaptureData, Endpoint, MediaFlow, SipMsg, TlsEvent

MAX_REPEATS_SHOWN = 6
_STATIC_PT = {0: "PCMU", 3: "GSM", 8: "PCMA", 9: "G722", 18: "G729"}


class Redactor:
    """Address and text redaction shared by every rendering."""

    def __init__(self, book: AddressBook, show_addresses: bool) -> None:
        self.book = book
        self.show = show_addresses
        self.sanitizer = Sanitizer(addresses=book)

    def addr(self, address: Optional[str]) -> str:
        if address is None:
            return "unknown"
        if self.show:
            return address
        return self.book.label(address)

    def hostport(self, address: Optional[str], port: Optional[int]) -> str:
        host = self.addr(address)
        try:
            if ipaddress.ip_address(host).version == 6:
                host = f"[{host}]"
        except ValueError:
            pass
        return f"{host}:{port}" if port is not None else host

    def text(self, value: Any, path: str, limit: int = 60) -> str:
        return self.sanitizer.text(value, path, limit=limit) or ""


def _iso(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ---------------------------------------------------------------------------
# grouping, retransmissions, offer/answer


def mark_retransmissions(messages: list) -> None:
    seen: dict = {}
    for message in messages:
        key = (
            message.src.key(),
            message.dst.key(),
            message.call_id,
            message.kind,
            message.method,
            message.status,
            message.cseq,
            message.branch,
        )
        if key in seen:
            first, count = seen[key]
            count += 1
            seen[key] = (first, count)
            message.retrans = count - 1
            message.retrans_after = max(0.0, message.t - first)
        else:
            seen[key] = (message.t, 1)
            if message.tool_retrans:
                message.retrans = 1


def label_offer_answer(messages: list) -> None:
    outstanding: Optional[tuple] = None  # source key of the pending offer
    answered_cseq: set = set()
    for message in messages:
        if message.sdp is None:
            continue
        side = message.src.key()
        if message.kind == "response" and message.cseq in answered_cseq:
            message.sdp.role = "answer"
            continue
        if outstanding is not None and outstanding != side:
            message.sdp.role = "answer"
            answered_cseq.add(message.cseq)
            outstanding = None
        else:
            message.sdp.role = "offer"
            outstanding = side


def group_calls(messages: list) -> list:
    groups: dict = {}
    order: list = []
    for message in messages:
        key = message.call_id
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(message)
    return [groups[key] for key in order]


def call_kind(messages: list) -> str:
    methods = {m.method for m in messages if m.kind == "request"}
    if "INVITE" in methods:
        return "call"
    if "REGISTER" in methods:
        return "registration"
    if methods == {"OPTIONS"}:
        return "options"
    if not methods:
        return "responses-only"
    return "other"


def outcome(messages: list, kind: str, role_of: Any) -> str:
    finals: dict = {}
    challenged = False
    for message in messages:
        if message.kind == "response" and message.status is not None:
            if message.method in ("INVITE", "REGISTER", "OPTIONS") and message.status >= 200:
                finals[(message.method, message.cseq)] = message
                if message.status in (401, 407):
                    challenged = True
    if kind == "registration":
        last = _last(finals, "REGISTER")
        if last is None:
            return "no final response to REGISTER seen"
        if 200 <= last.status < 300:
            return "registered (" + str(last.status) + ")" + (" after an authentication challenge" if challenged else "")
        return f"registration failed with {last.status}" + (" after an authentication challenge" if challenged else "")
    if kind == "options":
        last = _last(finals, "OPTIONS")
        return f"OPTIONS answered {last.status}" if last else "no final response to OPTIONS seen"
    if kind != "call":
        return ""
    invites = [m for m in messages if m.kind == "request" and m.method == "INVITE"]
    last = _last(finals, "INVITE")
    cancelled = any(m.kind == "request" and m.method == "CANCEL" for m in messages)
    if last is None:
        if cancelled:
            return "cancelled before any final response"
        return "no final response to INVITE seen" if invites else ""
    text = ""
    if 200 <= last.status < 300:
        text = f"answered ({last.status})"
        bye = next((m for m in messages if m.kind == "request" and m.method == "BYE"), None)
        if bye is not None:
            text += f"; ended by BYE from {role_of(bye.src)}"
        else:
            text += "; no BYE seen (capture ends with the call up, or it ended another way)"
    elif last.status == 487 and cancelled:
        text = "cancelled by the caller before answer (487)"
    else:
        text = f"not answered: final response {last.status}"
        if last.status in (401, 407):
            text += " (challenge never answered)"
    if challenged and 200 <= last.status < 300:
        text += "; passed an authentication challenge"
    return text


def _last(finals: dict, method: str) -> Optional[SipMsg]:
    candidates = [m for (name, _), m in finals.items() if name == method]
    if not candidates:
        return None
    return max(candidates, key=lambda m: (m.cseq or 0, m.t))


# ---------------------------------------------------------------------------
# columns


class Columns:
    def __init__(self, messages: list, extra_endpoints: list, redactor: Redactor, collide: bool) -> None:
        self.redactor = redactor
        self.collide = collide
        self.cols: list = []  # dicts
        self._index: dict = {}
        self.sdp_owner: dict = {}  # (addr, port) -> col index
        first = next((m for m in messages if m.kind == "request"), messages[0] if messages else None)
        self.caller_key = self._key(first.src) if first else None
        for message in messages:
            self.sig(message.src)
            self.sig(message.dst)
        if first is not None:
            self._role(self.sig(first.src), "caller")
            self._role(self.sig(first.dst), "target")
        for message in messages:
            if message.sdp is not None:
                owner = self.sig(message.src)
                for media in message.sdp.media:
                    if media.address and media.port:
                        self.sdp_owner[(media.address, media.port)] = owner
                        self.sdp_owner[(media.address, media.port + 1)] = owner
        for endpoint in extra_endpoints:
            self.media(endpoint)

    def _key(self, endpoint: Endpoint) -> Any:
        return endpoint.key() if self.collide else endpoint.address

    def sig(self, endpoint: Endpoint) -> int:
        key = self._key(endpoint)
        if key not in self._index:
            self._index[key] = len(self.cols)
            self.cols.append({"address": endpoint.address, "ports": [], "roles": [], "media": False})
        col = self.cols[self._index[key]]
        if endpoint.port is not None and endpoint.port not in col["ports"]:
            col["ports"].append(endpoint.port)
        return self._index[key]

    def media(self, endpoint: Endpoint) -> int:
        owner = self.sdp_owner.get((endpoint.address, endpoint.port))
        if owner is not None:
            return owner
        if not self.collide:
            existing = self._index.get(endpoint.address)
            if existing is not None:
                return existing
        key = ("media", endpoint.address, endpoint.port if self.collide else None)
        if key not in self._index:
            self._index[key] = len(self.cols)
            self.cols.append({"address": endpoint.address, "ports": [], "roles": ["media"], "media": True})
        return self._index[key]

    def _role(self, index: int, role: str) -> None:
        roles = self.cols[index]["roles"]
        if role not in roles:
            roles.append(role)

    def role_of(self, endpoint: Endpoint) -> str:
        col = self.cols[self.sig(endpoint)]
        for role in ("caller", "target"):
            if role in col["roles"]:
                return role
        return "peer"

    def export(self) -> list:
        out = []
        for index, col in enumerate(self.cols):
            port = None
            if col["ports"]:
                # The signaling port: prefer a well-known one, else the first seen.
                port = next((p for p in col["ports"] if p in (5060, 5061, 5062, 5063, 5080)), col["ports"][0])
            roles = col["roles"] or ["peer"]
            out.append(
                {
                    "index": index,
                    "address": self.redactor.addr(col["address"]),
                    "port": port,
                    "label": self.redactor.hostport(col["address"], port),
                    "roles": roles,
                    "media": col["media"],
                }
            )
        return out


# ---------------------------------------------------------------------------
# events


def _sdp_lines(message: SipMsg, redactor: Redactor) -> list:
    if message.sdp is None:
        return []
    lines = []
    for media in message.sdp.media:
        if media.port == 0:
            lines.append(f"{message.sdp.role}: {media.media} REJECTED (port 0)")
            continue
        bits = [f"{message.sdp.role}:", media.media]
        bits.append(redactor.hostport(media.address, media.port))
        if media.proto:
            bits.append(media.proto)
        if media.codecs:
            bits.append("[" + " ".join(media.codecs) + "]")
        if media.direction:
            bits.append(media.direction)
        if media.ptime:
            bits.append(f"ptime={media.ptime}")
        lines.append(" ".join(bits))
        if media.crypto_suites:
            lines.append("SDES-SRTP offered: " + ", ".join(media.crypto_suites) + " (keys not shown)")
        elif media.srtp:
            lines.append("SRTP profile (keying not in SDP; not shown)")
    return lines


def sip_event(message: SipMsg, t0: float, columns: Columns, redactor: Redactor, path: str) -> dict:
    tags = []
    if message.kind == "response":
        reason = redactor.text(message.reason, path + ".reason", 40) if message.reason else ""
        label = f"{message.status} {reason}".strip()
        if message.method != "INVITE":
            label += f" ({redactor.text(message.method, path + '.m', 16)})"
    else:
        label = redactor.text(message.method, path + ".method", 16)
    if message.auth == "challenge":
        tags.append("auth-challenge")
    elif message.auth == "response":
        tags.append("auth-response")
    if message.retrans:
        tags.append("retransmission")
    if message.truncated:
        tags.append("truncated")
    details = []
    if message.auth == "challenge":
        scheme = f" ({message.auth_scheme})" if message.auth_scheme else ""
        details.append(f"authentication challenge{scheme}; nonce and realm not shown")
    elif message.auth == "response":
        scheme = f" ({message.auth_scheme})" if message.auth_scheme else ""
        details.append(f"authentication response{scheme}; credentials not shown")
    if message.retrans:
        after = f"{message.retrans_after:.3f}s after the original" if message.retrans_after is not None else "tool-flagged"
        details.append(f"retransmission #{message.retrans}, {after}")
    details.extend(_sdp_lines(message, redactor))
    if message.other_body_bytes:
        details.append(f"{message.other_body_bytes}-byte non-SDP body not shown")
    if message.truncated:
        details.append("frame was cut short by the capture snap length")
    return {
        "type": "sip",
        "t": round(message.t - t0, 6),
        "from": columns.sig(message.src),
        "to": columns.sig(message.dst),
        "label": label,
        "kind": message.kind,
        "status": message.status,
        "method": message.method,
        "tags": tags,
        "details": details,
        "transport": message.transport,
        "source": message.source,
        "retrans": message.retrans,
        "sdp": None
        if message.sdp is None
        else {
            "role": message.sdp.role,
            "media": [
                {
                    "media": m.media,
                    "address": redactor.addr(m.address),
                    "port": m.port,
                    "proto": m.proto,
                    "codecs": list(m.codecs),
                    "direction": m.direction,
                    "ptime": m.ptime,
                    "srtp": m.srtp,
                    "cryptoSuites": list(m.crypto_suites),
                }
                for m in message.sdp.media
            ],
        },
    }


def _fold_repeats(events: list) -> list:
    out = []
    counts: dict = {}
    for event in events:
        if event["type"] != "sip" or not event["retrans"]:
            out.append(event)
            continue
        key = (event["from"], event["to"], event["label"])
        counts[key] = counts.get(key, 0) + 1
        if counts[key] <= MAX_REPEATS_SHOWN:
            out.append(event)
        else:
            last = next(e for e in reversed(out) if e["type"] == "sip" and (e["from"], e["to"], e["label"]) == key)
            last["folded"] = last.get("folded", 0) + 1
            last["details"] = [d for d in last["details"] if not d.startswith("+")]
            last["details"].append(f"+{last['folded']} further repeat(s) not drawn (last at +{event['t']:.3f}s)")
    return out


def media_event(flow: MediaFlow, t0: float, columns: Columns, pt_names: dict, srtp: bool, redactor: Redactor) -> dict:
    names = []
    for pt, count in flow.payload_types.items():
        name = pt_names.get(pt) or _STATIC_PT.get(pt) or (f"pt{pt}")
        names.append(f"{name}({pt}) x{count}" if len(flow.payload_types) > 1 else f"{name}({pt})")
    kind = flow.kind.upper()
    label = f"{kind} {flow.packets} pkt" + ("s" if flow.packets != 1 else "")
    if len(names) == 1 and flow.kind == "rtp":
        label += " " + names[0]
    details = [
        f"{'first' if flow.packets == 1 else 'window'} +{flow.t_first - t0:.3f}s"
        + (f" .. +{flow.t_last - t0:.3f}s ({flow.t_last - flow.t_first:.2f}s)" if flow.packets > 1 else "")
    ]
    if len(names) > 1:
        details.insert(0, "payload types: " + ", ".join(names))
    if flow.kind == "rtp":
        telephone = [pt for pt in flow.payload_types if (pt_names.get(pt) or "").lower() == "telephone-event"]
        if flow.events or telephone:
            details.append(f"telephone-event: {flow.events} event(s); digit values are not shown")
        if flow.missing:
            details.append(f"~{flow.missing} packet(s) missing by sequence gap")
        if flow.ssrcs > 1:
            details.append(f"{flow.ssrcs} SSRCs (stream restarts)")
    if srtp:
        details.append("SRTP negotiated: payload encrypted, not inspected")
    if flow.heuristic:
        details.append("identified by RTP heuristics (no SDP mapped it to a call)")
    return {
        "type": "media",
        "t": round(flow.t_first - t0, 6),
        "t_last": round(flow.t_last - t0, 6),
        "from": columns.media(flow.src),
        "to": columns.media(flow.dst),
        "label": label,
        "proto": flow.kind,
        "packets": flow.packets,
        "payloadTypes": {str(k): v for k, v in flow.payload_types.items()},
        "telephoneEvents": flow.events,
        "missing": flow.missing,
        "details": details,
    }


# ---------------------------------------------------------------------------
# sections


def _pt_names(messages: list) -> tuple:
    names: dict = {}
    srtp = False
    for message in messages:
        if message.sdp is None:
            continue
        for media in message.sdp.media:
            for pt, name in media.payload_types:
                names[pt] = name
            srtp = srtp or media.srtp
    return names, srtp


def _sdp_endpoints(messages: list) -> set:
    found = set()
    for message in messages:
        if message.sdp is None:
            continue
        for media in message.sdp.media:
            if media.address and media.port:
                found.add((media.address, media.port))
                found.add((media.address, media.port + 1))
    return found


def build_call_sections(messages: list, flows: list, redactor: Redactor) -> tuple:
    """Return (sections, unassigned_flows)."""
    messages = sorted(messages, key=lambda m: (m.t, m.frame or 0))
    mark_retransmissions(messages)
    groups = group_calls(messages)
    collide = any(m.src.address is not None and m.src.address == m.dst.address for m in messages)
    frame_to_group = {}
    for index, group in enumerate(groups):
        for message in group:
            if message.frame is not None:
                frame_to_group[message.frame] = index
    endpoint_sets = [_sdp_endpoints(group) for group in groups]
    assigned: list = [[] for _ in groups]
    loose: list = []
    for flow in flows:
        target = frame_to_group.get(flow.setup_frame) if flow.setup_frame is not None else None
        if target is None:
            hits = [
                i
                for i, endpoints in enumerate(endpoint_sets)
                if flow.src.key() in endpoints or flow.dst.key() in endpoints
            ]
            if len(hits) > 1:
                hits = [
                    i
                    for i in hits
                    if groups[i][0].t - 1 <= flow.t_first <= groups[i][-1].t + 30
                ] or hits
            target = hits[0] if hits else None
        if target is None:
            candidates = [
                i
                for i, group in enumerate(groups)
                if call_kind(group) == "call" and group[0].t - 1 <= flow.t_first <= group[-1].t + 5
            ]
            target = candidates[0] if len(candidates) == 1 else None
        if target is None:
            loose.append(flow)
        else:
            assigned[target].append(flow)
    sections = []
    for index, group in enumerate(groups):
        group.sort(key=lambda m: (m.t, m.frame or 0))
        label_offer_answer(group)
        t0 = group[0].t
        kind = call_kind(group)
        columns = Columns(group, [ep for f in assigned[index] for ep in (f.src, f.dst)], redactor, collide)
        pt_names, srtp = _pt_names(group)
        events = []
        previous = None
        for message in group:
            event = sip_event(message, t0, columns, redactor, f"calls[{index}]")
            event["gap"] = None if previous is None else round(message.t - previous, 6)
            previous = message.t
            events.append(event)
        events = _fold_repeats(events)
        for flow in assigned[index]:
            events.append(media_event(flow, t0, columns, pt_names, srtp, redactor))
        events.sort(key=lambda e: (e["t"], 0 if e["type"] == "sip" else 1))
        sources = sorted({m.source for m in group})
        sections.append(
            {
                "index": index + 1,
                "kind": kind,
                "title": {"call": "Call", "registration": "Registration", "options": "OPTIONS", "responses-only": "Responses without requests"}.get(kind, "SIP transaction"),
                "callIdHash": short_hash(group[0].call_id) if group[0].call_id else None,
                "startUtc": _iso(t0),
                "startEpoch": t0,
                "durationSeconds": round(max([m.t for m in group] + [f.t_last for f in assigned[index]]) - t0, 3),
                "outcome": outcome(group, kind, columns.role_of),
                "source": sources[0] if len(sources) == 1 else "+".join(sources),
                "columns": columns.export(),
                "events": events,
                "counts": {
                    "sipMessages": len(group),
                    "retransmissions": sum(1 for m in group if m.retrans),
                    "mediaFlows": len(assigned[index]),
                },
            }
        )
    return sections, loose


def build_loose_media_section(flows: list, index: int, redactor: Redactor, note: str) -> Optional[dict]:
    if not flows:
        return None
    t0 = min(f.t_first for f in flows)
    endpoints = [ep for f in flows for ep in (f.src, f.dst)]
    columns = Columns([], endpoints, redactor, collide=any(f.src.address == f.dst.address for f in flows))
    events = [media_event(f, t0, columns, {}, False, redactor) for f in flows]
    events.sort(key=lambda e: e["t"])
    cols = columns.export()
    for col in cols:
        col["roles"] = ["media"]
    return {
        "index": index,
        "kind": "media-only",
        "title": "Media not tied to a SIP call",
        "callIdHash": None,
        "startUtc": _iso(t0),
        "startEpoch": t0,
        "durationSeconds": round(max(f.t_last for f in flows) - t0, 3),
        "outcome": note,
        "source": "capture",
        "columns": cols,
        "events": events,
        "counts": {"sipMessages": 0, "retransmissions": 0, "mediaFlows": len(flows)},
    }


def build_transport_section(events: list, sip_pairs: set, redactor: Redactor, index: int) -> Optional[dict]:
    """TCP/TLS connection rows. Plain-TCP SIP connection events are kept too."""
    if not events:
        return None
    # Group into connections by unordered endpoint pair.
    def pair(event: TlsEvent) -> frozenset:
        return frozenset([event.src.key(), event.dst.key()])

    connections: dict = {}
    for event in events:
        connections.setdefault(pair(event), []).append(event)
    kept = {}
    for key, items in connections.items():
        has_tls = any(e.kind in ("handshake", "appdata", "alert") for e in items)
        if has_tls or key in sip_pairs or any(
            (ep[1] in (5060, 5061, 5062, 5063, 5080)) for ep in key
        ):
            kept[key] = items
    if not kept:
        return None
    t0 = min(e.t for items in kept.values() for e in items)
    columns = Columns([], [], redactor, collide=False)
    for items in kept.values():
        for e in items:
            columns.sig(e.src)
            columns.sig(e.dst)
    # The server (receiving the first SYN / ClientHello) is the target.
    first = min((e for items in kept.values() for e in items), key=lambda e: e.t)
    columns._role(columns.sig(first.src), "caller")
    columns._role(columns.sig(first.dst), "target")
    out_events = []
    order = sorted(kept, key=lambda k: min(e.t for e in kept[k]))
    for number, key in enumerate(order, 1):
        items = sorted(kept[key], key=lambda e: (e.t, e.frame or 0))
        aggregated: dict = {}
        for e in items:
            if e.kind == "appdata":
                slot = aggregated.setdefault((e.src.key(), e.dst.key()), {"first": e, "records": 0, "bytes": 0, "last": e.t})
                slot["records"] += e.records
                slot["bytes"] += e.nbytes
                slot["last"] = e.t
                continue
            label = {
                "syn": "TCP SYN",
                "synack": "TCP SYN/ACK",
                "fin": "TCP FIN",
                "rst": "TCP RST",
                "handshake": "TLS " + e.detail,
                "alert": "TLS alert",
            }.get(e.kind, e.kind)
            out_events.append(
                {
                    "type": "transport",
                    "t": round(e.t - t0, 6),
                    "from": columns.sig(e.src),
                    "to": columns.sig(e.dst),
                    "label": f"{label} [conn {number}]",
                    "details": [],
                    "tags": [],
                }
            )
        for (src_key, dst_key), slot in aggregated.items():
            first_event = slot["first"]
            out_events.append(
                {
                    "type": "transport",
                    "t": round(first_event.t - t0, 6),
                    "t_last": round(slot["last"] - t0, 6),
                    "from": columns.sig(first_event.src),
                    "to": columns.sig(first_event.dst),
                    "label": f"TLS application data x{slot['records']} [conn {number}]",
                    "details": [f"{slot['bytes']} bytes of ciphertext; SIP content is not visible"],
                    "tags": ["encrypted"],
                }
            )
    out_events.sort(key=lambda e: e["t"])
    previous = None
    for event in out_events:
        event["gap"] = None if previous is None else round(event["t"] - previous, 6)
        previous = event["t"]
    return {
        "index": index,
        "kind": "transport",
        "title": "TCP/TLS connections",
        "callIdHash": None,
        "startUtc": _iso(t0),
        "startEpoch": t0,
        "durationSeconds": round(max(e.get("t_last", e["t"]) for e in out_events), 3),
        "outcome": f"{len(order)} connection(s); signaling inside TLS is encrypted",
        "source": "capture",
        "columns": columns.export(),
        "events": out_events,
        "counts": {"sipMessages": 0, "retransmissions": 0, "mediaFlows": 0},
    }


def build_document(
    *,
    capture: Optional[CaptureData],
    log_messages: list,
    flows: list,
    redactor: Redactor,
    source: dict,
    approved_networks: list,
    call_index: Optional[int],
    notes: list,
) -> dict:
    warnings = list(capture.warnings) if capture else []
    messages: list = []
    capture_ids = set()
    if capture is not None:
        messages.extend(capture.sip)
        capture_ids = {m.call_id for m in capture.sip}
    log_used = False
    extra = [m for m in log_messages if m.call_id not in capture_ids]
    if extra:
        messages.extend(extra)
        log_used = True
    transport_events = capture.tls if capture else []
    encrypted = any(e.kind == "appdata" for e in transport_events)
    sections: list = []
    loose: list = list(flows)
    if messages:
        sections, loose = build_call_sections(messages, flows, redactor)
    sip_pairs = {frozenset([m.src.key(), m.dst.key()]) for m in messages if m.transport in ("tcp", "tls")}
    transport = build_transport_section(transport_events, sip_pairs, redactor, 0)
    if transport is not None and (not messages or log_used or encrypted):
        sections.insert(0, transport)
    loose_section = build_loose_media_section(
        loose,
        0,
        redactor,
        "RTP/RTCP seen with no SIP message or SDP that maps it to a call",
    )
    if loose_section is not None:
        sections.append(loose_section)
    for number, section in enumerate(sections, 1):
        section["index"] = number
    if call_index is not None:
        picked = [s for s in sections if s["index"] == call_index]
        if not picked:
            raise IndexError(f"--call-id-index {call_index}: this capture has {len(sections)} section(s)")
        sections = picked
    sip_present = any(s["counts"]["sipMessages"] for s in sections)
    if not sip_present:
        if encrypted:
            notes.append(
                "No SIP messages are visible: signaling is TLS-encrypted. Showing what is still knowable "
                "(TCP/TLS connection events and media). For SIP detail, run with the run directory's softphone log."
            )
        else:
            notes.append("No SIP signaling was found; only the transport or media evidence below is drawn.")
    elif log_used:
        notes.append(
            "Signaling for some calls comes from the softphone log (TLS hides it on the wire); "
            "those calls are marked source=softphone-log. Media and TCP/TLS rows come from the capture, aligned by wall clock."
        )
    if capture is not None and any(m.source == "capture" for m in messages) and encrypted:
        notes.append("Some connections in this capture are TLS-encrypted; their SIP is not in the capture ladder.")
    document = {
        "schema": SCHEMA,
        "networkActivity": False,
        "source": source,
        "signalingEncrypted": encrypted,
        "redaction": {
            "addresses": "shown (operator copy)" if redactor.show else "approved addresses shown, others replaced by labels",
            "approvedNetworks": approved_networks if not redactor.show else [],
            "addressesRelabeled": len(redactor.book.pseudonyms),
            "credentials": "never shown",
            "cryptoKeys": "never shown",
            "userParts": "never shown (no SIP URIs are drawn)",
            "callIds": "hash only",
            "messageBodies": "SDP summary only",
            "dtmf": "event counts only, never digit values",
        },
        "notes": notes,
        "warnings": warnings,
        "sections": sections,
    }
    return document
