"""Diagnose one guided-call run directory.

The verdict in result.json is the starting point. This module adds what the
verdict alone does not say: the stage where the run stopped, the decisive
evidence, whose side the evidence points at (and how sure that is), and the
next commands built from the run's own recorded profile and flags.
"""

from __future__ import annotations

from typing import Any, Optional

from .callrun import CallRun, MAX_ANSWER_TIMEOUT
from .core import (
    HIGH, LOW, MEDIUM, NETWORK, NONE, OUR, THEIR, UNKNOWN, Diagnosis, Redaction,
    is_loopback, is_private,
)
from .files import unwrap
from .ladder_bridge import Lazy

RTP_PORT_SLACK = 1


# ---------------------------------------------------------------------------
# Evidence helpers


def _num(value: Any, digits: int = 2) -> str:
    if isinstance(value, float):
        return f"{value:.{digits}f}".rstrip("0").rstrip(".") or "0"
    return str(value)


def oracle_lines(run: CallRun) -> list:
    """Failing oracle assertions with their numbers, from assert.json (else result.json)."""
    out: list = []
    limits = (run.expect.get("expectations") or [{}])[0].get("parameters", {}) if isinstance(run.expect.get("expectations"), list) and run.expect.get("expectations") else {}
    assertions = run.assertion.get("assertions") if isinstance(run.assertion.get("assertions"), list) else []
    for item in assertions:
        if not isinstance(item, dict) or item.get("verdict") != "fail":
            continue
        ident = str(item.get("id", "?")).replace("dialog[0].", "")
        observed = unwrap(item.get("observed"))
        text = f"{ident}: {item.get('message')}"
        detail = _observed_text(ident, observed, limits)
        if detail:
            text += f" ({detail})"
        out.append(text)
    if not out:
        for item in (run.result.get("oracle") or {}).get("failedDetails") or []:
            out.append(f"{str(item.get('id', '?')).replace('dialog[0].', '')}: {item.get('message')}")
    return out


def _observed_text(ident: str, observed: Any, limits: dict) -> str:
    if observed is None:
        return ""
    if ident.endswith("media.sequence") and isinstance(observed, list):
        parts = []
        for number, stream in enumerate(observed, 1):
            if not isinstance(stream, dict):
                continue
            parts.append(
                f"stream {number}: {stream.get('received')}/{stream.get('expected')} received, lost {stream.get('lost')}, "
                f"dup {stream.get('duplicates')}, reordered {stream.get('reordered')}, ts jumps {stream.get('timestamp_jumps')}"
            )
        return "; ".join(parts)
    if ident.endswith("media.jitter") and isinstance(observed, list):
        values = []
        for value in observed:
            try:
                values.append(f"{float(value):.2f} ms")
            except (TypeError, ValueError):
                continue
        limit = limits.get("max_jitter_ms")
        return "jitter per stream " + ", ".join(values) + (f"; limit {limit} ms" if limit is not None else "")
    if ident.endswith("media.timing"):
        limit = limits.get("max_setup_ms")
        return f"limit {limit} ms" if limit is not None else ""
    if isinstance(observed, (str, int, float, bool)):
        return f"observed {observed}"
    if isinstance(observed, list) and all(isinstance(item, (str, int, float)) for item in observed):
        return "observed " + ", ".join(str(item) for item in observed)
    return ""


def oracle_unknown(run: CallRun) -> list:
    oracle = run.result.get("oracle") or {}
    return [str(item).replace("dialog[0].", "") for item in oracle.get("unknown") or []]


def sdp_text(sdp, red: Redaction) -> str:
    if sdp is None:
        return "none seen"
    bits = [red.hostport(sdp.address, sdp.port), sdp.proto or "?"]
    if sdp.formats:
        bits.append("PT " + ",".join(sdp.formats))
    if sdp.direction:
        bits.append(sdp.direction)
    if sdp.crypto:
        bits.append("SDES keying present (key material never shown)")
    return " ".join(bits)


def add_common(d: Diagnosis, run: CallRun) -> None:
    """Evidence every call diagnosis carries when the run recorded it."""
    red = d.red
    soft = run.softphone
    # Final statuses
    reg = soft.get("registration_status")
    if soft.get("registration_attempted"):
        d.evidence("registration", f"REGISTER final status {reg}" if reg is not None else "REGISTER: no final status (no response or a transport error)")
    inv = run.invite_times()
    status = soft.get("final_status")
    if status is not None:
        phrase = ""
        for message in run.inbound("INVITE", final=True):
            if message.status == status and message.phrase:
                phrase = " " + message.phrase
        if soft.get("answered"):
            d.evidence("INVITE", f"answered {status}{phrase}")
        else:
            d.evidence("INVITE", f"final status {status}{phrase}" + (f" (provisional seen: {inv['provisionalStatus']})" if inv.get("provisionalStatus") else ""))
    elif soft.get("dialed"):
        d.evidence("INVITE", "no final status was received")
    for label, text in run.far_end_headers():
        d.evidence(label, text)
    # SDP
    offer, answer = run.sdp(True), run.sdp(False)
    if offer is not None or answer is not None:
        d.evidence("SDP offer", sdp_text(offer, red))
        if answer is not None:
            d.evidence("SDP answer", sdp_text(answer, red))
    # Media counters
    tx, rx = soft.get("rtp_tx_packets"), soft.get("rtp_rx_packets")
    if tx is not None or rx is not None:
        text = f"PJSUA counters: {tx} packets out, {rx} in"
        types = ((run.result.get("codec") or {}).get("wire") or {}).get("rtpPayloadTypes")
        if isinstance(types, dict):
            text += "; capture payload types out " + _pts(types.get("outbound")) + ", in " + _pts(types.get("inbound"))
        d.evidence("RTP", text)
    scope = run.result.get("mediaScope") or {}
    if scope.get("peer"):
        text = f"media peer {scope['peer']}: "
        if scope.get("inScope") is True:
            how = scope.get("admittedBy") or "an approved rule"
            text += f"admitted by {how}" + (f" ({scope['network']})" if scope.get("network") else "")
        elif scope.get("inScope") is False:
            text += "refused (no scope rule admits it)"
            rules = scope.get("rules") or {}
            text += f"; rules: approved addresses {len(rules.get('approvedAddresses') or [])}, media networks {len(rules.get('mediaNetworks') or [])}"
            if scope.get("portAdmitted") is False:
                text += ", port outside the approved media port range"
        d.evidence("media scope", text)
    # Timing
    reg_t = run.registration_seconds()
    d.timing("registration", reg_t, "first REGISTER to its final response")
    if inv.get("provisional") is not None:
        d.timing("INVITE to first provisional", inv["provisional"], f"{inv.get('provisionalStatus')}")
    elif (soft.get("setup") or {}).get("inviteToProvisionalSeconds") is not None:
        d.timing("INVITE to first provisional", soft["setup"]["inviteToProvisionalSeconds"])
    answer_s = (soft.get("setup") or {}).get("inviteToAnswerSeconds")
    if answer_s is not None and soft.get("answered"):
        d.timing("INVITE to answer", answer_s)
    elif inv.get("final") is not None and not soft.get("answered"):
        d.timing("INVITE to final response", inv["final"])
    if soft.get("connected_seconds") is not None:
        d.timing("answered call duration", soft["connected_seconds"], f"planned {(run.plan_phone.get('duration_seconds') or {}).get('effective')}s")
    bye = run.bye_seconds()
    d.timing("teardown (BYE to 200)", bye if bye and bye > 0.0005 else None)
    d.timing("whole run", run.wall("started", "finished"))


def _pts(value: Any) -> str:
    if not isinstance(value, dict) or not value:
        return "none"
    return ", ".join(f"pt {k} x{v}" for k, v in sorted(value.items(), key=lambda item: str(item[0])))


# ---------------------------------------------------------------------------
# Media facts (reuses the ladder's capture reader)


class MediaFacts:
    def __init__(self, run: CallRun, ladder: Lazy) -> None:
        self.offer = run.sdp(True)
        self.answer = run.sdp(False)
        self.flows: list = []
        self.have_flows = False
        ports = set()
        for sdp in (self.offer, self.answer):
            if sdp is not None and sdp.port:
                ports.update({sdp.port, sdp.port + 1})
        if run.has_capture:
            self.flows = ladder.flows(ports)
            self.have_flows = bool(self.flows)
        self.out_to_answer = 0
        self.out_elsewhere = 0
        self.in_to_us = 0
        self.in_from_answer = 0
        self.in_other_sources: list = []
        if self.offer is None or self.answer is None:
            return
        for flow in self.flows:
            src, dst = flow.src, flow.dst
            if dst.address == self.answer.address and dst.port == self.answer.port:
                self.out_to_answer += flow.packets
            elif src.port == self.offer.port and src.address == self.offer.address:
                self.out_elsewhere += flow.packets
            if dst.port == self.offer.port and dst.address == self.offer.address:
                self.in_to_us += flow.packets
                if src.address == self.answer.address:
                    self.in_from_answer += flow.packets
                else:
                    self.in_other_sources.append(src.address)


def media_reasoning(d: Diagnosis, run: CallRun, facts: MediaFacts, *, one_way: bool) -> tuple:
    """Attribute a one-way or missing-media call. Returns (side, confidence)."""
    red = d.red
    reasoning: list = []
    distinguish: list = []
    offer, answer = facts.offer, facts.answer
    side, confidence = UNKNOWN, LOW
    if answer is None:
        reasoning.append("The answer SDP is not in the softphone log, so where the far end asked for RTP is unknown.")
        d.gap("answer SDP not available (no softphone log); media addressing could not be checked")
        return side, confidence, reasoning, distinguish
    answer_where = red.hostport(answer.address, answer.port)
    direction_note = ""
    if answer.direction in ("sendonly", "inactive") or answer.port == 0:
        reasoning.append(
            f"The answer SDP set direction {answer.direction or 'port 0'}, so the far end itself said it would not receive audio."
        )
        return THEIR, HIGH, reasoning, distinguish
    if facts.have_flows and offer is not None:
        if facts.out_to_answer:
            reasoning.append(
                f"Our RTP did go to the address the answer SDP named ({answer_where}): {facts.out_to_answer} packets in the capture."
            )
        elif facts.out_elsewhere:
            reasoning.append(
                f"Our RTP did not go to {answer_where}; the capture shows {facts.out_elsewhere} packets from our port to another destination."
            )
            side, confidence = OUR, MEDIUM
        else:
            reasoning.append(f"The capture shows no RTP from us to {answer_where}.")
        if facts.in_to_us:
            reasoning.append(
                f"{facts.in_to_us} RTP packets reached our port {offer.port}, {facts.in_from_answer} of them from the address the SDP named."
            )
        else:
            reasoning.append(f"Nothing arrived at our RTP port {offer.port} in the capture.")
        if facts.in_other_sources and not facts.in_from_answer:
            reasoning.append(
                "RTP reached our port from a different source address than the SDP named, which fits a media relay or NAT rewriting the source."
            )
            side, confidence = NETWORK, MEDIUM
    elif run.has_capture:
        flt = str(run.result.get("captureFilter") or run.plan.get("capture_filter") or "")
        sent = run.softphone.get("rtp_tx_packets") or 0
        if flt and answer.address and answer.address not in flt:
            reasoning.append(
                f"The capture holds none of the RTP: its filter reads {flt} and does not name the media address {red.addr(answer.address)}, so RTP to or from it was never recorded."
            )
            d.gap("the capture filter does not cover the media address; RTP direction rests on the softphone's own packet counters")
        elif sent:
            reasoning.append("The softphone counted RTP out but the capture holds no RTP the ladder reader could decode, so per-address counts are not available.")
            d.gap("no RTP flows could be read from the capture; relying on the softphone's packet counters")
        else:
            reasoning.append("The capture holds no RTP the ladder reader could decode, so per-address counts are not available.")
            d.gap("no RTP flows could be read from the capture; relying on the softphone's packet counters")
    else:
        reasoning.append("There is no capture in this run, so RTP addresses were not checked.")
        d.gap("no capture.pcap; RTP direction rests on the softphone's own counters")
    private_offer = offer is not None and is_private(offer.address)
    answer_private = is_private(answer.address)
    target_public = run.host is not None and not is_private(run.host) and not is_loopback(run.host)
    if answer_private and target_public:
        reasoning.append(
            f"The answer SDP advertises a private address ({answer_where}) while signaling reached a public one: the far end is "
            "behind NAT or does not rewrite its SDP."
        )
        side, confidence = THEIR, MEDIUM
    elif run.result.get("networkMode") == "private" and not run.loopback_target:
        reasoning.append(
            "The call left a private network namespace through the container runtime's NAT"
            + (f" and our offered address was private ({red.addr(offer.address)})" if private_offer else "")
            + ", so a NAT mapping that the far end cannot match is possible."
        )
        if side == UNKNOWN:
            side, confidence = NETWORK, LOW
    elif run.loopback_target:
        reasoning.append("The target is a loopback address, so no NAT can be involved.")
        if side == UNKNOWN and facts.out_to_answer:
            side, confidence = THEIR, MEDIUM
            reasoning.append("We sent RTP where we were told to and received none: the far end accepted the call but sent no media.")
        elif side == UNKNOWN and (run.softphone.get("rtp_tx_packets") or 0) > 0 and run.softphone.get("rtp_rx_packets") == 0:
            side, confidence = THEIR, LOW
            reasoning.append("The softphone's counters show RTP sent and none received, and nothing between us and a loopback target can drop it: the far end sent no media.")
    elif side == UNKNOWN and facts.out_to_answer and not facts.in_to_us:
        side, confidence = THEIR, LOW
        reasoning.append(
            "No NAT is evident, we sent RTP where the SDP said, and none returned; the far end is the more likely place for the fault, but this capture cannot rule out a firewall dropping inbound RTP."
        )
    distinguish.append(
        "Ask the owner whether their media server logged RTP from our address and port (arrived and was dropped, or never arrived)."
    )
    if one_way:
        distinguish.append(
            "Run once more with the other G.711 codec: a codec the far end cannot play often looks like one-way audio."
        )
    d.gap("the capture is scoped to approved addresses; RTP from other sources would not be recorded")
    return side, confidence, reasoning, distinguish


# ---------------------------------------------------------------------------
# Verdict handlers. Each sets outcome, stage, attribution, and next steps.


def _step_common(d: Diagnosis, run: CallRun, *, ladder_html: bool = True) -> None:
    d.step("Draw the call ladder from the recorded capture or softphone log.", run.cmd_ladder())
    if ladder_html:
        d.step("Save a self-contained HTML ladder to attach to the owner report.", run.cmd_ladder(html=True))
    d.step("Read the reference text for this verdict.", run.cmd_explain())


def _profile_note(run: CallRun) -> str:
    return "" if run.profile_known else " Replace PROFILE.yaml with the profile this run used (its name is recorded in result.json)."


def h_pass(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    soft = run.softphone
    oracle = run.result.get("oracle") or {}
    summary = oracle.get("summary") or {}
    d.outcome(
        f"The call passed: answered {soft.get('final_status')} after {_num((soft.get('setup') or {}).get('inviteToAnswerSeconds'))} s, "
        f"{soft.get('rtp_tx_packets')} RTP packets out and {soft.get('rtp_rx_packets')} in, codec {soft.get('codec')}."
    )
    d.stage("none", "the run completed through teardown")
    d.attribute(NONE, HIGH, ["The oracle found no failing assertion and RTP flowed both ways."])
    unknown = oracle_unknown(run)
    if summary:
        d.evidence("oracle", f"{summary.get('pass')} pass, {summary.get('fail')} fail, {summary.get('unknown')} unknown")
    if unknown:
        d.evidence("not judged", "the oracle did not judge: " + ", ".join(unknown) + " (nothing was configured for them)")
    d.gap("a pass proves one call path worked once; it is not a quality measurement")
    journal = run.result.get("journalCommand")
    if isinstance(journal, list) and journal and journal[:2] == ["./bin/sippycup", "journal"]:
        from .core import command

        d.step("Record this call in the engagement journal.", command(*journal[1:]))
    d.step("Draw the ladder of the passing call (keep it as the reference for comparisons).", run.cmd_ladder())


def h_preflight(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    detail = str((run.result.get("preflight") or {}).get("detail") or run.preflight_file.get("detail") or "")
    lowered = detail.lower()
    tls = run.transport == "tls" and ("tls" in lowered)
    d.evidence("preflight", f"OPTIONS preflight failed: {detail or 'no detail recorded'}")
    if tls:
        h_tls_preflight(d, run, detail, ladder)
        return
    d.stage("preflight", "the single OPTIONS request got no usable reply, so no call was placed")
    where = f"{run.transport.upper()} {run.host}:{run.target.get('port')}"
    sibling = run.siblings_other_transport()
    if "connection_refused" in lowered or "refused" in lowered:
        d.outcome(f"Nothing is listening: the target refused the {where} connection, so no call was placed.")
        d.attribute(
            THEIR, MEDIUM,
            ["The host answered with a refusal (TCP reset or ICMP port unreachable), so it is reachable and nothing accepts connections on that port and transport."],
            ["A wrong port or transport in the profile looks the same: confirm the signaling port and transport with the owner."],
        )
    elif "no_response" in lowered or "timeout" in lowered:
        d.outcome(f"No reply: nothing answered the OPTIONS request to {where} within the timeout, so no call was placed.")
        d.attribute(
            UNKNOWN, LOW,
            [
                "A silent target is consistent with the service being down, a firewall dropping our source, a wrong port or transport, or a routing fault; the capture holds only our own request.",
                "Because there was no reply at all, nothing here points at one side.",
            ],
            [
                "Preflight the same host over another approved transport: a reply there means the host is up and this port or transport is the problem.",
                "Ask the owner whether our source address is allowed through their firewall and whether the service is up.",
            ],
        )
    elif "unreachable" in lowered or "resolution" in lowered:
        d.outcome(f"Unreachable: the OPTIONS request to {where} could not be delivered, so no call was placed.")
        d.attribute(NETWORK, MEDIUM, ["The host or route is unreachable from the toolbox network."], ["Check the toolbox host's own connectivity and routing to the approved address."])
    else:
        d.outcome(f"The OPTIONS preflight to {where} did not meet its expectation, so no call was placed.")
        status = _status_in(detail)
        if status is not None and status >= 400:
            d.attribute(THEIR, MEDIUM, [f"The far end answered {status}: it is reachable and chose to refuse the preflight."], ["Ask the owner whether OPTIONS from our source address is allowed."])
        else:
            d.attribute(UNKNOWN, LOW, ["The preflight detail does not say whether the far end or the path failed."])
    for item in sibling:
        d.step(
            f"Preflight over the other approved {item['transport'].upper()} profile (a reply tells you the host is up and this transport is the problem).",
            run.cmd_preflight(item["host"], item["port"], item["transport"], item["tlsServerName"], item["tlsCaFile"]),
        )
    d.step("Repeat the same single preflight to see whether the failure is stable.", run.cmd_preflight(run.host, run.target.get("port"), run.transport))
    if not sibling:
        d.stop_and_ask(
            "If a repeat gets the same result, stop and ask the owner to confirm the signaling address, port, and transport and that our source address is allowed; this profile approves no other transport to try."
        )
    d.step("Check the profile still passes the gate (no traffic).", run.cmd_rehearse())
    d.step("Read the reference text for this verdict.", run.cmd_explain())


def _status_in(text: str) -> Optional[int]:
    import re

    match = re.search(r"SIP/2\.0 (\d{3})", text)
    return int(match.group(1)) if match else None


def tls_alerts(ladder: Lazy) -> list:
    """(sender role, previous record) for each TLS alert the ladder drew."""
    document = ladder.document()
    out: list = []
    for section in (document or {}).get("sections") or []:
        columns = section.get("columns") or []
        previous = None
        for event in section.get("events") or []:
            label = str(event.get("label", ""))
            if "alert" in label.lower() and event.get("type") != "media":
                try:
                    role = (columns[event["from"]].get("roles") or ["?"])[0]
                except (IndexError, KeyError, TypeError):
                    role = "?"
                out.append((role, previous))
            previous = label
    return out


def h_tls_preflight(d: Diagnosis, run: CallRun, detail: str, ladder: Optional[Lazy] = None) -> None:
    tls = run.result.get("tls") or {}
    name = tls.get("serverName")
    trust = tls.get("trust")
    ca = tls.get("caFile")
    lowered = detail.lower()
    d.stage("TLS", "the TLS handshake or certificate verification failed before any SIP request was sent")
    d.evidence("TLS trust", ("trust anchor: CA file " + str(ca) if ca else "trust anchor: the system store") + f"; reviewed server name {name}")
    side, confidence = UNKNOWN, LOW
    reasoning: list = []
    distinguish: list = []
    alerts = tls_alerts(ladder) if ladder is not None else []
    for role, previous in alerts[:2]:
        who = "us (the caller), which is how a client rejects a certificate it cannot verify" if role == "caller" else "the far end"
        d.evidence("TLS alert", f"sent by {who}" + (f", right after: {previous}" if previous else ""))
    if "hostname mismatch" in lowered or "not valid for" in lowered:
        d.outcome(
            f"TLS verification failed: the server's certificate is not valid for the reviewed name {name}; no SIP was sent."
        )
        reasoning = [
            "The handshake completed far enough to receive a certificate, and the certificate does not name the server name in our profile.",
            "Either the profile's tls_server_name is not the name this service presents, or the service presents the wrong certificate.",
        ]
        distinguish = [
            "Ask the owner for the exact server name (certificate SAN) they publish for this endpoint, and compare it with the profile's tls_server_name.",
            "If the name in the profile came from the owner's scope answers, the certificate is wrong on their side; if it was typed by hand, the profile is.",
        ]
        side = OUR
        confidence = LOW
    elif "local issuer" in lowered or "self signed" in lowered or "self-signed" in lowered or "unable to verify" in lowered or "untrusted" in lowered:
        d.outcome("TLS verification failed: the server certificate does not chain to the trust anchor in the profile; no SIP was sent.")
        reasoning = [
            "The certificate chain could not be built to the CA we trust"
            + (f" ({ca})" if ca else " (the system store)")
            + ": either our trust anchor is not the issuer of their certificate, or their server does not send the intermediate certificates.",
        ]
        distinguish = [
            "Ask the owner which CA signs the endpoint certificate and compare its fingerprint with the CA file the profile names (the run records its SHA-256).",
            "Never fall back to --tls-unverified: it hides exactly this problem.",
        ]
        side = OUR if trust == "file" else UNKNOWN
        confidence = LOW
    elif "expired" in lowered or "not yet valid" in lowered:
        d.outcome("TLS verification failed: the server certificate is outside its validity period; no SIP was sent.")
        reasoning = ["The certificate dates do not cover now. The toolbox clock is the only thing on our side that can be wrong."]
        distinguish = ["Compare the toolbox host clock with a trusted time source; if it is right, the certificate has expired on their side."]
        side, confidence = THEIR, MEDIUM
    elif "alert" in lowered or "handshake" in lowered or "protocol" in lowered or "version" in lowered:
        d.outcome("The TLS handshake failed before verification completed; no SIP was sent.")
        reasoning = ["The server ended or rejected the handshake (an alert, a protocol or cipher mismatch, or a non-TLS service on this port)."]
        distinguish = ["Preflight the same host over plain UDP or TCP if the profile set approves it: a reply there shows the host is up and TLS on this port is the problem."]
        side, confidence = UNKNOWN, LOW
    else:
        d.outcome("TLS failed before any SIP request was sent.")
        reasoning = ["The preflight detail does not name the exact verification error."]
    d.attribute(side, confidence, reasoning, distinguish)
    d.step(
        "Repeat only the TLS preflight with the profile's reviewed name and CA to see the exact error again.",
        run.cmd_preflight(run.host, run.target.get("port"), "tls", name, ca),
    )
    for item in run.siblings_other_transport():
        d.step(
            f"Preflight the other approved {item['transport'].upper()} profile to see whether the host answers at all.",
            run.cmd_preflight(item["host"], item["port"], item["transport"], item["tlsServerName"], item["tlsCaFile"]),
        )
    d.stop_and_ask(
        "Do not retry the call until the name and CA are confirmed: ask the owner for the endpoint's certificate server name and issuing CA."
    )
    d.step("Check the profile (no traffic).", run.cmd_rehearse())
    d.step("Read the reference text for TLS failures.", f"./bin/sippycup explain call.tls-not-verified")


def h_preflight_failed(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    h_preflight(d, run, ladder)


def h_tls_not_verified(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    tls = run.result.get("tls") or {}
    detail = str(tls.get("softphoneDetail") or "")
    d.evidence("PJSUA TLS", detail or "PJSUA reported TLS verification did not succeed")
    h_tls_preflight(d, run, detail or "tls verification failed", ladder)


def h_tls_pinning(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    d.outcome("PJSUA was not started: the reviewed TLS name could not be pinned to the literal address in the private namespace.")
    d.stage("TLS", "name pinning is proved before PJSUA starts; it failed, so nothing was sent by PJSUA")
    d.attribute(
        OUR, MEDIUM,
        ["Name pinning happens inside the toolbox container (a private namespace with a hosts file), not on the network, so this points at the toolbox environment."],
        ["Run the toolbox doctor to check the image and runtime."],
    )
    d.step("Check the toolbox image and runtime.", "./bin/sippycup doctor")
    d.step("Check the profile's server name (no traffic).", run.cmd_rehearse())
    d.step("Read the reference text.", run.cmd_explain())


def h_registration(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    soft = run.softphone
    status = soft.get("registration_status")
    d.stage("registration", "REGISTER did not succeed, so the driver quit before dialing")
    registers = run.outbound("REGISTER")
    authed = [m for m in registers if m.has_auth]
    account = run.account
    if status is None:
        d.outcome("Registration got no answer: no final response to REGISTER, so no call was placed.")
        d.attribute(
            UNKNOWN, LOW,
            ["The OPTIONS preflight succeeded but the registrar sent no final response to REGISTER: the registrar, a firewall treating REGISTER differently, or a lost response."],
            ["Retry without registering only if the platform does not need a REGISTER for this account (the owner's scope answers say)."],
        )
        d.step("Try the call without REGISTER (only if the platform does not require it).", run.cmd_call(no_register=True))
    elif status in (401, 407):
        if account is None:
            d.outcome(f"Registration was challenged ({status}) and no credentials were given, so no call was placed.")
            d.attribute(OUR, HIGH, ["The registrar asked for credentials and this run supplied none (no --username)."])
            d.step(
                "Repeat with the account from the owner's scope answers (replace USERNAME and the secret source).",
                _with_account(run),
            )
        elif len(authed) >= 1:
            d.outcome(f"Registration was rejected ({status}) after our credentials were presented: the account or password was not accepted.")
            d.attribute(
                OUR, MEDIUM,
                [
                    "The registrar challenged, we answered with the account's credentials, and it challenged again: the password (or username or realm) we sent was not accepted.",
                    "It could also be an account that exists on their side but is disabled, not provisioned for this source address, or locked.",
                ],
                [
                    "Ask the owner to confirm the username, the realm, and that the account is active for registrations from our source address.",
                    "Do not try other passwords: each attempt can count toward a lockout.",
                ],
            )
            d.stop_and_ask(
                "Stop and ask the owner to confirm the account and password before any retry; repeated wrong passwords can lock the account and are noticed as an attack."
            )
        else:
            d.outcome(f"Registration was rejected ({status}) and the log shows no authenticated REGISTER.")
            d.attribute(UNKNOWN, LOW, ["The softphone log does not show a REGISTER that carried credentials, so it is unclear whether they were sent."])
    elif status == 403:
        d.outcome("Registration was refused with 403 Forbidden: the registrar understood the request and refuses this identity or source.")
        d.attribute(
            THEIR, MEDIUM,
            ["403 is a policy decision (an ACL, a disabled or barred account, a source address the registrar does not allow), not a credential mismatch."],
            ["Ask the owner whether this account may register from our source address."],
        )
        d.stop_and_ask("Stop and ask the owner: a 403 will not change on retry, and retrying with the same identity only adds noise.")
    elif status == 404:
        d.outcome("Registration got 404: the registrar does not know this account or domain.")
        d.attribute(UNKNOWN, LOW, ["Either the username or realm we sent is wrong, or the account was never provisioned on their side."], ["Ask the owner to confirm the exact username and domain."])
        d.stop_and_ask("Stop and ask the owner to confirm the account; do not guess other usernames.")
    elif status == 429:
        d.outcome("Registration was rate limited (429).")
        d.attribute(THEIR, HIGH, ["The far end told us to slow down."])
        d.stop_and_ask("Stop and ask the owner before sending anything else; wait for any Retry-After they sent.")
    else:
        d.outcome(f"Registration failed with status {status}, so no call was placed.")
        d.attribute(THEIR if status >= 500 else UNKNOWN, LOW, [f"The registrar answered {status}."])
        d.step("Read the reference text for this verdict.", run.cmd_explain())
    d.step("Draw the ladder to see the REGISTER exchange.", run.cmd_ladder())
    d.step("Read the reference text for this verdict.", run.cmd_explain())
    d.gap("credentials, nonces and realms are never shown; only the number of REGISTER requests and whether they carried an Authorization header")
    if registers:
        d.evidence("REGISTER requests", f"{len(registers)} sent, {len(authed)} with an Authorization header")


def _with_account(run: CallRun) -> Optional[str]:
    words = run.call_words()
    if not words:
        return None
    from .core import command

    words = [w for w in words if w != "--no-register"]
    words += ["--username", "USERNAME", "--secret-env", "SIP_PASSWORD"]
    return command(*words, practice=run.practice)


def h_not_placed(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    d.outcome("The softphone did not place a call.")
    d.stage("INVITE", "PJSUA did not get as far as dialing")
    d.attribute(OUR, LOW, ["No INVITE left the toolbox; the softphone driver stopped first. See the softphone log."])
    d.step("Retry once with the same flags.", run.cmd_call())
    d.step("Read the reference text.", run.cmd_explain())


def h_invite_reject(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    status = run.final_status
    d.stage("INVITE", f"the INVITE was answered {status} and no call was established")
    retry_after = [value for label, value in run.far_end_headers() if label.startswith("Retry-After")]
    verdict = run.verdict
    account = run.account
    if verdict == "call-busy":
        d.outcome(f"The far end rejected the call with {status} (busy); the destination exists and refused to ring.")
        d.attribute(THEIR, HIGH, ["486 or 600 is the callee's state, not a signaling fault."])
        d.step("Try again later, or dial another approved destination.", run.cmd_call())
    elif verdict == "call-declined":
        d.outcome("The far end explicitly declined the call (603).")
        d.attribute(THEIR, HIGH, ["603 is a deliberate refusal by the destination or its policy."], ["Ask the owner whether this destination should accept test calls from our account."])
        d.stop_and_ask("Ask the owner whether this destination is meant to accept the call before retrying.")
    elif verdict == "call-forbidden":
        d.outcome("The far end answered 403 Forbidden: it understood the request and refuses it.")
        d.attribute(
            THEIR, MEDIUM,
            ["403 is a policy decision: an ACL, a barred destination, or an identity that may not call here. The call was well formed and reached the far end."],
            ["Ask the owner whether this account may dial this destination from our source address."],
        )
        d.stop_and_ask("Stop and ask the owner: retrying with the same identity will not help.")
    elif verdict == "call-not-found":
        d.outcome(f"The far end answered {status}: no such destination.")
        d.attribute(
            UNKNOWN, LOW,
            ["The platform was reachable and understood the request, but has no route for the dialed user: most often the destination we dialed is wrong, occasionally their dial plan does not yet include it."],
            ["Ask the owner for the exact test destination and compare it with this run's --dial."],
        )
        d.stop_and_ask("Ask the owner for the correct test destination before retrying; do not try other numbers by guessing.")
    elif verdict == "call-unavailable":
        d.outcome(f"The far end answered {status}: the service or callee is temporarily unavailable.")
        d.attribute(THEIR, MEDIUM, [f"{status} means the far end or something behind it cannot take the call now."], ["A repeat tells you whether it is momentary; a persistent 503 is an owner question."])
        d.step("Wait, then retry once (slowly).", run.cmd_call())
        d.stop_and_ask("If a second attempt also gets 503, stop and tell the owner their service is refusing calls.")
    elif verdict == "call-rate-limited":
        d.outcome("The far end answered 429 Too Many Requests: a rate limit or protection rule is throttling us.")
        d.attribute(THEIR, HIGH, ["429 is the far end's own rate limit; our traffic was one call, so the limit is aggressive or already tripped by earlier traffic."])
        d.stop_and_ask("Stop and ask the owner now. Do not retry: more attempts can extend a block." + (" The response named Retry-After: " + ", ".join(retry_after) + "." if retry_after else ""))
    elif verdict == "call-auth-failed":
        if account is None:
            d.outcome(f"The far end challenged the INVITE ({status}) and this run supplied no credentials.")
            d.attribute(OUR, HIGH, ["No --username was given, so there was nothing to answer the challenge with."])
            d.step("Repeat with the account from the owner's scope answers (replace USERNAME and the secret source).", _with_account(run))
        else:
            d.outcome(f"The far end answered {status} to the INVITE after our credentials were presented.")
            d.attribute(
                UNKNOWN, LOW,
                ["The credentials may be wrong for this destination, or the account may not be allowed to place calls here even though it could register."],
                ["Ask the owner whether this account may dial this destination."],
            )
            d.stop_and_ask("Stop and ask the owner to confirm the account may place calls to this destination.")
    elif verdict == "call-media-not-acceptable":
        h_488(d, run)
    elif verdict == "call-redirected":
        d.outcome(f"The far end answered {status}, a redirect; redirects are never followed.")
        d.attribute(THEIR, MEDIUM, ["The platform wants us to call somewhere else, and that place may be outside the approved scope."])
        d.stop_and_ask("Ask the owner whether the redirect target is in scope; approve and profile it separately if so.")
    else:
        group = (status or 0) // 100
        d.outcome(f"The far end rejected the call with final status {status}.")
        d.attribute(THEIR if group in (5, 6) else UNKNOWN, LOW, [f"A {group}xx final status with no more specific verdict."])
        d.step("Read the reference text for this verdict.", run.cmd_explain())
    d.step("Draw the ladder around the rejection.", run.cmd_ladder())
    d.step("Read the reference text for this verdict.", run.cmd_explain())


def h_488(d: Diagnosis, run: CallRun) -> None:
    phone = run.plan_phone
    exclusive = phone.get("codec_offer") == "only"
    codecs = list(phone.get("codecs") or [])
    srtp = (phone.get("srtp") or {}).get("mode") or "off"
    d.outcome(
        "The far end rejected the offered media (488): "
        + (f"the offer listed only {', '.join(codecs)}" if exclusive else "it accepted none of the offered formats")
        + (f" with SRTP {srtp}" if srtp != "off" else "")
        + "; no call was established."
    )
    d.stage("INVITE", "the far end rejected our SDP offer (488)")
    reasoning: list = []
    distinguish: list = []
    if exclusive:
        reasoning.append(
            f"You asked for {', '.join(codecs)} alone, so the far end's refusal is exactly its answer to that one codec: its policy does not allow it for this account or route."
        )
        side, confidence = THEIR, MEDIUM
        distinguish.append("Repeat with an approved G.711 codec (PCMU or PCMA) alone: success shows the refusal was about the codec.")
    elif srtp == "off":
        reasoning.append(
            "The default offer already contained PCMU and PCMA, which almost every platform accepts, so a codec list is the less likely cause. "
            "The far end may require SRTP, or object to another media attribute of the offer."
        )
        side, confidence = UNKNOWN, LOW
    else:
        reasoning.append(f"We offered SRTP ({srtp}); the far end refused the secure offer.")
        side, confidence = THEIR, MEDIUM
    if run.srtp_approved and srtp != "mandatory" and not exclusive:
        distinguish.append("Repeat with --srtp mandatory (the profile approves SRTP): success shows the account requires encryption.")
    d.attribute(side, confidence, reasoning, distinguish)
    if exclusive:
        for codec in run.alternative_codecs()[:2]:
            d.step(f"Offer {codec} alone (what the profile approves) to test whether the refusal was about the codec.", run.cmd_call(codec=[codec]))
    if srtp == "off" and run.srtp_approved and not exclusive:
        d.step("Offer SRTP (the profile approves it) in case the account requires encryption.", run.cmd_call(srtp="mandatory"))
    if not d.data["nextSteps"]:
        d.stop_and_ask("Ask the owner which media security and codec policy this account requires; the profile approves no variation of the offer to try.")


def h_not_answered(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    soft = run.softphone
    inv = run.invite_times()
    provisional = (run.result.get("setup") or {}).get("provisional") or ([inv["provisionalStatus"]] if inv.get("provisionalStatus") else [])
    timeout = run.plan_phone.get("answer_timeout_seconds")
    d.stage("answer", "the INVITE was accepted but no final answer came within the answer timeout")
    ringing = bool(provisional)
    d.outcome(
        f"The call was not answered within {timeout} s"
        + (f": {', '.join(str(p) for p in provisional)} was received, then silence" if ringing else ": no provisional response was received")
        + "; the caller cancelled."
    )
    retrans = _invite_retransmissions(ladder)
    if ringing:
        d.attribute(
            THEIR, MEDIUM,
            [
                f"The far end sent {provisional[0]} and never a final response, so it accepted the INVITE and is ringing, waiting, or has a dialplan that does not pick up.",
                "The signaling path works: the far end responded to our INVITE.",
            ],
            [
                "A longer --answer-timeout tells you whether it answers late (a slow-setup verdict) or never.",
                "Ask the owner whether this destination is meant to answer.",
            ],
        )
        if timeout and int(timeout) < MAX_ANSWER_TIMEOUT:
            longer = min(MAX_ANSWER_TIMEOUT, max(int(timeout) * 2, int(timeout) + 15))
            d.step(f"Wait longer for an answer ({longer} s; the limit is {MAX_ANSWER_TIMEOUT} s).", run.cmd_call(answer_timeout=longer))
    else:
        reasoning = ["No provisional or final response to the INVITE reached the softphone, although the OPTIONS preflight succeeded."]
        if retrans:
            reasoning.append(f"The capture shows the INVITE sent {retrans} extra times (retransmissions), so it was not answered at transaction level.")
        d.attribute(
            UNKNOWN, LOW, reasoning,
            [
                "A firewall or proxy that answers OPTIONS but drops INVITE is possible, as is a lost response.",
                "Try the same call without REGISTER if the platform does not need it, to separate an authentication path from the dial path.",
            ],
        )
        d.step("Try without REGISTER (only if the platform does not require it).", run.cmd_call(no_register=True))
        d.stop_and_ask("If a repeat also gets no response to the INVITE, ask the owner whether INVITEs from our source address reach their server.")
    d.step("Draw the ladder to see what the far end sent.", run.cmd_ladder())
    d.step("Read the reference text for this verdict.", run.cmd_explain())


def _invite_retransmissions(ladder: Lazy) -> int:
    document = ladder.document()
    if not document:
        return 0
    total = 0
    for section in document.get("sections") or []:
        if section.get("kind") == "call":
            total += (section.get("counts") or {}).get("retransmissions", 0)
    return total


def h_slow_setup(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    seconds = (run.result.get("setup") or {}).get("seconds")
    d.outcome(f"The call worked but was answered {_num(seconds)} s after the INVITE, later than the 5 s setup window.")
    d.stage("answer", "answer later than the oracle's setup window")
    d.attribute(
        THEIR, MEDIUM,
        ["The far end rang for a long time before answering; the signaling and media that followed were healthy, and only the setup-time assertion failed."],
        ["Ask the owner whether a delay of this length is expected for this destination (an IVR, a queue, or a slow dialplan)."],
    )
    d.step("If the delay is expected nothing needs fixing; keep the call as is.", None, kind="note")
    d.step("Draw the ladder to see the provisional responses and the answer.", run.cmd_ladder())
    d.step("Read the reference text for this verdict.", run.cmd_explain())


def h_one_way(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    soft = run.softphone
    nat = run.verdict == "possible-nat-one-way-media"
    d.stage("media", "the call was answered and RTP went out but none came back")
    facts = MediaFacts(run, ladder)
    side, confidence, reasoning, distinguish = media_reasoning(d, run, facts, one_way=True)
    d.outcome(
        f"One-way media: the call was answered ({soft.get('final_status')}), we sent {soft.get('rtp_tx_packets')} RTP packets and received "
        f"{soft.get('rtp_rx_packets')}"
        + (" (a NAT in the path is possible)." if nat else ".")
    )
    if facts.have_flows:
        d.evidence(
            "RTP per direction (capture)",
            f"out to the SDP address {facts.out_to_answer} packets; in to our port {facts.in_to_us} packets",
        )
    d.attribute(side, confidence, reasoning, distinguish)
    for codec in run.alternative_codecs()[:1]:
        d.step(f"Try the other G.711 codec ({codec}) in case the far end cannot play the first.", run.cmd_call(codec=[codec]))
    d.step("Draw the ladder to see the RTP rows against the SDP addresses.", run.cmd_ladder())
    d.step("Read the reference text for this verdict.", run.cmd_explain())


def h_silent_audio(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    rec = run.result.get("recording") or {}
    soft = run.softphone
    d.stage("media", "RTP flowed both ways but the audio is digital silence")
    d.outcome(
        f"The media path works but the audio is silent: {soft.get('rtp_tx_packets')} RTP packets out, {soft.get('rtp_rx_packets')} in, "
        f"and the recording's peak is {rec.get('peak')} (silence threshold {rec.get('silence_threshold_peak')})."
    )
    d.evidence("recording", f"peak {rec.get('peak')} ({rec.get('peak_dbfs')} dBFS), rms {rec.get('rms_dbfs')} dBFS, {rec.get('seconds')} s")
    d.attribute(
        THEIR, MEDIUM,
        [
            "Packets arrived in both directions, so the network and the addressing work; the payloads they carried are silence.",
            "The far end returns a silent stream: an application that plays nothing, a codec it cannot decode, or a media bridge that mutes.",
        ],
        [
            "If the destination is not an echo or playback endpoint (an IVR that is waiting for input), silence is its normal behavior; ask the owner what this destination plays.",
            "A different codec may change the result if the far end mis-decodes one.",
        ],
    )
    for codec in run.alternative_codecs()[:1]:
        d.step(f"Try the other G.711 codec ({codec}).", run.cmd_call(codec=[codec]))
    d.step("Draw the ladder to confirm RTP in both directions.", run.cmd_ladder())
    d.step("Read the reference text for this verdict.", run.cmd_explain())


def h_peer_hangup(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    soft = run.softphone
    planned = (run.plan_phone.get("duration_seconds") or {}).get("effective")
    d.stage("teardown", "the far end sent BYE before the planned duration")
    d.outcome(f"The far end hung up after {_num(soft.get('connected_seconds'), 1)} s of a planned {planned} s call.")
    d.attribute(
        THEIR, MEDIUM,
        [
            "The BYE came from the far end while media was healthy, so the platform ended the call: an IVR that finished, a session or max-duration timer, or a fault.",
            "A BYE time that is a round number (30 s, 60 s, 90 s) points at a timer or policy; a short, variable time points at an application ending the call.",
        ],
        ["Repeat once with --duration shorter than the BYE time to see whether the call then ends by our own hang-up."],
    )
    connected = soft.get("connected_seconds")
    if isinstance(connected, (int, float)) and connected > 1.5:
        d.step(
            f"Repeat with a duration shorter than the far end's hang-up time ({_num(connected, 1)} s) to see whether the call then ends by our own BYE.",
            run.cmd_call(duration=max(1, int(connected) - 1)),
        )
    d.step("Draw the ladder to see who sent BYE and when.", run.cmd_ladder())
    d.step("Read the reference text for this verdict.", run.cmd_explain())


def h_oracle_fail(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    soft = run.softphone
    failing = oracle_lines(run)
    d.stage("oracle", "the call was answered but the oracle's assertions failed")
    d.outcome(f"The call was answered but the oracle failed {len(failing) or 'some'} assertion(s): the signaling worked, the media did not meet the expected shape.")
    for line in failing:
        d.evidence("oracle assertion", line)
    early = bool((run.result.get("setup") or {}).get("earlyMedia"))
    text = "".join(failing)
    timing_only = bool(failing) and all("media.timing" in line for line in failing)
    if early:
        d.attribute(
            THEIR, LOW,
            [
                "The far end sent 183 Session Progress with early media. The oracle counts RTP before the 200 OK, and servers such as Asterisk re-base the RTP timestamp at the answer, which shows as a timestamp jump or jitter; this is usually benign for audio.",
                "The numbers above are the oracle's, not a listening test.",
            ],
            ["Listen to heard.wav in the run directory: if the audio is intact, the call is fine and the early-media timing is only what the oracle flagged."],
        )
    elif "lost" in text or "sequence" in text:
        d.attribute(
            UNKNOWN, LOW,
            ["The oracle describes what the capture shows (loss, reordering, or jumps), not why. Loss on the path, a far end that sends irregularly, and a capture that missed packets are all possible."],
            ["Compare the per-stream numbers: loss only in the stream from the far end points at their side or the path to us; both streams point at the path or capture."],
        )
    elif timing_only:
        d.attribute(THEIR, MEDIUM, ["Only setup timing failed; the answer came late."])
    else:
        d.attribute(UNKNOWN, LOW, ["An oracle failure describes the media or signaling observed, not the cause."])
    d.step("Draw the ladder to see the media rows and their timing.", run.cmd_ladder())
    d.step("Read the reference text for this verdict.", run.cmd_explain())


def h_srtp(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    srtp = run.result.get("srtp") or {}
    status = run.final_status
    d.stage("INVITE", "SRTP was mandatory and the far end did not negotiate it")
    d.evidence("SRTP", f"mode {srtp.get('mode')}; offer profile {srtp.get('offerProfile')}, answer profile {srtp.get('answerProfile')}")
    d.outcome(
        "SRTP was mandatory but the far end did not negotiate it"
        + (f" (final status {status})" if status is not None else "")
        + "; no protected media was exchanged."
    )
    exclusive = run.plan_phone.get("codec_offer") == "only"
    reasoning = [
        "PJSUA never falls back to plain RTP when SRTP is mandatory, so the far end either refused the secure offer or answered with plain RTP.",
    ]
    distinguish = []
    if status == 488 and exclusive:
        reasoning.append(
            "A 488 here may be about the codec rather than SRTP: this run offered only "
            + ", ".join(run.plan_phone.get("codecs") or [])
            + ". Repeating with an approved G.711 codec separates the two."
        )
        distinguish.append("Repeat with --srtp mandatory and a G.711 codec: success means the codec caused the 488; the same 488 means SRTP.")
        side, confidence = UNKNOWN, LOW
    else:
        reasoning.append("This shows the far end's SRTP policy for this account and destination.")
        distinguish.append("Ask the owner whether SDES-SRTP is supported for this account and which key-exchange they expect (SDES versus DTLS-SRTP).")
        side, confidence = THEIR, MEDIUM
    d.attribute(side, confidence, reasoning, distinguish)
    if exclusive:
        for codec in run.alternative_codecs()[:1]:
            d.step(f"Repeat with SRTP mandatory and {codec} (separates a codec refusal from an SRTP refusal).", run.cmd_call(srtp="mandatory", codec=[codec]))
    d.step("Compare with the plain-RTP baseline (the profile need not approve SRTP for this).", run.cmd_call(srtp="off"))
    d.step("Read the reference text for this verdict.", run.cmd_explain())
    d.step("Draw the ladder to compare the offer and answer media profiles.", run.cmd_ladder())


def h_codec_not_offered(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    codec = run.result.get("codec") or {}
    d.stage("answer", "the answer SDP chose a codec that was not offered")
    d.outcome("The far end answered with a codec that the offer did not contain.")
    d.evidence("codecs", f"offered {codec.get('offered')}, answered {codec.get('answered')}, unoffered {codec.get('unoffered')}")
    d.attribute(
        THEIR, HIGH,
        ["An answer must pick from the offered formats (RFC 3264 section 6); this one did not, which no setting on our side can cause."],
        ["Ask the owner whether a gateway, SBC, or transcoder rewrites SDP on this route."],
    )
    for item in run.alternative_codecs()[:1]:
        d.step(f"Offer {item} alone to see whether the far end then answers consistently.", run.cmd_call(codec=[item]))
    d.step("Draw the ladder to read the offer and the answer side by side.", run.cmd_ladder())
    d.step("Read the reference text for this verdict.", run.cmd_explain())


def h_dtmf(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    dtmf = run.result.get("dtmf") or {}
    d.stage("media", "DTMF was requested and was not carried as RFC 4733 events")
    if run.verdict == "dtmf-not-negotiated":
        d.outcome("DTMF was requested but the far end's answer has no telephone-event payload, so no digits were sent.")
        d.attribute(
            THEIR, HIGH,
            ["The answer SDP did not include telephone-event (RFC 4733); Sippycup never falls back to SIP INFO or in-band tones."],
            ["Ask the owner which DTMF method the platform expects (RFC 4733, SIP INFO, or in-band); only RFC 4733 is supported here."],
        )
        d.stop_and_ask("Ask the owner which DTMF method this platform accepts before changing anything; Sippycup only sends RFC 4733.")
    else:
        d.outcome("The digits on the wire differ from the digits requested.")
        d.attribute(
            OUR, LOW,
            ["The capture's outbound telephone-event sequence does not equal the request; this describes what the softphone sent, not how the far end interpreted it."],
            ["Check dtmf-events.txt in the run directory; a longer --dtmf-after gives the far end time to be ready."],
        )
        d.step("Repeat with more time before the first digit.", run.cmd_call())
    d.step("Read the reference text for this verdict.", run.cmd_explain())
    d.step("Draw the ladder to read the SDP.", run.cmd_ladder())


def h_scope_stop(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    scope = run.result.get("mediaScope") or {}
    soft = run.softphone
    rules = scope.get("rules") or {}
    d.stage("safety stop", "the negotiated media peer was outside the approved scope, so the call was hung up")
    if scope.get("admittedBy") and scope.get("portAdmitted") is False:
        why = "its port is outside the approved media port range"
    else:
        why = "its address is neither an approved address nor inside an owner-approved media network"
    d.outcome(f"Safety stop: the far end's media peer {d.red.text(scope.get('peer') or soft.get('media_peer'))} was refused because {why}; no media was exchanged beyond the first packets.")
    d.attribute(
        OUR, MEDIUM,
        [
            "Our approved scope is incomplete for this platform, not a platform failure: the toolbox's scope rule worked as designed. Signaling succeeded, and the far end's SDP named a media address that was never approved.",
            f"Rules in force: {len(rules.get('approvedAddresses') or [])} approved address(es), {len(rules.get('mediaNetworks') or [])} media network(s)"
            + (f", media ports {rules['mediaPorts'][0]}-{rules['mediaPorts'][1]}" if rules.get("mediaPorts") else ", no media port range")
            + ".",
        ],
        ["Only the owner can approve another media address or range; nothing on the toolbox side should widen the profile by itself."],
    )
    d.stop_and_ask(
        "Stop and ask the owner for the media-server addresses or range this platform uses (./bin/sippycup scope questions has the question sheet); do not edit the profile to admit the address yourself."
    )
    from .core import command

    d.step("Print the question sheet for the owner.", command("scope", "questions"))
    d.step(
        "See the unredacted media address (operator copy; do not paste it into the owner report).",
        run.cmd_diagnose("--show-addresses"),
    )
    d.step("Draw the ladder to see the SDP that named the address.", run.cmd_ladder())
    d.step("Read the reference text for this verdict.", run.cmd_explain())


def h_capture(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    died = run.verdict == "capture-died"
    d.stage("capture", "packet capture " + ("stopped during the run" if died else "did not start"))
    d.outcome(
        "Packet capture stopped during the run, so the evidence is not trusted and the call was stopped."
        if died else "Packet capture did not start, so nothing was sent."
    )
    d.attribute(
        OUR, HIGH,
        ["Capture runs inside the toolbox container; the platform never saw a call." if not died else "Capture runs inside the toolbox container; the call is not trusted without its evidence."],
        ["Check capture.log in the run directory and the disk space under work/."],
    )
    d.step("Check the toolbox environment and free disk space.", "./bin/sippycup doctor")
    d.step("Repeat the same call once the cause is fixed.", run.cmd_call())
    d.step("Read the reference text for this verdict.", run.cmd_explain())


def h_lapsed(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    d.stage("safety stop", "the profile's authorization expired during the run")
    d.outcome("The profile's authorization expired during the run, so the toolbox stopped before the next stage.")
    d.attribute(OUR, HIGH, ["Our authorization window ended; the toolbox re-checks it before each sending stage and stopped. This is not a platform fault."])
    d.stop_and_ask("Stop: only the owner can renew the authorization window. Do not edit valid_until yourself; get a new approval, then rehearse the profile again.")
    d.step("Check the profile (no traffic) after the owner renews it.", run.cmd_rehearse())
    d.step("Read the reference text for this verdict.", run.cmd_explain())


def h_cancelled(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    soft = run.softphone
    d.outcome(f"You interrupted the run (exit {run.result.get('exitCode')}): the call was hung up and the capture kept; no offline analysis was run.")
    if not soft or not soft.get("dialed"):
        stage = "registration" if soft.get("registration_attempted") else "preflight"
    elif soft.get("answered"):
        stage = "media"
    else:
        stage = "answer"
    d.stage(stage, "interrupted by SIGINT or SIGTERM" + (f" after {_num(soft.get('connected_seconds'), 1)} s of an answered call" if soft.get("answered") else ""))
    d.attribute(OUR, HIGH, ["The run ended because the operator (or a wrapper) sent SIGINT or SIGTERM; nothing about the platform's behavior can be concluded."])
    d.gap("report, triage, and the oracle were skipped on purpose, so there is no media verdict for this run")
    d.step("Repeat the call and let it finish.", run.cmd_call())
    d.step("Draw the ladder of what the capture recorded before the interrupt.", run.cmd_ladder())


def h_call_error(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    soft = run.softphone
    d.stage("media" if soft.get("answered") else "answer", "the softphone reported an error after the call was set up")
    d.outcome(f"The call reached the answered state but the softphone reported an error ({soft.get('error')}); the media verdict was not trusted.")
    d.evidence("softphone error", str(soft.get("error")))
    d.attribute(
        UNKNOWN, LOW,
        ["The error comes from the softphone driver (a timer or hang-up failure, for example), not from anything the far end sent; whether the far end contributed is not recorded."],
        ["Repeat once: a one-off driver error will not recur."],
    )
    d.step("Repeat the same call once.", run.cmd_call())
    d.step("Draw the ladder to see how the call ended.", run.cmd_ladder())
    d.step("Read the reference text.", run.cmd_explain())


def h_internal(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    d.stage("internal", "the toolbox failed internally")
    d.outcome("Sippycup failed internally; the evidence gathered so far is kept in the run directory.")
    d.attribute(OUR, MEDIUM, ["The notes carry the error; this is a toolbox fault, not a platform result."])
    for note in run.result.get("notes") or []:
        if "Internal error" in str(note):
            d.evidence("internal error", str(note))
    d.step("Check the toolbox image and runtime.", "./bin/sippycup doctor")
    d.step("Repeat once; if it fails the same way, keep the run directory and report it.", run.cmd_call())
    d.step("Read the reference text.", run.cmd_explain())


def h_inconclusive(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    d.stage("oracle", "the oracle returned unknown for something the verdict needs")
    d.outcome("The call was answered, but the evidence cannot decide pass or fail (unknown is never reported as pass).")
    d.evidence("not judged", ", ".join(oracle_unknown(run)) or "no assertion detail recorded")
    d.attribute(UNKNOWN, LOW, ["Encrypted signaling, a truncated capture, or missing RTP counts leave the oracle without enough to decide."])
    d.gap("the oracle's unknown results are listed above; a truncated or encrypted capture is the usual cause")
    d.step("Draw the ladder from whatever the capture and softphone log hold.", run.cmd_ladder())
    d.step("Repeat the call once to get a complete capture.", run.cmd_call())
    d.step("Read the reference text.", run.cmd_explain())


def h_blocked(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    d.stage("safety stop", "the gate refused before anything started")
    d.outcome("The call was refused before anything started: the profile is not approved, expired, or does not name target.host as a literal approved address.")
    d.attribute(OUR, HIGH, ["Our profile did not pass the gate, so nothing was sent; the gate worked as designed."])
    d.stop_and_ask("Fix the profile only through the owner's approval; do not edit the approval yourself.")
    d.step("See exactly which gate check failed (no traffic).", run.cmd_rehearse())


HANDLERS = {
    "pass": h_pass,
    "preflight-failed": h_preflight_failed,
    "tls-not-verified": h_tls_not_verified,
    "tls-name-pinning-failed": h_tls_pinning,
    "registration-failed": h_registration,
    "call-not-placed": h_not_placed,
    "call-busy": h_invite_reject,
    "call-declined": h_invite_reject,
    "call-auth-failed": h_invite_reject,
    "call-forbidden": h_invite_reject,
    "call-not-found": h_invite_reject,
    "call-unavailable": h_invite_reject,
    "call-rate-limited": h_invite_reject,
    "call-media-not-acceptable": h_invite_reject,
    "call-redirected": h_invite_reject,
    "call-rejected-4xx": h_invite_reject,
    "call-rejected-5xx": h_invite_reject,
    "call-rejected-6xx": h_invite_reject,
    "call-not-answered": h_not_answered,
    "slow-setup": h_slow_setup,
    "one-way-media": h_one_way,
    "possible-nat-one-way-media": h_one_way,
    "silent-audio": h_silent_audio,
    "peer-hung-up-early": h_peer_hangup,
    "fail": h_oracle_fail,
    "srtp-not-negotiated": h_srtp,
    "codec-not-offered": h_codec_not_offered,
    "dtmf-not-negotiated": h_dtmf,
    "dtmf-mismatch": h_dtmf,
    "media-outside-scope": h_scope_stop,
    "capture-failed": h_capture,
    "capture-died": h_capture,
    "authorization-lapsed": h_lapsed,
    "cancelled": h_cancelled,
    "internal-error": h_internal,
    "inconclusive": h_inconclusive,
    "call-error": h_call_error,
    "blocked": h_blocked,
}


def diagnose_call(run: CallRun, red: Redaction, ladder: Lazy) -> Diagnosis:
    d = Diagnosis("call", red)
    d.set(
        run=run.dir.name,
        verdict=run.verdict,
        state=run.result.get("state"),
        profile=red.text(run.result.get("profile")),
        target=f"{run.transport}://{red.hostport(run.host, run.target.get('port'))}" if run.host else None,
    )
    if not run.has_result:
        return _incomplete(d, run, ladder)
    handler = HANDLERS.get(str(run.verdict))
    add_common(d, run)
    if handler is None:
        d.outcome(f"The run ended with verdict {run.verdict}, which this version does not interpret further.")
        d.stage("internal", "unknown verdict")
        d.attribute(UNKNOWN, LOW, ["This verdict is not one the diagnosis knows."])
        d.step("Read the reference text for this verdict.", run.cmd_explain())
        d.step("Draw the ladder.", run.cmd_ladder())
    else:
        handler(d, run, ladder)
    for note in run.result.get("warnings") or []:
        d.gap(str(note))
    if not run.profile_known and any("PROFILE.yaml" in str(step.get("command", "")) for step in d.data["nextSteps"]):
        d.gap("the profile path is not recorded in this run (older run directory); PROFILE.yaml in the commands stands for it")
    _final_gaps(d, run, ladder)
    return d


def _final_gaps(d: Diagnosis, run: CallRun, ladder: Lazy) -> None:
    if run.transport == "tls" and not run.softphone.get("dialed"):
        pass
    elif run.transport == "tls" and not run.has_log:
        d.gap("signaling was TLS-encrypted and there is no softphone.log, so no SIP messages can be quoted")
    elif run.transport == "tls":
        d.gap("signaling was TLS-encrypted; SIP messages quoted here come from the softphone log, not the capture")
    if not run.has_capture:
        d.gap("no capture in this run directory; the ladder and RTP-per-direction checks are unavailable")
    note = _truncated_capture(ladder)
    if note:
        d.gap(note)


def _truncated_capture(ladder: Lazy) -> Optional[str]:
    document = ladder.peek()
    if not document:
        return None
    for warning in document.get("warnings") or []:
        if "truncat" in str(warning).lower() or "snap" in str(warning).lower():
            return f"the capture is truncated ({warning}); messages may be missing from the ladder"
    return None


def _incomplete(d: Diagnosis, run: CallRun, ladder: Lazy) -> Diagnosis:
    """A run directory with no result.json: the run was killed or is still going."""
    stamps = run.stamps
    last = [key for key in ("finished", "capture_stopped", "call_ended", "call_started", "capture_ready", "preflight_sent", "started") if key in stamps]
    reached = last[0] if last else None
    d.set(state="incomplete")
    d.outcome("This run has no result.json: it was killed before finishing, or it is still running.")
    stage = {"started": "capture", "capture_ready": "preflight", "preflight_sent": "preflight", "call_started": "answer"}.get(reached or "", "internal")
    d.stage(stage, f"the last recorded timestamp is {reached or 'none'}")
    d.attribute(UNKNOWN, LOW, ["Nothing was concluded because the run never wrote its result."])
    d.gap("result.json is missing; the verdict, notes, and counters were never written")
    d.step("Draw whatever the capture or softphone log recorded.", run.cmd_ladder() if (run.has_capture or run.has_log) else None)
    return d
