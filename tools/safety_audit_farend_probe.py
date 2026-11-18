#!/usr/bin/env python3
"""Audit probe: does a hostile far end steer PJSUA signaling or media off-scope?

Runs inside the toolbox image in a private network namespace. The approved
target is 127.0.0.2. "Unapproved" listeners on 127.0.0.66/.77/.88/.99 count
every datagram they receive (docs/SAFETY-AUDIT.md).

Copy it beneath work/ and run it in the image:

    cp tools/safety_audit_farend_probe.py work/
    ./bin/sippycup --isolated -- python3 /work/safety_audit_farend_probe.py SCENARIO [WORDS]

SCENARIO is rr_contact, contact_only, media_level_c, session_level_c,
rtcp_attr, reinvite, redirect, or refer. WORDS (comma-separated) prints the
PJSUA log lines containing them. With "uasonly SECONDS" it only serves the
far end, for a separately started `sippycup-call` in the same container.
AUDIT_OLD=1 puts /work/oldlib/lib (an older lib/ tree) first on the path.
"""

import json
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, "/usr/local/lib")
import os
if os.environ.get("AUDIT_OLD"):
    sys.path.insert(0, "/work/oldlib/lib")  # a copy of an older lib/ to compare against

from sippycup_softphone.driver import SoftphoneCall, place_call  # noqa: E402
from sippycup_workbench.call import generate_tone  # noqa: E402

APPROVED = "127.0.0.2"
RR = "127.0.0.66"
CONTACT = "127.0.0.77"
MEDIA = "127.0.0.88"
RTCP = "127.0.0.99"
scenario = sys.argv[1]
counts: dict[str, int] = {}
first_seen: dict[str, float] = {}
started = time.monotonic()


def listen(address: str, port: int, label: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address, port))
    sock.settimeout(0.2)
    while not stop.is_set():
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        key = f"{label} {address}:{port}"
        counts[key] = counts.get(key, 0) + 1
        first_seen.setdefault(key, round(time.monotonic() - started, 3))
        if label == "sip":
            counts.setdefault("sip-methods " + key, 0)
            line = data.split(b"\r\n", 1)[0].decode(errors="replace")
            counts[f"  first-line {address}: {line[:60]}"] = counts.get(f"  first-line {address}: {line[:60]}", 0) + 1


stop = threading.Event()
for address, port, label in (
    (RR, 5060, "sip"), (CONTACT, 5060, "sip"),
    (MEDIA, 40002, "rtp"), (MEDIA, 40003, "rtcp"), (MEDIA, 40000, "rtp"), (MEDIA, 40001, "rtcp"),
    (RTCP, 40011, "rtcp-attr"),
):
    threading.Thread(target=listen, args=(address, port, label), daemon=True).start()


def headers(message: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in message.split("\r\n")[1:]:
        if not line:
            break
        if ":" in line:
            name, value = line.split(":", 1)
            result.setdefault(name.strip().lower(), value.strip())
    return result


def sdp(session_c: str, media_c: str | None, port: int = 40000, extra: str = "") -> str:
    body = (
        "v=0\r\no=far 1 1 IN IP4 127.0.0.2\r\ns=far\r\n"
        f"c=IN IP4 {session_c}\r\nt=0 0\r\nm=audio {port} RTP/AVP 0\r\n"
    )
    if media_c:
        body += f"c=IN IP4 {media_c}\r\n"
    return body + "a=rtpmap:0 PCMU/8000\r\n" + extra


def uas() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((APPROVED, 5060))
    server.settimeout(0.2)
    dialog: dict[str, str] = {}
    reinvited = False
    while not stop.is_set():
        try:
            packet, peer = server.recvfrom(65535)
        except socket.timeout:
            if dialog.get("acked") and scenario == "reinvite" and not reinvited and time.monotonic() - float(dialog["acked"]) > 1.5:
                reinvited = True
                contact = dialog["contact"].strip("<>").split(">")[0]
                body = sdp(MEDIA, None, 40002)
                request = (
                    f"INVITE {contact} SIP/2.0\r\n"
                    f"Via: SIP/2.0/UDP {APPROVED}:5060;branch=z9hG4bKaudit2\r\n"
                    f"From: {dialog['to']}\r\nTo: {dialog['from']}\r\n"
                    f"Call-ID: {dialog['call-id']}\r\nCSeq: 7 INVITE\r\n"
                    f"Contact: <sip:far@{APPROVED}:5060>\r\nMax-Forwards: 70\r\n"
                    f"Content-Type: application/sdp\r\nContent-Length: {len(body)}\r\n\r\n{body}"
                )
                server.sendto(request.encode(), dialog["peer_tuple"])
            if dialog.get("acked") and scenario == "refer" and not reinvited and time.monotonic() - float(dialog["acked"]) > 1.0:
                reinvited = True
                contact = dialog["contact"].strip("<>").split(">")[0]
                request = (
                    f"REFER {contact} SIP/2.0\r\n"
                    f"Via: SIP/2.0/UDP {APPROVED}:5060;branch=z9hG4bKaudit4\r\n"
                    f"From: {dialog['to']}\r\nTo: {dialog['from']}\r\n"
                    f"Call-ID: {dialog['call-id']}\r\nCSeq: 8 REFER\r\n"
                    f"Contact: <sip:far@{APPROVED}:5060>\r\nMax-Forwards: 70\r\n"
                    f"Refer-To: <sip:victim@{CONTACT}:5060>\r\nContent-Length: 0\r\n\r\n"
                )
                server.sendto(request.encode(), dialog["peer_tuple"])
            continue
        message = packet.decode(errors="replace")
        first = message.split("\r\n", 1)[0]
        h = headers(message)
        to = h.get("to", "")
        if ";tag=" not in to:
            to += ";tag=far1"

        def reply(status: str, body: str = "", extra: str = "") -> None:
            lines = [
                f"SIP/2.0 {status}", f"Via: {h.get('via', '')}", f"From: {h.get('from', '')}",
                f"To: {to}", f"Call-ID: {h.get('call-id', '')}", f"CSeq: {h.get('cseq', '')}",
            ]
            if extra:
                lines.append(extra.rstrip("\r\n"))
            if body:
                lines.append("Content-Type: application/sdp")
            lines.append(f"Content-Length: {len(body.encode())}")
            server.sendto(("\r\n".join(lines) + "\r\n\r\n" + body).encode(), peer)

        if first.startswith("OPTIONS "):
            reply("200 OK")
            continue
        if first.startswith("INVITE ") and not dialog:
            dialog.update({"from": h.get("from", ""), "to": to, "call-id": h.get("call-id", ""),
                           "contact": h.get("contact", ""), "peer_tuple": peer})
            reply("100 Trying")
            if scenario == "redirect":
                reply("302 Moved Temporarily", extra=f"Contact: <sip:echo@{CONTACT}:5060>")
                continue
            contact = f"Contact: <sip:far@{APPROVED}:5060>"
            extra = contact
            body = sdp(APPROVED, None)
            if scenario == "rr_contact":
                extra = f"Record-Route: <sip:{RR}:5060;lr>\r\nContact: <sip:far@{CONTACT}:5060>"
            elif scenario == "contact_only":
                extra = f"Contact: <sip:far@{CONTACT}:5060>"
            elif scenario == "media_level_c":
                body = sdp(APPROVED, MEDIA)
            elif scenario == "session_level_c":
                body = sdp(MEDIA, APPROVED)
            elif scenario == "rtcp_attr":
                body = sdp(APPROVED, None, extra=f"a=rtcp:40011 IN IP4 {RTCP}\r\n")
            reply("200 OK", body, extra)
        elif first.startswith("INVITE "):
            reply("200 OK", sdp(APPROVED, None))
        elif first.startswith("ACK "):
            dialog.setdefault("acked", str(time.monotonic()))
        elif first.startswith("BYE "):
            reply("200 OK")
            counts["bye-at-approved"] = counts.get("bye-at-approved", 0) + 1
        elif first.startswith("SIP/2.0 200") and "INVITE" in h.get("cseq", ""):
            ack = (
                f"ACK {dialog['contact'].strip('<>').split('>')[0]} SIP/2.0\r\n"
                f"Via: SIP/2.0/UDP {APPROVED}:5060;branch=z9hG4bKaudit3\r\n"
                f"From: {dialog['to']}\r\nTo: {dialog['from']}\r\n"
                f"Call-ID: {dialog['call-id']}\r\nCSeq: 7 ACK\r\nContent-Length: 0\r\n\r\n"
            )
            server.sendto(ack.encode(), peer)
            counts["reinvite-answered"] = 1
        # RTP to the approved address is fine; no echo needed.


threading.Thread(target=uas, daemon=True).start()
rtp_sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
rtp_sink.bind((APPROVED, 40000))

if "uasonly" in sys.argv:
    # Serve the far end for a separately started command, then report.
    time.sleep(float(sys.argv[-1]))
    stop.set()
    print(json.dumps({"scenario": scenario, "unapproved_received": counts, "first_seen_s": first_seen}, indent=1))
    raise SystemExit(0)

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    tone = root / "tone.wav"
    generate_tone(tone, seconds=2.0)
    call = SoftphoneCall(
        destination="echo", host=APPROVED, port=5060, transport="udp",
        play_file=tone, record_file=root / "heard.wav", duration_seconds=6,
        log_file=root / "softphone.log", console_file=root / "console.txt",
        allowed_media_addresses=(APPROVED,), advertised_address="127.0.0.1",
        answer_timeout_seconds=5,
    )
    def watch_log() -> None:
        while not stop.is_set():
            for path in root.glob("sippycup-softphone-*/pjsua.log"):
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                if "RX" in text and "Response msg 200/INVITE" in text:
                    first_seen.setdefault("log-file shows RX 200/INVITE", round(time.monotonic() - started, 3))
                first_seen.setdefault("log-file bytes at 1s", None)
                if time.monotonic() - started > 1.0 and first_seen["log-file bytes at 1s"] is None:
                    first_seen["log-file bytes at 1s"] = len(text)
            time.sleep(0.01)

    if "watchlog" in sys.argv:
        threading.Thread(target=watch_log, daemon=True).start()
    result = place_call(call, private_root=root)
    time.sleep(1.0)
    stop.set()
    print(json.dumps({
        "scenario": scenario,
        "error": result.error,
        "media_peer": result.media_peer,
        "media_scope": result.media_scope,
        "final_status": result.final_status,
        "hangup": result.hangup,
        "rtp_tx": result.rtp_tx_packets,
        "unapproved_received": counts,
        "first_seen_s": first_seen,
    }, indent=1, default=str))
    log = (root / "softphone.log").read_text(errors="replace")
    sends = [line for line in log.splitlines() if "TX " in line and "to UDP" in line]
    print("PJSUA TX lines:")
    for line in sends:
        print("  ", line.strip()[:160])
    if len(sys.argv) > 2:
        console = (root / "console.txt").read_text(errors="replace")
        for line in (log + console).splitlines():
            if any(word in line for word in sys.argv[2].split(",")):
                print("  >", line.strip()[:200])
