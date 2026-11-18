#!/usr/bin/env python3
"""A minimal stand-in for the PJSUA console used by softphone driver tests.

It reads ``--config-file``, records what it was given in the witness file
named by FAKE_PJSUA_WITNESS, prints the console lines the driver parses, and
obeys the ``m``/``dq``/``h``/``q`` commands. FAKE_PJSUA_MODE selects
``answer`` (default), ``noanswer``, ``regfail``, ``reject``, ``outside``
(media peer address out of scope), ``badport`` (media peer port out of
scope), ``oneway`` (no received RTP), ``authfail`` (one rejected digest
re-send), ``authretry`` (two rejected re-sends), or ``regfail401`` (a
wrong password: 401, credentialed re-send, 401, PJSIP_EFAILEDCREDENTIAL).
FAKE_PJSUA_CODEC names the negotiated codec (default PCMU).

Answered calls log a timestamped TX INVITE with an SDP offer, a 180 and a
200 with an SDP answer, like PJSUA's level-5 message log. FAKE_PJSUA_DTMF is
``rfc4733`` (default: the answer carries telephone-event) or ``none`` (it
does not, and ``#`` digits are refused as PJSUA refuses them);
FAKE_PJSUA_ECHO_DTMF=1 reports every sent digit back as an incoming one.
With ``--use-srtp`` FAKE_PJSUA_SRTP_PEER is ``sdes`` (default: the answer
accepts a=crypto) or ``plain`` (a mandatory offer is rejected with 488; an
optional one is answered without crypto).
"""

import datetime
import json
import os
import sys
import threading
import time

PASSWORD_LEAK_MARKER = "--password"


def say(text):
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def main():
    config_path = sys.argv[sys.argv.index("--config-file") + 1]
    with open(config_path, encoding="utf-8") as source:
        config_text = source.read()
    options = {}
    for line in config_text.splitlines():
        name, _, value = line.partition("=")
        options.setdefault(name, []).append(value)
    witness = os.environ.get("FAKE_PJSUA_WITNESS")
    mode = os.environ.get("FAKE_PJSUA_MODE", "answer")
    record = {
        "argv": sys.argv,
        "environ": dict(os.environ),
        "config": config_text,
        "config_mode": oct(os.stat(config_path).st_mode & 0o777),
        "config_dir_mode": oct(os.stat(os.path.dirname(config_path)).st_mode & 0o777),
        "commands": [],
        "pid": os.getpid(),
    }
    codec = os.environ.get("FAKE_PJSUA_CODEC", "PCMU")
    log_path = options["--log-file"][0]
    duration = int(options["--duration"][0])
    password = options.get("--password", [""])[0]
    log = open(log_path, "w", encoding="utf-8")

    def log_line(text):
        log.write(text + "\n")
        log.flush()

    def stamp():
        return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

    def log_message(header, lines):
        log_line(f"{stamp()}    pjsua_core.c  .{header}")
        for item in lines:
            log_line(item)
        log_line("--end msg--")

    use_srtp = int(options.get("--use-srtp", ["0"])[0])
    srtp_peer = os.environ.get("FAKE_PJSUA_SRTP_PEER", "sdes")
    dtmf_peer = os.environ.get("FAKE_PJSUA_DTMF", "rfc4733")
    echo_dtmf = os.environ.get("FAKE_PJSUA_ECHO_DTMF") == "1"
    rtp_port = int(options.get("--rtp-port", ["4000"])[0])
    srtp_active = use_srtp > 0 and srtp_peer == "sdes"

    def offer_sdp():
        profile = "RTP/SAVP" if use_srtp == 2 else "RTP/AVP"
        lines = ["v=0", "c=IN IP4 127.0.0.1", f"m=audio {rtp_port} {profile} 0 120 121",
                 "a=rtpmap:0 PCMU/8000", "a=rtpmap:120 telephone-event/16000",
                 "a=rtpmap:121 telephone-event/8000"]
        if use_srtp:
            lines.append("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz")
        return lines

    def answer_sdp():
        profile = "RTP/SAVP" if srtp_active and use_srtp == 2 else "RTP/AVP"
        lines = ["v=0", "c=IN IP4 192.0.2.10", f"m=audio 4000 {profile} 0" + (" 101" if dtmf_peer == "rfc4733" else ""),
                 "a=rtpmap:0 PCMU/8000"]
        if dtmf_peer == "rfc4733":
            lines.append("a=rtpmap:101 telephone-event/8000")
        if srtp_active:
            lines.append("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNk")
        return lines

    def save():
        if witness:
            with open(witness, "w", encoding="utf-8") as output:
                json.dump(record, output)

    save()
    log_line("pjsua_core.c  .pjsua version 2.17 fake initialized")
    if password:
        # Simulate the worst case: the password and a digest response leak
        # into PJSUA's own log. The driver must redact both.
        log_line(f"debug: account password is {password}")
        log_line('Authorization: Digest username="alice", realm="x", response="deadbeef"')
        log_line('Proxy-Authorization: Digest username="alice", response="cafef00d"')
    say("main.c  Ready: Success")
    # TLS: FAKE_PJSUA_TLS is ok (default), mismatch, untrusted, or none (no
    # verification line at all). The verified host is the outbound proxy's.
    tls_mode = os.environ.get("FAKE_PJSUA_TLS", "ok") if "--use-tls" in options else None
    if tls_mode is not None and tls_mode != "none":
        outbound = options["--outbound"][0][len("sip:"):].split(";", 1)[0]
        message = {
            "ok": "OK",
            "mismatch": "The server identity does not match to any identities specified in the certificate",
            "untrusted": "The certificate is untrusted",
        }[tls_mode]
        log_line(f"sip_transport_tls.c  TLS cert verification result of {outbound} : {message}")
    tls_failed = tls_mode in ("mismatch", "untrusted")
    if tls_failed:
        mode = "tlsfail"
    if "--registrar" in options:
        if mode == "tlsfail":
            say("pjsua_acc.c  SIP registration failed, status=171165 (PJSIP_TLS_ECERTVERIF)")
        elif mode == "regfail":
            say("pjsua_acc.c  SIP registration failed, status=403 (Forbidden)")
        elif mode == "regfail401":
            for cseq in (1, 2):
                log_message(f"TX 500 bytes Request msg REGISTER/cseq={cseq} (tdta{cseq}) to UDP 192.0.2.10:5060:",
                            ["REGISTER sip:192.0.2.10 SIP/2.0", "Content-Length: 0"])
                log_message(f"RX 400 bytes Response msg 401/REGISTER/cseq={cseq} (rdata{cseq}) from UDP 192.0.2.10:5060:",
                            ["SIP/2.0 401 Unauthorized", "Content-Length: 0"])
            say("pjsua_acc.c  ..SIP registration error: Failed to authenticate (PJSIP_EFAILEDCREDENTIAL) [status=171044]")
        else:
            say("pjsua_acc.c  sip:alice@x: registration success, status=200 (OK), will re-register in 300 seconds")
    state = {"confirmed": False, "disconnected": False, "dialed": False}
    lock = threading.Lock()

    def media_dump():
        host = os.environ.get("FAKE_PJSUA_PEER", "192.0.2.10")
        peer = "198.51.100.77:4000" if mode == "outside" else f"{host}:4000"
        say(f"  [CONFIRMED] To: sip:echo@{host}")
        if mode == "badport":
            peer = f"{host}:9"
        if mode == "silent":
            # PJSUA prints this placeholder until the first RTP packet arrives.
            peer = "-"
        say(f"    #0 audio {codec} @8kHz, sendrecv, peer={peer}")
        if use_srtp:
            say("       SRTP status: " + ("Active Crypto-suite: AES_CM_128_HMAC_SHA1_80" if srtp_active else "Not active Crypto-suite: "))
        say("       RX pt=0, last update:00h:00m:01.008s ago")
        received = 0 if mode in ("oneway", "silent") else 42
        say(f"          total {received}pkt 6.7KB (8.4KB +IP hdr) @avg=64.0Kbps/80.0Kbps")
        say("       TX pt=0, ptime=20, last update:00h:00m:00.601s ago")
        say("          total 43pkt 6.8KB (8.6KB +IP hdr) @avg=64.0Kbps/80.0Kbps")

    def disconnect(reason):
        with lock:
            if state["disconnected"]:
                return
            state["disconnected"] = True
        if state["confirmed"]:
            media_dump()
        say(f"pjsua_app.c  .Call 0 is DISCONNECTED [reason={reason}]")
        log_line(f"Incoming Response msg {reason.split()[0]}/INVITE/cseq=2 (rdata0x1) in state Calling")

    def duration_timer():
        time.sleep(duration)
        with lock:
            active = state["confirmed"] and not state["disconnected"]
        if active:
            say(f"pjsua_app.c !Duration ({duration} seconds) has been exceeded for call 0, disconnecting the call")
            disconnect("200 (OK)")

    pending_uri = False
    pending_dtmf = False
    for raw in sys.stdin:
        command = raw.strip()
        record["commands"].append(command)
        save()
        if pending_uri:
            pending_uri = False
            state["dialed"] = True
            say("pjsua_app.c  .......Call 0 state changed to CALLING")
            if mode in ("authfail", "authretry"):
                # A Digest-challenging server that rejects the credentials:
                # one unauthenticated INVITE, then authenticated re-sends.
                def request(cseq, authorized):
                    log_line(f"TX 512 bytes Request msg INVITE/cseq={cseq} (tdta0x{cseq}) to UDP 192.0.2.10:5060:")
                    log_line(f"INVITE {command} SIP/2.0")
                    if authorized:
                        log_line('Proxy-Authorization: Digest username="alice", response="feedface"')
                    log_line("Content-Length: 0")
                    log_line("--end msg--")
                    log_line(f"Incoming Response msg 407/INVITE/cseq={cseq} (rdata0x{cseq}) in state Calling")

                request(1, False)
                request(2, True)
                if mode == "authretry":
                    request(3, True)
                disconnect("407 (Proxy Authentication Required)")
                continue
            if mode in ("answer", "outside", "badport", "oneway", "silent"):
                log_message("TX 900 bytes Request msg INVITE/cseq=1 (tdta0x1) to UDP 192.0.2.10:5060:",
                            [f"INVITE {command} SIP/2.0", "Content-Type: application/sdp", "", *offer_sdp()])
                if use_srtp == 2 and srtp_peer == "plain":
                    log_message("RX 300 bytes Response msg 488/INVITE/cseq=1 (rdata0x1) from UDP 192.0.2.10:5060:",
                                ["SIP/2.0 488 Not Acceptable Here", "Content-Length: 0"])
                    disconnect("488 (Not Acceptable Here)")
                    continue
                log_message("RX 300 bytes Response msg 180/INVITE/cseq=1 (rdata0x2) from UDP 192.0.2.10:5060:",
                            ["SIP/2.0 180 Ringing", "Content-Length: 0"])
                time.sleep(float(os.environ.get("FAKE_PJSUA_RING_SECONDS", "0")))
                log_message("RX 900 bytes Response msg 200/INVITE/cseq=1 (rdata0x3) from UDP 192.0.2.10:5060:",
                            ["SIP/2.0 200 OK", "Content-Type: application/sdp", "", *answer_sdp()])
                if srtp_active:
                    log_line(f"{stamp()} srtp0x1  .SRTP started, keying=SDES, crypto=AES_CM_128_HMAC_SHA1_80")
                log_line("Incoming Response msg 200/INVITE/cseq=1 (rdata0x1) in state Proceeding")
                say("pjsua_app.c  .....Call 0 state changed to CONNECTING")
                say("pjsua_app.c  .....Call 0 state changed to CONFIRMED")
                state["confirmed"] = True
                threading.Thread(target=duration_timer, daemon=True).start()
            elif mode == "tlsfail":
                disconnect("171165 (PJSIP_TLS_ECERTVERIF)")
            elif mode == "reject":
                log_line("Incoming Response msg 486/INVITE/cseq=1 (rdata0x1) in state Proceeding")
                disconnect("486 (Busy Here)")
            continue
        if pending_dtmf:
            pending_dtmf = False
            if dtmf_peer != "rfc4733":
                say("pjsua_app.c  Unable to send DTMF: Remote does not support RFC 2833 (PJMEDIA_RTP_EREMNORFC2833)")
                continue
            say("DTMF digits enqueued for transmission")
            log_line(f"{stamp()}            pjsua_aud.c !Call 0 dialing DTMF {command}")
            for digit in command:
                log_line(f"{stamp()}     strm0x1  Sending DTMF digit id {digit}")
                if echo_dtmf:
                    say(f"pjsua_app.c  Incoming DTMF on call 0: {digit}, using RFC2833 method")
            continue
        if command == "#":
            pending_dtmf = state["confirmed"] and not state["disconnected"]
            say("DTMF strings to send (0-9*R#A-B) (empty to cancel): ")
        elif command == "m":
            pending_uri = True
            say("Make call: ")
        elif command == "dq":
            if state["confirmed"] and not state["disconnected"]:
                media_dump()
        elif command == "h":
            if state["dialed"] and not state["disconnected"]:
                record.setdefault("hangups", []).append("BYE" if state["confirmed"] else "CANCEL")
                save()
                disconnect("200 (OK)" if state["confirmed"] else "487 (Request Terminated)")
        elif command == "q":
            break
    log.close()
    save()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
