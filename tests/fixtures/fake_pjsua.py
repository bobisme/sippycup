#!/usr/bin/env python3
"""A minimal stand-in for the PJSUA console used by softphone driver tests.

It reads ``--config-file``, records what it was given in the witness file
named by FAKE_PJSUA_WITNESS, prints the console lines the driver parses, and
obeys the ``m``/``dq``/``h``/``q`` commands. FAKE_PJSUA_MODE selects
``answer`` (default), ``noanswer``, ``regfail``, ``reject``, ``outside``
(media peer address out of scope), ``badport`` (media peer port out of
scope), ``oneway`` (no received RTP), ``authfail`` (one rejected digest
re-send), or ``authretry`` (two rejected re-sends). FAKE_PJSUA_CODEC names
the negotiated codec (default PCMU).
"""

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
        say(f"    #0 audio {codec} @8kHz, sendrecv, peer={peer}")
        say("       RX pt=0, last update:00h:00m:01.008s ago")
        received = 0 if mode == "oneway" else 42
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
            if mode in ("answer", "outside", "badport", "oneway"):
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
        if command == "m":
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
