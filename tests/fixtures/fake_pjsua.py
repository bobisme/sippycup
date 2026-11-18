#!/usr/bin/env python3
"""A minimal stand-in for the PJSUA console used by softphone driver tests.

It reads ``--config-file``, records what it was given in the witness file
named by FAKE_PJSUA_WITNESS, prints the console lines the driver parses, and
obeys the ``m``/``dq``/``h``/``q`` commands. FAKE_PJSUA_MODE selects
``answer`` (default), ``noanswer``, ``regfail``, ``reject``, or ``outside``.
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
    }
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
    if "--registrar" in options:
        if mode == "regfail":
            say("pjsua_acc.c  SIP registration failed, status=403 (Forbidden)")
        else:
            say("pjsua_acc.c  sip:alice@x: registration success, status=200 (OK), will re-register in 300 seconds")
    state = {"confirmed": False, "disconnected": False, "dialed": False}
    lock = threading.Lock()

    def media_dump():
        peer = "198.51.100.77:4000" if mode == "outside" else "192.0.2.10:4000"
        say("  [CONFIRMED] To: sip:echo@192.0.2.10")
        say(f"    #0 audio PCMU @8kHz, sendrecv, peer={peer}")
        say("       RX pt=0, last update:00h:00m:01.008s ago")
        say("          total 42pkt 6.7KB (8.4KB +IP hdr) @avg=64.0Kbps/80.0Kbps")
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
            if mode in ("answer", "outside"):
                log_line("Incoming Response msg 200/INVITE/cseq=1 (rdata0x1) in state Proceeding")
                say("pjsua_app.c  .....Call 0 state changed to CONNECTING")
                say("pjsua_app.c  .....Call 0 state changed to CONFIRMED")
                state["confirmed"] = True
                threading.Thread(target=duration_timer, daemon=True).start()
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
