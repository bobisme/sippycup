"""Fault-destination checks for the practice gate (bn-20l).

``tools/practice_gate.py`` calls :func:`check_faults` once. It runs the
rehearsal drill (`./bin/sippycup practice-target drill --format json`) and then
reads each scenario's own capture to prove two things independently:

* what the server did on the wire (for example no RTP from the peer for
  ``silent``, a BYE from the peer for ``drop``, a 503 final status, a 183 before
  the 200 for ``earlymedia``), and
* the verdict and exit code the guided call reported.

The wire rules are pure functions of decoded capture rows, so unit tests cover
them without a container. Only the practice namespace is ever contacted; the
drill itself refuses anything else.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup import practice_drill  # noqa: E402

CALLER = "127.0.0.1"
SERVER = "127.0.0.2"
FIELDS = (
    "frame.number", "frame.time_relative", "ip.src", "ip.dst", "udp.srcport", "udp.dstport",
    "sip.Method", "sip.Status-Code", "sip.CSeq.method", "rtp.payload",
)
Rows = list[dict[str, str]]
Check = Callable[[Rows], tuple[bool, Any]]


def tshark_argv(capture: str) -> list[str]:
    argv = ["--practice", "--", "tshark", "-r", capture, "-Y", "sip || udp", "-T", "fields",
            "-E", "separator=/t", "-E", "occurrence=f"]
    for name in FIELDS:
        argv.extend(["-e", name])
    return argv


def parse_rows(text: str) -> Rows:
    rows: Rows = []
    for line in text.splitlines():
        cells = line.split("\t")
        cells += [""] * (len(FIELDS) - len(cells))
        rows.append(dict(zip(FIELDS, cells)))
    return rows


# -- decoded-row helpers -------------------------------------------------------
def requests(rows: Rows, method: str, source: str | None = None) -> Rows:
    return [r for r in rows if r["sip.Method"] == method and (source is None or r["ip.src"] == source)]


def responses(rows: Rows, status: int, method: str = "INVITE") -> Rows:
    return [r for r in rows if r["sip.Status-Code"] == str(status) and r["sip.CSeq.method"] == method]


def rtp(rows: Rows, source: str) -> Rows:
    """RTP-looking packets: decoded payload present, or UDP from the media port range."""
    return [r for r in rows if r["ip.src"] == source and (r["rtp.payload"] or _media_port(r))]


def _media_port(row: dict[str, str]) -> bool:
    """The caller's RTP ports (PJSUA starts at 4000) or the server's 20000-20019."""
    port = row["udp.srcport"]
    return port.isdigit() and (4000 <= int(port) < 4100 or 20000 <= int(port) <= 20019)


def t(row: dict[str, str]) -> float:
    return float(row["frame.time_relative"])


def first(rows: Rows) -> dict[str, str] | None:
    return rows[0] if rows else None


def no_session(rows: Rows) -> bool:
    return not responses(rows, 200)


def rejected_with(status: int) -> Check:
    def check(rows: Rows) -> tuple[bool, Any]:
        seen = responses(rows, status)
        ok = bool(seen) and no_session(rows) and not rtp(rows, SERVER)
        return ok, {"final": status, "responses": len(seen), "answered": not no_session(rows)}

    return check


# -- per-scenario wire rules ---------------------------------------------------
def wire_echo(rows: Rows) -> tuple[bool, Any]:
    out, back = len(rtp(rows, CALLER)), len(rtp(rows, SERVER))
    return bool(responses(rows, 200)) and out > 50 and back > 50, {"to_server": out, "from_server": back}


def wire_noanswer(rows: Rows) -> tuple[bool, Any]:
    ringing = responses(rows, 180)
    cancel = requests(rows, "CANCEL", CALLER)
    return (
        bool(ringing) and bool(cancel) and no_session(rows) and not rtp(rows, SERVER),
        {"180": len(ringing), "cancel_from_caller": len(cancel), "answered": not no_session(rows)},
    )


def wire_late(rows: Rows) -> tuple[bool, Any]:
    invite, answer, ringing = first(requests(rows, "INVITE", CALLER)), first(responses(rows, 200)), first(responses(rows, 180))
    if not (invite and answer and ringing):
        return False, {"invite": bool(invite), "180": bool(ringing), "200": bool(answer)}
    delay = t(answer) - t(invite)
    return 11.0 <= delay <= 14.0 and t(ringing) < t(answer), {"answer_after_seconds": round(delay, 2)}


def wire_late_impatient(rows: Rows) -> tuple[bool, Any]:
    invite, cancel = first(requests(rows, "INVITE", CALLER)), first(requests(rows, "CANCEL", CALLER))
    if not (invite and cancel):
        return False, {"invite": bool(invite), "cancel": bool(cancel)}
    wait = t(cancel) - t(invite)
    return 5.0 <= wait <= 8.0 and no_session(rows), {"cancel_after_seconds": round(wait, 2)}


def wire_silent(rows: Rows) -> tuple[bool, Any]:
    # Count every UDP packet from the server's media ports, decoded as RTP or not.
    server_media = [r for r in rows if r["ip.src"] == SERVER and _media_port(r)]
    caller_rtp = rtp(rows, CALLER)
    return (
        bool(responses(rows, 200)) and not server_media and bool(caller_rtp),
        {"rtp_from_server": len(server_media), "rtp_from_caller": len(caller_rtp)},
    )


def wire_silence(rows: Rows) -> tuple[bool, Any]:
    """Packets flow from the server, and every payload byte is the u-law silence code 0xFF."""
    packets = [r for r in rtp(rows, SERVER) if r["rtp.payload"]]
    digital = [r for r in packets if set(r["rtp.payload"].replace(":", "").lower()) == {"f"}]
    return len(packets) > 50 and len(digital) == len(packets), {
        "rtp_packets": len(packets), "all_ff_payload": len(digital)
    }


def wire_drop(rows: Rows) -> tuple[bool, Any]:
    answer, bye = first(responses(rows, 200)), first(requests(rows, "BYE", SERVER))
    if not (answer and bye):
        return False, {"200": bool(answer), "bye_from_server": bool(bye)}
    gap = t(bye) - t(answer)
    return 2.5 <= gap <= 4.5 and not requests(rows, "BYE", CALLER), {"bye_after_answer_seconds": round(gap, 2)}


def wire_earlymedia(rows: Rows) -> tuple[bool, Any]:
    progress, answer = first(responses(rows, 183)), first(responses(rows, 200))
    if not (progress and answer):
        return False, {"183": bool(progress), "200": bool(answer)}
    early = [r for r in rtp(rows, SERVER) if t(r) < t(answer)]
    return (
        int(progress["frame.number"]) < int(answer["frame.number"]) and len(early) > 100,
        {"early_rtp_packets": len(early), "answer_after_seconds": round(t(answer), 2)},
    )


def wire_badpassword(rows: Rows) -> tuple[bool, Any]:
    challenged = [r for r in rows if r["sip.Status-Code"] == "401" and r["sip.CSeq.method"] == "REGISTER"]
    registered = [r for r in rows if r["sip.Status-Code"] == "200" and r["sip.CSeq.method"] == "REGISTER"]
    invites = requests(rows, "INVITE")
    return len(challenged) >= 2 and not registered and not invites, {
        "401_challenges": len(challenged), "registered": len(registered), "invites": len(invites)
    }


def wire_closedport(rows: Rows) -> tuple[bool, Any]:
    # The closed port is not decoded as SIP, so count the datagrams themselves.
    probes = [r for r in rows if r["ip.src"] == CALLER and r["udp.dstport"] == str(practice_drill.CLOSED_PORT)]
    replies = [r for r in rows if r["ip.src"] == SERVER and r["sip.Status-Code"]]
    return bool(probes) and not replies and not requests(rows, "INVITE"), {
        "options_to_closed_port": len(probes), "replies": len(replies)
    }


WIRE: dict[str, Check] = {
    "echo": wire_echo,
    "noanswer": wire_noanswer,
    "late": wire_late,
    "late-impatient": wire_late_impatient,
    "silent": wire_silent,
    "silence": wire_silence,
    "drop": wire_drop,
    "unavailable": rejected_with(503),
    "forbidden": rejected_with(403),
    "ratelimit": rejected_with(429),
    "busy": rejected_with(486),
    "decline": rejected_with(603),
    "notfound": rejected_with(404),
    "earlymedia": wire_earlymedia,
    "srtp-required": rejected_with(488),
    "badpassword": wire_badpassword,
    "closedport": wire_closedport,
}


def capture_path(run_directory: str) -> str:
    """The in-container path of a run's capture (``work/...`` is mounted at ``/work``)."""
    if not run_directory.startswith("work/") or ".." in run_directory.split("/"):
        raise ValueError(f"unexpected run directory {run_directory!r}")
    return "/" + run_directory + "/capture.pcap"


def check_faults(gate: Any) -> None:
    """Run the drill and assert wire behaviour plus verdict for every scenario."""
    result = gate.run("practice-target", "drill", "--format", "json", timeout=420)
    try:
        summary = json.loads(result.stdout)
    except ValueError:
        gate.record("fault drill produced a JSON summary", False, (result.stderr or result.stdout)[-300:])
        return
    gate.host_path("fault-drill.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    scenarios = {entry["scenario"]: entry for entry in summary["scenarios"]}
    missing = [item.name for item in practice_drill.SCENARIOS if item.name not in scenarios]
    gate.record("fault drill ran every scenario", not missing, missing or len(scenarios))
    for scenario in practice_drill.SCENARIOS:
        entry = scenarios[scenario.name]
        tshark = gate.run(*tshark_argv(capture_path(entry["runDirectory"])), timeout=120)
        rows = parse_rows(tshark.stdout) if tshark.returncode == 0 else []
        ok, detail = WIRE[scenario.name](rows) if rows else (False, f"tshark exit {tshark.returncode}")
        gate.record(f"fault {scenario.name}: server behavior on the wire ({scenario.wire})", ok, detail)
        gate.record(
            f"fault {scenario.name}: verdict {scenario.expected} with exit {scenario.expected_exit}",
            entry["verdict"] == scenario.expected and entry["exit"] == scenario.expected_exit,
            {"verdict": entry["verdict"], "exit": entry["exit"]},
        )
