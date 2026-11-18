"""`diagnose --compare RUN_A RUN_B`: what differs between two guided-call runs."""

from __future__ import annotations

from pathlib import Path

from . import COMPARE_SCHEMA
from .callrun import CallRun
from .core import work_relative
from .inputs import InputError, detect_kind, make_redaction

SETTINGS = (
    "profile", "transport", "target", "codec offer", "SRTP mode", "answer timeout",
    "duration", "register", "DTMF", "dial", "media required",
)


def _facts(run: CallRun, red) -> dict:
    phone = run.plan_phone
    soft = run.softphone
    result = run.result
    offer, answer = run.sdp(True), run.sdp(False)
    uri = str(phone.get("destination_uri") or result.get("destinationUri") or "")
    dial = uri.split("@")[0].split(":", 1)[-1] if "@" in uri else ""
    codec = result.get("codec") or {}
    inv = run.invite_times()
    scope = result.get("mediaScope") or {}
    types = (codec.get("wire") or {}).get("rtpPayloadTypes") or {}
    return {
        "profile": red.text(result.get("profile")),
        "transport": run.transport,
        "target": red.hostport(run.host, run.target.get("port")),
        "codec offer": ("only " if phone.get("codec_offer") == "only" else "preferring ") + ",".join(phone.get("codecs") or []),
        "SRTP mode": (phone.get("srtp") or {}).get("mode"),
        "answer timeout": phone.get("answer_timeout_seconds"),
        "duration": (phone.get("duration_seconds") or {}).get("effective"),
        "register": (run.account or {}).get("register") if run.account else "no account",
        "DTMF": (phone.get("dtmf") or {}).get("digits") and "digits requested" or "none",
        "dial": "recorded" if not dial else "same text as recorded",
        "_dial_value": dial,
        "_answer_core": None if answer is None else (red.addr(answer.address), tuple(answer.formats)),
        "media required": phone.get("media_required"),
        "verdict": run.verdict,
        "state": result.get("state"),
        "registration status": soft.get("registration_status"),
        "final INVITE status": soft.get("final_status"),
        "disconnect": f"{soft.get('disconnect_status')} {soft.get('disconnect_reason')}" if soft.get("disconnect_status") is not None else None,
        "hang-up by": soft.get("hangup"),
        "SDP offer": _sdp(offer, red),
        "SDP answer": _sdp(answer, red),
        "negotiated codec": codec.get("negotiated"),
        "RTP out/in (packets)": f"{soft.get('rtp_tx_packets')}/{soft.get('rtp_rx_packets')}" if soft.get("rtp_tx_packets") is not None or soft.get("rtp_rx_packets") is not None else None,
        "payload types out": _pts((types or {}).get("outbound")),
        "payload types in": _pts((types or {}).get("inbound")),
        "media peer": red.text(scope.get("peer")) if scope.get("peer") else None,
        "media peer admitted by": scope.get("admittedBy") if scope.get("peer") else None,
        "registration time (s)": _r(run.registration_seconds()),
        "INVITE to provisional (s)": _r(inv.get("provisional")),
        "INVITE to answer (s)": _r((soft.get("setup") or {}).get("inviteToAnswerSeconds")),
        "answered duration (s)": _r(soft.get("connected_seconds")),
        "failed oracle assertions": ", ".join(str(x).replace("dialog[0].", "") for x in (result.get("oracle") or {}).get("failed", [])) or None,
        "far-end Reason/Warning": "; ".join(f"{label}: {text}" for label, text in run.far_end_headers()) or None,
    }


def _r(value):
    return round(float(value), 3) if isinstance(value, (int, float)) else None


def _pts(value) -> str | None:
    if not isinstance(value, dict) or not value:
        return None
    return ",".join(f"{k}x{v}" for k, v in sorted(value.items(), key=lambda item: str(item[0])))


def _sdp(sdp, red) -> str | None:
    if sdp is None:
        return None
    return f"{red.hostport(sdp.address, sdp.port)} {sdp.proto} PT {','.join(sdp.formats)} {sdp.direction or ''}".strip()


def compare_runs(path_a: Path, path_b: Path, arguments):
    for path in (path_a, path_b):
        if detect_kind(path) != "call":
            raise InputError("--compare takes two guided-call run directories (each with a result.json from ./bin/sippycup call)")
    red = make_redaction([path_a, path_b], arguments.approve, arguments.show_addresses)
    run_a, run_b = CallRun(path_a), CallRun(path_b)
    fa, fb = _facts(run_a, red), _facts(run_b, red)
    # Timing values are expected to differ a little; only flag a spread above 2x and 0.5 s.
    differences, same = [], []
    timing_keys = {k for k in fa if k.endswith("(s)")}
    for key in fa:
        if key.startswith("_"):
            continue
        a, b = fa[key], fb[key]
        if key == "dial":
            if fa["_dial_value"] != fb["_dial_value"]:
                differences.append({"field": key, "a": "differs", "b": "differs (values not printed: user parts are never shown)"})
            else:
                same.append(key)
            continue
        if a is None and b is None:
            continue
        if key in timing_keys and isinstance(a, (int, float)) and isinstance(b, (int, float)):
            low, high = sorted((a, b))
            if high - low < 0.5 or (low > 0 and high / low < 2):
                same.append(key)
                continue
        if a == b:
            same.append(key)
        else:
            differences.append({"field": key, "a": "not recorded" if a is None else str(a), "b": "not recorded" if b is None else str(b)})
    diff_fields = {item["field"] for item in differences}
    changed_settings = [s for s in SETTINGS if s in diff_fields]
    likely, gaps = [], []
    outcome_differs = fa["verdict"] != fb["verdict"]
    if outcome_differs:
        if not changed_settings:
            likely.append(
                "The recorded settings (profile, transport, target, codec offer, SRTP, timeouts, account) are identical, so the difference lies in the far end, the path, or timing, not in our configuration. "
                "Compare the far-end headers and timings below, and ask the owner whether anything changed between the two runs."
            )
        elif len(changed_settings) == 1:
            likely.append(f"Only one setting differs ({changed_settings[0]}); it is the most likely cause of the different outcome.")
        else:
            likely.append(f"Several settings differ ({', '.join(changed_settings)}); change one at a time to find the one that matters.")
    for key in ("final INVITE status", "registration status"):
        if key in diff_fields:
            likely.append(f"The {key} differs: this is where the two runs part ways.")
    if fa["_answer_core"] and fb["_answer_core"] and fa["_answer_core"] != fb["_answer_core"]:
        likely.append("The far end's SDP answer names a different media address or different formats: a different media server or a changed SDP rewrite is in play.")
    if not run_a.has_log or not run_b.has_log:
        gaps.append("a run has no softphone.log, so SDP, headers, and registration timing could not be compared for it")
    summary = (
        f"{'Different outcomes' if outcome_differs else 'Same outcome'}: A {fa['verdict']}, B {fb['verdict']}; "
        f"{len(differences)} difference(s) in {len(differences) + len(same)} compared fields."
    )
    data = {
        "schema": COMPARE_SCHEMA,
        "a": {"run": path_a.name, "runRef": work_relative(path_a.resolve()), "verdict": fa["verdict"]},
        "b": {"run": path_b.name, "runRef": work_relative(path_b.resolve()), "verdict": fb["verdict"]},
        "summary": summary,
        "differences": differences,
        "same": same,
        "likely": [red.text(item, 400) for item in likely],
        "gaps": gaps,
        "redaction": {"addresses": "operator copy" if arguments.show_addresses else "approved addresses shown, others replaced by labels"},
        "networkActivity": False,
    }
    return data, red
