"""``srtp-policy``: what media protection does the edge accept and answer with?

At most three very short real calls, placed with the softphone driver (the
same PJSUA wrapper the guided call uses, so the same TLS verification, name
pinning, media-scope and hangup behaviour apply) to the reviewed destination
with the reviewed account:

1. ``plain-rtp``: RTP/AVP with no ``a=crypto``, over the profile's signaling.
2. ``sdes-mandatory``: RTP/SAVP with ``a=crypto`` (SDES), same signaling.
3. ``sdes-over-cleartext``: on a TLS target with an owner-approved cleartext
   endpoint, an SDES offer over that cleartext signaling, so the media key
   crosses the wire readable.

Each call lasts one second (digital silence), is charged to the request
budget at its worst case before it starts and then settled to the requests
its own log shows, and is preceded by an authorization re-check. A password
that is not accepted ends the check: nothing is retried. Findings state what
was offered and what was answered, as the softphone log recorded it.
"""

from __future__ import annotations

import json
import tempfile
import wave
from pathlib import Path
from typing import Any

from . import catalog
from .budget import BudgetExceeded, Stopped
from .checks import CheckResult, Context, ev, finding, quote

CHECK = "srtp-policy"
CALL_SECONDS = 1
OFFER_TEXT = {
    "off": "RTP/AVP without a=crypto (plain RTP)",
    "mandatory": "RTP/SAVP with a=crypto (mandatory SDES-SRTP)",
    "optional": "RTP/AVP with a=crypto (optional SDES-SRTP)",
}
LABEL = {
    "plain-rtp": "plain RTP",
    "sdes-mandatory": "mandatory SDES-SRTP",
    "sdes-over-cleartext": "SDES offer over cleartext signaling",
}
# Driver errors that end the whole run, not just this call.
SCOPE_ERRORS = {"media_peer_outside_scope", "capture_died", "cancelled"}
FATAL_ERRORS = SCOPE_ERRORS | {"tls_verification_failed", "tls_verification_not_observed"}


def write_silence(path: Path, seconds: int = 3) -> Path:
    with wave.open(str(path), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(8000)
        output.writeframes(b"\x00\x00" * 8000 * seconds)
    return path


def count_requests(log_text: str, transport: str) -> int:
    """Requests PJSUA really transmitted (retransmissions included).

    Over TCP or TLS the connection counts as the first request, so a call that
    connected but sent no SIP (for example a failed certificate verification)
    still counts one.
    """
    from sippycup_softphone.evidence import parse_messages

    sent = sum(1 for item in parse_messages(log_text) if item["direction"] == "TX" and item["kind"] == "Request")
    return sent if transport == "udp" else max(1, sent)


def describe(sdp: dict[str, Any] | None, fallback: str) -> str:
    if not sdp:
        return fallback
    suites = sdp.get("cryptoSuites") or []
    crypto = f"with a=crypto ({', '.join(suites)})" if suites else "without a=crypto"
    return f"{sdp.get('profile')} {crypto}"


def signaling_text(transport: str, port: int) -> str:
    return f"{transport.upper()} {port}"


def classify(probe: dict[str, Any], port: int, result: Any) -> dict[str, Any]:
    """What one call offered and what the edge answered, from the driver's result."""
    sdp = result.sdp or {}
    offer, answer = sdp.get("offer"), sdp.get("answer")
    srtp = result.srtp or {}
    status = result.final_status
    answered = bool(result.answered or (status is not None and 200 <= status < 300))
    if not result.started:
        outcome = "not-run"
    elif result.error in FATAL_ERRORS:
        outcome = "error"
    elif not answered and status in (401, 407):
        outcome = "unauthorized"
    elif answered:
        outcome = "answered"
    elif status is not None and status >= 300:
        outcome = "refused"
    else:
        outcome = "no-answer"
    return {
        "probe": probe["id"],
        "signaling": signaling_text(probe["transport"], port),
        "transport": probe["transport"],
        "requested": probe["srtp"],
        "outcome": outcome,
        "status": status,
        "offered": describe(offer, OFFER_TEXT[probe["srtp"]] + " (requested; the offer was not observed)"),
        "offeredObserved": offer is not None,
        "answered": describe(answer, "no SDP answer observed") if outcome == "answered" else None,
        "answerProfile": answer.get("profile") if answer else None,
        "answerCrypto": bool(answer and answer.get("cryptoSuites")),
        "srtpActive": bool(srtp.get("active")) and outcome == "answered",
        "suite": srtp.get("suite"),
        "error": result.error,
        "connectedSeconds": result.connected_seconds,
        "hangup": result.hangup,
        "secureSignaling": probe["transport"] == "tls",
        "warnings": list(result.warnings),
    }


def _evidence(row: dict[str, Any]) -> list[dict[str, Any]]:
    items = [ev("offered", f"{LABEL[row['probe']]} over {row['signaling']}: {row['offered']}")]
    if row["outcome"] == "answered":
        active = f"; SRTP active ({row['suite']})" if row["srtpActive"] else "; SRTP not active"
        items.append(ev("answered", f"status {row['status']}: {row['answered']}{active}"))
    elif row["status"] is not None:
        items.append(ev("answered", f"status {row['status']} (call not answered)"))
    else:
        items.append(ev("answered", f"no final answer ({row['outcome']})"))
    return items


def _summary(rows: list[dict[str, Any]]) -> str:
    parts = []
    for row in rows:
        if row["outcome"] == "answered":
            how = f"answered, SRTP active ({row['suite']})" if row["srtpActive"] else (
                f"answered with {row['answerProfile'] or 'no'} media, no SRTP")
        elif row["outcome"] == "refused":
            how = f"refused {row['status']}"
        else:
            how = row["outcome"] + (f" ({row['error']})" if row["error"] else "")
        parts.append(f"{LABEL[row['probe']]} over {row['signaling']}: {how}")
    return "; ".join(parts)


def assess(rows: list[dict[str, Any]], *, srtp_expected: bool) -> list[dict[str, Any]]:
    by_id = {row["probe"]: row for row in rows}
    findings: list[dict[str, Any]] = []
    plain = by_id.get("plain-rtp")
    if plain and plain["outcome"] == "answered":
        findings.append(finding(
            "srtp-policy.plain-rtp-accepted",
            f"A call offering only {plain['offered']} over {plain['signaling']} was answered "
            f"({plain['status']}); the edge does not require SRTP.",
            _evidence(plain), severity="medium" if srtp_expected else "low",
        ))
    sdes = by_id.get("sdes-mandatory")
    if sdes and sdes["outcome"] == "answered":
        if not sdes["srtpActive"]:
            findings.append(finding(
                "srtp-policy.downgrade",
                f"A mandatory SRTP offer ({sdes['offered']}) was answered {sdes['status']} with "
                f"{sdes['answered']}: the call was downgraded to unprotected media.",
                _evidence(sdes),
            ))
        elif not sdes["secureSignaling"]:
            findings.append(finding(
                "srtp-policy.keys-over-cleartext",
                f"The edge accepted an SDES offer over {sdes['signaling']} (cleartext): the SRTP key "
                "travelled in the SDP where a path observer can read it.",
                _evidence(sdes),
            ))
    elif sdes and sdes["outcome"] == "refused":
        findings.append(finding(
            "srtp-policy.sdes-not-accepted",
            f"The SDES offer ({sdes['offered']}) over {sdes['signaling']} was refused with {sdes['status']}.",
            _evidence(sdes),
        ))
    clear = by_id.get("sdes-over-cleartext")
    if clear and clear["outcome"] == "answered" and clear["srtpActive"]:
        findings.append(finding(
            "srtp-policy.keys-over-cleartext",
            f"The edge accepted an SDES offer over {clear['signaling']} even though its signaling is "
            "TLS: the SRTP key travelled in the SDP where a path observer can read it.",
            _evidence(clear),
        ))
    return findings


def _spend_and_call(ctx: Context, probe: dict[str, Any], port: int, call: Any, place: Any,
                    log_path: Path) -> tuple[Any, int]:
    cost = catalog.srtp_call_cost(probe["transport"])
    what = f"softphone call ({probe['id']})"
    ctx.budget.reserve(what, cost)
    result = None
    try:
        result = place(call, password=ctx.password, cancel=ctx.cancel, pjsua=ctx.pjsua,
                       environment=ctx.call_environment)
    finally:
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
        except OSError:
            text = ""
        if result is not None and not result.started:
            actual = 0  # PJSUA never ran
        elif text:
            actual = count_requests(text, probe["transport"])
        else:
            actual = cost  # nothing proves it sent fewer than reserved
        ctx.budget.settle(what, cost, actual)
    return result, actual


def run(ctx: Context) -> CheckResult:
    from sippycup.tls_trust import write_private_copy
    from sippycup_softphone.driver import (
        SoftphoneAccount, SoftphoneCall, SoftphoneError, build_config, place_call,
    )

    place = ctx.place_call or place_call
    account = ctx.section["account"]
    destination = ctx.section["destination"]
    probes = catalog.srtp_probes(ctx.endpoint.transport, ctx.section)
    temporary = None
    if ctx.run_dir is not None:
        directory = Path(ctx.run_dir) / "srtp-policy"
        directory.mkdir(mode=0o700, exist_ok=True)
    else:
        temporary = tempfile.TemporaryDirectory(prefix="sippycup-srtp-policy-")
        directory = Path(temporary.name)
    rows: list[dict[str, Any]] = []
    stop: str | None = None
    problem: str | None = None
    not_run: list[str] = []
    try:
        local = ctx.local_address
        if local is None:
            try:
                from sippycup_workbench.call import _local_address

                local = _local_address(ctx.endpoint.address, ctx.endpoint.port)
            except OSError:
                local = None
        silence = write_silence(directory / "silence.wav")
        ca_copy = None
        if ctx.endpoint.ca_data is not None and any(item["transport"] == "tls" for item in probes):
            ca_copy = write_private_copy(ctx.endpoint.ca_data, directory / "trust-anchor.pem")
        for probe in probes:
            if problem is not None or stop is not None:
                not_run.append(probe["id"])
                continue
            port = probe["port"] or ctx.endpoint.port
            lapsed = ctx.recheck()
            if lapsed:
                stop = f"authorization lapsed: {lapsed}"
                not_run.append(probe["id"])
                continue
            tls = probe["transport"] == "tls"
            call = SoftphoneCall(
                destination=destination,
                host=ctx.endpoint.address,
                port=port,
                transport=probe["transport"],
                play_file=silence,
                record_file=directory / f"{probe['id']}-heard.wav",
                duration_seconds=CALL_SECONDS,
                log_file=directory / f"{probe['id']}.log",
                console_file=directory / f"{probe['id']}-console.txt",
                account=SoftphoneAccount(username=account, realm="*", registrar=None),
                answer_timeout_seconds=ctx.answer_timeout,
                allowed_media_addresses=tuple(ctx.approved_addresses) or (ctx.endpoint.address,),
                advertised_address=local,
                tls_server_name=ctx.endpoint.server_name if tls else None,
                tls_ca_file=ca_copy if tls else None,
                srtp=probe["srtp"],
            )
            try:
                build_config(call)  # the driver's own validation, before anything is charged or sent
                result, requests = _spend_and_call(ctx, probe, port, call, place, call.log_file)
            except SoftphoneError as error:
                problem = f"the {probe['id']} call could not be expressed to the softphone: {error}"
                not_run.append(probe["id"])
                continue
            row = classify(probe, port, result)
            row["requests"] = requests
            rows.append(row)
            ctx.note(CHECK, "call", probe=row)
            (directory / f"{probe['id']}.json").write_text(
                json.dumps(result.as_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
            if row["outcome"] == "unauthorized":
                problem = (f"the reviewed credentials were not accepted ({row['status']}) on the "
                           f"{probe['id']} call; nothing was retried and no further call was placed")
            elif row["outcome"] == "not-run":
                problem = "the softphone (pjsua) did not start; no call was placed"
            elif row["error"] in SCOPE_ERRORS:
                stop = f"call stopped: {row['error']}"
            elif row["outcome"] == "error":
                problem = f"the {probe['id']} call ended with {row['error']}; nothing concluded"
    finally:
        if temporary is not None:
            temporary.cleanup()
    detail = {"calls": rows, "notRun": not_run, "callSeconds": CALL_SECONDS,
              "media": "digital silence, one second, hung up by the softphone"}
    if stop is not None:
        return CheckResult(CHECK, "error", f"{stop}; {_summary(rows) or 'no call completed'}", detail=detail, stop=stop)
    if not any(item["outcome"] in ("answered", "refused") for item in rows):
        return CheckResult(CHECK, "error", quote(problem or f"no call was answered or refused; nothing concluded: {_summary(rows)}"),
                           detail=detail)
    findings = assess(rows, srtp_expected=ctx.srtp_expected)
    summary = _summary(rows)
    if not_run:
        summary += f"; NOT RUN: {', '.join(not_run)}" + (f" ({problem})" if problem else "")
    if ctx.endpoint.transport == "tls" and len(probes) < 3:
        summary += "; SDES over cleartext not tested (no approved cleartext endpoint)"
        detail["sdesOverCleartext"] = "not tested: security_checks.cleartext_endpoints is empty"
    inconclusive = [item["probe"] for item in rows if item["outcome"] in ("no-answer", "error")]
    if inconclusive:
        summary += f"; INCONCLUSIVE: {', '.join(inconclusive)}"
    if findings:
        return CheckResult(CHECK, "finding", summary, findings, detail)
    if inconclusive or not_run:
        # Never a clean pass over calls that did not give an answer.
        return CheckResult(CHECK, "error", "incomplete, nothing concluded for every call: " + summary, detail=detail)
    return CheckResult(CHECK, "passed", summary, detail=detail)
