"""Execute one frozen campaign ``call`` step with the PJSUA softphone driver.

The campaign supervisor starts this runner once per step and writes a single
JSON envelope line to standard input::

    {"step": {...}, "credentials": {"REF": "VALUE"}, "context": {...}}

The password value stays in this process's memory and is handed to
:func:`place_call`, which writes it only to a private mode-0600 file on
``/dev/shm`` that PJSUA reads and the driver deletes. It is never placed in
argv, the environment, standard output or error, or the run directory.

The runner prints exactly one bounded, secret-free JSON line that the
supervisor records as a ``step.output`` event, and exits 0 only when the call
met the frozen expectations. Any other outcome exits 1 (2 for an envelope it
cannot safely execute) so the campaign's stop conditions apply.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import shutil
import signal
import socket
import struct
import sys
import tempfile
import threading
import time
import wave
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .driver import (
    SRTP_MODES,
    SoftphoneAccount,
    SoftphoneCall,
    SoftphoneError,
    SoftphoneResult,
    place_call,
    redact,
    remove_private_directory,
    registrar_uri,
)
from .evidence import (
    DEFAULT_DTMF_AFTER_SECONDS,
    DTMF_SETTLE_SECONDS,
    DtmfError,
    dtmf_seconds,
    validate_dtmf,
)

RESULT_VERSION = "sippycup.dev/softphone-step-result/v1"
RUNNER_NAME = "campaign-softphone-runner"
MAX_ENVELOPE_BYTES = 1024 * 1024
MAX_LINE_BYTES = 4096
# Seconds reserved inside the step budget: PJSUA start plus INVITE setup
# before the call duration, and BYE/quit after it. The runner hangs up when
# only the teardown reserve remains, before the supervisor's hard deadline.
SETUP_RESERVE_SECONDS = 2.0
TEARDOWN_RESERVE_SECONDS = 1.5
REGISTRATION_RESERVE_SECONDS = 1.0
MIN_BUDGET_SECONDS = 5
DEFAULT_CALL_SECONDS = 5
MAX_ANSWER_TIMEOUT_SECONDS = 30.0
MAX_REGISTRATION_TIMEOUT_SECONDS = 10.0
DEFAULT_DIAL_USER = "service"
CODECS = {"pcmu": "PCMU", "pcma": "PCMA", "g722": "G722", "opus": "opus"}
EXIT_PASSED = 0
EXIT_FAILED = 1
EXIT_INVALID = 2

_SIP_USER = re.compile(r"[A-Za-z0-9+*][A-Za-z0-9._+*-]{0,63}")
_TX_REQUEST = re.compile(r"TX \d+ bytes Request msg (INVITE|REGISTER)/cseq=(\d+)")
_RX_RESPONSE = re.compile(
    r"(?:RX \d+ bytes|Incoming) Response msg (\d{3})/(INVITE|REGISTER)/cseq=(\d+)"
)
_AUTHORIZATION = re.compile(r"^\s*(?:proxy-)?authorization\s*:", re.I)
_END_MESSAGE = "--end msg--"


class EnvelopeError(ValueError):
    """The envelope cannot be executed safely."""


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EnvelopeError(f"{label} must be an object")
    return value


def parse_envelope(raw: bytes) -> tuple[dict[str, Any], str | None, dict[str, Any]]:
    """Return ``(step, password, context)`` from one envelope line."""
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise EnvelopeError("envelope exceeds the 1 MiB limit")
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EnvelopeError("envelope is not one JSON object") from error
    envelope = _mapping(envelope, "envelope")
    if set(envelope) != {"step", "credentials", "context"}:
        raise EnvelopeError("envelope must contain exactly step, credentials, and context")
    step = _mapping(envelope["step"], "step")
    credentials = _mapping(envelope["credentials"], "credentials")
    context = _mapping(envelope["context"], "context")
    if step.get("type") != "call":
        raise EnvelopeError("the softphone runner executes only call steps")
    reference = step.get("credentialRef")
    password = None
    if reference is None:
        if credentials:
            raise EnvelopeError("credentials were supplied for a step without a credential reference")
    else:
        if set(credentials) != {reference}:
            raise EnvelopeError("credentials do not match the step's credential reference")
        password = credentials[reference]
        if not isinstance(password, str) or not password:
            raise EnvelopeError("credential value must be a non-empty string")
        if step.get("account") is None:
            raise EnvelopeError(
                "a credential reference needs the target's account.username in the manifest"
            )
    account = step.get("account")
    if account is not None and password is None:
        raise EnvelopeError("an account requires a credential reference")
    destination = _mapping(step.get("destination"), "step.destination")
    addresses = destination.get("addresses")
    if not isinstance(addresses, list) or not addresses:
        raise EnvelopeError("step destination has no frozen address")
    for address in addresses:
        try:
            ipaddress.ip_address(address)
        except (TypeError, ValueError) as error:
            raise EnvelopeError("step destination address must be a literal IP") from error
    dial = step.get("dial")
    if dial is not None:
        dial = _mapping(dial, "step.dial")
        if set(dial) != {"user"} or not isinstance(dial["user"], str) or _SIP_USER.fullmatch(dial["user"]) is None:
            raise EnvelopeError("step dial user is invalid")
    call = step.get("call")
    if call is not None:
        call = _mapping(call, "step.call")
        if "dtmf" not in call or set(call) - {"dtmf", "dtmfAfterSeconds", "durationSeconds"}:
            raise EnvelopeError(
                "step call must contain dtmf and optionally dtmfAfterSeconds and durationSeconds"
            )
        seconds = call.get("durationSeconds", 1)
        if isinstance(seconds, bool) or not isinstance(seconds, int) or not 1 <= seconds <= 3600:
            raise EnvelopeError("step call durationSeconds is invalid")
        try:
            validate_dtmf(call["dtmf"])
        except DtmfError as error:
            raise EnvelopeError(f"step call dtmf is invalid: {error}") from error
        after = call.get("dtmfAfterSeconds", DEFAULT_DTMF_AFTER_SECONDS)
        if isinstance(after, bool) or not isinstance(after, int) or not 0 <= after <= 60:
            raise EnvelopeError("step call dtmfAfterSeconds is invalid")
    media = step.get("media")
    if media is not None:
        media = _mapping(media, "step.media")
        if set(media) != {"srtp"} or media["srtp"] not in SRTP_MODES:
            raise EnvelopeError("step media must contain exactly srtp: off, optional, or mandatory")
    tls = step.get("tls")
    if tls is not None:
        from sippycup.tls_trust import (
            TrustError,
            validate_ca_reference,
            validate_server_name,
            validate_sha256,
        )

        tls = _mapping(tls, "step.tls")
        if set(tls) != {"serverName", "caFile", "caSha256"}:
            raise EnvelopeError("step tls must contain exactly serverName, caFile, and caSha256")
        if destination.get("transport") != "tls":
            raise EnvelopeError("step tls requires transport tls")
        try:
            if tls["serverName"] is not None:
                validate_server_name(tls["serverName"])
            if (tls["caFile"] is None) != (tls["caSha256"] is None):
                raise TrustError("caFile and caSha256 must be given together")
            if tls["caFile"] is not None:
                validate_ca_reference(tls["caFile"])
                validate_sha256(tls["caSha256"])
        except TrustError as error:
            raise EnvelopeError(f"step tls is invalid: {error}") from error
    authorization = _mapping(context.get("authorization"), "context.authorization")
    media = _mapping(authorization.get("mediaPorts"), "context.authorization.mediaPorts")
    if any(type(media.get(key)) is not int for key in ("start", "end")):
        raise EnvelopeError("context media ports are invalid")
    _mapping(context.get("expectations"), "context.expectations")
    evidence = _mapping(context.get("evidence"), "context.evidence")
    if not isinstance(evidence.get("retainPayload"), bool):
        raise EnvelopeError("context retainPayload must be boolean")
    directory = context.get("artifactDirectory")
    if not isinstance(directory, str) or not Path(directory).is_absolute():
        raise EnvelopeError("context artifactDirectory must be an absolute path")
    budget = _mapping(step.get("budget"), "step.budget")
    if type(budget.get("durationSeconds")) is not int or budget["durationSeconds"] < 1:
        raise EnvelopeError("step duration budget is invalid")
    return step, password, context


def call_duration(step: Mapping[str, Any]) -> dict[str, Any]:
    """Clamp the call to the step budget; report requested and effective seconds."""
    budget = step["budget"]["durationSeconds"]
    generated = step.get("generated")
    requested = (
        int(generated["factors"]["duration"])
        if generated is not None
        else int((step.get("call") or {}).get("durationSeconds", DEFAULT_CALL_SECONDS))
    )
    reserve = SETUP_RESERVE_SECONDS + TEARDOWN_RESERVE_SECONDS
    if (step.get("account") or {}).get("register"):
        reserve += REGISTRATION_RESERVE_SECONDS
    available = max(1, int(math.floor(budget - reserve)))
    effective = min(requested, available)
    value = {
        "requested": requested,
        "effective": effective,
        "budget": budget,
        "clamped": effective < requested,
    }
    call = step.get("call")
    if call is not None:
        # The reviewed digits must fit in the call: lengthen it to the DTMF
        # delay plus the digits when the budget allows, never beyond.
        needed = int(math.ceil(
            call.get("dtmfAfterSeconds", DEFAULT_DTMF_AFTER_SECONDS)
            + dtmf_seconds(call["dtmf"])
            + DTMF_SETTLE_SECONDS
        ))
        value["dtmfNeeds"] = needed
        if effective < needed <= available:
            value["effective"] = needed
            value["lengthenedForDtmf"] = True
        value["clamped"] = value["effective"] < requested
    return value


def write_tone(path: Path, seconds: float = 3.0, rate: int = 8000) -> None:
    """Write a deterministic synthetic two-tone canary (no recorded voice)."""
    frames = bytearray()
    for index in range(int(seconds * rate)):
        frequency = 440 if (index // (rate // 2)) % 2 == 0 else 660
        frames += struct.pack("<h", int(8000 * math.sin(2 * math.pi * frequency * index / rate)))
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as raw, wave.open(raw, "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(rate)
        output.writeframes(bytes(frames))


def local_address(host: str, port: int) -> str | None:
    """The kernel's source address toward the target; UDP connect sends nothing."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as probe:
            probe.connect((host, port))
            return str(ipaddress.ip_address(probe.getsockname()[0]))
    except OSError:
        return None


def authentication_attempts(log_text: str) -> dict[str, dict[str, int]]:
    """Count credentialed INVITE/REGISTER transactions PJSUA sent and how many
    were rejected with 401, 403, or 407, from its level-5 message log.

    Transactions are keyed by CSeq, so a retransmission is not a new attempt.
    """
    authenticated: set[tuple[str, int]] = set()
    rejected: set[tuple[str, int]] = set()
    current: tuple[str, int] | None = None
    responses: list[tuple[int, str, int]] = []
    for line in log_text.splitlines():
        if (match := _TX_REQUEST.search(line)) is not None:
            current = (match.group(1), int(match.group(2)))
            continue
        if (match := _RX_RESPONSE.search(line)) is not None:
            responses.append((int(match.group(1)), match.group(2), int(match.group(3))))
            current = None
            continue
        if current is not None:
            if _END_MESSAGE in line:
                current = None
            elif _AUTHORIZATION.search(line):
                authenticated.add(current)
    for status, method, cseq in responses:
        if (method, cseq) in authenticated and status in (401, 403, 407):
            rejected.add((method, cseq))
    return {
        method: {
            "attempts": sum(1 for item in authenticated if item[0] == method),
            "rejected": sum(1 for item in rejected if item[0] == method),
        }
        for method in ("INVITE", "REGISTER")
    }


def _setup_seconds(result: SoftphoneResult) -> float | None:
    """INVITE to 2xx from PJSUA's log timestamps, else the driver timeline."""
    logged = (result.setup or {}).get("inviteToAnswerSeconds")
    if logged is not None:
        return logged
    dialed = next((item["at"] for item in result.timeline if item["state"] == "DIALED"), None)
    confirmed = next((item["at"] for item in result.timeline if item["state"] == "CONFIRMED"), None)
    if dialed is None or confirmed is None:
        return None
    return round(max(0.0, confirmed - dialed), 3)


def factor_report(
    generated: Mapping[str, Any] | None,
    result: SoftphoneResult,
    duration: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Split a generated case's factors into performed and not performed.

    A factor is listed as exercised only when this runner actively did it or
    deliberately did not do something the value names as absent (for example
    ``dtmf: none``); everything else is ``notExercised`` with a reason.
    """
    if generated is None:
        return None
    factors = generated["factors"]
    exercised: dict[str, Any] = {}
    skipped: dict[str, str] = {}
    if not result.dialed:
        return {
            "exercised": {},
            "notExercised": {name: "call was not placed" for name in sorted(factors)},
            "actions": {
                "exercised": [],
                "notExercised": [
                    {"position": position, "action": action}
                    for position, action in enumerate(generated["actions"], 1)
                ],
            },
        }
    exercised["transport"] = factors["transport"]
    exercised["addressFamily"] = factors["addressFamily"]
    wanted = CODECS[factors["codec"]]
    if result.codec is not None and result.codec.lower() == wanted.lower():
        exercised["codec"] = factors["codec"]
    else:
        skipped["codec"] = f"offered {wanted} first; negotiated {result.codec or 'nothing'}"
    skipped["ptime"] = "runner does not set packetization time"
    srtp = result.srtp or {}
    srtp_active = bool(srtp.get("active"))
    protection = factors["mediaProtection"]
    if protection == "plain" and result.answered and not srtp_active:
        exercised["mediaProtection"] = "plain"
    elif protection == "plain":
        skipped["mediaProtection"] = (
            "SDES-SRTP was active" if srtp_active else "call was not answered"
        )
    elif protection == "sdes-srtp" and srtp_active:
        exercised["mediaProtection"] = "sdes-srtp"
    elif protection == "sdes-srtp":
        skipped["mediaProtection"] = (
            f"SDES-SRTP requested {srtp.get('requested', 'off')} but not active"
            if srtp.get("requested", "off") != "off"
            else "target media.srtp is off; runner offered plain RTP"
        )
    else:
        skipped["mediaProtection"] = "runner keys SRTP with SDES only, never DTLS"
    dtmf = result.dtmf
    dtmf_sent = bool(dtmf and dtmf.get("status") == "sent")
    if factors["dtmf"] == "none" and dtmf is None:
        exercised["dtmf"] = "none"
    elif factors["dtmf"] == "none":
        skipped["dtmf"] = "runner sent the case's reviewed DTMF digits"
    elif factors["dtmf"] == "rfc4733" and dtmf_sent:
        exercised["dtmf"] = "rfc4733"
    elif factors["dtmf"] == "rfc4733":
        skipped["dtmf"] = (
            f"RFC 4733 DTMF {dtmf.get('status')}"
            if dtmf is not None
            else "no reviewed digit string (cases[].call.dtmf)"
        )
    else:
        skipped["dtmf"] = "runner sends RFC 4733 events only, never SIP INFO or in-band"
    skipped["earlyMedia"] = "callee behavior; runner does not assert early media"
    if factors["holdReinvite"] == "disabled":
        exercised["holdReinvite"] = "disabled"
    else:
        skipped["holdReinvite"] = "runner sends no hold re-INVITE"
    caller_hangup = result.answered and result.hangup in ("duration", "driver_duration_backstop")
    if factors["teardownInitiator"] == "caller" and caller_hangup:
        exercised["teardownInitiator"] = "caller"
    elif factors["teardownInitiator"] == "caller":
        skipped["teardownInitiator"] = f"call ended by {result.hangup or 'nothing observed'}"
    else:
        skipped["teardownInitiator"] = "runner always hangs up as the caller"
    if duration["clamped"]:
        skipped["duration"] = (
            f"clamped to {duration['effective']} seconds by the step budget"
        )
    elif caller_hangup and result.hangup == "duration":
        exercised["duration"] = duration["effective"]
    else:
        skipped["duration"] = "call did not run to its planned duration"
    skipped["nat"] = "network environment; runner does not create NAT"
    if factors["impairment"] == "none":
        exercised["impairment"] = "none"
    else:
        skipped["impairment"] = "runner applies no impairment"
    actions_done = []
    actions_skipped = []
    dtmf_action_done = False
    for position, action in enumerate(generated["actions"], 1):
        if action == "hangup" and caller_hangup:
            actions_done.append({"position": position, "action": action})
        elif action == "dtmf" and dtmf_sent and not dtmf_action_done:
            # One reviewed digit string per call: it covers the first
            # dtmf action only.
            dtmf_action_done = True
            actions_done.append({"position": position, "action": action})
        else:
            actions_skipped.append({"position": position, "action": action})
    return {
        "exercised": exercised,
        "notExercised": skipped,
        "actions": {"exercised": actions_done, "notExercised": actions_skipped},
    }


def evaluate(
    step: Mapping[str, Any],
    context: Mapping[str, Any],
    result: SoftphoneResult,
    attempts: Mapping[str, Mapping[str, int]],
) -> list[str]:
    """Every reason the step failed; empty when it met its expectations."""
    reasons: list[str] = []
    expectations = step.get("expectations") or {}
    expected = expectations.get("finalStatus", 200)
    if result.error:
        reasons.append(result.error)
    account = step.get("account") or {}
    if account.get("register") and result.registered is not True:
        reasons.append("registration_failed")
    if 200 <= expected < 300:
        if not result.answered:
            reasons.append("not_answered")
        if result.final_status != expected:
            reasons.append("unexpected_final_status")
        bidirectional = expectations.get(
            "requireBidirectionalRtp",
            context["expectations"].get("requireBidirectionalRtp", False),
        )
        if bidirectional and not (
            (result.rtp_tx_packets or 0) > 0 and (result.rtp_rx_packets or 0) > 0
        ):
            reasons.append("bidirectional_rtp_not_observed")
        limit = expectations.get("maxSetupSeconds")
        setup = _setup_seconds(result)
        if limit is not None and (setup is None or setup > limit):
            reasons.append("setup_slower_than_expected")
    else:
        if result.answered:
            reasons.append("unexpectedly_answered")
        if result.final_status != expected:
            reasons.append("unexpected_final_status")
    if any(item["rejected"] > 1 for item in attempts.values()):
        reasons.append("repeated_rejected_authentication")
    if step["destination"]["transport"] == "tls" and result.dialed and result.tls_verified is not True:
        reasons.append("tls_not_verified")
    return list(dict.fromkeys(reasons))


def _bounded_line(summary: dict[str, Any], secrets: Sequence[str]) -> str:
    line = redact(json.dumps(summary, sort_keys=True, separators=(",", ":")), secrets)
    if len(line.encode()) <= MAX_LINE_BYTES:
        return line
    compact = {key: value for key, value in summary.items() if key not in ("factors",)}
    compact["truncated"] = True
    line = redact(json.dumps(compact, sort_keys=True, separators=(",", ":")), secrets)
    if len(line.encode()) <= MAX_LINE_BYTES:
        return line
    minimal = {
        key: summary.get(key)
        for key in ("apiVersion", "runner", "step", "case", "outcome", "finalStatus", "error")
    }
    minimal["truncated"] = True
    return redact(json.dumps(minimal, sort_keys=True, separators=(",", ":")), secrets)


def _private_root() -> str | None:
    shm = Path("/dev/shm")
    return str(shm) if shm.is_dir() and os.access(shm, os.W_OK | os.X_OK) else None


def _write_private_json(path: Path, value: Any) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def run(
    raw: bytes,
    *,
    pjsua: str = "pjsua",
    environ: Mapping[str, str] | None = None,
    clock: Callable[[], float] = time.monotonic,
    cancel: threading.Event | None = None,
    emit: Callable[[str], None] | None = None,
    private_root: Path | None = None,
) -> int:
    """Execute one envelope and return the process exit status.

    ``private_root`` (tests) replaces ``/dev/shm`` as the parent of the
    runner's and the driver's private directories.
    """
    started = clock()
    emit = emit or (lambda line: print(line, flush=True))
    secrets: list[str] = []
    summary: dict[str, Any] = {"apiVersion": RESULT_VERSION, "runner": RUNNER_NAME}
    try:
        step, password, context = parse_envelope(raw)
    except EnvelopeError as error:
        summary.update(outcome="invalid", error=f"invalid_envelope: {error}")
        emit(_bounded_line(summary, secrets))
        return EXIT_INVALID
    if password is not None:
        secrets.append(password)
    summary.update(step=step.get("index"), case=step.get("case"))
    destination = step["destination"]
    address = str(ipaddress.ip_address(destination["addresses"][0]))
    port = destination["port"]
    transport = destination["transport"]
    budget = step["budget"]["durationSeconds"]
    dial = (step.get("dial") or {}).get("user", DEFAULT_DIAL_USER)
    summary["dial"] = {"user": dial, "default": "dial" not in step}
    summary["transport"] = transport
    if budget < MIN_BUDGET_SECONDS:
        summary.update(
            outcome="invalid",
            error=f"step budget {budget}s is below the softphone minimum of {MIN_BUDGET_SECONDS}s",
        )
        emit(_bounded_line(summary, secrets))
        return EXIT_INVALID
    duration = call_duration(step)
    summary["durationSeconds"] = duration
    retain = context["evidence"]["retainPayload"]
    summary["payloadRetained"] = retain
    artifacts = Path(context["artifactDirectory"])
    account_facts = step.get("account")
    generated = step.get("generated")
    codecs = (CODECS[generated["factors"]["codec"]],) if generated is not None else ("PCMU",)
    tls = step.get("tls") or {}
    server_name = tls.get("serverName")
    call_options = step.get("call")
    srtp_mode = (step.get("media") or {}).get("srtp", "off")
    if transport == "tls":
        summary["tls"] = {
            "verified": False,
            "serverName": server_name or address,
            "trust": "file" if tls.get("caFile") else "system",
            "caSha256": tls.get("caSha256"),
        }
    account = None
    if account_facts is not None:
        account = SoftphoneAccount(
            username=account_facts["username"],
            realm=account_facts.get("realm", "*"),
            registrar=(
                registrar_uri(address, port, transport, server_name)
                if account_facts["register"]
                else None
            ),
        )
    media = context["authorization"]["mediaPorts"]
    teardown_at = started + budget - TEARDOWN_RESERVE_SECONDS
    answer_timeout = min(
        MAX_ANSWER_TIMEOUT_SECONDS,
        max(1.0, budget - SETUP_RESERVE_SECONDS - TEARDOWN_RESERVE_SECONDS - duration["effective"]),
    )
    cancel = cancel or threading.Event()

    def abort() -> str | None:
        return "step_budget_exhausted" if clock() >= teardown_at else None

    source = environ if environ is not None else os.environ
    environment = {
        name: value
        for name, value in source.items()
        if not name.startswith("SIPPYCUP_SECRET_")
        and not any(secret in value for secret in secrets)
    }
    private = Path(tempfile.mkdtemp(
        prefix="sippycup-campaign-softphone-",
        dir=str(private_root) if private_root is not None else _private_root(),
    ))
    private.chmod(0o700)
    exit_code = EXIT_FAILED
    try:
        ca_copy = None
        if tls.get("caFile") is not None:
            from sippycup.tls_trust import TrustError, read_verified_ca, write_private_copy

            # PJSUA loads only a private copy of bytes whose digest matched
            # the frozen plan, so the reviewed file cannot change under it.
            try:
                data = read_verified_ca(tls["caFile"], tls["caSha256"])
            except TrustError as error:
                raise SoftphoneError(f"{error}; nothing was sent") from error
            ca_copy = write_private_copy(data, private / "trust-anchor.pem")
        play = private / "canary.wav"
        write_tone(play)
        if call_options is not None and duration["effective"] < duration.get("dtmfNeeds", 0):
            raise SoftphoneError(
                f"the step budget leaves {duration['effective']}s of call, but the DTMF delay "
                f"and digits need {duration['dtmfNeeds']}s"
            )
        record = (artifacts / "heard.wav") if retain else (private / "heard.wav")
        call = SoftphoneCall(
            destination=dial,
            host=address,
            port=port,
            transport=transport,
            play_file=play,
            record_file=record,
            duration_seconds=duration["effective"],
            log_file=artifacts / "softphone.log",
            console_file=artifacts / "softphone-console.txt",
            account=account,
            codecs=codecs,
            answer_timeout_seconds=answer_timeout,
            registration_timeout_seconds=min(
                MAX_REGISTRATION_TIMEOUT_SECONDS, max(1.0, budget / 3)
            ),
            allowed_media_addresses=tuple(
                str(ipaddress.ip_address(item)) for item in destination["addresses"]
            ),
            allowed_media_ports=(media["start"], media["end"]),
            pin_signaling=True,
            advertised_address=local_address(address, port),
            tls_server_name=server_name,
            tls_ca_file=ca_copy,
            dtmf=(call_options or {}).get("dtmf"),
            dtmf_after_seconds=(call_options or {}).get(
                "dtmfAfterSeconds", DEFAULT_DTMF_AFTER_SECONDS
            ),
            srtp=srtp_mode,
        )
        result = place_call(
            call,
            password=password,
            cancel=cancel,
            abort=abort,
            pjsua=pjsua,
            environment=environment,
            clock=clock,
            kill_with_parent=True,
            private_root=private_root,
        )
        try:
            log_text = (artifacts / "softphone.log").read_text(encoding="utf-8", errors="replace")
        except OSError:
            log_text = ""
        attempts = authentication_attempts(log_text)
        reasons = evaluate(step, context, result, attempts)
        expected = (step.get("expectations") or {}).get("finalStatus", 200)
        summary.update(
            outcome="failed" if reasons else "passed",
            reasons=reasons,
            registrationAttempted=result.registration_attempted,
            registered=result.registered,
            registrationStatus=result.registration_status,
            answered=result.answered,
            finalStatus=result.final_status,
            expectedFinalStatus=expected,
            connectedSeconds=result.connected_seconds,
            setupSeconds=_setup_seconds(result),
            rtp={"txPackets": result.rtp_tx_packets, "rxPackets": result.rtp_rx_packets},
            codec=result.codec,
            hangup=result.hangup,
            error=result.error,
            authentication=attempts,
            setup=result.setup,
            localRtpPort=result.local_rtp_port,
            srtp={
                key: (result.srtp or {}).get(key)
                for key in ("requested", "active", "suite", "answerProfile")
            } if result.srtp else {"requested": srtp_mode, "active": None},
            warnings=result.warnings,
        )
        if result.dtmf is not None:
            summary["dtmf"] = {
                key: result.dtmf.get(key)
                for key in (
                    "requested", "requestedDigits", "method", "status", "negotiated",
                    "sent", "received", "answeredPayloadTypes",
                )
            }
        if transport == "tls":
            summary["tls"]["verified"] = result.tls_verified is True
            summary["tls"]["detail"] = result.tls_detail
        factors = factor_report(generated, result, duration)
        if factors is not None:
            summary["factors"] = factors
        detail = {**summary, "softphone": result.as_dict()}
        _write_private_json(
            artifacts / "softphone.json",
            json.loads(redact(json.dumps(detail, sort_keys=True), secrets)),
        )
        exit_code = EXIT_FAILED if reasons else EXIT_PASSED
    except SoftphoneError as error:
        summary.update(outcome="invalid", error=f"softphone_rejected_request: {error}")
        exit_code = EXIT_INVALID
    except Exception as error:  # pragma: no cover - defensive, never leak details
        summary.update(outcome="failed", error=f"runner_error: {type(error).__name__}")
        exit_code = EXIT_FAILED
    finally:
        remove_private_directory(private)
    emit(_bounded_line(summary, secrets))
    return exit_code


def main(argv: Sequence[str] | None = None, *, pjsua: str | None = None) -> int:
    del argv  # the step arrives only on standard input
    cancel = threading.Event()

    def stop(_signum: int, _frame: object) -> None:
        cancel.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, stop)
    raw = sys.stdin.buffer.readline(MAX_ENVELOPE_BYTES + 1)
    return run(raw, pjsua=pjsua or shutil.which("pjsua") or "pjsua", cancel=cancel)
