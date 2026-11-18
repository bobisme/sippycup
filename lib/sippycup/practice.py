"""Host-side helpers for the optional loopback-only practice target.

The practice target is a disposable Asterisk server that listens only on a
loopback address inside its own network namespace. These helpers validate that
address, generate the per-`up` state under the ignored ``work/practice``
directory, and render the ready-made rehearsal artifacts from the templates in
``examples/practice``. They never contact the network and never place the
generated password in argv, output, or connection facts.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import re
import secrets
import struct
import sys
import tempfile
import wave
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

CONNECTION_SCHEMA = "sippycup.dev/practice-connection/v1"
DEFAULT_ADDRESS = "127.0.0.2"
CALLER_ADDRESS = "127.0.0.1"
ACCOUNT = "practice"
DNS_NAME = "sippycup-practice"
APPROVAL_ID = "LOCAL-PRACTICE-ONLY"
VALIDITY = timedelta(hours=4)
SIGNALING_PORTS = {"udp": 5060, "tcp": 5060, "tls": 5061}
RTP_PORTS = {"start": 20000, "end": 20019}
CALLER_SIP_PORT = 5070
CALLER_RTP_PORT = 4000
# The practice proxy (bn-2g0): Kamailio on its own loopback address in the
# same namespace, in front of Asterisk. It challenges INVITE with 407 in its
# own realm, Record-Routes, and forwards to Asterisk, so the media address in
# the answer (the practice address) differs from the signaling address.
DEFAULT_PROXY_ADDRESS = "127.0.0.3"
PROXY_DNS_NAME = "sippycup-proxy"
PROXY_REALM = "sippycup-proxy"
PROXY_POLICY = (
    "REGISTER is answered by the proxy after 401 (realm sippycup-proxy); INVITE "
    "is challenged with 407 Proxy-Authenticate (same realm) and forwarded over "
    "TLS to Asterisk with Record-Route (two entries when the transport changes); "
    "in-dialog requests must carry the proxy's Route or get 404; OPTIONS is "
    "answered 200 OK by the proxy; a request flood from one source gets 503"
)
DESTINATIONS = {
    "echo": "answers and echoes received audio (alias 600)",
    "tone": "answers and plays the canary-v1 callee_to_caller prompt three times (alias 601)",
    "busy": "rejects before answer with 486 Busy Here (alias 486)",
    "decline": "rejects before answer with 603 Decline (alias 603)",
    "dtmf": (
        "answers with a steady 425 Hz tone, collects up to 32 RFC 4733 digits (4 s inter-digit "
        "timeout), and sends the same digits back as RFC 4733 events (alias 602)"
    ),
}
# Destinations that misbehave on purpose (bn-20l); `practice-target drill`
# rehearses each one. Shown by `practice-target info` after the four above.
FAULT_DESTINATIONS = {
    "noanswer": "rings (180) and never answers; the caller's answer timeout fires",
    "late": "rings for 12 s, then answers and echoes (--answer-timeout both sides)",
    "silent": "answers and sends no RTP at all while still receiving",
    "silence": "answers and sends RTP that is digital silence (packets flow, no audio)",
    "drop": "answers, echoes for 3 s, then hangs up from the server side (BYE from the peer)",
    "unavailable": "rejects before answer with 503 Service Unavailable",
    "forbidden": "rejects before answer with 403 Forbidden",
    "ratelimit": "rejects before answer with 429 Too Many Requests",
    "earlymedia": "183 Session Progress with 3 s of early media, then answers and echoes",
}
FAULT_ACCOUNTS = {
    "practice-srtp": "same password; demands SDES-SRTP, so a plain-RTP offer gets 488 (dial any destination)",
}
DESTINATIONS.update(FAULT_DESTINATIONS)
# What the practice profiles approve for --dial (target.approved_destinations
# in examples/practice/target-profile*.template.yaml; a unit test keeps the
# templates equal to this). The dial plan's numeric aliases are included, and
# so is MISSING_DESTINATION, which the dial plan deliberately lacks: dialing it
# is the drill's 404 `call-not-found` scenario, the case of a destination the
# owner approved but did not provision. Anything else (a typo such as `ecoh`)
# is refused by `call` and `matrix` before a packet is sent.
DESTINATION_ALIASES = ("600", "601", "602", "486", "603")
MISSING_DESTINATION = "nobody-home"
PROFILE_DESTINATIONS = (*DESTINATIONS, *DESTINATION_ALIASES, MISSING_DESTINATION)
UNAUTHENTICATED_POLICY = (
    "Every INVITE and REGISTER without valid Digest credentials is challenged "
    "with 401 Unauthorized; OPTIONS is answered 200 OK without credentials; "
    "an unknown destination user returns 404 after authentication."
)
STATE_FILES = {
    "password": "account.password",
    "ca": "ca.crt",
    "server_certificate": "server.crt",
    "profile": "target-profile.yaml",
    "profile_tls": "target-profile-tls.yaml",
    "campaign": "campaign.yaml",
    "campaign_tls": "campaign-tls.yaml",
    "expectations": "expectations.yaml",
    "uac": "uac.cfg",
    "uac_tls": "uac-tls.cfg",
    "uac_srtp": "uac-srtp.cfg",
    "phrase": "phrase.wav",
    "connection": "connection.json",
    # The practice proxy (bn-2g0).
    "proxy_certificate": "proxy.crt",
    "profile_proxy": "target-profile-proxy.yaml",
    "profile_proxy_tls": "target-profile-proxy-tls.yaml",
    "campaign_proxy": "campaign-proxy.yaml",
    "expectations_proxy": "expectations-proxy.yaml",
    # Matrix-ready copies of the four profiles (bn-3lq): same approval, but a
    # call limit sized for a small grid. The one-call profiles are untouched.
    "profile_matrix": "target-profile-matrix.yaml",
    "profile_matrix_tls": "target-profile-matrix-tls.yaml",
    "profile_matrix_proxy": "target-profile-matrix-proxy.yaml",
    "profile_matrix_proxy_tls": "target-profile-matrix-proxy-tls.yaml",
}
MATRIX_MAX_CALLS = 12
# (one-call profile, matrix-ready profile) pairs, in `info` order.
MATRIX_PROFILES = (
    ("target-profile.yaml", "target-profile-matrix.yaml"),
    ("target-profile-tls.yaml", "target-profile-matrix-tls.yaml"),
    ("target-profile-proxy.yaml", "target-profile-matrix-proxy.yaml"),
    ("target-profile-proxy-tls.yaml", "target-profile-matrix-proxy-tls.yaml"),
)
MATRIX_NOTE = (
    "# Matrix-ready variant (bn-3lq) of the one-call practice profile rendered next to\n"
    "# it by the same `practice-target up`: the same approval id, addresses, and window,\n"
    "# but limits.max_calls is %d so `matrix plan|run` accepts a small grid, and\n"
    "# features.srtp is true so the grid can include SDES-SRTP rows. Calls are still\n"
    "# one at a time and at least 1 s apart. The one-call profile is unchanged.\n"
)
# Files that carry the password or are regenerated by every `up`.
SECRET_FILES = ("account.password", "uac.cfg", "uac-tls.cfg", "uac-srtp.cfg")
_PLACEHOLDER = re.compile(r"@[A-Z_]+@")
_SILENCE_THRESHOLD = 104


class PracticeError(ValueError):
    """The practice target cannot be prepared safely."""


def validate_address(text: str) -> str:
    """Return the canonical practice address or refuse a non-loopback one."""
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise PracticeError(
            f"practice address must be a literal IPv4 loopback address: {text!r}"
        ) from exc
    if address.version != 4 or not address.is_loopback:
        raise PracticeError(
            f"refusing to bind the practice target to {address}: only IPv4 "
            "loopback addresses (127.0.0.0/8) inside the target's private "
            "network namespace are allowed, never a routable address"
        )
    if str(address) == CALLER_ADDRESS:
        raise PracticeError(
            "127.0.0.1 is the caller's source address; use a distinct loopback "
            "address such as 127.0.0.2 so captures show call direction"
        )
    if str(address) in {"127.0.0.0", "127.255.255.255"}:
        raise PracticeError(f"{address} is not a usable host address")
    return str(address)


def state_dir(project_dir: str | Path) -> Path:
    return Path(project_dir) / "work" / "practice"


def _ensure_state_dir(project_dir: str | Path) -> Path:
    work = Path(project_dir) / "work"
    if not work.is_dir() or work.is_symlink():
        raise PracticeError(f"work directory must be a real directory: {work}")
    state = state_dir(project_dir)
    if state.is_symlink():
        raise PracticeError(f"refusing a symlinked practice state directory: {state}")
    state.mkdir(mode=0o700, exist_ok=True)
    state.chmod(0o700)
    return state


def write_private(path: Path, data: str | bytes, mode: int = 0o600) -> None:
    """Atomically replace ``path`` with ``data`` created at ``mode``."""
    payload = data.encode("utf-8") if isinstance(data, str) else data
    if path.is_symlink():
        raise PracticeError(f"refusing to write through a symlink: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def render(template: str, values: dict[str, str]) -> str:
    rendered = template
    for key, value in values.items():
        rendered = rendered.replace(f"@{key}@", value)
    leftover = _PLACEHOLDER.search(rendered)
    if leftover:
        raise PracticeError(f"template placeholder was not rendered: {leftover.group(0)}")
    return rendered


def _template(project_dir: str | Path, name: str) -> str:
    return (Path(project_dir) / "examples" / "practice" / name).read_text(encoding="utf-8")


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def uac_options(variant: str, address: str) -> tuple[str, str]:
    """Return the registrar URI and extra PJSUA lines for a transport variant."""
    if variant == "udp":
        return f"sip:{address}:{SIGNALING_PORTS['udp']}", "--no-tcp"
    if variant == "tls":
        return (
            f"sip:{address}:{SIGNALING_PORTS['tls']};transport=tls",
            "\n".join(
                (
                    "--use-tls",
                    "--tls-ca-file /work/practice/ca.crt",
                    "--tls-verify-server",
                    "--no-tcp",
                )
            ),
        )
    if variant == "srtp":
        return (
            f"sip:{address}:{SIGNALING_PORTS['udp']}",
            "\n".join(("--no-tcp", "--use-srtp 2", "--srtp-secure 0")),
        )
    raise PracticeError(f"unknown softphone variant: {variant}")


def render_uac(
    project_dir: str | Path,
    *,
    address: str,
    password: str,
    variant: str = "udp",
    play_file: str = "/work/practice/phrase.wav",
    rec_file: str = "/work/practice/heard.wav",
    log_file: str = "/work/practice/pjsua.log",
    duration: int = 8,
    ca_file: str | None = None,
) -> str:
    registrar, extra = uac_options(variant, address)
    if ca_file is not None:
        extra = extra.replace("/work/practice/ca.crt", ca_file)
    return render(
        _template(project_dir, "uac.cfg.template"),
        {
            "ACCOUNT": ACCOUNT,
            "ADDRESS": address,
            "CALLER_ADDRESS": CALLER_ADDRESS,
            "CALLER_SIP_PORT": str(CALLER_SIP_PORT),
            "CALLER_RTP_PORT": str(CALLER_RTP_PORT),
            "REGISTRAR": registrar,
            "PASSWORD": password,
            "PLAY_FILE": play_file,
            "REC_FILE": rec_file,
            "LOG_FILE": log_file,
            "DURATION": str(duration),
            "VARIANT_OPTIONS": extra,
        },
    )


def _ulaw_to_linear(value: int) -> int:
    value = ~value & 0xFF
    sign = value & 0x80
    exponent = (value >> 4) & 0x07
    mantissa = value & 0x0F
    sample = (((mantissa << 3) + 0x84) << exponent) - 0x84
    return -sample if sign else sample


def ulaw_to_wav(source: Path, destination: Path) -> None:
    encoded = source.read_bytes()
    pcm = b"".join(struct.pack("<h", _ulaw_to_linear(byte)) for byte in encoded)
    temporary = destination.with_name(f".{destination.name}.tmp")
    with wave.open(str(temporary), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(8000)
        output.writeframes(pcm)
    temporary.chmod(0o644)
    os.replace(temporary, destination)


def wav_activity(path: str | Path) -> dict[str, Any]:
    """Summarize a 16-bit PCM WAV without exposing its content."""
    with wave.open(str(path), "rb") as source:
        if source.getsampwidth() != 2:
            raise PracticeError(f"{path} is not 16-bit PCM")
        channels = source.getnchannels()
        rate = source.getframerate()
        frames = source.readframes(source.getnframes())
    count = len(frames) // 2
    if count == 0:
        return {"seconds": 0.0, "rms": 0.0, "peak": 0, "active_fraction": 0.0}
    samples = struct.unpack(f"<{count}h", frames[: count * 2])
    peak = max(abs(sample) for sample in samples)
    active = sum(1 for sample in samples if abs(sample) >= _SILENCE_THRESHOLD)
    rms = math.sqrt(sum(sample * sample for sample in samples) / count)
    return {
        "seconds": round(count / channels / rate, 3),
        "rms": round(rms, 1),
        "peak": peak,
        "active_fraction": round(active / count, 4),
    }


def matrix_commands(files: dict[str, str]) -> dict[str, list[str]]:
    """The exact matrix commands for the direct and the proxied profile pair."""
    grid = "--dial echo --codecs PCMU,PCMA,G722 --srtp off,mandatory --max-calls %d" % MATRIX_MAX_CALLS
    out: dict[str, list[str]] = {}
    for label, udp, tls in (
        ("direct", files["profile_matrix"], files["profile_matrix_tls"]),
        ("proxy", files["profile_matrix_proxy"], files["profile_matrix_proxy_tls"]),
    ):
        pair = f"{udp} {tls}"
        out[label] = [
            f"./bin/sippycup matrix plan {pair} {grid}",
            f"./bin/sippycup --practice matrix run {pair} {grid} "
            f"--username {ACCOUNT} --secret-file {files['password']} --duration 4",
        ]
    return out


def connection_facts(
    *,
    address: str,
    container: str,
    image: str,
    started: datetime,
    valid_until: datetime,
    proxy_address: str = DEFAULT_PROXY_ADDRESS,
) -> dict[str, Any]:
    files = {key: f"work/practice/{name}" for key, name in STATE_FILES.items()}
    return {
        "schema_version": CONNECTION_SCHEMA,
        "container": container,
        "image": image,
        "network": "private namespace with loopback only (--network=none)",
        "join_with": "./bin/sippycup --practice COMMAND",
        "address": address,
        "dns_name": DNS_NAME,
        "caller_address": CALLER_ADDRESS,
        "signaling": {
            "udp": f"{address}:{SIGNALING_PORTS['udp']}",
            "tcp": f"{address}:{SIGNALING_PORTS['tcp']}",
            "tls": f"{address}:{SIGNALING_PORTS['tls']}",
        },
        "rtp_ports": dict(RTP_PORTS),
        "codecs": ["PCMU", "PCMA"],
        "media": ["RTP/AVP", "SDES-SRTP (offer a=crypto)"],
        "account": {"user": ACCOUNT, "realm": DNS_NAME, "domain": address},
        "destinations": {
            name: {"uri": f"sip:{name}@{address}", "behavior": behavior}
            for name, behavior in DESTINATIONS.items()
        },
        "fault_accounts": dict(FAULT_ACCOUNTS),
        "unauthenticated": UNAUTHENTICATED_POLICY,
        "files": files,
        "container_files": {
            key: f"/work/practice/{name}" for key, name in STATE_FILES.items()
        },
        "started_utc": _timestamp(started),
        "profile_valid_until_utc": _timestamp(valid_until),
        "authorization": (
            f"{APPROVAL_ID}: this profile names only a loopback address inside "
            "the practice namespace and cannot authorize traffic to any real host"
        ),
        "network_activity": False,
        "matrix": {
            "max_calls": MATRIX_MAX_CALLS,
            "profiles": {
                "direct": [files["profile_matrix"], files["profile_matrix_tls"]],
                "proxy": [files["profile_matrix_proxy"], files["profile_matrix_proxy_tls"]],
            },
            "commands": matrix_commands(files),
            "note": "12 cells = udp,tls x srtp off,mandatory x PCMU,PCMA,G722; the practice "
            "endpoints refuse G722 (488), so those 4 cells fail by design",
        },
        "proxy": {
            "address": proxy_address,
            "server": "Kamailio (Debian package) in the same loopback namespace",
            "dns_name": PROXY_DNS_NAME,
            "signaling": {
                "udp": f"{proxy_address}:{SIGNALING_PORTS['udp']}",
                "tcp": f"{proxy_address}:{SIGNALING_PORTS['tcp']}",
                "tls": f"{proxy_address}:{SIGNALING_PORTS['tls']}",
            },
            "media_address": address,
            "approved_addresses": [proxy_address, address],
            "account": {"user": ACCOUNT, "realm": PROXY_REALM, "domain": proxy_address},
            "policy": PROXY_POLICY,
            "destinations": "the same destinations, dialed at the proxy address "
            f"(for example sip:echo@{proxy_address})",
        },
    }


def matrix_variant(text: str) -> str:
    """The matrix-ready form of a rendered one-call practice profile.

    Only four lines change: the profile name, ``limits.max_calls``, the capture
    file name, and ``features.srtp`` (true). Anything else that does not match
    exactly is refused, so a template edit cannot silently skip a change.
    """
    edits = (
        (r"(?m)^name: (\S+)$", r"name: \1-matrix"),
        (r"(?m)^  max_calls: 1$", f"  max_calls: {MATRIX_MAX_CALLS}"),
        (r"(?m)^  output: (work/practice/call[a-z-]*)\.pcap$", r"  output: \1-matrix.pcap"),
        (r"(?m)^  srtp: (?:true|false)$", "  srtp: true"),
    )
    for pattern, replacement in edits:
        text, count = re.subn(pattern, replacement, text)
        if count != 1:
            raise PracticeError(f"cannot derive a matrix profile: {pattern!r} matched {count} times")
    return MATRIX_NOTE % MATRIX_MAX_CALLS + text


def prepare(
    project_dir: str | Path,
    *,
    address: str,
    container: str,
    image: str,
    now: datetime | None = None,
    proxy_address: str = DEFAULT_PROXY_ADDRESS,
) -> dict[str, Any]:
    """Create fresh per-`up` state and return the public connection facts."""
    address = validate_address(address)
    proxy_address = validate_address(proxy_address)
    if proxy_address == address:
        raise PracticeError("the proxy address must differ from the practice address")
    project = Path(project_dir)
    state = _ensure_state_dir(project)
    started = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    valid_from = started - timedelta(minutes=1)
    valid_until = started + VALIDITY

    for name in (*SECRET_FILES, "ca.crt", "server.crt", "proxy.crt", "connection.json"):
        path = state / name
        if path.is_symlink() or path.exists():
            path.unlink()

    password = secrets.token_urlsafe(24)
    write_private(state / "account.password", password + "\n")

    values = {
        "ADDRESS": address,
        "CALLER_ADDRESS": CALLER_ADDRESS,
        "APPROVAL_ID": APPROVAL_ID,
        "VALID_FROM": _timestamp(valid_from),
        "VALID_UNTIL": _timestamp(valid_until),
        "DNS_NAME": DNS_NAME,
        "PROXY_ADDRESS": proxy_address,
        "PROXY_DNS_NAME": PROXY_DNS_NAME,
    }
    write_private(
        state / "target-profile.yaml",
        render(_template(project, "target-profile.template.yaml"), values),
    )
    # The TLS variants pin the same literal address and add the reviewed
    # server name sippycup-practice and the per-`up` CA as the trust anchor.
    write_private(
        state / "target-profile-tls.yaml",
        render(_template(project, "target-profile-tls.template.yaml"), values),
    )
    write_private(state / "campaign.yaml", render(_template(project, "campaign.yaml"), values))
    write_private(
        state / "campaign-tls.yaml", render(_template(project, "campaign-tls.yaml"), values)
    )
    write_private(
        state / "expectations.yaml",
        render(_template(project, "expectations.yaml"), values),
    )
    for variant, name in (("udp", "uac.cfg"), ("tls", "uac-tls.cfg"), ("srtp", "uac-srtp.cfg")):
        write_private(
            state / name,
            render_uac(
                project,
                address=address,
                password=password,
                variant=variant,
                rec_file="/work/practice/heard.wav" if variant == "udp"
                else f"/work/practice/heard-{variant}.wav",
                log_file="/work/practice/pjsua.log" if variant == "udp"
                else f"/work/practice/pjsua-{variant}.log",
            ),
        )
    del password
    # The practice proxy's artifacts (bn-2g0): both the proxy (signaling) and
    # the practice address (media) are approved.
    for template, name in (
        ("target-profile-proxy.template.yaml", "target-profile-proxy.yaml"),
        ("target-profile-proxy-tls.template.yaml", "target-profile-proxy-tls.yaml"),
        ("campaign-proxy.yaml", "campaign-proxy.yaml"),
        ("expectations-proxy.yaml", "expectations-proxy.yaml"),
    ):
        write_private(state / name, render(_template(project, template), values))
    for source_name, matrix_name in MATRIX_PROFILES:
        write_private(
            state / matrix_name,
            matrix_variant((state / source_name).read_text(encoding="utf-8")),
        )
    archive_approvals(state, started)
    ulaw_to_wav(
        project / "media" / "canary-v1" / "caller_to_callee.pcmu",
        state / "phrase.wav",
    )
    facts = connection_facts(
        address=address,
        container=container,
        image=image,
        started=started,
        valid_until=valid_until,
        proxy_address=proxy_address,
    )
    write_private(state / "connection.json", json.dumps(facts, indent=2, sort_keys=True) + "\n")
    return facts


APPROVALS_DIR = "approvals"
APPROVED_PROFILES = (
    "target-profile.yaml",
    "target-profile-tls.yaml",
    "target-profile-proxy.yaml",
    "target-profile-proxy-tls.yaml",
    "target-profile-matrix.yaml",
    "target-profile-matrix-tls.yaml",
    "target-profile-matrix-proxy.yaml",
    "target-profile-matrix-proxy-tls.yaml",
)


def archive_approvals(state: Path, started: datetime) -> list[Path]:
    """Keep an immutable dated copy of each practice approval that `up` issued.

    Every `up` issues a new LOCAL-PRACTICE-ONLY window and overwrites the
    current profiles. Runs placed under an earlier window still need the record
    that authorized them, so `summary` can check them against it after a
    restart. The copies live in ``work/practice/approvals/``; they are created
    exclusively, never rewritten, and ``down`` keeps them (they hold no secret).
    """
    archive = state / APPROVALS_DIR
    if archive.is_symlink():
        raise PracticeError(f"refusing a symlinked practice approvals directory: {archive}")
    archive.mkdir(mode=0o700, exist_ok=True)
    stamp = started.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    written = []
    existing = {
        item.read_bytes()
        for item in archive.iterdir()
        if item.suffix == ".yaml" and item.is_file() and not item.is_symlink()
    }
    for name in APPROVED_PROFILES:
        source = state / name
        if not source.is_file():
            continue
        data = source.read_bytes()
        if data in existing:
            continue  # this approval is already on record (an idempotent re-archive)
        for attempt in range(1, 100):
            suffix = "" if attempt == 1 else f"-{attempt}"
            path = archive / f"{stamp}{suffix}-{name}"
            try:
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                continue
            with os.fdopen(descriptor, "wb") as output:
                output.write(data)
            written.append(path)
            break
    return written


def record_build(project_dir: str | Path, *, image: str, image_id: str) -> None:
    """Record the built image so the runtime-free doctor can report it."""
    state = _ensure_state_dir(project_dir)
    record = {
        "image": image,
        "image_id": image_id,
        "built_utc": _timestamp(datetime.now(timezone.utc)),
    }
    write_private(state / "image.json", json.dumps(record, sort_keys=True) + "\n", mode=0o644)


def remove_secrets(project_dir: str | Path) -> list[str]:
    state = state_dir(project_dir)
    removed = []
    for name in (*SECRET_FILES, "connection.json"):
        path = state / name
        if path.is_symlink() or path.exists():
            path.unlink()
            removed.append(f"work/practice/{name}")
    return removed


def load_facts(project_dir: str | Path) -> dict[str, Any]:
    path = state_dir(project_dir) / "connection.json"
    try:
        facts = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PracticeError(f"no practice connection facts at {path}: {exc}") from exc
    if not isinstance(facts, dict) or facts.get("schema_version") != CONNECTION_SCHEMA:
        raise PracticeError(f"unsupported practice connection facts: {path}")
    return facts


def render_facts_human(facts: dict[str, Any]) -> str:
    files = facts["files"]
    lines = [
        "Sippycup local practice target",
        f"Container:      {facts['container']} ({facts['network']})",
        f"Image:          {facts['image']}",
        f"Address:        {facts['address']} (DNS SAN {facts['dns_name']}); "
        f"caller source {facts['caller_address']}",
        f"UDP signaling:  {facts['signaling']['udp']}",
        f"TCP signaling:  {facts['signaling']['tcp']}",
        f"TLS signaling:  {facts['signaling']['tls']}",
        f"RTP ports:      {facts['rtp_ports']['start']}-{facts['rtp_ports']['end']} "
        f"({', '.join(facts['codecs'])}; {', '.join(facts['media'])})",
        f"Account user:   {facts['account']['user']} (realm {facts['account']['realm']})",
        f"Password file:  {files['password']} (mode 0600; never printed)",
        f"CA certificate: {files['ca']}",
        f"Target profile: {files['profile']} (valid until {facts['profile_valid_until_utc']})",
        f"TLS profile:    {files['profile_tls']} (server name {facts['dns_name']}, "
        f"CA {files['ca']}; connects only to {facts['address']})",
        f"Campaign:       {files['campaign']}",
        f"TLS campaign:   {files['campaign_tls']} (plan again after every up: the CA digest is frozen)",
        f"Expectations:   {files['expectations']}",
        f"Softphone:      {files['uac']}, {files['uac_tls']}, {files['uac_srtp']}",
        f"Caller audio:   {files['phrase']}",
        "Destinations:",
    ]
    for name, destination in facts["destinations"].items():
        lines.append(f"  {destination['uri']:<26} {destination['behavior']}")
    lines.append(f"  {'sip:' + MISSING_DESTINATION + '@' + facts['address']:<26} 404 Not Found after authentication "
                 "(notfound: not in the dial plan on purpose)")
    lines.append("  The practice profiles approve only these (and the aliases) for --dial; a typo such as "
                 "`ecoh` is refused before anything is sent.")
    for name, behavior in facts.get("fault_accounts", {}).items():
        lines.append(f"  account {name:<18} {behavior}")
    lines.append("  Rehearse every failure verdict: ./bin/sippycup practice-target drill")
    proxy = facts.get("proxy")
    if proxy:
        lines.extend(
            (
                "Proxy:          "
                f"{proxy['address']} ({proxy['server']}; DNS SAN {proxy['dns_name']})",
                f"  Signaling:    UDP {proxy['signaling']['udp']}, TCP {proxy['signaling']['tcp']}, "
                f"TLS {proxy['signaling']['tls']}",
                f"  Media:        {proxy['media_address']} (differs from the signaling address; "
                f"approve both: {', '.join(proxy['approved_addresses'])})",
                f"  Account:      {proxy['account']['user']} (realm {proxy['account']['realm']}; "
                "same password file)",
                f"  Behavior:     {proxy['policy']}",
                f"  Destinations: {proxy['destinations']}",
                f"  Profiles:     {files['profile_proxy']}, {files['profile_proxy_tls']} "
                f"(server name {proxy['dns_name']})",
                f"  Campaign:     {files['campaign_proxy']} (plan again after every up)",
                f"  Expectations: {files['expectations_proxy']}",
            )
        )
    matrix = facts.get("matrix")
    if matrix:
        lines.extend(
            (
                f"Matrix:         limits.max_calls {matrix['max_calls']}, SRTP approved; separate from the one-call "
                "profiles above (UDP + TLS pair per route; one profile per transport)",
                f"  Direct:       {', '.join(matrix['profiles']['direct'])}",
                f"  Via proxy:    {', '.join(matrix['profiles']['proxy'])}",
                f"  Note:         {matrix['note']}",
            )
        )
        for label in ("direct", "proxy"):
            plan, run = matrix["commands"][label]
            lines.extend((f"  Plan ({label}):", f"    {plan}", f"  Run ({label}):", f"    {run}"))
    lines.extend(
        (
            f"Unauthenticated: {facts['unauthenticated']}",
            f"Join:           {facts['join_with']}",
            f"Authorization:  {facts['authorization']}",
            "Network activity: none",
        )
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sippycup.practice", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("validate-address")
    check.add_argument("address")
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--project-dir", required=True)
    prepare_parser.add_argument("--address", required=True)
    prepare_parser.add_argument("--proxy-address", default=DEFAULT_PROXY_ADDRESS)
    prepare_parser.add_argument("--container", required=True)
    prepare_parser.add_argument("--image", required=True)
    info = commands.add_parser("info")
    info.add_argument("--project-dir", required=True)
    info.add_argument("--format", choices=("human", "json"), default="human")
    record = commands.add_parser("record-build")
    record.add_argument("--project-dir", required=True)
    record.add_argument("--image", required=True)
    record.add_argument("--image-id", required=True)
    clean = commands.add_parser("remove-secrets")
    clean.add_argument("--project-dir", required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "validate-address":
            print(validate_address(arguments.address))
        elif arguments.command == "prepare":
            facts = prepare(
                arguments.project_dir,
                address=arguments.address,
                container=arguments.container,
                image=arguments.image,
                proxy_address=arguments.proxy_address,
            )
            print(json.dumps(facts, sort_keys=True))
        elif arguments.command == "info":
            facts = load_facts(arguments.project_dir)
            if arguments.format == "json":
                print(json.dumps(facts, indent=2, sort_keys=True))
            else:
                print(render_facts_human(facts))
        elif arguments.command == "record-build":
            record_build(arguments.project_dir, image=arguments.image, image_id=arguments.image_id)
        elif arguments.command == "remove-secrets":
            for path in remove_secrets(arguments.project_dir):
                print(f"Removed {path}")
    except (PracticeError, OSError) as exc:
        print(f"practice-target: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
