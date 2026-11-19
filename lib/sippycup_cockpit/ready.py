"""``./bin/sippycup ready DIR``: the go/no-go check right before the first live packet.

It sends nothing to the target. It reuses the checks that already exist (the
cockpit model, which itself calls ``rehearse``, ``journal verify``, and the
scope derivative check; the image probe; the call's password-file rules; the
reviewed-CA reader) and adds what only matters on the day: the approval
window against a margin, the host clock, a loopback-only capture inside a
container started exactly the way the live commands start theirs, free disk
for evidence, the credential source, the TLS trust anchor, and the network
position read from the kernel's routing table (no packet).

Every line is GO, WARN, NO-GO, or INFO with a reason; every NO-GO names the
command (or the manual step) that fixes it. The verdict is NO-GO when any
line is NO-GO. Exit codes: 0 GO, 1 NO-GO, 2 usage error.

The result is also written to ``DIR/readiness/ready-STAMP.json`` (no secret,
mode 0600) so the cockpit can gate its LIVE actions on a GO for the current
profile.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

READY_VERSION = "sippycup.dev/ready/v1"
READINESS_DIR = "readiness"
LAUNCHER = "./bin/sippycup"
DEFAULT_MARGIN_MINUTES = 60
DEFAULT_MIN_FREE_MB = 2048
CERT_WARN_DAYS = 7
GO, WARN, NOGO, INFO = "go", "warn", "no-go", "info"
MARK = {GO: "[GO]   ", WARN: "[WARN] ", NOGO: "[NO-GO]", INFO: "[INFO] "}
VPN_PREFIXES = ("tun", "tap", "wg", "ppp", "tailscale", "zt", "utun", "ipsec", "vti", "nordlynx", "proton", "mullvad")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
MAX_SECRET_BYTES = 64 * 1024
MAX_RECORDS = 500


@dataclass
class Check:
    identifier: str
    title: str
    status: str
    lines: list[str] = field(default_factory=list)
    fix: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.identifier, "title": self.title, "status": self.status, "lines": self.lines,
                "fix": self.fix}


@dataclass
class Host:
    """Everything ``ready`` asks the host; tests replace it with fakes."""

    repo: Path
    environ: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)

    def run(self, argv: list[str], timeout: float = 30) -> tuple[int, str, str]:
        try:
            completed = subprocess.run(argv, cwd=self.repo, stdin=subprocess.DEVNULL, capture_output=True,
                                       text=True, timeout=timeout, check=False, env=dict(self.environ))
        except FileNotFoundError:
            return 127, "", f"{argv[0]}: not found"
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 124, "", str(exc)
        return completed.returncode, completed.stdout, completed.stderr

    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def disk_free(self, path: Path) -> int:
        return shutil.disk_usage(path).free

    def probe_image(self, image: str) -> dict[str, Any]:
        from .probes import probe_image

        return probe_image(self.repo, image)

    def local_zone(self) -> Any:
        return datetime.now().astimezone().tzinfo


# ---------------------------------------------------------------------------
# helpers


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _both(value: datetime | None, zone: Any) -> str:
    if value is None:
        return "unknown"
    local = value.astimezone(zone)
    return f"{local.strftime('%Y-%m-%d %H:%M:%S %Z')} ({_iso(value)})"


def _parse(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def _duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    return f"{days}d {hours:02d}h {minutes:02d}m" if days else f"{hours:02d}h {minutes:02d}m"


def file_sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def route_mode(model: dict[str, Any]) -> str:
    """The launcher option the live commands use: --practice or --isolated."""
    from .actions import practice_route

    return "--practice" if practice_route(model) else "--isolated"


# ---------------------------------------------------------------------------
# individual checks


def check_engagement(model: dict[str, Any]) -> Check:
    eng = model["engagement"]["display"]
    journal = model["journal"]
    if not model["engagement"]["exists"]:
        return Check("engagement", "Engagement record", NOGO, [f"{eng} does not exist"],
                     f"{LAUNCHER} journal init {eng} --title TITLE --owner OWNER")
    if not journal.get("valid"):
        return Check("engagement", "Engagement record", NOGO, [f"journal: {journal.get('error') or 'invalid'}"],
                     f"{LAUNCHER} journal verify {eng}   (then repair or re-create the engagement record)")
    lines = [f"journal valid, {journal.get('entries', 0)} entries (hash chain verified)"]
    missing = journal.get("missingEvidence") or []
    if missing:
        return Check("engagement", "Engagement record", WARN,
                     lines + [f"{len(missing)} journal evidence reference(s) point at missing files, e.g. {missing[0]}"],
                     f"{LAUNCHER} journal verify {eng}")
    return Check("engagement", "Engagement record", GO, lines)


def check_scope(model: dict[str, Any]) -> Check:
    eng = model["engagement"]["display"]
    scope = model["scope"]
    profile = model["profile"]
    state = scope["state"]
    if state == "complete":
        return Check("scope", "Scope compiled and current", GO,
                     [f"scope.yaml complete and consistent; derivatives {scope['derivatives']}"])
    if state == "missing" and profile["present"]:
        return Check("scope", "Scope compiled and current", WARN,
                     ["no scope.yaml: the target profile was written by hand, so nothing ties it to the owner's answers"])
    if state == "stale":
        return Check("scope", "Scope compiled and current", NOGO,
                     [f"scope.yaml changed after the last compile: {', '.join(scope['staleItems']) or 'recompile'}"],
                     f"{LAUNCHER} scope compile {eng}")
    if state == "complete-not-compiled":
        return Check("scope", "Scope compiled and current", NOGO, ["scope.yaml is complete but not compiled"],
                     f"{LAUNCHER} scope compile {eng}")
    if state == "missing":
        return Check("scope", "Scope compiled and current", NOGO, ["no scope.yaml and no target profile"],
                     f"{LAUNCHER} scope init {eng}")
    detail = [f"scope.yaml is {state}: {len(scope.get('unanswered') or [])} unanswered question(s)"]
    detail += [f"  {item}" for item in (scope.get("errors") or [])[:5]]
    return Check("scope", "Scope compiled and current", NOGO, detail, f"{LAUNCHER} scope check {eng}")


def check_profile(model: dict[str, Any]) -> Check:
    profile = model["profile"]
    eng = model["engagement"]["display"]
    if not profile["present"]:
        return Check("profile", "Profile passes rehearse", NOGO, ["no target-profile.yaml"],
                     f"{LAUNCHER} scope compile {eng}")
    if not profile["ready"]:
        return Check("profile", "Profile passes rehearse", NOGO,
                     [f"rehearse refuses it: {error}" for error in profile.get("errors") or ["not ready"]][:8],
                     f"{LAUNCHER} rehearse {eng}/target-profile.yaml   (fix scope.yaml, then scope compile {eng})")
    lines = ["rehearse: ready (approved, inside its window, literal approved address)"]
    lines += [f"rehearse warning: {item}" for item in profile.get("warnings") or []][:3]
    return Check("profile", "Profile passes rehearse", GO, lines)


def other_profiles(model: dict[str, Any]) -> list[dict[str, Any]]:
    """The compiled profiles of every further target (scope compile writes one per target)."""
    return [item for item in model.get("profiles") or [] if not item.get("first")]


def _other_profile_path(model: dict[str, Any], item: dict[str, Any]) -> Path:
    return Path(model["engagement"]["path"]) / Path(str(item["path"])).name


def check_other_profiles(host: "Host", model: dict[str, Any], mode: str, now: datetime, zone: Any) -> list[Check]:
    """One line per further target's profile: present, current, passes rehearse, TLS trust, route."""
    from sippycup_workbench.profile import ProfileError, load_profile

    eng = model["engagement"]["display"]
    checks: list[Check] = []
    for item in other_profiles(model):
        name = Path(str(item["path"])).name
        identifier = f"profile:{item.get('target')}"
        title = f"Profile {name}"[:26]
        shown = f"{eng}/{name}"
        if not item.get("present"):
            checks.append(Check(identifier, title, NOGO,
                                [f"{shown} (target {item.get('target')}) was compiled but is missing"],
                                f"{LAUNCHER} scope compile {eng}"))
            continue
        if item.get("state") not in (None, "current"):
            checks.append(Check(identifier, title, NOGO,
                                [f"{shown} (target {item.get('target')}) is {item.get('state')}: it no longer "
                                 "matches scope.yaml"], f"{LAUNCHER} scope compile {eng}"))
            continue
        if not item.get("ready"):
            checks.append(Check(identifier, title, NOGO,
                                [f"{shown} (target {item.get('target')}): rehearse refuses it: {error}"
                                 for error in item.get("errors") or ["not ready"]][:8],
                                f"{LAUNCHER} rehearse {shown}   (fix scope.yaml, then scope compile {eng})"))
            continue
        approved = item.get("approvedDestinations")
        lines = [f"{shown}: target {item.get('target')} {item.get('host')} port {item.get('port')}/"
                 f"{item.get('transport')}; rehearse: ready; current against scope.yaml",
                 "destinations: " + ("NOT RESTRICTED by this profile" if approved is None
                                     else ", ".join(approved) or "none approved")]
        status, fix = GO, None
        try:
            document = load_profile(_other_profile_path(model, item))
        except ProfileError:
            document = None
        tls = check_tls(host, model, document, now, zone)
        if tls is not None:
            lines += [f"TLS: {line}" for line in tls.lines]
            if tls.status in {NOGO, WARN}:
                status, fix = tls.status, tls.fix
        address = item.get("host")
        if address and address != model["target"].get("host") and mode != "--practice":
            route = host_route(host, str(address))
            if route.get("ok"):
                lines.append(f"route to {address}: source {route.get('source')}, interface "
                             f"{route.get('interface') or '?'} (host lookup only; the container route was "
                             "probed for the first target)")
            else:
                status = NOGO
                fix = f"connect the network or VPN that reaches {address} (ip route get {address})"
                lines.append(f"the kernel has no route to {address}: {route.get('error', 'no route')}")
        checks.append(Check(identifier, title, status, lines, fix))
    return checks


def check_window(model: dict[str, Any], now: datetime, zone: Any, margin_minutes: int) -> Check:
    auth = model["authorization"]
    eng = model["engagement"]["display"]
    start, end = _parse(auth.get("validFrom")), _parse(auth.get("validUntil"))
    plan = model["files"].get("planFacts") or {}
    planned = 0
    totals = plan.get("plannedTotals") if isinstance(plan.get("plannedTotals"), dict) else {}
    if isinstance(totals.get("durationSeconds"), int):
        planned = totals["durationSeconds"]
    required = margin_minutes * 60 + planned
    lines = [
        f"now        {_both(now, zone)}",
        f"opens      {_both(start, zone)}",
        f"closes     {_both(end, zone)}",
    ]
    if auth.get("status") != "approved" or end is None:
        return Check("window", "Approval window", NOGO, lines + [f"authorization: {auth.get('text')}"],
                     f"record the owner's written approval in {eng}/scope.yaml, then {LAUNCHER} scope compile {eng}")
    if start is not None and now < start:
        return Check("window", "Approval window", NOGO,
                     lines + [f"not open yet: opens in {_duration((start - now).total_seconds())}"],
                     f"no command fixes this: wait until {_both(start, zone)}")
    remaining = (end - now).total_seconds()
    if remaining <= 0:
        return Check("window", "Approval window", NOGO, lines + ["EXPIRED"],
                     f"get a renewed written approval, update authorization in {eng}/scope.yaml, then "
                     f"{LAUNCHER} scope compile {eng}")
    lines.append(f"remaining  {_duration(remaining)}")
    need = f"margin {margin_minutes} min" + (f" + the frozen campaign plan's {planned} s" if planned else "")
    if remaining < required:
        return Check("window", "Approval window", WARN,
                     lines + [f"less than the required {_duration(required)} ({need}) remains"],
                     f"finish before {_both(end, zone)}, or ask the owner to extend the window")
    # bn-3vxl: is the frozen campaign plan held to this window?
    if plan and not plan.get("error"):
        replan = (f"move {eng}/plan.json aside, then {LAUNCHER} scope compile {eng} and "
                  f"{LAUNCHER} campaign plan {eng}/campaign.yaml --output {eng}/plan.json")
        approval = plan.get("approval") or {}
        if not plan.get("windowBound"):
            return Check("window", "Approval window", WARN,
                         lines + ["the frozen campaign plan is NOT bound to an approval window of its own: "
                                  "campaign run would rely only on scope.yaml beside the manifest"], replan)
        plan_end = _parse(approval.get("validUntil"))
        if plan_end is None or plan_end.replace(microsecond=0) != end.replace(microsecond=0):
            return Check("window", "Approval window", WARN,
                         lines + [f"the frozen campaign plan is bound to a different window end "
                                  f"({approval.get('validUntil')}) than the profile"], replan)
        lines.append("the frozen campaign plan is bound to this window (checked before every step)")
    return Check("window", "Approval window", GO, lines + [f"at least {_duration(required)} left ({need})"])


def check_clock(host: Host) -> Check:
    """Ask the host whether the clock is synchronised; never contact a time server."""
    title = "Clock synchronised"
    if host.which("timedatectl"):
        code, out, _ = host.run(["timedatectl", "show", "-p", "NTPSynchronized", "-p", "NTP", "-p", "Timezone"],
                                timeout=10)
        values = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
        if code == 0 and values.get("NTPSynchronized") == "yes":
            return Check("clock", title, GO,
                         [f"timedatectl: NTPSynchronized=yes (NTP={values.get('NTP', '?')}, "
                          f"time zone {values.get('Timezone', '?')})"])
        if code == 0 and values.get("NTPSynchronized") == "no":
            fix = ("sudo timedatectl set-ntp true, wait until timedatectl shows "
                   "'System clock synchronized: yes'")
            return Check("clock", title, NOGO,
                         [f"timedatectl: NTPSynchronized=no (NTP={values.get('NTP', '?')}); the approval window "
                          "and every evidence timestamp depend on this clock"], fix)
    if host.which("chronyc"):
        code, out, _ = host.run(["chronyc", "-n", "tracking"], timeout=10)
        status = next((line.split(":", 1)[1].strip() for line in out.splitlines()
                       if line.lower().startswith("leap status")), None)
        if code == 0 and status == "Normal":
            offset = next((line.split(":", 1)[1].strip() for line in out.splitlines()
                           if line.lower().startswith("system time")), "?")
            return Check("clock", title, GO, [f"chronyc tracking: leap status Normal; system time {offset}"])
        if code == 0 and status:
            return Check("clock", title, NOGO, [f"chronyc tracking: leap status {status} (not synchronised)"],
                         "sudo chronyc makestep, then check chronyc tracking shows 'Leap status: Normal'")
    return Check("clock", title, WARN,
                 ["neither timedatectl nor chronyc could tell whether the clock is synchronised; "
                  "compare it with a trusted clock by hand"],
                 "date -u   (compare with a trusted clock; Sippycup never contacts a time server)")


def check_image(host: Host, image: str) -> Check:
    facts = host.probe_image(image)
    fix = f"make build IMAGE={image}"
    if not facts.get("checked"):
        return Check("image", "Toolbox image", NOGO, [f"cannot inspect {image}: {facts.get('detail')}"],
                     "install podman (or docker), then " + fix)
    if facts.get("present") is False:
        return Check("image", "Toolbox image", NOGO, [f"{image} is not built"], fix)
    if facts.get("stale"):
        return Check("image", "Toolbox image", NOGO,
                     [f"{image} (built {facts.get('created')}) was not built from this checkout's current code"], fix)
    lines = [f"{image} built {facts.get('created')}; {facts.get('method')}"]
    if facts.get("dirty"):
        lines.append("the working tree has uncommitted image inputs")
    if facts.get("stale") is None or "heuristic" in str(facts.get("method")):
        return Check("image", "Toolbox image", WARN,
                     lines + ["no build record proves it was built from this checkout"], fix)
    return Check("image", "Toolbox image", GO, lines + ["built from this checkout (input fingerprint matches)"])


def container_probe(host: Host, mode: str, address: str | None, port: Any) -> tuple[dict[str, Any] | None, str]:
    argv = [str(host.repo / "bin" / "sippycup"), mode, "doctor", "--ready-probe"]
    if address:
        argv += ["--route-to", str(address), "--route-port", str(port if isinstance(port, int) else 5060)]
    code, out, err = host.run(argv, timeout=60)
    try:
        value = json.loads(out.strip().splitlines()[-1]) if out.strip() else None
    except ValueError:
        value = None
    if code != 0 or not isinstance(value, dict):
        tail = (err.strip().splitlines() or out.strip().splitlines() or ["no output"])[-1]
        return None, f"exit {code}: {tail[:300]}"
    return value, ""


def check_capture(host: Host, model: dict[str, Any], mode: str, probe: dict[str, Any] | None, problem: str,
                  min_free_mb: int) -> Check:
    lines: list[str] = []
    title = "Capture and disk"
    shown = f"{LAUNCHER} {mode} doctor --ready-probe"
    if probe is None:
        return Check("capture", title, NOGO, [f"the probe container did not run: {problem}"],
                     f"{shown}   (and {LAUNCHER} doctor for the image's tools)")
    capture = probe.get("capture") or {}
    if not capture.get("ok"):
        return Check("capture", title, NOGO,
                     [f"loopback capture failed in {mode} mode: {capture.get('error', 'unknown')}",
                      f"CAP_NET_RAW: {'yes' if probe.get('cap_net_raw') else 'no'}"],
                     f"{LAUNCHER} {mode} doctor   (inspect capture capability in the same mode)")
    lines.append(f"loopback capture inside a {mode} container ({probe.get('network_mode')} network): "
                 f"{capture.get('packets')} packet(s) captured on lo; nothing sent to the target")
    if not probe.get("workdir_writable"):
        return Check("capture", title, NOGO, lines + ["work/ is not writable inside the container"],
                     "chmod u+w work   (evidence is written there)")
    work = host.repo / "work"
    try:
        free = host.disk_free(work)
    except OSError as exc:
        return Check("capture", title, NOGO, lines + [f"cannot read free space of work/: {exc}"], "df -h work")
    free_mb = free // (1024 * 1024)
    lines.append(f"free space for evidence under work/: {free_mb} MiB (minimum {min_free_mb} MiB)")
    if free_mb < min_free_mb:
        return Check("capture", title, NOGO, lines,
                     "free disk space on the filesystem holding work/ (df -h work), or move old evidence off it")
    return Check("capture", title, GO, lines)


def _secret_text_problems(raw: bytes) -> list[str]:
    """Surprises the tools do not already handle (they strip trailing CR/LF only)."""
    problems = []
    if raw.startswith(b"\xef\xbb\xbf"):
        problems.append("starts with a UTF-8 byte-order mark (the tools would send it as part of the password)")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return problems + ["is not UTF-8 (the tools refuse it)"]
    value = text.rstrip("\r\n")
    if not value:
        problems.append("is empty (or only a line break)")
        return problems
    if "\n" in value or "\r" in value:
        problems.append("holds more than one line (only a trailing line break is removed; the rest would be sent)")
    if value != value.strip():
        problems.append("has leading or trailing spaces or tabs (they are not removed and would be sent)")
    if text.endswith("\n\n") or text.endswith("\r\n\r\n"):
        problems.append("ends with more than one line break")
    return problems


def _practice_target(model: dict[str, Any]) -> bool:
    from .actions import practice_route

    return practice_route(model)


def _practice_copy(destination: str) -> str:
    """The practice account's password is generated by `practice-target up` and never printed."""
    return f"(umask 077; cp work/practice/account.password {destination})"


def check_credentials(host: Host, model: dict[str, Any], secret_file: str | None, secret_env: str | None) -> Check:
    from .runs import secret_file_problem

    title = "Credentials"
    account = model["target"]["account"]
    eng = model["engagement"]["display"]
    root = Path(model["engagement"]["path"])
    needed = bool(account.get("required"))
    plan = model["files"].get("planFacts") or {}
    if plan.get("credentialRefs"):
        needed = True
    if secret_file and secret_env:
        return Check("credentials", title, NOGO, ["give only one of --secret-file and --secret-env"],
                     f"{LAUNCHER} ready {eng} --secret-file PATH")
    if not secret_file and not secret_env:
        default = root / "account.password"
        if needed and default.exists():
            secret_file = f"{eng}/account.password"
        elif needed:
            fix = f"{LAUNCHER} ready {eng} --secret-file {eng}/account.password   (or --secret-env NAME)"
            if _practice_target(model):
                fix = (f"{_practice_copy(f'{eng}/account.password')}   (the practice password is never printed; "
                       f"then run ready again: it uses {eng}/account.password when that file exists)")
            return Check("credentials", title, WARN,
                         [f"the target needs an account ({account.get('username') or 'username from scope'}), "
                          "but no password source was given, so none was checked"], fix)
        else:
            return Check("credentials", title, GO, ["the scope says no account is needed; no password is used"])
    if secret_env:
        if not _ENV_NAME.fullmatch(secret_env):
            return Check("credentials", title, NOGO, [f"{secret_env!r} is not an environment variable name"],
                         f"{LAUNCHER} ready {eng} --secret-env NAME")
        if secret_env not in host.environ:
            return Check("credentials", title, NOGO, [f"environment variable {secret_env} is not set in this shell"],
                         f"IFS= read -rs {secret_env} && export {secret_env}   (type the password; it is not echoed)")
        problems = _secret_text_problems(host.environ[secret_env].encode("utf-8", "surrogateescape"))
        if problems:
            return Check("credentials", title, NOGO, [f"${secret_env} {item}" for item in problems],
                         f"IFS= read -rs {secret_env} && export {secret_env}   (set it again, exactly the password)")
        lines = [f"environment variable {secret_env} is set and well-formed (value never shown)",
                 "it reaches the container by name only (--env NAME), never in argv"]
        return Check("credentials", title, GO, lines)
    assert secret_file is not None
    path = Path(secret_file)
    absolute = path if path.is_absolute() else host.repo / path
    fix_create = (_practice_copy(secret_file) if _practice_target(model) else
                  f"(umask 077; IFS= read -rs P; printf '%s' \"$P\" > {secret_file}; unset P)")
    problem = secret_file_problem(absolute, host.repo / "work")
    if problem:
        fix = f"chmod 600 {secret_file}" if "readable by group" in problem else fix_create
        if "is not beneath" in problem:
            fix = f"move it beneath work/ (outside {eng}/calls, runs, checks, report and packs): {fix_create}"
        return Check("credentials", title, NOGO, [problem], fix)
    lines = [f"{secret_file}: regular file, mode 0600"]
    try:
        info = os.lstat(absolute)
        if info.st_uid != os.getuid():
            return Check("credentials", title, NOGO, lines + [f"owned by uid {info.st_uid}, not by you"],
                         f"recreate it as yourself: {fix_create}")
        if info.st_size > MAX_SECRET_BYTES:
            return Check("credentials", title, NOGO, lines + ["too large to be a password"], fix_create)
        raw = absolute.read_bytes()
    except OSError as exc:
        return Check("credentials", title, NOGO, [f"cannot read {secret_file}: {exc.strerror or exc}"], fix_create)
    problems = _secret_text_problems(raw)
    if problems:
        return Check("credentials", title, NOGO, [f"{secret_file} {item}" for item in problems], fix_create)
    if raw.endswith(b"\n"):
        lines.append("ends with one line break (the tools remove it)")
    try:
        relative = absolute.resolve().relative_to(root.resolve())
    except ValueError:
        relative = None
    if relative is not None and len(relative.parts) > 1:
        return Check("credentials", title, NOGO,
                     lines + [f"it lies inside the evidence tree ({eng}/{relative.parts[0]}/), where runs, reports, "
                              "and packs are written and shared"],
                     f"mv {secret_file} {eng}/account.password")
    lines.append("not inside a run, report, or pack directory (evidence never includes it)")
    return Check("credentials", title, GO, lines)


def _cert_dates(pem: str, host: Host) -> list[tuple[str, datetime | None]]:
    """(subject, notAfter) for each certificate in a PEM bundle, read offline."""
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", pem, re.S)
    found: list[tuple[str, datetime | None]] = []
    with tempfile.TemporaryDirectory(prefix="sippycup-ready-") as scratch:
        for index, block in enumerate(blocks[:16]):
            path = Path(scratch) / f"cert{index}.pem"
            path.write_text(block + "\n", encoding="ascii")
            try:
                decoded = ssl._ssl._test_decode_cert(str(path))  # type: ignore[attr-defined]
            except (AttributeError, ssl.SSLError, OSError, ValueError):
                found.append(("certificate", None))
                continue
            subject = ", ".join("=".join(pair) for part in decoded.get("subject", ()) for pair in part)
            until = decoded.get("notAfter")
            try:
                when = datetime.fromtimestamp(ssl.cert_time_to_seconds(until), timezone.utc) if until else None
            except ValueError:
                when = None
            found.append((subject or "certificate", when))
    return found


def check_tls(host: Host, model: dict[str, Any], profile_document: dict[str, Any] | None, now: datetime,
              zone: Any) -> Check | None:
    from sippycup.tls_trust import TrustError, read_ca, validate_server_name

    target = (profile_document or {}).get("target") or {}
    if target.get("transport") != "tls":
        return None
    eng = model["engagement"]["display"]
    title = "TLS trust"
    lines: list[str] = []
    fix_scope = f"edit targets[] in {eng}/scope.yaml, then {LAUNCHER} scope compile {eng}"
    name = target.get("tls_server_name")
    if not name:
        return Check("tls", title, NOGO,
                     ["no tls_server_name: the certificate would have to carry the IP address itself"],
                     f"add tls_server_name (the name on the owner's certificate) to the target: {fix_scope}")
    try:
        validate_server_name(name)
    except TrustError as exc:
        return Check("tls", title, NOGO, [str(exc)], fix_scope)
    lines.append(f"server name {name} (SNI and verification only; packets go to {target.get('host')})")
    reference = target.get("tls_ca_file")
    if not reference:
        return Check("tls", title, WARN, lines + ["no CA file: the image's system trust store is used"],
                     f"ask the owner for their CA certificate and add tls_ca_file: {fix_scope}")
    try:
        data, digest = read_ca(reference, host.repo / "work")
    except TrustError as exc:
        return Check("tls", title, NOGO, lines + [str(exc)],
                     f"put the owner's CA certificate (PEM, no private key) at {reference}")
    lines.append(f"CA {reference} parses; SHA-256 {digest}")
    plan_path = Path(model["engagement"]["path"]) / "plan.json"
    if plan_path.is_file():
        try:
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            plan = {}
        pins = {str((step.get("tls") or {}).get("caSha256")) for step in plan.get("steps") or []
                if isinstance(step, dict) and isinstance(step.get("tls"), dict)
                and (step["tls"].get("caFile") == reference)}
        pins.discard("None")
        if pins and pins != {digest}:
            return Check("tls", title, NOGO,
                         lines + [f"the frozen campaign plan pins {', '.join(sorted(pins))}, not the file's digest"],
                         f"{LAUNCHER} campaign plan {eng}/campaign.yaml --output {eng}/plan.json   "
                         "(after confirming the new CA with the owner)")
        if pins:
            lines.append("matches the digest pinned in the frozen campaign plan")
    dates = _cert_dates(data.decode("ascii", "replace"), host)
    status = GO
    fix = None
    for subject, until in dates:
        if until is None:
            lines.append(f"{subject}: expiry not readable")
            status = WARN if status == GO else status
            continue
        if until <= now:
            lines.append(f"{subject}: EXPIRED at {_both(until, zone)}")
            status, fix = NOGO, f"ask the owner for a current CA certificate for {reference}"
        elif until - now < timedelta(days=CERT_WARN_DAYS):
            lines.append(f"{subject}: expires {_both(until, zone)} (under {CERT_WARN_DAYS} days)")
            if status == GO:
                status = WARN
        else:
            lines.append(f"{subject}: valid until {_both(until, zone)}")
    return Check("tls", title, status, lines, fix)


def _private(address: ipaddress._BaseAddress) -> bool:
    shared = ipaddress.ip_network("100.64.0.0/10")
    return address.is_private or (address.version == 4 and address in shared)


def host_route(host: Host, address: str) -> dict[str, Any]:
    """Route lookup only (``ip route get``); no packet is sent."""
    facts: dict[str, Any] = {"ok": False}
    if host.which("ip"):
        code, out, err = host.run(["ip", "-j", "route", "get", address], timeout=10)
        if code == 0:
            try:
                entry = (json.loads(out) or [{}])[0]
            except (ValueError, IndexError):
                entry = {}
            facts.update(ok=bool(entry.get("prefsrc") or entry.get("dev")), source=entry.get("prefsrc"),
                         interface=entry.get("dev"), gateway=entry.get("gateway"), type=entry.get("type"))
        else:
            facts["error"] = (err.strip().splitlines() or ["route lookup failed"])[-1]
        code, out, _ = host.run(["ip", "-j", "route", "show", "default"], timeout=10)
        try:
            defaults = json.loads(out) if code == 0 and out.strip() else []
        except ValueError:
            defaults = []
        facts["defaults"] = [f"via {item.get('gateway', '-')} dev {item.get('dev', '?')}"
                             + (f" metric {item['metric']}" if "metric" in item else "") for item in defaults]
        facts["defaultInterfaces"] = [str(item.get("dev")) for item in defaults]
        return facts
    from sippycup_workbench.doctor import route_source

    found = route_source(address)
    facts.update(ok=found.get("ok", False), source=found.get("source"), error=found.get("error"))
    return facts


def check_network(host: Host, model: dict[str, Any], mode: str, probe: dict[str, Any] | None) -> tuple[Check, str | None]:
    title = "Network position"
    target = model["target"]
    address = target.get("host")
    if not address:
        return Check("network", title, NOGO, ["no target address yet"],
                     f"{LAUNCHER} scope compile {model['engagement']['display']}"), None
    if mode == "--practice":
        return Check("network", title, GO,
                     [f"{address} is the local practice target: commands join its loopback-only namespace "
                      "(--practice); nothing leaves this host"]), "127.0.0.1"
    try:
        literal = ipaddress.ip_address(address)
    except ValueError:
        return Check("network", title, NOGO, [f"{address} is not a literal IP address"],
                     f"{LAUNCHER} rehearse {model['engagement']['display']}/target-profile.yaml"), None
    facts = host_route(host, address)
    if not facts.get("ok"):
        return Check("network", title, NOGO,
                     [f"the kernel has no route to {address}: {facts.get('error', 'no route')}"],
                     "connect the network or VPN that reaches the target (ip route get " + address + ")"), None
    source = facts.get("source")
    status = GO
    lines = [f"route to {address}: source {source}, interface {facts.get('interface') or '?'}"
             + (f", gateway {facts['gateway']}" if facts.get("gateway") else ", directly connected")]
    fix = None
    try:
        source_ip = ipaddress.ip_address(source) if source else None
    except ValueError:
        source_ip = None
    if source_ip is not None and _private(source_ip) and not _private(literal):
        status = WARN
        lines.append(f"{source} is a private address and the target is public: a NAT sits in the path. The owner "
                     "must allowlist your PUBLIC address (ask your network administrator for it; Sippycup never asks "
                     "an outside service), and one-way audio is more likely")
        fix = "confirm with the owner which address they allowlisted for you"
    if literal.is_loopback:
        status = WARN
        lines.append(f"{address} is a loopback address on this host, but not the running practice target")
    interface = str(facts.get("interface") or "")
    if interface.startswith(VPN_PREFIXES):
        status = WARN
        lines.append(f"the route leaves through {interface}, which looks like a VPN: the owner sees the VPN's exit "
                     "address, not yours")
        fix = fix or "confirm with the owner that the VPN exit address is the one they allowlisted"
    defaults = facts.get("defaults") or []
    if len(defaults) > 1:
        status = WARN
        lines.append(f"{len(defaults)} default routes: {'; '.join(defaults)}")
        fix = fix or "ip route show default   (remove the default route you do not intend to use)"
    elif any(dev.startswith(VPN_PREFIXES) for dev in facts.get("defaultInterfaces") or []):
        status = WARN
        lines.append(f"the default route goes through a VPN interface ({defaults[0]})")
    if probe is not None:
        route = probe.get("route") or {}
        if not route.get("ok"):
            return Check("network", title, NOGO,
                         lines + [f"inside a {mode} container (as the live commands run) there is no route: "
                                  f"{route.get('error', 'unknown')}"],
                         f"{LAUNCHER} {mode} doctor --ready-probe --route-to {address}"), source
        inner = route.get("source")
        lines.append(f"inside a {mode} container ({probe.get('network_mode')} network) the route works; "
                     f"source {inner}" + ("" if inner == source else f" (translated to {source} by the container "
                                                                       "runtime on the way out)"))
    return Check("network", title, status, lines, fix), source


def authorizes(model: dict[str, Any], document: dict[str, Any] | None, zone: Any,
               credentials: str | None = None) -> list[str]:
    """What the profile authorizes, for one last human read-through."""
    document = document or {}
    target = document.get("target") or {}
    media = document.get("media") or {}
    limits = document.get("limits") or {}
    auth = model["authorization"]
    plan = model["files"].get("planFacts") or {}
    lines = [
        f"Target         {target.get('host')} port {target.get('port')}/{target.get('transport')}"
        + (f" (TLS name {target['tls_server_name']})" if target.get("tls_server_name") else ""),
        f"Approved addrs {', '.join(str(item) for item in target.get('approved_addresses') or []) or 'none'}"
        " (signaling and media)",
    ]
    approved_dial = target.get("approved_destinations")
    lines.append("Destinations   " + (
        "NOT RESTRICTED by this profile: check every --dial against the owner's written approval"
        if not isinstance(approved_dial, list) else
        (", ".join(str(item) for item in approved_dial) or "none approved") + " (the only --dial values accepted)"))
    for item in other_profiles(model):
        also = item.get("approvedDestinations")
        lines.append(f"Other profile  {Path(str(item['path'])).name}: target {item.get('target')} "
                     f"{item.get('host')} port {item.get('port')}/{item.get('transport')}; destinations "
                     + ("NOT RESTRICTED" if also is None else ", ".join(also) or "none approved"))
    networks = model["target"].get("mediaNetworks") or []
    ports = model["target"].get("mediaPorts")
    lines.append(f"Media only     {', '.join(networks) if networks else 'no extra networks'}"
                 + (f"; RTP ports {ports.get('start')}-{ports.get('end')}" if isinstance(ports, dict) else
                    f"; RTP ports {ports}" if ports else ""))
    if isinstance(media.get("codecs"), list):
        lines.append(f"Codecs         {', '.join(str(item) for item in media['codecs'])}")
    transports = sorted({target.get("transport")} | set((plan.get("authorization") or {}).get("transports") or []))
    lines.append(f"Transports     {', '.join(str(item) for item in transports if item)}")
    lines.append("Limits         " + ", ".join(f"{key}={value}" for key, value in sorted(limits.items())))
    if other_profiles(model):
        lines.append(f"Shared calls   max_calls={limits.get('max_calls')} is one total for this profile and "
                     "every other profile above (one approval), not a ceiling per profile; a matrix "
                     "over several of them counts their calls together")
    if plan.get("hardMaxima"):
        lines.append("Campaign max   " + ", ".join(f"{key}={value}" for key, value in sorted(plan["hardMaxima"].items())))
    checks = model["profile"].get("securityChecks") or []
    lines.append(f"Checks         {', '.join(checks) if checks else 'none approved'}")
    account = model["target"]["account"]
    if not account.get("required"):
        account_text = "none"
    elif credentials == GO:
        account_text = f"{account.get('username')} (password from the source checked above)"
    elif credentials == WARN:
        account_text = f"{account.get('username')} (no password source was given, so none was checked)"
    else:
        account_text = f"{account.get('username')} (the password source failed the check above)"
    lines.append("Account        " + account_text)
    lines.append(f"Window         {_both(_parse(auth.get('validFrom')), zone)} to "
                 f"{_both(_parse(auth.get('validUntil')), zone)}")
    lines.append(f"Approval       {auth.get('approvalId') or 'none'} by {model['profile'].get('approvedBy') or '?'}")
    return lines


# ---------------------------------------------------------------------------
# orchestration


def assess(engagement: Path, *, host: Host, image: str, margin_minutes: int = DEFAULT_MARGIN_MINUTES,
           min_free_mb: int = DEFAULT_MIN_FREE_MB, secret_file: str | None = None,
           secret_env: str | None = None, container: bool = True) -> dict[str, Any]:
    from .model import build_model
    from .probes import commands as registry_commands

    now = host.clock().astimezone(timezone.utc)
    zone = host.local_zone()
    model = build_model(engagement, repo=host.repo, now=now, image=None, commands=registry_commands(host.repo),
                        advisor=False)
    profile_path = Path(model["engagement"]["path"]) / "target-profile.yaml"
    document = None
    if model["profile"]["present"]:
        try:
            from sippycup_workbench.profile import load_profile

            document = load_profile(profile_path)
        except Exception:  # rehearse already reported why
            document = None
    mode = route_mode(model)
    image_check = check_image(host, image)
    checks = [check_engagement(model), check_scope(model), check_profile(model),
              *check_other_profiles(host, model, mode, now, zone),
              check_window(model, now, zone, margin_minutes), check_clock(host), image_check]
    probe, problem = (None, "skipped (--no-container)")
    if container and image_check.status == NOGO and "built from" not in " ".join(image_check.lines):
        # Never start (or pull) an image that is not there; the image line says why.
        probe, problem = None, "not started: the toolbox image is not available (see the image line)"
    elif container:
        probe, problem = container_probe(host, mode, model["target"].get("host") if mode != "--practice" else None,
                                         model["target"].get("port"))
    checks.append(check_capture(host, model, mode, probe, problem, min_free_mb) if container else
                  Check("capture", "Capture and disk", WARN, ["not checked (--no-container)"],
                        f"{LAUNCHER} ready {model['engagement']['display']}"))
    credentials = check_credentials(host, model, secret_file, secret_env)
    checks.append(credentials)
    tls = check_tls(host, model, document, now, zone)
    if tls is not None:
        checks.append(tls)
    network, source = check_network(host, model, mode, probe)
    checks.append(network)
    from .platform_scope import check_platform

    platform = check_platform(model)
    if platform is not None:
        checks.append(platform)
    blocking = [item for item in checks if item.status == NOGO]
    warnings = [item for item in checks if item.status == WARN]
    verdict = "NO-GO" if blocking else "GO"
    return {
        "apiVersion": READY_VERSION,
        "networkActivity": "none to the target (one loopback-only capture inside a local container)",
        "generatedAt": _iso(now),
        "localTime": now.astimezone(zone).strftime("%Y-%m-%d %H:%M:%S %Z"),
        "engagement": model["engagement"]["display"],
        "profile": model["profile"]["path"] if model["profile"]["present"] else None,
        "profileSha256": file_sha256(profile_path) if model["profile"]["present"] else None,
        # Every further target's compiled profile this verdict covers (file name -> SHA-256).
        "otherProfiles": {Path(str(item["path"])).name: file_sha256(_other_profile_path(model, item))
                          for item in other_profiles(model)},
        "approvalId": model["authorization"].get("approvalId"),
        "route": mode,
        "sourceAddress": source,
        "target": {key: model["target"].get(key) for key in ("host", "port", "transport")},
        "verdict": verdict,
        "blocking": len(blocking),
        "warnings": len(warnings),
        "checks": [item.as_dict() for item in checks],
        "authorizes": authorizes(model, document, zone, credentials.status),
    }


def record(result: dict[str, Any], engagement: Path) -> Path | None:
    """Write the result (no secret) to DIR/readiness/ready-STAMP.json, mode 0600."""
    if not (engagement / "engagement.json").is_file():
        return None
    directory = engagement / READINESS_DIR
    directory.mkdir(mode=0o700, exist_ok=True)
    stamp = result["generatedAt"].replace("-", "").replace(":", "")
    path = directory / f"ready-{stamp}.json"
    counter = 1
    while path.exists():
        counter += 1
        path = directory / f"ready-{stamp}-{counter}.json"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(result, output, indent=2, sort_keys=True)
        output.write("\n")
    return path


_RECORD_NAME = re.compile(r"ready-(\d{8}T\d{6}Z)(?:-(\d{1,6}))?\.json")


def _record_order(name: str) -> tuple[str, int]:
    match = _RECORD_NAME.fullmatch(name)
    assert match is not None
    return match.group(1), int(match.group(2) or 1)


def latest_record(engagement: Path) -> dict[str, Any] | None:
    """The newest readable ready record of an engagement, or None (bounded, no symlinks)."""
    from .runs import Unreadable, read_json

    directory = engagement / READINESS_DIR
    if not directory.is_dir() or directory.is_symlink():
        return None
    try:
        names = sorted((item.name for item in directory.iterdir() if _RECORD_NAME.fullmatch(item.name)),
                       key=_record_order)[-MAX_RECORDS:]
    except OSError:
        return None
    for name in reversed(names):
        try:
            value = read_json(directory / name, limit=256 * 1024)
        except Unreadable:
            continue
        if isinstance(value, dict) and value.get("apiVersion") == READY_VERSION:
            value["recordPath"] = f"{READINESS_DIR}/{name}"
            return value
    return None


def gate_facts(engagement: Path, profile_present: bool, now: datetime) -> dict[str, Any]:
    """What the cockpit shows and gates on: the newest record against the current profile."""
    from sippycup_workbench.scope_derive import compiled_profiles

    current = file_sha256(engagement / "target-profile.yaml") if profile_present else None
    # A GO covers every compiled profile: a further target's profile that was
    # added, removed, or changed since makes the record "for another profile".
    others = {item["path"]: file_sha256(engagement / item["path"])
              for item in compiled_profiles(engagement) if not item["first"]}
    latest = latest_record(engagement)
    facts: dict[str, Any] = {"command": None, "present": latest is not None, "verdict": None, "generatedAt": None,
                             "path": None, "current": False, "go": False, "ageSeconds": None}
    if latest is None:
        return facts
    generated = _parse(latest.get("generatedAt"))
    facts.update(
        verdict=latest.get("verdict"), generatedAt=latest.get("generatedAt"), path=latest.get("recordPath"),
        current=bool(current) and latest.get("profileSha256") == current
        and (latest.get("otherProfiles") or {}) == others,
        sourceAddress=latest.get("sourceAddress"), blocking=latest.get("blocking"),
        ageSeconds=(now - generated).total_seconds() if generated else None,
    )
    facts["go"] = facts["current"] and facts["verdict"] == "GO"
    return facts


def render(result: dict[str, Any], record_path: str | None) -> list[str]:
    lines = [
        f"Sippycup go/no-go: {result['engagement']}   (sends nothing to the target)",
        f"As of {result['localTime']} ({result['generatedAt']})",
        "",
    ]
    if result.get("sourceAddress") and result.get("route") != "--practice":
        lines.append(f">>> YOUR SOURCE ADDRESS toward {result['target']['host']}: {result['sourceAddress']}   "
                     "(the address the owner allowlists, unless a NAT translates it)")
        lines.append("")
    for item in result["checks"]:
        first, *rest = item["lines"] or [""]
        lines.append(f"{MARK[item['status']]} {item['title']:<26} {first}")
        lines.extend(f"{'':36}{line}" for line in rest)
        if item.get("fix") and item["status"] in {NOGO, WARN}:
            lines.append(f"{'':36}fix: {item['fix']}")
    lines.append("")
    lines.append("What the profile authorizes (read it once more before the first live packet):")
    lines.extend(f"  {line}" for line in result["authorizes"])
    lines.append("")
    if result["verdict"] == "GO":
        warn = f" with {result['warnings']} warning(s) to read above" if result["warnings"] else ""
        lines.append(f"VERDICT: GO{warn}")
        lines.append("The cockpit (./bin/sippycup go) asks for the last 4 characters of the approval id before it "
                     "starts a [LIVE] action; call, matrix run and campaign run typed in a shell do not ask.")
    else:
        lines.append(f"VERDICT: NO-GO ({result['blocking']} blocking line(s); fix each, then run ready again)")
    if record_path:
        lines.append(f"Recorded: {record_path}")
        summary = (f"Go/no-go {result['verdict']} at {result['generatedAt']} "
                   f"(source {result.get('sourceAddress') or '-'}, {result['blocking']} blocking, "
                   f"{result['warnings']} warning)")
        lines.append("Journal: " + shlex.join([LAUNCHER, "journal", "add", result["engagement"], "--kind", "action",
                                              "--summary", summary, "--evidence",
                                              record_path.split(f"{result['engagement']}/", 1)[-1]]))
    lines.append("Network activity: none to the target (one loopback-only capture inside a local container)")
    return lines


def main(argv: list[str] | None = None, *, host: Host | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="./bin/sippycup ready",
        description="Go/no-go check to run right before the first live packet. Sends nothing to the target. "
                    "Exit 0 GO, 1 NO-GO, 2 usage error.",
    )
    parser.add_argument("engagement", metavar="DIR", help="engagement directory, e.g. work/NAME")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--secret-file", metavar="PATH", help="the password file you will use (checked, never shown)")
    source.add_argument("--secret-env", metavar="NAME", help="the environment variable you will use (checked by name)")
    parser.add_argument("--margin", type=int, default=DEFAULT_MARGIN_MINUTES, metavar="MINUTES",
                        help="warn when less than this (plus a frozen campaign plan's duration) remains in the "
                             "approval window (default %(default)s)")
    parser.add_argument("--min-free-mb", type=int, default=DEFAULT_MIN_FREE_MB, metavar="MIB",
                        help="free space required under work/ for evidence (default %(default)s)")
    parser.add_argument("--image", default=os.environ.get("SIPPYCUP_IMAGE", "localhost/sippycup:latest"),
                        help="toolbox image (default: $SIPPYCUP_IMAGE or localhost/sippycup:latest)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--no-record", action="store_true", help="do not write DIR/readiness/ready-STAMP.json")
    parser.add_argument("--no-container", action="store_true",
                        help="skip the loopback capture container (the capture line is then a warning)")
    parser.add_argument("--repo", type=Path, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.margin < 0 or args.min_free_mb < 0:
        parser.error("--margin and --min-free-mb must not be negative")
    repo = (args.repo or Path(__file__).resolve().parents[2]).resolve()
    host = host or Host(repo)
    path = Path(args.engagement)
    engagement = (path if path.is_absolute() else Path.cwd() / path).resolve()
    if not engagement.is_dir():
        print(f"ready: {args.engagement} is not a directory", file=sys.stderr)
        print(f"Create it: {LAUNCHER} journal init work/NAME --title TITLE --owner OWNER", file=sys.stderr)
        return 2
    result = assess(engagement, host=host, image=args.image, margin_minutes=args.margin,
                    min_free_mb=args.min_free_mb, secret_file=args.secret_file, secret_env=args.secret_env,
                    container=not args.no_container)
    written = None
    if not args.no_record:
        try:
            saved = record(result, engagement)
        except OSError as exc:
            print(f"ready: could not record the result: {exc}", file=sys.stderr)
            saved = None
        written = f"{result['engagement']}/{saved.relative_to(engagement).as_posix()}" if saved else None
        result["recordPath"] = written
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for line in render(result, written):
            print(line)
    return 0 if result["verdict"] == "GO" else 1


if __name__ == "__main__":
    raise SystemExit(main())
