"""Everything a guided-call run directory records, loaded once, plus the command lines built from it."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

from . import siplog
from .core import command, container_to_host_path, is_loopback, work_relative
from .files import read_dict, read_json, read_text, read_yaml_dict, regular
from .inputs import sibling_profiles

_SAFE_USER = re.compile(r"^[A-Za-z0-9_.+*#-]{1,32}$")
_LONG_DIGITS = re.compile(r"[0-9]{7,}")
DEFAULT_ANSWER_TIMEOUT = 30
MAX_ANSWER_TIMEOUT = 120
G711 = ("PCMU", "PCMA")


def _safe_user(value: Optional[str]) -> Optional[str]:
    if value and _SAFE_USER.match(value) and not _LONG_DIGITS.search(value):
        return value
    return None


class CallRun:
    def __init__(self, run_dir: Path) -> None:
        self.dir = run_dir
        self.result = read_dict(run_dir / "result.json")
        self.plan = read_dict(run_dir / "plan.json")
        self.profile = read_dict(run_dir / "profile.json")
        self.phone = read_dict(run_dir / "softphone.json")
        self.assertion = read_dict(run_dir / "assert.json")
        self.stamps = read_dict(run_dir / "timestamps.json")
        self.expect = read_yaml_dict(run_dir / "expectations.yaml")
        pre = read_json(run_dir / "preflight.json")
        self.preflight_file = pre[0] if isinstance(pre, list) and pre and isinstance(pre[0], dict) else {}
        log = read_text(run_dir / "softphone.log")
        self.log_text = log or ""
        self.has_log = log is not None
        self.msgs: list = siplog.parse_messages(self.log_text) if log else []
        siplog.midnight_fix(self.msgs)
        self.has_capture = regular(run_dir / "capture.pcap") or regular(run_dir / "capture.pcapng")

    # -- basic facts -------------------------------------------------------
    @property
    def has_result(self) -> bool:
        return bool(self.result)

    @property
    def verdict(self) -> Optional[str]:
        return self.result.get("verdict")

    @property
    def target(self) -> dict:
        value = self.result.get("target") or self.plan.get("target") or {}
        return value if isinstance(value, dict) else {}

    @property
    def transport(self) -> str:
        return str(self.target.get("transport") or "udp")

    @property
    def host(self) -> Optional[str]:
        return self.target.get("host")

    @property
    def softphone(self) -> dict:
        value = self.result.get("softphone")
        return value if isinstance(value, dict) else {}

    @property
    def plan_phone(self) -> dict:
        value = self.plan.get("softphone")
        return value if isinstance(value, dict) else {}

    @property
    def account(self) -> Optional[dict]:
        value = self.plan_phone.get("account")
        return value if isinstance(value, dict) else None

    @property
    def practice(self) -> bool:
        authorization = self.profile.get("authorization")
        return isinstance(authorization, dict) and authorization.get("approval_id") == "LOCAL-PRACTICE-ONLY"

    @property
    def local_address(self) -> Optional[str]:
        return self.result.get("localAddress") or self.plan.get("local_address")

    @property
    def loopback_target(self) -> bool:
        return is_loopback(self.host)

    @property
    def final_status(self) -> Optional[int]:
        return self.softphone.get("final_status")

    # -- SIP messages from the softphone log -------------------------------
    def inbound(self, method: Optional[str] = None, final: Optional[bool] = None) -> list:
        out = []
        for message in self.msgs:
            if message.outbound or message.status is None:
                continue
            if method and message.method != method:
                continue
            if final is True and message.status < 200:
                continue
            if final is False and message.status >= 200:
                continue
            out.append(message)
        return out

    def outbound(self, method: str) -> list:
        return [m for m in self.msgs if m.outbound and m.status is None and m.method == method]

    def far_end_headers(self) -> list:
        """(label, text) for Reason, Warning, Retry-After on messages the far end sent."""
        found: list = []
        for message in self.msgs:
            if message.outbound:
                continue
            label = f"{message.status} {message.phrase or ''}".strip() if message.status else message.method
            for name, value in (("Reason", message.reason), ("Warning", message.warning), ("Retry-After", message.retry_after)):
                if value:
                    entry = (f"{name} (on {label} to {message.method})" if message.status else f"{name} (on {label})", value)
                    if entry not in found:
                        found.append(entry)
        return found

    def sdp(self, outbound: bool):
        """Last SDP summary the softphone sent (offer) or received (answer)."""
        chosen = None
        for message in self.msgs:
            if message.outbound == outbound and message.sdp is not None:
                if outbound or message.status is None or message.status < 300:
                    chosen = message.sdp
        return chosen

    # -- timing ------------------------------------------------------------
    def registration_seconds(self) -> Optional[float]:
        sent = self.outbound("REGISTER")
        if not sent:
            return None
        invites = self.outbound("INVITE")
        limit = invites[0].t if invites else float("inf")
        finals = [m for m in self.inbound("REGISTER", final=True) if sent[0].t <= m.t <= limit]
        if not finals:
            return None
        return max(0.0, finals[-1].t - sent[0].t) if len(finals) < 3 else max(0.0, finals[1].t - sent[0].t)

    def invite_times(self) -> dict:
        invites = self.outbound("INVITE")
        if not invites:
            return {}
        first = invites[0]
        out: dict = {"first": first.t, "count": len(invites)}
        later = [m for m in self.inbound("INVITE") if m.t >= first.t]
        for message in later:
            if message.status is not None and 100 < message.status < 200 and "provisional" not in out:
                out["provisional"] = message.t - first.t
                out["provisionalStatus"] = message.status
        last_final = [m for m in later if m.status is not None and m.status >= 200 and m.status not in (401, 407)]
        if last_final:
            out["final"] = last_final[0].t - first.t
            out["finalStatus"] = last_final[0].status
        return out

    def bye_seconds(self) -> Optional[float]:
        byes = [m for m in self.msgs if m.method == "BYE" and m.status is None]
        if not byes:
            return None
        done = [m for m in self.inbound("BYE") if m.t >= byes[0].t]
        return (done[0].t - byes[0].t) if done else None

    def wall(self, a: str, b: str) -> Optional[float]:
        from datetime import datetime

        try:
            start = datetime.fromisoformat(str(self.stamps.get(a)).replace("Z", "+00:00"))
            end = datetime.fromisoformat(str(self.stamps.get(b)).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
        return (end - start).total_seconds()

    # -- command lines -----------------------------------------------------
    def profile_path(self) -> Optional[str]:
        recorded = self.plan.get("profile_path")
        if isinstance(recorded, str) and recorded:
            return recorded
        name = self.result.get("profile") or self.plan.get("profile")
        if not name:
            return None
        host, port = self.target.get("host"), self.target.get("port")
        matches = [
            item for item in sibling_profiles(self.dir)
            if item["name"] == name and item["host"] == host and item["port"] == port
            and item["transport"] == self.transport
        ]
        if len(matches) == 1:
            return work_relative(matches[0]["path"])
        return None

    @property
    def profile_word(self) -> str:
        return self.profile_path() or "PROFILE.yaml"

    @property
    def profile_known(self) -> bool:
        return self.profile_path() is not None

    def run_ref(self) -> str:
        return work_relative(self.dir)

    def call_words(self, **override: Any) -> Optional[list]:
        """The ./bin/sippycup call words that repeat this run, with changes applied."""
        phone = self.plan_phone
        uri = str(phone.get("destination_uri") or self.result.get("destinationUri") or "")
        match = re.match(r"^sips?:([^@]+)@", uri)
        dial = _safe_user(match.group(1)) if match else None
        words = ["call", self.profile_word, "--dial", dial or "DESTINATION"]
        duration = (phone.get("duration_seconds") or {}).get("requested")
        if override.get("duration", duration):
            words += ["--duration", str(override.get("duration", duration))]
        timeout = override.get("answer_timeout", phone.get("answer_timeout_seconds"))
        if timeout and int(timeout) != DEFAULT_ANSWER_TIMEOUT:
            words += ["--answer-timeout", str(int(timeout))]
        codecs = override.get("codec")
        if codecs is None and phone.get("codec_offer") == "only":
            codecs = list(phone.get("codecs") or [])
        if codecs:
            words += ["--codec", ",".join(codecs)]
        srtp = override.get("srtp")
        if srtp is None and (phone.get("srtp") or {}).get("requested_by") == "--srtp":
            srtp = (phone.get("srtp") or {}).get("mode")
        if srtp:
            words += ["--srtp", srtp]
        account = self.account
        no_register = override.get("no_register")
        if no_register is None and account is not None and account.get("register") is False:
            no_register = True
        if account is not None:
            user = _safe_user(account.get("username"))
            words += ["--username", user or "USERNAME"]
            if account.get("realm") and account.get("realm") != "*":
                words += ["--realm", str(account["realm"])]
            source = str(account.get("password_source") or "")
            if source.startswith("environment variable "):
                words += ["--secret-env", source[len("environment variable "):]]
            elif source.startswith("file "):
                words += ["--secret-file", container_to_host_path(source[len("file "):])]
        if no_register:
            words += ["--no-register"]
        if phone.get("media_required") is False:
            words += ["--no-media-required"]
        dtmf = phone.get("dtmf")
        if isinstance(dtmf, dict) and dtmf.get("digits"):
            words += ["--dtmf", str(dtmf["digits"]), "--dtmf-after", str(dtmf.get("after_seconds", 1))]
        return words

    def cmd_call(self, **override: Any) -> Optional[str]:
        words = self.call_words(**override)
        return command(*words, practice=self.practice) if words else None

    def cmd_preflight(self, host: str, port: Any, transport: str, tls_name: Any = None, tls_ca: Any = None,
                      profile: Any = None) -> Optional[str]:
        # Bound to the profile whenever its file is known: the target, TLS
        # name and CA then come from the approval (docs/CLI.md, Scope binding).
        if profile:
            return command("preflight", "--profile", str(profile), practice=self.practice)
        words = ["preflight", host, str(port), transport]
        if transport == "tls":
            if tls_ca:
                words += ["--tls-ca", str(tls_ca)]
            if tls_name:
                words += ["--tls-server-name", str(tls_name)]
        return command(*words, practice=self.practice)

    def cmd_rehearse(self) -> Optional[str]:
        return command("rehearse", self.profile_word)

    def cmd_ladder(self, html: bool = False) -> Optional[str]:
        if not html:
            return command("ladder", self.run_ref())
        work_root = self.run_ref().split("/", 1)[0]
        short = re.sub(r"[^A-Za-z0-9]", "", self.dir.name)[-12:] or "run"
        return command("ladder", self.run_ref(), "--format", "html", "--output", f"{work_root}/ladder-{short}.html")

    def cmd_explain(self) -> Optional[str]:
        verdict = self.verdict
        return command("explain", f"call.{verdict}") if verdict else None

    def cmd_diagnose(self, *extra: str) -> Optional[str]:
        return command("diagnose", self.run_ref(), *extra)

    # -- what the profile approves ----------------------------------------
    @property
    def approved_codecs(self) -> Optional[list]:
        value = self.plan_phone.get("approved_codecs")
        return list(value) if isinstance(value, list) else None

    def alternative_codecs(self) -> list:
        """Codecs a retry may name: the profile's approved list, else the two G.711 names."""
        used = {str(item).upper() for item in (self.plan_phone.get("codecs") or [])}
        pool = self.approved_codecs if self.approved_codecs is not None else list(G711)
        return [item for item in pool if str(item).upper() not in used]

    @property
    def srtp_approved(self) -> bool:
        value = self.profile.get("features")
        return bool(isinstance(value, dict) and value.get("srtp"))

    def siblings_other_transport(self) -> list:
        out = []
        for item in sibling_profiles(self.dir):
            if item["host"] != self.host or item["transport"] == self.transport or not item["approved"] or item.get("expired"):
                continue
            if any(other["transport"] == item["transport"] and other["port"] == item["port"] for other in out):
                continue
            out.append(item)
        return out
