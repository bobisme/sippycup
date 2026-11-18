#!/usr/bin/env python3
"""Live gate for ``./bin/sippycup checks`` against the local practice target.

Opt-in (``make checks-gate``); needs the core and practice images. Runs every
runnable check against the real Asterisk practice target through the unified
launcher (``--practice``: loopback only, inside the practice namespace) and
asserts, per check, what Asterisk 22 with the practice configuration really
does. It also proves from each run's own capture that the number of requests
on the wire equals the reported ``requestsSent`` sum, that the practice
password appears nowhere in a run directory, and that a profile without an
approved list sends zero packets (exit 2).

It reuses the practice gate's lifecycle helpers and starts the target only
when it is not already up, removing only what it started.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "lib"))

import yaml  # noqa: E402

from practice_gate import Gate, GateFailure, images_available, practice  # noqa: E402

UDP_CHECKS = [
    "banner-disclosure", "options-methods", "unauthenticated-register", "digest-quality",
    "unauthenticated-invite", "user-enumeration", "nonce-replay",
]
TLS_CHECKS = ["tls-certificate", "tls-protocols", "cleartext-signaling"]
SRTP_CHECKS = ["srtp-policy"]
# practice-target/asterisk/pjsip.conf has a second TLS listener (5071) that
# accepts TLS 1.2 and TLS 1.3 so a TLS 1.3 handshake is really exercised.
TLS_MODERN_PORT = 5071

# What Asterisk 22 with practice-target/asterisk/pjsip.conf does, per check:
# finding ids expected (exactly), or None for "passed with no finding".
EXPECTED_UDP = {
    # user_agent = "Sippycup practice target (Asterisk)": a product, no version.
    "banner-disclosure": ("finding", {"banner-disclosure.product"}),
    # PJSIP advertises SUBSCRIBE, PUBLISH, UPDATE (inventory only, info).
    "options-methods": ("finding", {"options-methods.extra-methods"}),
    # Every unauthenticated REGISTER is challenged with 401.
    "unauthenticated-register": ("passed", set()),
    # MD5 only (PJSIP's default), qop=auth, long nonce, realm sippycup-practice.
    "digest-quality": ("finding", {"digest-quality.md5-only"}),
    # An anonymous INVITE is identified by source IP and challenged (401).
    "unauthenticated-invite": ("passed", set()),
    # Known and unknown users both hit the IP-identified endpoint: identical 401s.
    "user-enumeration": ("passed", set()),
    # Asterisk validates the nonce's signature and age but does not track the
    # nonce count, so the replayed REGISTER is accepted (observed).
    "nonce-replay": ("finding", {"nonce-replay.accepted"}),
}
EXPECTED_TLS = {
    # Verified for sippycup-practice against the generated CA; the generated
    # leaf lives for days only, so "expiring" is the one allowed finding.
    "tls-certificate": ("any", {"tls-certificate.expiring"}),
    # 5061 has method = tlsv1_2: only TLS 1.2 completes; no NULL/anonymous
    # suites. EXPORT, RC4, and 3DES cannot be offered by the toolbox's OpenSSL
    # and must be reported as untestable (an info finding), never as refused.
    "tls-protocols": ("finding", {"tls-protocols.no-tls13", "tls-protocols.untestable-probes"}),
    # The same address also answers OPTIONS on UDP and TCP 5060.
    "cleartext-signaling": ("finding", {"cleartext-signaling.answered"}),
}


class ChecksGate(Gate):
    def profile_variant(self, source: str, name: str, section: dict[str, Any] | None, port: int | None = None) -> str:
        document = yaml.safe_load((practice.state_dir(self.project) / source).read_text(encoding="utf-8"))
        if port is not None:
            document["target"]["port"] = port
        # Three INVITE attempts (unauthenticated-invite + the user-enumeration
        # pair) must fit the call ceiling; the practice profiles allow one.
        document["limits"]["max_calls"] = 3
        if section is not None:
            document["security_checks"] = section
        practice.write_private(self.host_path(name), yaml.safe_dump(document, sort_keys=False))
        return self.work_path(name)

    def run_checks(self, profile: str, label: str, *extra: str) -> tuple[int, dict[str, Any]]:
        result = self.run(
            "--practice", "checks", "run", profile, "--run-root", self.work_path(f"checks-{label}"),
            "--format", "json", *extra, timeout=300,
        )
        self.host_path(f"checks-{label}.json").write_text(result.stdout, encoding="utf-8")
        self.host_path(f"checks-{label}.stderr").write_text(result.stderr, encoding="utf-8")
        try:
            value = json.loads(result.stdout or "{}")
        except ValueError:
            value = {}
        return result.returncode, value

    def wire_requests(self, capture: str, address: str) -> dict[str, int]:
        """Requests on the wire: SIP over UDP, plus each TCP stream counted as
        max(1, SIP requests seen in it) (a TLS stream carries none visibly)."""
        result = self.run(
            "--practice", "--", "tshark", "-n", "-r", capture,
            "-Y", f"ip.dst == {address} && ((tcp.flags.syn == 1 && tcp.flags.ack == 0) || sip.Request-Line)",
            "-T", "fields", "-e", "tcp.stream", "-e", "sip.Method", "-e", "tcp.flags.syn",
        )
        if result.returncode != 0:
            raise GateFailure(f"tshark failed: {result.stderr.strip()[:300]}")
        udp = 0
        streams: dict[str, int] = {}
        for line in result.stdout.splitlines():
            fields = (line.split("\t") + ["", "", ""])[:3]
            stream, methods, _syn = fields
            count = len([item for item in methods.split(",") if item.strip()])
            if stream:
                streams[stream] = streams.get(stream, 0) + count
            else:
                udp += count
        return {"udp_sip": udp, "tcp_streams": len(streams),
                "total": udp + sum(max(1, value) for value in streams.values())}

    def assert_run(self, label: str, code: int, value: dict[str, Any], expected: dict[str, Any]) -> None:
        document = value.get("findings") or {}
        rows = {item["id"]: item for item in document.get("checks", [])}
        found: dict[str, set[str]] = {}
        for item in document.get("findings", []):
            found.setdefault(item["checkId"], set()).add(item["id"])
        self.record(f"{label}: run completed with findings (exit 1)", code == 1 and value.get("state") == "completed",
                    {"exit": code, "state": value.get("state"), "problem": value.get("problem")})
        for check_id, (status, ids) in expected.items():
            row = rows.get(check_id, {})
            got = found.get(check_id, set())
            if status == "any":
                ok = row.get("status") in ("passed", "finding") and got <= ids
            else:
                ok = row.get("status") == status and got == ids
            self.record(f"{label}: {check_id} -> {status} {sorted(ids) or ''}".rstrip(), ok,
                        {"status": row.get("status"), "findings": sorted(got), "summary": row.get("summary")})
        reported = sum(item.get("requestsSent", 0) for item in document.get("checks", []))
        self.record(f"{label}: requestsSent sum equals the result total", reported == value.get("requestsSent"),
                    {"sum": reported, "total": value.get("requestsSent")})
        run_dir = self.project / str(value.get("runDirectory") or "missing")
        capture = "/" + str(Path(value.get("runDirectory") or "missing") / "capture.pcap")
        wire = self.wire_requests(capture, self.address)
        self.record(f"{label}: requests in the capture equal the reported requestsSent ({reported})",
                    wire["total"] == reported and reported > 0, wire)
        password = self.password()
        leaked = [str(path.name) for path in run_dir.rglob("*")
                  if path.is_file() and password.encode() in path.read_bytes()]
        self.record(f"{label}: the practice password appears nowhere in the run directory (capture included)",
                    run_dir.is_dir() and not leaked, leaked or None)
        findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
        self.record(f"{label}: findings.json is the v1 document printed", findings == document
                    and findings.get("apiVersion") == "sippycup.dev/findings/v1")

    def check_udp(self) -> None:
        section = {"approved": UDP_CHECKS, "max_requests": 40, "account": practice.ACCOUNT, "destination": "echo"}
        profile = self.profile_variant("target-profile.yaml", "checks-udp.yaml", section)
        planned = self.run("checks", "plan", profile, "--format", "json")
        plan = json.loads(planned.stdout or "{}")
        self.record("checks plan (UDP) is ready and network-free", planned.returncode == 0 and plan.get("ready")
                    and plan.get("networkActivity") is False, plan.get("blockingErrors"))
        code, value = self.run_checks(profile, "udp", "--secret-file", "work/practice/account.password")
        self.assert_run("udp", code, value, EXPECTED_UDP)
        steps = [row for row in value.get("findings", {}).get("checks", []) if row["id"] == "unauthenticated-invite"]
        self.record("unauthenticated INVITE was challenged and ACKed (2 requests)",
                    bool(steps) and steps[0]["requestsSent"] == 2 and "ACKed" in steps[0]["summary"], steps)

    def check_tls(self) -> None:
        section = {"approved": TLS_CHECKS, "max_requests": 20,
                   "cleartext_endpoints": [{"transport": "udp", "port": 5060}, {"transport": "tcp", "port": 5060}]}
        profile = self.profile_variant("target-profile-tls.yaml", "checks-tls.yaml", section)
        code, value = self.run_checks(profile, "tls")
        self.assert_run("tls", code, value, EXPECTED_TLS)
        detail_path = self.project / str(value.get("runDirectory") or "missing") / "checks-detail.json"
        detail = json.loads(detail_path.read_text(encoding="utf-8")) if detail_path.exists() else {"checks": []}
        by_id = {item["id"]: item["detail"] for item in detail["checks"]}
        probes = {item["label"]: item["outcome"] for item in by_id.get("tls-protocols", {}).get("probes", [])}
        self.record(
            "TLS probes: 1.0, 1.1, 1.3 rejected; 1.2 accepted; NULL and anonymous suites rejected",
            probes.get("TLS 1.0") == "rejected" and probes.get("TLS 1.1") == "rejected"
            and probes.get("TLS 1.2") == "accepted" and probes.get("TLS 1.3") == "rejected"
            and probes.get("NULL ciphers") == "rejected" and probes.get("anonymous ciphers") == "rejected",
            probes,
        )
        protocols = by_id.get("tls-protocols", {})
        untestable = sorted(label for label, outcome in probes.items() if outcome == "untestable")
        reported = sorted((item["id"] for item in (value.get("findings") or {}).get("findings", [])
                           if item["id"] == "tls-protocols.untestable-probes"))
        # The toolbox's OpenSSL 3 cannot offer EXPORT, RC4, or 3DES suites: they must be
        # reported as not testable (never "rejected") and raise the info finding.
        self.record(
            "TLS probes the toolbox cannot offer (EXPORT, RC4, 3DES) are 'untestable' and reported, not 'rejected'",
            untestable == ["3DES ciphers", "EXPORT ciphers", "RC4 ciphers"]
            and sorted(protocols.get("notTestable", [])) == untestable
            and reported == ["tls-protocols.untestable-probes"],
            {"untestable": untestable, "notTestable": protocols.get("notTestable"), "findings": reported},
        )
        certificate = by_id.get("tls-certificate", {})
        self.record(
            f"certificate verified for {practice.DNS_NAME} (EC P-256, SHA-256 signature)",
            certificate.get("verified") is True and certificate.get("verifyName") == practice.DNS_NAME
            and (certificate.get("certificate") or {}).get("keyBits") == 256
            and (certificate.get("certificate") or {}).get("signatureAlgorithm") == "ecdsa-with-SHA256",
            {key: certificate.get(key) for key in ("verified", "verifyName", "daysLeft")},
        )

    def check_tls_modern(self) -> None:
        section = {"approved": ["tls-certificate", "tls-protocols"], "max_requests": 20}
        profile = self.profile_variant("target-profile-tls.yaml", "checks-tls13.yaml", section, port=TLS_MODERN_PORT)
        code, value = self.run_checks(profile, "tls13")
        document = value.get("findings") or {}
        rows = {item["id"]: item for item in document.get("checks", [])}
        found = {item["id"] for item in document.get("findings", []) if item["checkId"] == "tls-protocols"}
        self.record("tls13: run completed", value.get("state") == "completed" and code in (0, 1),
                    {"exit": code, "state": value.get("state"), "problem": value.get("problem")})
        run_dir = self.project / str(value.get("runDirectory") or "missing")
        detail_path = run_dir / "checks-detail.json"
        detail = json.loads(detail_path.read_text(encoding="utf-8")) if detail_path.exists() else {"checks": []}
        protocols = {item["id"]: item["detail"] for item in detail["checks"]}.get("tls-protocols", {})
        accepted = {item["protocol"]: item for item in protocols.get("acceptedVersions", [])}
        self.record(
            f"tls13: port {TLS_MODERN_PORT} accepts TLS 1.2 and TLS 1.3 (cipher reported), rejects 1.0 and 1.1",
            set(accepted) == {"TLS 1.2", "TLS 1.3"} and accepted["TLS 1.3"].get("negotiated") == "TLSv1.3"
            and all(item.get("cipher") for item in accepted.values()),
            {"accepted": accepted, "summary": rows.get("tls-protocols", {}).get("summary")},
        )
        self.record("tls13: no deprecated-version and no no-tls13 finding",
                    not ({"tls-protocols.deprecated-version", "tls-protocols.no-tls13"} & found), sorted(found))
        self.record("tls13: certificate facts from the same run are noted in the protocol detail",
                    (protocols.get("certificate") or {}).get("verified") is True, protocols.get("certificate"))

    def srtp_run(self, name: str, account: str, cleartext: bool, profile_source: str) -> tuple[int, dict[str, Any], dict[str, Any]]:
        section: dict[str, Any] = {"approved": SRTP_CHECKS, "max_requests": 40, "account": account,
                                   "destination": "echo"}
        if cleartext:
            section["cleartext_endpoints"] = [{"transport": "udp", "port": 5060}]
        profile = self.profile_variant(profile_source, f"checks-{name}.yaml", section)
        planned = self.run("checks", "plan", profile, "--format", "json")
        plan = json.loads(planned.stdout or "{}")
        self.record(f"{name}: plan is ready, network-free, and bounds the calls",
                    planned.returncode == 0 and plan.get("ready") and plan.get("networkActivity") is False
                    and plan.get("totalMaxRequests") == (18 if cleartext else 12), plan.get("blockingErrors"))
        code, value = self.run_checks(profile, name, "--secret-file", "work/practice/account.password")
        run_dir = self.project / str(value.get("runDirectory") or "missing")
        detail_path = run_dir / "checks-detail.json"
        detail = json.loads(detail_path.read_text(encoding="utf-8")) if detail_path.exists() else {"checks": []}
        calls = {item["probe"]: item for item in
                 ({c["id"]: c["detail"] for c in detail["checks"]}.get("srtp-policy", {}).get("calls", []))}
        document = value.get("findings") or {}
        reported = sum(item.get("requestsSent", 0) for item in document.get("checks", []))
        self.record(f"{name}: requestsSent sum equals the result total and the calls' own counts",
                    reported == value.get("requestsSent") == sum(item["requests"] for item in calls.values()),
                    {"sum": reported, "total": value.get("requestsSent"),
                     "calls": {key: item["requests"] for key, item in calls.items()}})
        password = self.password()
        leaked = [str(path.name) for path in run_dir.rglob("*")
                  if path.is_file() and password.encode() in path.read_bytes()]
        self.record(f"{name}: the practice password appears nowhere in the run directory", run_dir.is_dir() and not leaked,
                    leaked or None)
        return code, value, calls

    def check_srtp(self) -> None:
        # The default practice account answers anything: plain RTP and SDES, even over UDP.
        code, value, calls = self.srtp_run("srtp-udp", practice.ACCOUNT, False, "target-profile.yaml")
        found = {item["id"] for item in (value.get("findings") or {}).get("findings", [])}
        self.record("srtp-udp: plain RTP accepted and SDES keys accepted over cleartext UDP signaling",
                    found == {"srtp-policy.plain-rtp-accepted", "srtp-policy.keys-over-cleartext"} and code == 1, sorted(found))
        wire = self.wire_requests("/" + str(Path(value["runDirectory"]) / "capture.pcap"), self.address)
        self.record("srtp-udp: the SIP requests in the capture equal the reported requestsSent",
                    wire["udp_sip"] == value.get("requestsSent") > 0, wire)
        offered = {key: (item["offered"], item.get("answerProfile"), item["srtpActive"]) for key, item in calls.items()}
        self.record("srtp-udp: findings state what was offered and answered",
                    offered.get("plain-rtp", ("",))[0].startswith("RTP/AVP without a=crypto")
                    and offered.get("sdes-mandatory", ("",))[0].startswith("RTP/SAVP with a=crypto")
                    and offered["sdes-mandatory"][1] == "RTP/SAVP" and offered["sdes-mandatory"][2] is True, offered)
        # practice-srtp demands SDES: plain RTP is refused (488); SDES works over TLS, and is
        # also accepted over the cleartext UDP listener (the finding this check exists to raise).
        code, value, calls = self.srtp_run("srtp-tls", f"{practice.ACCOUNT}-srtp", True, "target-profile-tls.yaml")
        found = {item["id"] for item in (value.get("findings") or {}).get("findings", [])}
        self.record("srtp-tls: plain RTP refused with 488; mandatory SDES accepted over TLS; SDES keys accepted over cleartext UDP",
                    found == {"srtp-policy.keys-over-cleartext"} and code == 1
                    and calls.get("plain-rtp", {}).get("status") == 488
                    and calls.get("sdes-mandatory", {}).get("srtpActive") is True
                    and calls.get("sdes-over-cleartext", {}).get("srtpActive") is True,
                    {"findings": sorted(found), "calls": {key: (item["outcome"], item["status"], item["srtpActive"])
                                                           for key, item in calls.items()}})
        wire = self.wire_requests("/" + str(Path(value["runDirectory"]) / "capture.pcap"), self.address)
        self.record("srtp-tls: the cleartext UDP requests and the two TLS connections are in the capture",
                    wire["udp_sip"] == calls["sdes-over-cleartext"]["requests"] and wire["tcp_streams"] == 2, wire)

    def check_refusal(self) -> None:
        profile = self.profile_variant("target-profile.yaml", "checks-unapproved.yaml", None)
        capture_process, capture = self.start_capture("checks-unapproved.pcap")
        code, value = self.run_checks(profile, "unapproved")
        self.stop_capture(capture_process)
        frames = self.tshark_count(capture, "frame")
        self.record(
            "a profile without security_checks is refused before any packet (exit 2, 0 frames)",
            code == 2 and value.get("state") == "blocked" and frames == 0
            and not self.host_path("checks-unapproved").exists(),
            {"exit": code, "frames": frames, "blocking": value.get("blockingErrors")},
        )

    def execute(self) -> dict[str, Any]:
        ok = False
        summary: dict[str, Any] = {}
        try:
            self.ensure_target()
            self.check_refusal()
            self.check_udp()
            self.check_tls()
            self.check_tls_modern()
            self.check_srtp()
            ok = True
        except GateFailure:
            ok = False
        finally:
            summary = {
                "schema_version": "sippycup.dev/checks-gate/v1",
                "ok": ok and bool(self.checks) and all(item["ok"] for item in self.checks),
                "checks": self.checks,
                "evidence": str(self.gate_dir.relative_to(self.project)) if self.gate_dir else None,
                "network_activity": "loopback inside the practice namespace only",
            }
            if self.gate_dir:
                (self.gate_dir / "checks-gate-summary.json").write_text(
                    json.dumps(summary, indent=2) + "\n", encoding="utf-8")
            self.teardown()
        return summary


def main() -> int:
    available, reason = images_available()
    if not available:
        print(f"checks gate cannot run: {reason}", file=sys.stderr)
        return 2
    summary = ChecksGate(env=dict(os.environ)).execute()
    passed = sum(1 for item in summary["checks"] if item["ok"])
    print(f"checks gate: {'PASS' if summary['ok'] else 'FAIL'} "
          f"({passed}/{len(summary['checks'])} checks); evidence {summary['evidence']}")
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
