#!/usr/bin/env python3
"""Live codec-control and call-matrix gate against the practice target.

It reuses the practice gate's helpers (launcher, target lifecycle) and proves,
with the real PJSUA and Asterisk, that:

- the codec names Sippycup accepts are exactly the image PJSUA's codecs;
- ``call --codec PCMA`` offers only PCMA (plus telephone-event) in the
  captured SDP and the captured RTP uses only payload type 8;
- an unsupported codec gets 488 and ``call-media-not-acceptable``, and an
  unknown name is refused (exit 2) before anything starts;
- ``matrix run`` over the practice UDP and TLS profiles produces the grid
  and ``matrix.json``, and stops at the first 429 instead of continuing.

Evidence is kept under ``work/practice/codec-gate-<UTC>/``.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tools"))

import practice_gate  # noqa: E402
from practice_gate import GateFailure  # noqa: E402

from sippycup import practice  # noqa: E402
from sippycup_softphone.driver import SUPPORTED_CODECS, codec_matches, parse_codec_list  # noqa: E402

CODEC_LISTING_SCRIPT = (
    '(sleep 2; printf "Cp\\n"; sleep 1; printf "\\n"; sleep 1; printf "q\\n") | '
    "pjsua --null-audio --no-color --no-tcp --local-port=0 --log-level=1 --app-log-level=3"
)


class CodecGate(practice_gate.Gate):
    def ensure_target(self) -> None:
        super().ensure_target()
        assert self.gate_dir is not None
        renamed = self.gate_dir.with_name("codec-" + self.gate_dir.name)
        self.gate_dir.rename(renamed)
        self.gate_dir = renamed

    def call(self, label: str, *arguments: str) -> tuple[int, dict[str, Any], str]:
        result = self.run(
            "--practice", "call", "work/practice/target-profile.yaml", "--dial", "echo",
            "--username", "practice", "--secret-file", "work/practice/account.password",
            "--duration", "3", "--run-root", self.work_path(f"calls-{label}"), "--format", "json",
            *arguments, timeout=240,
        )
        self.host_path(f"call-{label}.json").write_text(result.stdout, encoding="utf-8")
        try:
            value = json.loads(result.stdout or "{}")
        except ValueError:
            value = {}
        return result.returncode, value, result.stderr

    def check_codec_list(self) -> None:
        result = self.run("--practice", "--", "sh", "-c", CODEC_LISTING_SCRIPT, timeout=60)
        listed = parse_codec_list(result.stdout)
        self.host_path("pjsua-codecs.txt").write_text(result.stdout, encoding="utf-8")
        entries = [{"name": item.split("/")[0], "clockRate": int(item.split("/")[1])} for item in listed]
        # Every enabled codec is reachable by exactly one supported name,
        # and every supported name reaches an enabled codec.
        reachable = all(sum(codec_matches(entry, name) for name in SUPPORTED_CODECS) == 1 for entry in entries)
        named = all(any(codec_matches(entry, name) for entry in entries) for name in SUPPORTED_CODECS)
        self.record(
            "the image PJSUA's enabled codecs are exactly the supported --codec names",
            bool(listed) and reachable and named,
            {"pjsua": listed, "supported": list(SUPPORTED_CODECS)},
        )

    def check_guided_codec(self) -> None:
        code, value, _stderr = self.call("pcma", "--codec", "PCMA")
        codec = value.get("codec") or {}
        wire = codec.get("wire") or {}
        types = wire.get("rtpPayloadTypes") or {}
        self.record(
            "call --codec PCMA: the captured offer lists only PCMA and telephone-event, and all "
            "captured RTP is payload type 8",
            code == 0 and value.get("verdict") == "pass" and codec.get("offered") == ["PCMA/8000"]
            and wire.get("sdpSource") == "capture" and (wire.get("offerFormats") or [None])[0] == 8
            and len(wire.get("offerFormats") or []) == 2
            and set(types.get("outbound") or {}) == {"8"} and set(types.get("inbound") or {}) == {"8"}
            and wire.get("verified") is True,
            {"exit": code, "verdict": value.get("verdict"), "codec": codec},
        )
        code, value, _stderr = self.call("g722", "--codec", "G722")
        codec = value.get("codec") or {}
        self.record(
            "call --codec G722 (not allowed by the practice endpoint): 488 is call-media-not-acceptable",
            code == 1 and value.get("verdict") == "call-media-not-acceptable"
            and (value.get("softphone") or {}).get("final_status") == 488
            and ((codec.get("wire") or {}).get("offerFormats") or [None])[0] == 9,
            {"exit": code, "verdict": value.get("verdict"), "codec": codec},
        )
        code, value, stderr = self.call("unknown", "--codec", "G729")
        self.record(
            "call --codec G729 (not in the image PJSUA) is refused with exit 2 before anything starts",
            code == 2 and "unsupported codec" in stderr and not self.host_path("calls-unknown").exists(),
            {"exit": code, "stderr": stderr.strip()[-200:]},
        )

    def matrix_profiles(self) -> list[str]:
        import yaml

        paths = []
        for name in ("target-profile.yaml", "target-profile-tls.yaml"):
            document = yaml.safe_load((practice.state_dir(self.project) / name).read_text(encoding="utf-8"))
            document["limits"]["max_calls"] = 4
            document["media"] = {"codecs": ["PCMU", "PCMA", "G722"]}
            target = "matrix-" + name
            practice.write_private(self.host_path(target), yaml.safe_dump(document, sort_keys=False))
            paths.append(self.work_path(target))
        return paths

    def matrix(self, label: str, *arguments: str) -> tuple[int, dict[str, Any], str]:
        result = self.run(
            "--practice", "matrix", "run", *self.matrix_profiles(), "--username", "practice",
            "--secret-file", "work/practice/account.password", "--duration", "3",
            "--run-root", self.work_path(f"matrix-calls-{label}"),
            "--matrix-root", self.work_path(f"matrix-{label}"), "--format", "json", *arguments,
            timeout=600,
        )
        self.host_path(f"matrix-{label}.json").write_text(result.stdout, encoding="utf-8")
        try:
            value = json.loads(result.stdout or "{}")
        except ValueError:
            value = {}
        return result.returncode, value, result.stderr

    def check_matrix(self) -> None:
        code, value, stderr = self.matrix("grid", "--dial", "echo", "--codecs", "PCMU,G722")
        grid = {
            (cell.get("transport"), cell.get("codec")): cell.get("verdict")
            for cell in value.get("cells") or []
        }
        records = sorted(self.host_path("matrix-grid").glob("*/matrix.json"))
        self.record(
            "matrix run (udp, tls) x (PCMU, G722): PCMU passes, G722 is call-media-not-acceptable, "
            "exit 1, one matrix.json",
            code == 1 and grid == {
                ("udp", "PCMU"): "pass", ("udp", "G722"): "call-media-not-acceptable",
                ("tls", "PCMU"): "pass", ("tls", "G722"): "call-media-not-acceptable",
            } and len(records) == 1
            and all(cell.get("codecVerifiedOnWire") for cell in value.get("cells") or []
                    if cell.get("verdict") == "pass"),
            {"exit": code, "grid": {f"{key[0]}/{key[1]}": item for key, item in grid.items()},
             "stderr": stderr.strip()[-300:] or None},
        )
        code, value, _stderr = self.matrix("stop", "--dial", "ratelimit", "--codecs", "PCMU,PCMA",
                                           "--transports", "udp")
        self.record(
            "matrix run stops at the first 429 (exit 3) and leaves the rest not-run",
            code == 3 and value.get("callsPlaced") == 1
            and [cell.get("status") for cell in value.get("cells") or []] == ["run", "not-run"],
            {"exit": code, "stop": value.get("stopReason")},
        )
        password = self.password()
        leaked = [
            str(path) for path in self.gate_dir.rglob("*")
            if path.is_file() and path.suffix != ".pcap"
            and password in path.read_text(encoding="utf-8", errors="replace")
        ]
        self.record("the practice password appears nowhere in the codec gate evidence", not leaked, leaked or None)

    def execute(self) -> dict[str, Any]:
        ok = False
        try:
            self.ensure_target()
            self.check_codec_list()
            self.check_guided_codec()
            self.check_matrix()
            ok = True
        except GateFailure:
            ok = False
        finally:
            summary = {
                "schema_version": "sippycup.dev/codec-gate/v1",
                "ok": ok and all(item["ok"] for item in self.checks) and bool(self.checks),
                "checks": self.checks,
                "evidence": str(self.gate_dir.relative_to(self.project)) if self.gate_dir else None,
                "network_activity": "loopback inside the practice namespace only",
                "finished": datetime.now(timezone.utc).isoformat(),
            }
            if self.gate_dir:
                (self.gate_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
            self.teardown()
        return summary


def main() -> int:
    available, reason = practice_gate.images_available()
    if not available:
        print(f"codec gate cannot run: {reason}", file=sys.stderr)
        return 2
    summary = CodecGate().execute()
    passed = sum(1 for item in summary["checks"] if item["ok"])
    print(f"codec gate: {'PASS' if summary['ok'] else 'FAIL'} ({passed}/{len(summary['checks'])} checks); "
          f"evidence {summary['evidence']}")
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
