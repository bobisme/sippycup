#!/usr/bin/env python3
"""Run the real disposable chaos exit gate and save bounded JSON evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import signal
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_chaos.lifecycle import ChaosLifecycle  # noqa: E402
from sippycup_chaos.profiles import compile_profile, load_profile  # noqa: E402
from sippycup_chaos.topology import (  # noqa: E402
    Direction,
    TopologyRequest,
    collect_network_snapshot,
    detect_capabilities,
    plan_topology,
)


PROFILE_ROOT = ROOT / "profiles" / "chaos"
TARGET = "198.18.0.6"
CONTROL = "198.18.0.2"
SUMMARY_RE = re.compile(
    r"(?P<sent>\d+) packets transmitted, (?P<received>\d+) received,"
    r"(?: \+(?P<duplicates>\d+) duplicates,)? "
    r"(?:\+(?P<errors>\d+) errors, )?"
    r"(?P<loss>[0-9.]+)% packet loss, time (?P<elapsed>\d+)ms"
)
RTT_RE = re.compile(
    r"rtt min/avg/max/mdev = "
    r"(?P<minimum>[0-9.]+)/(?P<average>[0-9.]+)/"
    r"(?P<maximum>[0-9.]+)/(?P<mdev>[0-9.]+) ms"
)
SEQUENCE_RE = re.compile(r"icmp_seq=(\d+)")


class _Cancellation:
    def __init__(self) -> None:
        self.signum: int | None = None
        self.active: ChaosLifecycle | None = None

    def request(self, signum: int) -> None:
        if self.signum is None:
            self.signum = signum
        if self.active is not None:
            self.active.cancel(signum)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _write_exclusive(path: Path, value: Any) -> None:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    with path.open("x", encoding="utf-8") as destination:
        destination.write(rendered)


def _parse_ping(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {
            "measurable": False,
            "reason": f"{path.name} was not produced",
        }
    text = path.read_text(encoding="utf-8", errors="replace")
    summary = SUMMARY_RE.search(text)
    if summary is None:
        return {"measurable": False, "reason": "ping summary is absent"}
    values: dict[str, Any] = {
        "measurable": True,
        "sent": int(summary.group("sent")),
        "received": int(summary.group("received")),
        "duplicates": int(summary.group("duplicates") or 0),
        "errors": int(summary.group("errors") or 0),
        "lossPercent": float(summary.group("loss")),
        "elapsedMilliseconds": int(summary.group("elapsed")),
    }
    rtt = RTT_RE.search(text)
    if rtt is not None:
        values["rttMilliseconds"] = {
            key: float(rtt.group(key))
            for key in ("minimum", "average", "maximum", "mdev")
        }
    sequences = [int(match.group(1)) for match in SEQUENCE_RE.finditer(text)]
    values["arrivalInversions"] = sum(
        current < previous
        for previous, current in zip(sequences, sequences[1:])
    )
    values["observedReplies"] = len(sequences)
    return values


def _traffic_command(name: str, directory: Path) -> list[str]:
    target = directory / "target-ping.txt"
    control = directory / "control-ping.txt"
    capabilities = directory / "traffic-effective-capabilities.txt"
    prefix = f"awk '/^CapEff:/ {{print $2}}' /proc/self/status > {capabilities}; "
    if name == "mtu-fragmentation":
        oversize = directory / "oversize-ping.txt"
        script = prefix + (
            f"ping -n -i 0.01 -M do -s 1252 -c 20 {TARGET} > {target}; "
            f"ping -n -M do -s 1253 -c 5 -W 1 {TARGET} > {oversize} || true; "
            f"ping -n -i 0.01 -c 20 {CONTROL} > {control}"
        )
    else:
        count, interval, size = {
            "asymmetric-media": (60, "0.001", 1400),
            "burst-loss": (1000, "0.001", 160),
            "clean": (200, "0.002", 160),
            "constrained-uplink": (60, "0.001", 1400),
            "duplicate": (1000, "0.001", 160),
            "fixed-delay": (100, "0.002", 160),
            "jitter": (300, "0.001", 160),
            "reorder": (1000, "0.001", 160),
        }[name]
        script = prefix + (
            f"ping -n -D -i {interval} -s {size} -c {count} {TARGET} > {target}; "
            f"ping -n -i 0.01 -c 20 {CONTROL} > {control}"
        )
    return ["sh", "-ceu", script]


def _profile_verdict(name: str, observed: dict[str, Any]) -> list[str]:
    target = observed["target"]
    control = observed["control"]
    failures = []
    if not target.get("measurable"):
        failures.append("target traffic was not measurable")
        return failures
    if not control.get("measurable"):
        failures.append("unrelated control traffic was not measurable")
    else:
        if control["lossPercent"] != 0:
            failures.append("unrelated control traffic had loss")
        if control.get("rttMilliseconds", {}).get("average", 999) >= 10:
            failures.append("unrelated control traffic was impaired")
    average = target.get("rttMilliseconds", {}).get("average", 0)
    mdev = target.get("rttMilliseconds", {}).get("mdev", 0)
    if name == "clean" and (target["lossPercent"] != 0 or average >= 10):
        failures.append("clean target traffic was unexpectedly impaired")
    elif name == "fixed-delay" and not 145 <= average <= 190:
        failures.append("fixed delay did not produce the expected symmetric RTT")
    elif name == "jitter" and not (average >= 90 and mdev >= 5):
        failures.append("jitter did not produce observable delay variation")
    elif name == "burst-loss" and target["lossPercent"] <= 0:
        failures.append("burst loss produced no observed loss")
    elif name == "duplicate" and target["duplicates"] <= 0:
        failures.append("duplicate profile produced no duplicate replies")
    elif name == "reorder" and target["arrivalInversions"] <= 0:
        failures.append("reorder profile produced no arrival inversion")
    elif name in {"constrained-uplink", "asymmetric-media"}:
        if target["lossPercent"] < 20 or average < 50:
            failures.append("rate-limited queue did not constrain target traffic")
    elif name == "mtu-fragmentation":
        oversize = observed["oversize"]
        if target["lossPercent"] != 0 or not oversize.get("measurable"):
            failures.append("MTU boundary probes were not measurable")
        elif oversize["received"] != 0:
            failures.append("packet above the frozen MTU unexpectedly succeeded")
    return failures


def run_gate(
    output: Path, cancellation: _Cancellation | None = None
) -> dict[str, Any]:
    cancellation = cancellation or _Cancellation()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    capabilities = detect_capabilities()
    before = collect_network_snapshot(()).to_dict()
    result: dict[str, Any] = {
        "apiVersion": "sippycup.dev/chaos-exit-gate/v1",
        "capabilities": capabilities.to_dict(),
        "controllerSnapshotBefore": before,
        "controllerSnapshotBeforeSha256": _sha256(before),
        "profiles": [],
        "failures": [],
    }
    for index, profile_path in enumerate(sorted(PROFILE_ROOT.glob("*.yaml")), 1):
        if cancellation.signum is not None:
            result["failures"].append(
                f"gate cancelled by {signal.Signals(cancellation.signum).name}"
            )
            break
        name = profile_path.stem
        profile_directory = output / name
        profile_directory.mkdir(mode=0o700)
        prefix = f"ceg{index:02d}{name.replace('-', '')[:12]}"
        namespace_names = tuple(
            f"{prefix}-{suffix}" for suffix in ("test", "impair", "uplink")
        )
        frozen = collect_network_snapshot(namespace_names)
        topology = plan_topology(
            TopologyRequest(
                targets=(f"{TARGET}/32",),
                direction=Direction.ASYMMETRIC,
                namespace_prefix=prefix,
                require_mtu=True,
            ),
            capabilities,
            frozen,
        )
        profile, digest = load_profile(profile_path)
        impairment = compile_profile(topology, profile, source_sha256=digest)
        lifecycle = ChaosLifecycle(topology, impairment)
        cancellation.active = lifecycle
        try:
            if cancellation.signum is not None:
                lifecycle.cancel(cancellation.signum)
            report = lifecycle.run(_traffic_command(name, profile_directory))
        finally:
            cancellation.active = None
        observed = {
            "target": _parse_ping(profile_directory / "target-ping.txt"),
            "control": _parse_ping(profile_directory / "control-ping.txt"),
        }
        capability_path = profile_directory / "traffic-effective-capabilities.txt"
        capability_hex = (
            capability_path.read_text(encoding="ascii").strip()
            if capability_path.is_file()
            else ""
        )
        observed["trafficEffectiveCapabilitiesHex"] = capability_hex
        oversize = profile_directory / "oversize-ping.txt"
        if oversize.exists():
            observed["oversize"] = _parse_ping(oversize)
        if cancellation.signum is not None:
            failures = [
                f"gate cancelled by {signal.Signals(cancellation.signum).name}"
            ]
        else:
            failures = _profile_verdict(name, observed)
        if capability_hex and re.fullmatch(r"[0-9a-fA-F]+", capability_hex):
            capability_mask = int(capability_hex, 16)
            if capability_mask & ((1 << 12) | (1 << 21)):
                failures.append("traffic child retained NET_ADMIN or SYS_ADMIN")
        elif cancellation.signum is None:
            failures.append("traffic child capability evidence is missing or malformed")
        if report["state"] != "succeeded":
            failures.append(f"lifecycle state was {report['state']}: {report['error']}")
        if not report["cleanup"]["restored"]:
            failures.append("lifecycle did not prove exact restoration")
        entry = {
            "name": name,
            "requested": impairment["directions"],
            "observed": observed,
            "lifecycle": {
                "state": report["state"],
                "cleanup": report["cleanup"],
            },
            "passed": not failures,
            "failures": failures,
        }
        _write_exclusive(profile_directory / "lifecycle-report.json", report)
        result["profiles"].append(entry)
        result["failures"].extend(f"{name}: {item}" for item in failures)
        if cancellation.signum is not None:
            result["failures"].append(
                f"gate cancelled by {signal.Signals(cancellation.signum).name}"
            )
            break
    after = collect_network_snapshot(()).to_dict()
    result["controllerSnapshotAfter"] = after
    result["controllerSnapshotAfterSha256"] = _sha256(after)
    result["controllerRestored"] = _canonical(before) == _canonical(after)
    if not result["controllerRestored"]:
        result["failures"].append(
            "controller routes/qdiscs differ after the profile matrix"
        )
    result["passed"] = not result["failures"]
    if cancellation.signum is not None:
        result["cancelledBy"] = signal.Signals(cancellation.signum).name
    _write_exclusive(output / "exit-gate-report.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    cancellation = _Cancellation()
    previous = {}

    def request_cancel(signum: int, _frame: object) -> None:
        cancellation.request(signum)

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.signal(signum, request_cancel)
    try:
        result = run_gate(args.output, cancellation)
    except BaseException as error:
        print(f"chaos exit gate: {error}", file=sys.stderr)
        return 2
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    if cancellation.signum is not None:
        return 130 if cancellation.signum == signal.SIGINT else 143
    if not result["passed"]:
        for failure in result["failures"]:
            print(f"FAIL {failure}", file=sys.stderr)
        return 1
    print(
        f"PASS {len(result['profiles'])} profiles; "
        f"controller snapshot {result['controllerSnapshotAfterSha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
