"""Network-free environment diagnostics."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

ESSENTIAL_TOOLS = (
    "python3",
    "sipp",
    "sippycup-options",
    "tshark",
    "dumpcap",
    "tcpdump",
    "capinfos",
    "editcap",
    "mergecap",
    "reordercap",
    "text2pcap",
)
ADDED_TOOLS = (
    "pjsua",
    "turnutils_stunclient",
    "turnutils_uclient",
    "turnutils_peer",
)
OPTIONAL_TOOLS = ("zeek", "visqol", "heplify")
OPTIONAL_PROFILES = {
    "webrtc": {
        "inspect": "./bin/sippycup webrtc status",
        "install": "./bin/sippycup webrtc build",
        "verify": "./bin/sippycup webrtc self-test",
    },
    "webrtc-signaling": {
        "inspect": "./bin/sippycup webrtc status",
        "install": "./bin/sippycup webrtc build",
        "verify": "./bin/sippycup webrtc signaling-self-test",
    },
    "practice-target": {
        "inspect": "./bin/sippycup practice-target status",
        "install": "./bin/sippycup practice-target build",
        "verify": "make practice-gate",
    },
}
_VERSION_ARGUMENTS = {
    "python3": ("--version",),
    "sipp": ("-v",),
    "tshark": ("--version",),
    "dumpcap": ("--version",),
    "tcpdump": ("--version",),
    "capinfos": ("--version",),
    "editcap": ("--version",),
    "mergecap": ("--version",),
    "reordercap": ("--version",),
    "text2pcap": ("--version",),
    "pjsua": ("--version",),
    "turnutils_stunclient": ("--help",),
    "turnutils_uclient": ("--help",),
    "turnutils_peer": ("--help",),
    "zeek": ("--version",),
    "visqol": ("--help",),
    "heplify": ("-v",),
}


def _version(command: str) -> str | None:
    path = shutil.which(command)
    if path is None:
        return None
    display_prefix = ""
    if command.startswith("turnutils_"):
        path = shutil.which("turnserver")
        if path is None:
            return "installed"
        arguments = ("--version",)
        display_prefix = "coturn "
    else:
        arguments = _VERSION_ARGUMENTS.get(command)
    if arguments is None:
        return "installed"
    try:
        result = subprocess.run(
            [path, *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "installed"
    lines = [
        item.strip()
        for item in result.stdout.splitlines()
        if item.strip()
        and not item.startswith('Running as user "root"')
        and "invalid option" not in item
    ]
    if command == "pjsua":
        line = next((item for item in lines if "PJ_VERSION" in item), "")
    else:
        line = next(iter(lines), "")
    if line:
        return f"{display_prefix}{line}"[:240]
    return "installed"


def _effective_capabilities() -> set[int]:
    try:
        lines = Path("/proc/self/status").read_text(encoding="utf-8").splitlines()
        raw = next(line.split()[1] for line in lines if line.startswith("CapEff:"))
        mask = int(raw, 16)
    except (OSError, StopIteration, ValueError):
        return set()
    return {bit for bit in range(64) if mask & (1 << bit)}


def _practice_target(root: Path) -> dict[str, Any]:
    """Report the practice profile from its records in the work directory.

    Doctor never calls the container runtime, so it reads the build record
    that `practice-target build` writes and the connection facts that `up`
    writes. `practice-target status` remains the authoritative live check.
    """
    state = root / "practice"
    image = None
    try:
        record = json.loads((state / "image.json").read_text(encoding="utf-8"))
        if isinstance(record, dict) and isinstance(record.get("image"), str):
            image = record["image"]
    except (OSError, ValueError):
        pass
    return {
        "installed": image is not None,
        "image": image,
        "up": (state / "connection.json").is_file(),
        "source": "work/practice build and up records",
    }


def route_source(address: str, port: int = 5060) -> dict[str, Any]:
    """The local source address the kernel would use to reach ``address``.

    A connected UDP socket makes the kernel look the route up and bind a
    source address; ``connect`` on a datagram socket sends no packet.
    """
    import ipaddress
    import socket

    try:
        family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
    except ValueError:
        return {"ok": False, "error": "not a literal IP address"}
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as probe:
            probe.connect((address, int(port)))
            source = probe.getsockname()[0]
    except OSError as error:
        return {"ok": False, "error": error.strerror or str(error)}
    return {"ok": True, "source": source}


def loopback_capture_probe(timeout: float = 8.0) -> dict[str, Any]:
    """Prove that capture works here: capture our own datagrams on ``lo``.

    The datagrams go from 127.0.0.1 to 127.0.0.1 inside this network
    namespace only; nothing reaches any target. Uses the same dumpcap and
    capabilities as the live commands' capture.
    """
    import socket
    import tempfile
    import time

    dumpcap = shutil.which("dumpcap")
    if dumpcap is None:
        return {"ok": False, "error": "dumpcap is not installed"}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink:
        sink.bind(("127.0.0.1", 0))
        port = sink.getsockname()[1]
        with tempfile.TemporaryDirectory(prefix="sippycup-ready-") as scratch:
            output = Path(scratch) / "probe.pcapng"
            try:
                process = subprocess.Popen(
                    [dumpcap, "-q", "-i", "lo", "-f", f"udp and dst port {port}", "-c", "3",
                     "-a", f"duration:{int(timeout)}", "-w", str(output)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                )
            except OSError as error:
                return {"ok": False, "error": f"cannot start dumpcap: {error.strerror or error}"}
            deadline = time.monotonic() + timeout + 2
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                while process.poll() is None and time.monotonic() < deadline:
                    sender.sendto(b"sippycup-ready-loopback-probe", ("127.0.0.1", port))
                    time.sleep(0.2)
            try:
                _, stderr = process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                _, stderr = process.communicate()
            size = output.stat().st_size if output.is_file() else 0
            packets = 0
            capinfos = shutil.which("capinfos")
            if size and capinfos:
                counted = subprocess.run([capinfos, "-M", "-c", "-r", "-T", str(output)],
                                         stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
                                         check=False)
                fields = counted.stdout.strip().split("\t")
                if counted.returncode == 0 and fields and fields[-1].strip().isdigit():
                    packets = int(fields[-1].strip())
    ok = process.returncode == 0 and packets > 0
    value: dict[str, Any] = {"ok": ok, "interface": "lo", "packets": packets, "exit": process.returncode}
    if not ok:
        lines = [line.strip() for line in (stderr or "").splitlines() if line.strip()]
        value["error"] = (lines[-1] if lines else "no packet was captured")[:300]
    return value


def ready_probe(workdir: str | Path, route_to: str | None = None, route_port: int = 5060) -> dict[str, Any]:
    """The in-container half of ``./bin/sippycup ready``; sends nothing to any target."""
    caps = _effective_capabilities()
    value: dict[str, Any] = {
        "schema_version": "sippycup.dev/ready-probe/v1",
        "network_activity": "loopback only (datagrams to 127.0.0.1 inside this namespace)",
        "network_mode": os.environ.get("SIPPYCUP_NETWORK_MODE", "unknown"),
        "cap_net_raw": 13 in caps,
        "capture": loopback_capture_probe(),
        "tools": {name: shutil.which(name) is not None for name in ("dumpcap", "tshark", "pjsua", "sipp")},
        "route": route_source(route_to, route_port) if route_to else None,
    }
    root = Path(workdir)
    value["workdir_writable"] = root.is_dir() and os.access(root, os.W_OK)
    return value


def diagnose(workdir: str | Path) -> dict[str, Any]:
    tools = {
        name: {"available": shutil.which(name) is not None, "version": _version(name)}
        for name in ESSENTIAL_TOOLS + ADDED_TOOLS + OPTIONAL_TOOLS
    }
    root = Path(workdir)
    caps = _effective_capabilities()
    checks = {
        "workdir_exists": root.is_dir(),
        "workdir_writable": root.is_dir() and os.access(root, os.W_OK),
        "cap_net_admin": 12 in caps,
        "cap_net_raw": 13 in caps,
        "running_as_root": os.geteuid() == 0,
        "essential_tools": all(tools[name]["available"] for name in ESSENTIAL_TOOLS),
        "independent_ua_tools": all(tools[name]["available"] for name in ADDED_TOOLS),
    }
    problems: list[dict[str, str]] = []
    if not checks["workdir_exists"]:
        problems.append({"code": "doctor.workdir_missing", "message": f"{root} does not exist"})
    elif not checks["workdir_writable"]:
        problems.append({"code": "doctor.workdir_read_only", "message": f"{root} is not writable"})
    missing = [name for name in ESSENTIAL_TOOLS if not tools[name]["available"]]
    if missing:
        problems.append(
            {"code": "doctor.tools_missing", "message": f"missing essential tools: {', '.join(missing)}"}
        )
    missing_added = [name for name in ADDED_TOOLS if not tools[name]["available"]]
    if missing_added:
        problems.append(
            {
                "code": "doctor.independent_tools_missing",
                "message": f"missing independent UA/NAT tools: {', '.join(missing_added)}",
            }
        )
    if not checks["cap_net_raw"]:
        problems.append(
            {
                "code": "doctor.capture_capability",
                "message": "CAP_NET_RAW is absent; live capture may fail. Launch through bin/sippycup or capture on the host.",
            }
        )
    return {
        "schema_version": "sippycup.dev/doctor/v1",
        "network_activity": False,
        "ok": not any(item["code"] != "doctor.capture_capability" for item in problems),
        "checks": checks,
        "tools": tools,
        "optional_profiles": OPTIONAL_PROFILES,
        "practice_target": _practice_target(root),
        "problems": problems,
    }
