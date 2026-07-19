"""Network-free environment diagnostics."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

ESSENTIAL_TOOLS = (
    "python3",
    "sipp",
    "sipsak",
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
_VERSION_ARGUMENTS = {
    "python3": ("--version",),
    "sipp": ("-v",),
    "sipsak": ("--version",),
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
        "problems": problems,
    }
