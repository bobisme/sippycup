"""Bounded, read-only capture triage."""

from __future__ import annotations

import csv
import io
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

MAX_CAPTURE_BYTES = 512 * 1024 * 1024
_AUTHORIZATION = re.compile(br"(?im)^(?:proxy-)?authorization\s*:")
_CALL_ID = re.compile(br"(?im)^call-id\s*:")


class TriageError(ValueError):
    """Capture triage cannot safely proceed."""


def _run(argv: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TriageError(f"command timed out: {argv[0]}") from exc
    except OSError as exc:
        raise TriageError(f"cannot run {argv[0]}: {exc}") from exc


def _metadata(path: Path) -> dict[str, Any]:
    result = _run(["capinfos", "-Tm", "-c", "-s", "-u", str(path)])
    if result.returncode != 0:
        raise TriageError(result.stderr.strip() or "capinfos rejected the capture")
    rows = list(csv.DictReader(io.StringIO(result.stdout)))
    if len(rows) != 1:
        raise TriageError("capinfos returned unexpected metadata")
    row = rows[0]
    try:
        return {
            "packets": int(row["Number of packets"]),
            "bytes": int(row["File size (bytes)"]),
            "duration_seconds": float(row["Capture duration (seconds)"]),
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise TriageError("capinfos metadata is malformed") from exc


def _protocol_counts(path: Path) -> dict[str, int]:
    names = ("sip", "sdp", "rtp", "rtcp", "tls", "stun")
    result = _run(
        [
            "tshark",
            "-r",
            str(path),
            "-q",
            "-z",
            f"io,stat,0,{','.join(names)}",
        ]
    )
    if result.returncode != 0:
        raise TriageError(result.stderr.strip() or "tshark rejected the capture")
    if len(result.stdout) > 1024 * 1024:
        raise TriageError("tshark protocol hierarchy exceeded the output limit")
    counts = {name: 0 for name in names}
    for line in result.stdout.splitlines():
        columns = [column.strip() for column in line.split("|")]
        if len(columns) != 15 or "<>" not in columns[1]:
            continue
        try:
            values = [int(value) for value in columns[2:14]]
        except ValueError:
            continue
        return {name: values[index * 2] for index, name in enumerate(names)}
    raise TriageError("tshark protocol statistics were malformed")


def analyze(path: str | Path) -> dict[str, Any]:
    capture = Path(path)
    if not capture.is_file() or not capture.exists():
        raise TriageError(f"capture is not readable: {capture}")
    size = capture.stat().st_size
    if size > MAX_CAPTURE_BYTES:
        raise TriageError(f"capture exceeds {MAX_CAPTURE_BYTES} bytes")
    if shutil.which("capinfos") is None or shutil.which("tshark") is None:
        raise TriageError("capinfos and tshark are required")

    metadata = _metadata(capture)
    protocols = _protocol_counts(capture)
    with capture.open("rb") as source:
        prefix = source.read(32 * 1024 * 1024)
    privacy = {
        "authorization_material_observed": bool(_AUTHORIZATION.search(prefix)),
        "call_identifiers_observed": bool(_CALL_ID.search(prefix)),
        "inspection_complete": size <= len(prefix),
        "values_disclosed": False,
    }
    findings: list[dict[str, Any]] = []
    findings.append(
        {
            "code": "capture.nonempty",
            "verdict": "pass" if metadata["packets"] else "fail",
            "message": f"{metadata['packets']} packets captured",
        }
    )
    findings.append(
        {
            "code": "capture.sip_present",
            "verdict": "pass" if protocols["sip"] else "unknown",
            "message": f"{protocols['sip']} SIP frames decoded",
        }
    )
    findings.append(
        {
            "code": "capture.media_present",
            "verdict": "pass" if protocols["rtp"] or protocols["rtcp"] else "unknown",
            "message": f"{protocols['rtp']} RTP and {protocols['rtcp']} RTCP frames decoded",
        }
    )
    if privacy["authorization_material_observed"]:
        findings.append(
            {
                "code": "privacy.authorization_present",
                "verdict": "warn",
                "message": "authorization material is present; do not share the source capture",
            }
        )
    return {
        "schema_version": "sippycup.dev/triage/v1",
        "network_activity": False,
        "capture": str(capture),
        "metadata": metadata,
        "protocol_frames": protocols,
        "privacy": privacy,
        "optional_analyzers": {
            "zeek": shutil.which("zeek") is not None,
            "visqol": shutil.which("visqol") is not None,
        },
        "findings": findings,
    }
