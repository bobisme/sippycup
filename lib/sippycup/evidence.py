"""Deterministic evidence inventory, sensitivity labels, and privacy lint."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import mimetypes
import os
import re
import stat
import struct
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


MANIFEST_VERSION = "sippycup.dev/evidence-manifest/v1"
LINT_VERSION = "sippycup.dev/privacy-lint/v1"
OVERRIDE_VERSION = "sippycup.dev/privacy-override/v1"
DEFAULT_MAX_CAPTURE_BYTES = 512 * 1024 * 1024
MAX_TEXT_SCAN_BYTES = 32 * 1024 * 1024
MANIFEST_NAME = "evidence-manifest.json"
EXPECTED_ARTIFACTS = {
    "plan.json",
    "reviewed-manifest.yaml",
    "commands.json",
    "events.jsonl",
    "versions.json",
    "capture.pcap",
    "report.txt",
    "report.stderr",
    "result.json",
    "timestamps.json",
    "preflight.json",
}
CAPTURE_SUFFIXES = {".pcap", ".pcapng"}
AUDIO_SUFFIXES = {".wav", ".wave", ".flac", ".mp3", ".ogg", ".opus", ".pcm", ".raw", ".ulaw", ".alaw", ".au"}
AUTHORIZATION = re.compile(br"(?im)^(?:proxy-)?authorization\s*:\s*\S.+$")
CALL_ID = re.compile(br"(?im)^call-id\s*:\s*[^\r\n]+")
SIP_USER = re.compile(br"(?i)sips?:([^@;>\s]+)@")
PHONE_IDENTIFIER = re.compile(br"(?<![0-9])\+[0-9][0-9() -]{5,}[0-9](?![0-9])")
ASCII_ADDRESS = re.compile(
    rb"(?<![0-9A-Fa-f:.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])"
    rb"|(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"
)


class EvidenceError(ValueError):
    """Evidence collection or privacy policy failure."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _media_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "application/json"
    if suffix == ".jsonl":
        return "application/x-ndjson"
    if suffix in {".yaml", ".yml"}:
        return "application/yaml"
    if suffix == ".pcap":
        return "application/vnd.tcpdump.pcap"
    if suffix == ".pcapng":
        return "application/x-pcapng"
    return mimetypes.guess_type(path.name)[0] or "application/octet-stream"


def _provenance(relative: str) -> str:
    name = Path(relative).name
    if name == "notes.jsonl":
        return "operator-note"
    if name == "journal.jsonl":
        return "operator-journal"
    if Path(relative).suffix.lower() in CAPTURE_SUFFIXES:
        return "network-capture"
    if name.startswith("report") or name.startswith("assert") or name.startswith("stats"):
        return "offline-analysis"
    if name in {"plan.json", "reviewed-manifest.yaml"}:
        return "reviewed-authorization"
    if name in {"commands.json", "versions.json"}:
        return "runtime-inventory"
    if name in {"events.jsonl", "result.json", "timestamps.json", "preflight.json"}:
        return "campaign-runtime"
    return "run-artifact"


def _sensitivity(relative: str, data: bytes, retain_payload: bool) -> str:
    path = Path(relative)
    name = path.name
    suffix = path.suffix.lower()
    if suffix in AUDIO_SUFFIXES or _audio_magic(data):
        return "restricted"
    if suffix in CAPTURE_SUFFIXES:
        return "restricted" if retain_payload else "confidential"
    if name in {"notes.jsonl", "journal.jsonl"} or AUTHORIZATION.search(data) or CALL_ID.search(data):
        return "confidential"
    if name in {"report.txt", "report.stderr", "preflight.json"}:
        return "confidential"
    if name in {
        "plan.json",
        "reviewed-manifest.yaml",
        "commands.json",
        "events.jsonl",
        "versions.json",
        "result.json",
        "timestamps.json",
    }:
        return "internal"
    return "confidential"


def _audio_magic(data: bytes) -> bool:
    return (
        data.startswith(b"fLaC")
        or data.startswith(b"OggS")
        or data.startswith(b"ID3")
        or data.startswith(b".snd")
        or (data.startswith(b"RIFF") and data[8:12] == b"WAVE")
    )


def _digest_and_prefix(path: Path) -> tuple[int, str, bytes]:
    digest = hashlib.sha256()
    size = 0
    prefix = bytearray()
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
                remaining = MAX_TEXT_SCAN_BYTES - len(prefix)
                if remaining > 0:
                    prefix.extend(chunk[:remaining])
    except OSError as error:
        raise EvidenceError(f"cannot inventory evidence artifact {path}: {error}") from error
    return size, digest.hexdigest(), bytes(prefix)


def _read_plan(root: Path) -> dict[str, Any]:
    try:
        value = json.loads((root / "plan.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _authorized_networks(plan: dict[str, Any], extras: Iterable[str]) -> list[Any]:
    authorization = plan.get("authorization", {})
    if not isinstance(authorization, dict):
        raise EvidenceError("plan authorization must be an object")
    configured = authorization.get("networks", [])
    if not isinstance(configured, list):
        raise EvidenceError("plan authorization networks must be a list")
    raw = list(configured) + list(extras)
    networks = []
    for value in raw:
        try:
            networks.append(ipaddress.ip_network(value, strict=True))
        except (TypeError, ValueError) as error:
            raise EvidenceError(f"invalid expected network {value!r}") from error
    return networks


def _classic_pcap_addresses(data: bytes) -> tuple[set[str], bool]:
    if len(data) < 24:
        return set(), False
    if data[:4] == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif data[:4] == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        return set(), False
    addresses: set[str] = set()
    offset = 24
    while offset + 16 <= len(data):
        _seconds, _fraction, included, _original = struct.unpack(
            endian + "IIII", data[offset : offset + 16]
        )
        offset += 16
        if included > 1024 * 1024 or offset + included > len(data):
            return addresses, False
        packet = data[offset : offset + included]
        offset += included
        if len(packet) < 14:
            continue
        network = 14
        ether_type = int.from_bytes(packet[12:14], "big")
        if ether_type == 0x8100 and len(packet) >= 18:
            ether_type = int.from_bytes(packet[16:18], "big")
            network = 18
        if ether_type == 0x0800 and len(packet) >= network + 20:
            addresses.add(str(ipaddress.ip_address(packet[network + 12 : network + 16])))
            addresses.add(str(ipaddress.ip_address(packet[network + 16 : network + 20])))
        elif ether_type == 0x86DD and len(packet) >= network + 40:
            addresses.add(str(ipaddress.ip_address(packet[network + 8 : network + 24])))
            addresses.add(str(ipaddress.ip_address(packet[network + 24 : network + 40])))
    return addresses, offset == len(data)


def _finding(code: str, path: str, detail: str) -> dict[str, str]:
    return {"code": code, "severity": "high", "path": path, "detail": detail}


def privacy_findings(
    root: Path,
    artifacts: list[dict[str, Any]],
    *,
    max_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
    expected_networks: Iterable[str] = (),
) -> list[dict[str, str]]:
    if isinstance(max_capture_bytes, bool) or not isinstance(max_capture_bytes, int) or max_capture_bytes < 1:
        raise EvidenceError("max_capture_bytes must be a positive integer")
    plan = _read_plan(root)
    networks = _authorized_networks(plan, expected_networks)
    findings: list[dict[str, str]] = []
    for artifact in artifacts:
        relative = artifact["path"]
        path = root / relative
        suffix = path.suffix.lower()
        size = artifact["size"]
        if suffix in CAPTURE_SUFFIXES and size > max_capture_bytes:
            findings.append(
                _finding(
                    "oversized-capture",
                    relative,
                    f"{size} bytes exceeds local limit {max_capture_bytes}",
                )
            )
        if artifact["mediaType"].startswith("audio/") or suffix in AUDIO_SUFFIXES:
            findings.append(
                _finding("decoded-audio", relative, "decoded audio artifact is present")
            )
        read_limit = min(size, MAX_TEXT_SCAN_BYTES)
        try:
            with path.open("rb") as source:
                data = source.read(read_limit)
        except OSError as error:
            findings.append(_finding("artifact-unreadable", relative, str(error)))
            continue
        if _audio_magic(data):
            findings.append(
                _finding("decoded-audio", relative, "decoded audio signature is present")
            )
        if AUTHORIZATION.search(data):
            findings.append(
                _finding(
                    "authorization-material",
                    relative,
                    "SIP Authorization or Proxy-Authorization material is present",
                )
            )
        if CALL_ID.search(data) or SIP_USER.search(data) or PHONE_IDENTIFIER.search(data):
            findings.append(
                _finding(
                    "subscriber-identifier",
                    relative,
                    "SIP call, user, or phone identifier is present",
                )
            )
        addresses: set[str] = set()
        for match in ASCII_ADDRESS.finditer(data):
            try:
                addresses.add(str(ipaddress.ip_address(match.group().decode())))
            except ValueError:
                pass
        if suffix in CAPTURE_SUFFIXES:
            capture_addresses, parsed = _classic_pcap_addresses(data)
            addresses.update(capture_addresses)
            if size > len(data) or not parsed:
                findings.append(
                    _finding(
                        "capture-uninspected",
                        relative,
                        "capture could not be completely privacy-inspected",
                    )
                )
        unexpected = sorted(
            address
            for address in addresses
            if not any(
                ipaddress.ip_address(address).version == network.version
                and ipaddress.ip_address(address) in network
                for network in networks
            )
        )
        if unexpected:
            findings.append(
                _finding(
                    "unexpected-network",
                    relative,
                    "addresses outside expected networks: " + ", ".join(unexpected),
                )
            )
        if size > MAX_TEXT_SCAN_BYTES and suffix not in CAPTURE_SUFFIXES:
            findings.append(
                _finding(
                    "artifact-uninspected",
                    relative,
                    f"artifact exceeds {MAX_TEXT_SCAN_BYTES}-byte inspection limit",
                )
            )
    unique = {
        (item["code"], item["path"], item["detail"]): item for item in findings
    }
    return [unique[key] for key in sorted(unique)]


def build_evidence_manifest(
    root: Path,
    *,
    created_at: str | None = None,
    max_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
    expected_networks: Iterable[str] = (),
) -> dict[str, Any]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise EvidenceError("evidence root must be a directory")
    plan = _read_plan(root)
    retain_payload = bool(plan.get("evidence", {}).get("retainPayload", True))
    artifacts = []
    for path in sorted(root.rglob("*")):
        if path.name == MANIFEST_NAME:
            continue
        if path.is_symlink():
            raise EvidenceError(f"evidence contains unsupported symlink {path.relative_to(root)}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        size, digest, prefix = _digest_and_prefix(path)
        artifacts.append(
            {
                "path": relative,
                "mediaType": _media_type(path),
                "size": size,
                "sha256": digest,
                "provenance": _provenance(relative),
                "sensitivity": _sensitivity(relative, prefix, retain_payload),
            }
        )
    identity_input = {
        "schema": MANIFEST_VERSION,
        "artifacts": artifacts,
        "missingExpected": sorted(
            EXPECTED_ARTIFACTS - {item["path"] for item in artifacts}
        ),
    }
    content_identity = hashlib.sha256(
        json.dumps(identity_input, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    findings = privacy_findings(
        root,
        artifacts,
        max_capture_bytes=max_capture_bytes,
        expected_networks=expected_networks,
    )
    try:
        result = json.loads((root / "result.json").read_text(encoding="utf-8"))
        run_state = result.get("state", "incomplete")
    except (OSError, json.JSONDecodeError, AttributeError):
        run_state = "incomplete"
    return {
        "apiVersion": MANIFEST_VERSION,
        "kind": "EvidenceManifest",
        "contentIdentity": f"sha256:{content_identity}",
        "runState": run_state,
        "artifacts": artifacts,
        "missingExpected": identity_input["missingExpected"],
        "privacy": {
            "status": "blocked" if findings else "pass",
            "findings": findings,
            "maxCaptureBytes": max_capture_bytes,
        },
        "creation": {
            "createdAt": created_at or _utc_now(),
            "contentIdentityIncludesCreation": False,
        },
    }


def _load_override(path: Path, root: Path, identity: str) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise EvidenceError("privacy override must be a regular file")
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        pass
    else:
        raise EvidenceError("privacy override must remain outside the evidence root")
    mode = stat.S_IMODE(resolved.stat().st_mode)
    if mode & 0o077:
        raise EvidenceError("privacy override must have mode 0600 or stricter")
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise EvidenceError(f"invalid privacy override JSON: {error}") from error
    if not isinstance(value, dict) or set(value) != {
        "apiVersion",
        "localOnly",
        "contentIdentity",
        "allowFindings",
        "justification",
    }:
        raise EvidenceError("privacy override has invalid fields")
    if value["apiVersion"] != OVERRIDE_VERSION or value["localOnly"] is not True:
        raise EvidenceError("privacy override must be a local-only v1 override")
    if value["contentIdentity"] != identity:
        raise EvidenceError("privacy override content identity does not match")
    if (
        not isinstance(value["allowFindings"], list)
        or not value["allowFindings"]
        or any(not isinstance(item, str) or not item for item in value["allowFindings"])
    ):
        raise EvidenceError("privacy override allowFindings must be a non-empty string list")
    if not isinstance(value["justification"], str) or not value["justification"].strip():
        raise EvidenceError("privacy override requires a justification")
    return value


def lint_evidence(
    root: Path,
    *,
    override: Path | None = None,
    created_at: str | None = None,
    max_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
    expected_networks: Iterable[str] = (),
) -> dict[str, Any]:
    manifest = build_evidence_manifest(
        root,
        created_at=created_at,
        max_capture_bytes=max_capture_bytes,
        expected_networks=expected_networks,
    )
    findings = manifest["privacy"]["findings"]
    allowed: set[str] = set()
    override_digest = None
    if override is not None:
        value = _load_override(override, root, manifest["contentIdentity"])
        allowed = set(value["allowFindings"])
        unknown = sorted(allowed - {item["code"] for item in findings})
        if unknown:
            raise EvidenceError(
                "privacy override names findings that are not present: "
                + ", ".join(unknown)
            )
        override_digest = hashlib.sha256(override.read_bytes()).hexdigest()
    unresolved = [item for item in findings if item["code"] not in allowed]
    return {
        "apiVersion": LINT_VERSION,
        "kind": "PrivacyLintResult",
        "contentIdentity": manifest["contentIdentity"],
        "passed": not unresolved,
        "findings": [
            {**item, "overridden": item["code"] in allowed} for item in findings
        ],
        "unresolvedFindingCount": len(unresolved),
        "override": (
            {"sha256": override_digest, "localOnly": True}
            if override_digest is not None
            else None
        ),
    }


def write_evidence_manifest(root: Path, **kwargs: Any) -> dict[str, Any]:
    manifest = build_evidence_manifest(root, **kwargs)
    path = root / MANIFEST_NAME
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{MANIFEST_NAME}.", suffix=".tmp", dir=root
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(manifest, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)
    return manifest
