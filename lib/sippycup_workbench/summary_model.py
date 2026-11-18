"""Owner-facing engagement report model (pure, offline, deterministic).

``build_report`` reads an engagement directory and the run roots it refers
to with bounded reads, and returns a JSON-serializable model. It never opens
a socket, never resolves a name, and never re-parses a capture: totals come
from the numbers the runs recorded (result documents, triage metadata, the
text report's packet line, step summaries, and the evidence manifest).

Every string copied from a run artifact passes through ``Sanitizer`` first.
Strings from the reviewed authorization records (scope file, target profiles,
campaign manifests) and operator metadata are not rewritten, only stripped of
control characters; the caller's privacy lint then fails the whole report
closed if any of them carries credential material, subscriber identifiers, or
an unapproved address.
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import itertools
import json
import os
import re
import stat
import tarfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

import yaml

from .journal import JournalError, verify as verify_journal
from .summary_privacy import AddressBook, Sanitizer, short_hash, strip_controls

REPORT_VERSION = "sippycup.dev/engagement-report/v1"
MAX_RUNS = 1000
MAX_ROOT_ENTRIES = 4096
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_YAML_BYTES = 1024 * 1024
MAX_EVENTS_BYTES = 16 * 1024 * 1024
MAX_EVENT_LINES = 100_000
MAX_TEXT_BYTES = 1024 * 1024
MAX_HASH_FILES = 512
MAX_HASH_BYTES = 2 * 1024 * 1024 * 1024
MAX_SOURCES = 64
MAX_PACKS = 64
MAX_LIST_ITEMS = 200
SAFE_RUN_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_STATUS_LINE = re.compile(r"^SIP/2\.0\s+([1-6][0-9]{2})(?:\s+(.*))?$")
_REASON_PHRASE = re.compile(r"^[A-Za-z][A-Za-z '()-]{0,60}$")
_IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\[\]/-]{0,127}$")
_PACKETS_LINE = re.compile(r"(?m)^Number of packets:\s+([0-9]{1,12})\s*$")
SEVERITIES = ("high", "medium", "low", "info")
CHECK_STATUSES = ("passed", "finding", "skipped", "error", "not-approved")
FINDINGS_VERSION = "sippycup.dev/findings/v1"
CALL_RESULT_VERSION = "sippycup.dev/call-result/v1"

# Reviewed table of derived observations. These are the only
# recommendations the report writes itself; everything else comes verbatim
# (sanitized) from a check run's remediation text.
OBSERVATIONS: dict[str, dict[str, str]] = {
    "one-way-media": {
        "severity": "low",
        "title": "Media flowed in one direction only",
        "summary": "Signaling succeeded and RTP was sent, but no RTP was received from the peer.",
        "recommendation": "Check that the media edge returns RTP to the negotiated address and port (symmetric RTP, NAT traversal, and firewall rules for the media port range).",
    },
    "possible-nat-one-way-media": {
        "severity": "info",
        "title": "One-way media consistent with NAT on the assessor side",
        "summary": "RTP was sent but none was received while the assessor was behind container NAT; this alone is not a target defect.",
        "recommendation": "Repeat the call from a path without NAT, or confirm that the service supports symmetric RTP for clients behind NAT.",
    },
    "preflight-server-error": {
        "severity": "low",
        "title": "OPTIONS preflight returned a server error",
        "summary": "The signaling edge answered the OPTIONS preflight with a 5xx or 6xx status.",
        "recommendation": "Confirm whether the edge is degraded or deliberately rejects OPTIONS; monitoring that depends on OPTIONS will report it unhealthy.",
    },
    "tls-not-verified": {
        "severity": "low",
        "title": "TLS server identity was not verified",
        "summary": "A TLS run could not verify the server certificate against the reviewed name and trust anchor; no SIP was sent on that connection.",
        "recommendation": "Serve a certificate chain that validates for the reviewed server name (or IP SAN) from the agreed trust anchor.",
    },
    "media-outside-scope": {
        "severity": "low",
        "title": "Media was negotiated to an address outside the approved scope",
        "summary": "The far end offered a media address that was not approved; the call was hung up before media was sent there.",
        "recommendation": "Confirm the media server addresses and add them to the written scope, or correct the advertised SDP connection address.",
    },
    "oracle-assertion-failed": {
        "severity": "info",
        "title": "A call-path assertion failed on an answered call",
        "summary": "The offline packet oracle reported failed assertions for an answered call.",
        "recommendation": "Review the failing assertions in the run's assertion output before drawing a conclusion; reproduce independently.",
    },
    "campaign-stopped": {
        "severity": "info",
        "title": "A campaign stopped before completing every step",
        "summary": "A campaign run ended early on a failed step, a safety ceiling, a deadline, or an operator stop.",
        "recommendation": "Review the stop reason; rerun the remaining steps only inside the approved window and ceilings.",
    },
    "capture-incomplete": {
        "severity": "low",
        "title": "Evidence capture did not complete",
        "summary": "Packet capture failed or stopped during a run, so the run's evidence is incomplete.",
        "recommendation": "Rerun the affected step after fixing capture placement; do not rely on the incomplete run's evidence.",
    },
}


class Unreadable(Exception):
    """A run artifact could not be read safely."""


@dataclass
class Options:
    audience: str = "owner"
    include_journal_notes: bool = False
    run_globs: tuple[str, ...] = ()
    since: datetime | None = None
    title: str | None = None
    generated_at: str | None = None
    run_roots: tuple[Path, ...] = ()
    profiles: tuple[Path, ...] = ()
    manifests: tuple[Path, ...] = ()
    forbidden: tuple[str, ...] = ()
    cli_version: str | None = None


@dataclass
class Context:
    addresses: AddressBook
    sanitizer: Sanitizer
    allow_call_ids: bool
    forbidden: tuple[str, ...]


# --------------------------------------------------------------------------
# Bounded readers


def _regular(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as error:
        raise Unreadable("missing") from error
    if stat.S_ISLNK(info.st_mode):
        raise Unreadable("symlink")
    if not stat.S_ISREG(info.st_mode):
        raise Unreadable("not-a-regular-file")
    return info


def _read_bytes(path: Path, limit: int) -> bytes:
    info = _regular(path)
    if info.st_size > limit:
        raise Unreadable("oversized")
    try:
        with path.open("rb") as source:
            data = source.read(limit + 1)
    except OSError as error:
        raise Unreadable("unreadable") from error
    if len(data) > limit:
        raise Unreadable("oversized")
    return data


def read_json(path: Path, limit: int = MAX_JSON_BYTES) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value

    data = _read_bytes(path, limit)
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise Unreadable("malformed") from error


def read_yaml(path: Path, limit: int = MAX_YAML_BYTES) -> Any:
    data = _read_bytes(path, limit)
    try:
        return yaml.safe_load(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError, RecursionError) as error:
        raise Unreadable("malformed") from error


def _optional_json(path: Path, problems: list[str], name: str) -> Any:
    if not path.exists() and not path.is_symlink():
        return None
    try:
        return read_json(path)
    except Unreadable as error:
        problems.append(f"{name}: {error}")
        return None


# --------------------------------------------------------------------------
# Small helpers


def parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else None
    if not isinstance(value, str) or not value or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _from_ns(value: Any) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value / 1e9, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _num(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value != value or value in (float("inf"), float("-inf")):
        return None
    return round(float(value), 3)


def _bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value[:MAX_LIST_ITEMS] if isinstance(value, list) else []


def _reviewed(value: Any, limit: int = 200) -> str | None:
    """Operator-reviewed text: strip controls, keep content, lint later."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return iso(value)
    text = strip_controls(str(value))
    return text[:limit] if text else None


def _is_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return True


def _canonical_ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip().strip("[]")))
    except ValueError:
        return None


def _split_host_port(value: Any) -> tuple[str | None, int | None]:
    if not isinstance(value, str):
        return None, None
    text = value.strip()
    match = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\]:([0-9]{1,5})", text)
    if match:
        return _canonical_ip(match.group(1)), int(match.group(2))
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        if port.isdigit():
            return _canonical_ip(host), int(port)
    return _canonical_ip(text), None


def _status_line(value: Any) -> tuple[int | None, str | None]:
    if not isinstance(value, str):
        return None, None
    match = _STATUS_LINE.match(strip_controls(value))
    if not match:
        return None, None
    reason = (match.group(2) or "").strip()
    return int(match.group(1)), reason if _REASON_PHRASE.fullmatch(reason) else None


def _ident(value: Any) -> str | None:
    if isinstance(value, str) and _IDENT.fullmatch(value):
        return value
    return None


def _digest(value: Any) -> str | None:
    if isinstance(value, str):
        candidate = value.removeprefix("sha256:")
        if _HEX64.fullmatch(candidate):
            return candidate
    return None


# --------------------------------------------------------------------------
# Authorization sources


@dataclass
class Source:
    kind: str
    ref: str
    approval_id: str | None = None
    approved_by: str | None = None
    status: str | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    networks: list[str] = field(default_factory=list)
    media_networks: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    transports: list[str] = field(default_factory=list)
    server_names: list[str] = field(default_factory=list)
    destinations: list[str] = field(default_factory=list)
    accounts: list[str] = field(default_factory=list)
    assessor: list[str] = field(default_factory=list)
    limits: dict[str, int] = field(default_factory=dict)
    media_ports: tuple[int, int] | None = None

    def covers(self, address: str | None, port: int | None, transport: str | None) -> bool:
        if address is None:
            return False
        book = AddressBook()
        for network in self.networks:
            book.add_network(network)
        if not book.approved(address):
            return False
        if self.ports and port is not None and port not in self.ports:
            return False
        if self.transports and transport is not None and transport not in self.transports:
            return False
        return True

    def covers_address(self, address: str | None) -> bool:
        if address is None:
            return False
        book = AddressBook()
        for network in self.networks + self.media_networks:
            book.add_network(network)
        return book.approved(address)

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "ref": self.ref,
            "approvalId": self.approval_id,
            "approvedBy": self.approved_by,
            "status": self.status,
            "validFrom": iso(self.valid_from),
            "validUntil": iso(self.valid_until),
            "networks": sorted(set(self.networks)),
            "mediaNetworks": sorted(set(self.media_networks)),
            "ports": sorted(set(self.ports)),
            "transports": sorted(set(self.transports)),
            "serverNames": sorted(set(self.server_names)),
            "destinations": sorted(set(self.destinations)),
            "accounts": sorted(set(self.accounts)),
            "limits": dict(sorted(self.limits.items())),
            "mediaPorts": (
                {"start": self.media_ports[0], "end": self.media_ports[1]}
                if self.media_ports
                else None
            ),
        }


def _str_list(value: Any) -> list[str]:
    return [str(item) for item in _list(value) if isinstance(item, (str, int)) and str(item).strip()]


def _int_list(value: Any) -> list[int]:
    return [item for item in _list(value) if _int(item) is not None]


def _scope_source(document: dict[str, Any], ref: str) -> Source:
    auth = _dict(document.get("authorization"))
    signaling = _dict(document.get("signaling"))
    media = _dict(document.get("media"))
    source = Source(
        kind="scope",
        ref=ref,
        approval_id=_reviewed(auth.get("approval_id")),
        approved_by=_reviewed(auth.get("approved_by")),
        status=_reviewed(auth.get("status"), 32),
        valid_from=parse_time(auth.get("valid_from")),
        valid_until=parse_time(auth.get("valid_until")),
        networks=_str_list(signaling.get("networks")),
        media_networks=_str_list(media.get("networks")),
        ports=_int_list(signaling.get("ports")),
        transports=[t for t in _str_list(signaling.get("transports")) if t in {"udp", "tcp", "tls"}],
    )
    for target in _list(document.get("targets")):
        target = _dict(target)
        if _is_ip(target.get("address")):
            source.networks.append(str(target["address"]))
        if isinstance(target.get("tls_server_name"), str):
            source.server_names.append(target["tls_server_name"])
    port_range = _dict(media.get("port_range"))
    if _int(port_range.get("start")) and _int(port_range.get("end")):
        source.media_ports = (port_range["start"], port_range["end"])
    account = _dict(document.get("account"))
    if isinstance(account.get("username"), str):
        source.accounts.append(account["username"])
    for destination in _list(document.get("destinations")):
        destination = _dict(destination)
        for key in ("user", "name"):
            if isinstance(destination.get(key), (str, int)):
                source.destinations.append(str(destination[key]))
    source.assessor = _str_list(_dict(document.get("client")).get("source_addresses"))
    for key, value in _dict(document.get("limits")).items():
        if _int(value) is not None:
            source.limits[str(key)] = value
    return source


def _profile_source(document: dict[str, Any], ref: str) -> Source:
    target = _dict(document.get("target"))
    auth = _dict(document.get("authorization"))
    source = Source(
        kind="target-profile",
        ref=ref,
        approval_id=_reviewed(auth.get("approval_id")),
        approved_by=_reviewed(auth.get("approved_by")),
        status=_reviewed(auth.get("status"), 32),
        valid_from=parse_time(auth.get("valid_from")),
        valid_until=parse_time(auth.get("valid_until")),
        networks=[a for a in _str_list(target.get("approved_addresses")) if _is_ip(a)],
        ports=[target["port"]] if _int(target.get("port")) else [],
        transports=[target["transport"]] if target.get("transport") in {"udp", "tcp", "tls"} else [],
    )
    if isinstance(target.get("tls_server_name"), str):
        source.server_names.append(target["tls_server_name"])
    for key, value in _dict(document.get("limits")).items():
        if _int(value) is not None:
            source.limits[str(key)] = value
    return source


def _manifest_source(document: dict[str, Any], ref: str) -> Source:
    auth = _dict(document.get("authorization"))
    source = Source(
        kind="campaign-manifest",
        ref=ref,
        networks=_str_list(auth.get("networks")),
        ports=_int_list(auth.get("signalingPorts")),
        transports=[t for t in _str_list(auth.get("transports")) if t in {"udp", "tcp", "tls"}],
    )
    media_ports = _dict(auth.get("mediaPorts"))
    if _int(media_ports.get("start")) and _int(media_ports.get("end")):
        source.media_ports = (media_ports["start"], media_ports["end"])
    for key, value in _dict(auth.get("ceilings")).items():
        if _int(value) is not None:
            source.limits[str(key)] = value
    for target in _list(document.get("targets")):
        target = _dict(target)
        signaling = _dict(target.get("signaling"))
        if isinstance(signaling.get("tlsServerName"), str):
            source.server_names.append(signaling["tlsServerName"])
        account = _dict(target.get("account"))
        if isinstance(account.get("username"), str):
            source.accounts.append(account["username"])
    for case in _list(document.get("cases")):
        dial = _dict(_dict(case).get("dial"))
        if isinstance(dial.get("user"), (str, int)):
            source.destinations.append(str(dial["user"]))
    return source


# --------------------------------------------------------------------------
# Run discovery


@dataclass
class RawRun:
    name: str
    ref: str
    path: Path
    kind: str
    docs: dict[str, Any] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)


def _relative(root: Path, path: Path, externals: dict[Path, str]) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        pass
    for base, label in externals.items():
        try:
            return f"{label}/{path.relative_to(base).as_posix()}"
        except ValueError:
            continue
    return f"external/{path.name}"


def _detect_kind(path: Path) -> str | None:
    names = {"findings.json", "result.json", "plan.json", "events.jsonl", "timestamps.json"}
    present = set()
    try:
        for child in itertools.islice(path.iterdir(), MAX_ROOT_ENTRIES):
            if child.name in names:
                present.add(child.name)
    except OSError:
        return None
    if "findings.json" in present:
        return "check"
    if "events.jsonl" in present or ("plan.json" in present and "result.json" in present and not (path / "softphone.json").exists() and not (path / "profile.json").exists()):
        return "campaign"
    if "result.json" in present:
        return "call"
    if present:
        return "unknown"
    return None


def _journal_run_roots(root: Path, entries: Iterable[dict[str, Any]]) -> set[Path]:
    roots: set[Path] = set()
    for entry in entries:
        for reference in entry.get("evidence", []):
            parts = PurePosixPath(reference).parts
            if len(parts) >= 3:
                roots.add(root.joinpath(*parts[:-2]))
    return roots


def discover_runs(
    root: Path,
    *,
    extra_roots: Iterable[Path],
    profile_paths: Iterable[Path],
    journal_entries: Iterable[dict[str, Any]],
) -> tuple[list[RawRun], list[str], list[str]]:
    """Return runs, run-root descriptions (relative), and warnings."""
    warnings: list[str] = []
    candidates: list[Path] = [root / "runs", root / "calls", root / "checks"]
    candidates.extend(sorted(path.parent / "calls" for path in profile_paths))
    candidates.extend(sorted(_journal_run_roots(root, journal_entries)))
    candidates.extend(extra_roots)
    resolved_roots: list[Path] = []
    for candidate in candidates:
        try:
            if candidate.is_symlink() or not candidate.is_dir():
                continue
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved not in resolved_roots:
            resolved_roots.append(resolved)
    externals: dict[Path, str] = {}
    for index, base in enumerate(sorted(r for r in resolved_roots if not r.is_relative_to(root)), 1):
        externals[base] = f"external-root-{index}"
    runs: list[RawRun] = []
    seen: set[Path] = set()
    descriptions: list[str] = []
    for base in resolved_roots:
        descriptions.append(_relative(root, base, externals) or ".")
        try:
            children = list(itertools.islice(base.iterdir(), MAX_ROOT_ENTRIES + 1))
        except OSError:
            warnings.append(f"run root {_relative(root, base, externals)} could not be listed")
            continue
        if len(children) > MAX_ROOT_ENTRIES:
            warnings.append(
                f"run root {_relative(root, base, externals)} exceeds the {MAX_ROOT_ENTRIES}-entry limit"
            )
            children = children[:MAX_ROOT_ENTRIES]
        for child in sorted(children, key=lambda item: item.name):
            if child.is_symlink() or not child.is_dir():
                continue
            if SAFE_RUN_NAME.fullmatch(child.name) is None:
                warnings.append("ignored a run directory with an unsafe name")
                continue
            if child in seen:
                continue
            kind = _detect_kind(child)
            if kind is None:
                continue
            seen.add(child)
            runs.append(
                RawRun(
                    name=child.name,
                    ref=_relative(root, child, externals),
                    path=child,
                    kind=kind,
                )
            )
            if len(runs) >= MAX_RUNS:
                warnings.append(f"run discovery stopped at the {MAX_RUNS}-run limit")
                return runs, sorted(set(descriptions)), warnings
    return runs, sorted(set(descriptions)), warnings


def _load_events(path: Path, problems: list[str]) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        data = _read_bytes(path, MAX_EVENTS_BYTES)
    except Unreadable as error:
        problems.append(f"events.jsonl: {error}")
        return []
    events: list[dict[str, Any]] = []
    bad = 0
    for line in data.decode("utf-8", "replace").splitlines()[:MAX_EVENT_LINES]:
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except (ValueError, RecursionError):
            bad += 1
            continue
        if isinstance(value, dict):
            events.append(value)
        else:
            bad += 1
    if bad:
        problems.append(f"events.jsonl: {bad} malformed lines skipped")
    return events


def _load_raw(run: RawRun) -> None:
    names = {
        "call": ("result.json", "softphone.json", "triage.json", "assert.json", "timestamps.json", "versions.json", "preflight.json", "evidence-manifest.json"),
        "campaign": ("result.json", "plan.json", "preflight.json", "timestamps.json", "versions.json", "evidence-manifest.json"),
        "check": ("findings.json", "timestamps.json", "versions.json", "evidence-manifest.json"),
        "unknown": ("result.json", "timestamps.json", "evidence-manifest.json"),
    }[run.kind]
    for name in names:
        value = _optional_json(run.path / name, run.problems, name)
        if value is not None:
            run.docs[name] = value
    if run.kind == "campaign":
        run.docs["events"] = _load_events(run.path / "events.jsonl", run.problems)
        report = run.path / "report.txt"
        if report.exists():
            try:
                text = _read_bytes(report, MAX_TEXT_BYTES).decode("utf-8", "replace")
                run.docs["report.txt"] = text
            except Unreadable as error:
                run.problems.append(f"report.txt: {error}")


# --------------------------------------------------------------------------
# Evidence inventory


def _stream_hash(path: Path) -> tuple[int, str] | None:
    try:
        info = _regular(path)
    except Unreadable:
        return None
    if info.st_size > MAX_HASH_BYTES:
        return None
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
                if size > MAX_HASH_BYTES:
                    return None
    except OSError:
        return None
    return size, digest.hexdigest()


def _sensitivity_guess(name: str) -> str:
    suffix = PurePosixPath(name).suffix.lower()
    base = PurePosixPath(name).name
    if suffix in {".wav", ".pcap", ".pcapng"}:
        return "restricted" if suffix == ".wav" else "confidential"
    if base in {"plan.json", "commands.json", "events.jsonl", "versions.json", "result.json", "timestamps.json", "findings.json"}:
        return "internal"
    return "confidential"


def _evidence(run: RawRun, ctx: Context, path_prefix: str) -> dict[str, Any]:
    manifest = run.docs.get("evidence-manifest.json")
    artifacts: list[dict[str, Any]] = []
    stale: list[str] = []
    source = "none"
    identity = None
    privacy = None
    privacy_codes: list[str] = []
    if isinstance(manifest, dict) and isinstance(manifest.get("artifacts"), list):
        source = "evidence-manifest"
        identity = _digest(manifest.get("contentIdentity"))
        privacy_doc = _dict(manifest.get("privacy"))
        privacy = privacy_doc.get("status") if privacy_doc.get("status") in {"pass", "blocked"} else None
        privacy_codes = sorted(
            {
                item["code"]
                for item in _list(privacy_doc.get("findings"))
                if isinstance(item, dict) and _ident(item.get("code"))
            }
        )
        for index, item in enumerate(manifest["artifacts"][:MAX_HASH_FILES]):
            item = _dict(item)
            name = item.get("path")
            if not isinstance(name, str) or not _safe_relative(name):
                continue
            size = _int(item.get("size"))
            entry = {
                "path": ctx.sanitizer.identifier(name, f"{path_prefix}.artifacts[{index}].path", limit=200),
                "size": size,
                "sha256": _digest(item.get("sha256")),
                "sensitivity": item.get("sensitivity") if item.get("sensitivity") in {"public", "internal", "confidential", "restricted"} else "unknown",
            }
            try:
                current = (run.path / name).lstat().st_size
            except OSError:
                current = None
            if current != size:
                stale.append(entry["path"])
            artifacts.append(entry)
    else:
        source = "computed-by-summary"
        files: list[Path] = []
        try:
            for path in sorted(run.path.rglob("*")):
                if len(files) >= MAX_HASH_FILES:
                    break
                if path.is_symlink() or not path.is_file():
                    continue
                files.append(path)
        except OSError:
            pass
        for index, path in enumerate(files):
            relative = path.relative_to(run.path).as_posix()
            hashed = _stream_hash(path)
            artifacts.append(
                {
                    "path": ctx.sanitizer.identifier(relative, f"{path_prefix}.artifacts[{index}].path", limit=200),
                    "size": hashed[0] if hashed else None,
                    "sha256": hashed[1] if hashed else None,
                    "sensitivity": _sensitivity_guess(relative),
                }
            )
        identity_input = [
            {"path": item["path"], "size": item["size"], "sha256": item["sha256"]}
            for item in artifacts
        ]
        identity = hashlib.sha256(
            json.dumps(identity_input, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    return {
        "source": source,
        "contentIdentity": f"sha256:{identity}" if identity else None,
        "privacyStatus": privacy,
        "privacyFindingCodes": privacy_codes,
        "artifacts": artifacts,
        "artifactCount": len(artifacts),
        "totalBytes": sum(item["size"] or 0 for item in artifacts),
        "changedSinceManifest": sorted(set(stale)),
    }


def _safe_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return not (
        path.is_absolute()
        or "\\" in value
        or any(part in {"", ".", ".."} for part in path.parts)
    )


# --------------------------------------------------------------------------
# Per-kind run models


def _base_run(run: RawRun) -> dict[str, Any]:
    return {
        "id": run.name,
        "ref": run.ref,
        "kind": run.kind,
        "readable": "ok",
        "problems": [],
        "started": None,
        "finished": None,
        "durationSeconds": None,
        "target": None,
        "verdict": None,
        "state": None,
        "reasons": [],
        "sent": {},
        "details": {},
        "integrity": [],
    }


class _Labeler:
    """Show reviewed identifiers; pseudonymize everything else."""

    def __init__(self, reviewed: set[str], prefix: str) -> None:
        self.reviewed = reviewed
        self.prefix = prefix
        self.labels: dict[str, str] = {}

    def __call__(self, value: Any) -> str | None:
        if value is None:
            return None
        text = str(value)
        if text in self.reviewed and _IDENT.fullmatch(text):
            return text
        if text not in self.labels:
            self.labels[text] = f"{self.prefix}-{len(self.labels) + 1}"
        return self.labels[text]


@dataclass
class _Scope:
    sources: list[Source]
    destinations: _Labeler
    accounts: _Labeler
    server_names: _Labeler
    addresses: AddressBook


def _target(scope: _Scope, address: Any, port: Any, transport: Any, server_name: Any = None) -> dict[str, Any]:
    canonical = _canonical_ip(address) if address is not None else None
    return {
        "address": scope.addresses.label(canonical) if canonical else ("unrecorded" if address is None else "unrecognized-host"),
        "approvedAddress": bool(canonical and scope.addresses.approved(canonical)),
        "port": _int(port),
        "transport": transport if transport in {"udp", "tcp", "tls"} else None,
        "serverName": scope.server_names(server_name) if isinstance(server_name, str) else None,
        "_raw": canonical,
    }


def _destination_user(uri: Any) -> str | None:
    if not isinstance(uri, str):
        return None
    match = re.match(r"(?i)^sips?:([^@;>\s]+)@", uri)
    return match.group(1) if match else None


def _call_run(run: RawRun, model: dict[str, Any], scope: _Scope, ctx: Context, prefix: str) -> None:
    result = run.docs.get("result.json")
    san = ctx.sanitizer
    if not isinstance(result, dict) or result.get("apiVersion") != CALL_RESULT_VERSION:
        model["readable"] = "unreadable"
        model["problems"].append("result.json: not a call result")
        return
    timestamps = _dict(result.get("timestamps")) or _dict(run.docs.get("timestamps.json"))
    started = parse_time(timestamps.get("started"))
    finished = parse_time(timestamps.get("finished"))
    model["started"], model["finished"] = iso(started), iso(finished)
    target = _dict(result.get("target"))
    tls = _dict(result.get("tls"))
    model["target"] = _target(scope, target.get("host"), target.get("port"), target.get("transport"), tls.get("serverName") if tls else None)
    model["verdict"] = _ident(result.get("verdict"))
    model["state"] = _ident(result.get("state"))
    model["profile"] = san.identifier(result.get("profile"), f"{prefix}.profile", limit=80)
    model["reasons"] = [
        san.text(note, f"{prefix}.reasons[{index}]", limit=400)
        for index, note in enumerate(_list(result.get("notes"))[:20])
    ]
    softphone = _dict(result.get("softphone"))
    preflight = result.get("preflight")
    pre_code, pre_reason = _status_line(_dict(preflight).get("detail")) if isinstance(preflight, dict) else (None, None)
    oracle = _dict(result.get("oracle"))
    oracle_summary = _dict(oracle.get("summary"))
    recording = _dict(result.get("recording"))
    triage_doc = _dict(run.docs.get("triage.json"))
    triage_meta = _dict(triage_doc.get("metadata"))
    triage_result = _dict(result.get("triage"))
    media_peer, media_port = _split_host_port(softphone.get("media_peer"))
    setup = None
    timeline = _list(_dict(run.docs.get("softphone.json")).get("timeline"))
    marks = {item.get("state"): _num(item.get("at")) for item in timeline if isinstance(item, dict)}
    if marks.get("CONFIRMED") is not None and marks.get("DIALED") is not None:
        setup = round(marks["CONFIRMED"] - marks["DIALED"], 3)
    dialogs = []
    assertion_doc = _dict(run.docs.get("assert.json"))
    for index, dialog in enumerate(_list(assertion_doc.get("dialogs"))[:20]):
        dialog = _dict(dialog)
        call_id = dialog.get("call_id")
        if not isinstance(call_id, str):
            continue
        dialogs.append(
            {
                "callIdHash": short_hash(call_id),
                "callId": (
                    san.identifier(call_id, f"{prefix}.details.dialogs[{index}].callId", limit=128)
                    if ctx.allow_call_ids
                    else None
                ),
                "state": _ident(dialog.get("state")),
            }
        )
    tls_media = _dict(tls.get("media"))
    rtp_tx = _int(softphone.get("rtp_tx_packets"))
    rtp_rx = _int(softphone.get("rtp_rx_packets"))
    model["details"] = {
        "destination": scope.destinations(_destination_user(result.get("destinationUri"))),
        "networkMode": _ident(result.get("networkMode")),
        "preflight": None
        if not isinstance(preflight, dict)
        else {"ok": _bool(preflight.get("ok")), "statusCode": pre_code, "reason": pre_reason},
        "registration": {
            "attempted": _bool(softphone.get("registration_attempted")),
            "registered": _bool(softphone.get("registered")),
            "statusCode": _int(softphone.get("registration_status")),
        },
        "call": {
            "dialed": _bool(softphone.get("dialed")),
            "answered": _bool(softphone.get("answered")),
            "finalStatus": _int(softphone.get("final_status")),
            "disconnectStatus": _int(softphone.get("disconnect_status")),
            "disconnectReason": san.text(softphone.get("disconnect_reason"), f"{prefix}.details.call.disconnectReason", limit=80),
            "connectedSeconds": _num(softphone.get("connected_seconds")),
            "setupSeconds": setup,
            "hangup": _ident(softphone.get("hangup")),
            "error": san.identifier(softphone.get("error"), f"{prefix}.details.call.error", limit=80),
        },
        "media": {
            "codec": san.identifier(softphone.get("codec"), f"{prefix}.details.media.codec", limit=32),
            "direction": _ident(softphone.get("media_direction")),
            "peer": scope.addresses.label(media_peer) if media_peer else None,
            "peerApproved": bool(media_peer and scope.addresses.approved(media_peer)),
            "peerPort": media_port,
            "toPeerPackets": _int(tls_media.get("outbound")) if tls_media else rtp_tx,
            "fromPeerPackets": _int(tls_media.get("inbound")) if tls_media else rtp_rx,
            "countSource": "capture (TLS media decode)" if tls_media else "PJSUA call statistics",
        },
        "tls": None
        if not tls
        else {
            "verified": _bool(tls.get("verified")),
            "serverName": scope.server_names(tls.get("serverName")) if isinstance(tls.get("serverName"), str) and not _is_ip(tls.get("serverName")) else (scope.addresses.label(_canonical_ip(tls.get("serverName"))) if _canonical_ip(tls.get("serverName")) else None),
            "trust": tls.get("trust") if tls.get("trust") in {"system", "file"} else None,
            "caSha256": _digest(tls.get("caSha256")),
            "preflightVerified": _bool(tls.get("preflightVerified")),
            "softphoneVerified": _bool(tls.get("softphoneVerified")),
        },
        "oracle": {
            "verdict": oracle.get("verdict") if oracle.get("verdict") in {"pass", "fail", "unknown"} else None,
            "pass": _int(oracle_summary.get("pass")),
            "fail": _int(oracle_summary.get("fail")),
            "unknown": _int(oracle_summary.get("unknown")),
            "failed": sorted(
                {
                    san.identifier(item, f"{prefix}.details.oracle.failed", limit=96)
                    for item in _list(oracle.get("failed"))
                    if isinstance(item, str)
                }
            ),
            "decidesVerdict": not bool(tls),
        },
        "recording": None
        if not recording
        else {
            "present": _bool(recording.get("present")),
            "seconds": _num(recording.get("seconds")),
            "silent": _bool(recording.get("silent")),
            "peakDbfs": _num(recording.get("peak_dbfs")),
        },
        "dialogs": dialogs,
        "triagePackets": _int(triage_result.get("packets")),
    }
    duration = _dict(result.get("durationSeconds"))
    model["limitsApplied"] = {"durationLimit": _int(duration.get("limit")), "durationEffective": _int(duration.get("effective"))}
    model["sent"] = {
        "optionsRequests": 1 if isinstance(preflight, dict) else 0,
        "registerAttempts": 1 if softphone.get("registration_attempted") is True else 0,
        "calls": 1 if softphone.get("dialed") is True else 0,
        "rtpPacketsSent": rtp_tx if rtp_tx is not None or softphone.get("answered") is not False else 0,
        "capturePackets": _int(triage_meta.get("packets")) if triage_meta else _int(triage_result.get("packets")),
        "captureBytes": _int(triage_meta.get("bytes")),
        "checkRequests": None,
        "summary": san.text(result.get("networkActivity"), f"{prefix}.sent.summary", limit=300),
    }
    model["_mediaPeerRaw"] = media_peer


def _campaign_run(run: RawRun, model: dict[str, Any], scope: _Scope, ctx: Context, prefix: str) -> None:
    san = ctx.sanitizer
    plan = _dict(run.docs.get("plan.json"))
    result = _dict(run.docs.get("result.json"))
    events = run.docs.get("events", [])
    timestamps = _dict(run.docs.get("timestamps.json"))
    started = parse_time(timestamps.get("started"))
    finished = parse_time(timestamps.get("finished"))
    times = [t for t in (_from_ns(e.get("timeUnixNs")) for e in events) if t is not None]
    if started is None and times:
        started = min(times)
    if finished is None and times:
        finished = max(times)
    model["started"], model["finished"] = iso(started), iso(finished)
    if not plan:
        model["readable"] = "partial" if result or events else "unreadable"
        model["problems"].append("plan.json: missing or unreadable")
    metadata = _dict(plan.get("metadata"))
    model["campaign"] = san.identifier(metadata.get("name"), f"{prefix}.campaign", limit=80)
    model["state"] = _ident(result.get("state")) if result else None
    if not result:
        model["problems"].append("result.json: missing or unreadable")
        if model["readable"] == "ok":
            model["readable"] = "partial"
    model["verdict"] = model["state"]
    authorization = _dict(plan.get("authorization"))
    hard = {key: value for key, value in _dict(authorization.get("hardMaxima")).items() if _int(value) is not None}
    steps = [_dict(step) for step in _list(plan.get("steps"))]
    step_state: dict[int, dict[str, Any]] = {}
    stop_reason = None
    final_event = None
    truncated: set[int] = set()
    for event in events:
        name = event.get("event")
        number = _int(event.get("step"))
        if name in {"campaign.failed", "campaign.timed_out", "campaign.cancelled", "campaign.succeeded"}:
            final_event = name
            if isinstance(event.get("reason"), str):
                stop_reason = san.identifier(event["reason"], f"{prefix}.stopReason", limit=64)
        if name == "campaign.stop_requested" and isinstance(event.get("reason"), str) and stop_reason is None:
            stop_reason = san.identifier(event["reason"], f"{prefix}.stopReason", limit=64)
        if number is None:
            continue
        state = step_state.setdefault(number, {"outcome": "not-run", "output": None, "exitCode": None})
        if name == "step.started":
            state["outcome"] = "started"
        elif name == "step.succeeded":
            state["outcome"] = "succeeded"
        elif name == "step.failed":
            state["outcome"] = "failed"
            state["exitCode"] = _int(event.get("exitCode"))
        elif name == "step.timed_out":
            state["outcome"] = "timed-out"
        elif name == "step.cancelled":
            state["outcome"] = "cancelled"
        elif name == "step.start_failed":
            state["outcome"] = "start-failed"
        elif name == "step.output_truncated":
            truncated.add(number)
        elif name == "step.output" and event.get("stream") == "stdout" and isinstance(event.get("text"), str):
            for line in event["text"].splitlines()[:4]:
                try:
                    value = json.loads(line)
                except (ValueError, RecursionError):
                    continue
                if isinstance(value, dict):
                    state["output"] = value
                    break
    cases = []
    totals = {"options": 0, "register": 0, "calls": 0, "rtp": 0, "rtpKnown": not any(step.get("type") == "call" for step in steps), "optionsLowerBound": False}
    not_exercised: list[dict[str, Any]] = []
    for index, step in enumerate(steps):
        number = _int(step.get("index")) or index + 1
        state = step_state.get(number, {"outcome": "not-run", "output": None, "exitCode": None})
        output = _dict(state.get("output"))
        destination = _dict(step.get("destination"))
        addresses = _list(destination.get("addresses"))
        tls = _dict(step.get("tls"))
        case_prefix = f"{prefix}.details.cases[{index}]"
        kind = step.get("type") if step.get("type") in {"options", "call"} else "other"
        status = _int(output.get("status_code")) if "status_code" in output else _int(output.get("finalStatus"))
        rtp = _dict(output.get("rtp"))
        auth = _dict(output.get("authentication"))
        register = _dict(auth.get("REGISTER"))
        tls_out = _dict(output.get("tls"))
        tls_verified = _bool(output.get("tls_verified")) if "tls_verified" in output else _bool(tls_out.get("verified"))
        case = {
            "step": number,
            "case": san.identifier(step.get("case"), f"{case_prefix}.case", limit=64),
            "type": kind,
            "target": _target(scope, addresses[0] if addresses else None, destination.get("port"), destination.get("transport"), tls.get("serverName")),
            "destination": scope.destinations(_dict(step.get("dial")).get("user")) if _dict(step.get("dial")).get("user") is not None else None,
            "outcome": state["outcome"],
            "statusCode": status,
            "expectedStatus": _int(_dict(step.get("expectations")).get("finalStatus")),
            "met": _bool(output.get("met")),
            "registered": _bool(output.get("registered")),
            "rtpToPeer": _int(rtp.get("txPackets")),
            "rtpFromPeer": _int(rtp.get("rxPackets")),
            "setupSeconds": _num(output.get("setupSeconds")),
            "codec": san.identifier(output.get("codec"), f"{case_prefix}.codec", limit=32) if output.get("codec") else None,
            "tlsVerified": tls_verified,
            "reasons": sorted(
                {
                    san.identifier(item, f"{case_prefix}.reasons", limit=64)
                    for item in _list(output.get("reasons"))
                    if isinstance(item, str)
                }
            ),
            "summaryRecorded": bool(output),
            "summaryTruncated": number in truncated,
        }
        cases.append(case)
        if state["outcome"] != "not-run":
            if kind == "options":
                # A step whose summary was withheld (runners stay silent while
                # secrets are in use) still sent at least its one request.
                totals["options"] += _int(output.get("requests_sent")) or 1
                if not output:
                    totals["optionsLowerBound"] = True
            if kind == "call":
                totals["calls"] += 1
                totals["register"] += _int(register.get("attempts")) or 0
                if case["rtpToPeer"] is not None:
                    totals["rtp"] += case["rtpToPeer"]
                    totals["rtpKnown"] = True
        factors = _dict(output.get("factors"))
        for item in _list(factors.get("notExercised"))[:40]:
            if isinstance(item, dict):
                not_exercised.append(
                    {
                        "step": number,
                        "factor": san.identifier(item.get("factor") or item.get("name"), f"{case_prefix}.notExercised.factor", limit=48),
                        "reason": san.text(item.get("reason"), f"{case_prefix}.notExercised.reason", limit=160),
                    }
                )
            elif isinstance(item, str):
                not_exercised.append({"step": number, "factor": san.identifier(item, f"{case_prefix}.notExercised", limit=48), "reason": None})
    preflight_entries = []
    for index, entry in enumerate(_list(run.docs.get("preflight.json"))[:64]):
        entry = _dict(entry)
        code, reason = _status_line(entry.get("detail"))
        preflight_entries.append(
            {
                "target": _target(scope, entry.get("address"), entry.get("port"), entry.get("transport"), _dict(entry.get("tls")).get("serverName")),
                "ok": _bool(entry.get("ok")),
                "statusCode": _int(entry.get("statusCode")) or code,
                "reason": reason,
                "warning": san.identifier(entry.get("warning"), f"{prefix}.details.preflight[{index}].warning", limit=64) if entry.get("warning") else None,
                "tlsVerified": _bool(_dict(entry.get("tls")).get("verified")) if entry.get("tls") else None,
            }
        )
    report_text = run.docs.get("report.txt") or ""
    packets = _PACKETS_LINE.search(report_text)
    capture_bytes = _capture_size(run)
    completed = _int(result.get("completedSteps"))
    model["details"] = {
        "cases": cases,
        "preflight": preflight_entries,
        "stopReason": stop_reason if model["state"] != "succeeded" else None,
        "finalEvent": final_event,
        "completedSteps": completed,
        "plannedSteps": len(steps),
        "plannedTotals": {k: v for k, v in _dict(plan.get("plannedTotals")).items() if _int(v) is not None},
        "hardMaxima": hard,
        "notExercised": not_exercised,
    }
    if model["state"] not in (None, "succeeded"):
        model["reasons"].append(
            san.text(
                f"campaign ended {model['state']}" + (f" ({stop_reason})" if stop_reason else ""),
                f"{prefix}.reasons",
            )
        )
    # Campaign-level primary target: first resolved destination.
    resolved = [_dict(item) for item in _list(plan.get("resolvedDestinations"))]
    first = resolved[0] if resolved else {}
    model["target"] = _target(scope, first.get("address"), first.get("port"), first.get("transport")) if first else None
    model["targets"] = [
        _target(scope, item.get("address"), item.get("port"), item.get("transport")) for item in resolved[:32]
    ]
    model["sent"] = {
        "optionsRequests": totals["options"] + len(preflight_entries),
        "optionsLowerBound": totals["optionsLowerBound"],
        "registerAttempts": totals["register"],
        "calls": totals["calls"],
        "rtpPacketsSent": totals["rtp"] if totals["rtpKnown"] else None,
        "capturePackets": int(packets.group(1)) if packets else None,
        "captureBytes": capture_bytes,
        "checkRequests": None,
        "summary": None,
    }
    model["limitsApplied"] = hard


def _capture_size(run: RawRun) -> int | None:
    """Capture size from the evidence manifest, else from the file itself."""
    manifest = _dict(run.docs.get("evidence-manifest.json"))
    for item in _list(manifest.get("artifacts")):
        if isinstance(item, dict) and item.get("path") == "capture.pcap":
            return _int(item.get("size"))
    try:
        return _regular(run.path / "capture.pcap").st_size
    except Unreadable:
        return None


def _check_target(scope: _Scope, value: Any) -> dict[str, Any] | None:
    target = _dict(value)
    if not target:
        return None
    address = target.get("address") or target.get("host")
    if address is None and _list(target.get("addresses")):
        address = target["addresses"][0]
    name = target.get("serverName") or target.get("tlsServerName") or target.get("name")
    return _target(scope, address, target.get("port"), target.get("transport"), name if isinstance(name, str) and not _is_ip(name) else None)


def _check_run(run: RawRun, model: dict[str, Any], scope: _Scope, ctx: Context, prefix: str) -> list[dict[str, Any]]:
    san = ctx.sanitizer
    findings_doc = run.docs.get("findings.json")
    if not isinstance(findings_doc, dict) or findings_doc.get("apiVersion") != FINDINGS_VERSION:
        model["readable"] = "unreadable"
        model["problems"].append("findings.json: not a findings/v1 document")
        return []
    generated = parse_time(findings_doc.get("generatedAt"))
    timestamps = _dict(run.docs.get("timestamps.json"))
    started = parse_time(timestamps.get("started")) or generated
    finished = parse_time(timestamps.get("finished")) or generated
    model["started"], model["finished"] = iso(started), iso(finished)
    model["target"] = _check_target(scope, findings_doc.get("target"))
    checks = []
    requests = 0
    known = False
    for index, check in enumerate(_list(findings_doc.get("checks"))):
        check = _dict(check)
        status = check.get("status") if check.get("status") in CHECK_STATUSES else "unknown"
        sent = _int(check.get("requestsSent"))
        if sent is not None:
            requests += sent
            known = True
        checks.append(
            {
                "id": san.identifier(check.get("id"), f"{prefix}.details.checks[{index}].id", limit=80),
                "status": status,
                "requestsSent": sent,
                "summary": san.text(check.get("summary"), f"{prefix}.details.checks[{index}].summary", limit=300),
            }
        )
    checks.sort(key=lambda item: (item["id"] or "", item["status"]))
    counts = {status: sum(1 for c in checks if c["status"] == status) for status in CHECK_STATUSES}
    model["details"] = {"checks": checks, "statusCounts": counts}
    model["verdict"] = "findings" if counts["finding"] else ("errors" if counts["error"] else "no-findings")
    model["state"] = "completed"
    model["sent"] = {
        "optionsRequests": None,
        "registerAttempts": None,
        "calls": None,
        "rtpPacketsSent": None,
        "capturePackets": None,
        "captureBytes": None,
        "checkRequests": requests if known else None,
        "summary": None,
    }
    model["limitsApplied"] = {}
    findings = []
    for index, item in enumerate(_list(findings_doc.get("findings"))):
        item = _dict(item)
        fp = f"{prefix}.findings[{index}]"
        severity = item.get("severity") if item.get("severity") in SEVERITIES else "info"
        evidence = []
        for e_index, entry in enumerate(_list(item.get("evidence"))[:20]):
            entry = _dict(entry)
            artifact = entry.get("artifact")
            evidence.append(
                {
                    "kind": san.identifier(entry.get("kind"), f"{fp}.evidence[{e_index}].kind", limit=48),
                    "detail": san.text(entry.get("detail"), f"{fp}.evidence[{e_index}].detail", limit=300),
                    "artifact": (
                        f"{run.ref}/{san.identifier(artifact, f'{fp}.evidence[{e_index}].artifact', limit=160)}"
                        if isinstance(artifact, str) and _safe_relative(artifact)
                        else None
                    ),
                }
            )
        findings.append(
            {
                "id": san.identifier(item.get("id"), f"{fp}.id", limit=80),
                "checkId": san.identifier(item.get("checkId"), f"{fp}.checkId", limit=80),
                "title": san.text(item.get("title"), f"{fp}.title", limit=160) or "Untitled finding",
                "severity": severity,
                "confidence": san.identifier(item.get("confidence"), f"{fp}.confidence", limit=32),
                "summary": san.text(item.get("summary"), f"{fp}.summary", limit=600),
                "evidence": evidence,
                "remediation": san.text(item.get("remediation"), f"{fp}.remediation", limit=600),
                "references": [
                    san.text(ref, f"{fp}.references[{r_index}]", limit=200)
                    for r_index, ref in enumerate(_list(item.get("references"))[:10])
                ],
                "derived": False,
                "target": model["target"],
                "seen": model["started"],
                "run": run.name,
            }
        )
    return findings


# --------------------------------------------------------------------------
# Integrity checks


def _exception(code: str, run: str | None, detail: str) -> dict[str, Any]:
    return {"code": code, "run": run, "detail": detail}


def _window_check(scope: _Scope, model: dict[str, Any], raw_targets: list[str]) -> list[dict[str, Any]]:
    exceptions = []
    started = parse_time(model.get("started"))
    finished = parse_time(model.get("finished")) or started
    if started is None:
        model["windowChecked"] = False
        return exceptions
    windows = [
        source
        for source in scope.sources
        if source.valid_from is not None
        and source.valid_until is not None
        and (not raw_targets or any(source.covers_address(address) for address in raw_targets))
    ]
    if not windows:
        model["windowChecked"] = False
        return exceptions
    model["windowChecked"] = True
    inside = any(
        source.valid_from <= started and finished <= source.valid_until for source in windows
    )
    if not inside:
        exceptions.append(
            _exception(
                "outside-approval-window",
                model["id"],
                f"run time {iso(started)} to {iso(finished)} is outside every approval window for its target",
            )
        )
    approved = [s for s in windows if s.status in (None, "approved")]
    if inside and not any(
        source.valid_from <= started and finished <= source.valid_until for source in approved
    ):
        exceptions.append(
            _exception("approval-not-active", model["id"], "the covering approval record is not in approved status")
        )
    return exceptions


def _target_check(scope: _Scope, model: dict[str, Any], target: dict[str, Any] | None, label: str) -> list[dict[str, Any]]:
    if target and target.get("address") == "unrecognized-host":
        return [_exception("target-not-literal", model["id"], f"{label} is not a literal address")]
    if not target or target.get("_raw") is None:
        return []
    raw = target["_raw"]
    if not scope.sources:
        return []
    if not any(source.covers(raw, target.get("port"), target.get("transport")) for source in scope.sources):
        port = target.get("port")
        transport = target.get("transport")
        return [
            _exception(
                "target-not-approved",
                model["id"],
                f"{label} {target['address']}:{port if port is not None else '?'}/{transport or '?'} is not in any approved address, port, and transport set",
            )
        ]
    return []


def _ceiling_check(model: dict[str, Any], scope: _Scope) -> list[dict[str, Any]]:
    exceptions = []
    sent = model.get("sent", {})
    applied = model.get("limitsApplied") or {}
    if model["kind"] == "campaign":
        for metric, ceiling in (("capturePackets", "packets"), ("captureBytes", "bytes"), ("calls", "calls")):
            value = sent.get(metric)
            limit = applied.get(ceiling)
            if value is not None and limit is not None and value > limit:
                exceptions.append(
                    _exception("ceiling-exceeded", model["id"], f"recorded {metric} {value} exceeds the frozen {ceiling} ceiling {limit}")
                )
    if model["kind"] == "call":
        call = model["details"].get("call", {})
        limit = applied.get("durationLimit")
        connected = call.get("connectedSeconds")
        if limit is not None and connected is not None and connected > limit + 2:
            exceptions.append(
                _exception("ceiling-exceeded", model["id"], f"connected {connected}s exceeds the duration limit {limit}s")
            )
    return exceptions


# --------------------------------------------------------------------------
# Observations, findings, limitations


def _observation(code: str, run: dict[str, Any], detail: str | None = None) -> dict[str, Any]:
    spec = OBSERVATIONS[code]
    return {
        "id": f"obs-{code}",
        "checkId": f"derived:{code}",
        "title": spec["title"],
        "severity": spec["severity"],
        "confidence": "derived",
        "summary": spec["summary"] + (f" {detail}" if detail else ""),
        "evidence": [{"kind": "run", "detail": f"{run['kind']} run verdict {run.get('verdict') or 'unrecorded'}", "artifact": run["ref"]}],
        "remediation": spec["recommendation"],
        "references": [],
        "derived": True,
        "target": run.get("target"),
        "seen": run.get("started"),
        "run": run["id"],
    }


def _observations(run: dict[str, Any]) -> list[dict[str, Any]]:
    found = []
    verdict = run.get("verdict")
    details = run.get("details", {})
    if run["kind"] == "call":
        if verdict in OBSERVATIONS:
            found.append(_observation(verdict, run))
        if verdict == "tls-name-pinning-failed":
            found.append(_observation("tls-not-verified", run))
        tls = details.get("tls") or {}
        if tls and tls.get("verified") is False and verdict != "tls-not-verified":
            found.append(_observation("tls-not-verified", run))
        preflight = details.get("preflight") or {}
        if (preflight.get("statusCode") or 0) >= 500:
            found.append(_observation("preflight-server-error", run, f"Status {preflight['statusCode']}."))
        oracle = details.get("oracle") or {}
        if oracle.get("verdict") == "fail" and (details.get("call") or {}).get("answered") and oracle.get("decidesVerdict"):
            found.append(_observation("oracle-assertion-failed", run, "Failed: " + ", ".join(oracle.get("failed") or []) + "."))
        if verdict in {"capture-failed", "capture-died"}:
            found.append(_observation("capture-incomplete", run))
    elif run["kind"] == "campaign":
        for entry in details.get("preflight", []):
            if (entry.get("statusCode") or 0) >= 500 or entry.get("warning") == "server_error_response":
                found.append(_observation("preflight-server-error", run, f"Status {entry.get('statusCode')}."))
                break
        for case in details.get("cases", []):
            if case.get("tlsVerified") is False:
                found.append(_observation("tls-not-verified", run, f"Step {case['step']}."))
                break
        if run.get("state") not in (None, "succeeded"):
            reason = details.get("stopReason") or run.get("state")
            if reason in {"capture_process_died", "capture_failed"}:
                found.append(_observation("capture-incomplete", run))
            else:
                found.append(_observation("campaign-stopped", run, f"Stop reason: {reason}."))
    return found


def _merge_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in items:
        target = item.get("target") or {}
        target_key = f"{target.get('address')}:{target.get('port')}/{target.get('transport')}"
        key = (item.get("checkId") or "", item.get("title") or "", target_key)
        if key not in merged:
            merged[key] = {
                **{k: v for k, v in item.items() if k not in {"run", "seen"}},
                "targetLabel": target_key if target else "unrecorded",
                "firstSeen": item.get("seen"),
                "lastSeen": item.get("seen"),
                "runs": [item["run"]],
                "occurrences": 1,
            }
            continue
        existing = merged[key]
        existing["occurrences"] += 1
        if item["run"] not in existing["runs"]:
            existing["runs"].append(item["run"])
        seen = item.get("seen")
        if seen and (existing["firstSeen"] is None or seen < existing["firstSeen"]):
            existing["firstSeen"] = seen
        if seen and (existing["lastSeen"] is None or seen > existing["lastSeen"]):
            existing["lastSeen"] = seen
        if SEVERITIES.index(item["severity"]) < SEVERITIES.index(existing["severity"]):
            existing["severity"] = item["severity"]
    ordered = sorted(
        merged.values(),
        key=lambda f: (SEVERITIES.index(f["severity"]), f["derived"], f.get("checkId") or "", f["title"], f["targetLabel"]),
    )
    for index, finding in enumerate(ordered, 1):
        finding["ref"] = f"F-{index:02d}"
        finding["runs"] = sorted(finding["runs"])
        if finding.get("target"):
            finding["target"] = {k: v for k, v in finding["target"].items() if not k.startswith("_")}
    return ordered


# --------------------------------------------------------------------------
# Journal and packs


def _journal(root: Path, ctx: Context, include_notes: bool) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not (root / "journal.jsonl").exists() and not (root / "engagement.json").exists():
        return {"present": False, "valid": None, "entries": [], "entryCount": 0, "headSha256": None, "missingEvidence": 0, "error": None}, []
    try:
        verification = verify_journal(root)
    except JournalError as error:
        return {
            "present": True,
            "valid": False,
            "entries": [],
            "entryCount": 0,
            "headSha256": None,
            "missingEvidence": 0,
            "error": ctx.sanitizer.text(str(error), "journal.error", limit=200),
        }, []
    entries = []
    for entry in verification.entries[-500:]:
        sequence = entry["sequence"]
        item = {
            "sequence": sequence,
            "kind": entry["kind"],
            "recordedAt": iso(parse_time(entry["recordedAt"])) or ctx.sanitizer.identifier(entry["recordedAt"], f"journal.entries[{sequence}].recordedAt", limit=40),
            "title": ctx.sanitizer.text(entry["summary"], f"journal.entries[{sequence}].title", limit=200),
            "evidenceCount": len(entry["evidence"]),
        }
        if include_notes and entry["detail"]:
            item["notes"] = ctx.sanitizer.text(entry["detail"], f"journal.entries[{sequence}].notes", limit=2000)
        entries.append(item)
    return {
        "present": True,
        "valid": True,
        "entries": entries,
        "entryCount": len(verification.entries),
        "headSha256": verification.final_sha256,
        "missingEvidence": len(verification.missing_evidence),
        "notesIncluded": include_notes,
        "error": None,
    }, list(verification.entries)


def _packs(root: Path, ctx: Context) -> list[dict[str, Any]]:
    candidates: list[Path] = []
    for base in (root, root / "packs"):
        try:
            if base.is_symlink() or not base.is_dir():
                continue
            for child in sorted(itertools.islice(base.iterdir(), MAX_ROOT_ENTRIES)):
                if child.name.endswith((".tar", ".tar.age")) and child.is_file() and not child.is_symlink():
                    candidates.append(child)
        except OSError:
            continue
    packs = []
    for index, path in enumerate(candidates[:MAX_PACKS]):
        entry: dict[str, Any] = {
            "name": ctx.sanitizer.identifier(path.relative_to(root).as_posix(), f"packs[{index}].name", limit=160),
            "encrypted": path.name.endswith(".age"),
            "size": None,
            "sha256": None,
            "contentIdentity": None,
            "readable": True,
        }
        hashed = _stream_hash(path)
        if hashed:
            entry["size"], entry["sha256"] = hashed
        if not entry["encrypted"]:
            try:
                with tarfile.open(path, "r:") as archive:
                    for member in itertools.islice(archive, 2048):
                        if member.name == "pack-manifest.json" and member.isfile() and member.size <= MAX_JSON_BYTES:
                            source = archive.extractfile(member)
                            if source is not None:
                                value = json.loads(source.read(MAX_JSON_BYTES).decode("utf-8"))
                                identity = _digest(_dict(value).get("contentIdentity"))
                                entry["contentIdentity"] = f"sha256:{identity}" if identity else None
                            break
            except (OSError, tarfile.TarError, ValueError, UnicodeDecodeError, RecursionError):
                entry["readable"] = False
        packs.append(entry)
    return packs


# --------------------------------------------------------------------------
# Top level


def _engagement_metadata(root: Path) -> dict[str, Any]:
    path = root / "engagement.json"
    try:
        value = read_json(path, 64 * 1024)
    except Unreadable:
        return {}
    return value if isinstance(value, dict) else {}


def _toolbox(raws: list[RawRun], cli_version: str | None) -> dict[str, Any]:
    tools: dict[str, set[str]] = {}
    images: set[str] = set()
    pythons: set[str] = set()

    def visit(name: str, value: Any) -> None:
        value = _dict(value)
        version = value.get("version")
        if isinstance(version, str):
            text = strip_controls(version)[:80]
            if re.fullmatch(r"[A-Za-z0-9 ().,_+:-]{1,80}", text):
                tools.setdefault(name, set()).add(text)

    for run in raws:
        versions = _dict(run.docs.get("versions.json"))
        for key, value in versions.items():
            if key in {"image", "imageId", "imageDigest"} and isinstance(value, str) and re.fullmatch(r"(sha256:)?[0-9a-f]{12,64}", value):
                images.add(value)
            elif key == "python" and isinstance(value, str) and re.fullmatch(r"[0-9.]{1,16}", value):
                pythons.add(value)
            elif isinstance(value, dict) and re.fullmatch(r"[a-z][a-z0-9-]{0,40}", key):
                visit(key, value)
    return {
        "cliVersion": cli_version or "unknown",
        "imageIds": sorted(images),
        "python": sorted(pythons),
        "tools": {name: sorted(values) for name, values in sorted(tools.items())},
    }


def _sum(runs: list[dict[str, Any]], metric: str) -> dict[str, Any]:
    known = [run["sent"].get(metric) for run in runs if run["sent"].get(metric) is not None]
    applicable = [run for run in runs if metric in run["sent"]]
    return {
        "total": sum(known) if known else None,
        "runsRecorded": len(known),
        "runsUnrecorded": len([r for r in applicable if r["sent"].get(metric) is None and r["readable"] != "unreadable" and _applies(r, metric)]),
    }


def _applies(run: dict[str, Any], metric: str) -> bool:
    if run["kind"] == "check":
        return metric == "checkRequests"
    if metric == "checkRequests":
        return False
    return True


def build_report(root: Path, options: Options) -> tuple[dict[str, Any], Context]:
    root = root.resolve(strict=True)
    metadata = _engagement_metadata(root)
    addresses = AddressBook()
    # 1. Reviewed authorization records.
    sources: list[Source] = []
    source_warnings: list[str] = []
    scope_path = root / "scope.yaml"
    if scope_path.is_file() and not scope_path.is_symlink():
        try:
            document = read_yaml(scope_path)
            if isinstance(document, dict):
                sources.append(_scope_source(document, "scope.yaml"))
        except Unreadable as error:
            source_warnings.append(f"scope.yaml is unreadable ({error})")
    yaml_files: list[Path] = []
    try:
        yaml_files = sorted(
            path
            for path in itertools.islice(root.iterdir(), MAX_ROOT_ENTRIES)
            if path.suffix in {".yaml", ".yml"} and path.name != "scope.yaml" and path.is_file() and not path.is_symlink()
        )[:MAX_SOURCES]
    except OSError:
        pass
    explicit_profiles = [Path(p) for p in options.profiles]
    explicit_manifests = [Path(p) for p in options.manifests]
    profile_paths: list[Path] = []
    for path in yaml_files + explicit_profiles + explicit_manifests:
        try:
            document = read_yaml(path)
        except Unreadable as error:
            source_warnings.append(f"{path.name} is unreadable ({error})")
            continue
        if not isinstance(document, dict):
            continue
        try:
            ref = path.resolve().relative_to(root).as_posix()
        except (OSError, ValueError):
            ref = f"external/{path.name}"
        if str(document.get("schema_version", "")).startswith("sippycup.dev/target-profile/"):
            sources.append(_profile_source(document, ref))
            profile_paths.append(path.resolve())
        elif document.get("kind") == "Campaign" and isinstance(document.get("authorization"), dict):
            sources.append(_manifest_source(document, ref))
    seen_refs: set[str] = set()
    unique_sources = []
    for source in sources:
        if source.ref in seen_refs:
            continue
        seen_refs.add(source.ref)
        unique_sources.append(source)
    sources = unique_sources
    for source in sources:
        for network in source.networks + source.media_networks:
            addresses.add_network(network)
        for item in source.assessor:
            canonical = _canonical_ip(item)
            if canonical:
                addresses.assessor.add(canonical)
    reviewed_destinations = {d for s in sources for d in s.destinations}
    reviewed_accounts = {a for s in sources for a in s.accounts}
    reviewed_names = {n for s in sources for n in s.server_names}
    scope = _Scope(
        sources=sources,
        destinations=_Labeler(reviewed_destinations | reviewed_accounts, "unreviewed-destination"),
        accounts=_Labeler(reviewed_accounts, "unreviewed-account"),
        server_names=_Labeler(reviewed_names, "unreviewed-server-name"),
        addresses=addresses,
    )
    sanitizer = Sanitizer(addresses=addresses, forbidden=tuple(options.forbidden))
    ctx = Context(
        addresses=addresses,
        sanitizer=sanitizer,
        allow_call_ids=options.audience == "internal",
        forbidden=tuple(options.forbidden),
    )

    # 2. Journal (also names run roots through its evidence references).
    journal, journal_entries = _journal(root, ctx, options.include_journal_notes or options.audience == "internal")

    # 3. Runs.
    raws, run_roots, discovery_warnings = discover_runs(
        root,
        extra_roots=[Path(p) for p in options.run_roots],
        profile_paths=profile_paths,
        journal_entries=journal_entries,
    )
    sanitizer.run_names = {raw.name for raw in raws}
    for raw in raws:
        try:
            _load_raw(raw)
        except Exception as error:  # noqa: BLE001 - never crash on one run
            raw.problems.append(f"run could not be read ({type(error).__name__})")
        result = _dict(raw.docs.get("result.json"))
        local = _canonical_ip(result.get("localAddress"))
        if local and not addresses.approved(local):
            addresses.assessor.add(local)
    filtered: list[RawRun] = []
    for raw in raws:
        if options.run_globs and not any(
            fnmatch.fnmatchcase(raw.name, pattern) or fnmatch.fnmatchcase(raw.ref, pattern)
            for pattern in options.run_globs
        ):
            continue
        filtered.append(raw)
    runs: list[dict[str, Any]] = []
    candidate_findings: list[dict[str, Any]] = []
    exceptions: list[dict[str, Any]] = []
    for raw in filtered:
        model = _base_run(raw)
        prefix = f"runs[{raw.name}]"
        try:
            model["problems"].extend(sanitizer.text(p, f"{prefix}.problems") for p in raw.problems)
            if raw.problems:
                model["readable"] = "partial"
            if raw.kind == "call":
                _call_run(raw, model, scope, ctx, prefix)
            elif raw.kind == "campaign":
                _campaign_run(raw, model, scope, ctx, prefix)
            elif raw.kind == "check":
                candidate_findings.extend(_check_run(raw, model, scope, ctx, prefix))
            else:
                model["readable"] = "unreadable"
                model["problems"].append("unrecognized run directory")
        except Exception as error:  # noqa: BLE001 - one bad run must not stop the report
            model = _base_run(raw)
            model["readable"] = "unreadable"
            model["problems"] = [f"run could not be interpreted ({type(error).__name__})"]
        if options.since is not None:
            started = parse_time(model.get("started"))
            if started is None or started < options.since:
                continue
        start, end = parse_time(model.get("started")), parse_time(model.get("finished"))
        if start and end and end >= start:
            model["durationSeconds"] = round((end - start).total_seconds(), 3)
        model["evidence"] = _evidence(raw, ctx, f"{prefix}.evidence")
        if model["readable"] != "unreadable":
            raw_targets = []
            for target in [model.get("target")] + list(model.get("targets") or []) + [c.get("target") for c in model["details"].get("cases", [])]:
                if target and target.get("_raw"):
                    raw_targets.append(target["_raw"])
            model["integrity"].extend(_target_check(scope, model, model.get("target"), "target"))
            for case in model["details"].get("cases", []):
                if case["outcome"] != "not-run":
                    model["integrity"].extend(_target_check(scope, model, case.get("target"), f"step {case['step']} target"))
            for entry in model["details"].get("preflight", []) if isinstance(model["details"].get("preflight"), list) else []:
                model["integrity"].extend(_target_check(scope, model, entry.get("target"), "preflight target"))
            peer = model.pop("_mediaPeerRaw", None)
            if peer and not addresses.approved(peer):
                model["integrity"].append(
                    _exception("media-peer-not-approved", raw.name, f"media peer {addresses.label(peer)} is not an approved address")
                )
            model["integrity"].extend(_window_check(scope, model, raw_targets))
            model["integrity"].extend(_ceiling_check(model, scope))
            if model["started"] is None:
                model["problems"].append("no recorded start time; approval window not checked")
        model.pop("_mediaPeerRaw", None)
        runs.append(model)
    # Addresses outside the approved set that appeared in any artifact text.
    for path, label in sorted(set(sanitizer.unapproved_hits)):
        run_name = None
        match = re.match(r"runs\[([^\]]+)\]", path)
        if match:
            run_name = match.group(1)
        exceptions.append(_exception("unapproved-address-in-artifact", run_name, f"{label} appeared in {path}"))
    runs.sort(key=lambda r: (r.get("started") or "9999", r["id"]))
    for index, run in enumerate(runs, 1):
        run["label"] = f"R{index}"
    for run in runs:
        exceptions.extend(run["integrity"])
        candidate_findings.extend(_observations(run) if run["readable"] != "unreadable" else [])
    # Deduplicate exceptions.
    unique_exceptions = {(e["code"], e["run"] or "", e["detail"]): e for e in exceptions}
    exceptions = [unique_exceptions[key] for key in sorted(unique_exceptions)]
    findings = _merge_findings(candidate_findings)
    # Strip private target fields.
    for run in runs:
        for holder in [run] + run["details"].get("cases", []) + (run["details"].get("preflight") if isinstance(run["details"].get("preflight"), list) else []):
            if isinstance(holder.get("target"), dict):
                holder["target"] = {k: v for k, v in holder["target"].items() if not k.startswith("_")}
        if run.get("targets"):
            run["targets"] = [{k: v for k, v in t.items() if not k.startswith("_")} for t in run["targets"]]

    # 4. Window and summary facts.
    windows = [s for s in sources if s.valid_from and s.valid_until]
    window = None
    if windows:
        window = {
            "from": iso(min(s.valid_from for s in windows)),
            "until": iso(max(s.valid_until for s in windows)),
        }
    totals = {
        metric: _sum(runs, metric)
        for metric in ("optionsRequests", "registerAttempts", "calls", "rtpPacketsSent", "capturePackets", "captureBytes", "checkRequests")
    }
    totals["optionsRequests"]["lowerBound"] = any(r["sent"].get("optionsLowerBound") for r in runs)
    ceilings = _engagement_ceilings(sources)
    limitations = _limitations(runs, sources, source_warnings + discovery_warnings, journal)
    recommendations = []
    for finding in findings:
        if finding.get("remediation"):
            recommendations.append(
                {
                    "finding": finding["ref"],
                    "severity": finding["severity"],
                    "title": finding["title"],
                    "text": finding["remediation"],
                    "derived": finding["derived"],
                }
            )
    generated = options.generated_at
    title = options.title or _reviewed(metadata.get("title")) or root.name
    kinds = {kind: sum(1 for r in runs if r["kind"] == kind) for kind in ("call", "campaign", "check", "unknown")}
    model = {
        "apiVersion": REPORT_VERSION,
        "kind": "EngagementReport",
        "audience": options.audience,
        "networkActivity": False,
        "engagement": {
            "title": _reviewed(title, 200),
            "owner": _reviewed(metadata.get("owner")),
            "createdAt": iso(parse_time(metadata.get("createdAt"))),
            "generatedAt": generated,
            "runRoots": run_roots,
            "filters": {
                "runs": list(options.run_globs),
                "since": iso(options.since),
            },
        },
        "toolbox": _toolbox([raw for raw in filtered], options.cli_version),
        "authorization": {
            "sources": [source.as_dict() for source in sources],
            "window": window,
            "approvedAddresses": sorted({str(n) for n in addresses.networks}),
            "present": bool(sources),
        },
        "integrityExceptions": exceptions,
        "runs": runs,
        "runCounts": kinds,
        "totals": totals,
        "ceilings": ceilings,
        "findings": findings,
        "findingCounts": {
            severity: sum(1 for f in findings if f["severity"] == severity) for severity in SEVERITIES
        },
        "journal": journal,
        "packs": _packs(root, ctx),
        "limitations": limitations,
        "recommendations": recommendations,
        "privacy": {
            "audience": options.audience,
            "callIdsShown": ctx.allow_call_ids,
            "journalNotesIncluded": bool(journal.get("notesIncluded")),
            "redactedStrings": sanitizer.redactions,
            "unapprovedAddressLabels": len(addresses.pseudonyms),
        },
    }
    model["executiveSummary"] = _executive(model)
    model["integrity"] = {
        "journalHeadSha256": journal.get("headSha256"),
        "runContentIdentities": [
            {"run": run["id"], "contentIdentity": run["evidence"]["contentIdentity"], "source": run["evidence"]["source"]}
            for run in runs
        ],
    }
    return model, ctx


def _engagement_ceilings(sources: list[Source]) -> list[dict[str, Any]]:
    rows = []
    for source in sources:
        for key, value in sorted(source.limits.items()):
            rows.append({"source": source.ref, "kind": source.kind, "limit": key, "value": value})
    return rows


STAGES = (
    ("call", "Guided baseline call", lambda r: r["kind"] == "call"),
    ("auth-call", "Authenticated call (registration)", lambda r: r["kind"] == "call" and (r["details"].get("registration") or {}).get("attempted")),
    ("tls", "TLS signaling", lambda r: (r.get("target") or {}).get("transport") == "tls" or any((c.get("target") or {}).get("transport") == "tls" for c in r["details"].get("cases", []))),
    ("campaign", "Supervised campaign", lambda r: r["kind"] == "campaign"),
    ("checks", "Security checks", lambda r: r["kind"] == "check"),
)


def _limitations(runs: list[dict[str, Any]], sources: list[Source], warnings: list[str], journal: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    readable = [r for r in runs if r["readable"] != "unreadable"]
    for code, label, test in STAGES:
        if not any(test(r) for r in readable):
            items.append({"code": f"stage-not-run:{code}", "text": f"{label}: not run in this engagement."})
    for run in runs:
        if run["readable"] == "unreadable":
            items.append({"code": "run-unreadable", "text": f"Run {run['id']} could not be read: {'; '.join(p for p in run['problems'] if p) or 'unrecognized'}."})
        elif run["readable"] == "partial":
            items.append({"code": "run-partial", "text": f"Run {run['id']} is incomplete: {'; '.join(p for p in run['problems'] if p)}."})
        if run["readable"] != "unreadable" and run.get("windowChecked") is False and run.get("started"):
            items.append({"code": "window-not-checked", "text": f"Run {run['id']}: no recorded validity window covers its target, so its time was not re-checked against an approval window."})
        if run["kind"] == "check":
            for check in run["details"].get("checks", []):
                if check["status"] in {"skipped", "not-approved", "error"}:
                    items.append(
                        {
                            "code": f"check-{check['status']}",
                            "text": f"Check {check['id']} ({run['id']}) was {check['status']}" + (f": {check['summary']}" if check.get("summary") else "."),
                        }
                    )
        if run["kind"] == "campaign":
            for case in run["details"].get("cases", []):
                if case["outcome"] == "not-run":
                    items.append({"code": "step-not-run", "text": f"Campaign {run['id']} step {case['step']} ({case['case']}) was never run."})
            for entry in run["details"].get("notExercised", []):
                items.append(
                    {
                        "code": "factor-not-exercised",
                        "text": f"Campaign {run['id']} step {entry['step']}: factor {entry['factor']} was not exercised" + (f" ({entry['reason']})." if entry.get("reason") else "."),
                    }
                )
        if run["kind"] == "call":
            oracle = run["details"].get("oracle") or {}
            if not oracle.get("decidesVerdict") and run["details"].get("tls"):
                items.append({"code": "tls-oracle-blind", "text": f"Call {run['id']}: signaling was TLS-encrypted, so the packet oracle could not inspect SIP; verdict facts come from the softphone log and decoded RTP."})
    if not sources:
        items.append({"code": "no-authorization-record", "text": "No scope file, target profile, or campaign manifest was found in the engagement directory; targets and windows could not be re-checked."})
    if journal.get("present") is False:
        items.append({"code": "no-journal", "text": "No assessment journal was found; the report cannot be tied to a journal head hash."})
    for warning in sorted(set(warnings)):
        items.append({"code": "discovery-warning", "text": warning})
    items.append({"code": "recorded-numbers-only", "text": "Totals come from numbers the runs recorded; captures were not re-parsed. Media quality was not measured."})
    return items


def _executive(model: dict[str, Any]) -> dict[str, Any]:
    runs = model["runs"]
    counts = model["runCounts"]
    findings = model["findings"]
    exceptions = model["integrityExceptions"]
    window = model["authorization"]["window"]
    approval_ids = sorted({s["approvalId"] for s in model["authorization"]["sources"] if s.get("approvalId")})
    reported = [f for f in findings if not f["derived"]]
    derived = [f for f in findings if f["derived"]]
    starts = sorted(r["started"] for r in runs if r.get("started"))
    ends = sorted(r["finished"] for r in runs if r.get("finished"))
    parts = []
    if runs:
        span = f"between {starts[0]} and {ends[-1]}" if starts and ends else "at unrecorded times"
        parts.append(
            f"{len(runs)} run{'s' if len(runs) != 1 else ''} were recorded {span}: "
            f"{counts['call']} guided call{'s' if counts['call'] != 1 else ''}, "
            f"{counts['campaign']} campaign{'s' if counts['campaign'] != 1 else ''}, and "
            f"{counts['check']} security-check run{'s' if counts['check'] != 1 else ''}."
        )
    else:
        parts.append("No runs were recorded in this engagement directory.")
    if approval_ids:
        parts.append(
            "Activity was checked against approval "
            + ", ".join(approval_ids)
            + (f" (window {window['from']} to {window['until']})." if window else ".")
        )
    elif model["authorization"]["present"]:
        parts.append("Activity was checked against the reviewed scope records in the engagement directory.")
    else:
        parts.append("No authorization record was found, so targets and times could not be re-checked.")
    severity_text = ", ".join(
        f"{sum(1 for f in reported if f['severity'] == s)} {s}" for s in SEVERITIES if any(f["severity"] == s for f in reported)
    )
    parts.append(
        (
            f"Security checks reported {len(reported)} finding{'s' if len(reported) != 1 else ''} ({severity_text})"
            if reported
            else ("Security checks reported no findings" if counts["check"] else "No security-check runs were recorded, so there are no check findings")
        )
        + (f"; the report derived {len(derived)} observation{'s' if len(derived) != 1 else ''} from run results." if derived else ".")
    )
    if exceptions:
        parts.append(f"{len(exceptions)} integrity exception{'s' if len(exceptions) != 1 else ''} require review before this report is relied on.")
    else:
        parts.append("Every run fell inside the approved targets and window.")
    rows = []
    for finding in findings[:4]:
        rows.append(
            {
                "ref": finding["ref"],
                "severity": finding["severity"],
                "title": finding["title"],
                "where": finding.get("targetLabel"),
                "source": "derived observation" if finding["derived"] else "security check",
                "runs": len(finding["runs"]),
            }
        )
    if len(findings) > 4:
        rows.append({"ref": "-", "severity": "none", "title": f"{len(findings) - 4} more finding{'s' if len(findings) != 5 else ''} in the Findings section", "where": "-", "source": "report", "runs": 0})
    passed = [r for r in runs if r.get("verdict") in ("pass", "succeeded", "no-findings")]
    failed = [r for r in runs if r not in passed and r.get("kind") != "check"]
    filler = []
    if not runs:
        filler.append({"ref": "-", "severity": "none", "title": "No runs were recorded", "where": "-", "source": "run results", "runs": 0})
    if not findings:
        filler.append({"ref": "-", "severity": "none", "title": "No findings reported and no observations derived", "where": "-", "source": "security checks and run results", "runs": 0})
    if passed:
        filler.append({"ref": "-", "severity": "none", "title": f"{len(passed)} run{'s' if len(passed) != 1 else ''} completed as expected", "where": "-", "source": "run results", "runs": len(passed)})
    if failed:
        verdicts: dict[str, int] = {}
        for run in failed:
            key = run.get("verdict") or run["readable"]
            verdicts[key] = verdicts.get(key, 0) + 1
        breakdown = ", ".join(f"{name} ({count})" for name, count in sorted(verdicts.items()))
        filler.append({"ref": "-", "severity": "none", "title": f"{len(failed)} run{'s' if len(failed) != 1 else ''} did not pass: {breakdown}", "where": "-", "source": "run results", "runs": len(failed)})
    filler.append({"ref": "-", "severity": "none", "title": f"{len(exceptions)} integrity exception{'s' if len(exceptions) != 1 else ''}", "where": "-", "source": "report re-check", "runs": len({e['run'] for e in exceptions if e['run']})})
    for row in filler:
        if len(rows) >= 3:
            break
        rows.append(row)
    return {"paragraph": " ".join(parts), "rows": rows[:5]}
