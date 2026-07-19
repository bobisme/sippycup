"""Read-only capability detection and disposable topology planning.

This module deliberately contains no mutation primitive.  It can inspect
routes, qdiscs, capabilities, and named namespaces, then render a frozen plan
for a later lifecycle owner to apply.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


PLAN_VERSION = "sippycup.dev/chaos-topology-plan/v1"
MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
_NAME_RE = re.compile(r"[a-z][a-z0-9-]{0,30}")
_INTERFACE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}")
_CONFIRMATION_RE = re.compile(r"dedicated-test-vm:[A-Za-z0-9][A-Za-z0-9_.-]{0,62}")
_CAP_NET_ADMIN = 12
_CAP_SYS_ADMIN = 21


class TopologyError(ValueError):
    """The requested topology cannot be planned safely."""


class FeatureState(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class Direction(str, Enum):
    EGRESS = "egress"
    INGRESS = "ingress"
    BIDIRECTIONAL = "bidirectional"
    ASYMMETRIC = "asymmetric"


class TopologyKind(str, Enum):
    DISPOSABLE_ROUTER = "disposable-router"
    DANGEROUS_HOST_NETWORK = "dangerous-host-network"


@dataclass(frozen=True, slots=True)
class CapabilitySnapshot:
    execution_mode: str
    podman: FeatureState
    iproute2: FeatureState
    tc: FeatureState
    net_admin: FeatureState
    netem: FeatureState
    ifb: FeatureState
    classifier: FeatureState
    mtu: FeatureState
    evidence: Mapping[str, str]
    sys_admin: FeatureState = FeatureState.UNKNOWN
    pasta: FeatureState = FeatureState.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "executionMode": self.execution_mode,
            "features": {
                "podman": self.podman.value,
                "iproute2": self.iproute2.value,
                "tc": self.tc.value,
                "netAdmin": self.net_admin.value,
                "netem": self.netem.value,
                "ifb": self.ifb.value,
                "classifier": self.classifier.value,
                "mtu": self.mtu.value,
                "sysAdmin": self.sys_admin.value,
                "pasta": self.pasta.value,
            },
            "evidence": dict(sorted(self.evidence.items())),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CapabilitySnapshot":
        try:
            features = value["features"]
            evidence = value.get("evidence", {})
            execution_mode = str(value["executionMode"])
            if execution_mode not in {"rootless", "rootful"}:
                raise ValueError("executionMode must be rootless or rootful")
            return cls(
                execution_mode=execution_mode,
                podman=FeatureState(features["podman"]),
                iproute2=FeatureState(features["iproute2"]),
                tc=FeatureState(features["tc"]),
                net_admin=FeatureState(features["netAdmin"]),
                netem=FeatureState(features["netem"]),
                ifb=FeatureState(features["ifb"]),
                classifier=FeatureState(features["classifier"]),
                mtu=FeatureState(features["mtu"]),
                evidence={str(key): str(item) for key, item in evidence.items()},
                sys_admin=FeatureState(
                    features.get("sysAdmin", FeatureState.UNKNOWN.value)
                ),
                pasta=FeatureState(
                    features.get("pasta", FeatureState.UNKNOWN.value)
                ),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise TopologyError(f"invalid capability snapshot: {error}") from error


@dataclass(frozen=True, slots=True)
class NamespaceSnapshot:
    name: str
    exists: bool
    routes: Any
    qdiscs: Any

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "exists": self.exists,
            "routes": self.routes,
            "qdiscs": self.qdiscs,
        }


@dataclass(frozen=True, slots=True)
class NetworkSnapshot:
    host_routes: Any
    host_qdiscs: Any
    namespaces: tuple[NamespaceSnapshot, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": {
                "routes": self.host_routes,
                "qdiscs": self.host_qdiscs,
            },
            "namespaces": [item.to_dict() for item in self.namespaces],
        }


@dataclass(frozen=True, slots=True)
class TopologyRequest:
    targets: tuple[str, ...]
    direction: Direction
    topology: TopologyKind = TopologyKind.DISPOSABLE_ROUTER
    namespace_prefix: str = "sippycup-chaos"
    dangerous_confirmation: str | None = None
    require_mtu: bool = False
    host_interface: str | None = None


CommandReader = Callable[[Sequence[str]], str]


def _read_command(command: Sequence[str]) -> str:
    try:
        completed = subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TopologyError(f"read-only probe failed for {command[0]!r}: {error}") from error
    if completed.returncode:
        detail = completed.stderr[:2048].decode(errors="replace").strip()
        raise TopologyError(
            f"read-only probe {' '.join(command)!r} failed"
            + (f": {detail}" if detail else "")
        )
    if len(completed.stdout) > MAX_SNAPSHOT_BYTES:
        raise TopologyError(
            f"read-only probe {' '.join(command)!r} exceeded "
            f"{MAX_SNAPSHOT_BYTES} bytes"
        )
    return completed.stdout.decode()


def _json_probe(reader: CommandReader, command: Sequence[str]) -> Any:
    try:
        value = json.loads(reader(command))
    except json.JSONDecodeError as error:
        raise TopologyError(
            f"read-only probe {' '.join(command)!r} did not return JSON"
        ) from error
    if not isinstance(value, list):
        raise TopologyError(f"read-only probe {' '.join(command)!r} must return an array")
    return value


def _valid_name(value: str, field: str) -> str:
    if not _NAME_RE.fullmatch(value):
        raise TopologyError(
            f"{field} must match {_NAME_RE.pattern!r}; got {value!r}"
        )
    return value


def collect_network_snapshot(
    namespace_names: Sequence[str],
    *,
    reader: CommandReader = _read_command,
) -> NetworkSnapshot:
    """Read host and existing namespace routes/qdiscs without changing them."""

    names = tuple(_valid_name(name, "namespace name") for name in namespace_names)
    if len(set(names)) != len(names):
        raise TopologyError("namespace names must be unique")
    host_routes = _json_probe(reader, ("ip", "-json", "route", "show", "table", "all"))
    host_qdiscs = _json_probe(reader, ("tc", "-json", "qdisc", "show"))
    listed = reader(("ip", "netns", "list"))
    existing = {
        line.split()[0]
        for line in listed.splitlines()
        if line.strip() and _NAME_RE.fullmatch(line.split()[0])
    }
    snapshots: list[NamespaceSnapshot] = []
    for name in names:
        if name not in existing:
            snapshots.append(NamespaceSnapshot(name, False, [], []))
            continue
        routes = _json_probe(
            reader,
            (
                "nsenter",
                f"--net=/run/netns/{name}",
                "ip",
                "-json",
                "route",
                "show",
                "table",
                "all",
            ),
        )
        qdiscs = _json_probe(
            reader,
            ("nsenter", f"--net=/run/netns/{name}", "tc", "-json", "qdisc", "show"),
        )
        snapshots.append(NamespaceSnapshot(name, True, routes, qdiscs))
    return NetworkSnapshot(host_routes, host_qdiscs, tuple(snapshots))


def _is_rootless(euid: int, uid_map: str) -> bool:
    if euid != 0:
        return True
    for line in uid_map.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0] == "0":
            return fields[1] != "0"
    return False


def _module_state(name: str, module_root: Path, sys_module_root: Path) -> FeatureState:
    if (sys_module_root / name).exists():
        return FeatureState.AVAILABLE
    release_root = module_root / platform.release()
    if not release_root.exists():
        return FeatureState.UNKNOWN
    builtin = release_root / "modules.builtin"
    try:
        if builtin.exists() and any(
            candidate in builtin.read_text(errors="replace")
            for candidate in (name, name.replace("_", "-"))
        ):
            return FeatureState.AVAILABLE
        if any(release_root.rglob(f"{name}.ko*")):
            return FeatureState.AVAILABLE
    except OSError:
        return FeatureState.UNKNOWN
    return FeatureState.UNAVAILABLE


def _capability_state(status_text: str, bit: int) -> FeatureState:
    match = re.search(r"^CapEff:\s*([0-9a-fA-F]+)\s*$", status_text, re.MULTILINE)
    if match is None:
        return FeatureState.UNKNOWN
    return (
        FeatureState.AVAILABLE
        if int(match.group(1), 16) & (1 << bit)
        else FeatureState.UNAVAILABLE
    )


def detect_capabilities(
    *,
    euid: int | None = None,
    uid_map: str | None = None,
    status_text: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
    module_root: Path = Path("/lib/modules"),
    sys_module_root: Path = Path("/sys/module"),
    tun_path: Path = Path("/dev/net/tun"),
) -> CapabilitySnapshot:
    """Detect capabilities without loading modules or changing network state."""

    actual_euid = os.geteuid() if euid is None else euid
    if uid_map is None:
        try:
            uid_map = Path("/proc/self/uid_map").read_text()
        except OSError:
            uid_map = ""
    if status_text is None:
        try:
            status_text = Path("/proc/self/status").read_text()
        except OSError:
            status_text = ""
    rootless = _is_rootless(actual_euid, uid_map)
    command_states = {
        name: FeatureState.AVAILABLE if which(name) else FeatureState.UNAVAILABLE
        for name in ("podman", "ip", "tc", "pasta")
    }
    try:
        tun_available = (
            tun_path.is_char_device()
            and os.access(tun_path, os.R_OK | os.W_OK)
        )
    except OSError:
        tun_available = False
    pasta = (
        FeatureState.AVAILABLE
        if command_states["pasta"] is FeatureState.AVAILABLE and tun_available
        else FeatureState.UNAVAILABLE
    )
    net_admin = _capability_state(status_text, _CAP_NET_ADMIN)
    sys_admin = _capability_state(status_text, _CAP_SYS_ADMIN)
    netem = _module_state("sch_netem", module_root, sys_module_root)
    ifb = _module_state("ifb", module_root, sys_module_root)
    flower = _module_state("cls_flower", module_root, sys_module_root)
    u32 = _module_state("cls_u32", module_root, sys_module_root)
    classifier = (
        FeatureState.AVAILABLE
        if FeatureState.AVAILABLE in {flower, u32}
        else FeatureState.UNKNOWN
        if FeatureState.UNKNOWN in {flower, u32}
        else FeatureState.UNAVAILABLE
    )
    mtu = (
        FeatureState.AVAILABLE
        if command_states["ip"] is FeatureState.AVAILABLE
        and net_admin is FeatureState.AVAILABLE
        else FeatureState.UNAVAILABLE
        if command_states["ip"] is FeatureState.UNAVAILABLE
        or net_admin is FeatureState.UNAVAILABLE
        else FeatureState.UNKNOWN
    )
    return CapabilitySnapshot(
        execution_mode="rootless" if rootless else "rootful",
        podman=command_states["podman"],
        iproute2=command_states["ip"],
        tc=command_states["tc"],
        net_admin=net_admin,
        netem=netem,
        ifb=ifb,
        classifier=classifier,
        mtu=mtu,
        sys_admin=sys_admin,
        pasta=pasta,
        evidence={
            "effectiveUid": str(actual_euid),
            "kernelRelease": platform.release(),
            "pastaTunDevice": str(tun_path) if tun_available else "unavailable",
            "probePolicy": "read-only; no module loading or qdisc/link mutation",
        },
    )


def _canonical_targets(
    values: Sequence[str],
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    if not values:
        raise TopologyError("at least one frozen target CIDR is required")
    networks: dict[
        tuple[int, int, int], ipaddress.IPv4Network | ipaddress.IPv6Network
    ] = {}
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as error:
            raise TopologyError(
                f"target {value!r} must be a canonical literal CIDR, not a hostname"
            ) from error
        if network.prefixlen == 0:
            raise TopologyError("default-route target filters are forbidden")
        if network.is_multicast or network.is_unspecified:
            raise TopologyError(f"target network {network} is not a unicast scope")
        key = (network.version, int(network.network_address), network.prefixlen)
        networks[key] = network
    return tuple(networks[key] for key in sorted(networks))


def _require(
    capabilities: CapabilitySnapshot,
    names: Sequence[str],
    *,
    context: str,
) -> None:
    missing = []
    for name in names:
        value = getattr(capabilities, name)
        if value is not FeatureState.AVAILABLE:
            missing.append(f"{name}={value.value}")
    if missing:
        raise TopologyError(
            f"{context} is unsupported by the probed environment: "
            + ", ".join(missing)
        )


def _hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def plan_topology(
    request: TopologyRequest,
    capabilities: CapabilitySnapshot,
    snapshot: NetworkSnapshot,
) -> dict[str, Any]:
    """Render a deterministic, no-change topology plan."""

    prefix = _valid_name(request.namespace_prefix, "namespace prefix")
    networks = _canonical_targets(request.targets)
    namespace_names = {
        "test": f"{prefix}-test",
        "impairment": f"{prefix}-impair",
        "uplink": f"{prefix}-uplink",
    }
    for name in namespace_names.values():
        _valid_name(name, "derived namespace name")

    expected_snapshots = (
        set(namespace_names.values())
        if request.topology is TopologyKind.DISPOSABLE_ROUTER
        else set()
    )
    actual_snapshots = {item.name for item in snapshot.namespaces}
    if actual_snapshots != expected_snapshots:
        raise TopologyError(
            "network snapshot must contain exactly the planned namespaces"
        )
    occupied = sorted(item.name for item in snapshot.namespaces if item.exists)
    if occupied:
        raise TopologyError(
            "refusing to reuse existing namespaces: " + ", ".join(occupied)
        )

    if request.topology is TopologyKind.DISPOSABLE_ROUTER:
        _require(
            capabilities,
            (
                "iproute2",
                "tc",
                "net_admin",
                "sys_admin",
                "netem",
                "classifier",
                "pasta",
            ),
            context="disposable impairment routing",
        )
        if request.require_mtu:
            _require(capabilities, ("mtu",), context="MTU impairment")
        dangerous = False
        privilege_boundary = (
            "NET_ADMIN/SYS_ADMIN are confined to the isolated lifecycle "
            "controller; the traffic child drops both capabilities and host "
            "routes/qdiscs are read-only"
        )
        attachments = {
            "egress": {
                "namespace": namespace_names["impairment"],
                "interface": "imp-uplink0",
                "hook": "egress",
            },
            "ingress": {
                "namespace": namespace_names["impairment"],
                "interface": "imp-test0",
                "hook": "egress",
            },
        }
        ifb_required = False
        rendered_namespaces = namespace_names
        rendered_interfaces = {
            "test": {"namespace": namespace_names["test"], "name": "test0"},
            "impairmentTest": {
                "namespace": namespace_names["impairment"],
                "name": "imp-test0",
            },
            "impairmentUplink": {
                "namespace": namespace_names["impairment"],
                "name": "imp-uplink0",
            },
            "uplink": {"namespace": namespace_names["uplink"], "name": "uplink0"},
            "uplinkExternal": {
                "namespace": namespace_names["uplink"],
                "name": "pasta0",
            },
        }
        packet_path = {
            "outbound": [
                f"{namespace_names['test']}:test0",
                f"{namespace_names['impairment']}:imp-test0",
                f"{namespace_names['impairment']}:imp-uplink0",
                f"{namespace_names['uplink']}:uplink0",
                f"{namespace_names['uplink']}:pasta0",
                "authorized-target",
            ],
            "inbound": [
                "authorized-target",
                f"{namespace_names['uplink']}:pasta0",
                f"{namespace_names['uplink']}:uplink0",
                f"{namespace_names['impairment']}:imp-uplink0",
                f"{namespace_names['impairment']}:imp-test0",
                f"{namespace_names['test']}:test0",
            ],
        }
    else:
        if not request.dangerous_confirmation or not _CONFIRMATION_RE.fullmatch(
            request.dangerous_confirmation
        ):
            raise TopologyError(
                "dangerous host-network mode requires "
                "--dangerous-confirmation dedicated-test-vm:NAME"
            )
        if capabilities.execution_mode != "rootful":
            raise TopologyError("dangerous host-network mode requires rootful execution")
        if request.host_interface is None or not _INTERFACE_RE.fullmatch(
            request.host_interface
        ):
            raise TopologyError(
                "dangerous host-network mode requires a concrete --host-interface"
            )
        host_devices = {
            str(item.get("dev"))
            for item in snapshot.host_qdiscs
            if isinstance(item, dict) and item.get("dev") is not None
        }
        if request.host_interface not in host_devices:
            raise TopologyError(
                f"host interface {request.host_interface!r} is absent from "
                "the pre-mutation qdisc snapshot"
            )
        _require(
            capabilities,
            ("iproute2", "tc", "net_admin", "netem", "classifier"),
            context="dangerous host-network impairment",
        )
        if request.direction in {
            Direction.INGRESS,
            Direction.BIDIRECTIONAL,
            Direction.ASYMMETRIC,
        }:
            _require(capabilities, ("ifb",), context="host-network ingress shaping")
            if "ifb-sippycup" in host_devices:
                raise TopologyError(
                    "refusing to reuse existing host IFB interface ifb-sippycup"
                )
        if request.require_mtu:
            _require(capabilities, ("mtu",), context="MTU impairment")
        dangerous = True
        privilege_boundary = (
            "DANGEROUS: NET_ADMIN and qdisc mutation occur in the host network "
            f"namespace; operator confirmed {request.dangerous_confirmation}"
        )
        attachments = {
            "egress": {
                "namespace": "host",
                "interface": request.host_interface,
                "hook": "egress",
            },
            "ingress": {
                "namespace": "host",
                "interface": "ifb-sippycup",
                "hook": "egress-after-ingress-redirect",
            },
        }
        ifb_required = request.direction in {
            Direction.INGRESS,
            Direction.BIDIRECTIONAL,
            Direction.ASYMMETRIC,
        }
        rendered_namespaces = {}
        rendered_interfaces = {
            "hostUplink": {"namespace": "host", "name": request.host_interface},
            **(
                {"hostIngressIfb": {"namespace": "host", "name": "ifb-sippycup"}}
                if ifb_required
                else {}
            ),
        }
        packet_path = {
            "outbound": [f"host:{request.host_interface}", "authorized-target"],
            "inbound": [
                "authorized-target",
                f"host:{request.host_interface}",
                *(
                    ["host:ifb-sippycup"]
                    if ifb_required
                    else []
                ),
            ],
        }

    requested_directions = (
        ("egress",)
        if request.direction is Direction.EGRESS
        else ("ingress",)
        if request.direction is Direction.INGRESS
        else ("egress", "ingress")
    )
    selected_attachments = {
        name: attachments[name] for name in requested_directions
    }
    filters = [
        {
            "direction": direction,
            "family": f"ipv{network.version}",
            "network": str(network),
            "tcProtocol": "ip" if network.version == 4 else "ipv6",
            "match": (
                f"dst_ip {network}"
                if direction == "egress"
                else f"src_ip {network}"
            ),
        }
        for network in networks
        for direction in requested_directions
    ]
    target_document = [str(network) for network in networks]
    snapshot_document = snapshot.to_dict()
    return {
        "apiVersion": PLAN_VERSION,
        "kind": "ChaosTopologyPlan",
        "noChange": True,
        "dangerous": dangerous,
        "topology": request.topology.value,
        "direction": request.direction.value,
        "packetPath": packet_path,
        "namespaces": rendered_namespaces,
        "interfaces": rendered_interfaces,
        "attachments": selected_attachments,
        "ifbRequired": ifb_required,
        "targetFilters": filters,
        "targetScopeSha256": _hash(target_document),
        "capabilities": capabilities.to_dict(),
        "preMutationSnapshot": snapshot_document,
        "snapshotSha256": _hash(snapshot_document),
        "privilegeBoundary": privilege_boundary,
        "mutationCommands": [],
        "assumptions": [
            "the lifecycle executor must compare post-cleanup routes and qdiscs "
            "byte-for-byte with preMutationSnapshot",
            "the profile compiler may attach only to the listed attachment points",
            "target filters are frozen literal CIDRs and must not be widened",
        ],
    }
