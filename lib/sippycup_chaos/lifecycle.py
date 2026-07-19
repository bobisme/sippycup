"""Ownership-aware chaos lifecycle execution and packet-level measurement."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import statistics
import struct
import subprocess
import time
from typing import Any, Callable, Protocol, Sequence

from .profiles import (
    PLAN_API_VERSION,
    PLAN_KIND,
    PROFILE_API_VERSION,
    PROFILE_KIND,
    ProfileError,
    compile_profile,
)
from .topology import NetworkSnapshot, collect_network_snapshot


REPORT_API_VERSION = "sippycup.dev/chaos-run-report/v1"
REPORT_KIND = "ChaosRunReport"
MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_COMMAND_OUTPUT = 64 * 1024
MAX_OBSERVATION_BYTES = 512 * 1024 * 1024
MIN_DELAY_SAMPLES = 20
MIN_RATE_SAMPLES = 200
TERMINATE_GRACE_SECONDS = 2.0


class LifecycleError(RuntimeError):
    """The lifecycle could not proceed or prove safe cleanup."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""


class ChildProcess(Protocol):
    pid: int

    def poll(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int: ...


class Backend(Protocol):
    def run(self, argv: Sequence[str], *, timeout: float = 10.0) -> CommandResult: ...

    def read(self, argv: Sequence[str]) -> str: ...

    def popen(self, argv: Sequence[str]) -> ChildProcess: ...


class SubprocessBackend:
    """Bounded subprocess adapter; commands are always executed as argv arrays."""

    def run(self, argv: Sequence[str], *, timeout: float = 10.0) -> CommandResult:
        try:
            completed = subprocess.run(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise LifecycleError(f"command {argv[0]!r} failed to run: {error}") from error
        return CommandResult(
            completed.returncode,
            completed.stdout[:MAX_COMMAND_OUTPUT],
            completed.stderr[:MAX_COMMAND_OUTPUT],
        )

    def read(self, argv: Sequence[str]) -> str:
        result = self.run(argv)
        if result.returncode:
            detail = result.stderr.decode(errors="replace").strip()
            raise LifecycleError(
                f"read-only command {' '.join(argv)!r} failed"
                + (f": {detail}" if detail else "")
            )
        return result.stdout.decode()

    def popen(self, argv: Sequence[str]) -> ChildProcess:
        try:
            return subprocess.Popen(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as error:
            raise LifecycleError(f"cannot start traffic child: {error}") from error


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def load_json_document(path: str | Path, field: str) -> dict[str, Any]:
    document_path = Path(path)
    try:
        with document_path.open("rb") as source:
            raw = source.read(MAX_DOCUMENT_BYTES + 1)
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise LifecycleError(f"{field} exceeds 4 MiB")
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise LifecycleError(f"cannot load {field}: {error}") from error
    if not isinstance(value, dict):
        raise LifecycleError(f"{field} must be a JSON object")
    return value


def validate_impairment_plan(
    topology_plan: Any, impairment_plan: Any
) -> dict[str, Any]:
    """Recompile embedded settings and require byte-equivalent command intent."""

    if not isinstance(impairment_plan, dict):
        raise LifecycleError("impairment plan must be an object")
    profile = impairment_plan.get("profile")
    directions = impairment_plan.get("directions")
    if not isinstance(profile, dict) or not isinstance(directions, list):
        raise LifecycleError("impairment plan profile/directions are malformed")
    settings: dict[str, Any] = {}
    for index, item in enumerate(directions):
        if not isinstance(item, dict):
            raise LifecycleError(f"impairment direction {index} must be an object")
        direction = item.get("direction")
        if direction not in {"egress", "ingress"} or direction in settings:
            raise LifecycleError("impairment directions are invalid or duplicated")
        impairment = item.get("impairment")
        if not isinstance(impairment, dict):
            raise LifecycleError("impairment settings must be an object")
        settings[direction] = impairment
    try:
        source_sha256 = profile["sourceSha256"]
        embedded_profile = {
            "apiVersion": PROFILE_API_VERSION,
            "kind": PROFILE_KIND,
            "metadata": {"name": profile["name"]},
            "seed": profile["seed"],
            "durationSeconds": profile["durationSeconds"],
            "direction": profile["direction"],
            "directions": settings,
        }
        expected = compile_profile(
            topology_plan, embedded_profile, source_sha256=source_sha256
        )
    except (KeyError, ProfileError) as error:
        raise LifecycleError(f"invalid impairment plan: {error}") from error
    actual_owner = impairment_plan.get("owner")
    owner_prefix = f"sippycup-{_sha256(topology_plan)[:8]}-"
    if (
        not isinstance(actual_owner, str)
        or not re.fullmatch(r"sippycup-[0-9a-f]{8}-[0-9a-f]{8}", actual_owner)
        or not actual_owner.startswith(owner_prefix)
    ):
        raise LifecycleError("impairment owner does not bind to the topology plan")
    # The compiler intentionally omits free-form metadata.description from the
    # public plan while including it in the opaque owner suffix.  Rebind only
    # that opaque suffix; every command and ownership sub-tag remains exact.
    expected_owner = expected["owner"]
    expected["owner"] = actual_owner
    for command in expected["commands"]:
        owns = command["owns"]
        if not owns.startswith(expected_owner):
            raise LifecycleError("recompiled command ownership is inconsistent")
        command["owns"] = actual_owner + owns[len(expected_owner) :]
    if _canonical(expected) != _canonical(impairment_plan):
        raise LifecycleError(
            "impairment plan differs from deterministic recompilation; "
            "refusing injected or modified commands"
        )
    if expected["apiVersion"] != PLAN_API_VERSION or expected["kind"] != PLAN_KIND:
        raise LifecycleError("impairment plan contract is unsupported")
    return expected


def _snapshot_dict(snapshot: NetworkSnapshot | dict[str, Any]) -> dict[str, Any]:
    return snapshot.to_dict() if isinstance(snapshot, NetworkSnapshot) else snapshot


@dataclass(slots=True)
class _NamespaceOwner:
    name: str
    marker: str
    sealed: bool = False
    exposed_to_child: bool = False


class ChaosLifecycle:
    """Apply a frozen plan, own traffic, and prove exact restoration."""

    def __init__(
        self,
        topology_plan: dict[str, Any],
        impairment_plan: dict[str, Any],
        *,
        backend: Backend | None = None,
        snapshotter: Callable[[Sequence[str]], NetworkSnapshot | dict[str, Any]]
        | None = None,
        namespace_path_validator: Callable[[str], str] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.topology = topology_plan
        self.plan = validate_impairment_plan(topology_plan, impairment_plan)
        self.backend = backend or SubprocessBackend()
        self.snapshotter = snapshotter or (
            lambda names: collect_network_snapshot(names, reader=self.backend.read)
        )
        self.namespace_path_validator = (
            namespace_path_validator or self._validate_namespace_path
        )
        self.clock = clock
        self._cancel_signal: int | None = None
        self._child: ChildProcess | None = None
        self._infrastructure: list[ChildProcess] = []
        self._cleanups: list[tuple[str, Callable[[], None]]] = []
        self._cleanup_started = False
        self._events: list[dict[str, Any]] = []
        self._owners: dict[str, _NamespaceOwner] = {}
        self._traffic_stopped_at: float | None = None
        self._topology_cleanup_started_at: float | None = None
        self._has_run = False

    def cancel(self, signum: int = signal.SIGINT) -> None:
        if self._cancel_signal is None:
            self._cancel_signal = signum

    def _event(self, event: str, **details: Any) -> None:
        self._events.append(
            {"sequence": len(self._events) + 1, "event": event, **details}
        )

    def _run_checked(self, argv: Sequence[str], operation: str) -> None:
        if self._cancel_signal is not None and not self._cleanup_started:
            raise LifecycleError(
                f"cancelled before {operation}: "
                f"{signal.Signals(self._cancel_signal).name}"
            )
        result = self.backend.run(argv)
        if result.returncode:
            detail = result.stderr.decode(errors="replace").strip()
            raise LifecycleError(
                f"{operation} failed with status {result.returncode}"
                + (f": {detail}" if detail else "")
            )
        self._event("object.applied", operation=operation, argv=list(argv))

    def _register(self, name: str, cleanup: Callable[[], None]) -> None:
        if self._cleanup_started:
            raise LifecycleError("cannot register cleanup after cleanup begins")
        self._cleanups.append((name, cleanup))

    def _namespace_names(self) -> tuple[str, ...]:
        frozen = self.topology.get("preMutationSnapshot")
        if not isinstance(frozen, dict):
            return ()
        snapshots = frozen.get("namespaces")
        if not isinstance(snapshots, list):
            return ()
        names = tuple(
            item.get("name")
            for item in snapshots
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        )
        planned = self.topology.get("namespaces")
        if isinstance(planned, dict) and set(names) != set(planned.values()):
            raise LifecycleError(
                "frozen namespace snapshot does not match planned namespaces"
            )
        return names

    def _verify_preflight(self) -> None:
        observed = _snapshot_dict(self.snapshotter(self._namespace_names()))
        frozen = self.topology["preMutationSnapshot"]
        if _canonical(observed) != _canonical(frozen):
            raise LifecycleError(
                "live routes/qdiscs/namespaces differ from the frozen pre-run snapshot"
            )
        self._event("snapshot.preflight_verified", sha256=_sha256(observed))

    def _namespace_marker(self, name: str) -> str:
        digest = hashlib.sha256(f"{self.plan['owner']}:{name}".encode()).hexdigest()
        return f"scown{digest[:8]}"

    @staticmethod
    def _validate_namespace_path(name: str) -> str:
        path = f"/run/netns/{name}"
        try:
            metadata = os.lstat(path)
        except OSError as error:
            raise LifecycleError(
                f"owned namespace path {path!r} is unavailable: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise LifecycleError(
                f"owned namespace path {path!r} is not a regular bind-mount file"
            )
        return path

    def _namespace_prefix(self, name: str) -> list[str]:
        path = self.namespace_path_validator(name)
        if path != f"/run/netns/{name}":
            raise LifecycleError("namespace path validator returned a non-canonical path")
        return ["nsenter", f"--net={path}"]

    def _owned_namespace_prefix(self, name: str) -> list[str]:
        owner = self._owners.get(name)
        if owner is None or not owner.sealed:
            raise LifecycleError(f"namespace {name!r} is not frozen owned state")
        prefix = self._namespace_prefix(name)
        result = self.backend.run(
            [*prefix, "ip", "-json", "link", "show", "dev", owner.marker]
        )
        if result.returncode:
            raise LifecycleError(
                f"owned namespace marker is missing before entering {name}"
            )
        try:
            links = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise LifecycleError(
                f"owned namespace marker query is malformed for {name}"
            ) from error
        if (
            not isinstance(links, list)
            or len(links) != 1
            or links[0].get("ifalias") != self.plan["owner"]
        ):
            raise LifecycleError(
                f"owned namespace marker changed before entering {name}"
            )
        return prefix

    def _create_namespace(self, name: str) -> None:
        self._run_checked(["ip", "netns", "add", name], f"create namespace {name}")
        owner = _NamespaceOwner(name, self._namespace_marker(name))
        self._owners[name] = owner

        def cleanup() -> None:
            if owner.exposed_to_child:
                prefix = self._namespace_prefix(name)
                result = self.backend.run(
                    [*prefix, "ip", "-json", "link", "show", "dev", owner.marker]
                )
                if result.returncode:
                    raise LifecycleError(
                        f"refusing to delete namespace {name}: ownership marker missing"
                    )
                try:
                    links = json.loads(result.stdout)
                except json.JSONDecodeError as error:
                    raise LifecycleError(
                        f"refusing to delete namespace {name}: invalid marker query"
                    ) from error
                if (
                    not isinstance(links, list)
                    or len(links) != 1
                    or links[0].get("ifalias") != self.plan["owner"]
                ):
                    raise LifecycleError(
                        f"refusing to delete namespace {name}: ownership changed"
                    )
            result = self.backend.run(["ip", "netns", "del", name])
            if result.returncode:
                # Absence is idempotent; anything still listed is a hard failure.
                listed = self.backend.read(["ip", "netns", "list"])
                if name in {line.split()[0] for line in listed.splitlines() if line}:
                    raise LifecycleError(f"cannot delete owned namespace {name}")

        self._register(f"namespace:{name}", cleanup)
        self._run_checked(
            [
                *self._namespace_prefix(name),
                "ip",
                "link",
                "add",
                owner.marker,
                "type",
                "dummy",
            ],
            f"create ownership marker in {name}",
        )
        self._run_checked(
            [
                *self._namespace_prefix(name),
                "ip",
                "link",
                "set",
                "dev",
                owner.marker,
                "alias",
                self.plan["owner"],
            ],
            f"tag namespace {name}",
        )
        owner.sealed = True

    def _tag_link(self, namespace: str, interface: str) -> None:
        self._run_checked(
            [
                *self._owned_namespace_prefix(namespace),
                "ip",
                "link",
                "set",
                "dev",
                interface,
                "alias",
                self.plan["owner"],
            ],
            f"tag link {namespace}:{interface}",
        )

    def _create_veth_pair(
        self,
        left_name: str,
        left_namespace: str,
        right_name: str,
        right_namespace: str,
    ) -> None:
        self._run_checked(
            [
                "ip",
                "link",
                "add",
                left_name,
                "type",
                "veth",
                "peer",
                "name",
                right_name,
            ],
            f"create {left_name}/{right_name} veth",
        )
        locations = {left_name: "host", right_name: "host"}
        sealed = {"value": False}

        def cleanup() -> None:
            for interface in (left_name, right_name):
                namespace = locations[interface]
                prefix = (
                    []
                    if namespace == "host"
                    else self._owned_namespace_prefix(namespace)
                )
                query = self.backend.run(
                    [*prefix, "ip", "-json", "link", "show", "dev", interface]
                    if prefix
                    else ["ip", "-json", "link", "show", "dev", interface]
                )
                if query.returncode:
                    continue
                if sealed["value"]:
                    try:
                        links = json.loads(query.stdout)
                    except json.JSONDecodeError as error:
                        raise LifecycleError(
                            f"veth ownership query for {interface} is malformed"
                        ) from error
                    if (
                        not isinstance(links, list)
                        or len(links) != 1
                        or links[0].get("ifalias") != self.plan["owner"]
                    ):
                        raise LifecycleError(
                            f"refusing to delete veth {interface}: ownership changed"
                        )
                result = self.backend.run(
                    [*prefix, "ip", "link", "del", "dev", interface]
                    if prefix
                    else ["ip", "link", "del", "dev", interface]
                )
                if result.returncode:
                    raise LifecycleError(f"cannot delete owned veth {interface}")
                return

        self._register(f"veth:{left_name}:{right_name}", cleanup)
        for interface in (left_name, right_name):
            self._run_checked(
                [
                    "ip",
                    "link",
                    "set",
                    "dev",
                    interface,
                    "alias",
                    self.plan["owner"],
                ],
                f"tag veth {interface}",
            )
        sealed["value"] = True
        self._run_checked(
            ["ip", "link", "set", left_name, "netns", left_namespace],
            f"move {left_name}",
        )
        locations[left_name] = left_namespace
        self._run_checked(
            ["ip", "link", "set", right_name, "netns", right_namespace],
            f"move {right_name}",
        )
        locations[right_name] = right_namespace

    def _apply_disposable_topology(self) -> None:
        namespaces = self.topology["namespaces"]
        test = namespaces["test"]
        impairment = namespaces["impairment"]
        uplink = namespaces["uplink"]
        for name in (test, impairment, uplink):
            self._create_namespace(name)

        self._create_veth_pair("test0", test, "imp-test0", impairment)
        self._create_veth_pair(
            "imp-uplink0", impairment, "uplink0", uplink
        )

        address_commands = (
            (test, "test0", "198.18.0.1/30"),
            (impairment, "imp-test0", "198.18.0.2/30"),
            (impairment, "imp-uplink0", "198.18.0.5/30"),
            (uplink, "uplink0", "198.18.0.6/30"),
        )
        for namespace, interface, address in address_commands:
            prefix = self._owned_namespace_prefix(namespace)
            self._run_checked(
                [*prefix, "ip", "addr", "add", address, "dev", interface],
                f"address {namespace}:{interface}",
            )
            self._run_checked(
                [*prefix, "ip", "link", "set", "dev", interface, "up"],
                f"raise {namespace}:{interface}",
            )
        ipv6_address_commands = (
            (test, "test0", "fd42:7369:7070:1::1/64"),
            (impairment, "imp-test0", "fd42:7369:7070:1::2/64"),
            (impairment, "imp-uplink0", "fd42:7369:7070:2::1/64"),
            (uplink, "uplink0", "fd42:7369:7070:2::2/64"),
        )
        for namespace, interface, address in ipv6_address_commands:
            self._run_checked(
                [
                    *self._owned_namespace_prefix(namespace),
                    "ip",
                    "-6",
                    "addr",
                    "add",
                    address,
                    "dev",
                    interface,
                ],
                f"IPv6 address {namespace}:{interface}",
            )
        for namespace in (test, impairment, uplink):
            self._run_checked(
                [
                    *self._owned_namespace_prefix(namespace),
                    "ip",
                    "link",
                    "set",
                    "dev",
                    "lo",
                    "up",
                ],
                f"raise {namespace}:lo",
            )
        self._run_checked(
            [
                *self._owned_namespace_prefix(impairment),
                "unshare",
                "--mount",
                "--propagation",
                "private",
                "--mount-proc",
                "sysctl",
                "-q",
                "-w",
                "net.ipv4.ip_forward=1",
            ],
            "enable disposable IPv4 forwarding",
        )
        self._run_checked(
            [
                *self._owned_namespace_prefix(impairment),
                "unshare",
                "--mount",
                "--propagation",
                "private",
                "--mount-proc",
                "sysctl",
                "-q",
                "-w",
                "net.ipv6.conf.all.forwarding=1",
            ],
            "enable disposable IPv6 forwarding",
        )
        self._run_checked(
            [
                *self._owned_namespace_prefix(test),
                "ip",
                "route",
                "add",
                "default",
                "via",
                "198.18.0.2",
            ],
            "route test through impairment",
        )
        self._run_checked(
            [
                *self._owned_namespace_prefix(uplink),
                "ip",
                "route",
                "add",
                "198.18.0.0/30",
                "via",
                "198.18.0.5",
            ],
            "route uplink return path",
        )
        self._run_checked(
            [
                *self._owned_namespace_prefix(test),
                "ip",
                "-6",
                "route",
                "add",
                "default",
                "via",
                "fd42:7369:7070:1::2",
            ],
            "route IPv6 test through impairment",
        )
        self._run_checked(
            [
                *self._owned_namespace_prefix(uplink),
                "ip",
                "-6",
                "route",
                "add",
                "fd42:7369:7070:1::/64",
                "via",
                "fd42:7369:7070:2::1",
            ],
            "route IPv6 uplink return path",
        )
        self._start_disposable_uplink(uplink)

    def _stop_process(self, process: ChildProcess, label: str) -> None:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=TERMINATE_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=TERMINATE_GRACE_SECONDS)
        else:
            process.wait()
        self._event("infrastructure.stopped", process=label, pid=process.pid)

    def _start_disposable_uplink(self, namespace: str) -> None:
        if self._cancel_signal is not None:
            raise LifecycleError("cancelled before disposable uplink start")
        self._owned_namespace_prefix(namespace)
        argv = [
            "pasta",
            "--quiet",
            "--foreground",
            "--config-net",
            "--netns",
            namespace,
            "--ns-ifname",
            "pasta0",
            "--tcp-ports",
            "none",
            "--udp-ports",
            "none",
        ]
        process = self.backend.popen(argv)
        self._infrastructure.append(process)

        def cleanup() -> None:
            self._stop_process(process, "pasta")
            if process in self._infrastructure:
                self._infrastructure.remove(process)

        self._register("infrastructure:pasta", cleanup)
        self._event("infrastructure.started", process="pasta", pid=process.pid)
        ready = False
        for _attempt in range(100):
            if process.poll() is not None:
                raise LifecycleError(
                    f"pasta exited during startup with status {process.poll()}"
                )
            result = self.backend.run(
                [
                    *self._owned_namespace_prefix(namespace),
                    "ip",
                    "-json",
                    "link",
                    "show",
                    "dev",
                    "pasta0",
                ]
            )
            if result.returncode == 0:
                ready = True
                break
            time.sleep(0.01)
        if not ready:
            raise LifecycleError("pasta did not create pasta0 before the startup deadline")
        self._tag_link(namespace, "pasta0")
        self._event("infrastructure.ready", process="pasta")

    def _qdisc_owned(self, namespace: str, interface: str) -> bool:
        prefix = (
            []
            if namespace == "host"
            else self._owned_namespace_prefix(namespace)
        )
        result = self.backend.run(
            [*prefix, "tc", "-json", "qdisc", "show", "dev", interface]
        )
        if result.returncode:
            return False
        try:
            qdiscs = json.loads(result.stdout)
        except json.JSONDecodeError:
            return False
        return any(
            isinstance(item, dict)
            and item.get("handle") == "1:"
            and item.get("kind") == "prio"
            for item in qdiscs
        )

    def _apply_dangerous_ingress(self) -> None:
        if not self.topology.get("ifbRequired"):
            return
        interface = self.topology["interfaces"]["hostUplink"]["name"]
        ifb = "ifb-sippycup"
        self._run_checked(
            ["ip", "link", "add", ifb, "type", "ifb"], "create host ingress IFB"
        )
        ifb_sealed = {"value": False}

        def cleanup_ifb() -> None:
            if ifb_sealed["value"]:
                result = self.backend.run(
                    ["ip", "-json", "link", "show", "dev", ifb]
                )
                if result.returncode:
                    return
                try:
                    links = json.loads(result.stdout)
                except json.JSONDecodeError as error:
                    raise LifecycleError(
                        "host IFB ownership query is malformed"
                    ) from error
                if (
                    not isinstance(links, list)
                    or len(links) != 1
                    or links[0].get("ifalias") != self.plan["owner"]
                ):
                    raise LifecycleError(
                        "refusing to delete host IFB: ownership changed"
                    )
            if self.backend.run(["ip", "link", "del", ifb]).returncode:
                raise LifecycleError("cannot delete owned host IFB")

        self._register("host-ifb", cleanup_ifb)
        self._run_checked(
            ["ip", "link", "set", "dev", ifb, "alias", self.plan["owner"]],
            "tag host ingress IFB",
        )
        ifb_sealed["value"] = True
        self._run_checked(
            ["ip", "link", "set", "dev", ifb, "up"], "raise host ingress IFB"
        )
        self._run_checked(
            ["tc", "qdisc", "add", "dev", interface, "clsact"],
            "create scoped host ingress hook",
        )

        def cleanup_clsact() -> None:
            result = self.backend.run(
                ["tc", "-json", "qdisc", "show", "dev", interface]
            )
            if result.returncode:
                raise LifecycleError("cannot verify owned host clsact")
            try:
                qdiscs = json.loads(result.stdout)
            except json.JSONDecodeError as error:
                raise LifecycleError("host clsact ownership query is malformed") from error
            if not any(
                isinstance(item, dict)
                and item.get("kind") == "clsact"
                and item.get("handle") == "ffff:"
                for item in qdiscs
            ):
                raise LifecycleError("refusing host clsact cleanup: ownership changed")
            if self.backend.run(
                ["tc", "qdisc", "del", "dev", interface, "clsact"]
            ).returncode:
                raise LifecycleError("cannot delete owned host clsact")

        self._register("host-clsact", cleanup_clsact)
        filters = [
            item
            for item in self.topology["targetFilters"]
            if item["direction"] == "ingress"
        ]
        for index, target in enumerate(filters):
            selector, network = target["match"].split(" ", 1)
            self._run_checked(
                [
                    "tc",
                    "filter",
                    "add",
                    "dev",
                    interface,
                    "ingress",
                    "protocol",
                    target["tcProtocol"],
                    "prio",
                    str(50 + index),
                    "flower",
                    selector,
                    network,
                    "action",
                    "mirred",
                    "egress",
                    "redirect",
                    "dev",
                    ifb,
                ],
                f"redirect authorized host ingress target {index + 1}",
            )

    def _register_host_qdisc_cleanup(self, command: dict[str, Any]) -> None:
        namespace = command["namespace"]
        direction = command["direction"]
        attachment = next(
            item["attachment"]
            for item in self.plan["directions"]
            if item["direction"] == direction
        )
        interface = attachment["interface"]

        def cleanup() -> None:
            if not self._qdisc_owned(namespace, interface):
                raise LifecycleError(
                    f"refusing qdisc cleanup on {interface}: owned handle is absent"
                )
            prefix = (
                []
                if namespace == "host"
                else self._owned_namespace_prefix(namespace)
            )
            result = self.backend.run(
                [*prefix, "tc", "qdisc", "del", "dev", interface, "root", "handle", "1:"]
            )
            if result.returncode:
                raise LifecycleError(f"cannot delete owned qdisc on {interface}")

        self._register(f"qdisc:{direction}", cleanup)

    def _apply_impairment(self) -> None:
        for command in self.plan["commands"]:
            if command["namespace"] != "host":
                self._owned_namespace_prefix(command["namespace"])
            self._run_checked(command["argv"], f"apply {command['id']}")
            if command["id"].endswith("-root"):
                self._register_host_qdisc_cleanup(command)

    def _stop_child(self) -> None:
        child = self._child
        if child is None:
            return
        if child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=TERMINATE_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=TERMINATE_GRACE_SECONDS)
        else:
            child.wait()
        self._traffic_stopped_at = self.clock()
        self._event("traffic.stopped", returncode=child.poll())
        self._child = None

    def _cleanup(self) -> list[str]:
        if self._cleanup_started:
            return []
        self._cleanup_started = True
        self._stop_child()
        self._topology_cleanup_started_at = self.clock()
        self._event("topology.cleanup_started")
        failures: list[str] = []
        while self._cleanups:
            name, cleanup = self._cleanups.pop()
            last_error: Exception | None = None
            for attempt in range(1, 4):
                try:
                    cleanup()
                    self._event(
                        "object.cleaned", operation=name, attempts=attempt
                    )
                    last_error = None
                    break
                except Exception as error:
                    last_error = error
                    self._event(
                        "object.cleanup_retry",
                        operation=name,
                        attempt=attempt,
                        error=str(error),
                    )
            if last_error is not None:  # cleanup continues after every failure
                failures.append(f"{name}: {last_error}")
                self._event(
                    "object.cleanup_failed", operation=name, error=str(last_error)
                )
        return failures

    def _post_cleanup_verified(self) -> tuple[bool, str]:
        try:
            observed = _snapshot_dict(self.snapshotter(self._namespace_names()))
        except Exception as error:
            return False, f"cannot collect post-cleanup snapshot: {error}"
        frozen = self.topology["preMutationSnapshot"]
        if _canonical(observed) != _canonical(frozen):
            return False, "post-cleanup routes/qdiscs/namespaces differ from pre-run"
        return True, _sha256(observed)

    def run(
        self,
        command: Sequence[str],
        *,
        observations: dict[str, tuple[Path, Path]] | None = None,
    ) -> dict[str, Any]:
        if self._has_run:
            raise LifecycleError(
                "a lifecycle instance is single-use; create a new instance "
                "to prove a fresh preflight snapshot"
            )
        self._has_run = True
        if not command or not all(isinstance(item, str) and item for item in command):
            raise LifecycleError("traffic command must be a non-empty argv array")
        state = "failed"
        exit_code = 1
        error: str | None = None
        self._event("lifecycle.started", owner=self.plan["owner"])
        try:
            self._verify_preflight()
            if self.topology["topology"] == "disposable-router":
                self._apply_disposable_topology()
            else:
                self._apply_dangerous_ingress()
            self._apply_impairment()
            for owner in self._owners.values():
                if not owner.sealed:
                    raise LifecycleError("namespace ownership marker was not sealed")
                owner.exposed_to_child = True
            child_argv = list(command)
            if self.topology["topology"] == "disposable-router":
                child_argv = [
                    *self._owned_namespace_prefix(
                        self.topology["namespaces"]["test"]
                    ),
                    "setpriv",
                    "--no-new-privs",
                    "--bounding-set=-net_admin,-sys_admin",
                    "--inh-caps=-all",
                    "--ambient-caps=-all",
                    "--pdeathsig",
                    "SIGKILL",
                    *child_argv,
                ]
            if self._cancel_signal is not None:
                raise LifecycleError(
                    f"cancelled before traffic start: "
                    f"{signal.Signals(self._cancel_signal).name}"
                )
            self._child = self.backend.popen(child_argv)
            self._event("traffic.started", pid=self._child.pid, argv=child_argv)
            deadline = self.clock() + self.plan["profile"]["durationSeconds"]
            while True:
                returncode = self._child.poll()
                if returncode is not None:
                    self._stop_child()
                    if returncode == 0:
                        state, exit_code = "succeeded", 0
                    else:
                        state, exit_code = "child_failed", 1
                        error = f"traffic child exited with status {returncode}"
                    break
                if self._cancel_signal is not None:
                    self._stop_child()
                    state = "cancelled"
                    exit_code = 130 if self._cancel_signal == signal.SIGINT else 143
                    error = signal.Signals(self._cancel_signal).name
                    break
                if self.clock() >= deadline:
                    self._stop_child()
                    state, exit_code = "timed_out", 124
                    error = "profile duration elapsed"
                    break
                time.sleep(0.01)
        except BaseException as caught:
            error = str(caught)
            if self._cancel_signal is not None:
                state = "cancelled"
                exit_code = 130 if self._cancel_signal == signal.SIGINT else 143
                self._event("lifecycle.cancelled", error=error)
            else:
                self._event("lifecycle.failed", error=error)
        cleanup_failures = self._cleanup()
        restored, restore_detail = self._post_cleanup_verified()
        if cleanup_failures or not restored:
            state, exit_code = "cleanup_failed", 1
            details = cleanup_failures + ([] if restored else [restore_detail])
            error = "; ".join(details)
        measurement = measure_observations(
            self.plan, observations or {}
        )
        self._event("lifecycle.finished", state=state, restored=restored)
        traffic_before_teardown = (
            self._traffic_stopped_at is None
            or self._topology_cleanup_started_at is None
            or self._traffic_stopped_at <= self._topology_cleanup_started_at
        )
        return {
            "apiVersion": REPORT_API_VERSION,
            "kind": REPORT_KIND,
            "owner": self.plan["owner"],
            "state": state,
            "exitCode": exit_code,
            "error": error,
            "cleanup": {
                "restored": restored,
                "snapshotSha256": restore_detail if restored else None,
                "failures": cleanup_failures,
                "trafficStoppedBeforeTopologyTeardown": traffic_before_teardown,
            },
            "measurement": measurement,
            "events": self._events,
        }


@dataclass(frozen=True, slots=True)
class _Packet:
    time_seconds: float
    key: tuple[int, int, int, int, str]


def _pcap_packets(path: Path) -> list[_Packet]:
    try:
        with path.open("rb") as source:
            data = source.read(MAX_OBSERVATION_BYTES + 1)
    except OSError as error:
        raise LifecycleError(f"cannot read observation {path}: {error}") from error
    if len(data) > MAX_OBSERVATION_BYTES:
        raise LifecycleError(f"observation {path} exceeds 512 MiB")
    if len(data) < 24:
        raise LifecycleError(f"observation {path} is not a classic PCAP")
    magic = data[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if magic not in formats:
        raise LifecycleError(f"observation {path} has unsupported PCAP magic")
    endian, fraction = formats[magic]
    _, _, _, _, _, _, linktype = struct.unpack_from(f"{endian}IHHIIII", data, 0)
    offset = 24
    packets: list[_Packet] = []
    while offset < len(data):
        if len(data) - offset < 16:
            raise LifecycleError(f"observation {path} has a truncated record header")
        seconds, subseconds, captured, original = struct.unpack_from(
            f"{endian}IIII", data, offset
        )
        offset += 16
        if captured > original or captured > len(data) - offset:
            raise LifecycleError(f"observation {path} has an invalid record length")
        frame = data[offset : offset + captured]
        offset += captured
        rtp = _rtp_identity(frame, linktype)
        if rtp is not None:
            packets.append(_Packet(seconds + subseconds / fraction, rtp))
    return packets


def _rtp_identity(frame: bytes, linktype: int) -> tuple[int, int, int, int, str] | None:
    if linktype == 1:
        if len(frame) < 14:
            return None
        ether_type = int.from_bytes(frame[12:14], "big")
        offset = 14
        while ether_type in {0x8100, 0x88A8}:
            if len(frame) < offset + 4:
                return None
            ether_type = int.from_bytes(frame[offset + 2 : offset + 4], "big")
            offset += 4
    elif linktype == 101:
        if not frame:
            return None
        ether_type = 0x0800 if frame[0] >> 4 == 4 else 0x86DD
        offset = 0
    else:
        raise LifecycleError(f"unsupported PCAP link type {linktype}")
    if ether_type == 0x0800:
        if len(frame) < offset + 20:
            return None
        ihl = (frame[offset] & 0x0F) * 4
        if ihl < 20 or len(frame) < offset + ihl or frame[offset + 9] != 17:
            return None
        offset += ihl
    elif ether_type == 0x86DD:
        if len(frame) < offset + 40 or frame[offset + 6] != 17:
            return None
        offset += 40
    else:
        return None
    if len(frame) < offset + 8:
        return None
    udp_length = int.from_bytes(frame[offset + 4 : offset + 6], "big")
    if udp_length < 20 or len(frame) < offset + udp_length:
        return None
    payload = frame[offset + 8 : offset + udp_length]
    if len(payload) < 12 or payload[0] >> 6 != 2:
        return None
    csrc_count = payload[0] & 0x0F
    header_length = 12 + csrc_count * 4
    if payload[0] & 0x10:
        if len(payload) < header_length + 4:
            return None
        extension_words = int.from_bytes(
            payload[header_length + 2 : header_length + 4], "big"
        )
        header_length += 4 + extension_words * 4
    if len(payload) < header_length:
        return None
    sequence = int.from_bytes(payload[2:4], "big")
    timestamp = int.from_bytes(payload[4:8], "big")
    ssrc = int.from_bytes(payload[8:12], "big")
    payload_type = payload[1] & 0x7F
    digest = hashlib.sha256(payload[header_length:]).hexdigest()
    return ssrc, sequence, timestamp, payload_type, digest


def _requested_loss(loss: dict[str, Any] | None) -> float:
    if loss is None:
        return 0.0
    if loss["model"] == "random":
        return float(loss["percent"])
    start = float(loss["startPercent"]) / 100.0
    recovery = float(loss["recoveryPercent"]) / 100.0
    bad = float(loss["badLossPercent"])
    good = float(loss["goodLossPercent"])
    stationary_bad = start / (start + recovery)
    return stationary_bad * bad + (1.0 - stationary_bad) * good


def _metric(
    requested: float,
    observed: float | None,
    samples: int,
    minimum_samples: int,
    tolerance: float,
    unit: str,
) -> dict[str, Any]:
    sufficient = samples >= minimum_samples
    return {
        "requested": requested,
        "observed": observed,
        "unit": unit,
        "samples": samples,
        "minimumSamples": minimum_samples,
        "tolerance": tolerance,
        "sufficientSamples": sufficient,
        "withinTolerance": (
            None
            if not sufficient or observed is None
            else abs(observed - requested) <= tolerance
        ),
    }


def _measure_pair(
    impairment: dict[str, Any], before: Path, after: Path
) -> dict[str, Any]:
    sent = _pcap_packets(before)
    received = _pcap_packets(after)
    sent_by_key: dict[tuple[int, int, int, int, str], deque[tuple[int, float]]] = (
        defaultdict(deque)
    )
    for index, packet in enumerate(sent):
        sent_by_key[packet.key].append((index, packet.time_seconds))
    delays_ms: list[float] = []
    received_indexes: list[int] = []
    duplicates = 0
    matched = 0
    for packet in received:
        queue = sent_by_key.get(packet.key)
        if queue:
            send_index, sent_at = queue.popleft()
            delay = (packet.time_seconds - sent_at) * 1000.0
            if delay < 0:
                raise LifecycleError(
                    "paired RTP packet has a negative capture delay; "
                    "observations must share one clock"
                )
            delays_ms.append(delay)
            received_indexes.append(send_index)
            matched += 1
        else:
            duplicates += 1
    lost = max(len(sent) - matched, 0)
    reordered = 0
    high_water = -1
    for index in received_indexes:
        if index < high_water:
            reordered += 1
        else:
            high_water = index
    denominator = len(sent)
    loss_percent = lost * 100.0 / denominator if denominator else None
    duplicate_percent = duplicates * 100.0 / denominator if denominator else None
    reorder_percent = reordered * 100.0 / denominator if denominator else None
    mean_delay = statistics.fmean(delays_ms) if delays_ms else None
    jitter = statistics.pstdev(delays_ms) if len(delays_ms) >= 2 else None
    delay = impairment.get("delay", {})
    requested_delay = float(delay.get("milliseconds", 0))
    requested_jitter = float(delay.get("jitterMilliseconds", 0))
    requested_duplicate = float(impairment.get("duplicate", {}).get("percent", 0))
    requested_reorder = float(impairment.get("reorder", {}).get("percent", 0))
    requested_loss = _requested_loss(impairment.get("loss"))
    return {
        "packetCounts": {
            "before": len(sent),
            "after": len(received),
            "matched": matched,
            "lost": lost,
            "duplicates": duplicates,
            "reordered": reordered,
        },
        "delay": _metric(
            requested_delay,
            mean_delay,
            len(delays_ms),
            MIN_DELAY_SAMPLES,
            max(5.0, requested_delay * 0.15),
            "milliseconds",
        ),
        "jitter": _metric(
            requested_jitter,
            jitter,
            len(delays_ms),
            MIN_DELAY_SAMPLES,
            max(5.0, requested_jitter * 0.35),
            "milliseconds",
        ),
        "loss": _metric(
            requested_loss,
            loss_percent,
            denominator,
            MIN_RATE_SAMPLES,
            max(2.0, requested_loss * 0.5),
            "percent",
        ),
        "reorder": _metric(
            requested_reorder,
            reorder_percent,
            denominator,
            MIN_RATE_SAMPLES,
            max(2.0, requested_reorder * 0.5),
            "percent",
        ),
        "duplicate": _metric(
            requested_duplicate,
            duplicate_percent,
            denominator,
            MIN_RATE_SAMPLES,
            max(2.0, requested_duplicate * 0.5),
            "percent",
        ),
    }


def measure_observations(
    plan: dict[str, Any],
    observations: dict[str, tuple[Path, Path]],
) -> dict[str, Any]:
    rendered: list[dict[str, Any]] = []
    for item in plan["directions"]:
        direction = item["direction"]
        paths = observations.get(direction)
        if paths is None:
            rendered.append(
                {
                    "direction": direction,
                    "status": "insufficient_samples",
                    "reason": "paired before/after PCAP observations were not supplied",
                    "metrics": None,
                }
            )
            continue
        try:
            metrics = _measure_pair(item["impairment"], paths[0], paths[1])
        except LifecycleError as error:
            rendered.append(
                {
                    "direction": direction,
                    "status": "invalid_observation",
                    "reason": str(error),
                    "metrics": None,
                }
            )
            continue
        values = [
            metric
            for name, metric in metrics.items()
            if name != "packetCounts"
        ]
        if any(not metric["sufficientSamples"] for metric in values):
            status = "insufficient_samples"
        elif any(metric["withinTolerance"] is False for metric in values):
            status = "outside_tolerance"
        else:
            status = "within_tolerance"
        rendered.append(
            {
                "direction": direction,
                "status": status,
                "reason": None,
                "metrics": metrics,
            }
        )
    return {
        "method": "paired classic-PCAP RTP identity and capture timestamps",
        "directions": rendered,
        "allWithinTolerance": bool(rendered)
        and all(item["status"] == "within_tolerance" for item in rendered),
    }
