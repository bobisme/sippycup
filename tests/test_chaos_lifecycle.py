from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import struct
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_chaos.lifecycle import (  # noqa: E402
    ChaosLifecycle,
    CommandResult,
    LifecycleError,
    measure_observations,
    validate_impairment_plan,
)
from sippycup_chaos.cli import main as chaos_main  # noqa: E402
from sippycup_chaos.profiles import compile_profile, load_profile  # noqa: E402
from sippycup_chaos.topology import (  # noqa: E402
    CapabilitySnapshot,
    Direction,
    FeatureState,
    NetworkSnapshot,
    NamespaceSnapshot,
    TopologyRequest,
    plan_topology,
)


PROFILE_ROOT = ROOT / "profiles" / "chaos"


def _capabilities() -> CapabilitySnapshot:
    return CapabilitySnapshot(
        execution_mode="rootless",
        podman=FeatureState.AVAILABLE,
        iproute2=FeatureState.AVAILABLE,
        tc=FeatureState.AVAILABLE,
        net_admin=FeatureState.AVAILABLE,
        netem=FeatureState.AVAILABLE,
        ifb=FeatureState.UNAVAILABLE,
        classifier=FeatureState.AVAILABLE,
        mtu=FeatureState.AVAILABLE,
        evidence={"fixture": "read-only"},
        sys_admin=FeatureState.AVAILABLE,
        pasta=FeatureState.AVAILABLE,
    )


def _plans(profile_name: str = "fixed-delay") -> tuple[dict, dict]:
    prefix = "lifelab"
    frozen = NetworkSnapshot(
        host_routes=[{"dst": "default", "dev": "eth0"}],
        host_qdiscs=[{"kind": "noqueue", "dev": "eth0"}],
        namespaces=tuple(
            NamespaceSnapshot(f"{prefix}-{suffix}", False, [], [])
            for suffix in ("test", "impair", "uplink")
        ),
    )
    topology = plan_topology(
        TopologyRequest(
            targets=("198.18.0.6/32",),
            direction=Direction.ASYMMETRIC,
            namespace_prefix=prefix,
            require_mtu=True,
        ),
        _capabilities(),
        frozen,
    )
    profile, digest = load_profile(PROFILE_ROOT / f"{profile_name}.yaml")
    return topology, compile_profile(
        topology, profile, source_sha256=digest
    )


class _FakeChild:
    _next_pid = 900000

    def __init__(self, returncode: int | None = 0, on_poll=None):
        self.pid = _FakeChild._next_pid
        _FakeChild._next_pid += 1
        self.returncode = returncode
        self.on_poll = on_poll
        self.polls = 0
        self.stopped = False

    def poll(self):
        self.polls += 1
        if self.on_poll is not None:
            self.on_poll(self)
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = -signal.SIGTERM
        self.stopped = True
        return self.returncode


class _FakeBackend:
    def __init__(self):
        self.namespaces: set[str] = set()
        self.markers: dict[tuple[str, str], str] = {}
        self.links: dict[str, list[str | None]] = {}
        self.peers: dict[str, str] = {}
        self.qdiscs: dict[tuple[str, str], tuple[str, str]] = {}
        self.commands: list[tuple[str, ...]] = []
        self.mutation_count = 0
        self.fail_mutation: int | None = None
        self.traffic_start_mutation_count: int | None = None
        self.next_child = _FakeChild()
        self.infrastructure_child = _FakeChild(returncode=None)
        self.on_child_poll = None

    @staticmethod
    def _tc(command):
        if command and command[0] == "nsenter":
            return command[1].removeprefix("--net=/run/netns/"), command[2:]
        return "host", command

    def _mutation(self, command):
        read_only = (
            "-json" in command
            or command[:3] == ("ip", "netns", "list")
        )
        if not read_only:
            self.mutation_count += 1
            if self.fail_mutation == self.mutation_count:
                return CommandResult(42, stderr=b"injected failure")
        return None

    def run(self, argv, *, timeout=10.0):
        command = tuple(argv)
        self.commands.append(command)
        injected = self._mutation(command)
        if injected is not None:
            return injected
        namespace = "host"
        inner = command
        if command and command[0] == "nsenter":
            namespace = command[1].removeprefix("--net=/run/netns/")
            inner = command[2:]
        if command[:3] == ("ip", "netns", "add"):
            name = command[3]
            if name in self.namespaces:
                return CommandResult(1)
            self.namespaces.add(name)
        elif command[:3] == ("ip", "netns", "del"):
            name = command[3]
            if name not in self.namespaces:
                return CommandResult(1)
            self.namespaces.remove(name)
            self.markers = {
                key: value
                for key, value in self.markers.items()
                if key[0] != name
            }
            self.qdiscs = {
                key: value for key, value in self.qdiscs.items() if key[0] != name
            }
            removed = [
                interface
                for interface, value in self.links.items()
                if value[0] == name
            ]
            for interface in removed:
                peer = self.peers.pop(interface, None)
                self.links.pop(interface, None)
                if peer is not None:
                    self.peers.pop(peer, None)
                    self.links.pop(peer, None)
        elif (
            namespace != "host"
            and len(inner) == 6
            and inner[:3] == ("ip", "link", "add")
            and inner[-2:] == ("type", "dummy")
        ):
            self.markers[(namespace, inner[3])] = ""
        elif (
            namespace != "host"
            and len(inner) == 7
            and inner[:4] == ("ip", "link", "set", "dev")
            and inner[5] == "alias"
        ):
            interface = inner[4]
            if (namespace, interface) in self.markers:
                self.markers[(namespace, interface)] = inner[6]
            elif interface in self.links and self.links[interface][0] == namespace:
                self.links[interface][1] = inner[6]
        elif (
            namespace != "host"
            and inner[:4] == ("ip", "-json", "link", "show")
        ):
            interface = inner[-1]
            if interface == "pasta0":
                return CommandResult(
                    0, json.dumps([{"ifname": "pasta0"}]).encode()
                )
            alias = self.markers.get((namespace, interface))
            link = self.links.get(interface)
            if alias is None and link is not None and link[0] == namespace:
                alias = link[1]
            if alias is None:
                return CommandResult(1)
            return CommandResult(
                0,
                json.dumps([{"ifname": interface, "ifalias": alias}]).encode(),
            )
        elif (
            namespace != "host"
            and inner[:4] == ("ip", "link", "del", "dev")
        ):
            interface = inner[-1]
            peer = self.peers.pop(interface, None)
            self.links.pop(interface, None)
            if peer is not None:
                self.peers.pop(peer, None)
                self.links.pop(peer, None)
        elif (
            len(command) == 9
            and command[:3] == ("ip", "link", "add")
            and command[4:6] == ("type", "veth")
            and command[6:8] == ("peer", "name")
        ):
            left, right = command[3], command[8]
            self.links[left] = ["host", None]
            self.links[right] = ["host", None]
            self.peers[left] = right
            self.peers[right] = left
        elif (
            len(command) == 7
            and command[:4] == ("ip", "link", "set", "dev")
            and command[5] == "alias"
        ):
            self.links[command[4]][1] = command[6]
        elif (
            len(command) == 6
            and command[:3] == ("ip", "link", "set")
            and command[4] == "netns"
        ):
            self.links[command[3]][0] = command[5]
        elif (
            len(command) == 8
            and command[:3] == ("ip", "-n", command[2])
            and command[3:5] == ("link", "add")
            and command[-2:] == ("type", "dummy")
        ):
            self.markers[(command[2], command[5])] = ""
        elif (
            len(command) == 9
            and command[0:2] == ("ip", "-n")
            and command[3:6] == ("link", "set", "dev")
            and command[7] == "alias"
        ):
            self.markers[(command[2], command[6])] = command[8]
        elif command[:3] == ("ip", "-json", "-n"):
            namespace = command[3]
            marker = command[-1]
            if marker == "pasta0":
                return CommandResult(
                    0, json.dumps([{"ifname": "pasta0"}]).encode()
                )
            alias = self.markers.get((namespace, marker))
            link = self.links.get(marker)
            if alias is None and link is not None and link[0] == namespace:
                return CommandResult(
                    0,
                    json.dumps(
                        [{"ifname": marker, "ifalias": link[1]}]
                    ).encode(),
                )
            if alias is None:
                return CommandResult(1)
            return CommandResult(
                0,
                json.dumps([{"ifname": marker, "ifalias": alias}]).encode(),
            )
        elif command[:3] == ("ip", "-json", "link"):
            interface = command[-1]
            value = self.links.get(interface)
            if value is None or value[0] != "host":
                return CommandResult(1)
            return CommandResult(
                0,
                json.dumps([{"ifname": interface, "ifalias": value[1]}]).encode(),
            )
        elif "link" in command and "del" in command and "dev" in command:
            interface = command[-1]
            peer = self.peers.pop(interface, None)
            self.links.pop(interface, None)
            if peer is not None:
                self.peers.pop(peer, None)
                self.links.pop(peer, None)
        namespace, tc = self._tc(command)
        if len(tc) >= 7 and tc[:3] == ("tc", "qdisc", "add") and "root" in tc:
            interface = tc[tc.index("dev") + 1]
            self.qdiscs[(namespace, interface)] = ("1:", "prio")
        elif tc[:4] == ("tc", "-json", "qdisc", "show"):
            interface = tc[tc.index("dev") + 1]
            value = self.qdiscs.get((namespace, interface))
            rendered = [] if value is None else [{"handle": value[0], "kind": value[1]}]
            return CommandResult(0, json.dumps(rendered).encode())
        elif len(tc) >= 7 and tc[:3] == ("tc", "qdisc", "del") and "root" in tc:
            interface = tc[tc.index("dev") + 1]
            if (namespace, interface) not in self.qdiscs:
                return CommandResult(1)
            del self.qdiscs[(namespace, interface)]
        return CommandResult(0)

    def read(self, argv):
        command = tuple(argv)
        self.commands.append(command)
        if command == ("ip", "netns", "list"):
            return "".join(f"{name}\n" for name in sorted(self.namespaces))
        result = self.run(argv)
        if result.returncode:
            raise LifecycleError("fake read failed")
        return result.stdout.decode()

    def popen(self, argv):
        self.commands.append(tuple(argv))
        if argv[0] == "pasta":
            return self.infrastructure_child
        self.traffic_start_mutation_count = self.mutation_count
        child = self.next_child
        child.on_poll = self.on_child_poll
        return child


def _snapshotter(topology, backend):
    def snapshot(_names):
        frozen = topology["preMutationSnapshot"]
        return {
            "host": frozen["host"],
            "namespaces": [
                {
                    "name": item["name"],
                    "exists": item["name"] in backend.namespaces,
                    "routes": [],
                    "qdiscs": [],
                }
                for item in frozen["namespaces"]
            ],
        }

    return snapshot


def _run(topology, plan, backend):
    return ChaosLifecycle(
        topology,
        plan,
        backend=backend,
        snapshotter=_snapshotter(topology, backend),
        namespace_path_validator=lambda name: f"/run/netns/{name}",
    ).run(["true"])


class ChaosLifecycleTests(unittest.TestCase):
    def test_success_restores_exact_state_and_repeated_runs_are_clean(self):
        topology, plan = _plans()
        backend = _FakeBackend()
        first = _run(topology, plan, backend)
        self.assertEqual(first["state"], "succeeded")
        self.assertTrue(first["cleanup"]["restored"])
        self.assertTrue(first["cleanup"]["trafficStoppedBeforeTopologyTeardown"])
        self.assertEqual(backend.namespaces, set())
        self.assertEqual(backend.qdiscs, {})
        self.assertEqual(backend.links, {})
        traffic_argv = next(
            command for command in backend.commands if command[-1] == "true"
        )
        self.assertIn("setpriv", traffic_argv)
        self.assertIn("--bounding-set=-net_admin,-sys_admin", traffic_argv)
        backend.next_child = _FakeChild()
        backend.infrastructure_child = _FakeChild(returncode=None)
        second = _run(topology, plan, backend)
        self.assertEqual(second["state"], "succeeded")
        self.assertEqual(backend.namespaces, set())

    def test_every_partial_apply_failure_rolls_back_owned_objects(self):
        topology, plan = _plans()
        probe = _FakeBackend()
        baseline = _run(topology, plan, probe)
        self.assertEqual(baseline["state"], "succeeded")
        mutation_total = probe.traffic_start_mutation_count
        self.assertIsNotNone(mutation_total)
        assert mutation_total is not None
        for fail_at in range(1, mutation_total + 1):
            with self.subTest(fail_at=fail_at):
                backend = _FakeBackend()
                backend.fail_mutation = fail_at
                report = _run(topology, plan, backend)
                self.assertIn(report["state"], {"failed", "cleanup_failed"})
                self.assertEqual(backend.namespaces, set())
                self.assertEqual(backend.qdiscs, {})
                self.assertEqual(backend.links, {})

    def test_cancel_stops_traffic_before_topology_cleanup(self):
        topology, plan = _plans()
        backend = _FakeBackend()
        backend.next_child = _FakeChild(returncode=None)
        lifecycle = ChaosLifecycle(
            topology,
            plan,
            backend=backend,
            snapshotter=_snapshotter(topology, backend),
            namespace_path_validator=lambda name: f"/run/netns/{name}",
        )

        def cancel_on_poll(child):
            if child.polls == 1:
                lifecycle.cancel(signal.SIGINT)

        backend.on_child_poll = cancel_on_poll
        report = lifecycle.run(["long-call"])
        self.assertEqual((report["state"], report["exitCode"]), ("cancelled", 130))
        names = [event["event"] for event in report["events"]]
        self.assertLess(names.index("traffic.stopped"), names.index("topology.cleanup_started"))
        self.assertTrue(report["cleanup"]["trafficStoppedBeforeTopologyTeardown"])
        self.assertEqual(backend.namespaces, set())

    def test_killed_child_is_failure_but_cleanup_succeeds(self):
        topology, plan = _plans()
        backend = _FakeBackend()
        backend.next_child = _FakeChild(returncode=-signal.SIGKILL)
        report = _run(topology, plan, backend)
        self.assertEqual(report["state"], "child_failed")
        self.assertTrue(report["cleanup"]["restored"])
        self.assertEqual(backend.namespaces, set())

    def test_preflight_drift_fails_before_mutation(self):
        topology, plan = _plans()
        backend = _FakeBackend()

        def drift(_names):
            value = json.loads(json.dumps(topology["preMutationSnapshot"]))
            value["host"]["routes"].append({"dst": "203.0.113.0/24"})
            return value

        report = ChaosLifecycle(
            topology,
            plan,
            backend=backend,
            snapshotter=drift,
            namespace_path_validator=lambda name: f"/run/netns/{name}",
        ).run(["true"])
        self.assertEqual(report["state"], "cleanup_failed")
        self.assertFalse(any(command[:3] == ("ip", "netns", "add") for command in backend.commands))

    def test_snapshot_recollection_preserves_frozen_namespace_order(self):
        topology, plan = _plans()
        backend = _FakeBackend()
        frozen_names = tuple(
            item["name"] for item in topology["preMutationSnapshot"]["namespaces"]
        )
        observed_orders = []

        def snapshot(names):
            observed_orders.append(tuple(names))
            return _snapshotter(topology, backend)(names)

        report = ChaosLifecycle(
            topology,
            plan,
            backend=backend,
            snapshotter=snapshot,
            namespace_path_validator=lambda name: f"/run/netns/{name}",
        ).run(["true"])
        self.assertEqual(report["state"], "succeeded")
        self.assertEqual(observed_orders, [frozen_names, frozen_names])

    def test_noncanonical_namespace_path_is_rejected_and_cleaned(self):
        topology, plan = _plans()
        backend = _FakeBackend()
        report = ChaosLifecycle(
            topology,
            plan,
            backend=backend,
            snapshotter=_snapshotter(topology, backend),
            namespace_path_validator=lambda _name: "/run/netns/substituted",
        ).run(["true"])
        self.assertEqual(report["state"], "failed")
        self.assertIn("non-canonical", report["error"])
        self.assertTrue(report["cleanup"]["restored"])
        self.assertEqual(backend.namespaces, set())
        self.assertFalse(any(command[0] == "nsenter" for command in backend.commands))

    def test_foreign_qdisc_is_never_deleted(self):
        topology, plan = _plans()
        backend = _FakeBackend()
        backend.next_child = _FakeChild(returncode=0)

        def replace_owned(_child):
            for key in list(backend.qdiscs):
                backend.qdiscs[key] = ("1:", "foreign")

        backend.on_child_poll = replace_owned
        report = _run(topology, plan, backend)
        self.assertEqual(report["state"], "cleanup_failed")
        deletes = [
            command
            for command in backend.commands
            if "qdisc" in command and "del" in command
        ]
        self.assertEqual(deletes, [])

    def test_modified_impairment_command_is_rejected(self):
        topology, plan = _plans()
        plan["commands"][0]["argv"].append("injected")
        with self.assertRaisesRegex(LifecycleError, "deterministic recompilation"):
            validate_impairment_plan(topology, plan)

    def test_cli_sigint_is_delivered_to_lifecycle_and_reported(self):
        class FakeLifecycle:
            instance = None

            def __init__(self, _topology, _plan):
                self.cancelled = None
                FakeLifecycle.instance = self

            def cancel(self, signum):
                self.cancelled = signum

            def run(self, _command, *, observations):
                os.kill(os.getpid(), signal.SIGINT)
                self.assert_cancelled()
                return {
                    "apiVersion": "sippycup.dev/chaos-run-report/v1",
                    "kind": "ChaosRunReport",
                    "exitCode": 130,
                }

            def assert_cancelled(self):
                if self.cancelled != signal.SIGINT:
                    raise AssertionError("SIGINT was not delivered")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            topology = root / "topology.json"
            impairment = root / "impairment.json"
            report = root / "report.json"
            topology.write_text("{}", encoding="utf-8")
            impairment.write_text("{}", encoding="utf-8")
            with mock.patch(
                "sippycup_chaos.cli.ChaosLifecycle", FakeLifecycle
            ):
                status = chaos_main(
                    [
                        "run",
                        "--report",
                        str(report),
                        str(topology),
                        str(impairment),
                        "--",
                        "true",
                    ]
                )
        self.assertEqual(status, 130)
        self.assertEqual(FakeLifecycle.instance.cancelled, signal.SIGINT)


def _rtp_frame(sequence: int, timestamp: int, payload: bytes = b"x" * 160) -> bytes:
    rtp = (
        bytes((0x80, 0))
        + sequence.to_bytes(2, "big")
        + timestamp.to_bytes(4, "big")
        + (0x12345678).to_bytes(4, "big")
        + payload
    )
    udp_length = 8 + len(rtp)
    udp = (
        (10000).to_bytes(2, "big")
        + (20000).to_bytes(2, "big")
        + udp_length.to_bytes(2, "big")
        + b"\0\0"
        + rtp
    )
    total = 20 + len(udp)
    ip = (
        b"\x45\0"
        + total.to_bytes(2, "big")
        + b"\0\0\0\0"
        + b"\x40\x11\0\0"
        + b"\xc6\x12\0\x01"
        + b"\xc6\x12\0\x06"
    )
    ethernet = b"\x02\0\0\0\0\2\x02\0\0\0\0\1\x08\0"
    return ethernet + ip + udp


def _write_pcap(path: Path, packets):
    data = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for time_seconds, frame in packets:
        seconds = int(time_seconds)
        micros = round((time_seconds - seconds) * 1_000_000)
        data.extend(struct.pack("<IIII", seconds, micros, len(frame), len(frame)))
        data.extend(frame)
    path.write_bytes(data)


class ChaosMeasurementTests(unittest.TestCase):
    def test_fixed_delay_clean_loss_and_order_are_within_tolerance(self):
        _topology, plan = _plans("fixed-delay")
        with tempfile.TemporaryDirectory() as temporary:
            before = Path(temporary) / "before.pcap"
            after = Path(temporary) / "after.pcap"
            sent = [
                (1.0 + index * 0.02, _rtp_frame(index, index * 160))
                for index in range(220)
            ]
            received = [(at + 0.080, frame) for at, frame in sent]
            _write_pcap(before, sent)
            _write_pcap(after, received)
            report = measure_observations(
                plan, {"egress": (before, after), "ingress": (before, after)}
            )
        self.assertTrue(report["allWithinTolerance"])
        for direction in report["directions"]:
            self.assertEqual(direction["status"], "within_tolerance")
            metrics = direction["metrics"]
            self.assertAlmostEqual(metrics["delay"]["observed"], 80, places=3)
            self.assertEqual(metrics["loss"]["observed"], 0)
            self.assertEqual(metrics["reorder"]["observed"], 0)

    def test_loss_duplicate_reorder_are_counted_from_packet_identity(self):
        _topology, plan = _plans("asymmetric-media")
        with tempfile.TemporaryDirectory() as temporary:
            before = Path(temporary) / "before.pcap"
            after = Path(temporary) / "after.pcap"
            sent = [
                (1.0 + index * 0.02, _rtp_frame(index, index * 160))
                for index in range(220)
            ]
            order = [index for index in range(220) if index not in {20, 40, 60, 80}]
            order[100], order[101] = order[101], order[100]
            order.extend((10, 30))
            received = [
                (
                    1.200 + arrival * 0.02,
                    sent[index][1],
                )
                for arrival, index in enumerate(order)
            ]
            _write_pcap(before, sent)
            _write_pcap(after, received)
            report = measure_observations(plan, {"egress": (before, after)})
        metrics = report["directions"][0]["metrics"]
        self.assertEqual(metrics["packetCounts"]["lost"], 4)
        self.assertEqual(metrics["packetCounts"]["duplicates"], 2)
        self.assertGreaterEqual(metrics["packetCounts"]["reordered"], 1)
        self.assertAlmostEqual(metrics["loss"]["observed"], 4 / 220 * 100)

    def test_insufficient_samples_are_explicit(self):
        _topology, plan = _plans("fixed-delay")
        with tempfile.TemporaryDirectory() as temporary:
            before = Path(temporary) / "before.pcap"
            after = Path(temporary) / "after.pcap"
            sent = [
                (1.0 + index * 0.02, _rtp_frame(index, index * 160))
                for index in range(10)
            ]
            _write_pcap(before, sent)
            _write_pcap(after, [(at + 0.08, frame) for at, frame in sent])
            report = measure_observations(plan, {"egress": (before, after)})
        self.assertEqual(report["directions"][0]["status"], "insufficient_samples")
        self.assertFalse(
            report["directions"][0]["metrics"]["loss"]["sufficientSamples"]
        )
        self.assertEqual(
            report["directions"][1]["reason"],
            "paired before/after PCAP observations were not supplied",
        )

    def test_public_report_schema_and_lifecycle_document_exist(self):
        schema = json.loads(
            (ROOT / "schemas" / "chaos-run-report-v1.schema.json").read_text()
        )
        self.assertEqual(
            schema["properties"]["apiVersion"]["const"],
            "sippycup.dev/chaos-run-report/v1",
        )
        documentation = (ROOT / "docs" / "CHAOS-LIFECYCLE.md").read_text().lower()
        for phrase in (
            "trafficstoppedbeforetopologyteardown",
            "byte-equivalent",
            "insufficient_samples",
            "gilbert-elliott",
            "5 ms",
            "200 sent packets",
            "pasta",
        ):
            self.assertIn(phrase, documentation)


if __name__ == "__main__":
    unittest.main()
