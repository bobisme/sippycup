from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tools"))

from chaos_exit_gate import _parse_ping, _profile_verdict  # noqa: E402
from sippycup_chaos.profiles import compile_profile, load_profile  # noqa: E402
from sippycup_chaos.topology import (  # noqa: E402
    Direction,
    FeatureState,
    NetworkSnapshot,
    NamespaceSnapshot,
    TopologyError,
    TopologyKind,
    TopologyRequest,
    plan_topology,
)
from tests.test_chaos_lifecycle import _capabilities, _plans  # noqa: E402


PROFILE_ROOT = ROOT / "profiles" / "chaos"


class ChaosExitGateTests(unittest.TestCase):
    def test_every_profile_command_is_confined_to_a_frozen_namespace(self):
        topology, _unused = _plans()
        planned_names = set(topology["namespaces"].values())
        for path in sorted(PROFILE_ROOT.glob("*.yaml")):
            with self.subTest(profile=path.name):
                profile, digest = load_profile(path)
                plan = compile_profile(topology, profile, source_sha256=digest)
                for command in plan["commands"]:
                    self.assertIn(command["namespace"], planned_names)
                    self.assertEqual(command["argv"][0], "nsenter")
                    self.assertEqual(
                        command["argv"][1],
                        f"--net=/run/netns/{command['namespace']}",
                    )
                    self.assertNotEqual(command["namespace"], "host")

    def test_every_required_capability_fails_loudly_when_unavailable_or_unknown(self):
        fields = (
            "iproute2",
            "tc",
            "net_admin",
            "sys_admin",
            "netem",
            "classifier",
            "pasta",
            "mtu",
        )
        for field in fields:
            for state in (FeatureState.UNAVAILABLE, FeatureState.UNKNOWN):
                with self.subTest(feature=field, state=state.value):
                    capabilities = replace(_capabilities(), **{field: state})
                    prefix = "capgate"
                    snapshot = NetworkSnapshot(
                        [],
                        [],
                        tuple(
                            # The planner requires the exact three absent names.
                            NamespaceSnapshot(
                                f"{prefix}-{suffix}", False, [], []
                            )
                            for suffix in ("test", "impair", "uplink")
                        ),
                    )
                    with self.assertRaisesRegex(
                        TopologyError,
                        field,
                    ):
                        plan_topology(
                            TopologyRequest(
                                targets=("198.18.0.6/32",),
                                direction=Direction.BIDIRECTIONAL,
                                namespace_prefix=prefix,
                                require_mtu=True,
                            ),
                            capabilities,
                            snapshot,
                        )

    def test_dangerous_mode_requires_exact_confirmation_and_rootful_boundary(self):
        capabilities = _capabilities()
        snapshot = NetworkSnapshot(
            [],
            [{"kind": "fq_codel", "dev": "eth0"}],
            (),
        )
        for confirmation in (
            None,
            "yes",
            "dedicated-test-vm:",
            "dedicated-test-vm:lab/../../host",
        ):
            with self.subTest(confirmation=confirmation):
                with self.assertRaisesRegex(TopologyError, "dedicated-test-vm"):
                    plan_topology(
                        TopologyRequest(
                            targets=("198.51.100.10/32",),
                            direction=Direction.EGRESS,
                            topology=TopologyKind.DANGEROUS_HOST_NETWORK,
                            dangerous_confirmation=confirmation,
                            host_interface="eth0",
                        ),
                        capabilities,
                        snapshot,
                    )
        with self.assertRaisesRegex(TopologyError, "rootful"):
            plan_topology(
                TopologyRequest(
                    targets=("198.51.100.10/32",),
                    direction=Direction.EGRESS,
                    topology=TopologyKind.DANGEROUS_HOST_NETWORK,
                    dangerous_confirmation="dedicated-test-vm:lab",
                    host_interface="eth0",
                ),
                capabilities,
                snapshot,
            )

    def test_ping_parser_and_profile_verdict_cover_kernel_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ping.txt"
            path.write_text(
                "64 bytes from 198.18.0.6: icmp_seq=2 ttl=63 time=1 ms\n"
                "64 bytes from 198.18.0.6: icmp_seq=1 ttl=63 time=2 ms\n"
                "5 packets transmitted, 0 received, +5 errors, "
                "100% packet loss, time 4096ms\n"
            )
            observed = _parse_ping(path)
        self.assertTrue(observed["measurable"])
        self.assertEqual(observed["errors"], 5)
        self.assertEqual(observed["arrivalInversions"], 1)
        clean_control = {
            "measurable": True,
            "lossPercent": 0.0,
            "rttMilliseconds": {"average": 0.1},
        }
        constrained = {
            "target": {
                "measurable": True,
                "lossPercent": 85.0,
                "rttMilliseconds": {"average": 148.0, "mdev": 60.0},
                "elapsedMilliseconds": 500,
                "duplicates": 0,
                "arrivalInversions": 0,
            },
            "control": clean_control,
        }
        self.assertEqual(
            _profile_verdict("constrained-uplink", constrained),
            [],
        )

    def test_gate_artifacts_document_host_and_controller_boundaries(self):
        runner = (ROOT / "bin" / "chaos-exit-gate").read_text()
        for phrase in (
            "host-routes-before",
            "host-routes-after",
            "host-qdiscs-before",
            "host-qdiscs-after",
            "host-loopback-heartbeat",
            "--device=/dev/net/tun",
        ):
            self.assertIn(phrase, runner)


if __name__ == "__main__":
    unittest.main()
