from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_chaos.topology import (  # noqa: E402
    CapabilitySnapshot,
    Direction,
    FeatureState,
    NetworkSnapshot,
    NamespaceSnapshot,
    TopologyError,
    TopologyKind,
    TopologyRequest,
    collect_network_snapshot,
    detect_capabilities,
    plan_topology,
)


def capabilities(**changes) -> CapabilitySnapshot:
    values = {
        "execution_mode": "rootless",
        "podman": FeatureState.AVAILABLE,
        "iproute2": FeatureState.AVAILABLE,
        "tc": FeatureState.AVAILABLE,
        "net_admin": FeatureState.AVAILABLE,
        "netem": FeatureState.AVAILABLE,
        "ifb": FeatureState.UNAVAILABLE,
        "classifier": FeatureState.AVAILABLE,
        "mtu": FeatureState.AVAILABLE,
        "sys_admin": FeatureState.AVAILABLE,
        "pasta": FeatureState.AVAILABLE,
        "evidence": {"fixture": "read-only"},
    }
    values.update(changes)
    return CapabilitySnapshot(**values)


def snapshot(prefix: str = "lab") -> NetworkSnapshot:
    return NetworkSnapshot(
        host_routes=[{"dst": "default", "dev": "eth0"}],
        host_qdiscs=[{"kind": "noqueue", "dev": "eth0"}],
        namespaces=tuple(
            NamespaceSnapshot(f"{prefix}-{suffix}", False, [], [])
            for suffix in ("test", "impair", "uplink")
        ),
    )


class TopologyPlannerTests(unittest.TestCase):
    def test_disposable_asymmetric_plan_has_explicit_paths_and_no_mutations(self):
        before = snapshot()
        document = plan_topology(
            TopologyRequest(
                targets=("2001:db8:1::/64", "10.20.30.40/32", "10.20.30.40/32"),
                direction=Direction.ASYMMETRIC,
                namespace_prefix="lab",
            ),
            capabilities(),
            before,
        )
        self.assertTrue(document["noChange"])
        self.assertFalse(document["dangerous"])
        self.assertEqual(document["mutationCommands"], [])
        self.assertEqual(
            set(document["attachments"]), {"egress", "ingress"}
        )
        self.assertEqual(
            document["attachments"]["egress"]["interface"], "imp-uplink0"
        )
        self.assertEqual(
            document["attachments"]["ingress"]["interface"], "imp-test0"
        )
        self.assertFalse(document["ifbRequired"])
        self.assertEqual(
            {
                (item["network"], item["direction"], item["match"])
                for item in document["targetFilters"]
            },
            {
                ("10.20.30.40/32", "egress", "dst_ip 10.20.30.40/32"),
                ("10.20.30.40/32", "ingress", "src_ip 10.20.30.40/32"),
                ("2001:db8:1::/64", "egress", "dst_ip 2001:db8:1::/64"),
                ("2001:db8:1::/64", "ingress", "src_ip 2001:db8:1::/64"),
            },
        )
        self.assertEqual(document["preMutationSnapshot"], before.to_dict())

    def test_direction_mapping_is_honest_and_independent(self):
        for direction, attachment in (
            (Direction.EGRESS, "egress"),
            (Direction.INGRESS, "ingress"),
        ):
            with self.subTest(direction=direction):
                document = plan_topology(
                    TopologyRequest(
                        targets=("10.0.0.7/32",),
                        direction=direction,
                        namespace_prefix="lab",
                    ),
                    capabilities(),
                    snapshot(),
                )
                self.assertEqual(set(document["attachments"]), {attachment})
                self.assertEqual(
                    document["attachments"][attachment]["hook"], "egress"
                )

    def test_unsupported_features_reject_instead_of_approximating(self):
        for feature in ("net_admin", "sys_admin", "netem", "classifier", "pasta"):
            with self.subTest(feature=feature):
                with self.assertRaisesRegex(TopologyError, feature):
                    plan_topology(
                        TopologyRequest(
                            targets=("10.0.0.7/32",),
                            direction=Direction.ASYMMETRIC,
                            namespace_prefix="lab",
                        ),
                        capabilities(**{feature: FeatureState.UNKNOWN}),
                        snapshot(),
                    )

    def test_host_network_is_separately_named_confirmed_and_ifb_gated(self):
        request = TopologyRequest(
            targets=("10.0.0.7/32",),
            direction=Direction.INGRESS,
            topology=TopologyKind.DANGEROUS_HOST_NETWORK,
            namespace_prefix="lab",
        )
        with self.assertRaisesRegex(TopologyError, "dedicated-test-vm"):
            plan_topology(
                request,
                capabilities(execution_mode="rootful", ifb=FeatureState.AVAILABLE),
                NetworkSnapshot([], [{"dev": "eth0"}], ()),
            )
        confirmed = TopologyRequest(
            **{
                **{
                    field: getattr(request, field)
                    for field in (
                        "targets",
                        "direction",
                        "topology",
                        "namespace_prefix",
                        "require_mtu",
                    )
                },
                "dangerous_confirmation": "dedicated-test-vm:voice-lab-01",
                "host_interface": "eth0",
            }
        )
        with self.assertRaisesRegex(TopologyError, "ifb"):
            plan_topology(
                confirmed,
                capabilities(
                    execution_mode="rootful", ifb=FeatureState.UNAVAILABLE
                ),
                NetworkSnapshot([], [{"dev": "eth0"}], ()),
            )
        document = plan_topology(
            confirmed,
            capabilities(execution_mode="rootful", ifb=FeatureState.AVAILABLE),
            NetworkSnapshot([], [{"dev": "eth0"}], ()),
        )
        self.assertTrue(document["dangerous"])
        self.assertTrue(document["ifbRequired"])
        self.assertIn("DANGEROUS", document["privilegeBoundary"])
        self.assertEqual(document["namespaces"], {})
        self.assertEqual(
            document["packetPath"]["outbound"],
            ["host:eth0", "authorized-target"],
        )

    def test_targets_are_literal_canonical_bounded_unicast_filters(self):
        for target in (
            "voice.example.test",
            "10.0.0.1/24",
            "0.0.0.0/0",
            "224.0.0.0/4",
        ):
            with self.subTest(target=target), self.assertRaises(TopologyError):
                plan_topology(
                    TopologyRequest(
                        targets=(target,),
                        direction=Direction.EGRESS,
                        namespace_prefix="lab",
                    ),
                    capabilities(),
                    snapshot(),
                )

    def test_existing_namespace_is_never_reused(self):
        occupied = snapshot()
        occupied = NetworkSnapshot(
            occupied.host_routes,
            occupied.host_qdiscs,
            (
                NamespaceSnapshot("lab-test", True, [{"dst": "default"}], []),
                *occupied.namespaces[1:],
            ),
        )
        with self.assertRaisesRegex(TopologyError, "refusing to reuse"):
            plan_topology(
                TopologyRequest(
                    targets=("10.0.0.7/32",),
                    direction=Direction.EGRESS,
                    namespace_prefix="lab",
                ),
                capabilities(),
                occupied,
            )

    def test_snapshot_reads_only_routes_qdiscs_and_existing_namespaces(self):
        calls = []

        def reader(command):
            calls.append(tuple(command))
            values = {
                ("ip", "-json", "route", "show", "table", "all"): '[{"dst":"default"}]',
                ("tc", "-json", "qdisc", "show"): '[{"kind":"noqueue"}]',
                ("ip", "netns", "list"): "lab-test (id: 1)\n",
                (
                    "nsenter",
                    "--net=/run/netns/lab-test",
                    "ip",
                    "-json",
                    "route",
                    "show",
                    "table",
                    "all",
                ): '[{"dst":"10.0.0.0/24"}]',
                (
                    "nsenter",
                    "--net=/run/netns/lab-test",
                    "tc",
                    "-json",
                    "qdisc",
                    "show",
                ): '[{"kind":"fq_codel"}]',
            }
            return values[tuple(command)]

        result = collect_network_snapshot(
            ("lab-test", "lab-impair", "lab-uplink"), reader=reader
        )
        self.assertTrue(result.namespaces[0].exists)
        self.assertFalse(result.namespaces[1].exists)
        forbidden = {"add", "del", "replace", "set", "change", "link"}
        self.assertFalse(
            any(forbidden & set(command) for command in calls), calls
        )

    def test_rootless_and_capability_detection_are_evidence_based(self):
        with tempfile.TemporaryDirectory() as directory:
            module_root = Path(directory) / "modules"
            sys_root = Path(directory) / "sys"
            for module in ("sch_netem", "ifb", "cls_flower"):
                (sys_root / module).mkdir(parents=True)

            def available(name):
                return f"/usr/bin/{name}"

            detected = detect_capabilities(
                euid=0,
                uid_map="0 1000 1\n",
                status_text="CapEff:\t0000000000001000\n",
                which=available,
                module_root=module_root,
                sys_module_root=sys_root,
                tun_path=Path("/dev/null"),
            )
        self.assertEqual(detected.execution_mode, "rootless")
        self.assertEqual(detected.net_admin, FeatureState.AVAILABLE)
        self.assertEqual(detected.sys_admin, FeatureState.UNAVAILABLE)
        self.assertEqual(detected.netem, FeatureState.AVAILABLE)
        self.assertEqual(detected.ifb, FeatureState.AVAILABLE)
        self.assertEqual(detected.classifier, FeatureState.AVAILABLE)
        self.assertEqual(detected.pasta, FeatureState.AVAILABLE)
        missing_tun = detect_capabilities(
            euid=0,
            uid_map="0 1000 1\n",
            status_text="CapEff:\t0000000000001000\n",
            which=available,
            module_root=module_root,
            sys_module_root=sys_root,
            tun_path=Path(directory) / "missing-tun",
        )
        self.assertEqual(missing_tun.pasta, FeatureState.UNAVAILABLE)

    def test_capability_snapshot_round_trip_is_strict(self):
        encoded = capabilities().to_dict()
        self.assertEqual(CapabilitySnapshot.from_dict(encoded), capabilities())
        encoded["features"]["netem"] = "maybe"
        with self.assertRaises(TopologyError):
            CapabilitySnapshot.from_dict(encoded)


class TopologyArtifactTests(unittest.TestCase):
    def test_public_schema_and_architecture_document_exist(self):
        schema = json.loads(
            (ROOT / "schemas" / "chaos-topology-plan-v1.schema.json").read_text()
        )
        self.assertEqual(
            schema["properties"]["apiVersion"]["const"],
            "sippycup.dev/chaos-topology-plan/v1",
        )
        documentation = (ROOT / "docs" / "CHAOS-TOPOLOGY.md").read_text().lower()
        for phrase in (
            "test0",
            "imp-test0",
            "imp-uplink0",
            "uplink0",
            "privilege boundary",
            "dangerous-host-network",
            "dedicated-test-vm",
            "pre-mutation snapshot",
        ):
            self.assertIn(phrase, documentation)


if __name__ == "__main__":
    unittest.main()
