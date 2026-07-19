from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_chaos.profiles import (  # noqa: E402
    ProfileError,
    compile_profile,
    load_profile,
    validate_profile,
)
from sippycup_chaos.topology import (  # noqa: E402
    CapabilitySnapshot,
    Direction,
    FeatureState,
    NetworkSnapshot,
    NamespaceSnapshot,
    TopologyRequest,
    TopologyKind,
    plan_topology,
)


PROFILE_ROOT = ROOT / "profiles" / "chaos"


def capabilities() -> CapabilitySnapshot:
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


def topology(direction: Direction = Direction.ASYMMETRIC) -> dict:
    prefix = "profilelab"
    snapshot = NetworkSnapshot(
        host_routes=[{"dst": "default", "dev": "eth0"}],
        host_qdiscs=[{"kind": "noqueue", "dev": "eth0"}],
        namespaces=tuple(
            NamespaceSnapshot(f"{prefix}-{suffix}", False, [], [])
            for suffix in ("test", "impair", "uplink")
        ),
    )
    return plan_topology(
        TopologyRequest(
            targets=("10.20.30.40/32", "2001:db8:1::7/128"),
            direction=direction,
            namespace_prefix=prefix,
            require_mtu=True,
        ),
        capabilities(),
        snapshot,
    )


def loaded(name: str) -> tuple[dict, str]:
    return load_profile(PROFILE_ROOT / f"{name}.yaml")


class ProfileCompilerTests(unittest.TestCase):
    def test_all_reviewed_profiles_compile_without_executing(self):
        expected = {
            "clean",
            "fixed-delay",
            "jitter",
            "burst-loss",
            "constrained-uplink",
            "reorder",
            "duplicate",
            "mtu-fragmentation",
            "asymmetric-media",
        }
        self.assertEqual({item.stem for item in PROFILE_ROOT.glob("*.yaml")}, expected)
        for name in sorted(expected):
            with self.subTest(profile=name):
                profile, digest = loaded(name)
                plan = compile_profile(topology(), profile, source_sha256=digest)
                self.assertTrue(plan["noChange"])
                self.assertFalse(plan["execution"]["performed"])
                self.assertEqual(plan["profile"]["sourceSha256"], digest)
                self.assertTrue(
                    all(
                        isinstance(command["argv"], list)
                        and all(isinstance(arg, str) for arg in command["argv"])
                        for command in plan["commands"]
                    )
                )

    def test_clean_is_a_real_no_command_control(self):
        profile, digest = loaded("clean")
        plan = compile_profile(topology(), profile, source_sha256=digest)
        self.assertEqual(plan["commands"], [])
        self.assertEqual(
            {item["direction"] for item in plan["directions"]},
            {"egress", "ingress"},
        )
        self.assertTrue(
            all(item["targetFilters"] for item in plan["directions"])
        )

    def test_commands_are_target_scoped_and_deterministic(self):
        profile, digest = loaded("jitter")
        first = compile_profile(topology(), profile, source_sha256=digest)
        second = compile_profile(topology(), profile, source_sha256=digest)
        self.assertEqual(
            json.dumps(first, sort_keys=True, separators=(",", ":")),
            json.dumps(second, sort_keys=True, separators=(",", ":")),
        )
        filters = [
            command["argv"]
            for command in first["commands"]
            if "-filter-" in command["id"]
        ]
        self.assertEqual(len(filters), 4)
        self.assertTrue(any("dst_ip" in argv for argv in filters))
        self.assertTrue(any("src_ip" in argv for argv in filters))
        netem = [
            command["argv"]
            for command in first["commands"]
            if command["id"].endswith("-netem")
        ]
        self.assertEqual(len(netem), 2)
        self.assertTrue(
            all(
                argv[argv.index("netem") + 1 : -2]
                == ["delay", "60ms", "20ms", "25%", "distribution", "normal"]
                for argv in netem
            )
        )
        self.assertTrue(all(argv[-2] == "seed" for argv in netem))
        seeds = {argv[-1] for argv in netem}
        self.assertEqual(len(seeds), 2)

    def test_burst_loss_rate_reorder_duplicate_and_mtu_translate(self):
        expectations = {
            "burst-loss": ("gemodel",),
            "constrained-uplink": ("tbf", "128kbit", "latency", "100ms"),
            "reorder": ("reorder", "4%", "gap", "5"),
            "duplicate": ("duplicate", "2%", "10%"),
            "mtu-fragmentation": ("link", "set", "mtu", "1280"),
        }
        for name, tokens in expectations.items():
            with self.subTest(profile=name):
                profile, digest = loaded(name)
                plan = compile_profile(topology(), profile, source_sha256=digest)
                flattened = [
                    token
                    for command in plan["commands"]
                    for token in command["argv"]
                ]
                for token in tokens:
                    self.assertIn(token, flattened)

    def test_invalid_percentages_nonfinite_values_and_unknown_keys_fail(self):
        profile, _ = loaded("duplicate")
        for invalid in (-0.1, 100.1, float("nan"), float("inf"), True):
            candidate = copy.deepcopy(profile)
            candidate["directions"]["egress"]["duplicate"]["percent"] = invalid
            with self.subTest(value=invalid), self.assertRaises(ProfileError):
                validate_profile(candidate)
        candidate = copy.deepcopy(profile)
        candidate["directions"]["egress"]["surprise"] = 1
        with self.assertRaisesRegex(ProfileError, "unknown"):
            validate_profile(candidate)

    def test_reorder_without_delay_and_impossible_rate_queue_fail(self):
        profile, _ = loaded("reorder")
        del profile["directions"]["egress"]["delay"]
        with self.assertRaisesRegex(ProfileError, "requires a non-zero delay"):
            validate_profile(profile)
        profile, _ = loaded("constrained-uplink")
        profile["directions"]["egress"]["rate"]["limitBytes"] = 64000
        with self.assertRaisesRegex(ProfileError, "exactly one"):
            validate_profile(profile)
        profile, _ = loaded("constrained-uplink")
        profile["directions"]["egress"]["queuePackets"] = 100
        with self.assertRaisesRegex(ProfileError, "requires a netem"):
            validate_profile(profile)

    def test_direction_contract_is_explicit(self):
        profile, digest = loaded("fixed-delay")
        with self.assertRaisesRegex(ProfileError, "not covered"):
            compile_profile(
                topology(Direction.EGRESS), profile, source_sha256=digest
            )
        profile["directions"]["ingress"]["delay"]["milliseconds"] = 81
        with self.assertRaisesRegex(ProfileError, "use asymmetric"):
            validate_profile(profile)
        profile["direction"] = "asymmetric"
        self.assertEqual(validate_profile(profile)["direction"], "asymmetric")

    def test_tampered_or_unscoped_topology_fails_closed(self):
        profile, digest = loaded("fixed-delay")
        for mutate in (
            lambda value: value.update(targetFilters=[]),
            lambda value: value["targetFilters"].pop(),
            lambda value: value["targetFilters"][0].update(
                match="dst_ip 0.0.0.0/0"
            ),
            lambda value: value.update(targetScopeSha256="0" * 64),
            lambda value: value["attachments"]["egress"].update(
                namespace="host", interface="eth0"
            ),
            lambda value: value.update(snapshotSha256="0" * 64),
            lambda value: value.update(mutationCommands=[["tc", "qdisc", "add"]]),
        ):
            plan = topology()
            mutate(plan)
            with self.subTest(plan=plan), self.assertRaises(ProfileError):
                compile_profile(plan, profile, source_sha256=digest)

    def test_mtu_is_rejected_on_host_network_even_when_confirmed(self):
        host_capabilities = capabilities()
        host_capabilities = CapabilitySnapshot(
            execution_mode="rootful",
            podman=host_capabilities.podman,
            iproute2=host_capabilities.iproute2,
            tc=host_capabilities.tc,
            net_admin=host_capabilities.net_admin,
            netem=host_capabilities.netem,
            ifb=FeatureState.AVAILABLE,
            classifier=host_capabilities.classifier,
            mtu=host_capabilities.mtu,
            evidence=host_capabilities.evidence,
            sys_admin=host_capabilities.sys_admin,
            pasta=host_capabilities.pasta,
        )
        plan = plan_topology(
            TopologyRequest(
                targets=("10.20.30.40/32",),
                direction=Direction.ASYMMETRIC,
                topology=TopologyKind.DANGEROUS_HOST_NETWORK,
                dangerous_confirmation="dedicated-test-vm:profile-lab",
                require_mtu=True,
                host_interface="eth0",
            ),
            host_capabilities,
            NetworkSnapshot([], [{"dev": "eth0", "kind": "fq_codel"}], ()),
        )
        profile, digest = loaded("mtu-fragmentation")
        with self.assertRaisesRegex(ProfileError, "only permitted"):
            compile_profile(plan, profile, source_sha256=digest)

    def test_cli_dry_run_prints_json_and_never_overwrites(self):
        profile_path = PROFILE_ROOT / "fixed-delay.yaml"
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            topology_path = temp / "topology.json"
            topology_path.write_text(json.dumps(topology()), encoding="utf-8")
            command = [
                sys.executable,
                str(ROOT / "bin" / "sippycup-chaos"),
                "profile-plan",
                str(topology_path),
                str(profile_path),
            ]
            completed = subprocess.run(
                command,
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["kind"], "ChaosImpairmentPlan")
            output = temp / "plan.json"
            output.write_text("operator-owned", encoding="utf-8")
            completed = subprocess.run(
                [*command, "--output", str(output)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "operator-owned")

    def test_yaml_duplicates_and_aliases_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            duplicate = Path(temporary) / "duplicate.yaml"
            duplicate.write_text("seed: 1\nseed: 2\n", encoding="utf-8")
            with self.assertRaisesRegex(ProfileError, "duplicate key"):
                load_profile(duplicate)
            alias = Path(temporary) / "alias.yaml"
            alias.write_text("value: &shared {}\ncopy: *shared\n", encoding="utf-8")
            with self.assertRaisesRegex(ProfileError, "aliases"):
                load_profile(alias)

    def test_public_schemas_and_safety_document_exist(self):
        profile_schema = json.loads(
            (ROOT / "schemas" / "chaos-profile-v1.schema.json").read_text()
        )
        plan_schema = json.loads(
            (ROOT / "schemas" / "chaos-impairment-plan-v1.schema.json").read_text()
        )
        self.assertEqual(
            profile_schema["properties"]["apiVersion"]["const"],
            "sippycup.dev/chaos-profile/v1",
        )
        self.assertEqual(
            plan_schema["properties"]["apiVersion"]["const"],
            "sippycup.dev/chaos-impairment-plan/v1",
        )
        documentation = (ROOT / "docs" / "CHAOS-PROFILES.md").read_text().lower()
        for phrase in (
            "dry run",
            "target-scope digest",
            "deterministic",
            "mandatory non-zero delay",
            "disposable router",
            "no subprocess",
        ):
            self.assertIn(phrase, documentation)


if __name__ == "__main__":
    unittest.main()
