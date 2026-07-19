import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_resilience.common import ResilienceError
from sippycup_resilience.migration import analyze_migration, default_policy


def packet(policy, **updates):
    value = {
        "source": copy.deepcopy(policy["initialTuple"]),
        "ssrc": policy["ssrc"],
        "authenticated": True,
        "consentFresh": True,
        "afterTeardown": False,
    }
    value.update(updates)
    return value


class MigrationTests(unittest.TestCase):
    def test_strict_tuple_passes_without_redirect_claim(self):
        policy = default_policy()
        report = analyze_migration(policy, [packet(policy)])
        self.assertEqual(report["status"], "pass")
        self.assertIsNone(report["redirectClaim"])

    def test_spoofed_tuple_is_rejected_and_never_becomes_active(self):
        policy = default_policy()
        forged = packet(
            policy,
            source={"address": "192.0.2.99", "port": 30000},
            authenticated=False,
        )
        report = analyze_migration(policy, [forged, packet(policy)])
        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["activeTuple"], policy["initialTuple"])
        self.assertEqual(report["acceptedPackets"], 1)

    def test_authenticated_symmetric_rebinding_is_explicit(self):
        policy = default_policy("symmetric-rtp")
        moved = packet(policy, source={"address": "192.0.2.11", "port": 30000})
        report = analyze_migration(policy, [moved])
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["activeTuple"], moved["source"])
        self.assertEqual(len(report["migrations"]), 1)

    def test_ice_consent_collision_and_late_packet_fail_independently(self):
        policy = default_policy("ice")
        packets = [
            packet(policy, consentFresh=False),
            packet(policy, ssrc=policy["ssrc"] + 1),
            packet(policy, afterTeardown=True),
        ]
        codes = {
            item["code"] for item in analyze_migration(policy, packets)["findings"]
        }
        self.assertEqual(
            codes, {"ice_consent_expired", "ssrc_collision", "packet_after_teardown"}
        )

    def test_hostnames_multicast_and_unknown_fields_fail_closed(self):
        policy = default_policy()
        policy["initialTuple"]["address"] = "voice.test"
        with self.assertRaisesRegex(ResilienceError, "IP literal"):
            analyze_migration(policy, [packet(default_policy())])
        policy = default_policy()
        value = packet(policy)
        value["unknown"] = True
        with self.assertRaisesRegex(ResilienceError, "unsupported"):
            analyze_migration(policy, [value])


if __name__ == "__main__":
    unittest.main()
