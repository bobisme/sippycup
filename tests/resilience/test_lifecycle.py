import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_resilience.common import ResilienceError
from sippycup_resilience.lifecycle import (
    RESOURCE_KEYS,
    SCENARIOS,
    analyze_lifecycle,
    synthetic_snapshots,
)


class LifecycleTests(unittest.TestCase):
    def test_clean_soak_covers_every_scenario_and_claims_no_scale(self):
        report = analyze_lifecycle(synthetic_snapshots(6000))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["scenariosObserved"], sorted(SCENARIOS))
        self.assertIsNone(report["scaleClaim"])

    def test_each_resource_leak_is_detected_after_settle(self):
        expected = {
            "sessions": "sessions_not_recovered",
            "sockets": "sockets_not_recovered",
            "tasks": "tasks_not_recovered",
            "memoryBytes": "memory_not_recovered",
        }
        for resource in RESOURCE_KEYS:
            with self.subTest(resource=resource):
                report = analyze_lifecycle(
                    synthetic_snapshots(8, resource), memory_tolerance_bytes=0
                )
                self.assertIn(
                    expected[resource], {item["code"] for item in report["findings"]}
                )

    def test_memory_tolerance_is_explicit(self):
        snapshots = synthetic_snapshots(2)
        snapshots[-1]["memoryBytes"] += 1024
        self.assertEqual(
            analyze_lifecycle(snapshots, memory_tolerance_bytes=1024)["status"],
            "pass",
        )
        self.assertEqual(
            analyze_lifecycle(snapshots, memory_tolerance_bytes=1023)["status"],
            "fail",
        )

    def test_nonmonotonic_or_unsettled_trace_fails_closed(self):
        snapshots = synthetic_snapshots(2)
        snapshots[-1]["cycle"] = 1
        with self.assertRaisesRegex(ResilienceError, "strictly increasing"):
            analyze_lifecycle(snapshots)
        snapshots = synthetic_snapshots(2)
        snapshots[-1]["phase"] = "baseline"
        with self.assertRaisesRegex(ResilienceError, "settled"):
            analyze_lifecycle(snapshots)

    def test_unknown_fields_and_boolean_counters_are_rejected(self):
        snapshots = synthetic_snapshots(1)
        snapshots[1]["unknown"] = 1
        with self.assertRaisesRegex(ResilienceError, "unsupported"):
            analyze_lifecycle(snapshots)
        snapshots = synthetic_snapshots(1)
        snapshots[1]["tasks"] = True
        with self.assertRaisesRegex(ResilienceError, "integer"):
            analyze_lifecycle(snapshots)


if __name__ == "__main__":
    unittest.main()
