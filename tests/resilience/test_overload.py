import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_resilience.common import ResilienceError
from sippycup_resilience.overload import (
    analyze_overload,
    synthetic_transactions,
)


class OverloadTests(unittest.TestCase):
    def test_balanced_overload_is_bounded_and_censored(self):
        report = analyze_overload(synthetic_transactions())
        self.assertEqual(report["status"], "pass")
        self.assertEqual(set(report["clientSuccessPercent"].values()), {50.0})
        self.assertIsNone(report["capacityClaim"])

    def test_retry_after_is_honored(self):
        records = synthetic_transactions(2, 1, 0)
        first = records[0]
        records.append({**first, "atMs": 1000, "attempt": 2, "response": 200, "retryAfterMs": None})
        records.sort(key=lambda item: item["atMs"])
        self.assertEqual(
            analyze_overload(records, fairness_tolerance_percent=100)["status"],
            "pass",
        )
        records[-1]["atMs"] = 999
        codes = {
            item["code"]
            for item in analyze_overload(
                records, fairness_tolerance_percent=100
            )["findings"]
        }
        self.assertIn("retry_before_retry_after", codes)

    def test_retry_amplification_and_retry_after_non_overload_fail(self):
        records = [
            {"atMs": 0, "client": "a", "requestId": "r", "attempt": 1, "response": 200, "retryAfterMs": None},
            {"atMs": 1, "client": "a", "requestId": "r", "attempt": 2, "response": 503, "retryAfterMs": 1},
            {"atMs": 2, "client": "a", "requestId": "r", "attempt": 3, "response": 200, "retryAfterMs": None},
        ]
        codes = {item["code"] for item in analyze_overload(records)["findings"]}
        self.assertEqual(codes, {"retry_amplification", "retry_after_non_overload"})

    def test_unfair_clients_are_reported(self):
        records = synthetic_transactions(2, 4, 2)
        for item in records:
            if item["client"] == "peer-2":
                item["response"] = 503
                item["retryAfterMs"] = 1000
        report = analyze_overload(records, fairness_tolerance_percent=10)
        self.assertIn("client_unfairness", {item["code"] for item in report["findings"]})

    def test_malformed_retry_and_noncontiguous_attempts_fail_closed(self):
        record = synthetic_transactions(2, 1, 1)[0]
        record["retryAfterMs"] = 1
        with self.assertRaisesRegex(ResilienceError, "only accepted"):
            analyze_overload([record])
        records = synthetic_transactions(2, 1, 0)
        records.append({**records[0], "atMs": 1000, "attempt": 3})
        records.sort(key=lambda item: item["atMs"])
        with self.assertRaisesRegex(ResilienceError, "contiguous"):
            analyze_overload(records)


if __name__ == "__main__":
    unittest.main()
