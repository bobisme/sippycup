from __future__ import annotations

import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys
import unittest
from types import SimpleNamespace

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup.envelope import compile_envelope_plan  # noqa: E402
from sippycup.envelope_analysis import (  # noqa: E402
    analyze_degradation,
    fuse_observation,
    run_health_adapter,
)

EXAMPLE = ROOT / "examples" / "ferivox-envelope.yaml"


def plan():
    raw = EXAMPLE.read_bytes()
    return compile_envelope_plan(yaml.safe_load(raw), hashlib.sha256(raw).hexdigest())


POLICY = {
    "staleAfterMs": 1000,
    "baselineSamples": 2,
    "metrics": {
        "call.setupP95Ms": {
            "direction": "max", "soft": 200, "hard": 500,
            "consecutive": 2, "changeDelta": 100, "required": True,
        },
        "call.timeoutRatePercent": {
            "direction": "max", "soft": 1, "hard": 5,
            "consecutive": 2, "changeDelta": 1, "required": True,
        },
    },
}


def trace(setups, timeouts=None):
    timeouts = timeouts or [0] * len(setups)
    return [
        {
            "level": index + 1,
            "atMs": index * 1000,
            "metrics": {
                "call.setupP95Ms": {
                    "state": "known", "value": setup, "source": "sipp"
                },
                "call.timeoutRatePercent": {
                    "state": "known", "value": timeout, "source": "sipp"
                },
            },
        }
        for index, (setup, timeout) in enumerate(zip(setups, timeouts))
    ]


class ObservationFusionTests(unittest.TestCase):
    def test_all_sources_are_typed_and_stale_health_is_not_healthy(self):
        sample = fuse_observation(
            level=1, at_ms=5000,
            sipp={"successRatePercent": 99, "setupP95Ms": 100,
                  "timeoutRatePercent": 0, "server5xxRatePercent": 0},
            oracle={"assertions": [{"verdict": "pass"}, {"verdict": "fail"}]},
            rtp={"lossPercent": 0.5, "jitterMs": 3},
            socket_errors=0,
            health={"state": "known", "value": 90, "observedAtMs": 3000},
            stale_after_ms=1000,
        )
        self.assertEqual(sample["metrics"]["oracle.failedAssertions"]["value"], 1)
        self.assertEqual(sample["metrics"]["health.value"]["state"], "stale")
        missing = fuse_observation(
            level=1, at_ms=0, sipp=None, oracle=None, rtp=None,
            socket_errors=None, health=None, stale_after_ms=1000,
        )
        self.assertTrue(all(v["state"] == "missing" for v in missing["metrics"].values()))

    def test_health_adapter_deadline_malformed_failure_and_known(self):
        def timeout(*_a, **_k):
            raise subprocess.TimeoutExpired(["health"], 0.1)
        self.assertEqual(
            run_health_adapter(["health"], deadline_ms=100, sampled_at_ms=1,
                               runner=timeout)["state"], "missing"
        )
        for result in (
            SimpleNamespace(returncode=1, stdout=b"", stderr=b"x"),
            SimpleNamespace(returncode=0, stdout=b"{}", stderr=b""),
        ):
            fact = run_health_adapter(
                ["health"], deadline_ms=100, sampled_at_ms=1,
                runner=lambda *_a, result=result, **_k: result,
            )
            self.assertEqual(fact["state"], "missing")
        fact = run_health_adapter(
            ["health"], deadline_ms=100, sampled_at_ms=100,
            runner=lambda *_a, **_k: SimpleNamespace(
                returncode=0,
                stdout=json.dumps({"value": 88, "observedAtMs": 90}).encode(),
                stderr=b"",
            ),
        )
        self.assertEqual((fact["state"], fact["value"]), ("known", 88.0))


class ConservativeDetectionTests(unittest.TestCase):
    def test_stable_and_noisy_runs_are_censored_not_capacity_claims(self):
        def seeded_noise():
            seeded = random.Random(224)
            return [150 + seeded.randint(-80, 80) for _ in range(5)]

        noisy = seeded_noise()
        self.assertEqual(noisy, seeded_noise())
        for values, last_clear in (
            ([100, 105, 98, 110, 103], 5),
            (noisy, 4),
        ):
            result = analyze_degradation(plan(), trace(values), POLICY)
            self.assertEqual(result["outcome"], "censored")
            self.assertIsNone(result["capacityClaim"])
            self.assertEqual(
                result["testedKneeInterval"]["lowerTestedHealthy"], last_clear
            )
            self.assertIsNone(
                result["testedKneeInterval"]["upperTestedDegraded"]
            )

    def test_gradual_change_requires_repeated_evidence_and_cites_samples(self):
        result = analyze_degradation(
            plan(), trace([100, 105, 205, 215, 240]), POLICY
        )
        self.assertEqual(result["outcome"], "degraded")
        self.assertEqual(
            result["testedKneeInterval"],
            {
                "lowerTestedHealthy": 2,
                "upperTestedDegraded": 4,
                "censoredByTestedCeiling": False,
            },
        )
        self.assertEqual(result["trigger"]["action"], "backoff")
        citation = next(
            item for item in result["trigger"]["citations"]
            if item["metric"] == "call.setupP95Ms"
        )
        self.assertEqual(citation["streak"], 2)
        self.assertEqual(citation["rule"], POLICY["metrics"]["call.setupP95Ms"])

    def test_abrupt_hard_threshold_stops_immediately(self):
        result = analyze_degradation(
            plan(), trace([100, 600]), POLICY
        )
        self.assertEqual(result["outcome"], "hard_stop")
        self.assertEqual(result["trigger"]["sampleIndex"], 1)
        self.assertEqual(result["trigger"]["action"], "stop")

    def test_hysteresis_resets_streak_until_two_adverse_samples(self):
        result = analyze_degradation(
            plan(), trace([100, 220, 180, 230, 240]), POLICY
        )
        self.assertEqual(result["trigger"]["level"], 5)
        self.assertEqual(result["testedKneeInterval"]["lowerTestedHealthy"], 3)

    def test_missing_or_stale_required_data_stops_as_unknown(self):
        samples = trace([100])
        samples[0]["metrics"]["call.setupP95Ms"] = {
            "state": "stale", "source": "sipp", "detail": "late"
        }
        result = analyze_degradation(plan(), samples, POLICY)
        self.assertEqual(result["outcome"], "unknown")
        self.assertEqual(result["trigger"]["action"], "stop")
        self.assertIsNone(result["testedKneeInterval"]["lowerTestedHealthy"])

    def test_change_point_detects_adverse_shift_below_absolute_soft_limit(self):
        policy = json.loads(json.dumps(POLICY))
        policy["metrics"]["call.setupP95Ms"].update(
            {"soft": 400, "hard": 600, "changeDelta": 80}
        )
        result = analyze_degradation(
            plan(), trace([100, 105, 190, 200]), policy
        )
        self.assertEqual(result["outcome"], "degraded")
        self.assertEqual(result["trigger"]["level"], 4)

    def test_decision_never_uses_unobserved_plan_levels(self):
        result = analyze_degradation(plan(), trace([100, 110, 120]), POLICY)
        self.assertEqual(
            result["testedKneeInterval"],
            {
                "lowerTestedHealthy": 3,
                "upperTestedDegraded": None,
                "censoredByTestedCeiling": True,
            },
        )
        bad = trace([100])
        bad[0]["level"] = 99
        with self.assertRaisesRegex(Exception, "frozen plan"):
            analyze_degradation(plan(), bad, POLICY)
        reordered = trace([100, 110])
        reordered[1]["atMs"] = -1
        with self.assertRaisesRegex(Exception, "monotonic"):
            analyze_degradation(plan(), reordered, POLICY)


if __name__ == "__main__":
    unittest.main()
