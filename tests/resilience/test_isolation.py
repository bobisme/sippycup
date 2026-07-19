import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_resilience.common import ResilienceError
from sippycup_resilience.isolation import (
    analyze_isolation,
    clean_observations,
    decode_watermark,
    plan_isolation,
    render_watermark,
)
from sippycup_media.canary import CODECS, decode_payload, encode_payload


class IsolationTests(unittest.TestCase):
    def test_plan_is_deterministic_unique_and_network_free(self):
        plan = plan_isolation(4096, "fixed")
        self.assertEqual(plan, plan_isolation(4096, "fixed"))
        self.assertEqual(len({item["marker"] for item in plan["calls"]}), 4096)
        self.assertEqual(len({item["ssrc"] for item in plan["calls"]}), 4096)
        self.assertEqual(plan["networkExecutions"], 0)

    def test_clean_observations_pass_without_capacity_claim(self):
        plan = plan_isolation(64)
        report = analyze_isolation(plan, clean_observations(plan))
        self.assertEqual(report["status"], "pass")
        self.assertIsNone(report["capacityClaim"])

    def test_cross_call_audio_and_ssrc_are_detected(self):
        plan = plan_isolation(3)
        observations = clean_observations(plan)
        observations[0]["marker"] = observations[1]["marker"]
        observations[0]["ssrc"] = observations[2]["ssrc"]
        codes = {
            item["code"] for item in analyze_isolation(plan, observations)["findings"]
        }
        self.assertEqual(codes, {"cross_call_marker", "ssrc_misassociation"})

    def test_watermarks_survive_every_supported_codec(self):
        marker = plan_isolation(2)["calls"][0]["marker"]
        for codec in CODECS:
            with self.subTest(codec=codec.name):
                pcm = render_watermark(marker, codec.sample_rate_hz)
                returned = decode_payload(encode_payload(pcm, codec), codec)
                self.assertEqual(
                    decode_watermark(returned, codec.sample_rate_hz), marker
                )

    def test_mixed_call_watermarks_have_ambiguous_symbols(self):
        plan = plan_isolation(2)
        left = render_watermark(plan["calls"][0]["marker"])
        right = render_watermark(plan["calls"][1]["marker"])
        mixed = tuple(a + b for a, b in zip(left, right))
        self.assertIn("?", decode_watermark(mixed))

    def test_wrong_tuple_late_media_and_missing_call_fail_independently(self):
        plan = plan_isolation(3)
        observations = clean_observations(plan)
        observations[0]["sourcePort"] += 2
        observations[1]["afterTeardown"] = True
        observations.pop()
        codes = {
            item["code"] for item in analyze_isolation(plan, observations)["findings"]
        }
        self.assertEqual(
            codes,
            {"source_tuple_mismatch", "media_after_teardown", "call_unobserved"},
        )

    def test_plan_and_observation_boundaries_fail_closed(self):
        plan = plan_isolation(2)
        broken = copy.deepcopy(plan)
        broken["calls"][1]["marker"] = broken["calls"][0]["marker"]
        with self.assertRaisesRegex(ResilienceError, "unique"):
            analyze_isolation(broken, [])
        observation = clean_observations(plan)[0]
        observation["extra"] = True
        with self.assertRaisesRegex(ResilienceError, "unsupported"):
            analyze_isolation(plan, [observation])


if __name__ == "__main__":
    unittest.main()
