from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_media.analysis import (  # noqa: E402
    ANALYSIS_RESULT_VERSION,
    MediaAnalysisError,
    analyze_payload,
)
from sippycup_media.canary import (  # noqa: E402
    CODECS,
    DIRECTIONS,
    encode_payload,
    synthesize,
)

ASSETS = ROOT / "media" / "canary-v1"


def facts(result: dict[str, object]) -> dict[str, dict[str, object]]:
    return {item["id"]: item for item in result["assertionFacts"]}


def pcmu_payload(transform=None) -> bytes:
    codec = CODECS[0]
    samples = list(synthesize("caller_to_callee", codec.sample_rate_hz))
    if transform is not None:
        samples = transform(samples, codec.sample_rate_hz)
    return encode_payload(samples, codec)


class MediaAnalysisCalibrationTests(unittest.TestCase):
    def test_all_codecs_and_directions_pass_calibrated_loopback(self) -> None:
        for codec in CODECS:
            for direction in DIRECTIONS:
                with self.subTest(codec=codec.name, direction=direction):
                    payload = (
                        ASSETS / f"{direction}.{codec.extension}"
                    ).read_bytes()
                    result = analyze_payload(
                        payload,
                        codec.name,
                        direction,
                        send_start_ms=1000,
                        recording_start_ms=1000,
                    )
                    self.assertEqual(result["measurementStatus"], "measured")
                    self.assertEqual(result["apiVersion"], ANALYSIS_RESULT_VERSION)
                    self.assertTrue(
                        all(marker["present"] for marker in result["markers"])
                    )
                    self.assertLessEqual(
                        abs(result["metrics"]["roundTripLatencyMs"]["value"]),
                        result["uncertainty"]["roundTripMs"],
                    )
                    self.assertEqual(
                        result["metrics"]["missingRegions"]["value"], []
                    )
                    failing = [
                        item["id"]
                        for item in result["assertionFacts"]
                        if item["verdict"] != "pass"
                    ]
                    self.assertEqual(failing, [])

    def test_delay_reports_acquisition_and_synchronized_round_trip(self) -> None:
        def delayed(samples, rate):
            return [0] * (40 * rate // 1000) + samples

        result = analyze_payload(
            pcmu_payload(delayed),
            "PCMU",
            "caller_to_callee",
            send_start_ms=5000,
            recording_start_ms=5000,
        )
        self.assertEqual(
            result["metrics"]["acquisitionTimeMs"]["value"], 140.0
        )
        self.assertEqual(
            result["metrics"]["roundTripLatencyMs"]["value"], 40.0
        )
        self.assertEqual(
            result["metrics"]["durationDriftMs"]["value"], 0.0
        )
        self.assertEqual(result["uncertainty"]["roundTripMs"], 20)
        self.assertTrue(result["claims"]["roundTripLatency"])
        self.assertFalse(result["claims"]["oneWayLatency"])
        self.assertFalse(result["claims"]["mos"])

    def test_unsynchronized_recording_never_claims_latency(self) -> None:
        result = analyze_payload(
            pcmu_payload(), "PCMU", "caller_to_callee"
        )
        self.assertEqual(
            result["metrics"]["roundTripLatencyMs"]["state"], "unknown"
        )
        self.assertEqual(
            facts(result)["media.canary.round_trip_latency"]["verdict"],
            "unknown",
        )
        self.assertFalse(result["claims"]["roundTripLatency"])
        self.assertFalse(result["claims"]["oneWayLatency"])


class IndependentDetectorTests(unittest.TestCase):
    def assert_other_facts_pass(
        self, result: dict[str, object], failing: set[str]
    ) -> None:
        ignored = {
            "media.canary.round_trip_latency",
            "media.canary.acquisition",
        }
        for identifier, item in facts(result).items():
            if identifier in ignored or identifier in failing:
                continue
            self.assertEqual(item["verdict"], "pass", identifier)

    def test_amplitude_only_trips_gain_detector(self) -> None:
        result = analyze_payload(
            pcmu_payload(
                lambda samples, _: [value // 2 for value in samples]
            ),
            "PCMU",
            "caller_to_callee",
        )
        gain = result["metrics"]["grossGainChangeDb"]["value"]
        self.assertAlmostEqual(gain, -6.0, delta=0.1)
        self.assertEqual(facts(result)["media.canary.gain"]["verdict"], "fail")
        self.assert_other_facts_pass(result, {"media.canary.gain"})

    def test_clipping_only_trips_clipping_detector(self) -> None:
        def clipped_markers(samples, rate):
            for start, end in ((100, 170), (220, 290), (340, 410)):
                for index in range(start * rate // 1000, end * rate // 1000):
                    samples[index] = max(
                        -32767, min(32767, samples[index] * 4)
                    )
            return samples

        result = analyze_payload(
            pcmu_payload(clipped_markers), "PCMU", "caller_to_callee"
        )
        self.assertGreater(result["metrics"]["clippingSamples"]["value"], 0)
        self.assertEqual(
            facts(result)["media.canary.clipping"]["verdict"], "fail"
        )
        self.assert_other_facts_pass(result, {"media.canary.clipping"})

    def test_silence_energy_only_trips_silence_detector(self) -> None:
        def noisy_silence(samples, rate):
            start = 440 * rate // 1000
            length = 100 * rate // 1000
            samples[start : start + length] = [
                1000 if index % 2 else -1000 for index in range(length)
            ]
            return samples

        result = analyze_payload(
            pcmu_payload(noisy_silence), "PCMU", "caller_to_callee"
        )
        self.assertEqual(
            result["metrics"]["unexpectedEnergyWindows"]["value"],
            ["calibrated"],
        )
        self.assertEqual(
            facts(result)["media.canary.silence"]["verdict"], "fail"
        )
        self.assert_other_facts_pass(result, {"media.canary.silence"})

    def test_loss_reports_missing_marker_and_dropout_without_masking(self) -> None:
        def marker_loss(samples, rate):
            start = 220 * rate // 1000
            end = 290 * rate // 1000
            samples[start:end] = [0] * (end - start)
            return samples

        result = analyze_payload(
            pcmu_payload(marker_loss), "PCMU", "caller_to_callee"
        )
        self.assertIn("c2s-2", result["metrics"]["missingRegions"]["value"])
        self.assertEqual(
            result["metrics"]["dropouts"]["value"],
            [{"startMs": 220, "durationMs": 80}],
        )
        failing = {"media.canary.markers", "media.canary.continuity"}
        for identifier in failing:
            self.assertEqual(facts(result)[identifier]["verdict"], "fail")
        self.assert_other_facts_pass(result, failing)

    def test_duration_only_detects_audio_beyond_expected_window(self) -> None:
        def trailing_audio(samples, rate):
            return samples + [1000] * (40 * rate // 1000)

        result = analyze_payload(
            pcmu_payload(trailing_audio), "PCMU", "caller_to_callee"
        )
        self.assertEqual(result["metrics"]["durationDriftMs"]["value"], 40.0)
        self.assertEqual(
            facts(result)["media.canary.duration"]["verdict"], "fail"
        )
        self.assert_other_facts_pass(result, {"media.canary.duration"})

    def test_direction_code_swap_is_not_mistaken_for_missing_audio(self) -> None:
        payload = encode_payload(
            synthesize("callee_to_caller", 8000), CODECS[0]
        )
        result = analyze_payload(payload, "PCMU", "caller_to_callee")
        self.assertTrue(result["metrics"]["directionSwap"]["value"])
        self.assertEqual(
            facts(result)["media.canary.direction"]["verdict"], "fail"
        )
        self.assertEqual(
            facts(result)["media.canary.continuity"]["verdict"], "pass"
        )
        self.assertEqual(
            facts(result)["media.canary.clipping"]["verdict"], "pass"
        )

    def test_all_zero_payload_reports_missing_regions_and_dropouts(self) -> None:
        payload = encode_payload([0] * 8000, CODECS[0])
        result = analyze_payload(payload, "PCMU", "caller_to_callee")
        missing = set(result["metrics"]["missingRegions"]["value"])
        self.assertTrue({"c2s-1", "c2s-2", "c2s-3"}.issubset(missing))
        self.assertTrue(result["metrics"]["dropouts"]["value"])
        self.assertEqual(
            facts(result)["media.canary.markers"]["verdict"], "fail"
        )
        self.assertEqual(
            facts(result)["media.canary.continuity"]["verdict"], "fail"
        )


class MediaAnalysisContractTests(unittest.TestCase):
    def test_unsupported_and_encrypted_are_typed_not_measurable(self) -> None:
        with mock.patch("sippycup_media.analysis.decode_payload") as decoder:
            unsupported = analyze_payload(
                b"opaque", "OPUS", "caller_to_callee"
            )
            encrypted = analyze_payload(
                b"ciphertext",
                "PCMU",
                "caller_to_callee",
                encrypted=True,
            )
            decoder.assert_not_called()
        for result, reason in (
            (unsupported, "unsupported_protocol"),
            (encrypted, "unsupported_encryption"),
        ):
            self.assertEqual(result["measurementStatus"], "not_measurable")
            self.assertEqual(result["reason"], reason)
            self.assertFalse(result["claims"]["mos"])
            self.assertFalse(result["claims"]["oneWayLatency"])
            self.assertTrue(
                all(
                    item["verdict"] == "unknown"
                    for item in result["assertionFacts"]
                )
            )
            self.assertTrue(
                all(
                    value["state"] == "unknown"
                    for value in result["metrics"].values()
                )
            )

    def test_assertion_facts_match_oracle_result_shape(self) -> None:
        result = analyze_payload(
            pcmu_payload(), "PCMU", "caller_to_callee"
        )
        oracle_schema = json.loads(
            (
                ROOT / "oracle/schemas/results-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        required = set(
            oracle_schema["$defs"]["assertion_result"]["required"]
        )
        verdicts = set(oracle_schema["$defs"]["verdict"]["enum"])
        for item in result["assertionFacts"]:
            self.assertTrue(required.issubset(item))
            self.assertIn(item["verdict"], verdicts)
            self.assertIn(item["observed"]["state"], {"known", "unknown"})
            self.assertNotIn("payload", json.dumps(item).lower())

    def test_result_schema_and_cli_contract(self) -> None:
        schema = json.loads(
            (
                ROOT / "schemas/media-analysis-result-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            schema["properties"]["apiVersion"]["const"],
            ANALYSIS_RESULT_VERSION,
        )
        completed = subprocess.run(
            [
                str(ROOT / "bin/sippycup"),
                "media",
                "analyze",
                str(ASSETS / "caller_to_callee.pcmu"),
                "--codec",
                "PCMU",
                "--direction",
                "caller_to_callee",
                "--send-start-ms",
                "1000",
                "--recording-start-ms",
                "1000",
                "--format",
                "json",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["measurementStatus"], "measured")
        serialized = json.dumps(result).lower()
        self.assertNotIn("decoded_audio", serialized)
        self.assertNotIn("pcm_bytes", serialized)
        self.assertNotIn("mos_score", serialized)

    def test_cli_not_measurable_exit_and_bounded_input(self) -> None:
        completed = subprocess.run(
            [
                str(ROOT / "bin/sippycup"),
                "media",
                "analyze",
                str(ASSETS / "caller_to_callee.pcmu"),
                "--codec",
                "OPUS",
                "--direction",
                "caller_to_callee",
                "--format",
                "json",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 4)
        self.assertEqual(
            json.loads(completed.stdout)["measurementStatus"],
            "not_measurable",
        )
        with self.assertRaisesRegex(MediaAnalysisError, "exceeds"):
            analyze_payload(
                b"\x00" * (1024 * 1024 + 1),
                "PCMU",
                "caller_to_callee",
            )

    def test_partial_or_nonfinite_timing_is_rejected(self) -> None:
        with self.assertRaisesRegex(MediaAnalysisError, "together"):
            analyze_payload(
                pcmu_payload(),
                "PCMU",
                "caller_to_callee",
                send_start_ms=0,
            )
        with self.assertRaisesRegex(MediaAnalysisError, "finite"):
            analyze_payload(
                pcmu_payload(),
                "PCMU",
                "caller_to_callee",
                send_start_ms=float("nan"),
                recording_start_ms=0,
            )


if __name__ == "__main__":
    unittest.main()
