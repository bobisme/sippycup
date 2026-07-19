from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_media.canary import (  # noqa: E402
    CANARY_VERSION,
    CLIPPING_THRESHOLD_PCM,
    CODECS,
    DIRECTIONS,
    PACKETIZATION_MS,
    SILENCE_THRESHOLD_PCM,
    check_fixture_set,
    decode_payload,
    generate_fixture_set,
    marker_specs,
    recover_markers,
)

FIXTURES = ROOT / "media" / "canary-v1"


class AudioCanaryFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(
            (FIXTURES / "manifest.json").read_text(encoding="utf-8")
        )
        cls.assets = {
            (item["direction"], item["codec"]): item
            for item in cls.manifest["assets"]
        }

    def test_manifest_covers_two_directions_and_three_codecs(self) -> None:
        self.assertEqual(self.manifest["schema"], CANARY_VERSION)
        self.assertEqual(self.manifest["license"], "CC0-1.0")
        self.assertFalse(self.manifest["synthetic_speech"])
        self.assertEqual(
            set(self.assets),
            {
                (direction, codec.name)
                for direction in DIRECTIONS
                for codec in CODECS
            },
        )
        self.assertEqual(
            self.manifest["thresholds"],
            {
                "clipping_abs_pcm": CLIPPING_THRESHOLD_PCM,
                "marker_min_correlation": 0.8,
                "marker_position_tolerance_ms": PACKETIZATION_MS,
                "silence_max_abs_pcm": SILENCE_THRESHOLD_PCM,
            },
        )

    def test_payload_hashes_packetization_and_size_are_exact(self) -> None:
        total_bytes = 0
        for codec in CODECS:
            for direction in DIRECTIONS:
                item = self.assets[(direction, codec.name)]
                payload = (FIXTURES / item["filename"]).read_bytes()
                total_bytes += len(payload)
                self.assertEqual(len(payload), 8000)
                self.assertEqual(item["encoded_bytes"], len(payload))
                self.assertEqual(item["packet_payload_bytes"], 160)
                self.assertEqual(item["packetization_ms"], 20)
                self.assertEqual(item["duration_ms"], 1000)
                self.assertEqual(
                    item["sha256"], hashlib.sha256(payload).hexdigest()
                )
                self.assertEqual(
                    len(payload) // item["packet_payload_bytes"], 50
                )
        self.assertLessEqual(total_bytes, 64 * 1024)

    def test_each_codec_recovers_every_expected_marker(self) -> None:
        threshold = self.manifest["thresholds"]["marker_min_correlation"]
        tolerance = self.manifest["thresholds"][
            "marker_position_tolerance_ms"
        ]
        for codec in CODECS:
            for direction in DIRECTIONS:
                with self.subTest(codec=codec.name, direction=direction):
                    item = self.assets[(direction, codec.name)]
                    decoded = decode_payload(
                        (FIXTURES / item["filename"]).read_bytes(), codec
                    )
                    self.assertEqual(
                        len(decoded), codec.sample_rate_hz
                    )
                    recovered = recover_markers(
                        decoded, direction, codec.sample_rate_hz
                    )
                    self.assertEqual(
                        [marker["id"] for marker in recovered],
                        [marker["id"] for marker in item["markers"]],
                    )
                    for marker in recovered:
                        self.assertGreaterEqual(
                            marker["correlation"], threshold, marker
                        )
                        self.assertLessEqual(
                            abs(
                                marker["observed_start_ms"]
                                - marker["expected_start_ms"]
                            ),
                            tolerance,
                            marker,
                        )

    def test_direction_codes_cannot_be_confused(self) -> None:
        for codec in CODECS:
            for direction in DIRECTIONS:
                other = next(item for item in DIRECTIONS if item != direction)
                decoded = decode_payload(
                    (
                        FIXTURES
                        / self.assets[(direction, codec.name)]["filename"]
                    ).read_bytes(),
                    codec,
                )
                wrong = recover_markers(decoded, other, codec.sample_rate_hz)
                self.assertTrue(
                    all(marker["correlation"] < 0.40 for marker in wrong),
                    (codec.name, direction, wrong),
                )
                self.assertTrue(
                    set(marker["id"] for marker in marker_specs(direction))
                    .isdisjoint(
                        marker["id"] for marker in marker_specs(other)
                    )
                )

    def test_silence_steps_and_clipping_thresholds_survive_decode(self) -> None:
        for codec in CODECS:
            for direction in DIRECTIONS:
                item = self.assets[(direction, codec.name)]
                decoded = decode_payload(
                    (FIXTURES / item["filename"]).read_bytes(), codec
                )
                self.assertLess(
                    max(abs(sample) for sample in decoded),
                    CLIPPING_THRESHOLD_PCM,
                )
                for window in item["silence_windows"]:
                    start = (
                        window["start_ms"] * codec.sample_rate_hz // 1000
                    )
                    end = (
                        (window["start_ms"] + window["duration_ms"])
                        * codec.sample_rate_hz
                        // 1000
                    )
                    self.assertLessEqual(
                        max(abs(sample) for sample in decoded[start:end]),
                        SILENCE_THRESHOLD_PCM,
                        (codec.name, direction, window["id"]),
                    )
                observed_levels = []
                for step in item["amplitude_steps"]:
                    start = (
                        (step["start_ms"] + 5)
                        * codec.sample_rate_hz
                        // 1000
                    )
                    end = (
                        (step["start_ms"] + step["duration_ms"] - 5)
                        * codec.sample_rate_hz
                        // 1000
                    )
                    observed = max(abs(sample) for sample in decoded[start:end])
                    observed_levels.append(observed)
                    self.assertLessEqual(
                        abs(observed - step["level_pcm"])
                        / step["level_pcm"],
                        0.05,
                        (codec.name, direction, step["id"]),
                    )
                self.assertEqual(observed_levels, sorted(observed_levels))

    def test_regeneration_is_byte_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as first_name:
            with tempfile.TemporaryDirectory() as second_name:
                first = Path(first_name)
                second = Path(second_name)
                generate_fixture_set(first)
                generate_fixture_set(second)
                first_files = {
                    item.name: item.read_bytes() for item in first.iterdir()
                }
                second_files = {
                    item.name: item.read_bytes() for item in second.iterdir()
                }
                self.assertEqual(first_files, second_files)
        self.assertTrue(check_fixture_set(FIXTURES))

    def test_check_rejects_tampering_and_unexpected_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            generate_fixture_set(temporary)
            payload = temporary / "caller_to_callee.pcmu"
            payload.write_bytes(b"\x00" + payload.read_bytes()[1:])
            self.assertFalse(check_fixture_set(temporary))
            generate_fixture_set(temporary)
            (temporary / "opaque-recording.wav").write_bytes(b"not permitted")
            self.assertFalse(check_fixture_set(temporary))

    def test_generated_assets_have_explicit_license_and_source(self) -> None:
        readme = (FIXTURES / "README.md").read_text(encoding="utf-8")
        license_text = (FIXTURES / "LICENSE.generated.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn(self.manifest["source_authority"], readme)
        self.assertIn("CC0-1.0", license_text)
        self.assertIn("No speech, recordings,", license_text)
        self.assertIn("third-party samples", license_text)


if __name__ == "__main__":
    unittest.main()
