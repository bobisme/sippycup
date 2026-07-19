from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import random
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup.evidence import build_evidence_manifest  # noqa: E402
from sippycup_media.analysis import analyze_payload  # noqa: E402
from sippycup_media.canary import (  # noqa: E402
    CODECS,
    DIRECTIONS,
    PACKETIZATION_MS,
    encode_payload,
    synthesize,
)
from sippycup_media.rtp import (  # noqa: E402
    MediaSessionError,
    build_packet_plan,
    load_session,
    validate_telephone_events,
)

ASSETS = ROOT / "media" / "canary-v1"
SESSION = ROOT / "tests" / "fixtures" / "media" / "session-transition.json"
PACKET_BYTES = 160


def assertion_verdicts(result: dict[str, object]) -> dict[str, str]:
    return {item["id"]: item["verdict"] for item in result["assertionFacts"]}


def split_packets(payload: bytes) -> list[bytes]:
    if len(payload) % PACKET_BYTES:
        raise AssertionError("fixture payload is not packet aligned")
    return [
        payload[index : index + PACKET_BYTES]
        for index in range(0, len(payload), PACKET_BYTES)
    ]


def silence_packets(codec) -> list[bytes]:
    return split_packets(
        encode_payload([0] * codec.sample_rate_hz, codec)
    )


def seeded_impairment(
    payload: bytes,
    codec,
    profile: str,
    seed: int,
    direction: str = "caller_to_callee",
) -> tuple[bytes, dict[str, object]]:
    """Model a timestamp-aware receiver after a deterministic network fault."""
    packets = split_packets(payload)
    silence = silence_packets(codec)
    rng = random.Random(seed)
    delay_ms = 0
    lost: list[int] = []
    duplicates = 0
    reordered = 0

    if profile == "clean":
        arrivals = list(enumerate(packets))
    elif profile == "fixed-delay":
        delay_ms = 160
        arrivals = list(enumerate(packets))
    elif profile == "jitter":
        # Two 60+/-20 ms directions, rounded to the receiver's 20 ms playout
        # quantum. Packet jitter changes arrival order; timestamps restore it.
        path_delays = [
            120 + rng.randint(-20, 20) + rng.randint(-20, 20)
            for _ in packets
        ]
        delay_ms = (
            round(max(path_delays[:5]) / PACKETIZATION_MS)
            * PACKETIZATION_MS
        )
        arrivals = sorted(
            enumerate(packets),
            key=lambda item: item[0] * PACKETIZATION_MS
            + path_delays[item[0]],
        )
        reordered = sum(
            left[0] > right[0]
            for left, right in zip(arrivals, arrivals[1:])
        )
    elif profile == "burst-loss":
        start = rng.randrange(5, 14)
        lost = list(range(start, start + 4))
        arrivals = [
            (index, packet)
            for index, packet in enumerate(packets)
            if index not in lost
        ]
    elif profile == "duplicate":
        duplicate_index = rng.randrange(len(packets))
        arrivals = list(enumerate(packets))
        arrivals.insert(
            duplicate_index + 1,
            (duplicate_index, packets[duplicate_index]),
        )
        duplicates = 1
    elif profile == "reorder":
        first = rng.randrange(5, len(packets) - 1)
        arrivals = list(enumerate(packets))
        arrivals[first], arrivals[first + 1] = (
            arrivals[first + 1],
            arrivals[first],
        )
        reordered = 1
    else:
        raise AssertionError(f"unknown calibration profile {profile}")

    # A real receiver de-duplicates and places packets by RTP timestamp. Lost
    # slots are represented as decoder silence so the time axis is preserved.
    received = {index: packet for index, packet in arrivals}
    reconstructed = [
        received.get(index, silence[index]) for index in range(len(packets))
    ]
    if delay_ms:
        # Delay is silence on one continuous codec clock. Concatenating an
        # independently encoded G.722 silence payload would reset encoder
        # state and introduce an artificial transition not caused by netem.
        output = encode_payload(
            [0] * (delay_ms * codec.sample_rate_hz // 1000)
            + list(synthesize(direction, codec.sample_rate_hz)),
            codec,
        )
    else:
        output = b"".join(reconstructed)
    return output, {
        "profile": profile,
        "seed": seed,
        "delayMs": delay_ms,
        "lostPackets": lost,
        "duplicates": duplicates,
        "reordered": reordered,
        "sha256": hashlib.sha256(output).hexdigest(),
    }


class SeededMediaCalibrationGateTests(unittest.TestCase):
    def analyze(
        self,
        payload: bytes,
        codec: str,
        direction: str = "caller_to_callee",
    ) -> dict[str, object]:
        return analyze_payload(
            payload,
            codec,
            direction,
            send_start_ms=10_000,
            recording_start_ms=10_000,
        )

    def test_clean_loopback_recovers_every_marker_for_every_codec_direction(
        self,
    ) -> None:
        for codec in CODECS:
            for direction in DIRECTIONS:
                with self.subTest(codec=codec.name, direction=direction):
                    source = (
                        ASSETS / f"{direction}.{codec.extension}"
                    ).read_bytes()
                    impaired, record = seeded_impairment(
                        source, codec, "clean", 1001, direction
                    )
                    result = self.analyze(impaired, codec.name, direction)
                    self.assertEqual(record["sha256"], hashlib.sha256(source).hexdigest())
                    self.assertTrue(all(item["present"] for item in result["markers"]))
                    self.assertLessEqual(
                        abs(result["metrics"]["roundTripLatencyMs"]["value"]),
                        PACKETIZATION_MS,
                    )
                    self.assertTrue(
                        all(
                            verdict == "pass"
                            for verdict in assertion_verdicts(result).values()
                        )
                    )

    def test_seeded_delay_and_jitter_are_repeatable_and_calibrated(self) -> None:
        for codec in CODECS:
            source = (
                ASSETS / f"caller_to_callee.{codec.extension}"
            ).read_bytes()
            with self.subTest(codec=codec.name, profile="fixed-delay"):
                impaired, record = seeded_impairment(
                    source, codec, "fixed-delay", 1002
                )
                result = self.analyze(impaired, codec.name)
                self.assertEqual(record["delayMs"], 160)
                self.assertLessEqual(
                    abs(result["metrics"]["roundTripLatencyMs"]["value"] - 160),
                    PACKETIZATION_MS,
                )
                self.assertTrue(
                    all(
                        value == "pass"
                        for value in assertion_verdicts(result).values()
                    )
                )
            with self.subTest(codec=codec.name, profile="jitter"):
                runs = [
                    seeded_impairment(source, codec, "jitter", 1003)
                    for _ in range(3)
                ]
                self.assertEqual(
                    {record["sha256"] for _, record in runs},
                    {runs[0][1]["sha256"]},
                )
                result = self.analyze(runs[0][0], codec.name)
                observed = result["metrics"]["roundTripLatencyMs"]["value"]
                self.assertLessEqual(
                    abs(observed - runs[0][1]["delayMs"]),
                    PACKETIZATION_MS,
                )
                self.assertTrue(
                    all(
                        value == "pass"
                        for value in assertion_verdicts(result).values()
                    )
                )

    def test_fault_profiles_cross_only_their_documented_boundaries(self) -> None:
        codec = CODECS[0]
        source = (ASSETS / "caller_to_callee.pcmu").read_bytes()

        lost, loss_record = seeded_impairment(
            source, codec, "burst-loss", 1004
        )
        self.assertEqual(loss_record["lostPackets"], [11, 12, 13, 14])
        loss_verdicts = assertion_verdicts(self.analyze(lost, "PCMU"))
        self.assertEqual(loss_verdicts["media.canary.markers"], "fail")
        self.assertEqual(loss_verdicts["media.canary.continuity"], "fail")
        for identifier, verdict in loss_verdicts.items():
            if identifier not in {
                "media.canary.markers",
                "media.canary.continuity",
            }:
                self.assertEqual(verdict, "pass", identifier)

        for profile, seed, counter in (
            ("duplicate", 1007, "duplicates"),
            ("reorder", 1006, "reordered"),
        ):
            with self.subTest(profile=profile):
                impaired, record = seeded_impairment(
                    source, codec, profile, seed
                )
                self.assertEqual(record[counter], 1)
                self.assertEqual(impaired, source)
                self.assertTrue(
                    all(
                        verdict == "pass"
                        for verdict in assertion_verdicts(
                            self.analyze(impaired, "PCMU")
                        ).values()
                    )
                )

    def test_one_way_all_zero_and_clipped_media_fail_independently(self) -> None:
        codec = CODECS[0]
        good = (ASSETS / "caller_to_callee.pcmu").read_bytes()
        absent = encode_payload([0] * codec.sample_rate_hz, codec)
        outgoing = self.analyze(good, "PCMU", "caller_to_callee")
        returning = self.analyze(absent, "PCMU", "callee_to_caller")
        self.assertEqual(
            assertion_verdicts(outgoing)["media.canary.markers"], "pass"
        )
        self.assertEqual(
            assertion_verdicts(returning)["media.canary.markers"], "fail"
        )
        self.assertEqual(
            assertion_verdicts(returning)["media.canary.continuity"], "fail"
        )

        clipped = list(synthesize("caller_to_callee", codec.sample_rate_hz))
        for start, end in ((100, 170), (220, 290), (340, 410)):
            for index in range(
                start * codec.sample_rate_hz // 1000,
                end * codec.sample_rate_hz // 1000,
            ):
                clipped[index] = max(
                    -32767, min(32767, clipped[index] * 4)
                )
        clipping = self.analyze(
            encode_payload(clipped, codec), "PCMU", "caller_to_callee"
        )
        self.assertEqual(
            assertion_verdicts(clipping)["media.canary.clipping"], "fail"
        )
        self.assertEqual(
            assertion_verdicts(clipping)["media.canary.markers"], "pass"
        )


class DtmfAndPrivacyExitGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = build_packet_plan(load_session(SESSION, ASSETS))
        cls.events = tuple(
            packet
            for packet in cls.plan.packets
            if packet.kind == "telephone-event"
        )

    def test_valid_rfc4733_digits_and_redundant_endings_pass(self) -> None:
        result = validate_telephone_events(self.events, "12#")
        self.assertEqual(
            result,
            {
                "status": "passed",
                "digits": "12#",
                "events": 3,
                "packets": 21,
                "redundantEndPackets": 3,
            },
        )

    def test_malformed_dtmf_variants_fail_closed(self) -> None:
        without_last_ending = self.events[:-1]
        with self.assertRaisesRegex(MediaSessionError, "endings"):
            validate_telephone_events(without_last_ending, "12#")

        malformed_payload = list(self.events)
        event, flags, duration = struct.unpack(
            "!BBH", malformed_payload[4].payload
        )
        malformed_payload[4] = replace(
            malformed_payload[4],
            payload=struct.pack("!BBH", event, flags & 0x7F, duration),
        )
        with self.assertRaisesRegex(MediaSessionError, "ending"):
            validate_telephone_events(malformed_payload, "12#")

        wrong_order = (
            self.events[7:14] + self.events[0:7] + self.events[14:]
        )
        with self.assertRaisesRegex(MediaSessionError, "sequence|digit"):
            validate_telephone_events(wrong_order, "12#")

    def test_decoded_wav_is_not_implicit_and_is_restricted_if_retained(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            required = {
                "reviewed-manifest.yaml": "apiVersion: test\n",
                "plan.json": json.dumps(
                    {
                        "authorization": {"networks": ["127.0.0.0/8"]},
                        "evidence": {"retainPayload": True},
                    }
                ),
                "commands.json": "{}\n",
                "events.jsonl": "{}\n",
                "versions.json": "{}\n",
                "preflight.json": "[]\n",
                "report.txt": "\n",
                "report.stderr": "",
                "timestamps.json": "{}\n",
                "result.json": '{"state":"succeeded"}\n',
            }
            for name, content in required.items():
                (root / name).write_text(content, encoding="utf-8")
            result = analyze_payload(
                (ASSETS / "caller_to_callee.pcmu").read_bytes(),
                "PCMU",
                "caller_to_callee",
            )
            (root / "analysis.json").write_text(
                json.dumps(result), encoding="utf-8"
            )
            self.assertEqual(list(root.glob("*.wav")), [])

            (root / "decoded.wav").write_bytes(
                b"RIFF" + b"\x00" * 4 + b"WAVEfmt " + b"\x00" * 64
            )
            manifest = build_evidence_manifest(root)
            decoded = next(
                item
                for item in manifest["artifacts"]
                if item["path"] == "decoded.wav"
            )
            self.assertEqual(decoded["sensitivity"], "restricted")


if __name__ == "__main__":
    unittest.main()
