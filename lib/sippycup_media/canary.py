"""Source-authoritative deterministic audio canary generation.

The synthesized waveform uses only integer arithmetic.  FFmpeg is used solely
as a codec implementation for raw PCMU, PCMA, and G.722 payloads.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

CANARY_VERSION = "sippycup-audio-canary-v1"
SEED = 0x5A17C0DE
DURATION_MS = 1000
PACKETIZATION_MS = 20
MARKER_DURATION_MS = 70
MARKER_LEVEL = 11600
MARKER_LEVEL_DBFS = -9.0
SILENCE_THRESHOLD_PCM = 104
CLIPPING_THRESHOLD_PCM = 32760
DIRECTIONS = ("caller_to_callee", "callee_to_caller")


@dataclass(frozen=True, slots=True)
class Codec:
    name: str
    extension: str
    ffmpeg_format: str
    ffmpeg_codec: str
    sample_rate_hz: int
    rtp_clock_hz: int
    payload_type: int


CODECS = (
    Codec("PCMU", "pcmu", "mulaw", "pcm_mulaw", 8000, 8000, 0),
    Codec("PCMA", "pcma", "alaw", "pcm_alaw", 8000, 8000, 8),
    Codec("G722", "g722", "g722", "g722", 16000, 8000, 9),
)

_MARKER_STARTS_MS = (100, 220, 340)
_STEP_SPECS = (
    ("step_minus_24_dbfs", 560, 100, 2068, -24.0),
    ("step_minus_18_dbfs", 680, 100, 4125, -18.0),
    ("step_minus_12_dbfs", 800, 100, 8231, -12.0),
)
_SILENCE_WINDOWS = (
    ("leading", 0, 80),
    ("calibrated", 440, 100),
    ("trailing", 920, 80),
)


def _xorshift32(state: int) -> int:
    state ^= state << 13
    state ^= state >> 17
    state ^= state << 5
    return state & 0xFFFFFFFF


def marker_specs(direction: str) -> tuple[dict[str, int | str | float], ...]:
    if direction not in DIRECTIONS:
        raise ValueError(f"unsupported direction: {direction}")
    state = SEED ^ (0x13579BDF if direction == DIRECTIONS[0] else 0x2468ACE0)
    specs: list[dict[str, int | str | float]] = []
    bases = (620, 790, 970)
    for index, (start_ms, base) in enumerate(zip(_MARKER_STARTS_MS, bases), 1):
        state = _xorshift32(state)
        perturbation = (state % 61) - 30
        low = base + perturbation
        high = low + 310 + index * 47
        start_hz, end_hz = (
            (low, high)
            if direction == DIRECTIONS[0]
            else (high, low)
        )
        specs.append(
            {
                "id": f"{'c2s' if direction == DIRECTIONS[0] else 's2c'}-{index}",
                "start_ms": start_ms,
                "duration_ms": MARKER_DURATION_MS,
                "start_hz": start_hz,
                "end_hz": end_hz,
                "level_pcm": MARKER_LEVEL,
                "level_dbfs": MARKER_LEVEL_DBFS,
            }
        )
    return tuple(specs)


def _triangle(phase: int) -> int:
    position = (phase >> 16) & 0xFFFF
    return max(-32767, 32767 - 2 * abs(position - 32768))


def _render_chirp(
    samples: list[int],
    sample_rate_hz: int,
    *,
    start_ms: int,
    duration_ms: int,
    start_hz: int,
    end_hz: int,
    level_pcm: int,
) -> None:
    start = start_ms * sample_rate_hz // 1000
    length = duration_ms * sample_rate_hz // 1000
    fade = max(1, 5 * sample_rate_hz // 1000)
    phase = 0
    for offset in range(length):
        frequency = start_hz + (end_hz - start_hz) * offset // max(1, length - 1)
        phase = (phase + frequency * (1 << 32) // sample_rate_hz) & 0xFFFFFFFF
        envelope = min(fade, offset + 1, length - offset)
        value = _triangle(phase) * level_pcm * envelope // (32767 * fade)
        samples[start + offset] = value


def _render_tone(
    samples: list[int],
    sample_rate_hz: int,
    *,
    start_ms: int,
    duration_ms: int,
    frequency_hz: int,
    level_pcm: int,
) -> None:
    start = start_ms * sample_rate_hz // 1000
    length = duration_ms * sample_rate_hz // 1000
    fade = max(1, 5 * sample_rate_hz // 1000)
    phase = 0
    for offset in range(length):
        phase = (phase + frequency_hz * (1 << 32) // sample_rate_hz) & 0xFFFFFFFF
        envelope = min(fade, offset + 1, length - offset)
        samples[start + offset] = (
            _triangle(phase) * level_pcm * envelope // (32767 * fade)
        )


def synthesize(direction: str, sample_rate_hz: int) -> tuple[int, ...]:
    """Return the authoritative signed 16-bit mono canary waveform."""
    if sample_rate_hz not in {8000, 16000}:
        raise ValueError("canary synthesis supports only 8 kHz and 16 kHz")
    samples = [0] * (DURATION_MS * sample_rate_hz // 1000)
    for marker in marker_specs(direction):
        _render_chirp(
            samples,
            sample_rate_hz,
            start_ms=int(marker["start_ms"]),
            duration_ms=int(marker["duration_ms"]),
            start_hz=int(marker["start_hz"]),
            end_hz=int(marker["end_hz"]),
            level_pcm=int(marker["level_pcm"]),
        )
    direction_tone = 433 if direction == DIRECTIONS[0] else 467
    for _, start_ms, duration_ms, level_pcm, _ in _STEP_SPECS:
        _render_tone(
            samples,
            sample_rate_hz,
            start_ms=start_ms,
            duration_ms=duration_ms,
            frequency_hz=direction_tone,
            level_pcm=level_pcm,
        )
    return tuple(samples)


def pcm_bytes(samples: Iterable[int]) -> bytes:
    values = tuple(samples)
    return struct.pack(f"<{len(values)}h", *values)


def _run_ffmpeg(arguments: Sequence[str], payload: bytes) -> bytes:
    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg is None:
        raise RuntimeError("ffmpeg is required to generate or decode canaries")
    command = [
        ffmpeg,
        "-nostdin",
        "-hide_banner",
        "-loglevel",
        "error",
        "-fflags",
        "+bitexact",
        *arguments,
    ]
    completed = subprocess.run(
        command,
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"ffmpeg failed ({completed.returncode}): {detail}")
    return completed.stdout


def encode_payload(samples: Sequence[int], codec: Codec) -> bytes:
    return _run_ffmpeg(
        (
            "-f",
            "s16le",
            "-ar",
            str(codec.sample_rate_hz),
            "-ac",
            "1",
            "-i",
            "pipe:0",
            "-map_metadata",
            "-1",
            "-flags:a",
            "+bitexact",
            "-c:a",
            codec.ffmpeg_codec,
            "-f",
            codec.ffmpeg_format,
            "pipe:1",
        ),
        pcm_bytes(samples),
    )


def decode_payload(payload: bytes, codec: Codec) -> tuple[int, ...]:
    input_rate = (
        ()
        if codec.ffmpeg_format == "g722"
        else ("-ar", str(codec.sample_rate_hz))
    )
    decoded = _run_ffmpeg(
        (
            "-f",
            codec.ffmpeg_format,
            *input_rate,
            "-ac",
            "1",
            "-i",
            "pipe:0",
            "-map_metadata",
            "-1",
            "-flags:a",
            "+bitexact",
            "-f",
            "s16le",
            "-acodec",
            "pcm_s16le",
            "-ar",
            str(codec.sample_rate_hz),
            "-ac",
            "1",
            "pipe:1",
        ),
        payload,
    )
    if len(decoded) % 2:
        raise RuntimeError("decoder returned an odd number of PCM bytes")
    return tuple(item[0] for item in struct.iter_unpack("<h", decoded))


def _correlation(left: Sequence[int], right: Sequence[int]) -> float:
    if len(left) != len(right) or not left:
        return 0.0
    numerator = sum(a * b for a, b in zip(left, right))
    left_energy = sum(a * a for a in left)
    right_energy = sum(b * b for b in right)
    if left_energy == 0 or right_energy == 0:
        return 0.0
    return numerator / ((left_energy * right_energy) ** 0.5)


def recover_markers(
    decoded: Sequence[int],
    direction: str,
    sample_rate_hz: int,
    *,
    search_ms: int = PACKETIZATION_MS,
) -> tuple[dict[str, int | str | float], ...]:
    """Recover expected markers by local normalized cross-correlation."""
    reference = synthesize(direction, sample_rate_hz)
    search = search_ms * sample_rate_hz // 1000
    recovered: list[dict[str, int | str | float]] = []
    for marker in marker_specs(direction):
        expected = int(marker["start_ms"]) * sample_rate_hz // 1000
        length = int(marker["duration_ms"]) * sample_rate_hz // 1000
        template = reference[expected : expected + length]
        best_score = -1.0
        best_start = expected
        first = max(0, expected - search)
        last = min(len(decoded) - length, expected + search)
        for candidate in range(first, last + 1):
            score = _correlation(decoded[candidate : candidate + length], template)
            if score > best_score:
                best_score = score
                best_start = candidate
        recovered.append(
            {
                "id": str(marker["id"]),
                "expected_start_ms": int(marker["start_ms"]),
                "observed_start_ms": round(best_start * 1000 / sample_rate_hz, 3),
                "correlation": round(best_score, 6),
            }
        )
    return tuple(recovered)


def _asset_manifest(
    direction: str, codec: Codec, filename: str, payload: bytes
) -> dict[str, object]:
    return {
        "direction": direction,
        "codec": codec.name,
        "filename": filename,
        "media_sample_rate_hz": codec.sample_rate_hz,
        "rtp_clock_rate_hz": codec.rtp_clock_hz,
        "static_payload_type": codec.payload_type,
        "packetization_ms": PACKETIZATION_MS,
        "packet_payload_bytes": len(payload) * PACKETIZATION_MS // DURATION_MS,
        "duration_ms": DURATION_MS,
        "encoded_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "markers": list(marker_specs(direction)),
        "amplitude_steps": [
            {
                "id": name,
                "start_ms": start,
                "duration_ms": duration,
                "level_pcm": level,
                "level_dbfs": dbfs,
            }
            for name, start, duration, level, dbfs in _STEP_SPECS
        ],
        "silence_windows": [
            {"id": name, "start_ms": start, "duration_ms": duration}
            for name, start, duration in _SILENCE_WINDOWS
        ],
    }


def generate_fixture_set(output: Path) -> dict[str, object]:
    output.mkdir(parents=True, exist_ok=True)
    assets: list[dict[str, object]] = []
    expected_files = {
        "README.md",
        "LICENSE.generated.txt",
        "manifest.json",
    }
    for direction in DIRECTIONS:
        for codec in CODECS:
            filename = f"{direction}.{codec.extension}"
            expected_files.add(filename)
            payload = encode_payload(
                synthesize(direction, codec.sample_rate_hz), codec
            )
            (output / filename).write_bytes(payload)
            assets.append(_asset_manifest(direction, codec, filename, payload))
    for child in output.iterdir():
        if child.is_file() and child.name not in expected_files:
            child.unlink()
    manifest: dict[str, object] = {
        "schema": CANARY_VERSION,
        "seed": f"0x{SEED:08x}",
        "source_authority": "lib/sippycup_media/canary.py",
        "license": "CC0-1.0",
        "synthetic_speech": False,
        "thresholds": {
            "marker_min_correlation": 0.80,
            "silence_max_abs_pcm": SILENCE_THRESHOLD_PCM,
            "clipping_abs_pcm": CLIPPING_THRESHOLD_PCM,
            "marker_position_tolerance_ms": PACKETIZATION_MS,
        },
        "assets": assets,
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def _directory_hashes(path: Path) -> dict[str, str]:
    generated_names = _generated_names()
    return {
        child.name: hashlib.sha256(child.read_bytes()).hexdigest()
        for child in sorted(path.iterdir())
        if child.is_file() and child.name in generated_names
    }


def _generated_names() -> set[str]:
    return {
        "manifest.json",
        *(
            f"{direction}.{codec.extension}"
            for direction in DIRECTIONS
            for codec in CODECS
        ),
    }


def check_fixture_set(output: Path) -> bool:
    if not output.is_dir():
        return False
    names = {child.name for child in output.iterdir() if child.is_file()}
    allowed_names = _generated_names() | {
        "README.md",
        "LICENSE.generated.txt",
    }
    if not _generated_names().issubset(names) or not names.issubset(allowed_names):
        return False
    with tempfile.TemporaryDirectory(prefix="sippycup-canary-") as temporary:
        generated = Path(temporary)
        generate_fixture_set(generated)
        return _directory_hashes(output) == _directory_hashes(generated)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate deterministic sippycup audio canary payloads"
    )
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit nonzero unless OUTPUT exactly matches a fresh generation",
    )
    arguments = parser.parse_args(argv)
    if arguments.check:
        if check_fixture_set(arguments.output):
            print(f"canary fixtures are deterministic: {arguments.output}")
            return 0
        print(f"canary fixtures differ from fresh generation: {arguments.output}")
        return 1
    generate_fixture_set(arguments.output)
    print(f"generated {len(DIRECTIONS) * len(CODECS)} assets: {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
