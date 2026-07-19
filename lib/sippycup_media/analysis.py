"""Calibrated, privacy-preserving deterministic canary analysis."""

from __future__ import annotations

import math
import statistics
from pathlib import Path
from typing import Sequence

from .canary import (
    CODECS,
    DIRECTIONS,
    DURATION_MS,
    PACKETIZATION_MS,
    SILENCE_THRESHOLD_PCM,
    Codec,
    decode_payload,
    marker_specs,
    synthesize,
)

ANALYSIS_RESULT_VERSION = "sippycup.media-analysis-result/v1"
MAX_ANALYSIS_BYTES = 1024 * 1024
MAX_ANALYSIS_DURATION_MS = 10_000
MARKER_CORRELATION_MIN = 0.80
GROSS_GAIN_DB = 3.0
ANALYSIS_CLIPPING_PCM = 30_000
REGION_MISSING_RATIO = 0.20
DROPOUT_RMS_RATIO = 0.20
CODEC_DECODER_DELAY_MS = {
    "PCMU": 0.0,
    "PCMA": 0.0,
    "G722": 1.375,
}

_STEP_SPECS = (
    ("step_minus_24_dbfs", 560, 100),
    ("step_minus_18_dbfs", 680, 100),
    ("step_minus_12_dbfs", 800, 100),
)
_SILENCE_WINDOWS = (
    ("leading", 0, 80),
    ("calibrated", 440, 100),
    ("trailing", 920, 80),
)


class MediaAnalysisError(ValueError):
    """A bounded input or decoding error suitable for CLI output."""


def known(value: object) -> dict[str, object]:
    return {"state": "known", "value": value}


def unknown(reason: str, detail: str) -> dict[str, object]:
    return {"state": "unknown", "reason": reason, "detail": detail}


def _rms(values: Sequence[int]) -> float:
    if not values:
        return 0.0
    return math.sqrt(sum(value * value for value in values) / len(values))


def _correlation(left: Sequence[int], right: Sequence[int]) -> float:
    if len(left) != len(right) or not left:
        return 0.0
    numerator = sum(a * b for a, b in zip(left, right))
    left_energy = sum(a * a for a in left)
    right_energy = sum(b * b for b in right)
    if left_energy == 0 or right_energy == 0:
        return 0.0
    return numerator / math.sqrt(left_energy * right_energy)


def _best_match(
    decoded: Sequence[int],
    template: Sequence[int],
    first: int,
    last: int,
    sample_rate_hz: int,
) -> tuple[int, float]:
    if len(decoded) < len(template):
        return max(0, first), 0.0
    first = max(0, first)
    last = min(len(decoded) - len(template), last)
    if last < first:
        return first, 0.0
    coarse_step = max(1, sample_rate_hz // 1000)
    candidates = range(first, last + 1, coarse_step)
    best_start = first
    best_score = -1.0
    for candidate in candidates:
        score = _correlation(
            decoded[candidate : candidate + len(template)], template
        )
        if score > best_score:
            best_start, best_score = candidate, score
    refine_first = max(first, best_start - coarse_step)
    refine_last = min(last, best_start + coarse_step)
    for candidate in range(refine_first, refine_last + 1):
        score = _correlation(
            decoded[candidate : candidate + len(template)], template
        )
        if score > best_score:
            best_start, best_score = candidate, score
    return best_start, max(0.0, best_score)


def detect_markers(
    decoded: Sequence[int],
    direction: str,
    sample_rate_hz: int,
) -> tuple[dict[str, object], ...]:
    reference = synthesize(direction, sample_rate_hz)
    specs = marker_specs(direction)
    expected_starts = [
        int(spec["start_ms"]) * sample_rate_hz // 1000 for spec in specs
    ]
    lengths = [
        int(spec["duration_ms"]) * sample_rate_hz // 1000 for spec in specs
    ]
    templates = [
        reference[start : start + length]
        for start, length in zip(expected_starts, lengths)
    ]
    # Chirp phase is intentionally discriminative; a one-millisecond coarse
    # grid can skip the G.722 correlation peak after its decoder delay.
    step = max(1, sample_rate_hz // 4000)
    first_shift = -expected_starts[0]
    last_shift = min(
        500 * sample_rate_hz // 1000,
        len(decoded) - expected_starts[-1] - lengths[-1],
    )

    def sequence_score(shift: int) -> float:
        scores = []
        for expected, template in zip(expected_starts, templates):
            observed = expected + shift
            if observed < 0 or observed + len(template) > len(decoded):
                scores.append(0.0)
            else:
                scores.append(
                    _correlation(
                        decoded[observed : observed + len(template)], template
                    )
                )
        return statistics.median(scores)

    common_shift = first_shift
    best_sequence_score = -1.0
    for shift in range(first_shift, last_shift + 1, step):
        score = sequence_score(shift)
        if score > best_sequence_score:
            common_shift, best_sequence_score = shift, score
    for shift in range(
        max(first_shift, common_shift - step),
        min(last_shift, common_shift + step) + 1,
    ):
        score = sequence_score(shift)
        if score > best_sequence_score:
            common_shift, best_sequence_score = shift, score

    results: list[dict[str, object]] = []
    for spec in specs:
        expected = int(spec["start_ms"]) * sample_rate_hz // 1000
        length = int(spec["duration_ms"]) * sample_rate_hz // 1000
        search = PACKETIZATION_MS * sample_rate_hz // 1000
        observed, score = _best_match(
            decoded,
            reference[expected : expected + length],
            expected + common_shift - search,
            expected + common_shift + search,
            sample_rate_hz,
        )
        present = score >= MARKER_CORRELATION_MIN
        results.append(
            {
                "id": str(spec["id"]),
                "expectedStartMs": int(spec["start_ms"]),
                "observedStartMs": (
                    known(round(observed * 1000 / sample_rate_hz, 3))
                    if present
                    else unknown("missing_field", "marker not recovered")
                ),
                "correlation": round(score, 6),
                "present": present,
            }
        )
    return tuple(results)


def _marker_shift(markers: Sequence[dict[str, object]]) -> float | None:
    shifts = []
    for marker in markers:
        observed = marker["observedStartMs"]
        if observed["state"] == "known":
            shifts.append(
                float(observed["value"]) - float(marker["expectedStartMs"])
            )
    return statistics.median(shifts) if shifts else None


def _slice_ms(
    values: Sequence[int],
    sample_rate_hz: int,
    start_ms: float,
    duration_ms: int,
) -> Sequence[int]:
    start = max(0, round(start_ms * sample_rate_hz / 1000))
    end = max(start, round((start_ms + duration_ms) * sample_rate_hz / 1000))
    return values[start:min(len(values), end)]


def _merge_dropout_packets(starts: Sequence[int]) -> list[dict[str, int]]:
    if not starts:
        return []
    result: list[dict[str, int]] = []
    run_start = starts[0]
    previous = starts[0]
    for start in starts[1:]:
        if start != previous + PACKETIZATION_MS:
            result.append(
                {
                    "startMs": run_start,
                    "durationMs": previous - run_start + PACKETIZATION_MS,
                }
            )
            run_start = start
        previous = start
    result.append(
        {
            "startMs": run_start,
            "durationMs": previous - run_start + PACKETIZATION_MS,
        }
    )
    return result


def _fact(
    identifier: str,
    verdict: str,
    message: str,
    observed: dict[str, object],
) -> dict[str, object]:
    return {
        "id": identifier,
        "verdict": verdict,
        "applicability": "unknown" if verdict == "unknown" else "applicable",
        "message": message,
        "evidence": [],
        "observed": observed,
    }


def _not_measurable(
    codec_name: str,
    direction: str,
    reason: str,
    detail: str,
) -> dict[str, object]:
    observed = unknown(reason, detail)
    identifiers = (
        "acquisition",
        "round_trip_latency",
        "markers",
        "continuity",
        "clipping",
        "gain",
        "duration",
        "direction",
        "silence",
    )
    return {
        "apiVersion": ANALYSIS_RESULT_VERSION,
        "measurementStatus": "not_measurable",
        "reason": reason,
        "codec": codec_name,
        "direction": direction,
        "packetizationToleranceMs": PACKETIZATION_MS,
        "uncertainty": {
            "markerPositionMs": PACKETIZATION_MS,
            "roundTripMs": PACKETIZATION_MS,
        },
        "claims": {
            "mos": False,
            "oneWayLatency": False,
            "roundTripLatency": False,
        },
        "metrics": {
            "acquisitionTimeMs": observed,
            "roundTripLatencyMs": observed,
            "dropouts": observed,
            "clippingSamples": observed,
            "grossGainChangeDb": observed,
            "durationDriftMs": observed,
            "directionSwap": observed,
            "unexpectedEnergyWindows": observed,
            "missingRegions": observed,
        },
        "markers": [],
        "regions": [],
        "assertionFacts": [
            _fact(
                f"media.canary.{identifier}",
                "unknown",
                f"canary {identifier.replace('_', ' ')} is not measurable",
                observed,
            )
            for identifier in identifiers
        ],
    }


def analyze_payload(
    payload: bytes,
    codec_name: str,
    direction: str,
    *,
    encrypted: bool = False,
    send_start_ms: float | None = None,
    recording_start_ms: float | None = None,
) -> dict[str, object]:
    """Analyze one bounded raw codec payload without serializing decoded audio."""
    if direction not in DIRECTIONS:
        raise MediaAnalysisError(
            f"direction must be one of {', '.join(DIRECTIONS)}"
        )
    if len(payload) > MAX_ANALYSIS_BYTES:
        raise MediaAnalysisError(
            f"payload exceeds {MAX_ANALYSIS_BYTES} encoded bytes"
        )
    codec = next((item for item in CODECS if item.name == codec_name), None)
    if encrypted:
        return _not_measurable(
            codec_name,
            direction,
            "unsupported_encryption",
            "encrypted media payload cannot be decoded",
        )
    if codec is None:
        return _not_measurable(
            codec_name,
            direction,
            "unsupported_protocol",
            f"unsupported codec {codec_name}",
        )
    if (send_start_ms is None) != (recording_start_ms is None):
        raise MediaAnalysisError(
            "send and recording start times must be supplied together"
        )
    if any(
        value is not None and not math.isfinite(value)
        for value in (send_start_ms, recording_start_ms)
    ):
        raise MediaAnalysisError("timing values must be finite")
    try:
        decoded = decode_payload(payload, codec)
    except RuntimeError as error:
        raise MediaAnalysisError(f"codec decode failed: {error}") from error
    if len(decoded) > codec.sample_rate_hz * MAX_ANALYSIS_DURATION_MS // 1000:
        raise MediaAnalysisError(
            f"decoded media exceeds {MAX_ANALYSIS_DURATION_MS} ms"
        )

    own_markers = detect_markers(decoded, direction, codec.sample_rate_hz)
    other_direction = next(item for item in DIRECTIONS if item != direction)
    other_markers = detect_markers(
        decoded, other_direction, codec.sample_rate_hz
    )
    own_present = sum(bool(item["present"]) for item in own_markers)
    other_present = sum(bool(item["present"]) for item in other_markers)
    own_score = statistics.median(
        float(item["correlation"]) for item in own_markers
    )
    other_score = statistics.median(
        float(item["correlation"]) for item in other_markers
    )
    direction_swap = (
        other_present >= 2
        and (own_present < 2 or other_score > own_score + 0.20)
    )
    shift_ms = _marker_shift(own_markers)
    alignment_ms = shift_ms if shift_ms is not None else 0.0
    path_shift_ms = alignment_ms - CODEC_DECODER_DELAY_MS[codec.name]
    reference = synthesize(direction, codec.sample_rate_hz)

    missing_regions = [
        str(item["id"]) for item in own_markers if not item["present"]
    ]
    regions: list[dict[str, object]] = []
    gain_values: list[float] = []
    for identifier, start_ms, duration_ms in _STEP_SPECS:
        expected = _slice_ms(
            reference, codec.sample_rate_hz, start_ms, duration_ms
        )
        observed = _slice_ms(
            decoded,
            codec.sample_rate_hz,
            start_ms + alignment_ms,
            duration_ms,
        )
        expected_rms = _rms(expected)
        observed_rms = _rms(observed)
        ratio = observed_rms / expected_rms if expected_rms else 0.0
        missing = ratio < REGION_MISSING_RATIO
        if missing:
            missing_regions.append(identifier)
        else:
            gain_values.append(20 * math.log10(max(ratio, 1e-12)))
        regions.append(
            {
                "id": identifier,
                "kind": "amplitude_step",
                "expectedStartMs": start_ms,
                "observedRmsPcm": round(observed_rms, 3),
                "expectedRmsPcm": round(expected_rms, 3),
                "levelRatio": round(ratio, 6),
                "missing": missing,
            }
        )

    unexpected_energy: list[str] = []
    for identifier, start_ms, duration_ms in _SILENCE_WINDOWS:
        observed = _slice_ms(
            decoded,
            codec.sample_rate_hz,
            start_ms + alignment_ms,
            duration_ms,
        )
        maximum = max((abs(value) for value in observed), default=0)
        noisy = maximum > SILENCE_THRESHOLD_PCM
        if noisy:
            unexpected_energy.append(identifier)
        regions.append(
            {
                "id": identifier,
                "kind": "silence",
                "expectedStartMs": start_ms,
                "maxAbsPcm": maximum,
                "thresholdPcm": SILENCE_THRESHOLD_PCM,
                "unexpectedEnergy": noisy,
            }
        )

    dropout_starts: list[int] = []
    for start_ms in range(0, DURATION_MS, PACKETIZATION_MS):
        expected = _slice_ms(
            reference, codec.sample_rate_hz, start_ms, PACKETIZATION_MS
        )
        expected_rms = _rms(expected)
        if expected_rms <= 500:
            continue
        observed = _slice_ms(
            decoded,
            codec.sample_rate_hz,
            start_ms + alignment_ms,
            PACKETIZATION_MS,
        )
        if _rms(observed) < expected_rms * DROPOUT_RMS_RATIO:
            dropout_starts.append(start_ms)
    dropouts = _merge_dropout_packets(dropout_starts)
    clipping_samples = sum(
        abs(value) >= ANALYSIS_CLIPPING_PCM for value in decoded
    )
    gain_db = (
        round(statistics.median(gain_values), 3)
        if gain_values
        else None
    )
    gross_gain = gain_db is not None and abs(gain_db) > GROSS_GAIN_DB
    duration_ms = len(decoded) * 1000 / codec.sample_rate_hz
    duration_drift = round(
        duration_ms - DURATION_MS - max(0.0, path_shift_ms), 3
    )

    acquisition = next(
        (
            item["observedStartMs"]
            for item in own_markers
            if item["observedStartMs"]["state"] == "known"
        ),
        unknown("missing_field", "no expected marker acquired"),
    )
    if (
        send_start_ms is not None
        and recording_start_ms is not None
        and own_present
    ):
        latencies = [
            recording_start_ms
            + float(item["observedStartMs"]["value"])
            - send_start_ms
            - float(item["expectedStartMs"])
            - CODEC_DECODER_DELAY_MS[codec.name]
            for item in own_markers
            if item["observedStartMs"]["state"] == "known"
        ]
        round_trip = known(round(statistics.median(latencies), 3))
    else:
        round_trip = unknown(
            "missing_field",
            (
                "no expected marker acquired"
                if not own_present
                else "synchronized send and recording starts not supplied"
            ),
        )

    metrics = {
        "acquisitionTimeMs": acquisition,
        "roundTripLatencyMs": round_trip,
        "dropouts": known(dropouts),
        "clippingSamples": known(clipping_samples),
        "grossGainChangeDb": (
            known(gain_db)
            if gain_db is not None
            else unknown("missing_field", "calibrated gain regions missing")
        ),
        "durationDriftMs": known(duration_drift),
        "directionSwap": known(direction_swap),
        "unexpectedEnergyWindows": known(unexpected_energy),
        "missingRegions": known(missing_regions),
    }
    markers_pass = own_present == len(own_markers)
    duration_pass = abs(duration_drift) <= PACKETIZATION_MS
    facts = [
        _fact(
            "media.canary.acquisition",
            "pass" if acquisition["state"] == "known" else "unknown",
            "first expected marker acquisition time",
            acquisition,
        ),
        _fact(
            "media.canary.round_trip_latency",
            "pass" if round_trip["state"] == "known" else "unknown",
            "synchronized marker round-trip latency",
            round_trip,
        ),
        _fact(
            "media.canary.markers",
            "pass" if markers_pass else "fail",
            "all expected direction markers recovered",
            known(
                {
                    "present": own_present,
                    "expected": len(own_markers),
                    "toleranceMs": PACKETIZATION_MS,
                }
            ),
        ),
        _fact(
            "media.canary.continuity",
            "fail" if dropouts else "pass",
            "active-region packet dropouts",
            metrics["dropouts"],
        ),
        _fact(
            "media.canary.clipping",
            "fail" if clipping_samples else "pass",
            "decoded samples at calibrated clipping threshold",
            metrics["clippingSamples"],
        ),
        _fact(
            "media.canary.gain",
            (
                "unknown"
                if gain_db is None
                else ("fail" if gross_gain else "pass")
            ),
            "median calibrated amplitude-step gain change",
            metrics["grossGainChangeDb"],
        ),
        _fact(
            "media.canary.duration",
            "pass" if duration_pass else "fail",
            "duration drift after marker alignment",
            metrics["durationDriftMs"],
        ),
        _fact(
            "media.canary.direction",
            "fail" if direction_swap else "pass",
            "direction-specific marker code",
            metrics["directionSwap"],
        ),
        _fact(
            "media.canary.silence",
            "fail" if unexpected_energy else "pass",
            "unexpected energy in calibrated silence",
            metrics["unexpectedEnergyWindows"],
        ),
    ]
    return {
        "apiVersion": ANALYSIS_RESULT_VERSION,
        "measurementStatus": "measured",
        "reason": None,
        "codec": codec.name,
        "direction": direction,
        "packetizationToleranceMs": PACKETIZATION_MS,
        "uncertainty": {
            "markerPositionMs": PACKETIZATION_MS,
            "roundTripMs": PACKETIZATION_MS,
        },
        "claims": {
            "mos": False,
            "oneWayLatency": False,
            "roundTripLatency": round_trip["state"] == "known",
        },
        "metrics": metrics,
        "markers": list(own_markers),
        "regions": regions,
        "assertionFacts": facts,
    }


def load_payload(path: Path) -> bytes:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise MediaAnalysisError(f"cannot read media payload: {error}") from error
    if len(payload) > MAX_ANALYSIS_BYTES:
        raise MediaAnalysisError(
            f"payload exceeds {MAX_ANALYSIS_BYTES} encoded bytes"
        )
    return payload
