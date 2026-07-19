# Calibrated canary media analysis

`sippycup media analyze` measures a returned deterministic canary from a raw
PCMU, PCMA, or G.722 payload file. It performs correlation and calibrated
region analysis without serializing decoded samples or writing a WAV file.

```sh
./bin/sippycup media analyze work/returned.pcmu \
  --codec PCMU --direction caller_to_callee \
  --send-start-ms 12000 --recording-start-ms 12000 \
  --format json
```

The two start values must come from the same local monotonic clock. With both
present, the result may report round-trip marker latency. Without them,
acquisition time is still measured from the beginning of the recording, but
round-trip latency is a typed unknown. The analyzer never labels a value as
one-way latency and never emits MOS, PESQ, or POLQA.

## Measurements and calibration

The result version is `sippycup.media-analysis-result/v1`. Every metric is a
typed known or unknown value and carries these limits:

| Measurement | Calibration / threshold |
|---|---|
| Marker recovery | correlation at least 0.80 |
| Marker position and round trip | uncertainty ±20 ms, one packet |
| G.722 decoder delay | 1.375 ms removed from path latency and duration |
| Dropout | active 20 ms region below 20% of reference RMS |
| Missing calibrated region | below 20% of reference RMS |
| Gross gain change | median step-region change beyond ±3 dB |
| Clipping | decoded magnitude at least 30,000 PCM |
| Silence energy | decoded magnitude above 104 PCM |
| Duration drift | failure beyond ±20 ms after marker alignment |

The three direction-specific markers are scored jointly under one offset, then
refined independently. This prevents a similar chirp from impersonating the
sequence and lets the opposite direction be identified as a direction swap
rather than generic missing audio.

`assertionFacts` uses the same `id`, three-state `verdict`, `applicability`,
`message`, `evidence`, and typed `observed` fields as the packet-oracle
`assertion_result` definition. A caller may prefix the IDs with its dialog ID
and merge these facts into an oracle result. The standalone analysis has no
PCAP frame evidence, so its evidence arrays are empty.

## Not-measurable boundary

Unsupported codecs and encrypted payloads return
`measurementStatus: not_measurable`, typed
`unsupported_protocol`/`unsupported_encryption` observations, and exit status
4. They never receive fabricated continuity or quality values. Invalid files,
partial/non-finite timing context, and payloads over 1 MiB exit 2.
Decoded input is bounded to ten seconds, and initial marker acquisition
searches at most 500 ms beyond its generated position.

Normal output contains only metrics, marker/region metadata, and assertion
facts. It does not contain encoded payload bytes, decoded PCM, or audio.

## Detector isolation

`make media-analyze-test` synthesizes independent fixtures for delay, gain,
marker clipping, calibrated-silence energy, marker loss, excess duration,
all-zero audio, and direction swap. Each transform changes only its intended
region where possible, and tests require unrelated detectors to continue
passing. Baselines cover both directions through PCMU, PCMA, and G.722.

The seeded impairment exit-gate results, adversarial RFC 4733 cases, and known
codec limits are recorded in
[`MEDIA-CALIBRATION.md`](MEDIA-CALIBRATION.md).
