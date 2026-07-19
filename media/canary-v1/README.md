# Deterministic audio canary v1

The codec payloads in this directory are generated artifacts. The
authoritative source is `lib/sippycup_media/canary.py`; rebuild them with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/generate_audio_canaries.py \
  media/canary-v1
PYTHONDONTWRITEBYTECODE=1 python3 tools/generate_audio_canaries.py \
  --check media/canary-v1
```

Each one-second mono payload has three direction-specific chirps, a calibrated
zero-valued silence interval, and three amplitude steps. Caller-to-callee
chirps sweep upward; callee-to-caller chirps sweep downward, use distinct
seeded frequencies, and carry different marker IDs. Assets contain no
recordings or third-party samples.

PCMU and PCMA use an 8 kHz media/RTP clock. G.722 contains 16 kHz decoded audio
but, as required by its RTP profile, uses an 8 kHz RTP clock. Every asset is
exactly 50 packets at 20 ms packetization.

The manifest's silence threshold is `104` signed 16-bit PCM units (about
-50 dBFS). A sample with absolute value at least `32760` is considered
clipped. These are analysis thresholds, not synthesis targets; authoritative
silence is exact zero before codec round-trip.

Marker recovery searches one packetization interval around each expected
position and requires normalized correlation of at least `0.80`. That
tolerance absorbs codec delay and quantization without allowing the opposite
direction's code to match.
