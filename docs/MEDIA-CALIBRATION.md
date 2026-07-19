# Media oracle calibration exit gate

The reproducible exit gate is:

```sh
make media-gate
```

It uses the reviewed chaos-profile seeds to drive a bounded synthetic RTP
receiver model. The model preserves the RTP time axis, de-duplicates by
sequence number, restores timestamp order, and fills lost packet slots with
codec silence. It does not require `NET_ADMIN`, mutate a qdisc, or claim to be
a measurement of the host kernel's netem implementation. Live netem
observation remains covered separately by `CHAOS-LIFECYCLE.md`.

## Recorded calibration

The results below were generated from the checked-in CC0 canaries. Timing
values include the documented ±20 ms packetization uncertainty.

| Profile | Seed | Scope | Expected result |
|---|---:|---|---|
| clean | 1001 | PCMU, PCMA, G.722; both directions | 3/3 markers, every media assertion passes, RTT 0 ms |
| fixed-delay | 1002 | all codecs | 160 ms round-trip playout delay, observed 160 ms, all content assertions pass |
| jitter | 1003 | all codecs | seeded 140 ms playout acquisition, observed 140 ms, byte-identical on three repeats |
| burst-loss | 1004 | PCMU packets 11–14 | marker and continuity fail; gain, clipping, duration, direction, and silence remain passing |
| duplicate | 1007 | one duplicated packet | transport counter increments; timestamp-aware reconstructed audio remains identical |
| reorder | 1006 | one adjacent inversion | transport counter increments; timestamp-aware reconstructed audio remains identical |

Clean minimum marker correlations are 0.999894 for PCMU, 0.999900 for PCMA,
and 0.999590 for G.722. The fixed-delay fixture hashes are
`89d24a521bf0842b95ef39e76fc5ce37a145099d977366e7b232d97eb432f998`,
`caec38ef991ae442daf7a0bd854d524431241113de3be9a891116c12675d674a`,
and `ea01894165f9e0a6698068327797f2bbd0ee3d32cca40aa11b1091b17dfaf02a`
for PCMU, PCMA, and G.722 respectively. The jitter fixture hashes in the same
order are
`4ce4d4cd55db13855e2afb2b23c8e4815ef123785b3153b569d85c4602339a4e`,
`07b222773fca1dd79fd9018181a46aa84cf122586cd0aff8c5f85091b20699a1`,
and `d7e5bd8de26c02897a774f1efaa68a2eb8edd675817934923b02eec46d3c6d4d`.

Adversarial fixtures independently prove that one absent direction/all-zero
media fails marker and continuity checks, marker clipping fails clipping
without hiding marker recovery, and malformed RFC 4733 streams fail for a
missing redundant ending, cleared end bit, or reordered digit group. The
valid `12#` stream has seven packets per digit and exactly three identical
end packets.

## Known codec and interpretation limits

- G.722 has a calibrated 1.375 ms decoder delay. Its encoder/decoder is
  stateful, so delayed silence and the canary must share one continuous codec
  clock. Concatenating independently encoded G.722 fragments can create a
  false transition and is deliberately not treated as a network fixture.
- Duplicate and reordered RTP packets are content-neutral only after a
  receiver places them by sequence/timestamp. Transport assertions must still
  report those faults; the audio analyzer consumes the reconstructed codec
  timeline rather than arrival-order bytes.
- The one-second canary has 50 audio packets. It is sufficient for marker and
  continuity calibration but below the 200-packet threshold used for precise
  chaos rate measurements. No loss percentage is inferred from this gate.
- Seeded jitter calibrates a packetized playout timeline, not an unknown
  product's jitter-buffer policy. A real Ferivox run should record its actual
  returned media and synchronized local send/recording starts.
- Round-trip latency is claimed only when those starts share a clock. One-way
  latency and MOS/PESQ/POLQA remain unclaimed.
- RFC 4733 validation is intentionally exact for Sippycup's negotiated
  8 kHz, 100 ms events: marker on the first packet, monotonic duration,
  sequence continuity, digit order, and three redundant endings.

Decoded WAV is never an implicit analyzer output. If an operator separately
retains decoded audio, the evidence inventory labels it `restricted`; normal
analysis JSON contains only typed measurements and hashes/metadata, not audio
samples.
