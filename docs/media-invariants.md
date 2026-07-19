# RTP/RTCP correlation and invariants

`lib/sippycup_oracle/media.py` maps observed RTP five-tuples, SSRCs, payload
types, and RTCP sender reports to the active offer/answer revision of one
dialog leg. Assertions return `pass`, `fail`, or `unknown` plus explicit
`applicable`, `not_applicable`, or `unknown` applicability. Every result has
frame/time evidence; when no media exists, negotiation evidence is used.

The evaluator checks:

- bidirectional media;
- negotiated or explicitly allowed endpoint addresses and ports;
- payload types, expected codecs, and RFC 4733 telephone-event traffic;
- setup windows, media before an SDP answer, and media after the BYE request;
- sequence loss, duplication, reordering, timestamp jumps, and jitter;
- unexplained payload or SSRC transitions; and
- negotiated re-INVITE/UPDATE transitions.

An address outside signaling, SDP, and explicitly allowed scope fails endpoint
validation. Symmetric RTP is represented as `symmetric_rtp`, distinct from an
exact SDP tuple, and may be disabled. A payload or SSRC change across an active
renegotiation boundary is valid; the same change without a new negotiated
revision fails.

## Metrics

Per SSRC and five-tuple, sequence numbers are extended across the 16-bit wrap:

- `received` is captured RTP packet count;
- `unique` is the number of distinct extended sequence numbers;
- `expected = max_extended - min_extended + 1`;
- `lost = max(expected - unique, 0)`;
- `duplicates` counts already-seen extended sequence numbers;
- `reordered` counts first-seen numbers below the highest previously seen.

Interarrival jitter follows RFC 3550’s estimator:

`J(i) = J(i-1) + (|D(i-1,i)| - J(i-1)) / 16`

where transit is arrival time converted to RTP clock units minus RTP
timestamp. The result is converted to milliseconds using the codec clock
rate. Timestamp continuity compares RTP timestamp delta with arrival delta in
clock units using the configured tolerance.

RTCP sender SSRC and network direction correlate reports to RTP streams.
Ambiguous or absent matches remain typed unknowns.

## Encryption and incomplete data

SRTP/SRTCP receives transport-only analysis: direction, endpoints, timing, and
packet presence remain applicable, while payload, sequence, DTMF, codec
quality, timestamp, and jitter observations hidden by encryption are unknown.
Unknown negotiation or packet fields never become passes. A disabled
expectation is `not_applicable`, not silently successful.
