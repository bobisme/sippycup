# WebRTC SDP negotiation oracle

`sippycup webrtc sdp` parses and evaluates WebRTC offer/answer state without
opening a socket. It does not apply SIP offer/answer assumptions.

Normalize raw SDP into bounded facts:

```sh
./bin/sippycup webrtc sdp normalize \
  examples/webrtc/audio-offer.redacted.sdp \
  --actor local --type offer
```

The normalizer accepts at most 256 KiB and 4096 bounded lines. It emits hashes
of the complete SDP, ICE credentials, and certificate fingerprint value;
those source values and the raw SDP are not emitted. The normalized form
records only negotiation facts such as mids, media directions, codec
parameters, RTCP feedback, extmaps, ICE options, DTLS setup role, and
end-of-candidates state.

Evaluate a normalized revision transcript:

```sh
./bin/sippycup webrtc sdp evaluate \
  examples/webrtc/sdp-policy.json \
  examples/webrtc/sdp-transcript.clean.json
```

The evaluator checks:

- approved DTLS-SRTP/SCTP transport profiles, complete and non-expanding
  BUNDLE groups, unique mids, and `rtcp-mux`;
- allowed media kinds, codecs, RTCP feedback, and RTP header extensions;
- trickle ICE and end-of-candidates evidence;
- fingerprint algorithms and valid offer/answer DTLS setup-role pairs;
- answer direction, codec, kind, and mid compatibility;
- pending offers, glare, rollback ownership, and retry-before-rollback;
- renegotiation generations and atomic ICE credential changes.

An unfinished offer or empty transcript is `incomplete`, never a pass. Reports
separate findings from unknown evidence, set `networkActivity` to false,
declare that raw SDP was not retained, and make no capacity claim.

Generate deterministic single and pairwise negative cases:

```sh
./bin/sippycup webrtc sdp generate \
  examples/webrtc/sdp-policy.json \
  examples/webrtc/sdp-transcript.clean.json
```

The policy caps generated cases at 128. Case IDs are derived from canonical
JSON, so repeated generation is stable.

Minimize a failing transcript while preserving one finding:

```sh
./bin/sippycup webrtc sdp minimize \
  POLICY.json FAILING-TRANSCRIPT.json sdp.rtcp_mux_required
```

The minimizer greedily removes revisions and media sections only when the
requested finding still reproduces. It never executes or contacts the
described peer.
