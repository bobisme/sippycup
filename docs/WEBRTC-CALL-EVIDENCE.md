# WebRTC cross-layer call evidence

`sippycup webrtc call-evidence POLICY.json EVIDENCE.json` correlates hashed,
normalized SDP revisions, ICE pair changes, DTLS associations, SRTP/SRTCP
streams, directional audio analysis, and recovery into one offline verdict.

Every generation must form a revision → ICE → DTLS → SRTP/SRTCP chain. Media
streams must bind to the observed DTLS association, SRTCP must bind to a
matching RTP SSRC, both required directions need hashed deterministic-canary
evidence, and later generations require bounded recovery evidence.
Failed component reports fail the call; incomplete reports, encrypted audio,
partial captures, missing layers, and unknown continuity remain explicitly
incomplete.

The strict contract rejects ICE credentials, tokens, candidate addresses,
literal IP addresses, browser/device metadata, unknown fields, raw audio, and
unbounded inputs. It retains only hashes, counters, enums, SSRCs, latency, and
typed uncertainty. The report makes no capacity claim.

The policy, evidence, and report schemas are published as
`schemas/webrtc-call-{policy,evidence,report}-v1.schema.json`.
