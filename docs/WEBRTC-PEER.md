# Optional independent WebRTC peer

The WebRTC profile uses a small Pion endpoint built in a separate image. It is
independent of the target implementation and does not add Go, Pion, or a new
network listener to Sippycup's core image.

The dependency is pinned to Pion WebRTC v4.2.13. `go.mod` and `go.sum` freeze
the complete Go module graph, and the Go builder image is pinned by digest.
The build uses `-trimpath`, disables VCS autodiscovery, records the repository
revision plus a digest of the exact peer build inputs, and produces a static
binary. The optional image repeats that provenance in labels and inherits the
existing toolbox rather than duplicating its setup.

The low-level binary currently exposes:

- `capabilities`: a network-free, versioned adapter capability document;
- `self-test`: one bounded audio-only Pion-to-Pion call confined to the
  loopback interface and a caller-selected UDP port range;
- `version`: machine-readable build provenance.

Build and inspect it through the unified entrypoint:

```sh
./bin/sippycup webrtc status
./bin/sippycup webrtc build
./bin/sippycup webrtc capabilities
./bin/sippycup webrtc self-test
./bin/sippycup webrtc ice-turn POLICY.json OBSERVATION.json
./bin/sippycup webrtc sdp evaluate POLICY.json TRANSCRIPT.json
```

The self-test registers only PCMU audio, requires DTLS-SRTP, exchanges ICE
candidates incrementally, attaches an RTCP reader, sends exactly 50
deterministic 20 ms RTP packets, verifies the returned payload digest, has a
30-second absolute maximum deadline, gracefully closes both peers, waits for
the RTCP reader to stop, and emits normalized JSON events without SDP,
candidate addresses, ICE credentials, keys, or media payloads.

The capability document distinguishes the implementation's available
`capabilities` from `verifiedCapabilities`. Audio, trickle ICE, ICE restart,
DTLS-SRTP, and RTCP are verified by this profile. STUN and TURN UDP/TCP/TLS are
available in the pinned implementation but remain unverified here. They and
service-specific WSS signaling remain unavailable as target actions until
their dedicated oracles, signaling adapter, authorization-bound runner, and
exit gate are complete.

The profile must be launched through `bin/sippycup` before it is considered an
operator feature. Running the low-level binary directly is for development and
does not grant target authorization.
