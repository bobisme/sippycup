# DTLS-SRTP media-security oracle

`sippycup webrtc media-security` evaluates normalized DTLS, SRTP, and SRTCP
evidence without opening a socket:

```sh
./bin/sippycup webrtc media-security \
  examples/webrtc/dtls-srtp-policy.json \
  examples/webrtc/dtls-srtp-observation.clean.json
```

The policy freezes allowed DTLS versions, cipher suites, role pairs, SRTP
profiles, replay/sequence bounds, RTCP protection, rekey expectations, and
event/resource ceilings. Missing handshake, context, packet, downgrade, or
cleanup evidence produces `incomplete`, not pass.

The oracle independently checks:

- SDP fingerprint hash binding to the observed certificate fingerprint and
  the adapter's verification result;
- complementary DTLS roles plus matching peer version/cipher observations;
- rejection of disallowed-version probes before media is reached;
- allowed and peer-consistent SRTP protection profiles;
- distinct opaque RTP and RTCP key identifiers without collecting keys;
- accepted replays, invalid authentication, RTP rollover/sequence regression,
  excessive gaps, SRTCP indexes, encryption, and unknown SSRC contexts;
- monotonic epochs, changed key identifiers, context binding, and two-sided
  rekey after an observed ICE restart;
- failure closure, cleanup, and packet/SSRC/epoch/duration ceilings.

`rtpKeyIdHash` and `rtcpKeyIdHash` are hashes of adapter-generated opaque key
identifiers, not hashes of key bytes. Adapters must never expose master keys,
session keys, keying material, certificates, raw packets, or payloads to this
contract. The report always declares `sessionKeysObserved: false` and makes no
capacity or cryptographic-strength claim beyond the supplied observations.

Exit codes are `0` for pass, `1` for findings, `2` for rejected input, and `3`
for incomplete evidence. Inputs must be regular non-symlink JSON files no
larger than 4 MiB.
