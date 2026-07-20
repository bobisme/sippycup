# ICE, STUN, and TURN security oracle

`sippycup webrtc ice-turn` evaluates normalized connectivity evidence without
opening a socket. It separates the reviewed policy from observations so packet
capture, a browser adapter, the independent peer, or a local coturn lab can
produce the same bounded input.

```sh
./bin/sippycup webrtc ice-turn \
  examples/webrtc/ice-turn-policy.json \
  examples/webrtc/ice-turn-observation.clean.json
```

The command returns `0` for pass, `1` for a finding, `2` for rejected input,
and `3` when required evidence is unknown. A missing selected pair, consent
observation, allocation, or cleanup proof is never promoted to pass.

The policy freezes:

- allowed candidate types, address disclosure, and private-host mDNS policy;
- literal approved STUN/TURN server tuples;
- peer CIDRs to which TURN permissions and channels may be created;
- nomination, consent freshness, and restart-credential requirements;
- credential/allocation lifetimes and TURN transports;
- permission, channel-binding, and amplification rules;
- event, packet, byte, and duration ceilings.

The observation vocabulary covers candidate gathering, server contacts,
selected pairs, consent checks, ICE restarts, TURN credentials, allocations,
permissions, channel bindings, relayed data, aggregate traffic, cleanup, and
typed peer/server/network failures. It intentionally contains no raw SDP,
candidate strings, usernames, passwords, nonces, realm values, tokens, packet
payloads, or key material.

Every event has a nondecreasing bounded timestamp and an exact data shape.
Unknown fields, hostnames, noncanonical CIDRs, booleans used as counters,
duplicate server scope, overlarge inputs, and symlink inputs fail closed.

The report carries findings and unknowns separately, identifies a single or
mixed failure domain when observed, and always sets `capacityClaim` to null.
It describes evidence; it does not authorize STUN/TURN contact or claim that a
server is safe beyond the supplied trace.
