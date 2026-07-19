# Voice-edge resilience gates

`sippycup resilience` provides five strict, network-free oracles that can be
prepared before an authorized Ferivox target exists. They consume explicit
JSON observations; they do not discover hosts, open sockets, place calls, or
claim that synthetic scale is production capacity.

## Cross-call isolation

Create deterministic, non-secret identities for 64 concurrent call paths:

```sh
./bin/sippycup resilience isolation plan --calls 64 \
  --output work/isolation-plan.json
./bin/sippycup resilience isolation demo --calls 64
./bin/sippycup resilience isolation render work/isolation-plan.json \
  call-000001 --output work/call-000001.s16le
./bin/sippycup resilience isolation decode work/call-000001.s16le
```

Each call receives a unique marker, SSRC, DTMF code, and source/destination
port. `isolation analyze PLAN OBSERVATIONS` requires every planned call to be
observed and fails on a marker owned by another call, SSRC misassociation,
source-tuple drift, missing calls, or media after teardown. The maximum
offline plan is 4,096 calls; that is identifier coverage, not authorization
to create 4,096 calls. Each 32-symbol identity can be rendered as raw PCM16;
the decoder reports ambiguous symbols when two differing call watermarks are
mixed. The watermark round-trips through the included PCMU, PCMA, and G.722
codec implementations in the exit gate.

## Lifecycle soak

Generate review data, then analyze settled counters:

```sh
./bin/sippycup resilience lifecycle simulate --cycles 6000 \
  --output work/lifecycle-snapshots.json
./bin/sippycup resilience lifecycle analyze work/lifecycle-snapshots.json
```

The trace begins with a cycle-zero baseline. Every later record is a settled
post-cleanup snapshot with `sessions`, `sockets`, `tasks`, and `memoryBytes`.
The scenario vocabulary covers answered/BYE, CANCEL/487, re-INVITE, lost-BYE
expiry, reconnect, and graceful drain/restart. Session, socket, and task
counters must return to baseline; memory has an explicit bounded tolerance.
Synthetic traces never substantiate a Ferivox scale claim.
Session-expiry scenarios model the cleanup behavior defined by
[RFC 4028](https://datatracker.ietf.org/doc/html/rfc4028).

## SIP overload and retry discipline

```sh
./bin/sippycup resilience overload demo
./bin/sippycup resilience overload analyze work/transactions.json
```

Each transaction identifies its peer, logical request, attempt, response, and
optional `retryAfterMs`. The oracle detects retries after successful requests,
attempt amplification, missing or violated Retry-After bounds, and unfair
logical-request success rates between peers. Results remain authorization
censored and do not estimate capacity.
The checks follow the overload concerns and feedback model in
[RFC 7339](https://datatracker.ietf.org/doc/html/rfc7339).

## TLS and secure media

```sh
./bin/sippycup resilience secure-media demo --profile dtls-srtp
./bin/sippycup resilience secure-media check policy.json observation.json
```

Supported review profiles are `sip-tls`, `srtp`, and `dtls-srtp`. The oracle
fails invalid certificate/hostname evidence, TLS-version downgrade, missing
required mTLS, unapproved RTP fallback, failed media authentication, accepted
replays, or exposed key material. This validates supplied observations; it
does not independently prove cryptographic strength or extract secret keys.
The secure-media expectations come from
[SRTP](https://datatracker.ietf.org/doc/html/rfc3711) and
[DTLS-SRTP](https://datatracker.ietf.org/doc/html/rfc5764).

## RTP tuple migration and spoof resistance

```sh
./bin/sippycup resilience migration demo --mode strict
./bin/sippycup resilience migration check policy.json packets.json
```

Modes are `strict`, `symmetric-rtp`, and `ice`. A new source tuple becomes
active only when the reviewed policy permits rebinding and the observation
attests authentication; ICE additionally requires fresh consent. Wrong SSRC,
failed authentication, expired consent, unauthorized tuple changes, and
post-teardown packets fail independently. Rejected tuples never become the
reply destination.
ICE consent behavior follows
[RFC 7675](https://datatracker.ietf.org/doc/html/rfc7675).
The example address `192.0.2.10` is from the documentation-only TEST-NET-1
range; it did not come from Ferivox and must be replaced only under an
approved target plan.

## Safety and exit behavior

All inputs are strict, size/count bounded, and reject unknown fields.
Generated files use exclusive creation with mode 0600. Exit status is 0 for a
passing report, 1 for a valid failing observation, and 2 for malformed input
or unsafe CLI use. The shared output schema is
`schemas/resilience-report-v1.schema.json`.

Run the complete offline gate with:

```sh
make resilience-test
```
