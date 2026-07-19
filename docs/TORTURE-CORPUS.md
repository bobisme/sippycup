# Bounded protocol torture corpus

`sippycup_torture.corpus` generates a small, bit-exact robustness corpus for
offline review and later use by the guarded torture runner. Generated source is
authoritative: no opaque packet blob is required.

Every case declares provenance, validity, required dialog state, risk,
acceptable outcomes, packet and byte cost, SHA-256, and exact wire bytes. The
current corpus covers bounded RFC 4475-inspired SIP parsing cases, transaction
and dialog anomalies, contradictory SDP, RTP sequence/timestamp/SSRC/payload
transitions, RFC 4733 duration and redundancy behavior, and malformed RTCP.

The source layer cannot discover targets or open sockets. `send_exact` accepts
an already-authorized injected transport, performs one write, rejects short
writes, and never retries. Cases are limited to three packets and 4096 bytes.
Credential guessing, spoofed reflection, and unbounded amplification are
outside the corpus contract.

Use only against an explicitly authorized, isolated test target. The next
runner layer is responsible for target allowlists, dialog-state gating,
deadlines, recovery checks, and aggregate traffic budgets.

## State-aware runner

`TortureRunner` accepts an explicit case selection and injected providers for
dialog establishment, exact mutation transmission, response classification,
clean recovery canaries, health, and server-metric thresholds. Its immutable
limits default to one case, one action at a time, at most one case per second,
and a 30-second run. Hard caps prevent callers from silently turning the runner
into a load or amplification tool.

`dry_run()` lists every selected case, source hash, required dialog state, and
both selected mutation traffic and maximum aggregate traffic. A mutation is
never followed by another mutation until a distinguishable clean recovery
canary succeeds. Operator stop, duration, health, metrics, action timeout,
failure, packet, and byte ceilings all stop new cases. Evidence uses distinct
traffic-class labels and preserves the exact source mutation bytes.

## Conservative minimization

`HierarchicalMinimizer` removes message sections, headers, body lines, header
value tokens, and mutation dimensions in successive delta-debugging passes.
Candidates must remain byte subsequences of the original; destinations,
dialog states, authorization ceilings, and dimensions can never expand.

The default reproduction quorum is three of five. Only unanimous candidates
become a new reduction base; quorum-only results are labeled flaky to prevent
an unstable failure from being over-minimized. Global candidate, packet, and
byte ceilings bound the complete retest campaign. A standalone bundle records
the exact reproducer, source and result hashes, argv-style command,
authorization, expected and actual outcomes, capture frames, stability, and
the full reduction trace.

## Technical exit gate and owner review

Run the complete technical proof without target network activity:

```sh
make torture-exit-gate
```

The deterministic report exercises every case through an isolated local
datagram endpoint and proves exact bytes and packet boundaries. It also proves
that recovery failure stops admission, health failure sends no mutation, a
seeded composite failure minimizes and replays, secret-bearing command
arguments are redacted, and the corpus contains no credential, reflection, or
load behavior.

Technical success deliberately leaves `ownerReview.status` as `pending` and
`authorizationGranted` as false. Generate a machine-bound review packet:

```sh
./bin/sippycup torture review-template \
  --reviewer Quad \
  --output work/ferivox-assessment/torture-defaults-review.json
```

The packet binds Quad's review to the current corpus identity, technical-gate
digest, and these defaults:

| Ceiling | Default |
|---|---:|
| Cases | 1 |
| Mutation packets | 6 |
| Mutation bytes | 8192 |
| Rate | 1 case/second |
| Concurrency | 1 |
| Duration | 30 seconds |
| Failures | 1 |
| Action timeout | 5 seconds |

Quad can change `reviewStatus` to `approved`, add a unique `reviewId` and UTC
`reviewedAt`, and return the exact file. Validate it against the current code:

```sh
./bin/sippycup torture validate-review \
  work/ferivox-assessment/torture-defaults-review.json
```

Any code, corpus, gate, or default-limit drift invalidates the review. A valid
review acknowledges these tool defaults only. It does not authorize a target,
address, account, test window, or live packet.
