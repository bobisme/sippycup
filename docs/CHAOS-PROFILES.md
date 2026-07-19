# Seeded chaos impairment profiles

`./bin/sippycup chaos profile-plan` validates a reviewed YAML profile, binds it to
the literal target selectors and attachment points in a frozen topology plan,
and prints a deterministic `sippycup.dev/chaos-impairment-plan/v1` document.
Compilation is a dry run: `noChange` is true, `execution.performed` is false,
and no subprocess or networking mutation is available in the compiler.

```sh
./bin/sippycup chaos topology-plan \
  --capabilities work/chaos-capabilities.json \
  --target 10.20.30.40/32 \
  --direction asymmetric \
  --namespace-prefix voice-lab \
  --output work/topology.json

./bin/sippycup chaos profile-plan \
  work/topology.json profiles/chaos/asymmetric-media.yaml \
  --output work/impairment.json

jq -r '.commands[] | [.id, (.argv | @sh)] | @tsv' work/impairment.json
```

Output files are created exclusively; an existing review artifact is never
overwritten. The final `jq` command is for human review only. Do not pipe its
output into a shell. The lifecycle component consumes the structured `argv`
arrays, verifies ownership, enforces the deadline, and performs cleanup.

## Reviewed profile set

The profiles under `profiles/chaos/` cover:

- `clean`: a control run with no mutation commands;
- `fixed-delay`: identical fixed one-way delay in both directions;
- `jitter`: bounded correlated delay variation with a named distribution;
- `burst-loss`: a Gilbert-Elliott burst-loss model;
- `constrained-uplink`: caller egress shaped by a bounded TBF rate queue;
- `reorder`: correlated reorder with mandatory non-zero delay;
- `duplicate`: correlated duplication;
- `mtu-fragmentation`: an MTU of 1280 on run-owned router interfaces; and
- `asymmetric-media`: independently specified caller and return paths.

Every profile declares a non-zero deterministic seed, a duration from 1 to
3600 seconds, and an explicit direction. `bidirectional` requires byte-for-byte
equivalent normalized settings for egress and ingress. Different settings must
be declared `asymmetric`. Netem receives a stable per-direction seed derived
from the reviewed profile seed; rate-only and clean profiles record no derived
seed because their kernel behavior is not randomized.

## Translation and scope

The compiler creates a `prio` root only for directions that need qdisc
impairment. Flower filters send only the topology plan's frozen destination
CIDRs (egress) or source CIDRs (ingress) to the impaired band. IPv4 and IPv6
selectors retain their protocol and canonical CIDR. Rate limiting uses a TBF
qdisc, with netem below it when both are requested.

MTU cannot be filtered by peer CIDR. It is therefore rejected for the
host-network topology and allowed only on the disposable router's dedicated,
run-owned interfaces after the topology capability record proves MTU support.
The target scope is still frozen in the plan, but the interface-level nature
of MTU is made explicit in the command and ownership record.

The compiler recomputes and verifies the topology's target-scope digest,
canonical CIDRs, selector direction, protocol, match expression, attachment
points, empty mutation list, and no-change marker. A missing, duplicated,
widened, or inconsistent filter fails before command generation.

## Validation limits

Percentages must be finite and between 0 and 100; enabled effects must be
greater than zero. Delay, jitter, queue, rate, burst, MTU, seed, and duration
have hard upper and lower bounds. Jitter may not exceed base delay.
Correlation or a distribution without jitter is rejected. Reorder without
delay is rejected because Linux netem cannot produce meaningful reorder in
that configuration.

A TBF rate requires exactly one queue bound: `latencyMilliseconds` or
`limitBytes`. `queuePackets` is the netem packet limit and cannot stand alone
as an ambiguous replacement for the rate queue. Unknown keys are rejected at
every level, and YAML is loaded with safe constructors.

The JSON schemas are `schemas/chaos-profile-v1.schema.json` and
`schemas/chaos-impairment-plan-v1.schema.json`. Runtime validation is stricter
than schema validation where constraints span fields or bind to topology
state.
