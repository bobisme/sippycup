# Immutable envelope budgets and ramp controller

`sippycup envelope` compiles a separately reviewed load authorization into a
frozen one-dimensional ramp. Planning and the current `run` command are
side-effect-free: the run command is a deterministic controller simulator and
sends no network traffic.

```sh
./bin/sippycup envelope plan examples/ferivox-envelope.yaml \
  --max-calls-per-second 4 \
  --output work/envelope-plan.json

./bin/sippycup envelope run work/envelope-plan.json \
  --manifest examples/ferivox-envelope.yaml \
  --output work/envelope-simulation.json
```

The manifest API is `sippycup.dev/envelope/v1`. Its strict schema is
`schemas/envelope-v1.schema.json`. All eight hard maxima are mandatory:

- calls per second;
- concurrent calls;
- media packets per second;
- total calls;
- total duration;
- hold duration for each ramp level;
- cooldown duration;
- recovery deadline.

Every value is a positive unsigned 64-bit integer expressed in the field's
name unit. Booleans, fractions, zero, negative values, unknown fields,
arithmetic overflow, and ramps larger than 100,000 levels fail before a plan
is produced.

## Immutable lowering

Each `--max-*` option can only lower the matching reviewed manifest maximum.
It cannot expand authorization. The plan preserves both `sourceMaxima` and
the effective `hardMaxima`; validation rejects any increase or any rewritten
step, total, schedule, intensity, or budget. `run` also requires the exact
reviewed manifest and verifies its SHA-256 before simulating.

Lowering a maximum can make a plan infeasible. That is an error when the first
level cannot fit. If at least one level fits, planning stops before the first
unfunded level and records `budget_exhausted`. It never silently starts a step
without remaining total-call and total-duration budget.

## Ramp and worst-case accounting

Exactly one of CPS, concurrency, or media PPS is selected as `ramp.dimension`.
Its workload value must equal the low starting level. Every other intensity
remains unchanged at its reviewed baseline. Levels increase by `ramp.step`;
the final level is the exact authorized dimension ceiling when aggregate
budgets permit it.

Each step carries a conservative worst-case budget:

- calls are the larger of CPS × hold time and concurrency rotations during
  the hold;
- media packets are media PPS × hold time;
- call-seconds are concurrency × hold time;
- ramp duration is the sum of completed holds.

`plannedWorstCase` also reserves the complete authorized cooldown and recovery
deadline. Checked arithmetic is used before expansion, addition, or
multiplication.

## Controller priority

The deterministic simulator starts levels on their scheduled hold boundary.
Synthetic controls may be supplied as ordered JSON:

```json
{
  "commands": [
    {"atSeconds": 20, "command": "pause"},
    {"atSeconds": 35, "command": "resume"},
    {"atSeconds": 55, "command": "stop"}
  ]
}
```

At the same timestamp, pause and stop commands take precedence over a ramp
event, and stop takes precedence over pause or resume. A pause prevents the
next level from starting; resume restarts the full hold clock. The simulator
rechecks remaining authorization before every step, produces a deterministic
event timeline, and records `networkTrafficSent: false`.

This controller deliberately does not infer a capacity knee, evaluate health,
or execute load. Subsequent components consume its immutable plan to add
observation, conservative degradation decisions, teardown, cooldown, and
recovery canaries.

The observation fusion, repeated/change-point policy, hard stops, and tested
knee-interval contract are documented in
[`ENVELOPE-DEGRADATION.md`](ENVELOPE-DEGRADATION.md).
