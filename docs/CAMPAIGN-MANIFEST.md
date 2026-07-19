# Campaign manifest v1

`campaign plan` is the fail-closed boundary between a written authorization
and future traffic-generating commands. It reads YAML, validates the complete
scope, resolves every destination, performs checked budget arithmetic, and
produces a frozen JSON plan. Planning sends no SIP, RTP, or probe traffic.
It prints to stdout by default or atomically creates the explicit `--output`
path. Ordinary system DNS may be queried for hostnames.

The normative structural schema is
[`schemas/campaign-v1.schema.yaml`](../schemas/campaign-v1.schema.yaml).
The planner additionally enforces relationships JSON Schema cannot express:

- Every resolved address must be contained by an approved CIDR.
- Target transports, signaling ports, and credential references must be
  authorized.
- Case targets must exist, case identifiers must be unique, and planned
  totals must fit the hard maxima.
- Documentation ranges, `.invalid`, `example.*`, `localhost`, and common
  placeholder words cannot be targets.
- All size and count arithmetic is checked against unsigned 64-bit limits.
- Unknown fields and unsupported case or transport combinations are errors.
- Enum spelling is normative (`udp`, `tcp`, `tls`, `options`, and `call`);
  uppercase aliases are rejected, and arrays declared unique by the schema
  reject duplicates instead of silently normalizing them.
- Per-case expectations use `sippycup.dev/case-expectations/v1` and only admit
  final/provisional status, RTP directionality, and setup-time assertions.
  Payload-, credential-, SDP-, and audio-shaped fields are rejected so private
  material cannot be copied into plans and event streams.
- Evidence directories must be relative and cannot contain `..`.

## Plan a campaign

Planning is side-effect-free with respect to SIP/RTP traffic and target state.

```sh
./bin/campaign plan tests/fixtures/campaign/valid.yaml \
  --resolve voice.test=10.20.30.40 \
  --output plan.json
```

`--resolve HOST=IP` freezes DNS without querying the resolver. Once any
`--resolve` option is supplied, every hostname must have one or more pinned
answers. Repeat it to model multiple A or AAAA answers. This is useful for
review, CI, and approving a plan that must not silently change with DNS.

The following options create a stricter plan:

```text
--max-calls
--max-packets
--max-bytes
--max-duration-seconds
--max-concurrent-calls
--max-packets-per-second
--max-calls-per-second
```

An override equal to or below the manifest ceiling is accepted. An override
above it fails; the command line can never widen authorization. A reduction
that makes the declared cases exceed the new maximum also fails rather than
silently dropping steps.

## Authorization fields

`authorization.networks` is the complete destination-address allowlist.
`signalingPorts`, `mediaPorts`, `transports`, and `credentialRefs` constrain
how those destinations may be used. Credential references are opaque names;
never put passwords, tokens, or private keys in a manifest.

All seven ceilings are mandatory:

- `calls`, `packets`, `bytes`, and `durationSeconds` limit total work.
- `concurrentCalls`, `packetsPerSecond`, and `callsPerSecond` limit intensity.

Case `budget` values are conservative per-run upper bounds, not predictions.
The compiler multiplies them by `count` and reports exact `plannedTotals`.
Executors must enforce both the frozen plan's `hardMaxima` and each step's
budget. `stopConditions` are mandatory even for a one-step campaign.
The v1 planner rejects more than 100,000 expanded steps; split a larger
authorization into separately reviewed campaigns instead of producing an
unreviewable plan or exhausting planner memory.

## Determinism and review

For the same manifest bytes, DNS answers, and reductions, JSON output is byte
stable: keys, networks, destinations, expectations, assumptions, and capture
terms are sorted. `metadata.manifestSha256` binds the plan to the exact input.
The plan contains every generated step, all resolved addresses, the capture
filter, evidence policy, exact hard maxima, computed totals, and DNS
assumptions. Review and archive it before an executor is allowed to run.
`resolutionPins` records the exact hostname-to-address map used for the later
source-manifest recompile; active execution never calls DNS.
The capture filter contains only addresses, signaling transports, and ports
referenced by generated steps, plus the authorized media range; unused
authorized targets and signaling ports are deliberately excluded.

## Finite coverage model

An optional `matrix` section records the finite behavioral space that a later
covering-array generator may select from. The compiler validates and freezes
the model, but does not expand it into traffic by itself. All twelve factors
are required when `matrix` is present:

| Factor | Accepted values |
| --- | --- |
| `transport` | `udp`, `tcp`, `tls` |
| `addressFamily` | `ipv4`, `ipv6` |
| `codec` | `pcmu`, `pcma`, `g722`, `opus` |
| `ptime` | `10`, `20`, `30`, `40`, `60` milliseconds |
| `mediaProtection` | `plain`, `sdes-srtp`, `dtls-srtp` |
| `dtmf` | `rfc4733`, `sip-info`, `inband`, `none` |
| `earlyMedia` | `disabled`, `183-sdp`, `reliable` |
| `holdReinvite` | `disabled`, `sendonly`, `inactive` |
| `teardownInitiator` | `caller`, `callee`, `timeout` |
| `duration` | integer seconds from 1 through 3600 |
| `nat` | `none`, `endpoint-nat`, `symmetric-nat` |
| `impairment` | `none`, `loss`, `jitter`, `latency`, `reorder`, `duplicate` |

Every domain is non-empty, unique, and limited to 32 values. Matrix transports
must also be authorized by `authorization.transports`.
`interactionStrength` is an integer from 1 through 12 and defaults to pairwise
strength 2 when omitted. Strength selects the desired interaction coverage; it
does not weaken any authorization ceiling.

Predicates are conjunctions. A factor may select one value or a list of
allowed values. Constraints have a stable `id`, optional `rationale`, and
exactly one of these forms:

```yaml
constraints:
  - id: tls-requires-dtls-srtp
    if: {transport: [tls]}
    then: {mediaProtection: [dtls-srtp]}
  - id: no-ipv6-nat
    exclude: {addressFamily: [ipv6], nat: [endpoint-nat, symmetric-nat]}
  - id: lab-is-ipv4
    require: {addressFamily: [ipv4]}
```

`require` limits all valid rows to its predicate, `exclude` removes matching
rows, and `if`/`then` expresses implication. Unknown factors, values outside a
declared domain, duplicate IDs, and malformed logical forms fail with the
exact field path. The compiler runs a bounded satisfiability check. If no row
can meet the model it reports an irreducible conflicting set of constraint
IDs, so removing any one reported constraint restores satisfiability.

`mandatoryCases` contain named, complete assignments of all twelve factors.
They are checked against both their domains and every logical constraint.
`riskWeights` are named predicates with a positive integer `weight` and
required human rationale. They annotate prioritization; they never authorize
traffic or override constraints. A risk annotation may also request stronger
coverage over an explicit factor subset:

```yaml
riskWeights:
  - id: secure-media
    when: {mediaProtection: [sdes-srtp, dtls-srtp]}
    weight: 5
    rationale: Keying failures have higher security impact.
    coveringFactors: [transport, codec, mediaProtection]
    interactionStrength: 3
```

The risk-specific strength must exceed the matrix-wide strength and cannot
exceed the number of selected factors.

### Deterministic covering generation

`sippycup.covering.generate_covering_array()` defaults to the model's pairwise
strength and adds every requested risk-specific higher-strength subset. For
each requested tuple it asks whether the tuple can be extended to a complete
row under all constraints. Extendable tuples enter the required ledger;
non-extendable tuples enter the excluded ledger with the directly responsible
constraint IDs when available. A deterministic greedy constructor then emits
valid rows until every required ledger entry appears.

The numeric seed only chooses among equally valid construction paths. The same
model and seed produce byte-for-byte-equivalent rows and ledgers. Different
seeds may produce different compact rows, but never different coverage claims.
Mandatory rows are emitted first. Generation refuses more than 250,000
requested tuples instead of consuming unbounded memory.

This is interaction coverage, not exhaustive testing: pairwise coverage says
that every permitted pair appeared, not that all full combinations or all
implementation defects were exercised. The Ferivox example's generated array
is over one thousand times smaller than its Cartesian product while retaining
its complete pairwise and selected three-way ledgers.

`sippycup.covering.generate_event_sequences()` performs the corresponding
operation for ordered call actions. Supported actions are `dtmf`, `hold`,
`resume`, `reinvite`, `failure`, `recover`, and terminal `hangup`. Calls begin
in an established state; `resume` requires an earlier unmatched `hold`,
`recover` requires an immediately active failure state, actions cannot occur
after `hangup`, and every generated trace ends in `hangup`. Ordered tuples are
subsequences, so `hold` then `dtmf` and `dtmf` then `hold` are distinct claims.
The result includes required and excluded ordered-tuple ledgers and is stable
for its seed.

### Compile budgeted campaign cases

`campaign matrix` combines covering rows and action traces into ordinary
`call` cases, validates the complete generated manifest through `campaign
plan`, and writes three review artifacts atomically:

```sh
./bin/campaign matrix examples/ferivox-campaign.yaml \
  --seed 20260718 \
  --manifest-output generated-campaign.json \
  --report-output matrix-report.json \
  --markdown-output matrix-report.md
```

The first `call` case in the source manifest is the budget and expectation
template. Its `count` must be 1. Matrix compilation requires one unambiguous
literal-IP target for every generated address-family/transport combination;
it never invents a destination, signaling port, address, or capability.
Generated cases retain a canonical `generated` annotation in the frozen plan:
the matrix row number, action-sequence number, complete factor assignment, and
each ordered action. Reports map the stable case ID back to those fields and
number action positions from 1.

Selection capacity is the strictest of authorized calls, packets, bytes,
duration, and optional `--max-cases`. Mandatory rows are always first and
cannot be dropped; compilation fails if the budget cannot hold all of them.
Remaining candidates are ordered by matching historical-failure weight, then
risk weight, then deterministic row order. Historical hints are a JSON list:

```json
[
  {
    "id": "regression-opus",
    "factors": {"codec": ["opus"]},
    "actions": ["reinvite"],
    "weight": 100
  }
]
```

Pass the file with `--history history.json`. Hints affect priority only. They
do not add tuples, weaken constraints, enlarge authorization, or change the
coverage claim.

The JSON report uses `sippycup.dev/matrix-report/v1` and includes Cartesian
size, generated and selected/executed size, seed, full and selected traffic
estimates, every required tuple with `coveredBy` case IDs, exact uncovered
tuples, and every excluded tuple with reasons. The Markdown view carries the
same summary, budget, uncovered set, and exclusions. When capacity truncates
the suite, both factor and ordered-action ledgers are recomputed from only the
selected cases; `complete` cannot remain true while a tuple is uncovered.

Compilation itself sends no network traffic. `executedSize` names the number
of executable cases selected into the generated manifest, not completed live
calls. The report explicitly limits its claim to constrained t-way selection;
it never calls that selection exhaustive testing or proof of correctness.
The bundled basic SIPp adapter currently consumes the selected destination
transport and call budget. The remaining generated factor/action annotation is
preserved for scenario-capable adapters and result correlation; do not report
those behaviors as observed until an adapter and packet evidence confirm them.

Run the independent compact-coverage exit gate with:

```sh
make matrix-gate
```

The gate checks 30 reproducible random constrained models against a
brute-force pair oracle, the deterministic Ferivox golden ledgers, excluded
tuple reasons, sequence ordering and recovery state, minimal unsatisfiable
conflicts, source-locked side-effect-free planning, and exact truncation
accounting. It then publishes the full-budget and authorized-sample comparison
as `sippycup.dev/matrix-gate/v1` JSON. For seed `20260718`, the reference
Cartesian size is 590,490 and the covering array is 30 rows (a 19,683:1
compaction). The full budget covers 636/636 factor tuples and 42/42 ordered
action tuples. The sample authorization selects four calls and truthfully
reports incomplete coverage; the exact counts remain golden-tested so
algorithm drift requires deliberate review.

The checked-in
[`examples/ferivox-campaign.yaml`](../examples/ferivox-campaign.yaml) documents
Ferivox-oriented allowed and excluded combinations, mandatory baseline, and
riskier secure-media/NAT interactions. It uses a private lab literal, so
planning it performs no DNS lookup and sends no probe:

```sh
./bin/campaign plan examples/ferivox-campaign.yaml --output ferivox-plan.json
```

Review the model and replace its lab scope before use. Planning only validates
and freezes the model; it does not contact Ferivox.

`--output` creates the reviewed plan atomically with mode 0600, refuses to
overwrite an existing plan, and removes its temporary file if planning is
interrupted. Its parent directory must already exist. Omitting it prints JSON
to stdout for inspection, but shell
redirection itself can create an empty destination before `campaign` starts;
use `--output` for an executable frozen plan.

## Supervised execution

`campaign run` executes an already reviewed frozen JSON plan. The exact source
manifest is mandatory:

```sh
./bin/campaign plan campaign.yaml \
  --resolve voice.test=10.20.30.40 \
  --output plan.json
./bin/campaign run plan.json \
  --manifest campaign.yaml \
  --run-root work/runs
```

Before any secret provider, directory, process, resolver, or packet is created,
the command hashes the supplied manifest bytes, recompiles them using only the
plan's frozen DNS pins and reduced maxima, and compares the entire canonical
plan. A coherent hand-written plan cannot authorize itself. `campaign execute`
is an alias with the same authorization lock and evidence lifecycle.

The bundled runner is started once per step in a new process group and receives
that step as a single JSON line on standard input. Active CLI execution does
not accept arbitrary runners. Exit zero means the step succeeded; any other
status stops the campaign. The smaller of the step budget and remaining global
duration is a hard deadline. SIGINT and SIGTERM stop new steps immediately,
terminate the active process group, wait a bounded grace period, then kill
stragglers. A successful leader is not enough: its complete process group is
confirmed empty before the next step starts.

Each run exclusively creates (and will not overwrite) an append-only event stream using
[`schemas/events-v1.schema.json`](../schemas/events-v1.schema.json). Sequence
numbers define ordering; timestamps are informational. Runner stdout and
stderr are recorded as `step.output` events up to `--output-limit` bytes
(256 KiB by default), after which output is drained and discarded with a
single truncation event. This bounds both in-memory buffering and persisted
untrusted output. Exit statuses are 0 for success, 1 for child/start failure,
124 for a deadline, 130 for SIGINT, 143 for SIGTERM, and 2 for invalid input.

Before starting a child, the runtime independently revalidates the complete
frozen plan: exact keys and lowercase enums, unique arrays, authorization
containment, literal destinations, ports/transports/credentials, budget sums
and maxima, evidence policy, SHA-256 syntax, expectations, and the minimal
capture filter. Plans are limited to 8 MiB and a runner's one-step stdin
message to 1 MiB. Stdin delivery happens on a supervised thread, so a runner
that never reads cannot hold the deadline or signal loop hostage. Cleanup
retains the process-group ID even after its leader exits, kills surviving
descendants, then executes at most 64 registered rollback actions in LIFO
order. Grace periods must be finite and non-negative.

The generic runtime itself creates no network configuration. Resource-owning
adapters use its bounded LIFO rollback registry, while the integrated
capture-to-report lifecycle below supervises capture separately around the
generic step runner.

## Capture-to-report execution

`campaign execute` wraps the supervisor in a complete evidence lifecycle:

```sh
./bin/campaign execute plan.json \
  --manifest campaign.yaml \
  --run-root work/runs \
  --interface any
```

It creates a collision-safe UTC run directory with mode 0700, starts `tcpdump`
and waits for its output file before any packet is sent, sends one bounded SIP
OPTIONS preflight to every used frozen destination, and only then dispatches
steps to SIPp/sipsak. A failed preflight stops capture and writes a failure
result without starting a call. Capture is stopped before the offline report
is generated. The directory includes the frozen plan, start/finish timestamps,
redacted command metadata, executable identities and hashes, preflight
results, structured events, capture log and PCAP, report output, and a final
result. Under rootless Podman, container root maps back to the invoking user.

Capture is a mandatory runtime control, not just an artifact. An immediate-mode
watchdog continuously checks that tcpdump remains alive and enforces total
packet, byte, call, packets-per-second, and calls-per-second ceilings from the
live PCAP. Crossing a ceiling stops admission and the active process group.
Sequential call admission independently enforces CPS. Capture death is a hard
failure. Custom runners are available only through an explicit in-process
test hook and are rejected by the active CLI.

Credential references can be supplied without putting values in command-line
arguments:

```sh
SIP_TEST_PASSWORD='...' ./bin/campaign execute plan.json \
  --manifest campaign.yaml \
  --secret-env staging-user=SIP_TEST_PASSWORD

./bin/campaign execute plan.json --manifest campaign.yaml \
  --secret-fd staging-user=3 3<secret-file
./bin/campaign execute plan.json --manifest campaign.yaml \
  --secret-provider /path/to/provider
```

The provider receives only the reference name and returns the value on stdout.
Secrets travel to a custom runner in its one-shot stdin envelope, never in
argv. Known values and SIP Authorization headers are redacted before event
persistence. The bundled SIPp runner intentionally refuses authenticated
steps because SIPp's password option would expose the value in argv; use a
runner with a safe stdin/FD credential interface for those cases.

Secret source variables and any environment variable containing a resolved
secret value are removed from capture, runner, report, and provider
environments. Providers run in their own process group with a two-second
deadline and 1 MiB output limit; timeout, overflow, or a leader that leaves
descendants triggers whole-group termination.

When `evidence.retainPayload` is false, the finalized classic PCAP keeps link,
IP, UDP, and the fixed 12-byte RTP header (payload type, sequence, timestamp,
and SSRC), but removes RTP extensions, CSRC data, and encoded media bytes.
SIP signaling payload remains available for dialog analysis. Set
`retainPayload: true` only when written authorization and evidence handling
permit storage of voice payload.

Run the real isolated capture/SIPp/report check with:

```sh
make campaign-selftest
```

Before releasing campaign changes, `make campaign-gate` runs the complete
planner/runtime/integration and oracle suites, oracle benchmark, tool smoke
test, legacy call self-test, and isolated campaign self-test.

## Errors and emergency stop

Human-readable errors are the default. Automation can request a stable,
versioned JSON error on stderr:

```sh
./bin/campaign plan campaign.yaml --error-format json
./bin/campaign execute plan.json --manifest campaign.yaml --error-format json
```

For an emergency stop, press Ctrl-C once. SIGINT stops admission of new
traffic, terminates the active step and its entire process group, stops
capture, runs registered rollback actions in reverse order, and exits 130.
SIGTERM follows the same path and exits 143. This applies during capture
startup, preflight, a running step, and report generation. Do not repeatedly
send signals: bounded graceful teardown is intentionally given a moment to
flush the PCAP and evidence files. If the terminal is lost, send SIGTERM to
the `campaign execute` PID.

The integration creates no qdisc or firewall state. Future impairment adapters
must register rollback before applying mutable network state. A crash of the
container runtime or host cannot guarantee userspace cleanup; run impairment
tests only in an isolated namespace or VM and inspect `tc qdisc show`
afterward.

Known limitations: the bundled SIPp adapter refuses authenticated calls because
SIPp exposes its password option in process argv; supply a custom stdin-aware
runner. TLS preflight uses normal certificate validation. Campaign execution
is local and sequential—there is no distributed controller.
