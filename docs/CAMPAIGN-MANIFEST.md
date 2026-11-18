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
- A case `dial.user` and a target `account.username` use one conservative
  grammar: 1-64 letters, digits, and `+ * . _ -`, starting with a letter,
  digit, `+`, or `*`. No `@`, URI parameter, header, or whitespace can reach
  a Request-URI. `dial` is valid only on a `call` case, and `account`
  requires the same target's `credentialRef`.

## Plan a campaign

Planning is side-effect-free with respect to SIP/RTP traffic and target state.

```sh
./bin/sippycup campaign plan tests/fixtures/campaign/valid.yaml \
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

`ceilings.calls` is enforced at plan time for every transport. The planner
gives each `call` step a budget of exactly one call and rejects a plan whose
call steps exceed `ceilings.calls`; the executor revalidates that bound, so a
tampered plan with more call steps than the ceiling is refused before any
directory, process, or packet exists. The capture watchdog additionally counts
cleartext `INVITE` requests, but it cannot see inside TLS, so for TLS targets
the plan-time bound (one call per step, one dialog per call step, enforced by
the softphone runner) is what holds the ceiling.

`stopConditions` accepts one optional field, `preflightServerError`
(boolean). When `true`, a 5xx or 6xx answer to the OPTIONS preflight fails the
campaign as `preflight_failed` and nothing further is sent: no later preflight
and no step. When omitted (or `false`) such an answer is recorded in
`preflight.json` as a `server_error_response` warning and the run proceeds,
because any final response proves reachability. The field is frozen into the
plan only when the manifest states it, so manifests that omit it compile to
exactly the same plan as before.
The v1 planner rejects more than 100,000 expanded steps; split a larger
authorization into separately reviewed campaigns instead of producing an
unreviewable plan or exhausting planner memory.

## Dial destinations and accounts

A `call` case can name the SIP user it dials, and a target can name the
account its calls use:

```yaml
targets:
  - name: pbx
    address: 10.20.30.40
    signaling: {transport: udp, port: 5060}
    credentialRef: staging-user          # the password's opaque name
    account:
      username: "1001"                   # digest and registration username
      realm: pbx.lab                     # optional; omit to answer any realm
      register: true                     # optional; default false
cases:
  - id: dial-echo
    type: call
    target: pbx
    count: 1
    dial: {user: "9196"}                 # sip:9196@10.20.30.40:5060
    budget: {packetsPerRun: 2500, bytesPerRun: 1200000, durationSecondsPerRun: 15}
```

The destination belongs to the case; the account belongs to the target next
to its `credentialRef`. Quote numeric users: YAML reads `9196` as an integer,
which the planner rejects. `register: true` sends REGISTER to the frozen target
address and dials only after it succeeds; `false` answers only the INVITE's
digest challenge. The password is never a manifest field.

Both are frozen into every generated `call` step (`step.dial` and
`step.account`; OPTIONS steps carry neither) and are therefore covered by the
manifest lock: `campaign run` recompiles the reviewed manifest and refuses a
plan whose dial user, username, realm, or registration flag differs. The
runtime validator also checks both independently: exact keys, the grammar,
`call` steps only, an account only with a credential reference, and the same
account on every call step of a target. Manifests without these fields compile
to exactly the same plan bytes as before they existed (golden digests in
`tests/test_softphone_runner.py`). Matrix compilation copies the template
case's `dial` into every generated case.

## DTMF and SRTP

A `call` case can send reviewed RFC 4733 digits, and a target can choose
SDES-SRTP for its calls:

```yaml
targets:
  - name: pbx
    # ...
    media: {srtp: optional}              # off | optional | mandatory
cases:
  - id: ivr-pin
    type: call
    target: pbx
    count: 1
    dial: {user: "9196"}
    call:
      dtmf: "12#,34"                     # 1-32 of 0-9 A-D * #; ',' pauses 1 s
      dtmfAfterSeconds: 1                # optional, 0-60, default 1
      durationSeconds: 10                # optional, 1-3600; not with generated
    budget: {packetsPerRun: 2500, bytesPerRun: 1200000, durationSecondsPerRun: 16}
```

Quote the digits: YAML reads `1234` as an integer, which the planner rejects.
`call` is frozen into the case's steps (`step.call`) and `media` into every
call step of the target (`step.media`); OPTIONS steps carry neither. Both are
covered by the manifest lock, and the runtime validator checks them again:
exact keys, the digit grammar and bounds, `call` steps only, a
`durationSeconds` only without `generated`, and the same `media` (or none) on
every call step of a target. Manifests without them compile to exactly the
same plan bytes as before. A call step with `call` or `media` always runs on
`campaign-softphone-runner`. DTMF digits are part of the reviewed plan: do
not put a real PIN in a manifest.

The runner sends the digits as RFC 4733 events with PJSUA's RFC 2833 console
command `dtmfAfterSeconds` after answer and never falls back to SIP INFO or
in-band tones; a peer that did not negotiate telephone-event fails the step
with `dtmf_not_negotiated`, and digits PJSUA did not send fail it with
`dtmf_not_sent`. `durationSeconds` (default 5) is how long the call stays
connected, for example to hear an IVR answer; the runner lengthens a call
that is too short for the delay plus 0.25 s per digit, 1 s per pause, and 1 s
to settle, and refuses the step (exit 2) when the budget cannot fit that.
`srtp: optional` offers RTP/AVP with `a=crypto`; `mandatory` offers RTP/SAVP
and fails the step with `srtp_not_negotiated` when SRTP is not negotiated.
SDES keys are confidential only over TLS signaling; over UDP or TCP the
runner still uses SRTP and adds the warning
`sdes-key-exposed-on-cleartext-signaling`.

The DTMF digits on the wire are in the RTP payload: a campaign capture with
`retainPayload: false` keeps only packet headers (54 bytes), so it shows the
telephone-event packets but not which digits they carry. Use
`retainPayload: true` when the capture must prove the digits.

## Codecs

A `call` case can choose the only codecs its calls offer:

```yaml
cases:
  - id: pcma-only
    type: call
    target: pbx
    count: 1
    dial: {user: "9196"}
    call:
      codecs: [PCMA]                     # offered alone (plus telephone-event)
    budget: {packetsPerRun: 2500, bytesPerRun: 1200000, durationSecondsPerRun: 12}
```

`codecs` lists 1-9 distinct names from the image's PJSUA set (`PCMU`,
`PCMA`, `G722`, `GSM`, `iLBC`, `opus`, `speex/8000`, `speex/16000`,
`speex/32000`; see `GUIDED-CALL.md`, "Codec control"), first preferred. Names
are case-insensitive in the manifest and frozen into `step.call.codecs` in
that spelling, so the manifest lock covers them. `call` now needs `dtmf` or
`codecs` (`dtmfAfterSeconds` only with `dtmf`), and `codecs` is refused
together with `generated` (whose `codec` factor already chooses). `runtime.py`
revalidates the frozen list independently (exact spelling, no duplicates, not
with `generated`), and `campaign-softphone-runner` checks it again. The field
is optional: manifests without it compile to exactly the same plan bytes as
before (golden digests in `tests/test_softphone_runner.py`).

The runner offers only these codecs (PJSUA `--dis-codec=*`, then
`--add-codec`), and its result line adds `codecs` with `requested`,
`offered`, `answered`, `negotiated`, `negotiatedPayloadType`, and
`offerOnlyRequested` from PJSUA's log. A far end that answers with a codec
it was not offered fails the step with `codec_not_offered`. A case that
expects the far end to refuse a codec sets `expectations.finalStatus: 488`.

## TLS server name and trust anchor

A TLS target can name the certificate it must present while every packet
still goes to its literal address:

```yaml
targets:
  - name: edge-tls
    address: 192.0.2.10
    signaling:
      transport: tls
      port: 5061
      tlsServerName: sbc.voice.example-corp.net   # SNI and certificate name
      tlsCaFile: work/ENGAGEMENT/owner-ca.crt      # optional private CA (PEM)
```

`tlsServerName` uses the same strict grammar as the profile field (lowercase
LDH, at most 253 characters, not an IP, no wildcard, no reserved or
placeholder name). `tlsCaFile` must be a `work/...` path to a regular PEM CA
certificate without a private key; without it the system trust store is
used. Both are valid only with transport `tls`; any other `signaling` key is
rejected, and there is no key that disables verification. Without a name,
the certificate must carry the literal address as an IP SAN.

`campaign plan` reads the CA file and freezes it into every step of the
target as `tls: {serverName, caFile, caSha256}` and adds an assumption that
states what is verified and that the name is never resolved. The manifest
lock recompiles with the frozen digest, so editing the name or digest in a
plan fails the lock, and `runtime.py` revalidates the block independently
(exact keys, transport `tls`, grammar, digest shape, the same block on every
step of a target). Before execution creates a run directory or starts
capture, it re-reads every frozen CA file and refuses, with nothing sent,
when a SHA-256 differs from the plan (`TLS CA file F changed since it was
reviewed ...; refusing to execute, nothing was sent`). Plan again after a
reviewed CA changes. Manifests without these fields compile to the same
plan bytes as before (golden digests in `tests/test_softphone_runner.py`).

The campaign preflight and `options` steps send the name as SNI and in the
Request-URI and verify it with the reviewed CA bytes loaded from memory.
`preflight.json` entries for TLS targets add
`tls: {verified, serverName, trust, caSha256}`. A TLS `call` step always runs
in `campaign-softphone-runner`, never SIPp, which does not verify
certificates; `campaign-sipp-runner` refuses a non-`options` step that
carries `tls`. The softphone runner verifies the CA bytes against the frozen
digest again, gives PJSUA a private copy, and dials the literal address with
the same namespace pinning as the guided call (see `docs/GUIDED-CALL.md`).
Its result line adds `tls: {verified, serverName, trust, caSha256, detail}`
and fails a TLS call with `tls_not_verified` unless PJSUA verified the
expected name.

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
./bin/sippycup campaign matrix examples/ferivox-campaign.yaml \
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
When a generated case runs on the softphone runner (it has a dial destination
or a credential), the runner performs transport, address family, codec
preference (`pcmu`, `pcma`, `g722`; `opus` is offered first but counted only
if negotiated), call duration, and caller-initiated teardown. Its result line
lists each factor under `factors.exercised` or `factors.notExercised` with a
reason, and each action by position: a caller `hangup`, and the first
`dtmf` action when the case's reviewed digits were sent, are performed.
Absence values it deliberately honors (`dtmf: none` when the case sends no
digits, `mediaProtection: plain` when the answered call used plain RTP,
`holdReinvite: disabled`, `impairment: none`) count as exercised.
`dtmf: rfc4733` is exercised only when the case has `call.dtmf` and PJSUA
sent every digit with telephone-event negotiated; `mediaProtection:
sdes-srtp` only when the target's `media.srtp` made SRTP active. `sip-info`,
`inband`, `dtls-srtp`, `ptime`, `earlyMedia`, `nat`, hold, and impairments
are never claimed.
A codec counts only when PJSUA reports that codec negotiated; a duration
clamped by the step budget is not exercised.

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
./bin/sippycup campaign plan examples/ferivox-campaign.yaml --output ferivox-plan.json
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
./bin/sippycup campaign plan campaign.yaml \
  --resolve voice.test=10.20.30.40 \
  --output plan.json
./bin/sippycup campaign run plan.json \
  --manifest campaign.yaml \
  --run-root work/runs
```

Before any secret provider, directory, process, resolver, or packet is created,
the command hashes the supplied manifest bytes, recompiles them using only the
plan's frozen DNS pins and reduced maxima, and compares the entire canonical
plan. A coherent hand-written plan cannot authorize itself. `campaign execute`
is an alias with the same authorization lock and evidence lifecycle.

A bundled runner is started once per step in a new process group and receives
that step as a single JSON line on standard input. Active CLI execution does
not accept arbitrary runners. Exit zero means the step succeeded; any other
status stops the campaign.

The frozen step alone selects the runner; no option, environment variable, or
path on the command line can change it:

| Step | Runner |
| --- | --- |
| `options` | `campaign-sipp-runner` (in-tree OPTIONS transaction)  |
| `call` without `dial` and without `credentialRef` | `campaign-sipp-runner` (SIPp `uac`), unchanged |
| `call` with `dial` or `credentialRef` | `campaign-softphone-runner` (PJSUA) |

`versions.json` records every runner's path and SHA-256 under `runners` and
the selection as run-length `stepRunners` ranges (`firstStep`, `lastStep`,
`runner`, `sha256`); `commands.json` lists each runner command. `runner` keeps
the first step's runner for older readers.

### Softphone runner

`campaign-softphone-runner` places exactly one PJSUA call per step through
`lib/sippycup_softphone`. Its envelope adds `context` (the frozen media port
range and networks, global expectations, `retainPayload`, and a mode-0700
`steps/NNNNNN/` artifact directory in the run directory). It:

- dials `sip:<dial.user>@<first frozen address>:<port>` over the step
  transport (`service` when a credentialed call names no `dial`), with a
  global outbound route that pins every request to that address and
  `--accept-redirect=0`;
- registers only when `account.register` is true, and dials only after the
  registration succeeds;
- takes the password value from the envelope in memory and passes it to the
  driver, which writes it only to a private mode-0600 file in a mode-0700
  `/dev/shm` directory that PJSUA reads and that is deleted. The value is
  never in argv, PJSUA's environment (variables holding it, and
  `SIPPYCUP_SECRET_*`, are removed), standard output or error, or any run
  directory file;
- plays a deterministic synthetic two-tone canary and records received audio
  only to the private temporary directory, which is deleted, unless
  `retainPayload: true`, in which case `heard.wav` is kept in the step
  directory;
- hangs up and fails when the negotiated media peer is not one of the step's
  frozen addresses or its port is outside `authorization.mediaPorts`, so all
  media stays inside the capture filter and its watchdog;
- treats `durationSecondsPerRun` as a hard limit: the call lasts the generated
  `duration` factor (5 seconds otherwise), clamped to the budget minus 3.5
  seconds of setup and teardown (4.5 with registration). It hangs up when 1.5
  seconds of budget remain, so it exits before the supervisor's deadline.
  Budgets below 5 seconds are refused;
- sends the step's `call.dtmf` digits as RFC 4733 events and uses the
  target's `media.srtp` mode (see "DTMF and SRTP");
- exits 0 only when the expected `finalStatus` (default 200) was received
  and, for a 2xx expectation, the call was answered, the registration (if
  any) succeeded, `maxSetupSeconds` held (INVITE to 2xx from PJSUA's log
  timestamps, including any digest challenge), requested DTMF was sent,
  mandatory SRTP was negotiated, and, when
  `requireBidirectionalRtp` applies (case value, else the global one), PJSUA
  counted RTP sent and received. A case that expects a non-2xx status passes
  only if the call was not answered and that status arrived. Every other
  outcome exits 1; an envelope it cannot execute safely exits 2;
- prints one secret-free JSON line (`sippycup.dev/softphone-step-result/v1`,
  at most 4 KiB) with the outcome and reasons, dial user, registration and
  its final SIP status (`registrationStatus`, for example 401 for a wrong
  password), final status, connected and setup seconds, `setup` (INVITE to
  180/183 and to 2xx), `localRtpPort`, `dtmf` (requested, sent, received,
  `method: rfc4733`, status, negotiated), `srtp` (requested, active, suite,
  answer profile), `warnings`, RTP tx/rx packet counts, codec,
  hangup side, requested/effective duration, payload policy, credentialed
  INVITE/REGISTER attempts and rejections, and matrix factors. It is recorded
  as a `step.output` event even when secrets are in use (up to 16 KiB per
  step; other runners stay silent when secrets exist). The step directory
  also holds redacted `softphone.log`, `softphone-console.txt`, and
  `softphone.json`.

A wrong password costs exactly one credentialed attempt. The image's PJSIP is
built with `PJSIP_MAX_STALE_COUNT 1` (PJSIP otherwise re-sends credentials up
to three times whenever a server answers with a new nonce, which most servers
do for a wrong password), PJSUA runs with `--rereg-delay=0` so a failed
registration is not retried, and the driver quits on the first failure. The
runner also counts credentialed transactions by CSeq in PJSUA's message log
and fails with `repeated_rejected_authentication` if more than one was
rejected. The capture watchdog counts calls by INVITE Call-ID, so the single
digest re-send of an INVITE is not mistaken for a second call. The smaller of the step budget and remaining global
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
./bin/sippycup --isolated campaign execute work/plan.json \
  --manifest work/campaign.yaml \
  --run-root work/runs \
  --interface any
```

The lifecycle runs its own `tcpdump`, so it needs `NET_RAW`. A rootless
container on the host network does not have it, and neither does an
unprivileged host shell; both stop with `capture process failed during
startup` before any traffic. With rootless Podman, use `--isolated` as shown.
The launcher then runs the packaged `campaign` in the container's private
network namespace and rewrites arguments that resolve beneath the host `work/`
directory to `/work/...`, so the plan, manifest, and run root must live there.
The other `campaign execute` examples in this document omit `--isolated` and
`work/` for brevity. Without container options the command runs directly on
the host and needs host SIPp, tcpdump, and capture privileges. OPTIONS
preflights and `options` steps use the in-tree Python client
(`lib/sippycup/options.py`), so no separate OPTIONS tool is needed.

Isolated traffic leaves through the runtime's NAT. Signaling and the bounded
preflight use symmetric response routing, but media returns only if the
target sends RTP to the observed source address.

It creates a collision-safe UTC run directory with mode 0700, starts `tcpdump`
and waits for its output file before any packet is sent, sends one bounded SIP
OPTIONS preflight to every used frozen destination, and only then dispatches
steps: `call` steps to SIPp, `options` steps to the in-tree OPTIONS client. A
failed preflight stops capture and writes a failure result without starting
a call. Capture is stopped before the offline report
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
SIP_TEST_PASSWORD='...' ./bin/sippycup campaign execute plan.json \
  --manifest campaign.yaml \
  --secret-env staging-user=SIP_TEST_PASSWORD

./bin/sippycup campaign execute plan.json --manifest campaign.yaml \
  --secret-fd staging-user=3 3<secret-file
./bin/sippycup campaign execute plan.json --manifest campaign.yaml \
  --secret-provider /path/to/provider
```

With `--isolated`, the launcher forwards each variable named by
`--secret-env REF=NAME` into the container with the runtime's name-only
`--env NAME` form, so the value never appears in the runtime's argv. Other
variables, including default `SIPPYCUP_SECRET_*` names, are not forwarded;
name them explicitly. `--secret-fd` descriptors and a host `--secret-provider`
path do not cross into the container.

The provider receives only the reference name and returns the value on stdout.
Secrets travel to the runner in its one-shot stdin envelope, never in argv.
Known values and SIP Authorization headers are redacted before event
persistence. A credentialed `call` step always runs on the softphone runner;
the bundled SIPp runner still refuses any step with credentials because SIPp's
password option would expose the value in argv. OPTIONS steps of a
credentialed target are sent unauthenticated, and their envelope carries
no credential value.

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

Run the isolated softphone-runner check with:

```sh
make campaign-softphone-selftest
```

In one isolated container it starts a PJSUA auto-answer echo peer on
`127.0.0.2:5062` and plans and runs, with the real `campaign run`, a campaign
whose call dials `echo` with an account (`register: true`) and a credential
supplied through `--secret-env`. It asserts success, exactly one INVITE dialog
whose Request-URI user is `echo`, more than 20 RTP packets each way with every
RTP frame cut to its 12-byte header, an oracle PASS on the run's own capture,
and that the secret appears nowhere in the tree. It then runs the same account
against `campaign-sip-challenge-stub` on `127.0.0.3`, which rejects every
credential with a fresh nonce, once with and once without registration, and
asserts from each capture exactly two transactions of which one carries
credentials, one dialog, no INVITE after a failed registration, and state
`failed` (not a call-ceiling stop). A PJSUA peer cannot verify a password, so
a successful digest login is not proven here; use the next section with a
registrar.

Before releasing campaign changes, `make campaign-gate` runs the complete
planner/runtime/integration and oracle suites, oracle benchmark, tool smoke
test, legacy call self-test, and the isolated campaign and softphone
campaign self-tests.

### Authenticated call against a local server

For a practice server that listens on loopback address `ADDRESS`, SIP port
`PORT` (UDP), sends RTP from `ADDRESS` within `RTP_START`-`RTP_END`, and has
account `USER` in realm `REALM` with destination `DIAL`, save as
`work/practice-auth.yaml` (replace every capitalized word with a literal):

```yaml
apiVersion: sippycup.dev/v1
kind: Campaign
metadata: {name: practice-auth-call}
authorization:
  networks: [ADDRESS/32]
  signalingPorts: [PORT]
  mediaPorts: {start: RTP_START, end: RTP_END}
  transports: [udp]
  credentialRefs: [practice-user]
  ceilings:
    calls: 1
    packets: 3000
    bytes: 1500000
    durationSeconds: 60
    concurrentCalls: 1
    packetsPerSecond: 400
    callsPerSecond: 1
  stopConditions:
    consecutiveFailures: 1
    unexpectedResponse: true
    packetLossPercent: 5
targets:
  - name: practice
    address: ADDRESS
    signaling: {transport: udp, port: PORT}
    credentialRef: practice-user
    account: {username: "USER", realm: REALM, register: true}
cases:
  - id: authenticated-call
    type: call
    target: practice
    count: 1
    dial: {user: "DIAL"}
    budget: {packetsPerRun: 2500, bytesPerRun: 1200000, durationSecondsPerRun: 15}
    expectations:
      apiVersion: sippycup.dev/case-expectations/v1
      finalStatus: 200
      requireBidirectionalRtp: true
expectations:
  allowedSipStatuses: [100, 180, 200]
  requireBidirectionalRtp: true
evidence: {capture: true, retainPayload: false, directory: evidence/practice-auth-call}
```

Then plan and run it in the network namespace where `ADDRESS` is reachable
(capture needs `NET_RAW`, so under rootless Podman that is `--isolated`;
the isolated container's loopback is its own, so the server must run in that
same namespace):

```sh
./bin/sippycup campaign plan work/practice-auth.yaml --output work/practice-auth.plan.json
read -rs PRACTICE_SIP_PASSWORD && export PRACTICE_SIP_PASSWORD
./bin/sippycup --isolated campaign run work/practice-auth.plan.json \
  --manifest work/practice-auth.yaml --run-root work/runs --interface lo \
  --secret-env practice-user=PRACTICE_SIP_PASSWORD
```

The command prints the run directory. Check it with:

```sh
run=work/runs/<printed directory name>
jq . "$run/result.json"            # state "succeeded"
jq -r 'select(.event=="step.output") | .text' "$run/events.jsonl" | jq .
# expect outcome "passed", registered true, finalStatus 200, rtp counts > 0,
# authentication.REGISTER.rejected 0 and authentication.INVITE.rejected 0
tshark -r "$run/capture.pcap" -Y 'sip.Method == "REGISTER"' -T fields -e sip.CSeq.seq -e sip.Authorization
grep -rF -- "$PRACTICE_SIP_PASSWORD" "$run" && echo LEAK || echo clean
```

To check lockout safety, run the same plan with a wrong password: the result
is `failed`, `authentication.REGISTER` is `{"attempts": 1, "rejected": 1}`,
and the capture holds exactly one REGISTER with an `Authorization` header and
no INVITE.

## OPTIONS preflight and `options` step contract

Both use one bounded transaction from `lib/sippycup/options.py`, sent only to
the frozen literal address:

- UDP: a connected socket, the real local address and port plus `;rport` in
  Via, at most two datagrams (the request and one retransmission after 0.5 s),
  and no retransmission once any matching response arrived. A reply counts
  only when its status line is strict (`SIP/2.0 NNN reason`) and its Call-ID,
  `CSeq: 1 OPTIONS`, and top Via branch match this transaction; any other
  datagram is counted as ignored. An ICMP port-unreachable is recorded as a
  note, never as a refusal, and the outcome is still no response.
- TCP/TLS: one connection and one request; the reply is read until the header
  terminator (and any body), across segments, bounded at 64 KiB and the same
  deadline. Provisional responses are skipped until a final one.
- IPv6 literals are bracketed in the Request-URI, To, and Via sent-by.
- The preflight deadline is 2 seconds per destination.

The pre-call **preflight** answers "is the destination reachable": any final
response passes, because many servers answer OPTIONS with 401, 403, 404, or
405 and are still valid targets. Each `preflight.json` entry records `ok`,
the status line in `detail`, `statusCode`, `statusClass`, and `warning`. A 5xx
or 6xx still proves reachability, so it does not stop the run (failing would
block assessments of degraded or deliberately rejecting edges), but it is
never silent: `warning` is `server_error_response` and `campaign execute`
prints a warning to standard error. No response, refusal, an unreachable
network, or a TLS failure fails the preflight as before.

An **`options` step** is judged against the frozen case: when the case has
`expectations.finalStatus`, the final status must equal it; otherwise a 2xx is
required. The step prints one JSON summary (outcome, status, requests sent,
retransmissions, ignored datagrams, TLS verification, elapsed time,
expectation, `met`) that appears as a `step.output` event. The step
retransmits over UDP only when its frozen `budget.packets` is at least 4 (two
requests and two responses), and its deadline is the smaller of the step's
`durationSeconds` and 5 seconds.

Preflight traffic is not part of `plannedTotals`, but it is captured: the
watchdog starts before the first preflight packet and counts preflight packets
against every `hardMaxima` ceiling, and execution stops before any step if a
ceiling is already crossed. Budget headroom for it: up to four UDP packets per
used destination in the worst case (two requests, two responses), or one TCP
or TLS connection (handshake, request, response, and teardown).

## Errors and emergency stop

Human-readable errors are the default. Automation can request a stable,
versioned JSON error on stderr:

```sh
./bin/sippycup campaign plan campaign.yaml --error-format json
./bin/sippycup campaign execute plan.json --manifest campaign.yaml --error-format json
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

Known limitations: a plain credential-free `call` without `dial` still runs
SIPp's built-in `uac` scenario, one unauthenticated INVITE to the user
`service` with no audio; add `dial` (and an account with a credential
reference when the target requires one) to use the softphone runner instead.
The softphone runner dials only the first frozen address of a multi-address
target, accepts media only from the step's frozen addresses within the
authorized RTP range (a separate media server address is refused, because
the capture filter and watchdog would not see it), sends DTMF only as RFC
4733 events and SRTP only with SDES keying, sends no hold or re-INVITE, and
does not set ptime. A server that answers a correct response with a
genuinely stale nonce is not retried (one attempt per transaction is the
lockout rule), so that call fails. `authorization.mediaPorts` is the
target's media port range: the runner checks the negotiated remote port
against it, and the capture filter (`udp portrange START-END` with the target
host) admits every packet whose target-side port is in it, so both RTP
directions are captured whatever local port PJSUA uses (it starts at 4000;
the result line reports `localRtpPort`). The local port is therefore not
forced into the range. Digest
authentication itself is exercised only against a real registrar, not by the
loopback self-test. Every TLS connection a campaign makes (preflight,
`options` steps, and softphone calls) verifies the certificate, against the
reviewed `tlsServerName` or else the literal address as an IP SAN, and the
reviewed `tlsCaFile` or else the system trust store. There is no unverified
mode for campaigns. The traffic watchdog counts calls by the `INVITE ` text
in captured packets, so it cannot count calls over TLS; packet, byte, rate,
and duration ceilings still apply, and the runners place exactly one call per
step. The name is pinned only for PJSUA's resolver (a private hosts file in a
user and mount namespace); a TLS target with a name therefore needs
unprivileged user namespaces in the toolbox container (the default for
rootless Podman), and the softphone runner refuses the call otherwise.
Campaign execution is local and sequential—there is no distributed
controller.
