# Assessment execution and recordkeeping

Sippycup separates authorization, execution evidence, human reasoning, and
publication. This prevents a chat transcript, shell history, or analyst memory
from becoming the accidental source of truth.

No command in this document authorizes traffic. Quad's written scope and
validity window remain mandatory.

## Sources of truth

| Record | Purpose | Mutation model |
|---|---|---|
| Target profile | Small one-call readiness and approval gate | Reviewed before use |
| Campaign manifest and frozen plan | Complete scope, destinations, credentials references, cases, ceilings, and stop conditions | Plan is immutable |
| Campaign run directory | Commands, versions, preflight, events, PCAP, reports, assertions, result, and timestamps | Exclusively created |
| Assessment journal | Authorization changes, hypotheses, actions, observations, findings, decisions, evidence links, and follow-ups | Append-only hash chain |
| Evidence manifest and pack | Artifact hashes, sensitivity, privacy findings, reproducible archive, optional signature/encryption | Rebuilt and verified |
| Internal report draft | Human-readable synthesis of the verified journal | New output only |
| Public outline | Disclosure checklist without private journal content | New output only |

The campaign event stream records what the supervised executor did. The
assessment journal records why the operator did it and what the evidence
means. Do not manually duplicate packet data, credentials, or large command
output into the journal; link to the retained artifact instead.

## Create the engagement record

Keep the engagement and all of its campaign runs under the same ignored,
private directory:

```sh
./bin/sippycup journal init work/ferivox-assessment \
  --title "Ferivox staging security assessment" \
  --owner Quad
```

The command exclusively creates a mode-0700 directory containing:

- `engagement.json`, immutable private metadata;
- `journal.jsonl`, an initially empty mode-0600 append-only journal.

It refuses an existing directory. Journal entries are finite, strictly
sequenced JSON records. Every entry hashes its canonical contents and the
previous entry hash. Verification rejects edits, deletion from the middle,
reordering, incomplete writes, unexpected fields, unsafe evidence paths,
oversized records, and symlinked journals.

The chain does not identify who made an entry. Clean deletion of the final
entry—or replacement of the entire journal—cannot be detected from the
remaining chain alone. Preserve the final digest in a separately controlled
system or include the completed journal in a signed evidence pack to anchor
the record. Encryption protects transport and storage confidentiality but
does not establish author identity by itself.

## What to record

Use these entry kinds consistently:

- `authorization`: exact approval identifier, scope change, validity window,
  ceiling, stop condition, or revocation—never a credential value;
- `hypothesis`: a testable security claim and the evidence that would support
  or refute it;
- `action`: a reviewed plan, offline analysis, or approved live action;
- `observation`: an evidence-backed fact without a severity claim;
- `finding`: a candidate or validated security impact, clearly labeled in its
  detail;
- `decision`: why a test was run, deferred, narrowed, or stopped;
- `follow-up`: remediation, retest, missing evidence, or owner action;
- `note`: relevant context that does not fit another kind.

Example:

```sh
./bin/sippycup journal add work/ferivox-assessment \
  --kind hypothesis \
  --summary "RTP source tuple changes may be accepted after establishment" \
  --tag rtp --tag security

./bin/sippycup journal add work/ferivox-assessment \
  --kind action \
  --summary "Completed the approved one-call baseline" \
  --evidence runs/RUN_ID/plan.json \
  --evidence runs/RUN_ID/events.jsonl \
  --evidence runs/RUN_ID/result.json
```

Evidence references are normalized paths beneath the engagement directory.
Absolute paths, `..`, backslashes, and dot segments are rejected. References
may be recorded before an artifact exists, but verification reports every
missing, non-regular, symlinked, or escaping reference.

Summary and detail text supplied directly as options can appear in shell
history and process inspection. Keep them non-secret. For sensitive working
prose, create a mode-0600 file under `work/` with an editor and use
`--summary-file` or `--detail-file`; `-` reads standard input. Never record
passwords, bearer tokens, SIP authorization responses, private keys, or
decoded voice.

## Execution framework

### 1. Preparation

Run the image doctor, create a pending target profile, and create the
engagement journal. Record current unknowns as hypotheses or follow-ups.

### 2. Written authorization

Record the approval identifier, exact staging addresses, interfaces, test
accounts or roles, allowed test classes, traffic ceilings, stop conditions,
validity window, live contact, evidence retention, and disclosure status.
Credential values stay in the approved external secret source.

### 3. Network-free rehearsal

Compile the small target profile and full campaign plan. Pin every resolved
address, lower ceilings as needed, and archive the reviewed manifest and
frozen plan. Planning and rehearsal send no SIP or RTP traffic.

### 4. Baseline

Begin with one OPTIONS transaction and one manual or automated call. Capture
signaling and media, prove both directions and teardown, and establish a
golden behavior pack before adversarial cases.

### 5. Security cases

Progress from exposure and TLS configuration through authentication and
authorization, malformed state transitions, media spoofing and replay,
cross-call isolation, overload, and recovery. Each campaign must remain
independently bounded. Admin and WebSocket testing use a separate profile once
Quad supplies its scope and roles.

### 6. Stop and preserve

Stop immediately on an authorization ceiling, capture failure, unexpected
destination, service instability, privacy concern, or Quad's request. Record
the reason as a journal decision. Do not delete an interrupted run; its
evidence manifest truthfully marks missing artifacts.

### 7. Analyze and validate

Run offline packet assertions, media analysis, behavior comparison, and
privacy lint. A tool result is a candidate until an independent reproduction
or code-side explanation validates it. Record unknowns as unknowns.

### 8. Report and retest

Link findings to run artifacts, record remediation decisions, execute a
separately approved retest, and preserve both original and retest evidence.

## Verification and report drafts

Get the current readiness decision and ordered offline actions:

```sh
./bin/sippycup status work/ferivox-assessment
```

The advisor does not infer approval from journal prose, benchmark claims, or
past runs. Only the strict target profile can become ready, and status still
stops at human review rather than executing a network command.

Verify the journal at any point:

```sh
./bin/sippycup journal verify work/ferivox-assessment
```

Generate a new internal draft:

```sh
./bin/sippycup journal render work/ferivox-assessment \
  --audience internal \
  --output work/ferivox-assessment/internal-report-01.md
```

The internal renderer includes journal text and evidence paths. Its output is
mode 0600 and confidential. It refuses to overwrite an earlier draft.

Generate a publication scaffold:

```sh
./bin/sippycup journal render work/ferivox-assessment \
  --audience public \
  --output work/ferivox-assessment/blog-outline-01.md
```

The public renderer deliberately copies no title, owner, journal prose,
technical finding, evidence path, count, or timestamp. It emits only a
suggested structure and disclosure checklist. A human must write the article
from validated facts, run privacy review, and obtain Quad's approval for the
exact text.

## Campaign evidence inside the engagement

Place supervised runs below the engagement root:

```sh
./bin/sippycup campaign execute work/ferivox-assessment/plan.json \
  --manifest work/ferivox-assessment/campaign.yaml \
  --run-root work/ferivox-assessment/runs \
  --interface any
```

For each run, rebuild and lint its evidence inventory without contacting the
target:

```sh
./bin/sippycup evidence manifest \
  work/ferivox-assessment/runs/RUN_ID --write
./bin/sippycup evidence lint work/ferivox-assessment/runs/RUN_ID
```

Package, sign, or encrypt only after the privacy and disclosure decisions
documented in `EVIDENCE-PRIVACY.md` and `EVIDENCE-PACKS.md`.
