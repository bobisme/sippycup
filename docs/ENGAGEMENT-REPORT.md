# Owner engagement report

`./bin/sippycup summary DIR` assembles the document you hand the platform
owner after an assessment: what was approved, what was run, what happened,
what was found, and what to fix. It reads the engagement directory and its
run directories, re-checks every run against the reviewed authorization, and
writes a Markdown report, a single self-contained HTML file, and the report
model as JSON.

```sh
./bin/sippycup summary work/ferivox-assessment
```

The command sends nothing and resolves nothing. It runs from the checkout on
the host (like `status`) and also inside the image. It needs only the Python
standard library and PyYAML.

## Output

By default it creates a new mode-0700 directory `DIR/report/` with mode-0600
files:

| File | Content |
|---|---|
| `engagement-report.md` | GitHub-flavoured Markdown with tables |
| `engagement-report.html` | One self-contained page: inline CSS and static SVG, no scripts, no external assets |
| `report.json` | The report model (`sippycup.dev/engagement-report/v1`); always written |

It never replaces an earlier report silently. When `DIR/report/` already
holds a report, the new one goes to `DIR/report-STAMP/` (the generation time,
for example `report-20261118T040000Z`, with `-2`, `-3` appended if needed).
`DIR/report/` then holds an older report. Every `summary` prints
`Send to the owner: PATH` for the report it just wrote and, when others
exist, `EARLIER report(s), do not send: ...`; send the path from your last
`summary`. Nothing in the earlier directories is changed or deleted.
`--force` replaces the report files in the existing directory instead. An
explicit `--output PATH` must be a new or empty directory unless you pass
`--force`. Files are written to a private staging directory and renamed into
place, so an interrupted run leaves no partial report.

## Options

| Option | Meaning |
|---|---|
| `--output PATH` | Output directory (default `DIR/report`) |
| `--format F` | `md`, `html`, `text`, or `json`; repeatable. Default `md` and `html`. `report.json` is always written |
| `--audience owner\|internal` | Default `owner`. `internal` also shows journal notes and full Call-IDs; nothing else changes |
| `--runs GLOB ...` | Only runs whose directory name or engagement-relative path matches |
| `--since TIME` | Only runs that started at or after this RFC 3339 time |
| `--title TEXT` | Report title (default: the title in `engagement.json`) |
| `--generated-at TIME` | Fixed generation time, for reproducible output |
| `--run-root DIR` | Another directory of run directories; repeatable |
| `--matrix-root DIR` | Another directory of matrix run directories (each holds `matrix.json`); repeatable. `DIR/matrix` and `matrix/` next to each profile are read without it |
| `--profile PATH`, `--manifest PATH` | Another target profile or campaign manifest to treat as an authorization record |
| `--include-journal-notes` | Include journal entry detail text (sanitized) in an owner report |
| `--forbid-file PATH` | A file whose value (for example the account password file) must appear nowhere in the report. The value is only compared, never stored or printed |
| `--allow-exceptions` | Exit 0 even when integrity exceptions are present |
| `--journal` | Append an `action` entry with the `report.json` SHA-256 to the journal |
| `--force` | Replace report files in an existing output directory |

## Exit status

| Exit | Meaning |
|---|---|
| 0 | Report written; no integrity exceptions (or `--allow-exceptions`) |
| 1 | Report written; integrity exceptions are listed at its top |
| 2 | Usage or input error; nothing written. Also returned when `--journal` fails after the report was written |
| 3 | Privacy lint failed on the model or a rendering; nothing written |

A report with integrity exceptions is still written, because the owner needs
to see them; the non-zero status keeps automation from treating it as clean.

## What it reads

All reads are bounded (JSON 8 MiB, event streams 16 MiB, text 1 MiB, at most
1000 runs). A malformed, oversized, symlinked, duplicate-key, or missing file
becomes an `unreadable` or `partial` run entry and a limitation; it never
stops the report.

- **Engagement metadata**: `engagement.json` from `journal init` (title,
  owner, creation time), the journal (verified with the journal API: valid or
  not, entry count, head hash, missing evidence), and evidence packs
  (`*.tar`, `*.tar.age`) in `DIR` or `DIR/packs` with their SHA-256 and, for
  plain tar packs, the content identity in `pack-manifest.json`.
- **Authorization records**: `DIR/scope.yaml`, every target profile and
  campaign manifest directly in `DIR` (recognized by `schema_version` and
  `kind: Campaign`), and any `--profile`/`--manifest`. Copies inside run
  directories are never treated as the authority.
- **Runs**: the children of `DIR/runs` (campaign default in the assessment
  workflow), `DIR/calls` (the guided call default: `calls/` next to the
  profile), `DIR/checks`, `calls/` next to each profile found, every run root
  named by a journal evidence reference, and each `--run-root`. A directory
  with `findings.json` is a security-check run, one with `events.jsonl` or a
  campaign `plan.json` is a campaign, and one with a call `result.json` is a
  guided call.

- **Matrices**: the `matrix.json` of each directory under `DIR/matrix`,
  `matrix/` next to each profile found (where `matrix run` writes by default),
  and each `--matrix-root`.

Numbers are the ones the runs recorded: the call result, `softphone.json`,
`triage.json` capture metadata, the campaign's `step.output` summaries and
`preflight.json`, the `Number of packets` line of `report.txt`, the capture
size from the evidence manifest, and `requestsSent` from check runs. Captures
are never re-parsed. An OPTIONS step whose summary was withheld (runners stay
silent while secrets are in use) counts as one request and the total says
"at least".

Security-check runs use `sippycup.dev/findings/v1`:

```json
{"apiVersion": "sippycup.dev/findings/v1", "target": {}, "generatedAt": "...",
 "checks": [{"id": "", "status": "passed|finding|skipped|error|not-approved", "requestsSent": 0, "summary": ""}],
 "findings": [{"id": "", "checkId": "", "title": "", "severity": "info|low|medium|high", "confidence": "",
   "summary": "", "evidence": [{"kind": "", "detail": "", "artifact": "relative/path"}],
   "remediation": "", "references": []}]}
```

Unknown extra fields are ignored. An unknown severity is treated as `info`.

## Report sections

1. **Integrity exceptions** (only when present), first.
2. **Executive summary**: one paragraph and a three-to-five row "what we
   found" table.
3. **Authorization**: every reviewed record with approval identifier, who
   approved, status, validity window, approved addresses, ports, transports,
   server names, and limits. A campaign file has no status of its own; its row
   shows the approval id and window it was compiled with, marked as a copy of
   the scope's approval. When the approval window was renewed, the section
   (and the executive summary) lists each window that was in force and which
   runs (R1-R12, R13) fell under it, so "every run fell inside the approved
   window" can be read off the page. The approval records behind those
   windows are named in the Integrity section.
   A **Call limit** block (`CALL LIMIT` in the text
   report) gives, per approval id, `Calls: N of M used, K left`: the approved
   call limit, the calls counted in `ENG/call-ledger.jsonl` (the count every
   command checks before it sends), and the calls left; and the calls the
   runs in the report placed. A call counts from its first INVITE on, as the
   ledger counts it. The ledger can be higher (runs outside the report's run
   roots or filters, a command still running, attempts an older rule counted:
   a preflight or a REGISTER was sent, no INVITE); it is never lower unless it
   was emptied or shortened, which raises `call-ledger-unaccounted`. When the
   limit was exceeded, the executive summary says so in its own sentence.
4. **Activity ledger**: every run with lane label, start, end, kind, target
   (a campaign that used UDP and TLS names both), what was sent, verdict, and
   reason; a run that never started (for example packet capture could not
   start on the assessor's side) says so, names no target, and is not a
   finding about the owner's system (it is listed under Limitations and in the
   executive summary); engagement totals; a static SVG
   timeline of the runs across the approval window and a per-call media bar
   (RTP packets to and from the peer), each next to a text table with the
   same numbers.
5. **Results**: calls (preflight, registration, answer status, setup time
   from the softphone timeline, RTP both ways, codec, TLS verification facts,
   oracle pass/fail/unknown with the failing assertion names), campaigns
   (per-case outcomes, status against the expectation, stop reason, preflight
   warnings), call matrices (below), and security checks (every check and its
   status).
   **Call matrices** draw one grid per `matrix.json`
   (`schemas/call-matrix-v1.schema.json`): a row per transport and SRTP mode,
   a column per codec, and in each cell the verdict, the setup time of a
   passing call, the run label (R#) of the call that produced it, and a mark
   when SDES keys went over cleartext signaling. A cell the matrix did not run
   says "not run", the heading gives the state and stop reason, and a stopped
   matrix adds a limitation. The grid is not trusted as written: it must
   validate against the schema, its counts must match its cells, and every
   cell that ran must name a run directory the report found, with the verdict
   and transport that run recorded. Otherwise the report carries an integrity
   exception (`matrix-invalid`, `matrix-run-missing`, `matrix-verdict-mismatch`,
   `matrix-run-mismatch`, `matrix-count-mismatch`, `matrix-unreadable`) and a
   document that fails the schema is not drawn. Free text goes through the
   same sanitizer and privacy lint as the rest of the report; paths are never
   printed. A matrix whose runs were all practice-target runs is labelled so.
6. **Findings**: merged across check runs by check id, title, and target,
   with first and last seen and the runs that evidence each one, ordered by
   severity; then observations derived from run results, labelled as derived.
7. **Recommendations**: the remediation text of each finding. The report
   writes its own advice only for derived observations, from a small reviewed
   table in `lib/sippycup_workbench/summary_model.py` (`OBSERVATIONS`).
8. **Limitations**: stages never run, checks skipped or not approved and
   why, campaign steps never run, matrix factors not exercised, unreadable
   runs, and the fact that totals are recorded numbers.
9. **Evidence index**: per run, every artifact with size, SHA-256, and
   sensitivity, from the evidence manifest (or computed with a bounded
   streaming hash when there is none, labelled as such), the manifest's
   privacy status, and any artifact whose size changed since the manifest;
   the journal entries (kind, time, title); and packs.
10. **Integrity footer**: the SHA-256 of `report.json`, the journal head hash,
    and every run's content identity, so the report can be tied to the
    evidence. `--journal` records the same `report.json` hash in the
    journal.

Derived observations and their severity:

| Code | Severity | Raised when |
|---|---|---|
| `one-way-media` | low | A call verdict is `one-way-media` |
| `possible-nat-one-way-media` | info | A call verdict is `possible-nat-one-way-media` |
| `preflight-server-error` | low | A preflight answered 5xx or 6xx |
| `tls-not-verified` | low | A TLS run did not verify the server |
| `media-outside-scope` | low | A call verdict is `media-outside-scope` |
| `oracle-assertion-failed` | info | The automatic packet check (the offline oracle) failed on an answered, non-TLS call |
| `campaign-window-ended` | info | A campaign ended `authorization_lapsed`: Sippycup stopped it before a step because the approval window ended, was too short for that step, or the approval was withdrawn (a safety stop, not a target failure) |
| `campaign-stopped` | info | A campaign ended in any other state but `succeeded`, after at least one step or preflight started. A campaign that never started (no event stream, no preflight, no step) is not an observation: it is the assessor's failure and nothing was sent |
| `capture-incomplete` | low | Capture failed or died during a run |

## Independent re-check

The gates already refuse out-of-scope traffic. The report checks again,
from the recorded artifacts, and lists any exception at the top:

| Code | Meaning |
|---|---|
| `target-not-approved` | A run, step, or preflight target is not in any approved address, port, and transport set (an owner-approved media network never counts here: it admits media only) |
| `target-not-literal` | A recorded target is not a literal address |
| `media-peer-not-approved` | A call's negotiated media peer is neither an approved address nor inside an approved media network (scope `media.networks`, profile `media.networks`); each call's `details.media.peerApprovedBy` says which rule approved it (`approved-address` or `media-network`) and `peerRecordedRule` what the run itself recorded |
| `outside-approval-window` | A run's start or end lies outside every window that covers its target |
| `approval-not-active` | The covering record is not in `approved` status |
| `ceiling-exceeded` | Recorded packets, bytes, calls, or call time exceed the frozen ceiling |
| `unapproved-address-in-artifact` | A run artifact's text named an address outside the approved set |
| `destination-not-approved` | A call dialed a destination that is not on the approved destination list |
| `call-limit-exceeded` | The calls placed under one approval id in the engagement, counted in start order across all commands, went above its limit (`limits.calls`), or the engagement's call ledger counts more than the limit. Only runs of the practice bench (`work/practice`) are left out; an engagement that rehearses under the practice approval id is counted |
| `call-ledger-unaccounted` | The engagement's call ledger does not account for every run directory that placed or may have placed calls under the approval (it was emptied, shortened or replaced), so the calls cannot be confirmed against the limit |
| `approval-record-edited` | A compiled profile or manifest was edited after `scope compile`, or is not recorded by it; it is not used as an approval record |

Windows come from the scope file and target profiles. A campaign manifest's
`authorization.approval` window is what `campaign run` enforced, but it has no
status, so the report shows it (the id and window the file holds) and does not
use it as a window record; a campaign is checked against the windows of the records that approve
its addresses. A call or checks run whose recorded `profile.json` equals one
of the practice approvals that `practice-target up` archived in
`work/practice/approvals/` (loopback-only, `LOCAL-PRACTICE-ONLY`) is checked
against that approval instead, labelled as a practice target run, and left out
of the totals; see `PRACTICE-TARGET.md`. A run whose target no windowed record covers, or that recorded
no start time, is listed under Limitations as not re-checked against a
window; it is not silently treated as inside one.

Each run is judged by the approval in force when it ran (bn-2rgk). `call`,
`checks run` and `campaign run` record `approvalRecord` in `result.json`: the
integrity state of the profile or manifest they used, its SHA-256, and the
SHA-256 of the scope file it was compiled from. They also keep a write-once
copy of that scope file in `ENG/approved-scopes/scope-SHA256.yaml`. When the
state is `compiled-current` and the copy still hashes to its name, the report
checks the run's targets, window, status and destinations against that copy
alone (the run's reasons say so), not against the current records. Each run's window is the one in that copy,
so after a renewal the older runs are checked against the older window. A run's
own `profile.json` never authorizes anything. Runs without such a record (made
before this change, or with a hand-written profile or manifest) are judged
against the current records; when other runs do have a record, the report
lists them under Limitations (`approval-in-force-unrecorded`).

## Wording

The report is for the system owner, who does not know the tool. Owner text uses
plain words: "the automatic packet check" for the offline oracle, "the test
softphone" for the softphone's own log and statistics, and no engagement-file
names in a run's reasons. The precise names (the approval record file of each
window, the evidence file names) stay in the Integrity and Evidence index
sections. A loopback target is stated once, under Limitations (or, for practice
runs, in the practice-runs item), not on every row.

## Privacy

The owner report never includes passwords, Digest responses or nonces, full
Call-IDs (a 12-character SHA-256 prefix stands in), subscriber identifiers
beyond the accounts and destinations the reviewed records name, absolute host
paths (every path is engagement-relative; runs outside it appear as
`external-root-N/RUN`), journal detail text (only kind, time, and title
unless `--include-journal-notes`), or any address outside the approved set.

Two layers enforce this:

1. **Sanitizer.** Every string copied from a run artifact is cleaned before
   it enters the model. Control and bidirectional-override characters are
   removed; `Authorization`/`WWW-Authenticate` material, `Digest` parameters
   (`response`, `nonce`, `cnonce`, `opaque`, `username`, `realm`, `uri`),
   `password=`/`secret=`/`token=` assignments, `Call-ID` values, SIP and tel
   URIs, `+` phone numbers, runs of seven or more digits, and high-entropy
   tokens (16 or more characters mixing upper case, lower case, and digits)
   are replaced with labels; any `--forbid-file` value becomes
   `[secret redacted]`. Approved addresses stay; the assessor's own recorded
   source addresses become `assessor-address`; every other address becomes
   `unapproved-address-N` and raises an integrity exception. Destinations and
   accounts not named by a reviewed record become `unreviewed-destination-N`.
   Free text is truncated to 600 characters.
2. **Fail-closed lint.** The finished model (every key and value, by JSON
   path) and every rendering (by line) are checked with the patterns of
   `lib/sippycup/evidence.py` (authorization material, Call-ID headers, SIP
   users, phone identifiers, addresses outside the approved networks), plus
   Digest parameters, credential assignments, `--forbid-file` values, and
   control characters. Any hit exits 3, writes nothing, and names each
   offending field path and rule, never the value. Operator-supplied text
   (the title, the engagement metadata, approval records) is not rewritten,
   so a phone number in `--title` stops the report.

`--audience internal` relaxes only journal notes and full Call-IDs; the lint
still runs.

## Rendering

The HTML page has an executive summary first, a restrained system font stack,
light and dark colour schemes (`prefers-color-scheme`), print rules (`@page`,
no breaks inside findings, tables, or figures), and a layout that works at
phone width (wide tables scroll inside their own frame). Every table has a
caption and `scope` attributes; severity is a text label (`HIGH`, `MEDIUM`,
`LOW`, `INFO`) as well as a colour; collapsible evidence sections use
`<details open>`, so everything is readable with scripts disabled and nothing
is hidden in print. A Content-Security-Policy meta tag forbids every external
load. All values are HTML-escaped; Markdown values escape `\`, backquote,
`*`, `_`, `[`, `]`, `<`, `>`, `|`, `~`, and `&`.

The same inputs and `--generated-at` produce byte-identical files.

## Recording the report

```sh
./bin/sippycup summary work/ferivox-assessment --journal
./bin/sippycup journal verify work/ferivox-assessment
```

`--journal` appends `Rendered the owner engagement report; report.json sha256
...` with the report files as evidence. To share a report, give the owner the
HTML or Markdown file; keep `report.json` with the evidence. Treat both as
confidential until the owner approves wider distribution.

## Limits

- The report summarizes recorded artifacts; it does not reproduce findings or
  re-analyze captures, and it cannot detect evidence that was deleted before
  it ran (anchor the journal head and packs as described in
  [`ASSESSMENT-WORKFLOW.md`](ASSESSMENT-WORKFLOW.md)).
- The high-entropy rule can redact an unusual but harmless identifier;
  `[token]` in a reason means the original is in the run directory.
- Run directory names and the approved addresses are shown verbatim; keep
  secrets out of them.
- No headless-browser check is part of the tests; HTML structure is verified
  with `html.parser`.

See also: [`ASSESSMENT-WORKFLOW.md`](ASSESSMENT-WORKFLOW.md),
[`EVIDENCE-PRIVACY.md`](EVIDENCE-PRIVACY.md),
[`EVIDENCE-PACKS.md`](EVIDENCE-PACKS.md), [`GUIDED-CALL.md`](GUIDED-CALL.md),
and [`CAMPAIGN-MANIFEST.md`](CAMPAIGN-MANIFEST.md).
