# Diagnose a run that did not pass

During the live engagement a call fails and the platform owner is waiting on
the line. `./bin/sippycup diagnose RUN_DIR` turns the files that run left behind
into one page that answers four questions:

1. **What happened**, in one sentence, and at which stage it stopped.
2. **How sure are we**, and what evidence decides it.
3. **Whose side is it probably on**: `our side`, `their side`,
   `network or NAT in between`, or `cannot tell from this evidence`, with the
   reasoning and what would tell the alternatives apart.
4. **What to run next**: real `./bin/sippycup ...` lines built from the run's own
   recorded profile and flags, or an explicit "stop and ask the owner".

It is offline. It reads files, runs TShark on the run's capture through the
ladder reader, and sends nothing. It runs on the host like `ladder`, and in the
image under `--isolated` or `--practice`.

```sh
./bin/sippycup diagnose work/ENGAGEMENT/calls/RUN_ID              # the full page
./bin/sippycup diagnose work/ENGAGEMENT/calls/RUN_ID --brief      # five lines
./bin/sippycup diagnose work/ENGAGEMENT/calls/RUN_ID --format json
./bin/sippycup diagnose --compare work/ENGAGEMENT/calls/PASSING work/ENGAGEMENT/calls/FAILING
```

| Option | Meaning |
| --- | --- |
| `--format text\|json` | A page for the terminal (default) or the same content as `sippycup.dev/diagnosis/v1`. |
| `--brief` | Five lines (at most 150 characters each) for a status bar. With `--format json` it is `sippycup.dev/diagnosis-brief/v1`. |
| `--compare RUN_A RUN_B` | What differs between two guided-call runs (see "Comparing two runs"). |
| `--output FILE` | Write there (mode 0600, atomic, never through a symbolic link) instead of standard output. |
| `--no-ladder` | Skip the ladder excerpt; no capture is read. The page then rests on the recorded files only. |
| `--width N` | Text width, 60 to 300. Default 100. |
| `--approve NET` | An address or CIDR whose addresses may be shown. A run directory adds its own approved networks. |
| `--show-addresses` | Operator copy: every address unredacted, with a banner that it is not for the owner report. |

Exit status: 0 written; 2 bad arguments or an unusable path; 4 the directory is
not a run Sippycup knows (the message names the newest runs when you pointed at
a directory of runs); 5 internal error or privacy lint refusal (nothing is
written). A run that failed still exits 0: the exit status says whether the
diagnosis was produced, not whether the run passed.

## What it reads

| Run | Directory | Files used |
| --- | --- | --- |
| Guided call | `work/ENG/calls/ID` | `result.json`, `plan.json` (the recorded flags), `profile.json`, `softphone.json`, `softphone.log`, `assert.json`, `expectations.yaml`, `preflight.json`, `timestamps.json`, `capture.pcap` through the ladder |
| Matrix | the matrix directory | `matrix.json`; each failing cell's guided-call run directory (found from the path in `matrix.json`) |
| Campaign | the campaign run directory | `result.json`, `events.jsonl`, `plan.json`, `preflight.json`, `steps/N/softphone.*`, `capture.pcap` |
| Checks | the checks run directory | `result.json`, `findings.json`, `checks-detail.json`, `transcript.jsonl`, `plan.json`, `profile.json` |

A page for a call that has no `result.json` (the run was killed, or is still
going) says so and names the last stage its timestamps reached.

## What a page contains

```
WHAT HAPPENED            one sentence, and the stage where the run stopped
WHOSE SIDE, AND HOW SURE the side, a confidence (high, medium, low), the reasoning,
                         and what would tell the alternatives apart
DECISIVE EVIDENCE        quoted minimally, the lines that decide the stage first
TIMING                   registration, INVITE to provisional, INVITE to answer,
                         answered duration, teardown, whole run
LADDER EXCERPT           the ladder model's own drawing, centred on the failure
NEXT STEPS               numbered commands, or ">> STOP" when the owner must decide
WHAT THIS EVIDENCE CANNOT SHOW   the gaps, said out loud
```

Stages are `preflight`, `TLS`, `registration`, `INVITE`, `answer`, `media`,
`teardown`, `oracle`, `capture`, `safety stop`, `internal`, and `none` (the run
passed, or it was interrupted before a stage mattered).

The decisive evidence is the final SIP status line, the `Reason`, `Warning`, and
`Retry-After` headers the **far end** sent (never the ones we sent), the failing
oracle assertions with their numbers (received, expected, lost, duplicates,
reordered, timestamp jumps, jitter against its limit), the RTP counts per
direction and the payload types, the media peer and which scope rule admitted
or refused it (approved address, owner-approved media network, or media port
range), the TLS trust anchor, reviewed server name and verification error, the
SDP offer and answer addresses, and the stage timings.

## The attribution

The side is a judgment from recorded evidence, never a proof. The page always
shows the confidence and says what is missing.

| Situation | Side | Why |
| --- | --- | --- |
| 486, 603, 429, 403, 503, 5xx, a BYE from the far end, a silent far end on loopback | their side | The far end answered, or ended the call, by its own decision. |
| 401 or 407 with no credentials given; wrong CA or name in our profile; a failed gate; a lapsed window; an interrupt; capture failure | our side | The cause is in what we supplied or in the toolbox. |
| Registration 401 after we presented credentials | our side (medium) | The password, username, or realm was not accepted; a disabled or locked account looks the same, and the page says so. |
| One-way media where RTP reached our port from a different address than the SDP named; a private address behind NAT | network or NAT in between | The addressing, not the application, differs. |
| Silence on OPTIONS or INVITE; 404; 488 with a default offer; an oracle failure with no early media; TLS verification where both ends could be wrong | cannot tell | Several causes fit; the page lists what separates them. |
| Media outside the approved scope | our side (medium) | The toolbox's scope rule worked; our approved scope is incomplete for this platform. Only the owner can fix that. |

One-way media is judged from the ladder's RTP reader: whether our RTP went to
the address and port the answer SDP named, how many packets reached our port
and from which source, whether the SDP names a private address while signaling
reached a public one, and whether our offered address was private behind the
container's NAT. A capture that does not cover the media address (a campaign
whose approved networks list only the proxy, for example) is named as a gap
rather than counted as "nothing arrived".

## Next steps never go beyond the approval

Commands are rebuilt from `plan.json` (profile path, `--dial`, `--duration`,
`--answer-timeout`, `--codec`, `--srtp`, `--no-register`, the account and the
password source, `--dtmf`) with one change at a time:

- A longer `--answer-timeout` only when ringing was seen and the limit (120 s) allows it.
- Another `--codec` only from the profile's approved codec list, else PCMU or PCMA.
- `--srtp mandatory` only when the profile's `features.srtp` is true.
- `preflight` over another transport only from a sibling profile that is approved and unexpired.
- `--practice` is added only for runs made under the `LOCAL-PRACTICE-ONLY` approval.
- A `--dial` or `--username` that looks like a phone number is replaced by a placeholder, because user parts are never printed.

The page says **stop and ask the owner** and suggests no retry when the verdict
is rate limiting (429), forbidden (403), declined (603), a rejected registration
password, credentials rejected for the INVITE, a repeated 503, a TLS name or CA
that was not confirmed, a lapsed authorization, a media-scope safety stop, a
redirect, or a DTMF method the platform does not offer. It never suggests
`--tls-unverified`, a wider profile, or a different destination guessed from
the one that failed.

If the profile path is not recorded (a run made before this version), the
commands carry `PROFILE.yaml` and a gap line says so; the page also tries the
engagement's own profiles by name, host, port, and transport first.

## Matrix, campaign, and checks runs

- **Matrix.** Counts passed, failed, and not-run cells, shows the stop reason, and
  diagnoses each failing cell with the call rules. When one setting accounts
  for every failure it says so and rules out the others ("every failure shares
  codec G722 and no cell with it passed; transport udp and srtp mandatory passed
  in other cells, so those are not the cause"). A stop on 429, a rejected
  password, a 503, a lapsed window, or a media-scope stop says stop and ask.
- **Campaign.** Finds the failing step in `events.jsonl`, reads the runner's
  result (registration status, final status, the number of authentication
  attempts and rejections, RTP counts), quotes headers from the step's
  `softphone.log`, and draws the run's capture. A failed preflight, a timed-out
  or interrupted run, and a step that failed without a structured result are
  each named for what they are.
- **Checks.** Counts findings by severity and checks by status. Findings point at
  their side (they describe the target) and are marked as candidates to
  confirm; checks that errored with nothing answering are not findings, and the
  page says so; checks that were not approved are listed as not run. Next
  steps are `checks explain ID` for the top findings.

## Comparing two runs

`diagnose --compare RUN_A RUN_B` takes two guided-call runs, normally a passing
and a failing one of the same call. It prints the settings that differ (profile,
transport, target, codec offer, SRTP mode, timeouts, account, DTMF), the
statuses, the SDP offer and answer, RTP counts and payload types, the media
peer and the rule that admitted it, and the timings (only a spread above 0.5 s
and 2x counts). It then says what that suggests: when no setting differs it says
the difference lies in the far end, the path, or timing and not in our
configuration; when exactly one setting differs it names it as the likely
cause. `--dial` values are compared but never printed.

## For the cockpit

The cockpit can show the failure of the last call without a new code path:

```sh
./bin/sippycup diagnose work/ENGAGEMENT/calls/RUN_ID --brief --no-ladder --format json
```

returns five ready-to-print `lines`, plus `stage`, `side`, `confidence`, and a
`stopAndAsk` flag (show it prominently and offer no "retry" action when it is
true). The same command without `--format json` prints the five lines directly.
`--no-ladder` keeps it to the recorded files (about 0.1 s); with the ladder it
takes one to three seconds because TShark reads the capture.

## Privacy

The same rules as the owner report and the ladder, enforced twice: every string
that reaches the page goes through the report sanitizer, and every finished
rendering is linted (fail closed, exit 5, nothing written) with the evidence
patterns plus the ladder's own. Never printed: Authorization or
Proxy-Authorization, nonces, digest responses, realms, `a=crypto` key material,
SIP URIs and user parts, Call-IDs, message bodies other than an SDP summary,
DTMF digit values, passwords, and the text of any header the toolbox itself
sent. Approved addresses are shown; every other address becomes
`unapproved-address-N`. For the media-scope stop that is exactly what the
operator needs to see, so the page offers the same command with
`--show-addresses` as an operator copy that must not be attached to an owner
report (the secrets rules still apply to it).

## Limits

- TLS-encrypted signaling has no readable SIP in the capture. When the run has
  a `softphone.log`, SIP statuses and headers come from it; when it does not,
  the page says no SIP can be quoted.
- A truncated or unreadable capture is named as a gap; the ladder excerpt is
  dropped and the page rests on the recorded files.
- The capture is scoped to approved addresses; RTP from any other source would
  not be recorded, and the page says so for media diagnoses.
- Attribution is an inference from one run. A far end that fails once and
  passes the next time is described by `--compare`, not by one page.
