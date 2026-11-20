# Call matrix

`./bin/sippycup matrix` answers the first question on a new platform: which
transport x codec x SRTP combinations work. Each cell of the grid is one
guided call (`GUIDED-CALL.md`), placed strictly one after another through the
same code path and gates as `./bin/sippycup call`.

```sh
./bin/sippycup matrix plan work/ENGAGEMENT/target-profile.yaml work/ENGAGEMENT/target-profile-tls.yaml \
  --dial 1001 --codecs PCMU,PCMA,G722 --srtp off,mandatory --max-calls 12
./bin/sippycup matrix run work/ENGAGEMENT/target-profile.yaml work/ENGAGEMENT/target-profile-tls.yaml \
  --dial 1001 --codecs PCMU,PCMA,G722 --srtp off,mandatory --max-calls 12 \
  --username 1001 --secret-env SIP_PASSWORD
```

The two files are what `./bin/sippycup scope compile` writes for a scope with
two targets: `target-profile.yaml` for the first entry of `targets` and
`target-profile-NAME.yaml` for each other entry, NAME being that target's
`name` (here a target named `tls`). See `SCOPE-INTAKE.md`, "One profile per
target". Do not copy or edit a profile to get a second transport: add the
target to `scope.yaml` and compile.

`plan` (and `run --dry-run`) runs on the host, reads only the profiles, and
sends nothing. `run` always runs in the prepared image with a private network
namespace, like `call`: it rejects `--admin` and composes with `--practice`.

## What the profiles approve

A target profile approves exactly one transport (`target.transport` and
`target.port`), so a grid over several transports takes one approved profile
per transport; two profiles with the same transport are refused. The plan is
limited to what the profiles approve, and anything outside it is refused with
exit 2 before anything starts:

| Flag | Values | Approved by |
|---|---|---|
| `--transports T[,T]` | `udp`, `tcp`, `tls`; default every profile's | a given profile with that `target.transport` |
| `--codecs C[,C]` | the `call --codec` names; default the profiles' common `media.codecs` | the profile's `media.codecs` when it has one |
| `--srtp M[,M]` | `off`, `optional`, `mandatory`; default `off` | `features.srtp: true` for anything but `off` |
| `--dial D` | one destination for every cell | each given profile's `target.approved_destinations` when it has one |

`--dial` must be on the approved destination list of every profile that
has one (`GUIDED-CALL.md`, "Approved destinations"). A matrix over two
targets therefore needs the destination under both targets in `scope.yaml`.
Otherwise the plan is blocked (exit 2, nothing sent) with one line per
profile:

```text
BLOCK: work/ENGAGEMENT/target-profile-tls.yaml: destination 'ecoh' is not one of the destinations the owner approved for this target (approved: echo, dtmf); check the spelling, or ask the owner, record the new destination under destinations in scope.yaml, and run scope compile
```

For a profile without the list, the plan prints a `NOTE:` line that the
destination is not restricted by that profile.

Each cell offers only its one codec (plus telephone-event). SRTP over UDP or
TCP is allowed when approved, and the plan prints the
`sdes-key-exposed-on-cleartext-signaling` warning for those cells.

The plan is blocked (exit 2, nothing sent) when the grid has more calls than
`--max-calls` (default 6, at most 48), when it places more calls through a
profile than that profile's `limits.max_calls`, when the profiles that share
one `authorization.approval_id` (the profiles `scope compile` writes for the
targets of one scope) together get more calls than the smallest
`limits.max_calls` among them, or when any profile fails the
guided call's gate (approval, validity window, a literal approved
`target.host`, and an authorization that lasts for the whole planned grid).
Calls start at least 1 s apart, and further apart when a profile's
`limits.max_calls_per_second` asks for it.

The scope's `limits.calls` is the owner's total for the engagement, and
`scope compile` copies it into every target profile as `limits.max_calls`.
Calls already counted under the same approval by `call`, earlier matrices,
`checks run` or `campaign run` count against it too: `matrix run` reserves
the whole grid in `ENG/call-ledger.jsonl` before the first cell and gives back
the cells that sent no INVITE (not run, refused, preflight unanswered,
registration failed), and `matrix plan` is BLOCKED when the grid would exceed
what remains. The plan prints `Calls: N of M used, K left` and how many calls
the grid would place (see SAFETY-AUDIT.md, finding 6). It is not a ceiling per
profile: a grid over the UDP and TLS profiles of a scope with `calls: 6` may
place 6 calls in total, not 6 through each. The plan prints a
`Shared ceiling:` line for such profiles, and a larger grid is refused, for
example with `limits.calls: 3`:

```text
Call matrix plan: BLOCKED - 4 call(s) to echo (--max-calls 6)
BLOCK: the matrix places 4 calls under approval QUAD-APPROVAL-7Q2X, more than its limits.max_calls 3 (2 through work/eng/target-profile.yaml, 2 through work/eng/target-profile-edge-tls.yaml); the profiles of one approval (one scope) share one call ceiling, it is not a ceiling per profile; narrow --transports, --codecs, or --srtp to 3 call(s) or fewer in total, or ask the owner to approve more calls (limits.calls in scope.yaml) and run scope compile
  udp: work/eng/target-profile.yaml (2 call(s); limits.max_calls 3, approved codecs PCMU, PCMA, SRTP not approved)
  tls: work/eng/target-profile-edge-tls.yaml (2 call(s); limits.max_calls 3, approved codecs PCMU, PCMA, SRTP not approved)
  Shared ceiling: approval QUAD-APPROVAL-7Q2X allows 3 call(s) in total across work/eng/target-profile.yaml, work/eng/target-profile-edge-tls.yaml; this grid places 4.
  Calls: 0 of 3 used, 3 left (approval QUAD-APPROVAL-7Q2X, counted in work/eng/call-ledger.jsonl); this matrix would place 4, more than the 3 left, so it would be refused
  ...
This command sent no packets.
Network activity: none
```

The count covers one `matrix run`. Separate `call` and `matrix run`
invocations are not added up (see finding 6 in `SAFETY-AUDIT.md`).

## Running

`run` prints one line on standard error as each cell starts and ends
(`Matrix: cell 3/8 udp/PCMA/srtp off: calling ...`, then its verdict), and
the grid when the run ends. A `--username` without `--secret-env` or
`--secret-file` (or `--no-register`) is refused before anything starts.

Every cell is one complete guided call with every one of its gates: the
profile gate and the authorization re-check before the preflight and before
the call, scoped capture that must be running before anything is sent, one
OPTIONS preflight, one PJSUA call, the media-scope stop, the duration limit,
and the offline report, triage, oracle, and codec proof. A secret from
`--secret-env` is read once; each call receives it only in its own private
environment mapping and never in argv or a file.

The run stops, and the remaining cells are `not-run`, at the first cell
whose verdict is a stop condition: `registration-failed` or
`call-auth-failed` (another call would repeat the credentials),
`call-rate-limited` (429), `call-unavailable` with a 503, `authorization-lapsed`,
`blocked`, `capture-failed`, `capture-died`, `media-outside-scope`,
`signaling-outside-scope`, `internal-error`, or `cancelled`. Ctrl-C, SIGTERM, or SIGHUP hangs up the current call
the same way as `call` and runs no further cell.

Exit status:

| Code | Meaning |
|---|---|
| 0 | Every cell ran and passed |
| 1 | The grid ran; at least one cell did not pass |
| 2 | Refused before any packet (not approved, over a ceiling, a bad argument) |
| 3 | Stopped early on a stop condition; the remaining cells were not run |
| 130 / 143 | Cancelled by SIGINT / SIGTERM |

## Evidence

Each call writes its normal run directory (by default `calls/` next to its
profile, or `--run-root`). The matrix writes one `matrix.json`
(`schemas/call-matrix-v1.schema.json`) in a new mode-0700 directory beneath
the first profile's `matrix/` (or `--matrix-root`). Each cell records its
transport, codec, SRTP mode, profile, status, verdict, exit code, final SIP
status, setup seconds (INVITE to answer, PJSUA log timestamps), the offered
and negotiated codec with its payload type, whether the codec was verified on
the wire, whether SRTP was active, and the call's run directory.

`./bin/sippycup summary ENGAGEMENT` picks the calls up as ordinary call runs
from the `calls/` directories it already reads, and draws the grid from
`matrix.json` (it finds `matrix/` next to the profiles, or use
`summary --matrix-root DIR`); see `ENGAGEMENT-REPORT.md`.

## Practice target

`./bin/sippycup practice-target up` renders ready-made matrix profiles
(`work/practice/target-profile-matrix*.yaml`, `limits.max_calls: 12`, direct and
through the proxy) and `practice-target info` prints the exact commands; see
"Practice the call matrix" in `PRACTICE-TARGET.md`. The older example below
uses hand-made copies of the one-call profiles.

The practice Asterisk endpoints allow only PCMU and PCMA. A run over copies
of the practice profiles with `limits.max_calls: 6`, `features.srtp: true`,
and `media.codecs: [PCMU, PCMA, G722]` (recorded before bn-28vz; both copies
keep the practice approval id, so the same grid now needs
`limits.max_calls: 12` in each, and the output also has a `Shared ceiling:`
line):

```text
$ ./bin/sippycup --practice matrix run work/codec-matrix/udp.yaml work/codec-matrix/tls.yaml \
    --dial echo --codecs PCMU,PCMA,G722 --srtp off,mandatory --max-calls 12 \
    --username practice --secret-file work/practice/account.password --duration 4
Call matrix: COMPLETED - 12 of 12 call(s) placed, 8 passed
  udp: work/codec-matrix/udp.yaml (6 call(s); limits.max_calls 6, approved codecs PCMU, PCMA, G722, SRTP approved)
  tls: work/codec-matrix/tls.yaml (6 call(s); limits.max_calls 6, approved codecs PCMU, PCMA, G722, SRTP approved)
  Each cell is one guided call (4s, offering only its codec), strictly in order, at least 1.0s apart.
  transport  srtp       PCMU         PCMA         G722
  udp        off        pass 0.000s  pass 0.000s  call-media-not-acceptable
  udp        mandatory  pass 0.002s  pass 0.001s  srtp-not-negotiated
  tls        off        pass 0.041s  pass 0.041s  call-media-not-acceptable
  tls        mandatory  pass 0.043s  pass 0.043s  srtp-not-negotiated
```

G.722 is refused with 488 in every row. With `--srtp mandatory` the guided
call reports that 488 as `srtp-not-negotiated`, because mandatory SRTP was not
negotiated either. `make codec-gate` repeats a smaller grid, and a run that
stops at the first 429, against the practice target.
