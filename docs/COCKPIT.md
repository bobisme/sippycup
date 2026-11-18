# The operator cockpit: `./bin/sippycup go`

`./bin/sippycup go [DIR]` shows where an engagement stands and walks you
through the next step. It reads files on disk, shows a nine-stage checklist,
and offers the next commands. When you choose one, it starts the ordinary
public command (`./bin/sippycup ...`) and streams its output.

The cockpit is a guide, not a new gate. It never sends traffic itself, never
calls a library entry point that would skip a check, and never weakens the
gates in the commands it starts. Every LIVE command still checks scope,
authorization, the literal approved address, and the profile limits itself.

## Start

```bash
./bin/sippycup go                 # find the engagement under work/, or create one
./bin/sippycup go work/acme       # a specific engagement
./bin/sippycup go --plain         # print the dashboard once and exit
./bin/sippycup go --format json   # the same model as JSON (sippycup.dev/cockpit/v1)
./bin/sippycup go --line          # numbered menu, no full-screen UI
```

Without `DIR`, the cockpit looks for engagement directories directly under
`work/` (it ignores `work/practice`). With one candidate it uses it; with more
than one it lists them (and asks, when interactive). With none, an interactive
session offers to create one with `journal init` and `scope init`; a
non-interactive session prints those commands and exits with status 2.

Modes:

- A terminal at least 60x20 with a usable `TERM` gets the curses UI.
- `TERM=dumb`, a smaller terminal, or `--line` gets the line UI: numbered
  actions and typed commands. It works in any terminal and over a screen
  reader.
- With no terminal (a pipe, CI), the cockpit prints the plain dashboard once.
  The last line is always `Next: <command>`.

`--no-runtime` skips the container-runtime checks (image age, practice target
container), so the dashboard comes from files alone.

## What the dashboard shows

- **Authorization**: the state of the approval in the target profile
  (`valid`, `expiring` under 60 minutes, `expired`, `not-yet-valid`,
  `pending`, `revoked`, `missing`) with a live countdown and the approval id.
- **Scope**: `missing`, `incomplete` (with the unanswered owner questions,
  never their values), `inconsistent`, `stale` derivatives, or `complete`.
- **Platform** and **Web surfaces** (only when the scope file has a
  `platform` or `application` section): the environment, how many of the 24
  platform questions are open and exactly which (number, group, state, and
  the question, never the answer), the open production-safety answers, each
  web surface with `ready`, `pending`, `undecided`, or `out-of-scope`, and
  the state of the `application-surfaces.yaml` record. `[??]` means open
  answers; they do not hold the SIP stages. `[!!]` means an answer holds the
  SIP profile (for example a destination that reaches the public phone
  network without the carrier's permission). The line always says that
  nothing is sent to web surfaces. Stage 3 gains the step
  `platform and web answers recorded (N open; they do not hold the SIP tests)`.
- **Target**: host, port, transport, whether the host is a literal approved
  address, whether an account is needed, and the destinations.
- **Profile** (only when the scope has more than one target): one line for
  each profile that `scope compile` wrote, `target-profile.yaml` for the
  first target and `target-profile-NAME.yaml` for each other one. Each line
  gives the target, the destinations that profile accepts for `--dial`,
  and whether the profile is ready and current, stale, edited, or missing.
  The numbered actions (rehearse, go/no-go, the guided call, the checks) use
  `target-profile.yaml`. For each other profile the cockpit offers two
  `[offline]` actions, its `rehearse` and its dry run. To place a call with
  such a profile, run the printed dry run command from a shell without
  `--dry-run` and with the password source. The destination the cockpit
  suggests is always one that the profile in the command approves.
- **Image**: whether the toolbox image exists and whether it is older than
  the last change to its inputs. `make build` records a fingerprint of the
  image inputs in `work/.image-builds/`; without that record the cockpit
  compares the image creation time with the last commit that touched the
  inputs.
- **Practice**: whether the local practice target is up (from
  `work/practice/connection.json`) and the state of its practice profile.
- **Journal**: whether the hash chain verifies, and the last entry.
- **Go/no-go**: the newest `ready` result (`DIR/readiness/`), whether it was
  for the current profile, and the source address it saw.
- **Runs**: guided calls, practice calls, campaign runs, and security-check
  runs (`findings.json`, `sippycup.dev/findings/v1`). Unreadable or oversized
  files are shown as `[??]` and never stop the dashboard.
- **Next actions**: the commands for the current stage first, then the
  status advisor's suggestions. Each has a network label.

Status always uses text markers; colour is only a supplement and is off when
`NO_COLOR` is set.

| Marker | Meaning |
| --- | --- |
| `[ok]` | done or healthy |
| `[!!]` | needs attention, or blocked |
| `[??]` | unknown or unreadable |
| `[stop]` | a run Sippycup stopped itself to stay inside the scope (for example `media-outside-scope`): a safety stop, not a target failure |
| `[  ]` | not done yet |
| `[>>]` | the current stage |
| `[--]` | recommended but skipped |
| `[..]` | a manual step for you to do |
| `[offline]` | network-free; runs when you press Enter |
| `[local]` | changes local containers or files; asks y/N |
| `[LIVE]` | sends traffic; needs the typed approval token |

## The nine stages

The stage text lives in one module (`lib/sippycup_cockpit/help_text.py`);
press `?` or type `sN` to read it in the cockpit.

1. **Prepare**: the engagement record and a current toolbox image.
2. **Practice**: a passing guided call against the local practice target.
   Recommended; type `skip` (line UI) or press `S` (curses) to move on
   without it. The skip is stored in `.cockpit.json` and is never shown as
   done.
3. **Scope**: answer the owner questions, check, and compile.
4. **Rehearse**: the compiled profile is approved, in its window, and names a
   literal address, and the go/no-go check (`./bin/sippycup ready DIR`, see
   below) said GO for exactly this profile. It is the gate before the first
   live stage.
5. **First call**: one guided baseline call with a PASS verdict.
6. **Campaign**: freeze the campaign plan, then run it.
7. **Security checks**: `checks plan`, then `checks run` (through `--practice`
   when the target is the practice address or the practice proxy's address,
   like every live action; the password comes from the same
   `file`/`env` prompt as the call). Done when a checks run completed: its
   `result.json` state is `completed` and no check ended in `error`. Findings
   are the output of a completed run, not a failure. Shown as `[--]` not
   applicable when the profile's `security_checks.approved` is empty.
8. **Evidence**: every run has an evidence manifest and a journal entry.
9. **Owner report**: `summary DIR --journal` wrote `report/report.json` (or a
   newer `report-STAMP/`) with no integrity exceptions, and that report lists
   every run (run it again after a new run). An internal draft from the
   journal is optional.

Each stage is derived from files on disk, so the cockpit shows the same state
after a restart, and work done outside the cockpit counts.

The cockpit does not offer the advisor's `init` (a hand-made pending profile):
`scope compile` refuses to overwrite a profile it did not generate
(`scope.derivative_unmanaged`), so following both would block stage 3.
`./bin/sippycup practice-target rehearsal` drives a whole engagement through
these stages and checks after each one that `go --plain` and `go --format json`
agree; see [PRACTICE-TARGET.md](PRACTICE-TARGET.md).

## Confirmation

Every action opens a panel first. It shows the exact command, the network
label, and, for LIVE actions, what will be sent:

- the literal address, port, and transport;
- the route (`--practice` when the target is the practice address);
- the profile limits;
- the approval id and its source file;
- the plan from a network-free dry run (`call ... --dry-run --format json`,
  or the frozen campaign plan's destinations, totals, and hard maxima).

`[offline]` actions run on Enter. `[local]` actions ask `y/N`. A `[LIVE]`
action starts only when you type the last four characters of the approval id.
A wrong or empty token starts nothing. The cockpit refuses a LIVE action, and
offers no token prompt, when:

- there is no GO from `./bin/sippycup ready DIR` for the current profile (the
  last check said NO-GO, was for an earlier version of the profile, or was
  never run). The practice call is not gated. A GO older than 12 hours is
  shown with a reminder to run `ready` again;
- the profile has no approval id;
- the profile is not ready (`rehearse` would refuse it: expired, not yet
  valid, not approved, or not a literal address);
- the dry run reports BLOCKED or fails.

The command that runs is the one shown in the panel, plus only the password
source you choose.

## Passwords

The cockpit never accepts a password as typed text. When the target needs an
account, answer the prompt with one of:

- `file PATH`: a regular file beneath `work/`, not a symbolic link, with no
  group or other permissions (mode 0600). The command gets
  `--secret-file PATH`.
- `env NAME`: an environment variable that is already set. The command gets
  `--secret-env NAME`.

To create a file without the password reaching shell history:

```bash
(umask 077; IFS= read -rs P; printf '%s' "$P" > work/acme/account.password; unset P)
ls -l work/acme/account.password   # expect -rw-------
```

For a campaign, the cockpit reads the file and passes it to the child process
in the environment variable `SIPPYCUP_COCKPIT_SECRET`
(`--secret-env REF=SIPPYCUP_COCKPIT_SECRET`). The value never appears in argv,
the screen, logs, or the journal.

## Running and stopping

Output streams as the command runs. Ctrl-C is forwarded to the command, so
its own clean shutdown runs (for a campaign, the supervisor stops and records
the stop). The cockpit restores the terminal on every exit path, including
SIGTERM (exit status 143).

When the command finishes, the cockpit shows its exit code and any new run
directory, then refreshes the dashboard.

## Go/no-go: `./bin/sippycup ready DIR`

Run it right before the first live packet (the cockpit offers it as the
`[local]` action of stage 4). It sends nothing to the target and gives one
verdict, GO or NO-GO, with one line per check and, for every NO-GO or
warning, the command or manual step that fixes it:

| Line | GO when | NO-GO when (fix) |
| --- | --- | --- |
| Engagement record | the journal hash chain verifies | no engagement or a broken journal (`journal verify`) |
| Scope compiled and current | scope.yaml is complete, consistent, and compiled | stale, incomplete, or not compiled (`scope compile`, `scope check`) |
| Profile passes rehearse | `rehearse` would accept it | any `rehearse` error (fix scope.yaml, compile) |
| Production safety answers (only when the scope has a `platform` section) | every production-safety answer is recorded, or the scope says `staging` or `dedicated-test`; open answers on production (or with no environment answer) are a WARNING that lists the open questions, and so is a confirmed destination that reaches the public phone network | a destination reaches the public phone network without the carrier's permission and a toll answer, a destination is on the never-dial list, or `limits.concurrent_calls` is above the owner's production maximum (`scope check`) |
| Approval window | it started, and more than `--margin` minutes (default 60) plus a frozen campaign plan's duration remain; shown in local time and UTC with the time remaining (less is a warning) | not open yet (wait until the printed time), expired, or not approved |
| Clock synchronised | `timedatectl` (or `chronyc tracking`) says synchronised; no time server is contacted | the host says it is not synchronised (`timedatectl set-ntp true`); unknown is a warning |
| Toolbox image | present and its build record matches this checkout | missing or built from other code (`make build IMAGE=...`) |
| Capture and disk | a loopback-only capture works inside a container started exactly like the live commands' (`--isolated`, or `--practice` for the practice target), and work/ has `--min-free-mb` (default 2048) free | the capture or the container fails, work/ is not writable, or the disk is short |
| Credentials | the `--secret-file` or `--secret-env` you will use exists, is yours, mode 0600, beneath work/, and holds exactly one line (a trailing line break is fine: the tools remove it) | missing, group- or world-readable, empty, more than one line, leading or trailing spaces, a byte-order mark, not UTF-8, or inside a run, report, or pack directory |
| TLS trust (TLS profiles) | the server name is set, the CA file parses, matches the digest frozen in plan.json, and has not expired (under 7 days is a warning) | no server name, an unreadable CA, a changed CA, or an expired one |
| Network position | the kernel has a route to the target (`ip route get`, no packet), from the host and inside the live commands' container | no route |

The network line prints your source address prominently: it is the address
the owner allowlists. When that source is private and the target public, a
NAT sits in the path (the owner must allowlist your public address, and
one-way audio is more likely); a VPN interface or two default routes are
also warnings. Without `--secret-file`/`--secret-env`, `DIR/account.password`
is checked when it exists; otherwise the line is a warning.

The result ends with what the profile authorizes on one screen (addresses,
media networks and ports, codecs, transports, limits, campaign maxima,
approved checks, account, window, approval id) for a last read-through. It
asks for no typed phrase: the LIVE action itself asks for the last four
characters of the approval id, as always.

`ready` writes the result (no secret) to `DIR/readiness/ready-STAMP.json`
(mode 0600; `--no-record` skips it) and prints the `journal add` command that
records it. Exit codes: 0 GO, 1 NO-GO, 2 usage error. `--format json` prints
the same result (`sippycup.dev/ready/v1`).

```bash
./bin/sippycup ready work/acme --secret-file work/acme/account.password
./bin/sippycup ready work/acme --secret-env SIP_PASSWORD --margin 90 --format json
```

## Emergency stop: `./bin/sippycup stop`

When the owner says "stop now", run `./bin/sippycup stop` in any terminal on
this host. It ends every Sippycup sender started from this checkout and
proves the silence:

1. It finds every running container that `./bin/sippycup` started from this
   checkout (each carries the labels `dev.sippycup.checkout` and
   `dev.sippycup.command`; an unlabelled container from exactly
   `$SIPPYCUP_IMAGE` also counts), lists the processes inside each
   (PJSUA, SIPp, the media sender, dumpcap), and any host process started
   from this checkout's sender commands.
2. It sends SIGTERM to each. Every Sippycup command handles it: the guided
   call, the matrix, the checks, and the campaign's softphone runner hang
   up an answered call with BYE (CANCEL a ringing one), unregister, stop the
   capture, and record the run as `cancelled`.
3. After `--grace` seconds (default 30) anything still running is killed and
   reported as FORCED.
4. It looks again from scratch and proves that no container of this
   checkout is running and no sender process is left (`Silence: PROVED`).

It never touches evidence under work/, containers of another checkout or
image, or the practice target (add `--include-practice` to take the practice
target down too, through `practice-target down`). It prints what it stopped
and how (clean or forced), and a `journal add` command to record the stop
(`--engagement DIR` fills in the directory). Exit codes: 0 silence proved (or
nothing was running), 1 something could not be stopped or the runtime could
not be asked, 2 usage error. `stop --dry-run` lists what would be stopped and
signals nothing.

```bash
./bin/sippycup stop --dry-run
./bin/sippycup stop --engagement work/acme
```

`make stop-gate` (opt-in, needs both images, about 4 minutes) proves this
against the practice target: it stops a 60-second guided call, a call matrix,
a softphone campaign, and a checks run mid-flight and checks that each
capture shows the BYE and no RTP after it, that each run records
`cancelled`, and that silence is proved.

## Run browser

Type `rN` (line UI) or choose the Runs tab (curses) to open a run. It shows
the verdict, the key facts, the notes, the files, and quick network-free
actions:

| Key | Action |
| --- | --- |
| `v` | read `report.txt` in a pager |
| `t` | `triage` the capture |
| `a` | `assert` the expectations against the capture |
| `m` | `evidence manifest` |
| `l` | `evidence lint` |
| `p` | `evidence pack` |
| `j` | add a journal entry with this run's evidence |

A journal note goes to `journal add --summary-file -` on standard input, so it
never appears in argv. Do not put secrets in a note.

## Keys

| Line UI | Curses | Action |
| --- | --- | --- |
| `N` | arrows, Enter | choose action N |
| `rN` | Tab, then arrows | open run N |
| `sN` | `1`..`9` | stage help |
| `skip` | `S` | skip or restore the practice stage |
| `?` | `?` | help |
| Enter | `r` | refresh |
| `q` | `q` | quit |

## Related

- [ASSESSMENT-WORKFLOW.md](ASSESSMENT-WORKFLOW.md): the same workflow as
  separate commands.
- [PRACTICE-TARGET.md](PRACTICE-TARGET.md): the local practice target.
- [CLI.md](CLI.md): every public command.
