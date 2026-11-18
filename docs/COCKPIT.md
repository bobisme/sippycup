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
- **Target**: host, port, transport, whether the host is a literal approved
  address, whether an account is needed, and the destinations.
- **Image**: whether the toolbox image exists and whether it is older than
  the last change to its inputs. `make build` records a fingerprint of the
  image inputs in `work/.image-builds/`; without that record the cockpit
  compares the image creation time with the last commit that touched the
  inputs.
- **Practice**: whether the local practice target is up (from
  `work/practice/connection.json`) and the state of its practice profile.
- **Journal**: whether the hash chain verifies, and the last entry.
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
   literal address.
5. **First call**: one guided baseline call with a PASS verdict.
6. **Campaign**: freeze the campaign plan, then run it.
7. **Security checks**: `checks plan`, then `checks run` (through `--practice`
   when the target is the practice address; the password comes from the same
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
