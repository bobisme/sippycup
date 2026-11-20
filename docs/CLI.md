# Unified command-line interface

`./bin/sippycup` is the public entrypoint for every operator workflow. Its
command registry is loaded and validated before dispatch, and the same records
drive routing, help, activity labels, and machine-readable discovery.

```sh
./bin/sippycup --help
./bin/sippycup help torture
./bin/sippycup commands
./bin/sippycup commands --format json
./bin/sippycup version
```

`./bin/sippycup go [DIR]` is the guided operator cockpit: a host-side
dashboard and checklist that starts other public commands only after a
confirmation panel (typed approval token for LIVE actions). It sends no traffic
itself. Its `--plain` and `--format json` modes are read-only; see
[COCKPIT.md](COCKPIT.md).

`./bin/sippycup ready DIR` is the go/no-go check right before the first live
packet (host-side; one loopback-only capture inside a local container, nothing
to the target; exit 0 GO, 1 NO-GO). `./bin/sippycup stop` is the emergency
stop: it ends every container and host process this checkout started (SIGTERM,
then SIGKILL after `--grace`), proves silence, and never touches evidence or
other containers (`--dry-run` lists only). Every container `./bin/sippycup`
starts carries the labels `dev.sippycup.checkout` and `dev.sippycup.command`
for it. See [COCKPIT.md](COCKPIT.md).

These discovery commands do not resolve a target, start a container, or make a
network connection. The JSON output follows
`schemas/commands-v1.schema.json` and always reports `networkActivity: false`.

## Execution boundaries

The registry makes execution location explicit:

- Workbench and first-party analysis commands run directly from the checkout,
  so host paths retain their ordinary meaning.
- Host workflows such as scoped capture and reporting retain their existing
  wrappers and privilege boundaries.
- Preflight and the closed-loop self-test run in the prepared image. Self-test
  always selects the isolated network. Preflight sends from the same private
  network namespace as `call` (same route and source address); only
  `--admin preflight` keeps the host network.
- `campaign run` and `campaign execute` always run in the prepared image with
  a private network namespace, where their own `tcpdump` works rootless (on
  the host it has no permission). They reject `--admin`; `--practice`
  composes. `campaign plan` and the other subcommands run from the checkout.
- A sending command (`call`, `matrix run`, `checks run`, `campaign run`,
  `campaign execute`, `preflight`, `media send`) refuses to start while another
  sender of this checkout is active, found the way `stop` finds them; it names
  the other run and sends nothing. `SIPPYCUP_ALLOW_OVERLAP=NAME[,NAME]` names
  the runs it may knowingly run beside; the run then records `overlap` in its
  result, and `diagnose` and the owner report call its verdict unreliable.
- `SIPPYCUP_ROUTED_PRACTICE=CONTAINER` (set by `make routed-rehearsal`) joins
  the routed practice target: the launcher checks the container and fails
  closed, then maps its link-local address to host loopback in every
  networked container. Nothing else may target a link-local address.
- `call` always runs in the prepared image with a private network namespace,
  where rootless capture works, and rewrites `work/...` paths to `/work/...`.
  It rejects `--admin`. `call --dry-run` and `call --help` run from the
  checkout without a container.
- `checks run` follows the same rules as `call`: a private container, `--admin`
  rejected, and `--practice` composes. `checks list`, `explain`, and `plan` run
  from the checkout and are network-free. See `SECURITY-CHECKS.md`.
- `matrix run` follows the same rules as `call` and places each cell as one
  guided call, one after another. `matrix plan` (and `run --dry-run`) runs
  from the checkout and is network-free. See `CALL-MATRIX.md`.
- Commands that take `--secret-env NAME` (or `REF=NAME`) receive only that
  variable in the container, forwarded with the runtime's name-only
  `--env NAME` form so the value never appears in a command line.
- `doctor` inspects the prepared image by default. `doctor --host` is the
  explicit local inventory.
- `doctor --cleanup` lists Sippycup's own leftovers and `doctor --cleanup --apply`
  removes them (host-side, dry run by default): stale private `/dev/shm`
  directories, stopped Sippycup containers, dangling Sippycup image builds. It
  never touches `work/`. See `./bin/sippycup doctor --cleanup --help`.
- `mcp` runs in a fixed offline container: no network, no Linux capabilities,
  read-only root and work files, and no `--isolated`/`--admin` broadening.
- Adding `--isolated` or `--admin` before a packaged first-party command runs
  that command in the image with the requested boundary.
- `--practice` runs container commands in the network namespace of the
  running local practice target (loopback only) with `NET_RAW`, and routes
  packaged commands into the image like `--isolated`. It fails closed when
  the target is not up and cannot be combined with `--isolated` or
  `--admin`; `mcp`, `mcp-live`, `selftest`, and host-side commands reject it.
  See `PRACTICE-TARGET.md`.

Examples:

```sh
./bin/sippycup capture --target staging.example.invalid --dry-run
./bin/sippycup preflight staging.example.invalid 5060 udp --dry-run
./bin/sippycup torture exit-gate
./bin/sippycup --isolated --admin chaos capabilities
./bin/sippycup selftest /work/selftest.pcap
./bin/sippycup call work/engagement/profile.yaml --dial 1001 --dry-run
./bin/sippycup checks plan work/engagement/profile.yaml
./bin/sippycup matrix plan work/engagement/profile.yaml --dial 1001 --codecs PCMU,PCMA
./bin/sippycup webrtc validate examples/webrtc/offline-scenario.json
./bin/sippycup webrtc signaling-self-test
```

The guided optional WebRTC path, including failure recovery and the live
admission boundary, is documented in `docs/WEBRTC-WORKFLOW.md`.

An activity label describes what a command *can* do; it is never target
authorization. `offline` help or planning does not make a later execution
authorized.

## Scope binding

Every command that can send traffic is in one of three classes. The class says
whether the command checks an owner approval before it sends.

| Command | Class | What is checked before the first packet |
| --- | --- | --- |
| `call`, `matrix`, `checks` | Scope-bound | The profile must pass `rehearse` (approved, inside its window, literal approved addresses), and the window must cover the run. |
| `campaign` | Scope-bound | The frozen plan must match the reviewed manifest and its authorized networks. The plan carries the approval window when the manifest states it (`scope compile` writes it); a manifest without a window runs with a warning (see `SAFETY-AUDIT.md`, finding 5). |
| `mcp-live` | Scope-bound | A signed capability and a profile-bound plan (`MCP-LIVE.md`). |
| `go` | Scope-bound | The cockpit sends nothing itself. It starts only the commands above, after its own profile and approval checks. |
| `preflight` | Optionally bound | With `--profile`: the same profile checks, and the target is the profile's. Without: nothing. |
| `media` | Optionally bound | `media send --profile`: the same profile checks, and the SDP destination must be in the media scope. Without: loopback destinations only. |
| `capture` | Unbound | It sends nothing. It records the host or network that you name. |
| `chaos`, `chaos-exit-gate` | Unbound | Local network impairment. The topology file names the scope. |
| `webrtc` | Unbound | The optional peer has its own admission boundary (`WEBRTC-WORKFLOW.md`). |
| `media-echo`, `selftest`, `practice-target`, `ready`, `stop` | Unbound (local only) | Loopback or a private namespace. They take no target. |
| `shell`, `-- COMMAND` | Unbound | Nothing. They run arbitrary in-image tools. |

Commands that are not in the table are offline.

`preflight` and `media send` print one `Scope:` line in human output and a
`scope` object in JSON output:

```text
Scope: profile acme-staging (approval CHG-4711, window 2026-11-20T08:00:00Z to 2026-11-20T16:00:00Z)
Scope: UNBOUND (operator-supplied target 192.0.2.10)
Scope: UNBOUND (loopback only)
```

```json
{"binding":"profile","profile":"acme-staging","profileFile":"work/acme/target-profile.yaml",
 "approvalId":"CHG-4711","validFrom":"2026-11-20T08:00:00Z","validUntil":"2026-11-20T16:00:00Z"}
{"binding":"unbound","operatorSuppliedTarget":"192.0.2.10"}
{"binding":"unbound","reason":"loopback only"}
```

For `media send` the bound object also has `destinations`: each remote SDP
endpoint with the rule that admitted it (`approved-address`, or
`media-network` and the network).

`--require-profile`, or `SIPPYCUP_REQUIRE_PROFILE=1` in the environment, makes
`preflight` and `media send` refuse to run without `--profile` (exit 2, nothing
sent). Any value other than empty or `0` turns it on. It does not change
`shell` or `-- COMMAND`.

`shell` and `-- COMMAND` print this on stderr before they start, and enforce
nothing:

```text
Scope: UNBOUND (the -- escape hatch: no approval, window, address or port is checked here; it can send to any address this host can reach). Send only to addresses copied from the approved profile.
```

A refused bound command exits 2 before it resolves a name or opens a socket.
The message says what was refused, that nothing was sent, and what to do.

## Preflight

`preflight HOST [PORT] [udp|tcp|tls]` resolves HOST, checks TCP reachability
for TCP and TLS, prints an informational `openssl s_client` certificate
summary for TLS, and sends one SIP OPTIONS transaction with the in-image
`sippycup-options` client. Over UDP it sends at most two datagrams.

For an engagement use `preflight --profile PROFILE`. The approval and its
window (which must cover the 40 s that a preflight can take) are checked
first. HOST, PORT, the transport, the TLS server name and the CA come from the
profile, and `target.host` must be a literal approved address. You may also
type them, but then each one must equal the profile's value. A mismatch, or
`--tls-unverified`, is refused with exit 2 before any packet.

| Option | Meaning |
| --- | --- |
| `--profile PROFILE` | Bind to an approved target profile (see "Scope binding") |
| `--require-profile` | Refuse to run without `--profile` |
| `--format text\|json` | `json` prints one `sippycup.dev/preflight-result/v1` object on stdout (`target`, `scope`, `dryRun`, `networkActivity`, `exitStatus`, and `options`: the `sippycup-options` result) and the stage output on stderr |
| `--expect-status N` | Require this final status (default: any 2xx) |
| `--expect-class C` | Require `2xx`, `3xx`, `4xx`, `5xx`, `6xx`, or `any` |
| `--tls-ca /work/PATH` | Also trust this PEM CA file; it must be under `/work` |
| `--tls-server-name NAME` | Verify the certificate for NAME and send it as SNI; packets still go only to HOST |
| `--tls-unverified` | Skip certificate verification; always reported as `UNVERIFIED`, never the default |
| `--dry-run` | Print the bounded plan; no resolution or traffic |

TLS verifies by default, against `--tls-server-name` or else HOST. The
removed `--tls-ignore-cert-failure` is rejected with a usage error. The first
failing stage decides the exit code:

| Exit | Meaning |
| --- | --- |
| 0 | A final response met the expectation |
| 1 | A final response arrived but did not meet the expectation |
| 2 | Usage error; nothing was sent |
| 3 | No valid final response before the deadline (UDP silence or ICMP port unreachable, TCP connect timeout, closed or malformed reply) |
| 4 | Name resolution failed, connection refused, or host/network unreachable |
| 5 | TLS handshake or certificate verification failed |

```sh
./bin/sippycup preflight --profile work/engagement/profile.yaml --expect-class any
./bin/sippycup preflight staging.example.invalid 5060 udp --expect-class any
./bin/sippycup --practice preflight 127.0.0.2 5061 tls \
  --tls-ca /work/practice/ca.crt --tls-server-name sippycup-practice
```

The in-image client is also available as an advanced tool with the same exit
codes and a machine-readable result:

```sh
./bin/sippycup -- sippycup-options 192.0.2.10 5060 udp --format json
```

`sippycup-options HOST PORT TRANSPORT [--timeout S] [--expect-status N |
--expect-class C] [--tls-server-name NAME] [--tls-ca-file PATH] [--insecure]
[--format text|json]` accepts an IP literal (IPv6 with or without brackets)
or a name, which it resolves once. It is not a registry command.

## Third-party tools and the shell

Use `shell` for an interactive toolbox or `--` for one arbitrary in-image
command:

```sh
./bin/sippycup shell
./bin/sippycup -- tshark -r /work/selftest.pcap
```

The escape hatch intentionally exposes the container toolbox and is not part
of the stable first-party command contract. Both print a `Scope: UNBOUND`
notice on stderr first: nothing they run is checked against an approval (see
"Scope binding").

## Compatibility

The sibling scripts and installed `sippycup-*` binaries remain compatibility
entrypoints throughout the 1.x line. They are implementation interfaces:
existing automation may continue using them, but new documentation and
examples use the unified entrypoint. Compatibility shims preserve argument
boundaries, exit status, signals, and machine-readable stdout without adding
deprecation text.

Campaign runners, loopback fixtures, container preflight/report helpers,
runtime selection, and smoke programs are internal. They do not appear in
global help and may change independently of the public command registry.

## Engagement report

`./bin/sippycup summary DIR` is a workbench command: it runs from the checkout
on the host (and in the image under `--isolated` or `--practice`), reads only
recorded artifacts, and writes the owner report to `DIR/report/`. Exit status
is 0 when written, 1 when written with integrity exceptions, 2 for usage
errors, and 3 when the privacy lint refused to write anything. See
`ENGAGEMENT-REPORT.md`.

## Call ladder

`./bin/sippycup ladder RUN_DIR|CAPTURE [--format text|html|json] [--output FILE]
[--call-id-index N] [--width N] [--approve NET] [--show-addresses]` draws a
redacted SIP and media sequence diagram from recorded evidence. It is offline
(`direct` mode: host, or the image under `--isolated`/`--practice`). Exit
status is 0 when drawn, 2 for bad arguments or an unusable path, 3 for an
unreadable capture, 4 when there is nothing to draw (no SIP, TLS, or RTP), and
5 for an internal error or a privacy lint refusal. See `LADDER.md`.

## Diagnose a run

`./bin/sippycup diagnose RUN_DIR [--format text|json] [--brief] [--output FILE]
[--no-ladder] [--width N] [--approve NET] [--show-addresses]` and
`./bin/sippycup diagnose --compare RUN_A RUN_B` turn a guided call, matrix,
campaign, or checks run directory into one page: what happened and at which
stage, the decisive evidence, whose side it probably is on and how sure that
is, and the next `./bin/sippycup` commands built from the run's own recorded
profile and flags (or a stop-and-ask). It is offline (`direct` mode, like
`ladder`). Exit status is 0 when written (even for a failed run), 2 for bad
arguments or an unusable path, 4 when the directory is not a known run, and 5
for an internal error or a privacy lint refusal. `--brief` prints five lines
for the cockpit. See `DIAGNOSE.md`.


## Dress rehearsal

`./bin/sippycup practice-target rehearsal` walks the whole owner-facing chain
against the local practice target with the public commands, in the order of a
real engagement: `journal init`, `scope init`, the cockpit's practice call,
`scope check` and `scope compile`, `rehearse`, `--practice preflight` over UDP
and verified TLS, the guided `call` (and one with `--dtmf`), `campaign plan`
and `campaign run`, `checks plan` and `checks run`, the cockpit's evidence
actions, and `summary --forbid-file`. After each stage it requires
`go --plain` and `go --format json` to agree with each other and with the
stage just finished. It prints PASS or FAIL per stage with the exact commands,
exits 0 only when every stage passed (1 on a failure, 2 when it could not
start), keeps the evidence in `work/practice/rehearsals/dress-STAMP/`, and
starts and stops the practice target only when it was down. `--list` prints
the stages and sends nothing. `make dress-rehearsal` runs it. The approved
checks include `srtp-policy`, and a last stage shows the media-scope safety
stop once in a throwaway engagement (`DIR-stop`). `--proxy` (`make
dress-rehearsal-proxy`) writes the scope answers in the proxy shape:
signaling to the practice proxy `127.0.0.3` (407 challenges, realm and
certificate name `sippycup-proxy`), media from `127.0.0.2`. `--media-cidr`
(`make dress-rehearsal-proxy-cidr`) is the proxy shape with media answered
as the range `127.0.0.2/31` (a media-only `media.networks` entry). See
`PRACTICE-TARGET.md`.

## Scope intake output

`./bin/sippycup scope answer DIR [QUESTION]` records the owner's answers in
`DIR/scope.yaml` question by question: it prints each open question as on the
sheet, asks its answers field by field, checks each with the `scope check`
rules (a refused answer is explained and asked again), and saves it at once,
atomically and mode 0600, keeping comments. Enter leaves a question open;
`quit`, Ctrl-C, and end of input stop and keep what was saved. It never asks
for a password and records `approved` only when that word is typed at the
approval prompt, which the walk asks last, with a summary of what is approved.
Any later change to what may be sent (a target, a destination, a limit, the
media ranges, `--set` included) sets the approval back to `pending` and says
so. QUESTION opens exactly what it names (a question, a field such as
`contact.channel`, a list, or one entry such as `targets[1]`) and refuses a
name that matches nothing. `--all` also walks answered questions, and
`--set FIELD=VALUE` (repeatable) records plain answers without prompts (never
the approval). It ends with the check result, the open questions, and the next
command. `scope check` ends with a `Next:` line, and `scope init` on a missing
directory prints the full `journal init DIR --title ... --owner ...` command.
Hand-editing `scope.yaml` remains an alternative. See `SCOPE-INTAKE.md`,
"scope answer".

`./bin/sippycup scope init DIR --platform` also writes the empty `platform`
and `application` sections. `scope questions` prints two parts: the SIP
service, then "Part 2: the whole platform" (questions P1 to P18 and A1 to A6).
For a scope file with those sections, `scope check` prints their open answers
as `WARN` lines (exit 0 when the SIP part is clean), `scope compile` prints
`Wrote application-surfaces: PATH (sha256 ...) [record only; nothing is sent]`
and its JSON carries `applicationSurfaces`, the cockpit prints `Platform` and
`Web surfaces` lines, `status --format json` carries `facts.scope.platform`,
and `ready` prints the line `Production safety answers`. A scope file without
the sections produces the same output as before, except for part 2 of the
question sheet. See `SCOPE-INTAKE.md`, "Platform and application answers".

## Bash completion

Source the completion from a checkout:

```sh
source completions/sippycup.bash
```

Top-level command names are read from the live JSON registry, so completion
cannot drift from `sippycup --help`.
