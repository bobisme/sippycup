# First engagement: the evening before

Read this the evening before your first engagement. It gives the exact order
of commands for the two common shapes:

- **direct**: the SIP server is the target, and media comes from the same address;
- **proxy**: a proxy or SBC is the target, and media comes from other addresses
  that the owner gives as a network (CIDR).

It tells you what each stage prints when it is right, when to stop, and what
to send to the owner. Every command here was run end to end on the practice
target (`./bin/sippycup practice-target up`). Rehearse the sequence there
first. `work/acme` is a placeholder for your engagement directory.

The commands below show `--practice`. Against the owner's target, give the
same command without `--practice`. That route (the toolbox's own private
network namespace, NAT, a real capture interface) is rehearsed on this host by
`make routed-rehearsal`; run it once before the real target (section 0).

## 0. Before you start (offline)

```sh
make build
./bin/sippycup doctor
./bin/sippycup journal init work/acme --title "ACME voice test" --owner "ACME voice team"
./bin/sippycup scope init work/acme
(umask 077; ./bin/sippycup scope questions work/acme > work/acme/questions-for-owner.md)
```

The `umask` keeps the file private like the other engagement files (a plain
`>` creates it readable by everyone on the machine).

- When it is right: `doctor` prints `Doctor: ready`. `scope init` prints
  `Created pending scope file: work/acme/scope.yaml` and
  `No addresses, approval, limits, or credentials were invented.`
- **Send to the owner:** `questions-for-owner.md`. Do not continue until you
  have their written answers: the literal addresses, the window, the limits,
  the destinations, the account, and, for the proxy shape, the media network
  and the media port range.
- If `scope init` says `engagement directory does not exist`, run the
  `journal init ... --title "..." --owner "..."` command it prints first.

### Before the real target: the routed rehearsal

```sh
make routed-rehearsal
```

It walks the whole chain (scope, compile, ready, preflight, calls, TLS+SRTP,
DTMF, matrix, campaign, checks, evidence lint, owner report, an overlapping
call, and `stop` during a call) with the commands exactly as this page gives
them for a real target: no `--practice`. The target is the practice image on
an internal network; your commands reach it from their private network
namespace through a real NAT (the rootless port forwarder), so you see what
the owner's network will show you. Nothing leaves this machine. It prints
`Routed rehearsal: PASS in ... (14/14 stages)` at the end; see `PRACTICE-TARGET.md`, "Routed
rehearsal". If it fails, fix that first: the same command will fail against
the owner.

### Practice target: answer the questions as you will for the owner

`./bin/sippycup practice-target info` prints the address, ports, account and
realm, but not a window, limits, contact or the other answers an owner would
give. The worked example `examples/scope/practice-scope.yaml` has all of them.
Rehearse the real step: run `scope answer` and type the example's values
(its comments say where each one comes from):

```sh
./bin/sippycup practice-target up      # "container ... already exists" means it is already up: carry on
./bin/sippycup scope answer work/acme
```

| Question | Type |
|---|---|
| 1 | `LOCAL-PRACTICE-ONLY`, `practice target (you)` |
| 3 | `UTC`, `now`, `+4h` |
| 4 | `127.0.0.2` |
| 5 | `5060, 5061`, `udp, tls`; target `practice`, Enter (address 127.0.0.2), `udp`, Enter (5060), `y`; target `tls`, Enter, Enter (tls), Enter (5061), certificate name `sippycup-practice`, CA `work/practice/ca.crt`, `n` |
| 7 | `127.0.0.1` |
| 8 to 10 | `yes`; `practice`, `sippycup-practice`; `practice-password`, `other` |
| 11 | `echo` `practice` `echo` `echo`, `y`; `dtmf` `practice` `dtmf` `echo`, `y`; `echo-tls` `tls` `echo` `echo`, `n` |
| 12 to 16 | `127.0.0.2`; `20000`, `20019`; `rtp, sdes-srtp`; `PCMU, PCMA`, `rfc4733`; `yes` |
| 17 to 19 | `40`, `2`, `1`; `200`, `200000`, `50000000`; `60`, `3600` |
| 20 to 23 | `3`, `yes`, `20`; `options, call`, `none`; `you`, `this terminal`, `yes`; `7`, `private` |
| 2 (asked last) | `approved`, after reading the summary it shows (on a real engagement: only with the owner's written approval of exactly that summary) |

Changing an answer that decides what may be sent (a target, a destination, a
limit, the window, the media ranges) sets the approval back to `pending`, and
nothing can be sent until you do both of these, in this order:

```sh
./bin/sippycup scope answer work/acme 2      # record the approval again (only with the owner's written approval)
./bin/sippycup scope compile work/acme
```

Every message that tells you to change such an answer names these two
commands. If you compile first, `scope compile` says `NOTHING CAN BE SENT with
what this wrote` and prints the same `Next:` line; a call then prints
`BLOCK: authorization is pending, not approved; ...` with it too.

**With `--platform`** (see "When the owner wants the whole platform tested"
below) `scope answer` reaches part 2 after question 23. It asks once:

```text
== Part 2: the whole platform (questions P1 to P18 and A1 to A6) ==
  24 of these questions are still open: P1, P2, ...
  Walk the platform questions now? [y/N] >
```

Press Enter (or `n`) when the owner has not answered them yet: they stay open,
nothing is invented, and it goes straight on to question 2. Open platform
answers are `WARN` lines and do not hold the approval. Type `y` to walk them.
If you record the approval first and the platform answers later: recording or
changing P3 to P17 or A1 to A3 sets the approval back to pending (they are
part of what the owner approves), and question 2 is asked again at the end of
that session. P1, P2, P18 and A4 to A6 never change the approval. The header
prints the same list.
On the practice target, rehearse them once with these answers:

| Question | Type |
|---|---|
| Part 2 offer | `y` |
| P1 | `Practice platform`; then for the eleven parts: `yes`, `yes` (SIP edge, media servers), and `no` nine times |
| P2 | `nothing` |
| P3 to P6 | `dedicated-test`; `no`; `none`; `none` |
| P7 to P10 | `none` for each company (hosting, CDN or web firewall, phone carrier, SMS, e-mail: five times). Each is then recorded as not involved (`out-of-path`), and its permission and reference are not asked |
| P11 | `on-net` for each destination (three times: echo, dtmf, echo-tls) |
| P12, P13 | `none`, Enter (no prefixes); `no-cost` |
| P14 to P17 | `any time, UTC`; `2`, `1`; `none`; `you`, `this terminal`, `stop` |
| P18 | `sippycup-practice`, `127.0.0.2`, `no`, `no`, `n` |
| A1 to A6 | not asked: they apply only when a web part (admin console, customer web app, API, browser calling) is `yes` in P1 |
| 2 (asked last) | `approved`, after reading the summary; it now has a `Platform dialing` line that says for each destination `stays on the platform`, `REACHES THE PUBLIC PHONE NETWORK`, or `NOT RECORDED` |

To rehearse A1 to A6 as well (your real engagement may have an admin console
in scope), answer `yes` for the admin console in P1 (the third part) and then:

| Question | Type |
|---|---|
| A1 | `admin-console`, `browser`, `yes`, `https://sippycup-practice/admin`, `n` |
| A2 | `127.0.0.2`, `443`, `sippycup-practice`, `public` |
| A3 | not asked (no browser calling) |
| A4 | `admin-test`, `admin`, `practice-tenant`, `admin-test` (a reference NAME, never a password), `n` |
| A5, A6 | `none`; `none`, Enter |

These are a record only: nothing in Sippycup sends web requests, and the
practice target has no web console. On a real engagement type the owner's
answers, `unknown`, or `pending`; never these.

**Proxy shape (practice proxy at `127.0.0.3`).** Answer the same questions with
these rows changed; every other row is as in the table above. This was run
end to end on the practice target: `scope answer` ended `Scope: COMPLETE and
CONSISTENT`, `rehearse` printed `Ready: yes`, and a call placed with the
resulting profile passed.

| Question | Type |
|---|---|
| 4 | `127.0.0.3` (the proxy: the only address SIP goes to) |
| 5 | `5060, 5061`, `udp, tls`; target `practice` `127.0.0.3` `udp` `5060`, `y`; target `tls` `127.0.0.3` `tls` `5061`, certificate name `sippycup-proxy`, CA `work/practice/ca.crt`, `n` |
| 8 to 10 | `yes`; `practice`, `sippycup-proxy` (the realm); `practice-password`, `other` |
| 12 to 16 | `127.0.0.2/31` (the media servers' range, as an owner gives a pool; the literal `127.0.0.2` also works); then `20000`, `20019`; `rtp, sdes-srtp`; `PCMU, PCMA`, `rfc4733`; `yes` |

After `scope compile`, `rehearse` prints `Signaling and media: 127.0.0.3 ...`
and `Media only: 127.0.0.2/31 (2 addresses) (owner-approved media networks;
never a signaling target)`. The call prints `Media scope: peer 127.0.0.2:20014
admitted by the approved media network 127.0.0.2/31 (media only)`. (The port
differs from call to call.) If the media answer is only the signaling address
(`127.0.0.3`; run this way), the call stops `Guided call: MEDIA-OUTSIDE-SCOPE`
with `Media scope: peer 127.0.0.2:20012 NOT approved`: the scope is missing the
media servers, which is not a fault of the proxy. Question numbers follow `scope questions`; `scope answer` prints the
one it is asking.

It ends with `Scope: COMPLETE and CONSISTENT` and
`Next: ./bin/sippycup scope compile work/acme`. A typing mistake is refused
with the reason and asked again; `quit` stops and keeps what you typed, and
`./bin/sippycup scope answer work/acme 11` changes one answer later.

Faster, the hand-edit route: copy the worked example over the pending
`scope.yaml` that `scope init` made, and set the window (the `date -u -d`
form below is GNU `date`, as on this Linux host):

```sh
./bin/sippycup practice-target up      # "container ... already exists" means it is already up: carry on
cp examples/scope/practice-scope.yaml work/acme/scope.yaml
chmod 600 work/acme/scope.yaml
date -u +%Y-%m-%dT%H:%M:%SZ                    # now: paste into valid_from
date -u -d '+4 hours' +%Y-%m-%dT%H:%M:%SZ      # paste into valid_until
```

Edit `valid_from` and `valid_until` in `work/acme/scope.yaml` (UTC, trailing
`Z`; the window must contain the current time). The file ships with a window
in the past on purpose: until you set it, `scope check` stops with
`scope.window_expired`. Nothing else needs to change. Its `credential_ref` is
`practice-password`. It has two targets, `practice` (UDP, profile
`target-profile.yaml`) and `tls` (TLS, profile `target-profile-tls.yaml`,
which the SRTP call and the matrix below use). The TLS target trusts the CA
that `practice-target up` writes to `work/practice/ca.crt`. That is a new file
after every `up`, and a frozen campaign plan pins the old one. `scope compile`
does not change that. After every `up`, freeze a new plan (section 5, "When
the plan is stale"); the same applies after any `down` and `up`.

**The `credential_ref` format:** lowercase letters, digits and `-`, starting
with a letter, at most 63 characters. `PRACTICE_PASSWORD`, `practice_password`
and `practice.password` are refused with `credential reference name has an
unsupported format`. It is only a name for the password (it is the name you
pass to `campaign run --secret-env`); the password itself never goes in
`scope.yaml`.

### When the owner wants the whole platform tested

The question sheet has two parts. Part 1 is the SIP service. Part 2 is the
product around it: the web site, the admin console, the API, real customers,
the hosting provider, carriers, and the limits on a live system (questions
P1 to P18 and A1 to A6, each with the reason it is asked). Take both parts to
the scoping conversation. If the test covers more than one SIP server, create
the scope file with the two extra sections:

```sh
./bin/sippycup scope init work/acme --platform
```

For a scope file that exists already, copy the `platform:` and `application:`
sections from `examples/scope/platform-scope.yaml`. `scope answer` then also
asks P1 to P18 and A1 to A6.

- Write each answer as the owner gave it. If the owner does not know, type
  `unknown`. If you are waiting for an answer, type `pending`. Never guess.
- A name is not an address. Ask for the literal IP address behind every
  public name, and whether it is shared with other customers or changes.
- The owner cannot give permission for another company. Record the hosting
  provider, the CDN or web firewall, the carrier, and the SMS and email
  providers as `out-of-path`, `permitted` (with where that is written), or
  `pending`.
- Ask which destinations stay on the platform and which reach the public
  phone network, and get the never-dial list.
- **Sippycup has no tool that sends web or API requests.** These answers are
  a record. `scope compile` writes them to `application-surfaces.yaml` for
  review. They do not start any test.

## 1. Scope (offline)

Record the owner's written answers, then check and compile:

```sh
./bin/sippycup scope answer work/acme
./bin/sippycup scope check work/acme
./bin/sippycup scope compile work/acme
./bin/sippycup rehearse work/acme/target-profile.yaml
```

`scope answer` shows each open question as the owner saw it, asks its answers
one field at a time, checks each with the `scope check` rules, and saves it at
once. Press Enter where the owner has not answered: the question stays open.
Run it again when more answers come in; `scope answer work/acme NUMBER`
changes one answer. It records `approved` only when you type that word, and
typing it asserts that you hold the owner's written approval. You can also
edit `work/acme/scope.yaml` by hand (mode 0600); both give the same file. See
`SCOPE-INTAKE.md`, "scope answer".

- If `scope check` or `scope compile` prints an `ERROR`, it names the field
  (for example `[destinations[0].expect]`) and, for a YAML mistake, the line
  and column. Fix that line and run `scope check` again. `scope compile`
  reports exactly what `scope check` reports; it never prints a traceback.
- When it is right, the output contains:
  - `Scope: COMPLETE and CONSISTENT`;
  - after compile, the derived `target-profile.yaml`, `campaign.yaml`, and
    `expectations.yaml`, and a `Next: ./bin/sippycup rehearse ...` line;
  - `Ready: yes` from `rehearse`.
- If compile prints `NOTHING CAN BE SENT with what this wrote`, the scope is
  not approved (or has an error): the profiles are written as `pending` and
  every sending command refuses them. Run the `Next:` line it prints
  (`scope answer work/acme 2`, then `scope compile` again). A `STALE:` line
  names an earlier `campaign.yaml` that compile did not write again; do not
  use it (`campaign plan` and `campaign run` refuse it).
- With platform sections: open answers there are `WARN` lines and do not
  block the SIP steps. `scope check` still prints
  `Scope: COMPLETE and CONSISTENT`, and compile also prints
  `Wrote application-surfaces: ... [record only; nothing is sent]`.
  The exception is an `ERROR` such as `scope.pstn_destination_unconfirmed`
  (a destination reaches the public phone network without the carrier's
  permission and a toll answer) or `scope.destination_never_dial`. Stop and
  ask the owner, or remove the destination. See `SCOPE-INTAKE.md`,
  "The severity rule".
- Proxy shape: rehearse also prints
  `Media only: 127.0.0.2/31 (2 addresses) (owner-approved media networks; never a signaling target)`
  and `Media ports: 20000-20019`.
- `rehearse` also prints the only destinations that `call` and `matrix`
  accept for `--dial` with that profile, for example
  `Destinations: echo, dtmf (the only values call and matrix accept for --dial with this profile)`.
  They are the `destinations[].user` values of that target in `scope.yaml`.
  To dial another destination, ask the owner, add it with
  `./bin/sippycup scope answer work/acme destinations` (type `add`) or in
  `scope.yaml` by hand, and run `scope compile` again. Never edit a profile.
- **More than one target (for example UDP and TLS):** compile writes one
  profile for each entry of `targets` in `scope.yaml`. Do not copy or edit a
  profile by hand.

  | Target in `scope.yaml` | Profile to pass |
  |---|---|
  | the first one | `work/acme/target-profile.yaml` |
  | each other one, by its `name` (for example `tls`) | `work/acme/target-profile-tls.yaml` |

  Compile prints the list (`NOTE: one target profile per target: ...`). Each
  profile has its own transport, port, TLS name and CA file, and its own
  destinations. Give each destination in `scope.yaml` a `target:` line. Run
  `rehearse` on each profile:

  ```sh
  ./bin/sippycup rehearse work/acme/target-profile-tls.yaml
  ```

  A `target-profile-NAME.yaml` that you made by hand earlier makes compile
  stop with `scope.derivative_unmanaged`. Run `scope compile --force` once to
  replace it with the generated one. See `SCOPE-INTAKE.md`.

## 2. The password

Use one of these two methods. The cockpit and the tools never take a typed
password in argv.

```sh
(umask 077; IFS= read -rs P; printf '%s' "$P" > work/acme/account.password; unset P)
ls -l work/acme/account.password      # expect -rw-------
```

Pass it to a command as `--secret-file work/acme/account.password`. For a
campaign, put it in an environment variable:

```sh
IFS= read -r ACME_PASSWORD < work/acme/account.password; export ACME_PASSWORD
```

and pass `--secret-env practice-password=ACME_PASSWORD`. The part before `=`
is the credential reference: the `credential_ref` from `scope.yaml`
(`practice-password` in the practice example; lowercase, see section 1), and
`campaign plan` prints it. The part after `=` is the name of the environment
variable.

**On the practice target you do not type a password.** `practice-target up`
makes a random one and writes it to `work/practice/account.password`; it is
never printed. Copy it into your engagement directory instead of typing:

```sh
(umask 077; cp work/practice/account.password work/acme/account.password)
ls -l work/acme/account.password      # expect -rw-------
```

`ready work/acme` with no password option uses `work/acme/account.password`
when that file exists. `call` and `ready` read the file; neither prints it.

**After `practice-target down` and `up` the copy is stale.** `up` makes a new
password every time and `down` deletes the old one. Copy it again (the same
`cp`) before the next `call`. A stale copy gives
`Guided call: REGISTRATION-FAILED` (401). Copy the password again and place
the call once more. This applies to the practice target only: on a real
owner's account `REGISTRATION-FAILED` means stop (see "Stop conditions").

## 3. First traffic: preflight, then one call (LIVE)

Run the go/no-go check first. It sends nothing to the target. It checks the
journal, the scope, the profile, the approval window, the clock, the image,
capture, the password file, and the route, and it prints your source address
(the address the owner must allow).

```sh
./bin/sippycup ready work/acme --secret-file work/acme/account.password
```

When the scope has platform answers, `ready` adds the line
`Production safety answers`. It is `[WARN]` while an answer is open on a
production system, and lists the open questions. Read it and decide with the
owner; it does not turn a GO into a NO-GO.

Continue only on `VERDICT: GO`. On `NO-GO`, each blocking line has a `fix:`
line; do it and run `ready` again. A `[WARN] Credentials` line means no
password source was given, so none was checked (the summary block says so too);
give `--secret-file` or put the file at `work/acme/account.password` and run
`ready` again. Run the `Journal:` line it prints. The
cockpit refuses LIVE actions until a GO exists for the current profile. See
[COCKPIT.md](COCKPIT.md).

When the approval window has ended or has not opened yet, `ready`, `rehearse`
and `call` say so first (`EXPIRED`, `not open yet`). Ask the owner for a new
written window (see "Stop conditions"), record it with
`./bin/sippycup scope answer work/acme authorization.window` (or in
`scope.yaml` by hand), and run `scope compile`.

The "last 4 characters of the approval id" prompt appears only in the cockpit
(`./bin/sippycup go`), before it starts a LIVE action. `call`, `matrix run`
and `campaign run` typed in a shell do not ask: the gates are the profile,
its window, and `--dial` (see "Approved destinations").

With more than one target, `ready` has one `Profile target-profile-NAME`
line for each other profile (present, current against `scope.yaml`, passes
`rehearse`, TLS trust, route), and a missing, stale, or blocked one is
`NO-GO`. The cockpit shows one `Profile` line for each compiled profile. Its
numbered actions use `target-profile.yaml`; for each other profile it offers
that profile's `rehearse` and dry run. To place a call with another profile,
run the dry run command that the cockpit prints, without `--dry-run` and with
the password source, from a shell.

```sh
./bin/sippycup --practice preflight --profile work/acme/target-profile.yaml
./bin/sippycup --practice call work/acme/target-profile.yaml --dial echo --username practice --dry-run
./bin/sippycup --practice call work/acme/target-profile.yaml --dial echo --username practice \
  --secret-file work/acme/account.password
```

Give `preflight` the profile, not a host. With `--profile` the address, port
and transport (and the TLS name and CA) come from the approved profile, and the
approval and its window are checked before any packet. The output then has the
line `Scope: profile NAME (approval ID, window FROM to UNTIL)`. A `preflight
HOST PORT TRANSPORT` without a profile still runs, but it prints
`Scope: UNBOUND (operator-supplied target HOST)`: nothing checked that host
against the approval. On the day of a real engagement, set
`export SIPPYCUP_REQUIRE_PROFILE=1` in your shell; `preflight` and `media send`
then refuse to run without `--profile`. `./bin/sippycup shell` and
`./bin/sippycup -- COMMAND` are never checked against an approval and say so
(`Scope: UNBOUND ...` on stderr). See "Scope binding" in [CLI.md](CLI.md).

On the practice target `ready` can also print a `[WARN] Profile target-profile-tls`
line: the practice CA lives two days, so it says the CA expires in under 7
days. Expected there; on a real engagement read it as a real warning.

When it is right:

```text
Guided call: PASS (completed)
  Preflight:    ok: SIP/2.0 200 OK
Record it: ./bin/sippycup journal add work/acme --kind action --summary '...' --evidence calls/RUN/result.json ...
```

Run the `Record it:` line exactly as printed. A call takes about 15 s and
prints nothing until it ends. `call --dry-run` lists what `call` does by
itself (capture, one OPTIONS preflight, one call, offline report); it is not a
procedure for you to follow by hand.

When a run does not pass, it prints a `Diagnose:` line. Run it. In the
example, `RUN` is a placeholder for the run directory name that the call
printed (a name like `20261119T203804Z-practice-ab12cd34`):

```sh
./bin/sippycup diagnose work/acme/calls/RUN
```

The page says where the run stopped, the decisive evidence, whose side the
cause is probably on and how sure that is, and the next command. When the
page starts its next steps with `STOP`, do not retry: ask the owner. See
[DIAGNOSE.md](DIAGNOSE.md).

Variants that passed, one call each:

```sh
... call work/acme/target-profile.yaml --dial echo ... --codec PCMA
... call work/acme/target-profile.yaml --dial dtmf ... --dtmf '159#'
... call work/acme/target-profile-tls.yaml --dial echo ... --srtp mandatory
```

When they are right, the output contains these lines:

- `Codec: offered PCMA/8000 (only the requested); answered PCMA/8000; negotiated PCMA (pt 8)`
- `DTMF: requested 159# (rfc4733), status sent; on the wire sent '159#', received '159#'`
- `SRTP: mandatory requested; active (AES_CM_128_HMAC_SHA1_80, RTP/SAVP)`

## 4. Matrix (LIVE)

```sh
./bin/sippycup matrix plan work/acme/target-profile.yaml work/acme/target-profile-tls.yaml \
  --dial echo --codecs PCMU,PCMA --srtp off,mandatory --max-calls 8
./bin/sippycup --practice matrix run work/acme/target-profile.yaml work/acme/target-profile-tls.yaml \
  --dial echo --codecs PCMU,PCMA --srtp off,mandatory --max-calls 8 \
  --username practice --secret-file work/acme/account.password --duration 4
```

- When it is right: one `Matrix: cell i/n ...` line for each cell, then
  `Call matrix: COMPLETED - 8 of 8 call(s) placed, 8 passed`, the grid, and a
  `Record it:` line that links the matrix record and every cell's run in one
  journal entry. Run it.
- A `WARNING: ... sdes-key-exposed-on-cleartext-signaling` line for SRTP over
  UDP is expected. Report it to the owner.

## 5. Campaign (LIVE)

```sh
./bin/sippycup campaign plan work/acme/campaign.yaml --output work/acme/plan.json
./bin/sippycup --practice campaign run work/acme/plan.json --manifest work/acme/campaign.yaml \
  --run-root work/acme/runs --interface lo --secret-env practice-password=ACME_PASSWORD
```

- When it is right:
  - `plan` prints
    `Wrote frozen plan: work/acme/plan.json (4 step(s); review it before running)`
    and the next command. Read the plan before you run it.
  - `run` prints `Campaign: SUCCEEDED (4 of 4 step(s) completed; exit 0)`
    and a `Record it:` line.
- The plan is bound to the approval window from `scope.yaml`. `run` checks
  the window before every step and stops before a step that could end after
  it (`Campaign: AUTHORIZATION_LAPSED`, exit 1). After any change to the
  approval in `scope.yaml`, run `scope compile`, then freeze a new plan (below).
- **When the plan is stale.** A frozen plan is never overwritten:
  `campaign plan` refuses with `refusing to overwrite existing frozen plan`
  and writes nothing. The plan goes stale when the approval window is renewed
  (`scope compile`), when the campaign file is written again, or when a CA
  file changes (every `practice-target up`). `ready` says so (`NO-GO` or
  `WARN`), and `campaign run` refuses with `source manifest SHA-256 does not
  match frozen plan` or a similar line; nothing is sent in either case. All
  three print the same line under `fix:` or `run:`. It keeps the old plan
  under a dated name and freezes a new one from the current campaign file:

  ```sh
  mv -n work/acme/plan.json work/acme/plan-STAMP.json && \
    ./bin/sippycup campaign plan work/acme/campaign.yaml --output work/acme/plan.json
  ```

  (`STAMP`: a date and time such as `20261119T234928Z`; the printed line has
  it filled in, so run that line.) Do not delete the old plan, and do not
  overwrite it by any other means. Read the new plan before you run it. Run
  `scope compile` first only when `scope.yaml` changed; `campaign plan` refuses
  a campaign file that `scope.yaml` no longer backs and says so.
- Use `--interface lo` only with `--practice`. Against the owner's target,
  leave out `--interface` (the default is `any`). `campaign run` always runs
  in the image's private network namespace (like `call`), where packet
  capture works without root; you need no `--isolated`. If capture cannot
  start, it says so, nothing is sent, and no run directory is kept. With
  `No such interface` in that message, the `--interface` name does not exist
  where the command runs (`lo` typed without `--practice`, or your host's
  `eth0`): leave out `--interface` and give the command again.

## 6. Security checks (LIVE, only if the owner approved them)

Record them with `./bin/sippycup scope answer work/acme 24`: the approved ids
(from `./bin/sippycup checks list`) and `max_requests`; it adds
`security-checks` to `test_scope.allowed_classes` with them. By hand: add
`security_checks.approved`, `max_requests`, and `security-checks` in
`test_scope.allowed_classes`. Then run `scope compile` again.

```sh
./bin/sippycup checks plan work/acme/target-profile.yaml
./bin/sippycup --practice checks run work/acme/target-profile.yaml --secret-file work/acme/account.password
```

- When it is right: `Findings (most severe first):` followed by a
  `Record it:` line.
- The first line says how it ended, for example
  `Security checks: COMPLETED (exit 0, fail-on medium)`. Exit 0: completed,
  and no finding is `medium` or higher (`low` and `info` findings do not
  change it). Exit 1: completed with at least one finding of `medium` or
  higher (`--fail-on` moves that line); that is normal too. Findings are
  results for the owner, not tool errors. Exit 2: refused before any packet.

## 7. Look at the evidence (offline)

```sh
./bin/sippycup ladder work/acme/calls/RUN       # RUN: a run directory name under calls/
./bin/sippycup explain call.VERDICT             # VERDICT: a verdict from a run, for example call.registration-failed
./bin/sippycup go work/acme            # cockpit: every unrecorded run is an action
./bin/sippycup journal verify work/acme
```

- When it is right:
  - `journal verify` prints `Journal: valid (N entries, ...)` and no
    `Missing or unsafe evidence references` line.
  - The cockpit `go work/acme --plain` shows `[ok]` for stages 3 to 9.

## 8. After: report and packs for the owner (offline)

```sh
./bin/sippycup summary work/acme --journal --forbid-file work/acme/account.password
ID=$(podman image inspect --format '{{.Id}}' localhost/sippycup:latest)
./bin/sippycup pack create work/acme/runs/RUN work/acme/packs/campaign.tar --image-digest "sha256:$ID"
./bin/sippycup pack verify work/acme/packs/campaign.tar --format markdown
./bin/sippycup evidence lint work/acme/runs/RUN
./bin/sippycup pack export-ci work/acme/packs/campaign.tar work/acme/ci-campaign
```

- When it is right:
  - `summary` prints `Engagement report: DIRECTORY`, a
    `Send to the owner: DIRECTORY/engagement-report.html` line,
    `Integrity exceptions: 0`, and a journal entry. `--forbid-file` makes
    sure that the password is in no output.
  - The first report goes to `work/acme/report`. Every later `summary` goes to
    a new `work/acme/report-STAMP` and never replaces an earlier report, so
    `report/` then holds an OLDER report. When an older one exists, `summary`
    prints `EARLIER report(s), do not send: ...`. Send only the directory on
    the `Engagement report:` line of your last `summary`.
  - `pack verify` prints `- Verdict: **pass**`.
- `pack create` and `pack verify` print the privacy findings first, on
  standard error (`WARNING: N privacy finding(s) ...`), and they are the
  findings `evidence lint` reports for the same run. A real run nearly always
  has some: the capture holds the account's SIP Digest authorization, and call
  records hold user names. **A pack with findings is evidence you keep. Do not
  send it to anyone as it stands**, plain or not. `pack create` does not stop
  you (the pack stays on your disk); `export-ci` does, until you add
  `--allow-privacy-findings`.
- **Send to the owner:**
  - the `Send to the owner:` file that your last `summary` printed (the
    newest `report` or `report-STAMP` directory; `engagement-report.html`, or
    `.md`). It holds no password, Digest response, or full Call-ID;
  - the CI export of each run, which has the verification result and copies
    no capture, audio, or other artifact:
    `./bin/sippycup pack export-ci work/acme/packs/RUN.tar work/acme/ci-RUN --allow-privacy-findings`;
  - only if the owner needs the capture itself: a pack encrypted to the
    owner's age key (ask the owner for it). Add `--recipient AGE_PUBLIC_KEY`
    to `pack create`; the result is `RUN.tar.age`, readable only with the
    owner's private key. Send nothing else from `runs/` or `calls/`.

  Make one pack for each run that you hand over. Never send capture files
  outside an encrypted pack.

Clean up at the end:

```sh
./bin/sippycup doctor --cleanup     # dry run: lists only untagged old builds and stopped containers;
                                    # --apply never removes a tagged image or one that a container uses
./bin/sippycup practice-target down
```

## Practice only: rehearse the failures

Before the engagement, see each failure once. The drill places the guided call
against the practice target's fault destinations (no answer, silence, 503, 403,
busy, a wrong password, a closed port, and the others) and checks that the
verdict you would read on the day is the one Sippycup reports:

```sh
./bin/sippycup practice-target up      # "container ... already exists" means it is already up: carry on
./bin/sippycup practice-target drill --list     # what it will do and for how long; sends nothing
./bin/sippycup practice-target drill            # about 2 minutes
```

- When it is right: one block for each scenario with its verdict and the
  `explain` text, then a table whose `result` column says `PASS` for every
  scenario, and `Drill: PASS in 124.1 s; evidence work/practice/drills/...`
  (exit 0). `MISMATCH` and exit 1 mean a verdict was not what was expected;
  exit 2 means it could not start and nothing was sent.
- It reaches only the practice target and cannot be pointed anywhere else.
  Leave the practice target alone while it runs: a call, a campaign, or the
  cockpit placing a call at the same time spoils both verdicts. Wait for
  `Drill: PASS`.
- Read the page for a scenario you expect to meet, for example
  `./bin/sippycup explain call.call-forbidden`. `PRACTICE-TARGET.md`,
  "Rehearse failures", lists the scenarios.

## Stop conditions

Stop and send nothing more if one of these happens:

- `scope check` reports any `ERROR`, or `rehearse` prints `Ready: no`.
- A call prints `Guided call: BLOCKED`. Nothing was sent. For a destination
  that is not approved, the `BLOCK:` line names the approved ones.
- A `call limit:` refusal. The owner's `limits.calls` counts every call
  placed in the engagement, by `call`, `matrix run`, `checks run` and
  `campaign run` together (the count is in `work/acme/call-ledger.jsonl`).
  `rehearse`, `ready` and every plan print `Calls: N of M used, K left`; watch
  it. A call counts once its INVITE may have left, whatever happened next; an
  attempt that sent no INVITE (preflight unanswered, registration failed) is
  given back. Only the owner can raise the limit. With the owner's new
  number in writing: `./bin/sippycup scope answer work/acme limits.calls`,
  then `./bin/sippycup scope answer work/acme 2` (the change sets the
  approval back to pending), then `./bin/sippycup scope compile work/acme`.
  Do not delete or edit the
  ledger (the next command refuses, because the run directories still show
  the calls), and do not copy the engagement directory to send from the copy:
  when a directory beside this one counts calls under the same approval
  reference, `ready` is `NO-GO`, `rehearse` is `Ready: no` and every command
  that places a call refuses (`call limit: this call is refused in ...
  Nothing was sent.`). The text names the one directory to go on in (the one
  with the earlier first call; its count adds the other's calls); the other
  needs a new written approval from the owner. Security checks that place no
  call are not counted by the call limit and still run within their own
  request ceiling.
- A refusal that says a profile or manifest was edited, is stale, or was not
  recorded by `scope compile`. Put the change in `work/acme/scope.yaml` and
  run `./bin/sippycup scope compile work/acme` again; never edit a compiled
  file.
- The authorization window has ended or has not started yet.
- `registration-failed` or `call-auth-failed`. Do not try the password again
  without the owner: every attempt is a credentialed attempt on their account.
- `call-rate-limited` (429), or `call-unavailable` with 503.
- `media-outside-scope`. The far end named or used a media address that the
  owner did not approve. Ask the owner, then record the address in scope.
- `signaling-outside-scope`. The far end routed our next SIP request to an
  address that the owner did not approve, and the softphone was killed
  without a BYE. Tell the owner that one call is left to time out on their
  side, and ask which signaling addresses their platform uses.
- `capture-failed`, `capture-died`, or `internal-error`.
- The owner contact asks you to stop.

To stop everything this checkout is sending, from any terminal:

```sh
./bin/sippycup stop
```

It ends each run with its normal shutdown (BYE, unregister), kills what is
left after 30 s, then checks that nothing is still sending and prints
`Silence: PROVED`, then a `Record it:` line. With one engagement under `work/`
it is ready to run. With none or several it ends in the placeholder
`work/NAME`: replace `NAME` with your engagement directory (for example
`work/acme`) and run the line, or give `--engagement work/acme` to `stop`
next time. `./bin/sippycup stop
--dry-run` lists what it would stop and signals nothing. Do not run `stop`
while you want another run from this checkout to continue.

## Testing from behind NAT

On the engagement you are almost always behind NAT: your machine's private
address is translated to a public address that the owner allowlists. The
routed rehearsal shows the same effects on this host. What you will see:

- The SDP and the first Via carry your private address (the container uses
  your machine's own address). The target cannot reach that address; media
  returns only because the target sends RTP back to where it came from
  (symmetric RTP, `rtp_symmetric` / `comedia`). If the owner's side does not,
  calls are answered with no audio from them: `diagnose` names this
  `possible-nat-one-way-media`.
- The softphone reads the `received`/`rport` the registrar writes in its Via
  and moves its Contact there: `call` prints a `NAT:` note with the address
  the target saw, and records it as `natAddresses` in `result.json`. That is
  the address the owner must allowlist; if it is not the one you gave them,
  stop and tell them. (`make routed-rehearsal` prints the same `NAT:` fact in
  its call stage and repeats these points in its last lines.)
- `evidence lint` accepts that address where it appears as text (a Via
  `received=`), never as a packet's address.
- RTCP is sparse in the received direction; judge media by RTP.
- A request from the target to you (a re-INVITE, an inbound call) reaches you
  only while your NAT keeps the flow open; a long silence can close it.
- `ready` shows the route your host takes to the target; the commands send
  from their private namespace, whose source address is the same host
  address.

## Overlapping runs

A sending command (`call`, `matrix run`, `checks run`, `campaign run`,
`preflight`, `media send`) refuses to start while another sender of this
checkout is active: two runs against one target spoil each other's verdicts.
It names the other run and sends nothing. Wait for it, or end it with
`./bin/sippycup stop`. That is the way on. `SIPPYCUP_ALLOW_OVERLAP=<the name
it printed>` exists only for running two senders at once on purpose: both
verdicts are then reported as "another run was active; this verdict is
unreliable", and two calls at once can be more than the owner's
`concurrent_calls` allows, which the owner report raises as the integrity
exception `concurrent-calls-exceeded`. Do not use it on an engagement unless
the owner agreed to it.

## Troubleshooting

Each row is an error or verdict seen in this walk-through:

| You see | Cause | Do |
|---|---|---|
| `Guided call: REGISTRATION-FAILED` (401) | wrong password. On the practice target: the copy in your engagement directory is from before the last `practice-target up` | Stop. Check the password file with the owner. Do not retry. Practice only: copy `work/practice/account.password` again (section 2). |
| `Guided call: BLOCKED` / `BLOCK: destination 'ecoh' is not one of the destinations the owner approved for this target (approved: echo, dtmf)` (exit 2) | typo in `--dial` (`ecoh`), or a destination that is not in the scope | Nothing was sent. Use a destination from the `approved:` list. For a new one, ask the owner, add it with `scope answer work/acme destinations` (or in `scope.yaml`), and run `scope compile`. |
| `Guided call: CALL-NOT-FOUND` (404) | the destination is in the scope, but the platform has no such user; or the profile has no destination list (`rehearse` prints `Destinations: NOT RESTRICTED`) and `--dial` has a typo | Run the `Diagnose:` line: it says whether the destination was on the approved list. Ask the owner for the exact destination. Do not guess. |
| `Guided call: PREFLIGHT-FAILED` ... `Hostname mismatch ... [TLS UNVERIFIED]` | wrong `tls_server_name` | Use the certificate name that the owner gave. |
| `PREFLIGHT-FAILED` ... `unable to get local issuer certificate` | wrong or stale `tls_ca_file` | Get the owner's CA again. |
| `PREFLIGHT-FAILED` `no_response: timeout`, target on 127.x | `--practice` is missing | Add `--practice` (the call prints this hint). The failed run stays in the report: record it as a mistake in the journal. |
| `Guided call: MEDIA-OUTSIDE-SCOPE` (exit 1) | media address (or network) not in the scope | Stop. Ask the owner to approve the media address. |
| `Guided call: MEDIA-OUTSIDE-SCOPE` (exit 1) with the peer at the signaling address | the owner's media answer (question 12) does not list the signaling address, so media is admitted only where the answer says | Stop. Ask the owner whether the signaling address also carries media; if yes, add it to `media.networks` and run `scope compile`. |
| `call: another sending command of this checkout is active` (exit 2) | another call, matrix, campaign or checks run of this checkout is still running | Nothing was sent. Wait for it, or `./bin/sippycup stop`. |
| `campaign: error: packet capture could not start (...)` | `campaign run` was started outside the launcher's container (for example `bin/campaign` on the host) | Nothing was sent and no run directory was kept. Use `./bin/sippycup campaign run ...`. |
| `Guided call: BLOCKED` / `BLOCK: authorization has expired (valid_until ...)` | window ended | Ask the owner for a new written window. Record it (`scope answer work/acme authorization.window`), record the approval again (`scope answer work/acme 2`), and run `scope compile`. |
| `Guided call: BLOCKED` / `BLOCK: authorization is pending, not approved; ...`, or `Ready: no` with the same text | an answer that decides what may be sent was changed (or the approval was never recorded), and `scope compile` wrote the profile as pending | Nothing was sent. With the owner's written approval of the scope as it is now: `./bin/sippycup scope answer work/acme 2`, then `./bin/sippycup scope compile work/acme`. The line itself ends with these two commands. |
| `campaign: error: packet capture could not start (No such device exists). ... No such interface` | the `--interface` name does not exist where the command runs (`lo` without `--practice`, or a host interface name) | Nothing was sent and no run directory was kept. Leave out `--interface`. |
| `campaign: error: refusing to plan: the approval window has ended` / `refusing to plan: the approval in the scope file beside the manifest ... differs` / `refusing to run: ...` (exit 2) | window ended, not open yet, too short for the first step, or the approval in `scope.yaml` was revoked or changed since `campaign.yaml` was written (`scope compile` leaves the old `campaign.yaml` when the scope has an error) | Nothing was sent. Ask the owner for a new written window, record it, record the approval again (`scope answer work/acme 2`), run `scope compile`, then `campaign plan` again. |
| `Campaign: AUTHORIZATION_LAPSED` (exit 1) and `Safety stop on our side` | the window ended (or the approval was revoked) between two steps | The completed steps are valid. Ask the owner for a new window before you send the rest. |
| `campaign: WARNING: this campaign plan is not bound to an approval window` | the manifest has no `authorization.approval` (hand-written or old) | Generate the manifest with `scope compile` and plan again. |
| `ERROR scope.window_not_started` / `scope.window_expired` | window is in the future or in the past | Same: wait, or ask for a new window. |
| `ERROR scope.malformed [targets[0].address]: ... (no hostnames)` | hostname instead of an address | Ask for the literal IP. Ignore the follow-on errors until this one is fixed. |
| `WARN scope.network_too_broad` / `scope.media_not_enumerable` | media network such as a /8 | Confirm the range with the owner. Prefer the smallest range. |
| `--username needs the account password` (exit 2) | `--secret-file` or `--secret-env` is missing | Add one of them. Nothing was sent. |
| `The practice target ws-... is not up.` (exit 2) | `--practice` used while the target is down | `./bin/sippycup practice-target up` |
| `Guided call: CANCELLED`, exit 130 | Ctrl-C | The call was hung up and its run is kept. A matrix shows the cancelled grid. |
| `privacy findings block default CI export` | `evidence lint` findings | Review them, then use `--allow-privacy-findings`. |
| `Missing or unsafe evidence references` from `journal verify` | a journal entry names a file that is not there | Check the entry. Runs cancelled before capture have no `capture.pcap`. |
