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
same command without `--practice`. That route was not run when this page was
written (loopback only), so check its first output line carefully.

## 0. Before you start (offline)

```sh
make build
./bin/sippycup doctor
./bin/sippycup journal init work/acme --title "ACME voice test" --owner "ACME voice team"
./bin/sippycup scope init work/acme
./bin/sippycup scope questions work/acme > work/acme/questions-for-owner.md
```

- When it is right: `doctor` prints `Doctor: ready`. `scope init` prints
  `Created pending scope file: work/acme/scope.yaml` and
  `No addresses, approval, limits, or credentials were invented.`
- **Send to the owner:** `questions-for-owner.md`. Do not continue until you
  have their written answers: the literal addresses, the window, the limits,
  the destinations, the account, and, for the proxy shape, the media network
  and the media port range.

On the practice target, `./bin/sippycup practice-target info` prints the same
facts that an owner would give you. Fill `scope.yaml` by hand from them.

## 1. Scope (offline)

Write the owner's answers into `work/acme/scope.yaml`, then:

```sh
./bin/sippycup scope check work/acme
./bin/sippycup scope compile work/acme
./bin/sippycup rehearse work/acme/target-profile.yaml
```

- When it is right, the output contains:
  - `Scope: COMPLETE and CONSISTENT`;
  - after compile, the derived `target-profile.yaml`, `campaign.yaml`, and
    `expectations.yaml`;
  - `Ready: yes` from `rehearse`.
- Proxy shape: rehearse also prints
  `Media only: 127.0.0.2/31 (2 addresses) (owner-approved media networks; never a signaling target)`
  and `Media ports: 20000-20019`.
- **Second (TLS) target:** compile writes a profile only for the first target.
  For a TLS call or a UDP+TLS matrix, copy the profile:

  ```sh
  (umask 077; cp work/acme/target-profile.yaml work/acme/target-profile-tls.yaml)
  ```

  In the copy, change these fields:
  - `name` (for example `acme-tls`);
  - `target.port`;
  - `target.transport: tls`;
  - add `target.tls_server_name` and `target.tls_ca_file` (for example
    `work/acme/owner-ca.crt`).

  Then run `./bin/sippycup rehearse work/acme/target-profile-tls.yaml`.
  Copy it again after every `scope compile`. See `SCOPE-INTAKE.md`.

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

and pass `--secret-env REF=ACME_PASSWORD`. REF is the credential reference in
`campaign.yaml`, and `campaign plan` prints it.

## 3. First traffic: preflight, then one call (LIVE)

Run the go/no-go check first. It sends nothing to the target. It checks the
journal, the scope, the profile, the approval window, the clock, the image,
capture, the password file, and the route, and it prints your source address
(the address the owner must allow).

```sh
./bin/sippycup ready work/acme --secret-file work/acme/account.password
```

Continue only on `VERDICT: GO`. On `NO-GO`, each blocking line has a `fix:`
line; do it and run `ready` again. Run the `Journal:` line it prints. The
cockpit refuses LIVE actions until a GO exists for the current profile. See
[COCKPIT.md](COCKPIT.md).

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

When it is right:

```text
Guided call: PASS (completed)
  Preflight:    ok: SIP/2.0 200 OK
Record it: ./bin/sippycup journal add work/acme --kind action --summary '...' --evidence calls/RUN/result.json ...
```

Run the `Record it:` line exactly as printed. A call takes about 15 s and
prints nothing until it ends.

When a run does not pass, it prints a `Diagnose:` line. Run it:

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
  `Call matrix: COMPLETED - 8 of 8 call(s) placed, 8 passed` and the grid.
- A `WARNING: ... sdes-key-exposed-on-cleartext-signaling` line for SRTP over
  UDP is expected. Report it to the owner.

## 5. Campaign (LIVE)

```sh
./bin/sippycup campaign plan work/acme/campaign.yaml --output work/acme/plan.json
./bin/sippycup --practice campaign run work/acme/plan.json --manifest work/acme/campaign.yaml \
  --run-root work/acme/runs --interface lo --secret-env REF=ACME_PASSWORD
```

- When it is right:
  - `plan` prints
    `Wrote frozen plan: work/acme/plan.json (3 step(s); review it before running)`
    and the next command. Read the plan before you run it.
  - `run` prints `Campaign: SUCCEEDED (3 of 3 step(s) completed; exit 0)`
    and a `Record it:` line.
- Use `--interface lo` only with `--practice`. Against the owner's target,
  leave out `--interface` (the default is `any`).

## 6. Security checks (LIVE, only if the owner approved them)

Add this to the scope: `security_checks.approved` (ids from
`./bin/sippycup checks list`), `max_requests`, and `security-checks` in
`test_scope.allowed_classes`. Then run `scope compile` again.

```sh
./bin/sippycup checks plan work/acme/target-profile.yaml
./bin/sippycup --practice checks run work/acme/target-profile.yaml --secret-file work/acme/account.password
```

- When it is right: `Findings (most severe first):` followed by a
  `Record it:` line.
- Exit 1 with findings is normal. Findings are results for the owner, not
  tool errors.

## 7. Look at the evidence (offline)

```sh
./bin/sippycup ladder work/acme/calls/RUN
./bin/sippycup explain call.VERDICT
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
  - `summary` prints `Engagement report: work/acme/report`,
    `Integrity exceptions: 0`, and a journal entry. `--forbid-file` makes
    sure that the password is in no output.
  - `pack verify` prints `- Verdict: **pass**`.
- `export-ci` refuses while privacy findings are open. Read them with
  `evidence lint` (it prints JSON). If you accept them, add
  `--allow-privacy-findings`.
- **Send to the owner:**
  - `work/acme/report/engagement-report.html` (or `.md`);
  - the `.tar` packs.

  Make one pack for each run that you hand over. Do not send capture files
  outside a pack.

Clean up at the end:

```sh
./bin/sippycup doctor --cleanup     # dry run; add --apply only for images you own
./bin/sippycup practice-target down
```

## Stop conditions

Stop and send nothing more if one of these happens:

- `scope check` reports any `ERROR`, or `rehearse` prints `Ready: no`.
- A call prints `Guided call: BLOCKED`. Nothing was sent.
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
`Silence: PROVED`. It prints a journal line; run it. `./bin/sippycup stop
--dry-run` lists what it would stop and signals nothing. Do not run `stop`
while you want another run from this checkout to continue.

## Troubleshooting

Each row is an error or verdict seen in this walk-through:

| You see | Cause | Do |
|---|---|---|
| `Guided call: REGISTRATION-FAILED` (401) | wrong password | Stop. Check the password file with the owner. Do not retry. |
| `Guided call: CALL-NOT-FOUND` (404) | typo in `--dial` (`ecoh`) | Use the destination exactly as written in the scope. |
| `Guided call: PREFLIGHT-FAILED` ... `Hostname mismatch ... [TLS UNVERIFIED]` | wrong `tls_server_name` | Use the certificate name that the owner gave. |
| `PREFLIGHT-FAILED` ... `unable to get local issuer certificate` | wrong or stale `tls_ca_file` | Get the owner's CA again. |
| `PREFLIGHT-FAILED` `no_response: timeout`, target on 127.x | `--practice` is missing | Add `--practice` (the call prints this hint). |
| `Guided call: MEDIA-OUTSIDE-SCOPE` (exit 1) | media address (or network) not in the scope | Stop. Ask the owner to approve the media address. |
| `Guided call: BLOCKED` / `BLOCK: authorization has expired (valid_until ...)` | window ended | Ask the owner for a new written window, record it, and run `scope compile`. |
| `ERROR scope.window_not_started` / `scope.window_expired` | window is in the future or in the past | Same: wait, or ask for a new window. |
| `ERROR scope.malformed [targets[0].address]: ... (no hostnames)` | hostname instead of an address | Ask for the literal IP. Ignore the follow-on errors until this one is fixed. |
| `WARN scope.network_too_broad` / `scope.media_not_enumerable` | media network such as a /8 | Confirm the range with the owner. Prefer the smallest range. |
| `--username needs the account password` (exit 2) | `--secret-file` or `--secret-env` is missing | Add one of them. Nothing was sent. |
| `The practice target ws-... is not up.` (exit 2) | `--practice` used while the target is down | `./bin/sippycup practice-target up` |
| `Guided call: CANCELLED`, exit 130 | Ctrl-C | The call was hung up and its run is kept. A matrix shows the cancelled grid. |
| `privacy findings block default CI export` | `evidence lint` findings | Review them, then use `--allow-privacy-findings`. |
| `Missing or unsafe evidence references` from `journal verify` | a journal entry names a file that is not there | Check the entry. Runs cancelled before capture have no `capture.pcap`. |
