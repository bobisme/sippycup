# Guided baseline call

`./bin/sippycup call` executes the reviewed one-call plan in one terminal.
It replaces the manual sequence that `one-call` prints: a sudo host capture
in one terminal, a hand-written PJSUA configuration in another, Ctrl-C, then
report, triage, and assertions.

```sh
./bin/sippycup call work/ENGAGEMENT/profile.yaml --dial DESTINATION
```

The command never authorizes traffic. It refuses unless the target profile
already carries the service owner's approval.

## What it does

1. **Gate.** It rehearses the profile and refuses, sending nothing and
   starting nothing, unless the profile is approved, inside its validity
   window, and `target.host` is itself one of the literal
   `approved_addresses`. The validity window must also cover the latest
   possible end of the call. The same gate runs again immediately before
   the first packet and before the call.
2. **Capture.** In a private container network namespace, where rootless
   capture works without sudo, it starts `tcpdump` with a filter that names
   only the approved addresses: the signaling port plus UDP for RTP, for
   example `(host 192.0.2.10) and (udp port 5060 or udp)`. Nothing is sent
   until tcpdump reports that it is listening. If capture stops at any
   point, the run fails and the call hangs up.
3. **Preflight.** It sends exactly one SIP OPTIONS transaction with the
   in-tree client (over UDP at most two datagrams: the request and one
   retransmission after 0.5 s if nothing arrived). Any final response counts
   as reachable; `preflight.json` records the status line. No response, a
   refused or unreachable destination, or a TLS verification failure stops
   the run without placing a call.
4. **Call.** It places exactly one PJSUA call to
   `sip:DESTINATION@HOST:PORT` over the profile's transport. When you give
   an account, PJSUA registers first and dials only after registration
   succeeds. PJSUA plays a WAV file and records what it receives. It hangs up
   at `min(--duration, limits.max_duration_seconds)` seconds after answer.
5. **Offline analysis.** After capture stops it runs the standard report,
   triage, and the call-path oracle. Oracle expectations are generated from
   the profile: allowed endpoints are the approved addresses plus the local
   address, bidirectional media is required unless you pass
   `--no-media-required`, and no codec is assumed.
6. **Evidence.** It writes a new run directory and an evidence manifest, then
   prints a verdict, the run directory, the exact journal command, and a
   `Network activity:` line that states what was sent.

## Options

| Option | Meaning |
|---|---|
| `--dial DESTINATION` | User part dialed at the profile's target. Required. |
| `--duration SECONDS` | Call time after answer. Default 10. Clamped to `limits.max_duration_seconds`. |
| `--answer-timeout SECONDS` | Hang up (CANCEL) if the call is not answered in time. Default 30, maximum 120. |
| `--play FILE` | A 16-bit PCM WAV beneath `work/`, such as the agreed canary phrase. Default: a generated two-tone WAV with no recorded voice. |
| `--codec NAME` | Codec preference, repeatable, first is preferred. Default `PCMU`. |
| `--username USER` | Account for registration and digest challenges. |
| `--realm REALM` | Digest realm. Default `*`. |
| `--no-register` | Answer INVITE challenges without sending REGISTER. |
| `--secret-env NAME` | Read the password from environment variable NAME (preferred). |
| `--secret-file PATH` | Read the password from a mode-0600 file beneath `work/`. |
| `--run-root DIR` | Directory beneath `work/` for the run directory. Default: `calls/` next to the profile. |
| `--engagement DIR` | Journal directory used in the suggested journal command. Default: the profile's directory. |
| `--no-media-required` | Do not require RTP in both directions. |
| `--format json` | Print the result document instead of the human summary. |
| `--dry-run` | Print the plan and softphone parameters; send nothing. |

Keep the profile beneath `work/`: the call runs in the image, which sees only
the work directory. The launcher rewrites `work/...` arguments to `/work/...`.

## Credentials

Prefer an environment variable that your secret manager sets only for this
command:

```sh
SIP_PASSWORD="$(your-secret-tool read staging-sip)" \
  ./bin/sippycup call work/ENGAGEMENT/profile.yaml --dial 1001 \
  --username staging-user --secret-env SIP_PASSWORD
```

The launcher forwards only the named variable, with the runtime's name-only
`--env NAME` form, so the value is never in any command line. Inside the
image:

- the variable is removed from the environment before any child starts, and
  is absent from the environment of tcpdump, PJSUA, TShark, and the report;
- the password goes only into a mode-0600 PJSUA configuration file in a
  private mode-0700 directory on `/dev/shm` (memory; the system temporary
  directory only when `/dev/shm` is unavailable), which is deleted as
  soon as PJSUA has read it and again when the call ends;
- the password and every `Authorization` and `Proxy-Authorization` header
  value are redacted from the persisted softphone log and console.

`--secret-file` reads a regular, non-symlink file beneath `work/` whose mode
grants no group or other access. A password that contains whitespace, quotes,
or control characters is refused before anything starts, because PJSUA
configuration files are whitespace-delimited.

Registration and INVITE are always sent to the approved target. PJSUA is
given a global outbound route to the target, so in-dialog requests do not
follow a remote Contact elsewhere, and redirects (3xx) are refused. If the
negotiated media peer is not an approved address, the call is hung up and
the verdict is `media-outside-scope`.

## Run directory

Each run creates a new mode-0700 directory such as
`work/ENGAGEMENT/calls/20261117T120000.000000Z-voice-staging-1a2b3c4d`. It is
never reused. Files are mode 0600:

| File | Content |
|---|---|
| `profile.json` | Copy of the profile used (no credentials). |
| `plan.json` | Parameters, scope networks, capture filter, play file hash. |
| `commands.json` | Capture, softphone, and analysis commands; the password appears only as `<redacted>`. |
| `versions.json` | Tool paths, hashes, and versions. |
| `timestamps.json` | UTC start, capture ready, preflight, call start/end, capture stop, finish. |
| `capture.pcap`, `capture.log` | The scoped capture and tcpdump output. |
| `preflight.json` | The single OPTIONS result. |
| `softphone.json` | Structured driver result: registration, final status, state timeline, RTP counters. |
| `softphone.log`, `softphone-console.txt` | Redacted PJSUA log and console. |
| `played.wav` | The generated tone (absent when `--play` is used; its hash is in `plan.json`). |
| `heard.wav` | Audio received from the far end. |
| `expectations.yaml` | Generated oracle expectations. |
| `report.txt`, `triage.json`, `assert.json` | Offline report, triage, and oracle result (with `.stderr` files). |
| `result.json` | Stable result, `schemas/call-result-v1.schema.json`. |
| `evidence-manifest.json` | Hashes, sensitivity labels, and privacy findings. |

`capture.pcap`, `heard.wav`, and the logs may contain voice, numbers, and
identities. Treat the directory like any capture. The evidence manifest
normally reports privacy `blocked` because of decoded audio and SIP
identifiers; use the evidence privacy workflow before sharing anything.

## Verdicts and exit status

| Verdict | Meaning | Exit |
|---|---|---|
| `pass` | Call answered, oracle passed. | 0 |
| `fail`, `inconclusive` | Call answered; oracle failed or could not decide. | 1 |
| `possible-nat-one-way-media` | Signaling succeeded and RTP was sent, but no inbound RTP was observed in isolated mode. This is consistent with NAT and is not, by itself, a target defect. | 1 |
| `one-way-media` | The same observation without NAT in the path. | 1 |
| `preflight-failed`, `registration-failed`, `call-not-answered`, `call-error`, `media-outside-scope` | The run stopped at that step. | 1 |
| `capture-failed`, `capture-died`, `authorization-lapsed`, `internal-error` | The run stopped for safety; see `notes` in the result. | 1 |
| `cancelled` | Ctrl-C or SIGTERM. | 130 / 143 |
| `blocked` | Refused before anything started; no run directory. | 2 |

RTP counts come from PJSUA's own call statistics and are labelled as such.
Codec, media peer, and recording level are reported only when observed;
otherwise they are `null`. An oracle `unknown` stays unknown.

## Isolated mode and NAT

The call runs in the container runtime's private network namespace. Traffic
to a non-loopback target leaves through the runtime's NAT (for example pasta
or slirp4netns). The output says so. PJSUA advertises the container's source
address toward the target in Contact and SDP. If the target cannot return
media through that NAT, signaling succeeds but no RTP arrives; Sippycup then
reports `possible-nat-one-way-media` instead of blaming the target.

## Emergency stop

Ctrl-C or SIGTERM hangs up the call (BYE when established, CANCEL while
ringing), stops capture, keeps the evidence, writes a `cancelled` result and
evidence manifest, and exits 130 or 143. The offline report, triage, and
assertions are skipped after a cancel; run them later on the kept capture.
If the driver itself dies, PJSUA sees its standard input close and quits,
which also ends the call.

## Dry run

```sh
./bin/sippycup call work/ENGAGEMENT/profile.yaml --dial 1001 --dry-run
```

This runs from the checkout without a container. It prints the same steps
as `one-call`, the softphone parameters, and the capture filter, and it sends
no packets. Exit status is 0 when ready and 2 when blocked.

## Recording the run

The output ends with a journal command, for example:

```sh
./bin/sippycup journal add work/ENGAGEMENT --kind action \
  --summary 'Guided baseline call (voice-staging): pass' \
  --evidence calls/RUN_ID/result.json \
  --evidence calls/RUN_ID/evidence-manifest.json \
  --evidence calls/RUN_ID/capture.pcap
```

## Self-test

```sh
make call-selftest
```

The self-test runs in one isolated container. It starts a PJSUA
auto-answer, auto-loop echo peer on `127.0.0.2:5062`, runs the real call
implementation against a profile approved only for `127.0.0.2`, and checks
one OPTIONS, one INVITE dialog, RTP in both directions, an oracle PASS, a
non-silent recording, a complete mode-0700 run directory, and that a test
credential appears nowhere in the tree. Because the peer is inside the same
container, the self-test drives the in-image entrypoint directly instead of
the host launcher. The PJSUA peer accepts REGISTER without a challenge, so
the self-test exercises registration but not digest authentication.

## Reusing the softphone driver

`lib/sippycup_softphone` places one bounded call without depending on this
command. Build a `SoftphoneCall`, optionally with a `SoftphoneAccount`, and
call `place_call(call, password=..., cancel=..., abort=...)`. It returns a
`SoftphoneResult` with the registration result, final SIP status, call-state
timeline, connected time, PJSUA RTP counters, and any error.

`allowed_media_ports=(start, end)` additionally hangs up when the negotiated
remote RTP port is outside that range, and `place_call(...,
kill_with_parent=True)` makes Linux kill PJSUA if the calling process dies.
PJSUA registration runs with `--rereg-delay=0`, and the image's PJSIP is
built with `PJSIP_MAX_STALE_COUNT 1`, so a wrong password costs one
credentialed attempt for this command too.

Campaigns use the same driver: a campaign `call` case with `dial` or a
credential reference runs on `campaign-softphone-runner`, which places this
call for each reviewed plan step under the campaign supervisor, capture
watchdog, and evidence lifecycle. See "Dial destinations and accounts" and
"Softphone runner" in [`CAMPAIGN-MANIFEST.md`](CAMPAIGN-MANIFEST.md).
