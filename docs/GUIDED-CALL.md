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
   Over TLS, PJSUA always verifies the server certificate
   (`--tls-verify-server`) against `target.tls_ca_file`, or the system bundle
   `/etc/ssl/certs/ca-certificates.crt` when the profile names none. With
   `target.tls_server_name`, the destination, registrar, identity, and
   outbound proxy use that name, so PJSUA sends it as SNI and checks it
   against the certificate; PJSUA runs in a private user and mount namespace
   in which `/etc/hosts` holds exactly `LITERAL NAME` and
   `/etc/nsswitch.conf` holds `hosts: files`, so the name maps only to the
   literal address and no DNS query can be made. The driver proves that
   mapping with `getent` inside the namespace before PJSUA starts and
   refuses (`tls_name_pinning_unavailable` or `tls_name_pinning_mismatch`)
   otherwise. Without a name, PJSUA verifies the literal address against the
   certificate's IP SAN. The preflight loads the same CA bytes, which are
   read once; PJSUA gets a private copy of them (`trust-anchor.pem`).
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
| `--codec NAME[,NAME]` | Offer only these codecs (plus telephone-event), first preferred; repeatable or comma-separated, case-insensitive. Names: `PCMU`, `PCMA`, `G722`, `GSM`, `iLBC`, `opus`, `speex/8000`, `speex/16000`, `speex/32000`. Default: the profile's `media.codecs`, else PCMU preferred among all PJSUA codecs. See "Codec control". |
| `--username USER` | Account for registration and digest challenges. |
| `--realm REALM` | Digest realm. Default `*`. |
| `--no-register` | Answer INVITE challenges without sending REGISTER. |
| `--secret-env NAME` | Read the password from environment variable NAME (preferred). |
| `--secret-file PATH` | Read the password from a mode-0600 file beneath `work/`. |
| `--run-root DIR` | Directory beneath `work/` for the run directory. Default: `calls/` next to the profile. |
| `--engagement DIR` | Journal directory used in the suggested journal command. Default: the profile's directory. |
| `--no-media-required` | Do not require RTP in both directions. |
| `--dtmf DIGITS` | Send these RFC 4733 (telephone-event) digits after answer: 1-32 of `0-9 A-D * #`, with `,` for a 1 s pause. Never SIP INFO or in-band. |
| `--dtmf-after SECONDS` | Delay from answer to the first digit, 0-60. Default 1. |
| `--srtp off\|optional\|mandatory` | SDES-SRTP. Default: `optional` for a TLS profile whose `features.srtp` is true, else `off`. |
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

Registration and INVITE are always sent to the approved target, and
redirects (3xx) are refused. PJSUA is given a global outbound route to the
target, but PJSIP still sends in-dialog requests (ACK, BYE) along a route set
or Contact that the far end names. So the driver reads PJSUA's message log
while the call runs (bn-2jg, `docs/SAFETY-AUDIT.md`):

- If PJSUA sends SIP to any address other than `target.host` (or the reviewed
  TLS name), the driver kills PJSUA at once, without a BYE along that route,
  and the verdict is `signaling-outside-scope`. The one message PJSIP already
  sent (normally the ACK) is the only one.
- If the far end's SDP (the answer, or a later re-INVITE or UPDATE) names a
  media destination outside the scope, the call is hung up and the verdict is
  `media-outside-scope`. A media-level `c=` overrides the session-level one,
  `a=rtcp` with an address counts, and the RTP port must be in
  `media.port_range`. The address PJSUA receives RTP from is checked too. Only
  the first few RTP/RTCP packets reach the unapproved address before the
  hang-up.

Behind a proxy or SBC the media address usually differs from the signaling
address; approve both (see the practice proxy in `docs/PRACTICE-TARGET.md`).

### Media networks and media ports

Owners usually approve media as a range: a media-server pool such as a `/27`.
The profile's optional `media` section carries it, for MEDIA ONLY:

```yaml
media:
  networks: [198.51.100.0/27]               # media-server pools (CIDR)
  port_range: {start: 10000, end: 20000}    # the far end's RTP ports
```

The media peer is approved when it is a literal `target.approved_addresses`
entry or lies inside a `media.networks` range, and, when `port_range` is
present, its port lies inside the range; anything else stops the call with
`media-outside-scope` exactly as before. `media.networks` never widens
signaling: the preflight, registration, and INVITE go only to `target.host`,
which must itself be a literal approved address, so a profile whose host lies
inside a media range is refused (exit 2, nothing sent). `rehearse` refuses a
range of more than 1024 addresses (see the breadth rule in
`SCOPE-INTAKE.md`) and prints the ranges on their own `Media only:` line for
review. With media networks the capture filter adds `net RANGE and udp`, the
oracle allowlist lists every address of the ranges, and `plan.json` records
them as `authorization.media_networks` (and `media_ports`), apart from the
literal `authorization.networks`.

`result.json` records the rules and which one admitted the peer:

```json
"mediaScope": {"rules": {"approvedAddresses": ["203.0.113.10"], "mediaNetworks": ["198.51.100.0/27"],
               "mediaPorts": [10000, 20000]},
               "peer": "198.51.100.12:10044", "admittedBy": "media-network",
               "network": "198.51.100.0/27", "portAdmitted": true, "inScope": true}
```

`admittedBy` is `approved-address`, `media-network`, or `null` (refused); the
human output prints it as `Media scope: peer ... admitted by the approved
media network ...`. The call matrix (each cell is a guided call) copies it
into each cell as `mediaAdmittedBy`/`mediaNetwork`, and `srtp-policy` rows
carry the same two fields.

## DTMF

`--dtmf 12#,34` sends `12#`, waits 1 s, then sends `34`, starting
`--dtmf-after` seconds after answer. The driver types PJSUA's legacy console
command `#` (send RFC 2833 DTMF) followed by each chunk, so PJSUA sends RFC
4733 events with the telephone-event payload type the peer answered with.
PJSUA always offers telephone-event. If the peer did not negotiate it, PJSUA
refuses (`Remote does not support RFC 2833`): nothing is sent, SIP INFO and
in-band tones are never tried, and the verdict is `dtmf-not-negotiated`. The
call must be long enough for the delay plus 0.25 s per digit, 1 s per pause,
and 1 s to settle; otherwise it is refused before anything starts.

After the call, tshark decodes RTP on the negotiated media port from the
capture with its `rtpevent` dissector disabled, and the event codes are read
from the raw payload: one event is one SSRC and RTP timestamp, so repeated
and end packets count once. `result.json` `dtmf` carries `requested`,
`requestedDigits`, `method: rfc4733`, `status` (`sent`, `notNegotiated`,
`notSent`, `incomplete`, `mismatch`), `negotiated`, `payloadTypes`, `sent`
(the outbound digits on the wire, `sentSource: capture`), `echoed` (the
inbound digits), `pjsuaSent`/`pjsuaReceived` (what PJSUA logged), `verified`,
and `wire`. The call passes only when the captured outbound digits equal the
requested digits; otherwise the verdict is `dtmf-mismatch`. The generated
oracle expectations set `require_dtmf: true`, and the oracle ignores RFC 4733
event packets (which keep one timestamp for the whole event) when it judges
RTP timestamp jumps and jitter. Under SRTP the event code is encrypted: the
capture then shows only the number of events, which must equal the number of
requested digits, and `verified` stays `null`.

## Codec control

The image's PJSUA 2.17 has these audio codecs (its `Cp` console listing):
`PCMU/8000`, `PCMA/8000`, `G722/16000`, `GSM/8000`, `iLBC/8000`,
`opus/48000/2`, and `speex` at 8000, 16000, and 32000 Hz (L16 is disabled).
`--codec` accepts exactly one name for each: `PCMU`, `PCMA`, `G722`, `GSM`,
`iLBC`, `opus`, `speex/8000`, `speex/16000`, `speex/32000` (any letter case).
Any other name, or a name given twice, is refused with exit 2 before
anything starts. `make codec-gate` checks the list against the live binary.

With `--codec`, the call offers only the named codecs, in that order, plus
telephone-event: PJSUA gets `--dis-codec=*` and then one `--add-codec` per
name. Without `--codec`, the default is unchanged: PCMU is preferred and
PJSUA still offers every other codec it has.

A profile can approve codecs with an optional section (`scope compile`
writes it from the scope's `media.codecs`):

```yaml
media:
  codecs: [PCMU, PCMA]
```

Then `--codec` must name only approved codecs (anything else is refused with
exit 2), and without `--codec` the call offers exactly the approved list.
`rehearse` refuses an unknown or duplicate name in the section.

`result.json` `codec` records `requested`, `exclusive`, `approved`,
`offered`, `answered`, `negotiated` (the answer's first codec) with its
`negotiatedPayloadType`, `offerOnlyRequested`, `unoffered`, and `wire`. The
wire proof comes from the capture: tshark lists the SDP of the INVITE offer
and the 2xx answer (`codec-sdp.txt`; under TLS the signaling is encrypted, so
the offer and answer come from PJSUA's log and `sdpSource` says
`pjsua-log`) and the RTP payload types on the negotiated media port in each
direction (`codec-rtp.txt`; RTP headers stay cleartext under SRTP).
`wire.verified` is true only when an exclusive offer listed nothing but the
requested codecs and every captured RTP packet used the negotiated payload
type, telephone-event, or comfort noise.

A far end that answers with a codec the offer did not contain gets the
verdict `codec-not-offered` (an answer must choose from the offer, RFC 3264
section 6). A far end that accepts none of the offered codecs normally
answers 488, which is `call-media-not-acceptable`; with `--codec` a note says
which codecs were offered.

## SRTP

`--srtp optional` offers RTP/AVP with `a=crypto` (PJSUA `--use-srtp=1`) and
accepts a plain answer; `--srtp mandatory` offers RTP/SAVP (`--use-srtp=2`),
and a call that does not negotiate SRTP fails with the distinct verdict
`srtp-not-negotiated` (PJSUA never falls back to plain RTP; a peer that
refuses SRTP typically answers 488). Keying is SDES (`--srtp-keying=0`).
SDES keys travel in the SDP, so they are confidential only over TLS: over
TLS PJSUA requires secure signaling for SRTP (`--srtp-secure=1`); over UDP or
TCP SRTP is still tested (`--srtp-secure=0`) and the result carries the
warning `sdes-key-exposed-on-cleartext-signaling`. `a=crypto` key values are
redacted from the persisted softphone log and console.

`result.json` `srtp` carries `mode`, `active`, `suite` (for example
`AES_CM_128_HMAC_SHA1_80`), `offerProfile`, `answerProfile` (`RTP/SAVP` or
`RTP/AVP`), `secureSignaling`, `warning`, and `media`. With SRTP active the
oracle cannot read RTP payloads, so its result is recorded but does not
decide the verdict; the RTP header is still cleartext, so RTP to and from
the negotiated media peer is counted from the capture (`srtp-media.txt`)
exactly as for TLS calls.

## Registration status and setup time

A failed registration reports the SIP status of the final REGISTER response
in PJSUA's message log, for example `Registration: FAILED (status 401)` for a
wrong password (PJSIP itself reports only `PJSIP_EFAILEDCREDENTIAL`), 403,
or the 408 PJSIP generates when nothing answers. `notes` repeats it.

`setup` (in `result.json` and under `softphone`) is measured from PJSUA's log
timestamps: `inviteToProvisionalSeconds` (first INVITE sent to the first 180
or 183), `inviteToAnswerSeconds` (to the 2xx), with the statuses. It starts
at the first INVITE, so a digest challenge round trip is included. Where the
oracle decides (UDP/TCP, plain RTP) its `max_setup_ms: 5000` applies; for
TLS or SRTP calls the same 5 s limit is applied to `inviteToAnswerSeconds`.

## Local RTP port

The capture filter admits all UDP to and from the approved addresses, so
media is captured in both directions whatever local port PJSUA picks.
`softphone.local_rtp_port` reports the port from PJSUA's SDP offer (PJSUA
starts at 4000 and takes the next free pair). The driver's
`allowed_media_ports` range applies to the remote (target) media port only.

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
| `tls-media.txt` | TLS calls only: RTP to and from the negotiated media peer, decoded by tshark from the capture. |
| `srtp-media.txt` | SRTP active on UDP/TCP signaling: RTP headers to and from the negotiated media peer. |
| `dtmf-events.txt` | `--dtmf` only: RTP on the negotiated media port with raw payloads, from which RFC 4733 events are decoded. |
| `codec-sdp.txt`, `codec-rtp.txt` | The captured SDP offer and answer (UDP/TCP signaling) and the RTP payload type of every packet on the negotiated media port. |
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
| `one-way-media` | The same observation without NAT in the path (loopback or host network). A far end that sends no RTP at all lands here: PJSUA never learns its media address, the softphone driver hangs the call up early, and `call` confirms from the far end's own SDP that the address was approved before it reports this instead of `media-outside-scope`. | 1 |
| `slow-setup` | Answered, and the only failed assertion is the oracle's 5 s setup window. `setup.seconds` says how long ringing took. | 1 |
| `peer-hung-up-early` | Answered and healthy, but the far end sent BYE more than 1.5 s before the planned duration. | 1 |
| `silent-audio` | RTP flowed both ways but `heard.wav` is digital silence. Packet counts alone would have passed. Skipped with `--no-media-required`. | 1 |
| `call-not-answered` | No final response before `--answer-timeout`; the caller cancelled. The notes say whether 180 or 183 was received. | 1 |
| `call-busy` (486, 600), `call-declined` (603), `call-forbidden` (403), `call-not-found` (404, 410, 604), `call-unavailable` (480, 503), `call-rate-limited` (429), `call-media-not-acceptable` (488, 606), `call-auth-failed` (401, 407), `call-redirected` (3xx) | The far end refused the call with that final status; the status is in the notes. | 1 |
| `call-rejected-4xx`, `call-rejected-5xx`, `call-rejected-6xx` | Any other final rejection; the status class is in the code. | 1 |
| `preflight-failed`, `registration-failed`, `call-error`, `media-outside-scope`, `signaling-outside-scope` | The run stopped at that step. | 1 |
| `capture-failed`, `capture-died`, `authorization-lapsed`, `internal-error` | The run stopped for safety; see `notes` in the result. | 1 |
| `cancelled` | Ctrl-C, SIGTERM, or SIGHUP (the terminal closed). | 130 / 143 |
| `blocked` | Refused before anything started; no run directory. | 2 |

| `tls-not-verified` | TLS verification failed or was not confirmed; PJSUA sent no SIP request on that connection. | 1 |
| `tls-name-pinning-failed` | The reviewed name could not be pinned to the literal address; PJSUA was not started. | 1 |
| `srtp-not-negotiated` | `--srtp mandatory`, and the call did not negotiate SDES-SRTP. | 1 |
| `dtmf-not-negotiated` | `--dtmf`, and the peer did not negotiate telephone-event; nothing was sent. | 1 |
| `dtmf-mismatch` | The digits PJSUA sent, or the digits seen on the wire, differ from the request. | 1 |
| `codec-not-offered` | The far end's SDP answer named a codec that the offer did not contain. | 1 |

Every verdict has `./bin/sippycup explain call.VERDICT`. `result.json` also
carries `setup` (seconds from INVITE to answer, the 18x statuses seen, and
whether a 183 offered early media; early-media RTP is included in the PJSUA
packet counts) and `oracle.failedDetails` (each failed assertion's id,
message, and scalar observed value).

### Rehearse failures

The practice target has destinations that fail on purpose, and
`./bin/sippycup practice-target drill` runs the guided call against each one
and prints what the server did, the verdict, the expected verdict, and the
`explain` text. Do this once before an engagement so the failure verdicts are
familiar (`docs/PRACTICE-TARGET.md`, "Rehearse failures"). The oracle is strict
by design: `earlymedia` reports `fail` because Asterisk re-bases the RTP
timestamp when it answers an early-media call.

### TLS calls

Over TLS the packet oracle cannot see SIP (the signaling is encrypted), so
its result is recorded but does not decide the verdict, and a `notes` entry
says so. A TLS call passes only when the preflight verified the certificate,
PJSUA logged `TLS cert verification result of NAME:PORT : OK` for the
expected name (and no failed result), registration (when requested) and the
call succeeded, and RTP in both directions was decoded from the capture on
the negotiated media port (`tls-media.txt`). Missing RTP counts give
`inconclusive`; RTP in one direction gives the same NAT-aware verdicts as
UDP. `result.json` carries `tls`: `verified`, `serverName` (the name, or the
literal address when the IP SAN is verified), `trust` (`system` or `file`),
`caFile`, `caSha256`, `preflightVerified`, `softphoneVerified`,
`softphoneDetail`, `connectsTo`, and `media`.

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

Ctrl-C, SIGTERM, or SIGHUP (closing the terminal) hangs up the call (BYE when established, CANCEL while
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

`dtmf="12#"` with `dtmf_after_seconds` sends RFC 4733 digits after answer,
`srtp="off"|"optional"|"mandatory"` selects SDES-SRTP, and the result adds
`dtmf`, `srtp`, `sdp` (offer and answer audio facts), `setup`,
`local_rtp_port`, and `warnings`. `exclusive_codecs=True` offers only
`codecs` (PJSUA `--dis-codec=*` before the `--add-codec` lines; telephone-event
is still offered); by default the listed codecs are only raised in priority
and PJSUA offers every other codec it has. Until the first RTP packet
arrives PJSUA prints the media peer as `-`; the driver treats that as
unknown (`media_peer` stays `null`), not as out of scope, so a far end that
sends no RTP runs its full duration. The private directory that holds the
password configuration is removed after PJSUA and every process in its
process group are reaped, the configuration file first, with brief retries.

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
