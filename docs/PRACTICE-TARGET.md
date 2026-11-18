# Local practice target

The practice target is an optional, disposable, standards-compliant SIP
server for rehearsing the complete operator sequence before a real
engagement. It exists because the bundled `campaign-loopback-uas` fixture is
a tiny Python responder, not a SIP stack: several live-path bugs (a missing
`rport` in the campaign preflight Via, an unresolvable host-network hostname,
and a closed container stdin) passed every fixture-based gate and failed
only against a real server.

It is kept outside the core image, like the WebRTC peer. Nothing in it can
authorize traffic to a real host.

## What it is

- **Server:** Asterisk 22.12.0 (the current 22 LTS release) with `chan_pjsip`
  and its bundled pjproject 2.17. Debian 13 does not package Asterisk, so
  `Containerfile.practice` builds the pinned upstream release from source and
  checks the SHA-256 of both the Asterisk and the pjproject tarballs, the way
  the core image builds SIPp and PJSIP. Only 30 modules are compiled: PJSIP
  signaling, registrar and Digest authentication, RTP, SRTP, the `Echo` and
  `Playback` applications, the `TIMEOUT()` function, `pbx_config`, G.711
  codecs, and the PCM/WAV formats. The image is about 100 MB and builds in about a minute.
- **Account:** one throwaway user, `practice`, realm `sippycup-practice`.
  `up` generates a new random password every time and writes it with mode
  0600 to `work/practice/account.password`. The password is never in argv,
  terminal output, container labels, image layers, or the connection facts.
  Inside the container it exists only in a tmpfs.
- **Signaling:** UDP and TCP on port 5060, TLS on port 5061. `up` creates a
  new CA and server certificate (ECDSA P-256, two-day validity). The server
  certificate carries the DNS SAN `sippycup-practice` and the IP SAN of the
  practice address. The CA key is deleted inside the container right after
  signing. The CA certificate is written to `work/practice/ca.crt`.
- **Media:** plain RTP or SDES-SRTP (when the caller offers `a=crypto`), PCMU
  and PCMA, server RTP ports 20000-20019.
- **Destinations** (`sip:NAME@127.0.0.2`):

  | Destination | Alias | Behavior |
  | --- | --- | --- |
  | `echo` | `600` | Answers and echoes received audio |
  | `tone` | `601` | Answers, plays the `media/canary-v1` callee-to-caller canary three times, hangs up |
  | `busy` | `486` | Rejects before answer with `486 Busy Here` |
  | `decline` | `603` | Rejects before answer with `603 Decline` |
  | anything else (`notfound`) | | `404 Not Found` after authentication; the drill dials `nobody-home` |

  Destinations that misbehave on purpose (rehearsed by
  `./bin/sippycup practice-target drill`; see "Rehearse failures"):

  | Destination | Behavior | Wire behavior |
  | --- | --- | --- |
  | `noanswer` | Rings and never answers | `180 Ringing`, no final response; the caller's answer timeout fires and its CANCEL ends the channel |
  | `late` | Rings 12 s, then answers and echoes | `180`, then `200 OK` about 12 s after the INVITE |
  | `silent` | Answers and sends no audio | `200 OK`; the server sends zero RTP packets while it still receives (`Answer()` then `Wait()` writes no frames) |
  | `silence` | Answers and plays digital silence | `200 OK`; RTP both ways, every server payload byte is `0xFF` (u-law silence) |
  | `drop` | Answers, echoes for 3 s, hangs up | `200 OK`, then `BYE` from the server (`TIMEOUT(absolute)`) |
  | `unavailable` | Rejects before answer | `503 Service Unavailable` |
  | `forbidden` | Rejects before answer | `403 Forbidden` |
  | `ratelimit` | Rejects before answer | `429 Too Many Requests` (`PJSIPHangup(429)`) |
  | `earlymedia` | 3 s of early media, then answers and echoes | `183 Session Progress` with SDP and RTP before the `200 OK` |
  | account `practice-srtp` | Same password; demands SDES-SRTP | `488 Not Acceptable Here` for the guided call's plain-RTP offer; dial any destination as this user |
  | `dtmf` | `602` | Answers with a steady 425 Hz tone, collects up to 32 RFC 4733 digits (4 s after the last digit), and sends the same digits back as RFC 4733 events |
  | anything else | | `404 Not Found` after authentication |

- **Unauthenticated requests:** every INVITE and REGISTER without valid
  Digest credentials is challenged with `401 Unauthorized`, whether it claims
  the practice user or any other identity. OPTIONS is answered `200 OK`
  without credentials, so preflights work like they do against most
  production edges.
- **Response routing:** `force_rport` is off. A UDP response goes to the Via
  sent-by port unless the request carries RFC 3581 `rport`. This is the strict
  RFC 3261 behavior that exposed the old campaign preflight bug, so the
  target keeps catching clients that omit `rport` or their real port.

## Network placement

The target runs with `--network=none`: its network namespace contains only
the loopback interface. Asterisk binds the practice address (default
`127.0.0.2`) in that namespace. The caller uses `127.0.0.1`, so the packet
oracle, which keys direction on IP addresses, can tell caller from callee.

Toolbox commands reach the target with the global launcher option
`--practice`. It runs the toolbox container in the target's network
namespace (`--network=container:sippycup-practice`) with `NET_RAW`, instead of
on the host network. Preflight, PJSUA, `campaign execute`, and `tcpdump` then
all see the same loopback interface. Rootless Podman permits packet capture
there because the namespace belongs to the rootless user namespace; no sudo is
needed at any step.

No name entries are added on either side. Every client addresses the target
by its literal address, and nothing in the toolbox resolves its own fixed
hostname any more (sipsak did; it was replaced by the in-tree OPTIONS
client). To verify the certificate's DNS name, pass it as a TLS server name
(`--tls-server-name sippycup-practice`) instead of resolving it. The TLS
profile and campaign do exactly that: they connect to the literal address
and verify `sippycup-practice` against `work/practice/ca.crt`.

Safety rules:

- `up` refuses any address that is not IPv4 loopback (`127.0.0.0/8`), and it
  also refuses `127.0.0.1`, the network and broadcast addresses, and names.
  The container entrypoint repeats the check and refuses to start if any
  interface other than `lo` exists.
- `--practice` fails closed before any container starts unless the named
  container is running, carries the label `dev.sippycup.profile=practice`,
  and has network mode `none`.
- `--practice` cannot be combined with `--isolated` or `--admin`. It is
  rejected by the fixed sandboxes (`mcp`, `mcp-live`), by `selftest`, by
  `doctor --host`, and by host-side commands such as `report` and `capture`.
  Like `--isolated`, it routes packaged `direct` and `workbench` commands
  into the container and rewrites `work/...` arguments to `/work/...`.
- The target container drops all capabilities, has a read-only root file
  system, `no-new-privileges`, and memory and process limits. The Asterisk
  Manager Interface is disabled.

Alternatives considered: publishing ports on the host loopback would make
the target reachable from any host process and would require host capture
privileges (sudo) for evidence. A shared bridge network would add a routable
container address. Joining the target's namespace keeps everything inside one
unreachable loopback and makes rootless capture work.

## Commands

```sh
./bin/sippycup practice-target build    # pinned optional image
./bin/sippycup practice-target up       # optional: --address 127.0.0.5
./bin/sippycup practice-target status
./bin/sippycup practice-target info     # or: info --format json
./bin/sippycup practice-target down
```

`info` prints the addresses, ports, account user, destinations, and the
locations of the password, CA, profile, campaign, expectations, and softphone
files. It never prints the password. `down` removes the container and deletes
the password and the softphone configurations; captures and reports remain.

`SIPPYCUP_PRACTICE_IMAGE` (default `localhost/sippycup-practice:latest`) and
`SIPPYCUP_PRACTICE_CONTAINER` (default `sippycup-practice`) override the image
tag and the container name. Set the same container name for `--practice`.

## Files written by `up`

All files are under the ignored `work/practice/` directory (mode 0700):

| File | Content |
| --- | --- |
| `account.password` | The throwaway password, mode 0600 |
| `ca.crt`, `server.crt` | The CA to verify against, and the server certificate |
| `target-profile.yaml` | Approved profile for the practice address, approval id `LOCAL-PRACTICE-ONLY`, valid for four hours from `up` |
| `target-profile-tls.yaml` | The same approval for TLS on port 5061: literal address `127.0.0.2`, `tls_server_name: sippycup-practice`, `tls_ca_file: work/practice/ca.crt` |
| `campaign.yaml` | Baseline campaign: one OPTIONS case on UDP and one on TCP |
| `campaign-tls.yaml` | TLS campaign: one OPTIONS case and one authenticated softphone call to `echo`, verified as `sippycup-practice` against `work/practice/ca.crt` |
| `expectations.yaml` | Packet-oracle expectations for the echo call |
| `uac.cfg`, `uac-tls.cfg`, `uac-srtp.cfg` | PJSUA configurations (UDP, TLS with server verification, SDES-SRTP), mode 0600 |
| `phrase.wav` | The caller-to-callee canary, decoded, for PJSUA to play |
| `connection.json` | Public connection facts |

The templates are in `examples/practice/`. The checked-in profile template
uses placeholders that cannot pass `rehearse`, so there is no standing
approval in the repository and nothing that expires in the future.

## Rehearse the complete operator sequence

Run each step from the repository root. Use two terminals for the capture.

1. Build and start the target, then read the connection facts:

   ```sh
   make build
   ./bin/sippycup practice-target build
   ./bin/sippycup practice-target up
   ```

2. Rehearse the generated profile (no network activity):

   ```sh
   ./bin/sippycup rehearse work/practice/target-profile.yaml
   ./bin/sippycup one-call work/practice/target-profile.yaml
   ```

   `one-call` renders the generic host-network plan. Its capture step uses
   the host capture wrapper (sudo) and its preflight runs on the host
   network, which cannot reach the practice namespace. For the practice
   target, use the `--practice` forms in steps 3 and 5 instead.

3. Send one bounded OPTIONS preflight over each transport. TLS verifies the
   server certificate; trust the generated CA and verify its DNS name:

   ```sh
   ./bin/sippycup --practice preflight 127.0.0.2 5060 udp
   ./bin/sippycup --practice preflight 127.0.0.2 5060 tcp
   ./bin/sippycup --practice preflight 127.0.0.2 5061 tls \
     --tls-ca /work/practice/ca.crt --tls-server-name sippycup-practice
   ```

   Without `--tls-ca` the TLS preflight fails with exit 5 (the practice CA is
   not a system CA). `--tls-unverified` skips verification and is always
   reported as `UNVERIFIED`.

4. Plan and execute the baseline campaign. Execution captures its own
   packets and runs the campaign's own OPTIONS preflight first:

   ```sh
   ./bin/sippycup campaign plan work/practice/campaign.yaml \
     --output work/practice/plan.json
   ./bin/sippycup --practice campaign execute work/practice/plan.json \
     --manifest work/practice/campaign.yaml \
     --run-root work/practice/runs \
     --interface lo
   ```

   `campaign plan` refuses to overwrite an existing plan; remove
   `work/practice/plan.json` before you plan again.

5. Start a capture in the practice namespace (first terminal):

   ```sh
   ./bin/sippycup --practice -- tcpdump -Z root -i lo -U -s 0 \
     -w /work/practice/call.pcap host 127.0.0.2
   ```

6. Place the authenticated call (second terminal). PJSUA registers, plays
   `phrase.wav`, records the echo to `work/practice/heard.wav`, and hangs up
   after eight seconds. Type `q` and Enter to leave it:

   ```sh
   ./bin/sippycup --practice -- pjsua \
     --config-file /work/practice/uac.cfg sip:echo@127.0.0.2
   ```

   For the TLS variant use `uac-tls.cfg` and
   `'sip:echo@127.0.0.2:5061;transport=tls'` (quoted for the shell); for
   SDES-SRTP use
   `uac-srtp.cfg`. Stop the capture with Ctrl-C.

7. Analyze the capture:

   ```sh
   ./bin/sippycup report work/practice/call.pcap
   ./bin/sippycup --practice triage work/practice/call.pcap
   ./bin/sippycup --practice assert \
     --expect work/practice/expectations.yaml work/practice/call.pcap
   ```

   `assert` should report an overall PASS with bidirectional media.
   `triage` warns that authorization material is present: the capture holds
   Digest responses for the throwaway account.

8. Try the negative cases from `CALL-CHECKLIST.md`: `sip:busy@127.0.0.2`,
   `sip:decline@127.0.0.2`, an unknown destination, and one wrong password.

9. TLS with the reviewed server name, still only to the literal address.
   The guided call verifies `sippycup-practice` against the practice CA:

   ```sh
   ./bin/sippycup rehearse work/practice/target-profile-tls.yaml
   ./bin/sippycup --practice call work/practice/target-profile-tls.yaml \
     --dial echo --username practice \
     --secret-file work/practice/account.password
   ./bin/sippycup campaign plan work/practice/campaign-tls.yaml \
     --output work/practice/plan-tls.json
   ./bin/sippycup --practice campaign run work/practice/plan-tls.json \
     --manifest work/practice/campaign-tls.yaml \
     --run-root work/practice/runs-tls --interface lo \
     --secret-env practice-password=PRACTICE_PASSWORD
   ```

   `campaign run` reads the password from the environment variable named by
   `--secret-env` (here `PRACTICE_PASSWORD`; set it from
   `work/practice/account.password` without echoing it). Plan the TLS
   campaign again after every `up`: each `up` makes a new CA,
   and execution refuses a plan whose frozen CA digest no longer matches.

10. Tear down:

   ```sh
   ./bin/sippycup practice-target down
   ```

## Rehearse failures

On the real engagement things go wrong, and the failure verdicts are only
useful if you have seen them before. The drill places the guided call
(`./bin/sippycup --practice call`) against each fault destination with the
right options and prints, per scenario, what the server did, the verdict
Sippycup reported, the expected verdict, `PASS` or `MISMATCH`, the run
directory, and the `./bin/sippycup explain call.VERDICT` text:

```sh
./bin/sippycup practice-target up
./bin/sippycup practice-target drill              # all scenarios, about 2 minutes
./bin/sippycup practice-target drill silent       # one scenario
./bin/sippycup practice-target drill all --format json
./bin/sippycup practice-target drill --list       # scenarios and estimates, sends nothing
```

The scenarios are `echo` (healthy control), `noanswer`, `late` (patient
caller, `--answer-timeout 20`), `late-impatient` (`--answer-timeout 6`),
`silent`, `silence`, `drop`, `unavailable`, `forbidden`, `ratelimit`, `busy`,
`decline`, `notfound`, `earlymedia`, `srtp-required`, `badpassword` (wrong
password: `registration-failed`), and `closedport` (a copy of the generated
profile whose port is 5099: `preflight-failed`). An estimate is printed first;
the drill exits 0 only when every verdict and exit code matches, 1 on a
mismatch, 2 when it could not start (nothing sent).

The drill cannot be pointed anywhere else: it has no address or profile
option, reads the generated practice facts, requires the profile to name only
that IPv4 loopback address under the `LOCAL-PRACTICE-ONLY` approval, and
reaches the target only through `--practice`, which fails closed unless the
named container is the running, labelled, network-less practice target. The
`closedport` and `badpassword` scenarios write a copy of that profile and a
wrong password file under `work/practice/drills/`; each drill run keeps its
evidence there.

Not rehearsable here: `possible-nat-one-way-media` (needs a non-loopback
target behind NAT), `media-outside-scope` (needs a server that advertises an
unapproved media address), `tls-not-verified` (covered by the gate's TLS
checks), `capture-*`, `authorization-lapsed`. A codec mismatch is not a
drill scenario, but the practice endpoints allow only PCMU and PCMA, so
`call --codec G722` (which offers G.722 alone) gets `488` and
`call-media-not-acceptable` (`GUIDED-CALL.md`, "Codec control");
`srtp-required` produces the same `488` verdict from the other common cause.
`hold` (a server-initiated re-INVITE with `sendonly`) is not possible with the
dialplan applications in the minimal module set: `StartMusicOnHold` does not
send a re-INVITE.

## Regression gate

```sh
make practice-gate
```

`make practice-gate` needs both images. It starts the target if it is not
already up and removes only what it started. With no sudo, it:

- rehearses the generated profile;
- requires that `sipsak` is absent from the toolbox image;
- runs the launcher preflight over UDP and TCP and requires `200 OK`; over
  TLS requires success when verified against the practice CA as
  `sippycup-practice` and by its IP SAN, exit 5 (a verification failure, not
  a pass) with no trust anchor and with a wrong server name, and an
  `UNVERIFIED` report for `--tls-unverified`; requires exit 3 (no response)
  against a closed UDP port and exit 4 (refused) against a closed TCP port;
- checks that the practice route carries no hosts entry for the toolbox
  hostname, so every later check proves that no tool needs one (`getent`
  sends no packets);
- plans the practice campaign and runs `campaign execute` in the practice
  namespace, which requires the campaign's own `sip_options_preflight` to get
  `200 OK` (status class `2xx`, no warning) over UDP and TCP, and both
  `options` steps to report the in-tree client's JSON summary with
  `finalStatus` 200 met. Because Asterisk runs with `force_rport` off, a
  client that drops its real Via port and `rport` gets no reply and fails
  these checks;
- sends one unauthenticated INVITE and requires a `401` with a Digest
  challenge;
- registers and places one authenticated PJSUA echo call with in-namespace
  `tcpdump`, then requires `report`, `triage`, and `assert` to pass, with
  bidirectional media, one credentialed INVITE, and a non-silent recording;
- tries one wrong password and requires rejection after exactly one
  credentialed REGISTER;
- requires `486` from `busy` and `603` from `decline`;
- places a TLS-signaled call to `tone` with server verification against the
  generated CA, requires a non-silent recording, and requires a TLS attempt
  that trusts only the system CAs to fail;
- requires `rehearse` and `one-call` to be ready for
  `work/practice/target-profile-tls.yaml` with server name
  `sippycup-practice`, the practice CA, and connections only to the literal
  address, and requires that the name does not resolve on the practice route;
- runs `./bin/sippycup --practice call work/practice/target-profile-tls.yaml
  --dial echo --username practice --secret-file work/practice/account.password`
  under a capture of all loopback traffic and requires `pass` with
  `tls.verified`, registration, and RTP decoded in both directions; from the
  capture it requires zero DNS packets (port 53), only `127.0.0.1` and the
  practice address, every ClientHello carrying SNI `sippycup-practice`, and
  TLS 1.2;
- requires a guided call with a wrong server name, and one that trusts only
  the system store, to exit non-zero with no client application data on the
  wire, and drives the softphone driver itself into both failures
  (`tls_verification_failed`, no SIP request), with a positive control that
  reaches the `401` challenge;
- plans `work/practice/campaign-tls.yaml` (options case plus an authenticated
  softphone call that dials `echo`), requires the name and CA SHA-256 in every
  step, runs it with `./bin/sippycup --practice campaign run ... --secret-env
  practice-password=VARIABLE`, and requires success with TLS verified in the
  preflight and the call, and no password in the evidence;
- plans a copy of that manifest whose CA file is a copy, modifies the copy,
  and requires execution to refuse with nothing captured;
- places an SDES-SRTP echo call and requires `RTP/SAVP` with `a=crypto` in
  the offer and answer and a non-silent recording.

- runs the whole fault drill and proves each scenario twice from the run's own
  capture: the server's wire behavior (no RTP from the peer for `silent`, every
  server payload `0xFF` for `silence`, BYE from the peer about 3 s after the
  answer for `drop`, the final 503/403/429/486/603/404/488, `183` and early RTP
  before the `200` for `earlymedia`, `180` then `200` about 12 s later for
  `late`, CANCEL from the caller for `noanswer`) and the verdict with its exit
  code. `make practice-drill-gate` runs only these checks.

Evidence and a `summary.json` are kept in `work/practice/gate-<UTC>-<PID>/`.
Under unittest, `tests/test_practice_gate.py` runs only with
`SIPPYCUP_PRACTICE_GATE=1` and skips when an image is absent; the make target
sets `SIPPYCUP_PRACTICE_GATE_REQUIRE_IMAGES=1` so a missing image fails it.
`make full-gate` includes it.

## Softphone gate

```sh
make softphone-gate
```

An opt-in gate for the softphone voice features, built on the practice gate
(same images, same target lifecycle). Evidence is kept in
`work/practice/softphone-gate-<UTC>-<PID>/`. It:

- places a guided call to `dtmf` with `--dtmf '159#,*0AD'` and requires
  `pass`, the digits `159#*0AD` decoded from the capture in both directions
  (sent and echoed back by Asterisk), and an oracle `media.dtmf` pass;
- registers with a wrong password and requires `registration-failed` with
  SIP status 401 in the human output and `result.json`, after exactly one
  credentialed REGISTER;
- places `--srtp mandatory` over TLS and requires `pass`, `RTP/SAVP` with an
  active suite, RTP in both directions, and no SDES key in the softphone log;
- places `--srtp optional` over UDP and requires the
  `sdes-key-exposed-on-cleartext-signaling` warning;
- in an isolated container, places `--srtp mandatory` against a plain-RTP
  PJSUA peer and requires `srtp-not-negotiated` with final status 488;
- runs `./bin/sippycup --practice campaign run` on a campaign whose call case
  sends `2468` to `dtmf` with `retainPayload: true`, and requires success,
  the runner line's `dtmf.status: sent`, the digits sent and echoed in the
  capture, RTP in both directions on the authorized media ports with
  `localRtpPort` reported, and no password in the evidence.

`tests/test_softphone_gate.py` runs it only with `SIPPYCUP_SOFTPHONE_GATE=1`.
It is not part of `make full-gate`.

## Limits

- The campaign manifest has OPTIONS cases only. The bundled SIPp runner
  refuses authenticated steps (SIPp would expose the password in argv), and
  the target challenges every unauthenticated INVITE, so an unauthenticated
  `call` case could only fail. The authenticated call uses PJSUA.
- Every `up` generates a new CA, so plan `campaign-tls.yaml` again after
  each `up`; an old plan is refused because the CA digest changed.
- The no-DNS proof is a capture of the practice namespace's only interface
  (loopback). The namespace has no route elsewhere, so a query to any other
  resolver could not leave it either; the gate also requires the name not to
  resolve outside PJSUA's pinned namespace.
- Only IPv4 loopback is supported. IPv6, NAT behavior, DTLS-SRTP, WebRTC,
  video, DTMF verification, hold, and transfer are not exercised. Hold is
  not available as a fault destination; a codec mismatch is made with
  `--codec` instead (see "Rehearse failures").
- The target answers one realistic shape of SIP edge (Asterisk with
  `force_rport` off). A real service can still differ in codecs, timers,
  authentication, and routing.
- The recording check proves that audio returned; it is not a quality
  measurement.
- `--practice` uses Podman's `container:` network mode. Other runtimes are
  not verified.

## Why it can never authorize real traffic

The practice profile, campaign, and expectations name only the loopback
practice address. That address exists only inside a network namespace that
has no other interface, so no packet sent by a practice command can leave the
host or reach another process outside the namespace. The profile's approval
id is `LOCAL-PRACTICE-ONLY`, it expires four hours after `up`, and it is
regenerated each time. No existing planner or profile validation was relaxed
for the practice target: loopback literals were already valid profile and
campaign addresses. Reaching a real target still requires the owner's written
authorization, a reviewed profile and plan, and the normal launcher modes
without `--practice`.
