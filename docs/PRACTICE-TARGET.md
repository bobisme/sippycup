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
  codecs, and the PCM/WAV formats. The image is about 165 MB (100 MB before
  the Kamailio practice proxy, whose Debian package pulls in Python) and
  builds in about a minute.
- **Account:** one throwaway user, `practice`, realm `sippycup-practice`.
  `up` generates a new random password every time and writes it with mode
  0600 to `work/practice/account.password`. The password is never in argv,
  terminal output, container labels, image layers, or the connection facts.
  Inside the container it exists only in a tmpfs.
- **Signaling:** UDP and TCP on port 5060, TLS on port 5061. `up` creates a
  new CA and server certificate (ECDSA P-256, two-day validity). The server
  certificate carries the DNS SAN `sippycup-practice` and the IP SAN of the
  practice address. The CA key is deleted inside the container right after
  signing. The CA certificate is written to `work/practice/ca.crt`. Port 5061
  accepts TLS 1.2 only. A second TLS listener on 5071 accepts TLS 1.2 and TLS
  1.3 (never 1.0 or 1.1), only so `checks` can exercise a real TLS 1.3
  handshake (`make checks-gate`); the guided-call paths use 5061.
- **Media:** plain RTP or SDES-SRTP (when the caller offers `a=crypto`), PCMU
  and PCMA, server RTP ports 20000-20019.
- **Destinations** (`sip:NAME@127.0.0.2`):

  | Destination | Alias | Behavior |
  | --- | --- | --- |
  | `echo` | `600` | Answers and echoes received audio |
  | `tone` | `601` | Answers, plays the `media/canary-v1` callee-to-caller canary three times, hangs up |
  | `busy` | `486` | Rejects before answer with `486 Busy Here` |
  | `decline` | `603` | Rejects before answer with `603 Decline` |
  | `nobody-home` (`notfound`) | | Not in the dial plan on purpose: `404 Not Found` after authentication (the drill's `notfound` scenario) |

  The practice profiles list these destinations, the aliases, the fault
  destinations below, and `nobody-home` as `target.approved_destinations`.
  `call` and `matrix` refuse any other `--dial` (for example the typo
  `ecoh`) with exit 2 before anything is sent, exactly as a profile from
  `scope compile` does on an engagement (`GUIDED-CALL.md`, "Approved
  destinations"). Try it once: it is the refusal you will see for a typo.

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
  | `nobody-home` | | `404 Not Found` after authentication (any other name gets 404 from the server too, but the practice profiles refuse to dial it) |

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

## Practice proxy (second SIP stack)

A real engagement target is rarely one Asterisk that challenges with 401 and
puts signaling and media on one address. It is usually a proxy or SBC in
front of media servers. The same practice container therefore also runs
Kamailio (Debian 13's `kamailio` 6.0 package plus `kamailio-tls-modules`;
no database module) on its own loopback address, `127.0.0.3` by default
(`up --proxy-address P`). It is always on: it starts beside Asterisk in under
a second, binds nothing on the Asterisk address, and the existing profiles,
campaigns, gates, and drill never send to it.

| | Direct Asterisk (`127.0.0.2`) | Proxy (`127.0.0.3`) |
| --- | --- | --- |
| Signaling | UDP/TCP 5060, TLS 5061 (`sippycup-practice`) | UDP/TCP 5060, TLS 5061 (`sippycup-proxy`, same per-`up` CA, IP SAN `127.0.0.3`) |
| OPTIONS | 200 from Asterisk | 200 from the proxy itself |
| REGISTER | 401, realm `sippycup-practice` | 401, realm `sippycup-proxy`; in-memory registrar in the proxy |
| INVITE | 401 `WWW-Authenticate` | **407 `Proxy-Authenticate`**, realm `sippycup-proxy`, qop `auth` |
| Routing | none | `Record-Route` (two entries when the transport changes); in-dialog requests (ACK, BYE, UPDATE, re-INVITE) must carry the proxy's `Route`, otherwise `404 Not Here` |
| Media | `127.0.0.2:20000-20019` | the same: the SDP answer names `127.0.0.2`, which **differs from the signaling address** |
| Flood | none | more than 60 requests in 2 s from one source get `503` with `Retry-After` (pike) |

The account is the same (`practice`, `work/practice/account.password`); the
destinations are the same, dialed at the proxy (`sip:echo@127.0.0.3`). The
proxy forwards every authenticated INVITE to Asterisk over TLS (it verifies
Asterisk's certificate against the per-`up` CA). `up` also writes
`target-profile-proxy.yaml` and `target-profile-proxy-tls.yaml` (approved
addresses: the proxy and the media address), `campaign-proxy.yaml` (OPTIONS
on UDP and TCP and one softphone call, both networks authorized, one-call
ceiling), `expectations-proxy.yaml`, and `proxy.crt`.

```sh
./bin/sippycup --practice preflight 127.0.0.3 5061 tls \
  --tls-ca /work/practice/ca.crt --tls-server-name sippycup-proxy
./bin/sippycup --practice call work/practice/target-profile-proxy.yaml \
  --dial echo --username practice --secret-file work/practice/account.password
./bin/sippycup --practice call work/practice/target-profile-proxy-tls.yaml \
  --dial echo --srtp mandatory --username practice \
  --secret-file work/practice/account.password
```

To see the media-scope stop, copy `target-profile-proxy.yaml`, remove
`127.0.0.2` from `approved_addresses`, and place the same call: the verdict is
`media-outside-scope` and the call is hung up as soon as PJSUA reports the
media peer.

### How Asterisk trusts the proxy

Asterisk must accept calls the proxy already authenticated without accepting
unauthenticated calls from anyone else. Everything here shares one loopback
namespace, so any process can send from any `127.x` address, including the
proxy's: trusting the source address alone would let any local client skip
authentication. The decision:

- At every container start the entrypoint generates a random 192-bit trunk
  token. It exists only in the container's tmpfs (rendered `kamailio.cfg` and
  `pjsip.conf`), never in `work/`, argv, or the container environment.
- The proxy removes any `X-Sippycup-Trunk` header a client sends and adds its
  own to the INVITEs it forwards. The trunk leg is TLS, so the token never
  appears in a capture.
- Asterisk identifies the endpoint `proxy-trunk` (no Digest auth) by that
  header only (`endpoint_identifier_order = header,username,ip`, so it is
  checked first), and the endpoint ACL denies it from every source except the
  proxy address.
- A request without the exact token, from any source including `127.0.0.3`,
  is identified exactly as before and challenged with 401. The proxy gate
  proves each case (forged token, no token from the proxy address, the real
  token from another source: 401; the real token from the proxy address: no
  challenge).

Residual risk, accepted for a practice target: a process that can read the
container's tmpfs and send from `127.0.0.3` can impersonate the proxy.

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
| `approvals/STAMP-target-profile.yaml`, `approvals/STAMP-target-profile-tls.yaml` | An immutable copy of each practice approval that `up` issued (STAMP is the `up` time). `down` keeps them; they hold no secret |
| `proxy.crt` | The practice proxy's certificate (`sippycup-proxy`, IP SAN of the proxy address) |
| `target-profile-proxy.yaml`, `target-profile-proxy-tls.yaml` | Approved profiles for the practice proxy: signaling to the proxy, approved addresses proxy and media address; the TLS one pins `sippycup-proxy` |
| `campaign-proxy.yaml` | Campaign through the proxy: OPTIONS on UDP and TCP and one authenticated softphone call (407), both networks authorized |
| `expectations-proxy.yaml` | Packet-oracle expectations for an echo call through the proxy |
| `target-profile-matrix.yaml`, `target-profile-matrix-tls.yaml`, `target-profile-matrix-proxy.yaml`, `target-profile-matrix-proxy-tls.yaml` | Matrix-ready copies of the four profiles above (see "Practice the call matrix"); also archived in `approvals/` |

The templates are in `examples/practice/`. The checked-in profile template
uses placeholders that cannot pass `rehearse`, so there is no standing
approval in the repository and nothing that expires in the future.

## Practice the call matrix

The one-call profiles above carry `limits.max_calls: 1`, so `matrix plan` and
`matrix run` correctly refuse them. `up` therefore also renders a matrix-ready
copy of each, as separate files, so the one-call profiles and everything that
depends on them are unchanged. A copy differs in four things only: the profile
name gets `-matrix`, `limits.max_calls` is 12 (concurrency and the 1 call per
second limit stay at 1), `features.srtp` is true (so SDES-SRTP rows are
allowed), and the capture file name. Target, approved addresses, approval id,
and the four-hour window are identical, and the files are archived with the
other approvals, so `summary` treats their runs as practice runs.

Every `up` also starts a new practice approval window in the call ledger
(`work/practice/call-ledger.jsonl`): all practice commands together may place
200 calls until the next `up`, and each profile's `limits.max_calls` still
bounds one command. When the budget is used, `call` and the others refuse
with the counts; `practice-target down` and `up` start a new window.

A matrix takes one profile per transport, so each route is a pair: direct
(`target-profile-matrix.yaml` + `target-profile-matrix-tls.yaml`) and through
the proxy (`target-profile-matrix-proxy.yaml` +
`target-profile-matrix-proxy-tls.yaml`). `practice-target info` prints the exact
commands:

```sh
./bin/sippycup matrix plan work/practice/target-profile-matrix.yaml work/practice/target-profile-matrix-tls.yaml \
  --dial echo --codecs PCMU,PCMA,G722 --srtp off,mandatory --max-calls 12
./bin/sippycup --practice matrix run work/practice/target-profile-matrix.yaml work/practice/target-profile-matrix-tls.yaml \
  --dial echo --codecs PCMU,PCMA,G722 --srtp off,mandatory --max-calls 12 \
  --username practice --secret-file work/practice/account.password --duration 4
```

Use the `-proxy` pair for the same grid through the proxy. Twelve cells take
about two minutes. G.722 is refused by the practice endpoints, so the G722
cells fail by design (`call-media-not-acceptable`, or `srtp-not-negotiated`
with `--srtp mandatory`); the other eight pass. `rehearse` on a matrix profile
says "ready" and one warning that the profile approves up to 12 calls, which
is expected for a matrix or a campaign. The owner report draws the finished
grid (`summary`, see `ENGAGEMENT-REPORT.md`). `make codec-gate` runs a short
matrix over these profiles.

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
target behind NAT), `media-outside-scope` (not in the drill; rehearse it
through the practice proxy with a profile that approves only the proxy, see
"Practice proxy"), `tls-not-verified` (covered by the gate's TLS
checks), `capture-*`, `authorization-lapsed`. A codec mismatch is not a
drill scenario, but the practice endpoints allow only PCMU and PCMA, so
`call --codec G722` (which offers G.722 alone) gets `488` and
`call-media-not-acceptable` (`GUIDED-CALL.md`, "Codec control");
`srtp-required` produces the same `488` verdict from the other common cause.
`hold` (a server-initiated re-INVITE with `sendonly`) is not possible with the
dialplan applications in the minimal module set: `StartMusicOnHold` does not
send a re-INVITE.

## Dress rehearsal

The drill rehearses failures of one command. The dress rehearsal rehearses
the whole owner-facing chain, in the order you will use it on the real
engagement, with the real public commands:

```sh
./bin/sippycup practice-target rehearsal            # about 90 s
./bin/sippycup practice-target rehearsal --proxy    # the proxy shape, about 90 s
./bin/sippycup practice-target rehearsal --list     # the stages; sends nothing
make dress-rehearsal                                # the same, with the make image variables
make dress-rehearsal-proxy                          # --proxy, with the make image variables
```

| # | Stage | Commands |
| --- | --- | --- |
| 1 | Practice target up and verified | `practice-target status` (and `up` when it is down) |
| 2 | New engagement | `journal init DIR`, `scope init DIR --name dress-rehearsal` |
| 3 | Practice call from the cockpit (stage 2) | the cockpit's `--practice call work/practice/target-profile.yaml --dial echo ...`, then the `journal add` the call prints |
| 4 | Scope | writes the answers file `DIR/scope.yaml` from the connection facts, copies the CA to `DIR/practice-ca.crt`, then `scope check DIR`, `scope compile DIR` |
| 5 | Rehearse | `rehearse DIR/target-profile.yaml`, `checks plan DIR/target-profile.yaml` |
| 6 | Preflight | `--practice preflight --profile DIR/target-profile.yaml` (bound: UDP target and approval from the profile); `--practice preflight 127.0.0.2 5061 tls --tls-ca DIR/practice-ca.crt --tls-server-name sippycup-practice` |
| 7 | Guided call | the cockpit's `--practice call DIR/target-profile.yaml --dial echo --username practice` plus `--secret-file`, then `--dial dtmf --dtmf '159#'`; each with its `journal add` |
| 8 | Campaign | the cockpit's `campaign plan` and `--practice campaign run ... --secret-env practice-password=SIPPYCUP_COCKPIT_SECRET` (UDP and TLS OPTIONS, UDP and TLS authenticated calls) |
| 9 | Security checks | `checks plan`, then the cockpit's `--practice checks run DIR/target-profile.yaml` plus `--secret-file` (the seven UDP checks and `srtp-policy`) |
| 10 | Evidence | each `journal add` and `evidence manifest` that the cockpit offers |
| 11 | Owner report | the cockpit's `summary DIR --journal` plus `--forbid-file work/practice/account.password` |
| 12 | Safety stop (throwaway engagement `DIR-stop`) | `journal init`, `scope init`, answers that approve only the proxy, `scope check`, `scope compile`, `rehearse`, the cockpit's `--practice call ... --dial echo` (must end `media-outside-scope`, exit 1), its `journal add`, `evidence manifest`, and the cockpit's `summary` |

DIR is `work/practice/rehearsals/dress-STAMP-PID`. Where a stage says "the
cockpit's", the rehearsal takes the exact argv from `./bin/sippycup go DIR
--format json` and adds only what the cockpit's confirmation panel would add
(the password source). After each stage it runs `go DIR --plain` and `go DIR
--format json` and requires that both name the same current stage and next
command, and that this is the stage that should follow. A stage passes only
when its own assertions hold, for example: verdict `pass`; the DTMF digits
decoded from the capture in both directions; TLS verified as
`sippycup-practice`; campaign `succeeded` with four steps and its run directory
printed as a host path; every approved check ran to `passed` or `finding`;
an owner report with zero integrity exceptions that labels the practice call
as practice and carries exactly the check findings the checks run reported
(including those of `srtp-policy`); and the practice password in no file of
the engagement.

The approved checks are the seven UDP checks plus `srtp-policy` (two
1-second calls on a UDP first target: plain RTP, then a mandatory SDES
offer). `security_checks.max_requests` is generated as exactly the sum of the
declared bounds (33: 21 for the seven, 12 for `srtp-policy`), the same sum
`scope check` compares it with.

### Proxy shape (`--proxy`)

The real engagement is most likely a proxy or SBC: signaling to one address,
407 challenges in the proxy's realm, Record-Route, and media from other
addresses. `--proxy` runs the same twelve stages, but the answers describe
the practice proxy exactly as the owner of such a platform writes them:

| Answer | Value |
| --- | --- |
| `signaling.networks`, `targets[].address` | `127.0.0.3` (the proxy), UDP 5060 and TLS 5061 |
| `targets[].tls_server_name` | `sippycup-proxy` (`tls_ca_file`: the engagement's copy of the practice CA) |
| `media.networks` | `127.0.0.2` (the practice address; it differs from the signaling address) |
| `account.realm` | `sippycup-proxy` |

Everything after that goes through what `scope compile` generated, unedited:
the profile approves `127.0.0.3` and `127.0.0.2`, the campaign authorizes both
networks, the expectations allow both. Preflight goes to the proxy (TLS
verified as `sippycup-proxy`). In addition to the assertions above, every
guided call must have signalled to `127.0.0.3` with its media peer on
`127.0.0.2`, and `unauthenticated-invite` must have seen the proxy's 407.
DIR is `work/practice/rehearsals/dress-proxy-STAMP-PID`.

### Media as a range (`--media-cidr`)

Owners usually approve media as a media-server pool, a range. `--media-cidr`
(it implies `--proxy`) answers `media.networks` with `127.0.0.2/31` instead of
the literal `127.0.0.2`. That `/31` covers `127.0.0.2` and `127.0.0.3`: no
range wider than one address can hold `127.0.0.2` without `127.0.0.3`, so the
signaling address lies inside it too, which is harmless because signaling is
approved only through the literal address. `scope compile` then writes
`target.approved_addresses: [127.0.0.3]` and `media.networks: [127.0.0.2/31]`
(media only), which the stage asserts, and `rehearse` must show the range on
its `Media only:` line. In addition to the proxy assertions, every guided call
must record `mediaScope.admittedBy: media-network` with network
`127.0.0.2/31`, and stage 7 places one more call through the same route with a
copy of the profile whose `target.host` is the media address `127.0.0.2`
(inside the range): it must be refused before any packet (exit 2, state
`blocked`, no run directory), because a media network never admits
signaling. The owner report shows those calls with `peerApprovedBy:
media-network` and lists the range under "approved for media only". The stop
leg answers the adjacent range `127.0.0.4/31`, just outside the media
address, so the call must stop `media-outside-scope` with `mediaScope`
recording the refusal. DIR is
`work/practice/rehearsals/dress-proxy-cidr-STAMP-PID`; `make
dress-rehearsal-proxy-cidr` runs it.

### The safety stop (stage 12)

Every variant ends with one deliberately failing leg, so you see the stop
once before it happens on the real engagement. It uses a separate throwaway
engagement, `DIR-stop`, so the main engagement's owner report stays clean.
Its answers make the most likely owner mistake: media "on the same address
as signaling", so only the proxy `127.0.0.3` is approved and the real media
address `127.0.0.2` is not. The cockpit's guided call must end
`media-outside-scope` (exit 1) with the media peer on `127.0.0.2` and at most
10 RTP packets sent there before the hangup (typically 3). Then:

- the cockpit lists the run as `[stop]` with the reason "safety stop, not a
  target failure: the media peer ... is not an approved address or inside an
  approved media network, so the call was hung up after N RTP packets; add
  the owner's media addresses or media network to the scope and compile
  again";
- the owner report of `DIR-stop` lists it as an `info` observation titled
  "Safety stop: media was negotiated to an address outside the approved
  scope", no oracle observation, the executive summary row "1 run was ended
  by a Sippycup safety stop (media-outside-scope), not a target failure", and
  exactly one integrity exception, `media-peer-not-approved`, that discloses
  the packets sent before the stop. `summary` therefore exits 1 there, which
  the stage requires.

The direct variant uses the same stop leg (only the proxy has a media address
that differs from its signaling address).

Output is one `[PASS]` or `[FAIL]` line per stage with the commands it ran
(the password is never printed; the campaign's variable is shown as
`<from work/practice/account.password>`), then a table and the total time.
The first failure stops the chain; later stages are `SKIP`. Exit status: 0
when every stage passed, 1 on a failure, 2 when it could not start (no
practice image, or the practice approval ends in under 20 minutes). The
evidence stays in DIR: every run, the owner report in `report/`, the full
output of every command in `rehearsal/commands.log`, and
`rehearsal/summary.json`. When the target was down, the rehearsal starts it
and takes it down again; when it was up, it stays up with the same password
and CA. The answers file uses approval id `LOCAL-PRACTICE-REHEARSAL` and the
window from now until the practice approval ends.

Like the drill, it has no address, profile, or host option, and it reaches
the target only through `--practice`. `make dress-rehearsal-gate` runs it
through `tests/test_dress_rehearsal_gate.py` (opt-in with
`SIPPYCUP_DRESS_REHEARSAL_GATE=1`) and also requires that the target is left
as it was found; `make dress-rehearsal-proxy-gate` runs the `--proxy` variant
the same way (`SIPPYCUP_DRESS_REHEARSAL_GATE=proxy`, or `all` for both).

### Practice runs in the owner report

Every `up` issues a new four-hour approval and overwrites
`target-profile.yaml`, so a run placed before a restart used to fall outside
the window of the current profile, and `summary` reported
`outside-approval-window`. A practice call in a real engagement (the cockpit's
stage 2 writes it to `DIR/practice-calls/`, and the call prints a `journal add`
for it) was reported as `target-not-approved`. Now `up` keeps each approval in
`work/practice/approvals/`, and `summary` checks a call or checks run whose
recorded `profile.json` is equal, field for field, to one of those archived
approvals against that approval only. An archived file counts only when it is
a target profile with approval id `LOCAL-PRACTICE-ONLY` whose host and every
approved address are IPv4 loopback addresses other than `127.0.0.1`. Such runs
are listed with the reason "practice target run", appear with the archived
approval (kind `practice-target-profile`) under Authorization, are not counted
in the totals, and are named in a `practice-runs` limitation. Every other run
is checked exactly as before; a practice approval never covers a run that did
not use it. Runs made before this archive existed have no record and are
still reported.

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

## Proxy gate

```sh
make practice-proxy-gate
```

An opt-in gate (about 90 s; same images and target lifecycle as the practice
gate) for every path through the practice proxy. Evidence is kept in
`work/practice/proxy-gate-<UTC>-<PID>/`. It:

- requires the proxy facts and the rendered proxy profiles to be ready, with
  the proxy and the media address approved;
- runs the launcher preflight to the proxy over UDP, TCP, and TLS verified as
  `sippycup-proxy`, and requires exit 5 when verified as `sippycup-practice`;
- runs raw probes (`tools/practice_proxy_probe.py`): 407 for INVITE and 401
  for REGISTER in realm `sippycup-proxy`, 404 for an in-dialog BYE without
  the proxy's Route, a client-supplied trunk token stripped, and the trust
  decision above (four refusals and one positive control);
- places guided calls through the proxy: with registration (pass, one oracle
  dialog, two INVITEs around the 407, every caller request including ACK and
  BYE sent to the proxy, RTP only between the caller and `127.0.0.2`), with
  `--no-register`, with DTMF `159#` (sent and echoed), to `drop` (the server
  BYE arrives from the proxy), and over TLS pinned to `sippycup-proxy` with
  `--srtp mandatory`;
- requires `media-outside-scope` with at most 10 RTP packets to the media
  address when a copy of the profile approves only the proxy;
- runs `campaign-proxy.yaml` (one-call ceiling: the capture watchdog counts
  the INVITE re-sent after the 407 as the same call) and a SIPp-runner
  campaign whose unauthenticated call fails on the 407, which SIPp ACKs;
- runs `checks run` against the proxy over UDP (unauthenticated INVITE
  challenged with 407 and ACKed) and TLS (certificate verified for
  `sippycup-proxy`).

`tests/test_practice_proxy_gate.py` runs it only with
`SIPPYCUP_PRACTICE_PROXY_GATE=1`. It is not part of `make full-gate`.

## Limits

- Through the proxy, the SIPp runner fails exactly as it does against
  Asterisk directly: it never authenticates (the password would be in SIPp's
  argv), so its unauthenticated INVITE gets 407. SIPp itself handles the 407
  at the protocol level (it ACKs it); only the PJSUA softphone runner places
  authenticated calls.
- The proxy forwards to Asterisk over TLS, so the trunk leg is not readable in
  a capture. The oracle still merges a Record-Routed dialog seen on two
  cleartext hops into one dialog (unit-tested), which matters for captures a
  target owner provides from both sides of their SBC.
- The proxy does not anchor media (no rtpengine), does not hide topology, and
  is not a B2BUA: Call-ID and tags pass through unchanged. A B2BUA SBC would
  change the Call-ID between legs; only the caller's leg is ever captured on a
  real engagement.
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
  video, SIP INFO and in-band DTMF, hold, and transfer are not exercised
  (RFC 4733 DTMF is, through the `dtmf` destination). Hold is
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
