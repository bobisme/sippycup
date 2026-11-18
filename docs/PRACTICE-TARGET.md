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
  the core image builds SIPp and PJSIP. Only 29 modules are compiled: PJSIP
  signaling, registrar and Digest authentication, RTP, SRTP, the `Echo` and
  `Playback` applications, `pbx_config`, G.711 codecs, and the PCM/WAV
  formats. The image is about 100 MB and builds in about a minute.
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

Because the runtime refuses `--add-host` in a joined namespace, `--practice`
mounts the target's own hosts file read-only. That file maps `sippycup`
(the toolbox's fixed hostname, which sipsak resolves before it sends) to
`127.0.0.1` and `sippycup-practice` to the practice address.

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
| `campaign.yaml` | Baseline campaign: one OPTIONS case on UDP and one on TCP |
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

3. Send one bounded OPTIONS preflight over each transport:

   ```sh
   ./bin/sippycup --practice preflight 127.0.0.2 5060 udp
   ./bin/sippycup --practice preflight 127.0.0.2 5060 tcp
   ./bin/sippycup --practice preflight 127.0.0.2 5061 tls
   ```

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

9. Tear down:

   ```sh
   ./bin/sippycup practice-target down
   ```

## Regression gate

```sh
make practice-gate
```

`make practice-gate` needs both images. It starts the target if it is not
already up and removes only what it started. With no sudo, it:

- rehearses the generated profile;
- runs the launcher preflight over UDP, TCP, and TLS and requires success,
  and requires a non-zero exit against closed UDP and TCP ports;
- checks that a host-network toolbox resolves its fixed hostname (the
  practice route never uses the host network, so this checks that fix
  directly; `getent` sends no packets);
- plans the practice campaign and runs `campaign execute` in the practice
  namespace, which requires the campaign's own `sip_options_preflight` to get
  `200 OK` over UDP and TCP;
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
- places an SDES-SRTP echo call and requires `RTP/SAVP` with `a=crypto` in
  the offer and answer and a non-silent recording.

Evidence and a `summary.json` are kept in `work/practice/gate-<UTC>-<PID>/`.
Under unittest, `tests/test_practice_gate.py` runs only with
`SIPPYCUP_PRACTICE_GATE=1` and skips when an image is absent; the make target
sets `SIPPYCUP_PRACTICE_GATE_REQUIRE_IMAGES=1` so a missing image fails it.
`make full-gate` includes it.

## Limits

- The campaign manifest has OPTIONS cases only. The bundled SIPp runner
  refuses authenticated steps (SIPp would expose the password in argv), and
  the target challenges every unauthenticated INVITE, so an unauthenticated
  `call` case could only fail. The authenticated call uses PJSUA.
- The campaign has no TLS case. Its TLS preflight validates against the
  container's system trust store, which does not contain the practice CA.
  The launcher preflight and PJSUA cover TLS.
- Only IPv4 loopback is supported. IPv6, NAT behavior, DTLS-SRTP, WebRTC,
  video, DTMF verification, hold, and transfer are not exercised.
- The target answers one realistic shape of SIP edge (Asterisk with
  `force_rport` off). A real service can still differ in codecs, timers,
  authentication, and routing.
- The recording check proves that audio returned; it is not a quality
  measurement.
- `--practice` uses Podman's `HostsPath` and `container:` network mode.
  Other runtimes are not verified.

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
