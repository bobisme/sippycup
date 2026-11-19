# Safety audit of the guardrails (bn-2jg)

Sippycup promises that it sends nothing outside what the service owner
approved: signaling only to the literal approved target, media only to
approved addresses, media networks and ports, only inside the approval
window, only within the call and request ceilings, only the approved checks,
and that credentials never leak. This page records an audit of that promise
as a whole, done after about fifteen features were merged in parallel. It
says what was tested, how, what was found and fixed, and which risks remain
for the operator to manage by procedure.

All experiments ran on loopback: in a private container network namespace
(`./bin/sippycup --isolated -- ...`) or in the practice target's namespace,
which has no route off the host. No external host was contacted.

## Summary

| # | Severity | Finding | State |
|---|---|---|---|
| 1 | Critical | A far end's `Record-Route` or `Contact` steered PJSUA's ACK and BYE to an unapproved address, although the driver sets a global `--outbound` route. The call still ended `one-way-media` with no scope alarm. | Fixed (detect and stop) |
| 2 | Critical | The media-scope check read PJSUA's `peer=`, which is where RTP came *from*. A far end whose SDP names an unapproved address (media-level `c=`, `a=rtcp`, or a re-INVITE) received the whole call's RTP and RTCP with no alarm, if it sent no RTP or sent it from an approved address. | Fixed (detect and stop) |
| 3 | Medium | SIGHUP (closing the terminal) killed `call`, `checks`, `matrix` and campaigns at once: no BYE, no unregistration (REGISTER stays for 300 s), no `result.json`. | Fixed |
| 4 | Low | `approved_addresses` accepted a YAML integer (`2130706433` is 127.0.0.1), non-canonical spellings, and unspecified, multicast or broadcast addresses. | Fixed |
| 5 | High | `campaign run` has no approval window and no approval status. A frozen plan runs after `valid_until`, after revocation, and a long campaign can cross the window's end. | Fixed (bn-3vxl) |
| 6 | Medium | Ceilings are per process and per invocation. Two commands at once (two terminals, or the cockpit and a shell) each get the full ceiling, and `max_calls` is not a budget across repeated `call` runs. | Reported |
| 7 | Medium | Some senders are not bound to a profile at all: `preflight HOST`, `media send`, `shell` and `--`. `media send` took its destination from the session's remote SDP and would send its canary to any literal unicast address (bn-328). | Fixed for `media send`; `preflight` can be bound and says when it is not; `shell` and `--` say UNBOUND (bn-328, bn-3df) |
| 8 | Medium | No kernel egress filter. Findings 1 and 2 are now caught within one poll interval, but a few packets still leave before the stop, and a host name in a far-end URI or SDP causes a DNS lookup first. | Reported (design) |
| 9 | Low | Campaign run artifacts (including `capture.pcap`) are written mode 0644 in a 0755 `runs/` directory; call and checks runs are 0600/0700. | Fixed (bn-3vxl) |
| 10 | Low | Campaign `authorization.networks` has no size limit (`0.0.0.0/0` is accepted); media networks are capped at 1024 addresses. | Fixed (bn-3vxl) |
| 11 | Low | A profile with unquoted timestamps (which `scope` documents as fine) makes `call` stop with `internal-error` (`datetime is not JSON serializable`) before any packet. Fails closed. | Reported |

## Fixes

### 1 and 2: the softphone driver watches what PJSUA sends

`lib/sippycup_softphone/driver.py` now tails PJSUA's level-5 message log
while the call runs. That log is written as each message is sent or
received. A measurement showed the received 200 OK in the file 66 ms after the
call started, before the first RTP packet, so the log is a usable live source.

- Every `TX ... to UDP|TCP|TLS HOST:PORT` line must name the literal
  `target.host` (or the reviewed TLS server name, which is pinned to it).
  Anything else means PJSUA followed a far-end route. The driver then sends
  SIGKILL to PJSUA's process group at once: a hang-up or a quit would send a
  BYE along the same route. The call ends `signaling_outside_scope`, and the
  guided call verdict is `signaling-outside-scope` (a safety stop, like
  `media-outside-scope`, in the cockpit, the matrix stop list, the owner report
  and `srtp-policy`).
- Every SDP the far end sends (the answer, a re-INVITE or UPDATE offer) is
  checked. A media-level `c=` overrides the session-level one, `a=rtcp` with an
  address counts, and port 0 and the hold address are skipped. Each address
  must be an approved address or lie in an approved media network, and the
  RTP port must lie in `media.port_range`. A name is never admitted. On a
  violation the driver hangs up (`media_peer_outside_scope`). The BYE uses the
  route that the first check has already proven. `result.json` records the
  refused destination in `softphone.scope_violation` and
  `softphone.media_scope.sdpRefused`.

The received-RTP `peer=` check is kept as a second signal.

Loopback evidence (`tools/safety_audit_farend_probe.py`: a
hostile UAS on 127.0.0.2, with counting listeners on 127.0.0.66/.77/.88/.99,
the approved target 127.0.0.2, and PJSUA 2.17 from the image):

| Far end does | Before (packets to unapproved addresses, result) | After |
|---|---|---|
| 200 OK with `Record-Route: <sip:127.0.0.66;lr>` | ACK + 2 BYE to .66; no error; guided verdict `one-way-media` | 1 ACK to .66 (sent by PJSIP before anything can act); PJSUA killed; `signaling-outside-scope` |
| 200 OK with `Contact: <sip:far@127.0.0.77>` only | ACK + 2 BYE to .77; no error | 1 ACK; killed; `signaling-outside-scope` |
| SDP `c=` at media level 127.0.0.88 | 300 RTP + 5 RTCP (the whole 6 s call); no error; verdict `one-way-media` | 1 RTP + 4 RTCP, then BYE to .2; `media-outside-scope` |
| `a=rtcp:40011 IN IP4 127.0.0.99` | 5 RTCP; no error | 4 RTCP, then BYE; `media-outside-scope` |
| re-INVITE moving media to 127.0.0.88 after 1.5 s | 220 RTP + 3 RTCP; no error | 3 RTCP, 0 RTP, then BYE; `media-outside-scope` |
| Session-level `c=` .88, media-level `c=` .2 | nothing to .88 (correct) | unchanged |
| 302 redirect to 127.0.0.77 | not followed (`--accept-redirect=0`) | unchanged |
| REFER to `sip:victim@127.0.0.77` | 202 accepted, no INVITE sent (`--max-calls=1`) | unchanged |

Tests: `tests/test_scope_watch.py` (12 tests; they failed on the old code).
The fake PJSUA now logs its TX destination from the configured route and has
the modes `steer`, `sdpsteer` and `rtcpsteer`.

### 3: SIGHUP

The image runs `tini` as PID 1, which passes SIGHUP to the command. No sender
handled it, so Python's default action ended the process at once. A practice
call that got SIGHUP 12 s in left no `result.json` and no `softphone.log`, and
the capture shows no BYE and no `REGISTER Expires: 0`. Now `call`, `checks`,
`matrix`, the campaign supervisor, the campaign executor and the campaign
softphone runner treat SIGHUP like SIGTERM (exit 143). The same experiment
now shows `cancelled`, then BYE at 10.87 s, then unregistration, and the
evidence is complete. Tests: `tests.test_guided_call.SignalTests` and
`tests.test_runtime.RuntimeSignalTests` (both failed on the old code: the
test process died with exit 129).

### 7: `media send` is bound to a profile; unbound senders say so (bn-328, bn-3df)

Before: `./bin/sippycup media send SESSION --dry-run`, with a session whose
remote SDP names `8.8.8.8:5353`, printed a 71-packet plan for that address and
exited 0. The live path had the same checks (literal unicast, port 1024 or
above), so it would have sent there. Only the dry run was tried.

Now (`lib/sippycup_workbench/binding.py`, which composes `rehearse`,
`host_is_approved_literal` and `media_scope.profile_scope`, and adds no rule of
its own):

- `media send --profile PROFILE` requires an approved profile whose window
  covers the send. Every remote SDP endpoint must be an approved address or in
  an approved media network, and within `media.port_range`. Without a profile
  only loopback destinations are accepted, labelled `UNBOUND (loopback only)`.
  The same session now exits 2 with no socket opened, live and with
  `--dry-run`.
- `preflight --profile PROFILE` takes host, port, transport, TLS name and CA
  from the profile and refuses a mismatch before any packet. Without a profile
  it still runs and prints `Scope: UNBOUND (operator-supplied target HOST)`.
- `--require-profile` or `SIPPYCUP_REQUIRE_PROFILE=1` makes both refuse to run
  unbound.
- `shell` and `-- COMMAND` print a `Scope: UNBOUND` notice on stderr. They
  enforce nothing, by design.

| Command | Class |
|---|---|
| `call`, `matrix`, `checks`, `campaign`, `mcp-live`, `go` | Scope-bound |
| `preflight`, `media` (`media send`) | Optionally bound (`--profile`; `--require-profile` makes it mandatory) |
| `capture`, `chaos`, `chaos-exit-gate`, `webrtc` | Unbound (own scope inputs; see their pages) |
| `media-echo`, `selftest`, `practice-target`, `ready`, `stop` | Unbound, local only |
| `shell`, `-- COMMAND` | Unbound |

The table with what each class checks is in `CLI.md`, "Scope binding".
Tests: `tests/test_scope_binding.py`.

### 4: approved address spelling

`rehearse` now accepts only canonical string literals
(`str(ip_address(a)) == a`) that are single unicast hosts. A reviewer reads
exactly the address that is used. Tests: `tests/test_safety_audit.py`.

### 5: campaigns are bound to the approval window

The manifest and the frozen plan now carry the window
(`authorization.approval`: `id`, `validFrom`, `validUntil`), which `scope
compile` writes from the scope. The details are in `CAMPAIGN-MANIFEST.md`,
"Approval window". In short:

- `campaign plan` refuses a window that has already ended (nothing is
  written) and warns when the planned duration cannot fit.
- `campaign run` refuses before any secret, directory, capture or packet when
  it is outside the window or when the preflights and the first step cannot
  fit. It checks again before every preflight and before every step, with
  that step's own planned duration. When the window ends between steps, it
  stops before the next step, records `authorization_lapsed` in
  `events.jsonl` and `result.json`, and exits 1.
- A `scope.yaml` beside the manifest is read at each of those checks. A
  status other than `approved`, or an approval that differs from the plan,
  refuses the run or stops it before the next step. This is how a revocation
  reaches a campaign.
- The manifest lock covers the window: a plan whose window was edited or
  removed is refused.
- A manifest with no window and no scope file beside it still runs (the
  self-tests and older manifests are of that kind), with a `WARNING` on
  standard error from `plan` and `run`, `approvalWindow.bound: false` in
  `result.json`, a warning in `ready` and the cockpit, and a limitation in
  the owner report.

Verified by `tests/test_campaign_window.py` (38 tests with an injected
clock; no test sleeps for the window) and on the practice bench: a
four-call softphone campaign against the practice Asterisk on 127.0.0.2,
planned with a window that ended 27 s later. Calls 1 and 2 completed. Before
call 3 (15 s budget, 13 s left) the campaign stopped: `Campaign:
AUTHORIZATION_LAPSED (2 of 4 step(s) completed; exit 1)`. The run's capture
holds 1050 packets, 531 of them to 127.0.0.2. The last packet to 127.0.0.2
is the unregistration of call 2 at 21:33:42.146; the stop was recorded at
21:33:43.177 and the window ended at 21:33:57. No packet in either direction
follows the stop, and the capture holds 4 INVITE packets (two calls, each
INVITE sent once and once again with credentials). No step was running at
the stop, so there was no teardown to observe after it.

### 9: campaign artifacts are private

`campaign run` now works with umask 077, creates a new run root with mode
0700, and sets every directory of the run to 0700 and every file to 0600 at
the end. On the practice bench (tcpdump and PJSUA run inside the practice
namespace), all 24 to 32 paths of each run were 0700 or 0600, `capture.pcap`
included, and `diagnose`, `ladder`, `evidence`, `summary` and the dress
rehearsals read the runs as before. An existing `runs/` directory keeps its
mode: keep the engagement directory 0700 (as `journal init` creates it).

### 10: campaign signaling networks have a breadth rule

`authorization.networks` is refused when a network contains the unspecified
address (`0.0.0.0/0`, `::/0`, `0.0.0.0/8`, ...), when its IPv4 networks hold
more than 16,777,216 addresses together (one `/8`), or its IPv6 networks more
than one `/64`. Both the planner and the runtime validator of the frozen
plan apply it. The cap is the widest shape the shipped manifests use (the
isolated self-test authorizes `127.0.0.0/8`), so it stops "any", not a
careless range; `scope check` still warns above a `/16`.

## Guardrails verified sound, and how

| Guardrail | How it was checked |
|---|---|
| Guided call, matrix and checks refuse unless the profile is approved, inside its window, and `target.host` is itself a literal approved address | Code: `call.gate` (`lib/sippycup_workbench/call.py`), `checks/runner.py`, matrix delegates to the call gate; experiment: probes with integer, octal, mapped-IPv6, name, and zone-id hosts were all refused for traffic. |
| The window must cover the latest possible end of the call, and it is re-checked before the preflight and before the call | Code: `gate(..., planned_seconds)`, `recheck("preflight")`, `recheck("call")`. Checks re-run `rehearse` before each request (`lapsed()`). |
| The OPTIONS preflight and the security checks send only to the literal | Code: both use a connected socket to the literal (`options.py`, `checks/sip.py`). A far-end Contact or Record-Route only changes header text; every datagram still goes to the literal. |
| PJSUA does not follow 3xx, does not place a transferred call, and uses no STUN, ICE or TURN | Experiment (302 and REFER above). Config: `--accept-redirect=0`, `--max-calls=1`, no `--stun-srv`, no `--use-ice`. |
| TLS verification cannot be turned off for calls, and the reviewed name never reaches DNS | Code: `build_config` always writes `--tls-verify-server`; the name is pinned in a private mount namespace (`hosts: files`). `--tls-unverified` exists only on `preflight` and is reported as UNVERIFIED. |
| `--practice` reaches only loopback | Experiment: from `./bin/sippycup --practice -- python3 ...`, sending to 192.0.2.1, 10.0.2.2, 1.1.1.1 and `::ffff:192.0.2.1` failed with "Network is unreachable"; the namespace has only `lo` and no routes. `--practice` with `--admin` or `--isolated` is refused. The launcher requires the container to be running, labelled `practice`, and in network mode `none`. |
| A `LOCAL-PRACTICE-ONLY` profile cannot cover a routable address | Code: `summary_practice.is_practice_approval` requires the target and every approved address to be loopback other than 127.0.0.1. The label grants nothing by itself: such a profile goes through the same `rehearse` gate as any other. |
| The password never reaches argv, artifacts, logs, or pcaps | Experiment: a full dress rehearsal (12/12 PASS) with a sampler that read every process's `cmdline` and `environ` every 0.1 s (759 samples). The password was in no `cmdline`. A byte search of all 169 rehearsal files (pcaps included), `/tmp` and `/dev/shm` found it nowhere. PJSUA gets the password only in a mode-0600 config file in a 0700 directory under `/dev/shm`, removed as soon as PJSUA reads it. `--secret-file` is opened with `O_NOFOLLOW`, must be a regular file beneath `work/`, and must be mode 0600. |
| Frozen campaign plans cannot drift from the reviewed manifest | Code: `verify_frozen_plan` recompiles the manifest bytes (read once) with the frozen DNS pins and CA digests and compares byte for byte. |
| A crashed or killed terminal client does not leave PJSUA sending past its bounds | Experiment: SIGKILL of the podman client 12 s into a 20 s practice call. The container ran on, ended the call at its duration with BYE and unregistration, and wrote complete evidence. If the container's main process dies, the namespace dies with it. The campaign softphone runner also asks for `PR_SET_PDEATHSIG`. |
| MCP live preflight is bound to the profile | Code: `live_tools._plan_bindings` requires exactly one plan destination, which must be in the profile's approved addresses and match its port and transport; the container runs with `--cap-drop=ALL`, read-only, with a pids limit. |

## Residual risks the operator must manage by procedure

1. **A campaign manifest without a window is not bound (finding 5, fixed
   for generated manifests).** A manifest from `scope compile` carries the
   window, and `campaign run` enforces it and reads `scope.yaml` beside the
   manifest for a revocation. A hand-written manifest with no
   `authorization.approval` and no scope file beside it still runs, with a
   `WARNING`. For such a plan, check the written window by hand. A
   revocation reaches a campaign through `scope.yaml` only: set
   `authorization.status: revoked` there, or press Ctrl-C. It takes effect
   before the next step, not inside a running step. The MCP one-call tool
   applies the same gate to `scope.yaml` beside its reviewed manifest
   (bn-wcx2).
2. **Ceilings are per process (finding 6).** Run one sender at a time, from one
   terminal, and do not repeat `call` beyond what the owner approved:
   `max_calls` limits one matrix or campaign run, not the engagement. Within
   one `matrix run`, the profiles of one approval (the per-target profiles of
   one scope) share one `max_calls` (bn-28vz); separate invocations are not
   added up. Recommended fix: a per-approval send ledger under `work/` with an
   exclusive lock.
3. **Unbound senders (finding 7).** `shell` and `-- COMMAND` send wherever they
   are told, and so does `preflight HOST` without `--profile`. Each prints a
   `Scope: UNBOUND` line. Use `preflight --profile PROFILE` and
   `media send --profile PROFILE`, set `SIPPYCUP_REQUIRE_PROFILE=1` for the
   engagement, and use `shell` and `--` only with addresses copied from the
   approved profile.
4. **Detection, not prevention (finding 8).** With a hostile or misconfigured far
   end, a few packets (one ACK, up to about 5 RTP/RTCP packets) can reach an
   address the far end named before Sippycup stops. A host name in a far-end
   URI or SDP causes one DNS lookup first. The run says so
   (`signaling-outside-scope` or `media-outside-scope`). Report it to the owner
   as an integrity exception. The robust fix is an nftables egress allowlist
   inside the call's private network namespace.
5. **The window uses the wall clock.** Changing the host clock moves the window.
   Keep NTP on and do not change the time during an engagement.
6. **Editing the profile during a run has no effect.** `call` and `matrix` keep the
   profile they loaded. To stop at once, press Ctrl-C (SIGINT), send SIGTERM,
   or close the terminal (now SIGHUP). After a killed client, run
   `podman ps` to find the container still running and stop it with
   `podman stop`.
7. **The private network namespace is not an egress filter.** `--isolated`,
   `call`, `checks` and `matrix` run with rootless Podman's default network
   (pasta): outbound traffic is NAT'd through the host to any address, and
   only inbound traffic is closed.
8. **Secrets in process environments.** `--secret-env` passes the value by name.
   It is never in argv, but it is in the environment of the `podman` client,
   `conmon`, the container's `tini`, and the Python command, which other
   processes of the same user can read. On a shared host prefer
   `--secret-file`.
9. **Run roots made before this fix keep their mode (finding 9, fixed).**
   New campaign runs are 0700/0600. A `runs/` directory that already exists
   is not changed: keep the engagement directory mode 0700 (as `journal
   init` creates it).
10. **A far end that advertises a private address in its SDP now stops the
    call.** An SBC behind NAT often writes its private address (for example
    10.x) in `c=`. PJSUA sends RTP there until it switches to the address RTP
    comes from. Before this audit the call passed. Now it ends
    `media-outside-scope`, because those packets really did go to an
    unapproved address that may be routable from the assessor's network.
    Ask the owner to correct the SDP or to approve that address as a media
    network.
11. **A campaign continues after a scope stop.** In the campaign softphone
    runner, `signaling_outside_scope` and `media_peer_outside_scope` fail
    the step, but the campaign goes on to the next step unless
    `stopConditions` trip. Set `consecutiveFailures: 1`, or watch the run and
    stop it. Recommended fix (owner: campaign code): treat scope errors as
    fatal for the whole campaign, as `srtp-policy` and `matrix` do.

## How to repeat the experiments

The far-end probe is `tools/safety_audit_farend_probe.py`. It is not a
shipped command; see its docstring.

```sh
cp tools/safety_audit_farend_probe.py work/
./bin/sippycup --isolated -- python3 /work/safety_audit_farend_probe.py rr_contact
#   or contact_only, media_level_c, session_level_c, rtcp_attr, reinvite, redirect, refer
./bin/sippycup practice-target rehearsal     # full dress rehearsal (secrets sweep)
```

The stop experiment ran a practice call
(`./bin/sippycup --practice call work/practice/target-profile.yaml --dial echo
--username practice --secret-file work/practice/account.password --duration 20`)
under `script`. It sent SIGHUP or SIGKILL to the `podman` client 12 s in, and
then read the run's capture with tshark for BYE and `REGISTER Expires: 0`. The
secrets sampler read `/proc/*/cmdline` and `/proc/*/environ` every 0.1 s during
the rehearsal.

The unit tests that pin the fixes are `tests/test_scope_watch.py`,
`tests/test_safety_audit.py`, `tests/test_guided_call.py` (SignalTests),
`tests/test_runtime.py` (RuntimeSignalTests), `tests/test_scope_binding.py`
and, for findings 5, 9 and 10, `tests/test_campaign_window.py`.
