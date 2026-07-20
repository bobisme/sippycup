# sippycup

![Sippycup voice-network assessment toolbox](assets/sippycup-readme-hero.png)

A containerized toolbox for authorized, network-only assessment of SIP/RTP
voice systems. It contains call generators, protocol viewers, packet capture
and replay tools, network impairment tools, TLS scanners, softphone/media
utilities, and programmable packet mutation libraries. Podman is preferred;
nerdctl and Docker are supported fallbacks.

Use it only against the exact staging addresses and credentials covered by
your test authorization. Keep carrier trunks and unrelated networks out of
scope.

## Build and enter

```sh
cd ~/src/sippycup
make build
make smoke
make selftest
make report
./bin/sippycup shell
```

`./bin/sippycup` is the single public entrypoint. Run
`./bin/sippycup --help` for the network-free command index or
`./bin/sippycup commands --format json` for the versioned machine-readable
registry. Running it without a command still opens the shell for compatibility.
See `docs/CLI.md` for execution boundaries, compatibility, and the advanced
third-party-tool escape hatch.

Local agents can use the same entrypoint through the offline MCP server:

```sh
./bin/sippycup mcp
```

This launches a stdio-only server with networking disabled, all capabilities
dropped, a read-only root filesystem, and `work/` mounted read-only. It exposes
only an allowlisted documentation/schema catalog and typed offline tools; it
cannot authorize targets or send traffic. Run `make mcp-exit-gate` after a
build, and see `docs/MCP.md` plus `docs/MCP-SECURITY.md`.

An opt-in, separately sandboxed `./bin/sippycup mcp-live` server adds immutable
artifact preparation and one capability-bound SIP OPTIONS preflight. It
requires an operator-owned public-key trust root, private replay/audit state,
and an externally issued short-lived grant; Sippycup cannot mint one. A
credential-free, capture-backed one-call tool is implemented but disabled by
default pending its live exit gate. Campaigns, arbitrary messages, and load
remain unavailable through MCP. See `docs/MCP-LIVE.md`.

The launcher and Makefile choose `podman`, then `nerdctl`, then `docker`.
Override the choice with the path or name of one compatible executable:

```sh
SIPPYCUP_RUNTIME=docker make build
SIPPYCUP_RUNTIME=docker ./bin/sippycup shell
```

Arguments cannot be embedded in `SIPPYCUP_RUNTIME`. Docker Desktop host
networking is version- and configuration-dependent; the launcher warns on
non-Linux Docker hosts rather than silently rewriting destinations.

For a release candidate on a disposable Linux runner, `make full-gate` adds
the real nine-profile rootless chaos/host-isolation matrix to the ordinary
campaign, oracle, media, UI, learned-pack, torture, smoke, and loopback gates.
The build context excludes runtime captures, local target configuration,
tracker data, VCS data, and host bytecode via `.containerignore`.

`make selftest` completes a closed-loop SIPp call on loopback and writes
`work/selftest.pcap`. It uses the isolated mode so signaling and packet
capture work under a rootless runtime.

The launcher uses the host network so SIP and SDP advertise reachable
addresses. Files written under `/work` appear in `~/src/sippycup/work`.
`NET_RAW` is enabled for capture and raw-packet tools.

Linux does not permit rootless Podman to capture host interfaces merely by
adding the container's namespaced `NET_RAW` capability. There are three
capture options:

- Run `./bin/sippycup --isolated shell` to capture the container's private
  network namespace. This works rootlessly, but NAT may make advertised
  SIP/SDP addresses unsuitable for inbound media.
- Capture on the host with its normal `tcpdump` or Wireshark permissions
  while running the toolbox rootlessly with host networking.
- Run the image through the host's approved rootful Podman setup when both
  host networking and in-container capture are required.

Do not casually add `--privileged`.

## Included tools

| Purpose | Tools |
|---|---|
| SIP calls and diagnostics | SIPp 3.7.7 with PCAP, TLS, and SCTP; checksum-pinned PJSUA 2.17; sipsak; baresip |
| NAT traversal diagnostics | coturn STUN/TURN clients and RFC 5769 checker; PJSUA ICE/TURN |
| SIP security checks | SIPVicious; Nmap SIP NSE scripts |
| Capture and inspection | Wireshark CLI (`tshark`, `dumpcap`, `capinfos`, `editcap`, `mergecap`, `reordercap`, `text2pcap`); tcpdump; sngrep; ngrep |
| Terminal packet UI | Termshark |
| RTP/media production | SIPp PCAP playback; GStreamer; FFmpeg; SoX; baresip |
| Packet construction and fuzzing | Scapy; boofuzz; hping3; socat; netcat (`nc`) |
| Replay and load | tcpreplay; SIPp; iperf3 |
| Network impairment | `tc netem` from iproute2 |
| TLS and exposure | testssl.sh; sslscan; OpenSSL; Nmap |
| Host/network diagnosis | iproute2, conntrack, nftables, ethtool, mtr, traceroute, DNS tools |

SIPVicious includes authentication-testing functionality. Agree on test
accounts and attempt limits before using it; do not point credential testing
at real customer accounts.

## Prepared workflows

Start with the zero-network workbench:

```sh
./bin/sippycup doctor
./bin/sippycup init config/voice-staging.yaml
./bin/sippycup rehearse config/voice-staging.yaml
./bin/sippycup one-call config/voice-staging.yaml
./bin/sippycup triage work/selftest.pcap
```

`doctor` runs inside the prepared image so its answer describes the toolbox
you will actually use, not whichever utilities happen to be installed on the
host. Use `./bin/sippycup doctor --host` only when you explicitly want a
host-side inventory.

`init` deliberately creates a pending profile with no invented addresses or
approval. `rehearse` remains blocked until the profile contains the authorized
service owner's approval identifier, validity window, literal approved
addresses, and finite limits. `one-call` only prints the reviewed sequence; it
never executes its network-active steps. See `docs/WORKBENCH.md`.

Create a private, hash-chained engagement journal before testing:

```sh
./bin/sippycup journal init work/voice-assessment
./bin/sippycup journal add work/voice-assessment \
  --kind hypothesis --summary "Record a bounded, testable security hypothesis"
./bin/sippycup journal verify work/voice-assessment
./bin/sippycup status work/voice-assessment
```

Campaign run directories retain the machine record; the journal retains
authorization changes, hypotheses, observations, findings, decisions, and
evidence links. It can render a confidential internal assessment draft or a
publication outline that deliberately contains none of the private journal
text. `status` verifies these records and recommends only network-free next
steps; it never executes target traffic. See `docs/ASSESSMENT-WORKFLOW.md` for
the end-to-end execution and recordkeeping framework.

Copy `config/target.env.example` to the ignored `config/target.env` when the
staging details arrive. It is a worksheet only; scripts require targets on
their command lines so traffic cannot be sent accidentally from stale
configuration.

Preview a narrowly scoped host capture:

```sh
./bin/sippycup capture --target staging.example.invalid --dry-run
```

Remove `--dry-run` only after replacing the placeholder with an authorized
staging host. The wrapper invokes the host's `sudo tcpdump`, includes all UDP
to the supplied scope so dynamic RTP ports are retained, and records capture
metadata alongside the PCAP.

Run the low-impact network preflight:

```sh
./bin/sippycup preflight staging.example.invalid 5060 udp --dry-run
```

Remove `--dry-run` only after reviewing the target. Live preflight resolves the
address, checks the selected transport, and sends one SIP OPTIONS transaction.
It does not enumerate users, try credentials, or generate load.

Generate an offline report:

```sh
./bin/sippycup report work/selftest.pcap
# Equivalently:
make report CAPTURE=work/selftest.pcap
```

Evaluate a capture against executable call-path expectations:

```sh
./bin/sippycup assert work/selftest.pcap \
  --expect examples/oracle-expectations.yaml
```

Use `--format json` for stable automation output. Exit codes distinguish pass,
assertion failure, malformed expectations, unreadable captures, inconclusive
analysis, and internal/TShark failure. See `docs/oracle-exit-gate.md`.

## Bounded robustness fixtures

The source-generated torture corpus contains finite, bit-exact SIP, SDP, RTP,
RFC 4733, and RTCP cases for later use by the guarded state-aware runner:

```sh
make torture-test
make torture-exit-gate
```

The technical exit gate produces a deterministic offline safety proof and a
separate current-code digest for the service owner's default-limit review.
Neither artifact authorizes live traffic. See `docs/TORTURE-CORPUS.md` for the
corpus, safety boundary, owner-review packet, and validation workflow.

Open the same capture in a terminal UI:

```sh
./bin/sippycup -- termshark -r /work/selftest.pcap
```

See `docs/CALL-CHECKLIST.md` for the details to request and a repeatable
manual-call procedure.

Heavyweight ViSQOL, Zeek, HOMER/HEP, and the independent WebRTC peer are kept
outside the core image. Their scope and admission criteria are documented in
`docs/OPTIONAL-PROFILES.md`. The WebRTC trust boundaries and versioned offline
contracts are in `docs/WEBRTC-THREAT-MODEL.md` and
`docs/WEBRTC-CONTRACTS.md`.

Install and verify the optional independent WebRTC peer when that surface is in
scope:

```sh
./bin/sippycup webrtc build
./bin/sippycup webrtc validate \
  examples/webrtc/offline-scenario.json \
  --result examples/webrtc/offline-result.json
./bin/sippycup webrtc self-test
./bin/sippycup webrtc signaling-self-test
./bin/sippycup webrtc relay-self-test
./bin/sippycup webrtc exit-gate
./bin/sippycup webrtc ice-turn \
  examples/webrtc/ice-turn-policy.json \
  examples/webrtc/ice-turn-observation.clean.json
./bin/sippycup webrtc sdp evaluate \
  examples/webrtc/sdp-policy.json \
  examples/webrtc/sdp-transcript.clean.json
./bin/sippycup webrtc media-security \
  examples/webrtc/dtls-srtp-policy.json \
  examples/webrtc/dtls-srtp-observation.clean.json
./bin/sippycup webrtc call-evidence \
  examples/webrtc/call-policy.json \
  examples/webrtc/call-evidence.clean.json
```

The validator and evidence commands are socket-free. The two self-tests use
loopback only: one places a bounded DTLS-SRTP audio call and the other checks a
fixed browser-style WSS service. Neither can contact an assessment target. See
`docs/WEBRTC-PEER.md`, `docs/WEBRTC-ICE-TURN.md`, `docs/WEBRTC-SDP.md`, and
`docs/WEBRTC-DTLS-SRTP.md`.

The repository also includes deterministic one-second PCMU, PCMA, and G.722
audio canaries for both call directions. Their source generator, packetization,
marker positions, gain steps, silence/clipping thresholds, and reproducibility
commands are documented in `docs/AUDIO-CANARY-ASSETS.md`.

Use `sippycup media send` to preview or send those assets from completed local
and remote SDP snapshots, including standards-correct negotiated RFC 4733
digits and bounded re-INVITE transitions. The safe session format, dry-run
workflow, echo fixture, and timing report are documented in
`docs/MEDIA-SEND.md`.

Admin and WebSocket security scope is independently approval-gated. The
network-free profile compiler and evidence oracle are available through:

```sh
./bin/sippycup web-security plan \
  examples/web-security/offline-profile.json \
  examples/web-security/example-adapter.json
```

See `docs/WEB-SECURITY.md`. The checked-in adapter is an offline example and
does not imply permission to test any deployed service.

Analyze a returned raw codec payload with `sippycup media analyze`. It reports
marker acquisition, synchronized round-trip latency, continuity, clipping,
gain, duration, direction, and silence facts with explicit uncertainty and
typed not-measurable results. See `docs/MEDIA-ANALYZE.md`.

## Voice-edge resilience oracles

Five network-free gates are available while the target is still being
hardened:

```sh
./bin/sippycup resilience isolation demo --calls 64
./bin/sippycup resilience lifecycle simulate --cycles 6000
./bin/sippycup resilience overload demo
./bin/sippycup resilience secure-media demo --profile srtp
./bin/sippycup resilience migration demo --mode strict
```

They detect cross-call media contamination, settled resource leaks, SIP retry
storms and unfair overload behavior, TLS/SRTP downgrade or replay failures,
and unauthorized RTP tuple migration. Synthetic call counts are coverage
fixtures, never target authorization or capacity claims. See
`docs/RESILIENCE-GATES.md`.

## Reproducible campaigns

The versioned campaign workflow turns written scope into a frozen,
independently revalidated plan and a complete capture-to-report run directory:

```sh
./bin/sippycup campaign plan campaign.yaml --resolve voice.test=10.20.30.40 \
  --output plan.json
./bin/sippycup campaign execute plan.json --manifest campaign.yaml \
  --run-root work/runs --interface any
```

Execution is preflight-gated, deadline-bound, signal-safe, and records
structured events without placing credential values in argv. See
`docs/CAMPAIGN-MANIFEST.md` for the schema, secret-source contracts, artifact
layout, and isolated integration self-test.

## Immutable capacity envelopes

Compile a separately reviewed, one-dimensional CPS, concurrency, or media-PPS
ramp without sending traffic:

```sh
./bin/sippycup envelope plan examples/capacity-envelope.yaml \
  --max-calls-per-second 4 --output work/envelope-plan.json
./bin/sippycup envelope run work/envelope-plan.json \
  --manifest examples/capacity-envelope.yaml
```

All intensity, total-call, duration, hold, cooldown, and recovery maxima are
mandatory. CLI flags can only lower them. The current run command is a
deterministic, network-free controller simulator for reviewing timing,
worst-case budgets, and pause/stop precedence. See `docs/ENVELOPE.md`.

Campaign runs also receive a deterministic sensitivity-labeled evidence
manifest. Before sharing any run, use:

```sh
./bin/sippycup evidence lint work/runs/RUN
```

The lint blocks Authorization material, subscriber identifiers, unexpected
networks, decoded audio, oversized or incompletely inspected captures unless
an identity-bound mode-0600 local override explicitly acknowledges them. It
never edits the source PCAP or report. See `docs/EVIDENCE-PRIVACY.md`.

Compare a learned/oracle golden behavior pack against a candidate without
being distracted by regenerated SIP/RTP identifiers, ephemeral ports, frame
numbers, or capture clock origin:

```sh
./bin/sippycup diff evidence/baseline evidence/candidate --format human
```

Codec, endpoint topology, one-way media, response/setup timing, assertion,
and post-BYE changes remain semantic and link back to source frames. JSON,
human, and JUnit views share one versioned result model. See
`docs/GOLDEN-BEHAVIOR-DIFF.md`.

Package a run for workspace-independent offline verification, with optional
external minisign signing, age recipient encryption, and privacy-safe CI
reports:

```sh
./bin/sippycup pack create work/runs/RUN evidence.tar --image-digest sha256:...
./bin/sippycup pack verify evidence.tar --format json
./bin/sippycup pack export-ci evidence.tar ci-results
```

Signing and encryption remain optional; Sippycup never manages keys, and CI
exports include no evidence artifacts unless their paths are selected
explicitly. See `docs/EVIDENCE-PACKS.md`.

## Low-impact starting commands

Set the staging host first:

```sh
export TARGET=staging.example.invalid
```

`staging.example.invalid` is a deliberately non-routable placeholder. Replace
it with the exact authorized staging hostname or address before running a
command.

Check SIP responsiveness and advertised methods:

```sh
./bin/sippycup -- sipsak -vv -s "sip:${TARGET}"
./bin/sippycup -- nmap -sU -p 5060 --script sip-methods "${TARGET}"
./bin/sippycup -- sipvicious_svmap "${TARGET}"
```

Capture signaling and common RTP ranges:

```sh
./bin/sippycup -- tshark -i any \
  -f "port 5060 or port 5061 or udp portrange 10000-20000" \
  -w /work/session.pcapng
```

View SIP call flows:

```sh
./bin/sippycup -- sngrep -d any
```

Run exactly one built-in SIPp UAC call at a low rate:

```sh
./bin/sippycup -- sipp "${TARGET}:5060" -sn uac -m 1 -r 1
```

That built-in scenario will not match every system. Authentication, SIP-TLS,
custom headers, codec negotiation, and expected responses usually require a
project-specific SIPp XML scenario.

Inspect a SIP-TLS listener:

```sh
./bin/sippycup -- testssl "${TARGET}:5061"
./bin/sippycup -- sslscan "${TARGET}:5061"
```

Use the advanced escape hatch—for example,
`./bin/sippycup -- sipp -h`—for the complete interfaces of bundled
third-party tools.

## Packet loss, jitter, and reordering

`tc netem` is installed but `NET_ADMIN` is deliberately withheld by default.
The safest way to grant it is in an isolated container network namespace:

```sh
./bin/sippycup --isolated --admin shell
```

For this isolated administrative mode the launcher also grants `SYS_ADMIN`
inside rootless Podman's user and mount namespaces so the lifecycle can bind
named child network namespaces. The traffic command itself is capability
dropped with `setpriv`.

Run the reproducible host-isolation and all-profile gate on a disposable
runner with `make chaos-exit-gate`; its evidence and environment limits are
documented in `docs/CHAOS-EXIT-GATE.md`.

Using `./bin/sippycup --admin` without `--isolated` combines `NET_ADMIN` with
host networking. In a rootful container, `tc` then controls the host's
interfaces. Use that combination only on a dedicated test VM. Record the
original qdisc, target only the intended traffic, and remove every test
qdisc when finished:

```sh
./bin/sippycup --admin -- tc qdisc show
./bin/sippycup --admin -- tc qdisc del dev DEVICE root
```

For routine work, a separate disposable VM or network namespace acting as an
impairment router is safer than changing the workstation's host interface.

The chaos topology planner turns that recommendation into a reviewable,
no-change artifact. Probe the exact isolated impairment environment, then
freeze the packet path and authorized target filters:

```sh
./bin/sippycup --isolated --admin chaos capabilities \
  --output /work/chaos-capabilities.json

./bin/sippycup chaos topology-plan \
  --capabilities work/chaos-capabilities.json \
  --target 10.20.30.40/32 \
  --direction asymmetric \
  --namespace-prefix voice-lab
```

The default three-namespace router keeps `NET_ADMIN` out of the host network
namespace and shapes ingress and egress on independent interfaces. See
`docs/CHAOS-TOPOLOGY.md` for packet paths, capability decisions, snapshots,
and the separately confirmed `dangerous-host-network` fallback.

Compile one of the seeded, bounded impairment profiles against the reviewed
topology without changing the network:

```sh
./bin/sippycup chaos profile-plan \
  work/topology.json profiles/chaos/jitter.yaml \
  --output work/impairment.json
```

The compiler verifies the frozen target digest and emits structured
target-filtered `tc`/netem command arrays for the later lifecycle owner; it
never executes them. The reviewed clean, delay, jitter, burst-loss, constrained
uplink, reorder, duplicate, MTU, and asymmetric profiles are documented in
`docs/CHAOS-PROFILES.md`.

The lifecycle runner owns the disposable namespaces, pasta uplink, traffic
process group, qdiscs, cleanup, exact post-run snapshot comparison, and paired
PCAP measurements:

```sh
./bin/sippycup --isolated --admin chaos run \
  --report work/chaos-run.json \
  work/topology.json work/impairment.json \
  -- sipp 198.51.100.20:5060 -sn uac -m 1 -r 1
```

See `docs/CHAOS-LIFECYCLE.md` for ownership checks, cancellation ordering,
paired observation syntax, sample minimums, and kernel tolerances.

## Suggested evidence to save

Use the campaign run directory for exact commands, UTC times, addresses,
tool versions, SIPp output, bounded PCAPs, reports, results, and the structured
event timeline. Use the assessment journal for authorization, hypotheses,
observations, decisions, recovery notes, and links to server-side metrics.
Do not rely on shell history or chat transcripts as the assessment record.
