# Safe operator workbench

The workbench is the network-free front door for preparing and interpreting a
Ferivox assessment. Profile preparation commands run directly from the
repository. `doctor` runs in the built image by default so it checks the
environment that will perform the assessment.

## Environment diagnosis

```sh
./bin/sippycup doctor
./bin/sippycup doctor --format json
```

Doctor inventories essential tools, the independent PJSUA/coturn toolset,
optional analyzers, work-directory access, and effective `NET_RAW` and
`NET_ADMIN` capabilities. Version probes use known help/version flags only.
They do not resolve names, bind test listeners, open target sockets, or
capture packets.

To diagnose the host itself instead, opt in explicitly:

```sh
./bin/sippycup doctor --host
```

That result may legitimately report missing SIP utilities or packet-capture
capabilities; they do not need to be installed locally when the image doctor
is ready.

An absent `NET_RAW` capability is guidance rather than permission to use
`--privileged`. Prefer the project launcher or a normally authorized host
capture.

## Pending target profile

Create a profile before Quad supplies the final details:

```sh
./bin/sippycup init config/ferivox-staging.yaml
```

The generated profile conforms to
`schemas/target-profile-v1.schema.json` and starts with:

- `authorization.status: pending`;
- an empty approval identifier and validity window;
- no approved IP addresses;
- one call, one concurrent call, one call per second, and 120 seconds;
- every conditional ICE, TURN, SRTP, DTLS-SRTP, and WebRTC feature disabled.

The profile contains no credentials. Do not add SIP passwords or private keys
to it.

Before a profile can become ready, copy Quad's approval identifier and exact
validity window into it, add every literal approved staging address, and
change `status` to `approved`. A benchmark or an informal capacity statement
is not an approval identifier or a traffic ceiling.

## Rehearsal

```sh
./bin/sippycup rehearse config/ferivox-staging.yaml
```

Rehearsal parses and validates the profile without DNS resolution or network
traffic. It rejects missing or expired approval, absent literal address pins,
invalid ports and transports, unbounded or contradictory limits, unsafe
capture interfaces, and inconsistent feature selections.

Exit status is zero only when the plan is ready. JSON output has the same
decision:

```sh
./bin/sippycup rehearse config/ferivox-staging.yaml --format json
```

## Guided one-call plan

```sh
./bin/sippycup one-call config/ferivox-staging.yaml
```

This command composes the exact operator sequence:

1. preview the target-scoped capture;
2. start the capture;
3. send the single OPTIONS preflight;
4. place one manual softphone call;
5. stop capture;
6. generate the existing offline report;
7. run bounded triage.

It prints `BLOCKED` while rehearsal fails and always reports that it sent no
packets. The current one-call planner also requires `target.host` itself to be
one of the approved literal addresses; this prevents a reviewed plan from
later following a changed DNS answer. Hostname/SNI pinning needs a separate
reviewed transport feature rather than an implicit lookup. Automated
execution remains a separate exit-gated task requiring Quad's live staging
approval.

## Capture triage and explanations

```sh
./bin/sippycup triage work/selftest.pcap
./bin/sippycup explain capture.media_present
```

Triage accepts a readable capture up to 512 MiB and runs `capinfos` plus one
bounded TShark protocol pass. It reports packet, byte, duration, SIP, SDP,
RTP, RTCP, TLS, and STUN counts. Its privacy inventory records only whether
authorization material and call identifiers were observed; it never prints
their values. The existing assertion, media, privacy-lint, behavior-diff, and
evidence-pack tools remain authoritative for their richer domains.

An unknown media result is not proof that media was absent. Encryption,
dynamic ports, truncation, or dissector classification can make RTP
unrecognizable. `explain` preserves that uncertainty in operator guidance.

All commands support stable JSON where applicable.

## Assessment journal

The host-side workbench also provides `journal init`, `journal add`, `journal
verify`, and `journal render`. These commands never resolve names or contact a
target. They maintain the human engagement record alongside the campaign
executor's machine evidence and produce separate internal and public report
scaffolds. See `ASSESSMENT-WORKFLOW.md`.

## Engagement advisor

Ask Sippycup what is ready and what safe preparation remains:

```sh
./bin/sippycup status work/ferivox-assessment
./bin/sippycup status work/ferivox-assessment --format json
```

Status verifies the journal hash chain, rehearses the ignored target profile,
runs the local torture technical gate, validates any owner defaults review,
and inventories campaign results, evidence manifests, and privacy status. It
returns ordered next actions as argument arrays.

Every recommended command is network-free. Status may recommend initializing
records, completing human approval, rehearsing, rendering the one-call plan,
building evidence manifests, running privacy lint, or refreshing an internal
report. It never recommends or invokes `campaign execute`, a live torture
runner, a scanner, or a target command. Even a completely ready status is
named `ready-for-human-review`, not authorized or running.

## Container runtimes

`bin/container-runtime` implements a single selection contract:

1. `SIPPYCUP_RUNTIME`, when explicitly configured;
2. Podman;
3. nerdctl backed by containerd;
4. Docker.

The launcher passes arguments as an array and does not evaluate runtime
strings. Runtime overrides cannot contain arguments. Capability, device,
volume, host-network, and isolated-network flags use the common CLI surface
supported by these runtimes.

Podman on Linux remains the reference environment for rootless isolation and
the full chaos exit gate. Docker Desktop host networking can differ from a
native Linux host; Sippycup warns rather than changing the target or network
mode behind the operator's back.
