# Unified command-line interface

`./bin/sippycup` is the public entrypoint for every operator workflow. Its
command registry is loaded and validated before dispatch, and the same records
drive routing, help, activity labels, and machine-readable discovery.

```sh
./bin/sippycup --help
./bin/sippycup help torture
./bin/sippycup commands
./bin/sippycup commands --format json
./bin/sippycup version
```

`./bin/sippycup go [DIR]` is the guided operator cockpit: a host-side
dashboard and checklist that starts other public commands only after a
confirmation panel (typed approval token for LIVE actions). It sends no traffic
itself. Its `--plain` and `--format json` modes are read-only; see
[COCKPIT.md](COCKPIT.md).

These discovery commands do not resolve a target, start a container, or make a
network connection. The JSON output follows
`schemas/commands-v1.schema.json` and always reports `networkActivity: false`.

## Execution boundaries

The registry makes execution location explicit:

- Workbench and first-party analysis commands run directly from the checkout,
  so host paths retain their ordinary meaning.
- Host workflows such as scoped capture and reporting retain their existing
  wrappers and privilege boundaries.
- Preflight and the closed-loop self-test run in the prepared image. Self-test
  always selects the isolated network.
- `call` always runs in the prepared image with a private network namespace,
  where rootless capture works, and rewrites `work/...` paths to `/work/...`.
  It rejects `--admin`. `call --dry-run` and `call --help` run from the
  checkout without a container.
- `checks run` follows the same rules as `call`: a private container, `--admin`
  rejected, and `--practice` composes. `checks list`, `explain`, and `plan` run
  from the checkout and are network-free. See `SECURITY-CHECKS.md`.
- Commands that take `--secret-env NAME` (or `REF=NAME`) receive only that
  variable in the container, forwarded with the runtime's name-only
  `--env NAME` form so the value never appears in a command line.
- `doctor` inspects the prepared image by default. `doctor --host` is the
  explicit local inventory.
- `mcp` runs in a fixed offline container: no network, no Linux capabilities,
  read-only root and work files, and no `--isolated`/`--admin` broadening.
- Adding `--isolated` or `--admin` before a packaged first-party command runs
  that command in the image with the requested boundary.
- `--practice` runs container commands in the network namespace of the
  running local practice target (loopback only) with `NET_RAW`, and routes
  packaged commands into the image like `--isolated`. It fails closed when
  the target is not up and cannot be combined with `--isolated` or
  `--admin`; `mcp`, `mcp-live`, `selftest`, and host-side commands reject it.
  See `PRACTICE-TARGET.md`.

Examples:

```sh
./bin/sippycup capture --target staging.example.invalid --dry-run
./bin/sippycup preflight staging.example.invalid 5060 udp --dry-run
./bin/sippycup torture exit-gate
./bin/sippycup --isolated --admin chaos capabilities
./bin/sippycup selftest /work/selftest.pcap
./bin/sippycup call work/engagement/profile.yaml --dial 1001 --dry-run
./bin/sippycup checks plan work/engagement/profile.yaml
./bin/sippycup webrtc validate examples/webrtc/offline-scenario.json
./bin/sippycup webrtc signaling-self-test
```

The guided optional WebRTC path, including failure recovery and the live
admission boundary, is documented in `docs/WEBRTC-WORKFLOW.md`.

An activity label describes what a command *can* do; it is never target
authorization. `offline` help or planning does not make a later execution
authorized.

## Preflight

`preflight HOST [PORT] [udp|tcp|tls]` resolves HOST, checks TCP reachability
for TCP and TLS, prints an informational `openssl s_client` certificate
summary for TLS, and sends one SIP OPTIONS transaction with the in-image
`sippycup-options` client. Over UDP it sends at most two datagrams.

| Option | Meaning |
| --- | --- |
| `--expect-status N` | Require this final status (default: any 2xx) |
| `--expect-class C` | Require `2xx`, `3xx`, `4xx`, `5xx`, `6xx`, or `any` |
| `--tls-ca /work/PATH` | Also trust this PEM CA file; it must be under `/work` |
| `--tls-server-name NAME` | Verify the certificate for NAME and send it as SNI; packets still go only to HOST |
| `--tls-unverified` | Skip certificate verification; always reported as `UNVERIFIED`, never the default |
| `--dry-run` | Print the bounded plan; no resolution or traffic |

TLS verifies by default, against `--tls-server-name` or else HOST. The
removed `--tls-ignore-cert-failure` is rejected with a usage error. The first
failing stage decides the exit code:

| Exit | Meaning |
| --- | --- |
| 0 | A final response met the expectation |
| 1 | A final response arrived but did not meet the expectation |
| 2 | Usage error; nothing was sent |
| 3 | No valid final response before the deadline (UDP silence or ICMP port unreachable, TCP connect timeout, closed or malformed reply) |
| 4 | Name resolution failed, connection refused, or host/network unreachable |
| 5 | TLS handshake or certificate verification failed |

```sh
./bin/sippycup preflight staging.example.invalid 5060 udp --expect-class any
./bin/sippycup --practice preflight 127.0.0.2 5061 tls \
  --tls-ca /work/practice/ca.crt --tls-server-name sippycup-practice
```

The in-image client is also available as an advanced tool with the same exit
codes and a machine-readable result:

```sh
./bin/sippycup -- sippycup-options 192.0.2.10 5060 udp --format json
```

`sippycup-options HOST PORT TRANSPORT [--timeout S] [--expect-status N |
--expect-class C] [--tls-server-name NAME] [--tls-ca-file PATH] [--insecure]
[--format text|json]` accepts an IP literal (IPv6 with or without brackets)
or a name, which it resolves once. It is not a registry command.

## Third-party tools and the shell

Use `shell` for an interactive toolbox or `--` for one arbitrary in-image
command:

```sh
./bin/sippycup shell
./bin/sippycup -- tshark -r /work/selftest.pcap
```

The escape hatch intentionally exposes the container toolbox and is not part
of the stable first-party command contract.

## Compatibility

The sibling scripts and installed `sippycup-*` binaries remain compatibility
entrypoints throughout the 1.x line. They are implementation interfaces:
existing automation may continue using them, but new documentation and
examples use the unified entrypoint. Compatibility shims preserve argument
boundaries, exit status, signals, and machine-readable stdout without adding
deprecation text.

Campaign runners, loopback fixtures, container preflight/report helpers,
runtime selection, and smoke programs are internal. They do not appear in
global help and may change independently of the public command registry.

## Engagement report

`./bin/sippycup summary DIR` is a workbench command: it runs from the checkout
on the host (and in the image under `--isolated` or `--practice`), reads only
recorded artifacts, and writes the owner report to `DIR/report/`. Exit status
is 0 when written, 1 when written with integrity exceptions, 2 for usage
errors, and 3 when the privacy lint refused to write anything. See
`ENGAGEMENT-REPORT.md`.

## Call ladder

`./bin/sippycup ladder RUN_DIR|CAPTURE [--format text|html|json] [--output FILE]
[--call-id-index N] [--width N] [--approve NET] [--show-addresses]` draws a
redacted SIP and media sequence diagram from recorded evidence. It is offline
(`direct` mode: host, or the image under `--isolated`/`--practice`). Exit
status is 0 when drawn, 2 for bad arguments or an unusable path, 3 for an
unreadable capture, 4 when there is nothing to draw (no SIP, TLS, or RTP), and
5 for an internal error or a privacy lint refusal. See `LADDER.md`.


## Dress rehearsal

`./bin/sippycup practice-target rehearsal` walks the whole owner-facing chain
against the local practice target with the public commands, in the order of a
real engagement: `journal init`, `scope init`, the cockpit's practice call,
`scope check` and `scope compile`, `rehearse`, `--practice preflight` over UDP
and verified TLS, the guided `call` (and one with `--dtmf`), `campaign plan`
and `campaign run`, `checks plan` and `checks run`, the cockpit's evidence
actions, and `summary --forbid-file`. After each stage it requires
`go --plain` and `go --format json` to agree with each other and with the
stage just finished. It prints PASS or FAIL per stage with the exact commands,
exits 0 only when every stage passed (1 on a failure, 2 when it could not
start), keeps the evidence in `work/practice/rehearsals/dress-STAMP/`, and
starts and stops the practice target only when it was down. `--list` prints
the stages and sends nothing. `make dress-rehearsal` runs it. The approved
checks include `srtp-policy`, and a last stage shows the media-scope safety
stop once in a throwaway engagement (`DIR-stop`). `--proxy` (`make
dress-rehearsal-proxy`) writes the scope answers in the proxy shape:
signaling to the practice proxy `127.0.0.3` (407 challenges, realm and
certificate name `sippycup-proxy`), media from `127.0.0.2`. See
`PRACTICE-TARGET.md`.

## Bash completion

Source the completion from a checkout:

```sh
source completions/sippycup.bash
```

Top-level command names are read from the live JSON registry, so completion
cannot drift from `sippycup --help`.
