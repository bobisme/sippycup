# Capability-backed MCP preparation and preflight

Sippycup's live MCP surface is a separate server and container boundary:

```sh
./bin/sippycup mcp-live
```

It exposes `prepare_assessment` and `preflight_target` by default. The first verifies
an externally signed prepare grant and freezes the exact profile and reviewed
plan into a private immutable snapshot without traffic. The second consumes a
separate preflight grant and sends exactly one SIP OPTIONS transaction to the
single literal signaling destination bound by the grant, profile, and plan.

The implemented `execute_one_call` tool remains disabled by default until the
live MCP exit gate is complete. An operator can enable it for a controlled
local gate with `SIPPYCUP_MCP_LIVE_ENABLE_ONE_CALL=1`. Enabling it adds only
`NET_RAW` inside the isolated bridge so the fixed helper can capture evidence;
`NET_ADMIN` remains absent.

The original `./bin/sippycup mcp` remains offline and cannot access this
surface.

## Operator-owned setup

The operator, not the MCP client or Sippycup server, owns grant issuance. Keep
the issuer's private key outside the Sippycup checkout, container, MCP client
configuration, assessment inputs, and state directory. Place only public keys
in an owner-private trust directory:

```text
/operator/sippycup-trust/
├── trust.json
└── quad-2026.pem
```

`trust.json` is strict:

```json
{
  "apiVersion": "sippycup.dev/mcp-live-trust/v1",
  "keys": [
    {
      "keyId": "quad-2026",
      "issuer": "quad-security",
      "publicKey": "quad-2026.pem"
    }
  ]
}
```

Create an owner-private state root with two empty subdirectories:

```sh
install -d -m 0700 /operator/sippycup-live-state
install -d -m 0700 /operator/sippycup-live-state/audit
install -d -m 0700 /operator/sippycup-live-state/snapshots
install -d -m 0700 /operator/sippycup-live-state/evidence
```

Then configure the launcher:

```sh
export SIPPYCUP_MCP_LIVE_TRUST_ROOT=/operator/sippycup-trust
export SIPPYCUP_MCP_LIVE_STATE_ROOT=/operator/sippycup-live-state
export SIPPYCUP_MCP_LIVE_CLIENT_ID=trusted-launcher:alice
./bin/sippycup mcp-live --check-config
```

The command uses Podman, nerdctl, or Docker through the normal runtime
selector. It mounts `work/` read-only as the input root, mounts the public trust
root read-only, mounts only the private state root read-write, drops all Linux
capabilities, uses a read-only container filesystem, and places the process in
an isolated bridge network. The fixed adapter is the only exposed operation
that uses that network.

An MCP client configuration uses the absolute path to `bin/sippycup`, argument
`mcp-live`, and those three environment variables. Treat the ability to alter
that client configuration as privileged. With stdio, the configured client ID
is an audit binding rather than cryptographic proof of identity; the signed
grant remains bearer authority.

## Inputs and results

The three tool paths are relative to `work/`:

- the Ed25519 capability envelope;
- the approved target profile;
- the reviewed frozen campaign plan.

Every input is opened beneath a fixed directory with a no-symlink descriptor
walk and hashed from frozen bytes. The plan must validate under the normal
campaign runtime, the target profile must currently rehearse as ready, their
single signaling tuple must match exactly, and all seven traffic ceilings must
fit the signed grant.

Preparation writes mode-0400 copies of the frozen profile and plan beneath a
mode-0700 content-addressed snapshot. It returns hashes, literal targets,
ceilings, expiry, and an audit reference—never the capability or its signature.

Preflight atomically consumes the nonce before calling the fixed SIP OPTIONS
adapter. Invalid, expired, mismatched, or replayed grants report
`networkActivity: false` and never invoke the adapter. A completed attempt
reports `networkActivity: true` even if the destination is unreachable, because
one bounded transaction was attempted.

When explicitly enabled, one-call additionally requires the exact reviewed
manifest whose SHA-256 is already bound by the frozen plan. It rejects
credentials, multiple steps, non-call cases, disabled capture, calls/CPS/
concurrency other than one, duration above 60 seconds, more than 2,000 packets,
more than 2 MiB, or more than 200 packets per second. Its grant binds the
signaling tuple and exact RTP port range. A fixed subprocess helper performs
capture, one OPTIONS preflight, the call, watchdog enforcement, process-group
cleanup, payload stripping, reporting, and evidence-manifest creation. The MCP
result contains only hashes and a bounded receipt.

The fixed helper has a 130-second outer deadline and is killed as a process
group on timeout. Server/container termination is the emergency stop during
the pre-exit-gate phase. Client-cancellation propagation and the local
packet-level gate still need to pass before one-call is enabled by default.

This surface never exposes arbitrary RTP, scans, arbitrary messages, arbitrary
commands, credential testing, campaigns, or load.

The current target restriction is enforced in the verifier and fixed adapter,
not by a per-grant kernel egress ACL. Run this opt-in surface on a dedicated
assessment host or behind an operator-controlled firewall. A controller-owned
literal-endpoint egress layer remains a requirement for the live execution exit
gate; the bridge network is containment, not authorization.
