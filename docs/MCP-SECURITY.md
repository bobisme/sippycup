# MCP security contract

Sippycup's first MCP surface is a local, stdio-only, offline control plane. It
helps an agent discover the toolbox and invoke a small set of read-only
workflows. It is not an authorization system and it cannot initiate target
traffic.

## Trust boundaries

The MCP client launches the server and can see returned data. The server runs in
a separate container with no network, all Linux capabilities dropped, a
read-only root filesystem, and the project `work/` directory mounted read-only.
The client and its operator remain responsible for protecting results marked
`internal`.

Every caller path must be relative to the fixed work root. Canonical containment
is checked and symlink traversal is rejected. Public resources come from a
compiled allowlist; there is no arbitrary file resource.

## Phase 1 allowlist

Resources include the command registry, this security contract, selected public
documentation, and selected public schemas. Tools include sandbox inspection,
doctor, target rehearsal, redacted engagement status, capture triage, campaign
and envelope planning, evidence lint and pack verification, and the technical
torture exit gate.

All tool results use `sippycup.dev/mcp-result/v1`, declare
`networkActivity: false`, carry a sensitivity label, redact known secret fields,
and have a one MiB serialized-output ceiling. Fixed helper processes use argv
arrays without a shell, a deterministic environment, output file limits,
deadlines, a dedicated process group, and kill-on-timeout cleanup. Calls have a
small concurrency ceiling.

## Explicit exclusions

The server does not expose:

- a shell, arbitrary executable, arbitrary argv, or advanced `-- COMMAND`;
- live preflight, SIP calls, RTP sending, campaigns, chaos, credential testing,
  scanners, packet crafting, fuzz execution, or load;
- an operation that creates, approves, extends, or revokes target
  authorization;
- assessment journals, arbitrary repository files, raw capture contents,
  credential providers, private keys, environment variables, or unrestricted
  run artifacts;
- HTTP/SSE transport or a listening socket.

Planning a campaign accepts literal target addresses only. Hostname resolution
is rejected because DNS would violate the offline contract.

## Future live tools

Live tools are a separate phase. They require an externally issued,
short-lived capability bound to the exact action, client, literal targets,
reviewed plan digest, expiry, nonce, and hard traffic ceilings. MCP will validate
but never mint that capability. A separate live exit gate must prove zero
packets for invalid grants, cancellation cleanup, ceiling enforcement,
redaction, and evidence integrity before those tools can ship.
