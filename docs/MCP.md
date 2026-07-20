# Agent access with MCP

Sippycup includes an optional local Model Context Protocol server for agent
discovery and safe offline analysis:

```sh
./bin/sippycup mcp
```

Configure an stdio-capable MCP client with the absolute path to
`bin/sippycup` and the single argument `mcp`. The launcher selects Podman,
nerdctl, or Docker and starts the prepared image with networking disabled, all
capabilities dropped, a read-only root filesystem, and `work/` mounted
read-only.

Build the image and verify the server before adding it to an agent:

```sh
make build
./bin/sippycup mcp --self-test
```

## Claude Code

From the Sippycup checkout, add the server at Claude Code's private,
project-local scope:

```sh
claude mcp add --transport stdio --scope local sippycup \
  -- "$(pwd)/bin/sippycup" mcp
```

The `local` scope is intentional: it makes the server available only to you in
this checkout and does not write a machine-specific absolute path to the
repository. Use `--scope user` instead if you want Sippycup available from
every project on your machine.

Verify or remove the registration with:

```sh
claude mcp get sippycup
claude mcp list
claude mcp remove --scope local sippycup
```

Inside Claude Code, `/mcp` shows the connection and its tools. Restart an
already-running session if it does not notice the new registration.

## Codex

From the Sippycup checkout, add the stdio server:

```sh
codex mcp add sippycup -- "$(pwd)/bin/sippycup" mcp
```

Codex stores this registration in its normal user configuration. The Codex
CLI, IDE extension, and ChatGPT desktop app on the same Codex host share that
MCP configuration.

Verify or remove the registration with:

```sh
codex mcp get sippycup
codex mcp list
codex mcp remove sippycup
```

Inside the Codex TUI, `/mcp` shows the active server and tools. Restart an
already-running client after adding or changing the registration.

Client references: [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp)
and [Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp).

## Other stdio clients

Most desktop and CLI clients accept this configuration shape:

```json
{
  "mcpServers": {
    "sippycup": {
      "command": "/absolute/path/to/sippycup/bin/sippycup",
      "args": ["mcp"]
    }
  }
}
```

Use the checkout's actual absolute path. No target, credential, container
capability, or environment variable belongs in the client configuration.

These registrations start the offline `mcp` surface only. Do not replace the
argument with `mcp-live`: that surface requires operator-owned trust and state,
externally issued capability grants, and the separate setup in
[MCP-LIVE.md](MCP-LIVE.md).

The MCP SDK is contained in the image; no host Python package is required.
Developers running `bin/sippycup-mcp` directly need Python and
`mcp==1.27.2`.

Start by reading `sippycup://catalog`. It lists the allowlisted public
documents and schemas. MCP's normal `tools/list` response describes the typed
offline tools. Every tool path is relative to `work/`; absolute paths,
traversal, and symlinks are rejected.

The catalog also publishes `mcp-live-capability-v1`, the verifier contract for
later approval-bound tools. Publishing that schema does not enable traffic:
the current MCP server cannot mint grants, consume grants, or execute live
actions. The verification design and trust assumptions are documented in
[MCP-SECURITY.md](MCP-SECURITY.md).

The separately launched, capability-backed preparation/preflight surface is
documented in [MCP-LIVE.md](MCP-LIVE.md). It uses the same top-level
`./bin/sippycup` entrypoint but is not part of this offline server.

Useful checks:

```sh
./bin/sippycup mcp --self-test
./bin/sippycup mcp --exit-gate
```

Both checks are offline. The exit gate uses a real MCP client session to verify
initialization, discovery, resource reads, the exact tool allowlist, structured
tool calls, traversal rejection, and absence of packet capabilities.

MCP deliberately cannot authorize a target or send traffic. Live actions still
use the normal reviewed Sippycup workflow and remain unavailable to agents until
the separate approval-bound MCP phase passes its exit gate. See
[MCP-SECURITY.md](MCP-SECURITY.md) for the complete boundary.

If startup fails, run `./bin/sippycup mcp --self-test` in a terminal. A missing
image means `make build` has not completed. A runtime-selection error means none
of Podman, nerdctl, or Docker is available; set `SIPPYCUP_RUNTIME` to one
compatible executable. Direct host execution is for development only and
requires `mcp==1.27.2`; the normal container path carries its own dependency.
