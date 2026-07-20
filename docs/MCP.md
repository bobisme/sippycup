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

Most desktop and CLI clients use this configuration shape:

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
