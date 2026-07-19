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
- `doctor` inspects the prepared image by default. `doctor --host` is the
  explicit local inventory.
- Adding `--isolated` or `--admin` before a packaged first-party command runs
  that command in the image with the requested boundary.

Examples:

```sh
./bin/sippycup capture --target staging.example.invalid --dry-run
./bin/sippycup preflight staging.example.invalid 5060 udp --dry-run
./bin/sippycup torture exit-gate
./bin/sippycup --isolated --admin chaos capabilities
./bin/sippycup selftest /work/selftest.pcap
```

An activity label describes what a command *can* do; it is never target
authorization. `offline` help or planning does not make a later execution
authorized.

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

## Bash completion

Source the completion from a checkout:

```sh
source completions/sippycup.bash
```

Top-level command names are read from the live JSON registry, so completion
cannot drift from `sippycup --help`.
