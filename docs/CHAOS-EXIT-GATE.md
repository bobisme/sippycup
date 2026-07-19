# Chaos isolation exit gate

Run the exit gate on a disposable Linux test host or CI runner:

```sh
make chaos-exit-gate IMAGE=localhost/sippycup:latest
```

`bin/chaos-exit-gate [OUTPUT]` refuses an existing output directory. It starts
a rootless Podman container with only the isolated administrative
capabilities and `/dev/net/tun`, mounts the source read-only, and saves:

- raw and canonical host route snapshots before and after;
- host qdisc and link snapshots before and after;
- a continuous host-loopback heartbeat;
- controller route/qdisc snapshots and hashes;
- requested settings, observed ping distributions, and lifecycle cleanup
reports for every file in `profiles/chaos`;
- the read-only capability record used to plan the runs.

SIGINT and SIGTERM are forwarded to the active lifecycle, which stops traffic
before its LIFO topology cleanup. The host wrapper owns both the heartbeat and
the exact Podman container ID; its exit trap stops/removes them even when the
gate is interrupted. Versioned `exit-gate-report.json` follows
`schemas/chaos-exit-gate-v1.schema.json`.

The canonical host route comparison removes only volatile `expires`,
`expires_ms`, and `used` countdown fields. Raw snapshots are retained so that
reviewers can prove any difference is limited to natural timer decay. Route
destinations, gateways, devices, metrics, flags, and every qdisc field must be
byte-identical. The host heartbeat must report zero loss.

Each profile sends target traffic through both impairment attachment points
and sends an independent control stream only to the first router interface,
before either shaped interface. The gate checks clean RTT, fixed RTT, jitter
variation, burst loss, duplicate replies, arrival inversions, constrained
queue behavior, asymmetric behavior, and the 1280-byte MTU boundary. Every
run must report exact cleanup restoration. These ICMP observations establish
that the kernel applied each profile; RTP-specific paired-PCAP measurement is
covered separately by `tests.test_chaos_lifecycle`.

The gate also has adversarial tests for every partial mutation, cancellation,
killed children, changed ownership markers/qdiscs, namespace path
substitution, frozen-state drift, modified commands, unavailable or unknown
capabilities, and dangerous host-mode confirmation.

## Environment limits

The read-only capability probe does not load kernel modules. If netem or a
flower/u32 classifier is loadable but not already present, planning fails
loudly; prepare the disposable runner outside Sippycup and rerun the probe.
The exit gate never treats a mutation probe as production capability
evidence. Pasta requires `/dev/net/tun`, which the wrapper passes explicitly.

`NET_ADMIN` and `SYS_ADMIN` exist only in rootless Podman's user, mount, and
network namespaces. The traffic child drops both. Dangerous host-network mode
is not exercised automatically: it requires rootful execution, a concrete
host interface, and the exact `dedicated-test-vm:NAME` confirmation, and
belongs only on a manually designated disposable VM.

`make full-gate` runs the ordinary campaign/unit/container gates followed by
this real host-isolation matrix. It intentionally requires the environment
described above; `make campaign-gate` remains usable on hosts without
`/dev/net/tun` or the namespace capabilities.
