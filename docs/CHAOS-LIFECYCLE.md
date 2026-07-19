# Owned chaos lifecycle and observed impairment

`./bin/sippycup chaos run` is the only component that executes a compiled chaos
plan. It recompiles the impairment settings embedded in the plan and requires
the complete document, structured command arrays, attachment points, target
filters, topology digest, snapshot digest, and ownership tags to match. A
modified command never reaches `tc`.

The default disposable topology creates only the three names in the reviewed
topology plan. Each namespace receives a unique dummy ownership marker, and
each veth receives the run owner as its interface alias. Two run-owned veth
pairs form:

```text
test0 <-> imp-test0 | impairment router | imp-uplink0 <-> uplink0
```

The internal IPv4 ranges are `198.18.0.0/30` and `198.18.0.4/30`; the IPv6
ranges are `fd42:7369:7070:1::/64` and `fd42:7369:7070:2::/64`. The child runs
in the test namespace through fixed-argument `nsenter` plus `setpriv`, which
removes `NET_ADMIN` and
`SYS_ADMIN` from its capability bounding set. A foreground,
process-group-owned `pasta` instance
gives the uplink namespace outbound IPv4/IPv6 connectivity without adding a
host route, host NAT rule, host link, or host qdisc. Unsolicited inbound pasta
port forwarding is disabled. The container therefore needs `pasta`, supplied
by Debian's `passt` package.
Pasta also requires `/dev/net/tun`; `./bin/sippycup --isolated --admin`
passes that device, and capability detection fails loudly when it is absent.

The executor rejects namespace path substitution before every entry: the
frozen name must resolve to the exact, non-symlink
`/run/netns/<planned-name>` bind-mount file, and its dummy marker must still
carry the exact plan owner alias. It uses `nsenter --net=<fixed-path>` because
`ip netns exec` additionally remounts `/sys`, an operation unavailable in a
rootless Podman container even when its bounded `SYS_ADMIN` is enabled.
The two forwarding sysctls run in a short-lived private mount namespace with
a freshly mounted `/proc`; this makes `/proc/sys/net` refer to the owned
impairment namespace without changing the controller's mount or network
namespace.

```sh
./bin/sippycup chaos run \
  --report work/chaos-run.json \
  --observation egress=work/egress-before.pcap,work/egress-after.pcap \
  --observation ingress=work/ingress-before.pcap,work/ingress-after.pcap \
  work/topology.json work/impairment.json \
  -- sipp 198.51.100.20:5060 -sn uac -m 1 -r 1
```

Options precede the two plan paths. An output report is exclusively created
and is never allowed to overwrite evidence. Omitting paired observations does
not invent measurements: the report explicitly says `insufficient_samples`.

## Ownership and cleanup

Immediately after creating an object, the lifecycle registers its inverse.
Registration is LIFO, so target traffic stops first, owned qdiscs and pasta
stop next, and namespaces disappear last. A namespace exposed to the traffic
child is deleted only if its marker interface still has the exact run alias.
Veths, addresses, routes, and sysctls live inside those owned namespaces and
disappear with them.

Qdiscs have no arbitrary label field. Their ownership is therefore the
combination of a plan-bound owner record, reserved handles (`1:`, `10:`,
`20:`), exact interface/namespace attachment, and a live kind/handle check.
Cleanup refuses to delete a root whose `1:` handle is no longer the planned
`prio`. The separately confirmed host-ingress mode similarly verifies the
run-created IFB alias and `ffff:` clsact before deletion. It never replaces an
existing root or clsact: `add` fails closed.

Cleanup retries a transient failure up to three times, continues through
independent cleanup actions, and then collects a fresh route/qdisc/namespace
snapshot. The report succeeds only when that snapshot is byte-equivalent to
the frozen pre-run snapshot. Preflight also requires live state to match the
frozen snapshot before the first mutation. Repeated runs therefore begin from
the same proven state.

SIGINT, SIGTERM, duration expiry, child failure, startup failure, and partial
application all enter the same cleanup path. Cancellation stops and waits for
the traffic process group before `topology.cleanup_started`; the report exposes
`trafficStoppedBeforeTopologyTeardown` so campaign cancellation ordering is
machine-checkable.

## Packet-level measurement

Measurements use paired classic-PCAP files captured immediately before and
after an impairment point on the same clock. Ethernet and raw-IP PCAP link
types are supported for IPv4/IPv6 UDP RTP. Packets are paired by SSRC, RTP
sequence, RTP timestamp, payload type, and a payload digest. Capture timestamps
provide per-packet delay. Unmatched sent identities are loss, extra received
identities are duplication, and arrival inversions relative to sent order are
reordering.

Reports include requested and observed mean delay, delay standard deviation
(jitter), loss percentage, reorder percentage, and duplicate percentage for
each direction. Gilbert-Elliott requested loss is reported as its stationary
expected loss, not as a promise about one finite burst sequence.

Timer scheduling, qdisc clock granularity, capture placement, and finite
sampling make exact equality misleading. The documented comparison tolerances
are:

- mean delay: the larger of 5 ms or 15% of requested delay;
- jitter standard deviation: the larger of 5 ms or 35% of requested jitter;
- loss, reorder, and duplication: the larger of 2 percentage points or 50% of
  the requested rate.

Delay and jitter need at least 20 paired packets. Rate metrics need at least
200 sent packets. Below either threshold, `withinTolerance` is null and the
direction is `insufficient_samples`. Negative paired delays, malformed PCAPs,
unsupported link types, and absent observations are never coerced into a pass.
These tolerances characterize local kernel impairment; they do not claim to
simulate a particular Internet access network exactly.

The report contract is
`schemas/chaos-run-report-v1.schema.json`.
