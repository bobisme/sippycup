# Disposable chaos topology

`sippycup-chaos topology-plan` is a read-only boundary. It detects the
environment, freezes literal target CIDRs, snapshots routes and qdiscs, and
prints `sippycup.dev/chaos-topology-plan/v1`. It never creates a namespace,
link, route, filter, qdisc, or kernel module. The plan deliberately contains an
empty `mutationCommands` array; later profile and lifecycle components consume
the reviewed attachment points.

## Default packet path

The default `disposable-router` topology has three disposable namespaces and
five explicitly named interfaces:

```text
outbound
  test namespace:test0
    -> impairment namespace:imp-test0
    -> impairment namespace:imp-uplink0
    -> uplink namespace:uplink0
    -> uplink namespace:pasta0
    -> pasta userspace gateway
    -> authorized target

inbound
  authorized target
    -> pasta userspace gateway
    -> uplink namespace:pasta0
    -> uplink namespace:uplink0
    -> impairment namespace:imp-uplink0
    -> impairment namespace:imp-test0
    -> test namespace:test0
```

The impairment namespace is a router with two independent egress attachment
points. Test egress is shaped on `imp-uplink0`. Test ingress is shaped as
router egress on `imp-test0`. Bidirectional and asymmetric profiles therefore
have honest, independent directions without pretending that one qdisc controls
both directions. IFB is not required by this default topology.

Each run uses fresh namespace names derived from a reviewed prefix. Planning
fails if one already exists. `targetFilters` contains only canonical literal
IPv4 or IPv6 CIDRs; hostnames, non-canonical networks, multicast scopes, and
default routes are rejected. Egress selectors match the target as destination;
ingress selectors match it as source. `targetScopeSha256` freezes that ordered
scope for the profile compiler and lifecycle executor.

## Capability decisions

The read-only capability snapshot distinguishes `available`, `unavailable`,
and `unknown`. Required unknowns are rejected rather than approximated.
Planning the disposable router requires iproute2, `tc`, namespaced
`NET_ADMIN` and `SYS_ADMIN`, pasta, netem, and a flower or u32 classifier.
Pasta availability also requires a readable and writable `/dev/net/tun`; the
isolated administrative launcher passes that device explicitly.
`SYS_ADMIN` is used only to bind named child network namespaces inside the
isolated rootless container's user/mount namespace. MTU profiles additionally
require the MTU capability. Detection reads the effective capability mask,
user-namespace mapping, installed commands, and existing/built-in kernel
modules; it never loads a module or attempts a trial qdisc.

Namespace commands enter the exact frozen `/run/netns/<name>` bind mount with
`nsenter`; they do not use `ip netns exec`, whose unrelated `/sys` remount is
not permitted by rootless Podman.

Generate a capability record in the exact impairment environment, then use it
for a host-side no-change plan:

```sh
./bin/sippycup --isolated --admin -- \
  sippycup-chaos capabilities --output /work/chaos-capabilities.json

./bin/sippycup-chaos topology-plan \
  --capabilities work/chaos-capabilities.json \
  --target 10.20.30.40/32 \
  --direction asymmetric \
  --namespace-prefix voice-lab
```

If a feature cannot be established, the planner refuses the requested
direction. In particular, the single-interface host fallback needs IFB for
ingress; the planner never silently turns ingress into egress or
bidirectional impairment.

## Privilege boundary

In `disposable-router`, the lifecycle controller uses `NET_ADMIN` and
`SYS_ADMIN` only inside the isolated rootless container. The traffic child is
started through `setpriv` with both capabilities removed from its bounding,
inheritable, and ambient sets. Host routes and host qdiscs are read-only, and
later cleanup must prove they match the pre-mutation snapshot byte-for-byte.

`dangerous-host-network` is a separate topology name, not a flag that widens
the default. It is accepted only for rootful execution with effective
`NET_ADMIN` and an explicit confirmation naming the dedicated VM:

```sh
./bin/sippycup-chaos topology-plan \
  --topology dangerous-host-network \
  --dangerous-confirmation dedicated-test-vm:voice-lab-01 \
  --host-interface eth0 \
  --target 10.20.30.40/32 \
  --direction ingress
```

Host ingress additionally requires IFB and classifier support. The resulting
plan is marked `dangerous: true` and names the privilege boundary in plain
language. This mode is for an isolated test VM only.

## Pre-mutation snapshot

Before any later mutation, the planner records host routes with
`ip -json route show table all` and host qdiscs with
`tc -json qdisc show`. It also records routes and qdiscs for every planned
named namespace if one exists; existence causes the plan to fail rather than
reuse state. `snapshotSha256` binds the exact pre-mutation snapshot. The
lifecycle owner must snapshot again after cleanup and reject any difference.
