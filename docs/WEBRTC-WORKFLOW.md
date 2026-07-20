# Guided WebRTC workflow

This path starts offline, proves the independent peer in a loopback-only lab,
and stops before target traffic unless a service-specific adapter and written
approval are both present. Do not point the self-tests at a deployment: they
have no target argument and cannot scan one.

## 1. Validate the contracts offline

```sh
./bin/sippycup webrtc validate \
  examples/webrtc/offline-scenario.json \
  --result examples/webrtc/offline-result.json
```

This checks the scenario/result binding, literal destinations, execution
class, authorization shape, ceilings, evidence policy, and secret-free result
contract. It sends no traffic and does not grant authorization.

## 2. Install and inspect the optional peer

```sh
./bin/sippycup webrtc status
./bin/sippycup webrtc build
./bin/sippycup webrtc capabilities > work/webrtc-capabilities.json
./bin/sippycup webrtc validate \
  examples/webrtc/offline-scenario.json \
  --capabilities work/webrtc-capabilities.json
```

The build is separate from the core image and pins Pion plus its Go dependency
graph. Capability validation fails when the concrete adapter cannot satisfy a
scenario requirement.

## 3. Run the local lab

```sh
./bin/sippycup webrtc self-test
./bin/sippycup webrtc signaling-self-test
./bin/sippycup webrtc relay-self-test
./bin/sippycup webrtc exit-gate
```

Both commands run in the optional image with no external container network,
all capabilities dropped, a read-only root filesystem, and a deadline. The
audio check places one Pion-to-Pion DTLS-SRTP call on loopback. The signaling
check starts one fixed loopback WSS fixture and covers TLS, Origin,
authentication, expiry, replay, authorization, size/rate, state, and
reconnection behavior. The relay check forces the same media path through a
disposable authenticated loopback TURN/UDP server.

`exit-gate` runs all three clean components, injects and detects a foreign
Origin acceptance flaw, proves a clean recovery run, and forces a one-second
media cancellation. Its aggregate report binds each component by SHA-256,
rechecks redaction and ceilings, grants no authorization, and makes no
capacity claim.

Exact v1 limits are one call per media component, 50 RTP packets per call,
160 payload bytes per packet, a 30-second maximum component deadline, at most
1,000 peer UDP ports, 12 signaling connections, and 24 signaling messages.
Every container has no external network, drops all capabilities, and uses a
read-only root filesystem.

## 4. Evaluate evidence offline

```sh
./bin/sippycup webrtc sdp evaluate POLICY.json TRANSCRIPT.json
./bin/sippycup webrtc ice-turn POLICY.json OBSERVATION.json
./bin/sippycup webrtc media-security POLICY.json OBSERVATION.json
./bin/sippycup webrtc call-evidence POLICY.json EVIDENCE.json
./bin/sippycup triage CAPTURE.pcap
./bin/sippycup report CAPTURE.pcap
```

The first four are normalized, socket-free oracles. Capture triage and report
are also offline; collect a capture only inside the separately approved scope.

## Live admission

There is intentionally no generic WSS request, browser automation, URL,
payload, or production-scanning command. An authorized one-call action remains
unavailable until the service owner supplies:

- the signaling protocol and fixed adapter vocabulary;
- literal signaling, STUN/TURN, and media destinations;
- TLS server names and permitted browser Origins;
- external test credential references and intended roles;
- a written approval reference, short UTC window, negative-test classes, and
  hard call/message/packet/byte ceilings.

The future command must revalidate those fields at execution time. A scenario,
successful local lab, or old approval artifact cannot authorize traffic.

## Recovery

- Missing container runtime: install Podman, nerdctl, or Docker, then rerun
  `./bin/sippycup webrtc status`.
- Missing image: run `./bin/sippycup webrtc build`; a failed build does not
  alter the core image.
- Capability mismatch: reduce the scenario or install the reviewed adapter;
  never ignore the missing capability.
- Self-test failure: rerun once, preserve the JSON report, and inspect the
  failed check. Unknown or missing evidence is not a pass.
- TLS or Origin failure: confirm the intended identity/origin in the local
  adapter. Do not disable certificate or Origin validation.
- Live command unavailable: the service adapter or approval is incomplete.
  Continue with offline evidence; do not substitute an arbitrary WebSocket
  client.

Residual local-gate gaps are explicit: a real browser engine, TURN over TCP
and TLS, a service-specific target signaling adapter, and approval-bound
target execution.
