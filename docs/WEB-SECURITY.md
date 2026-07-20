# Admin and WebSocket security profiles

Sippycup separates admin/API scope from signaling and media approval. A WebRTC
call approval does not authorize admin requests, and an admin approval does not
authorize WebSocket probes unless both surfaces are named explicitly.

Compile the checked-in offline fixture:

```sh
./bin/sippycup web-security plan \
  examples/web-security/offline-profile.json \
  examples/web-security/example-adapter.json
```

This is an offline compiler. It returns fixed adapter case and route IDs,
literal connect addresses, separate TLS server names, external credential
references, exact authorization state, and hard ceilings. It never returns
provider locations, credentials, URLs, methods, headers, request bodies,
arbitrary WebSocket messages, or a general request primitive.

Evaluate normalized evidence:

```sh
./bin/sippycup web-security evidence PLAN.json OBSERVATION.json
```

The evidence must bind the canonical plan digest and contain exactly one
bounded normalized result per case. Unexpected authorization outcomes,
check/case confusion, traffic while an approval window is blocked, ceiling
violations, request-rate excess, and incomplete cleanup fail. Missing cases,
adapter errors, and unknown outcomes remain incomplete. Tokens, cookies,
headers, bodies, messages, and session contents are not fields in the
contract.

## Profile boundary

The profile has three execution classes:

- `offline_fixture`: loopback destinations and no target authorization;
- `local_lab`: loopback/private/link-local destinations and no target
  authorization;
- `approved_target`: literal frozen destinations, a UTC window no longer than
  24 hours, an approval reference, and separately named `admin` and/or
  `websocket` surfaces.

DNS names are TLS identities only; they never authorize resolution or a
destination. Credentials use bounded `env://`, `fd://`, or registered
`exec://` references and map one-to-one to roles. Values never enter plans.

The v1 ceilings cover cases, connections, HTTP requests, WebSocket messages,
authentication failures, bytes, duration, and request rate. They are hard
maximums, not defaults.

## Service-specific adapters

An adapter declares a fixed versioned set of route IDs, abstract operations,
and cases. Routes contain no paths. Cases contain no methods or payloads. The
compiler rejects a profile/adapter identity mismatch, unsupported check,
missing role/origin fixture, cross-surface route, or expansion past `maxCases`.

The checked-in adapter is an offline example, not a target adapter. A real
adapter cannot be completed until the owner supplies the protocol shape and
approval identifies:

- literal admin and WSS connect addresses, ports, and TLS names;
- exact admin and WebSocket authorization surfaces;
- test accounts and intended roles;
- allowed origins and a harmless foreign-origin fixture;
- permitted checks, attempt ceilings, time window, and approval reference.

Until then, `web-security` compiles and evaluates evidence only. It sends no
network traffic.
