# WebRTC scenario and result contracts

Sippycup's optional WebRTC components exchange two strict, versioned
documents:

- `schemas/webrtc-scenario-v1.schema.json` describes reviewed intent,
  capabilities, destinations, ceilings, and evidence policy.
- `schemas/webrtc-result-v1.schema.json` describes normalized events,
  assertions, evidence references, redactions, and the aggregate outcome.

The contracts are useful without a WebRTC runtime. The standard-library
validator in `sippycup_webrtc.contracts` performs cross-field checks that JSON
Schema alone cannot express clearly.

## Scenario rules

`executionClass` is one of:

- `offline_fixture`: no target authorization and loopback destinations only;
- `local_lab`: no target authorization and only loopback, private, or
  link-local literal addresses;
- `approved_target`: a non-empty approval reference and bounded validity
  window are mandatory.

All destinations are literal IP addresses. A hostname, redirect, candidate, or
TURN alternate address is not implicitly authorized. A later runner must
compare every actual destination with the frozen set before sending a packet.

The adapter advertises a versioned capability set. Validation fails when the
scenario requires a capability the selected adapter does not supply.
Negotiation flags also require their matching capability, so an adapter cannot
silently ignore trickle ICE or an ICE restart.

`credentialRefs` contains external provider references, never values. Inline
and data providers are forbidden. V1 is audio-only, never retains raw audio,
and forbids full SDP retention for approved targets.

The limits are upper bounds, not defaults:

- calls and concurrency;
- total duration and signaling messages;
- packets and bytes;
- retained evidence bytes.

A compiler or runner may reduce them but must never widen them.

## Result rules

Every result declares whether network activity occurred and has an aggregate
status of `pass`, `fail`, or `incomplete`. Assertions use four verdicts:

- `pass`;
- `fail`;
- `unknown`, with a required typed reason;
- `not_applicable`.

An aggregate pass cannot contain failed or unknown assertions. A failure needs
at least one failed assertion, and an incomplete result needs at least one
unknown assertion. Summary counters must exactly match the assertion list.

Events have strictly increasing sequence numbers, named sources, sensitivity,
and bounded scalar data. They should carry canonical SDP hashes, candidate
classes, redacted address hashes, negotiation generations, DTLS roles and
versions, SRTP profiles, counters, and verdict inputs—not credentials, full
packets, or arbitrary adapter output.

Assertions reference evidence by stable artifact ID. Each artifact records a
SHA-256 digest, media type, and sensitivity. There is no unrestricted path or
embedded artifact field. Known credential field names, bearer values, ICE
password lines, authorization headers, and private keys cause semantic
validation to fail.

## Offline fixture

`examples/webrtc/offline-scenario.json` and
`examples/webrtc/offline-result.json` are deliberately network-free fixtures.
They are not target templates and cannot be promoted into target
authorization.

```python
import json
from pathlib import Path

from sippycup_webrtc.contracts import validate_result, validate_scenario

scenario = json.loads(
    Path("examples/webrtc/offline-scenario.json").read_text()
)
validate_scenario(
    scenario,
    adapter_capabilities=scenario["adapter"]["requiredCapabilities"],
)

result = json.loads(
    Path("examples/webrtc/offline-result.json").read_text()
)
validate_result(result)
```

Use the unified network-free validator before installing the optional peer:

```sh
./bin/sippycup webrtc validate \
  examples/webrtc/offline-scenario.json \
  --result examples/webrtc/offline-result.json
```

Add `--capabilities CAPABILITIES.json` to bind required capabilities to a
captured adapter capability document. Without that flag, validation checks the
scenario against its declared requirements and reports the binding as
`not-supplied`; it does not claim that an installed adapter supports them.
Validation never grants target authorization.
