# Packet oracle record and schema contract

The packet adapter consumes `tshark --no-duplicate-keys -T json` data, not
columns or terminal text. The duplicate-key option is mandatory because it
preserves repeated SDP media and attribute fields as ordered arrays.
`tshark_json_args()` returns the supported invocation. Field names are exact
dissector keys and timestamps become `Decimal` epochs whether TShark emits an
epoch string or a UTC ISO timestamp; neither terminal width nor the process
locale can change parsing. Capture format is determined from pcap/pcapng magic
bytes.

The immutable Python records live in `lib/sippycup_oracle` and serialize as
`sippycup.packet-records/v1`. They model:

- frame evidence and capture completeness;
- source and destination endpoints;
- SIP transaction identifiers, excluding authentication values;
- SDP revisions and media sections;
- RTP and RTCP header metadata, excluding payload bytes.

Every applicable value is either:

```json
{"state": "known", "value": 42}
```

or a typed unknown:

```json
{"state": "unknown", "reason": "truncated_capture", "detail": "rtp.timestamp"}
```

Unknown reasons are `missing_field`, `malformed_field`,
`truncated_capture`, `unsupported_encryption`, `unsupported_protocol`, and
`ambiguous`. Absence of a protocol is represented by no protocol record; for
example, `rtp: null` means that TShark did not identify RTP in that frame.
An encrypted media record has
`payload_visibility.state == "unknown"` and reason
`unsupported_encryption`; it never implies that audio quality was inspected.
SRTP- or SRTCP-only dissections still produce RTP or RTCP metadata records,
but every unavailable encrypted header field is a typed unknown. Missing frame
lengths make capture status unknown. Missing SDP presence and payload formats
likewise remain unknown instead of becoming `false` or an empty affirmative
value.

## Public JSON schema versions

- Expectations: `sippycup.expectations/v1`, defined by
  `oracle/schemas/expectations-v1.schema.json`.
- Results: `sippycup.results/v1`, defined by
  `oracle/schemas/results-v1.schema.json`.

Both schemas use JSON Schema 2020-12. An expectations YAML file is valid when
its parsed data validates against the expectations JSON schema. Unknown
assertion results never silently become passes. `on_unknown` may promote an
unknown observation to an assertion failure, but otherwise the overall run is
inconclusive.

Schema versions are part of the public interface. Additive or breaking field
changes require a new versioned schema; consumers must reject versions they do
not support.

## Calibrated media facts

The deterministic canary analyzer emits an `assertionFacts` array whose items
use the result schema's `assertion_result` shape: three-state verdict,
applicability, message, evidence, and typed observed value. Standalone raw
payload analysis has no PCAP frame numbers, so evidence is empty. A capture
workflow may prefix the fact ID with its correlated dialog ID and attach the
appropriate RTP frame evidence before merging it into the packet-oracle
`assertions` array.

Unsupported codecs and encrypted payloads export unknown facts with
`unsupported_protocol` or `unsupported_encryption`; they never become passing
quality assertions. See `docs/MEDIA-ANALYZE.md` for calibration thresholds and
the separate `sippycup.media-analysis-result/v1` envelope.

## Exit-code contract for `sippycup assert`

| Code | Meaning |
| ---: | --- |
| 0 | All selected assertions passed |
| 1 | At least one assertion failed |
| 2 | Expectations are malformed or use an unsupported schema version |
| 3 | Capture is missing, unreadable, or not pcap/pcapng |
| 4 | Analysis is inconclusive because at least one required result is unknown |
| 5 | Internal tool or TShark execution failure |

Failure takes precedence over inconclusive when both occur. Input errors take
precedence over assertion evaluation. This contract is reserved here for the
later assertion CLI; the adapter itself raises `CaptureDecodeError` rather
than exiting.

## Privacy boundary

Normal serialized records contain no packet bytes, RTP payload, decoded audio,
SIP `Authorization` or `Proxy-Authorization` values. Downstream code should
reference a frame and timestamp through `EvidenceRef` instead of embedding raw
packet data. A future explicit forensic export must use a separate opt-in
record type and must not alter this default.

## Fixture coverage

`tests/oracle/fixtures` covers pcap and pcapng magic, IPv4 SIP/SDP, IPv6 RTP,
truncation, malformed dissections, encrypted media, missing structural fields,
no-SIP, and no-RTP input. In addition to deterministic synthetic dissector
fixtures, integration tests generate semantic IPv4 pcap and IPv6 pcapng
captures with `text2pcap`, run real TShark JSON dissection, and verify repeated
audio/video SDP sections retain their own address, formats, direction, ptime,
RTCP, codec, and telephone-event metadata.
