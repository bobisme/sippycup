# Packet oracle exit gate

The compact golden and mutation corpus is listed in
`tests/oracle/fixtures/golden-corpus.json`. It covers UDP and TCP signaling,
IPv4 and IPv6, pcap and pcapng, early media, re-INVITE, forks, packet
loss/reordering/duplication, RFC 4733 DTMF, one-way media, third-party
endpoints, post-BYE leakage, physical truncation, and dissector disagreement.

Run the complete gate:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/oracle -v
PYTHONDONTWRITEBYTECODE=1 python3 tests/oracle/benchmark_oracle.py
```

Real capture tests generate packets with `text2pcap`, convert formats with
`editcap`, and parse the result with TShark. Physical snaplen truncation is
therefore tested below the synthetic record layer.

## Assertion CLI

```sh
./bin/sippycup assert work/call.pcapng \
  --expect examples/oracle-expectations.yaml

./bin/sippycup assert work/call.pcapng \
  --expect examples/oracle-expectations.yaml \
  --format json
```

Human and JSON output are projections of the same result document. Human
failure lines include assertion ID, verdict, applicability, frame, and epoch
timestamp. JSON follows `oracle/schemas/results-v1.schema.json` and includes
per-dialog and per-stream evidence.

Exit codes are stable:

| Code | Meaning |
| ---: | --- |
| 0 | All applicable assertions pass |
| 1 | An assertion fails |
| 2 | Expectations are malformed or unsupported |
| 3 | Capture is unreadable or not pcap/pcapng |
| 4 | Required analysis remains unknown |
| 5 | TShark or internal analysis fails |

Failure takes precedence over unknown. `on_unknown: inconclusive` returns 4;
`on_unknown: fail` promotes applicable unknowns to failures and returns 1.
Not-applicable checks do not make a run inconclusive.

## Determinism, privacy, and performance

The gate compares byte-identical canonical JSON across repeated analysis and
checks that every expected failure carries known frame/time evidence. It also
rejects default output containing SIP authorization values, raw RTP payload
markers, decoded audio, or audio byte fields.

The supported in-memory envelope is 20,000 RTP packets analyzed in less than
8 seconds with less than 128 MiB peak analysis allocation on the development
host. `benchmark_oracle.py` measures only analysis allocations after corpus
construction and emits a machine-readable result. This is an initial safety
bound, not a promise that arbitrary captures are held entirely in memory
without cost; larger production captures should be bounded or streamed in a
future adapter.
