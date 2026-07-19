# Negotiated canary RTP sender

`sippycup media send` is a small, bounded RTP packetizer for the deterministic
audio canaries. It sends PCMU, PCMA, or G.722 plus negotiated RFC 4733
telephone events. It does not originate SIP or guess media endpoints.

The input is a `sippycup.media-session/v1` JSON document. Each revision embeds
the completed local and remote SDP snapshots that are current after an
offer/answer exchange. The sender derives its UDP bind address/port from the
local SDP and its destination address/port from the remote SDP. Codec and
telephone-event payload types, RTP clock, and 20 ms packetization also come
from those snapshots; there are deliberately no command-line endpoint or
payload-type overrides.

Preview the exact packet plan without opening a socket:

```sh
./bin/sippycup media send examples/media-session.json \
  --dry-run --format json
```

After replacing the example SDP with completed SDP from an authorized isolated
call, send it with:

```sh
./bin/sippycup media send work/media-session.json --format json
```

The local source address must exist on the sending host. The sender rejects
hostnames, multicast/unspecified addresses, ports below 1024, non-20 ms
packetization, unknown codecs, mismatched payload mappings, and SRTP/keying
attributes before creating any UDP socket. Session input is limited to 256
KiB, eight SDP revisions, sixteen digits, 200 packets, and a five-second echo
timeout. All revision endpoints are bound successfully before the first packet
is emitted.

## Re-INVITE revisions

Revision zero activates at 0 ms. A later entry represents a successfully
completed re-INVITE offer/answer and supplies its activation time. Activation
must be unique, increasing, within the one-second canary, and aligned to a
20 ms packet boundary. The first packet at that boundary uses the new source,
destination, codec payload type, and telephone-event payload type. Results
report `activationMs`, `firstPacketMs`, and `delayMs`; the deterministic
fixture requires zero transition delay.

Rejected or incomplete SDP must not be placed in the session document. This
sender intentionally does not infer offer/answer state from live signaling;
the packet oracle remains responsible for proving which SDP revision became
active.

## RFC 4733 behavior

Digits `0-9`, `*`, `#`, and `A-D` use the matching negotiated dynamic
`telephone-event/8000` payload. Each event:

- sets the RTP marker bit only on its first packet;
- keeps one RTP timestamp for the complete event;
- advances duration by 160 clock ticks per 20 ms packet to 800 ticks;
- sets the end bit at 100 ms;
- sends three identical end packets with consecutive RTP sequence numbers;
- preserves sequence continuity from the preceding audio packets.

The sender never falls back to in-band digits or a guessed payload type.
`validate_telephone_events` provides the corresponding fail-closed check for
a returned `PlannedPacket` stream. It requires event codes in digit order,
the first-packet marker, continuous RTP sequences, the exact duration
progression, and all three redundant ending packets. The media calibration
gate includes missing-ending, cleared-end-bit, and reordered-digit adversarial
cases.

## Echo validation and timing

When `echo.required` is true, every datagram must return byte-for-byte from the
negotiated remote endpoint before the sender continues. The result reports
audio and telephone-event echo counts, maximum send lateness, measured
round-trip latency, and revision transition delay. It never presents
round-trip time as one-way latency.

`./bin/sippycup media-echo` is a deadline- and packet-count-bounded fixture for
isolated loopback tests. For example:

```sh
./bin/sippycup media-echo --bind 127.0.0.1 --port 21000 \
  --max-packets 71 --deadline-ms 4000 --telephone-event-pt 101
```

The checked-in `tests/fixtures/media/packet-plan-v1.json` is the exact
packet-level expectation. Regenerate it with `make media-packet-golden`; verify
behavior with `make media-send-test`. Exit status 2 means invalid session/SDP,
and status 3 means bind, send, timeout, or echo validation failure.
