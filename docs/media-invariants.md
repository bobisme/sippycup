# RTP/RTCP correlation and invariants

`lib/sippycup_oracle/media.py` maps observed RTP five-tuples, SSRCs, payload
types, and RTCP sender reports to the active offer/answer revision of one
dialog leg. Assertions return `pass`, `fail`, or `unknown` plus explicit
`applicable`, `not_applicable`, or `unknown` applicability. Every result has
frame/time evidence; when no media exists, negotiation evidence is used.

The evaluator checks:

- bidirectional media;
- negotiated or explicitly allowed endpoint addresses and ports;
- payload types, expected codecs, and RFC 4733 telephone-event traffic;
- setup windows, media before an SDP answer, and media after the BYE request;
- sequence loss, duplication, reordering, timestamp jumps, and jitter;
- unexplained payload or SSRC transitions; and
- negotiated re-INVITE/UPDATE transitions.

An address outside signaling, SDP, and explicitly allowed scope fails endpoint
validation. Symmetric RTP is represented as `symmetric_rtp`, distinct from an
exact SDP tuple, and may be disabled. A payload or SSRC change across an active
renegotiation boundary is valid; the same change without a new negotiated
revision fails.

## Metrics

Per SSRC and five-tuple, sequence numbers are extended across the 16-bit wrap:

- `received` is captured RTP packet count;
- `unique` is the number of distinct extended sequence numbers;
- `expected = max_extended - min_extended + 1`;
- `lost = max(expected - unique, 0)`;
- `duplicates` counts already-seen extended sequence numbers;
- `reordered` counts first-seen numbers below the highest previously seen.

Interarrival jitter follows RFC 3550’s estimator:

`J(i) = J(i-1) + (|D(i-1,i)| - J(i-1)) / 16`

where transit is arrival time converted to RTP clock units minus RTP
timestamp. The result is converted to milliseconds using the codec clock
rate. Timestamp continuity compares RTP timestamp delta with arrival delta in
clock units using the configured tolerance.

RTCP sender SSRC and network direction correlate reports to RTP streams.
Ambiguous or absent matches remain typed unknowns.

## Which dialog owns a stream

A capture can hold several calls, and only the cleartext ones show their SIP
and SDP; a TLS call's RTP is visible but its dialog is not. Without the
run's record (below) ports alone cannot tell two calls apart: before the
record existed every softphone call bound local RTP port 4000. An RTP
stream (five-tuple and SSRC) may belong only to a dialog that
was in progress when the stream started: from the dialog's first SIP evidence
to its last one plus 250 ms when the capture shows it ended, open-ended
otherwise. RTCP uses the start of the latest RTP stream on the adjacent ports.
A stream that started in no visible dialog's lifetime (for example the RTP of
a TLS call placed after a cleartext call) is not judged against any dialog:
the result carries `capture.media.attribution` with verdict `unknown` and the
unattributed packets as evidence, so the run is inconclusive, not failed. A
stream that started during a call and runs on after its BYE still belongs to
that call, so late media still fails `media.timing`.

### The run's record of local RTP ports (`call-media.json`)

`campaign run` and `call` write `call-media.json` next to `capture.pcap`
(schema `sippycup.call-media/v1`, `lib/sippycup_oracle/call_media.py`). It
lists each softphone call the run placed: its local address, the local RTP
port PJSUA advertised in its SDP offer (RTCP is the next port), the
signaling transport, and the window in which the call ran (`call`: the
softphone's start and end; `campaign run`: the step's `step.started` and
end events in `events.jsonl`). `complete` is true when every call the run
placed is listed. Campaign steps try their own pair: step N starts at
4000 + 2 × ((N − 1) mod 50), so ports 4000–4099 (PJSUA moves on by two when
a pair is in use, and the record holds the port really used). Campaign
steps never overlap, so a port reused 50 steps later is told apart by its
window. `call` keeps PJSUA's default of 4000 (the next free pair when
another call holds it).

`./bin/sippycup assert` reads the file from the capture's directory when it
is there, and uses it only for frames with exactly one endpoint at a
recorded local address:

- On a recorded call's port within its window, the frame goes only to the
  visible dialog that advertised that port in its SDP. When there is none
  (a TLS call), the frame belongs to that recorded call and is not judged;
  `capture.media.attribution` then passes and names the call, its
  transport, and its port, and says that those packets were not judged.
- One port recorded for two calls whose windows overlap: the frame is
  unattributed (and ambiguity evidence for a visible dialog among them), so
  the result is unknown.
- With a complete record, a local port the record does not list and no
  visible dialog advertised (for example a call placed from another
  terminal at the same time) is unattributed: unknown, never judged against
  the dialog that happens to be up. A far end that sends this run's media
  to a wrong local port is therefore inconclusive, not failed, when a
  record is present.

A capture without the file (runs made before it existed, or a capture
copied elsewhere), or with a file that does not validate (the oracle warns
on stderr and does not use it), is analyzed exactly as described above.

## Media after teardown

`media.timing` fails when RTP is seen before the answer or after teardown.
The party that sends BYE must stop media at its BYE. The party that receives
the BYE cannot stop earlier than the BYE reaches it, and its 2xx often comes
from a signaling element while a separate media element is still being told
to stop, so its media is late only more than 250 ms after its 2xx to the BYE.
When the capture has no 2xx for the BYE, or the direction of a stream is
unknown, the BYE time applies with no grace.

## Encryption and incomplete data

SRTP/SRTCP receives transport-only analysis: direction, endpoints, timing, and
packet presence remain applicable, while payload, sequence, DTMF, codec
quality, timestamp, and jitter observations hidden by encryption are unknown.
Unknown negotiation or packet fields never become passes. A disabled
expectation is `not_applicable`, not silently successful.
