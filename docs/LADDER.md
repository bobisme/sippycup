# Call ladder

`./bin/sippycup ladder` draws a SIP and media sequence diagram (a "ladder")
from recorded evidence, so an operator can see a misbehaving call in seconds
and the platform owner can read the same picture in the report. It is offline:
it reads files, runs TShark on them, and sends nothing.

```sh
./bin/sippycup ladder work/practice/calls/RUN_ID                 # terminal
./bin/sippycup ladder work/practice/calls/RUN_ID --format html --output ladder.html
./bin/sippycup ladder capture.pcap --approve 203.0.113.0/24 --call-id-index 2
./bin/sippycup ladder RUN_ID_DIR --format json                   # same content, machine readable
```

| Option | Meaning |
| --- | --- |
| `--format text\|html\|json` | Terminal ASCII (default), one self-contained HTML file, or the underlying document (`sippycup.dev/ladder/v1`). |
| `--output FILE` | Write there (mode 0600, atomic) instead of standard output. |
| `--call-id-index N` | Draw only section N. Sections are numbered `[1]`, `[2]`... in the order shown (a registration, a call, and the OPTIONS preflight are separate sections). |
| `--width N` | Text width, 60 to 300. Default: terminal width, 100 when piped. |
| `--approve NET` | Address or CIDR that may be shown. A run directory adds its own approved networks from `plan.json`, `profile.json`, and `result.json`. |
| `--show-addresses` | Operator copy: every address unredacted, with a banner saying not to attach it to an owner report. |

Exit status: 0 drawn; 2 bad arguments or unusable path; 3 unreadable capture;
4 nothing to draw (no SIP, no TLS, no RTP); 5 internal error or privacy lint
refusal (nothing is written).

## What it draws

One column per endpoint, labelled `address:port` and `caller` / `target` /
`media`. The first request fixes caller and target. Each SIP message is an arrow
with the method or `status reason`, a relative timestamp, and the gap since the
previous message. Marks:

- `[RETRANS #n]` (drawn with `~`): an exact repeat of an earlier message, with
  how long after the original. More than six repeats of one message are folded
  into a count.
- `[AUTH CHALLENGE]` / `[AUTH RESPONSE]`: 401/407 challenges and requests that
  carry Authorization or Proxy-Authorization. Only the scheme is named.
- `offer:` / `answer:` lines under the arrow: media type, address:port, profile
  (RTP/AVP or RTP/SAVP), codec names, direction, ptime. SDES-SRTP shows the
  suite name only.

Media follows the address in the SDP, not the signaling address. When it is the
same host as a signaling endpoint (the usual direct call, whatever the ports),
it shares that endpoint's column. When the SDP names a host that no signaling
message in the call uses (an SBC or proxy in front of separate media servers,
such as the practice proxy: signaling to 127.0.0.3, media at 127.0.0.2), that
host gets its own column labelled `(media)` with its RTP port, and the RTP/RTCP
rows run between the caller and that column. An arrow that passes over another
column leaves that column's line drawn.

Labels are never cut mid-word and tags are never cut. The column gaps grow to
fit the labels (up to `--width`; the HTML widens its drawing). If they still
do not fit, the reason phrase is shortened by whole words first
(`407 Proxy... [AUTH CHALLENGE]`); a label that still cannot fit is shortened
at a word with `...` and the full label is printed under the arrow, and the
tags move to a `tags:` line there. Use a wider `--width` for the full text.

Media is aggregated (`===>`): per direction, packet count, payload types,
first and last time, sequence gaps, and the number of telephone-event (DTMF)
events. RTCP appears as its own aggregate row. TShark decodes RTP from the SDP
in the capture; when SIP is not in the capture, the ports from the softphone
log are used, else RTP heuristics (labelled).

The outcome line states how the call ended (answered and who sent BYE,
rejected with the final status, cancelled, registered after a challenge, no
final response).

## TLS-encrypted signaling

A TLS capture holds no readable SIP. The ladder says so and draws what is
still knowable: TCP SYN/FIN/RST, TLS handshake records, aggregated
application-data volume per direction, and the media. If the run directory has
`softphone.log` (PJSUA prints every SIP message), those messages become the
call sections, marked `source: softphone-log`, and are placed on the capture's
timeline by wall clock. The log's time of day is taken as UTC; a whole-hour
offset that places it inside the capture window is applied and noted. Log
timestamps are PJSUA processing times, so a response can appear a few
milliseconds after the media it triggered.

## Privacy

The same rules as the owner report, enforced twice: the document is built from
redacted values, and every finished rendering is linted (fail closed, with the
`sippycup.evidence` patterns plus ladder-specific ones). Never printed:

- Authorization, Proxy-Authorization, nonces, responses, opaque, realms;
- `a=crypto` key material (the suite name only);
- SIP URIs and user parts (arrows show methods, never request URIs);
- Call-IDs (a 12-hex hash, the same `callIdHash` as the report);
- message bodies other than the SDP summary;
- DTMF digit values (only an event count).

Addresses follow the report: approved addresses are shown, the assessor's
own address is labelled, everything else becomes `unapproved-address-N`. A bare
capture has no approved networks, so pass `--approve` (or `--show-addresses`
for a private operator copy). Reason phrases go through the report sanitizer.

## Robustness

Handled and tested: multiple calls in one capture, IPv6, SIP over TCP with
segmentation and several messages per segment, retransmissions, truncated
frames (warning with a count), TLS, and captures with no SIP (clear message,
exit 4, or a transport/media-only ladder when TLS or RTP exists).
Known limits: a message cut off by a snap length or a lost TCP segment is
missing from the ladder and reported only as a warning count; calls are keyed
by Call-ID (forks share one section); forked INVITEs are not split into legs.

## In the owner report

`summary` is unchanged and does not embed ladders. To attach one, generate the
HTML (without `--show-addresses`) per run and place it beside the report:

```sh
./bin/sippycup ladder work/engagement/calls/RUN_ID --format html \
  --output work/engagement/report/ladder-RUN_ID.html
```

The file has no external assets, follows light and dark mode, and prints on
paper (the plain-text copy is hidden when printing).

## Implementation

`lib/sippycup_ladder/`: `capture.py` (TShark through the oracle's bounded
runner and packet adapter; SDP through the oracle's SDP parser),
`softphone_log.py`, `build.py` (grouping, retransmissions, columns, media
assignment), `render_text.py`, `render_html.py`, `cli.py`. Tests:
`tests/test_ladder.py` with synthetic captures from `tests/ladder_support.py`.
