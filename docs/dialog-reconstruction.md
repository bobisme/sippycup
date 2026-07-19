# SIP dialog reconstruction

`lib/sippycup_oracle/dialogs.py` deterministically reconstructs SIP
transactions and dialog legs from typed packet records. It is read-only and
does not interpret terminal output or packet payload bytes.

Transactions are keyed by Call-ID, CSeq number and method, top Via branch, and
the initiating flow. The flow component prevents identical identifiers on
different network paths from colliding. Responses match only the reverse
flow. Exact repeated requests or responses become retransmission evidence,
while unmatchable responses remain explicit orphans.

Initial INVITE attempts with the same Call-ID, caller tag, and flow form one
call root, allowing a Digest challenge and authenticated retry to remain in
one history. Each distinct remote To-tag becomes a separate dialog leg, so
forks are never forced into a single linear call. Tagged re-INVITE and UPDATE
transactions attach to the matching leg.
Challenge To-tags do not create fork legs. ACK completion is bound to the
exact INVITE CSeq and leg, so an ACK for a challenged attempt cannot satisfy a
later successful attempt.

Every state transition contains an `EvidenceRef` with frame number and
timestamp. Events distinguish provisional and final responses, challenges,
CANCEL, local or remote BYE, re-INVITE, UPDATE, and ACK. A dialog is complete
only for a conclusive sequence:

- successful INVITE, ACK, BYE, and successful BYE response;
- CANCEL success, INVITE 487, and ACK; or
- final failed INVITE and ACK.

Anything less yields a typed `Unknown` completion plus localized evidence.
Confirmed-but-unterminated captures therefore never become complete-dialog
passes. Any relevant truncated, malformed, structurally unknown, ambiguous, or
orphaned signaling also prevents known completion.

SDP revisions follow offer/answer state rather than request/response position.
This includes offerless INVITE with an offer in a reliable provisional or 2xx
response and its answer in PRACK or ACK. SDP revisions retain every
media section. Each section records its own media type, address, port,
transport profile, payload types, codec mappings, direction, ptime, RTCP
endpoint, and telephone-event payloads. Repeated-field association depends on
the adapter’s mandatory TShark `--no-duplicate-keys` invocation and transient
SDP line parsing; raw message bytes are never retained or serialized.

Failed in-dialog re-INVITEs restore the established state. Changed RSeq or SDP
on a provisional response is a new revision, not a retransmission. Route sets
are the reverse of establishment Record-Route order; observed Route headers
remain separate evidence.

The scenario fixture and tests cover baseline completion, Digest challenge,
retransmission, CANCEL, remote BYE, early media, forks, re-INVITE/UPDATE,
incomplete captures, response-only captures, and deliberately colliding
identifiers on different flows.
