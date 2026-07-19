# Learned dialog intermediate model

The learner accepts packet-oracle records, selects exactly one complete
dialog, classifies the configured local network as the test-agent role, and
emits `sippycup.learned-dialog/v1`.

Call-IDs, tags, branches, CSeq values, signaling/media addresses and ports,
SSRCs, RTP sequences, timestamps, and absolute packet times become typed,
stable placeholders. The model retains methods, responses, ordering, relative
timing windows, codecs, teardown initiator, optional provisionals, and
source-frame provenance. Captured SIP identities and Authorization values are
not fields in the oracle input model and cannot enter learned serialization.

Learning fails closed for incomplete dialogs, unresolved ambiguity,
multiple/forked legs, invalid local scope, and TLS/SRTP/DTLS captures.
Challenge retries, CANCEL, remote BYE, and successful re-INVITE have
deterministic fixtures. Runnable SIPp generation is a separate review boundary;
this intermediate form never sends traffic.

`generate_pack` converts the model into annotated SIPp XML, a named
secret-reference CSV contract, oracle expectations, deterministic media
references, provenance hashes, a field-disposition report, a README, and an
unreviewed manifest template. Every receive has a finite timeout; SIPp
regenerates message lengths, identifiers, addresses, ports, and SDP endpoints.
Digest actions are generated only when a 401/407 challenge exists and both
username and password are named secret references. The generated target is
`REPLACE_WITH_REVIEWED_TARGET.invalid`, `reviewed` is false, and
`sourcePeerApproved` is false, so execution requires a separate explicit
review boundary.

`validate_pack` executes the generated semantic actions only across an
`AF_UNIX` datagram pair—no IPv4/IPv6 socket or external packet is created. It
captures the reference exchange, loads the generated oracle expectations, and
diffs transaction presence/order, methods, directions, response classes, SDP
codecs, timing windows with an explicit tolerance, and teardown initiator
against `canonical-model.json`. The result records image/Python/tool versions,
the unchanged source-manifest hash, and `authorizationChanged: false`.
Concrete or already reviewed targets are refused by this offline path.

The exit gate also scans every text and binary pack artifact for exact
captured values and populated Authorization header forms. It verifies every
generated file hash against provenance, every receive/pause bound, and an
empty semantic packet diff for baseline, challenge, CANCEL, remote-BYE, and
re-INVITE goldens. Hostile incomplete, multi-dialog, and ambiguous inputs
leave no pack directory behind.
