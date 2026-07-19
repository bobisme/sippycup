# Golden call behavior comparison

`sippycup-diff` compares a reviewed baseline behavior pack with a candidate
pack entirely offline. Each pack is a directory containing:

- `canonical-model.json`, using `sippycup.learned-dialog/v1`;
- `oracle-result.json`, using `sippycup.results/v1`.

The learned model supplies dialog state, transaction ordering, response
status and timing windows, SDP revisions, codecs, and teardown behavior. The
oracle result supplies endpoint topology, media directions and metrics,
assertion verdicts, and source-frame evidence. Neither input is modified.

```sh
sippycup-diff evidence/baseline evidence/candidate --format human
sippycup-diff evidence/baseline evidence/candidate --format json \
  > behavior-diff.json
sippycup-diff evidence/baseline evidence/candidate --format junit \
  > behavior-diff.xml
```

Exit status is 0 for semantic equality, 1 for a semantic difference, and 2
for an invalid pack or option.

## Versioned normalization boundary

Every result identifies
`sippycup.dev/golden-behavior-normalization/v1`. That rule set normalizes only:

- learned typed placeholders for Call-IDs, tags, branches, CSeqs, contacts,
  signaling/media addresses and ports, message lengths, SSRCs, RTP sequence
  numbers, and RTP timestamps, while preserving their equality relationships;
- raw RTP SSRCs in oracle flow keys;
- raw port numbers above 1023, which are treated as ephemeral;
- capture frame numbers and absolute evidence timestamps;
- a common offset applied to all learned transaction timing windows.

Well-known ports, IP endpoint addresses in oracle topology, transport,
direction, ordering, response status, SDP role and protocol, payload type,
codec, packet time, media metrics, assertion applicability/verdict/observation,
dialog completion, and teardown initiator remain semantic. Missing timing is
never equivalent to a numeric timing value. The explicit
`--timing-tolerance-ms` applies only to response windows and the
`media.timing` observation; its accepted range is 0–5000 ms.

The normalized identity therefore treats regenerated identifiers and a
shifted capture clock as equal without turning codec, endpoint, one-way media,
setup latency, assertion, or post-BYE regressions into false matches.

## One result model, three views

The versioned JSON result is the source of truth and is described by
[`schemas/golden-behavior-diff-v1.schema.json`](../schemas/golden-behavior-diff-v1.schema.json).
Each change has a category, semantic path, baseline and candidate values, and
the available source evidence from both packs. Changes are sorted by path.

Human and JUnit output are pure renderings of that same result. The human view
shows concise before/after values and source frames. JUnit emits one
`baseline-vs-candidate` test case whose failure text is the human rendering,
so CI and interactive review cannot disagree about the underlying changes.
