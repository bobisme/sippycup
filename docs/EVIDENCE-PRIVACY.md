# Evidence manifests and privacy lint

Every completed campaign run writes `evidence-manifest.json`. The same
inventory can be rebuilt for a completed or interrupted run without contacting
the target:

```sh
sippycup-evidence manifest work/runs/RUN --write
sippycup-evidence lint work/runs/RUN
```

The manifest uses `sippycup.dev/evidence-manifest/v1`; its normative schema is
[`schemas/evidence-manifest-v1.schema.json`](../schemas/evidence-manifest-v1.schema.json).
Each regular source artifact is sorted by relative path and records:

- SHA-256 and exact byte size;
- media type and provenance;
- sensitivity: `public`, `internal`, `confidential`, or `restricted`.

The inventory covers the reviewed source manifest, frozen plan, redacted
commands, event timeline, executable/image and tool versions, preflight,
capture, offline reports, assertions and stats when present, result,
timestamps, and TUI notes/bookmarks. Notes remain separate private metadata.
Decoded audio is always restricted. Captures retaining media payload are
restricted; payload-stripped captures are still confidential.

`contentIdentity` hashes only the manifest schema, sorted artifact records, and
the exact missing-artifact list. Creation time lives in a separate `creation`
envelope with `contentIdentityIncludesCreation: false`. Rebuilding identical
content at another time therefore retains its immutable identity while
honestly recording a new creation event. The manifest excludes itself from
the artifact identity.

Interrupted directories remain inspectable. They receive `runState:
incomplete`, a content identity for everything that exists, and a sorted
`missingExpected` list. Missing output is never fabricated or confused with an
empty successful result.

## Privacy lint

Lint reads source artifacts without rewriting them. Exit status is 0 for
clean or explicitly overridden content, 1 for blocked high-risk findings, and
2 for invalid input or policy. It detects:

- SIP `Authorization` and `Proxy-Authorization` material;
- Call-IDs, SIP users, and international-format phone identifiers;
- literal addresses outside the plan allowlist and any explicit
  `--allow-network` additions;
- decoded audio by extension or file signature;
- captures above `--max-capture-bytes`;
- captures or large artifacts that could not be completely inspected.

Classic PCAP endpoint addresses are parsed from Ethernet IPv4/IPv6 records.
An unparseable or only partially scanned capture fails closed as
`capture-uninspected`. The default capture limit is 512 MiB.

```sh
sippycup-evidence lint work/runs/RUN \
  --allow-network 10.40.0.0/16 \
  --max-capture-bytes 104857600
```

The network addition is an expected evidence range, not permission to send
traffic. Privacy lint never uploads anything.

## Explicit local override

All current privacy findings are high risk and block by default. An override
must be a regular local JSON file outside the evidence root, mode 0600 or
stricter, bound to the exact content identity, and justified:

```json
{
  "apiVersion": "sippycup.dev/privacy-override/v1",
  "localOnly": true,
  "contentIdentity": "sha256:...",
  "allowFindings": ["subscriber-identifier"],
  "justification": "Authorized local incident review"
}
```

Use it explicitly:

```sh
sippycup-evidence lint work/runs/RUN --override /secure/local-override.json
```

The override is never copied into the run or included as an artifact. The lint
result records only its SHA-256 and `localOnly: true`. Changing any source
artifact changes the content identity and invalidates the override. This is an
acknowledgement for local handling, not anonymization and not permission to
share the evidence.

Source PCAPs, notes, reports, and other artifacts are never redacted or
modified by manifest generation or lint. Future packaging may omit an
artifact, but omission must be declared; reversible PCAP anonymization is not
promised.
