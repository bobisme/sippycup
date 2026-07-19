# Portable evidence packs

`./bin/sippycup pack` turns a completed or inspectable campaign run into a
self-contained deterministic tar archive. The source directory must already
contain `evidence-manifest.json`; pack creation re-hashes every declared
artifact before writing anything.

```sh
./bin/sippycup pack create work/runs/RUN evidence.tar \
  --image-digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
./bin/sippycup pack verify evidence.tar --format markdown
./bin/sippycup pack export-ci evidence.tar ci-results
```

The archive contains `pack-manifest.json`, the evidence manifest, and exactly
the artifacts declared by that evidence manifest. The pack manifest uses
`sippycup.dev/evidence-pack/v1`; its schema is
[`schemas/evidence-pack-v1.schema.json`](../schemas/evidence-pack-v1.schema.json).
It records the immutable evidence content identity, exact artifact
hashes/sizes/types/provenance/sensitivity, the supplied container image digest,
and a minimal SPDX 2.3 package record. The SPDX record identifies the
Sippycup pack producer; it is deliberately not presented as a complete
dependency SBOM.

Pack creation fixes tar order, modes, owners, and timestamps. Repacking the
same evidence and image digest is byte deterministic.

## Workspace-independent verification

Verification reads archive members as streams and never extracts them. It
rejects:

- changed hashes or sizes;
- missing or undeclared members;
- duplicate archive members or duplicate declarations;
- absolute, backslash, dot, or parent-traversal paths;
- links, devices, directories, and other non-regular members;
- a relabeled pack inventory that differs from the embedded evidence manifest;
- an invalid embedded content identity.

The original workspace, capture tools, and target network are not used.
Verification status is `pass`, `content-failure`, or `signature-failure`.
CLI exit codes are respectively 0, 1, and 3; invalid arguments or unavailable
external tools use 2.

JSON, Markdown, and JUnit are renderings of the same
`sippycup.dev/evidence-pack-verification/v1` result:

```sh
./bin/sippycup pack verify evidence.tar --format json
./bin/sippycup pack verify evidence.tar --format markdown
./bin/sippycup pack verify evidence.tar --format junit
```

## Optional minisign signatures

Sippycup invokes `minisign`; it never creates, imports, copies, stores, rotates,
or deletes a key:

```sh
./bin/sippycup pack sign evidence.tar --secret-key /secure/minisign.key
./bin/sippycup pack verify evidence.tar \
  --signature evidence.tar.minisig \
  --public-key /secure/minisign.pub
```

The secret key remains at the caller-supplied path and minisign owns any
passphrase interaction. Signature verification covers the exact archive
bytes. A bad signature is reported separately from valid or invalid archive
content.

## Optional age recipient encryption

One or more age recipients can be supplied while creating a pack:

```sh
./bin/sippycup pack create work/runs/RUN evidence.tar.age \
  --image-digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --recipient age1example
```

Sippycup creates the plaintext tar only inside a mode-0700 temporary
directory, asks `age` to encrypt it, atomically moves only the encrypted
result, and removes the temporary directory on success, failure, or
interruption. It does not generate or manage age identities. Use the standard
`age --decrypt` workflow outside Sippycup before content verification. The
encrypted file itself may be signed with the same `sign` command.

## Privacy-safe CI export

`export-ci` first requires the embedded privacy lint status to pass, then
writes only `verification.json`, `verification.md`,
`verification.junit.xml`, and `ci-export.json` by default. No capture, decoded
audio, note, report, or other evidence artifact is exported implicitly,
regardless of sensitivity.

If privacy lint is blocked, default export is blocked too. After local review,
the operator can acknowledge those findings explicitly:

```sh
./bin/sippycup pack export-ci evidence.tar ci-results \
  --allow-privacy-findings
```

The acknowledgement is recorded in `ci-export.json`; it does not include any
source artifact.

An artifact is copied only when its exact declared path is explicitly named:

```sh
./bin/sippycup pack export-ci evidence.tar ci-results \
  --allow-privacy-findings \
  --include-artifact report.txt
```

The export manifest records the selected artifact's sensitivity and
`explicitlySelected: true`. Selecting `confidential` or `restricted` content
is an affirmative disclosure decision; CI retention and access policy remain
the operator's responsibility.
