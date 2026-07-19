# Evidence pack exit gate

The portable-pack exit gate is implemented by
`tests/test_evidence_pack_exit_gate.py` and the lower-level adversarial tests
in `tests/test_evidence_pack.py`.

The gate covers:

- reproducible verification of the published sanitized pack after copying it
  away from its source workspace and changing the working directory;
- mutation of every logical archive member's content and path;
- modified, missing, duplicate, traversal, non-canonical, undeclared, and
  sensitivity-relabeled archive members;
- exact archive-byte integrity through an optional minisign signature;
- privacy-blocked Authorization, Call-ID, and decoded-audio fixtures;
- reports-only CI export after explicit privacy acknowledgement, with byte
  scans proving those fixtures do not leak;
- interrupted/incomplete evidence with preserved missing-artifact state;
- identifier/time-origin golden-diff equivalence and codec, one-way-media,
  and assertion regression detection;
- real container interoperability with the documented minisign and age
  commands.

Run the automated gate:

```sh
python3 -m unittest tests.test_evidence_pack_exit_gate -v
python3 tools/generate_sanitized_evidence_pack.py --check
```

The published sample is
[`examples/evidence-pack/sanitized-evidence.tar`](../examples/evidence-pack/sanitized-evidence.tar).

## Integrity boundary and limit

Unsigned verification authenticates the logical pack structure against its
embedded immutable evidence identity: declared paths, member metadata,
content hashes, sizes, sensitivity, and canonical ordering. A self-contained
unsigned archive cannot authenticate otherwise-unused tar padding against an
external expectation. Use the optional minisign signature when exact archive
bytes—including padding—must be authenticated. The gate mutates such a byte
and requires the signature path to reject it.

The sample's all-zero image digest is a documented fixture sentinel. Real
packs must record the actual inspected image digest.
