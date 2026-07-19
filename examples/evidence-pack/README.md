# Sanitized portable evidence pack

`sanitized-evidence.tar` is a deterministic, privacy-clean example for
offline import and CI verification. It contains only synthetic metadata and
an empty classic-PCAP header; it contains no call, subscriber, credential,
network-traffic, or audio payload.

Verify it without a source workspace:

```sh
sippycup-pack verify examples/evidence-pack/sanitized-evidence.tar
sippycup-pack export-ci examples/evidence-pack/sanitized-evidence.tar ci-output
```

Reproduce or check the committed bytes:

```sh
python3 tools/generate_sanitized_evidence_pack.py
python3 tools/generate_sanitized_evidence_pack.py --check
```

The all-zero image digest is an explicit fixture sentinel, not a published
container identity.
