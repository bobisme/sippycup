# Security posture checks

`./bin/sippycup checks` runs a reviewed catalog of low-volume SIP edge
posture checks against one owner-approved target and writes findings. Every
check declares the most requests it can send. The transport layer counts
each request before it is sent and refuses the one that would pass the bound.
Nothing runs unless the target profile names the check.

This is a posture review. It is not a scanner, a fuzzer, or a password
tester. See [Non-goals](#non-goals).

```sh
./bin/sippycup checks list
./bin/sippycup checks explain nonce-replay
./bin/sippycup checks plan work/engagement/profile.yaml
./bin/sippycup checks run work/engagement/profile.yaml --dry-run
./bin/sippycup checks run work/engagement/profile.yaml --secret-env ACCOUNT_PASSWORD
```

`list`, `explain`, and `plan` run on the host. They do not resolve names,
open sockets, or start a container, and they end with
`Network activity: none`. `run` always runs in the prepared image with a
private network namespace (like `call`). It rejects `--admin`, and it
composes with `--practice` for the local practice target
(`PRACTICE-TARGET.md`). `run --dry-run` prints the plan and sends nothing.

## The catalog

| Check | Impact | Max requests | Needs | What it looks at |
|---|---|---|---|---|
| `banner-disclosure` | passive | 1 | - | `Server`/`User-Agent` in one OPTIONS answer: product and version disclosure |
| `options-methods` | passive | 1 | - | `Allow`/`Supported` in the same kind of answer: methods beyond basic calling (inventory only) |
| `tls-certificate` | passive | 2 | tls | Verified handshake for the reviewed name; on failure, one more handshake only to read the certificate: name, chain, expiry, key size, signature |
| `tls-protocols` | passive | 9 | tls | One handshake each: TLS 1.0, 1.1, 1.2, 1.3, then NULL, EXPORT, RC4, 3DES, and anonymous suites. A probe that the local TLS library cannot offer is reported `untestable` and is not sent |
| `cleartext-signaling` | passive | 1 per endpoint (at most 8) | tls, `cleartext_endpoints` | One OPTIONS to each owner-listed cleartext UDP/TCP port on the TLS target's address |
| `unauthenticated-register` | active | 1 | account | One REGISTER *query* (no `Contact`, RFC 3261 10.2.3), so no binding is ever made |
| `digest-quality` | active | 1 | account | The Digest challenge: algorithms (MD5 only), `qop`, nonce length and variety, internal realm. It reuses the challenge from `unauthenticated-register` when there is one (0 requests) |
| `unauthenticated-invite` | active | 4 | destination | One INVITE with an `a=inactive` SDP to the approved destination. It is always ended correctly: ACK for a final failure, CANCEL then ACK for a provisional answer, ACK then BYE for a 2xx |
| `user-enumeration` | active | 10 | account | The account against one random name (`sc` plus 12 hex digits), once by REGISTER query and once by INVITE (when a destination is approved). Different answers are a finding; timing is reported but never used as evidence |
| `nonce-replay` | active | 3 | account, password | A challenge, one authenticated REGISTER query, then the same `Authorization` header again. If the replay is accepted, that is a finding. A wrong password ends the check, and nothing is retried |
| `srtp-policy` | - | 0 | - | Planned. Listed so that it can be discussed, but it cannot be approved or run |

A *request* is one SIP request message, including the ACK, CANCEL, or BYE
that ends an INVITE, or one TCP connection made only for a TLS handshake
probe. Over TCP or TLS, the connection attempt counts as its first request.
A refused or unverified connection put packets on the wire, so it is counted
even when no SIP was sent.

`./bin/sippycup checks explain ID` prints the purpose, the exact requests, the
bound, the possible findings with their severities, the remediation, and the
references for each check.

## Approval: default deny

`run` and `plan` refuse (exit 2, nothing sent, no run directory) unless all
of these are true:

- `rehearse` passes for the profile: approved status, an open validity
  window, literal approved addresses, finite limits. The host must be one of
  the profile's `approved_addresses`.
- The profile has a `security_checks` section, and each check to run is
  listed in `security_checks.approved`. A check that is not listed is
  `not-approved` and gets no packet. `--only ID` can only narrow the list.
- The sum of the bounds of the checks that will run is at most
  `security_checks.max_requests` (1 to 200).
- The INVITE attempts (`unauthenticated-invite` 1, `user-enumeration` 2) are
  at most `limits.max_calls`.

```yaml
security_checks:
  approved: [banner-disclosure, options-methods, unauthenticated-register,
             digest-quality, unauthenticated-invite, user-enumeration, nonce-replay]
  max_requests: 40
  account: alice              # the account to compare and to authenticate as
  destination: "9196"         # the user part to INVITE
  cleartext_endpoints:        # TLS targets only; only these are probed
    - {transport: udp, port: 5060}
```

`rehearse` validates this section. It rejects unknown, planned, placeholder,
and duplicate ids, and unknown fields. A check whose prerequisite is missing
(for example `tls-certificate` on a UDP target, or `nonce-replay` without a
secret) is `skipped` with the reason, and it does not fail the run.

The account password comes only from `--secret-env NAME` or
`--secret-file PATH` (mode 0600 beneath `work/`). It is the same mechanism
that `call` uses. The value never appears in argv, events, logs, or any
artifact, and every artifact is scanned for it before it is written.

With scope intake, the owner answers the `security_checks` question
(`SCOPE-INTAKE.md`). `scope check` validates the list against the catalog and
the scope's limits. `scope compile` carries it into `target-profile.yaml`.

## Execution rules

- One request at a time, at least 1 second apart. Only the ACK, CANCEL, or
  BYE that ends an INVITE is sent without waiting.
- Nothing is retried. A timeout is reported as a timeout.
- A check that tries to send more than its declared bound gets an internal
  error. The request is refused before it is sent, the check is `error`, and
  the run stops with exit 3. A unit test proves this with a stub that
  receives exactly one packet.
- Capture is scoped to the target address and starts before the first
  packet. If the capture fails, the run stops with exit 3 and sends nothing.
- If an unauthenticated INVITE progresses or an unauthenticated REGISTER is
  accepted, the remaining active checks are skipped. Use
  `--continue-after-finding` to run them. A 5xx answer (other than 501) also
  stops the run.
- SIGINT or SIGTERM stops after the current transaction. It still ends an
  open INVITE correctly.

## Results

Each run writes a mode-0700 directory beneath the profile's directory
(`checks/`), or beneath `--run-root`. The directory contains:

| File | Content |
|---|---|
| `findings.json` | The v1 findings document (`schemas/findings-v1.schema.json`) |
| `checks-detail.json` | Per-check facts: probe outcomes, certificate fields, step lists |
| `transcript.jsonl` | Every counted request with its check, label, and time |
| `capture.pcap`, `capture.log` | The scoped capture and its log |
| `plan.json`, `profile.json`, `timestamps.json` | The approved plan, the profile as used, and the run times |
| `result.json`, `evidence-manifest.json` | Exit code and totals, and SHA-256 hashes of every artifact |

`findings.json` has this shape. Other tools read it, so it does not change
within v1:

```json
{
  "apiVersion": "sippycup.dev/findings/v1",
  "target": {"address": "127.0.0.2", "port": 5060, "transport": "udp", "serverName": null},
  "generatedAt": "2026-11-18T03:21:18.123104Z",
  "checks": [{"id": "nonce-replay", "status": "finding", "requestsSent": 3,
              "summary": "replay accepted (SIP/2.0 200 OK)"}],
  "findings": [{
    "id": "nonce-replay.accepted", "checkId": "nonce-replay",
    "title": "Replayed digest credentials are accepted",
    "severity": "medium", "confidence": "high",
    "summary": "The same Authorization header (same nonce and nonce count) was accepted a second time.",
    "evidence": [
      {"kind": "challenge", "detail": "algorithm MD5, qop auth, nonce 17949720..."},
      {"kind": "status-line", "detail": "authenticated: SIP/2.0 200 OK"},
      {"kind": "status-line", "detail": "replayed (same nonce, nc=00000001): SIP/2.0 200 OK"}
    ],
    "remediation": "Track the nonce count per nonce and reject a repeated or lower count; ...",
    "references": ["RFC 7616 section 3.3", "RFC 7616 section 5.5", "CWE-294"]
  }]
}
```

Check status is one of `passed`, `finding`, `skipped`, `not-approved`, and
`error`. Findings are sorted most severe first. Evidence quotes are at most
160 characters, nonces are truncated, and `artifact` is present only when an
evidence item names a file in the run directory.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Completed, with no finding at or above `--fail-on` (default `medium`) |
| 1 | Completed, with at least one finding at or above `--fail-on` |
| 2 | Refused before any packet: not approved, over budget, outside the window, or a bad argument |
| 3 | Run error: capture failure, a check error, an exceeded bound, or an interruption |

A finding is a candidate. Confirm it as `ASSESSMENT-WORKFLOW.md` describes
before you report it.

## Practice target

Against the local Asterisk practice target, a UDP run sends 14 requests. It
finds a product banner (info), extra methods (info), MD5-only Digest (low),
and an accepted nonce replay (medium; Asterisk does not track nonce counts).
Unauthenticated REGISTER and INVITE are challenged, and user enumeration
gets identical answers. A TLS run sends 9 requests. The certificate verifies
(the generated leaf is short-lived, so it is `expiring`). Only TLS 1.2 is
accepted (`no-tls13`, info), and cleartext 5060 answers too (medium).

`make checks-gate` (opt-in, needs both images) runs both profiles through
`./bin/sippycup --practice checks run` and asserts each of these outcomes. It
also asserts that the requests in each run's own capture equal the reported
`requestsSent` sum, that the password appears nowhere in the run directory,
and that a profile without `security_checks` is refused with zero packets.

## Non-goals

These checks never do the following:

- Guess passwords, try more than the one owner-supplied password, or brute
  force anything.
- Scan for extensions or users. `user-enumeration` compares one known
  account with one random name, once per method.
- Flood, load test, or send malformed messages (see the separately approved
  torture and chaos tooling).
- Exploit anything, or test whether an advertised method works without
  authentication. `options-methods` is an inventory only.
- Scan ports. Only the target port and the owner-listed cleartext endpoints
  are contacted.
- Make a registration binding, or let a call carry media. A REGISTER is
  always a query, and an INVITE offers an inactive stream and is always
  ended.
- Resolve host names. Targets are literal approved addresses, and the TLS
  name is used only for SNI and verification.
- Test SRTP policy yet (`srtp-policy` is planned).
