# Scope intake

The service owner's written scope used to be copied by hand into three
independent files that could drift apart: the target profile, the campaign
manifest, and the oracle expectations. `./bin/sippycup scope` records the
answers once, checks them, and generates those three files from the one source.

Everything here is offline and host-side. No command resolves names, opens a
socket, or needs a container runtime. Nothing in a scope file authorizes
traffic by itself: the owner's written approval and validity window remain
mandatory, and the generated profile still goes through `rehearse`.

## The scope file

One private scope file per engagement, by default `ENGAGEMENT_DIR/scope.yaml`,
mode 0600, in the versioned format `sippycup.dev/scope/v1`
([`schemas/scope-v1.schema.json`](../schemas/scope-v1.schema.json)). Keep it
under the ignored `work/` tree. A complete placeholder example with every field
annotated is in [`examples/scope/scope.yaml`](../examples/scope/scope.yaml); it
is pending and uses documentation-only addresses, so it cannot compile into an
approved profile.

| Section | Fields |
|---|---|
| top level | `schema_version`, `name` (`[a-z][a-z0-9-]{0,62}`) |
| `authorization` | `status` (`pending`, `approved`, `revoked`), `approval_id`, `approved_by`, `valid_from`, `valid_until` (RFC 3339 with a timezone; unquoted is fine) |
| `signaling` | `networks` (literal IPs or CIDRs), `ports`, `transports` (`udp`, `tcp`, `tls`) |
| `targets[]` | `name`, `address` (literal IP), `transport`, `port`, `tls_server_name` (required for `tls`: the DNS name on the certificate), optional `tls_ca_file` (`tls` only: `work/...` PEM of a private CA; omit for a public CA) |
| `media` | `networks`, `port_range` (`start`, `end`), `protection` (`rtp`, `sdes-srtp`, `dtls-srtp`), `codecs` (`PCMU`, `PCMA`, `G722`, `OPUS`), `dtmf` (`rfc4733`, `sip-info`, `inband`, `none`), `symmetric_rtp` |
| `client` | `source_addresses`: the address(es) the service sees our tests come from, plus the local address your own capture shows when that differs (behind NAT, the private address) |
| `account` | `required`; when true: `username`, `realm`, `credential_ref`, `credential_delivery` |
| `destinations[]` | `name`, optional `target` (implied when there is one target), `user`, `expect` (`echo`, `agent`, `reject`) |
| `limits` | `calls`, `concurrent_calls`, `calls_per_second`, `packets_per_second`, `packets`, `bytes`, `call_duration_seconds`, `total_duration_seconds` |
| `stop_conditions` | `consecutive_failures`, `unexpected_response`, `packet_loss_percent` |
| `test_scope` | `allowed_classes` (the baseline generates `options` and `call`), `exclusions` (write `[none]` for none) |
| `contact` | `name`, `channel`, `can_stop_test` |
| `evidence` | `retention_days`, `disclosure` (`private`, `coordinated`, `public-after-remediation`) |
| `security_checks` | optional: `approved` (check ids from `./bin/sippycup checks list`), `max_requests`; also add `security-checks` to `test_scope.allowed_classes` (see "The one exception" below) |

Per-target TLS server names, dial destinations with expected behavior, the
account identity and credential reference, and expected media protection and
codecs are recorded here so later commands can consume them; today only the
three derivatives below do. The codecs become the profile's optional
`media.codecs`, which `call` and `matrix` treat as the approved codec list
(`GUIDED-CALL.md`, "Codec control").

### Secrets

The file holds credential REFERENCE names only: `credential_ref` is the opaque
name of a secret in your approved external secret source, and
`credential_delivery` records how the owner will deliver it. Any field named
like a password, token, secret, pre-shared key, or private key, and any value
shaped like one (inline `password=...`, PEM blocks, URL or SIP user:password
pairs, bearer tokens, JWTs, long key-like strings) is rejected with
`scope.secret_field` or `scope.secret_value`. The error names the field and
never repeats the value. Unknown fields and duplicate YAML keys are rejected
too. A rejected file produces no derivatives.

## `scope init ENGAGEMENT_DIR`

```sh
./bin/sippycup journal init work/ferivox-assessment
./bin/sippycup scope init work/ferivox-assessment
```

Creates a pending mode-0600 `scope.yaml` containing no addresses, approval, or
limits (`status: pending`, everything else null or empty). It refuses to
overwrite an existing file. The directory must already exist. `scope init`
works whether or not the directory already has a journal, and `journal init`
works in an existing directory that has no journal yet, so either order is fine.
`--name` sets the engagement name (default: a slug of the directory name).

## `scope questions [ENGAGEMENT_DIR]`

Renders a plain-text/Markdown question sheet to send to the service owner. It
covers the approval identifier and approver, the validity window with timezone,
literal signaling and media addresses or CIDRs, ports and transports, the TLS
server name, whether calls need an account and how the password will be
delivered (never the password), destinations and what each should do, RTP or
SRTP (SDES, DTLS), codecs and DTMF, the media port range, every ceiling, stop
conditions, symmetric RTP for clients behind NAT, test classes and exclusions,
the live contact, and evidence retention and disclosure. It also asks for the
source address your tests will come from.

Without a directory the output is generic and contains nothing from any
engagement. With a directory, each question is marked `answered`,
`unanswered`, or `not-applicable`; values are never echoed. If the scope file
is invalid, nothing is marked and the sheet says so.

## `scope check ENGAGEMENT_DIR`

Network-free validation. Human output by default, `--format json`
(`sippycup.dev/scope-check/v1`) for automation. Exit 0 only when the scope is
complete and consistent; 1 when findings exist; 2 when the file is absent.
Every finding has a stable `code`, a `field` path, a `kind`, and the derived
artifacts it blocks.

| Code | Meaning |
|---|---|
| `scope.missing` | An answer is unanswered (field says which) |
| `scope.malformed` | Wrong type, format, enum value, or duplicate |
| `scope.unknown_field`, `scope.secret_field`, `scope.secret_value`, `scope.schema_version`, `scope.unreadable`, `scope.not_object` | Structurally invalid file |
| `scope.not_found` | No scope file |
| `scope.authorization_not_approved` | `status` is not `approved` |
| `scope.window_not_started`, `scope.window_expired`, `scope.window_order` | Validity window problems, judged against the clock |
| `scope.target_outside_networks` | A target address is outside `signaling.networks` |
| `scope.port_not_approved`, `scope.transport_not_approved` | A target uses an unapproved port or transport |
| `scope.tls_server_name_missing` | A TLS target has no server name |
| `scope.tls_ca_unreadable` | `tls_ca_file` is not a readable PEM CA certificate beneath `work/` (or holds a private key) |
| `scope.tls_ca_without_tls` | `tls_ca_file` on a target whose transport is not `tls` |
| `scope.credential_ref_missing` | An account is required but no credential reference name is recorded |
| `scope.concurrency_exceeds_calls` | More concurrent calls than total calls |
| `scope.ceiling_infeasible` | The ceilings cannot hold one baseline call (see below) |
| `scope.placeholder_value` | A documentation range, `example.*`, `.invalid`, or placeholder word that `campaign plan` would reject |
| `scope.destination_target_unknown` | A destination names an unknown target |
| `scope.media_ports_invalid` | The media port range start is above its end |
| `scope.class_excluded`, `scope.no_baseline_class` | Test classes contradict the exclusions or allow no baseline case |
| `scope.contact_cannot_stop` | The live contact cannot stop the test |
| `scope.ceiling_low_rate`, `scope.network_too_broad`, `scope.media_not_enumerable` | Warnings |

## `scope compile ENGAGEMENT_DIR`

Generates, atomically and mode 0600, into the engagement directory:

- `target-profile.yaml`, the name `status` looks for. It carries the first
  target, every target address (and single-host media address) as
  `approved_addresses`, the approval and window, the limits (`max_duration_seconds`
  is the per-call duration), and SRTP features from `media.protection`. It is
  `approved` only when the whole scope checks clean; otherwise it stays
  `pending` and `rehearse` blocks it.
- `campaign.yaml`, a baseline manifest: one `options` and one `call` case per
  approved target (a `call` case only for a target that has a destination),
  with the campaign ceilings and stop conditions taken directly from the scope.
  The scope's `approval_id`, `valid_from`, and `valid_until` become the
  manifest's `authorization.approval` (`id`, `validFrom`, `validUntil`, in
  UTC), so `campaign plan` and `campaign run` are bound to the same window as
  the profile (see `CAMPAIGN-MANIFEST.md`, "Approval window").
  Per-case budgets are conservative upper bounds: OPTIONS gets 4 packets, 4096
  bytes, 3 seconds; a call gets the smaller of 20 seconds and what the ceilings
  leave, about 100 packets per second per direction plus signaling at 256 bytes
  each, shared evenly across targets. A call needs at least 5 seconds, 24
  packets, and 8192 bytes to fit, otherwise `scope.ceiling_infeasible`.
  Each `call` case dials (`dial.user`) the `user` of the first destination on
  its target whose `expect` is not `reject`; a target whose destinations all
  reject gets no `dial`, so nothing is invented. When `account.required` is
  true, every target carries `credentialRef: <account.credential_ref>` and
  `account: {username, realm, register: true}` from the scope (registration
  first, like the guided call). Such calls run on the softphone campaign
  runner (see `CAMPAIGN-MANIFEST.md`). A destination `user` or account
  `username` outside the manifest's stricter grammar (letters, digits, and
  `+ * . _ -`; for example one containing `#` or `@`) fails the manifest
  validator, so `campaign.yaml` is skipped with that reason.
- `expectations.yaml`, the oracle expectations: allowed endpoints (target
  addresses, enumerated media addresses up to 1024, and your source addresses),
  expected codecs, bidirectional media when a destination echoes or answers,
  and symmetric RTP. DTMF is never required: the scope records which method
  the service supports, and a baseline call sends no digits.

Generated artifacts are validated with the real code paths before they are
written: `rehearse` on the profile (with the compile-time clock), `campaign
plan`'s compiler on the manifest, and the oracle expectations loader. One that
fails is not written.

If part of the scope is unanswered, only the artifacts that depend on it are
skipped, and the output says which and why; the profile is written as
`pending` whenever its own structural inputs exist. The campaign manifest also
depends on the authorization answers because a manifest carries no approval of
its own (only its window, copied from these answers). Nothing is invented: no
placeholder host, approval, or limit is ever substituted. Exit 0 only when all three were written and the scope is clean; 1
when some were skipped or the profile is pending; 2 for an invalid scope file
or a refusal.

### Signaling and media on different addresses

Behind a proxy or SBC, answer `signaling.networks` and the targets with the
proxy's address and `media.networks` with the media servers: their literal
addresses, or the media-server pool as a range (CIDR), which is how most
owners approve media. `scope compile` writes them so:

| `media.networks` answer | Profile | Admits |
|---|---|---|
| a literal address (`198.51.100.7`) or a `/32` | `target.approved_addresses` (after the target) | media; the profile already treats literal approved addresses as reachable |
| a range (`198.51.100.0/27`) | `media.networks` | media ONLY: never a signaling target |
| `media.port_range` | `media.port_range` | the far end's RTP ports; a media port outside it stops the call |

The campaign manifest puts the signaling networks in
`authorization.networks` and every media network no signaling network
already contains in the media-only `authorization.mediaNetworks`, so the
campaign planner never accepts a media server as a signaling target; its
capture and watchdog include the media (see `CAMPAIGN-MANIFEST.md`, "Media
on other addresses"). Media networks beyond the breadth rule below are
merged into `authorization.networks` as before. The expectations list every
address (up to 1024), and the guided call, the call matrix, and `srtp-policy` accept
a media peer that is a literal approved address or lies inside a
`media.networks` range. Signaling is never widened: `target.host` must still
be one of the literal `approved_addresses`, so a call whose host lies inside
a media range is refused before any packet. Each run records which rule
admitted the media peer (`result.json` `mediaScope.admittedBy`:
`approved-address` or `media-network` with the range).

Breadth rule. A media range in the profile holds at most 1024 addresses
(IPv4 `/22` or narrower, IPv6 `/118` or narrower), at most 1024 in total and
at most 16 ranges, with no host bits set, and none containing unspecified,
multicast, reserved, or broadcast addresses (`0.0.0.0/8`, `224.0.0.0/4`,
`240.0.0.0/4`, `255.255.255.255`, `::`, `ff00::/8`). A real media-server
pool is a few dozen to a few hundred addresses; anything wider is more likely
a copied "any" or a whole provider block. 1024 is also the most the packet
oracle's literal allowlist carries, so every admitted address is still
checked offline. `scope check` reports a wider range as
`scope.media_network_too_broad` (an error that blocks only the profile; the
campaign manifest is still generated) and a range of more than 256 addresses
as the warning `scope.media_network_wide`; `rehearse` refuses a profile that
breaks the rule. Either message says what to ask the owner for: the exact
media-server pool(s), each of at most 1024 addresses, or the literal media
addresses.

Leave the media address out and the guided call ends `media-outside-scope` as
soon as the peer is known, a safety stop that the cockpit marks `[stop]` and
the owner report discloses as an integrity exception with the RTP packets sent
before the hangup. `./bin/sippycup practice-target rehearsal --proxy`
rehearses exactly this shape and that stop, and `rehearsal --media-cidr` the
same with media answered as a range (see `PRACTICE-TARGET.md`).

### What is not generated

Hostnames (targets are literal addresses), media CIDRs larger than 1024
addresses (the oracle takes literal endpoints, so expectations are skipped;
the profile is not generated either, see the breadth rule above), media
ranges in the profile's `approved_addresses` (they go to the media-only
`media.networks`), a final-status expectation
for a destination that should reject, capture settings other than the profile
defaults, and anything about test classes beyond `options` and `call`. A
profile represents one target; the manifest carries all of them.

A guided call or a call matrix over a second target (for example the TLS
target next to a UDP first target) needs a profile for it, and compile writes
only the first. Copy the generated profile to a new name in the same
directory (for example `target-profile-tls.yaml`), change only `name`,
`target.port`, `target.transport`, and for TLS add `target.tls_server_name`
and `target.tls_ca_file` exactly as the scope's second target says, then run
`rehearse` on the copy. Keep the approval, window, addresses, and limits
unchanged. The copy is not a managed derivative, so compile neither updates
nor refuses because of it: copy it again after every `scope compile`.
`summary` checks its runs against the scope like any other run.
[FIRST-ENGAGEMENT.md](FIRST-ENGAGEMENT.md) shows the copy step.

The one exception is the `security_checks` answer. When `test_scope.allowed_classes`
includes `security-checks`, `scope check` validates `security_checks.approved`
against the reviewed catalog. It also checks each check's prerequisites
against the first target, and the summed request bounds against
`security_checks.max_requests`, `limits.packets`, and `limits.calls`.
`scope compile` then copies the list into the profile, with the account
username, the first destination's user, and (for a TLS first target) the
approved cleartext signaling ports. See `SECURITY-CHECKS.md`.

### Staleness and hand edits

The profile and manifest reject unknown fields, and the expectations loader
rejects unknown keys, so no hash can live inside the derivatives. Compile
instead writes one sidecar, `scope-derivatives.json` (mode 0600), recording the
scope file's SHA-256, each derivative's path and SHA-256, the scope hash each
was generated from, the generation time, and what was skipped.

`status` (and `derivative_state`) report each derivative as `current`, `stale`
(the scope changed since it was generated), `edited` (its hash no longer
matches), or `missing`. Any of these makes the overall state `stale`, a
blocker, with `scope compile` as the next safe action. A sidecar that cannot be
read is `invalid` and treated the same way.

Compile never silently clobbers. It overwrites a derivative only if the sidecar
records it and its hash still matches. A derivative that was edited by hand
(`scope.derivative_modified`) or that exists without a sidecar record, such as a
profile from `init` (`scope.derivative_unmanaged`), makes compile refuse and
write nothing; `--force` overwrites it. The sidecar is an aid against honest
mistakes, not a tamper-proof seal: anyone who can edit the derivatives can edit
the sidecar.

### Revoking or changing an approval

`campaign run` reads `scope.yaml` beside the manifest before the run and
before every step. Set `authorization.status: revoked` there and no campaign
starts, and a running one stops before its next step
(`authorization_lapsed`). After any change to the approval id or window,
run `scope compile`, move the old `plan.json` aside, and run `campaign plan`
again: a plan frozen from the old window is refused. `call`, `matrix`, and
`checks` read the profile instead, so always run `scope compile` after the
change.

## Advisor

`./bin/sippycup status ENGAGEMENT_DIR` recommends `scope init` and `scope
questions` first when no scope file exists. When one exists it reports the check
result, recommends `scope check` while it fails, and reports stale derivatives
with `scope compile` as the next action. Every recommended action is
network-free.
