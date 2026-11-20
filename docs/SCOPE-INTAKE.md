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
| `platform` | optional: `name`, `components`, `out_of_scope`, `environment`, `third_parties`, `dialing`, `operations`, `addressing` (see "Platform and application answers" below) |
| `application` | optional: `surfaces`, `identities`, `object_classes`, `route_inventory` (same section) |

Per-target TLS server names, dial destinations with expected behavior, the
account identity and credential reference, and expected media protection and
codecs are recorded here so later commands can consume them; today only the
three derivatives below do. The codecs become the profile's optional
`media.codecs`, which `call` and `matrix` treat as the approved codec list
(`GUIDED-CALL.md`, "Codec control").

### Secrets

The file holds credential REFERENCE names only: `credential_ref` is the opaque
name of a secret in your approved external secret source (spell it with
lowercase letters, digits and `-`, starting with a letter, at most 63
characters: `acme-password`, not `ACME_PASSWORD`), and
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
overwrite an existing file. The directory must already exist; when it does
not, `scope init` creates nothing and prints the complete `journal init DIR
--title "..." --owner "..."` command to run first. `scope init`
works whether or not the directory already has a journal, and `journal init`
works in an existing directory that has no journal yet, so either order is fine.
`--name` sets the engagement name (default: a slug of the directory name).
`--platform` also writes the empty `platform` and `application` sections
(question sheet part 2); use it when the test covers a whole product, not one
SIP service.

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

The sheet has two parts. Part 1 is the SIP service (the numbered questions
above). Part 2, "the whole platform", has questions P1 to P18 and A1 to A6 in
plain words, each with a "Why we ask" line: what is in and out of scope,
production and real customers, the other companies involved, where test calls
go, the limits on a live system, names versus addresses, and the web, API, and
browser-calling surfaces. Part 2 is always printed, so the owner sees it even
when the scope file does not record it yet.

Without a directory the output is generic and contains nothing from any
engagement. With a directory, each question is marked `answered`,
`unanswered`, or `not-applicable`; values are never echoed. If the scope file
is invalid, nothing is marked and the sheet says so. A part 2 question can
also be `pending` or `unknown` (see below); it is `not-applicable` only when
the owner's own answer rules it out.

## `scope answer ENGAGEMENT_DIR [QUESTION]`

Records the owner's written answers in `scope.yaml` for you, question by
question. You do not have to write YAML. Editing `scope.yaml` by hand stays
possible and gives the same result: `scope check` and `scope compile` read the
file the same way.

```sh
./bin/sippycup scope answer work/acme              # every open question, in sheet order
./bin/sippycup scope answer work/acme 11           # one question (here: destinations), to add or change
./bin/sippycup scope answer work/acme limits.calls # the question that asks this field
./bin/sippycup scope answer work/acme --all        # every question, also the answered ones
./bin/sippycup scope answer work/acme --set limits.calls=40 --set media.codecs=PCMU,PCMA
```

For each question it prints the question exactly as the owner saw it on the
sheet (`scope questions`), then asks its answers one field at a time: what a
valid answer looks like, the current value, and a prompt. Structured answers
are asked field by field: each target (name, literal address, transport,
port, and for TLS the certificate name and the CA file), each destination
(name, target, what to dial, what it should do), the window (the timezone the
owner used, then the start and the end), the media port range, and every
ceiling. QUESTION is the sheet number (1 to 24, P1 to P18, A1 to A6), the id
(`destinations`, `authorization.window`), or a field (`limits.calls`,
`targets`).

At every prompt:

| You type | Result |
|---|---|
| the answer | it is checked; if it is accepted it is saved at once |
| Enter | the owner has not answered yet: the question stays open (a recorded answer is kept). Nothing is invented. |
| `pending`, `unknown` | for platform and application answers (part 2) only: the open answers of that format |
| `?` | how to write a valid answer |
| `clear` | removes a recorded answer; the question is open again |
| `quit` | stops; every answer accepted so far is already saved |

Ctrl-C and Ctrl-D (end of input) also stop. The file is then valid and has
every answer accepted before; a target or destination that was half typed is
not written.

**Checks.** Each answer is checked with the same code as `scope check`: the
answer goes into a copy of the document and the copy is checked. An answer
that would add an error for its own field is refused with the reason, and the
prompt asks again. Examples: a hostname where a literal address belongs
(`sip.acme.tld` for a target address or a network), a documentation address
(`192.0.2.7`), a target outside the signaling networks or on a port that is
not approved, more concurrent calls than calls, a malformed credential
reference, and anything that looks like a password, token, or key (it is not
written). An answer that contradicts ANOTHER recorded answer (for example
signaling networks that no longer contain a target) is shown with the error
`scope check` would report; it is recorded only when you type `y`. A window
that has not started yet (or has ended) is recorded with a `NOTE`, because it
is what the owner wrote: `scope check` keeps reporting it until the window is
open.

**Window.** Type the timezone the owner used (`Europe/Amsterdam`, `UTC`,
`+01:00`), then the start and the end as the owner wrote them
(`2026-12-01 09:00`). They are written as RFC 3339 with that date's offset
(`2026-12-01T09:00:00+01:00`, daylight saving time included), and the prompt
shows each one in UTC. The end may also be relative to the start (`+8h`). For
the practice target, `now` and `+4h` give a window that is open now.

**The approval.** `authorization.status: approved` is recorded only when you
type the word `approved` at the approval prompt (question 2, asked after the
window). The prompt shows the reference, the approver, and the window, and
says that typing it asserts that the owner approved this scope in writing. It
is refused until the reference, the approver, and the window are recorded.
`yes` is not accepted, `--set` never sets it, and nothing else sets it.

**Secrets.** The password is never asked for. The credential reference prompt
explains the format (a name such as `acme-password`, lowercase letters, digits
and `-`) and refuses a value that is the content of
`ENGAGEMENT_DIR/account.password`.

**The file.** Only `scope.yaml` is changed (and nothing at all while the file
is invalid: fix the line `scope check` names by hand first). Every write is
atomic (a temporary file in the same directory, then a rename) and leaves the
file mode 0600. PyYAML, the YAML library here, cannot keep comments when it
writes a document, so `scope answer` edits the text instead: it replaces only
the value of the answered field, and keeps every comment, blank line, the key
order, and every answer it did not ask about byte for byte. After each edit it
reads the file back with the `scope check` loader and requires exactly the
intended answers. When an unusual layout makes that impossible, it says so
before the write (`its comments are NOT kept`), writes the whole document, and
keeps the previous file beside it as `scope.yaml.bak-STAMP` (mode 0600). If
`scope.yaml` changes on disk during a session (another editor), it writes
nothing more and stops.

**Optional question 24.** The walk does not ask the security checks question;
the summary prints the command that does (`scope answer DIR 24`). The approved
ids and `max_requests` are checked together, and `security-checks` is added
to `test_scope.allowed_classes` with them.

**Without a terminal.** Answers can come on standard input, one per line;
each answer is echoed after its prompt, so a log reads like a session.
`--set FIELD=VALUE` (repeatable) records plain answers without prompts:
everything that is one field (`limits.calls`, `media.codecs`, `contact.name`,
`signaling.networks`, and the one-field platform answers). Targets, destinations, the
window, and the approval are refused there. All `--set` values are checked
together; if one is refused, nothing is written (exit 2).

**The end.** It runs the same check as `scope check` and prints its findings
(the `scope.missing` lines are counted, not listed), the questions that are
still open by number, and the exact next command: `scope answer` again while
questions are open, `scope check` when an answer must be corrected, or
`scope compile` when the scope is complete and consistent. Exit 0 when the
scope checks clean, 1 when findings remain, 2 for a refusal, 130 after Ctrl-C.
`Network activity: none`.

## `scope check ENGAGEMENT_DIR`

Network-free validation. Human output by default, `--format json`
(`sippycup.dev/scope-check/v1`) for automation. Exit 0 only when the scope is
complete and consistent; 1 when findings exist; 2 when the file is absent.
The human output ends with a `Next:` line: `scope compile` when the scope is
clean, otherwise `scope answer` (or a hand edit) for the answer to record or
correct.
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
| `scope.pstn_destination_unconfirmed`, `scope.carrier_answer_conflict`, `scope.destination_never_dial`, `scope.limit_exceeds_production` | Platform answers that hold the profile and the campaign (see "Platform and application answers") |
| `scope.reach_unknown_destination`, `scope.surface_address_mismatch`, `scope.surface_component_conflict`, `scope.tls_ca_conflict` | Two platform or application answers contradict each other |
| `scope.production_safety_open`, `scope.third_party_unresolved`, `scope.destination_reach_open`, `scope.surface_not_ready`, `scope.address_shared`, `scope.address_changing`, `scope.platform_open` | Warnings: open platform or application answers |

## `scope compile ENGAGEMENT_DIR`

Generates, atomically and mode 0600, into the engagement directory:

- `target-profile.yaml`, the name `status` looks for. It carries the first
  target, every target address (and single-host media address) as
  `approved_addresses`, the approval and window, the limits (`max_duration_seconds`
  is the per-call duration), and SRTP features from `media.protection`. It is
  `approved` only when the whole scope checks clean; otherwise it stays
  `pending` and `rehearse` blocks it. It also carries
  `target.approved_destinations`: the `user` of every destination the scope
  lists for that target (see "Approved destinations" below).
- `target-profile-NAME.yaml`, one for each further entry of `targets`, where
  NAME is that target's `name` (see "One profile per target" below).
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
placeholder host, approval, or limit is ever substituted. Exit 0 only when
every derivative (one profile per target, the manifest, and the expectations)
was written and the scope is clean; 1
when some were skipped or the profile is pending; 2 for an invalid scope file
or a refusal.

### Approved destinations

The owner approves what may be dialed: `destinations[]` in `scope.yaml`.
Compile writes the `user` of each destination into the profile of its
target, as `target.approved_destinations`. `call` (also with `--dry-run`) and
`matrix plan|run` compare `--dial` with that list, exactly and with the same
upper and lower case. A value that is not on the list (a typo such as `ecoh`,
or a number the owner did not list) is refused with exit 2 before anything
starts: no capture, no preflight, no call. The message names the approved
destinations:

```text
Guided call: BLOCKED
BLOCK: destination 'ecoh' is not one of the destinations the owner approved for this target (approved: echo, dtmf); check the spelling, or ask the owner, record the new destination under destinations in scope.yaml, and run scope compile
Nothing was started and no packets were sent.
Network activity: none
```

To dial a new destination, get the owner's written approval, add it to
`destinations` in `scope.yaml` (with `target:` when the scope has more than
one target), and run `scope compile`. Do not edit the profile: a hand edit
is reported as an edited derivative and blocks the next compile.

- Every destination of the target is on the list, also one with
  `expect: reject`.
- A target with no destination gets an empty list. Its profile approves no
  call destination, and `rehearse` prints `Destinations: none`.
- The list holds at most 64 entries of 1 to 64 characters from letters,
  digits, and `. _ + * # -` (the characters `destinations[].user` accepts).
  `rehearse` refuses a profile whose list breaks these rules, or whose
  `security_checks.destination` is not on it.
- `rehearse` prints the list (`Destinations: echo, dtmf (...)`), and the
  dry run prints it as `approved dial:`.
- A profile without the field (made by hand, or compiled by an older
  version) still works and does not restrict the destination. `rehearse`
  then prints a `WARN:` line and `Destinations: NOT RESTRICTED by this
  profile`, and the call result prints `Destination: ... (NOT CHECKED: ...)`.
  Run `scope compile` to get the list.

`checks` dials only `security_checks.destination`, which compile takes from
the same scope destinations. The MCP live path sends one OPTIONS preflight
and dials nothing. The campaign manifest's `dial.user` comes from the scope
too, and `campaign plan` freezes it.

### One profile per target

A profile approves exactly one target (one address, port, and transport).
A scope with more than one entry in `targets` (for example the same
platform over UDP and over TLS) therefore compiles into one profile for each:

| Target | File | Sidecar key |
|---|---|---|
| the first entry of `targets` | `target-profile.yaml` | `profile` |
| every other entry | `target-profile-NAME.yaml`, NAME = that target's `name` | `profile:NAME` |

The first target keeps the name that `status`, the cockpit, and `ready` look
for, so nothing changes for a scope with one target. Target names are unique
and are 1 to 41 characters from `a-z`, `0-9`, and `-`, so the file names are
predictable and cannot collide.

Each profile has its own `target` (`host`, `port`, `transport`, and for TLS
`tls_server_name` and `tls_ca_file`), its own `target.approved_destinations`
(only the destinations whose `target:` names it), and its own `name` (the
scope name, then `-NAME` for the other targets). All of them share the
approval, the window, `approved_addresses`, the limits, and the media scope
(`media.codecs`, `media.networks`, `media.port_range`). `security_checks`
goes only into the first target's profile. The limits are written into each
profile, but `limits.calls` stays one total: a `matrix run` over several of
these profiles counts their calls together (they share the approval id) and
refuses a grid with more calls than `limits.calls`. The scope's totals for
the whole engagement are in the campaign manifest.

Compile prints which file belongs to which target:

```text
NOTE: one target profile per target: target-profile.yaml (udp, udp port 5060); target-profile-tls.yaml (tls, tls port 5061). Pass the profile of the target you are testing to rehearse, call, and matrix; each approves only the destinations the scope lists for its target
```

Pass the profile of the target under test to `rehearse` and `call`, and one
profile per transport to `matrix` (`CALL-MATRIX.md`). Every profile is a
managed derivative: `scope-derivatives.json` records its hash, `status`
reports it as `current`, `stale`, `edited`, or `missing`, and `ready` and
the cockpit report each profile's readiness (see "Staleness and hand edits").

When a target leaves `targets` (or becomes the first one), the next compile
removes its `target-profile-NAME.yaml`, so an approved profile for a target
that is no longer in scope does not stay behind. A file that was edited by
hand is not removed: compile leaves it, stops tracking it, and says so.

A `target-profile-NAME.yaml` that exists but was not written by compile (for
example a hand copy from an earlier version of this procedure) makes compile
refuse with `scope.derivative_unmanaged`; `scope compile --force` replaces
it with the generated profile.

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
profile represents one target, so compile writes one profile per target (see
"One profile per target" above); the manifest carries all of them.
`summary` checks the runs of every profile against the scope.

The one exception is the `security_checks` answer. When `test_scope.allowed_classes`
includes `security-checks`, `scope check` validates `security_checks.approved`
against the reviewed catalog. It also checks each check's prerequisites
against the first target, and the summed request bounds against
`security_checks.max_requests`, `limits.packets`, and `limits.calls`.
`scope compile` then copies the list into the profile, with the account
username, the first destination's user, and (for a TLS first target) the
approved cleartext signaling ports. See `SECURITY-CHECKS.md`.

## Platform and application answers

Use these two optional sections when the owner wants the whole product
tested: a phone platform with a web site, an admin console, an API, real
customers, carriers, and outside hosting. A scope file without them is valid
and behaves exactly as before. Start a new file with
`./bin/sippycup scope init DIR --platform`, or copy the two sections from
[`examples/scope/platform-scope.yaml`](../examples/scope/platform-scope.yaml),
which annotates every field with its question number.

**No live application runner exists.** These sections are a record. No
Sippycup command sends HTTP or WebSocket traffic to a surface recorded here,
and `scope compile` does not create a `web-security` profile from them.

### Open answers: `pending` and `unknown`

Any answer in these two sections may be the word `pending` (you asked and are
waiting for the owner) or `unknown` (the owner does not know yet). Both are
OPEN, the same as an empty answer. Nothing is inferred from an open answer.
An open answer is shown as open, never as not-applicable: a question is
`not-applicable` only when the owner's own answer rules it out (for example
the web questions when the admin console, the customer web app, the API, and
browser calling are all recorded as `out-of-scope`).

### Fields

| Field | Question | Answer |
|---|---|---|
| `platform.name` | P1 | the product name |
| `platform.components.*` | P1 | `in-scope`, `out-of-scope`, `pending`, or `unknown` for each of `sip_edge`, `media_servers`, `admin_console`, `customer_web_app`, `api`, `websocket_webrtc`, `provisioning`, `voicemail`, `ivr`, `conference`, `recording` |
| `platform.out_of_scope` | P2 | a list of plain words; `[none]` when nothing is out of scope |
| `platform.environment.kind` | P3 | `production`, `staging`, `dedicated-test` |
| `platform.environment.real_customers` | P4 | `true` or `false` |
| `platform.environment.test_tenant` | P5 | the test tenant's label; `none` when there is none |
| `platform.environment.never_touch` | P6 | data that must never be opened or changed; `[none]` only when the system holds no real data |
| `platform.third_parties.{hosting,cdn_waf,pstn_carrier,sms,email}` | P7 to P10 | `provider`, `permission` (`out-of-path`: confirmed not involved in what is tested; `permitted`; `pending`; `unknown`), `reference` (where the permission is written; required for `permitted`) |
| `platform.dialing.reach` | P11 | each `destinations[].name` mapped to `on-net` (stays on the platform) or `pstn` (reaches the public phone network) |
| `platform.dialing.never_dial`, `never_dial_prefixes` | P12 | exact numbers and optional prefixes, always in quotes (`"112"`); `[none]` when there are none |
| `platform.dialing.toll` | P13 | `no-cost`, `accepted`, `refused` |
| `platform.operations.allowed_hours` | P14 | plain words with a timezone |
| `platform.operations.max_concurrent_calls`, `max_requests_per_second` | P15 | whole numbers |
| `platform.operations.blocking` | P16 | the alarms and automatic blocks a test may trigger, and who can undo a block |
| `platform.operations.emergency_contact` (`name`, `channel`), `stop_signal` | P17 | who to call when something breaks, and the owner's stop signal |
| `platform.addressing[]` | P18 | `name` (a public DNS name), `addresses` (the literal IPs behind it), `shared` (with other customers), `changing` (behind a load balancer or delivery network whose addresses change) |
| `application.surfaces[]` | A1 to A3 | `name`, `kind` (`browser`, `api`, `websocket`), `status` (`in-scope`, `out-of-scope`, `pending`, `unknown`), `base_url` (`https://`, or `wss://` for a websocket), `connect_address` (literal IP), `connect_port`, `tls_server_name`, `tls_ca` (`public`, `private`), optional `tls_ca_file` (`work/...`), `allowed_origins` (websocket) |
| `application.identities[]` | A4 | `id`, `role`, `tenant`, `credential_ref` (the NAME of the secret, never its value) |
| `application.object_classes` | A5 | kinds of stored files, for example `[voicemail, recording]` |
| `application.route_inventory` | A6 | `kind` (`openapi`, `har`, `route-list`, `none`), optional `file` (`work/...`; recorded, never read) |

Names and addresses. A public DNS name is an identity only: `base_url`,
`tls_server_name`, and `addressing[].name` are never looked up. A destination
is a literal IP address the owner wrote down. A hostname in
`connect_address` or `addressing[].addresses` is an error; write `pending`
until the owner gives the address.

A HAR file records a real browser session and can hold session cookies. Ask
the owner to remove them before sending it, and keep the file under `work/`.

### The severity rule

`scope check` treats the two sections by one rule:

1. **A wrong answer is an error**, as everywhere else in the file: an unknown
   field, anything that looks like a secret (both make the whole file
   invalid), a malformed value, a hostname where a literal address belongs,
   or two recorded answers that contradict each other. The scope is then not
   clean, so the profile stays `pending` until you correct the answer or
   write `pending`. Each such finding names its field.
2. **An open answer is never an error.** Missing, `pending`, and `unknown`
   answers in these sections do NOT block the SIP/RTP part of an engagement
   that is otherwise complete: `scope check` exits 0, and the profile, the
   campaign manifest, and the expectations are generated as before. An open
   answer is a WARNING when it gates something:
   - `scope.surface_not_ready`: a surface that is `in-scope` lacks its
     address, port, TLS name, CA answer, or (websocket) origins, or the
     hosting provider or CDN/web firewall has not been resolved, or
     production-safety answers are open. That surface is recorded as
     `pending`, not `approved`. Only that surface is held.
   - `scope.third_party_unresolved`: a company whose permission the owner
     cannot give alone is not yet `out-of-path` or `permitted` (with a
     reference). Hosting gates everything hosted there, including the SIP
     edge; the CDN/web firewall, SMS, and email providers gate the web
     surfaces; the carrier gates any call that may leave the platform.
   - `scope.production_safety_open`: the scope says `production` (or does
     not say, which is treated as production) and one of P4, P6, P7, P11,
     P12, P14, P15, P16, P17 is open. For example: production with real
     customers but no never-touch list, or no emergency contact and stop
     signal.
   - `scope.destination_reach_open`: it is not recorded whether a
     destination stays on the platform.
   - `scope.address_shared`, `scope.address_changing`: an address used by a
     SIP target or an in-scope surface is shared with other customers, or
     changes.
   - `scope.platform_open`: one summary line with the numbers of all open
     questions.
3. **Four contradictions are about SIP traffic itself and are errors that
   hold the profile and the campaign**, because a call could do harm that no
   later step can undo:
   - `scope.pstn_destination_unconfirmed`: a destination is recorded as
     `pstn`, but `third_parties.pstn_carrier.permission` is not `permitted`
     or `dialing.toll` is not `no-cost` or `accepted`. No call may leave the
     platform until the owner answers both, or the destination is removed.
   - `scope.carrier_answer_conflict`: the carrier is `out-of-path`, yet a
     destination is `pstn`.
   - `scope.destination_never_dial`: a `destinations[].user` equals a
     `never_dial` number or starts with a `never_dial_prefixes` entry.
   - `scope.limit_exceeds_production`: `limits.concurrent_calls` is above
     `operations.max_concurrent_calls`.

Limits of this check. The never-dial list and the reach answers are checked
against `destinations[]` in the scope file. They are not enforced at run time:
`call --dial` and `matrix` do not read them, so dial only destinations that
are in the scope. `allowed_hours` is plain text for the operator; the
approval window in `authorization` is what the tools enforce.

### `application-surfaces.yaml`

When the scope has a `platform` or `application` section, `scope compile`
also writes `application-surfaces.yaml` (mode 0600) beside the other
derivatives. It is a record for review:

- every surface with its state: `approved` (in scope, every answer it needs
  is given, and the scope's authorization is approved and in its window),
  `pending` (in scope, with the list of what is open), `undecided` (the owner
  has not said whether it is in scope), or `out-of-scope`;
- the platform answers, the third parties with `resolved` or `open`, the
  dialing answers, the production limits, the names and addresses, the test
  identities (reference names only), and the open questions;
- the same approval reference and window as the scope (`authorization`), and
  the scope file's SHA-256 (`generatedFrom`).

Every value is copied from the scope file. The record contains no path,
method, header, or body, and an open answer is written as `pending`,
`unknown`, or `unanswered`. It states that no live application runner exists.
It is not validated against the `web-security` profile contract
([WEB-SECURITY.md](WEB-SECURITY.md)): that contract also needs an adapter, a
check list, hard ceilings, a window of at most 24 hours, and credential source
references, which the scope file does not record.

The record does not change the compile exit code: open answers leave it 0
when the SIP part is clean. It is skipped (with the reasons) while an error
exists in the two sections. Compile does not overwrite a record that was
edited by hand or that it did not write (`scope.derivative_modified`,
`scope.derivative_unmanaged`; `--force` overwrites). The record carries its
own content hash and is not listed in `scope-derivatives.json`; the cockpit
shows it as `current`, `stale` (the scope changed since), `edited`, or
`not-compiled`. A stale record does not block a SIP run.

### Staleness and hand edits

The profile and manifest reject unknown fields, and the expectations loader
rejects unknown keys, so no hash can live inside the derivatives. Compile
instead writes one sidecar, `scope-derivatives.json` (mode 0600), recording the
scope file's SHA-256, each derivative's path and SHA-256, the scope hash each
was generated from, the generation time, and what was skipped.

`status` (and `derivative_state`) report each derivative (`profile`, each
`profile:NAME` of a further target, `campaign`, `expectations`) as `current`, `stale`
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
the sidecar, or strip the compile header from a copied profile. See
SAFETY-AUDIT.md, rehearsal 2 finding 4, for the two cases it does not stop.

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
result, recommends `scope check` and `scope answer` while it fails, and reports stale derivatives
with `scope compile` as the next action. Every recommended action is
network-free.
