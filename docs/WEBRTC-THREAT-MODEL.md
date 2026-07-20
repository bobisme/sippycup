# WebRTC assessment threat model

This document defines the security boundary for Sippycup's WebRTC voice
assessment track. It is a testing contract, not target authorization. A target
run still requires an approved engagement, literal destinations, a validity
window, traffic ceilings, credentials supplied out of band, and an operator
review of the frozen plan.

WebRTC standardizes media negotiation and transport building blocks, but not
the signaling protocol that carries offers, answers, candidates, or application
events. Sippycup therefore treats signaling as a narrow, service-specific
adapter. It will not provide a generic arbitrary WebSocket or HTTP request
primitive.

## Assets and security objectives

| Asset | Security objective |
| --- | --- |
| User and service identity | A peer cannot assume, retain, replay, or confuse another identity or role. |
| Signaling session | Messages are confidential in transit, bound to the authenticated session and call, ordered consistently, and authorized by type. |
| SDP and ICE state | Revisions, credentials, candidates, roles, and restarts are bound to the intended peer and negotiation generation. |
| DTLS identity | The certificate used on the selected media path matches the authenticated signaling fingerprint and negotiated role. |
| SRTP and SRTCP | Media and control traffic have confidentiality, integrity, replay protection, and the expected key/profile binding. |
| TURN service | Allocations, permissions, channels, quotas, and credential lifetimes cannot be abused as an open relay or amplification service. |
| Media application | Audio reaches only the intended call context; SSRC, tuple, call, and model/session state cannot cross tenants or calls. |
| Availability | Malformed, reordered, duplicated, partial, or abandoned sessions do not leak resources or cause unbounded retries. |
| Evidence | Reports preserve enough provenance to reproduce a finding without leaking tokens, ICE passwords, private candidates, or user audio. |
| Administration plane | Browser-facing call actions cannot silently inherit broader admin authority, and admin state is not exposed through generic signaling probes. |

## Trust boundaries

```text
browser or independent peer
    │  HTTPS/WSS: login, session, offer/answer, trickle, app events
    ▼
signaling edge ───── identity/session service
    │                         │
    │ negotiated identity    │ authorization and tenant context
    ▼                         ▼
ICE/STUN/TURN ───── selected candidate pair
    │
    │ DTLS fingerprint and role from signaling
    ▼
DTLS-SRTP/SRTCP endpoint ───── media application or model process
    │
    ▼
privacy-filtered evidence and assessment report
```

The browser/peer, signaling edge, TURN service, media endpoint, media
application, and evidence store are separate principals even when one
deployment combines them in a process or host. A successful check at one
boundary is not evidence that another boundary is secure.

## Attacker capabilities

The assessment models these capabilities independently:

1. An unauthenticated network client can open allowed HTTPS/WSS, STUN, TURN,
   ICE, DTLS, and media flows from the approved test source.
2. A low-privilege authenticated user controls its signaling messages, SDP,
   candidates, timing, reconnects, and media packets within explicit ceilings.
3. A web origin other than the service origin can cause a victim browser to
   attempt a WebSocket connection, but Sippycup never drives a real victim
   account without separate authorization.
4. An on-path observer can capture and reorder test-lab packets. Active
   interception, certificate substitution, or impairment requires a disposable
   lab or a separately approved chaos topology.
5. A peer can replay previously generated assessment messages and packets that
   contain no live secret, subject to a case-specific approval and replay
   ceiling.
6. A peer may know public call identifiers, ICE usernames, candidates,
   fingerprints, SSRCs, and protocol metadata observed in its own authorized
   call. It does not possess server private keys, another user's token, TURN
   shared secrets, or decrypted traffic from another tenant.

The baseline does not assume host access, source-code access, compromised
infrastructure, stolen credentials, DNS control, browser extension privileges,
or control of a third-party TURN provider. Those are separate assessment modes.

## Required invariants and evidence

| Boundary | Invariant | Minimum evidence | Safe execution class |
| --- | --- | --- | --- |
| WSS transport | The authenticated signaling channel uses the expected TLS identity and does not silently downgrade. | TLS/WSS metadata and adapter result; no token values. | Offline fixture or approved one-call. |
| Browser origin | Disallowed origins cannot establish an authenticated signaling session through ambient browser credentials. | Origin case, response class, close code, session-state observation. | Disposable local lab first; approved low-rate target check later. |
| Authentication | Expired, revoked, replayed, absent, or wrong-role sessions fail closed and do not retain call authority. | Redacted credential reference, role, message class, outcome, server correlation ID if available. | Explicit auth-test approval required. |
| Message authorization | Every message type is bound to the authenticated tenant, call, peer role, and current state. | Normalized event sequence and state transition verdict. | Approved one-call; cross-account cases require two test accounts. |
| Offer/answer | Only valid revisions affect the active negotiation; glare, rollback, and stale messages are deterministic. | Canonical SDP hashes, revision/generation IDs, typed parsing results. | Offline first, approved one-call for target behavior. |
| ICE | Candidates and connectivity checks are bound to the current ICE credentials and generation. | Candidate class, redacted address, pair state, role, nomination and restart events. | Local lab or approved literal STUN/TURN/media endpoints. |
| Consent | Media stops or revalidates as specified when consent is lost; abandoned sessions are reclaimed. | Bounded timeline, connectivity/consent events, media counters, cleanup observation. | Local impairment lab unless target owner explicitly approves disruption. |
| TURN | Credentials expire, allocations are identity/quota bound, and relaying is limited by permissions and approved destinations. | Transport, allocation lifetime, permission/channel state, byte/packet counters. | Local coturn first; target requires explicit TURN scope. |
| DTLS | The observed certificate fingerprint, negotiation generation, selected pair, and setup role agree with authenticated signaling. | Hash algorithm and fingerprint match verdict, DTLS role/version, pair and revision references. | Passive/offline or approved one-call. |
| SRTP/SRTCP | The negotiated profile is used; replay, wrong-context, and cross-call packets are rejected without redirecting a session. | Profile, protected packet counters, rejection/replay observations, no keys. | Negative packets require explicit media-security approval. |
| Media isolation | Audio, SSRCs, tuples, RTCP, and application context cannot cross calls or tenants. | Independent canary IDs, call/stream correlation, direction, continuity, leak verdict. | At least two authorized test calls; no real user media. |
| Resource lifecycle | Partial handshakes, reconnects, restarts, and disconnects have bounded work and release state. | Event timeline, retry counts, final cleanup state, resource adapter observations. | Local lab first; target concurrency/duration explicitly capped. |
| Evidence | Secrets and sensitive endpoint metadata are classified and redacted before normal reports or exports. | Privacy-lint result, hashes, redaction counters, sensitivity label. | Offline. |

A missing observation is `unknown`, never `pass`. Evidence from signaling,
packet capture, a peer, or a service health adapter is identified by source.
An oracle must not infer cryptographic strength from a cipher name alone or
claim server-side rejection merely because the client stopped receiving media.

## Data classification

WebRTC evidence adds the following handling rules to the general evidence
policy:

- Authentication cookies, bearer tokens, TURN passwords, ICE passwords,
  private keys, exported keying material, and decrypted third-party media are
  `secret`; Sippycup must not store them in argv, logs, schemas, or reports.
- ICE usernames, full SDP, host candidates, private or public candidate
  addresses, call identifiers, DTLS certificate material, and browser/device
  fingerprints are `sensitive`; normal reports use hashes, classes, or policy
  redaction.
- Aggregate counters, protocol enums, redacted fingerprints, fixture-only
  addresses, generated canary identifiers, and finding codes may be
  `internal` or `public` according to the engagement policy.
- Raw audio payload retention defaults to disabled. Only generated,
  non-speech canaries may enter reusable fixtures.

Credential inputs are references to an external provider. A signaling adapter
receives the resolved value through a protected channel at execution time and
must not echo it. Schema fixtures use unmistakably non-secret placeholders and
cannot be promoted into an approved plan.

## Authorization matrix

| Activity | Offline/local lab | Approved target requirements |
| --- | --- | --- |
| Parse, normalize, diff, and lint SDP or event fixtures | Always allowed. | No target contact. |
| Start independent peers, local signaling, and local coturn in an isolated topology | Allowed with loopback or owned container networks and no unintended egress. | Not applicable. |
| Passive triage of an operator-supplied capture | Allowed read-only. | Capture collection and handling remain the operator's responsibility. |
| Establish one WSS/WebRTC call | Not applicable. | Approval ID, literal signaling and media/STUN/TURN destinations, account/role, time window, one-call ceilings. |
| Test origin, expiry, replay, role, or malformed signaling behavior | Fixture/local lab by default. | Explicit auth-negative-test flag and attempt/rate ceiling. |
| Send unusual ICE, DTLS, SRTP, SRTCP, or replay traffic | Fixture/local lab by default. | Explicit protocol-negative-test flag and packet/byte ceilings. |
| Test two-account or cross-tenant isolation | Local lab with generated accounts. | Both test identities and permitted relationship documented. |
| Impair connectivity or withdraw consent | Local lab. | Explicit disruption approval, exact tuple, duration, and recovery gate. |
| Run concurrency, soak, or capacity tests | Local lab within host limits. | Separate load authorization and envelope; WebRTC coverage alone grants none. |
| Probe admin APIs | Fixture/local mock only. | Separate admin/API scope; never implied by WebRTC approval. |

## Stop conditions

Execution stops and reports a bounded failure when any of these occurs:

- authorization is absent, expired, revoked, not yet valid, or does not cover
  every literal destination, credential role, protocol action, and case;
- DNS produces an address not frozen in the reviewed plan;
- a redirect, candidate, TURN alternate-server response, or service message
  introduces an unapproved destination;
- attempt, call, packet, byte, duration, concurrency, or evidence-size ceiling
  would be exceeded;
- capture/evidence integrity is lost, a credential appears in output, or
  privacy classification cannot be determined;
- the target shows unexpected instability, an unrelated user or tenant appears
  in evidence, or cleanup cannot be proven;
- cancellation is requested or the supervising operator loses control.

Discovered candidates are observations, not automatic authorization. Sippycup
may describe an unapproved candidate but must not send connectivity checks or
media to it.

## Component responsibilities

- The scenario compiler rejects unknown fields, unsupported combinations,
  placeholder targets, missing ceilings, and adapter capability mismatches.
- The signaling adapter implements a fixed message vocabulary and produces
  normalized events. It cannot expose arbitrary methods, URLs, headers, or
  payloads through the high-level workflow.
- The independent peer enforces the frozen plan at the packet boundary,
  including candidate-pair and TURN destinations that appear after signaling.
- Protocol oracles distinguish `pass`, `fail`, `unknown`, and `not_applicable`
  and attach evidence references to every assertion.
- The runner monitors ceilings and cancellation independently of the peer,
  kills the full process group on failure, and verifies cleanup.
- Evidence tooling redacts before ordinary output and refuses a pack that
  contains known credential fields or unapproved raw media.
- `bin/sippycup` remains the only supported operator entrypoint. Optional peer
  installation must not weaken the core container or MCP sandbox.

## Exit criteria for live WebRTC support

Live WebRTC execution is not ready until a disposable exit gate proves:

1. interoperability between at least two independent endpoints;
2. direct and relayed audio with deterministic canaries and RTCP evidence;
3. offer/answer, trickle ICE, restart, reconnect, cancellation, and cleanup;
4. fail-closed handling for stale revisions, wrong fingerprints, expired
   credentials, unapproved candidates, and exceeded ceilings;
5. redaction of tokens, ICE/TURN secrets, endpoint metadata, and raw media;
6. zero unintended egress from the local topology;
7. the entire workflow is reachable through `bin/sippycup`;
8. target execution remains impossible without a separately validated,
   externally issued authorization.

