# Optional analysis profiles

The core image stays focused on bounded SIP/RTP testing and offline evidence.
Large or conditional integrations are separate roadmap items so installing a
packet toolbox does not also install a data lake, a heavyweight model build,
or an unnecessary WebRTC stack.

## Quality profile: ViSQOL

The quality profile will compare returned canary audio with its clean
reference using ViSQOL speech mode. It will:

- normalize the supported speech sample rate explicitly;
- score repeated samples rather than presenting one score as universal MOS;
- retain the existing factual clipping, silence, gain, continuity, and
  latency results alongside the estimate;
- produce typed not-measurable output for encrypted or absent payloads.

ViSQOL and its build dependencies will not enter the core image.

## Observability profile: Zeek and HEP

Zeek will be an independent offline SIP interpretation, normalized and
compared with the TShark oracle. Its built-in SIP analyzer is UDP-only, so a
missing Zeek record cannot override evidence from TCP, TLS, or another
dissector.

HEP export and HOMER will be optional services for long campaign
observability. Export must pass evidence privacy policy, use an explicit
destination, and remain disabled by default.

## WebRTC profile: Pion

A small Pion peer is justified only if Quad confirms that the Ferivox staging
surface includes WebRTC, ICE, or DTLS-SRTP. It would exercise candidate
gathering, ICE restart, STUN/TURN transports, DTLS fingerprints, SRTP/RTCP,
and direct RTP access under the same literal-address and traffic ceilings.

No Pion component will be added merely because WebRTC testing might become
useful later.

## Admission gates

Each optional profile must have:

- pinned versions and reproducible build provenance;
- a network-free smoke and fixture path;
- stable JSON output and explicit uncertainty;
- bounded memory, file-size, duration, and traffic behavior;
- no secret material in argv, reports, or image layers;
- a documented relationship to the campaign authorization and exit gates.
