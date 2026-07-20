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

WebRTC is now an explicit assessment track. A small, independently implemented
peer such as Pion will exercise audio-only offer/answer, trickle ICE, candidate
gathering, ICE restart, STUN/TURN transports, DTLS fingerprints, SRTP/RTCP,
and deterministic media canaries under the same literal-address and traffic
ceilings as the rest of Sippycup.

The profile will also cover pluggable WSS signaling, browser-origin and session
controls, SDP negotiation, consent freshness, TURN authorization, DTLS-SRTP
identity binding, and privacy-safe evidence. Signaling adapters remain
service-specific because WebRTC does not define a signaling protocol.

The peer stays outside the core image so users who only assess SIP/RTP systems
do not inherit its build and runtime footprint.

The trust boundaries, authorization classes, evidence requirements, and live
admission criteria are defined in
[`WEBRTC-THREAT-MODEL.md`](WEBRTC-THREAT-MODEL.md).

## Admission gates

Each optional profile must have:

- pinned versions and reproducible build provenance;
- a network-free smoke and fixture path;
- stable JSON output and explicit uncertainty;
- bounded memory, file-size, duration, and traffic behavior;
- no secret material in argv, reports, or image layers;
- a documented relationship to the campaign authorization and exit gates.
