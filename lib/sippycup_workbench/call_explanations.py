"""`./bin/sippycup explain call.VERDICT` texts for the guided call's verdicts.

One entry per verdict in ``schemas/call-result-v1.schema.json``; a unit test
keeps the two lists equal. Each text says what Sippycup observed, what it does
not prove, and what to check next.
"""

from __future__ import annotations

CALL_EXPLANATIONS: dict[str, tuple[str, str]] = {
    "call.pass": (
        "The guided call passed",
        "The call was answered, the oracle passed, RTP flowed in both directions, and the recording is not silent. It proves one call path worked once; it is not a quality measurement.",
    ),
    "call.fail": (
        "The call was answered but the oracle failed",
        "The notes name each failed assertion (for example an RTP timestamp jump, loss, reordering, or jitter above the limit). Read assert.json in the run directory; an oracle failure describes the media or signaling observed, not the cause. For example, Asterisk re-bases the RTP timestamp where early media ends and the answer begins, which the oracle reports as a timestamp jump.",
    ),
    "call.srtp-not-negotiated": (
        "SRTP was mandatory but the call did not negotiate it",
        "The call was placed with --srtp mandatory and the far end either rejected the secure offer (commonly 488) or answered with plain RTP, so no protected media was exchanged. This shows the far end's SRTP policy for this account and destination; it is not a media-quality result. Compare the offer and answer media profiles (RTP/SAVP and a=crypto) in the softphone log.",
    ),
    "call.dtmf-not-negotiated": (
        "DTMF digits were required but telephone-event was not negotiated",
        "The far end's answer did not include the RFC 4733 telephone-event payload, so no digits were sent. Sippycup never falls back to SIP INFO or in-band tones on its own. Check the answer SDP's rtpmap lines; the platform may expect a different DTMF method.",
    ),
    "call.dtmf-mismatch": (
        "The DTMF digits on the wire differ from the digits requested",
        "The capture's outbound telephone-event sequence does not equal the requested digit string (digits missing, repeated, or out of order). Read dtmf-events.txt in the run directory. This describes what the softphone sent, not what the far end interpreted.",
    ),
    "call.codec-not-offered": (
        "The far end answered with a codec that was not offered",
        "The SDP answer named a codec (payload type and rtpmap) that the offer did not contain. An answer must choose from the offered formats (RFC 3264 section 6), so this is a far-end SDP fault, not a media-quality result: a gateway that rewrites SDP, a fixed codec policy that ignores the offer, or a transcoder answering for another leg. The result's codec section lists offered, answered, and unoffered codecs; read the answer SDP in softphone.log or the capture.",
    ),
    "call.inconclusive": (
        "The call was answered but the evidence cannot decide",
        "The oracle returned unknown for something the verdict needs (encrypted signaling, a truncated capture, or missing RTP counts). Unknown is never reported as pass; capture again or inspect the evidence.",
    ),
    "call.possible-nat-one-way-media": (
        "Signaling worked, RTP went out, none came back (NAT possible)",
        "The call was answered and PJSUA sent RTP, but no inbound RTP was observed, and the call left a private network namespace through the container runtime's NAT. This is consistent with NAT or an address advertised in SDP that the far end cannot reach; it is not by itself a target defect. Compare the SDP addresses with the capture.",
    ),
    "call.one-way-media": (
        "Signaling worked, RTP went out, none came back",
        "The call was answered and PJSUA sent RTP, but nothing arrived from the far end, and no NAT is in the path (loopback or host network). The far end accepted the call and sent no audio: a gateway without a media path, a codec or SRTP mismatch the far end did not reject, or an application that plays nothing.",
    ),
    "call.preflight-failed": (
        "The OPTIONS preflight failed; no call was placed",
        "The single OPTIONS request got no usable reply (timeout, refusal, or TLS failure), so the guided call stopped before dialing. Check the approved address, port, transport, and whether the service answers OPTIONS from your source.",
    ),
    "call.registration-failed": (
        "Registration was refused or timed out; no call was placed",
        "PJSUA could not register the account (wrong password, wrong realm or user, or the registrar did not answer). The driver quits after the first failure so a wrong password costs one challenged attempt. Fix the credentials; use --no-register if the target does not need a REGISTER.",
    ),
    "call.call-not-answered": (
        "The far end never answered before the answer timeout",
        "The far end sent provisional responses (or none) and no final answer within --answer-timeout, so the caller cancelled. Ringing that never ends is a callee that does not pick up, a dialplan that waits, or a lost final response. If the far end answers later than your timeout, raise --answer-timeout.",
    ),
    "call.call-not-placed": (
        "The softphone did not place a call",
        "PJSUA did not get as far as dialing. See the softphone log in the run directory.",
    ),
    "call.call-error": (
        "The call was answered but the softphone reported an error",
        "The call reached the answered state, and the softphone driver recorded an error (for example a timer or hang-up failure). The error field names it; the media verdict was not trusted.",
    ),
    "call.media-outside-scope": (
        "The negotiated media peer is not an approved address",
        "The far end's media address is outside the profile's approved addresses and outside every owner-approved media network (media.networks), or its port is outside media.port_range, so Sippycup hung the call up. The softphone's media guard drops the RTP and RTCP packets PJSUA addresses there before they leave (PJSUA sends RTCP as soon as it reads the answer and again as it hangs up); the Media guard line and result.json (mediaGuard) count them, and none is sent. This is a safety stop, not a target failure. Review the SDP in the capture, then ask the owner for the media-server addresses or range (see ./bin/sippycup scope questions) before changing the scope.",
    ),
    "call.signaling-outside-scope": (
        "PJSUA sent SIP to an address that is not the approved target",
        "The far end's Record-Route or Contact told PJSUA to send in-dialog requests (ACK, BYE) to another address. PJSIP sent the first one before anything could intervene, so Sippycup killed PJSUA at once instead of hanging up along that route; the far end's dialog times out by itself. This is a safety stop, not a target failure. The address is in result.json (softphone.scope_violation). Ask the owner whether that address is part of the service and, if so, get it approved as the target, or have the far end record-route through the approved address.",
    ),
    "call.capture-failed": (
        "Packet capture did not start; nothing was sent",
        "Capture needs CAP_NET_RAW inside a private network namespace, which ./bin/sippycup call provides. See capture.log in the run directory.",
    ),
    "call.capture-died": (
        "Packet capture stopped during the run",
        "The call is not trusted without its evidence, so the run was stopped. Check disk space and capture.log.",
    ),
    "call.authorization-lapsed": (
        "The profile's authorization expired during the run",
        "Sippycup re-checks authorization before each packet-sending stage and stopped. Review and renew the profile before sending anything else.",
    ),
    "call.internal-error": (
        "Sippycup failed internally",
        "The notes carry the error. Evidence gathered so far is kept in the run directory.",
    ),
    "call.tls-not-verified": (
        "TLS server verification did not succeed",
        "PJSUA sent no SIP request on the connection because the certificate did not chain to the trust anchor or did not name the reviewed server name. Check the CA file and server name in the profile.",
    ),
    "call.tls-name-pinning-failed": (
        "The reviewed TLS name could not be pinned to the literal address",
        "PJSUA was not started and sent nothing. The name is pinned without DNS in a private namespace; the pin could not be proved.",
    ),
    "call.cancelled": (
        "Cancelled by SIGINT or SIGTERM",
        "The call was hung up (BYE when established, CANCEL while ringing), the capture was kept, and the offline analysis was skipped. Exit status 130 or 143.",
    ),
    "call.blocked": (
        "Refused before anything started",
        "The profile is not approved, expired, or does not name target.host as a literal approved address. Nothing was started and no packets were sent; exit status 2.",
    ),
    "call.call-busy": (
        "The far end answered 486 Busy Here (or 600)",
        "The callee exists and is on another call or refuses to ring. It is a normal telephony outcome, not a signaling fault. Try again later or another destination.",
    ),
    "call.call-declined": (
        "The far end answered 603 Decline",
        "The callee explicitly refused the call. Unlike 486, this is a deliberate policy or user decision.",
    ),
    "call.call-auth-failed": (
        "The far end answered 401 or 407 and the credentials did not help",
        "Either no credentials were given (pass --username with --secret-env or --secret-file) or they were refused for the INVITE. A wrong password normally fails earlier as registration-failed.",
    ),
    "call.call-forbidden": (
        "The far end answered 403 Forbidden",
        "The server understood the request and refuses it: a policy, an ACL, a barred destination, or an identity that may not call here. Retrying with the same identity will not help.",
    ),
    "call.call-not-found": (
        "The far end answered 404 (or 410 or 604): no such destination",
        "Check the --dial user part and the dial plan. The server is reachable and authenticated the request but has no route for this destination.",
    ),
    "call.call-unavailable": (
        "The far end answered 503 (or 480): temporarily unavailable",
        "The service, its upstream, or the callee is not able to take the call now. 503 often means overload or a failed downstream; retry later and slowly.",
    ),
    "call.call-rate-limited": (
        "The far end answered 429 Too Many Requests",
        "A rate limit or protection rule is throttling the caller. Stop and wait; do not retry quickly. Review the profile's call-rate limits before repeating.",
    ),
    "call.call-media-not-acceptable": (
        "The far end answered 488 (or 606): offered media not acceptable",
        "The far end could not accept the SDP offer: a codec it does not allow, SRTP required but not offered (or the reverse), or an unsupported media direction. With --codec (or a profile's media.codecs) the offer lists only those codecs, so this verdict means the far end accepts none of them; the result's codec section shows the offer. Compare the offer in the capture with the far end's requirements.",
    ),
    "call.call-redirected": (
        "The far end answered with a 3xx redirect",
        "Redirects are not followed, because the redirect target could be outside the approved scope. Review the Contact in the response, and approve and profile it separately if it is in scope.",
    ),
    "call.call-rejected-4xx": (
        "The far end rejected the call with another 4xx status",
        "A client-error final status with no more specific verdict. The status is in the notes and the softphone result.",
    ),
    "call.call-rejected-5xx": (
        "The far end rejected the call with another 5xx status",
        "A server-error final status (not 503) with no more specific verdict. The status is in the notes and the softphone result; the fault is on the far end or behind it.",
    ),
    "call.call-rejected-6xx": (
        "The far end rejected the call with another 6xx status",
        "A global-failure final status (not 603 or 606). The status is in the notes and the softphone result.",
    ),
    "call.peer-hung-up-early": (
        "The far end sent BYE before the planned duration",
        "The call was answered and media was healthy, but the peer ended it well before --duration. An IVR that finished its prompt, a session timer, a server-side limit, or a fault can all do this; the capture shows who sent BYE and when.",
    ),
    "call.silent-audio": (
        "RTP flowed, but the audio is digital silence",
        "Packets arrived in both directions and the recording exists, but its peak is below the silence threshold. The far end sends packets that carry no audio (or the audio it returns is the silence you played). Packet counts alone would have called this a pass.",
    ),
    "call.slow-setup": (
        "The call was answered, but later than the setup window",
        "Only the oracle's setup-time assertion failed: the answer came after the 5 s window, with ringing in between. The call itself worked. If this is expected, raise --answer-timeout so the caller waits; the verdict still reports the delay.",
    ),
}
