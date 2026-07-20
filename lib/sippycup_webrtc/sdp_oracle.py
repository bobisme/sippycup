"""Strict, offline WebRTC SDP negotiation oracle.

The oracle consumes normalized SDP facts instead of raw SDP.  This keeps
credentials and full session descriptions out of retained evidence while
still allowing independent adapters to report the facts that affect
offer/answer security and interoperability.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import itertools
import json
from pathlib import Path
import re
import sys
from typing import Any, Callable, Mapping

POLICY_VERSION = "sippycup.dev/sdp-policy/v1"
TRANSCRIPT_VERSION = "sippycup.dev/sdp-transcript/v1"
REPORT_VERSION = "sippycup.dev/sdp-report/v1"
CASES_VERSION = "sippycup.dev/sdp-cases/v1"
MAX_INPUT_BYTES = 4 * 1024 * 1024
_HASH = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_.:+/-]{1,128}$")
_STATIC_CODECS = {
    0: ("PCMU", 8000, 1),
    8: ("PCMA", 8000, 1),
    9: ("G722", 8000, 1),
}


class SDPOracleError(ValueError):
    """An input violates the strict normalized-SDP contract."""


def _object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SDPOracleError(f"{path} must be an object")
    return value


def _array(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise SDPOracleError(f"{path} must be an array")
    return value


def _exact(
    value: Mapping[str, Any],
    path: str,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    missing = required - set(value)
    extra = set(value) - required - optional
    if missing:
        raise SDPOracleError(f"{path} is missing: {', '.join(sorted(missing))}")
    if extra:
        raise SDPOracleError(f"{path} has unknown fields: {', '.join(sorted(extra))}")


def _integer(value: Any, path: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SDPOracleError(f"{path} must be an integer")
    if not minimum <= value <= maximum:
        raise SDPOracleError(f"{path} must be between {minimum} and {maximum}")
    return value


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise SDPOracleError(f"{path} must be boolean")
    return value


def _enum(value: Any, path: str, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise SDPOracleError(f"{path} must be one of: {', '.join(sorted(allowed))}")
    return value


def _token(value: Any, path: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise SDPOracleError(f"{path} must be a bounded token")
    return value


def _bounded_string(value: Any, path: str, maximum: int = 128) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise SDPOracleError(f"{path} must be a bounded string")
    return value


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise SDPOracleError(f"{path} must be a SHA-256 digest")
    return value


def _unique_tokens(value: Any, path: str, maximum: int = 64) -> list[str]:
    items = _array(value, path)
    if len(items) > maximum:
        raise SDPOracleError(f"{path} exceeds {maximum} entries")
    result = [_token(item, f"{path}[{index}]") for index, item in enumerate(items)]
    if len(result) != len(set(result)):
        raise SDPOracleError(f"{path} must contain unique values")
    return result


def validate_policy(document: Any) -> dict[str, Any]:
    policy = dict(_object(document, "$"))
    _exact(policy, "$", {"apiVersion", "media", "ice", "dtls", "negotiation", "limits"})
    if policy["apiVersion"] != POLICY_VERSION:
        raise SDPOracleError("$.apiVersion is unsupported")

    media = _object(policy["media"], "$.media")
    _exact(
        media,
        "$.media",
        {
            "allowedKinds",
            "allowedProtocols",
            "requireBundle",
            "requireRtcpMux",
            "allowedCodecs",
            "requiredRtcpFeedback",
            "allowedExtmapUris",
        },
    )
    kinds = _unique_tokens(media["allowedKinds"], "$.media.allowedKinds", 4)
    if not kinds or not set(kinds) <= {"audio", "video", "application"}:
        raise SDPOracleError("$.media.allowedKinds contains an unsupported kind")
    protocols = _unique_tokens(
        media["allowedProtocols"], "$.media.allowedProtocols", 8
    )
    supported_protocols = {
        "UDP/TLS/RTP/SAVPF",
        "TCP/TLS/RTP/SAVPF",
        "UDP/DTLS/SCTP",
        "TCP/DTLS/SCTP",
    }
    if not protocols or not set(protocols) <= supported_protocols:
        raise SDPOracleError("$.media.allowedProtocols contains an unsupported value")
    _boolean(media["requireBundle"], "$.media.requireBundle")
    _boolean(media["requireRtcpMux"], "$.media.requireRtcpMux")
    codecs = _object(media["allowedCodecs"], "$.media.allowedCodecs")
    if set(codecs) != set(kinds):
        raise SDPOracleError("$.media.allowedCodecs must exactly cover allowedKinds")
    for kind, values in codecs.items():
        names = _unique_tokens(values, f"$.media.allowedCodecs.{kind}", 32)
        if not names:
            raise SDPOracleError(f"$.media.allowedCodecs.{kind} must not be empty")
    feedback_items = _array(
        media["requiredRtcpFeedback"], "$.media.requiredRtcpFeedback"
    )
    if len(feedback_items) > 16:
        raise SDPOracleError("$.media.requiredRtcpFeedback exceeds 16 entries")
    feedback = [
        _bounded_string(item, f"$.media.requiredRtcpFeedback[{index}]")
        for index, item in enumerate(feedback_items)
    ]
    if len(feedback) != len(set(feedback)):
        raise SDPOracleError("$.media.requiredRtcpFeedback must contain unique values")
    known_feedback = {
        "nack",
        "nack pli",
        "ccm fir",
        "transport-cc",
        "goog-remb",
    }
    if any(item not in known_feedback for item in feedback):
        raise SDPOracleError("$.media.requiredRtcpFeedback contains an unsupported value")
    uris = _array(media["allowedExtmapUris"], "$.media.allowedExtmapUris")
    if len(uris) > 64 or len(uris) != len(set(uris)):
        raise SDPOracleError("$.media.allowedExtmapUris must be unique and bounded")
    for index, uri in enumerate(uris):
        if not isinstance(uri, str) or not 1 <= len(uri) <= 512 or not uri.startswith(
            ("urn:", "http://", "https://")
        ):
            raise SDPOracleError(
                f"$.media.allowedExtmapUris[{index}] must be a bounded URI"
            )

    ice = _object(policy["ice"], "$.ice")
    _exact(
        ice,
        "$.ice",
        {
            "requireTrickle",
            "requireEndOfCandidates",
            "requireCredentialChangeOnRestart",
        },
    )
    for key in ice:
        _boolean(ice[key], f"$.ice.{key}")

    dtls = _object(policy["dtls"], "$.dtls")
    _exact(dtls, "$.dtls", {"requireFingerprint", "allowedHashAlgorithms", "allowedSetupPairs"})
    _boolean(dtls["requireFingerprint"], "$.dtls.requireFingerprint")
    algorithms = _unique_tokens(
        dtls["allowedHashAlgorithms"], "$.dtls.allowedHashAlgorithms", 8
    )
    if not algorithms or not set(algorithms) <= {"sha-256", "sha-384", "sha-512"}:
        raise SDPOracleError("$.dtls.allowedHashAlgorithms contains an unsupported value")
    pairs = _array(dtls["allowedSetupPairs"], "$.dtls.allowedSetupPairs")
    if not pairs or len(pairs) > 8:
        raise SDPOracleError("$.dtls.allowedSetupPairs must contain 1 to 8 entries")
    normalized_pairs: set[tuple[str, str]] = set()
    for index, item in enumerate(pairs):
        path = f"$.dtls.allowedSetupPairs[{index}]"
        pair = _object(item, path)
        _exact(pair, path, {"offer", "answer"})
        normalized_pairs.add(
            (
                _enum(pair["offer"], f"{path}.offer", {"actpass", "active", "passive"}),
                _enum(pair["answer"], f"{path}.answer", {"active", "passive"}),
            )
        )
    if len(normalized_pairs) != len(pairs):
        raise SDPOracleError("$.dtls.allowedSetupPairs must be unique")

    negotiation = _object(policy["negotiation"], "$.negotiation")
    _exact(
        negotiation,
        "$.negotiation",
        {"allowGlare", "requireRollbackBeforeRetry", "maxRevisions"},
    )
    _boolean(negotiation["allowGlare"], "$.negotiation.allowGlare")
    _boolean(
        negotiation["requireRollbackBeforeRetry"],
        "$.negotiation.requireRollbackBeforeRetry",
    )
    _integer(negotiation["maxRevisions"], "$.negotiation.maxRevisions", 1, 1024)

    limits = _object(policy["limits"], "$.limits")
    _exact(
        limits,
        "$.limits",
        {"maxMSections", "maxCodecsPerSection", "maxExtmapsPerSection", "maxGeneratedCases"},
    )
    _integer(limits["maxMSections"], "$.limits.maxMSections", 1, 64)
    _integer(limits["maxCodecsPerSection"], "$.limits.maxCodecsPerSection", 1, 128)
    _integer(limits["maxExtmapsPerSection"], "$.limits.maxExtmapsPerSection", 0, 128)
    _integer(limits["maxGeneratedCases"], "$.limits.maxGeneratedCases", 1, 128)
    return policy


def _validate_codec(value: Any, path: str) -> None:
    codec = _object(value, path)
    _exact(codec, path, {"payloadType", "name", "clockRate", "channels", "rtcpFeedback"})
    _integer(codec["payloadType"], f"{path}.payloadType", 0, 127)
    _token(codec["name"], f"{path}.name")
    _integer(codec["clockRate"], f"{path}.clockRate", 1, 384000)
    _integer(codec["channels"], f"{path}.channels", 1, 32)
    feedback = _array(codec["rtcpFeedback"], f"{path}.rtcpFeedback")
    if len(feedback) > 16:
        raise SDPOracleError(f"{path}.rtcpFeedback exceeds 16 entries")
    normalized = [
        _bounded_string(item, f"{path}.rtcpFeedback[{index}]")
        for index, item in enumerate(feedback)
    ]
    if len(normalized) != len(set(normalized)):
        raise SDPOracleError(f"{path}.rtcpFeedback must contain unique values")


def _validate_extmap(value: Any, path: str) -> None:
    extmap = _object(value, path)
    _exact(extmap, path, {"id", "uri", "direction"})
    _integer(extmap["id"], f"{path}.id", 1, 255)
    if not isinstance(extmap["uri"], str) or not 1 <= len(extmap["uri"]) <= 512:
        raise SDPOracleError(f"{path}.uri must be a bounded string")
    _enum(
        extmap["direction"],
        f"{path}.direction",
        {"sendrecv", "sendonly", "recvonly", "inactive"},
    )


def _validate_section(
    value: Any,
    path: str,
    *,
    max_codecs: int,
    max_extmaps: int,
) -> None:
    section = _object(value, path)
    _exact(
        section,
        path,
        {
            "mid",
            "kind",
            "protocol",
            "port",
            "direction",
            "rtcpMux",
            "iceUfragHash",
            "icePwdHash",
            "iceOptions",
            "endOfCandidates",
            "fingerprint",
            "setup",
            "codecs",
            "extmaps",
        },
    )
    _token(section["mid"], f"{path}.mid")
    _enum(section["kind"], f"{path}.kind", {"audio", "video", "application"})
    _token(section["protocol"], f"{path}.protocol")
    _integer(section["port"], f"{path}.port", 0, 65535)
    _enum(
        section["direction"],
        f"{path}.direction",
        {"sendrecv", "sendonly", "recvonly", "inactive"},
    )
    _boolean(section["rtcpMux"], f"{path}.rtcpMux")
    _digest(section["iceUfragHash"], f"{path}.iceUfragHash")
    _digest(section["icePwdHash"], f"{path}.icePwdHash")
    _unique_tokens(section["iceOptions"], f"{path}.iceOptions", 16)
    _boolean(section["endOfCandidates"], f"{path}.endOfCandidates")
    fingerprint = section["fingerprint"]
    if fingerprint is not None:
        fingerprint = _object(fingerprint, f"{path}.fingerprint")
        _exact(fingerprint, f"{path}.fingerprint", {"algorithm", "valueHash"})
        _enum(
            fingerprint["algorithm"],
            f"{path}.fingerprint.algorithm",
            {"sha-1", "sha-256", "sha-384", "sha-512"},
        )
        _digest(fingerprint["valueHash"], f"{path}.fingerprint.valueHash")
    _enum(section["setup"], f"{path}.setup", {"actpass", "active", "passive", "holdconn"})
    codecs = _array(section["codecs"], f"{path}.codecs")
    if len(codecs) > max_codecs:
        raise SDPOracleError(f"{path}.codecs exceeds the policy limit")
    for index, codec in enumerate(codecs):
        _validate_codec(codec, f"{path}.codecs[{index}]")
    payloads = [item["payloadType"] for item in codecs]
    if len(payloads) != len(set(payloads)):
        raise SDPOracleError(f"{path}.codecs payload types must be unique")
    extmaps = _array(section["extmaps"], f"{path}.extmaps")
    if len(extmaps) > max_extmaps:
        raise SDPOracleError(f"{path}.extmaps exceeds the policy limit")
    for index, extmap in enumerate(extmaps):
        _validate_extmap(extmap, f"{path}.extmaps[{index}]")
    ids = [item["id"] for item in extmaps]
    if len(ids) != len(set(ids)):
        raise SDPOracleError(f"{path}.extmaps IDs must be unique")


def validate_transcript(document: Any, policy_document: Any) -> dict[str, Any]:
    policy = validate_policy(policy_document)
    transcript = dict(_object(document, "$"))
    _exact(transcript, "$", {"apiVersion", "networkActivity", "revisions"})
    if transcript["apiVersion"] != TRANSCRIPT_VERSION:
        raise SDPOracleError("$.apiVersion is unsupported")
    _boolean(transcript["networkActivity"], "$.networkActivity")
    revisions = _array(transcript["revisions"], "$.revisions")
    if len(revisions) > policy["negotiation"]["maxRevisions"]:
        raise SDPOracleError("$.revisions exceeds the policy limit")
    for index, item in enumerate(revisions):
        path = f"$.revisions[{index}]"
        revision = _object(item, path)
        _exact(
            revision,
            path,
            {
                "sequence",
                "type",
                "actor",
                "generation",
                "sdpHash",
                "bundleMids",
                "media",
            },
        )
        if _integer(revision["sequence"], f"{path}.sequence", 1, 1000000) != index + 1:
            raise SDPOracleError("$.revisions sequence must start at 1 and be contiguous")
        kind = _enum(revision["type"], f"{path}.type", {"offer", "answer", "rollback"})
        _enum(revision["actor"], f"{path}.actor", {"local", "remote"})
        _integer(revision["generation"], f"{path}.generation", 0, 65535)
        bundle = _unique_tokens(revision["bundleMids"], f"{path}.bundleMids", 64)
        media = _array(revision["media"], f"{path}.media")
        if kind == "rollback":
            if revision["sdpHash"] is not None or bundle or media:
                raise SDPOracleError(f"{path} rollback must not contain SDP facts")
            continue
        _digest(revision["sdpHash"], f"{path}.sdpHash")
        if not media or len(media) > policy["limits"]["maxMSections"]:
            raise SDPOracleError(f"{path}.media must contain a bounded set of sections")
        for section_index, section in enumerate(media):
            _validate_section(
                section,
                f"{path}.media[{section_index}]",
                max_codecs=policy["limits"]["maxCodecsPerSection"],
                max_extmaps=policy["limits"]["maxExtmapsPerSection"],
            )
        mids = [section["mid"] for section in media]
        if len(mids) != len(set(mids)):
            raise SDPOracleError(f"{path}.media mids must be unique")
    return transcript


def _direction_compatible(offer: str, answer: str) -> bool:
    permitted = {
        "sendrecv": {"sendrecv", "sendonly", "recvonly", "inactive"},
        "sendonly": {"recvonly", "inactive"},
        "recvonly": {"sendonly", "inactive"},
        "inactive": {"inactive"},
    }
    return answer in permitted[offer]


def normalize_sdp(
    raw_sdp: str,
    *,
    actor: str,
    revision_type: str,
    generation: int,
    sequence: int,
) -> dict[str, Any]:
    """Parse raw SDP into bounded, hash-only negotiation facts."""
    _enum(actor, "actor", {"local", "remote"})
    _enum(revision_type, "type", {"offer", "answer"})
    _integer(generation, "generation", 0, 65535)
    _integer(sequence, "sequence", 1, 1000000)
    if not isinstance(raw_sdp, str):
        raise SDPOracleError("raw SDP must be text")
    encoded = raw_sdp.encode("utf-8")
    if len(encoded) > 256 * 1024 or "\x00" in raw_sdp:
        raise SDPOracleError("raw SDP exceeds the safe parser boundary")
    lines = [line.rstrip("\r") for line in raw_sdp.splitlines()]
    if not lines or len(lines) > 4096 or any(len(line) > 4096 for line in lines):
        raise SDPOracleError("raw SDP has an invalid line count or line length")

    bundle: list[str] = []
    sections: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    payload_order: list[int] = []
    codec_values: dict[int, tuple[str, int, int]] = {}
    feedback: dict[int, list[str]] = {}

    def finish_section() -> None:
        nonlocal current, payload_order, codec_values, feedback
        if current is None:
            return
        if current["mid"] is None:
            raise SDPOracleError("every media section must have a mid")
        if current["iceUfragHash"] is None or current["icePwdHash"] is None:
            raise SDPOracleError(f"media {current['mid']} is missing ICE credentials")
        codecs = []
        for payload in payload_order:
            value = codec_values.get(payload) or _STATIC_CODECS.get(payload)
            if value is None:
                continue
            name, rate, channels = value
            codecs.append(
                {
                    "payloadType": payload,
                    "name": name,
                    "clockRate": rate,
                    "channels": channels,
                    "rtcpFeedback": sorted(
                        set(feedback.get(payload, []) + feedback.get(-1, []))
                    ),
                }
            )
        current["codecs"] = codecs
        sections.append(current)
        current = None
        payload_order = []
        codec_values = {}
        feedback = {}

    for line_number, line in enumerate(lines, 1):
        if len(line) < 2 or line[1] != "=":
            raise SDPOracleError(f"raw SDP line {line_number} is malformed")
        if line.startswith("a=group:BUNDLE "):
            if current is not None:
                raise SDPOracleError("BUNDLE group must be session-level")
            bundle = line.split()[1:]
            if len(bundle) != len(set(bundle)):
                raise SDPOracleError("BUNDLE group contains duplicate mids")
            for mid in bundle:
                _token(mid, "BUNDLE mid")
        elif line.startswith("m="):
            finish_section()
            fields = line[2:].split()
            if len(fields) < 4:
                raise SDPOracleError(f"raw SDP line {line_number} has a malformed m-line")
            kind = _enum(fields[0], "m-line kind", {"audio", "video", "application"})
            try:
                port = int(fields[1].split("/", 1)[0])
                payload_order = [int(item) for item in fields[3:] if item.isdigit()]
            except ValueError as exc:
                raise SDPOracleError(f"raw SDP line {line_number} has invalid numbers") from exc
            _integer(port, "m-line port", 0, 65535)
            if any(not 0 <= payload <= 127 for payload in payload_order):
                raise SDPOracleError("RTP payload type is outside 0..127")
            current = {
                "mid": None,
                "kind": kind,
                "protocol": fields[2],
                "port": port,
                "direction": "sendrecv",
                "rtcpMux": False,
                "iceUfragHash": None,
                "icePwdHash": None,
                "iceOptions": [],
                "endOfCandidates": False,
                "fingerprint": None,
                "setup": "actpass",
                "codecs": [],
                "extmaps": [],
            }
        elif current is not None and line.startswith("a=mid:"):
            if current["mid"] is not None:
                raise SDPOracleError("media section contains duplicate mid attributes")
            current["mid"] = _token(line[6:], "mid")
        elif current is not None and line == "a=rtcp-mux":
            current["rtcpMux"] = True
        elif current is not None and line.startswith("a=ice-ufrag:"):
            current["iceUfragHash"] = hashlib.sha256(line[12:].encode()).hexdigest()
        elif current is not None and line.startswith("a=ice-pwd:"):
            current["icePwdHash"] = hashlib.sha256(line[10:].encode()).hexdigest()
        elif current is not None and line.startswith("a=ice-options:"):
            current["iceOptions"] = sorted(set(line[14:].split()))
        elif current is not None and line == "a=end-of-candidates":
            current["endOfCandidates"] = True
        elif current is not None and line.startswith("a=fingerprint:"):
            fields = line[14:].split()
            if len(fields) != 2:
                raise SDPOracleError("fingerprint attribute is malformed")
            current["fingerprint"] = {
                "algorithm": fields[0].lower(),
                "valueHash": hashlib.sha256(fields[1].encode()).hexdigest(),
            }
        elif current is not None and line.startswith("a=setup:"):
            current["setup"] = line[8:]
        elif current is not None and line in {
            "a=sendrecv",
            "a=sendonly",
            "a=recvonly",
            "a=inactive",
        }:
            current["direction"] = line[2:]
        elif current is not None and line.startswith("a=rtpmap:"):
            try:
                payload_text, encoding = line[9:].split(None, 1)
                parts = encoding.split("/")
                payload = int(payload_text)
                codec_values[payload] = (
                    _token(parts[0], "codec name"),
                    int(parts[1]),
                    int(parts[2]) if len(parts) > 2 else 1,
                )
            except (ValueError, IndexError) as exc:
                raise SDPOracleError("rtpmap attribute is malformed") from exc
        elif current is not None and line.startswith("a=rtcp-fb:"):
            try:
                payload_text, value = line[10:].split(None, 1)
                payload = -1 if payload_text == "*" else int(payload_text)
            except ValueError as exc:
                raise SDPOracleError("rtcp-fb attribute is malformed") from exc
            feedback.setdefault(payload, []).append(
                _bounded_string(value, "rtcp-fb value")
            )
        elif current is not None and line.startswith("a=extmap:"):
            try:
                id_direction, uri = line[9:].split(None, 1)
                id_parts = id_direction.split("/", 1)
                extmap_id = int(id_parts[0])
                direction = id_parts[1] if len(id_parts) == 2 else "sendrecv"
            except ValueError as exc:
                raise SDPOracleError("extmap attribute is malformed") from exc
            current["extmaps"].append(
                {"id": extmap_id, "uri": uri.split()[0], "direction": direction}
            )
    finish_section()
    if not sections:
        raise SDPOracleError("raw SDP contains no media sections")
    mids = [item["mid"] for item in sections]
    if len(mids) != len(set(mids)):
        raise SDPOracleError("raw SDP contains duplicate mids")
    revision = {
        "sequence": sequence,
        "type": revision_type,
        "actor": actor,
        "generation": generation,
        "sdpHash": hashlib.sha256(encoded).hexdigest(),
        "bundleMids": bundle,
        "media": sections,
    }
    # Reuse the strict field validator with permissive structural ceilings.
    for index, section in enumerate(sections):
        _validate_section(
            section,
            f"revision.media[{index}]",
            max_codecs=128,
            max_extmaps=128,
        )
    return revision


def evaluate(policy_document: Any, transcript_document: Any) -> dict[str, Any]:
    policy = validate_policy(policy_document)
    transcript = validate_transcript(transcript_document, policy)
    findings: list[dict[str, Any]] = []
    unknowns: list[dict[str, Any]] = []

    def fail(code: str, revision: int, detail: str) -> None:
        findings.append(
            {"severity": "fail", "code": code, "revision": revision, "detail": detail}
        )

    pending: dict[str, Any] | None = None
    stable_offer: dict[str, Any] | None = None
    stable_answer: dict[str, Any] | None = None
    rollback_required: set[str] = set()
    negotiated = 0
    allowed_kinds = set(policy["media"]["allowedKinds"])
    allowed_protocols = set(policy["media"]["allowedProtocols"])
    allowed_extmaps = set(policy["media"]["allowedExtmapUris"])
    allowed_pairs = {
        (item["offer"], item["answer"]) for item in policy["dtls"]["allowedSetupPairs"]
    }

    for index, revision in enumerate(transcript["revisions"]):
        kind = revision["type"]
        actor = revision["actor"]
        if kind == "rollback":
            if pending is None:
                fail("sdp.rollback_without_pending_offer", index, actor)
            elif actor != pending["actor"]:
                fail("sdp.rollback_by_wrong_actor", index, actor)
            pending = None
            rollback_required.discard(actor)
            continue

        mids = [section["mid"] for section in revision["media"]]
        bundle = revision["bundleMids"]
        if policy["media"]["requireBundle"] and set(bundle) != set(mids):
            fail("sdp.bundle_incomplete", index, "BUNDLE must contain every mid exactly once")
        if any(mid not in mids for mid in bundle):
            fail("sdp.bundle_unknown_mid", index, "BUNDLE references an absent mid")

        for section in revision["media"]:
            mid = section["mid"]
            if section["kind"] not in allowed_kinds:
                fail("sdp.media_kind_disallowed", index, f"{mid}:{section['kind']}")
            if section["protocol"] not in allowed_protocols:
                fail("sdp.protocol_disallowed", index, f"{mid}:{section['protocol']}")
            if policy["media"]["requireRtcpMux"] and not section["rtcpMux"]:
                fail("sdp.rtcp_mux_required", index, mid)
            if policy["ice"]["requireTrickle"] and "trickle" not in section["iceOptions"]:
                fail("sdp.trickle_required", index, mid)
            if (
                policy["ice"]["requireEndOfCandidates"]
                and kind == "answer"
                and not section["endOfCandidates"]
            ):
                fail("sdp.end_of_candidates_missing", index, mid)
            fingerprint = section["fingerprint"]
            if policy["dtls"]["requireFingerprint"] and fingerprint is None:
                fail("sdp.fingerprint_missing", index, mid)
            elif (
                fingerprint is not None
                and fingerprint["algorithm"] not in policy["dtls"]["allowedHashAlgorithms"]
            ):
                fail(
                    "sdp.fingerprint_algorithm_disallowed",
                    index,
                    f"{mid}:{fingerprint['algorithm']}",
                )
            allowed_codecs = {
                name.lower() for name in policy["media"]["allowedCodecs"][section["kind"]]
            }
            active_codecs = [
                codec for codec in section["codecs"] if codec["name"].lower() in allowed_codecs
            ]
            if section["port"] != 0 and not active_codecs:
                fail("sdp.no_allowed_codec", index, mid)
            for codec in active_codecs:
                missing = set(policy["media"]["requiredRtcpFeedback"]) - set(
                    codec["rtcpFeedback"]
                )
                if missing:
                    fail(
                        "sdp.rtcp_feedback_missing",
                        index,
                        f"{mid}:{codec['name']}:{','.join(sorted(missing))}",
                    )
            for extmap in section["extmaps"]:
                if extmap["uri"] not in allowed_extmaps:
                    fail("sdp.extmap_disallowed", index, f"{mid}:{extmap['uri']}")

        if kind == "offer":
            if actor in rollback_required and policy["negotiation"]["requireRollbackBeforeRetry"]:
                fail("sdp.retry_without_rollback", index, actor)
            if pending is not None:
                if pending["actor"] == actor:
                    fail("sdp.offer_while_pending", index, actor)
                else:
                    if not policy["negotiation"]["allowGlare"]:
                        fail("sdp.glare", index, f"{pending['actor']}->{actor}")
                    rollback_required.update({pending["actor"], actor})
                    if not policy["negotiation"]["allowGlare"]:
                        continue
            pending = revision
            continue

        if pending is None:
            fail("sdp.answer_without_offer", index, actor)
            continue
        if actor == pending["actor"]:
            fail("sdp.answer_by_offerer", index, actor)
            pending = None
            continue

        offer_by_mid = {section["mid"]: section for section in pending["media"]}
        answer_by_mid = {section["mid"]: section for section in revision["media"]}
        if set(answer_by_mid) != set(offer_by_mid):
            fail("sdp.answer_mid_mismatch", index, "answer mids differ from offer")
        if not set(revision["bundleMids"]) <= set(pending["bundleMids"]):
            fail("sdp.answer_bundle_expanded", index, "answer expanded BUNDLE")
        for mid in sorted(set(answer_by_mid) & set(offer_by_mid)):
            offer_section = offer_by_mid[mid]
            answer_section = answer_by_mid[mid]
            if answer_section["kind"] != offer_section["kind"]:
                fail("sdp.answer_kind_changed", index, mid)
            if answer_section["protocol"] != offer_section["protocol"]:
                fail("sdp.answer_protocol_changed", index, mid)
            if not _direction_compatible(
                offer_section["direction"], answer_section["direction"]
            ):
                fail("sdp.direction_incompatible", index, mid)
            if (offer_section["setup"], answer_section["setup"]) not in allowed_pairs:
                fail(
                    "sdp.dtls_role_invalid",
                    index,
                    f"{mid}:{offer_section['setup']}/{answer_section['setup']}",
                )
            offered = {
                (
                    item["payloadType"],
                    item["name"].lower(),
                    item["clockRate"],
                    item["channels"],
                )
                for item in offer_section["codecs"]
            }
            selected = {
                (
                    item["payloadType"],
                    item["name"].lower(),
                    item["clockRate"],
                    item["channels"],
                )
                for item in answer_section["codecs"]
                if item["name"].lower()
                in {
                    name.lower()
                    for name in policy["media"]["allowedCodecs"][answer_section["kind"]]
                }
            }
            if answer_section["port"] != 0 and not selected:
                fail("sdp.answer_without_codec", index, mid)
            if not selected <= offered:
                fail("sdp.answer_codec_not_offered", index, mid)

            if stable_offer is not None and stable_answer is not None:
                old_offer_by_mid = {
                    item["mid"]: item for item in stable_offer["media"]
                }
                old_answer_by_mid = {
                    item["mid"]: item for item in stable_answer["media"]
                }
                for side, old_by_mid, new_section in (
                    ("offer", old_offer_by_mid, offer_section),
                    ("answer", old_answer_by_mid, answer_section),
                ):
                    if mid not in old_by_mid:
                        continue
                    old = old_by_mid[mid]
                    changed = (
                        old["iceUfragHash"] != new_section["iceUfragHash"],
                        old["icePwdHash"] != new_section["icePwdHash"],
                    )
                    if changed[0] != changed[1]:
                        fail("sdp.partial_ice_restart", index, f"{side}:{mid}")
                    generation_changed = (
                        revision["generation"] != stable_answer["generation"]
                    )
                    if (
                        generation_changed
                        and policy["ice"]["requireCredentialChangeOnRestart"]
                        and not all(changed)
                    ):
                        fail(
                            "sdp.restart_reused_credentials",
                            index,
                            f"{side}:{mid}",
                        )
                    if all(changed) and not generation_changed:
                        fail(
                            "sdp.credentials_changed_without_generation",
                            index,
                            f"{side}:{mid}",
                        )
        if revision["generation"] != pending["generation"]:
            fail("sdp.offer_answer_generation_mismatch", index, "generation")
        negotiated += 1
        stable_offer = pending
        stable_answer = revision
        pending = None

    if pending is not None:
        unknowns.append({"code": "sdp.pending_offer", "actor": pending["actor"]})
    if not transcript["revisions"]:
        unknowns.append({"code": "sdp.no_revisions"})
    elif negotiated == 0 and not findings:
        unknowns.append({"code": "sdp.no_completed_negotiation"})
    status = "fail" if findings else ("incomplete" if unknowns else "pass")
    return {
        "apiVersion": REPORT_VERSION,
        "status": status,
        "networkActivity": False,
        "observedNetworkActivity": transcript["networkActivity"],
        "revisions": len(transcript["revisions"]),
        "completedNegotiations": negotiated,
        "findings": findings,
        "unknowns": unknowns,
        "retainedRawSdp": False,
        "capacityClaim": None,
    }


Mutation = tuple[str, Callable[[dict[str, Any]], None]]


def _mutations(transcript: dict[str, Any]) -> list[Mutation]:
    non_rollback = [
        (index, revision)
        for index, revision in enumerate(transcript["revisions"])
        if revision["type"] != "rollback" and revision["media"]
    ]
    answers = [
        (index, revision)
        for index, revision in non_rollback
        if revision["type"] == "answer"
    ]
    if not non_rollback:
        return []
    first_index, _ = non_rollback[0]

    def section_change(index: int, key: str, value: Any) -> Callable[[dict[str, Any]], None]:
        return lambda item: item["revisions"][index]["media"][0].__setitem__(key, value)

    mutations: list[Mutation] = [
        (
            "bundle.drop-mid",
            lambda item: item["revisions"][first_index].__setitem__("bundleMids", []),
        ),
        ("rtcp-mux.disable", section_change(first_index, "rtcpMux", False)),
        (
            "trickle.remove",
            section_change(first_index, "iceOptions", []),
        ),
        ("fingerprint.remove", section_change(first_index, "fingerprint", None)),
        ("codec.remove", section_change(first_index, "codecs", [])),
        ("setup.holdconn", section_change(first_index, "setup", "holdconn")),
    ]
    if answers:
        answer_index, answer = answers[0]

        def expand_answer_direction(item: dict[str, Any]) -> None:
            # sendonly/sendonly is deliberately incompatible and remains
            # meaningful even when the seed offer was sendrecv.
            item["revisions"][first_index]["media"][0]["direction"] = "sendonly"
            item["revisions"][answer_index]["media"][0]["direction"] = "sendonly"

        def set_unoffered_payload(item: dict[str, Any]) -> None:
            codecs = item["revisions"][answer_index]["media"][0]["codecs"]
            if codecs:
                codecs[0]["payloadType"] = 127
            else:
                codecs.append(
                    {
                        "payloadType": 127,
                        "name": "unknown",
                        "clockRate": 8000,
                        "channels": 1,
                        "rtcpFeedback": [],
                    }
                )

        mutations.extend(
            [
                (
                    "answer.direction-expand",
                    expand_answer_direction,
                ),
                (
                    "answer.codec-not-offered",
                    set_unoffered_payload,
                ),
                (
                    "answer.end-of-candidates.remove",
                    section_change(answer_index, "endOfCandidates", False),
                ),
            ]
        )
    return mutations


def generate_cases(policy_document: Any, transcript_document: Any) -> dict[str, Any]:
    policy = validate_policy(policy_document)
    transcript = validate_transcript(transcript_document, policy)
    mutations = _mutations(transcript)
    combinations = [(item,) for item in mutations]
    combinations.extend(itertools.combinations(mutations, 2))
    cases = []
    for selected in combinations[: policy["limits"]["maxGeneratedCases"]]:
        candidate = deepcopy(transcript)
        identifiers = []
        for identifier, mutate in selected:
            mutate(candidate)
            identifiers.append(identifier)
        encoded = json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode()
        cases.append(
            {
                "id": hashlib.sha256(encoded).hexdigest()[:16],
                "mutations": identifiers,
                "transcript": candidate,
            }
        )
    return {
        "apiVersion": CASES_VERSION,
        "networkActivity": False,
        "strategy": "deterministic-single-and-pairwise",
        "cases": cases,
        "truncated": len(combinations) > len(cases),
    }


def minimize_failure(
    policy_document: Any, transcript_document: Any, finding_code: str
) -> dict[str, Any]:
    policy = validate_policy(policy_document)
    candidate = validate_transcript(transcript_document, policy)
    if finding_code not in {item["code"] for item in evaluate(policy, candidate)["findings"]}:
        raise SDPOracleError(f"finding is not present: {finding_code}")
    candidate = deepcopy(candidate)

    def preserves(document: dict[str, Any]) -> bool:
        try:
            return finding_code in {
                item["code"] for item in evaluate(policy, document)["findings"]
            }
        except SDPOracleError:
            return False

    changed = True
    while changed:
        changed = False
        for index in range(len(candidate["revisions"]) - 1, -1, -1):
            trial = deepcopy(candidate)
            del trial["revisions"][index]
            for sequence, revision in enumerate(trial["revisions"], 1):
                revision["sequence"] = sequence
            if preserves(trial):
                candidate = trial
                changed = True
                break
    for revision_index, revision in enumerate(list(candidate["revisions"])):
        for section_index in range(len(revision["media"]) - 1, -1, -1):
            if len(candidate["revisions"][revision_index]["media"]) <= 1:
                break
            trial = deepcopy(candidate)
            removed_mid = trial["revisions"][revision_index]["media"][section_index]["mid"]
            del trial["revisions"][revision_index]["media"][section_index]
            trial["revisions"][revision_index]["bundleMids"] = [
                mid
                for mid in trial["revisions"][revision_index]["bundleMids"]
                if mid != removed_mid
            ]
            if preserves(trial):
                candidate = trial
    return {
        "apiVersion": "sippycup.dev/sdp-minimized/v1",
        "networkActivity": False,
        "findingCode": finding_code,
        "transcript": candidate,
        "report": evaluate(policy, candidate),
    }


def _read(path: str) -> Any:
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise SDPOracleError(f"input must be a regular non-symlink file: {path}")
    if candidate.stat().st_size > MAX_INPUT_BYTES:
        raise SDPOracleError(f"input exceeds {MAX_INPUT_BYTES} bytes: {path}")
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SDPOracleError(f"cannot read JSON input {path}: {exc}") from exc


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="webrtc-sdp",
        description="Evaluate or generate normalized WebRTC SDP evidence offline.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    evaluate_parser = subparsers.add_parser("evaluate", help="evaluate a transcript")
    evaluate_parser.add_argument("policy")
    evaluate_parser.add_argument("transcript")
    generate_parser = subparsers.add_parser(
        "generate", help="generate bounded negative/pairwise cases"
    )
    generate_parser.add_argument("policy")
    generate_parser.add_argument("transcript")
    minimize_parser = subparsers.add_parser(
        "minimize", help="minimize a transcript preserving one finding"
    )
    minimize_parser.add_argument("policy")
    minimize_parser.add_argument("transcript")
    minimize_parser.add_argument("finding_code")
    normalize_parser = subparsers.add_parser(
        "normalize", help="parse raw SDP and emit hash-only normalized facts"
    )
    normalize_parser.add_argument("sdp")
    normalize_parser.add_argument("--actor", choices=("local", "remote"), required=True)
    normalize_parser.add_argument("--type", choices=("offer", "answer"), required=True)
    normalize_parser.add_argument("--generation", type=int, default=0)
    normalize_parser.add_argument("--sequence", type=int, default=1)
    parsed = parser.parse_args(arguments)
    try:
        if parsed.command == "normalize":
            raw_path = Path(parsed.sdp)
            if raw_path.is_symlink() or not raw_path.is_file():
                raise SDPOracleError(
                    f"input must be a regular non-symlink file: {parsed.sdp}"
                )
            if raw_path.stat().st_size > 256 * 1024:
                raise SDPOracleError("raw SDP exceeds the safe parser boundary")
            try:
                raw_sdp = raw_path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise SDPOracleError(f"cannot read SDP input {parsed.sdp}: {exc}") from exc
            result = normalize_sdp(
                raw_sdp,
                actor=parsed.actor,
                revision_type=parsed.type,
                generation=parsed.generation,
                sequence=parsed.sequence,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        policy = _read(parsed.policy)
        transcript = _read(parsed.transcript)
        if parsed.command == "evaluate":
            result = evaluate(policy, transcript)
        elif parsed.command == "generate":
            result = generate_cases(policy, transcript)
        else:
            result = minimize_failure(
                policy, transcript, parsed.finding_code
            )
    except SDPOracleError as exc:
        print(f"SDP input rejected: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    if parsed.command != "evaluate":
        return 0
    return {"pass": 0, "fail": 1, "incomplete": 3}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
