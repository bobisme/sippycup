"""Fail-closed signaling and secure-media policy oracle."""

from __future__ import annotations

from typing import Any

from .common import (
    ResilienceError,
    boolean,
    exact_keys,
    nonempty_string,
    require_mapping,
    verdict,
)

REPORT_VERSION = "sippycup.dev/secure-media-report/v1"
PROFILES = ("sip-tls", "srtp", "dtls-srtp")


def analyze_secure_media(policy_value: Any, observation_value: Any) -> dict[str, Any]:
    policy = require_mapping(policy_value, "secure-media policy")
    exact_keys(
        policy,
        (
            "profile",
            "requireMutualTls",
            "minimumTlsVersion",
            "allowRtpFallback",
            "requireReplayProtection",
        ),
        name="secure-media policy",
    )
    if policy["profile"] not in PROFILES:
        raise ResilienceError(f"profile must be one of {', '.join(PROFILES)}")
    require_mtls = boolean(policy["requireMutualTls"], "requireMutualTls")
    allow_fallback = boolean(policy["allowRtpFallback"], "allowRtpFallback")
    require_replay = boolean(
        policy["requireReplayProtection"], "requireReplayProtection"
    )
    minimum_tls = nonempty_string(
        policy["minimumTlsVersion"], "minimumTlsVersion", 16
    )
    if minimum_tls not in {"TLS1.2", "TLS1.3"}:
        raise ResilienceError("minimumTlsVersion must be TLS1.2 or TLS1.3")
    observation = require_mapping(observation_value, "secure-media observation")
    exact_keys(
        observation,
        (
            "certificateValid",
            "hostnameValid",
            "mutualTls",
            "tlsVersion",
            "mediaProfile",
            "authenticationValid",
            "replayAccepted",
            "keyMaterialExposed",
        ),
        name="secure-media observation",
    )
    for key in (
        "certificateValid",
        "hostnameValid",
        "mutualTls",
        "authenticationValid",
        "replayAccepted",
        "keyMaterialExposed",
    ):
        boolean(observation[key], key)
    tls_version = nonempty_string(observation["tlsVersion"], "tlsVersion", 16)
    if tls_version not in {"TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"}:
        raise ResilienceError("tlsVersion is unsupported")
    media_profile = nonempty_string(
        observation["mediaProfile"], "mediaProfile", 32
    )
    if media_profile not in {"RTP", "SRTP", "DTLS-SRTP"}:
        raise ResilienceError("mediaProfile is unsupported")
    findings: list[dict[str, Any]] = []

    def fail(code: str) -> None:
        findings.append({"severity": "fail", "code": code})

    if not observation["certificateValid"]:
        fail("certificate_invalid")
    if not observation["hostnameValid"]:
        fail("hostname_or_sni_invalid")
    versions = {"TLS1.0": 10, "TLS1.1": 11, "TLS1.2": 12, "TLS1.3": 13}
    if versions[tls_version] < versions[minimum_tls]:
        fail("tls_version_downgrade")
    if require_mtls and not observation["mutualTls"]:
        fail("mutual_tls_missing")
    expected_media = {"sip-tls": None, "srtp": "SRTP", "dtls-srtp": "DTLS-SRTP"}[
        policy["profile"]
    ]
    if expected_media is not None and media_profile != expected_media:
        if not (allow_fallback and media_profile == "RTP"):
            fail("media_profile_downgrade")
    if media_profile in {"SRTP", "DTLS-SRTP"} and not observation["authenticationValid"]:
        fail("media_authentication_failed")
    if require_replay and media_profile == "RTP":
        fail("replay_protection_unavailable")
    if require_replay and observation["replayAccepted"]:
        fail("replay_accepted")
    if observation["keyMaterialExposed"]:
        fail("key_material_exposed")
    return {
        "apiVersion": REPORT_VERSION,
        "status": verdict(findings),
        "profile": policy["profile"],
        "findings": findings,
        "cryptographicStrengthClaim": None,
    }


def default_policy(profile: str) -> dict[str, Any]:
    if profile not in PROFILES:
        raise ResilienceError(f"profile must be one of {', '.join(PROFILES)}")
    return {
        "profile": profile,
        "requireMutualTls": False,
        "minimumTlsVersion": "TLS1.2",
        "allowRtpFallback": False,
        "requireReplayProtection": profile != "sip-tls",
    }


def clean_observation(profile: str) -> dict[str, Any]:
    if profile not in PROFILES:
        raise ResilienceError(f"profile must be one of {', '.join(PROFILES)}")
    return {
        "certificateValid": True,
        "hostnameValid": True,
        "mutualTls": False,
        "tlsVersion": "TLS1.3",
        "mediaProfile": {
            "sip-tls": "RTP",
            "srtp": "SRTP",
            "dtls-srtp": "DTLS-SRTP",
        }[profile],
        "authenticationValid": True,
        "replayAccepted": False,
        "keyMaterialExposed": False,
    }
