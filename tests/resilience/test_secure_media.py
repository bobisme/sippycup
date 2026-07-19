import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_resilience.common import ResilienceError
from sippycup_resilience.secure_media import (
    PROFILES,
    analyze_secure_media,
    clean_observation,
    default_policy,
)


class SecureMediaTests(unittest.TestCase):
    def test_all_profiles_pass_clean_observation_without_strength_claim(self):
        for profile in PROFILES:
            with self.subTest(profile=profile):
                report = analyze_secure_media(
                    default_policy(profile), clean_observation(profile)
                )
                self.assertEqual(report["status"], "pass")
                self.assertIsNone(report["cryptographicStrengthClaim"])

    def test_every_security_failure_is_independent(self):
        policy = default_policy("dtls-srtp")
        policy["requireMutualTls"] = True
        observation = clean_observation("dtls-srtp")
        observation.update(
            {
                "certificateValid": False,
                "hostnameValid": False,
                "mutualTls": False,
                "tlsVersion": "TLS1.1",
                "mediaProfile": "RTP",
                "authenticationValid": False,
                "replayAccepted": True,
                "keyMaterialExposed": True,
            }
        )
        codes = {
            item["code"]
            for item in analyze_secure_media(policy, observation)["findings"]
        }
        self.assertEqual(
            codes,
            {
                "certificate_invalid",
                "hostname_or_sni_invalid",
                "mutual_tls_missing",
                "tls_version_downgrade",
                "media_profile_downgrade",
                "replay_protection_unavailable",
                "replay_accepted",
                "key_material_exposed",
            },
        )

    def test_explicit_rtp_fallback_is_not_silently_assumed(self):
        policy = default_policy("srtp")
        observation = clean_observation("srtp")
        observation["mediaProfile"] = "RTP"
        self.assertEqual(analyze_secure_media(policy, observation)["status"], "fail")
        policy["allowRtpFallback"] = True
        policy["requireReplayProtection"] = False
        self.assertEqual(analyze_secure_media(policy, observation)["status"], "pass")

    def test_unknown_and_boolean_policy_values_fail_closed(self):
        policy = default_policy("srtp")
        policy["unknown"] = True
        with self.assertRaisesRegex(ResilienceError, "unsupported"):
            analyze_secure_media(policy, clean_observation("srtp"))
        policy = default_policy("srtp")
        policy["allowRtpFallback"] = 1
        with self.assertRaisesRegex(ResilienceError, "boolean"):
            analyze_secure_media(policy, clean_observation("srtp"))


if __name__ == "__main__":
    unittest.main()
