"""bn-2jg safety-audit regressions outside the softphone driver.

See docs/SAFETY-AUDIT.md. Host-only; no container, capture, or socket.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_workbench.profile import rehearse  # noqa: E402

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)


def profile(host: object, approved: list[object]) -> dict:
    return {
        "schema_version": "sippycup.dev/target-profile/v1",
        "name": "audit",
        "target": {"host": host, "port": 5060, "transport": "udp", "approved_addresses": approved},
        "authorization": {
            "status": "approved", "approved_by": "owner", "approval_id": "CHG-1",
            "valid_from": (NOW - timedelta(hours=1)).isoformat(),
            "valid_until": (NOW + timedelta(hours=1)).isoformat(),
        },
        "limits": {"max_calls": 1, "max_concurrency": 1, "max_calls_per_second": 1, "max_duration_seconds": 30},
        "capture": {"interface": "any", "output": "work/call.pcap"},
        "features": {"ice": False, "turn": False, "srtp": False, "dtls_srtp": False, "webrtc": False},
    }


class ApprovedAddressSpellingTests(unittest.TestCase):
    """An approved address is exactly what a reviewer read: one canonical unicast literal."""

    def refused(self, host: object, approved: list[object]) -> list[str]:
        result = rehearse(copy.deepcopy(profile(host, approved)), now=NOW)
        self.assertFalse(result.ready, f"{approved!r} must not be ready")
        return list(result.errors)

    def test_a_yaml_integer_is_not_an_address(self):
        # 2130706433 is 127.0.0.1; ipaddress accepts the integer, a reviewer would not.
        errors = self.refused("127.0.0.2", ["127.0.0.2", 2130706433])
        self.assertTrue(any("canonical" in error for error in errors), errors)

    def test_non_canonical_spellings_are_refused(self):
        for spelling in ("2001:DB8::1", "2001:db8:0:0::1"):
            with self.subTest(spelling=spelling):
                self.refused(spelling, [spelling])

    def test_addresses_that_are_not_one_unicast_host_are_refused(self):
        for address in ("0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255"):
            with self.subTest(address=address):
                errors = self.refused(address, [address])
                self.assertTrue(any("unicast" in error for error in errors), errors)

    def test_canonical_unicast_literals_stay_ready(self):
        for address in ("192.0.2.10", "127.0.0.2", "2001:db8::1"):
            with self.subTest(address=address):
                self.assertTrue(rehearse(profile(address, [address]), now=NOW).ready)


if __name__ == "__main__":
    unittest.main()
