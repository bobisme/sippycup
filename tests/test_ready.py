"""Unit tests for ``./bin/sippycup ready`` (go/no-go), with fakes for every host fact.

Nothing here starts a container or contacts a network: the container probe,
``timedatectl``, ``chronyc``, ``ip route``, the image probe, and free disk are
all answered by ``FakeHost``.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import sys

sys.path.insert(0, str(Path(__file__).parent))

from cockpit_support import NOW, ROOT, compiled_engagement, iso, make_repo, write_go  # noqa: E402

from sippycup_cockpit import ready  # noqa: E402
from sippycup_cockpit.model import build_model  # noqa: E402

GOOD_PROBE = {"schema_version": "sippycup.dev/ready-probe/v1", "network_mode": "private", "cap_net_raw": True,
              "capture": {"ok": True, "packets": 3, "interface": "lo"}, "workdir_writable": True,
              "route": {"ok": True, "source": "12.0.0.7"}}
GOOD_IMAGE = {"image": "localhost/sippycup:test", "checked": True, "present": True, "stale": False,
              "created": "2026-11-17T10:00:00Z", "method": "build record vs checkout fingerprint", "dirty": False}


class FakeHost(ready.Host):
    def __init__(self, repo: Path, *, now: datetime = NOW, environ: dict[str, str] | None = None):
        super().__init__(repo, environ=environ or {}, clock=lambda: now)
        self.tools = {"timedatectl", "ip"}
        self.timedatectl = "NTPSynchronized=yes\nNTP=yes\nTimezone=UTC\n"
        self.chronyc = "Leap status     : Normal\nSystem time     : 0.000001 seconds fast\n"
        self.route = [{"dst": "x", "gateway": "12.0.0.1", "dev": "eth0", "prefsrc": "12.0.0.7"}]
        self.route_code = 0
        self.defaults = [{"gateway": "12.0.0.1", "dev": "eth0"}]
        self.probe: dict | None = json.loads(json.dumps(GOOD_PROBE))
        self.probe_code = 0
        self.image = dict(GOOD_IMAGE)
        self.free = 50 * 1024 ** 3
        self.calls: list[list[str]] = []

    def run(self, argv, timeout=30):
        self.calls.append(list(argv))
        if argv[0] == "timedatectl":
            return 0, self.timedatectl, ""
        if argv[0] == "chronyc":
            return 0, self.chronyc, ""
        if argv[:4] == ["ip", "-j", "route", "get"]:
            return (self.route_code, json.dumps(self.route), "RTNETLINK answers: Network is unreachable"
                    if self.route_code else "")
        if argv[:4] == ["ip", "-j", "route", "show"]:
            return 0, json.dumps(self.defaults), ""
        if argv[0].endswith("bin/sippycup") and "--ready-probe" in argv:
            return self.probe_code, json.dumps(self.probe) if self.probe is not None else "", "boom"
        raise AssertionError(f"unexpected command {argv}")

    def which(self, name):
        return f"/usr/bin/{name}" if name in self.tools else None

    def disk_free(self, path):
        return self.free

    def probe_image(self, image):
        return dict(self.image, image=image)

    def local_zone(self):
        return timezone.utc


class ReadyTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = make_repo(Path(self.temp.name))
        (self.repo / "bin").mkdir()
        self.root = compiled_engagement(self.repo, now=NOW, account=True, go=False)
        self.password = self.root / "account.password"
        self.password.write_text("correct horse\n", encoding="utf-8")
        self.password.chmod(0o600)
        self.host = FakeHost(self.repo)

    def assess(self, **kwargs) -> dict:
        kwargs.setdefault("image", "localhost/sippycup:test")
        return ready.assess(self.root, host=self.host, **kwargs)

    def check(self, result: dict, identifier: str) -> dict:
        return next(item for item in result["checks"] if item["id"] == identifier)


class ReadyVerdictTests(ReadyTestCase):
    def test_everything_in_order_is_go_and_sends_nothing_to_the_target(self) -> None:
        # 127.0.0.2 without a practice target up: the fake routes it; loopback is only a warning.
        result = self.assess()
        statuses = {item["id"]: item["status"] for item in result["checks"]}
        self.assertEqual("GO", result["verdict"], statuses)
        self.assertEqual("go", statuses["credentials"])
        self.assertEqual(0, result["blocking"])
        probe = [call for call in self.host.calls if "--ready-probe" in call]
        self.assertEqual(1, len(probe))
        self.assertEqual("--isolated", probe[0][1], "the probe runs in the live commands' network mode")
        self.assertNotIn("correct horse", json.dumps(result))

    def test_practice_target_uses_the_practice_namespace(self) -> None:
        from cockpit_support import practice_state

        practice_state(self.repo, now=NOW)
        result = self.assess()
        probe = next(call for call in self.host.calls if "--ready-probe" in call)
        self.assertEqual("--practice", probe[1])
        self.assertNotIn("--route-to", probe)
        self.assertEqual("go", self.check(result, "network")["status"])
        self.assertEqual("--practice", result["route"])

    def test_main_exit_codes_json_and_record(self) -> None:
        out = io.StringIO()
        with redirect_stdout(out):
            code = ready.main([str(self.root), "--format", "json", "--repo", str(self.repo),
                               "--image", "localhost/sippycup:test"], host=self.host)
        value = json.loads(out.getvalue())
        self.assertEqual(0, code)
        self.assertEqual("GO", value["verdict"])
        records = sorted((self.root / "readiness").glob("ready-*.json"))
        self.assertEqual(1, len(records))
        self.assertEqual(0o600, records[0].stat().st_mode & 0o777)
        facts = ready.gate_facts(self.root, True, NOW)
        self.assertTrue(facts["go"] and facts["current"])
        self.host.image["present"] = False
        out = io.StringIO()
        with redirect_stdout(out):
            code = ready.main([str(self.root), "--repo", str(self.repo)], host=self.host)
        self.assertEqual(1, code)
        self.assertIn("VERDICT: NO-GO", out.getvalue())
        self.assertIn("fix: make build IMAGE=", out.getvalue())
        self.assertFalse(ready.gate_facts(self.root, True, NOW + timedelta(seconds=1))["go"])
        with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as raised:
            ready.main([str(self.root), "--margin", "-1"], host=self.host)
        self.assertEqual(2, raised.exception.code)
        self.assertEqual(2, ready.main([str(self.root / "missing")], host=self.host))

    def test_a_go_for_an_older_profile_is_not_current(self) -> None:
        write_go(self.root, now=NOW)
        profile = self.root / "target-profile.yaml"
        profile.write_text(profile.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        facts = ready.gate_facts(self.root, True, NOW)
        self.assertTrue(facts["present"])
        self.assertFalse(facts["current"])
        self.assertFalse(facts["go"])


class EngagementScopeProfileTests(ReadyTestCase):
    def test_invalid_journal_is_no_go(self) -> None:
        (self.root / "journal.jsonl").write_text("{not json\n", encoding="utf-8")
        item = self.check(self.assess(), "engagement")
        self.assertEqual("no-go", item["status"])
        self.assertIn("journal verify", item["fix"])

    def test_stale_scope_is_no_go_with_compile_fix(self) -> None:
        scope = self.root / "scope.yaml"
        scope.write_text(scope.read_text(encoding="utf-8").replace("contact:\n  name: Fixture operator",
                                                                    "contact:\n  name: Other operator"),
                         encoding="utf-8")
        item = self.check(self.assess(), "scope")
        self.assertEqual("no-go", item["status"], item)
        self.assertEqual(f"./bin/sippycup scope compile work/{self.root.name}", item["fix"])

    def test_profile_that_rehearse_refuses_is_no_go(self) -> None:
        later = NOW + timedelta(hours=5)
        self.host = FakeHost(self.repo, now=later)
        result = self.assess()
        self.assertEqual("no-go", self.check(result, "profile")["status"])
        window = self.check(result, "window")
        self.assertEqual("no-go", window["status"])
        self.assertIn("EXPIRED", window["lines"])
        self.assertIn("scope compile", window["fix"])
        self.assertEqual("NO-GO", result["verdict"])


class WindowTests(unittest.TestCase):
    def model(self, start, end, status="approved", plan=None) -> dict:
        return {"authorization": {"status": status, "validFrom": iso(start), "validUntil": iso(end), "text": status},
                "engagement": {"display": "work/eng"}, "files": {"planFacts": plan}}

    def test_not_open_yet_is_no_go_with_the_time_to_wait(self) -> None:
        item = ready.check_window(self.model(NOW + timedelta(hours=1), NOW + timedelta(hours=4)), NOW,
                                  timezone.utc, 60)
        self.assertEqual("no-go", item.status)
        self.assertIn("wait until 2026-11-17 13:00:00 UTC", item.fix)

    def test_less_than_margin_warns_and_shows_both_clocks(self) -> None:
        item = ready.check_window(self.model(NOW - timedelta(hours=1), NOW + timedelta(minutes=40)), NOW,
                                  timezone(timedelta(hours=-5), "EST"), 60)
        self.assertEqual("warn", item.status)
        text = "\n".join(item.lines)
        self.assertIn("remaining  00h 40m", text)
        self.assertIn("EST (2026-11-17T12:40:00Z)", text)

    def test_campaign_plan_duration_is_added_to_the_margin(self) -> None:
        plan = {"plannedTotals": {"durationSeconds": 7200}}
        item = ready.check_window(
            dict(self.model(NOW - timedelta(hours=1), NOW + timedelta(hours=2)), files={"planFacts": plan}),
            NOW, timezone.utc, 60)
        self.assertEqual("warn", item.status)
        self.assertIn("7200 s", item.lines[-1])

    def test_pending_authorization_is_no_go(self) -> None:
        item = ready.check_window(self.model(NOW - timedelta(hours=1), NOW + timedelta(hours=2), status="pending"),
                                  NOW, timezone.utc, 60)
        self.assertEqual("no-go", item.status)


class ClockAndImageTests(ReadyTestCase):
    def test_unsynchronised_clock_is_no_go(self) -> None:
        self.host.timedatectl = "NTPSynchronized=no\nNTP=no\n"
        item = ready.check_clock(self.host)
        self.assertEqual("no-go", item.status)
        self.assertIn("timedatectl set-ntp true", item.fix)

    def test_chrony_fallback(self) -> None:
        self.host.tools = {"chronyc"}
        self.assertEqual("go", ready.check_clock(self.host).status)
        self.host.chronyc = "Leap status     : Not synchronised\n"
        self.assertEqual("no-go", ready.check_clock(self.host).status)

    def test_unknown_clock_warns_and_never_asks_a_time_server(self) -> None:
        self.host.tools = set()
        item = ready.check_clock(self.host)
        self.assertEqual("warn", item.status)
        self.assertEqual([], self.host.calls)

    def test_image_branches(self) -> None:
        self.host.image.update(present=False)
        self.assertEqual("no-go", ready.check_image(self.host, "img").status)
        self.host.image.update(present=True, stale=True)
        item = ready.check_image(self.host, "img")
        self.assertEqual(("no-go", "make build IMAGE=img"), (item.status, item.fix))
        self.host.image.update(checked=False, detail="no runtime")
        self.assertEqual("no-go", ready.check_image(self.host, "img").status)
        self.host.image = dict(GOOD_IMAGE, stale=False, method="heuristic: image creation time vs last commit")
        self.assertEqual("warn", ready.check_image(self.host, "img").status)


class CaptureTests(ReadyTestCase):
    def test_missing_image_is_never_started_or_pulled(self) -> None:
        self.host.image.update(present=False)
        result = self.assess()
        self.assertFalse([call for call in self.host.calls if "--ready-probe" in call])
        item = self.check(result, "capture")
        self.assertEqual("no-go", item["status"])
        self.assertIn("toolbox image is not available", item["lines"][0])

    def test_probe_container_that_does_not_run_is_no_go(self) -> None:
        self.host.probe_code, self.host.probe = 125, None
        item = self.check(self.assess(), "capture")
        self.assertEqual("no-go", item["status"])
        self.assertIn("doctor --ready-probe", item["fix"])

    def test_failed_loopback_capture_is_no_go(self) -> None:
        self.host.probe["capture"] = {"ok": False, "error": "You don't have permission to capture on that device"}
        self.host.probe["cap_net_raw"] = False
        item = self.check(self.assess(), "capture")
        self.assertEqual("no-go", item["status"])
        self.assertIn("permission", item["lines"][0])

    def test_unwritable_work_and_low_disk_are_no_go(self) -> None:
        self.host.probe["workdir_writable"] = False
        self.assertEqual("no-go", self.check(self.assess(), "capture")["status"])
        self.host.probe["workdir_writable"] = True
        self.host.free = 100 * 1024 * 1024
        item = self.check(self.assess(min_free_mb=2048), "capture")
        self.assertEqual("no-go", item["status"])
        self.assertIn("100 MiB", item["lines"][-1])


class CredentialTests(ReadyTestCase):
    def cred(self, **kwargs) -> dict:
        return self.check(self.assess(**kwargs), "credentials")

    def test_default_file_in_the_engagement_root_is_accepted(self) -> None:
        item = self.cred()
        self.assertEqual("go", item["status"], item)
        self.assertIn("ends with one line break (the tools remove it)", item["lines"])

    def test_group_readable_file_is_no_go_with_chmod(self) -> None:
        self.password.chmod(0o640)
        item = self.cred(secret_file=f"work/{self.root.name}/account.password")
        self.assertEqual("no-go", item["status"])
        self.assertEqual(f"chmod 600 work/{self.root.name}/account.password", item["fix"])

    def test_missing_empty_multiline_bom_and_spaces_are_no_go(self) -> None:
        cases = {
            "missing": None, "empty": b"\n", "two lines": b"pass\nword\n", "bom": b"\xef\xbb\xbfpassword",
            "spaces": b"password \n", "not utf-8": b"\xff\xfe",
        }
        for label, data in cases.items():
            with self.subTest(label=label):
                path = self.root / f"{label.replace(' ', '-')}.password"
                if data is not None:
                    path.write_bytes(data)
                    path.chmod(0o600)
                item = self.cred(secret_file=f"work/{self.root.name}/{path.name}")
                self.assertEqual("no-go", item["status"], item)
                self.assertTrue(item["fix"])
                self.assertNotIn("pass", " ".join(item["lines"]).replace("password", ""))

    def test_secret_inside_the_evidence_tree_is_no_go(self) -> None:
        calls = self.root / "calls"
        calls.mkdir()
        inside = calls / "account.password"
        inside.write_text("secret", encoding="utf-8")
        inside.chmod(0o600)
        item = self.cred(secret_file=f"work/{self.root.name}/calls/account.password")
        self.assertEqual("no-go", item["status"])
        self.assertIn("evidence tree", item["lines"][-1])
        self.assertTrue(item["fix"].startswith("mv "))

    def test_secret_outside_work_is_no_go(self) -> None:
        outside = Path(self.temp.name) / "pw"
        outside.write_text("secret", encoding="utf-8")
        outside.chmod(0o600)
        item = self.cred(secret_file=str(outside))
        self.assertEqual("no-go", item["status"])
        self.assertIn("beneath", item["lines"][0])

    def test_env_branches(self) -> None:
        item = self.cred(secret_env="SIP_PASSWORD")
        self.assertEqual("no-go", item["status"])
        self.assertIn("read -rs SIP_PASSWORD", item["fix"])
        self.host.environ = {"SIP_PASSWORD": "pw\nextra"}
        self.assertEqual("no-go", self.cred(secret_env="SIP_PASSWORD")["status"])
        self.host.environ = {"SIP_PASSWORD": "good-password\n"}
        self.assertEqual("go", self.cred(secret_env="SIP_PASSWORD")["status"])
        self.assertEqual("no-go", self.cred(secret_env="BAD-NAME")["status"])

    def test_no_source_when_an_account_is_needed_warns(self) -> None:
        self.password.unlink()
        item = self.cred()
        self.assertEqual("warn", item["status"])
        self.assertIn("--secret-file", item["fix"])


class TlsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = make_repo(Path(self.temp.name))
        self.root = self.repo / "work" / "eng"
        self.root.mkdir()
        (self.repo / "work" / "eng" / "ca.crt").write_bytes((ROOT / "tests" / "fixtures" / "tls" / "test-ca.crt").read_bytes())
        self.host = FakeHost(self.repo)
        self.model = {"engagement": {"display": "work/eng", "path": str(self.root)}}

    def document(self, **target) -> dict:
        value = {"host": "203.0.113.5", "port": 5061, "transport": "tls", "tls_server_name": "sip.owner.test",
                 "tls_ca_file": "work/eng/ca.crt"}
        value.update(target)
        return {"target": {key: item for key, item in value.items() if item is not None}}

    def check(self, **target) -> ready.Check:
        result = ready.check_tls(self.host, self.model, self.document(**target), NOW, timezone.utc)
        assert result is not None
        return result

    def test_udp_profile_has_no_tls_line(self) -> None:
        self.assertIsNone(ready.check_tls(self.host, self.model, {"target": {"transport": "udp"}}, NOW, timezone.utc))

    def test_good_ca_parses_and_names_the_server(self) -> None:
        with mock.patch.object(ready, "_cert_dates", return_value=[("CN=Test CA", NOW + timedelta(days=300))]):
            item = self.check()
        self.assertEqual("go", item.status, item.lines)
        self.assertIn("SHA-256", item.lines[1])

    def test_missing_server_name_missing_ca_and_bad_pin_are_no_go(self) -> None:
        self.assertEqual("no-go", self.check(tls_server_name=None).status)
        self.assertEqual("no-go", self.check(tls_ca_file="work/eng/absent.crt").status)
        (self.root / "plan.json").write_text(json.dumps({"steps": [
            {"tls": {"caFile": "work/eng/ca.crt", "caSha256": "0" * 64, "serverName": "sip.owner.test"}}]}))
        item = self.check()
        self.assertEqual("no-go", item.status)
        self.assertIn("campaign plan", item.fix)

    def test_expired_ca_is_no_go_and_soon_expiring_warns(self) -> None:
        with mock.patch.object(ready, "_cert_dates", return_value=[("CN=Test CA", NOW - timedelta(days=1))]):
            self.assertEqual("no-go", self.check().status)
        with mock.patch.object(ready, "_cert_dates", return_value=[("CN=Test CA", NOW + timedelta(days=2))]):
            self.assertEqual("warn", self.check().status)

    def test_real_certificate_dates_are_read_offline(self) -> None:
        pem = (ROOT / "tests" / "fixtures" / "tls" / "test-ca.crt").read_text(encoding="ascii")
        dates = ready._cert_dates(pem, self.host)
        self.assertTrue(dates)
        self.assertIsInstance(dates[0][1], datetime)


class NetworkTests(ReadyTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.model = build_model(self.root, repo=self.repo, now=NOW, advisor=False)
        self.model["target"]["host"] = "11.1.2.3"  # public (TEST-NET ranges count as private)

    def network(self, probe=GOOD_PROBE) -> ready.Check:
        return ready.check_network(self.host, self.model, "--isolated", probe)[0]

    def test_public_source_is_go_and_printed(self) -> None:
        item = self.network()
        self.assertEqual("go", item.status, item.lines)
        self.assertIn("source 12.0.0.7", item.lines[0])

    def test_no_route_is_no_go(self) -> None:
        self.host.route_code = 2
        item = self.network()
        self.assertEqual("no-go", item.status)
        self.assertIn("ip route get 11.1.2.3", item.fix)

    def test_container_without_route_is_no_go(self) -> None:
        probe = dict(GOOD_PROBE, route={"ok": False, "error": "Network is unreachable"})
        self.assertEqual("no-go", self.network(probe).status)

    def test_private_source_to_public_target_warns_about_nat(self) -> None:
        self.host.route = [{"dev": "eth0", "prefsrc": "192.168.1.20", "gateway": "192.168.1.1"}]
        item = self.network()
        self.assertEqual("warn", item.status)
        self.assertIn("NAT", item.lines[1])
        self.host.route = [{"dev": "eth0", "prefsrc": "100.64.3.4", "gateway": "100.64.0.1"}]
        self.assertEqual("warn", self.network().status, "carrier-grade NAT counts as NAT")

    def test_vpn_interface_and_two_default_routes_warn(self) -> None:
        self.host.route = [{"dev": "wg0", "prefsrc": "12.0.0.7"}]
        self.assertIn("VPN", " ".join(self.network().lines))
        self.host.route = [{"dev": "eth0", "prefsrc": "12.0.0.7"}]
        self.host.defaults = [{"gateway": "12.0.0.1", "dev": "eth0"}, {"gateway": "10.8.0.1", "dev": "tun0"}]
        item = self.network()
        self.assertEqual("warn", item.status)
        self.assertIn("2 default routes", " ".join(item.lines))


class RenderTests(ReadyTestCase):
    def test_text_has_one_verdict_a_mark_per_line_and_fixes(self) -> None:
        self.host.timedatectl = "NTPSynchronized=no\n"
        result = self.assess()
        lines = ready.render(result, f"work/{self.root.name}/readiness/ready-x.json")
        text = "\n".join(lines)
        self.assertEqual(1, text.count("VERDICT:"))
        self.assertIn("VERDICT: NO-GO", text)
        self.assertIn("[NO-GO] Clock synchronised", text)
        self.assertIn("fix: sudo timedatectl set-ntp true", text)
        self.assertIn("What the profile authorizes", text)
        self.assertIn("--evidence readiness/ready-x.json", text)


if __name__ == "__main__":
    unittest.main()
