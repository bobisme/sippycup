"""Offline tests for the dress rehearsal (`practice-target rehearsal`)."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup import practice, practice_rehearsal as rehearsal  # noqa: E402
from sippycup_workbench.journal import initialize  # noqa: E402
from sippycup_workbench.profile import load_profile, rehearse  # noqa: E402
from sippycup_workbench.scope import inspect  # noqa: E402
from sippycup_workbench.scope_derive import compile_scope  # noqa: E402

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)


def facts(address: str = "127.0.0.2", hours: float = 4) -> dict:
    return {"address": address, "profile_valid_until_utc": (NOW + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")}


class ScopeAnswersTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.work = Path(self.temporary.name) / "work"
        self.root = self.work / "eng"
        self.work.mkdir()
        initialize(self.root, title="t", owner="o")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_answers_check_clean_and_compile_into_an_approved_profile_with_checks(self) -> None:
        # A real CA certificate is needed for tls_ca_file; reuse one PEM shape.
        ca = self.root / "practice-ca.crt"
        ca.write_text(_pem())
        text = rehearsal.scope_answers(facts(), now=NOW, name="dress-rehearsal", ca_file="work/eng/practice-ca.crt")
        path = self.root / "scope.yaml"
        path.write_text(text)
        path.chmod(0o600)
        with mock.patch.dict(os.environ, {"SIPPYCUP_WORK_ROOT": str(self.work)}):
            report = inspect(path, now=NOW)
        problems = [f"{item.code} {item.field}" for item in report.findings if item.severity == "error"]
        self.assertEqual([], problems)
        self.assertTrue(report.ok and report.complete)
        self.assertIn("127.0.0.2", text)
        self.assertIn("valid_from: 2026-11-18T11:59:00Z", text)
        self.assertIn("valid_until: 2026-11-18T16:00:00Z", text)
        self.assertNotIn("password:", text)
        for check in rehearsal.CHECKS:
            self.assertIn(check, text)
        self.assertIn("max_requests: 33", text)

    def test_window_too_short_or_routable_address_is_refused(self) -> None:
        with self.assertRaises(rehearsal.CannotStart):
            rehearsal.scope_answers(facts(hours=0.1), now=NOW, name="x", ca_file="work/x/ca.crt")
        for address in ("10.0.0.5", "127.0.0.1", "192.0.2.1"):
            with self.subTest(address=address), self.assertRaises(practice.PracticeError):
                rehearsal.scope_answers(facts(address=address), now=NOW, name="x", ca_file="work/x/ca.crt")


def _pem() -> str:
    """A throwaway self-signed CA certificate (public material only)."""
    import shutil

    if shutil.which("openssl") is None:
        raise unittest.SkipTest("openssl is not available")
    with tempfile.TemporaryDirectory() as directory:
        key, cert = Path(directory) / "k", Path(directory) / "c"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "2", "-subj", "/CN=test-ca"],
                       check=True, capture_output=True)
        return cert.read_text()


class CompileTests(unittest.TestCase):
    def test_compiled_profile_rehearses_ready_and_carries_the_checks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "work" / "eng"
            root.parent.mkdir()
            initialize(root, title="t", owner="o")
            ca = root / "practice-ca.crt"
            ca.write_text(_pem())
            now = datetime.now(timezone.utc)
            live = {"address": "127.0.0.2",
                    "profile_valid_until_utc": (now + timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")}
            (root / "scope.yaml").write_text(rehearsal.scope_answers(live, now=now, name="dress-rehearsal",
                                                                     ca_file="work/eng/practice-ca.crt"))
            (root / "scope.yaml").chmod(0o600)
            with mock.patch.dict(os.environ, {"SIPPYCUP_WORK_ROOT": str(root.parent)}):
                outcome = compile_scope(root, now=now)
            self.assertEqual(0, outcome.exit_code, outcome.as_dict())
            profile = load_profile(root / "target-profile.yaml")
            self.assertTrue(rehearse(profile, now=now).ready)
            self.assertEqual([*rehearsal.UDP_CHECKS, "srtp-policy"], profile["security_checks"]["approved"])
            self.assertEqual(33, profile["security_checks"]["max_requests"])
            self.assertEqual("practice", profile["security_checks"]["account"])
            self.assertEqual(["127.0.0.2"], profile["target"]["approved_addresses"])

    def compile_shape(self, shape_facts: dict, *, proxy: bool, media_approved: bool = True):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name) / "work" / "eng"
        root.parent.mkdir()
        initialize(root, title="t", owner="o")
        (root / "practice-ca.crt").write_text(_pem())
        now = datetime.now(timezone.utc)
        live = {**shape_facts, "profile_valid_until_utc": (now + timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        shape = rehearsal.shape_for(live, proxy=proxy, media_approved=media_approved)
        text = rehearsal.scope_answers(live, now=now, name="dress-rehearsal", ca_file="work/eng/practice-ca.crt",
                                       shape=shape, checks=rehearsal.CHECKS if media_approved else ())
        (root / "scope.yaml").write_text(text)
        (root / "scope.yaml").chmod(0o600)
        with mock.patch.dict(os.environ, {"SIPPYCUP_WORK_ROOT": str(root.parent)}):
            outcome = compile_scope(root, now=now)
        self.assertEqual(0, outcome.exit_code, outcome.as_dict())
        import yaml

        profile = load_profile(root / "target-profile.yaml")
        self.assertTrue(rehearse(profile, now=now).ready)
        campaign = yaml.safe_load((root / "campaign.yaml").read_text())
        expectations = yaml.safe_load((root / "expectations.yaml").read_text())
        return text, profile, campaign, expectations

    def test_proxy_shape_compiles_with_signaling_and_media_on_different_addresses(self) -> None:
        text, profile, campaign, expectations = self.compile_shape(PROXY_FACTS, proxy=True)
        self.assertIn("networks: [127.0.0.3]", text)
        self.assertIn("networks: [127.0.0.2]", text)
        self.assertIn("realm: sippycup-proxy", text)
        self.assertEqual("127.0.0.3", profile["target"]["host"])
        self.assertEqual(["127.0.0.3", "127.0.0.2"], profile["target"]["approved_addresses"])
        self.assertEqual([*rehearsal.UDP_CHECKS, "srtp-policy"], profile["security_checks"]["approved"])
        # Signaling networks only; the media address is media only (bn-24x).
        self.assertEqual(["127.0.0.3/32"], campaign["authorization"]["networks"])
        self.assertEqual(["127.0.0.2/32"], campaign["authorization"]["mediaNetworks"])
        tls = next(item for item in campaign["targets"] if item["signaling"]["transport"] == "tls")
        self.assertEqual("sippycup-proxy", tls["signaling"]["tlsServerName"])
        self.assertEqual({"username": "practice", "realm": "sippycup-proxy", "register": True}, tls["account"])
        self.assertEqual({"127.0.0.3", "127.0.0.2", "127.0.0.1"}, set(expectations["capture"]["allowed_endpoints"]))

    def test_stop_leg_answers_approve_only_the_signaling_address(self) -> None:
        text, profile, campaign, expectations = self.compile_shape(PROXY_FACTS, proxy=True, media_approved=False)
        self.assertIn("DELIBERATE MISTAKE", text)
        self.assertNotIn("security_checks", text)
        self.assertEqual(["127.0.0.3"], profile["target"]["approved_addresses"])
        self.assertEqual(["127.0.0.3/32"], campaign["authorization"]["networks"])
        self.assertNotIn("mediaNetworks", campaign["authorization"])
        self.assertNotIn("127.0.0.2", expectations["capture"]["allowed_endpoints"])


PROXY_FACTS = {"address": "127.0.0.2", "proxy": {"address": "127.0.0.3", "dns_name": "sippycup-proxy"}}


class ShapeTests(unittest.TestCase):
    def test_direct_and_proxy_shapes(self) -> None:
        direct = rehearsal.shape_for(PROXY_FACTS, proxy=False)
        self.assertEqual(("127.0.0.2", ("127.0.0.2",), "sippycup-practice"),
                         (direct.signaling, direct.media, direct.server_name))
        proxy = rehearsal.shape_for(PROXY_FACTS, proxy=True)
        self.assertEqual(("127.0.0.3", ("127.0.0.2",), "sippycup-proxy", "sippycup-proxy"),
                         (proxy.signaling, proxy.media, proxy.server_name, proxy.realm))
        stop = rehearsal.shape_for(PROXY_FACTS, proxy=True, media_approved=False)
        self.assertEqual(("127.0.0.3",), stop.media)
        with self.assertRaises(ValueError):
            rehearsal.shape_for(PROXY_FACTS, proxy=False, media_approved=False)

    def test_missing_or_unsafe_proxy_facts_are_refused(self) -> None:
        with self.assertRaises(rehearsal.CannotStart):
            rehearsal.shape_for({"address": "127.0.0.2"}, proxy=True)
        with self.assertRaises(rehearsal.CannotStart):
            rehearsal.shape_for({"address": "127.0.0.2", "proxy": {"address": "127.0.0.2", "dns_name": "sippycup-proxy"}},
                                proxy=True)
        with self.assertRaises(rehearsal.CannotStart):
            rehearsal.shape_for({"address": "127.0.0.2", "proxy": {"address": "127.0.0.3", "dns_name": "evil\nx"}},
                                proxy=True)
        for address in ("10.0.0.5", "127.0.0.1"):
            with self.subTest(address=address), self.assertRaises(practice.PracticeError):
                rehearsal.shape_for({"address": "127.0.0.2", "proxy": {"address": address, "dns_name": "sippycup-proxy"}},
                                    proxy=True)

    def test_max_requests_is_exactly_the_declared_bounds(self) -> None:
        self.assertEqual({"approved": list(rehearsal.UDP_CHECKS), "max_requests": 21},
                         rehearsal.checks_section(rehearsal.UDP_CHECKS))
        self.assertEqual(33, rehearsal.checks_section()["max_requests"])


class CockpitAgreementTests(unittest.TestCase):
    MODEL = {"currentStage": "first-call", "nextCommand": "./bin/sippycup call x --dry-run", "complete": False,
             "stages": [{"id": "scope", "title": "Scope", "state": "done"},
                        {"id": "first-call", "title": "First call", "state": "current"}]}
    PLAIN = ("Stages\n  [ok] 3 Scope\n  [>>] 5 First call   <- you are here\n\n"
             "Next: ./bin/sippycup call x --dry-run\n")

    def test_agreeing_renderings_at_the_expected_stage(self) -> None:
        view = rehearsal.cockpit_view(self.MODEL, self.PLAIN)
        self.assertEqual("first-call", view["plainStage"])
        self.assertEqual([], rehearsal.agreement_problems(view, "first-call"))

    def test_wrong_stage_and_disagreement_are_reported(self) -> None:
        view = rehearsal.cockpit_view(self.MODEL, self.PLAIN)
        self.assertTrue(rehearsal.agreement_problems(view, "campaign"))
        other = rehearsal.cockpit_view(self.MODEL, self.PLAIN.replace("Next: ./bin/sippycup call x --dry-run",
                                                                      "Next: ./bin/sippycup something-else"))
        self.assertTrue(any("differs" in item for item in rehearsal.agreement_problems(other, "first-call")))
        moved = rehearsal.cockpit_view(self.MODEL, self.PLAIN.replace("[>>] 5 First call   <- you are here",
                                                                      "[>>] 3 Scope   <- you are here"))
        self.assertTrue(any("go --plain" in item for item in rehearsal.agreement_problems(moved, "first-call")))

    def test_complete(self) -> None:
        model = {"currentStage": None, "nextCommand": None, "complete": True, "stages": []}
        view = rehearsal.cockpit_view(model, "Stages\n\nNext: every stage is complete; record remediation.\n")
        self.assertEqual([], rehearsal.agreement_problems(view, None))
        self.assertTrue(rehearsal.agreement_problems(view, "report"))

    def test_only_offered_launcher_actions_are_used(self) -> None:
        model = {"actions": [
            {"id": "a", "available": True, "argv": ["./bin/sippycup", "summary", "work/x"]},
            {"id": "b", "available": False, "argv": ["./bin/sippycup", "x"], "unavailableReason": "blocked"},
            {"id": "c", "available": True, "argv": ["/bin/sh", "-c", "x"]},
        ]}
        self.assertEqual("a", rehearsal.find_action(model, "a")["id"])
        for identifier in ("b", "c", "missing"):
            with self.subTest(identifier=identifier), self.assertRaises(rehearsal.RehearsalError):
                rehearsal.find_action(model, identifier)


class StopLegTests(unittest.TestCase):
    REPORT = {
        "integrityExceptions": [{"code": "media-peer-not-approved", "run": "R",
                                 "detail": "media peer unapproved-address-1 is not an approved address; the "
                                           "media guard dropped the 1 RTP and 4 RTCP packets addressed to it "
                                           "before they left, so no media was sent to it, and the media-scope "
                                           "stop hung the call up"}],
        "runs": [{"kind": "call", "verdict": "media-outside-scope",
                  "details": {"media": {"toPeerPackets": 0, "peerApproved": False,
                                        "guardDropped": {"rtp": 1, "rtcp": 4, "other": 0}}}}],
        "findings": [{"id": "obs-media-outside-scope", "severity": "info",
                      "title": "Safety stop: media was negotiated to an address outside the approved scope"}],
        "executiveSummary": {"rows": [{"title": "1 run was ended by a Sippycup safety stop (media-outside-scope), "
                                                "not a target failure"}]},
    }

    def driver(self):
        return rehearsal.Rehearsal(Path("."), runner=lambda *a: None, out=io.StringIO())

    def test_a_correctly_presented_stop_passes(self) -> None:
        self.assertEqual(0, self.driver().stop_report(json.loads(json.dumps(self.REPORT))))

    def test_misleading_presentations_fail(self) -> None:
        cases = {
            # bn-3l8o: not one packet may reach the unapproved address, and
            # the report must carry the guard's RTP and RTCP counts.
            "one packet sent": lambda r: r["runs"][0]["details"]["media"].update(toPeerPackets=1),
            "no guard record": lambda r: r["runs"][0]["details"]["media"].pop("guardDropped"),
            "packets not explained": lambda r: r["integrityExceptions"][0].update(
                detail="the media-scope stop hung the call up after 1 RTP packet was sent to it"),
            "a target finding": lambda r: r["findings"][0].update(severity="low"),
            "an oracle observation": lambda r: r["findings"].append({"id": "obs-oracle-assertion-failed"}),
            "no exception": lambda r: r.update(integrityExceptions=[]),
            "did not pass": lambda r: r["executiveSummary"]["rows"].__setitem__(0, {"title": "1 run did not pass"}),
        }
        for name, mutate in cases.items():
            report = json.loads(json.dumps(self.REPORT))
            mutate(report)
            with self.subTest(name), self.assertRaises(rehearsal.RehearsalError):
                self.driver().stop_report(report)

    def test_the_cockpit_must_mark_the_stop(self) -> None:
        run = {"kind": "call", "verdict": "media-outside-scope", "safetyStop": True,
               "reason": "safety stop, not a target failure: ..."}
        self.driver().require_stop_presented({"runs": [run]})
        with self.assertRaises(rehearsal.RehearsalError):
            self.driver().require_stop_presented({"runs": [{**run, "safetyStop": False}]})


class SecretScanTests(unittest.TestCase):
    def test_files_containing_finds_the_secret_anywhere(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a").mkdir()
            (root / "a" / "clean.txt").write_text("nothing here")
            (root / "a" / "leak.bin").write_bytes(b"\x00xx-hunter2-xx")
            self.assertEqual(["a/leak.bin"], rehearsal.files_containing(root, b"hunter2"))


class FailureSummaryTests(unittest.TestCase):
    def test_a_failed_call_names_the_failing_assertion_and_host_run_path(self) -> None:
        printed = json.dumps({"verdict": "fail", "runDirectory": "/work/eng/calls/R1", "oracle": {
            "failedDetails": [{"id": "dialog[0].media.timing", "message": "late media"}]}})
        self.assertEqual("verdict fail; dialog[0].media.timing: late media; run work/eng/calls/R1",
                         rehearsal._failure_summary(printed))
        self.assertIsNone(rehearsal._failure_summary("not json"))


class DriverTests(unittest.TestCase):
    def test_missing_practice_image_stops_before_anything_is_sent(self) -> None:
        calls = []

        def runner(argv, env, timeout):
            calls.append(argv)
            return rehearsal.Completed(argv, 1, "Practice profile: not installed\nTarget: down\n", "")

        with tempfile.TemporaryDirectory() as directory:
            out = io.StringIO()
            code = rehearsal.Rehearsal(Path(directory), runner=runner, out=out).execute()
        self.assertEqual(2, code)
        self.assertEqual([["./bin/sippycup", "practice-target", "status"]], calls)
        self.assertIn("practice-target build", out.getvalue())

    def test_a_failed_stage_skips_the_rest_and_exits_1(self) -> None:
        stages = []
        driver = rehearsal.Rehearsal(Path("."), runner=lambda *a: None, out=io.StringIO())

        def fail():
            raise rehearsal.RehearsalError("boom")

        self.assertFalse(driver.stage("one", fail))
        self.assertFalse(driver.stage("two", lambda: stages.append("ran")))
        self.assertEqual(["FAIL", "SKIP"], [stage.status for stage in driver.stages])
        self.assertEqual([], stages)

    def test_list_is_network_free(self) -> None:
        result = subprocess.run([str(ROOT / "bin" / "sippycup"), "practice-target", "rehearsal", "--list"],
                                cwd=ROOT, capture_output=True, text=True, check=False)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("owner report: summary --forbid-file", result.stdout)
        self.assertIn("12. safety stop: media address not approved", result.stdout)
        self.assertIn("Network activity: none", result.stdout)
        proxy = subprocess.run([str(ROOT / "bin" / "sippycup"), "practice-target", "rehearsal", "--proxy", "--list"],
                               cwd=ROOT, capture_output=True, text=True, check=False)
        self.assertEqual(0, proxy.returncode, proxy.stderr)
        self.assertIn("scope answers (proxy shape)", proxy.stdout)
        self.assertIn("preflight to the proxy", proxy.stdout)


if __name__ == "__main__":
    unittest.main()
