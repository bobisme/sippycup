"""Offline tests for the fault destinations, the rehearsal drill, and the gate's wire rules."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))

from sippycup import practice, practice_drill  # noqa: E402
import practice_faults  # noqa: E402


def row(**values) -> dict[str, str]:
    base = {name: "" for name in practice_faults.FIELDS}
    base.update({name.replace("_", "."): value for name, value in values.items()})
    return base


def sip_request(number, at, method, src, dst="127.0.0.2"):
    return {**row(), "frame.number": str(number), "frame.time_relative": str(at),
            "ip.src": src, "ip.dst": dst, "sip.Method": method}


def sip_response(number, at, status, method="INVITE", src="127.0.0.2"):
    return {**row(), "frame.number": str(number), "frame.time_relative": str(at),
            "ip.src": src, "sip.Status-Code": str(status), "sip.CSeq.method": method}


def media(number, at, src, port, payload=""):
    return {**row(), "frame.number": str(number), "frame.time_relative": str(at), "ip.src": src,
            "udp.srcport": str(port), "rtp.payload": payload}


class ScenarioTableTests(unittest.TestCase):
    def test_scenarios_are_unique_and_every_verdict_is_a_schema_verdict(self):
        schema = json.loads((ROOT / "schemas" / "call-result-v1.schema.json").read_text())
        verdicts = set(schema["properties"]["verdict"]["enum"])
        names = [item.name for item in practice_drill.SCENARIOS]
        self.assertEqual(len(names), len(set(names)))
        for item in practice_drill.SCENARIOS:
            with self.subTest(scenario=item.name):
                self.assertIn(item.expected, verdicts)
                self.assertIn(item.expected_exit, (0, 1))
                self.assertEqual(item.expected_exit == 0, item.expected == "pass")
                self.assertIn(item.name, practice_faults.WIRE, "every scenario needs a wire rule")
        self.assertEqual(set(practice_faults.WIRE), set(names))

    def test_all_runs_in_about_three_minutes_or_less(self):
        total = practice_drill.estimate_seconds(list(practice_drill.SCENARIOS))
        self.assertLessEqual(total, 180)
        self.assertGreater(total, 60)

    def test_dialed_destinations_exist_in_the_dialplan_or_are_deliberately_unknown(self):
        dialplan = (ROOT / "practice-target" / "asterisk" / "extensions.conf").read_text()
        defined = set(re.findall(r"^exten => ([a-z0-9-]+),1,", dialplan, re.M))
        for item in practice_drill.SCENARIOS:
            with self.subTest(scenario=item.name):
                if item.name == "notfound":
                    self.assertNotIn(item.dial, defined)
                else:
                    self.assertIn(item.dial, defined)

    def test_fault_destinations_are_documented_in_info_and_the_docs(self):
        dialplan = (ROOT / "practice-target" / "asterisk" / "extensions.conf").read_text()
        block = dialplan.split("BEGIN fault destinations", 1)[1].split("END fault destinations", 1)[0]
        defined = set(re.findall(r"^exten => ([a-z0-9-]+),1,", block, re.M))
        self.assertEqual(defined, set(practice.FAULT_DESTINATIONS))
        document = (ROOT / "docs" / "PRACTICE-TARGET.md").read_text()
        for name in defined | set(practice.FAULT_ACCOUNTS):
            with self.subTest(name=name):
                self.assertIn(f"`{name}`", document)
        self.assertEqual(
            sorted(practice.FAULT_ACCOUNTS),
            ["practice-srtp"],
        )
        pjsip = (ROOT / "practice-target" / "asterisk" / "pjsip.conf").read_text()
        self.assertIn("[@ACCOUNT@-srtp]", pjsip)

    def test_every_new_application_is_enabled_in_the_menuselect_list(self):
        containerfile = (ROOT / "Containerfile.practice").read_text()
        # Wait, Ringing, Progress, Set, Answer, Hangup are core applications;
        # TIMEOUT() needs func_timeout; Playback and Echo are already enabled.
        for module in ("func_timeout", "app_playback", "app_echo"):
            self.assertIn(f"--enable {module}", containerfile)
        self.assertIn("silence.ulaw", containerfile)
        self.assertIn("silence.alaw", containerfile)

    def test_select_and_unknown_names(self):
        self.assertEqual(len(practice_drill.select("all")), len(practice_drill.SCENARIOS))
        self.assertEqual([item.name for item in practice_drill.select("drop")], ["drop"])
        with self.assertRaises(practice_drill.DrillError):
            practice_drill.select("echo; rm")
        with self.assertRaises(practice_drill.DrillError):
            practice_drill.select("127.0.0.9")

    def test_call_arguments_name_only_the_generated_practice_profile(self):
        for item in practice_drill.SCENARIOS:
            with self.subTest(scenario=item.name):
                argv = practice_drill.call_argv(
                    item, "work/practice/target-profile.yaml", "work/practice/account.password",
                    "work/practice/drills/x/calls",
                )
                self.assertEqual(argv[:3], ["--practice", "call", "work/practice/target-profile.yaml"])
                self.assertNotIn("--host", argv)
                self.assertNotIn("--isolated", argv)
                self.assertNotIn("--admin", argv)
        for item in practice_drill.SCENARIOS:
            self.assertRegex(item.dial, r"^[a-z0-9-]+$")


class NamespaceSafetyTests(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        from test_practice_target import make_project

        self.project = make_project(Path(self._directory.name))
        self.facts = practice.prepare(
            self.project, address="127.0.0.2", container="sippycup-practice",
            image="localhost/sippycup-practice:latest",
        )

    def tearDown(self):
        self._directory.cleanup()

    def test_the_generated_practice_state_is_accepted(self):
        facts = practice_drill.verify_namespace(self.project)
        self.assertEqual(facts["address"], "127.0.0.2")

    def test_a_profile_naming_any_other_address_is_refused(self):
        profile = self.project / "work" / "practice" / "target-profile.yaml"
        text = profile.read_text()
        for replacement in ("192.0.2.10", "10.0.0.5", "127.0.0.1"):
            with self.subTest(address=replacement):
                profile.write_text(text.replace("127.0.0.2", replacement))
                with self.assertRaises(practice_drill.DrillError):
                    practice_drill.verify_namespace(self.project)
        profile.write_text(text.replace("LOCAL-PRACTICE-ONLY", "CHG-1234"))
        with self.assertRaises(practice_drill.DrillError):
            practice_drill.verify_namespace(self.project)

    def test_facts_with_a_routable_address_are_refused(self):
        path = self.project / "work" / "practice" / "connection.json"
        facts = json.loads(path.read_text())
        for address in ("192.0.2.10", "8.8.8.8", "::1", "example.com", ""):
            with self.subTest(address=address):
                facts["address"] = address
                path.write_text(json.dumps(facts))
                with self.assertRaises(practice_drill.DrillError):
                    practice_drill.verify_namespace(self.project)

    def test_a_missing_target_state_is_refused_before_anything_is_sent(self):
        with tempfile.TemporaryDirectory() as empty:
            with self.assertRaises(practice_drill.DrillError):
                practice_drill.verify_namespace(Path(empty))

    def test_variant_profiles_change_only_the_port(self):
        with tempfile.TemporaryDirectory() as name:
            drill_dir = practice.state_dir(self.project) / "drills" / "t"
            drill_dir.mkdir(parents=True, mode=0o700)
            scenario = practice_drill.BY_NAME["closedport"]
            profile, secret = practice_drill.prepare_inputs(self.project, scenario, drill_dir)
            self.assertEqual(profile, "work/practice/drills/t/profile-closedport.yaml")
            self.assertEqual(secret, "work/practice/account.password")
            import yaml

            original = yaml.safe_load((practice.state_dir(self.project) / "target-profile.yaml").read_text())
            variant = yaml.safe_load((drill_dir / "profile-closedport.yaml").read_text())
            self.assertEqual(variant["target"]["port"], practice_drill.CLOSED_PORT)
            self.assertEqual(variant["target"]["host"], original["target"]["host"])
            self.assertEqual(variant["target"]["approved_addresses"], original["target"]["approved_addresses"])
            self.assertEqual(variant["authorization"], original["authorization"])
            wrong = practice_drill.BY_NAME["badpassword"]
            _profile, secret = practice_drill.prepare_inputs(self.project, wrong, drill_dir)
            self.assertEqual(secret, "work/practice/drills/t/wrong.password")
            self.assertEqual((drill_dir / "wrong.password").stat().st_mode & 0o077, 0)


class LauncherTests(unittest.TestCase):
    def run_launcher(self, *arguments):
        return subprocess.run(
            [str(ROOT / "bin" / "sippycup"), "practice-target", *arguments],
            cwd=ROOT, text=True, capture_output=True, timeout=60, check=False,
            env={**os.environ, "SIPPYCUP_PRACTICE_CONTAINER": "faults-test-missing"},
        )

    def test_list_sends_nothing_and_shows_every_scenario(self):
        result = self.run_launcher("drill", "--list")
        self.assertEqual(result.returncode, 0, result.stderr)
        for item in practice_drill.SCENARIOS:
            self.assertIn(item.name, result.stdout)
        self.assertTrue(result.stdout.rstrip().endswith("Network activity: none"))

    def test_unknown_scenarios_and_address_options_are_refused(self):
        for arguments in (("nothing",), ("--address", "192.0.2.1"), ("--host", "192.0.2.1"), ("echo", "192.0.2.1")):
            with self.subTest(arguments=arguments):
                result = self.run_launcher("drill", *arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Drill:", result.stdout)

    def test_drill_refuses_when_the_target_is_not_up(self):
        result = self.run_launcher("drill", "echo")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("Nothing was sent.", result.stderr)

    def test_help_documents_the_drill(self):
        result = self.run_launcher("help")
        self.assertIn("drill [NAME|all]", result.stdout)


class WireRuleTests(unittest.TestCase):
    """The rules must accept the behavior they name and reject its opposite."""

    def test_silent_requires_zero_server_rtp(self):
        good = [sip_response(3, 0.1, 200), media(10, 0.2, "127.0.0.1", 4000, "ff")]
        self.assertTrue(practice_faults.wire_silent(good)[0])
        bad = good + [media(11, 0.3, "127.0.0.2", 20010)]
        self.assertFalse(practice_faults.wire_silent(bad)[0])
        self.assertFalse(practice_faults.wire_silent([sip_response(3, 0.1, 200)])[0])

    def test_drop_requires_a_bye_from_the_server_about_three_seconds_after_answer(self):
        rows = [sip_response(3, 0.1, 200), sip_request(9, 3.2, "BYE", "127.0.0.2")]
        self.assertTrue(practice_faults.wire_drop(rows)[0])
        rows = [sip_response(3, 0.1, 200), sip_request(9, 3.2, "BYE", "127.0.0.1")]
        self.assertFalse(practice_faults.wire_drop(rows)[0])
        rows = [sip_response(3, 0.1, 200), sip_request(9, 9.9, "BYE", "127.0.0.2")]
        self.assertFalse(practice_faults.wire_drop(rows)[0])

    def test_rejections_need_the_status_and_no_answer(self):
        check = practice_faults.rejected_with(503)
        self.assertTrue(check([sip_response(3, 0.1, 503)])[0])
        self.assertFalse(check([sip_response(3, 0.1, 486)])[0])
        self.assertFalse(check([sip_response(3, 0.1, 503), sip_response(4, 0.2, 200)])[0])

    def test_earlymedia_requires_183_before_200_with_rtp_in_between(self):
        rows = [sip_response(3, 0.01, 183), sip_response(400, 3.0, 200)]
        rows += [media(10 + i, 0.02 + i * 0.02, "127.0.0.2", 20000, "ff") for i in range(120)]
        self.assertTrue(practice_faults.wire_earlymedia(rows)[0])
        self.assertFalse(practice_faults.wire_earlymedia([sip_response(400, 3.0, 200)])[0])
        late_183 = [sip_response(500, 3.1, 183), sip_response(400, 3.0, 200)] + rows[2:]
        self.assertFalse(practice_faults.wire_earlymedia(late_183)[0])

    def test_silence_requires_all_ff_payloads(self):
        rows = [media(i, i * 0.02, "127.0.0.2", 20000, "ff:ff:ff:ff") for i in range(60)]
        self.assertTrue(practice_faults.wire_silence(rows)[0])
        rows[5] = media(5, 0.1, "127.0.0.2", 20000, "ff:7f:ff:ff")
        self.assertFalse(practice_faults.wire_silence(rows)[0])

    def test_late_noanswer_and_closed_port(self):
        invite = sip_request(1, 0.0, "INVITE", "127.0.0.1")
        self.assertTrue(practice_faults.wire_late(
            [invite, sip_response(2, 0.1, 180), sip_response(3, 12.05, 200)])[0])
        self.assertFalse(practice_faults.wire_late(
            [invite, sip_response(2, 0.1, 180), sip_response(3, 2.0, 200)])[0])
        self.assertTrue(practice_faults.wire_noanswer(
            [invite, sip_response(2, 0.1, 180), sip_request(5, 6.1, "CANCEL", "127.0.0.1")])[0])
        self.assertFalse(practice_faults.wire_noanswer([invite, sip_request(5, 6.1, "CANCEL", "127.0.0.1")])[0])
        probe = {**row(), "ip.src": "127.0.0.1", "udp.dstport": "5099"}
        self.assertTrue(practice_faults.wire_closedport([probe])[0])
        self.assertFalse(practice_faults.wire_closedport([probe, sip_response(2, 0.1, 200, "OPTIONS")])[0])

    def test_capture_paths_stay_under_work(self):
        self.assertEqual(
            practice_faults.capture_path("work/practice/drills/a/calls/b"),
            "/work/practice/drills/a/calls/b/capture.pcap",
        )
        for bad in ("/etc", "work/../etc", "other/work"):
            with self.assertRaises(ValueError):
                practice_faults.capture_path(bad)

    def test_parse_rows_pads_short_lines(self):
        rows = practice_faults.parse_rows("1\t0.5\t127.0.0.1\n")
        self.assertEqual(rows[0]["ip.src"], "127.0.0.1")
        self.assertEqual(rows[0]["rtp.payload"], "")


if __name__ == "__main__":
    unittest.main()
