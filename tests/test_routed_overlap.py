"""Wave 10: overlapping runs (finding 6), the routed path (finding 5), and the link-local guard.

No container is started here: the overlap check gets a fake runtime and
/proc, and the launcher a fake runtime that prints its arguments. ``make
routed-rehearsal`` proves the real thing across the tool container's network
stack.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from sippycup import link_local, overlap_record  # noqa: E402
from sippycup.evidence import privacy_findings  # noqa: E402
from sippycup_cockpit import overlap  # noqa: E402
from sippycup_softphone.driver import nat_addresses  # noqa: E402
from sippycup_workbench.profile import rehearse  # noqa: E402

from test_guided_call import NOW, profile_document  # noqa: E402
from test_stop import CHECKOUT, IMAGE, OURS, OTHER, FakeHost, container  # noqa: E402

LAUNCHER = ROOT / "bin" / "sippycup"


class OverlapTests(unittest.TestCase):
    def check(self, host, environ=None):
        stderr, stdout = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
            code = overlap.main(["--command", "call"], host=host,
                                environ={"SIPPYCUP_IMAGE": IMAGE, **(environ or {})})
        return code, stdout.getvalue(), stderr.getvalue()

    def ours(self, command="call", argv=("sippycup-call", "/work/x.yaml"), ident=OURS, name="busy_call"):
        return container(ident, name, labels={"dev.sippycup.checkout": CHECKOUT, "dev.sippycup.command": command},
                         command=argv)

    def test_a_second_sender_is_refused_naming_the_other_run(self):
        code, out, err = self.check(FakeHost([self.ours()]))
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("busy_call", err)
        self.assertIn("./bin/sippycup stop", err)
        self.assertIn("Nothing was sent", err)
        self.assertIn("Wait for it to finish", err)

    def test_nothing_active_passes_silently(self):
        self.assertEqual(self.check(FakeHost([])), (0, "", ""))

    def test_another_checkout_and_non_senders_do_not_count(self):
        other = container(OTHER, "theirs", labels={"dev.sippycup.checkout": "/elsewhere",
                                                   "dev.sippycup.command": "call"})
        cockpit = self.ours(command="ui", argv=("sippycup-ui",), ident="f" * 64, name="cockpit")
        capture = self.ours(command="advanced", argv=("timeout", "60", "tcpdump"), ident="1" * 64, name="cap")
        self.assertEqual(self.check(FakeHost([other, cockpit, capture]))[0], 0)

    def test_an_advanced_softphone_counts(self):
        pjsua = self.ours(command="advanced", argv=("pjsua", "--config-file", "/work/x.cfg"), name="raw")
        self.assertEqual(self.check(FakeHost([pjsua]))[0], 2)

    def test_a_host_sender_counts(self):
        process = {"pid": 4242, "argv": [f"{CHECKOUT}/bin/campaign", "run", "plan.json"], "uid": os.getuid(),
                   "cwd": CHECKOUT, "cgroup": ""}
        code, _out, err = self.check(FakeHost([], [process]))
        self.assertEqual(code, 2)
        self.assertIn("campaign", err)

    def test_an_unanswerable_runtime_refuses(self):
        class Broken(FakeHost):
            def running_containers(self):
                raise RuntimeError("runtime failed")

        code, _out, err = self.check(Broken([]))
        self.assertEqual(code, 2)
        self.assertIn("cannot tell whether another run", err)

    def test_the_opt_out_must_name_every_active_run_and_is_recorded(self):
        host = FakeHost([self.ours()])
        self.assertEqual(self.check(host, {overlap.ALLOW_ENV: "someone_else"})[0], 2)
        code, out, err = self.check(host, {overlap.ALLOW_ENV: "busy_call"})
        self.assertEqual(code, 0)
        self.assertIn("unreliable", err)
        record = overlap_record.recorded({overlap_record.ENV: out.strip()})
        self.assertEqual(record["activeRuns"][0]["name"], "busy_call")
        self.assertEqual(record["note"], "another run was active; this verdict is unreliable")

    def test_no_record_without_the_launcher(self):
        self.assertEqual(overlap_record.field({}), {})
        self.assertEqual(overlap_record.field({overlap_record.ENV: "not json"})["overlap"]["activeRuns"], [])


class DiagnoseOverlapTests(unittest.TestCase):
    def test_diagnose_says_the_verdict_is_unreliable(self):
        from sippycup_diagnose.cli import _mark_overlap

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "result.json").write_text(json.dumps(
                {"overlap": {"activeRuns": [{"name": "busy_call"}], "note": "x"}}), encoding="utf-8")
            data = {"outcome": "The call failed."}
            _mark_overlap(data, path)
        self.assertTrue(data["outcome"].startswith("Another run was active; this verdict is unreliable"))
        self.assertIn("busy_call", data["outcome"])
        self.assertTrue(data["outcome"].endswith("The call failed."))


class RoutedRehearsalTests(unittest.TestCase):
    def test_routed_answers_check_clean_and_the_stop_leg_answers_media_elsewhere(self):
        from unittest import mock

        from sippycup import routed_rehearsal as routed
        from sippycup_workbench.journal import initialize
        from sippycup_workbench.scope import inspect
        from test_practice_rehearsal import NOW as REHEARSAL_NOW, _pem

        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory) / "work"
            work.mkdir()
            root = work / "eng"
            initialize(root, title="t", owner="o")
            (root / "routed-ca.crt").write_text(_pem())
            for media in ((routed.ROUTED_ADDRESS,), (routed.STOP_MEDIA_ADDRESS,)):
                text = routed.routed_scope(now=REHEARSAL_NOW, name="dress-rehearsal", ca_file="work/eng/routed-ca.crt",
                                           source="192.0.2.50", media=media)
                path = root / "scope.yaml"
                path.write_text(text)
                path.chmod(0o600)
                with mock.patch.dict(os.environ, {"SIPPYCUP_WORK_ROOT": str(work)}):
                    report = inspect(path, now=REHEARSAL_NOW)
                errors = [f"{item.code} {item.field}" for item in report.findings if item.severity == "error"]
                self.assertEqual(errors, [], media)
                self.assertIn(f"networks: [{media[0]}]", text)
                self.assertIn("approval_id: ROUTED-REHEARSAL", text)
        self.assertFalse(link_local.problems([routed.STOP_MEDIA_ADDRESS], {}),
                         "the stop leg's media answer must not need the routed mapping")

    def test_stage_list_sends_nothing(self):
        result = subprocess.run([sys.executable, str(ROOT / "tools" / "routed_rehearsal.py"), "--list"],
                                capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip().splitlines()[-1], "Network activity: none")
        self.assertEqual(len(result.stdout.strip().splitlines()), 15)


class CockpitCompletionTests(unittest.TestCase):
    """A real engagement has no practice call: a skipped practice stage must not block completion."""

    def model(self, preferences):
        run = {"kind": "call", "passed": True, "readable": True, "name": "r1", "relative": "work/e/calls/r1",
               "evidenceManifest": True, "completed": True}
        campaign = {**run, "kind": "campaign", "name": "r2", "relative": "work/e/runs/r2"}
        return {
            "engagement": {"initialized": True},
            "readiness": {"image": {"present": True, "stale": False}, "practice": {"installed": True, "up": False},
                          "goNoGo": {"go": True}},
            "scope": {"state": "complete", "present": True, "unanswered": [], "derivatives": "current"},
            "profile": {"present": True, "ready": True, "securityChecks": []},
            "runs": [run, campaign],
            "journal": {"evidence": ["work/e/calls/r1/result.json", "work/e/runs/r2/result.json"]},
            "files": {"ownerReport": {"integrityExceptions": 0, "runs": ["r1", "r2"]}, "campaign": True,
                      "plan": True, "packs": False, "internalReport": False},
            "preferences": preferences,
        }

    def test_skipped_practice_leaves_the_engagement_complete(self):
        from sippycup_cockpit.model import derive_stages

        stages = {item["id"]: item["state"] for item in derive_stages(self.model({"skipPractice": True}))}
        self.assertNotIn("current", stages.values(), stages)
        self.assertEqual(stages["practice"], "recommended")
        unskipped = {item["id"]: item["state"] for item in derive_stages(self.model({}))}
        self.assertEqual(unskipped["practice"], "current")


class LinkLocalTests(unittest.TestCase):
    def test_link_local_is_refused_unless_it_is_the_routed_target(self):
        self.assertTrue(link_local.problems(["169.254.77.2"], {}))
        self.assertTrue(link_local.problems(["169.254.0.0/16"], {link_local.ENV: "169.254.77.2"}))
        self.assertTrue(link_local.problems(["169.254.77.9"], {link_local.ENV: "169.254.77.2"}))
        self.assertTrue(link_local.problems(["fe80::1"], {}))
        self.assertEqual(link_local.problems(["169.254.77.2"], {link_local.ENV: "169.254.77.2"}), [])
        self.assertEqual(link_local.problems(["192.0.2.10", "10.0.0.0/8", "not-an-address"], {}), [])

    def test_rehearse_refuses_a_link_local_target(self):
        document = profile_document()
        document["target"]["host"] = "169.254.77.2"
        document["target"]["approved_addresses"] = ["169.254.77.2"]
        saved = os.environ.pop(link_local.ENV, None)
        self.addCleanup(lambda: saved is not None and os.environ.__setitem__(link_local.ENV, saved))
        result = rehearse(document, now=NOW)
        self.assertFalse(result.ready)
        self.assertTrue(any("is link-local" in item for item in result.errors), result.errors)

    def test_campaign_plan_refuses_a_link_local_network(self):
        from sippycup.campaign import ManifestError, compile_plan
        from test_campaign import fixture

        manifest, _digest = fixture()
        manifest["authorization"]["networks"] = ["169.254.77.0/30"]
        saved = os.environ.pop(link_local.ENV, None)
        self.addCleanup(lambda: saved is not None and os.environ.__setitem__(link_local.ENV, saved))
        with self.assertRaisesRegex(ManifestError, "link-local"):
            compile_plan(manifest, "0" * 64, resolver=lambda host: ["169.254.77.2"])


class NatTests(unittest.TestCase):
    LOG = ("12:00:01.000 pjsua_acc.c  .IP address change detected for account 1 "
           "(172.16.0.35:45936 --> 10.237.92.5:60501). Updating registration..\n")

    def test_pjsua_address_change_is_parsed(self):
        self.assertEqual(nat_addresses(self.LOG), [
            {"address": "10.237.92.5", "port": 60501, "local": "172.16.0.35", "localPort": 45936}])
        self.assertEqual(nat_addresses(self.LOG + self.LOG), nat_addresses(self.LOG))
        self.assertEqual(nat_addresses("IP address change detected for account 1 (a.example:1 --> b:2)"), [])

    def lint(self, result, capture_bytes=b""):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "result.json").write_text(json.dumps(result), encoding="utf-8")
            (root / "softphone.log").write_bytes(b"Via: SIP/2.0/UDP 172.16.0.35:5060;received=10.237.92.5\n")
            artifacts = [{"path": "softphone.log", "size": (root / "softphone.log").stat().st_size,
                          "mediaType": "text/plain"}]
            return privacy_findings(root, artifacts, expected_networks=["169.254.77.2/32"])

    def test_the_lint_ignores_an_unspecified_address_in_text(self):
        # Two colons occur by chance in TLS ciphertext; "::" names no party.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "result.json").write_text("{}", encoding="utf-8")
            (root / "blob.txt").write_bytes(b"\x17\x03 q :: z 0.0.0.0 \x99")
            findings = privacy_findings(root, [{"path": "blob.txt", "size": 20, "mediaType": "text/plain"}])
        self.assertFalse([item for item in findings if item["code"] == "unexpected-network"], findings)

    def test_the_lint_ignores_chance_ipv6_in_binary_bytes_but_not_in_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "result.json").write_text("{}", encoding="utf-8")
            (root / "rtp.bin").write_bytes(b"\x80\x00::5\x9f\x01")
            (root / "sip.txt").write_bytes(b"Via: SIP/2.0/UDP [2001:db8::5]:5060\r\n")
            findings = privacy_findings(root, [{"path": "rtp.bin", "size": 7, "mediaType": "application/octet-stream"},
                                               {"path": "sip.txt", "size": 36, "mediaType": "text/plain"}])
        flagged = {item["path"]: item["detail"] for item in findings if item["code"] == "unexpected-network"}
        self.assertNotIn("rtp.bin", flagged)
        self.assertIn("2001:db8::5", flagged.get("sip.txt", ""))

    def test_the_lint_accepts_our_nat_address_as_text(self):
        flagged = [item for item in self.lint({"localAddress": "172.16.0.35"}) if item["code"] == "unexpected-network"]
        self.assertTrue(flagged and "10.237.92.5" in flagged[0]["detail"])
        quiet = self.lint({"localAddress": "172.16.0.35", "natAddresses": ["10.237.92.5"]})
        self.assertFalse([item for item in quiet if item["code"] == "unexpected-network"])


class LauncherTests(unittest.TestCase):
    def runtime(self, root: Path, inspect: str = "") -> Path:
        runtime = root / "runtime"
        branch = f"printf '%s\\n' '{inspect}'; exit 0" if inspect else "exit 125"
        runtime.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = ps ]; then echo "[]"; exit 0; fi\n'
            f'if [ "$1" = container ] && [ "$2" = inspect ]; then {branch}; fi\n'
            "printf '%s\\n' \"$@\"\n",
            encoding="utf-8",
        )
        runtime.chmod(runtime.stat().st_mode | stat.S_IXUSR)
        return runtime

    def run_cli(self, *arguments, env):
        environment = {key: value for key, value in os.environ.items()
                       if key not in {"SIPPYCUP_ROUTED_PRACTICE", "SIPPYCUP_ROUTED_ADDRESS", "SIPPYCUP_OVERLAP"}}
        return subprocess.run([str(LAUNCHER), *arguments], cwd=ROOT, env={**environment, **env}, text=True,
                              capture_output=True, timeout=30, check=False)

    def test_documented_campaign_run_goes_into_a_private_container(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {"SIPPYCUP_RUNTIME": str(self.runtime(Path(directory)))}
            result = self.run_cli("campaign", "run", "work/e/plan.json", "--manifest", "work/e/campaign.yaml",
                                  env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = result.stdout.splitlines()
        self.assertIn("run", arguments)
        self.assertNotIn("--network=host", arguments)
        self.assertIn("--env=SIPPYCUP_NETWORK_MODE=private", arguments)
        self.assertIn("/work/e/plan.json", arguments)

    def test_campaign_run_rejects_admin(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {"SIPPYCUP_RUNTIME": str(self.runtime(Path(directory)))}
            result = self.run_cli("--admin", "campaign", "run", "work/e/plan.json", env=env)
        self.assertEqual(result.returncode, 2)
        self.assertIn("rejects --admin", result.stderr)

    def test_routed_practice_fails_closed_when_the_target_is_not_up(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {"SIPPYCUP_RUNTIME": str(self.runtime(Path(directory))),
                   "SIPPYCUP_ROUTED_PRACTICE": "nope-routed"}
            result = self.run_cli("call", "work/e/target-profile.yaml", env=env)
        self.assertEqual(result.returncode, 2)
        self.assertIn("The routed practice target nope-routed is not up", result.stderr)
        self.assertIn("No container or network activity was started", result.stderr)
        self.assertNotIn("sippycup-call", result.stdout)

    def routed_runtime(self, root: Path) -> Path:
        runtime = root / "routed-runtime"
        runtime.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = ps ]; then echo "[]"; exit 0; fi\n'
            'if [ "$1" = container ] && [ "$2" = inspect ]; then echo "true|routed-practice|169.254.77.2|rnet "; exit 0; fi\n'
            'if [ "$1" = network ] && [ "$2" = inspect ]; then echo true; exit 0; fi\n'
            "printf '%s\\n' \"$@\"\n",
            encoding="utf-8",
        )
        runtime.chmod(runtime.stat().st_mode | stat.S_IXUSR)
        return runtime

    def test_routed_mode_maps_the_address_and_keeps_senders_off_the_host(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {"SIPPYCUP_RUNTIME": str(self.routed_runtime(Path(directory))),
                   "SIPPYCUP_ROUTED_PRACTICE": "ws-x-routed"}
            call = self.run_cli("call", "work/e/target-profile.yaml", env=env)
            media = self.run_cli("media", "send", "work/e/session.json", "--profile", "work/e/p.yaml", env=env)
            capture = self.run_cli("capture", "--help", env=env)
        self.assertEqual(call.returncode, 0, call.stderr)
        arguments = call.stdout.splitlines()
        self.assertIn("--network=pasta:--map-host-loopback,169.254.77.2", arguments)
        self.assertIn("--env=SIPPYCUP_ROUTED_ADDRESS=169.254.77.2", arguments)
        self.assertNotIn("--network=host", arguments)
        # media send runs on the host normally; routed, it goes into the mapped container.
        self.assertEqual(media.returncode, 0, media.stderr)
        self.assertIn("--network=pasta:--map-host-loopback,169.254.77.2", media.stdout.splitlines())
        self.assertEqual(capture.returncode, 2)
        self.assertIn("refused while SIPPYCUP_ROUTED_PRACTICE is set", capture.stderr)

    def test_a_caller_cannot_name_the_routed_address(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {"SIPPYCUP_RUNTIME": str(self.runtime(Path(directory))),
                   "SIPPYCUP_ROUTED_ADDRESS": "169.254.77.2", "SIPPYCUP_OVERLAP": '{"activeRuns":[]}'}
            result = self.run_cli("call", "work/e/target-profile.yaml", env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse([item for item in result.stdout.splitlines()
                          if "SIPPYCUP_ROUTED_ADDRESS" in item or "SIPPYCUP_OVERLAP" in item])
        self.assertFalse([item for item in result.stdout.splitlines() if "map-host-loopback" in item])


if __name__ == "__main__":
    unittest.main()
