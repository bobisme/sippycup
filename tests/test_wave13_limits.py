"""Wave 13: known limits closed (bn-3w2v).

1. ``SIPPYCUP_ALLOW_OVERLAP`` does not go past the owner's limit on calls at
   once: the command that places calls refuses where it reserves them.
2. ``campaign run`` without ``--run-root`` runs into ``runs/`` of the
   engagement directory the campaign file lies in.
3. ``stop`` ends a launcher that claimed its start and has no container yet;
   ``stop --dry-run`` lists it and changes nothing.
4. ``checks run`` that places no call is refused in a directory the
   two-directory rule stops.
5. The campaign's window refusal prints the real directory.

Fakes, a throwaway checkout and a fake container runtime only: nothing here
sends anything.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

import cockpit_support as support  # noqa: E402
from test_guided_call import Fakes  # noqa: E402
from test_stop import CHECKOUT, IMAGE, OURS, TITLE, FakeHost, container  # noqa: E402
from test_wave11_guard import executable, launcher_environment, throwaway_checkout  # noqa: E402

from sippycup import call_ledger, campaign, overlap_record  # noqa: E402
from sippycup.campaign import compile_plan  # noqa: E402
from sippycup.integration import AuthorizationLapsed, execute_campaign  # noqa: E402
from sippycup_cockpit import overlap, stop  # noqa: E402
from sippycup_workbench import call as guided  # noqa: E402
from sippycup_workbench import matrix  # noqa: E402

NOW = datetime.now(timezone.utc).replace(microsecond=0)
TOOL = ROOT / "tests" / "fixtures" / "campaign" / "integration-tool.py"
APPROVAL = "QUAD-APPROVAL-7Q2X"


def record(*commands: str) -> str:
    """The launcher's SIPPYCUP_OVERLAP for runs of these commands."""
    return json.dumps({"activeRuns": [{"name": f"run-{index}", "kind": "container", "detail": f"{command}: x",
                                       "command": command} for index, command in enumerate(commands)],
                       "allowedBy": "SIPPYCUP_ALLOW_OVERLAP", "note": overlap_record.UNRELIABLE})


def beside(*commands: str):
    return mock.patch.dict(os.environ, {overlap_record.ENV: record(*commands)})


# --------------------------------------------------------------------------- 1: the override and calls at once


class ConcurrencyRuleTests(unittest.TestCase):
    def refusal(self, limit, *commands, raw=None):
        environ = {overlap_record.ENV: raw if raw is not None else record(*commands)}
        return overlap_record.concurrency_refusal(limit, "call", environ)

    def test_a_run_that_started_alone_is_never_refused(self):
        self.assertIsNone(overlap_record.concurrency_refusal(1, "call", {}))

    def test_a_second_call_is_refused_at_one_call_at_once(self):
        text = self.refusal(1, "call")
        self.assertIn("this call was started beside run-0 (SIPPYCUP_ALLOW_OVERLAP)", text)
        self.assertIn("2 calls could be up at once, above the owner's limit of 1 call(s) at once", text)
        self.assertIn("Nothing was sent.", text)
        self.assertIn("./bin/sippycup stop", text)
        for command in ("matrix", "campaign", "checks", "one-call"):
            self.assertIsNotNone(self.refusal(1, command), command)

    def test_a_limit_that_allows_both_lets_the_override_work(self):
        self.assertIsNone(self.refusal(2, "call"))
        self.assertIsNotNone(self.refusal(2, "call", "matrix"))
        self.assertIsNone(self.refusal(3, "call", "matrix"))

    def test_a_run_that_places_no_call_does_not_count(self):
        self.assertIsNone(self.refusal(1, "preflight"))
        self.assertIsNone(self.refusal(1, "media", "preflight"))
        self.assertIsNotNone(self.refusal(1, "preflight", "call"))

    def test_what_cannot_be_told_is_refused(self):
        for command in ("advanced", "chaos", "resilience", "?", ""):
            self.assertIn("is not known", self.refusal(8, command), command)
        for raw in ("not json", "[]", '{"activeRuns": []}', '{"activeRuns": ["x"]}', '{"activeRuns": [{}]}'):
            self.assertIn("Nothing was sent.", self.refusal(8, raw=raw), raw)

    def test_a_limit_that_is_not_a_number_counts_as_one(self):
        for limit in (None, 0, -3, True, "4"):
            self.assertIn("limit of 1 call(s) at once", self.refusal(limit, "call"), repr(limit))

    def test_the_launchers_record_names_each_run_by_its_command(self):
        labelled = container(OURS, "clever_name", labels={**TITLE, stop.CHECKOUT_LABEL: CHECKOUT,
                                                           stop.COMMAND_LABEL: "matrix"})
        stdout, stderr = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as name, contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            code = overlap.main(["--command", "call"], host=FakeHost([labelled]), claims=Path(name) / "none",
                                environ={"SIPPYCUP_IMAGE": IMAGE, overlap.ALLOW_ENV: "clever_name"})
        self.assertEqual(code, 0, stderr.getvalue())
        handed = stdout.getvalue().strip()
        self.assertEqual(json.loads(handed)["activeRuns"][0]["command"], "matrix")
        # What the launcher hands over is what the run refuses on.
        self.assertIn("2 calls could be up at once",
                      overlap_record.concurrency_refusal(1, "call", {overlap_record.ENV: handed}))
        self.assertIn("is refused, before it sends anything", stderr.getvalue())
        self.assertNotIn("concurrent-calls-exceeded", stderr.getvalue())

    def test_a_claimed_launcher_and_a_host_process_are_named_too(self):
        launcher = stop.Target("launcher", "41", "launcher-41", "campaign run: starting (claimed at x)", "claim")
        self.assertEqual(overlap.run_command(launcher), "campaign")
        process = stop.Target("process", "42", "sippycup-media", "/x/bin/sippycup-media send", "host process")
        self.assertEqual(overlap.run_command(process), "media")
        unlabelled = stop.Target("container", "a" * 12, "old", "?: sipp -sn uac", "image")
        self.assertEqual(overlap.run_command(unlabelled), "?")

    def test_reserve_refuses_before_it_writes_anything(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name) / "work" / "eng"
            directory.mkdir(parents=True)
            with beside("call"), self.assertRaisesRegex(call_ledger.CeilingRefused, "2 calls could be up at once"):
                call_ledger.reserve(directory, approval_id="CHG-1", ceiling=40, calls=1, command="call",
                                    source="target-profile.yaml", concurrent_limit=1)
            self.assertEqual(list(directory.iterdir()), [])
            with beside("call"):
                call_ledger.reserve(directory, approval_id="CHG-1", ceiling=40, calls=1, command="call",
                                    source="target-profile.yaml", concurrent_limit=2)
            self.assertEqual(call_ledger.check(directory, "CHG-1").used, 1)


class OverrideAtTheGatesTests(unittest.TestCase):
    """The four commands that place calls, with `limits.concurrent_calls: 1`, started under the override."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = support.make_repo(Path(temporary.name))
        self.work = self.repo / "work"
        self.root = support.compiled_engagement(self.repo, now=NOW, go=False)
        self.profile = self.root / "target-profile.yaml"
        self.ledger = self.root / call_ledger.LEDGER_FILE

    def call(self):
        fakes = Fakes()
        options = guided.CallOptions(profile=self.profile, destination="echo", duration=3)
        code, value = guided.execute(options, fakes.dependencies(self.work, now=lambda: NOW))
        return fakes, code, value

    def test_the_profile_carries_the_owners_limit(self):
        self.assertEqual(guided.concurrent_limit(yaml.safe_load(self.profile.read_text())), 1)
        self.assertEqual(guided.concurrent_limit({"limits": {"max_concurrency": 3}}), 3)
        self.assertEqual(guided.concurrent_limit({}), 1)

    def test_call_beside_a_call_sends_nothing(self):
        with beside("call"):
            fakes, code, value = self.call()
        self.assertEqual((code, value["state"], fakes.events), (guided.EXIT_REFUSED, "blocked", []))
        self.assertEqual(value["networkActivity"], "none")
        self.assertIsNone(value["runDirectory"])
        self.assertIn("above the owner's limit of 1 call(s) at once", value["blockingErrors"][0])
        self.assertFalse((self.root / "calls").exists())
        self.assertFalse(self.ledger.exists())

    def test_call_beside_a_preflight_still_runs_and_records_the_overlap(self):
        with beside("preflight"):
            _fakes, code, value = self.call()
        self.assertEqual(code, 0, value)
        self.assertEqual(value["overlap"]["note"], overlap_record.UNRELIABLE)

    def test_matrix_run_beside_a_call_places_no_cell(self):
        executed = []

        def execute(options, deps):
            executed.append(options)
            return 0, {"verdict": "pass", "timestamps": {"preflight_sent": "x"}, "softphone": {}}

        deps = matrix.MatrixDependencies(
            execute=execute, call_dependencies=lambda environ: Fakes().dependencies(self.work, now=lambda: NOW),
            now=lambda: NOW, sleep=lambda _s: None, work_root=self.work, install_signal_handlers=False,
        )
        options = matrix.MatrixOptions(profiles=(self.profile,), destination="echo", codecs=("PCMU",),
                                       srtp=("off",), max_calls=4, duration=3)
        with beside("call"):
            code, value = matrix.run(options, deps)
        self.assertEqual((code, value["state"], executed), (matrix.EXIT_REFUSED, "blocked", []))
        self.assertTrue(any("this matrix run was started beside run-0" in item for item in value["blockingErrors"]))
        self.assertFalse((self.root / "matrix").exists())
        self.assertFalse(self.ledger.exists())
        code, value = matrix.run(options, deps)
        self.assertEqual((code, len(executed)), (0, 1), value)

    def campaign(self):
        manifest = self.root / "campaign.yaml"
        raw = manifest.read_bytes()
        plan = compile_plan(yaml.safe_load(raw), hashlib.sha256(raw).hexdigest())
        order = self.root / "order.txt"
        return execute_campaign(
            plan, manifest_bytes=raw, run_root=self.root / "runs",
            runner=[sys.executable, str(TOOL), "runner", str(order)],
            capture_command=[sys.executable, str(TOOL), "capture", "{capture}", str(order)],
            report_command=[sys.executable, str(TOOL), "report", "{capture}"],
            preflight=lambda _destination: (True, "SIP/2.0 200 OK"),
            allow_test_runner=True, manifest_path=manifest, clock=lambda: NOW,
        )

    def test_campaign_run_beside_a_call_creates_nothing(self):
        with beside("call"), self.assertRaisesRegex(AuthorizationLapsed, "this campaign run was started beside"):
            self.campaign()
        self.assertFalse((self.root / "runs").exists())
        self.assertFalse((self.root / "order.txt").exists())
        self.assertFalse(self.ledger.exists())
        result, _run_dir = self.campaign()
        self.assertEqual(result.state, "succeeded")

    def test_checks_that_place_an_invite_are_refused_beside_a_call(self):
        from sippycup_checks import checks, runner
        from test_checks import profile_document, test_deps, write_profile

        called = []

        def fake(name):
            def run(ctx):
                called.append(name)
                return checks.CheckResult(name, "skipped", "fake: sent nothing")
            return run

        root = self.work / "checks-eng"
        root.mkdir()
        section = {"approved": ["banner-disclosure", "unauthenticated-invite"], "max_requests": 10,
                   "destination": "echo"}
        profile = write_profile(root, profile_document("127.0.0.1", 5060, "udp", section))
        deps = test_deps(root, implementations={**checks.IMPLEMENTATIONS, "banner-disclosure": fake("banner"),
                                                "unauthenticated-invite": fake("invite")})
        with beside("call"):
            code, value = runner.execute(runner.RunOptions(profile=profile), deps)
        self.assertEqual((code, value["state"], called), (runner.EXIT_REFUSED, "blocked", []))
        self.assertIn("this checks run was started beside run-0", value["blockingErrors"][0])
        self.assertEqual([path.name for path in root.iterdir()], ["profile.yaml"])


# --------------------------------------------------------------------------- 2: the campaign's run root


class CampaignRunRootTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = support.make_repo(Path(temporary.name))
        self.root = support.compiled_engagement(self.repo, now=NOW, go=False)

    def test_a_campaign_file_in_an_engagement_directory_runs_into_its_runs(self):
        self.assertEqual(campaign.default_run_root(self.root / "campaign.yaml"), self.root / "runs")

    def test_any_other_manifest_keeps_work_runs(self):
        loose = self.repo / "work" / "loose"
        loose.mkdir()
        self.assertEqual(campaign.default_run_root(loose / "campaign.yaml"), Path("work/runs"))
        (loose / "scope.yaml").symlink_to(self.root / "scope.yaml")
        self.assertEqual(campaign.default_run_root(loose / "campaign.yaml"), Path("work/runs"))

    def run_cli(self, *extra: str) -> Path:
        manifest = self.root / "campaign.yaml"
        raw = manifest.read_bytes()
        plan = self.root / "plan.json"
        plan.write_text(json.dumps(compile_plan(yaml.safe_load(raw), hashlib.sha256(raw).hexdigest())))
        seen = {}

        def stand_in(_plan, **keywords):
            seen.update(keywords)
            raise AuthorizationLapsed("stopped by the test before anything exists")

        with mock.patch("sippycup.integration.execute_campaign", stand_in), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            campaign.main(["run", str(plan), "--manifest", str(manifest), *extra])
        return seen["run_root"]

    def test_campaign_run_without_run_root_uses_the_engagements_runs(self):
        self.assertEqual(self.run_cli(), self.root / "runs")

    def test_an_explicit_run_root_is_kept(self):
        other = self.repo / "work" / "elsewhere"
        self.assertEqual(self.run_cli("--run-root", str(other)), other)

    def test_the_ledgers_cross_check_reads_that_directory(self):
        self.assertIn("runs", call_ledger.RUN_ROOTS)


# --------------------------------------------------------------------------- 3: stop and a claimed start


class StopClaimedLauncherTests(unittest.TestCase):
    """The real launcher with a runtime whose `ps` never lists a container: only the claim shows the run."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name).resolve()
        self.checkout = throwaway_checkout(root)
        self.started = root / "started"
        # `run` stays this process (as the real runtime's client does, with
        # the checkout label in its arguments) and never becomes a container.
        self.runtime = executable(root / "runtime", (
            "#!/bin/sh\n"
            'if [ "$1" = ps ]; then echo "[]"; exit 0; fi\n'
            f'if [ "$1" = run ]; then : > "{self.started}"; while :; do sleep 0.1; done; fi\n'
            "exit 125\n"
        ))
        self.claims = self.checkout / "work" / ".sender-claims"

    def launch(self):
        process = subprocess.Popen(
            [str(self.checkout / "bin" / "sippycup"), "call", "work/e/target-profile.yaml"],
            cwd=self.checkout, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, env=launcher_environment(SIPPYCUP_RUNTIME=str(self.runtime)))
        self.addCleanup(lambda: (process.kill(), process.wait()))
        deadline = time.monotonic() + 60
        while not self.started.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(self.started.exists(), "the launcher never reached its runtime")
        return process

    def stop(self, *arguments):
        return subprocess.run(
            [sys.executable, "-m", "sippycup_cockpit.stop", "--repo", str(self.checkout), "--grace", "10",
             *arguments],
            text=True, capture_output=True, timeout=120, cwd=self.checkout,
            env=launcher_environment(SIPPYCUP_RUNTIME=str(self.runtime), PYTHONPATH=str(ROOT / "lib"),
                                     PYTHONDONTWRITEBYTECODE="1"))

    def snapshot(self):
        return sorted((path.name, path.stat().st_mtime_ns, path.read_bytes()) for path in self.claims.iterdir())

    def test_stop_ends_a_launcher_that_has_no_container_yet(self):
        process = self.launch()
        result = self.stop()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"launcher-{process.pid}", result.stdout)
        self.assertIn("stopped before its container was listed", result.stdout)
        self.assertIn("Silence: PROVED", result.stdout)
        self.assertEqual(process.wait(timeout=30), -signal.SIGTERM)

    def test_stop_dry_run_lists_it_and_changes_nothing(self):
        process = self.launch()
        before = self.snapshot()
        result = self.stop("--dry-run")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"launcher-{process.pid}", result.stdout)
        self.assertIn("would be stopped", result.stdout)
        self.assertEqual(self.snapshot(), before)
        self.assertIsNone(process.poll(), "a dry run signals nothing")
        # A dry run in a checkout that never claimed anything creates nothing either.
        process.kill()
        process.wait()
        for path in self.claims.iterdir():
            path.unlink()
        self.claims.rmdir()
        self.assertEqual(self.stop("--dry-run").returncode, 0)
        self.assertFalse(self.claims.exists())

    def test_a_claim_whose_process_is_not_the_launcher_is_not_signalled(self):
        other = subprocess.Popen(["sleep", "60"], stdin=subprocess.DEVNULL)
        self.addCleanup(lambda: (other.kill(), other.wait()))
        self.claims.mkdir(parents=True)
        overlap.write_claim(self.claims, Path("/proc"), other.pid, "call work/e/target-profile.yaml")
        result = self.stop("--grace", "1")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("is not this checkout's launcher or its container runtime; it was not signalled",
                      result.stdout)
        self.assertIn("Silence: NOT PROVED", result.stdout)
        self.assertIsNone(other.poll(), "a process that is not the launcher must be left alone")

    def test_a_claim_of_a_process_that_is_gone_is_not_a_target(self):
        gone = subprocess.Popen(["true"])
        gone.wait()
        self.claims.mkdir(parents=True)
        (self.claims / ("a" * 32 + ".json")).write_text(json.dumps({
            "v": overlap.CLAIM_VERSION, "id": "a" * 32, "pid": gone.pid, "startTime": "1", "command": "call"}))
        result = self.stop()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("No Sippycup sender from this checkout is running.", result.stdout)


class LateContainerTests(unittest.TestCase):
    """The launcher's container was on its way up when the launcher was signalled: it is stopped too."""

    def test_a_container_that_appears_after_the_launcher_ended_is_stopped(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        repo = Path(temporary.name)
        claims = repo / "work" / ".sender-claims"
        claims.mkdir(parents=True)
        proc = repo / "proc"
        (proc / "777").mkdir(parents=True)
        (proc / "777" / "stat").write_text("777 (podman) S 1 " + " ".join(["0"] * 17) + " 1000 0\n")
        (proc / "777" / "status").write_text("Name:\tx\nPPid:\t1\n")
        late = container(OURS, "late-call", labels={**TITLE, stop.CHECKOUT_LABEL: str(repo),
                                                    stop.COMMAND_LABEL: "call"})

        class Host(FakeHost):
            def signal_launcher(self, pid, start, signum):
                self.signals.append((signal.Signals(signum).name, f"launcher {pid} {start}"))
                (proc / "777" / "stat").unlink()
                # The runtime had already begun to start the container.
                self.containers[OURS] = late
                return None

        host = Host([])
        host.repo, host.proc = repo, proc
        overlap.write_claim(claims, proc, 777, "call work/e/target-profile.yaml")
        report = stop.stop(host, checkout=str(repo), image=IMAGE, practice_container="p",
                           include_practice=False, grace=5, dry_run=False)
        self.assertEqual(host.signals, [("SIGTERM", "launcher 777 1000"), ("TERM", OURS)])
        self.assertEqual([(item.kind, item.outcome) for item in report.targets],
                         [("launcher", "clean"), ("container", "clean")])
        self.assertTrue(report.silence["proved"], report.silence)
        self.assertFalse(report.failed)


# --------------------------------------------------------------------------- 4: checks in a stopped directory


class ChecksInAStoppedDirectoryTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name) / "work"
        self.root = self.work / "eng-b"
        self.root.mkdir(parents=True)
        self.called: list[str] = []

    def sibling(self, approval: str) -> None:
        other = self.work / "eng"
        other.mkdir()
        call_ledger.reserve(other, approval_id=approval, ceiling=40, calls=2, command="call",
                            source="target-profile.yaml")

    def run_checks(self, approval: str):
        from sippycup_checks import checks, runner
        from test_checks import profile_document, test_deps, write_profile

        def options_only(ctx):
            self.called.append("banner-disclosure")
            return checks.CheckResult("banner-disclosure", "skipped", "fake: sent nothing")

        document = profile_document("127.0.0.1", 5060, "udp", {"approved": ["banner-disclosure"], "max_requests": 5})
        document["authorization"]["approval_id"] = approval
        profile = write_profile(self.root, document)
        deps = test_deps(self.root, implementations={**checks.IMPLEMENTATIONS, "banner-disclosure": options_only})
        return runner.execute(runner.RunOptions(profile=profile), deps)

    def test_checks_that_place_no_call_are_refused_where_the_rule_stops_the_directory(self):
        from sippycup_checks import runner

        self.sibling("CHG-1")
        code, value = self.run_checks("CHG-1")
        self.assertEqual((code, value["state"], self.called), (runner.EXIT_REFUSED, "blocked", []))
        self.assertEqual((value["requestsSent"], value["networkActivity"], value["runDirectory"]), (0, "none", None))
        (error,) = value["blockingErrors"]
        self.assertIn("this checks run is refused in work/eng-b. Nothing was sent.", error)
        self.assertIn("Go on in work/eng ", error)
        self.assertFalse((self.root / "checks").exists())
        self.assertEqual(error, call_ledger.elsewhere_rule(self.root, "CHG-1", 0).refusal("checks run"))

    def test_the_directory_that_goes_on_and_the_bench_references_run_as_before(self):
        self.sibling("CHG-1")
        self.assertIsNone(call_ledger.stopped_elsewhere(self.work / "eng", "CHG-1", "checks run"))
        self.assertIsNone(call_ledger.stopped_elsewhere(self.root, "CHG-OTHER", "checks run"))
        for approval in sorted(call_ledger.BENCH_APPROVAL_IDS):
            self.assertIsNone(call_ledger.stopped_elsewhere(self.root, approval, "checks run"), approval)
        self.sibling_bench = self.work / "bench"
        self.sibling_bench.mkdir()
        call_ledger.reserve(self.sibling_bench, approval_id="LOCAL-PRACTICE-REHEARSAL", ceiling=40, calls=1,
                            command="call", source="target-profile.yaml")
        code, value = self.run_checks("LOCAL-PRACTICE-REHEARSAL")
        self.assertEqual(self.called, ["banner-disclosure"], value)
        self.assertNotEqual(value["state"], "blocked")


# --------------------------------------------------------------------------- 5: the window text


class CampaignWindowTextTests(unittest.TestCase):
    def emitted(self, manifest: Path) -> str:
        from sippycup import approval

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            campaign._emit_error(argparse.Namespace(manifest=manifest, error_format="human"), "authorization_lapsed",
                                 f"refusing to run: the approval window has ended; {approval.NEW_WINDOW}")
        return stderr.getvalue()

    def test_the_campaign_window_text_names_the_engagement_directory(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name) / "work" / "eng"
            directory.mkdir(parents=True)
            (directory / "scope.yaml").write_text("authorization: {status: approved}\n")
            text = self.emitted(directory / "campaign.yaml")
            self.assertNotIn("DIR", text)
            self.assertIn(f"record the approval again (./bin/sippycup scope answer {directory} 2), run "
                          f"./bin/sippycup scope compile {directory}, then campaign plan again", text)

    def test_a_manifest_without_a_scope_file_keeps_the_general_text(self):
        with tempfile.TemporaryDirectory() as name:
            self.assertIn("(scope answer DIR 2)", self.emitted(Path(name) / "campaign.yaml"))


if __name__ == "__main__":
    unittest.main()
