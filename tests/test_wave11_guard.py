"""Wave 11 (third rehearsal), builder ``guard``: findings 1, 2, 4, 5, 7 and 9.

1  simultaneous starts: the overlap check claims a start under a file lock
2  the count per approval reference is never shown without the other references
4  the same approval reference counted in a sibling directory is named
5  ``stop`` and the read-only commands run with a stale SIPPYCUP_ROUTED_PRACTICE
7  a matrix cell that the gate blocked mid-run is not a placed call
9  ``ready`` and the cockpit notice a frozen plan that no longer matches campaign.yaml

No container is started and nothing is sent: the launcher gets a fake runtime
inside a throwaway checkout (symlinks to this checkout's bin, lib and config,
and a work directory of its own).
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from sippycup import call_ledger  # noqa: E402
from sippycup_cockpit import overlap, ready  # noqa: E402
from sippycup_cockpit import model as cockpit_model  # noqa: E402
from sippycup_workbench import matrix  # noqa: E402

from test_guided_call import NOW, profile_document  # noqa: E402
from test_stop import CHECKOUT, IMAGE, OURS, FakeHost, container  # noqa: E402


def throwaway_checkout(root: Path) -> Path:
    """A checkout the launcher takes for its own: real work/, everything else linked."""
    checkout = root / "checkout"
    (checkout / "work").mkdir(parents=True)
    for name in ("bin", "lib", "config"):
        (checkout / name).symlink_to(ROOT / name)
    return checkout


def launcher_environment(**extra: str) -> dict[str, str]:
    dropped = {"SIPPYCUP_ROUTED_PRACTICE", "SIPPYCUP_ROUTED_ADDRESS", "SIPPYCUP_OVERLAP", "SIPPYCUP_ALLOW_OVERLAP"}
    return {**{key: value for key, value in os.environ.items() if key not in dropped}, **extra}


def executable(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


# --------------------------------------------------------------------------- finding 1


class FakeProc:
    """A /proc with just enough for the claim check: PID/stat and PID/status."""

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir()

    def add(self, pid: int, start: str = "1000", state: str = "S") -> None:
        directory = self.root / str(pid)
        directory.mkdir(exist_ok=True)
        fields = [state, "1", *(["0"] * 17), start, "0"]
        (directory / "stat").write_text(f"{pid} (podman (run)) {' '.join(fields)}\n")
        (directory / "status").write_text("Name:\tx\nPPid:\t1\n")

    def remove(self, pid: int) -> None:
        for name in ("stat", "status"):
            (self.root / str(pid) / name).unlink()
        (self.root / str(pid)).rmdir()


class ClaimTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.claims = root / "claims"
        self.proc = FakeProc(root / "proc")

    def host(self, containers=()):
        host = FakeHost(list(containers))
        host.proc = self.proc.root
        return host

    def check(self, host=None, *, claim_pid=None, environ=None):
        stderr, stdout = io.StringIO(), io.StringIO()
        argv = ["--command", "call"] + (["--claim-pid", str(claim_pid)] if claim_pid is not None else [])
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
            code = overlap.main(argv, host=host or self.host(), claims=self.claims,
                                environ={"SIPPYCUP_IMAGE": IMAGE, **(environ or {})})
        return code, stdout.getvalue(), stderr.getvalue()

    def claim(self, pid, start="1000"):
        self.proc.add(pid, start)
        code, out, err = self.check(claim_pid=pid)
        self.assertEqual(code, 0, err)
        self.assertRegex(out, r"^claim [0-9a-f]{32}\n$")
        return out.split()[1]

    def test_the_first_start_claims_and_the_next_is_refused_before_any_container_exists(self):
        identifier = self.claim(111)
        written = json.loads((self.claims / f"{identifier}.json").read_text())
        self.assertEqual((written["pid"], written["startTime"], written["command"]), (111, "1000", "call"))
        self.assertEqual(stat.S_IMODE((self.claims / f"{identifier}.json").stat().st_mode), 0o600)
        self.proc.add(222)
        code, out, err = self.check(claim_pid=222)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("another sending command of this checkout is active", err)
        self.assertIn("launcher-111", err)
        self.assertIn("Nothing was sent", err)
        # The refused start left no claim of its own.
        self.assertEqual([path.stem for path in self.claims.glob("*.json")], [identifier])

    def test_a_claim_ends_with_its_process_so_a_crash_never_wedges_the_tool(self):
        identifier = self.claim(111)
        self.proc.remove(111)
        self.proc.add(222)
        code, out, _err = self.check(claim_pid=222)
        self.assertEqual(code, 0)
        self.assertFalse((self.claims / f"{identifier}.json").exists(), "the finished claim is deleted")

    def test_a_reused_process_id_a_zombie_and_an_unreadable_claim_are_not_live(self):
        for change in ("reused", "zombie", "garbage", "renamed"):
            with self.subTest(change=change):
                for path in self.claims.glob("*.json"):
                    path.unlink()
                identifier = self.claim(111)
                path = self.claims / f"{identifier}.json"
                if change == "reused":
                    self.proc.add(111, start="2000")
                elif change == "zombie":
                    self.proc.add(111, state="Z")
                elif change == "garbage":
                    path.write_text("{not json")
                else:
                    path.rename(self.claims / ("0" * 32 + ".json"))
                self.proc.add(222)
                self.assertEqual(self.check(claim_pid=222)[0], 0)
                self.assertFalse(path.exists())

    def test_a_claim_and_its_running_container_are_one_run(self):
        identifier = self.claim(111)
        running = container(OURS, "busy_call", labels={"dev.sippycup.checkout": CHECKOUT,
                                                       "dev.sippycup.command": "call",
                                                       overlap.CLAIM_LABEL: identifier})
        self.proc.add(222)
        code, _out, err = self.check(self.host([running]), claim_pid=222)
        self.assertEqual(code, 2)
        self.assertIn("busy_call", err)
        self.assertNotIn("launcher-111", err)
        # The allowed-overlap route names the container, as before, and is recorded.
        code, out, err = self.check(self.host([running]), claim_pid=222, environ={overlap.ALLOW_ENV: "busy_call"})
        self.assertEqual(code, 0, err)
        first, second = out.splitlines()
        self.assertRegex(first, r"^claim [0-9a-f]{32}$")
        record = json.loads(second)
        self.assertEqual([item["name"] for item in record["activeRuns"]], ["busy_call"])
        self.assertEqual(record["allowedBy"], overlap.ALLOW_ENV)
        self.assertIn("unreliable", err)

    def test_the_allowed_overlap_must_name_a_launcher_that_has_no_container_yet(self):
        self.claim(111)
        self.proc.add(222)
        self.assertEqual(self.check(claim_pid=222, environ={overlap.ALLOW_ENV: "busy_call"})[0], 2)
        code, out, _err = self.check(claim_pid=222, environ={overlap.ALLOW_ENV: "launcher-111"})
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.splitlines()[1])["activeRuns"][0]["kind"], "launcher")

    def test_a_claim_of_another_launcher_counts_without_claim_pid_too(self):
        self.claim(111)
        self.assertEqual(self.check()[0], 2)

    def test_an_unusable_claim_directory_or_a_dead_launcher_fails_closed(self):
        self.claims.write_text("a file where the directory should be")
        self.proc.add(222)
        code, out, err = self.check(claim_pid=222)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("Nothing was sent", err)
        self.claims.unlink()
        code, out, err = self.check(claim_pid=333)  # no such process
        self.assertEqual((code, out), (2, ""))
        self.assertIn("Nothing was sent", err)

    def test_the_lock_is_free_again_after_the_check_and_is_not_inherited(self):
        import fcntl

        self.claim(111)
        descriptor = os.open(self.claims / overlap.LOCK_NAME, os.O_RDWR)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)  # raises if the check still held it
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        with overlap._ClaimLock(self.claims) as lock:
            self.assertFalse(os.get_inheritable(lock.descriptor))

    def test_a_held_lock_refuses_after_the_wait_instead_of_passing(self):
        import fcntl

        self.claims.mkdir()
        descriptor = os.open(self.claims / overlap.LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        with self.assertRaises(overlap.ClaimError):
            with overlap._ClaimLock(self.claims, wait=0.2):
                self.fail("the lock was held elsewhere")


class SimultaneousStartTests(unittest.TestCase):
    """The real launcher, several at the same instant, a runtime whose `ps` never shows a container."""

    STARTS = 6

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.checkout = throwaway_checkout(root)
        self.started = root / "started"
        self.started.mkdir()
        # `run` is the "container": it notes that it started and stays for a
        # while. `ps` lists nothing, as the real runtime does in the moment
        # before a container exists, so only the claim can hold the others off.
        self.runtime = executable(root / "runtime", (
            "#!/bin/sh\n"
            'if [ "$1" = ps ]; then echo "[]"; exit 0; fi\n'
            f'if [ "$1" = run ]; then : > "{self.started}/$$"; printf \'%s\\n\' "$@" > "{self.started}/$$.args"; '
            'exec sleep "${FAKE_RUN_SECONDS:-4}"; fi\n'
            "exit 125\n"
        ))

    def start(self, seconds="4", **extra):
        return subprocess.Popen(
            [str(self.checkout / "bin" / "sippycup"), "call", "work/e/target-profile.yaml"],
            cwd=self.checkout, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
            env=launcher_environment(SIPPYCUP_RUNTIME=str(self.runtime), FAKE_RUN_SECONDS=seconds, **extra))

    def finish(self, processes):
        results = []
        for process in processes:
            _out, err = process.communicate(timeout=120)
            results.append((process.returncode, err))
        return results

    def started_count(self):
        return len([path for path in self.started.iterdir() if path.suffix != ".args"])

    def test_exactly_one_of_several_simultaneous_starts_runs(self):
        results = self.finish([self.start() for _ in range(self.STARTS)])
        codes = sorted(code for code, _err in results)
        self.assertEqual(codes, [0] + [2] * (self.STARTS - 1), results)
        self.assertEqual(self.started_count(), 1)
        for code, err in results:
            if code == 2:
                self.assertIn("another sending command of this checkout is active", err)
                self.assertIn("launcher-", err)
                self.assertIn("Nothing was sent", err)
        # The one that ran carried its claim as a label.
        (arguments,) = [path.read_text().splitlines() for path in self.started.glob("*.args")]
        self.assertTrue([item for item in arguments if item.startswith("--label=dev.sippycup.claim=")], arguments)
        # Its process is gone now, so the next start is not held up.
        again = self.finish([self.start(seconds="0")])
        self.assertEqual(again[0][0], 0, again)
        self.assertEqual(self.started_count(), 2)

    def test_a_killed_run_does_not_hold_the_next_start(self):
        first = self.start(seconds="60")
        deadline = time.monotonic() + 60
        while self.started_count() == 0 and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(self.started_count(), 1)
        refused = self.finish([self.start(seconds="0")])
        self.assertEqual(refused[0][0], 2, refused)
        first.send_signal(signal.SIGKILL)
        first.communicate(timeout=30)
        passed = self.finish([self.start(seconds="0")])
        self.assertEqual(passed[0][0], 0, passed)

    def test_the_allowed_overlap_route_still_starts_and_hands_over_its_record(self):
        first = self.start(seconds="60")
        self.addCleanup(lambda: (first.kill(), first.communicate()))
        deadline = time.monotonic() + 60
        while self.started_count() == 0 and time.monotonic() < deadline:
            time.sleep(0.05)
        name = f"launcher-{first.pid}"
        (code, err), = self.finish([self.start(seconds="0", SIPPYCUP_ALLOW_OVERLAP=name)])
        self.assertEqual(code, 0, err)
        self.assertIn(f"running beside {name}", err)
        records = [line for path in self.started.glob("*.args") for line in path.read_text().splitlines()
                   if line.startswith("--env=SIPPYCUP_OVERLAP=")]
        self.assertEqual(len(records), 1)
        self.assertEqual(json.loads(records[0].split("=", 2)[2])["activeRuns"][0]["name"], name)

    def test_a_dry_run_claims_nothing(self):
        process = subprocess.run(
            [str(self.checkout / "bin" / "sippycup"), "call", "work/e/target-profile.yaml", "--dry-run"],
            cwd=self.checkout, text=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=60,
            env=launcher_environment(SIPPYCUP_RUNTIME=str(self.runtime)))
        self.assertNotIn("another sending command", process.stderr)
        self.assertFalse((self.checkout / "work" / ".sender-claims").exists())


# --------------------------------------------------------------------------- finding 5


class StaleRoutedVariableTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.checkout = throwaway_checkout(root)
        # No container of that name: `container inspect` fails.
        self.runtime = executable(root / "runtime", (
            "#!/bin/sh\n"
            'if [ "$1" = ps ]; then echo "[]"; exit 0; fi\n'
            'if [ "$1" = container ] && [ "$2" = inspect ]; then exit 125; fi\n'
            "printf 'STARTED %s\\n' \"$*\"\n"
        ))

    def run_cli(self, *arguments, name="sippycup-practice-routed"):
        return subprocess.run(
            [str(self.checkout / "bin" / "sippycup"), *arguments], cwd=self.checkout, text=True,
            capture_output=True, stdin=subprocess.DEVNULL, timeout=120,
            env=launcher_environment(SIPPYCUP_RUNTIME=str(self.runtime), SIPPYCUP_ROUTED_PRACTICE=name))

    REFUSAL = "is not up (SIPPYCUP_ROUTED_PRACTICE is set)"

    def test_stop_dry_run_runs_and_says_the_variable_is_ignored(self):
        result = self.run_cli("stop", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(self.REFUSAL, result.stderr)
        self.assertIn("Note: SIPPYCUP_ROUTED_PRACTICE is set, but the routed practice target "
                      "sippycup-practice-routed is not up", result.stderr)
        self.assertIn("No Sippycup sender from this checkout is running", result.stdout)

    def test_an_invalid_name_does_not_block_stop_either(self):
        result = self.run_cli("stop", "--dry-run", name="not a name!")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("invalid name and is ignored", result.stderr)
        self.assertEqual(self.run_cli("call", "work/e/p.yaml", name="not a name!").returncode, 2)

    def test_read_only_host_commands_are_not_refused(self):
        commands = {
            "summary": ("summary", "work/none"), "report": ("report", "work/none.pcap"),
            "rehearse": ("rehearse", "work/none/target-profile.yaml"), "ready": ("ready", "work/none"),
            "go": ("go", "work/none", "--plain"), "journal": ("journal", "verify", "work/none"),
            "diagnose": ("diagnose", "work/none/calls/x"), "explain": ("explain", "call.registration-failed"),
        }
        for name, arguments in commands.items():
            with self.subTest(command=name):
                result = self.run_cli(*arguments)
                self.assertNotIn(self.REFUSAL, result.stderr)
                self.assertNotIn("No container or network activity was started", result.stderr)
                self.assertIn("Note: SIPPYCUP_ROUTED_PRACTICE is set", result.stderr)
                self.assertNotIn("STARTED", result.stdout)

    def test_senders_and_container_commands_still_fail_closed(self):
        for arguments in (("call", "work/e/target-profile.yaml"), ("preflight", "--profile", "work/e/p.yaml"),
                          ("matrix", "run", "work/e/p.yaml", "--dial", "echo"),
                          ("campaign", "run", "work/e/plan.json", "--manifest", "work/e/campaign.yaml"),
                          ("checks", "run", "work/e/p.yaml"), ("media", "send", "work/e/s.json"),
                          ("--isolated", "rehearse", "work/e/p.yaml"), ("capture", "--target", "192.0.2.1"),
                          ("--", "true"), ()):
            with self.subTest(arguments=arguments):
                result = self.run_cli(*arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(self.REFUSAL, result.stderr)
                self.assertIn("No container or network activity was started", result.stderr)
                self.assertNotIn("STARTED", result.stdout)
        practice = self.run_cli("--practice", "stop")
        self.assertEqual(practice.returncode, 2)
        self.assertIn("cannot be combined with --practice or --admin", practice.stderr)


# --------------------------------------------------------------------------- findings 2 and 4


class ReferenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name) / "work"
        self.engagement = self.directory("eng")

    def directory(self, name):
        path = self.work / name
        path.mkdir(parents=True)
        return path

    def reserve(self, approval, calls=1, directory=None, ceiling=40):
        return call_ledger.reserve(directory or self.engagement, approval_id=approval, ceiling=ceiling, calls=calls,
                                   command="call", source="target-profile.yaml")

    def test_calls_stay_under_their_reference_when_it_is_switched_back_and_forth(self):
        # The tester saw "28 placed, 27 counted": 27 under the first reference
        # and 1 under the second, which no line named.
        self.reserve("TICKET-1", 3)
        self.reserve("TICKET-2", 1, ceiling=10)
        failed = self.reserve("TICKET-1", 1)
        failed.release(1, "no INVITE was sent")
        self.reserve("TICKET-1", 1)
        counts = {item.approval_id: item for item in call_ledger.reference_counts(self.engagement)}
        self.assertEqual({key: item.used for key, item in counts.items()}, {"TICKET-1": 4, "TICKET-2": 1})
        self.assertEqual((counts["TICKET-1"].ceiling, counts["TICKET-2"].ceiling), (40, 10))
        self.assertEqual(list(counts), ["TICKET-1", "TICKET-2"])
        back = call_ledger.status(self.engagement, "TICKET-1", 40, context=True)
        self.assertEqual((back.used, back.left), (4, 36))
        self.assertIn("1 call(s) were placed here under reference TICKET-2", back.line())
        self.assertIn("5 in all", back.line())
        forth = call_ledger.status(self.engagement, "TICKET-2", 10, context=True)
        self.assertEqual(forth.used, 1)
        self.assertIn("4 call(s) were placed here under reference TICKET-1", forth.line(1, "call"))
        self.assertIn("new written approval", forth.line())

    def test_a_new_reference_is_never_shown_as_a_silent_zero(self):
        self.reserve("TICKET-1", 24)
        fresh = call_ledger.status(self.engagement, "TICKET-1-CORRECTED", 10, context=True)
        self.assertEqual(fresh.used, 0)
        self.assertTrue(fresh.line().startswith(
            "Calls: 0 of 10 used, 10 left (approval TICKET-1-CORRECTED, counted in work/eng/call-ledger.jsonl). "
            "Also in work/eng: 24 call(s) were placed here under reference TICKET-1 (24 in all"), fresh.line())
        self.assertEqual(fresh.as_dict()["otherReferences"][0]["used"], 24)
        self.assertEqual(fresh.line(notes=False),
                         "Calls: 0 of 10 used, 10 left (approval TICKET-1-CORRECTED, counted in "
                         "work/eng/call-ledger.jsonl)")

    def test_without_context_the_status_is_what_it_was(self):
        # The owner report builds its own per-reference lines (builder report2).
        self.reserve("TICKET-1", 2)
        self.reserve("TICKET-2", 1)
        plain = call_ledger.status(self.engagement, "TICKET-2", 10)
        self.assertEqual(plain.notes(), [])
        self.assertEqual(set(plain.as_dict()), {"approvalId", "ledger", "limit", "used", "left", "error"})
        self.assertNotIn("TICKET-1", plain.line())

    def test_reference_counts_never_raises(self):
        self.assertEqual(call_ledger.reference_counts(self.engagement), [])
        (self.engagement / call_ledger.LEDGER_FILE).write_text("not json\n")
        self.assertEqual(call_ledger.reference_counts(self.engagement), [])

    def test_the_same_reference_in_a_sibling_directory_is_named_with_its_count(self):
        day_two = self.directory("eng-day2")
        self.reserve("TICKET-1", 24)
        found = call_ledger.status(day_two, "TICKET-1", 40, context=True)
        self.assertEqual([(item.directory, item.used) for item in found.elsewhere], [("work/eng", 24)])
        self.assertTrue(found.elsewhere_blocks)
        self.assertIn("Same approval reference TICKET-1 in another directory: work/eng counts 24 call(s)",
                      found.line())
        self.assertIn("NOT in the count above", found.line())
        # The other way round too, once the copy has placed a call.
        self.reserve("TICKET-1", 1, directory=day_two)
        self.assertEqual([(item.directory, item.used) for item in
                          call_ledger.same_approval_elsewhere(self.engagement, "TICKET-1")],
                         [("work/eng-day2", 1)])
        # Another reference, released calls, and a directory without a ledger say nothing.
        self.assertEqual(call_ledger.same_approval_elsewhere(day_two, "TICKET-9"), [])
        third = self.directory("third")
        self.reserve("TICKET-3", 1, directory=third).release(1, "nothing was sent")
        self.assertEqual(call_ledger.same_approval_elsewhere(day_two, "TICKET-3"), [])

    def test_the_practice_bench_is_exempt_and_bench_references_do_not_block(self):
        bench = self.directory("practice")
        call_ledger.new_approval_window(bench, approval_id=call_ledger.PRACTICE_APPROVAL_ID, budget=200, by="test")
        self.reserve(call_ledger.PRACTICE_APPROVAL_ID, 5, directory=bench)
        self.assertEqual(call_ledger.same_approval_elsewhere(self.engagement, call_ledger.PRACTICE_APPROVAL_ID), [])
        self.reserve(call_ledger.PRACTICE_APPROVAL_ID, 2)
        self.assertEqual(call_ledger.same_approval_elsewhere(bench, call_ledger.PRACTICE_APPROVAL_ID), [])
        copy = self.directory("eng-b")
        found = call_ledger.status(copy, call_ledger.PRACTICE_APPROVAL_ID, 40, context=True)
        self.assertEqual([item.directory for item in found.elsewhere], ["work/eng"])
        self.assertFalse(found.elsewhere_blocks)
        self.assertIn("work/eng counts 2 call(s)", found.line())
        self.assertIn("expected for this practice reference", found.line())

    def test_bench_references_are_the_benches_own_constants(self):
        from sippycup import practice, practice_rehearsal, routed_rehearsal

        self.assertEqual(call_ledger.BENCH_APPROVAL_IDS,
                         {practice.APPROVAL_ID, practice_rehearsal.APPROVAL_ID, routed_rehearsal.ROUTED_APPROVAL_ID})

    def test_an_unreadable_sibling_ledger_counts_only_when_it_names_the_reference(self):
        broken = self.directory("broken")
        (broken / call_ledger.LEDGER_FILE).write_text('{"approval":"TICKET-1","calls":3,"event":"reserve"\n')
        other = self.directory("other")
        (other / call_ledger.LEDGER_FILE).write_text("garbage about TICKET-7\n")
        found = call_ledger.same_approval_elsewhere(self.engagement, "TICKET-1")
        self.assertEqual([(item.directory, item.used) for item in found], [("work/broken", None)])
        status = call_ledger.CallsStatus("TICKET-1", "work/eng/call-ledger.jsonl", 40, 0, elsewhere=tuple(found))
        self.assertIn("work/broken has a ledger that names it and cannot be read", status.line())

    # -- what the operator sees ------------------------------------------------

    def profile(self, directory, approval, limit=40):
        path = directory / "target-profile.yaml"
        path.write_text(yaml.safe_dump(profile_document(**{"authorization.approval_id": approval,
                                                           "limits.max_calls": limit})), encoding="utf-8")
        return path

    def test_rehearse_prints_the_other_reference_and_the_sibling_directory(self):
        from sippycup_workbench import cli

        self.reserve("TICKET-1", 24)
        self.reserve("TICKET-2", 1, directory=self.directory("eng-day2"))
        result = cli.rehearse_file(self.profile(self.engagement, "TICKET-2", 10))
        calls = result.facts["calls"]
        self.assertEqual(calls["line"], "Calls: 0 of 10 used, 10 left (approval TICKET-2, counted in "
                                        "work/eng/call-ledger.jsonl)")
        self.assertEqual(len(calls["notes"]), 2)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cli._emit({"ready": result.ready, "errors": [], "warnings": [], "facts": result.facts}, "text")
        text = output.getvalue()
        self.assertIn("Calls: Also in work/eng: 24 call(s) were placed here under reference TICKET-1", text)
        self.assertIn("Calls: Same approval reference TICKET-2 in another directory: work/eng-day2 counts 1 call(s)",
                      text)

    def test_dry_run_and_matrix_plan_lines_carry_the_notes(self):
        from sippycup_workbench.call import calls_status

        self.reserve("TICKET-1", 24)
        path = self.profile(self.engagement, "TICKET-2", 10)
        line = calls_status(path, yaml.safe_load(path.read_text())).line(1, "call")
        self.assertIn("this call would place 1. Also in work/eng: 24 call(s) were placed here under reference "
                      "TICKET-1", line)
        plan = matrix.build_plan(matrix.MatrixOptions(profiles=(path,), destination="echo", codecs=("PCMU",)),
                                 now=NOW, work_root=self.work)
        self.assertIn("24 call(s) were placed here under reference TICKET-1", plan["callsLeft"][0]["line"])

    def ready_check(self, directory, approval, limit=40):
        path = self.profile(directory, approval, limit)
        model = {"engagement": {"display": f"work/{directory.name}"}}
        return ready.check_calls(model, path, yaml.safe_load(path.read_text()))

    def test_ready_is_no_go_when_a_sibling_directory_counts_the_same_owner_reference(self):
        self.reserve("TICKET-1", 24)
        check = self.ready_check(self.directory("eng-day2"), "TICKET-1")
        self.assertEqual(check.status, ready.NOGO)
        text = "\n".join(check.lines)
        self.assertIn("work/eng counts 24 call(s)", text)
        self.assertIn("go on in work/eng", check.fix)
        self.assertIn("new written approval from the owner", check.fix)

    def test_ready_stays_go_for_a_practice_reference_and_for_another_reference_but_says_both(self):
        self.reserve(call_ledger.PRACTICE_APPROVAL_ID, 27)
        copy = self.ready_check(self.directory("eng-b"), call_ledger.PRACTICE_APPROVAL_ID)
        self.assertEqual(copy.status, ready.GO)
        self.assertIn("work/eng counts 27 call(s)", "\n".join(copy.lines))
        switched = self.ready_check(self.engagement, "LOCAL-PRACTICE-ONLY-2", 10)
        self.assertEqual(switched.status, ready.GO)
        self.assertIn("27 call(s) were placed here under reference LOCAL-PRACTICE-ONLY", "\n".join(switched.lines))

    def test_readys_fix_for_an_untrusted_ledger_does_not_offer_a_new_id_as_a_way_round(self):
        self.reserve("TICKET-1", 2)
        run = self.engagement / "calls" / "20261117T120000.000000Z-x-00000000"
        run.mkdir(parents=True)
        (run / "profile.json").write_text(json.dumps({"authorization": {"approval_id": "TICKET-1"}}))
        (run / "result.json").write_text(json.dumps({"verdict": "pass"}))
        check = self.ready_check(self.engagement, "TICKET-1")
        self.assertEqual(check.status, ready.NOGO)
        self.assertNotIn("or ask the owner for a new approval id", check.fix)
        self.assertIn("A new approval id is not a way around this", check.fix)
        self.assertIn("only when the owner gives a new written approval", check.fix)
        self.assertIn("changing the id without one only hides the calls already placed", "\n".join(check.lines))


# --------------------------------------------------------------------------- finding 7


class BlockedCellTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name) / "work"
        self.engagement = self.work / "engagement"
        self.engagement.mkdir(parents=True)
        self.profile = self.engagement / "udp.yaml"
        self.profile.write_text(yaml.safe_dump(profile_document(**{
            "limits.max_calls": 40, "media": {"codecs": ["PCMU", "PCMA"]},
            "features": {"ice": False, "turn": False, "srtp": True, "dtls_srtp": False, "webrtc": False}})))

    BLOCK = ("target-profile.yaml no longer matches work/engagement/scope.yaml (the scope changed after the "
             "compile); run ./bin/sippycup scope compile work/engagement")

    def run_matrix(self, blocked_at=2):
        calls, lines = [], []

        def execute(options, deps):
            calls.append(options)
            if len(calls) == blocked_at:
                # What call.execute returns when its gate refuses: no run directory.
                return 2, {"apiVersion": "sippycup.dev/call/v1", "state": "blocked", "verdict": "blocked",
                           "exitCode": 2, "blockingErrors": [self.BLOCK], "runDirectory": None,
                           "networkActivity": "none"}
            return 0, {"verdict": "pass", "state": "completed", "callCounted": True,
                       "softphone": {"final_status": 200}, "setup": {"inviteToAnswerSeconds": 0.04},
                       "codec": {"offered": ["PCMU"], "negotiated": "PCMU", "negotiatedPayloadType": 0,
                                 "wire": {"verified": True}},
                       "srtp": {"active": False}, "runDirectory": f"work/engagement/calls/run-{len(calls)}"}

        class CallDeps:
            pass

        deps = matrix.MatrixDependencies(
            execute=execute, call_dependencies=lambda env: CallDeps(), now=lambda: NOW,
            sleep=lambda seconds: None, monotonic=lambda: 0.0, environ={"PATH": "/usr/bin"},
            work_root=self.work, install_signal_handlers=False, progress=lines.append)
        options = matrix.MatrixOptions(profiles=(self.profile,), destination="echo", codecs=("PCMU", "PCMA"),
                                       srtp=("off", "mandatory"), max_calls=4)
        code, value = matrix.run(options, deps)
        return code, value, calls, lines

    def test_a_cell_blocked_mid_run_is_not_placed_and_names_no_run_directory(self):
        code, value, calls, lines = self.run_matrix()
        self.assertEqual((code, value["state"]), (3, "stopped"))
        self.assertEqual(len(calls), 2)
        self.assertEqual([cell["status"] for cell in value["cells"]], ["run", "refused", "not-run", "not-run"])
        self.assertEqual((value["callsPlaced"], value["passed"]), (1, 1))
        blocked = value["cells"][1]
        self.assertEqual(blocked["verdict"], "blocked")
        self.assertFalse(blocked.get("runDirectory"))
        self.assertIn("the scope changed after the compile", blocked["reason"])
        for cell in value["cells"]:
            self.assertEqual(cell["status"] == "run", bool(cell.get("runDirectory")), cell)
        text = matrix.render_human(value)
        self.assertIn("Call matrix: STOPPED - 1 of 4 call(s) placed, 1 passed", text)
        self.assertIn("STOPPED: blocked: cell 2 was not placed; the profile gate refused it before anything was "
                      "sent for it: " + self.BLOCK, text)
        self.assertIn("Network activity: 1 guided call(s)", text)
        self.assertIn("blocked, nothing was sent for this cell", lines[-1])
        # The record on disk says the same, and still fits its schema.
        (directory,) = list((self.engagement / "matrix").iterdir())
        written = json.loads((directory / "matrix.json").read_text())
        self.assertEqual(written["callsPlaced"], 1)
        from sippycup_workbench import summary_matrix

        schema = json.loads((ROOT / "schemas" / "call-matrix-v1.schema.json").read_text())
        self.assertEqual(summary_matrix.validate(written, schema), [])
        # The ledger counts the one call that was placed.
        approval = yaml.safe_load(self.profile.read_text())["authorization"]["approval_id"]
        self.assertEqual(call_ledger.status(self.engagement, approval, 40).used, 1)

    def test_a_first_cell_that_is_blocked_places_nothing(self):
        code, value, calls, _lines = self.run_matrix(blocked_at=1)
        self.assertEqual((code, value["state"], value["callsPlaced"]), (2, "blocked", 0))
        self.assertEqual(value["networkActivity"], "none")
        approval = yaml.safe_load(self.profile.read_text())["authorization"]["approval_id"]
        self.assertEqual(call_ledger.status(self.engagement, approval, 40).used, 0)

    def test_the_owner_report_raises_no_missing_run_for_the_blocked_cell(self):
        import shutil

        from sippycup_workbench.summary_model import Options, build_report
        from test_summary_matrix import FIXTURE, MATRIX_NAME, UDP_PASS, cell, matrix_document

        root = self.work / "eng"
        shutil.copytree(FIXTURE, root)
        cells = [cell(1, "udp", "PCMU", "off", UDP_PASS), cell(2, "udp", "PCMA", "off"),
                 cell(3, "tls", "PCMU", "off"), cell(4, "tls", "PCMA", "off")]
        # Cell 2 as the fixed runner records a blocked cell.
        cells[1].update(status="refused", verdict="blocked", exitCode=2,
                        reason="the profile gate refused it before anything was sent for it: " + self.BLOCK)
        directory = root / "matrix" / MATRIX_NAME
        directory.mkdir(parents=True)
        (directory / "matrix.json").write_text(json.dumps(matrix_document(cells, callsPlaced=1, passed=1)))
        model, _ = build_report(root, Options(generated_at="2026-11-18T04:00:00Z"))
        codes = [item["code"] for item in model["integrityExceptions"] if item["code"].startswith("matrix-")]
        self.assertEqual(codes, [])


# --------------------------------------------------------------------------- finding 9


class StalePlanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "work" / "eng"
        self.root.mkdir(parents=True)
        self.manifest = self.root / "campaign.yaml"
        self.manifest.write_text("metadata: {name: first}\n")
        digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        (self.root / "plan.json").write_text(json.dumps({
            "metadata": {"name": "first", "manifestSha256": digest}, "steps": [],
            "authorization": {"approval": {"id": "T", "validFrom": "a", "validUntil": "b"}}}))

    def model(self):
        return {"engagement": {"display": "work/eng"}, "files": cockpit_model._files(self.root, self.root.parents[1])}

    def test_a_plan_frozen_from_this_campaign_file_says_nothing(self):
        model = self.model()
        self.assertIs(model["files"]["planFacts"]["manifestMatches"], True)
        self.assertIsNone(ready.check_plan(model))
        self.assertEqual(cockpit_model._plan_step(model["files"]),
                         {"label": "frozen plan present (campaign plan)", "done": True})

    def test_ready_warns_with_the_line_campaign_run_prints_once_the_campaign_file_was_rewritten(self):
        from sippycup_workbench.replan import replan_command

        self.manifest.write_text("metadata: {name: second}\n")  # scope compile wrote it again
        model = self.model()
        self.assertIs(model["files"]["planFacts"]["manifestMatches"], False)
        check = ready.check_plan(model)
        self.assertEqual((check.identifier, check.status), ("plan", ready.WARN))
        self.assertIn("no longer matches", check.lines[0])
        self.assertIn("campaign run will refuse this plan and send nothing", check.lines[1])
        expected = replan_command("work/eng/plan.json", "work/eng/campaign.yaml")
        self.assertEqual(check.fix.split(" && ")[1], expected.split(" && ")[1])
        self.assertTrue(check.fix.startswith("mv -n work/eng/plan.json work/eng/plan-"))
        self.assertTrue(check.fix.endswith(
            "&& ./bin/sippycup campaign plan work/eng/campaign.yaml --output work/eng/plan.json"))
        rendered = "\n".join(ready.render({
            "engagement": "work/eng", "localTime": "x", "generatedAt": "y", "checks": [check.as_dict()],
            "authorizes": [], "verdict": "GO", "warnings": 1, "blocking": 0}, None))
        self.assertIn("[WARN]  Frozen campaign plan", rendered)
        self.assertIn("fix: mv -n work/eng/plan.json", rendered)
        self.assertIn("VERDICT: GO with 1 warning(s)", rendered)

    def test_the_cockpit_step_is_not_done_for_a_stale_plan(self):
        self.manifest.write_text("metadata: {name: second}\n")
        step = cockpit_model._plan_step(self.model()["files"])
        self.assertIs(step["done"], False)
        self.assertIn("does NOT", step["label"])
        self.assertIn("campaign run will refuse it", step["label"])

    def test_nothing_to_compare_is_not_called_stale(self):
        self.manifest.unlink()
        model = self.model()
        self.assertIsNone(model["files"]["planFacts"]["manifestMatches"])
        self.assertIsNone(ready.check_plan(model))
        self.assertIs(cockpit_model._plan_step(model["files"])["done"], True)


if __name__ == "__main__":
    unittest.main()
