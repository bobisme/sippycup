"""Unit tests for ``./bin/sippycup stop`` with a fake container runtime and /proc.

No container is started or signalled here; ``make stop-gate`` proves the
real thing against the practice target.
"""

from __future__ import annotations

import io
import json
import signal
import sys
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "lib"))

from sippycup_cockpit import stop  # noqa: E402

CHECKOUT = "/srv/sippycup"
IMAGE = "localhost/sippycup:latest"
OURS = "a" * 64
LEGACY = "b" * 64
OTHER = "c" * 64
PRACTICE = "d" * 64
STRANGER = "e" * 64


def container(ident, name, *, image=IMAGE, labels=None, command=("sippycup-call", "/work/x.yaml")):
    return {"Id": ident, "Names": [name], "Image": image, "Labels": labels or {}, "State": "running",
            "Command": list(command)}


TITLE = {"org.opencontainers.image.title": "sippycup"}


class FakeHost(stop.Host):
    """Containers end after TERM unless listed in ``stubborn`` (then only after KILL)."""

    def __init__(self, containers, processes=(), *, stubborn=(), immortal=(), runtime="podman"):
        super().__init__(Path(CHECKOUT), runtime)
        self.containers = {item["Id"]: item for item in containers}
        self.procs = {item["pid"]: item for item in processes}
        self.stubborn = set(stubborn)
        self.immortal = set(immortal)
        self.signals: list[tuple[str, str]] = []
        self.clock = 0.0
        self.down_calls = 0

    def running_containers(self):
        return list(self.containers.values())

    def container_processes(self, ident):
        return ["/usr/bin/tini -- sippycup-call", "pjsua --config-file /tmp/x"]

    def runtime_call(self, arguments, timeout=60):
        verb, _, name, ident = arguments
        self.signals.append((name, ident))
        if ident not in self.containers:
            return 125, "Error: no such container"
        if ident in self.immortal:
            return 0, ""
        if name == "TERM" and ident not in self.stubborn or name == "KILL":
            self.containers.pop(ident)
        return 0, ""

    def processes(self):
        return list(self.procs.values())

    def alive(self, pid):
        return pid in self.procs

    def kill(self, pid, signum):
        self.signals.append((signal.Signals(signum).name, str(pid)))
        if pid not in self.immortal:
            self.procs.pop(pid, None)

    def practice_down(self):
        self.down_calls += 1
        self.containers.pop(PRACTICE, None)
        return 0, "Removed practice target container ws-practice"

    def sleep(self, seconds):
        self.clock += seconds

    def monotonic(self):
        return self.clock

    def now(self):
        return datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)


def standard_containers():
    return [
        container(OURS, "call-1", labels={**TITLE, stop.CHECKOUT_LABEL: CHECKOUT, stop.COMMAND_LABEL: "call"}),
        container(LEGACY, "old-campaign", labels=dict(TITLE), command=("campaign", "run")),
        container(OTHER, "other-checkout", labels={**TITLE, stop.CHECKOUT_LABEL: "/elsewhere"}),
        container(PRACTICE, "ws-practice", image="localhost/sippycup-practice:latest",
                  labels={stop.PRACTICE_LABEL: "practice"}, command=("asterisk",)),
        container(STRANGER, "postgres", image="docker.io/library/postgres:16", labels={}),
    ]


def run_stop(host, **kwargs):
    kwargs.setdefault("include_practice", False)
    kwargs.setdefault("grace", 5)
    kwargs.setdefault("dry_run", False)
    return stop.stop(host, checkout=CHECKOUT, image=IMAGE, practice_container="ws-practice", **kwargs)


class ClassifyTests(unittest.TestCase):
    def test_only_this_checkout_by_label_or_exact_image(self) -> None:
        ours, practice, untouched = stop.classify(standard_containers(), checkout=CHECKOUT, image=IMAGE,
                                                  practice_container="ws-practice")
        self.assertEqual({OURS: "label", LEGACY: "image (no checkout label: started before stop support)"},
                         {item.ident: item.matched_by for item in ours})
        self.assertEqual(PRACTICE, practice["id"])
        self.assertIn("other-checkout (localhost/sippycup:latest, another checkout)", untouched)
        self.assertFalse([item for item in untouched if "postgres" in item], "unrelated containers are not listed")

    def test_another_practice_target_is_never_ours(self) -> None:
        _, practice, untouched = stop.classify(standard_containers(), checkout=CHECKOUT, image=IMAGE,
                                               practice_container="sippycup-practice")
        self.assertIsNone(practice)
        self.assertIn("ws-practice (another practice target)", untouched)

    def test_host_senders_are_this_checkouts_bin_commands_and_tools_run_here(self) -> None:
        processes = [
            {"pid": 10, "argv": ["python3", f"{CHECKOUT}/bin/campaign", "run"], "uid": 1000, "cwd": "/", "cgroup": ""},
            {"pid": 11, "argv": ["pjsua", "--null-audio"], "uid": 1000, "cwd": f"{CHECKOUT}/work", "cgroup": ""},
            {"pid": 12, "argv": ["pjsua"], "uid": 1000, "cwd": "/home/other", "cgroup": ""},
            {"pid": 13, "argv": ["sipp"], "uid": 1000, "cwd": CHECKOUT, "cgroup": f"0::/libpod-{OURS}.scope"},
            {"pid": 14, "argv": ["python3", "/elsewhere/bin/campaign"], "uid": 1000, "cwd": "/", "cgroup": ""},
            {"pid": 15, "argv": ["python3", f"{CHECKOUT}/bin/sippycup-go"], "uid": 1000, "cwd": "/", "cgroup": ""},
            {"pid": 16, "argv": ["python3", f"{CHECKOUT}/bin/campaign"], "uid": 0, "cwd": "/", "cgroup": ""},
        ]
        found = stop.host_senders(processes, checkout=CHECKOUT, uid=1000, own={99}, container_ids=set())
        self.assertEqual(["10", "11"], [item.ident for item in found])


class StopFlowTests(unittest.TestCase):
    def test_dry_run_signals_nothing(self) -> None:
        host = FakeHost(standard_containers())
        report = run_stop(host, dry_run=True)
        self.assertEqual([], host.signals)
        self.assertEqual(2, len(report.targets))
        lines = "\n".join(stop.render(report, None))
        self.assertIn("would be stopped: SIGTERM, then SIGKILL", lines)
        self.assertIn("untouched ws-practice (the practice target; add --include-practice)", lines)

    def test_clean_stop_terms_first_and_proves_silence(self) -> None:
        host = FakeHost(standard_containers())
        report = run_stop(host)
        self.assertEqual([("TERM", OURS), ("TERM", LEGACY)], host.signals)
        self.assertEqual({"clean": 2}, report.counts())
        self.assertTrue(report.silence["proved"])
        self.assertFalse(report.failed)
        self.assertIn(OTHER, host.containers, "another checkout's container is untouched")
        self.assertIn(PRACTICE, host.containers, "the practice target is untouched")
        self.assertIn(STRANGER, host.containers)
        line = stop.journal_line(report, "work/acme")
        self.assertIn("journal add work/acme --kind action", line)
        self.assertIn("2 Sippycup sender(s) stopped (2 clean, 0 forced, 0 failed); silence verified", line)

    def test_stubborn_sender_is_forced_after_the_grace_period(self) -> None:
        host = FakeHost(standard_containers(), stubborn={OURS})
        report = run_stop(host, grace=3)
        self.assertEqual([("TERM", OURS), ("TERM", LEGACY), ("KILL", OURS)], host.signals)
        outcomes = {item.ident: item.outcome for item in report.targets}
        self.assertEqual({OURS: "forced", LEGACY: "clean"}, outcomes)
        self.assertGreaterEqual(host.clock, 3)
        self.assertTrue(report.silence["proved"])
        self.assertIn("FORCED", "\n".join(stop.render(report, None)))

    def test_unstoppable_sender_fails_and_silence_is_not_proved(self) -> None:
        host = FakeHost(standard_containers(), immortal={OURS})
        report = run_stop(host)
        self.assertEqual("failed", next(item.outcome for item in report.targets if item.ident == OURS))
        self.assertFalse(report.silence["proved"])
        self.assertTrue(report.failed)
        text = "\n".join(stop.render(report, None))
        self.assertIn("Silence: NOT PROVED", text)
        self.assertIn("SILENCE NOT PROVED", stop.journal_line(report, None))

    def test_host_process_is_terminated_then_killed(self) -> None:
        processes = [{"pid": 10, "argv": ["python3", f"{CHECKOUT}/bin/campaign"], "uid": __import__("os").getuid(),
                      "cwd": "/", "cgroup": ""}]
        host = FakeHost([], processes)
        report = run_stop(host)
        self.assertEqual([("SIGTERM", "10")], host.signals)
        self.assertEqual({"clean": 1}, report.counts())

    def test_include_practice_takes_the_target_down_through_practice_target_down(self) -> None:
        host = FakeHost(standard_containers())
        report = run_stop(host, include_practice=True)
        self.assertEqual(1, host.down_calls)
        self.assertEqual("stopped", report.practice["outcome"])
        self.assertNotIn(("TERM", PRACTICE), host.signals, "never signalled directly")
        self.assertTrue(report.silence["proved"])

    def test_without_a_runtime_only_host_processes_are_inspected(self) -> None:
        host = FakeHost([], runtime=None)
        report = run_stop(host)
        self.assertIn("no container runtime found", report.notes[0])

    def test_main_json_and_exit_codes(self) -> None:
        host = FakeHost(standard_containers())
        out = io.StringIO()
        with redirect_stdout(out):
            code = stop.main(["--format", "json", "--engagement", "work/acme"], host=host)
        value = json.loads(out.getvalue())
        self.assertEqual(0, code)
        self.assertTrue(value["ok"] and value["silence"]["proved"] and value["workUntouched"])
        self.assertIn("journal add work/acme", value["journalCommand"])
        host = FakeHost(standard_containers(), immortal={OURS})
        with redirect_stdout(io.StringIO()):
            self.assertEqual(1, stop.main([], host=host))
        with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as raised:
            stop.main(["--grace", "-1"], host=host)
        self.assertEqual(2, raised.exception.code)


if __name__ == "__main__":
    unittest.main()
