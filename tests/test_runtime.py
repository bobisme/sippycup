from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup.campaign import compile_plan
from sippycup.runtime import (
    CampaignSupervisor,
    EVENT_API_VERSION,
    EXIT_FAILED,
    EXIT_SIGINT,
    EXIT_SIGTERM,
    EXIT_SUCCESS,
    EXIT_TIMEOUT,
    EventWriter,
    MAX_STEP_INPUT_BYTES,
    RuntimeError,
    run_plan,
)


FIXTURES = ROOT / "tests" / "fixtures" / "campaign"
RUNNER = FIXTURES / "fake-runner.py"
NON_READER = FIXTURES / "non-reading-runner.py"
RUNTIME_DRIVER = FIXTURES / "runtime-driver.py"
SEQUENTIAL_RUNNER = FIXTURES / "sequential-runner.py"


class _NullEventWriter:
    def emit(self, *_args, **_kwargs):
        pass


def make_plan(*modes: str) -> dict:
    raw = (FIXTURES / "valid.yaml").read_bytes()
    manifest = yaml.safe_load(raw)
    manifest["cases"] = [copy.deepcopy(manifest["cases"][0]) for _ in modes]
    for index, (case, mode) in enumerate(zip(manifest["cases"], modes), 1):
        case["id"] = f"{mode}-{index}"
        case["expectations"] = {
            "apiVersion": "sippycup.dev/case-expectations/v1",
            "finalStatus": 200,
        }
        case["budget"]["durationSecondsPerRun"] = 1
    manifest["authorization"]["ceilings"]["packets"] = 1000
    manifest["authorization"]["ceilings"]["bytes"] = 1_000_000
    manifest["authorization"]["ceilings"]["durationSeconds"] = max(2, len(modes) + 1)
    return compile_plan(
        manifest,
        "a" * 64,
        resolver=lambda _host: ["10.20.30.40"],
    )


def read_events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


class RuntimeTests(unittest.TestCase):
    def execute(self, plan, *, runner=None, output_limit=256 * 1024):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        events = Path(temporary.name) / "events.jsonl"
        result = run_plan(
            plan,
            runner or [sys.executable, str(RUNNER)],
            events,
            grace_seconds=0.1,
            output_limit=output_limit,
        )
        return result, read_events(events)

    def test_success_event_order_matches_golden_and_schema_contract(self):
        result, events = self.execute(make_plan("success"))
        self.assertEqual(result.exit_code, EXIT_SUCCESS)
        projected = [[event["event"], event["state"]] for event in events]
        golden = json.loads((FIXTURES / "success-events.golden.json").read_text())
        self.assertEqual(projected, golden)
        self.assertEqual(
            [event["sequence"] for event in events],
            list(range(1, len(events) + 1)),
        )
        for event in events:
            self.assertEqual(event["apiVersion"], EVENT_API_VERSION)
            self.assertIsInstance(event["timeUnixNs"], int)
            self.assertEqual(event["campaign"], "baseline-call")
            _assert_event_matches_schema(self, event)

    def test_child_failure_stops_before_next_step(self):
        result, events = self.execute(make_plan("crash", "success"))
        self.assertEqual(result.exit_code, EXIT_FAILED)
        self.assertEqual(
            [event["event"] for event in events if event["event"] == "step.started"],
            ["step.started"],
        )
        failure = next(event for event in events if event["event"] == "step.failed")
        self.assertEqual(failure["exitCode"], 17)
        self.assertEqual(events[-1]["event"], "campaign.failed")

    def test_partial_startup_is_a_deterministic_failure(self):
        result, events = self.execute(
            make_plan("success"), runner=["/definitely/not/a/runner"]
        )
        self.assertEqual(result.exit_code, EXIT_FAILED)
        self.assertEqual(
            [event["event"] for event in events],
            ["campaign.started", "step.started", "step.start_failed", "campaign.failed"],
        )

    def test_timeout_stops_the_whole_process_group(self):
        result, events = self.execute(make_plan("spawn"))
        self.assertEqual(result.exit_code, EXIT_TIMEOUT)
        output = next(event for event in events if event["event"] == "step.output")
        grandchild_pid = int(output["text"].strip())
        self.assertIn("step.timed_out", [event["event"] for event in events])
        self.assertEqual(events[-1]["event"], "campaign.timed_out")
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline and _process_is_running(grandchild_pid):
            time.sleep(0.01)
        self.assertFalse(_process_is_running(grandchild_pid))

    def test_leader_exit_does_not_escape_descendant_cleanup(self):
        result, events = self.execute(make_plan("leader-first"))
        self.assertEqual(result.exit_code, EXIT_SUCCESS)
        child_pid = int(
            next(event for event in events if event["event"] == "step.output")[
                "text"
            ].strip()
        )
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline and _process_is_running(child_pid):
            time.sleep(0.01)
        self.assertFalse(_process_is_running(child_pid))

    def test_successful_step_group_is_empty_before_next_step_starts(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        state = root / "descendant.pid"
        result = run_plan(
            make_plan("success", "success"),
            [sys.executable, str(SEQUENTIAL_RUNNER), str(state)],
            root / "events.jsonl",
            grace_seconds=0.1,
        )
        self.assertEqual(result.exit_code, EXIT_SUCCESS)
        self.assertFalse(_process_is_running(int(state.read_text())))

    def test_non_reading_runner_cannot_block_deadline_or_cancellation(self):
        plan = make_plan("success")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "events.jsonl"
        started = time.monotonic()
        result = run_plan(
            plan,
            [sys.executable, str(NON_READER)],
            path,
            output_limit=0,
            grace_seconds=0.1,
            runner_input=lambda _step: b"x" * MAX_STEP_INPUT_BYTES,
        )
        self.assertEqual(result.exit_code, EXIT_TIMEOUT)
        self.assertLess(time.monotonic() - started, 2.5)
        events = read_events(path)
        self.assertIn("step.timed_out", [event["event"] for event in events])

    def test_sensitive_output_is_redacted_before_persistence(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "events.jsonl"
        result = run_plan(
            make_plan("sensitive"),
            [sys.executable, str(RUNNER)],
            path,
            redactions=["fixture-super-secret"],
        )
        self.assertEqual(result.exit_code, EXIT_SUCCESS)
        persisted = path.read_text()
        self.assertNotIn("deadbeef", persisted)
        self.assertNotIn("fixture-super-secret", persisted)
        self.assertIn("<redacted>", persisted)

    def test_untrusted_output_is_drained_but_bounded(self):
        result, events = self.execute(make_plan("output"), output_limit=8192)
        self.assertEqual(result.exit_code, EXIT_SUCCESS)
        outputs = [event for event in events if event["event"] == "step.output"]
        self.assertLessEqual(
            sum(len(event["text"].encode()) for event in outputs),
            8192,
        )
        truncated = next(
            event for event in events if event["event"] == "step.output_truncated"
        )
        self.assertEqual(truncated["retainedBytes"], 8192)
        self.assertGreater(truncated["droppedBytes"], 0)

    def test_cleanup_is_idempotent(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        with EventWriter(Path(temporary.name) / "events.jsonl", "test") as writer:
            supervisor = CampaignSupervisor(
                make_plan("success"),
                [sys.executable, str(RUNNER)],
                writer,
            )
            supervisor.cleanup()
            supervisor.cleanup()

    def test_cleanup_registry_is_bounded_lifo_and_rolls_back_partial_start(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        order = []
        with EventWriter(Path(temporary.name) / "events.jsonl", "test") as writer:
            supervisor = CampaignSupervisor(
                make_plan("success"),
                ["/definitely/not/a/runner"],
                writer,
            )
            supervisor.register_cleanup("first", lambda: order.append("first"))
            supervisor.register_cleanup("second", lambda: order.append("second"))
            result = supervisor.run()
        self.assertEqual(result.exit_code, EXIT_FAILED)
        self.assertEqual(order, ["second", "first"])

        with EventWriter(Path(temporary.name) / "bounded.jsonl", "test") as writer:
            bounded = CampaignSupervisor(
                make_plan("success"),
                ["/definitely/not/a/runner"],
                writer,
            )
            for index in range(64):
                bounded.register_cleanup(str(index), lambda: None)
            with self.assertRaisesRegex(RuntimeError, "limited"):
                bounded.register_cleanup("overflow", lambda: None)
            bounded.cleanup()

    def test_unsafe_grace_and_reserved_event_fields_are_rejected(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        for value in (float("nan"), float("inf"), -1):
            with self.subTest(value=value), EventWriter(
                Path(temporary.name) / f"{len(list(Path(temporary.name).iterdir()))}.jsonl",
                "test",
            ) as writer:
                with self.assertRaisesRegex(RuntimeError, "finite"):
                    CampaignSupervisor(
                        make_plan("success"),
                        [sys.executable, str(RUNNER)],
                        writer,
                        grace_seconds=value,
                    )
        with EventWriter(Path(temporary.name) / "collision.jsonl", "test") as writer:
            with self.assertRaisesRegex(RuntimeError, "reserved"):
                writer.emit("step.started", "running", sequence=99)

    def test_runner_input_has_a_hard_size_limit(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "events.jsonl"
        result = run_plan(
            make_plan("success"),
            [sys.executable, str(RUNNER)],
            path,
            runner_input=lambda _step: b"x" * (MAX_STEP_INPUT_BYTES + 1),
        )
        self.assertEqual(result.exit_code, EXIT_FAILED)
        self.assertIn("byte limit", path.read_text())

    def test_handwritten_unsafe_plans_are_rejected(self):
        base = make_plan("success")
        mutations = [
            lambda plan: plan["metadata"].update({"manifestSha256": "z" * 64}),
            lambda plan: plan["authorization"]["transports"].append("UDP"),
            lambda plan: plan["authorization"]["signalingPorts"].append(5060),
            lambda plan: plan["resolvedDestinations"][0].update(
                {"address": "203.0.113.1"}
            ),
            lambda plan: plan["plannedTotals"].update({"packets": 0}),
            lambda plan: plan["evidence"].update({"directory": "../escape"}),
            lambda plan: plan.update({"captureFilter": "ip"}),
            lambda plan: plan["steps"][0].update({"type": "CALL"}),
            lambda plan: plan.update({"unexpected": True}),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                plan = copy.deepcopy(base)
                mutation(plan)
                with self.assertRaises(RuntimeError):
                    CampaignSupervisor(
                        plan,
                        [sys.executable, str(RUNNER)],
                        _NullEventWriter(),
                    )


class RuntimeSignalTests(unittest.TestCase):
    def test_sigint_and_sigterm_have_stable_exit_status_and_events(self):
        for signum, expected_code in (
            (signal.SIGINT, EXIT_SIGINT),
            (signal.SIGTERM, EXIT_SIGTERM),
        ):
            with self.subTest(signal=signum), tempfile.TemporaryDirectory() as directory:
                plan_path = Path(directory) / "plan.json"
                events_path = Path(directory) / "events.jsonl"
                plan_path.write_text(json.dumps(make_plan("sleep")))
                process = subprocess.Popen(
                    [
                        sys.executable,
                        str(RUNTIME_DRIVER),
                        str(plan_path),
                        str(events_path),
                        sys.executable,
                        str(RUNNER),
                    ],
                    cwd=ROOT,
                )
                _wait_for_event(events_path, "step.started")
                process.send_signal(signum)
                self.assertEqual(process.wait(timeout=3), expected_code)
                events = read_events(events_path)
                stop = next(
                    event
                    for event in events
                    if event["event"] == "campaign.stop_requested"
                )
                self.assertEqual(stop["state"], "stopping")
                self.assertIn("step.cancelled", [event["event"] for event in events])
                self.assertEqual(events[-1]["event"], "campaign.cancelled")
                self.assertEqual(
                    events[-1]["signal"],
                    signal.Signals(signum).name,
                )


def _wait_for_event(path: Path, name: str) -> None:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if path.exists() and name in path.read_text():
            return
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {name}")


def _process_is_running(pid: int) -> bool:
    try:
        state = Path(f"/proc/{pid}/stat").read_text().split()[2]
    except (FileNotFoundError, ProcessLookupError):
        return False
    return state != "Z"


def _assert_event_matches_schema(test: unittest.TestCase, event: dict) -> None:
    schema = json.loads((ROOT / "schemas" / "events-v1.schema.json").read_text())
    test.assertTrue(set(schema["required"]).issubset(event))
    branches = schema["allOf"][0]["oneOf"]
    matches = [
        branch
        for branch in branches
        if branch["properties"]["event"]["const"] == event["event"]
        and branch["properties"]["state"]["const"] == event["state"]
        and set(branch["required"]).issubset(event)
    ]
    test.assertEqual(len(matches), 1, event)


if __name__ == "__main__":
    unittest.main()
