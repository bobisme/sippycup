import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

from sippycup_torture import (
    ActionResult,
    CorpusError,
    RunnerCallbacks,
    RunnerError,
    RunnerLimits,
    TortureRunner,
    build_corpus,
)


def ok_action(label, evidence=b"clean-canary"):
    def action(case, context):
        state = case.dialog_state if label == "dialog-ready" else None
        return ActionResult(True, label, (evidence,), dialog_state=state)
    return action


def exact_mutation(case, context):
    lengths = case.packet_lengths or (len(case.wire_bytes),)
    packets = []
    offset = 0
    for length in lengths:
        packets.append(case.wire_bytes[offset : offset + length])
        offset += length
    return ActionResult(True, "exact-bytes-sent", tuple(packets), tuple(packets))


def acceptable(case, context):
    return ActionResult(True, case.expected_outcomes[0], (b"response",))


class RunnerTests(unittest.TestCase):
    def callbacks(self, **overrides):
        values = {
            "establish": ok_action("dialog-ready"),
            "inject": exact_mutation,
            "classify": acceptable,
            "recovery": ok_action("clean-call-passed"),
            "health": lambda: True,
            "metrics_within_threshold": lambda: True,
        }
        values.update(overrides)
        return RunnerCallbacks(**values)

    def runner(self, directory, **kwargs):
        return TortureRunner(
            build_corpus()[:2],
            kwargs.pop("callbacks", self.callbacks()),
            Path(directory) / "evidence",
            limits=kwargs.pop("limits", RunnerLimits(max_cases=2)),
            **kwargs,
        )

    def test_dry_run_is_exact_and_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = self.runner(tmp).dry_run()
        self.assertEqual(2, len(plan["cases"]))
        self.assertEqual(
            sum(item["mutationPackets"] for item in plan["cases"]),
            plan["selectedMutationTraffic"]["packets"],
        )
        self.assertEqual(1, plan["maximumTraffic"]["concurrency"])

    def test_run_preserves_exact_mutations_and_labels_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.runner(tmp)
            result = runner.run()
            evidence = Path(tmp) / "evidence"
            events = [json.loads(line) for line in (evidence / "events.jsonl").read_text().splitlines()]
            self.assertEqual("completed", result["state"])
            classes = {event.get("trafficClass") for event in events}
            self.assertTrue({"mutation", "baseline-establish", "baseline-recovery"} <= classes)
            for index, case in enumerate(build_corpus()[:2]):
                path = evidence / f"{index:03d}-{case.id}-mutation-source.bin"
                self.assertEqual(case.wire_bytes, path.read_bytes())

    def test_failed_recovery_stops_before_second_case(self):
        calls = []

        def recovery(case, context):
            calls.append(case.id)
            return ActionResult(False, "clean-call-failed")

        with tempfile.TemporaryDirectory() as tmp:
            result = self.runner(tmp, callbacks=self.callbacks(recovery=recovery)).run()
        self.assertEqual("recovery-canary-failed", result["reason"])
        self.assertEqual(1, result["counters"]["cases"])
        self.assertEqual(1, len(calls))

    def test_wrong_dialog_state_fails_before_injection(self):
        injected = []

        def establish(case, context):
            return ActionResult(True, "dialog-ready", dialog_state="wrong-state")

        def inject(case, context):
            injected.append(case.id)
            return exact_mutation(case, context)

        with tempfile.TemporaryDirectory() as tmp:
            result = self.runner(
                tmp,
                callbacks=self.callbacks(establish=establish, inject=inject),
            ).run()
        self.assertEqual("dialog-establishment-failed", result["reason"])
        self.assertEqual([], injected)

    def test_injector_must_attest_exact_packet_boundaries(self):
        wrong = lambda case, context: ActionResult(
            True, "sent", sent_packets=(case.wire_bytes + b"x",)
        )
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RunnerError, "exact case packet bytes"):
                self.runner(tmp, callbacks=self.callbacks(inject=wrong)).run()

    def test_unacceptable_classification_counts_as_failure_then_recovers(self):
        unexpected = lambda case, context: ActionResult(True, "made-up-outcome")
        with tempfile.TemporaryDirectory() as tmp:
            result = self.runner(
                tmp,
                callbacks=self.callbacks(classify=unexpected),
                limits=RunnerLimits(max_cases=2, max_failures=1),
            ).run()
        self.assertEqual("failure-ceiling-reached", result["reason"])
        self.assertEqual(1, result["counters"]["cases"])

    def test_operator_health_metrics_and_duration_stop_before_mutation(self):
        cases = (
            ("operator-stop", {"stop_event": self._set_event()}),
            ("health-check-failed", {"callbacks": self.callbacks(health=lambda: False)}),
            (
                "server-metric-threshold",
                {"callbacks": self.callbacks(metrics_within_threshold=lambda: False)},
            ),
            (
                "duration-ceiling-reached",
                {"monotonic": iter((0.0, 31.0)).__next__},
            ),
        )
        for expected, options in cases:
            with self.subTest(expected), tempfile.TemporaryDirectory() as tmp:
                result = self.runner(tmp, **options).run()
                self.assertEqual(expected, result["reason"])
                self.assertEqual(0, result["counters"]["cases"])

    def test_timeout_halts_and_requests_cancellation(self):
        cancelled = threading.Event()

        def blocked(case, context):
            while not context.cancel.is_set():
                time.sleep(0.001)
            cancelled.set()
            return ActionResult(False, "cancelled")

        limits = RunnerLimits(max_cases=1, action_timeout_s=0.01)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RunnerError, "timed out"):
                self.runner(tmp, callbacks=self.callbacks(inject=blocked), limits=limits).run()
        self.assertTrue(cancelled.wait(0.1))

    def test_failure_ceiling_halts_after_clean_recovery(self):
        failed = lambda case, context: ActionResult(False, "unexpected-response")
        with tempfile.TemporaryDirectory() as tmp:
            result = self.runner(
                tmp,
                callbacks=self.callbacks(classify=failed),
                limits=RunnerLimits(max_cases=2, max_failures=1),
            ).run()
        self.assertEqual("failure-ceiling-reached", result["reason"])
        self.assertEqual(1, result["counters"]["cases"])

    def test_frozen_hard_caps_and_traffic_caps_fail_closed(self):
        with self.assertRaises(CorpusError):
            RunnerLimits(max_concurrency=2)
        with self.assertRaises(CorpusError):
            RunnerLimits(max_rate_hz=float("nan"))
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.runner(tmp, limits=RunnerLimits(max_cases=2, max_packets=1))
            with self.assertRaisesRegex(RunnerError, "traffic ceilings"):
                runner.run()

    @staticmethod
    def _set_event():
        event = threading.Event()
        event.set()
        return event


if __name__ == "__main__":
    unittest.main()
