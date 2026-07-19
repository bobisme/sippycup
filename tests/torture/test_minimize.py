import json
from pathlib import Path
import tempfile
import unittest

from sippycup_torture import (
    Authorization,
    CorpusError,
    HierarchicalMinimizer,
    MinimizerLimits,
    Reproducer,
    TrialResult,
)


SOURCE = (
    b"INVITE sip:b@example.invalid SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP 192.0.2.20;branch=z9hG4bK-a\r\n"
    b"X-Noise: removable\r\n"
    b"X-Trigger: CRASH-MARKER\r\n"
    b"Content-Type: application/sdp\r\n"
    b"Content-Length: 25\r\n\r\n"
    b"v=0\r\ns=noise\r\na=trigger\r\n"
)


def authorization():
    return Authorization("192.0.2.10:5060/udp", "pre-dialog", 1, len(SOURCE))


class MinimizerTests(unittest.TestCase):
    def test_composite_failure_reduces_to_exact_subsequence_and_bundle(self):
        source = Reproducer(SOURCE, ("header-order", "trigger-value", "body-noise"), authorization())

        def predicate(candidate):
            failed = b"CRASH-MARKER" in candidate.wire_bytes
            return TrialResult(failed, "process-reset" if failed else "400", (b"frame",))

        minimizer = HierarchicalMinimizer(
            source,
            predicate,
            expected_outcome="no-process-reset",
            command=("sippycup", "torture", "--case", "standalone"),
        )
        result = minimizer.minimize()
        reduced = bytes.fromhex(result["wireHex"])
        self.assertEqual("stable", result["stability"])
        self.assertLess(len(reduced), len(SOURCE))
        self.assertIn(b"CRASH-MARKER", reduced)
        self.assertEqual({"required": 3, "trials": 5}, result["quorum"])

        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "bundle"
            minimizer.write_bundle(destination, result)
            self.assertEqual(reduced, (destination / "reproducer.bin").read_bytes())
            manifest = json.loads((destination / "manifest.json").read_text())
            self.assertEqual("no-process-reset", manifest["expectedOutcome"])
            self.assertTrue(list((destination / "capture-frames").iterdir()))
            self.assertTrue((destination / "reduction-trace.jsonl").read_text())

    def test_flaky_baseline_is_labeled_and_not_minimized(self):
        source = Reproducer(SOURCE, ("trigger",), authorization())
        outcomes = iter((True, False, True, False, True))

        def predicate(candidate):
            failed = next(outcomes)
            return TrialResult(failed, "reset" if failed else "ok")

        minimizer = HierarchicalMinimizer(
            source,
            predicate,
            expected_outcome="ok",
            command=("sippycup", "torture"),
        )
        result = minimizer.minimize()
        self.assertEqual("flaky", result["stability"])
        self.assertEqual(SOURCE, bytes.fromhex(result["wireHex"]))
        self.assertEqual(1, result["trafficUsed"]["candidateTests"])

    def test_non_reproducing_source_fails_closed(self):
        source = Reproducer(SOURCE, (), authorization())
        minimizer = HierarchicalMinimizer(
            source,
            lambda candidate: TrialResult(False, "ok"),
            expected_outcome="ok",
            command=("sippycup", "torture"),
        )
        with self.assertRaisesRegex(CorpusError, "does not meet"):
            minimizer.minimize()

    def test_authorization_and_limits_are_immutable_and_bounded(self):
        with self.assertRaises(CorpusError):
            Authorization("", "pre-dialog", 1, 10)
        with self.assertRaises(CorpusError):
            MinimizerLimits(trials=5, quorum=6)
        with self.assertRaises(CorpusError):
            MinimizerLimits(max_candidates=1000)

    def test_predicate_cannot_smuggle_new_bytes_dimensions_or_scope(self):
        source = Reproducer(SOURCE, ("known",), authorization())
        minimizer = HierarchicalMinimizer(
            source,
            lambda candidate: TrialResult(True, "reset"),
            expected_outcome="ok",
            command=("tool",),
        )
        with self.assertRaisesRegex(CorpusError, "introduce"):
            minimizer._test(
                Reproducer(SOURCE + b"new", ("unknown",), authorization()),
                "adversarial",
            )

    def test_total_retest_budget_stops_reduction(self):
        source = Reproducer(SOURCE, ("trigger",), authorization())
        limits = MinimizerLimits(max_total_packets=5, max_total_bytes=len(SOURCE) * 5)
        minimizer = HierarchicalMinimizer(
            source,
            lambda candidate: TrialResult(True, "reset"),
            limits=limits,
            expected_outcome="ok",
            command=("tool",),
        )
        result = minimizer.minimize()
        self.assertEqual(SOURCE, bytes.fromhex(result["wireHex"]))
        self.assertLessEqual(result["trafficUsed"]["reservedPackets"], 5)

    def test_saved_command_redacts_secret_bearing_arguments(self):
        source = Reproducer(SOURCE, (), authorization())
        minimizer = HierarchicalMinimizer(
            source,
            lambda candidate: TrialResult(True, "reset"),
            expected_outcome="ok",
            command=("tool", "--password", "hunter2", "--token=abc"),
        )
        result = minimizer.minimize()
        self.assertEqual(
            ["tool", "--password", "<redacted>", "--token=<redacted>"],
            result["command"],
        )


if __name__ == "__main__":
    unittest.main()
