import json
from pathlib import Path
import socket
import tempfile
import unittest

from sippycup_torture import (
    ActionResult,
    Authorization,
    HierarchicalMinimizer,
    MinimizerLimits,
    Reproducer,
    RunnerCallbacks,
    RunnerLimits,
    TortureRunner,
    TrialResult,
    build_corpus,
    corpus_manifest,
    exact_injector,
)


class TortureExitGate(unittest.TestCase):
    def test_every_case_crosses_isolated_datagram_endpoint_bit_exactly(self):
        cases = build_corpus()
        expected_packets = []
        for case in cases:
            lengths = case.packet_lengths or (len(case.wire_bytes),)
            offset = 0
            for length in lengths:
                expected_packets.append(case.wire_bytes[offset : offset + length])
                offset += length

        client, endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(client.close)
        self.addCleanup(endpoint.close)

        callbacks = RunnerCallbacks(
            establish=lambda case, context: ActionResult(
                True, "dialog-ready", (b"clean-establish",), dialog_state=case.dialog_state
            ),
            inject=exact_injector(client.send),
            classify=lambda case, context: ActionResult(
                True, case.expected_outcomes[0], (b"reference-response",)
            ),
            recovery=lambda case, context: ActionResult(
                True, "clean-call-passed", (b"clean-recovery",)
            ),
        )
        limits = RunnerLimits(
            max_cases=len(cases),
            max_packets=len(expected_packets),
            max_bytes=sum(map(len, expected_packets)),
            max_rate_hz=10,
            max_duration_s=60,
        )
        with tempfile.TemporaryDirectory() as tmp:
            result = TortureRunner(
                cases,
                callbacks,
                Path(tmp) / "evidence",
                limits=limits,
                sleeper=lambda delay: None,
            ).run()
            endpoint.settimeout(0.1)
            received = [endpoint.recv(4096) for _ in expected_packets]
            self.assertEqual(expected_packets, received)
            self.assertEqual("completed", result["state"])
            events = [
                json.loads(line)
                for line in (Path(tmp) / "evidence" / "events.jsonl").read_text().splitlines()
            ]
            classifications = [
                event for event in events
                if event.get("trafficClass") == "observation"
            ]
            self.assertEqual(len(cases), len(classifications))
            self.assertTrue(all(event["ok"] for event in classifications))

    def test_deliberately_fragile_endpoint_fails_recovery_and_stops(self):
        cases = build_corpus()[:2]
        injections = []
        recoveries = 0

        def inject(case, context):
            injections.append(case.id)
            lengths = case.packet_lengths or (len(case.wire_bytes),)
            packets = []
            offset = 0
            for length in lengths:
                packets.append(case.wire_bytes[offset : offset + length])
                offset += length
            return ActionResult(True, "fragile-endpoint-reset", tuple(packets), tuple(packets))

        def recovery(case, context):
            nonlocal recoveries
            recoveries += 1
            return ActionResult(False, "clean-canary-failed")

        callbacks = RunnerCallbacks(
            establish=lambda case, context: ActionResult(
                True, "ready", dialog_state=case.dialog_state
            ),
            inject=inject,
            classify=lambda case, context: ActionResult(
                True, case.expected_outcomes[0]
            ),
            recovery=recovery,
        )
        with tempfile.TemporaryDirectory() as tmp:
            result = TortureRunner(
                cases,
                callbacks,
                Path(tmp) / "evidence",
                limits=RunnerLimits(max_cases=2),
            ).run()
        self.assertEqual("recovery-canary-failed", result["reason"])
        self.assertEqual(1, recoveries)
        self.assertEqual(1, len(injections))

    def test_injected_health_failure_stops_without_mutation(self):
        injected = []
        case = build_corpus()[0]
        callbacks = RunnerCallbacks(
            establish=lambda case, context: ActionResult(
                True, "ready", dialog_state=case.dialog_state
            ),
            inject=lambda case, context: injected.append(case.id),
            classify=lambda case, context: ActionResult(True, case.expected_outcomes[0]),
            recovery=lambda case, context: ActionResult(True, "recovered"),
            health=lambda: False,
        )
        with tempfile.TemporaryDirectory() as tmp:
            result = TortureRunner((case,), callbacks, Path(tmp) / "evidence").run()
        self.assertEqual("health-check-failed", result["reason"])
        self.assertEqual([], injected)

    def test_seeded_composite_failure_reduces_reliably_and_replays_offline(self):
        source_bytes = (
            b"INVITE sip:test@example.invalid SIP/2.0\r\n"
            b"X-Noise: remove-me\r\n"
            b"X-Trigger: SEEDED-RESET\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        auth = Authorization("192.0.2.10:5060/udp", "pre-dialog", 1, len(source_bytes))
        source = Reproducer(source_bytes, ("noise", "seeded-trigger"), auth)

        def endpoint(candidate):
            failed = b"SEEDED-RESET" in candidate.wire_bytes
            return TrialResult(failed, "reset" if failed else "accepted", (b"pcap-frame",))

        minimizer = HierarchicalMinimizer(
            source,
            endpoint,
            limits=MinimizerLimits(max_candidates=32),
            expected_outcome="accepted-or-rejected-without-reset",
            command=("sippycup-torture", "replay", "--authorization", "secret"),
        )
        result = minimizer.minimize()
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            minimizer.write_bundle(bundle, result)
            manifest = json.loads((bundle / "manifest.json").read_text())
            replay = (bundle / "reproducer.bin").read_bytes()
        self.assertEqual("stable", manifest["stability"])
        self.assertLess(len(replay), len(source_bytes))
        self.assertIn(b"SEEDED-RESET", replay)
        self.assertEqual("<redacted>", manifest["command"][-1])
        self.assertTrue(endpoint(Reproducer(replay, (), auth)).failed)

    def test_corpus_contract_excludes_credential_reflection_and_load_behavior(self):
        manifest = corpus_manifest()
        self.assertFalse(manifest["safety"]["credentialGuessing"])
        self.assertFalse(manifest["safety"]["spoofedReflection"])
        self.assertFalse(manifest["safety"]["unboundedAmplification"])
        self.assertLessEqual(manifest["safety"]["maxCasePackets"], 3)
        for case in build_corpus():
            lowered = case.wire_bytes.lower()
            self.assertNotIn(b"authorization:", lowered)
            self.assertNotIn(b"proxy-authorization:", lowered)


if __name__ == "__main__":
    unittest.main()
