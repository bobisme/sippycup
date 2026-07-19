import json
from pathlib import Path
import signal
import unittest

from tools.chaos_exit_gate import _Cancellation, _parse_ping
from tests.test_chaos_lifecycle import _FakeBackend, _plans, _run


ROOT = Path(__file__).resolve().parents[1]


class FinalIntegrationContractTests(unittest.TestCase):
    def test_chaos_gate_cancellation_reaches_active_lifecycle(self):
        class FakeLifecycle:
            def __init__(self):
                self.signals = []

            def cancel(self, signum):
                self.signals.append(signum)

        cancellation = _Cancellation()
        lifecycle = FakeLifecycle()
        cancellation.active = lifecycle
        cancellation.request(signal.SIGINT)
        cancellation.request(signal.SIGTERM)
        self.assertEqual(signal.SIGINT, cancellation.signum)
        self.assertEqual([signal.SIGINT, signal.SIGTERM], lifecycle.signals)
        topology, plan = _plans()
        real = __import__(
            "sippycup_chaos.lifecycle", fromlist=["ChaosLifecycle"]
        ).ChaosLifecycle(topology, plan)
        self.assertTrue(callable(real.cancel))

    def test_base_exception_during_traffic_start_still_restores_topology(self):
        class InterruptBackend(_FakeBackend):
            def popen(self, argv):
                if argv[0] == "pasta":
                    return super().popen(argv)
                raise KeyboardInterrupt()

        topology, plan = _plans()
        backend = InterruptBackend()
        report = _run(topology, plan, backend)
        self.assertEqual("failed", report["state"])
        self.assertTrue(report["cleanup"]["restored"])
        self.assertEqual(set(), backend.namespaces)
        self.assertEqual({}, backend.qdiscs)
        self.assertEqual({}, backend.links)

    def test_cancelled_gate_tolerates_absent_partial_observation(self):
        missing = _parse_ping(ROOT / "work" / "does-not-exist.txt")
        self.assertFalse(missing["measurable"])
        self.assertIn("was not produced", missing["reason"])

    def test_host_wrapper_owns_background_cleanup_and_container_identity(self):
        source = (ROOT / "bin" / "chaos-exit-gate").read_text()
        for contract in (
            'realpath -m -- "${1:-',
            "trap cleanup EXIT",
            "trap 'exit 130' INT",
            "trap 'exit 143' TERM",
            "--cidfile=",
            '"${project_dir}/bin/container-runtime"',
            '"${runtime}" stop --time 5',
            'kill -INT "${heartbeat_pid}"',
        ):
            self.assertIn(contract, source)

    def test_container_context_excludes_runtime_and_secret_material(self):
        patterns = (ROOT / ".containerignore").read_text().splitlines()
        for required in (
            ".git", ".bones", "work", "config/target.env",
            "**/__pycache__", "**/*.pyc", "*.pcap", "*.pcapng",
        ):
            self.assertIn(required, patterns)

    def test_chaos_exit_report_schema_is_strict_and_versioned(self):
        schema = json.loads(
            (ROOT / "schemas" / "chaos-exit-gate-v1.schema.json").read_text()
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            "sippycup.dev/chaos-exit-gate/v1",
            schema["properties"]["apiVersion"]["const"],
        )
        self.assertTrue(
            {
                "controllerSnapshotBeforeSha256",
                "controllerSnapshotAfterSha256",
                "controllerRestored",
                "profiles",
                "failures",
                "passed",
            }.issubset(schema["required"])
        )

    def test_full_gate_includes_real_host_isolation(self):
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("full-gate: campaign-gate chaos-exit-gate", makefile)


if __name__ == "__main__":
    unittest.main()
