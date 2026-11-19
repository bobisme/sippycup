"""bn-3oib: each call gets its own local RTP port, and the run records it.

The oracle side (attribution by the recorded port) is tested in
tests/oracle/test_recorded_media_ports.py; this file covers who chooses the
port and who writes ``call-media.json``, and that the host suite runs the
oracle tests at all.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sippycup import integration  # noqa: E402
from sippycup_oracle.call_media import CALL_MEDIA_VERSION, parse_call_media  # noqa: E402
from sippycup_softphone import SoftphoneCall, SoftphoneError, build_config  # noqa: E402
from sippycup_softphone import campaign_runner  # noqa: E402
from sippycup_softphone.driver import SoftphoneResult  # noqa: E402
from test_guided_call import Fakes, GuidedCallCase  # noqa: E402
from test_softphone_runner import FAKE_PJSUA, step_envelope  # noqa: E402


def softphone_call(directory: Path, **values) -> SoftphoneCall:
    play = directory / "play.wav"
    play.write_bytes(b"RIFF")
    defaults = dict(
        destination="echo", host="192.0.2.10", port=5060, transport="udp",
        play_file=play, record_file=directory / "heard.wav", duration_seconds=2,
        log_file=directory / "softphone.log",
    )
    defaults.update(values)
    return SoftphoneCall(**defaults)


class DriverRtpPortTests(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.directory = Path(self._directory.name)

    def test_default_keeps_pjsua_default_port(self):
        self.assertNotIn("--rtp-port", build_config(softphone_call(self.directory)))

    def test_requested_port_reaches_pjsua(self):
        config = build_config(softphone_call(self.directory, rtp_port=4002))
        self.assertIn("--rtp-port=4002\n", config)

    def test_invalid_ports_are_refused(self):
        for port in (4001, 80, 65535, True, "4000"):
            with self.subTest(port=port), self.assertRaises(SoftphoneError):
                build_config(softphone_call(self.directory, rtp_port=port))


class CampaignStepPortTests(unittest.TestCase):
    def test_each_step_tries_its_own_pair_and_the_pool_wraps(self):
        ports = [campaign_runner.step_rtp_port({"index": index}) for index in range(1, 52)]
        self.assertEqual(ports[:3], [4000, 4002, 4004])
        self.assertEqual(len(set(ports[:50])), 50)
        self.assertEqual(ports[49], 4098)
        self.assertEqual(ports[50], 4000)
        self.assertTrue(all(port % 2 == 0 for port in ports))

    def test_the_runner_passes_the_step_port_to_pjsua(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = root / "steps" / "000002"
            artifacts.mkdir(parents=True, mode=0o700)
            private = root / "private"
            private.mkdir(mode=0o700)
            witness = root / "witness.json"
            lines: list[str] = []
            code = campaign_runner.run(
                step_envelope(artifacts=artifacts),
                pjsua=str(FAKE_PJSUA),
                environ={
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "FAKE_PJSUA_WITNESS": str(witness),
                    "FAKE_PJSUA_MODE": "answer",
                },
                emit=lines.append,
                private_root=private,
            )
            self.assertEqual(code, 0, lines)
            config = json.loads(witness.read_text())["config"]
            self.assertIn("--rtp-port=4002", config)


class CampaignRecordTests(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.run_dir = Path(self._directory.name)

    def plan(self):
        return {"steps": [
            {"index": 1, "destination": {"addresses": ["127.0.0.2"], "port": 5060, "transport": "udp"}},
            {"index": 2, "destination": {"addresses": ["127.0.0.2"], "port": 5061, "transport": "tls"}},
            {"index": 3, "destination": {"addresses": ["127.0.0.2"], "port": 5060, "transport": "udp"}},
        ]}

    def events(self, *rows):
        lines = [
            json.dumps({"event": event, "step": step, "timeUnixNs": at})
            for event, step, at in rows
        ]
        (self.run_dir / "events.jsonl").write_text("\n".join(lines) + "\n")

    def softphone(self, index, port):
        directory = self.run_dir / "steps" / f"{index:06d}"
        directory.mkdir(parents=True)
        (directory / "softphone.json").write_text(json.dumps({"localRtpPort": port}))

    def test_record_lists_each_softphone_step_with_port_and_window(self):
        self.events(
            ("step.started", 1, 10), ("step.succeeded", 1, 20),
            ("step.started", 2, 30), ("step.failed", 2, 40),
        )
        self.softphone(1, 4000)
        self.softphone(2, 4002)
        document = integration.call_media_record(self.run_dir, self.plan(), [1, 2])
        record = parse_call_media(document)
        self.assertEqual(document["schema_version"], CALL_MEDIA_VERSION)
        self.assertTrue(record.complete)
        self.assertEqual(
            [(call.id, call.transport, call.rtp_port) for call in record.calls],
            [("step 1", "udp", 4000), ("step 2", "tls", 4002)],
        )
        self.assertEqual(document["calls"][1]["started_unix_ns"], 30)
        self.assertEqual(document["calls"][1]["ended_unix_ns"], 40)
        self.assertEqual(document["calls"][0]["local_address"], "127.0.0.1")

    def test_a_step_without_a_port_makes_the_record_incomplete(self):
        self.events(("step.started", 1, 10), ("step.succeeded", 1, 20),
                    ("step.started", 3, 30), ("step.cancelled", 3, 40))
        self.softphone(1, 4000)
        document = integration.call_media_record(self.run_dir, self.plan(), [1, 3])
        self.assertFalse(document["complete"])
        self.assertEqual([item["id"] for item in document["calls"]], ["step 1"])

    def test_no_record_without_a_started_softphone_step(self):
        self.events(("step.started", 1, 10), ("step.succeeded", 1, 20))
        self.assertIsNone(integration.call_media_record(self.run_dir, self.plan(), [2]))


class GuidedCallRecordTests(GuidedCallCase):
    def test_call_run_records_its_one_call_before_the_oracle_runs(self):
        fakes = Fakes()
        seen: list[bool] = []
        place = fakes.place_call

        def place_call(call, **kwargs):
            result: SoftphoneResult = place(call, **kwargs)
            result.local_rtp_port = 4002
            return result

        def run_offline(argv, stdout, stderr, environment, original=fakes.run_offline):
            if "--expect" in argv:
                seen.append((Path(argv[1]).parent / "call-media.json").is_file())
            return original(argv, stdout, stderr, environment)

        fakes.place_call = place_call
        fakes.run_offline = run_offline
        code, value = self.run_call(fakes)
        self.assertEqual(code, 0, value)
        self.assertEqual(seen, [True])
        (run_dir,) = self.run_directories()
        record = parse_call_media(json.loads((run_dir / "call-media.json").read_text()))
        self.assertTrue(record.complete)
        (call,) = record.calls
        self.assertEqual((call.id, call.transport, call.local_address, call.rtp_port),
                         ("call", "udp", "10.0.2.100", 4002))


class OracleSuiteDiscoveryTests(unittest.TestCase):
    def test_host_suite_discovers_the_oracle_tests(self):
        # tests/oracle must stay a package: without __init__.py the host
        # suite (`unittest discover -s tests`) silently skips all of it.
        suite = unittest.TestLoader().discover(
            str(ROOT / "tests" / "oracle"), top_level_dir=str(ROOT / "tests")
        )

        def ids(item):
            for test in item:
                if isinstance(test, unittest.TestSuite):
                    yield from ids(test)
                else:
                    yield test.id()

        found = list(ids(suite))
        self.assertGreaterEqual(len(found), 100)
        self.assertTrue(all(name.startswith("oracle.") for name in found), found[:3])
        self.assertTrue(any("test_recorded_media_ports" in name for name in found))


if __name__ == "__main__":
    unittest.main()
