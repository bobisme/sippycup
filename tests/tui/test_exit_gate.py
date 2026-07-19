import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from sippycup_tui.app import KEYS, MissionApp
from sippycup_tui.controls import ActionController


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "tui" / "fixtures" / "replay.jsonl"


class FakeAPI:
    def __init__(self):
        self.calls = []
    def start(self): self.calls.append("start-one-call")
    def pause_new_calls(self): self.calls.append("pause")
    def graceful_stop(self): self.calls.append("graceful-stop")
    def emergency_stop(self): self.calls.append("emergency-stop")
    def skip_current(self): self.calls.append("skip")


class TuiExitGate(unittest.TestCase):
    def test_first_time_loopback_walkthrough_using_only_help(self):
        api = FakeAPI()
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            controller = ActionController(api, run)
            app = MissionApp(controller)
            app.key("?")
            help_text = app.render(width=100, height=30)
            for key, action in KEYS.items():
                self.assertIn(key, help_text)
            app.key("?")

            app.ingest({
                "schema": "sippycup.ui-event/v1", "sequence": 1,
                "source": "walkthrough", "kind": "plan.ready",
                "payload": {
                    "authorization": "loopback only", "plannedCases": 1,
                    "capturePath": "capture.pcapng", "reportPath": "report/index.html",
                },
            })
            app.drain()
            app.key("s", confirmed=True)
            app.ingest({
                "schema": "sippycup.ui-event/v1", "sequence": 2,
                "source": "walkthrough", "kind": "run.started",
                "payload": {
                    "rtp": {
                        "caller->callee": {"value": "160 packets", "status": "good"},
                        "callee->caller": {"value": "159 packets", "status": "good"},
                    },
                    "capture": {"value": "active", "status": "good"},
                },
            })
            app.drain()
            app.key("b", text="both RTP directions visible", evidence="capture.pcapng#20")
            app.key("x")
            app.ingest({
                "schema": "sippycup.ui-event/v1", "sequence": 3,
                "source": "walkthrough", "kind": "run.completed",
                "payload": {
                    "capture": {"value": "closed", "status": "good"},
                    "reportPath": "report/index.html",
                },
            })
            app.drain()
            screen = app.render(width=100, height=30)
            record = app.snapshot().as_json_record()
            notes = [json.loads(line) for line in (run / "notes.jsonl").read_text().splitlines()]

        self.assertEqual(["start-one-call", "graceful-stop"], api.calls)
        self.assertIn("caller->callee", screen)
        self.assertIn("callee->caller", screen)
        self.assertIn("report/index.html", screen)
        self.assertEqual("bookmark", notes[0]["kind"])
        self.assertEqual("complete", record["phase"])

    def test_sigint_style_close_lost_child_and_malformed_event_preserve_state(self):
        api = FakeAPI()
        with tempfile.TemporaryDirectory() as tmp:
            app = MissionApp(ActionController(api, Path(tmp)))
            app.ingest("\x1b[31mnot json")
            app.ingest({
                "apiVersion": "sippycup.dev/events/v1", "sequence": 1,
                "campaign": "loopback", "event": "campaign.failed", "state": "failed",
                "completedSteps": 0,
            })
            app.drain()
            app.close()
            app.close()
            snapshot = app.snapshot()
        self.assertEqual("failed", snapshot.state.phase)
        self.assertEqual(1, snapshot.state.schema_errors)
        self.assertEqual(["graceful-stop"], api.calls)

    def test_heavy_tool_output_stays_bounded_and_input_responsive(self):
        app = MissionApp(capacity=8)
        start = time.monotonic()
        for sequence in range(1, 50001):
            accepted = app.ingest({
                "apiVersion": "sippycup.dev/events/v1", "sequence": sequence,
                "campaign": "load", "event": "step.output", "state": "running",
                "step": 1, "stream": "stdout", "text": "x" * 4096,
            })
            self.assertTrue(accepted)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 3.0)
        self.assertEqual(0, app.drain())
        app.key("?")
        self.assertTrue(app.snapshot().help_visible)

    def test_resize_snapshots_and_screen_reader_json_are_complete(self):
        app = MissionApp()
        for line in FIXTURE.read_text().splitlines():
            app.ingest(line)
        app.drain()
        for width, height in ((40, 10), (60, 16), (100, 30), (160, 50)):
            output = app.render(width=width, height=height)
            self.assertLessEqual(len(output.splitlines()), height)
            self.assertTrue(all(len(line) <= width for line in output.splitlines()))
        record = app.snapshot().as_json_record()
        for field in ("schema", "phase", "actions", "model", "keyBindings", "guidance"):
            self.assertIn(field, record)
        self.assertIn("trafficStart", record["guidance"])
        self.assertIn("artifacts", record["guidance"])

    def test_non_tty_cli_defaults_to_json_and_malformed_is_nonzero(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "sippycup-ui"), str(FIXTURE)],
            cwd=ROOT, text=True, capture_output=True, timeout=5,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("complete", json.loads(result.stdout)["phase"])
        with tempfile.TemporaryDirectory() as tmp:
            malformed = Path(tmp) / "bad.jsonl"
            malformed.write_text("not-json\n")
            failed = subprocess.run(
                [sys.executable, str(ROOT / "bin" / "sippycup-ui"), str(malformed)],
                cwd=ROOT, text=True, capture_output=True, timeout=5,
            )
        self.assertEqual(1, failed.returncode)
        self.assertEqual(1, json.loads(failed.stdout)["state"]["schema_errors"])


if __name__ == "__main__":
    unittest.main()
