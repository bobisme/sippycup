from datetime import datetime, timezone
from pathlib import Path
import json
import tempfile
import unittest

from sippycup_tui.controls import ActionController, ControlError, remaining_budget
from sippycup_tui.state import PHASE_ACTIONS, ViewState


class FakeAPI:
    def __init__(self):
        self.calls = []
    def start(self): self.calls.append("start")
    def pause_new_calls(self): self.calls.append("pause")
    def graceful_stop(self): self.calls.append("graceful")
    def emergency_stop(self): self.calls.append("emergency")
    def skip_current(self): self.calls.append("skip")


class ControlTests(unittest.TestCase):
    def test_stop_is_available_in_every_phase(self):
        self.assertTrue(all("stop" in actions for actions in PHASE_ACTIONS.values()))

    def test_dangerous_actions_require_fresh_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            api = FakeAPI()
            controller = ActionController(api, Path(tmp))
            for index, action in enumerate(("start", "emergency-stop", "skip")):
                with self.assertRaisesRegex(ControlError, "confirmation"):
                    controller.invoke(action, ViewState(), idempotency_key=f"bad-{index}")
                confirmation = controller.request_confirmation(action)
                controller.invoke(
                    action, ViewState(), idempotency_key=f"good-{index}",
                    confirmation=confirmation.token,
                )
        self.assertEqual(["start", "emergency", "skip"], api.calls)

    def test_repeated_key_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            api = FakeAPI()
            controller = ActionController(api, Path(tmp))
            first = controller.invoke("graceful-stop", ViewState(), idempotency_key="key-1")
            second = controller.invoke("graceful-stop", ViewState(), idempotency_key="key-1")
        self.assertEqual(first, second)
        self.assertEqual(["graceful"], api.calls)

    def test_notes_are_separate_private_metadata_and_idempotent(self):
        fixed = datetime(2026, 7, 18, 21, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            controller = ActionController(FakeAPI(), run, now=lambda: fixed)
            controller.note(
                "jitter begins", ViewState(phase="running"),
                idempotency_key="note-1", bookmark=True, evidence="capture.pcapng#42",
            )
            duplicate = controller.note(
                "jitter begins", ViewState(), idempotency_key="note-1", bookmark=True
            )
            records = (run / "notes.jsonl").read_text().splitlines()
            parsed = json.loads(records[0])
            self.assertEqual(1, len(records))
            self.assertFalse(duplicate.applied)
            self.assertEqual("bookmark", parsed["kind"])
            self.assertEqual("2026-07-18T21:00:00Z", parsed["timeUtc"])
            self.assertEqual("capture.pcapng#42", parsed["evidence"])
            self.assertEqual(0o600, (run / "notes.jsonl").stat().st_mode & 0o777)

    def test_termshark_handoff_uses_fixed_argv_and_returns_same_state(self):
        launched = []
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            run.mkdir()
            capture = run / "current capture.pcapng"
            capture.write_bytes(b"pcap")
            controller = ActionController(
                FakeAPI(), run, launcher=lambda argv: launched.append(argv) or 0
            )
            receipt = controller.open_capture(capture, ViewState(phase="recovery"))
            self.assertEqual("recovery", receipt.state)
            self.assertEqual(["termshark", "-r", str(capture)], launched[0])
            outside = Path(tmp) / "outside.pcap"
            outside.write_bytes(b"x")
            with self.assertRaisesRegex(ControlError, "run directory"):
                controller.open_capture(outside, ViewState())

    def test_remaining_budget_never_exceeds_safety_gate(self):
        self.assertEqual(90, remaining_budget(100, 10))
        self.assertEqual(0, remaining_budget(100, 150))
        with self.assertRaises(ControlError):
            remaining_budget(100, -1)


if __name__ == "__main__":
    unittest.main()
