from pathlib import Path
import queue
import unittest

from sippycup_tui.state import (
    BoundedEventBuffer, Event, EventError, ViewState, decode_event,
    reduce_event, replay, visible_schema_error,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "replay.jsonl"


class StateTests(unittest.TestCase):
    def fixture_events(self):
        return tuple(decode_event(line) for line in FIXTURE.read_text().splitlines())

    def test_replay_is_deterministic_and_reaches_complete(self):
        events = self.fixture_events()
        first, second = replay(events), replay(events)
        self.assertEqual(first, second)
        self.assertEqual("complete", first.phase)
        self.assertEqual(("stop", "termshark", "note", "quit"), first.actions)
        self.assertEqual(first.as_json_record(), second.as_json_record())

    def test_every_required_phase_has_actions(self):
        kinds = ("plan.started", "plan.ready", "run.started", "run.warning",
                 "stop.requested", "recovery.started", "run.completed", "run.failed")
        phases = {reduce_event(ViewState(), Event(i, "test", kind)).phase
                  for i, kind in enumerate(kinds)}
        self.assertEqual({"planning", "ready", "running", "warning", "stopping",
                          "recovery", "complete", "failed"}, phases)

    def test_schema_errors_are_rejected_and_can_be_rendered(self):
        with self.assertRaisesRegex(EventError, "unsupported event schema"):
            decode_event({"schema": "old", "sequence": 1, "source": "x", "kind": "x"})
        state = reduce_event(ViewState(), visible_schema_error("old schema", 1))
        self.assertEqual("warning", state.phase)
        self.assertEqual(1, state.schema_errors)
        self.assertIn("old schema", state.warnings)

    def test_ansi_tool_output_is_not_scraped(self):
        with self.assertRaisesRegex(EventError, "not JSON"):
            decode_event("\x1b[31mFAILED\x1b[0m")

    def test_late_event_is_visible_and_not_applied(self):
        state = reduce_event(ViewState(), Event(4, "campaign", "run.started"))
        late = reduce_event(state, Event(3, "campaign", "run.completed"))
        self.assertEqual("running", late.phase)
        self.assertEqual(1, late.late)
        self.assertIn("late event", late.warnings[0])

    def test_bounded_queue_backpressure_reports_drops(self):
        buffer = BoundedEventBuffer(1)
        self.assertTrue(buffer.put(Event(1, "campaign", "run.started")))
        self.assertFalse(buffer.put(Event(2, "campaign", "run.completed")))
        diagnostic = buffer.get()
        self.assertEqual("ui.dropped", diagnostic.kind)
        self.assertEqual(1, reduce_event(ViewState(), diagnostic).dropped)
        queued = buffer.get(timeout=0.1)
        self.assertEqual("run.started", queued.kind)
        buffer.task_done(queued)
        with self.assertRaises(queue.Empty):
            buffer.get(timeout=0.001)

    def test_payload_and_unknown_fields_are_bounded(self):
        base = {"schema": "sippycup.ui-event/v1", "sequence": 1, "source": "x", "kind": "x"}
        with self.assertRaisesRegex(EventError, "unknown event fields"):
            decode_event({**base, "ansi": "no"})
        with self.assertRaisesRegex(EventError, "64 KiB"):
            decode_event({**base, "payload": {"large": "x" * 70000}})


if __name__ == "__main__":
    unittest.main()
