import unittest

from sippycup_tui import EventError, adapt_assertion, adapt_campaign, reduce_event, ViewState


class AdapterTests(unittest.TestCase):
    def campaign(self, event, **fields):
        return {
            "apiVersion": "sippycup.dev/events/v1",
            "sequence": fields.pop("sequence", 1),
            "campaign": "fixture",
            "event": event,
            "state": fields.pop("state", "running"),
            **fields,
        }

    def test_campaign_terminal_events_map_to_shared_semantics(self):
        cases = (
            ("campaign.started", "run.started", "running"),
            ("campaign.stop_requested", "stop.requested", "stopping"),
            ("campaign.succeeded", "run.completed", "complete"),
            ("campaign.failed", "run.failed", "failed"),
        )
        for producer, kind, phase in cases:
            with self.subTest(producer):
                event = adapt_campaign(self.campaign(producer))
                self.assertEqual(kind, event.kind)
                self.assertEqual(phase, reduce_event(ViewState(), event).phase)

    def test_campaign_output_text_is_never_forwarded_or_scraped(self):
        record = self.campaign("step.output", text="\x1b[31mFAILED\x1b[0m")
        self.assertIsNone(adapt_campaign(record))

    def test_assertion_adapter_exposes_aggregate_not_protocol_records(self):
        event = adapt_assertion(
            {
                "schema_version": "sippycup.results/v1",
                "verdict": "fail",
                "summary": {"pass": 1, "fail": 1, "unknown": 0},
                "dialogs": [{"call_id": "must-not-leak"}],
            },
            sequence=7,
        )
        self.assertEqual("assertions.failed", event.kind)
        self.assertNotIn("dialogs", event.payload)
        self.assertEqual("failed", reduce_event(ViewState(), event).phase)

    def test_schema_mismatches_fail_explicitly(self):
        with self.assertRaisesRegex(EventError, "campaign event schema"):
            adapt_campaign({"apiVersion": "old"})
        with self.assertRaisesRegex(EventError, "assertion result schema"):
            adapt_assertion({"schema_version": "old"}, sequence=1)


if __name__ == "__main__":
    unittest.main()
