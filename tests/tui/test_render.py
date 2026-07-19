import unittest

from sippycup_tui.render import (
    DashboardModel, Metric, WarningLink, apply_dashboard_event, render_text,
)
from sippycup_tui.state import Event, ViewState


def full_model():
    return DashboardModel(
        authorization="192.0.2.10/32 UDP 5060 + negotiated RTP",
        planned_cases=12,
        current_step="3 INVITE",
        next_step="4 media canary",
        utc_started="2026-07-18T21:00:00Z",
        utc_elapsed="00:00:08",
        budgets={"packets": Metric("120/500", "good"), "seconds": Metric("8/30", "warning")},
        capture=Metric("active 42 KiB", "good"),
        capture_path="/work/run/capture.pcapng",
        report_path="/work/run/report/index.html",
        sip_ladder=("1 INVITE ->", "2 <- 100", "3 <- 200", "4 ACK ->"),
        sip_counters={"2xx": Metric("1", "good"), "timeouts": Metric("0", "good")},
        media={"codec": Metric("PCMU/8000", "good"), "endpoint": Metric("unknown", "unknown")},
        rtp={"caller->callee": Metric("400 pkts, 0% loss, 2ms jitter", "good"),
             "callee->caller": Metric("stale 5s", "stale")},
        assertions={"pass": Metric("7", "good"), "unknown": Metric("1", "unknown")},
        recovery=Metric("pending", "unknown"),
        warnings=(WarningLink("jitter near threshold", "assertions.json#rtp-2"),),
        first_run=False,
    )


class RenderTests(unittest.TestCase):
    def test_full_layout_contains_every_required_panel_and_text_status(self):
        output = render_text(full_model(), ViewState(phase="running"), width=100, height=30)
        for label in ("AUTHORIZATION", "PLAN", "UTC", "CAPTURE", "REPORT", "BUDGETS", "SIP LADDER",
                      "SIP COUNTERS", "NEGOTIATED MEDIA", "RTP BY DIRECTION",
                      "ASSERTIONS", "RECOVERY CANARY", "WARNINGS"):
            self.assertIn(label, output)
        self.assertIn("[OK]", output)
        self.assertIn("[? UNKNOWN]", output)
        self.assertIn("[~ STALE]", output)
        self.assertIn("assertions.json#rtp-2", output)
        self.assertTrue(all(len(line) <= 100 for line in output.splitlines()))
        self.assertLessEqual(len(output.splitlines()), 30)

    def test_compact_resize_is_safe_and_legible(self):
        output = render_text(full_model(), ViewState(phase="warning"), width=60, height=16)
        self.assertIn("SIP", output)
        self.assertIn("RTP", output)
        self.assertTrue(all(len(line) <= 60 for line in output.splitlines()))
        with self.assertRaises(ValueError):
            render_text(full_model(), ViewState(), width=39, height=10)

    def test_help_overlay_lists_all_one_key_actions(self):
        help_text = render_text(full_model(), ViewState(), width=100, height=30, help_overlay=True)
        for binding in ("s start", "p pause-new-calls", "x graceful-stop", "! emergency-stop",
                        "k skip", "n note", "b bookmark", "t Termshark", "? help", "q quit"):
            self.assertIn(binding, help_text)

    def test_first_run_guidance_says_when_traffic_starts_and_where_output_lives(self):
        output = render_text(DashboardModel(), ViewState(), width=100, height=30)
        self.assertIn("no traffic starts during planning", output)
        self.assertIn("run directory", output)

    def test_presentation_event_updates_without_protocol_reasoning(self):
        event = Event(1, "campaign", "run.warning", {
            "message": "capture stale", "evidence": "events.jsonl#9",
            "capture": {"value": "stale", "status": "stale"},
            "rtp": {"a->b": {"value": "unknown", "status": "unknown"}},
        })
        model = apply_dashboard_event(DashboardModel(), event)
        self.assertEqual("stale", model.capture.status)
        self.assertEqual("unknown", model.rtp["a->b"].status)
        self.assertEqual("events.jsonl#9", model.warnings[0].evidence)

    def test_json_view_exposes_same_actions(self):
        state = ViewState(phase="complete", actions=("termshark", "note", "quit"))
        record = full_model().as_json_record(state)
        self.assertEqual(list(state.actions), record["actions"])
        self.assertEqual("complete", record["phase"])


if __name__ == "__main__":
    unittest.main()
