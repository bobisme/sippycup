"""Regressions for the seams the proxy-shape dress rehearsal exposed (bn-38v).

Each test names the seam it pins down; see docs/PRACTICE-TARGET.md "Proxy
shape" and "The safety stop". Offline: no containers, no network.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_cockpit import actions, model as cockpit_model  # noqa: E402
from sippycup_cockpit.render import run_line  # noqa: E402
from sippycup_cockpit.runs import _call_summary  # noqa: E402
from sippycup_workbench import summary_model  # noqa: E402
from sippycup_workbench.call import _network_activity  # noqa: E402

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)


def route_model(host: str, *, addresses: list[str] | None, up: bool = True) -> dict:
    practice = {"up": up, "address": "127.0.0.2"}
    if addresses is not None:
        practice["addresses"] = addresses
    return {"readiness": {"practice": practice}, "target": {"host": host}}


class CockpitPracticeRouteTests(unittest.TestCase):
    """Seam 1: the cockpit routed only 127.0.0.2 through --practice, so every live
    command for an engagement whose target is the practice proxy ran outside the
    practice namespace and failed its preflight."""

    def test_the_proxy_address_is_routed_through_practice(self) -> None:
        both = ["127.0.0.2", "127.0.0.3"]
        self.assertTrue(actions.practice_route(route_model("127.0.0.3", addresses=both)))
        self.assertTrue(actions.practice_route(route_model("127.0.0.2", addresses=both)))
        self.assertEqual(["./bin/sippycup", "--practice"], actions._route(route_model("127.0.0.3", addresses=both)))

    def test_other_hosts_and_a_down_target_are_not(self) -> None:
        both = ["127.0.0.2", "127.0.0.3"]
        self.assertFalse(actions.practice_route(route_model("127.0.0.4", addresses=both)))
        self.assertFalse(actions.practice_route(route_model("192.0.2.10", addresses=both)))
        self.assertFalse(actions.practice_route(route_model("127.0.0.3", addresses=both, up=False)))
        # Facts written before the proxy existed: only the practice address.
        self.assertTrue(actions.practice_route(route_model("127.0.0.2", addresses=None)))
        self.assertFalse(actions.practice_route(route_model("127.0.0.3", addresses=None)))

    def test_practice_facts_list_the_proxy_from_the_connection_facts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "work" / "practice"
            state.mkdir(parents=True)
            (state / "image.json").write_text(json.dumps({"image": "localhost/sippycup-practice:latest"}))
            (state / "connection.json").write_text(json.dumps({
                "address": "127.0.0.2", "started_utc": "2026-11-18T11:00:00Z",
                "profile_valid_until_utc": "2026-11-18T15:00:00Z", "authorization": "LOCAL-PRACTICE-ONLY: x",
                "proxy": {"address": "127.0.0.3"},
            }))
            facts = cockpit_model._practice_facts(Path(directory), NOW)
        self.assertEqual(["127.0.0.2", "127.0.0.3"], facts["addresses"])


class NetworkActivityTests(unittest.TestCase):
    """Seam 2: the activity statement said "INVITE dialog with RTP to 127.0.0.3:5060/udp"
    when the RTP went to the media address 127.0.0.2."""

    SOFTPHONE = {"started": True, "registration_attempted": True, "dialed": True, "rtp_tx_packets": 500,
                 "rtp_rx_packets": 500}

    def activity(self, softphone: dict, host: str) -> str:
        return _network_activity(preflight_sent=True, softphone=softphone, target=f"{host}:5060/udp",
                                 network_mode="private", loopback=True, host=host)

    def test_media_peer_on_another_address_is_named(self) -> None:
        text = self.activity({**self.SOFTPHONE, "media_peer": "127.0.0.2:20000"}, "127.0.0.3")
        self.assertIn("1 INVITE dialog to 127.0.0.3:5060/udp, RTP with the media peer 127.0.0.2:20000 "
                      "(not the signaling address),", text)
        self.assertNotIn("with RTP to 127.0.0.3", text)

    def test_media_on_the_signaling_address_reads_as_before(self) -> None:
        text = self.activity({**self.SOFTPHONE, "media_peer": "127.0.0.2:20000"}, "127.0.0.2")
        self.assertIn("1 INVITE dialog with RTP to 127.0.0.2:5060/udp inside", text)

    def test_an_unapproved_media_peer_is_never_named(self) -> None:
        text = self.activity({**self.SOFTPHONE, "rtp_tx_packets": 3, "media_peer": "127.0.0.2:20004",
                              "error": "media_peer_outside_scope"}, "127.0.0.3")
        self.assertNotIn("127.0.0.2", text)
        self.assertIn("RTP with a media peer outside the approved addresses until the media-scope stop", text)


def stopped_run() -> dict:
    return {
        "id": "R-stop", "kind": "call", "ref": "calls/R-stop", "verdict": "media-outside-scope",
        "started": "2026-11-18T12:00:00Z", "target": {"address": "127.0.0.3", "port": 5060, "transport": "udp"},
        "details": {
            "call": {"answered": True, "error": "media_peer_outside_scope"},
            "media": {"toPeerPackets": 3, "fromPeerPackets": 3, "peerApproved": False},
            "oracle": {"verdict": "fail", "decidesVerdict": True,
                       "failed": ["dialog[0].media.directionality", "dialog[0].media.endpoints"]},
            "preflight": {"statusCode": 200},
        },
    }


class OwnerReportSafetyStopTests(unittest.TestCase):
    """Seams 3 to 5: the owner report presented the stop as a target finding (low),
    claimed nothing was sent ("hung up before media was sent there") although
    PJSUA had sent 3 RTP packets, added an oracle observation the stop itself
    caused, and summarized the run as "did not pass"."""

    def test_the_stop_is_one_informational_observation_with_the_packet_count(self) -> None:
        found = summary_model._observations(stopped_run())
        self.assertEqual(["obs-media-outside-scope"], [item["id"] for item in found])
        stop = found[0]
        self.assertEqual("info", stop["severity"])
        self.assertTrue(stop["title"].startswith("Safety stop:"))
        self.assertIn("This is a safety stop, not a target failure.", stop["summary"])
        self.assertIn("RTP packets sent to that address before the stop: 3 (", stop["summary"])
        self.assertIn("RTCP control packets sent beside it before the stop are not counted", stop["summary"])
        self.assertNotIn("before media was sent", stop["summary"])

    def test_an_ordinary_oracle_failure_is_still_reported(self) -> None:
        run = stopped_run()
        run["verdict"] = "fail"
        found = [item["id"] for item in summary_model._observations(run)]
        self.assertIn("obs-oracle-assertion-failed", found)

    def test_the_integrity_exception_discloses_the_packets(self) -> None:
        self.assertEqual("; the media-scope stop hung the call up after 3 RTP packets were sent to it "
                         "(the count is the test softphone's and covers RTP only; RTCP control packets sent "
                         "beside it before the stop are not counted)",
                         summary_model._stop_detail(stopped_run()))
        single = stopped_run()
        single["details"]["media"]["toPeerPackets"] = 1
        self.assertIn("after 1 RTP packet was sent", summary_model._stop_detail(single))
        other = stopped_run()
        other["verdict"] = "fail"
        self.assertEqual("", summary_model._stop_detail(other))

    def test_the_executive_summary_calls_it_a_safety_stop(self) -> None:
        run = stopped_run()
        model = {
            "runs": [run], "runCounts": {"call": 1, "campaign": 0, "check": 0},
            "findings": [{**summary_model._observations(run)[0], "ref": "F-01", "targetLabel": "127.0.0.3:5060/udp",
                          "runs": ["R-stop"]}],
            "integrityExceptions": [{"code": "media-peer-not-approved", "run": "R-stop", "detail": "x"}],
            "authorization": {"window": None, "sources": [], "present": True},
        }
        rows = [row["title"] for row in summary_model._executive(model)["rows"]]
        self.assertIn("1 run was ended by a Sippycup safety stop (media-outside-scope), not a target failure", rows)
        self.assertFalse(any("did not pass" in row for row in rows))


class CockpitSafetyStopTests(unittest.TestCase):
    """Seam 6: the cockpit listed the stop as an ordinary failure ([!!]) whose
    reason was the first note ("... no NAT applies.")."""

    def test_a_media_scope_stop_is_marked_and_explained(self) -> None:
        document = {
            "verdict": "media-outside-scope", "state": "failed",
            "notes": ["The target is a loopback address inside the container's own network namespace; no NAT applies.",
                      "The negotiated media peer is not an approved address; the call was hung up."],
            "softphone": {"media_peer": "127.0.0.2:20004", "rtp_tx_packets": 3, "error": "media_peer_outside_scope"},
        }
        summary: dict = {"relative": "calls/R", "kind": "call", "readable": True, "time": "t"}
        _call_summary(document, summary)
        self.assertTrue(summary["safetyStop"])
        self.assertFalse(summary["passed"])
        self.assertTrue(summary["reason"].startswith("safety stop, not a target failure: the media peer "
                                                     "127.0.0.2:20004 is not an approved address"))
        self.assertIn("after 3 RTP packets", summary["reason"])
        self.assertEqual("Safety stop", summary["facts"][0][0])
        self.assertIn("[stop]", run_line(1, summary))

    def test_a_guarded_stop_says_the_packets_were_dropped_not_sent(self) -> None:
        # bn-3l8o: PJSUA counts a packet the media guard dropped as sent.
        document = {
            "verdict": "media-outside-scope", "state": "failed", "notes": ["x"],
            "softphone": {"media_peer": "127.0.0.2:20004", "rtp_tx_packets": 1, "error": "media_peer_outside_scope"},
            "mediaGuard": {"active": True, "blocked": {"rtp": 1, "rtcp": 4, "other": 0}},
        }
        summary: dict = {"relative": "calls/R", "kind": "call", "readable": True, "time": "t"}
        _call_summary(document, summary)
        self.assertIn("the media guard dropped the 1 RTP and 4 RTCP packets addressed there; none were sent",
                      summary["reason"])
        self.assertNotIn("after 1 RTP packet", summary["reason"])

    def test_an_ordinary_failure_keeps_its_marker(self) -> None:
        summary: dict = {"relative": "calls/R", "kind": "call", "readable": True, "time": "t"}
        _call_summary({"verdict": "no-answer", "notes": ["nobody answered"]}, summary)
        self.assertNotIn("safetyStop", summary)
        self.assertIn("[!!]", run_line(1, summary))


if __name__ == "__main__":
    unittest.main()
