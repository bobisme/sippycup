"""diagnose says what is true (rehearsal 2, findings 28 and 29).

28: a passing call that the journal already names no longer gets a step that
says to record it. 29: a call stopped because the far end's media PORT was
outside the approved range no longer says the media ADDRESS was never approved.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from test_diagnose import APPROVED, Fixture  # noqa: E402

PASS = {"answered": True, "final_status": 200, "rtp_tx_packets": 200, "rtp_rx_packets": 200, "codec": "PCMU",
        "setup": {"inviteToAnswerSeconds": 0.01}}
ORACLE = {"summary": {"pass": 10, "fail": 0, "unknown": 0}}


class AlreadyRecordedTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.fx = Fixture(Path(self._tmp.name))
        name = self.fx.dir.name
        journal = ["./bin/sippycup", "journal", "add", "work/eng", "--kind", "action", "--summary", "s",
                   "--evidence", f"calls/{name}/result.json", "--evidence", f"calls/{name}/evidence-manifest.json"]
        self.fx.call("pass", state="completed", softphone=PASS,
                     result={"oracle": ORACLE, "journalCommand": journal})

    def record_steps(self, data: dict) -> list[str]:
        return [step["command"] for step in data["nextSteps"] if step.get("command") and " journal add " in step["command"]]

    def test_an_unrecorded_pass_still_says_to_record_it(self) -> None:
        data = self.fx.diagnose()
        self.assertEqual(1, len(self.record_steps(data)))

    def test_a_pass_the_journal_names_is_not_told_to_record_again(self) -> None:
        name = self.fx.dir.name
        entry = {"sequence": 3, "kind": "action", "summary": "x", "evidence": [f"calls/{name}/result.json"]}
        (self.fx.eng / "journal.jsonl").write_text(json.dumps(entry) + "\n", encoding="utf-8")
        data = self.fx.diagnose()
        self.assertEqual([], self.record_steps(data))
        journal = [item for item in data["evidence"] if item["label"] == "journal"]
        self.assertEqual(1, len(journal), data["evidence"])
        self.assertIn("already recorded", journal[0]["text"])
        self.assertIn("entry #3", journal[0]["text"])

    def test_a_journal_entry_for_another_run_does_not_hide_the_step(self) -> None:
        entry = {"sequence": 1, "kind": "action", "summary": "x", "evidence": ["calls/some-other-run/result.json"]}
        (self.fx.eng / "journal.jsonl").write_text(json.dumps(entry) + "\n", encoding="utf-8")
        self.assertEqual(1, len(self.record_steps(self.fx.diagnose())))


class PortStopTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.fx = Fixture(Path(self._tmp.name))

    def stop(self, scope: dict) -> dict:
        self.fx.call("media-outside-scope",
                     softphone={"answered": True, "final_status": 200, "error": "media_peer_outside_scope",
                                "media_peer": "198.51.100.10:30000"},
                     result={"mediaScope": scope})
        return self.fx.diagnose()

    def test_a_port_outside_the_range_says_port_and_does_not_say_the_address_was_never_approved(self) -> None:
        data = self.stop({"peer": "198.51.100.10:30000", "inScope": False, "admittedBy": "approved-address",
                          "portAdmitted": False,
                          "rules": {"approvedAddresses": APPROVED, "mediaNetworks": None, "mediaPorts": [20000, 20019]}})
        text = json.dumps(data)
        self.assertIn("media port outside the approved media port range", text)
        self.assertIn("its address was approved", text)
        self.assertNotIn("named a media address that was never approved", text)
        self.assertIn("RTP port range the media servers use", json.dumps(data["stopAndAsk"]))
        self.assertIn("another media port range", text)

    def test_an_unapproved_address_still_says_address(self) -> None:
        data = self.stop({"peer": "203.0.113.200:20000", "inScope": False, "admittedBy": None,
                          "rules": {"approvedAddresses": APPROVED, "mediaNetworks": None}})
        text = json.dumps(data)
        self.assertIn("named a media address that was never approved", text)
        self.assertIn("media-server addresses or range", json.dumps(data["stopAndAsk"]))


if __name__ == "__main__":
    unittest.main()
