"""The `Record it:` summary says which call it was (rehearsal 2, finding 27).

It used to be `Guided baseline call (NAME): pass` for every call, whatever the
destination, transport, DTMF or SRTP, so a journal of five calls read as five
identical lines.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

import cockpit_support as support  # noqa: E402
from test_guided_call import Fakes  # noqa: E402

from sippycup_workbench import call as guided  # noqa: E402

NOW = datetime.now(timezone.utc).replace(microsecond=0)


class TitleTests(unittest.TestCase):
    def test_title_names_destination_transport_and_the_options_that_differ(self) -> None:
        facts = {"destination": "echo", "host": "127.0.0.2", "port": 5061, "transport": "tls",
                 "srtp": "mandatory", "codecs": ["PCMA"], "dtmf": True}
        self.assertEqual(
            "Guided call to echo over tls 127.0.0.2:5061 (prac): pass [SRTP mandatory, codec PCMA, DTMF]",
            guided._journal_title("pass", "prac", facts),
        )
        plain = {**facts, "srtp": "off", "codecs": [], "dtmf": False, "transport": "udp", "port": 5060}
        self.assertEqual("Guided call to echo over udp 127.0.0.2:5060 (prac): pass",
                         guided._journal_title("pass", "prac", plain))
        self.assertEqual("Guided call (prac): internal-error", guided._journal_title("internal-error", "prac", None))

    def test_a_real_call_result_names_its_destination_and_transport(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = support.make_repo(Path(temporary))
            root = support.compiled_engagement(repo, now=NOW, go=False)
            lines = []
            for extra in ({}, {"duration": 4}):
                options = guided.CallOptions(profile=root / "target-profile.yaml", destination="echo", **{"duration": 3, **extra})
                code, value = guided.execute(options, Fakes().dependencies(repo / "work", now=lambda: NOW))
                self.assertIn(code, (0, 1), value)
                command = value["journalCommand"]
                lines.append(command[command.index("--summary") + 1])
        self.assertIn("to echo over udp 127.0.0.2:5060", lines[0])
        self.assertNotIn("baseline", lines[0])
        self.assertTrue(lines[0].startswith("Guided call to echo over udp"), lines[0])


if __name__ == "__main__":
    unittest.main()
