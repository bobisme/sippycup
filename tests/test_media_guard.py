"""bn-3l8o: no RTP or RTCP leaves for an address outside the media scope.

Rehearsal 3 (finding 3): the media-scope stop hung the call up, but the
capture showed 1 RTP and 4 RTCP packets already sent to the address the
owner did not list. PJSUA starts its media stream while it processes the
SDP answer (two RTCP packets before the ACK, RTP 2-3 ms later) and sends
two more RTCP packets as it hangs up; the driver, reading PJSUA's log, can
only react afterwards. The media guard (``media_guard.c``) is preloaded into
PJSUA and drops those datagrams inside ``sendto()``.

Here: the guard's rules and the driver's handling with the fixture console
``tests/fixtures/fake_pjsua.py`` (which prints the library's lines), the
compiled library itself on loopback when a C compiler is present, and the
words the commands use for it (finding 17).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from sippycup_softphone import SoftphoneCall, SoftphoneError, place_call  # noqa: E402
from sippycup_softphone import driver  # noqa: E402
from sippycup_workbench import call as guided  # noqa: E402
from sippycup_workbench import media_scope  # noqa: E402

from test_guided_call import FAKE_PJSUA, write_tone  # noqa: E402

SOURCE = ROOT / "lib" / "sippycup_softphone" / "media_guard.c"
PROBE = ROOT / "tests" / "fixtures" / "media_guard_probe.py"


def a_call(**values) -> SoftphoneCall:
    defaults = {
        "destination": "echo", "host": "192.0.2.10", "port": 5060, "transport": "udp",
        "play_file": Path("p.wav"), "record_file": Path("r.wav"), "duration_seconds": 2,
        "log_file": Path("l.log"),
    }
    defaults.update(values)
    return SoftphoneCall(**defaults)


class RulesTests(unittest.TestCase):
    def test_no_media_scope_means_no_guard_rules(self):
        self.assertIsNone(driver.media_guard_rules(a_call()))
        self.assertFalse(driver.has_media_scope(a_call()))

    def test_addresses_and_networks_become_cidr_and_ports_a_range(self):
        call = a_call(allowed_media_addresses=("192.0.2.10", "2001:db8::5"),
                      allowed_media_networks=("203.0.113.0/28",), allowed_media_ports=(10000, 20000))
        self.assertEqual(driver.media_guard_rules(call),
                         "v1;addr=192.0.2.10/32,2001:db8::5/128,203.0.113.0/28;ports=10000-20000")

    def test_an_empty_media_answer_admits_no_address(self):
        # The owner listed no media address: nothing is admitted, not everything.
        self.assertEqual(driver.media_guard_rules(a_call(allowed_media_addresses=())), "v1;addr=-;ports=*")

    def test_only_a_port_rule_admits_any_address(self):
        self.assertEqual(driver.media_guard_rules(a_call(allowed_media_ports=(4000, 4100))),
                         "v1;addr=*;ports=4000-4100")

    def test_more_rules_than_the_guard_takes_are_refused(self):
        many = tuple(f"198.51.{index // 250}.{index % 250 + 1}" for index in range(driver.MEDIA_GUARD_MAX_RULES + 1))
        with self.assertRaises(SoftphoneError):
            driver.media_guard_rules(a_call(allowed_media_addresses=many))

    def test_the_library_is_the_configured_one_or_the_installed_one(self):
        with mock.patch.dict(os.environ, {driver.MEDIA_GUARD_LIBRARY_ENV: "/somewhere/guard.so"}):
            self.assertEqual(driver.media_guard_library(), "/somewhere/guard.so")
        with tempfile.TemporaryDirectory() as directory:
            installed = Path(directory) / "guard.so"
            with mock.patch.dict(os.environ), mock.patch.object(driver, "MEDIA_GUARD_INSTALLED", installed):
                os.environ.pop(driver.MEDIA_GUARD_LIBRARY_ENV, None)
                self.assertIsNone(driver.media_guard_library())
                installed.write_bytes(b"")
                # A runner started with a reduced environment still finds it.
                self.assertEqual(driver.media_guard_library(), str(installed))


class DriverGuardTests(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name)
        self.play = self.root / "play.wav"
        write_tone(self.play)
        self.library = self.root / "guard.so"
        self.library.write_bytes(b"")

    def call(self, **values):
        defaults = {
            "play_file": self.play, "record_file": self.root / "heard.wav", "duration_seconds": 4,
            "log_file": self.root / "softphone.log", "console_file": self.root / "console.txt",
            "allowed_media_addresses": ("192.0.2.10",),
        }
        defaults.update(values)
        return a_call(**defaults)

    def run_fake(self, call, mode, *, library="set", guard="loaded"):
        witness = self.root / f"witness-{mode}-{guard}.json"
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "FAKE_PJSUA_WITNESS": str(witness),
               "FAKE_PJSUA_MODE": mode, "FAKE_PJSUA_GUARD": guard}
        private = self.root / f"private-{mode}-{guard}"
        private.mkdir(mode=0o700, exist_ok=True)
        configured = {} if library is None else {
            driver.MEDIA_GUARD_LIBRARY_ENV: str(self.library if library == "set" else library)}
        with mock.patch.dict(os.environ), \
                mock.patch.object(driver, "MEDIA_GUARD_INSTALLED", self.root / "not-installed.so"):
            os.environ.pop(driver.MEDIA_GUARD_LIBRARY_ENV, None)
            os.environ.update(configured)
            result = place_call(call, pjsua=str(FAKE_PJSUA), environment=env, private_root=private)
        self.assertEqual(list(private.iterdir()), [], "private directory leaked")
        return result, (json.loads(witness.read_text()) if witness.exists() else None)

    def test_the_guard_is_preloaded_with_the_calls_rules_and_an_approved_call_is_untouched(self):
        result, record = self.run_fake(self.call(duration_seconds=1, allowed_media_ports=(4000, 4100)), "answer")
        self.assertIsNone(result.error, result)
        self.assertEqual(result.hangup, "duration")
        self.assertEqual(record["environ"]["LD_PRELOAD"], str(self.library))
        self.assertEqual(record["environ"]["SIPPYCUP_MEDIA_GUARD_RULES"], "v1;addr=192.0.2.10/32;ports=4000-4100")
        self.assertEqual(result.media_guard, {
            "active": True, "library": str(self.library), "rules": "addr=192.0.2.10/32 ports=4000-4100",
            "blocked": {"rtp": 0, "rtcp": 0, "other": 0}, "destinations": [], "listTruncated": False,
        })
        self.assertTrue(result.media_scope["inScope"])

    def test_dropped_rtp_and_rtcp_are_counted_and_the_call_is_hung_up(self):
        result, record = self.run_fake(self.call(duration_seconds=20), "sdpsteer")
        self.assertEqual(result.error, "media_peer_outside_scope")
        self.assertEqual(record.get("hangups"), ["BYE"])
        guard = result.media_guard
        self.assertTrue(guard["active"])
        # Two RTCP as the stream starts, one RTP, two RTCP from the hang-up.
        self.assertEqual(guard["blocked"], {"rtp": 1, "rtcp": 4, "other": 0})
        self.assertEqual(sorted(guard["destinations"]), ["198.51.100.88:4000", "198.51.100.88:4001"])
        self.assertFalse(result.media_scope["inScope"])

    def test_rtcp_only_steering_counts_rtcp(self):
        result, _record = self.run_fake(self.call(duration_seconds=20), "rtcpsteer")
        self.assertEqual(result.error, "media_peer_outside_scope")
        self.assertEqual(result.media_guard["blocked"], {"rtp": 0, "rtcp": 4, "other": 0})

    def test_a_drop_alone_stops_the_call_even_when_the_sdp_was_in_scope(self):
        result, record = self.run_fake(self.call(duration_seconds=20), "guardswitch")
        self.assertEqual(result.error, "media_peer_outside_scope")
        self.assertEqual(result.hangup, "scope")
        self.assertEqual(record.get("hangups"), ["BYE"])
        self.assertEqual(result.media_guard["blocked"]["rtp"], 1)
        self.assertFalse(result.media_scope["inScope"])
        self.assertLess(result.connected_seconds or 0, 5.0)

    def test_a_guard_that_does_not_report_itself_active_means_no_dial(self):
        for guard in ("absent", "otherprog", "otherrules"):
            with self.subTest(guard=guard):
                result, record = self.run_fake(self.call(), "answer", guard=guard)
                self.assertEqual(result.error, "media_guard_not_active")
                self.assertFalse(result.dialed)
                self.assertNotIn("m", record["commands"])
                self.assertFalse(result.media_guard["active"])

    def test_a_configured_but_missing_library_starts_nothing(self):
        result, record = self.run_fake(self.call(), "answer", library=self.root / "missing.so")
        self.assertEqual(result.error, "media_guard_unavailable")
        self.assertFalse(result.started)
        self.assertIsNone(record, "PJSUA was started without the guard library")

    def test_outside_the_image_the_call_runs_and_the_result_says_the_guard_was_not_active(self):
        result, record = self.run_fake(self.call(duration_seconds=1), "answer", library=None)
        self.assertIsNone(result.error, result)
        self.assertNotIn("LD_PRELOAD", record["environ"])
        self.assertEqual(result.media_guard["active"], False)
        self.assertIsNone(result.media_guard["library"])

    def test_a_call_without_media_scope_gets_no_guard(self):
        result, record = self.run_fake(self.call(duration_seconds=1, allowed_media_addresses=None), "answer")
        self.assertIsNone(result.error, result)
        self.assertIsNone(result.media_guard)
        self.assertNotIn("LD_PRELOAD", record["environ"])
        self.assertNotIn("SIPPYCUP_MEDIA_GUARD_RULES", record["environ"])


@unittest.skipUnless(shutil.which("cc") and sys.platform.startswith("linux"), "needs a C compiler on Linux")
class CompiledGuardTests(unittest.TestCase):
    """The real library, preloaded into a Python sender, on loopback only."""

    @classmethod
    def setUpClass(cls):
        cls._directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._directory.cleanup)
        cls.library = Path(cls._directory.name) / "media-guard.so"
        built = subprocess.run(
            ["cc", "-O2", "-fPIC", "-shared", "-Wall", "-Wextra", "-Werror", "-o", str(cls.library), str(SOURCE), "-ldl"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        if built.returncode != 0:
            raise AssertionError("media_guard.c does not compile cleanly:\n" + built.stdout.decode("utf-8", "replace"))

    def probe(self, rules=None):
        argv = [sys.executable, "-I", str(PROBE), str(self.library), *([rules] if rules else [])]
        completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
        return json.loads(completed.stdout)

    def test_media_outside_the_rules_is_dropped_and_everything_else_passes(self):
        report = self.probe()
        self.assertEqual(report["exit"], 0, report)
        arrived = report["arrived"]
        expected = {
            "rtp to approved address and port": True,
            "rtp with marker to approved address and port": True,
            "rtcp to approved address, any port": True,
            "rtp to approved address, port outside the range": False,
            "rtp to unapproved address": False,
            "rtcp receiver report to unapproved address": False,
            "rtcp sender report to unapproved address": False,
            "other binary datagram to unapproved address": False,
            "rtp to unapproved address on a connected socket": False,
            "rtp to approved address on a connected socket": True,
            "rtp to unapproved address, IPv4-mapped": False,
            "rtp to approved address, IPv4-mapped": True,
            "sip to unapproved address (signaling is not judged)": True,
            "keep-alive to unapproved address (signaling is not judged)": True,
        }
        self.assertEqual(arrived, expected)
        self.assertTrue(report["tcp"], "a TCP stream was touched")
        lines = [line for line in report["stderr"] if line.startswith("sippycup-media-guard: ")]
        port = report["port"]
        active = [line for line in lines if " active " in line]
        self.assertEqual(len(active), 1, lines)
        match = driver._GUARD_ACTIVE.match(active[0])
        self.assertIsNotNone(match, active[0])
        self.assertEqual(match.group(2), f"addr=127.0.0.2/32 ports={port}-{port}")
        kinds = [driver._GUARD_BLOCKED.match(line).group(1) for line in lines if " blocked " in line]
        self.assertEqual(kinds, ["RTP", "RTP", "RTCP", "RTCP", "OTHER", "RTP", "RTP"])

    def test_without_rules_the_library_does_nothing(self):
        report = self.probe("none")
        self.assertTrue(all(report["arrived"].values()), report)
        self.assertEqual([line for line in report["stderr"] if "media-guard" in line], [])

    def test_unreadable_rules_drop_all_media_but_never_signaling(self):
        report = self.probe("v1;addr=not-an-address;ports=*")
        arrived = report["arrived"]
        self.assertEqual({label for label, seen in arrived.items() if seen},
                         {"sip to unapproved address (signaling is not judged)",
                          "keep-alive to unapproved address (signaling is not judged)"})
        self.assertTrue(any("error" in line for line in report["stderr"]))
        self.assertFalse(any(" active " in line for line in report["stderr"]))

    def test_no_address_rule_admits_nothing_and_any_address_rule_only_checks_the_port(self):
        nothing = self.probe("v1;addr=-;ports=*")["arrived"]
        self.assertFalse(nothing["rtp to approved address and port"])
        self.assertFalse(nothing["rtcp to approved address, any port"])
        anywhere = self.probe("v1;addr=*;ports=*")["arrived"]
        self.assertTrue(all(anywhere.values()), anywhere)


class ContainerfileTests(unittest.TestCase):
    def test_the_image_builds_installs_and_requires_the_guard(self):
        text = (ROOT / "Containerfile").read_text(encoding="utf-8")
        self.assertIn("COPY lib/sippycup_softphone/media_guard.c /src/media_guard.c", text)
        self.assertIn("COPY --from=pjsip-builder /build-media-guard.so " + str(driver.MEDIA_GUARD_INSTALLED), text)
        self.assertIn(f"ENV {driver.MEDIA_GUARD_LIBRARY_ENV}={driver.MEDIA_GUARD_INSTALLED}", text)
        # A PJSIP that sends datagrams through another call must fail the build.
        self.assertIn("sendmsg|sendmmsg", text)


class WordingTests(unittest.TestCase):
    GUARD = {"active": True, "library": "/x.so", "rules": "addr=- ports=*",
             "blocked": {"rtp": 1, "rtcp": 4, "other": 0},
             "destinations": ["192.0.2.10:20009", "192.0.2.10:20008"], "listTruncated": False}

    def classify(self, softphone):
        return guided.classify(
            cancelled_signal=None, stop_reason=None, preflight_ok=True, softphone=softphone,
            oracle=None, media_required=True, network_mode="private", host="192.0.2.10",
            approved=["192.0.2.10"],
        )

    def test_the_stop_note_counts_rtp_and_rtcp_and_says_nothing_was_sent(self):
        _state, verdict, _code, notes = self.classify(
            {"error": "media_peer_outside_scope", "answered": True, "media_peer": "192.0.2.10:20008",
             "media_guard": self.GUARD})
        self.assertEqual(verdict, "media-outside-scope")
        text = " ".join(notes)
        self.assertIn("dropped 1 RTP and 4 RTCP packets", text)
        self.assertIn("no media was sent there", text)
        # A note reaches the owner report, which shows no unapproved address
        # (the dress rehearsal's stop leg failed on exactly this); the
        # operator's Media guard line names where the packets were going.
        self.assertNotIn("192.0.2.10", text)
        self.assertIn("addressed to that address", text)
        line = guided.media_guard_text(self.GUARD, name_destinations=True)
        self.assertIn("addressed to 192.0.2.10:20009, 192.0.2.10:20008", line)

    def test_without_an_active_guard_the_note_does_not_promise_zero(self):
        _state, _verdict, _code, notes = self.classify(
            {"error": "media_peer_outside_scope", "answered": True, "media_peer": "192.0.2.10:20008",
             "media_guard": {"active": False}})
        self.assertIn("NOT active", " ".join(notes))
        self.assertIn("may have reached", " ".join(notes))

    def test_guard_failures_are_a_call_that_was_not_placed(self):
        for error, words in (("media_guard_unavailable", "PJSUA was not started"),
                             ("media_guard_not_active", "no INVITE and no media were sent")):
            with self.subTest(error=error):
                state, verdict, code, notes = self.classify({"error": error, "answered": False, "dialed": False})
                self.assertEqual((state, verdict, code), ("failed", "call-not-placed", guided.EXIT_NOT_PASS))
                self.assertIn(words, " ".join(notes))
                self.assertIn("make build", " ".join(notes))

    def test_an_approved_call_gets_no_guard_sentence(self):
        quiet = dict(self.GUARD, blocked={"rtp": 0, "rtcp": 0, "other": 0}, destinations=[])
        self.assertIsNone(guided.media_guard_text(quiet))
        self.assertIsNone(guided.media_guard_text(None))

    PROFILE = {
        "target": {"host": "192.0.2.10", "port": 5060, "transport": "udp",
                   "approved_addresses": ["192.0.2.10", "192.0.2.44"]},
        "media": {"addresses": ["192.0.2.44"], "port_range": {"start": 10000, "end": 20000}},
    }

    def test_where_lines_use_rehearses_words(self):
        lines = media_scope.where_lines(self.PROFILE)
        self.assertEqual(lines, [
            "Signaling only: 192.0.2.10 (the target host; the owner did not list it for media, "
            "so a call stops if media is offered there)",
            "Media at: 192.0.2.44 (literal addresses from the owner's media answer; never a signaling target)",
            "Media ports: 10000-20000 (the far end's RTP ports)",
        ])
        same = json.loads(json.dumps(self.PROFILE))
        same["media"]["addresses"] = ["192.0.2.10"]
        self.assertEqual(media_scope.where_lines(same)[0],
                         "Signaling and media: 192.0.2.10 (the target host; the owner also listed it for media)")
        ranges = json.loads(json.dumps(self.PROFILE))
        ranges["media"] = {"networks": ["198.51.100.0/27"]}
        self.assertEqual(media_scope.where_lines(ranges), [
            "Signaling and media: 192.0.2.10, 192.0.2.44 (literal approved addresses; signaling goes only "
            "to the target host)",
            "Media only: 198.51.100.0/27 (32 addresses) (owner-approved media networks; never a signaling target)",
        ])

    def test_rehearse_prints_exactly_those_lines_and_the_stop_sentence(self):
        import contextlib
        import io

        from sippycup_workbench import cli

        facts = {"target": {**self.PROFILE["target"]}, "media_addresses": ["192.0.2.44"],
                 "media_ports": {"start": 10000, "end": 20000}}
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cli._emit({"ready": True, "facts": facts}, "human")
        printed = output.getvalue().splitlines()
        for line in media_scope.where_lines(self.PROFILE):
            self.assertIn(line, printed)
        self.assertIn(f"Media stop: {media_scope.GUARD_STATEMENT}", printed)

    def test_ready_describes_the_media_answer_as_rehearse_does(self):
        from sippycup_cockpit import ready

        model = {"authorization": {}, "files": {}, "profile": {},
                 "target": {"account": {"required": False}}}
        lines = ready.authorizes(model, self.PROFILE, None)
        text = "\n".join(lines)
        self.assertNotIn("media only at", text)
        self.assertNotIn("no extra networks", text)
        self.assertNotIn("Approved addrs", text)
        for line in media_scope.where_lines(self.PROFILE):
            self.assertIn(line, lines)
        self.assertIn(f"Media stop: {media_scope.GUARD_STATEMENT}", lines)

    def test_dry_run_says_where_media_may_go(self):
        lines = guided._media_where(self.PROFILE)
        self.assertEqual(lines[:-1], media_scope.where_lines(self.PROFILE))
        self.assertEqual(lines[-1], f"Media stop: {media_scope.GUARD_STATEMENT}")

    def test_report_states_what_the_guard_dropped(self):
        from sippycup_workbench import summary_model

        result = {"mediaGuard": self.GUARD}
        self.assertEqual(summary_model._guard_dropped(result), {"rtp": 1, "rtcp": 4, "other": 0})
        self.assertEqual(summary_model._sent_after_guard(1, result), 0)
        self.assertEqual(summary_model._sent_after_guard(250, {}), 250)
        self.assertIsNone(summary_model._guard_dropped({"mediaGuard": {"active": False}}))
        detail = summary_model._stop_detail({
            "verdict": "media-outside-scope",
            "details": {"media": {"toPeerPackets": 0, "guardDropped": {"rtp": 1, "rtcp": 4, "other": 0}}},
        })
        self.assertIn("the media guard dropped the 1 RTP and 4 RTCP packets", detail)
        self.assertIn("no media was sent to it", detail)
        # A run from before the guard keeps its own honest sentence.
        old = summary_model._stop_detail({"verdict": "media-outside-scope",
                                          "details": {"media": {"toPeerPackets": 3}}})
        self.assertIn("after 3 RTP packets were sent to it", old)


if __name__ == "__main__":
    unittest.main()
