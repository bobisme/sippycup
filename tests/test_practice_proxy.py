"""Offline tests for the practice proxy (bn-2g0) and the defects it exposed.

- the generated proxy facts, profiles, campaign, and expectations;
- the rendered configuration templates (every placeholder is substituted by
  the entrypoint; the trust between proxy and Asterisk is token plus ACL);
- the oracle reports a Record-Routed dialog captured on two hops as one
  dialog, not as two fork legs with ambiguous media;
- media from the side that did not send BYE is late only after its 2xx;
- the softphone media scope accepts networks (campaign authorization) and
  asks PJSUA for the media peer right after answer;
- the raw probe helper's parsing.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import yaml  # noqa: E402

import practice_proxy_probe as probe  # noqa: E402
from sippycup import practice  # noqa: E402
from sippycup.campaign import compile_plan  # noqa: E402
from sippycup_oracle.dialogs import reconstruct_dialogs  # noqa: E402
from sippycup_oracle.media import (  # noqa: E402
    MediaExpectations,
    evaluate_invariants,
    partition_media_frames,
)
from sippycup_oracle.records import Known, Verdict  # noqa: E402
from sippycup_softphone import SoftphoneCall, SoftphoneError, place_call  # noqa: E402
from sippycup_softphone.campaign_runner import (  # noqa: E402
    EnvelopeError,
    media_networks,
    write_tone,
)
from sippycup_softphone.driver import _media_outside_scope  # noqa: E402
from sippycup_workbench.profile import load_profile, rehearse  # noqa: E402
from tests.oracle.test_dialogs import scenario_frames  # noqa: E402
from tests.oracle.test_media import assertions, baseline_dialog, good_media, rtp_frame  # noqa: E402

LAUNCHER = ROOT / "bin" / "sippycup"
FAKE_PJSUA = ROOT / "tests" / "fixtures" / "fake_pjsua.py"
CALLER = "192.0.2.10"
PROXY = "203.0.113.5"
CALLEE = "198.51.100.20"


def make_project(root: Path) -> Path:
    project = root / "project"
    project.mkdir()
    (project / "examples").symlink_to(ROOT / "examples")
    (project / "media").symlink_to(ROOT / "media")
    (project / "work").mkdir()
    return project


class ProxyPrepareTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.project = make_project(Path(self.temporary.name))
        self.now = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
        self.facts = practice.prepare(
            self.project, address="127.0.0.2", container="c", image="i", now=self.now
        )
        self.state = self.project / "work" / "practice"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_facts_describe_the_proxy_and_its_split_media(self) -> None:
        proxy = self.facts["proxy"]
        self.assertEqual(proxy["address"], "127.0.0.3")
        self.assertEqual(proxy["media_address"], "127.0.0.2")
        self.assertEqual(proxy["approved_addresses"], ["127.0.0.3", "127.0.0.2"])
        self.assertEqual(proxy["signaling"]["tls"], "127.0.0.3:5061")
        self.assertEqual(proxy["account"]["realm"], "sippycup-proxy")
        self.assertNotEqual(proxy["account"]["realm"], self.facts["account"]["realm"])
        self.assertIn("407", proxy["policy"])
        human = practice.render_facts_human(self.facts)
        self.assertIn("Proxy:          127.0.0.3", human)
        self.assertIn("approve both: 127.0.0.3, 127.0.0.2", human)
        self.assertIn("work/practice/target-profile-proxy.yaml", human)
        password = (self.state / "account.password").read_text(encoding="utf-8").strip()
        self.assertNotIn(password, human + json.dumps(self.facts))

    def test_proxy_profiles_approve_signaling_and_media_and_are_ready(self) -> None:
        for name, port, transport in (
            ("target-profile-proxy.yaml", 5060, "udp"),
            ("target-profile-proxy-tls.yaml", 5061, "tls"),
        ):
            with self.subTest(name=name):
                profile = load_profile(self.state / name)
                self.assertEqual(profile["target"]["host"], "127.0.0.3")
                self.assertEqual((profile["target"]["port"], profile["target"]["transport"]), (port, transport))
                self.assertEqual(profile["target"]["approved_addresses"], ["127.0.0.3", "127.0.0.2"])
                ready = rehearse(profile, now=self.now + timedelta(minutes=5))
                self.assertTrue(ready.ready, ready.errors)
        tls = load_profile(self.state / "target-profile-proxy-tls.yaml")
        self.assertEqual(tls["target"]["tls_server_name"], "sippycup-proxy")
        for name in ("target-profile-proxy.template.yaml", "target-profile-proxy-tls.template.yaml"):
            self.assertFalse(rehearse(load_profile(ROOT / "examples" / "practice" / name)).ready)

    def test_proxy_campaign_authorizes_both_networks_with_one_call(self) -> None:
        manifest = yaml.safe_load((self.state / "campaign-proxy.yaml").read_text(encoding="utf-8"))
        self.assertEqual(manifest["authorization"]["networks"], ["127.0.0.3/32", "127.0.0.2/32"])
        self.assertEqual(manifest["authorization"]["ceilings"]["calls"], 1)
        plan = compile_plan(manifest, "0" * 64, resolver=lambda host: [])
        self.assertEqual({item["address"] for item in plan["resolvedDestinations"]}, {"127.0.0.3"})
        self.assertEqual([step["type"] for step in plan["steps"]], ["options", "options", "call"])
        expectations = yaml.safe_load((self.state / "expectations-proxy.yaml").read_text())
        self.assertEqual(
            expectations["capture"]["allowed_endpoints"], ["127.0.0.1", "127.0.0.3", "127.0.0.2"]
        )
        for name in ("campaign-proxy.yaml", "expectations-proxy.yaml", "target-profile-proxy.yaml"):
            self.assertNotRegex((self.state / name).read_text(), r"@[A-Z_]+@")

    def test_proxy_address_must_differ_from_the_practice_address(self) -> None:
        with self.assertRaises(practice.PracticeError):
            practice.prepare(self.project, address="127.0.0.3", container="c", image="i")
        with self.assertRaises(practice.PracticeError):
            practice.prepare(
                self.project, address="127.0.0.2", container="c", image="i", proxy_address="10.0.0.1"
            )
        facts = practice.prepare(
            self.project, address="127.0.0.5", container="c", image="i", proxy_address="127.0.0.6"
        )
        self.assertEqual(facts["proxy"]["approved_addresses"], ["127.0.0.6", "127.0.0.5"])


class ProxyLauncherTests(unittest.TestCase):
    def run_practice(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [LAUNCHER, "practice-target", *arguments], cwd=ROOT,
            env={**os.environ, "SIPPYCUP_RUNTIME": "/definitely/missing/runtime"},
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False,
        )

    def test_help_names_the_proxy_option(self) -> None:
        self.assertIn("--proxy-address", self.run_practice("help").stdout)

    def test_up_refuses_an_unsafe_or_colliding_proxy_address_before_any_side_effect(self) -> None:
        for arguments in (
            ("--proxy-address", "192.0.2.10"),
            ("--proxy-address", "127.0.0.1"),
            ("--proxy-address", "127.0.0.2"),
            ("--address", "127.0.0.3"),
        ):
            with self.subTest(arguments=arguments):
                result = self.run_practice("up", *arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn("No supported container runtime", result.stderr)


class ProxyTemplateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.entrypoint = (ROOT / "practice-target" / "entrypoint").read_text(encoding="utf-8")
        self.kamailio = (ROOT / "practice-target" / "kamailio" / "kamailio.cfg").read_text(encoding="utf-8")
        self.pjsip = (ROOT / "practice-target" / "asterisk" / "pjsip.conf").read_text(encoding="utf-8")

    def test_every_placeholder_is_rendered_by_the_entrypoint(self) -> None:
        rendered = set(re.findall(r"text//(@[A-Z_]+@)/", self.entrypoint))
        templates = [
            *sorted((ROOT / "practice-target" / "asterisk").glob("*.conf")),
            *sorted((ROOT / "practice-target" / "kamailio").glob("*.cfg")),
        ]
        for path in templates:
            with self.subTest(path=path.name):
                used = set(re.findall(r"@[A-Z_]+@", path.read_text(encoding="utf-8")))
                self.assertLessEqual(used, rendered)

    def test_proxy_challenges_with_407_record_routes_and_strips_the_trunk_header(self) -> None:
        for fragment in (
            'pv_proxy_authenticate("PROXY_REALM"',
            'pv_www_authenticate("PROXY_REALM"',
            "record_route();",
            "loose_route()",
            "consume_credentials();",
            "listen=tls:@PROXY_ADDRESS@:5061",
            "tcp_source_ipv4=@PROXY_ADDRESS@",
            "sip:@ADDRESS@:5061;transport=tls",
        ):
            self.assertIn(fragment, self.kamailio)
        request_route = self.kamailio.split("request_route {", 1)[1]
        self.assertLess(request_route.index('remove_hf("X-Sippycup-Trunk")'), request_route.index("route(WITHINDLG)"))
        self.assertIn('sl_send_reply("404", "Not Here: In-Dialog Request Without Route")', self.kamailio)

    def test_asterisk_trusts_only_the_token_from_the_proxy_address(self) -> None:
        self.assertIn("endpoint_identifier_order = header,username,ip", self.pjsip)
        trunk = self.pjsip.split("; ==== BEGIN proxy trunk (bn-2g0) ====", 1)[1]
        endpoint = trunk.split("[proxy-trunk]\ntype = identify", 1)[0]
        self.assertIn("identify_by = header", endpoint)
        self.assertIn("deny = 0.0.0.0/0.0.0.0", endpoint)
        self.assertIn("permit = @PROXY_ADDRESS@/255.255.255.255", endpoint)
        self.assertNotIn("\nauth =", endpoint)
        self.assertIn("match_header = X-Sippycup-Trunk: @TRUNK_TOKEN@", trunk)
        self.assertIn('trunk_token="$(openssl rand -hex 24)"', self.entrypoint)
        self.assertIn("unset password trunk_token", self.entrypoint)


class RecordRoutedDialogTests(unittest.TestCase):
    """bn-2g0 defect: a proxied dialog seen on both hops became two 'fork legs'."""

    def proxied(self):
        caller_hop = scenario_frames("baseline", caller_address=CALLER, callee_address=PROXY, start=1)
        next_hop = scenario_frames("baseline", caller_address=PROXY, callee_address=CALLEE, start=7)
        return caller_hop + next_hop

    def test_relayed_hop_is_merged_into_one_dialog_of_the_caller_hop(self) -> None:
        result = reconstruct_dialogs(self.proxied())
        self.assertEqual(len(result.dialogs), 1)
        dialog = result.dialogs[0]
        self.assertEqual(dialog.caller.address, Known(CALLER))
        self.assertEqual(dialog.callee.address, Known(PROXY))
        self.assertEqual(dialog.complete, Known(True))
        # Only the caller hop's offer and answer, not the relayed copies.
        self.assertEqual(len(dialog.sdp_revisions), 2)

    def test_media_of_a_proxied_dialog_is_assigned_and_bidirectional(self) -> None:
        dialogs = reconstruct_dialogs(self.proxied()).dialogs
        assigned, ambiguity = partition_media_frames(good_media(), dialogs)
        result = assertions(evaluate_invariants(
            assigned[0], dialogs[0], MediaExpectations(), assignment_ambiguity=ambiguity[0]
        ))
        self.assertEqual(result["media.assignment"].verdict, Verdict.PASS)
        self.assertEqual(result["media.directionality"].verdict, Verdict.PASS)

    def test_unrelated_flows_with_the_same_call_id_are_not_merged(self) -> None:
        # The same Call-ID and From tag sent by the caller to a second server
        # (not relayed by the first one) stays a separate dialog.
        other = scenario_frames("baseline", caller_address=CALLER, callee_address="198.51.100.99", start=7)
        caller_hop = scenario_frames("baseline", caller_address=CALLER, callee_address=PROXY, start=1)
        self.assertEqual(len(reconstruct_dialogs(caller_hop + other).dialogs), 2)


class TeardownTimingTests(unittest.TestCase):
    """bn-2g0 defect: RTP in flight while the BYE crossed the proxy failed timing."""

    def timing(self, *extra):
        result = assertions(evaluate_invariants(good_media() + extra, baseline_dialog()))
        return result["media.timing"]

    def test_peer_media_before_its_bye_response_is_not_late(self) -> None:
        # Baseline: the caller sends BYE at 0.5 s; the peer's 200 is at 0.6 s.
        timing = self.timing(rtp_frame(300, "0.55", caller_to_callee=False, sequence=12, timestamp=320))
        self.assertEqual(timing.verdict, Verdict.PASS)

    def test_peer_media_after_accepting_the_bye_is_late(self) -> None:
        timing = self.timing(rtp_frame(301, "0.90", caller_to_callee=False, sequence=12, timestamp=320))
        self.assertEqual(timing.verdict, Verdict.FAIL)
        self.assertEqual({item.frame_number.value for item in timing.evidence}, {301})

    def test_bye_sender_media_after_its_bye_is_still_late(self) -> None:
        timing = self.timing(rtp_frame(302, "0.55", caller_to_callee=True, sequence=4, timestamp=480))
        self.assertEqual(timing.verdict, Verdict.FAIL)


class MediaScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name)
        self.play = self.root / "play.wav"
        write_tone(self.play, seconds=0.5)

    def tearDown(self) -> None:
        self._directory.cleanup()

    def call(self, **values) -> SoftphoneCall:
        defaults = {
            "destination": "echo", "host": "192.0.2.10", "port": 5060, "transport": "udp",
            "play_file": self.play, "record_file": self.root / "heard.wav", "duration_seconds": 2,
            "log_file": self.root / "softphone.log", "console_file": self.root / "console.txt",
        }
        defaults.update(values)
        return SoftphoneCall(**defaults)

    def test_networks_extend_the_media_scope(self) -> None:
        call = self.call(allowed_media_addresses=("127.0.0.3",),
                         allowed_media_networks=("127.0.0.2/32",))
        self.assertFalse(_media_outside_scope(call, "127.0.0.2:20004"))
        self.assertFalse(_media_outside_scope(call, "127.0.0.3:20004"))
        self.assertTrue(_media_outside_scope(call, "127.0.0.4:20004"))
        only_networks = self.call(allowed_media_networks=("10.0.0.0/24",))
        self.assertFalse(_media_outside_scope(only_networks, "10.0.0.77:4000"))
        self.assertTrue(_media_outside_scope(only_networks, "10.0.1.1:4000"))
        # Without networks the address list alone decides, as before.
        self.assertTrue(_media_outside_scope(self.call(allowed_media_addresses=("127.0.0.3",)), "127.0.0.2:1"))

    def test_invalid_network_is_refused_before_pjsua_starts(self) -> None:
        call = self.call(allowed_media_networks=("not-a-network",))
        with self.assertRaises(SoftphoneError):
            place_call(call, pjsua=str(FAKE_PJSUA), private_root=self.root)

    def test_campaign_context_networks_become_the_media_networks(self) -> None:
        context = {"authorization": {"networks": ["127.0.0.3/32", "127.0.0.2/32"]}}
        self.assertEqual(media_networks(context), ("127.0.0.3/32", "127.0.0.2/32"))
        self.assertIsNone(media_networks({"authorization": {}}))
        for bad in ("127.0.0.2/32", ["127.0.0.2/8"], [7]):
            with self.subTest(bad=bad), self.assertRaises(EnvelopeError):
                media_networks({"authorization": {"networks": bad}})

    def test_scope_stop_asks_for_the_media_peer_right_after_answer(self) -> None:
        witness = self.root / "witness.json"
        private = self.root / "private"
        private.mkdir()
        environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                       "FAKE_PJSUA_WITNESS": str(witness), "FAKE_PJSUA_MODE": "outside"}
        result = place_call(
            self.call(duration_seconds=20, allowed_media_addresses=("192.0.2.10",)),
            pjsua=str(FAKE_PJSUA), environment=environment, private_root=private,
        )
        self.assertEqual(result.error, "media_peer_outside_scope")
        # The hang-up follows the first call dump, sent at CONFIRMED rather
        # than after the 0.5 s quality delay.
        states = {item["state"]: item["at"] for item in result.timeline}
        self.assertLess(states["DISCONNECTED"] - states["CONFIRMED"], 0.45)
        commands = json.loads(witness.read_text())["commands"]
        self.assertEqual(commands[2:4], ["dq", "h"])


class ProbeParsingTests(unittest.TestCase):
    def test_status_header_and_challenge_parsing(self) -> None:
        response = (
            "SIP/2.0 407 Proxy Authentication Required\r\nCall-ID: abc@127.0.0.1\r\n"
            'Proxy-Authenticate: Digest realm="sippycup-proxy", nonce="n1", qop="auth"\r\n\r\n'
        )
        self.assertEqual(probe._status(response), 407)
        self.assertEqual(probe._header(response, "call-id"), "abc@127.0.0.1")
        self.assertEqual(
            probe._challenge(response, "Proxy-Authenticate"),
            {"realm": "sippycup-proxy", "nonce": "n1", "qop": "auth"},
        )
        self.assertIsNone(probe._status("INVITE sip:x SIP/2.0\r\n"))


if __name__ == "__main__":
    unittest.main()
