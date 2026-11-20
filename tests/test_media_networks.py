"""Owner-approved media networks (bn-1qm): media only, never signaling.

Every layer that enforces or judges media scope: the profile field and its
breadth rule (rehearse), scope compile/check/questions, the softphone
driver's decision, the guided call (and so the matrix), srtp-policy and the
checks capture, evidence privacy, the owner report, the practice-approval
rule, the ladder, the cockpit, and the dress rehearsal's answers. Negative
cases: a peer just outside the network stops, a media network never admits
a signaling target, and an over-broad network is refused before any packet.
"""

from __future__ import annotations

import contextlib
import io
import ipaddress
import json
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from sippycup_softphone import SoftphoneCall, SoftphoneResult  # noqa: E402
from sippycup_softphone.driver import _media_outside_scope, media_scope_decision  # noqa: E402
from sippycup_workbench import call as guided  # noqa: E402
from sippycup_workbench import cli  # noqa: E402
from sippycup_workbench.media_scope import (  # noqa: E402
    MediaScope,
    profile_media,
    profile_scope,
    validate_networks,
)
from sippycup_workbench.profile import approved_codecs, host_is_approved_literal, rehearse  # noqa: E402
from sippycup_workbench.scope import inspect  # noqa: E402
from sippycup_workbench.scope_derive import compile_scope  # noqa: E402
from sippycup_workbench.scope_questions import render_questions  # noqa: E402
from sippycup_workbench.summary_model import Options, build_report  # noqa: E402
from sippycup_workbench.summary_practice import is_practice_approval  # noqa: E402
from sippycup_workbench.summary_privacy import AddressBook  # noqa: E402

from test_guided_call import NOW, Fakes, GuidedCallCase, profile_document  # noqa: E402
from test_scope import complete_scope  # noqa: E402

POOL = "192.0.2.32/27"          # owner-approved media pool (192.0.2.32 - .63)
INSIDE = "192.0.2.40"
JUST_OUTSIDE = "192.0.2.64"      # the first address after the pool
SIGNALING = "192.0.2.10"


def media_profile(**media):
    document = profile_document()
    document["media"] = media or {"networks": [POOL], "port_range": {"start": 10000, "end": 20000}}
    return document


def call_for(**values) -> SoftphoneCall:
    defaults = dict(
        destination="echo", host=SIGNALING, port=5060, transport="udp", play_file=Path("p.wav"),
        record_file=Path("h.wav"), duration_seconds=5, log_file=Path("l.log"),
        allowed_media_addresses=(SIGNALING, "192.0.2.11"), allowed_media_networks=(POOL,),
        allowed_media_ports=(10000, 20000),
    )
    defaults.update(values)
    return SoftphoneCall(**defaults)


class BreadthRuleTests(unittest.TestCase):
    def check(self, value):
        errors: list[str] = []
        return validate_networks(value, errors), errors

    def test_plausible_pools_are_accepted_and_canonical(self):
        for value in (["192.0.2.32/27"], ["10.0.0.0/22"], ["10.0.0.0/24", "10.0.4.0/24"],
                      ["192.0.2.7/32"], ["2001:db8::/118"], [" 10.1.0.0/24 "]):
            with self.subTest(value=value):
                result, errors = self.check(value)
                self.assertEqual(errors, [])
                self.assertEqual(result, [str(ipaddress.ip_network(item.strip())) for item in value])

    def test_over_broad_and_unsafe_networks_are_refused_with_what_to_ask(self):
        cases = {
            "0.0.0.0/0": "addresses",
            "10.0.0.0/21": "2048 addresses",
            "10.0.0.0/8": "more than the 1024",
            "2001:db8::/64": "IPv6 /118",
            "224.0.0.0/24": "multicast",
            "0.0.0.0/24": "unspecified",
            "240.0.0.0/24": "reserved",
            "255.255.255.0/24": "broadcast",
            "ff02::/120": "multicast",
        }
        for value, needle in cases.items():
            with self.subTest(value=value):
                result, errors = self.check([value])
                self.assertIsNone(result)
                self.assertEqual(len(errors), 1, errors)
                self.assertIn(needle, errors[0])
                if value != "0.0.0.0/0" or "ask the owner" in errors[0]:
                    self.assertIn("ask the owner", errors[0])

    def test_host_bits_duplicates_totals_and_counts_are_refused(self):
        self.assertIn("write the network address 192.0.2.32/27", self.check(["192.0.2.40/27"])[1][0])
        self.assertIn("listed twice", " ".join(self.check(["10.0.0.0/24", "10.0.0.0/24"])[1]))
        result, errors = self.check(["10.0.0.0/22", "10.0.4.0/24"])
        self.assertIsNone(result)
        self.assertIn("together hold 1280 addresses", errors[0])
        self.assertIn("more than 16", self.check([f"10.0.{n}.0/28" for n in range(17)])[1][0])
        for bad in ([], "10.0.0.0/24", [7], ["not-a-network"]):
            self.assertIsNone(self.check(bad)[0], bad)


class ProfileTests(unittest.TestCase):
    def test_media_networks_and_ports_without_codecs_are_ready_and_shown(self):
        result = rehearse(media_profile(), now=NOW)
        self.assertTrue(result.ready, result.errors)
        self.assertEqual(result.facts["media_networks"], [POOL])
        self.assertEqual(result.facts["media_ports"], {"start": 10000, "end": 20000})
        self.assertNotIn("approved_codecs", result.facts)
        self.assertIsNone(approved_codecs(media_profile()))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli._emit(result.as_dict(), "human")
        text = out.getvalue()
        self.assertIn("Ready: yes", text)
        self.assertIn(f"Media only: {POOL} (32 addresses) (owner-approved media networks; never a signaling target)",
                      text)
        self.assertIn("Signaling and media: 192.0.2.10, 192.0.2.11", text)
        self.assertIn("Media ports: 10000-20000", text)

    def test_old_profiles_are_unchanged(self):
        plain = rehearse(profile_document(), now=NOW)
        self.assertTrue(plain.ready)
        self.assertNotIn("media_networks", plain.facts)
        codecs = profile_document()
        codecs["media"] = {"codecs": ["PCMU"]}
        self.assertEqual(rehearse(codecs, now=NOW).facts["approved_codecs"], ("PCMU",))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli._emit(plain.as_dict(), "human")
        self.assertNotIn("Media only", out.getvalue())

    def test_over_broad_network_is_refused_by_rehearse(self):
        result = rehearse(media_profile(networks=["10.0.0.0/16"]), now=NOW)
        self.assertFalse(result.ready)
        self.assertTrue(any("65536 addresses" in e and "ask the owner" in e for e in result.errors), result.errors)
        self.assertFalse(rehearse(media_profile(networks=["0.0.0.0/0"]), now=NOW).ready)

    def test_malformed_media_sections_are_refused(self):
        for media in ({}, {"networks": []}, {"port_range": {"start": 20000, "end": 10000}},
                      {"port_range": {"start": 1}}, {"networks": [POOL], "extra": 1}, {"codecs": []}):
            with self.subTest(media=media):
                document = profile_document()
                document["media"] = media
                self.assertFalse(rehearse(document, now=NOW).ready)

    def test_a_media_network_never_makes_the_host_a_literal_approved_address(self):
        document = media_profile()
        document["target"]["host"] = INSIDE
        self.assertFalse(host_is_approved_literal(document))
        errors = guided.gate(document, now=NOW, planned_seconds=60)
        self.assertIn("guided calls require target.host itself to be one of the literal approved_addresses", errors)

    def test_profile_media_reader_never_widens_on_bad_input(self):
        self.assertEqual(profile_media(media_profile(networks=["10.0.0.0/8"], port_range={"start": 10000, "end": 20000})),
                         ((), (10000, 20000)))
        self.assertEqual(profile_media({"media": "x"}), ((), None))
        scope = profile_scope(media_profile())
        self.assertEqual(scope.rule(SIGNALING), ("approved-address", None))
        self.assertEqual(scope.rule(INSIDE), ("media-network", POOL))
        self.assertIsNone(scope.rule(JUST_OUTSIDE))
        self.assertEqual(len(MediaScope((), ("10.0.0.0/30",)).enumerate()), 4)

    def test_schema_describes_the_new_fields(self):
        schema = json.loads((ROOT / "schemas" / "target-profile-v1.schema.json").read_text())
        media = schema["properties"]["media"]
        # addresses: the owner's media answer, written by scope compile (wave 10).
        self.assertEqual(set(media["properties"]), {"codecs", "networks", "port_range", "addresses"})
        self.assertNotIn("required", media)
        self.assertIn("MEDIA ONLY", media["description"])


class DriverDecisionTests(unittest.TestCase):
    def test_rules_and_which_one_admitted_the_peer(self):
        call = call_for()
        literal = media_scope_decision(call, f"{SIGNALING}:10002")
        self.assertEqual((literal["admittedBy"], literal["network"], literal["inScope"]),
                         ("approved-address", None, True))
        network = media_scope_decision(call, f"{INSIDE}:10002")
        self.assertEqual((network["admittedBy"], network["network"], network["inScope"]),
                         ("media-network", POOL, True))
        self.assertEqual(network["rules"]["mediaNetworks"], [POOL])
        self.assertFalse(_media_outside_scope(call, f"{INSIDE}:10002"))

    def test_peer_just_outside_the_network_stops(self):
        call = call_for()
        decision = media_scope_decision(call, f"{JUST_OUTSIDE}:10002")
        self.assertIsNone(decision["admittedBy"])
        self.assertFalse(decision["inScope"])
        self.assertTrue(_media_outside_scope(call, f"{JUST_OUTSIDE}:10002"))
        self.assertTrue(_media_outside_scope(call, "192.0.2.31:10002"))  # just below the pool

    def test_port_outside_the_range_stops_even_inside_the_network(self):
        call = call_for()
        decision = media_scope_decision(call, f"{INSIDE}:9999")
        self.assertEqual((decision["admittedBy"], decision["portAdmitted"], decision["inScope"]),
                         ("media-network", False, False))
        self.assertTrue(_media_outside_scope(call, f"{INSIDE}:20001"))

    def test_unknown_peer_and_no_scope(self):
        self.assertIsNone(media_scope_decision(call_for(), "-")["inScope"])
        self.assertFalse(_media_outside_scope(call_for(), None))
        bare = call_for(allowed_media_addresses=None, allowed_media_networks=None, allowed_media_ports=None)
        self.assertIsNone(media_scope_decision(bare, f"{INSIDE}:1"))
        ports_only = call_for(allowed_media_addresses=None, allowed_media_networks=None)
        self.assertEqual(media_scope_decision(ports_only, f"{INSIDE}:10000")["admittedBy"], "any-address")

    def test_a_network_of_the_other_family_never_matches(self):
        call = call_for(allowed_media_addresses=(SIGNALING,), allowed_media_networks=("2001:db8::/120",))
        self.assertTrue(_media_outside_scope(call, f"{INSIDE}:10002"))


class GuidedCallTests(GuidedCallCase):
    def test_call_passes_networks_and_ports_and_records_the_rule(self):
        self.write_profile(media_profile())

        def answered(call, cancel):
            result = SoftphoneResult(destination_uri="sip:x")
            result.started = result.dialed = result.answered = True
            result.final_status = result.disconnect_status = 200
            result.rtp_tx_packets, result.rtp_rx_packets = 200, 199
            result.codec, result.connected_seconds, result.hangup = "PCMU", 4.0, "duration"
            result.media_peer = f"{INSIDE}:10002"
            return result

        fakes = Fakes(softphone=answered)
        code, value = self.run_call(fakes)
        self.assertEqual(code, 0, value)
        call = fakes.softphone_call
        self.assertEqual(call.allowed_media_addresses, ("192.0.2.10", "192.0.2.11"))
        self.assertEqual(call.allowed_media_networks, (POOL,))
        self.assertEqual(call.allowed_media_ports, (10000, 20000))
        self.assertEqual(call.host, SIGNALING)
        self.assertEqual(fakes.preflight_destination["address"], SIGNALING)
        self.assertEqual(value["mediaScope"]["admittedBy"], "media-network")
        self.assertEqual(value["mediaScope"]["network"], POOL)
        self.assertIn(f"admitted by the approved media network {POOL} (media only)", guided.render_human(value))
        (run_dir,) = self.run_directories()
        result = json.loads((run_dir / "result.json").read_text())
        self.assertEqual(result["mediaScope"]["admittedBy"], "media-network")
        profile = json.loads((run_dir / "profile.json").read_text())
        self.assertEqual(profile["media"]["networks"], [POOL])
        plan = json.loads((run_dir / "plan.json").read_text())
        self.assertEqual(plan["authorization"]["media_networks"], [POOL])
        self.assertEqual(plan["authorization"]["media_ports"], {"start": 10000, "end": 20000})
        self.assertNotIn(POOL, plan["authorization"]["networks"])
        self.assertEqual(plan["softphone"]["media_scope"]["media_networks"], [POOL])
        self.assertIn(f"net {POOL}", fakes.capture_argv[-1])
        expectations = yaml.safe_load((run_dir / "expectations.yaml").read_text())
        endpoints = expectations["capture"]["allowed_endpoints"]
        self.assertIn(INSIDE, endpoints)
        self.assertNotIn(JUST_OUTSIDE, endpoints)
        self.assertEqual(len(endpoints), 2 + 1 + 32)

    def test_peer_outside_both_rules_still_stops(self):
        self.write_profile(media_profile())

        def stopped(call, cancel):
            result = SoftphoneResult(destination_uri="sip:x")
            result.started = result.dialed = result.answered = True
            result.final_status = 200
            result.media_peer = f"{JUST_OUTSIDE}:10002"
            result.error = "media_peer_outside_scope"
            result.rtp_tx_packets = 3
            return result

        code, value = self.run_call(Fakes(softphone=stopped))
        self.assertEqual(code, 1)
        self.assertEqual(value["verdict"], "media-outside-scope")
        self.assertIsNone(value["mediaScope"]["admittedBy"])
        self.assertFalse(value["mediaScope"]["inScope"])
        self.assertIn("not an approved address and not inside an approved media network", " ".join(value["notes"]))

    def test_old_profile_call_is_unchanged(self):
        fakes = Fakes()
        code, value = self.run_call(fakes)
        self.assertEqual(code, 0, value)
        self.assertIsNone(fakes.softphone_call.allowed_media_networks)
        self.assertIsNone(fakes.softphone_call.allowed_media_ports)
        self.assertNotIn(" net ", fakes.capture_argv[-1])
        self.assertEqual(fakes.capture_argv[-1], "(host 192.0.2.10 or host 192.0.2.11) and (udp port 5060 or udp)")

    def test_signaling_to_an_address_inside_the_media_network_is_refused_before_any_packet(self):
        document = media_profile()
        document["target"]["host"] = INSIDE
        self.write_profile(document)
        fakes = Fakes()
        code, value = self.run_call(fakes)
        self.assertEqual(code, 2)
        self.assertEqual(value["state"], "blocked")
        self.assertEqual(fakes.events, [])
        self.assertEqual(self.run_directories(), [])

    def test_silent_far_end_with_sdp_inside_the_network_is_not_a_scope_breach(self):
        self.assertTrue(guided._peer_unknown_but_approved({"media_peer": None}, [SIGNALING], [INSIDE], [POOL]))
        self.assertFalse(guided._peer_unknown_but_approved({"media_peer": None}, [SIGNALING], [JUST_OUTSIDE], [POOL]))
        self.assertFalse(guided._peer_unknown_but_approved({"media_peer": None}, [SIGNALING], [INSIDE]))

    def test_capture_filter_adds_media_networks_for_udp_only(self):
        self.assertEqual(
            guided.capture_filter([SIGNALING], 5061, "tls", [POOL]),
            f"((host {SIGNALING}) and (tcp port 5061 or udp)) or ((net {POOL}) and udp)",
        )


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name) / "assessment"
        self.root.mkdir(mode=0o700)

    def write(self, document):
        path = self.root / "scope.yaml"
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        path.chmod(0o600)

    def test_compile_writes_media_networks_and_ports_and_says_so(self):
        self.write(complete_scope())
        result = compile_scope(self.root, now=datetime(2026, 11, 20, 12, tzinfo=timezone.utc))
        self.assertEqual(result.exit_code, 0, result.as_dict())
        profile = yaml.safe_load((self.root / "target-profile.yaml").read_text())
        self.assertEqual(profile["target"]["approved_addresses"], ["10.20.30.40"])
        self.assertEqual(profile["media"]["networks"], ["10.20.31.0/28"])
        self.assertEqual(profile["media"]["port_range"], {"start": 10000, "end": 10100})
        self.assertEqual(profile["media"]["codecs"], ["PCMU", "PCMA"])
        notes = " ".join(result.notes)
        self.assertIn("10.20.31.0/28 (16 addresses) are in the profile's media.networks", notes)
        self.assertIn("media only; signaling still goes only to the literal target.host", notes)
        self.assertNotIn("ask the owner for the literal media addresses", notes)
        self.assertTrue(rehearse(profile, now=datetime(2026, 11, 20, 12, tzinfo=timezone.utc)).ready)

    def test_scope_check_refuses_a_media_range_the_profile_cannot_carry(self):
        document = complete_scope()
        document["media"]["networks"] = ["10.20.0.0/21"]
        self.write(document)
        report = inspect(self.root / "scope.yaml", now=datetime(2026, 11, 20, 12, tzinfo=timezone.utc))
        broad = [item for item in report.findings if item.code == "scope.media_network_too_broad"]
        self.assertEqual(len(broad), 1)
        self.assertIn("ask the owner", broad[0].message)
        self.assertEqual(broad[0].blocks, ("profile",))
        result = compile_scope(self.root, now=datetime(2026, 11, 20, 12, tzinfo=timezone.utc))
        self.assertIn("profile", result.skipped)
        self.assertFalse((self.root / "target-profile.yaml").exists())
        self.assertTrue((self.root / "campaign.yaml").exists())

    def test_scope_check_warns_about_a_wide_but_acceptable_range(self):
        document = complete_scope()
        document["media"]["networks"] = ["10.20.32.0/23"]
        self.write(document)
        report = inspect(self.root / "scope.yaml", now=datetime(2026, 11, 20, 12, tzinfo=timezone.utc))
        wide = [item for item in report.findings if item.code == "scope.media_network_wide"]
        self.assertEqual([item.severity for item in wide], ["warning"])
        self.assertIn("512 addresses", wide[0].message)

    def test_questions_ask_for_media_ranges_and_far_end_ports(self):
        text = render_questions()
        self.assertIn("media-server pool as a range in CIDR form", text)
        self.assertIn("never signaling", text)
        self.assertIn("1024 addresses (IPv4 /22 or narrower)", text)
        self.assertIn("the far-end UDP ports we will send media to", text)


class ChecksTests(unittest.TestCase):
    def test_srtp_policy_calls_carry_the_media_networks(self):
        from sippycup_checks import srtpcheck
        from sippycup_checks.checks import Budget, Context, Endpoint

        seen: list[SoftphoneCall] = []

        def place(call, **_kwargs):
            seen.append(call)
            result = SoftphoneResult(destination_uri="sip:x")
            result.started = True
            result.final_status = 488
            return result

        with tempfile.TemporaryDirectory() as directory:
            context = Context(
                endpoint=Endpoint(SIGNALING, 5060, "udp", domain=SIGNALING),
                section={"account": "a", "destination": "echo", "cleartext_endpoints": []},
                budget=Budget(total_limit=100, interval=0, monotonic=lambda: 0.0, sleep=lambda _s: None,
                              should_stop=lambda: None),
                approved_addresses=(SIGNALING,), media_networks=(POOL,), media_ports=(10000, 20000),
                place_call=place, run_dir=Path(directory), local_address="10.0.2.100",
            )
            context.budget.begin(srtpcheck.CHECK, 100)
            srtpcheck.run(context)
        self.assertTrue(seen)
        for call in seen:
            self.assertEqual(call.host, SIGNALING)
            self.assertEqual(call.allowed_media_networks, (POOL,))
            self.assertEqual(call.allowed_media_ports, (10000, 20000))

    def test_checks_capture_filter(self):
        from sippycup_checks.runner import capture_filter

        self.assertEqual(capture_filter([SIGNALING]), f"(host {SIGNALING}) and (tcp or udp)")
        self.assertEqual(capture_filter([SIGNALING], [POOL]),
                         f"((host {SIGNALING}) and (tcp or udp)) or ((net {POOL}) and udp)")


class EvidenceTests(unittest.TestCase):
    def test_plan_media_networks_are_expected_addresses(self):
        from sippycup.evidence import EvidenceError, _authorized_networks

        networks = _authorized_networks({"authorization": {"networks": ["192.0.2.10/32"],
                                                           "media_networks": [POOL]}}, [])
        self.assertIn(ipaddress.ip_network(POOL), networks)
        with self.assertRaises(EvidenceError):
            _authorized_networks({"authorization": {"networks": [], "media_networks": "x"}}, [])


class ReportTests(unittest.TestCase):
    FIXTURE = ROOT / "tests" / "fixtures" / "engagement-report" / "practice"
    PASS_CALL = "20261118T025420.201700Z-sippycup-local-practice-c956ec1d"

    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        # The fixture records the practice bench, made before the call
        # ledger: its calls ran under the bench budget, so it lives where the
        # bench lives (an engagement elsewhere counts its calls, bn-y3er).
        self.root = Path(self._temporary.name) / "work" / "practice"
        shutil.copytree(self.FIXTURE, self.root)
        self.result_path = self.root / "calls" / self.PASS_CALL / "result.json"

    def edit_result(self, change):
        value = json.loads(self.result_path.read_text())
        change(value)
        self.result_path.write_text(json.dumps(value))

    def add_media_network(self, network="127.0.0.48/28"):
        path = self.root / "target-profile.yaml"
        document = yaml.safe_load(path.read_text())
        document["media"] = {"networks": [network]}
        path.write_text(yaml.safe_dump(document))

    def model(self):
        model, _ = build_report(self.root, Options(generated_at="2026-11-18T04:00:00Z"))
        return model

    def run_of(self, model):
        return next(item for item in model["runs"] if item["id"] == self.PASS_CALL)

    def codes(self, model):
        return {(item["code"], item.get("run")) for item in model["integrityExceptions"]}

    def test_peer_outside_every_rule_is_flagged(self):
        self.edit_result(lambda v: v["softphone"].update(media_peer="127.0.0.50:20000"))
        model = self.model()
        self.assertIn(("media-peer-not-approved", self.PASS_CALL), self.codes(model))
        self.assertIsNone(self.run_of(model)["details"]["media"]["peerApprovedBy"])

    def test_peer_inside_an_approved_media_network_is_approved_for_media(self):
        self.add_media_network()
        self.edit_result(lambda v: (v["softphone"].update(media_peer="127.0.0.50:20000"),
                                    v.update(mediaScope={"admittedBy": "media-network",
                                                         "network": "127.0.0.48/28"})))
        model = self.model()
        self.assertEqual(model["integrityExceptions"], [])
        media = self.run_of(model)["details"]["media"]
        self.assertEqual((media["peer"], media["peerApproved"], media["peerApprovedBy"], media["peerRecordedRule"]),
                         ("127.0.0.50", True, "media-network", "media-network"))
        self.assertEqual(model["authorization"]["mediaOnlyNetworks"], ["127.0.0.48/28"])
        self.assertEqual(self.run_of(model)["details"]["media"]["peerApproved"], True)

    def test_a_media_network_never_approves_a_signaling_target(self):
        self.add_media_network()
        self.edit_result(lambda v: v["target"].update(host="127.0.0.50"))
        model = self.model()
        self.assertIn(("target-not-approved", self.PASS_CALL), self.codes(model))
        self.assertFalse(self.run_of(model)["target"]["approvedAddress"])
        # Shown (approved for evidence), not pseudonymized.
        self.assertEqual(self.run_of(model)["target"]["address"], "127.0.0.50")

    def test_manifest_copy_of_a_scope_media_network_stays_media_only(self):
        scope = complete_scope()
        scope["media"]["networks"] = ["127.0.0.48/28"]
        scope["signaling"]["networks"] = ["127.0.0.2"]
        (self.root / "scope.yaml").write_text(yaml.safe_dump(scope))
        manifest = yaml.safe_load((self.root / "campaign.yaml").read_text())
        manifest["authorization"]["networks"] = ["127.0.0.2/32", "127.0.0.48/28"]
        (self.root / "campaign.yaml").write_text(yaml.safe_dump(manifest))
        self.edit_result(lambda v: v["target"].update(host="127.0.0.50"))
        model = self.model()
        self.assertIn(("target-not-approved", self.PASS_CALL), self.codes(model))

    def test_address_book_roles(self):
        book = AddressBook()
        book.add_network("192.0.2.10")
        book.add_network(POOL, media_only=True)
        self.assertTrue(book.approved(INSIDE))
        self.assertFalse(book.approved_for_signaling(INSIDE))
        self.assertTrue(book.approved_for_signaling(SIGNALING))
        self.assertEqual(book.label(INSIDE), INSIDE)
        self.assertEqual(book.label(JUST_OUTSIDE), "unapproved-address-1")


class PracticeApprovalTests(unittest.TestCase):
    def approval(self, networks=None):
        document = {
            "schema_version": "sippycup.dev/target-profile/v1",
            "authorization": {"approval_id": "LOCAL-PRACTICE-ONLY"},
            "target": {"host": "127.0.0.2", "approved_addresses": ["127.0.0.2"]},
        }
        if networks is not None:
            document["media"] = {"networks": networks}
        return document

    def test_only_loopback_practice_networks_keep_the_practice_label(self):
        self.assertTrue(is_practice_approval(self.approval()))
        self.assertTrue(is_practice_approval(self.approval(["127.0.0.2/31"])))
        for networks in (["10.0.0.0/24"], ["127.0.0.0/31"], ["127.0.0.0/8"], "127.0.0.2/31", ["x"]):
            with self.subTest(networks=networks):
                self.assertFalse(is_practice_approval(self.approval(networks)))


class LadderAndCockpitTests(unittest.TestCase):
    def test_ladder_reads_media_networks_from_the_run_profile(self):
        from sippycup_ladder.inputs import resolve

        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            (run / "softphone.log").write_text("log\n")
            (run / "profile.json").write_text(json.dumps(media_profile()))
            inputs = resolve(str(run))
        self.assertIn(POOL, inputs.approved)

    def test_cockpit_target_summary_and_line_show_media_networks(self):
        from sippycup_cockpit import model as cockpit
        from sippycup_cockpit.render import _target_line

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target-profile.yaml"
            path.write_text(yaml.safe_dump(media_profile()))
            facts = cockpit._profile_facts(path, Path(directory), NOW)
        self.assertEqual(facts["mediaNetworks"], [POOL])
        summary = cockpit._target_summary(facts, {})
        self.assertEqual(summary["mediaNetworks"], [POOL])
        self.assertEqual(summary["approvedAddresses"], ["192.0.2.10", "192.0.2.11"])
        self.assertIn(f"media also from {POOL} (media only)", _target_line(summary))

    def test_cockpit_run_facts_name_the_rule(self):
        from sippycup_cockpit import runs

        summary: dict = {}
        document = {"verdict": "pass", "softphone": {}, "notes": [],
                    "mediaScope": {"peer": f"{INSIDE}:10002", "admittedBy": "media-network", "network": POOL}}
        runs._call_summary(document, summary)
        self.assertIn(("Media scope", f"peer {INSIDE}:10002 admitted by the approved media network {POOL} (media only)"),
                      summary["facts"])


class RehearsalAnswerTests(unittest.TestCase):
    FACTS = {
        "address": "127.0.0.2",
        "profile_valid_until_utc": "2099-01-01T00:00:00Z",
        "proxy": {"address": "127.0.0.3", "dns_name": "sippycup-proxy"},
    }

    def test_media_range_shapes(self):
        from sippycup import practice_rehearsal as rehearsal

        shape = rehearsal.shape_for(self.FACTS, proxy=True, media_cidr=True)
        self.assertEqual((shape.signaling, shape.media, shape.media_answer), ("127.0.0.3", ("127.0.0.2",), ("127.0.0.2/31",)))
        stop = rehearsal.shape_for(self.FACTS, proxy=True, media_approved=False, media_cidr=True)
        self.assertEqual(stop.media_answer, ("127.0.0.4/31",))
        self.assertNotIn(ipaddress.ip_address("127.0.0.2"), ipaddress.ip_network("127.0.0.4/31"))
        self.assertIn(ipaddress.ip_address("127.0.0.3"), ipaddress.ip_network("127.0.0.2/31"))
        now = datetime(2098, 12, 31, 12, tzinfo=timezone.utc)
        text = rehearsal.scope_answers(self.FACTS, now=now, name="dress", ca_file="x.crt", shape=shape)
        document = yaml.safe_load(text)
        self.assertEqual(document["media"]["networks"], ["127.0.0.2/31"])
        self.assertEqual(document["signaling"]["networks"], ["127.0.0.3"])
        stop_text = rehearsal.scope_answers(self.FACTS, now=now, name="dress", ca_file="x.crt", shape=stop, checks=())
        self.assertIn("just outside", stop_text)
        self.assertEqual(yaml.safe_load(stop_text)["media"]["networks"], ["127.0.0.4/31"])
        # The plain proxy shape is unchanged.
        plain = rehearsal.shape_for(self.FACTS, proxy=True)
        self.assertIsNone(plain.media_answer)
        self.assertEqual(yaml.safe_load(rehearsal.scope_answers(self.FACTS, now=now, name="dress", ca_file="x.crt",
                                                                shape=plain))["media"]["networks"], ["127.0.0.2"])

    def test_stage_titles_and_list(self):
        from sippycup import practice_rehearsal as rehearsal

        titles = rehearsal.stage_titles(True, True)
        self.assertEqual(len(titles), 12)
        self.assertIn("media as a range", titles[3])
        self.assertIn("just outside the approved range", titles[11])
        self.assertEqual(rehearsal.stage_titles(True), rehearsal.stage_titles(True, False))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = rehearsal.main(["--list", "--media-cidr", "--project-dir", str(ROOT)])
        self.assertEqual(code, 0)
        self.assertIn("signaling to the media address refused", out.getvalue())


if __name__ == "__main__":
    unittest.main()
