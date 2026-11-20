"""The owner's media answer decides where media may go (wave 10, finding 3).

When the owner answered the media question (scope ``media.networks``,
question 12), media is admitted only at what that answer lists, even when
the signaling address is elsewhere approved. ``scope compile`` records the
answer as profile ``media.addresses`` (its single addresses; the ranges stay
``media.networks``) and as manifest ``authorization.mediaAllowed``. A profile
or manifest without it (hand-written, or compiled before) keeps the old
rule. Every check here only narrows what is sent.
"""

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from sippycup.campaign import ManifestError, compile_plan  # noqa: E402
from sippycup_softphone import SoftphoneResult  # noqa: E402
from sippycup_softphone import campaign_runner  # noqa: E402
from sippycup_workbench.media_scope import media_addresses, profile_scope  # noqa: E402
from sippycup_workbench.profile import rehearse  # noqa: E402
from sippycup_workbench.scope_derive import compile_scope  # noqa: E402
from sippycup_workbench.summary_model import Source, _media_answer_admits, _Scope  # noqa: E402
from sippycup_workbench.summary_privacy import AddressBook  # noqa: E402

from test_guided_call import NOW, Fakes, GuidedCallCase, profile_document  # noqa: E402
from test_scope import complete_scope  # noqa: E402

SIGNALING = "192.0.2.10"
MEDIA = "192.0.2.11"


def answered_profile(addresses):
    document = profile_document()
    document["media"] = {"addresses": list(addresses)}
    return document


class ProfileRuleTests(unittest.TestCase):
    def test_answer_limits_media_to_the_listed_addresses(self):
        document = answered_profile([MEDIA])
        self.assertEqual(media_addresses(document), (MEDIA,))
        scope = profile_scope(document)
        self.assertTrue(scope.admits(MEDIA))
        self.assertFalse(scope.admits(SIGNALING), "the signaling address is not in the media answer")

    def test_no_answer_keeps_every_literal_approved_address(self):
        document = profile_document()
        self.assertEqual(media_addresses(document), (SIGNALING, MEDIA))

    def test_an_empty_answer_admits_no_literal_address(self):
        self.assertEqual(media_addresses(answered_profile([])), ())

    def test_the_answer_never_adds_an_address(self):
        # Only addresses that are also literal approved addresses count.
        self.assertEqual(media_addresses(answered_profile(["192.0.2.99", MEDIA])), (MEDIA,))

    def test_rehearse_refuses_an_answer_outside_the_approved_addresses(self):
        result = rehearse(answered_profile(["192.0.2.99"]), now=NOW)
        self.assertFalse(result.ready)
        self.assertTrue(any("media.addresses[0] 192.0.2.99 is not one of target.approved_addresses" in item
                            for item in result.errors), result.errors)

    def test_rehearse_refuses_non_canonical_and_non_list_answers(self):
        for value, text in ((["192.0.2.011"], "not a literal IP"), ("192.0.2.11", "must be a list"),
                            ([MEDIA, MEDIA], "listed twice")):
            with self.subTest(value=value):
                document = profile_document()
                document["media"] = {"addresses": value}
                result = rehearse(document, now=NOW)
                self.assertFalse(result.ready)
                self.assertTrue(any(text in item for item in result.errors), result.errors)

    def test_rehearse_reports_the_answer(self):
        result = rehearse(answered_profile([MEDIA]), now=NOW)
        self.assertTrue(result.ready, result.errors)
        self.assertEqual(result.facts["media_addresses"], [MEDIA])


class CompileTests(unittest.TestCase):
    def test_compile_records_the_answer_without_the_signaling_address(self):
        document = complete_scope()
        document["media"]["networks"] = ["10.20.31.0/28"]  # media servers only, not 10.20.30.40
        profile, manifest = self.compile(document)
        self.assertEqual(profile["media"]["addresses"], [])
        self.assertEqual(media_addresses(profile), ())
        self.assertFalse(profile_scope(profile).admits("10.20.30.40"))
        self.assertTrue(profile_scope(profile).admits("10.20.31.3"))
        self.assertEqual(manifest["authorization"]["mediaAllowed"], ["10.20.31.0/28"])

    def test_compile_keeps_the_signaling_address_when_the_owner_listed_it(self):
        profile, manifest = self.compile(complete_scope())
        self.assertEqual(profile["media"]["addresses"], ["10.20.30.40"])
        self.assertIn("10.20.30.40/32", manifest["authorization"]["mediaAllowed"])

    def compile(self, document):
        import tempfile

        import yaml

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scope.yaml").write_text(yaml.safe_dump(document), encoding="utf-8")
            outcome = compile_scope(root, now=NOW)
            self.assertEqual(outcome.exit_code, 0, outcome.as_dict())
            profile = yaml.safe_load((root / "target-profile.yaml").read_text())
            manifest = yaml.safe_load((root / "campaign.yaml").read_text())
        return profile, manifest


class GuidedCallTests(GuidedCallCase):
    def stopped_at(self, peer):
        def softphone(call, cancel):
            result = SoftphoneResult(destination_uri="sip:x")
            result.started = result.dialed = result.answered = True
            result.final_status = 200
            result.media_peer = peer
            result.error = "media_peer_outside_scope"
            result.rtp_tx_packets = 2
            return result
        return softphone

    def test_media_at_the_unlisted_signaling_address_stops(self):
        self.write_profile(answered_profile([MEDIA]))
        fakes = Fakes(softphone=self.stopped_at(f"{SIGNALING}:10002"))
        code, value = self.run_call(fakes)
        self.assertEqual(fakes.softphone_call.allowed_media_addresses, (MEDIA,))
        self.assertEqual(code, 1, value)
        self.assertEqual(value["verdict"], "media-outside-scope")

    def test_without_an_answer_both_addresses_admit_media(self):
        fakes = Fakes()
        code, value = self.run_call(fakes)
        self.assertEqual(code, 0, value)
        self.assertEqual(fakes.softphone_call.allowed_media_addresses, (SIGNALING, MEDIA))


class CampaignTests(unittest.TestCase):
    CONTEXT = {"authorization": {"networks": ["192.0.2.0/28"], "mediaPorts": {"start": 1, "end": 2}}}

    def test_runner_admits_only_the_answer(self):
        context = copy.deepcopy(self.CONTEXT)
        context["authorization"]["mediaAllowed"] = [f"{MEDIA}/32"]
        destination = {"addresses": [SIGNALING]}
        self.assertEqual(campaign_runner.media_step_addresses(destination, context), ())
        self.assertEqual(campaign_runner.media_networks(context), (f"{MEDIA}/32",))

    def test_runner_without_an_answer_is_unchanged(self):
        destination = {"addresses": [SIGNALING]}
        self.assertEqual(campaign_runner.media_step_addresses(destination, self.CONTEXT), (SIGNALING,))
        self.assertEqual(campaign_runner.media_networks(self.CONTEXT), ("192.0.2.0/28",))

    def test_runner_refuses_a_malformed_answer(self):
        context = copy.deepcopy(self.CONTEXT)
        context["authorization"]["mediaAllowed"] = "192.0.2.11/32"
        with self.assertRaises(campaign_runner.EnvelopeError):
            campaign_runner.media_networks(context)

    def plan(self, manifest):
        return compile_plan(manifest, "0" * 64, resolver=lambda host: ["10.20.30.40"])

    def test_plan_freezes_the_answer_and_refuses_one_that_widens(self):
        import ipaddress

        from sippycup.runtime import validate_plan
        from test_campaign import fixture  # noqa: PLC0415

        manifest, _digest = fixture()
        inside = f"{ipaddress.ip_network(manifest['authorization']['networks'][0])[1]}/32"
        manifest["authorization"]["mediaAllowed"] = [inside]
        plan = self.plan(manifest)
        self.assertEqual(plan["authorization"]["mediaAllowed"], [inside])
        validate_plan(plan)
        manifest["authorization"]["mediaAllowed"] = ["198.51.100.7/32"]
        with self.assertRaisesRegex(ManifestError, "only narrow"):
            self.plan(manifest)

    def test_plan_without_an_answer_has_no_field(self):
        from test_campaign import fixture  # noqa: PLC0415

        manifest, _digest = fixture()
        self.assertNotIn("mediaAllowed", self.plan(manifest)["authorization"])


class ReportTests(unittest.TestCase):
    def scope(self, answer):
        source = Source(kind="target-profile", ref="p", networks=[SIGNALING, MEDIA], media_answer=answer)
        book = AddressBook()
        for item in (SIGNALING, MEDIA):
            book.add_network(item)
        return _Scope(sources=[source], destinations=None, accounts=None, server_names=None, addresses=book)

    def test_report_judges_the_peer_by_the_answer(self):
        self.assertFalse(_media_answer_admits(self.scope([MEDIA]), SIGNALING))
        self.assertTrue(_media_answer_admits(self.scope([MEDIA]), MEDIA))
        self.assertTrue(_media_answer_admits(self.scope(None), SIGNALING))


if __name__ == "__main__":
    unittest.main()
