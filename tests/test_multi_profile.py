"""The cockpit, `ready`, and `diagnose` with one compiled profile per target (bn-3lbc, bn-2oqn).

Fixture engagements only; no container and no network.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))

from cockpit_support import NOW, make_engagement, make_repo, scope_text, write_go, write_scope  # noqa: E402
from test_diagnose import Fixture, reject_log  # noqa: E402
from test_ready import FakeHost  # noqa: E402

from sippycup_cockpit import ready  # noqa: E402
from sippycup_cockpit.model import build_model  # noqa: E402
from sippycup_cockpit.render import render_dashboard  # noqa: E402
from sippycup_workbench.profile import load_profile  # noqa: E402
from sippycup_workbench.scope_derive import compile_scope  # noqa: E402

SECOND = "target-profile-edge-tls.yaml"


def two_target_scope(*, tls_address: str = "127.0.0.2") -> str:
    """The cockpit fixture scope with a second, TLS target and per-target destinations."""
    document = yaml.safe_load(scope_text(valid_from=NOW - timedelta(hours=1), valid_until=NOW + timedelta(hours=3)))
    document["signaling"] = {"networks": ["127.0.0.2/32"] + ([f"{tls_address}/32"] if tls_address != "127.0.0.2" else []),
                             "ports": [5060, 5061], "transports": ["udp", "tls"]}
    document["targets"].append({"name": "edge-tls", "address": tls_address, "transport": "tls", "port": 5061,
                                "tls_server_name": "sbc.fixture.test"})
    document["destinations"] = [
        # The first destination in the file is on the SECOND target.
        {"name": "agent", "target": "edge-tls", "user": "7001", "expect": "agent"},
        {"name": "echo", "target": "edge", "user": "echo", "expect": "echo"},
        {"name": "dtmf", "target": "edge", "user": "dtmf", "expect": "echo"},
    ]
    return yaml.safe_dump(document, sort_keys=False)


class MultiProfileCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = make_repo(Path(self.temporary.name))
        (self.repo / "bin").mkdir()
        self.root = make_engagement(self.repo)
        self.compile(two_target_scope())

    def compile(self, text: str, **kwargs) -> None:
        write_scope(self.root, text)
        outcome = compile_scope(self.root, now=NOW, **kwargs)
        self.assertEqual(outcome.exit_code, 0, outcome.as_dict())

    def model(self, **kwargs) -> dict:
        kwargs.setdefault("now", NOW)
        return build_model(self.root, repo=self.repo, **kwargs)


class CockpitProfilesTests(MultiProfileCase):
    def test_the_model_lists_every_compiled_profile(self) -> None:
        model = self.model()
        json.dumps(model)  # still JSON-serializable
        self.assertEqual(
            [(item["path"], item["target"], item["first"], item["state"], item["ready"], item["transport"],
              item["approvedDestinations"], item["dial"]) for item in model["profiles"]],
            [("work/eng/target-profile.yaml", "edge", True, "current", True, "udp", ["echo", "dtmf"], "echo"),
             (f"work/eng/{SECOND}", "edge-tls", False, "current", True, "tls", ["7001"], "7001")],
        )

    def test_the_first_profiles_actions_never_dial_another_targets_destination(self) -> None:
        model = self.model()
        self.assertEqual(model["target"]["dial"], "echo")
        self.assertEqual(model["target"]["approvedDestinations"], ["echo", "dtmf"])
        for identifier in ("call-dry-run", "call"):
            action = next(item for item in model["actions"] if item["id"] == identifier)
            argv = action["argv"]
            self.assertEqual(argv[argv.index("call") + 1], "work/eng/target-profile.yaml")
            self.assertEqual(argv[argv.index("--dial") + 1], "echo")

    def test_each_further_profile_gets_offline_actions_with_its_own_destination(self) -> None:
        model = self.model()
        rehearse = next(item for item in model["actions"] if item["id"] == "rehearse-edge-tls")
        self.assertEqual(rehearse["argv"], ["./bin/sippycup", "rehearse", f"work/eng/{SECOND}"])
        dry = next(item for item in model["actions"] if item["id"] == "call-dry-run-edge-tls")
        self.assertEqual(dry["argv"], ["./bin/sippycup", "call", f"work/eng/{SECOND}", "--dial", "7001", "--dry-run"])
        for action in (rehearse, dry):
            self.assertEqual(action["network"], "none")
            self.assertFalse(action["networkActivity"])
            self.assertFalse(action["progress"], "a further profile is never the single next step")
        self.assertFalse(any(item["id"] == "call-edge-tls" for item in model["actions"]),
                         "no live action for a further profile")
        self.assertNotIn(SECOND, model["nextCommand"] or "")

    def test_a_target_without_an_approved_destination_offers_no_dial(self) -> None:
        document = yaml.safe_load(two_target_scope())
        document["destinations"] = [item for item in document["destinations"] if item["target"] == "edge-tls"]
        self.compile(yaml.safe_dump(document, sort_keys=False))
        model = self.model()
        self.assertIsNone(model["target"]["dial"])
        self.assertEqual(model["target"]["approvedDestinations"], [])
        dry = next((item for item in model["actions"] if item["id"] == "call-dry-run"), None)
        if dry is not None:
            self.assertFalse(dry["available"])
            self.assertIn("no approved destination to dial on this target", dry["unavailableReason"])

    def test_the_dashboard_shows_readiness_and_staleness_of_each_profile(self) -> None:
        lines = render_dashboard(self.model(), now=NOW)
        profile_lines = [line for line in lines if line.startswith("Profile ")]
        self.assertEqual(len(profile_lines), 2, lines)
        self.assertIn("[ok] work/eng/target-profile.yaml: target edge 127.0.0.2 port 5060/udp; dial echo, dtmf; "
                      "ready and current", profile_lines[0])
        self.assertIn(f"[ok] work/eng/{SECOND}: target edge-tls 127.0.0.2 port 5061/tls; dial 7001; "
                      "ready and current", profile_lines[1])

        extra = self.root / SECOND
        extra.write_text(extra.read_text().replace("port: 5061", "port: 5999"))
        model = self.model()
        self.assertEqual(model["profiles"][1]["state"], "edited")
        self.assertEqual(model["scope"]["state"], "stale")
        self.assertIn("profile:edge-tls (edited)", model["scope"]["staleItems"])
        line = next(line for line in render_dashboard(model, now=NOW) if SECOND in line and line.startswith("Profile"))
        self.assertIn("[!!]", line)
        self.assertIn("edited; run scope compile", line)
        # A stale profile is never offered as a runnable dry run.
        self.assertFalse(any(item["id"] == "call-dry-run-edge-tls" and item["available"]
                             for item in model["actions"]))

        extra.unlink()
        model = self.model()
        self.assertFalse(model["profiles"][1]["present"])
        line = next(line for line in render_dashboard(model, now=NOW) if SECOND in line and line.startswith("Profile"))
        self.assertIn("MISSING; run scope compile", line)

    def test_a_blocked_further_profile_is_shown_as_blocked(self) -> None:
        self.compile(two_target_scope(), force=True)
        extra = self.root / SECOND
        document = load_profile(extra)
        document["target"]["approved_destinations"] = "7001"
        extra.write_text(yaml.safe_dump(document, sort_keys=False))
        model = self.model()
        self.assertFalse(model["profiles"][1]["ready"])
        line = next(line for line in render_dashboard(model, now=NOW) if SECOND in line and line.startswith("Profile"))
        self.assertIn("[!!]", line)

    def test_a_single_target_engagement_shows_no_profile_lines(self) -> None:
        self.compile(scope_text(valid_from=NOW - timedelta(hours=1), valid_until=NOW + timedelta(hours=3)))
        model = self.model()
        self.assertFalse((self.root / SECOND).exists(), "the removed target's profile is gone")
        self.assertEqual([item["path"] for item in model["profiles"]], ["work/eng/target-profile.yaml"])
        self.assertFalse(any(line.startswith("Profile ") for line in render_dashboard(model, now=NOW)))
        self.assertFalse(any(item["id"].startswith(("rehearse-edge", "call-dry-run-edge")) for item in model["actions"]))


class ReadyProfilesTests(MultiProfileCase):
    def setUp(self) -> None:
        super().setUp()
        self.host = FakeHost(self.repo)

    def assess(self) -> dict:
        return ready.assess(self.root, host=self.host, image="localhost/sippycup:test")

    def check(self, result: dict) -> dict:
        return next(item for item in result["checks"] if item["id"] == "profile:edge-tls")

    def test_every_profile_is_reported_and_recorded(self) -> None:
        result = self.assess()
        self.assertEqual(result["verdict"], "GO", [(item["id"], item["status"], item["lines"]) for item in result["checks"]])
        check = self.check(result)
        # No CA file for the TLS target: the system trust store is a warning, as for a first TLS target.
        self.assertEqual(check["status"], "warn")
        text = " ".join(check["lines"])
        self.assertIn(f"work/eng/{SECOND}: target edge-tls 127.0.0.2 port 5061/tls; rehearse: ready; current", text)
        self.assertIn("destinations: 7001", text)
        self.assertIn("TLS: server name sbc.fixture.test", text)
        self.assertEqual(list(result["otherProfiles"]), [SECOND])
        self.assertEqual(result["otherProfiles"][SECOND], ready.file_sha256(self.root / SECOND))
        authorizes = "\n".join(result["authorizes"])
        self.assertIn("Destinations   echo, dtmf (the only --dial values accepted)", authorizes)
        self.assertIn(f"Other profile  {SECOND}: target edge-tls 127.0.0.2 port 5061/tls; destinations 7001", authorizes)
        self.assertIn("Shared calls   max_calls=2 is one total for this profile and every other profile", authorizes)
        rendered = "\n".join(ready.render(result, None))
        self.assertIn(f"Profile {SECOND}"[:26], rendered)

    def test_a_stale_missing_or_blocked_profile_is_no_go(self) -> None:
        extra = self.root / SECOND
        original = extra.read_text()
        extra.write_text(original.replace("port: 5061", "port: 5999"))
        result = self.assess()
        self.assertEqual(result["verdict"], "NO-GO")
        check = self.check(result)
        self.assertEqual(check["status"], "no-go")
        self.assertIn("is edited", " ".join(check["lines"]))
        self.assertIn("scope compile work/eng", check["fix"])

        extra.unlink()
        check = self.check(self.assess())
        self.assertEqual(check["status"], "no-go")
        self.assertIn("is missing", " ".join(check["lines"]))

    def test_a_profile_that_rehearse_refuses_is_no_go(self) -> None:
        # Expire the whole approval: every profile shares the window.
        self.host = FakeHost(self.repo, now=NOW + timedelta(hours=5))
        result = self.assess()
        self.assertEqual(result["verdict"], "NO-GO")
        check = self.check(result)
        self.assertEqual(check["status"], "no-go")
        self.assertIn("rehearse refuses it", " ".join(check["lines"]))
        self.assertIn(f"rehearse work/eng/{SECOND}", check["fix"])

    def test_a_further_target_on_another_address_gets_a_route_lookup(self) -> None:
        self.compile(two_target_scope(tls_address="127.0.0.9"))
        self.assertEqual(load_profile(self.root / SECOND)["target"]["host"], "127.0.0.9")
        result = self.assess()
        check = self.check(result)
        self.assertIn("route to 127.0.0.9: source 12.0.0.7", " ".join(check["lines"]))
        self.assertTrue(any(call[:4] == ["ip", "-j", "route", "get"] and call[-1] == "127.0.0.9"
                            for call in self.host.calls))
        self.host.route_code = 2
        result = self.assess()
        self.assertEqual(self.check(result)["status"], "no-go")
        self.assertIn("no route to 127.0.0.9", " ".join(self.check(result)["lines"]))

    def test_a_go_covers_every_profile(self) -> None:
        result = self.assess()
        ready.record(result, self.root)
        self.assertTrue(ready.gate_facts(self.root, True, NOW)["go"])
        # Recompiling with another destination changes only the second profile.
        document = yaml.safe_load(two_target_scope())
        document["destinations"][0]["user"] = "7002"
        self.compile(yaml.safe_dump(document, sort_keys=False))
        facts = ready.gate_facts(self.root, True, NOW)
        self.assertFalse(facts["current"], "the GO was for another version of the TLS profile")
        self.assertFalse(facts["go"])
        ready.record(self.assess(), self.root)
        self.assertTrue(ready.gate_facts(self.root, True, NOW + timedelta(seconds=1))["go"])

    def test_an_old_go_without_the_field_does_not_cover_a_further_profile(self) -> None:
        write_go(self.root, now=NOW)  # the fixture record has no otherProfiles
        self.assertFalse(ready.gate_facts(self.root, True, NOW)["current"])
        self.compile(scope_text(valid_from=NOW - timedelta(hours=1), valid_until=NOW + timedelta(hours=3)))
        write_go(self.root, now=NOW + timedelta(seconds=1))
        self.assertTrue(ready.gate_facts(self.root, True, NOW + timedelta(seconds=2))["current"],
                        "a single-profile engagement is unchanged")


class SharedCallCeilingTests(MultiProfileCase):
    """bn-28vz: the scope's limits.calls is one total across its compiled profiles."""

    def setUp(self) -> None:
        super().setUp()
        document = yaml.safe_load(two_target_scope())
        # Both targets approve `echo`, so one matrix can dial it through both profiles.
        document["destinations"].append({"name": "echo-tls", "target": "edge-tls", "user": "echo", "expect": "echo"})
        document["media"]["codecs"] = ["PCMU", "PCMA"]
        self.compile(yaml.safe_dump(document, sort_keys=False), force=True)

    def plan(self, codecs: tuple[str, ...]) -> dict:
        from sippycup_workbench import matrix

        options = matrix.MatrixOptions(
            profiles=(self.root / "target-profile.yaml", self.root / SECOND), destination="echo", codecs=codecs,
        )
        return matrix.build_plan(options, now=NOW, work_root=self.repo / "work")

    def test_a_grid_within_the_scope_limit_is_ready(self) -> None:
        for name in ("target-profile.yaml", SECOND):
            self.assertEqual(load_profile(self.root / name)["limits"]["max_calls"], 2)
        value = self.plan(("PCMU",))
        self.assertTrue(value["ready"], value["blockingErrors"])
        self.assertEqual(value["sharedCeilings"][0]["calls"], 2)
        self.assertEqual(value["sharedCeilings"][0]["max_calls"], 2)

    def test_siblings_cannot_each_use_the_whole_limit(self) -> None:
        from sippycup_workbench import matrix

        value = self.plan(("PCMU", "PCMA"))
        self.assertEqual(value["totalCalls"], 4)
        self.assertFalse(value["ready"])
        # Each profile alone stays within max_calls 2; only the shared count refuses it.
        self.assertFalse(any("through this profile" in item for item in value["blockingErrors"]))
        text = " ".join(value["blockingErrors"])
        self.assertIn("the matrix places 4 calls under approval", text)
        self.assertIn("more than its limits.max_calls 2", text)
        self.assertIn("2 through work/eng/target-profile.yaml, 2 through work/eng/" + SECOND, text)
        self.assertIn("limits.calls in scope.yaml", text)
        rendered = matrix.render_human(value)
        self.assertIn("Call matrix plan: BLOCKED", rendered)
        self.assertIn("This command sent no packets.", rendered)

    def test_run_refuses_before_any_call(self) -> None:
        from sippycup_workbench import matrix

        placed: list = []
        deps = matrix.MatrixDependencies(
            execute=lambda *args: placed.append(args) or (0, {}), now=lambda: NOW,
            work_root=self.repo / "work", install_signal_handlers=False,
        )
        options = matrix.MatrixOptions(
            profiles=(self.root / "target-profile.yaml", self.root / SECOND), destination="echo",
            codecs=("PCMU", "PCMA"),
        )
        code, value = matrix.run(options, deps)
        self.assertEqual(code, matrix.EXIT_REFUSED)
        self.assertEqual(value["state"], "blocked")
        self.assertEqual(placed, [])

    def test_a_single_profile_is_counted_alone(self) -> None:
        from sippycup_workbench import matrix

        options = matrix.MatrixOptions(
            profiles=(self.root / "target-profile.yaml",), destination="echo", codecs=("PCMU", "PCMA"),
        )
        value = matrix.build_plan(options, now=NOW, work_root=self.repo / "work")
        self.assertTrue(value["ready"], value["blockingErrors"])
        self.assertNotIn("sharedCeilings", value)


class DiagnoseDestinationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)

    def run_not_found(self, approved) -> dict:
        fixture = Fixture(Path(self.temporary.name)).call(
            "call-not-found", softphone={"final_status": 404}, log=reject_log("404 Not Found"))
        target = {"host": "198.51.100.10", "approved_addresses": ["198.51.100.10"]}
        if approved is not None:
            target["approved_destinations"] = approved
        fixture.write("profile.json", {"authorization": {"approval_id": "REAL-1"}, "features": {}, "target": target})
        return fixture.diagnose()

    def test_a_destination_on_the_approved_list_points_at_the_platform_or_the_scope(self) -> None:
        text = json.dumps(self.run_not_found(["echo", "dtmf"]))
        self.assertIn("was on the approved list of the profile this run used (2 approved destination(s))", text)
        self.assertIn("correct destinations in scope.yaml and run scope compile", text)
        self.assertNotIn("NOT checked", text)

    def test_an_unrestricted_profile_is_called_out(self) -> None:
        text = json.dumps(self.run_not_found(None))
        self.assertIn("was NOT checked against the owner's approved list", text)
        self.assertIn("so a mistyped --dial is refused before anything is sent", text)

    def test_a_destination_off_the_recorded_list_is_called_out(self) -> None:
        text = json.dumps(self.run_not_found(["dtmf"]))
        self.assertIn("is NOT on the approved list recorded with this run's profile", text)

    def test_the_dialed_value_is_never_printed(self) -> None:
        for approved in (["echo"], None, ["dtmf"]):
            data = self.run_not_found(approved)
            prose = json.dumps({key: value for key, value in data.items() if key != "nextSteps"})
            self.assertNotIn("'echo'", prose)
            self.assertNotIn("echo, ", prose)


if __name__ == "__main__":
    unittest.main()
