"""Dashboard model and stage derivation over fixture engagements."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cockpit_support import (  # noqa: E402
    NOW, ROOT, call_result, compiled_engagement, make_engagement, make_repo, practice_state, scope_text,
    write_approved_profile, write_run, write_scope,
)
from sippycup_cockpit import help_text  # noqa: E402
from sippycup_cockpit.model import authorization_window, build_model  # noqa: E402
from sippycup_cockpit.render import render_dashboard  # noqa: E402
from sippycup_cockpit.runs import MAX_JSON_BYTES  # noqa: E402

ALL_COMMANDS = None


def stage(model, identifier):
    return next(item for item in model["stages"] if item["id"] == identifier)


def action_ids(model):
    return [action["id"] for action in model["actions"]]


class CockpitModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.repo = make_repo(self.base)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def model(self, root, **kwargs):
        kwargs.setdefault("now", NOW)
        return build_model(root, repo=self.repo, **kwargs)

    def test_missing_engagement_starts_at_prepare_with_journal_init(self) -> None:
        model = self.model(self.repo / "work" / "absent")
        self.assertFalse(model["networkActivity"])
        self.assertFalse(model["engagement"]["exists"])
        self.assertEqual("prepare", model["currentStage"])
        self.assertEqual("./bin/sippycup journal init work/absent", model["nextCommand"])
        json.dumps(model)  # the model is JSON-serializable

    def test_missing_scope_recommends_scope_init_and_practice_first(self) -> None:
        root = make_engagement(self.repo)
        model = self.model(root)
        self.assertEqual("missing", model["scope"]["state"])
        self.assertEqual("practice", model["currentStage"])
        self.assertIn("scope-init", action_ids(model))
        scope_init = next(item for item in model["actions"] if item["id"] == "scope-init")
        self.assertEqual(["./bin/sippycup", "scope", "init", "work/eng"], scope_init["argv"])
        self.assertTrue(all(not action["networkActivity"] or action["network"] == "live"
                            for action in model["actions"]))

    def test_incomplete_scope_lists_unanswered_questions_without_values(self) -> None:
        root = make_engagement(self.repo)
        text = scope_text(valid_from=NOW, valid_until=NOW + timedelta(hours=2))
        text = text.replace("  ports: [5060]\n", "  ports: []\n").replace(
            "  retention_days: 30\n", "  retention_days: null\n")
        write_scope(root, text)
        model = self.model(root)
        self.assertEqual("incomplete", model["scope"]["state"])
        identifiers = {item["id"] for item in model["scope"]["unanswered"]}
        self.assertIn("evidence", identifiers)
        self.assertNotIn("QUAD-APPROVAL-7Q2X", json.dumps(model["scope"]))
        lines = "\n".join(render_dashboard(model))
        self.assertIn("unanswered question(s)", lines)

    def test_complete_scope_compiles_and_marks_stale_after_an_edit(self) -> None:
        root = compiled_engagement(self.repo, now=NOW)
        model = self.model(root)
        self.assertEqual("complete", model["scope"]["state"])
        self.assertEqual("done", stage(model, "scope")["state"])
        self.assertEqual("done", stage(model, "rehearse")["state"])
        path = root / "scope.yaml"
        path.write_text(path.read_text(encoding="utf-8").replace("calls: 2", "calls: 1"), encoding="utf-8")
        model = self.model(root)
        self.assertEqual("stale", model["scope"]["state"])
        self.assertTrue(model["scope"]["staleItems"])
        self.assertIn("./bin/sippycup scope compile work/eng", [a["command"] for a in model["actions"]])
        self.assertNotEqual("done", stage(model, "scope")["state"])
        self.assertFalse(any(item["id"] == "call" and item["available"] for item in model["actions"]))

    def test_authorization_windows_and_countdown(self) -> None:
        cases = [
            (NOW - timedelta(hours=1), NOW + timedelta(hours=3), "valid", "[ok]"),
            (NOW - timedelta(hours=1), NOW + timedelta(minutes=30), "expiring", "[!!]"),
            (NOW - timedelta(hours=3), NOW - timedelta(minutes=1), "expired", "[!!]"),
            (NOW + timedelta(hours=2), NOW + timedelta(hours=5), "not-yet-valid", "[!!]"),
        ]
        for valid_from, valid_until, state, marker in cases:
            with self.subTest(state=state):
                root = self.repo / "work" / state
                make_engagement(self.repo, state)
                write_approved_profile(root, valid_from=valid_from, valid_until=valid_until)
                model = self.model(root)
                auth = model["authorization"]
                self.assertEqual(state, auth["state"])
                self.assertEqual(marker, auth["marker"])
                self.assertEqual("QUAD-APPROVAL-7Q2X", auth["approvalId"])
                self.assertEqual(state in {"valid", "expiring"}, model["profile"]["ready"])
        window = authorization_window("approved", None, "2026-11-17T12:30:00Z", NOW)
        self.assertEqual(1800, window["secondsRemaining"])
        self.assertIn("00:30:00", window["text"])
        self.assertEqual("pending", authorization_window("pending", None, None, NOW)["state"])

    def test_runs_of_each_kind_including_findings_and_malformed(self) -> None:
        root = make_engagement(self.repo)
        write_approved_profile(root, valid_from=NOW - timedelta(hours=1), valid_until=NOW + timedelta(hours=2))
        write_run(root, "calls", "20261117T100000.000000Z-stage-a", {"result.json": call_result("pass"),
                                                                    "evidence-manifest.json": {"privacy": {"status": "blocked"}}})
        write_run(root, "calls", "20261117T100500.000000Z-stage-b", {"result.json": call_result("one-way-media")})
        write_run(root, "practice-calls", "20261117T090000.000000Z-practice", {
            "result.json": call_result("pass", profile="sippycup-local-practice", host="127.0.0.2")})
        write_run(root, "runs", "20261117T101000.000000Z-camp", {
            "result.json": {"state": "succeeded", "completedSteps": 2, "exitCode": 0},
            "events.jsonl": '{"event":"campaign.started"}\n{"event":"campaign.succeeded"}\n'})
        write_run(root, "checks", "20261117T102000.000000Z-checks", {"findings.json": {
            "apiVersion": "sippycup.dev/findings/v1", "checks": [{"id": "tls"}, {"id": "options"}],
            "findings": [{"severity": "medium", "title": "OPTIONS discloses the server version"}]}})
        write_run(root, "runs", "20261117T103000.000000Z-broken", {"result.json": "{not json"})
        write_run(root, "runs", "20261117T104000.000000Z-huge", {"result.json": " " * (MAX_JSON_BYTES + 10)})
        write_run(root, "runs", "20261117T105000.000000Z-running", {"events.jsonl": '{"event":"campaign.started"}\n'})
        model = self.model(root)
        runs = {run["name"].split("-", 1)[1]: run for run in model["runs"]}
        self.assertEqual("call", runs["stage-a"]["kind"])
        self.assertTrue(runs["stage-a"]["passed"])
        self.assertEqual("practice-call", runs["practice"]["kind"])
        self.assertEqual("one-way-media", runs["stage-b"]["verdict"])
        self.assertIn("No inbound RTP", runs["stage-b"]["reason"])
        self.assertEqual("campaign", runs["camp"]["kind"])
        self.assertEqual("succeeded", runs["camp"]["verdict"])
        self.assertEqual("checks", runs["checks"]["kind"])
        self.assertEqual("1 finding(s)", runs["checks"]["verdict"])
        self.assertIn("[medium] OPTIONS discloses", runs["checks"]["reason"])
        self.assertFalse(runs["broken"]["readable"])
        self.assertEqual("unreadable", runs["broken"]["verdict"])
        self.assertFalse(runs["huge"]["readable"])
        self.assertIn("display limit", runs["huge"]["reason"])
        self.assertEqual("incomplete", runs["running"]["verdict"])
        self.assertEqual("done", stage(model, "practice")["state"])
        self.assertEqual("done", stage(model, "first-call")["state"])
        identifiers = action_ids(model)
        self.assertIn("manifest-20261117T100500.000000Z-stage-b", identifiers)
        self.assertIn("journal-20261117T100000.000000Z-stage-a", identifiers)
        text = "\n".join(render_dashboard(model))
        self.assertIn("checks/20261117T102000.000000Z-checks", text)
        self.assertIn("[??]", text)

    def test_practice_stage_is_current_until_a_passing_practice_call(self) -> None:
        root = make_engagement(self.repo)
        practice_state(self.repo, now=NOW)
        model = self.model(root)
        self.assertEqual("practice", model["currentStage"])
        practice = model["readiness"]["practice"]
        self.assertTrue(practice["up"])
        self.assertEqual("valid", practice["authorization"]["state"])
        self.assertTrue(model["nextCommand"].startswith("./bin/sippycup --practice call work/practice/target-profile.yaml"))
        self.assertTrue(model["nextCommand"].endswith("--dry-run"))
        live = next(item for item in model["actions"] if item["id"] == "practice-call")
        self.assertEqual("live", live["network"])
        self.assertIn("--run-root", live["argv"])
        self.assertEqual("work/eng/practice-calls", live["argv"][live["argv"].index("--run-root") + 1])

    def test_skip_practice_preference_moves_on_without_marking_done(self) -> None:
        from sippycup_cockpit.model import save_preferences

        root = make_engagement(self.repo)
        save_preferences(root, {"skipPractice": True})
        model = self.model(root)
        self.assertEqual("recommended", stage(model, "practice")["state"])
        self.assertEqual("scope", model["currentStage"])

    def test_target_on_the_practice_address_routes_through_practice(self) -> None:
        practice_state(self.repo, now=NOW)
        root = compiled_engagement(self.repo, now=NOW)
        model = self.model(root)
        call = next(item for item in model["actions"] if item["id"] == "call")
        self.assertEqual(["./bin/sippycup", "--practice", "call", "work/eng/target-profile.yaml", "--dial", "echo"],
                         call["argv"])

    def test_commands_not_in_registry_are_hidden(self) -> None:
        root = compiled_engagement(self.repo, now=NOW, checks=True)
        without = self.model(root, commands={"call", "campaign", "scope", "practice-target"})
        self.assertNotIn("checks-run", action_ids(without))
        self.assertNotIn("summary", action_ids(without))
        with_new = self.model(root, commands={"call", "campaign", "scope", "practice-target", "checks", "summary"})
        self.assertIn("checks-plan", action_ids(with_new))
        checks = next(item for item in with_new["actions"] if item["id"] == "checks-run")
        self.assertEqual("live", checks["network"])
        self.assertEqual("checks", checks["stage"])
        self.assertEqual(["./bin/sippycup", "checks", "run", "work/eng/target-profile.yaml"], checks["argv"])

    def test_checks_on_the_practice_address_route_through_practice_and_ask_for_the_password(self) -> None:
        practice_state(self.repo, now=NOW)
        root = compiled_engagement(self.repo, now=NOW, checks=True, account=True)
        model = self.model(root)
        checks = next(item for item in model["actions"] if item["id"] == "checks-run")
        self.assertEqual(["./bin/sippycup", "--practice", "checks", "run", "work/eng/target-profile.yaml"],
                         checks["argv"])
        self.assertEqual("call", checks["secret"])

    def test_checks_stage_is_not_applicable_without_approved_checks(self) -> None:
        root = compiled_engagement(self.repo, now=NOW)
        model = self.model(root)
        self.assertEqual("not-applicable", stage(model, "checks")["state"])
        self.assertIn("not applicable", "\n".join(render_dashboard(model)))
        self.assertNotIn("checks-run", [a["id"] for a in model["actions"] if a["available"]])

    def test_checks_stage_follows_a_completed_checks_run(self) -> None:
        root = compiled_engagement(self.repo, now=NOW, checks=True)
        write_run(root, "calls", "20261117T100000.000000Z-call", {"result.json": call_result("pass")})
        write_run(root, "runs", "20261117T101000.000000Z-camp", {"result.json": {"state": "succeeded"}})
        model = self.model(root)
        self.assertEqual("checks", model["currentStage"])
        self.assertIn("checks plan", model["nextCommand"])
        findings = {"apiVersion": "sippycup.dev/findings/v1", "checks": [{"id": "banner-disclosure", "status": "finding"}],
                    "findings": [{"severity": "info", "title": "Edge announces its product name"}]}
        write_run(root, "checks", "20261117T102000.000000Z-stopped", {
            "findings.json": {**findings, "checks": [{"id": "banner-disclosure", "status": "error"}]},
            "result.json": {"apiVersion": "sippycup.dev/checks-result/v1", "state": "stopped", "exitCode": 3}})
        model = self.model(root)
        run = next(item for item in model["runs"] if item["name"].endswith("stopped"))
        self.assertFalse(run["completed"])
        self.assertEqual("checks", model["currentStage"])
        write_run(root, "checks", "20261117T103000.000000Z-done", {
            "findings.json": findings,
            "result.json": {"apiVersion": "sippycup.dev/checks-result/v1", "state": "completed", "exitCode": 0}})
        model = self.model(root)
        run = next(item for item in model["runs"] if item["name"].endswith("done"))
        self.assertTrue(run["completed"])
        self.assertEqual("1 finding(s)", run["verdict"])
        self.assertEqual("done", stage(model, "checks")["state"])
        self.assertEqual("evidence", model["currentStage"])

    def test_report_stage_needs_a_clean_owner_report_that_covers_every_run(self) -> None:
        from sippycup_workbench.journal import append

        root = compiled_engagement(self.repo, now=NOW)
        write_run(root, "calls", "20261117T100000.000000Z-call", {
            "result.json": call_result("pass"), "evidence-manifest.json": {"privacy": {"status": "pass"}}})
        write_run(root, "runs", "20261117T101000.000000Z-camp", {
            "result.json": {"state": "succeeded"}, "evidence-manifest.json": {"privacy": {"status": "pass"}}})
        append(root, kind="action", summary="call", evidence=["calls/20261117T100000.000000Z-call/result.json"])
        append(root, kind="action", summary="camp", evidence=["runs/20261117T101000.000000Z-camp/result.json"])
        model = self.model(root)
        self.assertEqual("report", model["currentStage"])
        self.assertEqual("./bin/sippycup summary work/eng --journal", model["nextCommand"])

        def report(directory, exceptions, runs, generated):
            path = root / directory
            path.mkdir()
            (path / "report.json").write_text(json.dumps({
                "apiVersion": "sippycup.dev/engagement-report/v1", "engagement": {"generatedAt": generated},
                "integrityExceptions": [{"code": "x"}] * exceptions, "runs": [{"id": run} for run in runs]}))

        report("report", 1, ["20261117T100000.000000Z-call", "20261117T101000.000000Z-camp"], "2026-11-17T11:00:00Z")
        model = self.model(root)
        self.assertEqual("report", model["currentStage"])
        self.assertEqual(1, model["files"]["ownerReport"]["integrityExceptions"])
        report("report-20261117T113000Z", 0, ["20261117T100000.000000Z-call"], "2026-11-17T11:30:00Z")
        self.assertEqual("report", self.model(root)["currentStage"])  # misses the campaign run
        report("report-20261117T114000Z", 0, ["20261117T100000.000000Z-call", "20261117T101000.000000Z-camp"],
               "2026-11-17T11:40:00Z")
        model = self.model(root)
        self.assertEqual("done", stage(model, "report")["state"])
        self.assertEqual("practice", model["currentStage"])  # the skipped recommendation comes back last
        self.assertEqual("report-20261117T114000Z/report.json", model["files"]["ownerReport"]["path"])

    def test_init_profile_is_not_offered_because_it_blocks_scope_compile(self) -> None:
        root = make_engagement(self.repo)
        model = self.model(root)
        self.assertNotIn("create-target-profile", action_ids(model))

    def test_advisor_paths_are_shown_relative_to_the_repository(self) -> None:
        root = make_engagement(self.repo)
        model = self.model(root)
        for action in model["actions"]:
            for value in action.get("argv") or []:
                self.assertFalse(value.startswith(str(self.repo)), action)

    def test_image_facts_feed_prepare_stage(self) -> None:
        root = make_engagement(self.repo)
        stale = self.model(root, image={"checked": True, "present": True, "stale": True, "image": "x",
                                        "created": "2026-11-01T00:00:00Z", "inputsChanged": "2026-11-02T00:00:00Z"})
        self.assertEqual("prepare", stale["currentStage"])
        build = next(item for item in stale["actions"] if item["id"] == "build-image")
        self.assertIn("make build", build["instruction"])
        fresh = self.model(root, image={"checked": True, "present": True, "stale": False, "image": "x"})
        self.assertEqual("done", stage(fresh, "prepare")["state"])

    def test_all_stages_done_has_no_single_next_command(self) -> None:
        root = compiled_engagement(self.repo, now=NOW)
        from sippycup_workbench.journal import append

        write_run(root, "practice-calls", "20261117T090000.000000Z-practice", {
            "result.json": call_result("pass", profile="sippycup-local-practice")})
        write_run(root, "calls", "20261117T100000.000000Z-call", {
            "result.json": call_result("pass"), "evidence-manifest.json": {"privacy": {"status": "pass"}}})
        write_run(root, "runs", "20261117T101000.000000Z-camp", {
            "result.json": {"state": "succeeded"}, "evidence-manifest.json": {"privacy": {"status": "pass"}}})
        (root / "plan.json").write_text("{}", encoding="utf-8")
        append(root, kind="action", summary="call", evidence=["calls/20261117T100000.000000Z-call/result.json"])
        append(root, kind="action", summary="camp", evidence=["runs/20261117T101000.000000Z-camp/result.json"])
        (root / "report").mkdir()
        (root / "report" / "report.json").write_text(json.dumps({
            "apiVersion": "sippycup.dev/engagement-report/v1", "engagement": {"generatedAt": "2026-11-17T11:00:00Z"},
            "integrityExceptions": [], "runs": [{"id": "20261117T100000.000000Z-call"},
                                                {"id": "20261117T101000.000000Z-camp"}]}), encoding="utf-8")
        model = self.model(root)
        states = [s["state"] for s in model["stages"]]
        self.assertEqual(states, ["done"] * 6 + ["not-applicable"] + ["done"] * 2, model["stages"])
        self.assertIsNone(model["nextCommand"])
        self.assertIn("every stage is complete", render_dashboard(model)[-1])

    def test_stage_help_text_lives_in_one_module(self) -> None:
        self.assertEqual([stage.number for stage in help_text.STAGES], list(range(1, 10)))
        for stage_text in help_text.STAGES:
            self.assertGreater(len(stage_text.what_and_why), 120, stage_text.identifier)
            for source in stage_text.source.split(","):
                document = source.strip().split(" ", 1)[0]
                self.assertTrue((ROOT / document).is_file(), document)
        self.assertIn("[LIVE]", help_text.keys_help())


if __name__ == "__main__":
    unittest.main()
