"""Confirmation logic with a fake runner and an injected clock."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cockpit_support import (  # noqa: E402
    NOW, compiled_engagement, make_engagement, make_repo, practice_state, write_approved_profile,
)
from sippycup_cockpit.actions import COCKPIT_SECRET_ENV, spawnable  # noqa: E402
from sippycup_cockpit.session import Session  # noqa: E402

DRY_RUN_READY = {
    "schema_version": "sippycup.dev/call-dry-run/v1", "ready": True,
    "one_call_plan": {"blocking_errors": [], "steps": []},
    "softphone": {"destination_uri": "sip:echo@127.0.0.2:5060", "transport": "udp",
                  "duration_seconds": {"effective": 10, "limit": 20}, "answer_timeout_seconds": 30,
                  "account": {"register": True, "username": "practice"}},
    "capture_filter": "(host 127.0.0.2) and (udp port 5060 or udp)",
}


class FakeProcess:
    def __init__(self, lines, code):
        self._lines = list(lines)
        self._code = code
        self.interrupted = 0

    def read_lines(self, timeout=0.1):
        lines, self._lines = self._lines, []
        return lines

    def poll(self):
        return None if self._lines else self._code

    def interrupt(self):
        self.interrupted += 1

    def terminate(self):
        pass


class FakeRunner:
    def __init__(self, preview=None, preview_code=0):
        self.preview = preview if preview is not None else json.dumps(DRY_RUN_READY)
        self.preview_code = preview_code
        self.probes: list[list[str]] = []
        self.started: list[dict] = []

    def probe(self, argv, timeout=120):
        self.probes.append(list(argv))
        return self.preview_code, self.preview

    def start(self, argv, *, env=None, stdin_data=None):
        self.started.append({"argv": list(argv), "env": dict(env or {}), "stdin": stdin_data})
        return FakeProcess(["ok"], 0)


class ConfirmationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = make_repo(Path(self.temporary.name))
        self.runner = FakeRunner()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def session(self, root, environ=None, now=NOW):
        return Session(self.repo, root, runner=self.runner, clock=lambda: now, environ=environ or {},
                       commands=None, host_has_tshark=True)

    def action(self, session, identifier):
        return next(item for item in session.actions if item["id"] == identifier)

    def test_network_free_action_needs_no_token(self) -> None:
        root = compiled_engagement(self.repo, now=NOW)
        session = self.session(root)
        confirmation = session.prepare(self.action(session, "rehearse"))
        self.assertIsNone(confirmation.refused)
        self.assertFalse(confirmation.live)
        self.assertIsNone(confirmation.token)
        self.assertEqual(["./bin/sippycup", "rehearse", "work/eng/target-profile.yaml"], confirmation.argv)
        self.assertEqual([], self.runner.probes)

    def test_live_call_requires_the_exact_last_four_of_the_approval_id(self) -> None:
        root = compiled_engagement(self.repo, now=NOW)
        session = self.session(root)
        confirmation = session.prepare(self.action(session, "call"))
        self.assertIsNone(confirmation.refused, confirmation.lines)
        self.assertTrue(confirmation.live)
        self.assertEqual("7Q2X", confirmation.token)
        self.assertNotIn("7Q2X", confirmation.approval_hint)
        for wrong in ("", "7q2x", "Q2X", "X7Q2X", "send", "QUAD-APPROVAL-7Q2X"):
            self.assertFalse(session.token_ok(confirmation, wrong), wrong)
        self.assertTrue(session.token_ok(confirmation, "7Q2X"))
        self.assertTrue(session.token_ok(confirmation, " 7Q2X \n"))
        self.assertEqual(
            [["./bin/sippycup", "call", "work/eng/target-profile.yaml", "--dial", "echo", "--dry-run",
              "--format", "json"]],
            self.runner.probes,
        )
        text = "\n".join(confirmation.lines)
        self.assertIn("Literal address: 127.0.0.2", text)
        self.assertIn("1 INVITE dialog with RTP, hung up 10 s after answer", text)
        self.assertIn("./bin/sippycup call work/eng/target-profile.yaml --dial echo", text)

    def test_live_action_refused_when_profile_not_ready(self) -> None:
        root = make_engagement(self.repo)
        write_approved_profile(root, valid_from=NOW - timedelta(hours=3), valid_until=NOW - timedelta(minutes=1))
        session = self.session(root)
        action = {"id": "call", "stage": "first-call", "title": "Place the guided baseline call", "reason": "x",
                  "network": "live", "label": "[LIVE]", "networkActivity": True,
                  "argv": ["./bin/sippycup", "call", "work/eng/target-profile.yaml", "--dial", "echo"],
                  "available": True, "approval": "engagement", "secret": "call"}
        confirmation = session.prepare(action)
        self.assertIn("gate would refuse", confirmation.refused)
        self.assertIn("expired", confirmation.refused)
        self.assertIsNone(confirmation.token)
        self.assertEqual([], self.runner.probes)

    def test_live_action_refused_without_an_approval_id(self) -> None:
        root = make_engagement(self.repo)
        write_approved_profile(root, valid_from=NOW - timedelta(hours=1), valid_until=NOW + timedelta(hours=1),
                               approval_id="", status="pending")
        session = self.session(root)
        action = {"id": "call", "stage": "first-call", "title": "t", "reason": "r", "network": "live",
                  "label": "[LIVE]", "argv": ["./bin/sippycup", "call", "p", "--dial", "echo"], "available": True,
                  "approval": "engagement"}
        confirmation = session.prepare(action)
        self.assertIn("no approval id", confirmation.refused)
        self.assertIsNone(confirmation.token)

    def test_blocked_dry_run_refuses_the_live_action(self) -> None:
        root = compiled_engagement(self.repo, now=NOW)
        blocked = dict(DRY_RUN_READY, ready=False,
                       one_call_plan={"blocking_errors": ["authorization has expired"], "steps": []})
        self.runner = FakeRunner(preview=json.dumps(blocked), preview_code=2)
        session = self.session(root)
        confirmation = session.prepare(self.action(session, "call"))
        self.assertIn("BLOCKED", confirmation.refused)
        self.assertIn("authorization has expired", confirmation.refused)

    def test_secret_file_must_be_private_and_beneath_work(self) -> None:
        root = compiled_engagement(self.repo, now=NOW, account=True)
        session = self.session(root)
        confirmation = session.prepare(self.action(session, "call"))
        self.assertEqual("call", confirmation.secret_needed)
        self.assertIn("--username", confirmation.argv)
        secret = root / "account.password"
        secret.write_text("s3cret-value", encoding="utf-8")
        secret.chmod(0o644)
        problem = session.apply_secret(confirmation, "file work/eng/account.password")
        self.assertIn("chmod 600", problem)
        outside = Path(self.temporary.name) / "outside.password"
        outside.write_text("x", encoding="utf-8")
        outside.chmod(0o600)
        self.assertIn("not beneath", session.apply_secret(confirmation, f"file {outside}"))
        self.assertIn("answer 'file PATH' or 'env NAME'", session.apply_secret(confirmation, "s3cret-value"))
        secret.chmod(0o600)
        self.assertIsNone(session.apply_secret(confirmation, "file work/eng/account.password"))
        self.assertEqual(["--secret-file", "work/eng/account.password"], confirmation.argv[-2:])
        self.assertNotIn("s3cret-value", " ".join(confirmation.argv))
        self.assertNotIn("s3cret-value", "\n".join(confirmation.lines))

    def test_secret_env_must_already_be_set_and_is_forwarded_by_name(self) -> None:
        root = compiled_engagement(self.repo, now=NOW, account=True)
        session = self.session(root, environ={"SIP_PASSWORD": "value-in-env"})
        confirmation = session.prepare(self.action(session, "call"))
        self.assertIn("not set", session.apply_secret(confirmation, "env MISSING_VARIABLE"))
        self.assertIn("letters, digits", session.apply_secret(confirmation, "env BAD-NAME"))
        self.assertIsNone(session.apply_secret(confirmation, "env SIP_PASSWORD"))
        self.assertEqual(["--secret-env", "SIP_PASSWORD"], confirmation.argv[-2:])
        self.assertNotIn("value-in-env", " ".join(confirmation.argv))

    def test_campaign_secret_file_goes_to_the_child_environment_only(self) -> None:
        root = compiled_engagement(self.repo, now=NOW, account=True)
        (root / "plan.json").write_text(json.dumps({
            "metadata": {"name": "fixture"}, "steps": [{}, {}],
            "authorization": {"credentialRefs": ["practice-password"], "hardMaxima": {"calls": 2}},
            "plannedTotals": {"calls": 1}, "resolvedDestinations": [
                {"address": "127.0.0.2", "port": 5060, "transport": "udp"}]}), encoding="utf-8")
        secret = root / "account.password"
        secret.write_text("campaign-secret\n", encoding="utf-8")
        secret.chmod(0o600)
        session = self.session(root)
        confirmation = session.prepare(self.action(session, "campaign-run"))
        self.assertIsNone(confirmation.refused, confirmation.lines)
        self.assertIn("Destinations (literal): 127.0.0.2:5060/udp", "\n".join(confirmation.lines))
        self.assertEqual("campaign", confirmation.secret_needed)
        self.assertIsNone(session.apply_secret(confirmation, "file work/eng/account.password"))
        self.assertEqual(["--secret-env", f"practice-password={COCKPIT_SECRET_ENV}"], confirmation.argv[-2:])
        self.assertEqual({COCKPIT_SECRET_ENV: "campaign-secret"}, confirmation.env)
        self.assertNotIn("campaign-secret", " ".join(confirmation.argv))

    def test_practice_call_uses_the_practice_approval_and_password_file(self) -> None:
        root = make_engagement(self.repo)
        practice_state(self.repo, now=NOW)
        session = self.session(root)
        confirmation = session.prepare(self.action(session, "practice-call"))
        self.assertIsNone(confirmation.refused, confirmation.lines)
        self.assertEqual("ONLY", confirmation.token)
        self.assertIsNone(confirmation.secret_needed)
        self.assertIn("--secret-file", confirmation.argv)
        (self.repo / "work" / "practice" / "account.password").chmod(0o644)
        refused = session.prepare(self.action(session, "practice-call"))
        self.assertIn("practice password file", refused.refused)

    def test_runner_only_spawns_the_launcher(self) -> None:
        from sippycup_cockpit.runner import RunnerError, SubprocessRunner

        self.assertTrue(spawnable(["./bin/sippycup", "status", "work/eng"]))
        for argv in (["/bin/sh", "-c", "true"], ["./bin/sippycup-torture"], [], ["./bin/sippycup", "a\x00b"]):
            self.assertFalse(spawnable(argv), argv)
        with self.assertRaises(RunnerError):
            SubprocessRunner(self.repo).start(["/bin/true"])

    def test_execute_detects_the_new_run_directory(self) -> None:
        root = compiled_engagement(self.repo, now=NOW)
        session = self.session(root)
        before = session.run_paths()
        run = root / "calls" / "20261117T120000.000000Z-new"
        run.mkdir(parents=True)
        (run / "result.json").write_text(json.dumps({"apiVersion": "sippycup.dev/call-result/v1",
                                                      "verdict": "pass", "state": "completed"}), encoding="utf-8")
        outcome = session.finish(before, 0, ["./bin/sippycup", "call"])
        self.assertEqual(["calls/20261117T120000.000000Z-new"], [item["relative"] for item in outcome.new_runs])

    def test_journal_note_goes_through_stdin_not_argv(self) -> None:
        root = compiled_engagement(self.repo, now=NOW)
        run = root / "runs" / "20261117T120000.000000Z-camp"
        run.mkdir(parents=True)
        (run / "result.json").write_text('{"state": "succeeded"}', encoding="utf-8")
        session = self.session(root)
        argv = session.journal_argv(session.runs[0], "observation")
        self.assertEqual(["./bin/sippycup", "journal", "add", "work/eng", "--kind", "observation",
                          "--summary-file", "-", "--evidence", "runs/20261117T120000.000000Z-camp/result.json"], argv)
        with self.assertRaises(ValueError):
            session.journal_argv(session.runs[0], "password")


if __name__ == "__main__":
    unittest.main()
