"""Campaigns are bound to the owner's approval window (bn-3vxl, bn-2yib).

Covers: the manifest/plan ``authorization.approval`` field, the plan-time
refusal and warnings, the run-time gate (before any packet, before every
preflight, before every step, the scope file beside the manifest), the
``authorization_lapsed`` stop in events/result/diagnose/report/cockpit,
private run artifact modes, and the signaling breadth rule.

No sleeping for the window: the clock is injected. No network: capture,
runner and report are the local fixture tool.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(Path(__file__).parent))

from sippycup import approval  # noqa: E402
from sippycup.campaign import (  # noqa: E402
    ManifestError,
    compile_plan,
    plan_window_check,
    verify_frozen_plan,
)
from sippycup.integration import AuthorizationLapsed, execute_campaign  # noqa: E402
from sippycup.runtime import RuntimeError as CampaignRuntimeError  # noqa: E402
from sippycup.runtime import validate_plan  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "campaign"
TOOL = FIXTURES / "integration-tool.py"
CAMPAIGN = ROOT / "bin" / "campaign"
DIAGNOSE = ROOT / "bin" / "sippycup-diagnose"
BASE = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)


def z(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def manifest_with(window: dict | None, *, steps: int = 3) -> dict:
    """``steps`` OPTIONS steps of 3 s each to 127.0.0.1, optionally windowed."""
    manifest = yaml.safe_load((FIXTURES / "valid.yaml").read_bytes())
    manifest["targets"][0]["address"] = "127.0.0.1"
    manifest["targets"][0].pop("credentialRef")
    manifest["authorization"]["credentialRefs"] = []
    manifest["authorization"]["networks"] = ["127.0.0.1/32"]
    case = copy.deepcopy(manifest["cases"][0])
    case["count"] = steps
    manifest["cases"] = [case]
    if window is not None:
        manifest["authorization"]["approval"] = window
    return manifest


def planned(window: dict | None, *, steps: int = 3) -> tuple[dict, bytes]:
    manifest = manifest_with(window, steps=steps)
    raw = yaml.safe_dump(manifest, sort_keys=True).encode()
    return compile_plan(manifest, hashlib.sha256(raw).hexdigest()), raw


def window(until: datetime, start: datetime | None = None, identifier: str | None = "CHG-1") -> dict:
    value: dict = {}
    if identifier is not None:
        value["id"] = identifier
    if start is not None:
        value["validFrom"] = z(start)
    value["validUntil"] = z(until)
    return value


def scope_document(status: str = "approved", until: datetime | None = None,
                   start: datetime | None = None, identifier: str = "CHG-1") -> dict:
    return {"authorization": {
        "status": status, "approval_id": identifier, "approved_by": "Owner",
        "valid_from": None if start is None else z(start),
        "valid_until": z(until or BASE + timedelta(hours=1)),
    }}


class ManifestFieldTests(unittest.TestCase):
    def test_approval_is_frozen_canonically_and_only_when_stated(self):
        plan, _ = planned({"id": "CHG-1", "validFrom": "2026-11-20T09:00:00+01:00",
                           "validUntil": "2026-11-20T13:00:00.900+01:00"})
        # UTC, whole seconds; a fraction rounds to the narrower window.
        self.assertEqual(plan["authorization"]["approval"],
                         {"id": "CHG-1", "validFrom": "2026-11-20T08:00:00Z", "validUntil": "2026-11-20T12:00:00Z"})
        self.assertTrue(any("approval window" in item for item in plan["assumptions"]))
        validate_plan(plan)
        bare, _ = planned(None)
        self.assertNotIn("approval", bare["authorization"])
        self.assertFalse(any("approval window" in item for item in bare["assumptions"]))

    def test_window_less_plan_bytes_do_not_depend_on_the_new_code(self):
        # The same manifest with and without the field differs only by the
        # field (and its assumption): nothing else moved in the plan.
        with_window, _ = planned(window(BASE))
        without, _ = planned(None)
        for plan in (with_window, without):
            plan["metadata"].pop("manifestSha256")
        with_window["authorization"].pop("approval")
        with_window["assumptions"] = [a for a in with_window["assumptions"] if "approval window" not in a]
        self.assertEqual(json.dumps(with_window, sort_keys=True), json.dumps(without, sort_keys=True))

    def test_unquoted_yaml_timestamp_is_accepted(self):
        manifest = manifest_with(None)
        text = yaml.safe_dump(manifest, sort_keys=True).replace(
            "authorization:\n", "authorization:\n  approval:\n    validUntil: 2026-11-20T12:00:00Z\n", 1)
        plan = compile_plan(yaml.safe_load(text), "0" * 64)
        self.assertEqual(plan["authorization"]["approval"], {"validUntil": "2026-11-20T12:00:00Z"})

    def test_malformed_approval_is_refused(self):
        cases = {
            "no end": ({"id": "x"}, "validUntil is required"),
            "no zone": ({"validUntil": "2026-11-20T12:00:00"}, "timezone"),
            "date only": ({"validUntil": "2026-11-20"}, "RFC 3339"),
            "order": ({"validFrom": "2026-11-20T12:00:00Z", "validUntil": "2026-11-20T12:00:00Z"}, "earlier"),
            "unknown key": ({"validUntil": "2026-11-20T12:00:00Z", "status": "approved"}, "unsupported fields"),
            "numeric id": ({"id": 7, "validUntil": "2026-11-20T12:00:00Z"}, "approval.id"),
            "null start": ({"validFrom": None, "validUntil": "2026-11-20T12:00:00Z"}, "validFrom"),
            "not a mapping": ("2026-11-20T12:00:00Z", "mapping"),
        }
        for name, (value, message) in cases.items():
            with self.subTest(name), self.assertRaisesRegex(ManifestError, message):
                compile_plan(manifest_with(value), "0" * 64)

    def test_manifest_lock_and_runtime_validator_cover_the_window(self):
        plan, raw = planned(window(BASE + timedelta(hours=1)))
        verify_frozen_plan(plan, raw)
        later = copy.deepcopy(plan)
        later["authorization"]["approval"]["validUntil"] = z(BASE + timedelta(days=30))
        with self.assertRaisesRegex(ManifestError, "differs from recompilation"):
            verify_frozen_plan(later, raw)
        removed = copy.deepcopy(plan)
        removed["authorization"].pop("approval")
        with self.assertRaisesRegex(ManifestError, "differs from recompilation"):
            verify_frozen_plan(removed, raw)
        for name, value in {
            "offset spelling": {"validUntil": "2026-11-20T13:00:00+00:00"},
            "extra key": {"validUntil": z(BASE), "status": "approved"},
            "no end": {"id": "x"},
            "not a dict": "soon",
        }.items():
            broken = copy.deepcopy(plan)
            broken["authorization"]["approval"] = value
            with self.subTest(name), self.assertRaisesRegex(CampaignRuntimeError, "authorization.approval"):
                validate_plan(broken)


class BreadthTests(unittest.TestCase):
    def compile(self, networks):
        manifest = manifest_with(None)
        manifest["authorization"]["networks"] = networks
        return compile_plan(manifest, "0" * 64)

    def test_any_address_networks_are_refused(self):
        for network in ("0.0.0.0/0", "::/0", "0.0.0.0/8", "0.0.0.0/32", "::/64"):
            with self.subTest(network), self.assertRaisesRegex(ManifestError, "unspecified"):
                self.compile([network, "127.0.0.1/32"])

    def test_total_addresses_are_capped(self):
        for networks, message in (
            (["126.0.0.0/7"], "IPv4 addresses"),
            (["127.0.0.0/8", "10.0.0.0/30"], "IPv4 addresses"),
            (["127.0.0.1/32", "fd00::/63"], "IPv6"),
            (["127.0.0.1/32", "fd00::/64", "fd00:0:0:1::/128"], "IPv6"),
        ):
            with self.subTest(networks), self.assertRaisesRegex(ManifestError, message):
                self.compile(networks)

    def test_existing_shapes_still_compile(self):
        # The loopback /8 of the isolated selftest and the lab /24 plus one
        # IPv6 /64 of the Ferivox example are exactly at or below the cap.
        self.compile(["127.0.0.0/8"])
        self.compile(["127.0.0.1/32", "10.77.0.0/24", "fd77::/64"])
        example = yaml.safe_load((ROOT / "examples" / "ferivox-campaign.yaml").read_bytes())
        compile_plan(example, "0" * 64)

    def test_runtime_validator_refuses_a_plan_edited_to_any(self):
        plan, _ = planned(None)
        plan["authorization"]["networks"] = ["0.0.0.0/0"]
        with self.assertRaisesRegex(CampaignRuntimeError, "unspecified"):
            validate_plan(plan)
        plan["authorization"]["networks"] = ["64.0.0.0/2"]
        with self.assertRaisesRegex(CampaignRuntimeError, "IPv4 addresses"):
            validate_plan(plan)


class PlanTimeTests(unittest.TestCase):
    def test_expired_window_refuses_and_open_window_passes(self):
        plan, _ = planned(window(BASE))
        refused, warnings = plan_window_check(plan, BASE + timedelta(seconds=1))
        self.assertIn("has ended", refused)
        self.assertIn("No plan was written and nothing was sent", refused)
        self.assertEqual(warnings, [])
        refused, warnings = plan_window_check(plan, BASE - timedelta(hours=1))
        self.assertIsNone(refused)
        self.assertEqual(warnings, [])

    def test_warnings_for_unbound_not_open_and_too_short(self):
        _, warnings = plan_window_check(planned(None)[0], BASE)
        self.assertEqual([code for code, _ in warnings], ["window_unbound"])
        self.assertIn("not bound to an approval window", warnings[0][1])
        plan, _ = planned(window(BASE + timedelta(hours=2), BASE + timedelta(hours=1)))
        refused, warnings = plan_window_check(plan, BASE)
        self.assertIsNone(refused)  # planning ahead of the window is allowed
        self.assertEqual([code for code, _ in warnings], ["window_not_open"])
        # 3 steps of 3 s are planned; 5 s remain.
        plan, _ = planned(window(BASE + timedelta(seconds=5)))
        refused, warnings = plan_window_check(plan, BASE)
        self.assertIsNone(refused)
        self.assertEqual([code for code, _ in warnings], ["window_too_short"])
        self.assertIn("planned duration (9 s) cannot fit", warnings[0][1])

    def plan_cli(self, manifest: dict, *extra: str):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "campaign.yaml").write_text(yaml.safe_dump(manifest, sort_keys=True))
        process = subprocess.run(
            [sys.executable, str(CAMPAIGN), "plan", str(root / "campaign.yaml"), *extra],
            text=True, capture_output=True, timeout=60, cwd=root,
        )
        return process, root

    def test_cli_refuses_an_ended_window_and_writes_nothing(self):
        ended = window(datetime(2020, 1, 1, tzinfo=timezone.utc))
        process, root = self.plan_cli(manifest_with(ended), "--output", "plan.json")
        self.assertEqual(process.returncode, 2)
        self.assertFalse((root / "plan.json").exists())
        self.assertEqual(process.stdout, "")
        self.assertIn("refusing to plan: the approval window has ended (valid until 2020-01-01T00:00:00Z)",
                      process.stderr)
        self.assertIn("ask the owner for a new written window", process.stderr)
        process, _ = self.plan_cli(manifest_with(ended))  # stdout mode: no plan either
        self.assertEqual((process.returncode, process.stdout), (2, ""))
        process, _ = self.plan_cli(manifest_with(ended), "--error-format", "json")
        self.assertEqual(json.loads(process.stderr)["code"], "authorization_lapsed")

    def test_cli_warns_about_a_plan_without_a_window(self):
        process, root = self.plan_cli(manifest_with(None), "--output", "plan.json")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue((root / "plan.json").is_file())
        self.assertIn("WARNING: this campaign plan is not bound to an approval window", process.stderr)
        process, _ = self.plan_cli(manifest_with(None), "--error-format", "json")
        self.assertEqual(process.returncode, 0)
        self.assertEqual(json.loads(process.stderr)["code"], "window_unbound")
        json.loads(process.stdout)  # the plan on stdout is untouched by the warning
        far = window(datetime(2099, 1, 1, tzinfo=timezone.utc))
        process, _ = self.plan_cli(manifest_with(far), "--output", "plan.json")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertNotIn("WARNING", process.stderr)

    def test_cli_run_warns_when_the_plan_is_not_bound(self):
        from sippycup import campaign as campaign_cli

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)

        def run(value, scope=None):
            manifest = manifest_with(value)
            raw = yaml.safe_dump(manifest, sort_keys=True).encode()
            directory = Path(tempfile.mkdtemp(dir=root))
            (directory / "campaign.yaml").write_bytes(raw)
            (directory / "plan.json").write_text(
                json.dumps(compile_plan(manifest, hashlib.sha256(raw).hexdigest())))
            if scope is not None:
                (directory / "scope.yaml").write_text(yaml.safe_dump(scope))
            stderr = io.StringIO()
            # Stop at the executor: this test is about what is said before it.
            with mock.patch("sippycup.integration.execute_campaign",
                            side_effect=CampaignRuntimeError("stopped by the test")) as executor, \
                    contextlib.redirect_stderr(stderr):
                code = campaign_cli.main(["run", str(directory / "plan.json"), "--manifest",
                                          str(directory / "campaign.yaml"), "--run-root", str(directory / "runs")])
            return code, stderr.getvalue(), executor

        far = datetime(2099, 1, 1, tzinfo=timezone.utc)
        code, text, executor = run(None)
        self.assertEqual(code, 2)
        self.assertIn("WARNING: this campaign plan is not bound to an approval window", text)
        self.assertEqual(executor.call_count, 1)
        self.assertTrue(str(executor.call_args.kwargs["manifest_path"]).endswith("campaign.yaml"))
        code, text, executor = run(window(far))
        self.assertNotIn("WARNING", text)
        # A plan without a window beside an approved scope file is bound by it: no warning.
        code, text, executor = run(None, scope_document("approved", far))
        self.assertNotIn("WARNING", text)
        self.assertEqual(executor.call_count, 1)
        # ...and a revoked scope refuses before the executor is reached.
        code, text, executor = run(None, scope_document("revoked", far))
        self.assertEqual((code, executor.call_count), (2, 0))
        self.assertIn("refusing to run", text)
        self.assertIn("revoked, not approved", text)

    def test_cli_run_refuses_outside_the_window_before_anything_exists(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for name, value, message in (
            ("ended", window(datetime(2020, 1, 1, tzinfo=timezone.utc)), "has ended"),
            ("early", window(datetime(2099, 1, 2, tzinfo=timezone.utc), datetime(2099, 1, 1, tzinfo=timezone.utc)),
             "has not opened yet"),
        ):
            manifest = manifest_with(value)
            raw = yaml.safe_dump(manifest, sort_keys=True).encode()
            (root / f"{name}.yaml").write_bytes(raw)
            plan = compile_plan(manifest, hashlib.sha256(raw).hexdigest())
            (root / f"{name}.json").write_text(json.dumps(plan))
            process = subprocess.run(
                [sys.executable, str(CAMPAIGN), "run", str(root / f"{name}.json"), "--manifest",
                 str(root / f"{name}.yaml"), "--run-root", str(root / "runs")],
                text=True, capture_output=True, timeout=60, cwd=root,
            )
            with self.subTest(name):
                self.assertEqual(process.returncode, 2)
                self.assertEqual(process.stdout, "")
                self.assertIn("refusing to run", process.stderr)
                self.assertIn(message, process.stderr)
                self.assertIn("Nothing was sent and no run directory was created", process.stderr)
                self.assertFalse((root / "runs").exists())


class Harness(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.order = self.root / "order.txt"
        self.preflights = 0

    def calls(self) -> int:
        return self.order.read_text().count("call\n") if self.order.exists() else 0

    def finished_steps(self) -> int:
        """Steps the newest run has recorded as succeeded."""
        streams = sorted(self.root.rglob("events.jsonl"))
        return streams[-1].read_text().count('"event":"step.succeeded"') if streams else 0

    def stepping_clock(self, seconds_per_step: float):
        """Time advances only when a step has finished: no sleeping in these tests."""
        return lambda: BASE + timedelta(seconds=seconds_per_step * self.finished_steps())

    def execute(self, plan_and_manifest, *, clock, manifest_path=None, runner_mode="runner", extra=()):
        plan, raw = plan_and_manifest

        def preflight(_destination):
            self.preflights += 1
            return True, "SIP/2.0 200 OK"

        return execute_campaign(
            plan,
            manifest_bytes=raw,
            run_root=self.root / "runs",
            runner=[sys.executable, str(TOOL), runner_mode, str(self.order), *extra],
            capture_command=[sys.executable, str(TOOL), "capture", "{capture}", str(self.order)],
            report_command=[sys.executable, str(TOOL), "report", "{capture}"],
            preflight=preflight,
            allow_test_runner=True,
            manifest_path=manifest_path,
            clock=clock,
        )

    def events(self, run_dir: Path) -> list[dict]:
        return [json.loads(line) for line in (run_dir / "events.jsonl").read_text().splitlines()]


class RunGateTests(Harness):
    def test_refuses_before_any_packet_outside_the_window(self):
        for name, value, now, message in (
            ("after the end", window(BASE), BASE, "has ended"),
            ("before the start", window(BASE + timedelta(hours=2), BASE + timedelta(hours=1)), BASE,
             "has not opened yet"),
            # 2 s of preflight and a 3 s first step do not fit in 4 s.
            ("too short for the first step", window(BASE + timedelta(seconds=4)), BASE, "only 4 s"),
        ):
            with self.subTest(name), self.assertRaisesRegex(AuthorizationLapsed, message):
                self.execute(planned(value), clock=lambda now=now: now)
        self.assertFalse((self.root / "runs").exists())  # no directory, capture, or preflight
        self.assertEqual((self.preflights, self.calls()), (0, 0))

    def test_runs_to_completion_inside_the_window(self):
        result, run_dir = self.execute(planned(window(BASE + timedelta(hours=1), BASE - timedelta(minutes=1))),
                                       clock=self.stepping_clock(10))
        self.assertEqual((result.state, result.exit_code, result.completed_steps), ("succeeded", 0, 3))
        facts = json.loads((run_dir / "result.json").read_text())["approvalWindow"]
        self.assertEqual(facts, {"bound": True, "source": "plan", "approvalId": "CHG-1",
                                 "validFrom": z(BASE - timedelta(minutes=1)),
                                 "validUntil": z(BASE + timedelta(hours=1))})

    def test_window_ending_between_steps_stops_before_the_next_step(self):
        # Each finished step moves the clock 10 s. The window ends at +22 s:
        # steps 1 (t=0) and 2 (t=10) fit; at t=20 only 2 s remain for the 3 s step 3.
        result, run_dir = self.execute(planned(window(BASE + timedelta(seconds=22))),
                                       clock=self.stepping_clock(10))
        self.assertEqual((result.state, result.exit_code, result.completed_steps),
                         ("authorization_lapsed", 1, 2))
        self.assertEqual(self.calls(), 2)  # the runner was never started for step 3
        events = self.events(run_dir)
        self.assertEqual([e["step"] for e in events if e["event"] == "step.started"], [1, 2])
        final = events[-1]
        self.assertEqual((final["event"], final["state"], final["reason"], final["notStartedStep"],
                          final["completedSteps"]), ("campaign.failed", "failed", "authorization_lapsed", 3, 2))
        self.assertIn("only 2 s of the approval window remain", final["detail"])
        document = json.loads((run_dir / "result.json").read_text())
        self.assertEqual((document["state"], document["exitCode"], document["completedSteps"]),
                         ("authorization_lapsed", 1, 2))
        stop = document["approvalWindow"]["stop"]
        self.assertEqual((stop["reason"], stop["kind"], stop["before"], stop["step"], stop["at"]),
                         ("authorization_lapsed", "too-short", "step", 3, z(BASE + timedelta(seconds=20))))
        # The evidence lifecycle still completed after the stop.
        for name in ("capture.pcap", "report.txt", "evidence-manifest.json", "timestamps.json"):
            self.assertTrue((run_dir / name).is_file(), name)
        self.assertIn("capture-stop", self.order.read_text())

    def test_window_already_over_at_the_next_step_reports_expired(self):
        result, run_dir = self.execute(planned(window(BASE + timedelta(seconds=22))),
                                       clock=self.stepping_clock(30))
        self.assertEqual((result.state, result.completed_steps, self.calls()), ("authorization_lapsed", 1, 1))
        stop = json.loads((run_dir / "result.json").read_text())["approvalWindow"]["stop"]
        self.assertEqual((stop["kind"], stop["step"]), ("expired", 2))

    def test_a_step_is_checked_with_its_own_planned_duration(self):
        # Exactly the step budget remaining is not enough (the end is exclusive,
        # like the guided call's gate); one second more is.
        result, _ = self.execute(planned(window(BASE + timedelta(seconds=13)), steps=2),
                                 clock=self.stepping_clock(10))
        self.assertEqual((result.state, result.completed_steps), ("authorization_lapsed", 1))
        self.order.unlink()
        shutil.rmtree(self.root / "runs")
        result, _ = self.execute(planned(window(BASE + timedelta(seconds=14)), steps=2),
                                 clock=self.stepping_clock(10))
        self.assertEqual((result.state, result.completed_steps), ("succeeded", 2))

    def test_window_ending_during_the_preflights_sends_no_step(self):
        ticks = iter([BASE, BASE + timedelta(seconds=30)])
        last = [BASE + timedelta(seconds=30)]

        def clock():
            return next(ticks, last[0])

        result, run_dir = self.execute(planned(window(BASE + timedelta(seconds=20))), clock=clock)
        self.assertEqual((result.state, result.exit_code, result.completed_steps),
                         ("authorization_lapsed", 1, 0))
        self.assertEqual((self.preflights, self.calls()), (0, 0))
        self.assertFalse((run_dir / "events.jsonl").exists())
        stop = json.loads((run_dir / "result.json").read_text())["approvalWindow"]["stop"]
        self.assertEqual((stop["before"], stop["step"]), ("preflight", None))

    def test_clock_passing_the_end_stops_a_running_step(self):
        # Backstop: admission never lets this happen, but a clock change can.
        marker = self.root / "running"

        def clock():
            return BASE + timedelta(hours=2) if marker.exists() else BASE

        manifest = manifest_with(window(BASE + timedelta(hours=1)), steps=1)
        manifest["cases"][0]["budget"]["durationSecondsPerRun"] = 20
        raw = yaml.safe_dump(manifest, sort_keys=True).encode()
        plan = compile_plan(manifest, hashlib.sha256(raw).hexdigest())
        result, run_dir = self.execute((plan, raw), clock=clock, runner_mode="runner-sleep", extra=(str(marker),))
        self.assertEqual((result.state, result.exit_code, result.completed_steps),
                         ("authorization_lapsed", 1, 0))
        names = [e["event"] for e in self.events(run_dir)]
        self.assertIn("campaign.stop_requested", names)
        self.assertEqual(json.loads((run_dir / "result.json").read_text())["approvalWindow"]["stop"]["before"],
                         "window-end")

    def test_plan_without_a_window_still_runs_and_says_so(self):
        result, run_dir = self.execute(planned(None), clock=self.stepping_clock(100000))
        self.assertEqual((result.state, result.completed_steps), ("succeeded", 3))
        self.assertEqual(json.loads((run_dir / "result.json").read_text())["approvalWindow"],
                         {"bound": False, "source": None, "approvalId": None, "validFrom": None,
                          "validUntil": None})


class ScopeFileTests(Harness):
    """A scope file beside the manifest is the live approval record."""

    def engagement(self, plan_and_manifest, scope: dict | str | None) -> Path:
        directory = self.root / "eng"
        directory.mkdir(exist_ok=True)
        (directory / "campaign.yaml").write_bytes(plan_and_manifest[1])
        if scope is not None:
            (directory / "scope.yaml").write_text(scope if isinstance(scope, str) else yaml.safe_dump(scope))
        return directory / "campaign.yaml"

    def test_revoked_or_pending_scope_refuses_before_any_packet(self):
        until = BASE + timedelta(hours=1)
        both = planned(window(until))
        for status in ("revoked", "pending", "expired", None):
            path = self.engagement(both, scope_document(status, until))
            with self.subTest(status), self.assertRaisesRegex(AuthorizationLapsed, "not approved"):
                self.execute(both, clock=lambda: BASE, manifest_path=path)
        self.assertFalse((self.root / "runs").exists())

    def test_unreadable_scope_fails_closed(self):
        both = planned(window(BASE + timedelta(hours=1)))
        for name, text in (("not yaml", "authorization: [unclosed"), ("no section", "name: x\n"),
                           ("no window", yaml.safe_dump({"authorization": {"status": "approved"}}))):
            path = self.engagement(both, text)
            with self.subTest(name), self.assertRaises(AuthorizationLapsed):
                self.execute(both, clock=lambda: BASE, manifest_path=path)
        (path.parent / "scope.yaml").unlink()
        (path.parent / "scope.yaml").symlink_to(self.root / "elsewhere.yaml")
        with self.assertRaisesRegex(AuthorizationLapsed, "cannot be read"):
            self.execute(both, clock=lambda: BASE, manifest_path=path)

    def test_scope_window_or_id_that_differs_from_the_plan_refuses(self):
        until = BASE + timedelta(hours=1)
        both = planned(window(until))
        for name, scope in (
            ("shortened", scope_document("approved", until - timedelta(minutes=30))),
            ("extended", scope_document("approved", until + timedelta(days=1))),
            ("another approval", scope_document("approved", until, identifier="CHG-2")),
            ("start added", scope_document("approved", until, start=BASE - timedelta(hours=1))),
        ):
            path = self.engagement(both, scope)
            with self.subTest(name), self.assertRaisesRegex(AuthorizationLapsed, "differs from the one frozen"):
                self.execute(both, clock=lambda: BASE, manifest_path=path)

    def test_matching_scope_runs(self):
        until = BASE + timedelta(hours=1)
        both = planned(window(until))
        path = self.engagement(both, scope_document("approved", until))
        result, _ = self.execute(both, clock=self.stepping_clock(10), manifest_path=path)
        self.assertEqual((result.state, result.completed_steps), ("succeeded", 3))

    def test_revocation_during_the_run_stops_before_the_next_step(self):
        until = BASE + timedelta(hours=1)
        both = planned(window(until))
        path = self.engagement(both, scope_document("approved", until))

        def clock():
            if self.calls() >= 1:  # the owner withdraws while step 1 runs
                (path.parent / "scope.yaml").write_text(yaml.safe_dump(scope_document("revoked", until)))
            return BASE

        result, run_dir = self.execute(both, clock=clock, manifest_path=path)
        self.assertEqual((result.state, result.exit_code, result.completed_steps, self.calls()),
                         ("authorization_lapsed", 1, 1, 1))
        stop = json.loads((run_dir / "result.json").read_text())["approvalWindow"]["stop"]
        self.assertEqual((stop["kind"], stop["step"]), ("not-approved", 2))
        self.assertIn("revoked, not approved", stop["detail"])

    def test_plan_without_a_window_is_bound_by_the_scope_beside_it(self):
        both = planned(None)
        path = self.engagement(both, scope_document("approved", BASE + timedelta(seconds=22)))
        result, run_dir = self.execute(both, clock=self.stepping_clock(10), manifest_path=path)
        self.assertEqual((result.state, result.completed_steps), ("authorization_lapsed", 2))
        facts = json.loads((run_dir / "result.json").read_text())["approvalWindow"]
        self.assertEqual((facts["bound"], facts["source"], facts["validUntil"]),
                         (True, "scope-file", z(BASE + timedelta(seconds=22))))
        path = self.engagement(both, scope_document("approved", BASE - timedelta(seconds=1)))
        with self.assertRaisesRegex(AuthorizationLapsed, "has ended"):
            self.execute(both, clock=lambda: BASE, manifest_path=path)


class PrivateArtifactTests(Harness):
    def test_run_root_directories_and_files_are_private(self):
        previous = os.umask(0o022)  # the operator's ordinary umask
        self.addCleanup(os.umask, previous)
        result, run_dir = self.execute(planned(None, steps=1), clock=lambda: BASE)
        self.assertEqual(result.state, "succeeded")
        self.assertEqual(os.umask(0o022), 0o022)  # restored for the caller
        self.assertEqual((self.root / "runs").stat().st_mode & 0o777, 0o700)
        modes = {}
        for directory, _names, files in os.walk(run_dir):
            modes[directory] = os.stat(directory).st_mode & 0o777
            for name in files:
                modes[os.path.join(directory, name)] = os.stat(os.path.join(directory, name)).st_mode & 0o777
        wrong = {path: oct(mode) for path, mode in modes.items()
                 if mode != (0o700 if os.path.isdir(path) else 0o600)}
        self.assertEqual(wrong, {})
        for name in ("capture.pcap", "capture.log", "events.jsonl", "plan.json", "result.json",
                     "report.txt", "evidence-manifest.json", "reviewed-manifest.yaml"):
            self.assertIn(str(run_dir / name), modes)


class PresentationTests(Harness):
    """A lapsed campaign reads as our safety stop, with the owner as next step."""

    def lapsed_run(self) -> Path:
        engagement = self.root / "work" / "eng"
        (engagement / "runs").mkdir(parents=True)
        plan, raw = planned(window(BASE + timedelta(seconds=22)))
        _result, run_dir = execute_campaign(
            plan, manifest_bytes=raw, run_root=engagement / "runs",
            runner=[sys.executable, str(TOOL), "runner", str(self.order)],
            capture_command=[sys.executable, str(TOOL), "capture", "{capture}", str(self.order)],
            report_command=[sys.executable, str(TOOL), "report", "{capture}"],
            preflight=lambda _d: (True, "SIP/2.0 200 OK"), allow_test_runner=True,
            clock=self.stepping_clock(10),
        )
        return run_dir

    def test_diagnose_calls_it_a_safety_stop_on_our_side(self):
        run_dir = self.lapsed_run()
        process = subprocess.run(
            [sys.executable, str(DIAGNOSE), str(run_dir), "--format", "json", "--no-ladder"],
            text=True, capture_output=True, timeout=180,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        data = json.loads(process.stdout)
        self.assertEqual((data["kind"], data["stage"], data["state"]),
                         ("campaign", "safety stop", "authorization_lapsed"))
        self.assertEqual((data["attribution"]["side"], data["attribution"]["confidence"]), ("our side", "high"))
        self.assertIn("not a platform failure", data["attribution"]["reasoning"][0])
        self.assertIn("before step 3", data["outcome"])
        self.assertIn("2 of 3 step(s) completed; 1 were not sent", data["outcome"])
        self.assertIn("Ask the owner for a new written window", data["stopAndAsk"])
        self.assertEqual(data["nextSteps"][0]["kind"], "stop-and-ask")
        self.assertTrue(any("valid until" in item["text"] for item in data["evidence"]))

    def test_cockpit_run_list_marks_it_as_a_stop(self):
        from sippycup_cockpit import render, runs

        summary = runs.summarize(self.lapsed_run())
        self.assertEqual((summary["kind"], summary["verdict"], summary["passed"]),
                         ("campaign", "authorization_lapsed", False))
        self.assertTrue(summary["safetyStop"])
        self.assertIn("safety stop, not a target failure", summary["reason"])
        self.assertIn("ask the owner for a new window", summary["reason"])
        self.assertIn(("Approval window", f"held to the window ending {z(BASE + timedelta(seconds=22))}"),
                      summary["facts"])
        self.assertIn("[stop]", render.run_line(1, summary))

    def test_owner_report_lists_it_as_a_safety_stop_observation(self):
        from sippycup_workbench.summary_model import SAFETY_STOPS, Options, build_report

        run_dir = self.lapsed_run()
        model, _ = build_report(run_dir.parent.parent, Options(generated_at="2026-11-20T13:00:00Z"))
        run = next(item for item in model["runs"] if item["kind"] == "campaign")
        self.assertEqual(run["verdict"], "authorization_lapsed")
        self.assertIn(run["verdict"], SAFETY_STOPS)
        self.assertIs(run["details"]["windowBound"], True)
        titles = [finding["title"] for finding in model["findings"]]
        self.assertIn("Safety stop: the approval no longer covered the next campaign step", titles)
        self.assertNotIn("A campaign stopped before completing every step", titles)
        finding = next(f for f in model["findings"] if f["title"].startswith("Safety stop: the approval"))
        self.assertIn("not a target failure", finding["summary"])
        self.assertIn("new written window", finding["remediation"])

    def test_owner_report_discloses_a_run_that_was_not_bound(self):
        from sippycup_workbench.summary_model import Options, build_report

        engagement = self.root / "work" / "eng"
        plan, raw = planned(None, steps=1)
        execute_campaign(
            plan, manifest_bytes=raw, run_root=engagement / "runs",
            runner=[sys.executable, str(TOOL), "runner", str(self.order)],
            capture_command=[sys.executable, str(TOOL), "capture", "{capture}", str(self.order)],
            report_command=[sys.executable, str(TOOL), "report", "{capture}"],
            preflight=lambda _d: (True, "SIP/2.0 200 OK"), allow_test_runner=True,
        )
        model, _ = build_report(engagement, Options(generated_at="2026-11-20T13:00:00Z"))
        text = json.dumps(model)
        self.assertIn("campaign-window-unbound", text)
        self.assertIn("carries no approval window", text)


class ReadyAndCockpitTests(unittest.TestCase):
    NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)

    def model(self, plan):
        return {"authorization": {"status": "approved", "validFrom": z(self.NOW - timedelta(hours=1)),
                                  "validUntil": z(self.NOW + timedelta(hours=6)), "text": "approved"},
                "engagement": {"display": "work/eng"}, "files": {"planFacts": plan}}

    def facts(self, value):
        from sippycup_cockpit.model import _plan_facts

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "plan.json"
            path.write_text(json.dumps(planned(value)[0]))
            return _plan_facts(path)

    def test_plan_facts_say_whether_the_plan_is_bound(self):
        bound = self.facts(window(self.NOW + timedelta(hours=6)))
        self.assertIs(bound["windowBound"], True)
        self.assertEqual(bound["approval"], {"id": "CHG-1", "validFrom": None,
                                             "validUntil": z(self.NOW + timedelta(hours=6))})
        bare = self.facts(None)
        self.assertIs(bare["windowBound"], False)
        self.assertIsNone(bare["approval"])

    def test_ready_warns_about_an_unbound_or_mismatched_plan(self):
        from sippycup_cockpit import ready

        item = ready.check_window(self.model(self.facts(window(self.NOW + timedelta(hours=6)))),
                                  self.NOW, timezone.utc, 60)
        self.assertEqual(item.status, "go")
        self.assertIn("9 s", "\n".join(item.lines))  # the planned duration is still added to the margin
        self.assertIn("the frozen campaign plan is bound to this window", "\n".join(item.lines))
        item = ready.check_window(self.model(self.facts(None)), self.NOW, timezone.utc, 60)
        self.assertEqual(item.status, "warn")
        self.assertIn("NOT bound to an approval window of its own", item.lines[-1])
        self.assertIn("campaign plan", item.fix)
        item = ready.check_window(self.model(self.facts(window(self.NOW + timedelta(hours=9)))),
                                  self.NOW, timezone.utc, 60)
        self.assertEqual(item.status, "warn")
        self.assertIn("different window end", item.lines[-1])
        # No frozen plan at all: nothing to say, still GO.
        self.assertEqual(ready.check_window(self.model(None), self.NOW, timezone.utc, 60).status, "go")


class ScopeCompileTests(unittest.TestCase):
    def test_compiled_manifest_carries_the_scope_window(self):
        from test_scope import NOW, complete_scope

        from sippycup_workbench.scope_derive import compile_scope

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "assessment"
            root.mkdir(mode=0o700)
            (root / "scope.yaml").write_text(yaml.safe_dump(complete_scope(), sort_keys=False))
            (root / "scope.yaml").chmod(0o600)
            result = compile_scope(root, now=NOW)
            self.assertEqual(result.exit_code, 0, result.as_dict())
            raw = (root / "campaign.yaml").read_bytes()
            manifest = yaml.safe_load(raw)
            self.assertEqual(manifest["authorization"]["approval"], {
                "id": "FERIVOX-2026-114", "validFrom": "2020-01-01T08:00:00Z",
                "validUntil": "2099-12-31T16:00:00Z"})
            plan = compile_plan(manifest, hashlib.sha256(raw).hexdigest())
            # The gate accepts the scope the manifest was generated from...
            gate = approval.WindowGate(plan, manifest_path=root / "campaign.yaml", clock=lambda: NOW)
            self.assertIsNone(gate.refusal(60))
            # ...and refuses as soon as that scope is revoked.
            document = complete_scope()
            document["authorization"]["status"] = "revoked"
            (root / "scope.yaml").write_text(yaml.safe_dump(document, sort_keys=False))
            self.assertEqual(gate.refusal(60).kind, "not-approved")

    def test_practice_templates_carry_the_practice_window(self):
        for name in ("campaign.yaml", "campaign-tls.yaml", "campaign-proxy.yaml"):
            text = (ROOT / "examples" / "practice" / name).read_text()
            with self.subTest(name):
                self.assertIn("    id: '@APPROVAL_ID@'\n    validFrom: '@VALID_FROM@'\n"
                              "    validUntil: '@VALID_UNTIL@'\n", text)


if __name__ == "__main__":
    unittest.main()
