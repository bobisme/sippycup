"""Wave 12: the fourth rehearsal's findings (bn-1j2l).

Finding 1 (SAFETY): an owner's approval reference that a sibling directory
counts calls under is one rule everywhere: `ready` NO-GO, `rehearse` not
ready, and every command that reserves a call refuses before it sends.
Finding 4: the text names one directory to go on in, identically from every
side. Nothing here sends anything.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from sippycup import call_ledger  # noqa: E402
from sippycup_cockpit import ready  # noqa: E402
from sippycup_workbench import matrix  # noqa: E402

from test_guided_call import NOW, profile_document  # noqa: E402


class TwoDirectories(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name) / "work"
        self.original = self.directory("eng")
        self.copy = self.directory("eng-b")

    def directory(self, name):
        path = self.work / name
        path.mkdir(parents=True)
        return path

    def reserve(self, directory, approval="CHG-1", calls=1, ceiling=40, command="call"):
        return call_ledger.reserve(directory, approval_id=approval, ceiling=ceiling, calls=calls,
                                   command=command, source="target-profile.yaml")

    def stamp(self, directory, at):
        """Rewrite the ledger's times, as if its calls were placed at ``at``."""
        path = directory / call_ledger.LEDGER_FILE
        lines = [json.loads(line) for line in path.read_text().splitlines()]
        for line in lines:
            line["at"] = at
        path.write_text("".join(json.dumps(line, sort_keys=True, separators=(",", ":")) + "\n" for line in lines))

    def both_hold_calls(self):
        """The state the rehearsal reached before this fix: both ledgers hold calls."""
        self.reserve(self.original, calls=1)
        self.stamp(self.original, "2026-11-20T04:00:05Z")
        (self.copy / call_ledger.LEDGER_FILE).write_text("".join(
            json.dumps({"v": call_ledger.VERSION, "event": "reserve", "id": f"copy{n}", "approval": "CHG-1",
                        "calls": 1, "ceiling": 40, "command": "call", "source": "target-profile.yaml",
                        "at": "2026-11-20T04:00:01Z"}, sort_keys=True) + "\n" for n in range(3)))

    def profile(self, directory, approval="CHG-1", limit=40):
        path = directory / "target-profile.yaml"
        path.write_text(yaml.safe_dump(profile_document(**{"authorization.approval_id": approval,
                                                           "limits.max_calls": limit})), encoding="utf-8")
        return path


class ReserveRefusesTests(TwoDirectories):
    def test_a_copied_directory_cannot_reserve_once_the_original_counts_calls(self):
        self.reserve(self.original, calls=2)
        for command in ("call", "matrix run", "campaign run", "checks run"):
            with self.assertRaises(call_ledger.CeilingRefused) as caught:
                self.reserve(self.copy, command=command)
            text = str(caught.exception)
            self.assertIn(f"this {command} is refused in work/eng-b. Nothing was sent.", text)
            self.assertIn("Go on in work/eng ", text)
            self.assertIn("work/eng-b sends nothing more under CHG-1", text)
            self.assertIn("new written approval from the owner", text)
            self.assertIn("./bin/sippycup scope answer work/eng-b authorization.approval_id", text)
        # Nothing was written in the copy, and the original goes on with its own count.
        self.assertFalse((self.copy / call_ledger.LEDGER_FILE).exists())
        self.reserve(self.original)
        self.assertEqual(call_ledger.status(self.original, "CHG-1", 40, context=True).used, 3)

    def test_the_first_call_from_the_copy_stops_the_original_instead(self):
        # The rehearsal's order: the original had no call under the reference yet.
        self.reserve(self.copy)
        with self.assertRaises(call_ledger.CeilingRefused) as caught:
            self.reserve(self.original)
        self.assertIn("Go on in work/eng-b ", str(caught.exception))
        self.reserve(self.copy)

    def test_the_bench_references_are_exempt_as_before(self):
        for approval in sorted(call_ledger.BENCH_APPROVAL_IDS):
            self.reserve(self.original, approval=approval, calls=2)
            self.reserve(self.copy, approval=approval)
            self.reserve(self.original, approval=approval)
            self.assertIsNone(call_ledger.elsewhere_rule(self.copy, approval, 1))
            found = call_ledger.status(self.copy, approval, 40, context=True)
            self.assertFalse(found.elsewhere_blocks)
            self.assertEqual((found.used, found.left), (1, 39))

    def test_another_reference_and_a_directory_elsewhere_are_not_refused(self):
        self.reserve(self.original, approval="CHG-1")
        self.reserve(self.copy, approval="CHG-2")
        other_parent = Path(self.temporary.name) / "elsewhere" / "eng"
        other_parent.mkdir(parents=True)
        self.reserve(other_parent, approval="CHG-1")

    def test_an_unreadable_sibling_ledger_that_names_the_reference_refuses(self):
        (self.original / call_ledger.LEDGER_FILE).write_text('{"approval":"CHG-1","calls":3,"event":"reserve"\n')
        with self.assertRaises(call_ledger.CeilingRefused) as caught:
            self.reserve(self.copy)
        self.assertIn("Nothing was sent.", str(caught.exception))
        self.assertIn("cannot be read in work/eng", str(caught.exception))
        self.assertIn("Restore that ledger", str(caught.exception))


class BothHoldCallsTests(TwoDirectories):
    """Finding 4: two directories that name each other get one answer, not a loop."""

    def test_both_sides_print_the_same_sentences_and_pick_the_earlier_first_call(self):
        self.both_hold_calls()
        here = call_ledger.status(self.original, "CHG-1", 40, context=True)
        there = call_ledger.status(self.copy, "CHG-1", 40, context=True)
        self.assertEqual(here.rule.text, there.rule.text)
        self.assertEqual(here.notes()[-1].split(". ", 1)[1], there.notes()[-1].split(". ", 1)[1])
        self.assertEqual((here.rule.keeper, there.rule.keeper), ("work/eng-b", "work/eng-b"))
        self.assertIn("Go on in work/eng-b (its ledger has the earlier first call, and its count adds", here.rule.text)
        self.assertIn("work/eng sends nothing more under CHG-1", here.rule.text)
        self.assertIn("work/eng-b (3 call(s), first at 2026-11-20T04:00:01Z), "
                      "work/eng (1 call(s), first at 2026-11-20T04:00:05Z)", here.rule.text)
        self.assertTrue(here.elsewhere_blocks)
        self.assertFalse(there.elsewhere_blocks)

    def test_the_directory_that_goes_on_adds_the_calls_of_the_other(self):
        self.both_hold_calls()
        there = call_ledger.status(self.copy, "CHG-1", 5, context=True)
        self.assertEqual((there.used, there.elsewhere_used, there.left), (3, 1, 1))
        self.assertIn("Calls: 4 of 5 used (3 here and 1 in another directory under the same approval), 1 left",
                      there.line())
        with self.assertRaises(call_ledger.CeilingRefused):
            self.reserve(self.original, ceiling=5)
        self.reserve(self.copy, ceiling=5)
        with self.assertRaises(call_ledger.CeilingRefused) as caught:
            self.reserve(self.copy, ceiling=5)
        text = str(caught.exception)
        self.assertIn("4 already counted in work/eng-b/call-ledger.jsonl", text)
        self.assertIn("1 more counted under the same approval in another directory beside it, 0 remain", text)
        self.assertIn("nothing was sent", text)

    def test_a_directory_copied_with_its_ledger_counts_the_same_calls_once(self):
        self.reserve(self.original, calls=27)
        (self.copy / call_ledger.LEDGER_FILE).write_bytes((self.original / call_ledger.LEDGER_FILE).read_bytes())
        here = call_ledger.status(self.original, "CHG-1", 40, context=True)
        there = call_ledger.status(self.copy, "CHG-1", 40, context=True)
        self.assertEqual(here.rule.text, there.rule.text)
        self.assertIn("Go on in work/eng (the first by name, as the first calls have the same time", here.rule.text)
        self.assertEqual((here.elsewhere_blocks, there.elsewhere_blocks), (False, True))
        self.assertEqual((here.used, here.elsewhere_used, here.left), (27, 0, 13))
        with self.assertRaises(call_ledger.CeilingRefused):
            self.reserve(self.copy)
        self.reserve(self.original, calls=13)
        with self.assertRaises(call_ledger.CeilingRefused):
            self.reserve(self.original)


class OperatorTextTests(TwoDirectories):
    def test_rehearse_is_not_ready_in_the_copy_and_says_why_in_the_refusals_words(self):
        from sippycup_workbench import cli

        self.reserve(self.original, calls=2)
        result = cli.rehearse_file(self.profile(self.copy))
        self.assertFalse(result.ready)
        refusal = call_ledger.elsewhere_rule(self.copy, "CHG-1", 0).refusal("call")
        self.assertIn(refusal, result.errors)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cli._emit({"ready": result.ready, "errors": list(result.errors), "warnings": [],
                       "facts": result.facts}, "text")
        text = output.getvalue()
        self.assertTrue(text.startswith("Ready: no\n"), text)
        self.assertIn("Nothing was sent. Approval CHG-1 has calls counted in work/eng (2 call(s)", text)
        # The original is still ready.
        self.assertFalse(any("call limit" in item for item in cli.rehearse_file(self.profile(self.original)).errors))

    def test_ready_no_go_carries_the_same_sentences_and_one_place_to_go_on(self):
        self.both_hold_calls()
        checks = {}
        for directory in (self.original, self.copy):
            path = self.profile(directory)
            checks[directory.name] = ready.check_calls({"engagement": {"display": f"work/{directory.name}"}}, path,
                                                       yaml.safe_load(path.read_text()))
        self.assertEqual((checks["eng"].status, checks["eng-b"].status), (ready.NOGO, ready.WARN))
        rule = call_ledger.elsewhere_rule(self.original, "CHG-1", 1)
        for check in checks.values():
            self.assertIn(rule.advice, "\n".join(check.lines))
        self.assertIn("go on in work/eng-b (./bin/sippycup ready work/eng-b)", checks["eng"].fix)
        self.assertNotIn("go on in work/eng ", checks["eng"].fix)
        self.assertIn("4 of 40 used (3 here and 1 in another directory", "\n".join(checks["eng-b"].lines))

    def test_dry_run_and_matrix_plan_say_they_would_be_refused(self):
        from sippycup_workbench.call import calls_status, ledger_blocking

        self.reserve(self.original, calls=2)
        path = self.profile(self.copy)
        document = yaml.safe_load(path.read_text())
        blocking = ledger_blocking(path, document, 1, "call")
        self.assertEqual(len(blocking), 1)
        self.assertIn("this call is refused in work/eng-b. Nothing was sent.", blocking[0])
        line = calls_status(path, document).line(1, "call")
        self.assertIn("this call would place 1, but it would be refused", line)
        self.assertIn("Go on in work/eng ", line)
        plan = matrix.build_plan(matrix.MatrixOptions(profiles=(path,), destination="echo", codecs=("PCMU",)),
                                 now=NOW, work_root=self.work)
        self.assertFalse(plan["ready"])
        self.assertTrue(any("this matrix run is refused in work/eng-b. Nothing was sent." in item
                            for item in plan["blockingErrors"]), plan["blockingErrors"])


# ----------------------------------------------------------- a real call, the report

import hashlib  # noqa: E402
import os  # noqa: E402
import subprocess  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402
from unittest import mock  # noqa: E402

from test_call_ledger_crosscheck import APPROVAL, Engagement  # noqa: E402
from test_campaign_window import CAMPAIGN, manifest_with, window  # noqa: E402
from test_guided_call import FAKE_PJSUA  # noqa: E402
from test_tls_name import CA_PEM, FAKE_UNSHARE, NAME  # noqa: E402

from sippycup.campaign import compile_plan  # noqa: E402
from sippycup_cockpit import overlap  # noqa: E402
from sippycup_softphone import SoftphoneCall, place_call  # noqa: E402
from sippycup_softphone import driver  # noqa: E402
from sippycup_workbench import call as guided  # noqa: E402
from sippycup_workbench import profile as profile_module  # noqa: E402
from sippycup_workbench import scope_answer  # noqa: E402
from sippycup_workbench.summary_model import Options, build_report  # noqa: E402
from sippycup_workbench.summary_render import render_markdown  # noqa: E402


class CopiedEngagementTests(Engagement):
    """Finding 1 with the real `call`: the copy sends nothing, and the report names the other count."""

    def sibling(self, calls: int) -> Path:
        other = self.work / "eng-original"
        other.mkdir()
        call_ledger.reserve(other, approval_id=APPROVAL, ceiling=40, calls=calls, command="call",
                            source="target-profile.yaml")
        return other

    def test_call_refuses_before_anything_is_started(self) -> None:
        self.sibling(2)
        _fakes, code, value = self.call()
        self.assertEqual(code, guided.EXIT_REFUSED)
        self.assertEqual(value["networkActivity"], "none")
        self.assertIsNone(value["runDirectory"])
        (error,) = value["blockingErrors"]
        self.assertIn("this call is refused in work/eng. Nothing was sent.", error)
        self.assertIn("Go on in work/eng-original", error)
        self.assertFalse((self.root / "calls").exists())
        self.assertFalse(self.ledger.exists())

    def test_campaign_plan_writes_no_plan_and_says_the_same(self) -> None:
        from sippycup import campaign

        self.sibling(2)
        output = self.root / "plan.json"
        stderr = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
            code = campaign.main(["plan", str(self.root / "campaign.yaml"), "--output", str(output)])
        self.assertEqual(code, 2, stderr.getvalue())
        self.assertFalse(output.exists())
        self.assertIn("refusing to plan: call limit: this campaign run is refused in work/eng. Nothing was sent.",
                      stderr.getvalue())
        self.assertIn("Go on in work/eng-original", stderr.getvalue())
        self.assertIn("No plan was written", stderr.getvalue())

    def test_the_owner_report_names_the_other_directorys_count(self) -> None:
        self.assertEqual(self.call()[1], 0)
        # Calls the other directory placed before this fix (it would be refused now).
        other = self.work / "eng-original"
        other.mkdir()
        (other / call_ledger.LEDGER_FILE).write_text("".join(json.dumps({
            "v": call_ledger.VERSION, "event": "reserve", "id": f"earlier{n}", "approval": APPROVAL, "calls": 1,
            "ceiling": 40, "at": "2026-11-19T00:00:00Z"}) + "\n" for n in range(3)))
        model = build_report(self.root, Options(generated_at="2026-11-20T00:00:00Z"))[0]
        (limitation,) = [item for item in model["limitations"]
                         if item["code"] == "same-approval-in-another-directory"]
        self.assertIn(f"Approval {APPROVAL} was also used from another directory", limitation["text"])
        self.assertIn("work/eng-original counts 3 call(s)", limitation["text"])
        self.assertIn("not the whole count for the approval", limitation["text"])
        self.assertIn("work/eng-original counts 3 call(s)", render_markdown(model, "0" * 64))

    def test_a_report_without_such_a_directory_has_no_such_limitation(self) -> None:
        self.assertEqual(self.call()[1], 0)
        model = build_report(self.root, Options(generated_at="2026-11-20T00:00:00Z"))[0]
        self.assertFalse([item for item in model["limitations"]
                          if item["code"] == "same-approval-in-another-directory"])


class ReadyRowTests(TwoDirectories):
    def check(self, directory, approval, limit=40):
        path = self.profile(directory, approval, limit)
        return ready.check_calls({"engagement": {"display": f"work/{directory.name}"}}, path,
                                 yaml.safe_load(path.read_text()))

    def test_a_new_reference_beside_calls_under_another_is_a_warn_until_its_first_call(self) -> None:
        # Finding 5: the rule is unchanged (a new reference keeps its own count).
        self.reserve(self.original, approval="CHG-1", calls=27)
        fresh = self.check(self.original, "CHG-2")
        self.assertEqual(fresh.status, ready.WARN)
        text = "\n".join(fresh.lines)
        self.assertIn("Calls: 0 of 40 used, 40 left (approval CHG-2", text)
        self.assertIn("27 call(s) were placed here under reference CHG-1", text)
        self.assertIn("no call is counted under CHG-2 yet", text)
        self.reserve(self.original, approval="CHG-2")
        self.assertEqual(self.check(self.original, "CHG-2").status, ready.GO)
        # A directory with one reference is GO as before.
        self.reserve(self.copy, approval="CHG-9")
        self.assertEqual(self.check(self.copy, "CHG-9").status, ready.GO)
        self.assertEqual(self.check(self.directory("third"), "CHG-7").status, ready.GO)

    def test_no_call_left_says_what_can_still_run(self) -> None:
        # Finding 8, wording only.
        self.reserve(self.original, calls=2, ceiling=2)
        check = self.check(self.original, "CHG-1", limit=2)
        self.assertEqual(check.status, ready.NOGO)
        self.assertIn("every command that places a call will refuse (security checks that place no call can "
                      "still run, within their own request ceiling)", check.lines[0])


class WindowTextTests(unittest.TestCase):
    """Finding 6: a next step, with the real launcher and directory."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "work" / "eng"
        self.directory.mkdir(parents=True)
        self.path = self.directory / "target-profile.yaml"

    def write(self, with_scope=True, **overrides):
        document = profile_document(**overrides)
        self.path.write_text(yaml.safe_dump(document), encoding="utf-8")
        if with_scope:
            (self.directory / "scope.yaml").write_text("authorization: {status: approved}\n")
        return document

    def test_a_window_that_ends_too_soon_has_a_next_step(self) -> None:
        document = self.write()
        (error,) = guided.gate(document, now=NOW, planned_seconds=7200, profile_path=self.path)
        self.assertTrue(error.startswith(
            "authorization expires before the call's latest possible end (7200s from now); nothing was sent; "
            "shorten the call with --duration, or ask the owner for a longer written window, record it with "
            "./bin/sippycup scope answer work/eng authorization.window"), error)
        self.assertTrue(error.endswith("run ./bin/sippycup scope compile work/eng"), error)
        self.assertEqual(guided.gate(document, now=NOW, planned_seconds=60, profile_path=self.path), [])

    def test_the_expired_text_prints_the_launcher_and_the_directory(self) -> None:
        document = self.write()
        late = NOW + timedelta(hours=3)
        (error,) = guided.gate(document, now=late, planned_seconds=60, profile_path=self.path)
        self.assertNotIn("DIR", error)
        self.assertIn("(./bin/sippycup scope answer work/eng authorization.window), record the approval again "
                      "(./bin/sippycup scope answer work/eng 2), and run ./bin/sippycup scope compile work/eng",
                      error)
        # rehearse, ready, preflight and checks run take the same path.
        filled = profile_module.with_next_command(
            list(profile_module.rehearse(document, now=late).errors), self.path)
        self.assertEqual(filled, [error])

    def test_a_profile_without_a_scope_file_beside_it_keeps_the_general_text(self) -> None:
        document = self.write(with_scope=False)
        (error,) = guided.gate(document, now=NOW + timedelta(hours=3), planned_seconds=60, profile_path=self.path)
        self.assertIn("(scope answer DIR authorization.window)", error)


class CampaignWindowFirstTests(unittest.TestCase):
    """Finding 6: after the window ended, a stale plan is not the first thing to fix."""

    def run_campaign(self, until: datetime):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        frozen = manifest_with(window(until), steps=3)
        raw = yaml.safe_dump(frozen, sort_keys=True).encode()
        (root / "plan.json").write_text(json.dumps(compile_plan(frozen, hashlib.sha256(raw).hexdigest())))
        # scope compile wrote the campaign file again: the plan is stale.
        (root / "campaign.yaml").write_bytes(yaml.safe_dump(manifest_with(window(until), steps=2),
                                                            sort_keys=True).encode())
        return root, subprocess.run(
            [sys.executable, str(CAMPAIGN), "run", str(root / "plan.json"), "--manifest",
             str(root / "campaign.yaml"), "--run-root", str(root / "runs")],
            text=True, capture_output=True, timeout=60, cwd=root,
        )

    def test_an_ended_window_is_reported_before_the_stale_plan(self) -> None:
        root, process = self.run_campaign(datetime(2020, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(process.returncode, 2)
        error = process.stderr
        self.assertIn("refusing to run: the approval window has ended", error)
        self.assertIn("Fix the window first and leave", error)
        self.assertIn("Nothing was sent and no run directory was created", error)
        self.assertLess(error.index("the approval window has ended"), error.index("plan-"))
        self.assertFalse((root / "runs").exists())

    def test_a_stale_plan_inside_the_window_is_reported_as_before(self) -> None:
        root, process = self.run_campaign(datetime(2099, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(process.returncode, 2)
        self.assertNotIn("has ended", process.stderr)
        self.assertIn("was frozen from a different", process.stderr)
        self.assertIn("campaign plan", process.stderr)
        self.assertFalse((root / "runs").exists())


class MediaGuardLineTests(Engagement):
    """Finding 3: a call the guard watched says so; finding 17: only PJSUA is preloaded."""

    def rendered(self, guard):
        _fakes, code, value = self.call()
        self.assertEqual((code, value["verdict"]), (0, "pass"))
        return guided.render_human({**value, "mediaGuard": guard})

    def test_an_active_guard_that_dropped_nothing_is_one_line_without_an_address(self) -> None:
        text = self.rendered({"active": True, "blocked": {"rtp": 0, "rtcp": 0, "other": 0},
                              "rules": "addr=192.0.2.10/32 ports=20000-20019", "destinations": []})
        (line,) = [line for line in text.splitlines() if "Media guard:" in line]
        self.assertEqual(line, "  Media guard:  active (nothing was dropped)")

    def test_a_guard_that_was_not_active_or_absent_gets_no_such_line(self) -> None:
        for guard in ({"active": False, "blocked": {"rtp": 0, "rtcp": 0, "other": 0}}, None):
            self.assertNotIn("active (nothing was dropped)", self.rendered(guard))

    def test_a_guard_that_dropped_packets_says_what_it_dropped_as_before(self) -> None:
        text = self.rendered({"active": True, "blocked": {"rtp": 1, "rtcp": 4, "other": 0},
                              "destinations": ["192.0.2.99:4000"]})
        self.assertIn("  Media guard:  dropped 1 RTP and 4 RTCP packets addressed to 192.0.2.99:4000", text)
        self.assertNotIn("nothing was dropped", text)

    def test_under_the_name_pin_only_pjsua_is_preloaded(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        (base / "work" / "eng").mkdir(parents=True)
        ca = base / "work" / "eng" / "owner-ca.crt"
        ca.write_bytes(CA_PEM)
        play = base / "play.wav"
        guided.generate_tone(play, seconds=0.5)
        library = base / "guard.so"
        library.write_bytes(b"")
        # A stand-in for unshare that notes whether the guard was preloaded into it.
        seen = base / "helper-environment.txt"
        helper = base / "unshare"
        helper.write_text(
            "#!/usr/bin/env python3\n"
            "import os, sys\n"
            f"open({str(seen)!r}, 'a').write(os.environ.get('LD_PRELOAD', '-') + '\\n')\n"
            f"os.execv(sys.executable, [sys.executable, {str(FAKE_UNSHARE)!r}, *sys.argv[1:]])\n")
        helper.chmod(0o755)
        witness = base / "pjsua-witness.json"
        private = base / "private"
        private.mkdir()
        call = SoftphoneCall(
            destination="echo", host="192.0.2.10", port=5061, transport="tls", play_file=play,
            record_file=base / "heard.wav", duration_seconds=1, log_file=base / "softphone.log",
            allowed_media_addresses=("192.0.2.10",), tls_server_name=NAME, tls_ca_file=ca)
        environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "FAKE_PJSUA_WITNESS": str(witness),
                       "FAKE_PJSUA_TLS": "ok", "FAKE_PJSUA_PEER": "192.0.2.10"}
        with mock.patch.dict(os.environ, {"SIPPYCUP_WORK_ROOT": str(base / "work"),
                                          driver.MEDIA_GUARD_LIBRARY_ENV: str(library)}):
            result = place_call(call, pjsua=str(FAKE_PJSUA), environment=environment, private_root=private,
                                unshare=str(helper))
        self.assertIsNone(result.error, result)
        # The fail-closed check is unchanged: PJSUA itself showed the guard with these rules.
        self.assertTrue(result.media_guard["active"])
        record = json.loads(witness.read_text())
        self.assertEqual(record["environ"]["LD_PRELOAD"], str(library))
        self.assertEqual(record["environ"]["SIPPYCUP_MEDIA_GUARD_RULES"], "v1;addr=192.0.2.10/32;ports=*")
        helpers = seen.read_text().split()
        self.assertTrue(helpers)
        self.assertEqual(set(helpers), {"-"}, "the guard was preloaded into a helper program")


class WordingTests(Engagement):
    def test_the_overlap_refusal_does_not_offer_the_override_as_a_way_on(self) -> None:
        # Finding 2 (wording only; what is refused is unchanged).
        from sippycup_cockpit import stop

        text = overlap.refusal([stop.Target("container", "abc", "clever_name", "running call", "label")], "call")
        self.assertNotIn("To run beside it on purpose, set", text)
        self.assertIn("Nothing was sent.", text)
        self.assertIn("not a way past this refusal", text)
        self.assertIn("SIPPYCUP_ALLOW_OVERLAP=clever_name", text)
        self.assertIn("more calls on the target at once than the owner's concurrent_calls allows", text)
        self.assertIn("concurrent-calls-exceeded", text)

    def test_the_part_2_header_names_the_answers_that_reset_the_approval(self) -> None:
        # Finding 7: read from the rule itself (GRANTS); the rule is unchanged.
        self.assertEqual(scope_answer._number_ranges(["P3", "P4", "P5", "A1", "A2", "A3"]), "P3 to P5 and A1 to A3")
        self.assertEqual(scope_answer._number_ranges(["P3"]), "P3")
        items = [item for item in scope_answer.items_for({"platform": {}, "application": {}}) if item.part == 2]
        resets = [item.number for item in items if scope_answer._grants(item)]
        self.assertEqual(scope_answer._number_ranges(resets), "P3 to P17 and A1 to A3")
        self.assertIn("platform.environment", scope_answer.GRANTS)

    def test_the_limits_warning_reads_as_a_sentence(self) -> None:
        # Papercut 11: "at concurrency 1, not one".
        document = profile_document(**{"limits.max_calls": 40})
        (warning,) = [item for item in profile_module.rehearse(document, now=NOW).warnings
                      if item.startswith("limits allow")]
        self.assertIn("limits allow up to 40 call(s) in all, 1 at a time, not a single call;", warning)

    def test_a_pass_with_no_digit_returned_is_said(self) -> None:
        # Papercut 9: the verdict is unchanged; the line is a warning.
        dtmf = {"requestedDigits": "159#", "status": "sent", "sent": "159#", "sentSource": "capture",
                "echoed": "", "verified": True, "wire": {}}
        _fakes, code, value = self.call()
        self.assertEqual((code, value["verdict"]), (0, "pass"))
        text = guided.render_human({**value, "dtmf": dtmf})
        self.assertIn("on the wire sent '159#', received ''", text)
        self.assertIn("  WARN:         no DTMF digit came back from the far end.", text)
        dtmf["echoed"] = "159#"
        self.assertNotIn("no DTMF digit came back",
                         guided.render_human({**value, "dtmf": dtmf}))

    def test_the_report_lists_an_address_once_in_the_authorization_table(self) -> None:
        # Papercut 14: "Addresses: 127.0.0.2, 127.0.0.2" (signaling and media answer the same address).
        self.assertEqual(self.call()[1], 0)
        model = build_report(self.root, Options(generated_at="2026-11-20T00:00:00Z"))[0]
        source = next(item for item in model["authorization"]["sources"] if item["networks"])
        address = source["networks"][0]
        # Two targets (UDP and TLS) at one address: the scope source named it once per target.
        source["networks"], source["mediaNetworks"] = [address, address], []
        rows = [line for line in render_markdown(model, "0" * 64).splitlines()
                if line.startswith("|") and source["ref"] in line and address in line]
        self.assertTrue(rows)
        for row in rows:
            self.assertIn(f"| {address} |", row)
            self.assertNotIn(f"{address}, {address}", row)

    def test_the_call_self_test_uses_a_reference_of_its_own_for_every_run(self) -> None:
        # `make call-selftest` writes a new directory under work/ on every run.
        # With one fixed reference the second run was refused by the rule of
        # finding 1 (seen when the gate was run twice in this wave).
        script = (ROOT / "bin" / "call-integration-selftest").read_text(encoding="utf-8")
        self.assertIn('root="${base}-$(date -u +%Y%m%dT%H%M%SZ)-${RANDOM}"', script)
        self.assertIn("  approval_id: SELFTEST-LOOPBACK-${root##*/}\n", script)
        self.assertNotIn("approval_id: SELFTEST-LOOPBACK\n", script)

    def test_the_launcher_says_nothing_was_sent_for_routed_with_practice(self) -> None:
        # Papercut 12.
        environment = {**os.environ, "SIPPYCUP_ROUTED_PRACTICE": "routed-x"}
        process = subprocess.run([str(ROOT / "bin" / "sippycup"), "--practice", "call", "work/x/target-profile.yaml"],
                                 text=True, capture_output=True, timeout=60, env=environment, cwd=ROOT)
        self.assertEqual(process.returncode, 2)
        self.assertIn("cannot be combined with --practice or --admin", process.stderr)
        self.assertIn("Nothing was sent; no container or network activity was started.", process.stderr)


from test_scope import NOW as SCOPE_NOW  # noqa: E402
from test_scope_platform import PlatformCase, platform_scope  # noqa: E402

from sippycup_workbench.scope_derive import compile_scope  # noqa: E402


class SurfaceNoteTests(PlatformCase):
    def test_the_compile_note_counts_the_platform_parts_beside_the_web_surfaces(self) -> None:
        # Papercut 13: the four counts are of web surfaces (question A1); with
        # no web part in scope they are all 0 although P1 was answered.
        document = platform_scope()
        self.write_scope(document)
        result = compile_scope(self.root, now=SCOPE_NOW)
        self.assertEqual(result.exit_code, 0, result.as_dict())
        (note,) = [item for item in result.as_dict()["notes"] if "records the platform and web surfaces" in item]
        record = self.record()
        parts = record["platform"]["components"]
        self.assertIn(f"platform parts: {len(parts['inScope'])} in scope, {len(parts['outOfScope'])} out of scope, "
                      f"{len(parts['open'])} not answered; web surfaces: {len(record['summary']['approved'])} approved",
                      note)
        self.assertGreater(len(parts["inScope"]) + len(parts["outOfScope"]), 0)


import test_rehearsal3_intake as intake3  # noqa: E402


class PlatformHeaderTests(intake3.AnswerTestCase):
    def test_the_part_2_header_says_which_answers_set_the_approval_back(self) -> None:
        # Finding 7: the header said platform answers do not hold the approval,
        # and then answering P3 set it back to pending.
        document = intake3.complete_scope()
        document["authorization"]["status"] = "pending"
        self.write_scope(document)
        self.scope.write_text(self.scope.read_text() + intake3.PLATFORM_TEMPLATE)
        _code, out = self.answer(["", "approved"])
        self.assertIn("If the approval (question 2) is already recorded: recording or changing P3 to P17 and "
                      "A1 to A3 sets it back to pending", out)
        self.assertIn("The other platform questions never change the approval.", out)
        self.assertLess(out.index("sets it back to pending"), out.index("Walk the platform questions now?"))


if __name__ == "__main__":
    unittest.main()
