"""Senders refuse a compiled profile or manifest that no longer matches `scope compile` (bn-zqe8).

`ready` and `scope compile` already noticed a hand-edited derivative; `call`,
`rehearse`, `preflight --profile`, `media send --profile`, `matrix`, `checks`,
`campaign run` and the MCP live tools did not, so an approved destination,
address, window or limit added by hand was honoured. Every test here uses
injected fakes: no container, capture, or socket.
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

import cockpit_support as support  # noqa: E402
from test_guided_call import Fakes  # noqa: E402

from sippycup.campaign import compile_plan  # noqa: E402
from sippycup.integration import AuthorizationLapsed, execute_campaign  # noqa: E402
from sippycup_checks import runner as checks_runner  # noqa: E402
from sippycup_workbench import call as guided  # noqa: E402
from sippycup_workbench import matrix  # noqa: E402
from sippycup_workbench.binding import BindingError, load_binding  # noqa: E402
from sippycup_workbench.cli import rehearse_file  # noqa: E402
from sippycup_workbench.scope_derive import derivative_integrity  # noqa: E402

NOW = datetime.now(timezone.utc).replace(microsecond=0)

# Hand edits an operator might make to the compiled profile, as text, so the
# compile header stays in place exactly as it would in an editor.
EDITS = {
    "destination": ("  approved_destinations:\n  - echo\n", "  approved_destinations:\n  - echo\n  - tone\n"),
    "address": ("  host: 127.0.0.2\n", "  host: 127.0.0.9\n"),
    "addresses": ("  approved_addresses:\n  - 127.0.0.2\n", "  approved_addresses:\n  - 127.0.0.2\n  - 127.0.0.9\n"),
    "window": ("  valid_until: '", "  valid_until: '2099"),
    "limit": ("  max_calls: 2\n", "  max_calls: 9\n"),
}


class IntegrityCase(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = support.make_repo(Path(temporary.name))
        self.work = self.repo / "work"
        self.root = support.compiled_engagement(self.repo, now=NOW, go=False)
        self.profile = self.root / "target-profile.yaml"

    def edit(self, path: Path, old: str, new: str) -> None:
        text = path.read_text(encoding="utf-8")
        if old == "  valid_until: '":
            start = text.index(old) + len(old)
            text = text[:start] + "2099" + text[start + 4:]
        else:
            self.assertIn(old, text)
            text = text.replace(old, new, 1)
        path.write_text(text, encoding="utf-8")

    def call(self, destination: str = "echo", **values):
        fakes = Fakes()
        options = guided.CallOptions(profile=self.profile, destination=destination, duration=3, **values)
        code, value = guided.execute(options, fakes.dependencies(self.work, now=lambda: NOW))
        return fakes, code, value


class ProfileIntegrityTests(IntegrityCase):
    def test_unedited_compiled_profile_is_current_and_calls(self) -> None:
        self.assertEqual(derivative_integrity(self.profile)["state"], "compiled-current")
        self.assertTrue(rehearse_file(self.profile).ready)
        fakes, code, value = self.call()
        self.assertEqual(code, 0, value)
        self.assertIn("softphone", fakes.events)

    def test_every_hand_edit_is_refused_by_call_before_any_packet(self) -> None:
        for name, (old, new) in EDITS.items():
            with self.subTest(edit=name):
                self.root = support.compiled_engagement(self.repo, now=NOW, go=False, name=f"eng-{name}")
                self.profile = self.root / "target-profile.yaml"
                self.edit(self.profile, old, new)
                fakes, code, value = self.call("tone" if name == "destination" else "echo")
                self.assertEqual(code, 2, value)
                self.assertEqual(value["state"], "blocked")
                self.assertEqual(fakes.events, [], "no capture, preflight, or call may start")
                self.assertEqual(value["networkActivity"], "none")
                first = value["blockingErrors"][0]
                self.assertIn("was edited after scope compile wrote it", first)
                self.assertIn(f"scope compile --force work/eng-{name}", first)
                self.assertIn("Never edit a compiled profile", first)
                self.assertFalse((self.root / "calls").exists())

    def test_rehearse_and_dry_run_are_not_ready_for_an_edited_profile(self) -> None:
        self.edit(self.profile, *EDITS["destination"])
        rehearsal = rehearse_file(self.profile)
        self.assertFalse(rehearsal.ready)
        self.assertIn("scope compile --force work/eng", rehearsal.errors[0])
        fakes = Fakes()
        code, plan = guided.execute(
            guided.CallOptions(profile=self.profile, destination="tone", dry_run=True),
            fakes.dependencies(self.work, now=lambda: NOW),
        )
        self.assertEqual(code, 2)
        self.assertFalse(plan["ready"])
        self.assertEqual(fakes.events, [])

    def test_preflight_and_media_binding_refuse_an_edited_profile(self) -> None:
        self.edit(self.profile, *EDITS["address"])
        with self.assertRaises(BindingError) as caught:
            load_binding(self.profile, planned_seconds=5, now=NOW, work_root=self.work, literal_host=True)
        self.assertIn("scope compile --force", " ".join(caught.exception.reasons))

    def test_matrix_and_checks_refuse_an_edited_profile(self) -> None:
        self.edit(self.profile, *EDITS["limit"])
        plan = matrix.build_plan(
            matrix.MatrixOptions(profiles=(self.profile,), destination="echo", codecs=("PCMU",), max_calls=4),
            now=NOW, work_root=self.work,
        )
        self.assertFalse(plan["ready"])
        self.assertTrue(any("was edited after scope compile" in item for item in plan["blockingErrors"]))
        document = yaml.safe_load(self.profile.read_text(encoding="utf-8"))
        checks = checks_runner.build_plan(document, now=NOW, work_root=self.work, profile_path=self.profile)
        self.assertFalse(checks["ready"])
        self.assertIn("was edited after scope compile", checks["blockingErrors"][0])

    def test_scope_changed_after_compile_is_refused_until_compiled_again(self) -> None:
        scope = self.root / "scope.yaml"
        scope.write_text(scope.read_text(encoding="utf-8").replace("calls: 2", "calls: 3"), encoding="utf-8")
        fakes, code, value = self.call()
        self.assertEqual(code, 2)
        self.assertEqual(fakes.events, [])
        self.assertIn("changed after the last scope compile", value["blockingErrors"][0])
        self.assertIn("run ./bin/sippycup scope compile work/eng", value["blockingErrors"][0])

    def test_profile_copied_out_of_its_engagement_is_refused(self) -> None:
        elsewhere = self.work / "other"
        elsewhere.mkdir()
        copy = elsewhere / "target-profile.yaml"
        copy.write_bytes(self.profile.read_bytes())
        self.assertIn("carries the scope compile header", derivative_integrity(copy)["error"])

    def test_unrecorded_profile_beside_compiled_ones_is_refused(self) -> None:
        extra = self.root / "target-profile-mine.yaml"
        extra.write_text(yaml.safe_dump(yaml.safe_load(self.profile.read_text(encoding="utf-8"))), encoding="utf-8")
        self.assertIn("was not written by scope compile", derivative_integrity(extra)["error"])

    def test_hand_written_profile_without_a_scope_is_unaffected(self) -> None:
        loose = self.work / "loose"
        loose.mkdir()
        path = support.write_approved_profile(
            loose, valid_from=NOW - timedelta(hours=1), valid_until=NOW + timedelta(hours=1)
        )
        self.assertEqual(derivative_integrity(path), {
            "state": "not-compiled", "path": "target-profile.yaml",
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "scopeSha256": None, "error": None,
        })


class SummaryIntegrityTests(IntegrityCase):
    """Runs made before this fix (or by hand) are still caught by the report."""

    def report(self):
        from sippycup_workbench.summary_model import Options, build_report

        model, _ = build_report(self.root, Options(generated_at="2026-11-19T00:00:00Z"))
        return model

    def test_unapproved_destination_and_edited_profile_are_integrity_exceptions(self) -> None:
        import json

        _fakes, code, value = self.call()
        self.assertEqual(code, 0)
        # What the old code let through: the profile edited to approve `tone`,
        # and a call placed to it.
        self.edit(self.profile, *EDITS["destination"])
        result = self.work.parent / value["runDirectory"] / "result.json"
        document = json.loads(result.read_text(encoding="utf-8"))
        document["destinationUri"] = "sip:tone@127.0.0.2:5060"
        result.write_text(json.dumps(document), encoding="utf-8")
        model = self.report()
        codes = {item["code"] for item in model["integrityExceptions"]}
        self.assertIn("destination-not-approved", codes)
        self.assertIn("approval-record-edited", codes)
        self.assertNotIn("Every run fell inside", model["executiveSummary"]["paragraph"])

    def test_approved_destination_raises_nothing(self) -> None:
        _fakes, code, _value = self.call()
        self.assertEqual(code, 0)
        codes = {item["code"] for item in self.report()["integrityExceptions"]}
        self.assertFalse(codes & {"destination-not-approved", "approval-record-edited"}, codes)


class ManifestIntegrityTests(IntegrityCase):
    def test_campaign_run_refuses_an_edited_manifest_before_anything_exists(self) -> None:
        manifest = self.root / "campaign.yaml"
        self.edit(manifest, "    calls: 2\n", "    calls: 9\n")
        raw = manifest.read_bytes()
        plan = compile_plan(yaml.safe_load(raw), hashlib.sha256(raw).hexdigest())
        with self.assertRaisesRegex(AuthorizationLapsed, "was edited after scope compile wrote it"):
            execute_campaign(plan, manifest_bytes=raw, run_root=self.root / "runs",
                             manifest_path=manifest, clock=lambda: NOW)
        self.assertFalse((self.root / "runs").exists())


if __name__ == "__main__":
    unittest.main()
