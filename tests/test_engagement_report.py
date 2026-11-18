"""Owner-facing engagement report: model, privacy, rendering, and CLI."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_workbench import summary_cli  # noqa: E402
from sippycup_workbench.journal import append, initialize, verify  # noqa: E402
from sippycup_workbench.summary_model import Options, build_report, parse_time  # noqa: E402
from sippycup_workbench.summary_privacy import Sanitizer  # noqa: E402
from sippycup_workbench.summary_render import render_html, render_markdown, render_text  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "engagement-report"
PRACTICE = FIXTURES / "practice"
GENERATED = "2026-11-18T04:00:00Z"
PASS_CALL = "20261118T025420.201700Z-sippycup-local-practice-c956ec1d"
WRONG_PASSWORD = "20261118T025439.548206Z-sippycup-local-practice-6fe5010f"
BUSY = "20261118T025443.708506Z-sippycup-local-practice-02c17f09"
TLS_CALL = "20261118T025453.149898Z-sippycup-local-practice-tls-228c57af"
UDP_CAMPAIGN = "20261118T025515.709822Z-local-practice-baseline-01965563"
TLS_CAMPAIGN = "20261118T025516.965852Z-local-practice-tls-0a50a448"

SECRET = "Fx7Q-hunter2-SECRETv9zK"
PHONE = "+14155550123"
AUTH = 'Authorization: Digest username="alice", realm="x", nonce="abc123nonce", response="0123456789abcdef0123456789abcdef"'
OUTSIDE = "198.51.100.77"
PLANT = f" {OUTSIDE} password={SECRET} {SECRET} {PHONE} sip:+14155550123@{OUTSIDE} Call-ID: deadbeefcafe-callid {AUTH}"
HOSTILE = '<script>alert("x")</script> \' " | *bold* _u_ [l](javascript:x) `tick` & &amp; # ‮evil‬ \x07bell ' + "Z" * 5000


def engagement(directory: Path) -> Path:
    target = directory / "engagement"
    shutil.copytree(PRACTICE, target)
    return target


def add_check_run(root: Path, name: str, document: dict | None = None) -> Path:
    run = root / "checks" / name
    run.mkdir(parents=True)
    value = document if document is not None else json.loads((FIXTURES / "findings-v1.json").read_text())
    (run / "findings.json").write_text(json.dumps(value))
    return run


def model_for(root: Path, **kwargs) -> dict:
    model, _ = build_report(root, Options(generated_at=GENERATED, **kwargs))
    return model


def run_cli(*arguments: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = summary_cli.main(list(arguments))
    return code, stdout.getvalue(), stderr.getvalue()


def outputs(directory: Path) -> dict[str, str]:
    return {path.name: path.read_text(encoding="utf-8") for path in sorted(directory.iterdir()) if path.is_file()}


# Keys whose values are enumerations or schema markers rather than text.
STRUCTURAL = {
    "apiVersion", "schema_version", "schema", "kind", "state", "verdict", "status", "severity",
    "type", "event", "stream", "transport", "trust", "sensitivity", "provenance", "mediaType",
    "outcome", "hangup", "media_direction", "rtp_counts_source", "runState", "path", "address",
    "host", "localAddress", "networkMode", "connectsTo", "peer", "media_peer", "caSha256", "sha256",
    "contentIdentity", "call_id", "generatedAt", "started", "finished", "createdAt",
}


def walk_strings(value, transform, everything=False, key=None):
    if isinstance(value, dict):
        return {k: walk_strings(item, transform, everything, k) for k, item in value.items()}
    if isinstance(value, list):
        return [walk_strings(item, transform, everything, key) for item in value]
    if isinstance(value, str) and (everything or key not in STRUCTURAL):
        if not everything and (re.fullmatch(r"\d{4}-\d\d-\d\dT[0-9:.]+Z", value) or value.startswith("SIP/2.0")):
            return value
        return transform(value)
    return value


def plant_everywhere(root: Path, suffix: str, everything: bool = False) -> None:
    """Wrap every text value of every JSON artifact in every run with SUFFIX.

    With everything=True even enumerations and schema markers are changed,
    which makes most documents unrecognizable; the report must still not
    crash or leak.
    """
    transform = (lambda s: suffix + " " + s + suffix)
    for path in sorted(root.glob("*/*/*.json")) + sorted(root.glob("*/*/steps/*/*.json")):
        if path.name == "evidence-manifest.json":
            continue
        value = json.loads(path.read_text())
        path.write_text(json.dumps(walk_strings(value, transform, everything)))
    for path in sorted(root.glob("*/*/events.jsonl")):
        lines = []
        for line in path.read_text().splitlines():
            event = json.loads(line)
            if isinstance(event.get("text"), str):
                inner = []
                for text_line in event["text"].splitlines():
                    try:
                        inner.append(json.dumps(walk_strings(json.loads(text_line), transform, everything)))
                    except ValueError:
                        inner.append(text_line + suffix)
                event["text"] = "\n".join(inner) + "\n"
            for key in ("reason", "case"):
                if isinstance(event.get(key), str):
                    event[key] = transform(event[key])
            lines.append(json.dumps(event))
        path.write_text("\n".join(lines) + "\n")
    for path in sorted(root.glob("*/*/report.txt")):
        path.write_text(path.read_text() + suffix + "\n")


class TagBalance(HTMLParser):
    VOID = {"meta", "br", "link", "img", "input", "hr", "col", "wbr", "source"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.errors: list[str] = []
        self.tags: list[tuple[str, dict]] = []
        self.text: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"unexpected </{tag}> with open {self.stack[-3:]}")
            return
        self.stack.pop()

    def handle_data(self, data):
        self.text.append(data)


def check_html(testcase: unittest.TestCase, document: str) -> TagBalance:
    parser = TagBalance()
    parser.feed(document)
    parser.close()
    testcase.assertEqual(parser.errors, [])
    testcase.assertEqual(parser.stack, [])
    return parser


def check_markdown_tables(testcase: unittest.TestCase, document: str) -> int:
    tables = 0
    columns = None
    for line in document.split("\n") + [""]:
        if line.startswith("|"):
            cells = len(re.split(r"(?<!\\)\|", line)) - 2
            if columns is None:
                columns = cells
                tables += 1
            testcase.assertEqual(cells, columns, line[:120])
        else:
            columns = None
    return tables


class ModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = engagement(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_practice_engagement_model(self) -> None:
        model = model_for(self.root)
        self.assertEqual(model["apiVersion"], "sippycup.dev/engagement-report/v1")
        self.assertEqual(model["runCounts"], {"call": 4, "campaign": 2, "check": 0, "unknown": 0})
        self.assertEqual(model["integrityExceptions"], [])
        runs = {run["id"]: run for run in model["runs"]}
        self.assertEqual(runs[PASS_CALL]["verdict"], "pass")
        self.assertEqual(runs[WRONG_PASSWORD]["verdict"], "registration-failed")
        self.assertFalse(runs[WRONG_PASSWORD]["details"]["registration"]["registered"])
        busy = runs[BUSY]["details"]
        self.assertEqual(busy["call"]["finalStatus"], 486)
        self.assertEqual(busy["oracle"]["failed"], ["dialog[0].media.directionality"])
        # "busy" is not named by any reviewed record; "echo" is (campaign-tls.yaml).
        self.assertEqual(busy["destination"], "unreviewed-destination-1")
        self.assertEqual(runs[PASS_CALL]["details"]["destination"], "echo")
        tls = runs[TLS_CALL]["details"]["tls"]
        self.assertTrue(tls["verified"])
        self.assertEqual(tls["serverName"], "sippycup-practice")
        self.assertRegex(tls["caSha256"], r"^[0-9a-f]{64}$")
        self.assertFalse(runs[TLS_CALL]["details"]["oracle"]["decidesVerdict"])
        self.assertEqual(runs[PASS_CALL]["details"]["media"]["toPeerPackets"], 500)
        campaign = runs[TLS_CAMPAIGN]["details"]
        self.assertEqual([c["outcome"] for c in campaign["cases"]], ["succeeded", "succeeded"])
        self.assertEqual(campaign["cases"][1]["rtpFromPeer"], 250)
        self.assertTrue(campaign["cases"][1]["tlsVerified"])
        self.assertTrue(runs[TLS_CAMPAIGN]["sent"]["optionsLowerBound"])
        self.assertEqual(runs[UDP_CAMPAIGN]["sent"]["optionsRequests"], 4)
        self.assertEqual(model["totals"]["calls"]["total"], 4)
        self.assertTrue(model["journal"]["valid"])
        self.assertEqual(model["journal"]["headSha256"], verify(self.root).final_sha256)
        self.assertEqual(model["authorization"]["window"], {"from": "2026-11-18T02:53:06Z", "until": "2026-11-18T06:54:06Z"})
        self.assertIn("LOCAL-PRACTICE-ONLY", model["executiveSummary"]["paragraph"])
        self.assertTrue(3 <= len(model["executiveSummary"]["rows"]) <= 5)
        self.assertIn("stage-not-run:checks", {item["code"] for item in model["limitations"]})
        # Engagement-relative paths only.
        self.assertEqual(runs[PASS_CALL]["ref"], f"calls/{PASS_CALL}")
        self.assertNotIn(str(self.root), json.dumps(model))

    def test_no_runs(self) -> None:
        root = Path(self.temporary.name) / "empty"
        initialize(root, title="Empty engagement", owner="Owner")
        model = model_for(root)
        self.assertEqual(model["runs"], [])
        self.assertEqual(model["findings"], [])
        self.assertIn("No runs were recorded", model["executiveSummary"]["paragraph"])
        codes = {item["code"] for item in model["limitations"]}
        self.assertIn("stage-not-run:call", codes)
        self.assertIn("no-authorization-record", codes)
        self.assertTrue(3 <= len(model["executiveSummary"]["rows"]) <= 5)
        render_markdown(model, "0" * 64)
        check_html(self, render_html(model, "0" * 64))

    def test_only_failed_runs(self) -> None:
        model = model_for(self.root, run_globs=("*-6fe5010f", "calls/*02c17f09"))
        self.assertEqual([run["id"] for run in model["runs"]], [WRONG_PASSWORD, BUSY])
        titles = [row["title"] for row in model["executiveSummary"]["rows"]]
        self.assertTrue(any("call-not-answered (1), registration-failed (1)" in t for t in titles), titles)

    def test_since_filter(self) -> None:
        model = model_for(self.root, since=parse_time("2026-11-18T02:55:00Z"))
        self.assertEqual({run["kind"] for run in model["runs"]}, {"campaign"})
        self.assertNotIn(PASS_CALL, {run["id"] for run in model["runs"]})

    def test_check_findings_are_merged_and_ordered(self) -> None:
        add_check_run(self.root, "20261118T031000Z-checks-a")
        second = json.loads((FIXTURES / "findings-v1.json").read_text())
        second["generatedAt"] = "2026-11-18T03:20:00Z"
        add_check_run(self.root, "20261118T032000Z-checks-b", second)
        model = model_for(self.root)
        findings = [f for f in model["findings"] if not f["derived"]]
        self.assertEqual([f["severity"] for f in findings], ["high", "low", "info"])
        self.assertEqual([f["ref"] for f in model["findings"][:3]], ["F-01", "F-02", "F-03"])
        header = findings[1]
        self.assertEqual(header["checkId"], "server-header")
        self.assertEqual(header["occurrences"], 2)
        self.assertEqual(header["runs"], ["20261118T031000Z-checks-a", "20261118T032000Z-checks-b"])
        self.assertEqual((header["firstSeen"], header["lastSeen"]), ("2026-11-18T03:10:00Z", "2026-11-18T03:20:00Z"))
        self.assertEqual(header["evidence"][0]["artifact"], "checks/20261118T031000Z-checks-a/responses.json")
        self.assertNotIn("notInSpec", json.dumps(model))
        check_run = next(run for run in model["runs"] if run["kind"] == "check")
        self.assertEqual(check_run["details"]["statusCounts"]["not-approved"], 1)
        self.assertEqual(check_run["sent"]["checkRequests"], 7)
        limitations = " ".join(item["text"] for item in model["limitations"])
        self.assertIn("invite-flood", limitations)
        self.assertIn("not-approved", limitations)
        self.assertIn("tls-legacy-protocols", limitations)
        self.assertEqual(model["recommendations"][0]["finding"], "F-01")
        self.assertEqual(model["executiveSummary"]["rows"][0]["severity"], "high")
        self.assertEqual(model["integrityExceptions"], [])

    def test_out_of_window_run_is_an_integrity_exception(self) -> None:
        path = self.root / "calls" / PASS_CALL / "result.json"
        value = json.loads(path.read_text())
        value["timestamps"]["started"] = "2026-11-18T07:00:00Z"
        value["timestamps"]["finished"] = "2026-11-18T07:01:00Z"
        path.write_text(json.dumps(value))
        model = model_for(self.root)
        codes = {(e["code"], e["run"]) for e in model["integrityExceptions"]}
        self.assertIn(("outside-approval-window", PASS_CALL), codes)
        self.assertIn("integrity exception", model["executiveSummary"]["paragraph"])

    def test_runs_without_a_covering_window_are_a_stated_limitation(self) -> None:
        (self.root / "target-profile.yaml").unlink()
        (self.root / "target-profile-tls.yaml").unlink()
        model = model_for(self.root)
        self.assertIsNone(model["authorization"]["window"])
        texts = [item["text"] for item in model["limitations"] if item["code"] == "window-not-checked"]
        self.assertEqual(len(texts), 6)
        # The campaign manifests still approve every target address.
        self.assertEqual(model["integrityExceptions"], [])

    def test_unapproved_target_is_pseudonymized_and_flagged(self) -> None:
        path = self.root / "calls" / BUSY / "result.json"
        value = json.loads(path.read_text())
        value["target"]["host"] = OUTSIDE
        path.write_text(json.dumps(value))
        model = model_for(self.root)
        text = json.dumps(model)
        self.assertNotIn(OUTSIDE, text)
        run = next(r for r in model["runs"] if r["id"] == BUSY)
        self.assertEqual(run["target"]["address"], "unapproved-address-1")
        self.assertIn(("target-not-approved", BUSY), {(e["code"], e["run"]) for e in model["integrityExceptions"]})

    def test_malformed_oversized_and_missing_files_are_unreadable_entries(self) -> None:
        (self.root / "calls" / PASS_CALL / "result.json").write_text("{not json")
        events = self.root / "runs" / UDP_CAMPAIGN / "events.jsonl"
        with events.open("r+b") as handle:
            handle.truncate(17 * 1024 * 1024)
        (self.root / "runs" / TLS_CAMPAIGN / "plan.json").unlink()
        broken = self.root / "calls" / "20261118T030000Z-garbage"
        broken.mkdir()
        (broken / "result.json").write_text(json.dumps([1, 2, 3]))
        duplicate = self.root / "calls" / "20261118T030001Z-duplicate"
        duplicate.mkdir()
        (duplicate / "result.json").write_text('{"apiVersion": "a", "apiVersion": "b"}')
        os.symlink("/etc/passwd", self.root / "calls" / BUSY / "softphone.json.link")
        model = model_for(self.root)
        runs = {run["id"]: run for run in model["runs"]}
        self.assertEqual(runs[PASS_CALL]["readable"], "unreadable")
        self.assertIn("result.json: malformed", " ".join(runs[PASS_CALL]["problems"]))
        self.assertIn("events.jsonl: oversized", " ".join(runs[UDP_CAMPAIGN]["problems"]))
        self.assertEqual(runs[TLS_CAMPAIGN]["readable"], "partial")
        self.assertEqual(runs["20261118T030000Z-garbage"]["readable"], "unreadable")
        self.assertEqual(runs["20261118T030001Z-duplicate"]["readable"], "unreadable")
        codes = {item["code"] for item in model["limitations"]}
        self.assertIn("run-unreadable", codes)
        check_html(self, render_html(model, "0" * 64))
        check_markdown_tables(self, render_markdown(model, "0" * 64))

    def test_journal_notes_and_call_ids_depend_on_audience(self) -> None:
        owner = model_for(self.root)
        text = json.dumps(owner)
        self.assertNotIn("operator private note", text)
        dialog = next(r for r in owner["runs"] if r["id"] == PASS_CALL)["details"]["dialogs"][0]
        self.assertIsNone(dialog["callId"])
        self.assertRegex(dialog["callIdHash"], r"^[0-9a-f]{12}$")
        assertion = json.loads((self.root / "calls" / PASS_CALL / "assert.json").read_text())
        self.assertNotIn(assertion["dialogs"][0]["call_id"], text)
        internal = model_for(self.root, audience="internal")
        self.assertIn("operator private note", json.dumps(internal))
        dialog = next(r for r in internal["runs"] if r["id"] == PASS_CALL)["details"]["dialogs"][0]
        self.assertEqual(dialog["callId"], assertion["dialogs"][0]["call_id"])
        notes = model_for(self.root, include_journal_notes=True)
        self.assertIn("operator private note", json.dumps(notes))
        self.assertIsNone(next(r for r in notes["runs"] if r["id"] == PASS_CALL)["details"]["dialogs"][0]["callId"])

    def test_derived_observations(self) -> None:
        path = self.root / "calls" / PASS_CALL / "result.json"
        value = json.loads(path.read_text())
        value["verdict"] = "one-way-media"
        value["preflight"]["detail"] = "SIP/2.0 503 Service Unavailable"
        path.write_text(json.dumps(value))
        model = model_for(self.root)
        derived = {f["checkId"]: f for f in model["findings"] if f["derived"]}
        self.assertIn("derived:one-way-media", derived)
        self.assertIn("derived:preflight-server-error", derived)
        self.assertEqual(derived["derived:one-way-media"]["severity"], "low")
        self.assertEqual(derived["derived:one-way-media"]["confidence"], "derived")
        self.assertTrue(all(r["derived"] for r in model["recommendations"]))


class PrivacyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = engagement(Path(self.temporary.name))
        add_check_run(self.root, "20261118T031000Z-checks-a")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_clean(self, files: dict[str, str]) -> None:
        for name, content in files.items():
            for needle in (SECRET, PHONE, "14155550123", OUTSIDE, "abc123nonce", "0123456789abcdef0123456789abcdef", "deadbeefcafe-callid", "Digest username", "‮", "\x07", "<script"):
                self.assertNotIn(needle, content, f"{needle!r} leaked into {name}")

    def test_planted_values_in_every_run_text_field_never_reach_the_report(self) -> None:
        plant_everywhere(self.root, PLANT)
        append(self.root, kind="observation", summary="planted" + PLANT, detail="detail" + PLANT)
        secret_file = Path(self.temporary.name) / "secret.txt"
        secret_file.write_text(SECRET + "\n")
        for audience in ("owner", "internal"):
            with self.subTest(audience=audience):
                out = Path(self.temporary.name) / f"out-{audience}"
                code, stdout, stderr = run_cli(
                    str(self.root), "--output", str(out), "--generated-at", GENERATED,
                    "--format", "md", "--format", "html", "--format", "text",
                    "--audience", audience, "--include-journal-notes", "--forbid-file", str(secret_file),
                )
                self.assertEqual(code, 1, stderr)
                files = outputs(out)
                exceptions = json.loads(files["report.json"])["integrityExceptions"]
                self.assertIn("unapproved-address-in-artifact", {item["code"] for item in exceptions})
                self.assertEqual(set(files), {"engagement-report.md", "engagement-report.html", "engagement-report.txt", "report.json"})
                self.assert_clean(files)
                self.assertIn("unapproved-address-", files["report.json"])
                self.assertNotIn(SECRET, stdout + stderr)

    def test_planted_values_without_forbid_file_are_still_removed(self) -> None:
        plant_everywhere(self.root, PLANT, everything=True)
        out = Path(self.temporary.name) / "out"
        code, _, stderr = run_cli(str(self.root), "--output", str(out), "--generated-at", GENERATED, "--allow-exceptions")
        self.assertEqual(code, 0, stderr)
        self.assert_clean(outputs(out))

    def test_operator_text_that_trips_the_lint_fails_closed(self) -> None:
        for title, code_name in (
            (f"Engagement for {PHONE}", "subscriber-identifier"),
            (f"Edge {OUTSIDE}", "unapproved-address"),
            ("password=hunter2hunter2", "credential-assignment"),
        ):
            with self.subTest(title=title):
                out = Path(self.temporary.name) / "never"
                code, stdout, stderr = run_cli(str(self.root), "--output", str(out), "--title", title, "--generated-at", GENERATED)
                self.assertEqual(code, 3)
                self.assertFalse(out.exists())
                self.assertFalse((self.root / "report").exists())
                self.assertIn("$.engagement.title", stderr)
                self.assertIn(code_name, stderr)
                self.assertNotIn(title, stderr + stdout)

    def test_forbidden_value_in_operator_metadata_fails_closed(self) -> None:
        secret_file = Path(self.temporary.name) / "secret.txt"
        secret_file.write_text(SECRET)
        code, _, stderr = run_cli(str(self.root), "--title", f"Report {SECRET}", "--forbid-file", str(secret_file))
        self.assertEqual(code, 3)
        self.assertIn("forbidden-secret", stderr)
        self.assertNotIn(SECRET, stderr)
        self.assertFalse((self.root / "report").exists())

    def test_lint_catches_what_a_broken_sanitizer_lets_through(self) -> None:
        plant_everywhere(self.root, PLANT)

        def passthrough(self, value, path, *, limit=600):
            return None if value is None else str(value)

        with mock.patch.object(Sanitizer, "text", passthrough):
            code, _, stderr = run_cli(str(self.root), "--generated-at", GENERATED)
        self.assertEqual(code, 3)
        self.assertFalse((self.root / "report").exists())
        self.assertRegex(stderr, r"\$\.(runs|findings|executiveSummary)\[\d+\]\.\S+: (subscriber-identifier|authorization-material|unapproved-address)")
        self.assertNotIn(SECRET, stderr)

    def test_sanitizer_rules(self) -> None:
        model, ctx = build_report(self.root, Options(generated_at=GENERATED))
        clean = ctx.sanitizer.text
        self.assertEqual(clean("SIP/2.0 200 OK", "p"), "SIP/2.0 200 OK")
        self.assertEqual(clean("pass=10 fail=0 unknown=2", "p"), "pass=10 fail=0 unknown=2")
        self.assertEqual(clean("call to 127.0.0.2:5060/udp", "p"), "call to 127.0.0.2:5060/udp")
        self.assertNotIn("hunter2", clean("the password: hunter2", "p"))
        self.assertNotIn("Zx9", clean("token Zx9fQ2LmP0aB7cD4eF", "p"))
        self.assertIn("e98b847753fe41839b190f7768be35bfe7368a5e3eb0807f826fdad6d20885af", clean("sha256 e98b847753fe41839b190f7768be35bfe7368a5e3eb0807f826fdad6d20885af", "p"))
        self.assertEqual(clean(f"run {PASS_CALL} ok", "p"), f"run {PASS_CALL} ok")
        self.assertEqual(clean("a‮b\x00c\td", "p"), "abc d")
        self.assertEqual(len(clean("x" * 5000, "p")), 600)


class RenderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = engagement(Path(self.temporary.name))
        add_check_run(self.root, "20261118T031000Z-checks-a")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_hostile_strings_are_escaped_in_every_rendering(self) -> None:
        plant_everywhere(self.root, HOSTILE)
        findings = self.root / "checks" / "20261118T031000Z-checks-a" / "findings.json"
        value = json.loads(findings.read_text())
        for item in value["findings"]:
            item["title"] = HOSTILE
            item["remediation"] = HOSTILE
        findings.write_text(json.dumps(value))
        model = model_for(self.root)
        html_text = render_html(model, "a" * 64)
        parser = check_html(self, html_text)
        self.assertNotIn("<script", html_text)
        self.assertIn("&lt;script&gt;", html_text)
        self.assertNotIn("‮", html_text)
        self.assertNotIn("\x07", html_text)
        self.assertNotIn("Z" * 700, html_text)
        self.assertEqual([t for t, _ in parser.tags if t == "script"], [])
        for tag, attributes in parser.tags:
            for name, attribute in attributes.items():
                self.assertFalse(name.startswith("on"), (tag, name))
                self.assertNotIn("javascript:", attribute or "")
        markdown = render_markdown(model, "a" * 64)
        self.assertGreater(check_markdown_tables(self, markdown), 5)
        self.assertNotRegex(markdown, r"(?<!\\)<script")
        self.assertIn("\\<script\\>", markdown)
        self.assertNotRegex(markdown, r"(?<!\\)\]\(javascript")
        self.assertNotIn("‮", markdown)
        text = render_text(model, "a" * 64)
        self.assertNotIn("\x07", text)

    def test_html_is_self_contained_accessible_and_printable(self) -> None:
        model = model_for(self.root)
        document = render_html(model, "b" * 64)
        parser = check_html(self, document)
        tags = [tag for tag, _ in parser.tags]
        self.assertNotIn("script", tags)
        self.assertNotIn("link", tags)
        self.assertNotIn("img", tags)
        self.assertNotRegex(document, r"(?i)(src|href)\s*=\s*\"?(https?:)?//")
        self.assertNotIn("@import", document)
        self.assertIn("prefers-color-scheme:dark", document)
        self.assertIn("@media print", document)
        self.assertIn("@page", document)
        self.assertIn("max-width:720px", document)
        self.assertGreaterEqual(tags.count("caption"), 5)
        self.assertEqual(tags.count("caption"), tags.count("table"))
        self.assertTrue(any(tag == "th" and a.get("scope") == "col" for tag, a in parser.tags))
        self.assertTrue(any(tag == "th" and a.get("scope") == "row" for tag, a in parser.tags))
        self.assertEqual(tags.count("svg"), 2)
        self.assertIn('lang="en"', document)
        # Severity is shown as text, not colour alone.
        self.assertIn(">HIGH</span>", document)
        # Executive summary comes before the detail sections.
        self.assertLess(document.index('id="summary"'), document.index('id="activity"'))
        self.assertLess(document.index('id="summary"'), document.index('id="findings"'))
        self.assertIn("b" * 64, document)

    def test_markdown_structure(self) -> None:
        model = model_for(self.root)
        document = render_markdown(model, "c" * 64)
        check_markdown_tables(self, document)
        headings = [line for line in document.splitlines() if line.startswith("## ")]
        self.assertEqual(headings[0], "## Executive summary")
        for name in ("## Authorization", "## Activity ledger", "## Results", "## Findings", "## Evidence index", "## Limitations", "## Recommendations", "## Integrity"):
            self.assertIn(name, headings)
        self.assertIn("**HIGH**", document)

    def test_outputs_are_byte_deterministic(self) -> None:
        first = Path(self.temporary.name) / "first"
        second = Path(self.temporary.name) / "second"
        for out in (first, second):
            code, _, stderr = run_cli(str(self.root), "--output", str(out), "--generated-at", GENERATED, "--format", "md", "--format", "html", "--format", "text")
            self.assertEqual(code, 0, stderr)
        self.assertEqual(outputs(first), outputs(second))
        model = json.loads((first / "report.json").read_text())
        self.assertEqual(model["engagement"]["generatedAt"], GENERATED)


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = engagement(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_default_output_modes_and_no_silent_overwrite(self) -> None:
        code, stdout, stderr = run_cli(str(self.root), "--generated-at", GENERATED)
        self.assertEqual(code, 0, stderr)
        report = self.root / "report"
        self.assertEqual(sorted(p.name for p in report.iterdir()), ["engagement-report.html", "engagement-report.md", "report.json"])
        self.assertEqual(report.stat().st_mode & 0o777, 0o700)
        for path in report.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertIn("Network activity: none", stdout)
        first = outputs(report)
        code, stdout, _ = run_cli(str(self.root), "--generated-at", "2026-11-18T05:00:00Z")
        self.assertEqual(code, 0)
        self.assertEqual(outputs(report), first)
        self.assertTrue((self.root / "report-20261118T050000Z" / "report.json").is_file())
        code, _, _ = run_cli(str(self.root), "--generated-at", "2026-11-18T05:00:00Z")
        self.assertTrue((self.root / "report-20261118T050000Z-2" / "report.json").is_file())
        code, _, _ = run_cli(str(self.root), "--generated-at", "2026-11-18T06:00:00Z", "--force")
        self.assertEqual(code, 0)
        self.assertIn("2026-11-18T06:00:00Z", (report / "report.json").read_text())

    def test_usage_errors_exit_two_and_write_nothing(self) -> None:
        missing = Path(self.temporary.name) / "missing"
        self.assertEqual(run_cli(str(missing))[0], 2)
        self.assertEqual(run_cli(str(self.root), "--since", "yesterday")[0], 2)
        self.assertEqual(run_cli(str(self.root), "--generated-at", "2026-11-18T04:00:00")[0], 2)
        busy = Path(self.temporary.name) / "busy"
        busy.mkdir()
        (busy / "keep.txt").write_text("keep")
        self.assertEqual(run_cli(str(self.root), "--output", str(busy))[0], 2)
        self.assertEqual((busy / "keep.txt").read_text(), "keep")
        self.assertEqual(run_cli(str(self.root), "--run-root", str(missing))[0], 2)
        self.assertFalse((self.root / "report").exists())
        with self.assertRaises(SystemExit) as raised, contextlib.redirect_stderr(io.StringIO()):
            summary_cli.main(["--format", "pdf", str(self.root)])
        self.assertEqual(raised.exception.code, 2)

    def test_integrity_exception_exit_status(self) -> None:
        path = self.root / "calls" / PASS_CALL / "result.json"
        value = json.loads(path.read_text())
        value["timestamps"]["started"] = "2026-11-18T01:00:00Z"
        path.write_text(json.dumps(value))
        code, stdout, _ = run_cli(str(self.root), "--generated-at", GENERATED)
        self.assertEqual(code, 1)
        self.assertIn("outside-approval-window", stdout)
        markdown = (self.root / "report" / "engagement-report.md").read_text()
        self.assertLess(markdown.index("Integrity exceptions"), markdown.index("## Executive summary"))
        code, _, _ = run_cli(str(self.root), "--generated-at", GENERATED, "--allow-exceptions", "--force")
        self.assertEqual(code, 0)

    def test_journal_flag_records_the_report_hash(self) -> None:
        before = len(verify(self.root).entries)
        code, stdout, stderr = run_cli(str(self.root), "--generated-at", GENERATED, "--journal")
        self.assertEqual(code, 0, stderr)
        entries = verify(self.root).entries
        self.assertEqual(len(entries), before + 1)
        digest = re.search(r"report.json SHA-256: ([0-9a-f]{64})", stdout).group(1)
        self.assertIn(digest, entries[-1]["summary"])
        self.assertIn("report/report.json", entries[-1]["evidence"])
        self.assertEqual(entries[-1]["kind"], "action")
        self.assertIn(digest, (self.root / "report" / "engagement-report.md").read_text())

    def test_external_run_root_uses_relative_labels(self) -> None:
        external = Path(self.temporary.name) / "elsewhere" / "runs"
        external.mkdir(parents=True)
        shutil.copytree(self.root / "calls" / PASS_CALL, external / "20261118T025500Z-extra-call")
        model = model_for(self.root, run_roots=(external,))
        refs = {run["ref"] for run in model["runs"]}
        self.assertIn("external-root-1/20261118T025500Z-extra-call", refs)
        self.assertNotIn(self.temporary.name, json.dumps(model))

    def test_launcher_routes_summary_on_the_host(self) -> None:
        import subprocess

        result = subprocess.run(
            [ROOT / "bin" / "sippycup", "summary", "--help"],
            cwd=ROOT,
            env={**os.environ, "SIPPYCUP_RUNTIME": "/definitely/missing/runtime"},
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--audience", result.stdout)
        self.assertIn("Network activity: none", result.stdout)


class AdvisorTests(unittest.TestCase):
    def test_owner_report_action_appears_once_a_run_exists(self) -> None:
        from sippycup_workbench.advisor import assess

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "assessment"
            initialize(root, title="Assessment", owner="Owner")
            before = {action["id"] for action in assess(root)["nextActions"]}
            self.assertNotIn("render-owner-report", before)
            (root / "calls" / "20261118T000000Z-call").mkdir(parents=True)
            actions = {action["id"]: action for action in assess(root)["nextActions"]}
            self.assertIn("render-owner-report", actions)
            self.assertEqual(actions["render-owner-report"]["argv"], ["./bin/sippycup", "summary", str(root)])
            self.assertFalse(actions["render-owner-report"]["networkActivity"])
            (root / "calls" / "20261118T000000Z-call").rmdir()
            (root / "runs" / "20261118T000000Z-campaign").mkdir(parents=True)
            self.assertIn("render-owner-report", {a["id"] for a in assess(root)["nextActions"]})


if __name__ == "__main__":
    unittest.main()
