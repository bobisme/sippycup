"""The owner report draws call-matrix grids and refuses to trust matrix.json blindly."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_workbench import summary_matrix  # noqa: E402
from sippycup_workbench.summary_model import Options, build_report  # noqa: E402
from sippycup_workbench.summary_privacy import lint_model, lint_text  # noqa: E402
from sippycup_workbench.summary_render import render_html, render_markdown, render_text  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "engagement-report" / "practice"
UDP_PASS = "20261118T025420.201700Z-sippycup-local-practice-c956ec1d"
UDP_FAIL = "20261118T025439.548206Z-sippycup-local-practice-6fe5010f"
TLS_PASS = "20261118T025453.149898Z-sippycup-local-practice-tls-228c57af"
MATRIX_NAME = "20261118T025400.000000Z-matrix-echo-aaaaaaaa"


def cell(index, transport, codec, srtp, run=None, verdict="pass", **extra):
    value = {
        "index": index, "transport": transport, "codec": codec, "srtp": srtp,
        "profile": "work/practice/p.yaml", "status": "run" if run else "not-run",
        "warning": None,
    }
    if run:
        value.update(verdict=verdict, state="completed", exitCode=0, finalStatus=200, setupSeconds=0.042,
                     runDirectory=f"/work/eng/calls/{run}", negotiated=codec, codecVerifiedOnWire=True, srtpActive=False)
    value.update(extra)
    return value


def matrix_document(cells, **extra):
    document = {
        "apiVersion": "sippycup.dev/call-matrix/v1", "state": "stopped", "ready": True, "destination": "echo",
        "transports": ["udp", "tls"], "codecs": ["PCMU", "PCMA"], "srtp": ["off"],
        "totalCalls": len(cells), "maxCalls": 12, "profiles": {}, "spacingSeconds": 1.0,
        "plannedWallSeconds": 20, "callSeconds": 4, "cells": cells, "blockingErrors": [],
        "exitCode": 3, "stopReason": "call-rate-limited: the far end answered 429", "callsPlaced": 2, "passed": 2,
        "timestamps": {"started": "2026-11-18T02:54:00Z", "finished": "2026-11-18T02:55:00Z"},
        "networkActivity": "2 guided call(s)",
    }
    document.update(extra)
    return document


def good_cells():
    return [
        cell(1, "udp", "PCMU", "off", UDP_PASS),
        cell(2, "udp", "PCMA", "off"),
        cell(3, "tls", "PCMU", "off", TLS_PASS),
        cell(4, "tls", "PCMA", "off"),
    ]


class SummaryMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "work" / "eng"
        shutil.copytree(FIXTURE, self.root)
        self.directory = self.root / "matrix" / MATRIX_NAME

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, document) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        (self.directory / "matrix.json").write_text(json.dumps(document))

    def report(self):
        return build_report(self.root, Options(generated_at="2026-11-18T04:00:00Z"))

    def codes(self, model):
        return sorted(e["code"] for e in model["integrityExceptions"] if e["code"].startswith("matrix-"))

    def test_grid_has_rows_codec_columns_verdicts_and_not_run_cells(self) -> None:
        self.write(matrix_document(good_cells()))
        model, ctx = self.report()
        self.assertEqual([], self.codes(model))
        (matrix,) = model["matrices"]
        self.assertEqual(["PCMU", "PCMA"], matrix["codecs"])
        self.assertEqual([("udp", "off"), ("tls", "off")], [(r["transport"], r["srtp"]) for r in matrix["rows"]])
        udp = matrix["rows"][0]["cells"]
        self.assertEqual(("pass", 0.042, "run"), (udp[0]["verdict"], udp[0]["setupSeconds"], udp[0]["status"]))
        self.assertEqual("not-run", udp[1]["status"])
        self.assertEqual({r["id"]: r["label"] for r in model["runs"]}[UDP_PASS], udp[0]["run"])
        self.assertEqual(2, matrix["notRun"])
        self.assertIn("matrix-incomplete", [item["code"] for item in model["limitations"]])
        text = render_text(model, "0" * 64)
        self.assertIn("CALL MATRIX", text)
        self.assertIn("not run", text)
        markdown = render_markdown(model, "0" * 64)
        self.assertIn("### Call matrices", markdown)
        self.assertIn("| udp | off | pass 0.042s \\[R", markdown)
        html = render_html(model, "0" * 64)
        self.assertIn("Call matrix M1", html)
        self.assertIn("mx mx-ok", html)
        # Path and address never reach the report; the privacy lint is clean.
        blob = json.dumps(model) + text + markdown + html
        self.assertNotIn("/work/eng/calls", blob)
        self.assertEqual([], lint_model(model, addresses=ctx.addresses))
        for name, rendered in (("txt", text), ("md", markdown), ("html", html)):
            self.assertEqual([], lint_text(name, rendered, addresses=ctx.addresses))

    def test_a_run_directory_that_does_not_exist_is_an_exception(self) -> None:
        cells = good_cells()
        cells[0]["runDirectory"] = "/work/eng/calls/20261118T000000.000000Z-never-existed-00000000"
        self.write(matrix_document(cells))
        model, _ = self.report()
        self.assertIn("matrix-run-missing", self.codes(model))

    def test_a_verdict_that_disagrees_with_its_run_is_an_exception(self) -> None:
        cells = good_cells()
        cells[0]["runDirectory"] = f"/work/eng/calls/{UDP_FAIL}"  # that run recorded registration-failed
        self.write(matrix_document(cells))
        model, _ = self.report()
        self.assertIn("matrix-verdict-mismatch", self.codes(model))

    def test_a_transport_that_disagrees_with_its_run_is_an_exception(self) -> None:
        cells = good_cells()
        cells[0]["transport"] = "tcp"
        self.write(matrix_document(cells, transports=["tcp", "tls"]))
        model, _ = self.report()
        self.assertIn("matrix-run-mismatch", self.codes(model))

    def test_counts_that_do_not_add_up_are_an_exception(self) -> None:
        self.write(matrix_document(good_cells(), callsPlaced=4, passed=3))
        model, _ = self.report()
        self.assertIn("matrix-count-mismatch", self.codes(model))

    def test_a_document_that_fails_the_schema_is_not_drawn(self) -> None:
        cells = good_cells()
        cells[1]["transport"] = "sctp"
        self.write(matrix_document(cells))
        model, _ = self.report()
        self.assertEqual([], model["matrices"])
        self.assertIn("matrix-invalid", self.codes(model))
        details = " ".join(e["detail"] for e in model["integrityExceptions"] if e["code"] == "matrix-invalid")
        self.assertNotIn("sctp", details)

    def test_free_text_is_sanitized(self) -> None:
        self.write(matrix_document(good_cells(), stopReason="rejected by 203.0.113.9 with nonce=abcdef0123456789abcdef"))
        model, ctx = self.report()
        (matrix,) = model["matrices"]
        self.assertNotIn("203.0.113.9", matrix["stopReason"])
        self.assertEqual([], lint_model(model, addresses=ctx.addresses))

    def test_no_matrix_means_no_section_content(self) -> None:
        model, _ = self.report()
        self.assertEqual([], model["matrices"])
        self.assertIn("No call matrix was found.", render_markdown(model, "0" * 64))

    def test_validator_covers_the_schema_keywords(self) -> None:
        schema = json.loads((ROOT / "schemas" / "call-matrix-v1.schema.json").read_text())
        self.assertEqual([], summary_matrix.validate(matrix_document(good_cells()), schema))
        broken = matrix_document(good_cells())
        del broken["cells"]
        broken["maxCalls"] = 99
        broken["state"] = "weird"
        problems = " ".join(summary_matrix.validate(broken, schema))
        for expected in ("missing required field cells", "$.maxCalls", "$.state"):
            self.assertIn(expected, problems)


if __name__ == "__main__":
    unittest.main()
