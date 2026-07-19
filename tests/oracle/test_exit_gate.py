from __future__ import annotations

import contextlib
import importlib
import io
import json
import subprocess
import sys
import tempfile
import time
import tracemalloc
import unittest
from unittest import mock
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_oracle.adapter import parse_tshark_json  # noqa: E402
from sippycup_oracle.cli import (  # noqa: E402
    EXIT_ASSERTION_FAILURE,
    EXIT_BAD_CAPTURE,
    EXIT_BAD_EXPECTATIONS,
    EXIT_INCONCLUSIVE,
    EXIT_INTERNAL,
    EXIT_PASS,
    ExpectationsError,
    TsharkExecutionError,
    _run_tshark_bounded,
    build_result_document,
    load_expectations,
    main,
    render_human,
    result_exit_code,
)
from sippycup_oracle.dialogs import reconstruct_dialogs  # noqa: E402
from sippycup_oracle.media import MediaExpectations, evaluate_invariants  # noqa: E402
from sippycup_oracle.records import (  # noqa: E402
    CaptureFormat,
    CaptureRecord,
    CaptureStatus,
    Known,
    Unknown,
    Verdict,
)
from tests.oracle.test_dialogs import scenario_frames  # noqa: E402
from tests.oracle.test_media import (  # noqa: E402
    assertions,
    baseline_dialog,
    good_media,
    rtp_frame,
)

FIXTURES = Path(__file__).parent / "fixtures"
EXAMPLE_EXPECTATIONS = ROOT / "examples" / "oracle-expectations.yaml"


def good_capture() -> CaptureRecord:
    return CaptureRecord(
        schema_version="sippycup.packet-records/v1",
        capture_format=CaptureFormat.PCAP,
        frames=scenario_frames("baseline") + good_media(),
    )


class GoldenCorpusGateTests(unittest.TestCase):
    def test_manifest_has_every_required_protocol_and_adversarial_case(self) -> None:
        corpus = json.loads(
            (FIXTURES / "golden-corpus.json").read_text(encoding="utf-8")
        )
        coverage = {
            label for case in corpus["cases"] for label in case["coverage"]
        }
        required = {
            "udp",
            "tcp",
            "ipv4",
            "ipv6",
            "pcap",
            "pcapng",
            "early-media",
            "re-invite",
            "fork",
            "loss",
            "reorder",
            "rfc4733",
            "one-way",
            "third-party",
            "post-teardown",
            "truncation",
            "malformed",
        }
        self.assertFalse(required - coverage)

    def test_every_manifest_case_executes_its_linked_runner(self) -> None:
        corpus = json.loads(
            (FIXTURES / "golden-corpus.json").read_text(encoding="utf-8")
        )
        for case in corpus["cases"]:
            with self.subTest(case=case["id"]):
                module_name, target = case["runner"].split(":", 1)
                class_name, method_name = target.split(".", 1)
                module = importlib.import_module(module_name)
                test_case = getattr(module, class_name)(method_name)
                result = unittest.TestResult()
                test_case.run(result)
                self.assertEqual(result.errors, [])
                self.assertEqual(result.failures, [])
                self.assertEqual(result.skipped, [])

    def test_mutation_corpus_produces_named_evidenced_failures(self) -> None:
        dialog = baseline_dialog()
        one_way = tuple(
            frame
            for frame in good_media()
            if frame.rtp is not None
            and frame.source.address == Known("192.0.2.10")
        )
        third_party = good_media() + (
            rtp_frame(
                700,
                "0.40",
                caller_to_callee=True,
                sequence=4,
                timestamp=480,
                source_address="203.0.113.77",
            ),
        )
        teardown = good_media() + (
            rtp_frame(
                701,
                "0.51",
                caller_to_callee=True,
                sequence=4,
                timestamp=480,
            ),
        )
        impaired = (
            rtp_frame(710, "0.32", caller_to_callee=True, sequence=1, timestamp=0),
            rtp_frame(711, "0.34", caller_to_callee=True, sequence=3, timestamp=160),
            rtp_frame(712, "0.36", caller_to_callee=True, sequence=2, timestamp=320),
            rtp_frame(713, "0.38", caller_to_callee=True, sequence=2, timestamp=320),
        )
        cases = (
            (one_way, "media.directionality"),
            (third_party, "media.endpoints"),
            (teardown, "media.timing"),
            (impaired, "media.sequence"),
        )
        for frames, assertion_id in cases:
            with self.subTest(assertion_id=assertion_id):
                result = assertions(evaluate_invariants(frames, dialog))[assertion_id]
                self.assertEqual(result.verdict, Verdict.FAIL)
                self.assertTrue(result.evidence)
                for evidence in result.evidence:
                    self.assertIsInstance(evidence.frame_number, Known)
                    self.assertIsInstance(evidence.timestamp_epoch, Known)

    def test_positive_early_media_reinvite_fork_and_dtmf_cases(self) -> None:
        early = reconstruct_dialogs(scenario_frames("early_media")).dialogs[0]
        early_media = (
            rtp_frame(720, "0.25", caller_to_callee=True, sequence=1, timestamp=0),
            rtp_frame(721, "0.25", caller_to_callee=False, sequence=1, timestamp=0),
        )
        self.assertEqual(
            assertions(evaluate_invariants(early_media, early))["media.timing"].verdict,
            Verdict.PASS,
        )
        reinvite = reconstruct_dialogs(scenario_frames("renegotiation")).dialogs[0]
        changed = (
            rtp_frame(730, "0.25", caller_to_callee=True, sequence=1, timestamp=0),
            rtp_frame(
                731,
                "0.55",
                caller_to_callee=True,
                sequence=2,
                timestamp=2400,
                payload_type=8,
                ssrc=300,
            ),
        )
        transition = assertions(
            evaluate_invariants(
                changed,
                reinvite,
                MediaExpectations(require_bidirectional=False),
            )
        )["media.transitions"]
        self.assertEqual(transition.verdict, Verdict.PASS)
        self.assertEqual(
            len(reconstruct_dialogs(scenario_frames("fork")).dialogs), 2
        )
        dtmf = assertions(
            evaluate_invariants(
                good_media(),
                baseline_dialog(),
                MediaExpectations(require_dtmf=True),
            )
        )["media.dtmf"]
        self.assertEqual(dtmf.verdict, Verdict.PASS)

    def test_truncation_and_dissector_disagreement_remain_unknown(self) -> None:
        frames = list(scenario_frames("baseline"))
        frames[1] = replace(
            frames[1], status=Known(CaptureStatus.TRUNCATED)
        )
        complete = reconstruct_dialogs(frames).dialogs[0].complete
        self.assertIsInstance(complete, Unknown)
        malformed = parse_tshark_json(
            (FIXTURES / "malformed.pcapng.tshark.json").read_text(
                encoding="utf-8"
            ),
            CaptureFormat.PCAPNG,
        )
        self.assertIsInstance(
            malformed.frames[0].evidence.frame_number, Unknown
        )


class CliContractGateTests(unittest.TestCase):
    def test_example_expectations_load_and_result_is_deterministic(self) -> None:
        expectation, policy, selector = load_expectations(EXAMPLE_EXPECTATIONS)
        capture = good_capture()
        first = build_result_document(
            capture, expectation, on_unknown=policy, dialog_selector=selector
        )
        second = build_result_document(
            capture, expectation, on_unknown=policy, dialog_selector=selector
        )
        encoded_first = json.dumps(first, sort_keys=True, separators=(",", ":"))
        encoded_second = json.dumps(second, sort_keys=True, separators=(",", ":"))
        self.assertEqual(encoded_first, encoded_second)
        self.assertEqual(first["verdict"], "pass")
        self.assertEqual(result_exit_code(first), EXIT_PASS)

    def test_human_and_json_are_views_of_identical_verdicts_and_evidence(self) -> None:
        document = build_result_document(
            good_capture(),
            MediaExpectations(expected_codecs=("PCMU",), require_dtmf=True),
        )
        human = render_human(document)
        self.assertIn(f"OVERALL {document['verdict'].upper()}", human)
        for item in document["assertions"]:
            self.assertIn(item["id"], human)
            self.assertIn(item["verdict"].upper(), human)
            for evidence in item["evidence"]:
                if evidence["frame_number"]["state"] == "known":
                    self.assertIn(
                        f"frame={evidence['frame_number']['value']}@", human
                    )

    def test_unknown_never_satisfies_required_expectation(self) -> None:
        encrypted = (
            rtp_frame(
                800,
                "0.32",
                caller_to_callee=True,
                sequence=None,
                timestamp=None,
                encrypted=True,
            ),
            rtp_frame(
                801,
                "0.33",
                caller_to_callee=False,
                sequence=None,
                timestamp=None,
                encrypted=True,
            ),
        )
        capture = CaptureRecord(
            "sippycup.packet-records/v1",
            CaptureFormat.PCAP,
            scenario_frames("baseline") + encrypted,
        )
        inconclusive = build_result_document(
            capture, MediaExpectations(), on_unknown="inconclusive"
        )
        self.assertEqual(inconclusive["verdict"], "unknown")
        self.assertEqual(result_exit_code(inconclusive), EXIT_INCONCLUSIVE)
        strict = build_result_document(
            capture, MediaExpectations(), on_unknown="fail"
        )
        self.assertEqual(strict["verdict"], "fail")
        self.assertEqual(result_exit_code(strict), EXIT_ASSERTION_FAILURE)

    def test_stable_input_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            bad_expectations = directory_path / "bad.yaml"
            bad_expectations.write_text("schema_version: wrong\n", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = main(
                    [
                        str(directory_path / "missing.pcap"),
                        "--expect",
                        str(bad_expectations),
                    ]
                )
            self.assertEqual(status, EXIT_BAD_EXPECTATIONS)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = main(
                    [
                        str(directory_path / "missing.pcap"),
                        "--expect",
                        str(EXAMPLE_EXPECTATIONS),
                    ]
                )
            self.assertEqual(status, EXIT_BAD_CAPTURE)

    def test_tshark_execution_failure_has_stable_internal_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "header-only.pcap"
            capture.write_bytes(
                bytes.fromhex(
                    "d4c3b2a1020004000000000000000000ffff000001000000"
                )
            )
            stderr = io.StringIO()
            with mock.patch(
                "sippycup_oracle.cli._run_tshark_bounded",
                side_effect=TsharkExecutionError("fixture execution failure"),
            ), contextlib.redirect_stderr(stderr):
                status = main(
                    [
                        str(capture),
                        "--expect",
                        str(EXAMPLE_EXPECTATIONS),
                    ]
                )
            self.assertEqual(status, EXIT_INTERNAL)
            self.assertIn("fixture execution failure", stderr.getvalue())

    def test_expectations_schema_is_strict_at_loader_boundary(self) -> None:
        invalid_documents = (
            # Unknown top-level and expectation fields.
            """
schema_version: sippycup.expectations/v1
extra: true
expectations: [{id: x, type: call_path}]
""",
            """
schema_version: sippycup.expectations/v1
expectations: [{id: x, type: call_path, extra: true}]
""",
            # Required ID, multiplicity, selector, and bool-vs-int.
            """
schema_version: sippycup.expectations/v1
expectations: [{type: call_path}]
""",
            """
schema_version: sippycup.expectations/v1
expectations:
  - {id: duplicate, type: call_path}
  - {id: duplicate, type: call_path}
""",
            """
schema_version: sippycup.expectations/v1
capture: {dialog_selector: ""}
expectations: [{id: x, type: call_path}]
""",
            """
schema_version: sippycup.expectations/v1
expectations:
  - id: x
    type: call_path
    parameters: {require_bidirectional: 1}
""",
            """
schema_version: sippycup.expectations/v1
expectations:
  - id: x
    type: call_path
    parameters: {max_duplicates: true}
""",
            # Frozen scope must be unique literal addresses.
            """
schema_version: sippycup.expectations/v1
capture: {allowed_endpoints: [voice.example.invalid]}
expectations: [{id: x, type: call_path}]
""",
            """
schema_version: sippycup.expectations/v1
capture: {allowed_endpoints: [192.0.2.1, 192.0.2.1]}
expectations: [{id: x, type: call_path}]
""",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.yaml"
            for document in invalid_documents:
                path.write_text(document, encoding="utf-8")
                with self.assertRaises(ExpectationsError):
                    load_expectations(path)

    def test_nonfinite_and_out_of_range_thresholds_exit_two(self) -> None:
        values = (".nan", ".inf", "-.inf", "1.01")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.yaml"
            for value in values:
                path.write_text(
                    (
                        "schema_version: sippycup.expectations/v1\n"
                        "expectations:\n"
                        "  - id: bounded\n"
                        "    type: call_path\n"
                        "    parameters:\n"
                        f"      max_loss_fraction: {value}\n"
                    ),
                    encoding="utf-8",
                )
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    status = main(
                        [
                            "missing.pcap",
                            "--expect",
                            str(path),
                        ]
                    )
                self.assertEqual(status, EXIT_BAD_EXPECTATIONS, value)

    def test_tshark_wall_time_and_output_are_bounded(self) -> None:
        with self.assertRaises(TsharkExecutionError):
            _run_tshark_bounded(
                [sys.executable, "-c", "print('x' * 10000)"],
                max_stdout_bytes=100,
            )
        with self.assertRaises(TsharkExecutionError):
            _run_tshark_bounded(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stderr.write('x' * 10000)",
                ],
                max_stderr_bytes=100,
            )
        with self.assertRaises(TsharkExecutionError):
            _run_tshark_bounded(
                [sys.executable, "-c", "import time; time.sleep(1)"],
                timeout_seconds=0.02,
            )

    def test_capture_and_analysis_amplification_limits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "oversize.pcap"
            capture.write_bytes(
                bytes.fromhex(
                    "d4c3b2a1020004000000000000000000ffff000001000000"
                )
            )
            with mock.patch("sippycup_oracle.cli.MAX_CAPTURE_BYTES", 1):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    status = main(
                        [
                            str(capture),
                            "--expect",
                            str(EXAMPLE_EXPECTATIONS),
                        ]
                    )
                self.assertEqual(status, EXIT_BAD_CAPTURE)
        with mock.patch("sippycup_oracle.cli.MAX_ANALYSIS_FRAMES", 1):
            with self.assertRaises(ValueError):
                build_result_document(good_capture(), MediaExpectations())

    def test_real_cli_human_json_parity_and_launcher_dispatch(self) -> None:
        from tests.oracle.test_tshark_integration import (
            RealTsharkIntegrationTests,
        )

        helper = RealTsharkIntegrationTests()
        temporary, capture_path, _ = helper._capture(CaptureFormat.PCAP, False)
        try:
            commands = []
            for output_format in ("human", "json"):
                commands.append(
                    subprocess.run(
                        [
                            str(ROOT / "bin" / "sippycup"),
                            "assert",
                            str(capture_path),
                            "--expect",
                            str(EXAMPLE_EXPECTATIONS),
                            "--format",
                            output_format,
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                )
            human, machine = commands
            self.assertEqual(human.returncode, EXIT_ASSERTION_FAILURE)
            self.assertEqual(machine.returncode, EXIT_ASSERTION_FAILURE)
            document = json.loads(machine.stdout)
            self.assertIn(f"OVERALL {document['verdict'].upper()}", human.stdout)
            for item in document["assertions"]:
                self.assertIn(item["id"], human.stdout)
                self.assertIn(item["verdict"].upper(), human.stdout)
        finally:
            temporary.cleanup()

    def test_default_json_has_no_credentials_payload_bytes_or_audio(self) -> None:
        document = build_result_document(
            good_capture(), MediaExpectations(require_dtmf=True)
        )
        encoded = json.dumps(document, sort_keys=True).lower()
        for forbidden in (
            "authorization",
            "proxy-authorization",
            "must-never-serialize",
            "payload-bytes",
            "decoded_audio",
            "audio_bytes",
        ):
            self.assertNotIn(forbidden, encoded)


class PerformanceGateTests(unittest.TestCase):
    def test_twenty_thousand_packet_analysis_envelope(self) -> None:
        frames = tuple(
            rtp_frame(
                1000 + index,
                str(Decimal("0.32") + Decimal(index) * Decimal("0.02")),
                caller_to_callee=True,
                sequence=index % 65536,
                timestamp=(index * 160) % (2**32),
            )
            for index in range(20_000)
        )
        tracemalloc.start()
        started = time.monotonic()
        analysis = evaluate_invariants(
            frames,
            baseline_dialog(),
            MediaExpectations(require_bidirectional=False),
        )
        elapsed = time.monotonic() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertTrue(analysis.streams)
        self.assertLess(elapsed, 8.0)
        self.assertLess(peak, 128 * 1024 * 1024)

    def test_many_dialog_analysis_amplification_envelope(self) -> None:
        frames = tuple(
            frame
            for index in range(250)
            for frame in scenario_frames(
                "baseline",
                call_id=f"many-{index}@example.invalid",
                start=index * 10 + 1,
            )
        )
        capture = CaptureRecord(
            "sippycup.packet-records/v1",
            CaptureFormat.PCAP,
            frames,
        )
        tracemalloc.start()
        started = time.monotonic()
        document = build_result_document(
            capture,
            MediaExpectations(require_bidirectional=False),
        )
        elapsed = time.monotonic() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertEqual(len(document["dialogs"]), 250)
        self.assertLess(elapsed, 8.0)
        self.assertLess(peak, 128 * 1024 * 1024)

    def test_real_tshark_json_round_trip_envelope(self) -> None:
        from tests.oracle.test_tshark_integration import (
            RealTsharkIntegrationTests,
        )

        started = time.monotonic()
        temporary, _, capture = RealTsharkIntegrationTests()._capture(
            CaptureFormat.PCAP, False
        )
        elapsed = time.monotonic() - started
        try:
            self.assertTrue(capture.frames)
            self.assertLess(elapsed, 3.0)
        finally:
            temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
