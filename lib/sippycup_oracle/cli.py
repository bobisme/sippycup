"""Command-line capture oracle with stable JSON, human, and exit contracts."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import fields
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Sequence

import yaml

from .adapter import (
    CaptureDecodeError,
    parse_tshark_json,
    probe_capture_format,
    tshark_json_args,
)
from .dialogs import reconstruct_dialogs
from .media import (
    Applicability,
    AssertionResult,
    MediaExpectations,
    evaluate_invariants,
    partition_media_frames,
)
from .records import (
    RESULT_SCHEMA_VERSION,
    EvidenceRef,
    Known,
    Unknown,
    UnknownReason,
    Verdict,
    to_primitive,
)

EXIT_PASS = 0
EXIT_ASSERTION_FAILURE = 1
EXIT_BAD_EXPECTATIONS = 2
EXIT_BAD_CAPTURE = 3
EXIT_INCONCLUSIVE = 4
EXIT_INTERNAL = 5

MAX_CAPTURE_BYTES = 512 * 1024 * 1024
MAX_TSHARK_STDOUT_BYTES = 256 * 1024 * 1024
MAX_TSHARK_STDERR_BYTES = 1024 * 1024
MAX_TSHARK_SECONDS = 120.0
MAX_ANALYSIS_FRAMES = 1_000_000
MAX_ANALYSIS_DIALOGS = 10_000
_ID_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")


class ExpectationsError(ValueError):
    pass


class TsharkExecutionError(RuntimeError):
    pass


def _expect_type(value: Any, expected: type, name: str) -> Any:
    if not isinstance(value, expected):
        raise ExpectationsError(f"{name} must be {expected.__name__}")
    return value


def load_expectations(path: str | Path) -> tuple[MediaExpectations, str, str | None]:
    try:
        with Path(path).open("r", encoding="utf-8") as source:
            document = yaml.safe_load(source)
    except (OSError, yaml.YAMLError) as exc:
        raise ExpectationsError(f"cannot read expectations: {exc}") from exc
    _expect_type(document, dict, "expectations document")
    unknown_top = set(document) - {"schema_version", "capture", "expectations"}
    if unknown_top:
        raise ExpectationsError(
            f"unknown top-level fields: {', '.join(sorted(unknown_top))}"
        )
    if document.get("schema_version") != "sippycup.expectations/v1":
        raise ExpectationsError("unsupported or missing expectations schema_version")
    items = _expect_type(document.get("expectations"), list, "expectations")
    if len(items) != 1:
        raise ExpectationsError("exactly one call_path expectation is required")
    item = _expect_type(items[0], dict, "expectations[0]")
    unknown_item = set(item) - {"id", "type", "parameters", "on_unknown"}
    if unknown_item:
        raise ExpectationsError(
            f"unknown expectation fields: {', '.join(sorted(unknown_item))}"
        )
    identifier = item.get("id")
    if not isinstance(identifier, str) or _ID_PATTERN.fullmatch(identifier) is None:
        raise ExpectationsError(
            "expectation id is required and must match the published pattern"
        )
    if item.get("type") != "call_path":
        raise ExpectationsError("expectation type must be call_path")
    on_unknown = item.get("on_unknown", "inconclusive")
    if on_unknown not in {"fail", "inconclusive"}:
        raise ExpectationsError("on_unknown must be fail or inconclusive")
    parameters = _expect_type(item.get("parameters", {}), dict, "parameters")
    capture = _expect_type(document.get("capture", {}), dict, "capture")
    allowed = set(capture) - {"dialog_selector", "allowed_endpoints"}
    if allowed:
        raise ExpectationsError(f"unknown capture fields: {', '.join(sorted(allowed))}")
    known_parameters = {
        field.name
        for field in fields(MediaExpectations)
        if field.name != "allowed_endpoints"
    }
    unknown_parameters = set(parameters) - known_parameters
    if unknown_parameters:
        raise ExpectationsError(
            f"unknown call_path parameters: {', '.join(sorted(unknown_parameters))}"
        )
    merged = dict(parameters)
    if "allowed_endpoints" in capture:
        endpoints = _expect_type(
            capture["allowed_endpoints"], list, "capture.allowed_endpoints"
        )
        merged["allowed_endpoints"] = endpoints
    tuple_fields = {"allowed_endpoints", "expected_codecs"}
    bool_fields = {
        "require_bidirectional",
        "require_dtmf",
        "allow_symmetric_rtp",
    }
    decimal_fields = {
        "max_setup_ms",
        "max_loss_fraction",
        "max_jitter_ms",
        "timestamp_jump_tolerance_ms",
    }
    for name in tuple_fields & merged.keys():
        values = _expect_type(merged[name], list, name)
        if not all(isinstance(value, str) for value in values):
            raise ExpectationsError(f"{name} entries must be strings")
        if any(not value for value in values) or len(set(values)) != len(values):
            raise ExpectationsError(f"{name} entries must be non-empty and unique")
        if name == "allowed_endpoints":
            try:
                for value in values:
                    ipaddress.ip_address(value)
            except ValueError as exc:
                raise ExpectationsError(
                    "allowed_endpoints entries must be literal IP addresses"
                ) from exc
        merged[name] = tuple(values)
    for name in bool_fields & merged.keys():
        if type(merged[name]) is not bool:
            raise ExpectationsError(f"{name} must be bool")
    for name in decimal_fields & merged.keys():
        try:
            merged[name] = Decimal(str(merged[name]))
        except InvalidOperation as exc:
            raise ExpectationsError(f"{name} must be numeric") from exc
        if not merged[name].is_finite():
            raise ExpectationsError(f"{name} must be finite")
        if merged[name] < 0:
            raise ExpectationsError(f"{name} must be non-negative")
    if (
        "max_loss_fraction" in merged
        and merged["max_loss_fraction"] > 1
    ):
        raise ExpectationsError("max_loss_fraction must be between 0 and 1")
    for name in {"max_duplicates", "max_reordered"} & merged.keys():
        if type(merged[name]) is not int or merged[name] < 0:
            raise ExpectationsError(f"{name} must be a non-negative integer")
    try:
        expectation = MediaExpectations(**merged)
    except TypeError as exc:
        raise ExpectationsError(str(exc)) from exc
    selector = capture.get("dialog_selector")
    if selector is not None and (
        not isinstance(selector, str) or not selector or len(selector) > 255
    ):
        raise ExpectationsError(
            "capture.dialog_selector must be a non-empty string up to 255 characters"
        )
    return expectation, on_unknown, selector


def _unknown_evidence() -> EvidenceRef:
    unknown = Unknown(UnknownReason.MISSING_FIELD, "capture has no frame evidence")
    return EvidenceRef(unknown, unknown)


def _apply_unknown_policy(
    result: AssertionResult, on_unknown: str
) -> AssertionResult:
    if (
        on_unknown == "fail"
        and result.verdict is Verdict.UNKNOWN
        and result.applicability is Applicability.APPLICABLE
    ):
        return AssertionResult(
            result.id,
            Verdict.FAIL,
            result.applicability,
            f"{result.message} (unknown policy: fail)",
            result.evidence,
            result.observed,
        )
    return result


def _assertion_json(
    result: AssertionResult, dialog_index: int
) -> dict[str, Any]:
    return {
        "id": f"dialog[{dialog_index}].{result.id}",
        "verdict": result.verdict.value,
        "applicability": result.applicability.value,
        "message": result.message,
        "evidence": [
            {
                "frame_number": to_primitive(item.frame_number),
                "timestamp_epoch": to_primitive(item.timestamp_epoch),
            }
            for item in result.evidence
        ],
        "observed": to_primitive(result.observed),
    }


def build_result_document(
    capture,
    expectation: MediaExpectations,
    *,
    on_unknown: str = "inconclusive",
    dialog_selector: str | None = None,
) -> dict[str, Any]:
    if len(capture.frames) > MAX_ANALYSIS_FRAMES:
        raise ValueError("capture exceeds the analysis frame limit")
    reconstruction = reconstruct_dialogs(capture.frames)
    dialogs = [
        dialog
        for dialog in reconstruction.dialogs
        if dialog_selector is None or dialog.key.call_id == dialog_selector
    ]
    if len(dialogs) > MAX_ANALYSIS_DIALOGS:
        raise ValueError("capture exceeds the analysis dialog limit")
    assigned_media, assignment_ambiguity = partition_media_frames(
        capture.frames, tuple(dialogs)
    )
    assertions: list[dict[str, Any]] = []
    dialog_json: list[dict[str, Any]] = []
    stream_json: list[dict[str, Any]] = []
    if not dialogs:
        evidence = (
            capture.frames[0].evidence if capture.frames else _unknown_evidence()
        )
        missing = AssertionResult(
            "dialog.present",
            Verdict.UNKNOWN,
            Applicability.APPLICABLE,
            "no matching SIP dialog could be reconstructed",
            (evidence,),
            Unknown(UnknownReason.MISSING_FIELD, "SIP dialog"),
        )
        assertions.append(_assertion_json(_apply_unknown_policy(missing, on_unknown), 0))
    for index, dialog in enumerate(dialogs):
        fallback = (
            dialog.transitions[0].evidence
            if dialog.transitions
            else dialog.sdp_revisions[0].revision.evidence
            if dialog.sdp_revisions
            else _unknown_evidence()
        )
        completion = AssertionResult(
            "dialog.complete",
            (
                Verdict.PASS
                if isinstance(dialog.complete, Known) and dialog.complete.value is True
                else Verdict.UNKNOWN
            ),
            Applicability.APPLICABLE,
            (
                "dialog setup and teardown are complete"
                if isinstance(dialog.complete, Known) and dialog.complete.value is True
                else "dialog completeness is inconclusive"
            ),
            (fallback,),
            dialog.complete,
        )
        signaling_frames = tuple(
            frame
            for frame in capture.frames
            if frame.sip is not None
            and isinstance(frame.sip.call_id, Known)
            and frame.sip.call_id.value == dialog.key.call_id
        )
        analysis = evaluate_invariants(
            signaling_frames + assigned_media[index],
            dialog,
            expectation,
            assignment_ambiguity=assignment_ambiguity[index],
        )
        all_results = (completion,) + analysis.assertions
        assertions.extend(
            _assertion_json(_apply_unknown_policy(item, on_unknown), index)
            for item in all_results
        )
        dialog_json.append(
            {
                "id": f"dialog[{index}]",
                "call_id": dialog.key.call_id,
                "state": dialog.state.value,
                "complete": to_primitive(dialog.complete),
                "evidence": to_primitive(fallback),
            }
        )
        for stream_index, stream in enumerate(analysis.streams):
            stream_json.append(
                {
                    "id": f"dialog[{index}].stream[{stream_index}]",
                    "dialog_id": f"dialog[{index}]",
                    "direction": stream.direction.value,
                    "correlation": stream.correlation.value,
                    "flow": to_primitive(stream.key),
                    "encrypted": stream.encrypted,
                    "metrics": to_primitive(stream.metrics),
                    "evidence": [
                        to_primitive(frame.evidence) for frame in stream.frames
                    ],
                }
            )
    counts = {
        name: sum(item["verdict"] == name for item in assertions)
        for name in ("pass", "fail", "unknown")
    }
    applicable_unknown = any(
        item["verdict"] == "unknown"
        and item["applicability"] == "applicable"
        for item in assertions
    )
    if counts["fail"]:
        overall = Verdict.FAIL
    elif applicable_unknown:
        overall = Verdict.UNKNOWN
    else:
        overall = Verdict.PASS
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "verdict": overall.value,
        "summary": counts,
        "assertions": assertions,
        "dialogs": dialog_json,
        "streams": stream_json,
    }


def result_exit_code(document: dict[str, Any]) -> int:
    return {
        Verdict.PASS.value: EXIT_PASS,
        Verdict.FAIL.value: EXIT_ASSERTION_FAILURE,
        Verdict.UNKNOWN.value: EXIT_INCONCLUSIVE,
    }[document["verdict"]]


def render_human(document: dict[str, Any]) -> str:
    lines = [
        f"OVERALL {document['verdict'].upper()} "
        f"(pass={document['summary']['pass']} "
        f"fail={document['summary']['fail']} "
        f"unknown={document['summary']['unknown']})"
    ]
    for item in document["assertions"]:
        evidence_parts: list[str] = []
        for evidence in item["evidence"]:
            frame = evidence["frame_number"]
            timestamp = evidence["timestamp_epoch"]
            frame_value = frame.get("value", "?")
            time_value = timestamp.get("value", "?")
            evidence_parts.append(f"frame={frame_value}@{time_value}")
        lines.append(
            f"{item['verdict'].upper():7} "
            f"[{item['applicability']}] {item['id']}: {item['message']} "
            f"({' '.join(evidence_parts)})"
        )
    return "\n".join(lines) + "\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sippycup assert",
        description="Evaluate SIP/RTP call-path expectations against a capture.",
    )
    parser.add_argument("capture")
    parser.add_argument("--expect", required=True, dest="expectations")
    parser.add_argument(
        "--format", choices=("human", "json"), default="human"
    )
    return parser


def _run_tshark_bounded(
    command: Sequence[str],
    *,
    timeout_seconds: float = MAX_TSHARK_SECONDS,
    max_stdout_bytes: int = MAX_TSHARK_STDOUT_BYTES,
    max_stderr_bytes: int = MAX_TSHARK_STDERR_BYTES,
) -> tuple[int, str, str]:
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                command,
                stdout=stdout_file,
                stderr=stderr_file,
            )
        except OSError as exc:
            raise TsharkExecutionError(f"cannot execute TShark: {exc}") from exc
        started = time.monotonic()
        reason: str | None = None
        while process.poll() is None:
            stdout_size = os.fstat(stdout_file.fileno()).st_size
            stderr_size = os.fstat(stderr_file.fileno()).st_size
            if stdout_size > max_stdout_bytes:
                reason = "TShark stdout exceeded its byte limit"
            elif stderr_size > max_stderr_bytes:
                reason = "TShark stderr exceeded its byte limit"
            elif time.monotonic() - started > timeout_seconds:
                reason = "TShark exceeded its wall-time limit"
            if reason is not None:
                process.kill()
                process.wait()
                raise TsharkExecutionError(reason)
            time.sleep(0.01)
        stdout_size = os.fstat(stdout_file.fileno()).st_size
        stderr_size = os.fstat(stderr_file.fileno()).st_size
        if stdout_size > max_stdout_bytes or stderr_size > max_stderr_bytes:
            raise TsharkExecutionError("TShark output exceeded its byte limit")
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(max_stdout_bytes + 1).decode(
            "utf-8", "replace"
        )
        stderr = stderr_file.read(max_stderr_bytes + 1).decode(
            "utf-8", "replace"
        )
        return process.returncode, stdout, stderr


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        expectation, on_unknown, selector = load_expectations(args.expectations)
    except ExpectationsError as exc:
        print(f"expectations error: {exc}", file=sys.stderr)
        return EXIT_BAD_EXPECTATIONS
    try:
        if Path(args.capture).stat().st_size > MAX_CAPTURE_BYTES:
            print("capture error: capture exceeds the byte limit", file=sys.stderr)
            return EXIT_BAD_CAPTURE
        capture_format = probe_capture_format(args.capture)
    except OSError as exc:
        print(f"capture error: cannot stat capture: {exc}", file=sys.stderr)
        return EXIT_BAD_CAPTURE
    except CaptureDecodeError as exc:
        print(f"capture error: {exc}", file=sys.stderr)
        return EXIT_BAD_CAPTURE
    try:
        tshark_status, tshark_stdout, tshark_stderr = _run_tshark_bounded(
            tshark_json_args(args.capture)
        )
    except TsharkExecutionError as exc:
        print(f"internal error: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
    if tshark_status != 0:
        print(f"TShark error: {tshark_stderr.strip()}", file=sys.stderr)
        return EXIT_INTERNAL
    try:
        capture = parse_tshark_json(tshark_stdout, capture_format)
        document = build_result_document(
            capture,
            expectation,
            on_unknown=on_unknown,
            dialog_selector=selector,
        )
    except (CaptureDecodeError, ValueError, TypeError) as exc:
        print(f"analysis error: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
    if args.format == "json":
        print(json.dumps(document, sort_keys=True, separators=(",", ":")))
    else:
        sys.stdout.write(render_human(document))
    return result_exit_code(document)


if __name__ == "__main__":
    raise SystemExit(main())
