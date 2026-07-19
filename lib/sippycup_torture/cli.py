"""Offline CLI for inspecting the corpus and frozen torture plans."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from .corpus import CorpusError, build_corpus, corpus_manifest
from .exit_gate import default_review, run_exit_gate, validate_review
from .runner import ActionResult, RunnerCallbacks, RunnerLimits, TortureRunner


def _inert(case, context):
    return ActionResult(True, "dry-run-only", dialog_state=case.dialog_state)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="sippycup-torture")
    commands = root.add_subparsers(dest="command", required=True)
    corpus = commands.add_parser("corpus", help="print the exact offline corpus manifest")
    corpus.add_argument("--format", choices=("json", "ids"), default="json")

    exit_gate = commands.add_parser(
        "exit-gate", help="run the deterministic network-free technical gate"
    )
    exit_gate.add_argument("--output", type=Path)

    review = commands.add_parser(
        "review-template", help="create a pending owner defaults-review record"
    )
    review.add_argument("--reviewer", default="Quad")
    review.add_argument("--output", type=Path, required=True)

    validate = commands.add_parser(
        "validate-review", help="validate owner review against current code"
    )
    validate.add_argument("review", type=Path)

    plan = commands.add_parser("plan", help="render a no-network frozen execution plan")
    plan.add_argument("--case", action="append", dest="cases", required=True)
    plan.add_argument("--max-cases", type=int, default=1)
    plan.add_argument("--max-packets", type=int, default=6)
    plan.add_argument("--max-bytes", type=int, default=8192)
    plan.add_argument("--max-rate-hz", type=float, default=1.0)
    plan.add_argument("--max-concurrency", type=int, default=1)
    plan.add_argument("--max-duration", type=float, default=30.0)
    plan.add_argument("--max-failures", type=int, default=1)
    plan.add_argument("--action-timeout", type=float, default=5.0)
    return root


def _json_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _load_json(path: Path):
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_json_no_duplicates,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read review: {exc}") from exc


def _write_exclusive(path: Path, value: object) -> None:
    if path.exists():
        raise ValueError(f"refusing to overwrite existing output: {path}")
    if not path.parent.is_dir():
        raise ValueError(f"output parent does not exist: {path.parent}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise ValueError(f"refusing to overwrite existing output: {path}") from exc
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "corpus":
            corpus = build_corpus()
            if args.format == "ids":
                print("\n".join(case.id for case in corpus))
            else:
                print(json.dumps(corpus_manifest(), indent=2, sort_keys=True))
            return 0
        if args.command == "exit-gate":
            report = run_exit_gate()
            if args.output is not None:
                _write_exclusive(args.output, report)
                print(args.output)
            else:
                print(json.dumps(report, indent=2, sort_keys=True))
            return 0 if report["status"] == "pass" else 1
        if args.command == "review-template":
            report = run_exit_gate()
            _write_exclusive(
                args.output,
                default_review(report, reviewer=args.reviewer),
            )
            print(args.output)
            return 0
        if args.command == "validate-review":
            report = run_exit_gate()
            result = validate_review(_load_json(args.review), report)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["ready"] else 1

        corpus = build_corpus()
        by_id = {case.id: case for case in corpus}
        unknown = sorted(set(args.cases) - set(by_id))
        if unknown:
            raise CorpusError("unknown case id(s): " + ", ".join(unknown))
        selected = tuple(by_id[case_id] for case_id in args.cases)
        limits = RunnerLimits(
            max_cases=args.max_cases,
            max_packets=args.max_packets,
            max_bytes=args.max_bytes,
            max_rate_hz=args.max_rate_hz,
            max_concurrency=args.max_concurrency,
            max_duration_s=args.max_duration,
            max_failures=args.max_failures,
            action_timeout_s=args.action_timeout,
        )
        callbacks = RunnerCallbacks(_inert, _inert, _inert, _inert)
        with tempfile.TemporaryDirectory() as tmp:
            runner = TortureRunner(selected, callbacks, Path(tmp) / "unused", limits=limits)
            print(json.dumps(runner.dry_run(), indent=2, sort_keys=True))
        return 0
    except (CorpusError, ValueError) as exc:
        print(f"sippycup-torture: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
