"""Offline CLI for inspecting the corpus and frozen torture plans."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from .corpus import CorpusError, build_corpus, corpus_manifest
from .runner import ActionResult, RunnerCallbacks, RunnerLimits, TortureRunner


def _inert(case, context):
    return ActionResult(True, "dry-run-only", dialog_state=case.dialog_state)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="sippycup-torture")
    commands = root.add_subparsers(dest="command", required=True)
    corpus = commands.add_parser("corpus", help="print the exact offline corpus manifest")
    corpus.add_argument("--format", choices=("json", "ids"), default="json")

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


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        corpus = build_corpus()
        if args.command == "corpus":
            if args.format == "ids":
                print("\n".join(case.id for case in corpus))
            else:
                print(json.dumps(corpus_manifest(), indent=2, sort_keys=True))
            return 0

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
