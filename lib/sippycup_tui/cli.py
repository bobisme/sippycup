"""Replay structured mission events as accessible JSON or terminal text."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .app import MissionApp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sippycup-ui")
    parser.add_argument("events", type=Path, help="structured UI/campaign JSONL or oracle JSON")
    parser.add_argument("--format", choices=("auto", "json", "text"), default="auto")
    parser.add_argument("--width", type=int, default=100)
    parser.add_argument("--height", type=int, default=30)
    parser.add_argument("--help-overlay", action="store_true")
    args = parser.parse_args(argv)
    try:
        raw = args.events.read_text(encoding="utf-8")
    except OSError as exc:
        parser.error(str(exc))
    app = MissionApp()
    stripped = raw.lstrip()
    if stripped.startswith("{") and "\n{" not in stripped:
        app.ingest(json.loads(raw))
    else:
        for line in raw.splitlines():
            if line.strip():
                app.ingest(line)
    app.drain()
    if args.help_overlay:
        app.key("?")
    output_format = args.format
    if output_format == "auto":
        output_format = "text" if sys.stdout.isatty() else "json"
    if output_format == "json":
        print(json.dumps(app.snapshot().as_json_record(), indent=2, sort_keys=True))
    else:
        print(app.render(width=args.width, height=args.height))
    return 1 if app.state.schema_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
