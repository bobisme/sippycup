#!/usr/bin/env python3
"""Generate the deterministic, privacy-clean portable pack example."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup.evidence import write_evidence_manifest
from sippycup.evidence_pack import create_evidence_pack


IMAGE_DIGEST = "sha256:" + "0" * 64


def _write_run(root: Path) -> None:
    plan = {
        "authorization": {"networks": ["192.0.2.0/24"]},
        "evidence": {"retainPayload": False},
    }
    files = {
        "plan.json": json.dumps(plan, indent=2, sort_keys=True) + "\n",
        "reviewed-manifest.yaml": "apiVersion: sippycup.dev/campaign/v1\n",
        "commands.json": '{"runner":["offline-fixture"]}\n',
        "events.jsonl": '{"event":"campaign.started","state":"running"}\n',
        "versions.json": '{"image":"sanitized-fixture","python":"3"}\n',
        "preflight.json": "[]\n",
        "report.txt": "sanitized offline fixture: no calls or payloads\n",
        "report.stderr": "",
        "result.json": '{"state":"succeeded","exitCode":0}\n',
        "timestamps.json": '{"started":"fixture","finished":"fixture"}\n',
    }
    for relative, content in files.items():
        (root / relative).write_text(content, encoding="utf-8")
    (root / "capture.pcap").write_bytes(
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    )
    manifest = write_evidence_manifest(
        root, created_at="2026-07-18T00:00:00Z"
    )
    if manifest["privacy"]["status"] != "pass":
        raise RuntimeError("sanitized fixture unexpectedly failed privacy lint")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "examples" / "evidence-pack" / "sanitized-evidence.tar",
    )
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args(argv)
    with tempfile.TemporaryDirectory() as temporary:
        temporary_root = Path(temporary)
        run = temporary_root / "run"
        run.mkdir()
        _write_run(run)
        generated = temporary_root / "sanitized-evidence.tar"
        create_evidence_pack(
            run, generated, image_digest=IMAGE_DIGEST
        )
        if arguments.check:
            if (
                not arguments.output.is_file()
                or arguments.output.read_bytes() != generated.read_bytes()
            ):
                print("sanitized evidence pack differs from generation", file=sys.stderr)
                return 1
            return 0
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_bytes(generated.read_bytes())
        arguments.output.chmod(0o644)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
