#!/usr/bin/env python3
"""Repository entry point for deterministic audio canary generation."""

from __future__ import annotations

import sys
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1]
SOURCE_LIB = SOURCE_ROOT / "lib"
if not (SOURCE_LIB / "sippycup_media").is_dir():
    SOURCE_LIB = Path("/usr/local/lib")
sys.path.insert(0, str(SOURCE_LIB))

from sippycup_media.canary import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
