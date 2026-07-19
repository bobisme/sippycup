#!/usr/bin/env python3
"""Direct runtime driver for signal tests; never used by active CLI execution."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "lib"))

from sippycup.runtime import run_plan

plan = json.loads(Path(sys.argv[1]).read_text())
result = run_plan(plan, sys.argv[3:], Path(sys.argv[2]), grace_seconds=0.1)
raise SystemExit(result.exit_code)
