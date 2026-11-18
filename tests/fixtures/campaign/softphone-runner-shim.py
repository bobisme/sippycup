#!/usr/bin/env python3
"""Test shim: the real softphone campaign runner with a fake PJSUA binary.

argv: FAKE_PJSUA WITNESS_FILE. The shim records its own argv and
environment (as the supervisor started it) to WITNESS_FILE so tests can prove
the credential value is absent from both, then runs the unmodified runner.
"""

import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib"))

from sippycup_softphone.campaign_runner import main  # noqa: E402

fake_pjsua, witness = sys.argv[1], sys.argv[2]
with open(witness, "a", encoding="utf-8") as output:
    output.write(json.dumps({"argv": sys.argv, "environ": dict(os.environ)}) + "\n")
raise SystemExit(main([], pjsua=fake_pjsua))
