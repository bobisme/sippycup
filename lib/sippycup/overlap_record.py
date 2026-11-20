"""The overlap a run was started beside, for its result record (wave 10, finding 6).

``./bin/sippycup`` refuses a sending command while another sender of this
checkout is active (sippycup_cockpit.overlap). When the operator allows it
(SIPPYCUP_ALLOW_OVERLAP), the launcher hands the run a description of the
other runs as SIPPYCUP_OVERLAP; the run records it as ``overlap`` in its
result, and diagnose and the owner report call the verdict unreliable.
"""

from __future__ import annotations

import json
import os
from typing import Any, Mapping

ENV = "SIPPYCUP_OVERLAP"
UNRELIABLE = "another run was active; this verdict is unreliable"


def recorded(environ: Mapping[str, str] | None = None) -> dict[str, Any] | None:
    """The overlap record for this run, or None when it started alone."""
    text = (os.environ if environ is None else environ).get(ENV, "")
    if not text:
        return None
    try:
        value = json.loads(text)
    except ValueError:
        value = None
    runs = value.get("activeRuns") if isinstance(value, dict) else None
    kept = []
    for item in runs if isinstance(runs, list) else []:
        if isinstance(item, dict):
            kept.append({key: str(item.get(key, ""))[:160] for key in ("name", "kind", "detail")})
    return {"activeRuns": kept[:8], "note": UNRELIABLE}


def field(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """``{"overlap": ...}`` for a result document, or ``{}`` when the run started alone."""
    value = recorded(environ)
    return {"overlap": value} if value is not None else {}
