"""The one recovery for a frozen campaign plan that no longer fits its inputs.

A frozen plan (``plan.json``) is never overwritten: ``campaign plan`` refuses
when the output exists, on purpose. It pins the campaign file's digest, the
DNS answers, the CA digests, and the approval window it was frozen with, and
the runs that used it kept a copy. When the campaign file, the approval window,
or a CA changes (``scope compile`` after a window renewal, or
``practice-target up``, which makes a new CA each time), the plan is stale.
The safe recovery is always the same: keep the old plan under a dated name and
freeze a new one from the current campaign file. This module builds that one
command so ``ready``, the refusals, and the docs all print the same line, and
it works when pasted as it stands.
"""

from __future__ import annotations

import shlex
from datetime import datetime, timezone
from pathlib import Path

LAUNCHER = "./bin/sippycup"


def kept_name(plan: str | Path, now: datetime | None = None) -> str:
    """Where the old plan is kept: ``plan.json`` becomes ``plan-STAMP.json`` beside it."""
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    path = Path(str(plan))
    return str(path.with_name(f"{path.stem}-{moment.strftime('%Y%m%dT%H%M%SZ')}{path.suffix}"))


def replan_command(plan: str | Path, manifest: str | Path, now: datetime | None = None) -> str:
    """``mv -n PLAN PLAN-STAMP && campaign plan MANIFEST --output PLAN``, safe to paste.

    The kept name carries the time to the second and ``mv -n`` never replaces
    a file; ``&&`` stops before ``campaign plan`` if the move fails.
    """
    plan_text, manifest_text = str(plan), str(manifest)
    return (
        f"mv -n {shlex.quote(plan_text)} {shlex.quote(kept_name(plan_text, now))} && "
        f"{LAUNCHER} campaign plan {shlex.quote(manifest_text)} --output {shlex.quote(plan_text)}"
    )
