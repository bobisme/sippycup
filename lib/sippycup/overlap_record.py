"""The overlap a run was started beside, for its result record (wave 10, finding 6).

``./bin/sippycup`` refuses a sending command while another sender of this
checkout is active (sippycup_cockpit.overlap). When the operator allows it
(SIPPYCUP_ALLOW_OVERLAP), the launcher hands the run a description of the
other runs as SIPPYCUP_OVERLAP; the run records it as ``overlap`` in its
result, and diagnose and the owner report call the verdict unreliable.

The owner's limit on calls at once holds under the override too (wave 13):
the launcher does not know the profile, so the command that places calls
checks the record against its own limit where it reserves its calls
(:func:`concurrency_refusal`, called by ``call_ledger.reserve`` and by
``campaign run``), before anything is sent.
"""

from __future__ import annotations

import json
import os
from typing import Any, Mapping

ENV = "SIPPYCUP_OVERLAP"
UNRELIABLE = "another run was active; this verdict is unreliable"
# What the launcher's check names each active run by (``command`` in the
# record). Each of ONE_CALL_COMMANDS has at most one call up at a time (a
# matrix, a campaign and the checks place their calls one after another);
# NO_CALL_COMMANDS place none. Any other sender (a passthrough, chaos,
# resilience, a host process) is not known and counts as too many.
NO_CALL_COMMANDS = frozenset({"preflight", "media"})
ONE_CALL_COMMANDS = frozenset({"call", "matrix", "checks", "campaign", "one-call"})


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


def concurrency_refusal(limit: Any, command: str, environ: Mapping[str, str] | None = None) -> str | None:
    """Why ``command``, which places calls, may not start beside the runs it was allowed to overlap.

    None when it started alone, or when its one call beside the calls of the
    other runs stays within ``limit`` (the profile's ``limits.max_concurrency``
    or the plan's ``concurrentCalls``). Fail closed: a limit that is not a
    positive whole number counts as 1, and a record that cannot be read or a
    run whose command is not known is refused. Sends nothing.
    """
    text = (os.environ if environ is None else environ).get(ENV, "")
    if not text:
        return None
    allowed = limit if type(limit) is int and limit >= 1 else 1
    try:
        value = json.loads(text)
    except ValueError:
        value = None
    runs = value.get("activeRuns") if isinstance(value, dict) else None
    ending = (" Nothing was sent. Wait for the other run to finish, or end it with ./bin/sippycup stop, and run "
              "this command again without SIPPYCUP_ALLOW_OVERLAP.")
    if not isinstance(runs, list) or not runs or not all(isinstance(item, dict) for item in runs):
        return (f"calls at once: this {command} was started beside another run (SIPPYCUP_ALLOW_OVERLAP), but the "
                f"record of that run cannot be read, so it cannot be held to the owner's limit of {allowed} "
                f"call(s) at once (limits.concurrent_calls).{ending}")
    placing = [item for item in runs if str(item.get("command", "")) not in NO_CALL_COMMANDS]
    unknown = [item for item in placing if str(item.get("command", "")) not in ONE_CALL_COMMANDS]
    names = ", ".join(str(item.get("name", "?"))[:80] for item in (unknown or placing)[:8])
    if unknown:
        return (f"calls at once: this {command} was started beside {names} (SIPPYCUP_ALLOW_OVERLAP), and how many "
                f"calls that run has up at once is not known, so this {command} cannot be held to the owner's "
                f"limit of {allowed} call(s) at once (limits.concurrent_calls).{ending}")
    if 1 + len(placing) <= allowed:
        return None
    return (f"calls at once: this {command} was started beside {names} (SIPPYCUP_ALLOW_OVERLAP), which "
            f"place{'s' if len(placing) == 1 else ''} calls too: {1 + len(placing)} calls could be up at once, "
            f"above the owner's limit of {allowed} call(s) at once (limits.concurrent_calls). The override does "
            f"not go past the owner's limit.{ending}")
