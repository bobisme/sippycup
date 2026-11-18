"""Diagnose a call-matrix directory and, through each failing cell, its guided-call run."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Optional

from .call import diagnose_call
from .callrun import CallRun
from .core import (
    HIGH, LOW, MEDIUM, NONE, OUR, UNKNOWN, Diagnosis, command, work_relative,
)
from .files import read_dict
from .inputs import make_redaction
from .ladder_bridge import Lazy

MAX_CHILDREN = 8
STOP_AND_ASK = {
    "registration-failed": "the credentials were rejected; more calls would repeat them",
    "call-auth-failed": "the credentials were rejected for the INVITE; more calls would repeat them",
    "call-rate-limited": "the far end rate limited us (429)",
    "call-unavailable": "the far end answered 503 (unavailable)",
    "authorization-lapsed": "the authorization window ended",
    "blocked": "the profile gate refused",
    "media-outside-scope": "the far end's media peer is outside the approved scope",
    "capture-failed": "packet capture failed",
    "capture-died": "packet capture stopped",
}


def resolve_run_dir(display: Optional[str], base: Path) -> Optional[Path]:
    """Find a cell's run directory from the display path result files record."""
    if not display:
        return None
    relative = Path(display)
    candidates = []
    for parent in [base.resolve()] + list(base.resolve().parents):
        if parent.name == "work":
            candidates.append(parent.parent / relative)
            break
    candidates += [Path.cwd() / relative, base / relative.name, base.parent / relative.name]
    for candidate in candidates:
        try:
            if candidate.is_dir() and not candidate.is_symlink():
                return candidate
        except OSError:
            continue
    return None


def _cell_label(cell: dict) -> str:
    return f"{cell.get('transport')}/{cell.get('codec')}/srtp {cell.get('srtp')}"


def _dimension_findings(cells: list) -> list:
    """Dimension values that account for every failure, e.g. 'codec G722: 0 of 4 passed'."""
    run_cells = [c for c in cells if c.get("status") == "run"]
    out = []
    for dimension in ("codec", "transport", "srtp"):
        values = sorted({str(c.get(dimension)) for c in run_cells})
        if len(values) < 2:
            continue
        stats = {}
        for value in values:
            group = [c for c in run_cells if str(c.get(dimension)) == value]
            stats[value] = (sum(1 for c in group if c.get("verdict") == "pass"), len(group))
        failing = [v for v, (ok, n) in stats.items() if ok == 0]
        passing = [v for v, (ok, n) in stats.items() if ok == n]
        if failing and passing and len(failing) + len(passing) == len(values):
            for value in failing:
                ok, total = stats[value]
                reasons = Counter(
                    f"{c.get('verdict')}" + (f" ({c.get('finalStatus')})" if c.get("finalStatus") else "")
                    for c in run_cells if str(c.get(dimension)) == value
                )
                out.append(
                    f"{dimension} {value}: {ok} of {total} passed ({', '.join(f'{k} x{n}' for k, n in reasons.items())}); "
                    f"every cell with {dimension} {', '.join(passing)} passed"
                )
    return out


def diagnose_matrix(path: Path, arguments) -> tuple:
    matrix = read_dict(path / "matrix.json")
    cells = [c for c in matrix.get("cells", []) if isinstance(c, dict)]
    cell_dirs = []
    for cell in cells:
        found = resolve_run_dir(cell.get("runDirectory"), path)
        cell["_dir"] = found
        if found is not None:
            cell_dirs.append(found)
    red = make_redaction([path] + cell_dirs, arguments.approve, arguments.show_addresses)
    d = Diagnosis("matrix", red)
    state = matrix.get("state")
    ran = [c for c in cells if c.get("status") == "run"]
    passed = [c for c in ran if c.get("verdict") == "pass"]
    failed = [c for c in ran if c.get("verdict") != "pass"]
    notrun = [c for c in cells if c.get("status") != "run"]
    d.set(run=path.name, verdict=state, state=state, target=None)
    if matrix.get("blockingErrors"):
        d.outcome("The matrix was refused before anything was sent: " + "; ".join(str(x) for x in matrix["blockingErrors"][:3]))
        d.stage("safety stop", "the plan or a profile gate refused the grid")
        d.attribute(OUR, HIGH, ["The plan did not pass its gates (profile approval, call limits, or authorization window); nothing was sent."])
        return d, red
    outcome = (
        f"{len(passed)} of {len(ran)} cells passed"
        + (f", {len(failed)} failed" if failed else "")
        + (f", {len(notrun)} not run" if notrun else "")
        + (f"; the run stopped early: {matrix.get('stopReason')}" if state == "stopped" else "")
        + "."
    )
    d.outcome(outcome)
    d.evidence("grid", f"destination {len(set(c.get('transport') for c in cells))} transport(s) x {len(set(c.get('codec') for c in cells))} codec(s) x {len(set(c.get('srtp') for c in cells))} SRTP mode(s); {matrix.get('callsPlaced')} of {matrix.get('totalCalls')} calls placed")
    for line in _dimension_findings(cells):
        d.evidence("pattern", line, 300)
    if state == "stopped":
        d.evidence("stop", str(matrix.get("stopReason")), 300)
    times = [c.get("setupSeconds") for c in ran if isinstance(c.get("setupSeconds"), (int, float))]
    if times:
        d.timing("slowest cell setup", max(times), "INVITE to answer over the passed cells")
    stamps = matrix.get("timestamps") or {}
    d.timing("whole matrix", _span(stamps.get("started"), stamps.get("finished")))

    children = []
    first_failing_dir = None
    for cell in failed[:MAX_CHILDREN]:
        cell_dir = cell.get("_dir")
        entry = {"cell": cell.get("index"), "label": _cell_label(cell), "verdict": cell.get("verdict"), "runRef": None}
        if cell_dir is None:
            entry["line"] = f"cell {cell.get('index')} {_cell_label(cell)}: {cell.get('verdict')} (run directory not found next to the matrix)"
            children.append(entry)
            continue
        if first_failing_dir is None:
            first_failing_dir = cell_dir
        sub = diagnose_call(CallRun(cell_dir), red, Lazy(cell_dir, arguments.show_addresses, arguments.approve, enabled=False))
        sub.finalize()
        sd = sub.data
        entry.update(
            runRef=work_relative(cell_dir.resolve()), stage=sd["stage"], side=sd["attribution"]["side"],
            confidence=sd["attribution"]["confidence"], outcome=sd["outcome"], stopAndAsk=bool(sd.get("stopAndAsk")),
        )
        entry["line"] = (
            f"cell {cell.get('index')} {_cell_label(cell)}: {cell.get('verdict')} at {sd['stage']}, "
            f"{sd['attribution']['side']} ({sd['attribution']['confidence']}). Next: ./bin/sippycup diagnose {entry['runRef']}"
        )
        entry["_diagnosis"] = sub
        children.append(entry)
    for cell in notrun[:4]:
        children.append({"cell": cell.get("index"), "label": _cell_label(cell), "verdict": "not-run", "runRef": None,
                         "line": f"cell {cell.get('index')} {_cell_label(cell)}: not run ({red.text(cell.get('reason') or 'stopped earlier', 160)})"})
    d.data["children"] = [{k: v for k, v in entry.items() if k != "_diagnosis"} for entry in children]

    # Attribution: the sides of the failing cells' own diagnoses.
    sides = Counter(c["side"] for c in d.data["children"] if c.get("side"))
    verdicts = Counter(str(c.get("verdict")) for c in failed)
    if not failed and not notrun:
        d.stage("none", "every cell passed")
        d.attribute(NONE, HIGH, ["Every planned cell completed and passed."])
        d.gap("a pass proves each combination worked once; it is not a quality measurement")
    elif not failed:
        d.stage("none", "no cell failed")
        d.attribute(NONE, MEDIUM, ["No placed cell failed."])
    else:
        top = children[0] if children else {}
        d.stage(top.get("stage", "INVITE") if top.get("stage") else "INVITE", f"first failing cell: {top.get('label')}")
        reasoning = [f"{len(failed)} cell(s) failed: " + ", ".join(f"{v} x{n}" for v, n in verdicts.items()) + "."]
        decisive = {side for side in sides if side != UNKNOWN}
        causes = _cause_lines(cells)
        reasoning.extend(causes)
        if len(decisive) == 1 and (causes or len(sides) == 1):
            side = next(iter(decisive))
            conf = MEDIUM if causes else (LOW if any(c.get("confidence") == LOW for c in d.data["children"] if c.get("side")) else MEDIUM)
            if UNKNOWN in sides:
                reasoning.append("Some failing cells could not be attributed alone; the pattern across the grid ties them to the same cause.")
            d.attribute(side, conf, reasoning, _dim_hint(cells))
        elif sides:
            reasoning.append("The failing cells point at different sides: " + ", ".join(f"{s} x{n}" for s, n in sides.items()) + "; read each cell below.")
            d.attribute(UNKNOWN, LOW, reasoning, _dim_hint(cells))
        else:
            d.attribute(UNKNOWN, LOW, reasoning + ["The cells' run directories were not found, so they could not be diagnosed."])
    stop_verdict = next((c.get("verdict") for c in failed if c.get("verdict") in STOP_AND_ASK), None)
    if state == "stopped" and stop_verdict:
        d.stop_and_ask(
            f"The matrix stopped because {STOP_AND_ASK[stop_verdict]}. Stop and ask the owner before running more cells; "
            "the remaining cells were deliberately not sent."
        )
    if first_failing_dir is not None:
        d.step("Diagnose the first failing cell on its own (a full page with its ladder).", command("diagnose", work_relative(first_failing_dir.resolve())))
    # Real repeat commands from the first failing child that suggests one.
    for entry in children:
        sub = entry.get("_diagnosis")
        if sub is None or sub.data.get("stopAndAsk"):
            continue
        for step in sub.data["nextSteps"]:
            if step["kind"] == "command" and step.get("command", "").startswith(("./bin/sippycup call", "./bin/sippycup --practice call")):
                d.step(f"Repeat cell {entry['cell']} on its own (same profile and flags, one change).", step["command"])
                break
        break
    d.gap("a not-run cell was never sent; its absence says nothing about the platform")
    if any(c.get("_dir") is None for c in failed):
        d.gap("some cells' run directories could not be located from the paths in matrix.json")
    return d, red


def _cause_lines(cells: list) -> list:
    """When one setting accounts for every failure, say which settings it rules out."""
    run_cells = [c for c in cells if c.get("status") == "run"]
    failing = [c for c in run_cells if c.get("verdict") != "pass"]
    passing = [c for c in run_cells if c.get("verdict") == "pass"]
    if not failing or not passing:
        return []
    out = []
    for dimension in ("codec", "transport", "srtp"):
        values = {str(c.get(dimension)) for c in failing}
        if len(values) != 1:
            continue
        value = next(iter(values))
        if any(str(c.get(dimension)) == value for c in passing):
            continue
        ruled_out = []
        for other in ("codec", "transport", "srtp"):
            if other == dimension:
                continue
            for other_value in sorted({str(c.get(other)) for c in failing}):
                if any(str(c.get(other)) == other_value for c in passing):
                    ruled_out.append(f"{other} {other_value}")
        out.append(
            f"Every failure shares {dimension} {value} and no cell with it passed"
            + (f"; {', '.join(ruled_out)} passed in other cells, so those are not the cause." if ruled_out else ".")
        )
    return out


def _dim_hint(cells: list) -> list:
    return [
        "Compare the passing and failing cells' codec, transport, and SRTP mode: the pattern lines above name the setting every failure shares.",
        "Diagnose one failing cell for the SIP status, headers, and ladder.",
    ]


def _span(start: Optional[str], end: Optional[str]) -> Optional[float]:
    from datetime import datetime

    try:
        a = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
        b = datetime.fromisoformat(str(end).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (b - a).total_seconds()
