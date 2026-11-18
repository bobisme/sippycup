"""Call-matrix grids for the owner report (``summary``).

``./bin/sippycup matrix run`` writes one ``matrix.json``
(``schemas/call-matrix-v1.schema.json``) per grid and one ordinary run
directory per cell. ``summary`` already lists those runs as calls; this module
adds the grid itself.

A ``matrix.json`` is never trusted as written. It is validated against the
schema (a small structural validator; the project ships no JSON Schema
library), its counts are checked against its cells, and every cell that claims
a run must name a run directory that the report found, whose recorded verdict
is the one the matrix claims. A matrix that fails any of these is an integrity
exception and its grid is drawn with the problems listed. Nothing here shows a
path, an address, or free text that did not go through the report's sanitizer.
"""

from __future__ import annotations

import itertools
import re
from pathlib import Path
from typing import Any, Callable

MATRIX_FILE = "matrix.json"
MATRIX_API = "sippycup.dev/call-matrix/v1"
MAX_MATRICES = 50
MAX_CELLS = 48
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SCHEMA_NAME = "call-matrix-v1.schema.json"


def schema_path() -> Path | None:
    here = Path(__file__).resolve()
    for base in (here.parents[2], Path("/usr/local/share/sippycup")):
        candidate = base / "schemas" / SCHEMA_NAME
        if candidate.is_file():
            return candidate
    return None


# --------------------------------------------------------------------------
# Structural validation (the subset of JSON Schema that the schema file uses)


def _type_ok(value: Any, name: str) -> bool:
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return True


def validate(value: Any, schema: dict[str, Any], path: str = "$", limit: int = 20) -> list[str]:
    """Problems as ``path: rule`` strings; they never quote a value."""
    problems: list[str] = []

    def add(message: str) -> None:
        if len(problems) < limit:
            problems.append(f"{path}: {message}")

    if "const" in schema and value != schema["const"]:
        add("is not the required constant")
    if "enum" in schema and value not in schema["enum"]:
        add("is not an allowed value")
    kind = schema.get("type")
    if kind is not None:
        names = kind if isinstance(kind, list) else [kind]
        if not any(_type_ok(value, name) for name in names):
            add(f"has the wrong type (expected {' or '.join(names)})")
            return problems
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            add("is below the minimum")
        if "maximum" in schema and value > schema["maximum"]:
            add("is above the maximum")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                add(f"is missing required field {key}")
        properties = schema.get("properties", {})
        extra = schema.get("additionalProperties")
        for key, child in value.items():
            if key in properties:
                problems.extend(validate(child, properties[key], f"{path}.{key}", limit)[: max(0, limit - len(problems))])
            elif isinstance(extra, dict):
                problems.extend(validate(child, extra, f"{path}.{key}", limit)[: max(0, limit - len(problems))])
            elif extra is False:
                add(f"has an unexpected field {key}")
    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        for index, child in enumerate(value[:MAX_CELLS * 4]):
            problems.extend(validate(child, schema["items"], f"{path}[{index}]", limit)[: max(0, limit - len(problems))])
    return problems[:limit]


# --------------------------------------------------------------------------
# Discovery


def discover(
    root: Path, extra_roots: list[Path], profile_paths: list[Path]
) -> tuple[list[tuple[str, Path]], list[str]]:
    """Matrix directories as (relative reference, matrix.json path), and warnings.

    Looked up in ``DIR/matrix``, ``matrix/`` beside each profile (where
    ``matrix run`` writes by default), and each ``--matrix-root``; a directory
    that itself holds a matrix.json counts too.
    """
    warnings: list[str] = []
    bases: list[Path] = [root / "matrix"]
    bases.extend(sorted(path.parent / "matrix" for path in profile_paths))
    bases.extend(extra_roots)
    found: list[tuple[str, Path]] = []
    seen: set[Path] = set()
    for base in bases:
        try:
            if base.is_symlink() or not base.is_dir():
                continue
            resolved = base.resolve(strict=True)
            candidates = [resolved] + sorted(
                child for child in itertools.islice(resolved.iterdir(), 4096) if child.is_dir() and not child.is_symlink()
            )
        except OSError:
            continue
        for directory in candidates:
            path = directory / MATRIX_FILE
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                real = path.resolve(strict=True)
            except OSError:
                continue
            if real in seen:
                continue
            if SAFE_NAME.fullmatch(directory.name) is None:
                warnings.append("ignored a matrix directory with an unsafe name")
                continue
            seen.add(real)
            try:
                ref = real.parent.relative_to(root).as_posix()
            except ValueError:
                ref = f"external-matrix/{directory.name}"
            found.append((ref, real))
            if len(found) >= MAX_MATRICES:
                warnings.append(f"matrix discovery stopped at the {MAX_MATRICES}-matrix limit")
                return found, warnings
    return found, warnings


# --------------------------------------------------------------------------
# Model


def _exception(code: str, matrix: str, detail: str) -> dict[str, Any]:
    return {"code": code, "run": None, "detail": f"matrix {matrix}: {detail}"}


def _cell(raw: dict[str, Any], run: dict[str, Any] | None, san: Any, prefix: str, ident: Callable[[Any], Any]) -> dict[str, Any]:
    return {
        "index": raw.get("index"),
        "transport": raw.get("transport"),
        "srtp": raw.get("srtp"),
        "codec": san.identifier(raw.get("codec"), f"{prefix}.codec", limit=32),
        "status": raw.get("status"),
        "verdict": ident(raw.get("verdict")),
        "finalStatus": raw.get("finalStatus") if isinstance(raw.get("finalStatus"), int) else None,
        "setupSeconds": raw.get("setupSeconds") if isinstance(raw.get("setupSeconds"), (int, float)) and not isinstance(raw.get("setupSeconds"), bool) else None,
        "negotiated": san.identifier(raw.get("negotiated"), f"{prefix}.negotiated", limit=32),
        "codecVerifiedOnWire": raw.get("codecVerifiedOnWire") if isinstance(raw.get("codecVerifiedOnWire"), bool) else None,
        "srtpActive": raw.get("srtpActive") if isinstance(raw.get("srtpActive"), bool) else None,
        "warning": raw.get("warning") if raw.get("warning") in {"sdes-key-exposed-on-cleartext-signaling"} else None,
        "reason": san.text(raw.get("reason"), f"{prefix}.reason", limit=200) if raw.get("reason") else None,
        "run": None if run is None else run.get("label"),
        "runId": None if run is None else run["id"],
    }


def build(
    path: Path,
    ref: str,
    *,
    read_json: Callable[[Path], Any],
    known_runs: set[str],
    runs_by_id: dict[str, dict[str, Any]],
    ctx: Any,
    destinations: Callable[[Any], Any],
    ident: Callable[[Any], Any],
    schema: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """One matrix model (or None when unreadable) and its integrity exceptions."""
    name = path.parent.name
    exceptions: list[dict[str, Any]] = []
    try:
        document = read_json(path)
    except Exception as error:  # noqa: BLE001 - an unreadable matrix is reported, not fatal
        return None, [_exception("matrix-unreadable", name, f"matrix.json could not be read ({type(error).__name__})")]
    if not isinstance(document, dict) or document.get("apiVersion") != MATRIX_API:
        return None, [_exception("matrix-invalid", name, "matrix.json is not a call matrix (apiVersion)")]
    problems: list[str] = []
    if schema is None:
        exceptions.append(_exception("matrix-unvalidated", name, "the matrix schema file is not available, so the grid was not validated"))
    else:
        problems = validate(document, schema)
        for problem in problems[:5]:
            exceptions.append(_exception("matrix-invalid", name, "fails the call-matrix schema: " + problem))
        if problems:
            return None, exceptions
    san = ctx.sanitizer
    prefix = f"matrices[{name}]"
    raw_cells = [c for c in document.get("cells", []) if isinstance(c, dict)]
    cells: list[dict[str, Any]] = []
    indexes = [c.get("index") for c in raw_cells]
    if len(set(indexes)) != len(indexes):
        exceptions.append(_exception("matrix-count-mismatch", name, "two cells share an index"))
    for raw in raw_cells[:MAX_CELLS]:
        run = None
        if raw.get("status") == "run":
            directory = raw.get("runDirectory")
            run_name = Path(directory).name if isinstance(directory, str) and directory else None
            if not run_name or SAFE_NAME.fullmatch(run_name) is None or run_name not in known_runs:
                exceptions.append(
                    _exception("matrix-run-missing", name, f"cell {raw.get('index')} names a run directory the report did not find")
                )
            else:
                run = runs_by_id.get(run_name)
                if run is not None:
                    claimed = raw.get("verdict")
                    if run.get("verdict") != ident(claimed):
                        exceptions.append(
                            _exception(
                                "matrix-verdict-mismatch",
                                name,
                                f"cell {raw.get('index')} claims verdict {ident(claimed)} but its run recorded {run.get('verdict')}",
                            )
                        )
                    recorded = (run.get("target") or {}).get("transport")
                    if recorded and recorded != raw.get("transport"):
                        exceptions.append(
                            _exception("matrix-run-mismatch", name, f"cell {raw.get('index')} is {raw.get('transport')} but its run used {recorded}")
                        )
        elif raw.get("status") == "not-run" and raw.get("runDirectory"):
            exceptions.append(_exception("matrix-run-mismatch", name, f"cell {raw.get('index')} is not-run but names a run directory"))
        cells.append(_cell(raw, run, san, f"{prefix}.cells[{raw.get('index')}]", ident))
    placed = sum(1 for c in raw_cells if c.get("status") == "run")
    passed = sum(1 for c in raw_cells if c.get("status") == "run" and c.get("verdict") == "pass")
    state = document.get("state")
    if state in {"completed", "stopped", "cancelled"}:
        if document.get("callsPlaced") is not None and document["callsPlaced"] != placed:
            exceptions.append(_exception("matrix-count-mismatch", name, "callsPlaced does not match the cells that ran"))
        if document.get("passed") is not None and document["passed"] != passed:
            exceptions.append(_exception("matrix-count-mismatch", name, "passed does not match the cells that passed"))
        if document.get("totalCalls") != len(raw_cells):
            exceptions.append(_exception("matrix-count-mismatch", name, "totalCalls does not match the number of cells"))
    order_t = {t: i for i, t in enumerate(document.get("transports", []))}
    order_s = {s: i for i, s in enumerate(document.get("srtp", []))}
    keys = sorted({(c["transport"], c["srtp"]) for c in cells}, key=lambda k: (order_t.get(k[0], 99), order_s.get(k[1], 99)))
    codecs = [san.identifier(c, f"{prefix}.codecs", limit=32) for c in document.get("codecs", [])]
    rows = []
    for transport, srtp in keys:
        by_codec = {c["codec"]: c for c in cells if c["transport"] == transport and c["srtp"] == srtp}
        rows.append({"transport": transport, "srtp": srtp, "cells": [by_codec.get(codec) for codec in codecs]})
    timestamps = document.get("timestamps") if isinstance(document.get("timestamps"), dict) else {}
    ran = [runs_by_id[c["runId"]] for c in cells if c.get("runId") in runs_by_id]
    practice = bool(ran) and len(ran) == placed and all(r.get("practiceApproval") for r in ran)
    model = {
        "id": name,
        "ref": ref,
        "state": state,
        "destination": destinations(document.get("destination")),
        "transports": list(document.get("transports", [])),
        "srtp": list(document.get("srtp", [])),
        "codecs": codecs,
        "totalCalls": document.get("totalCalls"),
        "callsPlaced": placed,
        "passed": passed,
        "notRun": sum(1 for c in raw_cells if c.get("status") == "not-run"),
        "stopReason": san.text(document.get("stopReason"), f"{prefix}.stopReason", limit=200) if document.get("stopReason") else None,
        "exitCode": document.get("exitCode") if isinstance(document.get("exitCode"), int) else None,
        "callSeconds": document.get("callSeconds"),
        "started": timestamps.get("started") if isinstance(timestamps.get("started"), str) else None,
        "finished": timestamps.get("finished") if isinstance(timestamps.get("finished"), str) else None,
        "practice": practice,
        "sdesOverCleartext": any(c["warning"] for c in cells),
        "rows": rows,
        "cells": cells,
        "integrity": [e["code"] for e in exceptions],
    }
    return model, exceptions
