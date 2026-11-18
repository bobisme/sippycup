"""Local, network-free probes the cockpit hands to the model.

The image probe asks the container runtime for local image metadata only
(``image inspect``; it never pulls) and compares the build time with the
last commit that changed an image input. It can be skipped with
``--no-runtime``; the dashboard then shows the image as unknown.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

Run = Callable[..., subprocess.CompletedProcess]
# Code that the Containerfile copies into the image. Documentation is also
# copied, but a docs-only change does not make the image's behaviour stale.
_IGNORED_INPUTS = ("docs", "README.md", "examples")
_COPY = re.compile(r"^COPY\s+(?!--from)(.+)$", re.MULTILINE)
RECORD_DIR = ".image-builds"


def image_inputs(repo: Path) -> list[str]:
    """Source paths the Containerfile copies, minus documentation."""
    try:
        text = (repo / "Containerfile").read_text(encoding="utf-8")
    except OSError:
        return ["Containerfile", "bin", "lib"]
    sources = {"Containerfile"}
    for match in _COPY.findall(text):
        tokens = [token for token in match.split() if not token.startswith("--")]
        for source in tokens[:-1]:
            if source.split("/", 1)[0] not in _IGNORED_INPUTS:
                sources.add(source.rstrip("/"))
    return sorted(sources)


def inputs_fingerprint(repo: Path) -> str:
    """SHA-256 over the relative path and bytes of every image input file."""
    digest = hashlib.sha256()
    files: list[Path] = []
    for source in image_inputs(repo):
        path = repo / source
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(item for item in path.rglob("*") if item.is_file() and "__pycache__" not in item.parts)
    for path in sorted(set(files)):
        relative = path.relative_to(repo).as_posix()
        digest.update(relative.encode() + b"\0")
        try:
            digest.update(hashlib.sha256(path.read_bytes()).digest())
        except OSError:
            digest.update(b"unreadable")
    return digest.hexdigest()


def _record_path(repo: Path, image: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", image)
    return repo / "work" / RECORD_DIR / f"{safe}.json"


def _parse_created(text: str) -> datetime | None:
    # Podman prints e.g. "2026-11-18 01:49:51.597783825 +0000 UTC"; docker RFC 3339.
    text = text.strip()
    match = re.match(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.\d+)?\s*(Z|[+-]\d{2}:?\d{2})?", text)
    if not match:
        return None
    zone = match.group(3) or "+0000"
    if zone == "Z":
        zone = "+0000"
    try:
        return datetime.strptime(f"{match.group(1)}T{match.group(2)}{zone.replace(':', '')}", "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        return None


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if value else None


def _inspect(repo: Path, image: str, run: Run) -> tuple[dict[str, Any] | None, str]:
    try:
        runtime = run([str(repo / "bin" / "container-runtime")], capture_output=True, text=True, timeout=10,
                      check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"no container runtime: {exc}"
    if runtime.returncode != 0 or not runtime.stdout.strip():
        return None, "no supported container runtime found"
    try:
        inspect = run([runtime.stdout.strip(), "image", "inspect", "--format", "{{.Created}}|{{.Id}}", image],
                      capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"image inspect failed: {exc}"
    if inspect.returncode != 0:
        return {"present": False}, "image not found locally"
    created_text, _, identifier = inspect.stdout.strip().partition("|")
    return {"present": True, "created": _parse_created(created_text), "id": identifier.strip() or None}, ""


def record_build(repo: Path, image: str, *, run: Run = subprocess.run) -> Path:
    """Record which image-input fingerprint the freshly built image was built from."""
    facts, detail = _inspect(repo, image, run)
    if not facts or not facts.get("present"):
        raise RuntimeError(detail or "image not found")
    path = _record_path(repo, image)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "image": image,
        "imageId": facts["id"],
        "inputsSha256": inputs_fingerprint(repo),
        "recordedAt": _iso(datetime.now(timezone.utc)),
    }
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
    return path


def probe_image(repo: Path, image: str, *, run: Run = subprocess.run) -> dict[str, Any]:
    """Local image facts and whether the image predates the current inputs.

    With a build record (written by ``make build``) for this exact image id,
    staleness is exact: the recorded input fingerprint differs from the
    checkout. Otherwise it falls back to a heuristic: the image is older than
    the last commit that changed an image input.
    """
    facts: dict[str, Any] = {"image": image, "checked": True, "present": None, "stale": None,
                             "created": None, "id": None, "inputsChanged": None, "dirty": False,
                             "detail": "", "method": None}
    inspected, detail = _inspect(repo, image, run)
    if inspected is None:
        facts.update(checked=False, detail=detail)
        return facts
    if not inspected["present"]:
        facts.update(present=False, detail=detail)
        return facts
    created = inspected["created"]
    facts.update(present=True, created=_iso(created), id=inspected["id"])
    record_path = _record_path(repo, image)
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        record = None
    if isinstance(record, dict) and record.get("imageId") == inspected["id"] and record.get("inputsSha256"):
        facts["method"] = "build record vs checkout fingerprint"
        facts["stale"] = record["inputsSha256"] != inputs_fingerprint(repo)
        facts["recordedAt"] = record.get("recordedAt")
        return facts
    facts["method"] = "heuristic: image creation time vs last commit of image inputs (no build record)"
    inputs = image_inputs(repo)
    try:
        log = run(["git", "-C", str(repo), "log", "-1", "--format=%ct", "--", *inputs],
                  capture_output=True, text=True, timeout=10, check=False)
        status = run(["git", "-C", str(repo), "status", "--porcelain", "--", *inputs],
                     capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        facts["detail"] = "git unavailable; staleness unknown"
        return facts
    if log.returncode == 0 and log.stdout.strip().isdigit():
        changed = datetime.fromtimestamp(int(log.stdout.strip()), timezone.utc)
        facts["inputsChanged"] = _iso(changed)
        if created is not None:
            facts["stale"] = created < changed
    facts["dirty"] = status.returncode == 0 and bool(status.stdout.strip())
    return facts


def commands(repo: Path) -> set[str]:
    from .runner import iter_commands

    return set(iter_commands(repo / "config" / "commands.tsv"))


def find_engagements(repo: Path, limit: int = 200) -> list[Path]:
    """Directories directly under work/ that hold engagement.json."""
    work = repo / "work"
    found = []
    try:
        entries = sorted(work.iterdir())[:limit]
    except OSError:
        return []
    for entry in entries:
        if entry.name == "practice" or entry.is_symlink() or not entry.is_dir():
            continue
        marker = entry / "engagement.json"
        if marker.is_file() and not marker.is_symlink():
            try:
                value = json.loads(marker.read_text(encoding="utf-8")[:65536])
            except (OSError, ValueError):
                continue
            if isinstance(value, dict) and value.get("apiVersion") == "sippycup.dev/engagement/v1":
                found.append(entry)
    return found
