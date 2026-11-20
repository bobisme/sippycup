"""List and remove Sippycup's own leftovers: ``doctor --cleanup``.

Three kinds of leftover are recognised, each by an exact rule:

``shm``         private temporary directories that the softphone drivers create
                under ``/dev/shm`` (``sippycup-softphone-XXXXXXXX`` and
                ``sippycup-campaign-softphone-XXXXXXXX``), owned by the current
                user, with no live process referencing them, and older than
                ``--min-age`` seconds.
``containers``  stopped (exited, created, or stopped) containers created from a
                Sippycup image.
``images``      dangling (untagged) images that carry Sippycup's image labels
                and are used by no container.

Nothing else is ever listed or removed. In particular ``work/`` (engagement
evidence) is never touched. The default is a dry run; ``--apply`` removes.
Removal is done with descriptor-relative ``unlink``/``rmdir`` and the container
runtime's non-forcing ``rm``/``rmi`` with a validated hexadecimal identifier;
no shell and no recursive delete of a variable path is involved.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

SHM_ROOT = Path("/dev/shm")
# tempfile.mkdtemp suffixes are eight characters from [a-z0-9_].
PRIVATE_DIRECTORY = re.compile(r"^sippycup-(?:campaign-softphone|softphone)-[a-z0-9_]{8}$")
IDENTIFIER = re.compile(r"^[0-9a-f]{12,64}$")
SIPPYCUP_IMAGES = frozenset(
    {"localhost/sippycup", "localhost/sippycup-practice", "localhost/sippycup-webrtc"}
)
SIPPYCUP_TITLES = frozenset({"sippycup", "sippycup-practice"})
STOPPED_STATES = frozenset({"exited", "stopped", "created", "configured"})
KINDS = ("shm", "containers", "images")
DEFAULT_MIN_AGE_SECONDS = 600
RUNTIME_TIMEOUT_SECONDS = 60


@dataclass
class Item:
    kind: str
    ident: str
    detail: str
    removable: bool = True
    reason: str = ""
    removed: bool = False
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "id": self.ident,
            "detail": self.detail,
            "removable": self.removable,
            "reason": self.reason,
            "removed": self.removed,
            "error": self.error,
        }


@dataclass
class Report:
    apply: bool
    items: list[Item] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return any(item.error for item in self.items)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "sippycup.dev/cleanup/v1",
            "apply": self.apply,
            "items": [item.as_dict() for item in self.items],
            "notes": self.notes,
            "workUntouched": True,
        }


# -- private temporary directories ------------------------------------------


def _referenced_paths(proc: Path) -> set[str]:
    """Every path string that a visible process names in argv, cwd or open files."""
    seen: set[str] = set()
    try:
        entries = [entry for entry in proc.iterdir() if entry.name.isdigit()]
    except OSError:
        return seen
    for entry in entries:
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        seen.update(part.decode("utf-8", "replace") for part in raw.split(b"\0") if part)
        for name in ("cwd", "exe"):
            try:
                seen.add(os.readlink(entry / name))
            except OSError:
                pass
        try:
            descriptors = list((entry / "fd").iterdir())
        except OSError:
            continue
        for descriptor in descriptors:
            try:
                seen.add(os.readlink(descriptor))
            except OSError:
                pass
    return seen


def _newest_mtime(path: Path, names: Sequence[str]) -> float:
    newest = os.lstat(path).st_mtime
    for name in names:
        try:
            newest = max(newest, os.lstat(path / name).st_mtime)
        except OSError:
            pass
    return newest


def find_private_directories(
    *,
    shm_root: Path = SHM_ROOT,
    proc_root: Path = Path("/proc"),
    now: float | None = None,
    min_age: float = DEFAULT_MIN_AGE_SECONDS,
    uid: int | None = None,
) -> list[Item]:
    now = time.time() if now is None else now
    uid = os.getuid() if uid is None else uid
    try:
        names = sorted(name for name in os.listdir(shm_root) if PRIVATE_DIRECTORY.fullmatch(name))
    except OSError:
        return []
    if not names:
        return []
    referenced = _referenced_paths(proc_root)
    items: list[Item] = []
    for name in names:
        path = shm_root / name
        try:
            info = os.lstat(path)
        except OSError:
            continue
        if not stat.S_ISDIR(info.st_mode):
            items.append(Item("shm", str(path), "not a directory", False, "not a directory"))
            continue
        if info.st_uid != uid:
            items.append(Item("shm", str(path), f"owned by uid {info.st_uid}", False, "not owned by you"))
            continue
        try:
            contents = sorted(os.listdir(path))
        except OSError as error:
            items.append(Item("shm", str(path), "unreadable", False, f"cannot list: {error.strerror}"))
            continue
        age = now - _newest_mtime(path, contents)
        detail = f"{len(contents)} file(s), idle {int(max(age, 0))}s"
        prefix = str(path)
        live = any(item == prefix or item.startswith(prefix + "/") for item in referenced)
        if live:
            items.append(Item("shm", prefix, detail, False, "a live process references it"))
        elif age < min_age:
            items.append(Item("shm", prefix, detail, False, f"newer than --min-age {int(min_age)}s"))
        else:
            items.append(Item("shm", prefix, detail))
    return items


def remove_private_directory(path: Path, *, shm_root: Path = SHM_ROOT, uid: int | None = None) -> None:
    """Remove one private directory; raise ``OSError`` or ``ValueError`` if it is not eligible.

    The directory is opened by name relative to ``shm_root`` with
    ``O_NOFOLLOW``, re-checked through the descriptor, emptied of its plain
    files, and only then removed. A nested directory or special file aborts the
    removal instead of recursing.
    """
    uid = os.getuid() if uid is None else uid
    if path.parent != shm_root or not PRIVATE_DIRECTORY.fullmatch(path.name):
        raise ValueError(f"refusing to remove {path}: not a Sippycup private directory")
    root_fd = os.open(shm_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            info = os.fstat(fd)
            if info.st_uid != uid or not stat.S_ISDIR(info.st_mode):
                raise ValueError(f"refusing to remove {path}: not owned by you")
            for name in os.listdir(fd):
                if name in (".", "..") or "/" in name:
                    raise ValueError(f"refusing to remove {path}: unexpected entry name")
                entry = os.lstat(name, dir_fd=fd)
                if stat.S_ISDIR(entry.st_mode):
                    raise ValueError(f"refusing to remove {path}: unexpected nested directory {name!r}")
                os.unlink(name, dir_fd=fd)
        finally:
            os.close(fd)
        os.rmdir(path.name, dir_fd=root_fd)
    finally:
        os.close(root_fd)


# -- containers and images -----------------------------------------------------


def _runtime_json(runtime: str, arguments: Sequence[str], run: Callable[..., Any]) -> Any:
    completed = run(
        [runtime, *arguments],
        capture_output=True,
        text=True,
        timeout=RUNTIME_TIMEOUT_SECONDS,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip().splitlines()[-1] if completed.stderr.strip() else "runtime failed")
    return json.loads(completed.stdout or "[]")


def _repository(image: str) -> str:
    image = image.split("@", 1)[0]
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        image = image[: image.rfind(":")]
    return image


def _is_sippycup_labels(labels: Any) -> bool:
    if not isinstance(labels, dict):
        return False
    return "dev.sippycup.profile" in labels or labels.get("org.opencontainers.image.title") in SIPPYCUP_TITLES


def find_containers(
    runtime: str, *, image: str | None = None, run: Callable[..., Any] = subprocess.run
) -> list[Item]:
    data = _runtime_json(runtime, ["ps", "--all", "--format", "json"], run)
    items: list[Item] = []
    for container in data if isinstance(data, list) else []:
        ident = str(container.get("Id", ""))
        reference = str(container.get("Image", ""))
        state = str(container.get("State", "")).lower()
        if _repository(reference) not in SIPPYCUP_IMAGES and not _is_sippycup_labels(container.get("Labels")):
            continue
        if image is not None and reference != image:
            continue
        names = container.get("Names") or []
        name = names[0] if names else ident[:12]
        detail = f"{name} from {reference} ({state})"
        if state not in STOPPED_STATES:
            continue
        if not IDENTIFIER.fullmatch(ident):
            items.append(Item("containers", ident[:12], detail, False, "unexpected identifier"))
            continue
        items.append(Item("containers", ident, detail))
    return items


def find_images(
    runtime: str,
    *,
    now: float | None = None,
    min_age: float = DEFAULT_MIN_AGE_SECONDS,
    run: Callable[..., Any] = subprocess.run,
) -> list[Item]:
    now = time.time() if now is None else now
    data = _runtime_json(runtime, ["images", "--filter", "dangling=true", "--format", "json"], run)
    items: list[Item] = []
    for image in data if isinstance(data, list) else []:
        ident = str(image.get("Id", ""))
        if image.get("Names") or not _is_sippycup_labels(image.get("Labels")):
            continue
        labels = image.get("Labels") or {}
        # The label names the build's kind, not a tag: this image has no tag (it is dangling).
        detail = f"untagged old build of {labels.get('org.opencontainers.image.title', 'sippycup')}"
        if not IDENTIFIER.fullmatch(ident):
            items.append(Item("images", ident[:12], detail, False, "unexpected identifier"))
            continue
        if int(image.get("Containers") or 0) > 0:
            items.append(Item("images", ident, detail, False, "a container still uses it"))
            continue
        created = image.get("Created")
        if isinstance(created, (int, float)) and now - created < min_age:
            items.append(Item("images", ident, detail, False, f"newer than --min-age {int(min_age)}s"))
            continue
        items.append(Item("images", ident, detail))
    return items


def _remove_runtime(runtime: str, item: Item, run: Callable[..., Any]) -> None:
    verb = "rm" if item.kind == "containers" else "rmi"
    if not IDENTIFIER.fullmatch(item.ident):
        raise ValueError("unexpected identifier")
    completed = run(
        [runtime, verb, "--", item.ident],
        capture_output=True,
        text=True,
        timeout=RUNTIME_TIMEOUT_SECONDS,
        check=False,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip().splitlines()[-1] if completed.stderr.strip() else "runtime failed"
        raise RuntimeError(message)


# -- orchestration -------------------------------------------------------------


def run_cleanup(
    *,
    apply: bool = False,
    kinds: Iterable[str] = KINDS,
    min_age: float = DEFAULT_MIN_AGE_SECONDS,
    image: str | None = None,
    shm_root: Path = SHM_ROOT,
    runtime: str | None = None,
    run: Callable[..., Any] = subprocess.run,
    now: float | None = None,
    proc_root: Path = Path("/proc"),
) -> Report:
    kinds = tuple(kinds)
    report = Report(apply=apply)
    if "shm" in kinds:
        report.items.extend(
            find_private_directories(shm_root=shm_root, proc_root=proc_root, now=now, min_age=min_age)
        )
    if "containers" in kinds or "images" in kinds:
        if runtime is None:
            report.notes.append("no container runtime found; containers and images were not inspected")
        else:
            for kind, finder in (
                ("containers", lambda: find_containers(runtime, image=image, run=run)),
                ("images", lambda: find_images(runtime, now=now, min_age=min_age, run=run)),
            ):
                if kind not in kinds:
                    continue
                try:
                    report.items.extend(finder())
                except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
                    report.notes.append(f"could not list {kind}: {error}")
    if apply:
        for item in report.items:
            if not item.removable:
                continue
            try:
                if item.kind == "shm":
                    remove_private_directory(Path(item.ident), shm_root=shm_root)
                else:
                    assert runtime is not None
                    _remove_runtime(runtime, item, run)
                item.removed = True
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                item.error = str(error)
    return report


def render(report: Report) -> str:
    lines: list[str] = []
    mode = "APPLY" if report.apply else "DRY RUN (nothing is removed; add --apply)"
    lines.append(f"Sippycup leftovers: {mode}")
    for kind, title in (
        ("shm", "Private temporary directories"),
        ("containers", "Stopped Sippycup containers"),
        ("images", "Dangling Sippycup image builds (untagged leftovers of earlier builds; an image that has a "
                   "tag, such as localhost/sippycup:latest, or that a container uses is never removed)"),
    ):
        rows = [item for item in report.items if item.kind == kind]
        lines.append(f"{title}: {len(rows)}")
        for item in rows:
            if item.removed:
                state = "removed"
            elif item.error:
                state = f"FAILED: {item.error}"
            elif item.removable:
                state = "would remove" if not report.apply else "pending"
            else:
                state = f"kept ({item.reason})"
            shown = item.ident if kind == "shm" else item.ident[:12]
            lines.append(f"  {shown}  [{item.detail}]  {state}")
    for note in report.notes:
        lines.append(f"Note: {note}")
    removable = sum(1 for item in report.items if item.removable)
    removed = sum(1 for item in report.items if item.removed)
    if report.apply:
        lines.append(f"Removed {removed} of {removable} eligible item(s).")
    else:
        lines.append(f"{removable} eligible item(s). Re-run with --apply to remove them.")
    lines.append("work/ evidence is never touched. Network activity: none")
    return "\n".join(lines)


def main(arguments: Sequence[str], *, run: Callable[..., Any] = subprocess.run) -> int:
    import argparse
    import shutil

    parser = argparse.ArgumentParser(
        prog="sippycup doctor --cleanup",
        description="List (default) or remove Sippycup's own leftovers. work/ is never touched.",
    )
    parser.add_argument("--apply", action="store_true", help="remove what the dry run lists")
    parser.add_argument("--kind", action="append", choices=KINDS, help="limit to one kind (repeatable)")
    parser.add_argument(
        "--min-age", type=float, default=DEFAULT_MIN_AGE_SECONDS, metavar="SECONDS",
        help="keep anything newer than this (default %(default)s)",
    )
    parser.add_argument("--image", help="only containers created from exactly this image reference")
    parser.add_argument("--format", choices=("human", "json"), default="human")
    parser.add_argument("--shm-dir", help=argparse.SUPPRESS)
    args = parser.parse_args(list(arguments))
    if args.min_age < 0:
        parser.error("--min-age must not be negative")
    shm_root = SHM_ROOT
    if args.shm_dir is not None:
        shm_root = Path(args.shm_dir)
        if not shm_root.is_absolute() or not shm_root.is_dir() or shm_root.is_symlink():
            parser.error("--shm-dir must be an absolute directory")
    runtime = os.environ.get("SIPPYCUP_RUNTIME")
    if runtime is not None and (not runtime.strip() or any(c.isspace() for c in runtime)):
        parser.error("SIPPYCUP_RUNTIME must name one executable without arguments")
    runtime = shutil.which(runtime) if runtime else next(
        (found for found in (shutil.which(name) for name in ("podman", "nerdctl", "docker")) if found), None
    )
    report = run_cleanup(
        apply=args.apply,
        kinds=args.kind or KINDS,
        min_age=args.min_age,
        image=args.image,
        shm_root=shm_root,
        runtime=runtime,
        run=run,
    )
    if args.format == "json":
        print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
    else:
        print(render(report))
    return 1 if report.failed else 0
