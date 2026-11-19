"""``./bin/sippycup stop``: end everything Sippycup is sending from this host, and prove it.

What it stops, by exact rule:

``containers``  running containers that carry ``dev.sippycup.checkout=<this
                checkout>`` (every container ``./bin/sippycup`` starts has it),
                and running unlabelled containers created from exactly this
                checkout's image (``$SIPPYCUP_IMAGE``), started before the label
                existed. A container of another checkout, of another image, or
                the practice target is never touched (the practice target only
                with ``--include-practice``, through ``practice-target down``).
``host``        host processes started from this checkout's ``bin/`` sender
                commands (a host-side ``campaign``, ``sippycup-media``...), and
                ``pjsua``/``sipp`` processes whose working directory is inside
                this checkout.

How: first SIGTERM to every sender (``kill --signal TERM`` for a container,
which its init forwards to the command). Each Sippycup command handles that
signal itself: the guided call, matrix, checks, and the softphone campaign
runner hang up an answered call with BYE, CANCEL a ringing one, unregister,
stop the capture, and record a ``cancelled`` result. After ``--grace``
seconds anything still running is killed (SIGKILL) and reported as forced.
Finally it proves silence: no container of this checkout is running and no
sender process is left. Evidence under ``work/`` is never touched.

Exit codes: 0 silence proved (or nothing was running), 1 something could not
be stopped or silence could not be proved, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

LAUNCHER = "./bin/sippycup"
CHECKOUT_LABEL = "dev.sippycup.checkout"
COMMAND_LABEL = "dev.sippycup.command"
PRACTICE_LABEL = "dev.sippycup.profile"
SIPPYCUP_TITLES = frozenset({"sippycup"})
DEFAULT_GRACE_SECONDS = 30.0
SETTLE_SECONDS = 10.0
POLL_SECONDS = 0.5
IDENTIFIER = re.compile(r"^[0-9a-f]{12,64}$")
# bin/ commands that send traffic when run on the host instead of in the image.
HOST_SENDERS = frozenset({
    "campaign", "campaign-sipp-runner", "campaign-softphone-runner", "sippycup-media", "sippycup-media-echo",
    "sippycup-call", "sippycup-checks", "sippycup-matrix", "sippycup-chaos", "sippycup-resilience",
})
SENDER_EXECUTABLES = frozenset({"pjsua", "sipp", "baresip"})


@dataclass
class Target:
    kind: str  # "container" or "process"
    ident: str
    name: str
    detail: str
    matched_by: str
    processes: list[str] = field(default_factory=list)
    outcome: str = "running"  # running -> clean | forced | failed | already-gone
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "id": self.ident, "name": self.name, "detail": self.detail,
                "matchedBy": self.matched_by, "processes": self.processes, "outcome": self.outcome,
                "error": self.error}


@dataclass
class Report:
    dry_run: bool
    started: str
    targets: list[Target] = field(default_factory=list)
    practice: dict[str, Any] | None = None
    untouched: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    silence: dict[str, Any] = field(default_factory=dict)
    finished: str | None = None

    @property
    def failed(self) -> bool:
        if self.dry_run:
            return bool(self.notes and any(note.startswith("could not") for note in self.notes))
        return (any(item.outcome == "failed" for item in self.targets)
                or not self.silence.get("proved", False)
                or bool(self.practice and self.practice.get("outcome") == "failed"))

    def counts(self) -> dict[str, int]:
        values: dict[str, int] = {}
        for item in self.targets:
            values[item.outcome] = values.get(item.outcome, 0) + 1
        return values

    def as_dict(self) -> dict[str, Any]:
        return {
            "apiVersion": "sippycup.dev/stop/v1",
            "dryRun": self.dry_run,
            "started": self.started,
            "finished": self.finished,
            "targets": [item.as_dict() for item in self.targets],
            "counts": self.counts(),
            "practice": self.practice,
            "untouched": self.untouched,
            "notes": self.notes,
            "silence": self.silence,
            "ok": not self.failed,
            "workUntouched": True,
        }


class Host:
    """The container runtime, /proc, signals, and the clock; tests replace it."""

    def __init__(self, repo: Path, runtime: str | None, proc: Path = Path("/proc")):
        self.repo = repo
        self.runtime = runtime
        self.proc = proc

    def runtime_json(self, arguments: list[str]) -> Any:
        assert self.runtime is not None
        completed = subprocess.run([self.runtime, *arguments], capture_output=True, text=True, timeout=60,
                                   check=False, stdin=subprocess.DEVNULL)
        if completed.returncode != 0:
            raise RuntimeError((completed.stderr.strip().splitlines() or ["runtime failed"])[-1])
        return json.loads(completed.stdout or "[]")

    def runtime_call(self, arguments: list[str], timeout: float = 60) -> tuple[int, str]:
        assert self.runtime is not None
        try:
            completed = subprocess.run([self.runtime, *arguments], capture_output=True, text=True,
                                       timeout=timeout, check=False, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return 124, "timed out"
        return completed.returncode, (completed.stderr.strip() or completed.stdout.strip())

    def running_containers(self) -> list[dict[str, Any]]:
        data = self.runtime_json(["ps", "--format", "json"])
        return data if isinstance(data, list) else []

    def container_processes(self, ident: str) -> list[str]:
        """The processes inside one container (``top``), for the operator to see what ends."""
        assert self.runtime is not None
        try:
            completed = subprocess.run([self.runtime, "top", ident, "pid", "args"], capture_output=True, text=True,
                                       timeout=20, check=False, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return []
        if completed.returncode != 0:
            return []
        rows = completed.stdout.splitlines()[1:]
        return [" ".join(row.split()[1:])[:160] for row in rows if row.split()]

    def processes(self) -> list[dict[str, Any]]:
        found = []
        try:
            entries = [entry for entry in self.proc.iterdir() if entry.name.isdigit()]
        except OSError:
            return found
        for entry in entries:
            try:
                raw = (entry / "cmdline").read_bytes()
                status = (entry / "status").read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            argv = [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]
            if not argv:
                continue
            uid = next((int(line.split()[1]) for line in status.splitlines() if line.startswith("Uid:")), -1)
            try:
                cwd = os.readlink(entry / "cwd")
            except OSError:
                cwd = ""
            try:
                cgroup = (entry / "cgroup").read_text(encoding="utf-8", errors="replace")
            except OSError:
                cgroup = ""
            found.append({"pid": int(entry.name), "argv": argv, "uid": uid, "cwd": cwd, "cgroup": cgroup})
        return found

    def alive(self, pid: int) -> bool:
        return (self.proc / str(pid)).exists()

    def kill(self, pid: int, signum: int) -> None:
        os.kill(pid, signum)

    def practice_down(self) -> tuple[int, str]:
        completed = subprocess.run([str(self.repo / "bin" / "sippycup"), "practice-target", "down"],
                                   capture_output=True, text=True, timeout=120, check=False,
                                   stdin=subprocess.DEVNULL, cwd=self.repo)
        return completed.returncode, (completed.stdout + completed.stderr).strip()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def monotonic(self) -> float:
        return time.monotonic()

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _labels(container: dict[str, Any]) -> dict[str, str]:
    labels = container.get("Labels")
    return labels if isinstance(labels, dict) else {}


def _name(container: dict[str, Any]) -> str:
    names = container.get("Names") or []
    return str(names[0] if isinstance(names, list) and names else container.get("Id", "")[:12])


def classify(containers: list[dict[str, Any]], *, checkout: str, image: str,
             practice_container: str) -> tuple[list[Target], dict[str, Any] | None, list[str]]:
    """Split running containers into ours, the practice target, and the untouched rest."""
    ours: list[Target] = []
    practice = None
    untouched: list[str] = []
    for container in containers:
        ident = str(container.get("Id", ""))
        labels = _labels(container)
        name = _name(container)
        reference = str(container.get("Image", ""))
        command = container.get("Command")
        shown = " ".join(command) if isinstance(command, list) else str(command or "")
        if labels.get(PRACTICE_LABEL) == "practice":
            if name == practice_container:
                practice = {"id": ident, "name": name, "image": reference}
            else:
                untouched.append(f"{name} (another practice target)")
            continue
        checkout_label = labels.get(CHECKOUT_LABEL)
        if checkout_label == checkout:
            matched = "label"
        elif checkout_label is None and reference == image and labels.get("org.opencontainers.image.title") in SIPPYCUP_TITLES:
            matched = "image (no checkout label: started before stop support)"
        else:
            if checkout_label is not None or labels.get("org.opencontainers.image.title") in SIPPYCUP_TITLES:
                untouched.append(f"{name} ({reference}, another checkout)")
            continue
        if not IDENTIFIER.fullmatch(ident):
            untouched.append(f"{name} (unexpected identifier)")
            continue
        detail = f"{labels.get(COMMAND_LABEL, '?')}: {shown}"[:200]
        ours.append(Target("container", ident, name, detail, matched))
    return ours, practice, untouched


def host_senders(processes: list[dict[str, Any]], *, checkout: str, uid: int, own: set[int],
                 container_ids: set[str]) -> list[Target]:
    """Host processes from this checkout that send traffic (never container processes)."""
    found = []
    bin_dir = os.path.join(checkout, "bin") + os.sep
    for process in processes:
        if process["pid"] in own or process["uid"] != uid:
            continue
        if "libpod-" in process["cgroup"] or "/docker-" in process["cgroup"] or "containerd" in process["cgroup"]:
            continue  # a container's process: handled with its container
        argv = process["argv"]
        heads = argv[:2]
        sender = next((item for item in heads if item.startswith(bin_dir)
                       and os.path.basename(item) in HOST_SENDERS), None)
        executable = os.path.basename(argv[0])
        inside = process["cwd"] == checkout or process["cwd"].startswith(checkout + os.sep)
        if sender or (executable in SENDER_EXECUTABLES and inside):
            found.append(Target("process", str(process["pid"]), os.path.basename(sender or argv[0]),
                                shlex.join(argv)[:200], "host process of this checkout"))
    return found


def inventory(host: Host, *, checkout: str, image: str, practice_container: str,
              include_practice: bool, own: set[int]) -> Report:
    report = Report(dry_run=False, started=_iso(host.now()))
    if host.runtime is None:
        report.notes.append("no container runtime found; only host processes were inspected")
        containers: list[dict[str, Any]] = []
    else:
        try:
            containers = host.running_containers()
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
            report.notes.append(f"could not list containers: {error}")
            containers = []
    ours, practice, untouched = classify(containers, checkout=checkout, image=image,
                                         practice_container=practice_container)
    for target in ours:
        target.processes = host.container_processes(target.ident)
    report.targets.extend(ours)
    report.targets.extend(host_senders(host.processes(), checkout=checkout, uid=os.getuid(), own=own,
                                       container_ids={item.ident for item in ours}))
    report.untouched = untouched
    if practice is not None:
        if include_practice:
            report.practice = {**practice, "outcome": "running"}
        else:
            report.untouched.append(f"{practice['name']} (the practice target; add --include-practice)")
    return report


def _running_ids(host: Host, wanted: set[str], report: Report) -> set[str] | None:
    try:
        running = {str(item.get("Id", "")) for item in host.running_containers()}
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        report.notes.append(f"could not list containers while waiting: {error}")
        return None
    return wanted & running


def _wait(host: Host, report: Report, targets: list[Target], seconds: float) -> None:
    deadline = host.monotonic() + seconds
    while True:
        containers = {item.ident for item in targets if item.kind == "container" and item.outcome == "running"}
        processes = [item for item in targets if item.kind == "process" and item.outcome == "running"]
        still = _running_ids(host, containers, report) if containers and host.runtime else set()
        for item in targets:
            if item.outcome != "running":
                continue
            gone = (item.ident not in (still or set())) if item.kind == "container" else not host.alive(int(item.ident))
            if item.kind == "container" and still is None:
                gone = False
            if gone:
                item.outcome = "ended"
        if not any(item.outcome == "running" for item in targets) or host.monotonic() >= deadline:
            return
        host.sleep(POLL_SECONDS)


def _signal(host: Host, item: Target, signum: int) -> str | None:
    if item.kind == "container":
        name = "TERM" if signum == signal.SIGTERM else "KILL"
        code, message = host.runtime_call(["kill", "--signal", name, item.ident], timeout=30)
        if code != 0 and "no such container" not in message.lower() and "not running" not in message.lower():
            return message or f"exit {code}"
        return None
    try:
        host.kill(int(item.ident), signum)
    except ProcessLookupError:
        return None
    except OSError as error:
        return str(error)
    return None


def prove_silence(host: Host, report: Report, *, checkout: str, image: str, practice_container: str,
                  own: set[int]) -> None:
    """Look again from scratch: nothing of this checkout may still be running."""
    again = inventory(host, checkout=checkout, image=image, practice_container=practice_container,
                      include_practice=False, own=own)
    stopped = {item.ident for item in report.targets if item.kind == "container"}
    left_processes = [process for process in host.processes()
                      if os.path.basename(process["argv"][0]) in SENDER_EXECUTABLES
                      and any(ident in process["cgroup"] for ident in stopped)]
    remaining = [f"{item.kind} {item.name} ({item.ident[:12]})" for item in again.targets]
    remaining += [f"process {process['pid']} {process['argv'][0]} (inside a stopped container)"
                  for process in left_processes]
    if report.practice is not None:
        try:
            practice_running = any(_name(item) == practice_container for item in host.running_containers())
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError):
            practice_running = True
        if practice_running:
            remaining.append(f"practice target {practice_container}")
    listed = not any(note.startswith("could not list containers") for note in again.notes)
    report.silence = {
        "proved": not remaining and listed,
        "remaining": remaining,
        "checked": "running containers of this checkout (label or image), sender processes on this host",
    }
    if not listed:
        report.silence["remaining"].append("the container runtime could not be asked; silence is not proved")


def stop(host: Host, *, checkout: str, image: str, practice_container: str, include_practice: bool,
         grace: float, dry_run: bool) -> Report:
    own = {os.getpid(), os.getppid()}
    report = inventory(host, checkout=checkout, image=image, practice_container=practice_container,
                       include_practice=include_practice, own=own)
    report.dry_run = dry_run
    if dry_run:
        report.finished = _iso(host.now())
        return report
    # 1. Ask every sender to end its dialogs itself (BYE / CANCEL / unregister).
    for item in report.targets:
        problem = _signal(host, item, signal.SIGTERM)
        if problem:
            item.error = f"SIGTERM: {problem}"
    _wait(host, report, report.targets, grace)
    for item in report.targets:
        if item.outcome == "ended":
            item.outcome = "clean"
    # 2. Force what is left after the grace period.
    leftovers = [item for item in report.targets if item.outcome == "running"]
    for item in leftovers:
        problem = _signal(host, item, signal.SIGKILL)
        if problem:
            item.error = (item.error + "; " if item.error else "") + f"SIGKILL: {problem}"
    if leftovers:
        _wait(host, report, leftovers, SETTLE_SECONDS)
        for item in leftovers:
            item.outcome = "forced" if item.outcome == "ended" else "failed"
    # 3. The practice target, only when asked.
    if report.practice is not None:
        code, output = host.practice_down()
        report.practice["outcome"] = "stopped" if code == 0 else "failed"
        report.practice["detail"] = output.splitlines()[0] if output else ""
    # 4. Prove silence.
    prove_silence(host, report, checkout=checkout, image=image, practice_container=practice_container, own=own)
    report.finished = _iso(host.now())
    return report


def journal_line(report: Report, engagement: str | None) -> str:
    counts = report.counts()
    clean, forced, failed = counts.get("clean", 0), counts.get("forced", 0), counts.get("failed", 0)
    total = len(report.targets)
    silence = "silence verified" if report.silence.get("proved") else "SILENCE NOT PROVED"
    summary = (f"Emergency stop at {report.started}: {total} Sippycup sender(s) stopped "
               f"({clean} clean, {forced} forced, {failed} failed); {silence} at {report.finished}")
    if report.practice is not None:
        summary += f"; practice target {report.practice.get('outcome')}"
    return shlex.join([LAUNCHER, "journal", "add", engagement or "work/NAME", "--kind", "action",
                       "--summary", summary])


def default_engagement(repo: Path) -> str | None:
    """``work/NAME`` when exactly one engagement exists under work/, else None."""
    from .probes import find_engagements

    found = find_engagements(repo)
    return f"work/{found[0].name}" if len(found) == 1 else None


def render(report: Report, engagement: str | None) -> list[str]:
    lines = []
    if report.dry_run:
        lines.append("Sippycup emergency stop: DRY RUN (nothing is signalled; run without --dry-run to stop)")
    else:
        lines.append(f"Sippycup emergency stop at {report.started}")
    if not report.targets:
        lines.append("No Sippycup sender from this checkout is running.")
    for item in report.targets:
        state = {"clean": "stopped cleanly (ended after SIGTERM; its own shutdown ran: BYE/CANCEL, unregister)",
                 "forced": "FORCED (still running after the grace period; killed)",
                 "failed": f"FAILED to stop: {item.error}",
                 "running": "would be stopped: SIGTERM, then SIGKILL after the grace period",
                 "already-gone": "already gone"}.get(item.outcome, item.outcome)
        lines.append(f"  {item.kind:9} {item.ident[:12]:12} {item.name}: {state}")
        lines.append(f"            {item.detail}  [matched by {item.matched_by}]")
        for process in item.processes[:8]:
            lines.append(f"              - {process}")
    if report.practice is not None:
        verb = "would be taken down (practice-target down)" if report.dry_run else report.practice.get("outcome")
        lines.append(f"  practice  {report.practice['name']}: {verb}")
    for item in report.untouched:
        lines.append(f"  untouched {item}")
    for note in report.notes:
        lines.append(f"Note: {note}")
    if not report.dry_run:
        if report.silence.get("proved"):
            lines.append("Silence: PROVED. No Sippycup sender container or sender process of this checkout is left.")
            if any("the practice target" in item for item in report.untouched):
                lines.append("The practice target is still up: it is a server and sends nothing on its own "
                             "(take it down with ./bin/sippycup practice-target down).")
        else:
            lines.append("Silence: NOT PROVED. Still running:")
            lines.extend(f"  - {item}" for item in report.silence.get("remaining") or ["(unknown)"])
        lines.append("Record it: " + journal_line(report, engagement))
        if engagement is None:
            lines.append("  (work/NAME is a placeholder, not a directory: replace it with your engagement "
                         "directory, for example work/acme, before you run the line; or give --engagement DIR "
                         "next time and it is filled in)")
    lines.append("work/ evidence is never touched. Run directories of stopped commands record state 'cancelled'.")
    return lines


def _runtime() -> str | None:
    import shutil

    configured = os.environ.get("SIPPYCUP_RUNTIME")
    if configured:
        return shutil.which(configured)
    return next((found for found in (shutil.which(name) for name in ("podman", "docker", "nerdctl")) if found), None)


def main(argv: list[str] | None = None, *, host: Host | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="./bin/sippycup stop",
        description="End every Sippycup sender started from this checkout: SIGTERM so calls end with BYE/CANCEL "
                    "and unregister, SIGKILL after the grace period, then prove silence. Never touches evidence, "
                    "unrelated containers, or the practice target (unless --include-practice). Exit 0 silence "
                    "proved, 1 something is still running, 2 usage error.",
    )
    parser.add_argument("--dry-run", action="store_true", help="list what would be stopped; signal nothing")
    parser.add_argument("--grace", type=float, default=DEFAULT_GRACE_SECONDS, metavar="SECONDS",
                        help="how long senders get to end their dialogs before SIGKILL (default %(default)s)")
    parser.add_argument("--include-practice", action="store_true",
                        help="also take the local practice target down (practice-target down)")
    parser.add_argument("--engagement", metavar="DIR", help="engagement for the printed journal command")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--repo", type=Path, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if not 0 <= args.grace <= 600:
        parser.error("--grace must be between 0 and 600 seconds")
    repo = host.repo if host is not None else (args.repo or Path(__file__).resolve().parents[2]).resolve()
    host = host or Host(repo, _runtime())
    image = os.environ.get("SIPPYCUP_IMAGE", "localhost/sippycup:latest")
    practice_container = os.environ.get("SIPPYCUP_PRACTICE_CONTAINER", "sippycup-practice")
    if args.engagement is None:
        args.engagement = default_engagement(repo)
    report = stop(host, checkout=str(repo), image=image, practice_container=practice_container,
                  include_practice=args.include_practice, grace=args.grace, dry_run=args.dry_run)
    if args.format == "json":
        value = report.as_dict()
        if not report.dry_run:
            value["journalCommand"] = journal_line(report, args.engagement)
        print(json.dumps(value, indent=2, sort_keys=True))
    else:
        for line in render(report, args.engagement):
            print(line)
    return 1 if report.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
