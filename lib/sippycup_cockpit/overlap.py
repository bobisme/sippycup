"""Refuse a sending command while another sender of this checkout is active (wave 10, finding 6).

Two runs against one target spoil each other's verdicts: the capture, the
ladder, and the oracle mix both calls. Before ``./bin/sippycup`` starts a
sending command (call, matrix run, checks run, campaign run|execute,
preflight, media send) it runs this check, which finds this checkout's
senders exactly the way ``./bin/sippycup stop`` does (``stop.classify`` and
``stop.host_senders``). One checkout holds one engagement, so every active
sender of it is treated as aimed at an overlapping target: the launcher
cannot see another run's target, and guessing "different" would let a
spoiled verdict through.

Exit 0 and print nothing: no other sender. Exit 2 with the refusal on stderr:
another sender is active (or the container runtime could not be asked);
nothing was sent. With ``SIPPYCUP_ALLOW_OVERLAP`` naming every active run
(container name or host process id, comma separated), exit 0 and print one
JSON line describing them; the launcher hands it to the run as
``SIPPYCUP_OVERLAP`` and the run records it, so diagnose and the owner report
say the verdict is unreliable.

Claims (wave 11, finding 1). A container takes a moment to appear, so two
commands started closer together than that did not see each other and both
ran, past the owner's ``concurrent_calls``. The launcher therefore passes
``--claim-pid`` (its own process id, which becomes the container runtime's
when it ``exec``s it) and this check, under one exclusive file lock on
``work/.sender-claims/lock``:

1. lists this checkout's running senders, as before;
2. reads the claims of other launchers (``work/.sender-claims/ID.json``). A
   claim is live while the process it names is alive (same process id and
   same kernel start time, and not a zombie); a claim whose process is gone,
   or that cannot be read, is deleted and ignored, so a crash never wedges
   the tool. A live claim whose container is already running (the container
   carries the claim id as the label ``dev.sippycup.claim``) or whose process
   is a host sender already listed is that same run, not a second one;
3. refuses, or passes under ``SIPPYCUP_ALLOW_OVERLAP`` as before (a launcher
   that has no container yet is named ``launcher-PID``);
4. on a pass writes this launcher's claim and prints ``claim ID`` as the
   first line of stdout (the overlap record, if any, is the second).

The lock is held only for this check: the file descriptor is closed before
this process exits and is never inherited by the container runtime. If the
lock or the claim directory cannot be used, the check refuses (fail closed).
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from sippycup.overlap_record import UNRELIABLE

from . import stop

ALLOW_ENV = "SIPPYCUP_ALLOW_OVERLAP"
RECORD_ENV = "SIPPYCUP_OVERLAP"
# Container commands (dev.sippycup.command) that send to a target.
SENDING_COMMANDS = frozenset({"call", "matrix", "checks", "campaign", "preflight", "media", "one-call",
                              "chaos", "resilience", "torture"})


CLAIM_LABEL = "dev.sippycup.claim"
CLAIM_VERSION = "sippycup.dev/sender-claim/v1"
CLAIMS_DIRECTORY = ("work", ".sender-claims")
LOCK_NAME = "lock"
# The lock is held for one inventory (one `ps` of the container runtime).
LOCK_WAIT_SECONDS = 90.0


class ClaimError(RuntimeError):
    """The claim directory or its lock cannot be used; nothing may be sent."""


def claims_directory(repo: Path) -> Path:
    return Path(repo).joinpath(*CLAIMS_DIRECTORY)


def process_start(proc: Path, pid: int) -> str | None:
    """The kernel start time of a live process (field 22 of ``/proc/PID/stat``); None when gone or a zombie."""
    try:
        text = (proc / str(pid) / "stat").read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return None
    fields = text.rsplit(")", 1)[-1].split()
    if len(fields) < 20 or fields[0] in {"Z", "X"}:
        return None
    return fields[19]


class _ClaimLock:
    """One exclusive lock per checkout around "look, then claim"; released on exit."""

    def __init__(self, directory: Path, wait: float = LOCK_WAIT_SECONDS) -> None:
        self.directory = directory
        self.wait = wait
        self.descriptor: int | None = None

    def __enter__(self) -> "_ClaimLock":
        try:
            os.makedirs(self.directory, mode=0o700, exist_ok=True)
            status = os.lstat(self.directory)
            if not os.path.isdir(self.directory) or os.path.islink(self.directory) or status.st_uid != os.getuid():
                raise ClaimError(f"{self.directory} is not a directory of this user")
            # Not inheritable (Python's default), so no child keeps the lock.
            self.descriptor = os.open(self.directory / LOCK_NAME,
                                      os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except OSError as error:
            raise ClaimError(f"cannot use {self.directory}: {error.strerror or error}") from error
        deadline = time.monotonic() + self.wait
        while True:
            try:
                fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    os.close(self.descriptor)
                    self.descriptor = None
                    raise ClaimError(f"another command held the lock {self.directory / LOCK_NAME} for more than "
                                     f"{self.wait:.0f} s") from None
                time.sleep(0.05)
            except OSError as error:
                os.close(self.descriptor)
                self.descriptor = None
                raise ClaimError(f"cannot lock {self.directory / LOCK_NAME}: {error.strerror or error}") from error

    def __exit__(self, *_exc: object) -> None:
        if self.descriptor is not None:
            try:
                fcntl.flock(self.descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self.descriptor)
                self.descriptor = None


def live_claims(directory: Path, proc: Path) -> list[dict[str, Any]]:
    """Claims whose process is alive; every other claim file is deleted. Call under the lock."""
    try:
        paths = sorted(directory.glob("*.json"))
    except OSError as error:
        raise ClaimError(f"cannot read {directory}: {error.strerror or error}") from error
    live: list[dict[str, Any]] = []
    for path in paths:
        claim: Any = None
        try:
            if not path.is_symlink():
                claim = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            claim = None
        valid = (isinstance(claim, dict) and claim.get("v") == CLAIM_VERSION and type(claim.get("pid")) is int
                 and isinstance(claim.get("startTime"), str) and claim.get("id") == path.stem)
        if valid and process_start(proc, claim["pid"]) == claim["startTime"]:
            live.append(claim)
            continue
        # The process is gone (or the file names none): the claim is over.
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise ClaimError(f"cannot remove the finished claim {path}: {error.strerror or error}") from error
    return live


def write_claim(directory: Path, proc: Path, pid: int, command: str) -> str:
    """Record that the launcher ``pid`` is about to start a sender. Call under the lock."""
    started = process_start(proc, pid)
    if started is None:
        raise ClaimError(f"the launcher process {pid} is not running")
    identifier = uuid.uuid4().hex
    claim = {"v": CLAIM_VERSION, "id": identifier, "pid": pid, "startTime": started, "command": command[:160],
             "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    path = directory / f"{identifier}.json"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(claim, output, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    except OSError as error:
        raise ClaimError(f"cannot write the claim {path}: {error.strerror or error}") from error
    return identifier


def claim_targets(claims: list[dict[str, Any]], *, own: set[int], running_claims: set[str],
                  listed: list[stop.Target]) -> list[stop.Target]:
    """Live claims of other launchers that are not already listed as a running sender."""
    processes = {item.ident for item in listed if item.kind == "process"}
    found = []
    for claim in claims:
        pid = claim["pid"]
        if pid in own or claim["id"] in running_claims or str(pid) in processes:
            continue
        found.append(stop.Target(
            "launcher", str(pid), f"launcher-{pid}",
            f"{claim.get('command') or '?'}: starting (claimed at {claim.get('at') or '?'}; its container is not "
            "listed yet, or has just ended)", "claim of this checkout"))
    return found


def _ancestors(proc: Path) -> set[int]:
    """This process and every parent (the launcher that asked, its shell...)."""
    found: set[int] = set()
    pid = os.getpid()
    while pid > 1 and pid not in found:
        found.add(pid)
        try:
            status = (proc / str(pid) / "status").read_text(encoding="utf-8", errors="replace")
        except OSError:
            break
        parent = next((line.split()[1] for line in status.splitlines() if line.startswith("PPid:")), "0")
        pid = int(parent) if parent.isdigit() else 0
    return found


def _container_sends(container: dict[str, Any]) -> bool:
    labels = stop._labels(container)
    command = labels.get(stop.COMMAND_LABEL, "")
    if command in SENDING_COMMANDS:
        return True
    argv = container.get("Command")
    head = argv[0] if isinstance(argv, list) and argv else str(argv or "").split(" ")[0]
    # An advanced passthrough that runs a SIP sender directly (pjsua, sipp).
    return os.path.basename(str(head)) in stop.SENDER_EXECUTABLES


def active_senders(host: stop.Host, *, checkout: str, image: str, practice_container: str,
                   running_claims: set[str] | None = None) -> list[stop.Target]:
    """This checkout's running senders, found the way stop finds them; RuntimeError if unknowable.

    ``running_claims`` (a set to fill) receives the claim ids that this
    checkout's running containers carry.
    """
    containers: list[dict[str, Any]] = []
    if host.runtime is not None:
        try:
            containers = host.running_containers()
        except (RuntimeError, OSError, ValueError) as error:
            raise RuntimeError(f"could not list running containers: {error}") from error
    sending = [item for item in containers if _container_sends(item)]
    ours, _practice, _untouched = stop.classify(sending, checkout=checkout, image=image,
                                                practice_container=practice_container)
    if running_claims is not None:
        running_claims.update(
            str(stop._labels(item).get(CLAIM_LABEL)) for item in containers
            if stop._labels(item).get(stop.CHECKOUT_LABEL) == checkout and stop._labels(item).get(CLAIM_LABEL))
    processes = stop.host_senders(host.processes(), checkout=checkout, uid=os.getuid(),
                                  own=_ancestors(host.proc), container_ids={item.ident for item in ours})
    return [*ours, *processes]


def refusal(others: list[stop.Target], command: str) -> str:
    lines = [f"{command}: another sending command of this checkout is active:"]
    for item in others:
        lines.append(f"  {item.name} ({item.kind}: {item.detail})")
    lines += [
        "Two runs against one target spoil each other's verdicts (the capture, ladder, and oracle mix both).",
        f"Wait for it to finish, or end it with {stop.LAUNCHER} stop. Nothing was sent.",
        *([f"A launcher-PID entry is a command that claimed its start and whose container is not listed yet: "
           f"{stop.LAUNCHER} stop --dry-run shows it once it runs."]
          if any(item.kind == "launcher" for item in others) else []),
        f"To run beside it on purpose, set {ALLOW_ENV}={','.join(item.name for item in others)}; "
        f"both runs' results then say \"{UNRELIABLE}\".",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None, *, host: stop.Host | None = None,
         environ: dict[str, str] | None = None, claims: Path | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sippycup-overlap", description=__doc__.splitlines()[0])
    parser.add_argument("--command", required=True, help="the sending command about to start, for the message")
    parser.add_argument("--repo", type=Path, default=None)
    parser.add_argument("--claim-pid", type=int, default=None,
                        help="the launcher's process id: claim the start for it (it execs the container runtime)")
    args = parser.parse_args(argv)
    environ = dict(os.environ if environ is None else environ)
    repo = host.repo if host is not None else (args.repo or Path(__file__).resolve().parents[2]).resolve()
    host = host or stop.Host(repo, stop._runtime())
    image = environ.get("SIPPYCUP_IMAGE", "localhost/sippycup:latest")
    practice_container = environ.get("SIPPYCUP_PRACTICE_CONTAINER", "sippycup-practice")
    directory = claims if claims is not None else claims_directory(repo)
    if args.claim_pid is None and not directory.is_dir():
        # Asked without the launcher and nothing was ever claimed here.
        return _decide(args, host, environ, repo, image, practice_container, None)
    try:
        with _ClaimLock(directory):
            return _decide(args, host, environ, repo, image, practice_container, directory)
    except ClaimError as error:
        print(f"{args.command}: cannot tell whether another run of this checkout is starting ({error}). "
              f"Nothing was sent. Check that {directory} is a directory you can write, then run the command again.",
              file=sys.stderr)
        return 2


def _decide(args: argparse.Namespace, host: stop.Host, environ: dict[str, str], repo: Path, image: str,
            practice_container: str, directory: Path | None) -> int:
    """Look, refuse or pass, and claim; with ``directory`` the caller holds its lock."""
    running_claims: set[str] = set()
    try:
        others = active_senders(host, checkout=str(repo), image=image, practice_container=practice_container,
                                running_claims=running_claims)
    except RuntimeError as error:
        print(f"{args.command}: cannot tell whether another run of this checkout is active ({error}). "
              f"Nothing was sent. Check the container runtime, or run {stop.LAUNCHER} stop --dry-run.",
              file=sys.stderr)
        return 2
    if directory is not None:
        own = _ancestors(host.proc)
        if args.claim_pid is not None:
            own.add(args.claim_pid)
        others = [*others, *claim_targets(live_claims(directory, host.proc), own=own,
                                          running_claims=running_claims, listed=others)]
    record = None
    if others:
        allowed = {item.strip() for item in environ.get(ALLOW_ENV, "").split(",") if item.strip()}
        if not allowed or any(item.name not in allowed and item.ident not in allowed for item in others):
            print(refusal(others, args.command), file=sys.stderr)
            return 2
        record = {"activeRuns": [{"name": item.name, "kind": item.kind, "detail": item.detail[:160]}
                                 for item in others],
                  "allowedBy": ALLOW_ENV, "note": UNRELIABLE}
    if directory is not None and args.claim_pid is not None:
        # Before anything is printed: a pass without a claim must not happen.
        print(f"claim {write_claim(directory, host.proc, args.claim_pid, args.command)}")
    if record is not None:
        print(f"{args.command}: running beside {', '.join(item.name for item in others)} ({ALLOW_ENV}); "
              f"{UNRELIABLE}.", file=sys.stderr)
        print(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
