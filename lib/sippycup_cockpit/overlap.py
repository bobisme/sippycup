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
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from sippycup.overlap_record import UNRELIABLE

from . import stop

ALLOW_ENV = "SIPPYCUP_ALLOW_OVERLAP"
RECORD_ENV = "SIPPYCUP_OVERLAP"
# Container commands (dev.sippycup.command) that send to a target.
SENDING_COMMANDS = frozenset({"call", "matrix", "checks", "campaign", "preflight", "media", "one-call",
                              "chaos", "resilience", "torture"})


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


def active_senders(host: stop.Host, *, checkout: str, image: str, practice_container: str) -> list[stop.Target]:
    """This checkout's running senders, found the way stop finds them; RuntimeError if unknowable."""
    containers: list[dict[str, Any]] = []
    if host.runtime is not None:
        try:
            containers = host.running_containers()
        except (RuntimeError, OSError, ValueError) as error:
            raise RuntimeError(f"could not list running containers: {error}") from error
    sending = [item for item in containers if _container_sends(item)]
    ours, _practice, _untouched = stop.classify(sending, checkout=checkout, image=image,
                                                practice_container=practice_container)
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
        f"To run beside it on purpose, set {ALLOW_ENV}={','.join(item.name for item in others)}; "
        f"both runs' results then say \"{UNRELIABLE}\".",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None, *, host: stop.Host | None = None,
         environ: dict[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sippycup-overlap", description=__doc__.splitlines()[0])
    parser.add_argument("--command", required=True, help="the sending command about to start, for the message")
    parser.add_argument("--repo", type=Path, default=None)
    args = parser.parse_args(argv)
    environ = dict(os.environ if environ is None else environ)
    repo = host.repo if host is not None else (args.repo or Path(__file__).resolve().parents[2]).resolve()
    host = host or stop.Host(repo, stop._runtime())
    image = environ.get("SIPPYCUP_IMAGE", "localhost/sippycup:latest")
    practice_container = environ.get("SIPPYCUP_PRACTICE_CONTAINER", "sippycup-practice")
    try:
        others = active_senders(host, checkout=str(repo), image=image, practice_container=practice_container)
    except RuntimeError as error:
        print(f"{args.command}: cannot tell whether another run of this checkout is active ({error}). "
              f"Nothing was sent. Check the container runtime, or run {stop.LAUNCHER} stop --dry-run.",
              file=sys.stderr)
        return 2
    if not others:
        return 0
    allowed = {item.strip() for item in environ.get(ALLOW_ENV, "").split(",") if item.strip()}
    if not allowed or any(item.name not in allowed and item.ident not in allowed for item in others):
        print(refusal(others, args.command), file=sys.stderr)
        return 2
    record = {"activeRuns": [{"name": item.name, "kind": item.kind, "detail": item.detail[:160]}
                             for item in others],
              "allowedBy": ALLOW_ENV, "note": UNRELIABLE}
    print(f"{args.command}: running beside {', '.join(item.name for item in others)} ({ALLOW_ENV}); "
          f"{UNRELIABLE}.", file=sys.stderr)
    print(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
