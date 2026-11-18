#!/usr/bin/env python3
"""A stand-in for ``unshare`` in the softphone driver's name-pinning tests.

The driver runs ``unshare --user --map-root-user --mount -- /bin/sh -c
SCRIPT sh HOSTS NSSWITCH COMMAND...``. This fake checks that shape, records
it in FAKE_UNSHARE_WITNESS (appending one JSON line per run), and then:

- for ``getent ahosts NAME`` answers from HOSTS the way glibc would with
  ``hosts: files`` (FAKE_UNSHARE_MODE ``fail`` exits 2, ``extra`` adds a
  second address);
- otherwise executes COMMAND with FAKE_PINNED_HOSTS naming the host map.
"""

import json
import os
import sys


def main():
    argv = sys.argv[1:]
    expected = ["--user", "--map-root-user", "--mount", "--", "/bin/sh", "-c"]
    if argv[: len(expected)] != expected or argv[7] != "sh":
        print(f"unexpected unshare argv: {argv}", file=sys.stderr)
        return 97
    script, hosts, nsswitch, command = argv[6], argv[8], argv[9], argv[10:]
    witness = os.environ.get("FAKE_UNSHARE_WITNESS")
    if witness:
        with open(witness, "a", encoding="utf-8") as output:
            output.write(json.dumps({
                "script": script,
                "hosts": open(hosts, encoding="utf-8").read(),
                "nsswitch": open(nsswitch, encoding="utf-8").read(),
                "command": command,
            }) + "\n")
    mode = os.environ.get("FAKE_UNSHARE_MODE", "ok")
    if command[:2] == ["getent", "ahosts"]:
        if mode == "fail":
            return 2
        name = command[2]
        for line in open(hosts, encoding="utf-8"):
            fields = line.split()
            if len(fields) >= 2 and name in fields[1:]:
                print(f"{fields[0]}       STREAM {name}")
                if mode == "extra":
                    print(f"203.0.113.99    STREAM {name}")
        return 0
    os.environ["FAKE_PINNED_HOSTS"] = hosts
    os.execvp(command[0], command)
    return 98


if __name__ == "__main__":
    raise SystemExit(main())
