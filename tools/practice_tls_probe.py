#!/usr/bin/env python3
"""One unauthenticated TLS softphone attempt for the practice gate.

The gate copies this file into its evidence directory and runs it inside the
practice namespace, so the softphone driver itself (not the OPTIONS
preflight, which would stop a guided call first) meets a wrong server name or
an untrusted CA. It prints the driver's result as JSON.

Usage: practice_tls_probe.py ADDRESS SERVER_NAME CA_FILE|system OUTPUT_DIR
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

for candidate in (Path("/usr/local/lib"), Path(__file__).resolve().parents[1] / "lib"):
    if (candidate / "sippycup_softphone").is_dir():
        sys.path.insert(0, str(candidate))
        break

from sippycup_softphone import SoftphoneCall, place_call  # noqa: E402
from sippycup_workbench.call import generate_tone  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    address, name, ca, output = argv
    directory = Path(output)
    directory.mkdir(parents=True)
    play = directory / "probe-tone.wav"
    generate_tone(play, seconds=1.0)
    call = SoftphoneCall(
        destination="echo",
        host=address,
        port=5061,
        transport="tls",
        play_file=play,
        record_file=directory / "probe-heard.wav",
        duration_seconds=2,
        log_file=directory / "probe-softphone.log",
        answer_timeout_seconds=6.0,
        allowed_media_addresses=(address,),
        tls_server_name=name,
        tls_ca_file=None if ca == "system" else Path(ca),
    )
    result = place_call(call, environment={"PATH": "/usr/local/bin:/usr/bin:/bin"})
    print(json.dumps(result.as_dict(), sort_keys=True))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
