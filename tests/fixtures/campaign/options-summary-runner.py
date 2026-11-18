#!/usr/bin/env python3
"""Fixture OPTIONS runner: prints a one-line JSON summary that leaks a secret.

argv[1] is the fixture secret. The runner never needs it from its envelope;
it models a tool that echoes a secret it learned elsewhere, which the
supervisor's redaction must scrub from retained output.
"""

import json
import sys

envelope = json.loads(sys.stdin.readline())
print(
    json.dumps(
        {
            "step": envelope["step"]["index"],
            "status": 200,
            "credentialsReceived": len(envelope["credentials"]),
            "leak": sys.argv[1],
        }
    )
)
