"""Reviewed, low-volume SIP edge security posture checks (``./bin/sippycup checks``).

Every check is a handful of protocol-conformant requests whose count is
declared in :mod:`sippycup_checks.catalog` and enforced by the transport layer
(:mod:`sippycup_checks.budget`). Nothing here guesses passwords, scans
extensions or ports, floods, or exploits anything.
"""

FINDINGS_VERSION = "sippycup.dev/findings/v1"
