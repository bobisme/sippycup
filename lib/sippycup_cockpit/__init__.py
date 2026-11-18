"""Operator cockpit: one front door that shows where an engagement stands.

The cockpit is host-side and standard-library only (plus the workbench
modules it reuses). It never sends traffic itself: every action it offers is
a separate ``./bin/sippycup ...`` subprocess, so every existing gate,
ceiling, and refusal still applies.
"""

COCKPIT_VERSION = "sippycup.dev/cockpit/v1"
