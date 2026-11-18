"""Reusable single-call PJSUA softphone driver.

The driver has no dependency on the guided ``call`` command so campaign
runners can place one bounded call with the same secret handling.
"""

from .driver import (
    SoftphoneAccount,
    SoftphoneCall,
    SoftphoneError,
    SoftphoneResult,
    build_config,
    destination_uri,
    parse_pjsua_log,
    place_call,
    redact,
)

__all__ = [
    "SoftphoneAccount",
    "SoftphoneCall",
    "SoftphoneError",
    "SoftphoneResult",
    "build_config",
    "destination_uri",
    "parse_pjsua_log",
    "place_call",
    "redact",
]
