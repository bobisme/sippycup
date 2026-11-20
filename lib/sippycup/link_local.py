"""Link-local targets are refused unless they are the routed practice target.

A 169.254.0.0/16 (or fe80::/10) address is never forwarded beyond the local
segment, but a send to one still leaves this machine on the default route's
interface. The only legitimate use is the routed rehearsal, where the
launcher maps one such address to host loopback (pasta --map-host-loopback)
after it has checked the routed practice container, and exports that address
as ``SIPPYCUP_ROUTED_ADDRESS``. Any other link-local target, approved address,
or media network is refused before anything is sent.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Iterable, Mapping

ENV = "SIPPYCUP_ROUTED_ADDRESS"
_LINK_LOCAL = (ipaddress.ip_network("169.254.0.0/16"), ipaddress.ip_network("fe80::/10"))


def problems(values: Iterable[object], environ: Mapping[str, str] | None = None) -> list[str]:
    """Why each link-local address or network in ``values`` may not be used here."""
    routed = (os.environ if environ is None else environ).get(ENV, "")
    found: list[str] = []
    for value in values:
        try:
            network = ipaddress.ip_network(str(value), strict=False)
        except ValueError:
            continue
        if not any(network.version == outer.version and network.overlaps(outer) for outer in _LINK_LOCAL):
            continue
        if routed and network.num_addresses == 1 and str(network.network_address) == routed:
            continue
        found.append(
            f"{value} is link-local; a send there leaves this machine on the default route's "
            "interface. Only the routed practice target may use one (make routed-rehearsal); "
            f"{ENV} {'names ' + routed if routed else 'is not set'}"
        )
    return found
