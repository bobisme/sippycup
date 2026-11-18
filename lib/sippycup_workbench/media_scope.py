"""Owner-approved media networks and media ports in a target profile.

Most SIP platforms put media servers on a pool of addresses (a /27 or a /24)
that differs from the signaling address, and owners approve that pool as a
range. A target profile carries it as an optional, MEDIA-ONLY rule::

    media:
      networks: [198.51.100.0/27]       # where RTP may come from and go to
      port_range: {start: 10000, end: 20000}   # the far end's RTP ports

Separation (the safety rule): ``media.networks`` widens only where MEDIA may
flow. Signaling is still bound to ``target.host``, which must itself be one
of the literal ``target.approved_addresses``; nothing in this module, and no
caller, treats an address inside a media network as a signaling target.

Breadth rule (refused by ``rehearse``, so no packet is sent):

* each entry is a network in CIDR form with no host bits set (or a literal);
* each network holds at most :data:`MAX_MEDIA_ADDRESSES` (1024) addresses,
  that is IPv4 /22 or narrower and IPv6 /118 or narrower, and all networks
  together hold at most 1024 addresses; at most :data:`MAX_MEDIA_NETWORKS`
  networks. 1024 is also the most the packet oracle's literal allowlist can
  carry, so every admitted media address is still checked offline;
* no network may contain an unspecified, multicast, reserved, or broadcast
  address (0.0.0.0/8, 224.0.0.0/4, 240.0.0.0/4, ::, ff00::/8).

A media-server pool that an owner really controls is a few dozen to a few
hundred addresses; anything wider is far more likely a copied "any" or a
whole provider range, and the error tells the operator what to ask for.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

MAX_MEDIA_ADDRESSES = 1024
MAX_MEDIA_NETWORKS = 16
NETWORKS_FIELD = "media.networks"
PORTS_FIELD = "media.port_range"

_FORBIDDEN = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("ff00::/8"),
)

ASK_OWNER = (
    "ask the owner for the exact media-server pool(s): one or more ranges of at most "
    f"{MAX_MEDIA_ADDRESSES} addresses each (IPv4 /22 or narrower, for example 198.51.100.0/27), "
    "or the literal media addresses"
)


def _minimum_prefix(version: int) -> int:
    bits = 32 if version == 4 else 128
    return bits - (MAX_MEDIA_ADDRESSES.bit_length() - 1)


def validate_networks(value: Any, errors: list[str], *, indexed: bool = True) -> list[str] | None:
    """Canonical media networks, or ``None`` with every problem in ``errors``.

    ``indexed=False`` names entries by value only (scope check validates a
    filtered list whose positions differ from the scope file's).
    """
    if not isinstance(value, list) or not value:
        errors.append(f"{NETWORKS_FIELD} must be a non-empty list of CIDR networks; {ASK_OWNER}")
        return None
    if len(value) > MAX_MEDIA_NETWORKS:
        errors.append(f"{NETWORKS_FIELD} lists {len(value)} networks, more than {MAX_MEDIA_NETWORKS}; {ASK_OWNER}")
        return None
    problems: list[str] = []
    result: list[str] = []
    total = 0
    for index, item in enumerate(value):
        where = f"{NETWORKS_FIELD}[{index}]" if indexed else "media network"
        if not isinstance(item, str):
            problems.append(f"{where} must be a string such as 198.51.100.0/27")
            continue
        try:
            network = ipaddress.ip_network(item.strip(), strict=True)
        except ValueError:
            try:
                loose = ipaddress.ip_network(item.strip(), strict=False)
                problems.append(f"{where} {item!r} has host bits set; write the network address {loose}")
            except ValueError:
                problems.append(f"{where} {item!r} is not a CIDR network or literal IP address")
            continue
        if network.prefixlen < _minimum_prefix(network.version):
            problems.append(
                f"{where} {network} holds {network.num_addresses} addresses, more than the "
                f"{MAX_MEDIA_ADDRESSES} a media network may hold (IPv{network.version} "
                f"/{_minimum_prefix(network.version)} or narrower); {ASK_OWNER}"
            )
            continue
        bad = next(
            (forbidden for forbidden in _FORBIDDEN
             if forbidden.version == network.version and network.overlaps(forbidden)),
            None,
        )
        if bad is not None or (network.version == 4 and ipaddress.ip_address("255.255.255.255") in network):
            problems.append(
                f"{where} {network} contains unspecified, multicast, reserved, or broadcast addresses "
                f"({bad or '255.255.255.255'}); no media server lives there; {ASK_OWNER}"
            )
            continue
        text = str(network)
        if text in result:
            problems.append(f"{where} {text} is listed twice")
            continue
        total += network.num_addresses
        result.append(text)
    if not problems and total > MAX_MEDIA_ADDRESSES:
        problems.append(
            f"{NETWORKS_FIELD} together hold {total} addresses, more than {MAX_MEDIA_ADDRESSES}; {ASK_OWNER}"
        )
    if problems:
        errors.extend(problems)
        return None
    return result


def validate_ports(value: Any, errors: list[str]) -> tuple[int, int] | None:
    """The far end's approved RTP port range ``(start, end)``, inclusive."""
    if not isinstance(value, dict) or set(value) != {"start", "end"}:
        errors.append(f"{PORTS_FIELD} must be a mapping with exactly start and end")
        return None
    start, end = value.get("start"), value.get("end")
    if type(start) is not int or type(end) is not int or not 1 <= start <= end <= 65535:
        errors.append(f"{PORTS_FIELD} start and end must be ports from 1 to 65535 with start <= end")
        return None
    return start, end


@dataclass(frozen=True)
class MediaScope:
    """Where media may flow for one profile: literal addresses, networks, ports."""

    addresses: tuple[str, ...]
    networks: tuple[str, ...] = ()
    ports: tuple[int, int] | None = None

    def rule(self, address: str | None) -> tuple[str, str | None] | None:
        """``("approved-address", None)`` or ``("media-network", cidr)``; None when not admitted."""
        try:
            parsed = ipaddress.ip_address(str(address))
        except ValueError:
            return None
        if any(_same(parsed, item) for item in self.addresses):
            return "approved-address", None
        for text in self.networks:
            network = ipaddress.ip_network(text)
            if network.version == parsed.version and parsed in network:
                return "media-network", text
        return None

    def admits(self, address: str | None) -> bool:
        return self.rule(address) is not None

    def enumerate(self) -> list[str]:
        """Every literal address media may use (the oracle allowlist takes literals only)."""
        found: list[str] = []
        for item in self.addresses:
            text = str(ipaddress.ip_address(item))
            if text not in found:
                found.append(text)
        for text in self.networks:
            network = ipaddress.ip_network(text)
            hosts = [network.network_address] if network.num_addresses == 1 else list(network)
            for address in hosts:
                if str(address) not in found:
                    found.append(str(address))
        return found

    def as_dict(self) -> dict[str, Any]:
        return {
            "approvedAddresses": list(self.addresses),
            "mediaNetworks": list(self.networks),
            "mediaPorts": None if self.ports is None else {"start": self.ports[0], "end": self.ports[1]},
        }


def _same(parsed: Any, text: str) -> bool:
    try:
        return ipaddress.ip_address(str(text)) == parsed
    except ValueError:
        return False


def profile_media(document: Any) -> tuple[tuple[str, ...], tuple[int, int] | None]:
    """``(media networks, media port range)`` from a profile; empty when absent or invalid.

    Callers run ``rehearse`` first, which refuses an invalid section; this
    reader never widens anything on malformed input, it just returns nothing.
    """
    media = document.get("media") if isinstance(document, dict) else None
    if not isinstance(media, dict):
        return (), None
    scratch: list[str] = []
    networks = validate_networks(media["networks"], scratch) if "networks" in media else None
    ports = validate_ports(media["port_range"], scratch) if "port_range" in media else None
    return tuple(networks or ()), ports


def profile_scope(document: Any) -> MediaScope:
    """The media scope of a profile: its literal approved addresses plus its media rule."""
    target = document.get("target") if isinstance(document, dict) else None
    approved = target.get("approved_addresses") if isinstance(target, dict) else None
    addresses: list[str] = []
    for item in approved if isinstance(approved, list) else []:
        try:
            addresses.append(str(ipaddress.ip_address(str(item))))
        except ValueError:
            continue
    networks, ports = profile_media(document)
    return MediaScope(tuple(addresses), networks, ports)


def capture_terms(networks: Iterable[str]) -> str:
    """``net A or net B`` for a tcpdump filter; empty when there are none."""
    return " or ".join(f"net {ipaddress.ip_network(item)}" for item in networks)


def describe(networks: Sequence[str]) -> str:
    """``198.51.100.0/27 (32 addresses), ...`` for operator output."""
    parts = []
    for text in networks:
        count = ipaddress.ip_network(text).num_addresses
        parts.append(f"{text} ({count} address{'es' if count != 1 else ''})")
    return ", ".join(parts)
