"""Campaign capture scope: which packets a campaign capture keeps, and how to read them.

The capture filter is a safety control (the traffic watchdog counts only what
tcpdump writes) and an evidence boundary (only authorized traffic is kept),
so its rule is stated once here and used by the planner, the runtime
validator, and execution:

* signaling: for each frozen destination address a used step names, its
  signaling transport and port, plus UDP in the authorized media port range
  (``(host A and (udp port 5060 or udp portrange S-E))``); this is the
  original filter, unchanged;
* media: UDP with an endpoint port inside ``authorization.mediaPorts`` and an
  endpoint address inside an authorized media network (``authorization.networks``
  and the optional media-only ``authorization.mediaNetworks``), for every such
  network that the signaling terms do not already cover
  (``(udp portrange S-E and (host M or net N))``).

Nothing else is captured: no TCP outside the signaling terms, no UDP outside
the media port range, and no address outside the authorization. The capture
can therefore never become "all UDP".

This module also locates the IP header in each PCAP record for the link
types tcpdump writes on Linux (Ethernet on ``lo``, Linux cooked SLL/SLL2 on
``any``, raw IP on tunnels), so payload stripping, the watchdog's media
count, and the privacy linter read the same packets the same way.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Iterable, Mapping, Sequence

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276
SUPPORTED_LINKTYPES = frozenset(
    {LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL,
     LINKTYPE_IPV4, LINKTYPE_IPV6, LINKTYPE_LINUX_SLL2}
)


def _sort_key(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> tuple[int, int, int]:
    return network.version, int(network.network_address), network.prefixlen


def _address_key(text: str) -> tuple[int, int]:
    address = ipaddress.ip_address(text)
    return address.version, int(address)


def signaling_filter(steps: Sequence[Mapping[str, Any]], media_ports: Mapping[str, int]) -> str:
    """The original per-destination filter (frozen into every plan)."""
    scopes: dict[str, set[tuple[str, int]]] = {}
    for step in steps:
        destination = step["destination"]
        for address in destination["addresses"]:
            scopes.setdefault(address, set()).add((destination["transport"], destination["port"]))
    rendered = []
    for address in sorted(scopes, key=_address_key):
        terms = [
            f"{'udp' if transport == 'udp' else 'tcp'} port {port}"
            for transport, port in sorted(scopes[address])
        ]
        terms.append(f"udp portrange {media_ports['start']}-{media_ports['end']}")
        rendered.append(f"(host {address} and ({' or '.join(terms)}))")
    return " or ".join(rendered)


def media_capture_networks(
    steps: Sequence[Mapping[str, Any]],
    networks: Iterable[str],
    media_networks: Iterable[str] = (),
) -> list[str]:
    """Authorized media networks the signaling terms do not already capture.

    A single-address network equal to a captured destination address is
    already covered (its host term includes the media port range).
    """
    captured = {
        ipaddress.ip_address(address)
        for step in steps
        for address in step["destination"]["addresses"]
    }
    found: dict[str, Any] = {}
    for text in [*networks, *media_networks]:
        network = ipaddress.ip_network(text, strict=True)
        if network.num_addresses == 1 and network.network_address in captured:
            continue
        found[str(network)] = network
    return [str(item) for item in sorted(found.values(), key=_sort_key)]


def media_term(networks: Sequence[str], media_ports: Mapping[str, int]) -> str:
    """``(udp portrange S-E and (host M or net N))``; empty without networks."""
    if not networks:
        return ""
    hosts = []
    for text in networks:
        network = ipaddress.ip_network(text, strict=True)
        hosts.append(
            f"host {network.network_address}" if network.num_addresses == 1 else f"net {network}"
        )
    return f"(udp portrange {media_ports['start']}-{media_ports['end']} and ({' or '.join(hosts)}))"


def full_filter(
    steps: Sequence[Mapping[str, Any]],
    media_ports: Mapping[str, int],
    networks: Iterable[str],
    media_networks: Iterable[str] = (),
) -> str:
    """Signaling terms plus the authorized media term (see the module rule)."""
    base = signaling_filter(steps, media_ports)
    term = media_term(media_capture_networks(steps, networks, media_networks), media_ports)
    return f"{base} or {term}" if term else base


def frozen_filter(
    steps: Sequence[Mapping[str, Any]],
    media_ports: Mapping[str, int],
    networks: Iterable[str],
    media_networks: Sequence[str] | None,
) -> str:
    """The filter a plan freezes.

    A plan without ``mediaNetworks`` (every plan frozen before the field
    existed, and every manifest that omits it) keeps the original signaling
    filter byte for byte; a plan with it freezes the full filter.
    """
    if media_networks is None:
        return signaling_filter(steps, media_ports)
    return full_filter(steps, media_ports, networks, media_networks)


def execution_filter(plan: Mapping[str, Any]) -> tuple[str, str]:
    """``(filter, source)`` that execution hands to tcpdump.

    ``source`` is ``plan`` when the frozen filter already holds the media
    term (or nothing outside it is authorized for media), and
    ``plan+authorized-media`` when an older plan's frozen filter is extended
    with the media term over its own ``authorization.networks``. The
    extension names only networks and ports the plan authorizes, so it never
    widens what may be captured beyond the reviewed authorization; it makes
    the capture and the watchdog see the media the softphone runner already
    admits there.
    """
    authorization = plan["authorization"]
    frozen = plan["captureFilter"]
    if "mediaNetworks" in authorization:
        return frozen, "plan"
    term = media_term(
        media_capture_networks(plan["steps"], authorization["networks"]),
        authorization["mediaPorts"],
    )
    if not term:
        return frozen, "plan"
    return f"{frozen} or {term}", "plan+authorized-media"


def ip_offset(linktype: int, packet: bytes) -> tuple[int, int] | None:
    """``(ip_version, offset)`` of the IP header in one record, or ``None``."""
    if linktype == LINKTYPE_ETHERNET:
        if len(packet) < 14:
            return None
        offset = 14
        ether_type = int.from_bytes(packet[12:14], "big")
        if ether_type == 0x8100 and len(packet) >= 18:
            ether_type = int.from_bytes(packet[16:18], "big")
            offset = 18
        version = {0x0800: 4, 0x86DD: 6}.get(ether_type)
        return (version, offset) if version else None
    if linktype == LINKTYPE_LINUX_SLL:
        if len(packet) < 16:
            return None
        version = {0x0800: 4, 0x86DD: 6}.get(int.from_bytes(packet[14:16], "big"))
        return (version, 16) if version else None
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(packet) < 20:
            return None
        version = {0x0800: 4, 0x86DD: 6}.get(int.from_bytes(packet[0:2], "big"))
        return (version, 20) if version else None
    if linktype == LINKTYPE_NULL:
        if len(packet) < 4:
            return None
        family = int.from_bytes(packet[0:4], "little") or int.from_bytes(packet[0:4], "big")
        version = 4 if family == 2 else 6 if family in (10, 24, 28, 30) else None
        return (version, 4) if version else None
    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        if not packet:
            return None
        version = packet[0] >> 4
        return (version, 0) if version in (4, 6) else None
    return None


def udp_ports(linktype: int, packet: bytes) -> tuple[int, int, int] | None:
    """``(udp_header_offset, source_port, destination_port)`` for a UDP record."""
    located = ip_offset(linktype, packet)
    if located is None:
        return None
    version, network = located
    if version == 4:
        if len(packet) < network + 20 or packet[network + 9] != 17:
            return None
        udp = network + (packet[network] & 0x0F) * 4
    else:
        if len(packet) < network + 40 or packet[network + 6] != 17:
            return None
        udp = network + 40
    if len(packet) < udp + 8:
        return None
    return (
        udp,
        int.from_bytes(packet[udp : udp + 2], "big"),
        int.from_bytes(packet[udp + 2 : udp + 4], "big"),
    )


def ip_addresses(linktype: int, packet: bytes) -> tuple[str, str] | None:
    """Source and destination address of one record."""
    located = ip_offset(linktype, packet)
    if located is None:
        return None
    version, network = located
    if version == 4 and len(packet) >= network + 20:
        return (
            str(ipaddress.ip_address(packet[network + 12 : network + 16])),
            str(ipaddress.ip_address(packet[network + 16 : network + 20])),
        )
    if version == 6 and len(packet) >= network + 40:
        return (
            str(ipaddress.ip_address(packet[network + 8 : network + 24])),
            str(ipaddress.ip_address(packet[network + 24 : network + 40])),
        )
    return None


def media_header_length(
    linktype: int,
    packet: bytes,
    media_ports: Mapping[str, int],
    signaling_ports: set[int] | frozenset[int],
) -> int | None:
    """Bytes to keep of a media record (UDP plus the fixed 12-byte RTP header).

    ``None`` when the record is not media: not UDP, a signaling port on either
    side, or neither port inside the media port range.
    """
    found = udp_ports(linktype, packet)
    if found is None:
        return None
    udp, source, destination = found
    if source in signaling_ports or destination in signaling_ports:
        return None
    start, end = media_ports["start"], media_ports["end"]
    if start <= source <= end or start <= destination <= end:
        return min(len(packet), udp + 8 + 12)
    return None


def media_flows(
    data: bytes,
    media_ports: Mapping[str, int],
    signaling_ports: Iterable[int],
) -> tuple[int, dict[tuple[str, str], int]]:
    """``(records, {(source, destination): media records})`` of a classic PCAP.

    Media records are classified exactly as the watchdog and payload
    stripping classify them (:func:`media_header_length`), so a gate can
    compare the capture with what the watchdog counted.
    """
    import struct

    if len(data) < 24:
        raise ValueError("capture is too short")
    if data[:4] == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif data[:4] == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise ValueError("not a classic PCAP")
    linktype = struct.unpack(endian + "I", data[20:24])[0] & 0x0FFFFFFF
    signaling = frozenset(signaling_ports)
    flows: dict[tuple[str, str], int] = {}
    records = 0
    offset = 24
    while offset + 16 <= len(data):
        included = struct.unpack(endian + "I", data[offset + 8 : offset + 12])[0]
        packet = data[offset + 16 : offset + 16 + included]
        offset += 16 + included
        if len(packet) < included:
            raise ValueError("capture record is truncated")
        records += 1
        if media_header_length(linktype, packet, media_ports, signaling) is None:
            continue
        addresses = ip_addresses(linktype, packet)
        if addresses is not None:
            flows[addresses] = flows.get(addresses, 0) + 1
    return records, flows
