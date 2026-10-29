"""Enumerate assigned IPv4 addresses on physical, virtual and loopback adapters."""

import ipaddress
import socket

import psutil


def local_ipv4():
    try:
        addresses = psutil.net_if_addrs()
    except psutil.Error as exc:
        raise OSError(str(exc)) from exc
    try:
        stats = psutil.net_if_stats()
    except (OSError, psutil.Error):
        stats = {}
    rows = []
    for name, entries in addresses.items():
        for entry in entries:
            if entry.family != socket.AF_INET:
                continue
            address = ipaddress.IPv4Address(entry.address)
            if address.is_unspecified:
                continue
            adapter = stats.get(name)
            row = {
                "name": name,
                "address": str(address),
                "netmask": entry.netmask,
                "up": adapter.isup if adapter else None,
                "loopback": address.is_loopback,
                "link_local": address.is_link_local,
            }
            if row not in rows:
                rows.append(row)
    return sorted(rows, key=lambda r: (r["loopback"], r["up"] is False, r["name"], r["address"]))
