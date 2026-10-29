"""Local setup diagnostics. These checks never send a packet to the peer."""

import ipaddress
import shutil
import socket
import tempfile
from pathlib import Path

from .icmp import RawICMP
from .interfaces import local_ipv4

PRIVATE = tuple(ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
DOCUMENTATION = tuple(
    ipaddress.IPv4Network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
SHARED = ipaddress.IPv4Network("100.64.0.0/10")


def result(name, status, detail):
    return {"name": name, "status": status, "detail": detail}


def address_checks(peer, bind):
    peer, bind = ipaddress.IPv4Address(peer), ipaddress.IPv4Address(bind)
    checks = []
    if peer == bind and not bind.is_unspecified:
        checks.append(
            result(
                "Endpoint addresses",
                "fail",
                "Both endpoints have the same IPv4. "
                "Enter the other computer's address as the peer.",
            )
        )
    elif peer.is_loopback or bind.is_loopback:
        checks.append(
            result(
                "Endpoint addresses",
                "warn",
                "127.x.x.x stays on this computer. "
                "Use each computer's reachable IPv4 for a real peer.",
            )
        )
    elif any(peer in net or bind in net for net in DOCUMENTATION):
        checks.append(
            result(
                "Endpoint addresses",
                "warn",
                "An endpoint uses an example-only IPv4 (192.0.2.x, 198.51.100.x or 203.0.113.x). "
                "Replace example addresses before connecting on a real network.",
            )
        )
    if peer in SHARED:
        detail = (
            "The peer uses shared address space (100.64.0.0/10), often used by carrier NAT. "
            "It is not publicly routed; both peers need a shared network that routes this address."
        )
    elif any(peer in net for net in PRIVATE):
        detail = (
            "The peer has a private IPv4. It needs a reachable LAN or routed private network; "
            "a private address at another home is not reachable over the Internet. Guest Wi-Fi "
            "and client isolation can also block peers on the same Wi-Fi."
        )
    elif peer.is_link_local:
        detail = (
            "169.254.x.x is link-local and normally works only on the same network link. "
            "Check the adapter and DHCP if this address was unexpected."
        )
    else:
        detail = (
            "Both endpoints need directly reachable IPv4 addresses. Pingo has no NAT traversal. "
            "A router's public IPv4 or TCP/UDP port forwarding alone does not provide inbound "
            "ICMP to this computer. NAT may rewrite Pingo's ICMP identifier."
        )
    checks.append(result("Address reachability and NAT", "manual", detail))
    return checks


def route_source(peer, bind):
    # UDP connect selects a local route/source without sending a UDP datagram.
    # ICMP may be subject to different policy; this is not a connectivity test.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        sock.bind((bind, 0))
        sock.connect((peer, 9))
        return sock.getsockname()[0]


def local_network_checks(peer, bind):
    checks = []
    try:
        source = route_source(peer, bind)
        if source == peer:
            checks.append(
                result(
                    "Local route",
                    "fail",
                    f"The route to {peer} points back to this computer. "
                    "Choose the remote endpoint.",
                )
            )
        else:
            alternatives = []
            if bind == "0.0.0.0":
                try:
                    for adapter in local_ipv4():
                        if adapter["up"] is False or not adapter["netmask"]:
                            continue
                        network = ipaddress.IPv4Network(
                            f"{adapter['address']}/{adapter['netmask']}", strict=False
                        )
                        if ipaddress.IPv4Address(peer) in network and adapter["address"] != source:
                            alternatives.append(f"{adapter['name']} ({adapter['address']})")
                except (OSError, RuntimeError, ValueError):
                    pass  # Adapter inventory is advisory; preserve the actual route result.
            checks.append(
                result(
                    "Local route",
                    "warn" if alternatives else "pass",
                    f"The OS selected source {source} for {peer}. "
                    "This does not prove ICMP delivery. If this is an unexpected adapter or "
                    "another VPN, check its routes and policies. "
                    + (
                        "A different adapter shares the peer's subnet: "
                        + ", ".join(alternatives)
                        + ". A VPN or preferred route may be overriding the LAN route. "
                        "The other computer must expect the source IPv4 it actually receives. "
                        "Review VPN routing before changing peer settings."
                        if alternatives else ""
                    ),
                )
            )
    except OSError as exc:
        checks.append(
            result(
                "Local route",
                "warn",
                f"Could not select a local route/source: {exc}. Check Wi-Fi/Ethernet, other VPNs, "
                "and 'This computer's IPv4'; an old DHCP address may no longer be assigned here. "
                "0.0.0.0 lets the OS choose an interface. ICMP policy can differ from this check.",
            )
        )
    try:
        carrier = RawICMP(peer, bind)
        carrier.close()
        checks.append(
            result(
                "ICMP socket and local address",
                "pass",
                "Opened and bound the ICMP carrier without sending packets. Capture permissions "
                "were checked where required. Firewall and peer reachability remain unverified.",
            )
        )
    except (OSError, ValueError, RuntimeError) as exc:
        checks.append(
            result(
                "ICMP socket and local address",
                "fail",
                f"Cannot open/bind the ICMP carrier: {exc}. Run as Administrator/root and select "
                "an IPv4 assigned to this computer, or 0.0.0.0. macOS needs BPF/libpcap access.",
            )
        )
    return checks


def storage_checks(config):
    directory = Path(config.receive_dir)
    ancestor = directory
    try:
        while not ancestor.exists() and ancestor != ancestor.parent:
            ancestor = ancestor.parent
        with tempfile.TemporaryFile(dir=ancestor) as stream:
            stream.write(b"Pingo setup check")
            stream.flush()
        free = shutil.disk_usage(ancestor).free
        checks = [result("Receive folder", "pass", f"Writable parent verified for {directory}.")]
        checks.append(
            result(
                "Receive disk space",
                "warn" if free < config.max_file_bytes else "pass",
                f"{free // (1024 * 1024):,} MiB free; file limit "
                f"{config.max_file_bytes // (1024 * 1024):,} MiB; directory quota "
                f"{config.max_receive_bytes // (1024 * 1024):,} MiB. "
                "Partials and checkpoints use space/quota. Clear old received files when full; "
                "the sender and receiver may have different limits.",
            )
        )
        return checks
    except OSError as exc:
        return [result("Receive folder", "fail", f"Cannot write to {directory}: {exc}")]


def vpn_checks(profile):
    checks = []
    tunnel = ipaddress.IPv4Interface(profile["address"])
    peer = ipaddress.IPv4Address(profile["peer"])
    bind = ipaddress.IPv4Address(profile["bind"])
    if peer in tunnel.network or (not bind.is_unspecified and bind in tunnel.network):
        checks.append(
            result(
                "VPN endpoint overlap (VPN only)",
                "fail",
                "The tunnel subnet contains an outer endpoint address. Choose a different tunnel "
                "subnet so ICMP traffic stays outside the tunnel.",
            )
        )
    if profile["vpn_listen"] and (profile["default_route"] or profile["kill_switch"]):
        checks.append(
            result(
                "VPN responder settings (VPN only)",
                "fail",
                "Responders must not enable a default route or client kill switch.",
            )
        )
    if profile["default_route"]:
        allowed = [ipaddress.IPv4Network(n) for n in profile["allowed_source"]]
        if not any(n.prefixlen == 0 for n in allowed):
            checks.append(
                result(
                    "VPN reply sources (VPN only)",
                    "warn",
                    "Default routing usually needs allowed peer source 0.0.0.0/0 for Internet "
                    "replies. This trusts your peer to supply any IPv4 source.",
                )
            )
        if profile["kill_switch"] is False or profile["no_dns"]:
            checks.append(
                result(
                    "VPN traffic protection (VPN only)",
                    "warn",
                    "The kill switch or tunnel DNS is disabled. Traffic or DNS may use the "
                    "ordinary network. Default routing covers IPv4 only; an enabled kill switch "
                    "blocks outside IPv6.",
                )
            )
    checks.append(
        result(
            "VPN routing and exit (VPN only)",
            "manual",
            "Choose a tunnel subnet that does not overlap either LAN or another VPN. Peers need "
            "different tunnel IPs on the same subnet. Routed networks need forwarding, firewall "
            "rules and a return route or NAT on the exit; Pingo does not configure those. "
            "Internet access needs working exit DNS. A handshake cannot verify the exit "
            "or large packet delivery.",
        )
    )
    return checks
