"""Linux nonpersistent TUN and reversible IPv4 route setup.

No DNS, firewall, NAT, forwarding, IPv6, or existing routes are modified.
"""

import ipaddress
import json
import logging
import os
import re
import select
import struct
import subprocess
import sys

from .congestion import Congestion
from .crypto import PacketError
from .icmp import checksum
from .transport import Endpoint

LOG = logging.getLogger(__name__)
IP_PACKET = b"\x03"
IP_ACK, IP_DATA = b"\x04", b"\x05"
MTU = 1000


def validate_packet(packet: bytes, allowed_sources=()) -> bytes:
    if not 20 <= len(packet) <= MTU or packet[0] >> 4 != 4:
        raise PacketError("VPN accepts IPv4 packets of 20..1000 bytes")
    ihl = (packet[0] & 15) * 4
    if ihl < 20 or ihl > len(packet) or int.from_bytes(packet[2:4], "big") != len(packet):
        raise PacketError("invalid inner IPv4 length")
    if checksum(packet[:ihl]):
        raise PacketError("invalid inner IPv4 header checksum")
    source = ipaddress.IPv4Address(packet[12:16])
    if allowed_sources and not any(source in network for network in allowed_sources):
        raise PacketError("inner source outside allowed networks")
    return packet


class Tun:
    def __init__(self, name: str):
        if sys.platform != "linux":
            raise OSError("Linux TUN requires /dev/net/tun; use Wintun on Windows")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", name):
            raise ValueError("TUN name must contain 1..15 letters, digits, underscores or hyphens")
        import fcntl

        self.fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
        try:
            # IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL: never attach to a pre-existing interface.
            result = fcntl.ioctl(self.fd, 0x400454CA, struct.pack("16sH22x", name.encode(), 0x9001))
            self.name = result[:16].split(b"\x00", 1)[0].decode("ascii")
        except BaseException:
            os.close(self.fd)
            raise

    def read(self, timeout=0.2):
        if select.select([self.fd], [], [], timeout)[0]:
            return os.read(self.fd, 65535)
        return None

    def write(self, packet):
        try:
            if os.write(self.fd, packet) != len(packet):
                raise OSError("partial TUN packet write")
        except BlockingIOError:
            pass  # Bounded kernel queue; drop under congestion.

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def run_ip(args):
    return subprocess.run(
        ["ip", *args], check=True, capture_output=True, text=True, timeout=5
    ).stdout


class Routes:
    """Only add routes; journal inverses after success, roll back in reverse order."""

    def __init__(
        self, peer: str, interface: str, address: str, routes=(), default=False, runner=run_ip
    ):
        self.peer = str(ipaddress.IPv4Address(peer))
        self.interface = interface
        self.address = str(ipaddress.IPv4Interface(address))
        if ipaddress.IPv4Address(self.peer) in ipaddress.IPv4Interface(self.address).network:
            raise ValueError("TUN subnet must not contain the outer peer address")
        self.routes = [str(ipaddress.IPv4Network(route, strict=True)) for route in routes]
        if any(ipaddress.IPv4Network(route).prefixlen == 0 for route in self.routes):
            raise ValueError("use --default-route for a default route")
        if len(self.routes) > 32 or len(set(self.routes)) != len(self.routes):
            raise ValueError("at most 32 distinct routes are allowed")
        if default:
            self.routes.extend(["0.0.0.0/1", "128.0.0.0/1"])
        if len(set(self.routes)) != len(self.routes):
            raise ValueError("duplicate route")
        self.runner = runner
        self.undo = []

    def _route_add(self, args):
        self.runner(["-4", "route", "add", *args])
        self.undo.append(["-4", "route", "del", *args])

    def __enter__(self):
        try:
            # Inspect before bringing TUN up, so endpoint routing comes from the real network.
            original = json.loads(self.runner(["-j", "-4", "route", "get", self.peer]))
            if len(original) != 1 or "dev" not in original[0]:
                raise ValueError("cannot identify original endpoint route")
            route = original[0]
            if route["dev"] == self.interface or route.get("type") in ("local", "unreachable"):
                raise ValueError("endpoint must be reachable through a separate network interface")
            # Restrict automation to the three ordinary Linux lookup rules.
            rules = json.loads(self.runner(["-j", "-4", "rule", "show"]))
            tables = {255: "local", 254: "main", 253: "default"}
            ordinary = {(0, "local"), (32766, "main"), (32767, "default")}
            observed = set()
            for rule in rules:
                table = tables.get(rule.get("table"), rule.get("table"))
                if (
                    set(rule) - {"priority", "src", "dst", "table", "protocol"}
                    or rule.get("src", "all") != "all"
                    or rule.get("dst", "all") != "all"
                ):
                    raise ValueError(
                        "custom policy routing detected; automatic route setup refused"
                    )
                observed.add((rule.get("priority"), table))
            if len(rules) != 3 or observed != ordinary:
                raise ValueError("custom policy routing detected; automatic route setup refused")
            # Pin endpoint even for selected routes that contain the endpoint address.
            if self.routes:
                existing = json.loads(
                    self.runner(["-j", "-4", "route", "show", "exact", self.peer + "/32"])
                )
                if existing:
                    if (
                        len(existing) != 1
                        or existing[0].get("dev") != route["dev"]
                        or (existing[0].get("gateway") != route.get("gateway"))
                    ):
                        raise ValueError("conflicting endpoint host route")
                else:
                    pin = [self.peer + "/32"]
                    if route.get("gateway"):
                        pin.extend(["via", route["gateway"]])
                    pin.extend(["dev", route["dev"]])
                    if route.get("prefsrc"):
                        pin.extend(["src", route["prefsrc"]])
                    self._route_add(pin)
            self.runner(["link", "set", "dev", self.interface, "mtu", str(MTU)])
            self.runner(["-4", "address", "add", self.address, "dev", self.interface])
            self.undo.append(["-4", "address", "del", self.address, "dev", self.interface])
            self.runner(["link", "set", "dev", self.interface, "up"])
            for network in self.routes:
                self._route_add([network, "dev", self.interface])
            return self
        except BaseException:
            self.close()
            raise

    def close(self):
        failed = []
        while self.undo:
            command = self.undo.pop()
            try:
                self.runner(command)
            except (OSError, subprocess.SubprocessError) as exc:
                failed.append(command)
                LOG.error("route cleanup failed (%s); run: ip %s", exc, " ".join(command))
        if failed:
            raise OSError("route cleanup incomplete; exact recovery commands were logged")

    def __exit__(self, *args):
        self.close()


class VPN:
    def __init__(self, endpoint: Endpoint, tun, allowed_sources, traffic=None):
        self.endpoint = endpoint
        self.tun = tun
        self.allowed_sources = tuple(ipaddress.IPv4Network(net) for net in allowed_sources)
        self.traffic = traffic
        self.congestion = Congestion()
        endpoint.handler = self.receive

    def reset(self):
        self.congestion = Congestion()

    def receive(self, data):
        if data.startswith(IP_ACK):
            if len(data) != 9:
                raise PacketError("invalid VPN acknowledgment")
            self.congestion.acknowledge(int.from_bytes(data[1:], "big"))
            return
        if data.startswith(IP_DATA):
            if len(data) < 29:
                raise PacketError("short VPN datagram")
            packet = validate_packet(data[9:], self.allowed_sources)
            self.tun.write(packet)
            self._trace("rx", packet)
            self.endpoint.send(IP_ACK + data[1:9])
            return
        if not data.startswith(IP_PACKET):
            raise PacketError("unknown VPN frame")
        packet = validate_packet(data[1:], self.allowed_sources)
        self.tun.write(packet)
        self._trace("rx", packet)

    def _trace(self, direction, packet):
        if self.traffic:
            self.traffic.packet(
                direction,
                packet,
                str(ipaddress.IPv4Address(packet[16:20])),
                layer="tun",
                source=str(ipaddress.IPv4Address(packet[12:16])),
                protocol=packet[9],
                window=round(self.congestion.window, 2),
                rtt_ms=round(self.congestion.rtt * 1000, 2),
            )

    def run(self, stop):
        while not stop.is_set():
            self.endpoint.check()
            if not self.endpoint.ready.wait(0.2):
                continue
            if not self.congestion.available():
                stop.wait(0.005)
                continue
            packet = self.tun.read(0.2)
            if packet:
                try:
                    validate_packet(packet)
                except PacketError:
                    continue
                identifier = self.congestion.sent()
                self.endpoint.send(IP_DATA + identifier.to_bytes(8, "big") + packet)
                self._trace("tx", packet)
