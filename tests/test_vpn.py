import json
import subprocess
import threading

import pytest

from pingo.crypto import PacketError
from pingo.vpn import IP_PACKET, MTU, VPN, Routes, validate_packet

from .helpers import connected, ipv4


class FakeIP:
    def __init__(self, fail_route=None, existing=None, rules=None):
        self.commands = []
        self.fail_route = fail_route
        self.existing = existing or []
        self.rules = (
            rules
            if rules is not None
            else [
                {"priority": 0, "src": "all", "table": "local"},
                {"priority": 32766, "src": "all", "table": "main"},
                {"priority": 32767, "src": "all", "table": "default"},
            ]
        )

    def __call__(self, args):
        self.commands.append(args)
        if args[:4] == ["-j", "-4", "route", "get"]:
            return json.dumps([{"dev": "eth0", "gateway": "192.0.2.1", "prefsrc": "192.0.2.10"}])
        if args[:4] == ["-j", "-4", "rule", "show"]:
            return json.dumps(self.rules)
        if args[:4] == ["-j", "-4", "route", "show"]:
            return json.dumps(self.existing)
        if args[:3] == ["-4", "route", "add"] and args[3] == self.fail_route:
            raise subprocess.CalledProcessError(2, ["ip", *args], stderr="route exists")
        return ""


def test_default_route_pins_endpoint_first_and_reverses_cleanup():
    ip = FakeIP()
    with Routes("192.0.2.20", "pingo0", "10.77.0.1/30", default=True, runner=ip):
        additions = [cmd for cmd in ip.commands if cmd[:3] == ["-4", "route", "add"]]
        assert [cmd[3] for cmd in additions] == ["192.0.2.20/32", "0.0.0.0/1", "128.0.0.0/1"]
        assert additions[0][4:] == ["via", "192.0.2.1", "dev", "eth0", "src", "192.0.2.10"]
        assert ["link", "set", "dev", "pingo0", "mtu", str(MTU)] in ip.commands
    deletions = [cmd for cmd in ip.commands if cmd[:3] == ["-4", "route", "del"]]
    assert [cmd[3] for cmd in deletions] == ["128.0.0.0/1", "0.0.0.0/1", "192.0.2.20/32"]
    assert not any("replace" in cmd for cmd in ip.commands)


def test_setup_failure_rolls_back_added_routes():
    ip = FakeIP(fail_route="128.0.0.0/1")
    with pytest.raises(subprocess.CalledProcessError):
        with Routes("192.0.2.20", "pingo0", "10.77.0.1/30", default=True, runner=ip):
            pass
    deletions = [cmd[3] for cmd in ip.commands if cmd[:3] == ["-4", "route", "del"]]
    assert deletions == ["0.0.0.0/1", "192.0.2.20/32"]
    assert ["-4", "address", "del", "10.77.0.1/30", "dev", "pingo0"] in ip.commands


def test_runtime_failure_rolls_back():
    ip = FakeIP()
    with pytest.raises(RuntimeError):
        with Routes("192.0.2.20", "pingo0", "10.77.0.1/30", routes=["192.168.50.0/24"], runner=ip):
            raise RuntimeError("runtime")
    assert [
        "-4",
        "route",
        "del",
        "192.0.2.20/32",
        "via",
        "192.0.2.1",
        "dev",
        "eth0",
        "src",
        "192.0.2.10",
    ] in ip.commands


def test_existing_endpoint_route_is_preserved():
    ip = FakeIP(existing=[{"dev": "eth0", "gateway": "192.0.2.1"}])
    with Routes("192.0.2.20", "pingo0", "10.77.0.1/30", default=True, runner=ip):
        pass
    assert not any("192.0.2.20/32" in cmd for cmd in ip.commands if "del" in cmd)


def test_custom_rules_and_conflicting_host_route_refused():
    for ip in (FakeIP(rules=[{"table": 100}]), FakeIP(existing=[{"dev": "wrong"}])):
        with pytest.raises(ValueError):
            with Routes("192.0.2.20", "pingo0", "10.77.0.1/30", default=True, runner=ip):
                pass
        assert not any(cmd[:3] == ["-4", "route", "add"] for cmd in ip.commands)


@pytest.mark.parametrize(
    "routes", [["0.0.0.0/0"], ["192.168.1.1/24"], ["10.0.0.0/8", "10.0.0.0/8"]]
)
def test_bad_route_inputs(routes):
    with pytest.raises(ValueError):
        Routes("192.0.2.20", "pingo0", "10.77.0.1/30", routes=routes)


def test_tun_subnet_must_not_capture_outer_endpoint():
    with pytest.raises(ValueError, match="outer peer"):
        Routes("192.0.2.20", "pingo0", "192.0.2.21/24")


class FakeTun:
    def __init__(self, packets=()):
        self.packets = list(packets)
        self.written = []
        self.received = threading.Event()

    def read(self, timeout=0.2):
        if self.packets:
            return self.packets.pop(0)
        return None

    def write(self, packet):
        self.written.append(packet)
        self.received.set()


@pytest.mark.parametrize(
    "reply_source,allowed",
    [
        ("10.77.0.2", ["10.77.0.0/30"]),
        ("198.51.100.42", ["0.0.0.0/0"]),
        ("192.168.50.7", ["10.77.0.0/30", "192.168.50.0/24"]),
    ],
)
def test_encrypted_vpn_packet_round_trip(reply_source, allowed):
    a_packet = ipv4(b"hello", source="10.77.0.1", destination="10.77.0.2", protocol=17)
    b_packet = ipv4(b"reply", source=reply_source, destination="10.77.0.1", protocol=17)
    with connected(mode="vpn") as (client, server, *_):
        a, b = FakeTun(), FakeTun()
        VPN(client, a, allowed)
        VPN(server, b, ["10.77.0.0/30"])
        client.send(IP_PACKET + a_packet)
        server.send(IP_PACKET + b_packet)
        assert a.received.wait(1) and b.received.wait(1)
        assert a.written == [b_packet] and b.written == [a_packet]


@pytest.mark.parametrize(
    "packet", [b"", b"\x60" + b"x" * 39, ipv4(b"x" * 1000), b"\x44" + b"x" * 19, ipv4(b"x")[:-1]]
)
def test_invalid_vpn_packets(packet):
    with pytest.raises(PacketError):
        validate_packet(packet)


def test_peer_source_allowlist():
    with connected(mode="vpn") as (_, server, *_):
        vpn = VPN(server, FakeTun(), ["10.77.0.0/30"])
        with pytest.raises(PacketError, match="source"):
            vpn.receive(IP_PACKET + ipv4(source="192.0.2.10"))
        with pytest.raises(PacketError):
            vpn.receive(b"wrong kind")


def test_cleanup_failure_is_visible(caplog):
    ip = FakeIP()
    routes = Routes("192.0.2.20", "pingo0", "10.77.0.1/30", default=True, runner=ip)
    routes.__enter__()
    original = routes.runner

    def fail(args):
        if args[:3] == ["-4", "route", "del"]:
            raise OSError("permission denied")
        return original(args)

    routes.runner = fail
    with pytest.raises(OSError, match="cleanup incomplete"):
        routes.close()
    assert "ip -4 route del" in caplog.text
