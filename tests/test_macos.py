import ctypes as c
import json
import socket
import struct
import subprocess
from types import SimpleNamespace

import pytest

from pingo import cli
from pingo.crypto import PacketError
from pingo.icmp import RawICMP, encode
from pingo.macos import (
    IFCONFIG,
    NETWORKSETUP,
    PFCTL,
    ROUTE,
    CaptureHeader,
    MacCapture,
    MacDNS,
    MacKillSwitch,
    MacRoutes,
    Utun,
    capture_ipv4,
    unlock_macos,
)

from .helpers import ipv4


@pytest.mark.parametrize("link", [0, 1, 12, 101, 108])
def test_capture_decodes_supported_mac_link_headers(link):
    packet = ipv4(encode(b"hello"))
    frame = packet
    if link == 1:
        frame = bytes(12) + b"\x08\x00" + packet + bytes(10)
    elif link in (0, 108):
        frame = struct.pack("=I" if link == 0 else "!I", socket.AF_INET) + packet
    assert capture_ipv4(frame, link) == packet
    assert c.sizeof(CaptureHeader) == 24
    assert CaptureHeader.captured.offset == 16


def test_capture_handles_vlan_and_rejects_truncation_and_unknown_links():
    packet = ipv4(encode(b"hello"))
    frame = bytes(12) + b"\x81\x00\x00\x01\x08\x00" + packet
    assert capture_ipv4(frame, 1) == packet
    for body, link in ((frame[:-2], 1), (b"", 1), (packet, 258), (bytes(4), 0)):
        with pytest.raises(PacketError):
            capture_ipv4(body, link)


class Function:
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *args):
        return self.callback(*args)


class FakePcap:
    def __init__(self, packet, fail_filter=False):
        self.buffer = c.create_string_buffer(bytes(12) + b"\x08\x00" + packet)
        self.header = CaptureHeader()
        self.header.captured = self.header.length = len(self.buffer.raw) - 1
        self.closed, self.freed, self.expression = False, False, None
        callbacks = {
            "pcap_open_live": lambda *_: 1,
            "pcap_compile": self.compile,
            "pcap_setfilter": lambda *_: -1 if fail_filter else 0,
            "pcap_freecode": self.free,
            "pcap_setnonblock": lambda *_: 0,
            "pcap_get_selectable_fd": lambda *_: 42,
            "pcap_datalink": lambda *_: 1,
            "pcap_next_ex": self.next,
            "pcap_geterr": lambda *_: b"filter failed",
            "pcap_close": self.close,
        }
        for name, callback in callbacks.items():
            setattr(self, name, Function(callback))

    def compile(self, handle, program, expression, optimize, mask):
        self.expression = expression.decode()
        return 0

    def free(self, *_):
        self.freed = True

    def next(self, handle, header, data):
        c.cast(header, c.POINTER(c.POINTER(CaptureHeader)))[0] = c.pointer(self.header)
        c.cast(data, c.POINTER(c.c_void_p))[0] = c.addressof(self.buffer)
        return 1

    def close(self, *_):
        self.closed = True


def test_libpcap_receives_requests_with_peer_and_bind_filter():
    library = FakePcap(ipv4(encode(b"test")))
    capture = MacCapture(
        "192.0.2.10", "192.0.2.20", library=library, runner=lambda _: "interface: en0\n"
    )
    try:
        assert capture.recv(0.1) == b"test"
        assert "src host 192.0.2.10" in library.expression
        assert "dst host 192.0.2.20" in library.expression
        assert "icmp[0] = 8" in library.expression
        assert library.freed
    finally:
        capture.close()
    assert library.closed


def test_libpcap_setup_failure_releases_filter_and_capture():
    library = FakePcap(ipv4(encode(b"test")), fail_filter=True)
    with pytest.raises(OSError, match="filter failed"):
        MacCapture("192.0.2.10", library=library, runner=lambda _: "interface: en0")
    assert library.closed and library.freed


def test_raw_carrier_selects_mac_capture_without_consuming_raw_replies(monkeypatch):
    calls = []
    raw = SimpleNamespace(
        bind=lambda *_: None,
        settimeout=lambda *_: None,
        close=lambda: calls.append("raw closed"),
        sendto=lambda *_: None,
    )
    capture = SimpleNamespace(
        recv=lambda timeout: b"captured request", close=lambda: calls.append("capture closed")
    )
    monkeypatch.setattr("pingo.icmp.sys.platform", "darwin")
    monkeypatch.setattr("pingo.icmp.socket.socket", lambda *_: raw)
    monkeypatch.setattr("pingo.macos.MacCapture", lambda *_: capture)
    carrier = RawICMP("192.0.2.10")
    assert carrier.recv() == b"captured request"
    carrier.close()
    assert calls == ["capture closed", "raw closed"]


class FakeUtun:
    def __init__(self):
        self.address, self.sent, self.closed = None, [], False
        self.packet = struct.pack("!I", socket.AF_INET) + b"packet"

    def fileno(self):
        return 3

    def connect(self, address):
        self.address = address

    def getsockopt(self, *_):
        return b"utun17\0"

    def setblocking(self, value):
        assert value is False

    def send(self, packet):
        self.sent.append(packet)
        return len(packet)

    def recv(self, *_):
        return self.packet

    def close(self):
        self.closed = True


@pytest.mark.parametrize("name,unit", [("auto", 0), ("pingo0", 0), ("utun8", 9)])
def test_utun_dynamic_allocation_and_family_framing(monkeypatch, name, unit):
    raw = FakeUtun()

    def ioctl(fd, request, info):
        assert request == 0xC0644E03 and len(info) == 100
        assert info[4:].rstrip(b"\0") == b"com.apple.net.utun_control"
        return struct.pack("=I96s", 7, b"com.apple.net.utun_control")

    monkeypatch.setattr("pingo.macos.select.select", lambda *_: ([raw], [], []))
    with Utun(name, factory=lambda *_: raw, ioctl=ioctl) as tun:
        assert raw.address == (7, unit) and tun.name == "utun17"
        assert tun.read() == b"packet"
        tun.write(b"reply")
        assert raw.sent == [struct.pack("!I", socket.AF_INET) + b"reply"]
        raw.packet = struct.pack("!I", 30) + b"IPv6"
        assert tun.read() is None
    assert raw.closed


def test_utun_failure_closes_only_its_socket():
    raw = FakeUtun()

    def fail(*_):
        raise OSError("adapter unavailable")

    with pytest.raises(OSError):
        Utun("auto", factory=lambda *_: raw, ioctl=fail)
    assert raw.closed
    with pytest.raises(ValueError):
        Utun("../../other", factory=lambda *_: raw, ioctl=fail)


class FakeNetwork:
    def __init__(self, fail=None, flags="<UP,GATEWAY,DONE>"):
        self.calls, self.fail = [], fail
        self.route = f"gateway: 192.0.2.1\ninterface: en0\nflags: {flags}\n"
        self.dns = {"Wi-Fi": [], "Ethernet": ["2001:db8::53"]}
        self.root = 'anchor "com.apple/*" all\n'
        self.anchors, self.interfaces = "", "en0\nlo0 (skip)\n"

    def __call__(self, args, data=None):
        self.calls.append((args, data))
        if self.fail and self.fail(args):
            raise subprocess.CalledProcessError(1, args, stderr="simulated failure")
        if args[:4] == [ROUTE, "-n", "get", "-inet"]:
            return self.route
        if args == [NETWORKSETUP, "-listallnetworkservices"]:
            return "An asterisk denotes a disabled service.\nWi-Fi\nEthernet\n*Disabled\n"
        if args[:2] == [NETWORKSETUP, "-getdnsservers"]:
            servers = self.dns[args[2]]
            return (
                "\n".join(servers) if servers else f"There aren't any DNS Servers set on {args[2]}."
            )
        if args[:2] == [NETWORKSETUP, "-setdnsservers"]:
            self.dns[args[2]] = [] if args[3:] == ["Empty"] else args[3:]
        if args == [PFCTL, "-sr"]:
            return self.root
        if args[0] == PFCTL and "-a" in args and args[-1] == "-sr":
            return "block drop quick all"
        if args == [PFCTL, "-a", "com.apple", "-s", "Anchors"]:
            return self.anchors
        if args == [PFCTL, "-s", "Interfaces", "-v"]:
            return self.interfaces
        if args == [PFCTL, "-E"]:
            return "pf enabled\nToken : 123456789\n"
        return ""


def test_mac_routes_pin_outer_peer_before_tunnel_and_reverse_owned_changes():
    runner = FakeNetwork()
    with MacRoutes("192.0.2.20", "utun17", "10.77.0.1/30", default=True, runner=runner):
        added = [args for args, _ in runner.calls if args[:3] == [ROUTE, "-n", "add"]]
        assert [args[5] for args in added] == [
            "192.0.2.20",
            "10.77.0.0/30",
            "0.0.0.0/1",
            "128.0.0.0/1",
        ]
        assert added[0][-1] == "192.0.2.1"
        assert any(args[:3] == [IFCONFIG, "utun17", "inet"] for args, _ in runner.calls)
    deleted = [args[5] for args, _ in runner.calls if args[:3] == [ROUTE, "-n", "delete"]]
    assert deleted == ["128.0.0.0/1", "0.0.0.0/1", "10.77.0.0/30", "192.0.2.20"]


def test_mac_route_failure_rolls_back_and_preserves_existing_host_route():
    runner = FakeNetwork(fail=lambda args: "add" in args and "128.0.0.0/1" in args)
    with pytest.raises(subprocess.CalledProcessError):
        with MacRoutes("192.0.2.20", "utun17", "10.77.0.1/30", default=True, runner=runner):
            pytest.fail("must roll back")
    assert [ROUTE, "-n", "delete", "-inet", "-host", "192.0.2.20", "192.0.2.1"] in [
        a for a, _ in runner.calls
    ]
    runner = FakeNetwork(flags="<UP,GATEWAY,HOST,DONE>")
    with MacRoutes("192.0.2.20", "utun17", "10.77.0.1/30", default=True, runner=runner):
        pass
    assert not any("-host" in args for args, _ in runner.calls)


@pytest.mark.parametrize("routes", [["0.0.0.0/0"], ["10.0.0.1/24"], ["10.0.0.0/8"] * 2])
def test_mac_route_inputs_are_validated(routes):
    with pytest.raises(ValueError):
        MacRoutes("192.0.2.20", "utun17", "10.77.0.1/30", routes)


def test_mac_dns_restores_auto_and_ipv6_servers_and_respects_external_changes(tmp_path):
    runner = FakeNetwork()
    with MacDNS("utun17", ["1.1.1.1"], runner, tmp_path) as dns:
        assert runner.dns == {"Wi-Fi": ["1.1.1.1"], "Ethernet": ["1.1.1.1"]}
        assert dns.path.exists()
    assert runner.dns == {"Wi-Fi": [], "Ethernet": ["2001:db8::53"]}
    assert not dns.path.exists()
    with MacDNS("utun17", ["1.1.1.1"], runner, tmp_path):
        runner.dns["Wi-Fi"] = ["9.9.9.9"]
    assert runner.dns["Wi-Fi"] == ["9.9.9.9"]


def test_mac_dns_partial_failure_rolls_back_and_crash_journal_recovers(tmp_path):
    runner = FakeNetwork(
        fail=lambda args: (
            args[:3] == [NETWORKSETUP, "-setdnsservers", "Ethernet"] and args[3:] == ["1.1.1.1"]
        )
    )
    with pytest.raises(subprocess.CalledProcessError):
        MacDNS("utun17", ["1.1.1.1"], runner, tmp_path).__enter__()
    assert runner.dns == {"Wi-Fi": [], "Ethernet": ["2001:db8::53"]}
    runner.fail = None
    dns = MacDNS("utun17", ["1.1.1.1"], runner, tmp_path).__enter__()
    unlock_macos(runner, tmp_path)
    assert not dns.path.exists() and runner.dns["Wi-Fi"] == []


def test_mac_pf_uses_only_owned_anchor_and_enable_reference(tmp_path):
    runner = FakeNetwork()
    with MacKillSwitch("192.0.2.20", "utun17", runner, tmp_path) as guard:
        installs = [
            (args, data) for args, data in runner.calls if "-f" in args and "-n" not in args
        ]
        assert len(installs) == 1 and guard.anchor in installs[0][0]
        assert "block drop quick all" in installs[0][1] and "no state" in installs[0][1]
        assert ([PFCTL, "-F", "states"], None) in runner.calls
    assert ([PFCTL, "-a", guard.anchor, "-F", "rules"], None) in runner.calls
    assert ([PFCTL, "-X", "123456789"], None) in runner.calls
    assert not guard.path.exists()
    assert not any("-d" in args or args == [PFCTL, "-F", "all"] for args, _ in runner.calls)


def test_mac_pf_retains_guard_on_failure_and_unlock_is_targeted(tmp_path):
    runner = FakeNetwork()
    guard = MacKillSwitch("192.0.2.20", "utun17", runner, tmp_path)
    with pytest.raises(RuntimeError):
        with guard:
            raise RuntimeError("transport failed")
    assert guard.path.exists() and not any("-X" in args for args, _ in runner.calls)
    unlock_macos(runner, tmp_path)
    assert not guard.path.exists()


@pytest.mark.parametrize("problem", ["root", "ordering", "retained", "skip"])
def test_mac_pf_refuses_unsafe_host_policy_before_mutation(tmp_path, problem):
    runner = FakeNetwork()
    if problem == "root":
        runner.root += "pass out quick all\n"
    elif problem == "ordering":
        runner.anchors = "000.Other\n"
    elif problem == "retained":
        runner.anchors = "000.Pingo_" + "a" * 32
    else:
        runner.interfaces = "en0 (skip)\n"
    with pytest.raises(ValueError):
        MacKillSwitch("192.0.2.20", "utun17", runner, tmp_path).__enter__()
    assert not any("-E" in args or "-f" in args for args, _ in runner.calls)


def test_mac_unlock_rejects_journal_anchor_identity_mismatch(tmp_path):
    path = tmp_path / ("pf-" + "a" * 32 + ".json")
    path.write_text(json.dumps({"anchor": "com.apple/other", "token": "123"}))
    runner = FakeNetwork()
    with pytest.raises(ValueError, match="identity mismatch"):
        unlock_macos(runner, tmp_path)
    assert not runner.calls


def test_mac_cli_unlock_uses_mac_recovery(monkeypatch):
    called = []
    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr("pingo.macos.unlock_macos", lambda: called.append(True))
    assert cli.main(["unlock"]) == 0 and called == [True]


def test_mac_dns_refuses_stale_recovery_before_changing_services(tmp_path):
    runner = FakeNetwork()
    dns = MacDNS("utun17", ["1.1.1.1"], runner, tmp_path).__enter__()
    runner.calls.clear()
    with pytest.raises(ValueError, match="previous Pingo DNS"):
        MacDNS("utun18", ["9.9.9.9"], runner, tmp_path).__enter__()
    assert not runner.calls
    dns.close()


def test_mac_pf_releases_enable_reference_if_journal_cannot_be_saved(tmp_path, monkeypatch):
    runner = FakeNetwork()

    def fail(*_):
        raise OSError("disk full")

    monkeypatch.setattr("pingo.macos.save_state", fail)
    with pytest.raises(OSError, match="disk full"):
        MacKillSwitch("192.0.2.20", "utun17", runner, tmp_path).__enter__()
    assert ([PFCTL, "-X", "123456789"], None) in runner.calls
    assert not any("-f" in args and "-n" not in args for args, _ in runner.calls)


def test_mac_sudo_storage_keeps_original_desktop_owner(monkeypatch, tmp_path):
    from pingo import permissions

    monkeypatch.setattr(permissions.sys, "platform", "darwin")
    monkeypatch.setattr(permissions.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setenv("SUDO_UID", "501")
    monkeypatch.setenv("SUDO_GID", "20")
    calls = []
    monkeypatch.setattr(permissions.os, "chown", lambda *args: calls.append(args), raising=False)
    permissions.preserve_desktop_owner(tmp_path / "file")
    assert calls == [(tmp_path / "file", 501, 20)]
    monkeypatch.setenv("SUDO_UID", "invalid")
    assert permissions.desktop_owner() is None


def test_mac_desktop_storage_and_supported_platform(tmp_path, monkeypatch):
    from pingo import desktop

    monkeypatch.setattr(desktop.sys, "platform", "darwin")
    monkeypatch.setattr(desktop.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(desktop, "desktop_owner", lambda: None)
    assert desktop.data_directory() == tmp_path / "Library/Application Support/Pingo"
    monkeypatch.setattr(desktop, "private_directory", lambda path: path.mkdir(exist_ok=True))
    app = desktop.Desktop(tmp_path / "app")
    from .test_desktop import connection

    profile = connection(app)
    checks = app.check(profile["id"])
    assert (
        next(check for check in checks if check["name"] == "Supported operating system")["status"]
        == "pass"
    )
    assert any(check["name"] == "macOS capture and VPN" for check in checks)
