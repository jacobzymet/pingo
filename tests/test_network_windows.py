import ctypes
import json
import subprocess

import pytest

from pingo.network import LinuxDNS, LinuxKillSwitch, WindowsDNS, unlock_linux
from pingo.wfp import GUID, KEYS, Filter, WindowsKillSwitch, unlock_windows
from pingo.windows import WindowsRoutes, Wintun


def test_linux_kill_switch_atomic_install_and_normal_cleanup():
    calls = []

    def runner(args, data=None):
        calls.append((args, data))

    with LinuxKillSwitch("192.0.2.20", "pingo0", runner=runner) as guard:
        assert len(calls) == 1
        assert calls[0][0] == ["nft", "-f", "-"]
        rules = calls[0][1]
        assert "policy drop" in rules and "meta nfproto ipv4" in rules
        assert "icmp type { echo-request, echo-reply }" in rules
    assert calls[1][0] == ["nft", "delete", "table", "inet", guard.table]


def test_linux_kill_switch_retained_on_failure_and_targeted_unlock():
    calls = []

    def runner(args, data=None):
        calls.append((args, data))

    guard = LinuxKillSwitch("192.0.2.20", "pingo0", runner=runner)
    with pytest.raises(RuntimeError):
        with guard:
            raise RuntimeError("transport failed")
    assert len(calls) == 1 and guard.active
    with pytest.raises(ValueError):
        unlock_linux("filter", runner=runner)
    unlock_linux(guard.table, runner=runner)
    assert calls[-1][0][-1] == guard.table


def test_linux_dns_setup_failure_reverts_only_owned_link():
    calls = []

    def runner(args, data=None):
        calls.append(args)
        if args[1] == "domain":
            raise OSError("resolved unavailable")

    with pytest.raises(OSError):
        with LinuxDNS("pingo0", ["1.1.1.1"], runner=runner):
            pytest.fail("must not start")
    assert calls[-1] == ["resolvectl", "revert", "pingo0"]


def test_windows_dns_respects_existing_policy_and_cleans_owned_rule():
    calls = []

    def runner(script, payload=None):
        calls.append((script, payload))
        if script.endswith(".Count"):
            return "0"
        if "Add-DnsClientNrptRule" in script:
            return "{owned-rule}"
        return ""

    with WindowsDNS("pingo0", ["1.1.1.1"], runner=runner):
        assert any("Add-DnsClientNrptRule" in script for script, _ in calls)
    assert "Remove-DnsClientNrptRule" in calls[-1][0]
    assert calls[-1][1]["comment"].startswith("Pingo-")
    with pytest.raises(ValueError, match="existing Windows DNS policy"):
        with WindowsDNS("pingo0", ["1.1.1.1"], runner=lambda *_: "1"):
            pytest.fail("must not replace existing DNS policy")


class WindowsIP:
    def __init__(self, fail=None, existing=None):
        self.commands = []
        self.fail = fail
        self.existing = existing

    def __call__(self, script, payload=None):
        self.commands.append((script, payload))
        if "Find-NetRoute" in script:
            return json.dumps({"InterfaceIndex": 4, "NextHop": "192.0.2.1"})
        if "Get-NetAdapter" in script:
            return "12"
        if "@(Get-NetRoute" in script:
            return json.dumps(self.existing or [])
        if script.startswith("New-NetRoute") and payload["prefix"] == self.fail:
            raise subprocess.CalledProcessError(1, script)
        return ""


def test_windows_route_setup_pins_peer_and_rolls_back():
    runner = WindowsIP(fail="128.0.0.0/1")
    with pytest.raises(subprocess.CalledProcessError):
        with WindowsRoutes("192.0.2.20", "pingo0", "10.77.0.1/30", default=True, runner=runner):
            pytest.fail("must not finish")
    added = [
        payload["prefix"]
        for script, payload in runner.commands
        if script.startswith("New-NetRoute")
    ]
    deleted = [
        payload["prefix"]
        for script, payload in runner.commands
        if script.startswith("Remove-NetRoute")
    ]
    assert added == ["192.0.2.20/32", "0.0.0.0/1", "128.0.0.0/1"]
    assert deleted == ["0.0.0.0/1", "192.0.2.20/32"]
    assert any("Remove-NetIPAddress" in script for script, _ in runner.commands)


def test_windows_routes_preserve_existing_matching_peer_route():
    runner = WindowsIP(existing=[{"InterfaceIndex": 4, "NextHop": "192.0.2.1"}])
    with WindowsRoutes("192.0.2.20", "pingo0", "10.77.0.1/30", default=True, runner=runner):
        pass
    assert not any(
        payload.get("prefix") == "192.0.2.20/32"
        for script, payload in runner.commands
        if script.startswith("Remove-NetRoute")
    )


class Function:
    def __init__(self, function):
        self.function = function

    def __call__(self, *args):
        return self.function(*args)


class FakeWintun:
    def __init__(self, existing=False, start=True):
        self.calls = []
        self.buffer = ctypes.create_string_buffer(b"hello")
        self.target = ctypes.create_string_buffer(20)
        funcs = {
            "WintunOpenAdapter": lambda *_: 8 if existing else None,
            "WintunCreateAdapter": lambda *_: 10,
            "WintunCloseAdapter": lambda handle: self.calls.append(("close", handle)),
            "WintunStartSession": lambda *_: 20 if start else None,
            "WintunEndSession": lambda handle: self.calls.append(("end", handle)),
            "WintunGetReadWaitEvent": lambda *_: 30,
            "WaitForSingleObject": lambda *_: 0,
            "WintunReceivePacket": self.receive,
            "WintunReleaseReceivePacket": lambda *_: self.calls.append(("release",)),
            "WintunAllocateSendPacket": lambda *_: ctypes.addressof(self.target),
            "WintunSendPacket": lambda *_: self.calls.append(("send",)),
            "WintunGetAdapterLUID": self.luid,
        }
        for name, func in funcs.items():
            setattr(self, name, Function(func))

    def receive(self, session, pointer):
        ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32))[0] = 5
        return ctypes.addressof(self.buffer)

    def luid(self, adapter, pointer):
        ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint64))[0] = 1234


def test_wintun_packet_ownership_and_shutdown_order(tmp_path):
    path = tmp_path / "wintun.dll"
    path.write_bytes(b"test fake")
    dll = FakeWintun()
    with Wintun("pingo0", path, loader=lambda _: dll) as adapter:
        assert adapter.read() == b"hello"
        assert ("release",) in dll.calls
        adapter.write(b"world")
        assert dll.target.raw.startswith(b"world")
    assert dll.calls[-2:] == [("end", 20), ("close", 10)]
    adapter.close()
    assert dll.calls[-2:] == [("end", 20), ("close", 10)]


def test_wintun_never_attaches_existing_adapter(tmp_path):
    path = tmp_path / "wintun.dll"
    path.write_bytes(b"test fake")
    dll = FakeWintun(existing=True)
    with pytest.raises(FileExistsError):
        Wintun("pingo0", path, loader=lambda _: dll)
    assert dll.calls == [("close", 8)]


class FakeWFP:
    def __init__(self, fail=False):
        self.calls, self.filters = [], []
        self.fail = fail
        names = (
            "FwpmEngineOpen0",
            "FwpmEngineClose0",
            "FwpmTransactionBegin0",
            "FwpmTransactionCommit0",
            "FwpmTransactionAbort0",
            "FwpmFilterAdd0",
            "FwpmFilterDeleteByKey0",
        )
        for name in names:
            setattr(self, name, Function(lambda *args, name=name: self.call(name, args)))

    def call(self, name, args):
        self.calls.append(name)
        if name == "FwpmEngineOpen0":
            ctypes.cast(args[-1], ctypes.POINTER(ctypes.c_void_p))[0] = 12
        if name == "FwpmFilterAdd0":
            item = ctypes.cast(args[1], ctypes.POINTER(Filter)).contents
            self.filters.append((bytes(item.key.data), item.flags, item.action.type, item.count))
            if self.fail:
                return 5
        return 0


def test_wfp_installs_persistent_block_transaction_and_normal_removal():
    dll = FakeWFP()
    adapter = type("Adapter", (), {"dll": FakeWintun(), "adapter": 10})()
    with WindowsKillSwitch("192.0.2.20", adapter, dll=dll):
        assert dll.calls[-1] == "FwpmTransactionCommit0"
        assert len(dll.filters) == 3
        assert all(flags == 1 and action == 0x1001 for _, flags, action, _ in dll.filters)
        assert [key for key, *_ in dll.filters] == [key.bytes_le for key in KEYS]
    assert dll.calls.count("FwpmFilterDeleteByKey0") == 3
    assert dll.calls[-1] == "FwpmEngineClose0"
    assert ctypes.sizeof(GUID) == 16
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        assert ctypes.sizeof(Filter) == 200


def test_wfp_aborts_setup_and_retains_committed_filters_on_failure():
    adapter = type("Adapter", (), {"dll": FakeWintun(), "adapter": 10})()
    failed = FakeWFP(fail=True)
    with pytest.raises(OSError):
        with WindowsKillSwitch("192.0.2.20", adapter, dll=failed):
            pytest.fail("must not commit")
    assert "FwpmTransactionAbort0" in failed.calls
    assert "FwpmTransactionCommit0" not in failed.calls
    dll = FakeWFP()
    with pytest.raises(RuntimeError):
        with WindowsKillSwitch("192.0.2.20", adapter, dll=dll):
            raise RuntimeError("crashed")
    assert "FwpmFilterDeleteByKey0" not in dll.calls
    unlock_windows(dll=dll)
    assert dll.calls.count("FwpmFilterDeleteByKey0") == 3
