"""Wintun adapter and journaled Windows IPv4 routing. Requires Administrator."""

import ctypes
import ipaddress
import json
import logging
import re
import subprocess
import sys
from pathlib import Path

LOG = logging.getLogger(__name__)


def powershell(script, payload=None):
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$ErrorActionPreference='Stop'; $p=ConvertFrom-Json ([Console]::In.ReadToEnd()); "
            + script,
        ],
        input=json.dumps(payload or {}),
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    return result.stdout.strip()


class Wintun:
    def __init__(self, name, dll_path, loader=None, runner=powershell):
        if sys.platform != "win32" and loader is None:
            raise OSError("Wintun requires Windows")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", name):
            raise ValueError("adapter name must contain 1..15 letters, digits, '_' or '-'")
        path = Path(dll_path).resolve(strict=True)
        if path.suffix.lower() != ".dll":
            raise ValueError("provide an explicit path to the official wintun.dll")
        if loader is None:
            status = runner(
                "(Get-AuthenticodeSignature -LiteralPath $p.path).Status.ToString()",
                {"path": str(path)},
            )
            if status != "Valid":
                raise OSError("wintun.dll must have a valid Authenticode signature")

            def loader(path):
                return ctypes.WinDLL(str(path), use_last_error=True)

        self.dll = loader(path)
        self.name = name
        self.adapter = self.session = None
        self._bind()
        existing = self.dll.WintunOpenAdapter(name)
        if existing:
            self.dll.WintunCloseAdapter(existing)
            raise FileExistsError("refusing to attach to a pre-existing Wintun adapter")
        self.adapter = self.dll.WintunCreateAdapter(name, "Pingo", None)
        if not self.adapter:
            self._error()
        try:
            self.session = self.dll.WintunStartSession(self.adapter, 0x400000)
            if not self.session:
                self._error()
            self.event = self.dll.WintunGetReadWaitEvent(self.session)
            if not self.event:
                self._error()
            self.kernel = loader("kernel32.dll")
            self.kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            self.kernel.WaitForSingleObject.restype = ctypes.c_uint32
        except BaseException:
            self.close()
            raise

    def _bind(self):
        handle, uint = ctypes.c_void_p, ctypes.c_uint32
        signatures = {
            "WintunOpenAdapter": ([ctypes.c_wchar_p], handle),
            "WintunCreateAdapter": ([ctypes.c_wchar_p, ctypes.c_wchar_p, handle], handle),
            "WintunCloseAdapter": ([handle], None),
            "WintunStartSession": ([handle, uint], handle),
            "WintunEndSession": ([handle], None),
            "WintunGetReadWaitEvent": ([handle], handle),
            "WintunReceivePacket": ([handle, ctypes.POINTER(uint)], handle),
            "WintunReleaseReceivePacket": ([handle, handle], None),
            "WintunAllocateSendPacket": ([handle, uint], handle),
            "WintunSendPacket": ([handle, handle], None),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.dll, name)
            function.argtypes, function.restype = args, result

    @staticmethod
    def _error():
        raise ctypes.WinError(ctypes.get_last_error())

    def read(self, timeout=0.2):
        size = ctypes.c_uint32()
        packet = self.dll.WintunReceivePacket(self.session, ctypes.byref(size))
        if not packet:
            if ctypes.get_last_error() != 259:  # ERROR_NO_MORE_ITEMS
                self._error()
            result = self.kernel.WaitForSingleObject(self.event, int(timeout * 1000))
            if result == 258:
                return None
            if result != 0:
                self._error()
            packet = self.dll.WintunReceivePacket(self.session, ctypes.byref(size))
            if not packet:
                if ctypes.get_last_error() == 259:
                    return None
                self._error()
        try:
            if not 0 < size.value <= 65535:
                raise OSError("invalid Wintun packet length")
            return ctypes.string_at(packet, size.value)
        finally:
            self.dll.WintunReleaseReceivePacket(self.session, packet)

    def write(self, packet):
        if not 0 < len(packet) <= 65535:
            raise ValueError("invalid Wintun packet length")
        target = self.dll.WintunAllocateSendPacket(self.session, len(packet))
        if not target:
            if ctypes.get_last_error() == 111:  # ERROR_BUFFER_OVERFLOW
                return
            self._error()
        ctypes.memmove(target, packet, len(packet))
        self.dll.WintunSendPacket(self.session, target)

    def close(self):
        if self.session:
            self.dll.WintunEndSession(self.session)
            self.session = None
        if self.adapter:
            self.dll.WintunCloseAdapter(self.adapter)
            self.adapter = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class WindowsRoutes:
    def __init__(self, peer, interface, address, routes=(), default=False, runner=powershell):
        self.peer = str(ipaddress.IPv4Address(peer))
        self.interface = interface
        self.address = ipaddress.IPv4Interface(address)
        if ipaddress.IPv4Address(peer) in self.address.network:
            raise ValueError("TUN subnet must not contain the outer peer address")
        self.routes = [str(ipaddress.IPv4Network(route)) for route in routes]
        if any(ipaddress.IPv4Network(route).prefixlen == 0 for route in self.routes):
            raise ValueError("use --default-route for a default route")
        if len(self.routes) > 32 or len(set(self.routes)) != len(self.routes):
            raise ValueError("at most 32 distinct routes are allowed")
        if default:
            self.routes.extend(["0.0.0.0/1", "128.0.0.0/1"])
        if len(set(self.routes)) != len(self.routes):
            raise ValueError("duplicate route")
        self.runner, self.undo = runner, []

    def _add(self, prefix, index, next_hop):
        payload = {"prefix": prefix, "index": index, "hop": next_hop}
        self.runner(
            "New-NetRoute -DestinationPrefix $p.prefix -InterfaceIndex $p.index "
            "-NextHop $p.hop -RouteMetric 1 -PolicyStore ActiveStore | Out-Null",
            payload,
        )
        self.undo.append(
            (
                "Remove-NetRoute -DestinationPrefix $p.prefix -InterfaceIndex $p.index "
                "-NextHop $p.hop -PolicyStore ActiveStore -Confirm:$false",
                payload,
            )
        )

    def __enter__(self):
        try:
            raw = self.runner(
                "Find-NetRoute -RemoteIPAddress $p.peer | Where-Object "
                "{ $_.PSObject.Properties.Name -contains 'NextHop' } | "
                "Select-Object InterfaceIndex,NextHop | ConvertTo-Json -Compress",
                {"peer": self.peer},
            )
            original = json.loads(raw)
            if not isinstance(original, dict) or not original.get("InterfaceIndex"):
                raise ValueError("cannot identify original endpoint route")
            self.index = int(
                self.runner("(Get-NetAdapter -Name $p.name).ifIndex", {"name": self.interface})
            )
            if original["InterfaceIndex"] == self.index:
                raise ValueError("endpoint must use a separate network interface")
            if self.routes:
                existing = self.runner(
                    "@(Get-NetRoute -DestinationPrefix $p.prefix -ErrorAction SilentlyContinue "
                    "| Select-Object InterfaceIndex,NextHop) | ConvertTo-Json -Compress",
                    {"prefix": self.peer + "/32"},
                )
                if existing and existing != "[]":
                    entries = json.loads(existing)
                    entries = entries if isinstance(entries, list) else [entries]
                    if len(entries) != 1 or entries[0] != original:
                        raise ValueError("conflicting endpoint host route")
                else:
                    self._add(self.peer + "/32", original["InterfaceIndex"], original["NextHop"])
            self.runner(
                "Set-NetIPInterface -InterfaceIndex $p.index -AddressFamily IPv4 "
                "-NlMtuBytes 1000 -Dhcp Disabled; "
                "New-NetIPAddress -InterfaceIndex $p.index -IPAddress $p.address "
                "-PrefixLength $p.prefix -PolicyStore ActiveStore | Out-Null",
                {
                    "index": self.index,
                    "address": str(self.address.ip),
                    "prefix": self.address.network.prefixlen,
                },
            )
            self.undo.append(
                (
                    "Remove-NetIPAddress -InterfaceIndex $p.index -IPAddress $p.address "
                    "-Confirm:$false",
                    {"index": self.index, "address": str(self.address.ip)},
                )
            )
            for prefix in self.routes:
                self._add(prefix, self.index, "0.0.0.0")
            return self
        except BaseException:
            self.close()
            raise

    def close(self):
        failures = []
        while self.undo:
            script, payload = self.undo.pop()
            try:
                self.runner(script, payload)
            except (OSError, subprocess.SubprocessError) as exc:
                LOG.error(
                    "Windows route cleanup failed: %s; command: %s; arguments: %s",
                    exc,
                    script,
                    json.dumps(payload),
                )
                failures.append(payload)
        if failures:
            raise OSError("Windows route cleanup incomplete; recovery commands logged")

    def __exit__(self, *_):
        self.close()
