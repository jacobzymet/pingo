"""Owned firewall/DNS state, with cleanup that never replaces existing rules."""

import ipaddress
import logging
import re
import subprocess
import uuid

from .windows import powershell

LOG = logging.getLogger(__name__)


def command(args, data=None):
    return subprocess.run(
        args, input=data, check=True, text=True, capture_output=True, timeout=10
    ).stdout


class LinuxKillSwitch:
    def __init__(self, peer, interface, runner=command):
        self.peer = str(ipaddress.IPv4Address(peer))
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", interface):
            raise ValueError("invalid interface name")
        self.interface = interface
        self.table = "pingo_" + uuid.uuid4().hex
        self.runner, self.active = runner, False

    def __enter__(self):
        rules = (
            f"add table inet {self.table}\n"
            f"add chain inet {self.table} output {{ type filter hook output priority -10; "
            "policy drop; }\n"
            f'add rule inet {self.table} output oifname "lo" accept\n'
            f'add rule inet {self.table} output meta nfproto ipv4 oifname "{self.interface}" '
            "accept\n"
            f"add rule inet {self.table} output ip daddr {self.peer} "
            "icmp type { echo-request, echo-reply } accept\n"
            f"add chain inet {self.table} forward {{ type filter hook forward priority -10; "
            "policy drop; }\n"
            f"add rule inet {self.table} forward meta nfproto ipv4 "
            f'oifname "{self.interface}" accept\n'
        )
        # One nft transaction; a setup error cannot leave a partially installed table.
        self.runner(["nft", "-f", "-"], rules)
        self.active = True
        LOG.info("Kill switch active; crash recovery: pingo unlock --table %s", self.table)
        return self

    def close(self):
        if self.active:
            try:
                self.runner(["nft", "delete", "table", "inet", self.table])
            except (OSError, subprocess.SubprocessError):
                LOG.error("Kill switch retained; recover with: pingo unlock --table %s", self.table)
                raise
            self.active = False

    def __exit__(self, exc_type, *_):
        if exc_type is None:
            self.close()
        else:
            LOG.error(
                "Kill switch retained after failure; recover with: pingo unlock --table %s",
                self.table,
            )


def unlock_linux(table, runner=command):
    if not table or not re.fullmatch(r"pingo_[0-9a-f]{32}", table):
        raise ValueError("specify the exact pingo_<32 hex digits> table printed at startup")
    runner(["nft", "delete", "table", "inet", table])


class LinuxDNS:
    def __init__(self, interface, servers, runner=command):
        self.interface = interface
        self.servers = [str(ipaddress.IPv4Address(server)) for server in servers]
        self.runner, self.active = runner, False

    def __enter__(self):
        try:
            # The adapter is newly created; revert restores its unconfigured DNS state.
            self.runner(["resolvectl", "dns", self.interface, *self.servers])
            self.active = True
            self.runner(["resolvectl", "domain", self.interface, "~."])
            self.runner(["resolvectl", "default-route", self.interface, "yes"])
            self.runner(["resolvectl", "llmnr", self.interface, "no"])
            self.runner(["resolvectl", "mdns", self.interface, "no"])
            return self
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.active:
            self.runner(["resolvectl", "revert", self.interface])
            self.active = False

    def __exit__(self, *_):
        self.close()


class WindowsDNS:
    def __init__(self, interface, servers, runner=powershell):
        self.interface = interface
        self.servers = [str(ipaddress.IPv4Address(server)) for server in servers]
        self.runner, self.rule = runner, None
        self.comment = "Pingo-" + uuid.uuid4().hex

    def __enter__(self):
        if self.runner("@(Get-DnsClientNrptPolicy -Effective).Count") != "0":
            raise ValueError("existing Windows DNS policy; automatic DNS setup refused")
        try:
            self.runner(
                "Set-DnsClientServerAddress -InterfaceAlias $p.name -ServerAddresses $p.servers",
                {"name": self.interface, "servers": self.servers},
            )
            self.rule = self.runner(
                "(Add-DnsClientNrptRule -Namespace '.' -NameServers $p.servers "
                "-Comment $p.comment -PassThru).Name",
                {"servers": self.servers, "comment": self.comment},
            )
            if not self.rule:
                raise OSError("Windows DNS policy did not return its identity")
            self.runner("Clear-DnsClientCache")
            return self
        except BaseException:
            self.close()
            raise

    def close(self):
        # Query our comment as well, to recover a command which succeeded but lost its output.
        self.runner(
            "Get-DnsClientNrptRule | Where-Object { $_.Comment -eq $p.comment } | "
            "Remove-DnsClientNrptRule -Confirm:$false; Clear-DnsClientCache",
            {"comment": self.comment},
        )
        self.rule = None

    def __exit__(self, *_):
        self.close()


def cleanup_windows_dns(runner=powershell):
    runner(
        "Get-DnsClientNrptRule | Where-Object { $_.Comment -match '^Pingo-[0-9a-f]{32}$' } | "
        "Remove-DnsClientNrptRule -Confirm:$false; Clear-DnsClientCache"
    )
