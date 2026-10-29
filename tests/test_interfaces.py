import socket
from types import SimpleNamespace

from pingo import interfaces


def test_all_assigned_ipv4s_include_virtual_down_and_loopback(monkeypatch):
    def address(value, family=socket.AF_INET):
        return SimpleNamespace(family=family, address=value, netmask="255.255.255.0")

    monkeypatch.setattr(
        interfaces.psutil,
        "net_if_addrs",
        lambda: {
            "Ethernet": [
                address("192.168.1.2"),
                address("192.168.1.3"),
                address("::1", socket.AF_INET6),
            ],
            "Wi-Fi": [address("10.0.0.2")],
            "VPN": [address("10.77.0.1")],
            "Virtual": [address("169.254.1.2")],
            "Loopback": [address("127.0.0.1")],
            "Empty": [address("0.0.0.0")],
        },
    )
    monkeypatch.setattr(
        interfaces.psutil,
        "net_if_stats",
        lambda: {
            "Ethernet": SimpleNamespace(isup=True),
            "Wi-Fi": SimpleNamespace(isup=False),
        },
    )
    rows = interfaces.local_ipv4()
    assert len(rows) == 6
    assert len([r for r in rows if r["name"] == "Ethernet"]) == 2
    assert next(r for r in rows if r["name"] == "Wi-Fi")["up"] is False
    assert next(r for r in rows if r["name"] == "VPN")["up"] is None
    assert next(r for r in rows if r["name"] == "Virtual")["link_local"]
    assert rows[-1]["loopback"]


def test_missing_stats_does_not_hide_addresses(monkeypatch):
    monkeypatch.setattr(
        interfaces.psutil,
        "net_if_addrs",
        lambda: {
            "VPN": [SimpleNamespace(family=socket.AF_INET, address="10.77.0.1", netmask=None)],
        },
    )

    def denied():
        raise OSError("unavailable")

    monkeypatch.setattr(interfaces.psutil, "net_if_stats", denied)
    assert interfaces.local_ipv4()[0]["address"] == "10.77.0.1"
