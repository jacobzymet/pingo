import socket
from types import SimpleNamespace

import pytest

from pingo import diagnostics
from pingo.config import Config
from pingo.diagnostics import address_checks, local_network_checks, storage_checks, vpn_checks


@pytest.mark.parametrize(
    "peer,bind,status,description",
    [
        ("10.0.0.2", "10.0.0.2", "fail", "same IPv4"),
        ("127.0.0.2", "0.0.0.0", "warn", "stays on this computer"),
        ("192.0.2.20", "0.0.0.0", "warn", "example-only"),
        ("8.8.8.8", "203.0.113.1", "warn", "example-only"),
        ("192.168.1.2", "0.0.0.0", "manual", "private IPv4"),
        ("100.64.1.2", "0.0.0.0", "manual", "carrier NAT"),
        ("169.254.10.2", "0.0.0.0", "manual", "link-local"),
        ("8.8.8.8", "0.0.0.0", "manual", "no NAT traversal"),
    ],
)
def test_address_guidance_distinguishes_real_network_failures(peer, bind, status, description):
    checks = address_checks(peer, bind)
    assert any(c["status"] == status and description in c["detail"] for c in checks)


def test_route_check_uses_numeric_address_without_transmitting(monkeypatch):
    calls = []

    class Socket:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            calls.append("closed")

        def settimeout(self, value):
            calls.append(("timeout", value))

        def bind(self, address):
            calls.append(("bind", address))

        def connect(self, address):
            calls.append(("connect", address))

        def getsockname(self):
            return ("10.0.0.1", 45678)

        def send(self, *_):
            pytest.fail("local checks must not transmit")

    def create(family, kind):
        assert family == socket.AF_INET and kind == socket.SOCK_DGRAM
        return Socket()

    monkeypatch.setattr(diagnostics.socket, "socket", create)
    assert diagnostics.route_source("10.0.0.2", "10.0.0.1") == "10.0.0.1"
    assert ("bind", ("10.0.0.1", 0)) in calls
    assert ("connect", ("10.0.0.2", 9)) in calls
    assert calls[-1] == "closed"


def test_icmp_check_closes_carrier_and_does_not_claim_delivery(monkeypatch):
    closed = []
    monkeypatch.setattr(diagnostics, "route_source", lambda *_: "10.0.0.1")
    monkeypatch.setattr(
        diagnostics, "RawICMP", lambda *_: SimpleNamespace(close=lambda: closed.append(True))
    )
    checks = local_network_checks("10.0.0.2", "0.0.0.0")
    assert closed == [True]
    assert all(c["status"] == "pass" for c in checks)
    assert "remain unverified" in checks[1]["detail"]


def test_unavailable_route_and_raw_permission_have_actionable_independent_results(monkeypatch):
    def no_route(*_):
        raise OSError("Network is unreachable")

    def no_raw(*_):
        raise PermissionError("access denied")

    monkeypatch.setattr(diagnostics, "route_source", no_route)
    monkeypatch.setattr(diagnostics, "RawICMP", no_raw)
    checks = local_network_checks("10.0.0.2", "10.0.0.99")
    assert checks[0]["status"] == "warn" and "DHCP" in checks[0]["detail"]
    assert checks[1]["status"] == "fail" and "Administrator/root" in checks[1]["detail"]


def test_route_to_self_is_a_failure(monkeypatch):
    monkeypatch.setattr(diagnostics, "route_source", lambda *_: "10.0.0.2")
    monkeypatch.setattr(diagnostics, "RawICMP", lambda *_: SimpleNamespace(close=lambda: None))
    assert local_network_checks("10.0.0.2", "0.0.0.0")[0]["status"] == "fail"


def test_storage_checks_low_space_without_leaving_test_files(tmp_path, monkeypatch):
    directory = tmp_path / "new" / "received"
    monkeypatch.setattr(diagnostics.shutil, "disk_usage", lambda *_: SimpleNamespace(free=1024))
    checks = storage_checks(Config("10.0.0.2", tmp_path / "peer.key", receive_dir=directory))
    assert checks[0]["status"] == "pass"
    assert checks[1]["status"] == "warn"
    assert list(tmp_path.iterdir()) == []


def test_storage_checks_path_that_is_a_file(tmp_path):
    directory = tmp_path / "received"
    directory.write_text("keep me")
    checks = storage_checks(Config("10.0.0.2", tmp_path / "peer.key", receive_dir=directory))
    assert checks[0]["status"] == "fail"
    assert directory.read_text() == "keep me"


def vpn_profile(**changes):
    return {
        "peer": "192.168.1.2",
        "bind": "192.168.1.1",
        "address": "10.77.0.1/30",
        "vpn_listen": False,
        "default_route": False,
        "kill_switch": None,
        "allowed_source": [],
        "no_dns": False,
        **changes,
    }


@pytest.mark.parametrize("field", ["peer", "bind"])
def test_vpn_rejects_outer_endpoint_inside_tunnel_subnet(field):
    checks = vpn_checks(vpn_profile(**{field: "10.77.0.2"}))
    assert any(c["status"] == "fail" and "overlap" in c["name"] for c in checks)


def test_default_vpn_warns_about_missing_reply_sources_and_disabled_protection():
    checks = vpn_checks(vpn_profile(default_route=True, kill_switch=False))
    assert len([c for c in checks if c["status"] == "warn"]) == 2
    checks = vpn_checks(vpn_profile(default_route=True, allowed_source=["0.0.0.0/0"]))
    assert all(c["status"] == "manual" for c in checks)


def test_vpn_responder_cannot_use_client_kill_switch():
    checks = vpn_checks(vpn_profile(vpn_listen=True, kill_switch=True))
    assert any(c["status"] == "fail" and "Responders" in c["detail"] for c in checks)
