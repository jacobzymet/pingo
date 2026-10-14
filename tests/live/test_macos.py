"""Opt-in native Darwin checks; no host route, DNS, or PF changes."""

import os
import socket
import sys
import time

import pytest

from pingo.icmp import RawICMP
from pingo.macos import PFCTL, MacKillSwitch, Utun, command

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        sys.platform != "darwin" or os.environ.get("PINGO_MAC_LIVE") != "1",
        reason="requires explicit PINGO_MAC_LIVE=1 and root/BPF access on macOS",
    ),
]


def test_mac_kernel_capture_receives_echo_requests():
    payload = b"Pingo-native-capture-" + os.urandom(16)
    with_carrier = RawICMP("127.0.0.1", "127.0.0.1")
    try:
        with_carrier.send(payload)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if with_carrier.recv(0.2) == payload:
                return
        pytest.fail("libpcap did not capture the original loopback ICMP echo request")
    finally:
        with_carrier.close()


def test_mac_kernel_allocates_and_releases_a_fresh_utun():
    with Utun("auto") as tun:
        name = tun.name
        assert name.startswith("utun") and socket.if_nametoindex(name) > 0
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if name not in {item[1] for item in socket.if_nameindex()}:
            return
        time.sleep(0.05)
    pytest.fail("owned utun did not disappear after closing its control socket")


def test_mac_native_pf_parser_accepts_guard_without_installing_it():
    guard = MacKillSwitch("192.0.2.20", "utun9999")
    command([PFCTL, "-n", "-a", guard.anchor, "-f", "-"], guard.rules())
