import io
import json
import threading
import time

import pytest

from pingo.congestion import Congestion
from pingo.reliable import Reliable
from pingo.traffic import TracedCarrier, Traffic
from pingo.vpn import IP_ACK, IP_DATA, VPN

from .helpers import carriers, connected, ipv4
from .test_vpn import FakeTun


class FlushedStream(io.StringIO):
    def __init__(self):
        super().__init__()
        self.flushes = 0

    def flush(self):
        self.flushes += 1


def test_live_wire_hex_and_flush_for_every_packet():
    stream = FlushedStream()
    traffic = Traffic("hex", stream)
    a, b = carriers()
    wrapped = TracedCarrier(a, traffic, "192.0.2.20")
    wrapped.send(b"ciphertext")
    b.send(b"reply")
    assert wrapped.recv(0.01) == b"reply"
    traffic.close()
    events = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert [event["direction"] for event in events] == ["tx", "rx"]
    assert bytes.fromhex(events[0]["wire_hex"]) == b"ciphertext"
    assert stream.flushes == 2
    assert events[0]["bytes"] == 10
    wrapped.close()
    b.close()


def test_summary_hides_wire_and_tun_payload_and_off_emits_nothing():
    stream = FlushedStream()
    summary = Traffic("summary", stream)
    summary.packet("tx", b"private", "peer")
    summary.close()
    hex_traffic = Traffic("hex", stream)
    hex_traffic.packet("tx", b"private", "peer", layer="tun")
    hex_traffic.close()
    Traffic("off", stream).packet("tx", b"private", "peer")
    assert len(stream.getvalue().splitlines()) == 2
    assert "private" not in stream.getvalue() and "wire_hex" not in stream.getvalue()


def test_vpn_aimd_reacts_to_loss_and_ack_without_unbounded_queue():
    now = [0.0]
    flow = Congestion(clock=lambda: now[0])
    seq = flow.sent()
    now[0] = 0.1
    flow.acknowledge(seq)
    assert flow.window > 4 and not flow.pending
    flow.sent()
    now[0] = 5
    assert flow.available()
    assert flow.window < 4 and not flow.pending
    flow.acknowledge(999)
    for _ in range(100):
        if flow.available():
            flow.sent()
        now[0] += 0.001
    assert len(flow.pending) <= int(flow.window) <= 64


def test_rtt_estimator_increases_timeout_for_slow_peer():
    with connected() as (_, _, sender, _):
        sender._sample(0.3)
        assert sender.rto == pytest.approx(0.9)
        before = sender.rto
        sender._sample(0.5)
        assert sender.rto > before
        assert isinstance(sender, Reliable)


def test_vpn_congestion_frames_reach_tun_and_ack():
    with connected(mode="vpn") as (client, server, *_):
        a, b = FakeTun(), FakeTun()
        sender = VPN(client, a, ["10.77.0.0/30"])
        VPN(server, b, ["10.77.0.0/30"])
        packet = ipv4(b"hello", source="10.77.0.1", destination="10.77.0.2", protocol=17)
        seq = sender.congestion.sent()
        acknowledged = threading.Event()
        original = sender.receive

        def receive(data):
            original(data)
            if data.startswith(IP_ACK):
                acknowledged.set()

        client.handler = receive
        client.send(IP_DATA + seq.to_bytes(8, "big") + packet)
        assert b.received.wait(1) and acknowledged.wait(1)
        assert b.written == [packet] and not sender.congestion.pending



def test_blocked_telemetry_drops_bounded_records_without_blocking_network():
    class SlowStream(FlushedStream):
        def __init__(self):
            super().__init__()
            self.entered = threading.Event()
            self.release = threading.Event()

        def write(self, data):
            self.entered.set()
            if not self.release.wait(3):
                raise OSError("slow output timed out")
            return super().write(data)

    stream = SlowStream()
    traffic = Traffic("hex", stream, max_pending=2)
    try:
        traffic.packet("tx", b"one", "peer")
        assert stream.entered.wait(1)
        started = time.monotonic()
        for _ in range(100):
            traffic.packet("tx", b"packet", "peer")
        assert time.monotonic() - started < 0.5
        assert traffic.dropped > 0
    finally:
        stream.release.set()
        traffic.close()


def test_broken_telemetry_does_not_interrupt_packet_delivery():
    class BrokenStream(FlushedStream):
        def flush(self):
            raise BrokenPipeError("log consumer closed")

    traffic = Traffic("summary", BrokenStream())
    try:
        traffic.packet("tx", b"first", "peer")
        deadline = time.monotonic() + 1
        while traffic.write_error is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert isinstance(traffic.write_error, BrokenPipeError)
        traffic.packet("rx", b"second", "peer")  # Must not raise.
        assert traffic.dropped >= 2
    finally:
        traffic.close()
