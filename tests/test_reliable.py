import os
import time

import pytest

from pingo.crypto import PacketError
from pingo.reliable import ACK, DATA, FRAME, MAX_MESSAGE, RemoteError

from .helpers import connected


def test_fragmented_round_trip_with_data_and_ack_loss_and_duplicates():
    received = []
    with connected(handler=lambda blob: received.append(blob) or b"done") as (
        client,
        server,
        sender,
        receiver,
    ):
        client.carrier.drop_every = 7
        client.carrier.duplicate_every = 11
        server.carrier.drop_every = 5
        server.carrier.duplicate_every = 13
        blob = os.urandom(MAX_MESSAGE)
        assert sender.send(blob) == b"done"
        assert received == [blob]
        assert len(receiver._incoming) == 0


def test_lost_final_ack_does_not_repeat_operation():
    received = []
    with connected(handler=lambda data: received.append(data) or b"ok") as (_, server, sender, _):
        server.carrier.drop_next = 1
        assert sender.send(b"once") == b"ok"
        assert received == [b"once"]


def test_late_original_packet_cannot_repeat_after_result_expiry():
    received = []
    with connected(handler=lambda data: received.append(data) or b"ok") as (
        client,
        server,
        sender,
        receiver,
    ):
        client.carrier.drop_next = 1
        before = len(client.carrier.sent)
        assert sender.send(b"once") == b"ok"
        original = client.carrier.sent[before]
        receiver._completed.clear()
        server.carrier.inbox.put(original)
        # An explicit subsequent operation also waits for the reader to process the old packet.
        assert sender.send(b"next") == b"ok"
        assert received == [b"once", b"next"]


def test_permanent_loss_times_out():
    with connected() as (client, _, sender, _):
        client.carrier.drop_every = 1
        with pytest.raises(TimeoutError):
            sender.send(b"lost")


def test_receiver_error_reaches_sender():
    def reject(_):
        raise ValueError("refused")

    with connected(handler=reject) as (_, _, sender, _):
        with pytest.raises(RemoteError, match="refused"):
            sender.send(b"x")


def test_bounds_and_expiry():
    with connected() as (_, _, sender, receiver):
        for value in (b"", b"x" * (MAX_MESSAGE + 1)):
            with pytest.raises(ValueError):
                sender.send(value)
        for _ in range(8):
            receiver.receive(FRAME.pack(DATA, os.urandom(16), 0, 2) + b"x" * 1000)
        assert len(receiver._incoming) == 4
        for value in receiver._incoming.values():
            value[3] = time.monotonic() - 46
        receiver.expire()
        assert not receiver._incoming


@pytest.mark.parametrize(
    "packet",
    [
        b"x",
        FRAME.pack(DATA, b"x" * 16, 1, 1) + b"x",
        FRAME.pack(DATA, b"x" * 16, 0, 99) + b"x",
        FRAME.pack(ACK, b"x" * 16, 0, 1) + b"bad",
        FRAME.pack(DATA, b"x" * 16, 0, 2) + b"short",
    ],
)
def test_invalid_frames(packet):
    with connected() as (_, _, _, receiver):
        with pytest.raises(PacketError):
            receiver.receive(packet)
