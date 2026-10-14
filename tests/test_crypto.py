import os
import struct

import pytest

from pingo.crypto import HEADER, MAX_PLAIN, PacketError, Session, sign, verify

from .helpers import KEY


def sessions():
    c, s = os.urandom(32), os.urandom(32)
    return Session(KEY, c, s, True), Session(KEY, c, s, False)


def test_bidirectional_and_nonce_separation():
    a, b = sessions()
    left, right = a.encrypt(b"same"), b.encrypt(b"same")
    assert left != right
    assert b.decrypt(left) == a.decrypt(right) == b"same"
    with pytest.raises(PacketError):
        a.decrypt(a.encrypt(b"reflection"))


def test_tampering_does_not_poison_replay_window():
    a, b = sessions()
    original = a.encrypt(b"payload")
    for offset in (0, 4, 20, HEADER.size, len(original) - 1):
        changed = bytearray(original)
        changed[offset] ^= 1
        with pytest.raises(PacketError):
            b.decrypt(bytes(changed))
    forged = original[:20] + struct.pack("!Q", 1000000) + original[28:]
    with pytest.raises(PacketError):
        b.decrypt(forged)
    assert b.decrypt(original) == b"payload"


def test_reordering_duplicate_and_stale():
    a, b = sessions()
    packets = [a.encrypt(str(i).encode()) for i in range(1030)]
    assert b.decrypt(packets[3]) == b"3"
    assert b.decrypt(packets[1]) == b"1"
    with pytest.raises(PacketError):
        b.decrypt(packets[1])
    assert b.decrypt(packets[-1]) == b"1029"
    with pytest.raises(PacketError):
        b.decrypt(packets[0])


def test_wrong_key_session_and_restart():
    a, b = sessions()
    c, _ = sessions()
    with pytest.raises(PacketError):
        c.decrypt(a.encrypt(b"old session"))
    c = Session(b"x" * 32, b"c" * 32, b"s" * 32, False)
    d = Session(KEY, b"c" * 32, b"s" * 32, True)
    with pytest.raises(PacketError):
        c.decrypt(d.encrypt(b"wrong key"))


@pytest.mark.parametrize("packet", [b"", b"PG01", b"x" * 1201])
def test_invalid_lengths(packet):
    _, b = sessions()
    with pytest.raises(PacketError):
        b.decrypt(packet)


def test_packet_and_counter_bounds():
    a, b = sessions()
    assert b.decrypt(a.encrypt(b"x" * MAX_PLAIN)) == b"x" * MAX_PLAIN
    with pytest.raises(ValueError):
        a.encrypt(b"x" * (MAX_PLAIN + 1))
    a._counter = 2**32
    with pytest.raises(OverflowError):
        a.encrypt(b"x")


def test_authenticated_handshake():
    packet = sign(KEY, b"hello")
    assert verify(KEY, packet, 5) == b"hello"
    with pytest.raises(PacketError):
        verify(b"z" * 32, packet, 5)
    with pytest.raises(PacketError):
        verify(KEY, packet + b"x", 5)
