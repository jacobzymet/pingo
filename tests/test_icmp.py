import pytest

from pingo.crypto import PacketError
from pingo.icmp import checksum, decode, encode

from .helpers import ipv4


@pytest.mark.parametrize("payload", [b"x", b"abc", b"x" * 1200])
def test_round_trip(payload):
    frame = encode(payload, 65537)
    assert checksum(frame) == 0
    assert decode(ipv4(frame), "192.0.2.10") == payload


@pytest.mark.parametrize(
    "change",
    ["peer", "checksum", "reply", "identifier", "fragment", "length", "ihl", "protocol", "short"],
)
def test_reject_bad_packets(change):
    frame = encode(b"payload")
    packet = bytearray(ipv4(frame))
    if change == "peer":
        packet[12] ^= 1
    elif change == "checksum":
        packet[-1] ^= 1
    elif change in ("reply", "identifier"):
        icmp = bytearray(frame)
        icmp[0 if change == "reply" else 4] = 0
        icmp[2:4] = b"\x00\x00"
        icmp[2:4] = checksum(bytes(icmp)).to_bytes(2, "big")
        packet = bytearray(ipv4(bytes(icmp)))
    elif change == "fragment":
        packet[6] = 0x20
    elif change == "length":
        packet[3] -= 1
    elif change == "ihl":
        packet[0] = 0x44
    elif change == "protocol":
        packet[9] = 17
    else:
        packet = packet[:10]
    with pytest.raises(PacketError):
        decode(bytes(packet), "192.0.2.10")


def test_payload_bounds():
    for data in (b"", b"x" * 1201):
        with pytest.raises(ValueError):
            encode(data)
