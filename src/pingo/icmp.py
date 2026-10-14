"""IPv4 ICMP echo-request carrier. Echo replies are deliberately ignored."""

import ipaddress
import socket
import struct
import sys

from .crypto import MAX_WIRE, PacketError

IDENTIFIER = 0x5047


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def encode(payload: bytes, sequence: int = 0) -> bytes:
    if not 0 < len(payload) <= MAX_WIRE:
        raise ValueError("ICMP payload outside bounds")
    packet = struct.pack("!BBHHH", 8, 0, 0, IDENTIFIER, sequence & 0xFFFF) + payload
    return packet[:2] + struct.pack("!H", checksum(packet)) + packet[4:]


def decode(packet: bytes, peer: str) -> bytes:
    if len(packet) < 28 or packet[0] >> 4 != 4:
        raise PacketError("invalid IPv4 header")
    ihl = (packet[0] & 15) * 4
    total = int.from_bytes(packet[2:4], "big")
    fragments = int.from_bytes(packet[6:8], "big")
    if ihl < 20 or total != len(packet) or total < ihl + 9 or packet[9] != 1:
        raise PacketError("invalid IPv4 length or protocol")
    if fragments & 0x3FFF or str(ipaddress.IPv4Address(packet[12:16])) != peer:
        raise PacketError("fragmented packet or wrong peer")
    icmp = packet[ihl:]
    if len(icmp) > MAX_WIRE + 8 or checksum(icmp):
        raise PacketError("invalid ICMP size/checksum")
    kind, code, _, identifier, _ = struct.unpack_from("!BBHHH", icmp)
    if kind != 8 or code != 0 or identifier != IDENTIFIER:
        raise PacketError("not a Pingo echo request")
    return icmp[8:]


class RawICMP:
    def __init__(self, peer: str, bind: str = "0.0.0.0"):
        self.peer = str(ipaddress.IPv4Address(peer))
        self.capture = None
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        try:
            self.socket.bind((str(ipaddress.IPv4Address(bind)), 0))
            self.socket.settimeout(0.2)
            if sys.platform == "darwin":
                from .macos import MacCapture

                self.capture = MacCapture(self.peer, bind)
        except BaseException:
            self.socket.close()
            raise
        self.sequence = 0

    def send(self, payload: bytes) -> None:
        packet = encode(payload, self.sequence)
        self.sequence = (self.sequence + 1) & 0xFFFF
        self.socket.sendto(packet, (self.peer, 0))

    def recv(self, timeout: float = 0.2) -> bytes | None:
        if self.capture is not None:
            return self.capture.recv(timeout)
        self.socket.settimeout(timeout)
        try:
            packet, address = self.socket.recvfrom(65535)
            if address[0] != self.peer:
                return None
            return decode(packet, self.peer)
        except (socket.timeout, PacketError):
            return None

    def close(self) -> None:
        if self.capture is not None:
            self.capture.close()
        self.socket.close()
