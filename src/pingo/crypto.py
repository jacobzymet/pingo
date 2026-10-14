"""Standard AEAD/HKDF primitives and a bounded, authenticated replay window.

Session keys come exclusively from a completed ephemeral Noise handshake.
Session objects and ephemeral private keys are never serialized.
"""

import hashlib
import hmac
import struct
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"PG02"
HEADER = struct.Struct("!4s16sQ")
MAX_WIRE = 1200  # ICMP payload; 1228 bytes including ordinary IPv4/ICMP headers.
MAX_PLAIN = MAX_WIRE - HEADER.size - 16
WINDOW = 1024


class PacketError(ValueError):
    """Malformed, unauthenticated, stale, or replayed packet."""


def authenticate(key: bytes, body: bytes) -> bytes:
    return hmac.digest(key, b"pingo/handshake/v2\x00" + body, "sha256")


def sign(key: bytes, body: bytes) -> bytes:
    return body + authenticate(key, body)


def verify(key: bytes, packet: bytes, size: int) -> bytes:
    if len(packet) != size + 32 or not hmac.compare_digest(
        authenticate(key, packet[:size]), packet[size:]
    ):
        raise PacketError("invalid handshake")
    return packet[:size]


class Session:
    def __init__(self, outgoing: bytes, incoming: bytes, handshake_hash: bytes):
        if any(len(value) != 32 for value in (outgoing, incoming, handshake_hash)):
            raise ValueError("Noise split keys and handshake hash must be 32 bytes")

        # Separate datagram keys from Noise's ordered transport cipher states.
        def datagram_key(key):
            return HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=handshake_hash,
                info=b"pingo/datagram/v2",
            ).derive(key)

        self.id = hashlib.sha256(b"pingo/id/v2" + handshake_hash).digest()[:16]
        self._out = ChaCha20Poly1305(datagram_key(outgoing))
        self._in = ChaCha20Poly1305(datagram_key(incoming))
        self._counter = 0
        self._highest = -1
        self._bitmap = 0
        self._send_lock = threading.Lock()

    def encrypt(self, data: bytes) -> bytes:
        if not data or len(data) > MAX_PLAIN:
            raise ValueError("plaintext outside packet bounds")
        with self._send_lock:
            # A conservative key lifetime, well below the 64-bit counter limit.
            if self._counter >= 2**32:
                raise OverflowError("session exhausted; reconnect")
            counter = self._counter
            self._counter += 1
            header = HEADER.pack(MAGIC, self.id, counter)
            nonce = b"\x00" * 4 + counter.to_bytes(8, "big")
            return header + self._out.encrypt(nonce, data, header)

    def decrypt(self, packet: bytes) -> bytes:
        if not HEADER.size + 16 < len(packet) <= MAX_WIRE:
            raise PacketError("invalid ciphertext length")
        magic, session_id, counter = HEADER.unpack_from(packet)
        if magic != MAGIC or session_id != self.id or counter >= 2**32:
            raise PacketError("wrong session or counter")
        delta = self._highest - counter
        if delta >= WINDOW or (delta >= 0 and (self._bitmap >> delta) & 1):
            raise PacketError("replay or stale counter")
        try:
            plaintext = self._in.decrypt(
                b"\x00" * 4 + counter.to_bytes(8, "big"),
                packet[HEADER.size :],
                packet[: HEADER.size],
            )
        except InvalidTag as exc:
            raise PacketError("authentication failed") from exc
        # Update only after authentication; a forged high counter cannot move the window.
        if counter > self._highest:
            shift = counter - self._highest
            self._bitmap = (
                ((self._bitmap << shift) | 1) & ((1 << WINDOW) - 1) if (shift < WINDOW) else 1
            )
            self._highest = counter
        else:
            self._bitmap |= 1 << delta
        return plaintext
