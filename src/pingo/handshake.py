"""Noise NNpsk0 with bounded authenticated framing for a lossy carrier."""

import os

from cryptography.exceptions import InvalidTag
from noise.connection import NoiseConnection
from noise.exceptions import NoiseHandshakeError, NoiseInvalidMessage

from .crypto import PacketError, Session, sign, verify

PROTOCOL = b"Noise_NNpsk0_25519_ChaChaPoly_SHA256"
HELLO, RESPONSE = b"PGN1", b"PGN2"
PREFIX_SIZE = 21  # marker (4), application mode (1), exchange identifier (16)
BODY_SIZE = PREFIX_SIZE + 48  # X25519 ephemeral public key and full empty-payload tag


def noise_connection(key, mode, exchange, initiator):
    if len(key) != 32 or len(mode) != 1 or len(exchange) != 16:
        raise ValueError("invalid handshake parameters")
    noise = NoiseConnection.from_name(PROTOCOL)
    noise.set_psks(psk=key)
    noise.set_prologue(b"pingo/session/v2\x00" + mode + exchange)
    if initiator:
        noise.set_as_initiator()
    else:
        noise.set_as_responder()
    noise.start_handshake()
    return noise


def session_from_noise(noise):
    if not noise.handshake_finished:
        raise ValueError("Noise handshake is incomplete")
    # noiseprotocol is pinned: this adapter reads only its completed Split() states.
    protocol = noise.noise_protocol
    return Session(
        protocol.cipher_state_encrypt.k,
        protocol.cipher_state_decrypt.k,
        noise.get_handshake_hash(),
    )


class InitiatorHandshake:
    def __init__(self, key, mode):
        self.exchange = os.urandom(16)
        self.mode = mode
        self.failed = False
        self._noise = noise_connection(key, mode, self.exchange, True)
        self.hello = sign(key, HELLO + mode + self.exchange + bytes(self._noise.write_message()))

    def accept(self, key, packet):
        body = verify(key, packet, BODY_SIZE)
        if body[:PREFIX_SIZE] != RESPONSE + self.mode + self.exchange:
            raise PacketError("wrong handshake response")
        try:
            if self._noise is None or self._noise.read_message(body[PREFIX_SIZE:]):
                raise ValueError("unexpected Noise handshake payload")
            session = session_from_noise(self._noise)
        except (InvalidTag, ValueError, NoiseHandshakeError, NoiseInvalidMessage) as exc:
            self.failed = True
            raise PacketError("invalid Noise handshake response") from exc
        finally:
            self.close()
        return session

    def close(self):
        self._noise = None


def respond(key, mode, packet):
    body = verify(key, packet, BODY_SIZE)
    if body[:5] != HELLO + mode:
        raise PacketError("wrong application mode or protocol version")
    exchange = body[5:PREFIX_SIZE]
    noise = noise_connection(key, mode, exchange, False)
    try:
        if noise.read_message(body[PREFIX_SIZE:]):
            raise ValueError("unexpected Noise handshake payload")
        response = sign(key, RESPONSE + mode + exchange + bytes(noise.write_message()))
        return session_from_noise(noise), response
    except (InvalidTag, ValueError, NoiseHandshakeError, NoiseInvalidMessage) as exc:
        raise PacketError("invalid Noise handshake request") from exc
