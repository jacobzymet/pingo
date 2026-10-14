"""Published Cacophony NNpsk0 vectors; all keys here are public test values."""

import json
from pathlib import Path

import pytest
from noise.connection import Keypair, NoiseConnection

from pingo.handshake import PROTOCOL, session_from_noise


def test_published_noise_nnpsk0_vector_and_datagram_key_adapter():
    vector = json.loads((Path(__file__).parent / "fixtures/noise-nnpsk0.json").read_text())
    peers = []
    for role in ("init", "resp"):
        peer = NoiseConnection.from_name(PROTOCOL)
        peer.set_psks(psk=bytes.fromhex(vector[f"{role}_psks"][0]))
        peer.set_prologue(bytes.fromhex(vector[f"{role}_prologue"]))
        (peer.set_as_initiator if role == "init" else peer.set_as_responder)()
        peer.set_keypair_from_private_bytes(
            Keypair.EPHEMERAL, bytes.fromhex(vector[f"{role}_ephemeral"])
        )
        with pytest.warns(UserWarning, match="ephemeral keypairs is already set"):
            peer.start_handshake()
        peers.append(peer)
    for index, message in enumerate(vector["messages"]):
        sender, receiver = peers[index % 2], peers[(index + 1) % 2]
        payload = bytes.fromhex(message["payload"])
        if index < 2:
            ciphertext = bytes(sender.write_message(payload))
            assert bytes(receiver.read_message(ciphertext)) == payload
        else:
            ciphertext = sender.encrypt(payload)
            assert receiver.decrypt(ciphertext) == payload
        assert ciphertext.hex() == message["ciphertext"]
    assert peers[0].get_handshake_hash().hex() == vector["handshake_hash"]
    assert peers[1].get_handshake_hash() == peers[0].get_handshake_hash()
    assert not hasattr(peers[0].noise_protocol, "handshake_state")
    assert not hasattr(peers[1].noise_protocol, "handshake_state")
    initiator, responder = map(session_from_noise, peers)
    assert responder.decrypt(initiator.encrypt(b"application datagram")) == b"application datagram"
    assert initiator.decrypt(responder.encrypt(b"reply")) == b"reply"
