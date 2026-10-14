import time

import pytest

from pingo.crypto import MAGIC, PacketError, sign
from pingo.handshake import HELLO, RESPONSE, InitiatorHandshake, respond
from pingo.transport import FINISH, READY, Endpoint

from .helpers import KEY, carriers, connected


@pytest.mark.parametrize("dropped", ["hello", "response", "finish", "ready"])
def test_handshake_recovers_loss(dropped):
    def configure(client, server, *_):
        if dropped == "hello":
            client.carrier.drop_next = 1
        elif dropped == "response":
            server.carrier.drop_next = 1
        else:
            endpoint = client if dropped == "finish" else server
            original = endpoint.carrier.send

            def send(data):
                if data.startswith(MAGIC):
                    endpoint.carrier.send = original
                    return
                original(data)

            endpoint.carrier.send = send

    with connected(before_connect=configure) as (client, server, *_):
        assert client.ready.is_set() and server.ready.is_set()
        assert client.session.id == server.session.id


def test_wrong_key_and_mode_fail_handshake():
    for key, mode in ((b"x" * 32, "direct"), (KEY, "vpn")):
        a, b = carriers()
        server = Endpoint(b, KEY)
        client = Endpoint(a, key, mode)
        try:
            server.start(responder=True)
            with pytest.raises(TimeoutError):
                client.connect(attempts=2, timeout=0.01)
            assert server.session is None
        finally:
            client.close()
            server.close()


def test_old_handshake_cannot_restore_session_after_restart():
    a, b = carriers()
    handshake = InitiatorHandshake(KEY, b"D")
    old = Endpoint(b, KEY)
    old._receive(handshake.hello, True, time.monotonic())
    response = b.sent[-1]
    old_client = handshake.accept(KEY, response)
    finish = old_client.encrypt(FINISH + b"D")
    old._receive(finish, True, time.monotonic())
    assert old.session is not None
    restarted = Endpoint(b, KEY)
    restarted._receive(handshake.hello, True, time.monotonic())
    assert b.sent[-1] != response
    restarted._receive(finish, True, time.monotonic())
    assert restarted.session is None
    assert not restarted.ready.is_set()
    restarted.close()
    old.close()
    a.close()


def test_confirmation_required():
    a, b = carriers()
    endpoint = Endpoint(b, KEY)
    handshake = InitiatorHandshake(KEY, b"D")
    endpoint._receive(handshake.hello, True, time.monotonic())
    session = handshake.accept(KEY, b.sent[-1])
    with pytest.raises(PacketError):
        endpoint._receive(session.encrypt(b"premature data"), True, time.monotonic())
    assert not endpoint.ready.is_set()
    endpoint.close()
    a.close()


def test_congestion_vpn_rejects_legacy_mode_before_adopting_session():
    a, b = carriers()
    endpoint = Endpoint(b, KEY, mode="vpn")
    handshake = InitiatorHandshake(KEY, b"V")
    try:
        with pytest.raises(PacketError, match="wrong application mode"):
            endpoint._receive(handshake.hello, True, time.monotonic())
        assert endpoint.session is None and endpoint._pending is None
    finally:
        handshake.close()
        endpoint.close()
        a.close()


def test_new_session_replaces_old_after_confirmation_only():
    with connected() as (client, server, sender, receiver):
        old = server.session
        handshake = InitiatorHandshake(KEY, b"D")
        server._receive(handshake.hello, True, time.monotonic() + 1)
        assert server.session is old
        replacement = handshake.accept(KEY, server.carrier.sent[-1])
        server._receive(replacement.encrypt(FINISH + b"D"), True, time.monotonic() + 1)
        assert server.session.id == replacement.id
        assert replacement.decrypt(server.carrier.sent[-1]) == READY + b"D"


def test_invalid_response_envelope_does_not_poison_noise_state():
    def configure(client, server, *_):
        original = server.carrier.send

        def send(data):
            if data.startswith(RESPONSE):
                changed = bytearray(data)
                changed[-1] ^= 1
                original(bytes(changed))
            original(data)

        server.carrier.send = send

    with connected(before_connect=configure) as (client, server, *_):
        assert client.ready.is_set()


def test_invalid_noise_request_does_not_replace_pending_or_rate_limit_valid_request():
    a, b = carriers()
    endpoint = Endpoint(b, KEY)
    handshake = InitiatorHandshake(KEY, b"D")
    body = bytearray(handshake.hello[:-32])
    body[-1] ^= 1
    now = time.monotonic()
    try:
        with pytest.raises(PacketError, match="invalid Noise"):
            endpoint._receive(sign(KEY, bytes(body)), True, now)
        assert endpoint._pending is None
        endpoint._receive(handshake.hello, True, now)
        pending = endpoint._pending
        assert pending is not None
        endpoint._receive(handshake.hello, True, now + 0.01)
        assert endpoint._pending is pending and b.sent[-1] == pending.response
    finally:
        handshake.close()
        endpoint.close()
        a.close()


def test_authenticated_low_order_noise_response_fails_cleanly():
    a, b = carriers()
    client = Endpoint(a, KEY)
    original = a.send

    def send(data):
        original(data)
        if data.startswith(HELLO):
            b.send(sign(KEY, RESPONSE + data[4:21] + bytes(48)))

    a.send = send
    try:
        with pytest.raises(TimeoutError, match="invalid Noise"):
            client.connect(attempts=1, timeout=0.02)
        assert client.session is None and not client.ready.is_set()
    finally:
        client.close()
        b.close()


def test_later_psk_disclosure_does_not_recover_recorded_session_keys():
    initiator = InitiatorHandshake(KEY, b"D")
    server, response = respond(KEY, b"D", initiator.hello)
    client = initiator.accept(KEY, response)
    archived = client.encrypt(b"past application data")
    assert server.decrypt(archived) == b"past application data"
    # A PSK holder can replay the captured HELLO, but cannot reproduce the erased
    # responder ephemeral private key from its recorded public key.
    attacker, fresh_response = respond(KEY, b"D", initiator.hello)
    assert fresh_response != response and attacker.id != server.id
    with pytest.raises(PacketError):
        attacker.decrypt(archived)
    assert initiator._noise is None


def test_exchange_mode_and_old_version_are_bound_without_downgrade():
    first, second = InitiatorHandshake(KEY, b"D"), InitiatorHandshake(KEY, b"D")
    server, response = respond(KEY, b"D", first.hello)
    try:
        with pytest.raises(PacketError, match="wrong handshake response"):
            second.accept(KEY, response)
        altered = first.hello[:4] + b"C" + first.hello[5:-32]
        with pytest.raises(PacketError, match="invalid Noise"):
            respond(KEY, b"C", sign(KEY, altered))
        with pytest.raises(PacketError):
            respond(KEY, b"D", b"PGH1" + first.hello[4:])
        assert first.hello[21:53] != second.hello[21:53]
    finally:
        first.close()
        second.close()


def test_close_releases_session_and_pending_keys():
    with connected() as (client, server, *_):
        client.close()
        assert client.session is None and not client.ready.is_set()
        handshake = InitiatorHandshake(KEY, b"D")
        server._receive(handshake.hello, True, time.monotonic() + 1)
        assert server._pending is not None
        server.close()
        assert server.session is None and server._pending is None
        handshake.close()
