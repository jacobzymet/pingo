import os
import time

import pytest

from pingo.crypto import PacketError, Session, sign
from pingo.transport import FINISH, HELLO, READY, Endpoint

from .helpers import KEY, carriers, connected


@pytest.mark.parametrize("dropped", ["hello", "response", "ready"])
def test_handshake_recovers_loss(dropped):
    def configure(client, server, *_):
        if dropped == "hello":
            client.carrier.drop_next = 1
        elif dropped == "response":
            server.carrier.drop_next = 1
        else:
            original = server.carrier.send

            def send(data):
                if data.startswith(b"PG01"):
                    server.carrier.send = original
                    return
                original(data)

            server.carrier.send = send

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
    c = os.urandom(32)
    hello = sign(KEY, HELLO + b"D" + c)
    old = Endpoint(b, KEY)
    old._receive(hello, True, time.monotonic())
    response = b.sent[-1]
    old_client = Session(KEY, c, response[37:69], True)
    finish = old_client.encrypt(FINISH + b"D")
    old._receive(finish, True, time.monotonic())
    assert old.session is not None
    restarted = Endpoint(b, KEY)
    restarted._receive(hello, True, time.monotonic())
    assert b.sent[-1] != response
    restarted._receive(finish, True, time.monotonic())
    assert restarted.session is None
    assert not restarted.ready.is_set()
    old.close()
    a.close()


def test_confirmation_required():
    a, b = carriers()
    endpoint = Endpoint(b, KEY)
    c = os.urandom(32)
    endpoint._receive(sign(KEY, HELLO + b"D" + c), True, time.monotonic())
    session = Session(KEY, c, b.sent[-1][37:69], True)
    with pytest.raises(PacketError):
        endpoint._receive(session.encrypt(b"premature data"), True, time.monotonic())
    assert not endpoint.ready.is_set()
    endpoint.close()
    a.close()


def test_congestion_vpn_rejects_legacy_mode_before_adopting_session():
    a, b = carriers()
    endpoint = Endpoint(b, KEY, mode="vpn")
    try:
        with pytest.raises(PacketError, match="wrong application mode"):
            endpoint._receive(sign(KEY, HELLO + b"V" + os.urandom(32)), True, time.monotonic())
        assert endpoint.session is None and endpoint._pending is None
    finally:
        endpoint.close()
        a.close()


def test_new_session_replaces_old_after_confirmation_only():
    with connected() as (client, server, sender, receiver):
        old = server.session
        c = os.urandom(32)
        server._receive(sign(KEY, HELLO + b"D" + c), True, time.monotonic() + 1)
        assert server.session is old
        response = server.carrier.sent[-1]
        replacement = Session(KEY, c, response[37:69], True)
        server._receive(replacement.encrypt(FINISH + b"D"), True, time.monotonic() + 1)
        assert server.session.id == replacement.id
        assert replacement.decrypt(server.carrier.sent[-1]) == READY + b"D"
