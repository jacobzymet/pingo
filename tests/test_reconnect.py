import errno
import threading

import pytest

from pingo.reconnect import Connector
from pingo.reliable import RemoteError
from pingo.transport import Endpoint

from .helpers import KEY, carriers


class ImmediateStop:
    def __init__(self):
        self.delays = []
        self.cancel = False

    def is_set(self):
        return self.cancel

    def wait(self, delay):
        self.delays.append(delay)
        return self.cancel


def test_connector_replaces_failed_socket_with_fresh_authenticated_session():
    endpoints = []
    peers = []
    stop = ImmediateStop()

    def factory():
        a, b = carriers()
        client, server = Endpoint(a, KEY), Endpoint(b, KEY)
        endpoints.append(client)
        peers.append(server)
        if len(endpoints) > 1:
            server.start(responder=True)
        return client

    connector = Connector(factory, stop, attempts=1, timeout=0.005, reconnects=1)
    try:
        connector.connect()
        first_session = connector.endpoint.session.id
        assert len(endpoints) == 2 and endpoints[0].carrier.closed
        assert stop.delays == [0.5]
        connector.recover()
        assert connector.endpoint.session.id != first_session
        assert endpoints[1].carrier.closed
    finally:
        connector.close()
        for peer in peers:
            peer.close()


def test_connector_closes_endpoint_on_interrupt_without_retry():
    a, b = carriers()
    endpoint = Endpoint(a, KEY)

    def interrupt(*_):
        raise KeyboardInterrupt

    endpoint.connect = interrupt
    with pytest.raises(KeyboardInterrupt):
        Connector(lambda: endpoint, threading.Event()).connect()
    assert a.closed
    b.close()


def test_messages_are_never_automatically_replayed_after_ambiguous_failure():
    connector = Connector(lambda: pytest.fail("must not reconnect"), threading.Event())

    class Channel:
        def send(self, _):
            raise TimeoutError("possibly already executed")

    connector.channel = Channel()
    with pytest.raises(TimeoutError):
        connector.send(b"message")
    connector.channel = type(
        "Reject", (), {"send": lambda *_: (_ for _ in ()).throw(RemoteError("peer rejected"))}
    )()
    with pytest.raises(RemoteError):
        connector.send(b"message")



def test_connector_retries_socket_factory_failure():
    stop = ImmediateStop()
    attempts = []
    peers = []

    def factory():
        attempts.append(1)
        if len(attempts) == 1:
            raise OSError(errno.ENETDOWN, "temporary network outage")
        a, b = carriers()
        client, server = Endpoint(a, KEY), Endpoint(b, KEY)
        peers.append(server)
        server.start(responder=True)
        return client

    connector = Connector(factory, stop, attempts=4, timeout=0.02, reconnects=1)
    try:
        connector.connect()
        assert len(attempts) == 2
        assert stop.delays == [0.5]
        assert connector.endpoint.ready.is_set()
    finally:
        connector.close()
        for peer in peers:
            peer.close()


@pytest.mark.parametrize(
    "error",
    [
        PermissionError("raw socket needs privileges"),
        FileNotFoundError(errno.ENOENT, "required runtime missing"),
        ValueError("invalid configuration"),
        RuntimeError("programming error"),
    ],
)
def test_connector_does_not_retry_permanent_factory_error(error):
    attempts = []
    stop = ImmediateStop()

    def factory():
        attempts.append(1)
        raise error

    with pytest.raises(type(error)):
        Connector(factory, stop, reconnects=3).connect()
    assert len(attempts) == 1
    assert stop.delays == []
