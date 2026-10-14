"""Reconnect supervisors never retry ambiguous message operations automatically."""

import logging

from .reliable import Reliable, RemoteError

LOG = logging.getLogger(__name__)


class Connector:
    def __init__(self, factory, stop, attempts=8, timeout=0.75, reconnects=10, on_event=None):
        self.factory, self.stop = factory, stop
        self.attempts, self.timeout, self.reconnects = attempts, timeout, reconnects
        self.endpoint = None
        self.channel = None
        self.on_event = on_event or (lambda *_args, **_kwargs: None)

    def connect(self):
        self.close()
        for failure in range(self.reconnects + 1):
            if self.stop.is_set():
                raise InterruptedError("connection cancelled")
            endpoint = self.factory()
            try:
                self.on_event("state", state="connecting")
                channel = Reliable(
                    endpoint, attempts=self.attempts, timeout=self.timeout, stop=self.stop
                )
                endpoint.connect(self.attempts, self.timeout, self.stop)
                endpoint.start()
                self.endpoint, self.channel = endpoint, channel
                self.on_event("state", state="connected")
                return
            except BaseException as exc:
                endpoint.close()
                if not recoverable(exc) or failure == self.reconnects:
                    raise
                delay = min(0.5 * 2 ** min(failure, 5), 10)
                self.on_event("state", state="reconnecting", delay=delay, attempt=failure + 1)
                LOG.warning("Peer unavailable; reconnecting in %.1fs", delay)
                if self.stop.wait(delay):
                    raise InterruptedError("connection cancelled") from None

    def send(self, data):
        if self.channel is None:
            self.connect()
        return self.channel.send(data)

    def recover(self):
        self.connect()

    def close(self):
        if self.endpoint:
            self.endpoint.close()
        self.endpoint = self.channel = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def recoverable(error):
    return isinstance(error, (OSError, RuntimeError)) and not isinstance(
        error, (RemoteError, InterruptedError, PermissionError)
    )
