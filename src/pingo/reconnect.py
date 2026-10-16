"""Reconnect supervisors never retry ambiguous message operations automatically."""

import errno
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
            endpoint = None
            try:
                endpoint = self.factory()
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
                if endpoint is not None:
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


# Retry temporary network failures, not permanent setup or application errors.
_TRANSIENT_ERRNOS = {
    errno.EAGAIN,
    errno.EINTR,
    errno.ENOBUFS,
    errno.ECONNABORTED,
    errno.ECONNREFUSED,
    errno.ECONNRESET,
    errno.ENETDOWN,
    errno.ENETUNREACH,
    errno.EHOSTUNREACH,
    errno.EPIPE,
    errno.ETIMEDOUT,
    errno.EIO,  # Capture devices can disappear during interface changes.
}
# Native Windows socket error numbers may not be translated to POSIX errno.
_TRANSIENT_ERRNOS.update({10004, 10035, 10050, 10051, 10052, 10053, 10054, 10055, 10060, 10061, 10065})


def recoverable(error):
    if isinstance(error, (RemoteError, InterruptedError, PermissionError)):
        return False
    if isinstance(error, (ConnectionError, TimeoutError)):
        return True
    if isinstance(error, OSError):
        return error.errno is None or error.errno in _TRANSIENT_ERRNOS
    return False
