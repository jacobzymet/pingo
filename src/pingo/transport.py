"""Application-independent authenticated sessions over a datagram carrier.

Carrier API: send(bytes), recv(timeout)->bytes|None, close(). A single reader owns
handshake/replay state. One receive callback may run at a time; it must not wait
for a reliable send. Timers and callback failures close the endpoint visibly.
"""

import logging
import threading
import time
from dataclasses import dataclass
from typing import Protocol

from .crypto import PacketError, Session
from .handshake import HELLO, InitiatorHandshake, respond

LOG = logging.getLogger(__name__)
FINISH, READY, PING, PONG = b"\x10", b"\x11", b"\x12", b"\x13"
MODES = {"direct": b"D", "vpn": b"C"}


@dataclass
class Pending:
    hello: bytes
    session: Session
    response: bytes
    expires: float


class Carrier(Protocol):
    def send(self, payload: bytes) -> None: ...
    def recv(self, timeout: float = 0.2) -> bytes | None: ...
    def close(self) -> None: ...


class Endpoint:
    def __init__(self, carrier: Carrier, key: bytes, mode: str = "direct", persistent=False):
        if len(key) != 32:
            raise ValueError("PSK must be 32 bytes")
        self.carrier = carrier
        self.key = key
        self.mode = MODES[mode]
        self.persistent = persistent
        self.session: Session | None = None
        self.ready = threading.Event()
        self.stopped = threading.Event()
        self.error: BaseException | None = None
        self.handler = lambda data: None
        self.on_session = lambda: None
        self.on_tick = lambda: None
        self._pending = None
        self._last_hello = 0.0
        self._last_rx = time.monotonic()
        self._last_ping = self._last_rx
        self._send_lock = threading.RLock()
        self._thread: threading.Thread | None = None

    def connect(self, attempts: int = 8, timeout: float = 0.75, stop=None) -> None:
        """Initiator handshake; call before starting the reader."""
        if self._thread is not None or self.session is not None:
            raise RuntimeError("connect requires a fresh endpoint")
        if not 1 <= attempts <= 20 or not 0.005 <= timeout <= 2:
            raise ValueError("invalid handshake retry bounds")
        handshake = InitiatorHandshake(self.key, self.mode)
        try:
            self._establish(handshake, attempts, timeout, stop)
        finally:
            handshake.close()

    def _establish(self, handshake, attempts, timeout, stop):
        session = None
        for _ in range(attempts):
            if stop is not None and stop.is_set():
                raise InterruptedError("connection cancelled")
            self.carrier.send(handshake.hello)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if stop is not None and stop.is_set():
                    raise InterruptedError("connection cancelled")
                packet = self.carrier.recv(min(0.2, max(0.001, deadline - time.monotonic())))
                if packet is None:
                    continue
                try:
                    session = handshake.accept(self.key, packet)
                    break
                except PacketError as exc:
                    if handshake.failed:
                        raise TimeoutError("peer sent an invalid Noise handshake response") from exc
            if session:
                break
        if session is None:
            raise TimeoutError(
                "peer did not authenticate; check addresses, key, mode, version and ICMP"
            )
        for _ in range(attempts):
            if stop is not None and stop.is_set():
                raise InterruptedError("connection cancelled")
            self.carrier.send(session.encrypt(FINISH + self.mode))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if stop is not None and stop.is_set():
                    raise InterruptedError("connection cancelled")
                packet = self.carrier.recv(min(0.2, max(0.001, deadline - time.monotonic())))
                if packet is None:
                    continue
                try:
                    if session.decrypt(packet) == READY + self.mode:
                        self.session = session
                        self._last_rx = self._last_ping = time.monotonic()
                        self.ready.set()
                        return
                except PacketError:
                    continue
        raise TimeoutError("peer did not confirm session")

    def start(self, responder: bool = False) -> None:
        if self._thread is not None:
            raise RuntimeError("endpoint already started")
        if not responder and self.session is None:
            raise RuntimeError("connect before starting initiator")
        self._thread = threading.Thread(target=self._run, args=(responder,), daemon=True)
        self._thread.start()

    def send(self, data: bytes) -> None:
        with self._send_lock:
            if self.stopped.is_set() or self.session is None:
                raise ConnectionError("endpoint has no active session")
            self.carrier.send(self.session.encrypt(data))

    def _hello(self, packet: bytes, now: float) -> None:
        if self._pending and now < self._pending.expires and packet == self._pending.hello:
            self.carrier.send(self._pending.response)
            return
        if now - self._last_hello < 0.25:
            return
        session, response = respond(self.key, self.mode, packet)
        self._last_hello = now
        self._pending = Pending(packet, session, response, now + 45)
        self.carrier.send(response)

    def _receive(self, packet: bytes, responder: bool, now: float) -> None:
        if responder and packet.startswith(HELLO):
            self._hello(packet, now)
            return
        if responder and self._pending and now < self._pending.expires:
            candidate = self._pending.session
            if packet[4:20] == candidate.id:
                data = candidate.decrypt(packet)
                if data != FINISH + self.mode:
                    raise PacketError("session requires confirmation")
                with self._send_lock:
                    self.on_session()
                    self.session = candidate
                    self._pending = None
                    self.ready.set()
                    self.send(READY + self.mode)
                self._last_rx = self._last_ping = now
                return
        if self.session is None:
            return
        data = self.session.decrypt(packet)
        self._last_rx = now
        if responder and data == FINISH + self.mode:
            self.send(READY + self.mode)
        elif data == PING:
            self.send(PONG)
        elif data not in (PONG, READY + self.mode):
            self.handler(data)

    def _run(self, responder: bool) -> None:
        try:
            while not self.stopped.is_set():
                packet = self.carrier.recv(0.2)
                now = time.monotonic()
                if packet:
                    try:
                        self._receive(packet, responder, now)
                    except PacketError:
                        pass
                if self._pending and now >= self._pending.expires:
                    self._pending = None
                self.on_tick()
                if self.session and now - self._last_ping >= 5:
                    self.send(PING)
                    self._last_ping = now
                if self.session and now - self._last_rx > 30:
                    if responder and (self.mode == MODES["direct"] or self.persistent):
                        with self._send_lock:
                            self.on_session()
                            self.session = None
                            self.ready.clear()
                    else:
                        raise TimeoutError("peer inactive for 30 seconds")
        except BaseException as exc:
            if not self.stopped.is_set():
                self.error = exc
                LOG.error("transport stopped: %s", exc)
        finally:
            self.stopped.set()

    def check(self) -> None:
        if self.error:
            raise ConnectionError(str(self.error)) from self.error
        if self.stopped.is_set():
            raise ConnectionError("endpoint stopped")

    def close(self) -> None:
        self.stopped.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=3)
        self.carrier.close()
        with self._send_lock:
            self._pending = None
            self.session = None
            self.ready.clear()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
