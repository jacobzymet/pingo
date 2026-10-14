"""Bounded stop-and-wait fragmentation and application-result acknowledgments."""

import math
import struct
import threading
import time
from collections import OrderedDict

from .crypto import PacketError
from .transport import Endpoint

FRAME = struct.Struct("!B16sHH")
DATA, ACK = 1, 2
FRAGMENT = 1000
MAX_MESSAGE = 65536
MAX_FRAGMENTS = math.ceil(MAX_MESSAGE / FRAGMENT)
MAX_RESULT = 256


class RemoteError(RuntimeError):
    pass


class Reliable:
    def __init__(self, endpoint: Endpoint, handler=None, attempts=8, timeout=0.75):
        self.endpoint = endpoint
        self.handler = handler or (lambda data: b"")
        self.attempts, self.timeout = attempts, timeout
        if not 1 <= attempts <= 20 or not 0.005 <= timeout <= 2:
            raise ValueError("invalid retry bounds")
        self.rto = timeout
        self._srtt = None
        self._variance = None
        self._lock = threading.Lock()
        self._waiter_lock = threading.Lock()
        self._waiter = None
        self._incoming = OrderedDict()
        self._completed = OrderedDict()
        self._send_counter = 0
        self._highest_completed = -1
        endpoint.handler = self.receive
        endpoint.on_session = self.reset
        endpoint.on_tick = self.expire

    def reset(self) -> None:
        self._incoming.clear()
        self._completed.clear()
        self._highest_completed = -1
        with self._waiter_lock:
            if self._waiter:
                self._waiter[3].append(b"\x01session replaced")
                self._waiter[2].set()

    def expire(self) -> None:
        now = time.monotonic()
        for key, value in list(self._incoming.items()):
            if now - value[3] > 45:
                del self._incoming[key]
        for key, value in list(self._completed.items()):
            if now - value[2] > 60:
                del self._completed[key]

    def send(self, blob: bytes) -> bytes:
        if not 0 < len(blob) <= MAX_MESSAGE:
            raise ValueError("reliable message must contain 1..65536 bytes")
        with self._lock:
            if self._send_counter >= 2**64:
                raise OverflowError("operation counter exhausted; reconnect")
            identifier = self._send_counter.to_bytes(16, "big")
            self._send_counter += 1
            count = math.ceil(len(blob) / FRAGMENT)
            result = b""
            for index in range(count):
                event, replies = threading.Event(), []
                with self._waiter_lock:
                    self._waiter = (identifier, index, event, replies)
                try:
                    frame = (
                        FRAME.pack(DATA, identifier, index, count)
                        + blob[index * FRAGMENT : (index + 1) * FRAGMENT]
                    )
                    for attempt in range(self.attempts):
                        self.endpoint.check()
                        started = time.monotonic()
                        self.endpoint.send(frame)  # Each retry gets a fresh AEAD counter.
                        if event.wait(self.rto):
                            if attempt == 0:
                                self._sample(time.monotonic() - started)
                            break
                        self.rto = min(2.0, self.rto * 2)
                    else:
                        raise TimeoutError(f"fragment {index + 1}/{count} not acknowledged")
                    result = replies[0]
                    if not result or result[0] != 0:
                        raise RemoteError(result[1:].decode("utf-8", errors="replace"))
                finally:
                    with self._waiter_lock:
                        self._waiter = None
            return result[1:]

    def _sample(self, elapsed):
        # Karn's rule: retransmitted fragments do not contribute RTT samples.
        if self._srtt is None:
            self._srtt, self._variance = elapsed, elapsed / 2
        else:
            self._variance = 0.75 * self._variance + 0.25 * abs(self._srtt - elapsed)
            self._srtt = 0.875 * self._srtt + 0.125 * elapsed
        self.rto = min(2.0, max(self.timeout, self._srtt + 4 * self._variance))

    def receive(self, packet: bytes) -> None:
        if len(packet) < FRAME.size:
            raise PacketError("short reliable frame")
        kind, identifier, index, count = FRAME.unpack_from(packet)
        body = packet[FRAME.size :]
        if not 1 <= count <= MAX_FRAGMENTS or index >= count:
            raise PacketError("invalid fragment coordinates")
        if kind == ACK:
            if not 1 <= len(body) <= MAX_RESULT or body[0] not in (0, 1):
                raise PacketError("invalid acknowledgment")
            with self._waiter_lock:
                waiter = self._waiter
                if waiter and waiter[:2] == (identifier, index) and not waiter[3]:
                    waiter[3].append(body)
                    waiter[2].set()
            return
        if kind != DATA or not 0 < len(body) <= FRAGMENT:
            raise PacketError("invalid data frame")
        if index < count - 1 and len(body) != FRAGMENT:
            raise PacketError("short non-final fragment")
        self.expire()
        if identifier in self._completed:
            old_count, result, _ = self._completed[identifier]
            if old_count != count:
                raise PacketError("fragment count changed")
            self._ack(identifier, index, count, result if index == count - 1 else b"\x00")
            return
        if int.from_bytes(identifier, "big") <= self._highest_completed:
            return  # Retired result: never repeat an application action after cache expiry.
        if identifier not in self._incoming:
            if index != 0 or len(self._incoming) >= 4:
                return  # Do not acknowledge an unbuffered fragment.
            self._incoming[identifier] = [count, 0, bytearray(), time.monotonic()]
        state = self._incoming[identifier]
        if state[0] != count:
            raise PacketError("fragment count changed")
        if index < state[1]:
            self._ack(identifier, index, count, b"\x00")
            return
        if index != state[1]:
            return
        if len(state[2]) + len(body) > MAX_MESSAGE:
            del self._incoming[identifier]
            self._ack(identifier, index, count, b"\x01message too large")
            return
        state[2].extend(body)
        state[1] += 1
        state[3] = time.monotonic()
        result = b"\x00"
        if state[1] == count:
            del self._incoming[identifier]
            try:
                response = self.handler(bytes(state[2]))
                if not isinstance(response, bytes) or len(response) >= MAX_RESULT:
                    raise ValueError("invalid application response")
                result += response
            except (ValueError, OSError, RemoteError) as exc:
                result = b"\x01" + str(exc).encode("utf-8")[: MAX_RESULT - 1]
            self._completed[identifier] = (count, result, time.monotonic())
            self._highest_completed = max(
                self._highest_completed, int.from_bytes(identifier, "big")
            )
            while len(self._completed) > 128:
                self._completed.popitem(last=False)
        self._ack(identifier, index, count, result)

    def _ack(self, identifier, index, count, result):
        self.endpoint.send(FRAME.pack(ACK, identifier, index, count) + result)
