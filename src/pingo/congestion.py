"""Bounded AIMD window and RTT-based pacing for best-effort VPN datagrams."""

import threading
import time


class Congestion:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.lock = threading.Lock()
        self.window = 4.0
        self.rtt = 0.1
        self.rto = 0.75
        self.pending = {}
        self.next_send = 0.0
        self.counter = 0
        self.last_loss = -float("inf")

    def _expire(self, now):
        lost = [key for key, sent in self.pending.items() if now - sent > self.rto]
        for key in lost:
            del self.pending[key]
        if lost and now - self.last_loss >= self.rto:
            self.window = max(1.0, self.window / 2)
            self.rto = min(5.0, self.rto * 2)
            self.last_loss = now

    def available(self):
        with self.lock:
            now = self.clock()
            self._expire(now)
            return len(self.pending) < int(self.window) and now >= self.next_send

    def sent(self):
        with self.lock:
            now = self.clock()
            identifier = self.counter
            self.counter += 1
            if identifier >= 2**64:
                raise OverflowError("VPN sequence exhausted; reconnect")
            self.pending[identifier] = now
            self.next_send = now + max(0.005, self.rtt / self.window)
            return identifier

    def acknowledge(self, identifier):
        with self.lock:
            sent = self.pending.pop(identifier, None)
            if sent is None:
                return
            elapsed = max(0.001, self.clock() - sent)
            self.rtt = 0.875 * self.rtt + 0.125 * elapsed
            self.rto = min(5.0, max(0.1, 4 * self.rtt))
            self.window = min(64.0, self.window + 1 / self.window)
