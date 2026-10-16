"""Bounded asynchronous packet logging; slow output must not stall networking."""

import json
import queue
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone


class Traffic:
    def __init__(self, mode="hex", stream=None, max_pending=512):
        if mode not in ("off", "summary", "hex"):
            raise ValueError("traffic mode must be off, summary, or hex")
        if type(max_pending) is not int or not 1 <= max_pending <= 8192:
            raise ValueError("max_pending must be 1..8192")
        self.mode = mode
        self.stream = stream if stream is not None else sys.stderr
        self.lock = threading.Lock()
        self.started = time.monotonic()
        self.packets = defaultdict(int)
        self.bytes = defaultdict(int)
        self.dropped = 0
        self.write_error = None
        self._lost_since_last = 0
        self._closed = False
        self._queue = queue.Queue(maxsize=max_pending) if mode != "off" else None
        self._worker = None
        if self._queue is not None:
            self._worker = threading.Thread(target=self._drain, name="pingo-traffic", daemon=True)
            self._worker.start()

    def packet(self, direction, data, peer, layer="icmp", **fields):
        if self._queue is None:
            return
        with self.lock:
            if self._closed:
                return
            key = (layer, direction)
            self.packets[key] += 1
            self.bytes[key] += len(data)
            if self.write_error is not None:
                self.dropped += 1
                return
            event = {
                "event": "traffic",
                "time": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                "direction": direction,
                "layer": layer,
                "peer": peer,
                "bytes": len(data),
                "packets_total": self.packets[key],
                "bytes_total": self.bytes[key],
                "bytes_per_second": round(
                    self.bytes[key] / max(time.monotonic() - self.started, 0.000001), 2
                ),
                **fields,
            }
            if self.mode == "hex" and layer == "icmp":
                event["wire_hex"] = data.hex()
            if self._lost_since_last:
                event["dropped_since_last"] = self._lost_since_last
            try:
                record = json.dumps(event, separators=(",", ":")) + "\n"
                self._queue.put_nowait(record)
            except queue.Full:
                self.dropped += 1
                self._lost_since_last += 1
            except (TypeError, ValueError, OverflowError):
                self.dropped += 1
                self._lost_since_last += 1
            else:
                self._lost_since_last = 0

    def _drain(self):
        while True:
            try:
                record = self._queue.get(timeout=0.05)
            except queue.Empty:
                with self.lock:
                    if self._closed:
                        return
                continue
            try:
                self.stream.write(record)
                self.stream.flush()
            except Exception as exc:
                # Broken or blocked diagnostics must not bring down the transport.
                with self.lock:
                    self.write_error = exc
                    self.dropped += 1
                    while True:
                        try:
                            self._queue.get_nowait()
                        except queue.Empty:
                            break
                        self.dropped += 1
                return

    def close(self, timeout=1.0):
        """Flush queued records on normal exit, with a bounded shutdown wait."""
        if self._queue is None:
            return
        with self.lock:
            self._closed = True
        if threading.current_thread() is not self._worker:
            self._worker.join(timeout=max(0.0, timeout))


class TracedCarrier:
    def __init__(self, carrier, traffic, peer):
        self.carrier, self.traffic, self.peer = carrier, traffic, peer

    def send(self, data):
        self.carrier.send(data)
        self.traffic.packet("tx", data, self.peer)

    def recv(self, timeout=0.2):
        data = self.carrier.recv(timeout)
        if data:
            self.traffic.packet("rx", data, self.peer)
        return data

    def close(self):
        self.carrier.close()
