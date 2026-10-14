"""Flushed, packet-by-packet JSON telemetry; wire dumps contain ciphertext only."""

import json
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone


class Traffic:
    def __init__(self, mode="hex", stream=None):
        if mode not in ("off", "summary", "hex"):
            raise ValueError("traffic mode must be off, summary, or hex")
        self.mode = mode
        self.stream = stream if stream is not None else sys.stderr
        self.lock = threading.Lock()
        self.started = time.monotonic()
        self.packets = defaultdict(int)
        self.bytes = defaultdict(int)

    def packet(self, direction, data, peer, layer="icmp", **fields):
        if self.mode == "off":
            return
        with self.lock:
            key = (layer, direction)
            self.packets[key] += 1
            self.bytes[key] += len(data)
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
            self.stream.write(json.dumps(event, separators=(",", ":")) + "\n")
            self.stream.flush()


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
