"""Offline representation and scheduling models; never used by the transport."""

import heapq
from collections import Counter
from dataclasses import replace

from .crypto import MAX_WIRE


class DistributionCodec:
    """Map ciphertext bits to a learned byte alphabet using a prefix tree.

    Symbol probabilities are dyadic approximations, not exact distribution matching.
    The four-byte length prefix and expansion remain observable.
    """

    def __init__(self, frequencies):
        counts = Counter(frequencies)
        if len(counts) < 2 or any(
            not isinstance(k, int) or not 0 <= k <= 255 or v <= 0 for k, v in counts.items()
        ):
            raise ValueError("distribution encoding needs at least two observed byte symbols")
        heap = [
            (count, index, symbol) for index, (symbol, count) in enumerate(sorted(counts.items()))
        ]
        heapq.heapify(heap)
        order = len(heap)
        while len(heap) > 1:
            left, right = heapq.heappop(heap), heapq.heappop(heap)
            heapq.heappush(heap, (left[0] + right[0], order, (left[2], right[2])))
            order += 1
        self.tree = heap[0][2]
        self.codes = {}

        def visit(node, prefix):
            if isinstance(node, int):
                self.codes[node] = prefix
            else:
                visit(node[0], prefix + "0")
                visit(node[1], prefix + "1")

        visit(self.tree, "")

    def encode(self, data):
        if len(data) > MAX_WIRE:
            raise ValueError("experimental input exceeds the Pingo packet limit")
        output = bytearray(len(data).to_bytes(4, "big"))
        node = self.tree
        for byte in data:
            for shift in range(7, -1, -1):
                node = node[(byte >> shift) & 1]
                if isinstance(node, int):
                    output.append(node)
                    node = self.tree
        if node is not self.tree:
            while not isinstance(node, int):
                node = node[0]
            output.append(node)
        return bytes(output)

    def decode(self, encoded):
        if not 4 <= len(encoded) <= 4 + MAX_WIRE * 8:
            raise ValueError("invalid experimental encoding length")
        length = int.from_bytes(encoded[:4], "big")
        if length > MAX_WIRE:
            raise ValueError("invalid decoded packet length")
        try:
            bits = "".join(self.codes[byte] for byte in encoded[4:])
        except KeyError as exc:
            raise ValueError("byte outside the learned alphabet") from exc
        needed = length * 8
        if len(bits) < needed:
            raise ValueError("truncated experimental encoding")
        data = bytes(int(bits[i : i + 8], 2) for i in range(0, needed, 8))
        if self.encode(data) != encoded:
            raise ValueError("noncanonical experimental encoding")
        return data


def pad(data, bucket):
    if not 32 <= bucket <= MAX_WIRE or len(data) > MAX_WIRE:
        raise ValueError("padding bucket must be 32..1200 bytes")
    body = len(data).to_bytes(4, "big") + data
    return body + bytes((-len(body)) % bucket)


def unpad(data):
    if len(data) < 4:
        raise ValueError("truncated padding frame")
    length = int.from_bytes(data[:4], "big")
    if length > MAX_WIRE or length + 4 > len(data) or any(data[length + 4 :]):
        raise ValueError("invalid padding frame")
    return data[4 : length + 4]


def transform(packets, strategy, rng, codec=None, bucket=128, max_delay_ms=100):
    if strategy not in ("distribution", "padding", "jitter"):
        raise ValueError("unknown experiment")
    previous = float("-inf")
    result, delays = [], []
    total_bytes = 0
    for packet in packets:
        payload, timestamp = packet.payload, packet.timestamp
        if strategy == "distribution":
            payload = codec.encode(payload)
            assert codec.decode(payload) == packet.payload
        elif strategy == "padding":
            payload = pad(payload, bucket)
            assert unpad(payload) == packet.payload
        else:
            timestamp = max(previous, timestamp + rng.uniform(0, max_delay_ms / 1000))
        previous = timestamp
        delays.append((timestamp - packet.timestamp) * 1000)
        total_bytes += len(payload)
        if total_bytes > 128 * 1024 * 1024:
            raise ValueError("experiment exceeds 128 MiB; use a shorter capture")
        result.append(
            replace(
                packet,
                payload=payload,
                timestamp=timestamp,
                size=packet.size + len(payload) - len(packet.payload),
            )
        )
    return result, delays
