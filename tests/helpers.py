import queue
import socket
import struct
from contextlib import contextmanager

from pingo.icmp import checksum
from pingo.reliable import Reliable
from pingo.transport import Endpoint

KEY = bytes(range(32))


class MemoryCarrier:
    def __init__(self):
        self.inbox = queue.Queue(maxsize=256)
        self.peer = None
        self.sent = []
        self.drop_next = 0
        self.drop_every = 0
        self.duplicate_every = 0
        self.closed = False

    def send(self, data):
        if self.closed:
            raise OSError("carrier closed")
        self.sent.append(data)
        number = len(self.sent)
        if self.drop_next:
            self.drop_next -= 1
            return
        if self.drop_every and number % self.drop_every == 0:
            return
        try:
            self.peer.inbox.put_nowait(data)
            if self.duplicate_every and number % self.duplicate_every == 0:
                self.peer.inbox.put_nowait(data)
        except queue.Full:
            pass

    def recv(self, timeout=0.2):
        try:
            return self.inbox.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self):
        self.closed = True


def carriers():
    a, b = MemoryCarrier(), MemoryCarrier()
    a.peer, b.peer = b, a
    return a, b


@contextmanager
def connected(handler=None, mode="direct", before_connect=None):
    a, b = carriers()
    client, server = Endpoint(a, KEY, mode), Endpoint(b, KEY, mode)
    sender, receiver = (
        Reliable(client, attempts=8, timeout=0.01),
        Reliable(server, handler=handler, attempts=8, timeout=0.01),
    )
    if before_connect:
        before_connect(client, server, sender, receiver)
    try:
        server.start(responder=True)
        client.connect(attempts=8, timeout=0.02)
        client.start()
        yield client, server, sender, receiver
    finally:
        client.close()
        server.close()


def ipv4(payload=b"", source="192.0.2.10", destination="192.0.2.20", protocol=1):
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        0,
        0,
        64,
        protocol,
        0,
        socket.inet_aton(source),
        socket.inet_aton(destination),
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload
