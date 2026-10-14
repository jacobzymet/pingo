import hashlib
import json
import os
import time

import pytest

from pingo.direct import ABORT, BEGIN, CHUNK, CHUNK_HEADER, END, Receiver, send_file, send_message
from pingo.reliable import RemoteError

from .helpers import connected


def begin(identifier, name, size):
    return (
        bytes([BEGIN]) + json.dumps({"id": identifier.hex(), "name": name, "size": size}).encode()
    )


def test_messages_and_streaming_files_under_loss(tmp_path):
    seen = []
    receiver = Receiver(tmp_path / "received", on_message=seen.append)
    data = os.urandom(160000)
    source = tmp_path / "source.bin"
    source.write_bytes(data)

    def attach(_client, _server, _sender, channel):
        receiver.attach(channel)

    try:
        with connected(before_connect=attach) as (client, server, sender, _):
            client.carrier.drop_every = 9
            server.carrier.drop_every = 7
            assert send_message(sender, "你好\nhello") == "message received"
            assert seen == ["你好\nhello"]
            name = send_file(sender, source)
            assert (receiver.directory / name).read_bytes() == data
            assert not list(receiver.directory.glob("*.part"))
            assert receiver.active is None
    finally:
        receiver.abort()


@pytest.mark.parametrize(
    "data",
    [b"", b"tiny", b"x" * 32768, b"x" * 65536],
    ids=["empty", "tiny", "one-chunk", "two-chunks"],
)
def test_file_sizes(tmp_path, data):
    receiver = Receiver(tmp_path / "out")
    path = tmp_path / "file.bin"
    path.write_bytes(data)
    with connected(handler=receiver.handle) as (_, _, sender, _):
        result = send_file(sender, path)
        assert (receiver.directory / result).read_bytes() == data


def test_hash_failure_never_completes(tmp_path):
    receiver = Receiver(tmp_path)
    identifier = os.urandom(16)
    receiver.handle(begin(identifier, "bad.bin", 3))
    receiver.handle(bytes([CHUNK]) + CHUNK_HEADER.pack(identifier, 0) + b"abc")
    with pytest.raises(ValueError, match="verification failed"):
        receiver.handle(bytes([END]) + identifier + b"\x00" * 32)
    assert not list(tmp_path.iterdir())
    assert receiver.active is None


def test_no_path_traversal_or_overwrite(tmp_path):
    receiver = Receiver(tmp_path / "out")
    identifier = b"a" * 16
    receiver.handle(begin(identifier, "../../CON", 0))
    name = receiver.handle(bytes([END]) + identifier + hashlib.sha256(b"").digest()).decode()
    final = receiver.directory / name
    assert final.parent == receiver.directory
    assert final.exists()
    assert "/" not in name and "\\" not in name
    final.write_bytes(b"preserve")
    receiver.handle(begin(identifier, "../../CON", 0))
    with pytest.raises(FileExistsError):
        receiver.handle(bytes([END]) + identifier + hashlib.sha256(b"").digest())
    assert final.read_bytes() == b"preserve"
    assert not list(receiver.directory.glob("*.part"))


def test_quotas_and_sender_limits(tmp_path):
    receiver = Receiver(tmp_path, max_file_bytes=10, max_receive_bytes=12)
    with pytest.raises(ValueError, match="size limit"):
        receiver.handle(begin(os.urandom(16), "big", 11))
    (tmp_path / "existing").write_bytes(b"x" * 8)
    with pytest.raises(ValueError, match="quota"):
        receiver.handle(begin(os.urandom(16), "quota", 5))
    with connected(handler=receiver.handle) as (_, _, sender, _):
        with pytest.raises(RemoteError, match="size limit"):
            sender.send(begin(os.urandom(16), "big", 11))
        with pytest.raises(ValueError):
            send_message(sender, "x" * 60001)
        with pytest.raises(ValueError):
            send_file(sender, tmp_path / "existing", max_file_bytes=7)


def test_offset_size_abort_and_expiry(tmp_path):
    receiver = Receiver(tmp_path)
    identifier = os.urandom(16)
    receiver.handle(begin(identifier, "test", 3))
    with pytest.raises(ValueError, match="offset"):
        receiver.handle(bytes([CHUNK]) + CHUNK_HEADER.pack(identifier, 1) + b"abc")
    assert not list(tmp_path.iterdir())
    receiver.handle(begin(identifier, "test", 3))
    with pytest.raises(ValueError, match="declared size"):
        receiver.handle(bytes([CHUNK]) + CHUNK_HEADER.pack(identifier, 0) + b"abcd")
    receiver.handle(begin(identifier, "test", 0))
    receiver.handle(bytes([ABORT]) + identifier)
    assert receiver.active is None
    receiver.handle(begin(identifier, "test", 0))
    receiver.active["touched"] = time.monotonic() - 61
    receiver.expire()
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "metadata",
    [
        b"[]",
        b"{}",
        b"not json",
        b'{"id": 1, "name": "x", "size": 1}',
        b'{"id": "xx", "name": "x", "size": 1}',
    ],
)
def test_malformed_metadata(tmp_path, metadata):
    receiver = Receiver(tmp_path)
    with pytest.raises(ValueError):
        receiver.handle(bytes([BEGIN]) + metadata)
    assert receiver.active is None


def test_session_change_cleans_partial_file(tmp_path):
    receiver = Receiver(tmp_path)

    def attach(_client, _server, _sender, channel):
        receiver.attach(channel)

    with connected(before_connect=attach) as (_, server, sender, _):
        sender.send(begin(os.urandom(16), "unfinished", 100))
        assert receiver.active
        server.on_session()
        assert receiver.active is None
        assert not list(tmp_path.iterdir())
