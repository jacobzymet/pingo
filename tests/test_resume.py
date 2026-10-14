import json
import os

import pytest

from pingo.direct import CHUNK, END
from pingo.resume import RESUME, ResumableReceiver, send_resumable

from .helpers import connected


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFOs")
def test_named_pipe_is_rejected_without_waiting_for_a_writer(tmp_path):
    path = tmp_path / "pipe"
    os.mkfifo(path, 0o600)
    with pytest.raises(ValueError, match="regular"):
        send_resumable(None, path)


class RestartingChannel:
    def __init__(self, directory, fail_kind):
        self.directory, self.fail_kind = directory, fail_kind
        self.failed = False
        self.offsets = []
        self.recover()

    def recover(self):
        if hasattr(self, "context"):
            self.context.__exit__(None, None, None)
            self.receiver.suspend()
        self.receiver = ResumableReceiver(self.directory)
        self.context = connected(handler=self.receiver.handle)
        self.channel = self.context.__enter__()[2]

    def send(self, data):
        result = self.channel.send(data)
        if data[0] == RESUME:
            self.offsets.append(json.loads(result).get("offset"))
        if data[0] == self.fail_kind and not self.failed:
            self.failed = True
            raise TimeoutError("receiver committed, acknowledgment lost, process restarted")
        return result

    def close(self):
        self.context.__exit__(None, None, None)
        self.receiver.suspend()


@pytest.mark.parametrize("kind", [CHUNK, END])
def test_resume_after_receiver_restart_and_lost_ack(tmp_path, kind):
    source = tmp_path / "file.bin"
    data = os.urandom(80000)
    source.write_bytes(data)
    channel = RestartingChannel(tmp_path / "received", kind)
    try:
        name = send_resumable(channel, source)
        assert (channel.directory / name).read_bytes() == data
        assert len(list(channel.directory.glob("*-file.bin"))) == 1
        assert not list(channel.directory.glob("*.part"))
        if kind == CHUNK:
            assert channel.offsets == [0, 32768]
        else:
            assert channel.offsets == [0, None]
        assert send_resumable(channel, source) == name
    finally:
        channel.close()


def test_corrupted_prefix_is_never_resumed(tmp_path):
    source = tmp_path / "file.bin"
    source.write_bytes(os.urandom(80000))
    channel = RestartingChannel(tmp_path / "received", CHUNK)
    original = channel.recover

    def corrupt_then_recover():
        channel.receiver.suspend()
        partial = next(channel.directory.glob("*.part"))
        with partial.open("r+b") as stream:
            stream.write(b"corrupt")
        original()

    channel.recover = corrupt_then_recover
    try:
        with pytest.raises(ValueError, match="differs from source"):
            send_resumable(channel, source)
        assert not list(channel.directory.glob("*-file.bin"))
    finally:
        channel.close()


def test_resume_preserves_checkpoint_ending_in_windows_eof_marker(tmp_path):
    source = tmp_path / "file.bin"
    data = b"a" * 32767 + b"\x1a" + b"remaining bytes"
    source.write_bytes(data)
    channel = RestartingChannel(tmp_path / "received", CHUNK)
    try:
        name = send_resumable(channel, source)
        assert (channel.directory / name).read_bytes() == data
        assert channel.offsets == [0, 32768]
    finally:
        channel.close()


def test_resume_records_are_bounded_and_expire(tmp_path, monkeypatch):
    channel = RestartingChannel(tmp_path / "out", CHUNK)
    source = tmp_path / "a.bin"
    source.write_bytes(b"a" * 80000)
    try:
        send_resumable(channel, source)
        record = next(channel.directory.glob("*.resume.json"))
        completed = next(channel.directory.glob("*-a.bin"))
        os.utime(record, (1, 1))
        channel.receiver._last_expire = 0
        channel.receiver.expire()
        assert not record.exists() and completed.exists()
        monkeypatch.setattr("pingo.resume.MAX_RECORDS", 0)
        with pytest.raises(RuntimeError, match="resume-record limit"):
            send_resumable(channel, source)
    finally:
        channel.close()


def test_pending_files_reserve_quota_across_sessions(tmp_path):
    receiver = ResumableReceiver(tmp_path, max_file_bytes=4096, max_receive_bytes=4096)

    def request(identifier, size):
        return (
            bytes([RESUME])
            + json.dumps(
                {
                    "id": identifier * 32,
                    "name": "a",
                    "size": size,
                    "digest": "0" * 64,
                }
            ).encode()
        )

    receiver.handle(request("1", 3000))
    receiver.suspend()
    with pytest.raises(ValueError, match="quota"):
        receiver.handle(request("2", 1000))
    reply = json.loads(receiver.handle(request("1", 3000)))
    assert reply["offset"] == 0
    receiver.suspend()


def test_completed_file_recovery_does_not_reserve_its_bytes_twice(tmp_path):
    receiver = ResumableReceiver(tmp_path / "out", max_file_bytes=4096, max_receive_bytes=8192)
    source = tmp_path / "a.bin"
    source.write_bytes(b"a" * 3000)
    with connected(handler=receiver.handle) as (_, _, sender, _):
        name = send_resumable(sender, source)
        next(receiver.directory.glob("*.resume.json")).unlink()
        (receiver.directory / "unrelated.bin").write_bytes(b"b" * 3000)
        assert send_resumable(sender, source) == name
        assert len(list(receiver.directory.glob("*-a.bin"))) == 1


@pytest.mark.parametrize(
    "response",
    [b"[]", b"{}", b'{"complete": 1}', b'{"complete": false, "offset": false, "prefix":"x"}'],
)
def test_invalid_resume_responses_are_rejected(tmp_path, response):
    source = tmp_path / "a.bin"
    source.write_bytes(b"hello")
    channel = type("InvalidChannel", (), {"send": lambda *_: response})()
    with pytest.raises(ValueError, match="invalid"):
        send_resumable(channel, source)


def test_uncheckpointed_trailing_bytes_are_truncated_on_resume(tmp_path):
    source = tmp_path / "file.bin"
    source.write_bytes(os.urandom(80000))
    channel = RestartingChannel(tmp_path / "received", CHUNK)
    original = channel.recover

    def append_uncommitted_then_recover():
        channel.receiver.suspend()
        partial = next(channel.directory.glob("*.part"))
        with partial.open("ab") as stream:
            stream.write(b"bytes written before the checkpoint transaction")
        original()

    channel.recover = append_uncommitted_then_recover
    try:
        name = send_resumable(channel, source)
        assert (channel.directory / name).read_bytes() == source.read_bytes()
        assert channel.offsets == [0, 32768]
    finally:
        channel.close()
