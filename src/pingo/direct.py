"""Messages and streaming files with end-to-end completion results."""

import hashlib
import json
import os
import re
import stat
import struct
import tempfile
import time
from pathlib import Path

from .permissions import preserve_desktop_owner
from .reliable import Reliable

MESSAGE, BEGIN, CHUNK, END, ABORT = 32, 33, 34, 35, 36
CHUNK_SIZE = 32768
CHUNK_HEADER = struct.Struct("!16sQ")


class Receiver:
    def __init__(
        self,
        directory: Path,
        max_file_bytes=64 * 1024**2,
        max_receive_bytes=256 * 1024**2,
        on_message=None,
    ):
        self.directory = directory
        existing = directory.exists()
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not existing:
            preserve_desktop_owner(directory)
        self.max_file_bytes = max_file_bytes
        self.max_receive_bytes = max_receive_bytes
        self.on_message = on_message or (lambda text: None)
        self.active = None

    def attach(self, channel: Reliable) -> None:
        channel.handler = self.handle

        def reset():
            self.abort()
            channel.reset()

        def tick():
            self.expire()
            channel.expire()

        channel.endpoint.on_session = reset
        channel.endpoint.on_tick = tick

    def expire(self) -> None:
        if self.active and time.monotonic() - self.active["touched"] > 60:
            self.abort()

    def abort(self) -> None:
        if self.active:
            state, self.active = self.active, None
            try:
                state["stream"].close()
            finally:
                state["temporary"].unlink(missing_ok=True)

    def _capacity(self, requested: int) -> None:
        used = 0
        for count, path in enumerate(self.directory.iterdir(), start=1):
            if count >= 1024:
                raise ValueError("receive directory file-count quota reached; clear old files")
            used += path.lstat().st_size
            if used + requested > self.max_receive_bytes:
                raise ValueError("receive directory byte quota reached; clear old files")
        if requested > self.max_receive_bytes:
            raise ValueError("file exceeds receive directory quota")

    def handle(self, blob: bytes) -> bytes:
        if not blob:
            raise ValueError("empty application request")
        kind, body = blob[0], blob[1:]
        if kind == MESSAGE:
            if len(body) > 60000:
                raise ValueError("message too large")
            text = body.decode("utf-8")
            self.on_message(text)
            return b"message received"
        if kind == BEGIN:
            if self.active:
                raise ValueError("a file is already in progress")
            if len(body) > 512:
                raise ValueError("metadata too large")
            metadata = json.loads(body)
            if not isinstance(metadata, dict) or set(metadata) != {"id", "name", "size"}:
                raise ValueError("invalid file metadata")
            if not isinstance(metadata["id"], str):
                raise ValueError("invalid file identity")
            identifier = bytes.fromhex(metadata["id"])
            if len(identifier) != 16 or not isinstance(metadata["name"], str):
                raise ValueError("invalid file identity")
            size = metadata["size"]
            if type(size) is not int or not 0 <= size <= self.max_file_bytes:
                raise ValueError("file outside configured size limit")
            self._capacity(size)
            # Never use the sender's path. Prefix avoids Windows device/reserved names.
            name = re.sub(r"[^A-Za-z0-9._-]", "_", metadata["name"])[:80].strip(". ")
            name = identifier.hex() + "-" + (name or "file")
            stream = tempfile.NamedTemporaryFile(
                dir=self.directory, prefix="pingo-", suffix=".part", delete=False
            )
            preserve_desktop_owner(Path(stream.name))
            self.active = {
                "id": identifier,
                "size": size,
                "offset": 0,
                "hash": hashlib.sha256(),
                "stream": stream,
                "temporary": Path(stream.name),
                "name": name,
                "touched": time.monotonic(),
            }
            return b"file accepted"
        if kind == ABORT:
            if len(body) != 16:
                raise ValueError("invalid abort")
            if self.active and self.active["id"] == body:
                self.abort()
            return b"file aborted"
        if self.active is None:
            raise ValueError("no file in progress")
        state = self.active
        try:
            if kind == CHUNK:
                if not CHUNK_HEADER.size < len(body) <= CHUNK_HEADER.size + CHUNK_SIZE:
                    raise ValueError("invalid file chunk")
                identifier, offset = CHUNK_HEADER.unpack_from(body)
                data = body[CHUNK_HEADER.size :]
                if identifier != state["id"] or offset != state["offset"]:
                    raise ValueError("file identity/offset mismatch")
                if offset + len(data) > state["size"]:
                    raise ValueError("file exceeds declared size")
                state["stream"].write(data)
                state["hash"].update(data)
                state["offset"] += len(data)
                state["touched"] = time.monotonic()
                return b""
            if kind != END or len(body) != 48 or body[:16] != state["id"]:
                raise ValueError("invalid file completion")
            if state["offset"] != state["size"] or body[16:] != state["hash"].digest():
                raise ValueError("file size/hash verification failed")
            state["stream"].flush()
            os.fsync(state["stream"].fileno())
            state["stream"].close()
            final = self.directory / state["name"]
            # Atomic creation without overwriting any existing file or symlink.
            if os.name == "nt":
                # Windows rename is atomic on this volume and fails if final already exists.
                os.rename(state["temporary"], final)
            else:
                os.link(state["temporary"], final)
                state["temporary"].unlink()
            self.active = None
            if os.name == "posix":
                fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            return state["name"].encode("ascii")
        except (OSError, ValueError):
            self.abort()
            raise


def send_message(channel: Reliable, text: str) -> str:
    data = text.encode("utf-8")
    if len(data) > 60000:
        raise ValueError("message exceeds 60000 UTF-8 bytes")
    return channel.send(bytes([MESSAGE]) + data).decode("utf-8")


def send_file(channel: Reliable, path: Path, max_file_bytes=64 * 1024**2) -> str:
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("file transfer requires a regular file")
    identifier = os.urandom(16)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("file transfer requires a regular file")
        size = info.st_size
        if not 0 <= size <= max_file_bytes:
            raise ValueError("file outside configured size limit")
        metadata = json.dumps({"id": identifier.hex(), "name": path.name[:60], "size": size})
        channel.send(bytes([BEGIN]) + metadata.encode("utf-8"))
        digest, offset = hashlib.sha256(), 0
        try:
            while data := stream.read(CHUNK_SIZE):
                digest.update(data)
                channel.send(bytes([CHUNK]) + CHUNK_HEADER.pack(identifier, offset) + data)
                offset += len(data)
            if offset != size:
                raise ValueError("file changed size during transfer")
            result = channel.send(bytes([END]) + identifier + digest.digest())
            return result.decode("ascii")
        except BaseException:
            try:
                channel.send(bytes([ABORT]) + identifier)
            except (OSError, RuntimeError):
                pass  # Receiver also expires abandoned partial files.
            raise
