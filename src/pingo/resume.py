"""Durable, content-verified transfers across fresh authenticated sessions."""

import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path

from .direct import ABORT, BEGIN, CHUNK, CHUNK_HEADER, CHUNK_SIZE, END, Receiver
from .permissions import preserve_desktop_owner
from .reconnect import recoverable

RESUME = 37
MAX_RECORDS = 128


def file_digest(stream, limit=None):
    digest = hashlib.sha256()
    remaining = limit
    while remaining is None or remaining > 0:
        data = stream.read(min(1024 * 1024, remaining) if remaining is not None else 1024 * 1024)
        if not data:
            break
        digest.update(data)
        if remaining is not None:
            remaining -= len(data)
    return digest


def sync_directory(directory):
    if os.name == "posix":
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class ResumableReceiver(Receiver):
    def __init__(self, *args, retention_seconds=86400, **kwargs):
        super().__init__(*args, **kwargs)
        self.retention_seconds = retention_seconds
        self._last_expire = 0
        self.expire()

    def attach(self, channel):
        channel.handler = self.handle

        def reset():
            self.suspend()
            channel.reset()

        def tick():
            self.expire()
            channel.expire()

        channel.endpoint.on_session = reset
        channel.endpoint.on_tick = tick

    def _record_path(self, identifier):
        return self.directory / (identifier.hex() + ".resume.json")

    def _capacity(self, requested, exclude=None):
        reserved = 0
        for path in self.directory.glob("*.resume.json"):
            if exclude is not None and path.name == exclude.hex() + ".resume.json":
                continue
            if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > 1024:
                raise ValueError("invalid resume record while calculating receive quota")
            record = json.loads(path.read_text(encoding="utf-8"))
            if (
                not isinstance(record, dict)
                or type(record.get("size")) is not int
                or type(record.get("offset")) is not int
                or not 0 <= record["offset"] <= record["size"] <= self.max_file_bytes
            ):
                raise ValueError("invalid resume reservation")
            if not record.get("complete"):
                reserved += record["size"] - record["offset"]
        super()._capacity(requested + reserved)

    def _save(self, state):
        path = self._record_path(state["id"])
        record = {key: state[key] for key in ("name", "size", "offset", "digest", "complete")}
        temporary = path.with_suffix(".tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(temporary, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            preserve_desktop_owner(temporary)
            json.dump(record, stream, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(self.directory)

    def suspend(self):
        if self.active and "digest" in self.active:
            state, self.active = self.active, None
            state["stream"].close()
        else:
            super().abort()

    def abort(self):
        state = self.active
        super().abort()
        if state and "digest" in state:
            self._record_path(state["id"]).unlink(missing_ok=True)

    def expire(self):
        now = time.time()
        if now - self._last_expire < 1:
            return
        self._last_expire = now
        if self.active and time.monotonic() - self.active["touched"] > 60:
            self.suspend()
        for path in self.directory.glob("*.resume.json"):
            if not re.fullmatch(r"[0-9a-f]{32}\.resume\.json", path.name):
                continue
            if now - path.lstat().st_mtime > self.retention_seconds:
                identifier = bytes.fromhex(path.name[:32])
                if self.active and self.active["id"] == identifier:
                    continue
                (self.directory / (identifier.hex() + ".part")).unlink(missing_ok=True)
                path.unlink()

    def _resume(self, body):
        if len(body) > 768:
            raise ValueError("resume metadata too large")
        metadata = json.loads(body)
        if not isinstance(metadata, dict) or set(metadata) != {"id", "name", "size", "digest"}:
            raise ValueError("invalid resume metadata")
        if not isinstance(metadata["id"], str) or not re.fullmatch(r"[0-9a-f]{32}", metadata["id"]):
            raise ValueError("invalid transfer ID")
        if not isinstance(metadata["digest"], str) or not re.fullmatch(
            r"[0-9a-f]{64}", metadata["digest"]
        ):
            raise ValueError("invalid transfer digest")
        if not isinstance(metadata["name"], str) or len(metadata["name"]) > 60:
            raise ValueError("invalid transfer name")
        size = metadata["size"]
        if type(size) is not int or not 0 <= size <= self.max_file_bytes:
            raise ValueError("file outside configured size limit")
        identifier = bytes.fromhex(metadata["id"])
        if self.active:
            if self.active["id"] != identifier:
                raise ValueError("a file is already in progress")
            self.suspend()
        name = re.sub(r"[^A-Za-z0-9._-]", "_", metadata["name"])[:80].strip(". ")
        name = identifier.hex() + "-" + (name or "file")
        temporary = self.directory / (identifier.hex() + ".part")
        state = {
            "id": identifier,
            "size": size,
            "digest": metadata["digest"],
            "offset": 0,
            "name": name,
            "complete": False,
            "temporary": temporary,
            "touched": time.monotonic(),
        }
        record_path = self._record_path(identifier)
        if record_path.exists():
            if not stat.S_ISREG(record_path.lstat().st_mode) or record_path.stat().st_size > 1024:
                raise ValueError("invalid resume record")
            record = json.loads(record_path.read_text(encoding="utf-8"))
            if not isinstance(record, dict) or set(record) != {
                "size",
                "digest",
                "name",
                "offset",
                "complete",
            }:
                raise ValueError("invalid resume record")
            if any(record.get(key) != state[key] for key in ("size", "digest", "name")):
                raise ValueError("resume identity differs from original file")
            if type(record["offset"]) is not int or not 0 <= record["offset"] <= size:
                raise ValueError("invalid resume offset")
            if type(record["complete"]) is not bool:
                raise ValueError("invalid resume completion")
            state.update(record)
        else:
            if len(list(self.directory.glob("*.resume.json"))) >= MAX_RECORDS:
                raise ValueError("resume-record limit reached; clear old transfers")
        final = self.directory / name
        # Recover a crash after atomic publication but before the completion journal.
        if final.exists():
            if not stat.S_ISREG(final.lstat().st_mode) or final.stat().st_size != size:
                raise ValueError("completed file differs from transfer")
            with final.open("rb") as stream:
                if file_digest(stream).hexdigest() != state["digest"]:
                    raise ValueError("completed file hash differs from transfer")
            if not record_path.exists():
                self._capacity(1024)
            state.update(offset=size, complete=True)
            self._save(state)
            temporary.unlink(missing_ok=True)
            return json.dumps({"complete": True, "name": name}).encode()
        if state["complete"]:
            raise ValueError("completed receiver file is missing")
        if record_path.exists():
            self._capacity(size - state["offset"], exclude=identifier)
        else:
            self._capacity(size + 1024)
        # Windows CRT text mode can remove a trailing 0x1A during open itself.
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        if not temporary.exists():
            if state["offset"]:
                raise ValueError("partial receiver file is missing")
            flags |= os.O_CREAT | os.O_EXCL
        elif not stat.S_ISREG(temporary.lstat().st_mode):
            raise ValueError("partial receiver file must be regular")
        fd = os.open(temporary, flags, 0o600)
        stream = os.fdopen(fd, "r+b")
        try:
            preserve_desktop_owner(temporary)
            if os.fstat(fd).st_size < state["offset"]:
                raise ValueError("partial receiver file is truncated")
            stream.truncate(state["offset"])
            stream.seek(0)
            state["hash"] = file_digest(stream, state["offset"])
            stream.seek(state["offset"])
            state["stream"] = stream
            self._save(state)
        except BaseException:
            stream.close()
            raise
        self.active = state
        return json.dumps(
            {"complete": False, "offset": state["offset"], "prefix": state["hash"].hexdigest()}
        ).encode()

    def handle(self, blob):
        if blob and blob[0] == RESUME:
            return self._resume(blob[1:])
        if blob and blob[0] == BEGIN and self.active and "digest" in self.active:
            raise ValueError("a resumable file is already in progress")
        state = self.active
        resumable = state is not None and "digest" in state
        if resumable and blob and blob[0] == END and blob[17:] != bytes.fromhex(state["digest"]):
            self.abort()
            raise ValueError("file hash differs from initial digest")
        result = super().handle(blob)
        if resumable and blob[0] == CHUNK:
            state["stream"].flush()
            os.fsync(state["stream"].fileno())
            self._save(state)
        elif resumable and blob[0] == END:
            state["complete"] = True
            self._save(state)
        elif blob and blob[0] == ABORT and len(blob) == 17:
            identifier = bytes(blob[1:])
            if self.active is None:
                (self.directory / (identifier.hex() + ".part")).unlink(missing_ok=True)
                self._record_path(identifier).unlink(missing_ok=True)
        return result


def send_resumable(channel, path: Path, max_file_bytes=64 * 1024**2, reconnects=10, progress=None):
    progress = progress or (lambda *_: None)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= max_file_bytes:
            raise ValueError("file must be regular and within the configured size limit")
        digest = file_digest(stream).digest()
        progress(0, info.st_size, "connecting")
        name = path.name[:60]
        identifier = hashlib.sha256(b"pingo/file/v2\x00" + digest + name.encode()).digest()[:16]
        metadata = json.dumps(
            {"id": identifier.hex(), "name": name, "size": info.st_size, "digest": digest.hex()}
        ).encode()
        expected = (
            identifier.hex() + "-" + (re.sub(r"[^A-Za-z0-9._-]", "_", name).strip(". ") or "file")
        )
        for failure in range(reconnects + 1):
            try:
                response = json.loads(channel.send(bytes([RESUME]) + metadata))
                if not isinstance(response, dict) or type(response.get("complete")) is not bool:
                    raise ValueError("invalid receiver resume response")
                if response.get("complete") is True:
                    if set(response) != {"complete", "name"} or response.get("name") != expected:
                        raise ValueError("invalid completed receiver filename")
                    progress(info.st_size, info.st_size, "verified")
                    return expected
                if set(response) != {"complete", "offset", "prefix"}:
                    raise ValueError("invalid receiver resume response")
                offset = response.get("offset")
                if type(offset) is not int or not 0 <= offset <= info.st_size:
                    raise ValueError("invalid receiver resume offset")
                stream.seek(0)
                prefix = file_digest(stream, offset)
                if prefix.hexdigest() != response.get("prefix"):
                    raise ValueError("receiver partial file differs from source")
                stream.seek(offset)
                progress(offset, info.st_size, "sending")
                while data := stream.read(CHUNK_SIZE):
                    channel.send(bytes([CHUNK]) + CHUNK_HEADER.pack(identifier, offset) + data)
                    offset += len(data)
                    progress(offset, info.st_size, "sending")
                current = os.fstat(stream.fileno())
                if offset != info.st_size or current.st_mtime_ns != info.st_mtime_ns:
                    raise ValueError("file changed during transfer")
                progress(offset, info.st_size, "verifying")
                completed = channel.send(bytes([END]) + identifier + digest).decode("ascii")
                if completed != expected:
                    raise ValueError("invalid completed receiver filename")
                progress(offset, info.st_size, "verified")
                return completed
            except (OSError, RuntimeError) as exc:
                if not recoverable(exc) or failure == reconnects:
                    raise
                channel.recover()
    raise RuntimeError("transfer retry limit exhausted")
