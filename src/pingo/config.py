import ipaddress
import os
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .permissions import private_file


@dataclass(frozen=True)
class Config:
    peer: str
    key_file: Path
    bind: str = "0.0.0.0"
    receive_dir: Path = Path("received")
    retry_seconds: float = 0.75
    attempts: int = 8
    max_file_bytes: int = 64 * 1024 * 1024
    max_receive_bytes: int = 256 * 1024 * 1024

    @classmethod
    def load(cls, path: Path) -> "Config":
        with path.open("rb") as stream:
            data = tomllib.load(stream)
        return cls.from_data(data, path.resolve().parent)

    @classmethod
    def from_data(cls, data, root):
        data = dict(data)
        allowed = {
            "peer",
            "key_file",
            "bind",
            "receive_dir",
            "retry_seconds",
            "attempts",
            "max_file_bytes",
            "max_receive_bytes",
        }
        if set(data) - allowed:
            raise ValueError(f"unknown configuration fields: {sorted(set(data) - allowed)}")
        if not {"peer", "key_file"} <= set(data):
            raise ValueError("configuration requires peer and key_file")
        for field in ("peer", "key_file", "bind", "receive_dir"):
            if field in data and not isinstance(data[field], str):
                raise ValueError(f"{field} must be a string")
        data["key_file"] = root / data["key_file"]
        data["receive_dir"] = root / data.get("receive_dir", "received")
        config = cls(**data)
        ipaddress.IPv4Address(config.peer)
        ipaddress.IPv4Address(config.bind)
        peer = ipaddress.IPv4Address(config.peer)
        if peer.is_unspecified or peer.is_multicast or int(peer) == 0xFFFFFFFF:
            raise ValueError("peer must be a unicast IPv4 address")
        if type(config.attempts) is not int or not 1 <= config.attempts <= 20:
            raise ValueError("attempts must be 1..20")
        if type(config.retry_seconds) not in (int, float) or not (
            0.05 <= config.retry_seconds <= 2
        ):
            raise ValueError("retry_seconds must be 0.05..2")
        if type(config.max_file_bytes) is not int or not (0 <= config.max_file_bytes <= 1024**3):
            raise ValueError("max_file_bytes must be 0..1073741824")
        if type(config.max_receive_bytes) is not int or not (
            0 <= config.max_receive_bytes <= 4 * 1024**3
        ):
            raise ValueError("max_receive_bytes must be 0..4294967296")
        return config

    def key(self) -> bytes:
        fd = os.open(
            self.key_file, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        )
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("key file must be a regular file")
            if os.name == "posix" and metadata.st_mode & 0o077:
                raise ValueError("key file must be private: chmod 600 KEYFILE")
            data = stream.read(33)
        if len(data) != 32:
            raise ValueError("key file must contain exactly 32 random bytes; use pingo keygen")
        return data


def generate_key(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            private_file(path)
            stream.write(os.urandom(32))
    except BaseException:
        path.unlink(missing_ok=True)
        raise
