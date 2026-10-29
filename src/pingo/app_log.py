"""Bounded desktop diagnostics; never persist messages or packet payloads."""

import json
import os
import threading
import time
from collections import deque
from pathlib import Path

from .permissions import private_directory, private_file


class AppLog:
    def __init__(self, root, max_bytes=1024 * 1024, backups=3):
        self.root = Path(root)
        self.path = self.root / "app.jsonl"
        self.max_bytes, self.backups = max_bytes, backups
        self.lock = threading.RLock()
        self.error = ""
        try:
            self._safe()
            private_directory(self.root)
        except (OSError, ValueError) as exc:
            self.error = str(exc)

    def _paths(self):
        return [self.path, *(self.root / f"app.jsonl.{i}" for i in range(1, self.backups + 1))]

    def _safe(self):
        for path in [self.root, *self._paths()]:
            if path.is_symlink() or (
                path.exists() and getattr(path.lstat(), "st_file_attributes", 0) & 0x400
            ):
                raise OSError("Log paths must not be symbolic links")

    def write(self, event):
        kind = event.get("event")
        if kind in ("traffic", "progress"):
            return
        record = {
            "at": event.get("at", time.time()),
            "event": kind,
            "level": event.get("level", "error" if kind == "error" else "info"),
        }
        # Explicit fields only: no keys, application messages, filenames or packet hex.
        for field in (
            "state", "action", "code", "peer", "size", "version", "platform", "reason",
        ):
            if field in event:
                record[field] = event[field]
        if kind in ("error", "log"):
            record["text"] = str(event.get("text", ""))[:4096]
        line = json.dumps(record, ensure_ascii=True) + "\n"
        with self.lock:
            try:
                self._safe()
                if self.path.exists() and self.path.stat().st_size:
                    with self.path.open("rb") as stream:
                        stream.seek(-1, os.SEEK_END)
                        if stream.read(1) != b"\n":
                            line = "\n" + line
                paths = self._paths()
                if self.path.exists() and self.path.stat().st_size + len(line) > self.max_bytes:
                    for i in range(self.backups, 0, -1):
                        if paths[i - 1].exists():
                            os.replace(paths[i - 1], paths[i])
                with self.path.open("a", encoding="utf-8") as stream:
                    private_file(self.path)
                    stream.write(line)
                self.error = ""
            except OSError as exc:
                self.error = str(exc)

    def read(self, limit=300):
        records = deque(maxlen=limit)
        with self.lock:
            try:
                self._safe()
                for path in reversed(self._paths()):
                    if not path.exists():
                        continue
                    with path.open(encoding="utf-8") as stream:
                        for line in stream:
                            try:
                                record = json.loads(line)
                                if isinstance(record, dict):
                                    records.append(record)
                            except ValueError:
                                continue  # A crash may leave an incomplete final record.
            except OSError as exc:
                self.error = str(exc)
        return {"records": list(records), "path": str(self.path), "error": self.error}
