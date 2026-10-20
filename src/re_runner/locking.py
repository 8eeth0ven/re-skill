"""Kernel-owned locks: process death releases ownership without stale PID races."""
import json
import os
import stat
import uuid
from pathlib import Path

from .errors import IntegrityError, Locked


class FileLock:
    def __init__(self, path: Path):
        self.path = path
        self.stream = None
        self.token = uuid.uuid4().hex

    def acquire(self) -> "FileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink():
            raise IntegrityError("Lock path is a symlink")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(self.path, flags, 0o600)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise IntegrityError("Lock is not a regular file")
        self.stream = os.fdopen(fd, "r+b", buffering=0)
        try:
            if os.name == "nt":
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    self.stream.write(b"\x00")
                self.stream.seek(0)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.stream.close()
            self.stream = None
            raise Locked("Another process owns this run") from exc
        self.stream.seek(1)
        self.stream.write(json.dumps({"pid": os.getpid(), "token": self.token}).encode("ascii"))
        self.stream.truncate()
        return self

    def release(self) -> None:
        if self.stream is not None:
            if os.name == "nt":
                import msvcrt
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            self.stream.close()
            self.stream = None
        # Never unlink: replacing the inode can admit two simultaneous owners.

    def __enter__(self) -> "FileLock":
        return self.acquire()

    def __exit__(self, *_: object) -> None:
        self.release()

