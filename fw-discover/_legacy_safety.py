"""Stdlib-only safety primitives for legacy scripts, including copied standalone use."""
import gzip
import io
import json
import os
import re
import stat
import tempfile
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit


def atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("Refusing a linked state path")
    fd, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def bounded_gzip(data: bytes, limit: int = 128 << 20) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        result = stream.read(limit + 1)
    if len(result) > limit:
        raise ValueError("gzip expanded-byte budget exceeded")
    return result


def atomic_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("Refusing a linked cache path")
    fd, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def read_bounded(stream, limit: int) -> bytes:
    content_length = stream.headers.get("Content-Length")
    if content_length and (not content_length.isdigit() or int(content_length) > limit):
        raise ValueError("HTTP Content-Length exceeds download budget")
    blocks, used, started = [], 0, time.monotonic()
    while True:
        block = stream.read(min(65536, limit - used + 1))
        if not block:
            break
        used += len(block)
        if used > limit or time.monotonic() - started > 180:
            raise ValueError("Download byte/time budget exceeded")
        blocks.append(block)
    return b"".join(blocks)


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, original: str):
        super().__init__()
        self.host = urlsplit(original).hostname

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destination = urlsplit(newurl)
        if destination.scheme != "https" or destination.hostname != self.host or destination.username:
            raise ValueError("Cross-host or non-HTTPS redirect rejected")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_get(url: str, headers: dict, timeout: int = 60, limit: int = 64 << 20) -> bytes:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or "\\" in url:
        raise ValueError("Legacy catalog fetch requires a clean HTTPS URL")
    opener = urllib.request.build_opener(SafeRedirect(url))
    request = urllib.request.Request(url, headers=headers)
    with opener.open(request, timeout=timeout) as response:
        return read_bounded(response, limit)


def safe_name(value: str) -> str:
    # Content-derived names never become a path, an option, or a Windows device name.
    import hashlib
    normalized = re.sub(r"[^A-Za-z0-9_-]", "-", value)[:96].strip("-") or "asset"
    return "fw-" + normalized + "-" + hashlib.sha256(value.encode()).hexdigest()[:12]


class KernelLock:
    def __init__(self, path: Path):
        self.path, self.stream = path, None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise ValueError("Linked lock path rejected")
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise ValueError("Lock is not a regular file")
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
        except OSError:
            self.stream.close()
            self.stream = None
            return False
        self.stream.seek(1)
        self.stream.write(json.dumps({"pid": os.getpid()}).encode("ascii"))
        self.stream.truncate()
        return True

    def release(self) -> None:
        if self.stream:
            if os.name == "nt":
                import msvcrt
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            self.stream.close()
            self.stream = None
        # Keep the lock inode. Stale processes release the kernel lock automatically.
