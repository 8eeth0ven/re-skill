"""ZIP/TAR/gzip intake. Entire indexes are checked before writing any member."""
import gzip
import os
import stat
import tarfile
import zipfile
from pathlib import Path

from .errors import BudgetExceeded, InvalidInput
from .safety import Budget, contained, safe_relative


def _validate_members(members: list[tuple[str, int, int, bool]], budget: Budget) -> None:
    if len(members) > budget.limits["max_files"]:
        raise BudgetExceeded("Archive file count budget exceeded")
    total, seen = 0, set()
    for name, size, compressed, _ in members:
        budget.check()
        normalized = safe_relative(name, budget.limits["max_depth"])
        if normalized.casefold() in seen:
            raise InvalidInput("Duplicate or case-colliding archive paths")
        seen.add(normalized.casefold())
        total += size
        if size < 0 or total > budget.limits["max_unpack_bytes"]:
            raise BudgetExceeded("Declared archive expansion exceeds budget")
        if size > max(compressed, 1) * budget.limits["max_archive_ratio"]:
            raise BudgetExceeded("Archive expansion ratio exceeds budget")
    # A file may not also be an ancestor of another member.
    files = {safe_relative(n).casefold() for n, _, _, directory in members if not directory}
    for name in seen:
        parts = name.split("/")
        if any("/".join(parts[:i]) in files for i in range(1, len(parts))):
            raise InvalidInput("Archive file/directory collision")


def _copy(stream, target: Path, budget: Budget, expected: int | None = None) -> None:
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, 0o600)
    count = 0
    try:
        with os.fdopen(fd, "wb") as output:
            while True:
                block = stream.read(65536)
                if not block:
                    break
                count += len(block)
                budget.consume("unpack_bytes", len(block))
                if expected is not None and count > expected:
                    raise InvalidInput("Archive size differs from declared member size")
                output.write(block)
        if expected is not None and count != expected:
            raise InvalidInput("Truncated archive member")
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def extract_archive(path: Path, output: Path, budget: Budget) -> list[dict]:
    if output.exists():
        raise InvalidInput("Extraction output must be new")
    output.mkdir(parents=True, mode=0o700)
    inventory = []
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                entries = archive.infolist()
                members = []
                for entry in entries:
                    mode = entry.external_attr >> 16
                    if entry.flag_bits & 1:
                        raise InvalidInput("Encrypted ZIP members cannot be analyzed")
                    if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                        raise InvalidInput("Archive links/devices are rejected")
                    if entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                        raise InvalidInput("Unsupported ZIP compression method")
                    members.append((entry.filename, entry.file_size, entry.compress_size, entry.is_dir()))
                _validate_members(members, budget)
                for entry in entries:
                    name = safe_relative(entry.filename, budget.limits["max_depth"])
                    target = contained(output, output / name)
                    if entry.is_dir():
                        target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    else:
                        budget.consume("files", 1)
                        with archive.open(entry) as stream:
                            _copy(stream, target, budget, entry.file_size)
                        inventory.append({"path": name, "bytes": entry.file_size})
        else:
            with tarfile.open(path, "r:*") as archive:
                entries = []
                for entry in archive:
                    if len(entries) >= budget.limits["max_files"]:
                        raise BudgetExceeded("TAR member count exceeded")
                    if not (entry.isfile() or entry.isdir()):
                        raise InvalidInput("TAR links, sparse files and devices are rejected")
                    if entry.sparse is not None:
                        raise InvalidInput("Sparse TAR files rejected")
                    if entry.isdir() and entry.name.rstrip("/") == ".":
                        continue
                    entries.append(entry)
                compressed = max(path.stat().st_size, 1)
                members = [(e.name, e.size, compressed, e.isdir()) for e in entries]
                _validate_members(members, budget)
                if sum(e.size for e in entries) > compressed * budget.limits["max_archive_ratio"]:
                    raise BudgetExceeded("TAR expansion ratio exceeded")
                for entry in entries:
                    name = safe_relative(entry.name, budget.limits["max_depth"])
                    target = contained(output, output / name)
                    if entry.isdir():
                        target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    else:
                        budget.consume("files", 1)
                        with archive.extractfile(entry) as stream:
                            _copy(stream, target, budget, entry.size)
                        inventory.append({"path": name, "bytes": entry.size})
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, OSError, RuntimeError) as exc:
        raise InvalidInput(f"Malformed archive: {type(exc).__name__}") from exc
    return inventory


def decompress_gzip(path: Path, target: Path, budget: Budget) -> int:
    compressed = path.stat().st_size
    try:
        with gzip.open(path, "rb") as stream:
            _copy(stream, target, budget)
        size = target.stat().st_size
        if size > max(compressed, 1) * budget.limits["max_archive_ratio"]:
            target.unlink(missing_ok=True)
            raise BudgetExceeded("gzip expansion ratio exceeded")
        return size
    except (EOFError, OSError) as exc:
        raise InvalidInput("Malformed gzip stream") from exc
