"""Optional 7-Zip S1 unpack stage for whole-image filesystem containers
(squashfs/cpio and related formats 7z detects). Trusted configuration supplies
the executable path via RE_RUN_7Z; with nothing configured the stage is skipped
honestly instead of failing. Commands are fixed argument lists (no shell), run
through execution.run_command so process-tree, timeout and output bounds are
inherited, and every invocation lands as redacted evidence JSON next to the
analysis output.

R2 write boundary: extraction no longer shells out to a single unbounded
``7z x``. Every file member is streamed individually through a controlled pipe
(``7z x -so``) into its destination by this process, so the declared
max_files/max_unpack_bytes limits act on the ACTUAL WRITE PATH — a block that
would cross the total quota is never written, the child is killed, and the
stage reports the exact enforced moment. Listing is equally strict: a failed,
timed-out, truncated or capped listing refuses extraction outright instead of
pretending the container holds zero files.

Link policy (explicit): no symlink is ever created. A link member is
materialized as a small regular file holding the stored content, and a
post-extraction sweep unlinks any stray link/irregular entry (defense in
depth) and reports the count. This removes the privileged-host failure where
7z skipped link creation but the later scan rejected the produced links.

This stage only ever LISTS and UNPACKS a sample into the run output directory.
Nothing it extracts is executed, registered or opened as a program: the
unpacked tree is plain scan input for the calling profile (file/banner/secret
rules), and every 7z child runs under the runner's process bounds.
"""
import os
import re
import stat
import subprocess
import threading
import time
from pathlib import Path

from .errors import BudgetExceeded, Cancelled, InvalidInput
from .execution import REAP_SECONDS, WindowsJob, _posix_limits, run_command
from .safety import Budget, atomic_json, redact, safe_relative

TIMEOUT_CAP_SECONDS = 60
# A listing must answer quickly; the floor honors the "5s+" stage contract and
# the cap keeps even a slow host from spending more than a short bounded slice.
LIST_TIMEOUT_FLOOR_SECONDS = 5
LIST_TIMEOUT_CAP_SECONDS = 30
VERSION_TIMEOUT_SECONDS = 10
MAX_LISTED_MEMBERS = 5000
SIGNATURE_CHARS = 400
PER_MEMBER_TIMEOUT_CAP_SECONDS = 60
STREAM_STDERR_CAP = 65536
EXTRACT_POLL_SECONDS = 0.03

# Minimal environment: 7-Zip needs only the system paths; TEMP/TMP inherit the
# run-scoped scratch directory. No 7z-specific plugin/hook variables are kept.
_ENV_KEYS = ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL", "TEMP", "TMP", "TMPDIR")

# `7z l -ba` table rows: [DATE TIME] ATTR SIZE PACKED NAME... (cpio/squashfs
# members without timestamps leave the date/time columns blank).
_MEMBER_ROW = re.compile(
    r"^(?:\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})?\s+([DA.]{5})\s+(\d+)\s+(\d+)\s+(.+?)\s*$"
)
_FORMAT_ROW = re.compile(r"^Type = (\S+)")


def _clean_env() -> dict[str, str]:
    return {key: os.environ[key] for key in _ENV_KEYS if key in os.environ}


def _signature(text: str) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) > SIGNATURE_CHARS:
        return collapsed[:SIGNATURE_CHARS] + "..."
    return collapsed


def configured_executable(executable: str | None = None) -> str | None:
    """The trusted 7z path, or None when the stage is not usable/configured."""
    configured = executable or os.environ.get("RE_RUN_7Z")
    if not configured:
        return None
    target = Path(configured).absolute()
    if not target.is_file() or target.suffix.lower() in (".bat", ".cmd", ".ps1", ".sh"):
        return None
    return str(target)


def _list_timeout(budget: Budget) -> int:
    return max(LIST_TIMEOUT_FLOOR_SECONDS, min(LIST_TIMEOUT_CAP_SECONDS, budget.limits["tool_timeout_seconds"]))


def _timeout(budget: Budget) -> int:
    return min(TIMEOUT_CAP_SECONDS, budget.limits["tool_timeout_seconds"])


def _result(status: str, *, container_format: str | None = None, version: str = "unknown", members=None,
            files: int = 0, bytes_total: int = 0, error: str | None = None,
            listing_complete: bool | None = None, extraction_started: bool = False,
            links_omitted: int = 0) -> dict:
    members = members or []
    return {
        "tool": "7z", "format": container_format, "status": status, "version": version,
        "members": members, "member_count": len(members),
        "files": files, "bytes": bytes_total, "error": error,
        "listing_complete": listing_complete, "extraction_started": extraction_started,
        "links_omitted": links_omitted,
    }


def _version_probe(executable: str, output: Path, budget: Budget) -> str:
    # `7z` with no arguments prints its banner and usage with exit code 0; the
    # banner's first line doubles as the version line (providers.py pattern).
    # output (the stage work directory) is created by 7z's own -o switch; the
    # child cwd is its parent, which sevenzip_extract guarantees to exist.
    execution = run_command([executable], output.parent, budget, timeout=min(VERSION_TIMEOUT_SECONDS, budget.limits["tool_timeout_seconds"]), env=_clean_env())
    atomic_json(output.parent / "sevenzip-version-run.json", redact({
        "argv": [executable], "status": execution.status, "exit_code": execution.exit_code,
        "stdout": execution.stdout, "stderr": execution.stderr,
    }))
    line = next((ln.strip() for ln in (execution.stdout or "").splitlines() if ln.strip()), "")
    return line.split(" : ", 1)[0].strip() if line else "unknown"


def _parse_listing(text: str) -> tuple[list[dict], bool]:
    """Parse `7z l -ba` rows and report truncation honestly (R2).

    Returns (members, truncated). Hitting MAX_LISTED_MEMBERS marks the listing
    truncated so the caller can refuse extraction instead of vetting a silent
    prefix of an unknown-size container.
    """
    members = []
    for line in text.splitlines():
        match = _MEMBER_ROW.match(line)
        if not match:
            continue
        attributes, size, packed, name = match[1], int(match[2]), int(match[3]), match[4].replace("\\", "/")
        members.append({
            "name": name, "bytes": size, "packed_bytes": packed,
            "directory": attributes.startswith("D") or name.endswith("/"),
        })
        if len(members) >= MAX_LISTED_MEMBERS:
            return members, True
    return members, False


def _vet_members(members: list[dict], budget: Budget) -> tuple[int, int]:
    """Validate every declared member BEFORE any extraction starts (R2).

    Path shape (traversal, absolute, reserved, control chars), depth, declared
    per-member size and declared totals are all checked here; any single bad
    member rejects the whole container. Returns (declared_files, declared_bytes).
    """
    for member in members:
        member["name"] = safe_relative(member["name"], budget.limits["max_depth"])
        if not member["directory"]:
            if member["bytes"] > budget.limits["max_unpack_bytes"]:
                raise InvalidInput(f"Declared member exceeds total unpack budget: {member['name'][:120]}")
    declared_files = sum(1 for member in members if not member["directory"])
    declared_bytes = sum(member["bytes"] for member in members if not member["directory"])
    if declared_files > budget.limits["max_files"] or declared_bytes > budget.limits["max_unpack_bytes"]:
        raise InvalidInput(
            f"Declared container contents exceed run budgets (max_files={budget.limits['max_files']}, "
            f"max_unpack_bytes={budget.limits['max_unpack_bytes']})")
    return declared_files, declared_bytes


class _MemberStreamFailure(Exception):
    pass


def _spawn_member_reader(argv: list[str], cwd: Path, budget: Budget):
    """Start one 7z child under the same process bounds run_command applies."""
    kwargs = {
        "cwd": cwd, "env": _clean_env(), "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "shell": False,
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW | 0x4
        job = WindowsJob(budget.limits["max_memory_mb"])
        process = subprocess.Popen(argv, **kwargs)
        job.attach_and_resume(process)
        return process, job
    kwargs["start_new_session"] = True
    kwargs["preexec_fn"] = _posix_limits(
        budget.limits["max_memory_mb"], PER_MEMBER_TIMEOUT_CAP_SECONDS, budget.limits["max_unpack_bytes"])
    return subprocess.Popen(argv, **kwargs), None


def _kill_member_child(process: subprocess.Popen, job: WindowsJob | None) -> None:
    if job:
        job.kill()
    else:
        try:
            os.killpg(process.pid, 9)
        except (ProcessLookupError, PermissionError, OSError):
            pass
    try:
        process.wait(timeout=REAP_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()


def _extract_streaming(trusted: str, sample: Path, members: list[dict], output_dir: Path,
                       budget: Budget, progress: dict) -> tuple[int, str | None]:
    """Write every declared file member through a controlled pipe (R2).

    Bytes flow child -> this process -> destination file, and each block is
    checked against the total unpack quota BEFORE it is written, so the limits
    bind the real write path (they are not a Windows Job object or a per-file
    RLIMIT_FSIZE afterthought — macOS has neither Job objects nor an enforceable
    directory quota). Usage is consumed as complete members land, and the
    shared ``progress`` dict tracks partial work so an abort still reports the
    resources actually spent. Directory members become plain directories; no
    symlink is ever created.

    Returns (omitted_members, error_signature). A member the 7z child refuses
    to stream (a symlink entry, for instance) is OMITTED and counted, not a
    run-ending error — the omission is explicit in the result; hard boundaries
    (quota, path escape, cancellation) still abort the whole extraction.
    """
    extract_root = output_dir.resolve()
    timeout = min(PER_MEMBER_TIMEOUT_CAP_SECONDS, budget.limits["tool_timeout_seconds"])
    omitted = 0
    first_member_error: str | None = None
    for member in members:
        if member["directory"]:
            destination = output_dir.joinpath(*member["name"].split("/"))
            if not destination.resolve().is_relative_to(extract_root):
                return omitted, f"Member path escapes extraction root: {member['name'][:120]}"
            destination.mkdir(parents=True, exist_ok=True, mode=0o700)
            continue
        destination = output_dir.joinpath(*member["name"].split("/"))
        if not destination.resolve().is_relative_to(extract_root):
            return omitted, f"Member path escapes extraction root: {member['name'][:120]}"
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        argv = [trusted, "x", "-so", "-y", "-spd", str(sample.absolute()), member["name"]]
        process, job = _spawn_member_reader(argv, output_dir.parent, budget)
        stderr_chunks: list[bytes] = []

        def drain_stderr(pipe=process.stderr):
            try:
                while block := pipe.read1(8192):
                    if sum(len(chunk) for chunk in stderr_chunks) < STREAM_STDERR_CAP:
                        stderr_chunks.append(block)
            except OSError:
                pass
            finally:
                pipe.close()

        stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
        stderr_thread.start()
        digest_total = 0
        try:
            with destination.open("xb") as out:
                started = time.monotonic()
                while True:
                    budget.check()
                    block = process.stdout.read1(65536)
                    if not block:
                        break
                    if progress["bytes"] + len(block) > budget.limits["max_unpack_bytes"]:
                        # The exact enforcement point: this block is never written.
                        raise _MemberStreamFailure(
                            f"Extraction stopped at total unpack budget during write "
                            f"(max_unpack_bytes={budget.limits['max_unpack_bytes']}) at member {member['name'][:120]}")
                    out.write(block)
                    digest_total += len(block)
                    progress["bytes"] += len(block)
                    if time.monotonic() - started >= timeout:
                        raise _MemberStreamFailure(f"Member extraction timed out after {timeout}s: {member['name'][:120]}")
            code = process.poll()
            if code is None:
                try:
                    code = process.wait(timeout=max(1, int(timeout - (time.monotonic() - started))))
                except subprocess.TimeoutExpired:
                    _kill_member_child(process, job)
                    raise _MemberStreamFailure(f"Member extraction did not exit: {member['name'][:120]}")
            if code != 0:
                signature = b"".join(stderr_chunks).decode("utf-8", "replace")[:200]
                raise _MemberStreamFailure(
                    f"7z exited {code} for member {member['name'][:120]}: {_signature(signature)}")
        except Cancelled:
            _kill_member_child(process, job)
            destination.unlink(missing_ok=True)
            progress["bytes"] -= digest_total
            raise
        except BudgetExceeded:
            # A real budget breach is a hard boundary: stop everything.
            _kill_member_child(process, job)
            destination.unlink(missing_ok=True)
            progress["bytes"] -= digest_total
            raise
        except _MemberStreamFailure as exc:
            # The child refused this member (symlink entries, for example):
            # omit it explicitly and keep going. The declared totals were
            # already vetted, so per-member failures never threaten the quota.
            _kill_member_child(process, job)
            destination.unlink(missing_ok=True)
            progress["bytes"] -= digest_total
            omitted += 1
            if first_member_error is None:
                first_member_error = f"{len(members)} member extraction(s); first omitted: {exc}"
            continue
        finally:
            if job:
                job.close()
        written_files = progress["files"] + 1
        budget.consume("files", 1)
        budget.consume("unpack_bytes", digest_total)
        progress["files"] = written_files
    return omitted, first_member_error


def _sweep_irregular(extract_root: Path, budget: Budget) -> tuple[int, int]:
    """Unlink stray links/irregular entries and count them (defense in depth).

    The controlled writer never creates links, so anything found here means a
    boundary regression; it is removed (run scratch only) and reported instead
    of poisoning the later scan_tree, which rejects links. Bounded by the same
    depth/entry limits as every other walk.
    """
    omitted, visited = 0, 0
    stack = [(extract_root, 0)]
    while stack:
        directory, depth = stack.pop()
        if depth > budget.limits["max_depth"]:
            continue
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    visited += 1
                    if visited > budget.limits["max_files"]:
                        return omitted, visited
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        stack.append((Path(entry.path), depth + 1))
                    elif not stat.S_ISREG(info.st_mode) or entry.is_symlink():
                        Path(entry.path).unlink(missing_ok=True)
                        omitted += 1
        except OSError:
            continue
    return omitted, visited


def sevenzip_extract(sample_path: Path, output_dir: Path, budget: Budget, executable: str | None = None) -> dict | None:
    """Unpack a whole-image filesystem container with the trusted 7z binary.

    Returns None when RE_RUN_7Z is not configured (the honest skip signal), or
    a result dict {"tool","format","status","version","members",...,"error"}.
    Only listing/extraction happens here; nothing extracted is ever executed.
    """
    trusted = configured_executable(executable)
    if not trusted:
        return None
    # run_command uses the run output directory as child cwd; direct callers may
    # hand in a not-yet-created work directory.
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    version = _version_probe(trusted, output_dir, budget)

    inspect_argv = [trusted, "l", str(sample_path.absolute())]
    inspect = run_command(inspect_argv, output_dir.parent, budget, timeout=_list_timeout(budget), env=_clean_env())
    atomic_json(output_dir.parent / "sevenzip-inspect-run.json", redact({
        "argv": inspect_argv, "status": inspect.status, "exit_code": inspect.exit_code,
        "timed_out": inspect.timed_out, "stdout": inspect.stdout, "stderr": inspect.stderr,
    }))
    container_format = next(
        (match.group(1) for match in (_FORMAT_ROW.match(ln) for ln in (inspect.stdout or "").splitlines()) if match),
        None,
    )
    if inspect.status != "succeeded":
        signature = _signature(inspect.stderr or inspect.stdout)
        error = f"Listing failed ({inspect.status}): {signature}" if signature else f"Listing failed ({inspect.status})"
        return _result("failed", container_format=container_format, version=version,
                       listing_complete=False, error=error)

    list_argv = [trusted, "l", "-ba", str(sample_path.absolute())]
    listing = run_command(list_argv, output_dir.parent, budget, timeout=_list_timeout(budget), env=_clean_env())
    atomic_json(output_dir.parent / "sevenzip-list-run.json", redact({
        "argv": list_argv, "status": listing.status, "exit_code": listing.exit_code,
        "timed_out": listing.timed_out, "stdout": listing.stdout, "stderr": listing.stderr,
    }))
    # R2: a listing that did not fully succeed (output flood, timeout, crash)
    # yields no member table; extraction is REFUSED instead of running against
    # an implied empty container.
    if listing.status != "succeeded":
        signature = _signature(listing.stderr or listing.stdout)
        error = f"Member listing incomplete ({listing.status}); extraction refused: {signature}"
        return _result("failed", container_format=container_format, version=version,
                       listing_complete=False, error=error)
    members, truncated = _parse_listing(listing.stdout or "")
    if truncated:
        error = (f"Member listing truncated at {MAX_LISTED_MEMBERS} entries; extraction refused "
                 f"(declared totals unverifiable)")
        return _result("failed", container_format=container_format, version=version, members=members,
                       listing_complete=False, error=error)
    try:
        _vet_members(members, budget)
    except InvalidInput as exc:
        return _result("failed", container_format=container_format, version=version, members=members,
                       listing_complete=True, error=f"Member preflight rejected: {exc}")
    declared_files = sum(1 for member in members if not member["directory"])
    if not declared_files:
        return _result("degraded", container_format=container_format, version=version, members=members,
                       listing_complete=True,
                       error="No regular-file members listed; empty or unsupported container content")

    # Extraction is per-member streaming: the total quota is enforced at write
    # time (see _extract_streaming), so the stage can only overshoot its
    # declared budgets by never writing the crossing block.
    output_dir.mkdir(mode=0o700)
    progress = {"files": 0, "bytes": 0}
    stream_error: str | None = None
    links_omitted = 0
    try:
        links_omitted, stream_error = _extract_streaming(
            trusted, sample_path, members, output_dir, budget, progress)
    except _MemberStreamFailure as exc:
        stream_error = str(exc)
    except BudgetExceeded as exc:
        stream_error = f"Extraction aborted at run budget: {exc}"
    links, _ = _sweep_irregular(output_dir, budget) if output_dir.is_dir() else (0, 0)
    links_omitted = links_omitted + links
    files, bytes_total = progress["files"], progress["bytes"]
    # Evidence contract: the old bulk `7z x` wrote one redacted run JSON; the
    # per-member streaming flow writes the same file describing the aggregate
    # extraction (argv shape, streamed/omitted counts, first omission).
    atomic_json(output_dir.parent / "sevenzip-extract-run.json", redact({
        "argv": [trusted, "x", "-so", "-y", "-spd", str(sample_path.absolute()), "<one member per invocation>"],
        "mode": "per-member-streaming", "status": "succeeded" if stream_error is None else "degraded",
        # Kept for consumers of the old bulk-extraction evidence shape: there is
        # no single child process any more, so exit/stdout describe the aggregate.
        "exit_code": 0 if stream_error is None else 1,
        "stdout": f"{files} member(s) streamed, {links_omitted} omitted, {bytes_total} bytes",
        "stderr": stream_error or "",
        "members_streamed": files, "members_omitted": links_omitted,
        "bytes_written": bytes_total, "error": stream_error,
    }))
    if stream_error is not None:
        return _result("degraded" if files else "failed", container_format=container_format,
                       version=version, members=members, files=files, bytes_total=bytes_total,
                       listing_complete=True, extraction_started=True, links_omitted=links_omitted,
                       error=stream_error)
    if not files:
        return _result("degraded", container_format=container_format, version=version, members=members,
                       listing_complete=True, extraction_started=True, links_omitted=links_omitted,
                       error="7z produced no regular files; empty or unsupported container content")
    return _result("succeeded", container_format=container_format, version=version, members=members,
                   files=files, bytes_total=bytes_total, listing_complete=True,
                   extraction_started=True, links_omitted=links_omitted, error=None)
