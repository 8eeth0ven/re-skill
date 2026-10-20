"""Bound subprocess time, memory, output and process-tree lifetime."""
import ctypes
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .errors import BudgetExceeded, Cancelled, CapabilityMissing
from .safety import Budget, atomic_write, redact_text, redact_text_truncated


class WindowsJob:
    def __init__(self, memory_mb: int):
        from ctypes import wintypes as w

        class Basic(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", w.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", w.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", w.DWORD), ("SchedulingClass", w.DWORD),
            ]

        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
            )]

        class Extended(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", Basic), ("IoInfo", IO), ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.restype = w.HANDLE
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
        kernel.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
        kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        kernel.TerminateJobObject.argtypes = [w.HANDLE, w.UINT]
        kernel.CloseHandle.argtypes = [w.HANDLE]
        self.kernel, self.handle = kernel, kernel.CreateJobObjectW(None, None)
        config = Extended()
        config.BasicLimitInformation.LimitFlags = 0x2000 | 0x100  # kill-on-close, process memory
        config.BasicLimitInformation.LimitFlags |= 0x8  # active-process limit
        config.BasicLimitInformation.ActiveProcessLimit = 16
        config.ProcessMemoryLimit = memory_mb * 1024 * 1024
        if not self.handle or not kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(config), ctypes.sizeof(config)):
            self.close()
            raise CapabilityMissing("Cannot create Windows process/memory isolation job")

    def attach_and_resume(self, process: subprocess.Popen) -> None:
        from ctypes import wintypes as w
        handle = w.HANDLE(int(process._handle))
        if not self.kernel.AssignProcessToJobObject(self.handle, handle):
            raise CapabilityMissing("Cannot attach process tree to Windows job")
        ntdll = ctypes.WinDLL("ntdll")
        ntdll.NtResumeProcess.argtypes = [w.HANDLE]
        ntdll.NtResumeProcess.restype = ctypes.c_long
        if ntdll.NtResumeProcess(handle) != 0:
            raise CapabilityMissing("Cannot resume isolated Windows process")

    def kill(self) -> None:
        if self.handle:
            self.kernel.TerminateJobObject(self.handle, 1)

    def close(self) -> None:
        if getattr(self, "handle", None):
            self.kernel.CloseHandle(self.handle)
            self.handle = None


@dataclass
class Execution:
    exit_code: int | None
    status: str
    stdout: str
    stderr: str
    timed_out: bool
    duration: float
    reap_failed: bool = False


REAP_SECONDS = 5.0


def _await_exit(process: subprocess.Popen, timeout: float) -> bool:
    """Wait for exit; if the process refuses to die, kill and wait a bounded extra window."""
    try:
        process.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        pass
    process.kill()
    deadline = time.monotonic() + REAP_SECONDS
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    return process.poll() is not None


def _sweep_escaped_group(pid: int) -> None:
    # Best-effort POSIX sweep: setsid grandchildren may escape the killed process
    # group, so re-signal any process still reporting the group. Never raises.
    proc = Path("/proc")
    if os.name == "nt" or not proc.is_dir():
        return
    try:
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                text = (entry / "stat").read_text()
                fields = text[text.rindex(")") + 1:].split()
                if fields[2] == str(pid):
                    os.killpg(pid, signal.SIGKILL)
                    return
            except (OSError, ValueError, IndexError):
                continue
    except OSError:
        return


def _posix_limits(memory_mb: int, seconds: int, file_bytes: int):
    def apply():
        import resource
        if sys.platform.startswith("linux"):
            libc = ctypes.CDLL(None, use_errno=True)
            libc.prctl(1, signal.SIGKILL, 0, 0, 0)
        # macOS reserves very large virtual address spaces. RLIMIT_AS is enforced on Linux;
        # POSIX CPU/files/time limits still apply on macOS, with memory readiness reported separately.
        if sys.platform.startswith("linux"):
            resource.setrlimit(resource.RLIMIT_AS, (memory_mb << 20, memory_mb << 20))
        resource.setrlimit(resource.RLIMIT_CPU, (seconds + 1, seconds + 2))
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    return apply


# Final settlement scrub for captured tool output. This runs after kill/reap
# and thread join and must NOT call budget.check(): settlement turns a stop
# into a finished Execution and may not be interrupted by cancellation (stop
# and settle stay separate, mirroring Budget.settling), so the bound on this
# phase is complexity, not the budget. redact_text is linear, and the hard cap
# below keeps even a misconfigured max_tool_output_bytes (contract ceiling is
# 16 MiB) linearly cheap on the main process.
REDACT_HARD_CAP_CHARS = 4 * 1024 * 1024


def _settle_output(raw: bytearray, *, stream_truncated: bool = False) -> str:
    """Redact one captured buffer with a hard linear bound on settlement work.

    R3 ordering: redaction runs on the FULL captured buffer first and only the
    already-redacted text is truncated at the cap. Truncating before redaction
    would let a private key or token straddle the cut — a BEGIN header with its
    body inside the retained region and its END marker beyond it decoded as an
    "unclosed" block that the old redactor kept verbatim. Dropping a tail never
    proves the retained prefix is safe, so nothing is truncated before it has
    been through the redactor. redact_text/redact_text_truncated are linear, so
    the complexity bound is unchanged; the cap only bounds the RESULT size and
    keeps worst-case settlement work constant-bounded even under a misconfigured
    max_tool_output_bytes.

    stream_truncated is set when the reader dropped bytes from this specific
    stream (the pipe carried more than the retained cap). The redactor then
    also scrubs a partial sensitive token whose head ends exactly at the cut —
    a straddled AKIA/gh_/sk- token legitimately fails its full-shape pattern
    when its tail is gone.
    """
    text = bytes(raw).decode("utf-8", "replace")
    redacted = redact_text_truncated(text) if stream_truncated else redact_text(text)
    if len(redacted) <= REDACT_HARD_CAP_CHARS:
        return redacted
    dropped = len(redacted) - REDACT_HARD_CAP_CHARS
    return redacted[:REDACT_HARD_CAP_CHARS] + f"\n[TRUNCATED {dropped} CHARS OVER SETTLEMENT REDACTION CAP {REDACT_HARD_CAP_CHARS}]"


def run_command(
    argv: list[str], cwd: Path, budget: Budget, *, timeout: int | None = None,
    env: dict[str, str] | None = None, stdout_path: Path | None = None,
    stderr_path: Path | None = None,
) -> Execution:
    if not argv or any(not isinstance(x, str) or "\x00" in x for x in argv):
        raise ValueError("Invalid argument list")
    budget.check()
    timeout = timeout or budget.limits["tool_timeout_seconds"]
    limit = budget.limits["max_tool_output_bytes"]
    started = time.monotonic()
    job = WindowsJob(budget.limits["max_memory_mb"]) if os.name == "nt" else None
    kwargs = {
        "cwd": cwd, "env": env, "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "shell": False,
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW | 0x4
    else:
        kwargs["start_new_session"] = True
        kwargs["preexec_fn"] = _posix_limits(
            budget.limits["max_memory_mb"], timeout, budget.limits["max_unpack_bytes"],
        )
    process = None
    buffers, sizes = [bytearray(), bytearray()], [0, 0]
    overflow = threading.Event()
    threads = []

    def reader(pipe, index):
        try:
            while block := pipe.read1(65536):
                sizes[index] += len(block)
                remaining = max(0, limit - len(buffers[index]))
                buffers[index].extend(block[:remaining])
                if sum(sizes) > limit:
                    overflow.set()
        finally:
            pipe.close()

    def kill_tree():
        if process is None:
            return
        if job:
            job.kill()
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                # Best-effort sweep: the group may already be gone, or the id
                # may have been recycled to a process we must not signal.
                pass
            _sweep_escaped_group(process.pid)

    status, timed_out = "failed", False
    reap_failed = False
    try:
        process = subprocess.Popen(argv, **kwargs)
        if job:
            job.attach_and_resume(process)
        for index, pipe in enumerate((process.stdout, process.stderr)):
            thread = threading.Thread(target=reader, args=(pipe, index), daemon=True)
            threads.append(thread)
            thread.start()
        while process.poll() is None:
            budget.check()
            if overflow.is_set():
                status = "output-exceeded"
                kill_tree()
                break
            if time.monotonic() - started >= timeout:
                status, timed_out = "timed-out", True
                kill_tree()
                break
            time.sleep(0.03)
        reap_failed = not _await_exit(process, 5)
        # Orphan children remain in the same job/group even after the main tool exits.
        kill_tree()
        for thread in threads:
            thread.join(timeout=5)
        if status not in ("timed-out", "output-exceeded", "cancelled", "budget-exceeded"):
            status = "output-exceeded" if overflow.is_set() else ("succeeded" if process.returncode == 0 else "failed")
    except (Cancelled, BudgetExceeded) as exc:
        status = "cancelled" if isinstance(exc, Cancelled) else "budget-exceeded"
    finally:
        if process:
            kill_tree()
            if not _await_exit(process, 5):
                reap_failed = True
        if job:
            job.close()
        for thread in threads:
            thread.join(timeout=1)
    stdout, stderr = (
        _settle_output(buffer, stream_truncated=sizes[index] > len(buffers[index]))
        for index, buffer in enumerate(buffers)
    )
    if stdout_path:
        atomic_write(stdout_path, stdout.encode("utf-8"))
    if stderr_path:
        atomic_write(stderr_path, stderr.encode("utf-8"))
    return Execution(process.returncode, status, stdout, stderr, timed_out, time.monotonic() - started, reap_failed)

