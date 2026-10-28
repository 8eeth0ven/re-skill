"""Ghidra headless decompile backend adapter (A-lane round 3).

Covers the 6d acceptance gap ``Ghidra 深度反编译 adapter``: analyzeHeadless is
wired as an independent decompile backend. decompile.py (radare2 route) is
outside this lane's writable set, so this is a sibling module with the same
stage shape: trusted executable resolution via RE_RUN_GHIDRA, a fixed argv run
through execution.run_command (process bounds, timeout, redacted evidence), a
post-script that ONLY reads the program database and writes its results into
the run output directory, and derived-output usage accounting.

Derived-output accounting note: ``_consume_derived`` below is adapted from
re_runner.decompile._consume_derived (same bounded walk + same honesty
markers); it is re-implemented here because decompile.py is a forbidden file
for this lane, and importing it would couple the adapter to that module's
private surface.

Honesty boundaries:
- The adapter never patches the binary, never runs it, and only reads.
- Analysis runs with the headless analyzer's defaults; no scriptable auto-
  analysis customization. Failures surface as failed/degraded with the
  tool's own stderr signature.
- Usage: produced files/bytes are consumed into the budget immediately after
  the child exits, stopping at the run's limits with an explicit marker.
"""
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from .errors import InvalidInput
from .safety import Budget, atomic_json, load_json, redact

TIMEOUT_CAP_SECONDS = 420          # JVM startup + auto-analysis for small ELF
DECOMPILE_PER_FUNCTION_SECONDS = 30
# The shared run_command child preflight sets RLIMIT_NOFILE=128, tuned for
# 7z-class children. A JVM cannot boot under it (log4j2 dies during charset
# service loading before Ghidra even starts -- bisected on this host). The
# adapter keeps every other process bound from execution._posix_limits
# (prctl/parent-death on Linux, RLIMIT_CPU, RLIMIT_FSIZE, no core, new session)
# and raises ONLY the descriptor ceiling to this value for the JVM child.
CHILD_NOFILE = 1024
REAP_SECONDS = 5
# Script-side caps: they bound what the post-script will list/decompile even if
# the program database holds more.
MAX_LISTED_FUNCTIONS = 5000
MAX_DECOMPILED_FUNCTIONS = 64

_POSTSCRIPT_NAME = "re_alane_dump.py"
# PyGhidra/CPython post-script (Ghidra 11.4): reads the current program,
# writes a JSON function list plus bounded decompilation text. Args:
# <out_json> <max_list> <max_decompile> [function-name ...]
_POSTSCRIPT = r'''
import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
out_json = args[0]
max_list = int(args[1])
max_decompile = int(args[2])
only = set(args[3:])

fm = currentProgram.getFunctionManager()
monitor = ConsoleTaskMonitor()
di = DecompInterface()
di.openProgram(currentProgram)

functions = []
decompiled = []
for func in fm.getFunctions(True):
    if len(functions) >= max_list:
        break
    entry = str(func.getEntryPoint())
    record = {"name": func.getName(), "entry": entry,
              "bytes": int(func.getBody().getNumAddresses())}
    functions.append(record)
    wanted = (not only and len(decompiled) < max_decompile) or func.getName() in only
    if wanted and len(decompiled) < max_decompile:
        result = di.decompileFunction(func, DECOMPILE_TIMEOUT, monitor)
        if result.decompileCompleted():
            code = result.getDecompiledFunction().getC()
            record["decompiled"] = True
            decompiled.append({"name": func.getName(), "entry": entry, "code": code})
        else:
            record["decompiled"] = False
            record["decompile_error"] = str(result.getErrorMessage())[:200]

payload = {
    "program": currentProgram.getName(),
    "language": str(currentProgram.getLanguageID()),
    "function_count_total": fm.getFunctionCount(),
    "functions": functions,
    "decompiled": decompiled,
}
with open(out_json, "w") as handle:
    json.dump(payload, handle)
print("ALANE_DUMP_OK functions=%d decompiled=%d" % (len(functions), len(decompiled)))
'''.replace("DECOMPILE_TIMEOUT", str(DECOMPILE_PER_FUNCTION_SECONDS))


def configured_headless(executable: str | None = None) -> str | None:
    """Resolve the trusted analyzeHeadless path, or None when unconfigured.

    Order: explicit argument, RE_RUN_GHIDRA (either the analyzeHeadless file
    itself or a Ghidra install directory), then PATH. Windows resolves the
    .bat launcher; POSIX the shell script.
    """
    candidates: list[str] = []
    if executable:
        candidates.append(executable)
    env_value = os.environ.get("RE_RUN_GHIDRA")
    if env_value:
        candidates.append(env_value)
    which = shutil.which("analyzeHeadless")
    if which:
        candidates.append(which)
    for candidate in candidates:
        path = Path(candidate)
        if path.is_dir():
            path = path / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
        if path.is_file() and os.access(path, os.X_OK):
            if path.suffix.lower() in (".bat", ".cmd") and os.name != "nt":
                continue
            return str(path)
    return None


def _tool_env() -> dict[str, str]:
    """Trusted fixed allow-list: Ghidra needs PATH/HOME (user settings dir) and
    the JVM resolver variables; nothing else is inherited."""
    keys = ("PATH", "HOME", "JAVA_HOME", "LANG", "LC_ALL",
            "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR")
    return {key: os.environ[key] for key in keys if key in os.environ}


def _run_bounded(argv: list[str], cwd: Path, budget: Budget, timeout: int) -> SimpleNamespace:
    """One headless child under execution-style bounds, with the JVM fd ceiling.

    Mirrors execution.run_command's shape (fixed argv, no shell, bounded
    capture, timeout -> kill -> reap, honest status) so evidence and failure
    semantics stay comparable. The only deliberate difference is
    RLIMIT_NOFILE=CHILD_NOFILE for the reason given at the constant.
    """
    budget.check()
    limit = budget.limits["max_tool_output_bytes"]

    def preexec():
        # Mirrors execution._posix_limits field-for-field (Linux
        # prctl(PR_SET_PDEATHSIG)=parent-death SIGKILL; RLIMIT_CPU at the
        # timeout, RLIMIT_FSIZE at the unpack quota, no core dumps) with ONE
        # deliberate deviation: RLIMIT_NOFILE is CHILD_NOFILE instead of the
        # shared 128, and it is set HERE because the shared helper pins the
        # hard limit too, after which no child could raise it.
        import resource
        if sys.platform.startswith("linux"):
            import ctypes
            libc = ctypes.CDLL(None, use_errno=True)
            libc.prctl(1, signal.SIGKILL, 0, 0, 0)   # PR_SET_PDEATHSIG
        resource.setrlimit(resource.RLIMIT_CPU, (timeout + 1, timeout + 2))
        resource.setrlimit(resource.RLIMIT_FSIZE, (budget.limits["max_unpack_bytes"],) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (CHILD_NOFILE, CHILD_NOFILE))

    kwargs = {
        "cwd": str(cwd), "env": _tool_env(), "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "shell": False,
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    else:
        kwargs["start_new_session"] = True
        kwargs["preexec_fn"] = preexec
    started = time.monotonic()
    process = subprocess.Popen(argv, **kwargs)
    timed_out = False
    try:
        out, err = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            process.kill()
        try:
            out, err = process.communicate(timeout=REAP_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            out, err = process.communicate()
    stdout = (out or b"")[:limit].decode("utf-8", "replace")
    stderr = (err or b"")[:limit].decode("utf-8", "replace")
    status = "timed-out" if timed_out else ("succeeded" if process.returncode == 0 else "failed")
    return SimpleNamespace(status=status, exit_code=process.returncode, timed_out=timed_out,
                           stdout=stdout, stderr=stderr,
                           duration_seconds=time.monotonic() - started)


def _consume_derived(directory: Path, budget: Budget) -> tuple[int, int, str | None]:
    """Fold derived tool output into real usage during a bounded walk.

    Adapted from re_runner.decompile._consume_derived (same semantics: files +
    unpack_bytes are consumed while scanning the produced tree immediately
    after the tool exits, stopping at the run's limits with an explicit marker
    instead of discovering the overshoot at final inventory time). Re-implemented
    here because decompile.py is outside this lane's writable set.
    """
    files = total = 0
    stack = [(directory, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > budget.limits["max_depth"]:
            return files, total, f"derived output exceeds max depth after {files} files/{total} bytes; usage is incomplete"
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    if entry.is_symlink():
                        continue
                    info = entry.stat(follow_symlinks=False)
                    if entry.is_dir(follow_symlinks=False):
                        stack.append((Path(entry.path), depth + 1))
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    files += 1
                    total += info.st_size
                    if files > budget.limits["max_files"] or total > budget.limits["max_unpack_bytes"]:
                        return files, total, f"derived output exceeds run budgets after {files} files/{total} bytes; usage is incomplete"
        except OSError:
            continue
    budget.consume("files", files)
    budget.consume("unpack_bytes", total)
    return files, total, None


def headless_decompile(binary_path: Path, output_dir: Path, budget: Budget,
                       executable: str | None = None, project_name: str = "alane",
                       max_functions: int = 16, only_functions: list[str] | None = None) -> dict | None:
    """Run Ghidra headless on one binary and return functions + decompilation.

    Returns None when RE_RUN_GHIDRA / explicit executable is not configured
    (the honest skip signal), or a result dict {"tool","status","functions",
    "decompiled",...}. The binary is IMPORTED read-only into a throwaway
    project; ``-deleteProject`` removes it after the post-script runs. Nothing
    is executed and nothing is patched.
    """
    headless = configured_headless(executable)
    if not headless:
        return None
    binary_path = Path(binary_path)
    if not binary_path.is_file():
        raise InvalidInput(f"Input binary not found: {binary_path}")
    if binary_path.stat().st_size > budget.limits["max_input_bytes"]:
        raise InvalidInput("Input exceeds max_input_bytes")
    output_dir = Path(output_dir)
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    work = output_dir / "work"
    scripts = output_dir / "scripts"
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    scripts.mkdir(parents=True, exist_ok=True, mode=0o700)
    script_path = scripts / _POSTSCRIPT_NAME
    script_path.write_text(_POSTSCRIPT, encoding="utf-8")
    out_json = output_dir / "ghidra-functions.json"
    argv = [
        headless, str(work.resolve()), project_name,
        "-import", str(binary_path.resolve()),
        "-scriptPath", str(scripts.resolve()),
        "-postScript", _POSTSCRIPT_NAME,
        str(out_json), str(MAX_LISTED_FUNCTIONS), str(min(max_functions, MAX_DECOMPILED_FUNCTIONS)),
        *(list(only_functions or [])),
        "-deleteProject",
    ]
    execution = _run_bounded(argv, output_dir.parent, budget,
                             timeout=min(TIMEOUT_CAP_SECONDS, budget.limits["tool_timeout_seconds"]))
    atomic_json(output_dir / "ghidra-headless-run.json", redact({
        "argv": argv, "status": execution.status, "exit_code": execution.exit_code,
        "timed_out": execution.timed_out,
        "stdout": execution.stdout[-4000:], "stderr": execution.stderr[-4000:],
    }))
    if not out_json.is_file():
        signature = " ".join((execution.stderr or execution.stdout or "").split())[:300]
        return {"tool": "ghidra", "status": "failed", "functions": [], "decompiled": [],
                "error": f"Headless run produced no function dump ({execution.status}): {signature}"}
    payload = load_json(out_json)
    files, total, marker = _consume_derived(output_dir, budget)
    decompiled = payload.get("decompiled", [])
    status = "succeeded" if decompiled and not marker else ("succeeded" if payload.get("functions") else "degraded")
    return {
        "tool": "ghidra", "status": status, "program": payload.get("program"),
        "language": payload.get("language"),
        "function_count_total": payload.get("function_count_total"),
        "functions": payload.get("functions", []),
        "decompiled": [{"name": d["name"], "entry": d["entry"], "code": d["code"]} for d in decompiled],
        "derived_files": files, "derived_bytes": total, "usage_marker": marker,
        "error": marker,
    }
