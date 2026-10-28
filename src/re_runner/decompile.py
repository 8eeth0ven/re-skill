"""Optional jadx/apktool S1 unpack stage. Trusted configuration supplies a path
via RE_RUN_JADX / RE_RUN_APKTOOL; with nothing configured the stage is skipped
honestly instead of failing. Commands are fixed argument lists (no shell), run
through execution.run_command so process-tree, timeout and output bounds are
inherited, and every invocation lands as redacted evidence JSON next to the
analysis output."""
import os
import shutil
from pathlib import Path

from .execution import run_command
from .errors import BudgetExceeded
from .safety import Budget, atomic_json, redact


TIMEOUT_CAP_SECONDS = 60
VERSION_TIMEOUT_SECONDS = 30
MAX_LISTED_SOURCES = 200
MAX_SCANNED_FILES = 2000
SIGNATURE_CHARS = 400

# Minimal environment: no R2-like plugin hooks exist, but java still needs the
# system paths, and TEMP/TMP inherit the run-scoped scratch directory.
_ENV_KEYS = ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL", "TEMP", "TMP", "TMPDIR", "JAVA_HOME")

# One probe per configured executable per process; the JSON evidence reflects
# the process that actually performed the probe.
_VERSION_CACHE: dict[tuple[str, str], str] = {}


def _clean_env() -> dict[str, str]:
    return {key: os.environ[key] for key in _ENV_KEYS if key in os.environ}


def _java() -> str | None:
    if home := os.environ.get("JAVA_HOME"):
        configured = Path(home).expanduser().absolute() / "bin" / ("java.exe" if os.name == "nt" else "java")
        if configured.is_file():
            return str(configured)
    executable = shutil.which("java")
    return str(Path(executable).absolute()) if executable else None


def _heap_arguments(budget: Budget) -> list[str]:
    # Keep JVM commit comfortably inside the run's Windows job memory limit.
    megabytes = max(64, min(512, int(budget.limits["max_memory_mb"]) // 2))
    # Tool diagnostics are evidence; ask for encoding-independent output.
    return ["-Xmx%dm" % megabytes, "-Dstdout.encoding=utf-8", "-Dstderr.encoding=utf-8"]


def _timeout(budget: Budget) -> int:
    return min(TIMEOUT_CAP_SECONDS, budget.limits["tool_timeout_seconds"])


def _signature(text: str) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) > SIGNATURE_CHARS:
        return collapsed[:SIGNATURE_CHARS] + "..."
    return collapsed


def _probe(tool: str, cache_key: tuple[str, str], argv: list[str], output: Path, budget: Budget) -> str:
    cached = _VERSION_CACHE.get(cache_key)
    if cached is not None:
        return cached
    execution = run_command(argv, output, budget, timeout=min(VERSION_TIMEOUT_SECONDS, budget.limits["tool_timeout_seconds"]), env=_clean_env())
    atomic_json(output / f"{tool}-version-run.json", redact({
        "argv": argv, "status": execution.status, "exit_code": execution.exit_code,
        "stdout": execution.stdout, "stderr": execution.stderr,
    }))
    line = next((ln.strip() for ln in (execution.stdout or "").splitlines() if ln.strip()), "")
    version = line if execution.status == "succeeded" and line else "unknown"
    _VERSION_CACHE[cache_key] = version
    return version


def _collect(directory: Path, patterns: tuple[str, ...]) -> list[str]:
    found: list[Path] = []
    for pattern in patterns:
        for path in sorted(directory.rglob(pattern)):
            if path.is_file():
                found.append(path)
                if len(found) >= MAX_SCANNED_FILES:
                    break
        if len(found) >= MAX_SCANNED_FILES:
            break
    return [path.relative_to(directory.parent).as_posix() for path in found[:MAX_LISTED_SOURCES]]


def _consume_derived(directory: Path, budget: Budget) -> tuple[int, int, str | None]:
    """Fold derived tool output into real usage during a bounded walk (R2).

    jadx/apktool write their own trees, so the runner cannot interpose on the
    write; the honest equivalent is to consume files/unpack_bytes while
    scanning the produced tree immediately after the tool exits, stopping at
    the run's limits with an explicit marker instead of discovering the
    overshoot only at final inventory time.
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
                    try:
                        budget.consume("files", 1)
                        budget.consume("unpack_bytes", info.st_size)
                    except BudgetExceeded:
                        return files, total, (f"derived output exceeded run budgets after {files} files/"
                                              f"{total} bytes; usage recorded at the enforcement point")
                    files += 1
                    total += info.st_size
        except OSError:
            continue
    return files, total, None


def _settle(
    tool: str, execution, version: str, sources: list[str], produced: bool, argv: list[str],
    output: Path, budget: Budget, derived: tuple[int, int, str | None] = (0, 0, None),
) -> dict:
    atomic_json(output / f"{tool}-run.json", redact({
        "argv": argv, "version": version, "status": execution.status,
        "exit_code": execution.exit_code, "timed_out": execution.timed_out,
        "stdout": execution.stdout, "stderr": execution.stderr,
    }))
    result = {"tool": tool, "status": "failed", "version": version, "sources": sources, "error": None,
              "derived_files": derived[0], "derived_bytes": derived[1], "derived_error": derived[2]}
    if execution.status == "succeeded":
        if produced and not derived[2]:
            result["status"] = "succeeded"
        elif produced:
            result["status"] = "degraded"
            result["error"] = derived[2]
        else:
            result["status"] = "degraded"
            result["error"] = f"{tool} exited 0 but produced no analyzable output; empty input or unsupported content"
    elif execution.status == "failed":
        # A non-zero exit is never reported as success. Whether or not partial
        # artifacts landed, the run is degraded with a failure signature (an
        # empty classes.dex makes jadx exit non-zero, and that is the honest
        # "nothing to decompile" signal, not a pipeline crash).
        signature = _signature(execution.stderr or execution.stdout)
        result["status"] = "degraded"
        result["error"] = f"Exit code {execution.exit_code}: {signature}" if signature else f"Exit code {execution.exit_code} without diagnostic output"
    else:
        # timed-out / output-exceeded / cancelled / budget-exceeded: the run
        # was stopped by a bound, so there is nothing trustworthy on disk.
        result["error"] = f"{tool} ended with status {execution.status}"
    return result


def jadx(apk_path: Path, output: Path, budget: Budget, executable: str | None = None) -> dict | None:
    configured = executable or os.environ.get("RE_RUN_JADX")
    if not configured:
        return None
    tool_dir = output / "jadx"
    # run_command uses the run output directory as child cwd; direct callers
    # may hand in a not-yet-created work directory.
    output.mkdir(parents=True, exist_ok=True)
    # The child cwd is the run output directory, so a configured path only
    # survives if it is absolute.
    target = Path(configured).absolute()
    if not target.exists():
        return {"tool": "jadx", "status": "skipped", "version": "unknown", "sources": [],
                "error": f"RE_RUN_JADX path does not exist: {configured}"}
    if target.is_file() and target.suffix.lower() in (".jar", ".txt", ".json", ".zip"):
        return {"tool": "jadx", "status": "skipped", "version": "unknown", "sources": [],
                "error": f"RE_RUN_JADX must reference the jadx launcher or distribution directory, not {target.name}"}
    if target.suffix.lower() in (".bat", ".cmd"):
        # Official bin/jadx.bat resolves the same lib/* classpath. Bypass cmd parsing entirely.
        distribution = target.parent.parent
        if not (distribution / "lib").is_dir():
            return {"tool": "jadx", "status": "skipped", "version": "unknown", "sources": [],
                    "error": "A batch launcher requires the official jadx distribution with sibling lib/"}
        target = distribution
    timeout = _timeout(budget)
    env = _clean_env()
    try:
        if target.is_dir():
            java = _java()
            if not java:
                return {"tool": "jadx", "status": "skipped", "version": "unknown", "sources": [],
                        "error": "jadx directory configuration requires java on PATH"}
            classpath = str(target / "lib" / "*")
            base = [java, *_heap_arguments(budget), "-cp", classpath, "jadx.cli.JadxCLI"]
            version = _probe("jadx", ("java", classpath), [*base, "--version"], output, budget)
            argv = [*base, "--no-res", "-j", "1", "-d", str(tool_dir), str(apk_path.absolute())]
        else:
            base = [str(target)]
            version = _probe("jadx", ("direct", str(target)), [*base, "--version"], output, budget)
            argv = [*base, "--no-res", "-j", "1", "-d", str(tool_dir), str(apk_path.absolute())]
        execution = run_command(argv, output, budget, timeout=timeout, env=env)
    except OSError as exc:
        return {"tool": "jadx", "status": "failed", "version": "unknown", "sources": [],
                "error": f"jadx could not be executed: {exc}"}
    sources = _collect(tool_dir, ("*.java",)) if tool_dir.exists() else []
    derived = _consume_derived(tool_dir, budget) if tool_dir.exists() else (0, 0, None)
    return _settle("jadx", execution, version, sources, bool(sources), argv, output, budget, derived)


def apktool(apk_path: Path, output: Path, budget: Budget, executable: str | None = None) -> dict | None:
    configured = executable or os.environ.get("RE_RUN_APKTOOL")
    if not configured:
        return None
    tool_dir = output / "apktool"
    output.mkdir(parents=True, exist_ok=True)
    target = Path(configured).absolute()
    if not target.exists() or (target.is_dir() and not target.suffix == ".jar"):
        return {"tool": "apktool", "status": "skipped", "version": "unknown", "sources": [],
                "error": f"RE_RUN_APKTOOL must reference an existing apktool jar or wrapper: {configured}"}
    if target.suffix.lower() in (".bat", ".cmd"):
        jar = target.parent / "apktool.jar"
        if not jar.is_file():
            return {"tool": "apktool", "status": "skipped", "version": "unknown", "sources": [],
                    "error": "A batch launcher requires the official sibling apktool.jar"}
        target = jar
    timeout = _timeout(budget)
    env = _clean_env()
    try:
        if target.suffix.lower() == ".jar":
            java = _java()
            if not java:
                return {"tool": "apktool", "status": "skipped", "version": "unknown", "sources": [],
                        "error": "apktool jar configuration requires java on PATH"}
            base = [java, *_heap_arguments(budget), "-jar", str(target)]
            version = _probe("apktool", ("jar", str(target)), [*base, "--version"], output, budget)
            argv = [*base, "d", "-f", "-o", str(tool_dir), str(apk_path.absolute())]
        else:
            base = [str(target)]
            version = _probe("apktool", ("direct", str(target)), [*base, "--version"], output, budget)
            argv = [*base, "d", "-f", "-o", str(tool_dir), str(apk_path.absolute())]
        execution = run_command(argv, output, budget, timeout=timeout, env=env)
    except OSError as exc:
        return {"tool": "apktool", "status": "failed", "version": "unknown", "sources": [],
                "error": f"apktool could not be executed: {exc}"}
    artifacts = _collect(tool_dir, ("AndroidManifest.xml", "apktool.yml", "*.smali")) if tool_dir.exists() else []
    derived = _consume_derived(tool_dir, budget) if tool_dir.exists() else (0, 0, None)
    return _settle("apktool", execution, version, artifacts, bool(artifacts), argv, output, budget, derived)
