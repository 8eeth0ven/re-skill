"""Optional bandit rule-engine pass for source trees. Trusted PATH resolution only."""
import os
import shutil
from pathlib import Path

from .errors import InvalidInput
from .execution import run_command
from .safety import Budget, atomic_json, parse_json, redact

# High-impact execution/de-serialization APIs the source profile turns into
# candidates: exec/eval, os.* command execution, subprocess with a shell and
# unsafe yaml loading. Complements the in-process AST taint paths (different
# rule ids, so the two layers never collide).
DANGEROUS_RULES = frozenset({"B102", "B307", "B506", "B602", "B604", "B605", "B606"})
MAX_FINDINGS = 200
ISSUE_TEXT_LIMIT = 200
STDOUT_HEAD = 4000
# bandit exit codes (verified against 1.9.4): 0 = no issues, 1 = issues found,
# 2 = it could not do its job. Exit 1 with parseable JSON is a success.
FINDINGS_EXIT = 1
KEEP_ENV = ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR")


def resolve_executable(executable: str | None = None) -> str | None:
    """Resolve the trusted bandit program: explicit argument, then PATH. None when absent."""
    candidate = executable or shutil.which("bandit")
    if not candidate:
        return None
    path = Path(candidate)
    if not path.is_file() or path.suffix.lower() in (".bat", ".cmd", ".ps1", ".sh"):
        raise InvalidInput("bandit must reference the trusted native bandit executable")
    return str(path)


def _version(executable: str, output: Path, budget: Budget, env: dict[str, str]) -> str:
    argv = [executable, "--version"]
    probe = run_command(argv, output, budget, timeout=5, env=env)
    atomic_json(output / "bandit-version-run.json", redact({
        "argv": argv, "status": probe.status, "exit_code": probe.exit_code,
        "stdout": probe.stdout, "stderr": probe.stderr,
    }))
    text = (probe.stdout or probe.stderr).strip().splitlines()
    first = text[0].strip() if text else ""
    if first.lower().startswith("bandit"):
        return first.split()[-1]
    return "unknown"


def _relative(filename: str, root: Path) -> str:
    try:
        return Path(filename).resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError, IndexError):
        return Path(filename).name


def _normalize(results, root: Path) -> list[dict]:
    findings = []
    for row in results[:MAX_FINDINGS]:
        if not isinstance(row, dict):
            return []
        lines = row.get("line_range")
        line = 0
        if isinstance(lines, list):
            line = next((n for n in lines if isinstance(n, int) and not isinstance(n, bool)), 0)
        findings.append({
            "rule": str(row.get("test_id", "unknown")),
            "severity": str(row.get("issue_severity", "UNDEFINED")),
            "file": _relative(str(row.get("filename", "")), root),
            "line": line,
            "issue_text": str(row.get("issue_text", ""))[:ISSUE_TEXT_LIMIT],
        })
    return findings


def bandit_scan(
    source_dir: Path, output_dir: Path, budget: Budget, executable: str | None = None,
) -> dict | None:
    """Run bandit over a source tree and normalize its findings.

    Returns None when no trusted bandit exists (the caller reports an honest
    skip). ToolRun semantics (argv/version/artifact enumeration) stay with the
    caller; this layer only guarantees the evidence files land in output_dir.
    """
    resolved = resolve_executable(executable)
    if resolved is None:
        return None
    env = {key: os.environ[key] for key in KEEP_ENV if key in os.environ}
    version = _version(resolved, output_dir, budget, env)
    target = Path(source_dir)
    argv = [resolved, "-q", "-f", "json"] + (["-r"] if target.is_dir() else []) + [str(target.absolute())]
    execution = run_command(
        argv, output_dir, budget, timeout=min(60, budget.limits["tool_timeout_seconds"]), env=env,
    )
    atomic_json(output_dir / "bandit-run.json", redact({
        "argv": argv, "version": version, "status": execution.status, "exit_code": execution.exit_code,
        "timed_out": execution.timed_out, "stdout_bytes": len(execution.stdout),
        "stdout_head": execution.stdout[:STDOUT_HEAD], "stderr": execution.stderr[:STDOUT_HEAD],
    }))
    if execution.status not in ("succeeded", "failed"):
        return {"tool": "bandit", "version": version, "status": "degraded", "findings": [], "metrics": {},
                "error": f"bandit run did not complete: {execution.status}"}
    if execution.status == "failed" and execution.exit_code != FINDINGS_EXIT:
        return {"tool": "bandit", "version": version, "status": "degraded", "findings": [], "metrics": {},
                "error": f"bandit exited with code {execution.exit_code}"}
    try:
        report = parse_json(execution.stdout)
        if not isinstance(report, dict) or not isinstance(report.get("results"), list):
            raise InvalidInput("bandit findings contract violated")
    except InvalidInput:
        return {"tool": "bandit", "version": version, "status": "failed", "findings": [], "metrics": {},
                "error": "Invalid bandit findings JSON"}
    atomic_json(output_dir / "bandit.json", redact(report))
    metrics = report.get("metrics")
    totals = metrics.get("_totals") if isinstance(metrics, dict) else None
    stats = {}
    if isinstance(totals, dict):
        stats = {key: value for key, value in totals.items() if isinstance(value, int) and not isinstance(value, bool)}
    return {
        "tool": "bandit", "version": version, "status": "succeeded",
        "findings": _normalize(report["results"], target), "metrics": stats, "error": None,
    }
