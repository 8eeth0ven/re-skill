"""Trusted-tool compilation providers. Trusted configuration supplies an executable path.

Mirrors providers.radare2: the executable comes from an explicit environment
variable (RE_RUN_SOLC) or a caller-supplied path, wrapper scripts are never
executed, and every invocation leaves redacted stdout/stderr evidence in the
work directory. A result never claims success unless the tool exited zero and
its machine-readable output parsed into real artifacts.
"""
import os
import re
from pathlib import Path

from .errors import InvalidInput
from .execution import run_command
from .safety import Budget, atomic_json, parse_json, redact

WRAPPER_SUFFIXES = (".bat", ".cmd", ".ps1", ".sh")
_KEEP_ENV = ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR")


def _environment() -> dict[str, str]:
    return {key: os.environ[key] for key in _KEEP_ENV if key in os.environ}


def _first_error_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:300]
    return ""


def _bytecode_len(value: object) -> int:
    if not isinstance(value, str):
        return 0
    text = value.strip()
    if text.startswith("0x"):
        text = text[2:]
    if not text or len(text) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", text):
        return 0
    return len(text) // 2


def solc_compile(source_path: Path, output_dir: Path, budget: Budget, executable: str | None = None) -> dict | None:
    """Compile one Solidity file with the trusted solc binary.

    Returns None when RE_RUN_SOLC (or the explicit executable argument) is not
    configured; the caller is expected to record a skipped check. On compile
    failure the result carries status "failed"/"degraded" plus a stderr
    signature — never a success claim. Only the source file's own directory is
    passed as solc --allow-paths, so multi-root import layouts do not resolve
    and surface as an honest compile failure.
    """
    configured = executable or os.environ.get("RE_RUN_SOLC")
    if not configured:
        return None
    executable_path = Path(configured)
    if not executable_path.is_file() or executable_path.suffix.lower() in WRAPPER_SUFFIXES:
        raise InvalidInput("RE_RUN_SOLC must reference the trusted native solc executable")
    output_dir.mkdir(parents=True, exist_ok=True)
    env = _environment()
    records = []

    version = run_command([str(executable_path), "--version"], output_dir, budget, timeout=15, env=env)
    first_line = (version.stdout or version.stderr).strip().splitlines()
    tool_version = first_line[0].strip() if first_line else "unknown"
    records.append({"argv": [str(executable_path), "--version"], "status": version.status, "exit_code": version.exit_code})
    atomic_json(output_dir / "solc-version-run.json", redact({
        "argv": records[0]["argv"], "status": version.status, "exit_code": version.exit_code,
        "stdout": version.stdout, "stderr": version.stderr,
    }))
    if version.status != "succeeded":
        return {
            "tool": "solc", "version": tool_version, "status": "degraded", "contracts": [],
            "error": f"solc version probe did not succeed ({version.status})",
            "stderr_signature": _first_error_line(version.stderr), "runs": records,
        }

    source_path = source_path if source_path.is_absolute() else source_path.resolve()
    argv = [
        str(executable_path), "--combined-json", "bin,abi",
        "--allow-paths", str(source_path.parent), str(source_path),
    ]
    execution = run_command(argv, output_dir, budget, timeout=min(60, budget.limits["tool_timeout_seconds"]), env=env)
    records.append({"argv": argv, "status": execution.status, "exit_code": execution.exit_code, "timed_out": execution.timed_out})
    atomic_json(output_dir / "solc-compile-run.json", redact({
        "argv": argv, "version": tool_version, "status": execution.status,
        "exit_code": execution.exit_code, "stdout": execution.stdout, "stderr": execution.stderr,
    }))
    failure = {"tool": "solc", "version": tool_version, "contracts": [], "runs": records}
    if execution.status != "succeeded":
        return {
            **failure,
            "status": "failed" if execution.status == "failed" else "degraded",
            "error": f"solc compilation did not succeed ({execution.status})",
            "stderr_signature": _first_error_line(execution.stderr) or _first_error_line(execution.stdout),
        }
    try:
        combined = parse_json(execution.stdout)
    except InvalidInput:
        return {
            **failure, "status": "failed",
            "error": "solc produced unparsable combined-json output",
            "stderr_signature": _first_error_line(execution.stderr),
        }
    if not isinstance(combined, dict) or not isinstance(combined.get("contracts"), dict):
        return {
            **failure, "status": "failed",
            "error": "combined-json output violates the expected shape (contracts object missing)",
            "stderr_signature": _first_error_line(execution.stderr),
        }
    compiler_version = combined.get("version") if isinstance(combined.get("version"), str) else tool_version
    contracts = []
    for index, key in enumerate(sorted(combined["contracts"])):
        item = combined["contracts"][key]
        if not isinstance(item, dict):
            continue
        name = key.rsplit(":", 1)[-1]
        abi = item.get("abi") if isinstance(item.get("abi"), list) else []
        bytecode_len = _bytecode_len(item.get("bin"))
        contracts.append({"name": name, "abi": abi, "bytecode_len": bytecode_len})
        safe_name = re.sub(r"[^A-Za-z0-9_-]", "_", name)[:48] or f"unnamed-{index}"
        atomic_json(output_dir / f"solc-contract-{index}-{safe_name}.json", redact({
            "contract": name, "compiler_version": compiler_version,
            "abi": abi, "bytecode": item.get("bin") if isinstance(item.get("bin"), str) else "",
            "bytecode_len": bytecode_len,
        }))
    return {
        "tool": "solc", "version": compiler_version,
        "status": "succeeded" if contracts else "degraded",
        "contracts": contracts,
        "error": None if contracts else "solc exited zero but produced no contract artifacts",
        "runs": records,
    }
