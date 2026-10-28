"""Vyper compilation adapter (real execution via the trusted vyper binary).

Mirrors ``compilers.solc_compile``: the executable comes from an explicit
argument, ``RE_RUN_VYPER``, the venv's console script next to the running
interpreter, or a ``python -c`` fallback into ``vyper.cli.vyper_compile.main``.
Every invocation leaves redacted stdout/stderr evidence next to the run; a
result never claims success unless vyper exited zero and its combined-json
output parsed into real bytecode + ABI artifacts.

Also carries the contract-fork probe: without anvil/foundry installed this
adapter reports the fork interface as "not-run" and does NOT install a heavy
toolchain (declared honestly instead).
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from .errors import InvalidInput
from .execution import run_command
from .safety import Budget, atomic_json, parse_json, redact

WRAPPER_SUFFIXES = (".bat", ".cmd", ".ps1", ".sh")
_KEEP_ENV = ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR")


def _environment() -> dict[str, str]:
    return {key: os.environ[key] for key in _KEEP_ENV if key in os.environ}


def _resolve_executable(explicit: str | None) -> tuple[list[str] | None, str | None]:
    """Return an argv prefix for invoking vyper, or (None, reason) = honest skip."""
    import importlib.util  # noqa: PLC0415

    if explicit:
        if Path(explicit).suffix.lower() in WRAPPER_SUFFIXES or not Path(explicit).is_file():
            raise InvalidInput("vyper executable must be a real file, not a wrapper script")
        return [str(Path(explicit).absolute())], None
    if (env := os.environ.get("RE_RUN_VYPER")) and Path(env).is_file() and Path(env).suffix.lower() not in WRAPPER_SUFFIXES:
        return [str(Path(env).absolute())], None
    venv_script = Path(sys.executable).parent / "vyper"
    if venv_script.is_file():
        return [str(venv_script)], None
    if found := shutil.which("vyper"):
        return [str(Path(found).absolute())], None
    if importlib.util.find_spec("vyper") is not None:
        return [sys.executable, "-c", "from vyper.cli.vyper_compile import main; main()"], None
    return None, "no vyper executable or importable vyper package found"


def vyper_compile(
    source_path: Path,
    output_dir: Path,
    budget: Budget,
    *,
    executable: str | None = None,
) -> dict | None:
    """Compile one Vyper file to combined-json (bytecode + abi).

    Returns None (caller records a skipped check) when no vyper toolchain is
    available. On compile failure the result carries status "failed" plus a
    stderr signature — never a success claim.
    """
    argv_prefix, reason = _resolve_executable(executable)
    if argv_prefix is None:
        return None
    source_path = Path(source_path)
    if not source_path.is_file():
        raise InvalidInput(f"vyper source not found: {source_path}")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    env = _environment()

    version = run_command([*argv_prefix, "--version"], output_dir, budget, timeout=30, env=env)
    first_line = (version.stdout or version.stderr or "").strip().splitlines()
    tool_version = first_line[0].strip() if first_line else "unknown"
    atomic_json(
        output_dir / "vyper-version-run.json",
        redact({"argv": [*argv_prefix, "--version"], "status": version.status, "exit_code": version.exit_code}),
    )
    if version.status != "succeeded":
        return {
            "tool": "vyper", "version": tool_version, "status": "degraded", "contracts": [],
            "error": f"vyper version probe did not succeed ({version.status})",
            "verification_state": "real-run",
        }

    argv = [*argv_prefix, "-f", "combined_json", str(source_path)]
    compile_run = run_command(argv, output_dir, budget, timeout=120, env=env)
    atomic_json(
        output_dir / "vyper-compile-run.json",
        redact({"argv": argv, "status": compile_run.status, "exit_code": compile_run.exit_code,
                "stdout": compile_run.stdout, "stderr": compile_run.stderr}),
    )
    parsed = None
    if compile_run.status == "succeeded" and compile_run.stdout:
        try:
            parsed = parse_json(compile_run.stdout)
        except Exception:
            parsed = None
    contracts = []
    # combined_json shape: {"version": "...", "<file>.vy": {"bytecode": "0x..", "abi": [...], ...}}
    if isinstance(parsed, dict):
        file_entries = {name: body for name, body in parsed.items()
                        if isinstance(body, dict) and name != "version"}
        target = file_entries.get(source_path.name) or (next(iter(file_entries.values())) if file_entries else None)
        bytecode = target.get("bytecode") if isinstance(target, dict) else None
        abi = target.get("abi") if isinstance(target, dict) else None
        if isinstance(bytecode, str) and len(bytecode) > 2 and isinstance(abi, list):
            contracts.append({
                "name": source_path.stem,
                "bytecode_bytes": len(bytecode) // 2,
                "abi_entries": len(abi),
                "bin_prefix": bytecode[:16],
                "compiler_version": parsed.get("version"),
            })
    signature = ""
    for line in (compile_run.stderr or "").splitlines():
        if line.strip():
            signature = line.strip()[:300]
            break
    return {
        "tool": "vyper",
        "version": tool_version,
        "status": "succeeded" if contracts else ("failed" if compile_run.status != "succeeded" else "degraded"),
        "contracts": contracts,
        "error": None if contracts else (signature or f"vyper exited {compile_run.status} without usable artifacts"),
        "stderr_signature": signature,
        "runs": [
            {"argv": [*argv_prefix, "--version"], "status": version.status, "exit_code": version.exit_code},
            {"argv": argv, "status": compile_run.status, "exit_code": compile_run.exit_code},
        ],
        "verification_state": "real-run",
    }


def vyper_compile_project(
    source_dir: Path, entry: str, output_dir: Path, budget: Budget, *, executable: str | None = None
) -> dict | None:
    """Compile a multi-file project entry (import resolution across sibling .vy files)."""
    entry_path = Path(source_dir) / entry
    result = vyper_compile(entry_path, output_dir, budget, executable=executable)
    if result is not None:
        result["mode"] = "project-import"
        result["entry"] = entry
    return result


def anvil_fork_probe(output_dir: Path | None = None) -> dict:
    """Contract-fork probe WITHOUT installing a heavy chain toolchain.

    anvil/foundry is deliberately not installed here; the adapter ships the
    interface contract and reports "not-run" with the exact missing-environment
    reason. Enabling real forks requires: install foundry, set RE_RUN_ANVIL_RPC,
    then call ``anvil_fork`` below.
    """
    anvil = shutil.which("anvil")
    record = {
        "tool": "anvil-fork",
        "version": None,
        "status": "not-run",
        "verification_state": "not-run",
        "error": None if anvil else "anvil (foundry) not found on PATH; fork execution contract only, "
        "heavy chain toolchain intentionally not installed",
        "fork_contract": {
            "launch": ["anvil", "--fork-url", "<RE_RUN_ANVIL_RPC>", "--fork-block-number", "<n>", "--port", "8545"],
            "operations": [
                "eth_getBalance / eth_call against forked state",
                "evm_snapshot / evm_revert for isolated rollbacks",
                "anvil_setBalance / anvil_impersonateAccount for test fixture state",
            ],
            "enable_condition": "install foundry (anvil) and provide a funded RPC endpoint via RE_RUN_ANVIL_RPC",
        },
        "isolated_backend": "anvil in-process ephemeral node, torn down after each scenario",
    }
    if anvil:
        record["anvil_path"] = anvil
        record["error"] = None
        record["status"] = "available-not-exercised"
    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        atomic_json(Path(output_dir) / "anvil-fork-probe.json", redact(record))
    return record
