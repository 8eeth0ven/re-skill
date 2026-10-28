"""Static UPX unpack route for packed PE samples.

Fully static: the trusted upx executable is invoked only to read and write
files (`upx --version`, `upx -d`). The sample itself is never launched as a
process, and a successful unpack is recorded as a file transformation with a
behavioral baseline/delta comparison — it is evidence about the artifact, not
a claim that any protection was bypassed at runtime.
"""
import os
from pathlib import Path

from .errors import InvalidInput
from .execution import run_command
from .safety import Budget, atomic_json, redact, regular_file, sha256_file

_SCRIPT_SUFFIXES = (".bat", ".cmd", ".ps1", ".sh")
_UPX_SECTION_PREFIXES = ("upx", ".upx")
# Formats UPX actually writes upx-prefixed section names for (PE upx0/upx1,
# Mach-O upxTEXT). A packed ELF usually drops its section header table, so the
# ELF tag is accepted for parity: indication can only fire when sections exist,
# while the direct upx_unpack route stays usable regardless of sections.
_UPX_FORMAT_TAGS = ("PE", "ELF", "MACHO")


def _trusted_executable(configured: str | None) -> Path:
    # Same trust boundary as providers.radare2: only a real executable file is
    # accepted; interpreted wrappers must never run on a sample's behalf.
    path = Path(configured or "").absolute()
    if not configured or not path.is_file() or path.suffix.lower() in _SCRIPT_SUFFIXES:
        raise InvalidInput("RE_RUN_UPX must reference the trusted native upx executable")
    return path


def _tool_env() -> dict[str, str]:
    # Mirror the provider allowlist: UPX must not inherit caller-controlled
    # configuration beyond the minimal OS variables it needs.
    keep = ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR")
    return {key: os.environ[key] for key in keep if key in os.environ}


def _pe_summary(path: Path) -> dict:
    """Static lief summary used for the baseline and the unpacked comparison."""
    import lief

    binary = lief.parse(str(path))
    if binary is None:
        raise InvalidInput(f"LIEF rejected {path.name}; UPX baseline comparison is unavailable")
    sections = [
        {"name": str(section.name), "bytes": int(section.size), "entropy": round(float(section.entropy), 4)}
        for section in list(binary.sections)[:2000]
    ]
    entropies = [item["entropy"] for item in sections if item["entropy"] > 0]
    return {
        "sha256": sha256_file(path),
        "bytes": int(regular_file(path).st_size),
        "section_names": sorted({item["name"].lower() for item in sections if item["name"]}),
        "sections": sections,
        "max_section_entropy": round(max(entropies), 4) if entropies else None,
        "import_libraries": sorted({str(entry.name) for entry in getattr(binary, "imports", [])})[:2000],
    }


def _packed_section_names(summary: dict) -> list[str]:
    return sorted(name for name in summary["section_names"] if name.startswith(_UPX_SECTION_PREFIXES))


def upx_indication(analysis: dict) -> dict | None:
    """Packing indication mirroring protections.annotate section-name thresholds."""
    format_tag = str(analysis.get("format", "")).rsplit(".", 1)[-1].upper()
    if format_tag not in _UPX_FORMAT_TAGS:
        return None
    sections = analysis.get("sections", [])
    if not isinstance(sections, list):
        return None
    names = {str(item.get("name", "")).lower() for item in sections}
    packed = sorted(name for name in names if name.startswith(_UPX_SECTION_PREFIXES))
    high_entropy = [
        str(item.get("name")) for item in sections
        if item.get("bytes", 0) >= 4096 and item.get("entropy", 0) >= 7.2
    ]
    if not packed and not high_entropy:
        return None
    return {"packed_sections": packed, "high_entropy_sections": high_entropy}


def _failure_signature(execution) -> str:
    text = (execution.stderr or execution.stdout or "").strip()
    if not text:
        return f"upx -d ended with status {execution.status} and exit code {execution.exit_code}"
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    # UPX prints its banner to stdout; the diagnostic line carries the signature
    # (e.g. "NotPackedException: not packed by UPX").
    signature = next((line for line in lines if "exception" in line.lower()), lines[-1])
    return redact(signature)[:500]


def _route(status: str, version: str, baseline: dict, unpacked: dict | None, delta: dict | None, error: str | None, runs: list) -> dict:
    return {
        "tool": "upx", "status": status, "version": version,
        "baseline": baseline, "unpacked": unpacked, "delta": delta, "error": error,
        "runs": runs,
        "evidence": ["upx-version-run.json", "upx-unpack-run.json"],
        "mode": "static file transformation; the sample is never launched as a process",
    }


def upx_unpack(sample_path: Path, output_dir: Path, budget: Budget, executable: str | None = None) -> dict | None:
    """Attempt one static `upx -d` pass and record baseline/delta evidence.

    Returns None when RE_RUN_UPX is not configured (caller records a skip).
    Statuses: succeeded (unpack confirmed by the behavioral comparison where
    packed section names existed), degraded (exit zero but comparison is
    inconclusive), failed (tool error or a sample UPX did not pack).
    """
    configured = executable or os.environ.get("RE_RUN_UPX")
    if not configured:
        return None
    tool = _trusted_executable(configured)
    regular_file(sample_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    env = _tool_env()
    baseline = _pe_summary(Path(sample_path))
    packed_names = _packed_section_names(baseline)

    # Version probe runs once per attempt so failures stay attributable.
    version_argv = [str(tool), "--version"]
    probe = run_command(version_argv, output_dir, budget, timeout=5, env=env)
    output_text = probe.stdout or probe.stderr
    version = output_text.strip().splitlines()[0] if output_text.strip() else "unknown"
    atomic_json(output_dir / "upx-version-run.json", redact({
        "argv": version_argv, "status": probe.status, "exit_code": probe.exit_code,
        "stdout": probe.stdout, "stderr": probe.stderr,
    }))

    target = output_dir / "unpacked.bin"
    argv = [str(tool), "-d", "-o", str(target), str(Path(sample_path).absolute())]
    execution = run_command(argv, output_dir, budget, timeout=min(60, budget.limits["tool_timeout_seconds"]), env=env)
    atomic_json(output_dir / "upx-unpack-run.json", redact({
        "argv": argv, "version": version, "status": execution.status, "exit_code": execution.exit_code,
        "stdout": execution.stdout, "stderr": execution.stderr,
    }))
    runs = [
        {"argv": version_argv, "status": probe.status, "exit_code": probe.exit_code},
        {"argv": argv, "status": execution.status, "exit_code": execution.exit_code, "timed_out": execution.timed_out},
    ]
    if execution.status != "succeeded":
        # upx -d exits non-zero for a sample it did not pack (NotPackedException);
        # the captured diagnostic line is recorded as the failure signature.
        return _route("failed", version, baseline, None, None, _failure_signature(execution), runs)
    if not target.is_file():
        return _route("failed", version, baseline, None, None, "UPX exited zero but produced no unpacked image", runs)
    try:
        unpacked = _pe_summary(target)
    except InvalidInput as exc:
        return _route("failed", version, baseline, None, None, str(exc), runs)
    budget.consume("unpack_bytes", unpacked["bytes"])
    delta = {
        "packed_section_names_baseline": packed_names,
        "packed_sections_absent": not any(name in unpacked["section_names"] for name in packed_names),
        "size_grew": unpacked["bytes"] > baseline["bytes"],
        "entropy_dropped": (
            unpacked["max_section_entropy"] is not None and baseline["max_section_entropy"] is not None
            and unpacked["max_section_entropy"] < baseline["max_section_entropy"]
        ),
        "sha256_changed": unpacked["sha256"] != baseline["sha256"],
    }
    if packed_names and not delta["packed_sections_absent"]:
        status, error = "degraded", "Unpacked image still carries UPX-named sections; behavioral comparison is inconclusive"
    else:
        status, error = "succeeded", None
    return _route(status, version, baseline, unpacked, delta, error, runs)
