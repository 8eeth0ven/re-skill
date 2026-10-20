"""Doctor inventory: global capability probe plus per-profile required/optional readiness."""
import importlib.metadata
import os
import platform
import shutil
import time
from dataclasses import asdict
from pathlib import Path

from .contracts import BUDGET_DEFAULTS
from .execution import run_command
from .models import Capability, KINDS
from .safety import Budget


PACKAGES = {
    "lief": ["pe", "elf", "mach-o", "imports", "sections"],
    "capstone": ["x86", "x86_64", "arm", "arm64", "mips", "disassembly"],
    "dnfile": ["dotnet-metadata"], "defusedxml": ["xml-without-external-entities"],
    "cryptography": ["private-key-sign-verify-control"],
    "PyYAML": ["bounded-safe-yaml"], "jsonschema": ["input-contracts"],
    "pyserial": ["bounded-serial-read"], "grpcio": ["grpc-query"],
    "grpcio-reflection": ["grpc-service-reflection"],
}
TOOLS = {
    "jadx": ["android-decompile"], "apktool": ["android-resources"],
    "adb": ["android-device-identity"], "ideviceinfo": ["ios-device-identity"],
    "r2": ["native-disassemble"], "ghidra": ["decompile-requires-provider-setup"],
    "tshark": ["traffic-deep-dissection"], "unsquashfs": ["squashfs-requires-isolation"],
    "qemu-system-x86_64": ["emulation-requires-image-configuration"],
    "forge": ["contract-test-requires-fixture-project"], "semgrep": ["source-analysis"],
    "docker": ["container-sandbox-requires-running-daemon"],
    "7z": ["firmware-archive-extract"], "upx": ["packed-sample-unpack"],
    "solc": ["solidity-compile"],
}

# Providers resolve tools from an explicit RE_RUN_<NAME> variable first (trusted operator
# configuration), then PATH. jadx/apktool additionally accept a directory (java classpath
# mode), which doctor reports as "present" without executing.
_ENV_PROVIDERS = {"jadx": "RE_RUN_JADX", "apktool": "RE_RUN_APKTOOL", "upx": "RE_RUN_UPX", "7z": "RE_RUN_7Z", "solc": "RE_RUN_SOLC", "r2": "RE_RUN_R2"}

# Tool resolution follows providers.radare2: RE_RUN_R2 (r2 only) or PATH, and .bat/.cmd/.ps1/.sh
# wrapper scripts are never executed; a native executable is required.
WRAPPER_SUFFIXES = (".bat", ".cmd", ".ps1", ".sh")
# Version commands that are safe to execute directly. Tools without an entry (ghidra) are only
# path-resolved and never launched. The whole probe keeps a shared wall-clock budget.
_VERSION_COMMANDS = {
    "jadx": ["--version"], "apktool": ["--version"], "adb": ["version"], "ideviceinfo": ["--version"],
    "r2": ["-qv"], "tshark": ["--version"], "unsquashfs": ["-v"], "qemu-system-x86_64": ["--version"],
    "forge": ["--version"], "semgrep": ["--version"], "docker": ["--version"], "solc": ["--version"],
    "7z": ["i"], "upx": ["--version"],
}
_VERSION_LINE_LIMIT = 200
_PROBE_WALL_SECONDS = 10


def _requirement(name, kind, required, purpose, operations, requires_environment=False):
    return {
        "name": name, "kind": kind, "required": required, "purpose": purpose,
        "operations": list(operations), "requires_environment": requires_environment,
    }


# Per-profile capability matrix, derived from the actual code paths of each profile module.
# required: the profile cannot start (or the module cannot import) without it.
# optional: improves or extends the profile; absence degrades but does not block.
# Entries marked "not-wired-yet" are suggested routes that no current code path invokes.
PROFILE_REQUIREMENTS = {
    "web": (
        _requirement(
            "grpcio", "package", False,
            "Optional gRPC reflection client for grpc:// locators on the shared web/api profile; "
            "missing raises CapabilityMissing (re-skill-runner[grpc])", PACKAGES["grpcio"],
        ),
        _requirement(
            "grpcio-reflection", "package", False,
            "Optional gRPC reflection stubs used to enumerate services; missing raises "
            "CapabilityMissing (re-skill-runner[grpc])", PACKAGES["grpcio-reflection"],
        ),
    ),
    "api": (
        _requirement(
            "grpcio", "package", False,
            "gRPC reflection client for grpc:// locators (profiles.web_api.grpc_services); missing "
            "raises CapabilityMissing (re-skill-runner[grpc])", PACKAGES["grpcio"],
        ),
        _requirement(
            "grpcio-reflection", "package", False,
            "gRPC reflection stubs used to enumerate services (profiles.web_api.grpc_services); "
            "missing raises CapabilityMissing (re-skill-runner[grpc])", PACKAGES["grpcio-reflection"],
        ),
    ),
    "android": (
        _requirement(
            "defusedxml", "package", True,
            "Hardened XML parsing for AAB/manifest data; profiles.mobile imports it at module load, "
            "so Android analysis cannot start without it", PACKAGES["defusedxml"],
        ),
        _requirement(
            "jadx", "tool", False,
            "Wired S1 decompilation route: profiles.mobile calls decompile.jadx when RE_RUN_JADX "
            "points to a jadx launcher or distribution directory (java classpath mode); skipped "
            "when unset", TOOLS["jadx"],
        ),
        _requirement(
            "apktool", "tool", False,
            "Wired S1 resource/manifest decode route: profiles.mobile calls decompile.apktool "
            "(java -jar) when RE_RUN_APKTOOL points to the apktool jar; skipped when unset",
            TOOLS["apktool"],
        ),
        _requirement(
            "adb", "tool", False,
            "Suggested live-device route; not wired into the android profile (the device profile "
            "owns live collection) (not-wired-yet)", TOOLS["adb"],
        ),
    ),
    "apple": (
        _requirement(
            "lief", "package", True,
            "Mach-O parsing for app-bundle executables via profiles.binary.native", PACKAGES["lief"],
        ),
        _requirement(
            "capstone", "package", True,
            "Disassembly engine imported unconditionally by profiles.binary.native for every parsed "
            "executable", PACKAGES["capstone"],
        ),
        _requirement(
            "defusedxml", "package", True,
            "Hardened XML parsing for entitlements/AAB data; profiles.mobile imports it at module "
            "load", PACKAGES["defusedxml"],
        ),
        _requirement(
            "ideviceinfo", "tool", False,
            "Live iOS identity needs an explicit ios:// locator in the device profile; static apple "
            "analysis never contacts devices", TOOLS["ideviceinfo"], True,
        ),
    ),
    "binary": (
        _requirement(
            "lief", "package", True,
            "Native PE/ELF/Mach-O header, section, import and symbol parsing "
            "(profiles.binary.native raises CapabilityMissing without it)", PACKAGES["lief"],
        ),
        _requirement(
            "capstone", "package", True,
            "Bounded entry-point disassembly for supported architectures "
            "(profiles.binary._disassemble)", PACKAGES["capstone"],
        ),
        _requirement(
            "r2", "tool", False,
            "Optional static function/reference provider resolved from RE_RUN_R2 or PATH under the "
            "providers.radare2 rules; skipped when absent", TOOLS["r2"],
        ),
        _requirement(
            "upx", "tool", False,
            "Wired static unpack route for UPX-indicated PE samples: profiles.binary calls "
            "unpackers.upx_unpack when RE_RUN_UPX is configured; skipped when unset. Static file "
            "rewriting only - samples are never executed", TOOLS["upx"],
        ),
        _requirement(
            "dnfile", "package", False,
            ".NET metadata for PE files declaring a CLR runtime directory; missing raises "
            "CapabilityMissing", PACKAGES["dnfile"],
        ),
    ),
    "firmware": (
        _requirement(
            "7z", "tool", False,
            "Wired isolated filesystem extraction for offset-0 squashfs/cpio images via "
            "extractors.sevenzip_extract when RE_RUN_7Z is configured; the extracted tree replaces "
            "the raw image as the scan input. UBI/TRX still fall back to a raw signature scan "
            "(7-Zip 25.01 provides no handler)", TOOLS["7z"],
        ),
        _requirement(
            "unsquashfs", "tool", False,
            "Alternative standalone squashfs tool; not wired into the current path (the 7z route "
            "above is the wired extractor) (not-wired-yet)",
            TOOLS["unsquashfs"],
        ),
    ),
    "source": (
        _requirement(
            "bandit", "tool", False,
            "Wired rule engine for source trees: profiles.source_firmware calls scanner.bandit_scan "
            "when bandit is on PATH (or passed explicitly); results are normalized to candidates "
            "alongside the in-process AST paths", ["python-static-rules"],
        ),
        _requirement(
            "semgrep", "tool", False,
            "Alternative cross-language rule engine; not wired into the current path "
            "(not-wired-yet)", TOOLS["semgrep"],
        ),
    ),
    "container": (
        _requirement(
            "docker", "tool", False,
            "OCI digests/config/layers are parsed with stdlib zip/tar; no docker daemon or sandbox "
            "is used (not-wired-yet)", TOOLS["docker"],
        ),
    ),
    "traffic": (
        _requirement(
            "scapy", "package", False,
            "Wired deep reassembly layer: profiles.traffic uses scapy for TCP stream reassembly and "
            "HTTP extraction when the package is importable (re-skill-runner[traffic-deep]); the "
            "stdlib header/flow index always runs. TLS payloads are never decrypted (no keys)",
            ["tcp-reassembly", "http-extraction"],
        ),
        _requirement(
            "tshark", "tool", False,
            "Alternative deep dissection engine; not wired into the current path (not-wired-yet)",
            TOOLS["tshark"],
        ),
    ),
    "device": (
        _requirement(
            "adb", "tool", False,
            "Live Android identity via 'adb -s <serial> shell getprop'; requires a connected, "
            "authorized device that doctor does not verify", TOOLS["adb"], True,
        ),
        _requirement(
            "ideviceinfo", "tool", False,
            "Live iOS identity via 'ideviceinfo -u <udid>'; requires a connected, trusted device "
            "that doctor does not verify", TOOLS["ideviceinfo"], True,
        ),
        _requirement(
            "pyserial", "package", False,
            "Passive two-second serial:// read with DTR/RTS deasserted; requires a physical port "
            "that doctor does not verify", PACKAGES["pyserial"], True,
        ),
    ),
    "ai": (),
    "contract": (
        _requirement(
            "solc", "tool", False,
            "Wired Solidity compilation: profiles.special calls compilers.solc_compile when "
            "RE_RUN_SOLC points to the native solc executable; ABI/bytecode artifacts are recorded "
            "as evidence and unprotected state-mutating functions become lexical candidates. "
            "skipped when unset", TOOLS["solc"],
        ),
        _requirement(
            "forge", "tool", False,
            "Foundry fork/test harness requires a local node or fixture project; not wired into the "
            "current analysis path (requires-environment) (not-wired-yet)", TOOLS["forge"], True,
        ),
    ),
}

_PROFILE_NOTES = {
    "ai": [
        "Pickle/joblib/PyTorch objects and ONNX models are intentionally blocked (never "
        "deserialized); intake records format, size and hash only.",
        "Behavioral probing (profiles.special.behavior_probe) runs a fixed redistributable canary "
        "set against explicitly authorized service assets with the ai-test operation; it is a "
        "behavioral oracle, not a claim about model internals.",
    ],
}


def _version_budget() -> Budget:
    return Budget({**BUDGET_DEFAULTS, "max_wall_seconds": _PROBE_WALL_SECONDS, "tool_timeout_seconds": 5})


def _resolve_tool(name: str) -> str | None:
    variable = _ENV_PROVIDERS.get(name)
    configured = os.environ.get(variable) if variable else None
    return configured or shutil.which(name)


def _first_line(text: str | None) -> str | None:
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:_VERSION_LINE_LIMIT]
    return None


def _execute_version(name: str, executable: str, budget: Budget) -> tuple[bool, str | None, str]:
    """Run a tool's version command; never raises. Returns (ok, version line, reason)."""
    arguments = _VERSION_COMMANDS.get(name)
    if not arguments:
        return False, None, "Found on PATH; version execution is not automated for this tool"
    remaining = _PROBE_WALL_SECONDS - (time.monotonic() - budget.started)
    if remaining < 0.5:
        return False, None, "Found on PATH; version execution skipped (probe time budget)"
    try:
        result = run_command([str(executable), *arguments], Path.cwd(), budget, timeout=max(1, min(5, int(remaining))))
    except Exception as exc:  # doctor must never fail because a tool is broken
        return False, None, f"Found on PATH; version execution failed: {type(exc).__name__}"
    if result.status == "succeeded" and result.exit_code == 0:
        line = _first_line(result.stdout) or _first_line(result.stderr)
        if line:
            return True, line, "Found on PATH; version verified by direct execution"
        return False, None, "Found on PATH; version execution produced no readable output"
    detail = "timed out" if result.timed_out else f"status {result.status}"
    return False, None, f"Found on PATH; version execution did not succeed ({detail})"


def _tool_state(name: str, budget: Budget) -> dict:
    executable = _resolve_tool(name)
    if not executable:
        return {"available": False, "status": "missing", "version": None, "reason": "Executable not on PATH"}
    if Path(executable).suffix.lower() in WRAPPER_SUFFIXES:
        return {
            "available": False, "status": "missing", "version": None,
            "reason": "Resolved to a .bat/.cmd/.ps1/.sh wrapper; providers.radare2 rules require a native executable",
        }
    ok, version, reason = _execute_version(name, executable, budget)
    return {"available": True, "status": "runnable" if ok else "present", "version": version, "reason": reason}


def _package_state(name: str) -> dict:
    try:
        return {"available": True, "status": "runnable", "version": importlib.metadata.version(name), "reason": "Installed"}
    except importlib.metadata.PackageNotFoundError:
        return {"available": False, "status": "missing", "version": None, "reason": "Python package is not installed"}
    except Exception as exc:  # metadata lookup must never break the doctor
        return {
            "available": False, "status": "missing", "version": None,
            "reason": f"Version lookup failed: {type(exc).__name__}",
        }


def _probe_global() -> dict:
    budget = _version_budget()
    values = []
    for name, operations in PACKAGES.items():
        state = _package_state(name)
        values.append(asdict(Capability(
            name, state["available"], state["version"], operations,
            None if state["available"] else state["reason"],
        )))
    for name, operations in TOOLS.items():
        state = _tool_state(name, budget)
        values.append(asdict(Capability(name, state["available"], state["version"], operations, state["reason"])))
    return {
        "os": platform.system(), "python": platform.python_version(), "profile": None,
        "builtin_profiles": list(KINDS), "capabilities": values,
        "isolation": "Windows job (memory + process tree)" if os.name == "nt" else "Linux process group + memory/CPU/file rlimits" if platform.system() == "Linux" else "POSIX process group + CPU/file rlimits; hard memory limit unavailable",
        "note": "Resource isolation is not a security sandbox; dynamic execution of samples is disabled.",
    }


def _probe_profile(profile: str) -> dict:
    specs = PROFILE_REQUIREMENTS[profile]
    budget = _version_budget()
    entries = []
    for spec in specs:
        entry = {
            "name": spec["name"], "kind": spec["kind"], "required": spec["required"],
            "purpose": spec["purpose"], "operations": list(spec["operations"]),
        }
        state = _package_state(spec["name"]) if spec["kind"] == "package" else _tool_state(spec["name"], budget)
        entry.update(state)
        if spec["requires_environment"]:
            # Tool/package works on this host, but a real device/session is not verified here.
            entry["requires-environment"] = True
        entries.append(entry)
    required = [spec["name"] for spec in specs if spec["required"]]
    required_missing = [entry["name"] for entry in entries if entry["required"] and not entry["available"]]
    return {
        "os": platform.system(), "python": platform.python_version(), "profile": profile,
        "builtin_profiles": list(KINDS), "capabilities": entries,
        "isolation": "Windows job (memory + process tree)" if os.name == "nt" else "Linux process group + memory/CPU/file rlimits" if platform.system() == "Linux" else "POSIX process group + CPU/file rlimits; hard memory limit unavailable",
        "note": "Resource isolation is not a security sandbox; dynamic execution of samples is disabled.",
        "profile_requirements": {
            "required": required,
            "optional": [spec["name"] for spec in specs if not spec["required"]],
            "required_missing": required_missing,
            "summary": {"required_ready": not required_missing},
            "notes": list(_PROFILE_NOTES.get(profile, [])),
        },
    }


def probe(profile: str | None = None) -> dict:
    if profile is None:
        return _probe_global()
    if profile not in PROFILE_REQUIREMENTS:
        raise ValueError(f"Unknown profile {profile!r}; expected one of: {', '.join(KINDS)}")
    return _probe_profile(profile)
