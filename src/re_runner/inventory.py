"""Portable tool inventory; live devices need an explicit separate profile/scope."""
import platform
import shutil
from datetime import datetime, timezone
from pathlib import Path

from .capabilities import probe
from .contracts import BUDGET_DEFAULTS
from .execution import run_command
from .safety import Budget, atomic_write, markdown_text


def snapshot(root: Path) -> tuple[str, dict]:
    versions = {}
    commands = {
        "java": ["-version"], "node": ["--version"], "uv": ["--version"],
        "git": ["--version"], "adb": ["version"], "jadx": ["--version"],
        "apktool": ["--version"], "r2": ["-v"], "tshark": ["--version"],
    }
    budget = Budget({**BUDGET_DEFAULTS, "max_wall_seconds": 60, "tool_timeout_seconds": 5})
    for name, arguments in commands.items():
        binary = shutil.which(name)
        if binary:
            result = run_command([binary, *arguments], root, budget, timeout=5)
            lines = (result.stdout + result.stderr).splitlines()
            versions[name] = {"status": result.status, "version": lines[0][:160] if lines else "No version output"}
        else:
            versions[name] = {"status": "missing", "version": None}
    serial_ports = []
    try:
        from serial.tools import list_ports
        serial_ports = [{"port": item.device, "description": item.description} for item in list_ports.comports()]
    except ImportError:
        pass
    value = {"host": platform.system(), "python": platform.python_version(), "versions": versions, "serial_ports": serial_ports, "capabilities": probe()}
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    lines = [f"# Environment inventory {timestamp} UTC", "", f"Host: {platform.system()} · Python {platform.python_version()}", "", "| Tool | Status | Version |", "| --- | --- | --- | --- |"]
    for name, result in versions.items():
        lines.append(f"| {name} | {result['status']} | {markdown_text(result['version'])} |")
    lines += ["", "Serial port descriptors (no ports opened):", ""]
    lines.extend("- " + markdown_text(item) for item in serial_ports)
    lines += ["", "Live Android/iOS collection uses re-run analyze with device-read scope and an exact device identity.", ""]
    output = root / "环境快照"
    atomic_write(output / f"snapshot-{timestamp}.md", "\n".join(lines).encode("utf-8"))
    atomic_write(output / "latest.md", "\n".join(lines).encode("utf-8"))
    return "\n".join(lines), value

