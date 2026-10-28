#!/usr/bin/env python3
"""Initialize shared APK workflow state without requiring Bash.

Usage: python pipeline/init_pipeline.py /absolute/app.apk [--output /task/run]
The JSON result names env.json/env.sh. Bash and PowerShell entry points load the
same variables; this initializer only probes aapt2 and writes task-local state.
"""
from __future__ import annotations

import argparse
import datetime
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path


RUN_TO = '''run_to() {
  local re_timeout_seconds=$1
  shift
  MSYS2_ARG_CONV_EXCL="*" MSYS_NO_PATHCONV=1 \\
  "$RE_PYTHON" "$SKILL_ROOT/pipeline/run_with_timeout.py" \\
    --deadline "$RE_PIPELINE_DEADLINE" --reserve "${RE_REPORT_RESERVE_SECONDS:-300}" \\
    "$re_timeout_seconds" "$@"
}
'''


def sdk_directory(environ=None, *, platform_name=None, home=None):
    """Honor explicit SDK configuration, then the host's standard user location."""
    environ = os.environ if environ is None else environ
    platform_name = sys.platform if platform_name is None else platform_name
    user_home = Path.home() if home is None else Path(home)
    configured = environ.get("ANDROID_SDK_ROOT") or environ.get("ANDROID_HOME")
    if configured:
        return Path(configured).expanduser()
    if platform_name == "darwin":
        return user_home / "Library" / "Android" / "sdk"
    if platform_name == "win32":
        local = Path(environ.get("LOCALAPPDATA") or user_home / "AppData" / "Local")
        return local / "Android" / "Sdk"
    return user_home / "Android" / "Sdk"


def latest_build_tool(sdk, name):
    """Select the highest installed numeric SDK version, not a lexical glob order."""
    base = Path(sdk) / "build-tools"
    candidates = [p for p in base.glob(f"*/{name}") if p.is_file()]
    return max(candidates, key=lambda p: (tuple(int(n) for n in re.findall(r"\d+", p.relative_to(base).parts[0])), str(p)), default=None)


def initialize(apk, output=None, *, skill_root=None, environ=None, platform_name=None):
    environ = os.environ if environ is None else environ
    platform_name = sys.platform if platform_name is None else platform_name
    is_windows = platform_name == "win32"
    apk = Path(apk).expanduser().resolve()
    if not apk.is_file():
        raise ValueError(f"Missing APK: {apk}")
    root = Path(skill_root).resolve() if skill_root else Path(__file__).resolve().parents[1]
    sdk = sdk_directory(environ, platform_name=platform_name).resolve()
    aapt = latest_build_tool(sdk, "aapt2.exe" if is_windows else "aapt2")
    aapt = aapt or shutil.which("aapt2")
    aapt = str(Path(aapt).resolve()) if aapt else "aapt2"
    package = None
    try:
        result = subprocess.run([aapt, "dump", "badging", str(apk)], capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=30)
        match = re.search(r"^package: name='([^']+)'", result.stdout, re.M)
        if match:
            package = match.group(1)
    except (OSError, subprocess.TimeoutExpired):
        pass
    package = re.sub(r"[^A-Za-z0-9._-]", "_", package or apk.stem) or "re_apk"
    now = datetime.datetime.now()
    destination = Path(output or environ.get("RE_PIPELINE_OUT") or
                       apk.parent / "输出" / f"{package}-{now:%Y%m%d}").expanduser().resolve()
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        base = destination.with_name(f"{destination.name}-{now:%H%M%S}-{os.getpid()}")
        destination = base
        sequence = 1
        while destination.exists():
            destination = base.with_name(f"{base.name}-{sequence}")
            sequence += 1
    for name in ("00-环境", "01-静态", "02-动态"):
        (destination / name).mkdir(parents=True, exist_ok=True)
    venv = root / "tools-env" / ".venv"
    venv_python = venv / ("Scripts/python.exe" if is_windows else "bin/python")
    if not is_windows and not venv_python.is_file() and (venv / "bin/python3").is_file():
        venv_python = venv / "bin/python3"
    adb = shutil.which("adb")
    adb = str(Path(adb).resolve()) if adb else str(sdk / "platform-tools" / ("adb.exe" if is_windows else "adb"))
    state = {
        "APK": str(apk), "SKILL_ROOT": str(root), "RE_PYTHON": sys.executable,
        "AAPT2": aapt, "SDK_DIR": str(sdk), "ADB_BIN": adb,
        "VENV_BIN": str(venv_python.parent), "VENV_PY": str(venv_python),
        "PKG": package, "OUT": str(destination), "RE_AVD": environ.get("RE_AVD", ""),
        "RE_DEVICE_SERIAL": environ.get("RE_DEVICE_SERIAL", ""),
        "RE_PIPELINE_DEADLINE": format(time.monotonic() + 3600, ".17g"),
        "RE_REPORT_RESERVE_SECONDS": 300,
    }
    env_json, env_sh = destination / "env.json", destination / "env.sh"
    env_json.write_text(json.dumps({"version": 1, "variables": state}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # Forward-slash paths work in Git Bash as well as native POSIX shells. JSON
    # retains native Windows spelling for PowerShell and subprocess argument lists.
    shell_state = {key: (value.replace("\\", "/") if is_windows and key in {
        "APK", "SKILL_ROOT", "RE_PYTHON", "AAPT2", "SDK_DIR", "ADB_BIN", "VENV_BIN", "VENV_PY", "OUT"
    } else value) for key, value in state.items()}
    env_sh.write_text("".join(f"{key}={shlex.quote(str(value))}\n" for key, value in shell_state.items()) + RUN_TO, encoding="utf-8", newline="\n")
    (destination / "00-环境" / "run.log").write_text(
        f"[{now:%Y-%m-%d %H:%M:%S}] pipeline start APK={apk} OUT={destination}\n", encoding="utf-8")
    return {"version": 1, "variables": state, "env_json": str(env_json), "env_sh": str(env_sh)}


STATE_KEYS = {
    "APK", "SKILL_ROOT", "RE_PYTHON", "AAPT2", "SDK_DIR", "ADB_BIN", "VENV_BIN", "VENV_PY",
    "PKG", "OUT", "RE_AVD", "RE_DEVICE_SERIAL", "RE_PIPELINE_DEADLINE", "RE_REPORT_RESERVE_SECONDS",
}
PATH_KEYS = {"APK", "SKILL_ROOT", "RE_PYTHON", "SDK_DIR", "ADB_BIN", "VENV_BIN", "VENV_PY", "OUT"}


def load_state(path):
    """Read trusted task state without running a probe, creating files, or resetting time."""
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        raise ValueError("Pipeline state must be a regular file")
    if path.stat().st_size > 1 << 20:
        raise ValueError("Pipeline state exceeds 1 MiB")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate pipeline state field: {key}")
            result[key] = value
        return result

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    if not isinstance(value, dict) or set(value) != {"version", "variables"} or type(value["version"]) is not int or value["version"] != 1:
        raise ValueError("Expected pipeline state version 1 and variables only")
    variables = value["variables"]
    if not isinstance(variables, dict) or set(variables) != STATE_KEYS:
        raise ValueError("Unknown or missing pipeline state variable; only workflow variables may be loaded")
    for key, item in variables.items():
        if key == "RE_REPORT_RESERVE_SECONDS":
            if type(item) is not int or not 0 <= item <= 3600:
                raise ValueError("Invalid report reserve in pipeline state")
            continue
        if not isinstance(item, str) or len(item) > 32768 or any(char in item for char in "\x00\r\n"):
            raise ValueError(f"Invalid pipeline state value: {key}")
        if key in PATH_KEYS and not Path(item).is_absolute():
            raise ValueError(f"Pipeline state requires an absolute path: {key}")
    if not Path(variables["AAPT2"]).is_absolute() and variables["AAPT2"] not in {"aapt2", "aapt2.exe"}:
        raise ValueError("Invalid aapt2 path in pipeline state")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,256}", variables["PKG"]):
        raise ValueError("Invalid package identifier in pipeline state")
    try:
        deadline = float(variables["RE_PIPELINE_DEADLINE"])
    except ValueError as exc:
        raise ValueError("Invalid deadline in pipeline state") from exc
    if not math.isfinite(deadline) or deadline <= 0:
        raise ValueError("Pipeline deadline must be finite and positive")
    return {"version": 1, "variables": variables, "env_json": str(path),
            "env_sh": str(Path(variables["OUT"]) / "env.sh")}


def main(argv=None):
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path, nargs="?")
    parser.add_argument("--state-file", type=Path, help="Load existing env.json without reinitializing")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if bool(args.apk) == bool(args.state_file) or (args.state_file and args.output):
        parser.error("Supply an APK (optionally --output) or --state-file, exclusively")
    try:
        result = load_state(args.state_file) if args.state_file else initialize(args.apk, args.output)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
