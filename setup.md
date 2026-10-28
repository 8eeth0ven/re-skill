# Setup Guide — Prepare the Tools for Your Analysis

## Unified runner

The repository provides `pyproject.toml` and `uv.lock`; the runner requires
Python 3.11+. Install and test only as requested for the current task, respecting
any explicit user limits on execution, installation, or device access.

```bash
uv sync --locked --all-extras --group dev
uv run --no-sync re-run doctor --profile binary
uv run --no-sync re-run analyze --manifest examples/assets.local.json --output re-runs
```

Without uv, `python -m pip install -e '.[devices,grpc]'` uses version ranges
rather than the exact uv lock. External JADX, Ghidra, IDA, Frida, and extractors
are installed separately; available adapters and supported depth vary by
profile. `RE_RUN_R2` accepts a trusted native executable. See [runner guide](docs/runner.zh-CN.md),
[status](docs/delivery-status.zh-CN.md) and [handoff](docs/agent-completion-prompt.zh-CN.md).

> Run from the repository root. Install the tools needed for the selected task,
> using the actual host's permissions and package availability. These are setup
> instructions for a user or agent, not a bundled installer. Record installation
> results and missing capabilities; existing macOS observations do not establish
> readiness on Windows or Linux.

## 0. Check the Current Environment

Run `python3 pipeline/env_check.py` on macOS/Linux or `python pipeline/env_check.py`
on Windows before choosing installations. Return codes 1 and 2 identify missing
capabilities; they do not mean the script failed to produce a diagnostic.

Optional inventory: `python3 pipeline/env_scan.py` records portable tool/version
probes and serial-port descriptors in `环境快照/snapshot-<timestamp>.md` and
`latest.md`; ports are not opened, and this inventory does not collect live
phone identity, root status, application lists, or firmware details. Collect
those observations through the runner's device profile with an exact identity
and `device-read` scope, or the explicit [real-device procedure](device-testing.md).
These version probes execute tools; defer them when the user defers execution/testing.

## Execution Discipline (formerly Section 0)

- Work section by section; for each item detect first, install only if missing (skip if present); single-command timeout 5 minutes; log the whole run to `setup-report-<date>.md` (skill root)
- Platform detection: use `python3 -c "import platform; print(platform.system())"` (or `python` on Windows); a failed `uname` is not evidence of Windows. On Windows prefer PowerShell (winget), fallback scoop/choco
- Sandbox/permission failures: switch to user-level installs (brew/winget user), or mark "needs human" and write it into the report

## 1. Base Runtimes

| Dependency | Detection | macOS/Linux install | Windows install |
|------|------|------------------|--------------|
| python ≥3.11 | `python3 --version` (win: `python --version`) | bundled, or `brew install python` | `winget install Python.Python.3.12` |
| uv | `uv --version` | `brew install uv` / `curl -LsSf https://astral.sh/uv/install.sh \| sh` | `winget install astral-sh.uv` or `powershell -c "irm https://astral.sh/uv/install.ps1 \| iex"` |
| java ≥17 | `java -version` | `brew install openjdk` | `winget install Microsoft.OpenJDK.17` |
| node ≥18 (for MCP) | `node -v` | `brew install node` | `winget install OpenJS.NodeJS.LTS` |
| 7z | `7z \| head -1` (win: just `7z`) | `brew install sevenzip` / `apt install p7zip-full` | `winget install 7zip.7zip` (or bundled) |

## 2. Reverse Engineering Toolchain

| Tool | macOS/Linux | Windows |
|------|-------------|---------|
| jadx | `brew install jadx` | `winget install Skylot.jadx` (if absent, scoop: `scoop install jadx`) |
| apktool | `brew install apktool` | `winget install apktool` (if absent, scoop) |
| radare2 | `brew install radare2` | `winget install radare2.radare2` (if absent, scoop) |
| adb (Android dynamics) | `brew install --cask android-platform-tools` | `winget install Google.PlatformTools` |

When Windows package managers are missing, use the existing PowerShell and try in order winget → scoop (`irm get.scoop.sh \| iex`) → choco; if none work, manually download the zip from GitHub releases into `%LOCALAPPDATA%\re-tools\` and add the directory to PATH (with PowerShell `[Environment]::SetEnvironmentVariable('Path',...)`).

## 3. Python RE Environment (tools-env)

Run in the skill root (uniform relative paths, consistent across machines):

```bash
# macOS/Linux: start in the repository root; tools-env is not bundled
mkdir -p tools-env
cd tools-env
UV_CACHE_DIR=/tmp/uv-cache uv venv
UV_CACHE_DIR=/tmp/uv-cache uv pip install -p .venv/bin/python frida-tools frida unicorn capstone androguard ropper apkid apkleaks
```

```powershell
# Windows: start in the repository root
New-Item -ItemType Directory -Path tools-env -Force | Out-Null
Set-Location tools-env
$env:UV_CACHE_DIR="$env:TEMP\uv-cache"
uv venv
uv pip install -p .venv\Scripts\python.exe frida-tools frida unicorn capstone androguard ropper apkid apkleaks
```

Verify the installed tools with `.venv/bin/frida --version` (Windows:
`.venv\Scripts\frida.exe --version`) and the relevant library imports. Match
the host Frida version to the device's frida-server version. The earlier local
baseline used Frida 17.x and had a keystone/Python 3.13 compatibility issue;
check current package compatibility instead of treating that observation as
a requirement for every host.

## 4. Emulator (Optional, for Dynamic Analysis)

- **macOS**: Android Studio AVD (after `brew install --cask android-studio`, install a suitable SDK system image, then create the matching AVD). For example, `avdmanager create avd -n re_avd -k "system-images;android-35;google_apis;arm64-v8a"` requires that image to be installed first. Record the created AVD name and select it explicitly in the pipeline; `Medium_Phone_API_36.0` is a historical local example, not a portable default. An android-emulator MCP can drive the selected AVD if separately configured.
- **Windows**: `winget install Google.AndroidStudio`, create the AVD as above; or LDPlayer/Nox (mind frida compatibility; pick the frida-server arch matching the x86 image)
- frida-server push (select a test emulator serial with `adb -s <serial>`): `adb -s <serial> push frida-server-<ver>-android-<arch> /data/local/tmp/re_fs && adb -s <serial> shell "chmod 755 /data/local/tmp/re_fs"` (rooted test emulator; use a server version and architecture matching the client and image, and register the copied file/PID for cleanup; source: github.com/frida/frida/releases)

## 5. MCP (Optional, As Needed)

- IDA: if IDA is installed locally, enable the MCP plugin (start via menu/shortcut; see your IDA version's notes)
- Other MCP options: see [AI RE tools](techniques/08-ai-re/ai-re-tools.md). Verify the chosen server's current installation requirements, actual tool schemas, and OS support; cloning this skill does not register it.

## 6. Verification and Wrap-up

1. Return to the repository root and run `python3 pipeline/env_check.py` on macOS/Linux or `python pipeline/env_check.py` on Windows. The legacy `env_check.sh` is macOS-only.
2. For an APK smoke test, use a suitable open-source or owned lab sample and execute S0–S4 per [pipeline/pipeline.md](pipeline/pipeline.md). Check the required static artifacts and any requested dynamic steps, as well as the report's limitations; a report can also describe a degraded run and does not by itself prove full setup success.
3. Write the following into `setup-report-<date>.md`: platform / per-item install results (✓/✗/skipped) / venv version / leftover items needing a human / health-check output.
4. Path fixes: if stale absolute paths from the old machine linger in pipeline.md (e.g. /Users/xxx, /opt/homebrew), replace them uniformly with PATH commands (jadx/apktool as bare command names) or the actual local paths

## 7. Post-Migration Scheduled Tasks (Optional)

The daily tool radar is a machine-local scheduled task and does not migrate with the directory. To use it on a new machine: read the process in radar/README.md and rebuild the scheduled task in the host (ZCode or equivalent) as "daily 09:00, discover → catalog → local smoke test"; skip it if unwanted — the radar can also be run manually for "one round".
