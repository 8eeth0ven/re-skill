# Setup Manual (AI-executed Automatically · Cross-platform macOS/Windows/Linux)

> Goal: move this skill to any new machine and let an AI that has read this manual **complete all installation and verification automatically**, no human required. Execute section by section, follow fallback paths on failure, and output a report at the end.

## 0. First Setup Step: Full Inventory Snapshot

First run `python3 pipeline/env_scan.py`: it inventories available software / external devices (USB · serial) / phone details (model · version · abi · **root status · third-party app list** · debugging state) / firmware ports, automatically generates "companion operation" suggestions, and **saves a snapshot to `环境快照/snapshot-<时间戳>.md`** (latest.md kept in sync). Re-run it on every setup / new-session start — after installing new software or plugging in devices, run it again and diff the snapshots to see what changed.

## Execution Discipline (formerly Section 0)

- Work section by section; for each item detect first, install only if missing (skip if present); single-command timeout 5 minutes; log the whole run to `初始化报告-<日期>.md` (skill root)
- Platform detection: `uname` (darwin/linux) or Windows (if the command errors, treat as win); on Windows prefer PowerShell (winget), fallback scoop/choco
- Sandbox/permission failures: switch to user-level installs (brew/winget user), or mark "needs human" and write it into the report

## 1. Base Runtimes

| Dependency | Detection | macOS/Linux install | Windows install |
|------|------|------------------|--------------|
| python ≥3.10 | `python3 --version` (win: `python --version`) | bundled, or `brew install python` | `winget install Python.Python.3.12` |
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

When Windows package managers are missing: `winget install Microsoft.PowerShell` first? Not needed — try in order winget → scoop (`irm get.scoop.sh \| iex`) → choco; if none work, manually download the zip from GitHub releases into `%LOCALAPPDATA%\re-tools\` and add the directory to PATH (with PowerShell `[Environment]::SetEnvironmentVariable('Path',...)`).

## 3. Python RE Environment (tools-env)

Run in the skill root (uniform relative paths, consistent across machines):

```bash
# macOS/Linux
cd <本技能根目录>/tools-env
UV_CACHE_DIR=/tmp/uv-cache uv venv
UV_CACHE_DIR=/tmp/uv-cache uv pip install -p .venv/bin/python frida-tools frida unicorn capstone androguard ropper apkid apkleaks
# Windows(PowerShell)
cd <本技能根目录>\tools-env
$env:UV_CACHE_DIR="$env:TEMP\uv-cache"
uv venv; uv pip install -p .venv\Scripts\python.exe frida-tools frida unicorn capstone androguard ropper apkid apkleaks
```

Verify: `.venv/bin/frida --version` (win: `.venv\Scripts\frida.exe --version`) printing 17.x means success. Do not install keystone (incompatible with python3.13).

## 4. Emulator (Optional, for Dynamic Analysis)

- **macOS**: Android Studio AVD (after `brew install --cask android-studio`, `avdmanager create avd -n re_avd -k "system-images;android-35;google_apis;arm64-v8a"`); this skill's android-emulator MCP can drive it directly
- **Windows**: `winget install Google.AndroidStudio`, create the AVD as above; or LDPlayer/Nox (mind frida compatibility; pick the frida-server arch matching the x86 image)
- frida-server push: `adb push frida-server-<ver>-android-<arch> /data/local/tmp/fs && adb shell "chmod 755 /data/local/tmp/fs"` (rooted emulator; source: github.com/frida/frida/releases)

## 5. MCP (Optional, As Needed)

- IDA: if IDA is installed locally, enable the MCP plugin (start via menu/shortcut; see your IDA version's notes)
- One-liner setup for other MCPs: see `techniques/08-ai-re/ai-re-tools.md` §8.6 (npx/uvx form, identical cross-platform)

## 6. Verification and Wrap-up

1. Run the health check: `python3 pipeline/env_check.py` (cross-platform version, preferred; the legacy `env_check.sh` is macOS-bash-only, kept as backup)
2. Smoke test (optional but recommended): download a small open-source APK → run the S0-S4 full chain per `pipeline/pipeline.md` → a generated report means setup succeeded
3. Write the following into `初始化报告-<日期>.md`: platform / per-item install results (✓/✗/skipped) / venv version / leftover items needing a human / health-check output
4. Path fixes: if stale absolute paths from the old machine linger in pipeline.md (e.g. /Users/xxx, /opt/homebrew), replace them uniformly with PATH commands (jadx/apktool as bare command names) or the actual local paths

## 7. Post-Migration Scheduled Tasks (Optional)

The daily tool radar is a machine-local scheduled task and does not migrate with the directory. To use it on a new machine: read the process in radar/README.md and rebuild the scheduled task in the host (ZCode or equivalent) as "daily 09:00, discover → catalog → local smoke test"; skip it if unwanted — the radar can also be run manually for "one round".
