# Building the Windows Vulnerability-Hunting Toolchain (An AI Auto-Execution Manual)

> Architecture: **target machine = a Windows 10/11 VM** (VMware Fusion / Parallels / Hyper-V all work; VMware recommended: serial/network debugging configuration is smoothest); **the local macOS machine only does orchestration and static analysis** (Ghidra/radare2/symbol downloads); everything dynamic (WinDbg kernel debugging, x64dbg, fuzzing) runs inside the VM.
> After reading this manual, the AI should **automatically complete all installation and verification on the target machine** without human intervention; on failure follow the degradation paths, and finally output the checklist table per §7.
> Address verification date: 2026-10-16. All "versions" defer to the corresponding releases pages; what this document records are the values verified on that day.

## 0. Execution Discipline

- Work section by section; in each section **detect first, then install** (skip if already installed); 5-minute timeout per single command; log everything to `工具链报告-<日期>.md` (toolchain-report-<date>.md)
- On the target machine always use **administrator PowerShell** (`Win+X → Terminal (Admin)`); package-manager order: winget → scoop (`irm get.scoop.sh | iex`) → GitHub releases manual zip extracted to `C:\tools\` and added to PATH
- Steps that need reboots (§1.2 bcdedit, after VS Build Tools installs) are **batched into one final reboot**; after rebooting, continue with the §7 self-check
- VM snapshot discipline: before installing any kernel-related component (driver debugging, test-signing mode), take a VMware snapshot first — rollback cost is zero

## 1. Base Environment (PowerShell Automation, winget First)

### 1.1 winget Baseline

```powershell
winget --version          # Win10 21H1+ / Win11 ships it; if absent install App Installer:
# winget comes from the Microsoft Store "App Installer", or https://github.com/microsoft/winget-cli/releases
winget source update
winget install --id Microsoft.WinDbg -e --accept-source-agreements --accept-package-agreements
```

- WinDbg Preview (the new WinDbg, Store edition): package id `Microsoft.WinDbg` (verified present that day, latest manifest 1.2610.1001.0; what winget installs is the Store WinDbg, including TTD/time-travel debugging)
- The old `windbg.exe` (classic) ships with the Windows SDK debuggers directory; this manual does not depend on it and can skip it

### 1.2 Dual-Machine Kernel-Debugging Configuration (Target in the VM + a Second Windows Machine as Host)

Kernel debugging requires a "host-side WinDbg". macOS cannot run WinDbg, so:

- **Plan A (recommended)**: **two VMs** in VMware — `win-target` (the debuggee) + `win-host` (the debugger), placed on the same host-only/vmnet network; `win-host` also installs `Microsoft.WinDbg`
- **Plan B (lightweight alternative)**: single-machine local kernel mode `windbgx -kl` (can view kernel memory/driver lists, cannot set breakpoints); suitable for a quick look at pools/objects, not for hunting driver bugs
- **Plan C**: a VMware serial pipe wired straight to a host process; use only when network debugging doesn't work (see the serial configuration below)

Target machine (`win-target`, administrator CMD/PS) — **network kernel debugging (recommended, fast)**:

```bat
bcdedit /debug on
:: hostip = win-host's IP; the key may be omitted to let the system generate one, then check with bcdedit /dbgsettings
bcdedit /dbgsettings net hostip:192.168.x.x port:50000 key:1.2.3.4.5.6.7.8.9.0.1.2.3.4.5
bcdedit /enum              :: note the auto-generated key (if not specified above)
shutdown /r /t 0           :: ← a reboot is required for this to take effect
```

Host side (`win-host`) connection syntax:

```powershell
# GUI: File → Attach to kernel → NET → fill in port=50000 and the target's key
# Command line:
windbgx -k net:port=50000,key=1.2.3.4.5.6.7.8.9.0.1.2.3.4.5 -y srv*C:\Symbols*https://msdl.microsoft.com/download/symbols -loga c:\kd.log
```

VMware serial plan (Plan C): VM Settings → Serial Port → use named pipe `\\.\pipe\com_1`, "this end is the server / the other end is an application"; target `bcdedit /dbgsettings serial debugport:1 baudrate:115200`; host side `windbgx -k com:pipe,port=\\.\pipe\com_1,baud=115200,pipe,reconnect` (the pipe is created on the VM/system running WinDbg).

### 1.3 Symbol Server (System-Wide, Configure Once)

```powershell
New-Item -ItemType Directory -Force -Path C:\Symbols | Out-Null
[Environment]::SetEnvironmentVariable('_NT_SYMBOL_PATH',
  'srv*C:\Symbols*https://msdl.microsoft.com/download/symbols', 'Machine')
# Takes effect in new terminals; WinDbg/x64dbg/ProcMon all honor this variable
# After the first kernel connection, run .reload /f nt in WinDbg to pre-download the full ntoskrnl symbols to C:\Symbols
```

Verify: `[Environment]::GetEnvironmentVariable('_NT_SYMBOL_PATH','Machine')` echoing the right value means success.

### 1.4 Python / git / 7zip / Common Runtimes

| Dependency | Detection | Install | Notes |
|---|---|---|---|
| Python 3.12+ | `python --version` | `winget install Python.Python.3.12` | installs the py launcher; tick Add to PATH |
| git | `git --version` | `winget install Git.Git` | for pulling winafl sources |
| 7zip | `7z \| head -1` | `winget install 7zip.7zip` | for unpacking Ghidra/DynamoRIO zips |
| JDK 25 (Ghidra 12 prerequisite) | `java -version` | `winget install EclipseAdoptium.Temurin.25.JDK` (verify the id with `winget search temurin`) | Ghidra 12.x officially requires **JDK 25 64-bit** |
| VS Build Tools (winafl prerequisite) | `cl 2>&1` | `winget install Microsoft.VisualStudio.2022.BuildTools --override "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"` | may need a reboot after install; can also be deferred to §3.1 |
| CMake | `cmake --version` | `winget install Kitware.CMake` | for building winafl |

## 2. Static Analysis

### 2.1 Ghidra (Both the Target Machine and macOS; brew cask does **not** have ghidra — verified hands-on)

- Download: https://github.com/NationalSecurityAgency/ghidra/releases —— latest that day **Ghidra 12.1.4** (zip named like `ghidra_12.1.4_PUBLIC_20260921.zip`; defer to the releases page Assets)
- Prerequisite: **JDK 25 64-bit** (installed in §1.4; Ghidra's official zip has not bundled a JDK since 11.0)
- Target-machine install (automated PowerShell):

```powershell
$url = (Invoke-RestMethod https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest).assets.browser_download_url
Invoke-WebRequest $url -OutFile "$env:TEMP\ghidra.zip"
7z x "$env:TEMP\ghidra.zip" -oC:\tools | Out-Null
Rename-Item (Get-ChildItem C:\tools -Directory -Filter 'ghidra_*')[0].FullName C:\tools\ghidra
# 验证: C:\tools\ghidra\ghidraRun.bat
```

- macOS side likewise, by hand: download the same zip → extract to `~/tools/ghidra/` → `~/tools/ghidra/ghidraRun` (macOS needs JDK 25: `brew install --cask temurin@25`, verify the id with `brew search temurin`; do **not** `brew install --cask ghidra` — Homebrew has no such cask; verified 2026-10-16: `No Cask with this name exists`)

### 2.2 Ghidra Headless Usage (the Main Entry for Automated Reversing)

```bash
# macOS / Windows syntax identical (on Windows replace $Ghidra with C:\tools\ghidra, and / with \)
$Ghidra/support/analyzeHeadless /tmp/ghidra-proj WinProj \
  -import C:\path\target.sys \
  -processor x86:LE:64:default \
  -postScript DecompileAllFunctions.java \
  -scriptPath ~/scripts
# 常用: -deleteProject 一次性跑; -process 批量; 内置脚本在 $Ghidra/Ghidra/Features/Decompiler/ghidra_scripts/
```

Typical AI-orchestrated flow: headless-import the driver/kernel module → `DecompilerParameterId` → run a custom postScript to batch-dump pseudo C → send it back to the macOS side for analysis.

### 2.3 IDA (Optional)

- Free IDA Free 9.1: https://hex-rays.com/ida-free (latest verified that day is 9.1; includes x86/x64 decompilation, commercial use prohibited; no SDK/limited IDAPython support). FLARE VM has preinstalled IDA Free 9.1 since 2025-06
- With an existing IDA Pro license: after installing, install the MCP plugin (see `../../../radar/MCP测试报告.md` — the local IDA MCP needs its service started manually once inside IDA); also usable inside the VM
- No license, no need: Ghidra + radare2 cover 90% of static needs

### 2.4 radare2

```powershell
winget install radare2.radare2     # 或 scoop install radare2; 或 github.com/radareorg/radare2/releases 下 zip
r2 -v                              # 验证
# macOS: brew install radare2
```

## 3. Fuzzing Environment

### 3.1 WinAFL (the Coverage-Guided Main Force for User Mode)

Repository: https://github.com/googleprojectzero/winafl ; depends on **DynamoRIO** (the instrumentation backend): https://github.com/DynamoRIO/dynamorio/releases (rolling cronbuild, that day 11.91.20735, files like `DynamoRIO-Windows-11.91.x.zip`, **defer to the releases page**; download both the Windows x64 and x86 zips and extract one each).

Build (VS developer command line; needs the §1.4 Build Tools + CMake; the official readme uses the VS2019 generator as the example — the VS2022 generator `"Visual Studio 17 2022"` works the same):

```bat
git clone https://github.com/googleprojectzero/winafl C:\tools\winafl
cd C:\tools\winafl
:: 32 位（32 位目标必需; 64 位换 build64 + -A x64 + bin64）
mkdir build32 && cd build32
cmake -G "Visual Studio 16 2019" -A Win32 .. -DDynamoRIO_DIR=C:\tools\DynamoRIO\cmake
cmake --build . --config Release
:: 可加速项: -DTINYINST=1（TinyInst 后端）; -DINTELPT=1（Intel PT 模式，先 git submodule update --init --recursive）
```

Run the official example to success (the source tree ships the test target `test.exe`, exporting the called function `fuzz`, two input arguments):

```bat
cd C:\tools\winafl\build32\bin\Release
mkdir in && echo hello > in\test.txt
afl-fuzz.exe -i in -o out -t 20000 -D C:\tools\DynamoRIO\bin32 ^
  -- -coverage_module test.exe -target_module test.exe -target_method fuzz -nargs 2 -fuzz_iterations 1000 ^
  -- test.exe @@
:: 10 分钟内 coverage path 数在涨、无 DLL 注入报错 = 跑通
```

Essentials: **the target's bitness must match the winafl.dll bitness** (64-bit programs use build64 + bin64); corpus minimization `winafl-cmin.py -D C:\tools\DynamoRIO\bin32 -t 100000 -i in -o minset -covtype edge -coverage_module m.dll -target_module test.exe -target_method fuzz -nargs 2 -- test.exe @@`; for DLL targets (e.g., image-decoding libraries, LMDB-class embedded libraries) use `-target_module <dll> -target_method <exported function>`, first writing a host exe that loads the DLL and hooks the method in.

### 3.2 kAFL (Intel PT Kernel Snapshot Fuzzing — High Bar; Decide the Investment After Reading the Notes)

- Repository: https://github.com/IntelLabs/kAFL (**archived and unmaintained as of 2026**; Phoronix reported Intel ended its investment; pure research)
- The bar (all must hold to play): a **bare-metal Linux host** (Ubuntu 20.04+/Debian, needs a patched kernel with reboots) + **Intel CPU Skylake or later** (needs Intel PT + PML + VT-x; AMD won't do) + QEMU/KVM + ~2GB per vCPU. **Neither macOS nor Windows hosts qualify**; playing requires a dedicated bare-metal Linux box or IceLane+ nested virtualization (not guaranteed)
- "rgpd", a kAFL-derived name, has no verifiable repository findable online as of 2026-10 — **do not deploy per old write-ups**. Active replacement ideas: 0dayResearchLab/msFuzz (Intel PT coverage-guided driver fuzzing), google/syzkaller (officially supports Windows targets' syscall/driver surface: https://github.com/google/syzkaller )
- Conclusion: routine Windows kernel bug-hunting goes through §3.3 IOCTL fuzzing + statically auditing IOCTL handlers; invest in kAFL only when specializing in kernel surfaces with qualifying hardware

### 3.3 IOCTL Fuzzing (the Main Force for Kernel-Driver Surfaces, Active Open-Source Choices)

- **koutto/ioctlbf**: https://github.com/koutto/ioctlbf —— an active small tool; scans a driver's legitimate IOCTL codes (`-d` device-name probing of the IOCTL range) then fuzzes them one by one; suited to quickly sweeping third-party drivers; the old version built on the antinucleus idea; compiling needs VS
- The classic **ioctlfuzzer** (Google Code archived, reference for ideas only): intercepts DeviceIoControl, records legitimate IRPs, then replays with mutations
- Microsoft's official **IoSpy/IoAttack** (ships with the WDK; requires test signing): https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/iospy-and-ioattack
- The custom idea (the AI can write it automatically): static (Ghidra headless finding the `METHOD_NEITHER/INLINE` branches in the `IRP_MJ_DEVICE_CONTROL` handler + CTL_CODE macro restoration) → a small user-mode C harness sending mutated buffers via `DeviceIoControl`, with a kernel debugger watching for crashes; high hit rates against METHOD_NEITHER/unvalidated-buffer-length classes
- Auxiliary: first run `driverquery /v` + `pnputil /enum-drivers` to list the attack surface; non-Microsoft-signed drivers take priority

### 3.4 honggfuzz (Windows Support, Annotated)

- https://github.com/google/honggfuzz ; Windows support is via **Cygwin/MinGW compilation**; the last official release **v2.6** (afterwards master rolls on; defer to the repository); the Windows side lacks perf hardware coverage, so feedback is weaker than on Linux/mac
- Practical positioning: on Windows, WinAFL (§3.1) already suffices for coverage guidance; honggfuzz is only a fallback when the target is unstable under WinAFL instrumentation (heavy anti-debugging/DynamoRIO conflicts); for a VLC PE-target field case see the pentestpartners blog (a two-bug case)
- On macOS you can directly `brew install honggfuzz`, but that is for mac targets and unrelated to the VM

## 4. Dynamic and Verification Tools

| Tool | Install | Use/notes |
|---|---|---|
| x64dbg | `winget install x64dbg.x64dbg` (latest manifest that day 2026.05.27; or a zip from https://snapshot.x64dbg.com/downloads/snapshots) | The user-mode debugging mainstay. After installing, the plugin pack is a must: from x64dbg's plugin manager install **ScyllaHide** (anti-anti-debugging), **x64dbgpy** (Python scripting), **Commander**; official downloads https://x64dbg.com or github.com/x64dbg/x64dbg releases |
| Process Hacker (now System Informer) | https://github.com/winsiderss/si-builds/releases (the original processhacker is unmaintained; the mainline was renamed System Informer — install the latest release setup; winget `SystemInformer.SystemInformer`, verify the id with `winget search informer`) | Kernel-object/handle/pool observation: view driver device objects, handle tables, unsigned drivers; the "can-see" eyes that kernel bug-hunting requires |
| Sysinternals suite | `winget install Microsoft.Sysinternals` | ProcMon (file/registry/process behavior matrix), ProcExp, AccessChk (service/directory ACL triage for escalation surfaces) |
| **PoolMon** | Not in the Sysinternals package — requires the **WDK**: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk ; after installing the WDK, `tools\other\amd64\poolmon.exe`; if you can't be bothered with the WDK, use **PoolMonX** (from the github.com/wj32/processhacker ecosystem) or System Informer's pool view instead | Pool-tag-level leak location; watch for leaks during long driver-fuzz runs |
| WinDbg Preview | Installed in §1.1 | Kernel debugging + TTD (time travel, a user-mode bug-reproduction marvel; record with `windbgx -ttd`) |

## 5. setup.ps1 One-Click Script (Skeleton; Save as `C:\tools\setup.ps1` and Run as Administrator)

```powershell
# Windows 漏洞挖掘工具链一键安装 · 2026-10-16 · 需管理员 PowerShell
# 用法: powershell -ExecutionPolicy Bypass -File setup.ps1
$ErrorActionPreference = 'Continue'
$results = @()
function Step($name, $check, $install) {
    if (& $check) { $script:results += [pscustomobject]@{Item=$name;Status='已装'}; return }
    try { & $install
        if (& $check) { $script:results += [pscustomobject]@{Item=$name;Status='新装'} }
        else          { $script:results += [pscustomobject]@{Item=$name;Status='装后检测失败'} } }
    catch { $script:results += [pscustomobject]@{Item=$name;Status="失败:$($_.Exception.Message)"} }
}
# 0) 前提: winget + 管理员
if (-not (Get-Command winget -EA SilentlyContinue)) { Write-Error '无 winget: 装 App Installer(商店) 后重跑'; exit 1 }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
      ).IsInRole('Administrators')) { Write-Error '需管理员 PowerShell'; exit 1 }
# 1) 基础(全走 winget; 版本以 winget 源为准)
$pkgs = @(
  @{n='WinDbg';      id='Microsoft.WinDbg'},
  @{n='Python3.12';  id='Python.Python.3.12'},
  @{n='git';         id='Git.Git'},
  @{n='7zip';        id='7zip.7zip'},
  @{n='CMake';       id='Kitware.CMake'},
  @{n='radare2';     id='radare2.radare2'},
  @{n='x64dbg';      id='x64dbg.x64dbg'},
  @{n='Sysinternals';id='Microsoft.Sysinternals'},
  @{n='JDK25(Temurin)';id='EclipseAdoptium.Temurin.25.JDK'} )   # id 不确定时先 winget search temurin
foreach ($p in $pkgs) {
  Step $p.n { winget list --id $p.id -e | Select-String $p.id } `
       { winget install --id $p.id -e --silent --accept-source-agreements --accept-package-agreements }
}
# 2) 符号路径(系统级)
New-Item -ItemType Directory -Force -Path C:\Symbols | Out-Null
[Environment]::SetEnvironmentVariable('_NT_SYMBOL_PATH',
  'srv*C:\Symbols*https://msdl.microsoft.com/download/symbols','Machine')
$results += [pscustomobject]@{Item='_NT_SYMBOL_PATH';Status=[Environment]::GetEnvironmentVariable('_NT_SYMBOL_PATH','Machine')}
# 3) VS Build Tools(winafl 前置; 大, 装完建议重启)
Step 'VS2022BuildTools' { winget list Microsoft.VisualStudio.2022.BuildTools | Select-String BuildTools } `
  { winget install Microsoft.VisualStudio.2022.BuildTools --silent --override
    "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended" }
# 4) Ghidra zip(github releases, 版本取 latest)
$rel = Invoke-RestMethod 'https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest'
$zip = $rel.assets | Where-Object name -Match '\.zip$' | Select-Object -First 1
Step 'Ghidra' { Test-Path C:\tools\ghidra\ghidraRun.bat } {
  New-Item -ItemType Directory -Force -Path C:\tools | Out-Null
  Invoke-WebRequest $zip.browser_download_url -OutFile "$env:TEMP\ghidra.zip"
  7z x "$env:TEMP\ghidra.zip" -oC:\tools | Out-Null
  Rename-Item (Get-ChildItem C:\tools -Directory -Filter 'ghidra_*' | Select-Object -First 1).FullName C:\tools\ghidra }
# 5) DynamoRIO + winafl 源码(编译仍需手动开 VS 命令行, 见手册 §3.1)
Step 'winafl-src' { Test-Path C:\tools\winafl } { git clone https://github.com/googleprojectzero/winafl C:\tools\winafl }
$dr = (Invoke-RestMethod 'https://api.github.com/repos/DynamoRIO/dynamorio/releases/latest').assets |
      Where-Object name -Match 'Windows.*x86_64|Windows-.*64' | Select-Object -First 1
if ($dr) { Invoke-WebRequest $dr.browser_download_url -OutFile "$env:TEMP\drio.zip"
           7z x "$env:TEMP\drio.zip" -oC:\tools | Out-Null }   # 解压目录名即版本号, 记录到报告
# 6) 汇总(需要 reboot / 手动的项在这里标出)
$results += [pscustomobject]@{Item='bcdedit内核调试';Status='手动: 见 §1.2, 配完需重启'}
$results += [pscustomobject]@{Item='winafl编译';      Status='手动: VS开发者命令行 cmake, 见 §3.1'}
$results | Format-Table -AutoSize
$results | Export-Csv C:\tools\setup-report.csv -NoTypeInformation
Write-Host "`n== 装完先重启一次(BuildTools/bcdedit), 再按手册 §7 自检 =="
```

## 6. macOS Local-Side Notes

**What can be done (no VM needed)**:
- Ghidra static: manual zip install (§2.1; brew has no cask — verified hands-on), headless batch decompiling of drivers/kernel modules, producing pseudo C and call graphs
- radare2: `brew install radare2`, complementing Ghidra
- **PDB symbol downloads (replacing symchk)**: macOS has no symchk; fetch directly following the msdl URL pattern — `https://msdl.microsoft.com/download/symbols/{PDB name}/{GUID without dashes uppercase + AGE in hex}/{PDB name}`. Parse the GUID/AGE from the PE's debug directory (the CodeView RSDS record):

```python
import pefile, re, sys, urllib.request
pe = pefile.PE(sys.argv[1], fast_load=True)
pe.parse_data_directories([pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']])
for d in pe.DIRECTORY_ENTRY_DEBUG:
    data = pe.get_data(d.struct.AddressOfRawData, d.struct.SizeOfData)
    if data[:4] == b'RSDS':
        pdb = data[24:].split(b'\x00')[0].decode()
        guid = data[4:20]; age = int.from_bytes(data[20:24],'little')
        g = ''.join(f'{b:02X}' for b in guid[:4][::-1]) + ''.join(f'{b:02X}' for b in guid[4:6][::-1]) \
            + ''.join(f'{b:02X}' for b in guid[6:8][::-1]) + ''.join(f'{b:02X}' for b in guid[8:])
        url = f'https://msdl.microsoft.com/download/symbols/{pdb}/{g}{age:X}/{pdb}'
        print(url); urllib.request.urlretrieve(url, pdb)   # 装好可进 Ghidra 的 PDB 符号路径
```

- Coverage-guided fuzz source review (reading winafl/syzkaller sources), report writing, AI orchestration (everything in the VM is executed by commands dispatched from the main thread)

**What cannot be done (a Windows VM is mandatory)**: WinDbg kernel/user debugging, x64dbg, actually running WinAFL/DynamoRIO, ProcMon, PoolMon, driver loading and bluescreen reproduction. Running x86 Windows binaries on macOS (arm64) is even more impossible. Orchestration: the main thread dispatches scripts and collects crash dumps via the VMware VM's shared folder (`\\vmware-host\Shared Folders\`) or `scp`/ssh (enable OpenSSH in the VM: `Add-WindowsCapability -Online -Name OpenSSH.Server`).

## 7. Verification Checklist (Self-Check After Install, Item by Item)

| # | Check | Command/action | Pass criteria |
|---|---|---|---|
| 1 | WinDbg installed | `windbgx -version` (or WinDbg appears in the Start menu) | outputs a version ≥1.26.x |
| 2 | Symbols working | in the target's WinDbg, `!peb` or after `.reload /f nt` run `x nt!Ke*` | ntoskrnl symbols listed without `*** ERROR: Module load completed but symbols could not be loaded` |
| 3 | Kernel dual-machine connected | on win-host `windbgx -k net:port=50000,key=...`, reboot the target | `Connected to Windows ...` appears and `!process 0 0`, `lm` lists nt |
| 4 | Ghidra runs | `C:\tools\ghidra\ghidraRun.bat` (mac: `~/tools/ghidra/ghidraRun`) | GUI comes up; headless imports any sys successfully |
| 5 | radare2 | `r2 -v` | ≥5.x |
| 6 | x64dbg | `x64dbg.exe` starts, attach to any process and break | F9 resumes execution |
| 7 | WinAFL demo passes | run the §3.1 test.exe command for 10 minutes | UI path count grows, no injection failures; if 0 new paths in 10 minutes, check bitness match/the -D path |
| 8 | ProcMon | capture 10 seconds of system activity | event count scrolling past 10,000 |
| 9 | PoolMon pool observation (optional) | run the WDK poolmon for 1 minute | per-tag list refreshing |
| 10 | macOS-side symbol download | the §6 python script downloads a PDB for any sys | file header `Microsoft C/C++ MSF 7.00` |
| 11 | VM snapshot | all the above pass | take the VMware snapshot `toolchain-ok-2026-10-16` |

Write the self-check results to `工具链报告-<日期>.md` (11 items ✓/✗/skipped + failure reasons + items needing humans); for failures, follow the corresponding section's degradation path (winget→scoop→manual zip) to install and retest.

## Appendix: Download Address Quick Reference (All Defer to the Actual Assets on the Releases Pages)

| Component | Address | Verified that day |
|---|---|---|
| Ghidra | github.com/NationalSecurityAgency/ghidra/releases | 12.1.4, needs JDK 25; brew cask does not exist |
| WinDbg | `winget install Microsoft.WinDbg` | manifest 1.2610.1001.0 |
| DynamoRIO | github.com/DynamoRIO/dynamorio/releases | cronbuild 11.91.20735 (rolling) |
| WinAFL | github.com/googleprojectzero/winafl | readme uses VS2019 as the example; VS2022 works |
| x64dbg | `winget install x64dbg.x64dbg` / x64dbg.com | 2026.05.27 |
| System Informer (formerly Process Hacker) | github.com/winsiderss/si-builds/releases | renamed continuation |
| Sysinternals | `winget install Microsoft.Sysinternals` / learn.microsoft.com/sysinternals | the full suite |
| WDK (includes PoolMon) | learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk | must match the OS version |
| ioctlbf | github.com/koutto/ioctlbf | active |
| kAFL | github.com/IntelLabs/kAFL | archived, unmaintained; Linux+Intel PT bar |
| syzkaller | github.com/google/syzkaller | official Windows support |
| honggfuzz | github.com/google/honggfuzz | Windows via Cygwin/MinGW; rolling after v2.6 |
| IDA Free | hex-rays.com/ida-free | 9.1 |
| Symbol server | msdl.microsoft.com/download/symbols | used by _NT_SYMBOL_PATH |
