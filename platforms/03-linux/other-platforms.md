# Other Platforms Security (knowledge base · Other platforms 1001013)

> Corresponding tree: Other platforms [1001013], 15 nodes. macOS is already its own area (→ `../05-macos/`); HarmonyOS is a standalone file in that same area. This file keeps the container (active surface) and the historical/archaeological surfaces: PSP/DOS/Symbian/WinCE/6502/BlackBerry/Win3.x.

## §1 Overview [1001014]

"Other platforms" is the knowledge base's bin for everything outside the main battlefields (Windows/Android/iOS/Linux), spanning 30 years. Methodology in one sentence: **switching platforms = switching file formats + switching instruction sets + switching the syscall surface; the RE methodology (static structure → dynamic behavior → locate the critical path) does not change**.

| Platform | File format | Instruction set | Active period | Status |
|---|---|---|---|---|
| macOS | Mach-O | x86_64/ARM64 | 2001-now | active, one of the mainstream RE targets |
| Containers | ELF (inside) + image layers | x86_64/ARM64 | 2013-now | active, cloud offense-defense |
| PSP | PRX/EBOOT | MIPS (Allegrex) | 2004-2014 | archaeology + emulators |
| 6502 | no unified format (bare ROM) | 6502 | 1975-1992 | retro computing |
| DOS | MZ EXE/COM | x86 16-bit | 1981-2000 | virus-history archaeology |
| Symbian | E32 image/SIS | ARM | 2000-2012 | prehistory of smartphone security |
| WinCE | PE (CE variant)/CAB | ARM/MIPS/SH4/x86 | 1996-2010 | industrial-control legacy |
| BlackBerry | COD | ARM/J2ME | 2003-2016 | archaeology |
| Win 3.x | NE | x86 16-bit | 1990-2001 | prehistory of PE |

## §2 macOS [1001257]

→ **Now a standalone area; the full text is at `../05-macos/macos-re-attack-surface.md`** (Mach-O hands-on/dyld injection tested/toolchain/LLDB workflow/TCC·XPC·persistence·notarization attack surfaces/hardening and the EDR detection surface; HarmonyOS is also in that area). Kernel-level → `../../techniques/07-kernel/cross-platform-kernel.md` §3.

## §3 Container Security [1001721]

The youngest node in the tree. A container is essentially an **isolated process sharing the kernel** — so container security = kernel isolation mechanisms (namespaces/cgroups/capabilities/seccomp) + the daemon surface (Docker daemon/containerd/K8s control plane).

```
逃逸路径总览:
容器内进程 ──┬─ ① daemon API 未授权(2375 裸奔)──挂载宿主根 → 直接拿下
             ├─ ② privileged 特权模式 ── mknod 磁盘/加载内核模块 → 逃逸
             ├─ ③ 挂载敏感路径(/var/run/docker.sock、/proc、/)
             ├─ ④ 内核漏洞(dirty cow / dirty pipe / CVE-2020-15257 shim 抽象套接字)
             └─ ⑤ K8s 面组件(kubelet 10250、dashboard、etcd、RBAC 失配)
```
(self-drawn ASCII)

### 3.1 Detection and technique checklist

- Container self-check (sample/blue-team perspective): `/proc/1/cgroup` (containing docker/kubepods) and `/.dockerenv` present, the `capsh --print` capability set, `fdisk -l` seeing the host disk = privileged container. Exemplar post: an app detecting whether it runs inside a docker container.
- The five escape types with case posts:
  1. Unauthenticated daemon: pentesting the docker remote API
  2. privileged: escaping the host via docker privileged mode
  3. CVE-2020-15257 (the containerd-shim abstract unix socket directly reachable in host mode): CVE-2020-15257 host-mode escape analysis
  4. Docker Engine authorization-plugin bypass CVE-2026-34040: Docker Engine CVE-2026-34040 container escape
  5. The K8s cluster surface: K8s cluster security (attacker's view, part 1)
- seccomp vs ptrace priority (scenarios where ptrace is blocked by default seccomp): bypassing seccomp with ptrace (the Stargate solve)

### 3.2 The RE perspective

Once inside a container, malware behaves exactly like Linux user-mode (ELF ecosystem, see [linux-security.md](linux-security.md)); what the container adds is **the sample's environment-awareness checks** (§3.1 self-checks) and **cloud-native persistence** (daemon implants, malicious image layers, sidecar injection). Analysis environments are themselves containerized — the sandbox is an image; the benefit is the whole strace/gdb suite rebuilds in seconds from a Dockerfile.

## §4 The PSP Handheld [1001015]

- **Architecture**: Sony's in-house Allegrex (MIPS32 core + VFPU vector coprocessor, 333MHz). RE = MIPS disassembly + the VFPU special instruction set.
- **Files**: `EBOOT.BIN` (main program; when encrypted, an encrypted ELFMIPS variant), `BOOT.BIN` (plaintext), `PRX` (relocatable modules, the equivalent of shared libraries); the firmware itself is also a PRX collection.
- **The cracking-history main line** (an early hot topic): ① firmware dump (reading flash via a vulnerability) → ② decrypting PRX (early on via the "decryption prism" key leak incident) → ③ custom firmware CFW (patching the loader PRX) → ④ the Pandora battery (the magic battery, modifying the serial to enter service mode for flashing).
- **Modern play**: dynamic debugging inside an emulator (PPSSPP) is far more convenient than real hardware; UMD isos mount directly to read the filesystem.
- Historical posts cluster in 2005-2010; grep the corpus for "PSP" to surface cracking posts.

## §5 6502 and Retro Computing [1001016]

- 6502: an 8-bit CPU (Apple II, Commodore 64, and the Famicom's 2A03 CPU is a modified 6502), no multiply/divide, zero-page addressing (0x00-0xFF used as registers), stack fixed to the 0x0100 page.
- The RE target is **bare ROM/PRG** (no file format, no relocation): IDA (`ida -m6502`), radare2, dedicated disassemblers; the Famicom side needs mapper (iNES .nes format) knowledge.
- The knowledge-base holdings are mostly early Famicom/Apple cracking and disassembly tutorial posts (early tree content).

## §6 DOS [1001017]

- **Formats**: `.COM` (a pure binary image loaded at 0x100, headerless) / `MZ EXE` (16-bit executable with a relocation table, the direct ancestor of PE).
- **Runtime surface**: `int 21h` (DOS services), `int 10h` (BIOS video), TSR stay-resident, `PSP` (program segment prefix ≈ command line + environment block). Real mode has no protection — a program can touch all 1MB directly: the golden age of viruses.
- **Virus techniques**: boot-sector viruses (MBR/DBR parasitism), file infectors (COM/MZ appended or cavity-injected), polymorphic encryption engines (the classic textbook is the knowledge base's Billy Belceb virus tutorial DOS volume [1000931], located in the Windows-security/virus-techniques area).
- **Modern analysis**: DOSBox + debug.exe (the MS-DOS built-in debugger; 16-bit real mode debugged thoroughly); IDA supports 16-bit x86 and MZ.
- The DOS node in the tree preserves the prehistory of PC security; "Reading notes: loading executables under DOS", "Calling the Chinese character library to display Chinese under DOS", "grub for dos bootloader analysis", "grub for dos boot stage1 analysis".

## §7 Symbian [1001018]

- Symbian OS: Nokia-led, ARM9/11. The **E32 image** format (magic `EPOC`) carries its own compression and UID1/2/3 checks; installers SIS/SISX (signature-based).
- RE chain: unpack SIS → dump the E32 image (already decompressed in memory) → analyze in IDA ARM. The S60 platform mixes Python/C++; library symbols (semc/nokia) are fairly complete.
- Security surface: Symbian Signed bypass, the capability model, certificate cracking (the DRM-cracking history). The community's active period was 2005-2012, the main mobile-RE battlefield before the Android era.
- Representative posts: "Notes on cracking Symbian S60 phone software", "Symbian virus analysis Part I", "Understanding Symbian virus (II)", "Symbian function/class to header and LIB mapping table", "The new Symbian OS 9 executable file format (E32Image)" — E32 format/virus analysis/cracking all covered.

## §8 Windows CE / Windows Mobile [1001021]

### 8.1 System structure [1001022]

WinCE shares ancestry with desktop Windows but a different core: modular kernel (nk.exe), object store, a unified 4GB virtual-memory layout (a 32MB slot per process); process/thread APIs resemble Win32 (a kernel32 subset), syscalls go through `TrapAPI`/direct swi.

### 8.2 RE [1001023]

- Files: PE variants (ARM/MIPS/SH4/x86 cross-compiled, `IMAGE_FILE_MACHINE_ARM` etc.) + `.cab` installers (unpackable via `extract`/msi back-annotation).
- Tools: IDA (the ARM workhorse), WinCE's built-in Remote Tools (PRV etc.), emulators (Visual Studio Emulator / Device Emulator) — **emulator snapshot debugging** was the most comfortable path of the day; the real-device side used ActiveSync + a remote debugging agent.
- Crack targets: navigation software (the biggest category domestically back then), input methods, shareware registration. The techniques share the Win32 lineage: find the registration check, patch, re-sign.

### 8.3 Security [1001024]

The signature-permission trusted tier, system-certificate forgery, kernel nk patches; and the full closure of the later WP era. Representative posts: "Windows CE essential development tools summary", "An AutoRun implementation for Windows CE", "Setting up an IDA remote-debugging environment for WINCE programs".

### 8.4 Program development [1001025]

eMbedded Visual C++ / VS2008 Smart Device; driver and system-capability experience posts live in this node. An RE person's development knowledge mainly serves writing patch DLLs and RAPI tools.

## §9 BlackBerry OS [1001026]

- Format **COD** (a compressed Java-bytecode variant, J2ME pedigree): ALX/Sibling/JAD install descriptors + the COD body.
- RE chain: COD → unpack (`cod-decoder`-class tools/zip-decompression variants) → class bytecode → dex2jar/JD-GUI and other Java tools reused directly.
- Crack targets: BES enterprise-mail policies, third-party Java app registration codes. Active period 2008-2013; representative posts: "BlackBerry 9530 CDMA MEID/ESN protection", "Decompiling BlackBerry COD files".

## §10 Windows 3.x [1001289]

- Format **NE** (New Executable, 16-bit): MZ header + NE header; the segment table has no virtual-address notion (allocated at load), `res` resource table, entry table. PE's direct predecessor — a living fossil for watching PE's evolution.
- 16-bit cracking: seg:offset address arithmetic, thunks (16/32 mixing), local/global heaps; tools SoftICE (the king of the 16-bit era), TD (Turbo Debugger), modern IDA.
- A large body of early NE cracking tutorials settled here.

## §11 Reference quick table

| Topic | Item | Link |
|---|---|---|
| macOS | macOS RE basics tutorial series |  |
| macOS/iOS tools | The complete guide to common iOS RE tools (2026) |  |
| Containers | Analyzing docker escape methods in different scenarios |  |
| Containers | Pentesting the docker remote API |  |
| Containers | Escaping the host via docker privileged mode |  |
| Containers | CVE-2020-15257 host-mode escape analysis |  |
| Containers | Docker Engine CVE-2026-34040 container escape |  |
| Containers | K8s cluster security (attacker's view, part 1) |  |
| Containers | Cloud offense-defense: container escape and k8s attack techniques |  |
| Containers | An app detecting whether it runs in docker |  |
| Containers | Bypassing seccomp with ptrace (the Stargate solve) |  |
