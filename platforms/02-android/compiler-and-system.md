# Compiler and System Internals — the Full ART Chain / SELinux / seccomp / binder

> Corresponding tree nodes: Compilers [1001297] / System Topics [1001344]
> Division of labor with the techniques library: area 11 `../../techniques/11-syscall-chain/dex-load-exec-chain.md` covers the **sequence and observation points** of "dex into memory to being executed"; this file adds the **compiler itself** (the javac→d8→dex2oat→JIT toolchain and output formats) and the **system security architecture** (SELinux/seccomp/binder policy and driver layers). Overlaps are cross-linked.

## 1. Compile-Chain Panorama: from .java to CPU instructions

```
.java ──javac──> .class ──d8/r8──> classes.dex ──打包──> .apk
                                              │
        [安装期] pm/installd → dex2oat(64) ──> oat/<arch>/base.{odex,vdex}
                                              │
        [运行期] ClassLoader → odex/vdex 优先,失败 fallback APK 内 dex
                    │
        ├─ nterp 汇编解释器执行(A12+ 默认)
        ├─ JIT:热点方法→quick code(匿名 code cache)
        └─ AOT:profile 回流→后台重 dex2oat(只编热方法)
```

### 1.1 Front end: javac and dx/d8/r8

- **javac**: `.java`→`.class` (JVM bytecode, stack-based; the tree's "class bytecode" subtree [1001301] covers exactly this layer).
- **dx** (old) → **d8** (AOSP 8.0+): the class→dex converter; **r8** is a superset of d8 + shrinking/optimization/obfuscation (replaces ProGuard). The `--min-api` parameter decides whether fallbacks such as default interface methods are generated.
- Key difference: JVM stack-based vs Dalvik **register-based** (virtual registers v0-vN actually mapped to physical registers) — this is why dex instructions are dense, and the basis of smali readability.

### 1.2 The Dalvik→ART evolution (tree "Android runtime [1001602]")

| Phase | Version | Execution | Essentials |
|---|---|---|---|
| Dalvik | ≤4.4 | JIT (2.2+) | Dalvik VM, `dexopt` produces odex (optimized bytecode, not machine code); the instruction-set tree [1001299] is this layer |
| ART full AOT | 5.0-6.0 | Full AOT at install time | dex2oat compiles everything at install → slow installs / space hog; the `Patchoat`/`oatdump` era |
| Mixed compilation | 7.0+ | JIT+PGO+AOT | Install → JIT runs + collects profile → idle background recompiles per profile ("speed-profile") |
| nterp | introduced 8.0, default 12+ | Assembly interpreter | Successor of mterp (A7-11); `ExecuteNterpImpl` C symbol, x0=ArtMethod |
| JIT zygote | 14+ | boot image with attached JIT cache | `dalvik.vm.jitzygoteimage` namespaced, faster startup |

### 1.3 dex2oat deep dive (core of tree "compilation [1001612]")

- **Trigger points**: ① install/update (PackageManagerService→installd→`/system/bin/dex2oat64`, arguments assembled by ArtService); ② background idle (bgdexopt_job, recompiles per Cloud Profiles); ③ manual: `pm compile -m speed-profile -f <pkg>`, `cmd package compile`; ④ boot-image compilation at power-on (in the image, `--boot-image` flag).
- **Key parameters** (for forging/analysis during RE): `--dex-file` input, `--oat-file/--output-vdex` outputs, `--compiler-filter=` (`verify`/`speed`/`speed-profile`/`everything` — decides how much gets compiled), `--runtime-arg -Xplugin:...`, `--dump-timers`; `-Ximage-compiler-option`.
- **The three outputs** (same directory `/data/app/<pkg>~~<rand>/oat/<arch>/`):
  - `base.odex` (ELF container holding the OAT header + quickened/AOT machine code; increasingly thin since A10)
  - `base.vdex` (original dex / compressed original + verification info, the **de-facto main body since A8.0**; see [file-formats.md](file-formats.md) §5)
  - `base.art` (optional, prewarmed image, class-pointer table)
- **Load priority** (empirically verified against main-branch source in the techniques library): odex→vdex→APK fallback; **anonymous-memory dex can also be paired with an anonymous vdex** (`AnonymousDexVdexLocation`, reused only when the checksum matches) — the principle of deleting the oat directory with `--clean-oat` before dumping to avoid grabbing cdex (eBPFDexDumper's default behavior).

### 1.4 The JIT system

- JIT compiler: method hot-count over threshold → `JitCompiler` → quick code lands in the **JIT code cache** (an in-process anonymous mapping, default capacity on the order of 16MB, can be relocated by GC).
- **Three RE pitfalls of the JIT region** (verified in the techniques library): ① anonymous mappings have no symbols; IDA/frida both see bare addresses; ② blocks get moved, so `Interceptor` hooks on JIT code expire at any time; ③ Stalker following JIT code needs `exclude` + timely unfollow.
- PGO: the JIT-collected profile is written to `profile.prof` (ART profile format, readable/mergeable by `profman`); Cloud Profiles (Android 9+) are pushed aggregated from the server.
- Method execution-state switching: the quick entry points to one of four states — nterp/JIT/AOT/JNI stub; `kAccCompileDontBother` blocks recompilation; deopt pulls compiled code back into the interpreter — **the full four-state matrix and observation points are in the techniques library `../../techniques/11-syscall-chain/dex-load-exec-chain.md` chain 3**.

### 1.5 Obfuscating compilers (tree: OLLVM-framework builds [1001751])

- **OLLVM**: LLVM-Pass-style obfuscation (control-flow flattening `-mllvm -fla` / bogus control flow `-bcf` / instruction substitution `-sub`); on the Android side: ndk + self-built clang, Pass injection; **active forks** (Hikari/Armariris/pluto…) and the 8-class obfuscation-trait master table plus four restoration routes are in the techniques library `../../techniques/10-algo-restore/deobfuscation-practice.md`, not duplicated.
- **BlackObfuscator**: replaces dex-level method bodies with custom-interpreter bytecode (open source; restoration walkthrough posts exist on the site).
- The tree's "front-end compilers [1001752]" is mostly javac/ecj/compiler-theory posts, weakly related to RE.

### 1.6 The decompilation side (tree "decompilation [1001636]")

ApkTool [1001596] (resources + smali round trip, `apktool d/b`, framework-library pitfalls), JEB [1001597] (dex→Java pseudocode + xrefs), tips and experience [1001635]. **The horizontal comparison (incl. jadx/Ghidra/CFR/Vineflower/Krakatau + version pitfalls + ROSAL stdlib deobfuscation) is cross-linked to the techniques library `../../techniques/05-toolbox/static-analysis-tools.md`, not duplicated.**

Representative posts: "Android ART analysis", "ART", "Notes on the Android OAT file format", "Parsing OAT files on Android 4.4.2", "oat_file_manager and oat_file_assistant", "The OatFile::Open flow and obtaining OatDexFile", "First experience debugging dex code in IDA"; internal empirical source in the techniques library: `vmp restoration` (incl. the ART bytecode-replacement mechanism).

## 2. Dalvik/ART instructions and VM details (tree Dalvik [1001603]/data structures [1001664])

- **Dalvik instruction set [1001299]**: invoke-virtual/static/direct/interface/super/range, the iget/iput field family, the sget/sput static family, const/string/class, new-instance, check-cast, array filling fill-array-data; **quickened instructions** (ART-specific): `invoke-virtual-quick`/`iget-quick` — at AOT time symbolic references are replaced with vtable indices/offsets, so a quick suffix = this dex has been through dex2oat (de-quickening is required when repairing after unpacking).
- **ArtMethod layout** (the core RE structure): `declaring_class_ +0` (u32 compressed reference; the layout narrows from A12, re-run offset probing when switching versions) → Class `+0x10` dex_cache → DexCache `+0x10` DexFile → `+0x8` begin (chained to get the dex base; the techniques library gives full offsets and version boundaries); probing scripts for `entry_point_from_quick_compiled_code_` and accessFlags are in the techniques library `../../techniques/02-frida/frida-api-reference.md` §6.
- **Virtual functions [1001613]**: a Java method is non-virtual whenever final/static/private, its invoke is statically bound; in RE the "virtual function table" corresponds to the Class's vtable (itable when imt conflicts) — hook interception does not land on the vtable but at the ArtMethod entry, which is the dividing line between ART hooks (the Xposed family) and SO hooks.

## 3. SELinux / SEAndroid (tree SEAndroid [1001626])

### 3.1 Principles

- **MAC mandatory access control**, default-deny: every process gets a **domain** label, every file/resource gets a **type** label, and policy only writes "allow domain type:class permission" — nothing written = denied. Official docs are in the AOSP documentation.
- Label shape: `u:object_r:<type>:s0`; app-process domains = `untrusted_app` (third-party)/`platform_app` (platform-signed)/`system_app`; files such as `apk_data_file`, `app_data_file`.
- Policy files: source `.te` compiled to `sepolicy` (binary, `/sys/fs/selinux/policy`) loaded at runtime; post-Treble the policy splits: system partition (system/sepolicy) + vendor partition (vendor SEPolicy), allowing vendors to update independently.
- Key files/commands: `/sys/fs/selinux/enforce` (0/1), `getenforce`/`setenforce`, `sesearch -A -s untrusted_app -t ...` to query rules, `audit2allow` to generate allows from avc logs, `magiskpolicy --live "allow ..."` (fine-grained relaxation under root).
- **avc denied logs**: `dmesg | grep avc` / logcat — when analyzing EoP samples, denied records are exactly the trace of the sample hitting the wall.

### 3.2 Offense-defense perspective

- **Bypass shapes** (the 8ksec kernel-level series): after kernel RCE, change the `cred->security` domain label (`selinux_enforcing`/the current task's sid) back to something like `u:r:magisk:s0`; or hit paths the `security_*` hooks do not cover (GPU DMA/cross-cache); SELinux only constrains the surface covered by LSM hooks, bare kernel bugs are not constrained by it.
- **Interaction with seccomp** (consensus from Reddit field reports): **when SELinux is permissive, zygote does not install seccomp filters** — so a permissive kernel on a custom ROM is a double weakening, not just the SELinux layer.
- Root scenario: Magisk performs mounts/Shamiko hiding in the `u:r:magisk:s0` domain; do not go globally permissive, use `magiskpolicy` for fine-grained relaxation (expanded in the techniques library `../../techniques/04-evasion/root-env-hiding.md` §4.2).
- App-side detection: `getprop ro.build.selinux` (whether SELinux is enabled), read `/sys/fs/selinux/enforce`; one part of the root-detection surface.

Representative posts: "SEAndroid IPC", "SELinux-Permissive-VS-Enforcing", "Modifying Magisk v24.1 source to hide an APK and run it as root".

## 4. seccomp (a branch of tree "system kernel" [1001346])

- **Principle**: SECure COMPuting mode — a process voluntarily installs a BPF filter limiting the syscall whitelist; violations get SIGSYS. Since Android 8.0 it is installed per app by **zygote** (app-domain filter + vendor additions), based on the architecture's syscall number table (arm64).
- **Direct consequences for RE/vulnerability hunting** (verified in the techniques library): **io_uring is fully blocked in the app domain** (since mid-2023, Google sealed it with seccomp-bpf over its security track record; `io_uring_setup` gets SIGSYS outright) — attacking the io_uring surface first requires switching seccomp domains (root/system process). The KCTF 2024 challenge-8 "Stargate" Ptrace-vs-seccomp bypass is exactly this kind of confrontation.
- **Probing and bypassing**:
  - Probe the whitelist: try syscalls one by one (check errno/SIGSYS), or read the Seccomp line of `/proc/self/status` (`Seccomp: 2` = filter mode);
  - Bypass ideas: ① switch process (spawn an unfiltered native child — filters survive fork/exec, but the debugger/system_server side has no such restriction); ② ptrace-inject into an unrestricted domain; ③ do it directly in kernel mode (kprobe/BPF, root); ④ find an allowed syscall combination that is equivalent (note: `faccessat2` only performs access-semantics checks and returns no fd, it **cannot** equivalently replace the blocked `openat` for reading files; what actually works is finding same-purpose unblocked calls — e.g. the `open`/`memfd_create`+`/proc/self/fd` combo, depending on the specific gaps of the filter).
- Tools: `seccomp-tools` (dump/asm/disasm, ruby implementation, `seccomp-tools dump ./bin` lists filters); frida `Process.setExceptionHandler` to catch SIGSYS and locate the blocking point.
- Representative posts: "The seccomp sandbox mechanism & 2019 ByteCTF VIP", "Modifying syscalls with seccomp-bpf + ptrace: principles (with demo)", "A universal Android svc tracing and hooking scheme — Frida-Seccomp", "A universal Android svc hook scheme based on seccomp + sigaction", "Seccomp BPF and container security", "A general AWD pwn defense gadget based on pwntools and seccomp-tools"; also "Implementing an SVC TraceHook sandbox & ideas for traceless hooks" (2022-06) — the complete landing of the ptrace+seccomp duo intercepting inline SVCs to modify arguments/return values (incl. the fork thread-tracking scheme).

## 5. The binder driver system (tree "system kernel" [1001346]/data structures [1001664])

- **What it is**: the substrate of all Android IPC — the `/dev/binder` character device; the client enters the kernel via `ioctl(BINDER_WRITE_READ)`, `binder_transaction` allocates the buffer, copies once, fixes up references, and wake_up wakes the server thread; `hwbinder` (HAL)/`vndbinder` (vendor) are vendor-isolated copies.
- **Core structures**: `binder_transaction_data` (target handle/ptr, code, data buffer+offsets[]), `flat_binder_object` (cross-process object: strong/weak refs, BINDER_TYPE_FD to pass fds), and the binder_proc/binder_node/binder_ref three-layer object graph.
- **Classic vulnerability patterns** (expanded in the techniques library `../../techniques/07-kernel/android-kernel-ebpf.md` §2): offsets[] out-of-bounds, `binder_fixup_parent` boundary errors, FDA refcount UAF, UAF caused by missing synchronization, vendor-private binder device permission misconfiguration crossing domains for EoP.
- **RE usage**: at the kernel layer hook `binder_transaction` and filter dumps of parcels by `target.handle+code` (IPC tracing blind to RASP); the ServiceManager query chain (svcmanager domain); at the Java layer enumerate the binder surface first with `service list`/`dumpsys -l`.
- **Full bidirectional sequence and observation-point matrix cross-linked**: the techniques library `../../techniques/11-syscall-chain/binder-signal-chain.md` (387 lines; client ioctl→transaction→wake_up→BR_TRANSACTION with every struct expanded + the ptrace anti-debug chain). Not duplicated here.

## 6. ROM/root/Magisk/custom systems (tree Android ROM [1001345]/root permissions [1001401]/Magisk [1001754]/custom systems [1001771])

- **Boot chain**: bootloader (locked/unlocked) → boot.img (header+zImage kernel+ramdisk) → init → zygote → system_server. AVB (Android Verified Boot) verifies partitions; after unlocking the bootloader the dm-verity state change can be detected by apps (`ro.boot.verifiedbootstate`).
- **Partition table** (A/B and virtual A/B): system/vendor/product/system_ext (OEM dynamic partitions in super); **GKI 2.0** (Android 12+) decouples kernel and modules with a stable KMI ABI — the impact on kernel exploitation and boot.img symbol-extraction practice are in the techniques library `../../techniques/07-kernel/android-kernel-ebpf.md`.
- **The three root options**: Magisk (systemless overlay + Zygisk), KernelSU (kernel mode, `ksud`), APatch (kernel patch + KPM); Shamiko/DenyHide residual surfaces (mounts/SELinux/props) and the solution order against banking-app detection stacks are cross-linked to the techniques library `../../techniques/04-evasion/root-env-hiding.md`.
- **Custom systems [1001771]**: self-built ROMs (AOSP lunch→packaging otapackage)/Xposed framework-level customization (LSPosed)/vendor modifications; this subtree is mostly LineageOS-family practice posts.

## 7. Toolbox and representative-post summary for this file

| Topic | Tools | Notes |
|---|---|---|
| dex2oat/output analysis | `pm compile`, `oatdump`, vdexExtractor, profman | newer oatdump centers on `dexdump`/vdex extraction, --export-dex-to removed |
| SELinux | sesearch/audit2allow/magiskpolicy, `getenforce` | source at system/sepolicy |
| seccomp | seccomp-tools (dump/asm/disasm) | ruby implementation, `seccomp-tools dump ./bin` lists filters |
| binder | binderProcState (dumpsys), `service list`, kernel kprobe/bpftrace | deep links into techniques library areas 07/11 |
| ART observation | frida (symbol/inline/stalker), eBPF uprobe, perfetto | decision tree in the techniques library area-11 observation-point matrix |

Representative posts:
- dex vmp restoration (incl. the ART bytecode mechanism): techniques library `vmp restoration` empirical source
- "eBPF applications in Android security (part 1/2)" (part 1: eBPF basics + toolchain; part 2: building a behavior-detection sandbox around binder); "eBPF on Android: compiling and patching the kernel", "Learn to hook syscalls with eBPF-BCC in 60 seconds", "An eBPF-based Android RE assistant — stackplz", "Linux kernel eBPF source analysis — verifier and JIT"
- KCTF 2024 challenge-8 "Stargate" Ptrace-vs-seccomp writeup (2024-09: nc connects twice producing two processes, ptrace stops the prctl call and rewrites it into an unrelated call to escape the sandbox; from the setter's side there is also the checkpoint of ptrace-injecting a `sleep infinity` process)
- The "All About Android RE" series (lesson 13 Frida intro, lesson 14 Frida all-in-one, lesson 23 Unidbg)
