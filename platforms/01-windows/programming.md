# Part 8: Programming — A Panorama of Low-Level Security Offense/Defense Programming

> Corresponding tree node: Windows Security [1000012] → Part 8: Programming [1000785] (18 child nodes).
> Main line: **injection and hooking are cross-cutting techniques, drivers are the Ring0 ticket, Rootkits/Bootkits are malware forms, and system programming is the foundation**. This part is organized by the 18 nodes, with deep dives on: the full injection taxonomy, hand-rolled inline hooks, driver IRP/IOCTL, and the basics of Windows malware development.

## 1. Fundamentals [1000786]

The four foundation blocks of low-level security-oriented programming:

- **Hardware-related [1000822]**: port IO (the x86 `in/out` privileged instructions, not directly usable from Ring3), USB drives (enumeration via `WM_DEVICECHANGE`/SetupDi — how malware samples ferry across air gaps), keyboard/mouse (global hooks see §3; driver-grade kbdclass filtering), disks (ATA Pass Through, direct sector read/write via `\\.\PhysicalDrive` — the mandatory path for MBR/Bootkit disk writes), BIOS (real-mode entry, pre-UEFI knowledge), SMM (System Management Mode, above Ring0).
- **Secure programming [1000833]**: self-protection (file/registry/process tamper-proofing), anti-debugging/anti-injection (echoing Part 5: Protection).
- **x86-64 programming [1000834]**: under 64-bit, `__fastcall` passes the first 4 arguments in RCX/RDX/R8/R9; hook stubs and shellcode must follow the new ABI.
- **Algorithms/development tips/C++ advice [1000835/1000836/1001198]**: RAII for handles, safe SEH usage, compiler principles [1001245] (the theoretical background of the Languages part/compiler selection).

## 2. Environments and Languages [1000787]

- **The assembly family**: MASM (Luo Yunbin's *32-bit Assembly Language under Windows* is this knowledge base's main Win32 asm textbook [1000805-1000808]), TASM (a 16-bit-era legacy), NASM, the RadASM IDE. The Win32 assembly route: window creation → message loop → controls → DLLs → event hooks.
- **C/C++ [1000809]**: the mainstay of security development; `Learning C/C++ from the Assembly Perspective` [1001716] is this library's recommended reverse-perspective learning method.
- **MIX languages [1000811]**: inline assembly in C++ (`__asm`)/Delphi mixed with C — a must-have skill for writing shellcode/hook stubs (inline assembly [1000820]).
- **Frameworks [1001784]**: **LLVM** [1001779] (writing obfuscation passes, echoing the Protection part's OLLVM), **Frida** [1001785] (the modern hooking/injection framework of choice, cross-language; the Reconstruction part also has Frida patches [1001743]).
- Environment selection conclusion: write injectors/hooks in C (small, controllable); write analysis automation in Python (Frida bindings); write packers/crypto in C + assembly.

## 3. Injection Techniques [1000852] (Key Focus)

**Injection knowledge overview**: deliver code/modules into the target process's address space for execution. Classified by execution vehicle:

```
The injection technique tree (restored in text)
DLL injection routes
 ├─ ① Remote thread CreateRemoteThread+LoadLibrary (classic)
 ├─ ② NtCreateThreadEx/RtlCreateUserThread (bypassing CreateRemoteThread monitoring)
 ├─ ③ APC injection QueueUserAPC (fires when the target thread is alertable)
 ├─ ④ SetWindowsHookEx (WH_GETMESSAGE/WH_CBT, the system loads the DLL on demand)
 ├─ ⑤ Input-method IME injection (imm32 loads a custom IME into GUI processes)
 ├─ ⑥ COM hijacking (registry CLSID/InprocServer32 pointing at a malicious dll)
 ├─ ⑦ AppInit_DLLs / Image File Execution Options Debugger
 ├─ ⑧ DLL hijacking/proxying (place the malicious dll early in the search path, forward exports)
 └─ ⑨ Process Hollowing (create suspended → unmap image → write → patch context → resume)
Shellcode routes
 ├─ ⑩ WriteProcessMemory + SetThreadContext (change EIP/RIP)
 ├─ ⑪ Thread-context injection/ghost threads (Thread Hijacking)
 ├─ ⑫ Reflective DLL Injection (self-implemented loader, no LoadLibrary on the way)
 └─ ⑬ Puppet processes/AtomBombing/PROPagate and other window-object abuse
```

### 3.1 Remote-Thread Injection (the Classic Four Steps)

```c
// Minimal implementation (tutorial)
HANDLE h  = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
LPVOID m = VirtualAllocEx(h, NULL, len, MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(h, m, dllPath, len, NULL);
CreateRemoteThread(h, NULL, 0,
    (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA"),
    m, 0, NULL);
```
Essentials: under ASLR the kernel32 base is consistent across processes in the same session (pre-Win7; afterwards sessions are isolated, but it still works in most scenarios — the robust way is `Toolhelp32Snapshot` to get the target's kernel32 base); the route most closely watched by EDR.

### 3.2 SetWindowsHookEx Injection

`SetWindowsHookEx(WH_GETMESSAGE, proc, hDll, threadId)`: when the target is a GUI thread, the system maps hDll into the target process to process messages. Advantage: no OpenProcess needed; disadvantage: requires a DLL + the target must have a message loop. Frequently used by keyloggers and input-method abuse scenarios.

### 3.3 APC Injection [1000855]

Queue a routine onto the target thread's APC queue; it executes when the thread enters the alertable state (`SleepEx/WaitForSingleObjectEx`). Walk all the target process's threads and queue once each to raise the hit rate; malware loves injecting into browsers/AV processes that constantly do async IO.

### 3.4 IME Injection and COM Hijacking

- **Input methods**: imm32 loads the IME (essentially a dll) into GUI processes; old cheats/stealer samples used it as a "legitimate loading channel"; the confrontation point: IME signature verification (modern Windows has tightened this).
- **COM hijacking [1000754, adjacent knowledge in the Reconstruction part's DLL hijacking]**: change `HKCU\Software\Classes\CLSID\{...}\InprocServer32` to point at your dll; when COM consumers like explorer load it, that's injection; no process operations needed, commonly used for persistence (linked with registry handling §10.3).

### 3.5 Process Hollowing

`CreateProcess(SUSPENDED)` → `NtUnmapViewOfSection` to clear the original image → `VirtualAllocEx` + write the malicious PE → `SetThreadContext` (EBX/RDX pointing at the new PEB ImageBase) → `ResumeThread`. A legitimate shell with malicious contents; standard in evasion and trojan generators; detection point: the in-memory image hash mismatching the on-disk file.

### 3.6 Reflective DLL Injection

The injector only writes the DLL bytes into the target's memory; the DLL ships a `ReflectiveLoader` export: self-relocation, self-import-resolution, calling DllMain — `LoadLibrary` never appears, and (by default) it never enters the module chains, bypassing module-enumeration detection. Metasploit/CS callbacks are exactly this technique. Modern confrontation: memory scanning, ETW, callback monitoring (`PsSetLoadImageNotifyRoutine`).

**Injection applications/tools** [1000857/1000854]: classic injectors (ProcMemCopier, ExtInject), game trainers, HIPS testing; the knowledge tree has a separate "injection-related [1000858]" node collecting variants (e.g., Early Bird — queueing an APC early in process creation).

**Representative posts**: "Dll Injection into NetTransport 2.25.337", "DLL Injection via QueueUserApc", "The Simplest DLL Injection", "DLL-less Remote-Thread Injection", "N Ideas and Implementations for Kernel DLL Injection", "Remote DLL Injection and Unloading in Win32 Assembly", "A Rogue Method of Injecting dll in the Kernel".

## 4. Hook Techniques [1000837] (Key Focus)

**The hook concept [1000838]**: intercept calls/messages and divert them. Classified by layer (the tree nodes cover them all):

| Type | Node | One-sentence principle | Layer |
|---|---|---|---|
| IAT Hook | 1000847 | patch the import-table function pointer | after PE load |
| InLine Hook | 1000844 | write a jmp stub at the function head | any time |
| API Hook | 1000840 | the umbrella term for the above two, Ring3 | — |
| Message Hook | 1000841 | SetWindowsHookEx on the message chain | USER layer |
| SSDT Hook | 1000843 | patch ntoskrnl SSDT table entries, Ring0 | kernel |
| IDT Hook | 1000845 | patch interrupt-descriptor-table entries | kernel |
| IRP Hook | 1000846 | hook the IRP dispatch queues (file/keyboard driver stacks) | kernel |
| Object Hook | 1000842 | patch function pointers inside kernel objects (e.g., OBJECT_TYPE->TypeInfo) | kernel |
| SEH Hook | 1000848 | vectored-exception VEH hooking INT3/illegal access | Ring3 |
| InfinityHook | 1001704 | hook WMI's ETW notification callbacks to bypass PatchGuard | kernel (Win10) |
| Detection/recovery/confrontation | 1000849 | verify bytes/table entries, restore hooked regions | — |

### 4.1 Hand-Rolling an Inline Hook (Core Code)

```c
// 32-bit minimal jmp stub (5 bytes); on 64-bit use a register stub or trampoline
// 1) Length disassembly: determine the complete instruction boundary covering >=5 bytes at the hooked function's head
size_t stolen_len = disasm_at(target, 5);   // use HDE/BeaEngine/Capstone
// 2) Back up the stolen bytes to build a trampoline: stolen + jmp target+len
 BYTE* tramp = alloc_near(target);
 memcpy(tramp, target, stolen_len);
 patch_jmp(tramp + stolen_len, (BYTE*)target + stolen_len);
// 3) Write the E9 detour at the head
 patch_jmp(target, my_hook);
// 4) Inside my_hook, after your work, call tramp to return to the original flow
```

Essentials and pitfalls:
- **Length disassembly is the soul**: overwriting half an instruction off an instruction boundary crashes for sure; use Capstone/HDE, not hand-counted bytes.
- **Short-jump range**: `E9` relative jumps span ±2GB; the detour function must be `VirtualAlloc`'d nearby, or use the 7-byte absolute jump stub `mov eax, addr; jmp eax`; on 64-bit you need a 12-byte stub (`mov rax, imm64; jmp rax`) or a 14-byte one.
- **Multi-threaded races**: while the stub is being written, other threads executing the head → first `SuspendThread` all threads, or use an atomic 8-byte write (write the later 5 bytes first);
- **Reentrancy and recursion**: calls to the original API inside the hook must go through the trampoline, or you loop forever;
- **x64 hot patching**: most system APIs reserve `mov edi,edi` (2 bytes) + 5 bytes of nop space at the head, usable directly (Microsoft's official hotpatch design).
- Ready-made libraries: Detours (Microsoft), MinHook (complete length-disassembly + trampoline implementation, recommended reading), Funchook; the tree's "hook libraries [1000839]" node collects these.
- **Hook detection confrontation [1000849]**: verify `.text` CRC/byte snapshots, re-read a clean copy from disk for comparison, kernel-side PatchGuard; the attackers use means like "hook pages made read-only + VEH repair". Corresponds to the Protection part's anti-debugging and Part 6's memory patches [1000738-1000742] (the Debug API, debug registers DR0-DR3 hardware-breakpoint hooks).

**Representative posts**: inline hooks — "An inline Hook Project", "The Key Points of inlineHook as a Rookie Understands It", "Bypassing Function-Head INLINE HOOK", "inline hook NtQueryDirectoryFile"; SSDT — "The Clever Uses of SSDT Hooks", "SSDT Inside and Outside the City Walls", "shadow ssdt study notes", "Finding the Original Table and Restoring the ssdt Table", "Modifying the SSDT Table to HOOK the NTDebugActiveProcess Function", "The Age-Old Art of SSDT Hooking".

### 4.2 The Frida Contrast: Scripted Hooking and Injection

The 2020s answer to the same task (the framework node [1001785]); learning it side by side with the hand-written version is most efficient:

```js
// frida -p <pid> or frida -f target.exe
Interceptor.attach(Module.getExportByName(null, "MessageBoxW"), {
  onEnter(args) { console.log("[+] title=", args[1].readUtf16String()); },
  onLeave(retval) { retval.replace(0); }              // changing the return value = a memory patch
});
// = hand-written: length disassembly + trampoline + detour; Frida does all of it automatically
Java.perform(() => {                                   // same for the Java/managed layer
  let Activity = Java.use("android.app.Activity");    // (echoing the Android side)
});
```

- `Interceptor.replace` = whole-function replacement (the hand-written detour simply never returns to the original function);
- `frida-trace -i "CreateFile*"` = batch hook generation with templates; a sample's API behavior profile in ten minutes;
- Relation to the hand-written way: Frida's underbelly is exactly §4.1's inline hook (the gum engine contains the full length disassembly); when EDR watches for frida-agent signatures you still need to fall back to hand-written/driver approaches.
- In-tree echo: the Reconstruction part's "Frida patches [1001743]" uses Frida as a patcher (an SMC substitute).

### 4.3 Hook-Type Selection Quick Reference

```
What do you want to intercept?      Ring3 first choice        Ring0 first choice
────────────────────────────────────────────────────────────
This process's APIs                 IAT (clean)/Inline (generic)  —
Cross-process APIs (monitoring)     DLL injection + Inline / Frida  object callbacks/ETW
Window messages/keyboard            SetWindowsHookEx           kbdclass IRP Hook
Files/registry                      minifilter not possible, Ring3 API Hook  minifilter/Cm callbacks
Networking                          WFP callout                WFP/NDIS
System-call entry points            — (PatchGuard blocks SSDT) InfinityHook (older Win10)
```

## 5. Driver Development [1000887] (Key Focus)

### 5.1 Getting Started with Drivers [1000888]

- Environment: WDK + VS; KMDF/WDM/UMDF selection (security scenarios mostly use bare WDM drivers for control).
- Skeleton:

```c
NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    DbgPrint("[drv] loaded\n");
    for (int i=0;i<IRP_MJ_MAXIMUM_FUNCTION;i++)
        drv->MajorFunction[i] = DefaultDispatch;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlDispatch; // the user-mode communication entry
    drv->DriverUnload = DriverUnload;
    IoCreateDevice(drv, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &dev);
    IoCreateSymbolicLink(&symLink, &devName);
    return STATUS_SUCCESS;
}
```

### 5.2 IRP/IOCTL: Ring3↔Ring0 Communication [1000894/1000895]

- User mode `CreateFile("\\\\.\\MyDev")` → `DeviceIoControl(h, CTL_CODE(...), in, out)` → the kernel's `IoctlDispatch` receives the IRP:
  - `irpStack = IoGetCurrentIrpStackLocation(Irp)`;
  - `CTL_CODE(DeviceType, Function, METHOD_xxx, FILE_ANY_ACCESS)`; `METHOD_NEITHER` passes raw user pointers (must `ProbeForRead/Write` + SEH wrapping, or you get an arbitrary-address privilege-escalation hole);
  - Three buffering approaches: BUFFERED (safe default)/IN_DIRECT/OUT_DIRECT/NEITHER;
- **Security red lines** (also the historical vulnerability patterns): IOCTLs not validating input lengths, `METHOD_NEITHER` without probing, devices openable by any user (ACL) — the three big sources of driver privilege-escalation vulnerabilities.
- IRP concept extensions: completing IRPs yourself (`IoCompleteRequest`); dispatching asynchronously to lower drivers (mandatory for file filtering); `IoBuildSynchronousFsdRequest` for actively issuing IRPs (inter-driver communication).

### 5.3 Driver Loading [1000889/1000890]

- The proper route: SCM (`CreateService SERVICE_KERNEL_DRIVER` → `StartService`), test-signing mode `bcdedit /set testsigning on`;
- The gray route: driver loaders (using vulnerable drivers' signature chains to load unsigned drivers, KDMapper maps via the Intel vendor driver iqvw64e), DSE bypass; 64-bit enforced signing is the main line;
- Debugging [1000891]: WinDbg dual-machine (serial/network NET pipe), `bu drv!DriverEntry`, symbols from the `srv*` Microsoft symbol server;
- In-tree special topics: "driver-programming fundamentals special topic [1000893]" in two sections (getting-started flow/WDM and user-mode communication), "Delphi driver-development research [1000892]" (an old series writing drivers in Delphi with KOL-style flavor).

**Representative posts**: "Driver Getting Started", "Entering the World of Windows Driver Development", "Dynamic Driver Loading", "Using DeviceIoControl and CreateFile in WDM Drivers", "WDM Drivers: Async I/O, Event Notification, Spinlocks", "WDM Drivers Passing Data with Buffer I/O, Direct, and Neither Modes", "A WinDbg User-Mode Debugging Tutorial", "A Simple WinDbg Script Tutorial".

## 6. System Programming [1000906]

The tree's "Windows System Programming" series [1000908-1000917] is this part's main theoretical textbook; the chapters map to security techniques:

| Series chapter | Node | Security application |
|---|---|---|
| Process management | 1000909 | process enumeration/termination/protection |
| Inter-process communication | 1000910 | injection channels, named-pipe malware C2 |
| Memory management | 1000911 | memory patches, shellcode execution in memory |
| Memory mapping | 1000912 | file-mapping injection, shared-memory IPC |
| System services | 1000913 | service-based persistence (a malware staple) |
| Async IO and completion ports | 1000914 | IOCP, high-performance C2/packet capture |
| Structured exception handling | 1000915 | SEH hooks, anti-debugging exception traps |
| DLL basics | 1000916 | hijacking/forwarding, DLL injection vehicles |
| DLL injection and API hooking | 1000917 | **the injection + hook master chapter** |

- Ring3-related [1000918]: everything user mode; Ring0 [1000919]: see §5 drivers; "operating-system writing [1000920]" is the hardcore extension.

## 7. Rootkits and Bootkits [1000861/1000860]

### 7.1 Rootkit Techniques [1000861]

Goal: persistence + hiding (files/processes/network/registry/the driver itself). The knowledge base's "Learning and Research on Rootkits [1000863]", nine sections, is the classic learning path:
1. Kernel hooks (SSDT/IRP); 2. the Ring3→Ring0 gates (call gates/vulnerability escalation); 3. Windows paging (PDE/PTE, directly changing page attributes to hide code); 4. direct hardware access (bypassing the OS); 5. detours modifying function execution paths; 6. stealth (DKOM — Direct Kernel Object Manipulation: unlinking an EPROCESS from ActiveProcessLinks to hide a process); 7. Ring0 calling Ring3 (APC-injecting the user payload); 8. process/thread monitoring (PSNotify callbacks); 9. miscellany.

- **DKOM hidden processes**: walk the `PsActiveProcessHead` list, unlink the target EPROCESS's `ActiveProcessLinks` by pointing BLINK/FLINK at itself — Task Manager/kernel enumeration go blind; detection: cross-comparison (thread counts/handle tables/CSRSS).
- **BIOS rootkits [1000862]**: persist by writing SPI Flash/EFI variables, starting before the OS (confronting modern SecureBoot/CapsuleUpdate).
- **Hiding techniques [1000874]**: filter-based file hiding (§10.2), port hiding (netstat hooking TDI/_INDICATE).

### 7.2 Bootkit [1000860]

Rewriting the MBR/VBR boot chain to take over execution before the OS: MBR rewriting (the TDL4/Gapz approach) → bootmgr verification bypass (early)/UEFI Bootkit (the LoJax approach) → loading kernel-mode code without driver files. The dividing line with rootkits: the Bootkit handles the takeoff (Ring-1/boot stage), the Rootkit handles stealth after landing.

## 8. Optimization Techniques [1000859]

Reverse-engineering relevance: size optimization (shellcode compression, minimal instruction encodings), execution optimization (inline assembly hotspots), the boundary between obfuscation and optimization — optimized code is the hardest to read (O2 inlining + loop unrolling).

## 9. Host Protection Techniques [1000876]

The HIPS perspective, both sides:
- **Attack surface [1000877]**: bypassing host protection (driver-signature loading, injecting into whitisted processes, COM object abuse);
- **Defense surface [1000878]**: hook the four event classes "process creation/driver loading/registry writes/file writes" (kernel callbacks `PsSetCreateProcessNotifyRoutine`, `ObRegisterCallbacks`, minifilter, `CmRegisterCallback`) to intercept and prompt — the architectural skeleton of domestic HIPS (the predecessors of 360/Huorong).

## 10. The Kernel-Object Handling Quartet

### 10.1 Process Handling [1000897]
Protection: handle-right stripping (`ObRegisterCallbacks` peeling PROCESS_VM_WRITE/TERMINATE), EPROCESS flags; hiding [1001457]: DKOM (§7.1), thread-affinity walking.
### 10.2 File Handling [1000900]
File filtering [1000902]: **minifilter** (FltRegisterFilter, pre/post callbacks on IRP_MJ_CREATE/READ) is the modern standard; the old sfilter/IFS route is obsolete but the idea is the same; file deletion [1000901]: forced deletion (rename + delete-on-reboot `MoveFileEx MOVEFILE_DELAY_UNTIL_REBOOT`), releasing locks (walk handles, DuplicateHandle, close).
### 10.3 Registry Handling [1000904]
`CmRegisterCallbackEx` monitors/filters registry operations — the detection point for COM-hijack-style persistence.
### 10.4 Network-Layer Handling [1000905]
TDI (old) → **WFP** (the standard Vista+ filtering platform, callout drivers intercepting connect/recv) → NDIS (the NIC layer, the lowest); packet-capture hooks on `NdisSend`, the kernel stacks of firewall-class software.

## 11. Application Development [1000879]

Not the security main line but frequently borrowed: network programming [1000880] (Winsock/IOCP high-performance servers, dual-use knowledge for DDoS/C2), multimedia [1000881], image recognition [1000884] (captcha-solving/image-matching cheats), UI programming [1000885] (cheat UIs), puzzle games/fun programming [1000882/1000883].

## 12. Security-Tool Development [1000921/1001424]

- Debugger development [1000922]: the Windows debug API loop (`WaitForDebugEvent`/`EXCEPTION_DEBUG_EVENT`); the tree's "debugger writing [1000924]" and "OllyDBG analysis report [1000925]" — read OD's structure to learn commercial debugger design; Linux debuggers [1001196] (the ptrace family).
- Monitoring tools [1000926]: the principles of Filemon/Regmon (see the §10 series), ETW is the modern direction.
- Emulators [1001706]: **Unicorn** [1001707] (the CPU-emulation framework carved out of qemu; write unpacking engines/automated analysis/emulation-based deobfuscation; echoing the static-analysis angr part), **QEMU** [1001717] (full-system emulation, the base of malware sandboxes).
- The Frida framework [1001785]: the modern unified answer to injection + hooking; `Interceptor.attach` is scripted inline hooking; with frida-trace you can map out a sample's API behavior in ten minutes.

## 13. Windows Malware-Development Basics (a Horizontal Summary)

The malicious combinations of the above techniques (with the defense view in sync):
1. **Delivery**: exploit documents/macros (VBA) → PowerShell fileless landing;
2. **Persistence**: services/scheduled tasks/registry Run/COM hijacking/WMI event subscriptions;
3. **Injection**: self-injection or migrating into trusted processes like explorer.exe/svchost.exe (§3);
4. **Hiding**: Rootkits/Bootkits (§7), process hollowing reskins;
5. **C2**: custom protocols over HTTP/DNS, IOCP servers;
6. **Lateral movement**: credential dumps (mimikatz-class: LSASS process injection + minidump).
Defense baseline: ETW + kernel callbacks + memory scanning + enforced signing; corresponding to knowledge-base Part 9, the Malware part (which has its own special topics).

## 14. Representative-Post Search Index (Supplementary Directions)

- Injection: "the eight great DLL injection methods", "APC injection in detail", "reflective injection hand-written", "Process Hollowing in practice", "input-method injection principles"
- Hooks: "a generic inline hook library", "SSDT hooks and restoration", "IRP hook keyboard filtering", "InfinityHook analysis", "VEH hooks"
- Drivers: "WDM drivers from getting started to communication", "IOCTL security vulnerability patterns", "KDMapper principles", "minifilter file filtering"
- Rootkits: "the Rootkit learning and research series" (tree [1000863], nine sections), "DKOM hidden processes", "MBR Bootkit analysis"
- System programming: the "Windows System Programming" series (tree [1000908-1000917]), "DLL injection and API hooking" [1000917]
- Emulators: "Unicorn getting started", "QEMU for malware analysis"
