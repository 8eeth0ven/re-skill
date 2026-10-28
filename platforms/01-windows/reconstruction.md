# Reconstruction (Part 6: Reconstruction 1000732)

> Positioning: the "re-processing" of reverse engineering — change the behavior, not the requirements: patches (file/memory/SMC/DLL hijack/inline) and secondary development (adding features to someone else's program). Knowledge main line: every technique = theoretical basis → mechanism (which system mechanisms it lands on) → example → reverse countermeasure (how the software vendor defends).

## 1. File Patches (Node 1000734)

- **Principle**: locate the key bytes in the file (jz→jmp, comparison values, jump targets), rewrite them directly, recompute the PE checksum (if any).
- **Location methods**: ① the address method (strongly version-bound); ② **signature search**: take several wildcard bytes of instruction context (e.g., `74 1A 68 ?? ?? ?? ?? E8`) to "kill" across versions; ③ string/constant reference backtracking.
- **Forms**: single-file patchers (read → match → write → back up), multi-language/multi-version patch configurations (KeyMake, PatchMaker-class "patch making" tools, Fundamentals node 1000735).
- **Countermeasures (vendor side)**: file-integrity CRC checks (see Protection §5.2), digital signatures, self-restoration at startup (writing back from resources) — hence the derivation of memory patches (§2).
- Examples: knowledge-base 1000736 gathers hands-on file-patching posts for various software; "How to Write File Patches", "A Detailed Explanation of Signature-Code Location Methods", "Locating Button Events with Signature Code", "A Convenient Signature-Code Search Tool", "Writing File Patches and Memory Patches with LPK", "A Super-Simple Signature-Search Algorithm with DEMO", "Memory Signature Search — a Boyer-Moore Implementation".

## 2. Memory Patches (Node 1000738, the Core of This Part)

### 2.1 The Memory-Access Mechanism (Node 1000739)

```
Patch process                     Target process
OpenProcess(PROCESS_VM_WRITE|VM_OPERATION|VM_READ, pid)
WriteProcessMemory(hProc, VA, newBytes, len)   ──►  takes effect at the target VA
(optional) CreateRemoteThread for a remote call/restore
```
- Precondition: obtain the target VA (module base+RVA; under ASLR use CreateToolhelp32Snapshot/Module32First to get the runtime base).
- Weaknesses: timing is hard to control (write too early and initialization overwrites you), cross-privilege (UAC/service processes), self-checks catch the byte changes.
- This is also the underpinning of "patch tools" (early memory patchers/UDP); the old posts "How to Crack Memory-Patch Data Content" and "A Discussion of Memory Patches" discuss the confrontation and capture.

### 2.2 The Debug API Mechanism (Node 1000741) — the "mini-debugger" patch

```
CreateProcess(DEBUG_ONLY_THIS_PROCESS) / DebugActiveProcess
loop WaitForDebugEvent:
  CREATE_PROCESS_DEBUG_EVENT → compute the base from lpImageName/the file header
  EXE/LOAD_DLL events        → record the module-base table
  break at the target moment (entry breakpoint/EXCEPTION_BREAKPOINT)
     WriteProcessMemory applies the patch
     ContinueDebugEvent(DBG_CONTINUE)
```
- Value: controllable timing (wait for the shell to finish decrypting, wait for DLLs to finish loading); nothing hits disk; naturally combines with "breakpoint counting/conditions".
- System foundation: debug events are delivered via the DebugObject (see the Internals/Protection chapters' debugging infrastructure); `EXCEPTION_DEBUG_EVENT` and `OUTPUT_DEBUG_STRING_EVENT` can both serve as synchronization points.
- Finished references: various "debugger-framework patchers" (x64dbg scripts are structurally the same).

### 2.3 The Debug-Register Mechanism (Node 1000742) — hardware-breakpoint patches (effective against self-checks)

```
DR0~DR3: breakpoint linear addresses   DR6: status (which one hit)   DR7: enable/length (b00-b03, LEN, RW)/type
Hit → the processor raises #DB → EXCEPTION_SINGLE_STEP to the debugger (or the program's SEH/VEH)
```
- **The DRx patch flow** (single execution, zero byte modification):
```
1. Set DR0=target VA, DR7 enable RW=00 (execute) LEN=1
2. The execution breakpoint hits (the instruction has not yet executed)
3. Save the original instruction → temporarily write in the patch instruction
4. Clear the DR0 enable, set EFLAGS.TF for single step
5. Single-step through the patch instruction → restore the original instruction, re-arm DR0
   (loop: every time execution reaches here, swap in the patch)
```
- Advantages: **the original code bytes never change**, CRC/self-checks are defeated; unlimited "logical patch points"; low privilege requirements (only SetThreadContext needed).
- Limits: only 4 DRx per thread (3 usable in practice, with DR7-validation/DR3-reserve strategies); multi-threading requires setting the context per thread; the program can detect DRx (Protection §1.2).
- Representative posts: Principles and Use of Debug Registers DR0-DR7; the finished tool Baymax Patch Tools v2.1 — a patcher that "prefers hardware breakpoints, degrading to INT3 when all 3 are used up" (the post notes a fix for the >3-DRx crash bug).

### 2.4 Frida Patches (Node 1001743, the Modern Form)

- `Memory.patchCode(addr, size, cb)` (automatically handles read-only code pages with mprotect + icache refresh), `Interceptor.attach/replace` for logic-level patches, `Module.findBaseAddress` against ASLR;
- JS scripts hot-load — the equivalent of a "runtime patching language", across Windows/macOS/Linux; the countermeasure has likewise become Frida detection (ports/the gum-js-loop thread name/frida-agent in maps).
- Relation to §2.1-2.3: Frida does gum-layer modifications inside the target process, without needing external OpenProcess privileges, but the injection itself can be blocked.

## 3. SMC Patches (Node 1000744) — Against Packed Programs

- **The problem**: a direct file patch modifies ciphertext, and your edit vanishes after runtime decryption; a direct memory patch written too early gets overwritten by the decryption.
- **Route A (timing method)**: wait for the shell to finish decompression/decryption (OEP breakpoint, see Protection §6.2) then apply the memory patch → essentially the timing special case of §2.2/2.3; companion-wise, package the patch logic as a "patch loader" (the Loader starts the target process + waits + writes).
- **Route B (self-modification injection)**: compile the patch logic into a stretch of SMC code injected into the target (code cave/new section), executed by the target process itself after decryption to perform the replacement.
- Knowledge-base instance nodes (1000746-1000753): hands-on SMC patches for **UPX / ASPack / ASProtect / PECompact / Huanying / MoleBox** — the shared skeleton: break on the shell-tail event (e.g., a `VirtualProtect` callback/OEP) → dump and verify → backfill the patch; ASProtect additionally requires getting past stolen code and IAT proxies; MoleBox (multi-file packaging) needs resources released first, then patched.
- Searches: "SMC Tutorial", "An SMC Patch", "A Few SMC Code Samples", "The Base-Address Problem When SMC-Cracking DLLs", "UPX Unpacking and Handling of Appended Data".

## 4. DLL Hijacking (Node 1000754)

- **Theoretical basis** (1000755) — the loader search order (Internals §6.3):

```
Application directory → system directory System32 → 16-bit system directory → Windows directory → current directory → %PATH%
(DLLs on the KnownDLLs list are mapped directly at known paths and do not participate in search hijacking)
```
- **The three technique forms**:
  1. **Missing-DLL form**: portable/legacy programs reference DLLs absent from the system (or undeclared in version manifests); drop a same-named malicious DLL into the application directory and it gets loaded — the entry for patches/injection;
  2. **Proxy-DLL form**: rename the real DLL; the hijacking DLL forwards all exports (bare jmp to the real DLL) + your own patch/hook code at the entry (DllMain) — `#pragma comment(linker, "/export:foo=real.foo")` or `.def` aliases;
  3. **Load-order form**: place a same-named DLL in the application directory (requires the target not in KnownDLLs, no strong SxS manifest binding).
- **Applications**: a memory-patch vehicle (see the post "How to Apply Memory Patches to DLL Files" — precisely LPK hijacking writing memory patches in DllMain), anti-debugging injection, feature extension (§6).
- **Defense view** (vendor side): manifest/`AddDllDirectory` explicit full-path loading, KnownDLLs, signature verification — so newer software is ever harder to hijack; old software/industrial-control/intranet remain the home turf.
- x64 note: the hijacking DLL's bitness must match the target; under WOW64, beware the System32/SysWOW64 directory mirroring trap.

## 5. InLine Patching (Node 1000757)

- **Theoretical basis** (1000758): write a `jmp rel32` (5 bytes) at the target function's head/hot path to divert to your own function (or rewrite the logic inline) — isomorphic with inline hooks; the difference is that a hook emphasizes "intercept and forward", while an inline patch emphasizes "permanently change behavior in place".
- Difference from file patches: what's modified is the memory image (you can wait until after decryption), nothing hits disk; difference from IAT patches: the IAT intercepts only "calls through the import table", while inline intercepts every path (including ones fetched dynamically via GetProcAddress).
- **Example applications** (1000759): changing API behavior (e.g., making `CreateFile` always succeed for a particular name), cracking network-validation clients (patching `send/recv` handling), combined with code caves to hold patch functions.
- Countermeasure: integrity checks + anti-memory checks → use the §2.3 DRx method for byte-free modification.

## 6. Secondary Development (Node 1000760) — the Orthodox Form of Reconstruction: Adding Features to a Program

### 6.1 The Theoretical Foundation (the pediy tutorials, Node 1000763)

The engineering system of a reverse engineer "spicing up" third-party programs — not changing the original code logic, but adding your own space and entry points on the side.

### 6.2 Adding Code Space (Node 1000764)

- **Code caves**: find a stretch in the tail gaps produced by PE section alignment (the 0x00 padding at the end of `.text`) to hold code;
- **Adding a section**: append a section at the file tail (modify NumberOfSections/SizeOfImage, align to FileAlignment/SectionAlignment); roomy, the first choice;
- Alignment and file-offset↔RVA conversion are basic skills (Internals, PE loading).

### 6.3 Function Calls and Self-Location (Nodes 1000765/1000769)

- New code calling system APIs: you cannot rely on the original IAT — resolve dynamically at runtime: **code self-location** (`call $+5/pop eax` to get EIP) → find the kernel32 base from PEB->Ldr → walk the export table to fetch addresses by name/hash (same origin as the Protection chapter's "API self-implementation" — one attacks, one uses);
- Relocations (node 1000768): if the new section contains absolute addresses, they need self-relocation or pure RIP/relative addressing under ASLR (x64 is naturally rip-relative friendly).

### 6.4 Message Loops and Adding Interfaces/Buttons (Nodes 1000767/1000766/1000770)

- **Win32** (1000771): find the target's window procedure (Internals §5, the message mechanism) → hook/subclass the WndProc to intercept new menu commands; or `CreateWindowEx` to add a button to its window + `InsertMenuItem` to add a menu, responding by intercepting `WM_COMMAND`;
- **Delphi** (1000772): at runtime use the VCL (TForm.FindComponent/dynamic Create) to inject controls and events — Delphi's rich RTTI makes secondary development easiest;
- **MFC** (1000773): append to the message-map table ON_COMMAND/edit the resource script to add menus.
- Adding interfaces (1000766): add exported functions/IPC endpoints to the target so external scripts can drive it.

### 6.5 Injection Entries (paired with the Programming chapter's injection nodes)

DLL-hijack (§4) secondary-development form: in the proxy DLL's DllMain, CreateThread starts your own feature thread — the same mechanism as patch-type hijacking, different payload.

### 6.6~6.7 Flow (abbreviated)

Locate resource/string tables → change icons and text (crossing with localization) → add save/export/automation features.

### 6.8 Classic Feature-Enhancement Examples (the 100074-100096 system, 1000774)

- **Windows built-in programs** (1000775): **Minesweeper** (1000776, read the board matrix + auto-flag mines, the first lesson for beginners), **Notepad** (1000777, add tabs/remove the length limit), **Calculator** (1000778, button automation/precision mods), **Task Manager** (1000779, show hidden processes/path columns — incidentally the positive use of "detecting hidden processes"), **Registry Editor enhancements** (1000780, favorites/permissions page);
- **QQ** (1000782, ad removal/multi-instance/message hooks), **WeChat** (1001366), **WeCom** (1001423), Hero Super Player (1000781, an old-post classic), other applications (1000783).
- The common playbook: locate the UI framework → message/control injection (§6.4) → countermeasure points (integrity, anti-injection).

### 6.9 Porting and Extracting Features (Node 1000784)

"Cut" an algorithm/module out of program A for use in B: static relocation-aware extraction (taking the dependency tables along), or DLL-ization wrapping (wrap the exe's exported functions as a DLL, see the loaddll idea, the Debugging chapter's node). Extracting a registration algorithm to make a keygen, or extracting a decoder to build a universal player — both follow this route.

## 7. Representative Posts and Search Index

- Knowledge Base · Patch Technology Directory (the Reconstruction panorama)
- Principles and use of debug registers DR0-DR7
- Baymax Patch Tools v2.1 (the DRx memory patcher)
- How to apply memory patches to DLL files (LPK hijacking)
- How to crack memory-patch data content (the confrontation view)
- A discussion of memory patches

SMC/UPX → "An SMC Patch"; DLL hijacking → "DLL Hijacking Techniques", "Hijacking USER32 via DLL", "A Detailed Analysis of DLL Hijacking", "Building DLL Hijacks Without naked"; Minesweeper → "A Rookie's Guide to Minesweeper Cheat Reversing", "Professional Minesweeper v1.2", "Minesweeper Cheating in Delphi Code"; Notepad → "Notepad XP v2.3", "Modifying the XP Notepad", "Notepad XP V2.78 (VB6 native)"; the pediy tutorial series (a five-parter, i.e., the §6 theoretical foundation).

Related chapters: Internals (the loader/message/SEH foundation), Protection (self-checks and other countermeasures), the Programming chapter's Hook/injection (engineering details, by another author).
