# Windows Kernel Attack-Surface Location (win-vuln · the Attack-Surface Part)

> Positioning: a **kernel attack-surface map** for white-box/gray-box researchers — from an ordinary user-mode process, exactly which paths can deliver data into the kernel, each path's parsing complexity and historical vulnerability density, and the decision basis for "which to hunt first". The mechanism foundation (processes/objects/SSDT/IRP) is in this library's [internals.md](../internals.md); the cross-platform comparison is in `../../../techniques/07-kernel/cross-platform-kernel.md`.
> Entries marked `[✅verified]` were checked online against official sources (2026-10-16); entries marked `[]` are common knowledge/pending re-verification — verify before use.

## 0. Fact-Verification Table (This Round's Online Verification)

| Entry | Verification result | Source |
|---|---|---|
| CVE-2018-8440 | True: ALPC EoP (the Task Scheduler surface), CVSS 7.8 local privilege escalation; **CISA KEV exploited in the wild** (added 2022-03-28, active). I.e., the surface of the 0day SandboxEscaper published 2018-08 | cvelistV5 official JSON `[✅verified]` |
| CVE-2021-1732 | True: Win32k EoP, **CWE-787 out-of-bounds write**; CISA KEV (added 2021-11-03, actively exploited in the wild) — the lesion is the user-mode-callback consistency of the window-class extra-bytes allocation path | cvelistV5 official JSON `[✅verified]` |
| CVE-2024-21338 | True: **appid.sys (the AppLocker driver) exposes an IOCTL with insufficient access control** (NVD's words, "Exposed IOCTL with Insufficient Access Control"), admin→kernel read-write; the PoC **works with HVCI on** (a pure data attack on the token), patched 2024-02; ransomware families used it to hit PPL-protected security processes. Sister vulnerability CVE-2024-38041 (2024-07) | NVD / hakaioffsec PoC `[✅verified]` |
| PPLdump (itm4n) | Mechanism true: a pure user-mode PPL bypass — `DefineDosDevice` forging a Known DLL entry (**PPL once did not validate Known DLL signatures**) + NTFS transactions performing phantom DLL hollowing, executing inside a PPL process; **sealed by the 2022-07 update (19044.1826); the repository is archived** | GitHub itm4n/PPLdump `[✅verified]` |
| The Credential Guard bypass lineage | True and active: Adam Chester's "Pass-the-Challenge" (2022-12, attacking the LSASS↔LSAIso challenge handshake); itm4n's "Revisiting a CG Bypass" (2022-05, patching two LSASS globals — LSASS trusts handles originating from LSAIso); SpecterOps' "Catching Credential Guard Off Guard" (2025-10); incendium (2024-04); MirrorDump (using DuplicateHandle on LSASS) | the various blogs `[✅verified]` |
| The BitLocker attack lineage | True: Wack0 maintains the bitlocker-attacks list (as of 2026-06), including bitpixie CVE-2023-21563 (PXE soft reboot not clearing keys, dormant 17+ years), push button decrypt CVE-2022-41099 (unencrypted WinRE partition), CrashXTS CVE-2025-21210 (AES-XTS targeted corruption of the SYSTEM hive → hiberfil written in plaintext), break out in hives CVE-2024-20666/-21213, YellowKey CVE-2026-45585 (NTFS transaction log across volumes), bitskrieg (2026-06 **unfixed**: WinRE's EMS serial port opening a SYSTEM shell) | github.com/Wack0/bitlocker-attacks `[✅verified]` |
| ARSO | True: after reboot, automatic login via the Autologon mechanism followed by immediate lock-screen; credentials **persisted in the registry as an LSA secret** for Winlogon to use at boot; the hardening item DisableAutomaticRestartSignOn | Microsoft Learn official docs `[✅verified]` |
| TPM sniffing to grab BitLocker keys | True: Denis Andzakovic (Pulse Security, 2019) hung a logic analyzer on the TPM's LPC/SPI bus and directly captured the plaintext VMK under default configuration; later faulTPM (AMD fTPM fault injection, 2023-04) | pulsesecurity.co.nz `[✅verified]` |
| The RPC enumeration toolchain | True: RpcView (open source, enumerates + decompiles RPC services), Trail of Bits' RpcInvestigator (2023, based on NtApiDotNet, can enumerate all active ALPC RPC servers), NtObjectManager's `Get-RpcServer`, RpcMon, itm4n's RPC fuzzing tutorials | GitHub/official blogs `[✅verified]` |
| Mandt's win32k callback research | True: Tarjei Mandt's "Kernel Attacks through User-Mode Callbacks" (BlackHat USA 2011) is the foundational paper on win32k user-mode-callback UAF, directly giving rise to the MS11-034 batch of fixes | BlackHat official PDF `[✅verified]` |
| kAFL | True: hardware-assisted kernel fuzzing (Intel PT coverage feedback + snapshot rollback, USENIX Security 2017), usable with Windows guests | USENIX paper PDF `[✅verified]` |
| j00ru syscall tables | j00ru.vrdl.nz maintains the NT syscall tables for every version of x86/x64/ARM — widely documented common knowledge; the site failed to connect directly this time, fetch it yourself before use | `[]` |
| The CLFS-family CVEs (24521/37969/28252) | clfs.sys parsing .blf logs with UAF/overflow; several exploited in the wild in 2022-2023 (used by Nokoyawa ransomware) — common knowledge (abundant MSRC/CrowdStrike advisories), not verified item by item | `[]` |
| CVE-2015-2546 / CVE-2018-8453 / CVE-2022-21882 | The win32k in-the-wild exploitation trio — common knowledge (vendor ITW advisories), not verified item by item | `[]` |
| PrintNightmare CVE-2021-34527 | The print spooler service's RPC-surface RCE/EoP, in the wild in 2021 — common knowledge | `[]` |

## 1. The Attack-Surface Overview Map

### 1.1 The Panorama: The Kernel Entries an Ordinary User Process Can Touch

```
User process (ring3, low integrity/ordinary token)
   │
   ├─① NT syscall ────────── ntdll!Zw* → nt!NtXxx (SSDT/KeServiceDescriptorTable)
   │      The pure core surface: process/thread/memory/handle/registry/file — the strictest validation, the oldest code
   │
   ├─② Win32k syscall ────── user32!NtUserXxx / gdi32!NtGdiXxx
   │      → KeServiceDescriptorTableShadow → win32k.sys/win32kbase.sys/win32kfull.sys
   │      A GUI-era legacy + high complexity + masses of kernel↔user callbacks = historically the most productive
   │
   ├─③ ALPC ──────────────── the ntdll RPC runtime → \RPC Control\* named ports
   │      The local message surface of system services (Task Scheduler/Spooler/RPCSS…)
   │
   ├─④ RPC/DCOM ──────────── the upper layer of ③ (ncalrpc/ncacn_*); endpoint + interface + method, three addressing layers
   │
   ├─⑤ IOCTL ─────────────── CreateFile(\\Device\\* / \\??\\*) + DeviceIoControl
   │      → nt!NtDeviceIoControlFile → IRP → the driver's dispatch routine (including fake BYOVD surfaces)
   │
   ├─⑥ Callback-registration APIs ── SetWindowsHookEx/event hooks/input injection → kernel reverse calls
   │      (win32k callbacks listed separately in §2; kernel callback registration APIs in §4 — the latter need driver identity)
   │
   ├─⑦ Object-manager extensions ── namespaces/DOS devices/symbolic links/private namespaces
   │      ObRegisterCallbacks (signature required); symbolic-link/transaction abuse (the Forshaw research line)
   │
   ├─⑧ ETW ───────────────── registering providers/writing events → nt!Etw*; mostly a detection/bypass surface rather than a memory-corruption surface
   │
   └─⑨ Registry virtualization/UAC virtualization ── low-privilege write redirection; ACL misconfiguration/hijack surfaces (many logic bugs, few memory bugs)
```

### 1.2 The Horizontal Comparison of the Nine Surfaces (Entry Functions | Complexity | Historical Vulnerability Density | Audit Difficulty)

| # | Surface | Representative entry functions | Parsing complexity | Historical vulnerability density | Audit difficulty |
|---|---|---|---|---|---|
| ① | NT syscall | `NtQuerySystemInformation`/`NtSetInformationThread` and hundreds more | low-medium (mostly argument validation) | medium: an old surface, many Info-class bugs (`SystemHandleInformation` leaking handles etc.); logic bugs (the `PreviousMode` class) occasional | medium: no source but complete symbols + years of docs, false positives easy; **pick obscure Info classes and races** |
| ② | Win32k syscall | `NtUserCreateWindowEx`/`NtUserMessageCall`/`NtUserSetWindowsHookEx`/`NtGdi*`, a thousand-plus | **extremely high** (nested structures + callbacks + object lifetimes) | **extremely high**: an MSRC regular, the in-the-wild favorite (several in KEV, see §2) | high: full symbols (tag* structures) but control flow jumps into user mode via callbacks, static tracking breaks |
| ③ | ALPC | `NtAlpcSendWaitReceivePort` (usually reached via the RPC runtime) | high (message attributes/handle passing/views/anonymous tokens) | medium-high: the Task Scheduler UAF (CVE-2018-8440 `[✅verified]`) etc.; the endpoint = an amplifier of server-side code quality | medium-high: endpoints enumerable (RpcView/RpcInvestigator `[✅verified]`), but server logic is scattered across service DLLs |
| ④ | RPC/DCOM | `RpcStringBindingCompose`→`NdrClientCall*` | high (IDL stubs + context handles + serialization) | high: PrintNightmare etc.; thousands of interfaces, **each service brings its own parser** | medium: IDL/symbols restore prototypes; automation friendly (NtApiDotNet generating clients) |
| ⑤ | IOCTL/drivers | `DeviceIoControl` | low (command code + buffer) — but **driver quality variance is huge** | extremely high (third-party/AV/peripheral drivers); Microsoft's own surfaces concentrate in clfs.sys (CLFS) and the like | low: one dispatch function per driver, straight into IDA; METHOD_NEITHER is a giveaway |
| ⑥ | GUI callbacks (win32k reverse calls) | `KeUserModeCallback`→`ntdll!KiUserCallbackDispatch`→user32's `gapfnScSend` table | extremely high (reentrancy + locks + lifetimes) | extremely high (same body as ②: Mandt 2011 `[✅verified]` founded it, the MS11-034 batch fix) | high: UAF-class needs manual lifetime reasoning; tooling weak |
| ⑦ | Object-manager extensions | `NtCreateSymbolicLinkObject`/`NtCreatePrivateNamespace` | low | low-medium: mostly logic bugs (symlink hijacks/permission misconfigurations) rather than memory bugs | low: a small surface, mostly covered by the Forshaw research line; just find the uncovered corners |
| ⑧ | ETW | `EtwEventRegister`/`NtTraceControl` | medium | low (memory corruption rare); **the detection-bypass/information-warfare surface** (silent providers, forged events) is high | medium: locating bypasses > finding bugs |
| ⑨ | Registry virtualization | writing `HKLM\Software\Classes` etc. triggers redirection | low | low-medium: ACL misconfigurations (SeriousSAM-class hive ACLs) | low: mostly logic auditing |

**The horizontal-comparison conclusions** (memorize before expanding):
1. **Density ordering**: ②⑥ (win32k's two faces of one body) > ⑤ (the driver-variance dividend) > ③④ (the server-code-quality dividend) > ① > ⑦⑧⑨.
2. **Threshold ordering** (eat the low-threshold first): ⑤ IOCTL (a single-driver closed loop, no callback jumps) < ③④ RPC/ALPC (auto-generatable clients) < ① syscall (an old surface, compete on obscurity) < ②⑥ win32k (must chew structures and lifetimes — and the biggest payoff).
3. **In-the-wild usage**: ②⑤ are the most used in the wild (the EoP standard of ransomware/APT), ③④ often serve as "fileless local privilege escalation".

## 2. The Win32k Attack Surface (the Classic High Yield)

### 2.1 The Surface's Composition

```
user32.dll / gdi32.dll / win32u.dll (a thin user-mode layer since Win10)
   │ NtUserXxx / NtGdiXxx (the win32u!NtUser* stubs)
   ▼
KeServiceDescriptorTableShadow (the second SSDT, mounted only for GUI threads)
   │ Win10+ x64 actually dispatches via win32k!Win32kApiSetTable `[]` (version-dependent, verify dynamically)
   ▼
win32k.sys (the dispatch shell) → win32kbase.sys (the core) + win32kfull.sys (full functionality)
   ├─ window/class/menu/desktop/window-station objects (tagWND/tagCLS/tagMENU/tagDESKTOP/tagWINDOWSTATION)
   ├─ per-thread tagTHREADINFO, per-window message queue tagQ
   └─ the GDI object pool: DCE/DC/RGN/PALETTE/BITMAP (textbook material for pool spraying)
```

Essentials:
- **Entry count crushes**: a thousand-plus win32k syscalls (far beyond nt's several hundred), and many accept **nested/variable-length/user-buffer pointers** (RECT*/CREATESTRUCT/menu templates/logical fonts……) — the highest parsing complexity in the field.
- **Symbol friendly**: public symbols hand you the complete `tagTHREADINFO`, `tagWND`, `tagDESKTOP` structures — white-box auditing need not reverse the structs; `dt win32kbase!tagWND` and you're off.
- **The attack precondition**: the calling thread must be bound to a desktop (any GUI process/or a CSRSS attach satisfies it; windowless service processes can also take the `NtUserXxx` route — don't think of the win32k surface as "must have UI").

### 2.2 User-Mode Callbacks (the UAF Master Engine)

The mechanism (Mandt 2011 `[✅verified]`):
```
win32k kernel side (function names with the xxx prefix = contain callback paths)
   │ KeUserModeCallback(index, arguments)
   ▼
ntdll!KiUserCallbackDispatch
   ▼
user32!gapfnScSend[index]   ← the user-mode dispatch table (FI_xxx callback numbers)
   │ executes: window procedures / hooks / ClientCallbacks (allocating window-class extra bytes, etc.)
   ▼
User code can use this to: modify callback-related globals, destroy objects, re-enter win32k
   ▼
After the kernel returns from the callback, it keeps using the "pre-callback" object pointers/locks/counts → UAF/double frees/invalid locks
```
- Three high-frequency callback classes: **window hooks** (`SetWindowsHookEx`; WH_* invoked in the target process by kernel-driven callbacks), **event hooks** (SetWinEventHook, cross-process notification), and **the xxxClient\* series** (e.g., `xxxClientAllocWindowClassExtraBytes` — the lesion of CVE-2021-1732 `[✅verified]`: the callback return value inconsistent with the kernel's bookkeeping → out-of-bounds write, CWE-787).
- The audit mantra: **for any function with the `xxx` prefix, check whether it still dares to directly use the pre-callback pointer after `KeUserModeCallback` returns**. Mandt's methodology (per object type, checking "whether each callback point re-validates") holds to this day — Unit42's 2023 "Inside Win32k Exploitation" series is still the modern retrospective of this line `[✅verified]`.

### 2.3 Object Lifetimes (tagWND Is the Center)

| Object | Lifetime essentials | Historical lesions |
|---|---|---|
| tagWND (the kernel-side window object; the user-side HWND/`CWnd` is just a handle wrapper) | creation (`xxxCreateWindowEx`) → lock count → destroy only marks zombie → delayed release; callback/message paths often reference across locks | CVE-2021-1732 (extra-bytes consistency) `[✅verified]`; MS15-061 UAF `[✅verified]` (the NCC retrospective) |
| tagCLS / window-class extra bytes | cbWndExtra declared by the user, allocated via callbacks — **double-entry bookkeeping** on both sides, naturally fissure-prone | same 1732 |
| tagMENU / menus/popup menus | `NtUserMenuItemFromPoint`/popup message loops callback-dense | a regular in all kinds of POCs |
| tagDESKTOP / tagWINDOWSTATION | the desktop heap (a section shared with user mode) has a long history; the switchover window of `SetThreadDesktop` | the older generation of heap-overflow surfaces |
| GDI pool objects (PALETTE/RGN/BITMAP) | pool-spray material; the palette-index path still had an EoP in 2019 (ZDI) `[✅verified]` | CVE-2012-2553 (VDM UAF, j00ru) `[✅verified]` |

### 2.4 The Location Method (How to Lay This Surface Out Systematically)

1. **Syscall-table traversal**: in WinDbg `dds win32kbase!Win32kApiSetTable` (or parse the shadow SSDT) to get all NtUser*/NtGdi* entries; against j00ru's syscall tables (`[]` common knowledge) mark the version-new additions (see §6).
2. **Callback-table traversal**: user32's `gapfnScSend` (FI_* indices) — item by item, see which callback numbers the kernel side uses most heavily — these are the anchors of the "reentrancy attack surface".
3. **Shard the audit by object type**: use validation functions like `ValidateHwnd`/`ValidateHmenu` as xref sources; chase whether "validate → use" for each object has a callback/wait point wedged in between.
4. **In-the-wild sample library**: the win32k entries in KEV (CVE-2015-2546, CVE-2018-8453, CVE-2021-1732 `[✅verified]`, CVE-2022-21882 `[]`) — their patch diffs are the "checkup templates" for the same class of bugs: whatever class of validation the patch changed, re-scan the same-class objects for stragglers.

Hands-on (WinDbg, inside a GUI-process context):

```
ln nt!KeServiceDescriptorTableShadow     ← the shadow table mounts only when used by GUI threads
dds poi(win32kbase!Win32kApiSetTable) L200   ← the Win10+ x64 dispatch table, item by item (version-dependent `[]`)
dt win32kbase!tagWND poi(0)               ← tag* structures come entirely from public symbols; no reversing needed
ub win32kbase!ValidateHwnd                ← the validation entry's xrefs are the source of object auditing
```

## 3. The ALPC/RPC Attack Surface

### 3.1 The Surface's Composition and Enumeration

```
RPC client (auto-generated NDR stubs)
   │ ncalrpc (local) goes over ALPC
   ▼
\RPC Control\* (the ALPC endpoints under the object directory; the RPC endpoint mapper registers here)
   ▼
The server process (the service DLLs inside svchost hosts: schedsvc.dll / spoolsv.exe / rpcss…)
   │ parsing: endpoint → interface UUID+version → method number → NDR deserialization → business logic
   ▼
The parsing layer (the NDR engine) + the service layer (hand-written logic) — both layers can be wrong
```

- **The enumeration three-piece** (`[✅verified]`): RpcView (graphical enumeration + decompilation of running RPC servers), Trail of Bits' RpcInvestigator (the NtApiDotNet kernel; enumerates all active ALPC RPC servers, mapping interface methods to endpoint processes), NtObjectManager's `Get-RpcServer` (PowerShell batch export of interface/method prototypes).
- Audit order advice: **group by service host first** (one svchost process = one service group = one port group); prioritize "high-privilege services + complex IDL + unauthenticated clients" combinations.
- The bare ALPC surface (going `NtAlpcConnectPort` directly without the RPC runtime) is niche but exists: message attributes, ALPC handle passing, `ALPC_SECURITY_ATTR`/anonymous tokens — historically a source of UAF/permission misconfigurations (CVE-2018-8440 is an ALPC surface `[✅verified]`).

### 3.2 Historical Patterns

| Pattern | Example |
|---|---|
| Server-side UAF (message-driven object lifetimes) | the Task Scheduler ALPC UAF (CVE-2018-8440, the SandboxEscaper 0day, CISA KEV `[✅verified]`) |
| High-privilege services exposing local RPC write primitives | PrintNightmare (CVE-2021-34527, the spooler RPC surface, in the wild 2021 `[]` common knowledge) |
| Service-configuration/DCOM combination logic bugs | the UPnP service EoP (CVE-2019-1405 with 1322 `[]` common knowledge) |
| Serialization/context-handle misuse | various NDR compatibility gaps (interface versions not validated, context handles crossing interfaces) |

### 3.3 Tools and Fuzzing

- Enumeration/monitoring: RpcView, RpcInvestigator, RpcMon (real-time RPC call monitoring) `[✅verified]`.
- Fuzzing: NtApiDotNet can **generate C# client stubs** straight from runtime interfaces — itm4n's RPC fuzzing route (enumerate → generate clients → feed malformed arguments to every method) `[✅verified]`; for method-level fuzzing prefer "pointer/array/nested-structure/SIZE_T length" arguments, skipping pure enumeration-forwarding methods (the §6 complexity principle).

## 4. Callbacks and Notifications (the Kernel Callback-Registration Surface)

### 4.1 Locating the Surface

Registration APIs (kernel side, requiring driver identity — so this surface is **the contact zone of "drivers vs the system"**):

| Registration API | Trigger moment | Typical consumers |
|---|---|---|
| `PsSetCreateProcessNotifyRoutine(Ex)` | process create/exit | EDR/AV/monitoring drivers |
| `PsSetLoadImageNotifyRoutine` | module mapping | same (DLL/driver-load detection) |
| `PsSetCreateThreadNotifyRoutine` | thread create/exit | monitoring |
| `CmRegisterCallback(Ex)` | registry operations | AV/compliance/privacy tools |
| `ObRegisterCallbacks` | process/thread/desktop handle operations (a signed driver required) | EDR (the handle stripping that protects lsass etc.) |
| `ExRegisterExtension`/`KeRegisterBugCheckReasonCallback` etc. | extension points/crash paths | miscellany (obscure but often unaudited) |

### 4.2 The Audit Perspective (Three Different "Digs")

1. **Third-party callbacks = untrusted code running in the kernel**: the callback routines registered by AV/EDR execute in kernel mode on **every process creation/registry access**, parsing an "attacker-controllable scene" (process names/image paths/command lines/registry paths). If a callback contains user-buffer copies, path parsing, pool allocations — that's a kernel bug the attacker can trigger on demand. **When auditing EDR drivers, look at the callback routines first, not the IRP dispatch** (both trigger frequency and input controllability are higher).
2. **The bypass surface (attacker's view)**: the callback registration tables themselves are kernel data (e.g., the `PspCreateProcessNotifyRoutine` array) — a data-only attack that removes callbacks blinds the EDR (bugs like CVE-2024-21338, "pure data rewriting + still usable under HVCI", exist precisely for this `[✅verified]`).
3. **The detection surface (defender's view)**: enumerate all registered callbacks in the system (walk the above arrays) and compare against vendor whitelists — finding nameless/extra callbacks is rootkit evidence. Forensics frameworks like Volatility have the corresponding plugin ideas.

## 5. BitLocker / ARSO / the Security-Subsystem Surface

### 5.1 The BitLocker Component Surface

```
The pre-boot environment: bootmgr → winload (FvebUnsealCallback unseals the VMK)
   │ TPM (PCR-sealed VMK) / PIN / USB / recovery password —— the protector matrix
   ▼
The OS volume: fvevol.sys (the volume filter driver, holding the FVEK for full-volume AES-XTS encryption)
   + volsnap.sys (volume shadow copies, a task-named component; the snapshot path is another historical bug line)
   ▼
Runtime: the FVEK resident in memory (the volume mounted = the decryption key in RAM)
```

- **The key hierarchy**: recovery password/TPM → unseals the VMK (Volume Master Key) → the VMK decrypts the FVEK (the full-volume encryption key). The attack-surface three questions: where is the VMK unsealed (the pre-boot environment), where does the FVEK reside (kernel memory), who is responsible for wiping (soft-reboot/hibernation/crash paths).
- **The public-enemy pattern — "not wiped clean"**: bitpixie (CVE-2023-21563): a PXE soft reboot not clearing keys, a bug **dormant for over 17 years**; CrashXTS (CVE-2025-21210): AES-XTS ciphertext properties enabling targeted corruption of the SYSTEM hive → the system writes hiberfil.sys in plaintext; push button decrypt (CVE-2022-41099): the WinRE partition is often unencrypted; interrupting the reset flow gets a SYSTEM shell to remove protectors `[✅verified]` (note: ordinary monthly cumulative updates do not automatically patch WinRE — PatchWinREScript must be run separately).
- **The hardware surface**: TPM sniffing (grabbing the VMK off the LPC/SPI bus, Andzakovic 2019 `[✅verified]`), the Intel DCI debugger (2023-03), fTPM fault injection (faulTPM, 2023-04), changing the UEFI variable disabling the IOMMU then PCI DMA (2026-03) `[✅verified]`.
- **The latest entries** (2026-05/06, all `[✅verified]`): YellowKey (CVE-2026-45585, the NTFS transaction log containing full NT paths → deleting winpeshl.ini across volumes for a SYSTEM shell); ram leak (the boot environment not restricting ramdisk sources — a hiberfil.sys inside a BitLocker partition can be loaded into memory, **unfixed**); bitskrieg (WinRE's EMS serial management console can open a SYSTEM shell, **unfixed**).
- **White-box landing points**: fvevol.sys/volsnap.sys have symbols on the symbol server; the boot-environment components (bootmgr/winload) have none — rely on strings + structural pattern recognition. The attack list is maintained directly at `github.com/Wack0/bitlocker-attacks`; read it before digging new holes to avoid collisions `[✅verified]`.

### 5.2 ARSO (Automatic Restart Sign-On)

- Mechanism `[✅verified]`: Windows Update triggers a reboot → the user's credentials **persisted in the registry as an LSA secret** → at boot Winlogon auto-logs-in via the Autologon mechanism → immediately locks the screen (the user returns unaware). On by default for "exclusive users"; Server/multi-user scenarios controlled by policy.
- Attack surface: ① with SYSTEM/disk access, the LSA secret can be extracted offline (equivalent to the user's **plaintext password**, usable for lateral movement — more valuable than a hash); ② at the auto-login instant there is a **window of an unlocked logged-on session**; ③ admins unaware ARSO is running → the key escrow remains available "after the reboot".
- The hardening counterpart (the "ought" when hunting bugs): the `DisableAutomaticRestartSignOn` policy/registry value, and the ARSO entries in the event logs — when auditing the client-configuration surface, check these two first.

### 5.3 The Credential Guard / LSA Protection (PPL) Bypass Surface

- Architecture: LSA Protection (RunAsPPL, PPL processes) blocks user-mode dumps; Credential Guard **isolates credentials into VTL1's LSAIso.exe** (VBS virtual secure mode) — even a pierced VTL0 kernel cannot touch VTL1 credentials.
- **The bypass lineage (three families by idea, all `[✅verified]`)**:
  1. User-mode logic bypass: PPLdump — Known DLLs not signature-checked + NTFS-transaction phantom hollowing (**sealed 2022-07**); itm4n 2022-05 — patching two LSASS globals, exploiting "LSASS trusts handles originating from LSAIso".
  2. Protocol-side bypass: Pass-the-Challenge (Adam Chester 2022-12) — not attacking VBS but the LSASS↔LSAIso challenge handshake itself; MirrorDump — using `DuplicateHandle` on LSASS to borrow a legitimate handle for duplication.
  3. Kernel-side bypass: CVE-2024-21338 (appid.sys) admin→kernel pure data attack, directly flipping protection bits to kill PPL processes — **HVCI on doesn't stop it**; in 2025-10 SpecterOps disclosed a new chain.
- **Audit implications**: when assessing the "bypass surface", sweep by three families — the configuration family (are PPL/CG actually enabled, is LSAIso running), the protocol family (the isolation channel's own trust assumptions), the data family (pure data targets like EPROCESS protection bits).

### 5.4 VBS/HVCI's Constraints on Kernel Bugs (Which Primitives Still Work)

| Primitive | Without HVCI | With HVCI | Notes |
|---|---|---|---|
| ROP/kernel-executing user-supplied code | yes | **no** (only already-signed pages executable) | HVCI = kernel-mode CFG + W^X |
| Pure-data token rewriting (stealing SYSTEM) | yes | **yes** | the CVE-2024-21338 PoC measured usable under HVCI `[✅verified]` — pure data attacks are not HVCI's business |
| `KTHREAD->PreviousMode` rewriting amplification | yes | yes (some structures KDP-protected) `[]` | mostly the data plane, but tightening year by year |
| BYOVD (vulnerable signed drivers) | yes | technically yes, blocked by Microsoft's vulnerable-driver blocklist (WDAC) | the blocklist lags and has coverage gaps |
| VTL1 (the CG key zone) read/write | — | **no** (needs an independent Hyper-V bug) | VTL0 kernel R/W ≠ VTL1 access |
| Pool/object UAF occupancy exploitation | yes | yes (occupancy objects swapped for legitimate signed objects containing only function pointers are harder) | function-pointer targets restricted; data-only finishes are the mainstream |

Conclusion: **HVCI kills "code execution", not "privilege escalation"** — audit/exploitation finishes tilt toward data-only (tokens, protection bits, callback arrays), which is already the mainstream in 2024-2026 in-the-wild samples.

## 6. New-Surface Hunting (Version Diffs and Fuzzing Entry Points)

### 6.1 Tracking New Syscalls / Interfaces

1. **Version-diff tables**: j00ru's syscall tables (per-version NT syscall tables `[]` common knowledge) + a self-built win32k table diff (`Win32kApiSetTable` compared item by item across two versions) → circle the **new NtUser\*/NtGdi\***.
2. **New interfaces = new features shipping**: new syscalls usually serve new UI features (compositor/input/new controls); first-version code-quality variance is large — "the first-patch year of a new interface's debut" is the golden window.
3. **Undocumented-interface restoration**: the Microsoft symbol server's PDBs (`dt`/`x` restore prototypes directly) + phnt (the Process Hacker native headers covering many semi-public NT APIs `[]` common knowledge) + leaked headers/ReactOS/wine as semantic references — cross the three and the prototype is 95% restored.
4. **Driver-surface diff**: \\Device nodes added/renamed in new versions (WinObj across two versions) and new service binaries — Microsoft's own new components (like CLFS back in the day) are often untilled ground: clfs.sys's .blf parsing bugs fired consecutively in 2022-2023 and went in the wild (`[]` common knowledge); "a complex user-creatable file format + kernel parsing" is the new-surface signal.

### 6.2 Choosing Fuzzing Entry Points (Complex Parsing > Simple Forwarding)

| Priority | Traits | Examples |
|---|---|---|
| ★★★ | nested/variable-length structures, length fields decoupled from the actual buffer, SIZE_T/USHORT mixing | menu templates, LOGFONT/ENUMLOGFONTEX, DEVMODE, serialized blobs |
| ★★★ | kernel parsing of user-controllable file formats | CLFS .blf, fonts (the atmfd era), graphics metafiles |
| ★★ | cross-layer forwarding with inconsistent validation on the two sides | the WOW64 boundary, ALPC attributes |
| ★ | pure forwarding/pure enumeration (get/set flag bits) | most simple NtQuery*Information items |

- Framework selection: the **kAFL/NYX family** (Intel PT hardware coverage + snapshot rollback, full system, Windows guests can run `[✅verified]`); bare user-mode driver-IOCTL fuzzing with ioctlbf-class brute enumerators `[]` common knowledge; the **Bochspwn idea** (j00ru: instrumented emulators watching "the kernel using uninitialized stack/pool") suits information-leak hunting.
- RPC-surface fuzzing: after RpcInvestigator/NtApiDotNet generate clients, run per §3.3.
- The universal discipline: first statically circle "the 20 highest-complexity entries" and throw all fuzzing resources at those 20 — never spread effort evenly across the whole table.

### 6.3 The Version-Diff Pipeline (Turning "New Surfaces" Into a List)

```
1. Take two versions' binaries: win32kbase.sys / win32kfull.sys / ntoskrnl.exe (+ PDBs)
2. Table diff: parse the shadow SSDT or Win32kApiSetTable → added/removed/re-addressed entries
3. Function level: the added entries' target functions → IDA symbol names → shard by object type per NtUserXxx semantics
4. Interface semantics: phnt/ReactOS for prototypes; not found = an undocumented new interface, reverse the arguments manually
5. Output: the new-interface list (entry/argument complexity/low-privilege reachability) → queue for fuzzing per the §6.2 priorities
```

- Run one round per major version per year (24H2/25H2…); focus on new interfaces that "ship with callbacks/nested structures from day one".

## 7. The Attack-Surface → Vulnerability-Density Mapping (Which to Hunt First)

| Surface | Representative CVEs ×3 | Entry difficulty | Suggested tools | One-sentence advice |
|---|---|---|---|---|
| ⑤ IOCTL/drivers (incl. BYOVD) | CVE-2024-21338 (appid.sys, `[✅verified]`), CVE-2022-24521 (CLFS `[]`), CVE-2023-28252 (CLFS `[]`) | ★ lowest | IDA + WinDbg dual-machine, ioctlbf, the symbol server | First stop: pick Microsoft drivers with built-in complex parsing (the CLFS class) + the full sweep of third-party drivers |
| ②⑥ Win32k (syscalls + callbacks) | CVE-2021-1732 `[✅verified]`, CVE-2018-8453 `[]`, CVE-2015-2546 `[]` | ★★★ high | symbol PDBs (tag* structures), Mandt's methodology, the Unit42 series, a self-built syscall diff | Second stop (also the highest ceiling): chew callback lifetimes sharded by object type |
| ③④ ALPC/RPC | CVE-2018-8440 `[✅verified]`, CVE-2021-34527 (PrintNightmare `[]`), CVE-2019-1405 `[]` | ★★ medium | RpcView, RpcInvestigator, NtObjectManager, RpcMon | The most automation-friendly: the enumerate → generate-clients → method-level-fuzz pipeline |
| BitLocker/pre-boot | CVE-2023-21563, CVE-2022-41099, CVE-2025-21210 (all `[✅verified]`, the Wack0 list) | ★★ medium (needs a boot-debugging environment) | Wack0/bitlocker-attacks, UEFI/boot debugging, logic analyzers (the hardware surface) | Obscure and high-value: physical-access scenarios land steadily in MSRC; read the list first to avoid collisions |
| ① NT syscall | Info-leak class (the SystemHandleInformation family `[]`), PreviousMode logic class | ★★ medium | j00ru's syscall tables, the WDK, WinDbg | Compete on obscure Info classes and races; don't crash into the main road |
| ④ kernel callbacks/⑦ object manager/⑧ ETW/⑨ virtualization | mostly logic bugs/bypasses (MirrorDump `[✅verified]`, SeriousSAM-class hive ACLs `[]`) | ★★ medium | Volatility, ProcMon, ACL auditing | Logic bugs + bypass surfaces; highest payoff when paired with EDR auditing |

**The decision tree**:
```
Time to lay it all out? → ⑤ eats the dividend first → ③④ build the automation pipeline → ②⑥ the long-line main assault
Only quick wins? → ⑤ third-party drivers + ③④ high-privilege services
Auditing EDR/security products? → the §4 callback surface + the §5.3 three bypass families
The target scenario includes physical access/offline disks? → the §5 BitLocker/ARSO full set
Have boot/virtualization debugging capability? → the §5.1 pre-boot environment (current unfixed entries: ram leak, bitskrieg `[✅verified]`)
```

## 8. Search Index and Relations

- On-site: the mechanism foundation [internals.md](../internals.md) (SSDT/object manager/message mechanism); "Cross-Platform Kernel Quick Reference" §4 (the Windows BYOVD live library, escalation-finish primitives, the kernel-debugging horizontal review); the later win-vuln per-bug-class specials.
- Key external resources (`[✅verified]` means verified reachable/true this round):
  - Wack0/bitlocker-attacks (the authoritative BitLocker attack list) `[✅verified]`
  - Trail of Bits' RpcInvestigator / NtApiDotNet `[✅verified]`
  - itm4n's blog (PPLdump, the CVE-2022-41099 analysis, RPC fuzzing) `[✅verified]`
  - Mandt's "Kernel Attacks through User-Mode Callbacks" BH USA 2011 PDF `[✅verified]`
  - research.ifcr.dk's "Pass-the-Challenge" `[✅verified]`; SpecterOps' "Catching Credential Guard Off Guard" `[✅verified]`
  - j00ru.vrdl.nz syscall tables `[]` (common knowledge; the site failed to connect directly — fetch it yourself)
- On-site search expressions: `win32k UAF 回调` / `ALPC Task Scheduler` / `appid.sys HVCI` / `ARSO LSA secret` / `WinRE BitLocker` → the respective sections of this document.
