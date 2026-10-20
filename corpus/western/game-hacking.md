# Western corpus · Game hacking (UnknownCheats & friends)

> Positioning: techniques our Chinese-corpus library lacks — Windows game internals, D3D hooking, kernel mapping. Authorized-research framing; this file inherits the boundaries of techniques/15-anti-cheat/anti-cheat-countermeasures.md (CTF / own-game testing / defender-side attack-surface research; no ready-made in-the-wild bypasses, no cheat distribution). Deduped against that file (engine architecture, ObRegisterCallbacks, DMA honeypots, VM-detection root causes live there) and 14-game-frameworks/unity-il2cpp.md (mobile Unity chain lives there; nothing below repeats them). Source state, Oct 2026: wiki.unknowncheats.me is dead (NXDOMAIN); the forum is Cloudflare-gated (plain WebFetch/curl get 403, "Just a moment"); content was mined via a reader-type fetch service against section indexes and `printthread.php?t=<id>` full-thread views, with search snippets filling gaps.

## D3D11/D3D12 hooking and overlay rendering

### Universal D3D11 hook (src: unknowncheats)
Author: evolution536 (2013; still the canonical skeleton every later hook builds on)
- Core trick: you never need symbols or SDK knowledge of the game. Create a throwaway D3D11 device + swapchain on the game's window, read the returned objects' VTables, take function pointers by index, and inline-detour those addresses — the game's real objects share the same VTable (same module, same interface).
- Load-bearing skeleton:
  - Window handle: `GetForegroundWindow()`, NOT `FindWindowA` — unicode titles like `Battlefield 3™` break the ANSI match; the handle only has to be valid for the dummy creation call.
  - `D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0, NULL, 0, D3D11_SDK_VERSION, &scd, &pSwapChain, &pDevice, NULL, &pContext)`.
  - Indexes that matter: `pSwapChainVtable[8]` = `Present`; `pDeviceContextVTable[12]` = `DrawIndexed`; `[50]` = `ClearRenderTargetView`. (D3D10: vtable [8] also Present; DX9 EndScene = [42].)
  - x86 detour: overwrite the entry with `0xE9 rel32` (5 bytes). x64: 14-byte detour —
    `push rax; movabs rax, target; xchg qword ptr [rsp], rax; ret` —
    only clobbers rax (saved on stack via push) and has no ±2 GB range limit; no 32-bit jump assumption.
  - Trampoline: copy the first N original instructions to executable memory and append a jump back; N must come from a length-disassembler (BeaEngine in the source), because 5/14 bytes do not always end on an instruction boundary. Allocate the trampoline page by walking `VirtualQuery` results until a free region within ±2 GB of the target is found (the `jmp rel32` back must reach).
  - Detour write sequence in the source: VirtualProtect the target to RWX → write stolen-instruction trampoline first → write the jmp at the target → restore protection; Present and DrawIndexed hooked as one unit so the overlay and the mesh filter cannot desync.
- Render inside Present: 2013-era source uses FW1FontWrapper for text; the modern replacement is an ImGui DX11 backend on the same hook (init on first Present call — the swapchain/context are only guaranteed valid then).
- Pitfalls: release the dummy device/swapchain after hooking (leak otherwise); fullscreen-exclusive swaps can recreate the swapchain — re-validate hooks; DrawIndexed sees only indexed draws, so wallhack-style mesh skipping = set IndexCount 0 or reorder the draw.
> Same approach: Direct3DX 11 Hooking (Dmac, section sticky); Direct3D 8/9 Interface Hooking (Roverturbo, section sticky — the EndScene/DrawPrimitive era equivalent); D3D11 How do I find IDXGISwapChain::Present() (pj4s, answered by Swiftik).

### D3D11 How do I find IDXGISwapChain::Present() (src: unknowncheats)
Author: pj4s (question), Swiftik (answer)
- Alternative to the dummy-device trick: attach x64dbg to the live game, break on `dxgi.dll`'s exports/symbols and catch Present on the call path — useful when the game creates its device through a wrapper or a different factory path your dummy device does not reproduce.
- Research value: teaches the general lesson that vtable indexes are per-interface-version constants but *addresses* are per-module-load; anchor hooks to the interface, never to raw offsets like `dxgi.dll + 0x6DE40` (the OP's trampoline at a hardcoded offset broke on the next driver update).
> Same approach: Hooking DirectX11 without the swapchain (Direct3D section).

### universal graphical hook 2022 / UniversalHookX (src: unknowncheats)
Author: illegalcsx2 (GitHub: bruhmoment21/UniversalHookX)
- One library covering DX9 / DX10 / DX11 / DX12 / OpenGL / Vulkan via "all present callbacks" plus per-API init-shader callbacks; deliberately runnable straight from DllMain (to be first in the process) or manually initialized per API via by-API mode.
- Design point: instead of hardcoding one vtable index per API, hook every Present-flavored entry and every shader-creation entry (D3D11 Create*Shader, D3D12 pipeline state, Vulkan SPIR-V stages), so the library survives driver and interface revisions without per-game offsets.
- The companion fork is a shader dumper: extracts full shader source and the uniform list for the game's current API model. That dump is the fastest route from rendered pixels to world/view/projection matrices and per-object constants — the rendering-side entry to ESP math without touching game memory structures.
- DX12 reality check from the thread: a Present hook alone is not enough for an imgui overlay; you also need the command queue and descriptor-heap bookkeeping, which is why DX12-era projects standardize on this library rather than porting the 2013 skeleton forward.
> Same approach: ImGui Hook for DirectX12, DirectX11 and DirectX9, x64/x86 (xMajdev); Rendering with ImGUI (RangeMachine — advertises itself as the base for building your own renderer); Direct3D 11 Renderer (Yazzn, 30k views); Precompiling shaders to remove D3DCompile dependency (dracorx — ship hooks without side-loading d3dcompiler.dll).

### Present-hook placement, defender view (src: unknowncheats)
Author: section consensus (Direct3D / D3D Tutorials and Source)
- Why ACs instrument the render path: any internal overlay must intercept Present/EndScene, so inline patches on dxgi/d3d11/d3d12 entries are cheap canaries — signature-scan a handful of addresses per driver build and you cover the whole ecosystem.
- The external alternative used forum-wide: own overlay window (WS_EX_LAYERED | WS_EX_TRANSPARENT | TOPMOST) + screen capture + external input; no game-process modification at all. Detection pressure then moves to window enumeration and input classification (see the input section) — i.e. the cat-and-mouse relocates rather than disappears.
- Shader-side defense: streaming shader compilation and keeping constants in compute buffers raise the cost of the dump-to-matrix pipeline.

## Kernel driver mapping under HVCI

### Tutorial for kdmapper — manual map your driver using a vulnerable driver by Intel (src: unknowncheats)
Author: Aspectlol (tutorial); critical correction by IChooseYou
- kdmapper canon: abuse a signed-but-vulnerable driver — canonically Intel's `iqvw64e.sys`, which exposes a memory sig-scanner primitive — to obtain arbitrary kernel read/write, then use that primitive to allocate, copy, relocate and execute your unsigned driver image. No loader entry, no service record, no registry footprint for the payload.
- The line everyone gets burned on (IChooseYou, in-thread): "If you don't clear the loaded driver cache after mapping, you will get clapped" — the *abused* vulnerable driver itself leaves a load/unload record (MmUnloadedDrivers and friends) that outlives your mapping; the mapper must clean that trace or pick an unlogged primitive.
- Ecosystem named in-thread: TheCruZ maintains the public fork; the "makaveli" release ships full source; "WinAPI" radar-style releases build on it.
- Deflation arc: the Intel driver is on every blocklist by 2025-2026; current threads (Manual mapping in 2025, kdmapper detection vectors 2026) keep the mapper logic and swap the primitive for an undiscovered vulnerable driver with rw primitives — mapping as a *technique* survives, specific primitives rot fast.
> Same approach: UCMapper update using nvaudio; Manual mapping my unsigned driver into kernel memory (2022); Manual Mapping in 24H2 (2025).

### UCMapper update using nvaudio (src: unknowncheats)
Author: UCMapper release thread (Sep 2023)
- Swap-the-primitive pattern in practice: same mapping logic as kdmapper, but the kernel rw primitive is obtained through NVIDIA's `nvaudio.sys` (audio driver) via its `MapViewExecute` image-processing path — mapping an image by getting the signed driver to map and process your PE rather than copying it yourself.
- Why it matters for the library: it documents that "mapper" = (vulnerable signed driver with the right primitive) × (image-placement logic), and the primitive menu is large — audio, network, GPU vendor drivers have all been used; each new driver buys a fresh detection window until its hash lands on a blocklist.
> Same approach: Manual mapping my unsigned driver into kernel memory (Feb 2022 — map and create a system thread inside a signed driver's context to stay HVCI-compatible).

### Manual Mapping in 24H2 (src: unknowncheats)
Author: necoarc00 (question); state-of-art answers by heapallocation, M4Max (2025)
- The HVCI-era goal restated: you cannot create unsigned executable kernel pages anymore, so "mapping" now means either (a) borrowing executable memory inside a legitimately signed driver's image, or (b) never executing new code at all — driving existing signed kernel functions.
- heapallocation's shortcut for (b): with just a kernel r/w primitive, hook "a random qword inside win32k" — any kernel data reached from user-mode syscalls — and route your operations through existing kernel functions; there is no new executable page to scan for, and the calls happen in legitimate win32k context.
- Named tools in-thread: ghostmapperum and KernelForge (KernelForge doubles as the usermode kernel-emulation library reused by the emulator projects in the next section).
- Vanguard-specific concern (thread's target): vgk's pool scanning makes plain pool-allocated images short-lived; M4Max's summary of community practice: most UC releases still ship kdmapper logic with the Intel driver swapped for another vulnerable driver.
> Same approach: Help: manual mapping in 2025 (May 2025 — how EAC/BE treat mapped kernel drivers); Manually mapped driver detection vectors (kdmapper) (Apr 2026 — community verdict: mapping gets riskier with each anti-cheat generation).

### Detection Vectors for Basic Manually Mapped Drivers (src: unknowncheats)
Author: bobsama (Mar 2023; still the reference checklist)
- The vectors a *basic* mapper leaves, as a defender's audit list (each is a standalone audit item):
  - Allocations in unsigned/kernel memory — pool regions with no owning module, no pool tag, non-paged.
  - PiDDBCache — driver-database timestamps inconsistent with your claimed driver identity.
  - MmUnloadedDrivers — the unload record of the vulnerable driver you abused (kdmapper's classic footgun; matches the IChooseYou warning in the kdmapper entry).
  - System service entries — service/SCM residue from the act of loading the primitive driver.
  - ETW kernel logger events — image loads and allocations observed by tracing even when no scan runs.
  - hal/heap references — heap entries and HAL-adjacent structures pointing into your mapped image.
  - KdpDprintfTransport, DIRIV, HardCodedPartitionId — lesser-known kernel globals that leak references to foreign memory.
  - "Things you executed" — KDP (kernel data protection) and page tables record your execution footprint: present, executable pages with no image backing them.
- Grouping for analysis: vectors 1-3 are *placement* evidence (where your image lives), 4-7 are *side-effect* evidence (what loading touched), 8 is *execution* evidence (what actually ran). A mapping technique only disappears from view when all three groups are clean — which is why pure pool allocation (kdmapper default) died first, and why 24H2-era techniques aim at "no new executable pages at all".
- Trend line (2023 → 2026 threads): detection moved earlier each year — hash → allocation shape → execution traces → behavior — which is why 2026 threads describe mapping as "becoming risky as anti-cheats improve".
- Research use: this list is a ready-made regression checklist for defenders ("can my AC see borrowed-image execution through all nine?") and a pre-flight checklist for researchers building detection-coverage matrices.
> Same approach: Manually mapped driver detection vectors (kdmapper) (Apr 2026); Manual mapping in 2025 (May 2025).

## Usermode kernel emulators — running the enemy without a kernel

### kernemul — driver and usermode emulator, x86-64 and ARM64 (src: unknowncheats)
Author: noahsx (Sep 2026; current flagship of this school)
- Idea: never touch a real kernel or a live game server. Emulate the Windows kernel plus a usermode environment well enough to load the *anti-cheat's own* driver and usermode modules, then study them from outside — the AC becomes a replayable test target.
- Reach claimed in-thread: 380+ kernel functions implemented; any service .sys can be loaded and its DriverEntry run — EAC's and VGK's (Vanguard) DriverEntry run to completion, with interactive keypress gating for steps that wait on hardware/events.
- Backend choice is the performance lever: WHPX/Hyper-V-backed emulation is dramatically faster than Unicorn for this workload — an HLE-heavy loop like `RtlpCreateRemoteRegistryHive` took *days* under Unicorn. Premade disk images + registry hives pinned to kernel build 26100 skip cold-start bringup. Host OS is not fixed: runs on Windows, Linux, even WSL2, since the whole guest is software-defined.
- Usermode half (built on KernelForge + hyperdbg) runs full game clients — Apex, The Finals, Valorant, CS2, Overwatch cited — so usermode AC DLLs can be exercised against the emulated kernel too.
- ARM64 alongside x86-64: the emulator is the only practical way most researchers will ever run ARM64 builds of AC drivers (increasingly shipped for Windows-on-ARM) without ARM hardware.
- Method notes worth stealing for any RE project:
  - AI + an IDA MCP loop accelerated handler implementation (LLM writes handler candidates against the disassembly).
  - *Dynamic cross-view testing*: vary one semantic field in an NT reply (e.g. `UserIsPresent` inside NtQuerySystemInformation output) and diff the AC's behavior — finds exactly which unimplemented path the target depends on.
  - Where the AC virtualizes its logic, classic devirtualization was still required before handlers could be lifted.
> Same approach: KEVLAR (x64 kernel driver emulator, EAC/BE/VGK); KACE (2022, earlier generation).

### KEVLAR — x64 kernel driver emulator source, EAC/BE/VGK (src: unknowncheats)
Author: KEVLAR release (Rust; via thread index + printthread metadata)
- Same thesis as kernemul, different construction: fabricate the kernel objects a driver touches — driver objects, registry paths, loader entries (InLoadOrderModuleList-style) and other kernel structures — then invoke DriverEntry directly; EAC/BE/VGK drivers named as validation targets.
- Value for the library: a Rust-source, dependency-light reference for "what subset of kernel state does a driver actually query" — the fabricated-object list is effectively a census of AC driver introspection surface.
> Same approach: KACE — Kernel Anti-Cheat Emulator in usermode (2022, the earlier generation of the same idea; superseded in capability by kernemul/KEVLAR but useful as the simplest readable codebase).

### Why the emulator school matters for defenders (src: unknowncheats)
Author: section pattern (Anti-Cheat Research)
- Emulation flips the economics of AC reverse engineering: instead of a two-machine kernel-debug setup per driver build, the AC driver becomes a unit test — feed crafted kernel state, watch its report stream, no game license or live server burned.
- The cross-view technique (vary one NT-reply field, diff behavior) is a general black-box differential for any kernel consumer — works on DRM, EDR, and hypervisor-serialized components too.
- Limits surfaced in-thread: fidelity is a treadmill (each kernel-build dependency, e.g. new registry hive formats, must be reimplemented), and VM-protected driver logic still needs classic devirt work first.

### EA Javelin — analysis and devirtualization (src: unknowncheats)
Author: deflin39 (2026; section sticky)
- Javelin = EA's anti-cheat. The thread walks a full VM analysis and devirtualization of its protected handler logic — locate the VM dispatcher, tag handler semantics, lift to IR, re-emit readable C. The *pipeline* is the payload of the entry: identical steps apply to Denuvo-style anti-tamper and to VM-protected malware.
- Placed here rather than in the engine-architecture file because the anti-cheat-countermeasures file already owns the engine taxonomy; this entry owns the devirt template.
> Same approach: Detection in Virtualization (obby1234, sticky); EAC (EOS) Full Architecture Teardown (2026 sticky).

### Detection in Virtualization (src: unknowncheats)
Author: obby1234 (sticky; index + snippet level)
- Counterintuitive thesis from the index line: hide a VM by faking the *status identifiers anti-cheats already read* (e.g. SMBIOS slot type) rather than fighting the hypervisor's ExitReason internals — spoofing the observable is cheaper than changing the mechanism.
- Second thesis: detection logic itself is code and therefore signature-visible; what one AC reads is observable by instrumenting the read, which is exactly what the emulator school exploits.
- Cross-ref: root causes of VM detection (RTC timing / GPU / firmware chain) and why physical research machines are preferred live in techniques/15-anti-cheat/anti-cheat-countermeasures.md §4.3 — not repeated here.
> Same approach: EAC (EOS) Full Architecture Teardown (protection process, modules and callbacks mapped end-to-end); Insecure Boot: bypassing every anti-cheat's Secure Boot check (qwnd1 — Secure Boot check bypass as a class; index-level reference).

## HWID: the identifier surface

### All methods of retrieving unique identifiers (HWIDs) on your PC (src: unknowncheats)
Author: apexlegends (Apr 2019; maintained through 2026, 733+ posts)
- The master list of where hardware bans stick — framed as "what any usermode/kernel component can read without asking anyone":
  - Disk: serials via IOCTLs on `\\.\PhysicalDriveN` / SCSI passthrough; plus the *cached copies* — partmgr query paths and volume shadow copies mean a spoofed serial survives nowhere if the cache still holds the original (restore points re-expose it).
  - NIC: MAC via ndis/nsiproxy; the **ARP table** as adjacent-MAC evidence (neighbors' MACs fingerprint the LAN even when yours is spoofed); UPnP/SSDP chatter as network-neighborhood identifiers.
  - SMBIOS: board/product serials, slot types, chassis; EFI variables incl. boot UUID via SystemFirmwareTableInformation class 0x5a; EFI/UEFI boot-log entries.
  - GPU: NVIDIA UUID via nvapi + the vendor query binary; AMD differs structurally (separate community appendix thread exists).
  - Registry: `SYSTEM` hive volatile keys, MachineGuid; VolumeId (per-partition volume GUID).
  - Peripherals: monitor EDID (serial inside the descriptor block), cached USB device serials (survive replug and even device swap if the cache is stale).
  - Filesystem timelines: file timestamps of system files as machine-age evidence; USN Journal ID per volume.
- Structural observation that makes the list usable: the identifiers cluster into three persistence tiers — *re-derivable at boot* (disk/SMBIOS/GPU/EDID: any spoof must persist across reboots, i.e. firmware-level), *queryable on demand* (ARP, UPnP/SSDP: network-shaped, leak even from adjacent machines), *cached artifacts* (registry volatile keys, partmgr cache, shadow copies, USB serial cache: stale copies that re-expose an old identity after spoofing — clean them or they contradict the new one).
- 2025-2026 updates in-thread: UEFI-variable rotation is now table stakes for top-tier spoofers; kzaaaw's warning — *randomizing even one byte in the EFI boot log can brick the machine for some anti-cheats* (they mis-parse the mutated log and refuse boot or flag the box). Firmware mutation is destructive-ops territory: research machines, images, and rollback plans only.
- Vanguard lore from the same thread (community claim; verify before citing in a report): empty taskbar + software cursor were used as heuristic tells of debugging/sandbox environments.
- Research use: simultaneously the defender's identifier inventory (which signals does our ban key actually survive on?) and the analyst's map of where a research machine leaks identity into a vendor cloud.
> Same approach: AMD GPU UUID appendix thread; the same thread's later pages for per-vendor constants and 2025-2026 tooling.

## Input: mouse-injection classification

### Mouse blocking workarounds — post-EAC-update classification (src: unknowncheats)
Author: ak42067 + halbatros (Jun 2025)
- After EAC added hooks blocking large classes of mouse input, the surviving taxonomy from the thread:
  - **Kernel filter drivers** — Mouclass hooks; Interception (installs mouse.sys/keyboard.sys as filter drivers between the HID stack and the OS). Still work at kernel level, *but* Valorant's vgc reportedly finds the Interception handle and interrupts the communication channel.
  - **Vendor-driver hijacks** — Logitech GHub kernel-driver CVE path: blocked. Razer hijack: contested in-thread ("fully patched" vs "working fine if you own a Razer mouse").
  - **Usermode spoofed calls** — mouse_event/SendInput with return-address/callstack spoofing on the win32 call path: still viable for some titles ("still works, using that for over a month, spoofing return address").
  - **HID input reports** — injecting at the HID report layer rather than the win32 layer (coolers' pointer in-thread).
  - **External hardware** — Arduino-class HID spoofers linger in the same taxonomy (physical device, fully synthetic identity); outside our software scope but completes the classification.
- Timing of that update season matters for researchers diffing AC builds: within weeks of the EAC hooks landing, the Rust AC update thread appears titled around blocking "virtual mouse input", and the GHub-IOCL thread asks for alternatives — i.e. *multiple vendors shipped input-classifier hardening in the same 2025 window*, which is visible as a correlated behavior diff across titles.
- Defender reading: the fact that a game-specific EAC update could kill "a bunch of common methods" at once means ACs maintain input *classification* (injected vs physical) as a first-class detection surface, not just per-driver signatures.
> Same approach: Alternative methods for Kernel-level Input Simulation (GHub IOCTL fake input blocked, 2025); RZCONTROL entry below; HIDClass IRP completion entry below.

### Alternative methods for Kernel-level Input Simulation (src: unknowncheats)
Author: help thread (May 2025)
- Data point more than technique: the moment the Logitech GHub IOCTL fake-input path died, this thread appeared asking for replacements — vendor-driver input routes have a *lifecycle* (discovered → weaponized → blocked) measured in months, and the community's replacement queue is exactly the four-layer taxonomy in the classification entry above.
- Research use: timestamps of "X got blocked" complaints across titles form a cheap timeline of when each AC vendor shipped which input classifier — correlatable against driver-build diffs on the analysis machine.

### Kernel-level mouse control via RZCONTROL driver (Razer Synapse 3/4 Macro module) (src: unknowncheats)
Author: halbatros et al. (Jun-Sep 2026 threads; skeleton from the workarounds thread)
- The generic lesson first: *vendor macro services are kernel-input oracles* — the Razer Synapse service legitimately talks to a kernel driver that injects mouse input, so logging its IOCTL stream with any IRP tracer yields a ready-made injection API with no driver writing.
- Load-bearing skeleton (values recovered verbatim from observed Razer Synapse Service traffic):
  - Enumerate `\\GLOBAL??` for a symbolic link containing `RZCONTROL`; open `\\?\` + link name with generic read/write + async flags; on open failure re-enumerate (the service recreates the link lazily).
  - `#define IOCTL_MOUSE 0x88883020`; payload struct `MOUSE_IOCTL_STRUCT { unk0; unk1=2; max_val=65536; unk2; unk3; x; y; unk4; }` — 0x20 bytes; movement = x/y in 65536-space (driver auto-centers); click = up_down flag 1 (down) / 2 (up).
- Detection reality per thread: works only with Razer mice present (the service gates on owned hardware); several ACs already special-case the device name.
> Same approach: Logitech GHub IOCTL fake input (blocked, 2025 thread); Mouse Driver + Example, Signed By Microsoft (Aug 2026).

### Mouse input injection via HIDClass's own IRP completion worker (src: unknowncheats)
Author: release thread (Aug 2026)
- Novel layer choice: a kernel driver that injects mouse movement/buttons/wheel by riding *HIDClass's IRP completion path* — completing read IRPs on behalf of the HID stack so the injected reports look like they came from the device's own completion worker, not from an upper filter.
- Why it matters: filter-driver positions (Interception-style) are enumerable via the driver stack; a completion-path injection does not add a visible stack layer, moving the detection burden to report-content heuristics (timing entropy, HID descriptor conformance).
> Same approach: Mouse blocking workarounds (classification entry above).

### Mouse Driver + Example, Signed By Microsoft (WORKING) (src: unknowncheats)
Author: release thread (Aug 2026)
- The "legitimate path" branch of the taxonomy: instead of hijacking a vendor driver, ship/reuse a Microsoft-signed mouse-class driver and drive it properly — community-tested against Valorant, Strinova, FragPunk, Overwatch in the release posts.
- Library value: the four-title test matrix is a snapshot of which ACs accept MS-signed input drivers vs which whitelist by device identity — i.e. the boundary between signature-based and identity-based input classification, measurable per title.
> Same approach: Interception stack explanation threads (mouse.sys/keyboard.sys filter placement).

### Input-detection meta (src: unknowncheats)
Author: section pattern (Anti-Cheat Research, 2025-2026)
- The mouse cat-and-mouse is pure *classification*: ACs enumerate HID device trees, check driver signatures and VID/PID plausibility, and statistically test input timing; attackers cycle layers (win32 → HID report → vendor ioctl → hardware HID spoof like Arduino).
- "Virtual mouse input" is now a named detection category — the Rust AC update thread is titled around blocking it; ACs maintain a classifier for injected-vs-physical at the event layer.
- Research framing: for a defender each layer above is a regression-test row; for the analyst, the layer the AC does *not* instrument is the gap — observable by diffing driver IOCTL traffic before/after input events.

## Overlays and windows as a host

### Discord overlay hijacking (src: unknowncheats)
Author: IChooseYou (2024)
- Insight: the Discord overlay already injects into game processes and owns a blessed window — so *becoming* the overlay beats *writing* an overlay.
- What hijacking its window state buys: no window of your own to enumerate, no custom IPC channel to fingerprint, an external process drawing through a window users already trust. Thread technique notes mention `GetWindowLongW`-style state reads to recover world-space info and virtual-alloc / write-process-memory with SEH guards for the remote side (guards matter: the overlay's window state changes asynchronously, so raw reads race and throw).
- Pattern to remember: *any software that legitimately draws over the game* (Discord, NVIDIA/AMD overlays, OBS game capture, Steam overlay) is a candidate host — the defensive question becomes "is our window-heuristic whitelist itself an attack surface?".
- Defender takeaway: third-party overlay processes are part of your trust boundary; their windows inherit a pass from window-based detection heuristics.
> Same approach: NVIDIA overlay shared-mapping exploit (Sk3p — maps your module into the NVIDIA overlay process via a shared-mapping technique; thread sits in a login-gated section, index-level reference only).

## Tools and names that recur across these threads (quick reference)

| Name | Role | Seen in |
|---|---|---|
| kdmapper (TheCruZ fork; makaveli variant) | map unsigned driver via vulnerable-driver rw primitive (canon: Intel iqvw64e.sys) | kdmapper tutorial + all mapping threads |
| UCMapper (nvaudio variant) | same logic, primitive = NVIDIA nvaudio.sys MapViewExecute | UCMapper thread (2023) |
| ghostmapperum | HVCI-era mapper tooling named in 24H2 thread | Manual Mapping in 24H2 (2025) |
| KernelForge | kernel-struct/usermode emulation library; base of emulator usermode halves | kernemul, 24H2 threads |
| kernemul | full driver+usermode emulator (WHPX backend) | kernemul release (2026) |
| KEVLAR | Rust kernel-emulator for EAC/BE/VGK drivers | KEVLAR release |
| KACE | earlier-generation usermode kernel emulator | KACE release (2022) |
| UniversalHookX | DX9/10/11/12/OpenGL/Vulkan present+shader hooks, DllMain-safe | universal graphical hook 2022 |
| FW1FontWrapper | Present-time text rendering (pre-ImGui era) | Universal D3D11 hook |
| BeaEngine | length-disassembler for safe trampoline cutting | Universal D3D11 hook |
| Interception | mouse.sys/keyboard.sys HID-stack filter drivers (input injection) | mouse classification threads |
| RZCONTROL (Razer Synapse) | vendor macro-service driver = kernel-input oracle (IOCTL 0x88883020) | mouse classification threads |
| hyperdbg | debugger used inside emulator bring-up | kernemul thread |

## How to re-mine this vein later

- Sections that matter: Anti-Cheat Research (f=185 — deep RE content, most stickies worth full reads), D3D Tutorials and Source, General Programming and Reversing, C and C++; Game Engine Programming's Source/UE4/Unity subforums for engine-specific offsets — thin so far, mine when a Windows Unity/UE target appears.
- Access recipe that worked (Oct 2026): plain WebFetch and curl are Cloudflare-blocked (403 "Just a moment..."); a reader-type fetch service succeeds intermittently — retry on challenge pages, and prefer `printthread.php?t=<id>` (full thread, no JS, no pagination noise) over the HTML thread view. Some threads (e.g. NVIDIA overlay) sit in login-gated sections and cannot be read anonymously at all.
- The wiki is dead (NXDOMAIN): search snippets citing "wiki pages" now resolve to forum threads; treat `wiki.unknowncheats.me` URLs as historical artifacts.

## Sources
- UnKnoWnCheaTs forum index — https://www.unknowncheats.me/forum/index.php
- Anti-Cheat Research section index — https://www.unknowncheats.me/forum/anti-cheat-research/
- D3D Tutorials and Source section index — https://www.unknowncheats.me/forum/d3d-tutorials-and-source/
- All methods of retrieving unique identifiers(HWIDs) on your PC (apexlegends) — https://www.unknowncheats.me/forum/anti-cheat-research/333662-methods-retrieving-unique-identifiers-hwids-pc.html
- Detection Vectors for Basic Manually Mapped Drivers (bobsama) — https://www.unknowncheats.me/forum/anti-cheat-research/574203-detection-vectors-basic-manually-mapped-drivers.html
- Tutorial for kdmapper (Aspectlol) — https://www.unknowncheats.me/forum/anti-cheat-research/343907-tutorial-kdmapper-manual-map-driver-using-vulnerable-driver-intel.html
- Manual Mapping in 24h2 (necoarc00, heapallocation) — https://www.unknowncheats.me/forum/anti-cheat-research/706105-manual-mapping-24h2.html
- UCMapper update using nvaudio — https://www.unknowncheats.me/forum/anti-cheat-research/600957-ucmapper-kernel-driver-manual-mapper-update-using-nvaudio.html
- Manual mapping my unsigned driver into kernel memory — https://www.unknowncheats.me/forum/anti-cheat-research/490276-manual-mapping-unsigned-driver-kernel-memory.html
- Manually mapped driver detection vectors (kdmapper) — https://www.unknowncheats.me/forum/anti-cheat-research/748499-manually-mapped-driver-detection-vectors-kdmapper-2.html
- Help: manual mapping in 2025 — https://www.unknowncheats.me/forum/anti-cheat-research/701167-manual-mapping-2025-a.html
- kernemul — driver and usermode emulator, x86-64 ARM64 (noahsx) — https://www.unknowncheats.me/forum/anti-cheat-research/773008-kernemul-driver-usermode-emulator-x86-64-arm64.html
- KEVLAR — x64 kernel driver emulator source (EAC/BE/VGK) — https://www.unknowncheats.me/forum/printthread.php?t=765226
- KACE — Kernel Anti-Cheat Emulator in usermode — https://www.unknowncheats.me/forum/anti-cheat-bypass/511355-kace-kernel-anti-cheat-emulator-usermode-3.html
- Universal D3D11 hook (evolution536) — https://www.unknowncheats.me/forum/d3d-tutorials-and-source/88369-universal-d3d11-hook.html
- universal graphical hook 2022 (illegalcsx2) — https://www.unknowncheats.me/forum/d3d-tutorials-and-source/503230-universal-graphical-hook-2022-a.html
- D3D11 How do I find IDXGISwapChain::Present() (pj4s / Swiftik) — https://www.unknowncheats.me/forum/d3d-tutorials-and-source/411481-d3d11-idxgiswapchain.html
- Mouse blocking workarounds (ak42067, halbatros) — https://www.unknowncheats.me/forum/apex-legends/703575-mouse-blocking-workarounds.html
- Alternative methods for Kernel-level Input Simulation (GHub IOCTL blocked) — https://www.unknowncheats.me/forum/anti-cheat-research/759056-alternative-methods-kernel-level-input-simulation-ghub-ioctl-fakeinput-blocke.html
- Mouse input injection via HIDClass's own IRP completion worker — https://www.unknowncheats.me/forum/anti-cheat-research/770029-hid-mouse-inject-mouse-input-injection-via-hidclasss-own-irp-completion-worker.html
- Kernel-level mouse control via RZCONTROL driver — https://www.unknowncheats.me/forum/printthread.php?t=771986
- Mouse Driver + Example, Signed By Microsoft — https://www.unknowncheats.me/forum/anti-cheat-research/766878-mouse-driver-example-signed-microsoft.html
- Discord overlay hijacking (IChooseYou) — https://www.unknowncheats.me/forum/general-programming-reversing/654045-discord-overlay-hijacking.html
- NVIDIA overlay shared-mapping exploit (Sk3p; login-gated, index only) — https://www.unknowncheats.me/forum/anti-cheat-research/704024-nvidia-overlay-shared-mapping-exploit.html
- EA Javelin: analysis and devirtualization / Detection in Virtualization / EAC (EOS) Full Architecture Teardown / Insecure Boot (section stickies; index + snippet level) — via Anti-Cheat Research section index
