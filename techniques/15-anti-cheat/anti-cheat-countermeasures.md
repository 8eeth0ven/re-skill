# Anti-Cheat Countermeasures (techniques/15-anti-cheat/anti-cheat-countermeasures)

> **Boundary statement (read first)**: this piece covers **technical analysis in an authorized context** — CTF game challenges, security testing of your own games, reverse-engineering research on anti-cheat engines, and defenders (game vendors) understanding the attack surface. **Live confrontation in online games = ban risk + terms-of-service violation**; making/selling/distributing cheats is criminally liable in many jurisdictions (in China: many precedents under the crime of damaging computer information systems / copyright infringement). This library provides no ready-made bypasses for in-the-wild games — only principles and research subjects. Driver-level confrontation and BYOVD background → `../07-kernel/cross-platform-kernel.md` §4.

## §0 Overview: The Three-Layer Anti-Cheat Architecture

```
┌──────────────────────────────────────────────┐
│ Cloud: behavior models / AI verdicts /        │ ← evidence aggregation; the hardest
│ reputation stores / ban decisions             │   to bypass (invisible)
├──────────────────────────────────────────────┤
│ User-mode modules: in-game embedded SDK /     │ ← the first thing you touch; the
│ integrity checks / forensics interfaces       │   first line of confrontation
├──────────────────────────────────────────────┤
│ Kernel-mode drivers: memory scans / handle    │ ← the main battlefield of
│ audits / environment detection                │   ACE-Guard/EAC/BE
└──────────────────────────────────────────────┘
```

The three layers' duties: the kernel driver gets the "god's-eye view" (who reads/writes whom, and who is reading/writing the game), user mode proves its own integrity, and the cloud delivers the final verdict (accumulating behavioral confidence when single-point evidence is insufficient). **The closer the verdict sits to the cloud, the harder the confrontation** — that is the direction modern anti-cheat is evolving.

## §1 ACE (Anti-Cheat Expert, Tencent)

### 1.1 Architecture and Product Line

- Tencent's game-security stack: on PC, TP (TenProtect, legacy) → ACE (current); on mobile, ACE Mobile (anti-cheat SDK + hardening + emulator detection); in the cloud, Anti-Cheat AI (behavior analysis).
- PC form: **kernel driver + in-process user-mode module + cloud analysis**; some games enable "pre-launch mode" — the driver loads at boot (earlier than any cheat, plugging the "cheat first" route).
- Mobile form: no kernel privileges (mostly non-root detection), focused on emulator detection / cracked-package detection / speed-hack detection / cloud-phone identification, connecting directly with the Android techniques library's confrontation lines (→ `../04-evasion/root-env-hiding.md`).

### 1.2 Detection Surfaces (PC kernel side)

| Surface | Principle | Meaning for the analyst |
|---|---|---|
| Memory scanning | the driver walks game-process memory comparing known cheat signatures / verifying key data structures (coordinates/HP) for consistency; **honeypots** on key data (forged pointers/coordinates — reading a honeypot = confirmed DMA) | the analysis machine cannot just CE-scan values — touching a honeypot flags you |
| Handle detection | enumerates every process's handles to the game process (OpenProcess traces); a non-whitelisted process holding read/write handles = suspicious | debuggers / frida injection expose handles by nature |
| DMA detection | counters external DMA cards (a PCIe capture card + a second machine reading memory): honeypot data + per-user-per-round encryption (key data encrypted differently for each user/match) + hardware-behavior side channels | DMA is not lawless territory: what you read may be ciphertext or bait |
| Peripheral fingerprints | legitimacy of keyboard/mouse injection paths (driver signatures / vendor IDs), input-timing distribution | simulated input (recoil-control scripts) is recognized via timing entropy |
| Environment detection | debugger / VM / injected-library whitelists | the research environment must be decoupled from the player environment (§4.3) |

### 1.3 ACE Mobile Detection-Surface Supplements (connecting with the Android library)

| Surface | Mobile form | Library counterpart |
|---|---|---|
| Emulator detection | signature files / sensors / frame-rate fingerprints; cloud-phone identification (frame-rate entropy) | detection-landscape.md emulator section |
| Cracked-package detection | signature verification + asset integrity (client self-check + server-issued challenge) | tool-detection-and-modding.md repackaging chain |
| Speed-hack detection | multi-source time-base comparison (system clock / monotonic clock / network clock) | this piece §3.3 timing |
| Injection/hook detection | the full frida-signature stack + inline-hook scanning + so integrity | frida-anti-detection.md |
| Peripheral fingerprints (recoil-control / auto-click) | touch-event timing distribution (microsecond level), external-device enumeration | same type as this piece §1.2 |

### 1.4 Detection of the Analyst's Tools

- **frida**: port / thread names (gum-js-loop) / mapping-name signatures; ACE Mobile has a complete frida-detection stack → the full confrontation chain is in `../04-evasion/frida-anti-detection.md` (change signatures / hide the gadget);
- **Debuggers**: handles + debugged-object flags (P_TRACED alike) + breakpoint-byte scanning (0xCC/BRK instruction self-checks);
- **CheatEngine**: the memory-scanning behavior itself is detected (enumeration/read-write patterns), regardless of the values scanned — "banned before changing any value" is exactly this;
- **IDA / static**: not detected (offline behavior), but samples (driver files) carry integrity reporting — the cloud can correlate "this machine dumped me".

## §2 EAC (Easy Anti-Cheat) and BattlEye

### 2.1 Form Comparison

| Dimension | EAC (Epic) | BattlEye |
|---|---|---|
| Kernel driver | yes, pre-launch at boot (BE_Service / EAC as a service) | yes, same pre-launch mode |
| Certificate & load chain | Microsoft-certified EV-signed driver, loaded via a service at game start; cross-platform (EAC also does mac/Linux/PS/Xbox) | same-grade signing, a boot-started service (BEService) |
| Detection repertoire | driver scans + handle audits + signature libraries + cloud statistics (the community reports a pronounced "delayed ban after evidence collection" strategy) | same grade; known for aggressive ban policies |
| Bypass-research boundary | the binary + driver are statically analyzable (legally signed but reversible code); **a published bypass = fast obsolescence**, vendors hot-update signatures | same |

Common ground: the drivers themselves carry **legal signatures** (vendor certificates, outside Microsoft's driver blocklist), and the load chain offers no attackable "forge a signature" step — a different road from Windows BYOVD (bring-your-own-vulnerable-driver): anti-cheat drivers have no known "vulnerabilities" to exploit; the confrontation is entirely about **discovering and evading detection rules**, not about breaking through the driver itself.

### 2.2 Load-Chain Details (timing the research environment must know)

```
boot/login → EAC/BE service process (BEService.exe / EasyAntiCheat.exe)
  → at game start the service loads the kernel driver (signed driver, PNP/service-control-manager path)
  → driver attach: enumerates processes / establishes game-process protection (handle stripping via ObRegisterCallbacks)
  → the in-game user-mode module starts TLS heartbeats + forensics reporting
```

- **ObRegisterCallbacks handle stripping**: the driver registers callbacks that strip permission bits from third-party processes' handles to the game process (read/write/VM_READ etc. cleared) — conventional injection on the analysis machine (full-rights OpenProcess) is neutered at the source;
- **The point of pre-launch**: a cheat driver loading before the anti-cheat driver grabs the advantageous position → the anti-cheat stays resident from boot, sealing the "start the cheat, then the game" route;
- Service-unload surface: the service process stops (whether the driver unloads after game close follows product policy); **the research window = the game runtime while the driver is loaded**; offline dumping of driver files is unrestricted.

### 2.3 Acquiring Research Subjects

- Driver files: EAC/BattlEye land with the game install (game directory/DriverStore) and can be copied directly for static analysis (legally signed; file copying is not blocked);
- User-mode modules: dlls/sos inside the game process, carrying VMProtect-grade shells; the unpacking approach → `../../platforms/01-windows/unpacking.md`;
- Communication protocols: user mode ↔ driver (IOCTL/FilterCommunicationPort) and ↔ cloud (TLS); the former is the main carrier of detection commands (§3.2).

### 2.4 Other Engines at a Glance (for contrast and orientation)

| Engine | Owner / flagship games | Form characteristics |
|---|---|---|
| Vanguard | Riot (Valorant) | the most aggressive: boot-resident driver (TDK series), loads before Windows login; firmware-level (TPM/Secure Boot chain) participates in verification |
| FairFight | pure server-side | behavior-statistics verdicts only, no client-side driver — the attack surface = the behavior distribution itself |
| nProtect/GameGuard | legacy Korean | mostly user mode + a driver, heavy obfuscation; lots of legacy old games |
| NetEase Yidun / in-house | Chinese mobile/PC games | the mobile side is the same type as ACE; in-house PC drivers follow BYOVD-style signing chains |
| Denuvo (Irdeto) | anti-tamper (not anti-cheat, but often coexists) | VM-grade protection of the game body, raising reversing costs for first-hand analysis |

The engine-typing mnemonic: **look at when the driver loads (pre-login / at game time) + where the verdict happens (client-side evidence / server-side statistics)** — the two decide whether the confrontation's center of gravity is environment confrontation or behavior fitting.

## §3 General Anti-Cheat Principles (analyst's view)

### 3.1 Kernel-Mode Read/Write

- Legitimate drivers (including the anti-cheat's own and signed tool drivers) can read/write any process via `MmCopyVirtualMemory`/APC injection — **cheats' "driver read/write" also uses signed drivers** (their own EV certificate or abuse of legitimate drivers; the latter is exactly the BYOVD idea, list in cross-platform-kernel §4.3);
- The detection side's counters: **handle audits** (the direct OpenProcess route dies) + **driver blocklists** (known cheat-driver hashes) + **kernel integrity** (kernel modification narrowed in the PatchGuard era);
- Once the data plane being read/written is "per-user encrypted", possessing the read/write primitive ≠ possessing valid data — the center of modern confrontation has moved from "can you read" to "is what you read real".

### 3.2 Obfuscated Communication

- User-mode SDK ↔ driver: IOCTL command numbers + encrypted input/output buffers (session keys / white-box); statically, the driver shows only the post-decryption dispatch logic, while the rules themselves are cloud-delivered;
- **Locating detection rules by tracing** (cross-link `../13-trace/trace-practice.md`): follow the IOCTL stream / driver dispatch functions at runtime and diff the instruction sets before vs. after "performing action A (opening CE)" — the detection rule's trigger path is exposed; likewise follow the call origins of the frida-signature scanning functions;
- Cloud protocol: TLS + certificate verification (the full capture-confrontation kit applies → `../04-evasion/capture-all-scenarios.md`), but what you capture is only the evidence-reporting channel, not the verdict logic.

### 3.3 Cloud Behavior Models

- Input features: mouse-trajectory frequency / microsecond-level timing deviation, firing-interval distribution, frame-rate entropy (an abnormally stable frame rate on cloud phones is a strong tell);
- Confrontation implication: **behavior simulation must pass statistical tests** — random jitter is not enough; you must fit human distributions (research-oriented: detection papers and open datasets are the entry to understanding verdict boundaries);
- Reputation systems: device fingerprints + account-linkage graphs; bans propagate across games (within the same engine ecosystem).

### 3.4 The Detection Timeline of One Match (analyst's view)

```
t0 boot: pre-launch drivers resident (ACE pre-launch / Vanguard / BE service)
t1 game start: integrity checks (game-file hashes / signatures / memory image) → environment snapshot (processes / drivers / handle baseline)
t2 during the match: live scanning (memory signatures / key data-structure consistency) + input-stream timing collection + honeypot monitoring
t3 after the match: evidence packaged and reported (encrypted) → cloud verdict (instant ban / delayed batch ban)
t4 correlation: historical evidence from the same device / same IP / same hardware fingerprint merged → reputation collapse = guilt-by-association bans
```

Every segment has a matching research incision: the t1 environment snapshot can be diffed (clean machine vs. research machine snapshot diff); the t2 scan cadence can be timed (the period of one full-memory pass = the bypass window); the t3 reporting channel can be captured (the evidence's shape = what it fears); t4 shows that **a single-point bypass ≠ safety** — the evidence chain closes in the cloud.

## §4 The Analyst-Confrontation View (hands-on, authorized context)

### 4.1 Driver Reverse Engineering (IDA + symbols)

- Most anti-cheat drivers are **not stripped or leak PDBs**: check symbols first (Windows driver symbol servers + local analysis, workflow → `../../platforms/01-windows/win-vuln/pe-re-and-symbols.md`);
- Static main line: DriverEntry → the MajorFunction[IRP_MJ_DEVICE_CONTROL] dispatch function → the command-number switch table = the detection-capability inventory; strings/log tags (the "\[EAC\]"/"\[ACE\]" prefixes) quickly anchor functional domains;
- Dynamic: two-machine WinDbg kernel debugging (setup → cross-platform-kernel §5); break on IOCTL dispatch on the (offline) research machine and backtrace user-mode command construction.

### 4.2 Locating Detection Rules (the trace method)

1. Run a baseline in a clean environment: fully trace driver IOCTL / game-module calls (tool selection → the 11-tool matrix in `../13-trace/trace-practice.md`);
2. Inject one single-variable action (open CE once / plug in frida once) and trace again;
3. The diff = the detection trigger path; follow the vine to locate the rule functions (scan signatures / handle enumeration / timing statistics);
4. Use it in reverse from the defender's view: detection-coverage assessment for your own game (which actions triggered no reports = detection blind spots).

### 4.3 Test-Machine Isolation

The three physical root causes of VM detection (not a signature problem — a "you cannot virtualize real hardware" problem):

| Root cause | Detection manifestation | Spoofable? |
|---|---|---|
| RTC/timing | rdtsc/HPET multi-source clock consistency: under virtualization, interrupt-injection latency leaves regular residuals; instruction-cycle statistics abnormal | extremely hard: needs full-stack timing consistency; spoofing a single source is useless |
| GPU | virtual GPU (no real vendor ROM / temperature sensor / performance distribution); render-command latency distribution differs from real cards | hard: GPU passthrough mitigates but still leaves traces |
| Firmware/driver chain | ACPI tables / SMBIOS / device descriptors are template values; the virtual device drivers' signing chains | medium: customizable but laborious, with signature libraries continuously updated |

Conclusion: **use physical machines for research**; VMs only for offline analysis that never contacts the engine's cloud reporting (static + self-signed test servers).

- **Why VMs do not work**: triple exposure via RTC/timing (anti-cheat measures rdtsc consistency / interrupt timing), GPU (virtual-GPU fingerprints + rendering traits), and driver signing (the virtual device chain); VM-detection principles → the emulator section of `../04-evasion/detection-landscape.md` (same origin);
- A workable research environment: physical machine + dedicated test accounts + network isolation (cloud evidence never leaves the research network); snapshot rollback at the disk level (system restore points) rather than VMs;
- Isolation red line: the research machine's drivers/samples never touch production game servers — pre-launch mode + cloud correlation lets testing behavior pollute the reputation of formal accounts.

### 4.4 The Mobile-Side Entry

Mobile anti-cheat (ACE Mobile / NetEase Yidun / ThoughtWork etc.) has no kernel privileges; the confrontation is entirely user-mode + the vendor-custom-ROM layer and fully overlaps the existing Android confrontation library: emulator and root detection → `../04-evasion/root-env-hiding.md`; frida confrontation → frida-anti-detection.md in the same directory; protocol analysis → `../10-algo-restore/protocol-offline-rpc.md`. This piece does not repeat the details.

### 4.5 What the Analysis Report Should Contain (deliverables for testing your own game)

The anti-cheat testing deliverables list, trimmed to the library's report standard (the two tables):
- **Detection coverage matrix**: cheat actions (memory value edits / speed hacks / injection / protocol replay / scripts) × detection layers (client/driver/cloud); each cell = detected or not + evidence path (logs/report samples);
- **Environment baseline**: test-machine fingerprint, game version, anti-cheat module version (engines hot-update frequently; the version must be pinned);
- **Bypass-cost assessment**: difficulty grading and failure reasons for attempted bypasses of each detected surface (for the defender's prioritization);
- **Blind-spot list**: the list of "no reports at all" actions produced by the §4.2 diff method — the most valuable part for the vendor.

## §5 Public Research and Precedent Anchors (the technical-history thread)

To understand why each engine is designed the way it is, the public confrontation history is the cheapest route:

| Event / research direction | Technical meaning |
|---|---|
| TP-era kernel confrontation (disk scanning / hidden processes / debugger bans) | the start of the "driver vs. driver" arms race; the modern ACE pre-launch mode is its continuation |
| The rise of DMA cheats (the 2019-2023 mainline) | pure-software detection failed → the honeypot + per-user encryption + hardware-fingerprint trio became standard |
| Public research: Vanguard firmware-chain analysis | anti-cheat reaching up to TPM/Secure Boot: the client's root of trust extends into firmware |
| Anti-cheat driver kernel-vulnerability disclosures (both EAC/BE have CVE history) | the defender's code is also an attack surface: the engine's own vulnerabilities go through SRC/PSIRT reporting |
| Cloud-phone / cloud-gaming cheating | the server-side root of the rise in frame-rate-entropy + timing-fingerprint detection |
| AI cheating (object detection + aim assistance) | the confrontation moves toward the "image side channel": the detecting end shifts from the system layer to input-behavior statistics |

Research-method anchors: academic-paper keywords (aimbot detection / anti-cheat bypass behavioral detection), and the engine vendors' public documentation (ACE's official tech column describes its own detection surfaces — **the defender's self-description is the most accurate detection-surface list**).

## §6 Legal and Ethical Boundaries (spelled out)

- **China**: cheat making/selling — abundant precedents under both the crime of damaging computer information systems (Criminal Law articles 285/286) and copyright infringement; there are conviction cases for "sell only, don't write" / "write only, don't sell" alike;
- **Terms of service**: even when online-game confrontation is not criminal, bans + device blacklisting are certain outcomes; conduct research on test servers / private servers (your own) / offline environments;
- **This library's coverage boundary**: static structure of anti-cheat engines / detection principles / authorized-testing methodology; **not covered**: building usable bypasses for in-the-wild games, cheat distribution channels, boosting/studio black-market operations;
- Vulnerability value outlet: anti-cheat engine vulnerabilities (detection bypass / privilege escalation) can go through the vendor's SRC (Tencent SRC / Epic and BE's security-reporting channels `[to verify: current BE/EAC vulnerability-reporting entry]`) — this is the legitimate monetization path.

## §7 Cross-Link Table

| Need | Destination |
|---|---|
| Full Windows driver reversing kit (symbols / two-machine debugging) | ../../platforms/01-windows/win-vuln/pe-re-and-symbols.md, driver-ioctl-audit.md |
| BYOVD driver list and kernel primitives | ../07-kernel/cross-platform-kernel.md §4.3 §4.4 |
| VM/emulator detection principles (basis for research-machine isolation) | ../04-evasion/detection-landscape.md |
| Locating detection rules by trace diffing | ../13-trace/trace-practice.md |
| frida-signature confrontation (mobile side) | ../04-evasion/frida-anti-detection.md |
| Unpacking (the game SDK's VMProtect shell) | ../../platforms/01-windows/unpacking.md |
| The full mobile confrontation chain | the whole ../04-evasion/ directory; game engine and framework reversing → ../14-game-frameworks/ |
