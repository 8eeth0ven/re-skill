# Platforms Branch Master Index (one of the re entry points · read-only router)

> Usage: the entry point is the branch router in ../../SKILL.md; open 1-2 files by name per task, reading the whole library is forbidden. The optional local corpus (Jinghua CHM volumes, 18,915 articles) is generated on your machine by digest_crawl.py and is NOT shipped here; the CHM body-extraction flow (7z x pediyNN.chm ... -o<dir>, gb18030) applies only to machines that have it.
> Structure: the knowledge base's ten top-level categories (chm.htm tree, 1702 nodes) + local Jinghua vols 1-24 full text + 2025 Jinghua 651-article index (Jinghua vol 26 not yet officially released)

## Sister libraries (overlapping cross-links, no duplication here)

- **Android RE techniques** (frida/unpacking/evasion/kernel-level/function panorama) → `../techniques/` branch
- **Web vulnerability testing checklist** (idor/injection/csrf and 40+ modules) → `~/.zcode/skills/skill/知识库/` (separate skill)

## 01-windows (10 files, the *Encryption and Decryption* system)

| File | When to open |
|------|-----------|
| [fundamentals.md](01-windows/fundamentals.md) || RE-generic fundamentals: three killer moves for crypto identification / PE in depth / x64 assembly / virtual memory, protection rings, interrupts and exceptions / debug registers / LLVM obfuscation |
| [basics.md](01-windows/basics.md) || PE structure panorama / Windows data structures (PEB/TEB) / API system / disassembly engines (the LDE eight-part series) / static analysis |
| [debugging.md](01-windows/debugging.md) || WinDbg intro-commands-scripts / debugger development (breakpoints/single-step/SEH/VEH exception dispatch) / x64dbg-Scylla/OllyDbg lineage |
| [unpacking.md](01-windows/unpacking.md) || Packer identification (150+ packers in a four-layer matrix) / unpacking workflow / IAT repair / compression vs encryption packers / DUMP |
| [internals.md](01-windows/internals.md) || Full process-creation chain (kernel32→NtCreateUserProcess→kernel→LdrpInitialize) / VAD / handle table / SSDT / messages / NTSYS |
| [protection.md](01-windows/protection.md) || Anti-debug matrix (PEB/NtQIP/DRx/rdtsc/exceptions/Anti-OD) / junk code / SMC / packer confrontation / VMProtect handlers |
| [reconstruction.md](01-windows/reconstruction.md) || Four patching mechanisms (file/memory/DRx byte-free/Frida) / SMC / DLL hijacking / secondary development |
| [languages.md](01-windows/languages.md) || Delphi/VB (P-Code/Native)/E-language (three forms, local source-text errata)/.NET/Python (PyInstaller)/Electron/AutoIt identification and toolchains |
| [programming.md](01-windows/programming.md) || 13 injection kinds (decision tree + code) / self-implemented Inline Hook (trampoline) / driver IRP-IOCTL / rootkit in nine parts / bootkit / WFP |
| [malware.md](01-windows/malware.md) || Analysis methodology (Procmon/API Monitor/Huorong Sword)/Silver Fox · LIVE · Mallox and other families / AV evasion (direct syscalls / white-plus-black / ETW patch / AMSI) / UAC bypass |

### win-vuln/ (Windows vulnerability hunting special track, 5 files)

| File | When to open |
|------|-----------|
| [win-vuln/pe-re-and-symbols.md](01-windows/win-vuln/pe-re-and-symbols.md) | Got a PE/driver to reverse: Ghidra/IDA workflows and headless automation, full symbol-server setup, WinDbg KDNET two-machine debugging, two complete static→dynamic→POC walkthroughs |
| [win-vuln/driver-ioctl-audit.md](01-windows/win-vuln/driver-ioctl-audit.md) | Auditing drivers: exposed-surface enumeration (missing ACL = openable by any user), CTL_CODE bit breakdown and METHOD_NEITHER semantics, seven audit checklist items (positive and negative code examples), BYOVD 11-driver list, BSOD→!analyze loop |
| [win-vuln/kernel-attack-surface.md](01-windows/win-vuln/kernel-attack-surface.md) | Finding surfaces: nine-surface panorama (Win32k callbacks/ALPC/kernel callbacks/BitLocker·ARSO·Credential Guard bypass surfaces), usable primitives under HVCI constraints, attack-surface→vulnerability-density decision tree |
| [win-vuln/kernel-pool-cve-patterns.md](01-windows/win-vuln/kernel-pool-cve-patterns.md) | For exploitation: four generations of pool layout evolution + Win11 isolation impact, pool-grooming primitive history, three paths from arbitrary write to EoP, a pattern library of 18 individually verified CVEs (incl. full PrintNightmare teardown) |
| [win-vuln/toolchain-setup.md](01-windows/win-vuln/toolchain-setup.md) | Getting hands-on: one-click setup.ps1 for target machines (WinDbg/symbols/x64dbg/WinAFL/ioctlbf), what a macOS host can do, 10-minute self-check list |

## 02-android (4 files; core RE see the techniques library, same skill at re/techniques)

| File | When to open |
|------|-----------|
| [android-knowledge-map.md](02-android/android-knowledge-map.md) || **Entry point for this area**: all 23 second-level categories routed one by one (85 cross-links into the techniques library); Hook/unpacking/packing/capture all go to the techniques library, programming/compiler/formats stay here |
| [compiler-and-system.md](02-android/compiler-and-system.md) || Full javac→d8/r8→dex2oat→JIT/nterp chain / SELinux policy / seccomp (app-domain io_uring blockage, empirically verified) / binder / ROM-root-Magisk |
| [file-formats.md](02-android/file-formats.md) || dex header field by field / class_data differential encoding / code_item + the SHA-1·Adler repair iron rule / ELF-GOT-PLT / oat·vdex·cdex / AXML·arsc / seven-format comparison |
| [malware-and-ctf.md](02-android/malware-and-ctf.md) || Three monetization schools / Joker·Anubis·SpyNote families / field cases / CTF five challenge families + solving pipeline |

## 03-linux (2 files)

| File | When to open |
|------|-----------|
| [linux-security.md](03-linux/linux-security.md) || ELF in depth (segments and sections/relocation/GOT-PLT lazy binding hand-traced diagram/inside dlopen)/GDB+GEF selection and python automation/ptrace anti-debug four classics/ELF virus four types/Mirai/Qiling-Unicorn |
| [other-platforms.md](03-linux/other-platforms.md) || macOS (Mach-O comparison/Hopper)/docker escape five types/historical platforms (Symbian/WinCE/BlackBerry/DOS) |

## 04-ios (4 files)

| File | When to open |
|------|-----------|
| [ios-re-fundamentals.md](04-ios/ios-re-fundamentals.md) || Mach-O (LC_ENCRYPTION_INFO/CryptID)/OC runtime (objc_msgSend assembly)/Swift/four dumping tools/fishhook rebinding/jailbreak generations (unc0ver→Dopamine rootless)/theos Tweak |
| [ios-offense-defense.md](04-ios/ios-offense-defense.md) || Anti-debug (sysctl P_TRACED/PT_DENY_ATTACH) × bypass quick table / 6 jailbreak-detection classes + frida bypasses (local source texts)/hardening matrix/localization in five steps |
| [ios-files-and-signing.md](04-ios/ios-files-and-signing.md) || **Files and signing deep dive (15 cases)**: dyld 4-pass load validation / lazy bind at assembly level / CodeResources validation chain + resource-rules bypass / Impactor protocol / dumping commands and pitfalls (Killed:9) / jailbreak chains (Pangu payload hiding · APFS snapshot bypass · remountRootFS) / iBoot recursive stack overflow end to end / KDP kernel debugging / fairplayd block-dispatch deobfuscation |
| [ios-dynamic-cases.md](04-ios/ios-dynamic-cases.md) || **Dynamic confrontation, 17 cases**: inlinehook signature patching / LLDB anti-anti-debug in five steps / full-scan svc hook / register patching of a short-video app / Theos·Tweak full workflow / jailbreak-free dylib injection (macho_edit) / SwiftDump / mTLS cert extraction + CFB ciphertext rewriting / URLScheme+JSBridge auditing |

## 05-macos (2 files, created 2026-10; numbered in parallel with 05-web, pick by name)

| File | When to open |
|------|-----------|
| [macos-re-attack-surface.md](05-macos/macos-re-attack-surface.md) || **Main file of the standalone mac area**: Mach-O hands-on (otool/nm/codesign tested on this machine)/dyld injection three-way comparison (DYLD_INSERT + platform binary exemption)/r2·LLDB tested workflows (thread return to bypass checks)/TCC dual databases · XPC endpoint enumeration (launchctl) · persistence · notarization/Gatekeeper / hardening (Swift/Metal/notarization hash)/EDR on mac |
| [harmonyos.md](05-macos/harmonyos.md) || hap format (signed zip/module structure)/ArkTS·ArkCompiler abc bytecode/tool status (abc-decompiler·abc2txt)/Android concept mapping table/SoftBus·atomic-service attack surfaces/PSIRT reporting/to-verify list |

## 05-web (2 files; vulnerability testing checklists live in the skill knowledge base)

| File | When to open |
|------|-----------|
| [web-security.md](05-web/web-security.md) || Full pentest workflow + toolchain / 20 sub-category vulnerability master table (cross-linked)/H2-H3-WebSocket-GraphQL/WAF/incident response (memory-shell hunting) |
| [code-audit.md](05-web/code-audit.md) || Taint methodology / Java (Struts·Spring CVE patterns/Shiro·Fastjson evolution lines, CC1·Fastjson local source texts)/PHP·Python·.NET/diff for 0day / CodeQL |

## 06-binary-vuln (4 files, 183 references into the local Jinghua corpus)

| File | When to open |
|------|-----------|
| [heap-exploitation.md](06-binary-vuln/heap-exploitation.md) || glibc chunk/bin lineage / tcache 2.26→2.32 evolution / **house-of 13-style comparison table** (local source text, heap layout in ASCII)/FSOP three generations / mitigation bypasses / ROP·SROP·BROP·dlresolve |
| [vuln-types-exploitation.md](06-binary-vuln/vuln-types-exploitation.md) || V8 six CVE patterns (object forgery/hole/TC)/Linux kernel (DirtyPipe·DirtyCred·22555)/Windows CSC/WinRAR·Office/VMware/Fuzzing seven engines / exploit writing |
| [ctf-system.md](06-binary-vuln/ctf-system.md) || KCTF rules / 2023-2024 annual challenge technique tables / PWN-RE methodology |
| [arm64-rop-practice.md](06-binary-vuln/arm64-rop-practice.md) || **ARM assembly in practice, 16 cases**: instruction quick reference (PC+8 trap / immediate ROR encoding / IT)/Thumb bit0 alignment + lldb fixes / BL·BLX encoding by hand / CrackMe patterns (magic division·jump tables)/C++ virtual functions at the assembly layer / inlinehook assembly forms / two iOS armv7·arm64 ROP cases with full code |

## 07-iot (split into levels: iot/ and wireless-hw/ subdirectories, open by name)

### iot/ (6 files)

| File | When to open |
|------|-----------|
| [iot/attack-surface-recon.md](07-iot/iot/attack-surface-recon.md) || IoT attack-surface panorama / reconnaissance as step one |
| [iot/firmware-extraction.md](07-iot/iot/firmware-extraction.md) || Five extraction routes: uboot console/SPI flash/backdoor accounts/vendor tools |
| [iot/firmware-decryption.md](07-iot/iot/firmware-decryption.md) || Decryption approach for D-Link-family encrypted firmware |
| [iot/firmware-emulation.md](07-iot/iot/firmware-emulation.md) || FirmAE/FAT/Qiling emulation and revival tricks |
| [iot/router-practice.md](07-iot/iot/router-practice.md) || CVE command-injection matrix + six field walkthroughs (Huawei HG532/Cisco full-pitfall flow, etc.) |
| [iot/protocols-services.md](07-iot/iot/protocols-services.md) || MQTT/CoAP/Mirai/industrial control |

### wireless-hw/ (7 files)

| File | When to open |
|------|-----------|
| [wireless-hw/hw-interfaces.md](07-iot/wireless-hw/hw-interfaces.md) || UART/JTAG/SPI/I2C pin identification |
| [wireless-hw/rfid-nfc.md](07-iot/wireless-hw/rfid-nfc.md) || M1 card crypto system / fully-encrypted card compromise / offline brute force |
| [wireless-hw/wifi-security.md](07-iot/wireless-hw/wifi-security.md) || KRACK/WPS/firmware vulnerabilities |
| [wireless-hw/ble-zigbee.md](07-iot/wireless-hw/ble-zigbee.md) || BLE wristband auth bypass / Zigbee primer |
| [wireless-hw/sdr-wireless.md](07-iot/wireless-hw/sdr-wireless.md) || SDR toolchain / replay / rogue base station |
| [wireless-hw/automotive.md](07-iot/wireless-hw/automotive.md) || CAN/UDS/rolling codes + **4 field cases**: ICSim simulated least-privilege environment (cannelloni·vconfig·cangw)/smart alarm cloud IDOR / plug-in terminal reverse engineering (power-pin starting point · high-value T-BOX terminals)/5G IoV attack directions |
| [wireless-hw/bios-uefi.md](07-iot/wireless-hw/bios-uefi.md) || Boot chain / Secure Boot + **3 field cases**: DCI/CCA capturing CSME·BIOS logs (GDK7 wrong-flash permanent-failure trap)/restoring OEM hidden WMI interfaces (acpidump triple·MOF extraction)/why CR3 mapping is rejected by MmMapIoSpace and the MMPFN swap bypass |

### Area level

| File | When to open |
|------|-----------|
| [iot-firmware-nav.md](07-iot/iot-firmware-nav.md) | Navigation shell (points to the iot/ files) |
| [hardware-wireless-nav.md](07-iot/hardware-wireless-nav.md) | Navigation shell (points to the wireless-hw/ files) |
| [ctf-writeup-methodology.md](07-iot/ctf-writeup-methodology.md) | Pwn decision tree / heap attack history / KCTF offense-defense / five challenge-type quick table |

## 08-business (1 file)

| File | When to open |
|------|-----------|
| [business-security.md](08-business/business-security.md) || Logic-vulnerability system (cross-linked skill)/account·payment security / risk control (cross-linked to techniques library device fingerprinting)/data compliance / SRC rating / black-gray industry map |

## 09-ai-security (1 file)

| File | When to open |
|------|-----------|
| [ai-security.md](09-ai-security/ai-security.md) || LLM three-layer attack surface / prompt injection (direct·indirect·multimodal)/Agent tool abuse (Tool Poisoning·Rug Pull·Lines Hopping)/OWASP LLM Top10 2025/RAG poisoning·model extraction/AIxCC/KernelGPT·DeepZero/MCP attack surface/guardrails/GitHub MCP incident post-mortem |

## 10-blockchain (2 files)

| File | When to open |
|------|-----------|
| [blockchain-security.md](10-blockchain/blockchain-security.md) || Top-10 contract vulnerabilities (reentrancy·flash loans·oracles·MEV, The DAO·Bybit $1.5B)/audit tool matrix + per-function checklist / honeypot·Rug identification / mixers and tracing / cross-chain bridge five cases / crypto forensics |
| [ai-blockchain-crossover.md](10-blockchain/ai-blockchain-crossover.md) || Freysa prompt injection / Truth Terminal / Agent token-launch Rug surfaces / oracles + zkML |

## 11-root-cause (root-cause perspective)

| File | When to open |
|------|-----------|
| [memory-error-root-causes.md](11-root-cause/memory-error-root-causes.md) || **Root-cause perspective**: six major memory-error classes (stack/heap/UAF/double-free/race/type-confusion-integer), each = code pattern walked line by line + ASCII memory diagram + why compiler and runtime cannot block it + evolution chain + precedents; the essence of mitigations (NX/ASLR/Canary/CFI/MTE/PAC/Safe-Linking each blocks one class); 20-CVE precedent index table. Exploitation techniques cross-linked from 06 |
| [kernel-vuln-root-cause-cases.md](11-root-cause/kernel-vuln-root-cause-cases.md) || **Kernel case-by-case deep dives**: DirtyPipe/22555/2588+DirtyCred/unix_gc/binder 2215+2020-0423/futex 3153/cldflt 36036+26229/0995/DirtyCOW, ten cases, each = source snippet (version labeled) + broken assumption + race window + primitive conversion + fix diff; closing 12-pattern root-cause table (smell + audit method). All ten cases included |
| [userspace-runtime-root-causes.md](11-root-cause/userspace-runtime-root-causes.md) || Why JIT produces bugs (TurboFan deopt assumptions / Map spoofing / BCE·Typer·race, three classes, 6+ local V8 threads) / deserialization as code-execution machinery / exploitable design trade-offs in heap managers (metadata sharing the heap with data / tcache LIFO) / why managed memory is still unsafe (JNI boundary / the trust boundary of dumpable dex) / five runtime root-cause precedent table |
| [injection-logic-root-causes.md](11-root-cause/injection-logic-root-causes.md) | The essence of injection = interpreter boundary (SQL parser illustrated / why parameterization cures it), root causes of nine injection surfaces, SSRF as the network version of TOCTOU, five logic-bug classes mapped as "developer mental model vs actual semantics" (IDOR = missing row-level ownership in the architecture), three-layer failure of permission models |
| [root-cause-to-technique-map.md](11-root-cause/root-cause-to-technique-map.md) | **Closing chapter**: 25 root causes × fault pattern / evolution into primitives / exploitation techniques (with in-library sources) / root-cause detection (grep patterns) / cure master table; audit grep checklists for seven stacks (kernel C/Java/V8/contracts/Go/IoT); history of mitigation deprecation |

## data/ (optional local corpus indexes — generated on your machine, not shipped in this repo)

The corpus indexes (full-text index of the Jinghua CHM volumes, the annual index, and the knowledge-base tree) are built locally by `digest_crawl.py` and live in `data/`, which is intentionally not part of this repository. Subagents on a machine that has generated them can reference them by path; on a fresh machine, skip this section — every technique in this repo stands on its own without the corpus.

| File | Description |
|------|-----------|
| `data/精华全量索引.md` | Full index of Jinghua vols 1-24, 18,915 articles (2000-2023), grep by title → get pediyNN + path |
| `data/精华26索引.md` + `_原始.jsonl` | 2025 annual Jinghua index, 651 articles |
| `data/完整目录树.md` / `tree.json` | Knowledge-base chm.htm tree, 1702 nodes (ten-category skeleton) |

## Maintenance conventions

- New content goes into the area md, then a row is added back to this index; no body text is stored in this index
- Body text keeps no external links / source attributions / personal names / verification dates, only approaches and hard-won knowledge; for corpus sources use the data/ indexes
- Images: extract the local original and view with Read, then convert to ASCII/text and mark "local original parsed"; purely online posts are marked "restored as text"
- When in conflict with `~/.zcode/rules`, rules win
