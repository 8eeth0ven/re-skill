# Breach Table: PoC Reuse & N-day Playbooks (Distilled from PoC-in-GitHub)

> The master index is at `../breach-tables-cve.md`; this piece takes over the "reference already-weaponized bugs" step after target selection. Ammunition source: nomi-sec/PoC-in-GitHub (GitHub PoC repos aggregated per CVE number, yearly volumes 1999-2026, one json per CVE = the GitHub search results). In 2026-10, a full pass filtered 873 RE-relevant CVEs/1403 repos for 2023-2026, verified repo by repo and distilled; purely web/CMS/logic surfaces excluded. Usage: **before attacking a new surface, check for existing PoCs on the same surface as templates; when tracking new patches, hunt bypasses per §1.3; copy the §3 standard parts for the report's reproduction environment**.

## 0. Using the Ammunition Source and Real-vs-Fake

| Step | How | Key points |
| --- | --- | --- |
| Pull | `git clone --depth 1` (via proxy), one directory per year/one json per CVE (repo name + description + link) | The 2026 volume has 2518 CVE jsons; the whole repo 11k+ |
| Filter | Bucket by repo-name + description regexes (iot-firmware/linux-kernel/binary-pwn/browser-v8/windows-kernel/camera-nas-emb/virtualization/android/apple-xnu/ics), exclusion words filter out pure web (SQL/XSS/CMS/deserialization) | A hit only means "relevant"; real vs fake requires inspecting the file tree repo by repo |
| Verify | Judge real by readme + file tree: exploit source/firmware analysis/trigger scripts present; info pages/news reposts/detectors get downgraded | Detector/checker-type repos = a large-deployment signal; bump their target priority |

**Six fake-PoC tells (a mandatory gate before ingesting; field-confirmed)**: ① the CVE attribution contradicts the vendor advisory (check NVD first); ② the PoC violates the protocol's binary format (plaintext masquerading as SSH packets); ③ pseudo-quantified parameters; ④ 10+ homogeneous repos for one CVE in a short window (a content farm — FreeFloat FTP is a regular); ⑤ platform confusion (a Unix bug talking about Windows SYSTEM); ⑥ fabricated compile flags/version numbers.

## 1. Five Localization Routes (the sources of high-star real PoCs are all traceable: auditing > fuzzing; fuzzing only does crash triage)

| Route | How to do it | Representatives |
| --- | --- | --- |
| 1.1 Fix-commit archaeology + official regression tests | Open-source engines (V8/WebKit/Firefox) always attach a regression test to bug fixes = the official PoC; check out the fix commit's **parent** to build your own vulnerable tree (more reliable than downloading historical binaries — avoids BuildConfig drift); architecture-dependent bugs need cross-builds from the source tree | Absolutely mainstream in the V8/WebKit 1day scene; XNU via bisecting opensource.apple.com tag ranges |
| 1.2 Patch-diff back-inference | Open source: git bisect to pin the introducing commit; archive both introducing and fixing commits; closed-source Windows: Ghidra-diff two builds — **the same pattern patched across N functions = an exploitability map**; Qualcomm: CodeLinaro commits + bulletins; Android: cs.android.com line-level anchors | MikroTik www multi-build comparison watching guards appear → back-derive the trigger + a version map |
| 1.3 Half-applied patches (the blind spot when tracking new patches) | Last version's patch checks a field but not its **product** (VMXNET3 TSO 32-bit imul truncation); pinning the dependency without changing the logic (Next.js pinned sharp, the decoder version untouched — **check the actual decoder version, not the top-level framework version**); blacklist-character bypasses and re-fires | Within 72h after every VMSA/MSRC/monthly bulletin, hunt bypasses against the patch = the highest-ROI 1-day→n-day move |
| 1.4 A freshly merged big refactor = an audit window | New data structures merged (maple tree), **defensive code** (class-existence checks/anti-crash fallbacks = new attack surfaces), type-signature-change refactors (size_t→signed introducing regressions) | Same logic as "rewrite/new parser" in release notes (the open-source.md row already covers it) |
| 1.5 Disclosure → self-written exploit | oss-security/lore mails and ITW advisories give the root cause but not the exploit; root-cause reuse targeting: **the same root-cause pattern surface produces bugs repeatedly** (nftables genmask 4+ CVEs in 3 years, the page-cache family's generational inheritance) — watching surfaces that already produced the same root cause beats blind scanning by far | io_uring OOB disclosure → self-written exploit; Android ITW → patch-diff reproduction |

## 2. Era Traits of Exploitation Primitives (data-only anti-mitigation is the mainstream answer: never touch code pointers)

| Primitive | What it does | Representatives/notes |
| --- | --- | --- |
| The cross-cache→page-cache finisher chain | slab UAF → cross-cache attack escalates to page UAF → overwrite a read-only file (SUID/libc/config); SMEP/KPTI/CET/KASLR all N/A; the de-facto standard for contemporary kernel LPEs | nftables 1086/AF_ALG CopyFail/CPU-timer races/DirtyClone all walk this path; the hard constraint is INIT_ON_ALLOC (Ubuntu 6.5+) |
| Dual-primitive pairing | Leak first, write second: a big capture overflows + a small capture leaks uninitialized heap; integer overflow + compile-time validation bypass | ASLR falls to information leaks, not brute force |
| Interpreter/pointer reuse | The Onigmo VM keeps the interpreter's own pointers alive through ASLR; **non-PIE target selection** (node's official builds); deopt confusion (externref↔i64) yielding non-compressed 64-bit pointers cutting straight through the V8 cage | In the CET/CFI/MTE era nobody forces through; all switch to data-only or logic bugs |
| Android's three-stage form | A framework logic bug into system_server → **borrow a high-privilege SELinux domain** (neverallow back-query: which domain can pass the kernel bug's gate) → a kernel data-only 1day finisher | The logic chain is 100% reliable, skipping all mitigations; persistence via signature-history injection (survives OTA) |
| KASLR leak sources | seq_operations reclaim-and-read/socket ops pointers/subsystem dump APIs/physmap direct reads/MSR 0xC0000082 (the most stable single point on Windows)/CPU side channels as the fallback | The five-part leak proof: window-independent + sandbox-piercing + no caps needed + remotely triggerable + reads sensitive data |
| 1day cross-vendor porting | Per-device offset tables (kallsyms+ikheaders+RELA self-checks); kmalloc geometry typed per distro; with STATIC_USERMODEHELPER sealing modprobe, degrade to direct cred patching | The GhostLock 4.19 porting checklist is the model; offline symbol extraction from boot.img without root |

## 3. Environment-Engineering Standard Parts (the common traits of trustworthy PoCs; copy into reproduction reports)

- **Dual-version comparison**: build the vulnerable tree (fix^) and the fixed tree (fix) with identical parameters; the PoC crashes on the former and runs clean on the latter = the criterion; d8 commonly uses `--allow-natives-syntax --expose-wasm`, feedback-shaping flags per the bug (`--homomorphic-ic` class); jsc disables concurrency first (`--useConcurrentJIT=false --useConcurrentGC=false`)
- **Images/versions pinned**: docker images pinned by sha256 digest; a three-tier version-matrix table (affected/tested/fixed) + memory requirements + success rates stated; the "patch only pins the dependency but still exploitable" counter-example also goes into the matrix
- **Kernel ranges**: kernelCTF LTS instances (QEMU + the official config) as a free verification range; bring your own initramfs+config+run.sh snapshots; a KASAN lab + vulnerable/fixed dual-kernel diffs; Windows escape PoCs use QEMU TCG as the disposable environment
- **Races**: an outer infinite retry ring; dual-knob tuning + observable log signals (a dmesg oracle's specific strings like `Unexpected outstanding_txns` = you're on the bug path) for iteration
- **Trigger amplifiers**: `bcdedit /set debug on` turns the NIC into kdnic.sys amplifying RSC coalescing; the NIC's Interrupt Moderation = Extreme; the fastboot command itself = a bug prober (OKAY = exploitable)
- **Honest-declaration discipline**: the flag-free review bar (no natives-syntax/zero hardcoded addresses/hit-rate attached); tiered statements "the write primitive works / the full chain only on version X"; the limitation list (CONFIG_LIST_HARDENED breaks post-free writes = degraded to DoS class) — **copy these capability-boundary declarations straight into the report template**
- **Delivery structure template**: a three-tier progression basic_poc→full_poc→sandbox_emulator; diagnose/crash/leak/analyze subdirectories; the vulnerable-config files + Dockerfile ship with the repo

## 4. Ten Hot Buckets Quick Reference (target selection = attack-surface density × privilege-free reach × ecosystem uptake)

| Bucket | Hotspots | One-line playbook |
| --- | --- | --- |
| linux-kernel (168) | io_uring > nf_tables transactions/refcounts > the page-cache family > legacy protocols (DECnet/SCTP/vsock/kTLS, zero fuzzing) > futex/binder | After `unshare -rUn`, nftables is the unprivileged entrance; 44% are same-year new bugs — the weaponization window is razor thin |
| iot-firmware (243) | Cisco 28 > Ivanti 26 > Fortinet 23 > TP-Link 21 > F5 19; shapes: injection 58 > auth bypass 28 > unauthenticated 26 > overflow 19 | **1/4 only count post-authentication**: the three escalation paths = pair with an auth-bypass/default credentials/WAN-side surface |
| binary-pwn (146) | nginx double-evaluation > Windows services > Apple drivers > kernels > language-runtime native layers (PHP/CPython/jq/OCaml) | Interpreter/JIT intermediate-code OOB = the new generation of high-level-language heap overflows |
| browser-v8 (96) | Genuine-engine class ~46% (V8 19/WebKit 13/Blink 13/Firefox 11); only 3 fullchains, concentrated in two author lineages | In-cage ARW is only half the journey; three exits: leftover wasm RWX / an SBX-bypass chain / deopt non-compressed pointers |
| windows-kernel (58) | **BYOVD 41%** with the mining ground shifting from AV to anti-cheat (Wellbia/GameDriver) + OEM preinstalls; Microsoft's own CLFS/AFD/http.sys keep producing; the print stack has gone cold | Handle forging (ObOpenObjectByPointer KernelMode) = a third primitive class independent of physical read/write |
| camera-nas-emb (68) | ONVIF 8899 unauthenticated GetProfiles→GetStreamUri leaking hardcoded RTSP credentials; the printer address book = an intranet credential mine (retarget SMB → Responder captures NTLMv2, relays into the domain) | Hardcoded credentials × unauthorized read interfaces = zero-click escalation |
| virtualization (23) | Guest→host, half in device-emulation backends (SCSI/virtio/VGA/9pfs/shared folders); VMware appliance management planes 30% (Thrift RPC/fixed keys/flag injection); KVM shadow MMU the new hotspot | Forging device descriptors inside the guest + knocking MMIO directly beats walking the guest driver's protocol stack |
| android (21) | Framework logic elevations 7 > kernel 5 > Qualcomm drivers + bootchain 6; direct binder memory corruption is actually scarce | Binder triggers reproduce with QEMU/cuttlefish — no full AOSP build needed |
| apple-xnu (11) | The kext surface is softer than XNU core (no consistent PAC hardening, slower updates); macOS sandbox escapes have a fixed recipe = hunt for sloppy XPC services | Byte-compare across three versions to confirm isomorphic bug shapes; the dyld shared cache slide (syscall 536) is its own surface |
| ics-scada (19) | Actual entrances are all HMI/middleware web layers — not one field-protocol exploit; field protocols only get unauthorized read/write checks (Modbus function codes 5/15 writing read-only coils) | ICS "crypto modules" attacked via key common-origin (vendor tools and devices sharing the same keys) |

## 5. New Shots Already Synced into the Tables

firmware.md (+5 rows): config ciphertext round-trips/QEMU-user hanging the vendor .so as a crypto oracle; same-model patch-diff back-derivation; proprietary-protocol auth-segment auditing (the TDDP pattern); DHCP Option 66 network-side supply; the cloud-management dual path. open-source.md (+3 rows): double-evaluation/second parses; defensive code = new attack surfaces; refactor regressions (type-signature changes). windows.md (+2 rows): syscall info-class delta audits; object-manager namespace squatting. browser-and-v8.md (+2 rows): the commit-archaeology + regression-test main path; the V8 post-sandbox era's three exits. general-and-wrapup.md (+1 row): root-cause reuse targeting.

The raw deep-dive material (repo-by-repo, CVE-by-CVE detail, incl. a 168-kernel-CVE pattern table / a 243-firmware-CVE vendor distribution): six local pieces at `/tmp/poc-radar/深挖-*.md` (session artifacts; clear after selectively merging).
