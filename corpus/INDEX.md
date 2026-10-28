# Corpus Branch Master Index (one of the RE single entry points · full distillation layer)

> This index routes concrete cases, historical techniques, and vendor lineages. Start with [`../platforms/INDEX.md`](../platforms/INDEX.md) or [`../techniques/INDEX.md`](../techniques/INDEX.md) for systematic knowledge. Scope, provenance, deduplication, and maintenance are in [`coverage-ledger.md`](coverage-ledger.md).
> To locate the original article, use the title in `../data/精华全量索引.md`; extraction instructions are in [`../platforms/maintenance.md`](../platforms/maintenance.md).
> For completed waves, pending work, and skipped clusters, read [`coverage-ledger.md`](coverage-ledger.md).

## 01-windows-re

| File | When to open |
|------|-----------|
| [packers-unpacking-cases.md](01-windows-re/packers-unpacking-cases.md) | Hands-on with specific packers: compression shells 11 cases / ASProtect all versions / Themida-WinLicense / VMP·Safengine·Enigma / Armadillo / domestic license shells / generic unpacking repair / packer-writing references |
| [protection-anti-debug-cases.md](01-windows-re/protection-anti-debug-cases.md) | Commercial protection teardowns: NtQSI killing debug handles / multi-byte INT3 / VMP 3.0.9 full set / game protections TP·HS·NP·GPK·EAC·ACE / dongles SENSE4·ROCKEY4·HID / CrackMe close reads |
| [debuggers-tools-cases.md](01-windows-re/debuggers-tools-cases.md) | Tool depth: OD plugin API and mods / OllyScript / IDA script & plugin 36 entries (ctree/Appcall/hot reload) / debugger development 14 cases / WinDbg depth / TRW·SoftICE legacy tools / x64dbg / Ghidra |
| [malware-evasion-cases.md](01-windows-re/malware-evasion-cases.md) | Family analysis: infection techniques / worm propagation / RAT backdoors / credential theft / ransomware mechanics / AV-evasion confrontation (incl. IOC signatures) |
| [drivers-kernel-cases.md](01-windows-re/drivers-kernel-cases.md) | R0 in practice: hiding tables in SSDT slots / MDL beating read-only / protection-driver confrontation (TP·EAC·XIGNCODE3) / rootkit case teardowns (FUTo·Machine Dog·Stuxnet) / DKOM hiding / signature bypass / R0↔R3 injection |

## 02-android-re

| File | When to open |
|------|-----------|
| [early-techniques-packing-history.md](02-android-re/early-techniques-packing-history.md) | **Read this one for the era evolution**: early-era cracking → repackaging/signature confrontation → the smali debugging era → gen-1 whole-file encryption (Bangcle/Naga/360) → gen-2 method extraction → gen-3 VMP → unpacker evolution (ZjDroid→FART→FRIDA-DEXDump) / vendor signature lineage and the five-generation view / the early hook & injection ecosystem |

## 05-network-proto

| File | When to open |
|------|-----------|
| [protocol-reversing-cases.md](05-network-proto/protocol-reversing-cases.md) | Concrete protocol restoration: PC/mobile game packet encryption / private-server auth clients / IM protocols / APP signature encryption / protobuf·netty / enterprise auth protocols / IoT & industrial-control protocols / protocol fuzzing |

## 06-crypto

| File | When to open |
|------|-----------|
| [keygen-algorithm-cases.md](06-crypto/keygen-algorithm-cases.md) | The full keygen spectrum: five ways to write a keygen / generic registration patterns / concrete software algorithm cases (010Editor·IDA·SourceInsight) / RSA·ECC·bignum / algorithm identification and modification (modified-MD5 three factors / DES weak keys) / password & key derivation / anti-crack design |

## To-be-built areas (priorities in the coverage ledger)

- [coverage-ledger.md](coverage-ledger.md#wave2-to-mine-list-ordered-by-value): planned areas, priorities, and suggested destinations.

## western/ (English-language sources)

> Source scope and acquisition history are maintained in [`coverage-ledger.md`](coverage-ledger.md#western-sources-wave-2026-10-19). Each file retains its existing source appendix for traceability.

| File | When to open |
|------|-----------|
| [western/game-hacking.md](western/game-hacking.md) | Windows game hacking we lacked: D3D11/D3D12 Present hooks & VMT detours / imgui overlays / HVCI-era kernel driver mapping (kdmapper lineage) / mapper detection vectors / userspace kernel emulators / mouse-injection classification / overlay hijack. Authorized-research framing inherited from techniques/15-anti-cheat |
| [western/patch-diffing-1day.md](western/patch-diffing-1day.md) | The craft cve-hunter lacks: obtaining patch pairs (MSU/dyld_shared_cache/OTA) / BinDiff & Diaphora workflows and noise triage / P0 variant-analysis methodology / in-the-wild 0day root-cause patterns |
| [western/forums-qa.md](western/forums-qa.md) | Top-voted RE StackExchange answers + Reddit-legendary VMProtect writeups (_xeroxz devirt, Salwan Triton/LLVM): ELF dynamic linking / generic unpacking taxonomy / obfuscation terms / compiler & odd-format identification / Unix anti-analysis |
| [western/windows-re-tutorials.md](western/windows-re-tutorials.md) | Distinctive lessons from the big free English books (mytechnotalent RE4E, Yurichev RE4B) + crackmes.de solution archive: compiler patterns (switch/div-magic/SSO string) / locating code tricks / crackme solution patterns |
| [western/malware-western.md](western/malware-western.md) | Western defensive craft: unpacking variants (pe-sieve/MalUnpack/tiny_tracer) / stego loaders (IcedID PNG, Hidden Bee) / loader anatomy (TxFs, BITS) / triage ladders / curated tool map |
| [western/linux-pwn-coursework.md](western/linux-pwn-coursework.md) | Recipe-driven pwn coursework: ret2libc/csu/one_gadget/SROP/pivot selection / format-string arithmetic / glibc 2.26→2.34 era applicability matrix / GEF workflow commands |
| [western/debugger-craft.md](western/debugger-craft.md) | Maintainer-side craft: x64dbg breakpoint/trace engine & .trace format / TitanHide & ScyllaHide state / IDA 8-9 microcode·idalib·MCP server / Ghidra PCode scripting / WinDbg TTD dx-LINQ |

## 90-legacy (not opened by default)

> **LEGACY — reduced use**: knowledge in this area is outdated; skip it when looking up techniques. Open it only when the task itself is "analyzing legacy samples / historical research / maintaining inherited environments". The "LEGACY ARCHIVE" sections at the end of the main-area files note which entries were moved here.

| File | When to (ever) open |
|------|-----------|
| [90-legacy/old-tools-platforms.md](90-legacy/old-tools-platforms.md) | Only for inherited environments of dead tools (TRW/SoftICE/W32Dasm/Immunity etc.) or when re-checking old writeups |
| [90-legacy/packers-protection-legacy.md](90-legacy/packers-protection-legacy.md) | Protection post-mortems tied to dead plugins/dead software (only 1 entry: the StrongOD bug) |
| [90-legacy/kernel-mobile-algo-proto-legacy.md](90-legacy/kernel-mobile-algo-proto-legacy.md) | 9x-XP-only kernel tricks (call gates / cross-session csrss) / dead service protocols / out-of-print software algorithms (no migration value) |

See [legacy triage criteria](coverage-ledger.md#legacy-triage-criteria) before adding or moving entries; preserve historical cases with current analysis value.

## Maintenance

- [coverage-ledger.md](coverage-ledger.md#maintenance-conventions): deduplication, source metadata, extraction, and ingestion rules.
