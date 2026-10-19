# Corpus Branch Master Index (one of the RE single entry points · full distillation layer)

> Positioning: the **semantic-dedup distillation layer** over all 18,915 articles of Kanxue Essentials vols 1-24 (2000-2023) — subdivided into nine categories; each topic file = the method distillation of that topic's cases across all 24 volumes. A given method keeps only one entry (same-approach sources listed on the last line); different semantics / different methods each get their own entry; an entry = chapter title + author.
> Relation to the sister branches: **platforms/ and techniques/ are the systematic knowledge (check those first); corpus/ is the case ammunition depot** (come here for concrete cases, era techniques, vendor lineages). To find an original article: grep the title in `../data/精华全量索引.md` to get the path → `7z x pediyNN.chm "<路径>" -o<目录> -y`.
> Coverage progress: **only the first wave of 8 topics is done** (2026-10-17); for pending areas and per-file skip clusters see [`coverage-ledger.md`](coverage-ledger.md).

## 01-windows-re (5 files)

| File | When to open |
|------|-----------|
| [packers-unpacking-cases.md](01-windows-re/packers-unpacking-cases.md) | Hands-on with specific packers: compression shells 11 cases / ASProtect all versions / Themida-WinLicense / VMP·Safengine·Enigma / Armadillo / domestic license shells / generic unpacking repair / packer-writing references |
| [protection-anti-debug-cases.md](01-windows-re/protection-anti-debug-cases.md) | Commercial protection teardowns: NtQSI killing debug handles / multi-byte INT3 / VMP 3.0.9 full set / game protections TP·HS·NP·GPK·EAC·ACE / dongles SENSE4·ROCKEY4·HID / CrackMe close reads |
| [debuggers-tools-cases.md](01-windows-re/debuggers-tools-cases.md) | Tool depth: OD plugin API and mods / OllyScript / IDA script & plugin 36 entries (ctree/Appcall/hot reload) / debugger development 14 cases / WinDbg depth / TRW·SoftICE legacy tools / x64dbg / Ghidra |
| [malware-evasion-cases.md](01-windows-re/malware-evasion-cases.md) | Family analysis: infection techniques / worm propagation / RAT backdoors / credential theft / ransomware mechanics / AV-evasion confrontation (incl. IOC signatures) |
| [drivers-kernel-cases.md](01-windows-re/drivers-kernel-cases.md) | R0 in practice: hiding tables in SSDT slots / MDL beating read-only / protection-driver confrontation (TP·EAC·XIGNCODE3) / rootkit case teardowns (FUTo·Machine Dog·Stuxnet) / DKOM hiding / signature bypass / R0↔R3 injection |

## 02-android-re (1 file)

| File | When to open |
|------|-----------|
| [early-techniques-packing-history.md](02-android-re/early-techniques-packing-history.md) | **Read this one for the era evolution**: early-era cracking → repackaging/signature confrontation → the smali debugging era → gen-1 whole-file encryption (Bangcle/Naga/360) → gen-2 method extraction → gen-3 VMP → unpacker evolution (ZjDroid→FART→FRIDA-DEXDump) / vendor signature lineage and the five-generation view / the early hook & injection ecosystem |

## 05-network-proto (1 file)

| File | When to open |
|------|-----------|
| [protocol-reversing-cases.md](05-network-proto/protocol-reversing-cases.md) | Concrete protocol restoration: PC/mobile game packet encryption / private-server auth clients / IM protocols / APP signature encryption / protobuf·netty / enterprise auth protocols / IoT & industrial-control protocols / protocol fuzzing |

## 06-crypto (1 file)

| File | When to open |
|------|-----------|
| [keygen-algorithm-cases.md](06-crypto/keygen-algorithm-cases.md) | The full keygen spectrum: five ways to write a keygen / generic registration patterns / concrete software algorithm cases (010Editor·IDA·SourceInsight) / RSA·ECC·bignum / algorithm identification and modification (modified-MD5 three factors / DES weak keys) / password & key derivation / anti-crack design |

## To-be-built areas (priorities in the coverage ledger)

03-iOS-macos / 04-linux-others / 07-binary-vulns-ctf / 08-smart-devices-hardware / 09-web-business — see the Wave2 list in [`coverage-ledger.md`](coverage-ledger.md).

## 90-legacy (not opened by default)

> **LEGACY — reduced use**: knowledge in this area is outdated; skip it when looking up techniques. Open it only when the task itself is "analyzing legacy samples / historical research / maintaining inherited environments". The "LEGACY ARCHIVE" sections at the end of the main-area files note which entries were moved here.

| File | When to (ever) open |
|------|-----------|
| [90-legacy/old-tools-platforms.md](90-legacy/old-tools-platforms.md) | Only for inherited environments of dead tools (TRW/SoftICE/W32Dasm/Immunity etc.) or when re-checking old writeups |
| [90-legacy/packers-protection-legacy.md](90-legacy/packers-protection-legacy.md) | Protection post-mortems tied to dead plugins/dead software (only 1 entry: the StrongOD bug) |
| [90-legacy/kernel-mobile-algo-proto-legacy.md](90-legacy/kernel-mobile-algo-proto-legacy.md) | 9x-XP-only kernel tricks (call gates / cross-session csrss) / dead service protocols / out-of-print software algorithms (no migration value) |

**Archive criteria** (move in if any holds; the main area prefers omission over error): (1) the tool is unusable today and the entry depends on it; (2) the technique only works on Win9x/ME/NT4/2000/XP (32-bit); (3) the target service/platform/version is dead with no migration value. **Do not move**: old packers / old virus families / hardware dongles (value for analyzing legacy in-the-wild samples), principle-level content, evolution histories with modern successors.

## Maintenance conventions

- **Same-method dedup**: keep one entry per method, list other same-method sources on the last line via `> Same approach:`; different semantics/methods each get their own entry — the goal is not thinness but full method coverage
- An entry = chapter title + author name; no URLs / volume numbers / dates / verification notes / process narrative (install addresses and IOC signatures are the exceptions)
- **Legacy triage (applied at write time)**: run every new distilled entry through the archive criteria above; on a hit write it directly into `90-legacy/`, not the main area; register the destination in the "LEGACY ARCHIVE" section at the end of the main-area file
- New files get a row in this index; each file carries its own "skip ledger" at the end, summarized centrally in `coverage-ledger.md`
- Extraction workflow (reusable): `/tmp/kx_all.txt` (full vol|path|title list; rebuild command in the coverage ledger) → topic grep → 7z batch extract → `kx_read.py` to plain text → read cluster representatives → distill and write
