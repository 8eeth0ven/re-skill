# Corpus Distillation Coverage Ledger (all 18,915 articles → nine categories)

> Purpose: records "which topics are distilled, which remain to be mined"; when continuing, take tasks from the Wave2 list — mechanical progress, no repeats, no omissions.
> Full-list rebuild: `cd <re>/data && awk '/^## 精华/{ed=$0; sub(/^## 精华/,"",ed); sub(/[^0-9].*$/,"",ed)} /^- /{sub(/^- /,""); print ed" | "$0}' 精华全量索引.md > /tmp/kx_all.txt`
> If /tmp has been cleared, rebuild the kx_read.py text-extraction script from memory (kanxue-kb-skill) or from the maintenance conventions in this ledger.

## Wave1 (completed 2026-10-17, 8 topics ~4200 lines)

| Topic | File | Deep-read/extraction | Notes |
|------|------|----------|------|
| Packers & unpacking (Win) | 01-windows-re/packers-unpacking-cases.md | 109 extracted / 40 deep-read | Android dex-dump cluster (260 items) not collected; belongs to area 02 |
| Protection & anti-debug (Win) | 01-windows-re/protection-anti-debug-cases.md | 69 extracted / 58 deep-read | Mobile cluster of 45 items not collected |
| Debuggers & tools | 01-windows-re/debuggers-tools-cases.md | 78 deep-read (over quota) | Mobile plugins/Xposed/iOS not collected |
| Malware & evasion | 01-windows-re/malware-evasion-cases.md | 109 extracted / 45 deep-read | Game-cheat cluster (Plants vs. Zombies, 25 articles) not collected |
| Drivers & kernel (Win) | 01-windows-re/drivers-kernel-cases.md | 77 deep-read | ~100 SSDT/filter tutorials merged as same approach |
| Android early era + hardening history | 02-android-re/early-techniques-packing-history.md | 117 extracted / 50 deep-read | System-vuln clusters (MasterKey/Stagefright) not collected |
| Protocols & packets | 05-network-proto/protocol-reversing-cases.md | 60 deep-read | Generic capture-tutorial cluster went to techniques/packet-capture-all-scenarios |
| Keygens & algorithms | 06-crypto/keygen-algorithm-cases.md | 110 extracted / 70 read | OLLVM/trace restoration clusters are covered by ../techniques/10-algo-restore/; use its branch INDEX for the current file list |

Also: an earlier 2026-10-17 batch (iOS code signing / iOS dynamics / three OLLVM pieces / ARM64 ROP / automotive BIOS, 78 articles) landed in `platforms/` + `techniques/`, outside this branch.

## Wave2 to-mine list (ordered by value)

> From Wave2 on, **apply legacy triage at write time** (criteria in this ledger’s "Legacy triage criteria" section); no more after-the-fact moves.

| Priority | Topic | Suggested file | Estimated corpus |
|------|------|---------|---------|
| High | Binary vulns & CTF remainder (pwn 238 / CVE 355 hits; platforms/06 already cites 183 — collect the increment) | 07-binary-vulns-ctf/exploit-cases.md | ~150-250 articles after filtering |
| High | VMP/VMProtect depth (W1/W2 each have skip clusters: packer-writing 15+ / VMP keygenme) | 06-crypto/vmp-protection-restoration.md or merge into 07 | ~30 articles |
| Med | iOS/macOS corpus remainder (jailbreak plugins/old techniques; platforms/04 already has 4) | 03-ios-macos/residual-cases.md | ~40 articles |
| Med | Smart devices & hardware (routers/firmware/IoT case remainder) | 08-smart-devices-hardware/cases.md | ~50 articles |
| Med | Linux & ELF (platforms/03 has only 2; ELF viruses/Qiling etc.) | 04-linux-others/cases.md | ~60 articles |
| Low | WEB/business (large overlap with the skill knowledge base; collect only reversing-oriented) | 09-web-business/cases.md | ~40 articles |
| Low | Game-cheat history (Plants vs. Zombies 25 articles etc., technique-oriented) | 01-windows-re/game-cheat-trainer-history.md | ~30 articles |

## Legacy-archive events (2026-10-18)

The eight Wave1 files went through the archive criteria; 20 entries were moved into `90-legacy/` (old-tools-platforms 10 / kernel-mobile-algo-proto 7 / packers-protection 1, plus 2 merged into same-file subsections): dead tools (TRW/SoftICE whole sections/W32Dasm/Immunity/StrongOD), 9x-XP-only (call gates into R0 / cross-session csrss), dead targets (MSN worm / Adobe AMF / UNFOXALL etc.). Packer lineages / virus families / dongles / hardening-history threads stay in the main area per the criteria.

## Semantics-preserving slim-down (2026-10-18)

User ruling: "too much data; reduce data but keep functional semantics": 17 files (corpus 8 main + archive 3 + iOS 2 + OLLVM 3 + ARM64 1) went 7653→3499 lines (-54%), with **entries 578→578, zero loss** (per-file grep title-set comparison). What was deleted: only background narrative / process bragging / repeated explanation / boilerplate code (marked `# (omitted: xxx)`); steps / commands / signatures / offsets / tables / pitfalls were all kept. **New distillations are written directly at this density** (3-15 lines per entry, narrative under one sentence) — no more write-thick-then-compress.

## Long term

- Essentials vol 26 (651 articles from 2025): not officially released; the index is prepared locally (`data/精华26索引.md`, not shipped); once released, re-run digest_crawl.py to backfill, then distill the same way
- Clusters in each file's "skip ledger": on continuation, re-check first whether they should be promoted to formal entries

## Western sources wave (2026-10-19)

User directive: mine foreign RE forums/collections. 7 parallel agents, ~2116 lines, 193 entries, all deduped against the overlapping Kanxue-corpus files before writing. Files under `western/` (see INDEX). Notable source states discovered: wiki.unknowncheats.me dead (NXDOMAIN); UC forum Cloudflare-gated (mineable via reader-service + printthread.php); crackmes.de dead (crackmes.one inherits the archive); Woodmann parked; malwaretech.com via Wayback only. Blocked-source notes live in each file's Sources appendix for later retry.

## Corpus scope and provenance

> Positioning: the **semantic-dedup distillation layer** over all 18,915 articles of Kanxue Essentials vols 1-24 (2000-2023) — subdivided into nine categories; each topic file = the method distillation of that topic's cases across all 24 volumes. A given method keeps only one entry (same-approach sources listed on the last line); different semantics / different methods each get their own entry; an entry = chapter title + author.

> Distilled from foreign forums/collections (UnknownCheats, RE StackExchange, crackmes.de archive, Project Zero, Diaphora/BinDiff, hasherezade/MalwareTech, pwn.college/ir0nstone/GuyInATuxedo, mrexodia/Hex-Rays/x64dbg docs). Same dedup discipline: each agent read the overlapping Kanxue file first and kept only novel ground. Every file ends with a `## Sources` appendix (title — URL) as the re-find anchor; that appendix is the one place URLs live.

## Legacy triage criteria

**Archive criteria** (move in if any holds; the main area prefers omission over error): (1) the tool is unusable today and the entry depends on it; (2) the technique only works on Win9x/ME/NT4/2000/XP (32-bit); (3) the target service/platform/version is dead with no migration value. **Do not move**: old packers / old virus families / hardware dongles (value for analyzing legacy in-the-wild samples), principle-level content, evolution histories with modern successors.

## Maintenance conventions


- **Same-method dedup**: keep one entry per method, list other same-method sources on the last line via `> Same approach:`; different semantics/methods each get their own entry — the goal is not thinness but full method coverage
- An entry = chapter title + author name; no URLs / volume numbers / dates / verification notes / process narrative (install addresses and IOC signatures are the exceptions)
- **Legacy triage (applied at write time)**: run every new distilled entry through the archive criteria above; on a hit write it directly into `90-legacy/`, not the main area; register the destination in the "LEGACY ARCHIVE" section at the end of the main-area file
- New files get a row in [`INDEX.md`](INDEX.md); each file carries its own "skip ledger" at the end, summarized centrally in `coverage-ledger.md`
- Extraction workflow (reusable): `/tmp/kx_all.txt` (full vol|path|title list; rebuild command in the coverage ledger) → topic grep → 7z batch extract → `kx_read.py` to plain text → read cluster representatives → distill and write
