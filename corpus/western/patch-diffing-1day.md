# Western corpus · Patch diffing & 1-day hunting (P0 / Diaphora / BinDiff)

> Positioning: the craft our cve-hunter lacks — obtaining patch pairs, diffing, triage, variant analysis.
> cve-hunter answers "which known CVE matches this version string"; it cannot prove a patch is present or absent.
> This file covers the western 1-day loop: **acquire patch pair → normalize (symbols/rebase) → diff → triage "unpatched function" shortlist → variant fan-out (audit + fuzz seed reuse)**.

## Pipeline overview (the 1-day loop all sources converge on)

1. **Acquire the pair**: pre-patch binary + post-patch binary of the *same* build line (same arch, same config). Never mix channels (debug/release, 32/64, vendor fork).
2. **Normalize**: load both in IDA with symbols downloaded (Windows PDB prompt; Apple dyld cache symbols; AOSP prebuilts) and let auto-analysis fully finish. Rebased/renamed functions are the #1 noise source — structural matchers (below) absorb most of it.
3. **Diff**: BinDiff for speed/graph view, Diaphora for pseudo-code diff + "potentially fixed" heuristics. Old = primary, new = secondary; triage the *changed* set, not the unmatched set.
4. **Triage**: sort by similarity just below 1.0, in security-interesting modules (memory managers, parsers, syscall handlers). A patch that adds exactly one bounds check / one lock / one refcount is a vulnerability fix by construction — the diff *is* the PoC description.
5. **Variant fan-out**: grep the codebase for the same pattern (P0: >40% of in-the-wild 0-days are variants of patched bugs); re-seed the fuzzer with the fixed bug's reproducer; in source-available targets feed the seed commit diff to an agent (Big Sleep pattern).

### Triage playbook (synthesized from the sources below)

- Sort the Matched Functions view by similarity **0.85–0.99** first — 1.0 is unchanged, <0.5 is usually recompiled noise (different compiler version, layout shift).
- Filter by module scope *before* eyeballing: bulletins/component lists (ASB for Android, CBS manifests for Windows) tell you where fixes landed; diff `win32k*/ntoskrnl/cng`, media codecs, GPU drivers, not the whole image.
- Prefer patches that add a single `memset`/bounds check/lock/refcount — one-semantic-edit diffs are vulnerability fixes; large rewrites are refactors (de-prioritize).
- Read the *unmatched* (new) functions too: fresh attack surface shipped alongside a fix often holds sibling bugs.
- For uninitialized-memory classes, diff **memset presence AND size operands** across versions (the Win8.1-vs-10 `0x400` vs `DWORD+0x3FC` quirk shows size-only changes are real fixes).
- Cross-version trick: fixes that land in one supported branch but not another (Win10-only, OEM-only) directly hand you a still-live 1-day — diff *sideways* across branches, not just forward in time.

### Session skeleton (how to lay out a pair-diff working dir)

```
1day/<vendor>-<component>-<yyyymm>/
  pair/            pre.<ext>, post.<ext>          # reconstructed binaries, LC_UUID/manifest-hash verified
  exports/         pre.DarwinX64.sqlite, post.*.sqlite   # Diaphora exports (reuse across months)
  diff/            out.sqlite                     # diaphora.py first.db second.db -o out.sqlite
  triage.md        shortlist: func | sim | conf | module | hypothesis | status(new/fixed/variant?)
  variants.md      pattern anchors + grep/audit results + sibling sites
  corpus/          pre-patch PoC/crash inputs for re-seeding fuzzers
```

- State the status of every shortlisted function explicitly (`fixed-here / still-live-elsewhere / refactor-noise`) — the whole value of the loop is the third column, and it is what cve-hunter's "does not prove the patch is missing" caveat needs closed.


---

## A. Patch pair acquisition — Windows (MSU / cumulative updates)

### Extracting and Diffing Windows Patches in 2020 (src: wumb0.in blog)
Author: wumb0
- Canonical MSU workflow. Microsoft Update Catalog search string: `YYYY-MM release-number (x86|x64|ARM64) cumulative`. Server builds often share identical downloads with matching Win10 builds; 1903/1909 share core files.
- Extract MSU then the inner PSFX cab (slow, ~78k files):
```powershell
expand.exe -F:* ".\windows10.0-kb4565351-x64_<hash>.msu" .\ext\
expand.exe -F:* ".\ext\Windows10.0-KB4565351-x64_PSFX.cab" .\patch\ | Out-Null
```
- Layout: arch-prefixed folders (`amd64`, `x86`, `wow64`, `msil`); delta subfolders `f` (forward), `r` (reverse), `n` (null/new). `.manifest` files carry file hashes — use them to verify reconstructed binaries.
- Deltas start with 4-byte LE CRC32 then `PA30` magic. Reconstruct real binaries with `ApplyDeltaB` from msdelta.dll via `delta_patch.py` (Python3+ctypes, also handles legacy PA19):
```powershell
python delta_patch.py -i ntoskrnl.exe -o ntoskrnl.2020-07.exe .\r\ntoskrnl.exe X:\...\2020-07\...\f\ntoskrnl.exe
python delta_patch.py -n -o vmcomputeagent.exe <path>\n\vmcomputeagent.exe   # new files
```
- Baseline trick: reverse deltas often already sit in `C:\Windows\WinSxS\` on a live system — `Get-ChildItem -Recurse C:\windows\WinSxS\ | ? {$_.Name -eq "ntoskrnl.exe"}`.
- PatchExtract.ps1 (Greg Linares, modified by wumb0) auto-sorts output into `JUNK/MSIL/PATCH/WOW64/x64/x86` (manifests/mum/cat go to JUNK).
- Diff step: open both in IDA, accept the PDB download prompt, let auto-analysis finish; close newer binary; BinDiff with new = secondary, old = primary.
> Same approach: worked example found `MmDuplicateMemory` patch adding a missing check that `KeWaitForSingleObject` returns `WAIT_OBJECT_0` — one-line semantic delta = candidate 1-day root cause.

### Decoding Windows CBS manifests / DCM PA30 delta format (src: Cobalt.io blog)
- Modern Windows patches are delta-compressed and do *not* unpack to plain binaries with `expand` alone; CBS manifests + PA30/DCM deltas must be decoded to recover target file versions.
- When delta application fails or output hashes mismatch the manifest, the manifest itself is ground truth for what shipped — parse it before blaming the diffing tool.
> Same approach: treat vendor packaging formats (delta encodings, manifests) as a first-class reversing target; pair reconstruction errors look exactly like "patch noise".

### Official scripts to recursively extract MSU/CAB (src: Microsoft Learn)
- Microsoft publishes a PowerShell script that recursively extracts `.msu` and nested `.cab` archives — the supported equivalent of repeated `expand -F:*`.
> Same approach: use for quick triage; fall back to delta_patch.py when the payload folders contain PA30-style deltas instead of full files.

## B. Patch pair acquisition — Apple (iOS/macOS dyld_shared_cache)

### ipsw: parse & extract from dyld_shared_cache (src: blacktop's ipsw docs)
- `ipsw` extracts standalone Mach-O dylibs **with proper symbol tables** out of the dyld_shared_cache — the standard preprocessing step before diffing iOS versions in BinDiff/IDA.
- Cache locations per OS version differ (legacy `/System/Library/Caches/com.apple.dyld/` vs modern Preboot/Cryptexes paths) — locate the right cache for each side of the pair first.
> Same approach: never diff raw cache blobs; extract per-dylib images so symbol-based matchers can fire.

### IDA 9.4: Apple dyld shared cache workflow improvements (src: Hex-Rays blog)
- IDA 9.4 ships improved dyld-cache loading, diffing and navigation workflows with proper symbol handling — first-class alternative to manual extraction.
> Same approach: check current-tool support before hand-rolling extraction; a vendor-supported loader removes rebase/symbol noise the matchers would otherwise eat.

### dscextract + Binary Ninja shared cache guide (src: Worth Doing Badly / Binary Ninja docs)
- dscextract: extracting working dylibs from the cache (Mach-O/Obj-C internals intact).
- Binary Ninja's shared-cache support lists all exported symbols with virtual addresses and can load individual images on demand.
- Practical issue: symbol resolution when opening caches is a recurring pain (binaryninja-api issue tracker); expect to fix up symbols before diffing.
> Same approach: pick the pair extraction path (ipsw / dscextract / native loader) per disassembler; always verify the extracted dylib's symbol count before diffing.

### Reversing iOS system libraries with radare2 — dyld cache deep dive (src: NowSecure blog, 2024)
- Deep-dive on how symbols and Objective-C classes are loaded from the dyld cache, and how to analyze the cache directly in radare2 — the FOSS path when no IDA/Binja license is at hand.
> Same approach: use as the format reference when extraction goes wrong (missing Obj-C metadata = wrong extraction, not a stripped binary).

## C. Patch pair acquisition — Android

### Android OTA full-image route (src: synthesis over AOSP tooling & security bulletin refs)
- Download two consecutive **full OTAs or factory images for the same device and build line** (security-patch-level N vs N-1); incremental OTAs also carry the delta but full images avoid delta-application issues.
- Unzip the `payload.bin` out of the OTA zip; extract partition images with a payload dumper (AOSP `payload_dumper` / payload-dumper-go). Convert sparse images before mounting:
```bash
unzip ota.zip payload.bin -d ota/
payload-dumper-go -o ota/out ota/payload.bin
simg2img system.img system.raw.img && mkdir mnt && hdiutil attach -nomount system.raw.img  # or mount -o ro on Linux
```
- Scope the diff with the **Android Security Bulletin** component list (media codecs/libstagefright, binder, Bluetooth, GPU drivers, system_server) — never diff the whole system image blindly; OEM partitions (vendor, odm) hold the vendor's own fixes the ASB doesn't describe.
> Same approach: for Pixel-vs-OEM comparisons, the *same* ASB patch often lands differently (or never — P0 documented OEMs that never synced an upstream kernel fix); the OEM lag is the 1-day window.

### AOSP source-tag diffing route (src: synthesis over AOSP release practice)
- Cheaper than OTA work and exact for the framework layer: diff consecutive AOSP security release tags; security commits carry redacted `bug: NNNNNN` tags with no CVE in the message:
```bash
git log old_tag..new_tag --grep="bug:" -i          # shortlist security fixes
git diff old_tag..new_tag -- <framework file>       # read the actual fix
```
- Map each `bug:` commit to the ASB entry by component + patch month; commits with no ASB match are either hardening or undisclosed fixes — prime variant-audit material.
- Kernel 1-day: diff the OEM kernel source drop (or prebuilt vmlinux/kallsyms) against upstream stable fixes; upstream commit messages name the subsystem and reporter, giving you the reproducer shape for free.
> Same approach: when binaries are too noisy (no symbols, heavy LTO), fall back to the source route and only open IDA for the final confirmation diff.

### IPSW pair acquisition skeleton (src: synthesis over Apple cache references)
- Download the two IPSWs bracketing the fix (same device, e.g. 20A362 → 20B50); mount the system volume DMG on macOS; collect the dyld_shared_cache (legacy `/System/Library/Caches/com.apple.dyld/dyld_shared_cache_X`, modern Preboot/Cryptexes paths) plus the specific framework dylibs if standalone on disk.
- Extract per-dylib images with `ipsw`/dscextract (section B), one directory per OS version, keeping names identical — the diff tools key on names first.
- For non-cached extensions/app daemons, diff the dylib/Mach-O files directly; verify you got both sides of the pair by comparing the target framework's build hash (LC_UUID) so you never diff two builds of the same version.
> Same approach: pair integrity (same dylib, adjacent builds, UUID-checked) matters more than tool choice — most "patch noise" reports are mismatched pairs.

## D. Diffing tools — BinDiff craft

> Tooling update: BinDiff has been open-sourced as `google/bindiff` (2023, v8+); at Google the BinDiff core engine powers a **large-scale malware processing pipeline** — the canonical example of running the matcher over huge corpora asynchronously/parallel. ("BinAsync" as a public tool does not exist; large-scale parallel diffing is done by wrapping the BinDiff engine, or with QBinDiff/Diaphora-parallel for automation.)

### BinDiff manual: core workflow (src: Zynamics BinDiff manual)
- Open one IDB → Ctrl+6 → Diff Database (Shift+D) → select the other IDB → Matched Functions subview. "Diff Database Filtered" limits the diff to an address range. Results save/load as `.BinDiff` files.
- Primary = currently open DB; secondary = the one compared against. "Primary/Secondary Unmatched" subviews list functions without counterparts — *new/removed code*, the other half of triage.
- Interpretation: **Similarity** (0–1) — 1 means identical mnemonics (operands/immediates may still differ); below 1 = changed code, sort by this to find patched functions. **Confidence** (0–1) — strength of the algorithm that produced the match; final similarity is multiplied by confidence. High similarity + low confidence = weak match, distrust it.
- Change column letters: G structural, I instruction, J jump, E entrypoint, L loop, C call — G/C on a security-sensitive function outranks I-only changes.
- Flowgraph view: green nodes identical, yellow matched-but-changed, red unmatched, (gray added). Right-click a match → View Flowgraphs.
> Same approach: triage order = (1) low-confidence high-similarity boundary cases, (2) similarity 0.85–0.99 in target modules, (3) secondary-unmatched (fresh code).

### BinDiff manual: matching algorithms (src: Zynamics BinDiff manual)
- Works on abstract graph structure, not raw instructions. Function signatures count codeblocks, edges, subfunction calls; matching runs globally, drills down through ambiguous attribute sets, then leverages callers/callees of confirmed matches plus basic-block and call-reference matching.
- Algorithm tiers (roughly by quality): hash matching (identical bytes) → name hash (real, non-autogenerated names only) → MD index variants → prime signature (structurally invariant product of instruction mnemonics) → string references → loop count → weak call-sequence/address-sequence.
- **Stripped binaries**: name matching never fires; MD index, prime products and string references (error-handling code keeps strings) do the work. Edge-Vector matching (1.8+) cut diffing time on large symbol-less disassemblies.
- Performance: edge-based matching is stronger but slower — disabling edge-matching algorithms is the first tuning step when diffing stalls.
> Same approach: rebasing is absorbed because matching keys on structure/strings/relative order, not absolute addresses; only "address sequence" matching needs equal-size equivalent sets.

### BinDiff manual: symbol porting & config (src: Zynamics BinDiff manual)
- Port symbols/comments: diff the fresh IDB against an old one containing your names/comments → Port Comments — matched-function names transfer (local variable names in target are overwritten).
- Config lives in `bindiff.xml`; algorithm order and confidence values are tunable but defaults are recommended.
> Same approach: after a productive diff session, port annotations back — month-over-month 1-day pipelines compound their symbol investment this way.

## E. Diffing tools — Diaphora craft

### Diaphora README: feature set & track record (src: Diaphora GitHub)
- IDA plugin (IDA 6.8→9.x), "most advanced FOSS program diffing tool". Standard: asm + CFG diffing, symbol/comment porting, manual match addition, similarity ratio, batch automation, call-graph matching, graph/asm/bytes/function-feature heuristics.
- Unique: porting structs/enums/unions/typedefs; **detection of potentially fixed vulnerabilities** (built for patch diffing); compilation-unit finding/diffing; Hex-Rays microcode support; parallel diffing; pseudo-code heuristics + patch generation + pseudo-code diff with syntax highlighting; scripting both export and diff stages.
- Documented patch-diffing hits: CVE-2020-1350 (SIGRed), CVE-2023-28231, CVE-2023-21768, PEGASUS iOS kernel bug fixed in iOS 9.3.5, MS15-034/MS15-050.
- Install: `hcli plugin install https://github.com/joxeankoret/diaphora/archive/refs/tags/3.4.2.zip` or drop into IDA `plugins/`.
> Same approach: AGPLv3 for 2.0+; the CVE list is the tool's regression suite — replicate those diffs as drills.

### Diaphora: headless automation (src: Diaphora wiki)
- Export an IDA database batch-mode:
```bash
export DIAPHORA_EXPORT_FILE=/path/to/database.db
export DIAPHORA_AUTO=1
ida64 -A -B -S/path/to/diaphora.py your_binary
```
- Diff two exports without IDA (pure Python):
```bash
export DIAPHORA_AUTO=1 DIAPHORA_AUTO_DIFF=1
export DIAPHORA_DIFF_OUT=/path/to/results.db
export DIAPHORADB1=/first.db DIAPHORADB2=/second.db
python /path/to/diaphora/diaphora.py
# or: python diaphora.py first.db second.db -o output.db
```
- Import results back into IDA:
```bash
ida64 -A -S"/path/to/diaphora_load_and_import.py output.db first.db second.db" your_binary.i64
```
- Tuning env vars: `DIAPHORA_MAX_PROCESSED_ROWS` (cap rows per heuristic query), `DIAPHORA_TIMEOUT_LIMIT` (per-heuristic seconds).
> Same approach: export once per version, keep the `.db`s — monthly patch cycles only pay the new export, then diff against the whole history.

### Diaphora: patch-diffing settings (src: Diaphora wiki)
- Diaphora was originally built for patch diffing, so **the default options are already the best for it**.
- One hard rule: on large databases the tool auto-enables speed options — "Relaxed calculations on difference ratios will be enabled"; **always disable this when doing patch diffing** or ratio numbers stop being trustworthy.
> Same approach: defaults for patch diffing; only deviate when diffing firmware-sized databases and accept the accuracy cost knowingly.

### Diaphora: heuristics & noise map (src: Diaphora wiki)
- 51 heuristics, executed in fixed order — order matters; tier labels:
  - **Best/very good**: same RVA + MD5 of bytes (or same order + hash), function hash (MD5 of non-relative bytes), bytes hash, identical asm or pseudo-code (incl. cleaned versions that strip `sub_XXX` autogenerated names), same address/nodes/edges/mnemonics; fuzzy hashes (DeepToad), fuzzy AST hash, Tarjan topological sort, pseudo-code fuzzy hashes (good, slower).
  - **Good**: same name; rare MD-Index, MD-Index + constants, most attributes, constants, mnemonics + names, SCC SPP, callgraph-based recursive matching (slow).
  - **Noise**: experimental set (small pseudo-code variants, low-complexity + names) rated poor→very poor; bytes-sum, SCC, loop count, SCC-SPP+names explicitly unreliable; brute-force above ratio 5.0 matches too much.
  - "Same graph" very slow, fails on >25k-function DBs with disk-full.
> Same approach: triage only Best/Good matches when precision matters; drop loop-count/bytes-sum matches to the bottom of the queue; for >25k-function images pre-split by module first.

### Diaphora: compilation units (src: Diaphora doc/articles)
- Diaphora can find and diff compilation units — group changed functions by CU to see *where* in the source tree the patch landed, collapsing hundreds of changed functions into a handful of edited source files.
> Same approach: CU-level view is the fastest "which subsystem got fixed" signal before reading any single function.

### Diaphora: known operational problems (src: Diaphora wiki index)
- Wiki documents the recurring failure modes to plan around: export takes too long; `MemoryError` on huge databases; temp folder fills up (the >25k-function "Same graph" disk-full case); IDA 7.x crashes during use.
> Same approach: pre-empt by splitting huge modules before export, pointing TMPDIR at a big disk, and keeping exports small (scope to the module under patch).

## F. Project Zero methodology — patch diffing, in-the-wild & variant analysis

### Using Binary Diffing to Discover Windows Kernel Memory Corruption Bugs (src: Project Zero blog, 2017)
Author: Mateusz Jurczyk
- The canonical P0 patch-diffing post. Core idea: diff syscall-handler code between **concurrently supported Windows versions** (7/10, 8.1/10) — security fixes and hardening applied only to Win 10 implicitly reveal bugs still live in 7/8.1. Disclosure fixes are the easiest to spot: they add a `memset`, not a buffer-size change.
- Method: decompile both sides to Hex-Rays .c listings; count `memset` references per top-level `Nt*` handler (direct calls and inlined `rep stosd` both decompile to `memset`; small zeroing `mov` sequences get missed and handled as false positives); sort alphabetically; textual diff the two lists.
- Triage: keep only functions with *more* memsets in the new version; filter out newly-introduced routines (check old-version function lists); manually investigate each survivor.
- Yield: Win7-vs-10 → 153 ntoskrnl functions (8 syscall handlers) + 89 win32k (16 handlers); Win8.1-vs-10 → 127 + 67. Two new CVEs: `NtGdiGetFontResourceInfoInternalW` (CVE-2017-8684, ~92-byte stack leak; pool branch safe because `PALLOCMEM` zeroes) and `NtGdiEngCreatePalette` (CVE-2017-8685, up to 1 kB stack leak with NULL source pointer + `bSafeReadBits` success).
- Cross-branch ammunition: `NtGdiEngCreatePalette` was fixed in Win 8 but left Win 7 exposed — vendors patching inconsistently across supported branches both expose users and hand researchers attack vectors.
- Refinement worth stealing: diff memset **size operands**, not just presence (manual `first-DWORD + memset 0x3FC` vs single `memset 0x400` was a real fix).
- Explicitly "low hanging fruit": pseudocode-level diffing with little OS-internals expertise found these CVEs cheaply.
> Same approach: a counting-anchors diff (memsets, locks, size constants, `ProbeForRead` calls) over decompilations beats full CFG diffing for specific bug classes — script it before reaching for BinDiff.

### Root Cause Analyses for 0-day In-the-Wild Exploits (src: Project Zero blog)
Author: Maddie Stone
- Rationale: a detected+exploited 0-day is a learning opportunity — "we need to use that as an opportunity to learn as much as possible… if we hope to make 0-day hard"; goal is concrete follow-ups: better detect, better lock down, prevent introduction.
- RCA template fields: **bug class; vulnerability details** (trigger + capability); **exploit method** (and whether it's a known technique); **hypothesis of discovery** (audit / fuzzing / variant analysis — inferred, never claimed); **historical/present/future context** (related past bugs); **variant analysis** (where to look, what was found); **structural improvements** (kill the bug class vs patch one instance); **detection methods** (catch similar bugs *while still 0-day*, explicitly not IOCs).
- Method: facts first (vuln + exploit), then hypotheses and prevention brainstorming.
> Same approach: adopt this template as the 1-day writeup format — the variant-analysis field is what turns one patch into a CVE family.

### 0-days In-the-Wild RCA database (src: Project Zero 0days-in-the-wild site)
- Since 2019 P0 systematically studies in-the-wild 0-days; maintains a public tracking spreadsheet of detected in-the-wild exploits and publishes an RCA per bug, aiming for timeliness.
- Standardized RCA template lives in their GitHub repo; outside researchers contribute analyses via pull requests.
- Coverage 2019–2024: Chrome/V8, Windows kernel & font drivers, IE, Safari/WebKit, Android kernels & GPU drivers, etc.
> Same approach: mine this database for per-bug-class patterns before starting your own variant hunt — it is a pre-sorted curriculum of "patch → root cause → where variants live".

### In-the-wild series: October 2020 (src: Project Zero blog)
Author: Maddie Stone
- 7 0-days in one month: FreeType heap overflow (Chrome, CVE-2020-15999), cng.sys (CVE-2020-17087), V8 TurboFan type confusion (CVE-2020-16009), Chrome-Android sandbox escape (CVE-2020-16010), Safari font stack R/W (CVE-2020-27930), XNU memory disclosure via mach message trailers (CVE-2020-27950), XNU type confusion with turnstiles (CVE-2020-27932). Delivered via watering holes → two exploit servers; fingerprinting on IP origin + user-agent.
- Patterns: when FreeType was patched, the exploit server swapped in a fresh V8 0-day within days — attackers monitor patches and hold replacements; assume retool capability.
- Attribution craft: same actor as a Feb 2020 operation (11+ 0-days/year); two servers = two coordinated operators (shared FreeType renderer bug, different surrounding code, different takedown times).
- Every platform used distinct anti-analysis; iOS encrypted exploits with ephemeral keys, forcing active MITM to recover.
- Lesson: deep RCA per 0-day + campaign context reveals operational fingerprints (shared bugs, timing, obfuscation style) usable for actor tracking.
> Same approach: when you find one exploit server, patch-diff *everything* it served — the bug cache exposed at once is a variant-analysis goldmine.

### The More You Know, The More You Know You Don't Know (src: Project Zero blog)
Author: Maddie Stone
- 2021 review: **56 of 58** in-the-wild 0-days matched previously public bug patterns, attack surfaces or exploitation techniques; only the FORCEDENTRY pair was genuinely novel → variant analysis is the dominant offensive model.
- Variant chains: Chromium webaudio race CVE-2021-21166 mirrored 2019 CVE-2019-13720 (same missing main/audio thread lock, different Handler) and existed in WebKit too (CVE-2021-1844); CVE-2021-30632 ~ CVE-2020-16009 (both failed deopt after map change); Safari IndexedDB CVE-2021-30858 ~ Chromium bug fixed Jan 2020; macOS CVE-2021-30869 a "pretty close variant" of CVE-2020-27932, found by a researcher doing variant analysis.
- **Incomplete fixes**: CVE-2022-21882 (first 0-day of 2022) worked because CVE-2021-1732 "actually was not fixed completely" — patch completeness must be verified by variant analysis after every fix.
- **Patch lag**: all known in-the-wild Android kernel 0-days were known upstream before exploitation; CVE-2021-0920's fix was drafted on LKML in 2016, merged only in 2021; CVE-2021-1048 sat ~14 months unfixed in Android after upstream Linux fixed it; some OEM devices never synced.
- Stats to aim at: 58 total, 39 (67%) memory corruption (17 UAF); Win32k share fell 75%→20% after Windows 7 EOL hardening; 5 of 7 Android 0-days hit GPU drivers (Adreno+Mali covers most devices — economic targeting).
> Same approach: for defenders P0 prescribes systematic variant mining of fixed bugs; for us that *is* the 1-day job description.

### From Naptime to Big Sleep: LLM-driven variant analysis (src: Project Zero blog)
- P0's definition: variant analysis = looking for new bugs resembling previously found and patched ones; >40% of in-the-wild 0-days were variants of known bugs, showing fuzzers miss variants.
- Cost model: attackers study a patched bug and hand-find similar unfixed ones — cheap; manual variant analysis is equally cost-effective for defenders.
- Big Sleep workflow (P0 + DeepMind): give an LLM agent a **seed commit's message + diff**, ask it to examine current repo HEAD for related unfixed issues; agent forms hypotheses, browses source, builds and runs test cases in a debugger, adapts on failure, emits RCA + crash report.
- First public AI-found exploitable bug: SQLite stack buffer underflow in `seriesBestIndex` (`ext/misc/series.c`) — `iColumn` may hold the ROWID sentinel `-1`; code assumed non-negative; `aIdx[iCol]` writes below the stack buffer in release builds. Trigger: `SELECT * FROM generate_series(1,10,1) WHERE ROWID = 1;` Found and fixed same day, pre-release.
- Why fuzzing missed it: OSS-Fuzz harness didn't enable generate_series; the fuzzingshell.c harness had an older unaffected version; even 150 CPU-hours of AFL with correct keywords failed — coverage is not a reliable guide for variants.
- Caveats: highly experimental; found bug only loosely related to seed; agent reasons vaguely pre-crash but explains well post-crash.
> Same approach: the seed-commit-diff → hypothesis → verify loop works manually too — after every patch you diff, write the pattern as a hypothesis list and grep/audit against the whole tree.

### Fuzz seed reuse after a patch (src: synthesis — Big Sleep + 2021 0-day review, both above)
- Why: fuzzers demonstrably miss variants of known bugs (P0: >40% of in-the-wild 0-days were variants; 56/58 matched known patterns) — coverage does not lead you to a variant sitting behind a different entry path.
- After root-causing a fixed bug, do three things in order:
  1. Add the fixed bug's reproducer/crash input to the fuzzer corpus (the *pre-patch* PoC, not the patched binary's output).
  2. Check the harness actually reaches the patched code — Big Sleep's SQLite bug survived 150 AFL CPU-hours because `generate_series` wasn't enabled in the OSS-Fuzz harness; harness coverage beats raw CPU time.
  3. Grep the tree for the same anchor pattern (missing lock pair, unchecked length, `-1` sentinel assumption) — manual variant audit, then fuzz each candidate site.
- If a variant exists in a sibling product (Chromium webaudio ↔ WebKit audio), port the seed and the harness both — P0 repeatedly found the "same" CVE alive in the other vendor's tree.
> Same approach: treat every patch you triage as a fuzzing investment, not just a report — the seed corpus is the compounding asset.

## G. Monetization / reporting surface

### MSRC bounty program structure (src: Microsoft MSRC blog & bounty portal)
- MSRC pays cash for vulnerabilities and exploitation techniques across programs; applications/on-prem servers tier $500–$30,000 including third-party and OSS components; recent year in review reported $20M+ to 562 researchers.
- Submission must go through the MSRC Researcher Submission process to be award-eligible.
- Severity bar is real: researchers report Moderate-severity confirmations with no bounty ("below the bar for immediate servicing") — triage patch-diff findings toward RCE/EoP/remote surfaces before reporting.
> Same approach: patch-diff output maps naturally to bounty reports (patch proves the bug class, your variant proves it's unfixed elsewhere); pick the program whose scope covers the module you diffed.

---

## H. Regression drills (practice curriculum)

- The Diaphora README's documented hits double as known-answer drills — each has a public patch pair and a public root cause, so you can grade yourself:
  1. **CVE-2020-1350 (SIGRed, Windows DNS `dns.exe`)** — RPC-reachable RCE; classic single-check patch in name parsing.
  2. **MS15-034 (HTTP.sys `HTTP.sys` range header)** — one bounds check on `HttpParsingHelper`/`UlParseRange`; the textbook "patch adds validation" diff.
  3. **PEGASUS kernel bug, iOS 9.3.5** — dyld-cache pair drill: extract kernel/Extension dylibs from 9.3.4 vs 9.3.5 IPSWs first.
  4. **CVE-2023-21768 / CVE-2023-28231 (Windows ancillary function driver / RADIUS)** — modern cumulative-update deltas; exercises the full MSU → PA30 → delta_patch.py chain.
- Jurczyk's 2017 exercise (count `memset` per `Nt*` handler, Win7 vs Win10) is the zero-IDE drill: needs only Hex-Rays listings and a text diff.
- Pass criteria per drill: recover (a) the changed function set, (b) the root cause line, (c) a variant hypothesis list of ≥3 sibling sites — training exactly the loop this file documents.

## Dedup note (against cve-hunter)

cve-hunter (`re/cve-hunter/README.md`) does known-CVE × version-string matching over OpenWrt SBOM and explicitly states version match "does not prove the patch is missing". Everything in this file — pair acquisition, delta decoding, binary diffing, similarity/confidence triage, variant fan-out — is new capability. Natural composition: cve-hunter's ledger seeds *which* component versions to pair-diff; this file's loop supplies the proof.

## Sources

- Project Zero blog (fetched via projectzero.google mirror; googleprojectzero.blogspot.com timed out from this network):
  - Using Binary Diffing to Discover Windows Kernel Memory Corruption Bugs (2017-10) — https://projectzero.google/2017/10/using-binary-diffing-to-discover.html
  - Root Cause Analyses for 0-day In-the-Wild Exploits (2020-07) — https://projectzero.google/2020/07/root-cause-analyses-for-0-day-in-wild.html
  - In-the-wild series: October 2020 (2021-03) — https://projectzero.google/2021/03/in-wild-series-october-2020-0-day.html
  - The More You Know, The More You Know You Don't Know (2022-04) — https://projectzero.google/2022/04/the-more-you-know-more-you-know-you.html
  - From Naptime to Big Sleep (2024-10) — https://projectzero.google/2024/10/from-naptime-to-big-sleep.html
- 0-days In-the-Wild RCA database — https://googleprojectzero.github.io/0days-in-the-wild/rca.html
- Diaphora (joxeankoret): README — https://github.com/joxeankoret/diaphora ; wiki pages "How can I automate the diffing process?", "Using Diaphora for patch diffing", "Heuristics and their explanation", wiki index — https://github.com/joxeankoret/diaphora/wiki ; doc/articles — https://github.com/joxeankoret/diaphora/tree/master/doc/articles
- BinDiff manual — https://www.zynamics.com/bindiff/manual/ ; open-source repo — https://github.com/google/bindiff ; Google Security Blog: BinDiff free / large-scale malware pipeline — https://security.googleblog.com/2016/03/bindiff-now-available-for-free.html
- wumb0: Extracting and Diffing Windows Patches in 2020 — https://wumb0.in/extracting-and-diffing-ms-patches-in-2020.html (PatchExtract gist: https://gist.github.com/wumb0/306f97dc8376c6f53b9f9865f60b4fb5)
- Cobalt.io: Decoding Windows CBS Manifests / DCM PA30 delta — https://www.cobalt.io/blog/decoding-windows-cbs-manifests-reversing-the-dcm/pa30-delta-format
- Microsoft Learn: scripts to extract .msu and .cab — https://learn.microsoft.com/en-us/troubleshoot/windows-server/support-tools/scripts-extract-msu-cab-files
- blacktop ipsw dyld guide — https://blacktop.github.io/ipsw/docs/guides/dyld
- Hex-Rays: IDA 9.4 Apple Dyld Shared Cache workflow improvements — https://hex-rays.com/blog/ida-9-4-apple-dyld-shared-cache-workflow-improvements
- Binary Ninja Shared Cache guide — https://docs.binary.ninja/guide/sharedcache.html ; dscextract — https://worthdoingbadly.com/dscextract ; NowSecure radare2 dyld series — https://www.nowsecure.com/blog/2024/09/11/reversing-ios-system-libraries-using-radare2-a-deep-dive-into-dyld-cache-part-1
- MSRC bounty portal / blog — https://www.microsoft.com/en-us/msrc/bounty ; https://www.microsoft.com/en-us/msrc/blog
- Blocked/failed fetches: googleprojectzero.blogspot.com (timeout ×2), orangecyberdefense.com intro-to-binary-diffing part 3 (403), Medium CVE-2019-1388 RCA (timeout) — content not used; listed for later retries.
