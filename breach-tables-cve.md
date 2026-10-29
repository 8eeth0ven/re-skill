# Breach Tables — CVE (Master Router)

> When you get a target, first pick the **category file** here and go shoot; each category has ≥20 rows of plays (what to recognize | where to hit | what counts as a hit | false leads). Opening all categories at once is forbidden. Branch capabilities / missing environments: `re-to-cve-audit.md`; whom to submit to: `disclosure-cve.md`. Surfaces absent from the table are still fair game.
> Universal hit criteria: CVE-worthy = the three questions **security-policy violation + exploitability proof + impact scope**; in-house forks / requires existing root / requires physical access / purely theoretical DoS usually get no ID.

| The target looks like this | Enter which category | One signature shot for that category |
|-----------|-----------|--------------|
| Routers / cameras / IoT devices / firmware bins / RTOS | [breach-tables/firmware.md](breach-tables/firmware.md) (27 rows, the CVE-grinding main force) | binwalk extracts cgi-bin → grep for backdoor credentials + system with attacker-controlled args |
| Open-source C/C++ libraries / parsers / kernel modules | [breach-tables/open-source.md](breach-tables/open-source.md) (24 rows) | A parser library absent from the OSS-Fuzz coverage list → one AFL++ shot |
| Android apps / SDKs / ROMs / head units | [breach-tables/android.md](breach-tables/android.md) (25 rows) | A .so exporting only JNI_OnLoad → RegisterNatives recovers the dynamic registration table |
| Windows drivers / kernel / desktop services | [breach-tables/windows.md](breach-tables/windows.md) (23 rows) | Signed driver with a missing DACL → IOCTL elevation, fire at METHOD_NEITHER |
| Electron / CEF / installers / extensions / game assets / supply chain | [breach-tables/desktop-and-ecosystem.md](breach-tables/desktop-and-ecosystem.md) (25 rows) | Custom-protocol parameter injects a URL → probe process/require |
| Browser kernels V8 / Chromium sandbox & IPC / extensions / SW | [breach-tables/browser-and-v8.md](breach-tables/browser-and-v8.md) (24 rows) | Typer boundary of a new API's first implementation → --trace-turbo to find the first wrong node |
| Cross-platform target picking / reproduction / anti-collision / submission / wrap-up for any platform | [breach-tables/general-and-wrapup.md](breach-tables/general-and-wrapup.md) (26 rows) | Trace a fix commit back to same-pattern call sites (incomplete patch = new ID) |

## Three Quick Rules

1. When reversing stalls, think **trace** first (who calls X → function-level; execution flow → Stalker with volume capping; syscall surface → eBPF) — see the decision tree in `techniques/13-trace/trace-practice.md`
2. **Firmware is the CVE-grinding main force** (broad surface, slow vendor response, impact easy to prove) — prefer starting from firmware.md
3. Check the "false leads" column of each row before concluding; once a hit is in hand, pass the three questions before entering the disclosure flow

**Local batch-candidate workbench**: when you don't want a single target but want to grind surfaces in batch, two complementary routes — `cve-hunter/` (known CVE × version matching, an N-day ledger that ranks and picks targets) + `fw-discover/` (**autonomous discovery**: unpack DD-WRT/OpenWrt public firmware → six rule classes — shadow accounts / factory private keys / network-facing command-injection flows / telnetd / default passwords — mining 0day candidates, target 100 entries, 30-minute keepalive). Everything both produce is candidates; external reporting still goes through a human.

**N-day template library**: `breach-tables/poc-reuse-nday.md` (distilled from a full pass over nomi-sec/PoC-in-GitHub filtered for RE-relevant 873 CVEs) — before attacking a new surface, check the ten hot buckets for already-weaponized bugs on the same surface to use as templates; five localization routes (commit archaeology + official regression tests / patch-diff back-inference / half-applied patches / freshly merged refactor windows / disclosure-with-self-written-exploit), a data-only anti-mitigation primitive spectrum, standard environment-engineering parts, and six fake-PoC detection rules.

## Focused N-day Reference

Open the [PoC reuse and N-day playbook](breach-tables/poc-reuse-nday.md) when a
matched component needs source/patch archaeology, version comparison, or PoC
authenticity checks. Its recorded counts and conclusions retain their stated
historical scope; a candidate is not a current verified vulnerability.
