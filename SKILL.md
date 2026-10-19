\---  
name: re  
description: |  
Unified reverse engineering skill (single entry · multiple branches): one entry routing to platform taxonomy / technique systems / fully automated execution / tool radar.  
Branches: ① Platforms (Windows/Android/Linux/iOS/WEB/binary vulnerabilities/smart devices/business/AI/blockchain/root-cause analysis)  
② Techniques (frida/unpacking/attack-and-evasion/traffic capture/pure algorithm restoration/kernel-level/function panorama/syscall chains/bypass decisions/AI RE)  
③ Automated execution (input APK → report with zero human effort) ④ Tool radar (discover new tools daily and smoke-test them).  
Trigger this skill when the user mentions any of the following keywords:  
reverse engineering, Android RE, iOS RE, IoT, frida, hook, unpacking, traffic capture,  
SSL pinning, anti-debugging, root detection, app packers, OLLVM, obfuscation, VMP, algorithm restoration, risk control,  
RPC, syscall, eBPF, kernel hook, bypass, RASP, pwn, CTF, vulnerability root cause,  
unidbg, full-chain execution, tool radar, MCP tools such as frida-mcp/jadx-mcp/ghidra-mcp.  
Trigger even when the user only says "look at this app's encryption", "how do I reverse this .so", or "run the pipeline".  
\---

# Unified Reverse Engineering Skill re (Single Entry · Multiple Branches)

One entry, four branches. **First ask "what situation am I in" — for the scenario-driven full usage guide see [`usage-scenarios.md`](usage-scenarios.md) (6 SRC field scenarios / 3 attack-and-evasion scenarios / 3 audit-assist scenarios / 3 learning scenarios / 3 automation commands / the boundary where re is NOT used)**; then pick a branch by need, enter the branch INDEX and open articles by name (full reads are forbidden).

**Real-device testing**: once a phone/microcontroller is plugged in, say "run real-device / serial validation" → it follows `device-testing.md` autonomously (full chain including protection discipline: no flashing, no firmware burning, no touching system partitions; frida-server for three architectures is prepared under tools-env/frida-server/).

**Unattended mode**: just say "unattended: reverse <apk> / hunt CVEs for <target>" and it runs end to end fully automatically — the master task brief and red lines are in [`unattended.md`](unattended.md).

**One-sentence summary**: stuck at "can't see it (no app traffic) / can't get in (packers · detection) / can't compute it (signature encryption) / being countered (hooks killed)" → use this skill; "got an API, test it for bugs" → skill; "got the source code" → secure-code-audit.

## Branch Routing (the single entry decision table; if unsure which branch, read usage-scenarios.md first and match your situation)

| What you want to do | Which branch | Entry |
| -------------- | ----- | ------------------------------------------------------------------------------------ |
| **Learn or look things up by platform/domain** (Windows/Android/iOS/Linux/WEB/binary vulnerabilities/smart devices/business/AI/blockchain, plus the cross-domain "root-cause analysis of vulnerabilities") | Platforms branch | `platforms/INDEX.md` (11 zones, every article tagged "when to open it") |
| **Work by technique** (hook/unpacking/evasion/traffic capture/algorithm restoration/offline RPC/kernel-level/bypass decisions/chain timing/AI RE) | Techniques branch | `techniques/INDEX.md` (11 zones) + the "quick technique picker" below |
| **Look up concrete cases / old techniques / era evolution** (how to unpack a given packer / packer evolution history / some program's registration algorithm / family samples / protocol restoration cases) | Corpus branch | `corpus/INDEX.md` (all 18915 articles semantically deduped and distilled, nine categories, entry = chapter name + author) |
| **Automated work**: produce a report from an APK, zero human effort | Execution branch | `pipeline/pipeline.md` (five-stage DAG with acceptance gates and fallbacks; environment health check `pipeline/env_check.sh`) |
| **Want a CVE / find bugs fast against a target** | First open `breach-tables-cve.md` (recognize the signature → one shot → hit criteria → false leads; 6 forms, 19 rows) | Branch capability: `re-to-cve-audit.md`; disclosure: `disclosure-cve.md`; **local batch candidate grinding**: `cve-hunter/README.md` (known CVE × version matching, N-day ledger) + `fw-discover/README.md` (**autonomous discovery**: unpack public router firmware → six rule classes mining 0day candidates, 30-minute keepalive) |
| **Find/fill in tools**, or see what new tools the daily automation discovered | Radar branch | `radar/README.md` (process) + `radar/发现日志.md` (daily 09:00 automatic: discover → catalog → local smoke test) + `techniques/05-toolbox/tool-master-table.md` |
| **First use on a new machine** | Environment init | Run [`setup.md`](setup.md) first |

## Quick Technique Picker (direct routes for high-frequency tasks; see techniques/INDEX.md for details)

| Task | Open first |
|------|------|
| **A function is detected / one line of thinking fails** | `techniques/12-bypass/bypass-playbook.md` (detection points × multiple bypass routes × applicability) |
| Writing a frida hook | `techniques/02-frida/java-layer` + `techniques/02-frida/native-hook-cheatsheet.md` (call up by domain/topic) |
| Unpacking | `techniques/03-unpacking/` (frida → eBPF progression) |
| Traffic capture (generic → per-vendor) | `techniques/04-evasion/capture-all-scenarios.md` → `techniques/04-evasion/vendor-capture-countermeasures.md` (key functions for 16 vendors incl. ByteDance/Alibaba/WeChat/Meituan) |
| Defeating risk control / device fingerprinting | `techniques/04-evasion/device-fingerprint-risk.md` |
| Pure algorithms / white-box / deobfuscation / offline RPC | the three articles in `techniques/10-algo-restore/` |
| Hook killed; find a deeper function | `techniques/09-function-map/` (five-layer mapping + fallback chain) |
| The full call chain down to the kernel | wrap up with `techniques/11-syscall-chain/observation-matrix.md` |
| Why the bug exists at all (root cause) | `platforms/11-root-cause/` (six major classes + ten kernel cases + mapping table) |

| **Locate common functions in 30 s / NOP patches / simple bug patterns** | `techniques/16-quick-ref/quick-reference.md` (16-row locating table + patch bytes for five architectures, self-verified on this machine) |

## Tool Environment (shared by branches 3/5)

- CLI: jadx/apktool/radare2 (r2)/adb/7z (brew family)
- The python stack lives in `tools-env/.venv` (frida 17.x/unicorn/capstone/androguard/ropper/apkid/apkleaks); **installing packages requires**: `UV_CACHE_DIR=/tmp/uv-cache uv pip install -p tools-env/.venv/bin/python <package>` (the sandbox forbids ~/.cache; the venv has no pip)
- For live MCP status see `radar/MCP测试报告.md` (android-emulator is automatable; IDA needs the plugin started manually; FOFA has no key; iOS has no Xcode)

## Usage Rules

1. After picking a branch from the single entry, use that branch's INDEX as the router and open 1-2 articles by name; full reads are forbidden
2. Body-text conventions: ideas and code only, no external links / attributions / personal names; corpus attributions go through the data/ index
3. Saying "run the full chain" to an APK enters the pipeline branch (see `pipeline/README.md` for the reference artifact structure)
4. All test values / hook output / probes follow `test-values.md` ([RE] prefix / 0x52455052 magic value / REPROBE-date sequence numbers; high-collision values like 0x42/deadbeef are forbidden); at wrap-up, grep the value family to confirm zero residue
5. Ingesting new knowledge: techniques → the matching techniques/ zone, platforms → the matching platforms/ zone, new tools → the master table + radar baseline (a smoke test is mandatory on ingestion)
5. The library's known legacy-defect list is in `自检报告.md` (read it before changes to avoid re-stepping on known mines); the radar's current tool status is in `radar/MCP测试报告.md` and `radar/工具测试报告.md`
6. SSL-pinning knowledge hierarchy: `techniques/04-evasion/ssl-pinning-bypass.md` is the primary article; java-layer/sslpinning-and-certificates.md (scripts), capture-all-scenarios.md (scenarios), and the per-vendor archive (by vendor) are subordinate; on conflict, the primary article wins
8. Moving to a new machine: run `setup.md` first (the AI installs the environment automatically); the radar scheduled task must be rebuilt on the new machine per radar/README
