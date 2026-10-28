# re Skill Usage Scenarios (When to Use · How to Use · The Full Picture)

> Knowledge that isn't anchored to scenarios is meaningless. **When the human is away**: the single sentence "unattended: …" goes through the unattended.md master control (fully automatic; only external submission / spending / actions beyond the authorization boundary are left on file). This document is organized by **real situation**: each scenario = trigger signal (what you're experiencing) → entry (which article to open) → steps → output → handoff to the next step. The complete entry-routing version is in [SKILL.md](SKILL.md); this is the plain-language version.

## I. SRC Field Work (The app provides the target's prerequisite analysis surface)

**re's role in SRC**: your goal is vulnerabilities, but the app hides the APIs — re handles "surface acquisition" (APIs/parameters/signatures); once acquired, hand off to `skill` (the SRC library) for vulnerability testing.

### Scenario 1: "The target is only an app; no web surface to be found"
- **Steps**: ① inspect the APK with the Android runner/static stages for components, exported Activities, sensitive strings, and URLs; use `pipeline/pipeline.md` S0–S4 only when the task calls for its dynamic chain (the historical small-sample full run took 9 minutes, not a runtime guarantee) → ② follow `techniques/04-evasion/capture-all-scenarios.md` and its scenario matrix to capture the API inventory → ③ hand the API list + parameters to skill (SRC) and attack with the idor-test/injection-test matrices
- **Output**: an API-surface inventory → SRC vulnerabilities
- **Handoff**: if the APIs turn out to have signature parameters, go to Scenario 3

### Scenario 2: "Can't capture the app's traffic" (high frequency)
- **Triage order** (the breakpoint-locating table at the top of capture-all-scenarios.md): no traffic through the proxy at all → VPN link; traffic but all TLS → certificate (Android 7+/14+ approaches); certificate installed but still failing → pinning (`techniques/04-evasion/ssl-pinning-bypass.md`); pinning bypassed but payload still garbled → encrypted traffic (Burp plaintext bridging); app detects proxy/VPN → iptables transparent proxy; nothing works → proprietary protocol (r0capture for a pcap)
- **Specific vendor**: check `techniques/04-evasion/vendor-capture-countermeasures.md` first (network stacks and key functions for 16 vendors incl. ByteDance/Alibaba/WeChat/Meituan — it tells you directly whom to hook)
- **Output**: plaintext requests/responses
- **Handoff**: signature/encryption parameters → Scenario 3

### Scenario 3: "The API has sign/token/encrypted parameters; replays get rejected"
- **Entry**: `techniques/10-algo-restore/algo-restoration-methodology.md` (identify the algorithm → white-box AES/DFA → identify modified crypto) → if the .so won't yield, `techniques/10-algo-restore/protocol-offline-rpc.md` (frida RPC lets the app compute for you — no restoration needed)
- **Output**: the ability to freely construct parameters (pure algorithm, or an RPC service)
- **Handoff**: offline batch replay to test logic bugs (races/idempotency); the testing part goes to skill

### Scenario 4: "The app crashes/pops a dialog the moment frida attaches"
- **Entry**: `techniques/12-bypass/bypass-playbook.md` — first pin the cause of death from the failure-signal table, then check the bypass-route matrix for that detection point (applicability + recommended order)
- **Depth**: detection principles in `techniques/04-evasion/detection-landscape.md` (identify the layer first); commercial RASP in `techniques/04-evasion/rasp-bypass.md`; if all fails, `techniques/07-kernel/` (traceless)
- **Output**: a stable environment you can attach/hook

### Scenario 5: "Need to see the logic of an old / delisted app version"
- **Entry**: find historical APKs (Coolapk/tmi) → `techniques/03-unpacking/` (identify the packer with APKiD first: `techniques/05-toolbox/recon-and-specials.md`) → unpack → jadx
- **Output**: readable source

### Scenario 6: "H5 / mini-program / hybrid app"
- **Entry**: the UNI-APP/mini-program section of capture-all-scenarios.md; mini-program PC client + Proxifier; the JS part goes to skill's js-reverse-guide

## II. Attack and Evasion (the arms race of detection and countermeasures)

### Scenario 7: "Hooking a function has no effect / the function got copied into the .so"
- **Entry**: `techniques/09-function-map/hook-fallback-playbook.md` (four-cause decision tree) → look up `techniques/09-function-map/android-function-layers.md` for a deeper-layer function with the same functionality → for direct svc-invocation surfaces see the svc interception compendium
- **Iron rule**: whichever layer the detection lives in, the bypass must be at that layer or deeper

### Scenario 8: "Ran into a detection technique I've never seen"
- **Entry**: match it in `techniques/04-evasion/detection-landscape.md` (detection written down to the syscall layer); no match → dynamic localization (the locator method in detection-bypass-snippets.md)

### Scenario 9: "Need long-term residence without being caught" (deep adversarial work)
- **Entry**: `techniques/07-kernel/kernel-hook-stealth.md` (wxshadow, traceless) → `techniques/07-kernel/kernel-symbol-locating.md` (locate the target in the kernel first) → the ANDROID-MRI approach
- **Boundary**: this layer is expensive; use it only after user mode has fully failed

## III. White-box Audit Assistance

### Scenario 10: "The audit target contains obfuscated .so files / a crypto black box"
- **Entry**: `techniques/10-algo-restore/deobfuscation-practice.md` (8 obfuscation classes matched one by one + four flattening routes + five VMP steps)

### Scenario 11: "Want to truly understand why a class of bugs exists" (audit internals)
- **Entry**: `platforms/11-root-cause/memory-error-root-causes.md` (six major code-pattern classes) → `platforms/11-root-cause/kernel-vuln-root-cause-cases.md` (ten cases dissected at source level) → when auditing, use the seven-stack grep lists of `platforms/11-root-cause/root-cause-to-technique-map.md`
- **Handoff**: the source-audit proper goes through the secure-code-audit skill

### Scenario 12: "Replaying a CVE / reading historical analyses"
- **Entry**: the matching article in the matching platforms zone (e.g. V8 → `platforms/06-binary-vuln/vuln-types-exploitation.md`; the kernel ten cases → `platforms/11-root-cause/kernel-vuln-root-cause-cases.md`)

## IV. Learning and Growth

### Scenario 13: "Systematically learn a platform" (Windows RE / iOS RE / IoT…)
- **Entry**: read the zone in order from `platforms/INDEX.md` (2-10 articles per zone; the Windows zone follows the *Encryption & Decryption* system)
- **Practice**: the KCTF problem table in platforms/06

### Scenario 14: "Quickly look up a concept/function/term"
- Direct examples: "what is Nterp" → techniques/11-syscall-chain/dex-load-exec-chain.md; "tcache double free" → platforms/06 heap exploitation; "/dev/tun" → techniques/11-syscall-chain/network-chain.md; "which packer is this .so" → `techniques/05-toolbox/recon-and-specials.md`
- **How to look up**: SKILL.md quick-picker table → INDEX → open by name

### Scenario 15: "Find a tool"
- Known need: the selection decision tree in `techniques/05-toolbox/tool-master-table.md`
- Want to see what's new lately: `optional-local:radar/discovery-log.md` (updated by configured daily runs or manual rounds)
- **Runs daily at 09:00 when a host schedule is configured**: the radar discovers new tools → evaluates → catalogs → smoke-tests locally. Copying the library does not create the schedule; see `setup.md` §7

## V. Automation (driven by a single sentence)

| You say | What happens |
|------|---------|
| "Run the full chain on /path/xx.apk" | Explicit local-APK S0–S4 request: dual static engines → packer verdict → hook candidates → selected test-emulator dynamics → seven-section report; blocked capabilities remain explicit. Static information/report requests use the runner without automatically starting an emulator (runtime varies; see pipeline budgets). |
| "Run one round of the tool radar" | Immediately executes one round manually: discover → catalog → smoke test |
| "Environment health check" | `python3 pipeline/env_check.py` (cross-platform preferred; `env_check.sh` is the legacy macOS fallback; historical green/yellow counts are not a current health verdict; run after installing new tools) |

### Scenario 16: "Want the AI to reverse fully automatically for you (multi-agent orchestration)"
- **Entry**: `techniques/01-methodology/llm-reverse-orchestration.md` (a copyable DAG template that shards APK analysis across parallel subagents)

### Scenario 17: "Want the AI to drive the tools (MCP-ified reversing)"
- **Entry**: `techniques/08-ai-re/ai-re-tools.md` (pick MCPs) + `techniques/08-ai-re/ai-re-workflows.md` (pipeline + copyable prompts)

### Scenario 18: "Given a PE/driver binary to audit" / "Need to find elevation or kernel bugs on Windows"
- **Entry**: `platforms/01-windows/win-vuln/` — `pe-re-and-symbols.md` → `driver-ioctl-audit.md` → `kernel-attack-surface.md` → `kernel-pool-cve-patterns.md`; with no environment, set up the target machine first with the setup.ps1 in `platforms/01-windows/win-vuln/toolchain-setup.md` (~30 minutes)
- **Output**: bug hypothesis → POC → (authorized context) report

### Scenario 19: "Want a CVE ID for a finding from reversing"
- **Entry**: while hunting, first pass `breach-tables-cve.md` (recognize the signature → first shots to fire → hit criteria → false leads); branch capability check `re-to-cve-audit.md` → pick a channel in `disclosure-cve.md` (open source: GitHub SA is fastest / Microsoft: MSRC / domestic: CNVD) + report templates
- **Judgment gate**: not every finding gets an ID — first pass the three questions "security-policy violation + exploitability proof + impact scope"

### Scenario 20: "Want to know if a tool will be detected before choosing it" / "A tool's signature got detected — how to modify it"
- **Entry**: `techniques/05-toolbox/tool-detection-and-modding.md` — the three-column master table for 19 tools (usage | detection surface | modification paths), the frida four-forms × 10 detection-points matrix, the repack-and-sign chain, a four-layer modification methodology, and detection-surface bills for four scenarios; for depth, go to `techniques/12-bypass/`

## VI. Boundaries: When NOT to Use re

| Situation | Use instead |
|------|--------|
| Pure web sites / SRC vulnerability testing (test directly once you have the APIs) | `skill` (SRC knowledge base) + api-pentest |
| White-box audit with source code (Java/PHP/Go) | `secure-code-audit` |
| Asset mapping / FOFA surface discovery | the dig-scope workflow in rules (fofa MCP) |
| Data analysis / report writing and layout | data-analyst / tech-doc |

**One-sentence summary**: anything stuck at the RE stage of "can't see it / can't get in / can't compute it / being detected" → re; anything at "got the APIs and parameters, now test for bugs" → skill; "got the source code" → secure-code-audit.


## Compatibility Search Vocabulary

Older host prompts may use the following phrases. They select existing routes rather than
requiring every term in the skill's discovery description.

| Terms in a task | Route |
|---|---|
| reverse engineering; Android RE; iOS RE; IoT; pwn; CTF; vulnerability root cause | [Platform index](platforms/INDEX.md), then the matching domain/root-cause article |
| frida; hook; frida-mcp; jadx-mcp; ghidra-mcp; unidbg; AI RE | [Technique index](techniques/INDEX.md), especially Frida, emulation, and AI/MCP methods |
| unpacking; app packers; OLLVM; obfuscation; VMP; algorithm restoration; “look at this app's encryption”; “how do I reverse this .so” | [Unpacking](techniques/03-unpacking/dex-unpacking.md) or [algorithm restoration](techniques/10-algo-restore/algo-restoration-methodology.md) |
| traffic capture; SSL pinning; anti-debugging; root detection; risk control; bypass; RASP | [Bypass decision playbook](techniques/12-bypass/bypass-playbook.md), then the relevant evasion method |
| RPC; syscall; eBPF; kernel hook | [Observation matrix](techniques/11-syscall-chain/observation-matrix.md) or [offline RPC](techniques/10-algo-restore/protocol-offline-rpc.md) |
| full-chain execution; “run the pipeline” | For an explicit APK/dynamic request use [APK S0–S4](pipeline/pipeline.md); static/report requests use [runner](docs/runner.md). Resolve a bare URL as Web versus APK input first. |
| tool radar | [Tool radar](radar/README.md) |
