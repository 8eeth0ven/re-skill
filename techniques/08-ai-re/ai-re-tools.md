# AI Reverse Engineering Tool Ecosystem: MCP-ized RE Tool Comparison and Selection

> Core conclusion: the ecosystem has split into three layers — the **orchestration layer** (REA/MobileRE-Skill: lets the Agent do work end-to-end), the **single-capability MCP layer** (jadx/ghidra/IDA/frida each MCP-ized; the Agent calls them on demand), and the **knowledge-lookup layer** (offline quick references like jniq). The three layers are not competitors; they compose.
> How the workflow chains together → see ai-re-workflows.md in the same directory; multi-Agent orchestration methodology → see `../01-methodology/llm-reverse-orchestration.md`.

## 0. One-Line Positioning Table (read this first)

| Tool | One-line positioning | Layer |
|---|---|---|
| REA | "Reverse Engineer Anything": a reverse-engineering CLI + MCP for AI agents; APK/so/websites/firmware all covered | Orchestration layer (tool bus) |
| MobileRE-Skill | AI-agent mobile-RE skill system: frida modules + standalone tools + decision trees; auto-routes a one-sentence requirement | Orchestration layer (domain skills) |
| LSPilot | On-device AI-driven LSPosed dynamic reversing: intent parsing → locate class/method → generate example → one-tap injection | Orchestration layer (on-device closed loop) |
| mobile-security-mcp | APK static analysis + RASP identification/bypass MCP (⚠️ see the tool list caveat in §4) | Single capability |
| jadx-mcp family | jadx decompilation MCP-ized (AI reads Java source) | Single capability |
| GhidraMCP family | Ghidra decompile/function analysis MCP-ized | Single capability |
| ida-pro-mcp | Full-feature IDA Pro MCP-ized (in local use) | Single capability |
| frida-mcp family | frida dynamic instrumentation MCP-ized (AI operates processes directly) | Single capability |
| dexllm | LLM-oriented DEX/APK analyzer (wraps DexKit + the DAD decompiler) | Single capability |
| barbatos | Zero-config Android runtime debugger with built-in Frida API + MCP | Single capability |
| R2Droid | On-device radare2 GUI + AI assistant (OpenAI-compatible API) | On-device self-contained |
| jniq | Offline bidirectional lookup of the JNIEnv function table (index/offset ↔ function name) | Knowledge lookup |
| lamda | Android full-stack device-control platform: on-device server + screen mirroring/UI automation/one-tap MITM/built-in hidden Frida + MCP | Orchestration layer (device side) |
| agent-device | Mobile-app automated-verification CLI/MCP (iOS/Android/HarmonyOS); accessibility snapshots save tokens | Single capability (device) |
| reverse-skill | RE/pentest skill-routing package: AI auto-routing + on-demand toolchain bootstrapping + self-evolving experience base | Orchestration layer (skill routing) |
| reverify | Anti-hallucination adjudication layer: the AI proposes, deterministic tools adjudicate VERIFIED/REFUTED against artifacts | Verification layer (new category) |
| radare2-mcp | Official radare2 MCP (C implementation; CLI/plugin/HTTP polymorphism) | Single capability |
| x64dbg-mcp-server | Native x64dbg MCP plugin (Zig single binary; full debugging features) | Single capability (Windows) |
| mcp-windbg | WinDbg MCP (incl. kernel debugging) | Single capability (Windows) |
| binary_ninja_mcp family | Binary Ninja MCP (plugin faction + headless 180-tool faction) | Single capability |
| ASC | "APK as a database" zero-preprocessing decompiler (designed for Agents) | Single capability (performance) |

## 1. Main Comparison Table of MCP-ized RE Tools

| Tool | MCP capability | Underlying wrapped | Status |
|---|---|---|---|
| REA | Dual form: MCP server + standalone CLI; supports Claude Code/Codex/Cursor/Gemini CLI etc. | headless JADX (JDK), Apktool, ADB, Ghidra/Hopper/IDA (native deep analysis; uses whatever is installed locally), Binwalk/Unblob (firmware), Chrome (websites), Go/Rust/WASM/EVM bytecode | 260.5k stars/65.5k forks, MIT, 3300+ commits. Node 22+; `npx rea-agents setup` one-tap registration |
| MobileRE-Skill | Mounts jadx-mcp + ghidra-mcp as external MCPs via kilo.json; the body is skill/decision trees + frida modules + 22 Python tools | frida (monitors 15 + bypass 10 + utils), the unpack.py unpacking pipeline, Unicorn emulation, DexKit chain-query ideas | 184 stars, MIT, bilingual CN/EN README. The Agent brain sits in `.kilo/agent/reverser.md` |
| LSPilot | Not MCP — an on-device Xposed module with a built-in AI function-calling toolset | On-device jadx decompilation (APK/DEX), DexKit, smali search, ARSC reading, BeanShell script engine, LSPosed injection | 128 stars. Requires LSPosed + Android 14+ + arm64-v8a; API docs at lspilot.fun |
| mobile-security-mcp | Lead toolset: apk_decompile (apktool) / apk_decompile_java (jadx hardware-accelerated) / rasp_identify / rasp_bypass (dynamically generates frida bypasses) | apktool/jadx/frida | A same-named repo exists but its tool list is completely different (pure-static 13 tools: manifest/permissions/secrets scanning; no decompile/rasp); the described toolset has no public repo — go by the tool list of the actually running service |
| jadx-ai-mcp | MCP server (plugin inside JADX-GUI) | jadx-gui + AI plugin | 2.9k stars (zinja-coder/jadx-ai-mcp) |
| jadx-mcp-server | Standalone MCP server (Python), paired with the JADX-AI plugin | same as above | 803 stars |
| jadx-headless-mcp | Headless MCP, no GUI needed, jadx-core opens the APK directly | jadx-core | 77 stars; two similar projects Samael-Z/VibRev at 20/7 stars |
| GhidraMCP | MCP server (Ghidra plugin) | Ghidra decompile/functions/datatypes | 11.3k stars, the de-facto ecosystem standard, continuously updated |
| bethington/ghidra-mcp | Dual form GUI plugin + headless, 200+ tools | Ghidra | 5.6k stars |
| reverse-engineering-assistant | MCP + in-Ghidra built-in AI analysis (RE-AI) | Ghidra | 874 stars (cyberkaida/rea) |
| ida-pro-mcp | Full-feature IDA MCP: decompile/disassemble/xref/rename/patch/debug | IDA Pro (Python plugin) | 12.9k stars. **Already in use by local ZCode** (get_metadata/decompile_function/… is this repo's tool surface) |
| IDA-NO-MCP | Anti-MCP idea: feed IDA output straight to the model, saving tokens | IDA | 2.1k stars (P4nda0s/IDA-NO-MCP) |
| ida-mcp-rs | Headless IDA MCP (Rust) | idat headless | 869 stars |
| dnakov/frida-mcp | stdio MCP directly controlling frida (spawn/attach/scripts) | frida | 455 stars |
| kahlo-mcp | Android instrumentation MCP for autonomous agents | frida | 136 stars |
| frida-c2-mcp | C2 style; long-term control of rooted Android/jailbroken iOS | frida | 70 stars |
| jshookmcp | AI RE workbench; claims 735 tools | frida/js hooks | 2.1k stars |
| open-reverselab | AI RE agent platform: MCP-ized Ghidra/Frida/x64dbg/Rizin | four engines | 1.3k stars |
| dexllm (dex-analyzer-for-llm) | MCP server + FastAPI/SSE backend (Claude tool use) | C++ core: pybind11 wrapping LuckyPray/DexKit + a DAD-aligned C++ Java decompiler | Main repo 2 stars (Apache-2.0, C++). **Note: the main repo is not named dexllm**; searching "dexllm" only surfaces the demo repo |
| barbatos | Zero-config Android runtime debugger with built-in MCP | frida API (Kotlin) | 11 stars, continuously updated |
| R2Droid | Not MCP — an in-app AI assistant with OpenAI-compatible streaming chat API; `[[cmd]]`/`<js>` execute command scripts | On-device cross-compiled radare2 + r2ghidra/r2dec/r2frida | 307 stars, MIT |
| jniq | No MCP — CLI + Claude Code skill form (Skill.md linked into the agent skills directory) | Built-in table (233 slots) generated by parsing the real jni.h | 2 stars, MIT, zero dependencies |
| radareorg/radare2-mcp | Official r2 MCP: C implementation; CLI/r2 plugin/stdio/HTTP polymorphism; r2pipe connects to a local or remote session; read-only sandbox and tool-whitelist modes | radare2 6.x | hundreds of stars; `r2pm -Uci r2mcp` one-tap install |
| duty1g/x64dbg-mcp-server | Native x64dbg MCP plugin: breakpoints/stepping/memory/registers fully exposed over HTTP | x64dbg (Zig plugin) | ~2.5k; single binary, zero deps; drop dist into the x64dbg directory and use |
| svnscha/mcp-windbg | MCP for WinDbg (user/kernel-mode debugging AI-ized) | WinDbg | ~1.6k |
| fosdickio/binary_ninja_mcp | Binja plugin-form MCP; LLM clients connect directly | Binary Ninja | 450+ |
| mrphrazer/binary-ninja-headless-mcp | Headless Binja MCP, 180 tools | headless BN | 250+ |
| firerpa/lamda | Android device-control platform MCP: WebRTC screen mirroring/UI+OCR automation/one-tap MITM (system CA)/built-in latest Frida with stealth patches/160+ APIs/multi-device clusters | Self-developed on-device server (root/non-root) | ~8.6k; Python client orchestration |
| callstack/agent-device | Mobile-app automated verification: CLI+MCP+Node API in three forms; token-friendly accessibility snapshots; cross-parallel-agent device coordination | adb/simctl/wda etc. | ~5k; npm-installable |
| sjkim1127/Reversecore_MCP | Security-analysis MCP combining r2+YARA+LIEF+Capstone (automated RE/malware analysis/forensics/SAST) | multi-engine | ~200 |
| jtsylve/re-mcp | Headless dual-engine MCP: one set covers both IDA Pro and Ghidra | idat/analyzeHeadless | ~170 |
| PhoenixHairpin/mcp-termux | Termux-side all-in-one Android RE MCP: 73 tools (eBPF stackplz + paradise memory dump + r2 static) | on-device toolchain | ~60; ARM64 root |
| 2akouwu/reverify | Verification-layer MCP+CLI: AI claims are adjudicated by deterministic tools against artifacts (VERIFIED/REFUTED with evidence); ships `reverify rollover` for long-session drift prevention | RE-engine outputs | ~1.3k; PyPI-installable |
| zhaoxuya520/reverse-skill | RE/pentest/security skill-routing package: AI auto-routing + on-demand toolchain bootstrapping + self-evolving experience base | skill documents | 40k-class (Trendshift chart) |
| SimoneAvogadro/android-reverse-engineering-skill | Claude skill: APK/XAPK/JAR/AAR decompilation + HTTP API extraction (Retrofit/OkHttp/Ktor/Apollo/Koin) + R8-stripped Kotlin metadata name recovery + framework-fingerprint triage | jadx/Vineflower | ~8k |
| P4nda0s/reverse-skills | Reverse-engineering Claude Code Skills plugin (by the author of IDA-NO-MCP) | skill documents | ~2.2k |
| haikow/claude-reverse-skills | Claude Code RE skill collection (apk/ida/radare2/js) + IDA MCP integration, Chinese | skill documents | hundreds |
| mrphrazer/ghidra-headless-mcp | Headless Ghidra MCP | analyzeHeadless | ~190 |

## 1.5 Three Integration Forms: How to Split MCP / Skill / CLI

This batch of tools does not integrate with Agents in a uniform way; before selecting, recognize the three forms (the community debate over "should unidbg be MCP-ized" is essentially this):

| Form | Mechanism | What it suits | Examples |
|---|---|---|---|
| **MCP server** | The Agent calls tools over a protocol and gets structured returns; the tools are ready-made, the actions fixed | API-ization of mature tools: decompilation, attach, list queries | jadx-mcp family, GhidraMCP, ida-pro-mcp, frida-mcp, REA, dexllm |
| **Skill / skill document** | No protocol involved; write "domain playbooks + decision trees + command templates" as documents hooked into the Agent; the Agent follows the doc to execute/write code itself | Steps customized per target: unidbg environment completion, so repair, confrontation decision trees | MobileRE-Skill (.kilo/skill decision trees), jniq (skill/SKILL.md), this library's re skill itself; heavyweight entrants after 2026-10: reverse-skill (routing package), android-reverse-engineering-skill (API extraction + Kotlin name recovery), reverse-skills |
| **CLI** | The Agent invokes it via shell; humans can use it directly; JSON output eases scripting | Offline deterministic queries, CI integration | REA CLI, jniq, standalone scripts like unpack.py/so.py |
**Rule of thumb**: fixed actions → MCP; per-target code to write → Skill; both humans and Agents will use it → CLI first (add an MCP shell in passing). One tool can occupy multiple forms at once (REA = CLI+MCP; jniq = CLI+Skill).

## 2. REA: Tool-Bus-Style Orchestration (the "Swiss army knife" of general reversing)

**Form**: one command, two uses — `npx rea-agents setup` registers the MCP into Claude Code/Codex/Cursor/Gemini CLI/Grok; or `npm i -g rea-agents` as a standalone CLI (JSON output, scriptable).
**Capability surface (by target)**:
- Android: headless JADX yields manifest/classes/decompiled methods (needs JDK), ADB direct device analysis, Apktool resource decoding, Flutter app inspection, JEB projects
- Native binaries: pseudocode/assembly/strings/symbols/call chains via Ghidra/Hopper/IDA (uses whichever is installed; it can even help you install Hopper upon approval)
- Others: JS/Electron, .NET, websites (Chrome-family browsers), Go/Rust/WASM/EVM bytecode, SQLite, firmware (Binwalk/Unblob), PCAP
**Selling point**: analysis is fully local; **every conclusion carries evidence** (command output/decompiled snippets returned) — the key design against LLM hallucination, the same idea as r0re's `--verified` facts.
**Ecological niche**: it builds no wheels of its own; it unifies the industry's existing tools into Agent-callable interfaces → "tool bus". Third-party derivatives have already appeared: DSH bridge (DeepSeek Harness plugin), LM Studio edition, ERA self-evolving agent, etc.
**Boundary**: each single capability is shallower than a dedicated MCP (e.g., GhidraMCP's 200+ tool granularity); its strength is breadth + out-of-the-box readiness.

### 2.1 REA Derivative Ecosystem

| Derivative repo | Description | stars |
|---|---|---|
| valorisa/Reverse-Engineer-Anything | Unofficial French tutorial guide | 24 |
| rea-githu/REA | "REA 6.3.0 local MCP zip" distribution repo | 70 |
| ringozzt/rea-research | Technical research on REA (as an MCP toolchain) | 52 |
| Fanqi89/dsh-rea (+sheilacraig/dsh-rea-mcp) | MCP bridge plugin for DeepSeek Harness | 17/2 |
| Nowng/rea-mcp | LM Studio integration edition | 0 |
| dav1dngy/era-agent | ERA: an "evolutionary RE agent" based on REA | 2 |
The derivative ecosystem is itself a signal: once a tool spawns "bridge editions / research editions / teaching editions", the main repo has crossed critical mass. The flip side flags risk — the distribution repo (rea-githu) is unofficial; when installing the MCP zip, trust only the main repo morluto/rea to guard against supply-chain poisoning.

## 3. MobileRE-Skill: Domain-Skill-Style Orchestration (mobile-RE specialized)

The opposite of REA's "broad but shallow": MobileRE-Skill is "narrow but deep" — it only does mobile reversing, but skill-izes the entire domain playbook.
**Three-layer structure**:
1. **Agent brain** (`.kilo/agent/reverser.md`): role definition + decision trees; a one-sentence requirement auto-selects modules/tools;
2. **Skill documents** (`.kilo/skill/`): task routing, decision trees, module index;
3. **Domain knowledge** (`references/`, 9 wiki domains: unpacking/anti-detection/crypto hooking/behavior analysis/static analysis/native analysis/troubleshooting/frida API quick-ref/smoke tests).
**Asset inventory**:
- 25 frida modules = monitors/ 15 (pure observation, no behavior change) + bypass/ 10 (active interference against detection); plus the utils/ helper script directory (so_dump, dex_*, the codeitem in-memory-dump JS, templates, detection-checklist scripts — not hook modules)
- 22 standalone tools (`tools/`, frida-independent): `so.py` (ELF static analysis), `unpack.py` (one-click unpack), `dex_rebuilder.py`/`dex_dedupe.py` (DEX backfill repair/dedupe), `frida_run.py` (unattended frida runs), `emu_run.py`/`uniharness.py` (Unicorn emulation), `trace_recon.py`, `cipher_lab.py`, `fsmon_run.py` (kernel-level file events), `hap_parser.py` (HarmonyOS HAP), Janus/injection/debug-detection scripts
- External MCPs: jadx-mcp (the AI directly reads decompiled Java source) + ghidra-mcp (disassembly analysis without a GUI)
**Unique capabilities**: the Dex2C/VMP three-step method (hook first → unidbg replay → Ghidra pseudocode), symbol/struct recovery (offline so recon + Ghidra cross-reference reasoning), six-layer drill-down (Java→JNI→Native→libc→syscall→SVC).
**One-sentence difference vs REA**: REA covers "see a bit of everything"; MobileRE-Skill covers "one step to the destination in Android confrontation scenarios" — especially anti-crash and unpacking (see ai-re-workflows.md §2).

## 4. LSPilot / mobile-security-mcp / the frida-mcp Family

### LSPilot

On-device closed-loop AI dynamic reversing: you state the goal in natural language (e.g., "hook the membership check"); the AI parses the intent → built-in function-calling tools auto-locate the target class/method → generate runnable example code + reversing ideas → inject live via LSPosed for real-time validation. The goal is to automate the whole "find → analyze → write → inject" chain: novices skip learning Xposed development; experts skip rewriting `findAndHook` boilerplate.
**Tech stack**: on-device jadx decompilation (APK/DEX), DexKit class/method/field chain queries, smali search, ARSC resource reading, type-signature parsing, string-reference analysis; the plugin engine is BeanShell (Java scripting, can call Android APIs); plugin directory `Android/media/<package>/LSPilot/Plugin/` (Java/Lua/JS supported).
**Threshold**: LSPosed + Android 14+ + arm64-v8a; install from GitHub Releases or the TG channel.
**Ecological niche**: complements the frida family — LSPosed injection is more "native" than frida (leaves no frida-server fingerprints), fitting scenarios where frida is killed on attach.

### mobile-security-mcp (⚠️ read it as two halves)

- **Public repo**: GitHub does have `Serhatcck/mobile-security-mcp` (6 stars, TypeScript, npm-installable), but it is **pure static analysis**, 13 tools (Android 5 + iOS 8): manifest parsing/permission checks/API extraction/secrets scanning, depending only on apktool+aapt — it does **not** contain apk_decompile_java, rasp_identify, rasp_bypass.
- **The lead**: the four-piece set from the user's lead (apktool decompile / jadx hardware-accelerated decompile / RASP identification / dynamically generated frida bypass) was not found under multiple keyword searches of the public repo; likely a private repo/internal tool/renamed project.
- **Substitutes**: functionally closest are REA (APK decompile + device analysis) and kahlo-mcp/frida-c2-mcp (RASP-style confrontation).

### frida-mcp Ecosystem (pick by scenario)

| Scenario | Pick |
|---|---|
| Directly spawn/attach/run scripts inside Claude/Agent | dnakov/frida-mcp (stdio, simplest) |
| Autonomous agent instrumenting Android for long stretches | FuzzySecurity/kahlo-mcp |
| C2-style long-term control of rooted/jailbroken devices | s4dp4nd4/frida-c2-mcp |
| JS-hook-centric; want a big all-in-one toolset | vmoranv/jshookmcp (735 tools claimed) |
| MCP-izing Ghidra/x64dbg/Rizin together | LING71671/open-reverselab |

## 5. dexllm / barbatos / R2Droid: Three "Small but Specific" Tools

- **dexllm** (real name `dex-analyzer-for-llm`): solves "LLM reading an APK costs too many tokens" — a C++ core (pybind11 wrapping LuckyPray/DexKit + a DAD-aligned Java decompiler) runs locally and hands only structured results to the model; backends are MCP + FastAPI/SSE, naturally fitting Claude tool use. Suits class-search/method-location preprocessing for very large APKs before handing off to jadx-mcp for close reading. Retrieval pitfall: the repo name does not contain "dexllm"; searching dexllm only finds a WASM demo repo (dexllm-web).
- **barbatos**: zero-config Android runtime debugger + Frida API + built-in MCP (Kotlin). The selling point is "usable once installed" — no MCP config, no server to run; the Agent connects to the debugger directly. Few stars, but the idea is worth watching.
- **R2Droid**: the reverse route — **not handing tools to a cloud Agent, but stuffing AI into the phone**. On-device radare2 full suite (r2ghidra/r2dec decompilation, r2frida dynamics, ESIL debugging, Sugiyama graph layout) + AI assistant (OpenAI-compatible API, streaming, custom prompts; `[[cmd]]` lets the AI execute r2 commands, `<js>` runs scripts). The only solution for on-site analysis with no network and no computer (e.g., only a phone allowed on premises).

## 6. jniq: The Template of the Knowledge-Lookup Layer (small and beautiful)

**Why it's needed**: the JNI function table has 233 slots; neither humans nor LLMs can memorize it; when reversing, you see `JNIEnv*` vtable calls like `*(env + 0x520)` in a memory dump — guessing is always wrong, and this is exactly where the LLM hallucinates with a straight face (see ai-re-workflows.md §4 pit 1).
**Principle**: parses the real jni.h (NDK edition, compatible with OpenJDK declaration style) and generates the built-in table with a script (`src/jniq/table.py`); offline deterministic queries, no guessing.
**Usage (install: `uv tool install jniq` or `pipx install jniq`, zero dependencies)**:

```bash
jniq 164                 # index → GetStringLength
jniq 0x520               # 64-bit byte offset → GetStringLength
jniq 0x298 -b 32         # 32-bit offset → ReleaseStringChars
jniq FindClass           # reverse lookup by function name (exact / case-insensitive)
jniq call int            # fuzzy search
jniq RegisterNatives --json   # JSON output for scripts
jniq                     # dump the whole table
jniq --jni-h /path/jni.h # one-shot query against a custom header (e.g., JDK21 new functions)
```

**Agent integration**: no MCP; ships as a Claude Code skill — copy/link `../../SKILL.md` into the agent skills directory; when the Agent meets a JNIEnv query it calls this instead of reciting an answer. The pattern is replicable: any "fact table LLMs get wrong" (ELF struct offsets, ArtMethod offsets, syscall numbers) deserves a tool of the same kind.

## 7. The Three Big Decompiler MCPs Compared (jadx vs Ghidra vs IDA)

| Dimension | jadx family | Ghidra family | IDA family |
|---|---|---|---|
| Head repos | zinja-coder/jadx-ai-mcp (2.9k) + jadx-mcp-server (803); headless faction 1013503897/jadx-headless-mcp (77) | LaurieWired/GhidraMCP (11.3k, de-facto standard); bethington/ghidra-mcp (5.6k, 200+ tools); cyberkaida/rea (874) | mrexodia/ida-pro-mcp (12.9k, **in local use**); P4nda0s/IDA-NO-MCP (2.1k); blacktop/ida-mcp-rs (869) |
| Strengths | DEX→Java source, classes/methods/strings/resources; easiest for LLMs to read | Free all-platform so/elf decompile + pseudocode; mature headless; batch analysis | Best commercial decompilation quality + F5 pseudocode + debugger; plugin ecosystem |
| Weaknesses | Cannot see native | Pseudocode slightly below IDA; slow on large so | Paid; single-instance license limits (headless multi-open needs forks: ida-multi-mcp/IDA-instances-MCP) |
| Form | GUI-plugin faction (zinja; needs jadx-gui open) vs headless faction (opens the APK directly, no GUI) | GUI-plugin + socket faction (LaurieWired) vs headless faction (pyghidra-mcp/mrphrazer) | GUI-plugin faction (mrexodia; server started inside IDA) vs headless faction (ida-mcp-rs) |
| Selection advice | Always the first step for an APK: let the AI finish reading the Java layer via jadx-mcp before anything else | Default for so analysis; the only choice without an IDA license or when CI batching is needed | Use it if licensed; already configured locally; tool surface includes decompile/disasm/xref/rename/patch/struct |
| Token strategy | Outputs Java source, token-friendly | Pull per function; avoid full listings | Same as jadx; IDA-NO-MCP champions "preprocess then feed directly" to save tokens |
**Combo pattern** (matching ai-re-workflows.md §1): jadx-mcp reads the Java layer to find JNI touchpoints → ida-pro-mcp/ghidra-mcp enters the so to decompile the key functions → frida-mcp/barbatos verifies dynamically. All three MCPs can hang on one Agent; there is no mutual exclusion.

**Debugger/engine MCP coverage (2026-10 snapshot)**
- Covered: x64dbg (x64dbg-mcp-server, Zig native plugin), WinDbg (mcp-windbg), Binary Ninja (binary_ninja_mcp plugin faction + binary-ninja-headless-mcp 180-tool faction), radare2 (official radare2-mcp), IDA/Ghidra/jadx (see §7).
- Still no head implementation: gdb-MCP (search hits are only scattered small repos), unidbg-MCP (only template repos like so-rev-mcp), volatility-MCP (small memory-forensics repos) — demand is real but no de-facto standard yet; recheck next round.
- New device-side layer: lamda (on-device full-stack control + MCP) and agent-device (lightweight verification loop) MCP-ize "real-device operation" as well, complementing the frida family (in-process).

### 7.1 Stability and Token Notes (summarized from hands-on use/community feedback)

- **GUI-plugin faction pitfalls**: jadx-ai-mcp and the mrexodia line all need the host GUI process alive; if the GUI crashes mid-session, all MCPs die. Prefer the headless faction for long tasks (jadx-headless-mcp, ida-mcp-rs, pyghidra-mcp).
- **Multi-instance**: IDA licensing restricts to a single instance; to open multiple binaries in parallel you need forks (ida-multi-mcp 452 stars/IDA-instances-MCP 456 stars, hardened specifically for multi-open); Ghidra headless has no such limit — more economical for batch jobs.
- **Token saving**: pull decompilation results per function, never whole-so decompile; IDA-NO-MCP's idea (preprocess then feed directly, bypassing MCP round-trips) is worth borrowing for extra-long tasks; jniq `--json` output eases script comparison instead of having the model read the full table.
- **Return values are evidence**: all three MCP families return the tools' raw output — writing "must cite the offsets/pseudocode snippets from tool returns" into the prompt is the first gate against hallucination (see ai-re-workflows.md §5).

## 8. Selection Decision Tree (copy and use)

```
What do you want to reverse?
├─ Android APK (main flow)
│   ├─ Want end-to-end automation, the requirement fits in one sentence → MobileRE-Skill (paired with jadx-mcp + ghidra-mcp)
│   ├─ Just want Claude/Cursor to be able to read the code → jadx-headless-mcp or REA
│   ├─ frida crashes on attach / heavy confrontation → LSPilot (LSPosed route) or MobileRE-Skill bypass modules
│   └─ APK is huge, tokens explode → locate with dexllm first, then close-read with jadx-mcp
├─ so / native binaries
│   ├─ Have IDA → ida-pro-mcp (in local use)
│   ├─ No IDA / need batching → GhidraMCP
│   └─ On-site phone analysis → R2Droid
├─ Anything might come (APK/website/firmware/bytecode mixed tasks) → REA
├─ Dynamic instrumentation
│   ├─ Simple spawn/attach → dnakov/frida-mcp
│   ├─ Long-term control / rooted devices → frida-c2-mcp / kahlo-mcp
│   └─ Zero-config debugging → barbatos
└─ JNI table lookup (jni.h 233 slots) → jniq (CLI/skill)
```

## 8.5 Common Combo Recipes (distilled from community practice)

| Scenario | Recipe | Source/basis |
|---|---|---|
| Protocol signature restoration | jadx-headless-mcp + ida-pro-mcp (static) → dnakov/frida-mcp (hook) → unidbg (offline cross-check) → mitmproxy (replay) | cnblogs post + community posts (the canonical four-stage pipeline) |
| One-sentence fully automatic mobile RE | MobileRE-Skill (brain/decision trees) + jadx-mcp + ghidra-mcp (hands) | MobileRE-Skill README (kilo.json mounts dual MCPs) |
| Mixed-target tasks (an APK today, a website tomorrow) | REA alone; the engine auto-switches per target | REA docs (showcase includes Electron/website/firmware) |
| Heavily anti-debugged targets | LSPilot (LSPosed route, dodging frida fingerprints) + MobileRE-Skill bypass modules as backstop | LSPilot README + MobileRE-Skill anti-crash pipeline |
| Huge-APK token control | dexllm produces a class index (structured summary) → jadx-mpc reads 3-5 named classes | dex-analyzer-for-llm README (token reduction aimed at Claude tool use) |
| On site without a computer | Install R2Droid on the phone (AI assistant + full r2 suite) | r2droid README |
| JNI reversing verification | Any recipe + jniq (always look up vtable slots, never recite) | jniq README ("the LLM is always guessing") |

## 8.6 Installation Quick Reference

> For Python-family (pip-type) installs into this library's tools-env, see the "Installation Quick Reference" sections in the 《05-toolbox》 docs; for MCP one-liners, prefer the npx/uvx forms.

```bash
# ── 编排层 ──
# REA(Node 22+;MCP 注册进 Claude Code/Codex/Cursor 等)
npx rea-agents setup
npm install --global rea-agents   # CLI 形态;rea update / rea --help

# MobileRE-Skill:clone 仓库(地址待核)→ Agent 大脑挂 .kilo/;外部 MCP 用下方 jadx/ghidra 两条
# LSPilot:LSPosed 模块,GitHub Releases / TG 频道装 APK(LSPosed+Android 14+arm64;API 文档 lspilot.fun)
# reverse-skill:github.com/zhaoxuya520/reverse-skill(clone 后挂进 agent skills 目录)
# reverse-skills(P4nda0s):github.com/P4nda0s/reverse-skills;android-reverse-engineering-skill:github.com/SimoneAvogadro/android-reverse-engineering-skill
# R2Droid:APK 直装(仓库待核);barbatos:github.com/victorlpgazolli/barbatos(macOS 单二进制)
# lamda(设备端全栈):github.com/firerpa/lamda

# ── 反编译 MCP ──
# jadx-ai-mcp(GUI 插件):github.com/zinja-coder/jadx-ai-mcp — jadx-gui 插件市场/release jar
# jadx-mcp-server:github.com/zinja-coder/jadx-mcp-server(配 JADX-AI 插件)
# jadx-headless-mcp(无需 GUI):github.com/1013503897/jadx-headless-mcp
# GhidraMCP(事实标准):github.com/LaurieWired/GhidraMcp(Ghidra 插件 + python server)
# bethington/ghidra-mcp(200+ 工具)/ mrphrazer/ghidra-headless-mcp:headless 派
# ida-pro-mcp:github.com/mrexodia/ida-pro-mcp(本机 ZCode 已在用,无需重装)
# ida-mcp-rs(headless Rust):github.com/blacktop/ida-mcp-rs

# ── 动态/设备 MCP ──
# frida-mcp(62 工具配方版,依赖 frida@17)
claude mcp add frida-mcp -- npx -y frida-mcp@latest
# dnakov/frida-mcp(最简 stdio):github.com/dnakov/frida-mcp,按 README 配 mcpServers
# kahlo-mcp:github.com/FuzzySecurity/kahlo-mcp;frida-c2-mcp:github.com/s4dp4nd4/frida-c2-mcp
# jshookmcp:github.com/vmoranv/jshookmcp;open-reverselab:github.com/LING71671/open-reverselab
# agent-device(移动 App 验证,npm)
npx agent-device

# radare2 MCP(官方,r2pm 一键)
r2pm -Uci r2mcp

# ── 知识/验证层 ──
# jniq(Python 3.9+,零依赖)
uv tool install jniq              # 或 pipx install jniq
# reverify(防幻觉验证层,PyPI)
uv tool install reverify          # 或 pipx install reverify

# dexllm(主仓,非 demo 仓)
git clone https://github.com/mobile-threat-hunter/dex-analyzer-for-llm

# ── Windows 调试/其他引擎 MCP ──
# mcp-windbg:github.com/svnscha/mcp-windbg
# x64dbg-mcp-server:github.com/duty1g/x64dbg-mcp-server(dist 拷入 x64dbg 目录即用)
# binary_ninja_mcp:github.com/fosdickio/binary_ninja_mcp(插件派)/ github.com/mrphrazer/binary-ninja-headless-mcp(180 工具 headless 派)
# ryuumonbuchi(217 工具 Ghidra MCP)/ knife(CLI/TUI/MCP)/ re-mcp(jtsylve)/ Reversecore_MCP(sjkim1127):仓库待核,见 §1 表
```

Note: mobile-security-mcp (the same-named npm package) and the toolset described in the user's lead are **not the same thing** (see §4); verify the tool list before installing.
