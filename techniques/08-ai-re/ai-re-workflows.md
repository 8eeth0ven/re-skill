# AI Reverse Engineering Workflow in Practice: The Analyze → Hook → Verify → Replay Pipeline

> Core process references: cnblogs post "Using AI for Automated APP Reverse Engineering" (2026-07: first IDA MCP + JADX MCP analysis → AI writes frida hook scripts → AI writes encrypt/decrypt scripts → AI writes mitmproxy auto-replay); community posts "Custom MCP Assisting Cursor for APP Reverse Engineering", "Is unidbg Really Suited for MCP", "Reverse Engineering Infrastructure: From GUI to API", "AI Toolchain Environment Setup".
> Tool selection → see ai-re-tools.md in the same directory; multi-Agent orchestration → see `../01-methodology/llm-reverse-orchestration.md`.

## 1. Four-Stage Pipeline Overview

The standard playbook the community has converged on (the backlion post's original text is exactly this flow; Trae/Cursor/Claude can all serve as the cockpit):

```
[Input: target APK + business question, e.g. "restore the signature algorithm"]
   │
   ▼
① Static analysis   jadx-mcp (AI reads the Java layer: entry points / network libs / crypto classes / JNI declarations)
   │                ida-pro-mcp / ghidra-mcp (when there is a so: JNI_OnLoad / exported functions / key-function pseudocode)
   │                Support: REA (one-stop), dexllm (pre-location for very large APKs), jniq (JNIEnv offset verification)
   ▼
② Hook authoring    AI generates frida scripts from the named classes/methods/offsets produced by ①
   │                Tooling: dnakov/frida-mcp / barbatos (Agent directly spawns + injects)
   │                Heavy confrontation: LSPilot (LSPosed injection) or MobileRE-Skill bypass modules
   ▼
③ Verification      Run the hook, capture runtime parameters (key/IV/plaintext/signature input & output)
   │                Cross-check: for the same input, static inference vs hook measurement must agree
   │                Offline native algorithms: unidbg environment-completion replay (better as a Skill than an MCP)
   ▼
④ Replay            AI writes mitmproxy scripts: replace request parameters / replay requests / auto-pass signing
                    Deliverable: reproducible PoC (request-construction script + evidence chain)
```

**Why this four-way split is the golden cut**: ① and ③ have ready-made MCPs (code reading / script running are the API-ization of mature tools); ② and ④ are the AI's forte (writing code), and their outputs are inherently verifiable (whether the script runs, whether the request passes signing — the machine has the say) — every stage has objective acceptance, leaving no room for hallucination.

### Per-Stage Tool Reference Table

| Stage | First choice | Alternatives | Agent-side actions |
|---|---|---|---|
| ① Static, Java | jadx-headless-mcp (no GUI) / jadx-ai-mcp (GUI open) | REA, dexllm (large packages) | get classes → read source → locate crypto classes / network layer |
| ① Static, native | ida-pro-mcp (in local use) | GhidraMCP, R2Droid (on-device) | decompile_function → get_xrefs → extract constants |
| ② Hook generation | AI writes + frida-mcp injects | barbatos, LSPilot, MobileRE-Skill modules | generate script → spawn → read log errors → self-repair loop |
| ③ Verification | frida hook cross-check | unidbg (offline replay of native), cipher_lab.py | compare static inference against runtime actual arguments |
| ④ Replay | mitmproxy script (AI-written) | Burp + AI-generated request templates | run script → assert response / signature passes |

## 2. MobileRE-Skill's Two Decision Diagrams (ideas you can copy directly)

### 2.1 Anti-Crash 6-Stage Pipeline (the standardized solution for "the app crashes the moment frida attaches")

Goal: keep the protected process alive while frida is present, until we hook what we want.

```
Stage 1 Locate the detecting SO
   └─ Pin down the .so that performs the detection from crash logs / tombstones / the so inventory
     (cross-reference the detection layering in 《04-evasion/detection-landscape.md》: svc > libc > JNI > Java)
Stage 2 Preempt init_array
   └─ Detection logic usually auto-starts inside init_array/JNI_OnLoad;
      hook before it runs (at dlopen/constructor time) to take the initiative
Stage 3 Symbol tracking
   └─ Track the detection function symbols (export table / dynamic registration table) to pin down "who is checking for frida"
Stage 4 Keep-alive
   └─ Hook the detection function's return value / fool the detection (instead of killing the thread —
      killing threads easily triggers integrity checks)
Stage 5 Shellcode detection
   └─ Some packers verify code-section hashes / scan for inline hooks; identify such shellcode check points
Stage 6 NOP out the crash function
   └─ Last resort: locate the crash function that actively aborts/exits, patchCode NOP / replace the return
```

Cross-links with existing knowledge in this library: the techniques of stages 2-3 are in 《02-frida/native-hook-cheatsheet.md》 (init_array/RegisterNatives); stages 5-6 in 《02-frida/advanced/patch-and-memory.md》 (nop/ret) and 《02-frida/advanced/gothook.md》 (GOT hook); also see the four-stage checklist in 《04-evasion/frida-anti-detection.md》 (process alive → attach → hook → dump). MobileRE-Skill's contribution is turning this string of manual experience into a skill the Agent can follow as a decision tree.

### 2.2 One-Click Unpacking Decision Tree (the actual unpack.py pipeline)

```
Determine the packer type
├─ Gen-1 packer (whole-file encryption; decrypts and loads the dex at runtime)
│   └─ A memory dump suffices → follow the "one-click unpack" 6-step pipeline:
│      ① dump & backfill (fixChecksum) → ② supplementary scan (missed dex)
│      → ③ pull to local → ④ checksum repair → ⑤ dedupe (dex_dedupe)
│      → ⑥ method-body marking (flag invalid method bodies) → feed the output straight into jadx
├─ Extraction packer (method bodies carved out, backfilled at runtime)
│   └─ The dex you dump has empty method bodies → you must actively trigger each method to load, then dump again
│      (the FART approach; the utils/ dex_* series)
├─ Dex2C / VMP
│   └─ Dumping is pointless → three-step method: hook first (hook the call sites directly for input/output)
│      → unidbg replay (run the so offline) → Ghidra pseudocode (human/AI reads the logic)
└─ In-memory DEX dump dual dumper (panda/mem): ptrace-free, stealthily pulls dex under anti-debug scenarios
```

Corresponding in-library docs: 《03-unpacking/dex-unpacking.md》 (the DexFile/DefineClass construction method), 《03-unpacking/so-repair-dump.md》 (native packers). In AI orchestration, hand this tree to the Agent and it auto-selects the pipeline by packer type — this is what "skill-izing a decision tree" looks like in practice.

## 3. Copyable Prompts (one per stage)

### Prompt A (① static analysis: recon instructions for JADX-MCP/IDA-MCP)

```
The target APK has been opened with jadx-headless-mcp (package name com.xxx.app).
Task: locate the request-signing algorithm; recon only, no code changes.
Steps:
1. List the network-layer entry points (okhttp3.OkHttpClient / interceptor list / WebView shouldInterceptRequest);
2. Search the four crypto patterns: javax.crypto.Cipher/Mac/MessageDigest class references,
   "HMAC/AES/RSA/SHA" keywords, Base64 encoding points, KeyStore/SecretKeySpec construction;
3. Find native declarations: every System.loadLibrary touchpoint + the corresponding native method signatures;
4. For every finding, output: ClassName#methodName + line number + a one-sentence evidence citation
   (quote the source snippet you actually read); conclusions without source backing are strictly forbidden;
5. End with a "next-step hook candidate list" (≤5 entries, ranked by confidence).
If a .so exists, append: use ida-pro-mcp to decompile the JNI touchpoint functions,
output the constant tables and comparison points from the pseudocode; offsets must come from
actual get_function_by_address returns.
```

Key points: restrict to "recon only"; force every conclusion to carry an evidence citation — this maps to the `[V]` fact rule in 《01-methodology/llm-reverse-orchestration.md》; for the native part, explicitly require "offsets must come from tool returns" to block hallucination (see §5 pit 1).

### Prompt B (②③ hook + verification: self-repair loop instructions for the Agent)

```
Based on blackboard F03 (com.xxx.security.SignUtil.sign(byte[]) calls the native signNatively),
write a frida script to verify the signature algorithm:
1. At the Java layer, hook SignUtil.sign and the class declaring signNatives; print args/return (hex);
2. At the native layer, hook libsec.so's RegisterNatives after JNI_OnLoad,
   dumping the registration table (function names/signatures/addresses) to a file;
3. Actively invoke signNatives once with the fixed input "0000" to capture the output;
4. Spawn via frida-mcp; if the process dies within seconds: follow the anti-crash 6-stage pipeline
   (first locate the detecting so → preempt init_array → NOP the crash point), outputting evidence per stage;
5. Acceptance: obtain one set of (input, output) pairs + the RegisterNatives table file path;
   if attach has not succeeded within 10 minutes, report which stage you are stuck at; do not retry indefinitely.
```

Key points: the MobileRE-Skill 6-stage pipeline names are written directly into the prompt (with a decision tree at hand, the Agent follows the tree); "report the blocking point + no infinite retries" maps to anti-pattern 8 of the orchestration doc.

### Prompt C (④ replay: instructions for the AI writing the mitmproxy script)

```
Conclusion: the signature algorithm is HMAC-SHA256 (key captured via hook: 32 bytes hex, see D-dynamic.log),
request header X-Sign = hex(hmac(body + nonce + ts)).
Task: write the mitmproxy addon script replay_sign.py:
1. Intercept requests to the target domain, recompute X-Sign and replace it (use current nonce/ts);
2. Provide a --replay mode: read the capture file, rewrite the body, replay, and assert on response code / business code;
3. On assertion failure print expected signature vs actual signature; do not fail silently;
4. Deliverables: the script + the full console output of one successful replay (i.e., the PoC evidence).
```

Key points: the verification material (the key captured by the hook) must come from stage B's output — each pipeline stage trusts only the measured output of the previous stage, never inference; a successful replay = the loop is closed.

## 4. Two Routes: Orchestration-Heavy (the r0re Line) vs Tool-MCP-Heavy (This Doc's Tooling Line)

The route of `../01-methodology/llm-reverse-orchestration.md`: **multi-Agent + blackboard + verification gates** — the emphasis is on "how to organize multiple LLM sessions to cooperate"; tools are bare host commands (subagents invoke jadx/r2/frida themselves).
This doc's tooling route: **single Agent + MCP toolbox** — the emphasis is on "every tool becomes the Agent's hands"; orchestration degenerates into the Agent calling tools in sequence itself.

| Dimension | Orchestration-heavy (r0re port) | MCP-heavy (Trae/Claude + MCP) |
|---|---|---|
| Core assets | Blackboard protocol + intent splitting + acceptance gates | MCP server fleet + skill documents (decision trees) |
| Context pressure | Each subagent takes exactly one intent, small context | Single session accumulates; large APKs easily overflow (need dexllm-style preprocessing) |
| Parallelism | Naturally multi-lane (subagents dispatched in the same round) | Mostly single-Agent serial (Trae/Cursor have no blackboard) |
| Hallucination defense | facts must be [V], verifier gating | Relies on direct reads of tool returns (MCP output is the evidence) |
| Tool upgrades | Swapping a tool = editing the subagent prompt | Swapping a tool = swapping/adding an MCP, plug-and-play |
| Fit | Large tasks: full six-layer APK coverage, CTF flags, parallel verification of multiple hypotheses | Medium tasks: single algorithm restoration, single-feature reversing, fast PoC |
**How to choose / how to mix (recommended posture)**:
1. **Large task (whole-package audit / unknown target) → orchestration as the skeleton, MCP as the flesh**: the main agent splits intents per llm-reverse-orchestration.md and dispatches subagents; each subagent's prompt directly specifies "complete this slice with jadx-headless-mcp/ida-pro-mcp" — with the tools MCP-ized, subagents no longer probe the environment themselves; startup cost drops sharply.
2. **Medium task (restore one signature/protocol) → pure MCP pipeline**: Trae/Claude in a single session just runs the four stages of §1; don't build a blackboard for a two-hour job.
3. **Heavy-confrontation scenario → orchestration + skill system**: MobileRE-Skill-style decision trees (6-stage anti-crash / unpacking tree) serve as the subagent's traveling skill documents; the blackboard records "detection-point D series / bypass facts" so each subagent doesn't re-step on the same mines.
4. **Rule of thumb**: need "multiple hypotheses in parallel + aggregated adjudication" → orchestration; need "one skill chain driven to the end" → MCP pipeline; when you lack neither, a blackboard (even a single md) + an MCP toolbox is the best cost-effectiveness.
Community addendum: whether unidbg should be MCP-ized is debated — MCP suits "an Agent operating a ready-made debugger", while unidbg requires writing Java environment-completion code per target, so it fits better as a **Skill** (have the AI write code) than an MCP (have the AI call a tool). The same reasoning applies to any "customized per target" step: custom code → Skill; fixed actions → MCP.

## 5. Pitfalls of AI Reversing and Acceptance-Gate Design

### Pit 1: Hallucinated offsets / hallucinated APIs — the most lethal

**Symptoms**: the AI reports "detection function at 0x1A3C" (actually 0x2A3C); the AI recites the JNIEnv table and calls 0x520 NewStringUTF (actually GetStringLength); fabricates nonexistent class paths / exported symbols.
**Root cause**: LLMs are naturally weak on "precise numeric facts"; its training memory does not contain your so; jniq exists precisely because "nobody can memorize this table — the LLM is always guessing".
**Acceptance gates**:
- Any offset/address/symbol may only be written into a fact when actual output from `get_function_by_address`/`nm`/`readelf` is on record (the `[V]` rule of the orchestration doc);
- JNI vtable offsets are always verified through jniq; the model answering directly is forbidden;
- The prompt explicitly states "offsets must come from tool returns" (see Prompt A).

### Pit 2: Not enough context — large APKs always blow up

**Symptoms**: jadx's full source won't fit into the session; midway through reading, the Agent starts "summary-style hallucination" (mis-remembering earlier conclusions).
**Acceptance gates**:
- Layered ingestion: dexllm/DexKit first produce a class index (returning only structured summaries), then read the source of 3-5 named classes;
- Copy anti-pattern 7 verbatim: large outputs go to files; facts only cite paths;
- On the orchestration route, each subagent takes exactly one intent (context isolation is precisely the blackboard pattern's advantage).

### Pit 3: Missing verification — "looks right" ≠ right

**Symptoms**: the AI declares "algorithm restored" but produces not one cross-check; after the hook script errors, the AI wraps it in try-catch to swallow the exception and then claims success; the replay script's assertions get commented out.
**Acceptance gates** (borrowed from r0re gating + reinforced by this pipeline):
1. **Runnable verifier**: completion must be accompanied by a script that runs and prints pass (Prompt C's assertions must not be removed);
2. **Cross-check**: static inference vs hook measurement, at least one matching (input, output) pair; for native, cross-check via unidbg replay;
3. **Evidence-chain citation**: the final conclusion's `from` cites ≥1 [V] fact (six-step chain: entry → JNI → native chain → constants → transforms → comparison);
4. **Independent re-verification**: a different subagent re-verifies with only the blackboard + script; the executor's self-report is not trusted;
5. **Decoys section listed explicitly**: what was ruled out (fake base64 among strings, misleading buttons in the UI), guarding against "answering the wrong question".

### Pit 4: "Success-rate hallucination" in adversarial scenarios

**Symptoms**: after the anti-crash pipeline completes, the Agent says "NOPed", but the next spawn still crashes (what got NOPed was a decoy detection point); the unpacked dump's dex won't open yet success is reported.
**Acceptance gates**: every stage of the 6-stage pipeline yields intermediate artifacts (detecting so name / registration-table file / survival screenshot); the acceptance of one-click unpacking is exactly step 6's "the output opens directly in jadx + method bodies are completely flagged non-empty" — only the objective result produced by the tool itself counts.

### Pit 5: Treating MCP as a silver bullet

**Symptoms**: 8 MCPs hung on the Agent; it calls them round-robin, dabbling shallowly in each (orchestration-doc anti-pattern 1: an intent written as "analyze the entire app").
**Acceptance gates**: the pipeline locks tools per stage — stage ① allows only jadx/IDA MCP, stage ② only the frida family; name them in the prompt; customization-type steps (unidbg environment completion, so repair) go through Skills letting the AI write code, not through MCP.

## 6. Quick-Start Checklist (current local state)

- In place: ida-pro-mcp (inside the local ZCode session; full tool surface: decompile/xref/patch/renames)
- Recommended additions (as needed): jadx-headless-mcp (essential for APKs), dnakov/frida-mcp (dynamic stage), jniq (`uv tool install jniq`, then link it into the skills directory)
- Heavy-confrontation pack: MobileRE-Skill (frida modules + the unpack.py decision tree read as skill documents), LSPilot (on-device LSPosed injection; needs an Android 14+ device)
- One-stop: REA (`npx rea-agents setup`; suits tasks where non-Android targets are mixed in)
- Environment details: frida install/launch in 《02-frida/env-and-quickstart.md》; prerequisites for capture & replay (certificates/pinning) in 《04-evasion/ssl-pinning-bypass.md》; unidbg environment completion in 《05-toolbox/emulation-frameworks.md》

## 7. Further Reading

- ai-re-tools.md (same directory): the full tool comparison and a selection decision tree
- 《../01-methodology/llm-reverse-orchestration.md》: the blackboard protocol and the four properties of intents — the "skeleton" of this doc's §4 mixing scheme
- 《../01-methodology/r0re-architecture.md》: the original design of the completion verification gate (CompletionVerifier), the source of this doc's §5 acceptance gates
- Source posts: cnblogs "Using AI for Automated APP Reverse Engineering"; community posts 290247/290311/290832
