# LLM Reverse Orchestration: a portable methodology abstracted from r0re/Cairn/muteki

> Goal: de-Dockerize the multi-agent collaboration mechanisms of the three projects, distill them into a general playbook replicable with nothing more than "main agent orchestration + parallel subagents", and provide an APK reverse-engineering task-sharding template you can copy verbatim.
> Factual basis: see r0re-architecture.md in the same directory.

## 1. Abstracting the collaboration patterns of the three projects

The three projects look different on the surface (Cairn is general state-space search, muteki is heterogeneous-engine security automation, r0re is Android reversing), but at the core they share the same **orchestrator-worker-blackboard** triple:

```
┌───────────────┐  dispatch tasks (rendered prompts)  ┌───────────────┐
│ Orchestrator  │ ─────────────────────────────────→ │  Workers ×N   │
│ (reason/race) │ ←───────────────────────────────── │ (explore)     │
└──────┬────────┘  structured JSON results back      └──────┬────────┘
       │ read/write                                      read/write
       ▼                                                          ▼
┌──────────────────────────────────────────────────────────────────┐
│            Shared blackboard (the single source of truth)        │
│  Fact (confirmed, carries the verified flag) / Intent (unclaimed)│
│  DeadEnd (disproven route) / Hint (human-injected)               │
└──────────────────────────────────────────────────────────────────┘
```

Responsibilities of the three roles (synthesized from Cairn dispatcher-design.md and the r0re/muteki implementations):

**Orchestrator (= the reason task)**: never touches target files, only reads blackboard graph snapshots, and does three things — ① Goal decomposition: split the overall goal into sub-problems and check each against existing Facts to find gaps; ② coverage check: run r0re's six-layer checklist (Manifest / Java-smali / Resource / Native / Network / Storage) and fill in whichever layer is missing; ③ produce Intents: every intent must satisfy the four properties — Specific (points at a named class/method/file/offset), Actionable (the worker knows which tool to use and where to look), Scoped (a single layer), Independent (parallelizable).

**Worker (= the explore/race tasks)**: claim one intent → execute real tools → write back immediately. Three iron rules: before starting, run `read + read-deadends` (never repeat a confirmed fact, never re-walk a dead end); "The MOMENT you confirm a finding", write the fact at once, and only what you literally saw in command output earns `--verified`; the moment a route is disproven, call `mark-deadend` ("A dead end is as valuable as a fact"). Large outputs go to files; facts only reference paths.

**Blackboard**: append-only, atomic facts (one finding per entry, with class/method/offset/path), human-insertable Hints. r0re additionally gates "completion" on the blackboard: a complete must reference at least one real fact id, and a rules verifier checks the evidence chain before letting it through — preventing the model from verbally declaring victory.

Dispatch cadence (shared by Cairn/r0re): tasks split into bootstrap (straight solve at the start) → race (optional, multiple workers sprinting) → reason ⇄ explore loop; after explore times out, the same session enters a conclude phase to salvage the conclusions already reached; three consecutive failures on the same intent blacklist it; hierarchical stall detection (15/25/45 minutes). Artifacts are shared via a unified analysis directory (`~/workspace/analysis/`): jadx/apktool outputs are generated once, and latecomers check before building.

## 2. Porting plan: replicate with a ZCode main agent + subagents (no Docker)

r0re's four pieces map onto a single ZCode session:

| r0re component | ZCode equivalent | How to land it |
|---|---|---|
| r0re-serve + blackboard REST | Markdown/JSON files in the task directory | see 2.2 |
| dispatcher (reason) | Main agent (yourself) | The main agent does not reverse directly: read the blackboard → split intents → dispatch |
| worker containers ×3 | Parallel general-purpose subagents | One subagent per intent, self-contained prompts |
| CompletionVerifier | Main-agent final acceptance | Rules checks + an independent review subagent |
| Toolchain container | Tools already installed on the host | Use whatever jadx/apktool/Ghidra/r2/frida you have; probe first inside the subagent |

### 2.1 Directory conventions (create these first when entering a task)
```
{task}_APK-reversing/
├── blackboard.md      # single source of truth: facts / deadends / open-intents sections
├── jadx_out/ apktool_out/ ghidra_out/   # shared artifacts, built once
├── candidates/        # per-subtask reports (r0re's report_*.md equivalent)
└── flag-verification/ # equivalent-model solve.py / verify.py + run outputs
```

### 2.2 Shared blackboard file format (copy directly)
```markdown
# Blackboard
## Facts (confirmed; [V] = literally seen in tool output)
- F01 [V] Entry validation lives in com.ctf.app.MainActivity.checkInput() (jadx_out/sources/.../MainActivity.java:87)
- F02 [V] libnative.so exports Java_com_ctf_app_NativeLib_verify, registered dynamically by JNI_OnLoad (nm -D output)
- F03     verify does a 15-round byte transform at 0x1A3C followed by memcmp (pending re-check)
## DeadEnds (disproven, do not retry)
- D01 The base64 string in strings is a decoy, never enters the comparison (confirmed by F02 disassembly)
## Open-Intents (to be claimed)
- I03 [from F02] Decompile the whole transform chain at 0x1A3C with Ghidra, extract the constant table → derive an equivalent Python model
- I04 [from F01] Chase whether checkInput's failure branch has a second-stage validation
## Hints (human)
- Challenge author's hint: input length is 15
```
Maintenance rules copied verbatim from r0re: append-only, never modify other people's records; atomic facts; long outputs go to files with path references; every subagent must return "F/D numbers added this round + one sentence" when it finishes, and the main agent merges them into the blackboard (this is the simplified version of the dispatcher's write-on-behalf protocol).

### 2.3 How to shard an APK analysis task
Shard along r0re's phase classifier + six-layer coverage; the natural parallel boundaries are "layer" and "intent":
- **P0 recon (serial, done by the main agent itself or a single subagent)**: the `apk-recon` equivalent — file/aapt badging/permissions/exported components/so inventory/certificate → produces the base F-series facts + the initial intent list. This step must run first so the later parallel work has shared context.
- **Parallel shard A | Java layer**: jadx runs once to disk (whoever arrives first builds it, latecomers use it directly) → find UI entries / validation classes / native method declarations / crypto API calls (find-crypto's four pattern classes: javax.crypto class names / algorithm keywords / Base64 / Keystore).
- **Parallel shard B | Manifest + resources**: apktool to disk → exported components / deep-links / strings.xml hardcoding / asset configs.
- **Parallel shard C | Native layer** (only when a so exists): nm -D/readelf -s to locate JNI symbols → r2/Ghidra headless decompilation of the validation functions → extract constants/transform chains/comparison points. r0re experience: run `readelf -Ws` first, and throw Ghidra only at confirmed key functions, never the whole binary.
- **Parallel shard D | dynamic verification** (only with a device/emulator): combinations of frida crypto/ssl/root/native hooks to verify the algorithm parameters inferred statically.
- **Serial shard E | equivalent modeling + solving**: take the constants and transform chains from A/C, write a Python equivalent model → invert / bounded-search for candidate inputs.
- **Serial shard F | final verification**: feed the candidate inputs back into the equivalent model and assert pass; install on a device for a live test if possible; check against the r0re guardrails — "No final answer from strings alone", "never guess a one-way hash unless the native compare proves that exact hash is what's compared".

### 2.4 How to set acceptance criteria (copy r0re's gating)
1. **Completion requires an evidence chain**: the flag/conclusion must `from` at least one [V] fact, with the full six-step chain present (Java/UI entry → JNI entry → native call chain → constants → transform → compare);
2. **A runnable verifier**: "You may return completion only when a runnable verifier prints an explicit pass condition" — done counts only when solve.py/verify.py runs through and prints pass;
3. **Reproduction commands**: the report attaches a copy-pasteable command sequence;
4. **Decoys explicitly labeled**: the report must contain a "Decoys / false leads" section stating what was ruled out;
5. **Main-agent re-check**: an independent subagent (or the main agent) re-verifies using only the candidate + evidence, never trusting a worker's self-reported complete — mirroring r0re's CompletionCandidate → verifier → quarantine chain.

### 2.5 Main-agent cadence (mimicking the dispatcher)
1. P0 recon → initialize the blackboard;
2. One round of reason: read the blackboard and produce 2-4 intents that satisfy the four properties, per the gaps;
3. Dispatch the corresponding subagents **in parallel within the same message** (if shards A/B/C do not depend on each other, send them together); every prompt is self-contained: one-sentence goal + the relevant blackboard section verbatim + artifact paths + output format (new F/D + report path on disk) + prohibitions (never re-walk a deadend, never modify other people's blackboard records, large outputs go to files);
4. Harvest: merge F/D into the blackboard; if an intent fails twice in a row, re-shard it; after three failures, blacklist it (switch dimension);
5. Loop 2-4 until reason judges the Goal covered by facts → enter E/F final verification → produce the report;
6. When stuck: go back to the blackboard and scan for "facts that unblock you" (r0re's wording), or inject a human Hint — never let a single subagent spin idle.

## 3. LLM APK reverse-engineering task-sharding template (copy directly)

```
Goal: {APK path} → recover {flag / key input / validation logic}, produce a reproducible verification chain
Artifact root: {task dir}/   Blackboard: {task dir}/blackboard.md (all subagents read-only + return deltas; the main agent is the sole writer)

P0 recon (serial, main agent)
  in : APK
  out: F01.. (base facts) + I01.. (initial intents) + jadx_out/apktool_out written to disk
  accept: package name / entry / permissions / so inventory / dex count / certificate — all six covered by facts

─── A/B/C/D below run in parallel (same-round dispatch) ───
A Java-layer subagent
  in : jadx_out/, blackboard F/D sections, I (Java-related)
  do : UI entry → validation classes → native declarations → crypto-API four-pattern scan
  out: new F/D + candidates/A-java.md + suggested intents for suspicious spots
  accept: every finding carries class name/method/line number; all System.loadLibrary touchpoints listed explicitly

B Manifest+resources subagent
  in : apktool_out/, blackboard
  do : exported components / deep-links / hardcoded strings / asset configs
  out: new F/D + candidates/B-manifest-res.md
  accept: no missed exported components; every hardcoded candidate labeled "candidate only, comparison point not reached"

C Native-layer subagent (only if a .so exists)
  in : lib/**/*.so, blackboard, JNI touchpoints derived from A (if none, wait one A round)
  do : readelf -Ws / nm -D → decompile the key functions with Ghidra/r2 → extract constants / transforms / comparison points
  out: new F/D (with offsets/symbols) + candidates/C-native.md + constant attachments
  accept: every transform-chain step has instruction-level evidence; the VA→file-offset mapping is recorded

D Dynamic-verification subagent (only with a device/emulator; can run in round two alongside C)
  in : package name, algorithm hypotheses from A/C
  do : frida crypto/root/ssl/native hooks; run one legitimate input to capture runtime parameters
  out: new F/D + candidates/D-dynamic.log
  accept: state explicitly whether the hook output matches the statically inferred key/IV/mode or not

─── Convergence point: main-agent reason ───
R1: merge A/B/C/D → gap analysis (six-layer coverage) → add intents (four-property check) → back to parallel
    (typical round two: after R1 dispatch C2 "decompile the transform chain at 0xXXXX" + the E prerequisite "constant-table extraction")

E Equivalent modeling + solving (serial)
  in : constants and transform chains from C
  do : Python reimplementation → inversion / bounded search
  out: flag-verification/solve.py + candidate inputs
  accept: the model matches native behavior on known input/output pairs (at least one differential test)

F Final verification + report (serial, independent re-check)
  in : candidate inputs + all F
  do : solve.py asserts pass (if a device is available, install and live-test); an independent subagent re-checks using only the blackboard + scripts
  out: final report (Result / six-step Evidence chain / Decoys / Reproduction)
  accept: 1) cites at least one [V] fact 2) the verifier prints pass 3) copy-pasteable commands attached 4) decoys listed explicitly
```

Parallel-boundary notes: shards A/B/C/D never write the same file and only read the blackboard — safe to dispatch in the same round; when C depends on A's JNI touchpoints, split into two rounds (A+B first, C+D next); E/F are naturally serial. If the native code is packed/SMC, nest r0re's sub-template ideas inside C: packed→unpack first (upx_shlib_emu-style approach), smc→runtime dump, jni→RegisterNatives table restoration, constants→memcmp target-table extraction.

## 4. Anti-pattern checklist (paid for in blood and tears by the three projects)

1. Writing an intent as "analyze the whole application" / "find the encryption" — not executable, not parallelizable (the r0re reason.md anti-pattern section);
2. Letting workers freely declare completion — there must be a runnable verifier + evidence fact references (r0re's verifier gating);
3. Producing a flag from strings/guesswork alone — "No final answer from strings alone";
4. Not recording dead ends, stepping in the same pit twice — deadends carry the same weight as facts;
5. Every worker decompiling the whole thing again — artifacts are built once, check before building (the race strategy);
6. Losing everything on a long-run timeout — the two-phase conclude salvage (the r0re/Cairn `_conclude` template);
7. Stuffing big blobs into the blackboard/facts — write them to files and reference the path, keep the blackboard scannable;
8. Retrying the same intent forever — re-shard after 2 failures, blacklist after 3;
9. Single-thread narrative reasoning about native code — "Every native finding must be backed by a command output or a generated analysis script";
10. Forgetting decoys: in CTF challenges "Morse/Base64/MD5-like values are common decoys" — until proven to reach the final comparison point, they are only candidates.
