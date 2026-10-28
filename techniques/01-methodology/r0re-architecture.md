# r0re Architecture Deep-Dive: a Kimi Code-driven multi-agent orchestration service for Android reverse engineering

> Based on a source review of r0re (fyrlove/r0re, the full 183-file tree of the main branch + key sources), its upstream oritera/Cairn, and the borrowed-from FishCodeTech/muteki; the project's docs are bilingual (`upstream-r0re:docs/README.zh-CN.md` / `upstream-r0re:docs/README.en.md`).

## 1. What r0re is and what problem it solves

r0re describes itself as "a local Android reverse-engineering / CTF analysis orchestration tool": project state is kept through a Web UI, a dispatcher launches Dockerized analysis workers per the YAML config (the Kimi Code CLI by default), and APKs dropped into `container-android/test_apk/` are analyzed automatically until a flag / key input / business logic is recovered.

Typical use case (the README run example, a CTF sample):
- Origin description: analyze this APK's validation logic across Java, JNI and native code;
- Goal: "recover the finally accepted flag/input" and produce a reproducible verification chain;
- Actual run: the project reached `COMPLETED`, the finalizer finished verification, `FLAG='kboloy0'`, and the graph contained 27 facts and 4 intents.

The real problem it solves is not "run jadx once" but: **a single LLM session's context and attention cannot carry a full reverse-engineering engagement** — "who has confirmed what / which route was disproven / where to dig next" must be externalized into shared state, so that multiple model sessions divide the work, never repeat each other, and reach verifiable conclusions.

Lineage (README "Project Lineage"): r0re is a second-generation fork of oritera/Cairn (a general AI state-space search engine, first validated on automated penetration scenarios); during development it borrowed the multi-agent CTF shared-blackboard / shared-evidence mechanism from FishCodeTech/muteki.

## 2. Architecture component breakdown

The whole is a four-piece set: Server (Web UI + protocol source of truth) — Dispatcher (scheduling) — Worker containers (analysis execution) — shared blackboard (REST). Across all 183 files, the core Java sources live under `src/main/java/com/fyr/r0re/` split into four packages: `server/` (17 classes), `dispatcher/` (26 classes), `protocol/`, `config/`.

### 2.1 r0re-serve (Spring Boot web service, default port 8001)
- Packaged by the root `Dockerfile`: `FROM eclipse-temurin:17-jre-jammy` + `COPY build/libs/r0re-*.jar` + `EXPOSE 8000`, entrypoint `java -jar`; `docker-compose.yaml` defines only this one service `r0re-server`, with the data volume mounted at `./datas/r0re/ → /root/.local/share/r0re/` (`R0RE_DATA_DIR`) and restart policy unless-stopped.
- Controller inventory (server package): `ProjectsController` (project CRUD / start-stop), `BlackboardController` (blackboard read/write), `IntentsController` (intent claiming / heartbeats / conclusions), `HintsController` (manually injected hints), `AnalysisController` + `AnalysisArtifactsService` (analysis artifact indexing), `ExportController` (export, including YAML graph snapshots), `AutomationController` + `AutomationScheduler` (automation), `CompletionPolicyService` (completion gating), `SystemController` (health).
- The Web UI is an embedded static page: `static/index.html` + Alpine.js + Cytoscape (with dagre/cola/elk/klay, four graph layouts) + Tailwind — i.e. the graph visualization draws the Fact/Intent relationship graph directly.
- Protocol models (`protocol/Models.java`): `Fact(id, description, kind, verified, creator)`, `Intent(id, from[], to, description, creator, worker, last_heartbeat_at, ...)`, `Hint(id, content, creator, created_at)`, `RuntimeEvent` (step-by-step event stream), `VerificationRecord` (the verification state machine for candidate flags), `JniMethodEntry` (class/method/signature/probable_symbol/libraries — the server structurally extracts the JNI method table from decompilation outputs).

### 2.2 r0re-dispatch (the dispatcher)
- `DispatcherRunner.java` (2437 lines) is the main loop: `runOnceUntilIdle` = `max(8, max_workers×6)` ticks + waiting for in-flight tasks; each tick pulls the project list → does quota scheduling by `max_workers` (global concurrency), `max_running_projects` (default 1), `max_project_workers` (default 3); `interval: 3` seconds doubles as the heartbeat cadence (inherited from Cairn's design).
- Multiple worker drivers are retained: `KimiWorkerDriver`, `ClaudeCodeWorkerDriver`, `CodexWorkerDriver`, `PiWorkerDriver`, `MockWorkerAdapter` (`ExternalCliWorkerAdapter` uniformly wraps external CLIs).
- Fault-tolerance constants: `STALLED_LIGHT/MEDIUM/HEAVY = 15/25/45 minutes` (stall detection graded by phase), `INTENT_FAILURE_BLOCK_THRESHOLD = 3` (the same intent failing 3 times in a row gets blacklisted), `REASON_FAILURE_CHECKPOINT_THRESHOLD = 2`.
- Phase classifier: DispatcherRunner uses a set of regexes to classify intent text into a phase (native/manifest/resource/signature/constant/verify/report); for example native matches `\b(jni|native|\.so|zygisk|frida|offset|symbol|elf|arm64|lib[a-z0-9_]+)\b`; the phase then maps to a cost class and to PromptFactory's sub-template selection.
- Project-level autonomy in swarm mode: only projects whose lease expired and whose `health=recovery_required` get auto-recovered (cooldown graded 15/30/20 seconds); projects the user manually stopped (health stays normal) are never auto-revived.

### 2.3 Worker container (container-android/, image `cairn-android-reverse:latest`)
Base image ubuntu:22.04, non-root user `reverser` (passwordless sudo), toolchain (item by item from the Dockerfile):
- Decompiling: jadx 1.5.0, apktool 2.10.0, Ghidra 11.2.1 PUBLIC (headless included), radare2 (built and installed from git);
- Dynamic: frida + frida-tools (pip), Android SDK platform-tools r37.0.0 (adb) + cmdline-tools (aapt);
- Auxiliary: androguard, unicorn, capstone (pip), Node.js v20.18.0, pi-coding-agent 0.73.0;
- Agent CLI: Kimi Code installed at `/opt/kimi-code` with a `kimi` symlink (the `Dockerfile.kimi-patch` layer, because "building the full Dockerfile from scratch is unstable at the apktool layer on this machine's network; this patch reuses the existing layer");
- Built-in knowledge: frida hook template JS (`crypto-hook.js`, `native-hook.js`, `root-bypass.js`, `ssl-pinning-bypass.js`, `trace-class.js`, `prelimimnary.js`), Ghidra post-scripts (`ListFunctions.java`, `DecompileToStdout.java`), the Android-RE-reference knowledge git repo, the r0re-blackboard skill;
- Environment variables bridging host devices: `ADB_SERVER_SOCKET=tcp:host.docker.internal:5037`, `FRIDA_HOST=host.docker.internal:14725`.

Container volume mounts (dispatch.kimi.swarm.example.yaml): `test_apk` (read-only), `output/live-analysis/{project_id} → ~/workspace/analysis` (read-write, artifacts shared across workers), `output/kimi-sessions/{project_id} → /tmp/r0re-kimi` (Kimi session persistence); network_mode host, stopped when done.

### 2.4 Shared blackboard (REST, workers connect directly)
This is r0re's biggest architectural inversion relative to Cairn (see §5). Implemented as `container-android/skills/r0re-blackboard/` (SKILL.md + blackboard.py, pure standard-library urllib, 20-second timeout):
- `GET  {R0RE_BLACKBOARD_URL}/projects/{id}/blackboard` — shared by read / read-deadends / list-intents;
- `POST /projects/{id}/intents/{intent_id}/heartbeat` — claim (body carries worker; prints `WON` on success, `LOST` with exit code 1 on failure);
- `POST /projects/{id}/blackboard/facts` — write-fact (worker, description, verified, intent_id);
- `POST /projects/{id}/blackboard/deadends` — mark-deadend;
- `POST /projects/{id}/intents/{intent_id}/conclude` — conclude (must be called, even for "nothing found");
- `POST /projects/{id}/complete` — complete (body carries a `from` list of fact ids, at least one; "The server gate will reject unsupported completions").
The returned blackboard JSON contains `facts`, `dead_ends` (id/description/creator), `open_intents`, `intents`, `hints`.

### 2.5 Host USB device bridge (`container-android/scripts/bin/device-bridge.sh`)
On macOS the adb server listens on TCP → the container connects via host.docker.internal; on the Mac, `adb forward` forwards the frida port 14725 → the container connects to the host's frida-server. Supports both usb and wifi modes; `start-r0re.sh --no-bridge` skips it.

### 2.6 Startup chain (start-r0re.sh)
Preflight (`r0re-preflight.sh`) → USB bridge → `r0re-repair.sh` repairs state → `r0re-serve.sh --background --port` → polls `curl /projects` until ready (default 60-second timeout) → `r0re-dispatch.sh --background --config=...`; `--supervise` supervises in the foreground (a `kill -0` liveness probe every 2 seconds; if serve dies, dispatch is restarted together with it); additionally there are launchd keep-alive, `r0re-health.sh`, `r0re-runtime-watch.sh`, `r0re-smoke-task.sh`, `r0re-acceptance.sh` and other ops scripts.

## 3. The worker's analysis flow: what steps run after receiving an APK

### 3.1 Task types and the swarm main chain
Three task types (Cairn primitives + r0re extensions):
- **bootstrap**: a one-shot full attempt at the project's initial state (timeout 1200s, conclude wrap-up 180s);
- **reason**: reads the graph snapshot and decides "is the Goal satisfied / propose new intents" (timeout 900s, `max_intents: 3`);
- **explore / swarm_explore**: claims one intent, executes it and produces facts (timeout 1800s);
- **race** (new in r0re): at the start of swarm mode, multiple workers all pounce on the whole target to race for speed.

Swarm dispatch logic (confirmed from the DispatcherRunner decompilation): initial project → `dispatchRace` (multiple racers sprint in parallel); if the race ends without a conclusion → log "race phase finished: no conclusive result, entering coordinator loop", entering the coordination loop; afterwards `dispatchReason` on demand (a project-level reason lease, at most one per project) → reason produces open intents → `dispatchSwarmExplore` dispatches them one by one (workers claim them inside the container themselves). In non-swarm mode it is the original Cairn flow: bootstrap → reason ⇄ explore.

The completion chain carries a **verification gate**: a `complete` call produces a CompletionCandidate (pending) → the Dispatcher's rules verifier (`completionCandidateRejectionReason`: candidate_type must be goal, value non-empty, source facts must really exist and must not include the goal, mock workers may not complete real projects) → pass means approve, fail means reject plus `quarantineProject` → after approval the finalizer (`r0re.finalizer`) settles it + exports the project + snapshots the workspace.

### 3.2 A single worker's analysis pipeline (distilled from prompts/android-reverse/bootstrap.md)
The bootstrap prompt lays out a standard five steps (skippable depending on target type):
1. **Target identification**: `file`, `aapt dump badging/permissions` (package name/version/entry Activity/permissions);
2. **Unpacking and decompilation**: `jadx --no-res --show-bad-code -d jadx_out/` (produces Java), `apktool d` (produces smali + resources); when packing is suspected (360/Tencent Legu/Baidu), check whether classes.dex is abnormally small/encrypted and whether `lib/` carries an unpacking stub, then switch to the host USB-bridge dynamic route: `adb-setup.sh connect-usb` → `frida-auto.sh <package> native` or `frida -H host.docker.internal:14725 -f <package> --no-pause`, with the explicit reminder "avoid assuming `frida -U` works inside the container";
3. **String/pattern quick scan**: grep the jadx sources for `password|secret|token|api_key|encrypt|decrypt|cipher|AES|RSA|MD5|SHA|HMAC`, URLs, `SharedPreferences|sqlite|ContentProvider`; in the so run `strings -a` + `readelf -s` for `JNI_OnLoad|encrypt|sign|verify`;
4. **Focus by Goal**: Crypto (trace `javax.crypto.Cipher/SecretKeySpec/MessageDigest` for algorithm/mode/key origin), Network (OkHttp/Retrofit→signature headers), Auth (token storage/pinning), Native bridge (`System.loadLibrary`/native declarations→the corresponding so), Components (manifest exported);
5. **Native deep-dive** (as needed): `readelf -h/-s`, `nm -D`, `r2 -A -q -c 'afl'`, then Ghidra headless.

Companion helper scripts (`container-android/scripts/bin/`, 7 of them): `apk-recon.sh` (file/aapt badging/permissions/exported components/so under lib/dex inventory/keytool certificate digest, purely static, no unpacking), `quick-jadx.sh` (jadx `--no-res --show-bad-code` + optional grep keywords, output to `~/workspace/analysis/jadx_out`), `ghidra-analyze.sh <so> [func]` (analyzeHeadless import and analyze → `ListFunctions.java` exports the function list and greps JNI/crypto keywords → `DecompileToStdout.java` decompiles a single function, falling back to `nm -D` / r2 on failure), `find-crypto.sh <jadx_out>` (four pattern classes: javax.crypto API class names / algorithm keywords / Base64 / key-storage locations), `so-strings.sh`, `adb-setup.sh`, `device-bridge.sh`.

**Dynamic layer**: `frida-auto.sh <package> <mode>` picks a hook combination per scenario — `crypto` (crypto APIs), `ssl` (pinning bypass), `root` (root detection bypass), `native` (native tracing), `custom:<script.js>`, `all`/`full`; the connection mode auto-adapts: inside a container (`/.dockerenv` exists) it defaults to `-H host.docker.internal:14725`.

**Deterministic solvers** (`tools/android/`, separating "automation facts vs model conclusions"): `android_ctf_runner.py` (builds its own workspace: unpacking, tool availability detection, java/native hints filtered by `flag|ctf|loadLibrary|native|JNI`, generates a Markdown report, pluggable deterministic plugins for known challenges), `ali_crackme3_solve.py` (Alibaba crackme3: restores the native transform chain `stored encrypted table → xor key 20 8e 13 39 → index rotations → xor 0x29 → PRGA-like S-box xor → byte rotate → first 15 bytes`), `wbox_solve.py`, `godot_ctf_runner.py`, `upx_shlib_emu.py` (UPX so unpacking emulation), `nrv2b.py`, `apply_relocs.py`.

### 3.3 Agent contract and state machine (.agents/android_reverse_ctf_agent.md)
The in-container agent configuration defines an 8-state analysis state machine:
`triage` (inventory the APK contents and tool availability) → `java_trace` (find UI events / validation classes / native calls / **decoys**) → `native_trace` (JNI entries and the native validation call chain) → `constant_extract` (comparison targets, keys, add/xor tables, encrypted blobs) → `equivalent_model` (**re-implement the validation logic in Python**) → `invert_or_search` (invert or bounded-search to derive inputs) → `verify` (assert the equivalent model passes, optional native emulation check) → `report` (final flag + explain false leads).

Guardrails (verbatim):
- "No final answer from strings alone." (no final answers from strings alone);
- No final answers by guessing a one-way hash "unless the native compare proves that exact hash is compared";
- "No claims about algorithms without evidence from code, constants, or verified behavior.";
- Hidden manual steps are forbidden: "every important action must be expressible as a script or command".

The report template enforces a six-step evidence chain: Java/UI entry → JNI/native entry → Native call chain → Constants → Transform → Compare, plus Decoys/false leads and Reproduction (`python3 tools/android/android_ctf_runner.py challenge.apk --workspace out`).

## 4. Prompt design highlights (ways of writing worth stealing)

r0re's prompt groups live under `src/main/resources/prompts/` in four sets — `default / mock / android-reverse / android-ctf` — each containing `bootstrap / reason / explore(+_conclude)` plus extension templates (android-reverse set: race, swarm_explore, explore_java/manifest/native plus each conclude; android-ctf set: explore_native_jni/constants/packed/smc/verify). `PromptFactory.java` routes intents to sub-templates by text keywords (e.g. a native intent matching `packed|upx|壳` → `explore_native_packed`, matching `smc|self.modif` → `explore_native_smc`, matching `jni|java_|registernatives|loadlibrary` → `explore_native_jni`, matching `constant|memcmp|table` → `explore_native_constants`), and compresses the graph snapshot (compactGraphYaml caps maxFacts/maxIntents/maxHints).

Design patterns worth excerpting:

1. **Blackboard discipline written into the prompts' "moment" phrasing** (shared section of bootstrap/swarm_explore):
   - "BEFORE choosing a direction: run `read` and `read-deadends` — never repeat a confirmed fact, never retry a dead end."
   - "The MOMENT you confirm a finding in real tool output: `write-fact "<finding with exact location>" --verified`. Pass `--verified` only for what you literally saw in command output."
   - "The MOMENT a route is disproven: `mark-deadend "<what was tried and why it failed>"`. A dead end is as valuable as a fact."
   - "Keep each fact atomic: one finding, exact class/method/offset/path. Large outputs go to files; reference the path."
   This operationalizes "when to write, at what granularity, and what counts as verified", instead of the abstract demand to "sync promptly".

2. **The reason prompt's "layered coverage check"** (android-reverse/reason.md): first decompose the Goal into sub-problems checked one by one against facts, then do the six-layer coverage analysis (Manifest / Java-smali / Resource / Native / Network / Storage), issuing intents for whichever layer is missing; it appends a "target type → high-value intent pattern" table (finding the encryption algorithm = `Cipher.getInstance → SecretKeySpec origin → IV generation → mode/padding`) and an anti-pattern list ("Analyze the whole application" is too broad, "Decompile the APK" is already done by bootstrap, "Look at all strings" is already scanned, issuing overlapping intents is forbidden).

3. **The four-property standard for intent descriptions**: "Specific (points at a named class/method/file/offset), Actionable (the worker knows which tool to use and where to look), Scoped (a single layer/component), Independent (parallelizable with other intents)", with good/bad examples: good — "Trace SecretKeySpec usage in com.app.crypto.AESUtil to find where the encryption key is constructed"; bad — "Find the encryption", "Analyze everything about security".

4. **Strict JSON output contract**: every prompt ends with "Return only one raw JSON object. Do not output anything else.", structured as `{"accepted": true/false, "data": {fact/complete/intents/description}}`; a rejection template is even pre-provided with the note "(never reject - you must handle the task professionally)".

5. **Two-phase wrap-up (conclude override)**: after the main phase times out or fails to parse, the same session enters the `_conclude` prompt, verbatim: "If you later receive a conclude-phase instruction, obey it immediately - stop everything and return the summary JSON." — a cheap second phase that salvages the work already done into facts, without wasting the long-run context.

6. **The race prompt's anti-duplicate-labor strategy**: "before a long-running step (Ghidra, full decompile), check the board and the analysis dir" — before starting heavy work, check whether someone on the board has already done it.

7. **Hard bilingual-report constraint** (an r0re signature): the bootstrap prompt requires writing both `report_en.md` and `report_zh.md`, two equivalent reports, via the write tool before returning JSON; the content covers an architecture overview, all confirmed findings (class names/methods/line numbers/offsets), mechanism deep-dives, bypass strategies, and key code snippets; fact.description references the report path. This is "conclusions as artifacts" rather than leaving only chat logs.

8. **The native-specific execution protocol** (android-ctf/explore_native.md): "Do not solve native crackmes by narrative reasoning alone. Every native finding must be backed by a command output or a generated analysis script." It also mandates maintaining the `~/workspace/analysis/ctf_state.json` state file; "You may return project completion only when a runnable verifier prints an explicit pass condition for the candidate." — completion rights are bound to a runnable verifier.

## 5. Differences from upstream Cairn; the blackboard mechanism borrowed from muteki

### 5.1 Original Cairn (upstream-Cairn:docs/specs/dispatcher-design.md, 1181 lines)
- Positioning: "Given an origin and a goal, it searches for a path through an unknown state space"; penetration testing is merely the first proving ground;
- Three components: Cairn Server (graph source of truth) / Dispatcher (**"the Agent never claims Intents directly, never heartbeats directly, never calls the Cairn API directly; the Dispatcher is the sole protocol writer"**) / one Worker container per project;
- Task model: bootstrap (straight solve at the start, timeout wrapped up by bootstrap_conclude) / reason (single-project lease) / explore (heartbeat claim first, then start), two-phase conclude;
- Worker selection rules: task type → max_running not full → health window → smaller priority first → fewer running first → random;
- Track record: the only all-kill (AK) at 54/54 in the second Tencent Cloud Hackathon; AGPL-3.0; backends: Claude Code / Codex / Pi; local mode skips Docker and reuses host CLIs.

### 5.2 r0re's key differences (source-level comparison)
| Dimension | Cairn | r0re |
|---|---|---|
| Implementation | Python/uv | Java 17 Spring Boot (serve+dispatch in one jar) |
| Protocol writer | Dispatcher only; agents return JSON that it writes on their behalf | **Workers in the container hit the blackboard REST directly** (blackboard.py: claim/write-fact/mark-deadend/conclude/complete) |
| Opening strategy | single bootstrap shot | swarm mode's **race, multiple workers sprinting** + coordination loop |
| Completion decision | agent self-reports complete | CompletionCandidate + rules-verifier gating + quarantine + auto-finalize + snapshot export |
| Prompts | generic default set | android-reverse/android-ctf sets + phase-regex sub-templates (jni/constants/packed/smc/verify) |
| Execution environment | generic pentest container | Android full-toolchain container + host USB adb/frida bridge + frida hook template library |
| Deterministic solving | none | android_ctf_runner + challenge plugins (ali_crackme3/wbox/godot/upx_shlib_emu) |
| Artifacts | facts on the graph | mandatory bilingual report_*.md + ctf_state.json + structured JNI method extraction |
| Extras | mock testing | launchd keep-alive, repair/watch/acceptance scripts, Web graph UI |

The costs and benefits of workers connecting directly to the blackboard: r0re gets claim races (heartbeat leases WON/LOST), instant dead_ends broadcast, and the ability to scan the whole board to self-rescue when stuck (muteki-style "When stuck — scan read for facts that unblock you"); the cost is that agent prompts must hard-code discipline to prevent board-flooding. Making dead_ends first-class ("A dead end is as valuable as a fact — it stops everyone from repeating it") appears in both projects' graph protocols; r0re pushes it forward into the worker's per-operation discipline.

### 5.3 What was borrowed from muteki
The muteki README describes itself: "A Coordinator schedules different Agent engines toward one goal, manages their context, and lets them collaborate through shared evidence"; a Planner (a separate model endpoint) makes coordination decisions and proposes Steps; Worker CLIs execute; the operator can Dispatch to create new Steps; workers missing input go through a pending card; budget items include concurrency/time/worker count/cost cap; multi-flag tasks keep collecting. The repository itself is a heavy product (Electron desktop + Next.js Web + Go runtime-agent + multi-engine adapters for claude/codex/cursor/devin/droid etc.); r0re took only its **shared evidence + coordinator/worker layering + step dispatch** collaboration skeleton and grafted it onto Cairn's Fact/Intent graph protocol.

## 6. Model configuration experience (GPT-5.4/5.5, GLM-5.1, Kimi K3)

- README "model configuration notes": during development **GPT-5.4, GPT-5.5, GLM-5.1, Kimi K3** were used; the public repo keeps only the Kimi K3 template, "refer to dispatch.kimi.swarm.example.yaml to add other models yourself" — i.e. model-agnostic: swap the base_url/key/CLI driver (the claudecode/codex/pi drivers are also retained in the code).
- `.env.example` key entries: `KIMI_MODEL_NAME=k3`, `KIMI_MODEL_PROVIDER_TYPE=anthropic` (via the Anthropic-compatible protocol), `KIMI_MODEL_BASE_URL` (pointing at the Kimi coding endpoint), `KIMI_MODEL_MAX_CONTEXT_SIZE=1048576` (1M context), `KIMI_MODEL_API_KEY` left blank to fill in; the YAML references everything through `${...}` indirection so no secrets enter Git.
- Container side: `KIMI_CODE_HOME=/tmp/r0re-kimi` (mounted to host `output/kimi-sessions/{project_id}`, sessions survive container restarts), `KIMI_CODE_DISABLE_AUTOUPDATE=1`, telemetry disabled.
- Concurrency experience: the default template runs 3 workers (`max_workers: 3`); the comment explicitly says "small machines can go down to 1 or 2", and the README admits "only tested up to 3"; `max_running_projects: 1` means single-project focus mode, all 3 workers pile onto one APK.
- Timeout budgets are graded by task type: bootstrap 1200s > explore 1800s (reason 900s), conclude uniformly 180s; `worker_healthcheck: startup_only`.
- Graded stall detection (15/25/45 minutes) + blacklisting an intent after three consecutive failures — a practical guardrail against large-context models "fake-living" (process running, no output).
