# Root Cause → Technique → Detection: The Master Mapping Table (Whole-Repo Index)

> Positioning: the **cross-cutting index** across the two library branches, platforms + techniques — it does not duplicate either branch's body text; it only answers "for one root cause, from failure mode to exploitation to detection to radical cure, which article in which library to read next". The root-cause theory originals are the sister pieces [injection-logic-root-causes.md](injection-logic-root-causes.md) (injection/logic/permissions) and [memory-error-root-causes.md](memory-error-root-causes.md) (memory class).

## 0. How to Use This Table

Three readings:
1. **White-box audit**: given source → first run §2's "root-cause-oriented audit checklist" (2–3 greps per stack); on a hit, go back to the §1 table row, check the "escalation primitive" column to size the impact and the "radical cure" column to write the fix recommendation;
2. **Vulnerability research**: given a PoC/CVE → find the matching root-cause row in §1 → the "exploitation technique" column points straight to the in-repo deep-dive articles;
3. **Learning root causes**: read down the "root cause" column top to bottom — that is the complete root-cause spectrum from memory safety to logic and permissions (data acquiring structural interpretation rights → grammatical standing → mental-model misalignment, a three-stage progression).

Column meanings: **failure mode** = what kind of code writes this bug; **escalation primitive** = what low-level capability the root cause upgrades into (arbitrary read-write/execution/traversal); **exploitation technique** = the engineering of that primitive and where it lives in-repo; **root-cause detection** = audit/fuzz means aimed at the root cause itself (not signatures); **radical cure** = the language-level or design-level solution that makes the whole class vanish (rather than fixing instances one by one).

## 1. The Master Table (26 Root Causes)

| Root cause | Typical failing code pattern | Escalation primitive | Exploitation technique · which in-repo article | Root-cause detection | Radical cure (language/design level) |
|------------|------------------------------|----------------------|------------------------------------------------|----------------------|--------------------------------------|
| [Memory] stack overflow | `char buf[64]; strcpy(buf,src)` unbounded copy | overwrite return address/RIP → control-flow hijack | ROP/ret2libc/SROP/stack pivot → [06/heap-exploitation.md](../06-binary-vuln/heap-exploitation.md) §8 | fuzz for long inputs; `rg 'strcpy\|sprintf\|gets\|memcpy'` without sizeof counterparts | canary+FORTIFY (mitigation); Rust/Go bounds checks (cure) |
| [Memory] heap overflow | `malloc(n); memcpy(p,src,m>n)` | overwrite adjacent chunk metadata → arbitrary-address write | tcache poisoning/unlink/FSOP → [06/heap-exploitation.md](../06-binary-vuln/heap-exploitation.md) §2-4, §7 | ASAN; allocation-vs-copy length diffing | safe-linking (mitigation); ownership languages (cure) |
| [Memory] off-by-one/null | a loop bound `<=` writes one extra byte | fabricate an illegal prev_size → chunk merging | House of Einherjar chaining → [06/heap-exploitation.md](../06-binary-vuln/heap-exploitation.md) §4.2 | diff patches for ±1; boundary-sensitive fuzz | containers/iterators instead of raw arrays |
| [Memory] UAF | `free(p); ... p->x` dangling reference | occupy the freed object → forged objects/function tables | heap spray + slot claiming; kernel UAF LPE → [06/vuln-types-exploitation.md](../06-binary-vuln/vuln-types-exploitation.md) §3; Android kernel surface → [techniques 07-kernel/kernel-exploit-fuzzing.md](../../techniques/07-kernel/kernel-exploit-fuzzing.md) | post-free same-identifier reference scanning; ASAN | ownership model/RCU/type isolation (slab freelist hardening) |
| [Memory] double-free | the same pointer freed twice (error branch/race) | tcache/fastbin dup → one chunk allocated twice | fastbin dup → [06/heap-exploitation.md](../06-binary-vuln/heap-exploitation.md) §3.2 | discipline review of NULL-after-free; ASAN double-free reports | unique_ptr/refcounting |
| [Memory] race condition | check-then-act without a lock; `copy_from_user` then TOCTOU | two paths operating on one object inside the window | DirtyPipe/DirtyCred-style credential replacement → [06/vuln-types-exploitation.md](../06-binary-vuln/vuln-types-exploitation.md) §3; syzkaller primer → [techniques 07-kernel/kernel-exploit-fuzzing.md](../../techniques/07-kernel/kernel-exploit-fuzzing.md) | race fuzzers; lock-coverage matrix review | atomics/conditional updates (per-CPU/completing check and use under the lock) |
| [Memory] type confusion | union/cast mismatch; JS engine typer vs runtime type disagreement | interpreting an object under another layout → forged objects | the V8 six-CVE patterns (TC/hole/pointer compression) → [06/vuln-types-exploitation.md](../06-binary-vuln/vuln-types-exploitation.md) §2 | Fuzzilli + IR mutation; typer range derivation audit | memory-safe languages; runtime map checks are not optional |
| [Memory] integer overflow/truncation | `int len=user; malloc(len); memcpy(p,src,len+4)` wraparound | small allocation big copy → heap overflow; int overflow bypassing ceilings | size-wraparound CVEs → [06/vuln-types-exploitation.md](../06-binary-vuln/vuln-types-exploitation.md); business-layer negative amounts → [08/business-security.md](../08-business/business-security.md) §3 | static: multiply-add without check patterns; fuzz boundary values (2^n±1) | checked arithmetic/bignums; business invariants explicitly encoded |
| [Memory] uninitialized | a local array passed straight to `write(fd,buf,n)` | leak of stack/heap residue (pointers/keys) | info leak breaking ASLR → [06/vuln-types-exploitation.md](../06-binary-vuln/vuln-types-exploitation.md) §3 | MSAN/`-Wuninitialized`; return-path review | default zero-init; prefer `calloc` |
| [Injection] SQL injection | `"...WHERE id="+id`; MyBatis `${}` | control the syntax tree (predicate injection/comments) | error-based/blind/OOB; black-box → the skill knowledge base SQLi/deserialization/XXE module; audit → [05/code-audit.md](../05-web/code-audit.md) §2-4 | concatenation taint greps (§2.2); sqlmap diffing | PreparedStatement/ORM + an ordering allowlist |
| [Injection] XSS | user input reaching HTML without context-aware escaping | execute JS in the target origin (credential theft/DOM operations) | stored XSS hitting admin backends; CSP bypass → [05/web-security.md](../05-web/web-security.md) §3; frontend surface → the skill knowledge base h1-techniques-XSS-and-frontend | context-aware DAST; template-engine escaping-switch review | template default escaping + layered by context; CSP as backstop |
| [Injection] command injection | `Runtime.exec("ping "+ip)`/`system(buf)` | shell metacharacters → arbitrary commands | the IoT-firmware `sprintf+system` high-frequency form → [07/iot/router-practice.md](../07-iot/iot/router-practice.md) CVE injection matrix; black-box → the skill knowledge base h1-high-severity-RCE-and-command-injection | `rg 'exec\|system\|popen'` + taint backtracking | argv-array APIs + argument allowlists (shell=False) |
| [Injection] path traversal | `new File(base+name)` | arbitrary file read/write → read configs/write webroot → RCE | chained with file upload → the skill knowledge base h1-high-severity-file-upload-chain; SSRF + traversal → h1-high-severity-SSRF-and-path-traversal | normalize-before/after diff fuzzing; concatenation-point greps | canonicalize + segment validation + no post-validation transformation |
| [Injection] SSTI/EL | `evaluate(userTpl)`; framework OGNL implicit evaluation | Turing-complete engine + reflection host → RCE | `${7*7}` probing → [05/web-security.md](../05-web/web-security.md) §3; the Struts OGNL evolution → [05/code-audit.md](../05-web/code-audit.md) §4 | template-source review (is user input treated as a template) | template/data separation; engine sandbox + reflection resolvers disabled |
| [Injection] XXE | parser enables external entities by default | parser-built-in fetch + file read (blind OOB) | converging with SSRF against metadata → the skill knowledge base h1-high-severity-SQLi-deserialization-XXE | missing-`DocumentBuilderFactory`-feature greps (§2.2) | DTD/external entities disabled by default (explicit factory switches) |
| [Injection] deserialization | `readObject(userBytes)`/`yaml.load` | arbitrary class construction logic executed = code execution | CC/Fastjson/Shiro gadget chains → [05/code-audit.md](../05-web/code-audit.md) §4; black-box → the skill knowledge base deserialization-gadgets | gadget-key signature scanning + entry taints; dependency manifests diffed against known chains | ban native serialization; JSON + schema + type allowlist + signatures |
| [Injection] SSRF | server-side `fetch(userUrl)` | intranet pivot + cloud metadata theft (account takeover) | redirect/DNS rebinding bypassing allowlists → root cause in [injection-logic-root-causes.md](injection-logic-root-causes.md) §3; black-box → the skill knowledge base h1-techniques-SSRF-info-leak-and-config; CodeQL taint skeleton → [05/code-audit.md](../05-web/code-audit.md) §9.1 | URL-parameter taints; a full inventory of fetch-class sinks | pin IP + re-validate every hop + schema allowlist + metadata v2 |
| [Logic] horizontal authz IDOR | `findById(id)` without an ownership condition | swap ids to walk other people's resources (architectural default omission) | object-graph traversal escalating to ATO → the skill knowledge base idor-supplement + h1-high-severity-IDOR-to-ATO | **two-account diffing is the only reliable oracle**; white-box: scanning `findById` without owner conditions (§2.2) | ORM row-level filters/Postgres RLS enforcing ownership |
| [Logic] vertical privilege escalation | edge authentication only; the backend never re-checks roles | ordinary users calling admin endpoints | hidden routes/`@PermitAll` misconfig → [05/code-audit.md](../05-web/code-audit.md) §7; black-box → the skill knowledge base h1-high-severity-privilege-escalation-and-access-control | route × role matrix checked row by row | per-object checks + default deny (annotations enforced at method level) |
| [Logic] business logic | skippable states/negatives/replay/concurrent debits | free goods/double-spends/coupon farming/negative reconciliation | combo chains and fund-loss cases → [08/business-security.md](../08-business/business-security.md) §1, §3; black-box → the skill knowledge base h1-high-severity-business-logic-and-race-fund-loss | nothing signature-scannable — business oracles are hand-built (two accounts + a state diagram) | state-machine transition tables + idempotency keys + atomic conditional debits |
| [Logic] CSRF | write endpoints relying solely on implicit cookie carriage | sending write requests with the user's hand | combos with XSS/authorization abuse → [05/web-security.md](../05-web/web-security.md) §3 | inventorying write endpoints without tokens/headers | SameSite + CSRF token + custom-header explicit presentation |
| [Logic] information disclosure | verbose errors/debug endpoints/backup files/hardcoded keys | lowering the cost of the next attack step (stack trace → framework version → gadget) | leak chains → the skill knowledge base h1-techniques-SSRF-info-leak-and-config; app-side hardcoded secrets → [techniques 04-evasion/capture-all-scenarios.md](../../techniques/04-evasion/capture-all-scenarios.md) (certificate/key extraction surface) | response diffing; path fuzzing; `rg 'password\|secret\|api[_-]key'` | unified error pages; keys into KMS; minimal returns |
| [Logic] cryptographic misuse | ECB mode/hardcoded keys/unsalted MD5/homegrown protocols | decrypted plaintexts/forged tokens/hash collisions | app-layer signature bypass → [techniques 04-evasion/rasp-bypass.md](../../techniques/04-evasion/rasp-bypass.md) | `rg 'ECB\|MD5\|DES'`; randomness-source review | mature libraries with default parameters; keys independent of code |
| [Injection] prompt injection | user text spliced into the LLM context/Agent instruction streams | hijacking model behavior → tool abuse → data exfiltration | indirect injection/Rug Pull → [09/ai-security.md](../09-ai-security/ai-security.md); AI × contracts → [10/ai-blockchain-crossover.md](../10-blockchain/ai-blockchain-crossover.md) | context-boundary review (do instructions and material share a stream) | instruction fencing + tool allowlists + output-side validation |
| [Logic] supply-chain poisoning | typosquatted dependencies/build-script execution/install hooks | build-time execution (dev machines/CI credentials) | dependency-confusion cases → [08/business-security.md](../08-business/business-security.md) §5-7 | lockfile diff audits; private registry proxy + signing | pinned versions + private registry + provenance verification |
| [Injection] file upload | extension/MIME/content triple-identity validation mismatch (blocklists + parser differences) | upload webshells/parsed into code execution | the full upload chain → the skill knowledge base h1-high-severity-file-upload-chain; Nginx/Apache parsing differences → [05/web-security.md](../05-web/web-security.md) §3 | blocklist greps (the `deny_ext` kind); Content-Type trust-point review | allowlists + randomized storage names + webroot isolation + server-side content sniffing for typing |

Smart-contract root causes form their own system and are not expanded in the master table; the original is [10/blockchain-security.md](../10-blockchain/blockchain-security.md) §2's ten bug classes. The mapping to the table above (note: most contract bugs are known root causes amplified in an "unstoppable + balance-is-state" environment):

| Contract bug | Corresponding master-table row | Amplification |
|--------------|-------------------------------|---------------|
| Reentrancy | [Memory] race condition | EVM external calls yield control flow with no locks; see the sister piece §6 |
| Integer overflow | [Memory] integer overflow/truncation | overflow directly rewrites balances (balance is state) |
| Missing access control | [Logic] vertical privilege escalation | no kill switch; one mistake is forever |
| Fake deposit | [Logic] business logic (idempotency) | replay at the exchange's bookkeeping layer |
| Flash-loan/oracle manipulation | the same trust-boundary class as [Injection] SSRF | external data sources entering on-chain state; validate-use separation |
| delegatecall storage collision | the layout version of [Memory] type confusion | proxy vs implementation contract storage-layout mismatch |

The table's "[Memory] → [Injection] → [Logic]" ordering is not random: the three segments are the root causes' three dimension-raises — **memory bugs are data acquiring structural interpretation rights (bytes treated as stack frames/chunks), injection bugs are data acquiring grammatical standing (bytes treated as ASTs), logic bugs are mental models misaligned with actual semantics (the bytes are entirely legal; the assumptions are wrong)**. Impact ceilings follow the same axis: memory tops out at arbitrary code execution; injection at whatever the host interpreter grants; logic at whatever the business grants (money, data, accounts).

## 2. The Root-Cause-Oriented Audit Checklist (Run These First on Any Codebase)

> Usage: pick the subsection for your target stack; each grep/review question maps to one §1 root-cause row. The grep tool is `rg` (ripgrep). A hit ≠ a bug — go back to the "root-cause detection" column and confirm reachability (is the entrance user-controllable?).

### 2.1 Kernel C (Linux/Android kernel)

```bash
# ① Integer wrap → small allocation with a large copy: user-controlled lengths enter unchecked multiplication/addition
rg -n 'copy_from_user|copy_from_iter' -A3 <dir> | rg -v 'if\s*\(|ret|check|fail'
rg -n '(size|len|count)\s*=\s*.*\*\s*|=\s*.*\+\s*1' --type c <dir>
# ② UAF/double-free: does the same identifier get dereferenced after kfree? Focus on error paths
rg -n 'kfree|kvfree|brelse|put_' --type c <dir> -A6
# ③ Races: are all writes to shared structures (global/file-private data) protected by locks?
rg -n 'mutex_lock|spin_lock|rcu_read_lock' <dir> | sort  # Compare against coverage of write paths
# ④ Uninitialized memory: stack arrays copied directly to output
rg -n '\w+\s+\w+\[\d+\];' -A3 <dir> | rg 'copy_to_user|memcpy'
```
Three review questions: does any error path miss a free / double-free? Are struct fields re-trusted after `copy_from_user`? Can the thing be swapped out between the permission check (check) and the actual operation (use) (credential/path-class TOCTOU)? The kernel fuzzing and exploitation primer chain is [techniques 07-kernel/kernel-exploit-fuzzing.md](../../techniques/07-kernel/kernel-exploit-fuzzing.md); the Android kernel observation surface is [techniques 07-kernel/android-kernel-ebpf.md](../../techniques/07-kernel/android-kernel-ebpf.md).

### 2.2 Java Web (Spring Family)

```bash
# ① SQL/MyBatis ${} concatenation
rg -n 'createStatement|createQuery|jdbcTemplate\.' -A2 src | rg '\+|getParam|@Request'
rg -n '\$\{' src/main/resources/mapper/            # ${} is raw concatenation; #{} is parameter binding
# ② Three sink classes: command execution/deserialization/XXE
rg -n 'Runtime\.getRuntime\(\)\.exec|ProcessBuilder|new ScriptEngine'
rg -n 'readObject|XMLDecoder|Yaml\.load|enableDefaultTyping|JSON\.parseObject'
rg -n 'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory' -A6 | rg -v 'disallow|EXTERNAL|secure'
# ③ SSRF: trace URL construction back to user-controlled sources
rg -n 'new URL\(|HttpClient|openStream|RestTemplate' -B4 src | rg 'getParameter|@RequestParam|@PathVariable'
# ④ Architectural access-control failures: findById-style calls without ownership conditions are high-value and often missed
rg -n 'findById|getOne|selectById|load\(' -A3 src | rg -v 'userId|tenantId|owner|current'
rg -n 'preHandle|@PermitAll|antMatchers' src        # Compare boundary authorization with unprotected routes
```
The taint-methodology corpus (CodeQL skeletons, component bugs classified by trigger surface, the Fastjson/Shiro evolution lines) → [05/code-audit.md](../05-web/code-audit.md) §4, §9.

### 2.3 JS Engines (V8 Class)

Static review focuses on **"the gap between optimizer promises and runtime facts"**:
```bash
rg -n 'VisitMul|VisitAdd|VisitBitwise|VisitCompare' src/compiler/typer.cc   # Is range inference conservative?
rg -n 'CheckBounds|CheckInt32Condition|CheckMaps' -B4 src/compiler/          # Which checks can Typer eliminate?
rg -n 'Map::TryUpdate|migrate|set_map' src/objects/                          # Map-migration windows can become type-confusion windows
```
Three questions: does TurboFan's inferred interval hold under every feedback (SimplifiedLowering truncation)? Can deopt roll back after the types are already polluted? Under pointer compression, which object's compressed map is cheapest to forge with a 32-bit offset? Cases and sandbox-escape chains → [06/vuln-types-exploitation.md](../06-binary-vuln/vuln-types-exploitation.md) §2; the fuzz tooling surface → the same piece §7 (Fuzzilli/AFL++ seven engines).

### 2.4 Smart Contracts (Solidity)

```bash
# ① Reentrancy: are state writes before or after external calls (checks-effects-interactions)?
rg -n '\.call\{|\.call\.value|\.transfer\(|\.send\(' -B8 -A4 contracts/
# ② Storage collisions/proxy layouts
rg -n 'delegatecall|assembly|storage' contracts/
# ③ Weak randomness/oracle-manipulation sources
rg -n 'block\.timestamp|blockhash|block\.difficulty|tx\.origin' contracts/
# ④ Attack-surface inventory: all externally reachable functions
rg -n 'function\s+\w+.*(external|public)' contracts/
```
Tools: `slither contracts/` (reentrancy-eth/unchecked-returndata rules) + Foundry PoC-reproduction templates → [10/blockchain-security.md](../10-blockchain/blockchain-security.md) §3. Three review questions: is state updated only after the external call? Does the upgrade proxy's storage-slot layout match the implementation contract's? Does the price come from an on-chain manipulable source?

### 2.5 PHP / Python Web Quick-Scan Edition

```bash
rg -n 'eval\(|assert\(|create_function|preg_replace.*\/e|unserialize\(|system\(|shell_exec' <dir>
rg -n 'subprocess\.(call|run|Popen)\(\s*["\x27]|os\.system|pickle\.loads|yaml\.load\(\s*\w+\)|render_template_string' <dir>
rg -n '\$_(GET|POST|REQUEST)\[' -A2 <dir>    # Shortest path from a superglobal directly to a sink
```

### 2.6 Mobile App Surface (Android, Black-box + Semi-White-box)

The mobile root-cause matrix stacks **client-trust root causes** (everything local is tamperable) on top of the server-side bugs: hooking/traffic-capture/unpacking are the standard trio for "treating the client as the attack surface" —
- the hook surface (Java/native) → [techniques 02-frida/java-layer/](../../techniques/02-frida/java-layer/) + [native-hook-cheatsheet.md](../../techniques/02-frida/native-hook-cheatsheet.md)
- packing/unpacking (the dex's true face) → [techniques 03-unpacking/dex-unpacking.md](../../techniques/03-unpacking/dex-unpacking.md)
- traffic capture and pinning bypass (the network surface) → [techniques 04-evasion/capture-all-scenarios.md](../../techniques/04-evasion/capture-all-scenarios.md) + [ssl-pinning-bypass.md](../../techniques/04-evasion/ssl-pinning-bypass.md)
- the client-side "detection"-class root causes (why local checks are always bypassed) → [techniques 04-evasion/detection-landscape.md](../../techniques/04-evasion/detection-landscape.md)

### 2.7 Go / Node Web

```bash
# Go: fmt.Sprintf concatenated into query/exec is a common injection pattern
rg -n 'fmt\.Sprintf\(' --type go src | rg 'Query|Exec|Raw|Order|Where'
rg -n 'exec\.Command\(ctx,\s*"sh",\s*"-c"' --type go src      # Fallback calls that invoke the shell
rg -n 'http\.Get\(|NewRequest\(' -B4 src | rg 'Param|Form|Query' # SSRF surface
# Node: eval family + template rendering + prototype chains
rg -n 'eval\(|new Function\(|child_process\.exec\(' src        # exec(String) invokes a shell
rg -n '\.render\(|renderTemplate\(' -B3 src | rg 'req\.(body|query|params)'
rg -n '__proto__|merge\(|lodash\.set\(' src                     # Prototype-pollution entry points
```
Go's `database/sql` parameter placeholders (`$1`/`?`) are the bind channel; any `Sprintf` in front of them is a fallback to the lexer channel — the verdict is the same as §1's master statement, regardless of language.

### 2.8 C++ Userspace Monoliths (Browser Renderers/Office/Virtualization)

Source-level three questions + patterns:
```bash
rg -n 'reinterpret_cast<|static_cast<' -B2 src | rg 'void\*|char\*'   # Likely type-confusion surfaces
rg -n 'unique_ptr|shared_ptr|raw new|delete ' src  # Mixed ownership models allow raw pointers to outlive their intended scope
rg -n 'base::CheckedNumeric|CheckedMul|saturated_cast' src  # Reverse signal: existing integer-overflow guards may expose unguarded neighboring operations
```
Without source, the procedure is fixed: version diffing (the pre/post-patch instruction delta = the root-cause coordinates) → PoC construction → crash attribution. Document-format (the Office Equation Editor) and virtualization-surface cases → [06/vuln-types-exploitation.md](../06-binary-vuln/vuln-types-exploitation.md) §5-6; diff-audit methodology is textually universal, the web-side version is in [05/code-audit.md](../05-web/code-audit.md) §8.

### 2.9 IoT Firmware (No Source)

Firmware audits have no source to grep, but there is an equivalent — **string cross-references in the disassembly are the sink list**:
```bash
binwalk -Me firmware.bin          # Extract squashfs
strings -tx ./squashfs-root/bin/httpd | grep -E 'ping|traceroute|wget|curl|reboot'
# In IDA/Ghidra: find xrefs to each command string → trace argument origins → check whether parsed HTTP variables reach them
```
Hitting `sprintf(buf,"...%s",user_var)` followed by `system(buf)` is the command-injection root cause (the firmware form of the master table's [Injection] command-injection row). Full five-path extraction/emulation/real-world cases → the [07/iot/](../07-iot/iot/) articles.

## 3. The Three Detection Layers for Root Causes (Which Root Cause Fits Which Detection)

| Means | Reliably finds | Structurally blind to | Reason |
|-------|----------------|------------------------|--------|
| grep/pattern review | sink-shaped root causes (injection/command/XXE/hardcoded) | logic, authz, races | it sees only "code shapes", not "missing semantic constraints" |
| SAST taint (CodeQL) | injections/SSRF with a source→sink path | bugs without sinks (IDOR/logic) | taint analysis presupposes a suspicious sink; `findById` is not a sink |
| DAST/fuzz | memory corruption (with a crash oracle), known-signature injections | logic/authz/negatives | the oracle problem: business correctness has no machine-judgeable "anomaly" signal |
| Two-account diffing (manual) | authz/logic | — | the only oracle that can express "business consistency" — the root cause of why it cannot be automated |

Read backwards, this table is the basis of hunting strategy: root causes densely covered by automation (memory, signature injections) have near-zero stock left and suit 0day research; root causes the tools are blind to (logic/authz) suit black-box business hunting — the two sides of the same coin as the skill knowledge base's division (the black-box matrix).

## 4. The Rise-and-Fall History of Cures and Mitigations (Why the "Radical Cure" Column Is Design-Level)

Mitigations get bypassed; bypass techniques get suppressed by new mitigations — the genealogy of this arms race is itself the review line for root causes (the mitigation-matrix original → [06/heap-exploitation.md](../06-binary-vuln/heap-exploitation.md) §6):

| Mitigation | Root causes suppressed | Bypassed by | Lesson |
|-----------|------------------------|-------------|--------|
| Stack canary | stack overflow overwriting the return address | info leaks reading the canary/format-string reads/ROP that never crosses the canary region | mitigation only raises cost; it does not eliminate the root cause |
| NX/DEP | on-stack code execution | ret2libc/ROP (data still works as a pointer sequence) | the "data as structure" root cause remains |
| ASLR | fixed-address exploitation | any info leak realigning the base | the leak root cause (uninitialized/OOB reads) and the execution root cause multiply |
| safe-unlinking/tcache key | heap pointer forgery | the high-version IO/FILE school | every generation of mitigation breeds the next exploitation school |
| Parameterized queries | SQL injection | ORDER BY/table-name positions (cannot be bound) | **even cures have a boundary: syntactic positions that cannot be bound still need allowlists** |
| SameSite cookie | CSRF | subdomains/certain browser policy differences | the "implicit carriage" root cause is only eradicated by explicit presentation (tokens) |
| Idempotency keys | replay | double submission inside the parallel window (key not yet effective) | the cure depends on the landing quality of "atomicizing check and use" |

Conclusion (echoing the sister piece §7): **the criterion for the "radical cure" column is making the whole class's generative mechanism vanish** (bind channels/ownership models/row-level ownership/atomicization), not making one payload fail. When writing fix recommendations in an audit report, use this table to judge whether you are proposing a mitigation or a cure — for mitigations you must state plainly "the bypass surface still exists".

## 5. Maintenance Conventions

- New bug classes get a row in §1; the "exploitation technique" column must point at **an existing in-repo file** (in platforms/ or techniques/; verify the path with `ls` first);
- Black-box techniques point only at the skill knowledge base (the two-library division: platforms/ covers principles, techniques/ covers reverse-engineering chains; black-box checklists live in `<local-skills-root>/skill/知识库/`);
- Root-cause theory always expands in the sister pieces; this table keeps its "one row, one verdict" index density and never copies body text.
