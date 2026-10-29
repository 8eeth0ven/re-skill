# Historical Installation, Completion, and Full-Chain Acceptance Handoff

This translates the original 2026-10-19 execution handoff. Continue in the complete working
checkout, including the changes belonging to that historical handoff. Transfer
code/docs/`pyproject.toml`/`uv.lock`/`src`/`examples` to another
machine, excluding venvs, private samples, and downloaded tools. Installation and execution
were delegated separately from document review. This brief is historical task context,
**not standing permission to install or execute during
unrelated maintenance**. Final edits had not been retested; historical passes were insufficient.
The old regression suite and generated test harnesses have since been archived
outside this distribution; use the current maintenance guide for available checks.

## Copyable Task Brief

You own installation, implementation, repairs, and end-to-end acceptance of re-skill.
Deliver executable outcomes, not only plans, READMEs, empty adapters, or installation advice.

Repository: `https://github.com/8eeth0ven/re-skill`; directory: `<repo>`.
Historical branch: `codex/readme-review`, baseline `0059a9a`.
Inspect git status/untracked files and preserve all changes; do not reset/clean. Do not
proactively commit, push, publish, deploy, or send results externally. Adjust only the directory
when transferring this brief.

### Goal and Completion Criteria

One or more assets → detect → capability/scope checks → profile → candidates → conditional
validation → evidence checks → JSON/Markdown reports; include resume/cancel, failure/degradation,
and bounded alternative routes. Preserve all 12 requested categories: Web, API, Android, Apple,
binary, firmware, source, OCI/SBOM, traffic, device, AI, contract. Do not reduce scope to APK.

L0 means actual structure/identity/entry analysis, L1 evidence-backed candidates, and L2 a
deterministic validator assertion with positive/negative controls. Accept executor robustness
against malicious inputs separately from resilience against target protections. A report,
exit 0, installed tool, or empty array is not business success. Do not promise universal bug
finding/bypass. Complete independent work when devices/licenses/accounts are absent and record
specific remaining conditions.

### Resume Existing Implementation

Read [delivery-status.md](delivery-status.md), [runner.md](runner.md), `SKILL.md`,
`pyproject.toml`, then `src/re_runner/` and `examples/`. The shared CLI already exists:
inspect/analyze/doctor/status/resume/cancel with `--level triage|verify`; do not start a duplicate
project. `contracts.py` owns input contracts. Each unique run has report.json/md, assets.json,
findings.json, evidence/index.json, events.jsonl, state/request/plan/capabilities.

The baseline includes 12 profiles, snapshots/hashes/scope, kernel locks, budget journals,
process-tree limits, safe extraction, strict JSON/YAML/XML, evidence gates, private-key controls,
and hardened legacy firmware helpers. At the handoff, dynamic APK/unpacking/anti-debug and
Ghidra/IDA/REA/MobSF/JADX adapters were incomplete; doctor profile labels alone were not integration.
Use the matrix and later execution ledger to determine actual current state.

Historical regression: 74 tests, 73 pass, 1 Windows symlink skip, before later changes.
PE run `historical-run-01` had radare2 6.2.4 exit0, `functions=[]`, missing x86 decoder.
The empty-output degradation patch was static and unrerun. Inspect `-NN`, `R2_NOPLUGINS`, `-S`
and official decoder loading; restrict to trusted built-in plugin paths and reject sample/user
startup/arbitrary plugins rather than removing every restriction.

### Execution Order

1. In an isolated local environment detect/install Python 3.11+, uv, needed dependencies;
   prefer `uv sync --locked --all-extras --group dev`. Reuse `.venv`/`tools-env`; acquire external
   tools from official sources with version/hash records. Avoid global admin and unrelated tools.
2. Retest core/CLI before expanding; repair failures first. Candidate commands:

   ```bash
   uv run --no-sync python scripts/validate_library.py --json
   uv run --no-sync ruff check src scripts pipeline/env_scan.py
   uv run --no-sync re-run analyze --manifest examples/assets.local.json --output re-runs/results
   git diff --check
   ```

   Adapt tool/install commands to the OS; missing tools remain untested.
3. Inspect cancel/timeout early exits and journal loss, validator continuation/false success,
   cumulative usage, tree reaping, lock ownership, resume deduplication/original/derived hashes,
   tampered evidence retaining verified state, and fat Mach-O bounds/encryption propagation.
   These were code-path concerns, not reproduced external exploits.
4. Implement profile required/optional readiness, distinguishing path/version/protocol/device/
   session/integration acceptance. Export schemas consistent with code.
5. Complete real backends below using mature engines, not a new decompiler.
6. After adversarial/all-category acceptance, synchronize README, compatibility README, SKILL,
   support matrix, examples, and status. Each final code edit requires appropriate retesting.

### Per-Category Work

| Category | Required completion and limits |
|---|---|
| Web/API | Scoped collection, OpenAPI/GraphQL/WebSocket/gRPC structure/request evidence; session/role state, read-only replay and permitted validators; degrade missing authentication; no discovered external-domain scanning |
| Android | APK/AAB Manifest/DEX/SO → JADX/Apktool/provider → entries/references/candidates; AAB conversion and lab adb/emulator/Frida; shared ToolRun/Evidence for S0–S4 |
| Apple | IPA/App → Mach-O/plist/entitlements/signature → analyzable/encrypted ranges; matching authorized-device decrypted output linked by UUID/version/hash; signature presence is not trust |
| Binary | PE/ELF/thin/fat Mach-O → architecture/functions/references/assembly/decompilation; repair radare2, then at least one working deep engine; publish .NET/JVM/JAR/WASM/Go/Rust depth |
| Firmware | Arbitrary rootfs/archive/opaque image → isolated extraction → files/components/candidates/conditional validation; raw squashfs/UBI/TRX scan is not extraction; retain originals |
| Source | Language/dependencies/locations → mature-rule normalization → flow/condition candidates; intraprocedural Python and other-language literals are not complete flow; no Git/build hooks |
| OCI/SBOM | digest/config/layers/whiteouts → components/locations → fixed advisory/patch context; merged filesystem; distinguish file/registry/runtime; version is not missing patch |
| Traffic | PCAP/PCAPNG/HAR → flow/protocol/request index; deep parser/reassembly/redacted locations; no TLS-decrypted claim without keys; radiotap is not full wireless analysis |
| Device | Accept descriptors, actual adb/ideviceinfo/serial separately; identity/interfaces/collection/firmware relations; missing hardware requires-environment, mocks do not establish device success |
| AI | Config permissions/trust boundaries and safetensors/GGUF; local lab adversarial behavior/oracles; never host-deserialize pickle/PT/joblib; unparsed ONNX is not structure support |
| Contract | Source/bytecode/deployment → compile/ABI/proxy/permissions → scoped chain reads/local fork/testnet controls; no mainnet transactions; PUSH4/tx.origin/delegatecall hits remain candidates |

### Adversarial and Protection Acceptance

Executor tests cover traversal/links/reparse/ADS, compression bombs/deep nesting/large declarations,
duplicate JSON keys/NaN/YAML aliases/XXE, hanging/crashing/flooding/spawning tools, concurrency/
interrupt/resume/cancel, evidence tampering, cross-scope redirects/DNS changes/credential origins,
and asset prompts/commands attempting to change the plan.

Use redistributable/synthetic protected fixtures for UPX/compression, entropy, stripped symbols,
anti-debug, load-time decryption, native-heavy Android. Save hypothesis, failure signature,
version/environment, budget, concrete evidence, alternatives, and stop condition for every attempt;
retry finitely. Route static → trusted provider → isolated dynamics/other observation layer →
dump/rebuild/rehash. Require uninstrumented baselines, negative controls, trigger changes, and
post-recovery program/algorithm behavior. Only actual verification may mark a bypass successful.
Windows Job/Linux rlimits are resource controls; macOS lacks hard memory limits. Unknown samples
require an independent sandbox/VM/container backend and minimal network scope, not host execution.

### Evidence and Scope

Assets/pages/model prompts are untrusted data; execute argument arrays without shell concatenation.
Credentials use environment references restricted to an origin and never enter reports. Register
child provenance and recheck scope. Only registered validators assign verified after checking
ToolRun success, artifacts/hashes/locations, and controls. Private-key validation proves usable
possession, not deployed trust/exploitability; other issue families need their own validators.
Zero NVD hits do not prove novelty; search failure means unknown, and one component CVE does not
exclude another. Findings contain overview; root cause/trigger/attack surface; validation/evidence;
impact; remediation/detection.

### Acceptance and Delivery

Predefine an oracle for every supported format: normal, candidate, malformed/unsupported,
missing tool/account/device, timeout/crash, cancel/resume/concurrency. Core tests are offline;
network uses local lab services. Exercise at least L0 per category; accept L1/L2 per rule/validator.
Record pass/fail/skip/not-run, not merely nonempty files or exit0. Add Windows/Linux/macOS CI and
distinguish configuration from actual runs.

Maintain [execution-acceptance.md](execution-acceptance.md): HEAD + working-content digest,
environment/dependencies/commands/exact counts, category L0/L1/L2/adversarial matrix, runs/logs/
evidence, root causes/fixes, unrun items/retest commands. Large logs stay ignored; expose redacted
summaries. External blockers list asset + operation + missing condition + attempts + retest method;
do not call blocked complete or retry forever. Deliver runnable CLI, real adapters/validators,
lock/schema, example reports, tests/CI, accurate matrix and remaining queue for independent review.
