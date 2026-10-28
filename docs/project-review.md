# Historical Project Review and Peer Comparison

Assessment: **2026-10-19**, baseline `0059a9a` (`origin/main`), with local
`codex/readme-review` fixes. Baseline size: **190 tracked files, 174 Markdown, 11 Python,
3 shell scripts**; counts measure material, not verification coverage. Evidence came from
repository documentation, static helper review, offline reproductions, and official peer READMEs.
No external security scan or complete APK/firmware research run was performed.

The gap tables and Windows environment record describe that baseline. A unified CLI, 12 profiles,
dependency lock, resource/lock/evidence core, and regressions were subsequently added. Do not use
this historical review as the current capability matrix: see [runner.md](runner.md),
[delivery-status.md](delivery-status.md), and [execution-acceptance.md](execution-acceptance.md).
The original final changes had not been retested; follow [the handoff](agent-completion-prompt.md)
for explicitly commissioned implementation/acceptance work.

## Capability and Product Assessment

The repository was best positioned as a reverse-engineering methods and agent-workflow layer:
broad platform/technique coverage, scenario routing, staged APK artifacts/degradation, and runnable
firmware helpers. The product risk was mixing knowledge, executable capability, and measured
results: APK orchestration was Markdown, most domains lacked callable execution, and machine-local
records were absent from the public checkout. “Automatic” and “verified” needed object/environment
qualification.

| Strength | Repository evidence | Value |
|---|---|---|
| Platform × technique × scenario routes | SKILL, three branch indexes, 20 scenarios | Focused reading rather than loading the whole library |
| Detailed mobile/low-level methods | Frida, unpacking, algorithms, syscalls, kernel, platforms | Switching tools and observation layers |
| APK stages and artifact contracts | pipeline/pipeline.md | Starting point for a programmatic DAG |
| Firmware candidate scripts/ledgers | cve-hunter, fw-discover | Operational work beyond a link collection |
| Candidate/disclosure distinction, device care/cleanup | Module READMEs, device-testing, test-values | Reviewable research process |
| Machine artifacts mostly excluded | .gitignore | Smaller distribution and fewer accidental private commits |

| Baseline gap | Consequence | Direction |
|---|---|---|
| No shared intake/scheduler | URL/local firmware/PE lack one command | Input model, detection, registry, CLI |
| Prose-driven installation | Poor reproducibility/version compatibility | Dependency list/lock, profile health |
| No shared evidence model | Hard to correlate APK/backend/firmware/binary | Asset/Evidence/ToolRun/Finding |
| Heuristics and novelty errors | Candidates mistaken for vulnerabilities/new findings | Validators/controls, semantic patch/advisory comparison |
| Local-machine assumptions | Missing reports/devices/paths on new hosts | Probe/degrade and dated local records |
| No public full-chain benchmark | “Worked” evidence lives in ignored paths | Redistributable fixtures/integration/failure cases |
| Multi-platform articles without runtime tests | OS command/tool differences break chains | OS matrix with actual execution |
| Inconsistent source conventions | External-link prohibition versus Sources appendices | Concise bodies with traceable source appendices |

## Branch Repairs and Original Follow-up Queue

| Repaired issue | Trigger/root cause | Fix |
|---|---|---|
| Skill discovery | Escaped `\---` at SKILL start; oversized description | Standard `---`, shorter description, routed optional local records |
| Firmware status silence | Parsed --status, but main handled only default/--once | Status output whenever --once is absent |
| gzip original mutation | extract_firmware wrote `blob[:1]` to binpath | Remove source writes; update extraction layer in memory only |
| Incomplete CVE package URL | .ipk URL omitted packages/arch/feed | Build release/arch/feed/filename from the same candidate |

A temporary gzip reproduced original mutation from **58 bytes to 1 byte**, even on extraction
failure. Acceptance requires byte preservation on success and failure. OpenWrt's
`23.05.0/packages/x86_64/base/Packages.gz` uses filename-only values such as
`464xlat_13_x86_64.ipk`, which cannot resolve directly at the release root.

| Priority | Baseline concern and evidence | Required correction |
|---|---|---|
| P1 | fw.py depends on DD-WRT/OpenWrt seeds; no local --input | Shared intake/local firmware profile |
| P1 | analyzers.py scan_file co-occurs network/exec strings | Keep candidates; add call/argument/config/behavior evidence |
| P1 | cve-pipeline/novelty use zero NVD hits as novelty gate | Compare root cause/versions/patches; an existing component CVE does not exclude another |
| P1 | ERR plus NEW can aggregate to NEW | Unknown on search failure, with per-source results |
| P1 | Check lock then write is non-atomic in both helpers | Atomic/file locks, ownership/staleness, concurrency tests |
| P1 | hunter marks done before download; fw marks some failures done | completed/skipped/failed/retryable and persisted reasons |
| P1 | Download-before-size-check; unbounded gzip expansion | Streaming byte/file/path/time budgets |
| P1 | Platform articles/manual steps lack execution/confirmation | Callable adapters/profiles/validators/integration |
| P2 | Fixed 127.0.0.1:7897 proxy; macOS env_scan paths/system_profiler | Explicit config, PATH/platform detection |
| P2 | APK Markdown init infers root from $0 (usually shell) | Loaded skill path or explicit root |
| P2 | Ignored data/radar/private CHM; historical counts in general guidance | local-only labels, redacted examples/reproduction |
| P2 | Entry says 18 scenarios/11 technique areas while actual scenarios=20 | Structural validation and synchronized indexes |

Priorities concern reliability/delivery, not confirmed remote-exploit severity.

## Recorded Verification and Candidate Commands

From repository root (Windows uses `python` instead of `python3`):

```bash
python3 -m unittest discover -s tests -v
python3 cve-hunter/hunter.py --help
python3 cve-hunter/hunter.py --status
python3 fw-discover/fw.py --help
python3 fw-discover/fw.py --status
python3 pipeline/env_check.py
```

Offline branch tests used temporary synthetic inputs for original retention, status output,
package URLs, and banner-upgrade conditions, without public targets. Skill validation needs
PyYAML and standard frontmatter/required-field checks. Check both Markdown files and anchors;
link existence is not business acceptance. The assessment host was Windows; env_check returned
**2**, missing JADX/Apktool/SDK/AVD and repository tools-env/.venv. Diagnostics did not establish
APK-chain success, and historical macOS full-chain claims were not rerun.

## Product Implications and Peer Comparison

Knowledge helps choose the next analysis step, but at baseline agents still improvised execution,
recovery, evidence checks, and asset relations. Reports alone do not establish accuracy, and
candidate counts do not count vulnerabilities. Focus on methods/routing/evidence/validation;
reuse mature decompilers/device/network backends while normalizing their workflow outputs.

The following reflects official README reading on **2026-10-19**, not installation, common-sample
benchmarking, vulnerability accuracy, model cost, or stability testing. Fast-moving main branches
can differ from releases; verify versions when actually choosing a backend.

| Project | Overlap | Documented strength at assessment | Limits/tradeoffs | Reusable ideas |
|---|---|---|---|---|
| [REA](https://github.com/morluto/rea) | Multi-asset RE/agent/tool orchestration | Runnable CLI/MCP, installation, broad artifacts, Evidence/cases | External engines/provider/host/release constraints; no guaranteed bugs | Intake/readiness/evidence/provider layer |
| [IDA Pro MCP](https://github.com/mrexodia/ida-pro-mcp) | AI native RE | Decompilation/xrefs/annotations/types/database/headless sessions | IDA Pro required; README excludes IDA Free; no complete mobile/hardware workflow | Native adapter/database lifecycle/validation datasets |
| [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) | AI-Ghidra bridge | Decompilation/methods/imports/exports/rename; PyGhidra headless docs | Ghidra/JDK/Python/extension compatibility; tool bridge scope | Install/minimal tool surface/headless adapter |
| [ReVa](https://github.com/cyberkaida/reverse-engineering-assistant) | Ghidra agent investigation | Small tools/context relations, GUI/headless, investigation skills | Ghidra ecosystem; local-service default; public binding needs auth/script controls | Small result slices/errors/long sessions |
| [Rust RE Skill](https://github.com/jingjing2222/rust-reverse-engineering-skill) | Skill workflows/scripts/Claude/Codex | Rust fingerprints/symbol-boundary recovery/artifact scripts/Ghidra progress | Narrow specialty; deep work needs engines, not all assets | Precise triggers/executable steps/progress/specialist samples |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Mobile static/dynamic reports | Deployable platform, REST API/CLI, Docker | Mobile focus, devices needed for dynamics, deeper obfuscation/native work external | APK backend/report productization/integration/public checks |

The repository's distinctive contribution was the broad methods and Chinese practice context;
retain good scenario indexes and sources. REA informs shared interfaces; IDA/Ghidra should own
native database/decompiler work; MobSF can supply basic mobile reporting. Evidence levels,
controls, truthful failures, and explicit support matrices remain necessary across all projects;
none guarantees arbitrary vulnerabilities under every sample/permission/environment/logic.

### Assessment Sources

Peer links above refer to their official READMEs: REA CLI/MCP/assets/tools/evidence/cases;
IDA prerequisites/tools/headless/sessions; Ghidra extension/tools/PyGhidra; ReVa tools/modes/skills/
service boundaries; Rust workflows/scripts/progress; MobSF mobile analysis/API/CLI/deployment.
Skill format/install sources: [Codex Skills](https://developers.openai.com/codex/skills),
[Claude Code Skills](https://code.claude.com/docs/en/skills). Package-path evidence:
[OpenWrt package index](https://downloads.openwrt.org/releases/23.05.0/packages/x86_64/base/Packages.gz).

## Recommendations

Complete intake/deterministic scheduling/adapters/state/evidence before broadening knowledge.
Define actual artifacts per asset and explicit missing-tool/device outputs; do not label empty
adapters supported. Candidates need input/conditions/call path or observed behavior, negative
controls, impact/remediation before confirmation. Novelty/CVE application follows verification.
Check original hashes, command/extraction budgets, state/reference consistency, and successful/
failed end-to-end cases. Before deployment, compare fixed-sample repeatability/false positives,
not ledger size. Detailed planning: [asset-to-result.md](asset-to-result.md); execution task:
[agent-completion-prompt.md](agent-completion-prompt.md).
