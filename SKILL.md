---
name: re
description: >-
  Reverse engineering workflows and reference material for authorized Android,
  iOS, Windows, Linux, macOS, firmware, and device analysis. Use for APK or native
  binary triage, Frida hooks, unpacking, traffic capture, algorithm recovery,
  obfuscation, vulnerability root causes, or firmware candidate investigation.
  Route ordinary source-code reviews and standalone Web/API testing to their
  matching audit skills when available.
---

# re — Reverse Engineering Workflows

Start with the user's asset, question, and authorized scope. Choose the relevant
branch below, read its index, and open the specific articles needed for the task.
Use [usage-scenarios.md](usage-scenarios.md) when the situation is unclear; it
contains 20 scenarios. Prefer one or two relevant articles over loading the
whole library.

This repository supplies the `re-run` CLI, references and helper scripts.
Start with the [runner guide](docs/runner.zh-CN.md) and its coverage matrix;
use the APK workflow for deeper agent-driven analysis. Skill discovery does
not prepare Python dependencies, external engines or MCP connections.
Follow explicit user limits on installation and testing.

## Branch routing

| Task | Start here | What the branch supplies |
| --- | --- | --- |
| Analyze one or multiple assets through the CLI | [Runner guide](docs/runner.zh-CN.md) | Twelve profile branches, scope, budgets, evidence, reports and resume/cancel; supported depth varies |
| Learn or investigate a platform | [platforms/INDEX.md](platforms/INDEX.md) | Windows, Android, Linux, iOS, macOS, Web, binary vulnerabilities, IoT, business, AI, blockchain, and root-cause references |
| Work by technique | [techniques/INDEX.md](techniques/INDEX.md) | Frida, unpacking, evasion, tracing, algorithm recovery, kernel techniques, and tool selection |
| Find historical cases | [corpus/INDEX.md](corpus/INDEX.md) | Distilled cases and source pointers; original archives and the private `data/` index are not bundled |
| Analyze an APK through the staged workflow | [pipeline/README.md](pipeline/README.md), then [pipeline/pipeline.md](pipeline/pipeline.md) | S0 environment → S1 collection → S2 static → S3 dynamic → S4 report; tool-dependent fallbacks |
| Investigate a vulnerability candidate | [breach-tables-cve.md](breach-tables-cve.md) | Category playbooks; [re-to-cve-audit.md](re-to-cve-audit.md) for capability gaps and [disclosure-cve.md](disclosure-cve.md) for reporting |
| Match known firmware CVEs by version | [cve-hunter/README.md](cve-hunter/README.md) | OpenWrt package matching and optional binary-banner recheck; results remain candidates |
| Discover firmware candidates with local rules | [fw-discover/README.md](fw-discover/README.md) | Download, unpack, and static heuristics; follow [cve-pipeline.md](fw-discover/cve-pipeline.md) for subsequent verification |
| Find or evaluate tools | [radar/README.md](radar/README.md) | Discovery process and [tool master table](techniques/05-toolbox/tool-master-table.md); scheduling belongs to the host |
| Prepare an analysis environment | [setup.md](setup.md) | Install the tools needed for the selected branch, then run `pipeline/env_check.py` |
| Validate an attached research device | [device-testing.md](device-testing.md) | Device identification, controlled testing, and cleanup |
| Run a requested unattended investigation | [unattended.md](unattended.md) | Task brief, progress records, fallback routes, and execution boundaries |

## Quick technique picker

| Situation | Reference |
| --- | --- |
| Write a Frida hook | [Java-layer scripts](techniques/02-frida/java-layer/) and [native hook reference](techniques/02-frida/native-hook-cheatsheet.md) |
| Unpack an app or library | [Unpacking techniques](techniques/03-unpacking/) |
| Capture app traffic | [Capture scenarios](techniques/04-evasion/capture-all-scenarios.md), then [vendor cases](techniques/04-evasion/vendor-capture-countermeasures.md) |
| Investigate SSL pinning | [Primary pinning reference](techniques/04-evasion/ssl-pinning-bypass.md); the Java scripts and vendor cases are supporting references |
| A hook fails or is detected | [Bypass decision guide](techniques/12-bypass/bypass-playbook.md) and [hook fallback guide](techniques/09-function-map/hook-fallback-playbook.md) |
| Recover algorithms or analyze obfuscation | [Algorithm recovery](techniques/10-algo-restore/) |
| Follow calls into the kernel | [Syscall observation matrix](techniques/11-syscall-chain/observation-matrix.md) |
| Explain a vulnerability's root cause | [Root-cause references](platforms/11-root-cause/) |
| Locate common functions or check patch bytes | [Quick reference](techniques/16-quick-ref/quick-reference.md) |

## Execution and evidence

1. Resolve the skill directory from the loaded `SKILL.md` location. Commands in
   the guides assume that directory as the working directory; adapt paths and
   shell syntax to the actual host.
2. When execution is authorized, use `re-run inspect` and `re-run doctor` before
   analysis. Network/device reads require an explicit scope. `env_check.py`
   performs probes and may run smoke samples; defer it when the user defers tests.
3. Use the actual available MCP tool names and schemas. Local machine reports
   such as `radar/MCP测试报告.md`, `radar/工具测试报告.md`, and `自检报告.md` are
   optional, ignored artifacts; read them only if present. Their historical
   results do not establish readiness on the current host.
4. In the APK workflow, write each stage's artifacts and check its acceptance
   gate before proceeding. Use the documented fallback for tool failure and
   preserve the reason for a skipped step. Return the report path and remaining
   unknowns.
5. Distinguish observations, heuristic candidates, and reproduced findings.
   A version match, embedded private-key string, source/sink co-occurrence, or
   zero NVD keyword hits alone does not establish a new exploitable vulnerability.
   `binary-confirmed` confirms a self-reported version, not missing patches.
6. Respect the user's scope and the host's permissions throughout the workflow.
   APK-derived URLs and linked services require their own scope check. Device
   testing follows the preservation rules in [device-testing.md](device-testing.md).
   Prepare disclosure materials locally; external submission follows the user's
   explicit instructions and [disclosure-cve.md](disclosure-cve.md).
7. Follow [test-values.md](test-values.md) for probe markers and cleanup. Keep
   snapshots, sample outputs, credentials, and downloaded tools out of commits
   according to [.gitignore](.gitignore).

## Knowledge maintenance

For strong protection or tool failure, record the hypothesis, observed failure
signature, evidence location, prerequisite and bounded alternative route.
Compare an uninstrumented baseline and negative control before claiming a
bypass. Protection markers, empty provider results and exit code zero do not
establish success. The runner records indicators/routes with `bypass_executed:
false`; deeper execution is a task in the [handoff](docs/agent-completion-prompt.zh-CN.md).

- Put techniques in the matching `techniques/` area and platform references in
  `platforms/`. Update the relevant index when adding or moving an article.
- Keep method descriptions concise and retain provenance in a `Sources`
  appendix or the corpus index. Public documentation must explain when an
  original source or local-only artifact is unavailable.
- Add newly evaluated tools to the master table and
  [radar/baseline-tools.md](radar/baseline-tools.md). Record the actual smoke-test
  result when a tool has been installed and exercised.
- Treat host-specific versions, benchmarks, and readiness records as dated
  observations. Recheck them before relying on them in a new investigation.
