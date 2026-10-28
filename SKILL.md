---
name: re
description: >-
  Reverse engineering of binaries, mobile apps, firmware, algorithms, and runtime behavior.
  Use to choose RE techniques, inspect supported assets with the bounded re-run CLI,
  run the staged APK workflow, investigate binary vulnerability hypotheses, or discover RE tools.
  For a standalone API penetration test or full source-code security audit, use the corresponding
  specialist skill; basic API/source asset inspection remains supported here.
---

# Reverse Engineering: One Entry, Task-Based Routing

Use this skill to inspect binaries, observe runtime behavior, restore algorithms and protocols,
validate vulnerability hypotheses, and select working tools. Choose the task below first.
If the situation is unclear, match it in [usage-scenarios.md](usage-scenarios.md).
The branch INDEX is its authoritative file list: open the relevant one or two articles by name,
then follow additional references only as needed. Do not read the whole library by default.

## Select the Workflow

| Task or available input | Start here | Continue with |
|---|---|---|
| Analyze one or multiple assets through the CLI | [Runner guide and capability matrix](docs/runner.md) | `re-run` supplies bounded profile analysis, evidence, reports, resume/cancel, and adapters; depth varies by profile |
| APK static information, candidates, and a complete report | [Runner guide](docs/runner.md) | Use the Android profile or requested static stages; a complete static report does not require an emulator |
| Explicit APK S0–S4/full-chain or requested dynamic analysis | [pipeline/pipeline.md](pipeline/pipeline.md) | Five-stage DAG with scoped device/emulator work, gates, and fallbacks; artifacts in [pipeline/README.md](pipeline/README.md) |
| Find a CVE or investigate a vulnerability hypothesis | [breach-tables-cve.md](breach-tables-cve.md) | Recognition → verification → acceptance → false-positive exclusions; [re-to-cve-audit.md](re-to-cve-audit.md) for research and [disclosure-cve.md](disclosure-cve.md) for disclosure preparation |
| Match components against known CVEs | [cve-hunter/README.md](cve-hunter/README.md) | Version-match candidates and the N-day ledger; a version match alone is not a confirmed vulnerability |
| Discover candidates in publicly released router firmware | [fw-discover/README.md](fw-discover/README.md) | Firmware extraction, static rules, and candidate triage; rule hits are hypotheses pending verification |
| Look up platform or domain knowledge | [platforms/INDEX.md](platforms/INDEX.md) | Windows, Android, Linux, iOS, macOS, WEB, binary vulnerabilities, IoT/hardware, business, AI, blockchain, and root causes |
| Choose a technique or solve a runtime obstacle | [techniques/INDEX.md](techniques/INDEX.md) | Use the direct technique routes below for frequent tasks |
| Find a concrete case, legacy technique, or historical evolution | [corpus/INDEX.md](corpus/INDEX.md) | Consult [corpus/coverage-ledger.md](corpus/coverage-ledger.md) before assuming coverage is complete; original-source lookup uses the data index |
| Discover or fill a tool gap | [radar/README.md](radar/README.md) | [Tool selection table](techniques/05-toolbox/tool-master-table.md); discovery → catalog → smoke test → log |
| Initialize a new machine | [setup.md](setup.md) | Inventory first, install missing dependencies, then run the cross-platform health check |

Resolve the input before choosing the DAG. A URL may identify a Web/API asset or an APK download;
use the supplied artifact/type/context to distinguish them. If “full pipeline” plus a bare URL
leaves that unresolved, clarify the intended asset before device work or package execution.
A Web URL does not enter the APK DAG. Clear local APK or documentation-only tasks need no extra
confirmation; select the requested static/dynamic depth directly.

The runner's Web/API/source profiles provide bounded asset inspection, structural evidence,
and declared candidate checks. A standalone API penetration test belongs to `api-pentest`
(or the broader `skill` workflow); a full source-code security audit belongs to
`secure-code-audit`. Use RE to supply binary/runtime evidence, unpacking, detection analysis,
or restored signatures when those investigations need it. Profile presence does not imply
full protocol/business testing or a full interprocedural source audit.

## Direct Technique Routes

| Task | Open first |
|---|---|
| A hook is detected or an approach fails | [Bypass decision playbook](techniques/12-bypass/bypass-playbook.md) |
| Write a Java or native frida hook | [Frida section in the index](techniques/INDEX.md#02-frida) and [native hook reference](techniques/02-frida/native-hook-cheatsheet.md); Java snippets are under `techniques/02-frida/java-layer/` |
| Unpack DEX or native code | [DEX unpacking](techniques/03-unpacking/dex-unpacking.md), then [eBPF unpacking](techniques/03-unpacking/ebpf-unpacking-deep.md) or [SO repair and dumping](techniques/03-unpacking/so-repair-dump.md) as applicable |
| Capture traffic | [General scenarios](techniques/04-evasion/capture-all-scenarios.md) → [vendor-specific countermeasures](techniques/04-evasion/vendor-capture-countermeasures.md) |
| Understand device fingerprinting or risk controls | [Device fingerprinting and risk controls](techniques/04-evasion/device-fingerprint-risk.md) |
| Restore algorithms, white-box logic, obfuscated code, or offline RPC | [Algorithm restoration methodology](techniques/10-algo-restore/algo-restoration-methodology.md), then the matching article in `techniques/10-algo-restore/` |
| A hook is terminated; locate an equivalent observation point | [Android function layers](techniques/09-function-map/android-function-layers.md) → [hook fallback playbook](techniques/09-function-map/hook-fallback-playbook.md) |
| Follow calls down to the kernel | [Observation matrix](techniques/11-syscall-chain/observation-matrix.md), then the relevant syscall-chain article |
| Explain the vulnerability's root cause | [Root-cause mapping](platforms/11-root-cause/root-cause-to-technique-map.md) |
| Locate common functions, NOP encodings, or simple bug patterns | [Quick reference](techniques/16-quick-ref/quick-reference.md) |
| Use AI/MCP or coordinate an RE workflow | [RE orchestration](techniques/01-methodology/llm-reverse-orchestration.md) and [AI-assisted workflows](techniques/08-ai-re/ai-re-workflows.md) |

## Execution Modes and Essential Constraints

Treat unlabelled legacy behavior and thresholds as inference. Evidence labels apply
only to their recorded version/platform scope; a historical verified result does
not establish current efficacy. Validate the selected claim before reporting it
as an observed outcome.

- **Real devices:** follow [device-testing.md](device-testing.md) for "run real-device / serial validation". No flashing, bootloader unlocking, firmware writes, or system-partition changes. Use only the permitted temporary test artifacts and self-installed test APKs. Microcontroller work is read-only; host kernel experiments belong in VMs. If no device is detected, record that result.
- **Unattended execution:** follow [unattended.md](unattended.md) for "unattended: reverse ..." or "unattended: hunt CVEs ...". Persist incremental evidence, follow acceptance gates, and use [racing.md](racing.md) when an approach fails. Keep the existing boundaries for outbound submission, spending, irreversible changes, scope, and physical actions.
- **Test values and cleanup:** follow [test-values.md](test-values.md): `[RE]` / `[REPROBE]`, `0x52455052`, `REPROBE-<date>-<seq>`, and device names prefixed with `re_`. High-collision probes such as `0x42` and `deadbeef` are forbidden. Check the value families at wrap-up and remove only the current task's temporary device state; retain labeled evidence.
- **Scheduled radar:** daily 09:00 execution depends on a configured host schedule. A copied directory does not install a scheduler. See [setup.md](setup.md) and [radar/README.md](radar/README.md) for migration or manual execution.

## Execution and Maintenance Details

Before running tools, read [execution readiness](docs/execution-reference.md#cli-runner-and-execution-readiness)
and the selected workflow. It defines runner limitations, scoped network/device reads,
observation/candidate/verified distinctions, and the baseline/control gate for bypass claims.
For installation or machine-local observations, use the [tool environment](docs/execution-reference.md#tool-environment).
For library updates, read [maintenance.md](maintenance.md) and the
[maintenance rules](docs/execution-reference.md#maintenance-rules); preserve raw corpus,
installed tools, and dated evidence. SSL pinning's authoritative methodology is
[ssl-pinning-bypass.md](techniques/04-evasion/ssl-pinning-bypass.md); other articles provide
snippets, scenarios, or vendor examples.

For host migration, use the [platform compatibility matrix](docs/compatibility.md).
For knowledge intake, evidence labels, variant dossiers, decay review, or article
renames, follow [knowledge engineering](docs/knowledge-engineering.md) and its
templates. These maintenance references are conditional; analysis tasks do not
need to preload them. Existing articles remain routable during staged migration.
