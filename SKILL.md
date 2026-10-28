---
name: re
description: >-
  Unified reverse engineering for Windows, Android, Linux, iOS, WEB, binary vulnerabilities,
  smart devices, business, AI, blockchain, and root-cause analysis. Routes platform knowledge,
  techniques, cases, APK automation, bounded asset-analysis CLI, CVE research, and tool discovery.
  Use for reverse engineering, Android RE, iOS RE, IoT, frida, hook, unpacking, traffic capture,
  SSL pinning, anti-debugging, root detection, app packers, OLLVM, obfuscation, VMP,
  algorithm restoration, risk control, RPC, syscall, eBPF, kernel hook, bypass, RASP,
  pwn, CTF, vulnerability root cause, unidbg, full-chain execution, tool radar,
  frida-mcp, jadx-mcp, ghidra-mcp, attack-and-evasion, and AI RE.
  Also use for "look at this app's encryption", "how do I reverse this .so", or "run the pipeline".
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
| Analyze one or multiple assets through the CLI | [Runner guide and capability matrix](docs/runner.zh-CN.md) | `re-run` supplies bounded profile analysis, evidence, reports, resume/cancel, and adapters; depth varies by profile |
| APK analysis or "run the full chain" | [pipeline/pipeline.md](pipeline/pipeline.md) | Five-stage DAG, acceptance gates, and fallbacks; artifact layout in [pipeline/README.md](pipeline/README.md) |
| Find a CVE or investigate a vulnerability hypothesis | [breach-tables-cve.md](breach-tables-cve.md) | Recognition → verification → acceptance → false-positive exclusions; [re-to-cve-audit.md](re-to-cve-audit.md) for research and [disclosure-cve.md](disclosure-cve.md) for disclosure preparation |
| Match components against known CVEs | [cve-hunter/README.md](cve-hunter/README.md) | Version-match candidates and the N-day ledger; a version match alone is not a confirmed vulnerability |
| Discover candidates in publicly released router firmware | [fw-discover/README.md](fw-discover/README.md) | Firmware extraction, static rules, and candidate triage; rule hits are hypotheses pending verification |
| Look up platform or domain knowledge | [platforms/INDEX.md](platforms/INDEX.md) | Windows, Android, Linux, iOS, macOS, WEB, binary vulnerabilities, IoT/hardware, business, AI, blockchain, and root causes |
| Choose a technique or solve a runtime obstacle | [techniques/INDEX.md](techniques/INDEX.md) | Use the direct technique routes below for frequent tasks |
| Find a concrete case, legacy technique, or historical evolution | [corpus/INDEX.md](corpus/INDEX.md) | Consult [corpus/coverage-ledger.md](corpus/coverage-ledger.md) before assuming coverage is complete; original-source lookup uses the data index |
| Discover or fill a tool gap | [radar/README.md](radar/README.md) | [Tool selection table](techniques/05-toolbox/tool-master-table.md); discovery → catalog → smoke test → log |
| Initialize a new machine | [setup.md](setup.md) | Inventory first, install missing dependencies, then run the cross-platform health check |

An API-only vulnerability assessment belongs to the separate `skill` skill;
a source-code audit belongs to `secure-code-audit`. Use RE here when runtime visibility,
packing, detection, signatures, or binary behavior blocks that work.

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

- **Real devices:** follow [device-testing.md](device-testing.md) for "run real-device / serial validation". No flashing, bootloader unlocking, firmware writes, or system-partition changes. Use only the permitted temporary test artifacts and self-installed test APKs. Microcontroller work is read-only; host kernel experiments belong in VMs. If no device is detected, record that result.
- **Unattended execution:** follow [unattended.md](unattended.md) for "unattended: reverse ..." or "unattended: hunt CVEs ...". Persist incremental evidence, follow acceptance gates, and use [racing.md](racing.md) when an approach fails. Keep the existing boundaries for outbound submission, spending, irreversible changes, scope, and physical actions.
- **Test values and cleanup:** follow [test-values.md](test-values.md): `[RE]` / `[REPROBE]`, `0x52455052`, `REPROBE-<date>-<seq>`, and device names prefixed with `re_`. High-collision probes such as `0x42` and `deadbeef` are forbidden. Check the value families at wrap-up and remove only the current task's temporary device state; retain labeled evidence.
- **Scheduled radar:** daily 09:00 execution depends on a configured host schedule. A copied directory does not install a scheduler. See [setup.md](setup.md) and [radar/README.md](radar/README.md) for migration or manual execution.

## CLI Runner and Execution Readiness

The repository includes the `re-run` CLI (`src/re_runner/`), `pyproject.toml`,
and `uv.lock`. The runner requires Python 3.11+; skill discovery alone does not
install its dependencies, external engines, or MCP connections. Follow
[setup.md](setup.md) and the user's installation/testing limits.

When execution is requested, inspect the asset and use the runner's profile
readiness report before analysis. Refer to the [runner guide](docs/runner.zh-CN.md)
for actual CLI options and profile coverage. Network and live-device reads use
its explicit scope mechanism; APK-derived URLs are not automatically follow-up
targets. Agent-driven APK analysis remains the separate staged workflow above.

Distinguish observations, heuristic candidates, and reproduced findings. A
private-key string, source/sink co-occurrence, version match, zero NVD hits, or
exit code zero does not prove exploitability or novelty. The runner's protection
routes are indicators/plans with `bypass_executed: false`; deeper work belongs in
the [completion handoff](docs/agent-completion-prompt.zh-CN.md). Compare a baseline
and negative control before claiming a successful bypass.

## Tool Environment

- Common CLI tools: `jadx`, `apktool`, `r2`, `adb`, and `7z`; detect availability before use.
- Python environment: `tools-env/.venv`. On this machine, use `UV_CACHE_DIR=/tmp/uv-cache uv pip install -p tools-env/.venv/bin/python <package>`; the venv has no pip and this cache path avoids known sandbox cache failures. Windows equivalents are in [setup.md](setup.md).
- Prefer `python3 pipeline/env_check.py` for cross-platform health checks. Keep `pipeline/env_check.sh` as the legacy macOS Bash fallback.
- Optional local MCP observations: `radar/MCP测试报告.md`; tool observations: `radar/工具测试报告.md`. These machine-local records are excluded from Git and may be absent in a fresh clone. They are dated observations, not a live capability guarantee. Check the installed client/server version and architecture before a dynamic session; prepared server binaries are under `tools-env/frida-server/` when installed.

## Maintenance Rules

1. Route through this entry and the selected INDEX; read relevant articles progressively. Each INDEX owns its branch's file list.
2. Method bodies contain methods and code, without new external links, attributions, or personal names. Preserve existing source lookup metadata and historical evidence; use the data index to locate original corpus material.
3. APK full-chain requests enter `pipeline/pipeline.md`; acceptance and artifact structure come from that workflow.
4. Apply `test-values.md` to probes, hooks, and output, including the verification and cleanup loop.
5. Ingest techniques into the matching `techniques/` area, domain knowledge into `platforms/`, and tools into the selection table plus radar baseline. Smoke-test installable tools before marking them usable.
6. Before maintenance, read [maintenance.md](maintenance.md) for current conventions and any available local historical audit for known regressions. Do not turn old smoke tests into current results.
7. [SSL pinning bypass](techniques/04-evasion/ssl-pinning-bypass.md) is the primary methodology. [Java certificate snippets](techniques/02-frida/java-layer/sslpinning-and-certificates.md), [capture scenarios](techniques/04-evasion/capture-all-scenarios.md), and the [vendor archive](techniques/04-evasion/vendor-capture-countermeasures.md) are subordinate; the primary article resolves conflicts.
8. On a new machine, follow `setup.md` first and restore the optional radar schedule separately. Leave raw corpus data, installed tools, and existing historical records intact during documentation maintenance.
