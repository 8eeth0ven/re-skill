<p align="center">
  <img src="assets/readme/hero.svg" alt="re — From binaries to evidence. One entry for knowledge, tools, and execution." width="100%">
</p>

<p align="center">
  <a href="SKILL.md"><strong>Open the skill</strong></a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="usage-scenarios.md">Find your scenario</a> ·
  <a href="techniques/INDEX.md">Explore techniques</a>
</p>

# re — Reverse Engineering Knowledge and Automation

A task-routed skill that connects platform knowledge, runtime techniques, and concrete cases with executable research workflows. Start from an APK, binary, algorithm, or runtime obstacle; follow the relevant route and leave a traceable record of what the evidence supports.

- **One entry, focused reading.** [SKILL.md](SKILL.md) selects the workflow; branch indexes lead to the articles needed for that task.
- **Knowledge connected to execution.** Move between hooking, unpacking, traffic capture, algorithm restoration, tracing, and root-cause analysis without rebuilding a toolchain from scattered notes.
- **Explicit evidence and fallbacks.** APK stages record PASS or documented DEGRADED outcomes. Missing tools, incomplete recovery, and unverified hypotheses remain visible in the report.

## Choose a Starting Point

| What you have or need | Start here |
|---|---|
| An APK to analyze from environment check through report | [APK pipeline](pipeline/pipeline.md) |
| A hook, detection, encryption, or tracing problem | [Technique index](techniques/INDEX.md) |
| A platform-specific question or vulnerability root cause | [Platform index](platforms/INDEX.md) |
| A concrete case, historical technique, or protection lineage | [Case corpus](corpus/INDEX.md) · [coverage ledger](corpus/coverage-ledger.md) |
| A vulnerability hypothesis to investigate | [Research decision tables](breach-tables-cve.md) |
| A component version to compare against known CVEs | [CVE matching workflow](cve-hunter/README.md) |
| Publicly released firmware to inspect | [Firmware discovery workflow](fw-discover/README.md) |
| A missing tool or a new tool to evaluate | [Tool radar](radar/README.md) |
| A phone, microcontroller, or serial device | [Real-device procedure](device-testing.md) |

Not sure which route fits? [Usage scenarios](usage-scenarios.md) map common situations to their first useful article.

## Quick Start

Use this repository as the `re` skill folder in your agent's supported skill location, then start with [SKILL.md](SKILL.md). The entry and its relative references stay together; individual articles can also be read directly.

From the repository root, check the library and available environment:

```bash
# Check local routes, index coverage, and source syntax.
python3 scripts/validate_library.py

# Check available tools and report missing capabilities.
python3 pipeline/env_check.py
```

These checks do not install packages. On a new machine, follow [setup.md](setup.md) to prepare the dependencies you need. The repository does **not** include the local `tools-env/` binaries/venv, raw `data/` corpus, or machine snapshots.

Then give the agent a concrete task, for example:

```text
Run the full pipeline on /absolute/path/client.apk and return the report.

My Frida hook is detected. Find an equivalent observation point
and record the evidence for the route that works.

Restore this .so's signing algorithm and document what remains unverified.
```

For an autonomous run, use the task brief in [unattended.md](unattended.md). Its existing execution and submission boundaries still apply.

## APK to Report

<p align="center">
  <img src="assets/readme/workflow.svg" alt="APK analysis workflow: S0 environment check, S1 information gathering and dependency join, S2 static analysis, S3 dynamic analysis, S4 report." width="100%">
</p>

The [pipeline](pipeline/README.md) defines commands, artifacts, acceptance gates, and fallback paths for each stage. Independent information gathering runs in parallel before dependent analysis joins; dynamic work uses the selected test emulator. Unavailable capabilities become explicit degradation entries rather than invented results.

The result is `输出/<package>-<date>/03-report.md`, alongside the supporting logs and artifacts. Continue from the report into the relevant technique or case article when deeper work is needed.

## Knowledge and Workflows

| Area | Role |
|---|---|
| [platforms/](platforms/INDEX.md) | Platform and domain knowledge: desktop/mobile systems, binaries, IoT, business, AI, blockchain, and root causes |
| [techniques/](techniques/INDEX.md) | Hooking, unpacking, evasion, algorithms, tracing, kernel observation, and tool selection |
| [corpus/](corpus/INDEX.md) | Distilled cases and historical methods, with completed and pending coverage recorded separately |
| `breach-tables/` | Recognition signals, validation actions, confirmation criteria, and false-positive exclusions, routed by the research entry |
| [pipeline/](pipeline/README.md) | APK analysis orchestration and report artifacts |
| [cve-hunter/](cve-hunter/README.md) · [fw-discover/](fw-discover/README.md) | Known-CVE matching and public-firmware candidate triage |
| [radar/](radar/README.md) | Tool discovery, baseline maintenance, and local smoke-test records |
| Local `data/` · `tools-env/` | Original corpus, generated research state, installed tools, and the Python environment; kept outside Git |

Each branch INDEX owns its file list. This page is the overview, not a second catalog.

## Working Conventions

- Use [alternative approaches](racing.md) when a route fails and [test-value conventions](test-values.md) to keep probes and cleanup traceable.
- Keep version matches and firmware rule hits as **candidates** until their evidence gates pass. [Disclosure preparation](disclosure-cve.md) covers the path from a finding to a prepared submission.
- Treat dated tool observations and offline mocks as their stated evidence, not current availability or physical-device validation. The Stalker device adapter has offline coverage; target-specific compatibility still needs measurement.
- Tool radar runs at daily 09:00 only when a host schedule is configured. Copying the folder does not install that schedule.
- See [maintenance.md](maintenance.md) for update discipline and repeatable validation.

Built for authorized security research and technical learning. Scope is described in [DISCLAIMER.md](DISCLAIMER.md). Licensed under [MIT](LICENSE).
