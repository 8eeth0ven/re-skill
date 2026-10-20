# re — Asset Analysis Runner & Reverse Engineering Workflows

**A task-oriented reverse engineering library for authorized security research.**

re helps a researcher or an AI agent choose an analysis route, use the relevant
tools, collect evidence, and prepare a reviewable report. It combines platform
references, practical techniques, historical cases, an APK workflow, and local
firmware candidate scripts.

[English](README.md) · [简体中文](README.zh-CN.md) · [Scenario guide](usage-scenarios.md) · [Project review](docs/project-review.zh-CN.md) · [All-asset roadmap](docs/asset-to-result.zh-CN.md)

> **Working-branch delivery:** `re-run` provides shared input, bounded analysis,
> evidence, resume/cancel and reports for 12 asset categories. Format and depth
> vary; dynamic unpacking, instrumentation and broader validators still need
> integration and acceptance. These changes are local and uncommitted; the latest
> edits have not been retested. Skill and tool installation are separate.

See the [runner guide and matrix](docs/runner.zh-CN.md),
[delivery status](docs/delivery-status.zh-CN.md) and the
[installation, completion and acceptance prompt](docs/agent-completion-prompt.zh-CN.md).

For the Agent preparing the environment, from this working checkout:

```bash
uv sync --locked --all-extras --group dev
uv run --no-sync re-run inspect --asset /absolute/path/to/sample.apk
uv run --no-sync re-run analyze --asset /absolute/path/to/sample.apk --output re-runs
uv run --no-sync re-run analyze --manifest examples/assets.local.json --output re-runs
```

Network/live-device reads require an explicit scope. Every run writes a unique
directory with JSON/Markdown reports, evidence, coverage, logs and state.
`--level verify` currently validates private-key possession using sign/verify
and a changed-message control; deployment trust and exploitability remain unknown.

## What you can do

| Goal | Start here | Expected result |
| --- | --- | --- |
| Analyze an APK | [APK workflow](pipeline/README.md) | Static artifacts, optional dynamic observations, and a report with skipped steps |
| Write a hook or investigate obfuscation | [Technique index](techniques/INDEX.md) | A relevant method, code examples, and verification guidance |
| Investigate a native binary or platform | [Platform index](platforms/INDEX.md) | Platform-specific analysis routes and tool references |
| Review known firmware CVE candidates | [cve-hunter](cve-hunter/README.md) | Version-match candidates and optional banner rechecks in a local ledger |
| Discover firmware issues with static rules | [fw-discover](fw-discover/README.md) | Heuristic candidates to prioritize for deeper verification |
| Find historical cases or choose tools | [Corpus index](corpus/INDEX.md), [tool table](techniques/05-toolbox/tool-master-table.md) | Distilled cases, source pointers, and tool options |
| Plan device testing or disclosure | [Device testing](device-testing.md), [disclosure](disclosure-cve.md) | A controlled validation or reporting workflow |

The [scenario guide](usage-scenarios.md) covers 20 common situations, including
traffic capture, signatures, failed hooks, unpacking, CTFs, and vulnerability
root causes.

## Quick start

### 1. Download and browse

```bash
git clone https://github.com/8eeth0ven/re-skill.git re
cd re
```

Read [SKILL.md](SKILL.md) for branch routing or the
[scenario guide](usage-scenarios.md) for a task-based entry. Browsing the library
requires no analysis tool installation.

### 2. Use it as an agent skill

Install the **whole repository** in a supported skill directory so its relative
references and helper scripts remain available. Choose one client and location.
For a user-level installation on macOS/Linux:

```bash
# Codex
git clone https://github.com/8eeth0ven/re-skill.git "$HOME/.agents/skills/re"

# Claude Code
git clone https://github.com/8eeth0ven/re-skill.git "$HOME/.claude/skills/re"
```

On Windows, use PowerShell:

```powershell
# Codex
$reSkillPath = Join-Path $HOME '.agents\skills\re'
git clone https://github.com/8eeth0ven/re-skill.git $reSkillPath

# Claude Code
$reSkillPath = Join-Path $HOME '.claude\skills\re'
git clone https://github.com/8eeth0ven/re-skill.git $reSkillPath
```

Create the parent directory if needed. If the destination already exists, update
that checkout instead of cloning over it. For project-local skills, use
`.agents/skills/re` in Codex or `.claude/skills/re` in Claude Code. Skill discovery
and invocation depend on your client version; see the
[Codex documentation](https://developers.openai.com/codex/skills) and
[Claude Code documentation](https://code.claude.com/docs/en/skills).

In Codex, invoke `$re`; in Claude Code, invoke `/re`. Other clients can read
[SKILL.md](SKILL.md) directly if they support the same skill layout.

### 3. Prepare only the tools your task needs

Follow [setup.md](setup.md), then run from the skill's repository root:

```bash
# macOS / Linux
python3 pipeline/env_check.py
```

```powershell
# Windows
python pipeline/env_check.py
```

The checker returns `0` for all checks passing, `1` for missing optional
capabilities, and `2` for critical tool gaps. It can probe adb and local MCP
availability and build a temporary smoke-test sample when the SDK is present.
The [setup guide](setup.md) covers `pyproject.toml`, `uv.lock` and separate
external tools. The optional [inventory](pipeline/env_scan.py) uses portable
version probes and serial-port enumeration; it does not collect live Android/iOS
data. `doctor --profile` reports per-kind required/optional capabilities with
missing/present/runnable readiness, and `re-run schema` exports the input/report
JSON Schemas; device/session-level readiness still needs the real environment.

| Task | Tools or environment |
| --- | --- |
| Browse references | Git or a browser |
| Run firmware Python helpers | Python 3.12+ recommended; their imports use the standard library |
| APK static workflow | Python, Java, JADX, Apktool; Android SDK/aapt2 and APKiD/apkleaks enhance coverage |
| APK dynamic workflow | adb, an appropriate emulator/device, and Frida as required; MCP is optional |
| Firmware extraction | Bounded TAR/ZIP/gzip; opaque filesystems need an isolated extractor adapter |
| Deep native analysis | An external engine such as Ghidra, IDA, or radare2, with its own setup |

Firmware `--status` and `--help` commands can be used without downloading samples:

```bash
python3 cve-hunter/hunter.py --status
python3 fw-discover/fw.py --status
```

On Windows, replace `python3` with `python`. These commands read local progress
and may create the empty data directory. `--once`, `--seed`, and `--verify` perform
network or analysis work; read each module's README before running them.

### 4. Give the agent a concrete task

```text
Use the re skill to analyze /absolute/path/to/sample.apk within my authorized
lab. Follow S0–S4, preserve evidence, and return the report path, conclusions,
and the steps that could not be completed.
```

```text
Use the re skill to inspect /absolute/path/to/sample.so. Identify the relevant
functions, trace the algorithm, and explain which conclusions are supported by
static or dynamic evidence.
```

The APK workflow produces this layout when executed by an agent with the
required tools:

```text
输出/<package>-<date>/
├── 00-环境/       environment checks and run logs
├── 01-静态/       decoded files, manifest notes, strings, symbols
├── 02-动态/       device observations, screenshots, logs if available
├── 黑板.md        stage findings and progress
└── 03-report.md   conclusions, evidence, limitations, next steps
```

See [pipeline/pipeline.md](pipeline/pipeline.md) for the full artifact contract.
This layout describes workflow output; it is not a bundled example run.

## Repository map

| Path | Role |
| --- | --- |
| [SKILL.md](SKILL.md) | Agent entry and routing rules |
| [src/re_runner/](src/re_runner/cli.py) | Unified CLI, profiles, execution, evidence and reporting |
| [pyproject.toml](pyproject.toml), [uv.lock](uv.lock) | Python package and dependency lock |
| [examples/](examples/README.md), [tests/](tests/test_runner_profiles.py) | Text examples and regression fixtures |
| [usage-scenarios.md](usage-scenarios.md) | 20 practical entry scenarios |
| [platforms/](platforms/INDEX.md) | Windows, Android, Linux, iOS, macOS, Web, binary vulnerabilities, IoT, business, AI, blockchain, root causes |
| [techniques/](techniques/INDEX.md) | Instrumentation, unpacking, evasion, algorithms, tracing, kernels, frameworks, tool selection |
| [corpus/](corpus/INDEX.md) | Distilled historical cases and coverage ledger |
| [pipeline/](pipeline/README.md) | APK workflow and environment helpers |
| [cve-hunter/](cve-hunter/README.md) | Known-CVE version matching and banner rechecks |
| [fw-discover/](fw-discover/README.md) | Firmware extraction, heuristic rules, and verification guidance |
| [breach-tables-cve.md](breach-tables-cve.md) | Vulnerability-investigation playbook router |
| [radar/](radar/README.md) | Tool discovery process and baseline; scheduling is host-managed |
| [docs/](docs/project-review.zh-CN.md) | Project review, competitor comparison, and implementation handoff |

## Capabilities and limits

- **Depth is explicit.** Twelve categories have execution branches; formats and
  L0/L1/L2 depth are documented separately. The legacy APK dynamic chain remains
  agent-driven. Resource limits are not a hostile-code security sandbox.
- **Candidates need verification.** A matched version can contain backported
  fixes. `binary-confirmed` means the banner agrees with the index, not that a
  vulnerability is reproduced. Firmware rule hits need data-flow, reachability,
  configuration, and behavior checks. Zero NVD keyword hits do not prove novelty.
- **Historical observations need rechecking.** Original-machine tool versions,
  smoke results, and discovery counts are not current-host guarantees. No public
  production benchmark is established. Regression fixtures are bundled; OS CI,
  physical devices and final edits still need the testing Agent's acceptance.
- **Some resources are local-only.** `data/`, original CHM archives, tool binaries,
  virtual environments, environment snapshots, and live radar reports are
  excluded by [.gitignore](.gitignore). The public corpus contains distilled notes.

See the [project review](docs/project-review.zh-CN.md) for verified defects,
strengths, and remaining limitations. The [all-asset roadmap](docs/asset-to-result.zh-CN.md)
and [Agent implementation prompt](docs/agent-completion-prompt.zh-CN.md) define
the remaining adapter, adversarial and acceptance work.

## Related projects

| Project | Focus | Where it fits alongside re |
| --- | --- | --- |
| [REA](https://github.com/morluto/rea) | CLI/MCP analysis across native binaries and application artifacts | A broader executable integration layer |
| [IDA Pro MCP](https://github.com/mrexodia/ida-pro-mcp) | IDA analysis, database operations, and headless sessions | Deep native analysis when IDA Pro is available |
| [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) | Ghidra analysis and annotation tools | Ghidra-backed tool access |
| [ReVa](https://github.com/cyberkaida/reverse-engineering-assistant) | Ghidra MCP with focused tools and investigation skills | Longer Ghidra investigations and headless workflows |
| [Rust RE Skill](https://github.com/jingjing2222/rust-reverse-engineering-skill) | Rust-specific workflows and artifact scripts | A specialist companion for Rust binaries |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Mobile static/dynamic assessment with APIs and a UI | A more packaged mobile assessment workflow |

This compares project roles and documented features, not measured performance.
For tradeoffs and sources, see the [full comparison](docs/project-review.zh-CN.md).

## Contributing

Keep additions task-oriented: describe when to use a technique, its prerequisites,
the evidence it produces, and its limits. Update the relevant index and retain
source references in a `Sources` appendix or corpus entry. Check relative links
and distinguish actual validation from planned work.

Exclude private samples, credentials, machine snapshots, and downloaded tools.
Use the [probe conventions](test-values.md) for research artifacts. Run relevant
checks when changing helper scripts; a documented workflow is only verified
after it has actually been exercised.

## License and authorized use

[MIT](LICENSE). Use within your authorized research scope; see
[DISCLAIMER.md](DISCLAIMER.md). Follow the licenses and access terms of any
separately obtained tool or original source material.
