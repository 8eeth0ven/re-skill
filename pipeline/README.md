# APK Analysis Workflow

Given an APK path and an authorized scope, an agent follows the five stages in
[pipeline.md](pipeline.md), uses the available analysis tools, and writes a
report with evidence and limitations.

**This directory contains the deeper APK workflow and environment helpers.**
For bounded static APK/AAB analysis, use the shared CLI:

```bash
re-run analyze --asset /absolute/path/to/sample.apk --type android --output re-runs
```

See the [runner guide](../docs/runner.zh-CN.md). The CLI does not yet execute
the full S0–S4 dynamic chain; this document guides its separate integration.

## Start a task

```text
Use the re skill to analyze /absolute/path/to/sample.apk in my authorized lab.
Follow the APK workflow, save the artifacts, and return the report path,
supported conclusions, and the steps that could not be completed.
```

1. Read [pipeline.md](pipeline.md) for the stage commands, artifact contracts,
   acceptance gates, and fallback paths.
2. Run S0 environment → S1 collection → S2 static → S3 dynamic → S4 report.
3. Write to `输出/<package>-<date>/` next to the APK, or the requested output path.
4. Verify stage artifacts before proceeding. Record tool failures and skipped
   capabilities, then use the applicable fallback. Respect the user's scope,
   cancellation, and host permissions.
5. Return `03-report.md` and the remaining unknowns.

Dynamic analysis requires a suitable emulator or device. Missing dynamic tools
do not establish that the app is safe; the report must describe the static-only
coverage and skipped checks.

## Files and environment

| File | Purpose |
| --- | --- |
| [pipeline.md](pipeline.md) | Five-stage workflow, commands, outputs, gates, and fallbacks |
| [env_check.py](env_check.py) | Python environment checker with macOS/Linux/Windows paths |
| [env_scan.py](env_scan.py) | Portable version probes and serial-port descriptors; no live-device collection |
| [env_check.sh](env_check.sh) | Older macOS Bash environment checker |

From the repository root, run `python3 pipeline/env_check.py` on macOS/Linux or
`python pipeline/env_check.py` on Windows. Return codes are `0` for all checks
passing, `1` for missing optional capabilities, and `2` for critical tool gaps.
The checker can create a temporary sample for tool smoke tests when the SDK is
available; missing SDK components leave those tests unperformed.

Prepare the required tools using [setup.md](../setup.md). The stage command
examples use Bash; Windows execution requires adapting them or using Git Bash
or WSL. Actual compatibility depends on each tool and device configuration.
Historical tool versions, AVD names, and MCP results in the workflow are reference
observations and must be rechecked on the current host.

## Expected artifacts

```text
输出/<package>-<date>/
├── 00-环境/       environment checks and run logs
├── 01-静态/       decoded files, manifest, strings, symbols
├── 02-动态/       device observations, screenshots, logs if available
├── 黑板.md        stage findings and progress
└── 03-report.md   conclusions, evidence, limitations, next steps
```

This is an output contract, not a bundled example run. For deeper methods, use
the [technique index](../techniques/INDEX.md); historical cases are in the
[corpus index](../corpus/INDEX.md). Original archives and the private `data/`
indexes are not included in the public repository.

Remaining tool integration and acceptance use the
[handoff prompt](../docs/agent-completion-prompt.zh-CN.md).
