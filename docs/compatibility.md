<!-- re-knowledge-metadata
{
  "schema": "re-knowledge/v1",
  "id": "re.operations.host-compatibility",
  "kind": "article",
  "host_platforms": [
    "macos",
    "windows",
    "linux"
  ],
  "target_platforms": [
    "android",
    "documentation"
  ],
  "target_versions": [],
  "last_tested": null,
  "confidence": "inference",
  "evidence": [
    {
      "id": "e-msys",
      "kind": "source",
      "ref": "https://www.msys2.org/docs/filesystem-paths/",
      "provenance": "source",
      "observed_at": "2026-10-28",
      "target_versions": []
    },
    {
      "id": "e-adb",
      "kind": "source",
      "ref": "https://developer.android.com/tools/adb",
      "provenance": "source",
      "observed_at": "2026-10-28",
      "target_versions": []
    },
    {
      "id": "e-powershell",
      "kind": "source",
      "ref": "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_redirection",
      "provenance": "source",
      "observed_at": "2026-10-28",
      "target_versions": [
        "PowerShell 7.4+"
      ]
    },
    {
      "id": "e-field-report",
      "kind": "user-report",
      "ref": "#field-pitfalls-host-and-target-behavior-are-not-interchangeable",
      "provenance": "user-report",
      "observed_at": null,
      "target_versions": []
    },
    {
      "id": "e-design",
      "kind": "analysis",
      "ref": "#binary-output-example",
      "provenance": "inference",
      "observed_at": null,
      "target_versions": []
    },
    {
      "id": "e-runtime-launchers",
      "kind": "source",
      "ref": "../src/re_runner/ghidra_adapter.py",
      "provenance": "source",
      "observed_at": "2026-10-28",
      "target_versions": []
    },
    {
      "id": "e-timeout-helper",
      "kind": "source",
      "ref": "../pipeline/run_with_timeout.py",
      "provenance": "source",
      "observed_at": "2026-10-28",
      "target_versions": []
    },
    {
      "id": "e-java-adapters",
      "kind": "source",
      "ref": "../src/re_runner/decompile.py",
      "provenance": "source",
      "observed_at": "2026-10-28",
      "target_versions": []
    }
  ],
  "claims": [
    {
      "id": "c-msys",
      "statement": "MSYS2 documents automatic native argument conversion and a per-command exclusion mechanism.",
      "confidence": "source-claimed",
      "evidence": [
        "e-msys"
      ]
    },
    {
      "id": "c-binary-channel",
      "statement": "The Android documentation provides exec-out for screenshot acquisition; acquisition correctness still needs validation.",
      "confidence": "source-claimed",
      "evidence": [
        "e-adb"
      ]
    },
    {
      "id": "c-powershell",
      "statement": "PowerShell documents native stdout byte preservation in redirection from version 7.4.",
      "confidence": "source-claimed",
      "target_versions": [
        "PowerShell 7.4+"
      ],
      "evidence": [
        "e-powershell"
      ]
    },
    {
      "id": "c-field-observations",
      "statement": "The user reported H1-H4; original device builds, dates and complete reproductions were not supplied.",
      "confidence": "source-claimed",
      "evidence": [
        "e-field-report"
      ]
    },
    {
      "id": "c-capture-example",
      "statement": "The binary capture recipe and its 30-second timeout are a proposed example, not a reproduction on the reported device.",
      "confidence": "inference",
      "value_kind": "example",
      "evidence": [
        "e-design"
      ]
    },
    {
      "id": "c-launcher-boundaries",
      "statement": "Recognized JADX/APKtool distributions use native Java paths; Ghidra retains a trusted batch launcher with argument restrictions, while the generic timeout helper refuses Windows batch scripts rather than silently invoking a shell.",
      "confidence": "source-claimed",
      "evidence": [
        "e-runtime-launchers",
        "e-timeout-helper",
        "e-java-adapters"
      ]
    }
  ],
  "review_after": "2026-11-27",
  "decay": {
    "mode": "event",
    "max_age_days": null,
    "triggers": [
      "host-shell-or-adb-update",
      "target-build-change",
      "contrary-byte-integrity-control"
    ],
    "note": "The review date is maintenance policy; source review dates are not device test dates."
  },
  "related_ids": [
    "re.governance.knowledge-engineering"
  ]
}
-->

# Host Compatibility and Field Pitfalls

Evidence default: inference; only tagged claims inherit listed evidence.

Use this guide when moving the skill between macOS, Windows, and Linux. Host OS,
target OS, shell, CPU architecture, and optional engines are separate dimensions.
An installed Python runner does not establish device access or a working native
debugger. [setup.md](../setup.md) owns installation; the [runner guide](runner.md)
owns asset contracts, capabilities, scope, and evidence states.

## Platform × Step Matrix

| Step | macOS | Windows, native PowerShell | Linux |
|---|---|---|---|
| Locate Python | `python3 --version`, or use uv's selected interpreter | `py -3 --version` or `python --version`; avoid assuming the Store alias is an installed interpreter | `python3 --version`, or uv's selected interpreter |
| Install runner dependencies | `uv sync --locked --all-extras --group dev` | Same uv command; no Bash activation required | Same uv command |
| Execute runner | `uv run --no-sync re-run ...` | Same uv command, with quoted Windows asset paths | Same uv command |
| Tools virtual environment | `tools-env/.venv/bin/python` | `tools-env/.venv/Scripts/python.exe` | `tools-env/.venv/bin/python` |
| Temporary workspace | Python `tempfile`; shell `$TMPDIR` when set | Python `tempfile`; PowerShell `$env:TEMP` | Python `tempfile`; shell `$TMPDIR` when set |
| Android SDK | Explicit SDK environment, then host-specific discovery | Explicit SDK environment, then `%LOCALAPPDATA%\Android\Sdk` when present | Explicit SDK environment, then host-specific discovery |
| Configure a native engine | Trusted executable on PATH or the adapter's explicit `RE_RUN_*` option | Trusted native executable/official launcher; preserve `.exe` and spaces in paths | Trusted executable on PATH or explicit option |
| Validate the library | `uv run --no-sync python scripts/validate_library.py --json` | Same Python command; shell-only checks must report unavailable rather than pretend to pass | Same Python command |
| Optional device work | Select an exact identity and scope | Same identity/scope contract; account for driver and shell differences | Same contract; USB permissions may need host setup |

Do not copy a macOS `bin/python` path onto Windows or add Homebrew directories as a
universal fallback. Optional dependency availability still depends on architecture
and the upstream package, especially native bindings and platform-specific debuggers.

### Shared CLI Commands

Run from the repository root after the selected dependencies are installed:

```text
uv sync --locked --all-extras --group dev
uv run --no-sync python scripts/validate_library.py --json
uv run --no-sync re-run inspect --asset "path with spaces/sample.apk"
```

macOS/Linux example:

```bash
uv run --no-sync re-run analyze --asset "$HOME/Samples/sample.apk" --output re-runs --language en
```

Windows example:

```powershell
uv run --no-sync re-run analyze --asset 'C:\Samples\sample.apk' --output re-runs --language en
```

The CLI's compatible report-language default remains `zh`; choose `--language en`
for a new English report. Resume retains the language stored in that run.
No activation script or global PATH edit is needed for these uv commands.

## Native Entry Points and Remaining Boundaries

The shared APK initializer has two host entries and one state format:

```bash
source pipeline/init_pipeline.sh "/path/to/sample.apk"
# Restore, without resetting the stored deadline:
source pipeline/init_pipeline.sh --state-file "/path/to/run/env.json"
```

```powershell
. ./pipeline/init_pipeline.ps1 -Apk 'C:\Samples\sample.apk' -Output 'C:\Research\run'
. ./pipeline/init_pipeline.ps1 -StateFile 'C:\Research\run\env.json'
```

`env.json` is the portable state contract; `env.sh` remains a compatibility output.
Choose an installed Python 3.11+ interpreter through `RE_PYTHON` when the shell's
Python alias is ambiguous. Loading an existing state does not start a new run,
probe a device, or renew the saved monotonic deadline. See the
[workflow initialization contract](../pipeline/pipeline.md#01-safe-shared-state-initialization-bash--git-bash--wsl)
for the original budget and same-host-boot limitation.

**c-launcher-boundaries — source-claimed:** the [Ghidra adapter](../src/re_runner/ghidra_adapter.py)
retains its trusted official Windows launcher but rejects characters that its
batch expansion can reinterpret. Use an independent working path without
`&`, `|`, `<`, `>`, `^`, `%`, `!`, double quotes, or newlines; preserve the original
input. Spaces and Unicode remain separate argv values, but native Windows tool
execution still needs confirmation on that host. Recognized JADX/APKtool
batch configurations use the [native Java/distribution adapter](../src/re_runner/decompile.py) instead.

The generic [timeout helper](../pipeline/run_with_timeout.py) reports exit **126**
for a Windows `.bat`/`.cmd` command. Use a native executable/Java entry or the
Android runner's supported adapter; it does not enable `shell=True` as a fallback.
The PowerShell initializer does not translate the Bash stage tables into
PowerShell commands. These are explicit implementation boundaries, not a claim
that every third-party RE engine runs on every host.

## Field Pitfalls: Host and Target Behavior Are Not Interchangeable

The four field cases below were supplied by the user in the knowledge-engineering
upgrade brief. Their exact test dates, target builds, and complete reproductions
were not supplied. They are **source-claimed field observations**, not a new claim
of verification on every device or shell. Preserve those unknowns when creating a
variant dossier or reproducing them. The named source IDs below distinguish official
tool behavior from a proposed mitigation.

| ID | Recognize | Recorded failure | Working rule and verification |
|---|---|---|---|
| H1 — MSYS argument conversion | Git Bash/MSYS launching native `adb.exe`, with Android paths such as `/data/local/tmp/...` | A target path was rewritten as a Windows host path. Exact MSYS/build versions are unknown. | MSYS2 documents automatic conversion [e-msys]. Prefer native PowerShell/Python for this boundary, or exclude the relevant arguments from conversion for the individual command. Check the actual remote argv/path before attributing a failure to the target. |
| H2 — PTY/text contamination | Copying a binary through an interactive `adb shell`, or a shell pipeline that treats native output as text | The acquired bytes were corrupted. Exact adb/shell/build versions are unknown. | Use a noninteractive binary channel such as `adb exec-out` [e-adb], and write stdout as bytes. Validate the format/signature and expected length or a known hash. An exit code alone does not validate an acquisition. |
| H3 — toybox `dd` options | A recipe assumes GNU `dd` flags, particularly `count_bytes` | The target's toybox build did not accept that option. Exact build/version is unknown. | Inspect the selected device's command help before choosing flags. Use only supported `bs`, `skip`, and `count` semantics, with offsets/counts calculated on the host. Reproduce against a small owned test file first; do not generalize to all toybox releases. |
| H4 — target-shell arithmetic | Computing a large address/offset with Android mksh arithmetic | The observed target performed signed 32-bit wraparound. Exact build/version is unknown. | Calculate offsets using host Python integers, pass the checked result as a literal, and validate the resulting range. This is a workaround for the observed build, not a claim that all Android shells have the same integer width. |

### MSYS Boundary Example

For a selected, permitted test device, MSYS2's exclusion variable can be scoped
to one command rather than persisted globally. This syntax example uses a read-only
path check; substitute the exact device and owned test path from the task.

```bash
MSYS2_ARG_CONV_EXCL='*' adb -s '<selected-serial>' shell ls /data/local/tmp/re_probe.bin
```

This prevents MSYS conversion for that native invocation [e-msys]. It does not fix
incorrect quoting inside a remote shell. Prefer argument arrays in Python and keep
host paths distinct from target paths. Do not rewrite input filenames or disable
path conversion globally for unrelated tools.

### Binary Output Example

PowerShell redirection behavior depends on version: native stdout byte preservation
was added in PowerShell 7.4 [e-powershell]. For a portable acquisition recipe, avoid depending
on that distinction and write the subprocess stdout directly to a binary file.
This example captures a screenshot only after the task has selected and scoped
the device; it does not discover or authorize devices.

```python
from pathlib import Path
import subprocess

serial = "<selected-serial>"
destination = Path("re_screenshot.png")
with destination.open("xb") as output:
    result = subprocess.run(
        ["adb", "-s", serial, "exec-out", "screencap", "-p"],
        stdout=output,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
if result.returncode:
    raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
with destination.open("rb") as captured:
    if captured.read(8) != b"\x89PNG\r\n\x1a\n":
        raise ValueError("The capture is not a PNG stream; retain it as failed evidence")
```

The 30-second timeout is an example task budget, not a measured device threshold.
The PNG signature check proves only the expected file prefix; a complete decode,
size/range check, or a known hash is needed for the task's stronger assertion.
The direct binary-file mitigation is an implementation inference based on the
documented channel/redirection behavior; it has not been retested on the user's
original device in this maintenance task.

## Keep Platform Knowledge Reusable

Record the host OS/architecture, shell/version, target build/ABI, command version,
input/output byte counts, expected versus observed behavior, and evidence location
when reproducing a pitfall. Raw captures, session identifiers, paths tied to one
engagement, and long device logs stay in that project's workspace. Promote only the
general recognition rule, bounded reproduction, verified scope, and counterexample
to the library. Use the [knowledge-engineering guide](knowledge-engineering.md)
and its article/variant templates for that promotion.

## Sources and Evidence Boundaries

- **e-msys — source-claimed:** [MSYS2 filesystem paths](https://www.msys2.org/docs/filesystem-paths/), automatic native argument conversion and `MSYS2_ARG_CONV_EXCL`; reviewed 2026-10-28.
- **e-adb — source-claimed:** [Android adb documentation](https://developer.android.com/tools/adb), SDK Platform Tools and `exec-out` screenshot capture; reviewed 2026-10-28.
- **e-powershell — source-claimed:** [PowerShell redirection documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_redirection), native byte redirection behavior from 7.4; reviewed 2026-10-28.
- **e-field-report — source-claimed:** the user's upgrade brief, four field observations H1–H4. Original device/build/date evidence is pending; do not relabel these as `verified-on-device`.

These source reviews do not certify installed versions or device compatibility.
The current implementation and test reports must state which host was actually
executed and which platform branches were exercised only through controlled tests.

## Optional Host Matrix Checks

The [CI example](../examples/ci/portable.yml) runs locked dependencies, route and
metadata checks, and the offline regression suite on macOS, Windows, and Linux,
with Python 3.11 and 3.13. It is an optional example, **not an active workflow or
a claim that those jobs have passed**. Copy it to `.github/workflows/portable.yml`
when repository workflow-write permission is available. The same checks run
locally without a hosted service.

Action versions in that example were checked against the
[official uv integration guide](https://docs.astral.sh/uv/guides/integration/github/)
on 2026-10-28. Runtime tools, devices, private samples, and model/cloud endpoints
are not provisioned by the workflow; existing conditional tests retain their
stated skip conditions. A green offline matrix does not certify dynamic bypasses.
