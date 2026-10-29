<!-- re-knowledge-metadata
{
  "schema": "re-knowledge/v1",
  "id": "re.operations.host-installation-matrix",
  "kind": "article",
  "host_platforms": [
    "macos",
    "windows",
    "linux"
  ],
  "target_platforms": [
    "documentation",
    "android"
  ],
  "target_versions": [],
  "last_tested": null,
  "confidence": "inference",
  "evidence": [
    {
      "id": "e-uv-install",
      "kind": "source",
      "ref": "https://docs.astral.sh/uv/getting-started/installation/",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-python",
      "kind": "source",
      "ref": "https://docs.astral.sh/uv/guides/install-python/",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-uv-env",
      "kind": "source",
      "ref": "https://docs.astral.sh/uv/pip/environments/",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-jdk",
      "kind": "source",
      "ref": "https://adoptium.net/installation/archives",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-jdk-mac",
      "kind": "source",
      "ref": "https://adoptium.net/installation/macOS",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-jdk-win",
      "kind": "source",
      "ref": "https://adoptium.net/installation/windows",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-node",
      "kind": "source",
      "ref": "https://nodejs.org/en/download",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-node-assets",
      "kind": "source",
      "ref": "https://nodejs.org/download/release/latest-v24.x/",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-sevenzip",
      "kind": "source",
      "ref": "https://www.7-zip.org/download.html",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-jadx",
      "kind": "source",
      "ref": "https://github.com/skylot/jadx",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-apktool",
      "kind": "source",
      "ref": "https://apktool.org/docs/install/",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-radare",
      "kind": "source",
      "ref": "https://github.com/radareorg/radare2/blob/master/INSTALL.md",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-radare-user",
      "kind": "source",
      "ref": "https://raw.githubusercontent.com/radareorg/radare2/master/sys/user.sh",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-radare-assets",
      "kind": "source",
      "ref": "https://github.com/radareorg/radare2/releases/expanded_assets/6.2.4",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-radare-brew",
      "kind": "source",
      "ref": "https://formulae.brew.sh/formula/radare2",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-sdk-install",
      "kind": "source",
      "ref": "https://developer.android.com/studio/install",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-sdk-manager",
      "kind": "source",
      "ref": "https://developer.android.com/tools/sdkmanager",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-sdk-env",
      "kind": "source",
      "ref": "https://developer.android.com/tools/variables",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-frida",
      "kind": "source",
      "ref": "https://frida.re/docs/installation/",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-frida-android",
      "kind": "source",
      "ref": "https://frida.re/docs/android/",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-java-adapters",
      "kind": "source",
      "ref": "../src/re_runner/decompile.py",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-r2-provider",
      "kind": "source",
      "ref": "../src/re_runner/providers.py",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-composition",
      "kind": "analysis",
      "ref": "#scope-and-evidence",
      "provenance": "inference",
      "observed_at": null,
      "target_versions": []
    },
    {
      "id": "e-uv-cli",
      "kind": "source",
      "ref": "https://docs.astral.sh/uv/reference/cli/",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-aapt2",
      "kind": "source",
      "ref": "https://developer.android.com/tools/aapt2",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-frida-packaging",
      "kind": "source",
      "ref": "https://raw.githubusercontent.com/frida/frida-tools/main/setup.py",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-sdk-resolver",
      "kind": "source",
      "ref": "../pipeline/init_pipeline.py",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    },
    {
      "id": "e-environment-checker",
      "kind": "source",
      "ref": "../pipeline/env_check.py",
      "provenance": "source",
      "observed_at": "2026-10-29",
      "target_versions": []
    }
  ],
  "claims": [
    {
      "id": "c-bootstrap",
      "statement": "uv documents standalone installers and managed Python installation for supported macOS, Windows and Linux hosts.",
      "confidence": "source-claimed",
      "evidence": [
        "e-uv-install",
        "e-python",
        "e-uv-cli"
      ]
    },
    {
      "id": "c-jdk",
      "statement": "Temurin documents platform installers and OS/architecture-specific archives; archive installation can avoid a host package manager.",
      "confidence": "source-claimed",
      "evidence": [
        "e-jdk",
        "e-jdk-mac",
        "e-jdk-win"
      ]
    },
    {
      "id": "c-node",
      "statement": "Node publishes host-specific installers and release archives.",
      "confidence": "source-claimed",
      "evidence": [
        "e-node",
        "e-node-assets"
      ]
    },
    {
      "id": "c-sevenzip",
      "statement": "7-Zip publishes Windows installers and macOS/Linux console archives for the listed host architectures.",
      "confidence": "source-claimed",
      "evidence": [
        "e-sevenzip"
      ]
    },
    {
      "id": "c-java-tools",
      "statement": "JADX documents a portable distribution requiring Java; APKtool documents direct jar execution without a wrapper.",
      "confidence": "source-claimed",
      "evidence": [
        "e-jadx",
        "e-apktool"
      ]
    },
    {
      "id": "c-radare",
      "statement": "radare2 publishes native release assets and documents a user-directory source installation; Homebrew lists its macOS formula.",
      "confidence": "source-claimed",
      "evidence": [
        "e-radare",
        "e-radare-user",
        "e-radare-assets",
        "e-radare-brew"
      ]
    },
    {
      "id": "c-sdk",
      "statement": "Android documents host-specific Studio setup, SDK environment variables and a deprecated sdkmanager compatibility route.",
      "confidence": "source-claimed",
      "evidence": [
        "e-sdk-install",
        "e-sdk-manager",
        "e-sdk-env",
        "e-aapt2"
      ]
    },
    {
      "id": "c-frida",
      "statement": "Frida documents Python-package installation on the three host families and separate Android server assets; uv documents explicit virtual-environment selection.",
      "confidence": "source-claimed",
      "evidence": [
        "e-frida",
        "e-frida-android",
        "e-uv-env",
        "e-frida-packaging"
      ]
    },
    {
      "id": "c-re-adapters",
      "statement": "The current RE Java adapters accept a JADX distribution directory and an APKtool jar, while the r2 provider requires a trusted native executable.",
      "confidence": "source-claimed",
      "evidence": [
        "e-java-adapters",
        "e-r2-provider"
      ]
    },
    {
      "id": "c-examples",
      "statement": "The installation order, user-owned directory convention, Python 3.12/JDK 17 examples and bounded verification procedure are a proposed integration recipe, not installation results.",
      "confidence": "inference",
      "value_kind": "example",
      "evidence": [
        "e-composition"
      ]
    },
    {
      "id": "c-sdk-resolution",
      "statement": "The current helpers select ANDROID_SDK_ROOT before ANDROID_HOME and then host defaults, prefer adb on PATH, and select the highest numeric installed SDK build-tool version. Some checker installation hints retain a legacy package-manager wording; this matrix owns current installation choices.",
      "confidence": "source-claimed",
      "evidence": [
        "e-sdk-resolver",
        "e-environment-checker"
      ]
    }
  ],
  "review_after": "2026-11-28",
  "decay": {
    "mode": "event",
    "max_age_days": null,
    "triggers": [
      "upstream-installer-or-release-layout-change",
      "host-architecture-or-runtime-requirement-change",
      "sdk-cli-deprecation-change"
    ],
    "note": "Review date is maintenance policy; source review is not host installation or device testing."
  },
  "related_ids": [
    "re.operations.host-compatibility",
    "re.governance.knowledge-engineering"
  ]
}
-->

# Host Installation Matrix

## Scope and Evidence

**Default confidence: inference.** The installation mechanisms identified as
`source-claimed` below were checked against primary documentation on **2026-10-29**.
No package was installed, downloaded for execution, or tested on a host/device for
this article. Version commands establish local availability only after an operator
runs them; they do not establish analysis correctness or device compatibility.

This page owns current **detect → install → resolve path → verify** choices for
macOS, native Windows PowerShell, and Linux. The combined-host table in
[setup](../setup.md) remains a historical example when it differs. Install only
what the chosen lane needs: Python/uv for the unified runner; JDK/JADX/APKtool for
the corresponding optional decompilers; the remaining tools for requested features.
Node is optional and does not become a runner prerequisite merely because an MCP
server might use it. Continue with the existing [runner setup](../setup.md#unified-runner)
after installing the selected host tools.

**Example choices, not measured requirements:** Python **3.12** satisfies this
repository's Python **3.11+** floor; JDK **17** is a shared example for Java tools.
Check the selected release's runtime requirements before installing it. A newer
Android command-line-tools release may require a newer JDK. Use the repository's
locked environment for the runner and a separate optional Frida environment.

## Host and Path Preflight

| Host | Detect before selecting a download | Shell and install location |
|---|---|---|
| macOS | `sw_vers`; `uname -m`; confirm Apple Silicon versus Intel in System Information when running a translated terminal | zsh/Bash; a user-owned tool directory, or the selected vendor installer. Homebrew is an optional macOS route when already available. |
| Windows | Settings → System → About: Windows version and system type; `$PSVersionTable.PSVersion` | Native PowerShell; choose Windows x64/ARM64 assets only when the release actually supplies them. Do not mix Git Bash paths with native commands. |
| Linux | `uname -sm`; read `/etc/os-release`; check the selected binary's libc/runtime requirements | POSIX shell; use a supported official archive or the distribution's documented package. Homebrew is not assumed. |

The following snippets use an **example** user-owned root. Extract each complete
selected distribution into its named subdirectory (preserve `bin/` and `lib/`),
or substitute its actual absolute location. Archive basenames vary by release;
select the artifact from the linked source rather than guessing a download URL.
Verify its published checksum/signature where available before executing it.
A missing architecture/build is `unavailable`, not a reason to install a target
Android binary as a host executable.

```bash
# macOS / Linux: choose once for this terminal
ReTools="$HOME/.local/share/re-host-tools"
mkdir -p "$ReTools"
```

```powershell
# Native Windows: choose once for this terminal
$ReTools = Join-Path $env:LOCALAPPDATA 'RE\host-tools'
New-Item -ItemType Directory -Path $ReTools -Force | Out-Null
```

Commands below change only the current shell's environment unless an installer
explicitly offers persistence. Save the selected absolute paths in the local setup
report. Reopen the shell after an installer changes PATH, then resolve again.
`command -v` or `Get-Command` can reveal a stale executable; test the resolved file,
not merely another copy found earlier on PATH.

## 1. uv Bootstrap

**Source-claimed: c-bootstrap.** uv can bootstrap before Python. Official installers
and release binaries are alternatives; no WinGet package id is required here.
[uv installation](https://docs.astral.sh/uv/getting-started/installation/)

| Host | Detect | Install | Resolve path | Verify |
|---|---|---|---|---|
| macOS | `command -v uv` | Run the POSIX installer below, or use the matching official release binary. | `command -v uv`; if PATH was not refreshed, use the installer's printed location. | `uv --version` |
| Windows | `Get-Command uv -ErrorAction SilentlyContinue` | Run the PowerShell installer below, or unpack an official Windows release binary. | `(Get-Command uv -CommandType Application).Source`; reopen PowerShell if needed. | `uv --version` |
| Linux | `command -v uv` | Same official POSIX installer, selecting a supported Linux build; no Linuxbrew prerequisite. | `command -v uv`; retain the actual installed executable path. | `uv --version` |

```bash
# macOS / Linux: inspect the official script before executing the install step
curl -LsSf https://astral.sh/uv/install.sh -o "$ReTools/uv-install.sh"
less "$ReTools/uv-install.sh"
sh "$ReTools/uv-install.sh"
```

```powershell
# Windows: the documented standalone installer; inspection can be done first
powershell -c "irm https://astral.sh/uv/install.ps1 | more"
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

## 2. Python

**Source-claimed: c-bootstrap.** The shared managed route is `uv python install 3.12`; uv uses Astral's `python-build-standalone` distributions. This is not a claim
that every Python download is a Python.org-built binary. An existing compatible
interpreter may be retained. [uv Python management](https://docs.astral.sh/uv/guides/install-python/)

| Host | Detect | Install | Resolve path | Verify |
|---|---|---|---|---|
| macOS | `python3 --version`; `uv python list --only-installed` | `uv python install 3.12` if no suitable interpreter exists. | `RePython="$(uv python find 3.12)"`; optionally `export RE_PYTHON="$RePython"` for pipeline helpers. | `"$RePython" -c 'import sys; print(sys.executable); print(sys.version); assert sys.version_info >= (3,11)'` |
| Windows | `Get-Command python,py -ErrorAction SilentlyContinue`; `uv python list --only-installed` | `uv python install 3.12`; do not treat a Windows Store alias as an installed interpreter. | `$RePython = (uv python find 3.12).Trim()`; optionally `$env:RE_PYTHON=$RePython`. | `& $RePython -c 'import sys; print(sys.executable); print(sys.version); assert sys.version_info >= (3,11)'` |
| Linux | `python3 --version`; `uv python list --only-installed` | `uv python install 3.12`, or retain a compatible distro Python without replacing system Python. | `RePython="$(uv python find 3.12)"`; optionally `export RE_PYTHON="$RePython"`. | Same exact-interpreter command as macOS. |

Use [`uv python find`](https://docs.astral.sh/uv/reference/cli/#uv-python-find) to avoid
depending on an unversioned `python` alias. A missing
managed build is an explicit installation limitation; consult the chosen OS's
Python distribution rather than assuming every Linux architecture has one.

## 3. JDK

**Source-claimed: c-jdk.** Choose a **JDK**, OS and host architecture in the
[Temurin release selector](https://adoptium.net/temurin/releases/).
[Archive instructions](https://adoptium.net/installation/archives),
[macOS PKG](https://adoptium.net/installation/macOS), and
[Windows MSI](https://adoptium.net/installation/windows) describe these routes.

| Host | Detect | Install | Resolve path | Verify |
|---|---|---|---|---|
| macOS | `command -v java`; `/usr/libexec/java_home -V` | Open the selected macOS PKG, or extract its matching archive. | For registered JDK 17: `export JAVA_HOME="$(/usr/libexec/java_home -v 17)"`; archive users set the actual `Contents/Home` directory. Prepend `$JAVA_HOME/bin` to PATH. | `"$JAVA_HOME/bin/java" -version`; `"$JAVA_HOME/bin/javac" -version` |
| Windows | `Get-Command java,javac -ErrorAction SilentlyContinue` | Use the official x64 MSI where supported; otherwise choose a matching supported Windows ZIP. | Set `$env:JAVA_HOME` to the actual JDK root containing `bin\java.exe`; prepend `"$env:JAVA_HOME\bin;"` to `$env:Path`. | `& "$env:JAVA_HOME\bin\java.exe" -version`; likewise `javac.exe -version`. |
| Linux | `command -v java`; `command -v javac` | Extract the matching Temurin Linux archive; official distro package instructions are an alternative for supported distributions. | `export JAVA_HOME="$ReTools/jdk"` after placing the extracted JDK root there; prepend `$JAVA_HOME/bin` to PATH. | `"$JAVA_HOME/bin/java" -version`; `"$JAVA_HOME/bin/javac" -version` |

For example, use `export PATH="$JAVA_HOME/bin:$PATH"` on POSIX or
`$env:Path="$env:JAVA_HOME\bin;$env:Path"` in PowerShell. Confirm bare `java -version`
now selects that JDK for the manual examples. **Source-claimed: c-re-adapters.**
The RE Java adapters first use an existing `JAVA_HOME/bin/java` (`java.exe` on
Windows), then fall back to Java on PATH. Bare `java` can therefore select a
different runtime: verify the precise `JAVA_HOME` executable shown in the table,
and keep PATH aligned when using other launchers. Studio's bundled runtime and
the shell's JDK can differ; an installed IDE alone does not settle this.

## 4. Node.js — Optional

**Source-claimed: c-node.** Choose a release satisfying the selected MCP/server's
requirements using [Node downloads](https://nodejs.org/en/download). The official
[release archive](https://nodejs.org/download/release/) provides installers,
OS/architecture archives and signed SHASUMS; no third-party version manager is
required. The [reviewed release listing](https://nodejs.org/download/release/latest-v24.x/)
shows example artifact families, not a permanent version pin.

| Host | Detect | Install | Resolve path | Verify |
|---|---|---|---|---|
| macOS | `command -v node`; `command -v npm` | Official macOS PKG, or extract the selected Darwin archive. | `command -v node`; archive users add the extracted `bin/` to PATH. | `node --version`; `npm --version` |
| Windows | `Get-Command node,npm -ErrorAction SilentlyContinue` | Official matching MSI, or extract the matching Windows ZIP. | `(Get-Command node -CommandType Application).Source`; add the archive root containing `node.exe` to `$env:Path` if needed. | `node --version`; `npm.cmd --version` (avoids relying on an unsigned `npm.ps1` execution policy). |
| Linux | `command -v node`; `command -v npm` | Extract the supported Linux archive for the host architecture/libc; use official build requirements if no matching artifact exists. | Add the extracted `bin/` to PATH; `command -v node`. | `node --version`; `npm --version` |

## 5. 7-Zip

**Source-claimed: c-sevenzip.** Use [official downloads](https://www.7-zip.org/download.html):
Windows installer, macOS console archive, or matching Linux console archive. A
Windows `.exe` and Android executable are not Linux/macOS host substitutes.

| Host | Detect | Install | Resolve path | Verify |
|---|---|---|---|---|
| macOS | `command -v 7zz`; `command -v 7z` | Extract the official macOS console `.tar.xz` to `$ReTools/7zip`. | Set `export RE_RUN_7Z="$ReTools/7zip/7zz"` to the actual console binary. | `"$RE_RUN_7Z" i` |
| Windows | `Get-Command 7z,7zz -ErrorAction SilentlyContinue` | Run the official Windows installer matching the host architecture. | Set `$env:RE_RUN_7Z` to the actual `7z.exe`; `C:\Program Files\7-Zip\7z.exe` is a candidate, not an assumed install result. | `& $env:RE_RUN_7Z i` |
| Linux | `command -v 7zz`; `command -v 7z` | Extract the official matching Linux console `.tar.xz` to `$ReTools/7zip`. | Set `export RE_RUN_7Z="$ReTools/7zip/7zz"` to the actual executable. | `"$RE_RUN_7Z" i` |

The `i` command reports version/format handlers. Record the exact selected binary;
an arbitrary distro `7z`/`p7zip` package does not imply identical format support.

## 6. JADX

**Source-claimed: c-java-tools.** Download the portable `jadx-<version>.zip` from
[JADX releases](https://github.com/skylot/jadx/releases) and preserve its `lib/`
directory. The [upstream README](https://github.com/skylot/jadx) documents Java
**11+**, 64-bit, for this distribution; source builds have separate JDK requirements.
The complete distribution directory works with the current RE Java adapter.

| Host | Detect | Install | Resolve path | Verify |
|---|---|---|---|---|
| macOS | `command -v jadx`; inspect the configured distribution's `lib/`. | Extract the portable ZIP to `$ReTools/jadx`. | `export RE_RUN_JADX="$ReTools/jadx"` for the extracted distribution. | `"$JAVA_HOME/bin/java" -cp "$RE_RUN_JADX/lib/*" jadx.cli.JadxCLI --version` |
| Windows | `Get-Command jadx -ErrorAction SilentlyContinue`; inspect the selected distribution. | Extract the portable ZIP to `$ReTools\jadx`, including `lib/`; GUI-only/with-JRE bundles are different choices. | `$env:RE_RUN_JADX=Join-Path $ReTools 'jadx'`. | `& "$env:JAVA_HOME\bin\java.exe" -cp "$env:RE_RUN_JADX\lib\*" jadx.cli.JadxCLI --version` |
| Linux | `command -v jadx`; inspect the distribution's `lib/`. | Extract the portable ZIP to `$ReTools/jadx`; upstream's Arch package is a distro-specific alternative, not a universal Linux command. | `export RE_RUN_JADX="$ReTools/jadx"`. | Same native-Java command as macOS. |

**Source-claimed: c-re-adapters.** The runner uses the directory's classpath directly;
setting `RE_RUN_JADX` to an arbitrary jar/ZIP is unsupported. A native version probe
does not prove successful decompilation of a particular sample.

## 7. APKtool

**Source-claimed: c-java-tools.** Obtain the selected jar through the official
[APKtool install guide](https://apktool.org/docs/install/) download link. The jar can
run directly without a shell/batch wrapper. Keep the selected version in the local
setup record; the existence of a newer major release is not compatibility evidence
for old workflows.

| Host | Detect | Install | Resolve path | Verify |
|---|---|---|---|---|
| macOS | `command -v apktool`; check any configured jar. | Save the selected jar as `$ReTools/apktool/apktool.jar`. | `export RE_RUN_APKTOOL="$ReTools/apktool/apktool.jar"` for the manual route. | `"$JAVA_HOME/bin/java" -jar "$RE_RUN_APKTOOL" --version` |
| Windows | `Get-Command apktool -ErrorAction SilentlyContinue`; check the jar. | Save the jar under `$ReTools\apktool\apktool.jar`; no write to `C:\Windows` is needed. | `$env:RE_RUN_APKTOOL=Join-Path $ReTools 'apktool\apktool.jar'`. | `& "$env:JAVA_HOME\bin\java.exe" -jar "$env:RE_RUN_APKTOOL" --version` |
| Linux | `command -v apktool`; check any configured jar. | Save the jar as `$ReTools/apktool/apktool.jar`; direct Java avoids requiring a root-owned wrapper installation. | `export RE_RUN_APKTOOL="$ReTools/apktool/apktool.jar"`. | `"$JAVA_HOME/bin/java" -jar "$RE_RUN_APKTOOL" --version` |

**Source-claimed: c-re-adapters.** Pointing the runner at the jar selects its native
Java path. Generic timeout-helper execution of Windows `.bat`/`.cmd` remains refused
with code 126; it is not made safe by setting PATH. See the
[launcher boundaries](compatibility.md#native-entry-points-and-remaining-boundaries).

## 8. radare2

**Source-claimed: c-radare.** Use the selected version's actual
[official release assets](https://github.com/radareorg/radare2/releases).
The [reviewed 6.2.4 asset listing](https://github.com/radareorg/radare2/releases/expanded_assets/6.2.4)
contains macOS PKGs, Windows ZIPs and Debian packages. This does not promise those
formats for every future release. [Upstream installation](https://github.com/radareorg/radare2/blob/master/INSTALL.md)
also documents a user-directory source build.

| Host | Detect | Install | Resolve path | Verify |
|---|---|---|---|---|
| macOS | `command -v r2`; `command -v radare2` | Open the matching official macOS PKG; alternatively `brew install radare2` when Homebrew is available, as listed by [Homebrew](https://formulae.brew.sh/formula/radare2). | `export RE_RUN_R2="$(command -v r2)"`; use the actual native executable. | `"$RE_RUN_R2" -v` |
| Windows | `Get-Command r2,radare2 -ErrorAction SilentlyContinue` | Extract the matching official Windows ZIP, preserving its runtime files. | Set `$env:RE_RUN_R2` to the extracted native `r2.exe` or `radare2.exe`, according to that release's contents. | `& $env:RE_RUN_R2 -v` |
| Linux | `command -v r2`; check distro and architecture. | For a compatible Debian-family host, install the selected non-`dev` `.deb` through its package installer. Otherwise use the bounded source-build route below with the host's build prerequisites. | `export RE_RUN_R2="$(command -v r2)"`; source example: `$HOME/.local/bin/r2`. | `"$RE_RUN_R2" -v` |

For a Linux source build, download/extract the chosen official release source,
install its documented C compiler/GNU Make prerequisites using that distribution's
package manager, and run `./sys/user.sh --without-pull` from the extracted root.
The [upstream script](https://raw.githubusercontent.com/radareorg/radare2/master/sys/user.sh)
places this user install in `$HOME/.local` by default. Inspect the script in the
chosen release for these options before running it; a source build is not an
already available binary fallback. Add `$HOME/.local/bin` to PATH, then resolve and
verify. A failed build stays `unavailable` with its diagnostic. The RE provider
accepts a trusted native r2 executable, not a `.bat`, `.sh` or `.ps1` wrapper.

## 9. Android SDK

**Source-claimed: c-sdk.** The [Studio installation guide](https://developer.android.com/studio/install)
provides each host's install procedure. Use its SDK Manager to install
**Platform-Tools** (`adb`) and a selected **Build-Tools** release
([AAPT2](https://developer.android.com/tools/aapt2)). IDE,
emulator/system images, NDK and physical-device drivers are separate optional
requirements; do not install an AVD merely to inspect an APK statically.

| Host | Detect | Install | Resolve path | Verify without a device |
|---|---|---|---|---|
| macOS | Check Studio's SDK Location and `ANDROID_HOME`; `command -v adb`. | Official matching Studio DMG → Setup Wizard → SDK Manager, or the command-line-tools route below. | Use the actual SDK Location; `$HOME/Library/Android/sdk` is only a candidate. Set `ANDROID_HOME`; retain `platform-tools/adb` and the selected `build-tools/<version>/aapt2` paths. | Run the selected `adb version`; read both packages' `source.properties`; run selected `aapt2 version`. |
| Windows | Check Studio's SDK Location and `$env:ANDROID_HOME`; `Get-Command adb -ErrorAction SilentlyContinue`. | Official supported Windows Studio installer → SDK Manager, or the matching command-line-tools route. Current Studio documentation excludes Windows ARM hosts. | Use the actual SDK Location; `$env:LOCALAPPDATA\Android\Sdk` is a candidate. Resolve `platform-tools\adb.exe` and `build-tools\<version>\aapt2.exe`. | Run those exact `.exe` files with `version`; read their package `source.properties`. |
| Linux | Check Studio's SDK Location, `ANDROID_HOME`, distro/runtime and `command -v adb`. | Official supported Studio `.tar.gz` → `android-studio/bin/studio` → SDK Manager, or supported command-line tools. Current Studio documentation excludes Linux ARM hosts. | Use actual SDK Location; `$HOME/Android/Sdk` is a candidate. Resolve `platform-tools/adb` and selected `build-tools/<version>/aapt2`. | Run selected `adb version` and `aapt2 version`; inspect package `source.properties`. |

[Android's environment reference](https://developer.android.com/tools/variables)
defines `ANDROID_HOME` as the SDK root and deprecates `ANDROID_SDK_ROOT`. If an older
workflow still sets both, make them identical. Do not set `ANDROID_SDK_HOME` to mean
SDK binaries; it has a different legacy user-preferences role. Add `platform-tools`
and, if needed, the **selected** `build-tools/<version>` directory to PATH; do not
merge tool directories from several SDK installations. This repository also reads
the legacy root variable, so a stale value can select the wrong tree.

### Command-Line-Tools Compatibility Route

The current [sdkmanager page](https://developer.android.com/tools/sdkmanager)
labels it deprecated in favor of Android CLI, while retaining this installation
interface. New Android CLI is an upstream alternative; this page does not claim
that this repository has integrated or tested it. For the documented compatibility
route, download the command-line-tools archive for the **host OS**, then arrange its
contents as `<SDK>/cmdline-tools/latest/{bin,lib,source.properties,...}` (avoid an
extra nested `cmdline-tools` directory). Select a JDK required by that release.

```bash
# macOS / Linux: set ANDROID_HOME to your actual SDK root first
ReSdkManager="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
"$ReSdkManager" --sdk_root="$ANDROID_HOME" --list
# Enter a build-tools version actually listed above; this is an operator choice
read -r ReBuildTools
"$ReSdkManager" --sdk_root="$ANDROID_HOME" "platform-tools" "build-tools;$ReBuildTools"
"$ReSdkManager" --sdk_root="$ANDROID_HOME" --licenses
"$ANDROID_HOME/platform-tools/adb" version
"$ANDROID_HOME/build-tools/$ReBuildTools/aapt2" version
```

```powershell
# Windows: set $env:ANDROID_HOME to your actual SDK root first
$ReSdkManager = Join-Path $env:ANDROID_HOME 'cmdline-tools\latest\bin\sdkmanager.bat'
& $ReSdkManager "--sdk_root=$env:ANDROID_HOME" --list
$ReBuildTools = Read-Host 'Build-tools version from the list'
& $ReSdkManager "--sdk_root=$env:ANDROID_HOME" 'platform-tools' "build-tools;$ReBuildTools"
& $ReSdkManager "--sdk_root=$env:ANDROID_HOME" --licenses
& (Join-Path $env:ANDROID_HOME 'platform-tools\adb.exe') version
& (Join-Path $env:ANDROID_HOME "build-tools\$ReBuildTools\aapt2.exe") version
```

Review and accept the required SDK licenses interactively. The Windows snippet
invokes a trusted SDK batch installer directly from PowerShell; it is **not** a
`run_to` recipe. Use an SDK path without shell metacharacters and prefer Studio's
SDK Manager if the launcher cannot handle the selected path. Selecting an SDK
package does not establish that its host binary supports every CPU or Linux libc.

## 10. Frida in a Separate Virtual Environment

**Source-claimed: c-frida.** [Frida installation](https://frida.re/docs/installation/)
documents the `frida-tools` Python package;
[uv documents explicit environment selection](https://docs.astral.sh/uv/pip/environments/).
**Integration inference: c-examples.** The recipe below composes those interfaces.
Start at the repository root; keep `tools-env/.venv` separate from the locked runner
`.venv`. Do not copy a virtual environment between hosts.

| Host | Detect | Install | Resolve path | Verify without attach/deployment |
|---|---|---|---|---|
| macOS | Check `tools-env/.venv/bin/python` and `frida`; do not rely on a global CLI. | Use the POSIX recipe below. | `tools-env/.venv/bin/python` and `tools-env/.venv/bin/frida`, resolved from the repository root. | Import the module and print its version; run that venv's `frida --version`. |
| Windows | `Test-Path tools-env\.venv\Scripts\python.exe`; inspect the same venv's CLI. | Use the PowerShell recipe below. | `tools-env\.venv\Scripts\python.exe` and `frida.exe`; no activation script is required. | Same import/version checks using the exact `.exe` paths. |
| Linux | Check `tools-env/.venv/bin/python` and `frida`. | Same POSIX venv recipe, subject to available host wheels/build prerequisites. | `tools-env/.venv/bin/python` and `tools-env/.venv/bin/frida`. | Same exact-venv checks as macOS. |

```bash
# macOS / Linux; Python 3.12 is an example, adjust to package compatibility
uv venv --python 3.12 tools-env/.venv
uv pip install --python tools-env/.venv/bin/python frida-tools frida
tools-env/.venv/bin/python -c 'import frida,sys; print(sys.executable); print(frida.__version__)'
tools-env/.venv/bin/frida --version
```

```powershell
# Native Windows
uv venv --python 3.12 tools-env\.venv
uv pip install --python tools-env\.venv\Scripts\python.exe frida-tools frida
& tools-env\.venv\Scripts\python.exe -c 'import frida,sys; print(sys.executable); print(frida.__version__)'
& tools-env\.venv\Scripts\frida.exe --version
```

Record both the `frida` core version and `frida-tools` distribution version
(`uv pip show --python <venv-python> frida frida-tools`). These are separate fields in the
[Frida tools packaging](https://raw.githubusercontent.com/frida/frida-tools/main/setup.py);
do not infer a server version from the tools package version. A later Android
server choice follows the **core** version and
the target ABI, not the host CPU or the tools package's version. Consult the
[Frida Android guide](https://frida.re/docs/android/) and selected release notes
when planning deployment; this page performs no device query, server push, root,
attach, injection or system-policy change.

## Keep Installation Separate from Target Behavior

Host architecture selects Python/JDK/native tool artifacts; Android target ABI
selects a later device/server/system-image artifact. `ANDROID_HOME` locates SDK
files; it does not select either architecture. A macOS ARM64 host can inspect an
APK containing several target ABIs without installing an emulator for each one.

Before transferring a command to another shell or acquiring target bytes, read the
[compatibility field cases](compatibility.md#field-pitfalls-host-and-target-behavior-are-not-interchangeable)
and its [native-entry boundaries](compatibility.md#native-entry-points-and-remaining-boundaries).
Those pages own MSYS path conversion, adb PTY/binary channels, target toybox `dd`
options and mksh arithmetic observations; this matrix does not duplicate them or
promote the attributed, version-unknown reports to device verification.

For a local setup record, capture host OS/architecture, selected release/assets,
resolved absolute executable paths, version output, and per-item status
`available`, `unavailable`, or `not-needed`, including failed diagnostics. Keep
installation/version checks distinct from an optional owned-sample smoke test.
No current-host or Windows/Linux real-machine success is asserted by this article.

## Repository SDK Resolution

**Source-claimed: c-sdk-resolution.** The shared
[SDK resolver](../pipeline/init_pipeline.py) tries `ANDROID_SDK_ROOT`, then
`ANDROID_HOME`, then its host default. Both the initializer and
[environment checker](../pipeline/env_check.py) prefer an `adb` already on PATH
over the selected SDK fallback. SDK Build-Tools auto-discovery chooses the highest
installed numeric version. Inspect the actual paths in `env.json` and the checker
report; manually verifying another executable does not change this selection.
Set legacy/new SDK variables consistently and resolve stale PATH entries before
interpreting a tool failure as target behavior.

Some checker failure hints still use earlier brew/winget wording. Treat those as
legacy diagnostic text, not a Linux installation command or a replacement for
this platform-specific matrix. Changing those hints is a separate implementation
cleanup; no tool installation or fresh capability certification occurred here.
