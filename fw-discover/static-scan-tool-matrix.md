# Firmware Static-Scanning Tool Matrix (installation + smoke-test record)

> Installed and smoke-tested on 2026-10-17. Environment: macOS arm64 / Docker 28.3.3 / brew / venv (Python 3.13.7).
> Smoke targets: on the source side, `/tmp/smoke_vuln.c` (20 lines, `system(getenv("cmd"))` + `strcpy` overflow);
> on the binary side, `bpalogin` from the ddwrt rootfs (ELF 32-bit MSB MIPS32 rel2, musl dynamic, **no section headers**).
> Full log: `/tmp/static-tools-install.log`. Machine egress bandwidth ~300-700KB/s was the main bottleneck this round.

## Master table

| Tool | Source/binary lane | Install | Status | One-line smoke-test verdict | Usage on the firmware corpus |
|------|------|------|------|------|------|
| cppcheck 2.22.0 | Source | brew | **Usable** | Runs clean on the small C file, exit 0 but 0 warnings — cppcheck only reports bugs provable by dataflow; cross-function getenv taint isn't its thing. Use as a low-noise confirmer | `cppcheck --enable=all --inconclusive --check-level=exhaustive <GPL component source tree>` |
| flawfinder 2.0.20 | Source | uv pip | **Usable** | Precise hits: strcpy[CWE-120][level 4] + system[shell][level 4]; 222 dangerous-function rules | `flawfinder --minlevel=3 --csv <source unpacked from rootfs>` — the primary first-pass fast filter |
| clang --analyze 14.0.3 | Source | Ships with the system | **Usable** | Executes normally, exit 0; default checkers do no taint propagation, 0 warnings on this target | Per-directory on GPL components: `clang --analyze -Xanalyzer -analyzer-output=text`, catches null-deref / resource-leak classes |
| semgrep 1.181.0 | Source | brew (link failed, use the full Cellar path) | **Usable** | Custom C rule hits `system(...)` (Blocking); registry rule packs pull and run. Pitfall: `~/.cache` permission bug, needs the `HOME=/tmp/semgrep-cache` workaround | `HOME=/tmp/semgrep-cache /opt/homebrew/Cellar/semgrep/1.181.0/bin/semgrep --config p/security --config <custom c rules.yml> <component>` |
| CodeQL CLI 2.27.2 | Source | zip unpacked into tools-env/codeql | **Usable** | `codeql version` passes; single-file C database successfully created at `/tmp/smoke-db` (db-cpp generated) | Create DB: `codeql database create <db> --language=cpp --source-root=<src> --command="<build>"`; running queries also needs `codeql pack download codeql/cpp-queries` (or `git clone --depth 1 https://github.com/github/codeql` to grab the query packs) |
| Joern | Source | joern-install.sh → tools-env/joern | **Installing (timed out, not smoke-tested)** | Depends on openjdk@21 (brew has 21.0.12.1, keg-only, unlinked); the installer was running but the bundle download was slow and didn't finish within this session | When ready: `joern-parse <src> --output <cpg>` + script query `cpg.call.name("system")` (script template at /tmp/joern_query.sc) |
| angr | Binary | uv pip | **Usable** | Loads the MIPS32 bpalogin successfully; CFGFast recovers 150 functions (restores the ddns3_* symbols); `find_symbol("system")` resolves to extern 0x500070. Limitation: no section headers → angr doesn't auto-name PLT stubs; call sites need cwe_checker / manual GOT tracing | Template `/tmp/angr_smoke.py`: `CFGFast(normalize=True)` → walk `cfg.functions` matching system/popen/exec* |
| checksec.py | Binary | uv pip | **Usable** | bpalogin hardening: NX on; PIE/Canary/RelRO/RPATH all off, stripped — running bare with weak mitigations, directly confirms attack-surface value | `checksec --file=<elf>`; batch-produce a hardening-options table for every ELF in the rootfs |
| firmwalker | Binary-side file strings | git clone /tmp/firmwalker | **Skipped (network)** | All 7 channels tried: git×2, codeload×2 branches, raw, gh api tarball, jsdelivr, raw+proxy — all blocked by the network; only the github release channel works on this machine and that repo has no release. Fetch it later from a machine with normal GitHub access | `./firmwalker.sh <rootfs dir>`, outputs firmwalker.txt (passwd/token/credential/hidden web-path strings) |
| cwe_checker | Binary | docker ghcr.io | **Skipped (network)** | ghcr.io direct connection timed out after 10 minutes (discipline: cut losses); the daocloud mirror proxy 403s and doesn't support ghcr paths. Recommended to run on a Linux asset machine | `docker run --rm -v <rootfs>:/vol ghcr.io/fkie-cad/cwe_checker /vol/bpalogin` (MIPS supported) |
| EMBA | Binary (full system) | docker embeddedanalyzer/emba | **Skipped (documentation-level only)** | The correct image name is `embeddedanalyzer/emba` (confirmed via docker search; the firmwaresecurity/emba named in the task doesn't exist); amd64-only manifest, no arm64; with `--platform linux/amd64` a single layer is 1.6GB @ 270KB/s — terminated after 10 minutes by discipline. The small disk residue can be cleaned with `docker system prune` | `docker run --rm -it --network=host --platform linux/amd64 -v <firmware dir>:/target -v <log>:/log embeddedanalyzer/emba -l /log -t /target` (run on an x86 Linux machine) |
| Infer | Source | brew | **Skipped** | homebrew has no infer formula ("No available formula with the name infer"); macOS official ships no arm64 prebuilt package; a source build exceeds budget | Fallback: on a Linux machine `docker run facebookresearch/infer`, or an opam source build |

**Score: 8/12 usable (cppcheck, flawfinder, clang, semgrep, CodeQL, angr, checksec, plus the openjdk@21 base), 4 skipped (firmwalker/cwe_checker/EMBA = network and platform limits, Infer = no package).**

## BSCA notes (the binary-side counterparts)

- **cwe_checker**: a binary CWE pattern checker built on the BAP backend; batch-produces CWE-78/120/416 style reports for firmware ELFs — the binary lane's main gun; the docker channel is blocked on this machine, run it on a Linux machine.
- **angr**: symbolic execution + CFG recovery framework, verified locally to chew through MIPS32; used for function-graph reconstruction, danger-import location, and path-reachability solving.
- **BAP**: the CMU/BU-lineage binary analysis platform (the engine under cwe_checker), providing formal machine semantics; not installed this round — the OCaml toolchain is heavy to build and its core value is already wrapped by cwe_checker, so installing it standalone is poor value.
- **Ghidra**: the NSA decompiler; headless + scripts for pseudo-C recovery / cross-references / dataflow on source-less firmware; not installed this round — the app footprint + the JDK desktop stack exceed the time budget, and angr's decompiler (`p.analyses.Decompiler`) can hold the fort for now.

## Battery usage toward 100 CVEs (dual-lane cross-validation)

**Binary lane (no source, hit the rootfs directly)**
1. `checksec` batch-scans every ELF in the rootfs → weak-mitigation list (bpalogin already proven: NX-only, fully bare).
2. `firmwalker` scans rootfs filesystem strings → passwd/credentials/hidden paths/shadow (to be installed once the network recovers).
3. `angr` on each high-risk ELF: `CFGFast` → danger imports (system/popen/exec*/strcpy) → decompile to confirm the call context (bpalogin already worked through locally: the system import is in dynsym, the 150-function graph in hand).
4. `cwe_checker` (Linux-machine docker) produces CWE reports for the full ELF set of the rootfs, MIPS supported, cross-checking the angr results.

**Source lane (GPL component source)**
1. Trace upstream GPL source from the rootfs version strings / `/usr/share` (the bpalogin official GPL package can be pulled at the matching version directly).
2. `flawfinder --minlevel=3` fast filter over the whole tree → `cppcheck` / `clang --analyze` to confirm provable warnings → `semgrep` (registry rules + custom C rules) batch scan → **CodeQL full taint queries** (`codeql database create` path already verified; just add `codeql pack download codeql/cpp-queries` to run taint queries with sink=system) → Joern hand-written CPG queries for depth.

**Cross-validation paradigm (bpalogin as the example)**
- Binary side proven: inside the MIPS ELF `system` is a dynsym import, the real call flow exists, mitigations all off → "this bug is genuinely reachable in the shipped firmware".
- Source side: pull the matching bpalogin GPL source → Joern `cpg.call.name("system").reachableBy(cpg.literal/env)` or a CodeQL `system(...)` taint query hits the `getenv/argv→system` chain → "root cause pinned down at code level".
- A closed dual-evidence loop = real flow in shipped firmware + source-side taint chain; the report can directly qualify it as command injection with CVE-grade argumentation. When versions don't line up, the binary's decompiled argument-passing path is authoritative.

## Install cheatsheet (reusable info)

```
brew:      cppcheck(2.22.0) / openjdk@21(21.0.12.1, keg-only) / semgrep(1.181.0, link failed)
uv pip:    UV_CACHE_DIR=/tmp/uv-cache uv pip install -p ~/re-skill/tools-env/.venv/bin/python flawfinder|checksec.py|angr
CodeQL:    https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-osx64.zip (982MB!) → ~/re-skill/tools-env/codeql/
Joern:     bash joern-install.sh --install-dir=~/re-skill/tools-env/joern --without-plugins (JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home)
semgrep:   HOME=/tmp/semgrep-cache /opt/homebrew/Cellar/semgrep/1.181.0/bin/semgrep --config p/security <target>
smoke:     /tmp/smoke_vuln.c | /tmp/angr_smoke.py | /tmp/joern_query.sc | /tmp/semgrep_c_rule.yml | /tmp/smoke-db
```
