# pipeline branch: agent-executed APK analysis workflow

> Select this S0–S4 DAG for an explicit APK full-chain/dynamic task. For APK static information
> and a complete static report, start with [the Android runner](../docs/runner.md) or the requested
> static stages; do not start an emulator merely because the user asks for a report. Resolve a
> bare URL as a Web asset versus an APK locator before entering this APK workflow.


> Input an APK path and an authorized analysis scope. An agent executes the five
> stages using available tools and writes a report. This is the deeper workflow:
> `re-run analyze --type android` provides bounded static APK/AAB analysis, not
> the complete S0–S4 dynamic chain. See the [runner matrix](../docs/runner.md)
> and [execution handoff](../docs/agent-completion-prompt.md).
> Persist artifacts and close each stage as PASS or documented DEGRADED before
> the next stage; failed gates never become success. Apply the fallback and
> preserve missing evidence. Scope, cancellation, and host permission limits
> remain controlling conditions, not tool failures to bypass.
> Executor: the main agent orchestrates. When the user or applicable instructions
> authorize delegation, dispatch independent S1 work together: A-1/A-2, B-1/B-2,
> and C-1/C-3. After the join, the main agent runs B-3/C-2/C-4 because they consume
> A artifacts; S2–S4 follow in order. Otherwise run that same dependency graph
> locally. Workers never write one another's files.
> Command baseline: identical across the three platforms (macOS/Linux/Windows) — jadx/apktool/adb etc. are always invoked by their PATH command names; installation and per-platform paths are in `../setup.md` §1–§2, the venv in §3; the check runs `pipeline/env_check.py` (cross-platform; the older `env_check.sh` is macOS-only).
> Command interpreter: bash syntax (native on macOS/Linux; Windows goes through Git-Bash/WSL).

## Full-chain DAG overview (at a glance)

```
Input: <absolute APK path> ──[ missing file = stop; execution limits still apply ]
  │
  ▼
S0 environment check (≤2min, serial)          python3 env_check.py → env_report.txt / status.md / 黑板.md
  │
  ▼
S1 information gathering (≤35min, independent A/B/C work in parallel, then join) ─┬─ A: apktool d + jadx -d (dual engines, mutual backup)
  │                                  ├─ B: APKiD → signature-so match → packer_verdict.md
  │                                  └─ C: badging + apkleaks; join → packer verdict / manifest_face / secrets_grep
  │
  ▼
S2 static analysis (≤15min, serial)          entry/so list → unpacking advice (cites technique-library articles) → urls/ips
  │                                  → so JNI symbols → hook candidates (six domains) → blackboard merge
  │
  ▼
S3 dynamic analysis (≤10min, android-emulator MCP)
  │                                  preflight/start emulator → install → launch → screenshots + UI tree
  │                                  → logcat filter → frida-server probe → light UI walkthrough
  │
  ▼
S4 report (≤5min, purely local, must-deliver)          03-report.md seven-section template + wrap-up checklist
  │
  ▼
Output: 输出/<package>-<date>/03-report.md + the "skipped items and reasons" list returned to the user
```

Every tool/capability degradation feeds into section 7 of S4. Honor scope, cancellation, and permission limits; preserve the available evidence and handover state rather than continuing prohibited work.

## MCP tool mapping (for S3; calls other than Bash)

| pipeline step | MCP tool and key parameters | bash-side equivalent degradation |
|---|---|---|
| S3-1 readiness / start emulator | `android_preflight` / `android_list_avds` / `android_list_devices`; verify the intended isolated test emulator, then start only its selected RE_AVD if needed (`timeoutMs=180000`) | only with a resolved isolated test AVD: `"$ADB_BIN" start-server` + background `"$SDK_DIR/emulator/emulator" -avd "$RE_AVD"`, then verify serial/AVD identity (Windows: `emulator.exe`); no suitable AVD → DEGRADED, never use a connected phone |
| S3-2 install | `android_install_app(apkPath, timeoutMs=180000)` (note: apkPath does not allow paths outside the project root, e.g. /tmp → raises `Path escapes project root`; go straight to the right-hand degradation) | `"$ADB_BIN" -s "$RE_DEVICE_SERIAL" install -r -t "$APK"` |
| S3-3 launch | `android_launch_app(applicationId="$PKG", timeoutMs=60000)` | `"$ADB_BIN" -s "$RE_DEVICE_SERIAL" shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1` |
| S3-4 screenshots / UI tree | `android_screenshot` (same restriction: path confined to the project root; called without a path it returns MCP image content for the agent to view directly — persist artifacts with the right-hand command) / `android_ui_describe` | `"$ADB_BIN" -s "$RE_DEVICE_SERIAL" exec-out screencap -p > x.png` / `"$ADB_BIN" -s "$RE_DEVICE_SERIAL" shell uiautomator dump` |
| S3-5 logcat | `android_logs(applicationId, lines=500)` | `"$ADB_BIN" -s "$RE_DEVICE_SERIAL" logcat -d -t 500` |
| S3-7 tap | `android_ui_tap(x, y)` | `"$ADB_BIN" -s "$RE_DEVICE_SERIAL" shell input tap x y` |
| optional enhancements | `node_repl` (JS deobfuscation), `WebSearch/WebFetch` (packer intelligence), `ida-pro-mcp` (only after check_connection passes), `fofa` (skipped without a key) | — |

## 0. Global conventions (common to every stage)

### 0.1 Safe Shared-State Initialization (Bash / Git-Bash / WSL)

Use the installed skill's actual absolute path. The checked-in initializer derives the root from `BASH_SOURCE`, verifies the APK, resolves SDK/venv paths, and persists state using Bash `%q`; do not derive the skill root from an interactive shell's `$0`.

```bash
source /absolute/skill-root/pipeline/init_pipeline.sh "/absolute/path/to/app.apk"
# Check the return status immediately. A missing input returns 2 before output creation.
# If initialization failed, fix that concrete local input/environment problem before running any stage.
```

`APK`, `SKILL_ROOT`, `AAPT2`, `SDK_DIR`, `ADB_BIN`, `VENV_BIN`, `VENV_PY`, `PKG`, `OUT`, `RE_AVD`, `RE_DEVICE_SERIAL`, and the budget deadline are saved in `$OUT/env.sh`. Every subsequent Bash session starts with `source "/absolute/artifact-root/env.sh"`; the file also restores `run_to`. Quote all path arguments. SDK discovery honors `ANDROID_SDK_ROOT` / `ANDROID_HOME`, then uses the platform default; aapt2 falls back to PATH and package naming falls back to the sanitized APK filename.

Default artifacts remain next to the APK at `输出/<package>-<date>/`. Set `RE_PIPELINE_OUT` before sourcing to choose another base. If that directory already contains artifacts, a timestamp/PID suffix creates a distinct run instead of overwriting evidence. Existing non-ASCII artifact names remain compatibility interfaces; all new explanatory prose is English.

`run_to <seconds> <command> [args...]` uses `run_with_timeout.py`, returns 124 on timeout/budget exhaustion, and terminates only the process tree it created. It bounds a command by both the requested timeout and the remaining global budget, reserving 300s for S4. Set `RE_REPORT_RESERVE_SECONDS=0` only when entering S4; no new analysis starts inside the report reserve.

### 0.2 Discipline parameters

- **Timeout discipline**: long commands always `run_to <seconds> <cmd>` (the cross-platform wrapper from 0.1, Python process-group timeout inside; on linux plain `timeout` also works, macOS needs gtimeout, Windows git-bash often has neither → run_to uniformly avoids the differences); decompilation defaults to 900s, 1800s for jadx on large APKs; rc=124 means timeout — log it to run.log and take the degradation.
- **Logging discipline**: every command appends `>> "$OUT/00-环境/run.log" 2>&1`, with one `echo "[$(date +%T)] <stage>-<step> start/end rc=$?"` line before and after; write incrementally — never dump everything at the end.
- **General degradation rule**: tool missing / command non-zero → write one `DEGRADED: <reason>` line into the artifacts and continue with the next item; a missing `$APK` stops input processing. Scope/cancellation/permission limits still stop the affected execution rather than being treated as bypassable tool failures.
- **MCP discipline**: for ida-pro-mcp run `check_connection` first; on failure → note in the report "IDA MCP not started, skipped"; fofa without a key is skipped outright; neither blocks the main line.
- **Stage ceilings and global budget**: S0 ≤2min / S1 ≤35min / S2 ≤15min / S3 ≤10min / S4 ≤5min. These are individual ceilings (67min summed), not guaranteed allocations: the separate **60min global hard limit takes precedence**. Reserve the final 5min for S4, stop starting analysis when 5min remain, harvest existing evidence at either the stage ceiling or global cutoff, and record D. Use the saved monotonic deadline across workers; do not reset the clock on resume.
- **Device ownership**: S3 uses a selected, isolated test emulator. Record its serial in `RE_DEVICE_SERIAL`, choose the intended AVD through `RE_AVD` or `android_list_avds`, and bind every MCP action to that device through its actual supported interface. If MCP cannot target it unambiguously, use `"$ADB_BIN" -s "$RE_DEVICE_SERIAL" ...`. Physical devices use `../device-testing.md`; do not silently treat a connected user phone as the emulator. Record pre-existing packages/files/services before mutations and clean only this run's changes. After selecting the emulator, persist its resolved serial/AVD using Bash-safe `printf 'RE_DEVICE_SERIAL=%q\nRE_AVD=%q\n' "$RE_DEVICE_SERIAL" "$RE_AVD" >> "$OUT/env.sh"`; never rely on an empty initializer default. Saved monotonic deadlines are valid within the same host boot; after a reboot, preserve the interrupted run's partial report and initialize a distinct run rather than reusing a stale monotonic deadline.

### 0.3 Final output directory structure (S4 acceptance baseline)

```
输出/<package>-<date>/
├── env.sh  黑板.md
├── 00-环境/   env_report.txt  status.md  run.log
├── 01-静态/   apktool_out/  jadx_out/  apkid.txt  packer_sos.txt  packer_verdict.md
│              badging.txt  manifest_face.md  apkleaks.txt  secrets_grep.txt
│              entry_and_so.md  脱壳建议.md  urls.txt  ips.txt  so_symbols.txt  hook候选点.md
├── 02-动态/   preflight.md  install.md  screenshot_*.png  ui_tree.txt
│              logcat_raw.txt  logcat_alert.txt  frida_probe.txt  frida_ps.txt
└── 03-report.md
```

---

## S0 environment check (serial, ≤2min)

| step | command | artifact | acceptance gate | failure degradation |
|---|---|---|---|---|
| S0-1 full check | `run_to 120 "$RE_PYTHON" "$SKILL_ROOT/pipeline/env_check.py" > "$OUT/00-环境/env_report.txt" 2>&1; echo "EXIT_CODE=$?" >> "$OUT/00-环境/env_report.txt"` (SKILL_ROOT from 0.1; on macOS only, the older `bash env_check.sh` also works) | `00-环境/env_report.txt` | exists, non-empty, contains an `EXIT_CODE=` line | script won't run (python3 missing) → run `which jadx apktool adb` + `java -version` by hand and write the four lines into env_report.txt |
| S0-2 interpret and mark | the main agent reads env_report.txt and writes one line per tool into `00-环境/status.md`, format: `jadx=OK` / `frida=MISSING→S3-6 degrade` / `AVD=OK(<selected-name>)` / `apkid=MISSING→S1-B goes signature matching` | `00-环境/status.md` | exists, non-empty, ≥5 lines | no degradation, mandatory — every later stage's degradation switches depend on it |
| S0-3 blackboard init | write `$OUT/黑板.md`: F00 target APK path/package/size (`ls -lh "$APK"`); F01 the environment-check conclusion line; placeholder blocks for S1/S2/S3 | `黑板.md` | exists and contains the APK path | none (purely local writes) |

**S0 exit decision**: EXIT_CODE=0 = full capability; =1 (has yellows) degrade the matching steps per status.md; =2 (jadx+apktool both critical-red) → S1-A doubly degrades to "unzip + aapt2 direct read", and the chain still continues. EXIT_CODE=124 means the S0 ceiling was reached: preserve partial output, record unavailable checks, and continue through explicit degradation.

---

## S1 Information Gathering (Parallel Independent Work, Then Dependency Join)

When delegation is authorized, dispatch A-1/A-2, B-1/B-2, and C-1/C-3 in the same round. B-3 consumes the completed A/B outputs; C-2 and C-4 consume A/C outputs and run only after those producers finish or explicitly degrade. Never interpret a not-yet-created producer file as an empty analysis result. If delegation is not authorized or workers are unavailable, preserve this same dependency order locally.

### S1-A Unpacking and decompilation (dual engines as mutual backup)

| step | command | artifact | acceptance gate | failure degradation |
|---|---|---|---|---|
| A-1 apktool unpack | `echo "[$(date +%T)] S1A apktool start" >> "$OUT/00-环境/run.log"; run_to 900 apktool d -f -o "$OUT/01-静态/apktool_out" "$APK" >> "$OUT/00-环境/run.log" 2>&1; echo "[$(date +%T)] S1A apktool end rc=$?" >> "$OUT/00-环境/run.log"` | `01-静态/apktool_out/AndroidManifest.xml` + smali tree | AndroidManifest.xml exists and is non-empty | timeout/failure → `run_to 300 unzip -q -o "$APK" -d "$OUT/01-静态/unzip_out"` (win without unzip → `7z x`); manifest steps switch to aapt2 (see slice C); on a second failure mark slice A DEGRADED |
| A-2 jadx decompile | `echo "[$(date +%T)] S1A jadx start" >> "$OUT/00-环境/run.log"; run_to 1800 jadx -d "$OUT/01-静态/jadx_out" --show-bad-code --no-debug-info "$APK" >> "$OUT/00-环境/run.log" 2>&1; echo "[$(date +%T)] S1A jadx end rc=$?" >> "$OUT/00-环境/run.log"` | `01-静态/jadx_out/sources/` | sources exists and `find ... -name '*.java' \| wc -l` ≥1 | do not automatically retry an empty result. Record executable/runtime absence, timeout, or decompiler error as tool/infrastructure degradation, not packing evidence. A completed but empty/stub-only decompilation can support a packing hypothesis only with corroborating APKiD/native-signature/stub evidence in B-3. Strings/hooks use the actually available smali/resources/raw extraction route below, with the source and missing evidence recorded |

### S1-B Packing / build profile (APKiD first, signature-so match as fallback)

| step | command | artifact | acceptance gate | failure degradation |
|---|---|---|---|---|
| B-1 APKiD | `if "$VENV_PY" -c 'import apkid' 2>/dev/null; then APKID_BIN="$VENV_BIN/apkid"; [ -x "$APKID_BIN" ] || APKID_BIN="$VENV_BIN/apkid.exe"; if [ -n "$APKID_BIN" ] && [ -x "$APKID_BIN" ]; then run_to 300 "$APKID_BIN" "$APK" > "$OUT/01-静态/apkid.txt" 2>&1; else echo NO_APKID_CLI > "$OUT/01-静态/apkid.txt"; fi; echo "rc=$?" >> "$OUT/01-静态/apkid.txt"; else echo NO_APKID > "$OUT/01-静态/apkid.txt"; fi` (note: apkid 3.1.0 has no `__main__`; `-m apkid` raises `No module named apkid.__main__` — the venv CLI entry must be used; VENV_BIN is the venv bin dir, bin/ on posix, Scripts/ on win, see 0.1) | `01-静态/apkid.txt` | real CLI output, `rc=0`, and no `NO_APKID*` marker | venv has no apkid → the B-2 fallback is the conclusion |
| B-2 signature-so match (always runs) | `unzip -l "$APK" | grep -iE 'libDexHelper|libjiagu|libtup|libexec|libsecexe|libsecmain|libnesec|libbaiduprotect|libegis|libnqshield|libnsaegis|libedog|libshell|libmobisec|libRSProtect|ijiami|lijt|bangcle' > "$OUT/01-静态/packer_sos.txt"; echo "hits=$(wc -l < "$OUT/01-静态/packer_sos.txt")" >> "$OUT/01-静态/packer_sos.txt"` | `01-静态/packer_sos.txt` | exists and contains a `hits=` line (hits=0 is legal = no known packer seen) | unzip broken → `7z l "$APK"` piped into the same grep |
| B-3 packer verdict | the main agent merges apkid + packer_sos + whether jadx produced anything, and writes `packer_verdict.md`, one of: `Packing verdict: none` / `Packing verdict: suspected (packer name)` / `Packing verdict: confirmed (packer name + evidence lines)` / `Packing verdict: undetermined (missing evidence/tool failure)` | `01-静态/packer_verdict.md` | exists and contains a `Packing verdict:` line | none |

**B-2 signature-so reference table** (15+ vendor signatures; the matched lines stay verbatim in packer_sos.txt):

| so signature | packer / vendor |
|---|---|
| libDexHelper.so | Bangcle (free edition) |
| libsecexe.so / libsecmain.so | Bangcle (legacy) |
| libjiagu.so / libjiagu_art.so | 360 Jiagu |
| libtup.so / libshell.so / libexec.so | Tencent Legu |
| libnesec.so | NetEase Yidun |
| libbaiduprotect.so | Baidu Protect |
| libegis.so | Tongfudun |
| libnqshield.so | NQ Mobile |
| libnsaegis.so / libedog.so | NAGA |
| libmobisec.so | Alibaba JuAnQuan |
| libRSProtect.so / ijiami.dat | Ijiami |
| lijt-related so | Legu / Lenovo-family packers |
| (corroborating) empty jadx + a Stub Application class name containing `com.secneo`/`com.qihoo`/`com.tencent.stub` | Bangcle / 360 / Tencent stub |

### S1-C Manifest and Sensitive Strings

C-1/C-3 are independent APK reads. **C-2/C-4 are post-join steps run by the main agent after A/C complete**, not parallel consumers of unfinished output. B-3 is also merged by the main agent after A/B complete.

After the join, select an existing scan root and persist its evidence type. A successful apktool run need not produce `unzip_out`; do not assume that directory exists. All smali trees live under `apktool_out`, including `smali_classesN`.

```bash
RE_CODE_ROOT=
RE_SOURCE_KIND=unavailable
if [ -d "$OUT/01-静态/jadx_out/sources" ] && [ -n "$(find "$OUT/01-静态/jadx_out/sources" -type f -name '*.java' -print -quit 2>/dev/null)" ]; then
  RE_CODE_ROOT="$OUT/01-静态/jadx_out/sources"
  RE_SOURCE_KIND=java
elif [ -d "$OUT/01-静态/apktool_out" ] && [ -n "$(find "$OUT/01-静态/apktool_out" -type f -name '*.smali' -print -quit 2>/dev/null)" ]; then
  RE_CODE_ROOT="$OUT/01-静态/apktool_out"
  RE_SOURCE_KIND=smali-and-resources
elif [ -d "$OUT/01-静态/apktool_out" ] && [ -n "$(find "$OUT/01-静态/apktool_out" -type f -print -quit 2>/dev/null)" ]; then
  RE_CODE_ROOT="$OUT/01-静态/apktool_out"
  RE_SOURCE_KIND=resources-only
elif [ -d "$OUT/01-静态/unzip_out" ] && [ -n "$(find "$OUT/01-静态/unzip_out" -type f -print -quit 2>/dev/null)" ]; then
  RE_CODE_ROOT="$OUT/01-静态/unzip_out"
  RE_SOURCE_KIND=raw-archive-strings-only
fi
printf 'RE_CODE_ROOT=%q\nRE_SOURCE_KIND=%q\n' "$RE_CODE_ROOT" "$RE_SOURCE_KIND" >> "$OUT/env.sh"
```

Resources/raw strings can provide leads, but they do not establish recovered executable code. Record missing Java/smali evidence as DEGRADED and never infer absence of APIs, secrets, or packing from an unavailable root.

| step | command | artifact | acceptance gate | failure degradation |
|---|---|---|---|---|
| C-1 badging profile | `"$AAPT2" dump badging "$APK" > "$OUT/01-静态/badging.txt" 2>&1; echo "rc=$?" >> "$OUT/01-静态/badging.txt"` | `01-静态/badging.txt` | contains a `package: name=` line | aapt2 broken → PKG already degraded to the file name in 0.1; component info falls back to the apktool manifest |
| C-2 component and permission extraction | `{ echo '## Permissions'; grep -oE 'uses-permission[^>]*name="[^"]*"' "$OUT/01-静态/apktool_out/AndroidManifest.xml" 2>/dev/null; echo '## exported components'; grep -B1 'android:exported="true"' "$OUT/01-静态/apktool_out/AndroidManifest.xml" 2>/dev/null | head -60; echo '## Entry'; grep -E 'launchable-activity|native-code' "$OUT/01-静态/badging.txt" 2>/dev/null; } > "$OUT/01-静态/manifest_face.md"` | `01-静态/manifest_face.md` | non-empty and contains a `## Permissions` section header | apktool slice degraded → `"$AAPT2" dump xmltree --file AndroidManifest.xml "$APK" > "$OUT/01-静态/manifest_xmltree.txt"` then grep |
| C-3 apkleaks | `if "$VENV_PY" -c 'import apkleaks' 2>/dev/null; then APKLEAKS_BIN="$VENV_BIN/apkleaks"; [ -x "$APKLEAKS_BIN" ] || APKLEAKS_BIN="$VENV_BIN/apkleaks.exe"; if [ -n "$APKLEAKS_BIN" ] && [ -x "$APKLEAKS_BIN" ]; then run_to 600 "$APKLEAKS_BIN" -f "$APK" -o "$OUT/01-静态/apkleaks.txt" >> "$OUT/00-环境/run.log" 2>&1; else echo NO_APKLEAKS_CLI > "$OUT/01-静态/apkleaks.txt"; fi; echo "rc=$?" >> "$OUT/01-静态/apkleaks.txt"; else echo NO_APKLEAKS > "$OUT/01-静态/apkleaks.txt"; fi` (note: ① apkleaks 2.6.3 has no `__main__`, the venv CLI entry must be used; ② venvs often lack pip, and `pip show` reports NO_APKLEAKS even when installed — hence the import probe) | `01-静态/apkleaks.txt` | real CLI output, `rc=0`, and no `NO_APKLEAKS*` marker | → the C-4 grep fallback is the conclusion |
| C-4 sensitive-string grep (always runs) | `if [ -n "$RE_CODE_ROOT" ] && [ -d "$RE_CODE_ROOT" ]; then { printf 'Source: %s (%s)\n' "$RE_CODE_ROOT" "$RE_SOURCE_KIND"; case "$RE_SOURCE_KIND" in resources-only|raw-archive-strings-only) printf 'DEGRADED: no recovered executable-code evidence; strings-only leads\n';; esac; echo '## Suspected key lines'; grep -rIiE '(api[_-]?key|secret|passwd|password|app[_-]?key|access[_-]?key)[^a-z]{0,3}[\"'"'"']?[A-Za-z0-9_\-]{8,}' "$RE_CODE_ROOT" 2>/dev/null | grep -viE 'R\.string|import |\.id\.|\.attr\.' | head -150; echo '## token references'; grep -rIln 'token' "$RE_CODE_ROOT" 2>/dev/null | head -40; echo '## URL'; grep -rIhoE 'https?://[a-zA-Z0-9./?=_&%:-]+' "$RE_CODE_ROOT" 2>/dev/null | sort -u | head -120; echo '## IP'; grep -rIhoE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$RE_CODE_ROOT" 2>/dev/null | sort -u | head -60; } > "$OUT/01-静态/secrets_grep.txt"; else printf 'DEGRADED: no recovered code/resource scan root; source evidence unavailable\n' > "$OUT/01-静态/secrets_grep.txt"; fi` | `01-静态/secrets_grep.txt` | records the selected source/type and all scan sections, or explicitly records DEGRADED when no root is available; empty sections are not negative proof | Java missing → scan existing smali/resources; no code recovered → resources/raw strings only with explicit limits; no root → DEGRADED, never fabricate an empty-success result |

**S1 acceptance gate (overall)**: status.md + badging.txt + packer_verdict.md + secrets_grep.txt — all four non-empty; a missing one gets a D with the reason on the blackboard, and S2 still proceeds.

**S1 parallel subagent prompt template** (dispatch independent work in the same round, then join):

```
Goal: run <S1-A A-1/A-2 | S1-B B-1/B-2 | S1-C C-1/C-3> on APK <absolute path>; persist artifacts under <OUT>/01-静态/
Input: the absolute APK path + this slice's table + the absolute env.sh path (source it to restore state/run_to) + output root $OUT
Output: every file in the table's "artifact" column; write a DEGRADED list as the last line (or "none" if empty)
Done when: every acceptance-gate cell passes, or DEGRADED has been marked
Forbidden: running commands outside the assigned steps; reading unfinished producer outputs; touching other slices' files; returning large outputs instead of persisting artifacts. The main agent owns B-3/C-2/C-4 and the final merge.
Return: a ≤200-word summary (list of new artifacts + degraded items)
```

---

## S2 static analysis (depends on S1 artifacts; main agent serial, ≤15min)

| step | command / action | artifact | acceptance gate | failure degradation |
|---|---|---|---|---|
| S2-1 entry and so list | `{ echo '## Entry'; grep -E 'launchable-activity' "$OUT/01-静态/badging.txt"; echo '## so list'; unzip -l "$APK" | grep '\.so' | awk '{print $4}' | sort; } > "$OUT/01-静态/entry_and_so.md"` | `entry_and_so.md` | contains both `##` section headers | no aapt2 → extract LAUNCHER from manifest_face.md |
| S2-2 unpacking route advice | the main agent writes `脱壳建议.md` from packer_verdict.md, **citing only technique-library article paths, never copying content**: frida first → `../techniques/03-unpacking/dex-unpacking.md`; frida detected → `../techniques/03-unpacking/ebpf-unpacking-deep.md`; so packed → `../techniques/03-unpacking/so-repair-dump.md`; RASP/self-destruct → `../techniques/04-evasion/rasp-bypass.md`; packer-detection counterplay → `../techniques/04-evasion/frida-anti-detection.md`. No packing evidence → write `Verdict: no unpacking currently indicated; assess jadx coverage before claiming complete code recovery` | `脱壳建议.md` | exists and contains a `Verdict:` line | none |
| S2-3 string master list | `grep -rIhoE 'https?://[^"'"'"' )<>]+' "$OUT/01-静态/jadx_out/resources" "$OUT/01-静态/apktool_out/res" 2>/dev/null | sort -u > "$OUT/01-静态/urls.txt"; grep -rIhoE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$OUT/01-静态/apktool_out/res" 2>/dev/null | sort -u | head -80 > "$OUT/01-静态/ips.txt"` | `urls.txt` / `ips.txt` | both files exist (may be empty) | none |
| S2-4 so symbol quick scan (only if so files exist) | `: > "$OUT/01-静态/so_symbols.txt"; TMPSO="$OUT/01-静态/re_native"; mkdir -p "$TMPSO"; unzip -Z1 "$APK" | grep -E '^lib/arm64-v8a/.*\.so$' | head -10 | while IFS= read -r so; do n=$(basename "$so"); unzip -p "$APK" "$so" > "$TMPSO/re_$n" 2>/dev/null; echo "== $n ==" >> "$OUT/01-静态/so_symbols.txt"; nm -D "$TMPSO/re_$n" 2>/dev/null | grep -iE 'Java_|JNI_OnLoad' | head -30 >> "$OUT/01-静态/so_symbols.txt"; done` | `so_symbols.txt` | exists and ≥1 `==` section header (with no so files, write "no native libraries") | nm broken / Windows has no nm (use llvm-nm or dumpbin; if neither) → per file swap in `r2 -q -c 'is~JNI' "$TMPSO/re_x.so"`; no JNI exports → record F "suspected RegisterNatives dynamic registration" |
| S2-5 frida hook candidates | the main agent greps `jadx_out/sources` by the six domains and writes `hook候选点.md` (domain → class/method → what to capture; write N/A for empty hits): | `hook候选点.md` | one section per domain (N/A counts) | jadx unavailable → grep the existing apktool smali trees (including smali_classesN). With resources/raw strings only, retain hints as unverified; without executable-code evidence record DEGRADED/N/A for method-level hook candidates |
| S2-6 blackboard merge | merge S1/S2 F/D entries into 黑板.md (append) | 黑板.md | ≥3 new F entries | none |

**S2-5 six-domain greps and candidate functions** (the six articles under `../techniques/02-frida/java-layer/`):

| domain (article) | grep probe | candidate hook functions |
|---|---|---|
| network & webview (`../techniques/02-frida/java-layer/network-webview.md`) | `grep -rIl 'okhttp3\|HttpURLConnection\|WebView' sources \| head -15` | OkHttpClient.newCall / HttpURLConnection.connect / WebView.shouldOverrideUrlLoading / loadUrl |
| crypto & self-echo (`../techniques/02-frida/java-layer/crypto-and-self-dump.md`) | `grep -rIl 'javax.crypto\|Cipher\.getInstance\|Mac\.getInstance' sources \| head -15` | Cipher.doFinal / Cipher.getInstance / Mac.doFinal / SecretKeySpec constructor |
| sslpinning & certificates (`../techniques/02-frida/java-layer/sslpinning-and-certificates.md`) | `grep -rIl 'X509TrustManager\|checkServerTrusted\|CertificatePinner' sources \| head -15` | checkServerTrusted / OkHostnameVerifier.verify / CertificatePinner.check |
| storage & system (`../techniques/02-frida/java-layer/storage-and-system.md`) | `grep -rIl 'getSharedPreferences\|SQLiteDatabase\|SharedPreferences' sources \| head -15` | SharedPreferences.getString/putString / SQLiteDatabase.query/execSQL |
| strings & JSON (`../techniques/02-frida/java-layer/strings-and-json.md`) | `grep -rIl 'JSONObject\|Base64\.encode\|JSONArray' sources \| head -15` | JSONObject.toString / JSONObject.<init> / Base64.encodeToString |
| UI & navigation (`../techniques/02-frida/java-layer/ui-and-navigation.md`) | `grep -rIl 'startActivity\|addFragment\|FragmentTransaction' sources \| head -15` | Activity.startActivity(Intent) / Fragment.onCreate |

**S2 acceptance gate (overall)**: entry_and_so.md + 脱壳建议.md + hook候选点.md non-empty; so_symbols/urls/ips may be empty but must exist.

---

## S3 dynamic analysis (android-emulator MCP; if S0 flagged red, the whole section degrades, ≤10min)

| step | tool (MCP call, not Bash) | artifact | acceptance gate | failure degradation |
|---|---|---|---|---|
| S3-1 selected test-emulator readiness | `android_preflight` + `android_list_avds` + `android_list_devices`; resolve the intended isolated test AVD and matching emulator serial. PASS only if that selected test emulator is online and its identity is verified. If absent, start only the selected `RE_AVD` with `android_start_emulator(avd=<RE_AVD>, timeoutMs=180000)`, then verify its actual serial/AVD identity. The global count of adb devices is not a readiness condition; a connected phone does not satisfy this step. | `02-动态/preflight.md`: selected AVD, resolved serial, identity/isolation evidence, and outcome | the intended isolated test emulator is online and unambiguously selected; persist its serial/AVD in env.sh | no suitable test AVD, ambiguous selection, or startup/identity failure → S3 wholesale DEGRADED, preserve preflight and go to S4; never select a user phone as fallback |
| S3-2 install | `android_install_app(apkPath=<absolute APK path>, timeoutMs=180000)`; **an APK outside the project root raises `Path escapes project root` → drop straight to `"$ADB_BIN" -s "$RE_DEVICE_SERIAL" install -r -t "$APK"` and record install.md** | `02-动态/install.md` (on success, the package name; on failure, the INSTALL_FAILED_ code) | contains a success line or a failure code | UPDATE_INCOMPATIBLE → uninstall and retry once **only for a disposable test package owned by this run on the selected isolated emulator**. Preserve pre-existing applications/data: otherwise choose a clean test AVD/copy or record D and skip dynamics; on a second failure record D |
| S3-3 launch | `android_launch_app(applicationId="$PKG", timeoutMs=60000)` | append the result to install.md | returned launched | crashes at launch → do not retry; still run S3-5 to capture the crash log |
| S3-4 screenshots ×2 + UI tree | ~10s after launch: `android_screenshot(path="$OUT/02-动态/screenshot_1.png")`; at 30s: `screenshot_2.png`; after each screenshot store the `android_ui_describe` result in `02-动态/ui_tree.txt` (append the second time). **Note: a path outside the project root raises `Path escapes project root` → persist screenshots uniformly with `"$ADB_BIN" -s "$RE_DEVICE_SERIAL" exec-out screencap -p > "$OUT/02-动态/screenshot_N.png"`; an extra no-path MCP screenshot may be called for the agent to view directly** | 2 png + ui_tree.txt | pngs exist and >10KB; ui_tree non-empty | black screen / empty tree: keep them anyway and annotate (that is itself an observation) |
| S3-5 logcat filter | `android_logs(applicationId="$PKG", lines=500)` stored wholesale in `02-动态/logcat_raw.txt`; then `grep -iE 'FATAL|AndroidRuntime|SIGSEGV|SIGABRT|frida|xposed|root|emulator|debug' "$OUT/02-动态/logcat_raw.txt" > "$OUT/02-动态/logcat_alert.txt"` | both files | logcat_raw non-empty | MCP logs fails → run `"$ADB_BIN" -s "$RE_DEVICE_SERIAL" logcat -d -t 500 > logcat_raw.txt` directly |
| S3-6 frida-server probe (optional) | Bash: `"$ADB_BIN" -s "$RE_DEVICE_SERIAL" shell 'ls /data/local/tmp/ 2>/dev/null' > "$OUT/02-动态/frida_probe.txt"; "$ADB_BIN" -s "$RE_DEVICE_SERIAL" shell 'getprop ro.build.version.sdk' >> "$OUT/02-动态/frida_probe.txt"`; a trusted pre-provisioned `/data/local/tmp/re_fs` is present → start that exact server on the selected test emulator, record its actual PID and pre-existing state, wait 10s → `run_to 30 "$VENV_PY" -c "import frida,sys; d=frida.get_device(sys.argv[1], timeout=10); print([p.name for p in d.enumerate_processes()][:20])" "$RE_DEVICE_SERIAL" > "$OUT/02-动态/frida_ps.txt" 2>&1` | frida_probe.txt (+frida_ps.txt) | frida_probe.txt exists (empty = no server, legal) | no server → annotate "dynamic hook not executed: no frida-server on the emulator; install steps in re/techniques/02-frida/env-and-quickstart.md"; **do not compile/push frida-server on the spot (over budget)** |
| S3-7 light UI walkthrough | when ui_tree has tappable controls: `android_ui_tap` the permission dialog's "Allow" + 1-2 main buttons; after each tap add `screenshot_3..n.png` + append a ui_describe | the screenshot sequence | ≥1 post-interaction screenshot | nothing tappable / instant crash → keep what exists, record D |

**S3 exit decision**: install succeeded and logcat_raw non-empty = done; install failed but preflight recorded = half-done (annotate); emulator never started = the whole section DEGRADED.

---

## S4 report (purely local, must-deliver, ≤5min)

Enter S4 while its reserved 300s remain; set `RE_REPORT_RESERVE_SECONDS=0` after sourcing env.sh in each S4 shell so report-only bounded commands may use that reserve. Do not start new analysis. Deliver a seven-section report even when earlier stages degraded, and never label incomplete analysis as a fully successful chain.

| step | action | artifact | acceptance gate | failure degradation |
|---|---|---|---|---|
| S4-1 aggregate | the main agent reads the blackboard + the head of each stage's artifacts and writes `03-report.md` (template below); SHA256 via `shasum -a 256 "$APK"` (mac; linux uses `sha256sum "$APK"`; win uses `certutil -hashfile "$APK" SHA256`) | `03-report.md` | all seven section titles present + section 7 non-empty | none: even if unfinished, first write in the known facts and the skipped items |
| S4-2 wrap-up | record actual PASS/DEGRADED/blocked outcomes and the timestamp in status.md; add evidence-based next steps to the blackboard; stop only task-started frida/hooks, remove only task-created device temp files, and uninstall only task-installed packages absent from the baseline. Preserve pre-existing applications/services and shared adb state. Keep local evidence artifacts. | incremental | recorded stage outcomes match artifacts and task-owned cleanup results exist | unverified cleanup is explicitly listed in section 7; a finished report does not imply every stage passed |

### 03-report.md fixed template (seven sections; a missing section gets N/A + reason)

```markdown
# <PKG> APK analysis report
- APK: <absolute path> | size: <ls -lh> | SHA256: <shasum -a 256 / sha256sum / certutil per platform>
- analysis time: <start-end> | chain: pipeline branch pipeline <date> | environment: env_report EXIT_CODE=<>

## 1. Basic information
package name / versionName / minSdk-targetSdk (from badging.txt) / signing certificate (apktool_out/original/META-INF file names) / entry Activity

## 2. Permissions and component surface
dangerous permissions (from manifest_face.md: LOCATION/CAMERA/RECORD_AUDIO/READ_SMS/QUERY_ALL_PACKAGES/accessibility etc.) / exported components / deep-links

## 3. Packing and unpacking advice
packing verdict (the conclusion in packer_verdict.md) + unpacking route (the technique-library citations in 脱壳建议.md; do not paste their content)

## 4. Hook candidates
the top entries of hook候选点.md summarized in the six-domain table (domain / class / method / what to capture)

## 5. Dynamic observations
install and launch results / screenshot highlights (the main agent describes the UI in one sentence per image) / logcat alert excerpts (FATAL / detection) / frida probe result

## 6. Risks and next steps
assessment of the sensitive-string/URL/IP asset surface; preferred first hooks; if packed: unpack first (cite the articles) then rerun this pipeline

## 7. Skipped items and reasons
one line per DEGRADED: stage-step-reason-suggested fix; even when all green write "none, the whole chain is green"
```

---

## Appendix: degradation route master table (quick reference)

| failure | automatic action | report impact |
|---|---|---|
| venv missing apkid/apkleaks/frida libs | B-2 signature-so match / C-4 grep / S3-6 annotation | section 3 uses the fallback conclusion; section 7 lists it |
| apktool broken | unzip unpack + aapt2 dump | manifest_face switches to the xmltree source |
| jadx unavailable/error/empty | distinguish tool failure from corroborated packing evidence; select existing Java → smali/resources → raw extraction, or record missing evidence | sections 3/4 identify the actual source and unresolved limitations |
| aapt2 broken | PKG = file name; components via apktool | section 1 annotated |
| emulator won't start | S3 wholesale DEGRADED | section 5 N/A + reason; section 7 lists it |
| install fails (INCOMPATIBLE) | owned disposable test package only: uninstall + one retry; otherwise clean test AVD/copy or D | still failing → sections 5/7 annotated |
| frida-server not on the device | not installed on the spot; annotate + cite the article | section 5 annotated |
| ida-pro-mcp not started | skipped as soon as check_connection fails | section 7 lists it (non-blocking) |
| fofa without a key | skipped | absent from the report (not this chain's capability) |
| any command timeout rc=124 | logged to run.log; that step's degradation runs | section 7 lists it |

## Whole-chain discipline (violation = redo)

1. **Persistence gate**: enter the next stage only after PASS or a documented DEGRADED fallback closes the current stage; record unavailable evidence rather than treating placeholder headings as successful analysis.
2. **Per-command timeout**: decompilation / whole-tree greps must use `run_to` (or linux `timeout`); rc=124 triggers the degradation.
3. **60min total budget**: stage ceilings do not sum to guaranteed allocations; use the global monotonic deadline, reserve 5min for S4, harvest immediately at either cutoff, and record D on the blackboard.
4. **Incremental logging**: run.log is append-only, with timestamps before and after every command.
5. **Handle routine tool failures autonomously**: record each unavailable capability in report section 7 and take its documented fallback without idle polling. Explicit scope, cancellation, permission, or missing-required-input limits remain stop conditions; preserve a partial report/handover instead of bypassing them.
6. **Blackboard append-only**: facts/deadends are appended; cite artifact paths, never paste content.
7. **Artifacts built once**: jadx/apktool outputs are shared across the whole chain; later references never rerun them.
8. **Deep dives move out**: the chain ends at the report; unpacking/algorithm/countermeasure details move to the matching articles under ../techniques/, never expanded inside the chain.
