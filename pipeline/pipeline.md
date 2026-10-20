# pipeline branch: agent-executed APK analysis workflow

> Input an APK path and an authorized analysis scope. An agent executes the five
> stages using the available tools and writes a report. This document defines
> the deeper workflow. The unified `re-run analyze --type android` CLI handles
> bounded static APK/AAB analysis; the complete S0–S4 dynamic chain is not yet
> wired into that runner. See [current matrix](../docs/runner.zh-CN.md) and
> [execution handoff](../docs/agent-completion-prompt.zh-CN.md).
> Write and check stage artifacts before continuing. Tool failures follow the
> documented fallback and remain visible in the report. Required authorization,
> missing input, cancellation, and host permission limits still apply.
> Executor: the main agent orchestrates. Use serial execution by default;
> delegate S1 slices only when the user or applicable instructions request it.
> Command baseline: identical across the three platforms (macOS/Linux/Windows) — jadx/apktool/adb etc. are always invoked by their PATH command names; installation and per-platform paths are in `../setup.md` §1–§2, the venv in §3; the check runs `pipeline/env_check.py` (cross-platform; the older `env_check.sh` is macOS-only).
> Command interpreter: bash syntax (native on macOS/Linux; Windows goes through Git-Bash/WSL).

## Full-chain DAG overview (at a glance)

```
Input: <absolute APK path> ──[ -f fails = the only hard stop ]
  │
  ▼
S0 environment check (≤2min, serial)          python3 env_check.py → env_report.txt / status.md / 黑板.md
  │
  ▼
S1 information gathering (≤35min, A/B/C three parallel slices) ─┬─ A: apktool d + jadx -d (dual engines, mutual backup)
  │                                  ├─ B: APKiD → signature-so match → packer_verdict.md
  │                                  └─ C: badging + manifest_face + apkleaks → secrets_grep
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

Every step's degradation exit feeds into section 7 of S4; no branch can block the chain.

## MCP tool mapping (for S3; calls other than Bash)

| pipeline step | MCP tool and key parameters | bash-side equivalent degradation |
|---|---|---|
| S3-1 readiness / start emulator | `android_preflight` / `android_list_devices` / `android_start_emulator(avd=<configured AVD>, timeoutMs=180000)` | Select an existing suitable AVD with `emulator -list-avds`; start it with `-avd "$RE_AVD"` (Windows: `emulator.exe`) |
| S3-2 install | `android_install_app(apkPath, timeoutMs=180000)` (note: apkPath does not allow paths outside the project root, e.g. /tmp → raises `Path escapes project root`; go straight to the right-hand degradation) | `adb install -r -t "$APK"` |
| S3-3 launch | `android_launch_app(applicationId="$PKG", timeoutMs=60000)` | `adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1` |
| S3-4 screenshots / UI tree | `android_screenshot` (same restriction: path confined to the project root; called without a path it returns MCP image content for the agent to view directly — persist artifacts with the right-hand command) / `android_ui_describe` | `adb exec-out screencap -p > x.png` / `adb shell uiautomator dump` |
| S3-5 logcat | `android_logs(applicationId, lines=500)` | `adb logcat -d -t 500` |
| S3-7 tap | `android_ui_tap(x, y)` | `adb shell input tap x y` |
| optional enhancements | `node_repl` (JS deobfuscation), `WebSearch/WebFetch` (packer intelligence), `ida-pro-mcp` (only after check_connection passes), `fofa` (skipped without a key) | — |

## 0. Global conventions (common to every stage)

### 0.1 Variable initialization (the chain's first Bash; run this first; cross-platform macOS/Linux/Windows-GitBash)

```bash
APK="<absolute APK path given by the user>"                # the only hard-stop condition: if [ -f "$APK" ] fails, terminate
SKILL_ROOT="$(pwd)"   # run this block from the checked-out skill root containing SKILL.md
# SDK root per platform: mac=~/Library/Android/sdk linux=~/Android/Sdk win=%LOCALAPPDATA%\Android\Sdk
case "$(uname -s)" in
  Darwin)                    SDK_DIR="$HOME/Library/Android/sdk";;
  MINGW*|MSYS*|CYGWIN*)      SDK_DIR="$HOME/AppData/Local/Android/Sdk";;
  *)                         SDK_DIR="$HOME/Android/Sdk";;
esac
AAPT2=$(ls "$SDK_DIR"/build-tools/*/aapt2* 2>/dev/null | sort -V | tail -1)   # pick the highest build-tools (win is aapt2.exe; the aapt2* glob covers both)
[ -z "$AAPT2" ] && AAPT2=aapt2                # no SDK → fall back to PATH
# venv python: win=Scripts\python.exe posix=bin/python, pick whichever exists (install steps in setup.md §3)
VENV_BIN="$SKILL_ROOT/tools-env/.venv/bin"
[ -x "$SKILL_ROOT/tools-env/.venv/Scripts/python.exe" ] && VENV_BIN="$SKILL_ROOT/tools-env/.venv/Scripts"
VENV_PY="$VENV_BIN/python"; [ -x "$VENV_PY" ] || VENV_PY="$VENV_BIN/python.exe"
RE_AVD="${RE_AVD:-}"   # select a matching existing AVD; no historical default
# Cross-platform timeout wrapper (replaces GNU timeout: native on linux / mac needs gtimeout / often absent in win git-bash): usage run_to <seconds> <cmd...>, timeout rc=124
run_to() { local s=$1; shift; python3 -c 'import subprocess,sys
try: sys.exit(subprocess.call(sys.argv[2:],timeout=float(sys.argv[1])))
except subprocess.TimeoutExpired: sys.exit(124)' "$s" "$@"; }
PKG=$("$AAPT2" dump badging "$APK" 2>/dev/null | grep -m1 "^package: name=" | sed "s/^package: name='\([^']*\)'.*/\1/")   # anchor on ^package: name= to grab only the package name (a greedy `.*name='` match runs to end-of-line, catching compileSdkVersionCodename='17' and making PKG=17)
[ -z "$PKG" ] && PKG=$(basename "$APK" .apk)          # aapt2 failed → degrade: use the file name
OUT="$(dirname "$APK")/输出/${PKG}-$(date +%Y%m%d)"    # output root: <next to the APK>/输出/<package>-<date>/
mkdir -p "$OUT"/{00-环境,01-静态,02-动态}
cat > "$OUT/env.sh" <<EOF
APK='$APK'; AAPT2='$AAPT2'; SDK_DIR='$SDK_DIR'; VENV_BIN='$VENV_BIN'; VENV_PY='$VENV_PY'; PKG='$PKG'; OUT='$OUT'; RE_AVD='$RE_AVD'
EOF
echo "[$(date +%F\ %T)] pipeline start APK=$APK OUT=$OUT" > "$OUT/00-环境/run.log"
```

Every later Bash starts with `source "$(dirname <this artifact root>)/env.sh"` or carries the variables directly (absolute paths first, to survive cwd drift).

### 0.2 Discipline parameters

- **Timeout discipline**: long commands always `run_to <seconds> <cmd>` (the cross-platform wrapper from 0.1, python subprocess timeout inside; on linux plain `timeout` also works, macOS needs gtimeout, Windows git-bash often has neither → run_to uniformly avoids the differences); decompilation defaults to 900s, 1800s for jadx on large APKs; rc=124 means timeout — log it to run.log and take the degradation.
- **Logging discipline**: every command appends `>> "$OUT/00-环境/run.log" 2>&1`, with one `echo "[$(date +%T)] <stage>-<step> start/end rc=$?"` line before and after; write incrementally — never dump everything at the end.
- **General degradation rule**: tool missing / command non-zero → write one `DEGRADED: <reason>` line into the artifacts and continue with the next item; only a missing `$APK` is a hard stop.
- **MCP discipline**: for ida-pro-mcp run `check_connection` first; on failure → note in the report "IDA MCP not started, skipped"; fofa without a key is skipped outright; neither blocks the main line.
- **Total budget**: S0 ≤2min / S1 ≤35min / S2 ≤15min / S3 ≤10min / S4 ≤5min, 60min total; a stage over budget immediately harvests what exists and moves on (record a D on the blackboard).

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
| S0-1 full check | `python3 "$SKILL_ROOT/pipeline/env_check.py" > "$OUT/00-环境/env_report.txt" 2>&1; echo "EXIT_CODE=$?" >> "$OUT/00-环境/env_report.txt"` (SKILL_ROOT from 0.1; on macOS only, the older `bash env_check.sh` also works) | `00-环境/env_report.txt` | exists, non-empty, contains an `EXIT_CODE=` line | script won't run (python3 missing) → run `which jadx apktool adb` + `java -version` by hand and write the four lines into env_report.txt |
| S0-2 interpret and mark | the main agent reads env_report.txt and writes one line per tool into `00-环境/status.md`, including the actual selected AVD and unavailable capabilities | `00-环境/status.md` | tool status and selected-device evidence recorded | mandatory; later degradation follows actual capabilities |
| S0-3 blackboard init | write `$OUT/黑板.md`: F00 target APK path/package/size (`ls -lh "$APK"`); F01 the environment-check conclusion line; placeholder blocks for S1/S2/S3 | `黑板.md` | exists and contains the APK path | none (purely local writes) |

**S0 exit decision**: EXIT_CODE=0 = full capability; =1 (has yellows) degrade the matching steps per status.md; =2 (jadx+apktool both critical-red) → S1-A doubly degrades to "unzip + aapt2 direct read", and the chain still continues.

---

## S1 information gathering (three parallel slices; may be dispatched to 3 subagents in the same round)

### S1-A Unpacking and decompilation (dual engines as mutual backup)

| step | command | artifact | acceptance gate | failure degradation |
|---|---|---|---|---|
| A-1 apktool unpack | `echo "[$(date +%T)] S1A apktool start" >> "$OUT/00-环境/run.log"; run_to 900 apktool d -f -o "$OUT/01-静态/apktool_out" "$APK" >> "$OUT/00-环境/run.log" 2>&1; echo "[$(date +%T)] S1A apktool end rc=$?" >> "$OUT/00-环境/run.log"` | `01-静态/apktool_out/AndroidManifest.xml` + smali tree | AndroidManifest.xml exists and is non-empty | timeout/failure → `run_to 300 unzip -q -o "$APK" -d "$OUT/01-静态/unzip_out"` (win without unzip → `7z x`); manifest steps switch to aapt2 (see slice C); on a second failure mark slice A DEGRADED |
| A-2 jadx decompile | `echo "[$(date +%T)] S1A jadx start" >> "$OUT/00-环境/run.log"; run_to 1800 jadx -d "$OUT/01-静态/jadx_out" --show-bad-code --no-debug-info "$APK" >> "$OUT/00-环境/run.log" 2>&1; echo "[$(date +%T)] S1A jadx end rc=$?" >> "$OUT/00-环境/run.log"` | `01-静态/jadx_out/sources/` | sources exists and `find ... -name '*.java' \| wc -l` ≥1 | jadx produces nothing (typical of packing) → do not retry; record F on the blackboard "empty jadx = suspected packing/empty shell, the real code is inside the packer"; the string/hook-candidate slices degrade to running over the smali tree |

### S1-B Packing / build profile (APKiD first, signature-so match as fallback)

| step | command | artifact | acceptance gate | failure degradation |
|---|---|---|---|---|
| B-1 APKiD | `if "$VENV_PY" -c 'import apkid' 2>/dev/null; then APKID_BIN="$VENV_BIN/apkid"; [ -x "$APKID_BIN" ] || APKID_BIN="$VENV_BIN/apkid.exe"; if [ -n "$APKID_BIN" ] && [ -x "$APKID_BIN" ]; then run_to 300 "$APKID_BIN" "$APK" > "$OUT/01-静态/apkid.txt" 2>&1; else run_to 300 "$VENV_PY" -m apkid "$APK" > "$OUT/01-静态/apkid.txt" 2>&1; fi; echo "rc=$?" >> "$OUT/01-静态/apkid.txt"; else echo NO_APKID > "$OUT/01-静态/apkid.txt"; fi` (note: apkid 3.1.0 has no `__main__`; `-m apkid` raises `No module named apkid.__main__` — the venv CLI entry must be used; VENV_BIN is the venv bin dir, bin/ on posix, Scripts/ on win, see 0.1) | `01-静态/apkid.txt` | not `NO_APKID` and non-empty | venv has no apkid → the B-2 fallback is the conclusion |
| B-2 signature-so match (always runs) | `unzip -l "$APK" | grep -iE 'libDexHelper|libjiagu|libtup|libexec|libsecexe|libsecmain|libnesec|libbaiduprotect|libegis|libnqshield|libnsaegis|libedog|libshell|libmobisec|libRSProtect|ijiami|lijt|bangcle' > "$OUT/01-静态/packer_sos.txt"; echo "hits=$(wc -l < "$OUT/01-静态/packer_sos.txt")" >> "$OUT/01-静态/packer_sos.txt"` | `01-静态/packer_sos.txt` | exists and contains a `hits=` line (hits=0 is legal = no known packer seen) | unzip broken → `7z l "$APK"` piped into the same grep |
| B-3 packer verdict | the main agent merges apkid + packer_sos + whether jadx produced anything, and writes `packer_verdict.md`, one of three: `Packing verdict: none` / `Packing verdict: suspected (packer name)` / `Packing verdict: confirmed (packer name + evidence lines)` | `01-静态/packer_verdict.md` | exists and contains a `Packing verdict:` line | none |

**B-2 signature-so reference table** (15+ vendor signatures; the matched lines stay verbatim in packer_sos.txt):

| so signature | packer / vendor |
|---|---|
| libDexHelper.so | Bangcle (梆梆, free edition) |
| libsecexe.so / libsecmain.so | Bangcle (梆梆, legacy) |
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

### S1-C Manifest and sensitive strings

| step | command | artifact | acceptance gate | failure degradation |
|---|---|---|---|---|
| C-1 badging profile | `"$AAPT2" dump badging "$APK" > "$OUT/01-静态/badging.txt" 2>&1; echo "rc=$?" >> "$OUT/01-静态/badging.txt"` | `01-静态/badging.txt` | contains a `package: name=` line | aapt2 broken → PKG already degraded to the file name in 0.1; component info falls back to the apktool manifest |
| C-2 component and permission extraction | `{ echo '## Permissions'; grep -oE 'uses-permission[^>]*name="[^"]*"' "$OUT/01-静态/apktool_out/AndroidManifest.xml" 2>/dev/null; echo '## exported components'; grep -B1 'android:exported="true"' "$OUT/01-静态/apktool_out/AndroidManifest.xml" 2>/dev/null | head -60; echo '## Entry'; grep -E 'launchable-activity|native-code' "$OUT/01-静态/badging.txt" 2>/dev/null; } > "$OUT/01-静态/manifest_face.md"` | `01-静态/manifest_face.md` | non-empty and contains a `## Permissions` section header | apktool slice degraded → `"$AAPT2" dump xmltree --file AndroidManifest.xml "$APK" > "$OUT/01-静态/manifest_xmltree.txt"` then grep |
| C-3 apkleaks | `if "$VENV_PY" -c 'import apkleaks' 2>/dev/null; then APKLEAKS_BIN="$VENV_BIN/apkleaks"; [ -x "$APKLEAKS_BIN" ] || APKLEAKS_BIN="$VENV_BIN/apkleaks.exe"; if [ -n "$APKLEAKS_BIN" ] && [ -x "$APKLEAKS_BIN" ]; then run_to 600 "$APKLEAKS_BIN" -f "$APK" -o "$OUT/01-静态/apkleaks.txt" >> "$OUT/00-环境/run.log" 2>&1; else run_to 600 "$VENV_PY" -m apkleaks -f "$APK" -o "$OUT/01-静态/apkleaks.txt" >> "$OUT/00-环境/run.log" 2>&1; fi; echo "rc=$?" >> "$OUT/01-静态/apkleaks.txt"; else echo NO_APKLEAKS > "$OUT/01-静态/apkleaks.txt"; fi` (note: ① apkleaks 2.6.3 has no `__main__`, the venv CLI entry must be used; ② venvs often lack pip, and `pip show` reports NO_APKLEAKS even when installed — hence the import probe) | `01-静态/apkleaks.txt` | not `NO_APKLEAKS` and non-empty | → the C-4 grep fallback is the conclusion |
| C-4 sensitive-string grep (always runs) | `{ echo '## Suspected key lines'; grep -rIiE '(api[_-]?key|secret|passwd|password|app[_-]?key|access[_-]?key)[^a-z]{0,3}[\"'"'"']?[A-Za-z0-9_\-]{8,}' "$OUT/01-静态/jadx_out/sources" 2>/dev/null | grep -viE 'R\.string|import |\.id\.|\.attr\.' | head -150; echo '## token references'; grep -rIln 'token' "$OUT/01-静态/jadx_out/sources" 2>/dev/null | head -40; echo '## URL'; grep -rIhoE 'https?://[a-zA-Z0-9./?=_&%:-]+' "$OUT/01-静态/jadx_out/sources" 2>/dev/null | sort -u | head -120; echo '## IP'; grep -rIhoE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$OUT/01-静态/jadx_out/sources" 2>/dev/null | sort -u | head -60; } > "$OUT/01-静态/secrets_grep.txt"`; when jadx degrades, replace sources with `"$OUT/01-静态/unzip_out"` | `01-静态/secrets_grep.txt` | exists and contains a `## URL` section header (individual sections may be empty) | double degradation (nearly impossible) → mark DEGRADED |

**S1 acceptance gate (overall)**: status.md + badging.txt + packer_verdict.md + secrets_grep.txt — all four non-empty; a missing one gets a D with the reason on the blackboard, and S2 still proceeds.

**S1 parallel subagent prompt template** (when dispatching the three slices in the same round):

```
Goal: run every step of <S1-A|S1-B|S1-C> on APK <absolute path>; persist artifacts under <OUT>/01-静态/
Input: the apk path + this slice's table above (execute the commands verbatim) + the output root $OUT
Output: every file in the table's "artifact" column; write a DEGRADED list as the last line (or "none" if empty)
Done when: every acceptance-gate cell passes, or DEGRADED has been marked
Forbidden: running commands outside the table; touching other slices' files; returning large outputs instead of writing them to disk
Return: a ≤200-word summary (list of new artifacts + degraded items)
```

---

## S2 static analysis (depends on S1 artifacts; main agent serial, ≤15min)

| step | command / action | artifact | acceptance gate | failure degradation |
|---|---|---|---|---|
| S2-1 entry and so list | `{ echo '## Entry'; grep -E 'launchable-activity' "$OUT/01-静态/badging.txt"; echo '## so list'; unzip -l "$APK" | grep '\.so' | awk '{print $4}' | sort; } > "$OUT/01-静态/entry_and_so.md"` | `entry_and_so.md` | contains both `##` section headers | no aapt2 → extract LAUNCHER from manifest_face.md |
| S2-2 unpacking route advice | the main agent writes `脱壳建议.md` from packer_verdict.md, **citing only technique-library article paths, never copying content**: frida first → `../techniques/03-unpacking/dex-unpacking.md`; frida detected → `../techniques/03-unpacking/ebpf-unpacking-deep.md`; so packed → `../techniques/03-unpacking/so-repair-dump.md`; RASP/self-destruct → `../techniques/04-evasion/rasp-bypass.md`; packer-detection counterplay → `../techniques/04-evasion/frida-anti-detection.md`. No packing → write `Verdict: no unpacking needed; the jadx output is the full code` | `脱壳建议.md` | exists and contains a `Verdict:` line | none |
| S2-3 string master list | `grep -rIhoE 'https?://[^"'"'"' )<>]+' "$OUT/01-静态/jadx_out/resources" "$OUT/01-静态/apktool_out/res" 2>/dev/null | sort -u > "$OUT/01-静态/urls.txt"; grep -rIhoE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$OUT/01-静态/apktool_out/res" 2>/dev/null | sort -u | head -80 > "$OUT/01-静态/ips.txt"; echo done >> "$OUT/01-静态/urls.txt"` | `urls.txt` / `ips.txt` | both files exist (may be empty) | none |
| S2-4 so symbol quick scan (only if so files exist) | `: > "$OUT/01-静态/so_symbols.txt"; TMPSO="${TMPDIR:-/tmp}"; mkdir -p "$TMPSO"; for so in $(unzip -l "$APK" | grep 'arm64-v8a/.*\.so' | awk '{print $4}' | head -10); do n=$(basename "$so"); unzip -p "$APK" "$so" > "$TMPSO/autore_$n" 2>/dev/null; echo "== $n ==" >> "$OUT/01-静态/so_symbols.txt"; nm -D "$TMPSO/autore_$n" 2>/dev/null | grep -iE 'Java_|JNI_OnLoad' | head -30 >> "$OUT/01-静态/so_symbols.txt"; done` | `so_symbols.txt` | exists and ≥1 `==` section header (with no so files, write "no native libraries") | nm broken / Windows has no nm (use llvm-nm or dumpbin; if neither) → per file swap in `r2 -q -c 'is~JNI' "$TMPSO/autore_x.so"`; no JNI exports → record F "suspected RegisterNatives dynamic registration" |
| S2-5 frida hook candidates | the main agent greps `jadx_out/sources` by the six domains and writes `hook候选点.md` (domain → class/method → what to capture; write N/A for empty hits): | `hook候选点.md` | one section per domain (N/A counts) | jadx degraded → grep the same APIs over the smali tree; a further degradation marks DEGRADED |
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
| S3-1 readiness check | `android_preflight` + `android_list_devices`; no device → select a configured compatible AVD and start it using the available tool's actual schema | write device/AVD/version/readiness evidence to `02-动态/preflight.md` | actual identity and readiness recorded | unavailable → S3 `DEGRADED`, reason and prerequisites in report section 7 |
| S3-2 install | `android_install_app(apkPath=<absolute APK path>, timeoutMs=180000)`; **an APK outside the project root raises `Path escapes project root` → drop straight to `adb install -r -t "$APK"` and record install.md** | `02-动态/install.md` (on success, the package name; on failure, the INSTALL_FAILED_ code) | contains a success line or a failure code | UPDATE_INCOMPATIBLE → `adb uninstall "$PKG"` then retry once; on a second failure record D and skip the rest |
| S3-3 launch | `android_launch_app(applicationId="$PKG", timeoutMs=60000)` | append the result to install.md | returned launched | crashes at launch → do not retry; still run S3-5 to capture the crash log |
| S3-4 screenshots ×2 + UI tree | ~10s after launch: `android_screenshot(path="$OUT/02-动态/screenshot_1.png")`; at 30s: `screenshot_2.png`; after each screenshot store the `android_ui_describe` result in `02-动态/ui_tree.txt` (append the second time). **Note: a path outside the project root raises `Path escapes project root` → persist screenshots uniformly with `adb exec-out screencap -p > "$OUT/02-动态/screenshot_N.png"`; an extra no-path MCP screenshot may be called for the agent to view directly** | 2 png + ui_tree.txt | pngs exist and >10KB; ui_tree non-empty | black screen / empty tree: keep them anyway and annotate (that is itself an observation) |
| S3-5 logcat filter | `android_logs(applicationId="$PKG", lines=500)` stored wholesale in `02-动态/logcat_raw.txt`; then `grep -iE 'FATAL|AndroidRuntime|SIGSEGV|SIGABRT|frida|xposed|root|emulator|debug' "$OUT/02-动态/logcat_raw.txt" > "$OUT/02-动态/logcat_alert.txt"` | both files | logcat_raw non-empty | MCP logs fails → run `adb logcat -d -t 500 > logcat_raw.txt` directly |
| S3-6 frida-server probe (optional) | Bash: `adb shell 'ls /data/local/tmp/ 2>/dev/null' > "$OUT/02-动态/frida_probe.txt"; adb shell 'getprop ro.build.version.sdk' >> "$OUT/02-动态/frida_probe.txt"`; grep finds frida-server → `adb shell 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'` wait 10s → `run_to 30 "$VENV_PY" -c "import frida; d=frida.get_usb_device(); print([p.name for p in d.enumerate_processes()][:20])" > "$OUT/02-动态/frida_ps.txt" 2>&1` | frida_probe.txt (+frida_ps.txt) | frida_probe.txt exists (empty = no server, legal) | no server → annotate "dynamic hook not executed: no frida-server on the emulator; install steps in re/techniques/02-frida/env-and-quickstart.md"; **do not compile/push frida-server on the spot (over budget)** |
| S3-7 light UI walkthrough | when ui_tree has tappable controls: `android_ui_tap` the permission dialog's "Allow" + 1-2 main buttons; after each tap add `screenshot_3..n.png` + append a ui_describe | the screenshot sequence | ≥1 post-interaction screenshot | nothing tappable / instant crash → keep what exists, record D |

**S3 exit decision**: install succeeded and logcat_raw non-empty = done; install failed but preflight recorded = half-done (annotate); emulator never started = the whole section DEGRADED.

---

## S4 report (purely local, must-deliver, ≤5min)

| step | action | artifact | acceptance gate | failure degradation |
|---|---|---|---|---|
| S4-1 aggregate | the main agent reads the blackboard + the head of each stage's artifacts and writes `03-report.md` (template below); SHA256 via `shasum -a 256 "$APK"` (mac; linux uses `sha256sum "$APK"`; win uses `certutil -hashfile "$APK" SHA256`) | `03-report.md` | all seven section titles present + section 7 non-empty | none: even if unfinished, first write in the known facts and the skipped items |
| S4-2 wrap-up | append actual completed/degraded/blocked stage states with timestamp; add evidence-based next steps to the blackboard | incremental | recorded states match artifacts | a finished report does not imply every stage passed |

### 03-report.md fixed template (seven sections; a missing section gets N/A + reason)

```markdown
# <PKG> fully automated RE report
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
| jadx empty (packed) | record F suspected packing; strings/hooks degrade to smali | sections 3/4 annotated with the source |
| aapt2 broken | PKG = file name; components via apktool | section 1 annotated |
| emulator won't start | S3 wholesale DEGRADED | section 5 N/A + reason; section 7 lists it |
| install fails (INCOMPATIBLE) | uninstall + one retry | still failing → sections 5/7 annotated |
| frida-server not on the device | not installed on the spot; annotate + cite the article | section 5 annotated |
| ida-pro-mcp not started | skipped as soon as check_connection fails | section 7 lists it (non-blocking) |
| fofa without a key | skipped | absent from the report (not this chain's capability) |
| any command timeout rc=124 | logged to run.log; that step's degradation runs | section 7 lists it |

## Whole-chain discipline (violation = redo)

1. **Persistence gate**: only enter the next stage after the stage's acceptance check passes (files exist and are non-empty); otherwise take the degradation — never run uncovered.
2. **Per-command timeout**: decompilation / whole-tree greps must use `run_to` (or linux `timeout`); rc=124 triggers the degradation.
3. **60min total budget**: a stage over budget is harvested immediately and the chain moves on; record D on the blackboard.
4. **Incremental logging**: run.log is append-only, with timestamps before and after every command.
5. **Never ask the user**: every anomaly becomes one line in report section 7 — no blocking, no polling.
6. **Blackboard append-only**: facts/deadends are appended; cite artifact paths, never paste content.
7. **Artifacts built once**: jadx/apktool outputs are shared across the whole chain; later references never rerun them.
8. **Deep dives move out**: the chain ends at the report; unpacking/algorithm/countermeasure details move to the matching articles under ../techniques/, never expanded inside the chain.
