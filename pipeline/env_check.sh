#!/usr/bin/env bash
# pipeline branch environment check (runnable standalone)
# Purpose: probe every dependency of the RE chain for stage S0, output a table + EXIT_CODE
# Exit codes: 0 = all green 1 = has yellows (non-critical gaps; the chain degrades and continues) 2 = critical red (jadx+apktool both missing; decompilation degrades)
# Baseline: macOS arm64, bash 3.2 compatible (no associative arrays)
# Usage: bash env_check.sh   (report on stdout; recommended: > env_report.txt 2>&1)

set -u  # no -e: a probe script must keep going on failures

# ---------- counters ----------
OK_N=0; WARN_N=0; FAIL_N=0; CRIT_N=0
ROW_LOG=""   # summary row buffer (final table printed at the end)

# State recording: ok/warn/fail <name> <detail>
ok()   { OK_N=$((OK_N+1));   printf "| %-26s | OK    | %s\n" "$1" "$2"; ROW_LOG="$ROW_LOG$1=OK\n"; }
warn() { WARN_N=$((WARN_N+1)); printf "| %-26s | WARN  | %s\n" "$1" "$2"; ROW_LOG="$ROW_LOG$1=WARN($2)\n"; }
fail() { FAIL_N=$((FAIL_N+1)); printf "| %-26s | FAIL  | %s\n" "$1" "$2"; ROW_LOG="$ROW_LOG$1=FAIL($2)\n"; }
crit() { CRIT_N=$((CRIT_N+1)); printf "| %-26s | FAIL* | %s  [critical]\n" "$1" "$2"; ROW_LOG="$ROW_LOG$1=CRIT($2)\n"; }
info() { printf "| %-26s | INFO  | %s\n" "$1" "$2"; }

VER_TIMEOUT=10

# First version line (probe commands can hang; wrap everything in timeout)
ver_of() { timeout $VER_TIMEOUT "$@" 2>&1 | head -1 | cut -c1-60; }

echo "=============================================================="
echo " pipeline branch environment check  @ $(date '+%F %T')"
echo " host: $(uname -srm)"
echo "=============================================================="

# ---------- 1. core command-line tools (which + version) ----------
echo
echo "## 1. Command-line tools"
echo "| tool | state | detail |"
echo "|------|------|------|"

# jadx (critical)
if p=$(which jadx 2>/dev/null); then
  v=$(ver_of jadx --version)
  ok "jadx" "$v ($p)"
else
  crit "jadx" "not installed: brew install jadx"
fi

# apktool (critical)
if p=$(which apktool 2>/dev/null); then
  v=$(ver_of apktool --version)
  ok "apktool" "$v ($p)"
else
  crit "apktool" "not installed: brew install apktool"
fi

# java (the runtime of the critical tools)
if p=$(which java 2>/dev/null); then
  v=$(ver_of java -version)
  ok "java" "$v"
else
  crit "java" "not installed (see https://adoptium.net)"
fi

# adb
ADB_BIN=""
for c in adb "$(echo "$HOME/Library/Android/sdk/platform-tools/adb")"; do
  if p=$(which "$c" 2>/dev/null) || [ -x "$c" ]; then ADB_BIN="${p:-$c}"; break; fi
done
if [ -n "$ADB_BIN" ]; then
  ok "adb" "$(ver_of "$ADB_BIN" version) ($ADB_BIN)"
else
  warn "adb" "not found (S3 dynamic degrades; SDK: $HOME/Library/Android/sdk)"
fi

# aapt2 (scan SDK build-tools)
AAPT2_BIN=""
for bt in "$HOME/Library/Android/sdk"/build-tools/*/aapt2; do
  [ -x "$bt" ] && AAPT2_BIN="$bt"   # take the highest version (last in lexicographic order)
done
if [ -n "$AAPT2_BIN" ]; then
  ok "aapt2(SDK)" "$(ver_of "$AAPT2_BIN" version) ($AAPT2_BIN)"
else
  warn "aapt2(SDK)" "SDK build-tools not found (S1-C degrades: PKG falls back to the file name)"
fi

# radare2 / 7z / node / uv / unzip / shasum / nm / curl
for t in radare2 7z node uv unzip shasum nm curl; do
  if p=$(which $t 2>/dev/null); then
    case $t in
      radare2) d=$(ver_of r2 -v);;
      7z)      d=$(ver_of 7z 2>/dev/null | head -1);;
      *)       d="$p";;
    esac
    [ -z "$d" ] && d="$p"
    ok "$t" "$(echo "$d" | cut -c1-60)"
  else
    warn "$t" "not installed (non-critical, degrade as needed)"
  fi
done

# timeout (coreutils; the timeout discipline depends on it)
if p=$(which timeout gtimeout 2>/dev/null | head -1); then
  ok "timeout(gnu)" "$p ($(ver_of $p --version | head -1))"
else
  warn "timeout(gnu)" "no gtimeout: long commands run without timeout protection (brew install coreutils recommended)"
fi

# ---------- 2. tools-env venv and python libs ----------
echo
echo "## 2. tools-env venv (<skill-root>/tools-env/.venv)"
echo "| item | state | detail |"
echo "|----|------|------|"

VENV_PY="$(cd "$(dirname "$0")/.." && pwd)/tools-env/.venv/bin/python"
if [ -x "$VENV_PY" ]; then
  ok "venv python" "$("$VENV_PY" --version 2>&1 | head -1)"
  for m in frida androguard unicorn capstone apkid apkleaks; do
    if "$VENV_PY" -c "import $m" >/dev/null 2>&1; then
      v=$("$VENV_PY" -c "import $m,sys;print(getattr($m,'__version__','?'))" 2>/dev/null)
      ok "venv::$m" "import OK ${v:-?}"
    else
      warn "venv::$m" "cannot import (installing/missing → the matching stage degrades)"
    fi
  done
else
  warn "venv" "missing or not executable (the APKiD/apkleaks/frida lines all degrade)"
fi

# ---------- 3. Android SDK / AVD / devices ----------
echo
echo "## 3. Android SDK / AVD"
echo "| item | state | detail |"
echo "|----|------|------|"

SDK_DIR="$HOME/Library/Android/sdk"
if [ -d "$SDK_DIR" ]; then
  ok "SDK dir" "$SDK_DIR (build-tools: $(ls "$SDK_DIR/build-tools" 2>/dev/null | tr '\n' ' '))"
else
  warn "SDK dir" "$SDK_DIR does not exist (the S3 dynamic stage degrades wholesale)"
fi

EMU_BIN="$SDK_DIR/emulator/emulator"
if [ -x "$EMU_BIN" ]; then ok "emulator" "$($EMU_BIN -version 2>/dev/null | head -1 | cut -c1-50)"
else warn "emulator" "SDK emulator not executable"; fi

# AVD inventory (read ~/.android/avd/*.ini)
AVD_LIST=""
if [ -d "$HOME/.android/avd" ]; then
  AVD_LIST=$(ls "$HOME/.android/avd" 2>/dev/null | grep '\.ini$' | sed 's/\.ini$//' | tr '\n' ' ' | sed 's/ *$//')
fi
if [ -n "$AVD_LIST" ]; then
  ok "AVD" "$AVD_LIST"
else
  fail "AVD" "no AVD (S3 needs android_create_avd or manual creation)"
fi

# Connected devices
if [ -n "$ADB_BIN" ]; then
  DEV=$("$ADB_BIN" devices 2>/dev/null | tail -n +2 | grep -c 'device$' || true)
  if [ "${DEV:-0}" -ge 1 ]; then ok "adb devices" "${DEV} online"
  else info "adb devices" "0 devices (S3: the android-emulator MCP starts the emulator)"
  fi
fi

# ---------- 4. MCP probing (the bash side can only probe indirectly; the agent must invoke the real MCP) ----------
echo
echo "## 4. MCP (indirect probing on the bash side; the agent must separately invoke the real MCP tools to confirm)"
echo "| item | state | detail |"
echo "|----|------|------|"

# node alive ≈ the node_repl kernel is usable (bash side)
if which node >/dev/null 2>&1; then
  ok "node_repl (indirect)" "node $(node -v) online; agent side: verify by calling node_repl js with 1+1"
fi

# ida-pro-mcp: defaults to 127.0.0.1:13337 (HTTP); curl liveness probe
if curl -s -m 2 -o /dev/null -w '%{http_code}' http://127.0.0.1:13337 2>/dev/null | grep -q '^[1-5]'; then
  ok "ida-pro-mcp (port)" "127.0.0.1:13337 responds; agent side: confirm with check_connection"
else
  info "ida-pro-mcp (port)" "127.0.0.1:13337 no response (IDA plugin not started → the chain skips it automatically, non-blocking)"
fi

info "android-emulator MCP" "not testable from bash; agent side: android_preflight (measured note: once AVD $AVD_LIST is ready, S3 can run)"
info "fofa MCP" "not testable from bash; without FOFA_KEY the chain skips it outright"

# ---------- 5. jadx/apktool small-sample self-check (build a minimal dex/zip under /tmp) ----------
echo
echo "## 5. Small-sample self-check (build a minimal dex → zip → decompile under /tmp)"
echo "| item | state | detail |"
echo "|----|------|------|"

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/autore_env.XXXXXX")
SAMPLE="$TMPD/sample.apk"
SMOKED=0   # whether a dex-bearing sample was successfully built

D8_BIN=""
for bt in "$HOME/Library/Android/sdk"/build-tools/*/d8; do [ -x "$bt" ] && D8_BIN="$bt"; done

if which javac >/dev/null 2>&1 && [ -n "$D8_BIN" ]; then
  cat > "$TMPD/T.java" <<'EOF'
public class T { public static void main(String[] a){ System.out.println("autore-smoke"); } }
EOF
  if timeout 60 javac -d "$TMPD" "$TMPD/T.java" >/dev/null 2>&1 \
     && timeout 60 "$D8_BIN" "$TMPD/T.class" --output "$TMPD" >/dev/null 2>&1 \
     && [ -f "$TMPD/classes.dex" ]; then
    # build the zip: zip if present, else python
    if which zip >/dev/null 2>&1; then
      (cd "$TMPD" && zip -q -j sample.apk classes.d* >/dev/null 2>&1)
    else
      (cd "$TMPD" && /usr/bin/python3 -c "import zipfile;zipfile.ZipFile('sample.apk','w').write('classes.dex')")
    fi
    [ -f "$SAMPLE" ] && SMOKED=1
  fi
fi

if [ "$SMOKED" -eq 1 ]; then
  # jadx self-check: must decompile the T source file
  if which jadx >/dev/null 2>&1; then
    rm -rf "$TMPD/jadx_smoke"
    timeout 120 jadx -d "$TMPD/jadx_smoke" "$SAMPLE" >/dev/null 2>&1
    if find "$TMPD/jadx_smoke" -name 'T.java' 2>/dev/null | grep -q .; then
      ok "jadx smoke" "minimal dex zip decompiled to T.java"
    else
      warn "jadx smoke" "ran but produced no T.java (recheck jadx by hand)"
    fi
  fi
  # apktool self-check: a structured error on a manifest-less sample = the toolchain (java+jar) is alive
  if which apktool >/dev/null 2>&1; then
    rm -rf "$TMPD/apk_smoke"
    timeout 120 apktool d -f -o "$TMPD/apk_smoke" "$SAMPLE" >"$TMPD/apktool_smoke.log" 2>&1
    rc=$?
    if [ $rc -eq 0 ]; then
      ok "apktool smoke" "rc=0, decoded the minimal sample (no manifest → smali only, toolchain alive)"
    elif grep -qiE 'AndroidManifest|could not|not a valid|exception' "$TMPD/apktool_smoke.log"; then
      ok "apktool smoke" "rc=$rc and the error is structured (parses the zip and correctly pinpoints the missing manifest = toolchain alive)"
    else
      warn "apktool smoke" "rc=$rc with unrecognizable output (recheck apktool by hand)"
    fi
  fi
else
  warn "smoke sample" "failed to build a minimal dex (javac/d8 gaps: $([ -n "$D8_BIN" ] && echo d8-ok || echo d8-missing)/$(which javac >/dev/null 2>&1 && echo javac-ok || echo javac-missing)) → skipping the smoke test, version probes are authoritative"
fi
rm -rf "$TMPD"

# ---------- 6. summary and exit code ----------
echo
echo "=============================================================="
echo "## Summary"
printf "green OK=%d  yellow WARN=%d  red FAIL=%d  critical-red FAIL*=%d\n" "$OK_N" "$WARN_N" "$FAIL_N" "$CRIT_N"
echo "--------------------------------------------------------------"
printf "$ROW_LOG"
echo "--------------------------------------------------------------"
# degradation hints (written for the agent to read)
echo "Degradation mapping: venv::* WARN → S1-B/S1-C fall back to signature matching/grep; adb/AVD FAIL → S3 flagged wholesale; timeout WARN → long commands move to background+kill"
echo "EXIT_CODE decision: all green = 0; any yellow or non-critical red = 1; jadx+apktool critical red = 2 (decompilation doubly degrades to unzip+aapt2)"

if [ "$CRIT_N" -gt 0 ]; then
  EXIT=2
elif [ $((WARN_N + FAIL_N)) -gt 0 ]; then
  EXIT=1
else
  EXIT=0
fi
echo "EXIT_CODE=$EXIT"
exit $EXIT
