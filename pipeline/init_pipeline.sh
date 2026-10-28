#!/usr/bin/env bash
# Source this file with one APK path; shared state is persisted with shell-safe quoting.
# Usage: source /absolute/skill-root/pipeline/init_pipeline.sh "/absolute/path/app.apk"

run_to() {
  local re_timeout_seconds=$1
  shift
  "$RE_PYTHON" "$SKILL_ROOT/pipeline/run_with_timeout.py" \
    --deadline "$RE_PIPELINE_DEADLINE" --reserve "${RE_REPORT_RESERVE_SECONDS:-300}" \
    "$re_timeout_seconds" "$@"
}

re_pipeline_init() {
  APK=${1:-}
  if [[ ! -f "$APK" ]]; then
    printf 'Missing APK: %s\n' "$APK" >&2
    return 2
  fi
  SKILL_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd) || return 2
  RE_PYTHON=$(command -v python3 || command -v python) || return 127
  APK=$("$RE_PYTHON" -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$APK") || return 2
  RE_PIPELINE_DEADLINE=$("$RE_PYTHON" -c 'import time; print(time.monotonic()+3600)') || return 2
  case "$(uname -s)" in
    Darwin) SDK_DIR=${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}} ;;
    MINGW*|MSYS*|CYGWIN*) SDK_DIR=${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/AppData/Local/Android/Sdk}} ;;
    *) SDK_DIR=${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Android/Sdk}} ;;
  esac
  ADB_BIN=$(command -v adb) || ADB_BIN="$SDK_DIR/platform-tools/adb"
  [[ -x "$SDK_DIR/platform-tools/adb.exe" && ! -x "$ADB_BIN" ]] && ADB_BIN="$SDK_DIR/platform-tools/adb.exe"
  AAPT2=$("$RE_PYTHON" - "$SDK_DIR" <<'PY'
from pathlib import Path
import re, shutil, sys
files = [p for p in (Path(sys.argv[1]) / 'build-tools').glob('*/aapt2*') if p.is_file()]
files.sort(key=lambda p: (tuple(int(n) for n in re.findall(r'\d+', p.parent.name)), str(p)))
print(str(files[-1]) if files else (shutil.which('aapt2') or 'aapt2'))
PY
) || return 2
  VENV_BIN="$SKILL_ROOT/tools-env/.venv/bin"
  [[ -x "$SKILL_ROOT/tools-env/.venv/Scripts/python.exe" ]] && VENV_BIN="$SKILL_ROOT/tools-env/.venv/Scripts"
  VENV_PY="$VENV_BIN/python"
  [[ -x "$VENV_PY" ]] || VENV_PY="$VENV_BIN/python.exe"
  PKG=$("$RE_PYTHON" - "$AAPT2" "$APK" <<'PY'
from pathlib import Path
import re, subprocess, sys
name = None
try:
    result = subprocess.run([sys.argv[1], 'dump', 'badging', sys.argv[2]], capture_output=True,
                            text=True, errors='replace', timeout=30)
    match = re.search(r"^package: name='([^']+)'", result.stdout, re.M)
    if match:
        name = match.group(1)
except (OSError, subprocess.TimeoutExpired):
    pass
print(re.sub(r'[^A-Za-z0-9._-]', '_', name or Path(sys.argv[2]).stem) or 're_apk')
PY
) || return 2
  OUT=${RE_PIPELINE_OUT:-$(dirname "$APK")/输出/${PKG}-$(date +%Y%m%d)}
  if [[ -d "$OUT" && -n "$(ls -A "$OUT" 2>/dev/null)" ]]; then
    OUT="${OUT}-$(date +%H%M%S)-$$"
  fi
  mkdir -p "$OUT"/{00-环境,01-静态,02-动态} || return 2
  OUT=$(cd "$OUT" && pwd) || return 2
  RE_AVD=${RE_AVD:-}
  RE_DEVICE_SERIAL=${RE_DEVICE_SERIAL:-}
  RE_REPORT_RESERVE_SECONDS=300
  local re_state_name
  {
    for re_state_name in APK SKILL_ROOT RE_PYTHON AAPT2 SDK_DIR ADB_BIN VENV_BIN VENV_PY PKG OUT RE_AVD RE_DEVICE_SERIAL RE_PIPELINE_DEADLINE RE_REPORT_RESERVE_SECONDS; do
      printf '%s=%q\n' "$re_state_name" "${!re_state_name}"
    done
    declare -f run_to
  } > "$OUT/env.sh"
  printf '[%s] pipeline start APK=%s OUT=%s\n' "$(date '+%F %T')" "$APK" "$OUT" > "$OUT/00-环境/run.log"
}

re_pipeline_init "$@"
re_pipeline_init_rc=$?
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  return "$re_pipeline_init_rc"
fi
exit "$re_pipeline_init_rc"
