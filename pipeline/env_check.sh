#!/usr/bin/env bash
# pipeline 分支 环境体检脚本(可独立执行)
# 用途:S0 阶段逐项探测逆向链路依赖,输出表格 + EXIT_CODE
# 退出码:0=全绿 1=有黄(非关键缺项,链路可降级继续) 2=关键红(jadx+apktool 双缺,反编译降级)
# 基准:macOS arm64, bash 3.2 兼容(无关联数组)
# 用法:bash env_check.sh   (stdout 输出报告;建议 > env_report.txt 2>&1)

set -u  # 不用 -e:探测类脚本失败要继续

# ---------- 计数器 ----------
OK_N=0; WARN_N=0; FAIL_N=0; CRIT_N=0
ROW_LOG=""   # 汇总行缓冲(最后打总表)

# 状态记录:ok/warn/fail <名称> <详情>
ok()   { OK_N=$((OK_N+1));   printf "| %-26s | OK    | %s\n" "$1" "$2"; ROW_LOG="$ROW_LOG$1=OK\n"; }
warn() { WARN_N=$((WARN_N+1)); printf "| %-26s | WARN  | %s\n" "$1" "$2"; ROW_LOG="$ROW_LOG$1=WARN($2)\n"; }
fail() { FAIL_N=$((FAIL_N+1)); printf "| %-26s | FAIL  | %s\n" "$1" "$2"; ROW_LOG="$ROW_LOG$1=FAIL($2)\n"; }
crit() { CRIT_N=$((CRIT_N+1)); printf "| %-26s | FAIL* | %s  [关键项]\n" "$1" "$2"; ROW_LOG="$ROW_LOG$1=CRIT($2)\n"; }
info() { printf "| %-26s | INFO  | %s\n" "$1" "$2"; }

VER_TIMEOUT=10

# 取版本第一行(探测类命令可能挂,统一 timeout 包)
ver_of() { timeout $VER_TIMEOUT "$@" 2>&1 | head -1 | cut -c1-60; }

echo "=============================================================="
echo " pipeline 分支 环境体检  @ $(date '+%F %T')"
echo " 主机: $(uname -srm)"
echo "=============================================================="

# ---------- 一、核心命令行工具(which + version) ----------
echo
echo "## 一、命令行工具"
echo "| 工具 | 状态 | 详情 |"
echo "|------|------|------|"

# jadx(关键)
if p=$(which jadx 2>/dev/null); then
  v=$(ver_of jadx --version)
  ok "jadx" "$v ($p)"
else
  crit "jadx" "未安装: brew install jadx"
fi

# apktool(关键)
if p=$(which apktool 2>/dev/null); then
  v=$(ver_of apktool --version)
  ok "apktool" "$v ($p)"
else
  crit "apktool" "未安装: brew install apktool"
fi

# java(关键工具的运行时)
if p=$(which java 2>/dev/null); then
  v=$(ver_of java -version)
  ok "java" "$v"
else
  crit "java" "未安装(详见 https://adoptium.net)"
fi

# adb
ADB_BIN=""
for c in adb "$(echo "$HOME/Library/Android/sdk/platform-tools/adb")"; do
  if p=$(which "$c" 2>/dev/null) || [ -x "$c" ]; then ADB_BIN="${p:-$c}"; break; fi
done
if [ -n "$ADB_BIN" ]; then
  ok "adb" "$(ver_of "$ADB_BIN" version) ($ADB_BIN)"
else
  warn "adb" "未找到(S3 动态降级;SDK: $HOME/Library/Android/sdk)"
fi

# aapt2(扫 SDK build-tools)
AAPT2_BIN=""
for bt in "$HOME/Library/Android/sdk"/build-tools/*/aapt2; do
  [ -x "$bt" ] && AAPT2_BIN="$bt"   # 取最高版本(字典序最后)
done
if [ -n "$AAPT2_BIN" ]; then
  ok "aapt2(SDK)" "$(ver_of "$AAPT2_BIN" version) ($AAPT2_BIN)"
else
  warn "aapt2(SDK)" "SDK build-tools 未找到(S1-C 降级:PKG 用文件名)"
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
    warn "$t" "未安装(非关键,按需降级)"
  fi
done

# timeout(coreutils;超时纪律依赖)
if p=$(which timeout gtimeout 2>/dev/null | head -1); then
  ok "timeout(gnu)" "$p ($(ver_of $p --version | head -1))"
else
  warn "timeout(gnu)" "无 gtimeout:长命令无超时保护(建议 brew install coreutils)"
fi

# ---------- 二、tools-env venv 与 python 库 ----------
echo
echo "## 二、tools-env venv(~/.zcode/skills/re/tools-env/.venv)"
echo "| 项 | 状态 | 详情 |"
echo "|----|------|------|"

VENV_PY="~/.zcode/skills/re/tools-env/.venv/bin/python"
if [ -x "$VENV_PY" ]; then
  ok "venv python" "$("$VENV_PY" --version 2>&1 | head -1)"
  for m in frida androguard unicorn capstone apkid apkleaks; do
    if "$VENV_PY" -c "import $m" >/dev/null 2>&1; then
      v=$("$VENV_PY" -c "import $m,sys;print(getattr($m,'__version__','?'))" 2>/dev/null)
      ok "venv::$m" "import OK ${v:-?}"
    else
      warn "venv::$m" "不可 import(在装/未装→对应阶段降级)"
    fi
  done
else
  warn "venv" "不存在或不可执行(APKiD/apkleaks/frida 线全降级)"
fi

# ---------- 三、Android SDK / AVD / 设备 ----------
echo
echo "## 三、Android SDK / AVD"
echo "| 项 | 状态 | 详情 |"
echo "|----|------|------|"

SDK_DIR="$HOME/Library/Android/sdk"
if [ -d "$SDK_DIR" ]; then
  ok "SDK 目录" "$SDK_DIR (build-tools: $(ls "$SDK_DIR/build-tools" 2>/dev/null | tr '\n' ' '))"
else
  warn "SDK 目录" "$SDK_DIR 不存在(S3 动态整段降级)"
fi

EMU_BIN="$SDK_DIR/emulator/emulator"
if [ -x "$EMU_BIN" ]; then ok "emulator" "$($EMU_BIN -version 2>/dev/null | head -1 | cut -c1-50)"
else warn "emulator" "SDK emulator 不可执行"; fi

# AVD 清单(读 ~/.android/avd/*.ini)
AVD_LIST=""
if [ -d "$HOME/.android/avd" ]; then
  AVD_LIST=$(ls "$HOME/.android/avd" 2>/dev/null | grep '\.ini$' | sed 's/\.ini$//' | tr '\n' ' ' | sed 's/ *$//')
fi
if [ -n "$AVD_LIST" ]; then
  ok "AVD" "$AVD_LIST"
else
  fail "AVD" "无 AVD(S3 需 android_create_avd 或手动建)"
fi

# 已连接设备
if [ -n "$ADB_BIN" ]; then
  DEV=$("$ADB_BIN" devices 2>/dev/null | tail -n +2 | grep -c 'device$' || true)
  if [ "${DEV:-0}" -ge 1 ]; then ok "adb 设备" "${DEV} 台在线"
  else info "adb 设备" "0 台(S3 由 android-emulator MCP 起模拟器)"
  fi
fi

# ---------- 四、MCP 探测(bash 侧只能间接测;agent 侧需真调 MCP) ----------
echo
echo "## 四、MCP(bash 侧间接探测;agent 须另行真调 MCP 工具确认)"
echo "| 项 | 状态 | 详情 |"
echo "|----|------|------|"

# node 活着≈node_repl 内核可用(bash 侧)
if which node >/dev/null 2>&1; then
  ok "node_repl(间接)" "node $(node -v) 在线;agent 侧: node_repl js 调 1+1 验证"
fi

# ida-pro-mcp:默认 127.0.0.1:13337(HTTP);curl 探活
if curl -s -m 2 -o /dev/null -w '%{http_code}' http://127.0.0.1:13337 2>/dev/null | grep -q '^[1-5]'; then
  ok "ida-pro-mcp(端口)" "127.0.0.1:13337 有响应;agent 侧: check_connection 确认"
else
  info "ida-pro-mcp(端口)" "127.0.0.1:13337 无响应(IDA 未启动插件→链路自动跳过,不阻塞)"
fi

info "android-emulator MCP" "bash 不可测;agent 侧: android_preflight(实测评:AVD $AVD_LIST 就绪即 S3 可跑)"
info "fofa MCP" "bash 不可测;无 FOFA_KEY 时链路直接跳过"

# ---------- 五、jadx/apktool 小样本自验(用 /tmp 造最小 dex/zip) ----------
echo
echo "## 五、小样本自验(/tmp 造最小 dex→zip→反编译)"
echo "| 项 | 状态 | 详情 |"
echo "|----|------|------|"

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/autore_env.XXXXXX")
SAMPLE="$TMPD/sample.apk"
SMOKED=0   # 是否成功造出含 dex 样本

D8_BIN=""
for bt in "$HOME/Library/Android/sdk"/build-tools/*/d8; do [ -x "$bt" ] && D8_BIN="$bt"; done

if which javac >/dev/null 2>&1 && [ -n "$D8_BIN" ]; then
  cat > "$TMPD/T.java" <<'EOF'
public class T { public static void main(String[] a){ System.out.println("autore-smoke"); } }
EOF
  if timeout 60 javac -d "$TMPD" "$TMPD/T.java" >/dev/null 2>&1 \
     && timeout 60 "$D8_BIN" "$TMPD/T.class" --output "$TMPD" >/dev/null 2>&1 \
     && [ -f "$TMPD/classes.dex" ]; then
    # 造 zip:优先 zip,无则 python
    if which zip >/dev/null 2>&1; then
      (cd "$TMPD" && zip -q -j sample.apk classes.d* >/dev/null 2>&1)
    else
      (cd "$TMPD" && /usr/bin/python3 -c "import zipfile;zipfile.ZipFile('sample.apk','w').write('classes.dex')")
    fi
    [ -f "$SAMPLE" ] && SMOKED=1
  fi
fi

if [ "$SMOKED" -eq 1 ]; then
  # jadx 自验:能反编译出 T 源文件
  if which jadx >/dev/null 2>&1; then
    rm -rf "$TMPD/jadx_smoke"
    timeout 120 jadx -d "$TMPD/jadx_smoke" "$SAMPLE" >/dev/null 2>&1
    if find "$TMPD/jadx_smoke" -name 'T.java' 2>/dev/null | grep -q .; then
      ok "jadx 冒烟" "最小 dex zip 反编译出 T.java"
    else
      warn "jadx 冒烟" "执行了但未产出 T.java(手工复核 jadx)"
    fi
  fi
  # apktool 自验:对无 manifest 样本报结构化错误=工具链(java+jar)活着
  if which apktool >/dev/null 2>&1; then
    rm -rf "$TMPD/apk_smoke"
    timeout 120 apktool d -f -o "$TMPD/apk_smoke" "$SAMPLE" >"$TMPD/apktool_smoke.log" 2>&1
    rc=$?
    if [ $rc -eq 0 ]; then
      ok "apktool 冒烟" "rc=0 成功解码最小样本(无 manifest 时仅出 smali,工具链活)"
    elif grep -qiE 'AndroidManifest|could not|not a valid|exception' "$TMPD/apktool_smoke.log"; then
      ok "apktool 冒烟" "rc=$rc 且报错结构化(能解析 zip 并正确定位缺 manifest=工具链活)"
    else
      warn "apktool 冒烟" "rc=$rc 无可识别输出(手工复核 apktool)"
    fi
  fi
else
  warn "冒烟样本" "未能造出最小 dex(javac/d8 缺:$([ -n "$D8_BIN" ] && echo d8-ok || echo d8-missing)/$(which javac >/dev/null 2>&1 && echo javac-ok || echo javac-missing))→跳过冒烟,version 探测为准"
fi
rm -rf "$TMPD"

# ---------- 六、汇总与退出码 ----------
echo
echo "=============================================================="
echo "## 汇总"
printf "绿 OK=%d  黄 WARN=%d  红 FAIL=%d  关键红 FAIL*=%d\n" "$OK_N" "$WARN_N" "$FAIL_N" "$CRIT_N"
echo "--------------------------------------------------------------"
printf "$ROW_LOG"
echo "--------------------------------------------------------------"
# 降级提示(写给 agent 读)
echo "降级映射:venv::* WARN→S1-B/S1-C 走特征匹配/grep 兜底;adb/AVD FAIL→S3 整段标注;timeout WARN→长命令改后台+kill"
echo "EXIT_CODE 判定:全绿=0;有黄或非关键红=1;jadx+apktool 关键红=2(反编译双降级为 unzip+aapt2)"

if [ "$CRIT_N" -gt 0 ]; then
  EXIT=2
elif [ $((WARN_N + FAIL_N)) -gt 0 ]; then
  EXIT=1
else
  EXIT=0
fi
echo "EXIT_CODE=$EXIT"
exit $EXIT
