# pipeline 分支 全自动逆向链路(pipeline)

> 零人工 DAG:输入一个 APK 绝对路径 → 五阶段自动推进 → 报告落盘。
> 铁律:**每阶段产物落盘且验收门通过才进下一阶段;任何失败走降级路径继续,不问用户、不中断**。
> 执行者:主 agent 编排。S1 的 A/B/C 三片可同轮并行下发 3 个 subagent(产物互不写同一文件);S2-S4 主 agent 串行。
> 命令基准:三平台通用(macOS/Linux/Windows)——jadx/apktool/adb 等一律按 PATH 命令名调用;安装与各平台路径见 `../初始化.md` §1-§2,venv 见 §3;体检跑 `pipeline/env_check.py`(跨平台,旧 `env_check.sh` 仅 macOS 可用)。
> 命令解释器:bash 语法(macOS/Linux 原生;Windows 走 Git-Bash/WSL)。

## 全链 DAG 总览(一眼版)

```
输入: <APK 绝对路径> ──[ -f 不存在 = 唯一硬终止 ]
  │
  ▼
S0 环境体检(≤2min, 串行)          python3 env_check.py → env_report.txt / status.md / 黑板.md
  │
  ▼
S1 信息收集(≤35min, A/B/C 三片并行) ─┬─ A: apktool d + jadx -d(双引擎互备)
  │                                  ├─ B: APKiD → 特征 so 匹配 → packer_verdict.md
  │                                  └─ C: badging + manifest_face + apkleaks → secrets_grep
  │
  ▼
S2 静态分析(≤15min, 串行)          入口/so 清单 → 脱壳建议(引用手法库篇目) → urls/ips
  │                                  → so JNI 符号 → hook 候选点(六域) → 黑板合并
  │
  ▼
S3 动态分析(≤10min, android-emulator MCP)
  │                                  preflight/起模拟器 → 装 → 启动 → 截图+UI树
  │                                  → logcat 过滤 → frida-server 探测 → UI 轻走查
  │
  ▼
S4 报告(≤5min, 纯本地必达)          03-report.md 七段模板 + 收尾清单
  │
  ▼
输出: 输出/<包名>-<日期>/03-report.md + 「未执行项及原因」清单回传用户
```

每一步的降级出口都汇入 S4 第 7 段;没有分支能阻塞链路。

## MCP 工具映射表(S3 用,Bash 之外的调用)

| pipeline 步骤 | MCP 工具与关键参数 | bash 侧等价降级 |
|---|---|---|
| S3-1 就绪/起模拟器 | `android_preflight` / `android_list_devices` / `android_start_emulator(avd="Medium_Phone_API_36.0", timeoutMs=180000)` | `$ADB_BIN start-server` + 后台 `"$SDK_DIR/emulator/emulator" -avd Medium_Phone_API_36.0`(win 下可执行文件是 `emulator.exe`) |
| S3-2 安装 | `android_install_app(apkPath, timeoutMs=180000)`(注:apkPath 不允许 project root 外路径,如 /tmp → 报 `Path escapes project root`,直接走右侧降级) | `adb install -r -t "$APK"` |
| S3-3 启动 | `android_launch_app(applicationId="$PKG", timeoutMs=60000)` | `adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1` |
| S3-4 截图/UI 树 | `android_screenshot`(同上,path 受 project root 限制;不带 path 调用则返回 MCP image content 供 agent 直视,产物另用右侧命令落盘) / `android_ui_describe` | `adb exec-out screencap -p > x.png` / `adb shell uiautomator dump` |
| S3-5 logcat | `android_logs(applicationId, lines=500)` | `adb logcat -d -t 500` |
| S3-7 点击 | `android_ui_tap(x, y)` | `adb shell input tap x y` |
| 增强可选 | `node_repl`(JS 反混淆)、`WebSearch/WebFetch`(壳情报)、`ida-pro-mcp`(check_connection 通过才用)、`fofa`(无 key 跳过) | — |

## 0. 全局约定(每阶段通用)

### 0.1 变量初始化(全链第一条 Bash,先跑这段;跨平台 macOS/Linux/Windows-GitBash)

```bash
APK="<用户给的 APK 绝对路径>"                # 唯一硬终止条件:[ -f "$APK" ] 不成立即终止
SKILL_ROOT="$HOME/.zcode/skills/re"          # 本技能根(含 初始化.md 的目录;换机部署时按实际改)
# SDK 根按平台:mac=~/Library/Android/sdk linux=~/Android/Sdk win=%LOCALAPPDATA%\Android\Sdk
case "$(uname -s)" in
  Darwin)                    SDK_DIR="$HOME/Library/Android/sdk";;
  MINGW*|MSYS*|CYGWIN*)      SDK_DIR="$HOME/AppData/Local/Android/Sdk";;
  *)                         SDK_DIR="$HOME/Android/Sdk";;
esac
AAPT2=$(ls "$SDK_DIR"/build-tools/*/aapt2* 2>/dev/null | sort -V | tail -1)   # 取最高版 build-tools(win 为 aapt2.exe,glob aapt2* 兼盖)
[ -z "$AAPT2" ] && AAPT2=aapt2                # SDK 无 → PATH 兜底
# venv python:win=Scripts\python.exe posix=bin/python,双形式择一(装法见 初始化.md §3)
VENV_BIN="$SKILL_ROOT/tools-env/.venv/bin"
[ -x "$SKILL_ROOT/tools-env/.venv/Scripts/python.exe" ] && VENV_BIN="$SKILL_ROOT/tools-env/.venv/Scripts"
VENV_PY="$VENV_BIN/python"; [ -x "$VENV_PY" ] || VENV_PY="$VENV_BIN/python.exe"
# 跨平台超时包装(替代 GNU timeout:linux 原生/mac 需 gtimeout/win git-bash 常无):用法 run_to <秒> <cmd...>,超时 rc=124
run_to() { local s=$1; shift; python3 -c 'import subprocess,sys
try: sys.exit(subprocess.call(sys.argv[2:],timeout=float(sys.argv[1])))
except subprocess.TimeoutExpired: sys.exit(124)' "$s" "$@"; }
PKG=$("$AAPT2" dump badging "$APK" 2>/dev/null | grep -m1 "^package: name=" | sed "s/^package: name='\([^']*\)'.*/\1/")   # 锚定 ^package: name= 只抓包名(`.*name='` 贪婪匹配会抓到行尾 compileSdkVersionCodename='17' 导致 PKG=17)
[ -z "$PKG" ] && PKG=$(basename "$APK" .apk)          # aapt2 失败降级:用文件名
OUT="$(dirname "$APK")/输出/${PKG}-$(date +%Y%m%d)"    # 输出根:<APK同级>/输出/<包名>-<日期>/
mkdir -p "$OUT"/{00-环境,01-静态,02-动态}
cat > "$OUT/env.sh" <<EOF
APK='$APK'; AAPT2='$AAPT2'; SDK_DIR='$SDK_DIR'; VENV_BIN='$VENV_BIN'; VENV_PY='$VENV_PY'; PKG='$PKG'; OUT='$OUT'
EOF
echo "[$(date +%F\ %T)] pipeline start APK=$APK OUT=$OUT" > "$OUT/00-环境/run.log"
```

后续每条 Bash 开头 `source "$(dirname <本产物根>)/env.sh"` 或直接带变量(绝对路径优先,防 cwd 漂移)。

### 0.2 纪律参数

- **超时纪律**:长命令一律 `run_to <秒> <cmd>`(0.1 定义的跨平台包装,内部 python subprocess 超时;linux 也可直接 `timeout`,macOS 需 gtimeout,Windows git-bash 常无 → 统一 run_to 免差异);反编译默认 900s,jadx 大 APK 1800s;rc=124 即超时,记 run.log 并走降级。
- **日志纪律**:每命令 `>> "$OUT/00-环境/run.log" 2>&1` 追加,前后各一行 `echo "[$(date +%T)] <阶段>-<步骤> start/end rc=$?"`;增量写,禁止跑完才落。
- **降级总则**:工具缺失/命令非零 → 产物里写一行 `DEGRADED: <原因>`,继续下一条;只有 `$APK` 不存在是硬终止。
- **MCP 纪律**:ida-pro-mcp 先 `check_connection`,失败 → 报告标注「IDA MCP 未启动,跳过」;fofa 无 key 直接跳;两者不阻塞主线。
- **总预算**:S0 ≤2min / S1 ≤35min / S2 ≤15min / S3 ≤10min / S4 ≤5min,合计 60min;超预算阶段立即收割已有产物进下一阶段(黑板记 D)。

### 0.3 最终输出目录结构(S4 验收基准)

```
输出/<包名>-<日期>/
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

## S0 环境体检(串行,≤2min)

| 步骤 | 命令 | 产物 | 验收门 | 失败降级 |
|---|---|---|---|---|
| S0-1 全量体检 | `python3 "$SKILL_ROOT/pipeline/env_check.py" > "$OUT/00-环境/env_report.txt" 2>&1; echo "EXIT_CODE=$?" >> "$OUT/00-环境/env_report.txt"`(SKILL_ROOT 见 0.1;仅 macOS 也可用旧 `bash env_check.sh`) | `00-环境/env_report.txt` | 存在且非空且含 `EXIT_CODE=` 行 | 脚本跑不起来(python3 缺)→ 手工 `which jadx apktool adb` + `java -version` 四连写进 env_report.txt |
| S0-2 解读标记 | 主 agent 读 env_report.txt,逐工具写 `00-环境/status.md`,格式:`jadx=OK` / `frida=MISSING→S3-7降级` / `AVD=OK(Medium_Phone_API_36.0)` / `apkid=MISSING→S1-B走特征匹配` | `00-环境/status.md` | 存在且非空且 ≥5 行 | 不降级,必做——后续阶段降级开关全靠它 |
| S0-3 黑板初始化 | 写 `$OUT/黑板.md`:F00 目标 APK 路径/包名/大小(`ls -lh "$APK"`);F01 环境体检结论行;S1/S2/S3 区块占位 | `黑板.md` | 存在且含 APK 路径 | 无(纯本地写) |

**S0 出口判定**:EXIT_CODE=0 全能力;=1(有黄)按 status.md 降级对应步骤;=2(jadx+apktool 双红)→ S1-A 双降级为「unzip+aapt2 直读」,链路仍继续。

---

## S1 信息收集(三片并行,可同轮下发 3 个 subagent)

### S1-A 解包与反编译(双引擎互为备份)

| 步骤 | 命令 | 产物 | 验收门 | 失败降级 |
|---|---|---|---|---|
| A-1 apktool 解包 | `echo "[$(date +%T)] S1A apktool start" >> "$OUT/00-环境/run.log"; run_to 900 apktool d -f -o "$OUT/01-静态/apktool_out" "$APK" >> "$OUT/00-环境/run.log" 2>&1; echo "[$(date +%T)] S1A apktool end rc=$?" >> "$OUT/00-环境/run.log"` | `01-静态/apktool_out/AndroidManifest.xml` + smali 树 | AndroidManifest.xml 存在且非空 | 超时/失败 → `run_to 300 unzip -q -o "$APK" -d "$OUT/01-静态/unzip_out"`(win 无 unzip → `7z x`);manifest 相关步骤改走 aapt2(见 C 片);再失败 A 片标 DEGRADED |
| A-2 jadx 反编译 | `echo "[$(date +%T)] S1A jadx start" >> "$OUT/00-环境/run.log"; run_to 1800 jadx -d "$OUT/01-静态/jadx_out" --show-bad-code --no-debug-info "$APK" >> "$OUT/00-环境/run.log" 2>&1; echo "[$(date +%T)] S1A jadx end rc=$?" >> "$OUT/00-环境/run.log"` | `01-静态/jadx_out/sources/` | sources 存在且 `find ... -name '*.java' \| wc -l` ≥1 | jadx 无产出(加固典型)→ 不重试,黑板记 F「jadx 空=疑似加固/空壳,真实代码在壳内」;字符串/hook 候选片降级到 smali 树跑 |

### S1-B 加固/编译画像(APKiD 优先,特征 so 匹配兜底)

| 步骤 | 命令 | 产物 | 验收门 | 失败降级 |
|---|---|---|---|---|
| B-1 APKiD | `if "$VENV_PY" -c 'import apkid' 2>/dev/null; then APKID_BIN="$VENV_BIN/apkid"; [ -x "$APKID_BIN" ] || APKID_BIN="$VENV_BIN/apkid.exe"; if [ -n "$APKID_BIN" ] && [ -x "$APKID_BIN" ]; then run_to 300 "$APKID_BIN" "$APK" > "$OUT/01-静态/apkid.txt" 2>&1; else run_to 300 "$VENV_PY" -m apkid "$APK" > "$OUT/01-静态/apkid.txt" 2>&1; fi; echo "rc=$?" >> "$OUT/01-静态/apkid.txt"; else echo NO_APKID > "$OUT/01-静态/apkid.txt"; fi` (注:apkid 3.1.0 无 `__main__`,`-m apkid` 报 `No module named apkid.__main__`,必须走 venv CLI 入口;VENV_BIN=venv bin 目录,posix 为 bin/、win 为 Scripts/,见 0.1) | `01-静态/apkid.txt` | 非 `NO_APKID` 且非空 | venv 无 apkid → B-2 兜底即结论 |
| B-2 特征 so 匹配(必跑) | `unzip -l "$APK" | grep -iE 'libDexHelper|libjiagu|libtup|libexec|libsecexe|libsecmain|libnesec|libbaiduprotect|libegis|libnqshield|libnsaegis|libedog|libshell|libmobisec|libRSProtect|ijiami|lijt|bangcle' > "$OUT/01-静态/packer_sos.txt"; echo "hits=$(wc -l < "$OUT/01-静态/packer_sos.txt")" >> "$OUT/01-静态/packer_sos.txt"` | `01-静态/packer_sos.txt` | 存在且含 `hits=` 行(hits=0 合法=未见已知壳) | unzip 坏 → `7z l "$APK"` 接同一 grep |
| B-3 壳判定结论 | 主 agent 合并 apkid + packer_sos + jadx 是否空产出,写 `packer_verdict.md`,三选一:`加固判定:无加固` / `加固判定:疑似加固(壳名)` / `加固判定:确认加固(壳名+证据行)` | `01-静态/packer_verdict.md` | 存在且含 `加固判定:` 行 | 无 |

**B-2 特征 so 对照表**(15+ 厂商特征,匹配行原样留在 packer_sos.txt):

| so 特征 | 壳/厂商 |
|---|---|
| libDexHelper.so | 梆梆(免费版) |
| libsecexe.so / libsecmain.so | Bangcle(梆梆旧版) |
| libjiagu.so / libjiagu_art.so | 360 加固 |
| libtup.so / libshell.so / libexec.so | 腾讯乐固(legu) |
| libnesec.so | 网易易盾 |
| libbaiduprotect.so | 百度加固 |
| libegis.so | 通付盾 |
| libnqshield.so | 网秦 |
| libnsaegis.so / libedog.so | 娜迦(NAGA) |
| libmobisec.so | 阿里聚安全 |
| libRSProtect.so / ijiami.dat | 爱加密 |
| lijt 相关 so | 乐加固/联想系壳 |
| (辅证)jadx 空 + Stub Application 类名含 `com.secneo`/`com.qihoo`/`com.tencent.stub` | 梆梆/360/腾讯 Stub |

### S1-C Manifest 与敏感串

| 步骤 | 命令 | 产物 | 验收门 | 失败降级 |
|---|---|---|---|---|
| C-1 badging 画像 | `"$AAPT2" dump badging "$APK" > "$OUT/01-静态/badging.txt" 2>&1; echo "rc=$?" >> "$OUT/01-静态/badging.txt"` | `01-静态/badging.txt` | 含 `package: name=` 行 | aapt2 坏 → PKG 已在 0.1 降级为文件名;组件信息改依赖 apktool manifest |
| C-2 组件与权限提取 | `{ echo '## 权限'; grep -oE 'uses-permission[^>]*name="[^"]*"' "$OUT/01-静态/apktool_out/AndroidManifest.xml" 2>/dev/null; echo '## exported 组件'; grep -B1 'android:exported="true"' "$OUT/01-静态/apktool_out/AndroidManifest.xml" 2>/dev/null | head -60; echo '## 入口'; grep -E 'launchable-activity|native-code' "$OUT/01-静态/badging.txt" 2>/dev/null; } > "$OUT/01-静态/manifest_face.md"` | `01-静态/manifest_face.md` | 非空且含 `## 权限` 段头 | apktool 片降级 → `"$AAPT2" dump xmltree --file AndroidManifest.xml "$APK" > "$OUT/01-静态/manifest_xmltree.txt"` 再 grep |
| C-3 apkleaks | `if "$VENV_PY" -c 'import apkleaks' 2>/dev/null; then APKLEAKS_BIN="$VENV_BIN/apkleaks"; [ -x "$APKLEAKS_BIN" ] || APKLEAKS_BIN="$VENV_BIN/apkleaks.exe"; if [ -n "$APKLEAKS_BIN" ] && [ -x "$APKLEAKS_BIN" ]; then run_to 600 "$APKLEAKS_BIN" -f "$APK" -o "$OUT/01-静态/apkleaks.txt" >> "$OUT/00-环境/run.log" 2>&1; else run_to 600 "$VENV_PY" -m apkleaks -f "$APK" -o "$OUT/01-静态/apkleaks.txt" >> "$OUT/00-环境/run.log" 2>&1; fi; echo "rc=$?" >> "$OUT/01-静态/apkleaks.txt"; else echo NO_APKLEAKS > "$OUT/01-静态/apkleaks.txt"; fi` (注:①apkleaks 2.6.3 无 `__main__`,须走 venv CLI 入口;②venv 常无 pip,`pip show` 检测即使已装也报 NO_APKLEAKS,故用 import 检测) | `01-静态/apkleaks.txt` | 非 `NO_APKLEAKS` 且非空 | → C-4 grep 兜底即结论 |
| C-4 敏感串 grep(必跑) | `{ echo '## 疑似密钥行'; grep -rIiE '(api[_-]?key|secret|passwd|password|app[_-]?key|access[_-]?key)[^a-z]{0,3}[\"'"'"']?[A-Za-z0-9_\-]{8,}' "$OUT/01-静态/jadx_out/sources" 2>/dev/null | grep -viE 'R\.string|import |\.id\.|\.attr\.' | head -150; echo '## token 引用点'; grep -rIln 'token' "$OUT/01-静态/jadx_out/sources" 2>/dev/null | head -40; echo '## URL'; grep -rIhoE 'https?://[a-zA-Z0-9./?=_&%:-]+' "$OUT/01-静态/jadx_out/sources" 2>/dev/null | sort -u | head -120; echo '## IP'; grep -rIhoE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$OUT/01-静态/jadx_out/sources" 2>/dev/null | sort -u | head -60; } > "$OUT/01-静态/secrets_grep.txt"`;jadx 降级时把 sources 换成 `"$OUT/01-静态/unzip_out"` | `01-静态/secrets_grep.txt` | 存在且含 `## URL` 段头(各段可为空) | 双降级(几乎不可能)→ 标 DEGRADED |

**S1 验收门(总)**:status.md + badging.txt + packer_verdict.md + secrets_grep.txt 四件非空;缺件黑板记 D 带原因,仍进 S2。

**S1 并行 subagent prompt 模板**(三片同轮下发时):

```
目标:对 APK <绝对路径> 跑 <S1-A|S1-B|S1-C> 全部步骤,产物落盘 <OUT>/01-静态/
输入:apk 路径 + 上面本片表格(命令原样执行) + 输出根 $OUT
产出:表格「产物」列全部文件;最后一行写 DEGRADED 清单(无则写无)
完成标准:验收门列全过或已标 DEGRADED
禁止:不跑表格外命令;不改其他片文件;大输出只落文件不回传
回传:≤200 字摘要(新增产物清单 + 降级项)
```

---

## S2 静态分析(依赖 S1 产物,主 agent 串行,≤15min)

| 步骤 | 命令/动作 | 产物 | 验收门 | 失败降级 |
|---|---|---|---|---|
| S2-1 入口与 so 清单 | `{ echo '## 入口'; grep -E 'launchable-activity' "$OUT/01-静态/badging.txt"; echo '## so 清单'; unzip -l "$APK" | grep '\.so' | awk '{print $4}' | sort; } > "$OUT/01-静态/entry_and_so.md"` | `entry_and_so.md` | 含两个 `##` 段头 | 无 aapt2 → 从 manifest_face.md 提 LAUNCHER |
| S2-2 脱壳路线建议 | 主 agent 依 packer_verdict.md 写 `脱壳建议.md`,**只引用手法库篇目路径不复制内容**:frida 首选→`~/.zcode/skills/re/手法/03-脱壳dump/dex脱壳.md`;frida 被检测→`03-脱壳dump/eBPF脱壳深挖.md`;so 加固→`03-脱壳dump/so修复dump.md`;RASP/自毁→`04-对抗攻防/RASP绕过.md`;壳检测对抗→`04-对抗攻防/frida反检测对抗.md`。无加固 → 写「结论:无需脱壳,jadx 产物即全量代码」 | `脱壳建议.md` | 存在且含 `结论:` 行 | 无 |
| S2-3 字符串总表 | `grep -rIhoE 'https?://[^"'"'"' )<>]+' "$OUT/01-静态/jadx_out/resources" "$OUT/01-静态/apktool_out/res" 2>/dev/null | sort -u > "$OUT/01-静态/urls.txt"; grep -rIhoE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$OUT/01-静态/apktool_out/res" 2>/dev/null | sort -u | head -80 > "$OUT/01-静态/ips.txt"; echo done >> "$OUT/01-静态/urls.txt"` | `urls.txt` / `ips.txt` | 两文件存在(可空) | 无 |
| S2-4 so 符号速览(有 so 才跑) | `: > "$OUT/01-静态/so_symbols.txt"; TMPSO="${TMPDIR:-/tmp}"; mkdir -p "$TMPSO"; for so in $(unzip -l "$APK" | grep 'arm64-v8a/.*\.so' | awk '{print $4}' | head -10); do n=$(basename "$so"); unzip -p "$APK" "$so" > "$TMPSO/autore_$n" 2>/dev/null; echo "== $n ==" >> "$OUT/01-静态/so_symbols.txt"; nm -D "$TMPSO/autore_$n" 2>/dev/null | grep -iE 'Java_|JNI_OnLoad' | head -30 >> "$OUT/01-静态/so_symbols.txt"; done` | `so_symbols.txt` | 存在且 ≥1 个 `==` 段头(无 so 时写「无 native 库」) | nm 坏/Windows 无 nm(用 llvm-nm 或 dumpbin,都没有)→ 单文件换 `r2 -q -c 'is~JNI' "$TMPSO/autore_x.so"`;无 JNI 导出 → 记 F「疑似 RegisterNatives 动态注册」 |
| S2-5 frida hook 候选点 | 主 agent 在 `jadx_out/sources` 按六域 grep,写 `hook候选点.md`(域→类/方法→抓什么;命中空写 N/A): | `hook候选点.md` | 六域各有一节(含 N/A) | jadx 降级 → smali 树 grep 同 API;再降级标 DEGRADED |
| S2-6 黑板合并 | S1/S2 的 F/D 合并进黑板.md(追加) | 黑板.md | 新增 ≥3 条 F | 无 |

**S2-5 六域 grep 与候选函数**(`../手法/02-frida/java层/` 六篇对应):

| 域(篇名) | grep 探针 | 候选 hook 函数 |
|---|---|---|
| 网络与webview | `grep -rIl 'okhttp3\|HttpURLConnection\|WebView' sources | head -15` | OkHttpClient.newCall / HttpURLConnection.connect / WebView.shouldOverrideUrlLoading / loadUrl |
| 加密与自吐 | `grep -rIl 'javax.crypto\|Cipher\.getInstance\|Mac\.getInstance' sources | head -15` | Cipher.doFinal / Cipher.getInstance / Mac.doFinal / SecretKeySpec 构造 |
| sslpinning与证书 | `grep -rIl 'X509TrustManager\|checkServerTrusted\|CertificatePinner' sources | head -15` | checkServerTrusted / OkHostnameVerifier.verify / CertificatePinner.check |
| 存储与系统 | `grep -rIl 'getSharedPreferences\|SQLiteDatabase\|SharedPreferences' sources | head -15` | SharedPreferences.getString/putString / SQLiteDatabase.query/execSQL |
| 字符串与JSON | `grep -rIl 'JSONObject\|Base64\.encode\|JSONArray' sources | head -15` | JSONObject.toString / JSONObject.<init> / Base64.encodeToString |
| UI与跳转 | `grep -rIl 'startActivity\|addFragment\|FragmentTransaction' sources | head -15` | Activity.startActivity(Intent) / Fragment.onCreate |

**S2 验收门(总)**:entry_and_so.md + 脱壳建议.md + hook候选点.md 非空;so_symbols/urls/ips 允许空但文件在。

---

## S3 动态分析(android-emulator MCP;S0 判红灯则整段降级,≤10min)

| 步骤 | 工具(MCP 调用,非 Bash) | 产物 | 验收门 | 失败降级 |
|---|---|---|---|---|
| S3-1 就绪检查 | `android_preflight` + `android_list_devices`;0 设备 → `android_start_emulator(avd="Medium_Phone_API_36.0", timeoutMs=180000)` | 结果摘要写 `02-动态/preflight.md`(含设备列表/AVD 名) | 含 `设备` 或 `AVD` 行 | 起不来 → S3 整段 `DEGRADED: 模拟器不可启动`,跳 S4,原因进报告第 7 段 |
| S3-2 安装 | `android_install_app(apkPath=<APK绝对路径>, timeoutMs=180000)`;**APK 不在 project root 内会报 `Path escapes project root` → 直接 `adb install -r -t "$APK"` 落 install.md** | `02-动态/install.md`(成功含包名;失败含 INSTALL_FAILED_ 码) | 含「成功」或失败码 | UPDATE_INCOMPATIBLE → `adb uninstall "$PKG"` 后重试一次;仍败记 D 跳后续 |
| S3-3 启动 | `android_launch_app(applicationId="$PKG", timeoutMs=60000)` | 结果追加 install.md | 返回 launched | 启动即崩 → 不重试,照跑 S3-5 抓崩溃日志 |
| S3-4 截图×2 + UI 树 | 启动后约 10s:`android_screenshot(path="$OUT/02-动态/screenshot_1.png")`;30s:`screenshot_2.png`;每次截图后 `android_ui_describe` 结果存 `02-动态/ui_tree.txt`(第二次 append)。**注:path 在 project root 外会报 `Path escapes project root` → 截图统一用 `adb exec-out screencap -p > "$OUT/02-动态/screenshot_N.png"` 落盘,MCP 无 path 截图可另调一次供 agent 直视** | 2 png + ui_tree.txt | png 存在且 >10KB;ui_tree 非空 | 黑屏/空树也保留并标注(本身是观察点) |
| S3-5 logcat 过滤 | `android_logs(applicationId="$PKG", lines=500)` 全量存 `02-动态/logcat_raw.txt`;再 `grep -iE 'FATAL|AndroidRuntime|SIGSEGV|SIGABRT|frida|xposed|root|emulator|debug' "$OUT/02-动态/logcat_raw.txt" > "$OUT/02-动态/logcat_alert.txt"` | 两文件 | logcat_raw 非空 | MCP logs 失败 → `adb logcat -d -t 500 > logcat_raw.txt` 直跑 |
| S3-6 frida-server 探测(可选) | Bash:`adb shell 'ls /data/local/tmp/ 2>/dev/null' > "$OUT/02-动态/frida_probe.txt"; adb shell 'getprop ro.build.version.sdk' >> "$OUT/02-动态/frida_probe.txt"`;grep 到 frida-server → `adb shell 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'` 等 10s → `run_to 30 "$VENV_PY" -c "import frida; d=frida.get_usb_device(); print([p.name for p in d.enumerate_processes()][:20])" > "$OUT/02-动态/frida_ps.txt" 2>&1` | frida_probe.txt(+frida_ps.txt) | frida_probe.txt 存在(空=无 server,合法) | 无 server → 标注「动态 hook 未执行:模拟器无 frida-server,装法见 re/手法/02-frida/环境与快速开始.md」;**不现场编译/推送 frida-server(超预算)** |
| S3-7 UI 轻走查 | ui_tree 有可点控件时:`android_ui_tap` 点权限弹窗「允许」+ 1-2 个主按钮,每次点后补 `screenshot_3..n.png` + ui_describe append | 截图序列 | ≥1 张交互后截图 | 点不动/闪退 → 保留已有,记 D |

**S3 出口判定**:install 成功且 logcat_raw 非空=完成;install 败但 preflight 有记录=半完成(标注);模拟器没起=整段 DEGRADED。

---

## S4 报告(纯本地,必达,≤5min)

| 步骤 | 动作 | 产物 | 验收门 | 失败降级 |
|---|---|---|---|---|
| S4-1 汇总 | 主 agent 读黑板 + 各阶段产物头,写 `03-report.md`(模板↓);SHA256 用 `shasum -a 256 "$APK"`(mac;linux 用 `sha256sum "$APK"`;win 用 `certutil -hashfile "$APK" SHA256`) | `03-report.md` | 七段标题齐全 + 第 7 段非空 | 无:写不完也先把已有事实与未执行项写进去 |
| S4-2 收尾 | status.md 追加 `全链完成: $(date +%T)`;黑板补 Hints 段(人工下一步建议) | 增量 | 有时间戳行 | 无 |

### 03-report.md 固定模板(七段,缺段写 N/A+原因)

```markdown
# <PKG> 全自动逆向报告
- APK: <绝对路径> | 大小: <ls -lh> | SHA256: <shasum -a 256 / sha256sum / certutil 按平台>
- 分析时间: <起止> | 链路: pipeline 分支 pipeline <日期> | 环境: env_report EXIT_CODE=<>

## 1. 基本信息
包名 / versionName / minSdk-targetSdk(badging.txt 摘) / 签名证书(apktool_out/original/META-INF 文件名) / 入口 Activity

## 2. 权限与组件面
高危权限(manifest_face.md 摘:LOCATION/CAMERA/RECORD_AUDIO/READ_SMS/QUERY_ALL_PACKAGES/无障碍等) / exported 组件 / deep-link

## 3. 加固与脱壳建议
加固判定(packer_verdict.md 结论) + 脱壳路线(脱壳建议.md 里的手法库篇目引用,不贴内容)

## 4. hook 候选点
六域表格摘 hook候选点.md 的 top 条目(域/类/方法/抓什么)

## 5. 动态观察
安装启动结果 / 截图要点(主 agent 看图一句话描述 UI)/ logcat 告警摘录(FATAL/检测类)/ frida 探测结果

## 6. 风险与下一步
敏感串/URL/IP 资产面评估;hook 首选点;若加固:先脱壳(引用篇目)再重跑本 pipeline

## 7. 未执行项及原因
逐条 DEGRADED:阶段-步骤-原因-建议修复动作;全绿也要写「无,全链绿」
```

---

## 附:降级路径总表(速查)

| 故障 | 自动动作 | 对报告影响 |
|---|---|---|
| venv 缺 apkid/apkleaks/frida 库 | B-2 特征 so 匹配 / C-4 grep / S3-6 标注 | 第 3 段用兜底结论;第 7 段列明 |
| apktool 坏 | unzip 解包 + aapt2 dump | manifest_face 改 xmltree 来源 |
| jadx 空(加固) | 记 F 疑似加固;字符串/hook 降 smali | 第 3/4 段标注来源 |
| aapt2 坏 | PKG=文件名;组件走 apktool | 第 1 段标注 |
| 模拟器起不来 | S3 整段 DEGRADED | 第 5 段 N/A+原因;第 7 段列明 |
| 安装失败(INCOMPATIBLE) | uninstall 重试 1 次 | 仍败 → 5/7 段标注 |
| frida-server 不在设备 | 不现场装,标注+引用篇目 | 第 5 段标注 |
| ida-pro-mcp 未启动 | check_connection 失败即跳过 | 第 7 段列明(不阻塞) |
| fofa 无 key | 跳过 | 不出现在报告(非本链路能力) |
| 任一命令超时 rc=124 | 记 run.log,走该步降级 | 第 7 段列明 |

## 全程纪律(违反=返工)

1. **落盘门**:每阶段验收(文件存在且非空)过了才进下一阶段;不过走降级,不裸奔。
2. **单命令超时**:反编译/全树 grep 必须 `run_to`(或 linux `timeout`);rc=124 触发降级。
3. **总预算 60min**:阶段超时立即收割进下一阶段,黑板记 D。
4. **日志增量**:run.log 只追加,每命令前后时间戳。
5. **不问用户**:一切异常转为报告第 7 段一行,不阻塞不征询。
6. **黑板只增**:facts/deadends 追加式,引用产物路径不贴内容。
7. **产物只建一次**:jadx/apktool 产物全链共享,后续引用不重跑。
8. **深挖外移**:链路到报告为止;脱壳/算法/对抗细节转 ../手法/ 对应篇目,不在链内展开。
