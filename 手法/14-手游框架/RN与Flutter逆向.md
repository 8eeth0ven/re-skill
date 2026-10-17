# RN 与 Flutter 逆向

> 定位：**命令流教程**——React Native 与 Flutter 两族 hybrid 框架的完整逆向(不止抓包)：字节码/快照 → 符号/源码级 → frida hook 业务函数。
> 分工：**抓包链路**(TLS/证书/代理)不归本篇，归 `../04-对抗攻防/抓包全场景.md` §2.7 与《ssl-pinning绕过》§3.3；本篇管"看懂代码、hook 住函数、定位加密参数"。
> 工具行索引:`../05-工具矩阵/工具总表.md`(dae / FlutterTap / Reqable 三行)。

## 0. 第一分钟：判定框架

```bash
unzip -l app.apk | grep -i -E "index.android.bundle|libhermes|libapp.so|libflutter|flutter_assets"
```

| 特征 | 框架与形态 | 走哪节 |
|---|---|---|
| `assets/index.android.bundle` + `lib/*/libhermes.so` | **RN + Hermes 字节码**(主流) | §1 |
| `assets/index.android.bundle` + 无 libhermes | RN 纯 JS bundle | §2 |
| `lib/arm64-v8a/libapp.so` + `libflutter.so` + `assets/flutter_assets/` | **Flutter(AOT 快照)** | §4 |

RN 的 bundle 也可能改名/塞进 `assets/` 子目录，按 `*.bundle` 模糊找；Flutter 的业务全在 `libapp.so`(Dart AOT snapshot)，Java 层只是壳。

## 1. RN Hermes：字节码全流程

### 1.1 版本头识别

```bash
file ext/assets/index.android.bundle
# Hermes JavaScript bytecode, version 84   ← file 直接给版本
xxd -l 16 ext/assets/index.android.bundle
# c6 1f bc 03 c1 03 c1 03 | 54 00 00 00 ...
# ↑魔数固定                  ↑offset 8 起小端 u32 = 字节码版本(0x54=84)
```

版本决定工具选型：**hbctool 只支持 76/84/85/86/89/90 子集**；**94~96(RN 0.73~0.83 及关 Hermes V1 的 0.84+)用 hermit(§1.3b)**；其余(更老/98+)一律换 hermes-dec(§1.3)兜底。

### 1.2 hbctool 全流程(拆指令 → 改 → 回编)

```bash
UV_CACHE_DIR=/tmp/uv-cache uv pip install -p ~/.zcode/skills/re/tools-env/.venv/bin/python hbctool
# 拆:
hbc-disasm ext/assets/index.android.bundle hbc_out
# 产出 hbc_out/:
#   metadata.js         版本/函数数/flags
#   string_id_table.js  全部字符串(§1.4 的主战场)
#   instruction.hasm    全部函数的反汇编文本(按函数分段,可直接编辑)
# 改完后回编:
hbc-asm hbc_out patched.bundle
# 回填 apk → 重签(链路见 05-工具矩阵/工具检测与魔改.md 重打包节)
```

改法示例：在 `instruction.hasm` 里定位目标函数(先经 §1.4 字符串定位)，把 `StrictEqual` 改 `StrictNotEqual`、把 `LoadConstUInt8` 的立即数改掉、或整段函数开头插 `ReturnUndefined` 短路校验——改完 hbc-asm 校验长度变化是否越界(hasm 注释里有区间提示)。

### 1.3 hermes-dec(全版本兜底 + 近似源码)

```bash
uv tool install hermes-dec          # 只依赖 py3 标准库;pipx 同理
hbc-file-parser ext/assets/index.android.bundle            # 头结构体检
hbc-disassembler ext/assets/index.android.bundle out.hasm  # 反汇编(不带版本限制)
hbc-decompiler ext/assets/index.android.bundle out.js      # 伪代码(近似 JS,控制流不完整)
```

定位用 hbctool(字符串表好用)，读逻辑用 hermes-dec 的 decompiler——两者经常配合开。

### 1.3b hermit(94~96 反编译+结构化 patch,新)

```bash
# release 预编译(github.com/xV4L3x/hermit),macOS arm64:
tar -xzf hermit-0.1.0-macos-arm64.tar.gz
xattr -dr com.apple.quarantine hermit-0.1.0-macos-arm64   # 未签名,清一次 quarantine
hermit-0.1.0-macos-arm64/hermit ext/assets/index.android.bundle   # GDB 风格 REPL+全屏字节码编辑器
# CLI 工具包(hermit-tools): hbc_disasm / hbc_dump / hbc_strings / hbc_functions / hbc_patch / hbc_roundtrip / hbc_section_map
```

与 hbctool 的 hasm 文本改法不同,hermit 是**结构化 patch**:指令可增可删(自动重定位跳转/异常表/字表),改完可字节级 round-trip 校验;还带确定性(非 AI)反编译到可读 JS 和 CFG/DOT。94~96 之外的版本(98 = RN 0.84+ 默认 Hermes V1)仍不支持,退 hermes-dec。2026-10 入库,冒烟 0.1.0 通过。

### 1.4 逆向 Hermes 字符串表(定位业务函数的正道)

1. `string_id_table.js` 里 grep 业务关键词:`grep -n -i "login\|sign\|encrypt\|token\|vip" hbc_out/string_id_table.js` 拿到 **string id**；
2. `instruction.hasm` 里 grep 该 id(`LoadConstString  r0, 12345`)——所有引用这个字符串的函数即目标；
3. 从函数段头抄函数名(Hermes 函数名也在字符串表)，交叉确认；
4. 要动态验证：运行时 hook——RN 的 JS 执行在 libhermes，frida 侧没有 V8 那样的现成桥，直接静态读 hasm + 改回编更实用；动态跟协议仍走 §3 native 桥。

### 1.5 Hermes 运行时面(动态验证)

静态改不动/要验证函数确实被调用时，落点在 `libhermes.so`：

```bash
frida-trace -U -f com.target.app -i '*Evaluate*JavaScript*' -i '*hermes*parse*'
# 观察 JS 执行入口;需要看具体 JS 函数的调用,仍以 §1.4 静态定位 + §1.2 改回编最直接
```

RN 应用的 Java 壳(ReactInstanceManager/ReactHost)加载 bundle 的路径也可 hook(`com.facebook.hermes.reactexecutor.HermesExecutorImpl` 的 loadScript 系列)，onEnter dump 入参即"引擎吃进去的 bundle 原文"——**对 bundle 又做了一层运行时解密/拼接的变体，这是唯一拿全量原文的点**。

### 1.6 改完回填 APK(重打包流)

```bash
# 1) 换 bundle
cp patched.bundle ext/assets/index.android.bundle
cd ext && zip -r ../patched.apk . && cd ..
# 2) 对齐+签名(zipalign/apksigner 均在 Android SDK build-tools)
zipalign -p -f 4 patched.apk aligned.apk
apksigner sign --ks debug.keystore --out signed.apk aligned.apk
# 3) 装机验证
adb install -r signed.apk
```

重签名会破坏原包签名校验(有校验的游戏/壳需过签名校验:`../05-工具矩阵/工具检测与魔改.md` 重打包链与 V1/V2 签名绕过节)。

## 2. RN 未启用 Hermes(纯 JS bundle)

### 2.1 直读

```bash
head -c 300 ext/assets/index.android.bundle   # 见 __d(function...{...}) 即 metro 模块化明文 JS
```

按 metro 格式拆模块：`__d(function(require,module,exports){...},<id>,[依赖ids])`——写脚本按 `),` 顶层切分或直接用编辑器折叠读；业务代码可能被压缩混淆(短变量名)，但结构与字符串都在。

### 2.2 source map 还原(有 .map 时)

```bash
unzip -l app.apk | grep -i "\.map"           # index.android.bundle.map 极少随包,遇到即中彩票
npx reverse-sourcemap -v -o restored/ ext/assets/index.android.bundle.map
# 还原出原始 src/ 目录树 + 变量名,直接读 TypeScript/JSX 源码
```

无 map 时：混淆 JS 的去混淆按 `../../平台/01-Windows安全/语言篇.md` §2 的 js 混淆思路(synchrony 类工具)。

## 3. RN native 桥面(逻辑/加密在 Java 或 so 层时)

- jadx 搜 `ReactMethod`/`NativeModule`/`TurboModule`——RN 暴露给 JS 的原生方法全在这，加密/设备指纹常做成 native module；
- Java 层：frida `Java.use` 直接 hook(《02-frida/java层/加密与自吐.md》全家桶照用)；
- so 层：`../02-frida/native层hook速查.md` RegisterNatives 一套；
- 新架构(JSI/TurboModule)桥在 C++(libhermes 旁的 so),JS 层参数已经是 JSI 值，静态读 hasm + 动态 hook Java 终点是省力组合。

## 4. Flutter 完整逆向(不止抓包)

### 4.1 素材与版本

```bash
unzip -o ../app.apk "lib/arm64-v8a/*" "assets/flutter_assets/*" -d ext
strings ext/lib/arm64-v8a/libflutter.so | grep -o 'Dart_VM.*' | head -1   # 引擎/Dart 版本指纹
```

要点：**业务逻辑全在 `libapp.so`**(Dart AOT snapshot,纯数据块无导出)；`libflutter.so` 是引擎(网络栈 BoringSSL 在这)。arm64 为主流，模拟器包可能 x64——blutter 只吃 arm64。

### 4.2 blutter 工具链(符号还原主力)

```bash
git clone https://github.com/worawit/blutter && cd blutter
# 依赖: g++>=13 或 clang>=16, python3 + pyelftools + requests, cmake/ninja
# macOS: brew install cmake ninja pkg-config icu4c capstone && pip3 install pyelftools requests
python3 blutter.py path/to/ext/lib/arm64-v8a blutter_out
# 首跑会自动拉对应版本 Dart 源码编译(耗时;同版本缓存复用;升级后 --rebuild)
```

产出：`asm/`(带符号汇编)、`blutter_frida.js`(本 app 专用 hook 模板)、`objs.txt`/`pp.txt`(Object Pool 对象树——**类/方法/字符串字面量及其偏移**)。

### 4.3 dae(雷达已入库，纯静态免编译，查询式工作流)

```bash
brew install ejfkdev/tap/dae        # 单二进制,不跑目标、不需要 Dart SDK
dae info ext/lib/arm64-v8a/libapp.so                 # 快照/SDK 概览
dae strings ext/lib/arm64-v8a/libapp.so -f sign      # 字符串表搜业务词
dae findrefs ext/lib/arm64-v8a/libapp.so string sign # 谁引用了这个字面量
dae getmethod ext/lib/arm64-v8a/libapp.so 'ApiClient.makeSign'   # 单方法伪代码
dae functions ext/lib/arm64-v8a/libapp.so login      # 函数清单过滤
dae callers ext/lib/arm64-v8a/libapp.so <NAME|0xADDR>  # 调用链
dae export ext/lib/arm64-v8a/libapp.so dae_out --app --decompile   # 全量: --app 跳过 dart:/flutter 库
```

全量导出含：`ida_script/addNames.py` + `ida_dart_struct.h`(IDA: File→Script file)、`r2_script/addNames.r2`(`r2 -i r2_script/addNames.r2 libapp.so`)、`frida.js` hook 模板、`text/pp.txt|objs.txt|strings.txt`、`callgraph.dot`。
**选型：dae 先行(秒级)定位，blutter 兜底(dae 版本不认的新 Dart 用它，代价是现场编译)。**

### 4.4 frida hook Dart 函数实战

blutter/dae 的地址都是**文件偏移**，运行地址 = libapp 基址 + 偏移：

```js
// dart_hook.js —— hook 业务签名函数拿参数明文
const libapp = Process.findModuleByName("libapp.so");
const makeSign = libapp.base.add(0x2C3B40);   // 从 objs.txt/getmethod 抄偏移

Interceptor.attach(makeSign, {
    onEnter(args) {
        // Dart 调用约定: x0=参数1...; 字符串是 Dart String 对象,读偏移处的长度+数据
        // blutter_frida.js 模板已带 Dart 对象读取 helper,优先用模板的读法
        console.log("makeSign hit");
    },
    onLeave(retval) { console.log("ret", retval); }
});
```

```bash
frida -U -f com.target.app -l dart_hook.js --no-pause
# 或直接用产出模板: frida -U -f com.target.app -l blutter_out/blutter_frida.js
```

### 4.5 so 层加密参数定位实战流(端到端)

1. **抓包确认密文形态**(走 `../04-对抗攻防/抓包全场景.md` §2.7:Flutter 自带 BoringSSL,先过证书层《ssl-pinning绕过》§3.3)；
2. `dae strings … -f 加密字段名/sign`(从抓包 JSON 抄字段名反查)→ `dae findrefs` → `dae getmethod` 出伪代码，确认算法位置：
   - 算法在 **Dart 层** → §4.4 hook，参数即明文/密钥；脱机走 `../10-纯算法/协议脱机与RPC.md`;
   - 算法在 **native so**(自编 so 或第三方加密库)→ 回 Java/JNI/native 常规链(`../02-frida/native层hook速查.md`);
3. **BoringSSL 边界兜底**：hook `libflutter.so` 的 `ssl_write`(符号/偏移按引擎版本,§4.1 版本指纹定位)，拿到的永远是**加密前明文**——绕过一切业务层加密定位难题；
4. 证书校验绕不过时：免 frida 方案 **FlutterTap**(Zygisk,工具总表有行)或 **reFlutter**(重打包改引擎: `pip install reflutter && reflutter app.apk` → 装 `release.RE.apk`,流量直接打屏/落 dump.dart)。

## 5. 排错速查

| 症状 | 最可能原因 | 动作 |
|---|---|---|
| hbc-disasm 报版本不支持 | 版本不在 76/84/85/86/89/90 | hermes-dec 三件套(§1.3) |
| hbc-asm 回编失败 | 指令长度越界/操作数错 | hasm 段内等长替换;改常量不改结构 |
| blutter 编译 Dart 报错 | 本机编译器太老(g++<13) | 换 clang>=16;macOS `brew install llvm` |
| dae 不认识快照 | Dart 版本太新 | 回 blutter(现场编同版) |
| hook libapp 偏移无效 | so 是 x64 模拟器包/偏移是 VA 不是文件偏移 | 重下 arm64 包;基址+文件偏移口径 |
| Dart 参数读出乱码 | Dart String 对象结构没按 helper 读 | 用 blutter_frida.js 模板的读法 |
| Flutter 请求抓不到 | 走 BoringSSL+自解析 DNS | 《抓包全场景》§2.7 → 《ssl-pinning》§3.3 |

## 6. 语料检索词(data/ 精华索引)

「Flutter 逆向初探」「Flutter Android 逆向介绍」「某修仙肉鸽游戏协议逆向分析折腾记录」「UNI-APP渗透测试-抓包」(同族 hybrid 框架思路)「APP加密报文Burp明文抓包方案」。
