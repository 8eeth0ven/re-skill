# UE 与 Cocos 手游逆向

> 定位：**命令流教程**——UE(Unreal)与 Cocos2d-x/Creator 两族手游的解包、符号还原、脚本层解密全流程。
> 分工：Unity/IL2CPP 走《Unity与IL2CPP.md》；检测与封号边界走《框架检测与对抗.md》；lua 逆出来之后要干协议，接 `../10-纯算法/协议脱机与RPC.md`。
> 说明：本篇 lua 字节码逆向与堆利用(`../../平台/06-二进制漏洞/`)无关，方法论全部来自游戏逆向语料(检索词见 §7)。

## 0. 第一分钟：判定引擎

```bash
unzip -l app.apk | grep -i -E "\.pak|\.utoc|\.ucas|\.uexp|\.umap|libUE|libUnreal|libAnarchy"
unzip -l app.apk | grep -i -E "libcocos|\.jsc|\.luac|src/.*lua|libgame"
```

| 特征 | 引擎 | 走哪节 |
|---|---|---|
| `*.pak`(老)或 `*.pak + *.utoc + *.ucas`(IoStore,4.23+/UE5) + `libUE4.so`/`libUnreal.so` | **UE** | §1-§2 |
| `libcocos2djs.so` + `assets/*.jsc`/`src/*.jsc` | **Cocos2d-x JS(jsb)** | §3 |
| `libcocos2dlua.so`/`libgame.so` + `assets/src/*.lua` | **Cocos2d-x Lua** | §4 |
| `libcocos2djs.so` + `assets/assets/` + `config.yml`/`application.cfg`? | **Cocos Creator 打包** | §3+§5 |

UE 大包还常把 pak 放 obb 或首次启动下载到 `/sdcard/Android/data/<pkg>/files/…`,unzip 看不到时去设备上找：`adb shell find /sdcard/Android/data/<pkg> -name "*.pak" -o -name "*.utoc"`。

## 1. UE：解包链

### 1.1 pak 解包(repak 命令流)

```bash
cargo install repak            # 或直接下 release 二进制；brew 系机器 cargo 装
repak info Game.pak            # 看版本/是否加密/挂载点
repak list Game.pak | head -50 # 列内容(加密 pak 也能列,读文件才要 key)
repak unpack Game.pak          # 解到当前目录;加密 pak:
repak --aes-key 0x<64位hex> unpack Game.pak
repak get Game.pak Content/Scripts/main.lua > main.lua   # 抽单个文件
```

IoStore(`.utoc/.ucas`)不归 repak 管：FModel 直接打开(见 §1.3)，或用 ZenTools 类工具先转。

### 1.2 AES key 定位

pak 加密时 key(0x + 64 hex)烧在 so 里，两条路：

- **静态**：IDA 开 `libUE4.so` 搜函数 `FAES::DecryptData`(符号没裁时直接有)，交叉引用处传参的 32 字节缓冲即 key；
- **动态**：frida 在 pak mount 后扫 so 附近堆内存找 32 字节高熵块(经典做法：hook pak 挂载函数 onLeave dump key 结构；或全场扫 `?b?b?b` 高熵 pattern 人肉筛)。
- 拿不准先用 `repak info` 确认加密标志再花力气。

### 1.3 看资源：FModel / umodel

- **FModel**(GUI)：指定游戏目录与 AES key，浏览/导出贴图、模型、蓝图、配置；utoc/ucas 原生支持；
- **umodel**(UE Viewer，GUI)：导 mesh/texture/animation，也能把蓝图 dump 成文本(选 UnrealScript/Blueprint 模式)——**看策划配置、数值表、隐藏道具用它最快**。

### 1.4 蓝图与 UAsset

- 蓝图 = 可视化脚本，编译成 `*.uasset` 里的字节码；文本化靠 umodel/FModel 的蓝图视图，复杂逻辑仍要回 libUE4.so 逆向(§2)；
- 数值/配置大头通常是 DataTable(`*.uasset`/`.json`/`.csv` 混在 Content 里)，解包后直接读，**UE 游戏先翻资源再啃 so，经常根本不用逆 so**。

## 2. UE 逆向难点：反射系统与 GNames/GObjects dump

### 2.1 为什么 UE so 难啃

libUE4.so 几十 MB、符号全裁；但 UE 的 C++ 对象体系靠**反射**运行——所有 `UClass`/`UFunction` 的名字、字段偏移、函数指针都在运行时的 `GNames`(FNamePool，4.23+)与 `GObjects`(FUObjectArray)两张表里。**dump 出这两张表 = 恢复整个 SDK**。

### 2.2 定位 GNames/GObjects(Android 实操)

```js
// ue_scan.js —— 思路骨架，签名随 UE 版本变，先静态后动态
const m = Process.findModuleByName("libUE4.so");
// 1) GNames: FNamePool 首块第一个条目恒为 "None"；扫 so 数据段找指向 "None" 字符串的池结构
Memory.scan(m.base, m.size, "4e 6f 6e 65 00", {   // "None\0"
    onMatch(addr) { console.log("None entry @", addr.sub(m.base)); }
});
// 2) GObjects: FUObjectArray 的 Objects 指针数组成员恒指向 Chunk;
//    在 IDA 里找 GetNameByIndex/FName::ToString 的 xref 反推池基址更稳
```

静态路线：IDA 搜 `?FName::ToString@`/`FNamePool` 残留符号或字符串 `"/Script/CoreUObject"`(第一个路径 FName)做锚点，xref 反推两表基址。

### 2.3 UEDumper 思路(产 SDK 头)

桌面端 UEDumper 的流程在 Android 上照搬：**注入 → 找到 GNames/GObjects 基址 → 遍历 FUObjectArray 的每个 UClass → 沿 SuperClass 链吐出 C++ 头(类名/字段偏移/函数地址)**。Android 落地即 frida 版遍历器：

```js
// 骨架:拿到 GObjects 后
for (let i = 0; i < objCount; i++) {
    const obj = readObjPtr(GObjects, i);       // chunked 指针数组按版本分块
    const cls = obj.vtable_class;              // UClass
    emitHeader(cls.name, cls.super, cls.fields /* FProperty 链,含偏移*/);
}
```

产出 `SDK/*.h` 后：配 IDA 结构体批量导入，so 里任意 UObject 子类的成员访问全部可读；游戏逻辑函数地址从 UFunction 拿，frida 直接 hook。

### 2.4 lua 热更的 UE 游戏

UE + xLua/UnLua/slua 的手游，业务逻辑全在 lua(见语料「Unity il2cpp lua 手游」同思路)：解 pak(§1)→ lua 层多半再叠一层 luajit/加密 → 转 §4 的 Cocos lua 流程，**一模一样的工具链**；UE 引擎层只剩协议加密时再回 §2.3 的 SDK 定位。

## 3. Cocos2d-x JS(jsb)：jsc 解密

### 3.1 形态与加密原理

- `*.jsc` = JS 代码经 **XXTEA 加密**(cocos 构建期 `setXXTEAKey` 设的 key 烧在 so 里)，文件头为 sign(默认 `XXTEA` 明文 5 字节) + 密文；解开后多数是**明文 JS**(少数再套 SpiderMonkey 字节码,判头见 §3.4)；
- 另有 `game.json`/`project.json` 明文配置可先读，常泄漏目录结构与热更地址。

### 3.2 key 定位三路

```bash
# 路1(最快): 静态 strings 猜——key 是可读短串(8-32 字节),常在 libcocos2djs.so 的 rodata
strings -n 6 ext/lib/arm64-v8a/libcocos2djs.so | grep -E "^[0-9a-zA-Z_-]{8,32}$" > cand.txt
# 人肉/脚本逐个试解(§3.3 脚本化)

# 路2(准): so 没裁符号时直接定位 key 交叉引用
nm -D ext/lib/arm64-v8a/libcocos2djs.so | grep -i xxtea
# 有 xxtea_decrypt 导出 → IDA 看 xref,取 key 全局变量

# 路3(必中): 运行时 hook
```

```js
Interceptor.attach(Module.findExportByName("libcocos2djs.so", "xxtea_decrypt"), {
    onEnter(a) { console.log("key:", a[2].readCString? a[2].readUtf8String(), "keylen:", a[3].toInt32()); }
});
```

### 3.3 解密命令(拿到 key 后)

```bash
UV_CACHE_DIR=/tmp/uv-cache uv pip install -p ~/.zcode/skills/re/tools-env/.venv/bin/python xxtea-py
python - <<'EOF'
import xxtea, pathlib
KEY, SIGN = b"THEKEY_YOU_FOUND", b"XXTEA"      # 按实际改
for p in pathlib.Path("ext/assets").rglob("*.jsc"):
    d = p.read_bytes()
    if not d.startswith(SIGN): continue
    out = xxtea.decrypt(d[len(SIGN):], KEY)
    if out: p.with_suffix(".js").write_bytes(out); print("ok", p)
EOF
```

### 3.4 解出来不是明文 JS 的判别

`xxd out.js | head -1`：见 `78 56 78 56`? 或 SpiderMonkey 字节码魔数(`53 50 41 4D`? 以实际引擎版本为准)→ 旧 jsb 真字节码：退路为「运行时 hook JS 引擎执行前点拿源码」(spawn 后 hook `JSScript`/`EvaluateString` 类入口 dump 明文)；Cocos Creator 3.x 的 js 走 V8，基本不遇此形态。

## 4. Cocos2d-x Lua：luajit 字节码

### 4.1 判定

```bash
xxd ext/assets/src/main.lua | head -2
# 1b 4c 4a xx = LuaJIT 字节码(\x1bLJ);  普通明文 lua 直接读
```

外层常再套一层 xxtea(key 找法同 §3.2，so 换成 `libcocos2dlua.so`/`libgame.so`)，剥完才见 `1b 4c 4a`。

### 4.2 标准链：解密 → 字节码 → 反编译

```bash
# 1) 反汇编(需要同版本 luajit 宿主;luajit 官方仓库 make 即可)
luajit -bl main.lua > main.bl            # -bl = bytecode list,能读 opcode 就能人肉跟
# 2) 反编译到 lua 源码:luajit-decompiler v2 / ljd 之类,按字节码版本选
#    输入 .lua(字节码)出 .lua(源码);控制流还原不完美,复杂函数回 -bl 人肉读
```

反编译失败的两大原因：opcode 表被改(§4.3)、字节码是内存 dump 缺头(补 `1b 4c 4a` 头 + flags 字节)。

### 4.3 opcode 被改的变体(魔改 luajit)

游戏方重编 luajit 时打乱 `lj_bcdef.h` 的字节码序号——所有公开反编译器直接输出乱码。恢复思路(语料「Cocos2d-x与LuaJIT汇编的初步解密」一系)：

1. 自编译同版本 luajit，写一段**含全部 opcode 特征**的对照 lua(循环/闭包/字符串拼接/比较跳转…)；
2. 游戏内若能触发它的编译(热更上传/控制台)，dump 出目标引擎编出的字节码；没有入口就用游戏自带函数体反推；
3. 逐条比对两版字节码，建立「标准 opcode ↔ 魔改 opcode」映射表；
4. patch 反编译器的 opcode 表(或写转换器把魔改字节码刷回标准序)，再走 §4.2。
5. 偷懒路：不还原源码，直接 frida hook lua 虚拟机的执行入口/luaL_loadbuffer，运行时拿解密后 buffer + 跟 VM 解释循环。

## 5. Cocos Creator 加密资源

- Creator 的图片/图集加密常见 `.cpb` 等自造后缀：xxtea(同一把 key)或异或；key 定位同 §3.2，只是解密函数从 `xxtea_decrypt` 换成 so 里的资源加载函数(`Image::initWithString` 类)；
- 判别法：拿两张已知 PNG 对比密文头——前 N 字节恒定 = 固定异或/stream cipher 头；全熵 = xxtea；
- 配置类(`config.json`/`*.csv`)多数不加密，先翻。

## 6. 排错速查

| 症状 | 最可能原因 | 动作 |
|---|---|---|
| repak unpack 报 wrong key | AES key 不对/版本不配 | `repak info` 核加密标志;§1.2 动态路 |
| utoc/ucas 打不开 | IoStore 不归 repak | FModel/ZenTools |
| jsc 解出全空 | key 错(xxtea 解失败返回空) | §3.2 路 3 必中 |
| luajit 反编译全乱码 | opcode 被改 | §4.3 映射表 |
| UE 找不到 GNames | 版本差异(4.22 前用 TNameEntryArray) | 按引擎版本换结构;§2.2 静态锚点 |
| lua/js 全解开了但没协议逻辑 | 逻辑在引擎层 | UE 回 §2.3 SDK；Cocos 回 so 层 `../02-frida/native层hook速查.md` |

## 7. 语料检索词(data/ 精华索引)

「Cocos2d-x与LuaJIT汇编的初步解密」「cocos2dx lua 反编译」「cocos2d游戏的lua脚本解密」「新手向unity+xlua解密lua脚本」「Cocos for Lua 伪网游的破解」「cocos2d游戏图片资源解密」「unreal engine逆向学习之反射设计/FName/dump工具使用(一二三)」「某修仙肉鸽游戏协议逆向分析折腾记录」。
