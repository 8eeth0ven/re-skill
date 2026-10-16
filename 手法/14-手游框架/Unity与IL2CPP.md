# Unity 与 IL2CPP 手游逆向全流程

> 定位：**命令流教程**——拿到一个 Unity 手游 APK，从判定引擎形态到 dump 符号到 frida 实战，每步给可复制命令。
> 分工：本篇管 Unity 全流程；跨引擎的检测/封号边界见《框架检测与对抗.md》；抓包层走 `../04-对抗攻防/抓包全场景.md`；
> PC 侧(Windows 单机 GameAssembly.dll)概念同源，见 `../../平台/01-Windows安全/语言篇.md` §3；工具行索引在 `../05-工具矩阵/工具总表.md`(Il2CppDumper / Zygisk-Il2CppDumper / frida-il2cpp-bridge / ReShift 四行)。

## 0. 第一分钟：判定 APK 是不是 Unity、哪种形态

```bash
unzip -l app.apk | grep -i -E "libil2cpp|global-metadata|libmono|libunity|Assembly-CSharp|libarmo"
```

| 看到什么 | 形态 | 走哪节 |
|---|---|---|
| `lib/arm64-v8a/libil2cpp.so` + `assets/bin/Data/Managed/Metadata/global-metadata.dat` | **IL2CPP 主形态** | §1 全流程 |
| `lib/*/libmono.so` + `assets/bin/Data/Managed/Assembly-CSharp.dll` | **Mono 老形态** | §2 直接 dnSpy |
| 有 libil2cpp.so 但 global-metadata 头不对(§3.1 头校验失败) | **metadata 加密加固** | §3 变体处理 |
| 只有 libunity.so、以上全无 | Unity 但脚本层另藏(嵌入小引擎/热更框架) | 先解包 assets 看热更目录(§4.3) |

抽取素材(后文统一用这个目录)：

```bash
mkdir -p u3d && cd u3d
unzip -o ../app.apk "lib/arm64-v8a/*" "assets/bin/Data/Managed/*" -d ext
ls ext/lib/arm64-v8a/ | head    # 确认 libil2cpp.so / libunity.so
ls -la ext/assets/bin/Data/Managed/Metadata/   # 确认 global-metadata.dat
```

注意 32 位包(`lib/armeabi-v7a/`)流程完全相同，只是 IDA 选 arm 架构；split apk 用 `adb shell pm path <pkg>` 拉全部分身再解。

## 1. IL2CPP 主流程：Il2CppDumper 全链

### 1.1 原理一句话

IL2CPP 把 C# 编成 native 的 `libil2cpp.so`，但类名/方法名/字符串字面量/字段偏移全留在 `global-metadata.dat` 里——dumper 解析这对组合，把"无符号大 so"还原成"C# 语义可读"。

### 1.2 跑 dumper

```bash
# 任何平台: 装 .NET runtime 后
git clone https://github.com/Perfare/Il2CppDumper && cd Il2CppDumper
dotnet Il2CppDumper.dll \
  ../u3d/ext/lib/arm64-v8a/libil2cpp.so \
  ../u3d/ext/assets/bin/Data/Managed/Metadata/global-metadata.dat \
  ../u3d/dump_out
# Windows 下即 Il2CppDumper.exe <so> <metadata> <outdir>
```

交互问架构就答 arm64；问 metadata 版本号自动识别失败时按 §3.1 手工看版本。

### 1.3 产出物清单与用途

| 文件 | 用途 |
|---|---|
| `dump.cs` | 全部类/方法/字段 + 每个方法头注释 `// RVA: 0x… VA: 0x…`——**检索主战场** |
| `script.py` | IDA 挂符号脚本(§1.4) |
| `ghidra.py` | Ghidra 等价脚本 |
| `il2cpp.h` | 结构体头，IDA 里配合 struct 使用 |
| `stringliteral.json` | 全部字符串字面量与引用位置，搜业务文案/报错文案定位函数 |
| `script.json` | 机械可读版符号表(自写工具消费) |

### 1.4 IDA 挂脚本(地址修正要点)

```
1. IDA 打开 libil2cpp.so(File → Open，按 ELF 加载，等自动分析跑完或先 Stop)
2. 基址归零：Edit → Segments → Rebase program… → 填 0
   (dumper 的 RVA 按 so 基址 0 计算；新版 script.py 会自检并提示，老版必须手工)
3. File → Script file… → 选 dump_out/script.py，等输出区打印完成
4. 此后 dump.cs 里的 RVA/VA 直接 G 跳转；函数名 = C# 全名，按 ; 加备注
```

Ghidra 同理：CodeBrowser → Script Manager → Run `ghidra.py`，无需手工 rebase(Ghidra 默认 0 基址加载 ELF)。

frida 侧不依赖脚本注入，直接用 RVA：

```js
const base = Module.findBaseAddress("libil2cpp.so");
const TakeDamage = base.add(0x123456);   // dump.cs 里抄 RVA
Interceptor.attach(TakeDamage, { onEnter(a) { console.log("hit", a[0], a[1]); } });
```

### 1.5 frida-il2cpp-bridge 桥(hook C# 方法实战)

比裸偏移稳(不受加固/重排影响)，按 C# 名字直接 hook：

```bash
mkdir ui3d && cd ui3d && npm init -y && npm i frida-il2cpp-bridge
```

`hook.js`：

```js
import "frida-il2cpp-bridge";

Il2Cpp.perform(() => {
    const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;

    // 枚举找类:名字不确定时先 dump 类清单
    // for (const c of img.classes) console.log(c.name);

    const cls = img.class("PlayerController");
    const m = cls.method("TakeDamage");
    m.implementation = function (dmg) {
        const hp = this.field("currentHp").value;   // 读字段
        console.log(`TakeDamage(${dmg}) hp=${hp}`);
        return m.invoke(this, 0);                   // 原逻辑照跑但伤害改 0(免伤)
    };
});
```

```bash
frida -U -f com.target.game -l hook.js --no-pause
```

常用桥 API 速记：`Il2Cpp.domain.assemblies` 列程序集；`cls.field(name).value` 读写实例字段；`Il2Cpp.gc()`；`cls.method(name).overload("System.Int32")` 选重载；`Il2Cpp.applicationVersion`。手机端免 PC 方案见工具总表 ReShift 行(Zygisk + IL2CPP SQLite 检视器)。

## 2. Mono 形态：直接 dnSpy

```bash
ls ext/assets/bin/Data/Managed/ | head
# Assembly-CSharp.dll / Assembly-CSharp-firstpass.dll / UnityEngine.*.dll
```

把 `Assembly-CSharp*.dll` 拖进 dnSpy/ILSpy 直接读 C# 源码——**mono 形态没有 IL2CPP 的 dump 步骤**，本来就是 IL。

**dll 被加密的变体**(常见加固：磁盘上是密文，mono 加载前内存解密)：

1. 特征：dnSpy 打开报错/全是乱码节；文件头不是 `MZ` + `BSJB`；
2. 解法(内存 dump 法)：跑起来后从内存捞解密后的镜像——
   - frida 扫内存特征 `MZ` 头 + 偏移 0x?? 处 `BSJB`(.NET metadata 签名)，整段 dump 回 dll 再修头；
   - 或 hook `libmono.so` 的 `mono_image_open_from_data_with_name`，onEnter 把 buffer 落盘；
3. 修不全时按语料「手游之u3d之dll文件加密之手动修复」「U3D逆向-Mono另类解密」的补头流程走(data/ 精华索引可查)。

## 3. global-metadata 加密变体(加固游戏)

### 3.1 头校验：先看加没加密

```bash
xxd -l 16 ext/assets/bin/Data/Managed/Metadata/global-metadata.dat
# 明文头: af bb b1 fa <版本u32 LE> ...   magic = 0xFAB11BAF
```

| 现象 | 结论 |
|---|---|
| 首四字节 `af bb b1 fa` | 明文 metadata，Il2CppDumper 直接吃 |
| 魔数不对但后段像结构 | **只加密头部/前 N 字节**(最常见的廉价加固) |
| 整文件高熵无结构 | 整文件加密/自造格式 |
| 文件根本不在 assets | 运行时从网络/加密资源下发 |

版本号(offset 4, 小端 u32)粗对：27≈Unity 2019-2021，29≈2022，31≈Unity 6。dump 时工具按版本选结构偏移，报版本错就先核这里。

### 3.2 头部加密的静态还原

只加密头的：多数是**保留文件长度、仅异或/覆写前 0x?? 字节**。取一个已知明文头(`af bb b1 fa` + 版本)，与密文头逐字节异或看是否出现循环 key：

```python
hdr = open("global-metadata.dat","rb").read(0x40)
plain = bytes.fromhex("afbb1bfa") + (29).to_bytes(4,"little")
xor = bytes(a ^ b for a, b in zip(hdr, plain[:8]))
print(xor.hex())   # 单字节循环 = 直接整段还原；无规律 = 换运行时 dump
```

### 3.3 运行时 dump(加密重、时机是关键)

核心认知：**游戏自己必须解出明文 metadata 才能跑**——dump 点放在"解密完成、使用之前"：

- **首选 Zygisk-Il2CppDumper**(工具总表有行)：root+Zygisk 环境装模块，游戏起来即 dump，产物自动落在
  `/storage/emulated/0/Android/data/<包名>/files/`(dump.cs + script.py + metadata 明文)，后续走 §1.4/§1.5；
- **frida 手工扫**(无 Zygisk 时)：游戏进主界面后扫 `af bb b1 fa` + 合法版本的组合：

```js
// scan_meta.js —— 找到疑似明文 metadata 并按长度 dump
const found = [];
for (const r of Process.enumerateRanges("rw-")) {
    Memory.scanSync(r.base, r.size, "af bb b1 fa 1d 00 00 00").forEach(m => {   // 1d=29, 按实际版本改
        try { found.push([m.address, r.size]); } catch (e) {}
    });
}
found.forEach(([addr]) => {
    const len = addr.add(0x10).readU32? 0 : 0;   // sanitizedLength/s fileSize 字段按版本结构读
    console.log("candidate @", addr);
});
```

扫到候选后按该版本 `Il2CppGlobalMetadataHeader` 的 `sanitizedMetadataSize`/`stringLiteralOffset` 交叉验证长度合理性再整段落盘，回 §1.2 重新 dump。

### 3.4 libil2cpp 导出被裁(Il2CppApi 混淆)变体

特征：so 无 `il2cpp_domain_get` 等导出、frida-il2cpp-bridge 报初始化失败。思路：bridge 的初始化依赖导出表，被裁时改从 `JNI_OnLoad`/`il2cpp_init` 内部调用链定位 il2cpp 域对象；语料「解决Il2Cppapi混淆，通杀DumpUnityCs文件」给出了不依赖导出表的通杀 dump 思路(data/ 精华索引可查)。静态路线退回 §1.4 纯 RVA 分析。

## 4. 实战三枪(拿下之后先打哪)

### 4.1 第一枪：hook 游戏函数验证控制权

用 §1.5 的 bridge 脚本改一个"看得见"的效果(伤害归零/金币增加/跳跃无敌)，确认 hook 生效——这是后续一切的地基。对抗失败(闪退)先开 `../12-绕过决策/绕过决策手册.md` 定检测层。

### 4.2 第二枪：改数值(内存搜值，一笔带过)

- 模拟器路线：雷电/MuMu 等带 root 的安卓模拟器，PC 端 Cheat Engine 进程列表直接选模拟器 VM 进程(Ld9BoxHeadless/MuMuVmSeries 等)搜内存值→改写/锁定；
- 真机 root 路线：GameGuardian 或 CE 的 ceserver；
- 精确路线(免搜值)：§1.5 桥直接 `field.value = 999999`，字段名从 dump.cs 抄，比 CE 稳且不怕指针偏移。

### 4.3 第三枪：协议定位(il2cpp 层拿明文)

抓包拿到密文(流程在 `../04-对抗攻防/抓包全场景.md` §2.9)后，回 dump 层找加密点：

1. `dump.cs` / `stringliteral.json` 搜 `encrypt|sign|send|Packet|ProtoBuf|msgId` 等关键词收敛类；
2. bridge hook 收敛出的序列化/加密函数，onEnter 打印入参——多数游戏此层就是明文；
3. 拿到"明文→密文"函数对后，脱机/重放走 `../10-纯算法/协议脱机与RPC.md` 三级火箭。

## 5. 检测面(il2cpp 侧特有 + 通用)

| 检测 | 手段 | 对策入口 |
|---|---|---|
| metadata/so 完整性 hash | 启动时算 `global-metadata.dat`/`.text` 段哈希对账 | 别改文件，全内存改；原理见《框架检测与对抗.md》§1 |
| dump 检测 | 读 maps 找 frida/检测 `/proc` 状态 | `../04-对抗攻防/frida反检测对抗.md` |
| mono 注入检测 | 扫 IL 注入特征(老 mono 外挂遗留攻防) | 同上 |
| 游戏内风控(行为/输入流) | 服务端行为分析 | 《框架检测与对抗.md》§3 |

## 6. 排错速查

| 症状 | 最可能原因 | 动作 |
|---|---|---|
| Il2CppDumper 报 ERROR: Magic | metadata 加密 | §3 全节 |
| dump 成功但 IDA 跳转对不上 | 基址没归零/so 与 metadata 版本不配 | §1.4 步骤 2；重下正确 split apk |
| bridge 报 Il2Cpp not found | 导出被裁/加固壳 | §3.4；先脱壳 `../03-脱壳dump/` |
| hook 上没反应 | 函数没被调用(热更/lua 层实现) | 看 §4.3——逻辑可能在脚本层不在 C# |
| 改字段无效 | 值有服务端校验/被定时刷新 | 改在 setter 函数层；网游见《框架检测与对抗.md》§5 封号边界 |

## 7. 语料检索词(data/ 精华索引)

「安卓U3D逆向从Assembly-CSharp到il2cpp」「记录一款Unity il2cpp lua手游的逆向全过程」「记录一款Unity il2cpp 手游封包的逆向」「解决Il2Cppapi混淆」「Unity加固的探索与实现」「Unity Mono 安卓游戏逆向 Frida Hook」「某单机斗地主手机游戏的分析」「旅行的青蛙Unity游戏逆向修改」。
