# RASP 绕过

> 商业 RASP（Runtime Application Self-Protection）对抗全流程：识别 → 定位校验点 → 选择绕过层 → 验证自毁解除。

## 0. RASP 是什么、与普通反调试的差异

RASP = 把检测、响应、加密、完整性校验打包进 app 运行时的一种商业 SDK（Talsec freeRASP、DexProtector、DexGuard、Promon SHIELD、Arxan、Zimperium anti-tamper、国内厂商加固等）。它不是"一段反调试代码"，而是一套**联动系统**：

| 维度 | 普通反调试/root 检测 | 商业 RASP |
|------|------|------|
| 检测点数量 | 1～5 处，集中在一个 so/类 | 几十处，Java/native/内核信号三层联动 |
| 检测结果 | 弹窗/退出，单点失败即全局失败 | 检测→改密钥→静默数据破坏，**不告诉你它发现了** |
| 完整性校验 | 校验 manifest 签名 | 校验自身 so 指令字节、linker 状态、DEX 分区、assets |
| 自毁机制 | 无或 exit | 密钥推导被污染 → 解密出垃圾 → 看似正常运行但业务全坏 |
| 密钥绑定 | 无 | 密钥派生自 APK 签名 + 未保护 DEX + 配置 + **自身代码内容** |
| 上报 | 本地日志 | raw Binder / 专用上报通道，服务端拉黑设备 |
| 绕过后果 | 绕过即赢 | 绕过 A 点触发 B 点；漏一处校验 → 静默自毁难排查 |
核心认知差：**普通反调试绕的是"检测"，RASP 绕的是"密钥与信任链"**。DexProtector 把解密密钥的一部分派生自 linker 函数 `rtld_db_dlactivity` 的机器码——frida 一 hook 这个函数，密钥就错了，第二阶段永远解不出来，且进程不崩溃、不弹窗。这就是 RASP 级对抗的本质：你 patch 的每一处都可能是密钥输入。
因此 RASP 绕过的方法论是**先还原信任链再动手**，而不是见 hook 就拦。判断自己面对的是哪一档：

```
症状分流（先跑一遍再决定打法）：
A. 检测命中 → 弹窗/闪退          → 普通检测，拦 exit/改返回值即可（本文 §2.1/§2.4）
B. 检测命中 → app 还能跑但业务乱码/数据解不开 → 密钥级自毁，转 §2.3 密钥推导
C. attach 瞬间进程消失，无日志     → 早期 svc 检测+自杀，转 §2.2/§2.5
D. 一切正常但服务端拉黑           → 检测结果走上报通道，拦上报+伪造响应
```

## 1. 识别层：先确认对面是哪家 RASP

### 1.1 自动识别

- **APKiD**（rednaga）：`apkid apk.apk` 输出 packer/obfuscator/compiler 标签，覆盖多数商业加固与 DexProtector。
- **mobile-security-mcp**（npm `mobile-security-mcp`，Serhatcck）：MCP server，对 APK/IPA 做清单/权限/端点/硬编码密钥扫描。
 - 注意：该仓库现有工具为 `apk_manifest_analyzer` / `apk_permissions_checker` / `android_api_extractor` / `android_secrets_scanner` 等，**未包含** `rasp_identify` / `rasp_bypass` 工具，也未列出 Zimperium/DexGuard/Promon/Arxan 识别库。用前先起服务看实际工具表。
- **strings + so 名人工核对**：识别 RASP 最可靠的还是 so 文件名与字符串特征（下表）。

### 1.2 手动识别特征表（各家 RASP / 加固指纹）

| 厂商 | so / 文件特征 | 补充识别点 |
|------|------|------|
| DexProtector (Licel) | `libdexprotector.so`、`libdpboot.so`，解包后 payload 带 `DPLF` magic 或藏在最后一个 PT_LOAD；自定义 ELF 头（非标准 e_ident） | manifest 注入 `ProtectedXxx` Application 类；assets 里有 `classes.dex.dat`、`se.dat`、`resources.dat`、`dp.mp3` |
| DexGuard (Guardsquare) | 纯 Java/Kotlin 混淆+加密，无专属 so；字符串加密类名随机、`javax.crypto` 密钥运行时拼 | 配合 Guardsquare 商业混淆器，DEX 层熵值极高 |
| Arxan (Guardsquare/Verimatrix) | native 代码虚拟化 + 自修改代码；so 内大量不透明谓词、控制流扁平化 | 函数体哈希自校验遍布全 so |
| Promon SHIELD | `libpns.so` / `libpnx.so` 系列 | 北欧系银行/金融常见 |
| Zimperium (z9 anti-tamper) | `libziks.so`、`libziFunctions.so` 等 z 前缀 | 与 MTD（移动威胁防御）企业部署绑定，检测上报走服务端 |
| Talsec freeRASP | Flutter/RN 集成，Android 侧 native 库 + `talsec.app/freerasp/events` 上报域 | 回调 `onRootDetected` / `onHookDetected` |
| GarudaDefender | 用户材料：核心检测在 `libkikypspro.so`，业务壳 `libcrackme.so` 提供自定义 dlsym 跳板 | dlsym 被 so 内跳板封装时，`Module.findExportByName` 会失灵，需从跳板表手动解析真实地址 |
| 国内大厂 RASP 样本 | `libmsaoaidsec.so`（某瓣等：frida 检测，CSDN 2026-04 有分析帖佐证）、爱加密/梆梆/360/腾讯乐固/网易易盾各自 so | 详见《检测原理全景.md》§2 |
识别产物要落清单：so 名 + Application 类 + 上报域名 + 检测函数数量级——决定后面选哪层打。

## 2. 绕过方法论分层（按对抗层级从低到高）

五层不是并列选项，是**递进尝试顺序**：先试高层（改动小、副作用小），自毁未解除再下沉。

### 2.1 ① patch 校验点：让完整性校验恒等（GarudaDefender 案例）

适用：校验逻辑集中在"算 hash → 与寄存器/内存中的期望值 CMP → 不等则走告警分支"的结构。
**链路还原方法论（从弹窗倒着挖，通用套路）**：
1. Java 层看到告警入口是 native 方法（如 `SystemAlert.onCreate` 声明为 native）→ 说明真实实现不在 dex；
2. 该方法经 so 的 JNI 注册表/跳板落到真实业务 so（用户材料：`libkikypspro.so+0x37A754`）；
3. 顺 RegisterNatives / 自定义 dlsym 跳板找到实现函数，decompile 看**谁调它**：弹窗是 UI 结果，往上找调度层（用户材料：`sub_68BD10` 调度 → `sub_64B840` 构造并显示 AlertDialog）；
4. 再往上找**为什么调度它**——检测函数返回异常值 / hash 校验失败（用户材料：`sub_AB31A0` 内 `0xAB3C7C: BL hash_crc` 算出实际值放 X0，`0xAB3C80: CMP X23, X0`，X23 是启动时存下的期望值）；
5. 结论：校验层在 `sub_AB31A0`，弹窗链只是下游。**patch 校验层，不动弹窗层**（动弹窗层会留下更多被二次校验的面）。
IDA 里的具体操作（对应上面 5 步）：

```
1. jadx 搜 SystemAlert / onCreate → native 方法名抄下
2. IDA 打开业务 so，搜字符串/导出表定位 JNI 实现；找不到 → 看 Java_前缀符号被去哪了
   （自定义 dlsym 跳板 = 字符串表 + 函数指针数组，直接搜方法名字符串，交叉引用到跳板项）
3. 对实现函数按 X 看交叉引用 → 上层调度（谁在什么条件下调它）
4. 调度层再往上 = 判定函数；判定函数里找「算值 BL → CMP → B.NE 告警分支」三连
5. patch 点选 CMP 处（不是 B.NE 处）——改 CMP 影响所有下游分支，改 B.NE 漏掉 else 路径
```

**绕过操作（同一目标两种思路）**：
- **IDA 静态 patch**：把 `CMP X23, X0`（及后续 B.NE）改成 `MOV X23, X0` 后接无条件走相等分支，或直接 NOP 掉 B.NE。注意重打包后 APK 签名变了，若 RASP 还校验 APK 签名需配合 §2.2 喂原包。
- **frida 动态 patch**：在 `BL hash_crc` 返回处 hook，把上下文 X23 改成 X0，使 CMP 恒等：

```js
const base = Module.findBaseAddress("libkikypspro.so");
Interceptor.attach(base.add(0xAB3C80), {          // CMP X23, X0 处(用户材料偏移)
    onEnter() { this.context.x23 = this.context.x0; }
});
```

动态法不改文件、不触发签名变化；但对做函数头 CRC 自检的 RASP，attach 本身会踩 prologue 扫描（见《检测原理全景.md》§7.2）——先确认目标函数头没被校验，或改用 Stalker。
**检测函数统一返回值**：该案例中 14 个环境检测函数（root/frida/调试/模拟器等）的返回值统一被替换为 `0x64`（"环境正常"状态码）——比逐个 hook 更稳的打法是找它们的**公共返回路径**（调度器里收状态码的那个寄存器/参数），一处改值全链路生效：

```js
// 思路示意：在调度器入口改状态码参数，而不是 hook 14 个函数
Interceptor.attach(base.add(调度器偏移), {
    onEnter(args) { /* 找到承载"环境状态"的参数/寄存器，统一置 0x64 */ }
});
```

### 2.2 ② syscall 层伪造：给 RASP 喂假文件（freeRASP 案例）

适用：RASP 在 native 层直接读自身 APK / 关键文件做完整性校验，Java 层 hook `getPackageInfo` 无效时。
思路（用户材料描述的绕法，机制层面成立）：拦截 `openat` / `read` / `fstat` 三个 syscall（libc 函数或 svc 层），当 RASP 打开 `base.apk` 时：
- `openat`：把 fd 重定向到**预存的原版 APK**（重打包前先留一份）；
- `fstat`：伪造 size/mtime 与原包一致；
- `read`/`pread`：从原包 fd 读，返回缓冲区内容即原包字节。
这样 RASP 读到的 APK 永远是"未篡改"的，hash/签名校验自然通过。freeRASP 侧的对抗强度：Talsec 官方文章承认 frida 检测是攻防核心，社区已有公开脚本（见 §3.2）；syscall 级细节以官方讨论与实际目标为准。
frida 实现骨架：

```js
const origApk = "/data/local/tmp/original.apk";   // 预存原包
let fakeFd = -1;
Interceptor.attach(Module.getExportByName("libc.so", "openat"), {
    onEnter(args) {
        const p = args[1].readCString();
        if (p && p.endsWith("base.apk")) {
            fakeFd = -1;
            const fd = new File(origApk, "rb");    // 记住重定向关系(按原 fd 映射)
            // 实战用 fs.open 保持 fd 表；此处示意
        }
    }
});
// read/pread: 按映射表从原包读; fstat: 返回原包 size/ino/mtime
```

实现注意：
- 若 RASP 用 svc 内联 openat（见《检测原理全景.md》§2.9），libc hook 失效 → 改用 frida Stalker 在 svc 指令处改寄存器，或内核态拦截（§2.5、07-内核级）。
- 假文件要全套：`/proc/self/maps` 里 base.apk 的映射区间、`fstat` 的 inode/size 都要对得上，高级 RASP 会交叉核验。
- 该思路同样适用于喂 `/proc/self/status`（TracerPid 归零）、`/proc/net/tcp`（抹 27042）、`/proc/mounts`（抹 magisk）——一套重定向框架打包所有检测文件。

### 2.3 ③ 密钥推导：不执行 app 也能解密（DexProtector 案例）

适用：商业加固把"防分析"做进密钥本身——你一 hook，密钥就错，app 静默变砖。此时不该继续绕检测，而是**离线推导密钥直接解数据**。
DexProtector 完整信任链：
1. 启动链：manifest 注入的 `ProtectedLiveNetTV` Application → 加载 `libdpboot.so` → JNI 加载 `libdexprotector.so`（自定义 ELF loader）→ 解密并映射 payload（`DPLF` magic 或最后 PT_LOAD 段），执行从 `DT_FINI_ARRAY` 起，用完的动态表区域清零（反 dump）。
2. **密钥与代码绑定**：payload 的 32 字节解密密钥 = 库内静态盐 + **linker 函数 `rtld_db_dlactivity` 的运行时机器码**。该函数正常是空的（只有 `ret`）；frida-server hook 它时会注入 trampoline——**密钥直接被腐蚀**，第二阶段永远执行不到。这是"密钥级反动态分析"的教科书实现。
3. master key（在解出的 `libdp.so` 里生成）绑定：APK 签名 + 未保护 DEX 文件 + DexProtector 配置 + **自身代码内容**——hook libdp.so 任何函数都可能改坏它。
4. 自毁机制：篡改的最终表现就是 master key 无效 → 类解密/asset 解密全坏。威胁在启动早期发现时直接腐蚀密钥或终止进程；否则记录后延迟反应。类加密还配反 dump（unmap 未用 DEX 区域，全量 dump 触发 SEGV_MAPERR）；字符串解密绑定 native 函数自身地址（对抗 RegisterNative 替换）；RASP 检测走 raw Binder 绕过 PackageManager。
5. 破法（对 10 个金融类 app 验证）：
 - 开发"不触发腐蚀机制"的插桩方式 hook `libdp.so`，**离线（不跑 app）算出合法 master key**；
 - master key 派生子密钥解开 `classes.dex.dat` / `se.dat` / `resources.dat` / `dp.mp3`；
 - 用自写 Redex pass（StringEncryption / RecoverHiddenAccess）把 `ProtectedX.s` 字符串调用与 `LibX.i` native 调用还原成干净 DEX；
 - 核心批评：方案是通用后构建产物，破一个 = 破所有。
方法论提炼：**遇到"绕过检测后 app 装正常但业务乱码/崩溃"，立刻怀疑密钥被密钥级检测污染**。对策：停止对抗运行时，转静态/离线——dump 加密产物 + 恢复密钥派生算法 + 离线解密。评估收益：这类方案是通用后构建加密，**一次推导的算法可复用到同版本所有 app**（Romain Thomas 演示了 10 个）。

### 2.4 ④ 检测函数统一返回值：Java 层收口（React Native 金融 App 案例）

适用：RASP 检测结果汇到少数几个 Java 方法/常量表，且检测只在启动跑一次（一过全过）。
SecureNexus 案例——三层防护、约 90 行 frida 脚本全绕：
- **静态侧（密钥恢复）**：Hermes 字节码 `assets/index.android.bundle` 反汇编还原 JS 逻辑 → 模块 632（crypto helper）里发现**硬编码 64 位 hex 字符串 = AES-256-CBC 密钥**，每台设备相同；模块 624（axios 拦截器）给出线上格式：前 32 hex = 随机 IV、其余 = 密文、包成 `{"payload":"<hex>"}`。用 pycryptodome 写镜像加解密，拿真实流量验证（登录表单里的账号从密文里干净解出）。
- **RASP 侧三组 hook**（全部在 `Java.perform` 内）：
 1. 自研检测类 `com.target.utils.RootDetector` 的六个静态方法 `a`–`f`（覆盖 frida 端口 27042/27015 扫描、frida-server 落盘、su 路径、test-keys、XposedBridge 类加载、magisk/busybox）→ `.implementation` 一律返回 `false`；
 2. RootBeer native：`com.scottyab.rootbeer.RootBeerNative.checkForRoot` 返回 `0`（中和 `libtoolChecker.so` 的 JNI 检查）；
 3. JailMonkey（RN 官方生态）：两个底层方法强制 `false` 之外，再**重写 `JailMonkeyModule.getConstants`**——先调原实现，把 `isJailBroken` / `hookDetected` / `canMockLocation` / `AdbEnabled` 全改成 `Boolean.valueOf(false)` 再返回。关键认知：**RN 的 JS 层从 constants map 读检测结果，在源头投毒比逐个 hook 更彻底**。
- **pinning 侧**：不碰 `CertificatePinner` / TrustManager，而是 hook **TLS 之上**的 RN bridge：`NetworkingModule.sendRequest`（请求前拿 method/URL/body）+ `ResponseUtil.onDataReceived`（响应后拿明文）。pinning 在 OkHttp 层照常校验真实服务器证书，读的高一层根本不经过对抗面。
- 该 app 的结构性弱点：检测**只在启动跑一次**、命中即 `System.exit(0)`（拦掉 exit 就行）、无模拟器检测。
方法论提炼：跨框架 app（RN/Flutter）的 RASP 判定终态常是一个**常量表/单一回调**，收口在那里 = 一处绕全链；外加"hook 点选在框架层而非对抗层"的分层思路。

### 2.5 ⑤ OS 级插桩：从进程外打（ANDROID-MRI）

适用：RASP 对进程内一切插桩（frida/xposed/自实现 hook）都有检测或密钥污染，用户态无解。
ANDROID-MRI：
- 把 trace 直接埋进 **Android 内核/OS 层**，追踪 runtime、ROM loader、root 接口——不向 app 进程注入任何代码，app 层的反篡改/root 检测/frida 检测**看不到它**；
- 50 个 ≥100 万安装的热门 app 实测：**绕过 97.6% 的 RASP 防护，frida 仅 52.4%**；顺带发现 17 个未公开敏感数据驻留内存问题；
- 定位是研究工具（生产 ROM 上以厂商签名部署），对授权测试的启示是：**用户态 RASP 的天花板在进程内，OS 级观测天然在检测面之外**——这从数字上解释了为什么重度加固目标最后都要下沉到内核。
实操衔接：授权环境下等价路径 = 内核态拦截（KernelSU + KPM hook sys_openat 等）或定制 ROM/emulator 层插桩，细节见 `07-内核级/跨平台内核速查.md`。frida 侧降级方案 = Stalker（不改原指令，躲 prologue CRC）+ 去特征编译（《frida反检测对抗.md》）。

## 3. Case 速查表

| Case | RASP/加固 | 绕过层 | 核心动作 |
|------|------|------|------|
| GarudaDefender crackme | libkikypspro.so（+libcrackme.so dlsym 跳板） | ①patch 校验点 | X23=X0 恒等 + 14 检测函数统一 0x64 |
| freeRASP (Talsec) | Flutter/RN 集成 | ②syscall 伪造 + ④返回值 | openat/read/fstat 喂原包；CodeShare 公开脚本拦 File/Runtime.exec/isDebuggerConnected/System.exit/killProcess + 断 events 上报 |
| DexProtector | libdpboot.so/libdexprotector.so | ③密钥推导 | 离线恢复 master key + Redex 还原 DEX；反制 rtld_db_dlactivity 密钥绑定 |
| React Native 金融 App | RootDetector+RootBeer+JailMonkey | ④返回值收口 | 六方法 false + checkForRoot=0 + getConstants 投毒；AES 密钥 Hermes bundle 里直接读；hook RN bridge 绕 pinning |
| ANDROID-MRI | 50 热门 app 的各家 RASP | ⑤OS 级 | 内核埋 trace，进程外观测，97.6% 绕过率 |

## 4. RASP 绕过通用 checklist

```
[ ] 1. 识别：APKiD + so 名/特征表 → 落清单（so、Application 类、上报域、检测面数量级）
[ ] 2. 粗探：不绕任何东西先跑一遍——记录哪些功能坏（区分"被拦"vs"静默自毁"）
       装正常但业务乱码/崩溃 = 密钥被污染 → 直接走第 6 步（密钥推导）
[ ] 3. 定位校验点：从可见症状（弹窗/退出/乱码）回溯——
       Java 告警方法 native 化 → JNI 注册表/跳板 → 调度层 → hash/CMP 校验层
       记下：校验输入（谁算实际值）vs 校验期望（X23/常量）——patch 期望侧
       IDA 三连搜法：算值 BL → CMP → B.NE；patch CMP 不 patch B.NE
[ ] 4. 选层（由低到高，改完即验，别一次全上）：
       Java 收口（一个常量表/回调管全部？）→ 检测函数统一返回值
       → libc hook（文件/环境喂假数据，openat/read/fstat 全套一致）
       → 静态 patch so（X23=X0 恒等法；注意重打包触发签名校验，配喂原包）
       → svc/Stalker（检测走 svc 时）
       → OS 级（用户态全灭时，07-内核级）
[ ] 5. 对抗二次检测：
       prologue CRC（函数头字节扫描，不限 PLT）→ 用 Stalker 或先还原再调用
       自定义 dlsym 跳板 → findExportByName 失灵，手动解析跳板表
       raw Binder 检测 → hook libbinder 事务或内核侧
       rtld_db_dlactivity 密钥绑定 → 别 hook linker，走离线推导
[ ] 6. 验证自毁解除：
       a. 检测点全绿后跑完整业务流（登录→交易→文件读写），不是只看首页
       b. 重启 app 再跑（一次性检测 vs 周期检测）
       c. dump DEX/内存确认解密产物有效（DexProtector 类加密时 dump 会 SEGV
          = unmap 反 dump 生效 = 你还在它的检测面里）
       d. 抓包确认数据明文可读（AES 密钥若硬编码在 bundle，直接离线解）
[ ] 7. 落盘：RASP 指纹 + 绕过层 + 踩坑记录进本 wiki，供回扫复用
```

### 4.1 常见失败模式与排查

| 症状 | 最可能原因 | 排查 |
|------|------|------|
| 绕过点全绿但 app 白屏/乱码 | 密钥级自毁已触发（§2.3） | 停止运行时对抗，转离线密钥推导 |
| frida 一 attach 进程就没了 | 早期 svc 检测 + 立即自杀 | spawn+挂起模式进，先 patch 早期 init；或 §2.5 |
| patch 后重打包闪退 | APK 签名校验（另一层完整性） | §2.2 喂原包，或改动态 patch 不落盘 |
| hook 生效几秒后被发现 | 周期性 prologue CRC 重扫 | Stalker 替代 Interceptor；或 patch 扫描函数本体 |
| `findExportByName` 返回 null | 自定义 dlsym 跳板/符号剥离 | IDA 里搜方法名字符串，跳板表手动解析真实地址 |
| 绕过后服务端拉黑 | 检测结果走上报通道 | 拦上报域（freeRASP 是 talsec.app/freerasp/events）+ 伪造成功响应 |

## 关联

- 《检测原理全景.md》§2/§7/§6、《frida反检测对抗.md》、《root与环境隐藏.md》、`07-内核级/跨平台内核速查.md`
