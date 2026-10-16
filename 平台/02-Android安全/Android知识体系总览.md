# Android安全 知识体系总览(树节点 1000943,252 节点,23 个二级)

> 分工原则:**frida/hook/脱壳/加固对抗/抓包/风控/内核**已被本机 `~/.zcode/skills/re/手法/`(12 区 63 篇)深度覆盖,本区只做 3-5 行摘要+互链,不重复展开;**编程开发/编译器/文件格式/系统体系/病毒木马/CTF** 是 手法库 未覆盖的空白,在本区深挖成篇。

## 1. 编程开发 [1000953] — 手法库 空白,本区简述

一句话:Android 正向开发能力是逆向的地基——看不懂怎么写就看不懂怎么破。

主要节点:NDK开发[1001273] / 安全开发[1001361] / 磁盘加密[1001623] / 沙盒[1001645] / 其他[1001343]。

- **NDK/JNI 开发**:JNI 函数注册两路(静态 `Java_包名_方法名` 命名约定 / 动态 `RegisterNatives`,后者是逆向定位 JNI 实现的核心面,详见 手法库 `02-frida/native层hook速查.md` 1.x RegisterNatives hook);`CMakeLists.txt` + `externalNativeBuild` 是现代构建入口。逆向价值:**能写才能补**——unidbg 补环境、frida 主动调用、so patch 都要求 NDK 级 C++ 能力。
- **系统签名体系**(树中散在"安全开发"):platform 签名(sharedUserId="android.uid.system")、签名 V1(JAR)/V2(APK Signing Block,整包校验)/V3(密钥轮换)/V3.1/V4(fs-verity 增量);`apksigner verify --print-certs` 验证;重打包后签名变化是「签名校验」反破解的根——绕法见 手法库 `02-frida/java层/存储与系统.md` §9.2 hook_pkms 伪造签名。
- **AOSP 编译**:`repo init/sync` → `lunch` 选 target → `make -j`;产出 system.img/boot.img/vendor.img;GKI 内核单独编(`build/build.sh`),boot.img 结构与提符号实操见 手法库 `07-内核级/Android内核与eBPF.md`。
- 工具:Android NDK/JDK17+/CMake/Android Studio;代表帖:《NDK编译.so动态库》、《Android下NDK开发-文件权限和用户篇》、《VS+VA搭建顺手的NDK集成开发环境》、《简单快捷的JNI接口函数混淆》、《JNI_OnLoad与init_array下断方法整理》。

## 2. Hook框架 [1000954] — 手法库 全覆盖,互链

主要节点:Hook类型[1001308](Dalvik Hook/Art Hook/SO Hook:GOT/Inline/LD_PRELOAD) / Hook注入框架[1001309](Frida[1001312]/Xposed[1001318]/Unidbg[1001702]) / 动态注入[1001310](so 注入/DEX 注入) / Anti Hook[1001360]。

3 行摘要:Hook 按「层」分三族——Java/ArtMethod 层(Xposed/LSPosed yahfa/sandhook、frida ART hook)、native SO 层(GOT 改表/inline trampoline/LD_PRELOAD)、注入族(ptrace/zygisk/DEX 注入)。原理差异与选型矩阵 手法库 `05-工具矩阵/动态与hook框架.md`(307 行)一篇讲全:frida 生态 vs Xposed 系、native inline hook 三家对比(Dobby/ShadowHook/Renef)、Android 版本×框架兼容矩阵。frida 脚本实战(java 层 6 篇分域速查/native 层 753 行速查)、GOT hook 两条完整实现(纯 JS 解析 ELF + linker soinfo,`02-frida/高级/gothook.md`)在 手法库 `02-frida/`(java层/native/高级 三层 16 篇)。**详见 手法库(同 skill re/手法),本区不重复。**

## 3. 漏洞分析 [1000956] — 内核面互链,应用面本区一句话

主要节点:linux底层[1001335] / Android底层[1001336] / 硬件驱动漏洞[1001337] / 漏洞扫描[1001340] / 相关工具[1001552]。

- 内核/底层漏洞(binder/futex/io_uring/页缓存家族)手法库 `07-内核级/内核利用与Fuzzing.md` 已带官方 CVE 链接深挖;应用层提权代表作 CVE-2024-0044(RunAnyApp UAF 越权拿任意应用私有数据)。
- 本区补充视角:Android 漏洞利用链的经典形态是「通用内核 LLE + 提权 + 持久化」,app 域被 seccomp 封 io_uring 后攻击面收窄的判断依据,见 [编译器与系统体系.md](编译器与系统体系.md) §5。

## 4. 病毒木马 [1000957] — 手法库 空白,本区深挖

主要节点:病毒分析[1001653] / 木马分析[1001654] / 恶意软件[1001655]。

一句话:Android 恶意样本三大变现流派(费流量/扣费/间谍)+ Discord Stealer/虚假交友/诈骗 APP 实战分析,全链(家族特征→分析流程→IOC 提取)在本区 [恶意样本与CTF.md](恶意样本与CTF.md) §1-3 展开。

## 5. 工具脚本 [1000958] — 手法库 全覆盖,互链

主要节点:反编译[1001292] / 调试器[1001293] / AXML解析[1001295] / 重打包工具[1001359] / 分析系统(TaintDroid[1001642]) / Wallbreaker[1001663]。

3 行摘要:反编译器横评(jadx/IDA/Ghidra/JEB/CFR/Vineflower+版本坑)、APKiD 加固识别、DexKit 查询、Androguard 脚本化,手法库 `05-工具矩阵/静态分析工具.md`(270 行)+ `专项与信息收集.md`(接手陌生 APK 第一分钟)全覆盖,100+ 工具总表在 `工具总表.md`。树中历史工具(Andbug/eclipse/Wallbreaker)已被 jadx+frida 生态取代,仅在考古时看。**详见 手法库(同 skill re/手法)。**

## 6. CTF [1001296] — 手法库 仅索引,本区深挖

一句话:Android CTF 题型五族(Java 层逻辑/so 逆向/VMP/反调试反注入/组合壳)与解题流水线,含 KCTF、腾讯游戏安全竞赛安卓方向的套路总结,在本区 [恶意样本与CTF.md](恶意样本与CTF.md) §4 展开。

## 7. 编译器 [1001297] — 手法库 仅链路,本区深挖

主要节点:Smail/Baksmail[1001598] / 编译[1001612](ollvm框架编译[1001751]/前端编译器[1001752]) / 反编译[1001636](ApkTool[1001596]/JEB[1001597]/技巧经验[1001635]) / 简介[1001750]。

一句话:从 javac→dx/d8→dex2oat→JIT/nterp 的整条编译执行链,加上 OLLVM 系混淆编译器的原理,在本区 [编译器与系统体系.md](编译器与系统体系.md) §1-2 展开(手法库 11 区只讲了「加载与执行」时序,编译器本体是空白)。

## 8. 安全应用/二次开发/安全开发/MDM管理 — 树中小类,合并一句话

- **安全应用 [1001330]**:把逆向能力用于防护产品(应用加固 SDK、杀毒引擎)的开发类文章合集,方法论与「混淆加固」镜像对称。
- **二次开发 [1001558]**:对既有 APK 加功能/改行为(对应 Windows 区的二次开发篇),核心技能是重打包+签名+对抗完整性校验。
- **安全开发 [1001631]** 与编程开发的安全开发子类重叠:写安全工具(frida 脚本分发、检测引擎)的工程化。
- **MDM管理 [1001673]**:企业移动设备管理(DeviceAdmin/DeviceOwner),攻防视角=预装管控面,逆向时见到 DeviceAdminReceiver 要警惕卸载保护。

## 9. 系统相关 [1001344] — 部分互链,核心本区深挖

主要节点:Android ROM[1001345] / 系统内核[1001346] / root权限[1001401] / Android运行系统[1001602](Dalvik[1001603]+指令集[1001299]/ART[1001604]) / Android源码学习[1001615] / SEAndroid[1001626] / Magisk[1001754] / 定制系统[1001771] / 数据结构[1001664]。

分工说明:内核攻击面/ftrace hook/Magisk+Shamiko root 隐藏已互链 手法库(07-内核级五篇 + 04-对抗攻防/root与环境隐藏.md);**SEAndroid 策略体系、seccomp 过滤、binder 驱动协议、Dalvik→ART 演进**在本区 [编译器与系统体系.md](编译器与系统体系.md) §3-6 深挖——这四块是知识库树原生内容且 手法库 只散点提及。

## 10. 调试逆向 [1001529] — 手法库 全覆盖,互链

主要节点:调试分析[1001528](静态逆向/动态调试/profiler/IDA Pro[1001547]:动态调试DEX/SO/脚本插件/花指令[1001772]/Android Studio/JEB/Unicorn/radare2) / 反跟踪[1001554](Anti-Debug:阻止附加/多进程保护/Hook检测/Root检测) / 完整性校验[1001610] / SSL劫持[1001385] / 游戏分析[1001630](Unity 3D/Cocos 2D/Cry Engine 3) / Unidbg[1001755]。

3 行摘要:IDA 动态调试 so(远程 android_server/debugserver)、JEB 调 dex、反调试全家族(TracerPid/ptrace 自附加/多进程互护/svc 内联检测)到 syscall 层的原理,手法库 `04-对抗攻防/检测原理全景.md`(310 行)一篇定层,RASP 级商业对抗在 `RASP绕过.md`。游戏引擎(Unity il2cpp dump/Cocos luajit)入口在 手法库 `05-工具矩阵`。**详见 手法库(同 skill re/手法)。**

## 11. 逆向分析 [1001530] — 本区简述(基础层)

主要节点:虚函数[1001613] / smali语法[1001656] / 基础知识[1001747] / ARM基础[1001766](ARM汇编语言[1001284]/Thumb[1001605]/AArch64[1001606]/SVC指令[1001768])。

- **smali**:dalvik 字节码的人类可读形态,`.smali` 寄存器 v0-vN(非参数寄存器+参数寄存器)、invoke-{virtual/static/direct/interface/range} 五族、字段 sget/sput 族;现代工作流里「通读 smali」已降级为「jadx 看 Java + 关键方法回看 smali 验证」——但**改 smali 重编译**(apktool b)仍是 patch APK 的主力路。
- **ARM 基础**:AArch64(A64)与 Thumb2(A32/T32)双指令集;逆向要点:BL/BLR 调用约定 x0-x7 传参、x29 FP/x30 LR/SP;SVC #0 进系统调用(x8 syscall 号,x0-x5 参数)——hook 降级时抓 svc 的完整约定表在 手法库 `09-函数全景/hook降级实战.md`(387 行,含 arm64 syscall 号速查)。

## 12. 混淆加固 [1001532] — 手法库 全覆盖,互链

主要节点:混淆&反混淆[1001589](源码/模板/AST/IR/DEX 混淆+反混淆+SO 混淆+JUMPOUT[1001622]) / 加固&脱壳[1001590](基础理论/Android软件壳/SO加固/反调试/运行环境检测/查壳工具/安全键盘/虚拟化VM[1001356]/脱壳技术[1001560]) / 资源保护[1001611]。

3 行摘要:加固三大壳形态(整体加密壳/抽取壳(函数NOP)/VMP 虚拟化),脱壳方案选型(FART 失效后的 JDex/BlackDex/dpt-shell/eBPF)与 dex 修复(cdex→dex+SHA-1/Adler 重算),手法库 `03-脱壳dump/` 三篇;8 类 so 混淆特征、花指令 patch、控制流平坦化四路线、VMP 五步还原法,手法库 `10-纯算法/去混淆实战.md`(306 行)。**详见 手法库(同 skill re/手法)。**

## 13. 文件格式 [1001533] — 手法库 空白,本区深挖

主要节点:class字节码[1001301](含 AOP:Javassist[1001575]/ASM[1001576]) / AXML[1001303] / ARSC[1001304] / DEX/ODEX[1001305](文件格式/加载过程/重组修复/修改/解析工具) / OAT[1001307](布局/DEX提取/smali转换) / ELF与so[1001341](格式规范/动态加载/Linker分析/Section/解析工具) / apk文件[1001539](assets/res/META-INF/resources.arsc/AndroidManifest.xml) / 库文件[1001536](jar/aar)。

一句话:dex(header/map_list/class_def/code_item)、elf(so 重定位/GOT/PLT/init_array)、oat/vdex/cdex、arsc、AXML 六大格式的字节级细节+对比表,在本区 [文件格式详解.md](文件格式详解.md) 全篇展开。

## 14. 协议分析 [1001535] — 手法库 全覆盖,互链

主要节点:数据包过滤与分析[1001280] / 分析实例[1001357] / 数据包重放与分析[1001546] / 抓包技术[1001769](工具[1001298]/环境搭建[1001770])。

3 行摘要:抓包 10 断点定位+13 场景矩阵(Android7+/14+ 证书、VPN 链、QUIC、Flutter、双向认证 dump p12、加密报文 Burp 明文桥接),手法库 `04-对抗攻防/抓包全场景.md`(306 行)是主入口;五类 SSL pinning 定位与绕过在 `ssl-pinning绕过.md`(263 行);协议脱机与重放(frida RPC/unidbg 三级火箭)在 手法库 `10-纯算法/协议脱机与RPC.md`(363 行)。**详见 手法库(同 skill re/手法)。**

## 15. 安全测试 [1001557] — 手法库 未覆盖,本区简述

主要节点:SDK测试[1001678] / Drozer测试框架[1001679] / 数据存储[1001680] / 其他[1001681]。

- **Drozer**:Android 安全测试框架(原 Mercury),agent 跑在设备上,console 发起攻击——核心模块 `app.package`/`app.activity`(导出组件枚举+Intent 触发)/`app.provider`(content provider 注入与目录穿越)/`app.broadcast`;命令样例:`dz> run app.package.attacksurface com.x`。2020s 后社区活跃度下降,MWR 归 F-Secure→WithSecure,现由 Reversec Labs 维护,可用;导出组件面测试思路持续有效。
- **数据存储**:SharedPreferences/MMKV 明文、SQLite(-wal 残留)、外部存储、日志泄露;测试=遍历 `/data/data/<pkg>` 找敏感明文(需 root 或 run-as debuggable 包)。

## 16. 二次开发 [1001558]

见 §8 合并说明。核心技能链:apktool d → 改 smali/资源 → apktool b → zipalign → apksigner 重签 → 对抗签名校验(见 手法库 `02-frida/java层/存储与系统.md` §9.2)。

## 17. 基础知识 [1001600] — 本区简述

主要节点:分析环境[1001561](adb[1001651]/命令配置[1001668]) / 学习方法[1001643] / 安全现状[1001646]。

- **adb 必会集**:`adb shell dumpsys activity top`(当前栈)/`adb shell pm path <pkg>`(拿 APK 路径)+`pull`/`am start -n`(带 extra 启动)/`ps -A | grep`+`/proc/<pid>/maps`、`adb backup` 提取(allowBackup=true 时)、`adb shell settings get`。
- **学习方法**:树中「学习方法」子树的多篇导引文指向同一结论:以一个真实目标贯穿(脱壳一个壳→hook 一个加密→还原一个协议),比按目录通读快一个量级——与 手法库 INDEX 的「禁止通读整库」用条一致。

## 18. 软件破解 [1001625] — 社区特色,本区简述

主要节点:去除广告[1000947] / 功能限制[1001624] / 序列号保护[1001629] / 时间限制[1001633] / 其他[1000948]。

一句话:Windows 破解文化在 Android 的镜像——去除广告(定位广告 SDK 初始化调用点 NOP/hook)、VIP 功能限制(改 `isVip` 返回值/服务端校验则转协议伪造)、时间限制( trial 到期检查,`System.currentTimeMillis` hook 或 smali patch)、序列号(本地校验逆算法,联网校验走抓包+脱机)。伦理边界:仅限自有/授权目标与 CTF。方法论与 hook 手段全部复用 手法库 02-frida 两篇速查。

## 19. 热修复/插桩 — 一句话+互链

- **热修复 [1001753]**:Tinker/QZONE/AndFix/Sophix 系——dex 补丁加载与 ClassLoader 插队;攻防视角=运行时换 dex 的合法通道,与脱壳 dump 的入口高度重合(找补丁 dex 的 ClassLoader 即拿明文)。
- **插桩 [1001775]**:广义=frida/Stalker/QBDI/Unicorn 全家;分级观测点(符号 hook→inline→stalker 指令级→内核)决策在 手法库 `11-链路内核级/观测点矩阵与使用路径.md`(253 行,35 行×7 列大矩阵)。

## 附:本区文件索引

| 文件 | 内容 |
|---|---|
| [Android知识体系总览.md](Android知识体系总览.md)(本文) | 23 二级分类+逐类去向 |
| [编译器与系统体系.md](编译器与系统体系.md) | ART/dex2oat/JIT/AOT 编译全链、SELinux、seccomp、binder |
| [文件格式详解.md](文件格式详解.md) | dex/elf/oat/vdex/cdex/arsc/AXML 字节级细节 |
| [恶意样本与CTF.md](恶意样本与CTF.md) | 恶意家族+实战案例+CTF 题型套路 |

> 维护:与 `~/.zcode/rules` 冲突时以 rules 为准;手法库(同 skill re/手法)更新时同步本文互链行。
