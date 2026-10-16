# iOS 攻防与进阶(反调试反注入 / 越狱检测 / 加固 / 恶意程序 / 协议 / 内核 / 汉化)

> 知识库 04-iOS安全 · 第 2/2 篇。第 1 篇:[iOS逆向体系.md](iOS逆向体系.md)(Mach-O/运行时/砸壳/调试/Hook/签名/越狱)。
> 定位:逆向体系是「怎么拆」,本篇是「拆的时候它怎么拦 + 更深的内核面」。

## 1. 反调试与反注入(承接第1篇 §7/§8)

### 1.1 sysctl 检测 P_TRACED(最经典)

```c
struct kinfo_proc info; size_t sz = sizeof(info);
sysctl((int[]){CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()}, 4, &info, &sz, 0, 0);
if (info.kp_proc.p_flag & P_TRACED) { /* 被 ptrace 附加 → 自杀/降级 */ }
```
- 对抗:hook `sysctl` 改写返回 buffer 的 flag 位(fishhook 可拦,因为走了符号);或内核层改——通过 xnuspy hook 内核 ptrace 函数绕过反调试(2024-06:读 xnu-7195.50.7.100 对应源码 `bsd/kern/mach_process.c`,用 pongoOS 模块 xnuspy 从用户态 hook 内核函数)。工具:xnuspy(仓库地址与 iOS 13/14 支持版本见其仓库)。
- 2026 版新对抗样例:某 QP 平台设备环境绕过技术深度解析(2026-03,验证清单:pthread_getname_np 线程名伪装/sysctl P_TRACED 清理/文件系统残留)。

### 1.2 ptrace(PT_DENY_ATTACH)

```c
ptrace(PT_DENY_ATTACH, 0, 0, 0);   // 之后任何 attach 被 kernel 拒绝
```
- 绕过:hook `ptrace` 让 PT_DENY_ATTACH(31) 调用变 NOP;或在调用前抢先 attach(竞速);lldb 下断 `symbolic breakpoint ptrace` 改返回值。

### 1.3 svc 内联(检测与反检测都升级)

目标直接内联 `svc #0x80` 直调 `SYS_sysctl/SYS_ptrace`,绕开符号表 → fishhook 失效(与 Android svc 直调完全同构,方法论互链 `re/手法/09-函数全景/hook降级实战.md` 的 svc 拦截章)。绕法:
- lldb 汇编断点逐个 nop(传统);
- Frida `Stalker`/硬件断点拦 svc;
- 通用工具:iOS 反反调试助手(替代单 APP 写插件/nop);利用 HookZz 实现反调试与绕过(ptrace/syscall/内联 svc 全谱)。
- 社区实战:iOS 搜索汇编绕过 svc 反动态调试(三六零 SRC,2023-01,版块内检索标题可达)。

### 1.4 反调试手法×绕法速查表(汇总)

| # | 检测手法 | 代码面 | 首选绕法 | 兜底 |
|---|---|---|---|---|
| 1 | sysctl P_TRACED | sysctl(KERN_PROC_PID) | fishhook/Tweak 改 buffer | xnuspy 内核层 |
| 2 | PT_DENY_ATTACH | ptrace(31,0,0,0) | hook ptrace NOP | 抢先 attach 竞速 |
| 3 | svc 内联直调 | 内联 svc #0x80 | lldb nop / Stalker | 硬件断点 |
| 4 | 时间差检测 | 两次 mach_absolute_time 差值 | hook 时间源(注意 vDSO 同构坑,见 手法库 09 区) | 让断点变硬件断点(零停顿) |
| 5 | 异常自检 | raise(SIGTRAP) 看是否被调试器吞 | hook signal/处理链 | Frida 转发原语义 |
| 6 | 调试符号/端口 | 检测 1234 端口/debugserver 进程名 | 改 debugserver 端口+改名 | — |

> 手法 4/5 与 Android 完全同构(SignalTrap 自测、时间反调试),原理层互链 `re/手法/04-对抗攻防/检测原理全景.md` §分层难度表——同一套「svc>libc>框架>语言」分层在 iOS 上是「svc>libSystem>OC/Swift」。

### 1.5 反注入(检测面清单)

| 检测 | 代码面 | 对抗 |
|---|---|---|
| dylib 注入枚举 | `dladdr(&fn)` 查 IMP 是否落在预期镜像;遍历 `_dyld_image_count` 对比白名单 | hook 枚举函数改返回;或 Dobby 层注入后摘 dyld 链(见 手法库 so 摘链同构) |
| 环境变量 | `getenv("DYLD_INSERT_LIBRARIES")` | 新版 dyld 已忽略,检测多为历史惯性 |
| Method hook 自检 | IMP 地址是否在本模块 __TEXT 区间 | 把 swizzle 的 IMP 指回原区间(inline trampoline 布局在模块内) |
| fishhook 自检 | 读 `__la_symbol_ptr` 槽位是否指向系统库 | 用静态链接/直接 syscall,或 hook 其校验函数 |

## 2. 越狱检测与绕过

### 2.1 检测面(攻方视角的清单,数量多但都薄)

文件路径检测的典型实现(fishhook 即可拦,列出便于识别特征):

```objc
// 典型检测代码(逆向时在 class-dump 头里常见 isJailbroken/canOpenURL 特征)
NSString *paths[] = { @"/Applications/Cydia.app", @"/usr/sbin/sshd",
                      @"/bin/bash", @"/private/var/lib/apt/", @"/etc/apt" };
for (p in paths) if ([[NSFileManager defaultManager] fileExistsAtPath:p]) return YES;
if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://"]]) return YES;
pid_t p = fork(); if (p >= 0) { if (p == 0) exit(0); return YES; }  // 沙盒内 fork 必败,非负即越狱
if (dlsym(RTLD_DEFAULT, "MSGetSessionIdentifier")) return YES;  // Substrate 痕迹
```

1. **文件/路径**:`/Applications/Cydia.app`、`/usr/sbin/sshd`、`/bin/bash`、`/private/var/lib/apt`…(rootless 越狱下大量失效——文件根本不在传统路径,这是 Dopamine 时代检测难度陡增的主因)。
2. **符号链接**:`/usr/sbin/sshd → /usr/libexec/sshd`(越狱搬运痕迹)。
3. **沙盒逃逸检测**:尝试写 `/private/` 根分区之外的越狱常用目录成功与否。
4. **fork/exec**:`fork` 在 App 沙盒默认失败,能成功=环境异常。
5. **dylib 列表**(见 §1.4)。
6. **系统 API 行为**:`UIApplication.shared.canOpenURL("cydia://")`;`system` 返回值。
7. **符号存在**:`dlsym(RTLD_DEFAULT, "MSGetSessionIdentifier")`(Substrate 痕迹)。

### 2.2 绕过体系

- **Tweak 一键系**(目标 App 进程内 hook 检测函数):A-Bypass、Liberty Lite( blinded by the light )、Shadow、Choicy(按 App 选择性禁用注入)。原理 = §8 的 swizzle/fishhook,把检测函数返回值收口。
- **rootless 越狱先天优势**:文件面检测大面积失效;残余检测靠 dylib/行为面,再配 Tweak 收口。
- **不越狱路线**:砸壳+重签+静态 patch 检测函数(配合第1篇 §9);或 TrollStore 版本的免越狱 tweak。
- 验证工具:越狱检测 app——《iOS越狱检测app及frida过检测》(2023-06-06)。该 crackme 覆盖 6 类检测+对应 frida 绕法——①stat 检测敏感路径(`/Applications/Cydia.app`、`/usr/sbin/sshd`,hook `stat` 改返回值 -1);②`_dyld_get_image_name` 遍历 dylib 匹配越狱库(hook 换返回合法 dylib 名);③`-[UIApplication canOpenURL:]` 探 cydia(hook 时注意 BOOL 返回值 replace 常崩,作者实测用 onLeave 改 retval);④`fileExistsAtPath` 越狱文件/目录;⑤`/private/` 私有路径可写性(越狱后 root,建文件无异常即中,hook 时用 `ObjC.classes.NSError.alloc` 构造假异常写入检测指针);⑥lstat 检测路径是否为符号链接(越狱搬运痕迹)。
- 风控级(设备指纹/一致性校验)与 Android 完全同构,互链 `re/手法/04-对抗攻防/设备指纹与风控.md`。

## 3. 加固与混淆(加固技术/混淆与反混淆节点)

### 3.1 商业加固矩阵

| 厂商 | iOS 手段 |
|---|---|
| 爱加密 | 本地数据加密/代码混淆/程序结构混排 |
| 顶象 | 可执行文件深度混淆 + VMP 虚拟机保护 |
| 网易易盾 | 类/方法/字符串混淆,反 class-dump |
| 腾讯 WeTest | 原子级混淆矩阵 |
| 360 天御/百度 | 加壳+防重签+防二次打包 |

iOS「加壳」≠ Android DEX 壳:iOS 商店强制 FairPlay 本身即全文件加密,厂商重心在**源码/链接期混淆 + 运行时反调试反注入 + 完整性校验(防重签/防 Tweak)**。逆向方拆法:混淆还原方法论与 Android OLLVM 完全同构(控制流平坦化/虚假控制流/bogus 花指令),互链 `re/手法/10-纯算法/去混淆实战.md` 的四路线。

### 3.2 开源混淆:Hikari/OLLVM(iOS)

《iOS 逆向与安全:使用 ollvm 混淆你的源码》(2023-02)是 Xcode 集成 OLLVM 的入门样例;**Hikari**(OLLVM 分支)源码解读《Hikari 源码分析 - AntiDebug》(2024-01)——混淆器自带的反调试 pass 在编译期插桩,拆法 = §1 的通用反反调试。

### 3.3 字符串/数据加密
Keychain、Sqlite(SQLCipher)、plist 加密、资源防盗(crypto 尾巴)——抓 key 优先 hook CommonCrypto(`CCCrypt`/`CC_MD5`)与 `SecItemCopyMatching`;通用加密自吐脚本思路互链 `re/手法/02-frida/java层/加密与自吐.md`(iOS 侧对象换成 ObjC/CommonCrypto)。

## 4. 恶意程序(恶意程序节点)

iOS 恶意样本史与代表面:

| 事件 | 年代 | 机制 | 分析来源 |
|---|---|---|---|
| **XcodeGhost** | 2015 | 污染非官方渠道 Xcode → 编译期植入 → App Store 数千 App 中招(微信/网易云音乐等);回传 UDID/感染参数,协议加密弱可被中间人接管 | 安天/腾讯分析 |
| WireLurker | 2014 | Mac 侧经 USB 感染 iOS(企业证书滥签) | Palo Alto |
| Golduck/AceDeciever 等 | 2016+ | 企业证书重签分发、证书钓鱼 | 各厂商博客 |
| mDNS/捷径/描述文件滥用 | 近年 | 社工面为主,非二进制漏洞 | — |

分析要点:iOS 恶意程序几乎全是**用户态+签名滥用**,少有内存破坏型;分析流程 = 砸壳(企业签/商店包)→ class-dump 看回传逻辑 → 抓 C2 协议(§5)。XcodeGhost 的教训(供应链:开发者工具链污染)与 SRC 供应链审计面直接相关。

## 5. 协议分析(协议分析节点 · 互链 手法库)

iOS 抓包与 Android 的差异只在「证书体系与工具名」,方法论完全共用,**主入口互链** `re/手法/04-对抗攻防/抓包全场景.md`(13 场景矩阵)、`ssl-pinning绕过.md`。iOS 特有面:

| 面 | iOS 做法 |
|---|---|
| HTTPS 抓包 | Charles/mitmproxy + 越狱机装 **SSL Kill Switch 2**(≈Android JustTrustMe);或 Frida 脚本 hook `SSLHandshake`/SecTrustEvaluate |
| 全流量(不越狱) | Mac `rvictl -s <UDID>` 建 RVI 虚拟网卡 → tcpdump/Wireshark(官方文档:Recording a Packet Trace);蜂窝/WiFi/非 HTTP 全可抓,但 TLS 内密文 |
| VPx/代理检测绕过 | Charles+Clash+Shadowrocket 组合(2024-07) |
| 双向认证/证书锁定 | hook 层 dump 客户端证书,同 手法库 ssl-pinning 篇 mTLS 章 |
| 私有协议 | r0capture 思路平移:hook `SSL_write/SSL_read` 或 `nw_` Network.framework 收发明文 |

代表帖:ios逆向某新闻md5+aes(2024-04:越狱+frida+SSL Kill Switch2 → Charles → md5 签名+aes 加密还原,完整闭环);「iOS逆向初探-变种AES加密的分析与还原」(2023-06);「小白逆向之路,ios抓包绕过SSL证书认证」(2024-04)。苹果自家协议(gsa/iTunes 登录)分析见版块 ppbb 系列(2017/2020,SRP6a 改良版)——协议+密码学高阶参考。

## 6. iOS 内核安全(漏洞相关节点 · 索引不展开)

> **与 `re/手法/07-内核级/跨平台内核速查.md` §2(iOS/XNU)互链,那边已有攻击面/数据结构/工具三层详表(KTRR/KDP/ipsw 等),本文只放索引+iOS 独有要点。**

| 主题 | 要点 | 深入处 |
|---|---|---|
| XNU 攻击面 | Mach IPC(mach_port 权限矩阵/send-once 竞态)、BSD syscalls(~540 条)、IOKit 清理路径、kext→DriverKit 迁移 | 跨平台速查 §2 |
| **PAC**(ARMv8.3/A12+) | 函数指针+返回地址签名;绕法:PAC gadget(可信代码代签)、签名重用、未保护间接跳转 JOP | USENIX'23《Demystifying PAC on Apple M1》;BH'23《Apple PAC, Four Years Later》;P0 2019 iPhone XS 首析 |
| KTRR | A10/A11 时代内核只读保护;A11 用外部调试寄存器绕过(KTRW) | 跨平台速查 |
| PPL/SPTM/TXM/Exclaves | PAC 之后的下一代收敛:页表管理/敏感中断搬入更高特权层 | alphaxiv《现代 iOS 安全特性》综述(2025) |
| 内核 hook | xnuspy(pongoOS 模块,用户态 hook 内核函数,iOS 13/14) | §1.1 帖 |
| 越狱与内核链 | unc0ver(rootful 内核提权)→ Dopamine(CoreTrust+arm64e 链) | 第1篇 §10 |

社区帖:iOS Hook 终极兵器库(2025:从 OC swizzle 到 ARM64e PAC 绕过与内核级劫持的分层路线图,本文 §1/§6 的进阶续读);一次失败的无痕 hook 尝试(ttxx 2023-08,版块检索——内核无痕对抗的踩坑实录,同构 手法库 07 区无痕篇)。

## 7. 游戏汉化(游戏汉化节点)

iOS 游戏汉化与 Windows 汉化(知识库树 1000254/1000277)流程同构,差异在资源形态与签名:

```
1) 拿 IPA(砸壳,见第1篇 §5) → 解包 Payload/*.app
2) 定位文本:
   - plist/json/sqlite/plain 字符串(多数 Unity/Cocos 转 iOS)
   - 资源打包:Unity 的 resources.assets/AssetBundle 用 UnityPy;
     自研格式 → IDA 逆加载函数定位索引结构
   - 本地化目录:*.lproj(官方多语言框架,改 zh-Hans.lproj 最省)
   - 字体:ttf/otf 缺字需补字形表(中文扩 A 免不了)
3) 改文本(等长/变长看索引是否有长度字段/哈希校验)
4) 重打包 + 重签(第1篇 §9 codesign/ldid/AltStore) → TrollStore/越狱机分发
5) 崩溃排查:完整性校验(CRC/CodeResources)→ 重签;文本越界 → 溢出
```
Unity/IL2CPP 类游戏的逻辑层逆向与 Android 完全同源(同一套 IL2CPP/AssetBundle),互链 手法库 工具矩阵;树节点 1001405 下精华帖以《Galgame 汉化中的逆向》(1001486)方法论可平移:字库定位→指针表→回填。

## 8. 学习路线与「其他」节点收口

- 入门:第1篇 §2 Mach-O → class-dump 看自家 App → 砸壳一个商店应用 → lldb 附加。
- 中级:Tweak(第1篇 §11)改一个检测函数;Frida hook CommonCrypto 自吐密钥(§5)。
- 高级:反反调试(§1)→ 混淆还原(§3)→ xnuspy/内核(§6)。
- 同构迁移:iOS↔Android 的 hook 降级/风控/抓包三面几乎一对一,见 手法库 04/09 区;macOS 是「可调试放大版 iOS」(SIP 可关),跨平台速查 §4。

## 9. 参考总表(本篇)

| 主题 | 资料 |
|---|---|
| 内核 ptrace 绕过 | xnuspy hook 内核 ptrace(2024-06) |
| 反反调试 | iOS 反反调试助手 |
| 反调试全谱 | HookZz 反调试与绕过 |
| 环境绕过(2026) | QP 平台设备环境绕过 |
| 协议还原 | ios逆向某新闻 md5+aes(2024-04) |
| Hook 进阶 | iOS Hook 终极兵器库(2025) |
| 恶意程序 | XcodeGhost 分析(安天) |
| PAC 学术 | USENIX'23 M1 PAC |
| PAC 黑帽 | Apple PAC Four Years Later |
| RVI 官方 | Recording a Packet Trace |
| 越狱检测app+frida过检测 | iOS越狱检测app及frida过检测 |
| svc 反调试绕过 | 绕过iOS 基于 svc 0x80 的 ptrace 反调试(2022-07);另见《bypass svc 0 PTRACE_TRACEME》 |
| Tweak 入门 | Tweak开发:给调音量增加震动反馈 |
| 无痕 hook | SVC的TraceHook沙箱的实现&无痕Hook实现思路(2022-06,ptrace+seccomp 拦内联 SVC) |
| 越狱检测(讨论) | ai 绕过 ios 越狱检测(三方 SDK GeoComply/Incognia/Sift,2026-04) |
| iOS inlinehook 绕反调试 | iOS inlinehook绕过反调试 |
| 免越狱 hook | 无需越狱,篡改动态符号表实现hook |
| 砸壳 | 一条命令完成iOS应用砸壳 / ios-dumpdecrypted砸壳 |
