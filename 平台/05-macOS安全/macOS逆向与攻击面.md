# macOS 逆向与攻击面(平台/05-macOS安全)

> 定位:macOS 独立区主篇。Mach-O 实操 / dyld 注入 / 工具链 / 桌面攻击面(TCC·XPC·持久化·公证)/ 加固与检测面。
> 内核级(XNU/IOKit/SIP/Mach IPC)不重复展开 → `../../手法/07-内核级/跨平台内核速查.md` §2 §3;iOS 同源工具链 → `../04-iOS安全/iOS逆向体系.md`;抓包对抗(Flutter 等) → `../../手法/04-对抗攻防/抓包全场景.md`。
> **本机实测环境**:macOS 26.6.2(25G83) arm64,SIP enabled,Gatekeeper assessments enabled,原生进程(proc_translated=0)。标 `[本机实测]` 的命令均在上述环境跑通,输出要点为原文摘录。

## §0 快速上手:五分钟认清一台 mac

```bash
sw_vers                          # 版本(Build 号决定内核结构偏移)
uname -m                         # arm64:注意 arm64e(指针认证)全面启用
csrutil status                   # SIP 状态(逆向机是否已解除限制)
spctl --status                   # Gatekeeper
sysctl sysctl.proc_translated    # 1=进程跑在 Rosetta 下(分析 Intel 样本时的坑)
```

macOS 逆向与 iOS 的关系:**同一套 XNU + Mach-O + ObjC/Swift + LLDB/Frida**,区别是 mac 能装任意工具、能关 SIP、能双机内核调试——是 iOS 研究的"可调试放大版"。从 Android 迁移的对照表在跨平台内核速查 §3.3。

## §1 Mach-O 逆向实操 `[本机实测]`

### 1.1 三板斧:otool -L / -l / codesign

以系统二进制 /usr/bin/file 为例(universal 3 架构:x86_64 + arm64 + arm64e):

```
$ otool -L /usr/bin/file
	/usr/lib/libbz2.1.0.dylib (compatibility version 1.0.0, current version 1.0.8)
	/usr/lib/libz.1.dylib    /usr/lib/liblzma.5.dylib
	/usr/lib/libSystem.B.dylib          ← LC_LOAD_DYLIB 逐条列出(≈ ldd)

$ codesign -dv /usr/bin/file
	Format=Mach-O universal (x86_64 arm64e arm64)
	CodeDirectory v=20400 flags=0x0(none) hashes=10+2
	Platform identifier=26            ← 平台二进制标志(dyld 环境变量豁免的判定依据,§2)
	Signed Time=Aug 1, 2026 ...
```

`otool -l` 看全量 Load Command——逆向时重点扫这几条:

| Load Command | 看什么 | 实测值(/usr/bin/file) |
|---|---|---|
| LC_SEGMENT_64 | 段布局:`__PAGEZERO`(4GB 空洞挡 NULL 解引用)/`__TEXT`(r-x)/`__DATA`(rw)/`__LINKEDIT` | __TEXT vmaddr 0x100000000,initprot 0x5(r-x) |
| LC_MAIN | 入口偏移(无 LC_ENTRYPOINT 时它就是 main 前 dyld 的交接点) | entryoff 83812 |
| LC_LOAD_DYLIB | 依赖库(≈DT_NEEDED) | libbz2/libz/liblzma/libSystem |
| LC_CODE_SIGNATURE | 签名数据位置 | dataoff 154528 |
| LC_LOAD_DYLINKER | 加载器 | /usr/lib/dyld |

样本分析套路:对比正常系统二进制的 LC 集合,多出来的 LC_LOAD_DYLIB(加载 /tmp 可疑库)、被抹掉的 LC_CODE_SIGNATURE、异常的 __TEXT initprot(变可写=自修改代码)都是强信号。

### 1.2 arm64e 专项:__auth_stubs 与 PAC

本机实测 /usr/bin/file 的 __TEXT 段里有 `__auth_stubs` 节(reserved2=16):arm64e 架构下**外部函数桩带指针认证**,跳转用 `braa/braz`(签名认证跳转)而非裸 `blr`。逆向影响:
- arm64e 二进制里伪造函数指针/GOT 的传统路线被 PAC 挡,绕法思路(PAC gadget/签名缓存重用)见跨平台内核速查 §1.1;
- 分析通用样本先 `lipo -thin arm64` 抽非 arm64e 切片(第三方 app 大多仍是普通 arm64)。

### 1.3 fat 二进制与架构选择

```
$ file /usr/bin/file
Mach-O universal binary with 3 architectures: [x86_64] [arm64] [arm64e]
$ lipo -thin arm64 /usr/bin/file -o /tmp/file_arm64   # 抽单架构再进 IDA/Ghidra/r2
```

Intel 模拟器/样本分析注意 Rosetta:跑在转译下的进程 `sysctl sysctl.proc_translated=1`,断点行为与内存布局有差异。

### 1.4 符号与 ObjC/Swift 元数据

```
$ nm -undefined-only /usr/bin/file      # 导入符号(defined=0:系统二进制 strip 过)
                 U _BZ2_bzDecompress / ___assert_rtn / ___chkstk_darwin ...
```

- **ObjC 信息量红利**:`otool -o` 直接吐类结构。实测 Terminal.app 可见 `__objc_classlist` 里 isa/superclass/baseMethods 指针链——class-dump 类工具就是把这张表走一遍生成头文件。第三方 mac app 的方法名/属性名绝大多数明文,静态分析先 dump 类再按名字定位校验函数。
- **Swift 元数据**:符号 mangle 成 `$s` 前缀(swift-demangle 还原);跨平台内核速查 §2.2 有 TypeMetadata/VWT 结构要点。Swift 逆向核心坑是**值语义与虚表调度**:方法调用走 VWT 而非 ObjC 的 objc_msgSend,Hook 点选择完全不同。
- 系统侧符号:/usr/bin/file 这类平台二进制 strip 得只剩 undefined,拿全量符号要装 Kernel Debug Kit(KDK)或 dSYM。

## §2 dyld 链与注入实测 `[本机实测]`

### 2.1 DYLD_INSERT_LIBRARIES 三组对照(核心结论)

环境:SIP **enabled**。自编译目标 hello_mac(adhoc 签名,内含 `strcmp(输入,"MAC-RE-DEMO-2026")` 的 license 校验)+ interpose dylib(`__DATA,__interpose` 节 hook strcmp 恒返回 0):

| 目标 | 结果 | 原因 |
|---|---|---|
| 自编译 adhoc 二进制 | **注入成功**:license 恒过;连 dyld/libSystem 启动期的 strcmp 都被拦到(`strcmp("hello_mac","launchd_sim")` 等启动日志级输出) | adhoc+无 library validation,dyld 不剥离环境变量 |
| 平台二进制 /bin/ls | **静默忽略**(无注入痕迹,程序照常跑) | 平台二进制(Platform identifier)的 DYLD_* 全部被 dyld 丢弃,连报错都无 |
| SIP off 机器 | 平台二进制同样可注入 | 限制链=SIP 保护 dyld + AMFI 校验,关 SIP 后放开 |

结论速记:**DYLD_INSERT_LIBRARIES ≈ LD_PRELOAD,但豁免矩阵=「平台二进制/有 library validation 的公证 app」被拒,其余(自编译/未开 hardened runtime 的第三方)SIP 开着也能注**。恶意样本滥用面=大量非公证第三方 app。

### 2.2 现代限制链拆解

- **SIP**:保护 /usr/bin、dyld 本体、系统文件——老式"改 dyld 剔除限制"路线在 SIP on 下不可行;`csrutil disable` 需进恢复模式。
- **硬编码库移除限制**:dyld 对受限进程直接清空 DYLD_INSERT_LIBRARIES/DYLD_LIBRARY_PATH 等(实测 /bin/ls 静默丢弃即此)。
- **AMFI**(AppleMobileFileIntegrity):amfid 守护 + 内核 kext 校验代码签名/entitlement;未签名 kext 现代 macOS 基本装不上(kext 走向淘汰,DriverKit 接棒——见跨平台内核速查 §1.4)。
- **Hardened Runtime + Library Validation**:app 开了 `com.apple.security.cs.disable-library-validation` 之外的默认配置时,只允许同 TeamID 的库注入;`allow-dyld-environment-variables` entitlement 才显式放行 DYLD_*。分析前先 `codesign -d --entitlements :- <app>` 查这两个开关。

### 2.3 实用注入/诊断命令

```bash
DYLD_PRINT_LIBRARIES=1 ./target           # 打印加载的每个库(比 otool -L 多算 dlopen 的)
DYLD_PRINT_ENV=1 ./target                 # dyld 收到的环境+是否被剥离
DYLD_INSERT_LIBRARIES=./inter.dylib ./t   # interpose 注入(见 2.1)
```

注入替代路线(目标被 library validation 挡时):Frida(走 task_for_pid+entitlement,macOS 上可直跑,比 iOS 研究机门槛低一档)/patch 二进制后 `codesign -f -s -` 重签/LLDB attach。trace 级别的观测见 `../../手法/13-trace/trace实战.md`(含 macOS spawn 坑)。

## §3 工具链与 LLDB 实测

### 3.1 工具矩阵(mac 本机视角)

| 工具 | 本机状态 | 用途/要点 |
|---|---|---|
| otool/lipo/nm/codesign/dsymutil | 系统自带 | §1 全套,零成本起手 |
| **r2/radare2** | 本机 6.2.4(Homebrew) | 见 3.2 实测;脚本化批量分析首选 |
| LLDB | 本机 1403.0.17(CLT) | §3.3 全流程;`po`/`expr`/ObjC 运行时感知 |
| Hopper | 未装 | mac 逆向标志性 GUI:伪代码+ObjC 标注+内置 LLDB,价格远低于 IDA,mac 平台首选商业件 |
| Ghidra | 未装 | 免费重炮,Mach-O/ObjC 支持成熟,arm64e 反编译可用 |
| IDA | 未装 | 通用最强,mac native GUI |
| Frida | 生态兼容 | macOS 进程注入与 Android 同套脚本(native 层互通用) |
| ipsw(blacktop) | 内核研究必装 | kernelcache 解包/符号恢复,见跨平台内核速查 §6 |

### 3.2 r2 实测一条流 `[本机实测]`

```
$ r2 -q -c 'ie; iM' /bin/ls          # 入口
0x00010960 0x100000960 ... program   # entry0
$ rabin2 -I /bin/ls                  # 二进制指纹
bintype mach0  class MACH064  machine arm64e  compiler clang
canary true  nx true  pic true  stripped true  os macos
```

要点:一键拿到 canary/nx/pic 三防护位+编译器指纹,样本分诊第一步;后续 `aaa; afl; pdf @ main` 常规流。r2 的 Mach-O 解析对 LC 的覆盖(rabin2 -e 看 entry/exports)与 otool 互补。

### 3.3 LLDB 逆向自编译 hello 全流程 `[本机实测]`

目标:绕过 hello_mac 的 license 校验。一条 batch 命令演示"断点→读参→强改返回值"三步:

```
$ lldb --batch \
    -o 'breakpoint set -n check_license' \
    -o 'run BADKEY-123' \
    -o 'register read x0 x1' \
    -o 'memory read -f s $x0' \
    -o 'thread return 1' \
    -o 'continue' -- /tmp/hello_mac
Breakpoint 1: where = hello_mac`check_license, address = 0x0000000100003eac
* thread #1, stop reason = breakpoint 1.1
      x0 = 0x000000016fdff26f            ← ARM64 第一参数
0x16fdff26f: "BADKEY-123"                 ← memory read -f s 直接吐字符串
(lldb) thread return 1                    ← 强制函数返回 1:license 恒过
input=BADKEY-123 result=1                 ← 校验被短路
```

流程要点(macOS 专属):
- ARM64 调用约定 x0-x7 传参,`memory read -f s $x0` 看字符串参数;
- **`thread return <值>` 是无 patch 绕校验的最短路径**(等价 x64dbg 的改 EAX+ret),配合 `b -n <函数名>` 对 ObjC 方法名同样生效(`b "-[ClassName methodName]"`);
- `expr`/`po` 可在断点处直接调 ObjC 运行时(`po [self someState]`);
- 反调试对抗(PT_DENY_ATTACH/sysctl P_TRACED)在 macOS 同样存在,绕法速查 → `../04-iOS安全/iOS攻防与进阶.md`(API 同源);
- 内核态调试:KDK + `kdp-remote udp://...`(boot-args 加 debug=0x144),详见跨平台内核速查 §5。

## §4 桌面攻击面(TCC / XPC / 持久化 / 公证)

### 4.1 TCC(隐私授权框架)

**实测数据库位置**(双库并存):

| 库 | 路径 | 实测内容 |
|---|---|---|
| 用户级 | `~/Library/Application Support/com.apple.TCC/TCC.db` | access 表:service(kTCCService*)+client(bundle id)+auth_value+csreq(签名要求 blob)+last_modified 等全列 |
| 系统级 | `/Library/Application Support/com.apple.TCC/TCC.db`(root,SIP 保护) | 同 schema;REG.db 记录注册行为 |

实测 tccd 双实例常驻(system 域+gui 域各一)。攻击面要点:
- 授权判定的锚是 **csreq blob**(代码签名要求)而非简单 bundle id——伪造 client 要连签名一起过;
- 绕过面(路径竞争/daemon 误信客户端声称身份/环境注入)与实例化模式 → 跨平台内核速查 §3.2;
- 红队视角:TCC.db 是**取证金矿**——直接 SELECT 出谁拿过屏幕录制/辅助功能/全盘盘访问授权,`auth_value` 2=allowed;
- 恶意软件高频目标:kTCCServiceAccessibility(键鼠监听)、kTCCServiceScreenCapture、kTCCServiceSystemPolicyAllFiles。

### 4.2 XPC 服务端点枚举 `[本机实测]`

```
$ launchctl list | wc -l        # 本机 534 行:label+pid+最后退出码
$ launchctl print system/com.apple.tccd.system | grep -E "program|state"
	program = /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
$ launchctl print gui/$(id -u)/com.apple.tccd | grep -A5 endpoints
	endpoints = { "com.apple.tccd" = { port = 0x53663, active = 1 ... } }
```

审计套路:**launchctl list 全量 label → print 逐个看 program 路径(system 域=root 权限 daemon)→ plist(LaunchDaemon 目录)看 MachServices 端点名 → 逆向该 daemon 的 `shouldAcceptNewConnection` 校验逻辑**(验 Entitlement?验 Audit Token?还是什么都不验)。漏检模式=特权 daemon 只验"连上了"不验"谁连的"——桌面提权经典面。plist 落点:
- /System/Library/LaunchDaemons(系统,SIP 保护)/Library/LaunchDaemons(第三方 root,**持久化高危区**)
- /Library/LaunchAgents、~/Library/LaunchAgents(用户级持久化)
- LaunchAgent 的 RunAtLoad/KeepAlive+指向 /tmp 或用户可写路径的二进制=恶意持久化指纹。

### 4.3 Gatekeeper 与公证(notarization)

```
$ spctl --status     # assessments enabled
```

- 链条:下载文件带 quarantine xattr → Gatekeeper 查公证票据(notarization=Apple 云端扫描后签发)→ 用户首次确认 → 之后校验 CDHash;
- 绕过研究面:quarantine 属性清除(xattr -d com.apple.quarantine,非 app-store 渠道下载的旧文件)/未公证 app 的右键打开绕首道门/handler 劫持;
- 恶意样本实测常用:DMG 内嵌 symlink、app 转置(translocation:从 quarantine 位置运行的 app 会被挪到随机只读挂载点——分析时注意真实路径被换)。

### 4.4 浏览器与其他桌面面

- 浏览器(Chrome/Safari)是 mac 恶意投放第一入口:沙箱逃逸→XPC 提权→TCC 收割是常见链;分析浏览器面先看 helper 进程与 Native Messaging host 清单;
- dmg/pkg 投放:pkg 的 pre/postinstall 脚本直接 bash,是社工样本主力载体(`pkgutil --expand` 解开审脚本);
- 外设:Thunderbolt/USB 物理面属无线硬件区 → `../07-智能设备/无线硬件/硬件接口.md`。

### 4.5 攻击面收口:桌面链速查

```
投放(quarantine dmg/pkg/浏览器) → Gatekeeper/公证首关
  → 用户态落地:LaunchAgent 持久化(§4.2 落点)
  → 提权/免杀:XPC 特权 daemon 校验缺失(§4.2)→ root
  → 收割:TCC 授权诱导(§4.1)/钥匙串/浏览器数据
  → 长驻:LaunchDaemon(root)+ 客户端伪造面
```
每一环的检测抓手:EDR(§6)看到的=持久化落点+出站流量;取证看到的=TCC.db 授权记录+launchctl 状态。

## §5 App 加固与逆向要点

- **Swift 逆向**:mangle 符号 swift-demangle;VWT 调度导致 Hook 点不同于 ObjC;async/await 状态机(编译器生成的 resume 函数链)是还原控制流的主要障碍。
- **ObjC 防护**:方法名混淆(class-dump 出乱码)/检测 swizzle(方法实现地址是否在预期镜像内)/反 class-dump(把 classlist 藏到运行时注册)。对抗本质同 Android 加固——dump 时机后移到运行时。
- **Metal shader**:游戏/渲染类 app 的 GPU 代码在 .metallib(AIR 字节码),分析工具链远不如 CPU 侧成熟;逆向重点转向**shader 与 CPU 侧的命令流**(MTLDebugCommandEncoder hook 可录命令流,类似 Android 的 GPU trace)。
- **公证后 hash 校验**:公证把 CDHash 绑定到 Apple 票据;**patch 二进制=CDHash 变=公证失效+Gatekeeper 拦**——所以 mac 破解必走"patch + adhoc 重签(`codesign -f -s -`)+去 quarantine"三连;app 自校验(读自身 CDHash 比对)的绕法=hook 校验函数或改比对结果,与 Windows 的 crc 自校验同型。
- 加固感知顺序(分析时先跑一遍):codesign 看是否 hardened runtime/ entitlements 里有没有 library validation 例外 → otool -l 找 LC_ENCRYPTION_INFO 加密位(桌面上罕见,iOS 常见) → strings 找反调试痕迹(PT_DENY_ATTACH/sysctl)。

## §6 检测面:EDR on mac 现状

| 检测层 | 代表 | 逆向/对抗视角 |
|---|---|---|
| 网络监控 | Little Snitch 类(出站防火墙) | 分析恶意样本先确认有没有装——出站告警会暴露 C2;红队侧它是"用户态可见的第一道提示" |
| 端点 EDR | CrowdSense/CrowdStrike/SentinelOne/Defender for Endpoint 等 | 内核 kext 路线已死(System Extension 接棒):网络内容过滤/端点安全 framework 都是用户态代理+系统扩展;绕过研究=System Extension 的 API 信任边界 |
| 系统自身 | XProtect(签名匹配,静默)/Gatekeeper/公证 | XProtect YARA 规则匹配已知样本;免杀思路与 Windows 同型但库浅得多 |
| 企业面 | MDM 推送的策略/证书 | 攻击面=MDM 注册流程与配置 profile 伪造 |

mac 恶意软件对抗 EDR 的公开手法:杀/禁 EDR 的特权 XPC 服务(XM Cyber 模式,跨平台内核速查 §3.1 有标注)、tcc 重置诱导用户重授权、LaunchDaemon 落点找 EDR 盲区(用户级)。

## §7 迁移与互链总表

| 你要做什么 | 去哪 |
|---|---|
| 内核洞(XNU/Mach IPC/IOKit/SIP 绕过/TCC 绕过模式) | 手法/07-内核级/跨平台内核速查.md §2 §3 |
| iOS 同源工具链(ObjC 运行时/越狱检测/fishhook) | ../04-iOS安全/iOS逆向体系.md、iOS攻防与进阶.md |
| 抓包对抗(Flutter/BoringSSL/QUIC,mac 侧同样适用) | 手法/04-对抗攻防/抓包全场景.md §2.7、大厂抓包对抗档案.md |
| trace/frida 在 mac 上的坑(spawn 限制) | 手法/13-trace/trace实战.md、手法/05-工具矩阵/工具实操笔记.md |
| Flutter so 偏移定位(本机 IDA 流) | 手法/04-对抗攻防/ssl-pinning绕过.md §3.3 |
| Mach-O 与 ELF 逐字段对照、历史平台 | ../03-Linux平台/其他平台.md(本区前身,指针保留) |
