# 手法分支总目录(re 单入口之一 · 只读路由)

> 用法:入口在 ../../SKILL.md 分支路由;按任务在下表点名开 1-2 篇,禁止通读整库。
> 结构:手法维度(frida/脱壳/对抗/工具/内核/函数/算法/链路/决策);平台与领域知识走 ../平台/ 分支。
> 代码类文件可直接复制使用;**hook 被干先开 12-绕过决策**。

## 01-方法论

| 文件 | 什么时候开 |
|------|-----------|
| [r0re-架构解析.md](01-方法论/r0re-架构解析.md) || 想懂多 LLM 会话协作逆 APK 的工程化:四件套/swarm 循环/验证门/prompt 精华 |
| [llm自动逆向编排.md](01-方法论/llm自动逆向编排.md) || 用 ZCode subagent 复刻:三角色/黑板/拆片/**可照抄 DAG 模板**/反模式 |

## 02-frida

| 文件 | 什么时候开 |
|------|-----------|
| [环境与快速开始.md](02-frida/环境与快速开始.md) || 装环境、spawn/attach、自定义端口、frida-trace |
| **java层/**(子目录 6 篇,按域取用) | | |
| [java层/网络与webview.md](02-frida/java层/网络与webview.md) || okhttp/URL/Uri/WebView/loadUrl/addJavascriptInterface |
| [java层/加密与自吐.md](02-frida/java层/加密与自吐.md) || Cipher/Mac/MessageDigest/Signature/**加密自吐全家桶** |
| [java层/存储与系统.md](02-frida/java层/存储与系统.md) || SP/ContentResolver/包名/**PMS 签名伪造**/防录屏/隐藏包名/无障碍/OAID |
| [java层/UI与跳转.md](02-frida/java层/UI与跳转.md) || Toast/Dialog/Activity 跳转/Intent 构造/goto_activity |
| [java层/字符串与JSON.md](02-frida/java层/字符串与JSON.md) || StringFactory/StringBuilder/org.json/fastjson |
| [java层/sslpinning与证书.md](02-frida/java层/sslpinning与证书.md) || SSLContext.init/dump 客户端证书 p12/证书定位器 |
| [native层hook速查.md](02-frida/native层hook速查.md) || so 层:NewStringUTF/dlsym/dlopen/pthread/clone/strstr/RegisterNatives/init_array+工具函数 |
| [frida-API详解.md](02-frida/frida-API详解.md) || Process/Memory/NativeFunction 类型表/Java($h/$l/$p/ArtMethod 偏移/fromJni 主动调用) |
| **高级/**(子目录 6 篇,进阶按主题取用) | | |
| [高级/stalker.md](02-frida/高级/stalker.md) || Stalker 原理/transform/卡死排查/putCallout/改寄存器/日志缓冲 |
| [高级/gothook.md](02-frida/高级/gothook.md) || GOT hook 两条完整路:ELF 头解析找 GOT+soinfo 方案 GotHook |
| [高级/patch与内存操作.md](02-frida/高级/patch与内存操作.md) || patchCode/Arm64Writer(nop/ret) |
| [高级/yahfa与arthook.md](02-frida/高级/yahfa与arthook.md) || yahfa 完整加载封装+ARTHookScripts ShadowFrame 机制 |
| [高级/so与soinfo操作.md](02-frida/高级/so与soinfo操作.md) || soinfo 摘链 soListRemove(详解在 gothook 与 03 区) |
| [高级/检测绕过片段.md](02-frida/高级/检测绕过片段.md) || usb/adb 检测绕过/去除 rwxp/vpn 代理绕过/TrustManagerImpl 精确定位/CertificatePinner 源码要点 |

## 03-脱壳dump

| 文件 | 什么时候开 |
|------|-----------|
| [dex脱壳.md](03-脱壳dump/dex脱壳.md) || DexFile 构造法/DefineClass 法/找 classLoader/方案选型(FART 在 A12-16 失效) |
| [eBPF脱壳深挖.md](03-脱壳dump/eBPF脱壳深挖.md) || **最深方案**:eBPF 隐蔽性/ART 入口形态(DexFile::DexFile x1=DEX begin)/-rs 修复管线/与 frida 对比 |
| [so修复dump.md](03-脱壳dump/so修复dump.md) || soinfo 偏移表/solist 遍历/dumpSoFromSoInfo/段回填 |

## 04-对抗攻防

| 文件 | 什么时候开 |
|------|-----------|
| [检测原理全景.md](04-对抗攻防/检测原理全景.md) || **对抗先定层**:反调试/frida/root/模拟器/VPN/RASP 检测到 syscall 层+分层难度表 |
| [RASP绕过.md](04-对抗攻防/RASP绕过.md) || 商业加固对抗:识别特征表/五层绕过方法论/案例/checklist |
| [frida反检测对抗.md](04-对抗攻防/frida反检测对抗.md) || 改特征/hook 检测函数/gadget 转地下/升级对抗+四阶段 checklist |
| [root与环境隐藏.md](04-对抗攻防/root与环境隐藏.md) || Magisk+Shamiko/KSU/APatch/残面处理/金融检测栈 |
| [ssl-pinning绕过.md](04-对抗攻防/ssl-pinning绕过.md) || 五类 pinning 定位与 bypass 脚本/Flutter 偏移/mTLS |
| [抓包全场景.md](04-对抗攻防/抓包全场景.md) || **通用抓包主入口**:13 场景矩阵(证书/VPN 链/QUIC/Flutter/加密报文/私有协议) |
| [大厂抓包对抗档案.md](04-对抗攻防/大厂抓包对抗档案.md) || **按厂专项**:字节/阿里/微信/美团/京东/小红书/快手/拼多多等 16 节,各厂网络栈/锁定层/**关键函数与 so**/抓包路径梯度+通用规律(转 RPC 决策点/放弃信号) |
| [设备指纹与风控.md](04-对抗攻防/设备指纹与风控.md) || 采集面 66 项/一致性校验/L1-L4 伪造/风控 SDK 案例/验证码/JA3 自检 |

## 05-工具矩阵

| 文件 | 什么时候开 |
|------|-----------|
| [工具总表.md](05-工具矩阵/工具总表.md) || **选型入口**:100+ 工具总表+按目标选工具链决策树 |
| [动态与hook框架.md](05-工具矩阵/动态与hook框架.md) || frida 生态/Xposed 系/inline hook 三家(Dobby/ShadowHook/Renef)/版本兼容矩阵 |
| [静态分析工具.md](05-工具矩阵/静态分析工具.md) || 反编译器横评/ROSAL 反混淆/SnikrFlow 符号执行/DexKit/加固识别 |
| [模拟执行框架.md](05-工具矩阵/模拟执行框架.md) || unidbg 用法/补环境坑/与 frida 对比 |
| [工具实操笔记.md](05-工具矩阵/工具实操笔记.md) | 命令级实操:jadx 全选项(单类秒级/--fallback 已废/--deobf 毁非混淆包)/r2 工作流(aflj 键名坑)/androguard 可复用脚本/frida 本机 spawn·attach(macOS 只能 spawn CLI 目标) |
| [工具检测与魔改.md](05-工具矩阵/工具检测与魔改.md) | **工具×对抗三列总表**(19 工具:检测面/魔改路径)/frida 四形态特征对账/重打包链与 V1·V2 签名绕过/魔改四层方法论(L1 部署→L4 替代)/零检测面清单与「能离线就离线」决策律 |
| [专项与信息收集.md](05-工具矩阵/专项与信息收集.md) || **陌生 APK 第一分钟**:APKiD/apkleaks/DIE/UltraSina 等 |

## 07-内核级

| 文件 | 什么时候开 |
|------|-----------|
| [Android内核与eBPF.md](07-内核级/Android内核与eBPF.md) || GKI/Binder·Futex·io_uring 攻击面/bpftrace 实战三脚本/boot.img 提符号/KGDB |
| [内核Hook与无痕对抗.md](07-内核级/内核Hook与无痕对抗.md) || ftrace/kprobe/fentry/LSM 对比/wxshadow 影子页全解/「为什么检测不到」 |
| [内核函数定位.md](07-内核级/内核函数定位.md) || 符号五路/KASLR 绕过/binder 定位六步/svc_hook/perf_event 硬断点 |
| [内核利用与Fuzzing.md](07-内核级/内核利用与Fuzzing.md) || 原语链/Dirty Frag 家族/syzkaller/「什么时候下内核」决策树 |
| [跨平台内核速查.md](07-内核级/跨平台内核速查.md) || iOS/macOS/Windows/通用内核攻击面对照 |

## 08-AI逆向

| 文件 | 什么时候开 |
|------|-----------|
| [AI逆向工具生态.md](08-AI逆向/AI逆向工具生态.md) || REA/MobileRE-Skill/LSPilot/jniq/dexllm/frida-mcp 横评+选型决策树 |
| [AI逆向工作流实战.md](08-AI逆向/AI逆向工作流实战.md) || 分析→hook→验证→重放流水线/3 个可照抄 prompt/五坑五验收门 |

## 09-函数全景

| 文件 | 什么时候开 |
|------|-----------|
| [安卓函数分层全景.md](09-函数全景/安卓函数分层全景.md) || **全库地基**:12 功能域五层映射(Java→JNI→libc→syscall→内核)+syscall 号速查 |
| [hook降级实战.md](09-函数全景/hook降级实战.md) || hook 被干→四死因决策树→六降级案例(可跑代码)→svc 拦截大全 |

## 10-纯算法

| 文件 | 什么时候开 |
|------|-----------|
| [纯算还原方法论.md](10-纯算法/纯算还原方法论.md) || 三层路线/算法指纹识别/白盒 AES+DFA/魔改三步法/12 参数案例/unidbg 补环境 |
| [去混淆实战.md](10-纯算法/去混淆实战.md) || 8 类混淆/平坦化四路线+unicorn·angr 骨架/VMP 五步法/决策树 |
| [jsvmp与vmp-lifter实操.md](10-纯算法/jsvmp与vmp-lifter实操.md) || **lifter 实操层**:JSVMP 五件套解剖/handler 语义双路提取(静态 babel+动态差分 probe)/翻译器+重放 diff 三段咬合脚本/dex VMP 四步工程/JSVMP·dex·native VM 定位与 RPC 决策 |
| [协议脱机与RPC.md](10-纯算法/协议脱机与RPC.md) || **脱机主入口**:三级火箭/frida RPC 工程化(JS+Python 骨架)/protobuf 黑盒/防重放/JA3 保持 |
| [OLLVM原理与Pass源码.md](10-纯算法/OLLVM原理与Pass源码.md) || **混淆器生成侧**:Flattening/SplitBBlocks Pass 源码六步/指令膨胀·花指令插入/逻辑等价公式(nor 万用门)/跳转加密(Hikari vs Goron)/字符串加密三代对照+自写 Pass/arm 落地形态 |
| [混淆还原案例集-静态.md](10-纯算法/混淆还原案例集-静态.md) || **静态还原 8 案例**:花指令特征清单与 patch 脚本/Hex-Rays 两步秒 BCF/Binary Ninja 去平坦化 HLIL 提取/ARM64 专项三轮迭代/initArray 字符串解密回填/IDA&FRIDA 联调 |
| [混淆还原案例集-动态.md](10-纯算法/混淆还原案例集-动态.md) || **动态还原 7 案例**:Unicorn 反平坦化(arm32 TBB/TBH)/全指令 trace 算法 C 复刻/AES·MD5 hook 链推理/MBA 取反化简/Xposed 爆破;案例参数·hook 点·坑拿来即改 |

## 11-链路内核级

| 文件 | 什么时候开 |
|------|-----------|
| [观测点矩阵与使用路径.md](11-链路内核级/观测点矩阵与使用路径.md) || **收口:任何「在哪挂」问题先查**:35 行×7 列观测点大矩阵+20 条任务反向速查 |
| [文件与属性链路.md](11-链路内核级/文件与属性链路.md) || openat→do_sys_openat2→pagecache/proc 伪文件/属性共享内存/IO 透明解密/mmap 缺页 |
| [网络链路.md](11-链路内核级/网络链路.md) || socket/connect/send/recv/NF 五钩子/tcpdump 内核口/VPN tun/DNS |
| [binder与信号链路.md](11-链路内核级/binder与信号链路.md) || binder 双向时序/ServiceManager/ptrace/信号(SIGTRAP 自测)/exit 链 |
| [dex加载与执行链路.md](11-链路内核级/dex加载与执行链路.md) || ClassLoader→mmap→DefineClass→nterp/JIT/JNI→OAT/VDEX+版本符号差异表 |
| [进程时序与内存链路.md](11-链路内核级/进程时序与内存链路.md) || zygote fork 全时序/抢注入时序线/线程 clone/scudo/缺页与 mprotect |

## 12-绕过决策

| 文件 | 什么时候开 |
|------|-----------|
| [绕过决策手册.md](12-绕过决策/绕过决策手册.md) || **「函数被检测/思路不行了」先开这篇**:两条铁律决策树(hook 四死因/检测层决定最低可行绕法)、14 检测点×4-6 绕法矩阵(适用情况+失败特征+推荐顺序)、资源五档、「什么情况最重要」三依据、24 条失败信号速查 |

## 13-trace

| 文件 | 什么时候开 |
|------|-----------|
| [trace实战.md](13-trace/trace实战.md) || **任何「跟一下执行流/谁调用了 X/系统调用面」任务**:11 工具全景对比表(syscall/函数/块/指令层)+frida-trace·Stalker·syscall 模拟三脚本本机实测(macOS spawn 坑/控量三参数/6.5 万事件每秒上限/减速 1.48 倍等硬数字)+调用树后处理+场景决策树+trace 工具自身检测面 |

## 14-手游框架

| 文件 | 什么时候开 |
|------|-----------|
| [14-手游框架/Unity与IL2CPP.md](14-手游框架/Unity与IL2CPP.md) || **Unity 手游主入口**:判定 APK 形态→Il2CppDumper 全流程(dump.cs/IDA 挂脚本/RVA 修正)→frida-il2cpp-bridge hook 实战→mono 直接 dnSpy→global-metadata 加密变体(头校验/dump 时机/Zygisk 版)→实战三枪 |
| [14-手游框架/UE与Cocos.md](14-手游框架/UE与Cocos.md) || UE:repak/FModel 解 pak(AES key 定位)/utoc→GNames GObjects 反射 dump(UEDumper 思路)/lua 热更;Cocos:jsc 的 xxtea key 三路定位与解密/luajit 字节码反编译/opcode 魔改恢复 |
| [14-手游框架/RN与Flutter逆向.md](14-手游框架/RN与Flutter逆向.md) || RN:Hermes 版本头→hbctool 拆改回编/hermes-dec 近似源码/字符串表定位/纯 JS bundle+source map;Flutter:**blutter+dae 双工具链**(libapp.so 符号还原→frida hook dart 函数→so 层加密参数定位端到端) |
| [14-手游框架/框架检测与对抗.md](14-手游框架/框架检测与对抗.md) || 游戏专属检测:引擎完整性自检(il2cpp/pak/脚本 hash)/游戏内风控(输入流·时间戳·服务端统计)/模拟器检测为何强(传感器熵+GPU 指纹)/单机改值 vs 网游封号边界 |

## 15-游戏对抗

| 文件 | 什么时候开 |
|------|-----------|
| [反作弊对抗.md](15-游戏对抗/反作弊对抗.md) || **反作弊引擎分析(授权语境,边界声明在篇首)**:ACE 架构(驱动+用户态+云,蜜罐/DMA 对抗/预启动)/EAC·BattlEye 加载链与签名/Vanguard 等引擎判型表/通用三层原理(内核读写·混淆通信·云端行为模型)/trace 差集定位检测规则/测试机隔离(VM 检测三根源:RTC时序·GPU·固件链)/自家游戏测试交付清单/外挂制作分发法律风险明写 |

## 16-常用速查

| 文件 | 什么时候开 |
|------|-----------|
| [常用手法速查.md](16-常用速查/常用手法速查.md) || **最简单最常用的一层**:16 行功能定位大表(root/frida/签名/加密 key/壳特征…锚点+命令)/NOP 与强制返回值字节表(五架构,本机实测 12/12)/分支·smali·so 补丁实操流/10 条简单漏洞模式速查;伴生自验脚本 verify_patch.py |
| [verify_patch.py](16-常用速查/verify_patch.py) || 补丁字节自验:capstone 反汇编校验+unicorn 演示返 0→返 1(改字节表先跑它) |

## 维护约定

- 新增内容进对应分类 md(或子目录),回本目录加行;本目录不存正文
- 正文**不放外部链接/出处标注/人名/核查日期**——只有思路与代码;需要出处时走 `../data/` 语料索引
- 与 `~/.zcode/rules` 冲突时以 rules 为准
