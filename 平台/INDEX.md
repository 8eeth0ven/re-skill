# 平台分支总目录(re 单入口之一 · 只读路由)

> 用法:入口在 ../../SKILL.md 分支路由;按任务点名开 1-2 篇,禁止通读整库。本地语料(精华1-24 CHM,18915 篇)的使用入口在 `data/精华全量索引.md`;查到文章后 `7z x pediyNN.chm "pediyNN/<tid>.html" "pediyNN/<tid>" -o<目录>` 解出正文+图片(gb18030 编码,图片 Read 直接看)。
> 结构:知识库十大分类(chm.htm 树 1702 节点)+ 本地精华 1-24 全文 + 2025 精华 651 篇目录(精华26 官方未发布)

## 姊妹库(重叠互链,不重复展开)

- **Android 逆向手法**(frida/脱壳/对抗/内核级/函数全景)→ `../手法/` 分支
- **Web 漏洞测试清单**(idor/injection/csrf 等 40+ 模块)→ `~/.zcode/skills/skill/知识库/`(独立 skill)

## 01-Windows安全(10 篇,《加密与解密》体系)

| 文件 | 什么时候开 |
|------|-----------|
| [基础知识.md](01-Windows安全/基础知识.md) || 逆向通用基础:密码学识别三杀招/PE 深入/x64 汇编/虚拟内存·保护环·中断异常/调试寄存器/LLVM 混淆 |
| [基础篇.md](01-Windows安全/基础篇.md) || PE 结构全景/Windows 数据结构(PEB/TEB)/API 体系/反汇编引擎(LDE 八连帖)/静态分析 |
| [调试篇.md](01-Windows安全/调试篇.md) || WinDbg 入门-命令-脚本/调试器开发(断点/单步/SEH/VEH 异常分发)/x64dbg-Scylla/OllyDbg 体系 |
| [解密篇.md](01-Windows安全/解密篇.md) || 壳识别(150+ 外壳四层矩阵)/脱壳流程/IAT 修复/压缩壳加密壳/DUMP |
| [系统篇.md](01-Windows安全/系统篇.md) || 进程创建全链(kernel32→NtCreateUserProcess→内核→LdrpInitialize)/VAD/句柄表/SSDT/消息/NTSYS |
| [保护篇.md](01-Windows安全/保护篇.md) || 反调试矩阵(PEB/NtQIP/DRx/rdtsc/异常/Anti-OD)/花指令/SMC/壳对抗/VMProtect handler |
| [重构篇.md](01-Windows安全/重构篇.md) || 补丁四机制(文件/内存/DRx 免改字节/Frida)/SMC/DLL 劫持/二次开发 |
| [语言篇.md](01-Windows安全/语言篇.md) || Delphi/VB(P-Code/Native)/易语言(三形态,本地原文勘误)/.NET/Python(PyInstaller)/Electron/AutoIt 识别与工具链 |
| [编程篇.md](01-Windows安全/编程篇.md) || 注入 13 种(决策树+代码)/Inline Hook 自实现(trampoline)/驱动 IRP-IOCTL/Rootkit 九节/Bootkit/WFP |
| [病毒木马篇.md](01-Windows安全/病毒木马篇.md) || 分析方法论(Procmon/API Monitor/火绒剑)/银狐·LIVE·Mallox 等家族/免杀(syscall 直调/白加黑/ETW patch/AMSI)/UAC 绕过 |

### win-vuln/(Windows 漏洞挖掘专项,5 篇)

| 文件 | 什么时候开 |
|------|-----------|
| [win-vuln/PE逆向与符号分析.md](01-Windows安全/win-vuln/PE逆向与符号分析.md) | 拿到 PE/驱动要逆向:Ghidra/IDA 工作流与 headless 自动化、符号服务器全套、WinDbg KDNET 双机调试、静态→动态→POC 两条完整走例 |
| [win-vuln/驱动IOCTL审计.md](01-Windows安全/win-vuln/驱动IOCTL审计.md) | 审驱动:暴露面枚举(ACL 缺失=任意用户可开)、CTL_CODE 位拆解与 METHOD_NEITHER 语义、七条审计 checklist(正反例代码)、BYOVD 11 驱动清单、BSOD→!analyze 闭环 |
| [win-vuln/内核攻击面定位.md](01-Windows安全/win-vuln/内核攻击面定位.md) | 找面:九面全景(Win32k 回调/ALPC/内核回调/BitLocker·ARSO·Credential Guard 绕过面)、HVCI 约束下的可用原语、攻击面→漏洞密度决策树 |
| [win-vuln/内核池与CVE模式库.md](01-Windows安全/win-vuln/内核池与CVE模式库.md) | 要利用:池布局四代演进+Win11 隔离影响、池风水原语史、任意写→提权三条路、18 个 CVE 逐条核实的模式库(含 PrintNightmare 全拆) |
| [win-vuln/工具链搭建.md](01-Windows安全/win-vuln/工具链搭建.md) | 落地:目标机一键 setup.ps1(WinDbg/符号/x64dbg/WinAFL/ioctlbf)、macOS 本机能做什么、10 分钟自检清单 |

## 02-Android安全(4 篇;核心逆向见 手法库(同 skill re/手法))

| 文件 | 什么时候开 |
|------|-----------|
| [Android知识体系总览.md](02-Android安全/Android知识体系总览.md) || **本区入口**:23 个二级分类逐一去向(85 处互链 手法库);Hook/脱壳/加固/抓包全去 手法库,编程/编译器/格式留本区 |
| [编译器与系统体系.md](02-Android安全/编译器与系统体系.md) || javac→d8/r8→dex2oat→JIT/nterp 全链/SELinux 策略/seccomp(app 域封 io_uring 实证)/binder/ROM-root-Magisk |
| [文件格式详解.md](02-Android安全/文件格式详解.md) || dex header 逐字段/class_data 差分编码/code_item+SHA-1·Adler 修复铁律/ELF-GOT-PLT/oat·vdex·cdex/AXML·arsc/七格式对比 |
| [恶意样本与CTF.md](02-Android安全/恶意样本与CTF.md) || 三大流派/Joker·Anubis·SpyNote 家族/实战案例/CTF 五族题型+解题流水线 |

## 03-Linux平台(2 篇)

| 文件 | 什么时候开 |
|------|-----------|
| [Linux安全.md](03-Linux平台/Linux安全.md) || ELF 详解(段节/重定位/GOT-PLT 延迟绑定手推图/dlopen 内部)/GDB+GEF 选型与 python 自动化/ptrace 反调试四板斧/ELF 病毒四型/Mirai/Qiling-Unicorn |
| [其他平台.md](03-Linux平台/其他平台.md) || macOS(Mach-O 对照/Hopper)/docker 逃逸五型/历史平台(Symbian/WinCE/黑莓/DOS) |

## 04-iOS安全(2 篇)

| 文件 | 什么时候开 |
|------|-----------|
| [iOS逆向体系.md](04-iOS安全/iOS逆向体系.md) || Mach-O(LC_ENCRYPTION_INFO/CryptID)/OC 运行时(objc_msgSend 汇编)/Swift/砸壳四工具/fishhook 重绑/越狱代际(unc0ver→Dopamine rootless)/theos Tweak |
| [iOS攻防与进阶.md](04-iOS安全/iOS攻防与进阶.md) || 反调试(sysctl P_TRACED/PT_DENY_ATTACH)×绕法速查/越狱检测 6 类+frida 绕法(本地原文)/加固矩阵/汉化五步 |

## 05-macOS安全(2 篇,2026-10 新建;编号与 05-WEB并行,按名取用)

| 文件 | 什么时候开 |
|------|-----------|
| [macOS逆向与攻击面.md](05-macOS安全/macOS逆向与攻击面.md) || **mac 独立区主篇**:Mach-O 实操(otool/nm/codesign 本机实测)/dyld 注入三组对照(DYLD_INSERT+平台二进制豁免)/r2·LLDB 实测流程(thread return 绕校验)/TCC 双库·XPC 端点枚举(launchctl)·持久化·公证/Gatekeeper/加固(Swift/Metal/公证 hash)/EDR on mac |
| [鸿蒙HarmonyOS.md](05-macOS安全/鸿蒙HarmonyOS.md) || hap 格式(签名 zip/模块结构)/ArkTS·方舟编译器 abc 字节码/工具现状(abc-decompiler·abc2txt)/与 Android 概念映射表/软总线·元服务攻击面/PSIRT 报送/待核清单 |

## 05-WEB安全(2 篇;漏洞测试清单见 skill 知识库)

| 文件 | 什么时候开 |
|------|-----------|
| [WEB安全体系.md](05-WEB安全/WEB安全体系.md) || 渗透全流程+工具链/20 子漏洞类总表(互链)/H2-H3-WebSocket-GraphQL/WAF/应急响应(内存马排查) |
| [代码审计.md](05-WEB安全/代码审计.md) || 污点方法论/Java(Struts·Spring CVE 模式/Shiro·Fastjson 演进线,CC1·Fastjson 本地原文)/PHP·Python·.NET/diff 找 0day/CodeQL |

## 06-二进制漏洞(3 篇,本地精华语料 183 篇引用)

| 文件 | 什么时候开 |
|------|-----------|
| [堆利用与防护.md](06-二进制漏洞/堆利用与防护.md) || glibc chunk/bin 谱系/tcache 2.26→2.32 演进/**house of 13 式对照表**(本地原文,堆布局 ASCII)/FSOP 三代/防护绕过/ROP·SROP·BROP·dlresolve |
| [漏洞类型与利用.md](06-二进制漏洞/漏洞类型与利用.md) || V8 六 CVE 模式(对象伪造/hole/TC)/Linux 内核(DirtyPipe·DirtyCred·22555)/Windows CSC/WinRAR·Office/VMware/Fuzzing 七引擎/Exp 编写 |
| [CTF体系.md](06-二进制漏洞/CTF体系.md) || KCTF 赛制/2023-2024 年度题目技术点表/PWN-逆向方法论 |

## 07-智能设备(已拆多级:iot/ 与 无线硬件/ 子目录,按需点名)

### iot/(6 篇)

| 文件 | 什么时候开 |
|------|-----------|
| [iot/攻击面与信息收集.md](07-智能设备/iot/攻击面与信息收集.md) || IoT 攻击面全景/信息收集第一步 |
| [iot/固件提取.md](07-智能设备/iot/固件提取.md) || 五路提取:uboot console/SPI flash/后门账号/厂商工具 |
| [iot/固件解密.md](07-智能设备/iot/固件解密.md) || D-Link 系加密固件解密思路 |
| [iot/固件仿真.md](07-智能设备/iot/固件仿真.md) || FirmAE/FAT/Qiling 仿真与救活技巧 |
| [iot/路由器实战.md](07-智能设备/iot/路由器实战.md) || CVE 命令注入矩阵+六篇实战流程(华为 HG532/思科全坑流等) |
| [iot/协议与服务.md](07-智能设备/iot/协议与服务.md) || MQTT/CoAP/Mirai/工控 |

### 无线硬件/(7 篇)

| 文件 | 什么时候开 |
|------|-----------|
| [无线硬件/硬件接口.md](07-智能设备/无线硬件/硬件接口.md) || UART/JTAG/SPI/I2C 引脚识别 |
| [无线硬件/RFID与NFC.md](07-智能设备/无线硬件/RFID与NFC.md) || M1 卡加密体系/全加密卡沦陷/离线爆破 |
| [无线硬件/WiFi安全.md](07-智能设备/无线硬件/WiFi安全.md) || KRACK/WPS/固件漏洞 |
| [无线硬件/BLE与Zigbee.md](07-智能设备/无线硬件/BLE与Zigbee.md) || BLE 手环认证绕过/Zigbee 入门 |
| [无线硬件/SDR与无线.md](07-智能设备/无线硬件/SDR与无线.md) || SDR 工具链/重放/伪基站 |
| [无线硬件/汽车安全.md](07-智能设备/无线硬件/汽车安全.md) || CAN/UDS/滚动码 |
| [无线硬件/BIOS与UEFI.md](07-智能设备/无线硬件/BIOS与UEFI.md) || 启动链/Secure Boot |

### 区级

| 文件 | 什么时候开 |
|------|-----------|
| [IoT与固件安全.md](07-智能设备/IoT与固件安全.md) || 导航壳(指到 iot/ 各篇) |
| [硬件与无线.md](07-智能设备/硬件与无线.md) || 导航壳(指到 无线硬件/ 各篇) |
| [CTF-writeup方法论.md](07-智能设备/CTF-writeup方法论.md) || Pwn 决策树/堆攻击史/KCTF 攻防/五题型速查 |

## 08-业务安全(1 篇)

| 文件 | 什么时候开 |
|------|-----------|
| [业务安全.md](08-业务安全/业务安全.md) || 逻辑漏洞体系(互链 skill)/账号·支付安全/风控(互链 手法库 设备指纹)/数据合规/SRC 定级/黑灰产图谱 |

## 09-AI安全(1 篇)

| 文件 | 什么时候开 |
|------|-----------|
| [AI安全.md](09-AI安全/AI安全.md) || LLM 三层攻击面/提示注入(直接·间接·多模态)/Agent 工具滥用(Tool Poisoning·Rug Pull·Lines Hopping)/OWASP LLM Top10 2025/RAG 投毒·模型窃取/AIxCC/KernelGPT·DeepZero/MCP 攻击面/guardrails/GitHub MCP 事件复盘 |

## 10-区块链安全(2 篇)

| 文件 | 什么时候开 |
|------|-----------|
| [区块链安全.md](10-区块链安全/区块链安全.md) || 合约十大漏洞(重入·闪电贷·预言机·MEV,The DAO·Bybit $1.5B)/审计工具矩阵+逐函数清单/貔貅·Rug 识别/混币与追踪/跨链桥五案/涉币取证 |
| [AI与区块链交叉安全.md](10-区块链安全/AI与区块链交叉安全.md) || Freysa 提示注射/Truth Terminal/Agent 发币 Rug 面/预言机+zkML |

## 11-漏洞根因学(根因视角)

| 文件 | 什么时候开 |
|------|-----------|
| [内存错误根因总论.md](11-漏洞根因学/内存错误根因总论.md) || **根因视角**:六大类内存错误(栈/堆/UAF/double-free/竞态/类型混淆整数)每类=代码模式逐行讲+ASCII 内存图+为什么编译器运行时拦不住+演化链+判例;缓解措施本质(NX/ASLR/Canary/CFI/MTE/PAC/Safe-Linking 各挡一类);20 CVE 判例索引表。利用手法互链 06 |
| [内核漏洞根因案例.md](11-漏洞根因学/内核漏洞根因案例.md) || **内核逐案深挖**:DirtyPipe/22555/2588+DirtyCred/unix_gc/binder 2215+2020-0423/futex 3153/cldflt 36036+26229/0995/DirtyCOW 十案,每案=源码片段(标版本)+假设被打破点+竞态窗口+原语化+修复 diff;末节 12 模式根因表(smell+审计法)。十案全录 |
| [用户态运行时根因.md](11-漏洞根因学/用户态运行时根因.md) || JIT 为什么出洞(TurboFan 去优化假设/Map 欺骗/BCE·Typer·竞态三类,本地 V8 帖 6+ 篇)、反序列化=执行代码的机制、堆管理器可利用的设计权衡(元数据与数据同堆/tcache LIFO)、托管内存为何仍不安全(JNI 边界/dex 可 dump 的信任边界)、运行时根因五模式判例表 |
| [注入与逻辑根因.md](11-漏洞根因学/注入与逻辑根因.md) || 注入的本质=解释器边界(SQL 解析器图解/参数化为什么根治)、九类注入面各自根因、SSRF=TOCTOU 网络版、逻辑洞五类「开发者心智模型 vs 实际语义」对照(IDOR=行级属主架构缺失)、权限模型三层失效 |
| [根因手法映射表.md](11-漏洞根因学/根因手法映射表.md) || **收口篇**:25 根因×出错模式/演化原语/利用手法(库内出处)/根因检测(grep 模式)/根治方案总表;七栈(内核 C/Java/V8/合约/Go/IoT)审计 grep 清单;缓解措施消亡史 |

## data/(语料索引,subagent 可直接用)

| 文件 | 说明 |
|------|-----------|
| `精华全量索引.md` | **精华 1-24 全量 18915 篇目录**(2000-2023),按标题 grep→拿 pediyNN+路径 |
| `精华26索引.md` + `_原始.jsonl` | **2025 年度精华 651 篇目录**(tid 边界 285073~289632 精确无漏;精华26 官方未发布,预计 2026 Q4,见获取报告) |
| `digest_crawl.py` | 可重跑增量爬虫(state+限速+429 退避),精华26 发布后重跑即得全量 |
| `完整目录树.md` / `tree.json` | 知识库 chm.htm 树 1702 节点(十大分类骨架) |
| `精华26获取报告.md` | 五途径结果/接口参数/chm-search 用法/盯发建议 |

## 维护约定

- 新增内容进对应区 md,回本目录加行;本目录不存正文
- 正文不放外部链接/出处标注/人名/核查日期,只有思路与干货;需要语料出处走 data/ 索引
- 图片:解出本地原图后 Read 查看,转 ASCII/文字入库标「本地原图已解析」;纯线上帖标「已文字还原」
- 与 `~/.zcode/rules` 冲突时以 rules 为准
