# Android 恶意样本与 CTF — 家族实战 + 案例 + 题型套路

> 对应树节点:病毒木马[1000957](病毒分析[1001653]/木马分析[1001654]/恶意软件[1001655]) + CTF[1001296]

## 1. Android 恶意样本全景:三大变现流派 + 附加类

| 流派 | 变现 | 代表家族 | 共同手法 |
|---|---|---|---|
| **费流量** | 后台刷广告/隐藏浏览/点击墙 | ExpensiveWall(2017 Google Play 数百 app;Check Point 确认其为 JiPi 家族新变种,JiPi 2017 年初现于 Google Play,高价 SMS/WAP 订阅欺诈,见 research.checkpoint.com/2017/expensivewall)、稻草人系 | 静默下载非展示加载网页/广告;设备解锁触发 |
| **扣费** | 短信订购/订阅服务/WAP 扣费 | **Joker**(Google Play 常年反复上架)、Ars blatant、xHelper、Faketoken | 隐蔽窗口执行运营商付费页;拦截/删除确认短信 |
| **间谍** | 全量窃密/监听/定位 | **SpyNote**、Anubis、Cerberus、RatMilad、商业 stalkerware | 无障碍/设备管理员提权;键盘记录;截屏;通讯录/SMS/GPS 外传 |
| 附加:银行木马 | 覆盖钓鱼+短信劫持 | Anubis、Ginp、EventBot(2020-04 首现,200+ 欧美金融 app,滥用 accessibility 服务窃凭证+SMS 2FA,MITRE S0478;近年式微,被 Anatsa/Hydra/TeaBot 接棒) | overlay 注入(floating window 盖登录页) |
| 附加:勒索/挖矿 | 锁屏勒索/挖矿 | Lockdroid 系、隐匿挖矿(Kryptowire 通报多起) | 设备管理员锁屏;后台 service 挖 XMR |

> 分类学参考:ACM 2025 研究统计 **384 个** Android 恶意家族、按行为 11 类(链接见 §5)——上表是逆向视角的工程化压缩。

### 1.1 家族深挖要点(分析时的「签名」)

- **Joker(FDP/Dropper)**:小马拖大马——宿主只做下载器,payload 动态拉取后反射加载隐藏 dex;**自动向 WAP/运营商页发起付费订阅并隐藏通知**。识别特征:assets 隐藏 dex/BBC 压缩 blob、`Class.forName` 反射链、对 `NotificationListenerService` 的滥用(拦确认短信)。学术取证:Iowa State 2021(链接 §5)。
- **Anubis(银行木马+RAT)**:overlay 钓鱼(监测前台 app 弹伪造登录)、键盘记录、SMS 拦截、加密货币钱包劫持、C2 over Tor(部分样本)。Malpedia 收录apk.anubis(链接 §5)。注意:2025 年 Trend 报的同名「Anubis」是**勒索 RaaS 组织,与 Android 家族无关**,情报别混。
- **SpyNote(SpyMax 同源)**:商业 RAT 泄露源码后泛滥——APK 伪装正常应用,申请无障碍+设备管理员+通知监听;功能面:实时屏幕/摄像头、录音、文件管理、短信通讯录窃取、shell。2024-2025 持续活跃:Cyfirma 2024 深度分析、Fortinet 2024 报其转向**加密货币钱包窃取**、DomainTools 2025 追踪同一威胁者基础设施重启(链接 §5)。样本多为 **无加固+明文 C2**(商业化产物不设防),分析门槛低,适合练手。
- **银狐系**(社区热帖):Windows 为主的家贼系木马(社工伪装聊天/办公软件),极致反沙箱;winos4.0 有源码拆解帖——Android 侧多为**下载跳板**(诱骗页引导装 APK),分析时抓「下载链+包名伪装」即可。
- **挖矿/远控杂类**:`DebugBlocker 样本`(反调试样本)、ELF 数据段注入病毒(Android/类 Unix ELF 感染,少见)、白象/Kimsuky APT 的移动端组件(间谍流派,定向)。

### 1.2 实战案例(2024 年度)

| 案例 | 日期 | 逆向要点 |
|---|---|---|
| 某虚假交友 APP(信息窃取)逆向分析 | 2024-03 | 交友诈骗 App 窃密行为全流程:假人设诱导→通讯录/SMS 窃取→上吊后台 |
| 一次诈骗 APP 的逆向分析 | 2024-07 | 诈骗 App 通信协议与后台还原——**情报反打**思路(拿 C2/管理端) |
| Discord Stealer | 2024 | Discord token/浏览器凭据窃取木马分析 |
| 银狐系列(极致反沙箱/winos4.0 源码) | 2024 | 反沙箱手法大全+源码拆解 |
| Solar 安全勒索家族专题(BabyK/Mallox/Phobos…) | 2024 | 多为 PC 端,Android 侧作对照 |
| 利用 CVE-2024-0044 获取应用数据 | 2024-07 | RunAnyApp UAF 越权(漏洞面,与恶意软件配合的提权组件) |

## 2. 恶意样本分析流水线(树 病毒分析[1001653] 方法论)

```
样本(APK) ──APKiD──> 家族/壳/编译器指纹
   │
   ├─ 静态:jadx 看 Manifest(权限/组件/无障碍/设备管理员)
   │        strings/URL/IP;assets/lib 里藏 payload;arsc 资源名
   │
   ├─ 动态:模拟器/root 真机跑(Burp/mitm 抓 C2 流量)
   │        frida hook 网络/文件/SMS/Telephony 面(复用 手法库 速查)
   │
   ├─ 行为面四查:①AccessibilityService 滥用 ②DeviceAdmin/锁屏 ③
   │   NotificationListener(拦短信) ④FloatingWindow/overlay(钓鱼盖层)
   │
   └─ 产出:IOC(C2 域名/证书/密钥)+行为报告+检测特征(YARA)
```

- **第一步 APKiD**(包装识别):互链 手法库 `05-工具矩阵/专项与信息收集.md`(接手陌生 APK 第一分钟全套)。
- **DroidLysis/UltraSina**:纯设备端静态套件,免环境依赖。
- **沙箱自建**:树「分析系统/TaintDroid[1001642]」=改 AOSP 污点跟踪的学术系沙箱(标记敏感数据流向,现代替代为 frida + LSPosed 系自建 tracing,以及 2024 年兴起的 Android eBPF 沙箱系列帖)。
- 行为四查的 hook 点全部在 手法库 `02-frida/java层/` 系列(存储与系统/网络与webview:无障碍/短信/网络面),不重复。

## 3. 情报反打与取证要点(树 病毒分析/木马分析)

- **C2 情报**:抓包拿 C2 域名→证书/JA3→反查基础设施(SpyNote 案例即 DomainTools 路数);诈骗 APP 案例的「后台还原」=顺管理端打(在授权/移交执法语境)。
- **取证链完整性**:hash 记录→沙箱行为留痕→frida hook 日志落盘;样本存储隔离(标本目录只读)。
- **检测特征产出**:per-family YARA(dex 字符串/so 常量/证书指纹);树「病毒查杀」类思路在 Windows 区同理复用。
- 伦理边界:仅授权应急/研究语境;样本不落地生产网。

## 4. Android CTF 题型与套路(树 CTF[1001296])

### 4.1 题型五族

| 族 | 特征 | 破法主线 |
|---|---|---|
| **Java 层逻辑** | jadx 打开即逻辑:字符串加密、简单算法、校验函数 | 静态读懂+frida 改返回值;或 smali patch 重打包(树「软件破解」手法的赛场版) |
| **so 逆向** | 关键校验在 native:JNI_OnLoad 动态注册、自实现算法 | IDA/Ghidra 定位 RegisterNatives→逆向函数;frida 主动调用加速 |
| **VMP** | dex 方法标记 native/空壳,壳自带解释器 | 还原三件事:**重排 JNIEnv + 操作码置换表 + 字节码解密**(dex vmp 帖方法论) |
| **反调试/反注入** | ptrace 自附加、TracerPid、frida 端口/线程名检测、多进程互护 | 定位检测点 patch;或调试器层绕(见 手法库 检测原理全景) |
| **组合壳** | 加固+抽取+so 加密三层套 | 分层剥:先脱壳(03 区方案)→再修 dex(文件格式篇 §1 修复铁律)→再逆算法 |

### 4.2 解题流水线(从拿 APK 到 flag)

1. **安装包体检**:APKiD 查壳→aapt2 看 Manifest(调试位 `debuggable`?导出组件?)→jadx 全局搜 `flag`/`check`/`verify`。
2. **定位关键函数**:字符串 xref、按钮 onClick、native 方法名(`Java_com_xxx` 或 RegisterNatives 表)。
3. **算法分析**:常量表识别(AES S-box/TEA delta 0x9E3779B9/RC4 KSA 特征)——算法指纹库互链 手法库 `10-纯算法/纯算还原方法论.md`。
4. **动态验证**:frida hook 中间值+主动调用比对;复杂 so 上 unidbg 模拟(手法库 `05-工具矩阵/模拟执行框架.md` 补环境坑清单)。
5. **收口**:静态还原算法本地算 flag(纯算路)或直接 patch 校验(破解题)。

### 4.3 赛事与代表帖(社区侧)

- **KCTF 攻防大赛**:安卓题常与 so/native 混合;2024 第八题「星门」= **Ptrace 绕 Seccomp**(seccomp 对抗教科书);第二题「星际生物」以 ChatGPT 辅助逆向为亮点(约 7 篇 wp)。
- **腾讯游戏安全竞赛(安卓方向)**:2024 决赛安卓解题报告(cslime 2024/04/22)、2022 复盘(xi@0ji233)、历年复现集(螺丝兔/Kvancy 4 篇)——反作弊对抗向,与 CTF 逆向互为镜像。
- **2015MSC 移动安全竞赛[1001272]**(树内):早期移动赛考古。
- 《安卓逆向这档事》系列:新手路线图即此——从装机到六边形全链约 22 课+番外。
- dex VMP 还原方法论帖(star,2025-01,「VM 逆向一篇就够了」同作者系)。
- 「星门」wp(2024-09:Ptrace 截停 prctl 改无关调用绕 seccomp);《安卓逆向这档事》系列(第十三/十四/二十三课);ebpf 在 Android 安全上的应用(上篇);《AutoIT FUD Crypter样本的分析》、《一个AutoIt盗号木马》(跨平台样本参考)。

### 4.4 CTF 与实战的能力映射

| CTF 技能 | 实战(Android 安全岗/红队) |
|---|---|
| VMP 还原 | 商业加固 dex VMP 分析(算法保护) |
| 反调试绕过 | 风控/反作弊对抗(手法库 04 区全套) |
| so 算法逆向 | 协议签名还原(SRC/风控) |
| 壳剥离 | 样本分析、爬虫目标解包 |
| Seccomp/Ptrace | 内核攻防(07 区) |

## 5. 参考资料定位

- 家族情报:Malpedia / Cyfirma / Fortinet / DomainTools 各家族专页
- 家族分类学综述:ACM 2025(384 家族)、MDPI 2020
- 工具状态注:oatdump `--export-dex-to` 已移除,新走 vdexExtractor;vdex 版本-Android 对应、xHelper/JiPi/EventBot 家族近态以 AOSP 源码与 Malpedia 为准。
