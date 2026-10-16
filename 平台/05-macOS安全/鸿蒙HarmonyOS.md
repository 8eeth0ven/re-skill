# 鸿蒙 HarmonyOS 逆向与攻击面(平台/05-macOS安全/鸿蒙HarmonyOS)

> 定位:鸿蒙独立篇(原收纳于"其他平台",现升独立节)。hap 格式/ArkTS·方舟编译器字节码/签名调试/工具现状/与 Android 互操作/攻击面(分布式软总线·元服务)/漏洞报送。
> 亲缘:应用层血统=Android(HAP≈APK 变体,签名/权限/分发同构),语言层血统=JS/TS 生态(abc 字节码≈闭源版 V8 bytecode)。Android 手法库大量可平移 → `../../手法/`(frida/对抗/抓包)。
> 现状声明:鸿蒙生态闭源成分重、公开逆向工具链成熟度远低于 Android,**工具条目标「待核」的用前自验**;本篇框架先行,条目随生态演进填。

## §1 生态与版本速览

- 双线:**OpenHarmony**(开源基金会,设备侧主线)+ **HarmonyOS NEXT**(华为商用,5.0 起去 AOSP 兼容层,纯鸿蒙,2024 商用)。老版本 HarmonyOS(4.x 及以前)= AOSP 底 + 鸿蒙框架,**本质还是 Android,全部 Android 手法直接适用**;只有 NEXT 才是"新平台"。
- 目标形态:手机/平板/穿戴/车机/智慧屏/IoT 模组;内核 Linux kernel(LM)/LiteOS-A/M(轻量设备)。
- 应用类型:**HAP**(主形态,Ability 包)/**元服务**(免安装原子化服务,卡片入口)/快服务。

## §2 HAP 格式拆解

### 2.1 包结构

HAP = **签名 ZIP**(与 APK 同理,直接 unzip):

```
xxx.hap (zip)
├── pack.info                 # 打包元信息(module 列表)
├── module.json               # ≈ AndroidManifest.json:ability/权限/API 版本
├── assets/ 或 ets/           # 前端资源
│   └── modules.abc           # ★ ArkTS 编译产物(方舟字节码,本篇主角)
├── libs/{arm64-v8a,...}/     # native .so(NAPI,C/C++ 产物,标准 ELF)
│   └── libentry.so / libace_napi.z.so ...
├── resources/                # 资源索引(resources.index)
└── META-INF/                 # 签名块(CERT.SF 系,华为证书链)
```

配套包:.har(静态共享包,≈AAR)、.hsp(动态共享包)、.app(多 HAP 聚合上传格式)。Entry 类型 HAP 必有一个;Feature 类型可拆装。

### 2.2 签名与分发

- 签名链:调试证书(DevEco 申请)/发布证书(华为 AGC 平台签发)——双证书+Profile 文件(≈Android 的签名 + 描述文件,类 iOS provisioning 思路);
- 系统强制校验签名才可装(hdc install 同样过校验);**重打包=必须重签**,流程与 Android 重签同型(替换签名块+zipalign 对应步骤),但证书获取门槛高于 Android 自签;
- 分发面:AppGallery(华为商店)唯一合法渠道,sideload 需开开发者模式(与 iOS 侧载现状更接近)。

## §3 ArkTS 与方舟编译器(ArkCompiler)

### 3.1 编译链

```
ArkTS(.ets) → [ArkTS 编译器(tsc 扩展)] → 方舟字节码 .abc(Panda/Ark IR)
                                   └→ AOT/JIT 运行时:方舟 RTS(ArkCompiler Runtime,ets_runtime)
C/C++ → NAPI → .so(ELF,标准工具链,但链接 bionic 替代品 musl 系)
```

- `.abc` 文件:魔数 `pandasm`/`0sA0` 系标识 `[待核:当前版本魔数]`,内含字面量池+记录(record≈class)+方法字节码;
- 字节码 ISA:方舟自研指令集(寄存器机,带累加器 acc),与 Dalvik 差异大,但**顶层概念可映射**:record↔class、method_id↔method idx、字符串池同型;
- 运行时双模式:解释器(字节码)+ AOT(机器码缓存);**AOT 缓存是分析捷径**:真机上 dump 出 AOT 后的机器码可直接进 IDA/Ghidra 走 ARM64 流程。

### 3.2 abc 逆向工具现状(2026)

| 工具 | 形态 | 现状 |
|---|---|---|
| abc-decompiler | GUI 反编译器(JEB 风格 fork) | 社区开源项目,abc→伪代码/汇编,活跃度一般 `[待核:最新版本兼容性]` |
| abc2txt / ark_disasm | 字节码 dump 工具 | 随 DevEco/OpenHarmony SDK toolchains 分发(pandasm 工具链),吐指令+字面量数组,无伪代码 |
| DevEco Studio | 官方 IDE | 附带 toolchains(签名/对齐/hdc);分析第三方 hap 需配 abc2txt 辅助 |
| jadx/JEB | — | **不支持 abc**(只吃 dex);Android 老工具链不通用 |
| IDA/Ghidra/r2 | native .so | 完全适用(NAPI so 是标准 ELF);abc 本体不支持 |

实操链:`unzip hap → abc2txt modules.abc`(或 abc-decompiler 开 GUI)→ 按 record/方法名定位业务逻辑 → 混淆则配合字面量池字符串锚点;核心算法(加解密/协议)大概率在 .so,回到 ELF 常规流(frida hook NAPI 导出函数同样适用)。

### 3.3 混淆与加固

- 官方工具链自带混淆(名称混淆/属性混淆,DevEco 配 obfuscation 规则),效果≈Android ProGuard 级;
- 商业加固(梆梆/爱加密/腾讯乐固等)已出鸿蒙版,形态≈加壳 abc + so 壳,对抗手法预期与 Android 脱壳同思路(运行时 dump abc/绕过壳校验),**公开成熟方案少** `[待核]`;
- 反调试/反 frida:NAPI so 层的对抗直接复用 Android 手法库(frida反检测对抗.md);abc 层的完整性自校验=运行时校验字面量/字节码哈希,Hook 点在 RTS。

## §4 签名、调试与真机分析

- **hdc**(HarmonyOS Device Connector,≈adb):`hdc list targets / hdc shell / hdc install xxx.hap / hdc file send`;调试走 hdc + DevEco 的 DAP 调试协议;
- **HDC 调试协议**:基于 HDC Server(USB/TCP),协议有公开逆向分析(社区有 hdc 协议解析文章),可自写自动化客户端;
- 真机调试态:hap 带 `debuggable` 标志+调试 Profile 才可断点;**非 debug 的第三方 app 只能走动态注入路线**(工具现状:`[待核]`,鸿蒙上 frida 官方不支持,社区有移植尝试——hdc 侧载+符号工具的生态远不如 Android);
- 模拟器/云真机:DevEco Profiler + 本地模拟器(arm/x86 镜像)是低成本动态环境;真机群用华为云调试。

## §5 与 Android 的互操作

| 层面 | 现状 |
|---|---|
| 老版本兼容 | HarmonyOS 4.x 及以前带 AOSP 框架,APK 直接装,Android 手法全适用 |
| NEXT 断代 | NEXT 移除 AOSP/APK 运行能力;**"出境转换"官方工具**(方舟转译器等)可将 Android app 转鸿蒙原生,转换产物的 abc 可反推原 dex 结构逻辑(混淆映射同源) |
| 工具平移度 | so 层≈100%(ELF/ARM64/NAPI≈JNI);abc 层≈0%(新字节码);签名/分发思想≈iOS(严管)>Android |
| 双框架 app | 同一 app 出 Android+鸿蒙双包,密钥/协议常同源——**打鸿蒙包不通时切 Android 包逆向再回灌**,是当前性价比最高的路线 |

## §5.1 概念映射表(Android → 鸿蒙)

| Android | 鸿蒙 | 差异要点 |
|---|---|---|
| APK | HAP | 都是签名 zip;HAP 多 Profile 文件层 |
| Activity/Service | UIAbility/ExtensionAbility | Ability 模型,生命周期回调名不同 |
| AndroidManifest.xml | module.json | 结构化 json,字段名可读性更好 |
| JNI | NAPI | 接口集不同(node-api 血统),so 常规 ELF |
| dex | abc(方舟字节码) | 新 ISA,需 abc2txt/abc-decompiler |
| ART(解释+AOT) | ArkCompiler RTS(解释+AOT/JIT) | 双 AOT 缓存可 dump |
| Binder IPC | RPC/软总线 + SAMGR 服务注册 | 无 binder,嗅觉换服务注册表 |
| adb | hdc | 命令风格近,协议独立(有社区逆向) |
| Play Store | AppGallery | 分发单渠道,sideload 要开发者模式 |
| dex 混淆(ProGuard) | SDK 自带 obfuscation | 名称/属性混淆同型 |
| 加固(梆梆等) | 鸿蒙版加固 | 鸿蒙版公开方案少 `[待核]` |

## §5.2 与 iOS 的对照(为什么"像 iOS"的部分)

- 签名严管:发布证书由厂商平台签发+Profile 描述文件机制 ≈ provisioning;
- 侧载受限:开发者模式+证书过期机制,生态封闭度介于 Android/iOS 之间偏 iOS;
- 分析启示:iOS 的签名/重签/越狱检测对抗经验(→ `../04-iOS安全/`)比 Android 经验更可平移到 NEXT 的签名与调试对抗。

## §6 攻击面

### 6.1 分布式软总线(SoftBus)

鸿蒙标志特性=跨设备组网(手机/平板/车机/穿戴自动发现互联),攻击面:
- 发现协议:Wi-Fi CoAP/组播广播,`[待核:当前版本发现协议栈细节]`;
- 认证:设备间可信组网(HiChain/设备认证),历史公开研究集中在**未认证发现面与认证绕过**;
- 跨设备调用(分布式任务调度/跨端迁移):权限模型跨设备后的语义边界(IDOR 思路:对端设备 ID 是否充分鉴权)是逻辑洞高发区;
- 工具:OpenHarmony 开源仓库(软总线模块源码可读)——闭源 NEXT 与开源版本有分叉,审计以开源版为认知底、真机行为为校验 `[待核:NEXT 软总线与开源版差异度]`。

### 6.2 元服务(原子化服务)

- 免安装、卡片即用:分发校验弱于完整 app 的假设要实测;服务卡片的数据通道(卡片刷新接口)是逻辑面;
- 元服务包体限制下业务薄、逻辑常在云端 API——**打服务端接口+卡片客户端参数篡改**是主路线(接口安全矩阵 → skill 知识库 api-pentest)。

### 6.3 其他面

- Web 组件:ArkWeb(内核血统 Chromium),Web 漏洞研究平移;JS bridge(postCardAction/javaScriptProxy)注入面;
- IPC:软总线上层+本地 IPC(HiView/服务注册),**没有 Binder**——Android 的 binder 嗅觉要换到服务注册表(SAMGR)面;
- 内核:Linux LM 的内核洞研究=Linux 流程(GKI 差异:华为维护分支);LiteOS 侧/IoT 模组 → `../07-智能设备/` 互链。

## §7 漏洞报送(HarmonyOS PSIRT)

- 入口:华为产品安全应急响应团队(PSIRT)官方漏洞提交渠道(华为官网 security 华为 PSIRT 页),邮箱 psirt@huawei.com `[待核:当前提交流程/SLA]`;
- 范围:HarmonyOS(含 NEXT)/OpenHarry/华为设备预装软件;**开源 OpenHarmony 洞同时可走 OH 社区安全流程**(SIG-Security);
- 报告格式遵循库规范两张表(vuln-report-format.md),HarmonyOS 专属要素:系统版本(Build 号)/设备型号/复现 hdc 日志;
- SRC 视角:华为漏洞奖励计划(与 PSIRT 一体),鸿蒙 NEXT 新面(软总线/元服务/方舟运行时)单价高于成熟 Android 面。

## §8 快速上手 checklist(拿到一个 hap 的前十分钟)

```
1. file xxx.hap → unzip -d hap_out/                     # 解包
2. 读 module.json:ability 清单/权限列表/debuggable 标志
3. ls libs/*/ → .so 清单(第三方 SDK 指纹:加固/风控/统计)
4. abc2txt assets/ets/modules.abc > abc.txt             # 字节码 dump(或 abc-decompiler)
5. grep 字符量池:url/key/token/签名盐 → 定位网络与加密层
6. .so 进 IDA/r2:NAPI 导出(napi_module_register 起)→ 常规 ELF 流
7. 动态:DevEco 模拟器装包 + hdc 日志;抓包先试系统代理(ohos 支持 HTTP 代理设置)
8. 不通 → 切同 app Android 包逆向(双框架同源),结论回灌
```

## §9 开源认知底:OpenHarmony 仓库怎么用

闭源 NEXT 的黑盒研究,以开源版做认知底再 diff 校验:

| 仓库模块 | 分析什么 |
|---|---|
| ark/compiler(ark_runtime) | abc 格式/ISA 定义/解释器实现——逆向 abc 的权威参照 |
| foundation/communication(dsoftbus) | 软总线发现/认证/组网协议——攻击面审计的源码底 |
| security(设备认证/HiChain) | 可信组网认证流——绕过研究的参照实现 |
| startup(应用框架) | app 启动/签名校验链——重签与调试对抗的依据 |

用法两步:①在开源码里定位目标机制(如签名校验函数)→②真机(NEXT)行为对照(是否同型/有无加严)。分叉处即研究增量。

## §10 待核清单(生态快变,用前自验)

| 条目 | 不确定点 | 验证方法 |
|---|---|---|
| abc 魔数/格式版本 | NEXT 大版本是否改格式 | 任一 DevEco 编译产物 hexdump 头 |
| abc-decompiler 兼容性 | 对 NEXT 新指令的覆盖 | 拿最新 hap 试 dump |
| 鸿蒙版 frida/注入工具 | 社区移植可用性 | ohos 真机+hdc 侧载实测 |
| 软总线发现协议细节 | NEXT 与开源版分叉度 | 抓包+开源码对照 |
| PSIRT 报送入口/SLA | 流程是否调整 | 官网 security 页复核 |
| 官方"出境转换"工具能力 | 转换覆盖面(ABI/JNI/混淆) | 双包 diff 验证 |
