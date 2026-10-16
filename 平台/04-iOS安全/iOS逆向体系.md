# iOS 逆向体系(Mach-O / 运行时 / 砸壳 / 调试 / Hook / 签名 / 越狱与 Tweak)

> 知识库 04-iOS安全 · 第 1/2 篇。第 2 篇:[iOS攻防与进阶.md](iOS攻防与进阶.md)(反调试/越狱检测/加固/恶意程序/协议/内核/汉化)。
> 跨平台互链:Android 侧方法论见 `re/手法/`(Frida 速查/脱壳/对抗攻防),重复内容本文只给锚点不展开。

## 1. 总览:iOS 逆向技术栈全景

iOS 逆向与 Android 逆向同构,差异集中在「封闭生态强约束」:App Store 分发必须签名+FairPlay 加密,系统盘只读,运行时 OC/Swift 而非 Java/Kotlin。典型工作流:

```
拿 IPA(越狱机 dump / 抓商店包) → 砸壳(FairPlay 解密) → 解包 Payload/*.app
  → 静态(class-dump 头文件 + Hopper/IDA 看 Mach-O)
  → 动态(lldb 附加 debugserver / Frida hook)
  → 改(重签重打包 / Tweak 注入) → 过检测(见第2篇)
```

与 Android 对照(详细方法论互链 `re/手法/05-工具矩阵/工具总表.md`):

| 环节 | Android | iOS |
|---|---|---|
| 包格式 | APK(zip+DEX) | IPA(zip+Mach-O) |
| 商店加密 | 无(靠厂商加固) | FairPlay(LC_ENCRYPTION_INFO) |
| 脱壳 | 内存 dump DEX(见 手法库 03 区) | 砸壳 dump 解密后 __TEXT |
| 头文件导出 | jadx 反编译 Java | class-dump 导 OC 头 |
| 运行时 hook | Xposed/Frida Java 层 | Method Swizzle/Frida/Substrate |
| native hook | GOT/inline(Dobby/ShadowHook) | fishhook(lazy/external 符号)/Dobby inline |
| 调试 | IDA/Android Studio + gdbserver | lldb + debugserver |
| root | Magisk | 越狱(unc0ver/Dopamine) |

## 2. Mach-O 文件格式(基础理论/文件格式节点)

### 2.1 整体布局

```
+------------------------+  文件偏移 0
| Mach-O Header (32B)    |  magic(cffaedfe=64位小端)/cputype/cpusubtype
|  filetype/ncmds/       |  ncmds=Load Command 数
|  sizeofcmds/flags/reserved
+------------------------+
| Load Commands 区        |  sizeofcmds 字节,每条 cmd+cmdsize 开头
|  LC_SEGMENT_64 __TEXT   |   → 映射段页权限与 Section 表
|  LC_SEGMENT_64 __DATA   |
|  LC_DYLD_INFO_ONLY      |   → bind/lazy-bind 重定位信息
|  LC_SYMTAB / LC_DYSYMTAB|   → 符号表/动态符号表
|  LC_LOAD_DYLIB ×N       |   → 依赖的动态库
|  LC_CODE_SIGNATURE      |   → 签名 blob
|  LC_ENCRYPTION_INFO_64  |   → cryptoff/cryptsize/cryptid(砸壳关键)
+------------------------+
| __TEXT 段(可读可执行)   |  __text/__stubs/__stub_helper/__objc_methname...
| __DATA 段(读写)         |  __got/__la_symbol_ptr/__objc_classlist/__cfstring...
| __LINKEDIT 段(只读数据) |  符号表/字符串表/签名/函数地址表
+------------------------+
```

要点:
- **段(Segment)是内存映射单位**(页对齐 16KB/4KB),Section 是段内逻辑分区;`__LINKEDIT` 不放代码,放 dyld 需要的元数据。
- `otool -h/-l/-L`、`lipo -info`、MachOView 是速查三件套;Mach-O 与 ELF 异同的系统讲解见语料帖深入浅出 Mach-O(2020,从内核 `load_machfile` 到 dyld 加载全链)、初探 Mach-O 学习小记(Header/ncmds/sizeofcmds/flags 逐字段)。
- 加载流程:内核 `mach-o` 解析 → `map` __TEXT → 交给 dyld → dyld 处理 LC_LOAD_DYLIB 依赖 → rebase/bind(改 `__DATA` 指针) → 调 init。逆向时 bind 信息(LC_DYLD_INFO)直接给出「哪个外部符号写进哪个地址」,是定位 API 调用的捷径。

### 2.2 Fat Binary(多架构)

App 商店包通常是 FAT:`FAT_HEADER(magic 0xcafebabe, nfat_arch)` 后跟 n 个 `fat_arch{cputype, cpusubtype, offset, size, align}`。分析前先 `lipo -thin arm64 xx -output xx.arm64` 抽出目标切片,否则工具可能解析到错误架构。同目录树参考 Android ELF 多架构 so 的处理(手法库 05 区)。

### 2.3 LC_ENCRYPTION_INFO 与 FairPlay

```c
struct encryption_info_command_64 {
  uint32_t cmd;        // LC_ENCRYPTION_INFO_64 = 0x2C
  uint32_t cmdsize;
  uint32_t cryptoff;   // 加密区在文件内的偏移(__TEXT 段内)
  uint32_t cryptsize;  // 加密字节数
  uint32_t cryptid;    // 0=未加密(自编译包);1=App Store FairPlay 加密
  uint32_t pad;
};
```
`cryptid=1` 时 `cryptoff` 起的 `cryptsize` 字节是 FairPlay 密文,内核加载时才解密回内存——所以磁盘上的静态工具看到的是密文,这就是「必须砸壳」的根因(§5)。

## 3. Objective-C 运行时(逆向分析节点)

### 3.1 objc_msgSend 消息派发

OC 方法调用编译为 `objc_msgSend(id self, SEL _cmd, ...)`,arm64 下是汇编手写(无栈帧),流程:

```
objc_msgSend:
  LDR  x16, [x0]           ; x0=self, 取 isa → class(注意经 &ISA_MASK)
  LDR  x11, [x16, #CACHE]  ; 方法缓存 buckets
  ... cache 命中 → 尾调 IMP
  未命中 → __objc_msgSend_uncached → lookUpImpOrForward
    ① class_rw_t 方法列表(含分类) ② 沿 superclass 上溯
    ③ 仍未命中 → _objc_msgForward → 消息转发(resolvesInstanceMethod/
       forwardingTargetForSelector/methodSignatureForSelector+forwardInvocation)
```

逆向价值:
- **方法名全部明文**:`__objc_methname` section 存 SEL 字符串,`strings`/class-dump 直接还原类-方法-属性全图,C 端符号被 strip 也不影响 OC 面。
- 消息转发三段是「检测类」逻辑的常见藏身处;`_objc_msgForward` 断点可抓全部走转发的调用。
- IMP 地址可从 `class_rw_t->methods` 里直接算出,配合 IDA 批量标注(IDAPython 遍历 `__objc_classlist`,见工具插件/IDA 节点)。

### 3.2 class_ro_t / class_rw_t / cache_t

```
objc_class ──ISA──> 元类
   │ DATA()
   ▼
class_rw_t(运行时可写)         class_ro_t(编译期只读)
  flags/版本                     类名/布局
  methods/properties/protocols   baseMethods(分类合并的底本)
  demangledName
  ro ────────────────────────────►
cache_t: masked buckets(SEL→IMP),高并发读写,
  逆向时 dump 它 = 拿到「实际被调过的方法表」
```
- 分类(Category)在运行时由 `attachCategories` 合入 `class_rw_t`,因此**静态看 Mach-O 必须扫 `__objc_catlist`**,否则漏掉分类里藏的逻辑(反调试常藏这)。
- Swift 类也走 OC 运行时桥接(`swift_unknownObjectRetain` 等),但方法派发优先走 vtable/静态派发,见 §4。

## 4. Swift 逆向(TypeMetadata / VWT)

Swift 编译产物对逆向不友好:符号 mangle(`_$s4main4CalcV3addyySiF` 类)、值类型不走 OC 消息、release 下泛型特化+优化打散结构。要点:

| 结构 | 作用 | 逆向意义 |
|---|---|---|
| TypeMetadata | 类型元数据(Kind/Name/字段描述/父类) | `$s…mangledName` demangle(`swift demangle`/IDA 插件)还原类型层次;`__swift5_types` section 是入口 |
| ValueWitnessTable(VWT) | 值类型初始化/拷贝/销毁函数表 | struct 生命周期 hook 点;枚举/可选的 tag 判别也在 VWT 相关路径 |
| Protocol Witness Table | 协议实现分发表 | 协议方法调用的实际落点(类似 vtable) |
| ContextDescriptor | 模块/类型/扩展/匿名函数描述 | `__swift5_fieldmd` 还原字段名(比 OC 时代信息量少但可用) |

调用约定:Swift 默认寄存器传参(x0 起,self 归属随 context);@objc/exported 才可被 class-dump 到。实战入门帖:Swift 逆向之授人以鱼不如授人以渔(2025-12,含「换一个 App 如何入手」方法论)、一款 Swift 写的软件逆向分析(2018,Prisma 案例)。混淆后的参数调用约定修复(编译优化导致 x0-x7 错位)是高阶坑。

## 5. 砸壳原理与工具(解密技术节点)

### 5.1 原理

FairPlay 只加密磁盘文件;内核/AMFI 加载时解密进物理页。因此砸壳 = **让 App 跑起来 → 从进程内存 dump 出已解密的 __TEXT → 修复 Mach-O → cryptid 改 0**。

```
磁盘 cryptid=1(密文) ──内核加载+AMFI解密──> 内存明文
                                           │
                    frida attach / debugserver / ptrace
                                           ▼
              memory read cryptoff~cryptsize → 回写文件同偏移
              header: cryptid=1→0(否则启动器以为还要解密)
              (可选)LC_CODE_SIGNATURE 重签/剥离
```

### 5.2 工具矩阵

| 工具 | 原理 | 特点 |
|---|---|---|
| dumpdecrypted | cycript 时代经典,dylib 注入后解密 dump | 老系统(A9/32 位)仍好用,新 iOS 基本退役 |
| frida-dump / frida-ios-dump | frida attach → `_dyld_image` 定位模块 → Memory.read 段 | 当前主流;配合 SSL Kill Switch 2 抓包链完整 |
| Clutch | 纯 native,速度快 | 越狱机命令行一键 |
| Bagbak / flexdecrypt 等 | node/命令行封装 | 面向批量 |

流程(frida-ios-dump):Mac 上 `python dump.py -H 手机IP`,越狱机装 frida-server;dump 出 `.app` 直接 `zip` 成可分析 IPA。与 Android 内存 dump DEX 同构,方法论互链 `re/手法/03-脱壳dump/`。验证壳是否砸干净:`otool -l` 看 `cryptid 0` + Hopper 能反汇编 `__text` 明文。

## 6. 静态分析工具(工具插件/IDA 节点)

| 工具 | 定位 | iOS 特色用法 |
|---|---|---|
| class-dump(-z swift 支持) | 导出 OC 头文件 | 砸壳后第一枪:类/方法/属性/协议全图 |
| Hopper | 性价比反汇编 | arm64 + OC 运行时标注,伪代码;macOS 原生 |
| IDA | 深度静态 | Fat 解包后加载;IDAPython 遍历 `__objc_classlist` 自动命名 IMP;Mach-O 插件丰富(树节点 1001484) |
| Ghidra | 免费替代 | 配合 Swift demangle 脚本 |
| MachOView / otool / lipo | 结构速查 | Load Commands/段/加密信息 |
| ipsw / class-dump-swift | 补充 | 内核 research 见第2篇 |

选型:快看类关系 class-dump → 中度分析 Hopper → 深挖逻辑/写脚本 IDA。Android 侧同构对照见 `re/手法/05-工具矩阵/静态分析工具.md`。

## 7. 动态调试:lldb + debugserver(调试相关节点)

越狱机调试标准链(免签报错需重签 debugserver,见 §9):

```
1) 手机 /usr/lib/debugserver(越狱自带;新系统需把 debugserver 拷出用 ldid
   签 platform-application+get-task-allow 再放回)
2) debugserver 127.0.0.1:1234 -a "TargetApp"(attach)或 -w(等待 spawn)
3) USB 转发:iproxy 1234 1234
4) Mac: lldb → process connect connect://127.0.0.1:1234
```

常用命令速查:
```
image list -o -f        # 模块与 ASLR slide
br s -a 0x1000+0x1234   # 按slide下断
br set -n "-[Class sel:]"  # 按OC符号断点(需符号未strip或已class-dump)
register read / x/32xw 0x...   # 寄存器/内存
expr -- (void)method...  # 动态调用(OC)
```
调试内核(KDP)与无痕对抗另见第2篇 §6 及 `re/手法/07-内核级/跨平台内核速查.md`。反调试对抗(sysctl P_TRACED/svc 内联 ptrace)完整版在第2篇 §1。

## 8. Hook 技术(Hook技术节点)

### 8.1 fishhook:__DATA 符号重绑定

原理:Mach-O 惰性/外部符号引用存在 `__DATA` 的 `__la_symbol_ptr`(lazy)/`__nl_symbol_ptr` 与 GOT;dyld `bind` 时按 LC_DYLD_INFO 把真实地址写入。fishhook 在运行时遍历所有 image 的 indirect symbol table,把目标符号(如 `open`/`stat`/`sysctl`)对应槽位换成自己的函数并保存原值:

```
调用 stat() ──► __DATA,__la_symbol_ptr[idx] ──► (fishhook 重绑)my_stat
                                      │保存
                                      ▼
                              原 libsystem_kernel stat
```
- 只能 hook **经过符号表的外部 C 函数**(系统库调用),不能 hook OC 方法/静态内联/直接 syscall——这也是 fishhook 被绕过的根本原因(目标用 svc 直调,见第2篇 §1.3)。
- 典型用途:Tweak 里拦文件/网络检测、越狱检测面覆盖。

### 8.2 Method Swizzling / CaptainHook

OC 层 `method_exchangeImplementations` 换 IMP,或 CaptainHook 宏套件(`CHOptimizedMethod` 系列)把 swizzle 写成声明式。越狱 Tweak 里最常用,配合 Logos 的 `%hook` 语法(§11)本质相同。检测方常用「IMP 是否指向 __TEXT 白名单区间」反查(第2篇 §2)。

### 8.3 Substrate 系与 inline hook

| 框架 | 层 | 说明 |
|---|---|---|
| Cydia Substrate(MsHookFunction) | inline | 传统越狱标配,商业闭源 |
| Substitute / ElleKit | inline | 开源替代;Dopamine(rootless)默认 ElleKit,兼容 Substrate API |
| Dobby | inline | 跨平台 arm64 inline hook,Tweak 与独立注入都能用;Android 侧同源(见 手法库 05 区对比) |
| libhooker | inline | rootless 时代 CoolStar 系 |

inline hook 在 arm64e(PAC)设备上要处理指针签名(A12+),通用框架已内置;自写 hook 需 `pacibsp/braa` 语义对齐(详见第2篇 §6 PAC)。

### 8.4 Hook 检测与反制
IMP 白名单、`dladdr` 查地址归属、fishhook 自检(读 `__la_symbol_ptr` 是否在系统库区间)——完整对抗在第2篇 §1/§2。

### 8.5 Frida(iOS)
越狱机装 frida-server 即全功能:OC 层 `ObjC.classes.xxx['- method:']` 直接 hook(用法与 Android Java 层同构,速查互链 `re/手法/02-frida/java层/` 系列);native 层 `Module.findExportByName('libsystem_c', 'open')` 对应 fishhook 面。树节点 1001407。iOS 特色坑:arm64e 上 hook 系统库受 PAC 限制时换 Dobby/substrate 路线。

## 9. 签名与重签(签名节点)

### 9.1 签名结构

```
IPA ── _CodeSignature/CodeResources(资源哈希清单)
  └─ Mach-O LC_CODE_SIGNATURE → CMS blob
       ├─ CodeDirectory(hash 槽:每 4KB 页的 SHA256)
       ├─ entitlements(键值:application-identifier/teamid/
       │    get-task-allow/keychain-access-groups/aps-environment…)
       └─ 证书链 + Provisioning Profile(embedded.mobileprovision)
```
- `get-task-allow=true` 是调试开关——重签调试包必带;商店包为 false,ldid 签不出同等效力(苹果根证书),只有开发者证书/企业证书/AltStore 免费证书三种现实路径。
- entitlements 决定能力边界(扩展/VPN/多任务),hook/调试报 `CS_KILLED` 多半是 entitlements 缺失。

### 9.2 工具与三条例外路径

| 工具/方案 | 用法 | 限制 |
|---|---|---|
| codesign(Xcode 自带) | `codesign -f -s "Apple Development: …" --entitlements ent.plist xx.app` | 需 Mac+证书 |
| ldid(越狱圈标配) | `ldid -e xx`(看权限)/`ldid -Sent.plist xx`(注入权限) | 伪签,越狱/TrollStore 环境有效 |
| AltStore / Sideloadly / SideStore | 免开发者付费账号侧载(7 天重签;免费号 3 App 上限) | SideStore 可免电脑续签 |
| TrollStore(CoreTrust 漏洞) | 永久签名任意带 entitlements 的 IPA,非越狱 | 限 iOS 14.0~17.0 等版本窗口(与 Dopamine 同源漏洞,见 §10) |

社区实战帖:iOS 签名杂谈(二)(2020,ldid -e 查 entitlements/签名细节)、小谈签名工具 ldid 和 codesign 的使用(2017,给 debugserver 签 get-task-allow 的完整操作)。重签流程模板:砸壳 IPA → 改 Bundle ID → 换 embedded.mobileprovision → `codesign`/`ldid` 重签全部 Mach-O(注意 Frameworks/PlugIns 子目录逐个签)→ zip 重打包。

## 10. 越狱体系

| 代际 | 工具 | 类型 | 机制要点 |
|---|---|---|---|
| 经典 | redsn0w/evasi0n/Pangu 系列 | untethered/tethered | bootrom/iBoot 漏洞,已随硬件封死成历史 |
| checkra1n | checkm8(A5~A11) | tethered 半完美 | bootrom 漏洞不可封,A11 后无 |
| unc0ver / Taurine | 内核漏洞 | rootful semi-untethered | 写 / 文件系统,重启后需重越狱;Sileo/ Cydia 生态 |
| Fugu15 → **Dopamine** | CoreTrust+内核链 | **rootless** semi-untethered | opa334 维护,iOS 15~18.x(随版本更新);不写根分区,越狱文件放 /var/jb,Tweaks 需 rootless 编译;配 **Procursus** 包仓库+Sileo |
| palera1n | checkm8(A8~A11)+ iOS15+ | rootless 可选 | Checkra1n 后继 |
| TrollStore | CoreTrust | 非越狱 | 仅永久签 IPA,无系统级注入 |

rootless 的安全研究意义:越狱痕迹大幅减少(`/,/usr` 只读未动),与「越狱检测」对抗直接相关(第2篇 §2)。Procursus 是跨发行版构建的包基底,隔离设计降低插件污染 /usr 风险。

## 11. Tweak 开发:theos + Logos(编程开发节点)

环境:`brew install ldid` + theos → `nic.pl` 选 tweak 模板。Makefile 设 `TARGET = iphone:clang:16.5:15.0`(rootless 加 `THEOS_PACKAGE_SCHEME=rootless`)。

Logos 语法(编译展开为 `_logos_register` + method swizzle/inline hook):

```objc
%hook TargetClass
- (BOOL)isJailbroken {
  return NO;                       // 直接改返回值
}
%new(addGroup)                      // 新增方法
- (void)hookedNewMethod { ... }
%end

// 构造函数自动注册;ctor 里可做 fishhook/inline 补充
%ctor {
  %init(TargetClass);
}
```

控制台输出:`%log` 打调用栈;安装:`make package install`(scp 到设备 /var/jb 或经典路径)。调试:Tweak 本质 dylib(MobileSubstrate/Dopamine 下 Substitute/ElleKit 注入),逻辑错误会随宿主崩溃——先小步 swizzle,再上复杂逻辑。入门帖:【iOS逆向与安全】iOS插件开发光速入门(2022-12)。

## 12. 参考总表

| 主题 | 资料 | 链接 |
|---|---|---|
| Mach-O 全链 | 深入浅出 Mach-O(2020) |  |
| Mach-O 入门 | 初探 Mach-O 学习小记 |  |
| Swift 逆向方法论 | Swift 逆向之授人以鱼不如授人以渔(2025) |  |
| Swift 实战 | 一款 Swift 写的软件逆向分析(2018) |  |
| 签名 | iOS 签名杂谈(二)(2020) |  |
| 签名工具 | ldid 和 codesign 的使用(2017) |  |
| Hook 全景 | iOS Hook 终极兵器库(2025) |  |
| 版块入口 | iOS安全版块(1478+ 主题) |  |
| 越狱工具 | Dopamine(rootless) |  |

> 砸壳工具以 frida-ios-dump 为当前主流,版块内检索「砸壳/脱壳」补链。
