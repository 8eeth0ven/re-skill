# iOS 文件与签名实战(Mach-O/dyld 全链 / 签名与重签 / 砸壳实操 / 越狱链与 bootchain / fairplayd 反混淆)

> 知识库 04-iOS安全 · 第 3 篇。基础概览(段布局/CryptID/工具矩阵/越狱代际)见 [iOS逆向体系.md](iOS逆向体系.md),本文只做增量深挖:内核与 dyld 加载源码级细节、签名校验链与 rules 绕过、砸壳完整命令与坑、越狱 rootfs 重挂载与 APFS 快照绕过源码、iBoot 递归栈溢出利用全流程、fairplayd 块调度反混淆。

## 1. Mach-O 与 dyld 加载

### 初探Mach-O学习小记
作者:BinGzL。mach_header_64 字段与 filetype 速查见 [iOS逆向体系.md](iOS逆向体系.md),此处留解析器必备。

**Load Command 类型 → 结构体映射**(写解析器按此选结构;LC_SEGMENT/64 特殊,带 nsects 个 section 头):

```
segment_command(_64)     LC_SEGMENT(_64);thread_command  LC_THREAD / LC_UNIXTHREAD
dylib_command            LC_ID_DYLIB / LC_LOAD_{,WEAK_}DYLIB / LC_REEXPORT_DYLIB
dylinker_command         LC_ID_DYLINKER / LC_LOAD_DYLINKER / LC_DYLD_ENVIRONMENT
symtab/dysymtab/uuid/rpath/entry_point/source_version_command  同名 LC_*
linkedit_data_command    LC_CODE_SIGNATURE / LC_SEGMENT_SPLIT_INFO / LC_FUNCTION_STARTS / LC_DATA_IN_CODE 等
encryption_info_command(_64) / version_min_command / dyld_info_command  同名 LC_*
```

section_64 关键字段:`sectname/segname[16]`、`addr/size`(虚址)、`offset`(文件偏移)、`align`(2 的幂)、`reloff/nreloc`。坑:不同 cmd 对应不同结构体,按 `load_command.cmd+cmdsize` 步进遍历。

### Mach-O格式分析
作者:dirge。速查 `otool -h git`(magic/cputype/filetype/ncmds/sizeofcmds/flags 一屏全出;0xfeedfacf=64 位小端,ARM64 cputype=0x0100000C)。内核 `parse_machfile`(bsd/kern/mach_loader.c)只处理以下 LC,其余直接忽略——逆向加载行为只关注这些:

| Command | 函数 | 说明 |
|---|---|---|
| LC_SEGMENT / LC_SEGMENT_64 | load_segment | 段映射 |
| LC_UNIXTHREAD / LC_MAIN | load_unixthread / load_main | 线程/入口(LC_MAIN 仅 depth==1) |
| LC_LOAD_DYLINKER | (pass 3 记录 dlp) | 之后 load_dylinker |
| LC_UUID | load_uuid | 128-bit ID |
| LC_CODE_SIGNATURE | load_code_signature | 签名校验 |
| LC_ENCRYPTION_INFO(_64) | set_code_unprotect | pass 3;FairPlay 解密 |

FairPlay 关键行为(pass 3):`set_code_unprotect` **只设置 decrypter,内核不真正解密**;失败返回 LOAD_DECRYPTFAIL 时置 `P_LTERM_DECRYPTFAIL` 并直接 `psignal(p, SIGKILL)`——解释了砸壳前静态工具看到密文、密钥缺失时进程秒被杀。LC 遍历校验 `cmdsize < sizeof(load_command)` 或 offset 越界即 LOAD_BADMACHO。

### 深入浅出Mach-O
作者:evilpan。segment 映射:文件 `begin+fileoff` 起 `filesize` 字节 → 进程 `vmaddr` 起 `vmsize`;**vmsize ≥ filesize,多出零填充**(__bss/__common 吃差值)。cmdsize 需 word 对齐(64 位 8B),尾部填充必须 0。段速查(lldb `image dump sections main`;看 section 用 `otool -V main -s __TEXT __stubs`,看签名用 `jtool2 --sig -v main` / `codesign -d`):

```
__PAGEZERO  [0x0-0x100000000) ---  占低地址防 NULL 解引用
__TEXT      r-x  fileoff=0  文件头(Header+LC)一并映射;__text/__stubs/__stub_helper/__cstring/__unwind_info
__DATA      rw-  __nl_symbol_ptr/__got/__la_symbol_ptr/__common(zero-fill)
__LINKEDIT  r--  fileoff+filesize==文件大小;内容随 cmd:符号表/函数起始表(uleb128)/dyld info/签名 blob
```

dyld_info_command 六元组:rebase/bind/weak_bind/lazy_bind/export 各 off+size;lazy bind 语义例:`_printf(libSystem.B.dylib) 延时绑定到 __DATA,__la_symbol_ptr 槽位`。内核加载 4-pass:0 边界页对齐 → 1 thread state/uuid/signature → 2 segments 实际映射 → 3 dyld/encryption/entry point。load_segment 要点:32 位先 widen 成 64;映射地址 = slide+vmaddr;file/vm 全 4K 页对齐;0 地址仅允许 __PAGEZERO;**内核不解析 section,只到 segment 粒度**(section 是 dyld/链接器概念)。

load_dylinker 递归调 parse_machfile(depth 限层);dyld 返回用户态后 `__dyld_start`(固定 0x1000)→rebaseDyld→mach_init→__guard_setup→`dyld::_main`:setContext→env→mapSharedCache→DYLD_INSERT_LIBRARIES→link 主程序→initializeMainExecutable(跑 __mod_init_funcs)→LC_MAIN 入口。ImageLoader::link 顺序:recursiveLoadLibraries→recursiveUpdateDepth(被依赖库排前)→recursiveRebase→recursiveBind→weakBind(仅非主程序)→recursiveGetDOFSections→recursiveApplyInterposing(仅 INSERTED 库可 interpose)。dyld_cache:iOS 路径 `/System/Library/Caches/com.apple.dyld/dyld_shared_cache_$arch`;是否已映射走 syscall 294 `shared_region_check_np`(295 = map_np);header 含 mapping/images 的 Offset/Count、codeSignature、slideInfo、localSymbols、uuid;每条 mapping_info{address,size,fileOffset,maxProt,initProt} 逐条 mmap;dump 系统库符号从 localSymbols+slideInfo 下手。

### dyld加载mach-o文件分析
作者:dirge。用户态加载链:`_main → instantiateFromLoadedImage → isCompatibleMachO → ImageLoaderMachO::instantiateMainExecutable → sniffLoadCommands → instantiateStart → addImage(挂入 sAllImages 记录映射区间)`。isCompatibleMachO 三级判定:magic 一致 → cputype 一致 → cpusubtype 在 `findCPUSubtypeList` 偏好列表内(或与宿主全同;x86/x86_64 不用 subtype)。

**sniffLoadCommands 全部畸形校验**(伪造/改造 Mach-O 或写解析器的规则集):

- `cmdsize < 8` 或 nextCmd 越过 endCmds → malformed;见 LC_DYLD_INFO(_ONLY) → compressed,Classic 无则直接 throw "missing LC_DYLD_INFO load command";
- `filesize > vmsize` → malformed(macOS 允许 vmsize==0 例外,iOS 不允许);
- codeSigningEnforced:vm/file 区间不得回绕、不可访问段 filesize 必须为 0、**load commands 必须整体落在某个 initprot==R+X 段内且从 fileoff 0 开始**、任意两段不交叠、**__LINKEDIT 必须是最后一段**;
- section 的 `offset+size` 不得超出所属段边界;段数 >255、依赖库 >4095 → malformed;每个 image 只允许一条 LC_CODE_SIGNATURE、一条 LC_ENCRYPTION_INFO(_64)。

addImage 额外动作:合并连续段为 mapped range;`DYLD_PRINT_LIBRARIES` 时打印 loaded 日志。

### Mach-O动态连接的简单分析
作者:dirge。lazy bind 全流程(printf 为例,lldb 单步实测):

```
main+34:  callq 0x100000f56            ; __stubs 里 printf 的 stub
0x100000f56: jmpq *0xb4(%rip)          ; 跳 __DATA,__la_symbol_ptr 槽位(初始值 0x100000f6c = __stub_helper 绑定桩)
0x100000f6c: pushq $0x0                ; 压入 lazy-bind ordinal
0x100000f71: jmp 0x100000f5c           ; stub_helper 头 → dyld_stub_binder
binder: 按 ordinal 查 lazy_bind 信息解析真实 printf 地址,回写槽位后直跳;第二次调用 jmpq 直达 printf
```

验证:断调用前后各 `x 0x100001010`——前值 `6c 0f 00 00 01 00 00 00`,后值 `5c 81 b1 96 ff 7f 00 00`。对照 Linux:__stubs≈PLT、__la_symbol_ptr≈GOT、stub_helper+binder≈ld.so 延迟解析器;GOT/lazy_symbol_ptr 是 fishhook 能生效的根。符号表侧:LC_SYMTAB 给 symoff/nsyms/stroff/strsize;LC_DYSYMTAB 划分 indirect/local/defined 区间。

## 2. 签名体系

### iOS 签名杂谈(一)
作者:obaby。转授权分发:PC 端经 iTunes 私有 API 建授权文件;**安装时不校验,运行时才校验**(无授权弹账号密码框)。删授权实验需删 `/private/var/mobile/Library/FairPlay/iTunes_Control/iTunes/` 下 `IC-Info.sidr/.sids/.sidt/.sisb/.sisv/.sidb` 六个文件。商店 IPA 结构:`Payload/xxx.app/SC_Info/`(授权)+ `iTunesMetadata.plist`(购买 AppleID/版本;**不参与安装校验也不参与签名,删掉照样装**;新版每个 Frameworks 子目录还有同内容 SC_Info)。

**双层签名校验链**:资源哈希在 `_CodeSignature/CodeResources`(files 键:文件名 → sha1(新版加 sha256)摘要 **base64**);CodeResources 自身哈希记录在可执行文件签名(CMS blob)里——改资源+更新 plist 哈希也过不了。计算脚本:

```python
import hashlib, base64
print(base64.encodebytes(hashlib.sha1(open(filepath,'rb').read()).digest()))  # 与 plist 中 <data> 一致
```

看可执行签名内 CodeResources 哈希:`jtool --sig`。例外:SC_Info 被 rules omit(见杂谈二),不同账号购买的同一应用互换 SC_Info 可正常安装运行。

### iOS 签名杂谈(二)
作者:obaby。CodeResources 的 rules 键(不参与校验的文件):

```
^SC_Info/.*\.sinf$ / .supp$   omit  weight 10000(新版含 PlugIns/*.appex/SC_Info 的 sinf|supp|supf|supx)
Info.plist / PkgInfo / ResourceRules.plist  omit;.*\.lproj/ optional weight 1000(本地化可缺)
^(.*/)?\.DS_Store$            omit  weight 2000;^embedded\.provisionprofile$  weight 20(只记嵌套不 omit)
```

**resource-rules 绕过(改已签 IPA 不重签)**:macOS 10.9 起 codesign 官方废弃 `--resource-rules`(TN2206),但旧版 codesign 仍可用且签出的 IPA 可正常安装。全排除配置:plist 的 rules 字典下 `<key>.*</key><false/>`;执行 `codesign -f -s 证书 --resource-rules=规则.plist xxx.app` 后 CodeResources 的 files/files2 全空——**此后改任何资源文件、重压缩即可装,无需再签**。检测判据:`codesign -dvvv` 显示使用了自定义忽略规则。

embedded.mobileprovision(mp)三要素:①entitlements(与二进制内不要求全同,差太远装不上/闪退);②设备列表:个人/开发证书 = `ProvisionedDevices`(UDID 不在列装不上),企业证书 = `ProvisionsAllDevices`(企业签横行根因);③CreationDate+TTL 有效期、bundleid(自动加 TeamID 前缀)、UUID、证书。查看:`security cms -D -i Payload/xxx.app/embedded.mobileprovision` 解出明文 plist;`ldid -e Payload/xxx.app/xxx` 看二进制实际 entitlements。

mp 与 IPA 原 bundleid **不必一致**(wildcard 受限:推送等不可用)。要推送:分发(Distribution)mp + bundleid 开 push + push 证书。**mp 过期续期:同账号同 bundleid 重建 mp 替换进 IPA 即可,不用重签**(前提当初用 resource-rules 签)。`codesign --entitlements path` 注入权限;**别用 ldid 签 IPA**,只用于越狱环境给单二进制(debugserver)写权限。

## 3. 重签名与安装

### cydia Impactor安装未签名IPA的协议抓取
作者:猪会被杀掉。Impactor 用 curl 走自有签名通信,fiddler 等中间人抓不到;三种进程内 hook 抓协议(全部写文件),用于还原与苹果签名服务器的完整交互(免费账号证书申请/装未签 IPA 协议面)。

①hook curl 的 `Curl_ossl_send/Curl_ossl_recv`(naked 函数保寄存器,回填 eax;recv 同构):

```c
__declspec(naked) void new_Curl_ossl_send(void* conn, int sockindex, const void *mem, size_t len){
    _asm pop esp_reg / _asm call old_Curl_ossl_send / _asm pushad / _asm mov len111, eax
    Log((const char*)mem, len);       // recv 同构:Log((const char*)buf, len111)
    // # (省略:popad / mov eax,len111 / push esp_reg / retn —— 恢复现场并回填返回值)
}
```

②hook iTunes/CFNetwork(重要协议走 HSTS,中间人同样失效):`CFHTTPMessageCreateRequest` 抓 URL+方法,`CFHTTPMessageSetBody` 抓 body——`CFStringGetCString(CFURLGetString(url),...)`、`CFDataGetBytePtr/CFDataGetLength` 落盘。③Win32 侧:hook `WinHttpSendRequest/HttpSendRequest` 拦 headers+optional 缓冲;再 hook `WinHttpOpenRequest` 对返回句柄 `WinHttpSetOption(WINHTTP_OPTION_PROXY / WINHTTP_OPTION_SECURE_PROTOCOLS)` 强制走本地代理转中间人。

## 4. 砸壳实操

### 一条命令完成iOS应用砸壳
作者:AloneMonkey。工具演进:dumpdecrypted(只砸主二进制)→ conradev 版(`_dyld_register_func_for_add_image` 回调逐模块 dump,覆盖 Framework)→ MonkeyDev tweak 免拷贝 → Clutch(posix_spawnp 直接出 IPA 但常报错)→ **frida-ios-dump**(frida 注入 JS 内存 dump + python 自动回传打包,一条命令)。

```
sudo pip install frida --upgrade --ignore-installed six   # 修 six 卸载报错
iproxy 2222 22                       # USB 映射 SSH;旧版脚本基于 python2
./dump.py 微信                       # 按显示名砸;-l 列 PID/Name/Identifier;-b com.tencent.xin 按 bundle id 砸
```

日志可见逐模块 dump(主二进制+Frameworks 各库解密回传),完成后当前目录生成解密 IPA。坑:应用重名必须走 -b;越狱机需装 frida-server。

### ios-dumpdecrypted砸壳
作者:Gnoliew。直用命令(手机 SSH 或 Terminal):

```
DYLD_INSERT_LIBRARIES=dumpdecrypted.dylib /var/containers/Bundle/Application/<UUID>/xxx.app/xxx
```

产物 `xxx.decrypted` 落**当前工作目录**;去后缀、`chmod -R 777`、`otool -l 二进制 | grep crypt` 见 0 即成功。**Killed: 9 坑** = dylib 没签名(或签名不被信任),重签:`codesign --force --verify --verbose --sign "iPhone Developer: xxx" dumpdecrypted.dylib`(证书先用 `security find-identity -v -p codesigning` 列出)。

### 无须越狱、自动集成、只需要一个砸壳的应用
作者:AloneMonkey。MonkeyDev 的 MonkeyApp 模板:Xcode New Project → MonkeyApp → 砸壳 ipa/app 拖进 TargetApp 目录(保留占位文件)→ 直接编译到非越狱手机。自带 `MonkeyAppDylib`(OC runtime hook + fishhook)、`AntiAntiDebug`、自动集成 Reveal+Cycript(默认端口 6666);默认库位置 `/opt/MonkeyDev/frameworks`(Reveal)、`/opt/MonkeyDev/library`(Cycript)。CaptainHook 模板(照抄改类名即用):

```objc
CHDeclareClass(CustomViewController)
CHOptimizedMethod(0, self, NSString*, CustomViewController, getMyName){
    NSString* password = CHIvar(self, _password, __strong NSString*); // 读私有 ivar
    return @"AloneMonkey";                                            // 改返回值
}
CHConstructor{ CHLoadLateClass(CustomViewController); CHClassHook(0, CustomViewController, getMyName); }
```

## 5. 越狱链与 bootchain

### 越狱主要步骤揭秘
作者:daemond(翻译)。**payload 投递**:iOS 9.0 前无免费账号自签,靠企业证书+私有部署;Pangu 7.1-7.1.2 把整个待装 IPA(gzip tar)嵌在 PC 端二进制自定义 section `__TEXT.__objc_cons2`(≈2.49MB;objc_cons1~11 塞 untether/plist/库):

```
jtool -e __TEXT.__objc_cons2 pangu   # 抽 section;file 验证 gzip;tar tvf 列出 Payload 内容
```

证书过期对策:回拨设备日期(该版本为 2014-06-02)。与设备通信走 iTunes AppleMobileDevice 私有 API(libimobiledevice 已复刻)。KPP 代际:iOS 9 KPP(EL3 软件)→ iOS 10 KTRR(硬件)→ xerub KPPLess 让 Yalu 支持 iPhone 7。

**沙箱逃逸(QiLin ShaiHulud)**:内核 R/W 把本进程 ucred 换成内核 ucred → 获得 execve/fork/posix_spawn 全部能力;**退出前必须恢复原 ucred**,否则内核凭据锁 panic。

**RootFS 重挂载(QiLin remountRootFS,可直接照抄)**:

```c
rootVnodeAddr = findKernelSymbol("_rootvnode");
// readKernelMemory 读 vnode → rootvnode->v_mount → mount 结构(偏移 0x70 = flags,版本相关)
mountFlags = (*(uint32_t*)(v_mount + 0x70)) & ~(MNT_ROOTFS | MNT_RDONLY);  // 清两标志,绕 mount 的 MACF 钩子
writeKernelMemory(v_mount + 0x70, &mountFlags, 4);
mount("apfs", "/", MNT_UPDATE, "/dev/disk0s1s1");   // 必须重调 mount(2)
mountFlags |= MNT_ROOTFS;  writeKernelMemory(...);  // 恢复标志
open("/test.txt", O_TRUNC|O_CREAT);                 // 写测验证,成功后 unlink
```

**iOS 11.3 APFS 快照绕过**:每次重启回退只读快照、tweaks 全丢。快照名 = `com.apple.os.update-<boot-manifest-hash 大写HEX>`;hash 取自 `IODeviceTree:/chosen` 属性 `boot-manifest-hash`(手工 `ioreg -p IODeviceTree -l | grep boot-manifest-hash`;代码 = Electra apfs_util.c copyBootHash:GetProperty 后逐字节 `%02X`)。绕过主干:iOS≤11.2.6 走老路;11.3+ 临时换 ucred → /dev/disk0s1s1 以 RW 挂临时目录 → `do_rename(临时目录, 快照名, "orig-fs")` **重命名快照** → unmount 清理 → 恢复 ucred → 重启(Electra 11.3.1 首跑强制重启)。没有快照可回退时 iOS 照常引导,越狱文件持久。dev vnode 还要 `wk32(specInfo + offsetof_si_flags, 0)` 清 v_specflags。术语:bin pack/base binaries = 常规 unix 工具;bootstrap = jailbreakd/Cydia 等其余。内核漏洞选型:VFS empty_list 免费账号可用但不稳;MPTCP 稳但 multipath entitlement 要付费开发者账号。

### iOS 7 bootchain 中的递归堆栈溢出漏洞
作者:daemond(翻译)。bootchain(越靠后越复杂、bug 概率越高):NAND 链 `SecureROM → LLB → iBoot → OS`;DFU 链 `SecureROM → iBSS → iBEC → Restore`。iBoot 不可重定位,固定加载 `memory_base+memory_size-1MB`(0x5FF00000/0x9FF00000/0xBFF00000)——**无 IASLR,全内存布局可预测**;dump 用 kloader/kdumper。内存自顶向下 CODE → DATA(BTree 头/分配器元数据)→ HEAP(任务栈固定 0x1C00)。调度器协作式且任务运行中不检查——**递归后没有 task_yield 则栈完整性检查形同虚设**。

**找递归环:调用图跑 Tarjan SCC**(xerub idastuff/tarjan.py)。直接自递归少且有深度限制(ResolvePathToCatalogEntry 限 64),目标 F()→G()→F() 小环:

```
ReadExtent() → memalign(64)
ReadExtentsEntry()/ReadBTreeEntry() → memalign(blockSize) → ReadExtent()
```

HFS+ 要点:目录文件是 B-tree,每 fork 记 8 个 extent,超出记到 extents overflow B-tree;iBoot 用同一 ReadExtent() 读两类 extent——**读溢出 extent 时再超 extent 密度 → 无限递归**,每帧 208 字节,栈从 HEAP 向下烧穿 DATA。

方法论:先写**用户态模拟器 iloader**(dummy allocation 对齐 main task 栈,`SP = BASE + 0x581d4`),试错全在模拟器完成再上真机。约束:避开 `task::irq_disable_count` 覆写 >999(panic);目标是分配器元数据(malloc 在递归路径反复执行);SP 微调两招——nvram `${boot-path}`/`${boot-ramdisk}` 可从 iOS 内设且重启保留,或长路径让 ResolvePathToCatalogEntry 下探(≤64 层)。

触发构造(HFS+ 卷头/BTree 头字段;BTree 头大部分空间 iBoot 不检查,**payload 就放头里**):

```
catalogFile.logicalSize = 0xFFFFFE00;   extentsFile.logicalSize = 0x3FFC000;
Catalog BTree:  nodeSize=512   totalNodes=0x7FFFFF  rootNode=0x7FFE(初触发)
Extents BTree:  nodeSize=16384 totalNodes=0xFFF     rootNode=0x500(必须大,LSB=0)
进阶:复制根块造高树,PUT_DWORD_BE(block, 116, 0x10000);最佳路径 ${boot-ramdisk}="/a/b/.../m/disk.dmg"
```

**利用原语:驱动 memalign 的 free_list_remove 得任意写**(分配器双循环链表,R0 块指针可控,指向 BTree 头假块):

```
free_list_remove:
    LDRD.W R10, R11, [R0,#0x40]   ; 必须 DWORD 对齐
    STR.W  R10, [R11]             ; 任意写: [R11] = R10
```

写目标选 memalign 栈帧里保存的 LR(拿 PC 控制)。对齐坑:LDRD 要 DWORD 对齐而指针在 DWORD+2 → **两轮迭代**(第一轮不 fit 切到对齐地址,第二轮 exact fit,R4==R0 干净返回),再安排假块值跳过 memalign 其余逻辑直接 ret 进 BTree 头 shellcode(整映射可执行)。收尾(nettoyeur):堆已全毁,shellcode 先禁用解释器,用 iBoot 自带 lzss 例程解压一段清理代码静默执行,**跳回 iBoot 起始点重启**——BSS/堆重初始化,拿到安全检查已禁用、GID AES key 可用的恢复控制台。真机攻击序列(前提:已越狱 + iBoot 版本精确匹配):

```
nvram boot-ramdisk="/a/b/.../m/disk.dmg"
dd if=/dev/rdisk0s1s1 of=backup bs=512k count=1    # 备份
dd of=/dev/rdisk0s1s1 if=ramdiskF.dmg bs=512k count=1
重启 → logo 闪(exploit 重启 iBoot)→ irecovery -s 连恢复控制台
```

应用:引导任意未签名内核(第三分区 /dev/rdisk0s1s3 + `nvram boot-partition=2` + boot-ramdisk 指向触发盘)。缓解评估:canary/调度检查/W^X 均难挡(溢整个 heap、精确写、可转 ROP);**有效防御:DATA/HEAP 间保护页、硬性递归深度检查(iOS 8 修法)、堆随机化/IASLR**。

## 6. 内核调试

### iOS内核调试教程
作者:梦野间(翻译)。四件套:可设启动参数的越狱设备(RedSn0w:Extras → Even More → Preferences → Boot Args 输入 `debug=0x8f -v wdt=0`)、串口调试线、Apple 版 GDB(与 Xcode 兼容)、serialKDPproxy(KDP 走 UDP 代理串口)。debug=0x8f 调试模式、-v verbose、wdt=0 关看门狗(可任意时刻暂停);设置后开机即挂起等调试器。

```
./SerialKDPProxy /dev/tty.usbserial-AH00NR2W   # 串口→KDP;启动日志打出 kernel slide
gdb -arch armv7
(gdb) target remote-kdp
(gdb) attach localhost
```

命令:`p (int)addr` 读 / `set {int}addr=val` 写 / `x/i addr` 反汇编 / `info registers` / `break *(addr)`(IDA 函数地址 + kernel slide);有符号 kernelcache 可按函数名下断。套路:IDA 找函数(如 OSUnserializeXML)→ 加 slide 下断 → 触发 → 栈/寄存器现场全拿,一分钟调试抵一小时静态。

## 7. fairplayd 混淆(块调度反混淆)

### 尝试解下fairplayd的混淆(块调度)
作者:lpcdma。块调度(block dispatch)≈ 开源 Hikari 的 IndirectBranch:「跳到固定偏移」改「跳到寄存器值」,寄存器值由每块入口的一段计算得出。解法目标:**静态算出每个块的跳转偏移,恢复 CFG**。样本 ios11.3.1 fairplayd.H2。三种形态:

1. **函数中间块**:入口几条算术(SUB/ADD/AND)直接口算 → 下一块地址;数量级问题用 **unicorn 逐块仿真**算,不人肉。
2. **带 this/r0/参数链**(x19 依赖 sub_100CB3AEC 返回值):往上回溯长链是障眼法——**被依赖函数其实是纯计算函数**,参数 int8_t 只有 0-0xff,枚举代入得 `w0 恒等于 0xfffffff0` → x19 = 0x1001594e4 = 下一函数地址。混淆函数当常量传播处理。
3. **依赖 X29(FP/栈底)**:W20←W9←X25←X0,X0 来自 `LDR W9,[X25,#8]`,X25 又链回 `STUR W8,[X29,#var_80]` 同一栈槽——W9 取的就是之前存的 5;**动笔画数据流图**看穿自引用,固定魔数(0xe226/0x7218)也是提示。解得 W20=5 → X9=0x100159564。

流程:先准确定位函数头尾(找跳转关系的前置);块图解出后要 F5 只能改指令修补跳转(自动化成本高)。本质:混淆计算链当**常量折叠+栈槽别名分析**做,unicorn 兜底。
