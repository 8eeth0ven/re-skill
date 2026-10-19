# iOS 动态实战案例集(反调试对抗实操 / Tweak开发 / 免越狱hook / 工具小件 / 游戏App实战)

> 知识库 04-iOS安全 · 第 3 篇。原理速查见 [iOS攻防与进阶.md](iOS攻防与进阶.md)(反调试/越狱检测速查表),本篇全是**实操级**案例:可照抄的命令、代码、坑。

## 1. 反调试对抗实操

### iOS inlinehook绕过反调试
作者:xia0。针对内联汇编 `svc #0x80` 直调系统调用的反调试(fishhook 失效场景)。目标特征(26 号 ptrace):`asm volatile("mov x0,#31\n mov x16,#26\n svc #128\n")`(PT_DENY_ATTACH + SYS_ptrace)。

**手法一:静态内存特征匹配 patch**——step1 解析自身 Mach-O 拿 __text 区间(遍 load_command,LC_SEGMENT_64 里 segname=__TEXT/sectname=__text,`start = addr + _dyld_get_image_vmaddr_slide(0)`);step2 遍历搜双指令特征码;step3 patch svc 为 nop:

```c
// mov x16,#0x1a = 0xd2800350 ; svc #0x80 = 0xd4001001
if (*((uint32_t*)p)==0xd2800350 && *((uint32_t*)p+1)==0xd4001001) return p;
uint8_t nop[4] = {0x1f,0x20,0x03,0xd5};   patchCode(ptrace_svc_p+4, nop, 4);
```

**手法二:inlinehook 动态绕过**(对抗混淆了系统调用号/编译变体):hook 代码段所有 svc,执行时判 x16 是否 26,是则跳过 svc,否则跳回原 svc 保证其他系统调用正常:

```c
new = mmap(NULL, pagesize, RW, MAP_ANON|MAP_SHARED, -1, 0);
memcpy(new, target_addr - 4*4, 4*4);       // 拷 svc 前 4 条指令(未做相对寻址修复,已知坑)
// 新页接判断码: cmp x16,#0x1a / b.ne 跳回原svc / 是 ptrace 跳到 svc 下一条
uint8_t check_jmp[] = {0x1f,0x6a,0x00,0xf1, 0x51,0x00,0x00,0x58, 0x20,0x02,0x1f,0xd6,
    /* orig_svc_next_addr 8B 小端 */ 0x51,0x00,0x00,0x58, 0x20,0x02,0x1f,0xd6, /* orig_svc_addr 8B */};
// # (省略:两个地址各按 8 字节小端逐字节展开)
patchCode(target_addr-4*4, /* ldr x16,#8 / br x16 / new_p */, 4*4);   // 目标处跳向新页
mprotect(new, len, PROT_READ|PROT_EXEC);
```

坑:被搬走的 4 条指令若含相对寻址(adrp/b)必须修复否则崩;集成进 xia0LLDB 可调试器内一键绕过。

### iOS LLDB中反反调试分析与实现
作者:xia0。LLDB 里 patch 掉 ptrace:内存找地址 → 改写首指令为 ret。**核心障碍**:iOS 不允许对代码段直接 mprotect/mach_vm_protect 加写权限,必须走 **remap**:

```c
new = mmap(0, 0x1000, RW, MAP_ANON|MAP_SHARED, -1, 0);
vm_copy(self_task, page_start, 0x1000, new);          // 拷 target 所在整页
*(uint32_t*)(new + patch_offset) = 0xd65f03c0;        // 写 ret
mprotect(new, 0x1000, PROT_READ|PROT_EXEC);           // mmap 页 max_protection=rwx 可改
mach_vm_remap(mach_task_self(), &target, 0x1000, 0, VM_FLAGS_OVERWRITE,
              self_task, new, TRUE, &c, &m, inherit); // 映射回 target 实现代码段改写
sys_icache_invalidate(...); sys_dcache_flush(...);    // 清缓存
```

坑:iOS 12 上 remap 后整页变 0(codesign 校验,HookZz 同样未支持),iOS 9 正常;忘 mprotect 改 rx 页属性是 rw 即执行异常(`memory region` 一查便知)。实战(爱奇艺 main 里动态调 ptrace):

```
debugserver 127.0.0.1:1234 -x backboard /var/.../iQiYiPhoneVideo.app/iQiYiPhoneVideo   # 经 iproxy
# lldb 挂上,main 断住后一行命令: debugme
(lldb) x/12i 0x00000001837dc180   # patch 前 mov x16,#0x1a / svc #0x80;patch 后首指令 0xd65f03c0 ret
```

libsystem_kernel 中 ptrace 识别特征就是 `mov x16,#0x1a; svc #0x80`(x16=26)。

### iOS反反调试助手
作者:Night_elf。通用越狱插件,设置面板按 App 勾选即绕,不逐 App 定位。PreferenceLoader+AppList(参考 RevealLoader),MonkeyDev 建 Logos Tweak 工程,plist 放 `/Package/Library/PreferenceLoader/Preferences/`,control Depends 加 `aplist, preferenceloader`。主逻辑:读 `/var/mobile/Library/Preferences/com.xxx.AntiAntiDebug.plist` 的 `AntiAntiDebugEnabled-<bundleid>` 开关,开了全量 hook:

```objc
MSHookFunction(MSFindSymbol(NULL,"_ptrace"), my_ptrace, &orig_ptrace);
MSHookFunction((void*)dlsym, my_dlsym, &orig_dlsym);
MSHookFunction((void*)sysctl, my_sysctl, &orig_sysctl);
MSHookFunction((void*)syscall, my_syscall, &orig_syscall);
hook_svc_x80();   // 内联 svc 专用
```

**svc 0x80 全量扫描 hook**(HookZz/Dobby,无法预知地址时的通用解):zz_macho 取 __text 起止+slide,循环 `zz_vm_search_data` 搜字节 `0xd4001001`,逐个 `ZzBuildHookAddress(svc, svc+4, pre_call, half_call, TRUE)` + `ZzEnableHook`。pre/half 回调按系统调用号分别处理——**不能统一 NOP**(正常逻辑也走 svc 会崩):

```c
// pre_call(RegState *rs):系统调用号 = rs->general.regs.x16,参数 = x0
SYS_syscall(ptrace,31,...) 变种: x1==PT_DENY_ATTACH → 写 regs.x1 = 0
SYS_ptrace 直调: x0==PT_DENY_ATTACH → 写 regs.x0 = 0
SYS_sysctl: STACK_SET 存 num_syscall 与 info_ptr(=regs.x2)
// half_call(返回前): info->kp_proc.p_flag &= ~(P_TRACED);  抹掉被调试标志位
```

坑:iOS 12.1.1 勾选后 debugserver 找不到进程,需 App 启动瞬间就挂载调试(启动时 attach)。

### 记一则iOS App 反调试绕过
作者:vlinkstone。症状:一启动就退出且无 crash log(主动退出),dump 工具没 dump 完,但日志显示所有 framework 已加载 → 走完 dyld 加载,lldb 断 `_dyld_start` 有时机。**拿解密 IPA 的取巧法**:改 frida-ios-dump 源码,把 `resume` 那行注释掉,程序停在解密完成后直接 dump 内存镜像。分析:MonkeyDev 全开反调试 hook 仍崩且堆栈被破坏;搜 svc 发现两段内联系统调用(一个退出、一个反调试),反调试前有破坏现场指令:

```asm
mov x1, #0
mov sp, x1      ; 清栈指针
mov x29, x1     ; 清帧指针
mov x30, x1     ; 清 lr —— 无脑 nop svc 会直接崩
```

解法:这两个函数没做别的事,直接在函数开头 ret(带返回值的改返回值),keypatch 完成;MonkeyDev 重打包安装即正常。防御视角:初始化阶段检测时机好;指令级 syscall+破坏堆栈防无脑 nop;启动后定时复查;动静太大(直接退出)不如上报;检测逻辑 inline 混进业务;隐而不发最狠。

### 记录1: 绕过iOS某音最新版反调试
作者:xiaoyiny。iPhone8 iOS13.3 越狱 + MonkeyDev + 砸壳 ipa(12.4.0)。AntiAntiDebug 开 sysctl hook 后调试器仍断开 → 检测在 `-[AppDelegate application:didFinishLaunchingWithOptions:]` 之前。定位流程(主二进制 170M,IDA 要耐心等):

1. AppDelegate didFinishLaunching 符号断点断不住 → 证实检测更早。
2. IDA 从入口 start 找 main,F5 发现 `mac_syscall`,切汇编码。
3. 特征:`mov x16,#0x1a`(26=ptrace)、`mov x0,#0x1f`(31=PT_DENY_ATTACH)、`svc #0x80` = `ptrace(31,0,0,0)` 内联版。
4. 验证绕过:在 svc 前一条(0x1043BE8F4)下断,断住后把装 31 的寄存器(该版本是 x1)改 0,continue → 反调试失效。

> 经验:改寄存器前先看汇编里 31 到底装在哪个寄存器,不同编译版本可能是 x0/x1。

## 2. Tweak 与 Theos 开发

### 手把手安装最新版Theos
作者:roysue(翻译)。

```bash
brew install dpkg ldid
sudo git clone --recursive https://github.com/theos/theos.git /opt/theos   # --recursive 必须,bootstrap.sh 已废弃
sudo chown $(id -u):$(id -g) /opt/theos
# ~/.bash_profile: export THEOS=/opt/theos; export PATH=/opt/theos/bin/:$PATH
# 验证:任意目录 nic.pl 出 New Instance Creator;旧版升级 git submodule update --recursive
```

### Tweak开发:给调音量增加震动反馈
作者:黑炭BC。Tweak + PreferenceBundle 全流程(样本 Volbrate)。hook 音量键(filter plist 的 Bundles 写 springboard):

```objc
%hook VolumeControl
-(void)increaseVolume {
    if(volVibrationOptions==2 || (volVibrationOptions==1 && volMax==YES)) [FeedbackCall vibrateDevice];
    else %orig;
}
// decreaseVolume 同构(volMin);-(float)volume 里 %orig 后记录 x==0→volMin、x==1→volMax、0<x<1 清两者
%end
```

私有 API 自定义震动(无官方文档):`AudioServicesPlaySystemSoundWithVibration(kSystemSoundID_Vibrate, nil, dict)`,dict 键 `VibePattern`(数组交替震/停毫秒,如 [YES,时长*1000,NO,50])与 `Intensity`(float)。

**PreferenceBundle(设置面板)**:theos `nic.pl` 选第 9 个模板 `preference_bundle_modern`,在 tweak 工程目录内创建,装后位于 `/Library/PreferenceBundles/`,与 tweak 一起 make。entry.plist = 设置入口图标文字;Root.plist = UI+变量声明(`<key>key</key><string>varName</string>`,并配 `<key>PostNotification</key><string>com.your.tweak/preferences.changed</string>` 让改设置发 Darwin 通知);Controller 继承 PSListController 实现 `- (id)specifiers`:`_specifiers = [[self loadSpecifiersFromPlistName:@"Root" target:self] retain];`。Tweak.xm 不能直接调 Bundle 取值,走 plist(`~/.Library/Preferences/`)交互,`%ctor` 初始化 + Darwin 通知实时响应:

```objc
// NSUserDefaults 分类补 objectForKey:inDomain: 后:
static void notificationCallback(...) {
    NSNumber *n = [[NSUserDefaults standardUserDefaults] objectForKey:@"enabled" inDomain:nsDomainString];
    enabled = (n)? [n boolValue]:YES;
}
%ctor {
    notificationCallback(NULL,NULL,NULL,NULL,NULL);   // 启动先读一次
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL,
        notificationCallback, (CFStringRef)nsNotificationString, NULL, CFNotificationSuspensionBehaviorCoalesce);
}
```

## 3. 免越狱 hook 与注入

### Unity3D游戏修改&iOS免越狱hook
作者:Night_elf。工具链:越狱机(砸壳必需)+ frida-ios-dump + IDA + Il2CppDumper + MonkeyDev + IPAPatch + 汇编转机器码工具。砸壳:`iproxy 2222 22; frida-ps -U` 找进程名;`python2 dump.py <游戏名>` 生成砸壳 ipa。

**IL2CPP 符号恢复**:①解压 ipa,主可执行 = 包里最大文件,`global-metadata.dat` 在 `xxx.app/Data/Managed/Metadata/`;②IDA 搜 `X-Unity-Version` 确认引擎版本;③Il2CppDumper 选主程序+metadata,选模式 3 → 生成 `dump.cs`(类/属性/函数全量)+ `script.py`;④IDA `File → Script File → script.py`,sub_xxx 全变 `类名$$函数名`。定位:dump.cs 搜业务词(金币搜 `Gold` → `get_Gold`),IDA 定位地址,lldb 下断验证(打开提示触发断点、返回值随金币变化 → 实锤)。
越狱 hook(MonkeyDev Tweak):

```objc
int (*old_get_Gold)(); int new_get_Gold(){ return 9999; }
%ctor{
    unsigned long Gold = _dyld_get_image_vmaddr_slide(0) + 0x1011aa060;  // slide+静态偏移
    MSHookFunction((void *)Gold, (void *)&new_get_Gold, (void **)&old_get_Gold);
}
```

未越狱修改:直接改汇编——get_Gold 返回处改 `mov x0,#9999; ret`(ret 机器码 `C0 03 5F D6`),汇编码转换器生成机器码替换,可执行文件放回 ipa 重压 zip 改名 app.ipa,丢进 IPAPatch 的 Assets 目录编译安装。免越狱 dylib 注入(MonkeyDev = iOSOpenDev 升级版):Xcode 新建 MonkeyApp 工程,砸壳 ipa/xxx.app 放 `TargetApp/`,dylib 里写 Logos hook 重签安装:

```objc
%hook UnityAppController
- (void)init{ %orig; /* UIAlertView 弹窗验证 hook 成功 */ }
%end
```

坑:未越狱不支持 MSHookFunction,sub_xxx 无符号 C 函数不能 inlinehook——只能 hook OC 方法或静态 patch;换目标 App 改 Tweak plist 的 Bundles 为目标 bundleid;Build Settings → User-Defined 加 `CODE_SIGNING_ALLOWED=NO`,Build System 改 Legacy,装 sshpass。

### iOS 11上的破解入门教程
作者:DeviLeo。脱离 CydiaSubstrate 纯手工砸壳+写 dylib+注入全流程(以《干掉月亮》为例)。

**bfinject 砸壳与注入**(须在 bfinject 目录下执行;中途闪退则 Ctrl+C 重启 App 再来):

```bash
iproxy 2222 22 && ssh root@localhost -p 2222        # 默认密码 alpine
ps -e | grep moon                                    # 拿进程名/PID
bash bfinject -P shootthemoon -L decrypt             # 或 -p PID;产物 decrypted.ipa 在 App Documents
scp -P 2222 root@localhost:/private/var/mobile/Containers/Data/Application/<UUID>/Documents/decrypted-app.ipa ./
bash bfinject -P shootthemoon -l ~/ShootMoonHacker   # 注入自编译 dylib
```

applst 列 App 信息:`bundleURL`(App 目录)/`dataContainerURL`(数据目录);Mac 端 Console.app 选 iPhone 按自定义日志前缀过滤,确认注入后代码是否执行。**破解 dylib**:Xcode 建 Cocoa Touch Framework,核心 Method Swizzling:

```objc
// 通用交换封装:method_exchangeImplementations(om, nm);om/nm 按 isInstanceMethod 取
// class_getInstanceMethod / class_getClassMethod;类名/方法名 NSClassFromString+NSSelectorFromString
- (void)my_updateScore:(int)score { score = 10; [self my_updateScore:score]; }  // 交换后 my_ 调的才是原实现
static void __attribute__((constructor)) entry(void){ /* [[NSObject new] hack] 里做交换 */ }
```

编译三配置:iOS Deployment Target 11.0、签名 None、目标 Generic iOS Device;带参方法名字符串带冒号(`updateScore:`,多参 `plus:and:`)。
**macho_edit 插 LC_LOAD_DYLIB**(免越狱持久注入):`macho_edit shootthemoon` → 2 Load command edit → 3 Insert load command → 1 LC_LOAD_DYLIB → path `@executable_path/ShootMoonHacker`。坑:有插入 bug,新条目可能带乱码尾巴(`...ShootMoonHackers/MediaP`),须 2 Remove 删掉重插;改完覆盖回 .app,Finder 压缩 Payload 改名 ipa,Impactor 安装(Apple ID 关二次验证;先卸原 App,签名不同不能覆盖)。

## 4. 工具小件

### 从Mach-O中导出swift对象定义的小工具SwiftDump
作者:butterflydog。class-dump 的 Swift 5 版:从 Mach-O 导出 struct/class/enum/protocol(支持 enum with payload case、继承与 protocol);混编工程 class-dump + SwiftDump 配合用。

```bash
SwiftDump ./TestMachO > result.txt
SwiftDump -a x86_64 ./TestMachO > result.txt   # fat binary 选架构(默认 arm64)
```
原理:借 Swift 运行时函数 demangle——`swift_getTypeByMangledNameInContext` / `swift_demangle_getDemangledName`,可还原复杂泛型(RxSwift 嵌套泛型签名全量展开)。另有 Frida 版 FridaSwiftDump 直接解析前台运行中的 App。

### 绕过Android/iOS的dlopen/dlsym限制的dlfunctions库
作者:waruqi。byOpen 库,Android/iOS 双端 fake dlopen。

- Android:7+ 的 dlopen/System.load 受 classloader-namespace 限制;常规 fake dlopen(Nougat_dlfunctions 等)只能从 /proc/self/maps 找已加载 so——byOpen 额外"把自己伪装成系统调用方"触发 System.loadLibrary,把**还没进 maps 的系统 so 强行加载**进来再 fake dlsym;符号检索同时支持 .dynsym/.symtab;低版本回落原生 dlopen。Java 层关键:反射取 `forName("java.lang.System")` 与 `getDeclaredMethod("loadLibrary",...)` 后 `loadLibrary.invoke(systemClass, name)`,让系统以为是系统自身在调。
- iOS:dlopen 本身能用,但 **AppStore 审核扫 dlopen/dlsym 调用判私有 API**;byOpen 自己实现 by_dlopen/by_dlsym,直接从已加载 images 列表查 symbol,规避二进制里的引用;符号名字符串自行加密变换,别明文编进包。用法:`by_pointer_t h = by_dlopen("libcurl.so", BY_RTLD_LAZY); f = by_dlsym(h, "curl_version");`。编译:xmake;`xmake f -p iphoneos -a arm64 && xmake`。

### 基于Frida和RPC，从Python中直接调用iOS的Native方法
作者:梦野间(翻译)。Frida NativeFunction 三步——找地址、建函数对象、调用:

```js
new NativeFunction(Module.findExportByName('AudioToolbox','AudioServicesPlaySystemSound'),'void',['int'])(1007)
// 分步: address → new NativeFunction(地址,'返回类型',['参数类型数组']) → 调用
```
函数签名不用逆,查 Apple 文档头文件(`void AudioServicesPlaySystemSound(SystemSoundID id)` → `'void',['int']`)。系统音效 id:1007 短信/1000 邮件/1100 锁屏/1108 拍照,音频在 `/System/Library/Audio/UISounds/`。调系统函数附任意 App;调 App 自己的必须附该 App。

**RPC 化——把 App 当本地 Python 库用**:

```js
// audiobox_rpc.js
rpc.exports = { sms: ()=>_play(1007), email: ()=>_play(1000) };
// ObjC 同样可 RPC:ObjC.classes.UIApplication.sharedApplication().openURL_(ObjC.classes.NSURL.URLWithString_(url))
```
```python
session = frida.get_usb_device().attach('Telegram')
script = session.create_script(open('./audiobox_rpc.js', encoding='utf-8').read())
script.load(); script.exports.sms(); script.exports.email(); session.detach()
```
核心价值:App 已实现 encrypt()/decrypt() 时别去抠密钥复现算法——直接 RPC 调 App 内函数,密钥在 Secure Enclave 也无所谓。

### 发现iOS INstruments服务器
作者:daemond(翻译)。iOS 设备上除 debugserver 还跑 **Instruments 服务**(DTServiceHub/DVTInstrumentsFoundation):进程列表、应用列表、启动/杀进程都走它。服务发现:挂 DeveloperDiskImage.dmg 见三个 plist(debugserver / instruments.remoteserver / instruments.deviceservice);Mac 侧经 MobileDevice.framework 启动:

```c
AMDeviceSecureStartService(device_handle, CFSTR("com.apple.debugserver"), &srv_handle);
AMDServiceConnectionReceive(srv_handle, buf, sizeof(buf), &nrecv);
```
**DTXMessage 机制**:Instruments 前后端协议 = 序列化 NSInvocation 跨设备传输。流:Xcode 发 `_notifyOfPublishedCapabilities:` → `_requestChannelWithCode:identifier:`(如 `com.apple.instruments.server.services.deviceinfo`)→ 对该 channel 发具体 selector(如 `runningProcesses`);channel identifier 决定接收者。关键结构(写协议交互必备):

```c
struct DTXMessageHeader { uint32 magic, cb; uint16 fragmentId, fragmentCount;
                          uint32 length, identifier, conversationIndex, channelCode, expectsReply; };
struct DTXMessagePayloadHeader { uint32 flags, auxiliaryLength; uint64 totalLength; };
```

工具:IDA 插件 dtxmsg(微码检测序列化时机,dump 每条消息并反序列化成明文)+ 独立客户端 dtxmsg_client(不依赖 Apple 代码)。敏感方法:

```
-[DTDeviceInfoService runningProcesses]
-[DTApplicationListingService installedApplicationsMatching:registerUpdateToken:]
-[DTProcessControlService launchSuspendedProcessWithDevicePath:bundleIdentifier:environment:arguments:]
-[DTProcessControlService killPid:]
```
方法论:分析私有协议**先逆官方客户端**(Xcode IDE 二进制里能看消息构造)比硬啃服务端序列化快;静态理解+断点抓线上样本结合成功率最高。

## 5. 游戏与 App 实战

### 浅谈iOS游戏的汉化
作者:obaby。两条非常规路线(通用五步流程见 iOS攻防与进阶.md §7,此处是增量手法)。

**路线一:跨平台"借尸还魂"**——同一套代码的跨平台游戏直接用 Windows 已汉化资源替换 iOS 版资源(恶霸鲁尼用 3dm 汉化版):替换 xml、font、english(注意菜单崩溃)、menu,重打包 `zip -0 -qr .../Bully2.zip .`。

**路线二:Caption Hook 动态汉化**——不改资源,hook 渲染函数运行时做原文→译文字典替换(自研引擎适用)。引擎贴图出口 `id -[HpLib_Graphics makeTextImage:]`:

```objc
CHDeclareClass(HpLib_Graphics);
CHOptimizedMethod(1, self, id, HpLib_Graphics, makeTextImage, NSString *, arg1) {
    NSString *ch_string = ch_dic[arg1];  if ([ch_string length]==0) ch_string = @"喵喵喵";
    return CHSuper(1, HpLib_Graphics, makeTextImage, ch_string);   // 无命中传原 arg1 走原逻辑
}
// 补:部分文本走 NSString 构造,一并 hook HpLib_GSystem strNSString /
// NSPlaceholderString 的 initWithBytes:length:encoding / initWithCString:encoding / initWithUTF8String
```

**成果保护**(防 dylib 被扒):字典加密(BABYStringEncoding/GTM_Encoder),dylib 内解密后 NSPropertyListSerialization 还原:`gtc2 = [[BABYStringEncoding alloc] initWithString:@"aCDEfGHijKlMnopQRsUvWXz012345689"]; [gtc2 decode:文件串 error:nil]`。命令行:`GTM_Encoder -encodeFile <key> <输入plist> <输出enc>`(-decodeFile 反向)。

### 某iOS遊戲抓包、修改
作者:Invert。单机+联网混合游戏(Arcaea 类)从数值修改到私服全链路。

**IDA 前处理**:Shift-F7 把名字带 const/string/data 的段权限全改只读,IDA 才能正确识别字符串;短字符串(如 `fr_v`)可能没被认出,用二进制搜:hex 后 Hex View 里 Alt-B Binary search。**本地数值修改**:残片存 `Preferences/moe.low.arc.plist` 的 `fr_v`,`fr_k` 是哈希校验——**不用逆校验算法**:XREF 定位读取函数,确认返回值直接赋给结构体无二次校验,把函数开头改成返回 999999999。机器码生成:Compiler Explorer 选 armv8-a 编译目标,抄每行汇编上方 hex(Little-endian DWORD 写文件要 swap);IDA Hex View 按 F2 直接覆写 hex,汇编界面按 P 重建函数可 F5;`Edit → Patch program → Apply patches to input file` 写回(须在汇编或 Hex 界面)。

**资源哈希校验绕过**:songlist/packlist/unlocks 三文件校验 = `std::string::compare` 比对写死的哈希串,compare 后紧跟 `CBNZ`(不等则跳)——**把所有 CBNZ 换 NOP(`1F 20 03 D5`)即绕过**,不用研究哈希算法。songlist 删 `remote_dl` 字段+放本地 ogg/aff 可把云歌曲转本地;改 unlocks 解锁全部曲目。

**HTTPS 抓包三层拆**:

1. 证书锁定:字符串确认 TrustKit → hook/patch `[TSKPinningValidator evaluateTrust:forHostname:]` 直接返回 true(`mov w0,#1; ret`)。
2. **mTLS 双向认证**:Burp 在中间会阻断客户端证书上送。定位:IDA 搜 `NSURLAuthenticationMethodClientCertificate` → `getClientIdentity` → 读 `self->sslCert`(PKCS12 二进制)与 `self->sslCertPassword`。
3. LLDB 动态提取:Xcode `Debug → Attach to Process by PID or Name`,`target modules list` 拿基址+函数偏移=断点地址;断在读 sslCert 处 `po $x8` dump 出 p12,同理拿密码。改完无需抓包的做法:Go 写转发代理 embed p12:

```go
//go:embed v4.0.255_key.p12
var key []byte; var password = "xxx"
clientKey, clientCert, _ := pkcs12.Decode(key, password)
http.DefaultClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{
    Certificates: []tls.Certificate{{Certificate: [][]byte{clientCert.Raw}, PrivateKey: clientKey}}}}
// handler 里把请求 URL 改写为真实 API host 转发,响应原样回写
```

Burp 侧 Python 插件改 host 指本地:processHttpMessage 里判 `getHost()=="arcapi-v2.lowiro.com"` 时 `messageInfo.setHttpService(helpers.buildHttpService("127.0.0.1", 5151, "http"))`。

**加密 API Endpoint 改写(CFB 通用技巧)**:endpoint 前缀 `https://arcapi-v2.lowiro.com/join/21/` 是 CFB 模式加密(密文 48 字节=3 block)。CFB 下 `C1 = P1 ⊕ XK1`,改明文只需 `C1' = P1' ⊕ P1 ⊕ C1`;改当前 block 会影响下一 block 的 XOR Key → 在解密 do-while 前下断,LLDB 看寄存器拿当前 block 的 C 与 XK(如 x10=C1、x9=XK1),`memory write $x10 0x11 0x22...` 逐 block 覆写,do-while 后断点 `x/16b $x11-16` 验证明文;3 block 改完把新密文写回 IDA 对应数据位置,私服 endpoint 生效。

### 关于某好车主ios版本分析
作者:那年没下雪。App 双向 SSL 抓不动,转 iOS 侧静态+动态分析请求头 `X-pa-Sign` 与 `Spartaid`(3.58.1,新版加密通用)。

**手工部署 debugserver**(无现成环境时):

```bash
# DeveloperDiskImage.dmg 在 Xcode 的 DeviceSupport/<版本>/ 下,挂载取 usr/bin/debugserver;
# 同目录造 entitlement.xml:debugapplications/get-task-allow/task_for_pid-allow/run-unsigned-code 全 true
codesign -s - --entitlements entitlement.xml -f debugserver
scp -r debugserver root@localhost -p xxxx:/usr/bin       # 经 iproxy 转发
# 手机: debugserver 127.0.0.1:1998 -a /var/mobile/进程
# Mac:  lldb -> process connect connect://localhost:1998
```

**X-PA-Sign 逆法**:IDA 搜字符串 `X-PA-SIGN` 到引用,定位加请求头的方法 → 签名函数 sub_1014DACA4 下断,lldb 打寄存器逐个对参加抓包样本:

| 寄存器 | 含义 |
|---|---|
| x0 | HTTP 方法 |
| x1 | 请求路径 |
| x2 | 请求参数 |
| x3 | body 的 base64 |
| x4 | 时间戳 |
| x5 | 平台 |
| x6 | 平台特定串 |
| x7 | 固定值 1 |

结论:参数按序拼接(GET 直接拼;POST 路径后接 body base64)后 SHA256。与 Android 版互相印证(Android so 难啃时切 iOS 侧是捷径)。

**Spartaid 逆法**:定位 Lion_meta 三个方法(前两收集设备信息、第三加密)。**不细读算法,直接断 CCCrypt 打入参/返回值**:AES ECB PKCS7,key 硬编码固定值(如 `OkqDu3nfoVGNIyQA`)。坑:iOS 的编码结果与 Java/Python 有差异,复现注意对齐。

### 是谁推开我的"窗"：iOS App接口安全分析
作者:starbuck(长亭 张一峰)。URLScheme + JSBridge 攻击面方法论(白盒审计/渗透通用)。

**成因链**:info.plist 注册自定义 URLScheme → 任意 App/网页可调(safari 里 js 自动点击即触发;首次需用户确认但无法分辨恶意跳转)→ 回调函数解析 scheme 参数(攻击者可控)→ 回调能加载任意 URL 且 WebView 注册了 JSBridge → 任意页面上下文调 JSBridge 接口。

- **案例1 远程窃 token**:scheme 参数 `url=https://evil.com` 过两道弱检查(有 url key + https 开头)被 BaseWebViewController 直接加载;JSBridge `registerLoginHandler` 暴露 Module 类任意函数调用 → getUserInfo 拿手机号/UID/companyID/token 外传(移动端 token 有效期长=账号接管)。
- **案例2 任意文件上传**:`shouldStartLoadWithRequest` 拦截自定义 scheme → handleMessage 解析 action/args(均可控)→ 权限校验缺陷 → action 拼 `jsapi_` 前缀+`completion` 后缀送 `performSelector` = **任意函数调用**;选 uploadImages(url=自己服务器, path=沙箱 sqlite 路径)→ 沙箱任意文件上传。performSelector 动态调用在这类回调里占比最大(有的 App 按数字前缀分发,传串数字就能连环调用)。
- **案例3 支付逻辑**:插件机制按插件 ID 可调 walletPaySDK,参数带 OrderID——生成订单诱导他人支付;支付类 SDK 必须显式展示商品与金额。
- **触发面扩展**:二维码扫描(同一 scheme 名多入口)、后台触发、WKWebView 的 JS 注入(沙箱/远程 JS 被注入所有页面=驻留 JSBridge;结合文件写可打 XSS)。

**审计/挖掘清单**:①看 info.plist URLScheme 定义 → ②跟回调函数重点找"加载任意 URL" → ③找二维码等其他加载任意 URL 途径 → ④枚举 JSBridge 可调接口找越权/敏感操作。开发建议:scheme 最少化;敏感操作原生实现;外部可调接口严格过滤调用者。
