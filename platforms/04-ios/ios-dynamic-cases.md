# iOS Dynamic Casebook (anti-debug confrontation hands-on / Tweak development / jailbreak-free hooking / tool bits / game and app field work)

> Knowledge base 04-iOS security · file 3 (companion to ios-files-and-signing.md). For principle quick tables see [ios-offense-defense.md](ios-offense-defense.md) (anti-debug/jailbreak-detection quick tables); this file is all **practice-grade** cases: copy-pasteable commands, code, and pitfalls.

## 1. Anti-Debug Confrontation, Hands-On

### Beating anti-debug with iOS inlinehook
Author: xia0. Against anti-debug that inlines `svc #0x80` to call syscalls directly (where fishhook fails). Target signature (syscall 26, ptrace): `asm volatile("mov x0,#31\n mov x16,#26\n svc #128\n")` (PT_DENY_ATTACH + SYS_ptrace).

**Move 1: static memory-signature patching** — step 1 parse your own Mach-O to get the __TEXT range (walk load_commands; in LC_SEGMENT_64 with segname=__TEXT/sectname=__text, `start = addr + _dyld_get_image_vmaddr_slide(0)`); step 2 walk and scan for the two-instruction signature; step 3 patch the svc into a nop:

```c
// mov x16,#0x1a = 0xd2800350 ; svc #0x80 = 0xd4001001
if (*((uint32_t*)p)==0xd2800350 && *((uint32_t*)p+1)==0xd4001001) return p;
uint8_t nop[4] = {0x1f,0x20,0x03,0xd5};   patchCode(ptrace_svc_p+4, nop, 4);
```

**Move 2: inlinehook dynamic bypass** (against obfuscated syscall numbers/compile variants): hook every svc in the code section; at execution check whether x16 is 26 — if so skip the svc, otherwise jump back to the original svc so the other syscalls keep working:

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

Pitfall: if the 4 relocated instructions contain relative addressing (adrp/b) they must be repaired or it crashes; integrated into xia0LLDB it becomes a one-click bypass inside the debugger.

### Analyzing and implementing anti-anti-debug in iOS LLDB
Author: xia0. Patch out ptrace from LLDB: find the address in memory → rewrite the first instruction as ret. **The core obstacle**: iOS forbids adding write permission to code sections via direct mprotect/mach_vm_protect; you must go through **remap**:

```c
new = mmap(0, 0x1000, RW, MAP_ANON|MAP_SHARED, -1, 0);
vm_copy(self_task, page_start, 0x1000, new);          // 拷 target 所在整页
*(uint32_t*)(new + patch_offset) = 0xd65f03c0;        // 写 ret
mprotect(new, 0x1000, PROT_READ|PROT_EXEC);           // mmap 页 max_protection=rwx 可改
mach_vm_remap(mach_task_self(), &target, 0x1000, 0, VM_FLAGS_OVERWRITE,
              self_task, new, TRUE, &c, &m, inherit); // 映射回 target 实现代码段改写
sys_icache_invalidate(...); sys_dcache_flush(...);    // 清缓存
```

Pitfalls: on iOS 12 the remapped page turns to zeros (codesign validation; HookZz doesn't support it either), while iOS 9 works; forgetting mprotect leaves the rx page as rw and execution faults (`memory region` reveals it instantly). Field case (iQiyi calling ptrace dynamically inside main):

```
debugserver 127.0.0.1:1234 -x backboard /var/.../iQiYiPhoneVideo.app/iQiYiPhoneVideo   # 经 iproxy
# lldb 挂上,main 断住后一行命令: debugme
(lldb) x/12i 0x00000001837dc180   # patch 前 mov x16,#0x1a / svc #0x80;patch 后首指令 0xd65f03c0 ret
```

The ptrace recognition signature inside libsystem_kernel is exactly `mov x16,#0x1a; svc #0x80` (x16=26).

### The iOS anti-anti-debug assistant
Author: Night_elf. A universal jailbreak plugin: tick per app in the settings panel and it bypasses — no per-app locating. PreferenceLoader + AppList (modeled on RevealLoader), a MonkeyDev Logos Tweak project, the plist in `/Package/Library/PreferenceLoader/Preferences/`, control Depends adds `aplist, preferenceloader`. Main logic: read the `AntiAntiDebugEnabled-<bundleid>` switch from `/var/mobile/Library/Preferences/com.xxx.AntiAntiDebug.plist`; when on, hook everything:

```objc
MSHookFunction(MSFindSymbol(NULL,"_ptrace"), my_ptrace, &orig_ptrace);
MSHookFunction((void*)dlsym, my_dlsym, &orig_dlsym);
MSHookFunction((void*)sysctl, my_sysctl, &orig_sysctl);
MSHookFunction((void*)syscall, my_syscall, &orig_syscall);
hook_svc_x80();   // 内联 svc 专用
```

**Full-scan svc 0x80 hooking** (HookZz/Dobby; the universal solution when addresses cannot be predicted): zz_macho gets the __TEXT start/end + slide, loops `zz_vm_search_data` scanning for the bytes `0xd4001001`, and per hit `ZzBuildHookAddress(svc, svc+4, pre_call, half_call, TRUE)` + `ZzEnableHook`. The pre/half callbacks dispatch on the syscall number — **do not NOP them all uniformly** (normal logic also goes through svc; blanket NOPs crash):

```c
// pre_call(RegState *rs):系统调用号 = rs->general.regs.x16,参数 = x0
SYS_syscall(ptrace,31,...) 变种: x1==PT_DENY_ATTACH → 写 regs.x1 = 0
SYS_ptrace 直调: x0==PT_DENY_ATTACH → 写 regs.x0 = 0
SYS_sysctl: STACK_SET 存 num_syscall 与 info_ptr(=regs.x2)
// half_call(返回前): info->kp_proc.p_flag &= ~(P_TRACED);  抹掉被调试标志位
```

Pitfall: on iOS 12.1.1 after ticking, debugserver can't find the process — the debugger must attach at the instant the app launches.

### A note on bypassing an iOS app's anti-debugging
Author: vlinkstone. Symptoms: exits on launch with no crash log (a voluntary exit); dump tools didn't finish, but the log shows all frameworks loaded → dyld loading finished, so breaking at `_dyld_start` has a window. **A shortcut to get the decrypted IPA**: modify frida-ios-dump's source, comment out the `resume` line; the program halts right after decryption and you dump the memory image directly. Analysis: with MonkeyDev's anti-anti-debug hooks all on it still crashes and the stack is wrecked; scanning for svc reveals two inline syscalls (one exits, one anti-debugs), with scene-wrecking instructions before the anti-debug:

```asm
mov x1, #0
mov sp, x1      ; 清栈指针
mov x29, x1     ; 清帧指针
mov x30, x1     ; 清 lr —— 无脑 nop svc 会直接崩
```

Solution: these two functions do nothing else, so just ret at the function head (change the return value where one is expected); keypatch finishes it; repackage with MonkeyDev, install, and it runs. Defensive perspective: the initialization phase is a good detection window; instruction-level syscalls + stack wrecking defeat blanket nops; periodic re-checks after launch; being too loud (exiting outright) is worse than reporting; inlining detection logic into business code; staying hidden and silent hits hardest.

### Record 1: bypassing the latest anti-debugging of an iOS short-video app
Author: xiaoyiny. iPhone8 iOS13.3 jailbreak + MonkeyDev + the dumped ipa (12.4.0). With AntiAntiDebug's sysctl hook on, the debugger still detaches → detection happens before `-[AppDelegate application:didFinishLaunchingWithOptions:]`. Locating flow (the main binary is 170MB; be patient with IDA):

1. The AppDelegate didFinishLaunching symbol breakpoint never hits → confirms the detection is earlier.
2. From the entry start, find main in IDA; F5 reveals `mac_syscall`; switch to the assembly listing.
3. Signature: `mov x16,#0x1a` (26=ptrace), `mov x0,#0x1f` (31=PT_DENY_ATTACH), `svc #0x80` = the inlined `ptrace(31,0,0,0)`.
4. Verified bypass: break one instruction before the svc (0x1043BE8F4); once hit, set the register holding 31 (x1 in this version) to 0 and continue → the anti-debug stops working.

> Lesson: before changing a register, check the assembly for which register actually holds 31 — different compile versions may use x0/x1.

## 2. Tweak and Theos Development

### Installing the latest Theos, step by step
Author: roysue (translation).

```bash
brew install dpkg ldid
sudo git clone --recursive https://github.com/theos/theos.git /opt/theos   # --recursive 必须,bootstrap.sh 已废弃
sudo chown $(id -u):$(id -g) /opt/theos
# ~/.bash_profile: export THEOS=/opt/theos; export PATH=/opt/theos/bin/:$PATH
# 验证:任意目录 nic.pl 出 New Instance Creator;旧版升级 git submodule update --recursive
```

### Tweak development: adding vibration feedback to volume changes
Author: 黑炭BC. The full Tweak + PreferenceBundle flow (sample: Volbrate). Hooking the volume keys (the filter plist's Bundles set to springboard):

```objc
%hook VolumeControl
-(void)increaseVolume {
    if(volVibrationOptions==2 || (volVibrationOptions==1 && volMax==YES)) [FeedbackCall vibrateDevice];
    else %orig;
}
// decreaseVolume 同构(volMin);-(float)volume 里 %orig 后记录 x==0→volMin、x==1→volMax、0<x<1 清两者
%end
```

Custom vibration via a private API (no official docs): `AudioServicesPlaySystemSoundWithVibration(kSystemSoundID_Vibrate, nil, dict)`, with dict keys `VibePattern` (an array alternating vibrate/pause in milliseconds, e.g. [YES,duration*1000,NO,50]) and `Intensity` (float).

**PreferenceBundle (the settings panel)**: in theos `nic.pl` pick the 9th template `preference_bundle_modern`, created inside the tweak project directory; after installing it lives at `/Library/PreferenceBundles/`, built together with the tweak. entry.plist = the settings-entry icon text; Root.plist = UI + variable declarations (`<key>key</key><string>varName</string>`, plus `<key>PostNotification</key><string>com.your.tweak/preferences.changed</string>` so setting changes post a Darwin notification); the Controller subclasses PSListController and implements `- (id)specifiers`: `_specifiers = [[self loadSpecifiersFromPlistName:@"Root" target:self] retain];`. Tweak.xm cannot call the Bundle for values directly — interact through the plist (`~/.Library/Preferences/`), initialize in `%ctor` and respond live via Darwin notifications:

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

## 3. Jailbreak-Free Hooking and Injection

### Unity3D game modding & jailbreak-free iOS hooking
Author: Night_elf. Toolchain: a jailbroken phone (mandatory for dumping) + frida-ios-dump + IDA + Il2CppDumper + MonkeyDev + IPAPatch + an assembly-to-opcode converter. Dumping: `iproxy 2222 22; frida-ps -U` to find the process name; `python2 dump.py <game name>` produces the decrypted ipa.

**IL2CPP symbol restoration**: ① unzip the ipa; the main executable = the largest file in the bundle; `global-metadata.dat` at `xxx.app/Data/Managed/Metadata/`; ② in IDA search `X-Unity-Version` to confirm the engine version; ③ Il2CppDumper picks the main program + metadata, mode 3 → emits `dump.cs` (full classes/properties/functions) + `script.py`; ④ in IDA `File → Script File → script.py` and every sub_xxx becomes `ClassName$$MethodName`. Locating: search dump.cs for business words (for gold coins search `Gold` → `get_Gold`), locate the address in IDA, break with lldb to verify (opening the prompt triggers the breakpoint, the return value tracks the coin count → confirmed).
Jailbroken hooking (MonkeyDev Tweak):

```objc
int (*old_get_Gold)(); int new_get_Gold(){ return 9999; }
%ctor{
    unsigned long Gold = _dyld_get_image_vmaddr_slide(0) + 0x1011aa060;  // slide+静态偏移
    MSHookFunction((void *)Gold, (void *)&new_get_Gold, (void **)&old_get_Gold);
}
```

Un-jailbroken modification: edit the assembly directly — at get_Gold's return, write `mov x0,#9999; ret` (ret opcode `C0 03 5F D6`); an assembly converter generates the opcode bytes, replace them, put the executable back into the ipa, re-zip, rename to app.ipa, drop it into IPAPatch's Assets directory, build and install. Jailbreak-free dylib injection (MonkeyDev = the upgraded iOSOpenDev): in Xcode create a MonkeyApp project, put the decrypted ipa/xxx.app under `TargetApp/`, write Logos hooks in the dylib, re-sign and install:

```objc
%hook UnityAppController
- (void)init{ %orig; /* UIAlertView 弹窗验证 hook 成功 */ }
%end
```

Pitfalls: no MSHookFunction without a jailbreak; symbol-less C sub_xxx functions cannot be inlinehooked — you can only hook OC methods or patch statically; to switch target apps, change the Tweak plist's Bundles to the target bundleid; Build Settings → User-Defined add `CODE_SIGNING_ALLOWED=NO`, set Build System to Legacy, install sshpass.

### A cracking starter tutorial on iOS 11
Author: DeviLeo. The full CydiaSubstrate-free, purely manual flow of dumping + writing a dylib + injection (using "Shoot the Moon" as the example).

**bfinject dumping and injection** (must be run inside the bfinject directory; if the app crashes mid-way, Ctrl+C, restart the app and retry):

```bash
iproxy 2222 22 && ssh root@localhost -p 2222        # 默认密码 alpine
ps -e | grep moon                                    # 拿进程名/PID
bash bfinject -P shootthemoon -L decrypt             # 或 -p PID;产物 decrypted.ipa 在 App Documents
scp -P 2222 root@localhost:/private/var/mobile/Containers/Data/Application/<UUID>/Documents/decrypted-app.ipa ./
bash bfinject -P shootthemoon -l ~/ShootMoonHacker   # 注入自编译 dylib
```

applst lists app info: `bundleURL` (the app directory)/`dataContainerURL` (the data directory); on the Mac, Console.app selecting the iPhone and filtering by a custom log prefix confirms whether the injected code ran. **The crack dylib**: in Xcode create a Cocoa Touch Framework; the core is Method Swizzling:

```objc
// 通用交换封装:method_exchangeImplementations(om, nm);om/nm 按 isInstanceMethod 取
// class_getInstanceMethod / class_getClassMethod;类名/方法名 NSClassFromString+NSSelectorFromString
- (void)my_updateScore:(int)score { score = 10; [self my_updateScore:score]; }  // 交换后 my_ 调的才是原实现
static void __attribute__((constructor)) entry(void){ /* [[NSObject new] hack] 里做交换 */ }
```

Three build settings: iOS Deployment Target 11.0, signing None, destination Generic iOS Device; argument-carrying method-name strings keep their colons (`updateScore:`, multi-arg `plus:and:`).
**macho_edit inserting LC_LOAD_DYLIB** (jailbreak-free persistent injection): `macho_edit shootthemoon` → 2 Load command edit → 3 Insert load command → 1 LC_LOAD_DYLIB → path `@executable_path/ShootMoonHacker`. Pitfall: an insertion bug can leave the new entry with a garbage tail (`...ShootMoonHackers/MediaP`); use 2 Remove to delete and re-insert; after editing, overwrite back into the .app, compress Payload in Finder, rename to ipa, install with Impactor (Apple ID with two-factor off; uninstall the original app first — differing signatures cannot overlay-install).

## 4. Tool Bits

### SwiftDump: a small tool exporting swift object definitions from a Mach-O
Author: butterflydog. The Swift 5 edition of class-dump: exports struct/class/enum/protocol from a Mach-O (supports enums with payload cases, inheritance and protocols); in mixed projects use class-dump + SwiftDump together.

```bash
SwiftDump ./TestMachO > result.txt
SwiftDump -a x86_64 ./TestMachO > result.txt   # fat binary 选架构(默认 arm64)
```

Principle: borrows the Swift runtime's demangle functions — `swift_getTypeByMangledNameInContext` / `swift_demangle_getDemangledName`; restores complex generics (RxSwift nested generic signatures fully expanded). There is also a Frida edition, FridaSwiftDump, parsing the app running in the foreground directly.

### dlfunctions: a library bypassing Android/iOS dlopen/dlsym restrictions
Author: waruqi. The byOpen library, a fake dlopen for both Android and iOS.

- Android: 7+ restricts dlopen/System.load via the classloader-namespace; conventional fake dlopens (Nougat_dlfunctions etc.) can only find already-loaded so from /proc/self/maps — byOpen additionally "disguises itself as the system caller" to trigger System.loadLibrary, **force-loading system so that never entered maps**, then fake dlsym; symbol lookup covers both .dynsym/.symtab; older versions fall back to native dlopen. The Java-layer key: via reflection grab `forName("java.lang.System")` and `getDeclaredMethod("loadLibrary",...)`, then `loadLibrary.invoke(systemClass, name)` so the system believes it called itself.
- iOS: dlopen itself works, but **AppStore review scans dlopen/dlsym calls to flag private APIs**; byOpen implements by_dlopen/by_dlsym itself, resolving symbols straight from the loaded-images list and avoiding references in the binary; encrypt/transform the symbol-name strings — never compile them in plaintext. Usage: `by_pointer_t h = by_dlopen("libcurl.so", BY_RTLD_LAZY); f = by_dlsym(h, "curl_version");`. Build: xmake; `xmake f -p iphoneos -a arm64 && xmake`.

### Calling iOS native methods directly from Python via Frida and RPC
Author: 梦野间 (translation). Frida NativeFunction in three steps — find the address, build the function object, call:

```js
new NativeFunction(Module.findExportByName('AudioToolbox','AudioServicesPlaySystemSound'),'void',['int'])(1007)
// 分步: address → new NativeFunction(地址,'返回类型',['参数类型数组']) → 调用
```
No need to reverse the signature — look it up in Apple's headers (`void AudioServicesPlaySystemSound(SystemSoundID id)` → `'void',['int']`). System sound IDs: 1007 SMS/1000 mail/1100 lock/1108 camera shutter; audio lives at `/System/Library/Audio/UISounds/`. Attach to any app to call system functions; to call an app's own, you must attach to that app.

**RPC-ification — treat the app as a local Python library**:

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
Core value: when the app already implements encrypt()/decrypt(), don't dig out keys and re-implement — RPC straight into the app's functions; even keys in the Secure Enclave don't matter.

### Discovering the iOS Instruments server
Author: daemond (translation). Beyond debugserver, iOS devices also run the **Instruments service** (DTServiceHub/DVTInstrumentsFoundation): process lists, app lists, launching/killing processes all go through it. Service discovery: mounting DeveloperDiskImage.dmg shows three plists (debugserver / instruments.remoteserver / instruments.deviceservice); the Mac side starts it via MobileDevice.framework:

```c
AMDeviceSecureStartService(device_handle, CFSTR("com.apple.debugserver"), &srv_handle);
AMDServiceConnectionReceive(srv_handle, buf, sizeof(buf), &nrecv);
```
**The DTXMessage mechanism**: the Instruments front/back-end protocol = serialized NSInvocation transported across the device. Flow: Xcode sends `_notifyOfPublishedCapabilities:` → `_requestChannelWithCode:identifier:` (e.g. `com.apple.instruments.server.services.deviceinfo`) → sends the concrete selector on that channel (e.g. `runningProcesses`); the channel identifier decides the receiver. Key structures (essential for writing protocol interactions):

```c
struct DTXMessageHeader { uint32 magic, cb; uint16 fragmentId, fragmentCount;
                          uint32 length, identifier, conversationIndex, channelCode, expectsReply; };
struct DTXMessagePayloadHeader { uint32 flags, auxiliaryLength; uint64 totalLength; };
```

Tools: the IDA plugin dtxmsg (microcode detects serialization moments, dumping and deserializing every message into plaintext) + the standalone client dtxmsg_client (no Apple code dependency). Sensitive methods:

```
-[DTDeviceInfoService runningProcesses]
-[DTApplicationListingService installedApplicationsMatching:registerUpdateToken:]
-[DTProcessControlService launchSuspendedProcessWithDevicePath:bundleIdentifier:environment:arguments:]
-[DTProcessControlService killPid:]
```
Methodology: for private protocols, **reverse the official client first** (message construction is visible in the Xcode IDE binary) — faster than grinding the server-side serialization; static understanding + breakpoint-captured live samples combine for the highest success rate.

## 5. Game and App Field Work

### A brief talk on localizing iOS games
Author: obaby. Two unconventional routes (the generic five-step flow is in ios-offense-defense.md §7; these are incremental techniques).

**Route 1: cross-platform "borrowing the corpse to revive the soul"** — for a cross-platform game sharing one codebase, directly swap the iOS resources with the already-localized Windows ones (Bully using the 3dm localized edition): replace xml, font, english (watch for menu crashes), menu, repackage with `zip -0 -qr .../Bully2.zip .`.

**Route 2: Caption Hook, dynamic localization** — no resource changes; hook the rendering function and do original→translated dictionary replacement at runtime (suits self-developed engines). The engine's text-to-texture outlet `id -[HpLib_Graphics makeTextImage:]`:

```objc
CHDeclareClass(HpLib_Graphics);
CHOptimizedMethod(1, self, id, HpLib_Graphics, makeTextImage, NSString *, arg1) {
    NSString *ch_string = ch_dic[arg1];  if ([ch_string length]==0) ch_string = @"喵喵喵";
    return CHSuper(1, HpLib_Graphics, makeTextImage, ch_string);   // 无命中传原 arg1 走原逻辑
}
// 补:部分文本走 NSString 构造,一并 hook HpLib_GSystem strNSString /
// NSPlaceholderString 的 initWithBytes:length:encoding / initWithCString:encoding / initWithUTF8String
```

**Protecting the work** (against dylib theft): encrypt the dictionary (BABYStringEncoding/GTM_Encoder), decode inside the dylib then restore with NSPropertyListSerialization: `gtc2 = [[BABYStringEncoding alloc] initWithString:@"aCDEfGHijKlMnopQRsUvWXz012345689"]; [gtc2 decode:fileString error:nil]`. Command line: `GTM_Encoder -encodeFile <key> <input plist> <output enc>` (-decodeFile reverses).

### Capturing and modifying an iOS game
Author: Invert. A single-player + online hybrid game (Arcaea-like) from value patching all the way to a private server.

**IDA preprocessing**: with Shift-F7 set every segment named const/string/data to read-only so IDA recognizes strings correctly; short strings (like `fr_v`) may go unrecognized — binary search: convert to hex then Hex View's Alt-B binary search. **Local value patching**: fragments live in `Preferences/moe.low.arc.plist` under `fr_v`, and `fr_k` is the hash check — **no need to reverse the check algorithm**: XREF locates the reading function, confirm the return value is assigned straight into a struct with no second check, and rewrite the function head to return 999999999. Opcode generation: pick the armv8-a target on Compiler Explorer, copy the hex above each assembly line (little-endian DWORDs need a swap when written to file); in IDA's Hex View press F2 to overwrite hex directly, press P in the assembly view to rebuild the function so F5 works; `Edit → Patch program → Apply patches to input file` writes back (must be in the assembly or Hex view).

**Resource hash-check bypass**: the songlist/packlist/unlocks checks = `std::string::compare` against hardcoded hash strings, with `CBNZ` right after compare (jump if unequal) — **turning all CBNZ into NOP (`1F 20 03 D5`) bypasses it**; no need to study the hash algorithm. Deleting the `remote_dl` field from songlist + dropping local ogg/aff turns cloud songs local; editing unlocks unlocks all tracks.

**HTTPS capture, three layers**:

1. Cert pinning: strings confirm TrustKit → hook/patch `[TSKPinningValidator evaluateTrust:forHostname:]` to return true directly (`mov w0,#1; ret`).
2. **mTLS mutual auth**: Burp in the middle blocks the client certificate upload. Locate: IDA search `NSURLAuthenticationMethodClientCertificate` → `getClientIdentity` → read `self->sslCert` (PKCS12 binary) and `self->sslCertPassword`.
3. Dynamic extraction with LLDB: Xcode `Debug → Attach to Process by PID or Name`; `target modules list` gives base + function offset = breakpoint address; break where sslCert is read, `po $x8` dumps the p12, same for the password. The no-capture-needed alternative after patching: a Go forwarding proxy embedding the p12:

```go
//go:embed v4.0.255_key.p12
var key []byte; var password = "xxx"
clientKey, clientCert, _ := pkcs12.Decode(key, password)
http.DefaultClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{
    Certificates: []tls.Certificate{{Certificate: [][]byte{clientCert.Raw}, PrivateKey: clientKey}}}}
// handler 里把请求 URL 改写为真实 API host 转发,响应原样回写
```

On the Burp side, a Python plugin redirects the host locally: in processHttpMessage, when `getHost()=="arcapi-v2.lowiro.com"`, call `messageInfo.setHttpService(helpers.buildHttpService("127.0.0.1", 5151, "http"))`.

**Encrypted API endpoint rewriting (a generic CFB technique)**: the endpoint prefix `https://arcapi-v2.lowiro.com/join/21/` is CFB-mode encrypted (48 ciphertext bytes = 3 blocks). Under CFB, `C1 = P1 ⊕ XK1`; to change the plaintext, just `C1' = P1' ⊕ P1 ⊕ C1`; changing the current block affects the next block's XOR key → break before the decryption do-while, read registers in LLDB to grab the current block's C and XK (e.g. x10=C1, x9=XK1), `memory write $x10 0x11 0x22...` block by block, and after the do-while break with `x/16b $x11-16` to verify the plaintext; after 3 blocks, write the new ciphertext back to the matching data location in IDA and the private-server endpoint takes effect.

### Analyzing a certain car-owner app, iOS edition
Author: 那年没下雪. The app's mutual SSL couldn't be captured, so pivot to iOS-side static + dynamic analysis of the request headers `X-pa-Sign` and `Spartaid` (3.58.1; generic for the new-version encryption).

**Deploying debugserver by hand** (when no ready-made environment exists):

```bash
# DeveloperDiskImage.dmg 在 Xcode 的 DeviceSupport/<版本>/ 下,挂载取 usr/bin/debugserver;
# 同目录造 entitlement.xml:debugapplications/get-task-allow/task_for_pid-allow/run-unsigned-code 全 true
codesign -s - --entitlements entitlement.xml -f debugserver
scp -r debugserver root@localhost -p xxxx:/usr/bin       # 经 iproxy 转发
# 手机: debugserver 127.0.0.1:1998 -a /var/mobile/进程
# Mac:  lldb -> process connect connect://localhost:1998
```

**Reversing X-PA-Sign**: IDA search the string `X-PA-SIGN` to its xref, locate the method adding the header → break at the signing function sub_1014DACA4, dump registers in lldb and match captured samples one by one:

| Register | Meaning |
|---|---|
| x0 | HTTP method |
| x1 | request path |
| x2 | request parameters |
| x3 | body base64 |
| x4 | timestamp |
| x5 | platform |
| x6 | platform-specific string |
| x7 | the constant 1 |

Conclusion: the parameters are concatenated in order (GET concatenated directly; POST appends body base64 after the path) then SHA256. Cross-verified against the Android build (when the Android so is hard to chew, switching to the iOS side is a shortcut).

**Reversing Spartaid**: locate the three Lion_meta methods (the first two collect device info, the third encrypts). **Don't read the algorithm closely — just break CCCrypt and feed in/return values**: AES ECB PKCS7 with a hardcoded fixed key (e.g. `OkqDu3nfoVGNIyQA`). Pitfall: iOS encoding results differ from Java/Python; align carefully when reproducing.

### Who opened my "window": iOS app API security analysis
Author: starbuck (Chaitin Tech, 张一峰). The URLScheme + JSBridge attack-surface methodology (generic for white-box audits/pentests).

**The causal chain**: info.plist registers a custom URLScheme → any app/webpage can invoke it (a js auto-click in Safari triggers it; the first time needs user confirmation but malicious redirects are indistinguishable) → the callback parses the scheme parameters (attacker-controlled) → the callback can load arbitrary URLs and the WebView registered a JSBridge → any page context can call JSBridge interfaces.

- **Case 1, remote token theft**: the scheme parameter `url=https://evil.com` passes two weak checks (a url key exists + starts with https) and gets loaded directly by BaseWebViewController; the JSBridge `registerLoginHandler` exposes arbitrary method invocation on the Module class → getUserInfo fetches phone/UID/companyID/token for exfiltration (long-lived mobile tokens = account takeover).
- **Case 2, arbitrary file upload**: `shouldStartLoadWithRequest` intercepts custom schemes → handleMessage parses action/args (both controllable) → a permission-check flaw → action is prefixed `jsapi_` and suffixed `completion` into `performSelector` = **arbitrary method invocation**; pick uploadImages(url=your server, path=a sandbox sqlite path) → arbitrary sandbox file upload. performSelector dynamic invocation is the biggest share in such callbacks (some apps dispatch by numeric prefix — sending a string of numbers chains calls).
- **Case 3, payment logic**: the plugin mechanism allows calling walletPaySDK by plugin ID, parameters carrying OrderID — create an order and induce others to pay; payment SDKs must explicitly show goods and amounts.
- **Trigger-surface expansion**: QR scanning (one scheme name, many entries), background triggers, WKWebView JS injection (sandboxed/remote JS injected into all pages = a resident JSBridge; combined with file writes this yields XSS).

**Audit/hunting checklist**: ① read the info.plist URLScheme definitions → ② follow the callback functions, focusing on "loads arbitrary URLs" → ③ find other arbitrary-URL load paths like QR codes → ④ enumerate the JSBridge-callable interfaces for privilege escalation/sensitive operations. Developer advice: minimize schemes; implement sensitive operations natively; strictly filter callers on externally invocable interfaces.
