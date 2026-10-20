# iOS Files and Signing in Practice (Mach-O/dyld full chain / signing and re-signing / dumping hands-on / jailbreak chains and bootchain / fairplayd deobfuscation)

> Knowledge base 04-iOS security · file 3. For the basic overview (segment layout/CryptID/tool matrix/jailbreak generations) see [ios-re-fundamentals.md](ios-re-fundamentals.md); this file only adds the deep dives: kernel- and dyld-loading detail at the source level, the signature-validation chain and rules bypasses, the complete dumping commands and pitfalls, jailbreak rootfs remounting and the APFS snapshot bypass with source, the iBoot recursive stack-overflow exploit end to end, and fairplayd block-dispatch deobfuscation.

## 1. Mach-O and dyld Loading

### First notes on Mach-O
Author: BinGzL. The mach_header_64 fields and the filetype quick table are in [ios-re-fundamentals.md](ios-re-fundamentals.md); what stays here is parser-essential.

**Load Command type → struct mapping** (pick structs by this when writing a parser; LC_SEGMENT/64 is special, carrying nsects section headers):

```
segment_command(_64)     LC_SEGMENT(_64);thread_command  LC_THREAD / LC_UNIXTHREAD
dylib_command            LC_ID_DYLIB / LC_LOAD_{,WEAK_}DYLIB / LC_REEXPORT_DYLIB
dylinker_command         LC_ID_DYLINKER / LC_LOAD_DYLINKER / LC_DYLD_ENVIRONMENT
symtab/dysymtab/uuid/rpath/entry_point/source_version_command  同名 LC_*
linkedit_data_command    LC_CODE_SIGNATURE / LC_SEGMENT_SPLIT_INFO / LC_FUNCTION_STARTS / LC_DATA_IN_CODE 等
encryption_info_command(_64) / version_min_command / dyld_info_command  同名 LC_*
```

section_64 key fields: `sectname/segname[16]`, `addr/size` (virtual), `offset` (file offset), `align` (power of two), `reloff/nreloc`. Pitfall: different cmds map to different structs; walk by `load_command.cmd+cmdsize` stepping.

### Mach-O format analysis
Author: dirge. Quick check `otool -h git` (magic/cputype/filetype/ncmds/sizeofcmds/flags all on one screen; 0xfeedfacf = 64-bit little-endian, ARM64 cputype=0x0100000C). The kernel's `parse_machfile` (bsd/kern/mach_loader.c) handles only the following LCs and ignores the rest outright — when reversing load behavior, watch only these:

| Command | Function | Notes |
|---|---|---|
| LC_SEGMENT / LC_SEGMENT_64 | load_segment | segment mapping |
| LC_UNIXTHREAD / LC_MAIN | load_unixthread / load_main | thread/entry (LC_MAIN only at depth==1) |
| LC_LOAD_DYLINKER | (pass 3 records dlp) | load_dylinker afterwards |
| LC_UUID | load_uuid | 128-bit ID |
| LC_CODE_SIGNATURE | load_code_signature | signature validation |
| LC_ENCRYPTION_INFO(_64) | set_code_unprotect | pass 3; FairPlay decryption |

Key FairPlay behavior (pass 3): `set_code_unprotect` **only sets the decrypter; the kernel does not actually decrypt**; on failure returning LOAD_DECRYPTFAIL it sets `P_LTERM_DECRYPTFAIL` and directly `psignal(p, SIGKILL)` — explaining why, before dumping, static tools see ciphertext and the process gets killed instantly when the key is missing. The LC walk rejects with LOAD_BADMACHO as soon as `cmdsize < sizeof(load_command)` or an offset runs past the end.

### Mach-O from the ground up
Author: evilpan. Segment mapping: file `begin+fileoff` for `filesize` bytes → process `vmaddr` for `vmsize`; **vmsize ≥ filesize, the excess zero-filled** (__bss/__common eat the difference). cmdsize must be word-aligned (8B on 64-bit), trailing padding must be 0. Segment quick table (lldb `image dump sections main`; sections via `otool -V main -s __TEXT __stubs`, the signature via `jtool2 --sig -v main` / `codesign -d`):

```
__PAGEZERO  [0x0-0x100000000) ---  占低地址防 NULL 解引用
__TEXT      r-x  fileoff=0  文件头(Header+LC)一并映射;__text/__stubs/__stub_helper/__cstring/__unwind_info
__DATA      rw-  __nl_symbol_ptr/__got/__la_symbol_ptr/__common(zero-fill)
__LINKEDIT  r--  fileoff+filesize==文件大小;内容随 cmd:符号表/函数起始表(uleb128)/dyld info/签名 blob
```

The dyld_info_command sextet: rebase/bind/weak_bind/lazy_bind/export each with off+size; lazy-bind semantics example: `_printf(libSystem.B.dylib) lazily bound into the __DATA,__la_symbol_ptr slot`. Kernel loading is 4-pass: 0 boundary page alignment → 1 thread state/uuid/signature → 2 segments actually mapped → 3 dyld/encryption/entry point. load_segment essentials: 32-bit is widened to 64 first; mapping address = slide+vmaddr; file/vm all 4K-page-aligned; address 0 allowed only for __PAGEZERO; **the kernel parses no sections, only down to segment granularity** (sections are a dyld/linker concept).

load_dylinker recursively calls parse_machfile (depth-limited); after dyld returns to user mode: `__dyld_start` (fixed 0x1000) → rebaseDyld → mach_init → __guard_setup → `dyld::_main`: setContext → env → mapSharedCache → DYLD_INSERT_LIBRARIES → link the main executable → initializeMainExecutable (runs __mod_init_funcs) → the LC_MAIN entry. ImageLoader::link order: recursiveLoadLibraries → recursiveUpdateDepth (depended-on libraries first) → recursiveRebase → recursiveBind → weakBind (non-main executables only) → recursiveGetDOFSections → recursiveApplyInterposing (only INSERTED libraries may interpose). dyld_cache: the iOS path `/System/Library/Caches/com.apple.dyld/dyld_shared_cache_$arch`; whether it is already mapped goes through syscall 294 `shared_region_check_np` (295 = map_np); the header holds each of mapping/images' Offset/Count, codeSignature, slideInfo, localSymbols, uuid; each mapping_info{address,size,fileOffset,maxProt,initProt} is mmap'd one by one; dumping system-library symbols starts from localSymbols+slideInfo.

### dyld mach-o file loading analysis
Author: dirge. User-mode load chain: `_main → instantiateFromLoadedImage → isCompatibleMachO → ImageLoaderMachO::instantiateMainExecutable → sniffLoadCommands → instantiateStart → addImage (hung into sAllImages recording the mapping range)`. isCompatibleMachO's three-level verdict: magic matches → cputype matches → cpusubtype is inside the `findCPUSubtypeList` preference list (or fully identical to the host; x86/x86_64 ignores subtype).

**All of sniffLoadCommands's malformation checks** (the rule set for forging/modifying Mach-O or writing parsers):

- `cmdsize < 8` or nextCmd running past endCmds → malformed; see LC_DYLD_INFO(_ONLY) → compressed; Classic without it throws "missing LC_DYLD_INFO load command" outright;
- `filesize > vmsize` → malformed (macOS allows the vmsize==0 exception, iOS does not);
- codeSigningEnforced: vm/file ranges must not wrap, inaccessible segments must have filesize 0, **load commands must land entirely inside some initprot==R+X segment starting at fileoff 0**, no two segments may overlap, **__LINKEDIT must be the last segment**;
- a section's `offset+size` must not exceed its segment's bounds; segments > 255, dependency libraries > 4095 → malformed; only one LC_CODE_SIGNATURE and one LC_ENCRYPTION_INFO(_64) allowed per image.

addImage's extra actions: merging consecutive segments into mapped ranges; printing the loaded log when `DYLD_PRINT_LIBRARIES` is set.

### A simple analysis of Mach-O dynamic linking
Author: dirge. The lazy-bind full flow (printf as the example, single-stepped in lldb):

```
main+34:  callq 0x100000f56            ; __stubs 里 printf 的 stub
0x100000f56: jmpq *0xb4(%rip)          ; 跳 __DATA,__la_symbol_ptr 槽位(初始值 0x100000f6c = __stub_helper 绑定桩)
0x100000f6c: pushq $0x0                ; 压入 lazy-bind ordinal
0x100000f71: jmp 0x100000f5c           ; stub_helper 头 → dyld_stub_binder
binder: 按 ordinal 查 lazy_bind 信息解析真实 printf 地址,回写槽位后直跳;第二次调用 jmpq 直达 printf
```

Verification: break before and after the call and run `x 0x100001010` each time — before: `6c 0f 00 00 01 00 00 00`, after: `5c 81 b1 96 ff 7f 00 00`. Compared with Linux: __stubs ≈ PLT, __la_symbol_ptr ≈ GOT, stub_helper+binder ≈ ld.so's lazy resolver; GOT/lazy_symbol_ptr is the root of fishhook's efficacy. Symbol-table side: LC_SYMTAB gives symoff/nsyms/stroff/strsize; LC_DYSYMTAB partitions the indirect/local/defined ranges.

## 2. The Signing System

### iOS signing notes (I)
Author: obaby. Transfer-authorization distribution: the PC side builds an authorization file via iTunes private APIs; **not validated at install, only at run time** (without authorization an account/password dialog pops). The delete-authorization experiment requires deleting the six files `IC-Info.sidr/.sids/.sidt/.sisb/.sisv/.sidb` under `/private/var/mobile/Library/FairPlay/iTunes_Control/iTunes/`. Store IPA structure: `Payload/xxx.app/SC_Info/` (authorization) + `iTunesMetadata.plist` (purchasing AppleID/version; **participates in neither install validation nor signing; delete it and it still installs**; newer versions carry an identical SC_Info inside every Frameworks subdirectory too).

**The two-layer signature validation chain**: resource hashes live in `_CodeSignature/CodeResources` (files key: filename → sha1 (newer versions add sha256) digest **base64**); CodeResources's own hash is recorded inside the executable's signature (the CMS blob) — modify a resource and update the plist hash and it still won't pass. Computing script:

```python
import hashlib, base64
print(base64.encodebytes(hashlib.sha1(open(filepath,'rb').read()).digest()))  # 与 plist 中 <data> 一致
```

To see the CodeResources hash inside the executable's signature: `jtool --sig`. Exception: SC_Info is omitted by rules (see notes II); swapping SC_Info between the same app purchased under different accounts installs and runs fine.

### iOS signing notes (II)
Author: obaby. CodeResources's rules key (files exempt from validation):

```
^SC_Info/.*\.sinf$ / .supp$   omit  weight 10000(新版含 PlugIns/*.appex/SC_Info 的 sinf|supp|supf|supx)
Info.plist / PkgInfo / ResourceRules.plist  omit;.*\.lproj/ optional weight 1000(本地化可缺)
^(.*/)?\.DS_Store$            omit  weight 2000;^embedded\.provisionprofile$  weight 20(只记嵌套不 omit)
```

**The resource-rules bypass (modify a signed IPA without re-signing)**: since macOS 10.9 codesign officially deprecated `--resource-rules` (TN2206), but the old codesign still works and the IPA it signs installs fine. Exclude-all configuration: under the plist's rules dict put `<key>.*</key><false/>`; after running `codesign -f -s <cert> --resource-rules=<rules.plist> xxx.app`, CodeResources's files/files2 are completely empty — **from then on, change any resource file and re-zip to install; no further signing needed**. Detection tell: `codesign -dvvv` showing a custom omission rule was used.

embedded.mobileprovision (mp), three essentials: ① entitlements (not required to fully match the ones inside the binary; too far apart and it won't install/crashes); ② the device list: personal/development certs = `ProvisionedDevices` (a UDID not on it won't install), enterprise certs = `ProvisionsAllDevices` (the root cause of enterprise-signing sprawl); ③ CreationDate+TTL validity, bundleid (auto-prefixed with the TeamID), UUID, certificates. Viewing: `security cms -D -i Payload/xxx.app/embedded.mobileprovision` decodes the plaintext plist; `ldid -e Payload/xxx.app/xxx` shows the binary's actual entitlements.

The mp and the IPA's original bundleid **need not match** (wildcards are limited: push etc. unusable). For push: a Distribution mp + a bundleid with push enabled + a push certificate. **mp expiry renewal: rebuild the mp under the same account and bundleid and swap it into the IPA; no re-signing needed** (provided it was originally signed with resource-rules). `codesign --entitlements path` injects entitlements; **never use ldid to sign an IPA** — reserve it for writing entitlements onto single binaries in jailbreak environments (debugserver).

## 3. Re-signing and Installation

### Capturing the protocol of Cydia Impactor installing an unsigned IPA
Author: 猪会被杀掉. Impactor speaks its own signed communication over curl, which fiddler-class MITM cannot catch; three in-process hook approaches to capture the protocol (all writing files), used to reconstruct the complete interaction with Apple's signing servers (free-account certificate requests / the unsigned-IPA install protocol surface).

① Hook curl's `Curl_ossl_send/Curl_ossl_recv` (naked functions preserving registers, backfilling eax; recv is isomorphic):

```c
__declspec(naked) void new_Curl_ossl_send(void* conn, int sockindex, const void *mem, size_t len){
    _asm pop esp_reg / _asm call old_Curl_ossl_send / _asm pushad / _asm mov len111, eax
    Log((const char*)mem, len);       // recv 同构:Log((const char*)buf, len111)
    // # (省略:popad / mov eax,len111 / push esp_reg / retn —— 恢复现场并回填返回值)
}
```

② Hook iTunes/CFNetwork (the important protocols go HSTS, so MITM fails here too): `CFHTTPMessageCreateRequest` captures URL + method, `CFHTTPMessageSetBody` captures the body — `CFStringGetCString(CFURLGetString(url),...)`, `CFDataGetBytePtr/CFDataGetLength` to disk. ③ On the Win32 side: hook `WinHttpSendRequest/HttpSendRequest` to intercept headers + the optional buffer; then hook `WinHttpOpenRequest` and for the returned handle call `WinHttpSetOption(WINHTTP_OPTION_PROXY / WINHTTP_OPTION_SECURE_PROTOCOLS)` to force traffic through a local proxy into a MITM position.

## 4. Dumping in Practice

### Dumping an iOS app with one command
Author: AloneMonkey. Tool evolution: dumpdecrypted (dumps only the main binary) → the conradev version (the `_dyld_register_func_for_add_image` callback dumps module by module, covering Frameworks) → the MonkeyDev tweak without copying → Clutch (posix_spawnp produces an IPA directly but often errors) → **frida-ios-dump** (frida injects JS to dump memory + python auto-transfers and packs, one command).

```
sudo pip install frida --upgrade --ignore-installed six   # 修 six 卸载报错
iproxy 2222 22                       # USB 映射 SSH;旧版脚本基于 python2
./dump.py 微信                       # 按显示名砸;-l 列 PID/Name/Identifier;-b com.tencent.xin 按 bundle id 砸
```

The log shows module-by-module dumping (the main binary + each Frameworks library decrypted and transferred); on completion a decrypted IPA appears in the current directory. Pitfalls: apps with duplicate names must go through -b; the jailbroken phone needs frida-server.

### Dumping with ios-dumpdecrypted
Author: Gnoliew. Direct command (phone SSH or Terminal):

```
DYLD_INSERT_LIBRARIES=dumpdecrypted.dylib /var/containers/Bundle/Application/<UUID>/xxx.app/xxx
```

The product `xxx.decrypted` lands in the **current working directory**; strip the suffix, `chmod -R 777`, then `otool -l <binary> | grep crypt` showing 0 means success. **The Killed: 9 pitfall** = the dylib is unsigned (or its signature untrusted); re-sign: `codesign --force --verify --verbose --sign "iPhone Developer: xxx" dumpdecrypted.dylib` (list certs first with `security find-identity -v -p codesigning`).

### No jailbreak, auto-integrated, only needing a dumped app
Author: AloneMonkey. MonkeyDev's MonkeyApp template: Xcode New Project → MonkeyApp → drag the dumped ipa/app into the TargetApp directory (keep the placeholder file) → build straight to a non-jailbroken phone. Ships with `MonkeyAppDylib` (OC runtime hook + fishhook), `AntiAntiDebug`, auto-integrated Reveal + Cycript (default port 6666); default library locations `/opt/MonkeyDev/frameworks` (Reveal), `/opt/MonkeyDev/library` (Cycript). The CaptainHook template (copy, rename the class, use):

```objc
CHDeclareClass(CustomViewController)
CHOptimizedMethod(0, self, NSString*, CustomViewController, getMyName){
    NSString* password = CHIvar(self, _password, __strong NSString*); // 读私有 ivar
    return @"AloneMonkey";                                            // 改返回值
}
CHConstructor{ CHLoadLateClass(CustomViewController); CHClassHook(0, CustomViewController, getMyName); }
```

## 5. Jailbreak Chains and the bootchain

### The main jailbreak steps demystified
Author: daemond (translation). **Payload delivery**: before iOS 9.0 there was no free-account self-signing; delivery relied on enterprise certificates + private deployment; Pangu 7.1-7.1.2 embedded the whole to-be-installed IPA (a gzip tar) inside a custom section `__TEXT.__objc_cons2` of the PC-side binary (≈2.49MB; objc_cons1~11 held the untether/plist/libraries):

```
jtool -e __TEXT.__objc_cons2 pangu   # 抽 section;file 验证 gzip;tar tvf 列出 Payload 内容
```

Certificate-expiry countermeasure: roll the device date back (for that version, to 2014-06-02). Device communication goes through iTunes AppleMobileDevice private APIs (already replicated by libimobiledevice). KPP generations: iOS 9 KPP (EL3 software) → iOS 10 KTRR (hardware) → xerub's KPPLess enabled Yalu on the iPhone 7.

**Sandbox escape (QiLin ShaiHulud)**: kernel R/W swaps this process's ucred for a kernel ucred → gains the full execve/fork/posix_spawn capability set; **the original ucred must be restored before exit**, otherwise the kernel credential lock panics.

**RootFS remounting (QiLin remountRootFS, directly copy-pasteable)**:

```c
rootVnodeAddr = findKernelSymbol("_rootvnode");
// readKernelMemory 读 vnode → rootvnode->v_mount → mount 结构(偏移 0x70 = flags,版本相关)
mountFlags = (*(uint32_t*)(v_mount + 0x70)) & ~(MNT_ROOTFS | MNT_RDONLY);  // 清两标志,绕 mount 的 MACF 钩子
writeKernelMemory(v_mount + 0x70, &mountFlags, 4);
mount("apfs", "/", MNT_UPDATE, "/dev/disk0s1s1");   // 必须重调 mount(2)
mountFlags |= MNT_ROOTFS;  writeKernelMemory(...);  // 恢复标志
open("/test.txt", O_TRUNC|O_CREAT);                 // 写测验证,成功后 unlink
```

**The iOS 11.3 APFS snapshot bypass**: every reboot rolls back to the read-only snapshot and all tweaks are lost. Snapshot name = `com.apple.os.update-<boot-manifest-hash uppercase HEX>`; the hash comes from the `boot-manifest-hash` property of `IODeviceTree:/chosen` (by hand `ioreg -p IODeviceTree -l | grep boot-manifest-hash`; in code = Electra's apfs_util.c copyBootHash: after GetProperty, byte by byte `%02X`). Bypass trunk: iOS≤11.2.6 takes the old route; on 11.3+ temporarily swap the ucred → mount /dev/disk0s1s1 RW at a temp directory → `do_rename(tempdir, snapshot-name, "orig-fs")` **renaming the snapshot** → unmount cleanup → restore the ucred → reboot (Electra 11.3.1 forced a reboot on first run). When there is no snapshot to roll back to, iOS boots as usual and jailbreak files persist. The dev vnode additionally needs `wk32(specInfo + offsetof_si_flags, 0)` to clear v_specflags. Terminology: bin pack/base binaries = the regular unix tools; bootstrap = jailbreakd/Cydia and the rest. Kernel-bug selection: the VFS empty_list works on free accounts but is unstable; MPTCP is stable but the multipath entitlement needs a paid developer account.

### A recursive stack-overflow bug in the iOS 7 bootchain
Author: daemond (translation). The bootchain (the later the link, the more complex and the higher the bug odds): the NAND chain `SecureROM → LLB → iBoot → OS`; the DFU chain `SecureROM → iBSS → iBEC → Restore`. iBoot is non-relocatable, loaded at a fixed `memory_base+memory_size-1MB` (0x5FF00000/0x9FF00000/0xBFF00000) — **no IASLR, the whole memory layout is predictable**; dump with kloader/kdumper. Memory grows top-down: CODE → DATA (BTree headers/allocator metadata) → HEAP (task stacks fixed at 0x1C00). The scheduler is cooperative and does not check while a task runs — **after recursion, without a task_yield the stack-integrity check is moot**.

**Finding recursion cycles: run Tarjan SCC over the call graph** (xerub idastuff/tarjan.py). Direct self-recursion is rare and depth-limited (ResolvePathToCatalogEntry capped at 64); the goal is a small F()→G()→F() cycle:

```
ReadExtent() → memalign(64)
ReadExtentsEntry()/ReadBTreeEntry() → memalign(blockSize) → ReadExtent()
```

HFS+ essentials: directory files are B-trees; each fork records 8 extents, the overflow going to the extents-overflow B-tree; iBoot reads both extent kinds with the same ReadExtent() — **when reading an overflow extent, exceeding the extent density again → infinite recursion**, each frame 208 bytes, the stack burning down from HEAP through DATA.

Methodology: first write a **user-mode emulator iloader** (dummy allocations aligned to the main task stack, `SP = BASE + 0x581d4`), do all trial-and-error in the emulator before touching hardware. Constraints: avoid `task::irq_disable_count` overwrites >999 (panic); the target is the allocator metadata (malloc runs repeatedly on the recursive path); two SP fine-tuning moves — nvram `${boot-path}`/`${boot-ramdisk}` can be set from inside iOS and survive reboot, or use a long path to make ResolvePathToCatalogEntry descend (≤64 levels).

Trigger construction (HFS+ volume header/BTree header fields; iBoot checks none of most of the BTree header space, **so the payload lives in the header**):

```
catalogFile.logicalSize = 0xFFFFFE00;   extentsFile.logicalSize = 0x3FFC000;
Catalog BTree:  nodeSize=512   totalNodes=0x7FFFFF  rootNode=0x7FFE(初触发)
Extents BTree:  nodeSize=16384 totalNodes=0xFFF     rootNode=0x500(必须大,LSB=0)
进阶:复制根块造高树,PUT_DWORD_BE(block, 116, 0x10000);最佳路径 ${boot-ramdisk}="/a/b/.../m/disk.dmg"
```

**Exploitation primitive: drive memalign's free_list_remove for an arbitrary write** (the allocator's doubly-linked list; the R0 block pointer is controllable, pointing at a fake block in the BTree header):

```
free_list_remove:
    LDRD.W R10, R11, [R0,#0x40]   ; 必须 DWORD 对齐
    STR.W  R10, [R11]             ; 任意写: [R11] = R10
```

Choose the write target as the LR saved in memalign's stack frame (for PC control). Alignment pitfall: LDRD needs DWORD alignment while the pointer sits at DWORD+2 → **two iterations** (the first doesn't fit and splits to an aligned address, the second is an exact fit, R4==R0, clean return), then arrange the fake-block values to skip memalign's remaining logic and ret straight into the BTree-header shellcode (the whole mapping is executable). Cleanup (nettoyeur): the heap is destroyed, so the shellcode first disables the interpreter, uses iBoot's own lzss routine to decompress a cleanup stub that runs silently, then **jumps back to iBoot's start point to reboot** — BSS/heap re-initialized, yielding a recovery console with safety checks disabled and the GID AES key available. The on-device attack sequence (preconditions: already jailbroken + exact iBoot version match):

```
nvram boot-ramdisk="/a/b/.../m/disk.dmg"
dd if=/dev/rdisk0s1s1 of=backup bs=512k count=1    # 备份
dd of=/dev/rdisk0s1s1 if=ramdiskF.dmg bs=512k count=1
重启 → logo 闪(exploit 重启 iBoot)→ irecovery -s 连恢复控制台
```

Application: booting any unsigned kernel (third partition /dev/rdisk0s1s3 + `nvram boot-partition=2` + boot-ramdisk pointing at the trigger disk). Mitigation assessment: canary/scheduler checks/W^X all struggle (the whole heap is overflowed, writes are precise, ROP is available); **effective defenses: a guard page between DATA/HEAP, a hard recursion-depth check (the iOS 8 fix), heap randomization/IASLR**.

## 6. Kernel Debugging

### An iOS kernel-debugging tutorial
Author: 梦野间 (translation). The four-piece kit: a jailbroken device whose boot args can be set (RedSn0w: Extras → Even More → Preferences → Boot Args, enter `debug=0x8f -v wdt=0`), a serial debug cable, Apple's GDB (Xcode-compatible), and serialKDPproxy (KDP over a UDP-proxied serial line). debug=0x8f debug mode, -v verbose, wdt=0 disables the watchdog (so it can pause at any moment); after setting, boot hangs waiting for the debugger.

```
./SerialKDPProxy /dev/tty.usbserial-AH00NR2W   # 串口→KDP;启动日志打出 kernel slide
gdb -arch armv7
(gdb) target remote-kdp
(gdb) attach localhost
```

Commands: `p (int)addr` to read / `set {int}addr=val` to write / `x/i addr` disassemble / `info registers` / `break *(addr)` (IDA function address + kernel slide); with a symbolized kernelcache you can break by function name. Routine: find the function in IDA (e.g. OSUnserializeXML) → break with the slide added → trigger → the whole stack/register scene in hand; one minute of debugging beats an hour of static work.

## 7. fairplayd Obfuscation (block-dispatch deobfuscation)

### Trying to undo fairplayd's obfuscation (block dispatch)
Author: lpcdma. Block dispatch ≈ open-source Hikari's IndirectBranch: "jump to a fixed offset" becomes "jump to a register value", with the register value computed by a short prologue at each block's entry. The goal of the solution: **statically compute each block's jump offset and recover the CFG**. Sample: ios11.3.1 fairplayd.H2. Three shapes:

1. **Mid-function blocks**: a few arithmetic ops (SUB/ADD/AND) at the entry that can be computed mentally → the next block's address; for orders-of-magnitude problems compute with **per-block unicorn emulation**, not by hand.
2. **With a this/r0/argument chain** (x19 depends on sub_100CB3AEC's return value): the long back-trace chain is a decoy — **the depended-on function is actually a pure computation function**, its int8_t argument only spans 0-0xff; enumerating the inputs yields `w0 is invariably 0xfffffff0` → x19 = 0x1001594e4 = the next function's address. Treat obfuscated functions as constant propagation.
3. **Depending on X29 (FP/stack base)**: W20←W9←X25←X0, X0 comes from `LDR W9,[X25,#8]`, and X25 chains back to `STUR W8,[X29,#var_80]`, the same stack slot — W9 is just the previously stored 5; **draw the data-flow diagram by hand** to see through the self-reference; the fixed magic numbers (0xe226/0x7218) are also a hint. Solving gives W20=5 → X9=0x100159564.

Workflow: first locate the function head and tail precisely (a prerequisite for figuring out jump relations); once the block graph is solved, getting F5 requires editing instructions to repair the jumps (automation is costly). Essence: treat the obfuscated computation chain as **constant folding + stack-slot alias analysis**, with unicorn as the fallback.
