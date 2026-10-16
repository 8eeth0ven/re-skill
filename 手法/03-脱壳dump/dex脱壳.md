# dex 脱壳 dump

> 覆盖:DexFile ByteBuffer 构造函数 dump、frida-dump DefineClass 法、加壳 app 用 enumerateClassLoadersSync 找 classLoader 的原理、mkdir/chmod 辅助函数、loadDex 主动加载 dex。

## 一、整体思路

脱壳本质是拦截「dex 被解密后、被 ART 拿去 defineClass」的瞬间,把内存里的 dex 字节落盘。三条常用路径:

| 路径 | 拦截点 | 适用 |
|------|--------|------|
| Java 层 | `dalvik.system.DexFile` 的 ByteBuffer 构造函数 |壳会走 InMemoryDexClassLoader / ByteBuffer 方式加载 dex |
| Native 层 | libart.so 的 `ClassLinker::DefineClass` 符号(frida-dump 原理) | 通用,只要类被加载就会触发 |
| classLoader 枚举 | `Java.enumerateClassLoadersSync()` | 不是直接 dump,而是找到壳的 classLoader 才能 hook 到解密后的类 |

## 二、DexFile ByteBuffer 构造函数 dump

什么时候用:目标壳用 `InMemoryDexClassLoader`(内部走 DexFile 的 ByteBuffer 构造函数)加载解密后的 dex,在这个构造函数里把每个 buffer 落盘。

```javascript
function hook_dexFile_init() {
    var DexFile = Java.use("dalvik.system.DexFile");
    DexFile.$init.overload('[Ljava.nio.ByteBuffer;', 'java.lang.ClassLoader', '[Ldalvik.system.DexPathList$Element;').implementation = function (buffers, loader, elements) {
        console.log("[+] DexFile constructor called");
        try {
            if (buffers != null) {
                for (var i = 0; i < buffers.length; i++) {
                    var buffer = buffers[i];
                    if (buffer != null) {
                        var array = buffer.array();
                        var dexPath = "/data/data/com.vnpay.bidv/files/dump_dex_com.vnpay.bidv/class_" + new Date().getTime() + "_" + i + ".dex";
                        var byteArray = Java.array('byte', array);
                        var file = new File(dexPath, "wb");
                        var arrayBuffer = new ArrayBuffer(byteArray.length);
                        for (let j = 0; j < byteArray.length; j++) {
                            arrayBuffer[j] = byteArray[j]
                        }
                        file.write(arrayBuffer)
                        file.flush();
                        file.close();
                        console.log("[+] Saved dex to: " + dexPath);
                    }
                }
            }
        } catch (e) {
        }
        return this.$init(buffers, loader, elements);
    };
}
```

注意:路径里的包名(`com.vnpay.bidv`)要换成目标 app 包名。

## 三、加壳 app 用 enumerateClassLoadersSync 找 classLoader 的原理

加壳之后的 hook 需要使用 classLoader,每一个加载的 dex 都对应有一个 classLoader,然后它们之间互相之间的函数调用,也需要使用到对方的 classLoader 才可以,没有办法直接使用,我们 hook 也需要使用到这些,因为这样子才能 hook 到这个 java 函数的具体地址,然后变成一个 native 函数再来进行 hook。

要点:
- 用 `classLoader.loadClass("目标类")` 探测哪个 loader 能加载到壳释放的业务类;
- 命中后 `Java.classFactory.loader = classLoader;` 把全局 factory 切过去,再 `Java.use` 才能找到。

完整示例代码(enumerateClassLoadersSync 探测 + 切换 loader + hook `ot2.b.getBdOz`)另见 `02-frida/java层/加密与自吐.md` 的「加壳的 hook」一节,此处不重复。

## 四、frida-dump:DefineClass 法(通用)

> **eBPF 方案见 [eBPF脱壳深挖.md](eBPF脱壳深挖.md)**(anti-frida 目标首选,零注入更隐蔽)。

原理:hook libart 里的 `ClassLinker::DefineClass`,第 5 个参数是 `const DexFile&`,按其内存布局读出 `begin_`(dex 起始地址)和 `size_`(dex 大小),发现新地址就落盘。不依赖壳的类型,只要类被加载就会经过这里。

辅助函数(全部用 NativeFunction 调 libc 实现,不依赖 Java 层,spawn 最早期也能用):

### 4.1 get_self_process_name:读 /proc/self/cmdline 拿包名

```javascript
function get_self_process_name() {
    var openPtr = Module.getExportByName('libc.so', 'open');
    var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);
    var readPtr = Module.getExportByName("libc.so", "read");
    var read = new NativeFunction(readPtr, "int", ["int", "pointer", "int"]);
    var closePtr = Module.getExportByName('libc.so', 'close');
    var close = new NativeFunction(closePtr, "int", ["int"]);
    var path = Memory.allocUtf8String("/proc/self/cmdline");
    var fd = open(path, 0);
    if (fd != -1) {
        var buffer = Memory.alloc(0x1000);
        var result;
        read(fd, buffer, 0x1000);
        close(fd);
        result = ptr(buffer).readCString();
        return result;
    }
    return "-1";
}
```

### 4.2 mkdir:不存在则创建目录(opendir 探测)

```javascript
function mkdir(path) {
    var mkdirPtr = Module.getExportByName('libc.so', 'mkdir');
    var mkdir = new NativeFunction(mkdirPtr, 'int', ['pointer', 'int']);
    var opendirPtr = Module.getExportByName('libc.so', 'opendir');
    var opendir = new NativeFunction(opendirPtr, 'pointer', ['pointer']);
    var closedirPtr = Module.getExportByName('libc.so', 'closedir');
    var closedir = new NativeFunction(closedirPtr, 'int', ['pointer']);
    var cPath = Memory.allocUtf8String(path);
    var dir = opendir(cPath);
    if (dir != 0) {
        closedir(dir);
        return 0;
    }
    mkdir(cPath, 755);
    chmod(path);
}
```

### 4.3 chmod:目录授权 755(方便后续拉取)

```javascript
function chmod(path) {
    var chmodPtr = Module.getExportByName('libc.so', 'chmod');
    var chmod = new NativeFunction(chmodPtr, 'int', ['pointer', 'int']);
    var cPath = Memory.allocUtf8String(path);
    chmod(cPath, 755);
}
```

### 4.4 dump_dex 主体

```javascript
function dump_dex() {
    var libart = Process.findModuleByName("libart.so");
    var addr_DefineClass = null;
    var symbols = libart.enumerateSymbols();
    for (var index = 0; index < symbols.length; index++) {
        var symbol = symbols[index];
        var symbol_name = symbol.name;
        //这个DefineClass的函数签名是Android9的
        //_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS9_8ClassDefE
        if (symbol_name.indexOf("ClassLinker") >= 0 &&
            symbol_name.indexOf("DefineClass") >= 0 &&
            symbol_name.indexOf("Thread") >= 0 &&
            symbol_name.indexOf("DexFile") >= 0) {
            console.log(symbol_name, symbol.address);
            addr_DefineClass = symbol.address;
        }
    }
    var dex_maps = {};
    var dex_count = 1;

    console.log("[DefineClass:]", addr_DefineClass);
    if (addr_DefineClass) {
        Interceptor.attach(addr_DefineClass, {
            onEnter: function(args) {
                var dex_file = args[5];
                //ptr(dex_file).add(Process.pointerSize) is "const uint8_t* const begin_;"
                //ptr(dex_file).add(Process.pointerSize + Process.pointerSize) is "const size_t size_;"
                var base = dex_file.add(Process.pointerSize).readPointer();
                var size = dex_file.add(Process.pointerSize + Process.pointerSize).readUInt();

                if (dex_maps[base] === undefined) {
                    dex_maps[base] = size;
                    var magic = base.readCString();
                    if (magic.indexOf("dex") === 0) {

                        var process_name = get_self_process_name();
                        if (process_name !== "-1") {
                            var dex_dir_path = "/data/data/" + process_name + "/files/dump_dex_" + process_name;
                            mkdir(dex_dir_path);
                            var dex_path = dex_dir_path + "/class" + (dex_count === 1 ? "" : dex_count) + ".dex";
                            console.log("[find dex]:", dex_path);
                            var fd = new File(dex_path, "wb");
                            if (fd) {
                                dex_count++;
                                var dex_buffer = ptr(base).readByteArray(size);
                                fd.write(dex_buffer);
                                fd.flush();
                                fd.close();
                                console.log("[dump dex]:", dex_path);

                            }
                        }
                    }
                }
            },
            onLeave: function(retval) {}
        });
    }
}

// dump_dex()
// /data/local
```

### 4.5 其他 Android 版本要改符号

上面匹配的符号串:

```
_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS9_8ClassDefE
```

这是 **Android 9** 的 `ClassLinker::DefineClass` mangled name。换系统版本时,符号(参数列表/命名空间)会变,需要在 libart.so 里重新按关键词(`ClassLinker` + `DefineClass` + `Thread` + `DexFile`)搜出当前版本的完整符号再匹配;同时 `args[5]` 的参数位置和 `DexFile` 内部 `begin_`/`size_` 的成员偏移也可能随版本变化,需用 IDA 对照当前 libart.so 结构确认。

另外注意 dex 结构:dump 出来的 dex 头部 magic 是 `dex\n035\0` 之类;如果壳抹掉了 header,需要工具修复(改 magic / header checksum / file_size)后才能进 jadx/JEB。

## 五、loadDex:frida 主动加载 dex

什么时候用:把外部编译好的 hook.dex 注入到目标进程里执行(配合 yahfa/patch classLoader 等方案,见 `02-frida/高级/yahfa与arthook.md`)。

```javascript
function loadDex(dexPath, optimizedDirectory, librarySearchPath, parent) {
    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    return DexClassLoader.$new(dexPath, optimizedDirectory, librarySearchPath, parent);
}

// 加载两个so
function main() {
    Java.perform(() => {
        var cl = loadDex( "/data/data/th.co.truemoney.wallet/files/hook.dex", "/data/data/th.co.truemoney.wallet/cache", null, Java.classFactory.loader);
        console.log(cl)
    })
}

main();
```

## 六、从 ArtMethod 拿 DexFile(辅助)

如果手里已经有 ArtMethod 指针,可以直接链出它所属的 DexFile(用于确认/读取 dex):

```javascript
function getDexFile(artmethod) {
    // 读取declaring_class_
    const declaring_class_ = ptr(artmethod.readU32())
    // 读取dex_cache_
    const dex_cache_ = ptr(declaring_class_.add(8 * 2).readU32());
    // 读取DexFile
    return dex_cache_.add(16).readPointer()
}
```

ArtMethod 偏移如何探测,另见 `02-frida/frida-API详解.md` 的 ArtMethod 章节。

## 相关文档

- so 的 dump 与修复:[so修复dump.md](so修复dump.md)
- 动态加载 so 的等待 hook(waitForModule):[../02-frida/高级/so与soinfo操作.md](../02-frida/高级/so与soinfo操作.md)
- eBPF 脱壳全解(更隐蔽,anti-frida 目标):[eBPF脱壳深挖.md](eBPF脱壳深挖.md)

## 方案现状与选型

本文件第二~六节是 frida/Java 层经典路线。近两年壳的对抗水位变化后,各方案现状如下:

### 1. FART:Android 12-16 直接失效

FART 靠改 ART 源码刷机、在 `dumpArtMethod` 里主动调用全量方法 dump CodeItem。失效三根因:

- `ArtMethod` 字段布局硬编码(entry_point_from_quick_compiled_code_、dex_code_item_offset 等),Android 12+ 布局与访问方式(Accessor 化)全变;
- ClassLinker→Invoke 执行链改动,原主动调用时机触发不了;
- odex/vdex 布局升级,内容可能只在 vdex 且为 compact dex。

原版实测上限约 Android 10(LineageOS 17.1 移植),12-16 要按新 AOSP 重移植。社区替代:重移植(cyrus-studio 实录)、MikRom 集成、Youpk、BlackDex、FRIDA-DEXDump、eBPF 方案。要「全量方法体」仍只有主动调用路线能保证,当前可用载体是 **JDex(LSPosed)** 而非 FART。

### 2. 其他工具定位

- **JDex/JDex2**(开源 J5now/JDex2):LSPosed 注入→真实 ClassLoader→遍历 DexFile→主动调构造方法触发回填→Native mCookie dump。抽取壳当前主力,免刷机。
- **RePairip**(ispointer):Pairip/Google 加固专杀,dump 所有 VMRunner 快照并完整重打包。
- **BlackDex**(CodingGay):免 root 独立 app,虚拟化+DexFile cookie 双路 dump,Android 5.0-12,深度模式可修 nop 函数体(实验性)。
- **dpt-shell**(luoyesiqiu):函数抽取壳**本体**,练手/验证脱壳工具的靶子,配套 dpt-unpacker/dpt-tool 反制。

### 3. 何时选 eBPF

- 目标有 anti-frida(扫 maps/线程名/端口/TracerPid)→ eBPF 是目前最隐蔽路线:`bpf()` 加载进内核、目标进程零注入零 ptrace,frida 全部检测面缺失;
- 需要 so+JNI 一条龙(dumpso/fixso/jni_symbols 符号回填);
- 接受两个代价:必须 root+ARM64+内核支持 uprobe/BTF;**只读观察模型**——抽取壳只回填真正执行过的方法,没跑到的拿不到(要全量仍需 JDex/FART 系主动调用)。
- 工具:**eBPFDexDumper**(Go,A13/16 实测)与 **eBPFDexDumper-rs**(Rust,修复管线更全:ringbuf 分块拼装、process_vm_readv 缺页兜底、CodeItem 反扫回填、SHA-1/Adler-32 重算)。

### 4. 各方案速查表

| 方案 | 路线 | root | 抽取壳全量 | 现状 |
|---|---|---|---|---|
| frida DefineClass(本文件四) | hook libart 符号 | 要 | 否 | 通用,anti-frida 环境易死 |
| eBPFDexDumper / -rs | eBPF uprobe 零注入 | 要 | 否(仅执行过的方法) | A13+ 实测,当前最深 |
| FART | 改 ART 源码刷机 | 刷机 | 是 | **A12-16 失效**,需重移植 |
| JDex/JDex2 | LSPosed 主动调用 | 免刷机 | 是(构造方法回填) | 抽取壳主力 |
| BlackDex | 免 root 虚拟化 | 不要 | 部分(深度模式实验性) | A5-12 |
| RePairip | VMRunner 快照重打包 | - | - | Pairip 专杀 |
| dpt-shell | 抽取壳本体 | - | - | 靶子,非脱壳工具 |

### 5. 一句话选型

无对抗要快 → 本文件 frida DefineClass 法;强对抗可 root → eBPF;抽取壳要全量方法体 → JDex;免 root → BlackDex;Pairip → RePairip。
