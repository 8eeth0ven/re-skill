# dex unpacking dump

> Covers: dumping via the DexFile ByteBuffer constructor, the frida-dump DefineClass method, the principle of finding the classLoader with enumerateClassLoadersSync in packed apps, mkdir/chmod helpers, and actively loading a dex with loadDex.

## 1. Overall approach

Unpacking is essentially intercepting the moment "the dex has been decrypted, and ART is about to defineClass it" and writing the in-memory dex bytes to disk. Three common routes:

| Route | Intercept point | Applicable |
|------|--------|------|
| Java layer | the ByteBuffer constructor of `dalvik.system.DexFile` | the packer loads the decrypted dex via InMemoryDexClassLoader / the ByteBuffer route |
| Native layer | the `ClassLinker::DefineClass` symbol in libart.so (how frida-dump works) | universal — fires whenever any class is loaded |
| classLoader enumeration | `Java.enumerateClassLoadersSync()` | not a direct dump — it finds the packer's classLoader so the decrypted classes can be hooked |

## 2. Dumping via the DexFile ByteBuffer constructor

When to use: the target packer loads the decrypted dex with `InMemoryDexClassLoader` (which internally goes through DexFile's ByteBuffer constructor); dump each buffer inside that constructor.

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

Note: the package name in the path (`com.vnpay.bidv`) must be replaced with the target app's package name.

## 3. The principle of finding the classLoader with enumerateClassLoadersSync in packed apps

Hooking a packed app requires the classLoader: every loaded dex has a corresponding classLoader, and calls between them also require each other's classLoaders — there is no way to use them directly. Our hooks need these too, because only that way can we hook the concrete address of the Java function, turning it into a native function to hook.

Key points:
- Probe with `classLoader.loadClass("<target class>")` to find which loader can load the business classes the packer released;
- On a hit, `Java.classFactory.loader = classLoader;` switches the global factory over; only then will `Java.use` find the class.

For the complete example code (enumerateClassLoadersSync probing + switching loaders + hooking `ot2.b.getBdOz`) see the "hooking packed apps" section of `../02-frida/java-layer/crypto-and-self-dump.md`; not duplicated here.

## 4. frida-dump: the DefineClass method (universal)

> **For the eBPF approach see [ebpf-unpacking-deep.md](ebpf-unpacking-deep.md)** (first choice for anti-frida targets — zero injection, stealthier).

Principle: hook `ClassLinker::DefineClass` in libart; the 5th argument is a `const DexFile&`, from whose memory layout read out `begin_` (dex start address) and `size_` (dex size), and dump whenever a new address appears. Independent of packer type — every class load passes through here.

Helper functions (all implemented via NativeFunction calls into libc, no dependency on the Java layer — usable at the earliest spawn stage):

### 4.1 get_self_process_name: read /proc/self/cmdline for the package name

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

### 4.2 mkdir: create the directory if absent (probed with opendir)

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

### 4.3 chmod: chmod the directory to 755 (easy to pull later)

```javascript
function chmod(path) {
    var chmodPtr = Module.getExportByName('libc.so', 'chmod');
    var chmod = new NativeFunction(chmodPtr, 'int', ['pointer', 'int']);
    var cPath = Memory.allocUtf8String(path);
    chmod(cPath, 755);
}
```

### 4.4 The dump_dex main body

```javascript
function dump_dex() {
    var libart = Process.findModuleByName("libart.so");
    var addr_DefineClass = null;
    var symbols = libart.enumerateSymbols();
    for (var index = 0; index < symbols.length; index++) {
        var symbol = symbols[index];
        var symbol_name = symbol.name;
        // This DefineClass signature is for Android 9
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

### 4.5 Other Android versions need a different symbol

The symbol string matched above:

```
_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS9_8ClassDefE
```

This is the **Android 9** mangled name of `ClassLinker::DefineClass`. On another system version the symbol (parameter list/namespaces) changes: re-search libart.so by the keywords (`ClassLinker` + `DefineClass` + `Thread` + `DexFile`) for the current version's full symbol and match on that; meanwhile the position of `args[5]` and the member offsets of `begin_`/`size_` inside `DexFile` may also shift between versions — confirm against the current libart.so layout with IDA.

Also note the dex structure: a dumped dex has a header magic like `dex\n035\0`; if the packer wiped the header, it must be repaired with a tool (fix the magic / header checksum / file_size) before jadx/JEB can open it.

## 5. loadDex: actively loading a dex from frida

When to use: inject an externally compiled hook.dex into the target process to run (paired with the yahfa/patch-classLoader approaches, see `../02-frida/advanced/yahfa-and-art-hook.md`).

```javascript
function loadDex(dexPath, optimizedDirectory, librarySearchPath, parent) {
    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    return DexClassLoader.$new(dexPath, optimizedDirectory, librarySearchPath, parent);
}

// Load both shared libraries
function main() {
    Java.perform(() => {
        var cl = loadDex( "/data/data/th.co.truemoney.wallet/files/hook.dex", "/data/data/th.co.truemoney.wallet/cache", null, Java.classFactory.loader);
        console.log(cl)
    })
}

main();
```

## 6. Getting the DexFile from an ArtMethod (helper)

If you already hold an ArtMethod pointer, you can chain straight to the DexFile it belongs to (to confirm/read the dex):

```javascript
function getDexFile(artmethod) {
    // Read declaring_class_
    const declaring_class_ = ptr(artmethod.readU32())
    // Read dex_cache_
    const dex_cache_ = ptr(declaring_class_.add(8 * 2).readU32());
    // Read DexFile
    return dex_cache_.add(16).readPointer()
}
```

For how to probe ArtMethod offsets see the ArtMethod chapter of `../02-frida/frida-api-reference.md`.

## Related docs

- so dumping and repair: [so-repair-dump.md](so-repair-dump.md)
- Wait-hook for dynamically loaded so (waitForModule): [../02-frida/advanced/so-soinfo-ops.md](../02-frida/advanced/so-soinfo-ops.md)
- The full eBPF unpacking guide (stealthier, for anti-frida targets): [ebpf-unpacking-deep.md](ebpf-unpacking-deep.md)

## Current state and picking an approach

Sections 2-6 of this file are the classic frida/Java-layer routes. With the packers' adversarial level having shifted over the past two years, the current state of each approach:

### 1. FART: dead on Android 12-16

FART works by flashing a modified-ART build and actively invoking every method inside `dumpArtMethod` to dump CodeItems. Three root causes of the failure:

- The `ArtMethod` field layout is hardcoded (entry_point_from_quick_compiled_code_, dex_code_item_offset, etc.), and Android 12+ changed the layout and access style completely (everything moved behind Accessors);
- The ClassLinker→Invoke execution chain changed, so the original active-invocation timing no longer fires;
- odex/vdex layout upgrades — the content may exist only in the vdex and as compact dex.

The original's tested ceiling is about Android 10 (the LineageOS 17.1 port); 12-16 needs a re-port against new AOSP. Community alternatives: re-ports (cyrus-studio's write-up), MikRom integration, Youpk, BlackDex, FRIDA-DEXDump, the eBPF approaches. For "every method body" only the active-invocation route still guarantees coverage, and the currently usable vehicle is **JDex (LSPosed)**, not FART.

### 2. Where the other tools fit

- **JDex/JDex2** (open source, J5now/JDex2): LSPosed injection → real ClassLoader → walk the DexFiles → actively call constructors to trigger backfill → Native mCookie dump. Today's main tool for extraction packers, no flashing needed.
- **RePairip** (ispointer): the specialist killer for Pairip/Google hardening — dumps all VMRunner snapshots and repackages them completely.
- **BlackDex** (CodingGay): root-free standalone app, dual-route dump via virtualization + DexFile cookie, Android 5.0-12; deep mode can repair nop'd method bodies (experimental).
- **dpt-shell** (luoyesiqiu): the function-extraction packer **itself** — the practice target for testing unpackers, with the dpt-unpacker/dpt-tool countermeasures alongside.

### 3. When to pick eBPF

- The target has anti-frida (scanning maps/thread names/ports/TracerPid) → eBPF is currently the stealthiest route: loaded into the kernel via `bpf()`, zero injection and zero ptrace on the target process — every frida detection surface is missing;
- You need the so+JNI one-stop shop (dumpso/fixso/jni_symbols symbol backfill);
- You accept two costs: root + ARM64 + a kernel with uprobe/BTF support; and the **read-only observation model** — an extraction packer only backfills methods that actually ran, the ones never reached are not obtained (full coverage still needs JDex/FART-style active invocation).
- Tools: **eBPFDexDumper** (Go, tested on A13/16) and **eBPFDexDumper-rs** (Rust, fuller repair pipeline: ringbuf chunk reassembly, process_vm_readv fallback for missing pages, CodeItem back-scan backfill, SHA-1/Adler-32 recomputation).

### 4. Quick-reference table

| Approach | Route | root | Full coverage of extraction packers | Status |
|---|---|---|---|---|
| frida DefineClass (section 4 of this file) | hook a libart symbol | yes | no | universal; dies easily in anti-frida environments |
| eBPFDexDumper / -rs | eBPF uprobe, zero injection | yes | no (only executed methods) | tested on A13+, currently the deepest |
| FART | modified-ART flash | flash | yes | **dead on A12-16**, needs a re-port |
| JDex/JDex2 | LSPosed active invocation | no flash | yes (constructor backfill) | main tool for extraction packers |
| BlackDex | root-free virtualization | no | partial (deep mode experimental) | A5-12 |
| RePairip | VMRunner snapshot repackage | - | - | Pairip specialist |
| dpt-shell | extraction packer itself | - | - | a target, not an unpacker |

### 5. One-line picker

No opposition and need speed → the frida DefineClass method in this file; heavy opposition with root available → eBPF; extraction packer needing every method body → JDex; root-free → BlackDex; Pairip → RePairip.
