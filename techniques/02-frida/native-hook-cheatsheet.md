# Native Layer Hook Cheatsheet

> Basic so-layer hook points + common utility functions. Every entry: when to use + complete code.

## 1. Basic Functions

### 1.1 NewStringUTF (JNI string creation)

When to use: to watch every place in the so that creates JNI strings (encryption results and concatenated parameters often surface here). Search for the symbol inside libart.so and attach.

```javascript
function hook_NewStringUTF() {
    var artModule = Process.findModuleByName("libart.so");
    var symbols = artModule.enumerateSymbols();
    var newStringUTF = null;
    for (let i = 0; i < symbols.length; i++) {
        let symbol = symbols[i];
        if (symbol.name.indexOf("NewStringUTF") !== -1) {
            console.log(symbol.name);
            newStringUTF = symbol.address;
        }
    }
    if (newStringUTF) {
        Interceptor.attach(newStringUTF, {
            onEnter: function (args) {
                let string = args[1].readCString()
                console.log("[字符串]:", string);
                console.log("[调用栈]:",Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join('\n') + '\n');
            }, onLeave: function (retval) {
            }
        })
    } else {
        console.log("没有这个函数")
    }
}
```

### 1.2 dlsym (dynamic function address lookup)

This function looks up the concrete address of a function. Its arguments are a handle (the so file's base address) and the function name, and it returns that function's address. Statically registered functions, the ones linking the native layer with the Java layer, pass through here, so this code can also be used to locate related statically registered code.

```javascript
function hook_dlsym(){
    // Resolve dlsym
    let dlsymAddr = Module.findExportByName("libdl.so","dlsym");
    console.log(dlsymAddr);
    // hook dlsym
    Interceptor.attach(dlsymAddr,{
        onEnter:function(args){
            this.args1 = args[1];
        },
        onLeave:function(retval){
            let md= Process.findModuleByAddress(retval);
            if(md==null)return;
            console.log("函数："+this.args1.readCString(),"模块："+md.name,"地址："+retval,"偏移："+retval.sub(md.base));
        }
    })  
}
```

### 1.3 dlopen / android_dlopen_ext (so load monitoring)

#### First variant (hook both low-version dlopen and high-version android_dlopen_ext)

When to use: wait until the target so has finished loading, then inline hook its internal functions.

```javascript
// On Android versions below 8.0, shared-object loading goes through dlopen
function hook_dlopen() {
    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter: function (args) {
            this.call_hook = false;
            var so_name = ptr(args[0]).readCString();
            if (so_name.indexOf("libxx.so") >= 0) {
                console.log("dlopen:", ptr(args[0]).readCString());
                this.call_hook = true;// dlopen found the target library
            }

        }, onLeave: function (retval) {
            if (this.call_hook) {// Hook the shared object once dlopen has found it
                inline_hook();
            }
        }
    });
    // Newer Android versions use android_dlopen_ext
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            var pathptr = args[0];
            if (pathptr !== undefined && pathptr != null) {
                var path = ptr(pathptr).readCString();
                console.log(path)
                if (path.indexOf("libxxx.so") !== -1) {
                    this.BookReader4Android = true
                }
            }
        },
        onLeave: function (retval) {
            if (this.BookReader4Android) {
            }
        }
    });
}
```

#### Second variant (parameterized so name)

```javascript
function hook_dlopen(so_name) {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            var pathptr = args[0];
            if (pathptr !== undefined && pathptr != null) {
                var path = ptr(pathptr).readCString();
                console.log(path)
                if (path.indexOf(so_name) !== -1) {
                    this.match = true
                }
            }
        },
        onLeave: function (retval) {
            if (this.match) {
                console.log(so_name, "加载成功")
            }
        }
    });
}
```

Note: if the target so loads earlier than your script (in attach mode it is already loaded by then), the dlopen hook is useless; switch to `waitForModule` polling or simply null-check `Process.findModuleByName`, see [advanced/so-soinfo-ops.md](advanced/so-soinfo-ops.md).

### 1.4 open (file access monitoring)

```javascript
var open_addr = Module.findExportByName(null, "open");
    Interceptor.attach(open_addr, {
        onEnter: function (args) {
            const filename = args[0].readCString()
            console.log(filename)
        },
        onLeave: function (retval){
            if (this.maps_file){
                retval.replace(0)
            }
        }
    })
```

### 1.5 Hooking init-time calls (.init_xxx scenarios)

Code that runs in .init_xxx executes during dlopen, so you must find the syscall inside the system functions used at the very beginning and hook it; similarly to below, this hooks one of the open-family functions:

```javascript
var open_addr = Module.findExportByName(null, "open");
    Interceptor.attach(open_addr, {
        onEnter: function (args) {
            const filename = args[0].readCString()
            if (filename.indexOf("maps") !== -1) {
                console.log(filename)
                console.log('RegisterNatives called from:\n' + Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join('\n') + '\n');
                // Thread.sleep(40)
                this.maps_file = true
            }
            if (!is_run) {
                locate_init()
            }
            is_run = true
        },
        onLeave: function (retval){
            if (this.maps_file){
                retval.replace(0)
            }
        }
    })
```

### 1.6 exit / kill (exiting and killing the process)

Hooking the exit and kill functions. But it is basically useless, because inside a so the same can be done via syscalls, commands like svc 0; the specifics are unclear, but it can likewise close the current process.

```javascript
function hook_exit() {
    var exit = Module.findExportByName(null, "exit")
    console.log("exit", exit)
    null !== exit && Interceptor.attach(exit,
        {
            onEnter: function (args) {
                var args1 = args[0];
                if (args1 !== undefined && args1 != null) {
                    var status = args1.readInt();
                    console.log("exit " + status);
                }
            }
        }
    );
}

function hook_kill() {
    const killAddr = Module.findExportByName(null, 'kill');
    console.log("kill", killAddr)
    null !== killAddr && Interceptor.attach(killAddr, {
        onEnter: function (args) {
            console.log('kill called with pid: ' + args[0].toInt32() + ', signal: ' + args[1].toInt32());
            // Modify args here to change behavior
        },
        onLeave: function (retval) {
            console.log('kill returned: ' + retval.toInt32());
            // Modify the return value here
        }
    });
}
```

### 1.7 pthread_create (attach version)

Generally this is the function used to create a thread when frida detection runs; the concrete hook is as follows:

```javascript
function hook_pthread_create() {
    var pthread_create_addr = Module.findExportByName(null, "pthread_create");
    Interceptor.attach(pthread_create_addr, {
        onEnter(args) {
            var parg2 = args[2]
            var parg3 = args[3]
            var so_name = Process.findModuleByAddress(parg2).name;
            const baseAddr = Module.findBaseAddress(so_name)
            console.log("pthread_create", so_name, parg3.toString(16), parg2.sub(baseAddr).toString(16))
        }
    })
}
```

### 1.8 pthread_create (replace version, rewritten with NativeCallback)

When to use: attach can only observe, replace can change behavior (e.g. deny a given so from starting threads).

```javascript
function create_pthread_create() {
    const pthread_create_addr = Module.findExportByName(null, "pthread_create")
    const pthread_create = new NativeFunction(pthread_create_addr, "int", ["pointer", "pointer", "pointer", "pointer"]);
    return new NativeCallback((parg0, parg1, parg2, parg3) => {
        const module = Process.findModuleByAddress(parg2);
        const so_name = module.name;
        const baseAddr = module.base
        console.log("pthread_create", so_name, "0x" + parg2.sub(baseAddr).toString(16), "0x" + parg3.toString(16))
        // A successful call returns 0
        return pthread_create(parg0, parg1, parg2, parg3)
    }, "int", ["pointer", "pointer", "pointer", "pointer"])
}


// Alternative
function replace_thread() {
    var new_pthread_create = create_pthread_create()
    var pthread_create_addr = Module.findExportByName(null, "pthread_create")
    // Replace the function
    Interceptor.replace(pthread_create_addr, new_pthread_create);
}

replace_thread()
```

### 1.9 __pthread_start

```javascript
// Frida script to hook pthread_start
function hook__pthread_start() {
    // Locate pthread_start
    var __pthread_start = DebugSymbol.fromName("_ZL15__pthread_startPv").address;
    console.log(__pthread_start)
    __pthread_start && Interceptor.attach(__pthread_start, {
        onEnter: function (args) {
            var addr = args[0].add(12 * 8).readPointer();
            var so_name = Process.findModuleByAddress(addr).name;
            var so_base = Module.getBaseAddress(so_name);
            console.log(so_name, so_base, addr.sub(so_base))
        }
    });
}

hook__pthread_start()
```

### 1.10 clone replacement (skip thread creation for selected so files)

When to use: when the detection thread is started with `clone` instead of `pthread_create` (common for ptrace/anti-debug threads); block thread creation from the specified so files outright.

```javascript
function replace_clone() {
    let p_clone_addr = Module.findExportByName("libc.so", "clone");
    let libNameList = ["libDexHelper.so", "libexec.so", "libexecmain.so", "libmsaoaidsec.so"];
    let retType = "int";
    let argTypes = ["pointer", "pointer", "int", "pointer", "pointer", "pointer", "pointer"];
    let p_clone = new NativeFunction(p_clone_addr, retType, argTypes);
    Interceptor.replace(p_clone, new NativeCallback(
        (p_arg0, p_arg1, p_arg2, p_arg3, p_arg4, p_arg5, p_arg6) => {
            if (p_arg3 != 0x0) {
                let new_p_arg3;
                if (Process.pointerSize === 4) {
                    new_p_arg3 = p_arg3.add(0x30).readPointer();
                } else {
                    new_p_arg3 = p_arg3.add(0x60).readPointer();
                }

                let so_name = Process.findModuleByAddress(new_p_arg3).name;
                let so_base = Module.getBaseAddress(so_name);
                let offset = new_p_arg3 - so_base;

                console.log(so_name, new_p_arg3, offset.toString(16));

                if (libNameList.indexOf(so_name) !== -1) {
                    console.warn("已跳过指定线程创建 -> ", offset);
                    return 0;
                }
            }

            return p_clone(p_arg0, p_arg1, p_arg2, p_arg3, p_arg4, p_arg5, p_arg6);
        }, retType, argTypes)
    );
}

replace_clone();
```

### 1.11 strstr / strcmp (string comparison)

#### strstr

```javascript
function hook_strstr() {
    var strstr = Module.findExportByName(null, "strstr");
    console.log("strstr", strstr)
    null !== strstr && Interceptor.attach(strstr, {
        onEnter: function (e) {
            var haystack = e[0].readCString();
            var needle = e[1].readCString();
            // Both arguments above are strings
        }, onLeave: function (e) {
            // A return value of 0 indicates that the detection did not match
        }
    })
}
```

#### strcmp

```javascript
function hook_strcmp() {
    Interceptor.attach(Module.findExportByName(null, 'strcmp'), {
        onEnter: function (args) {
            // Read strcmp's two string arguments
            var str1 = args[0].readUtf8String();
            var str2 = args[1].readUtf8String();
            // Print both strings passed to strcmp
            console.log('strcmp called with:');
            console.log('  str1: ' + str1);
            console.log('  str2: ' + str2);
        },
        onLeave: function (retval) {
            // Print strcmp's return value
            console.log('strcmp returned: ' + retval.toInt32());
        }
    });
}
```

### 1.12 memcpy (catching instruction copies into the code section)

When to use: the packer decrypts an encrypted instruction block and memcpys it back into the code section; filtering on "length 4 + source address inside the text section" catches instruction-level patches.

```javascript
 Interceptor.attach(Module.findExportByName("libc.so", "memcpy"), {
    onEnter: function (args) {
        this.dst = args[0];
        this.src = args[1];
        this.size = args[2].toInt32();
    },
    onLeave: function (retval) {
        // ARM64 instructions are 4 bytes wide
        if (this.size === 4) {
            // Check whether the address lies in a code segment
            if (textRange && (this.src.compare(textRange.base) >= 0 && this.src.compare(textRange.base.add(textRange.size)) < 0)) {
                console.log("可能是ARM64指令的memcpy:");

                console.log("复制地址: " + this.dst);
                console.log("源地址: " + this.src);
                console.log("复制位数大小: " + this.size);
                console.log("字节打印：")
                console.log(hexdump(this.dst, { offset: 0, length: this.size }));

                // Confirm with common ARM64 instruction patterns, for example by inspecting the leading bits
                var instruction = Memory.readU32(this.dst);
                console.log("Instruction (hex): " + instruction.toString(16));
            }
        }
    }
});
```

### 1.13 memcmp (flip the return value once on match, then detach)

This example also demonstrates the use of Thumb pointer `and(-2)` alignment:

```javascript
const l = Module.getExportByName("libc.so", "pthread_create")
// Align the address; it is normally already aligned
const i = l.and(-2)
// If this succeeds
const r = Interceptor.attach(Module.getExportByName("libc.so", "memcmp"), {
    onEnter: function (e) {
        this.match = 0 === e[0].compare(i) || 0 === e[1].compare(i)
    }, onLeave: function (e) {
        // Destroy the object
        this.match && (e.replace(new NativePointer(0)), r.detach())
    }
});
```

### 1.14 RegisterNatives (dynamic registration locating)

Dynamically registered functions (JNI dynamic binding) all pass through here; grab class/method/signature/function address/containing so/offset in one shot:

```javascript
function hook_RegisterNatives() {
    var RegisterNatives_addr = null;
    var symbols = Process.findModuleByName("libart.so").enumerateSymbols();
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i].name;
        if ((symbol.indexOf("CheckJNI") == -1) && (symbol.indexOf("JNI") >= 0)) {
            if (symbol.indexOf("RegisterNatives") >= 0) {
                RegisterNatives_addr = symbols[i].address;
                console.log("RegisterNatives_addr: ", RegisterNatives_addr);
                break;
            }
        }
    }
    Interceptor.attach(RegisterNatives_addr, {
        onEnter: function (args) {
            var env = args[0];
            var jclass = args[1];
            var class_name = Java.vm.tryGetEnv().getClassName(jclass);
            var methods_ptr = ptr(args[2]);
            var method_count = args[3].toInt32();
            console.log("RegisterNatives method counts: ", method_count);
            for (var i = 0; i < method_count; i++) {
                var name = methods_ptr.add(i * Process.pointerSize * 3).readPointer().readCString();
                var sig = methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize).readPointer().readCString();
                var fnPtr_ptr = methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();
                var find_module = Process.findModuleByAddress(fnPtr_ptr);
                console.log("类: ", class_name, "方法: ", name, "签名: ", sig, "函数地址: ", fnPtr_ptr, "模块名: ", find_module.name, "函数偏移: ", ptr(fnPtr_ptr).sub(find_module.base));
            }
        },
        onLeave: function (retval) {}
    });
}

hook_RegisterNatives()
```

### 1.15 init_array (call_constructors)

Hook this call_constructors: it is what runs the so's initialization functions, executing the so's initializers at the point where dlopen starts.

```javascript
function hook_init_array() {
    let linker = null;
    if (Process.pointerSize === 4) {
        linker = Process.findModuleByName("linker");
    } else {
        linker = Process.findModuleByName("linker64");
    }
    let call_constructors_addr, get_soname
    let symbols = linker.enumerateSymbols();
    for (let index = 0; index < symbols.length; index++) {
        let symbol = symbols[index];
        if (symbol.name === "__dl__ZN6soinfo17call_constructorsEv") {
            call_constructors_addr = symbol.address;
        } else if (symbol.name === "__dl__ZNK6soinfo10get_sonameEv") {
            get_soname = new NativeFunction(symbol.address, "pointer", ["pointer"]);
        }
    }
    console.log(call_constructors_addr)
    Interceptor.attach(call_constructors_addr, {
        onEnter: function (args) {
            let soinfo = args[0];
            let soname = get_soname(soinfo).readCString();
            // Initialization has not yet completed at this point
            // Load the shared object here; this is also a possible location for NOP patches
        },
        onLeave: function (retval) {
            if (this.match) {
                console.log("libDexHelper.so", "加载成功")
                const module = Process.findModuleByName("libDexHelper.so");
                // Initialization has completed; dlopen runs next
            }
        }
    });
}
```

### 1.16 Hooking strstr to defeat frida detection

When to use: the target scans for frida signature strings with strstr. But for those that do not use strstr or use something else, there is no way to catch it this way.

```javascript
function antifrida() {
    var strstr = Module.findExportByName(null, "strstr");
    console.log("strstr", strstr)
    null !== strstr && Interceptor.attach(strstr, {
        onEnter: function (e) {
            this.frida = Boolean(0), this.haystack = e[0], this.needle = e[1],
            null !== this.haystack.readCString() && null !== this.needle.readCString() &&
            (-1 === this.haystack.readCString().indexOf("frida") &&
                -1 === this.needle.readCString().indexOf("frida") &&
                -1 === this.haystack.readCString().indexOf("gum-js-loop") &&
                -1 === this.needle.readCString().indexOf("gum-js-loop") &&
                -1 === this.haystack.readCString().indexOf("gmain") &&
                -1 === this.needle.readCString().indexOf("gmain") &&
                -1 === this.haystack.readCString().indexOf("linjector") &&
                -1 === this.needle.readCString().indexOf("linjector") ||
                (this.frida = Boolean(1)))
        }, onLeave: function (e) {
            if (this.frida) {
                if (this.haystack.readCString().indexOf(this.needle.readCString()) !== -1) {
                    // console.log("[haystack] =>", this.haystack.readCString())
                    // console.log("[needle]   =>", this.needle.readCString())
                }
                e.replace(0);
            }
        }
    })
}
```

For more memory-level anti-detection (replacing the libfrida-agent signature, removing rwxp) see [advanced/detection-bypass-snippets.md](advanced/detection-bypass-snippets.md) and [frida-api-reference.md](frida-api-reference.md).

## 2. so Layer Operations

### 2.1 Enumerate all so files

```javascript
function hook_native(){
    var modules = Process.enumerateModules();
    for (var i in modules){
        var module = modules[i];
        console.log(module.name);
        console.log(module.size);
        console.log(module.base);
        console.log(module.path);
    }
}
```

### 2.2 Print all functions imported by a so

```javascript
const hooks = Module.load('/data/app/com.example.hookdemo-xMdClW3H4V5El06BIcGN0A==/lib/arm64/libhookdemo.so');
var Imports = hooks.enumerateImports();
for(var i = 0; i < Imports.length; i++) {
    // Function type
    console.log("type:",Imports[i].type);
    // Function name
    console.log("name:",Imports[i].name);
    // Owning module
    console.log("module:",Imports[i].module);
    // Function address
    console.log("address:",Imports[i].address);
 }
```

## 3. Utility Functions (Java/general)

### 3.1 Stack printing (ACCURATE / FUZZY)

Two precision levels for printing call stacks in native code; `FUZZY` copes with inlined/wiped stack-frame scenarios:

```javascript
console.log('backtrace called from:\n' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');

console.log('backtrace called from:\n' + Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join('\n') + '\n');

Thread.currentContext();
```

### 3.2 getStackTraceString (one-shot Java-layer stack printing)

```javascript
function getStackTraceString() {
    console.log(Java.use('android.util.Log')
        .getStackTraceString(Java.use('java.lang.Throwable')
            .$new()));
}
```

### 3.3 Print bytes as UTF-8

```javascript
function utf8Bytes(exampleBytes) {
    let StringClass = Java.use("java.lang.String");
    let CharsetClass = Java.use("java.nio.charset.Charset");
    let utf8Charset = CharsetClass.forName("UTF-8");
    return StringClass.$new(exampleBytes, utf8Charset);
}
```

### 3.4 Print a map as JSON (requires the target to bundle gson)

```javascript
function maptoJson(map){
    var Gson = Java.use('com.google.gson.Gson').$new();
    return Gson.toJsonTree(map).getAsJsonObject();
}
```

### 3.5 dumpAllFieldValue (print all fields of an object)

```javascript
function dumpAllFieldValue(obj) {
    if (obj === null) {
        return;
    }
    console.log("Dump all fields value for  " + obj.getClass() + " :");
    var cls = obj.getClass();
    while (cls !== null && !cls.equals(Java.use("java.lang.Object").class)) {
        var fields = cls.getDeclaredFields();
        if (fields === null || fields.length === 0) {
            cls = cls.getSuperclass();
            continue;
        }

        if (!cls.equals(obj.getClass())) {
            console.log("Dump super class  " + cls.getName() + " fields:");
        }

        for (var i = 0; i < fields.length; i++) {
            var field = fields[i];
            field.setAccessible(true);
            var name = field.getName();
            var value = field.get(obj);
            var type = field.getType();
            console.log(type + " " + name + "=" + value);
        }
        cls = cls.getSuperclass();
    }
}
```

### 3.6 getFieldValue (get a single field of an object)

```javascript
function getFieldValue(obj, className, fieldName) {
    try {
        var cls = Java.use(className).class; // Obtain the object's class
        var field = cls.getDeclaredField(fieldName); // Resolve the requested field
        field.setAccessible(true); // Make the field accessible
        return field.get(obj); // Read the field value
    } catch (e) {
        console.error("Failed to get field: " + fieldName + ", Error: " + e);
        return null;
    }
}

Java.enumerateClassLoadersSync().forEach(classLoader => {
        const pathList = getFieldValue(classLoader, "dalvik.system.BaseDexClassLoader", "pathList")
})
```

### 3.7 Print all method signatures

```javascript
var methods = clazz.class.getDeclaredMethods();
for (var i = 0; i < methods.length; i++) {
    // Read the method name and signature
    var methodName = methods[i].getName();
    var methodSignature = methods[i].toString(); // toString() returns the method signature
    console.log("Method: " + methodName + ", Signature: " + methodSignature);
}
```

### 3.8 Instruction.parse (parse a single assembly instruction)

Normally, on arm64 one instruction is 4 bytes:

```javascript
 Instruction.parse(ptr(address))
```

You can also just look at the hex:

```javascript
console.log(hexdump(ptr(address), {
    length: 4,
    header: true,
    ansi: true
}))
```

`ptr` converts an address into a pointer:

```javascript
ptr(0x4cb54 + 0x700c113000)
```

### 3.9 Thumb instruction and(-2) caveats

**Note that Thumb instructions need `and(-2)` before functions like hexdump and readArray work properly, but Instruction does not need and(-2).**

For a real-world example see the memcmp in 1.13 above (`l.and(-2)` first, then compare). In addition:
- Check whether an address is inside the current module:

```javascript
const isModuleCode = baseFirstAddress.compare(base) >= 0 &&
baseFirstAddress.compare(base.add(size)) < 0;
```

### 3.10 Rewriting instructions (Arm64Writer)

For the full function-ized nop/ret version (wrapped as retFunc/nopFunc) see also [advanced/patch-and-memory.md](advanced/patch-and-memory.md); here is the minimal form:

```javascript
Memory.protect(ptr(address), 4, 'rwx');
// Write a 'ret' instruction with Arm64Writer
var writer = new Arm64Writer(parg2);
writer.putRet();
writer.flush();
writer.dispose();
console.log("ret success");

// Write a NOP instruction
var writer = new Arm64Writer(parg2);
writer.putNop(); // Write a NOP instruction
writer.flush();  // Flush the instruction writer to memory
console.log("ret success");
```

### 3.11 Reading DCB data (function table entry -> module/symbol)

```javascript
const address = module.base.add(0xEA478);
// Read a 64-bit value with Memory.readU64
const value = Memory.readU64(address);
// Print the module and related symbols
const func_module = Process.findModuleByAddress(ptr(value))
console.log(func_module.name)
console.log(func_module.base)
const symbol = DebugSymbol.fromAddress(ptr(value));
console.log(symbol.name)
```

## Related Docs

- Java-layer hook points: the 6 docs in the java-layer/ directory (network-webview / crypto-and-self-dump / storage-and-system / ui-and-navigation / strings-and-json / sslpinning-and-certificates)
- Stalker: [advanced/stalker.md](advanced/stalker.md) / GOT hook: [advanced/gothook.md](advanced/gothook.md) / yahfa: [advanced/yahfa-and-art-hook.md](advanced/yahfa-and-art-hook.md) / detection bypass: [advanced/detection-bypass-snippets.md](advanced/detection-bypass-snippets.md)
- Memory/NativeFunction API details: [frida-api-reference.md](frida-api-reference.md)
