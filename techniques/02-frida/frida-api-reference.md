# frida API Reference

> Process / Memory / NativeFunction / CModule / Java wrapper objects / ArtMethod / proactive invocation, with copy-paste-ready examples.

## 1. Process

### 1.1 Get all already-loaded so files

```javascript
Process.enumerateModules()
```

### 1.2 Get the current thread id

```javascript
Process.getCurrentThreadId();
```

### 1.3 Find a module

```javascript
Process.findModuleByName("libc.so")
```

Example output:

```
[MI 6::com.chehejia.oc.m01 ]-> Process.findModuleByName("libc.so")
{
    "base": "0x7b38cc8000",
    "name": "libc.so",
    "path": "/system/lib64/libc.so",
    "size": 1163264
}
```

### 1.4 Get a module's base address

```javascript
const baseAddress = Process.getBaseAddress("libc.so")
baseAddress.add(0x111)
```

### 1.5 Convert a hex address to a frida pointer

```javascript
ptr("0x111")
```

### 1.6 Locate the heap

```javascript
var heap = Process.getHeap();
var startAddress = heap.start; // 假设我们从堆的起始地址开始
var size = heap.size;
var endAddress = startAddress.add(size);
```

## 2. Memory

Frida's Memory object is the core component for accessing and manipulating process memory.

### 2.1 Memory read and write

Read a byte array from a given address:

```javascript
var data = Memory.readByteArray(ptr("0x12345678"), 16);
```

Read a UTF-8 string from a given address:

```javascript
var str = Memory.readUtf8String(ptr("0x12345678"));
```

Write a byte array to a given address:

```javascript
Memory.writeByteArray(ptr("0x12345678"), new Uint8Array([0x01, 0x02, 0x03]));
```

Write a UTF-8 string to a given address:

```javascript
Memory.writeUtf8String(ptr("0x12345678"), "Hello, world!");
```

### 2.2 Memory permissions

Set memory permissions for a given address range. Common permissions include `'r'` (read-only), `'w'` (writable), and `'x'` (executable):

```javascript
Memory.protect(ptr("0x12345678"), 4096, 'rwx');
```

### 2.3 Memory allocation and release

Allocate memory of a given size and return the start address:

```javascript
var ptr = Memory.alloc(1024); // 分配1KB
```

Allocate memory and store a given UTF-8 string in it:

```javascript
var ptr = Memory.allocUtf8String("Hello, Frida!");
```

Free previously allocated memory. Note that not every allocation can be freed manually, especially if a system allocator was used:

```javascript
Memory.free(ptr);
```

### 2.4 Memory scanning (signature search)

`Memory.scan(address, size, pattern, options)`: search for a specific pattern within a given address range; `??` wildcards are supported:

```javascript
// 进行内存搜索
// frida的hex
const searchValue = "66 72 69 64 61"
const startAddress = ptr(0x7583c0c000)
const endAddress = ptr(0x7583d1e000)
Memory.scan(startAddress, endAddress.sub(startAddress).toInt32(), searchValue, {
    onMatch: function(address, size) {
        console.log("找到数据！地址：" + address);
        // 你可以在这里修改数据，例如：
    },
    onComplete: function() {
        console.log("搜索完成。");
    }
});

// 特殊匹配手法
Memory.scan(ptr("0x10000000"), 0x10000, "00 01 02 03 ?? ?? 06 07 08 09 ?? ?? ?? ?? 0e 0f", {
    onMatch: function(address) {
        console.log("找到数据！地址：" + address);
    },
    onComplete: function() {
        console.log("搜索完成。");
    }
});
```

### 2.5 Pointer read and write

```javascript
var ptrValue = Memory.readPointer(ptr("0x12345678"));
```

```javascript
Memory.writePointer(ptr("0x12345678"), ptr("0x87654321"));
```

### 2.6 Read and write specific data types

```javascript
var intValue = Memory.readInt(ptr("0x12345678"));
```

```javascript
Memory.writeInt(ptr("0x12345678"), 42);
```

```javascript
var floatValue = Memory.readFloat(ptr("0x12345678"));
```

```javascript
Memory.writeFloat(ptr("0x12345678"), 3.14);
```

### 2.7 Struct operations

```javascript
var layout = {
    field1: 'int',
    field2: 'pointer'
};
var struct = Memory.readStruct(ptr("0x12345678"), layout);
```

```javascript
Memory.writeStruct(ptr("0x12345678"), layout, { field1: 100, field2: ptr("0x87654321") });
```

### 2.8 patchCode (instruction patching)

Write a ret instruction (`0xC0 0x03 0x5F 0xD6` is arm64 ret):

```javascript
Memory.patchCode(parg2, 4, function (code) {
    var retBytes = new Uint8Array([0xC0, 0x03, 0x5F, 0xD6]);
    code.writeByteArray(retBytes);
});
```

Write a NOP instruction:

```javascript
Memory.patchCode(address, 4, function (code) {
    // 创建一个字节数组，包含 NOP 指令的机器码
    code.writeByteArray([0x1F, 0x20, 0x03, 0xD5]);  // 将字节数组写入目标内存
});
```

### 2.9 Comprehensive memory operation example

```javascript
// 创建一个字符串
var r = Memory.allocUtf8String("muyang");
console.log(Memory.readUtf8String(r))

// 创建一个r内存
var newaddress = Memory.alloc(10);
// 赋值过去
Memory.copy(newaddress,r,10);
console.log(hexdump(newaddress));
console.log(hexdump(r,{
    offset:0,
    length:10,
    header:true,
    ansi:true
}))

var arr = [ 0x6d,0x75,0x79,0x61,0x6e,0x67];
//申请一个新的内存空间 返回指针 大小是arr.length(改名r2,避免与上面var r重复声明报错)
const r2 = Memory.alloc(arr.length);
//将arr数组写入r2地址中
Memory.writeByteArray(r2,arr);
//输出
console.log(hexdump(r2, {
    offset: 0,
    length: arr.length,
    header: true,
    ansi: false
}));

var buffer = Memory.readByteArray(r2,arr.length);
console.log(buffer)
```

For specific memory operations you can just have GPT write them.

### 2.10 Memory antifrida (replace the libfrida-agent signature)

When to use: when the packer scans memory for the `libfrida-agent` string, replace the signature with `libwzdnb-agent`.

```javascript
function fridaReplace(startAddress, endAddress) {
    const searchValue = "6c 69 62 66 72 69 64 61 2d 61 67 65 6e 74"; // "libfrida-agent" 的十六进制表示
    let matchedAddresses = []; // 用于存储匹配的地址
    Memory.scan(startAddress, endAddress.sub(startAddress).toInt32(), searchValue, {
        onMatch: function (address, size) {
            console.log("找到数据！地址：" + address);
            matchedAddresses.push(address); // 将匹配的地址存储到数组中
        },
        onComplete: function () {
            console.log("搜索完成，共找到 " + matchedAddresses.length + " 个匹配项。");
            // 遍历所有匹配的地址并进行修改
            matchedAddresses.forEach(function (address) {
                try {
                    // 计算所在的页地址，并将权限设置为可写
                    const size = searchValue.split(" ").length
                    Memory.protect(address, size, 'rwx');
                    // 修改 "frida" 为 "wzdnb"
                    const replacement = "6c 69 62 77 7a 64 6e 62 2d 61 67 65 6e 74"; // "libwzdnb-agent" 的十六进制表示
                    const bytes = replacement.split(" ").map(byte => parseInt(byte, 16));
                    Memory.writeByteArray(address, bytes);
                    console.log("已将 'frida' 替换为 'wzdnb'，地址：" + address);
                    // 恢复原始内存权限（可根据需要设置合适的权限）
                    Memory.protect(address, size, 'r--');
                } catch (error) {
                    // console.error("修改地址 " + address + " 时出错：" + error);
                }
            });
        }
    });
}

function readFile(fileName) {
    console.log("> Reading file: ", fileName);
    const JString = Java.use("java.lang.String");
    const Files = Java.use("java.nio.file.Files");
    const Paths = Java.use("java.nio.file.Paths");
    const URI = Java.use("java.net.URI");

    const pathName = "file://" + fileName;
    const path = Paths.get(URI.create(pathName));
    const fileBytes = Files.readAllBytes(path);
    return JString.$new(fileBytes);
}

function replaceFrida() {
    const data = readFile("/proc/self/maps");
    // 马上去除全部hook
    Interceptor.detachAll();
    // 解析出来我们想要的数据位置
    let num = 0;
    let startAddress, endAddress;
    data.split("\n").forEach(line => {
        if (line.indexOf("/memfd") !== -1) {
            console.log(line);
            const match = line.match(/^([0-9a-f]+)-([0-9a-f]+)/);
            if (num === 0) {
                startAddress = ptr(parseInt(match[1], 16));
                endAddress = ptr(parseInt(match[2], 16));
            }
            num += 1;
        }
    })
    if (startAddress && endAddress) {
        fridaReplace(startAddress, endAddress);
        console.log("检测成功");
    }
}

replaceFrida();
```

Note that once `Interceptor.detachAll()` is called, every hook of the current script stops working immediately, so only use it at the wrap-up stage.

## 3. NativeFunction / NativeCallback

Signature:

```javascript
new NativeFunction(address, returnType, argTypes[, abi])
```

### 3.1 Supported types table

```
● Supported Types
  ○ void
  ○ pointer
  ○ int
  ○ uint
  ○ long
  ○ ulong
  ○ char
  ○ uchar
  ○ float
  ○ double
  ○ int8
  ○ uint8
  ○ int16
  ○ uint16
  ○ int32
  ○ uint32
  ○ int64
  ○ uint64
```

### 3.2 Combined with Interceptor.replace

```javascript
Interceptor.replace(module.base.add(0x4421C), new NativeCallback(function () {
    console.log("开始")
    return 1;  // 返回值对应 'int64' 返回类型(需要 64 位整数字面量时可用 1n,即 BigInt)
}, 'int64', ["int64"]));
```

### 3.3 Strings are pointers too

Strings are also passed as pointer; with JNI, everything besides the primitive types needs to be declared as pointer:

```javascript
const _init = new NativeFunction(
    module.findExportByName("Java_lab_galaxy_yahfa_HookMain_init"),
    'void',   // 如果底层JNI定义是 `static void init(...)`，这里就用 'void'
    ['pointer', 'pointer', 'int']
);
```

## 4. CModule

Embed C code directly; use it for performance-sensitive event callbacks (onEvent):

```javascript
const cm = new CModule(`
#include <gum/gumstalker.h>
#include <stdio.h>

void test(){
  console.log("成功");
}
`);
// 使用 NativeFunction 来调用该函数指针
const testFunc = new NativeFunction(cm.test, "void", []);
// 调用 test 函数
testFunc()
```

For usage combined with Stalker events see [advanced/stalker.md](advanced/stalker.md).

## 5. Java Wrapper Objects

### 5.1 Basic operations

```javascript
// 获取 Java 类的引用
var ExampleClass = Java.use('com.example.ExampleClass');
// 使用 new 关键字来创建 ExampleClass 的一个实例
var exampleObject = ExampleClass.$new();
// 使用对象进行一些操作，例如调用其方法
exampleObject.someMethod();

// 强制转换，obj转String
var castValue = Java.cast(obj, Java.use("java.lang.String"))

// 获取对象属性内容，得到的这个对象可以使用.value
// 也可以直接执行函数，是a.函数，而不是a.value.函数
obj.a.value
```

### 5.2 Create a Java class in frida (registerClass)

```javascript
const Hook_Log_e = Java.registerClass({
    name: 'lab.galaxy.yahfa.demoApp.Hook_Log_e', // 类名
    methods: {
        // 重写 Log.e 方法
        hook: {
            returnType: 'int',
            argumentTypes: ['java.lang.String', 'java.lang.String'],
            // 方法体实现
            implementation: function (tag, msg) {
                // 模拟 Log.w
                Java.use('android.util.Log').w("HookTest", "in Log.e(): " + tag + ", " + msg);

                // 返回模拟值
                return 1; // 返回 int 类型，模拟 Log.e 方法的行为
            }
        },
        // 备份方法，模拟 Log.e 逻辑不应出现在这里的警告
        backup: {
            returnType: 'int',
            argumentTypes: ['java.lang.String', 'java.lang.String'],
            implementation: function (tag, msg) {
                Java.use('android.util.Log').w("HookTest", "Log.e() should not be here");
                return 1; // 返回1来模拟 Log.e 方法的默认行为
            }
        }
    }
});
```

### 5.3 Create Java arrays / build arrays

```javascript
const StringClassArray = Java.array("Ljava.lang.Class;", [StringClass.class, StringClass.class]);
```

```javascript
var classArray = Java.array("Ljava.lang.Class;", [StringClass.class, StringClass.class]);
```

### 5.4 Get jclass / jobject ($h)

Just use the `$h` property; `$h` appears to be the handle property:

```javascript
const Log = Java.use("android.util.Log");
const logClassPtr = Log.class.$h;
const methodName = StringClass.$new("w")
const methodSig = StringClass.$new("(Ljava/lang/String;Ljava/lang/String;)I")
const methodNamePtr = methodName.$h
const methodSigPtr = methodSig.$h
const env = Java.vm.getEnv()
const env_ptr = env.handle
```

### 5.5 class-module ($l)

Get the spec:

```javascript
var log = Java.use("android.util.Log");
log.w.overload('java.lang.String', 'java.lang.String').implementation = function (tag, message) {
    console.log("log.w: ", tag, message);
    return this.w(tag, message);
}

console.log(log.$l)
console.log(log.$l.find("w"))
```

This `$l` is the regular class-module.

### 5.6 Method spec (_p)

Get the function details:

```javascript
var log = Java.use("android.util.Log");
log.w.overload('java.lang.String', 'java.lang.String').implementation = function (tag, message) {
    console.log("log.w: ", tag, message);
    return this.w(tag, message);
}
console.log(log.w.overload('java.lang.String', 'java.lang.String')._p)

log.w.overloads.forEach(function (method) {
    console.log(method._p)
})
```

### 5.7 enumerateClassLoadersSync

Enumerate every classLoader in the process; a must for packed apps (probe which loader can load the target class, then switch with `Java.classFactory.loader = classLoader`). For complete working code see the "hooking packed apps" section of [java-layer/crypto-and-self-dump.md](java-layer/crypto-and-self-dump.md) and [../03-unpacking/dex-unpacking.md](../03-unpacking/dex-unpacking.md).

### 5.8 setHiddenApiExemptions (hidden API exemption)

When to use: before calling non-SDK interfaces (the blocklist restriction introduced in P), exempt them first, then clear Parcel's creators cache:

```javascript
function VMRuntime_clear() {
       let VMRuntime = Java.use("dalvik.system.VMRuntime")
       VMRuntime.THE_ONE.value.setHiddenApiExemptions(["Landroid/os/Parcel;", "Landroid/content/pm", "Landroid/app"])
       var Parcel = Java.use("android.os.Parcel");
       if (Parcel.mCreators) {
           Parcel.mCreators.value.clear()
           console.log("mCreators 清空")
       }
       if (Parcel.sPairedCreators) {
           Parcel.sPairedCreators.value.clear()
           console.log("sPairedCreators 清空")
       }
   }
```

## 6. ArtMethod

### 6.1 getArtMethodSpec (automatic offset detection)

Obtain the quick_code offset and the rest. Principle: take the ArtMethod of the known native static method `android/os/Process.getElapsedCpuTime` and scan the first 0-64 bytes by signature (jniCode landing inside the libandroid_runtime range, accessFlags matching) to work out the jniCode/accessFlags offsets:

```javascript
function getArtMethodSpec(vm) {
    const nativeFunctionOptions = {
        exceptions: 'propagate'
    };
    const systemPropertyGet = new NativeFunction(Module.getExportByName('libc.so', '__system_property_get'), 'int',
        ['pointer', 'pointer'],
        nativeFunctionOptions);

    function getAndroidSystemProperty(name) {
        const PROP_VALUE_MAX = 92;
        const buf = Memory.alloc(PROP_VALUE_MAX);
        systemPropertyGet(Memory.allocUtf8String(name), buf);
        return buf.readUtf8String();
    }


    const pointerSize = Process.pointerSize;
    const kAccPublic = 0x0001;
    const kAccStatic = 0x0008;
    const kAccFinal = 0x0010;
    const kAccNative = 0x0100;
    const kAccFastInterpreterToInterpreterInvoke = 0x40000000;
    const kAccNterpInvokeFastPathFlag = 0x00200000;
    const kAccPublicApi = 0x10000000;
    let spec;

    vm.perform(env => {
        const process = env.findClass('android/os/Process');
        const getElapsedCpuTime = env.getStaticMethodId(process, 'getElapsedCpuTime', '()J');
        env.deleteLocalRef(process);

        const runtimeModule = Process.getModuleByName('libandroid_runtime.so');
        const runtimeStart = runtimeModule.base;
        const runtimeEnd = runtimeStart.add(runtimeModule.size);

        const apiLevel = parseInt(getAndroidSystemProperty('ro.build.version.sdk'), 10);

        const entrypointFieldSize = (apiLevel <= 21) ? 8 : pointerSize;

        const expectedAccessFlags = kAccPublic | kAccStatic | kAccFinal | kAccNative;
        const relevantAccessFlagsMask = ~(kAccFastInterpreterToInterpreterInvoke | kAccPublicApi | kAccNterpInvokeFastPathFlag) >>> 0;

        let jniCodeOffset = null;
        let accessFlagsOffset = null;
        let remaining = 2;
        for (let offset = 0; offset !== 64 && remaining !== 0; offset += 4) {
            const field = getElapsedCpuTime.add(offset);

            if (jniCodeOffset === null) {
                const address = field.readPointer();
                if (address.compare(runtimeStart) >= 0 && address.compare(runtimeEnd) < 0) {
                    jniCodeOffset = offset;
                    remaining--;
                }
            }

            if (accessFlagsOffset === null) {
                const flags = field.readU32();
                if ((flags & relevantAccessFlagsMask) === expectedAccessFlags) {
                    accessFlagsOffset = offset;
                    remaining--;
                }
            }
        }

        if (remaining !== 0) {
            throw new Error('Unable to determine ArtMethod field offsets');
        }

        const quickCodeOffset = jniCodeOffset + entrypointFieldSize;

        const size = (apiLevel <= 21) ? (quickCodeOffset + 32) : (quickCodeOffset + pointerSize);

        spec = {
            size,
            offset: {
                jniCode: jniCodeOffset,
                quickCode: quickCodeOffset,
                accessFlags: accessFlagsOffset
            }
        };

    });

    return spec;
}

const vm = Java.vm
console.log(JSON.stringify(getArtMethodSpec(vm)))
```

### 6.2 Get the artmethod (_p[3])

```javascript
var log = Java.use("android.util.Log");
log.w.overload('java.lang.String', 'java.lang.String').implementation = function (tag, message) {
    console.log("log.w: ", tag, message);
    return this.w(tag, message);
}

log.w.overloads.forEach(function (method) {
    console.log(method._p[3])
})
```

### 6.3 Parse the artmethod

You must first work out the artmethod-related offsets (detected by 6.1, for example):

```
// {"size":40,"offset":{"jniCode":24,"quickCode":32,"accessFlags":4}}
```

```javascript
var log = Java.use("android.util.Log");
log.w.overloads.forEach(function (method) {
    const point = method._p[3]
    console.log("[data_] ", point.add(24).readPointer())
    console.log("[quic_code] ", point.add(32).readPointer())
    console.log("[flag] ", point.add(4).readU32())
})
```

Interpreting the flag can be non-trivial.

### 6.4 getDexFile (get the DexFile from an ArtMethod)

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

## 7. Proactive Invocation via Java.classFactory._getType().fromJni

Script notes that may come in handy (special frida usage):

```text
// frida主动调用
// method.call(method, MyApplication, context) ==> 解决receiver是undefined
// $borrowClassHandle是一个函数，返回的是这个函数的类的jni指针值，也就是jclass
// $getHandle也是一个函数，在类里面会返回这个函数的实例对象的jni指针值
// 从jni属性转换为frida js类型，libanon.base.add(0x8A9D8).readPointer()这个的值就是正常的JNI值
//  var MyApplicationObj = Java.classFactory._getType('com.tyme.digital.ProtectedMyApplication').fromJni(libanon.base.add(0x8A9D8).readPointer());
// 如果报错了$borrowClassHandle，把全部属性的$borrowClassHandle打出来看看就清楚了
// 如果出现没有这个的名字，不知道应该使用什么类名字
//         console.log(Instrumentation.$l.list())
```

```javascript
function hook_java() {
    Java.perform(() => {
        var MyApplication = Java.use("com/tyme/digital/MyApplication");
        var MyApplicationObj = Java.classFactory._getType('com.tyme.digital.ProtectedMyApplication').fromJni(libanon.base.add(0x8A9D8).readPointer());
        var context = MyApplicationObj.getBaseContext()
        var Instrumentation = Java.use("android.app.Instrumentation")
        var method = Instrumentation.newApplication.overload("java.lang.Class", "android.content.Context")
        console.log(method.$borrowClassHandle)
        console.log(Instrumentation.$l.list())
        var result = method.call(method, MyApplication, context)
        console.log(result)
    })
}

// 如果需要更加精细化测试回调，可以参考test2的代码
```

## 8. Reading Files / Reading maps

### 8.1 Java version

The full implementation of `readFile` is in section [2.10 Memory antifrida](#210-memory-antifrida-replace-the-libfrida-agent-signature) above (replaceFrida there depends on the same function, so it is not repeated here). How to call it:

```javascript
readFile("/proc/self/maps")
```

### 8.2 so version (read via NativeFunction, no dependency on the Java layer)

```javascript
function readMaps() {
    var libc = Module.load("libc.so");
    const O_RDONLY = 0;  // 只读模式
    const MAPS_PATH = "/proc/self/maps";
    const BUFFER_SIZE = 1024;

// 使用 NativeFunction 创建 open、read 和 close 函数
    var open = new NativeFunction(libc.findExportByName("open"), "int", ["pointer", "int"]);
    var read = new NativeFunction(libc.findExportByName("read"), "ssize_t", ["int", "pointer", "size_t"]);
    var close = new NativeFunction(libc.findExportByName("close"), "int", ["int"]);
    // 将路径字符串转换为指针
    var pathPtr = Memory.allocUtf8String(MAPS_PATH);
    var fd = open(pathPtr, O_RDONLY);
    if (fd < 0) {
        console.log("Failed to open /proc/self/maps");
        return;
    }
    // 创建一个空的字符串来存储读取的数据
    var content = "";
    // 分配缓冲区来存储读取的数据
    var buffer = Memory.alloc(BUFFER_SIZE);
    // 循环读取文件内容，直到文件结束
    var bytesRead;
    do {
        bytesRead = read(fd, buffer, BUFFER_SIZE);
        if (bytesRead > 0) {
            // 读取的内容转换为字符串，并拼接到 content
            var chunk = buffer.readCString();
            content += chunk;
        }
    } while (bytesRead > 0);  // 直到没有更多数据可以读取
    // 关闭文件
    close(fd);
    return content;
}
```

## Related Docs

- Startup and toolchain: [env-and-quickstart.md](env-and-quickstart.md)
- Java-layer hook quick reference: the 6 docs in the java-layer/ directory; native layer: [native-hook-cheatsheet.md](native-hook-cheatsheet.md)
- Stalker: [advanced/stalker.md](advanced/stalker.md), GOT hook: [advanced/gothook.md](advanced/gothook.md), yahfa: [advanced/yahfa-and-art-hook.md](advanced/yahfa-and-art-hook.md), detection bypass: [advanced/detection-bypass-snippets.md](advanced/detection-bypass-snippets.md)
