# frida API 详解

> Process / Memory / NativeFunction / CModule / Java 包装对象 / ArtMethod / 主动调用,配可复制示例。

## 一、Process

### 1.1 获取全部已经加载的 so 文件

```javascript
Process.enumerateModules()
```

### 1.2 获取当前线程的 id

```javascript
Process.getCurrentThreadId();
```

### 1.3 查找模块

```javascript
Process.findModuleByName("libc.so")
```

输出示例:

```
[MI 6::com.chehejia.oc.m01 ]-> Process.findModuleByName("libc.so")
{
    "base": "0x7b38cc8000",
    "name": "libc.so",
    "path": "/system/lib64/libc.so",
    "size": 1163264
}
```

### 1.4 获取模块基础地址

```javascript
const baseAddress = Process.getBaseAddress("libc.so")
baseAddress.add(0x111)
```

### 1.5 16 进制地址转换为 frida 指针

```javascript
ptr("0x111")
```

### 1.6 找到堆地址

```javascript
var heap = Process.getHeap();
var startAddress = heap.start; // 假设我们从堆的起始地址开始
var size = heap.size;
var endAddress = startAddress.add(size);
```

## 二、Memory

Frida 的 Memory 对象是用于访问和操作进程内存的核心组件。

### 2.1 内存读取和写入

从指定地址读取字节数组:

```javascript
var data = Memory.readByteArray(ptr("0x12345678"), 16);
```

从指定地址读取 UTF-8 字符串:

```javascript
var str = Memory.readUtf8String(ptr("0x12345678"));
```

将字节数组写入指定地址:

```javascript
Memory.writeByteArray(ptr("0x12345678"), new Uint8Array([0x01, 0x02, 0x03]));
```

将 UTF-8 字符串写入指定地址:

```javascript
Memory.writeUtf8String(ptr("0x12345678"), "Hello, world!");
```

### 2.2 内存权限

设置指定地址范围的内存权限。常用的权限包括 `'r'`(只读)、`'w'`(可写)和 `'x'`(可执行):

```javascript
Memory.protect(ptr("0x12345678"), 4096, 'rwx');
```

### 2.3 内存分配和释放

分配指定大小的内存并返回起始地址:

```javascript
var ptr = Memory.alloc(1024); // 分配1KB
```

分配内存并存储指定的 UTF-8 字符串:

```javascript
var ptr = Memory.allocUtf8String("Hello, Frida!");
```

释放之前分配的内存。注意并不是所有的分配都可以手动释放,特别是如果使用了系统的分配方法:

```javascript
Memory.free(ptr);
```

### 2.4 内存扫描(特征码搜索)

`Memory.scan(address, size, pattern, options)`:在指定地址范围内搜索特定模式,支持 `??` 通配:

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

### 2.5 指针读写

```javascript
var ptrValue = Memory.readPointer(ptr("0x12345678"));
```

```javascript
Memory.writePointer(ptr("0x12345678"), ptr("0x87654321"));
```

### 2.6 读写特定数据类型

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

### 2.7 结构体操作

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

### 2.8 patchCode(指令 patch)

写 ret 指令(`0xC0 0x03 0x5F 0xD6` 是 arm64 的 ret):

```javascript
Memory.patchCode(parg2, 4, function (code) {
    var retBytes = new Uint8Array([0xC0, 0x03, 0x5F, 0xD6]);
    code.writeByteArray(retBytes);
});
```

写 NOP 指令:

```javascript
Memory.patchCode(address, 4, function (code) {
    // 创建一个字节数组，包含 NOP 指令的机器码
    code.writeByteArray([0x1F, 0x20, 0x03, 0xD5]);  // 将字节数组写入目标内存
});
```

### 2.9 内存操作综合示例

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

具体的内存操作可以让 gpt 写。

### 2.10 内存 antifrida(把 libfrida-agent 特征改掉)

什么时候用:壳在内存里扫描 `libfrida-agent` 字符串时,把特征替换成 `libwzdnb-agent`。

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

注意 `Interceptor.detachAll()` 一旦调用,当前脚本全部 hook 立即失效,所以只在收尾阶段用。

## 三、NativeFunction / NativeCallback

签名:

```javascript
new NativeFunction(address, returnType, argTypes[, abi])
```

### 3.1 支持的类型表

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

### 3.2 配合 Interceptor.replace

```javascript
Interceptor.replace(module.base.add(0x4421C), new NativeCallback(function () {
    console.log("开始")
    return 1;  // 返回值对应 'int64' 返回类型(需要 64 位整数字面量时可用 1n,即 BigInt)
}, 'int64', ["int64"]));
```

### 3.3 字符串也是 pointer

字符串也是使用的 pointer,如果是 jni,除了基础类型都是需要设置 pointer 的:

```javascript
const _init = new NativeFunction(
    module.findExportByName("Java_lab_galaxy_yahfa_HookMain_init"),
    'void',   // 如果底层JNI定义是 `static void init(...)`，这里就用 'void'
    ['pointer', 'pointer', 'int']
);
```

## 四、CModule

C 代码直接内嵌,性能敏感的事件回调(onEvent)用它:

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

配合 Stalker 的 events 用法见 [高级/stalker.md](高级/stalker.md)。

## 五、Java 包装对象

### 5.1 基础操作

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

### 5.2 frida 创建 java 类(registerClass)

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

### 5.3 创建 java 数组 / 构建数组

```javascript
const StringClassArray = Java.array("Ljava.lang.Class;", [StringClass.class, StringClass.class]);
```

```javascript
var classArray = Java.array("Ljava.lang.Class;", [StringClass.class, StringClass.class]);
```

### 5.4 拿到 jclass / jobject($h)

使用属性 `$h` 就可以,`$h` 似乎就是 handle 属性:

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

### 5.5 class-module($l)

得到 spec:

```javascript
var log = Java.use("android.util.Log");
log.w.overload('java.lang.String', 'java.lang.String').implementation = function (tag, message) {
    console.log("log.w: ", tag, message);
    return this.w(tag, message);
}

console.log(log.$l)
console.log(log.$l.find("w"))
```

这个 `$l` 就是正常的 class-module。

### 5.6 方法 spec(_p)

得到函数细节内容:

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

枚举进程里全部 classLoader,加壳 app 必用(探测哪个 loader 能加载目标类后 `Java.classFactory.loader = classLoader` 切换)。完整实战代码见 [java层/加密与自吐.md](java层/加密与自吐.md) 的「加壳的 hook」与 [../03-脱壳dump/dex脱壳.md](../03-脱壳dump/dex脱壳.md)。

### 5.8 setHiddenApiExemptions(隐藏 API 豁免)

什么时候用:调用非 SDK 接口(P 引入的黑名单限制)时先豁免,再清 Parcel 的 creators 缓存:

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

## 六、ArtMethod

### 6.1 getArtMethodSpec(偏移自动探测)

得到偏移量 quick_code 和其他的。原理:拿 `android/os/Process.getElapsedCpuTime` 这个已知 native 静态方法的 ArtMethod,在 0~64 字节里按特征(jniCode 落在 libandroid_runtime 区间、accessFlags 匹配)扫出 jniCode/accessFlags 偏移:

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

### 6.2 得到 artmethod(_p[3])

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

### 6.3 解析 artmethod

先要解决 artmethod 相关的偏移量才行(由 6.1 探测,例如):

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

对于 flag 的解释可能麻烦不简单。

### 6.4 getDexFile(从 ArtMethod 拿 DexFile)

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

## 七、Java.classFactory._getType().fromJni 主动调用

可能有用的脚本要点(frida 特殊使用):

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

## 八、读文件 / maps 读取

### 8.1 java 版

`readFile` 的完整实现见上文 [2.10 内存 antifrida](#210-内存-antifrida把-libfrida-agent-特征改掉) 段(该处 replaceFrida 依赖同一函数,此处不重复)。调用方式:

```javascript
readFile("/proc/self/maps")
```

### 8.2 so 版(NativeFunction 读,不依赖 Java 层)

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

## 相关文档

- 启动与工具链:[环境与快速开始.md](环境与快速开始.md)
- Java 层 hook 速查:java层/ 目录 6 篇;Native 层:[native层hook速查.md](native层hook速查.md)
- Stalker:[高级/stalker.md](高级/stalker.md)、GOT hook:[高级/gothook.md](高级/gothook.md)、yahfa:[高级/yahfa与arthook.md](高级/yahfa与arthook.md)、检测绕过:[高级/检测绕过片段.md](高级/检测绕过片段.md)
