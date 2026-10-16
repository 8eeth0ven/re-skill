# Native 层 Hook 速查

> so 层基础 hook 点 + 常用工具函数。每个条目:什么时候用 + 完整代码。

## 一、基础函数

### 1.1 NewStringUTF(JNI 字符串生成)

什么时候用:看 so 里所有 JNI 字符串生成的地方(加密结果、拼接参数经常在这里露头)。在 libart.so 里搜符号再 attach。

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

### 1.2 dlsym(动态查函数地址)

这个函数是用来查询具体函数地址的,参数为 handle(so 文件基地址),函数名称,返回为这个函数的地址。我们静态注册的函数,native 层和 java 层联系起来的函数,就会经过这个,这个代码也可以被用来查找相关的静态注册的代码。

```javascript
function hook_dlsym(){
    // 获取dlsym函数的地址
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

### 1.3 dlopen / android_dlopen_ext(so 加载监控)

#### 第一种写法(低版本 dlopen + 高版本 android_dlopen_ext 都挂)

什么时候用:等目标 so 加载完再 inline hook 它的内部函数。

```javascript
//8.0以下所有的so加载都通过dlopen
function hook_dlopen() {
    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter: function (args) {
            this.call_hook = false;
            var so_name = ptr(args[0]).readCString();
            if (so_name.indexOf("libxx.so") >= 0) {
                console.log("dlopen:", ptr(args[0]).readCString());
                this.call_hook = true;//dlopen函数找到了
            }

        }, onLeave: function (retval) {
            if (this.call_hook) {//dlopen函数找到了就hook so
                inline_hook();
            }
        }
    });
    // 高版本Android系统使用android_dlopen_ext
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

#### 第二种写法(参数化 so 名)

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

注意:如果目标 so 的加载时机比脚本还早(attach 模式下已经加载完),dlopen hook 没用,改用 `waitForModule` 轮询或直接 `Process.findModuleByName` 判空,见 [高级/so与soinfo操作.md](高级/so与soinfo操作.md)。

### 1.4 open(文件访问监控)

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

### 1.5 初始化调用函数 hook(.init_xxx 场景)

对于一些在 .init_xxx 执行的代码,是在 dlopen 运行中执行的代码,就必须要找到在最开始使用的系统函数中找到系统调用然后进行 hook,类似于这个是在 open 的某个函数下 hook 的:

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

### 1.6 exit / kill(退出与杀进程)

hook 这个 exit 函数 kill 函数的。但是基本上没什么用,因为在 so 里面,可以通过系统调用,即 svc 0 这种命令,具体不清楚,但是也可以关闭当前进程。

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
            // 在这里可以修改 args 来改变行为
        },
        onLeave: function (retval) {
            console.log('kill returned: ' + retval.toInt32());
            // 在这里可以修改返回值
        }
    });
}
```

### 1.7 pthread_create(attach 版)

一般来说这个函数是 frida 检测的时候就创建一个线程,具体 hook 如下:

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

### 1.8 pthread_create(replace 版,NativeCallback 重写)

什么时候用:attach 只能看,replace 可以改行为(比如拒绝某 so 起线程)。

```javascript
function create_pthread_create() {
    const pthread_create_addr = Module.findExportByName(null, "pthread_create")
    const pthread_create = new NativeFunction(pthread_create_addr, "int", ["pointer", "pointer", "pointer", "pointer"]);
    return new NativeCallback((parg0, parg1, parg2, parg3) => {
        const module = Process.findModuleByAddress(parg2);
        const so_name = module.name;
        const baseAddr = module.base
        console.log("pthread_create", so_name, "0x" + parg2.sub(baseAddr).toString(16), "0x" + parg3.toString(16))
        // 成功的返回值是0
        return pthread_create(parg0, parg1, parg2, parg3)
    }, "int", ["pointer", "pointer", "pointer", "pointer"])
}


// 或者
function replace_thread() {
    var new_pthread_create = create_pthread_create()
    var pthread_create_addr = Module.findExportByName(null, "pthread_create")
    // 函数替换
    Interceptor.replace(pthread_create_addr, new_pthread_create);
}

replace_thread()
```

### 1.9 __pthread_start

```javascript
// Frida script to hook pthread_start
function hook__pthread_start() {
    // 查找 pthread_start 函数地址
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

### 1.10 clone 替换(指定 so 跳过线程创建)

什么时候用:检测线程是用 `clone` 而不是 `pthread_create` 起的(ptrace/反调试线程常见);把指定 so 的线程创建直接拦掉。

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

### 1.11 strstr / strcmp(字符串比较)

#### strstr

```javascript
function hook_strstr() {
    var strstr = Module.findExportByName(null, "strstr");
    console.log("strstr", strstr)
    null !== strstr && Interceptor.attach(strstr, {
        onEnter: function (e) {
            var haystack = e[0].readCString();
            var needle = e[1].readCString();
            // 上面两个都是字符串
        }, onLeave: function (e) {
            // 返回值0就是没有检测到
        }
    })
}
```

#### strcmp

```javascript
function hook_strcmp() {
    Interceptor.attach(Module.findExportByName(null, 'strcmp'), {
        onEnter: function (args) {
            // 获取 strcmp 的参数（两个字符串）
            var str1 = args[0].readUtf8String();
            var str2 = args[1].readUtf8String();
            // 输出调用 strcmp 时传入的两个字符串
            console.log('strcmp called with:');
            console.log('  str1: ' + str1);
            console.log('  str2: ' + str2);
        },
        onLeave: function (retval) {
            // 输出 strcmp 返回值
            console.log('strcmp returned: ' + retval.toInt32());
        }
    });
}
```

### 1.12 memcpy(抓代码段指令搬运)

什么时候用:壳把加密的指令块解密后 memcpy 回代码段,按「长度 4 + 源地址在 text 段」过滤可以抓到指令级 patch。

```javascript
 Interceptor.attach(Module.findExportByName("libc.so", "memcpy"), {
    onEnter: function (args) {
        this.dst = args[0];
        this.src = args[1];
        this.size = args[2].toInt32();
    },
    onLeave: function (retval) {
        // ARM64指令是4字节
        if (this.size === 4) {
            // 检查地址是否落在代码段
            if (textRange && (this.src.compare(textRange.base) >= 0 && this.src.compare(textRange.base.add(textRange.size)) < 0)) {
                console.log("可能是ARM64指令的memcpy:");

                console.log("复制地址: " + this.dst);
                console.log("源地址: " + this.src);
                console.log("复制位数大小: " + this.size);
                console.log("字节打印：")
                console.log(hexdump(this.dst, { offset: 0, length: this.size }));

                // 可以根据常见的ARM64指令模式进一步确认，比如分析前几个bit
                var instruction = Memory.readU32(this.dst);
                console.log("Instruction (hex): " + instruction.toString(16));
            }
        }
    }
});
```

### 1.13 memcmp(命中一次即改返回值并 detach)

这个例子同时演示了 Thumb 指针 `and(-2)` 对齐的用法:

```javascript
const l = Module.getExportByName("libc.so", "pthread_create")
// 地址对齐，其实默认就是对齐的
const i = l.and(-2)
// 如果这个是成功的
const r = Interceptor.attach(Module.getExportByName("libc.so", "memcmp"), {
    onEnter: function (e) {
        this.match = 0 === e[0].compare(i) || 0 === e[1].compare(i)
    }, onLeave: function (e) {
        // 销毁掉
        this.match && (e.replace(new NativePointer(0)), r.detach())
    }
});
```

### 1.14 RegisterNatives(动态注册定位)

动态注册的函数(JNI 动态绑定)都从这里过,一次拿到 类/方法/签名/函数地址/所在 so/偏移:

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

### 1.15 init_array(call_constructors)

hook 这个 call_constructors,这个 call_constructors 就是用来执行 so 初始化函数的,它会去执行 so 的初始化函数,在 dlopen 开始所执行的位置。

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
            // 此时还没有执行完成初始化函数
            // 这个时候就可以加载so了，可以在这个位置nop掉其他的东西
        },
        onLeave: function (retval) {
            if (this.match) {
                console.log("libDexHelper.so", "加载成功")
                const module = Process.findModuleByName("libDexHelper.so");
                // 执行结束初始化函数了，接下来会跑dlopen
            }
        }
    });
}
```

### 1.16 hook strstr 解决 frida 检测 anti

什么时候用:目标用 strstr 扫 frida 特征字符串。但是对于一些不使用 strstr 或者使用其他的就没有办法进行检测了。

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

更多内存级反检测(替换 libfrida-agent 特征、去 rwxp)见 [高级/检测绕过片段.md](高级/检测绕过片段.md) 与 [frida-API详解.md](frida-API详解.md)。

## 二、so 层功能

### 2.1 枚举全部 so 文件

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

### 2.2 打印 so 全部导入的函数

```javascript
const hooks = Module.load('/data/app/com.example.hookdemo-xMdClW3H4V5El06BIcGN0A==/lib/arm64/libhookdemo.so');
var Imports = hooks.enumerateImports();
for(var i = 0; i < Imports.length; i++) {
    //函数类型
    console.log("type:",Imports[i].type);
    //函数名称
    console.log("name:",Imports[i].name);
    //属于的模块
    console.log("module:",Imports[i].module);
    //函数地址
    console.log("address:",Imports[i].address);
 }
```

## 三、工具函数(Java/通用)

### 3.1 堆栈打印(ACCURATE / FUZZY)

native 里打印调用栈两种精度,`FUZZY` 兼容被内联/抹栈帧的场景:

```javascript
console.log('backtrace called from:\n' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');

console.log('backtrace called from:\n' + Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join('\n') + '\n');

Thread.currentContext();
```

### 3.2 getStackTraceString(Java 层堆栈一行打印)

```javascript
function getStackTraceString() {
    console.log(Java.use('android.util.Log')
        .getStackTraceString(Java.use('java.lang.Throwable')
            .$new()));
}
```

### 3.3 字节 utf8 打印

```javascript
function utf8Bytes(exampleBytes) {
    let StringClass = Java.use("java.lang.String");
    let CharsetClass = Java.use("java.nio.charset.Charset");
    let utf8Charset = CharsetClass.forName("UTF-8");
    return StringClass.$new(exampleBytes, utf8Charset);
}
```

### 3.4 map 转 json 打印(依赖目标带 gson)

```javascript
function maptoJson(map){
    var Gson = Java.use('com.google.gson.Gson').$new();
    return Gson.toJsonTree(map).getAsJsonObject();
}
```

### 3.5 dumpAllFieldValue(打印对象全部属性)

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

### 3.6 getFieldValue(获取对象单一属性)

```javascript
function getFieldValue(obj, className, fieldName) {
    try {
        var cls = Java.use(className).class; // 获取对象的类
        var field = cls.getDeclaredField(fieldName); // 获取指定字段
        field.setAccessible(true); // 设置字段为可访问
        return field.get(obj); // 获取字段值
    } catch (e) {
        console.error("Failed to get field: " + fieldName + ", Error: " + e);
        return null;
    }
}

Java.enumerateClassLoadersSync().forEach(classLoader => {
        const pathList = getFieldValue(classLoader, "dalvik.system.BaseDexClassLoader", "pathList")
})
```

### 3.7 打印全部的方法签名

```javascript
var methods = clazz.class.getDeclaredMethods();
for (var i = 0; i < methods.length; i++) {
    // 获取方法的名称和签名
    var methodName = methods[i].getName();
    var methodSignature = methods[i].toString(); // toString() 方法会返回方法的签名信息
    console.log("Method: " + methodName + ", Signature: " + methodSignature);
}
```

### 3.8 Instruction.parse(解析单条汇编)

一般来说正常 arm64 都是 4 个字节为一条指令:

```javascript
 Instruction.parse(ptr(地址))
```

直接看 hex 也可以:

```javascript
console.log(hexdump(ptr(地址), {
    length: 4,
    header: true,
    ansi: true
}))
```

`ptr` 把地址转换为指针:

```javascript
ptr(0x4cb54 + 0x700c113000)
```

### 3.9 Thumb 指令 and(-2) 注意事项

**注意 Thumb 指令需要 `and(-2)` 才可以正常使用 hexdump 还有 readArray 这些函数,但是 Instruction 不需要 and(-2)。**

实战例子参见上文 1.13 的 memcmp(先 `l.and(-2)` 再 compare)。此外:
- 判断地址是否在当前模块:

```javascript
const isModuleCode = baseFirstAddress.compare(base) >= 0 &&
baseFirstAddress.compare(base.add(size)) < 0;
```

### 3.10 重新写入指令(Arm64Writer)

nop/ret 函数化的完整版本(封装成 retFunc/nopFunc)另见 [高级/patch与内存操作.md](高级/patch与内存操作.md),此处为最小写法:

```javascript
Memory.protect(ptr(地址), 4, 'rwx');
// 使用 Arm64Writer 写入 'ret' 指令
var writer = new Arm64Writer(parg2);
writer.putRet();
writer.flush();
writer.dispose();
console.log("ret success");

// 写入nop指令
var writer = new Arm64Writer(parg2);
writer.putNop(); // 写入 nop 指令
writer.flush();  // 刷新写入到内存
console.log("ret success");
```

### 3.11 读取 DCB 数据(函数表项 → 模块/符号)

```javascript
const address = module.base.add(0xEA478);
// 使用 Memory.readU64 读取 64 位数据
const value = Memory.readU64(address);
// 打印模块和相关符号
const func_module = Process.findModuleByAddress(ptr(value))
console.log(func_module.name)
console.log(func_module.base)
const symbol = DebugSymbol.fromAddress(ptr(value));
console.log(symbol.name)
```

## 相关文档

- Java 层 hook 点:java层/ 目录 6 篇(网络与webview/加密与自吐/存储与系统/UI与跳转/字符串与JSON/sslpinning与证书)
- Stalker:[高级/stalker.md](高级/stalker.md) / GOT hook:[高级/gothook.md](高级/gothook.md) / yahfa:[高级/yahfa与arthook.md](高级/yahfa与arthook.md) / 检测绕过:[高级/检测绕过片段.md](高级/检测绕过片段.md)
- Memory/NativeFunction API 细节:[frida-API详解.md](frida-API详解.md)
