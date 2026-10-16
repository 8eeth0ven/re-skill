# frida 高级·yahfa 与 ART inline hook

> 主题:yahfa 加载 + ARTHookScripts(smali 级 inline hook)

## 四、yahfa 加载(frida 里跑另一个 hook 框架)

什么时候用:app 检测 frida 的 inline hook(trap 指令),换 yahfa 的 ArtMethod 入口替换来躲检测。思路:把 libyahfa.so + hook.dex 塞进 app 数据目录,frida 里 `Module.load` 加载 so、用 NativeFunction 包装 yahfa 的 JNI 导出函数,再按 HookInfo 的字段描述完成 hook。

### 4.1 导入 yahfa

```javascript
// 加载相关需要的so
var data_files_path = "/data/data/th.co.truemoney.wallet/files/"
var libdlfuncPathStr = data_files_path + "libdlfunc.so";
Module.load(libdlfuncPathStr)
var libyahfaPathStr = data_files_path + "libyahfa.so";
Module.load(libyahfaPathStr)
const module = Process.findModuleByName("libyahfa.so");

const _shouldVisiblyInit = new NativeFunction(
    module.findExportByName("Java_lab_galaxy_yahfa_HookMain_00024Utils_shouldVisiblyInit"),
    'bool',
    ['pointer', 'pointer']
);
const _getThread = new NativeFunction(
    module.findExportByName("Java_lab_galaxy_yahfa_HookMain_00024Utils_getThread"),
    'long',
    ['pointer', 'pointer']
);
const _visiblyInit = new NativeFunction(
    module.findExportByName("Java_lab_galaxy_yahfa_HookMain_00024Utils_visiblyInit"),
    'int',    // return value是一个int（如果C++层是int返回，Frida层也要对应int；如返回值是jint）
    ['pointer', 'pointer', 'long']
);
const _init = new NativeFunction(
    module.findExportByName("Java_lab_galaxy_yahfa_HookMain_init"),
    'void',   // 如果底层JNI定义是 `static void init(...)`，这里就用 'void'
    ['pointer', 'pointer', 'int']
);
const _findMethodNative = new NativeFunction(
    module.findExportByName("Java_lab_galaxy_yahfa_HookMain_findMethodNative"),
    'pointer', // JNI层返回的是 Object( Method/Constructor )
    ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']
);
const _backupAndHookNative = new NativeFunction(
    module.findExportByName("Java_lab_galaxy_yahfa_HookMain_backupAndHookNative"),
    'bool', // JNI层一般返回 boolean
    ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']
);
```

### 4.2 init(带 Android preview SDK 修正)

```javascript
export function init() {
    const VERSION = Java.use('android.os.Build$VERSION');
    let buildSdk = VERSION.SDK_INT.value;
    // Android 6.0+ (即 Build.VERSION_CODES.M=23) 才考虑 PREVIEW_SDK_INT
    if (buildSdk >= 23) {
        try {
            const previewSdkInt = VERSION.PREVIEW_SDK_INT.value;
            if (previewSdkInt > 0) {
                buildSdk += 1;
            }
        } catch (e) {
            // 忽略
        }
    }
    const env_ptr = Java.vm.getEnv().handle;
    // 调用我们在上面定义的 this.init(...)，而不是直接 init(buildSdk)
    _init(env_ptr, ptr(0), buildSdk);
    console.log(`[HookMain] Initialized with SDK version: ${buildSdk}`);
}
```

### 4.3 Utils 类

```javascript
class Utils {
    constructor(env) {
        // 在 Frida 中获取 Env，用于之后调用 NativeFunction
        this.env = env;
        this.env_ptr = this.env.handle;
        this.nullptr = ptr(0x0);
    }

    shouldVisiblyInit() {
        return _shouldVisiblyInit(this.env_ptr, this.nullptr);
    }

    getThread() {
        return _getThread(this.env_ptr, this.nullptr);
    }

    visiblyInit(thread) {
        return _visiblyInit(this.env_ptr, this.nullptr, thread);
    }

    initClass() {
        // 模拟 Java 中的 Utils.initClass()
        if (this.shouldVisiblyInit()) {
            const thread = this.getThread();
            return this.visiblyInit(thread);
        } else {
            return 0;
        }
    }
}
```

### 4.4 YahfaHook 完整类

```javascript
export class YahfaHook {
    constructor(env) {
        this.env = env
        this.env_ptr = this.env.handle;
        this.nullptr = ptr(0x0);
        this.utilsObj = new Utils(env);
    }

    backupAndHookNative(target, hook, backup) {
        return _backupAndHookNative(this.env_ptr, this.nullptr, target, hook, backup);
    }

    findMethodNative(cls, methodName, methodSig) {
        return _findMethodNative(this.env_ptr, this.nullptr, cls, methodName, methodSig);
    }

    doHookDefault(patchClassLoader, originClassLoader) {
        try {
            // 使用patchClassLoader加载HookInfo类
            const HookInfoClass = patchClassLoader.loadClass("lab.galaxy.yahfa.HookInfo");
            const HookInfo = Java.cast(HookInfoClass, Java.use('java.lang.Class'));
            // 获取hookItemNames字段
            const hookItemNamesField = HookInfo.getDeclaredField("hookItemNames");
            hookItemNamesField.setAccessible(true);
            const hookItemNames = hookItemNamesField.get(null);
            hookItemNames.forEach(hookItemName => {
                this.doHookItemDefault(patchClassLoader, hookItemName, originClassLoader);
            });
        } catch (e) {
            console.error(`[HookMain] doHookDefault exception: ${e}`);
        }
    }

    doHookItemDefault(patchClassLoader, hookItemName, originClassLoader) {
        try {
            console.log(`[HookMain] Start hooking with item ${hookItemName}`);
            // 加载hookItem类
            const HookItemClass = patchClassLoader.loadClass(hookItemName);
            const HookItem = Java.cast(HookItemClass, Java.use('java.lang.Class'));
            // 获取className, methodName, methodSig字段
            const classNameField = HookItem.getDeclaredField("className");
            classNameField.setAccessible(true);
            const className = classNameField.get(null);
            const methodNameField = HookItem.getDeclaredField("methodName");
            methodNameField.setAccessible(true);
            const methodName = methodNameField.get(null);
            const methodSigField = HookItem.getDeclaredField("methodSig");
            methodSigField.setAccessible(true);
            const methodSig = methodSigField.get(null);
            if (!className) {
                console.warn(`[HookMain] No target class. Skipping...`);
                return;
            }
            // 加载目标类
            const TargetClassClass = originClassLoader.loadClass(className);
            const TargetClass = Java.cast(TargetClassClass, Java.use('java.lang.Class'));
            // 检查是否为抽象类
            const Modifier = Java.use('java.lang.reflect.Modifier');
            if (Modifier.isAbstract(TargetClass.getModifiers())) {
                console.warn(`[HookMain] Hook may fail for abstract class: ${className}`);
            }
            // 查找hook和backup方法
            let hookMethod = null;
            let backupMethod = null;
            const declaredMethods = HookItem.getDeclaredMethods();
            for (let i = 0; i < declaredMethods.length; i++) {
                const method = declaredMethods[i];
                const methodNameStr = method.getName();
                const modifiers = method.getModifiers();
                if (methodNameStr === "hook" && Modifier.isStatic(modifiers)) {
                    hookMethod = method;
                } else if (methodNameStr === "backup" && Modifier.isStatic(modifiers)) {
                    backupMethod = method;
                }
            }
            if (!hookMethod) {
                console.error(`[HookMain] Cannot find hook for ${methodName}`);
                return;
            }
            // 初始化类
            if (this.utilsObj.initClass() !== 0) {
                console.error(`[HookMain] Utils.initClass failed`);
                return;
            }
            // 查找并备份&钩取
            this.findAndBackupAndHook(TargetClass, methodName, methodSig, hookMethod, backupMethod);
        } catch (e) {
            console.error(`[HookMain] doHookItemDefault exception: ${e}`);
        }
    }

    findAndBackupAndHook(targetClass, methodName, methodSig, hook, backup) {
        let method;
        try {
            method = this.findMethodNative(targetClass, methodName.$h, methodSig.$h)
        } catch (e) {
            console.error(`[HookMain] findMethodNative exception: ${e}`);
            return;
        }
        try {
            this.backupAndHook(method, hook, backup);
        } catch (e) {
            console.error(`[HookMain] findAndBackupAndHook exception: ${e}`);
        }
    }

    backupAndHook(target, hook, backup) {
        if (target.isNull()) {
            throw new Error("null target method");
        }
        if (!hook) {
            throw new Error("null hook method");
        }

        const Modifier = Java.use('java.lang.reflect.Modifier');
        const hookModifiers = hook.getModifiers();
        if (!Modifier.isStatic(hookModifiers)) {
            throw new Error(`Hook must be a static method: ${hook}`);
        }
        // 检查方法兼容性
        this.checkCompatibleMethods(target, hook, "Original", "Hook");

        if (backup) {
            const backupModifiers = backup.getModifiers();
            if (!Modifier.isStatic(backupModifiers)) {
                throw new Error(`Backup must be a static method: ${backup}`);
            }
            this.checkCompatibleMethods(target, backup, "Original", "Backup");
        }

        // 调用原生备份和钩取方法
        const success = this.backupAndHookNative(
            target,
            hook.$h,
            backup ? backup.$h : this.nullptr
        );
        if (!success) {
            throw new Error(`Failed to hook ${hook.getName()}`);
        }

        console.log(`[HookMain] Successfully hooked method ${hook.getName()}`);
    }

    findMethod(cls, methodName, methodSig) {
        if (cls == null) {
            throw new Error("null class");
        }
        if (methodName == null) {
            throw new Error("null method name");
        }
        if (methodSig == null) {
            throw new Error("null method signature");
        }
        return this.findMethodNative(cls, methodName, methodSig);
    }

    findAndHook(targetClass, methodName, methodSig, hook) {
        this.hook(this.findMethod(targetClass, methodName, methodSig), hook);
    }

    hook(target, hook) {
        this.backupAndHook(target, hook, this.nullptr)
    }

    checkCompatibleMethods(originalPtr, replacementMethod, originalName, replacementName) {
        const Modifier = Java.use('java.lang.reflect.Modifier');
        const Method = Java.use('java.lang.reflect.Method');
        const Constructor = Java.use('java.lang.reflect.Constructor');

        // 1) original 可能是 Method 或 Constructor，在纯 JS 层并不知道其具体类型，只能尝试 cast
        let originalMethodObj;
        let originalConstructorObj;
        try {
            originalMethodObj = Java.cast(originalPtr, Method);
        } catch (e) {
            // 不是 Method
        }
        if (originalMethodObj === null) {
            try {
                originalConstructorObj = Java.cast(originalPtr, Constructor);
            } catch (e) {
            }
        }

        if (!originalMethodObj && !originalConstructorObj) {
            throw new Error("Type of target method is wrong (neither Method nor Constructor).");
        }
        let originalParams = [];
        if (originalMethodObj) {
            originalParams = originalMethodObj.getParameterTypes();
        } else {
            originalParams = originalConstructorObj.getParameterTypes();
        }

        let replacementParams = replacementMethod.getParameterTypes();

        if (originalMethodObj && !Modifier.isStatic(originalMethodObj.getModifiers())) {
            const declaringClass = originalMethodObj.getDeclaringClass();
            originalParams = [declaringClass].concat(originalParams);
        } else if (originalConstructorObj) {
            const declaringClass = originalConstructorObj.getDeclaringClass();
            originalParams = [declaringClass].concat(originalParams);
        }

        if (!Modifier.isStatic(replacementMethod.getModifiers())) {
            const declaringClass = replacementMethod.getDeclaringClass();
            replacementParams = [declaringClass].concat(replacementParams);
        }

        if (originalMethodObj) {
            const origRet = originalMethodObj.getReturnType();
            const repRet = replacementMethod.getReturnType();
            if (!repRet.isAssignableFrom(origRet)) {
                throw new Error(
                    `Incompatible return types. ${originalName}: ${origRet}, ` +
                    `${replacementName}: ${repRet}`
                );
            }
        } else {
            const repRet = replacementMethod.getReturnType();
            if (repRet.getName() === "void") {
                throw new Error(
                    `Incompatible return types. <init>: V, ${replacementName}: ${repRet}`
                );
            }
        }

        if (originalParams.length !== replacementParams.length) {
            throw new Error(
                `Number of arguments don't match. ` +
                `${originalName}: ${originalParams.length}, ` +
                `${replacementName}: ${replacementParams.length}`
            );
        }

        for (let i = 0; i < originalParams.length; i++) {
            if (!replacementParams[i].isAssignableFrom(originalParams[i])) {
                const origParamName = originalParams[i].getName();
                const repParamName = replacementParams[i].getName();
                throw new Error(
                    `Incompatible argument #${i}: ` +
                    `${originalName}: ${origParamName}, ` +
                    `${replacementName}: ${repParamName}`
                );
            }
        }
    }
}
```

配合 [../03-脱壳dump/dex脱壳.md](../../03-脱壳dump/dex脱壳.md) 的 loadDex 把 hook.dex 用 patchClassLoader 载入,即完成「加载 apk + hook」的整链。


---

## ARTHookScripts:smali 级 inline hook(ShadowFrame 机制)

> ARTHookScripts 的定位:突破 frida `Java.use` 只能 hook **方法入口**的限制,做到 Java 方法**体内任意一条 smali 指令处**的观察与改值——等效于「免调试器的方法内断点」。环境限定 Android 10(Pixel XL/AOSP,QP1A.191005.007.A3)+ frida 16.7.x(结构体偏移硬编码;repo 已修 Frida 17 兼容)。

### 1. 为什么 `Java.use` 做不到方法内 hook

frida 的 Java 层 hook 是**入口替换**:把目标 ArtMethod 的 entry point 换成跳板,方法一被调用就整体转到 JS 回调。它拿不到「方法执行到第 N 条字节码」这个粒度——回调发生在方法开始之前,方法体内部中间状态(局部变量在第 10 行被加密成什么、第 25 行的分支走向)全都在 ART 解释器/编译代码内部演进,JS 侧插不进手。要看方法内部,传统只有三条路:下断点跑 jdwp(对抗环境基本没戏)、改 smali 重打包(破坏签名、动静大)、或像 ARTHookScripts 这样——**直接改内存里正在被解释执行的字节码**。

### 2. 核心思路:字节码替换 + 寄存器现场操纵

整条链(方向:被 hook 方法 → JS → 写回):

```
目标方法第 N 条字节码
   │ 原地替换为 invoke-static Lbridge;.hook(IJ...)V   ← 覆盖写,原指令先存起来
   ▼
ART 解释器执行到这条 invoke-static
   ▼
调用 Java.registerClass 注册的 bridge 类静态方法
   (frida 注册的是 native java method → nativeFunctionCallback → 进 JS)
   ▼
JS 回调里:沿当前线程 Thread → ManagedStack 取「上级 fragment」
   → 拿到 caller(=被 hook 方法)的 ShadowFrame
   ▼
从 ShadowFrame.VRegs 读出 hook 点的寄存器现场(参数/局部变量值)
   ▼
JS 手动解释执行被覆盖的那条原指令(move/iget/add-int...)
   ▼
SetVReg 把结果写回 caller 的 ShadowFrame 寄存器组(即改上一帧的值)
   ▼
返回后 caller 继续解释后续字节码——原指令"像被执行过一样"
```

### 3. `Java.registerClass` 怎么当跳板

bridge 类是运行时用 `Java.registerClass` 造出来的静态方法载体。frida 对 registerClass 的 native method 实现走 `nativeFunctionCallback`:Java 侧一调,参数就封送进 JS 回调。ARTHookScripts 把覆盖指令写成对它的 `invoke-static`,并把**现场信息编码进参数**(寄存器号、原始值按指令需求转 int/long/对象引用传过去),JS 侧即拿到完整上下文。要点:

- invoke-static 的寄存器分配要自己算——smali 的 35c 指令格式只给 4 个寄存器槽(加范围版 3rc),传不完就打包;
- bridge 方法签名要宽进严出:`hook(I)V`/`hook(J)V`/`hook(Ljava/lang/Object;)V` 按原指令操作数类型分派;
- **原字节码必须先 dump 保存**,JS 侧解释执行的就是它。

### 4. ART 内部:ManagedStack → ShadowFrame → 寄存器

AOSP 源码定位(读 master 分支对得上):

- **`art/runtime/stack.h`——`ManagedStack`**:每个 `art::Thread` 挂一条,`PushShadowFrame()/PopShadowFrame()` 把解释器帧(`ShadowFrame` 段)和 native/compiled 帧(`QuickFrame` 段)串成一条栈遍历链。JS 回调发生时,**当前帧是 bridge 方法,上一段 fragment 就是被 hook 方法**——沿 ManagedStack 回溯一级即得。
- **`art/runtime/interpreter/shadow_frame.h`——`ShadowFrame`**:解释器里一个 Java 方法的完整执行上下文。关键字段:`ArtMethod* method_`(是谁)、`dex_pc`(执行到哪条)、`link_`(caller 帧链)、**VRegs 虚拟寄存器数组**——smali 的 v0..vN 就存在这里(解释器布局把 vregs 与引用数组分开放,引用要给 GC 扫)。所谓「读现场/改值」,就是 `GetVReg()/SetVReg()` 打在这上面。
- **`art/runtime/interpreter/interpreter_common.cc`**:解释器主循环 `Execute(ShadowFrame&,...)` 从 ShadowFrame 取指执行;解释器与编译代码互跳走 `ArtInterpreterToCompiledCodeBridge`。

「手动执行覆盖字节码」的含义:JS 侧用移植的迷你解释逻辑(或项目第五思路里的完整自定义解释器)模拟主循环对那**一条**指令的解释,效果与 ART 自己执行它等价,然后把结果写回 VRegs。**为什么不改完 dex_pc 直接让 ART 接着跑**:被覆盖的指令已经不在内存里了(被 invoke-static 顶掉),必须由 JS 代跑;代跑完 caller 从下一条继续,天然无缝。

### 5. 前置条件与坑

- **必须禁 oat**:AOT/JIT 编译过的方法直接跑机器码,线程上只有 QuickFrame、寄存器躺在真实 CPU 寄存器里,字节码替换形同虚设。禁用后方法回落解释器,ShadowFrame 才存在。
- **dex cache 处理**:防止 ART 因缓存/重编译把改过的字节码冲掉。
- **偏移硬编码**:`ShadowFrame`/`ArtMethod` 字段偏移随 Android 版本漂移——这是项目锁 Android 10 的根因,换版本要重对偏移(或走其「自定义 smali 解释器」模式换兼容性)。
- **GC 安全**:往 VRegs 写对象引用时走 SetVRegReference 一类入口,别裸写指针。

### 6. 能干什么

- **抽取壳**:逐条观察方法体指令在解密过程中如何被还原/搬运;
- **风控对抗**:在函数中途篡改校验中间值(入口 hook 改不了执行到一半的局部变量);
- **算法验证**:只关心第 N 行之后的状态时,免掉整套单步调试。

配套 API:`pathToArtMethod("com.x.Y.z").showSmali()` 先 dump 方法 smali 定位要 hook 的指令位置,`getFunctionBoundary(addr)` 辅助边界识别。工具横评与版本矩阵见《../../05-工具矩阵/动态与hook框架.md》第九节。


## 相关文档

- Java 层 hook 速查:../java层/ 目录 6 篇
