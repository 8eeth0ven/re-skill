# frida advanced · yahfa and ART inline hook

> Topic: yahfa loading + ARTHookScripts (smali-level inline hook)

## 4. Loading yahfa (running another hook framework inside frida)

When to use: the app detects frida's inline hooks (trap instructions), so you switch to yahfa's ArtMethod entry-point replacement to evade the detection. Approach: push libyahfa.so + hook.dex into the app's data directory, load the so from frida via `Module.load`, wrap yahfa's JNI exported functions with NativeFunction, then complete the hook following the HookInfo field descriptions.

### 4.1 Importing yahfa

```javascript
// Load the required shared libraries
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
    'int',    // Integer return type; it must match the C++/JNI return type, for example jint
    ['pointer', 'pointer', 'long']
);
const _init = new NativeFunction(
    module.findExportByName("Java_lab_galaxy_yahfa_HookMain_init"),
    'void',   // Use 'void' when the underlying JNI declaration is static void init(...)
    ['pointer', 'pointer', 'int']
);
const _findMethodNative = new NativeFunction(
    module.findExportByName("Java_lab_galaxy_yahfa_HookMain_findMethodNative"),
    'pointer', // The JNI layer returns an Object (Method or Constructor)
    ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']
);
const _backupAndHookNative = new NativeFunction(
    module.findExportByName("Java_lab_galaxy_yahfa_HookMain_backupAndHookNative"),
    'bool', // The JNI layer normally returns a boolean
    ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']
);
```

### 4.2 init (with the Android preview SDK correction)

```javascript
export function init() {
    const VERSION = Java.use('android.os.Build$VERSION');
    let buildSdk = VERSION.SDK_INT.value;
    // PREVIEW_SDK_INT applies only on Android 6.0+ (Build.VERSION_CODES.M = 23)
    if (buildSdk >= 23) {
        try {
            const previewSdkInt = VERSION.PREVIEW_SDK_INT.value;
            if (previewSdkInt > 0) {
                buildSdk += 1;
            }
        } catch (e) {
            // Ignore this lookup failure
        }
    }
    const env_ptr = Java.vm.getEnv().handle;
    // Call this.init(...) defined above rather than directly calling init(buildSdk)
    _init(env_ptr, ptr(0), buildSdk);
    console.log(`[HookMain] Initialized with SDK version: ${buildSdk}`);
}
```

### 4.3 The Utils class

```javascript
class Utils {
    constructor(env) {
        // Obtain the Frida JNI Env for subsequent NativeFunction calls
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
        // Reproduce Utils.initClass() from the Java implementation
        if (this.shouldVisiblyInit()) {
            const thread = this.getThread();
            return this.visiblyInit(thread);
        } else {
            return 0;
        }
    }
}
```

### 4.4 The full YahfaHook class

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
            // Load HookInfo through patchClassLoader
            const HookInfoClass = patchClassLoader.loadClass("lab.galaxy.yahfa.HookInfo");
            const HookInfo = Java.cast(HookInfoClass, Java.use('java.lang.Class'));
            // Read the hookItemNames field
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
            // Load the hookItem class
            const HookItemClass = patchClassLoader.loadClass(hookItemName);
            const HookItem = Java.cast(HookItemClass, Java.use('java.lang.Class'));
            // Read the className, methodName, and methodSig fields
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
            // Load the target class
            const TargetClassClass = originClassLoader.loadClass(className);
            const TargetClass = Java.cast(TargetClassClass, Java.use('java.lang.Class'));
            // Check whether the target is abstract
            const Modifier = Java.use('java.lang.reflect.Modifier');
            if (Modifier.isAbstract(TargetClass.getModifiers())) {
                console.warn(`[HookMain] Hook may fail for abstract class: ${className}`);
            }
            // Locate the hook and backup methods
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
            // Initialize the class
            if (this.utilsObj.initClass() !== 0) {
                console.error(`[HookMain] Utils.initClass failed`);
                return;
            }
            // Locate the method, create its backup, and install the hook
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
        // Check method compatibility
        this.checkCompatibleMethods(target, hook, "Original", "Hook");

        if (backup) {
            const backupModifiers = backup.getModifiers();
            if (!Modifier.isStatic(backupModifiers)) {
                throw new Error(`Backup must be a static method: ${backup}`);
            }
            this.checkCompatibleMethods(target, backup, "Original", "Backup");
        }

        // Call the native backup-and-hook method
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

        // 1) original may be a Method or Constructor; plain JS must try the appropriate cast
        let originalMethodObj;
        let originalConstructorObj;
        try {
            originalMethodObj = Java.cast(originalPtr, Method);
        } catch (e) {
            // Not a Method
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

Combined with loadDex from [dex-unpacking.md](../../03-unpacking/dex-unpacking.md) to load hook.dex via patchClassLoader, this completes the full "load apk + hook" chain.


---

## ARTHookScripts: smali-level inline hook (the ShadowFrame mechanism)

> What ARTHookScripts is for: it breaks through the limitation that frida `Java.use` can only hook **method entries**, achieving observation and value modification **at any single smali instruction inside a Java method body** — the equivalent of an in-method breakpoint without a debugger. The environment is pinned to Android 10 (Pixel XL/AOSP, QP1A.191005.007.A3) + frida 16.7.x (struct offsets are hardcoded; the repo has already fixed Frida 17 compatibility).

### 1. Why `Java.use` cannot hook inside a method

frida's Java-layer hook is **entry replacement**: the target ArtMethod's entry point is swapped for a trampoline, and the moment the method is called, execution transfers wholesale into the JS callback. It cannot get "the method has executed up to the N-th bytecode" granularity — the callback fires before the method even starts, and all intermediate state inside the method body (what a local variable got encrypted into at line 10, which way the branch at line 25 goes) evolves inside the ART interpreter/compiled code, out of reach of the JS side. To see inside a method there were traditionally only three routes: set breakpoints and drive jdwp (mostly hopeless in adversarial environments), patch smali and repackage (breaks the signature, very noisy), or do what ARTHookScripts does — **directly modify the bytecode currently being interpreted in memory**.

### 2. Core idea: bytecode replacement + register-state manipulation

The whole chain (direction: hooked method → JS → write-back):

```
Bytecode instruction N of the target method
   | Replace in place with invoke-static Lbridge;.hook(IJ...)V; save the overwritten instruction first
   ▼
The ART interpreter reaches this invoke-static
   ▼
Call the bridge class's static method registered through Java.registerClass
   (Frida registers a native Java method -> nativeFunctionCallback -> JS)
   ▼
In the JS callback: current Thread -> ManagedStack -> parent fragment
   -> obtain the caller's ShadowFrame (the caller is the hooked method)
   ▼
Read the hook-point register state, including arguments and locals, from ShadowFrame.VRegs
   ▼
Interpret the overwritten instruction manually in JS (move/iget/add-int...)
   ▼
SetVReg writes the result into the caller's ShadowFrame registers, modifying the previous frame
   ▼
Return; the caller interprets subsequent bytecode as though the original instruction had executed
```

### 3. How `Java.registerClass` serves as the trampoline

The bridge class is a static-method carrier built at runtime with `Java.registerClass`. frida's native-method implementation for registerClass goes through `nativeFunctionCallback`: as soon as the Java side calls it, the arguments are marshaled into the JS callback. ARTHookScripts writes the overwrite instruction as an `invoke-static` against it and **encodes the live state into the arguments** (register numbers; raw values passed as int/long/object references per what the instruction needs), so the JS side receives the complete context. Key points:

- Register allocation for the invoke-static must be computed by hand — smali's 35c instruction format only gives 4 register slots (plus the range form 3rc); if that is not enough, pack the values;
- The bridge method signature must be permissive on inputs: `hook(I)V`/`hook(J)V`/`hook(Ljava/lang/Object;)V` dispatch on the operand type of the original instruction;
- **The original bytecode must be dumped and saved first** — it is exactly what the JS side interprets and executes.

### 4. Inside ART: ManagedStack → ShadowFrame → registers

Where it sits in the AOSP source (matches when reading the master branch):

- **`art/runtime/stack.h` — `ManagedStack`**: one hangs off every `art::Thread`; `PushShadowFrame()/PopShadowFrame()` chains interpreter frames (the `ShadowFrame` segments) and native/compiled frames (the `QuickFrame` segments) into a single stack-traversal chain. When the JS callback fires, **the current frame is the bridge method and the previous fragment is the hooked method** — walk one level back along the ManagedStack and you have it.
- **`art/runtime/interpreter/shadow_frame.h` — `ShadowFrame`**: the complete execution context of one Java method in the interpreter. Key fields: `ArtMethod* method_` (who it is), `dex_pc` (which instruction has been reached), `link_` (the caller-frame chain), and the **VRegs virtual register array** — this is where smali's v0..vN live (the interpreter layout keeps vregs and the reference array separate, because references must be scannable by GC). "Reading the live state / changing values" means calling `GetVReg()/SetVReg()` on this.
- **`art/runtime/interpreter/interpreter_common.cc`**: the interpreter main loop `Execute(ShadowFrame&,...)` fetches and executes instructions from the ShadowFrame; jumps between the interpreter and compiled code go through `ArtInterpreterToCompiledCodeBridge`.

What "manually executing the overwritten bytecode" means: the JS side uses a ported mini-interpretation routine (or the full custom interpreter from the project's fifth approach) to emulate the main loop's interpretation of that **one** instruction, with an effect equivalent to ART executing it itself, then writes the result back into VRegs. **Why not just patch dex_pc and let ART carry on**: the overwritten instruction is no longer in memory (it was displaced by the invoke-static), so JS must run it on ART's behalf; once that is done the caller continues from the next instruction — naturally seamless.

### 5. Prerequisites and pitfalls

- **oat must be disabled**: AOT/JIT-compiled methods run machine code directly — the thread only has QuickFrames and the registers sit in real CPU registers, so bytecode replacement is pointless. Once disabled, methods fall back to the interpreter, and only then do ShadowFrames exist.
- **dex cache handling**: keep ART from flushing your modified bytecode away through caching/recompilation.
- **Hardcoded offsets**: `ShadowFrame`/`ArtMethod` field offsets drift across Android versions — this is the root reason the project is pinned to Android 10; on another version the offsets must be redone (or use its "custom smali interpreter" mode to trade for compatibility).
- **GC safety**: when writing object references into VRegs, go through an entry point like SetVRegReference — never write bare pointers.

### 6. What it can do

- **Extraction packers**: watch instruction by instruction how a method body's instructions get restored/relocated during decryption;
- **Risk-control combat**: tamper with intermediate check values mid-function (an entry hook cannot modify a local variable that is already half-executed);
- **Algorithm verification**: when you only care about the state after line N, skip the whole single-stepping session.

Companion APIs: `pathToArtMethod("com.x.Y.z").showSmali()` first dumps the method's smali to locate the instruction position to hook, and `getFunctionBoundary(addr)` helps identify boundaries. For the tool comparison and version matrix see section 9 of [dynamic-hook-frameworks.md](../../05-toolbox/dynamic-hook-frameworks.md).


## Related docs

- Java-layer hook quick reference: the 6 docs in ../java-layer/
