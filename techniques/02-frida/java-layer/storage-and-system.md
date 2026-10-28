# Java Layer Hook: Storage and System

> Topics: storage + detection countermeasures + package info and signatures

## 6. Storage

### 6.1 SharedPreferences

SharedPreferences (sp) is a hash-table-like store: it can store data, retrieve data, and persist strings and similar values. Hook the internal storage API to print whatever gets stored:

```javascript
var sp = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
sp.putBoolean.overload('java.lang.String', 'boolean').implementation = function(arg1,arg2){
    console.log("[SharedPreferencesImpl ] putBoolean -> key: "+arg1+" = "+arg2);
    return this.putBoolean(arg1,arg2);
}

sp.putString.overload('java.lang.String', 'java.lang.String').implementation = function(arg1,arg2){
    console.log("[SharedPreferencesImpl] putString -> key: "+arg1+" = "+arg2);
    return this.putString(arg1,arg2);
}

sp.putInt.overload('java.lang.String', 'int').implementation = function(arg1,arg2){
    console.log("[SharedPreferencesImpl] putInt -> key: "+arg1+" = "+arg2);
    return this.putInt(arg1,arg2);
}

sp.putFloat.overload('java.lang.String', 'float').implementation = function(arg1,arg2){
    console.log("[SharedPreferencesImpl] putFloat -> key: "+arg1+" = "+arg2);
    return this.putFloat(arg1,arg2);
}

sp.putLong.overload('java.lang.String', 'long').implementation = function(arg1,arg2){
    console.log("[SharedPreferencesImpl] putLong -> key: "+arg1+" = "+arg2);
    return this.putLong(arg1,arg2);
}
```

### 6.2 ContentResolver (cross-app data transfer)

Hook the API for data transfer between apps to print the URI being passed and the concrete fields:

```javascript
var content = Java.use("android.content.ContentResolver");
content.insert.overload("android.net.Uri","android.content.ContentValues").implementation = function(arg1,arg2){
    console.log("[ContentResolver] *insert -> Uri: "+arg1+"  Values: "+arg2);
    return this.insert(arg1,arg2);
}

content.delete.overload("android.net.Uri","java.lang.String","[Ljava.lang.String;").implementation = function(arg1,arg2,arg3){
    console.log("[ContentResolver] *delete -> Uri: "+arg1+"\n  -> arg2: "+arg2+"\n  -> arg3: "+arg3);
    return this.delete(arg1,arg2,arg3);
}

content.update.overload('android.net.Uri','android.content.ContentValues','java.lang.String','[Ljava.lang.String;').implementation = function(arg1,arg2,arg3,arg4){
    console.log("[ContentResolver] *update -> Uri: "+arg1+"\n  -> arg2: "+arg2+"\n  -> arg3: "+arg3+"\n  -> arg4: "+arg4);
    return this.update(arg1,arg2,arg3,arg4);
}

content.query.overload('android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle', 'android.os.CancellationSignal').implementation = function(arg1,arg2,arg3,arg4){
    console.log("[ContentResolver] *query -> Uri: "+arg1+"\n  -> arg2: "+arg2+"\n  -> arg3: "+arg3+"\n  -> arg4: "+arg4);
    return this.query(arg1,arg2,arg3,arg4);
}

content.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function(arg1,arg2,arg3,arg4,arg5){
    console.log("[ContentResolver] *query -> Uri: "+arg1+"\n  -> arg2: "+arg2+"\n  -> arg3: "+arg3+"\n  -> arg4: "+arg4+"\n  -> arg5: "+arg5);
    return this.query(arg1,arg2,arg3,arg4,arg5);
}

content.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal').implementation = function(arg1,arg2,arg3,arg4,arg5,arg6){
    console.log("[ContentResolver] *query -> Uri: "+arg1+"\n  -> arg2: "+arg2+"\n  -> arg3: "+arg3+"\n  -> arg4: "+arg4+"\n  -> arg5: "+arg5+"\n arg6: "+arg6);
    return this.query(arg1,arg2,arg3,arg4,arg5,arg6);
}
```


---

## 8. Detection Countermeasures

### 8.1 Stack hooking (when the target is anti-hook)

Strings that may be checked (packers scan the stack for these words): `Hooker lsposed sandhook hook virtual lody`.

```javascript
var Thread = Java.use('java.lang.Thread');
// Hook the instance method getStackTrace()
Thread.getStackTrace.implementation = function () {
    // Call the original method to obtain the stack trace
    var stackTrace = this.getStackTrace.apply(this, arguments);
    var value = ""
    for (var i = 0; i < stackTrace.length; i++) {
        var element = stackTrace[i];
        value += '  at ' + element.getClassName() +
            '.' + element.getMethodName() +
            ' (' + element.getFileName() +
            ':' + element.getLineNumber() + ')' + "\n"
    }
    if (value.indexOf("HotdogConductor") !== -1) {
        // Print the current thread information
        console.log('[+] getStackTrace() called from thread: ' + this.getName());
        // Print the stack trace
        console.log('Stack trace elements:');
        console.log(value)
    }
    return stackTrace; // Return the original result
};
```

Filtering (wipe the specified frames from the stack to pass anti-debug detection):

```javascript
// Extract the shared filtering logic
function filterElement(element) {
    // Normalize the filename and line number to match the target string exactly
    const line = '  at ' + element.getClassName() +
        '.' + element.getMethodName() +
        ' (' + element.getFileName() +
        ':' + element.getLineNumber() + ')' + "\n";
    // Match "buildResult(Native Method)" exactly
    return line.indexOf("buildResult(Native Method)") === -1;
}

// Hook Thread.getStackTrace()
var Thread = Java.use('java.lang.Thread');
Thread.getStackTrace.implementation = function () {
    const stackTrace = this.getStackTrace.apply(this, arguments);
    return stackTrace.filter(element => filterElement(element)); // Apply the filter directly
};
// Hook Throwable.getStackTrace() as well if stacks obtained through Throwable remain unfiltered
var Throwable = Java.use('java.lang.Throwable');
Throwable.getStackTrace.implementation = function () {
    const stackTrace = this.getStackTrace.apply(this, arguments);
    return stackTrace.filter(element => filterElement(element));
};
```

### 8.2 Defeating screen-recording protection

```javascript
var Window = Java.use("android.view.Window")
Window.setFlags.implementation = function (flags, mask) {
    this.setFlags(flags & ~8192, mask);
};
Window.addFlags.implementation = function (flags) {
    if (flags !== 8192) {
        this.addFlags(flags);
    }
};
var SurfaceView = Java.use("android.view.SurfaceView")
SurfaceView.setSecure.implementation = function (isSecure) {
};
```

### 8.3 Hiding package names (bypassing the "xx tool is installed" check)

```javascript
var PackageManager = Java.use("android.app.ApplicationPackageManager");
var appsToHide = [
    "com.xiaojia.xgj",
    "com.termux"
]
let ArrayList = Java.use("java.util.ArrayList")
PackageManager["getInstalledPackages"].implementation = function (i4) {
    console.log(`AndroidUtils.getInstalledPackages is called: i4=${i4}`);
    let result = this["getInstalledPackages"](i4).toArray()
    let filteredList = ArrayList.$new()
    // Iterate through the original list
    for (var i = 0; i < result.length; i++) {
        var pkgInfo = Java.cast(result[i], Java.use("android.content.pm.PackageInfo"));
        var pkgName = pkgInfo.packageName.value;
        // Check whether the package is in the hidden-package list
        if (appsToHide.indexOf(pkgName) === -1) {
            // Keep packages absent from the hidden-package list
            filteredList.add(pkgInfo);
        } else {
            console.log("解决检测包名")
        }
    }
    return filteredList;
};
```

### 8.4 Accessibility detection bypass

```javascript
Java.enumerateClassLoadersSync().forEach(classLoader => {
    try {
        if (classLoader.loadClass("android.view.accessibility.AccessibilityManager")) {
            Java.classFactory.loader = classLoader
        }
    } catch (e) {
        return
    }

    var AccessibilityManager = Java.use('android.view.accessibility.AccessibilityManager');
    let ArrayList = Java.use("java.util.ArrayList");
    AccessibilityManager["getInstalledAccessibilityServiceList"].implementation = function () {
        return ArrayList.$new();
    };

    AccessibilityManager["getEnabledAccessibilityServiceList"].implementation = function (i) {
        return ArrayList.$new();
    };

    var SettingsSecure = Java.use("android.provider.Settings$Secure");
    SettingsSecure.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (contentResolver, name) {
        var result = this.getString(contentResolver, name);
        if (name === "enabled_accessibility_services") {
            result = "";
        }
        return result;
    }
})
```

### 8.5 oaid

```javascript
var IdProviderImpl = Java.use("com.android.id.impl.IdProviderImpl");
IdProviderImpl["getOAID"].implementation = function (context) {
    console.log("调用了")
    const result = this.getOAID(context)
    console.log(result)
    return result
}
```

### 8.6 USB debugging detection bypass (Settings$Global / Secure getInt)

The full `usb_anti()` function (AccessibilityManager + Global/Secure getInt in one go) is in the "USB debugging detection bypass" section of [../advanced/detection-bypass-snippets.md](../advanced/detection-bypass-snippets.md) (the native-layer `__system_property_get` trick of setting `init.svc.adbd` to stopped is also in that doc).

## 9. Package Info and Signatures

### 9.1 Hook package info (getPackageInfo)

```javascript
function hook_package_info() {
    // Resolve the PackageManager class
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    
    // Hook getPackageInfo
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (packageName, flags) {
        console.log("[+] getPackageInfo called");
        console.log("[+] packageName: " + packageName);
        console.log("[+] flags: " + flags);
        
        // Call the original method
        var result = this.getPackageInfo(packageName, flags);
        
        // Print the returned PackageInfo
        console.log("[+] PackageInfo:");
        console.log("    packageName: " + result.packageName.value);
        console.log("    versionName: " + result.versionName.value);
        console.log("    versionCode: " + result.versionCode.value);
        console.log("    firstInstallTime: " + result.firstInstallTime.value);
        console.log("    lastUpdateTime: " + result.lastUpdateTime.value);
        
        return result;
    };
}
```

### 9.2 Hook the signature (hook_pkms, frida-side forgery)

When to use: when signature verification fails after repackaging, replace the signatures returned by `getPackageInfo` with the original package's signature (when flags include 64 = GET_SIGNATURES).

```javascript
function hook_pkms() {
    // Resolve the PackageManager class
    Java.enumerateClassLoadersSync().forEach(classLoader => {
        try {
            if (classLoader.loadClass("android.app.ApplicationPackageManager")) {
                Java.classFactory.loader = classLoader
                var PackageManager = Java.use("android.app.ApplicationPackageManager");
                var Base64 = Java.use("android.util.Base64");
                var sign = "MIICAzCCAWygAwIBAgIEUYH/FzANBgkqhkiG9w0BAQUFADBGMQ4wDAYDVQQHEwVIYW5vaTETMBEGA1UEChMKVmlldGluQmFuazEMMAoGA1UECxMDSVRDMREwDwYDVQQDEwhBbiBIb2FuZzAeFw0xMzA1MDIwNTUyMjNaFw0zODA0MjYwNTUyMjNaMEYxDjAMBgNVBAcTBUhhbm9pMRMwEQYDVQQKEwpWaWV0aW5CYW5rMQwwCgYDVQQLEwNJVEMxETAPBgNVBAMTCEFuIEhvYW5nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgI2mpcANCSIwwe/WLTBVG/IUEpM+ULVU+Ga9qwafkPxlaTNoK7kbo6ZTgj6h+E84oOnjZxIWGj6qOqx+mGgutw4hchqD13sW04AZksR6sAKBQOVpu6t4T8VPPxi0NaMjBwyUc6z/0CmrFHBwvwf12oJOthYo3urjVGReOoF51AQIDAQABMA0GCSqGSIb3DQEBBQUAA4GBADJLDyHC3rmeEweTcVoa5oWABEIM1QqwvtYK9Pz/1P4a/fXTESOm5eUjDmiUKAg1yNRwbt0988wMkSVOpyNgr5U5dmLyPXVZpBAP3vUyQh9h6rzjsmK+iSQO/YznRyzVvQgvV4eDUkD4uYecueHoVFX6rZkD8xtYftdInsOrr+ur"
                var Signature = Java.use("android.content.pm.Signature");
                // Hook getPackageInfo
                PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (packageName, flags) {
                    var result = this.getPackageInfo(packageName, flags);
                    if ((Number(flags) & 64) != 0 && packageName.indexOf("com.vietinbank.ipay") !== -1){
                        console.log("[pkms]", packageName, flags)
                        console.log(flags)
                        result.signatures.value[0] = Signature.$new(Base64.decode(sign, 2));
                    }
                    return result;
                };
            }
        } catch (e) {

        }
    })
    console.log("pkms hook成功")
}
```

### 9.3 PMS proxy approach (Xposed/Java layer, principle reference)

Intercepting only `getPackageInfo` with frida may not be enough; the more thorough route is to swap `sPackageManager` inside ActivityThread for a dynamic proxy at the Java layer, uniformly taking over all signature-related calls (getPackageInfo / getPackageInfoVersioned / checkSignatures / hasSigningCertificate):

```java
package com.zj.hookpms;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Log;

public class ServiceManagerWraper {

    public final static String ZJ = "ZJ595";

    public static void hookPMS(Context context, String signed, String appPkgName, int hashCode) {
        try {
            // Obtain the global ActivityThread instance
            Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
            Method currentActivityThreadMethod =
                    activityThreadClass.getDeclaredMethod("currentActivityThread");
            Object currentActivityThread = currentActivityThreadMethod.invoke(null);
            // Read ActivityThread's original sPackageManager
            Field sPackageManagerField = activityThreadClass.getDeclaredField("sPackageManager");
            sPackageManagerField.setAccessible(true);
            Object sPackageManager = sPackageManagerField.get(currentActivityThread);
            // Prepare a proxy object to replace the original object
            Class<?> iPackageManagerInterface = Class.forName("android.content.pm.IPackageManager");
            Object proxy = Proxy.newProxyInstance(
                    iPackageManagerInterface.getClassLoader(),
                    new Class<?>[]{iPackageManagerInterface},
                    new PmsHookBinderInvocationHandler(sPackageManager, signed, appPkgName, 0));
            // 1. Replace ActivityThread.sPackageManager
            sPackageManagerField.set(currentActivityThread, proxy);
            // 2. Replace ApplicationPackageManager.mPM
            PackageManager pm = context.getPackageManager();
            Field mPmField = pm.getClass().getDeclaredField("mPM");
            mPmField.setAccessible(true);
            mPmField.set(pm, proxy);
        } catch (Exception e) {
            Log.d(ZJ, "hook pms error:" + Log.getStackTraceString(e));
        }
    }

    public static void hookPMS(Context context) {
        String Sign = "原包的签名信息";
        hookPMS(context, Sign, "com.zj.hookpms", 0);
    }
}
```

```java
package com.xjy.hook;

import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

/**
 * PackageManager service hook handler
 * Intercept and modify signature-verification calls
 */
public class PmsHookBinderInvocationHandler implements InvocationHandler {
    private static final String TAG = "xyjuse";

    private Object mBase; // Original IPackageManager instance
    private String mFakeSignature; // Substitute signature bytes (Base64)
    private String mTargetPackage; // Target package name
    private int mTargetHashCode; // Target hashCode (optional)

    public PmsHookBinderInvocationHandler(Object base, String fakeSignature, String targetPackage, int hashCode) {
        this.mBase = base;
        this.mFakeSignature = fakeSignature;
        this.mTargetPackage = targetPackage;
        this.mTargetHashCode = hashCode;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        String methodName = method.getName();

        // Intercept the getPackageInfo method family
        if ("getPackageInfo".equals(methodName)) {
            return handleGetPackageInfo(method, args);
        }

        // Intercept getPackageInfoVersioned (Android 8.0+)
        if ("getPackageInfoVersioned".equals(methodName)) {
            return handleGetPackageInfoVersioned(method, args);
        }

        // Intercept getApplicationInfo
        if ("getApplicationInfo".equals(methodName)) {
            return handleGetApplicationInfo(method, args);
        }

        // Intercept checkSignatures
        if ("checkSignatures".equals(methodName)) {
            return handleCheckSignatures(method, args);
        }

        // Intercept hasSigningCertificate (Android P+)
        if ("hasSigningCertificate".equals(methodName)) {
            return handleHasSigningCertificate(method, args);
        }

        // Delegate other calls to the original implementation
        return method.invoke(mBase, args);
    }

    /**
     * Handle getPackageInfo calls
     */
    private Object handleGetPackageInfo(Method method, Object[] args) throws Throwable {
        // Call the original method
        Object result = method.invoke(mBase, args);

        if (result instanceof PackageInfo) {
            PackageInfo packageInfo = (PackageInfo) result;

            // Check whether this is the target package
            if (isTargetPackage(packageInfo.packageName)) {
                Log.d(TAG, "拦截到目标包的getPackageInfo调用: " + packageInfo.packageName);
                return modifyPackageInfo(packageInfo);
            }
        }

        return result;
    }

    /**
     * Handle getPackageInfoVersioned calls (Android 8.0+)
     */
    private Object handleGetPackageInfoVersioned(Method method, Object[] args) throws Throwable {
        Object result = method.invoke(mBase, args);

        if (result instanceof PackageInfo) {
            PackageInfo packageInfo = (PackageInfo) result;

            if (isTargetPackage(packageInfo.packageName)) {
                Log.d(TAG, "拦截到目标包的getPackageInfoVersioned调用: " + packageInfo.packageName);
                return modifyPackageInfo(packageInfo);
            }
        }

        return result;
    }

    /**
     * Handle getApplicationInfo calls
     */
    private Object handleGetApplicationInfo(Method method, Object[] args) throws Throwable {
        // ApplicationInfo normally requires no signature changes
        // Other security-check overrides can be added here
        return method.invoke(mBase, args);
    }

    /**
     * Handle checkSignatures calls
     */
    private Object handleCheckSignatures(Method method, Object[] args) throws Throwable {
        // Check whether the arguments contain the target package name
        if (args != null && args.length >= 2) {
            String pkg1 = (String) args[0];
            String pkg2 = (String) args[1];

            if (isTargetPackage(pkg1) || isTargetPackage(pkg2)) {
                Log.d(TAG, "拦截到签名比较调用，强制返回SIGNATURE_MATCH");
                return 0; // PackageManager.SIGNATURE_MATCH
            }
        }

        return method.invoke(mBase, args);
    }

    /**
     * Handle hasSigningCertificate calls (Android P+)
     */
    private Object handleHasSigningCertificate(Method method, Object[] args) throws Throwable {
        if (args != null && args.length >= 1) {
            String packageName = (String) args[0];

            if (isTargetPackage(packageName)) {
                Log.d(TAG, "拦截到hasSigningCertificate调用，强制返回true");
                return true;
            }
        }

        return method.invoke(mBase, args);
    }

    /**
     * Replace signature information in PackageInfo
     */
    private PackageInfo modifyPackageInfo(PackageInfo packageInfo) {
        try {
            if (mFakeSignature != null && !mFakeSignature.isEmpty()) {
                // Decode the Base64 signature
                byte[] signatureBytes = Base64.decode(mFakeSignature, Base64.NO_WRAP);
                Signature fakeSignature = new Signature(signatureBytes);

                // Replace the signatures field
                if (packageInfo.signatures != null && packageInfo.signatures.length > 0) {
                    packageInfo.signatures[0] = fakeSignature;
                    Log.d(TAG, "已替换signatures字段");
                }

                // Handle signingInfo on Android P+
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    if (packageInfo.signingInfo != null) {
                        try {
                            // Use reflection to replace the signatures in signingInfo
                            modifySigningInfo(packageInfo.signingInfo, fakeSignature);
                            Log.d(TAG, "已替换signingInfo字段");
                        } catch (Exception e) {
                            Log.e(TAG, "修改signingInfo失败", e);
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "修改PackageInfo签名失败", e);
        }

        return packageInfo;
    }

    /**
     * Replace the signatures in SigningInfo (Android P+)
     */
    private void modifySigningInfo(SigningInfo signingInfo, Signature fakeSignature) throws Exception {
        // Obtain SigningInfo's private fields
        Class<?> signingInfoClass = signingInfo.getClass();

        try {
            // Replace mSigningDetails
            java.lang.reflect.Field signingDetailsField = signingInfoClass.getDeclaredField("mSigningDetails");
            signingDetailsField.setAccessible(true);
            Object signingDetails = signingDetailsField.get(signingInfo);

            if (signingDetails != null) {
                // Replace SigningDetails.signatures
                Class<?> signingDetailsClass = signingDetails.getClass();
                java.lang.reflect.Field signaturesField = signingDetailsClass.getDeclaredField("signatures");
                signaturesField.setAccessible(true);

                Signature[] signatures = (Signature[]) signaturesField.get(signingDetails);
                if (signatures != null && signatures.length > 0) {
                    signatures[0] = fakeSignature;
                    signaturesField.set(signingDetails, signatures);
                }
            }
        } catch (NoSuchFieldException e) {
            // If this field is absent, try another lookup route
            Log.w(TAG, "SigningInfo字段结构可能已变化: " + e.getMessage());
        }
    }

    /**
     * Check whether this is the target package
     */
    private boolean isTargetPackage(String packageName) {
        if (mTargetPackage == null || packageName == null) {
            return false;
        }
        return mTargetPackage.equals(packageName);
    }
}
```

### 9.4 Print the signature (print_pkms, get the original package signature as base64)

```javascript
function print_pkms() {
    Java.perform(function () {
        try {
            var targetPackage = "com.vietinbank.ipay";
            // Obtain PackageManager
            var ActivityThread = Java.use("android.app.ActivityThread");
            var currentApplication = ActivityThread.currentApplication();
            var context = currentApplication.getApplicationContext();
            var packageManager = context.getPackageManager();
            // Read the signature
            var packageInfo = packageManager.getPackageInfo(targetPackage, 64); // GET_SIGNATURES
            if (packageInfo.signatures.value && packageInfo.signatures.value.length > 0) {
                var signature = packageInfo.signatures.value[0];
                var signatureBytes = signature.toByteArray();
                // Convert it to Base64
                var Base64 = Java.use("android.util.Base64");
                var base64String = Base64.encodeToString(signatureBytes, 2);
                console.log([base64String]);
            } else {
                console.log("[-] 未找到签名信息");
            }
        } catch (e) {
            console.log("[-] 获取签名失败: " + e);
        }
    });
}
```


---

## Related Docs

- USB/adb/native-layer detection bypass: [../advanced/detection-bypass-snippets.md](../advanced/detection-bypass-snippets.md)
- Environment detection principles: [../../04-evasion/detection-landscape.md](../../04-evasion/detection-landscape.md)
