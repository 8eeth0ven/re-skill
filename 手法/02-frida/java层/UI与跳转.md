# Java 层 Hook·UI 与跳转

> 主题:界面/系统(Toast/Dialog/Activity 跳转/Intent/Log)

## 七、界面 / 系统

### 7.1 Toast

```javascript
// 弹窗关键类
var toast = Java.use("android.widget.Toast");
toast.show.implementation = function () {
    console.log("toast.show: ");
    return this.show();
}
```

makeText(拿弹出的文案):

```javascript
var Toast = Java.use("android.widget.Toast");
Toast.makeText.overload("android.content.Context", "java.lang.CharSequence", "int").implementation = function (context, text, duration) {
    console.log("Toast message:", text);
    // 调用原始 makeText 方法生成 Toast 对象
    var toast = this.makeText(context, text, duration);
    // 返回生成的 Toast 对象
    return toast;
};
```

### 7.2 Dialog

```javascript
Java.perform(function() {
    var Dialog = Java.use("android.app.Dialog");
    // Hook show() 方法
    Dialog.show.implementation = function() {
        this.show();
    };
});
```

### 7.3 弹窗展示(主动弹 Toast,注意要切主线程)

```javascript
Java.perform(function () {
    let t = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
    Java.scheduleOnMainThread(function () {
        Java.use("android.widget.Toast").makeText(t, Java.use("java.lang.String").$new(e), 1).show()
    })
})
```

### 7.4 Activity 跳转监控(startActivity / startActivityForResult)

```javascript
Java.perform(function() {
    var Activity = Java.use('android.app.Activity');
    
    // Hook startActivity(Intent)
    Activity.startActivity.overload('android.content.Intent').implementation = function(intent) {
        var target = intent.getComponent().getClassName();
        var currentActivity = this.getClass().getName();
        console.log(`[Activity] FROM: ${currentActivity}`);
        console.log(`[Activity] TO: ${target}`);
        return this.startActivity(intent);
    };

    // Hook startActivityForResult(Intent, int)
    Activity.startActivityForResult.overload('android.content.Intent', 'int').implementation = function(intent, requestCode) {
        var target = intent.getComponent().getClassName();
        var currentActivity = this.getClass().getName();
        console.log(`[ActivityForResult] FROM: ${currentActivity}`);
        console.log(`[ActivityForResult] TO: ${target} (RequestCode: ${requestCode})`);
        return this.startActivityForResult(intent, requestCode);
    };
});
```

### 7.5 get_activity / goto_activity(页面跳转枚举与主动跳转)

枚举当前所有 Activity:

```javascript
function get_activity() {
    var ActivityThread = Java.use("android.app.ActivityThread");
    var currentActivityThread = ActivityThread.currentActivityThread();
    var activities = currentActivityThread.mActivities.value;

    var iterator = activities.entrySet().iterator();
    while (iterator.hasNext()) {
        var entry = iterator.next();
        console.log(entry.getClass())
    }
}
```

主动跳转到指定页面:

```javascript
function goto_activity() {
    Java.perform(function () {
        var Intent = Java.use("android.content.Intent");
        var ActivityThread = Java.use("android.app.ActivityThread");

        // 获取当前的 Application 上下文
        var currentApplication = ActivityThread.currentApplication();
        var context = currentApplication.getApplicationContext();

        var cpI = Java.use("o.cpI")
        // 构造 Intent
        var intent = Intent.$new(context, cpI.class); // 使用合适的构造器设置 Action 和 Data
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK.value); // 添加 FLAG_ACTIVITY_NEW_TASK
        // 启动目标页面
        console.log("Redirecting to: th.co.truemoney.wallet/o.cpI");
        context.startActivity(intent); // 使用上下文启动 Intent
    });
}
```

### 7.6 Intent 构造函数(全部重载)

```javascript
function intent() {
    console.log("Script loaded successfully!");

    // 使用Java.use获取Intent类
    var Intent = Java.use("android.content.Intent");

    // Hook无参构造函数
    Intent.$init.overload().implementation = function () {
        console.log("[$init.overload()] Intent的无参构造函数被调用");
        // 调用原始构造函数
        var result = this.$init();
        // 打印堆栈信息以了解调用来源
        console.log("调用堆栈:\n" + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        return result;
    };

    // Hook带有Action参数的构造函数
    Intent.$init.overload("java.lang.String").implementation = function (action) {
        console.log("[$init.overload('java.lang.String')] Intent构造函数被调用，action: " + action);
        var result = this.$init(action);
        console.log("调用堆栈:\n" + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        return result;
    };

    // Hook带有另一个Intent参数的构造函数（复制构造函数）
    Intent.$init.overload("android.content.Intent").implementation = function (otherIntent) {
        console.log("[$init.overload('android.content.Intent')] Intent复制构造函数被调用");
        // 获取原始Intent的信息
        if (otherIntent != null) {
            var action = otherIntent.getAction();
            var dataString = otherIntent.getDataString();
            var component = otherIntent.getComponent();
            var packageName = otherIntent.getPackage();
            var flags = otherIntent.getFlags();

            console.log("原始Intent信息: " +
                "Action=" + action +
                ", Data=" + dataString +
                ", Component=" + component +
                ", Package=" + packageName +
                ", Flags=" + flags);
        }
        var result = this.$init(otherIntent);
        console.log("调用堆栈:\n" + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        return result;
    };

    // Hook带有Action和Uri参数的构造函数
    Intent.$init.overload("java.lang.String", "android.net.Uri").implementation = function (action, uri) {
        console.log("[$init.overload('java.lang.String', 'android.net.Uri')] Intent构造函数被调用");
        console.log("Action: " + action + ", URI: " + (uri ? uri.toString() : "null"));
        var result = this.$init(action, uri);
        console.log("调用堆栈:\n" + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        return result;
    };

    // Hook带有Context和Class参数的构造函数
    Intent.$init.overload("android.content.Context", "java.lang.Class").implementation = function (context, cls) {
        console.log("[$init.overload('android.content.Context', 'java.lang.Class')] Intent构造函数被调用");
        console.log("Class: " + cls.getName());
        var result = this.$init(context, cls);
        console.log("调用堆栈:\n" + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        return result;
    };

    console.log("All Intent constructors hooked successfully!");
}
```

### 7.7 Log

```javascript
var log = Java.use("android.util.Log");
log.w.overload('java.lang.String', 'java.lang.String').implementation = function (tag, message) {
    console.log("log.w: ", tag, message);
    return this.w(tag, message);
}
```


## 相关文档

- 混淆类定位(o.cpI 等):[加密与自吐.md](加密与自吐.md) 的加壳 hook 节
