# Java Layer Hook: UI and Navigation

> Topics: UI/system (Toast/Dialog/Activity navigation/Intent/Log)

## 7. UI / System

### 7.1 Toast

```javascript
// Core dialog classes
var toast = Java.use("android.widget.Toast");
toast.show.implementation = function () {
    console.log("toast.show: ");
    return this.show();
}
```

makeText (grab the toast text):

```javascript
var Toast = Java.use("android.widget.Toast");
Toast.makeText.overload("android.content.Context", "java.lang.CharSequence", "int").implementation = function (context, text, duration) {
    console.log("Toast message:", text);
    // Call the original makeText method to create the Toast
    var toast = this.makeText(context, text, duration);
    // Return the created Toast
    return toast;
};
```

### 7.2 Dialog

```javascript
Java.perform(function() {
    var Dialog = Java.use("android.app.Dialog");
    // Hook show()
    Dialog.show.implementation = function() {
        this.show();
    };
});
```

### 7.3 Showing a toast (proactively pop a Toast; note you must switch to the main thread)

```javascript
Java.perform(function () {
    let t = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
    Java.scheduleOnMainThread(function () {
        Java.use("android.widget.Toast").makeText(t, Java.use("java.lang.String").$new(e), 1).show()
    })
})
```

### 7.4 Activity navigation monitoring (startActivity / startActivityForResult)

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

### 7.5 get_activity / goto_activity (activity enumeration and proactive navigation)

Enumerate all current activities:

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

Proactively navigate to a given page:

```javascript
function goto_activity() {
    Java.perform(function () {
        var Intent = Java.use("android.content.Intent");
        var ActivityThread = Java.use("android.app.ActivityThread");

        // Obtain the current Application context
        var currentApplication = ActivityThread.currentApplication();
        var context = currentApplication.getApplicationContext();

        var cpI = Java.use("o.cpI")
        // Construct the Intent
        var intent = Intent.$new(context, cpI.class); // Choose the appropriate constructor for Action and Data
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK.value); // Add FLAG_ACTIVITY_NEW_TASK
        // Launch the target screen
        console.log("Redirecting to: th.co.truemoney.wallet/o.cpI");
        context.startActivity(intent); // Start the Intent through the context
    });
}
```

### 7.6 Intent constructors (all overloads)

```javascript
function intent() {
    console.log("Script loaded successfully!");

    // Resolve Intent with Java.use
    var Intent = Java.use("android.content.Intent");

    // Hook the no-argument constructor
    Intent.$init.overload().implementation = function () {
        console.log("[$init.overload()] Intent no-argument constructor called");
        // Call the original constructor
        var result = this.$init();
        // Print the stack trace to identify the caller
        console.log("Backtrace:\n" + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        return result;
    };

    // Hook the constructor taking an Action
    Intent.$init.overload("java.lang.String").implementation = function (action) {
        console.log("[$init.overload('java.lang.String')] Intent constructor called, action: " + action);
        var result = this.$init(action);
        console.log("Backtrace:\n" + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        return result;
    };

    // Hook the constructor taking another Intent (copy constructor)
    Intent.$init.overload("android.content.Intent").implementation = function (otherIntent) {
        console.log("[$init.overload('android.content.Intent')] Intent copy constructor called");
        // Read the original Intent's information
        if (otherIntent != null) {
            var action = otherIntent.getAction();
            var dataString = otherIntent.getDataString();
            var component = otherIntent.getComponent();
            var packageName = otherIntent.getPackage();
            var flags = otherIntent.getFlags();

            console.log("Original Intent information: " +
                "Action=" + action +
                ", Data=" + dataString +
                ", Component=" + component +
                ", Package=" + packageName +
                ", Flags=" + flags);
        }
        var result = this.$init(otherIntent);
        console.log("Backtrace:\n" + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        return result;
    };

    // Hook the constructor taking Action and Uri
    Intent.$init.overload("java.lang.String", "android.net.Uri").implementation = function (action, uri) {
        console.log("[$init.overload('java.lang.String', 'android.net.Uri')] Intent constructor called");
        console.log("Action: " + action + ", URI: " + (uri ? uri.toString() : "null"));
        var result = this.$init(action, uri);
        console.log("Backtrace:\n" + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        return result;
    };

    // Hook the constructor taking Context and Class
    Intent.$init.overload("android.content.Context", "java.lang.Class").implementation = function (context, cls) {
        console.log("[$init.overload('android.content.Context', 'java.lang.Class')] Intent constructor called");
        console.log("Class: " + cls.getName());
        var result = this.$init(context, cls);
        console.log("Backtrace:\n" + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
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


## Related Docs

- Locating obfuscated classes (o.cpI etc.): the packed-app hook section of [crypto-and-self-dump.md](crypto-and-self-dump.md)
