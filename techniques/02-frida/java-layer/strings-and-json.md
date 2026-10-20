# Java Layer Hook: Strings and JSON

> Topics: general containers + strings + JSON

## 1. General Containers

### 1.1 HashMap.put

When to use: some request headers are added this way, possibly added directly through okhttp.

```javascript
//由于有些请求头会使用这个添加，可能通过okhttp直接增加
var hashMap = Java.use("java.util.HashMap");
hashMap.put.implementation = function (a, b) {
    console.log("hashMap.put: ", a, b);
    return this.put(a, b);
}
```

### 1.2 ConcurrentHashMap.put

```javascript
// java.util.concurrent.ConcurrentHashMap
var ConcurrentHashMap = Java.use("java.util.concurrent.ConcurrentHashMap");
ConcurrentHashMap.put.implementation = function (a, b) {
    console.log("ConcurrentHashMap.put: ", a, b);
    return this.put(a, b);
}
```

### 1.3 LinkedHashMap.put

```javascript
// java.util.LinkedHashMap
var LinkedHashMapClass = Java.use("java.util.LinkedHashMap");
LinkedHashMapClass.put.implementation = function (key, value) {
    console.log("LinkedHashMap key:", key, "value:", value);
    return this.put(key, value);
};
```


---

## 3. Strings

### 3.1 StringFactory (where strings are created, new String)

```javascript
// hook string的构造函数  字符串生成的地方例子，new String
var stringFactory = Java.use("java.lang.StringFactory");
stringFactory.newStringFromString.implementation = function (a) {
    var retval = this.newStringFromString(a);
    console.log("stringFactory.newStringFromString: ", retval);
    return retval;
}
stringFactory.newStringFromChars.overload('[C').implementation = function (a) {
    var retval = this.newStringFromChars(a);
    console.log("stringFactory.newStringFromChars: ", retval);
    return retval;
}
```

### 3.2 String concatenation, StringBuilder.toString

```javascript
// 字符串拼接
var sb = Java.use("java.lang.StringBuilder");
sb.toString.implementation = function () {
    var retval = this.toString();
    console.log("StringBuilder.toString: ", retval);
    return retval;
}
```

### 3.3 StringBuffer.toString (supports multi-threading)

```javascript
// 支持多线程 字符串拼接
var sb = Java.use("java.lang.StringBuffer");
sb.toString.implementation = function () {
    var retval = this.toString();
    console.log("StringBuffer.toString: ", retval);
    return retval;
}
```

## 4. JSON (heavily used)

Generally JSON is handled by the gson library; stock Android goes through org.json, and finance apps use fastjson heavily.

### 4.1 org.json.JSONObject

```javascript
// JSON处理
var jSONObject = Java.use("org.json.JSONObject");
jSONObject.put.overload('java.lang.String', 'java.lang.Object').implementation = function (a, b) {
    console.log("jSONObject.put: ", a, b);
    return this.put(a, b);
}
jSONObject.getString.implementation = function (a) {
    console.log("jSONObject.getString: ", a);
    var result = this.getString(a);
    console.log("jSONObject.getString result: ", result);
    return result;
}
```

The optString variant can trigger a stack trace per key to find out who is reading the field (the `getStackTraceString()` in the code is a general utility function, defined in section 3, Utility Functions (3.2), of [../native-hook-cheatsheet.md](../native-hook-cheatsheet.md); bring it along when copying):

```javascript
var JSONObject = Java.use("org.json.JSONObject");
JSONObject['optString'].overload('java.lang.String').implementation = function (str) {
    if(str === "data"){
        console.log('str', str)
        getStackTraceString();
    }
    let result = this['optString'](str);
    return result;
};
```

### 4.2 fastjson (some finance apps)

```javascript
function hookApp() {
    Java.enumerateClassLoadersSync().forEach(classLoader => {
        // 寻找com.alibaba.fastjson.JSON类
        try {
            if (classLoader.loadClass("com.alibaba.fastjson.JSON")) {
                Java.classFactory.loader = classLoader
                var fastJson = Java.use("com.alibaba.fastjson.JSON");
                console.log("found com.alibaba.fastjson.JSON");
                // 序列化监控
                fastJson.toJSONString.overload('java.lang.Object').implementation = function (obj) {
                    var jsonStr = this.toJSONString(obj);
                    console.log("\n=== 序列化监控 ===");
                    console.log("JSON 结果 =>", jsonStr);
                    return jsonStr;
                };
                // 反序列化监控
                fastJson.parseObject.overload('java.lang.String').implementation = function (jsonStr) {
                    console.log("\n=== 反序列化监控 ===");
                    console.log("输入 JSON =>", jsonStr);
                    var result = this.parseObject(jsonStr);
                    return result;
                };
            }
        } catch (error) {
        }
    })

}

setTimeout(hookApp, 2000)
```


## Related Docs

- Getting started and toolchain: [env-and-quickstart.md](../env-and-quickstart.md)
