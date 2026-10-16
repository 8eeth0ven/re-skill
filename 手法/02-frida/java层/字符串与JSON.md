# Java 层 Hook·字符串与 JSON

> 主题:通用容器 + 字符串 + JSON

## 一、通用容器

### 1.1 HashMap.put

什么时候用:有些请求头会使用这个添加,可能通过 okhttp 直接增加。

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

## 三、字符串

### 3.1 StringFactory(字符串生成的地方,new String)

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

### 3.2 字符串拼接 StringBuilder.toString

```javascript
// 字符串拼接
var sb = Java.use("java.lang.StringBuilder");
sb.toString.implementation = function () {
    var retval = this.toString();
    console.log("StringBuilder.toString: ", retval);
    return retval;
}
```

### 3.3 StringBuffer.toString(支持多线程)

```javascript
// 支持多线程 字符串拼接
var sb = Java.use("java.lang.StringBuffer");
sb.toString.implementation = function () {
    var retval = this.toString();
    console.log("StringBuffer.toString: ", retval);
    return retval;
}
```

## 四、JSON(用的非常多)

一般来说 json 都会使用 gson 这个库;安卓原生走 org.json,金融类 app 大量用 fastjson。

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

optString 版,可以按 key 触发堆栈定位是谁在读字段(代码里的 `getStackTraceString()` 为通用工具函数,定义见 [../native层hook速查.md](../native层hook速查.md) 三、工具函数(3.2),复制时需一并带上):

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

### 4.2 fastjson(部分金融类 app)

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


## 相关文档

- 入门与工具链:[环境与快速开始.md](../环境与快速开始.md)
