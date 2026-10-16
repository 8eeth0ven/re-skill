# Java 层 Hook·网络与 WebView

> 主题:网络(URL/okhttp/WebView) + 框架(ReactNative)

## 二、网络

### 2.1 java.net.URL 构造函数

```javascript
// hook java.net.URL
var URL = Java.use('java.net.URL');
URL.$init.overload('java.lang.String').implementation = function (a) {
    console.log('java.net.URL ' + a)
    this.$init(a)
}
```

### 2.2 okhttp3 Request$Builder.url

```javascript
//hook okhttp3 HttpUrl
var Builder = Java.use('okhttp3.Request$Builder');
Builder.url.overload('okhttp3.HttpUrl').implementation = function (a) {
    var res = this.url(a);
    console.log("okhttp3.HttpUrl result: " + res)
    return res;
}
```

### 2.3 Uri.parse

```javascript
var Uri = Java.use('android.net.Uri');
Uri.parse.overload('java.lang.String').implementation = function (str) {
    console.log(str)
    return this.parse(str);
}
```

### 2.4 okhttp3 请求头 addHeader

```javascript
var Builder = Java.use("okhttp3.Request$Builder");
Builder["addHeader"].implementation = function (str, str2) {
    console.log("okhttp3.Request$Builder.addHeader key: " + str)
    console.log("okhttp3.Request$Builder.addHeader val: " + str2)
    var result = this["addHeader"](str, str2);
    console.log("okhttp3.Request$Builder.addHeader result: " + result);
    return result;
};
```

### 2.5 WebView(loadUrl/postUrl/addJavascriptInterface)

什么时候用:Hybrid app 看 H5 加载的地址和 POST body;`loadUrl` 里可以按需触发堆栈打印定位调用方。

```javascript
function WebView() {
    let WebView = Java.use("android.webkit.WebView");
    WebView["postUrl"].implementation = function (str, bArr) {
        var string = Java.use('java.lang.String').$new(bArr);
        console.log(`WebView.postUrl is called: str=${str}, string=${string}`);
        this["postUrl"](str, bArr);
    };
    WebView["loadUrl"].overload('java.lang.String').implementation = function (str) {
        console.log(`WebView.loadUrl is called: str=${str}`);
        var s = Java.use('java.lang.String').$new(str);
        var t = Java.use('java.lang.String').$new("https");
        if (s.contains(t)) {
            getStackTraceString();
        }
        this["loadUrl"](str);
    };
    WebView["loadUrl"].overload('java.lang.String', 'java.util.Map').implementation = function (str, map) {
        console.log(`WebView.loadUrl 2is called: str=${str}, map=${map}`);
        this["loadUrl"](str, map);
    };
}
```

开启 debug(WebView 调试,chrome inspect 用),在拿到 WebView 实例的地方调用:

```javascript
this.setWebContentsDebuggingEnabled(true);
```

设置 java 对象(JS 桥):

```javascript
WebView["addJavascriptInterface"].implementation = function (object, name) {
    // console.log(`WebView.addJavascriptInterface is called: object=${object.getClass()}, name=${name}`);
    this["addJavascriptInterface"](object, name);
};
```

注意:上面 `loadUrl` 里调用的 `getStackTraceString()` 是通用工具函数,完整定义见 [../native层hook速查.md](../native层hook速查.md) 三、工具函数(3.2),复制本段代码时需一并带上。


---

## 十一、框架


### 11.1 ReactNative(js 调 java 函数)

```javascript
let JavaMethodWrapper = Java.use("com.facebook.react.bridge.JavaMethodWrapper");
JavaMethodWrapper["invoke"].implementation = function (jSInstance, readableArray) {
    console.log(this.mMethod.value)
    this["invoke"](jSInstance, readableArray);
};
```


## 相关文档

- so 层 hook:[native层hook速查.md](../native层hook速查.md)
- ssl pinning 绕过与证书 dump:[sslpinning与证书.md](sslpinning与证书.md)(同目录)
