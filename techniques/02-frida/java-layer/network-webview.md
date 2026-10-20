# Java Layer Hook: Networking and WebView

> Topics: networking (URL/okhttp/WebView) + frameworks (ReactNative)

## 2. Networking

### 2.1 java.net.URL constructor

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

### 2.4 okhttp3 request header addHeader

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

### 2.5 WebView (loadUrl/postUrl/addJavascriptInterface)

When to use: for hybrid apps, see which URL the H5 loads and the POST body; inside `loadUrl` you can trigger stack printing on demand to locate the caller.

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

Enable debugging (WebView debugging, for chrome inspect); call this where you have a WebView instance:

```javascript
this.setWebContentsDebuggingEnabled(true);
```

Register a Java object (JS bridge):

```javascript
WebView["addJavascriptInterface"].implementation = function (object, name) {
    // console.log(`WebView.addJavascriptInterface is called: object=${object.getClass()}, name=${name}`);
    this["addJavascriptInterface"](object, name);
};
```

Note: the `getStackTraceString()` called inside `loadUrl` above is a general utility function; its full definition is in section 3, Utility Functions (3.2), of [../native-hook-cheatsheet.md](../native-hook-cheatsheet.md); bring it along when copying this snippet.


---

## 11. Frameworks


### 11.1 ReactNative (JS calling Java functions)

```javascript
let JavaMethodWrapper = Java.use("com.facebook.react.bridge.JavaMethodWrapper");
JavaMethodWrapper["invoke"].implementation = function (jSInstance, readableArray) {
    console.log(this.mMethod.value)
    this["invoke"](jSInstance, readableArray);
};
```


## Related Docs

- so-layer hooks: [native-hook-cheatsheet.md](../native-hook-cheatsheet.md)
- SSL pinning bypass and certificate dumping: [sslpinning-and-certificates.md](sslpinning-and-certificates.md) (same directory)
