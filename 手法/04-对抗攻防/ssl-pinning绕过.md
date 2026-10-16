# SSL Pinning 绕过

> 分类 → 定位 → 分层绕过脚本 → Android 7+ 用户证书的系统层解法。
> 依据：httptoolkit 的 pinning 分层分析、akabe1 frida_multiple_unpinning（30+ 实现）、r0capture（mTLS dump）。

## 0. 原理底座：Android 的 TLS 校验链条

```
app 代码
 └─ OkHttp / Volley / HttpURLConnection / Flutter(dart:io)
     └─ javax.net.ssl.X509TrustManager (默认实现: conscrypt 的 TrustManagerImpl)
         └─ TrustManagerImpl.checkTrustedRecursive()   ← 系统默认链校验
             ├─ 证书链签名验证（Conscrypt/OpenSSL）
             └─ 网络安全配置 networkSecurityConfig（系统 CA / 用户 CA / pin-set）
```

Pin 的本质：**把「信任哪个 CA」缩小为「信任哪个具体证书/公钥」**。校验值通常是证书 SPKI 的 SHA-256（okhttp `sha256/<base64>`）。所以只要 hook 掉「比对」这一步，而不是伪造证书，就能放行任意中间人证书。

## 1. 分类与各层原理

### 1.1 OkHttp CertificatePinner（Java 层最常见）

```java
new OkHttpClient.Builder()
    .certificatePinner(new CertificatePinner.Builder()
        .add("api.target.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        .build())
```
- 执行点：`okhttp3.CertificatePinner.check$okhttp(String hostname, List<Certificate> peerCertificates)`——对返回链里每个证书算 SPKI hash，与 pin 集合比对，不匹配抛 `SSLPeerUnverifiedException`，日志关键字 **`Certificate pinning failure!`**；
- 注意它发生在 **TLS 握手完成后、HTTP 请求发出前**（应用层 pin，非传输层），所以 burp 能完成握手却在 read 响应时炸。

### 1.2 X509TrustManager 自实现（app 自己 new 一个）

```java
TrustManager[] tm = { new X509TrustManager() {
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        if (!chain[0].getEncoded().equals(本地内置证书DER)) throw ...;  // 各种姿势
    } ... }};
SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(null, tm, null);
```
- 变体多：比对证书 DER 全文、比对公钥、比对 CN/SAN、把内置证书放进 raw 资源用 `CertificateFactory` 解析后比 fingerprint；
- 还有 wrapper 型：`X509TrustManagerExtensions.checkServerTrusted(chain, authType, host)`（JSSE 的 hostname-aware 包装，内部一样走链验证）。

### 1.3 网络安全配置 pin-set（manifest 层）

```xml
<network-security-config>
  <domain-config>
    <domain includeSubdomains="true">api.target.com</domain>
    <pin-set expiration="2027-01-01"><pin digest="SHA-256">AAAA...</pin></pin-set>
  </domain-config>
</network-security-config>
```
- 由系统 `NetworkSecurityConfig` 在 `TrustManagerImpl` 校验后追加 pin 比对（`ApplicationConfig` → `NetworkSecurityTrustProvider`）。对绕过来说它和 1.2 走同一条 `checkTrustedRecursive` 管道，通用脚本顺带覆盖。

### 1.4 Native 层校验（libcurl/openssl/BoringSSL 自带）

- app 用 curl/自编 openssl/BoringSSL（Flutter 就是自带 BoringSSL 的典型）：校验发生在 so 内部（`SSL_get_verify_result`、`X509_verify_cert`、curl 的 `CURLOPT_PINNEDPUBLICKEY`）；
- Java 层 TrustManager 根本不在链路上，**Java hook 全部无效**；
- Flutter 特有：dart:io 的 SecurityContext 默认校验系统 CA；且 Flutter 用自己的 DNS 解析（不 Care 系统 proxy 的话连 burp 都进不去，要先 hook `HttpClient.badCertificateCallback` 或设 proxy 环境变量）。

### 1.5 双向校验 mTLS

- 服务端也要验客户端证书：app 内置 p12（res/raw/xxx.p12）+ 密码（硬编码/native 里算出来），握手时 `KeyManager`（`X509KeyManager`）提供私钥+证书链；
- 表现：burp 用假客户端证书 → 服务端 403/handshake failure。绕过的本质不是「绕过校验」而是**偷出客户端证书给 burp 用**（§3.4）。

## 2. 定位手法（先找到 pin 在哪一层再打）

### 2.1 字符串/日志定位

- 反编译（jadx）全局搜：`Certificate pinning failure`（okhttp）、`checkServerTrusted`、`X509TrustManager`、`sha256/`（pin 值格式）、`pin-set`、`networkSecurityConfig`（manifest）、`.p12`/`.bks`/`PKCS12`（mTLS keystore）；
- 资源层看 `res/xml/network_security_config.xml` 是否带 pin-set；`res/raw/` 是否有 p12/bks。

### 2.2 运行时调用栈定位（frida 一行流）

```javascript
// 让任何 Java 异常/关键方法把调用栈吐出来，从栈里看 pin 实现在哪个类
Java.perform(function () {
    var TME = Java.use("android.net.http.X509TrustManagerExtensions");
    TME.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String')
      .implementation = function (chain, authType, host) {
        console.log("X509TrustManagerExtensions.checkServerTrusted host=" + host);
        console.log(Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Throwable").$new()));
        return this.checkServerTrusted(chain, authType, host);
    };
});
```
- 栈里出现 `com.target.app.ssl.XXX` → 自实现 TrustManager，下一步精确 hook 该类；
- 栈里只有 okhttp/conscrypt → 库层 pin，通用脚本覆盖；
- 栈里啥都没有（Java 层无感）→ native pin，转 IDA 看 so（搜 `SSL_CTX_set_verify`、`curl_easy_setopt`、`SSL_get_verify_result`、`pin` 字符串与 `X509`/`sha256` 常量）。

### 2.3 文件读侧定位（hook File/KeyStore 构造）

```javascript
// mTLS：钩 KeyStore.load 看它读哪个 p12 + 密码
Java.perform(function () {
    var KS = Java.use("java.security.KeyStore");
    KS.load.overload('java.io.InputStream', '[C').implementation = function (is, pass) {
        console.log("KeyStore.load password=" + (pass ? Java.use("java.lang.String").$new(pass) : null));
        return this.load(is, pass);
    };
});
```

配合 hook `File` 构造/`openFileInput` 看 `res/raw` 里加载的证书文件名；密码若在 native 算（JNI 返回 char[]），hook 返回点或直接 IDA 找。

## 3. 分层绕过脚本

### 3.1 第一层：通用大杀器（先无脑跑一遍）

现代通用脚本（akabe1 的 frida_multiple_unpinning 覆盖 30+ 实现；httptoolkit 分析的覆盖面类似）核心动作：

```javascript
// A. 系统默认 TrustManager：让链校验返回空 list（= 全信）
var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
TrustManagerImpl.checkTrustedRecursive.implementation =
  function (chain, authType, host, clientAuth, clientAuthAlg, clientAuthParams, ocspData, tlsSctData) {
      console.log("[+] checkTrustedRecursive bypass for " + host);
      return Java.use("java.util.ArrayList").$new();   // 空证书 list
  };
// （老 Android 版本签名不同：checkTrusted(X509Certificate[], String, String) 返回空）

// B. OkHttp CertificatePinner：check$okhttp 直接 return（found = 什么都不抛）
var CertPinner = Java.use("okhttp3.CertificatePinner");
CertPinner.check$okhttp.overload('java.lang.String', 'java.util.List')
  .implementation = function (hostname, peerCerts) { return; };

// C. 自定义空 TrustManager 替换 SSLContext.init 的第二个参数
var SSLCtx = Java.use("javax.net.ssl.SSLContext");
SSLCtx.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
  .implementation = function (km, tm, sr) {
      var TMI = Java.registerClass({ /* implements X509TrustManager 全放行 */ });
      return this.init(km, [TMI.$new()], sr);
  };
// D. 顺带：webview 的 onReceivedSslError → handler.proceed()
// E. 顺带：okhttp3.internal.tls.OkHostnameVerifier / X509TrustManagerExtensions
```

要点：
- **为什么 hook checkTrustedRecursive 就够**：网络层（HttpURLConnection/okhttp 未配 pin 时）最终都收敛到 conscrypt 的这个方法；返回「空受信列表」意味着调用方认为无需再验证（各调用点拿到空 list 后直接通过）；
- **返回空 list 而不是抛异常/返回原结果**：gabriel.urdhr 的分析指出这类脚本实际是「关闭全部证书校验」而非只关 pin——安全上等价于全信任，测试期无所谓；
- **版本坑**：不同 Android/okhttp 版本方法签名不同（`check$okhttp` 是否存在、`checkTrustedRecursive` 参数个数 4/8 个），所以成熟脚本里全是 try/catch 逐个尝试——自己写也要这么兜。

### 3.2 第二层：定位到自实现类后精确 hook

通用脚本没命中（app 用了非常规库）时：

```javascript
// 例：定位到 com.target.app.security.MyTrustManager
var MTM = Java.use("com.target.app.security.MyTrustManager");
MTM.checkServerTrusted.implementation = function (chain, authType) {
    console.log("[+] MyTrustManager bypassed, authType=" + authType);
    // 不调原方法，直接返回 = 放行
};

// 例：网络层在 Volley/HurlStack 或自定义 SSLSocketFactory
var Factory = Java.use("com.target.app.net.MySSLSocketFactory");
Factory.createSocket.overload(...).implementation = ... // 返回套了空 TM 的 socket
```
- 精确 hook 的依据来自 §2 的调用栈定位；
- 混淆类名（a.b.c）时按方法签名（`([Ljava/security/cert/X509Certificate;Ljava/lang/String)V`）+ 字符串常量（jadx 里的 pin base64 值）反查。

### 3.3 第三层：Native pinning

定位：IDA 打开目标 so，搜导入表 `SSL_CTX_set_verify` / `SSL_get_verify_result` / `X509_verify_cert` / `curl_easy_setopt`（CURLOPT_PINNEDPUBLICKEY=10230，curl 用整数传 option，搜 `0x27f6` 类常量）、字符串 `sha256//`（curl pin 格式）。
frida 侧（针对 BoringSSL/libcrypto so）：

```javascript
// 思路：hook so 内的 SSL_CTX_set_verify，把回调换成永远返回 1（验证通过）
var set_verify = Module.findExportByName("libtarget.so", "SSL_CTX_set_verify")
              || Module.findExportByName("libssl.so", "SSL_CTX_set_verify");
Interceptor.attach(set_verify, {
    onEnter: function (args) {
        args[1] = ptr(0);            // SSL_VERIFY_NONE
        this.neverFail = true;
    }
});
// 以及 SSL_get_verify_result 强制返回 X509_V_OK(0)
Interceptor.replace(Module.findExportByName(null, "SSL_get_verify_result"),
    new NativeCallback(function (ssl) { return 0; }, 'long', ['pointer']));

// Flutter 专属（libflutter.so 符号被裁时的经典手法，httptoolkit 有完整版）：
// 1. 版本对上后按偏移找 ssl_verify_peer_cert / ssl_crypto_x509_session_verify_cert_chain
// 2. Interceptor.replace 成恒返回 1（error code 0 = 成功）
var addr = Module.findBaseAddress("libflutter.so").add(0x1D5C2C); // 偏移随版本
Interceptor.replace(addr, new NativeCallback(function (a, b, c, d) { return 1; },
    'int', ['pointer','pointer','pointer','pointer']));
```

Flutter 偏移查法：`strings libflutter.so | grep -o 'Dart_VM.*'` 看版本 → 对应 dart-sdk 源码/社区偏移表（httptoolkit 维护了脚本 re-frida-flutter-pinning，思路即上述）。so 裁符号时用 `Module.enumerateExports` + 运行时回溯调用点，或直接 patch so。

### 3.4 第四层：mTLS dump 客户端证书为 p12（r0capture 路线）

两条路线：
**路线一：静态提取**——APK 里找 p12/bks 资源（§2.1），jadx 找密码（搜 `KeyStore.getInstance("PKCS12")` 附近的 `toCharArray`），导入 burp（User Certificates）。
**路线二：运行时 dump（密码混淆/证书动态下发时）**——hook KeyManager 拿私钥+证书链重组 p12（r0capture 的核心思路）：

```javascript
// r0capture 的实际挂点：java.security.KeyStore$PrivateKeyEntry
// （KeyManager 每次握手取出的客户端凭据条目；比 hook 具体 KeyManager 实现更通用）
Java.perform(function () {
    var PKEntry = Java.use("java.security.KeyStore$PrivateKeyEntry");
    PKEntry.getPrivateKey.implementation = function () {
        var key = this.getPrivateKey();
        var certChain = this.getCertificateChain();
        dumpToP12(key, certChain, "r0ysue");   // KeyStore PKCS12 setKeyEntry + store 到 /sdcard
        return key;
    };
});
// 备选挂点：org.conscrypt.ClientKeyManager（或 app 自实现 X509KeyManager）
// 的 getPrivateKey(alias)/getCertificateChain(alias)，取值时机相同
```
- r0capture 实际是「应用层抓包通杀脚本」：dump 出的 p12 落 `/sdcard/Download/<包名>xxx.p12`，默认密码 `r0ysue`，keystore-explorer 打开确认后导入 burp/mitmproxy 完成双向代理；
- 原理本质：**p12 = 私钥 + 证书链 + 密码**。私钥和链都在 app 内存里（握手必须用），所以在 KeyManager 出口截获是一定能拿到的；比逆向找密码稳（对付「密码在 native 算」「证书服务端下发」都有效）。

## 4. Android 7+ 用户证书不被信任的系统层解法

背景：API 24 起 app 默认**不信任用户安装的 CA**（只信系统 CA + 自身 networkSecurityConfig 声明的）。burp 证书装到用户区 → 抓包直接 handshake failure。四条路：

### 4.1 networkSecurityConfig 改写（重打包）

反编译加 `res/xml/nsc.xml`（`<base-config cleartextTrafficPermitted="true"><trust-anchors><certificates src="user"/></trust-anchors></base-config>`）+ manifest 引用，回编译重签。代价：签名校验 app 会炸，且每个 app 都要改。

### 4.2 系统证书目录写入（root）

```bash
# burp CA (DER) 转 PEM → 按 subject_hash 重命名 → 塞进系统证书目录
openssl x509 -inform DER -in burp.der -out burp.pem
openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1   # 如 9a5ba575
mv burp.pem /data/misc/user/0/cacerts-added/9a5ba575.0   # 用户安装路径（只对声明信任用户的 app 有效）
# 真正要的是系统区：Android 14+ /apex/com.android.conscrypt/cacerts 是只读 apex 挂载，见下
```
- 传统：`/system/etc/security/cacerts/` remount rw 写入（systemless 时代用 Magisk 模块做，见 4.3）；
- **Android 14 变化**：CA 存储挪进 APEX（conscrypt APEX），只读且 hash 校验，手工 remount 不再简单可行——直接用现成模块更省事。

### 4.3 系统证书 Magisk 模块（推荐，免重打包）

- 代表项目：**MoveCertificate**（把用户 CA 提升为系统 CA：模块启动脚本把 `/data/misc/user/0/cacerts-added/*` bind mount 到系统证书目录）、**MagiskTrustUserCerts**（同思路）、**conscrypt-apex 适配版**（Android 14+ 的 APEX 内 cacerts 处理：模块在较晚 stage 用 overlay/bind 方式盖掉 apex 路径）；
- 原理：Magisk 的 systemless 挂载魔法——不真改分区，只在 mount 层面让 `/system/etc/security/cacerts/`（或 apex 等价路径）多出 burp 的证书文件。配合 Shamiko 的 DenyList 时注意：**目标 app 若在 DenyList 里，unmount 会把证书模块的挂载也还原** → 抓包失效，要么把模块路径排除在 unmount 外，要么测试时临时摘掉目标 app。

### 4.4 frida 强制走用户 CA（不动系统）

不装证书、不重打包，直接 hook 让目标 app 信任用户证书池：

```javascript
// 思路：改 NetworkSecurityConfig 的运行时结果 —— 通用大杀器脚本其实已顺带覆盖：
// checkTrustedRecursive 返回空 list 时，根本轮不到「用户 CA 是否受信」的判断，
// 所以 §3.1 的脚本是 Android 7+ 问题的「顺手解」，无需单独处理证书安装。
// 仅当不方便 hook（需要纯无 frida 环境）时才用 4.1-4.3 的系统层方案。
```

## 5. 排查顺序总表

| 症状 | 层 | 动作 |
|------|------|------|
| burp 握手就失败（无 app 日志） | 系统不信任用户 CA / native pin | 4.2/4.3 装系统证书 → 仍失败转 3.3 |
| 握手成功、读响应时炸 + 日志 `Certificate pinning failure!` | okhttp pin | 3.1-B |
| 异常栈有 app 自己的 TrustManager | 自实现 | 3.2 精确 hook |
| 栈只有 conscrypt | 系统/库层 | 3.1-A |
| Flutter app | BoringSSL | 3.3 偏移 replace |
| 服务端 403/handshake failure | mTLS | 3.4 dump p12 |
| 全 hook 了还失败 | native curl/openssl | IDA 定位 + 3.3 |
| 过了 pinning 但请求发不出去 | proxy 检测 | 见《检测原理全景》§5.1 |
