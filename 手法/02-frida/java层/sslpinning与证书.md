# Java 层 Hook·sslpinning 与证书

> 主题:抓包/证书(SSLContext.init 绕过 + dump 客户端证书)

## 十二、抓包 / 证书

### 12.1 sslpinning 绕过(SSLContext.init 版)

什么时候用:app 用自定义 TrustManager 校验系统 CA 之外的证书,抓不到包时,把自己的 CA 塞进去替换 TrustManager。需要在 `/data/local/tmp/cer/desktop.cer` 放证书文件。

```javascript
Java.perform(function () {
    console.log("");
    console.log("[.] Cert Pinning Bypass/Re-Pinning");

    var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
    var FileInputStream = Java.use("java.io.FileInputStream");
    var BufferedInputStream = Java.use("java.io.BufferedInputStream");
    var X509Certificate = Java.use("java.security.cert.X509Certificate");
    var KeyStore = Java.use("java.security.KeyStore");
    var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    // Load CAs from an InputStream
    console.log("[+] Loading our CA...")
    var cf = CertificateFactory.getInstance("X.509");

    // 这里需要ca证书
    try {
        console.log("加载ca 文件")
        var fileInputStream = FileInputStream.$new("/data/local/tmp/cer/desktop.cer");
    } catch (err) {
        console.log("[o] " + err);
        return
    }

    var bufferedInputStream = BufferedInputStream.$new(fileInputStream);
    var ca = cf.generateCertificate(bufferedInputStream);
    bufferedInputStream.close();

    var certInfo = Java.cast(ca, X509Certificate);
    console.log("[o] Our CA Info: " + certInfo.getSubjectDN());

    // Create a KeyStore containing our trusted CAs
    console.log("[+] Creating a KeyStore for our CA...");
    var keyStoreType = KeyStore.getDefaultType();
    var keyStore = KeyStore.getInstance(keyStoreType);
    keyStore.load(null, null);
    keyStore.setCertificateEntry("ca", ca);

    // Create a TrustManager that trusts the CAs in our KeyStore
    console.log("[+] Creating a TrustManager that trusts the CA in our KeyStore...");
    var tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
    var tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
    tmf.init(keyStore);
    console.log("[+] Our TrustManager is ready...");

    console.log("[+] Hijacking SSLContext methods now...")
    console.log("[-] Waiting for the app to invoke SSLContext.init()...")

    SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function (a, b, c) {
        console.log("[o] App invoked javax.net.ssl.SSLContext.init...");
        SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").call(this, a, tmf.getTrustManagers(), c);
        console.log("[+] SSLContext initialized with our custom TrustManager!");
    }
});
```

更多定位与绕过手法(TrustManagerImpl.checkTrustedRecursive、o.asq 精确定位、SSLpinning 定位器、okhttp CertificatePinner 源码分析)另见 [../高级/检测绕过片段.md](../高级/检测绕过片段.md)。

### 12.2 dump 客户端证书(r0capture 版)

什么时候用:服务器校验客户端证书(mTLS 双向认证)的情形,帮助 dump 客户端证书,并保存为 p12 的格式,证书密码为 r0ysue。

```javascript
if (Java.available) {
    Java.perform(function () {
        function storeP12(pri, p7, p12Path, p12Password) {
            var X509Certificate = Java.use("java.security.cert.X509Certificate")
            var p7X509 = Java.cast(p7, X509Certificate);
            var chain = Java.array("java.security.cert.X509Certificate", [p7X509])
            var ks = Java.use("java.security.KeyStore").getInstance("PKCS12", "BC");
            ks.load(null, null);
            ks.setKeyEntry("client", pri, Java.use('java.lang.String').$new(p12Password).toCharArray(), chain);
            try {
                var out = Java.use("java.io.FileOutputStream").$new(p12Path);
                ks.store(out, Java.use('java.lang.String').$new(p12Password).toCharArray())
            } catch (exp) {
                console.log(exp)
            }
        }

        //在服务器校验客户端的情形下，帮助dump客户端证书，并保存为p12的格式，证书密码为r0ysue
        Java.use("java.security.KeyStore$PrivateKeyEntry").getPrivateKey.implementation = function () {
            var result = this.getPrivateKey()
            var packageName = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName();
            // /data/data/com.paokeji.yiqu/files/cer
            storeP12(this.getPrivateKey(), this.getCertificate(), '/data/data/' + packageName + "/files/" + "base" + '.p12', 'r0ysue');
            console.log("dumpClinetCertificate=>" + '/data/data/' + packageName + "/files/" + "base" + '.p12' + '   pwd: r0ysue');
            // console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
            return result;
        }

        Java.use("java.security.KeyStore$PrivateKeyEntry").getCertificateChain.implementation = function () {
            var result = this.getCertificateChain()
            var packageName = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName();
            storeP12(this.getPrivateKey(), this.getCertificate(), '/data/data/' + packageName + "/files/base.p12", 'r0ysue');
            console.log("dumpClinetCertificate=>" + '/data/data/' + packageName + "/files/base.p12" + '   pwd: r0ysue');
            return result;
        }
        console.log("开始hook")
    })
}
```


## 相关文档

- 抓包全场景:[../../04-对抗攻防/抓包全场景.md](../../04-对抗攻防/抓包全场景.md)
- pinning 定位(TrustManagerImpl/o.asq/定位器/okhttp 源码):[../高级/检测绕过片段.md](../高级/检测绕过片段.md)
