# Java Layer Hook: SSL Pinning and Certificates

> Topics: traffic capture/certificates (SSLContext.init bypass + dumping the client certificate)

## 12. Traffic Capture / Certificates

### 12.1 SSL pinning bypass (SSLContext.init version)

When to use: when the app uses a custom TrustManager to verify certificates beyond the system CAs and you cannot capture traffic, stuff your own CA in and swap the TrustManager. The certificate file must be placed at `/data/local/tmp/cer/desktop.cer`.

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

    // Supply the CA certificate here
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

For more locating and bypass techniques (TrustManagerImpl.checkTrustedRecursive, pinpointing o.asq, the SSLpinning locator, okhttp CertificatePinner source analysis) see [../advanced/detection-bypass-snippets.md](../advanced/detection-bypass-snippets.md).

### 12.2 Dump the client certificate (r0capture version)

When to use: the scenario where the server verifies the client certificate (mTLS mutual authentication); it helps dump the client certificate and save it in p12 format, with the certificate password r0ysue.

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

        // When the server validates the client, dump the client certificate to PKCS#12; the example password is r0ysue
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


## Related Docs

- All traffic-capture scenarios: [../../04-evasion/capture-all-scenarios.md](../../04-evasion/capture-all-scenarios.md)
- Pinning localization (TrustManagerImpl/o.asq/locator/okhttp source): [../advanced/detection-bypass-snippets.md](../advanced/detection-bypass-snippets.md)
