# SSL Pinning Bypass

> Classify → locate → layered bypass scripts → the system-layer solution for user certificates on Android 7+.
> Basis: httptoolkit's layered pinning analysis, akabe1 frida_multiple_unpinning (30+ implementations), r0capture (mTLS dump).

## 0. Foundation: Android's TLS validation chain

```
app code
 └─ OkHttp / Volley / HttpURLConnection / Flutter(dart:io)
     └─ javax.net.ssl.X509TrustManager (default impl: conscrypt's TrustManagerImpl)
         └─ TrustManagerImpl.checkTrustedRecursive()   ← the system's default chain validation
             ├─ certificate chain signature verification (Conscrypt/OpenSSL)
             └─ network security config networkSecurityConfig (system CA / user CA / pin-set)
```

The essence of pinning: **narrowing "which CA to trust" down to "which specific certificate/public key to trust"**. The pinned value is usually the SHA-256 of the certificate's SPKI (okhttp `sha256/<base64>`). So you only need to hook the "comparison" step — not forge a certificate — to admit any man-in-the-middle cert.

## 1. Classification and per-layer principles

### 1.1 OkHttp CertificatePinner (most common in the Java layer)

```java
new OkHttpClient.Builder()
    .certificatePinner(new CertificatePinner.Builder()
        .add("api.target.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        .build())
```
- Execution point: `okhttp3.CertificatePinner.check$okhttp(String hostname, List<Certificate> peerCertificates)` — computes the SPKI hash for every certificate in the returned chain and compares against the pin set; a mismatch throws `SSLPeerUnverifiedException`, with the log keyword **`Certificate pinning failure!`**;
- Note this happens **after the TLS handshake completes and before the HTTP request goes out** (application-layer pinning, not transport layer), so burp can finish the handshake yet blow up when reading the response.

### 1.2 Self-implemented X509TrustManager (the app news up its own)

```java
TrustManager[] tm = { new X509TrustManager() {
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        if (!chain[0].getEncoded().equals(bundledLocalCertDER)) throw ...;  // many possible variants
    } ... }};
SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(null, tm, null);
```
- Many variants: compare the full certificate DER, compare the public key, compare CN/SAN, or put the bundled cert in raw resources, parse it with `CertificateFactory` and compare fingerprints;
- There is also the wrapper type: `X509TrustManagerExtensions.checkServerTrusted(chain, authType, host)` (JSSE's hostname-aware wrapper; internally it goes through chain validation all the same).

### 1.3 Network security config pin-set (manifest layer)

```xml
<network-security-config>
  <domain-config>
    <domain includeSubdomains="true">api.target.com</domain>
    <pin-set expiration="2027-01-01"><pin digest="SHA-256">AAAA...</pin></pin-set>
  </domain-config>
</network-security-config>
```
- The system's `NetworkSecurityConfig` appends the pin comparison after `TrustManagerImpl` validation (`ApplicationConfig` → `NetworkSecurityTrustProvider`). For bypass purposes it flows through the same `checkTrustedRecursive` pipeline as 1.2, and a generic script covers it incidentally.

### 1.4 Native-layer validation (libcurl/openssl/BoringSSL shipped in-app)

- The app uses curl/its own openssl/BoringSSL build (Flutter is the classic case with its bundled BoringSSL): validation happens inside the so (`SSL_get_verify_result`, `X509_verify_cert`, curl's `CURLOPT_PINNEDPUBLICKEY`);
- The Java-layer TrustManager is not on the path at all; **every Java hook is useless**;
- Flutter specifics: dart:io's SecurityContext validates system CAs by default; and Flutter does its own DNS resolution (if it ignores the system proxy, traffic cannot even reach burp — first hook `HttpClient.badCertificateCallback` or set proxy environment variables).

### 1.5 Mutual authentication (mTLS)

- The server also validates a client certificate: the app bundles a p12 (res/raw/xxx.p12) + password (hardcoded/computed in native); at handshake the `KeyManager` (`X509KeyManager`) supplies the private key + cert chain;
- Symptom: burp with a fake client cert → server 403/handshake failure. The bypass is not really "bypassing validation" but **stealing the client certificate for burp to use** (§3.4).

## 2. Locating the pin (find which layer it's on before striking)

### 2.1 String/log locating

- Decompile (jadx) and globally search: `Certificate pinning failure` (okhttp), `checkServerTrusted`, `X509TrustManager`, `sha256/` (the pin value format), `pin-set`, `networkSecurityConfig` (manifest), `.p12`/`.bks`/`PKCS12` (mTLS keystore);
- At the resource layer, check whether `res/xml/network_security_config.xml` has a pin-set; whether `res/raw/` has a p12/bks.

### 2.2 Runtime call-stack locating (a frida one-liner)

```javascript
// Make any Java exception/key method dump its call stack; from the stack, see which class implements the pin
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
- Stack shows `com.target.app.ssl.XXX` → a self-implemented TrustManager; next step, precisely hook that class;
- Stack shows only okhttp/conscrypt → library-layer pin; generic scripts cover it;
- Stack shows nothing at all (invisible at the Java layer) → native pin; go to IDA on the so (search for `SSL_CTX_set_verify`, `curl_easy_setopt`, `SSL_get_verify_result`, the strings `pin` and the `X509`/`sha256` constants).

### 2.3 File-read-side locating (hook File/KeyStore constructors)

```javascript
// mTLS: hook KeyStore.load to see which p12 it reads + the password
Java.perform(function () {
    var KS = Java.use("java.security.KeyStore");
    KS.load.overload('java.io.InputStream', '[C').implementation = function (is, pass) {
        console.log("KeyStore.load password=" + (pass ? Java.use("java.lang.String").$new(pass) : null));
        return this.load(is, pass);
    };
});
```

Pair with hooking the `File` constructor/`openFileInput` to see the certificate filename loaded from `res/raw`; if the password is computed in native (JNI returns char[]), hook the return point or find it in IDA.

## 3. Layered bypass scripts

### 3.1 Layer one: the generic sledgehammer (just run it blindly first)

Modern generic scripts (akabe1's frida_multiple_unpinning covers 30+ implementations; httptoolkit's analysis covers a similar range) do the following core moves:

```javascript
// A. The system's default TrustManager: make chain validation return an empty list (= trust everything)
var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
TrustManagerImpl.checkTrustedRecursive.implementation =
  function (chain, authType, host, clientAuth, clientAuthAlg, clientAuthParams, ocspData, tlsSctData) {
      console.log("[+] checkTrustedRecursive bypass for " + host);
      return Java.use("java.util.ArrayList").$new();   // empty certificate list
  };
// (Older Android versions have a different signature: checkTrusted(X509Certificate[], String, String) returns empty)

// B. OkHttp CertificatePinner: check$okhttp just returns (found = throws nothing)
var CertPinner = Java.use("okhttp3.CertificatePinner");
CertPinner.check$okhttp.overload('java.lang.String', 'java.util.List')
  .implementation = function (hostname, peerCerts) { return; };

// C. Replace the second argument of SSLContext.init with a custom empty TrustManager
var SSLCtx = Java.use("javax.net.ssl.SSLContext");
SSLCtx.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
  .implementation = function (km, tm, sr) {
      var TMI = Java.registerClass({ /* implements X509TrustManager, allow-all */ });
      return this.init(km, [TMI.$new()], sr);
  };
// D. Incidentally: webview's onReceivedSslError → handler.proceed()
// E. Incidentally: okhttp3.internal.tls.OkHostnameVerifier / X509TrustManagerExtensions
```

Key points:
- **Why hooking checkTrustedRecursive is enough**: the network layer (HttpURLConnection/okhttp without pins configured) ultimately converges on this conscrypt method; returning an "empty trusted list" means the caller believes nothing further needs verification (each call site passes once it gets the empty list);
- **Return an empty list rather than throwing/returning the original**: gabriel.urdhr's analysis points out these scripts actually "turn off all certificate validation", not just the pin — security-equivalent to full trust; fine during testing;
- **Version pitfalls**: method signatures differ across Android/okhttp versions (whether `check$okhttp` exists, whether `checkTrustedRecursive` takes 4 or 8 parameters), which is why mature scripts wrap everything in try/catch and try one by one — write yours the same way.

### 3.2 Layer two: precise hooks after locating the self-implemented class

When the generic script misses (the app uses an unconventional library):

```javascript
// Example: located com.target.app.security.MyTrustManager
var MTM = Java.use("com.target.app.security.MyTrustManager");
MTM.checkServerTrusted.implementation = function (chain, authType) {
    console.log("[+] MyTrustManager bypassed, authType=" + authType);
    // does not call the original; returning directly = allow
};

// Example: the network layer is in Volley/HurlStack or a custom SSLSocketFactory
var Factory = Java.use("com.target.app.net.MySSLSocketFactory");
Factory.createSocket.overload(...).implementation = ... // return a socket wrapped with an empty TM
```
- The basis for precise hooks comes from the call-stack locating in §2;
- With obfuscated class names (a.b.c), reverse-locate by method signature (`([Ljava/security/cert/X509Certificate;Ljava/lang/String)V`) + string constants (the pin base64 value from jadx).

### 3.3 Layer three: native pinning

Locate: open the target so in IDA; search the imports for `SSL_CTX_set_verify` / `SSL_get_verify_result` / `X509_verify_cert` / `curl_easy_setopt` (CURLOPT_PINNEDPUBLICKEY=10230; curl passes options as integers, search for constants like `0x27f6`), the string `sha256//` (curl pin format).
On the frida side (for a BoringSSL/libcrypto so):

```javascript
// Idea: hook SSL_CTX_set_verify inside the so; swap the callback for one that always returns 1 (verify OK)
var set_verify = Module.findExportByName("libtarget.so", "SSL_CTX_set_verify")
              || Module.findExportByName("libssl.so", "SSL_CTX_set_verify");
Interceptor.attach(set_verify, {
    onEnter: function (args) {
        args[1] = ptr(0);            // SSL_VERIFY_NONE
        this.neverFail = true;
    }
});
// And force SSL_get_verify_result to return X509_V_OK(0)
Interceptor.replace(Module.findExportByName(null, "SSL_get_verify_result"),
    new NativeCallback(function (ssl) { return 0; }, 'long', ['pointer']));

// Flutter-specific (the classic move when libflutter.so symbols are stripped; httptoolkit has the full version):
// 1. After matching the version, find ssl_verify_peer_cert / ssl_crypto_x509_session_verify_cert_chain by offset
// 2. Interceptor.replace it to always return 1 (error code 0 = success)
var addr = Module.findBaseAddress("libflutter.so").add(0x1D5C2C); // offset varies by version
Interceptor.replace(addr, new NativeCallback(function (a, b, c, d) { return 1; },
    'int', ['pointer','pointer','pointer','pointer']));
```

How to find Flutter offsets: `strings libflutter.so | grep -o 'Dart_VM.*'` to read the version → the matching dart-sdk source/community offset table (httptoolkit maintains the script re-frida-flutter-pinning; the idea is exactly the above). When the so is stripped, use `Module.enumerateExports` + runtime backtracking of call sites, or patch the so directly.

### 3.4 Layer four: dump the mTLS client certificate as p12 (the r0capture route)

Two routes:
**Route one: static extraction** — find the p12/bks resource in the APK (§2.1); find the password in jadx (search near `KeyStore.getInstance("PKCS12")` for `toCharArray`); import into burp (User Certificates).
**Route two: runtime dump (for obfuscated passwords/certs delivered dynamically)** — hook the KeyManager to grab the private key + cert chain and reassemble a p12 (r0capture's core idea):

```javascript
// r0capture's actual hook point: java.security.KeyStore$PrivateKeyEntry
// (the client-credential entry the KeyManager takes out at each handshake; more generic than hooking a concrete KeyManager impl)
Java.perform(function () {
    var PKEntry = Java.use("java.security.KeyStore$PrivateKeyEntry");
    PKEntry.getPrivateKey.implementation = function () {
        var key = this.getPrivateKey();
        var certChain = this.getCertificateChain();
        dumpToP12(key, certChain, "r0ysue");   // KeyStore PKCS12 setKeyEntry + store to /sdcard
        return key;
    };
});
// Alternative hook points: org.conscrypt.ClientKeyManager (or the app's own X509KeyManager)
// 's getPrivateKey(alias)/getCertificateChain(alias); the value is taken at the same moment
```
- r0capture is in effect "a kill-all application-layer capture script": the dumped p12 lands at `/sdcard/Download/<package>xxx.p12` with the default password `r0ysue`; open it in keystore-explorer to confirm, then import into burp/mitmproxy to complete the mutual proxy;
- Principle: **p12 = private key + cert chain + password**. The private key and chain are both in app memory (the handshake must use them), so intercepting at the KeyManager exit always gets them; sturdier than reversing for the password (works against "password computed in native" and "cert delivered by the server" alike).

## 4. The system-layer solutions for user certificates not being trusted on Android 7+

Background: since API 24, apps by default **do not trust user-installed CAs** (they trust only system CAs + what their own networkSecurityConfig declares). Install the burp cert into the user store → capture fails at the handshake outright. Four paths:

### 4.1 networkSecurityConfig rewrite (repackaging)

Decompile, add `res/xml/nsc.xml` (`<base-config cleartextTrafficPermitted="true"><trust-anchors><certificates src="user"/></trust-anchors></base-config>`) + reference it in the manifest, rebuild and re-sign. Cost: apps with signature checks blow up, and every app needs its own edit.

### 4.2 Writing into the system certificate directory (root)

```bash
# burp CA (DER) to PEM → rename by subject_hash → push into the system cert directory
openssl x509 -inform DER -in burp.der -out burp.pem
openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1   # e.g. 9a5ba575
mv burp.pem /data/misc/user/0/cacerts-added/9a5ba575.0   # the user-install path (only effective for apps that declare trust in user CAs)
# What you actually want is the system store: on Android 14+ /apex/com.android.conscrypt/cacerts is a read-only apex mount; see below
```
- Traditional: remount `/system/etc/security/cacerts/` rw and write (in the systemless era, do it with a Magisk module; see 4.3);
- **The Android 14 change**: CA storage moved into an APEX (the conscrypt APEX), read-only and hash-verified; manual remount is no longer straightforward — using a ready-made module saves trouble.

### 4.3 The system-certificate Magisk module (recommended; no repackaging)

- Representative projects: **MoveCertificate** (promotes user CAs to system CAs: the module's startup script bind-mounts `/data/misc/user/0/cacerts-added/*` into the system certificate directory), **MagiskTrustUserCerts** (same idea), **the conscrypt-apex adapted version** (handles cacerts inside the APEX on Android 14+: the module overlays the apex path via overlay/bind at a later stage);
- Principle: Magisk's systemless mount magic — it does not really modify the partition; it just makes `/system/etc/security/cacerts/` (or the apex-equivalent path) gain the burp certificate file at the mount layer. Note with Shamiko's DenyList: **if the target app is on the DenyList, the unmount also restores the cert module's mounts** → capture fails; either exclude the module path from the unmount or temporarily take the target app off the list while testing.

### 4.4 frida forces trust of user CAs (touching nothing system-level)

Without installing a cert or repackaging, directly hook the target app into trusting the user certificate pool:

```javascript
// Idea: alter the runtime result of NetworkSecurityConfig — the generic sledgehammer script already covers it:
// when checkTrustedRecursive returns an empty list, the "is the user CA trusted" question never even comes up,
// so the §3.1 script is a "free fix" for the Android 7+ problem; no separate certificate installation needed.
// Only use the 4.1-4.3 system-layer plans when hooking is inconvenient (a pure no-frida environment is required).
```

## 5. Triage order master table

| Symptom | Layer | Action |
|------|------|------|
| burp fails at the handshake (no app logs) | system doesn't trust the user CA / native pin | 4.2/4.3 install a system cert → still failing, go 3.3 |
| Handshake OK, blows up reading the response + log `Certificate pinning failure!` | okhttp pin | 3.1-B |
| The exception stack contains the app's own TrustManager | self-implemented | 3.2 precise hook |
| Stack shows only conscrypt | system/library layer | 3.1-A |
| Flutter app | BoringSSL | 3.3 offset replace |
| Server 403/handshake failure | mTLS | 3.4 dump p12 |
| Everything hooked and still failing | native curl/openssl | locate in IDA + 3.3 |
| Pinning passed but requests won't go out | proxy detection | see detection-landscape.md §5.1 |
