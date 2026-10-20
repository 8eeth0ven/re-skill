# frida advanced · detection-bypass snippets

> Topic: a collection of detection bypasses (usb/adb/rwxp/magisk/vpn) + SSL pinning location and bypass (TrustManagerImpl)

## 7. Detection-bypass collection

### 7.1 Hook the Java-layer USB debugging detection bypass (Settings$Global / Secure getInt)

When to use: the app reads settings like `adb_enabled` / `development_settings_enabled` to tell whether adb is connected or developer mode is on — force them all to return 0, and the accessibility detection gets bypassed along the way.

```javascript
function usb_anti() {
    Java.enumerateClassLoadersSync().forEach(classLoader => {
        Java.classFactory.loader = classLoader
        let ArrayList = Java.use("java.util.ArrayList");
        let AccessibilityManager = Java.use("android.view.accessibility.AccessibilityManager");
        AccessibilityManager["getInstalledAccessibilityServiceList"].implementation = function () {
            return ArrayList.$new();
        };

        AccessibilityManager["getEnabledAccessibilityServiceList"].implementation = function (i) {
            return ArrayList.$new();
        };

        let Global = Java.use("android.provider.Settings$Global");
        Global["getInt"].overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function (cr, s, i) {
            let ret = this["getInt"](cr, s, i);
            if (s === "adb_enabled" || s === "adb_wifi_enabled" || s === "development_settings_enabled" || s === "device_provisioned") {
                console.log("hook usb")
                ret = 0;
            }
            return ret;
        };

        let Secure = Java.use("android.provider.Settings$Secure");
        Secure["getInt"].overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function (cr, s, i) {
            let ret = this["getInt"](cr, s, i);
            if (s === "adb_enabled" || s === "adb_wifi_enabled" || s === "development_settings_enabled" || s === "device_provisioned") {
                console.log("hook usb")
                ret = 0;
            }
            return ret;
        };
    })
    console.log("[ * ] USB调试检测Hook完成");
}
```

### 7.2 Changing init.svc.adbd to stopped via __system_property_get (native version)

```javascript
function step1() {
    Interceptor.attach(Module.getExportByName(null, "__system_property_get"), {
        onEnter: function (args) {
            this.a0 = args[0];
            this.a1 = args[1];
        },
        onLeave: function (retval) {
            if (this.a0.readUtf8String() === 'init.svc.adbd') {
                this.a1.writeUtf8String('stopped');
                console.log(this.a0.readUtf8String())
            }
        },
    });
}
```

For these values, just modify them with magisk — magisk does not really change init's value, but user-space access can no longer reach it.

### 7.3 Removing rwxp (a frida memory signature)

The full implementation of `readFile` (java.nio version) is in section 2 (Memory, the "2.10 memory antifrida" part) of [frida-api-reference.md](../frida-api-reference.md); reused directly here:

```javascript
readFile("/proc/self/maps").split("\n").forEach(line => {
    if (line.indexOf("rwxp") !== -1) {
        const start_end = line.split(" ")[0].split("-")
        const start = ptr(parseInt(start_end[0], 16))
        const end = ptr(parseInt(start_end[1], 16))
        Memory.protect(start, end.sub(start).toInt32(), "r-x")
        console.log(line)
    }
})
```

### 7.4 Detecting magisk and zygisk (for command-line triage)

```bash
cat /proc/mounts | grep -i -e ksu -e magisk -e zygisk -e apatch -e overlay
```

### 7.5 VPN / proxy detection bypass

```javascript
// Hook用于绕过VPN和代理检测
Java.perform(function () {
    // Hook检查VPN的类和方法
    var ConnectivityManager = Java.use('android.net.ConnectivityManager');
    ConnectivityManager.getNetworkInfo.overload('int').implementation = function (networkType) {
        console.log('Bypassing VPN detection...');
        var result = this.getNetworkInfo(networkType);
        if (networkType === ConnectivityManager.TYPE_VPN.value) {
            console.log('VPN detected, returning null to bypass detection.');
            return null;
        }
        return result;
    };

    // Hook检查代理的类和方法
    var System = Java.use('java.lang.System');
    System.getProperty.overload('java.lang.String').implementation = function (key) {
        console.log('Bypassing proxy detection for key: ' + key);
        if (key === 'http.proxyHost' || key === 'https.proxyHost') {
            console.log('Proxy detected, returning null to bypass detection.');
            return null;
        }
        return this.getProperty(key);
    };

    // Hook检查代理的其他方法，如getDefaultProxy
    var Proxy = Java.use('android.net.Proxy');
    Proxy.getDefaultHost.implementation = function () {
        console.log('Bypassing proxy detection in getDefaultHost...');
        return null;
    };

    Proxy.getDefaultPort.implementation = function () {
        console.log('Bypassing proxy detection in getDefaultPort...');
        return -1; // 返回无效端口
    };

    console.log('VPN and Proxy detection hooks installed.');
});
```

For memory-level anti-detection (replacing libfrida-agent signature strings) see the "memory antifrida" part of [frida-api-reference.md](../frida-api-reference.md); for strstr-based anti-detection see the antifrida part of [native-hook-cheatsheet.md](../native-hook-cheatsheet.md).

## 8. Traffic capture: locating and bypassing SSL pinning

### 8.1 TrustManagerImpl.checkTrustedRecursive + o.asq precise-location method

Globally search for these two strings (inside the apk/so):

```
"Certificate pinning failure!"
Peer certificate chain:
```

Just replace o.asq below with the obfuscated class name you found:

```javascript
    Java.perform(function () {
        try {
            const array_list = Java.use("java.util.ArrayList");
            const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.checkTrustedRecursive.implementation = function (a1, a2, a3, a4, a5, a6) {
                console.log(' --> Bypassing TrustManagerImpl checkTrusted ');
                return array_list.$new();
            }

            console.log('[+] TrustManagerImpl');
        } catch (err) {
            console.log('[ ] TrustManagerImpl');
        }
        var asq = Java.use('o.asq');
        asq.create.overload("java.lang.String", "o.Pl").implementation = function (s, pl0) {
            console.log(`[+] Hooked o.asq.create(${s},${pl0})`);
        };
    });
```

If you cannot move the certificate into the system directory, use the certificate-handling tool MoveCertificate (ys1231).

### 8.2 SSL-pinning locator (hook the File constructor and inspect the X509TrustManagerExtensions call stack)

If the above finds nothing (the obfuscated class name does not match), use this code to help locate the key certificate-pinning code:

```javascript
//SSLpinning helper 帮助定位证书绑定的关键代码a
Java.perform(() => {
    Java.use("java.io.File").$init.overload('java.io.File', 'java.lang.String').implementation = function (file, cert) {
        var result = this.$init(file, cert)
        var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
        if (file.getPath().indexOf("cacert") >= 0 && stack.indexOf("X509TrustManagerExtensions.checkServerTrusted") >= 0) {
            var message = {};
            message["function"] = "SSLpinning position locator => " + file.getPath() + " " + cert;
            message["stack"] = stack;
            console.log(message["function"])
            console.log(message["stack"])
        }
        return result;
    }
})
```

Once found, hook that function; if that does not work, drop the com.android.org.conscrypt.TrustManagerImpl hook.

### 8.3 Appendix: okhttp CertificatePinner source essentials (which lines do the pinning checks)

Reading okhttp's CertificatePinner.check tells you what to bypass: the core is `check(String hostname, List<Certificate> peerCertificates)` — it iterates the pin set comparing sha1, and on mismatch throws `SSLPeerUnverifiedException("Certificate pinning failure!...")`. Just hook `check` and return.

```java
package com.android.okhttp;

import com.android.okhttp.internal.Util;
import com.android.okhttp.okio.ByteString;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.SSLPeerUnverifiedException;

public final class CertificatePinner {
    public static final CertificatePinner DEFAULT = new Builder().build();
    private final Map<String, Set<ByteString>> hostnameToPins;

    private CertificatePinner(Builder builder) {
        this.hostnameToPins = Util.immutableMap(builder.hostnameToPins);
    }

    public void check(String hostname, List<Certificate> peerCertificates) throws SSLPeerUnverifiedException {
        Set<ByteString> pins = findMatchingPins(hostname);
        if (pins == null) {
            return;
        }
        int size = peerCertificates.size();
        for (int i10 = 0; i10 < size; i10++) {
            if (pins.contains(sha1((X509Certificate) peerCertificates.get(i10)))) {
                return;
            }
        }
        StringBuilder message = new StringBuilder().append("Certificate pinning failure!").append("\n  Peer certificate chain:");
        int size2 = peerCertificates.size();
        for (int i11 = 0; i11 < size2; i11++) {
            X509Certificate x509Certificate = (X509Certificate) peerCertificates.get(i11);
            message.append("\n    ").append(pin(x509Certificate)).append(": ").append(x509Certificate.getSubjectDN().getName());
        }
        message.append("\n  Pinned certificates for ").append(hostname).append(":");
        for (ByteString pin : pins) {
            message.append("\n    sha1/").append(pin.base64());
        }
        throw new SSLPeerUnverifiedException(message.toString());
    }

    public void check(String hostname, Certificate... peerCertificates) throws SSLPeerUnverifiedException {
        check(hostname, Arrays.asList(peerCertificates));
    }

    Set<ByteString> findMatchingPins(String hostname) {
        Set<ByteString> directPins = this.hostnameToPins.get(hostname);
        Set<ByteString> wildcardPins = null;
        int indexOfFirstDot = hostname.indexOf(46);
        int indexOfLastDot = hostname.lastIndexOf(46);
        if (indexOfFirstDot != indexOfLastDot) {
            Set<ByteString> wildcardPins2 = this.hostnameToPins.get("*." + hostname.substring(indexOfFirstDot + 1));
            wildcardPins = wildcardPins2;
        }
        if (directPins == null && wildcardPins == null) {
            return null;
        }
        if (directPins == null || wildcardPins == null) {
            return directPins != null ? directPins : wildcardPins;
        }
        Set<ByteString> pins = new LinkedHashSet<>();
        pins.addAll(directPins);
        pins.addAll(wildcardPins);
        return pins;
    }

    public static String pin(Certificate certificate) {
        if (!(certificate instanceof X509Certificate)) {
            throw new IllegalArgumentException("Certificate pinning requires X509 certificates");
        }
        return "sha1/" + sha1((X509Certificate) certificate).base64();
    }

    private static ByteString sha1(X509Certificate x509Certificate) {
        return Util.sha1(ByteString.of(x509Certificate.getPublicKey().getEncoded()));
    }

    public static final class Builder {
        private final Map<String, Set<ByteString>> hostnameToPins = new LinkedHashMap();

        public Builder add(String hostname, String... pins) {
            if (hostname == null) {
                throw new IllegalArgumentException("hostname == null");
            }
            Set<ByteString> hostPins = new LinkedHashSet<>();
            Set<ByteString> previousPins = this.hostnameToPins.put(hostname, Collections.unmodifiableSet(hostPins));
            if (previousPins != null) {
                hostPins.addAll(previousPins);
            }
            for (String pin : pins) {
                if (!pin.startsWith("sha1/")) {
                    throw new IllegalArgumentException("pins must start with 'sha1/': " + pin);
                }
                ByteString decodedPin = ByteString.decodeBase64(pin.substring("sha1/".length()));
                if (decodedPin == null) {
                    throw new IllegalArgumentException("pins must be base64: " + pin);
                }
                hostPins.add(decodedPin);
            }
            return this;
        }

        public CertificatePinner build() {
            return new CertificatePinner(this);
        }
    }
}
```

### 8.4 Appendix: X509TrustManager code (the full interface)

```java
public interface X509TrustManager extends TrustManager {
    /**
     * Given the partial or complete certificate chain provided by the
     * peer, build a certificate path to a trusted root and return if it
     * can be validated and is trusted for client SSL
     * authentication based on the authentication type.
     * <p>
     * The authentication type is determined by the actual certificate
     * used. For instance, if RSAPublicKey is used, the authType
     * should be "RSA". Checking is case-sensitive.
     *
     * @param chain the peer certificate chain
     * @param authType the authentication type based on the client certificate
     * @throws IllegalArgumentException if null or zero-length chain
     *         is passed in for the chain parameter or if null or zero-length
     *         string is passed in for the  authType parameter
     * @throws CertificateException if the certificate chain is not trusted
     *         by this TrustManager.
     */
    public void checkClientTrusted(X509Certificate[] chain, String authType)
        throws CertificateException;

    /**
     * Given the partial or complete certificate chain provided by the
     * peer, build a certificate path to a trusted root and return if it
     * can be validated and is trusted for server SSL
     * authentication based on the authentication type.
     * <p>
     * The authentication type is the key exchange algorithm portion
     * of the cipher suites represented as a String, such as "RSA",
     * "DHE_DSS". Note: for some exportable cipher suites, the key
     * exchange algorithm is determined at run time during the
     * handshake. For instance, for TLS_RSA_EXPORT_WITH_RC4_40_MD5,
     * the authType should be RSA_EXPORT when an ephemeral RSA key is
     * used for the key exchange, and RSA when the key from the server
     * certificate is used. Checking is case-sensitive.
     *
     * @param chain the peer certificate chain
     * @param authType the key exchange algorithm used
     * @throws IllegalArgumentException if null or zero-length chain
     *         is passed in for the chain parameter or if null or zero-length
     *         string is passed in for the authType parameter
     * @throws CertificateException if the certificate chain is not trusted
     *         by this TrustManager.
     */
    public void checkServerTrusted(X509Certificate[] chain, String authType)
        throws CertificateException;

    /**
     * Return an array of certificate authority certificates
     * which are trusted for authenticating peers.
     *
     * @return a non-null (possibly empty) array of acceptable
     *          CA issuer certificates.
     */
    public X509Certificate[] getAcceptedIssuers();
}
```

### 8.5 Appendix: X509TrustManagerExtensions code (what the locator watches for)

`checkServerTrusted(chain, authType, host)` internally delegates to `TrustManagerImpl.checkServerTrusted` and is the choke point of pinning validation; the locator in 8.2 filters precisely on the `X509TrustManagerExtensions.checkServerTrusted` string in the stack.

```java
/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.net.http;

import android.security.net.config.UserCertificateSource;

import com.android.org.conscrypt.TrustManagerImpl;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.X509TrustManager;

/**
 * X509TrustManager wrapper exposing Android-added features.
 * <p>
 * The checkServerTrusted method allows callers to perform additional
 * verification of certificate chains after they have been successfully verified
 * by the platform.
 * </p>

 */
public class X509TrustManagerExtensions {

    private final TrustManagerImpl mDelegate;
    // Methods to use when mDelegate is not a TrustManagerImpl and duck typing is being used.
    private final X509TrustManager mTrustManager;
    private final Method mCheckServerTrusted;
    private final Method mIsSameTrustConfiguration;

    /**
     * Constructs a new X509TrustManagerExtensions wrapper.
     *
     * @param tm A {@link X509TrustManager} as returned by TrustManagerFactory.getInstance();
     * @throws IllegalArgumentException If tm is an unsupported TrustManager type.
     */
    public X509TrustManagerExtensions(X509TrustManager tm) throws IllegalArgumentException {
        if (tm instanceof TrustManagerImpl) {
            mDelegate = (TrustManagerImpl) tm;
            mTrustManager = null;
            mCheckServerTrusted = null;
            mIsSameTrustConfiguration = null;
            return;
        }
        // Use duck typing if possible.
        mDelegate = null;
        mTrustManager = tm;
        // Check that the hostname aware checkServerTrusted is present.
        try {
            mCheckServerTrusted = tm.getClass().getMethod("checkServerTrusted",
                    X509Certificate[].class,
                    String.class,
                    String.class);
        } catch (NoSuchMethodException e) {
            throw new IllegalArgumentException("Required method"
                    + " checkServerTrusted(X509Certificate[], String, String, String) missing");
        }
        // Get the option isSameTrustConfiguration method.
        Method isSameTrustConfiguration = null;
        try {
            isSameTrustConfiguration = tm.getClass().getMethod("isSameTrustConfiguration",
                    String.class,
                    String.class);
        } catch (ReflectiveOperationException ignored) {
        }
        mIsSameTrustConfiguration = isSameTrustConfiguration;
    }

    /**
     * Verifies the given certificate chain.
     *
     * <p>See {@link X509TrustManager#checkServerTrusted(X509Certificate[], String)} for a
     * description of the chain and authType parameters. The final parameter, host, should be the
     * hostname of the server.</p>
     *
     *
     * @throws CertificateException if the chain does not verify correctly.
     * @return the properly ordered chain used for verification as a list of X509Certificates.
     */
    public List<X509Certificate> checkServerTrusted(X509Certificate[] chain, String authType,
                                                    String host) throws CertificateException {
        if (mDelegate != null) {
            return mDelegate.checkServerTrusted(chain, authType, host);
        } else {
            try {
                return (List<X509Certificate>) mCheckServerTrusted.invoke(mTrustManager, chain,
                        authType, host);
            } catch (IllegalAccessException e) {
                throw new CertificateException("Failed to call checkServerTrusted", e);
            } catch (InvocationTargetException e) {
                if (e.getCause() instanceof CertificateException) {
                    throw (CertificateException) e.getCause();
                }
                if (e.getCause() instanceof RuntimeException) {
                    throw (RuntimeException) e.getCause();
                }
                throw new CertificateException("checkServerTrusted failed", e.getCause());
            }
        }
    }

    /**
     * Checks whether a CA certificate is added by an user.
     *
     * <p>Since {@link X509TrustManager#checkServerTrusted} may allow its parameter {@code chain} to
     * chain up to user-added CA certificates, this method can be used to perform additional
     * policies for user-added CA certificates.
     *
     * @return {@code true} to indicate that the certificate authority exists in the user added
     * certificate store, {@code false} otherwise.
     */
    public boolean isUserAddedCertificate(X509Certificate cert) {
        return UserCertificateSource.getInstance().findBySubjectAndPublicKey(cert) != null;
    }

    /**
     * Returns {@code true} if the TrustManager uses the same trust configuration for the provided
     * hostnames.
     */
    public boolean isSameTrustConfiguration(String hostname1, String hostname2) {
        if (mIsSameTrustConfiguration == null) {
            return true;
        }
        try {
            return (Boolean) mIsSameTrustConfiguration.invoke(mTrustManager, hostname1, hostname2);
        } catch (IllegalAccessException e) {
            throw new RuntimeException("Failed to call isSameTrustConfiguration", e);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException) {
                throw (RuntimeException) e.getCause();
            } else {
                throw new RuntimeException("isSameTrustConfiguration failed", e.getCause());
            }
        }
    }
}
```


## Related docs

- Java-layer hook quick reference: the 6 docs in ../java-layer/; native layer: [native-hook-cheatsheet.md](../native-hook-cheatsheet.md)
